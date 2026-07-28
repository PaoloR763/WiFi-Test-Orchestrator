from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Literal, cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

import wto_backend.services.agent_protocol as agent_protocol_module
from wto_backend.api.agent_schemas import (
    DesktopHeartbeatRequest,
    MobilePresenceRequest,
    PresenceResponse,
)
from wto_backend.config import Settings
from wto_backend.contracts import canonical_json
from wto_backend.domain.models import Agent, AgentPresence, CapabilityManifest
from wto_backend.repositories.agents import AgentRepository
from wto_backend.services.agent_protocol import AgentProtocolService
from wto_backend.services.errors import (
    AgentAuthenticationError,
    RequestClockSkewError,
    SequenceConflictError,
)

AGENT_ID = UUID("20000000-0000-4000-8000-000000000006")
BOOT_ID = UUID("30000000-0000-4000-8000-000000000003")
MANIFEST_ID = UUID("30000000-0000-4000-8000-000000000004")
MANIFEST_DIGEST = "b" * 64
BASE_TIME = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)

PresenceRequest = DesktopHeartbeatRequest | MobilePresenceRequest


class FrozenDateTime(datetime):
    current = BASE_TIME

    @classmethod
    def now(cls, tz: object = None) -> datetime:
        if tz is None:
            return cls.current.replace(tzinfo=None)
        return cls.current.astimezone(tz)  # type: ignore[arg-type]


class SessionDouble:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.commits = 0

    def add(self, value: object) -> None:
        self.added.append(value)

    def commit(self) -> None:
        self.commits += 1


class RepositoryDouble:
    def __init__(self, presence: AgentPresence, agent: Agent | None) -> None:
        self.stored_presence = presence
        self.stored_agent = agent
        self.presence_calls: list[tuple[UUID, bool]] = []
        self.agent_calls: list[tuple[UUID, bool, bool]] = []
        self.manifest_calls: list[tuple[UUID, UUID]] = []

    def presence(self, agent_id: UUID, *, lock: bool = False) -> AgentPresence | None:
        self.presence_calls.append((agent_id, lock))
        return self.stored_presence

    def agent(
        self,
        agent_id: UUID,
        *,
        lock: bool = False,
        refresh_existing: bool = False,
    ) -> Agent | None:
        self.agent_calls.append((agent_id, lock, refresh_existing))
        return self.stored_agent

    def manifest(self, agent_id: UUID, manifest_id: UUID) -> CapabilityManifest | None:
        self.manifest_calls.append((agent_id, manifest_id))
        return None


def request_for(
    kind: Literal["desktop", "mobile"],
    *,
    reported_at: datetime = BASE_TIME,
    boot_id: UUID = BOOT_ID,
    sequence: int = 7,
    state: str | None = None,
    reason: dict[str, str] | None = None,
) -> PresenceRequest:
    common: dict[str, object] = {
        "schema_version": "1.0.0",
        "agent_id": str(AGENT_ID),
        "boot_id": str(boot_id),
        "sequence": sequence,
        "agent_version": "0.1.0",
        "protocol_version": "1.0.0",
        "agent_reported_at": reported_at.isoformat().replace("+00:00", "Z"),
        "reason": reason,
        "manifest_id": str(MANIFEST_ID),
        "manifest_digest": MANIFEST_DIGEST,
    }
    if kind == "desktop":
        common["readiness"] = state or "ready"
        return DesktopHeartbeatRequest.model_validate(common)
    common["lifecycle"] = state or "background_window"
    return MobilePresenceRequest.model_validate(common)


def presence_state(presence: AgentPresence) -> tuple[object, ...]:
    return (
        presence.id,
        presence.agent_id,
        presence.kind,
        presence.boot_id,
        presence.sequence,
        presence.payload_digest,
        presence.agent_reported_at,
        presence.server_received_at,
        presence.presence_expires_at,
        presence.manifest_id,
        presence.version_id,
    )


def harness(
    request: PresenceRequest,
) -> tuple[AgentProtocolService, SessionDouble, RepositoryDouble, AgentPresence, Agent]:
    wire = request.model_dump(mode="json")
    digest = hashlib.sha256(canonical_json(wire)).digest()
    ttl = 90 if isinstance(request, DesktopHeartbeatRequest) else 120
    presence = AgentPresence(
        id=uuid4(),
        agent_id=AGENT_ID,
        kind="desktop" if isinstance(request, DesktopHeartbeatRequest) else "mobile",
        boot_id=request.boot_id,
        sequence=request.sequence,
        payload_digest=digest,
        agent_reported_at=request.agent_reported_at,
        server_received_at=BASE_TIME + timedelta(seconds=5),
        presence_expires_at=BASE_TIME + timedelta(seconds=5 + ttl),
        manifest_id=request.manifest_id,
        version_id=4,
    )
    agent = Agent(
        id=AGENT_ID,
        display_name="Presence unit agent",
        is_active=True,
        revoked_at=None,
        last_seen_at=BASE_TIME + timedelta(seconds=5),
        version_id=3,
    )
    session = SessionDouble()
    repository = RepositoryDouble(presence, agent)
    settings = cast(Settings, SimpleNamespace(agent_clock_skew_seconds=300))
    service = AgentProtocolService(cast(Session, session), settings)
    service.repo = cast(AgentRepository, repository)
    return service, session, repository, presence, agent


def send(service: AgentProtocolService, request: PresenceRequest) -> PresenceResponse:
    if isinstance(request, DesktopHeartbeatRequest):
        return service.heartbeat(agent_id=AGENT_ID, payload=request)
    return service.mobile_presence(agent_id=AGENT_ID, payload=request)


@pytest.mark.parametrize(
    ("kind", "clock_advance"),
    [
        pytest.param("mobile", 30, id="mobile-within-skew"),
        pytest.param("mobile", 301, id="mobile-after-301-seconds"),
        pytest.param("desktop", 301, id="desktop-after-301-seconds"),
    ],
)
def test_exact_replay_returns_durable_response_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
    kind: Literal["desktop", "mobile"],
    clock_advance: int,
) -> None:
    request = request_for(kind)
    service, session, repository, presence, agent = harness(request)
    before_presence = presence_state(presence)
    before_last_seen = agent.last_seen_at
    FrozenDateTime.current = BASE_TIME + timedelta(seconds=clock_advance)
    monkeypatch.setattr(agent_protocol_module, "datetime", FrozenDateTime)

    response = send(service, request)

    assert response.accepted_sequence == presence.sequence
    assert response.server_received_at == presence.server_received_at
    assert response.presence_expires_at == presence.presence_expires_at
    assert response.poll_after_seconds == (30 if kind == "desktop" else 60)
    assert repository.presence_calls == [(AGENT_ID, True)]
    assert repository.agent_calls == [(AGENT_ID, True, True)]
    assert repository.manifest_calls == []
    assert session.added == []
    assert session.commits == 0
    assert presence_state(presence) == before_presence
    assert agent.last_seen_at == before_last_seen


def test_same_sequence_with_different_digest_wins_over_body_clock_skew(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accepted = request_for("mobile")
    service, session, repository, _, _ = harness(accepted)
    changed = request_for("mobile", state="foreground")
    FrozenDateTime.current = BASE_TIME + timedelta(seconds=301)
    monkeypatch.setattr(agent_protocol_module, "datetime", FrozenDateTime)

    with pytest.raises(SequenceConflictError):
        send(service, changed)

    assert repository.agent_calls == [(AGENT_ID, True, True)]
    assert repository.manifest_calls == []
    assert session.added == []
    assert session.commits == 0


@pytest.mark.parametrize(
    "presence_request",
    [
        pytest.param(request_for("mobile", sequence=8), id="higher-sequence"),
        pytest.param(request_for("mobile", boot_id=uuid4()), id="different-boot"),
    ],
)
def test_new_publication_with_old_body_keeps_clock_skew_validation(
    monkeypatch: pytest.MonkeyPatch,
    presence_request: PresenceRequest,
) -> None:
    accepted = request_for("mobile")
    service, session, repository, _, _ = harness(accepted)
    FrozenDateTime.current = BASE_TIME + timedelta(seconds=301)
    monkeypatch.setattr(agent_protocol_module, "datetime", FrozenDateTime)

    with pytest.raises(RequestClockSkewError):
        send(service, presence_request)

    assert repository.agent_calls == []
    assert repository.manifest_calls == []
    assert session.added == []
    assert session.commits == 0


def test_revoked_agent_cannot_receive_durable_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = request_for("mobile")
    service, session, repository, presence, agent = harness(request)
    before_presence = presence_state(presence)
    agent.is_active = False
    agent.revoked_at = BASE_TIME + timedelta(seconds=1)
    FrozenDateTime.current = BASE_TIME + timedelta(seconds=301)
    monkeypatch.setattr(agent_protocol_module, "datetime", FrozenDateTime)

    with pytest.raises(AgentAuthenticationError):
        send(service, request)

    assert repository.agent_calls == [(AGENT_ID, True, True)]
    assert repository.manifest_calls == []
    assert session.added == []
    assert session.commits == 0
    assert presence_state(presence) == before_presence


def test_replay_results_and_errors_do_not_expose_payload_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "credential-like-wto_ac_1-sensitive-marker"
    accepted = request_for("mobile", reason={"code": "blocked", "detail": marker})
    service, _, _, _, _ = harness(accepted)
    FrozenDateTime.current = BASE_TIME + timedelta(seconds=301)
    monkeypatch.setattr(agent_protocol_module, "datetime", FrozenDateTime)

    response = send(service, accepted)
    assert marker not in str(response.model_dump(mode="json"))

    changed = request_for(
        "mobile",
        state="foreground",
        reason={"code": "blocked", "detail": "different-controlled-reason"},
    )
    with pytest.raises(SequenceConflictError) as captured:
        send(service, changed)
    assert marker not in str(captured.value)
    assert marker not in repr(captured.value)
