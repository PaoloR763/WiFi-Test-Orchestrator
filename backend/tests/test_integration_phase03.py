from __future__ import annotations

import json
import os
import secrets
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from redis import Redis
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError

from wto_backend.config import Settings, get_settings
from wto_backend.contracts import canonical_json, contract_root
from wto_backend.db.session import Database
from wto_backend.domain.models import (
    AgentCredential,
    AgentCredentialRotation,
    AuditLog,
    AuthSession,
    EnrollmentToken,
    IdempotencyRecord,
    RefreshToken,
    Role,
    SecretReplay,
    User,
)
from wto_backend.main import create_app
from wto_backend.security.agent_credentials import parse_machine_secret
from wto_backend.security.passwords import PasswordManager
from wto_backend.security.tokens import TokenManager
from wto_backend.services.auth import AuthService
from wto_backend.services.bootstrap import bootstrap_administrator
from wto_backend.services.errors import InvalidSessionError, LastAdministratorError
from wto_backend.services.idempotency import IdempotencyService
from wto_backend.services.rbac import UserAdministrationService
from wto_backend.services.seeds import seed_rbac

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("WTO_RUN_INTEGRATION") != "1",
        reason="set WTO_RUN_INTEGRATION=1 with disposable PostgreSQL and Redis",
    ),
]

ALL_TABLES = (
    "agent_presence, capability_manifests, secret_replays, idempotency_records, "
    "agent_credential_rotations, agent_credentials, enrollment_tokens, artifacts, "
    "metrics, executions, campaigns, test_definitions, "
    "capabilities, agents, devices, refresh_tokens, sessions, role_permissions, "
    "user_roles, audit_logs, permissions, roles, users"
)
ADMIN_PASSWORD = "phase-03-integration-admin-password"


def alembic_config() -> Config:
    return Config("alembic.ini")


@pytest.fixture(scope="module")
def settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()


@pytest.fixture(autouse=True)
def clean_database(settings: Settings) -> Iterator[None]:
    command.upgrade(alembic_config(), "head")
    owner = create_engine(settings.migration_database_url)
    with owner.begin() as connection:
        connection.execute(text(f"TRUNCATE TABLE {ALL_TABLES} CASCADE"))
    owner.dispose()
    redis = Redis(host=settings.redis_host, port=settings.redis_port, db=settings.redis_db)
    redis.flushdb()
    redis.close()
    database = Database(settings.database_url)
    manager = PasswordManager(
        memory_cost=settings.argon2_memory_cost,
        time_cost=settings.argon2_time_cost,
        parallelism=settings.argon2_parallelism,
    )
    with database.session_factory() as session:
        seed_rbac(session, correlation_id="integration-seed")
        bootstrap_administrator(
            session,
            username="admin",
            password=ADMIN_PASSWORD,
            passwords=manager,
            correlation_id="integration-bootstrap",
        )
    database.close()
    yield


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings), base_url="https://testserver") as test_client:
        yield test_client


def login(client: TestClient, username: str = "admin", password: str = ADMIN_PASSWORD) -> str:
    response = client.post(
        "/api/internal/v1/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Secure" in cookie
    return str(response.json()["access_token"])


def auth_headers(access: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access}"}


def test_migration_upgrade_downgrade_reupgrade(settings: Settings) -> None:
    del settings
    command.downgrade(alembic_config(), "20260711_0001")
    command.upgrade(alembic_config(), "head")
    database = Database(get_settings().migration_database_url)
    with database.engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260712_0004"
        assert connection.scalar(text("SELECT to_regclass('public.audit_logs')")) == "audit_logs"
    database.close()


def test_seeds_and_bootstrap_are_idempotent(settings: Settings) -> None:
    database = Database(settings.database_url)
    manager = PasswordManager(memory_cost=65536, time_cost=3, parallelism=1)
    with database.session_factory() as session:
        created, updated = seed_rbac(session, correlation_id="seed-second")
        assert created == 0 and updated == 0
        _, was_created = bootstrap_administrator(
            session,
            username="admin",
            password=ADMIN_PASSWORD,
            passwords=manager,
            correlation_id="bootstrap-second",
        )
        assert was_created is False
        assert [role.key for role in session.scalars(select(Role).order_by(Role.key))] == [
            "administrator",
            "operator",
            "test_manager",
            "viewer",
        ]
    database.close()


def test_login_refresh_rotation_reuse_and_audit(client: TestClient, settings: Settings) -> None:
    access = login(client)
    original_cookie = client.cookies.get("wto_refresh")
    assert original_cookie is not None
    me = client.get("/api/internal/v1/auth/me", headers=auth_headers(access))
    assert me.status_code == 200
    assert me.json()["must_change_password"] is True
    refreshed = client.post(
        "/api/internal/v1/auth/refresh", headers={"Origin": settings.allowed_origin}
    )
    assert refreshed.status_code == 200
    replacement_cookie = client.cookies.get("wto_refresh")
    assert replacement_cookie and replacement_cookie != original_cookie
    client.cookies.set("wto_refresh", original_cookie, path="/api/internal/v1/auth")
    reused = client.post(
        "/api/internal/v1/auth/refresh", headers={"Origin": settings.allowed_origin}
    )
    assert reused.status_code == 401
    assert reused.json()["error"]["correlation_id"]
    database = Database(settings.database_url)
    with database.session_factory() as session:
        family = session.scalar(select(AuthSession))
        assert family is not None and family.revocation_reason == "refresh_reuse"
        actions = set(session.scalars(select(AuditLog.action)))
        assert {"auth.login", "auth.refresh", "auth.refresh_reuse"}.issubset(actions)
        assert all(len(token.token_digest) == 32 for token in session.scalars(select(RefreshToken)))
    database.close()


def test_login_failures_rate_limit_and_generic_envelope(client: TestClient) -> None:
    missing = client.post(
        "/api/internal/v1/auth/login",
        json={"username": "does-not-exist", "password": "not-the-password"},
    )
    wrong = client.post(
        "/api/internal/v1/auth/login",
        json={"username": "admin", "password": "not-the-password"},
    )
    assert missing.status_code == wrong.status_code == 401
    assert missing.json()["error"]["message"] == wrong.json()["error"]["message"]
    for _ in range(5):
        response = client.post(
            "/api/internal/v1/auth/login",
            json={"username": "admin", "password": "not-the-password"},
        )
    assert response.status_code == 429
    assert response.json()["error"] == {
        "code": "login_rate_limited",
        "message": "Too many authentication attempts.",
        "details": None,
        "correlation_id": response.headers["X-Correlation-ID"],
    }


def test_csrf_rbac_role_removal_logout_and_password_change(
    client: TestClient, settings: Settings
) -> None:
    access = login(client)
    protected = client.get("/api/internal/v1/admin/protected", headers=auth_headers(access))
    assert protected.status_code == 200
    assert client.post("/api/internal/v1/auth/refresh").status_code == 403
    assert (
        client.post(
            "/api/internal/v1/auth/refresh",
            headers={"Origin": "https://attacker.invalid"},
        ).status_code
        == 403
    )
    database = Database(settings.database_url)
    with database.session_factory() as session:
        admin = session.scalar(select(User).where(User.username == "admin"))
        viewer_role = session.scalar(select(Role).where(Role.key == "viewer"))
        assert admin is not None and viewer_role is not None
    database.close()
    created = client.post(
        "/api/internal/v1/admin/users",
        headers=auth_headers(access),
        json={"username": "viewer1", "password": "viewer-initial-password"},
    )
    assert created.status_code == 201
    viewer_id = created.json()["id"]
    assert (
        client.put(
            f"/api/internal/v1/admin/users/{viewer_id}/roles/viewer",
            headers=auth_headers(access),
        ).status_code
        == 204
    )
    viewer_client = TestClient(client.app, base_url="https://testserver")
    viewer_access = login(viewer_client, "viewer1", "viewer-initial-password")
    assert (
        viewer_client.get(
            "/api/internal/v1/admin/protected", headers=auth_headers(viewer_access)
        ).status_code
        == 403
    )
    assert (
        client.delete(
            f"/api/internal/v1/admin/users/{viewer_id}/roles/viewer",
            headers=auth_headers(access),
        ).status_code
        == 204
    )
    assert (
        viewer_client.get(
            "/api/internal/v1/rbac/roles", headers=auth_headers(viewer_access)
        ).status_code
        == 403
    )
    changed = client.post(
        "/api/internal/v1/auth/change-password",
        headers={**auth_headers(access), "Origin": settings.allowed_origin},
        json={
            "current_password": ADMIN_PASSWORD,
            "new_password": "phase-03-rotated-admin-password",
        },
    )
    assert changed.status_code == 204
    assert client.get("/api/internal/v1/auth/me", headers=auth_headers(access)).status_code == 401


def test_last_admin_trigger_and_runtime_privileges(settings: Settings) -> None:
    database = Database(settings.database_url)
    with database.session_factory() as session:
        event = session.scalar(select(AuditLog).limit(1))
        assert event is not None
        privileges = session.execute(
            text(
                "SELECT has_table_privilege(current_user, 'audit_logs', 'UPDATE'), "
                "has_table_privilege(current_user, 'audit_logs', 'DELETE')"
            )
        ).one()
        assert privileges == (False, False)
        with pytest.raises(DBAPIError):
            session.execute(
                text("UPDATE audit_logs SET outcome='failure' WHERE id=:id"),
                {"id": event.id},
            )
            session.commit()
        session.rollback()
    database.close()


def test_owner_is_also_blocked_by_append_only_trigger(settings: Settings) -> None:
    owner = create_engine(settings.migration_database_url)
    with owner.connect() as connection:
        event_id = connection.scalar(text("SELECT id FROM audit_logs LIMIT 1"))
        assert event_id is not None
        with pytest.raises(DBAPIError):
            connection.execute(
                text("UPDATE audit_logs SET outcome='failure' WHERE id=:id"),
                {"id": event_id},
            )
        connection.rollback()
        constraint_count = connection.scalar(
            text(
                "SELECT count(*) FROM pg_constraint WHERE conname IN "
                "('uq_users_username','ck_sessions_absolute_expiry_after_issue',"
                "'fk_refresh_tokens_session_id_sessions')"
            )
        )
        assert constraint_count == 3
    owner.dispose()


def test_logout_global_logout_disabled_user_and_last_admin(
    client: TestClient, settings: Settings
) -> None:
    access = login(client)
    database = Database(settings.database_url)
    with database.session_factory() as session:
        admin = session.scalar(select(User).where(User.username == "admin"))
        assert admin is not None
        admin_id = admin.id
    database.close()
    cannot_disable = client.patch(
        f"/api/internal/v1/admin/users/{admin_id}",
        headers=auth_headers(access),
        json={"is_active": False},
    )
    cannot_remove = client.delete(
        f"/api/internal/v1/admin/users/{admin_id}/roles/administrator",
        headers=auth_headers(access),
    )
    assert cannot_disable.status_code == cannot_remove.status_code == 409
    logout = client.post(
        "/api/internal/v1/auth/logout",
        headers={**auth_headers(access), "Origin": settings.allowed_origin},
    )
    assert logout.status_code == 204
    assert client.get("/api/internal/v1/auth/me", headers=auth_headers(access)).status_code == 401
    access = login(client)
    logout_all = client.post(
        "/api/internal/v1/auth/logout-all",
        headers={**auth_headers(access), "Origin": settings.allowed_origin},
    )
    assert logout_all.status_code == 204
    assert client.get("/api/internal/v1/auth/me", headers=auth_headers(access)).status_code == 401
    access = login(client)
    created = client.post(
        "/api/internal/v1/admin/users",
        headers=auth_headers(access),
        json={"username": "disabled1", "password": "disabled-user-password"},
    )
    user_id = created.json()["id"]
    assert (
        client.patch(
            f"/api/internal/v1/admin/users/{user_id}",
            headers=auth_headers(access),
            json={"is_active": False},
        ).status_code
        == 200
    )
    disabled_login = client.post(
        "/api/internal/v1/auth/login",
        json={"username": "disabled1", "password": "disabled-user-password"},
    )
    assert disabled_login.status_code == 401


def test_concurrent_refresh_revokes_family_on_second_use(
    client: TestClient, settings: Settings
) -> None:
    login(client)
    refresh_token = client.cookies.get("wto_refresh")
    assert refresh_token is not None

    def rotate() -> str:
        database = Database(settings.database_url)
        try:
            with database.session_factory() as session:
                service = AuthService(
                    session,
                    passwords=PasswordManager(memory_cost=65536, time_cost=3, parallelism=1),
                    tokens=TokenManager(
                        signing_key=settings.jwt_signing_key.get_secret_value(),
                        issuer=settings.jwt_issuer,
                        audience=settings.jwt_audience,
                        ttl_minutes=settings.access_token_minutes,
                    ),
                    audit_hmac_key=settings.audit_subject_hmac_key.get_secret_value(),
                    absolute_days=30,
                    inactivity_days=7,
                )
                try:
                    service.refresh(token=refresh_token, correlation_id="concurrent-refresh")
                except InvalidSessionError:
                    return "reused"
                return "rotated"
        finally:
            database.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: rotate(), (1, 2)))
    assert sorted(results) == ["reused", "rotated"]
    database = Database(settings.database_url)
    with database.session_factory() as session:
        family = session.scalar(select(AuthSession))
        assert family is not None and family.revocation_reason == "refresh_reuse"
    database.close()


def test_concurrent_bootstrap_creates_one_admin(settings: Settings) -> None:
    owner = create_engine(settings.migration_database_url)
    with owner.begin() as connection:
        connection.execute(text(f"TRUNCATE TABLE {ALL_TABLES} CASCADE"))
    owner.dispose()
    database = Database(settings.database_url)
    with database.session_factory() as session:
        seed_rbac(session, correlation_id="concurrent-seed")
    database.close()

    def run_bootstrap(index: int) -> bool:
        local = Database(settings.database_url)
        try:
            with local.session_factory() as session:
                _, created = bootstrap_administrator(
                    session,
                    username="admin",
                    password=ADMIN_PASSWORD,
                    passwords=PasswordManager(memory_cost=65536, time_cost=3, parallelism=1),
                    correlation_id=f"concurrent-{index}",
                )
                return created
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(run_bootstrap, (1, 2)))
    assert sorted(results) == [False, True]


def test_last_administrator_is_preserved_under_concurrency(settings: Settings) -> None:
    database = Database(settings.database_url)
    with database.session_factory() as session:
        admin = session.scalar(select(User).where(User.username == "admin"))
        assert admin is not None
        admin_id = admin.id
    database.close()

    def mutate(operation: str) -> str:
        local = Database(settings.database_url)
        try:
            with local.session_factory() as session:
                actor = session.scalar(select(User).where(User.id == admin_id))
                assert actor is not None
                service = UserAdministrationService(
                    session,
                    PasswordManager(memory_cost=65536, time_cost=3, parallelism=1),
                )
                try:
                    if operation == "disable":
                        service.disable_user(
                            user_id=admin_id,
                            actor=actor,
                            correlation_id="concurrent-disable",
                        )
                    else:
                        service.remove_role(
                            user_id=admin_id,
                            role_key="administrator",
                            actor=actor,
                            correlation_id="concurrent-remove",
                        )
                except LastAdministratorError:
                    return "preserved"
                return "mutated"
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(mutate, ("disable", "remove")))
    assert results == ["preserved", "preserved"]


def agent_headers(
    credential: str, *, nonce: str | None = None, timestamp: datetime | None = None
) -> dict[str, str]:
    now = timestamp or datetime.now(UTC)
    return {
        "Authorization": f"Bearer {credential}",
        "X-WTO-Agent-Timestamp": now.isoformat().replace("+00:00", "Z"),
        "X-WTO-Agent-Nonce": nonce or secrets.token_urlsafe(16),
        "X-WTO-Agent-Protocol": "1.0.0",
        "X-Correlation-ID": str(uuid4()),
    }


def create_enrollment_token(
    client: TestClient, access: str, *, scope: str = "agent.enroll"
) -> dict[str, object]:
    response = client.post(
        "/api/v1/enrollment-tokens",
        headers=auth_headers(access),
        json={
            "scope": scope,
            "expires_in_minutes": 15,
            "allowed_platforms": ["simulated"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def registration_payload(
    enrollment_token: str,
    *,
    key: str | None = None,
    installation_id: str | None = None,
) -> dict[str, object]:
    idempotency_key = key or str(uuid4())
    return {
        "schema_version": "1.0.0",
        "idempotency_key": idempotency_key,
        "enrollment_token": enrollment_token,
        "installation_id": installation_id or str(uuid4()),
        "display_name": "Integration simulated agent",
        "platform": "simulated",
        "platform_version": "1",
        "agent_version": "0.1.0",
        "protocol_min_version": "1.0.0",
        "protocol_max_version": "1.0.0",
        "agent_reported_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def register_payload(client: TestClient, payload: dict[str, object]):
    return client.post(
        "/api/v1/agent-enrollments",
        headers={"Idempotency-Key": str(payload["idempotency_key"])},
        json=payload,
    )


def enroll_agent(client: TestClient, access: str) -> tuple[dict[str, object], dict[str, object]]:
    token = create_enrollment_token(client, access)
    request = registration_payload(str(token["enrollment_token"]))
    response = register_payload(client, request)
    assert response.status_code == 201, response.text
    replay = register_payload(client, request)
    assert replay.status_code == 201
    assert replay.json() == response.json()
    return request, response.json()


def test_phase04_enrollment_manifest_presence_rotation_and_revocation(
    client: TestClient, settings: Settings
) -> None:
    access = login(client)
    _, registration = enroll_agent(client, access)
    agent_id = str(registration["agent_id"])
    credential = registration["credential"]["credential"]  # type: ignore[index]
    root = contract_root()
    manifest = json.loads((root / "examples/valid/capability-manifest-desktop.json").read_text())
    manifest["agent_id"] = agent_id
    manifest["manifest_id"] = str(uuid4())
    manifest_response = client.put(
        "/api/v1/agents/self/capability-manifest",
        headers=agent_headers(str(credential)),
        json=manifest,
    )
    assert manifest_response.status_code == 200, manifest_response.text
    accepted_manifest = manifest_response.json()
    heartbeat = {
        "schema_version": "1.0.0",
        "agent_id": agent_id,
        "boot_id": str(uuid4()),
        "sequence": 1,
        "agent_version": "0.1.0",
        "protocol_version": "1.0.0",
        "agent_reported_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "readiness": "ready",
        "reason": None,
        "manifest_id": accepted_manifest["manifest_id"],
        "manifest_digest": accepted_manifest["manifest_digest"],
    }
    first = client.post(
        "/api/v1/agents/self/heartbeats",
        headers=agent_headers(str(credential)),
        json=heartbeat,
    )
    duplicate = client.post(
        "/api/v1/agents/self/heartbeats",
        headers=agent_headers(str(credential)),
        json=heartbeat,
    )
    assert first.status_code == duplicate.status_code == 200
    changed = {**heartbeat, "readiness": "degraded"}
    assert (
        client.post(
            "/api/v1/agents/self/heartbeats",
            headers=agent_headers(str(credential)),
            json=changed,
        ).status_code
        == 409
    )

    rotation_key = str(uuid4())
    rotation_request = {"schema_version": "1.0.0", "idempotency_key": rotation_key}
    rotated = client.post(
        "/api/v1/agents/self/credential-rotations",
        headers={**agent_headers(str(credential)), "Idempotency-Key": rotation_key},
        json=rotation_request,
    )
    assert rotated.status_code == 201, rotated.text
    pending = rotated.json()["pending_credential"]["credential"]
    rotation_id = rotated.json()["rotation_id"]
    retry = client.post(
        "/api/v1/agents/self/credential-rotations",
        headers={**agent_headers(str(credential)), "Idempotency-Key": rotation_key},
        json=rotation_request,
    )
    assert retry.status_code == 201 and retry.json() == rotated.json()
    activation_key = str(uuid4())
    activated = client.post(
        f"/api/v1/agents/self/credential-rotations/{rotation_id}/activate",
        headers={**agent_headers(pending), "Idempotency-Key": activation_key},
        json={"schema_version": "1.0.0", "idempotency_key": activation_key},
    )
    assert activated.status_code == 200, activated.text
    activation_retry = client.post(
        f"/api/v1/agents/self/credential-rotations/{rotation_id}/activate",
        headers={**agent_headers(pending), "Idempotency-Key": activation_key},
        json={"schema_version": "1.0.0", "idempotency_key": activation_key},
    )
    assert activation_retry.status_code == 200
    assert activation_retry.json() == activated.json()
    assert (
        client.post(
            "/api/v1/agents/self/heartbeats",
            headers=agent_headers(str(credential)),
            json=heartbeat,
        ).status_code
        == 401
    )
    heartbeat["sequence"] = 2
    heartbeat["agent_reported_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    assert (
        client.post(
            "/api/v1/agents/self/heartbeats",
            headers=agent_headers(pending),
            json=heartbeat,
        ).status_code
        == 200
    )
    mobile = {
        "schema_version": "1.0.0",
        "agent_id": agent_id,
        "boot_id": str(uuid4()),
        "sequence": 1,
        "agent_version": "0.1.0",
        "protocol_version": "1.0.0",
        "agent_reported_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "lifecycle": "foreground",
        "reason": None,
        "manifest_id": accepted_manifest["manifest_id"],
        "manifest_digest": accepted_manifest["manifest_digest"],
    }
    mobile_response = client.post(
        "/api/v1/agents/self/presence",
        headers=agent_headers(pending),
        json=mobile,
    )
    assert mobile_response.status_code == 200
    assert mobile_response.json()["poll_after_seconds"] == 60
    assert (
        client.post(f"/api/v1/agents/{agent_id}/revoke", headers=auth_headers(access)).status_code
        == 204
    )
    for path, body in (
        ("/api/v1/agents/self/heartbeats", heartbeat),
        ("/api/internal/v1/agent-protocol/task-fetch", None),
        (
            "/api/internal/v1/agent-protocol/progress",
            json.loads((root / "examples/valid/progress-event.json").read_text()),
        ),
        (
            "/api/internal/v1/agent-protocol/results",
            json.loads((root / "examples/valid/test-result-zero.json").read_text()),
        ),
        (
            "/api/internal/v1/agent-protocol/artifact-manifests",
            json.loads((root / "examples/valid/artifact-manifest.json").read_text()),
        ),
    ):
        assert client.post(path, headers=agent_headers(pending), json=body).status_code == 401
    assert (
        client.put(
            "/api/v1/agents/self/capability-manifest",
            headers=agent_headers(pending),
            json=manifest,
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/agents/self/presence",
            headers=agent_headers(pending),
            json=mobile,
        ).status_code
        == 401
    )
    blocked_rotation_key = str(uuid4())
    assert (
        client.post(
            "/api/v1/agents/self/credential-rotations",
            headers={
                **agent_headers(pending),
                "Idempotency-Key": blocked_rotation_key,
            },
            json={
                "schema_version": "1.0.0",
                "idempotency_key": blocked_rotation_key,
            },
        ).status_code
        == 401
    )


def test_phase04_nonce_replay_clock_skew_and_idempotency_conflict(
    client: TestClient,
) -> None:
    access = login(client)
    request, registration = enroll_agent(client, access)
    credential = str(registration["credential"]["credential"])  # type: ignore[index]
    nonce = secrets.token_urlsafe(16)
    headers = agent_headers(credential, nonce=nonce)
    assert (
        client.post("/api/internal/v1/agent-protocol/task-fetch", headers=headers).status_code
        == 200
    )
    assert (
        client.post("/api/internal/v1/agent-protocol/task-fetch", headers=headers).status_code
        == 401
    )
    old = agent_headers(credential, timestamp=datetime.now(UTC) - timedelta(seconds=301))
    assert client.post("/api/internal/v1/agent-protocol/task-fetch", headers=old).status_code == 401
    conflicting = {**request, "display_name": "Changed payload"}
    assert (
        client.post(
            "/api/v1/agent-enrollments",
            headers={"Idempotency-Key": str(request["idempotency_key"])},
            json=conflicting,
        ).status_code
        == 409
    )


def test_phase04_enrollment_token_states_concurrency_and_recovery(
    client: TestClient, settings: Settings
) -> None:
    access = login(client)
    expired = create_enrollment_token(client, access)
    database = Database(settings.database_url)
    with database.session_factory() as session:
        token = session.get(EnrollmentToken, UUID(str(expired["enrollment_token_id"])))
        assert token is not None
        token.created_at = datetime.now(UTC) - timedelta(minutes=20)
        token.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    expired_response = register_payload(
        client, registration_payload(str(expired["enrollment_token"]))
    )
    assert expired_response.status_code == 401
    assert expired_response.json()["error"]["code"] == "enrollment_failed"

    revoked = create_enrollment_token(client, access)
    assert (
        client.post(
            f"/api/v1/enrollment-tokens/{revoked['enrollment_token_id']}/revoke",
            headers=auth_headers(access),
        ).status_code
        == 204
    )
    revoked_response = register_payload(
        client, registration_payload(str(revoked["enrollment_token"]))
    )
    assert revoked_response.status_code == 401
    assert revoked_response.json()["error"]["code"] == "enrollment_failed"
    assert (
        revoked_response.json()["error"]["message"] == expired_response.json()["error"]["message"]
    )

    consumed = create_enrollment_token(client, access)
    first_request = registration_payload(str(consumed["enrollment_token"]))
    first = register_payload(client, first_request)
    assert first.status_code == 201
    second = register_payload(client, registration_payload(str(consumed["enrollment_token"])))
    assert second.status_code == 401

    concurrent = create_enrollment_token(client, access)
    concurrent_requests = [
        registration_payload(str(concurrent["enrollment_token"])) for _ in range(2)
    ]
    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(
            executor.map(
                lambda payload: register_payload(client, payload).status_code,
                concurrent_requests,
            )
        )
    assert sorted(statuses) == [201, 401]

    agent_id = str(first.json()["agent_id"])
    assert (
        client.post(f"/api/v1/agents/{agent_id}/revoke", headers=auth_headers(access)).status_code
        == 204
    )
    recovery = client.post(
        f"/api/v1/agents/{agent_id}/recovery-enrollment-tokens",
        headers=auth_headers(access),
    )
    assert recovery.status_code == 201
    recovered = register_payload(client, registration_payload(recovery.json()["enrollment_token"]))
    assert recovered.status_code == 201
    assert recovered.json()["agent_id"] == agent_id
    assert recovered.json()["credential"]["credential_version"] == 2
    with database.session_factory() as session:
        rejected_events = list(
            session.scalars(select(AuditLog).where(AuditLog.action == "agent.enroll_rejected"))
        )
        assert len(rejected_events) >= 3
        assert all("enrollment_token" not in event.event_metadata for event in rejected_events)
    database.close()


def test_phase04_idempotency_in_progress_and_secret_replay_expiry(
    client: TestClient, settings: Settings
) -> None:
    access = login(client)
    token = create_enrollment_token(client, access)
    request = registration_payload(str(token["enrollment_token"]))
    parsed = parse_machine_secret(str(token["enrollment_token"]), prefix="wto_enr_1")
    fingerprint_payload = dict(request)
    del fingerprint_payload["enrollment_token"]
    del fingerprint_payload["idempotency_key"]
    now = datetime.now(UTC)
    database = Database(settings.database_url)
    with database.session_factory() as session:
        session.add(
            IdempotencyRecord(
                principal_type="enrollment_token",
                principal_id=parsed.locator,
                operation_id=f"agent.register:{request['installation_id']}",
                idempotency_key=UUID(str(request["idempotency_key"])),
                request_fingerprint=IdempotencyService.fingerprint(
                    canonical_json(fingerprint_payload)
                ),
                state="pending",
                created_at=now,
                updated_at=now,
                expires_at=now + timedelta(days=7),
            )
        )
        session.commit()
    pending = register_payload(client, request)
    assert pending.status_code == 409
    assert pending.json()["error"]["code"] == "idempotency_in_progress"
    assert pending.headers["retry-after"] == "1"

    _, registration = enroll_agent(client, access)
    credential = str(registration["credential"]["credential"])
    agent_id = UUID(str(registration["agent_id"]))
    rotation_key = str(uuid4())
    rotation_body = {"schema_version": "1.0.0", "idempotency_key": rotation_key}
    rotation = client.post(
        "/api/v1/agents/self/credential-rotations",
        headers={**agent_headers(credential), "Idempotency-Key": rotation_key},
        json=rotation_body,
    )
    assert rotation.status_code == 201
    pending_id = UUID(rotation.json()["pending_credential"]["credential_id"])
    with database.session_factory() as session:
        record = session.scalar(
            select(IdempotencyRecord).where(
                IdempotencyRecord.principal_id == agent_id,
                IdempotencyRecord.operation_id == "agent.credential.rotate",
                IdempotencyRecord.idempotency_key == UUID(rotation_key),
            )
        )
        assert record is not None
        replay = session.scalar(
            select(SecretReplay).where(SecretReplay.idempotency_record_id == record.id)
        )
        rotation_record = session.get(AgentCredentialRotation, UUID(rotation.json()["rotation_id"]))
        assert replay is not None and rotation_record is not None
        expired_at = rotation_record.created_at + timedelta(microseconds=1)
        replay.expires_at = expired_at
        rotation_record.expires_at = expired_at
        session.commit()
    expired_replay = client.post(
        "/api/v1/agents/self/credential-rotations",
        headers={**agent_headers(credential), "Idempotency-Key": rotation_key},
        json=rotation_body,
    )
    assert expired_replay.status_code == 409
    assert expired_replay.json()["error"]["code"] == "secret_replay_expired"
    with database.session_factory() as session:
        credentials = list(
            session.scalars(select(AgentCredential).where(AgentCredential.agent_id == agent_id))
        )
        assert sum(item.state == "active" for item in credentials) == 1
        pending_credential = session.get(AgentCredential, pending_id)
        assert pending_credential is not None
        assert pending_credential.state == "expired"
    database.close()


def test_phase04_concurrent_rotation_stubs_limits_and_redis_fail_closed(
    client: TestClient,
) -> None:
    access = login(client)
    _, registration = enroll_agent(client, access)
    credential = str(registration["credential"]["credential"])

    rotation_keys = [str(uuid4()), str(uuid4())]

    def rotate(key: str) -> int:
        return client.post(
            "/api/v1/agents/self/credential-rotations",
            headers={**agent_headers(credential), "Idempotency-Key": key},
            json={"schema_version": "1.0.0", "idempotency_key": key},
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        rotation_statuses = list(executor.map(rotate, rotation_keys))
    assert sorted(rotation_statuses) == [201, 409]

    progress = json.loads((contract_root() / "examples/valid/progress-event.json").read_text())
    progress_key = str(progress["idempotency_key"])
    accepted = client.post(
        "/api/internal/v1/agent-protocol/progress",
        headers={**agent_headers(credential), "Idempotency-Key": progress_key},
        json=progress,
    )
    assert accepted.status_code == 200
    invalid = {**progress, "unknown": True}
    assert (
        client.post(
            "/api/internal/v1/agent-protocol/progress",
            headers={**agent_headers(credential), "Idempotency-Key": progress_key},
            json=invalid,
        ).status_code
        == 422
    )
    oversized = {"padding": "x" * (1024 * 1024 + 1)}
    assert (
        client.post(
            "/api/internal/v1/agent-protocol/results",
            headers={**agent_headers(credential), "Idempotency-Key": str(uuid4())},
            json=oversized,
        ).status_code
        == 413
    )
    accepted_skew = agent_headers(credential, timestamp=datetime.now(UTC) - timedelta(seconds=299))
    assert (
        client.post("/api/internal/v1/agent-protocol/task-fetch", headers=accepted_skew).status_code
        == 200
    )

    class BrokenRedis:
        def eval(self, *_: object, **__: object) -> object:
            raise ConnectionError("synthetic Redis outage")

    client.app.state.agent_replay_guard._client = BrokenRedis()
    unavailable = client.post(
        "/api/internal/v1/agent-protocol/task-fetch",
        headers=agent_headers(credential),
    )
    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["code"] == "dependency_unavailable"


def test_phase05_desktop_client_uses_real_phase04_public_protocol(
    client: TestClient, tmp_path: Path
) -> None:
    import asyncio

    import httpx
    from wto_desktop_agent.application.capabilities import (
        CapabilityRegistry,
        ManifestService,
    )
    from wto_desktop_agent.application.heartbeat import HeartbeatService
    from wto_desktop_agent.application.identity import IdentityManager
    from wto_desktop_agent.infrastructure.http_transport import HttpAgentTransport
    from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
    from wto_desktop_agent.platforms.simulated.adapter import SimulatedPlatformAdapter
    from wto_desktop_agent.ports.time import SystemClock

    access = login(client)
    token_response = client.post(
        "/api/v1/enrollment-tokens",
        headers=auth_headers(access),
        json={
            "scope": "agent.enroll",
            "expires_in_minutes": 15,
            "allowed_platforms": ["simulated"],
        },
    )
    assert token_response.status_code == 201
    token = str(token_response.json()["enrollment_token"])

    def phase04_handler(request: httpx.Request) -> httpx.Response:
        response = client.request(
            request.method,
            request.url.path,
            headers=dict(request.headers),
            content=request.content,
        )
        return httpx.Response(
            response.status_code,
            headers=dict(response.headers),
            content=response.content,
            request=request,
        )

    async def scenario() -> None:
        async_client = httpx.AsyncClient(transport=httpx.MockTransport(phase04_handler))
        transport = HttpAgentTransport("https://testserver", timeout_seconds=5, client=async_client)
        store = SQLiteStore(tmp_path / "desktop-agent.sqlite3")
        store.initialize()
        platform = SimulatedPlatformAdapter()
        identity = IdentityManager(
            store,
            platform,
            transport,
            SystemClock(),
            allow_insecure_development_store=True,
        )
        await identity.enroll(token=token, display_name="Phase 05 integration agent")
        first_credential_id = store.identity()["active_credential_id"]  # type: ignore[index]
        await identity.rotate()
        assert store.identity()["active_credential_id"] != first_credential_id  # type: ignore[index]
        store.start_runtime(str(uuid4()))
        credential = identity.active_credential()
        manifest = await ManifestService(
            store,
            CapabilityRegistry(platform),
            transport,
            platform,
            SystemClock(),
        ).ensure_published(credential)
        heartbeat = await HeartbeatService(store, transport, SystemClock()).send(credential)
        assert len(manifest["capabilities"]) == 15
        assert heartbeat["sequence"] == 0
        assert store.pending_manifest() is None
        assert store.pending_heartbeat() is None
        await async_client.aclose()

    asyncio.run(scenario())
