from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, Self, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from wto_desktop_agent.application.artifacts import StagedArtifact
from wto_desktop_agent.platforms.linux.capture_fingerprint import (
    CaptureExecutionPlan,
    canonical_capture_fingerprint,
    canonical_capture_fingerprint_v1,
)
from wto_desktop_agent.platforms.linux.capture_identity import (
    IW_INTERFACE_TYPE_COMMAND_MAPPER_VERSION,
    CaptureInterfaceType,
    parse_capture_interface_type,
    validate_networkmanager_connection_id,
    validate_networkmanager_uuid,
)
from wto_desktop_agent.platforms.linux.capture_recovery import (
    CaptureBinding,
    CaptureFingerprint,
    CaptureManualRecoveryRequired,
    CaptureMarker,
    CaptureMarkerState,
    CaptureRecoveryStore,
)
from wto_desktop_agent.platforms.linux.frequency import (
    SUPPORTED_CAPTURE_WIDTHS_MHZ,
    capture_channel_definition,
    validate_complete_channel_definition,
    validate_frequency_channel_width,
)
from wto_desktop_agent.platforms.linux.journal_state import (
    classify_capture_journal_name,
    pending_name_matches_execution,
)
from wto_desktop_agent.platforms.linux.secure_fs import (
    FileIdentity,
    QuarantinedObject,
    capture_file_identity,
    close_descriptor,
    logical_quarantine,
    rename_noreplace,
)
from wto_desktop_agent.ports.plugins import CancellationToken

MONITOR_CAPTURE_CAPABILITY = "capture.ieee80211.monitor"
PCAP_REPLAY_CAPABILITY = "traffic.pcap.replay"
CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE = "control_plane_authorization_unavailable"
_FCHMOD = cast(Callable[[int, int], None] | None, getattr(os, "fchmod", None))
_NETWORK_MANAGER_RESTORE_SCHEMA_VERSION = "networkmanager-restore-v1"
_IW_INTERFACE_TYPE_MAPPER_VERSION = IW_INTERFACE_TYPE_COMMAND_MAPPER_VERSION


@dataclass(frozen=True)
class PrivilegedAuthorizationDecision:
    allowed: bool
    reason: str | None = None


class ControlPlaneAuthorization(Protocol):
    def authorize(
        self, *, agent_id: str | None, capability_id: str
    ) -> PrivilegedAuthorizationDecision: ...


class UnavailableControlPlaneAuthorization:
    """Production default until a server-issued authorization contract exists."""

    def authorize(
        self, *, agent_id: str | None, capability_id: str
    ) -> PrivilegedAuthorizationDecision:
        del agent_id, capability_id
        return PrivilegedAuthorizationDecision(
            allowed=False,
            reason=CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE,
        )


def privileged_capability_decision(
    *,
    agent_id: str | None,
    capability_id: str,
    authorization: ControlPlaneAuthorization,
    role_allowed: bool,
    policy_enabled: bool,
    provider_ready: bool,
    permissions_ready: bool,
    allowlists_ready: bool,
    technical_ready: bool,
) -> PrivilegedAuthorizationDecision:
    control_plane = authorization.authorize(
        agent_id=agent_id,
        capability_id=capability_id,
    )
    if not control_plane.allowed:
        return PrivilegedAuthorizationDecision(
            allowed=False,
            reason=control_plane.reason or CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE,
        )
    if agent_id is None:
        return PrivilegedAuthorizationDecision(False, CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE)
    checks = (
        (role_allowed, "local_role_denied"),
        (policy_enabled, "local_policy_denied"),
        (permissions_ready, "permission_denied"),
        (allowlists_ready, "local_allowlist_incomplete"),
        (provider_ready, "provider_unavailable"),
        (technical_ready, "technical_self_check_failed"),
    )
    for ready, reason in checks:
        if not ready:
            return PrivilegedAuthorizationDecision(False, reason)
    return PrivilegedAuthorizationDecision(True)


class StrictCaptureModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NetworkManagerConnectionProfileMissing(RuntimeError):
    """The exact UUID selected for rollback no longer exists in NetworkManager."""


class CaptureRequest(StrictCaptureModel):
    task_id: UUID
    execution_id: UUID
    idempotency_key: UUID
    interface: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")
    channel: int = Field(ge=1, le=233)
    frequency_mhz: int = Field(ge=2400, le=71_000)
    width_mhz: Literal[20, 80, 160] = 20
    duration_seconds: int = Field(ge=1, le=3600)
    max_size_bytes: int = Field(ge=1024, le=1_073_741_824)
    capture_format: Literal["pcap", "pcapng"] = "pcapng"
    radiotap: Literal[True] = True
    snapshot_length: int = Field(default=262_144, ge=64, le=262_144)

    @model_validator(mode="after")
    def channel_matches_frequency(self) -> CaptureRequest:
        validate_frequency_channel_width(
            frequency_mhz=self.frequency_mhz,
            channel=self.channel,
            width_mhz=self.width_mhz,
        )
        return self


class NetworkManagerConnectionObservation(StrictCaptureModel):
    connection_uuid: str
    interface: str
    restore_position: int = Field(ge=0)

    @field_validator("connection_uuid", mode="before")
    @classmethod
    def canonical_connection_uuid(cls, value: object) -> str:
        return validate_networkmanager_uuid(value)


class InterfaceState(StrictCaptureModel):
    interface: str
    interface_type: CaptureInterfaceType
    administratively_up: bool
    network_manager_managed: bool | None
    channel: int | None
    frequency_mhz: int | None
    width_mhz: int | None
    center_frequency_1_mhz: int | None = None
    center_frequency_2_mhz: int | None = None
    band: Literal["2.4GHz", "5GHz", "6GHz", "60GHz"] | None = None
    geometry_version: str | None = None
    active_connection_uuids: tuple[str, ...] = ()
    ordered_active_connection_uuids: tuple[str, ...] = ()
    active_connection_interfaces: tuple[NetworkManagerConnectionObservation, ...] = ()
    active_connections_status: Literal["complete", "partial", "unavailable"] = "unavailable"
    active_connections_provenance: tuple[str, ...] = ()
    active_connections_source_errors: tuple[str, ...] = ()
    network_manager_connection_uuid: str | None = None
    primary_connection_uuid: str | None = None
    network_manager_connection_name: str | None = None
    network_manager_restore_schema_version: str | None = None
    interface_type_command_mapper_version: str = _IW_INTERFACE_TYPE_MAPPER_VERSION
    namespace: str | None = None
    wiphy: str | None = None
    driver: str | None = None

    @model_validator(mode="before")
    @classmethod
    def complete_legacy_20_mhz_geometry(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        converted = dict(value)
        ordered_was_provided = "ordered_active_connection_uuids" in converted
        if "ordered_active_connection_uuids" not in converted:
            converted["ordered_active_connection_uuids"] = tuple(
                converted.get("active_connection_uuids", ())
            )
        if "active_connection_uuids" not in converted:
            converted["active_connection_uuids"] = tuple(
                converted.get("ordered_active_connection_uuids", ())
            )
        if "primary_connection_uuid" not in converted:
            converted["primary_connection_uuid"] = converted.get("network_manager_connection_uuid")
        if "network_manager_connection_uuid" not in converted:
            converted["network_manager_connection_uuid"] = converted.get("primary_connection_uuid")
        if not ordered_was_provided and converted.get("active_connections_status") == "complete":
            active = tuple(converted.get("active_connection_uuids", ()))
            primary = converted.get("primary_connection_uuid")
            if (
                primary is not None
                and primary in active
                and all(type(connection_uuid) is str for connection_uuid in active)
                and len(set(active)) == len(active)
            ):
                canonical_order = tuple(
                    [
                        *sorted(
                            connection_uuid
                            for connection_uuid in active
                            if connection_uuid != primary
                        ),
                        primary,
                    ]
                )
                converted["active_connection_uuids"] = canonical_order
                converted["ordered_active_connection_uuids"] = canonical_order
        ordered = tuple(converted.get("ordered_active_connection_uuids", ()))
        if "active_connection_interfaces" not in converted:
            interface = converted.get("interface")
            converted["active_connection_interfaces"] = tuple(
                {
                    "connection_uuid": connection_uuid,
                    "interface": interface,
                    "restore_position": position,
                }
                for position, connection_uuid in enumerate(ordered)
            )
        if (
            "network_manager_restore_schema_version" not in converted
            and converted.get("active_connections_status") == "complete"
        ):
            converted["network_manager_restore_schema_version"] = (
                _NETWORK_MANAGER_RESTORE_SCHEMA_VERSION
            )
        if "interface_type_command_mapper_version" not in converted:
            converted["interface_type_command_mapper_version"] = _IW_INTERFACE_TYPE_MAPPER_VERSION
        if (
            converted.get("width_mhz") == 20
            and converted.get("frequency_mhz") is not None
            and converted.get("center_frequency_1_mhz") is None
        ):
            # A 20 MHz center is identical to the observed control frequency,
            # so this is the only legacy geometry that can be completed safely.
            converted["center_frequency_1_mhz"] = converted["frequency_mhz"]
        radio_values = (
            converted.get("frequency_mhz"),
            converted.get("channel"),
            converted.get("width_mhz"),
            converted.get("center_frequency_1_mhz"),
        )
        if all(value is not None for value in radio_values):
            try:
                definition = validate_complete_channel_definition(
                    frequency_mhz=int(converted["frequency_mhz"]),
                    channel=int(converted["channel"]),
                    width_mhz=int(converted["width_mhz"]),
                    center_frequency_1_mhz=int(converted["center_frequency_1_mhz"]),
                    center_frequency_2_mhz=(
                        int(converted["center_frequency_2_mhz"])
                        if converted.get("center_frequency_2_mhz") is not None
                        else None
                    ),
                )
            except (TypeError, ValueError):
                return converted
            if converted.get("band") is None:
                converted["band"] = definition.band
            if converted.get("geometry_version") is None:
                converted["geometry_version"] = definition.geometry_version
        return converted

    @field_validator("interface_type", mode="before")
    @classmethod
    def canonical_interface_type(cls, value: object) -> CaptureInterfaceType:
        return parse_capture_interface_type(value)

    @field_validator("active_connection_uuids", "ordered_active_connection_uuids", mode="before")
    @classmethod
    def canonical_active_connection_uuids(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise ValueError("active NetworkManager UUIDs are invalid")
        return tuple(validate_networkmanager_uuid(item) for item in value)

    @field_validator("network_manager_connection_uuid", "primary_connection_uuid", mode="before")
    @classmethod
    def canonical_primary_connection_uuid(cls, value: object) -> str | None:
        if value is None:
            return None
        return validate_networkmanager_uuid(value)

    @field_validator("network_manager_connection_name", mode="before")
    @classmethod
    def safe_connection_display_name(cls, value: object) -> str | None:
        if value is None:
            return None
        return validate_networkmanager_connection_id(value)

    @model_validator(mode="after")
    def validate_networkmanager_restore_identity(self) -> InterfaceState:
        if self.active_connection_uuids != self.ordered_active_connection_uuids:
            raise ValueError("NetworkManager active connection order is inconsistent")
        if self.network_manager_connection_uuid != self.primary_connection_uuid:
            raise ValueError("NetworkManager primary connection identity is inconsistent")
        if len(set(self.ordered_active_connection_uuids)) != len(
            self.ordered_active_connection_uuids
        ):
            raise ValueError("NetworkManager active connection UUIDs are duplicated")
        if (
            self.active_connections_status == "complete"
            and self.primary_connection_uuid is not None
            and self.primary_connection_uuid in self.ordered_active_connection_uuids
        ):
            expected_order = tuple(
                [
                    *sorted(
                        connection_uuid
                        for connection_uuid in self.ordered_active_connection_uuids
                        if connection_uuid != self.primary_connection_uuid
                    ),
                    self.primary_connection_uuid,
                ]
            )
            if self.ordered_active_connection_uuids != expected_order:
                raise ValueError("NetworkManager restore order is not deterministic")
        observed = tuple(
            (item.connection_uuid, item.interface, item.restore_position)
            for item in self.active_connection_interfaces
        )
        expected = tuple(
            (connection_uuid, self.interface, position)
            for position, connection_uuid in enumerate(self.ordered_active_connection_uuids)
        )
        if observed != expected:
            raise ValueError("NetworkManager connection/interface associations are inconsistent")
        return self

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Keep private NetworkManager aliases coherent in provider state copies."""

        converted = dict(update or {})
        if "active_connection_uuids" in converted:
            converted.setdefault(
                "ordered_active_connection_uuids",
                converted["active_connection_uuids"],
            )
        elif "ordered_active_connection_uuids" in converted:
            converted["active_connection_uuids"] = converted["ordered_active_connection_uuids"]
        if "network_manager_connection_uuid" in converted:
            converted.setdefault(
                "primary_connection_uuid",
                converted["network_manager_connection_uuid"],
            )
        elif "primary_connection_uuid" in converted:
            converted["network_manager_connection_uuid"] = converted["primary_connection_uuid"]
        if (
            "active_connection_uuids" in converted
            or "ordered_active_connection_uuids" in converted
            or "interface" in converted
        ) and "active_connection_interfaces" not in converted:
            ordered = tuple(
                converted.get(
                    "ordered_active_connection_uuids",
                    self.ordered_active_connection_uuids,
                )
            )
            interface = str(converted.get("interface", self.interface))
            converted["active_connection_interfaces"] = tuple(
                NetworkManagerConnectionObservation(
                    connection_uuid=connection_uuid,
                    interface=interface,
                    restore_position=position,
                )
                for position, connection_uuid in enumerate(ordered)
            )
        return super().model_copy(update=converted, deep=deep)


@dataclass(frozen=True)
class NetworkManagerRestoreOperation:
    connection_uuid: str
    interface: str
    position: int
    primary: bool

    @property
    def step_name(self) -> str:
        prefix = "restore_primary_connection" if self.primary else "restore_connection"
        return f"{prefix}:{self.connection_uuid}"


def networkmanager_restore_plan(
    state: InterfaceState,
) -> tuple[NetworkManagerRestoreOperation, ...]:
    """Return the one validated, deterministic NetworkManager restore plan."""

    # ``model_copy(update=...)`` intentionally skips validation.  Revalidate
    # here because snapshots loaded from journals and test/provider adapters
    # must not bypass durable identity rules.
    validated = InterfaceState.model_validate(state.model_dump(mode="python"))
    if validated.active_connections_status != "complete":
        raise ValueError("NetworkManager active connection observation is incomplete")
    if validated.network_manager_restore_schema_version != _NETWORK_MANAGER_RESTORE_SCHEMA_VERSION:
        raise ValueError("NetworkManager restore schema is unsupported")
    active = validated.ordered_active_connection_uuids
    primary = validated.primary_connection_uuid
    if bool(active) != (primary is not None):
        raise ValueError("NetworkManager primary connection is unavailable")
    if primary is not None and primary not in active:
        raise ValueError("NetworkManager primary connection is not active")
    secondary = sorted(connection_uuid for connection_uuid in active if connection_uuid != primary)
    ordered = [*secondary]
    if primary is not None:
        ordered.append(primary)
    association_by_uuid = {
        item.connection_uuid: item.interface for item in validated.active_connection_interfaces
    }
    operations = tuple(
        NetworkManagerRestoreOperation(
            connection_uuid=connection_uuid,
            interface=association_by_uuid[connection_uuid],
            position=position,
            primary=connection_uuid == primary,
        )
        for position, connection_uuid in enumerate(ordered)
    )
    if any(operation.interface != validated.interface for operation in operations):
        raise ValueError("NetworkManager connection belongs to another interface")
    return operations


_CAPTURE_JOURNAL_SCHEMA_VERSION = "2.0.0"
_CAPTURE_JOURNAL_AUTHORITY_SCHEMA_VERSION = "2.1.0"


def _validate_capture_authority_payload(
    request: CaptureRequest,
    capture_authority: dict[str, object],
) -> None:
    expected_fields = {
        "task_id",
        "execution_id",
        "idempotency_key",
        "fingerprint_version",
        "fingerprint_sha256",
        "operation_token",
    }
    if set(capture_authority) != expected_fields:
        raise ValueError("capture journal authority fields are invalid")
    expected_ids = {
        "task_id": str(request.task_id),
        "execution_id": str(request.execution_id),
        "idempotency_key": str(request.idempotency_key),
    }
    if any(capture_authority[field] != value for field, value in expected_ids.items()):
        raise ValueError("capture journal authority IDs are inconsistent")
    if (
        not isinstance(capture_authority["fingerprint_version"], str)
        or not capture_authority["fingerprint_version"]
        or not isinstance(capture_authority["fingerprint_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", capture_authority["fingerprint_sha256"]) is None
        or not isinstance(capture_authority["operation_token"], str)
        or re.fullmatch(r"[0-9a-f]{32}", capture_authority["operation_token"]) is None
    ):
        raise ValueError("capture journal fingerprint authority is invalid")


def _encode_capture_journal(
    request: CaptureRequest,
    state: InterfaceState,
    *,
    recorded_at: str,
    capture_authority: dict[str, object] | None = None,
) -> bytes:
    payload: dict[str, object] = {
        "schema_version": (
            _CAPTURE_JOURNAL_AUTHORITY_SCHEMA_VERSION
            if capture_authority is not None
            else _CAPTURE_JOURNAL_SCHEMA_VERSION
        ),
        "execution_id": str(request.execution_id),
        "recorded_at": recorded_at,
        "request": request.model_dump(mode="json"),
        "interface_state": state.model_dump(mode="json"),
    }
    if capture_authority is not None:
        _validate_capture_authority_payload(request, capture_authority)
        payload["capture_authority"] = dict(capture_authority)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _validate_legacy_journal_state(value: object) -> InterfaceState:
    """Validate the only legacy state that can be classified automatically.

    Version 1 journals identified connections solely by display name. Any such
    identity remains manual recovery. A disconnected legacy state can be
    validated safely, including the historical ``mesh point`` spelling, but it
    is still kept as a recovery journal rather than used to mutate an interface.
    """

    if not isinstance(value, dict):
        raise ValueError("legacy capture journal state is invalid")
    converted = dict(value)
    if {
        "active_connection_uuids",
        "network_manager_connection_uuid",
        "network_manager_connection_name",
    } & converted.keys():
        raise ValueError("legacy capture journal mixes incompatible identity fields")
    legacy_connections = converted.pop("active_connections", ())
    legacy_primary = converted.pop("network_manager_connection", None)
    if legacy_connections or legacy_primary is not None:
        raise ValueError("legacy connection-name journal requires manual recovery")
    converted["active_connection_uuids"] = ()
    converted["network_manager_connection_uuid"] = None
    converted["network_manager_connection_name"] = None
    return InterfaceState.model_validate(converted)


class RollbackStep(StrictCaptureModel):
    name: str
    completed: bool
    reason: str | None = None
    operation_token: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    connection_uuid: str | None = None
    position: int | None = Field(default=None, ge=0)
    operation_state: Literal["planned", "confirmed", "failed"] | None = None
    evidence: str | None = None

    @field_validator("connection_uuid", mode="before")
    @classmethod
    def canonical_step_connection_uuid(cls, value: object) -> str | None:
        if value is None:
            return None
        return validate_networkmanager_uuid(value)

    @model_validator(mode="after")
    def validate_operation_state(self) -> RollbackStep:
        if self.operation_state == "planned" and self.completed:
            raise ValueError("planned rollback operation cannot be completed")
        if self.operation_state == "confirmed" and not self.completed:
            raise ValueError("confirmed rollback operation must be completed")
        if self.operation_state == "failed" and self.completed:
            raise ValueError("failed rollback operation cannot be completed")
        connection_fields = (
            self.operation_token,
            self.connection_uuid,
            self.position,
            self.operation_state,
        )
        if any(value is not None for value in connection_fields) and not all(
            value is not None for value in connection_fields
        ):
            raise ValueError("NetworkManager rollback operation evidence is incomplete")
        return self


class RollbackReport(StrictCaptureModel):
    complete: bool
    steps: tuple[RollbackStep, ...]
    verification: InterfaceState | None = None
    verification_status: Literal["complete", "partial", "unavailable", "mismatch"] = "unavailable"
    verification_reason: str | None = None
    mutations_confirmed: bool = False

    @model_validator(mode="after")
    def validate_completion_evidence(self) -> RollbackReport:
        if self.verification_status == "complete" and self.verification is None:
            raise ValueError("complete rollback verification lacks its snapshot")
        if not self.complete:
            return self
        if (
            len(self.steps) == 1
            and self.steps[0].name == "idempotent_reuse"
            and self.steps[0].completed
            and self.verification is None
            and self.verification_status == "unavailable"
            and self.verification_reason is None
            and not self.mutations_confirmed
        ):
            # The coordinator without a durable recovery store can reuse an
            # artifact before it has performed any interface mutation.  This
            # report describes that no-rollback path; durable bindings still
            # require full verification in ``capture_result_from_binding``.
            return self
        step_names = tuple(step.name for step in self.steps)
        legacy_verification = step_names[-1:] == ("verify",)
        current_verification = step_names[-3:] == (
            "verify_active_connections",
            "verify_primary_connection",
            "verify_interface_state",
        )
        verification_step_count = 1 if legacy_verification else 3
        if (
            not self.mutations_confirmed
            or self.verification is None
            or self.verification_status != "complete"
            or self.verification_reason is not None
            or not self.steps
            or not all(step.completed for step in self.steps)
            or not (legacy_verification or current_verification)
            or len(self.steps) <= verification_step_count
        ):
            raise ValueError("complete rollback report lacks durable verification evidence")
        return self


class RollbackVerificationAssessment(StrictCaptureModel):
    status: Literal["complete", "partial", "unavailable", "mismatch"]
    reason: str | None = None


class CaptureResult(StrictCaptureModel):
    status: Literal["completed", "failed", "cancelled"]
    artifact_path: Path | None
    artifact_manifest: dict[str, object] | None
    metadata: dict[str, object]
    rollback: RollbackReport
    reason: str | None = None


@dataclass(frozen=True)
class PreparedCaptureFingerprint:
    plan: CaptureExecutionPlan
    canonical_document: dict[str, object]
    fingerprint: CaptureFingerprint
    alternate_fingerprints: tuple[CaptureFingerprint, ...]


def prepare_capture_fingerprint(
    request: CaptureRequest,
    plan: CaptureExecutionPlan,
) -> PreparedCaptureFingerprint:
    """Create the one fingerprint authority used by reuse and new capture."""

    canonical = canonical_capture_fingerprint(request, plan)
    fingerprint = CaptureFingerprint(canonical.version, canonical.sha256)
    alternate_fingerprints: tuple[CaptureFingerprint, ...] = ()
    if request.width_mhz == 20:
        legacy = canonical_capture_fingerprint_v1(request, plan)
        alternate_fingerprints = (CaptureFingerprint(legacy.version, legacy.sha256),)
    return PreparedCaptureFingerprint(
        plan=plan,
        canonical_document=canonical.document,
        fingerprint=fingerprint,
        alternate_fingerprints=alternate_fingerprints,
    )


def authorize_capture_reuse(
    request: CaptureRequest,
    *,
    role: str,
    enabled: bool,
    agent_id_provider: Callable[[], str | None],
    authorization: ControlPlaneAuthorization,
    allowed_interfaces: frozenset[str],
    protected_interfaces: frozenset[str],
    allowed_channels: frozenset[int],
    allowed_frequencies_mhz: frozenset[int],
    allowed_widths_mhz: frozenset[int],
    max_duration_seconds: int,
    max_size_bytes: int,
) -> None:
    """Authorize binding access using static policy, never live readiness."""

    agent_id = agent_id_provider()
    control_plane = authorization.authorize(
        agent_id=agent_id,
        capability_id=MONITOR_CAPTURE_CAPABILITY,
    )
    if not control_plane.allowed or agent_id is None:
        raise PermissionError(control_plane.reason or CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE)
    if role not in {"capture_node", "lab_node"}:
        raise PermissionError("local_role_denied")
    if not enabled:
        raise PermissionError("local_policy_denied")
    if request.interface not in allowed_interfaces:
        raise PermissionError("capture interface is not allowlisted")
    if request.interface in protected_interfaces:
        raise PermissionError("capture interface is protected")
    if request.channel not in allowed_channels:
        raise PermissionError("capture channel is not allowlisted")
    if request.frequency_mhz not in allowed_frequencies_mhz:
        raise PermissionError("capture frequency is not allowlisted")
    if request.width_mhz not in allowed_widths_mhz:
        raise PermissionError("capture width is not allowlisted")
    if request.duration_seconds > max_duration_seconds:
        raise PermissionError("capture duration exceeds policy")
    if request.max_size_bytes > max_size_bytes:
        raise PermissionError("capture size exceeds policy")


def capture_result_from_binding(
    binding: CaptureBinding,
    artifact_path: Path,
    *,
    reused: bool,
) -> CaptureResult:
    metadata = dict(binding.metadata)
    if reused:
        metadata["reused"] = True
    try:
        if binding.status != "completed" or binding.reason is not None:
            raise ValueError("durable capture binding result is incoherent")
        rollback = RollbackReport.model_validate(binding.rollback)
        if not rollback.complete or rollback.verification is None:
            raise ValueError("durable capture binding rollback is incomplete")
        CaptureCoordinator._validate_completed_rollback_report(
            rollback.verification,
            rollback,
            rollback_operation_token=binding.authority.operation_token,
        )
    except ValueError as error:
        raise CaptureManualRecoveryRequired(
            "capture binding rollback evidence is invalid"
        ) from error
    return CaptureResult(
        status=cast(Literal["completed", "failed", "cancelled"], binding.status),
        artifact_path=artifact_path,
        artifact_manifest=dict(binding.manifest),
        metadata=metadata,
        rollback=rollback,
        reason=binding.reason,
    )


def resolve_capture_binding_locked(
    store: CaptureRecoveryStore,
    request: CaptureRequest,
    prepared: PreparedCaptureFingerprint,
) -> CaptureResult | None:
    """Resolve and hash-validate a binding while its idempotency lock is held."""

    binding = store.read_binding(
        task_id=request.task_id,
        execution_id=request.execution_id,
        idempotency_key=request.idempotency_key,
        fingerprint=prepared.fingerprint,
        alternate_fingerprints=prepared.alternate_fingerprints,
    )
    if binding is None:
        return None
    artifact_path = store.validate_binding_artifact(binding)
    return capture_result_from_binding(binding, artifact_path, reused=True)


class CaptureOperationError(RuntimeError):
    def __init__(self, reason: str, rollback: RollbackReport) -> None:
        super().__init__(reason)
        self.reason = reason
        self.rollback = rollback


class CaptureBackend(Protocol):
    async def is_connectivity_interface(self, interface: str) -> bool: ...

    async def monitor_supported(self, interface: str) -> bool: ...

    async def snapshot(self, interface: str) -> InterfaceState: ...

    def preflight(self, request: CaptureRequest, state: InterfaceState) -> None: ...

    def capture_plan(self, request: CaptureRequest) -> CaptureExecutionPlan: ...

    async def set_managed(self, interface: str, managed: bool) -> None: ...

    async def set_link(self, interface: str, up: bool) -> None: ...

    async def set_type(self, interface: str, interface_type: CaptureInterfaceType) -> None: ...

    async def set_frequency(
        self,
        interface: str,
        frequency_mhz: int,
        width_mhz: int,
        *,
        channel: int,
        center_frequency_1_mhz: int,
        center_frequency_2_mhz: int | None,
    ) -> None: ...

    async def restore_connection(self, interface: str, connection_uuid: str) -> None: ...

    async def capture(
        self,
        request: CaptureRequest,
        output_descriptor: int,
        cancellation: CancellationToken,
    ) -> None: ...


class ArtifactStager(Protocol):
    async def find_existing(
        self,
        identity: dict[str, object],
        task_id: UUID,
        *,
        cancellation: CancellationToken,
    ) -> StagedArtifact | None: ...

    async def stage(
        self,
        manifest: dict[str, object],
        path: Path,
        task_id: UUID,
        *,
        maximum_size_bytes: int,
        cancellation: CancellationToken,
    ) -> StagedArtifact: ...

    async def stage_from_descriptor(
        self,
        manifest: dict[str, object],
        descriptor: int,
        expected_identity: FileIdentity,
        task_id: UUID,
        *,
        maximum_size_bytes: int,
        cancellation: CancellationToken,
        capture_authority: dict[str, object] | None = None,
        intent_durable_callback: Callable[[dict[str, object]], None] | None = None,
    ) -> StagedArtifact: ...


class CaptureJournal(Protocol):
    async def pending(self, execution_id: UUID) -> bool: ...

    async def record(
        self,
        request: CaptureRequest,
        state: InterfaceState,
        *,
        capture_authority: dict[str, object] | None = None,
    ) -> None: ...

    async def recover_state(
        self,
        request: CaptureRequest,
        *,
        capture_authority: dict[str, object],
    ) -> InterfaceState | None: ...

    async def clear(self, execution_id: UUID) -> None: ...


class NullCaptureJournal:
    async def pending(self, execution_id: UUID) -> bool:
        del execution_id
        return False

    async def record(
        self,
        request: CaptureRequest,
        state: InterfaceState,
        *,
        capture_authority: dict[str, object] | None = None,
    ) -> None:
        del request, state, capture_authority

    async def recover_state(
        self,
        request: CaptureRequest,
        *,
        capture_authority: dict[str, object],
    ) -> InterfaceState | None:
        del request, capture_authority
        return None

    async def clear(self, execution_id: UUID) -> None:
        del execution_id


class FileCaptureJournal:
    _maximum_journal_bytes = 2 * 1024 * 1024

    def __init__(self, state_dir: Path) -> None:
        self.root = state_dir.resolve() / "capture-journal"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink():
            raise PermissionError("capture journal cannot be a symlink")
        os.chmod(self.root, 0o700)
        self._root_descriptor = os.open(
            self.root,
            os.O_RDONLY
            | int(getattr(os, "O_DIRECTORY", 0))
            | int(getattr(os, "O_CLOEXEC", 0))
            | int(getattr(os, "O_NOFOLLOW", 0)),
        )
        root_metadata = os.fstat(self._root_descriptor)
        expected_uid = int(getattr(os, "geteuid", lambda: root_metadata.st_uid)())
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != expected_uid
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            close_descriptor(self._root_descriptor, context="capture journal directory")
            raise PermissionError("capture journal directory ownership or mode is unsafe")
        self._expected_uid = expected_uid
        self._recovery_issues: list[str] = []
        try:
            self._recover_temporaries()
        except BaseException as error:
            descriptor = self._root_descriptor
            self._root_descriptor = -1
            close_descriptor(
                descriptor,
                primary_error=error,
                context="capture journal directory",
            )
            raise

    @property
    def recovery_issues(self) -> tuple[str, ...]:
        return tuple(self._recovery_issues)

    def _path(self, execution_id: UUID) -> Path:
        return self.root / f"{execution_id}.json"

    async def record(
        self,
        request: CaptureRequest,
        state: InterfaceState,
        *,
        capture_authority: dict[str, object] | None = None,
    ) -> None:
        await asyncio.to_thread(self._record, request, state, capture_authority)

    async def recover_state(
        self,
        request: CaptureRequest,
        *,
        capture_authority: dict[str, object],
    ) -> InterfaceState | None:
        return await asyncio.to_thread(
            self._recover_state,
            request,
            capture_authority,
        )

    async def pending(self, execution_id: UUID) -> bool:
        return await asyncio.to_thread(self._pending, execution_id)

    def _pending(self, execution_id: UUID) -> bool:
        final_name = f"{execution_id}.json"
        try:
            metadata = os.stat(
                final_name,
                dir_fd=self._root_descriptor,
                follow_symlinks=False,
            )
            if not stat.S_ISREG(metadata.st_mode):
                raise PermissionError("capture journal is not a regular file")
            return True
        except FileNotFoundError:
            with os.scandir(self._root_descriptor) as entries:
                for entry in entries:
                    if pending_name_matches_execution(entry.name, execution_id):
                        return True
            return False

    def _recover_state(
        self,
        request: CaptureRequest,
        capture_authority: dict[str, object],
    ) -> InterfaceState | None:
        name = f"{request.execution_id}.json"
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0)),
                dir_fd=self._root_descriptor,
            )
        except FileNotFoundError:
            return None
        primary: BaseException | None = None
        try:
            before = os.fstat(descriptor)
            identity = capture_file_identity(
                self._root_descriptor,
                name,
                descriptor,
                expected_uid=self._expected_uid,
                expected_mode=0o600,
            )
            encoded = self._read_descriptor_content(
                descriptor,
                maximum_bytes=self._maximum_journal_bytes,
            )
            after = os.fstat(descriptor)
            current = capture_file_identity(
                self._root_descriptor,
                name,
                descriptor,
                expected_uid=self._expected_uid,
                expected_mode=0o600,
            )
            if (
                current != identity
                or not identity.matches_with_size(before)
                or not identity.matches_with_size(after)
                or (before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_mtime_ns, after.st_ctime_ns)
            ):
                raise RuntimeError("capture journal changed during recovery")
            payload = json.loads(encoded.decode("utf-8"))
            expected_fields = {
                "schema_version",
                "execution_id",
                "recorded_at",
                "request",
                "interface_state",
                "capture_authority",
            }
            if (
                not isinstance(payload, dict)
                or set(payload) != expected_fields
                or payload.get("schema_version") != _CAPTURE_JOURNAL_AUTHORITY_SCHEMA_VERSION
                or payload.get("execution_id") != str(request.execution_id)
                or payload.get("request") != request.model_dump(mode="json")
                or payload.get("capture_authority") != capture_authority
            ):
                raise RuntimeError("capture journal authority is inconsistent")
            return InterfaceState.model_validate(payload["interface_state"])
        except BaseException as error:
            primary = error
            raise
        finally:
            close_descriptor(
                descriptor,
                primary_error=primary,
                context="capture journal recovery",
            )

    def _record(
        self,
        request: CaptureRequest,
        state: InterfaceState,
        capture_authority: dict[str, object] | None = None,
    ) -> None:
        final_name = f"{request.execution_id}.json"
        try:
            os.stat(final_name, dir_fd=self._root_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("capture journal already exists")
        payload = _encode_capture_journal(
            request,
            state,
            recorded_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            capture_authority=capture_authority,
        )
        if len(payload) > self._maximum_journal_bytes:
            raise ValueError("capture journal exceeded its size limit")
        temporary = f".{request.execution_id}.pending.{secrets.token_hex(24)}"
        descriptor = os.open(
            temporary,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | int(getattr(os, "O_CLOEXEC", 0))
            | int(getattr(os, "O_NOFOLLOW", 0)),
            0o600,
            dir_fd=self._root_descriptor,
        )
        identity: FileIdentity | None = None
        primary: BaseException | None = None
        published = False
        publication_invalid = False
        try:
            identity = capture_file_identity(
                self._root_descriptor,
                temporary,
                descriptor,
                expected_uid=self._expected_uid,
                expected_mode=0o600,
            )
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("capture journal write made no progress")
                view = view[written:]
            if _FCHMOD is None:
                raise RuntimeError("capture journal mode hardening requires fchmod")
            _FCHMOD(descriptor, 0o600)
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if metadata.st_size != len(payload):
                raise RuntimeError("capture journal size changed before publication")
            refreshed_identity = capture_file_identity(
                self._root_descriptor,
                temporary,
                descriptor,
                expected_uid=self._expected_uid,
                expected_mode=0o600,
            )
            if refreshed_identity != replace(identity, st_size=refreshed_identity.st_size):
                raise RuntimeError("capture journal identity changed before publication")
            identity = refreshed_identity
            rename_noreplace(
                self._root_descriptor,
                temporary,
                self._root_descriptor,
                final_name,
            )
            published = True
            final_metadata = os.stat(
                final_name,
                dir_fd=self._root_descriptor,
                follow_symlinks=False,
            )
            descriptor_metadata = os.fstat(descriptor)
            published_content = self._read_descriptor_content(
                descriptor,
                maximum_bytes=self._maximum_journal_bytes,
            )
            post_content_metadata = os.fstat(descriptor)
            post_content_named_metadata = os.stat(
                final_name,
                dir_fd=self._root_descriptor,
                follow_symlinks=False,
            )
            if (
                not identity.matches(final_metadata)
                or not identity.matches(descriptor_metadata)
                or not identity.matches(post_content_metadata)
                or not identity.matches(post_content_named_metadata)
                or final_metadata.st_size != len(payload)
                or descriptor_metadata.st_size != len(payload)
                or post_content_metadata.st_size != len(payload)
                or descriptor_metadata.st_mtime_ns != post_content_metadata.st_mtime_ns
                or published_content != payload
            ):
                publication_invalid = True
                raise RuntimeError("capture journal publication identity changed")
            self._fsync_root()
        except BaseException as error:
            primary = error
        if primary is not None:
            if identity is not None and not published:
                logical_quarantine(
                    identity,
                    quarantine_prefix=".capture-journal-manual-",
                    primary_error=primary,
                )
            elif published and publication_invalid:
                try:
                    recovery_name = self._quarantine_publication(
                        final_name,
                        request.execution_id,
                    )
                    primary.add_note(
                        f"manual recovery required for capture journal {recovery_name}"
                    )
                except BaseException as recovery_error:
                    primary.add_note(
                        "capture journal invalid publication quarantine also failed: "
                        f"{recovery_error!r}"
                    )
            elif published:
                primary.add_note(f"manual recovery required for capture journal {final_name}")
            else:
                primary.add_note(f"manual recovery may be required for capture journal {temporary}")
            _close_descriptor(descriptor, primary, "capture journal file")
            raise primary
        _close_descriptor(descriptor, None, "capture journal file")

    async def clear(self, execution_id: UUID) -> None:
        await asyncio.to_thread(self._clear, execution_id)

    def _clear(self, execution_id: UUID) -> None:
        name = f"{execution_id}.json"
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0)),
                dir_fd=self._root_descriptor,
            )
        except FileNotFoundError:
            self._fsync_root()
            return
        primary: BaseException | None = None
        try:
            identity = capture_file_identity(
                self._root_descriptor,
                name,
                descriptor,
                expected_uid=self._expected_uid,
                expected_mode=0o600,
            )
            deletion = logical_quarantine(
                identity,
                quarantine_prefix=".capture-journal-retired-",
            )
            if not deletion.logical_deletion_confirmed:
                raise RuntimeError("capture journal logical quarantine was not durable")
        except BaseException as error:
            primary = error
            raise
        finally:
            _close_descriptor(descriptor, primary, "capture journal file")

    def _fsync_root(self) -> None:
        os.fsync(self._root_descriptor)

    def _quarantine_publication(self, name: str, execution_id: UUID) -> str:
        quarantine_name = f".{execution_id}.recovery.{secrets.token_hex(24)}"
        rename_noreplace(
            self._root_descriptor,
            name,
            self._root_descriptor,
            quarantine_name,
        )
        self._fsync_root()
        return quarantine_name

    @staticmethod
    def _read_descriptor_content(descriptor: int, *, maximum_bytes: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        result = bytearray()
        while True:
            remaining = maximum_bytes + 1 - len(result)
            if remaining <= 0:
                raise ValueError("capture journal exceeded its size limit")
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            result.extend(chunk)
        if len(result) > maximum_bytes:
            raise ValueError("capture journal exceeded its size limit")
        return bytes(result)

    def _recover_temporaries(self) -> None:
        with os.scandir(self._root_descriptor) as entries:
            names = tuple(entry.name for entry in entries)
        for name in names:
            classified = classify_capture_journal_name(name)
            if classified.classification != "pending":
                if classified.classification in {
                    "manual_recovery",
                    "invalid_ambiguous",
                }:
                    self._recovery_issues.append(f"{name}:manual_recovery_required")
                continue
            if classified.execution_id is None:
                self._recovery_issues.append(f"{name}:manual_recovery_required")
                continue
            execution_id = UUID(classified.execution_id)
            descriptor: int | None = None
            primary: BaseException | None = None
            identity: FileIdentity | None = None
            published_name: str | None = None
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | int(getattr(os, "O_CLOEXEC", 0))
                    | int(getattr(os, "O_NOFOLLOW", 0)),
                    dir_fd=self._root_descriptor,
                )
                metadata = os.fstat(descriptor)
                identity = capture_file_identity(
                    self._root_descriptor,
                    name,
                    descriptor,
                    expected_uid=self._expected_uid,
                    expected_mode=0o600,
                )
                if metadata.st_size <= 0 or metadata.st_size > self._maximum_journal_bytes:
                    raise ValueError("capture journal temporary size is invalid")
                encoded = bytearray()
                while len(encoded) < metadata.st_size:
                    chunk = os.read(descriptor, metadata.st_size - len(encoded))
                    if not chunk:
                        raise EOFError("capture journal temporary is incomplete")
                    encoded.extend(chunk)
                if os.read(descriptor, 1):
                    raise ValueError("capture journal temporary grew during recovery")
                post_read_metadata = os.fstat(descriptor)
                if (
                    not identity.matches(post_read_metadata)
                    or post_read_metadata.st_size != metadata.st_size
                    or post_read_metadata.st_mtime_ns != metadata.st_mtime_ns
                ):
                    raise RuntimeError("capture journal content changed during recovery")
                payload = json.loads(bytes(encoded).decode("utf-8"))
                base_fields = {
                    "schema_version",
                    "execution_id",
                    "recorded_at",
                    "request",
                    "interface_state",
                }
                schema_version = (
                    payload.get("schema_version") if isinstance(payload, dict) else None
                )
                expected_fields = set(base_fields)
                if schema_version == _CAPTURE_JOURNAL_AUTHORITY_SCHEMA_VERSION:
                    expected_fields.add("capture_authority")
                if not isinstance(payload, dict) or set(payload) != expected_fields:
                    raise ValueError("capture journal temporary payload is invalid")
                request = CaptureRequest.model_validate(payload["request"])
                if schema_version in {
                    _CAPTURE_JOURNAL_SCHEMA_VERSION,
                    _CAPTURE_JOURNAL_AUTHORITY_SCHEMA_VERSION,
                }:
                    InterfaceState.model_validate(payload["interface_state"])
                    if schema_version == _CAPTURE_JOURNAL_AUTHORITY_SCHEMA_VERSION:
                        authority = payload.get("capture_authority")
                        if not isinstance(authority, dict):
                            raise ValueError("capture journal authority is invalid")
                        _validate_capture_authority_payload(request, authority)
                elif schema_version == "1.0.0":
                    _validate_legacy_journal_state(payload["interface_state"])
                else:
                    raise ValueError("capture journal schema is unsupported")
                if (
                    str(execution_id) != payload.get("execution_id")
                    or request.execution_id != execution_id
                ):
                    raise ValueError("capture journal temporary identity is inconsistent")
                if not identity.matches(os.fstat(descriptor)):
                    raise RuntimeError("capture journal temporary identity changed")
                refreshed_identity = capture_file_identity(
                    self._root_descriptor,
                    name,
                    descriptor,
                    expected_uid=self._expected_uid,
                    expected_mode=0o600,
                )
                if refreshed_identity != identity:
                    raise RuntimeError("capture journal temporary identity changed")
                final_name = f"{execution_id}.json"
                rename_noreplace(
                    self._root_descriptor,
                    name,
                    self._root_descriptor,
                    final_name,
                )
                published_name = final_name
                final_metadata = os.stat(
                    final_name,
                    dir_fd=self._root_descriptor,
                    follow_symlinks=False,
                )
                descriptor_metadata = os.fstat(descriptor)
                published_content = self._read_descriptor_content(
                    descriptor,
                    maximum_bytes=self._maximum_journal_bytes,
                )
                post_content_metadata = os.fstat(descriptor)
                post_content_named_metadata = os.stat(
                    final_name,
                    dir_fd=self._root_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not identity.matches(final_metadata)
                    or not identity.matches(descriptor_metadata)
                    or not identity.matches(post_content_metadata)
                    or not identity.matches(post_content_named_metadata)
                    or final_metadata.st_size != metadata.st_size
                    or descriptor_metadata.st_size != metadata.st_size
                    or post_content_metadata.st_size != metadata.st_size
                    or final_metadata.st_mtime_ns != metadata.st_mtime_ns
                    or descriptor_metadata.st_mtime_ns != metadata.st_mtime_ns
                    or post_content_metadata.st_mtime_ns != metadata.st_mtime_ns
                    or published_content != bytes(encoded)
                ):
                    raise RuntimeError("capture journal publication identity changed")
                self._fsync_root()
            except BaseException as error:
                primary = error
                issue_name = name
                if published_name is not None:
                    try:
                        quarantine_name = self._quarantine_publication(
                            published_name,
                            execution_id,
                        )
                        issue_name = quarantine_name
                    except BaseException as recovery_error:
                        error.add_note(
                            "capture journal invalid publication quarantine also failed: "
                            f"{recovery_error!r}"
                        )
                        issue_name = published_name
                self._recovery_issues.append(
                    f"{issue_name}:{type(error).__name__}:manual_recovery_required"
                )
            finally:
                if descriptor is not None:
                    _close_descriptor(descriptor, primary, "capture journal recovery file")

    def close(self) -> None:
        descriptor = getattr(self, "_root_descriptor", -1)
        if descriptor < 0:
            return
        self._root_descriptor = -1
        close_descriptor(descriptor, context="capture journal directory")

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass


def _close_descriptor(descriptor: int, primary: BaseException | None, context: str) -> None:
    try:
        os.close(descriptor)
    except BaseException as close_error:
        if primary is None:
            raise
        primary.add_note(f"secondary {context} close failure: {close_error!r}")


@dataclass
class ReservedCaptureOutput:
    path: Path
    descriptor: int
    directory_descriptor: int
    identity: FileIdentity
    closed: bool = False
    quarantine_result: QuarantinedObject | None = None

    def validate_completed(self, maximum_size_bytes: int) -> int:
        os.fsync(self.descriptor)
        metadata = os.fstat(self.descriptor)
        if not self.identity.matches(metadata):
            raise PermissionError("capture output identity changed")
        current = capture_file_identity(
            self.directory_descriptor,
            self.identity.relative_name,
            self.descriptor,
            expected_uid=self.identity.st_uid,
            expected_mode=0o600,
        )
        if current != replace(self.identity, st_size=current.st_size):
            raise PermissionError("capture output pathname identity changed")
        size = int(metadata.st_size)
        if size <= 0 or size > maximum_size_bytes:
            raise RuntimeError("capture output size limit was violated")
        self.identity = current
        return size

    def hash_completed(self, maximum_size_bytes: int) -> tuple[int, str, os.stat_result]:
        size = self.validate_completed(maximum_size_bytes)
        before = os.fstat(self.descriptor)
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(self.descriptor, 1_048_576)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
        after = os.fstat(self.descriptor)
        current = capture_file_identity(
            self.directory_descriptor,
            self.identity.relative_name,
            self.descriptor,
            expected_uid=self.identity.st_uid,
            expected_mode=0o600,
        )
        if (
            observed != size
            or not self.identity.matches_with_size(before)
            or not self.identity.matches_with_size(after)
            or current != self.identity
            or (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise RuntimeError("capture output changed while hashing")
        return size, digest.hexdigest(), after

    def quarantine(self, *, primary_error: BaseException | None = None) -> QuarantinedObject:
        if self.quarantine_result is not None:
            return self.quarantine_result
        result = logical_quarantine(
            self.identity,
            quarantine_prefix=".capture-output-quarantine-",
            primary_error=primary_error,
        )
        if result.logical_deletion_confirmed:
            self.quarantine_result = result
        return result

    def close(self, *, primary_error: BaseException | None = None) -> None:
        if self.closed:
            return
        self.closed = True
        close_error: BaseException | None = None
        try:
            close_descriptor(
                self.descriptor,
                primary_error=primary_error,
                context="capture output",
            )
        except BaseException as error:
            close_error = error
        anchor = primary_error or close_error
        try:
            close_descriptor(
                self.directory_descriptor,
                primary_error=anchor,
                context="capture output directory",
            )
        except BaseException as error:
            close_error = close_error or error
        if primary_error is None and close_error is not None:
            raise close_error


class CaptureWorkspace:
    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.is_symlink():
            raise PermissionError("capture workspace cannot be a symlink")
        self.root = root.resolve()
        if os.name == "posix":
            os.chmod(self.root, 0o700)
        flags = (
            os.O_RDONLY
            | int(getattr(os, "O_DIRECTORY", 0))
            | int(getattr(os, "O_CLOEXEC", 0))
            | int(getattr(os, "O_NOFOLLOW", 0))
        )
        self._root_descriptor = os.open(self.root, flags)
        metadata = os.fstat(self._root_descriptor)
        expected_uid = int(getattr(os, "geteuid", lambda: metadata.st_uid)())
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            close_descriptor(self._root_descriptor, context="capture workspace")
            raise PermissionError("capture workspace ownership or mode is unsafe")

    @staticmethod
    def _validated_source_name(
        execution_id: UUID,
        capture_format: str,
        source_name: str | None,
    ) -> str:
        if capture_format not in {"pcap", "pcapng"}:
            raise ValueError("capture source format is invalid")
        legacy = f"capture-{execution_id}.{capture_format}"
        if source_name is None:
            return legacy
        tokenized = re.compile(
            rf"^capture-{re.escape(str(execution_id))}-[0-9a-f]{{32}}\."
            rf"{re.escape(capture_format)}$"
        )
        if tokenized.fullmatch(source_name) is None:
            raise ValueError("capture source name is not authorized for this operation")
        return source_name

    def reserve(
        self,
        execution_id: UUID,
        capture_format: str,
        *,
        source_name: str | None = None,
    ) -> ReservedCaptureOutput:
        if self._root_descriptor < 0:
            raise RuntimeError("capture workspace is closed")
        name = self._validated_source_name(execution_id, capture_format, source_name)
        directory_descriptor = os.dup(self._root_descriptor)
        descriptor: int | None = None
        primary: BaseException | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | int(getattr(os, "O_CLOEXEC", 0))
                | int(getattr(os, "O_NOFOLLOW", 0)),
                0o600,
                dir_fd=directory_descriptor,
            )
            metadata = os.fstat(descriptor)
            expected_uid = int(getattr(os, "geteuid", lambda: metadata.st_uid)())
            identity = capture_file_identity(
                directory_descriptor,
                name,
                descriptor,
                expected_uid=expected_uid,
                expected_mode=0o600,
            )
            return ReservedCaptureOutput(
                path=self.root / name,
                descriptor=descriptor,
                directory_descriptor=directory_descriptor,
                identity=identity,
            )
        except BaseException as error:
            primary = error
            if descriptor is not None:
                try:
                    identity = capture_file_identity(
                        directory_descriptor,
                        name,
                        descriptor,
                    )
                    logical_quarantine(
                        identity,
                        quarantine_prefix=".capture-output-quarantine-",
                        primary_error=error,
                    )
                except BaseException as cleanup_error:
                    error.add_note(f"capture reservation cleanup also failed: {cleanup_error!r}")
            raise
        finally:
            if primary is not None:
                if descriptor is not None:
                    close_descriptor(
                        descriptor,
                        primary_error=primary,
                        context="capture reservation",
                    )
                close_descriptor(
                    directory_descriptor,
                    primary_error=primary,
                    context="capture reservation directory",
                )

    def open_reserved(
        self,
        execution_id: UUID,
        capture_format: str,
        *,
        expected: dict[str, object] | None = None,
        source_name: str | None = None,
    ) -> ReservedCaptureOutput:
        if self._root_descriptor < 0:
            raise RuntimeError("capture workspace is closed")
        name = self._validated_source_name(execution_id, capture_format, source_name)
        directory_descriptor = os.dup(self._root_descriptor)
        descriptor = -1
        primary: BaseException | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0)),
                dir_fd=directory_descriptor,
            )
            metadata = os.fstat(descriptor)
            identity = capture_file_identity(
                directory_descriptor,
                name,
                descriptor,
                expected_uid=int(getattr(os, "geteuid", lambda: metadata.st_uid)()),
                expected_mode=0o600,
            )
            if expected is not None:
                observed = {
                    "directory_dev": identity.directory_dev,
                    "directory_ino": identity.directory_ino,
                    "st_dev": identity.st_dev,
                    "st_ino": identity.st_ino,
                    "st_uid": identity.st_uid,
                    "file_type": identity.file_type,
                    "mode": identity.mode,
                    "st_nlink": identity.st_nlink,
                }
                if observed != expected:
                    raise PermissionError("reserved capture inode changed")
            return ReservedCaptureOutput(
                path=self.root / name,
                descriptor=descriptor,
                directory_descriptor=directory_descriptor,
                identity=identity,
            )
        except BaseException as error:
            primary = error
            raise
        finally:
            if primary is not None:
                if descriptor >= 0:
                    close_descriptor(
                        descriptor,
                        primary_error=primary,
                        context="reserved capture",
                    )
                close_descriptor(
                    directory_descriptor,
                    primary_error=primary,
                    context="capture workspace directory",
                )

    def close(self) -> None:
        descriptor = getattr(self, "_root_descriptor", -1)
        if descriptor < 0:
            return
        self._root_descriptor = -1
        close_descriptor(descriptor, context="capture workspace directory")

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass


@dataclass(frozen=True)
class CaptureLiveDependencies:
    workspace: CaptureWorkspace
    stager: ArtifactStager
    journal: CaptureJournal
    recovery_store: CaptureRecoveryStore


class CaptureCoordinator:
    def __init__(
        self,
        backend: CaptureBackend,
        workspace: CaptureWorkspace | None,
        stager: ArtifactStager | None,
        journal: CaptureJournal | None = None,
        *,
        role: str,
        enabled: bool,
        agent_id_provider: Callable[[], str | None],
        authorization: ControlPlaneAuthorization,
        provider_ready: bool,
        privileged_ready: bool,
        technical_ready: bool,
        tree_containment_ready: bool | Callable[[], bool] = False,
        allowed_interfaces: frozenset[str],
        protected_interfaces: frozenset[str],
        allowed_channels: frozenset[int],
        allowed_frequencies_mhz: frozenset[int],
        allowed_widths_mhz: frozenset[int],
        max_duration_seconds: int,
        max_size_bytes: int,
        recovery_store: CaptureRecoveryStore | None = None,
        provider_version: str | None = None,
        live_dependencies_factory: Callable[[], CaptureLiveDependencies] | None = None,
    ) -> None:
        self.backend = backend
        self.workspace = cast(CaptureWorkspace, workspace)
        self.stager = cast(ArtifactStager, stager)
        self.journal = journal or NullCaptureJournal()
        self.role = role
        self.enabled = enabled
        self.agent_id_provider = agent_id_provider
        self.authorization = authorization
        self.provider_ready = provider_ready
        self.privileged_ready = privileged_ready
        self.technical_ready = technical_ready
        self._tree_containment_readiness = (
            tree_containment_ready
            if callable(tree_containment_ready)
            else lambda: tree_containment_ready
        )
        self.allowed_interfaces = allowed_interfaces
        self.protected_interfaces = protected_interfaces
        self.allowed_channels = allowed_channels
        self.allowed_frequencies_mhz = allowed_frequencies_mhz
        self.allowed_widths_mhz = allowed_widths_mhz
        self.max_duration_seconds = max_duration_seconds
        self.max_size_bytes = max_size_bytes
        self.recovery_store = recovery_store
        self.provider_version = provider_version
        self._live_dependencies_factory = live_dependencies_factory
        self._execution_lock = asyncio.Lock()

    @property
    def tree_containment_ready(self) -> bool:
        return bool(self._tree_containment_readiness())

    async def execute(
        self, request: CaptureRequest, cancellation: CancellationToken
    ) -> CaptureResult:
        if self._execution_lock.locked():
            raise RuntimeError("capture concurrency limit is one")
        async with self._execution_lock:
            return await self._execute_once(request, cancellation)

    async def _execute_once(
        self, request: CaptureRequest, cancellation: CancellationToken
    ) -> CaptureResult:
        if self.recovery_store is None and self._live_dependencies_factory is None:
            return await self._execute_without_recovery_store(request, cancellation)
        return await self._execute_durable(request, cancellation)

    def _initialize_live_dependencies(self) -> None:
        if self.recovery_store is not None:
            return
        if self._live_dependencies_factory is None:
            raise RuntimeError("durable capture dependencies are unavailable")
        dependencies = self._live_dependencies_factory()
        self.workspace = dependencies.workspace
        self.stager = dependencies.stager
        self.journal = dependencies.journal
        self.recovery_store = dependencies.recovery_store

    async def _execute_durable(
        self, request: CaptureRequest, cancellation: CancellationToken
    ) -> CaptureResult:
        self._authorize_reuse(request)
        plan = self.backend.capture_plan(request)
        prepared = prepare_capture_fingerprint(request, plan)
        original: InterfaceState | None = None
        if self.recovery_store is None:
            self._authorize_policy(request)
            await self._authorize_interface(request)
            original = await self.backend.snapshot(request.interface)
            self._validate_restorable_snapshot(request, original)
            self.backend.preflight(request, original)
            self._initialize_live_dependencies()
        store = cast(CaptureRecoveryStore, self.recovery_store)

        operation_lock = store.acquire_operation_lock(request.idempotency_key)
        primary: BaseException | None = None
        try:
            return await self._execute_durable_locked(
                request,
                cancellation,
                prepared=prepared,
                original=original,
            )
        except BaseException as error:
            primary = error
            raise
        finally:
            operation_lock.close(primary_error=primary)

    async def _execute_durable_locked(
        self,
        request: CaptureRequest,
        cancellation: CancellationToken,
        *,
        prepared: PreparedCaptureFingerprint,
        original: InterfaceState | None,
    ) -> CaptureResult:
        store = cast(CaptureRecoveryStore, self.recovery_store)

        reused = resolve_capture_binding_locked(store, request, prepared)
        if reused is not None:
            return reused

        identity = self._artifact_identity(request)
        marker_exists = store.marker_exists(request.idempotency_key)
        if marker_exists:
            original = None
        if not marker_exists:
            if original is None:
                self._authorize_policy(request)
                await self._authorize_interface(request)
                original = await self.backend.snapshot(request.interface)
                self._validate_restorable_snapshot(request, original)
                self.backend.preflight(request, original)
            legacy = await self.stager.find_existing(
                identity,
                request.task_id,
                cancellation=cancellation,
            )
            if legacy is not None:
                raise CaptureManualRecoveryRequired(
                    "capture artifact exists without a fingerprinted binding"
                )

        marker, created = store.begin_marker(
            task_id=request.task_id,
            execution_id=request.execution_id,
            idempotency_key=request.idempotency_key,
            fingerprint=prepared.fingerprint,
            request=prepared.canonical_document,
            capture_format=request.capture_format,
        )
        primary: BaseException | None = None
        try:
            store.validate_marker_root(marker.snapshot)
            needs_live_snapshot = marker.snapshot.state is CaptureMarkerState.RESERVATION_PLANNED
            if marker.snapshot.state is CaptureMarkerState.RESERVED:
                needs_live_snapshot = not await self.journal.pending(request.execution_id)
            if original is None and needs_live_snapshot:
                self._authorize_policy(request)
                await self._authorize_interface(request)
                original = await self.backend.snapshot(request.interface)
                self._validate_restorable_snapshot(request, original)
                self.backend.preflight(request, original)
            return await self._continue_durable_capture(
                request,
                cancellation,
                original,
                prepared.plan,
                identity,
                marker,
                created=created,
            )
        except BaseException as error:
            primary = error
            raise
        finally:
            marker.close(primary_error=primary)

    async def _continue_durable_capture(
        self,
        request: CaptureRequest,
        cancellation: CancellationToken,
        original: InterfaceState | None,
        plan: CaptureExecutionPlan,
        identity: dict[str, object],
        marker: CaptureMarker,
        *,
        created: bool,
    ) -> CaptureResult:
        del created
        output: ReservedCaptureOutput | None = None
        state = marker.snapshot.state
        authority_payload = marker.snapshot.authority.intent_payload()
        source_name = str(marker.snapshot.planned["source_name"])

        if state is CaptureMarkerState.RESERVATION_PLANNED:
            try:
                output = self.workspace.open_reserved(
                    request.execution_id,
                    request.capture_format,
                    source_name=source_name,
                )
            except FileNotFoundError:
                output = self.workspace.reserve(
                    request.execution_id,
                    request.capture_format,
                    source_name=source_name,
                )
            else:
                if os.fstat(output.descriptor).st_size != 0:
                    output.close()
                    raise CaptureManualRecoveryRequired(
                        "planned capture has an unexpected non-empty source"
                    )
            try:
                marker.advance(
                    CaptureMarkerState.RESERVED,
                    self._reserved_marker_details(output),
                )
            except BaseException as error:
                output.close(primary_error=error)
                raise
            state = marker.snapshot.state

        if state is CaptureMarkerState.RESERVED:
            reserved = marker.snapshot.detail(CaptureMarkerState.RESERVED)
            assert reserved is not None
            if output is None:
                output = self.workspace.open_reserved(
                    request.execution_id,
                    request.capture_format,
                    expected=reserved,
                    source_name=source_name,
                )
            if os.fstat(output.descriptor).st_size != 0:
                output.close()
                raise CaptureManualRecoveryRequired(
                    "reserved capture contains bytes without a completion marker"
                )
            if await self.journal.pending(request.execution_id):
                recovery_state = await self.journal.recover_state(
                    request,
                    capture_authority=authority_payload,
                )
                if recovery_state is None:
                    output.close()
                    raise CaptureManualRecoveryRequired(
                        "capture mutation evidence lacks its interface snapshot"
                    )
                self._validate_recovery_snapshot(request, recovery_state)
                rollback = await self._durable_rollback(marker, recovery_state)
                if not rollback.complete:
                    output.close()
                    raise CaptureOperationError("rollback_incomplete", rollback)
                await self.journal.clear(request.execution_id)
                quarantine = output.quarantine()
                source_quarantine = quarantine.quarantine_name
                output.close()
                marker.retire_aborted(
                    reason="recovered_incomplete_capture",
                    source_quarantine_name=source_quarantine,
                )
                raise CaptureOperationError("recovered_incomplete_capture", rollback)

            if original is None:
                output.close()
                raise CaptureManualRecoveryRequired(
                    "new capture lacks an authorized interface snapshot"
                )
            await self.journal.record(
                request,
                original,
                capture_authority=authority_payload,
            )
            started = datetime.now(UTC)
            primary: BaseException | None = None
            try:
                await self._mutate_and_capture(request, output, cancellation, original)
                size, digest, metadata = output.hash_completed(request.max_size_bytes)
                marker.advance(
                    CaptureMarkerState.CAPTURE_COMPLETE,
                    {
                        "size_bytes": size,
                        "sha256": digest,
                        "st_mtime_ns": int(metadata.st_mtime_ns),
                        "st_ctime_ns": int(metadata.st_ctime_ns),
                        "started_at": started.isoformat().replace("+00:00", "Z"),
                    },
                )
            except BaseException as error:
                primary = error
            if primary is not None:
                rollback = await self._durable_rollback(marker, original)
                if rollback.complete:
                    await self.journal.clear(request.execution_id)
                    quarantine = output.quarantine(primary_error=primary)
                    output.close(primary_error=primary)
                    marker.retire_aborted(
                        reason=(
                            "cancelled"
                            if isinstance(primary, asyncio.CancelledError)
                            else type(primary).__name__
                        ),
                        source_quarantine_name=quarantine.quarantine_name,
                    )
                else:
                    output.close(primary_error=primary)
                reason = (
                    "cancelled"
                    if isinstance(primary, asyncio.CancelledError)
                    else type(primary).__name__
                )
                raise CaptureOperationError(reason, rollback) from primary
            state = marker.snapshot.state

        if state in {
            CaptureMarkerState.CAPTURE_COMPLETE,
            CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING,
        }:
            reserved = marker.snapshot.detail(CaptureMarkerState.RESERVED)
            completed = marker.snapshot.detail(CaptureMarkerState.CAPTURE_COMPLETE)
            assert reserved is not None
            if output is None:
                output = self.workspace.open_reserved(
                    request.execution_id,
                    request.capture_format,
                    expected=reserved,
                    source_name=source_name,
                )
            if completed is None:
                if state is not CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING:
                    output.close()
                    raise CaptureManualRecoveryRequired(
                        "capture rollback marker lacks capture outcome"
                    )
                pending_detail = marker.snapshot.detail(
                    CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING
                )
                if pending_detail is None:
                    output.close()
                    raise CaptureManualRecoveryRequired(
                        "rollback verification marker lacks its durable report"
                    )
                pending_report = RollbackReport.model_validate(pending_detail["rollback"])
                rollback_state = await self.journal.recover_state(
                    request,
                    capture_authority=authority_payload,
                )
                if rollback_state is None:
                    if not pending_report.complete or pending_report.verification is None:
                        output.close()
                        raise CaptureManualRecoveryRequired(
                            "incomplete capture rollback lacks its interface journal"
                        )
                    rollback_state = pending_report.verification
                self._validate_recovery_snapshot(request, rollback_state)
                if pending_report.complete:
                    self._validate_completed_rollback_report(
                        rollback_state,
                        pending_report,
                        rollback_operation_token=(marker.snapshot.authority.operation_token),
                    )
                    rollback = pending_report
                else:
                    rollback = await self._durable_rollback(marker, rollback_state)
                if not rollback.complete:
                    output.close()
                    reason = (
                        "rollback_mismatch"
                        if rollback.verification_status == "mismatch"
                        else "rollback_verification_pending"
                    )
                    raise CaptureOperationError(reason, rollback)
                if await self.journal.pending(request.execution_id):
                    await self.journal.clear(request.execution_id)
                quarantine = output.quarantine()
                output.close()
                marker.retire_aborted(
                    reason="recovered_incomplete_capture",
                    source_quarantine_name=quarantine.quarantine_name,
                )
                raise CaptureOperationError("recovered_incomplete_capture", rollback)
            size, digest, metadata = output.hash_completed(request.max_size_bytes)
            if (
                size != completed["size_bytes"]
                or digest != completed["sha256"]
                or int(metadata.st_mtime_ns) != completed["st_mtime_ns"]
                or int(metadata.st_ctime_ns) != completed["st_ctime_ns"]
            ):
                output.close()
                raise CaptureManualRecoveryRequired("completed capture content changed")
            rollback_state = await self.journal.recover_state(
                request,
                capture_authority=authority_payload,
            )
            if rollback_state is None:
                output.close()
                raise CaptureManualRecoveryRequired(
                    "completed capture lacks its interface recovery journal"
                )
            self._validate_recovery_snapshot(request, rollback_state)
            rollback = await self._durable_rollback(marker, rollback_state)
            if not rollback.complete:
                output.close()
                reason = (
                    "rollback_mismatch"
                    if rollback.verification_status == "mismatch"
                    else "rollback_verification_pending"
                )
                raise CaptureOperationError(reason, rollback)
            finished = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            result_metadata = self._capture_metadata(
                request,
                rollback_state,
                plan,
                started_at=str(completed["started_at"]),
                finished_at=finished,
                fingerprint=marker.snapshot.authority.fingerprint,
            )
            marker.advance(
                CaptureMarkerState.INTERFACE_RESTORED,
                {
                    "rollback": rollback.model_dump(mode="json"),
                    "metadata": result_metadata,
                },
            )
            await self.journal.clear(request.execution_id)
            state = marker.snapshot.state

        restored = marker.snapshot.detail(CaptureMarkerState.INTERFACE_RESTORED)
        if restored is None:
            if output is not None:
                output.close()
            raise CaptureManualRecoveryRequired("capture marker lacks restored state")
        rollback_payload = cast(dict[str, object], restored["rollback"])
        metadata_payload = cast(dict[str, object], restored["metadata"])

        if state in {
            CaptureMarkerState.INTERFACE_RESTORED,
            CaptureMarkerState.STAGING_INTENT_DURABLE,
            CaptureMarkerState.LOCAL_ARTIFACT_COMMITTED,
            CaptureMarkerState.BINDING_PUBLISHED,
        } and await self.journal.pending(request.execution_id):
            journal_state = await self.journal.recover_state(
                request,
                capture_authority=authority_payload,
            )
            if journal_state is None:
                if output is not None:
                    output.close()
                raise CaptureManualRecoveryRequired(
                    "restored capture has ambiguous pending journal state"
                )
            await self.journal.clear(request.execution_id)

        if state is CaptureMarkerState.INTERFACE_RESTORED:
            if output is None:
                reserved = marker.snapshot.detail(CaptureMarkerState.RESERVED)
                assert reserved is not None
                output = self.workspace.open_reserved(
                    request.execution_id,
                    request.capture_format,
                    expected=reserved,
                    source_name=source_name,
                )
            manifest: dict[str, object] = {
                **identity,
                "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
            try:
                staged = await self.stager.stage_from_descriptor(
                    manifest,
                    output.descriptor,
                    output.identity,
                    request.task_id,
                    maximum_size_bytes=request.max_size_bytes,
                    cancellation=cancellation,
                    capture_authority=authority_payload,
                    intent_durable_callback=marker.note_intent_durable,
                )
                if marker.snapshot.state is not CaptureMarkerState.STAGING_INTENT_DURABLE:
                    raise CaptureManualRecoveryRequired(
                        "artifact committed without a durable capture intent transition"
                    )
                marker.advance(
                    CaptureMarkerState.LOCAL_ARTIFACT_COMMITTED,
                    {
                        "artifact_path": str(staged.path),
                        "artifact_relative_path": str(
                            staged.path.relative_to(
                                cast(CaptureRecoveryStore, self.recovery_store).artifact_root
                            )
                        ).replace("\\", "/"),
                        "manifest": staged.manifest,
                        "metadata": metadata_payload,
                        "rollback": rollback_payload,
                    },
                )
            except BaseException as error:
                output.close(primary_error=error)
                raise
            state = marker.snapshot.state

        if state is CaptureMarkerState.STAGING_INTENT_DURABLE:
            recovered_staged = await self.stager.find_existing(
                identity,
                request.task_id,
                cancellation=cancellation,
            )
            if recovered_staged is None:
                if output is not None:
                    output.close()
                raise CaptureManualRecoveryRequired(
                    "durable capture intent did not reconcile to a local artifact"
                )
            intent_detail = marker.snapshot.detail(CaptureMarkerState.STAGING_INTENT_DURABLE)
            completed_detail = marker.snapshot.detail(CaptureMarkerState.CAPTURE_COMPLETE)
            if (
                intent_detail is None
                or completed_detail is None
                or recovered_staged.manifest.get("sha256") != intent_detail["source_sha256"]
                or recovered_staged.manifest.get("sha256") != completed_detail["sha256"]
                or recovered_staged.manifest.get("size_bytes") != completed_detail["size_bytes"]
            ):
                if output is not None:
                    output.close()
                raise CaptureManualRecoveryRequired(
                    "reconciled artifact contradicts its capture marker"
                )
            marker.advance(
                CaptureMarkerState.LOCAL_ARTIFACT_COMMITTED,
                {
                    "artifact_path": str(recovered_staged.path),
                    "artifact_relative_path": str(
                        recovered_staged.path.relative_to(
                            cast(CaptureRecoveryStore, self.recovery_store).artifact_root
                        )
                    ).replace("\\", "/"),
                    "manifest": recovered_staged.manifest,
                    "metadata": metadata_payload,
                    "rollback": rollback_payload,
                },
            )
            state = marker.snapshot.state

        committed = marker.snapshot.detail(CaptureMarkerState.LOCAL_ARTIFACT_COMMITTED)
        if committed is None:
            if output is not None:
                output.close()
            raise CaptureManualRecoveryRequired("capture marker lacks committed artifact state")
        store = cast(CaptureRecoveryStore, self.recovery_store)
        if state is CaptureMarkerState.LOCAL_ARTIFACT_COMMITTED:
            binding = store.publish_binding(
                authority=marker.snapshot.authority,
                artifact_path=Path(str(committed["artifact_path"])),
                artifact_relative_path=str(committed["artifact_relative_path"]),
                manifest=cast(dict[str, object], committed["manifest"]),
                metadata=cast(dict[str, object], committed["metadata"]),
                rollback=cast(dict[str, object], committed["rollback"]),
                status="completed",
                reason=None,
            )
            marker.advance(
                CaptureMarkerState.BINDING_PUBLISHED,
                {"binding_name": binding.binding_name},
            )
            state = marker.snapshot.state
        else:
            recovered_binding = store.read_binding(
                task_id=request.task_id,
                execution_id=request.execution_id,
                idempotency_key=request.idempotency_key,
                fingerprint=marker.snapshot.authority.fingerprint,
            )
            if recovered_binding is None:
                if output is not None:
                    output.close()
                raise CaptureManualRecoveryRequired("published capture binding is missing")
            binding = recovered_binding

        artifact_path = store.validate_binding_artifact(binding)
        retired_source_name: str | None = None
        if output is None:
            try:
                reserved = marker.snapshot.detail(CaptureMarkerState.RESERVED)
                assert reserved is not None
                output = self.workspace.open_reserved(
                    request.execution_id,
                    request.capture_format,
                    expected=reserved,
                    source_name=source_name,
                )
            except FileNotFoundError:
                output = None
        if output is not None:
            quarantine = output.quarantine()
            retired_source_name = quarantine.quarantine_name
            output.close()
        marker.retire(
            reason="binding_published",
            source_quarantine_name=retired_source_name,
        )
        return capture_result_from_binding(binding, artifact_path, reused=False)

    async def _mutate_and_capture(
        self,
        request: CaptureRequest,
        output: ReservedCaptureOutput,
        cancellation: CancellationToken,
        original: InterfaceState,
    ) -> None:
        if original.network_manager_managed:
            await self.backend.set_managed(request.interface, False)
        await self.backend.set_link(request.interface, False)
        await self.backend.set_type(request.interface, "monitor")
        await self.backend.set_link(request.interface, True)
        channel = capture_channel_definition(
            frequency_mhz=request.frequency_mhz,
            channel=request.channel,
            width_mhz=request.width_mhz,
        )
        await self.backend.set_frequency(
            request.interface,
            request.frequency_mhz,
            request.width_mhz,
            channel=request.channel,
            center_frequency_1_mhz=channel.center_frequency_1_mhz,
            center_frequency_2_mhz=channel.center_frequency_2_mhz,
        )
        configured = await self.backend.snapshot(request.interface)
        if (
            configured.interface_type != "monitor"
            or configured.frequency_mhz != request.frequency_mhz
            or configured.channel != request.channel
            or configured.width_mhz != request.width_mhz
            or configured.center_frequency_1_mhz != channel.center_frequency_1_mhz
            or configured.center_frequency_2_mhz != channel.center_frequency_2_mhz
            or configured.band != channel.band
            or configured.geometry_version != channel.geometry_version
        ):
            raise RuntimeError("capture_frequency_verification_failed")
        if cancellation.cancelled:
            raise asyncio.CancelledError
        await self.backend.capture(request, output.descriptor, cancellation)

    def _capture_metadata(
        self,
        request: CaptureRequest,
        original: InterfaceState,
        plan: CaptureExecutionPlan,
        *,
        started_at: str,
        finished_at: str,
        fingerprint: CaptureFingerprint,
    ) -> dict[str, object]:
        channel = capture_channel_definition(
            frequency_mhz=request.frequency_mhz,
            channel=request.channel,
            width_mhz=request.width_mhz,
        )
        metadata: dict[str, object] = {
            "provider": plan.provider,
            "method": plan.method,
            "interface": request.interface,
            "wiphy": original.wiphy,
            "driver": original.driver,
            "channel": request.channel,
            "frequency_mhz": request.frequency_mhz,
            "width_mhz": request.width_mhz,
            "channel_band": channel.band,
            "center_frequency_1_mhz": channel.center_frequency_1_mhz,
            "center_frequency_2_mhz": channel.center_frequency_2_mhz,
            "channel_geometry_version": channel.geometry_version,
            "radiotap": request.radiotap,
            "capture_format": request.capture_format,
            "snapshot_length": request.snapshot_length,
            "requested_max_bytes": request.max_size_bytes,
            "effective_dumpcap_limit_bytes": plan.effective_size_limit_bytes,
            "effective_dumpcap_arguments": list(plan.effective_dumpcap_arguments),
            "fingerprint_version": fingerprint.version,
            "fingerprint_sha256": fingerprint.sha256,
            "started_at": started_at,
            "finished_at": finished_at,
        }
        if self.provider_version is not None:
            metadata["provider_version"] = self.provider_version
        return metadata

    @staticmethod
    def _reserved_marker_details(output: ReservedCaptureOutput) -> dict[str, object]:
        identity = output.identity
        return {
            "directory_dev": identity.directory_dev,
            "directory_ino": identity.directory_ino,
            "st_dev": identity.st_dev,
            "st_ino": identity.st_ino,
            "st_uid": identity.st_uid,
            "file_type": identity.file_type,
            "mode": identity.mode,
            "st_nlink": identity.st_nlink,
        }

    async def _finish_bound_cleanup(
        self,
        request: CaptureRequest,
        binding: CaptureBinding,
    ) -> None:
        store = cast(CaptureRecoveryStore, self.recovery_store)
        if not store.marker_exists(request.idempotency_key):
            return
        marker = store.open_marker(request.idempotency_key, blocking=False)
        primary: BaseException | None = None
        try:
            store.validate_marker_root(marker.snapshot)
            if marker.snapshot.authority != binding.authority:
                raise CaptureManualRecoveryRequired("capture marker and binding authorities differ")
            if marker.snapshot.state is CaptureMarkerState.LOCAL_ARTIFACT_COMMITTED:
                committed = marker.snapshot.detail(CaptureMarkerState.LOCAL_ARTIFACT_COMMITTED)
                if (
                    committed is None
                    or committed["artifact_path"] != binding.artifact_path
                    or committed["artifact_relative_path"] != binding.artifact_relative_path
                    or committed["manifest"] != binding.manifest
                    or committed["metadata"] != binding.metadata
                    or committed["rollback"] != binding.rollback
                ):
                    raise CaptureManualRecoveryRequired(
                        "capture binding contradicts its committed marker"
                    )
                marker.advance(
                    CaptureMarkerState.BINDING_PUBLISHED,
                    {"binding_name": binding.binding_name},
                )
            elif marker.snapshot.state is not CaptureMarkerState.BINDING_PUBLISHED:
                raise CaptureManualRecoveryRequired("capture binding contradicts its active marker")
            source_quarantine: str | None = None
            try:
                reserved = marker.snapshot.detail(CaptureMarkerState.RESERVED)
                assert reserved is not None
                output = self.workspace.open_reserved(
                    request.execution_id,
                    request.capture_format,
                    expected=reserved,
                    source_name=str(marker.snapshot.planned["source_name"]),
                )
            except FileNotFoundError:
                output = None
            if output is not None:
                quarantine = output.quarantine()
                source_quarantine = quarantine.quarantine_name
                output.close()
            marker.retire(
                reason="binding_cleanup_recovered",
                source_quarantine_name=source_quarantine,
            )
        except BaseException as error:
            primary = error
            raise
        finally:
            marker.close(primary_error=primary)

    @staticmethod
    def _binding_result(
        binding: CaptureBinding,
        artifact_path: Path,
        *,
        reused: bool,
    ) -> CaptureResult:
        return capture_result_from_binding(binding, artifact_path, reused=reused)

    async def _execute_without_recovery_store(
        self, request: CaptureRequest, cancellation: CancellationToken
    ) -> CaptureResult:
        self._authorize_policy(request)
        channel_definition = capture_channel_definition(
            frequency_mhz=request.frequency_mhz,
            channel=request.channel,
            width_mhz=request.width_mhz,
        )
        identity = self._artifact_identity(request)
        existing = await self.stager.find_existing(
            identity,
            request.task_id,
            cancellation=cancellation,
        )
        if existing is not None:
            now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            recovery_required = await self.journal.pending(request.execution_id)
            return CaptureResult(
                status="failed" if recovery_required else "completed",
                artifact_path=existing.path,
                artifact_manifest=existing.manifest,
                metadata={
                    "provider": "linux-dumpcap",
                    "method": "persisted-artifact-reuse",
                    "interface": request.interface,
                    "channel": request.channel,
                    "frequency_mhz": request.frequency_mhz,
                    "width_mhz": request.width_mhz,
                    "channel_band": channel_definition.band,
                    "center_frequency_1_mhz": channel_definition.center_frequency_1_mhz,
                    "center_frequency_2_mhz": channel_definition.center_frequency_2_mhz,
                    "channel_geometry_version": channel_definition.geometry_version,
                    "radiotap": request.radiotap,
                    "capture_format": request.capture_format,
                    "reused": True,
                    "finished_at": now,
                },
                rollback=RollbackReport(
                    complete=not recovery_required,
                    steps=(
                        RollbackStep(
                            name=(
                                "recovery_journal_present"
                                if recovery_required
                                else "idempotent_reuse"
                            ),
                            completed=not recovery_required,
                            reason=("manual_recovery_required" if recovery_required else None),
                        ),
                    ),
                ),
                reason="rollback_recovery_required" if recovery_required else None,
            )
        await self._authorize_interface(request)
        original = await self.backend.snapshot(request.interface)
        self._validate_restorable_snapshot(request, original)
        self.backend.preflight(request, original)
        encoded_journal = _encode_capture_journal(
            request,
            original,
            recorded_at="1970-01-01T00:00:00Z",
        )
        if len(encoded_journal) > FileCaptureJournal._maximum_journal_bytes:
            raise RuntimeError("capture journal is not representable")
        output = self.workspace.reserve(request.execution_id, request.capture_format)
        try:
            await self.journal.record(request, original)
        except BaseException as error:
            self._dispose_reserved_output(output, primary_error=error)
            raise
        started = datetime.now(UTC)
        primary: BaseException | None = None
        try:
            if original.network_manager_managed:
                await self.backend.set_managed(request.interface, False)
            await self.backend.set_link(request.interface, False)
            await self.backend.set_type(request.interface, "monitor")
            await self.backend.set_link(request.interface, True)
            await self.backend.set_frequency(
                request.interface,
                request.frequency_mhz,
                request.width_mhz,
                channel=request.channel,
                center_frequency_1_mhz=channel_definition.center_frequency_1_mhz,
                center_frequency_2_mhz=channel_definition.center_frequency_2_mhz,
            )
            configured = await self.backend.snapshot(request.interface)
            if (
                configured.interface_type != "monitor"
                or configured.frequency_mhz != request.frequency_mhz
                or configured.channel != request.channel
                or configured.width_mhz != request.width_mhz
                or configured.center_frequency_1_mhz != channel_definition.center_frequency_1_mhz
                or configured.center_frequency_2_mhz != channel_definition.center_frequency_2_mhz
                or configured.band != channel_definition.band
                or configured.geometry_version != channel_definition.geometry_version
            ):
                raise RuntimeError("capture_frequency_verification_failed")
            if cancellation.cancelled:
                raise asyncio.CancelledError
            await self.backend.capture(request, output.descriptor, cancellation)
            output.validate_completed(request.max_size_bytes)
        except BaseException as error:
            primary = error
        rollback = await self._rollback(original)
        if rollback.complete:
            try:
                await self.journal.clear(request.execution_id)
            except BaseException as journal_error:
                if primary is None:
                    primary = journal_error
                else:
                    primary.add_note(f"capture journal cleanup also failed: {journal_error!r}")
        if primary is not None:
            self._dispose_reserved_output(output, primary_error=primary)
            reason = (
                "cancelled"
                if isinstance(primary, asyncio.CancelledError)
                else type(primary).__name__
            )
            raise CaptureOperationError(reason, rollback) from primary
        try:
            manifest: dict[str, object] = {
                **identity,
                "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
            staged = await self.stager.stage_from_descriptor(
                manifest,
                output.descriptor,
                output.identity,
                request.task_id,
                maximum_size_bytes=request.max_size_bytes,
                cancellation=cancellation,
            )
            manifest = staged.manifest
            artifact_path = staged.path
            self._dispose_reserved_output(output)
        except BaseException as error:
            self._dispose_reserved_output(output, primary_error=error)
            raise CaptureOperationError(type(error).__name__, rollback) from error
        metadata: dict[str, object] = {
            "provider": "linux-dumpcap",
            "method": "radiotap-frequency-lock",
            "interface": request.interface,
            "wiphy": original.wiphy,
            "driver": original.driver,
            "channel": request.channel,
            "frequency_mhz": request.frequency_mhz,
            "width_mhz": request.width_mhz,
            "channel_band": channel_definition.band,
            "center_frequency_1_mhz": channel_definition.center_frequency_1_mhz,
            "center_frequency_2_mhz": channel_definition.center_frequency_2_mhz,
            "channel_geometry_version": channel_definition.geometry_version,
            "radiotap": request.radiotap,
            "capture_format": request.capture_format,
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        return CaptureResult(
            status="completed" if rollback.complete else "failed",
            artifact_path=artifact_path,
            artifact_manifest=manifest,
            metadata=metadata,
            rollback=rollback,
            reason=None if rollback.complete else "rollback_incomplete",
        )

    @staticmethod
    def _dispose_reserved_output(
        output: ReservedCaptureOutput,
        *,
        primary_error: BaseException | None = None,
    ) -> None:
        deletion_error: BaseException | None = None
        try:
            result = output.quarantine(primary_error=primary_error)
            if not result.logical_deletion_confirmed and primary_error is None:
                raise RuntimeError("capture output quarantine requires manual recovery")
        except BaseException as error:
            deletion_error = error
            if primary_error is not None:
                primary_error.add_note(f"capture output cleanup also failed: {error!r}")
        try:
            output.close(primary_error=primary_error or deletion_error)
        except BaseException as close_error:
            if primary_error is not None:
                primary_error.add_note(
                    f"capture output descriptor cleanup also failed: {close_error!r}"
                )
            elif deletion_error is None:
                raise
        if primary_error is None and deletion_error is not None:
            raise deletion_error

    def _authorize_policy(self, request: CaptureRequest) -> None:
        decision = self.authorization_decision()
        if not decision.allowed:
            raise PermissionError(decision.reason or "capture authorization denied")
        self._authorize_request_limits(request)

    def _authorize_reuse(self, request: CaptureRequest) -> None:
        """Authorize access to this operation's binding without live readiness gates."""

        authorize_capture_reuse(
            request,
            role=self.role,
            enabled=self.enabled,
            agent_id_provider=self.agent_id_provider,
            authorization=self.authorization,
            allowed_interfaces=self.allowed_interfaces,
            protected_interfaces=self.protected_interfaces,
            allowed_channels=self.allowed_channels,
            allowed_frequencies_mhz=self.allowed_frequencies_mhz,
            allowed_widths_mhz=self.allowed_widths_mhz,
            max_duration_seconds=self.max_duration_seconds,
            max_size_bytes=self.max_size_bytes,
        )

    def _authorize_request_limits(self, request: CaptureRequest) -> None:
        if request.interface not in self.allowed_interfaces:
            raise PermissionError("capture interface is not allowlisted")
        if request.interface in self.protected_interfaces:
            raise PermissionError("capture interface is protected")
        if request.channel not in self.allowed_channels:
            raise PermissionError("capture channel is not allowlisted")
        if request.frequency_mhz not in self.allowed_frequencies_mhz:
            raise PermissionError("capture frequency is not allowlisted")
        if request.width_mhz not in self.allowed_widths_mhz:
            raise PermissionError("capture width is not allowlisted")
        if request.duration_seconds > self.max_duration_seconds:
            raise PermissionError("capture duration exceeds policy")
        if request.max_size_bytes > self.max_size_bytes:
            raise PermissionError("capture size exceeds policy")

    async def _authorize_interface(self, request: CaptureRequest) -> None:
        if await self.backend.is_connectivity_interface(request.interface):
            raise PermissionError("connectivity interface cannot be selected for capture")
        if not await self.backend.monitor_supported(request.interface):
            raise RuntimeError("interface does not advertise monitor mode")

    async def _authorize(self, request: CaptureRequest) -> None:
        """Compatibility helper for read-only authorization diagnostics."""

        self._authorize_policy(request)
        await self._authorize_interface(request)

    @staticmethod
    def _artifact_identity(request: CaptureRequest) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "artifact_id": str(request.idempotency_key),
            "execution_id": str(request.execution_id),
            "artifact_type": request.capture_format,
            "media_type": (
                "application/vnd.tcpdump.pcap"
                if request.capture_format == "pcap"
                else "application/x-pcapng"
            ),
            "idempotency_key": str(request.idempotency_key),
        }

    @staticmethod
    def _validate_restorable_snapshot(request: CaptureRequest, state: InterfaceState) -> None:
        reason: str | None = None
        if state.interface != request.interface:
            reason = "interface_identity_mismatch"
        elif state.interface_type not in {"managed", "monitor", "AP", "mesh"}:
            reason = "unsupported_interface_type"
        elif state.interface_type_command_mapper_version != _IW_INTERFACE_TYPE_MAPPER_VERSION:
            reason = "interface_type_command_mapper_unsupported"
        elif state.network_manager_managed is None:
            reason = "networkmanager_state_unavailable"
        elif state.active_connections_status != "complete":
            reason = f"active_connections_{state.active_connections_status}"
        elif not state.namespace:
            reason = "namespace_unavailable"
        elif not state.wiphy:
            reason = "wiphy_unavailable"
        elif not state.driver:
            reason = "driver_unavailable"
        elif state.active_connection_uuids and not state.network_manager_managed:
            reason = "active_connection_on_unmanaged_interface"
        elif (
            state.network_manager_connection_name is not None
            and state.primary_connection_uuid is None
        ):
            reason = "active_connection_identity_unavailable"
        if reason is None:
            try:
                networkmanager_restore_plan(state)
            except ValueError as error:
                reason = f"networkmanager_restore_plan_invalid:{error}"
        radio_values = (
            state.channel,
            state.frequency_mhz,
            state.width_mhz,
            state.center_frequency_1_mhz,
            state.band,
            state.geometry_version,
        )
        radio_present = [value is not None for value in radio_values]
        if reason is None and any(radio_present) and not all(radio_present):
            reason = "radio_snapshot_incomplete"
        elif reason is None and not all(radio_present):
            reason = "radio_snapshot_required"
        elif (
            reason is None
            and state.channel is not None
            and state.frequency_mhz is not None
            and state.width_mhz is not None
        ):
            try:
                definition = validate_complete_channel_definition(
                    frequency_mhz=state.frequency_mhz,
                    channel=state.channel,
                    width_mhz=state.width_mhz,
                    center_frequency_1_mhz=state.center_frequency_1_mhz,
                    center_frequency_2_mhz=state.center_frequency_2_mhz,
                )
                if (
                    state.band != definition.band
                    or state.geometry_version != definition.geometry_version
                ):
                    raise ValueError("channel snapshot geometry identity is inconsistent")
            except ValueError:
                reason = "radio_snapshot_incoherent"
        if reason is not None:
            raise RuntimeError(f"snapshot_not_restorable: {reason}")

    @classmethod
    def _validate_recovery_snapshot(
        cls,
        request: CaptureRequest,
        state: InterfaceState,
    ) -> None:
        try:
            cls._validate_restorable_snapshot(request, state)
        except RuntimeError as error:
            raise CaptureManualRecoveryRequired(
                f"capture journal snapshot requires manual recovery: {error}"
            ) from error

    def authorization_decision(self) -> PrivilegedAuthorizationDecision:
        return privileged_capability_decision(
            agent_id=self.agent_id_provider(),
            capability_id=MONITOR_CAPTURE_CAPABILITY,
            authorization=self.authorization,
            role_allowed=self.role in {"capture_node", "lab_node"},
            policy_enabled=self.enabled,
            provider_ready=self.provider_ready,
            permissions_ready=self.privileged_ready,
            allowlists_ready=bool(
                self.allowed_interfaces
                and self.allowed_channels
                and self.allowed_frequencies_mhz
                and self.allowed_widths_mhz
            ),
            technical_ready=self.technical_ready and self.tree_containment_ready,
        )

    @staticmethod
    def _assess_rollback_verification(
        original: InterfaceState,
        verification: InterfaceState,
    ) -> RollbackVerificationAssessment:
        try:
            original = InterfaceState.model_validate(original.model_dump(mode="python"))
            verification = InterfaceState.model_validate(verification.model_dump(mode="python"))
        except ValueError:
            return RollbackVerificationAssessment(
                status="unavailable", reason="networkmanager_identity_invalid"
            )
        if verification.active_connections_status == "partial":
            return RollbackVerificationAssessment(
                status="partial", reason="active_connections_partial"
            )
        if verification.active_connections_status != "complete":
            return RollbackVerificationAssessment(
                status="unavailable", reason="active_connections_unavailable"
            )
        required_values = {
            "networkmanager": verification.network_manager_managed,
            "channel": verification.channel,
            "frequency": verification.frequency_mhz,
            "width": verification.width_mhz,
            "center_frequency_1": verification.center_frequency_1_mhz,
            "band": verification.band,
            "geometry_version": verification.geometry_version,
            "namespace": verification.namespace,
            "wiphy": verification.wiphy,
            "driver": verification.driver,
        }
        missing = [name for name, value in required_values.items() if value is None or value == ""]
        if missing:
            return RollbackVerificationAssessment(
                status="unavailable",
                reason=f"authoritative_observation_unavailable:{','.join(sorted(missing))}",
            )
        observed = (
            verification.interface,
            verification.interface_type,
            verification.administratively_up,
            verification.network_manager_managed,
            verification.primary_connection_uuid,
            frozenset(verification.ordered_active_connection_uuids),
            tuple(verification.active_connection_interfaces),
            verification.channel,
            verification.frequency_mhz,
            verification.width_mhz,
            verification.center_frequency_1_mhz,
            verification.center_frequency_2_mhz,
            verification.band,
            verification.geometry_version,
            verification.namespace,
            verification.wiphy,
            verification.driver,
        )
        expected = (
            original.interface,
            original.interface_type,
            original.administratively_up,
            original.network_manager_managed,
            original.primary_connection_uuid,
            frozenset(original.ordered_active_connection_uuids),
            tuple(original.active_connection_interfaces),
            original.channel,
            original.frequency_mhz,
            original.width_mhz,
            original.center_frequency_1_mhz,
            original.center_frequency_2_mhz,
            original.band,
            original.geometry_version,
            original.namespace,
            original.wiphy,
            original.driver,
        )
        if observed != expected:
            return RollbackVerificationAssessment(status="mismatch", reason="state_mismatch")
        return RollbackVerificationAssessment(status="complete")

    @staticmethod
    def _rollback_step_names(original: InterfaceState) -> tuple[str, ...]:
        names = ["link_down", "restore_type"]
        if (
            original.frequency_mhz is not None
            and original.channel is not None
            and original.width_mhz is not None
            and original.center_frequency_1_mhz is not None
            and original.width_mhz in SUPPORTED_CAPTURE_WIDTHS_MHZ
        ):
            names.append("restore_frequency")
        names.append("restore_link")
        if original.network_manager_managed is not None:
            names.append("restore_networkmanager")
        names.extend(operation.step_name for operation in networkmanager_restore_plan(original))
        return tuple(names)

    @staticmethod
    def _connection_operation_token(
        rollback_operation_token: str,
        operation: NetworkManagerRestoreOperation,
    ) -> str:
        authority = (
            f"{rollback_operation_token}:{operation.position}:"
            f"{operation.connection_uuid}:{int(operation.primary)}"
        )
        return hashlib.sha256(authority.encode("ascii")).hexdigest()[:32]

    @staticmethod
    def _connection_step(
        operation: NetworkManagerRestoreOperation,
        *,
        rollback_operation_token: str,
        operation_state: Literal["planned", "confirmed", "failed"],
        reason: str | None = None,
        evidence: str | None = None,
    ) -> RollbackStep:
        return RollbackStep(
            name=operation.step_name,
            completed=operation_state == "confirmed",
            reason=reason,
            operation_token=CaptureCoordinator._connection_operation_token(
                rollback_operation_token,
                operation,
            ),
            connection_uuid=operation.connection_uuid,
            position=operation.position,
            operation_state=operation_state,
            evidence=evidence,
        )

    @staticmethod
    def _connection_effect_observed(
        operation: NetworkManagerRestoreOperation,
        observed: InterfaceState,
    ) -> bool:
        if observed.active_connections_status != "complete":
            return False
        if operation.primary:
            return observed.primary_connection_uuid == operation.connection_uuid
        return operation.connection_uuid in observed.ordered_active_connection_uuids

    @classmethod
    def _validate_rollback_progress(
        cls,
        original: InterfaceState,
        steps: tuple[RollbackStep, ...],
        *,
        rollback_operation_token: str,
    ) -> None:
        expected_names = cls._rollback_step_names(original)
        if len(steps) > len(expected_names) or tuple(step.name for step in steps) != (
            expected_names[: len(steps)]
        ):
            raise CaptureManualRecoveryRequired(
                "durable rollback progress is not an authorized command prefix"
            )
        operation_by_name = {
            operation.step_name: operation for operation in networkmanager_restore_plan(original)
        }
        allowed_evidence = {
            "planned": {
                "intent_fsynced_before_command",
                "observation_required_before_mutation",
                "connection_observation_incomplete",
                "connection_observation_unavailable",
            },
            "confirmed": {
                "connection_restore_command_confirmed",
                "effect_observed_before_retry",
            },
            "failed": {
                "connection_restore_command_failed",
                "connection_profile_missing",
            },
        }
        for step in steps:
            operation = operation_by_name.get(step.name)
            if operation is None:
                if any(
                    value is not None
                    for value in (
                        step.operation_token,
                        step.connection_uuid,
                        step.position,
                        step.operation_state,
                        step.evidence,
                    )
                ):
                    raise CaptureManualRecoveryRequired(
                        "generic rollback step carries NetworkManager authority"
                    )
                continue
            expected_token = cls._connection_operation_token(
                rollback_operation_token,
                operation,
            )
            if (
                step.operation_token != expected_token
                or step.connection_uuid != operation.connection_uuid
                or step.position != operation.position
                or step.operation_state is None
                or step.evidence not in allowed_evidence[step.operation_state]
                or (step.operation_state == "confirmed" and step.reason is not None)
                or (step.operation_state == "failed" and step.reason is None)
            ):
                raise CaptureManualRecoveryRequired(
                    "NetworkManager rollback checkpoint authority is invalid"
                )

    @classmethod
    def _validate_completed_rollback_report(
        cls,
        original: InterfaceState,
        report: RollbackReport,
        *,
        rollback_operation_token: str,
    ) -> None:
        verification_names = {
            "verify",
            "verify_active_connections",
            "verify_primary_connection",
            "verify_interface_state",
        }
        mutation_steps = tuple(step for step in report.steps if step.name not in verification_names)
        verification_steps = tuple(step for step in report.steps if step.name in verification_names)
        expected_names = cls._rollback_step_names(original)
        restore_plan = networkmanager_restore_plan(original)
        legacy_names = (
            *expected_names[: len(expected_names) - len(restore_plan)],
            *(("restore_connections",) if restore_plan else ()),
        )
        mutation_names = tuple(step.name for step in mutation_steps)
        observed_verification_names = tuple(step.name for step in verification_steps)
        expected_verification_names: tuple[str, ...]
        if observed_verification_names == ("verify",):
            if (
                mutation_names != legacy_names
                or not all(step.completed for step in mutation_steps)
                or any(
                    value is not None
                    for step in mutation_steps
                    for value in (
                        step.operation_token,
                        step.connection_uuid,
                        step.position,
                        step.operation_state,
                        step.evidence,
                    )
                )
            ):
                raise CaptureManualRecoveryRequired(
                    "historical rollback report has ambiguous mutations"
                )
            expected_verification_names = ("verify",)
        else:
            cls._validate_rollback_progress(
                original,
                mutation_steps,
                rollback_operation_token=rollback_operation_token,
            )
            if mutation_names != expected_names or not all(
                step.completed for step in mutation_steps
            ):
                raise CaptureManualRecoveryRequired(
                    "completed rollback report lacks confirmed mutations"
                )
            expected_verification_names = (
                "verify_active_connections",
                "verify_primary_connection",
                "verify_interface_state",
            )
        if (
            observed_verification_names != expected_verification_names
            or not all(step.completed for step in verification_steps)
            or not report.complete
            or not report.mutations_confirmed
            or report.verification_status != "complete"
            or report.verification is None
            or cls._assess_rollback_verification(
                original,
                report.verification,
            ).status
            != "complete"
        ):
            raise CaptureManualRecoveryRequired(
                "completed rollback report lacks authoritative verification"
            )

    async def _apply_rollback(
        self,
        original: InterfaceState,
        *,
        confirmed_steps: tuple[RollbackStep, ...] = (),
        progress_callback: Callable[[tuple[RollbackStep, ...]], None] | None = None,
        rollback_operation_token: str | None = None,
    ) -> tuple[RollbackStep, ...]:
        if rollback_operation_token is None:
            rollback_operation_token = hashlib.sha256(
                original.model_dump_json().encode("utf-8")
            ).hexdigest()[:32]
        expected_names = self._rollback_step_names(original)
        self._validate_rollback_progress(
            original,
            confirmed_steps,
            rollback_operation_token=rollback_operation_token,
        )
        confirmed_names = tuple(step.name for step in confirmed_steps)
        incomplete = [step for step in confirmed_steps if not step.completed]
        if (
            len(confirmed_steps) > len(expected_names)
            or confirmed_names != expected_names[: len(confirmed_steps)]
            or len(incomplete) > 1
            or (incomplete and confirmed_steps[-1] is not incomplete[0])
            or (incomplete and incomplete[0].operation_state not in {"planned", "failed"})
        ):
            raise CaptureManualRecoveryRequired(
                "durable rollback progress is not a confirmed command prefix"
            )
        steps: list[RollbackStep] = list(confirmed_steps)
        if incomplete and incomplete[0].operation_state == "failed":
            return tuple(steps)
        already_confirmed = frozenset(step.name for step in confirmed_steps if step.completed)

        async def attempt(name: str, operation: object) -> bool:
            try:
                await operation  # type: ignore[misc]
                steps.append(RollbackStep(name=name, completed=True))
            except BaseException as error:
                steps.append(RollbackStep(name=name, completed=False, reason=type(error).__name__))
            if progress_callback is not None:
                progress_callback(tuple(steps))
            return steps[-1].completed

        if "link_down" not in already_confirmed:
            if not await attempt("link_down", self.backend.set_link(original.interface, False)):
                return tuple(steps)
        if "restore_type" not in already_confirmed:
            if not await attempt(
                "restore_type",
                self.backend.set_type(original.interface, original.interface_type),
            ):
                return tuple(steps)
        if (
            original.frequency_mhz is not None
            and original.channel is not None
            and original.width_mhz is not None
            and original.center_frequency_1_mhz is not None
            and original.width_mhz in SUPPORTED_CAPTURE_WIDTHS_MHZ
            and "restore_frequency" not in already_confirmed
        ):
            if not await attempt(
                "restore_frequency",
                self.backend.set_frequency(
                    original.interface,
                    original.frequency_mhz,
                    original.width_mhz,
                    channel=original.channel,
                    center_frequency_1_mhz=original.center_frequency_1_mhz,
                    center_frequency_2_mhz=original.center_frequency_2_mhz,
                ),
            ):
                return tuple(steps)
        if "restore_link" not in already_confirmed:
            if not await attempt(
                "restore_link",
                self.backend.set_link(original.interface, original.administratively_up),
            ):
                return tuple(steps)
        if (
            original.network_manager_managed is not None
            and "restore_networkmanager" not in already_confirmed
        ):
            if not await attempt(
                "restore_networkmanager",
                self.backend.set_managed(original.interface, original.network_manager_managed),
            ):
                return tuple(steps)

        restore_plan = networkmanager_restore_plan(original)
        for operation in restore_plan:
            if operation.step_name in already_confirmed:
                continue
            pending = steps[-1] if steps and steps[-1].name == operation.step_name else None
            if pending is not None and pending.operation_state != "planned":
                return tuple(steps)
            try:
                observed = await self.backend.snapshot(original.interface)
            except BaseException as error:
                if pending is None:
                    pending = self._connection_step(
                        operation,
                        rollback_operation_token=rollback_operation_token,
                        operation_state="planned",
                        evidence="observation_required_before_mutation",
                    )
                    steps.append(pending)
                    if progress_callback is not None:
                        progress_callback(tuple(steps))
                steps[-1] = pending.model_copy(
                    update={
                        "reason": type(error).__name__,
                        "evidence": "connection_observation_unavailable",
                    }
                )
                if progress_callback is not None:
                    progress_callback(tuple(steps))
                return tuple(steps)
            if observed.active_connections_status != "complete":
                if pending is None:
                    pending = self._connection_step(
                        operation,
                        rollback_operation_token=rollback_operation_token,
                        operation_state="planned",
                        evidence="observation_required_before_mutation",
                    )
                    steps.append(pending)
                steps[-1] = pending.model_copy(
                    update={
                        "reason": f"active_connections_{observed.active_connections_status}",
                        "evidence": "connection_observation_incomplete",
                    }
                )
                if progress_callback is not None:
                    progress_callback(tuple(steps))
                return tuple(steps)
            if self._connection_effect_observed(operation, observed):
                confirmed = self._connection_step(
                    operation,
                    rollback_operation_token=rollback_operation_token,
                    operation_state="confirmed",
                    evidence="effect_observed_before_retry",
                )
                if pending is None:
                    steps.append(confirmed)
                else:
                    steps[-1] = confirmed
                if progress_callback is not None:
                    progress_callback(tuple(steps))
                already_confirmed = frozenset({*already_confirmed, operation.step_name})
                continue
            if pending is None:
                pending = self._connection_step(
                    operation,
                    rollback_operation_token=rollback_operation_token,
                    operation_state="planned",
                    evidence="intent_fsynced_before_command",
                )
                steps.append(pending)
                if progress_callback is not None:
                    progress_callback(tuple(steps))
            try:
                await self.backend.restore_connection(
                    operation.interface,
                    operation.connection_uuid,
                )
            except NetworkManagerConnectionProfileMissing:
                steps[-1] = self._connection_step(
                    operation,
                    rollback_operation_token=rollback_operation_token,
                    operation_state="failed",
                    reason="connection_profile_missing",
                    evidence="connection_profile_missing",
                )
                if progress_callback is not None:
                    progress_callback(tuple(steps))
                return tuple(steps)
            except BaseException as error:
                steps[-1] = self._connection_step(
                    operation,
                    rollback_operation_token=rollback_operation_token,
                    operation_state="failed",
                    reason=type(error).__name__,
                    evidence="connection_restore_command_failed",
                )
                if progress_callback is not None:
                    progress_callback(tuple(steps))
                return tuple(steps)
            steps[-1] = self._connection_step(
                operation,
                rollback_operation_token=rollback_operation_token,
                operation_state="confirmed",
                evidence="connection_restore_command_confirmed",
            )
            if progress_callback is not None:
                progress_callback(tuple(steps))
            already_confirmed = frozenset({*already_confirmed, operation.step_name})
        return tuple(steps)

    async def _durable_rollback(
        self,
        marker: CaptureMarker,
        original: InterfaceState,
    ) -> RollbackReport:
        """Resume rollback from its durable confirmed prefix, then verify read-only."""

        if marker.snapshot.state in {
            CaptureMarkerState.RESERVED,
            CaptureMarkerState.CAPTURE_COMPLETE,
        }:
            marker.note_rollback_verification(
                RollbackReport(
                    complete=False,
                    steps=(),
                    verification_status="unavailable",
                    verification_reason="rollback_mutations_pending",
                    mutations_confirmed=False,
                ).model_dump(mode="json")
            )
        pending_detail = marker.snapshot.detail(CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING)
        if pending_detail is None:
            raise CaptureManualRecoveryRequired(
                "rollback verification marker lacks its durable report"
            )
        pending_report = RollbackReport.model_validate(pending_detail["rollback"])
        expected_step_names = self._rollback_step_names(original)
        verification_names = {
            "verify",
            "verify_active_connections",
            "verify_primary_connection",
            "verify_interface_state",
        }
        mutation_steps = tuple(
            step for step in pending_report.steps if step.name not in verification_names
        )
        legacy_batch = next(
            (step for step in mutation_steps if step.name == "restore_connections"),
            None,
        )
        if legacy_batch is not None:
            legacy_index = mutation_steps.index(legacy_batch)
            restore_plan = networkmanager_restore_plan(original)
            expected_base_count = len(expected_step_names) - len(restore_plan)
            base_names = expected_step_names[:legacy_index]
            if (
                not restore_plan
                or legacy_index != expected_base_count
                or tuple(step.name for step in mutation_steps[:legacy_index]) != base_names
                or not all(step.completed for step in mutation_steps[:legacy_index])
                or legacy_index != len(mutation_steps) - 1
            ):
                raise CaptureManualRecoveryRequired(
                    "historical NetworkManager rollback progress is ambiguous"
                )
            mutation_steps = mutation_steps[:legacy_index]
        self._validate_rollback_progress(
            original,
            mutation_steps,
            rollback_operation_token=marker.snapshot.authority.operation_token,
        )
        mutation_names = tuple(step.name for step in mutation_steps)
        confirmed_prefix = (
            len(mutation_steps) <= len(expected_step_names)
            and mutation_names == expected_step_names[: len(mutation_steps)]
            and all(step.completed for step in mutation_steps[:-1])
            and (
                not mutation_steps
                or mutation_steps[-1].completed
                or mutation_steps[-1].operation_state in {"planned", "failed"}
            )
        )

        def checkpoint(steps: tuple[RollbackStep, ...]) -> None:
            mutations_confirmed = tuple(step.name for step in steps) == expected_step_names and all(
                step.completed for step in steps
            )
            marker.note_rollback_verification(
                RollbackReport(
                    complete=False,
                    steps=steps,
                    verification_status="unavailable",
                    verification_reason="verification_pending",
                    mutations_confirmed=mutations_confirmed,
                ).model_dump(mode="json")
            )

        if confirmed_prefix and (
            len(mutation_steps) < len(expected_step_names)
            or (mutation_steps and not mutation_steps[-1].completed)
        ):
            mutation_steps = await self._apply_rollback(
                original,
                confirmed_steps=mutation_steps,
                progress_callback=checkpoint,
                rollback_operation_token=marker.snapshot.authority.operation_token,
            )
        rollback = await self._verify_rollback(
            original,
            mutation_steps,
            progress_callback=checkpoint,
        )
        if rollback.complete:
            self._validate_completed_rollback_report(
                original,
                rollback,
                rollback_operation_token=marker.snapshot.authority.operation_token,
            )
        # Persist even a complete read-only assessment before clearing the
        # journal or advancing/retiring the marker.  A crash after this point
        # can finish cleanup without replaying a mutator.
        marker.note_rollback_verification(rollback.model_dump(mode="json"))
        return rollback

    async def _verify_rollback(
        self,
        original: InterfaceState,
        mutation_steps: tuple[RollbackStep, ...],
        *,
        progress_callback: Callable[[tuple[RollbackStep, ...]], None] | None = None,
    ) -> RollbackReport:
        mutations_confirmed = tuple(
            step.name for step in mutation_steps
        ) == self._rollback_step_names(original) and all(step.completed for step in mutation_steps)
        if not mutations_confirmed:
            return RollbackReport(
                complete=False,
                steps=mutation_steps,
                verification_status="unavailable",
                verification_reason="rollback_mutation_unconfirmed",
                mutations_confirmed=False,
            )
        verification: InterfaceState | None = None
        try:
            verification = await self.backend.snapshot(original.interface)
            assessment = self._assess_rollback_verification(original, verification)
            steps = [*mutation_steps]
            active_complete = verification.active_connections_status == "complete" and frozenset(
                verification.ordered_active_connection_uuids
            ) == frozenset(original.ordered_active_connection_uuids)
            steps.append(
                RollbackStep(
                    name="verify_active_connections",
                    completed=active_complete,
                    reason=None if active_complete else assessment.reason or "active_set_mismatch",
                    evidence="read_only_snapshot",
                )
            )
            if progress_callback is not None:
                progress_callback(tuple(steps))
            primary_complete = (
                verification.active_connections_status == "complete"
                and verification.primary_connection_uuid == original.primary_connection_uuid
            )
            steps.append(
                RollbackStep(
                    name="verify_primary_connection",
                    completed=primary_complete,
                    reason=None if primary_complete else assessment.reason or "primary_mismatch",
                    evidence="read_only_snapshot",
                )
            )
            if progress_callback is not None:
                progress_callback(tuple(steps))
            steps.append(
                RollbackStep(
                    name="verify_interface_state",
                    completed=assessment.status == "complete",
                    reason=assessment.reason,
                    evidence="read_only_snapshot",
                )
            )
            if progress_callback is not None:
                progress_callback(tuple(steps))
        except BaseException as error:
            assessment = RollbackVerificationAssessment(
                status="unavailable", reason=type(error).__name__
            )
            steps = [*mutation_steps]
            for name in (
                "verify_active_connections",
                "verify_primary_connection",
                "verify_interface_state",
            ):
                steps.append(
                    RollbackStep(
                        name=name,
                        completed=False,
                        reason=assessment.reason,
                        evidence="read_only_snapshot_unavailable",
                    )
                )
                if progress_callback is not None:
                    progress_callback(tuple(steps))
        return RollbackReport(
            complete=mutations_confirmed and assessment.status == "complete",
            steps=tuple(steps),
            verification=verification,
            verification_status=assessment.status,
            verification_reason=assessment.reason,
            mutations_confirmed=mutations_confirmed,
        )

    async def _rollback(self, original: InterfaceState) -> RollbackReport:
        mutation_steps = await self._apply_rollback(original)
        return await self._verify_rollback(original, mutation_steps)


class DeferredCaptureCoordinator:
    """Resolve durable reuse before constructing any live capture dependency."""

    def __init__(
        self,
        *,
        state_dir: Path,
        artifact_root: Path,
        capture_plan_builder: Callable[[CaptureRequest], CaptureExecutionPlan],
        live_factory: Callable[[], CaptureCoordinator],
        role: str,
        enabled: bool,
        agent_id_provider: Callable[[], str | None],
        authorization: ControlPlaneAuthorization,
        allowed_interfaces: frozenset[str],
        protected_interfaces: frozenset[str],
        allowed_channels: frozenset[int],
        allowed_frequencies_mhz: frozenset[int],
        allowed_widths_mhz: frozenset[int],
        max_duration_seconds: int,
        max_size_bytes: int,
    ) -> None:
        self.state_dir = state_dir
        self.artifact_root = artifact_root
        self.capture_plan_builder = capture_plan_builder
        self.live_factory = live_factory
        self.role = role
        self.enabled = enabled
        self.agent_id_provider = agent_id_provider
        self.authorization = authorization
        self.allowed_interfaces = allowed_interfaces
        self.protected_interfaces = protected_interfaces
        self.allowed_channels = allowed_channels
        self.allowed_frequencies_mhz = allowed_frequencies_mhz
        self.allowed_widths_mhz = allowed_widths_mhz
        self.max_duration_seconds = max_duration_seconds
        self.max_size_bytes = max_size_bytes
        self._execution_lock = asyncio.Lock()
        self._live: CaptureCoordinator | None = None

    async def execute(
        self,
        request: CaptureRequest,
        cancellation: CancellationToken,
    ) -> CaptureResult:
        if self._execution_lock.locked():
            raise RuntimeError("capture concurrency limit is one")
        async with self._execution_lock:
            authorize_capture_reuse(
                request,
                role=self.role,
                enabled=self.enabled,
                agent_id_provider=self.agent_id_provider,
                authorization=self.authorization,
                allowed_interfaces=self.allowed_interfaces,
                protected_interfaces=self.protected_interfaces,
                allowed_channels=self.allowed_channels,
                allowed_frequencies_mhz=self.allowed_frequencies_mhz,
                allowed_widths_mhz=self.allowed_widths_mhz,
                max_duration_seconds=self.max_duration_seconds,
                max_size_bytes=self.max_size_bytes,
            )
            prepared = prepare_capture_fingerprint(
                request,
                self.capture_plan_builder(request),
            )
            reuse_store: CaptureRecoveryStore | None = None
            try:
                try:
                    reuse_store = CaptureRecoveryStore(
                        self.state_dir,
                        self.artifact_root,
                        reuse_only=True,
                    )
                except FileNotFoundError:
                    reuse_store = None
                binding_was_present = bool(
                    reuse_store is not None and reuse_store.binding_exists(request.idempotency_key)
                )
                operation_was_present = bool(
                    reuse_store is not None
                    and reuse_store.operation_lock_exists(request.idempotency_key)
                )
                if reuse_store is not None and (binding_was_present or operation_was_present):
                    operation_lock = reuse_store.acquire_operation_lock(
                        request.idempotency_key,
                        create=False,
                    )
                    primary: BaseException | None = None
                    try:
                        result = resolve_capture_binding_locked(
                            reuse_store,
                            request,
                            prepared,
                        )
                        if result is None and binding_was_present:
                            raise CaptureManualRecoveryRequired(
                                "capture binding disappeared while its lock was held"
                            )
                        if result is not None:
                            return result
                    except BaseException as error:
                        primary = error
                        raise
                    finally:
                        operation_lock.close(primary_error=primary)
            finally:
                if reuse_store is not None:
                    reuse_store.close()

            if self._live is None:
                self._live = self.live_factory()
            return await self._live.execute(request, cancellation)


class SimulatedCaptureBackend:
    def __init__(
        self,
        state: InterfaceState,
        *,
        connectivity: bool = False,
        monitor: bool = True,
        fail_steps: frozenset[str] = frozenset(),
        artifact_bytes: bytes = b"\x0a\x0d\x0d\x0aWTO-SIMULATED-PCAPNG",
    ) -> None:
        self.state = state
        self.connectivity = connectivity
        self.monitor = monitor
        self.fail_steps = fail_steps
        self.artifact_bytes = artifact_bytes
        self.calls: list[str] = []
        self._connection_names = (
            {state.primary_connection_uuid: state.network_manager_connection_name}
            if state.primary_connection_uuid is not None
            else {}
        )

    def _fail(self, step: str) -> None:
        self.calls.append(step)
        if step in self.fail_steps:
            raise RuntimeError(f"simulated {step} failure")

    async def is_connectivity_interface(self, interface: str) -> bool:
        del interface
        return self.connectivity

    async def monitor_supported(self, interface: str) -> bool:
        del interface
        return self.monitor

    async def snapshot(self, interface: str) -> InterfaceState:
        self._fail("snapshot")
        if interface != self.state.interface:
            raise RuntimeError("unknown simulated interface")
        return self.state

    def preflight(self, request: CaptureRequest, state: InterfaceState) -> None:
        if request.interface != state.interface:
            raise RuntimeError("simulated capture snapshot identity changed")
        parse_capture_interface_type(state.interface_type)
        networkmanager_restore_plan(state)

    def capture_plan(self, request: CaptureRequest) -> CaptureExecutionPlan:
        size_kib = max(1, request.max_size_bytes // 1024)
        return CaptureExecutionPlan(
            provider="simulated-capture",
            method="simulated-radiotap-frequency-lock",
            effective_size_limit_bytes=size_kib * 1024,
            effective_dumpcap_arguments=(
                "-q",
                "-i",
                request.interface,
                "-I",
                "-y",
                "IEEE802_11_RADIO",
                "-F",
                request.capture_format,
                "-s",
                str(request.snapshot_length),
                "-a",
                f"duration:{request.duration_seconds}",
                "-a",
                f"filesize:{size_kib}",
                "-w",
                "-",
            ),
        )

    async def set_managed(self, interface: str, managed: bool) -> None:
        del interface
        self._fail("set_managed")
        updates: dict[str, object] = {"network_manager_managed": managed}
        if not managed:
            updates.update(
                {
                    "active_connection_uuids": (),
                    "ordered_active_connection_uuids": (),
                    "active_connection_interfaces": (),
                    "network_manager_connection_uuid": None,
                    "primary_connection_uuid": None,
                    "network_manager_connection_name": None,
                }
            )
        self.state = InterfaceState.model_validate(
            {**self.state.model_dump(mode="python"), **updates}
        )

    async def set_link(self, interface: str, up: bool) -> None:
        self._fail("set_link")
        self.state = self.state.model_copy(update={"administratively_up": up})

    async def set_type(self, interface: str, interface_type: CaptureInterfaceType) -> None:
        self._fail("set_type")
        self.state = self.state.model_copy(update={"interface_type": interface_type})

    async def set_frequency(
        self,
        interface: str,
        frequency_mhz: int,
        width_mhz: int,
        *,
        channel: int,
        center_frequency_1_mhz: int,
        center_frequency_2_mhz: int | None,
    ) -> None:
        del interface
        self._fail("set_frequency")
        definition = validate_complete_channel_definition(
            frequency_mhz=frequency_mhz,
            channel=channel,
            width_mhz=width_mhz,
            center_frequency_1_mhz=center_frequency_1_mhz,
            center_frequency_2_mhz=center_frequency_2_mhz,
        )
        self.state = self.state.model_copy(
            update={
                "channel": definition.primary_channel,
                "frequency_mhz": frequency_mhz,
                "width_mhz": width_mhz,
                "center_frequency_1_mhz": center_frequency_1_mhz,
                "center_frequency_2_mhz": center_frequency_2_mhz,
                "band": definition.band,
                "geometry_version": definition.geometry_version,
            }
        )

    async def restore_connection(self, interface: str, connection_uuid: str) -> None:
        connection_uuid = validate_networkmanager_uuid(connection_uuid)
        self._fail(f"restore_connection:{connection_uuid}")
        active = [
            value
            for value in self.state.ordered_active_connection_uuids
            if value != connection_uuid
        ]
        active.append(connection_uuid)
        associations = tuple(
            NetworkManagerConnectionObservation(
                connection_uuid=value,
                interface=interface,
                restore_position=position,
            )
            for position, value in enumerate(active)
        )
        self.state = InterfaceState.model_validate(
            {
                **self.state.model_dump(mode="python"),
                "active_connection_uuids": tuple(active),
                "ordered_active_connection_uuids": tuple(active),
                "active_connection_interfaces": associations,
                "active_connections_status": "complete",
                "network_manager_connection_uuid": connection_uuid,
                "primary_connection_uuid": connection_uuid,
                "network_manager_connection_name": self._connection_names.get(connection_uuid),
            }
        )

    async def capture(
        self,
        request: CaptureRequest,
        output_descriptor: int,
        cancellation: CancellationToken,
    ) -> None:
        del request
        self._fail("capture")
        if cancellation.cancelled:
            raise asyncio.CancelledError
        view = memoryview(self.artifact_bytes)
        while view:
            written = os.write(output_descriptor, view)
            if written <= 0:
                raise OSError("simulated capture write made no progress")
            view = view[written:]
