from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, RootModel, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnrollmentTokenCreateRequest(StrictModel):
    scope: Literal["agent.enroll", "agent.recover"] = "agent.enroll"
    expires_in_minutes: int = Field(default=15, ge=1, le=1440)
    allowed_platforms: list[Literal["simulated", "windows", "linux", "android", "ios"]] = Field(
        default_factory=list, max_length=5
    )
    bound_agent_id: UUID | None = None

    @field_validator("allowed_platforms")
    @classmethod
    def unique_allowed_platforms(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("allowed_platforms must not contain duplicates")
        return value


class EnrollmentTokenResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    enrollment_token_id: UUID
    enrollment_token: str = Field(
        min_length=90,
        max_length=90,
        pattern=r"^wto_enr_1\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$",
    )
    scope: Literal["agent.enroll", "agent.recover"]
    expires_at: datetime
    max_uses: Literal[1] = 1


class AgentRegistrationRequest(StrictModel):
    schema_version: Literal["1.0.0"]
    idempotency_key: UUID
    enrollment_token: str = Field(
        min_length=90,
        max_length=90,
        pattern=r"^wto_enr_1\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$",
    )
    installation_id: UUID
    display_name: str = Field(min_length=1, max_length=128)
    platform: Literal["simulated", "windows", "linux", "android", "ios"]
    platform_version: str = Field(min_length=1, max_length=64)
    agent_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
    protocol_min_version: Literal["1.0.0"]
    protocol_max_version: Literal["1.0.0"]
    agent_reported_at: datetime


class AgentCredentialResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    credential_id: UUID
    credential_version: int = Field(ge=1)
    credential: str = Field(
        min_length=89,
        max_length=89,
        pattern=r"^wto_ac_1\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$",
    )
    issued_at: datetime
    expires_at: datetime
    state: Literal["active", "pending"]


class AgentRegistrationResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    device_id: UUID
    agent_id: UUID
    protocol_version: Literal["1.0.0"] = "1.0.0"
    server_received_at: datetime
    credential: AgentCredentialResponse


class RotationCreateRequest(StrictModel):
    schema_version: Literal["1.0.0"]
    idempotency_key: UUID


class RotationCreateResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    rotation_id: UUID
    expires_at: datetime
    pending_credential: AgentCredentialResponse


class RotationActivateRequest(StrictModel):
    schema_version: Literal["1.0.0"]
    idempotency_key: UUID


class RotationActivateResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    rotation_id: UUID
    credential_id: UUID
    credential_version: int
    activated_at: datetime


class CredentialMetadata(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    credential_id: UUID
    credential_version: int
    state: Literal["pending", "active", "revoked", "expired"]
    issued_at: datetime
    activated_at: datetime | None
    expires_at: datetime
    revoked_at: datetime | None
    revocation_reason: str | None


class ReasonValue(StrictModel):
    code: str = Field(min_length=1, max_length=64)
    detail: str | None = Field(default=None, max_length=256)


class DesktopHeartbeatRequest(StrictModel):
    schema_version: Literal["1.0.0"]
    agent_id: UUID
    boot_id: UUID
    sequence: int = Field(ge=0)
    agent_version: str
    protocol_version: Literal["1.0.0"]
    agent_reported_at: datetime
    readiness: Literal["ready", "degraded", "blocked"]
    reason: ReasonValue | None
    manifest_id: UUID
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class MobilePresenceRequest(StrictModel):
    schema_version: Literal["1.0.0"]
    agent_id: UUID
    boot_id: UUID
    sequence: int = Field(ge=0)
    agent_version: str
    protocol_version: Literal["1.0.0"]
    agent_reported_at: datetime
    lifecycle: Literal["foreground", "background_window", "user_initiated"]
    reason: ReasonValue | None
    manifest_id: UUID
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class PresenceResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    accepted_sequence: int
    server_received_at: datetime
    presence_expires_at: datetime
    poll_after_seconds: int = Field(ge=15, le=900)


class CapabilityManifestRequest(RootModel[dict[str, Any]]):
    pass


class AgentView(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    agent_id: UUID
    device_id: UUID | None
    display_name: str
    is_active: bool
    revoked_at: datetime | None
    protocol_version: str | None


class ProtocolStubResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    status: Literal["accepted", "no_task"]
    server_received_at: datetime
