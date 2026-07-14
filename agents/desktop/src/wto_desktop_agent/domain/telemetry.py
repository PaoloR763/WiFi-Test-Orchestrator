from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class StrictTelemetryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ObservationSource(StrictTelemetryModel):
    plane: Literal["control", "data", "telemetry", "artifact", "integration"]
    producer: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    method: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    version: str | None = Field(default=None, pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")


class ObservationReason(StrictTelemetryModel):
    code: Literal[
        "not_exposed_by_platform",
        "not_implemented",
        "permission_missing",
        "permission_denied",
        "user_interaction_required",
        "lifecycle_restricted",
        "provider_unavailable",
        "policy_denied",
        "not_applicable",
        "unknown",
        "incompatible_version",
        "agent_revoked",
        "expired",
        "blocked",
        "skipped",
    ]
    detail: str | None = Field(default=None, min_length=1, max_length=256)


class NormalizedObservation(StrictTelemetryModel):
    value: JsonValue | None
    unit: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9%._/:-]+$")
    source: ObservationSource
    availability: Literal["measured", "estimated", "unavailable", "unknown", "not_applicable"]
    confidence: Literal["high", "medium", "low", "unknown", "not_applicable"]
    reason: ObservationReason | None
    collected_at: datetime

    @model_validator(mode="after")
    def validate_null_semantics(self) -> NormalizedObservation:
        if self.collected_at.tzinfo is None:
            raise ValueError("collected_at must include a UTC offset")
        if self.value is None and self.availability in {"measured", "estimated"}:
            raise ValueError("a measured or estimated observation requires a value")
        if self.value is not None and self.availability in {"unavailable", "not_applicable"}:
            raise ValueError("an unavailable or not-applicable observation cannot contain a value")
        if self.value is None and self.reason is None:
            raise ValueError("a null observation requires reason")
        return self

    @classmethod
    def measured(
        cls,
        value: JsonValue,
        unit: str,
        source: ObservationSource,
        collected_at: datetime,
        *,
        confidence: Literal["high", "medium", "low"] = "high",
        reason: ObservationReason | None = None,
    ) -> NormalizedObservation:
        return cls(
            value=value,
            unit=unit,
            source=source,
            availability="measured",
            confidence=confidence,
            reason=reason,
            collected_at=collected_at.astimezone(UTC),
        )

    @classmethod
    def missing(
        cls,
        unit: str,
        source: ObservationSource,
        collected_at: datetime,
        reason: ObservationReason,
        *,
        availability: Literal["unavailable", "unknown", "not_applicable"] = "unavailable",
        confidence: Literal["unknown", "not_applicable"] = "unknown",
    ) -> NormalizedObservation:
        return cls(
            value=None,
            unit=unit,
            source=source,
            availability=availability,
            confidence=confidence,
            reason=reason,
            collected_at=collected_at.astimezone(UTC),
        )


class InterfaceSnapshot(StrictTelemetryModel):
    interface_key: str = Field(min_length=1, max_length=128)
    fields: dict[str, NormalizedObservation]


class WifiScanEntry(StrictTelemetryModel):
    interface_guid: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    bssid: str = Field(pattern=r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
    fields: dict[str, NormalizedObservation]


class InventorySnapshot(StrictTelemetryModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    snapshot_id: str = Field(min_length=36, max_length=36)
    started_at: datetime
    finished_at: datetime
    interfaces: list[InterfaceSnapshot]
    source_errors: dict[str, ObservationReason] = Field(default_factory=dict)


class WifiScanSnapshot(StrictTelemetryModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    interface_guid: str
    started_at: datetime
    finished_at: datetime
    entries: list[WifiScanEntry]
    reason: ObservationReason | None = None
