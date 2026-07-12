from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LocalTaskEnvelope(StrictModel):
    """Local execution model; it is not a public Phase 04 wire contract."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    protocol_version: Literal["1.0.0"] = "1.0.0"
    task_id: UUID
    execution_id: UUID
    task_type: str = Field(min_length=3, max_length=128)
    task_type_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    idempotency_key: UUID
    required_capabilities: list[str] = Field(min_length=1, max_length=15)
    foreground_requirement: Literal["not_required", "required", "required_on_mobile"]
    user_interaction_requirement: Literal["none", "possible", "required"]
    parameters: dict[str, Any] = Field(default_factory=dict)

    def logical_effect(self) -> dict[str, object]:
        return {
            "execution_id": str(self.execution_id),
            "task_type": self.task_type,
            "task_type_version": self.task_type_version,
            "required_capabilities": self.required_capabilities,
            "foreground_requirement": self.foreground_requirement,
            "user_interaction_requirement": self.user_interaction_requirement,
            "parameters": self.parameters,
        }


class PluginResult(StrictModel):
    status: Literal["completed", "failed"]
    outcome: Literal["pass", "fail", "inconclusive", "not_evaluated"]
    metrics: list[dict[str, Any]] = Field(default_factory=list, max_length=128)
    detail: str | None = Field(default=None, max_length=256)


class DoctorCheck(StrictModel):
    name: str
    status: Literal["OK", "DEGRADED", "BLOCKED"]
    detail: str
