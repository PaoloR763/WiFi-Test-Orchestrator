from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from wto_desktop_agent.domain.models import LocalTaskEnvelope, PluginResult
from wto_desktop_agent.ports.plugins import (
    CancellationToken,
    PluginDescriptor,
    ProgressCallback,
)


class ContractCheckParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ContractCheckPlugin:
    descriptor = PluginDescriptor(
        task_type="protocol.contract_check",
        task_type_version="1.0.0",
        provider_id="wto-agent-core",
        provider_version="0.1.0",
        method="contract_check",
        parameter_model=ContractCheckParameters,
        required_commands=frozenset(),
        max_timeout_seconds=30.0,
    )

    async def execute(
        self,
        task: LocalTaskEnvelope,
        cancellation: CancellationToken,
        progress: ProgressCallback,
    ) -> PluginResult:
        if cancellation.cancelled:
            raise asyncio.CancelledError
        self.descriptor.parameter_model.model_validate(task.parameters)
        await progress(100.0)
        return PluginResult(status="completed", outcome="pass")

    async def cleanup(self, task: LocalTaskEnvelope) -> None:
        return None


import asyncio  # noqa: E402
