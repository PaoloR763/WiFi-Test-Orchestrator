from __future__ import annotations

from collections.abc import Iterable

from wto_desktop_agent.domain.errors import PluginUnavailableError
from wto_desktop_agent.plugins.contract_check import ContractCheckPlugin
from wto_desktop_agent.ports.plugins import TestPlugin


class PluginRegistry:
    def __init__(self, plugins: Iterable[TestPlugin], configured_allowlist: frozenset[str]) -> None:
        compiled: dict[tuple[str, str], TestPlugin] = {}
        for plugin in plugins:
            key = (plugin.descriptor.task_type, plugin.descriptor.task_type_version)
            if key in compiled:
                raise ValueError(f"duplicate compiled plugin: {key}")
            compiled[key] = plugin
        compiled_names = {key[0] for key in compiled}
        if configured_allowlist - compiled_names:
            raise ValueError(
                "configuration cannot enable a plugin absent from the compiled registry"
            )
        self._plugins = {
            key: plugin for key, plugin in compiled.items() if key[0] in configured_allowlist
        }

    def get(self, task_type: str, task_type_version: str) -> TestPlugin:
        try:
            return self._plugins[(task_type, task_type_version)]
        except KeyError as error:
            raise PluginUnavailableError("plugin is unknown or not locally allowlisted") from error

    def descriptors(self) -> list[dict[str, object]]:
        return [
            {
                "task_type": descriptor.task_type,
                "task_type_version": descriptor.task_type_version,
                "provider_id": descriptor.provider_id,
                "provider_version": descriptor.provider_version,
                "method": descriptor.method,
                "required_commands": sorted(descriptor.required_commands),
            }
            for descriptor in sorted(
                (plugin.descriptor for plugin in self._plugins.values()),
                key=lambda item: (item.task_type, item.task_type_version),
            )
        ]


def build_plugin_registry(configured_allowlist: frozenset[str]) -> PluginRegistry:
    return PluginRegistry([ContractCheckPlugin()], configured_allowlist)
