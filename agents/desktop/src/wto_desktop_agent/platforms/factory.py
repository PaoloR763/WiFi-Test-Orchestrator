from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wto_desktop_agent.config import AgentSettings
    from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
    from wto_desktop_agent.ports.platform import PlatformAdapter


def create_platform_adapter(
    *,
    in_memory: bool = False,
    settings: AgentSettings | None = None,
    store: SQLiteStore | None = None,
) -> PlatformAdapter:
    if in_memory:
        from wto_desktop_agent.platforms.simulated.adapter import (
            SimulatedPlatformAdapter,
        )

        return SimulatedPlatformAdapter()
    if sys.platform == "win32":
        from wto_desktop_agent.platforms.windows.adapter import WindowsPlatformAdapter

        if settings is None or store is None:
            raise RuntimeError("Windows adapter requires settings and SQLite store")
        return WindowsPlatformAdapter(settings, store)
    if sys.platform.startswith("linux"):
        from wto_desktop_agent.platforms.linux.adapter import LinuxPlatformAdapter

        if settings is None or store is None:
            raise RuntimeError("Linux adapter requires settings and SQLite store")
        return LinuxPlatformAdapter(settings, store)
    raise RuntimeError(f"unsupported desktop platform: {sys.platform}")
