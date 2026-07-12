from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wto_desktop_agent.ports.platform import PlatformAdapter


def create_platform_adapter(*, in_memory: bool = False) -> PlatformAdapter:
    if in_memory:
        from wto_desktop_agent.platforms.simulated.adapter import (
            SimulatedPlatformAdapter,
        )

        return SimulatedPlatformAdapter()
    if sys.platform == "win32":
        from wto_desktop_agent.platforms.windows.adapter import WindowsPlatformAdapter

        return WindowsPlatformAdapter()
    if sys.platform.startswith("linux"):
        from wto_desktop_agent.platforms.linux.adapter import LinuxPlatformAdapter

        return LinuxPlatformAdapter()
    raise RuntimeError(f"unsupported desktop platform: {sys.platform}")
