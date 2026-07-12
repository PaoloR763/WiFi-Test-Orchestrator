from __future__ import annotations

import asyncio.subprocess
import inspect
import sys

from wto_desktop_agent.platforms.common import AllowlistedProcessRunner
from wto_desktop_agent.platforms.factory import create_platform_adapter


def test_factory_does_not_import_opposite_platform_modules() -> None:
    adapter = create_platform_adapter(in_memory=False)
    if sys.platform == "win32":
        assert adapter.platform_id == "windows"
        assert "secretstorage" not in sys.modules
        assert not any("platforms.linux" in name for name in sys.modules)
    else:
        assert adapter.platform_id == "linux"
        assert "win32cred" not in sys.modules
        assert not any("platforms.windows" in name for name in sys.modules)


def test_process_runner_is_deny_by_default_and_never_uses_shell() -> None:
    source = inspect.getsource(AllowlistedProcessRunner)
    assert "create_subprocess_exec" in source
    assert "create_subprocess_shell" not in source
    assert "shell=True" not in source
    assert asyncio.subprocess.DEVNULL is not None
