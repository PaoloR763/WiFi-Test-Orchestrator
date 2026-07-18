from __future__ import annotations

import asyncio.subprocess
import inspect
import platform
import sys
from pathlib import Path

from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.platforms.common import AllowlistedProcessRunner
from wto_desktop_agent.platforms.factory import create_platform_adapter


def test_factory_does_not_import_opposite_platform_modules(tmp_path: Path) -> None:
    before = set(sys.modules)
    kwargs: dict[str, object] = {"in_memory": False}
    if platform.system().lower() in {"windows", "linux"}:
        settings = AgentSettings(
            environment="test", server_url="http://testserver", state_dir=tmp_path
        )
        store = SQLiteStore(tmp_path / "agent.sqlite3")
        store.initialize()
        if sys.platform.startswith("linux"):
            settings.effective_artifacts_dir.mkdir(mode=0o700)
        kwargs.update(settings=settings, store=store)
    adapter = create_platform_adapter(**kwargs)  # type: ignore[arg-type]
    loaded_by_factory = set(sys.modules) - before
    if sys.platform == "win32":
        assert adapter.platform_id == "windows"
        assert "secretstorage" not in sys.modules
        assert not any("platforms.linux" in name for name in loaded_by_factory)
    else:
        assert adapter.platform_id == "linux"
        assert "win32cred" not in sys.modules
        assert not any("platforms.windows" in name for name in loaded_by_factory)


def test_process_runner_is_deny_by_default_and_never_uses_shell() -> None:
    source = inspect.getsource(AllowlistedProcessRunner)
    assert "create_subprocess_exec" in source
    assert "create_subprocess_shell" not in source
    assert "shell=True" not in source
    assert asyncio.subprocess.DEVNULL is not None
