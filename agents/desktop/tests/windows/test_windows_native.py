from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from pydantic import BaseModel

from wto_desktop_agent.domain.errors import (
    PluginUnavailableError,
    SecureStoreUnavailableError,
)
from wto_desktop_agent.platforms.factory import create_platform_adapter
from wto_desktop_agent.ports.platform import CommandRequest
from wto_desktop_agent.ports.plugins import CancellationToken

pytestmark = [
    pytest.mark.windows,
    pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows"),
]


def test_factory_creates_real_windows_adapter_without_linux_imports() -> None:
    assert "secretstorage" not in sys.modules
    assert not any("platforms.linux" in name for name in sys.modules)

    import pywintypes
    import win32api
    import win32con
    import win32cred
    import win32job

    from wto_desktop_agent.platforms.windows.adapter import WindowsPlatformAdapter
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner
    from wto_desktop_agent.platforms.windows.secret_store import (
        WindowsCredentialManagerStore,
    )

    adapter = create_platform_adapter(in_memory=False)

    assert isinstance(adapter, WindowsPlatformAdapter)
    assert adapter.platform_id == "windows"
    assert isinstance(adapter.process_runner, WindowsProcessRunner)
    assert isinstance(adapter.secret_store, WindowsCredentialManagerStore)
    assert adapter.secret_store.secure is True
    assert all(
        module.__loader__ is not None
        for module in (pywintypes, win32api, win32con, win32cred, win32job)
    )
    assert "secretstorage" not in sys.modules
    assert not any("platforms.linux" in name for name in sys.modules)


def test_windows_secret_store_fails_closed_on_credential_manager_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32cred

    from wto_desktop_agent.platforms.windows.secret_store import (
        WindowsCredentialManagerStore,
    )

    store = WindowsCredentialManagerStore()
    failure = OSError("controlled Credential Manager failure")
    monkeypatch.setattr(win32cred, "CredWrite", Mock(side_effect=failure))
    monkeypatch.setattr(win32cred, "CredRead", Mock(side_effect=failure))

    with pytest.raises(SecureStoreUnavailableError, match="write failed"):
        store.put("credential-active", "controlled-test-value")
    with pytest.raises(SecureStoreUnavailableError, match="read failed"):
        store.get("credential-active")


@pytest.mark.asyncio
async def test_windows_process_runner_is_deny_by_default() -> None:
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    runner = WindowsProcessRunner()
    with pytest.raises(PluginUnavailableError, match="not locally allowlisted"):
        await runner.run(
            CommandRequest(
                command_id="not-allowlisted",
                arguments={},
                timeout_seconds=1.0,
            ),
            CancellationToken(),
        )


class EmptyArguments(BaseModel):
    pass


@pytest.mark.asyncio
async def test_windows_process_runner_uses_exec_and_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32con

    from wto_desktop_agent.platforms.common import CommandSpec
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    process = SimpleNamespace(pid=4200)
    create_process = AsyncMock(return_value=process)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    executable = Path(sys.executable).resolve()
    spec = CommandSpec(
        command_id="controlled-test",
        executable=executable,
        argument_model=EmptyArguments,
        build_argv=lambda _: [],
        cwd=executable.parent,
        environment={},
    )

    runner = WindowsProcessRunner()
    result = await runner.start_process(spec, ["python.exe"], {"PATH": "controlled"})

    assert result is process
    create_process.assert_awaited_once_with(
        str(spec.executable),
        "python.exe",
        cwd=spec.cwd,
        env={"PATH": "controlled"},
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=win32con.CREATE_NEW_PROCESS_GROUP,
    )


def test_windows_process_runner_configures_and_assigns_kill_on_close_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32api
    import win32con
    import win32job

    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    process_id = 4201
    job = object()
    process_handle = Mock()
    information = {"BasicLimitInformation": {"LimitFlags": 0}}
    create_job = Mock(return_value=job)
    query_job = Mock(return_value=information)
    set_job = Mock()
    open_process = Mock(return_value=process_handle)
    assign_process = Mock()
    monkeypatch.setattr(win32job, "CreateJobObject", create_job)
    monkeypatch.setattr(win32job, "QueryInformationJobObject", query_job)
    monkeypatch.setattr(win32job, "SetInformationJobObject", set_job)
    monkeypatch.setattr(win32api, "OpenProcess", open_process)
    monkeypatch.setattr(win32job, "AssignProcessToJobObject", assign_process)

    runner = WindowsProcessRunner()
    runner.after_start(SimpleNamespace(pid=process_id))  # type: ignore[arg-type]

    create_job.assert_called_once_with(None, "")
    query_job.assert_called_once_with(job, win32job.JobObjectExtendedLimitInformation)
    assert (
        information["BasicLimitInformation"]["LimitFlags"]
        & win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    set_job.assert_called_once_with(
        job,
        win32job.JobObjectExtendedLimitInformation,
        information,
    )
    open_process.assert_called_once_with(
        win32con.PROCESS_TERMINATE | win32con.PROCESS_SET_QUOTA,
        False,
        process_id,
    )
    assign_process.assert_called_once_with(job, process_handle)
    process_handle.Close.assert_called_once_with()
