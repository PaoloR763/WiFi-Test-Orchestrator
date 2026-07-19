from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from wto_desktop_agent.platforms.common import (
    CommandSpec,
    LinuxCleanupScope,
    LinuxProcessRunner,
)
from wto_desktop_agent.platforms.linux.cgroup import CgroupV2Manager
from wto_desktop_agent.ports.platform import CommandRequest
from wto_desktop_agent.ports.plugins import CancellationToken

pytestmark = [
    pytest.mark.linux,
    pytest.mark.skipif(sys.platform != "linux", reason="requires Linux"),
    pytest.mark.skipif(
        os.environ.get("WTO_RUN_PRIVILEGED_LINUX_TESTS") != "1",
        reason="set WTO_RUN_PRIVILEGED_LINUX_TESTS=1 on an authorized disposable lab host",
    ),
]


def test_privileged_suite_requires_explicit_lab_harness() -> None:
    """Sentinel: real NIC transitions are implemented by the external lab runbook."""
    assert os.geteuid() == 0


class _EmptyArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


@pytest.mark.asyncio
async def test_real_cgroup_kills_setsid_descendant_in_delegated_harness(
    tmp_path: Path,
) -> None:
    manager = CgroupV2Manager()
    readiness = manager.readiness
    if not readiness.available:
        pytest.skip(f"real delegated cgroup v2 unavailable: {readiness.reason}")
    child_pid = tmp_path / "setsid-child.pid"
    code = (
        "import os,time;from pathlib import Path;"
        "child=os.fork();"
        f"Path({str(child_pid)!r}).write_text(str(child)) if child else None;"
        "os.setsid() if child == 0 else None;"
        "time.sleep(30)"
    )
    spec = CommandSpec(
        command_id="linux-test.cgroup-setsid",
        executable=Path(sys.executable).resolve(strict=True),
        argument_model=_EmptyArguments,
        build_argv=lambda _value: ["-c", code],
        cwd=tmp_path,
        environment={"PYTHONDONTWRITEBYTECODE": "1"},
        linux_cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
    )
    runner = LinuxProcessRunner({spec.command_id: spec}, cgroup_manager=manager)

    with pytest.raises(TimeoutError):
        await runner.run(
            CommandRequest(
                command_id=spec.command_id,
                arguments={},
                timeout_seconds=0.5,
            ),
            CancellationToken(),
        )

    assert child_pid.is_file()
    descendant = int(child_pid.read_text(encoding="utf-8"))
    for _ in range(100):
        if not Path(f"/proc/{descendant}").exists():
            break
        await asyncio.sleep(0.01)
    assert not Path(f"/proc/{descendant}").exists()
