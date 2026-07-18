from __future__ import annotations

import asyncio
import hashlib
import os
import signal
from pathlib import Path
from typing import Any

import pytest

from wto_desktop_agent.platforms.common import (
    LinuxProcessContext,
    LinuxProcessRunner,
)
from wto_desktop_agent.platforms.linux.capture import (
    CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE,
    PCAP_REPLAY_CAPABILITY,
    PrivilegedAuthorizationDecision,
    UnavailableControlPlaneAuthorization,
)
from wto_desktop_agent.platforms.linux.replay import (
    ReplayRequest,
    TcpreplayValidator,
)
from wto_desktop_agent.ports.plugins import CancellationToken

AGENT_ID = "40000000-0000-4000-8000-000000000001"


class StaticReplayGrant:
    def __init__(
        self,
        agent_id: str = AGENT_ID,
        capabilities: frozenset[str] = frozenset({PCAP_REPLAY_CAPABILITY}),
    ) -> None:
        self.agent_id = agent_id
        self.capabilities = capabilities

    def authorize(
        self, *, agent_id: str | None, capability_id: str
    ) -> PrivilegedAuthorizationDecision:
        allowed = agent_id == self.agent_id and capability_id in self.capabilities
        return PrivilegedAuthorizationDecision(
            allowed,
            None if allowed else CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE,
        )


def _request(**overrides: object) -> ReplayRequest:
    values: dict[str, object] = {
        "interface": "lab0",
        "scenario_id": "lab.approved",
        "artifact_name": "approved.pcap",
        "namespace": "wto-lab",
        "duration_seconds": 10,
        "rate_mbps": 20,
        "loops": 1,
    }
    values.update(overrides)
    return ReplayRequest.model_validate(values)


def _validator(tmp_path: Path, **overrides: object) -> TcpreplayValidator:
    if os.name != "posix":
        pytest.skip("secure replay descriptor semantics require POSIX")
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir(parents=True, exist_ok=True)
    artifact_root.chmod(0o700)
    artifact = artifact_root / "approved.pcap"
    artifact.write_bytes(b"approved replay fixture")
    artifact.chmod(0o600)
    namespace_root = tmp_path / "netns"
    namespace_root.mkdir(exist_ok=True)
    (namespace_root / "wto-lab").write_bytes(b"namespace marker")
    values: dict[str, object] = {
        "role": "capture_node",
        "policy_enabled": True,
        "agent_id_provider": lambda: AGENT_ID,
        "authorization": StaticReplayGrant(),
        "tool_ready": True,
        "tree_containment_ready": True,
        "artifact_root": artifact_root,
        "approved_artifacts": {"approved.pcap": hashlib.sha256(artifact.read_bytes()).hexdigest()},
        "allowed_interfaces": frozenset({"lab0"}),
        "allowed_scenarios": frozenset({"lab.approved"}),
        "namespace": "wto-lab",
        "namespace_root": namespace_root,
        "max_duration_seconds": 30,
        "max_rate_mbps": 100,
        "max_loops": 2,
        "max_size_bytes": 4096,
    }
    values.update(overrides)
    return TcpreplayValidator(**values)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_tcpreplay_valid_simulation_and_cancellation_cleanup(
    tmp_path: Path,
) -> None:
    validator = _validator(tmp_path)
    result = await validator.simulate(_request(), CancellationToken())
    token = CancellationToken()
    token.cancel()
    cancelled = await validator.simulate(_request(), token)

    assert result.status == "validated"
    assert result.cleanup_complete
    assert cancelled.status == "cancelled"
    assert validator.cleanup_calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization,agent_id_provider",
    [
        (UnavailableControlPlaneAuthorization(), lambda: AGENT_ID),
        (StaticReplayGrant(agent_id="other-agent"), lambda: AGENT_ID),
        (
            StaticReplayGrant(capabilities=frozenset({"capture.ieee80211.monitor"})),
            lambda: AGENT_ID,
        ),
    ],
)
async def test_replay_requires_exact_server_issued_agent_and_capability_grant(
    tmp_path: Path,
    authorization: object,
    agent_id_provider: object,
) -> None:
    validator = _validator(
        tmp_path,
        authorization=authorization,
        agent_id_provider=agent_id_provider,
    )
    with pytest.raises(PermissionError, match=CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE):
        await validator.simulate(_request(), CancellationToken())
    assert validator.cleanup_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "validator_overrides,request_overrides,error",
    [
        ({"role": "endpoint"}, {}, PermissionError),
        ({"policy_enabled": False}, {}, PermissionError),
        ({"tool_ready": False}, {}, PermissionError),
        ({"tree_containment_ready": False}, {}, PermissionError),
        ({"allowed_interfaces": frozenset({"lab1"})}, {}, PermissionError),
        ({"allowed_scenarios": frozenset({"lab.other"})}, {}, PermissionError),
        ({"approved_artifacts": {}}, {}, PermissionError),
        ({"namespace": "other"}, {}, PermissionError),
        ({"max_duration_seconds": 5}, {}, PermissionError),
        ({"max_rate_mbps": 10}, {}, PermissionError),
        ({"max_loops": 0}, {}, PermissionError),
    ],
)
async def test_tcpreplay_is_deny_by_default(
    tmp_path: Path,
    validator_overrides: dict[str, object],
    request_overrides: dict[str, object],
    error: type[Exception],
) -> None:
    validator = _validator(tmp_path, **validator_overrides)
    with pytest.raises(error):
        await validator.simulate(_request(**request_overrides), CancellationToken())
    assert validator.cleanup_calls == 0


@pytest.mark.asyncio
async def test_tcpreplay_rechecks_tree_containment_at_authorization_time(
    tmp_path: Path,
) -> None:
    readiness = [True]
    validator = _validator(
        tmp_path,
        tree_containment_ready=lambda: readiness[0],
    )
    assert validator.authorization_decision().allowed

    readiness[0] = False
    with pytest.raises(PermissionError):
        await validator.simulate(_request(), CancellationToken())

    assert validator.cleanup_calls == 0


@pytest.mark.asyncio
async def test_replay_validates_artifact_before_final_execution_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    validator = _validator(
        tmp_path,
        tree_containment_ready=lambda: events.append("final_authorization") or False,
    )

    async def validated_artifact(
        _request: ReplayRequest,
        expected_sha256: str,
        _cancellation: CancellationToken,
    ) -> str:
        events.append("artifact_validation")
        return expected_sha256

    monkeypatch.setattr(validator, "_hash_approved_artifact", validated_artifact)

    with pytest.raises(PermissionError):
        await validator.simulate(_request(), CancellationToken())

    assert events == ["artifact_validation", "final_authorization"]
    assert validator.cleanup_calls == 0


@pytest.mark.asyncio
async def test_tcpreplay_rejects_hash_mismatch_namespace_absence_and_oversize(
    tmp_path: Path,
) -> None:
    mismatch = _validator(tmp_path, approved_artifacts={"approved.pcap": "0" * 64})
    with pytest.raises(PermissionError, match="hash"):
        await mismatch.simulate(_request(), CancellationToken())

    absent = _validator(tmp_path)
    (tmp_path / "netns" / "wto-lab").unlink()
    with pytest.raises(RuntimeError, match="namespace"):
        await absent.simulate(_request(), CancellationToken())

    oversize = _validator(tmp_path, max_size_bytes=4)
    with pytest.raises(PermissionError, match="size"):
        await oversize.simulate(_request(), CancellationToken())


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [0o400, 0o600])
async def test_replay_accepts_only_approved_service_owned_file_modes(
    tmp_path: Path,
    mode: int,
) -> None:
    validator = _validator(tmp_path)
    artifact = tmp_path / "artifacts" / "approved.pcap"
    artifact.chmod(mode)

    result = await validator.simulate(_request(), CancellationToken())

    assert result.status == "validated"
    assert result.artifact_sha256 == hashlib.sha256(artifact.read_bytes()).hexdigest()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [0o440, 0o644, 0o640, 0o666])
async def test_replay_rejects_group_or_world_accessible_artifact_modes(
    tmp_path: Path,
    mode: int,
) -> None:
    validator = _validator(tmp_path)
    (tmp_path / "artifacts" / "approved.pcap").chmod(mode)

    with pytest.raises(PermissionError, match="0400 or 0600"):
        await validator.simulate(_request(), CancellationToken())

    assert validator.cleanup_calls == 0


@pytest.mark.asyncio
async def test_replay_rejects_artifact_root_mode_and_owner_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad_mode = _validator(tmp_path / "bad-mode")
    (tmp_path / "bad-mode" / "artifacts").chmod(0o750)
    with pytest.raises(PermissionError, match="0700"):
        await bad_mode.simulate(_request(), CancellationToken())

    bad_owner = _validator(tmp_path / "bad-owner")
    actual_uid = os.stat(tmp_path / "bad-owner" / "artifacts").st_uid
    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.replay._effective_uid",
        lambda: actual_uid + 1,
    )
    with pytest.raises(PermissionError, match="owner"):
        await bad_owner.simulate(_request(), CancellationToken())


def test_replay_artifact_file_owner_must_be_effective_service_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import replay as replay_module

    artifact = tmp_path / "owned.pcap"
    artifact.write_bytes(b"fixture")
    artifact.chmod(0o600)
    metadata = artifact.stat()
    monkeypatch.setattr(replay_module, "_effective_uid", lambda: metadata.st_uid + 1)

    with pytest.raises(PermissionError, match="owner"):
        replay_module._validate_artifact_file(metadata, max_size_bytes=4096)


@pytest.mark.asyncio
async def test_replay_hashes_multiple_bounded_chunks_without_read_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator = _validator(tmp_path, max_size_bytes=4 * 1_048_576)
    artifact = tmp_path / "artifacts" / "approved.pcap"
    content = b"a" * 1_048_576 + b"b" * 1_048_576 + b"tail"
    artifact.write_bytes(content)
    artifact.chmod(0o600)
    validator.approved_artifacts[artifact.name] = hashlib.sha256(content).hexdigest()
    requested_sizes: list[int] = []
    real_read = os.read

    def recording_read(descriptor: int, size: int) -> bytes:
        requested_sizes.append(size)
        return real_read(descriptor, size)

    monkeypatch.setattr("wto_desktop_agent.platforms.linux.replay.os.read", recording_read)
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda _self: (_ for _ in ()).throw(AssertionError("read_bytes is forbidden")),
    )

    result = await validator.simulate(_request(), CancellationToken())

    assert result.status == "validated"
    assert result.artifact_sha256 == hashlib.sha256(content).hexdigest()
    assert requested_sizes == [1_048_576, 1_048_576, 4, 1]
    assert max(requested_sizes) <= 1_048_576


@pytest.mark.asyncio
async def test_replay_maximum_size_hash_is_simulated_with_constant_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import replay as replay_module

    maximum_size = 1_073_741_824
    remaining = maximum_size
    block = b"x" * 1_048_576
    requested_sizes: list[int] = []

    def simulated_read(_descriptor: int, size: int) -> bytes:
        nonlocal remaining
        requested_sizes.append(size)
        if remaining == 0:
            return b""
        length = min(size, remaining)
        remaining -= length
        return block if length == len(block) else block[:length]

    class CountingDigest:
        def __init__(self) -> None:
            self.total = 0

        def update(self, chunk: bytes) -> None:
            self.total += len(chunk)

        def hexdigest(self) -> str:
            assert self.total == maximum_size
            return "a" * 64

    digest = CountingDigest()
    monkeypatch.setattr(replay_module.os, "read", simulated_read)
    monkeypatch.setattr(replay_module.hashlib, "sha256", lambda: digest)

    actual = await replay_module._hash_descriptor(
        123,
        maximum_size,
        CancellationToken(),
        deadline=asyncio.get_running_loop().time() + 30,
    )

    assert actual == "a" * 64
    assert remaining == 0
    assert requested_sizes[-1] == 1
    assert max(requested_sizes) <= 1_048_576
    assert len(requested_sizes) == 1025


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["truncate", "grow", "rewrite", "replace"])
async def test_replay_detects_concurrent_artifact_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    validator = _validator(tmp_path, max_size_bytes=4 * 1_048_576)
    artifact = tmp_path / "artifacts" / "approved.pcap"
    original = b"a" * (1_048_576 + 32)
    artifact.write_bytes(original)
    artifact.chmod(0o600)
    validator.approved_artifacts[artifact.name] = hashlib.sha256(original).hexdigest()
    real_read = os.read
    mutated = False

    def racing_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        if not mutated:
            mutated = True
            if mutation == "truncate":
                artifact.write_bytes(original[:64])
                artifact.chmod(0o600)
            elif mutation == "grow":
                with artifact.open("ab") as stream:
                    stream.write(b"growth")
            elif mutation == "rewrite":
                artifact.write_bytes(b"z" * len(original))
                artifact.chmod(0o600)
            else:
                replacement = artifact.with_suffix(".replacement")
                replacement.write_bytes(original)
                replacement.chmod(0o600)
                os.replace(replacement, artifact)
        return real_read(descriptor, size)

    monkeypatch.setattr("wto_desktop_agent.platforms.linux.replay.os.read", racing_read)

    with pytest.raises(PermissionError, match="truncated|grew|changed|hash"):
        await validator.simulate(_request(), CancellationToken())

    assert validator.cleanup_calls == 0


@pytest.mark.asyncio
async def test_replay_rejects_symlink_and_hardlink_artifacts(tmp_path: Path) -> None:
    symlink_validator = _validator(tmp_path / "symlink")
    root = tmp_path / "symlink" / "artifacts"
    artifact = root / "approved.pcap"
    outside = tmp_path / "symlink" / "outside.pcap"
    outside.write_bytes(artifact.read_bytes())
    outside.chmod(0o600)
    artifact.unlink()
    artifact.symlink_to(outside)
    with pytest.raises((OSError, PermissionError)):
        await symlink_validator.simulate(_request(), CancellationToken())

    hardlink_validator = _validator(tmp_path / "hardlink")
    hardlink_artifact = tmp_path / "hardlink" / "artifacts" / "approved.pcap"
    os.link(hardlink_artifact, hardlink_artifact.with_suffix(".other"))
    with pytest.raises(PermissionError, match="exactly one link"):
        await hardlink_validator.simulate(_request(), CancellationToken())


@pytest.mark.asyncio
async def test_replay_cancellation_during_hash_closes_descriptors_and_stops_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator = _validator(tmp_path, max_size_bytes=4 * 1_048_576)
    artifact = tmp_path / "artifacts" / "approved.pcap"
    content = b"a" * (2 * 1_048_576)
    artifact.write_bytes(content)
    artifact.chmod(0o600)
    validator.approved_artifacts[artifact.name] = hashlib.sha256(content).hexdigest()
    token = CancellationToken()
    real_read = os.read
    read_calls = 0
    closed: list[int] = []

    def cancelling_read(descriptor: int, size: int) -> bytes:
        nonlocal read_calls
        read_calls += 1
        chunk = real_read(descriptor, size)
        token.cancel()
        return chunk

    from wto_desktop_agent.platforms.linux import replay as replay_module

    real_close = replay_module.close_descriptor

    def recording_close(
        descriptor: int,
        *,
        primary_error: BaseException | None = None,
        context: str = "descriptor",
    ) -> None:
        closed.append(descriptor)
        real_close(descriptor, primary_error=primary_error, context=context)

    monkeypatch.setattr(replay_module.os, "read", cancelling_read)
    monkeypatch.setattr(replay_module, "close_descriptor", recording_close)

    result = await validator.simulate(_request(), token)

    assert result.status == "cancelled"
    assert read_calls == 1
    assert closed
    assert len(closed) == len(set(closed))
    assert validator.cleanup_calls == 1


@pytest.mark.asyncio
async def test_replay_hash_deadline_closes_descriptors_without_validation_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator = _validator(tmp_path)
    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.replay._HASH_TIMEOUT_SECONDS",
        0.0,
    )

    with pytest.raises(TimeoutError, match="deadline"):
        await validator.simulate(_request(), CancellationToken())

    assert validator.cleanup_calls == 0


@pytest.mark.asyncio
async def test_replay_revalidates_named_identity_and_closes_each_descriptor_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator = _validator(tmp_path)
    from wto_desktop_agent.platforms.linux import replay as replay_module

    real_close = replay_module.close_descriptor
    real_open = replay_module.os.open
    closed: list[int] = []
    artifact_open_calls = 0

    def recording_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal artifact_open_calls
        if path == "approved.pcap":
            artifact_open_calls += 1
        return real_open(path, flags, mode, dir_fd=dir_fd)

    def recording_close(
        descriptor: int,
        *,
        primary_error: BaseException | None = None,
        context: str = "descriptor",
    ) -> None:
        closed.append(descriptor)
        real_close(descriptor, primary_error=primary_error, context=context)

    monkeypatch.setattr(replay_module.os, "open", recording_open)
    monkeypatch.setattr(replay_module, "close_descriptor", recording_close)

    await validator.simulate(_request(), CancellationToken())

    assert len(closed) >= 3
    assert len(closed) == len(set(closed))
    assert artifact_open_calls == 1


@pytest.mark.asyncio
async def test_replay_preserves_primary_validation_error_when_close_also_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator = _validator(tmp_path, approved_artifacts={"approved.pcap": "0" * 64})
    from wto_desktop_agent.platforms.linux import replay as replay_module

    real_close = replay_module.close_descriptor
    artifact_close_calls = 0

    def close_then_report_failure(
        descriptor: int,
        *,
        primary_error: BaseException | None = None,
        context: str = "descriptor",
    ) -> None:
        nonlocal artifact_close_calls
        real_close(descriptor, primary_error=primary_error, context=context)
        if context != "replay artifact":
            return
        artifact_close_calls += 1
        close_error = OSError("injected close failure")
        if primary_error is None:
            raise close_error
        primary_error.add_note(f"secondary replay artifact close failure: {close_error!r}")

    monkeypatch.setattr(replay_module, "close_descriptor", close_then_report_failure)

    with pytest.raises(PermissionError, match="hash") as raised:
        await validator.simulate(_request(), CancellationToken())

    assert artifact_close_calls == 1
    assert any("close failure" in note for note in getattr(raised.value, "__notes__", ()))


def test_tcpreplay_request_rejects_arbitrary_arguments_paths_and_destinations() -> None:
    baseline = _request().model_dump()
    for extra in (
        {"arguments": ["--topspeed"]},
        {"destination": "internet.example"},
        {"artifact_path": "external/path.pcap"},
    ):
        with pytest.raises(ValueError):
            ReplayRequest.model_validate({**baseline, **extra})
    with pytest.raises(ValueError):
        _request(artifact_name="../external.pcap")


class FakePipeTransport:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class FakeProcessTransport:
    def __init__(self) -> None:
        self.close_calls = 0
        self.pipes = {1: FakePipeTransport(), 2: FakePipeTransport()}

    def close(self) -> None:
        self.close_calls += 1

    def get_pipe_transport(self, descriptor: int) -> FakePipeTransport | None:
        return self.pipes.get(descriptor)


class FakeProcess:
    def __init__(self, *, returncode: int | None = None, block_first_wait: bool = False) -> None:
        self.pid = 8123
        self.returncode = returncode
        self.wait_calls = 0
        self.kill_calls = 0
        self.block_first_wait = block_first_wait
        self._transport = FakeProcessTransport()

    def kill(self) -> None:
        self.kill_calls += 1

    async def wait(self) -> int:
        self.wait_calls += 1
        if self.block_first_wait and self.wait_calls == 1:
            await asyncio.Future()
        if self.returncode is None:
            self.returncode = -int(getattr(signal, "SIGKILL", 9))
        return self.returncode


def _context(process: FakeProcess, start_time: str = "100") -> LinuxProcessContext:
    return LinuxProcessContext(
        process=process,  # type: ignore[arg-type]
        pid=process.pid,
        process_group_id=process.pid,
        session_id=process.pid,
        start_time=start_time,
        pidfd=99,
    )


@pytest.mark.asyncio
async def test_linux_cleanup_refuses_lost_pidfd_through_productive_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = LinuxProcessRunner({})
    process = FakeProcess()
    context = _context(process)
    runner._contexts[id(process)] = context
    monkeypatch.setattr(
        "wto_desktop_agent.platforms.common._PIDFD_SEND_SIGNAL",
        lambda _pidfd, _signal: (_ for _ in ()).throw(ProcessLookupError()),
    )
    closed: list[int] = []
    monkeypatch.setattr("wto_desktop_agent.platforms.common.os.close", closed.append)

    with pytest.raises(RuntimeError, match="cleanup_identity_lost"):
        await runner._cleanup_process(  # type: ignore[arg-type]
            process,
            [],
            terminate=True,
            deadline=asyncio.get_running_loop().time() + 1,
        )
    assert process.kill_calls == 0
    assert process._transport.close_calls == 0
    assert all(pipe.close_calls == 1 for pipe in process._transport.pipes.values())
    assert context.closed
    assert closed == [99]
    assert id(process) not in runner._contexts


@pytest.mark.asyncio
async def test_linux_pidfd_uses_bounded_sigterm_then_sigkill_and_reaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = LinuxProcessRunner({})
    process = FakeProcess()
    runner._contexts[id(process)] = _context(process)
    signals: list[int] = []

    def send(_pidfd: int, sig: int) -> None:
        signals.append(sig)

    calls = 0

    async def controlled_wait_for(awaitable: Any, **kwargs: float) -> Any:
        nonlocal calls
        del kwargs
        calls += 1
        if calls == 1:
            awaitable.cancel()
            raise TimeoutError
        return await awaitable

    monkeypatch.setattr("wto_desktop_agent.platforms.common._PIDFD_SEND_SIGNAL", send)
    monkeypatch.setattr(asyncio, "wait_for", controlled_wait_for)

    await runner.terminate(process)  # type: ignore[arg-type]

    assert signals == [
        0,
        int(getattr(signal, "SIGTERM", 15)),
        0,
        int(getattr(signal, "SIGKILL", 9)),
    ]
    assert process.wait_calls == 1


@pytest.mark.asyncio
async def test_linux_process_already_finished_and_context_cleanup_are_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = LinuxProcessRunner({})
    process = FakeProcess(returncode=0)
    context = _context(process)
    runner._contexts[id(process)] = context
    closed: list[int] = []
    monkeypatch.setattr("wto_desktop_agent.platforms.common.os.close", closed.append)

    runner._force_cleanup_process(process)  # type: ignore[arg-type]
    runner._force_cleanup_process(process)  # type: ignore[arg-type]

    assert closed == [99]


@pytest.mark.asyncio
async def test_finished_leader_only_command_does_not_claim_tree_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = LinuxProcessRunner({})
    process = FakeProcess(returncode=0)
    context = _context(process)
    runner._contexts[id(process)] = context
    closed: list[int] = []
    monkeypatch.setattr("wto_desktop_agent.platforms.common.os.close", closed.append)

    await runner._cleanup_process(  # type: ignore[arg-type]
        process,
        [],
        terminate=False,
        deadline=asyncio.get_running_loop().time() + 1,
    )

    assert process.kill_calls == 0
    assert context.closed
    assert closed == [99]
