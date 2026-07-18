from __future__ import annotations

import asyncio
import inspect
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import pytest

import wto_desktop_agent.platforms.linux.cgroup as cgroup_module
from wto_desktop_agent.platforms.linux.cgroup import (
    CgroupCleanupIncompleteError,
    CgroupContainmentError,
    CgroupExecutionState,
    CgroupIdentity,
    CgroupReadiness,
    CgroupUnavailableError,
    CgroupV2Manager,
)


@dataclass
class FakeLeaf:
    path: Path
    pids: list[int]
    populated_override: bool | None = None
    closed: bool = False


class FakeCgroupFs:
    """Portable directory-backed simulation of the cgroupfs control surface."""

    def __init__(self, root: Path, *, ready: bool = True) -> None:
        self.root = root
        self.root.mkdir()
        self.ready = ready
        self.reason = None if ready else "cgroup_subtree_not_delegated"
        self.created_names: list[str] = []
        self.attach_calls: list[int] = []
        self.kill_calls = 0
        self.remove_calls = 0
        self.close_calls = 0
        self.lose_attached_pid = False
        self.kill_error: BaseException | None = None
        self.kill_leaves_populated = False
        self.close_error: BaseException | None = None
        self.identity_changed = False
        self.collisions = 0

    def probe(self) -> CgroupReadiness:
        return CgroupReadiness(
            self.ready,
            self.reason,
            PurePosixPath("/fake/delegated") if self.ready else None,
        )

    def create(self, local_name: str) -> tuple[object, CgroupIdentity]:
        if self.collisions:
            self.collisions -= 1
            raise FileExistsError(local_name)
        path = self.root / local_name
        path.mkdir(mode=0o700)
        metadata = path.stat()
        self.created_names.append(local_name)
        identity = CgroupIdentity(
            mount_device=int(self.root.stat().st_dev),
            mount_inode=int(self.root.stat().st_ino),
            parent_device=int(self.root.stat().st_dev),
            parent_inode=int(self.root.stat().st_ino),
            device=int(metadata.st_dev),
            inode=int(metadata.st_ino),
            owner_uid=0,
            mode=0o700,
            relative_path=PurePosixPath("/fake/delegated") / local_name,
            local_name=local_name,
        )
        return FakeLeaf(path, []), identity

    def attach(self, resource: object, pid: int) -> None:
        leaf = self._leaf(resource)
        self.attach_calls.append(pid)
        if not self.lose_attached_pid:
            leaf.pids.append(pid)

    def pids(self, resource: object) -> tuple[int, ...]:
        return tuple(self._leaf(resource).pids)

    def populated(self, resource: object) -> bool:
        leaf = self._leaf(resource)
        if leaf.populated_override is not None:
            return leaf.populated_override
        return bool(leaf.pids)

    def kill(self, resource: object) -> None:
        leaf = self._leaf(resource)
        self.kill_calls += 1
        if self.kill_error is not None:
            raise self.kill_error
        if not self.kill_leaves_populated:
            leaf.pids.clear()
            leaf.populated_override = False

    def remove(self, resource: object, identity: CgroupIdentity) -> None:
        leaf = self._leaf(resource)
        self.remove_calls += 1
        if self.identity_changed:
            raise CgroupContainmentError("execution cgroup identity changed before removal")
        metadata = leaf.path.stat()
        if (int(metadata.st_dev), int(metadata.st_ino)) != (
            identity.device,
            identity.inode,
        ):
            raise CgroupContainmentError("execution cgroup identity changed before removal")
        if self.populated(leaf) or leaf.pids:
            raise OSError("simulated cgroup is busy")
        leaf.path.rmdir()

    def close(self, resource: object) -> None:
        leaf = self._leaf(resource, allow_closed=True)
        self.close_calls += 1
        if leaf.closed:
            raise AssertionError("fake cgroup descriptor was closed twice")
        leaf.closed = True
        if self.close_error is not None:
            raise self.close_error

    @staticmethod
    def _leaf(resource: object, *, allow_closed: bool = False) -> FakeLeaf:
        assert isinstance(resource, FakeLeaf)
        if resource.closed and not allow_closed:
            raise RuntimeError("fake cgroup resource is closed")
        return resource

    @staticmethod
    def add_setsid_descendant(resource: object, pid: int) -> None:
        leaf = FakeCgroupFs._leaf(resource)
        # Session and process-group changes do not alter cgroup membership.
        leaf.pids.append(pid)


def _manager(tmp_path: Path, **kwargs: object) -> tuple[CgroupV2Manager, FakeCgroupFs]:
    backend = FakeCgroupFs(tmp_path / "fake-cgroup")
    manager = CgroupV2Manager(
        backend,
        nonce_factory=lambda _size: "a" * 32,
        **kwargs,  # type: ignore[arg-type]
    )
    return manager, backend


def test_readiness_and_local_execution_identity_are_stable(tmp_path: Path) -> None:
    manager, backend = _manager(tmp_path)

    assert manager.readiness == CgroupReadiness(
        True,
        None,
        PurePosixPath("/fake/delegated"),
    )
    handle = manager.create_execution()

    assert backend.created_names == ["wto-exec-" + "a" * 32]
    assert handle.path == PurePosixPath("/fake/delegated") / backend.created_names[0]
    assert handle.identity.local_name == backend.created_names[0]
    assert handle.state is CgroupExecutionState.CREATED
    handle.close()


def test_unavailable_or_invalid_local_name_fails_before_creation(
    tmp_path: Path,
) -> None:
    backend = FakeCgroupFs(tmp_path / "unavailable", ready=False)
    manager = CgroupV2Manager(backend)
    with pytest.raises(CgroupUnavailableError, match="not_delegated"):
        manager.create_execution()
    assert backend.created_names == []

    invalid_backend = FakeCgroupFs(tmp_path / "invalid")
    invalid = CgroupV2Manager(invalid_backend, nonce_factory=lambda _size: "remote/task/id")
    with pytest.raises(CgroupContainmentError, match="nonce"):
        invalid.create_execution()
    assert invalid_backend.created_names == []


def test_name_collision_gets_a_new_local_nonce(tmp_path: Path) -> None:
    backend = FakeCgroupFs(tmp_path / "collision")
    backend.collisions = 1
    nonces = iter(("a" * 32, "b" * 32))
    manager = CgroupV2Manager(backend, nonce_factory=lambda _size: next(nonces))

    handle = manager.create_execution()

    assert handle.identity.local_name == "wto-exec-" + "b" * 32
    handle.close()


def test_attach_and_verify_are_separate_fail_closed_transitions(tmp_path: Path) -> None:
    manager, backend = _manager(tmp_path)
    handle = manager.create_execution()

    handle.attach_pid(4123)
    assert handle.state is CgroupExecutionState.MOVED
    assert handle.attached_pid == 4123
    handle.verify_pid(4123)
    assert handle.state is CgroupExecutionState.ATTACHED
    handle.attach_verify(4123)
    assert backend.attach_calls == [4123]

    with pytest.raises(CgroupContainmentError, match="does not match"):
        handle.verify_pid(9999)
    handle.kill_remaining()
    handle.remove_empty()
    handle.close()


def test_missing_pid_verification_is_visible_and_never_claims_attachment(
    tmp_path: Path,
) -> None:
    manager, backend = _manager(tmp_path)
    backend.lose_attached_pid = True
    handle = manager.create_execution()

    with pytest.raises(CgroupContainmentError, match="not verified"):
        handle.attach_verify(4123)

    assert handle.state is CgroupExecutionState.INCOMPLETE
    assert isinstance(handle.incomplete_error, CgroupContainmentError)
    assert backend.attach_calls == [4123]
    handle.kill_remaining()
    handle.remove_empty()
    handle.close()


@pytest.mark.asyncio
async def test_setsid_descendant_stays_contained_and_cleanup_removes_once(
    tmp_path: Path,
) -> None:
    manager, backend = _manager(tmp_path)
    handle = manager.create_execution()
    handle.attach_verify(5100)
    backend.add_setsid_descendant(handle._resource, 5101)

    assert manager.pids(handle) == (5100, 5101)
    assert handle.is_populated()

    handle.kill_remaining()
    handle.kill_remaining()
    await handle.wait_empty(asyncio.get_running_loop().time() + 1)
    handle.remove_empty()
    handle.remove_empty()
    handle.close()
    handle.close()

    assert backend.kill_calls == 1
    assert backend.remove_calls == 1
    assert backend.close_calls == 1
    assert handle.removed and handle.closed
    assert not handle.path.name == "5100"


@pytest.mark.asyncio
async def test_populated_timeout_keeps_leaf_and_reports_incomplete(
    tmp_path: Path,
) -> None:
    clock = [10.0]

    async def advance(delay: float) -> None:
        clock[0] += delay
        await asyncio.sleep(0)

    manager, backend = _manager(tmp_path, clock=lambda: clock[0], sleep=advance)
    handle = manager.create_execution()
    handle.attach_verify(6200)
    backend.kill_leaves_populated = True
    handle.kill_remaining()

    with pytest.raises(TimeoutError, match="remained populated"):
        await handle.wait_empty(10.02)
    with pytest.raises(CgroupCleanupIncompleteError, match="still populated"):
        handle.remove_empty()

    assert handle.state is CgroupExecutionState.INCOMPLETE
    assert handle.path.name in {path.name for path in backend.root.iterdir()}
    assert backend.remove_calls == 0
    handle.close()


def test_kill_failure_and_identity_change_never_remove_unknown_cgroup(
    tmp_path: Path,
) -> None:
    manager, backend = _manager(tmp_path)
    handle = manager.create_execution()
    handle.attach_verify(7300)
    kill_error = OSError("cgroup.kill unavailable")
    backend.kill_error = kill_error

    with pytest.raises(OSError, match="cgroup.kill") as raised:
        handle.kill_remaining()
    assert raised.value is kill_error
    assert handle.state is CgroupExecutionState.INCOMPLETE
    assert backend.remove_calls == 0

    backend.kill_error = None
    handle.kill_remaining()
    backend.identity_changed = True
    with pytest.raises(CgroupContainmentError, match="identity changed"):
        handle.remove_empty()
    assert handle.path.name in {path.name for path in backend.root.iterdir()}
    handle.close()


@pytest.mark.asyncio
async def test_wait_cancellation_is_visible_and_does_not_remove(tmp_path: Path) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocked_sleep(_delay: float) -> None:
        entered.set()
        await release.wait()

    manager, backend = _manager(tmp_path, sleep=blocked_sleep)
    handle = manager.create_execution()
    handle.attach_verify(8400)
    waiting = asyncio.create_task(handle.wait_empty(asyncio.get_running_loop().time() + 30))
    await entered.wait()
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting

    assert handle.state is CgroupExecutionState.INCOMPLETE
    assert backend.remove_calls == 0
    handle.kill_remaining()
    handle.remove_empty()
    handle.close()


def test_close_error_is_once_and_preserves_primary_error(tmp_path: Path) -> None:
    manager, backend = _manager(tmp_path)
    handle = manager.create_execution()
    backend.close_error = OSError("controlled descriptor close failure")
    primary = RuntimeError("primary lifecycle error")

    handle.close(primary)
    handle.close(primary)

    assert backend.close_calls == 1
    assert handle.closed
    assert any("controlled descriptor close failure" in note for note in primary.__notes__)


def test_manager_uses_no_numeric_process_signals_or_process_group_cleanup() -> None:
    source = inspect.getsource(cgroup_module)

    for forbidden in (
        "os.kill(",
        "os.killpg(",
        ".terminate(",
        ".send_signal(",
        "process.kill(",
    ):
        assert forbidden not in source
    assert '"cgroup.kill"' in source
    assert '"cgroup.procs"' in source
    assert '"cgroup.events"' in source


def test_delegated_parent_does_not_require_writable_cgroup_kill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writes: list[str] = []

    def read_control(_descriptor: int, name: str, _limit: int) -> bytes:
        return {
            "cgroup.controllers": b"cpu memory\n",
            "cgroup.subtree_control": b"\n",
            "cgroup.procs": b"",
            "cgroup.events": b"populated 0\nfrozen 0\n",
            "cgroup.type": b"domain\n",
        }[name]

    monkeypatch.setattr(cgroup_module, "_read_control", read_control)
    monkeypatch.setattr(
        cgroup_module,
        "_open_and_close_writable",
        lambda _descriptor, name: writes.append(name),
    )

    cgroup_module._validate_parent_controls(17)

    assert writes == ["cgroup.subtree_control", "cgroup.procs"]
    assert "cgroup.kill" not in writes


def test_posix_leaf_creation_validates_cgroup_kill_not_parent() -> None:
    create_source = inspect.getsource(cgroup_module._PosixCgroupFsBackend.create)
    parent_source = inspect.getsource(cgroup_module._validate_parent_controls)

    assert '"cgroup.kill", os.O_WRONLY' in create_source
    assert '"cgroup.kill"' not in parent_source


def test_posix_readiness_probe_validates_and_removes_a_private_leaf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = cgroup_module._PosixCgroupFsBackend()
    resource = object()
    identity = CgroupIdentity(
        1,
        2,
        3,
        4,
        5,
        6,
        1000,
        0o700,
        PurePosixPath("/delegated/wto-exec-" + "a" * 32),
        "wto-exec-" + "a" * 32,
    )
    events: list[str] = []
    monkeypatch.setattr(backend, "create", lambda _name: (resource, identity))
    monkeypatch.setattr(backend, "populated", lambda _resource: False)
    monkeypatch.setattr(
        backend,
        "remove",
        lambda _resource, _identity: events.append("remove"),
    )
    monkeypatch.setattr(backend, "close", lambda _resource: events.append("close"))

    delegated = backend._probe_execution_leaf()

    assert delegated == PurePosixPath("/delegated")
    assert events == ["remove", "close"]


def test_posix_readiness_probe_missing_cgroup_kill_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = cgroup_module._PosixCgroupFsBackend()
    monkeypatch.setattr(
        backend,
        "_probe_execution_leaf",
        lambda: (_ for _ in ()).throw(FileNotFoundError("cgroup.kill")),
    )
    monkeypatch.setattr(cgroup_module.os, "name", "posix")
    monkeypatch.setattr(cgroup_module.sys, "platform", "linux")

    readiness = backend.probe()

    assert readiness.available is False
    assert readiness.reason == "cgroup_v2_control_missing"


def test_posix_readiness_probe_attempts_resource_close_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = cgroup_module._PosixCgroupFsBackend()
    resource = object()
    identity = CgroupIdentity(
        1,
        2,
        3,
        4,
        5,
        6,
        1000,
        0o700,
        PurePosixPath("/delegated/wto-exec-" + "c" * 32),
        "wto-exec-" + "c" * 32,
    )
    close_calls = 0
    monkeypatch.setattr(backend, "create", lambda _name: (resource, identity))
    monkeypatch.setattr(backend, "populated", lambda _resource: False)
    monkeypatch.setattr(backend, "remove", lambda _resource, _identity: None)

    def fail_close(_resource: object) -> None:
        nonlocal close_calls
        close_calls += 1
        raise OSError("controlled probe close failure")

    monkeypatch.setattr(backend, "close", fail_close)

    with pytest.raises(OSError, match="probe close failure"):
        backend._probe_execution_leaf()

    assert close_calls == 1


def test_posix_readiness_probe_cleanup_failure_is_visible_and_sticky(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = cgroup_module._PosixCgroupFsBackend()
    resource = object()
    local_name = "wto-exec-" + "d" * 32
    identity = CgroupIdentity(
        1,
        2,
        3,
        4,
        5,
        6,
        1000,
        0o700,
        PurePosixPath(f"/delegated/{local_name}"),
        local_name,
    )
    create_calls = 0
    remove_calls = 0

    def create(_name: str) -> tuple[object, CgroupIdentity]:
        nonlocal create_calls
        create_calls += 1
        return resource, identity

    def fail_remove(_resource: object, _identity: CgroupIdentity) -> None:
        nonlocal remove_calls
        remove_calls += 1
        raise OSError("controlled removal failure")

    monkeypatch.setattr(backend, "create", create)
    monkeypatch.setattr(backend, "populated", lambda _resource: False)
    monkeypatch.setattr(backend, "remove", fail_remove)
    monkeypatch.setattr(backend, "close", lambda _resource: None)
    monkeypatch.setattr(cgroup_module.os, "name", "posix")
    monkeypatch.setattr(cgroup_module.sys, "platform", "linux")

    first = backend.probe()
    second = backend.probe()

    assert first.available is False
    assert first == second
    assert first.detail is not None
    assert "controlled removal failure" in first.detail
    assert local_name in first.detail
    assert "manual cgroup recovery" in first.detail
    assert create_calls == 1
    assert remove_calls == 2


@pytest.mark.parametrize(
    "owner,mode",
    [
        (2000, stat.S_IFREG | 0o600),
        (0, stat.S_IFREG | 0o620),
        (0, stat.S_IFREG | 0o602),
    ],
)
def test_cgroup_control_owner_and_write_permissions_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    owner: int,
    mode: int,
) -> None:
    closed: list[int] = []
    metadata = type(
        "Metadata",
        (),
        {"st_mode": mode, "st_nlink": 1, "st_uid": owner},
    )()
    monkeypatch.setattr(cgroup_module.os, "open", lambda *_args, **_kwargs: 42)
    monkeypatch.setattr(cgroup_module.os, "fstat", lambda _descriptor: metadata)
    monkeypatch.setattr(cgroup_module.os, "close", lambda descriptor: closed.append(descriptor))
    monkeypatch.setattr(cgroup_module, "_GET_EFFECTIVE_UID", lambda: 1000)

    with pytest.raises(CgroupContainmentError, match="unsafe cgroup control"):
        cgroup_module._open_control(17, "cgroup.kill", os.O_WRONLY)

    assert closed == [42]


@pytest.mark.skipif(os.name != "posix", reason="POSIX cgroup creation dir_fd semantics")
def test_posix_leaf_failure_after_mkdir_removes_the_captured_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = os.open(
        tmp_path,
        os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0)),
    )
    metadata = os.fstat(descriptor)
    backend = cgroup_module._PosixCgroupFsBackend()
    parent = cgroup_module._ParentResource(
        os.dup(descriptor),
        metadata,
        metadata,
        PurePosixPath("/delegated"),
    )
    monkeypatch.setattr(backend, "_open_delegated_parent", lambda: parent)
    real_open = cgroup_module._open_directory_at
    calls = 0

    def fail_first_open(parent_descriptor: int, name: str) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("controlled post-mkdir open failure")
        return real_open(parent_descriptor, name)

    monkeypatch.setattr(cgroup_module, "_open_directory_at", fail_first_open)
    try:
        with pytest.raises(OSError, match="post-mkdir"):
            backend.create("wto-exec-" + "b" * 32)
        assert not (tmp_path / ("wto-exec-" + "b" * 32)).exists()
    finally:
        os.close(descriptor)
