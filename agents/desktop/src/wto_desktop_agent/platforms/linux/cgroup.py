from __future__ import annotations

import asyncio
import os
import re
import secrets
import stat
import sys
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Protocol, cast

_CGROUP_ROOT = PurePosixPath("/sys/fs/cgroup")
_PROC_SELF_CGROUP = Path("/proc/self/cgroup")
_PROC_SELF_MOUNTINFO = Path("/proc/self/mountinfo")
_LEAF_PREFIX = "wto-exec-"
_LEAF_PATTERN = re.compile(r"^wto-exec-[0-9a-f]{32}$")
_CONTROL_TOKEN = re.compile(r"^[a-z][a-z0-9_-]*$")
_MAX_CONTROL_BYTES = 4 * 1024 * 1024
_O_CLOEXEC = int(getattr(os, "O_CLOEXEC", 0))
_O_DIRECTORY = int(getattr(os, "O_DIRECTORY", 0))
_O_NOFOLLOW = int(getattr(os, "O_NOFOLLOW", 0))
_GET_EFFECTIVE_UID = cast(Callable[[], int] | None, getattr(os, "geteuid", None))
_PREAD = cast(Callable[[int, int, int], bytes] | None, getattr(os, "pread", None))


class CgroupUnavailableError(RuntimeError):
    """The host cannot provide the required delegated cgroup v2 subtree."""


class CgroupContainmentError(RuntimeError):
    """An execution cgroup failed an identity or containment invariant."""


class CgroupCleanupIncompleteError(RuntimeError):
    """The execution cgroup could not be proven empty and removed."""


@dataclass(frozen=True)
class CgroupReadiness:
    available: bool
    reason: str | None
    delegated_path: PurePosixPath | None = None
    detail: str | None = None


@dataclass(frozen=True)
class CgroupIdentity:
    mount_device: int
    mount_inode: int
    parent_device: int
    parent_inode: int
    device: int
    inode: int
    owner_uid: int
    mode: int
    relative_path: PurePosixPath
    local_name: str


class CgroupExecutionState(str, Enum):
    CREATED = "created"
    MOVED = "moved"
    ATTACHED = "attached"
    KILL_SENT = "kill_sent"
    EMPTY = "empty"
    REMOVED = "removed"
    INCOMPLETE = "incomplete"
    CLOSED = "closed"


class CgroupFsBackend(Protocol):
    """Opaque filesystem boundary used by the state machine and portable tests."""

    def probe(self) -> CgroupReadiness: ...

    def create(self, local_name: str) -> tuple[object, CgroupIdentity]: ...

    def attach(self, resource: object, pid: int) -> None: ...

    def pids(self, resource: object) -> tuple[int, ...]: ...

    def populated(self, resource: object) -> bool: ...

    def kill(self, resource: object) -> None: ...

    def remove(self, resource: object, identity: CgroupIdentity) -> None: ...

    def close(self, resource: object) -> None: ...


@dataclass
class CgroupExecutionHandle:
    identity: CgroupIdentity
    _backend: CgroupFsBackend = field(repr=False)
    _resource: object = field(repr=False)
    _manager: CgroupV2Manager = field(repr=False)
    _state: CgroupExecutionState = field(default=CgroupExecutionState.CREATED, repr=False)
    _attached_pid: int | None = field(default=None, repr=False)
    _kill_sent: bool = field(default=False, repr=False)
    _removed: bool = field(default=False, repr=False)
    _closed: bool = field(default=False, repr=False)
    _incomplete_error: BaseException | None = field(default=None, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    @property
    def state(self) -> CgroupExecutionState:
        return self._state

    @property
    def attached_pid(self) -> int | None:
        return self._attached_pid

    @property
    def kill_sent(self) -> bool:
        return self._kill_sent

    @property
    def removed(self) -> bool:
        return self._removed

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def incomplete_error(self) -> BaseException | None:
        return self._incomplete_error

    @property
    def path(self) -> PurePosixPath:
        return self.identity.relative_path

    def attach_pid(self, pid: int) -> None:
        self._manager.attach_pid(self, pid)

    def verify_pid(self, pid: int) -> None:
        self._manager.verify_pid(self, pid)

    def attach_verify(self, pid: int) -> None:
        self._manager.attach_verify(self, pid)

    def kill_remaining(self) -> None:
        self._manager.kill_remaining(self)

    def is_populated(self) -> bool:
        return self._manager.is_populated(self)

    async def wait_empty(self, deadline_monotonic: float) -> None:
        await self._manager.wait_empty(self, deadline_monotonic)

    def remove_empty(self) -> None:
        self._manager.remove_empty(self)

    def close(self, primary_error: BaseException | None = None) -> None:
        self._manager.close(self, primary_error=primary_error)


class CgroupV2Manager:
    """Create and clean private execution cgroups in a delegated v2 subtree.

    The default backend only accepts the kernel-reported cgroup for this process
    beneath the fixed ``/sys/fs/cgroup`` unified mount.  Tests inject a fake
    backend; neither paths nor cgroup names are accepted from task input.
    """

    def __init__(
        self,
        backend: CgroupFsBackend | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        poll_interval_seconds: float = 0.01,
        nonce_factory: Callable[[int], str] = secrets.token_hex,
    ) -> None:
        if poll_interval_seconds <= 0:
            raise ValueError("cgroup poll interval must be positive")
        self._backend = backend or _PosixCgroupFsBackend()
        self._clock = clock
        self._sleep = sleep
        self._poll_interval_seconds = poll_interval_seconds
        self._nonce_factory = nonce_factory

    def probe(self) -> CgroupReadiness:
        return self._backend.probe()

    @property
    def readiness(self) -> CgroupReadiness:
        return self.probe()

    def create_execution(self) -> CgroupExecutionHandle:
        readiness = self.probe()
        if not readiness.available:
            raise CgroupUnavailableError(
                f"Linux cgroup v2 containment is unavailable: {readiness.reason or 'unknown'}"
            )
        last_collision: FileExistsError | None = None
        for _ in range(16):
            local_name = f"{_LEAF_PREFIX}{self._nonce_factory(16)}"
            if _LEAF_PATTERN.fullmatch(local_name) is None:
                raise CgroupContainmentError("local cgroup nonce factory returned an invalid name")
            try:
                resource, identity = self._backend.create(local_name)
            except FileExistsError as error:
                last_collision = error
                continue
            if identity.local_name != local_name or identity.relative_path.name != local_name:
                primary = CgroupContainmentError("cgroup backend returned the wrong local identity")
                try:
                    self._backend.close(resource)
                except BaseException as close_error:
                    primary.add_note(f"cgroup resource close also failed: {close_error!r}")
                raise primary
            return CgroupExecutionHandle(
                identity=identity,
                _backend=self._backend,
                _resource=resource,
                _manager=self,
            )
        raise CgroupContainmentError("could not allocate a collision-free execution cgroup") from (
            last_collision
        )

    def attach_pid(self, handle: CgroupExecutionHandle, pid: int) -> None:
        self._validate_handle(handle)
        if isinstance(pid, bool) or pid <= 0:
            raise ValueError("cgroup target PID must be a positive integer")
        with handle._lock:
            self._require_open(handle)
            if handle._attached_pid is not None:
                if handle._attached_pid == pid and handle._state in {
                    CgroupExecutionState.MOVED,
                    CgroupExecutionState.ATTACHED,
                }:
                    return
                raise CgroupContainmentError("execution cgroup already has an attachment attempt")
            handle._attached_pid = pid
            try:
                self._backend.attach(handle._resource, pid)
            except BaseException as error:
                self._mark_incomplete(handle, error)
                raise
            handle._state = CgroupExecutionState.MOVED

    def verify_pid(self, handle: CgroupExecutionHandle, pid: int) -> None:
        self._validate_handle(handle)
        if isinstance(pid, bool) or pid <= 0:
            raise ValueError("cgroup target PID must be a positive integer")
        with handle._lock:
            self._require_open(handle)
            if handle._attached_pid != pid:
                raise CgroupContainmentError("PID verification does not match the moved guard")
            if handle._state is CgroupExecutionState.ATTACHED:
                return
            try:
                members = self._backend.pids(handle._resource)
                if pid not in members:
                    raise CgroupContainmentError(
                        "blocked spawn guard membership was not verified in cgroup.procs"
                    )
            except BaseException as error:
                self._mark_incomplete(handle, error)
                raise
            handle._state = CgroupExecutionState.ATTACHED

    def attach_verify(self, handle: CgroupExecutionHandle, pid: int) -> None:
        self.attach_pid(handle, pid)
        self.verify_pid(handle, pid)

    def pids(self, handle: CgroupExecutionHandle) -> tuple[int, ...]:
        self._validate_handle(handle)
        with handle._lock:
            if handle._removed or handle._closed:
                return ()
            try:
                return self._backend.pids(handle._resource)
            except BaseException as error:
                self._mark_incomplete(handle, error)
                raise

    def populated(self, handle: CgroupExecutionHandle) -> bool:
        self._validate_handle(handle)
        with handle._lock:
            if handle._removed or handle._closed:
                return False
            try:
                populated = self._backend.populated(handle._resource)
            except BaseException as error:
                self._mark_incomplete(handle, error)
                raise
            if not populated:
                handle._state = CgroupExecutionState.EMPTY
            return populated

    def is_populated(self, handle: CgroupExecutionHandle) -> bool:
        return self.populated(handle)

    def kill_remaining(self, handle: CgroupExecutionHandle) -> None:
        self._validate_handle(handle)
        with handle._lock:
            if handle._removed or handle._closed or handle._kill_sent:
                return
            try:
                self._backend.kill(handle._resource)
            except BaseException as error:
                self._mark_incomplete(handle, error)
                raise
            handle._kill_sent = True
            handle._state = CgroupExecutionState.KILL_SENT

    async def wait_empty(
        self,
        handle: CgroupExecutionHandle,
        deadline_monotonic: float,
    ) -> None:
        self._validate_handle(handle)
        while True:
            try:
                if not self.populated(handle):
                    return
                remaining = deadline_monotonic - self._clock()
                if remaining <= 0:
                    raise TimeoutError(
                        f"execution cgroup remained populated: {handle.identity.relative_path}"
                    )
                await self._sleep(min(self._poll_interval_seconds, remaining))
            except BaseException as error:
                with handle._lock:
                    self._mark_incomplete(handle, error)
                raise

    def remove_empty(self, handle: CgroupExecutionHandle) -> None:
        self._validate_handle(handle)
        with handle._lock:
            if handle._removed:
                return
            self._require_open(handle)
            try:
                if self._backend.populated(handle._resource):
                    raise CgroupCleanupIncompleteError("execution cgroup is still populated")
                if self._backend.pids(handle._resource):
                    raise CgroupCleanupIncompleteError("execution cgroup still lists processes")
                self._backend.remove(handle._resource, handle.identity)
            except BaseException as error:
                self._mark_incomplete(handle, error)
                raise
            handle._removed = True
            handle._state = CgroupExecutionState.REMOVED

    def close(
        self,
        handle: CgroupExecutionHandle,
        *,
        primary_error: BaseException | None = None,
    ) -> None:
        self._validate_handle(handle)
        close_error: BaseException | None = None
        with handle._lock:
            if handle._closed:
                return
            try:
                self._backend.close(handle._resource)
            except BaseException as error:
                close_error = error
            finally:
                handle._closed = True
                handle._state = CgroupExecutionState.CLOSED
        if close_error is None:
            return
        if primary_error is not None:
            primary_error.add_note(f"cgroup descriptor close also failed: {close_error!r}")
            return
        raise close_error

    def _validate_handle(self, handle: CgroupExecutionHandle) -> None:
        if handle._manager is not self or handle._backend is not self._backend:
            raise CgroupContainmentError("execution cgroup belongs to another manager")

    @staticmethod
    def _require_open(handle: CgroupExecutionHandle) -> None:
        if handle._closed:
            raise CgroupContainmentError("execution cgroup handle is closed")
        if handle._removed:
            raise CgroupContainmentError("execution cgroup was already removed")

    @staticmethod
    def _mark_incomplete(handle: CgroupExecutionHandle, error: BaseException) -> None:
        if handle._incomplete_error is None:
            handle._incomplete_error = error
        if not handle._removed and not handle._closed:
            handle._state = CgroupExecutionState.INCOMPLETE


@dataclass
class _ParentResource:
    descriptor: int
    mount_stat: os.stat_result
    parent_stat: os.stat_result
    delegated_path: PurePosixPath


@dataclass
class _PosixLeafResource:
    parent_descriptor: int
    directory_descriptor: int
    procs_read_descriptor: int
    procs_write_descriptor: int
    events_descriptor: int
    kill_descriptor: int
    local_name: str
    identity_stat: os.stat_result
    closed: bool = False


class _PosixCgroupFsBackend:
    def __init__(self) -> None:
        self._probe_lock = threading.RLock()
        self._sticky_probe_failure: CgroupReadiness | None = None

    def probe(self) -> CgroupReadiness:
        if os.name != "posix" or not sys.platform.startswith("linux"):
            return CgroupReadiness(False, "platform_unsupported")
        with self._probe_lock:
            if self._sticky_probe_failure is not None:
                return self._sticky_probe_failure
            try:
                delegated_path = self._probe_execution_leaf()
                return CgroupReadiness(True, None, delegated_path)
            except CgroupUnavailableError as error:
                return CgroupReadiness(
                    False,
                    _readiness_reason(error),
                    detail=_readiness_detail(error),
                )
            except (CgroupContainmentError, OSError, ValueError) as error:
                if self._sticky_probe_failure is not None:
                    return self._sticky_probe_failure
                return CgroupReadiness(
                    False,
                    _readiness_reason(error),
                    detail=_readiness_detail(error),
                )

    def _probe_execution_leaf(self) -> PurePosixPath:
        resource: object | None = None
        identity: CgroupIdentity | None = None
        removed = False
        close_attempted = False
        last_collision: FileExistsError | None = None
        try:
            for _ in range(16):
                try:
                    resource, identity = self.create(f"{_LEAF_PREFIX}{secrets.token_hex(16)}")
                    break
                except FileExistsError as error:
                    last_collision = error
            if resource is None or identity is None:
                raise CgroupContainmentError(
                    "cgroup readiness probe name allocation failed"
                ) from last_collision
            if self.populated(resource):
                raise CgroupContainmentError(
                    "new cgroup readiness probe was unexpectedly populated"
                )
            self.remove(resource, identity)
            removed = True
            close_attempted = True
            self.close(resource)
            resource = None
            return identity.relative_path.parent
        except BaseException as primary:
            if resource is not None and identity is not None and not removed:
                try:
                    if not self.populated(resource):
                        self.remove(resource, identity)
                        removed = True
                except BaseException as cleanup_error:
                    primary.add_note(
                        f"cgroup readiness probe removal also failed: {cleanup_error!r}"
                    )
                if not removed:
                    primary.add_note(
                        "manual cgroup recovery is required for locally generated "
                        f"{identity.local_name}"
                    )
                    with self._probe_lock:
                        self._sticky_probe_failure = CgroupReadiness(
                            False,
                            _readiness_reason(primary),
                            detail=_readiness_detail(primary),
                        )
            if resource is not None and not close_attempted:
                try:
                    close_attempted = True
                    self.close(resource)
                except BaseException as close_error:
                    primary.add_note(f"cgroup readiness probe close also failed: {close_error!r}")
            raise

    def create(self, local_name: str) -> tuple[object, CgroupIdentity]:
        if _LEAF_PATTERN.fullmatch(local_name) is None:
            raise CgroupContainmentError("execution cgroup name is invalid")
        parent = self._open_delegated_parent()
        created = False
        leaf_descriptor = -1
        leaf_stat: os.stat_result | None = None
        opened: list[int] = []
        try:
            os.mkdir(local_name, mode=0o700, dir_fd=parent.descriptor)
            created = True
            leaf_stat = os.stat(
                local_name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
            _validate_delegated_directory(leaf_stat, expected_uid=_effective_uid())
            leaf_descriptor = _open_directory_at(parent.descriptor, local_name)
            opened_leaf_stat = os.fstat(leaf_descriptor)
            if (int(opened_leaf_stat.st_dev), int(opened_leaf_stat.st_ino)) != (
                int(leaf_stat.st_dev),
                int(leaf_stat.st_ino),
            ):
                raise CgroupContainmentError("execution cgroup identity changed during creation")
            _validate_leaf_controls(leaf_descriptor)
            procs_read = _open_control(leaf_descriptor, "cgroup.procs", os.O_RDONLY)
            opened.append(procs_read)
            procs_write = _open_control(leaf_descriptor, "cgroup.procs", os.O_WRONLY)
            opened.append(procs_write)
            events = _open_control(leaf_descriptor, "cgroup.events", os.O_RDONLY)
            opened.append(events)
            _parse_events(_read_fd(events, 4096))
            kill = _open_control(leaf_descriptor, "cgroup.kill", os.O_WRONLY)
            opened.append(kill)
            path = parent.delegated_path / local_name
            identity = CgroupIdentity(
                mount_device=int(parent.mount_stat.st_dev),
                mount_inode=int(parent.mount_stat.st_ino),
                parent_device=int(parent.parent_stat.st_dev),
                parent_inode=int(parent.parent_stat.st_ino),
                device=int(leaf_stat.st_dev),
                inode=int(leaf_stat.st_ino),
                owner_uid=int(leaf_stat.st_uid),
                mode=stat.S_IMODE(leaf_stat.st_mode),
                relative_path=path,
                local_name=local_name,
            )
            resource = _PosixLeafResource(
                parent_descriptor=parent.descriptor,
                directory_descriptor=leaf_descriptor,
                procs_read_descriptor=procs_read,
                procs_write_descriptor=procs_write,
                events_descriptor=events,
                kill_descriptor=kill,
                local_name=local_name,
                identity_stat=leaf_stat,
            )
            return resource, identity
        except BaseException as primary:
            for descriptor in reversed(opened):
                _close_with_note(descriptor, primary, "cgroup control descriptor")
            if leaf_descriptor >= 0:
                _close_with_note(leaf_descriptor, primary, "cgroup directory descriptor")
            if created and leaf_stat is not None:
                try:
                    self._remove_created_leaf(parent.descriptor, local_name, leaf_stat)
                except BaseException as cleanup_error:
                    primary.add_note(f"partial cgroup removal also failed: {cleanup_error!r}")
            elif created:
                primary.add_note(
                    f"manual cgroup recovery may be required for locally generated {local_name}"
                )
            _close_with_note(parent.descriptor, primary, "delegated cgroup descriptor")
            raise

    def attach(self, resource: object, pid: int) -> None:
        leaf = _leaf(resource)
        _write_all(leaf.procs_write_descriptor, f"{pid}\n".encode("ascii"))

    def pids(self, resource: object) -> tuple[int, ...]:
        leaf = _leaf(resource)
        return _parse_pids(_read_fd(leaf.procs_read_descriptor, _MAX_CONTROL_BYTES))

    def populated(self, resource: object) -> bool:
        leaf = _leaf(resource)
        return _parse_events(_read_fd(leaf.events_descriptor, 4096))["populated"] == 1

    def kill(self, resource: object) -> None:
        leaf = _leaf(resource)
        _write_all(leaf.kill_descriptor, b"1\n")

    def remove(self, resource: object, identity: CgroupIdentity) -> None:
        leaf = _leaf(resource)
        current = _open_directory_at(leaf.parent_descriptor, leaf.local_name)
        try:
            metadata = os.fstat(current)
            if (int(metadata.st_dev), int(metadata.st_ino)) != (
                identity.device,
                identity.inode,
            ):
                raise CgroupContainmentError("execution cgroup identity changed before removal")
        finally:
            os.close(current)
        os.rmdir(leaf.local_name, dir_fd=leaf.parent_descriptor)

    def close(self, resource: object) -> None:
        leaf = _leaf(resource)
        if leaf.closed:
            return
        leaf.closed = True
        errors: list[BaseException] = []
        for name in (
            "kill_descriptor",
            "events_descriptor",
            "procs_write_descriptor",
            "procs_read_descriptor",
            "directory_descriptor",
            "parent_descriptor",
        ):
            descriptor = int(getattr(leaf, name))
            setattr(leaf, name, -1)
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except OSError as error:
                errors.append(error)
        if errors:
            for secondary in errors[1:]:
                errors[0].add_note(f"additional cgroup descriptor close error: {secondary!r}")
            raise errors[0]

    @staticmethod
    def _remove_created_leaf(
        parent_descriptor: int,
        local_name: str,
        expected: os.stat_result,
    ) -> None:
        current = _open_directory_at(parent_descriptor, local_name)
        try:
            metadata = os.fstat(current)
            if (int(metadata.st_dev), int(metadata.st_ino)) != (
                int(expected.st_dev),
                int(expected.st_ino),
            ):
                raise CgroupContainmentError("partial execution cgroup identity changed")
        finally:
            os.close(current)
        os.rmdir(local_name, dir_fd=parent_descriptor)

    def _open_delegated_parent(self) -> _ParentResource:
        _require_posix_primitives()
        components = _read_unified_cgroup_components()
        _validate_cgroup2_mount()
        descriptor = os.open("/", os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC)
        try:
            _validate_trusted_ancestor(os.fstat(descriptor))
            for component in ("sys", "fs", "cgroup"):
                child = _open_directory_at(descriptor, component)
                try:
                    _validate_trusted_ancestor(os.fstat(child))
                except BaseException:
                    os.close(child)
                    raise
                os.close(descriptor)
                descriptor = child
            mount_stat = os.fstat(descriptor)
            for component in components:
                child = _open_directory_at(descriptor, component)
                try:
                    _validate_cgroup_ancestor(os.fstat(child), _effective_uid())
                except BaseException:
                    os.close(child)
                    raise
                os.close(descriptor)
                descriptor = child
            parent_stat = os.fstat(descriptor)
            _validate_delegated_directory(parent_stat, expected_uid=_effective_uid())
            _validate_parent_controls(descriptor)
            delegated_path = _CGROUP_ROOT.joinpath(*components)
            return _ParentResource(descriptor, mount_stat, parent_stat, delegated_path)
        except BaseException:
            os.close(descriptor)
            raise


def _require_posix_primitives() -> None:
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise CgroupUnavailableError("cgroup v2 containment requires Linux")
    if _O_DIRECTORY == 0 or _O_NOFOLLOW == 0 or _O_CLOEXEC == 0:
        raise CgroupUnavailableError("secure dir_fd cgroup primitives are unavailable")
    if not all(function in os.supports_dir_fd for function in (os.open, os.mkdir, os.rmdir)):
        raise CgroupUnavailableError("required cgroup dir_fd operations are unavailable")
    if _GET_EFFECTIVE_UID is None:
        raise CgroupUnavailableError("effective UID inspection is unavailable")
    if _PREAD is None:
        raise CgroupUnavailableError("pread is required for stable cgroup control reads")


def _effective_uid() -> int:
    if _GET_EFFECTIVE_UID is None:
        raise CgroupUnavailableError("effective UID inspection is unavailable")
    return _GET_EFFECTIVE_UID()


def _read_unified_cgroup_components() -> tuple[str, ...]:
    try:
        lines = _PROC_SELF_CGROUP.read_text(encoding="ascii").splitlines()
    except OSError as error:
        raise CgroupUnavailableError("cannot read the process cgroup membership") from error
    parsed: list[tuple[str, str, str]] = []
    for line in lines:
        fields = line.split(":", 2)
        if len(fields) != 3:
            raise CgroupUnavailableError("process cgroup membership is malformed")
        parsed.append(cast(tuple[str, str, str], tuple(fields)))
    unified = [
        path for hierarchy, controllers, path in parsed if hierarchy == "0" and not controllers
    ]
    if len(parsed) != 1 or len(unified) != 1:
        raise CgroupUnavailableError("a unified cgroup v2 hierarchy is required")
    path = unified[0]
    if not path.startswith("/") or path == "/" or path.endswith(" (deleted)"):
        raise CgroupUnavailableError("the process is not in a delegated cgroup subtree")
    components = tuple(path[1:].split("/"))
    for component in components:
        if (
            not component
            or component in {".", ".."}
            or "\0" in component
            or len(os.fsencode(component)) > 255
        ):
            raise CgroupUnavailableError("process cgroup path contains an invalid component")
    return components


def _validate_cgroup2_mount() -> None:
    try:
        lines = _PROC_SELF_MOUNTINFO.read_text(encoding="ascii").splitlines()
    except OSError as error:
        raise CgroupUnavailableError("cannot inspect the cgroup mount") from error
    matches = 0
    for line in lines:
        if " - " not in line:
            continue
        before, after = line.split(" - ", 1)
        left = before.split()
        right = after.split()
        if len(left) < 6 or len(right) < 3:
            continue
        mountpoint = _decode_mount_field(left[4])
        if mountpoint != str(_CGROUP_ROOT):
            continue
        if right[0] != "cgroup2" or "rw" not in left[5].split(","):
            raise CgroupUnavailableError("the fixed cgroup root is not a writable v2 mount")
        matches += 1
    if matches != 1:
        raise CgroupUnavailableError("the fixed cgroup v2 mount was not found uniquely")


def _decode_mount_field(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def _open_directory_at(parent_descriptor: int, name: str) -> int:
    if not name or "/" in name or name in {".", ".."}:
        raise CgroupContainmentError("invalid cgroup path component")
    return os.open(
        name,
        os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
        dir_fd=parent_descriptor,
    )


def _open_control(directory_descriptor: int, name: str, access: int) -> int:
    descriptor = os.open(
        name,
        access | _O_NOFOLLOW | _O_CLOEXEC,
        dir_fd=directory_descriptor,
    )
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or int(metadata.st_nlink) != 1
            or int(metadata.st_uid) not in {0, _effective_uid()}
            or mode & 0o022
            or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
        ):
            raise CgroupContainmentError(f"unsafe cgroup control file: {name}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _validate_trusted_ancestor(metadata: os.stat_result) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISDIR(metadata.st_mode) or int(metadata.st_uid) != 0 or mode & 0o022:
        raise CgroupUnavailableError("cgroup root ancestor is not trusted")


def _validate_cgroup_ancestor(metadata: os.stat_result, effective_uid: int) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or int(metadata.st_uid) not in {0, effective_uid}
        or mode & 0o022
    ):
        raise CgroupUnavailableError("cgroup subtree ancestor is not trusted")


def _validate_delegated_directory(metadata: os.stat_result, *, expected_uid: int) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or int(metadata.st_uid) != expected_uid
        or mode & 0o022
        or mode & 0o300 != 0o300
    ):
        raise CgroupUnavailableError("cgroup subtree is not privately delegated")


def _validate_parent_controls(directory_descriptor: int) -> None:
    controllers = _read_control(directory_descriptor, "cgroup.controllers", 4096)
    available = _parse_controller_set(controllers)
    subtree = _read_control(directory_descriptor, "cgroup.subtree_control", 4096)
    enabled = _parse_controller_set(subtree)
    if not enabled.issubset(available):
        raise CgroupUnavailableError("cgroup subtree control is inconsistent")
    _open_and_close_writable(directory_descriptor, "cgroup.subtree_control")
    procs = _read_control(directory_descriptor, "cgroup.procs", _MAX_CONTROL_BYTES)
    _parse_pids(procs)
    _open_and_close_writable(directory_descriptor, "cgroup.procs")
    events = _read_control(directory_descriptor, "cgroup.events", 4096)
    _parse_events(events)
    group_type = (
        _read_control(directory_descriptor, "cgroup.type", 128)
        .decode("ascii", errors="strict")
        .strip()
    )
    if group_type != "domain":
        raise CgroupUnavailableError("delegated cgroup must be a domain cgroup")


def _validate_leaf_controls(directory_descriptor: int) -> None:
    controllers = _parse_controller_set(
        _read_control(directory_descriptor, "cgroup.controllers", 4096)
    )
    subtree = _parse_controller_set(
        _read_control(directory_descriptor, "cgroup.subtree_control", 4096)
    )
    if not subtree.issubset(controllers):
        raise CgroupContainmentError("execution cgroup controller state is inconsistent")
    group_type = (
        _read_control(directory_descriptor, "cgroup.type", 128)
        .decode("ascii", errors="strict")
        .strip()
    )
    if group_type != "domain":
        raise CgroupContainmentError("execution cgroup is not a domain cgroup")


def _read_control(directory_descriptor: int, name: str, limit: int) -> bytes:
    descriptor = _open_control(directory_descriptor, name, os.O_RDONLY)
    try:
        return _read_fd(descriptor, limit)
    finally:
        os.close(descriptor)


def _open_and_close_writable(directory_descriptor: int, name: str) -> None:
    descriptor = _open_control(directory_descriptor, name, os.O_WRONLY)
    os.close(descriptor)


def _read_fd(descriptor: int, limit: int) -> bytes:
    pread = _PREAD
    if pread is None:
        raise CgroupUnavailableError("pread is unavailable")
    result = bytearray()
    offset = 0
    while True:
        remaining = limit + 1 - len(result)
        if remaining <= 0:
            raise CgroupContainmentError("cgroup control file exceeded its read limit")
        chunk = pread(descriptor, min(65_536, remaining), offset)
        if not chunk:
            break
        result.extend(chunk)
        offset += len(chunk)
    if len(result) > limit:
        raise CgroupContainmentError("cgroup control file exceeded its read limit")
    return bytes(result)


def _write_all(descriptor: int, payload: bytes) -> None:
    if not payload:
        raise ValueError("cgroup control write cannot be empty")
    written = os.write(descriptor, payload)
    if written != len(payload):
        raise CgroupContainmentError("cgroup control write was incomplete")


def _parse_controller_set(payload: bytes) -> frozenset[str]:
    try:
        values = payload.decode("ascii", errors="strict").split()
    except UnicodeDecodeError as error:
        raise CgroupContainmentError("cgroup controller list is not ASCII") from error
    if any(_CONTROL_TOKEN.fullmatch(value) is None for value in values):
        raise CgroupContainmentError("cgroup controller list is malformed")
    return frozenset(values)


def _parse_pids(payload: bytes) -> tuple[int, ...]:
    try:
        lines = payload.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise CgroupContainmentError("cgroup.procs is not ASCII") from error
    result: list[int] = []
    for line in lines:
        if not line or not line.isdigit() or int(line) <= 0:
            raise CgroupContainmentError("cgroup.procs is malformed")
        result.append(int(line))
    return tuple(result)


def _parse_events(payload: bytes) -> dict[str, int]:
    try:
        lines = payload.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise CgroupContainmentError("cgroup.events is not ASCII") from error
    result: dict[str, int] = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or fields[0] in result or not fields[1].isdigit():
            raise CgroupContainmentError("cgroup.events is malformed")
        result[fields[0]] = int(fields[1])
    if result.get("populated") not in {0, 1}:
        raise CgroupContainmentError("cgroup.events has no valid populated state")
    return result


def _leaf(resource: object) -> _PosixLeafResource:
    if not isinstance(resource, _PosixLeafResource) or resource.closed:
        raise CgroupContainmentError("cgroup backend resource is unavailable")
    return resource


def _close_with_note(descriptor: int, primary: BaseException, description: str) -> None:
    try:
        os.close(descriptor)
    except OSError as error:
        primary.add_note(f"{description} close also failed: {error!r}")


def _readiness_reason(error: BaseException) -> str:
    if isinstance(error, PermissionError):
        return "cgroup_subtree_not_delegated"
    if isinstance(error, FileNotFoundError):
        return "cgroup_v2_control_missing"
    text = str(error)
    if "delegated" in text:
        return "cgroup_subtree_not_delegated"
    if "unified" in text or "v2" in text or "mount" in text:
        return "cgroup_v2_unavailable"
    return "cgroup_validation_failed"


def _readiness_detail(error: BaseException) -> str:
    fragments = [str(error).strip() or type(error).__name__]
    fragments.extend(str(note).strip() for note in getattr(error, "__notes__", ()))
    normalized = " | ".join(" ".join(fragment.split()) for fragment in fragments if fragment)
    return normalized[:512]
