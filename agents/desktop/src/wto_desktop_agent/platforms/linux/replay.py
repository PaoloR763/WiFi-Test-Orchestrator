from __future__ import annotations

import asyncio
import hashlib
import os
import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from wto_desktop_agent.platforms.linux.capture import (
    PCAP_REPLAY_CAPABILITY,
    ControlPlaneAuthorization,
    PrivilegedAuthorizationDecision,
    privileged_capability_decision,
)
from wto_desktop_agent.platforms.linux.parsers import validate_interface_name
from wto_desktop_agent.platforms.linux.secure_fs import close_descriptor
from wto_desktop_agent.ports.plugins import CancellationToken

_HASH_CHUNK_SIZE = 1_048_576
_HASH_TIMEOUT_SECONDS = 300.0
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_O_DIRECTORY = int(getattr(os, "O_DIRECTORY", 0))
_O_NOFOLLOW = int(getattr(os, "O_NOFOLLOW", 0))
_O_CLOEXEC = int(getattr(os, "O_CLOEXEC", 0))


class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    interface: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")
    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9._-]{2,63}$")
    artifact_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.pcap(?:ng)?$")
    namespace: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    duration_seconds: int = Field(ge=1, le=600)
    rate_mbps: int = Field(ge=1, le=10_000)
    loops: int = Field(ge=1, le=100)


class ReplaySimulation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["validated", "cancelled"]
    interface: str
    scenario_id: str
    artifact_sha256: str
    effective_duration_seconds: int
    effective_rate_mbps: int
    effective_loops: int
    namespace: str
    cleanup_complete: bool


class _ArtifactHashCancelled(Exception):
    pass


def _directory_flags() -> int:
    if _O_DIRECTORY == 0 or _O_NOFOLLOW == 0 or _O_CLOEXEC == 0:
        raise RuntimeError("secure Linux replay directory primitives are unavailable")
    return os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC


def _file_flags() -> int:
    if _O_NOFOLLOW == 0 or _O_CLOEXEC == 0:
        raise RuntimeError("secure Linux replay file primitives are unavailable")
    return os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC


def _effective_uid() -> int:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        raise RuntimeError("Linux ownership APIs are unavailable")
    return int(geteuid())


def _name_descriptor_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_uid),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_uid),
        int(metadata.st_mode),
        int(metadata.st_nlink),
    )


def _validate_artifact_root(metadata: os.stat_result) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise PermissionError("replay artifact root is not a directory")
    if int(metadata.st_uid) != _effective_uid():
        raise PermissionError("replay artifact root owner does not match the service account")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise PermissionError("replay artifact root mode must be 0700")


def _validate_artifact_file(metadata: os.stat_result, *, max_size_bytes: int) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise PermissionError("replay artifact is not a regular file")
    if int(metadata.st_uid) != _effective_uid():
        raise PermissionError("replay artifact owner does not match the service account")
    if stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}:
        raise PermissionError("replay artifact mode must be 0400 or 0600")
    if int(metadata.st_nlink) != 1:
        raise PermissionError("replay artifact must have exactly one link")
    if int(metadata.st_size) < 0 or int(metadata.st_size) > max_size_bytes:
        raise PermissionError("replay artifact exceeds size policy")


def _close_descriptors(
    descriptors: list[int],
    *,
    primary_error: BaseException | None,
) -> None:
    close_error: BaseException | None = None
    for descriptor in reversed(descriptors):
        try:
            close_descriptor(
                descriptor,
                primary_error=primary_error or close_error,
                context="replay artifact root",
            )
        except BaseException as error:
            if close_error is None:
                close_error = error
            else:
                close_error.add_note(f"another replay root close also failed: {error!r}")
    if primary_error is None and close_error is not None:
        raise close_error


def _open_artifact_root(path: Path) -> tuple[list[int], tuple[int, ...]]:
    if os.name != "posix" or not path.is_absolute() or path.anchor != "/":
        raise RuntimeError("replay artifact root requires an absolute POSIX path")
    components = path.parts[1:]
    if not components:
        raise PermissionError("filesystem root cannot be the replay artifact root")
    if any(component in {"", ".", ".."} or "\x00" in component for component in components):
        raise PermissionError("replay artifact root contains an unsafe component")

    flags = _directory_flags()
    descriptors: list[int] = []
    primary_error: BaseException | None = None
    try:
        parent = os.open("/", flags)
        descriptors.append(parent)
        for component in components:
            named = os.stat(component, dir_fd=parent, follow_symlinks=False)
            descriptor = os.open(component, flags, dir_fd=parent)
            descriptors.append(descriptor)
            observed = os.fstat(descriptor)
            if not stat.S_ISDIR(observed.st_mode) or _directory_identity(
                named
            ) != _directory_identity(observed):
                raise PermissionError("replay artifact root component identity changed")
            parent = descriptor
        metadata = os.fstat(descriptors[-1])
        _validate_artifact_root(metadata)
        return descriptors, _directory_identity(metadata)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if primary_error is not None:
            _close_descriptors(descriptors, primary_error=primary_error)


def _revalidate_artifact_root(path: Path, descriptors: list[int]) -> None:
    for component, parent, descriptor in zip(
        path.parts[1:], descriptors[:-1], descriptors[1:], strict=True
    ):
        named = os.stat(component, dir_fd=parent, follow_symlinks=False)
        observed = os.fstat(descriptor)
        if _directory_identity(named) != _directory_identity(observed):
            raise PermissionError("replay artifact root identity changed during hashing")


async def _hash_descriptor(
    descriptor: int,
    size_bytes: int,
    cancellation: CancellationToken,
    *,
    deadline: float,
) -> str:
    loop = asyncio.get_running_loop()
    digest = hashlib.sha256()
    remaining = size_bytes
    while remaining:
        if cancellation.cancelled:
            raise _ArtifactHashCancelled
        if loop.time() >= deadline:
            raise TimeoutError("replay artifact hashing deadline exceeded")
        requested = min(_HASH_CHUNK_SIZE, remaining)
        chunk = os.read(descriptor, requested)
        if loop.time() >= deadline:
            raise TimeoutError("replay artifact hashing deadline exceeded")
        if not chunk:
            raise PermissionError("replay artifact was truncated during hashing")
        if len(chunk) > requested:
            raise PermissionError("replay artifact read exceeded the requested chunk")
        digest.update(chunk)
        remaining -= len(chunk)
        await asyncio.sleep(0)

    if cancellation.cancelled:
        raise _ArtifactHashCancelled
    if loop.time() >= deadline:
        raise TimeoutError("replay artifact hashing deadline exceeded")
    if os.read(descriptor, 1):
        raise PermissionError("replay artifact grew during hashing")
    if loop.time() >= deadline:
        raise TimeoutError("replay artifact hashing deadline exceeded")
    return digest.hexdigest()


class TcpreplayValidator:
    """Deny-by-default validation and simulation; it never invokes tcpreplay."""

    def __init__(
        self,
        *,
        role: str,
        policy_enabled: bool,
        agent_id_provider: Callable[[], str | None],
        authorization: ControlPlaneAuthorization,
        tool_ready: bool,
        tree_containment_ready: bool | Callable[[], bool] = False,
        artifact_root: Path | None,
        approved_artifacts: dict[str, str],
        allowed_interfaces: frozenset[str],
        allowed_scenarios: frozenset[str],
        namespace: str | None,
        namespace_root: Path = Path("/var/run/netns"),
        max_duration_seconds: int,
        max_rate_mbps: int,
        max_loops: int,
        max_size_bytes: int,
    ) -> None:
        self.role = role
        self.policy_enabled = policy_enabled
        self.agent_id_provider = agent_id_provider
        self.authorization = authorization
        self.tool_ready = tool_ready
        self._tree_containment_readiness = (
            tree_containment_ready
            if callable(tree_containment_ready)
            else lambda: tree_containment_ready
        )
        self.artifact_root = (
            Path(os.path.abspath(artifact_root)) if artifact_root is not None else None
        )
        self.approved_artifacts = dict(approved_artifacts)
        self.allowed_interfaces = allowed_interfaces
        self.allowed_scenarios = allowed_scenarios
        self.namespace = namespace
        self.namespace_root = namespace_root
        self.max_duration_seconds = max_duration_seconds
        self.max_rate_mbps = max_rate_mbps
        self.max_loops = max_loops
        self.max_size_bytes = max_size_bytes
        self.cleanup_calls = 0

    @property
    def tree_containment_ready(self) -> bool:
        return bool(self._tree_containment_readiness())

    def _validate_request_authority(self, request: ReplayRequest) -> str:
        grant = self.authorization.authorize(
            agent_id=self.agent_id_provider(),
            capability_id=PCAP_REPLAY_CAPABILITY,
        )
        if not grant.allowed:
            raise PermissionError(grant.reason or "pcap replay authorization denied")
        if self.role not in {"capture_node", "lab_node"} or not self.policy_enabled:
            raise PermissionError("pcap replay authorization denied")
        artifact_root = self.artifact_root
        namespace = self.namespace
        if artifact_root is None or namespace is None:
            raise PermissionError("replay isolation policy is incomplete")
        if request.interface not in self.allowed_interfaces:
            raise PermissionError("replay interface is not allowlisted")
        validate_interface_name(request.interface)
        if request.scenario_id not in self.allowed_scenarios:
            raise PermissionError("replay destination scenario is not allowlisted")
        if request.namespace != namespace:
            raise PermissionError("replay namespace is not allowlisted")
        namespace_path = self.namespace_root / request.namespace
        if not namespace_path.is_file() or namespace_path.is_symlink():
            raise RuntimeError("isolated network namespace is unavailable")
        expected = self.approved_artifacts.get(request.artifact_name)
        if expected is None:
            raise PermissionError("replay artifact is not approved")
        if _SHA256.fullmatch(expected) is None:
            raise PermissionError("replay artifact approval hash is malformed")
        if request.duration_seconds > self.max_duration_seconds:
            raise PermissionError("replay duration exceeds policy")
        if request.rate_mbps > self.max_rate_mbps:
            raise PermissionError("replay rate exceeds policy")
        if request.loops > self.max_loops:
            raise PermissionError("replay loops exceed policy")
        return expected

    async def _hash_approved_artifact(
        self,
        request: ReplayRequest,
        expected_sha256: str,
        cancellation: CancellationToken,
    ) -> str:
        artifact_root = self.artifact_root
        if artifact_root is None:  # Guarded by _validate_request_authority.
            raise PermissionError("replay artifact root is unavailable")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _HASH_TIMEOUT_SECONDS
        root_descriptors: list[int] = []
        root_identity: tuple[int, ...] | None = None
        primary_error: BaseException | None = None
        try:
            root_descriptors, root_identity = _open_artifact_root(artifact_root)
            root_descriptor = root_descriptors[-1]
            artifact_descriptor = -1
            artifact_primary: BaseException | None = None
            try:
                if cancellation.cancelled:
                    raise _ArtifactHashCancelled
                if loop.time() >= deadline:
                    raise TimeoutError("replay artifact hashing deadline exceeded")
                named_before = os.stat(
                    request.artifact_name,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
                artifact_descriptor = os.open(
                    request.artifact_name,
                    _file_flags(),
                    dir_fd=root_descriptor,
                )
                before = os.fstat(artifact_descriptor)
                _validate_artifact_file(before, max_size_bytes=self.max_size_bytes)
                before_identity = _name_descriptor_identity(before)
                if _name_descriptor_identity(named_before) != before_identity:
                    raise PermissionError(
                        "replay artifact name no longer identifies its descriptor"
                    )

                actual = await _hash_descriptor(
                    artifact_descriptor,
                    int(before.st_size),
                    cancellation,
                    deadline=deadline,
                )

                after = os.fstat(artifact_descriptor)
                named_after = os.stat(
                    request.artifact_name,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
                if (
                    _name_descriptor_identity(after) != before_identity
                    or _name_descriptor_identity(named_after) != before_identity
                ):
                    raise PermissionError("replay artifact identity changed during hashing")
                if _directory_identity(os.fstat(root_descriptor)) != root_identity:
                    raise PermissionError("replay artifact root identity changed during hashing")
                _revalidate_artifact_root(artifact_root, root_descriptors)
                if actual != expected_sha256:
                    raise PermissionError("replay artifact hash does not match approval")
                return actual
            except BaseException as error:
                artifact_primary = error
                raise
            finally:
                if artifact_descriptor >= 0:
                    close_descriptor(
                        artifact_descriptor,
                        primary_error=artifact_primary,
                        context="replay artifact",
                    )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            _close_descriptors(root_descriptors, primary_error=primary_error)

    def authorization_decision(self) -> PrivilegedAuthorizationDecision:
        return privileged_capability_decision(
            agent_id=self.agent_id_provider(),
            capability_id=PCAP_REPLAY_CAPABILITY,
            authorization=self.authorization,
            role_allowed=self.role in {"capture_node", "lab_node"},
            policy_enabled=self.policy_enabled,
            provider_ready=self.tool_ready,
            permissions_ready=True,
            allowlists_ready=bool(
                self.allowed_interfaces and self.allowed_scenarios and self.approved_artifacts
            ),
            technical_ready=(
                self.tree_containment_ready
                and self.artifact_root is not None
                and self.namespace is not None
            ),
        )

    def _simulation_result(
        self,
        request: ReplayRequest,
        *,
        status: Literal["validated", "cancelled"],
        digest: str,
    ) -> ReplaySimulation:
        return ReplaySimulation(
            status=status,
            interface=request.interface,
            scenario_id=request.scenario_id,
            artifact_sha256=digest,
            effective_duration_seconds=request.duration_seconds,
            effective_rate_mbps=request.rate_mbps,
            effective_loops=request.loops,
            namespace=request.namespace,
            cleanup_complete=True,
        )

    async def simulate(
        self, request: ReplayRequest, cancellation: CancellationToken
    ) -> ReplaySimulation:
        expected = self._validate_request_authority(request)
        if cancellation.cancelled:
            self.cleanup_calls += 1
            return self._simulation_result(request, status="cancelled", digest=expected)
        try:
            digest = await self._hash_approved_artifact(request, expected, cancellation)
        except _ArtifactHashCancelled:
            self.cleanup_calls += 1
            return self._simulation_result(request, status="cancelled", digest=expected)

        decision = self.authorization_decision()
        if not decision.allowed:
            raise PermissionError(decision.reason or "pcap replay authorization denied")
        status: Literal["validated", "cancelled"] = "validated"
        try:
            await asyncio.sleep(0)
            if cancellation.cancelled:
                status = "cancelled"
        finally:
            self.cleanup_calls += 1
        return self._simulation_result(request, status=status, digest=digest)
