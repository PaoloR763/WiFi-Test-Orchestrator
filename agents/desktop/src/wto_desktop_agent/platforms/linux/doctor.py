from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Literal

from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.domain.models import DoctorCheck
from wto_desktop_agent.platforms.linux.journal_state import inspect_capture_journals
from wto_desktop_agent.platforms.linux.secret_store import (
    inspect_encrypted_file_secret_store_read_only,
    inspect_secret_service_read_only,
)
from wto_desktop_agent.platforms.linux.service_manager import LinuxServiceManager

_INTENT = re.compile(r"^intent-[0-9a-f]{48}\.json$")
_INTENT_RETIRED = re.compile(r"^\.artifact-intent-quarantine-[0-9a-f]{64}$")
_MARKER = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-" r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\.jsonl$"
)
_MARKER_RETIRED = re.compile(r"^\.capture-marker-retired-[0-9a-f]{64}$")
_MAXIMUM_DIAGNOSTIC_ENTRIES = 100_000
_MAXIMUM_CAPTURE_MARKER_BYTES = 4 * 1024 * 1024


def _effective_uid(metadata: os.stat_result) -> int:
    return int(getattr(os, "geteuid", lambda: metadata.st_uid)())


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | int(getattr(os, "O_DIRECTORY", 0))
        | int(getattr(os, "O_CLOEXEC", 0))
        | int(getattr(os, "O_NOFOLLOW", 0))
    )


def _validate_opened_directory(
    named: os.stat_result,
    opened: os.stat_result,
) -> None:
    named_identity = (
        int(named.st_dev),
        int(named.st_ino),
        int(named.st_uid),
        stat.S_IFMT(named.st_mode),
        stat.S_IMODE(named.st_mode),
        int(named.st_nlink),
    )
    opened_identity = (
        int(opened.st_dev),
        int(opened.st_ino),
        int(opened.st_uid),
        stat.S_IFMT(opened.st_mode),
        stat.S_IMODE(opened.st_mode),
        int(opened.st_nlink),
    )
    if named_identity != opened_identity:
        raise PermissionError("directory identity changed")
    if (
        not stat.S_ISDIR(opened.st_mode)
        or int(opened.st_uid) != _effective_uid(opened)
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        raise PermissionError("directory owner or mode is unsafe")


def _open_directory(path: Path) -> int | None:
    if not path.is_absolute():
        raise ValueError("diagnostic directory roots must be absolute")
    descriptor = os.open(Path(path.anchor), _directory_flags())
    try:
        final_named = os.fstat(descriptor)
        for component in path.parts[1:]:
            try:
                named = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                os.close(descriptor)
                return None
            if not stat.S_ISDIR(named.st_mode):
                raise PermissionError("path component is not a plain directory")
            child = os.open(component, _directory_flags(), dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if (
                    int(named.st_dev),
                    int(named.st_ino),
                    stat.S_IFMT(named.st_mode),
                ) != (
                    int(opened.st_dev),
                    int(opened.st_ino),
                    stat.S_IFMT(opened.st_mode),
                ):
                    raise PermissionError("directory identity changed")
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
            final_named = named
        _validate_opened_directory(final_named, os.fstat(descriptor))
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_child_directory(parent_descriptor: int, name: str) -> int | None:
    try:
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(named.st_mode):
        raise PermissionError("path component is not a plain directory")
    descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    try:
        _validate_opened_directory(named, os.fstat(descriptor))
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


SecretBackendInspector = Callable[[AgentSettings], DoctorCheck]


def _secret_service_check(settings: AgentSettings) -> DoctorCheck:
    inspected = inspect_secret_service_read_only(
        total_timeout_seconds=settings.linux_secret_service_total_timeout_seconds,
        operation_timeout_seconds=settings.linux_secret_service_operation_timeout_seconds,
    )
    if settings.linux_secret_backend == "auto":  # noqa: S105
        return inspected.model_copy(
            update={
                "detail": inspected.detail.replace(
                    "backend=secret_service",
                    "backend=auto effective=secret_service",
                    1,
                )
            }
        )
    return inspected


def _encrypted_file_secret_check(settings: AgentSettings) -> DoctorCheck:
    return inspect_encrypted_file_secret_store_read_only(settings.state_dir)


def _secret_check(
    settings: AgentSettings,
    injected: Mapping[str, SecretBackendInspector],
) -> DoctorCheck:
    backend = str(settings.linux_secret_backend)
    test_inspector = injected.get(backend)
    if test_inspector is not None:
        return test_inspector(settings)
    if backend in {"secret_service", "auto"}:
        return _secret_service_check(settings)
    if backend == "encrypted_file":
        return _encrypted_file_secret_check(settings)
    return DoctorCheck(
        name="secret_store",
        status="BLOCKED",
        detail=f"backend={backend} state=unknown_backend",
    )


def _artifact_check(artifacts_dir: Path) -> DoctorCheck:
    artifact_descriptor: int | None = None
    outbox_descriptor: int | None = None
    intent_descriptor: int | None = None
    try:
        artifact_descriptor = _open_directory(artifacts_dir)
        if artifact_descriptor is None:
            return DoctorCheck(
                name="artifact_state",
                status="DEGRADED",
                detail="Artifact root is missing; doctor did not create it",
            )
        outbox_descriptor = _open_child_directory(artifact_descriptor, "outbox")
        if outbox_descriptor is None:
            return DoctorCheck(
                name="artifact_state",
                status="DEGRADED",
                detail="Artifact intent state is missing; doctor did not initialize it",
            )
        intent_descriptor = _open_child_directory(outbox_descriptor, "intents")
        if intent_descriptor is None:
            return DoctorCheck(
                name="artifact_state",
                status="DEGRADED",
                detail="Artifact intent state is missing; doctor did not initialize it",
            )
        active = 0
        invalid = 0
        retired = 0
        entries_seen = 0
        with os.scandir(intent_descriptor) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > _MAXIMUM_DIAGNOSTIC_ENTRIES:
                    invalid += 1
                    break
                if _INTENT.fullmatch(entry.name):
                    active += 1
                elif _INTENT_RETIRED.fullmatch(entry.name):
                    retired += 1
                else:
                    invalid += 1
                metadata = os.stat(
                    entry.name,
                    dir_fd=intent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or int(metadata.st_uid) != _effective_uid(metadata)
                    or int(metadata.st_nlink) != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    invalid += 1
        if invalid:
            status: Literal["OK", "DEGRADED", "BLOCKED"] = "BLOCKED"
        elif active:
            status = "DEGRADED"
        else:
            status = "OK"
        return DoctorCheck(
            name="artifact_state",
            status=status,
            detail=f"artifact intents active={active}, retired={retired}, invalid={invalid}",
        )
    except (OSError, PermissionError, ValueError):
        return DoctorCheck(
            name="artifact_state",
            status="BLOCKED",
            detail="Artifact root ownership, mode, or identity is unsafe",
        )
    finally:
        for descriptor in (intent_descriptor, outbox_descriptor, artifact_descriptor):
            if descriptor is not None:
                os.close(descriptor)


def _capture_marker_check(state_dir: Path) -> DoctorCheck:
    root = state_dir / "capture-markers"
    descriptor: int | None = None
    try:
        descriptor = _open_directory(root)
        if descriptor is None:
            return DoctorCheck(
                name="capture_artifact_recovery",
                status="DEGRADED",
                detail="Capture marker state is missing; doctor did not create it",
            )
        active = retired = invalid = entries_seen = 0
        rollback_complete = verification_pending = rollback_mismatch = unavailable = 0
        manual_recovery = 0
        with os.scandir(descriptor) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > _MAXIMUM_DIAGNOSTIC_ENTRIES:
                    invalid += 1
                    break
                if _MARKER.fullmatch(entry.name):
                    active += 1
                elif _MARKER_RETIRED.fullmatch(entry.name):
                    retired += 1
                else:
                    invalid += 1
                metadata = os.stat(
                    entry.name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or int(metadata.st_uid) != _effective_uid(metadata)
                    or int(metadata.st_nlink) != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    invalid += 1
                    continue
                if not _MARKER.fullmatch(entry.name):
                    continue
                marker_descriptor = -1
                try:
                    marker_descriptor = os.open(
                        entry.name,
                        os.O_RDONLY
                        | int(getattr(os, "O_CLOEXEC", 0))
                        | int(getattr(os, "O_NOFOLLOW", 0)),
                        dir_fd=descriptor,
                    )
                    opened = os.fstat(marker_descriptor)
                    if (
                        int(opened.st_dev) != int(metadata.st_dev)
                        or int(opened.st_ino) != int(metadata.st_ino)
                        or opened.st_size <= 0
                        or opened.st_size > _MAXIMUM_CAPTURE_MARKER_BYTES
                    ):
                        raise ValueError("capture marker identity or size is invalid")
                    payload = bytearray()
                    while len(payload) < opened.st_size:
                        chunk = os.read(marker_descriptor, opened.st_size - len(payload))
                        if not chunk:
                            raise ValueError("capture marker is truncated")
                        payload.extend(chunk)
                    if os.read(marker_descriptor, 1):
                        raise ValueError("capture marker grew during inspection")
                    after = os.fstat(marker_descriptor)
                    named_after = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                    if any(
                        int(getattr(observed, field)) != int(getattr(metadata, field))
                        for observed in (after, named_after)
                        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                    ):
                        raise ValueError("capture marker changed during inspection")
                    lines = bytes(payload).splitlines()
                    event = json.loads(lines[-1].decode("utf-8"))
                    if not isinstance(event, dict):
                        raise ValueError("capture marker event is invalid")
                    state = event.get("state")
                    if state == "ROLLBACK_VERIFICATION_PENDING":
                        details = event.get("details")
                        rollback = details.get("rollback") if isinstance(details, dict) else None
                        verification = (
                            rollback.get("verification_status")
                            if isinstance(rollback, dict)
                            else None
                        )
                        if verification == "mismatch":
                            rollback_mismatch += 1
                        elif verification in {"partial", "unavailable"}:
                            verification_pending += 1
                            if verification == "unavailable":
                                unavailable += 1
                        else:
                            manual_recovery += 1
                    elif state in {
                        "INTERFACE_RESTORED",
                        "STAGING_INTENT_DURABLE",
                        "LOCAL_ARTIFACT_COMMITTED",
                        "BINDING_PUBLISHED",
                    }:
                        rollback_complete += 1
                    else:
                        manual_recovery += 1
                except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
                    invalid += 1
                finally:
                    if marker_descriptor >= 0:
                        os.close(marker_descriptor)
        marker_status: Literal["OK", "DEGRADED", "BLOCKED"]
        if invalid or verification_pending or rollback_mismatch or unavailable or manual_recovery:
            marker_status = "BLOCKED"
        elif active:
            marker_status = "DEGRADED"
        else:
            marker_status = "OK"
        return DoctorCheck(
            name="capture_artifact_recovery",
            status=marker_status,
            detail=(
                f"capture markers active={active}, retired={retired}, invalid={invalid}; "
                f"rollback_complete={rollback_complete}, "
                f"verification_pending={verification_pending}, "
                f"rollback_mismatch={rollback_mismatch}, unavailable={unavailable}, "
                f"manual_recovery={manual_recovery}"
            ),
        )
    except (OSError, PermissionError, ValueError):
        return DoctorCheck(
            name="capture_artifact_recovery",
            status="BLOCKED",
            detail="Capture marker state ownership, mode, or identity is unsafe",
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)


class LinuxReadOnlyDoctor:
    """Linux diagnostics composition with no runtime/bootstrap constructors."""

    def __init__(
        self,
        settings: AgentSettings,
        *,
        secret_backend_inspectors: Mapping[str, SecretBackendInspector] | None = None,
    ) -> None:
        self.settings = settings
        self._secret_backend_inspectors = dict(secret_backend_inspectors or {})

    def run(self) -> tuple[DoctorCheck, ...]:
        journals = inspect_capture_journals(self.settings.state_dir)
        journal_check = DoctorCheck(
            name="capture_interface_recovery",
            status=journals.status,
            detail=journals.detail,
        )
        service = LinuxServiceManager(
            self.settings.node_role,
            self.settings.state_dir,
        )
        service_state = service.status()
        service_check = DoctorCheck(
            name="service_manager",
            status="OK" if service_state == "active" else "DEGRADED",
            detail=f"systemd unit {service.unit} state: {service_state}",
        )
        return (
            _secret_check(self.settings, self._secret_backend_inspectors),
            service_check,
            journal_check,
            _capture_marker_check(self.settings.state_dir),
            _artifact_check(self.settings.effective_artifacts_dir),
        )
