from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import UUID

JournalNameClass = Literal[
    "active",
    "pending",
    "manual_recovery",
    "retired_quarantine",
    "invalid_ambiguous",
]
JournalInspectionStatus = Literal["OK", "DEGRADED", "BLOCKED"]

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-" r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
_ACTIVE = re.compile(rf"^(?P<execution>{_UUID})\.json$")
_PENDING = re.compile(rf"^\.(?P<execution>{_UUID})\.pending\.(?P<nonce>[0-9a-f]{{48}})$")
_RECOVERY = re.compile(rf"^\.(?P<execution>{_UUID})\.recovery\.(?P<nonce>[0-9a-f]{{48}})$")
_MANUAL = re.compile(r"^\.capture-journal-manual-[0-9a-f]{64}$")
_RETIRED = re.compile(r"^\.capture-journal-retired-[0-9a-f]{64}$")
_QUARANTINE = re.compile(r"^\.capture-journal-quarantine-[0-9a-f]{64}$")
_SUPPORTED_JOURNAL_SCHEMAS = frozenset({"1.0.0", "2.0.0", "2.1.0"})
_MAXIMUM_JOURNAL_BYTES = 2 * 1024 * 1024
_MAXIMUM_INSPECTION_ENTRIES = 100_000


@dataclass(frozen=True)
class JournalName:
    classification: JournalNameClass
    execution_id: str | None = None


@dataclass(frozen=True)
class JournalInspection:
    status: JournalInspectionStatus
    detail: str
    active: int = 0
    pending: int = 0
    manual_recovery: int = 0
    retired_quarantine: int = 0
    invalid_ambiguous: int = 0


def classify_capture_journal_name(name: str) -> JournalName:
    match = _ACTIVE.fullmatch(name)
    if match is not None:
        return JournalName("active", match.group("execution"))
    match = _PENDING.fullmatch(name)
    if match is not None:
        return JournalName("pending", match.group("execution"))
    match = _RECOVERY.fullmatch(name)
    if match is not None:
        return JournalName("manual_recovery", match.group("execution"))
    if _MANUAL.fullmatch(name) is not None:
        return JournalName("manual_recovery")
    if _RETIRED.fullmatch(name) is not None or _QUARANTINE.fullmatch(name) is not None:
        return JournalName("retired_quarantine")
    return JournalName("invalid_ambiguous")


def pending_name_matches_execution(name: str, execution_id: UUID) -> bool:
    classified = classify_capture_journal_name(name)
    return classified.classification == "pending" and classified.execution_id == str(execution_id)


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | int(getattr(os, "O_DIRECTORY", 0))
        | int(getattr(os, "O_CLOEXEC", 0))
        | int(getattr(os, "O_NOFOLLOW", 0))
    )


def _read_flags() -> int:
    return os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_uid),
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        int(metadata.st_nlink),
    )


def _read_valid_pending(
    root_descriptor: int,
    name: str,
    execution_id: str,
    expected_uid: int,
) -> None:
    descriptor = os.open(name, _read_flags(), dir_fd=root_descriptor)
    try:
        before = os.fstat(descriptor)
        named = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        if (
            _identity(before) != _identity(named)
            or not stat.S_ISREG(before.st_mode)
            or int(before.st_uid) != expected_uid
            or stat.S_IMODE(before.st_mode) != 0o600
            or int(before.st_nlink) != 1
            or before.st_size <= 0
            or before.st_size > _MAXIMUM_JOURNAL_BYTES
        ):
            raise ValueError("pending journal identity is unsafe")
        encoded = bytearray()
        while len(encoded) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(encoded))
            if not chunk:
                raise ValueError("pending journal is truncated")
            encoded.extend(chunk)
        if os.read(descriptor, 1):
            raise ValueError("pending journal grew during inspection")
        after = os.fstat(descriptor)
        if (
            _identity(before) != _identity(after)
            or before.st_size != after.st_size
            or (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise ValueError("pending journal changed during inspection")
        payload = json.loads(bytes(encoded).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("pending journal payload is invalid")
        schema = payload.get("schema_version")
        expected_fields = {
            "schema_version",
            "execution_id",
            "recorded_at",
            "request",
            "interface_state",
        }
        if schema == "2.1.0":
            expected_fields.add("capture_authority")
        request = payload.get("request")
        if (
            schema not in _SUPPORTED_JOURNAL_SCHEMAS
            or set(payload) != expected_fields
            or payload.get("execution_id") != execution_id
            or not isinstance(request, dict)
            or request.get("execution_id") != execution_id
            or not isinstance(payload.get("interface_state"), dict)
        ):
            raise ValueError("pending journal authority is invalid")
        if schema == "2.1.0":
            authority = payload.get("capture_authority")
            authority_fields = {
                "task_id",
                "execution_id",
                "idempotency_key",
                "fingerprint_version",
                "fingerprint_sha256",
                "operation_token",
            }
            if (
                not isinstance(authority, dict)
                or set(authority) != authority_fields
                or authority.get("execution_id") != execution_id
                or authority.get("task_id") != request.get("task_id")
                or authority.get("idempotency_key") != request.get("idempotency_key")
                or not isinstance(authority.get("fingerprint_version"), str)
                or not authority.get("fingerprint_version")
                or not isinstance(authority.get("fingerprint_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", authority["fingerprint_sha256"]) is None
                or not isinstance(authority.get("operation_token"), str)
                or re.fullmatch(r"[0-9a-f]{32}", authority["operation_token"]) is None
            ):
                raise ValueError("pending journal capture authority is invalid")
    finally:
        os.close(descriptor)


def inspect_capture_journals(state_dir: Path) -> JournalInspection:
    root = state_dir / "capture-journal"
    try:
        named_root = root.lstat()
    except FileNotFoundError:
        return JournalInspection(
            "DEGRADED",
            "capture journal directory is missing; doctor did not create it",
        )
    if not stat.S_ISDIR(named_root.st_mode) or root.is_symlink():
        return JournalInspection("BLOCKED", "capture journal root is not a plain directory")
    descriptor = -1
    try:
        descriptor = os.open(root, _directory_flags())
        opened_root = os.fstat(descriptor)
        expected_uid = int(getattr(os, "geteuid", lambda: opened_root.st_uid)())
        if (
            _identity(opened_root) != _identity(named_root)
            or int(opened_root.st_uid) != expected_uid
            or stat.S_IMODE(opened_root.st_mode) != 0o700
        ):
            return JournalInspection(
                "BLOCKED", "capture journal root ownership, mode, or identity is unsafe"
            )
        counts = {
            "active": 0,
            "pending": 0,
            "manual_recovery": 0,
            "retired_quarantine": 0,
            "invalid_ambiguous": 0,
        }
        issues: list[str] = []
        entries_seen = 0
        with os.scandir(descriptor) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > _MAXIMUM_INSPECTION_ENTRIES:
                    issues.append("bounded inspection limit exceeded")
                    break
                classified = classify_capture_journal_name(entry.name)
                counts[classified.classification] += 1
                if classified.classification == "invalid_ambiguous":
                    issues.append(f"ambiguous name: {entry.name[:96]}")
                    continue
                try:
                    metadata = os.stat(
                        entry.name,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or int(metadata.st_uid) != expected_uid
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                        or int(metadata.st_nlink) != 1
                    ):
                        raise ValueError("unsafe owner, type, mode, or link count")
                    if classified.classification == "pending":
                        assert classified.execution_id is not None
                        _read_valid_pending(
                            descriptor,
                            entry.name,
                            classified.execution_id,
                            expected_uid,
                        )
                except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as error:
                    issues.append(f"{entry.name[:96]}: {type(error).__name__}")
        blocked = (
            counts["active"] > 0
            or counts["manual_recovery"] > 0
            or counts["invalid_ambiguous"] > 0
            or bool(issues)
        )
        if blocked:
            status: JournalInspectionStatus = "BLOCKED"
        elif counts["pending"]:
            status = "DEGRADED"
        else:
            status = "OK"
        detail = "capture journals: " + ", ".join(
            f"{name}={value}" for name, value in counts.items()
        )
        if issues:
            detail += "; " + "; ".join(issues[:8])
        return JournalInspection(status, detail, **counts)
    except OSError as error:
        return JournalInspection(
            "BLOCKED", f"capture journal inspection failed: {type(error).__name__}"
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
