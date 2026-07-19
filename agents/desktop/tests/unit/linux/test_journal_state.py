from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from wto_desktop_agent.platforms.linux import journal_state
from wto_desktop_agent.platforms.linux.journal_state import (
    classify_capture_journal_name,
    inspect_capture_journals,
)

EXECUTION_ID = "20000000-0000-4000-8000-000000000071"


def test_journal_name_grammar_uses_fullmatch() -> None:
    assert classify_capture_journal_name(f"{EXECUTION_ID}.json").classification == "active"
    assert (
        classify_capture_journal_name(f".{EXECUTION_ID}.pending.{'a' * 48}").classification
        == "pending"
    )
    assert (
        classify_capture_journal_name(f".{EXECUTION_ID}.recovery.{'b' * 48}").classification
        == "manual_recovery"
    )
    assert (
        classify_capture_journal_name(f".capture-journal-retired-{'c' * 64}").classification
        == "retired_quarantine"
    )
    assert (
        classify_capture_journal_name(f".capture-journal-quarantine-{'d' * 64}").classification
        == "retired_quarantine"
    )
    for ambiguous in (
        f"prefix-{EXECUTION_ID}.json",
        f".{EXECUTION_ID}.pending.{'a' * 47}",
        f".capture-journal-quarantine-{'a' * 63}g",
        "anything-containing-pending",
    ):
        assert classify_capture_journal_name(ambiguous).classification == "invalid_ambiguous"


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX journal identities")


def _root(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    root = state / "capture-journal"
    root.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    os.chmod(root, 0o700)
    return root


def _write(root: Path, name: str, content: bytes = b"x") -> Path:
    path = root / name
    path.write_bytes(content)
    os.chmod(path, 0o600)
    return path


def _pending_payload() -> bytes:
    return json.dumps(
        {
            "schema_version": "2.0.0",
            "execution_id": EXECUTION_ID,
            "recorded_at": "2026-07-17T00:00:00Z",
            "request": {"execution_id": EXECUTION_ID},
            "interface_state": {},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_empty_and_safe_retired_history_do_not_block(tmp_path: Path) -> None:
    root = _root(tmp_path)
    assert inspect_capture_journals(root.parent).status == "OK"
    for index in range(512):
        _write(root, f".capture-journal-retired-{index:064x}")
    _write(root, f".capture-journal-quarantine-{'f' * 64}")
    report = inspect_capture_journals(root.parent)
    assert report.status == "OK"
    assert report.retired_quarantine == 513


def test_active_manual_and_ambiguous_names_block(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _write(root, f"{EXECUTION_ID}.json")
    _write(root, f".{EXECUTION_ID}.recovery.{'a' * 48}")
    _write(root, "active-ish.json")
    report = inspect_capture_journals(root.parent)
    assert report.status == "BLOCKED"
    assert report.active == 1
    assert report.manual_recovery == 1
    assert report.invalid_ambiguous == 1


def test_only_complete_pending_is_nonblocking_degraded(tmp_path: Path) -> None:
    root = _root(tmp_path)
    name = f".{EXECUTION_ID}.pending.{'a' * 48}"
    _write(root, name, _pending_payload())
    assert inspect_capture_journals(root.parent).status == "DEGRADED"

    (root / name).write_bytes(b"{")
    os.chmod(root / name, 0o600)
    assert inspect_capture_journals(root.parent).status == "BLOCKED"


@pytest.mark.parametrize("unsafe", ("symlink", "hardlink", "owner", "mode"))
def test_unsafe_journal_identity_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe: str,
) -> None:
    root = _root(tmp_path)
    retired = root / f".capture-journal-retired-{'e' * 64}"
    if unsafe == "symlink":
        target = _write(root, "target")
        retired.symlink_to(target)
    else:
        _write(root, retired.name)
        if unsafe == "hardlink":
            os.link(retired, root / "second-link")
        elif unsafe == "owner":
            real_stat = journal_state.os.stat

            def foreign_owner(path: object, *args: object, **kwargs: object) -> os.stat_result:
                metadata = real_stat(path, *args, **kwargs)
                if path == retired.name:
                    values = list(metadata)
                    values[4] = int(metadata.st_uid) + 1
                    return os.stat_result(values)
                return metadata

            monkeypatch.setattr(journal_state.os, "stat", foreign_owner)
        else:
            os.chmod(retired, 0o644)
    assert inspect_capture_journals(root.parent).status == "BLOCKED"
