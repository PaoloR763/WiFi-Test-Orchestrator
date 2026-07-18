from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from artifact_quarantine_vectors import ARTIFACT_PRUNE_QUARANTINE_VECTORS

from wto_desktop_agent.domain.artifact_paths import (
    ARTIFACT_PRUNE_QUARANTINE_PATH_LENGTH,
    ARTIFACT_PRUNE_QUARANTINE_PATH_PREFIX,
    ARTIFACT_PRUNE_QUARANTINE_PREFIX_LENGTH,
    ARTIFACT_PRUNE_QUARANTINE_TOKEN_LENGTH,
    ARTIFACT_PRUNE_QUARANTINE_TOKEN_OFFSET,
    is_artifact_prune_quarantine_path,
)
from wto_desktop_agent.domain.models import LocalTaskEnvelope
from wto_desktop_agent.infrastructure.sqlite.store import (
    SCHEMA_VERSION,
    SQLiteStore,
)

TASK_ID = UUID("10000000-0000-4000-8000-000000000301")
EXECUTION_ID = UUID("20000000-0000-4000-8000-000000000301")


def _seed_task(store: SQLiteStore) -> None:
    now = datetime.now(UTC)
    store.ingest_task(
        LocalTaskEnvelope(
            task_id=TASK_ID,
            execution_id=EXECUTION_ID,
            task_type="protocol.contract_check",
            task_type_version="1.0.0",
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(minutes=5),
            idempotency_key=UUID("30000000-0000-4000-8000-000000000301"),
            required_capabilities=["capture.ieee80211.monitor"],
            foreground_requirement="not_required",
            user_interaction_requirement="none",
            parameters={},
        )
    )


def _manifest(artifact_id: str, size: int) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "artifact_id": artifact_id,
        "execution_id": str(EXECUTION_ID),
        "artifact_type": "pcapng",
        "media_type": "application/x-pcapng",
        "size_bytes": size,
        "sha256": "0" * 64,
        "created_at": "2026-07-15T12:00:00Z",
        "idempotency_key": artifact_id,
    }


def test_artifact_audit_limit_is_bounded_and_pending_semantics_are_unchanged(
    store: SQLiteStore,
) -> None:
    _seed_task(store)
    identifiers = [f"30000000-0000-4000-8000-{index + 310:012d}" for index in range(3)]
    for index, artifact_id in enumerate(identifiers):
        store.ensure_artifact_queued(
            task_id=str(TASK_ID),
            relative_path=f"outbox/artifact-{index}.pcapng",
            media_type="application/x-pcapng",
            payload=_manifest(artifact_id, 10 + index),
        )
    for artifact_id in identifiers[:2]:
        row = store.artifact_upload(artifact_id)
        assert row is not None
        store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))

    pending = store.pending_outbox("pending_uploads")
    audited = store.artifact_uploads(states=frozenset({"pending"}), limit=10)

    assert SCHEMA_VERSION == 2
    assert [row["artifact_id"] for row in pending] == identifiers[2:]
    assert [row["artifact_id"] for row in audited] == identifiers[2:]
    assert store.artifact_upload_count(states=frozenset({"confirmed"})) == 2
    with pytest.raises(ValueError, match="between 1 and 10000"):
        store.artifact_uploads(limit=0)
    with pytest.raises(ValueError, match="between 1 and 10000"):
        store.artifact_uploads(limit=10_001)


def test_confirmed_pruning_query_is_parameterized_and_bounded(store: SQLiteStore) -> None:
    _seed_task(store)
    identifiers = [f"30000000-0000-4000-8000-{index + 320:012d}" for index in range(3)]
    for index, artifact_id in enumerate(identifiers):
        store.ensure_artifact_queued(
            task_id=str(TASK_ID),
            relative_path=f"outbox/confirmed-{index}.pcapng",
            media_type="application/x-pcapng",
            payload=_manifest(artifact_id, 10),
        )
        row = store.artifact_upload(artifact_id)
        assert row is not None
        store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
        with store.connection() as connection:
            connection.execute(
                "UPDATE pending_uploads SET confirmed_at=? WHERE artifact_id=?",
                (f"2026-07-{index + 1:02d}T00:00:00+00:00", artifact_id),
            )

    candidates = store.confirmed_artifacts_for_pruning(
        confirmed_before=None,
        retain_count=1,
        retain_bytes=15,
        limit=2,
    )

    assert len(candidates) == 2
    assert {row["artifact_id"] for row in candidates} == set(identifiers[:2])
    assert all(row["state"] == "confirmed" for row in candidates)

    quarantined = candidates[0]
    old_path = str(quarantined["relative_path"])
    quarantine_path = f"outbox/.artifact-prune-quarantine-{'a' * 64}"
    assert store.update_confirmed_artifact_path(
        str(quarantined["upload_id"]),
        expected_relative_path=old_path,
        quarantine_relative_path=quarantine_path,
    )
    assert not store.update_confirmed_artifact_path(
        str(quarantined["upload_id"]),
        expected_relative_path=old_path,
        quarantine_relative_path=quarantine_path,
    )

    remaining = store.confirmed_artifacts_for_pruning(
        confirmed_before=None,
        retain_count=0,
        retain_bytes=None,
        limit=10,
    )
    assert str(quarantined["artifact_id"]) not in {str(row["artifact_id"]) for row in remaining}
    retained = store.artifact_upload(str(quarantined["artifact_id"]))
    assert retained is not None
    assert retained["relative_path"] == quarantine_path
    assert store.artifact_upload_count(states=frozenset({"confirmed"})) == 3


def test_quarantined_rows_are_excluded_before_count_and_byte_ranking(
    store: SQLiteStore,
) -> None:
    _seed_task(store)
    quarantined_id = "30000000-0000-4000-8000-000000000331"
    recent_id = "30000000-0000-4000-8000-000000000332"
    old_id = "30000000-0000-4000-8000-000000000333"
    pending_id = "30000000-0000-4000-8000-000000000334"
    records = (
        (quarantined_id, 1_000, "2026-07-04T00:00:00+00:00"),
        (recent_id, 30, "2026-07-03T00:00:00+00:00"),
        (old_id, 20, "2026-07-02T00:00:00+00:00"),
    )
    for artifact_id, size, confirmed_at in records:
        store.ensure_artifact_queued(
            task_id=str(TASK_ID),
            relative_path=f"outbox/artifact-{artifact_id}.pcapng",
            media_type="application/x-pcapng",
            payload=_manifest(artifact_id, size),
        )
        row = store.artifact_upload(artifact_id)
        assert row is not None
        store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
        with store.connection() as connection:
            connection.execute(
                "UPDATE pending_uploads SET confirmed_at=? WHERE artifact_id=?",
                (confirmed_at, artifact_id),
            )
    store.ensure_artifact_queued(
        task_id=str(TASK_ID),
        relative_path="outbox/artifact-pending.pcapng",
        media_type="application/x-pcapng",
        payload=_manifest(pending_id, 5_000),
    )
    quarantined = store.artifact_upload(quarantined_id)
    assert quarantined is not None
    quarantine_path = f"outbox/.artifact-prune-quarantine-{'b' * 64}"
    assert store.update_confirmed_artifact_path(
        str(quarantined["upload_id"]),
        expected_relative_path=str(quarantined["relative_path"]),
        quarantine_relative_path=quarantine_path,
    )

    keep_one = store.confirmed_artifacts_for_pruning(
        confirmed_before=None,
        retain_count=1,
        retain_bytes=None,
        limit=10,
    )
    assert [row["artifact_id"] for row in keep_one] == [old_id]

    keep_two = store.confirmed_artifacts_for_pruning(
        confirmed_before=None,
        retain_count=2,
        retain_bytes=None,
        limit=10,
    )
    assert keep_two == []

    byte_candidates = store.confirmed_artifacts_for_pruning(
        confirmed_before=None,
        retain_count=None,
        retain_bytes=35,
        limit=10,
    )
    assert [row["artifact_id"] for row in byte_candidates] == [old_id]
    assert all(row["relative_path"] != quarantine_path for row in byte_candidates)
    assert store.artifact_upload(pending_id) is not None


def test_only_quarantines_never_produce_pruning_candidates(store: SQLiteStore) -> None:
    _seed_task(store)
    artifact_id = "30000000-0000-4000-8000-000000000341"
    store.ensure_artifact_queued(
        task_id=str(TASK_ID),
        relative_path="outbox/artifact-only-quarantine.pcapng",
        media_type="application/x-pcapng",
        payload=_manifest(artifact_id, 9_999),
    )
    row = store.artifact_upload(artifact_id)
    assert row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
    assert store.update_confirmed_artifact_path(
        str(row["upload_id"]),
        expected_relative_path=str(row["relative_path"]),
        quarantine_relative_path=f"outbox/.artifact-prune-quarantine-{'c' * 64}",
    )

    assert (
        store.confirmed_artifacts_for_pruning(
            confirmed_before=None,
            retain_count=0,
            retain_bytes=0,
            limit=10,
        )
        == []
    )


def test_pruning_quarantine_detection_is_exact_case_sensitive_and_ranked_in_sqlite(
    store: SQLiteStore,
) -> None:
    _seed_task(store)
    lexical_cases = tuple(
        (
            label,
            relative_path,
            10_000 if expected else 2,
            "2026-07-15T00:00:00+00:00",
        )
        for label, relative_path, expected in ARTIFACT_PRUNE_QUARANTINE_VECTORS
    )
    cases = lexical_cases + (
        ("recent_active", "outbox/artifact-recent.pcapng", 30, "2026-07-16T00:00:00+00:00"),
        ("old_active", "outbox/artifact-old.pcapng", 20, "2026-07-01T00:00:00+00:00"),
    )
    identifiers: dict[str, str] = {}
    for index, (label, relative_path, size, confirmed_at) in enumerate(cases):
        expected_quarantine = label == "canonical"
        assert is_artifact_prune_quarantine_path(relative_path) is expected_quarantine
        with store.connection() as connection:
            sql_quarantine = connection.execute(
                "SELECT (typeof(?)='text' AND length(CAST(? AS BLOB))=? "
                "AND instr(CAST(? AS BLOB),X'00')=0 "
                "AND substr(CAST(? AS BLOB),1,?)=CAST(? AS BLOB) "
                "AND CAST(substr(CAST(? AS BLOB),?,?) AS TEXT) "
                "NOT GLOB '*[^0-9a-f]*')",
                (
                    relative_path,
                    relative_path,
                    ARTIFACT_PRUNE_QUARANTINE_PATH_LENGTH,
                    relative_path,
                    relative_path,
                    ARTIFACT_PRUNE_QUARANTINE_PREFIX_LENGTH,
                    ARTIFACT_PRUNE_QUARANTINE_PATH_PREFIX,
                    relative_path,
                    ARTIFACT_PRUNE_QUARANTINE_TOKEN_OFFSET,
                    ARTIFACT_PRUNE_QUARANTINE_TOKEN_LENGTH,
                ),
            ).fetchone()[0]
        assert bool(sql_quarantine) is expected_quarantine
        artifact_id = f"30000000-0000-4000-8000-{index + 400:012d}"
        store.ensure_artifact_queued(
            task_id=str(TASK_ID),
            relative_path=f"outbox/vector-{index}.pcapng",
            media_type="application/x-pcapng",
            payload=_manifest(artifact_id, size),
        )
        row = store.artifact_upload(artifact_id)
        assert row is not None
        store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
        try:
            with store.connection() as connection:
                connection.execute(
                    "UPDATE pending_uploads SET relative_path=?,confirmed_at=? "
                    "WHERE artifact_id=?",
                    (relative_path, confirmed_at, artifact_id),
                )
        except sqlite3.IntegrityError:
            assert not expected_quarantine
            with store.connection() as connection:
                connection.execute(
                    "DELETE FROM pending_uploads WHERE artifact_id=?",
                    (artifact_id,),
                )
            continue
        identifiers[label] = artifact_id

    pending_id = "30000000-0000-4000-8000-000000000499"
    store.ensure_artifact_queued(
        task_id=str(TASK_ID),
        relative_path="outbox/pending-containing-quarantine.pcapng",
        media_type="application/x-pcapng",
        payload=_manifest(pending_id, 50_000),
    )

    retain_none = store.confirmed_artifacts_for_pruning(
        confirmed_before=None,
        retain_count=0,
        retain_bytes=None,
        limit=20,
    )
    selected = {str(row["artifact_id"]) for row in retain_none}
    selected_by_python = {
        identifiers[label]
        for label, relative_path, _size, _confirmed_at in cases
        if label in identifiers and not is_artifact_prune_quarantine_path(relative_path)
    }
    assert identifiers["canonical"] not in selected
    assert selected == selected_by_python
    assert identifiers["uppercase_prefix"] in selected
    assert identifiers["uppercase_token"] in selected
    assert pending_id not in selected

    keep_one = store.confirmed_artifacts_for_pruning(
        confirmed_before=None,
        retain_count=1,
        retain_bytes=None,
        limit=20,
    )
    assert {str(row["artifact_id"]) for row in keep_one} == selected - {
        identifiers["recent_active"]
    }


@pytest.mark.parametrize(
    ("label", "relative_path", "expected"),
    ARTIFACT_PRUNE_QUARANTINE_VECTORS,
)
def test_confirmed_artifact_path_persistence_uses_the_lexical_quarantine_predicate(
    store: SQLiteStore,
    label: str,
    relative_path: str,
    expected: bool,
) -> None:
    _seed_task(store)
    artifact_id = "30000000-0000-4000-8000-000000000498"
    original = "outbox/persisted-vector.pcapng"
    store.ensure_artifact_queued(
        task_id=str(TASK_ID),
        relative_path=original,
        media_type="application/x-pcapng",
        payload=_manifest(artifact_id, 2),
    )
    row = store.artifact_upload(artifact_id)
    assert row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))

    if expected:
        assert label == "canonical"
        assert store.update_confirmed_artifact_path(
            str(row["upload_id"]),
            expected_relative_path=original,
            quarantine_relative_path=relative_path,
        )
    else:
        with pytest.raises(ValueError, match="artifact quarantine path"):
            store.update_confirmed_artifact_path(
                str(row["upload_id"]),
                expected_relative_path=original,
                quarantine_relative_path=relative_path,
            )


def test_confirmed_row_with_nul_suffix_is_a_pruning_candidate(store: SQLiteStore) -> None:
    _seed_task(store)
    artifact_id = "30000000-0000-4000-8000-000000000497"
    original = "outbox/corrupt-nul-row.pcapng"
    corrupt = "outbox/.artifact-prune-quarantine-" + "a" * 64 + "\x00suffix"
    store.ensure_artifact_queued(
        task_id=str(TASK_ID),
        relative_path=original,
        media_type="application/x-pcapng",
        payload=_manifest(artifact_id, 2),
    )
    row = store.artifact_upload(artifact_id)
    assert row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
    with store.connection() as connection:
        connection.execute(
            "UPDATE pending_uploads SET relative_path=? WHERE artifact_id=?",
            (corrupt, artifact_id),
        )

    candidates = store.confirmed_artifacts_for_pruning(
        confirmed_before=None,
        retain_count=0,
        retain_bytes=None,
        limit=10,
    )

    assert [str(candidate["artifact_id"]) for candidate in candidates] == [artifact_id]
    assert not is_artifact_prune_quarantine_path(corrupt)
