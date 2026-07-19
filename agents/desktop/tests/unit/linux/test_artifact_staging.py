from __future__ import annotations

import asyncio
import errno
import hashlib
import inspect
import json
import os
import stat
import threading
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from artifact_quarantine_vectors import ARTIFACT_PRUNE_QUARANTINE_VECTORS

import wto_desktop_agent.application.artifacts as artifacts_module
import wto_desktop_agent.platforms.linux.secure_fs as secure_fs_module
from wto_desktop_agent.application.artifacts import (
    ArtifactReconciliationError,
    SQLiteArtifactStager,
)
from wto_desktop_agent.domain.artifact_paths import (
    is_artifact_prune_quarantine_path,
)
from wto_desktop_agent.domain.errors import PluginUnavailableError
from wto_desktop_agent.domain.models import LocalTaskEnvelope
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.platforms.linux.secure_fs import capture_file_identity
from wto_desktop_agent.ports.plugins import CancellationToken

TASK_ID = UUID("10000000-0000-4000-8000-000000000011")
EXECUTION_ID = UUID("20000000-0000-4000-8000-000000000011")
ARTIFACT_ID = UUID("30000000-0000-4000-8000-000000000011")

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux descriptor semantics")


def _store(tmp_path: Path) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
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
            idempotency_key=ARTIFACT_ID,
            required_capabilities=["capture.ieee80211.monitor"],
            foreground_requirement="not_required",
            user_interaction_requirement="none",
            parameters={},
        )
    )
    return store


def _manifest() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "artifact_id": str(ARTIFACT_ID),
        "execution_id": str(EXECUTION_ID),
        "artifact_type": "pcapng",
        "media_type": "application/x-pcapng",
        "created_at": "2026-07-14T12:00:00Z",
        "idempotency_key": str(ARTIFACT_ID),
    }


def _source(root: Path, data: bytes = b"stable capture bytes") -> Path:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    source = root / "capture-source.pcapng"
    source.write_bytes(data)
    os.chmod(source, 0o600)
    return source


def _outbox_objects(root: Path) -> list[Path]:
    return [
        entry
        for entry in (root / "outbox").iterdir()
        if entry.name
        not in {
            "intents",
            "prune-intents",
            "prune-active",
            "prune-retired",
            "prune-conflicts",
        }
    ]


def _quarantines(directory: Path, prefix: str) -> list[Path]:
    return sorted(entry for entry in directory.iterdir() if entry.name.startswith(prefix))


@dataclass(frozen=True)
class _ExpectedFileIdentity:
    st_dev: int
    st_ino: int
    st_uid: int
    file_type: int
    mode: int
    st_nlink: int


def _capture_path_identity(path: Path) -> _ExpectedFileIdentity:
    metadata = path.stat(follow_symlinks=False)
    return _ExpectedFileIdentity(
        st_dev=int(metadata.st_dev),
        st_ino=int(metadata.st_ino),
        st_uid=int(metadata.st_uid),
        file_type=stat.S_IFMT(metadata.st_mode),
        mode=stat.S_IMODE(metadata.st_mode),
        st_nlink=int(metadata.st_nlink),
    )


def assert_logically_quarantined(
    directory: Path,
    prefix: str,
    *,
    active_name: str,
    expected_identity: _ExpectedFileIdentity,
    expected_content: bytes | None = None,
    maintenance_issues: tuple[str, ...] | None = None,
) -> Path:
    assert not os.path.lexists(directory / active_name)
    quarantines = _quarantines(directory, prefix)
    assert len(quarantines) == 1
    quarantine = quarantines[0]
    observed = _capture_path_identity(quarantine)
    assert observed == expected_identity
    assert observed.file_type == stat.S_IFREG
    if expected_content is not None:
        assert quarantine.read_bytes() == expected_content
    if maintenance_issues is not None:
        assert any(
            "physical_delete_pending" in issue and quarantine.name in issue
            for issue in maintenance_issues
        )
    return quarantine


def assert_no_active_staging_name(root: Path) -> None:
    assert not [entry for entry in _outbox_objects(root) if entry.name.startswith(".staging-")]


def test_quarantine_assertion_rejects_recreated_inode_with_same_bytes_and_metadata(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "identity-helper"
    directory.mkdir(mode=0o700)
    active = directory / "active-object"
    active.write_bytes(b"same bytes")
    os.chmod(active, 0o400)
    expected = _capture_path_identity(active)
    active.rename(directory / ".retained-original")
    replacement = directory / ".artifact-cleanup-quarantine-replacement"
    replacement.write_bytes(b"same bytes")
    os.chmod(replacement, 0o400)

    with pytest.raises(AssertionError):
        assert_logically_quarantined(
            directory,
            ".artifact-cleanup-quarantine-",
            active_name=active.name,
            expected_identity=expected,
            expected_content=b"same bytes",
        )


def _prune_event_stages(stager: SQLiteArtifactStager) -> list[str]:
    stages: list[str] = []
    for event in stager.prune_intent_root.iterdir():
        if event.name.startswith("prune-"):
            stages.append(str(json.loads(event.read_text(encoding="utf-8"))["stage"]))
    return stages


def _prune_active_records(stager: SQLiteArtifactStager) -> list[Path]:
    return sorted(stager.prune_active_root.glob("active-*.json"))


def _retired_prune_active_records(stager: SQLiteArtifactStager) -> list[Path]:
    return sorted(stager.prune_retired_root.glob("retired-*.json"))


def _conflicted_prune_active_records(stager: SQLiteArtifactStager) -> list[Path]:
    return sorted(stager.prune_conflicts_root.glob("conflict-*.json"))


def _create_pending_final(
    stager: SQLiteArtifactStager,
    content: bytes,
    *,
    temporary_name: str = ".staging-pending-reconciliation",
    final_name: str = "artifact-pending-reconciliation.pcapng",
) -> tuple[Path, Path]:
    final = stager.outbox_root / final_name
    final.write_bytes(content)
    os.chmod(final, 0o400)
    manifest = {
        **_manifest(),
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    descriptors = stager._open_managed_tree()
    try:
        intent = stager._write_intent(
            descriptors[3],
            task_id=str(TASK_ID),
            temporary_name=temporary_name,
            final_name=final_name,
            manifest=manifest,
        )
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return final, stager.intent_root / intent.name


def _create_confirmed_prune_operation(
    stager: SQLiteArtifactStager,
    store: SQLiteStore,
    *,
    artifact_id: str,
    name: str,
    content: bytes,
) -> tuple[Any, Any, Path, _ExpectedFileIdentity]:
    path = stager.outbox_root / name
    path.write_bytes(content)
    os.chmod(path, 0o400)
    manifest = {
        **_manifest(),
        "artifact_id": artifact_id,
        "idempotency_key": artifact_id,
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    store.ensure_artifact_queued(
        task_id=str(TASK_ID),
        relative_path=f"outbox/{name}",
        media_type="application/x-pcapng",
        payload=manifest,
    )
    row = store.artifact_upload(artifact_id)
    assert row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
    descriptors = stager._open_managed_tree()
    try:
        control = stager._new_reconciliation_control()
        identity = stager._validate_named_artifact(
            descriptors[2],
            name,
            expected_size=len(content),
            expected_sha256=hashlib.sha256(content).hexdigest(),
            control=control,
        )
        operation, plan = stager._new_prune_operation(row, identity, manifest)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return operation, plan, path, _capture_path_identity(path)


def _prepare_prune_crash_stage(
    stager: SQLiteArtifactStager,
    operation: Any,
    plan: Any,
    *,
    quarantined: bool,
) -> None:
    descriptors = stager._open_managed_tree()
    prune_descriptor = stager._open_prune_intent_directory(descriptors[2])
    active_descriptor = stager._open_prune_active_directory(descriptors[2])
    control = stager._new_reconciliation_control()
    active = None
    events: list[Any] = []
    primary_error: BaseException | None = None
    try:
        active = stager._create_prune_active(
            active_descriptor,
            operation,
            control=control,
        )
        stager._append_planned_prune_event(
            control,
            prune_descriptor,
            active,
            artifacts_module._PruneStage.PREPARED,
            events,
        )
        if quarantined:
            identity = operation.identity(descriptors[2], operation.original_name)
            result = artifacts_module.logical_quarantine(
                identity,
                quarantine_prefix=artifacts_module.ARTIFACT_PRUNE_QUARANTINE_PREFIX,
                plan=plan,
            )
            assert result.logical_deletion_confirmed
            stager._append_planned_prune_event(
                control,
                prune_descriptor,
                active,
                artifacts_module._PruneStage.QUARANTINED,
                events,
            )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        stager._close_prune_events(events, primary_error=primary_error)
        stager._close_prune_active(active, primary_error=primary_error)
        os.close(active_descriptor)
        os.close(prune_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _prepare_prune_active_without_event(
    stager: SQLiteArtifactStager,
    operation: Any,
) -> None:
    descriptors = stager._open_managed_tree()
    active_descriptor = stager._open_prune_active_directory(descriptors[2])
    active = None
    primary_error: BaseException | None = None
    try:
        active = stager._create_prune_active(
            active_descriptor,
            operation,
            control=stager._new_reconciliation_control(),
        )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        stager._close_prune_active(active, primary_error=primary_error)
        os.close(active_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _seed_completed_prune_history(
    stager: SQLiteArtifactStager,
    template: Any,
    *,
    operation_count: int,
) -> None:
    for index in range(operation_count):
        operation = replace(template, operation_id=f"{index + 1:032x}")
        for stage in (
            artifacts_module._PruneStage.PREPARED,
            artifacts_module._PruneStage.QUARANTINED,
            artifacts_module._PruneStage.SQLITE_UPDATED,
        ):
            name = f"prune-{operation.operation_id}-{stage.value.lower()}-" f"{index + 1:032x}.json"
            payload = stager._prune_event_payload(operation, stage)
            path = stager.prune_intent_root / name
            path.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            os.chmod(path, 0o600)
    descriptor = os.open(
        stager.prune_intent_root,
        os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0)),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@pytest.mark.asyncio
async def test_stager_queues_private_stable_copy_with_matching_hash_and_size(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    original = b"stable capture bytes"
    source = _source(root, original)
    staged = await SQLiteArtifactStager(store, root).stage(
        _manifest(),
        source,
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )

    row = store.pending_outbox("pending_uploads")[0]
    assert staged.path.parent == root / "outbox"
    assert Path(str(row["relative_path"])) == Path("outbox") / staged.path.name
    assert str(row["relative_path"]) != source.name
    assert staged.path.read_bytes() == original
    assert row["size_bytes"] == len(original) == staged.manifest["size_bytes"]
    expected_hash = hashlib.sha256(original).hexdigest()
    assert row["sha256"] == expected_hash == staged.manifest["sha256"]
    assert json.loads(str(row["payload"])) == staged.manifest
    assert staged.path.stat().st_mode & 0o077 == 0
    assert staged.path.stat().st_mode & 0o777 == 0o400
    assert staged.path.stat().st_nlink == 1
    assert staged.path.parent.stat().st_mode & 0o777 == 0o700

    source.write_bytes(b"mutated after staging")
    source.unlink()
    assert staged.path.read_bytes() == original
    with store.connection() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


@pytest.mark.asyncio
async def test_descriptor_staging_copies_validated_inode_after_source_name_replacement(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    original = b"descriptor-stable-capture"
    source = _source(root, original)
    directory_descriptor = os.open(
        root,
        os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0)),
    )
    source_descriptor = os.open(
        source.name,
        os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0)),
        dir_fd=directory_descriptor,
    )
    identity = capture_file_identity(
        directory_descriptor,
        source.name,
        source_descriptor,
        expected_uid=os.geteuid(),
        expected_mode=0o600,
    )
    retained = root / "retained-original.pcapng"
    os.rename(source, retained)
    source.write_bytes(b"replacement-path-content")
    os.chmod(source, 0o600)
    assert os.fstat(source_descriptor).st_nlink == 1

    try:
        staged = await SQLiteArtifactStager(store, root).stage_from_descriptor(
            _manifest(),
            source_descriptor,
            identity,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    finally:
        os.close(source_descriptor)
        os.close(directory_descriptor)

    assert staged.path.read_bytes() == original
    assert source.read_bytes() == b"replacement-path-content"
    assert retained.read_bytes() == original
    assert staged.manifest["sha256"] == hashlib.sha256(original).hexdigest()


@pytest.mark.asyncio
async def test_descriptor_staging_rejects_an_unlinked_source_inode(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, b"unlinked-capture")
    directory_descriptor = os.open(
        root,
        os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0)),
    )
    source_descriptor = os.open(
        source.name,
        os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0)),
        dir_fd=directory_descriptor,
    )
    identity = capture_file_identity(
        directory_descriptor,
        source.name,
        source_descriptor,
        expected_uid=os.geteuid(),
        expected_mode=0o600,
    )
    source.unlink()
    assert os.fstat(source_descriptor).st_nlink == 0

    try:
        with pytest.raises(PermissionError, match="exactly one hard link"):
            await SQLiteArtifactStager(store, root).stage_from_descriptor(
                _manifest(),
                source_descriptor,
                identity,
                TASK_ID,
                maximum_size_bytes=4096,
                cancellation=CancellationToken(),
            )
    finally:
        os.close(source_descriptor)
        os.close(directory_descriptor)


@pytest.mark.asyncio
async def test_source_replaced_after_staging_does_not_change_queued_object(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, b"first inode")
    staged = await SQLiteArtifactStager(store, root).stage(
        _manifest(),
        source,
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    replacement = root / "replacement"
    replacement.write_bytes(b"replacement inode")
    os.chmod(replacement, 0o600)
    os.replace(replacement, source)

    assert staged.path.read_bytes() == b"first inode"


@pytest.mark.asyncio
async def test_stager_rejects_symlink_hardlink_and_oversize(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, b"x" * 128)
    stager = SQLiteArtifactStager(store, root)

    symlink = root / "capture-link.pcapng"
    symlink.symlink_to(source)
    with pytest.raises(ValueError):
        await stager.stage(
            _manifest(),
            symlink,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )

    hardlink = root / "capture-hardlink.pcapng"
    os.link(source, hardlink)
    with pytest.raises(PermissionError, match="hard link"):
        await stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    hardlink.unlink()

    with pytest.raises(RuntimeError, match="size limit"):
        await stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=64,
            cancellation=CancellationToken(),
        )
    assert not store.pending_outbox("pending_uploads")


@pytest.mark.asyncio
async def test_source_metadata_change_during_copy_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, b"a" * 4096)
    cleanup_name: str | None = None
    cleanup_identity: _ExpectedFileIdentity | None = None

    class MutatingStager(SQLiteArtifactStager):
        _chunk_size = 64

        def _after_chunk(self, copied: int) -> None:
            nonlocal cleanup_name, cleanup_identity
            if copied == self._chunk_size:
                temporary = next(
                    entry
                    for entry in self.outbox_root.iterdir()
                    if entry.name.startswith(".staging-")
                )
                cleanup_name = temporary.name
                cleanup_identity = _capture_path_identity(temporary)
                with source.open("r+b") as stream:
                    stream.seek(128)
                    stream.write(b"changed")
                    stream.flush()
                    os.fsync(stream.fileno())

    with pytest.raises(RuntimeError, match="changed during staging"):
        await MutatingStager(store, root).stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=8192,
            cancellation=CancellationToken(),
        )
    assert cleanup_name is not None
    assert cleanup_identity is not None
    assert_no_active_staging_name(root)
    assert_logically_quarantined(
        root / "outbox",
        ".artifact-cleanup-quarantine-",
        active_name=cleanup_name,
        expected_identity=cleanup_identity,
    )
    assert not list((root / "outbox" / "intents").iterdir())
    assert not store.pending_outbox("pending_uploads")


@pytest.mark.asyncio
async def test_collision_never_overwrites_existing_outbox_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root)
    cleanup: dict[str, tuple[str, _ExpectedFileIdentity]] = {}

    class CollisionStager(SQLiteArtifactStager):
        def _before_commit(self, transaction: object) -> None:
            del transaction
            temporary = next(
                entry for entry in self.outbox_root.iterdir() if entry.name.startswith(".staging-")
            )
            intent = next(
                entry for entry in self.intent_root.iterdir() if entry.name.startswith("intent-")
            )
            cleanup["temporary"] = (temporary.name, _capture_path_identity(temporary))
            cleanup["intent"] = (intent.name, _capture_path_identity(intent))
            collision.write_bytes(b"must survive")
            os.chmod(collision, 0o600)

    stager = CollisionStager(store, root)
    collision = stager.outbox_root / "artifact-collision.pcapng"
    names = iter(("temporary", "collision", "intent", "cleanup-temp", "cleanup-intent"))
    monkeypatch.setattr(
        "wto_desktop_agent.application.artifacts.secrets.token_hex",
        lambda _: next(names),
    )

    with pytest.raises(FileExistsError):
        await stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    assert collision.read_bytes() == b"must survive"
    assert not (stager.outbox_root / ".staging-temporary").exists()
    assert_logically_quarantined(
        stager.outbox_root,
        ".artifact-cleanup-quarantine-",
        active_name=cleanup["temporary"][0],
        expected_identity=cleanup["temporary"][1],
        expected_content=b"stable capture bytes",
        maintenance_issues=stager.maintenance_issues,
    )
    assert_logically_quarantined(
        stager.intent_root,
        ".artifact-cleanup-quarantine-",
        active_name=cleanup["intent"][0],
        expected_identity=cleanup["intent"][1],
        maintenance_issues=stager.maintenance_issues,
    )


@pytest.mark.asyncio
async def test_cancellation_removes_partial_temporary_file(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, b"a" * 4096)
    token = CancellationToken()
    cleanup_name: str | None = None
    cleanup_identity: _ExpectedFileIdentity | None = None

    class CancellingStager(SQLiteArtifactStager):
        _chunk_size = 64

        def _after_chunk(self, copied: int) -> None:
            nonlocal cleanup_name, cleanup_identity
            if copied == self._chunk_size:
                temporary = next(
                    entry
                    for entry in self.outbox_root.iterdir()
                    if entry.name.startswith(".staging-")
                )
                cleanup_name = temporary.name
                cleanup_identity = _capture_path_identity(temporary)
                token.cancel()

    stager = CancellingStager(store, root)
    with pytest.raises(asyncio.CancelledError):
        await stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=8192,
            cancellation=token,
        )
    assert cleanup_name is not None
    assert cleanup_identity is not None
    assert_no_active_staging_name(root)
    assert_logically_quarantined(
        root / "outbox",
        ".artifact-cleanup-quarantine-",
        active_name=cleanup_name,
        expected_identity=cleanup_identity,
        maintenance_issues=stager.maintenance_issues,
    )
    assert not list((root / "outbox" / "intents").iterdir())
    assert not store.pending_outbox("pending_uploads")


@pytest.mark.asyncio
async def test_publish_failure_removes_incomplete_temporary(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root)
    cleanup: dict[str, tuple[str, _ExpectedFileIdentity]] = {}

    class FailingPublisher(SQLiteArtifactStager):
        def _before_commit(self, transaction: object) -> None:
            del transaction
            temporary = next(
                entry for entry in self.outbox_root.iterdir() if entry.name.startswith(".staging-")
            )
            intent = next(
                entry for entry in self.intent_root.iterdir() if entry.name.startswith("intent-")
            )
            cleanup["temporary"] = (temporary.name, _capture_path_identity(temporary))
            cleanup["intent"] = (intent.name, _capture_path_identity(intent))

        @staticmethod
        def _publish_without_overwrite(
            temporary: str, final: str, directory_descriptor: int
        ) -> None:
            del temporary, final, directory_descriptor
            raise OSError("synthetic publication failure")

    stager = FailingPublisher(store, root)
    with pytest.raises(OSError, match="synthetic"):
        await stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    assert_no_active_staging_name(root)
    assert_logically_quarantined(
        root / "outbox",
        ".artifact-cleanup-quarantine-",
        active_name=cleanup["temporary"][0],
        expected_identity=cleanup["temporary"][1],
        expected_content=b"stable capture bytes",
        maintenance_issues=stager.maintenance_issues,
    )
    assert_logically_quarantined(
        root / "outbox" / "intents",
        ".artifact-cleanup-quarantine-",
        active_name=cleanup["intent"][0],
        expected_identity=cleanup["intent"][1],
        maintenance_issues=stager.maintenance_issues,
    )


@pytest.mark.asyncio
async def test_missing_renameat2_fails_closed_without_link_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root)
    stager = SQLiteArtifactStager(store, root)
    link_calls: list[tuple[object, ...]] = []

    class MissingRenameAt2:
        pass

    monkeypatch.setattr(
        secure_fs_module.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: MissingRenameAt2(),
    )
    monkeypatch.setattr(
        artifacts_module.os,
        "link",
        lambda *args, **kwargs: link_calls.append((*args, kwargs)),
    )

    with pytest.raises(PluginUnavailableError, match="renameat2") as raised:
        await stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )

    assert link_calls == []
    assert "os.link(" not in inspect.getsource(SQLiteArtifactStager)
    assert (
        len([entry for entry in _outbox_objects(root) if entry.name.startswith(".staging-")]) == 1
    )
    assert len(list(stager.intent_root.iterdir())) == 1
    assert len([note for note in raised.value.__notes__ if "cleanup incomplete" in note]) == 2
    assert not store.pending_outbox("pending_uploads")


@pytest.mark.asyncio
async def test_publication_error_survives_descriptor_close_failure(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root)
    publication_error = RuntimeError("controlled publication error")

    class ClosingFailureStager(SQLiteArtifactStager):
        publication_failed = False
        close_failed = False

        @staticmethod
        def _publish_without_overwrite(
            temporary: str,
            final: str,
            directory_descriptor: int,
        ) -> None:
            del temporary, final, directory_descriptor
            ClosingFailureStager.publication_failed = True
            raise publication_error

        def _close_descriptor(self, descriptor: int) -> None:
            os.close(descriptor)
            if self.publication_failed and not self.close_failed:
                self.close_failed = True
                raise OSError("controlled descriptor close failure")

    with pytest.raises(RuntimeError) as raised:
        await ClosingFailureStager(store, root).stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )

    assert raised.value is publication_error
    assert any("descriptor close" in note for note in raised.value.__notes__)
    assert not store.pending_outbox("pending_uploads")


def test_multiple_close_errors_are_notes_and_each_descriptor_is_closed_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stager = SQLiteArtifactStager(_store(tmp_path), tmp_path / "artifacts")
    calls: list[int] = []

    def fail_close(descriptor: int) -> None:
        calls.append(descriptor)
        raise OSError(f"controlled close failure {descriptor}")

    monkeypatch.setattr(stager, "_close_descriptor", fail_close)
    primary = RuntimeError("primary operation failure")

    stager._close_descriptors((101, 202, 101), primary_error=primary)

    assert calls == [101, 202]
    assert len(primary.__notes__) == 2
    assert all("descriptor close" in note for note in primary.__notes__)


@pytest.mark.asyncio
async def test_outbox_symlink_swap_after_initialization_is_rejected(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root)
    stager = SQLiteArtifactStager(store, root)
    original_outbox = root / "outbox-original"
    stager.outbox_root.rename(original_outbox)
    stager.outbox_root.symlink_to(original_outbox, target_is_directory=True)

    with pytest.raises(OSError):
        await stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    assert not store.pending_outbox("pending_uploads")


@pytest.mark.asyncio
async def test_incomplete_temporary_cleanup_is_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root)

    class FailingPublisher(SQLiteArtifactStager):
        @staticmethod
        def _publish_without_overwrite(
            temporary: str, final: str, directory_descriptor: int
        ) -> None:
            del temporary, final, directory_descriptor
            raise OSError("synthetic publication failure")

    real_quarantine = artifacts_module.logical_quarantine

    def reject_logical_quarantine(
        identity: object,
        *,
        quarantine_prefix: str,
        plan: object | None = None,
        primary_error: BaseException | None = None,
    ) -> object:
        if quarantine_prefix == ".artifact-cleanup-quarantine-":
            raise PermissionError("cleanup denied")
        return real_quarantine(  # type: ignore[arg-type]
            identity,
            quarantine_prefix=quarantine_prefix,
            plan=plan,  # type: ignore[arg-type]
            primary_error=primary_error,
        )

    monkeypatch.setattr(
        artifacts_module,
        "logical_quarantine",
        reject_logical_quarantine,
    )
    with pytest.raises(OSError, match="synthetic") as raised:
        await FailingPublisher(store, root).stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    cleanup_notes = [note for note in raised.value.__notes__ if "cleanup incomplete" in note]
    assert len(cleanup_notes) == 2


def test_intent_identity_failure_closes_descriptor_and_preserves_entry_for_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stager = SQLiteArtifactStager(_store(tmp_path), tmp_path / "artifacts")
    descriptors = stager._open_managed_tree()
    observed_descriptor: list[int] = []

    def fail_identity(
        _dir_fd: int,
        _name: str,
        file_fd: int,
        **_kwargs: object,
    ) -> object:
        observed_descriptor.append(file_fd)
        raise RuntimeError("controlled intent identity failure")

    monkeypatch.setattr(artifacts_module, "capture_file_identity", fail_identity)
    try:
        with pytest.raises(RuntimeError, match="identity failure") as raised:
            stager._write_intent(
                descriptors[3],
                task_id=str(TASK_ID),
                temporary_name=".staging-owned",
                final_name="artifact-owned.pcapng",
                manifest={
                    **_manifest(),
                    "size_bytes": 1,
                    "sha256": "0" * 64,
                },
            )
        assert len(observed_descriptor) == 1
        with pytest.raises(OSError):
            os.fstat(observed_descriptor[0])
        intents = list(stager.intent_root.iterdir())
        assert len(intents) == 1
        assert any("manual recovery" in note for note in raised.value.__notes__)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


@pytest.mark.asyncio
async def test_large_copy_runs_off_event_loop(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, b"a" * 4096)

    class SlowStager(SQLiteArtifactStager):
        _chunk_size = 64

        def _after_chunk(self, copied: int) -> None:
            del copied
            time.sleep(0.002)

    staging = asyncio.create_task(
        SlowStager(store, root).stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=8192,
            cancellation=CancellationToken(),
        )
    )
    ticks = 0
    while not staging.done():
        ticks += 1
        await asyncio.sleep(0.001)
    await staging
    assert ticks >= 10


@pytest.mark.asyncio
async def test_reconciliation_cancellation_stops_before_sqlite_or_deletion(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    entered = threading.Event()
    release = threading.Event()

    class BlockingReconciliationStager(SQLiteArtifactStager):
        _chunk_size = 16

        def _after_reconciliation_chunk(self, control: Any, copied: int) -> None:
            del control, copied
            entered.set()
            release.wait(timeout=5)

    stager = BlockingReconciliationStager(store, root)
    final, intent = _create_pending_final(stager, b"r" * 256)
    source = _source(root, b"new capture")
    task = asyncio.create_task(
        stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    )
    assert await asyncio.to_thread(entered.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert final.exists()
    assert intent.exists()
    assert not store.pending_outbox("pending_uploads")


@pytest.mark.asyncio
async def test_reconciliation_deadline_stops_before_durable_mutation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"

    class SlowReconciliationStager(SQLiteArtifactStager):
        _chunk_size = 16

        def _after_reconciliation_chunk(self, control: Any, copied: int) -> None:
            del control, copied
            time.sleep(0.03)

    stager = SlowReconciliationStager(
        store,
        root,
        reconciliation_timeout_seconds=0.01,
    )
    final, intent = _create_pending_final(stager, b"d" * 256)
    source = _source(root, b"deadline capture")

    with pytest.raises(
        ArtifactReconciliationError,
        match="reconciliation (?:deadline expired|external timeout)",
    ) as raised:
        await stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )

    assert isinstance(raised.value.__cause__, TimeoutError)
    assert final.exists()
    assert intent.exists()
    assert not store.pending_outbox("pending_uploads")
    assert not stager._unfinished_workers
    stager._ensure_available()


@pytest.mark.asyncio
async def test_phase05_schema_one_database_migrates_to_two_and_stages(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    with store.connection() as connection:
        connection.execute("DROP TABLE windows_network_operations")
        connection.execute("DELETE FROM schema_migrations WHERE version=2")
        connection.execute("PRAGMA user_version=1")
    store.initialize()
    root = tmp_path / "artifacts"
    source = _source(root)

    staged = await SQLiteArtifactStager(store, root).stage(
        _manifest(),
        source,
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )

    assert staged.path.is_file()
    assert len(store.pending_outbox("pending_uploads")) == 1
    with store.connection() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


@pytest.mark.asyncio
async def test_task_cancellation_before_commit_is_transactional(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, b"cancel before commit")
    entered = threading.Event()
    release = threading.Event()
    cleanup: dict[str, tuple[str, _ExpectedFileIdentity]] = {}

    class BlockingCommitStager(SQLiteArtifactStager):
        def _before_commit(self, transaction: object) -> None:
            del transaction
            temporary = next(
                entry for entry in self.outbox_root.iterdir() if entry.name.startswith(".staging-")
            )
            intent = next(
                entry for entry in self.intent_root.iterdir() if entry.name.startswith("intent-")
            )
            cleanup["temporary"] = (temporary.name, _capture_path_identity(temporary))
            cleanup["intent"] = (intent.name, _capture_path_identity(intent))
            entered.set()
            release.wait(timeout=5)

    stager = BlockingCommitStager(store, root)
    task = asyncio.create_task(
        stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    )
    assert await asyncio.to_thread(entered.wait, 5)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert not store.pending_outbox("pending_uploads")
    assert_no_active_staging_name(root)
    assert_logically_quarantined(
        root / "outbox",
        ".artifact-cleanup-quarantine-",
        active_name=cleanup["temporary"][0],
        expected_identity=cleanup["temporary"][1],
        expected_content=b"cancel before commit",
        maintenance_issues=stager.maintenance_issues,
    )
    assert_logically_quarantined(
        root / "outbox" / "intents",
        ".artifact-cleanup-quarantine-",
        active_name=cleanup["intent"][0],
        expected_identity=cleanup["intent"][1],
        maintenance_issues=stager.maintenance_issues,
    )


@pytest.mark.asyncio
async def test_cancellation_after_commit_claim_returns_confirmed_result(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, b"commit wins cancellation")
    entered = threading.Event()
    release = threading.Event()
    intent_identity: tuple[str, _ExpectedFileIdentity] | None = None

    class BlockingPublishedStager(SQLiteArtifactStager):
        def _after_publish(self, intent: Any) -> None:
            nonlocal intent_identity
            name = str(intent.name)
            path = self.intent_root / name
            intent_identity = (name, _capture_path_identity(path))
            entered.set()
            release.wait(timeout=5)

    stager = BlockingPublishedStager(store, root)
    task = asyncio.create_task(
        stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    )
    assert await asyncio.to_thread(entered.wait, 5)
    task.cancel()
    release.set()
    staged = await task

    assert staged.path.is_file()
    assert not task.cancelled()
    assert len(store.pending_outbox("pending_uploads")) == 1
    assert intent_identity is not None
    assert_logically_quarantined(
        root / "outbox" / "intents",
        ".artifact-intent-quarantine-",
        active_name=intent_identity[0],
        expected_identity=intent_identity[1],
        maintenance_issues=stager.maintenance_issues,
    )


@pytest.mark.asyncio
async def test_cancellation_after_publish_failure_reconciles_before_return(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, b"commit recovery wins cancellation")
    entered = threading.Event()
    release = threading.Event()
    intent_identity: tuple[str, _ExpectedFileIdentity] | None = None

    class FailingPublishedStager(SQLiteArtifactStager):
        def _after_publish(self, intent: Any) -> None:
            nonlocal intent_identity
            name = str(intent.name)
            path = self.intent_root / name
            intent_identity = (name, _capture_path_identity(path))
            entered.set()
            release.wait(timeout=5)
            raise RuntimeError("simulated post-publication failure")

    stager = FailingPublishedStager(store, root)
    task = asyncio.create_task(
        stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    )
    assert await asyncio.to_thread(entered.wait, 5)
    task.cancel()
    release.set()
    staged = await task

    assert staged.path.read_bytes() == b"commit recovery wins cancellation"
    assert not task.cancelled()
    assert len(store.pending_outbox("pending_uploads")) == 1
    assert intent_identity is not None
    assert_logically_quarantined(
        root / "outbox" / "intents",
        ".artifact-intent-quarantine-",
        active_name=intent_identity[0],
        expected_identity=intent_identity[1],
        maintenance_issues=stager.maintenance_issues,
    )


@pytest.mark.asyncio
async def test_crash_after_publication_is_reconciled_into_sqlite(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, b"recover published bytes")

    class CrashAfterPublish(SQLiteArtifactStager):
        def _after_publish(self, intent: object) -> None:
            del intent
            raise RuntimeError("simulated crash after publish")

    with pytest.raises(RuntimeError, match="simulated crash"):
        await CrashAfterPublish(store, root).stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    assert not store.pending_outbox("pending_uploads")
    assert len(_outbox_objects(root)) == 1
    intent = next((root / "outbox" / "intents").iterdir())
    intent_identity = _capture_path_identity(intent)

    recovered = SQLiteArtifactStager(store, root)
    rows = store.pending_outbox("pending_uploads")
    assert len(rows) == 1
    assert_logically_quarantined(
        recovered.intent_root,
        ".artifact-intent-quarantine-",
        active_name=intent.name,
        expected_identity=intent_identity,
        maintenance_issues=recovered.maintenance_issues,
    )
    validated = await recovered.validate_for_upload(str(ARTIFACT_ID))
    assert validated.read_bytes() == b"recover published bytes"


@pytest.mark.asyncio
async def test_crash_after_sqlite_insert_removes_intent_without_duplicate(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, b"row already durable")

    class CrashAfterQueue(SQLiteArtifactStager):
        def _after_queue(self, intent: object) -> None:
            del intent
            raise RuntimeError("simulated crash after queue")

    with pytest.raises(RuntimeError, match="simulated crash"):
        await CrashAfterQueue(store, root).stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    assert len(store.pending_outbox("pending_uploads")) == 1
    intent = next((root / "outbox" / "intents").iterdir())
    intent_identity = _capture_path_identity(intent)

    recovered = SQLiteArtifactStager(store, root)
    assert len(store.pending_outbox("pending_uploads")) == 1
    assert_logically_quarantined(
        recovered.intent_root,
        ".artifact-intent-quarantine-",
        active_name=intent.name,
        expected_identity=intent_identity,
        maintenance_issues=recovered.maintenance_issues,
    )


@pytest.mark.asyncio
async def test_future_upload_validation_detects_mutation_and_hardlink(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, b"immutable queued bytes")
    stager = SQLiteArtifactStager(store, root)
    staged = await stager.stage(
        _manifest(),
        source,
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    assert await stager.validate_for_upload(str(ARTIFACT_ID)) == staged.path

    os.chmod(staged.path, 0o600)
    staged.path.write_bytes(b"mutated queued bytes")
    os.chmod(staged.path, 0o400)
    with pytest.raises(RuntimeError, match="integrity|size"):
        await stager.validate_for_upload(str(ARTIFACT_ID))

    staged.path.unlink()
    staged.path.write_bytes(b"immutable queued bytes")
    os.chmod(staged.path, 0o400)
    hardlink = root / "queued-hardlink"
    os.link(staged.path, hardlink)
    with pytest.raises(PermissionError, match="hard link"):
        await stager.validate_for_upload(str(ARTIFACT_ID))


def test_artifact_root_and_managed_ancestors_reject_symlinks(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="must be absolute"):
        SQLiteArtifactStager(
            store,
            Path("relative-artifacts"),
            trusted_root=Path("relative-root"),
        )
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    root_link = tmp_path / "root-link"
    root_link.symlink_to(real, target_is_directory=True)
    with pytest.raises(OSError):
        SQLiteArtifactStager(store, root_link, trusted_root=tmp_path)

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    intermediate = state / "intermediate"
    intermediate.symlink_to(external, target_is_directory=True)
    with pytest.raises(OSError):
        SQLiteArtifactStager(
            store,
            intermediate / "artifacts",
            trusted_root=state,
        )


@pytest.mark.parametrize("linked_name", ["outbox", "intents"])
def test_outbox_and_intent_directory_reject_preexisting_symlink(
    tmp_path: Path,
    linked_name: str,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    target = tmp_path / f"real-{linked_name}"
    target.mkdir(mode=0o700)
    if linked_name == "outbox":
        (root / "outbox").symlink_to(target, target_is_directory=True)
    else:
        outbox = root / "outbox"
        outbox.mkdir(mode=0o700)
        (outbox / "intents").symlink_to(target, target_is_directory=True)
    with pytest.raises(OSError):
        SQLiteArtifactStager(store, root, trusted_root=tmp_path)


def test_untracked_final_is_reported_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    orphan = stager.outbox_root / "artifact-orphan.pcapng"
    orphan.write_bytes(b"untracked")
    os.chmod(orphan, 0o400)

    with pytest.raises(ArtifactReconciliationError, match="untracked_outbox_entry"):
        stager._reconcile_sync(stager._new_reconciliation_control())
    assert orphan.exists()


def test_reconciliation_removes_valid_uncommitted_temporary(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    content = b"durable temporary"
    temporary_name = ".staging-recovery"
    temporary = stager.outbox_root / temporary_name
    temporary.write_bytes(content)
    os.chmod(temporary, 0o400)
    manifest = {
        **_manifest(),
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    descriptors = stager._open_managed_tree()
    try:
        intent = stager._write_intent(
            descriptors[3],
            task_id=str(TASK_ID),
            temporary_name=temporary_name,
            final_name="artifact-never-published.pcapng",
            manifest=manifest,
        )
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    temporary_identity = _capture_path_identity(temporary)
    intent_path = stager.intent_root / intent.name
    intent_identity = _capture_path_identity(intent_path)

    recovered = SQLiteArtifactStager(store, root)
    assert not temporary.exists()
    assert_logically_quarantined(
        recovered.outbox_root,
        ".artifact-reconcile-quarantine-",
        active_name=temporary_name,
        expected_identity=temporary_identity,
        expected_content=content,
        maintenance_issues=recovered.maintenance_issues,
    )
    assert_logically_quarantined(
        recovered.intent_root,
        ".artifact-intent-quarantine-",
        active_name=intent.name,
        expected_identity=intent_identity,
        maintenance_issues=recovered.maintenance_issues,
    )
    assert not store.pending_outbox("pending_uploads")


def test_reconciliation_reports_inherited_link_unlink_pair_for_manual_recovery(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    content = b"legacy hardlink publication pair"
    final_name = "artifact-legacy-hardlink.pcapng"
    temporary_name = ".staging-legacy-hardlink"
    final = stager.outbox_root / final_name
    temporary = stager.outbox_root / temporary_name
    final.write_bytes(content)
    os.chmod(final, 0o400)
    os.link(final, temporary)
    manifest = {
        **_manifest(),
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    descriptors = stager._open_managed_tree()
    try:
        stager._write_intent(
            descriptors[3],
            task_id=str(TASK_ID),
            temporary_name=temporary_name,
            final_name=final_name,
            manifest=manifest,
        )
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

    with pytest.raises(ArtifactReconciliationError, match="PermissionError"):
        SQLiteArtifactStager(store, root)

    assert final.exists()
    assert temporary.exists()
    assert final.stat().st_nlink == 2
    assert not store.pending_outbox("pending_uploads")


@pytest.mark.asyncio
async def test_reconciliation_reports_sqlite_row_without_final(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    source = _source(root, b"row loses final")
    staged = await stager.stage(
        _manifest(),
        source,
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    staged.path.unlink()

    with pytest.raises(ArtifactReconciliationError, match="sqlite_artifact_missing"):
        SQLiteArtifactStager(store, root)


@pytest.mark.asyncio
async def test_idempotent_retry_ignores_new_created_at_and_returns_persisted_manifest(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root)
    stager = SQLiteArtifactStager(store, root)
    first = await stager.stage(
        _manifest(),
        source,
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    retry_manifest = {**_manifest(), "created_at": "2026-07-14T13:00:00Z"}

    second = await stager.stage(
        retry_manifest,
        source,
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )

    assert second == first
    assert second.manifest["created_at"] == "2026-07-14T12:00:00Z"
    assert len(store.rows("pending_uploads")) == 1
    with pytest.raises(RuntimeError, match="media_type"):
        await stager.find_existing(
            {**retry_manifest, "media_type": "application/octet-stream"},
            TASK_ID,
            cancellation=CancellationToken(),
        )


@pytest.mark.asyncio
async def test_pre_cancelled_reconciliation_performs_no_durable_mutation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root)
    stager = SQLiteArtifactStager(store, root)
    token = CancellationToken()
    token.cancel()

    with pytest.raises(asyncio.CancelledError):
        await stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=token,
        )

    assert not store.rows("pending_uploads")
    assert not _outbox_objects(root)
    assert not list(stager.intent_root.iterdir())


@pytest.mark.asyncio
async def test_external_reconciliation_timeout_poisons_noncooperative_stager(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root)
    entered = threading.Event()
    release = threading.Event()

    class NonCooperativeStager(SQLiteArtifactStager):
        def _reconcile_and_find_existing(
            self,
            supplied_manifest: dict[str, object],
            task_id: str,
            stop: threading.Event,
            deadline: float,
        ) -> object:
            entered.set()
            release.wait(timeout=2)
            return super()._reconcile_and_find_existing(supplied_manifest, task_id, stop, deadline)

    stager = NonCooperativeStager(
        store,
        root,
        reconciliation_timeout_seconds=0.02,
        reconciliation_cleanup_timeout_seconds=0.01,
    )
    started = time.monotonic()
    with pytest.raises(ArtifactReconciliationError, match="unavailable"):
        await stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    assert time.monotonic() - started < 0.5
    assert entered.is_set()
    with pytest.raises(ArtifactReconciliationError, match="grace period"):
        await stager.stage(
            _manifest(),
            source,
            TASK_ID,
            maximum_size_bytes=4096,
            cancellation=CancellationToken(),
        )
    assert not store.rows("pending_uploads")
    assert not _outbox_objects(root)
    assert not list(stager.intent_root.iterdir())
    release.set()
    await asyncio.sleep(0.05)
    assert not store.rows("pending_uploads")


def test_confirmed_rows_over_four_gib_do_not_block_startup(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    del stager
    for index in range(42):
        artifact_id = f"30000000-0000-4000-8000-{index:012d}"
        payload = {
            **_manifest(),
            "artifact_id": artifact_id,
            "idempotency_key": artifact_id,
            "size_bytes": 104_857_600,
            "sha256": "0" * 64,
        }
        store.ensure_artifact_queued(
            task_id=str(TASK_ID),
            relative_path=f"outbox/artifact-{index}.pcapng",
            media_type="application/x-pcapng",
            payload=payload,
        )
        row = store.artifact_upload(artifact_id)
        assert row is not None
        store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))

    recovered = SQLiteArtifactStager(store, root)

    assert recovered.outbox_root.is_dir()
    assert len(store.rows("pending_uploads")) == 42


def test_confirmed_pruning_selection_is_bounded_by_age_count_and_bytes(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    identifiers: list[str] = []
    for index, confirmed_at in enumerate(
        (
            "2026-07-01T00:00:00+00:00",
            "2026-07-10T00:00:00+00:00",
            "2026-07-14T00:00:00+00:00",
        )
    ):
        artifact_id = f"30000000-0000-4000-8000-{index + 200:012d}"
        identifiers.append(artifact_id)
        store.ensure_artifact_queued(
            task_id=str(TASK_ID),
            relative_path=f"outbox/retention-{index}.pcapng",
            media_type="application/x-pcapng",
            payload={
                **_manifest(),
                "artifact_id": artifact_id,
                "idempotency_key": artifact_id,
                "size_bytes": 10,
                "sha256": "0" * 64,
            },
        )
        row = store.artifact_upload(artifact_id)
        assert row is not None
        store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
        with store.connection() as connection:
            connection.execute(
                "UPDATE pending_uploads SET confirmed_at=? WHERE artifact_id=?",
                (confirmed_at, artifact_id),
            )

    by_age = store.confirmed_artifacts_for_pruning(
        confirmed_before="2026-07-05T00:00:00+00:00",
        retain_count=None,
        retain_bytes=None,
        limit=10,
    )
    by_count = store.confirmed_artifacts_for_pruning(
        confirmed_before=None,
        retain_count=1,
        retain_bytes=None,
        limit=10,
    )
    by_bytes = store.confirmed_artifacts_for_pruning(
        confirmed_before=None,
        retain_count=None,
        retain_bytes=15,
        limit=10,
    )

    assert [row["artifact_id"] for row in by_age] == identifiers[:1]
    assert {row["artifact_id"] for row in by_count} == set(identifiers[:2])
    assert {row["artifact_id"] for row in by_bytes} == set(identifiers[:2])


@pytest.mark.asyncio
async def test_pruning_logically_quarantines_confirmed_artifact_without_reclaiming_bytes(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root)
    stager = SQLiteArtifactStager(store, root)
    staged = await stager.stage(
        _manifest(),
        source,
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    confirmed = store.artifact_upload(str(ARTIFACT_ID))
    assert confirmed is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(confirmed["upload_id"]))
    original_identity = _capture_path_identity(staged.path)
    pending_id = "30000000-0000-4000-8000-000000000099"
    store.ensure_artifact_queued(
        task_id=str(TASK_ID),
        relative_path="outbox/pending-must-remain.pcapng",
        media_type="application/x-pcapng",
        payload={
            **_manifest(),
            "artifact_id": pending_id,
            "idempotency_key": pending_id,
            "size_bytes": 1,
            "sha256": "0" * 64,
        },
    )
    first = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )
    assert first.files_deleted == 0
    assert first.rows_deleted == 0
    assert first.bytes_deleted == 0
    assert not staged.path.exists(), first
    assert store.artifact_upload(pending_id) is not None
    retained = store.artifact_upload(str(ARTIFACT_ID))
    assert retained is not None
    retained_path = Path(str(retained["relative_path"]))
    assert retained_path.name.startswith(".artifact-prune-quarantine-")
    quarantine = assert_logically_quarantined(
        stager.outbox_root,
        ".artifact-prune-quarantine-",
        active_name=staged.path.name,
        expected_identity=original_identity,
        expected_content=b"stable capture bytes",
        maintenance_issues=first.issues,
    )
    assert set(_prune_event_stages(stager)) == {
        "PREPARED",
        "QUARANTINED",
        "SQLITE_UPDATED",
    }
    assert _prune_active_records(stager) == []
    assert len(_retired_prune_active_records(stager)) == 1

    second = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )
    assert second.selected == 0
    assert second.files_deleted == 0
    assert second.rows_deleted == 0
    assert second.bytes_deleted == 0
    assert store.artifact_upload(str(ARTIFACT_ID)) is not None
    assert store.artifact_upload(pending_id) is not None
    assert quarantine.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name",
    [
        relative_path.removeprefix("outbox/")
        for _label, relative_path, expected in ARTIFACT_PRUNE_QUARANTINE_VECTORS
        if not expected
        and "\x00" not in relative_path
        and "/" not in relative_path.removeprefix("outbox/")
        and not relative_path.startswith(("/", "./", "../"))
    ],
)
async def test_retain_zero_prunes_every_noncanonical_quarantine_name(
    tmp_path: Path,
    name: str,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    operation = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000509",
        name=name,
        content=b"noncanonical quarantine-like artifact",
    )
    stager._reconcile_sync(stager._new_reconciliation_control())
    assert not any(
        name in issue and "physical_delete_pending" in issue for issue in stager.maintenance_issues
    )

    report = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )

    row = store.artifact_upload(operation[0].artifact_id)
    assert row is not None
    assert is_artifact_prune_quarantine_path(str(row["relative_path"]))
    assert not operation[2].exists()
    assert report.selected == 1
    assert len(_quarantines(stager.outbox_root, ".artifact-prune-quarantine-")) == 1


@pytest.mark.asyncio
async def test_nul_corrupt_confirmed_row_is_not_treated_as_quarantine(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    artifact_id = "30000000-0000-4000-8000-000000000507"
    operation, _plan, original, _identity = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id=artifact_id,
        name="artifact-corrupt-nul-row.pcapng",
        content=b"corrupt NUL row still has a real artifact",
    )
    corrupt = operation.quarantine_relative_path + "\x00suffix"
    with store.connection() as connection:
        connection.execute(
            "UPDATE pending_uploads SET relative_path=? WHERE artifact_id=?",
            (corrupt, artifact_id),
        )

    with pytest.raises(ArtifactReconciliationError, match="unsafe_sqlite_path"):
        stager._reconcile_sync(stager._new_reconciliation_control())
    report = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )

    assert report.selected == 1
    assert any("unsafe_sqlite_path" in issue for issue in report.issues)
    assert original.exists()
    assert not any(
        "physical_delete_pending" in issue and operation.quarantine_name in issue
        for issue in stager.maintenance_issues
    )


@pytest.mark.asyncio
async def test_sqlite_updated_with_active_remaining_retires_active_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    staged = await stager.stage(
        _manifest(),
        _source(root, b"active remains after sqlite event"),
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    row = store.artifact_upload(str(ARTIFACT_ID))
    assert row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
    real_rename_noreplace = artifacts_module.rename_noreplace

    def fail_only_active_retirement(
        source_dir_fd: int,
        source_name: str,
        destination_dir_fd: int,
        destination_name: str,
    ) -> None:
        if source_name.startswith("active-") and destination_name.startswith("retired-"):
            raise RuntimeError("controlled active retirement crash")
        real_rename_noreplace(
            source_dir_fd,
            source_name,
            destination_dir_fd,
            destination_name,
        )

    monkeypatch.setattr(
        artifacts_module,
        "rename_noreplace",
        fail_only_active_retirement,
    )
    report = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )
    assert report.issues
    assert not staged.path.exists()
    assert set(_prune_event_stages(stager)) == {
        "PREPARED",
        "QUARANTINED",
        "SQLITE_UPDATED",
    }
    assert len(_prune_active_records(stager)) == 1
    historical_names = {event.name for event in stager.prune_intent_root.iterdir()}

    monkeypatch.setattr(
        artifacts_module,
        "rename_noreplace",
        real_rename_noreplace,
    )
    recovered = SQLiteArtifactStager(store, root)

    assert _prune_active_records(recovered) == []
    assert len(_retired_prune_active_records(recovered)) == 1
    assert {event.name for event in recovered.prune_intent_root.iterdir()} == historical_names
    recovered_row = store.artifact_upload(str(ARTIFACT_ID))
    assert recovered_row is not None
    assert str(recovered_row["relative_path"]).startswith("outbox/.artifact-prune-quarantine-")


def test_startup_never_scans_thousands_of_retired_records_before_one_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    operation, plan, _path, _identity = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000508",
        name="artifact-after-retired-history.pcapng",
        content=b"new active after retired history",
    )
    _prepare_prune_crash_stage(stager, operation, plan, quarantined=False)
    for index in range(2_048):
        retired = stager.prune_retired_root / f"retired-{index:032x}.json"
        retired.write_bytes(b"retired")
        os.chmod(retired, 0o600)
        conflict = stager.prune_conflicts_root / f"conflict-{index:032x}-{'a' * 64}.json"
        conflict.write_bytes(b"conflict")
        os.chmod(conflict, 0o600)

    retired_metadata = stager.prune_retired_root.stat()
    conflicts_metadata = stager.prune_conflicts_root.stat()
    real_scandir = artifacts_module.os.scandir

    def reject_retired_scan(path: int | str | os.PathLike[str]) -> Any:
        if isinstance(path, int):
            metadata = os.fstat(path)
            if (metadata.st_dev, metadata.st_ino) in {
                (retired_metadata.st_dev, retired_metadata.st_ino),
                (conflicts_metadata.st_dev, conflicts_metadata.st_ino),
            }:
                raise AssertionError("prune terminal history must not be enumerated")
        return real_scandir(path)

    monkeypatch.setattr(artifacts_module.os, "scandir", reject_retired_scan)
    recovered = SQLiteArtifactStager(
        store,
        root,
        reconciliation_timeout_seconds=1.0,
        reconciliation_maximum_entries=32,
    )

    row = store.artifact_upload(operation.artifact_id)
    assert row is not None
    assert row["relative_path"] == operation.quarantine_relative_path
    assert _prune_active_records(recovered) == []
    assert len(_retired_prune_active_records(recovered)) == 2_049
    assert len(_conflicted_prune_active_records(recovered)) == 2_048


def test_noncanonical_name_inside_active_requires_manual_recovery(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    invalid = stager.prune_active_root / f"retired-{'a' * 32}.json"
    invalid.write_bytes(b"not an active record")
    os.chmod(invalid, 0o600)

    recovered = SQLiteArtifactStager(store, root)

    assert invalid.exists()
    assert any(
        f"prune_active:{invalid.name}:manual_recovery_required:invalid_name" == issue
        for issue in recovered.maintenance_issues
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_directory", ["active", "retired", "both"])
async def test_retirement_fsync_failure_after_rename_stays_outside_active_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_directory: str,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    staged = await stager.stage(
        _manifest(),
        _source(root, b"retirement fsync crash"),
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    row = store.artifact_upload(str(ARTIFACT_ID))
    assert row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
    active_identity = stager.prune_active_root.stat()
    retired_identity = stager.prune_retired_root.stat()
    directory_syncs = {"active": 0, "retired": 0}
    real_fsync = artifacts_module.os.fsync
    real_rename_noreplace = artifacts_module.rename_noreplace
    failed: set[str] = set()
    retirement_renamed = False

    def observe_retirement_rename(
        source_dir_fd: int,
        source_name: str,
        destination_dir_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal retirement_renamed
        real_rename_noreplace(
            source_dir_fd,
            source_name,
            destination_dir_fd,
            destination_name,
        )
        if source_name.startswith("active-") and destination_name.startswith("retired-"):
            retirement_renamed = True

    def fail_target_directory_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        current_directory: str | None = None
        if retirement_renamed:
            if (metadata.st_dev, metadata.st_ino) == (
                active_identity.st_dev,
                active_identity.st_ino,
            ):
                current_directory = "active"
                directory_syncs["active"] += 1
            elif (metadata.st_dev, metadata.st_ino) == (
                retired_identity.st_dev,
                retired_identity.st_ino,
            ):
                current_directory = "retired"
                directory_syncs["retired"] += 1
        if (
            retirement_renamed
            and current_directory is not None
            and current_directory not in failed
            and failed_directory in {current_directory, "both"}
        ):
            failed.add(current_directory)
            raise OSError("controlled retirement directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(
        artifacts_module,
        "rename_noreplace",
        observe_retirement_rename,
    )
    monkeypatch.setattr(artifacts_module.os, "fsync", fail_target_directory_fsync)
    report = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )

    expected_failures = {"active", "retired"} if failed_directory == "both" else {failed_directory}
    assert failed == expected_failures
    assert directory_syncs == {"active": 1, "retired": 1}
    assert report.issues
    assert not staged.path.exists()
    assert _prune_active_records(stager) == []
    assert len(_retired_prune_active_records(stager)) == 1

    monkeypatch.setattr(artifacts_module.os, "fsync", real_fsync)
    recovered = SQLiteArtifactStager(store, root)
    assert _prune_active_records(recovered) == []
    assert len(_retired_prune_active_records(recovered)) == 1


@pytest.mark.asyncio
async def test_retirement_validation_failure_still_fsyncs_both_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    await stager.stage(
        _manifest(),
        _source(root, b"retirement validation failure"),
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    row = store.artifact_upload(str(ARTIFACT_ID))
    assert row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
    active_identity = stager.prune_active_root.stat()
    retired_identity = stager.prune_retired_root.stat()
    directory_syncs = {"active": 0, "retired": 0}
    retirement_renamed = False
    real_rename_noreplace = artifacts_module.rename_noreplace
    real_capture_identity = artifacts_module.capture_file_identity
    real_fsync = artifacts_module.os.fsync

    def observe_retirement_rename(
        source_dir_fd: int,
        source_name: str,
        destination_dir_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal retirement_renamed
        real_rename_noreplace(
            source_dir_fd,
            source_name,
            destination_dir_fd,
            destination_name,
        )
        if source_name.startswith("active-") and destination_name.startswith("retired-"):
            retirement_renamed = True

    def fail_retired_identity(
        directory_descriptor: int,
        relative_name: str,
        descriptor: int,
        *,
        expected_uid: int,
        expected_mode: int,
    ) -> Any:
        if retirement_renamed and relative_name.startswith("retired-"):
            raise RuntimeError("controlled post-rename validation failure")
        return real_capture_identity(
            directory_descriptor,
            relative_name,
            descriptor,
            expected_uid=expected_uid,
            expected_mode=expected_mode,
        )

    def count_directory_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if retirement_renamed:
            if (metadata.st_dev, metadata.st_ino) == (
                active_identity.st_dev,
                active_identity.st_ino,
            ):
                directory_syncs["active"] += 1
            elif (metadata.st_dev, metadata.st_ino) == (
                retired_identity.st_dev,
                retired_identity.st_ino,
            ):
                directory_syncs["retired"] += 1
        real_fsync(descriptor)

    monkeypatch.setattr(artifacts_module, "rename_noreplace", observe_retirement_rename)
    monkeypatch.setattr(artifacts_module, "capture_file_identity", fail_retired_identity)
    monkeypatch.setattr(artifacts_module.os, "fsync", count_directory_fsync)

    report = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )

    assert directory_syncs == {"active": 1, "retired": 1}
    assert any("retirement_durability_indeterminate" in issue for issue in report.issues)
    assert _prune_active_records(stager) == []
    assert len(_retired_prune_active_records(stager)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("conflict_kind", ["regular", "symlink", "hardlink", "mode"])
async def test_retired_destination_conflicts_move_active_out_of_the_active_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    conflict_kind: str,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    staged = await stager.stage(
        _manifest(),
        _source(root, b"retired destination conflict"),
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    row = store.artifact_upload(str(ARTIFACT_ID))
    assert row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
    real_rename_noreplace = artifacts_module.rename_noreplace

    def fail_retirement_once(
        source_dir_fd: int,
        source_name: str,
        destination_dir_fd: int,
        destination_name: str,
    ) -> None:
        if source_name.startswith("active-") and destination_name.startswith("retired-"):
            raise RuntimeError("controlled retirement pause")
        real_rename_noreplace(
            source_dir_fd,
            source_name,
            destination_dir_fd,
            destination_name,
        )

    monkeypatch.setattr(artifacts_module, "rename_noreplace", fail_retirement_once)
    report = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )
    assert report.issues
    assert not staged.path.exists()
    active = _prune_active_records(stager)
    assert len(active) == 1
    operation_id = active[0].name.removeprefix("active-").removesuffix(".json")
    destination = stager.prune_retired_root / f"retired-{operation_id}.json"
    outside = tmp_path / f"retired-conflict-{conflict_kind}"
    outside.write_bytes(b"conflict")
    os.chmod(outside, 0o600)
    if conflict_kind == "symlink":
        destination.symlink_to(outside)
    elif conflict_kind == "hardlink":
        os.link(outside, destination)
    else:
        destination.write_bytes(b"conflict")
        os.chmod(destination, 0o640 if conflict_kind == "mode" else 0o600)
    before = destination.lstat()

    monkeypatch.setattr(
        artifacts_module,
        "rename_noreplace",
        real_rename_noreplace,
    )
    recovered = SQLiteArtifactStager(store, root)

    after = destination.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode, after.st_nlink) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
    )
    assert _prune_active_records(recovered) == []
    conflicts = _conflicted_prune_active_records(recovered)
    assert len(conflicts) == 1
    assert conflicts[0].name.startswith(f"conflict-{operation_id}-")
    assert any("manual_recovery_required" in issue for issue in recovered.maintenance_issues)


def test_retired_conflict_before_incomplete_operation_does_not_consume_entry_budget(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(
        store,
        root,
        reconciliation_maximum_entries=1,
    )
    conflict_operation, conflict_plan, _conflict_path, _ = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000505",
        name="artifact-conflict-first.pcapng",
        content=b"conflict first",
    )
    valid_operation, valid_plan, _valid_path, _ = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000506",
        name="artifact-valid-second.pcapng",
        content=b"valid second",
    )
    conflict_operation = replace(conflict_operation, operation_id="0" * 31 + "1")
    valid_operation = replace(valid_operation, operation_id="0" * 31 + "2")
    _prepare_prune_crash_stage(
        stager,
        conflict_operation,
        conflict_plan,
        quarantined=False,
    )
    _prepare_prune_crash_stage(
        stager,
        valid_operation,
        valid_plan,
        quarantined=False,
    )
    retired_conflict = stager.prune_retired_root / f"retired-{conflict_operation.operation_id}.json"
    retired_conflict.write_bytes(b"pre-existing retired conflict")
    os.chmod(retired_conflict, 0o600)
    descriptors = stager._open_managed_tree()
    prune_descriptor = stager._open_prune_intent_directory(descriptors[2])
    active_descriptor = stager._open_prune_active_directory(descriptors[2])
    retired_descriptor = stager._open_prune_retired_directory(descriptors[2])
    conflicts_descriptor = stager._open_prune_conflicts_directory(descriptors[2])
    try:
        result = stager._reconcile_prune_intents(
            stager._new_reconciliation_control(),
            descriptors[2],
            prune_descriptor,
            active_descriptor,
            retired_descriptor,
            conflicts_descriptor,
        )
    finally:
        for descriptor in (
            conflicts_descriptor,
            retired_descriptor,
            active_descriptor,
            prune_descriptor,
            *reversed(descriptors),
        ):
            os.close(descriptor)

    assert result.processed_operations == 1
    assert not result.has_more
    assert _prune_active_records(stager) == []
    assert len(_conflicted_prune_active_records(stager)) == 1
    assert len(_retired_prune_active_records(stager)) == 2
    valid_row = store.artifact_upload(valid_operation.artifact_id)
    assert valid_row is not None
    assert valid_row["relative_path"] == valid_operation.quarantine_relative_path


def test_crash_between_manual_event_and_conflict_move_retries_terminalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    operation, plan, _path, _identity = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000504",
        name="artifact-conflict-crash.pcapng",
        content=b"manual event before conflict move",
    )
    _prepare_prune_crash_stage(stager, operation, plan, quarantined=False)
    retired = stager.prune_retired_root / f"retired-{operation.operation_id}.json"
    retired.write_bytes(b"existing retired")
    os.chmod(retired, 0o600)
    real_move = SQLiteArtifactStager._move_prune_active_to_conflict
    attempts = 0

    def crash_first_move(
        self: SQLiteArtifactStager,
        active: Any,
        active_descriptor: int,
        conflicts_descriptor: int,
        *,
        event_guard: Any,
    ) -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("controlled crash after manual event")
        return real_move(
            self,
            active,
            active_descriptor,
            conflicts_descriptor,
            event_guard=event_guard,
        )

    monkeypatch.setattr(
        SQLiteArtifactStager,
        "_move_prune_active_to_conflict",
        crash_first_move,
    )
    first = SQLiteArtifactStager(store, root)
    assert len(_prune_active_records(first)) == 1
    assert _conflicted_prune_active_records(first) == []
    assert "MANUAL_RECOVERY_REQUIRED" in _prune_event_stages(first)
    assert any("manual_recovery_required" in issue for issue in first.maintenance_issues)

    monkeypatch.setattr(SQLiteArtifactStager, "_move_prune_active_to_conflict", real_move)
    second = SQLiteArtifactStager(store, root)
    assert _prune_active_records(second) == []
    assert len(_conflicted_prune_active_records(second)) == 1
    assert retired.read_bytes() == b"existing retired"


def test_conflict_nonce_collision_never_overwrites_and_uses_a_new_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    operation, _plan, artifact, _identity = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000503",
        name="artifact-conflict-nonce.pcapng",
        content=b"nonce collision",
    )
    _prepare_prune_active_without_event(stager, operation)
    active_identity = _capture_path_identity(_prune_active_records(stager)[0])
    colliding_nonce = "a" * 64
    replacement_nonce = "b" * 64
    collision = (
        stager.prune_conflicts_root / f"conflict-{operation.operation_id}-{colliding_nonce}.json"
    )
    collision.write_bytes(b"pre-existing conflict")
    os.chmod(collision, 0o600)
    real_token_hex = artifacts_module.secrets.token_hex
    nonces = iter((colliding_nonce, replacement_nonce))

    def planned_token_hex(size: int) -> str:
        if size == 32:
            return next(nonces)
        return real_token_hex(size)

    monkeypatch.setattr(artifacts_module.secrets, "token_hex", planned_token_hex)
    recovered = SQLiteArtifactStager(store, root)

    assert collision.read_bytes() == b"pre-existing conflict"
    conflicts = _conflicted_prune_active_records(recovered)
    assert {path.name for path in conflicts} == {
        collision.name,
        f"conflict-{operation.operation_id}-{replacement_nonce}.json",
    }
    moved = next(path for path in conflicts if path != collision)
    assert _capture_path_identity(moved) == active_identity
    assert artifact.exists()


@pytest.mark.asyncio
async def test_retirement_exdev_is_manual_recovery_and_preserves_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    staged = await stager.stage(
        _manifest(),
        _source(root, b"retirement EXDEV"),
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    row = store.artifact_upload(str(ARTIFACT_ID))
    assert row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
    real_rename_noreplace = artifacts_module.rename_noreplace

    def reject_cross_device_retirement(
        source_dir_fd: int,
        source_name: str,
        destination_dir_fd: int,
        destination_name: str,
    ) -> None:
        if source_name.startswith("active-") and destination_name.startswith("retired-"):
            raise OSError(errno.EXDEV, "controlled cross-device retirement")
        real_rename_noreplace(
            source_dir_fd,
            source_name,
            destination_dir_fd,
            destination_name,
        )

    monkeypatch.setattr(
        artifacts_module,
        "rename_noreplace",
        reject_cross_device_retirement,
    )
    report = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )

    assert report.issues
    assert not staged.path.exists()
    assert len(_prune_active_records(stager)) == 1
    assert _retired_prune_active_records(stager) == []
    recovered = SQLiteArtifactStager(store, root)
    assert len(_prune_active_records(recovered)) == 1
    assert any("manual_recovery_required" in issue for issue in recovered.maintenance_issues)


@pytest.mark.asyncio
@pytest.mark.parametrize("crash_stage", ["prepared", "quarantined", "sqlite_updated"])
async def test_prune_journal_recovers_each_durable_crash_boundary(
    tmp_path: Path,
    crash_stage: str,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root, f"prune crash {crash_stage}".encode())

    class CrashBoundaryStager(SQLiteArtifactStager):
        def _after_prune_prepared(self, operation: object) -> None:
            del operation
            if crash_stage == "prepared":
                raise RuntimeError("crash after PREPARED")

        def _after_prune_quarantine(self, operation: object) -> None:
            del operation
            if crash_stage == "quarantined":
                raise RuntimeError("crash after logical quarantine")

        def _after_prune_sqlite_update(self, operation: object) -> None:
            del operation
            if crash_stage == "sqlite_updated":
                raise RuntimeError("crash after SQLite commit")

    stager = CrashBoundaryStager(store, root)
    staged = await stager.stage(
        _manifest(),
        source,
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    original_identity = _capture_path_identity(staged.path)
    row = store.artifact_upload(str(ARTIFACT_ID))
    assert row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))

    report = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )
    assert report.files_deleted == report.rows_deleted == report.bytes_deleted == 0
    assert report.issues
    assert "PREPARED" in _prune_event_stages(stager)
    assert len(_prune_active_records(stager)) == 1

    recovered = SQLiteArtifactStager(store, root)
    recovered_row = store.artifact_upload(str(ARTIFACT_ID))
    assert recovered_row is not None
    recovered_path = Path(str(recovered_row["relative_path"]))
    assert recovered_path.name.startswith(".artifact-prune-quarantine-")
    assert_logically_quarantined(
        recovered.outbox_root,
        ".artifact-prune-quarantine-",
        active_name=staged.path.name,
        expected_identity=original_identity,
        expected_content=f"prune crash {crash_stage}".encode(),
        maintenance_issues=recovered.maintenance_issues,
    )
    assert "QUARANTINED" in _prune_event_stages(recovered)
    assert "SQLITE_UPDATED" in _prune_event_stages(recovered)
    assert _prune_active_records(recovered) == []
    assert len(_retired_prune_active_records(recovered)) == 1

    again = SQLiteArtifactStager(store, root)
    assert len(_quarantines(again.outbox_root, ".artifact-prune-quarantine-")) == 1
    assert store.artifact_upload(str(ARTIFACT_ID)) == recovered_row


def test_active_without_prepared_fails_closed_outside_the_active_index(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    operation, _plan, artifact, artifact_identity = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000510",
        name="artifact-active-without-prepared.pcapng",
        content=b"active without prepared",
    )
    _prepare_prune_active_without_event(stager, operation)

    recovered = SQLiteArtifactStager(store, root)

    row = store.artifact_upload(operation.artifact_id)
    assert row is not None
    assert row["relative_path"] == operation.original_relative_path
    assert artifact.exists()
    assert _capture_path_identity(artifact) == artifact_identity
    assert _prune_active_records(recovered) == []
    assert len(_conflicted_prune_active_records(recovered)) == 1
    assert "MANUAL_RECOVERY_REQUIRED" in _prune_event_stages(recovered)
    assert any("active_without_prepared" in issue for issue in recovered.maintenance_issues)


@pytest.mark.parametrize("unsafe_kind", ["corrupt", "symlink", "hardlink", "mode"])
def test_unsafe_prune_active_record_never_mutates_artifact_or_sqlite(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    operation, plan, artifact, artifact_identity = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000513",
        name="artifact-unsafe-active.pcapng",
        content=b"unsafe active record",
    )
    _prepare_prune_crash_stage(stager, operation, plan, quarantined=False)
    active = _prune_active_records(stager)[0]
    if unsafe_kind == "corrupt":
        active.write_bytes(b"{invalid-json")
        os.chmod(active, 0o600)
    elif unsafe_kind == "symlink":
        retained = stager.prune_active_root / ".retained-active"
        active.rename(retained)
        active.symlink_to(retained.name)
    elif unsafe_kind == "hardlink":
        os.link(active, stager.prune_active_root / ".active-hardlink")
    else:
        os.chmod(active, 0o640)

    recovered = SQLiteArtifactStager(store, root)

    row = store.artifact_upload(operation.artifact_id)
    assert row is not None
    assert row["relative_path"] == operation.original_relative_path
    assert artifact.exists()
    assert _capture_path_identity(artifact) == artifact_identity
    assert not _quarantines(recovered.outbox_root, ".artifact-prune-quarantine-")
    assert any("invalid_or_replaced_event" in issue for issue in recovered.maintenance_issues)


def test_replaced_prune_active_name_never_mutates_artifact_or_sqlite(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    operation, plan, artifact, artifact_identity = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000514",
        name="artifact-replaced-active.pcapng",
        content=b"replaced active record",
    )
    _prepare_prune_crash_stage(stager, operation, plan, quarantined=False)
    active = _prune_active_records(stager)[0]
    replaced = False

    class RacingStager(SQLiteArtifactStager):
        def _before_prune_active_open(self, candidate: Any) -> None:
            nonlocal replaced
            if replaced:
                return
            replacement = self.prune_active_root / ".replacement-active"
            replacement.write_bytes(active.read_bytes())
            os.chmod(replacement, 0o600)
            os.replace(replacement, active)
            replaced = True

    recovered = RacingStager(store, root)

    assert replaced
    row = store.artifact_upload(operation.artifact_id)
    assert row is not None
    assert row["relative_path"] == operation.original_relative_path
    assert artifact.exists()
    assert _capture_path_identity(artifact) == artifact_identity
    assert any("invalid_or_replaced_event" in issue for issue in recovered.maintenance_issues)


def test_manual_recovery_active_does_not_consume_valid_operation_budget(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    manual = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000515",
        name="artifact-manual-active.pcapng",
        content=b"manual active",
    )
    valid = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000516",
        name="artifact-valid-active.pcapng",
        content=b"valid active",
    )
    manual_operation = replace(manual[0], operation_id="0" * 32)
    valid_operation = replace(valid[0], operation_id="f" * 32)
    _prepare_prune_active_without_event(stager, manual_operation)
    _prepare_prune_crash_stage(stager, valid_operation, valid[1], quarantined=False)

    recovered = SQLiteArtifactStager(
        store,
        root,
        reconciliation_maximum_entries=1,
    )

    manual_row = store.artifact_upload(manual_operation.artifact_id)
    valid_row = store.artifact_upload(valid_operation.artifact_id)
    assert manual_row is not None
    assert valid_row is not None
    assert manual_row["relative_path"] == manual_operation.original_relative_path
    assert valid_row["relative_path"] == valid_operation.quarantine_relative_path
    assert manual[2].exists()
    assert not valid[2].exists()
    assert _prune_active_records(recovered) == []
    assert len(_conflicted_prune_active_records(recovered)) == 1
    assert len(_retired_prune_active_records(recovered)) == 1
    assert any("active_without_prepared" in issue for issue in recovered.maintenance_issues)


def test_prune_journal_over_4096_events_recovers_pending_operations_incrementally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    prepared = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000511",
        name="artifact-large-journal-prepared.pcapng",
        content=b"prepared after history",
    )
    quarantined = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000512",
        name="artifact-large-journal-quarantined.pcapng",
        content=b"quarantined after history",
    )
    _prepare_prune_crash_stage(stager, prepared[0], prepared[1], quarantined=False)
    _prepare_prune_crash_stage(stager, quarantined[0], quarantined[1], quarantined=True)
    _seed_completed_prune_history(stager, prepared[0], operation_count=1_366)
    assert len(list(stager.prune_intent_root.iterdir())) > 4_096
    historical_names = {entry.name for entry in stager.prune_intent_root.iterdir()}
    real_scandir = artifacts_module.os.scandir

    def reject_global_journal_scan(path: Any) -> Any:
        if isinstance(path, int):
            descriptor_path = Path(f"/proc/self/fd/{path}")
            if descriptor_path.resolve() == stager.prune_intent_root.resolve():
                raise AssertionError("startup scanned the append-only prune journal")
        return real_scandir(path)

    monkeypatch.setattr(artifacts_module.os, "scandir", reject_global_journal_scan)

    first = SQLiteArtifactStager(
        store,
        root,
        reconciliation_maximum_entries=1,
    )
    rows_after_first = [
        store.artifact_upload("30000000-0000-4000-8000-000000000511"),
        store.artifact_upload("30000000-0000-4000-8000-000000000512"),
    ]
    assert (
        sum(
            row is not None
            and str(row["relative_path"]).startswith("outbox/.artifact-prune-quarantine-")
            for row in rows_after_first
        )
        == 1
    )
    assert "prune_journal:reconciliation_deferred:operation_limit" in first.maintenance_issues
    assert len(_prune_active_records(first)) == 1

    second = SQLiteArtifactStager(
        store,
        root,
        reconciliation_maximum_entries=1,
    )
    rows_after_second = [
        store.artifact_upload("30000000-0000-4000-8000-000000000511"),
        store.artifact_upload("30000000-0000-4000-8000-000000000512"),
    ]
    assert all(
        row is not None
        and str(row["relative_path"]).startswith("outbox/.artifact-prune-quarantine-")
        for row in rows_after_second
    )
    assert not prepared[2].exists()
    assert not quarantined[2].exists()
    quarantines = _quarantines(second.outbox_root, ".artifact-prune-quarantine-")
    assert len(quarantines) == 2
    observed_identities = {_capture_path_identity(path) for path in quarantines}
    assert observed_identities == {prepared[3], quarantined[3]}
    assert historical_names <= {entry.name for entry in stager.prune_intent_root.iterdir()}
    assert _prune_active_records(second) == []
    assert len(_retired_prune_active_records(second)) == 2

    rows_before_idempotent_run = tuple(rows_after_second)
    third = SQLiteArtifactStager(
        store,
        root,
        reconciliation_maximum_entries=1,
    )
    assert len(_quarantines(third.outbox_root, ".artifact-prune-quarantine-")) == 2
    assert (
        store.artifact_upload("30000000-0000-4000-8000-000000000511"),
        store.artifact_upload("30000000-0000-4000-8000-000000000512"),
    ) == rows_before_idempotent_run


def test_prune_journal_deadline_after_progress_continues_on_second_run(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    operations = [
        _create_confirmed_prune_operation(
            stager,
            store,
            artifact_id=f"30000000-0000-4000-8000-{index + 520:012d}",
            name=f"artifact-deadline-{index}.pcapng",
            content=f"deadline-{index}".encode(),
        )
        for index in range(2)
    ]
    for operation, plan, _path, _identity in operations:
        _prepare_prune_crash_stage(stager, operation, plan, quarantined=False)
    control = stager._new_reconciliation_control()
    processed = 0

    def expire_after_progress(operation_id: str) -> None:
        nonlocal processed
        del operation_id
        processed += 1
        if processed == 1:
            control.deadline = time.monotonic()

    stager._after_prune_operation_reconciled = expire_after_progress  # type: ignore[method-assign]
    descriptors = stager._open_managed_tree()
    prune_descriptor = stager._open_prune_intent_directory(descriptors[2])
    active_descriptor = stager._open_prune_active_directory(descriptors[2])
    retired_descriptor = stager._open_prune_retired_directory(descriptors[2])
    conflicts_descriptor = stager._open_prune_conflicts_directory(descriptors[2])
    try:
        with pytest.raises(TimeoutError, match="deadline"):
            stager._reconcile_prune_intents(
                control,
                descriptors[2],
                prune_descriptor,
                active_descriptor,
                retired_descriptor,
                conflicts_descriptor,
            )
    finally:
        os.close(conflicts_descriptor)
        os.close(retired_descriptor)
        os.close(active_descriptor)
        os.close(prune_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    assert processed == 1
    assert (
        sum(
            str(store.artifact_upload(str(operation.artifact_id))["relative_path"]).startswith(
                "outbox/.artifact-prune-quarantine-"
            )
            for operation, _plan, _path, _identity in operations
        )
        == 1
    )

    recovered = SQLiteArtifactStager(store, root)
    assert all(
        str(store.artifact_upload(str(operation.artifact_id))["relative_path"]).startswith(
            "outbox/.artifact-prune-quarantine-"
        )
        for operation, _plan, _path, _identity in operations
    )
    assert len(_quarantines(recovered.outbox_root, ".artifact-prune-quarantine-")) == 2


def test_cancelled_prune_journal_reconciliation_performs_no_mutation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    operation, plan, path, identity = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000531",
        name="artifact-cancelled-prune-recovery.pcapng",
        content=b"cancelled recovery",
    )
    _prepare_prune_crash_stage(stager, operation, plan, quarantined=False)
    stop = threading.Event()
    stop.set()
    control = stager._new_reconciliation_control(stop=stop)
    descriptors = stager._open_managed_tree()
    prune_descriptor = stager._open_prune_intent_directory(descriptors[2])
    active_descriptor = stager._open_prune_active_directory(descriptors[2])
    retired_descriptor = stager._open_prune_retired_directory(descriptors[2])
    conflicts_descriptor = stager._open_prune_conflicts_directory(descriptors[2])
    try:
        with pytest.raises(RuntimeError, match="cancelled"):
            stager._reconcile_prune_intents(
                control,
                descriptors[2],
                prune_descriptor,
                active_descriptor,
                retired_descriptor,
                conflicts_descriptor,
            )
    finally:
        os.close(conflicts_descriptor)
        os.close(retired_descriptor)
        os.close(active_descriptor)
        os.close(prune_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    row = store.artifact_upload(operation.artifact_id)
    assert row is not None
    assert row["relative_path"] == operation.original_relative_path
    assert path.exists()
    assert _capture_path_identity(path) == identity
    assert _prune_event_stages(stager) == ["PREPARED"]


@pytest.mark.parametrize(
    "race_point",
    ["between_discovery_and_open", "after_open", "after_parse"],
)
def test_replaced_prune_event_never_mutates_artifact_or_sqlite(
    tmp_path: Path,
    race_point: str,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    operation, plan, artifact, artifact_identity = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000541",
        name="artifact-event-race.pcapng",
        content=b"event race artifact",
    )
    _prepare_prune_crash_stage(stager, operation, plan, quarantined=False)
    event = next(stager.prune_intent_root.glob("*prepared*.json"))
    replaced = False

    def replace_event() -> None:
        nonlocal replaced
        if replaced:
            return
        replacement = stager.prune_intent_root / ".replacement-event"
        replacement.write_bytes(event.read_bytes())
        os.chmod(replacement, 0o600)
        os.replace(replacement, event)
        replaced = True

    class RacingStager(SQLiteArtifactStager):
        def _before_prune_event_open(self, candidate: Any) -> None:
            if race_point == "between_discovery_and_open" and "prepared" in str(candidate.name):
                replace_event()

        def _after_prune_event_open(self, candidate: Any, descriptor: int) -> None:
            del descriptor
            if race_point == "after_open" and "prepared" in str(candidate.name):
                replace_event()

        def _after_prune_events_parsed(self, events: tuple[Any, ...]) -> None:
            if race_point == "after_parse" and any(
                "prepared" in str(opened.candidate.name) for opened in events
            ):
                replace_event()

    recovered = RacingStager(store, root)
    assert replaced
    row = store.artifact_upload(operation.artifact_id)
    assert row is not None
    assert row["relative_path"] == operation.original_relative_path
    assert artifact.exists()
    assert _capture_path_identity(artifact) == artifact_identity
    assert not _quarantines(recovered.outbox_root, ".artifact-prune-quarantine-")
    assert _prune_event_stages(recovered) == ["PREPARED"]
    assert any("invalid_or_replaced_event" in issue for issue in recovered.maintenance_issues)


def test_replaced_prune_event_does_not_consume_the_valid_operation_budget(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    invalid = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000543",
        name="artifact-invalid-event-budget.pcapng",
        content=b"invalid event budget",
    )
    valid = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000544",
        name="artifact-valid-event-budget.pcapng",
        content=b"valid event budget",
    )
    invalid_operation = replace(invalid[0], operation_id="0" * 31 + "1")
    valid_operation = replace(valid[0], operation_id="f" * 32)
    _prepare_prune_crash_stage(stager, invalid_operation, invalid[1], quarantined=False)
    _prepare_prune_crash_stage(stager, valid_operation, valid[1], quarantined=False)
    invalid_event = next(
        stager.prune_intent_root.glob(f"prune-{invalid_operation.operation_id}-*.json")
    )

    class RacingStager(SQLiteArtifactStager):
        def _before_prune_event_open(self, candidate: Any) -> None:
            if candidate.operation_id != invalid_operation.operation_id:
                return
            replacement = self.prune_intent_root / ".replacement-invalid-budget-event"
            replacement.write_bytes(invalid_event.read_bytes())
            os.chmod(replacement, 0o600)
            os.replace(replacement, invalid_event)

    recovered = RacingStager(
        store,
        root,
        reconciliation_maximum_entries=1,
    )
    invalid_row = store.artifact_upload(invalid_operation.artifact_id)
    valid_row = store.artifact_upload(valid_operation.artifact_id)
    assert invalid_row is not None
    assert valid_row is not None
    assert invalid_row["relative_path"] == invalid_operation.original_relative_path
    assert valid_row["relative_path"] == valid_operation.quarantine_relative_path
    assert invalid[2].exists()
    assert not valid[2].exists()
    assert _capture_path_identity(invalid[2]) == invalid[3]
    quarantines = _quarantines(recovered.outbox_root, ".artifact-prune-quarantine-")
    assert len(quarantines) == 1
    assert _capture_path_identity(quarantines[0]) == valid[3]
    assert any("invalid_or_replaced_event" in issue for issue in recovered.maintenance_issues)


@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink", "mode"])
def test_unsafe_prune_event_never_mutates_artifact_or_sqlite(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    operation, plan, artifact, artifact_identity = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000551",
        name="artifact-unsafe-event.pcapng",
        content=b"unsafe event artifact",
    )
    _prepare_prune_crash_stage(stager, operation, plan, quarantined=False)
    event = next(stager.prune_intent_root.glob("*prepared*.json"))
    if unsafe_kind == "symlink":
        retained = stager.prune_intent_root / ".retained-event"
        event.rename(retained)
        event.symlink_to(retained.name)
    elif unsafe_kind == "hardlink":
        os.link(event, stager.prune_intent_root / ".event-hardlink")
    else:
        os.chmod(event, 0o640)

    recovered = SQLiteArtifactStager(store, root)
    row = store.artifact_upload(operation.artifact_id)
    assert row is not None
    assert row["relative_path"] == operation.original_relative_path
    assert artifact.exists()
    assert _capture_path_identity(artifact) == artifact_identity
    assert not _quarantines(recovered.outbox_root, ".artifact-prune-quarantine-")
    assert any("invalid_or_replaced_event" in issue for issue in recovered.maintenance_issues)


@pytest.mark.skipif(
    getattr(os, "geteuid", lambda: 1)() != 0,
    reason="owner mismatch needs a disposable root container",
)
def test_wrong_owner_prune_event_never_mutates_sqlite(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    operation, plan, artifact, artifact_identity = _create_confirmed_prune_operation(
        stager,
        store,
        artifact_id="30000000-0000-4000-8000-000000000552",
        name="artifact-owner-event.pcapng",
        content=b"owner event artifact",
    )
    _prepare_prune_crash_stage(stager, operation, plan, quarantined=False)
    event = next(stager.prune_intent_root.glob("*prepared*.json"))
    os.chown(event, 1, -1)

    recovered = SQLiteArtifactStager(store, root)
    row = store.artifact_upload(operation.artifact_id)
    assert row is not None
    assert row["relative_path"] == operation.original_relative_path
    assert artifact.exists()
    assert _capture_path_identity(artifact) == artifact_identity
    assert any("invalid_or_replaced_event" in issue for issue in recovered.maintenance_issues)


@pytest.mark.asyncio
async def test_prune_sqlite_update_failure_keeps_durable_quarantine_association(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    stager = SQLiteArtifactStager(store, root)
    staged = await stager.stage(
        _manifest(),
        _source(root, b"manual prune recovery"),
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    row = store.artifact_upload(str(ARTIFACT_ID))
    assert row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
    original_update = store.update_confirmed_artifact_path
    monkeypatch.setattr(store, "update_confirmed_artifact_path", lambda *args, **kwargs: False)

    report = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )

    assert report.files_deleted == report.rows_deleted == report.bytes_deleted == 0
    assert not staged.path.exists()
    quarantines = _quarantines(stager.outbox_root, ".artifact-prune-quarantine-")
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == b"manual prune recovery"
    retained = store.artifact_upload(str(ARTIFACT_ID))
    assert retained is not None
    assert retained["relative_path"] == row["relative_path"]
    assert "MANUAL_RECOVERY_REQUIRED" in _prune_event_stages(stager)
    assert any("confirmed_row_changed" in issue for issue in report.issues)
    assert _prune_active_records(stager) == []
    assert len(_conflicted_prune_active_records(stager)) == 1
    monkeypatch.setattr(store, "update_confirmed_artifact_path", original_update)

    recovered = SQLiteArtifactStager(store, root)
    assert _prune_active_records(recovered) == []
    assert len(_conflicted_prune_active_records(recovered)) == 1
    assert len(_quarantines(recovered.outbox_root, ".artifact-prune-quarantine-")) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink"])
async def test_pruning_reports_and_preserves_symlink_or_hardlink(
    tmp_path: Path, unsafe_kind: str
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root)
    stager = SQLiteArtifactStager(store, root)
    staged = await stager.stage(
        _manifest(),
        source,
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    row = store.artifact_upload(str(ARTIFACT_ID))
    assert row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))
    if unsafe_kind == "symlink":
        target = tmp_path / "outside-artifact"
        target.write_bytes(staged.path.read_bytes())
        staged.path.unlink()
        staged.path.symlink_to(target)
    else:
        os.link(staged.path, tmp_path / "second-artifact-link")

    report = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )

    assert report.files_deleted == 0
    assert report.rows_deleted == 0
    assert report.issues
    assert staged.path.exists()
    assert store.artifact_upload(str(ARTIFACT_ID)) is not None


@pytest.mark.asyncio
async def test_pruning_keeps_row_when_validated_inode_is_replaced_and_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    root = tmp_path / "artifacts"
    source = _source(root)
    stager = SQLiteArtifactStager(store, root)
    staged = await stager.stage(
        _manifest(),
        source,
        TASK_ID,
        maximum_size_bytes=4096,
        cancellation=CancellationToken(),
    )
    attacked_row = store.artifact_upload(str(ARTIFACT_ID))
    assert attacked_row is not None
    store.confirm_outbox(
        "pending_uploads",
        "upload_id",
        str(attacked_row["upload_id"]),
    )

    safe_id = "30000000-0000-4000-8000-000000000012"
    safe_content = b"independent-confirmed-artifact"
    safe_path = stager.outbox_root / "artifact-independent.pcapng"
    safe_path.write_bytes(safe_content)
    os.chmod(safe_path, 0o400)
    store.ensure_artifact_queued(
        task_id=str(TASK_ID),
        relative_path=f"outbox/{safe_path.name}",
        media_type="application/x-pcapng",
        payload={
            **_manifest(),
            "artifact_id": safe_id,
            "idempotency_key": safe_id,
            "size_bytes": len(safe_content),
            "sha256": hashlib.sha256(safe_content).hexdigest(),
        },
    )
    safe_row = store.artifact_upload(safe_id)
    assert safe_row is not None
    store.confirm_outbox("pending_uploads", "upload_id", str(safe_row["upload_id"]))

    real_quarantine = artifacts_module.logical_quarantine
    replacement = stager.outbox_root / ".attacker-replacement"
    replacement.write_bytes(staged.path.read_bytes())
    os.chmod(replacement, 0o400)
    swapped = False

    def replace_between_validation_and_delete(
        identity: object,
        *,
        quarantine_prefix: str,
        plan: object | None = None,
        primary_error: BaseException | None = None,
    ) -> object:
        nonlocal swapped
        if (
            not swapped
            and getattr(identity, "relative_name", None) == staged.path.name
            and quarantine_prefix == ".artifact-prune-quarantine-"
        ):
            swapped = True
            os.replace(replacement, staged.path)
        return real_quarantine(  # type: ignore[arg-type]
            identity,
            quarantine_prefix=quarantine_prefix,
            plan=plan,  # type: ignore[arg-type]
            primary_error=primary_error,
        )

    monkeypatch.setattr(
        artifacts_module,
        "logical_quarantine",
        replace_between_validation_and_delete,
    )

    report = await stager.prune_confirmed(
        maximum_age_seconds=None,
        retain_count=0,
        retain_bytes=None,
    )

    assert swapped
    assert staged.path.exists()
    assert store.artifact_upload(str(ARTIFACT_ID)) is not None
    assert not safe_path.exists()
    retained_safe = store.artifact_upload(safe_id)
    assert retained_safe is not None
    safe_quarantine = stager.artifact_root / str(retained_safe["relative_path"])
    assert safe_quarantine.exists()
    assert safe_quarantine.read_bytes() == safe_content
    assert report.files_deleted == 0
    assert report.rows_deleted == 0
    assert report.bytes_deleted == 0
    assert report.issues
