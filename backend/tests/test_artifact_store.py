from __future__ import annotations

from pathlib import Path

import pytest

from wto_backend.artifact_store import LocalFilesystemArtifactStore


class FailingReadStore(LocalFilesystemArtifactStore):
    def _read_probe(self, path: Path) -> bytes:
        del path
        raise OSError("forced read failure")


def readiness_files(root: Path) -> list[Path]:
    return list(root.glob(".readiness-*"))


def test_artifact_readiness_writes_reads_and_cleans_up(tmp_path: Path) -> None:
    store = LocalFilesystemArtifactStore(tmp_path)
    store.check_readiness()
    assert readiness_files(tmp_path) == []


def test_artifact_readiness_cleans_up_after_error(tmp_path: Path) -> None:
    store = FailingReadStore(tmp_path)
    with pytest.raises(OSError, match="forced read failure"):
        store.check_readiness()
    assert readiness_files(tmp_path) == []
