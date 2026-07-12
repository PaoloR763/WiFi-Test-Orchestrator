from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Protocol


class ArtifactStore(Protocol):
    def check_readiness(self) -> None: ...


class LocalFilesystemArtifactStore:
    """Local development adapter; physical paths never leave this boundary."""

    _probe_prefix = ".readiness-"
    _probe_payload = b"wto-ready"

    def __init__(self, root: Path) -> None:
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True)

    def _read_probe(self, path: Path) -> bytes:
        return path.read_bytes()

    def check_readiness(self) -> None:
        descriptor, raw_path = tempfile.mkstemp(prefix=self._probe_prefix, dir=self._root)
        probe_path = Path(raw_path)
        try:
            with os.fdopen(descriptor, "wb") as probe:
                probe.write(self._probe_payload)
                probe.flush()
                os.fsync(probe.fileno())
            if self._read_probe(probe_path) != self._probe_payload:
                raise OSError("artifact readiness verification failed")
        finally:
            probe_path.unlink(missing_ok=True)
