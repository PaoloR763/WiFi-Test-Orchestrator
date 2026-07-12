from __future__ import annotations

from pathlib import Path


class DisabledArtifactUploader:
    async def upload(self, artifact_id: str, relative_path: Path) -> None:
        raise RuntimeError("artifact upload is deferred until its public server API is published")


class DisabledUpdater:
    async def check(self) -> str:
        return "disabled_phase05"
