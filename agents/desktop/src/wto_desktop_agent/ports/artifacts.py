from __future__ import annotations

from pathlib import Path
from typing import Protocol


class ArtifactUploader(Protocol):
    async def upload(self, artifact_id: str, relative_path: Path) -> None: ...


class Updater(Protocol):
    async def check(self) -> str: ...
