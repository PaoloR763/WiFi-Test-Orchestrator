from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Final

ARTIFACT_PRUNE_QUARANTINE_PREFIX: Final = ".artifact-prune-quarantine-"
ARTIFACT_PRUNE_QUARANTINE_TOKEN_LENGTH: Final = 64
ARTIFACT_PRUNE_QUARANTINE_PATH_PREFIX: Final = f"outbox/{ARTIFACT_PRUNE_QUARANTINE_PREFIX}"
ARTIFACT_PRUNE_QUARANTINE_PREFIX_LENGTH: Final = len(ARTIFACT_PRUNE_QUARANTINE_PATH_PREFIX)
ARTIFACT_PRUNE_QUARANTINE_TOKEN_OFFSET: Final = ARTIFACT_PRUNE_QUARANTINE_PREFIX_LENGTH + 1
ARTIFACT_PRUNE_QUARANTINE_PATH_LENGTH: Final = (
    ARTIFACT_PRUNE_QUARANTINE_PREFIX_LENGTH + ARTIFACT_PRUNE_QUARANTINE_TOKEN_LENGTH
)

_ARTIFACT_PRUNE_QUARANTINE_PATTERN = re.compile(
    rf"\A{re.escape(ARTIFACT_PRUNE_QUARANTINE_PATH_PREFIX)}"
    rf"[0-9a-f]{{{ARTIFACT_PRUNE_QUARANTINE_TOKEN_LENGTH}}}\Z"
)


def is_artifact_prune_quarantine_path(value: str) -> bool:
    """Return true only for the exact lexical POSIX quarantine representation."""

    if _ARTIFACT_PRUNE_QUARANTINE_PATTERN.fullmatch(value) is None:
        return False
    relative = PurePosixPath(value)
    return (
        not relative.is_absolute()
        and relative.as_posix() == value
        and relative.parts == ("outbox", relative.name)
    )
