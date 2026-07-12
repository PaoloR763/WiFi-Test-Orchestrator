from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore


class FakeClock:
    def __init__(self, now: datetime | None = None) -> None:
        self.current = now or datetime(2026, 7, 12, 12, 0, tzinfo=UTC)
        self.sleeps: list[float] = []

    def now(self) -> datetime:
        return self.current

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)


@pytest.fixture
def store(tmp_path: Path) -> SQLiteStore:
    result = SQLiteStore(tmp_path / "agent.sqlite3")
    result.initialize()
    return result
