"""Create the empty Phase 02 migration baseline.

Revision ID: 20260711_0001
Revises:
Create Date: 2026-07-11 00:00:00+00:00
"""

from collections.abc import Sequence

revision: str = "20260711_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Keep Phase 02 free of definitive domain tables."""


def downgrade() -> None:
    """The empty baseline has no domain state to remove."""
