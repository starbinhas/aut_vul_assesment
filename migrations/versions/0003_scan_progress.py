"""Progresso da fase do scan: percentual, info, início da fase e hora da medição.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-07
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column("scans", sa.Column("progress_pct", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("progress_info", sa.String(80), nullable=True))
    op.add_column("scans", sa.Column("phase_started_at", TS, nullable=True))
    op.add_column("scans", sa.Column("progress_at", TS, nullable=True))


def downgrade() -> None:
    for col in ("progress_at", "phase_started_at", "progress_info", "progress_pct"):
        op.drop_column("scans", col)
