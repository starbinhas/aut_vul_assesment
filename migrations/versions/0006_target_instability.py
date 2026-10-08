"""Entrega parcial quando o alvo cai/fica instável no meio do scan (etapa 4).

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-08
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("partial", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("scans", sa.Column("partial_reason", sa.String(length=64), nullable=True))
    op.add_column(
        "scans", sa.Column("stop_requested_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("scans", "stop_requested_at")
    op.drop_column("scans", "partial_reason")
    op.drop_column("scans", "partial")
