"""Estado de revisão manual (A06/A09) por scan.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-08
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "manual_check_results",
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("check_id", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("reviewed_by", sa.String(length=64), nullable=True),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.scan_id"]),
        sa.PrimaryKeyConstraint("scan_id", "check_id"),
    )


def downgrade() -> None:
    op.drop_table("manual_check_results")
