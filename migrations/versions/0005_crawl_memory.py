"""Memória de rastreio por alvo: URLs já descobertas, semeadas no próximo scan.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-08
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

_JSON = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "crawl_memory",
        sa.Column("target_id", sa.String(length=64), primary_key=True),
        sa.Column("routes", _JSON, nullable=False, server_default="[]"),
        sa.Column("scan_id", sa.String(length=64), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("crawl_memory")
