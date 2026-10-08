"""Páginas rastreadas por scan (portão de cobertura da etapa 4).

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-08
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("pages_crawled", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "pages_crawled")
