"""Config do 2º usuário de teste para a checagem A01 (IDOR) por site.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-09
"""

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Tudo nullable: sites sem 2º usuário configurado continuam iguais (IDOR fica desligado).
    # A senha do 2º usuário NÃO é persistida (vem por execução, como a do 1º usuário).
    op.add_column(
        "target_auth_config", sa.Column("other_email", sa.String(length=320), nullable=True)
    )
    op.add_column("target_auth_config", sa.Column("idor_resources", sa.Text(), nullable=True))
    op.add_column(
        "target_auth_config", sa.Column("owner_marker", sa.String(length=2048), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("target_auth_config", "owner_marker")
    op.drop_column("target_auth_config", "idor_resources")
    op.drop_column("target_auth_config", "other_email")
