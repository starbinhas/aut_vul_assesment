"""Config de scan autenticado por site (sem a senha; essa é por execução).

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-08
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "target_auth_config",
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("login_url", sa.String(length=2048), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("token_path", sa.String(length=200), nullable=False, server_default="token"),
        sa.Column("protected_path", sa.String(length=2048), nullable=True),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["target_id"], ["targets.target_id"]),
        sa.PrimaryKeyConstraint("target_id"),
    )


def downgrade() -> None:
    op.drop_table("target_auth_config")
