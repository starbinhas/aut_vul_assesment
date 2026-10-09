"""Login por formulário/cookie no scan autenticado (modo + nomes dos campos).

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-09
"""

import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # server_default "token": configs antigas continuam sendo login por API (comportamento atual).
    op.add_column(
        "target_auth_config",
        sa.Column("login_mode", sa.String(length=16), nullable=False, server_default="token"),
    )
    op.add_column(
        "target_auth_config", sa.Column("username_field", sa.String(length=100), nullable=True)
    )
    op.add_column(
        "target_auth_config", sa.Column("password_field", sa.String(length=100), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("target_auth_config", "password_field")
    op.drop_column("target_auth_config", "username_field")
    op.drop_column("target_auth_config", "login_mode")
