"""Nível da autorização da cópia de teste: intrusive (padrão) x stress (libera o agressivo).

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-08
"""

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # server_default "intrusive": autorizações antigas continuam valendo só para o intrusivo,
    # nunca liberam o agressivo por acidente.
    op.add_column(
        "staging_authorizations",
        sa.Column(
            "scope_level",
            sa.String(length=16),
            nullable=False,
            server_default="intrusive",
        ),
    )


def downgrade() -> None:
    op.drop_column("staging_authorizations", "scope_level")
