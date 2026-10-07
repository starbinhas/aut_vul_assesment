"""Interface web: organizações, usuários, sites (targets), auditoria e andamento do scan.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-07
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column("scans", sa.Column("status_detail", sa.String(200), nullable=True))
    op.add_column("scans", sa.Column("requested_by", sa.String(64), nullable=True))
    op.create_index("ix_scans_status", "scans", ["status"])

    op.create_table(
        "organizations",
        sa.Column("org_id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "users",
        sa.Column("user_id", sa.String(64), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False, unique=True, index=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("password_hash", sa.String(200), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.org_id"), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("failed_logins", sa.Integer, nullable=False, server_default="0"),
        sa.Column("locked_until", TS, nullable=True),
        sa.Column("last_login_at", TS, nullable=True),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("role in ('admin', 'client')", name="ck_users_role"),
        # Cliente sempre pertence a uma organização; admin não pertence a nenhuma.
        sa.CheckConstraint(
            "(role = 'client' and org_id is not null) or (role = 'admin' and org_id is null)",
            name="ck_users_org",
        ),
    )
    op.create_table(
        "targets",
        sa.Column("target_id", sa.String(64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.org_id"),
            nullable=False,
            index=True,
        ),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("base_url", sa.String(2048), nullable=False),
        sa.Column("verification_token", sa.String(64), nullable=False),
        sa.Column("verified_at", TS, nullable=True),
        sa.Column("last_check_at", TS, nullable=True),
        sa.Column("last_check_error", sa.String(300), nullable=True),
        sa.Column("recurrence", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("created_by", sa.String(64), nullable=True),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "domain", name="uq_targets_org_domain"),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("at", TS, nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("user_id", sa.String(64), nullable=True),
        sa.Column("org_id", sa.String(64), nullable=True, index=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("object_type", sa.String(32), nullable=True),
        sa.Column("object_id", sa.String(128), nullable=True),
        sa.Column("detail", postgresql.JSONB, nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    for table in ("audit_log", "targets", "users", "organizations"):
        op.drop_table(table)
    op.drop_index("ix_scans_status", "scans")
    op.drop_column("scans", "requested_by")
    op.drop_column("scans", "status_detail")
