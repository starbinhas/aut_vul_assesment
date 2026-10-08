"""Cópia de teste (homologação) autorizada: libera o perfil intrusivo fora do laboratório.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-08
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "staging_authorizations",
        sa.Column("auth_id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("production_target_id", sa.String(length=64), nullable=False),
        sa.Column("staging_target_id", sa.String(length=64), nullable=False),
        sa.Column("staging_host", sa.String(length=253), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("checklist", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("term_version", sa.String(length=32), nullable=True),
        sa.Column("term_sha256", sa.String(length=64), nullable=True),
        sa.Column("signer_name", sa.String(length=200), nullable=True),
        sa.Column("signer_role", sa.String(length=200), nullable=True),
        sa.Column("signer_user_id", sa.String(length=64), nullable=True),
        sa.Column("signer_ip", sa.String(length=64), nullable=True),
        sa.Column("emergency_contact", sa.String(length=200), nullable=True),
        sa.Column("valid_days", sa.Integer(), nullable=True),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", sa.String(length=64), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_note", sa.String(length=500), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.org_id"]),
        sa.ForeignKeyConstraint(["production_target_id"], ["targets.target_id"]),
        sa.ForeignKeyConstraint(["staging_target_id"], ["targets.target_id"]),
        sa.PrimaryKeyConstraint("auth_id"),
    )
    for column in ("org_id", "production_target_id", "staging_target_id"):
        op.create_index(f"ix_staging_authorizations_{column}", "staging_authorizations", [column])


def downgrade() -> None:
    op.drop_table("staging_authorizations")
