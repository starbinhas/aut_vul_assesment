"""Schema inicial: scans, findings, processed_messages, stage_progress, reports, remediation_cache.

Revision ID: 0001
Revises:
Create Date: 2026-10-06
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    # Escrita pela etapa 1 (autorização); as etapas 4-6 só leem.
    op.create_table(
        "scans",
        sa.Column("scan_id", sa.String(64), primary_key=True),
        sa.Column("target_id", sa.String(64), nullable=False, index=True),
        sa.Column("verified", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("scope_locked", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("scope", postgresql.JSONB, nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "findings",
        sa.Column("finding_id", sa.String(64), primary_key=True),
        sa.Column(
            "scan_id", sa.String(64), sa.ForeignKey("scans.scan_id"), nullable=False, index=True
        ),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("cwe", sa.Integer, nullable=True),
        sa.Column("data", postgresql.JSONB, nullable=False),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_findings_scan_status", "findings", ["scan_id", "status"])
    op.create_table(
        "processed_messages",
        sa.Column("stream", sa.String(64), primary_key=True),
        sa.Column("message_id", sa.String(128), primary_key=True),
        sa.Column("processed_at", TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "stage_progress",
        sa.Column("scan_id", sa.String(64), sa.ForeignKey("scans.scan_id"), primary_key=True),
        sa.Column("tool", sa.String(16), primary_key=True),
        sa.Column("done_at", TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "reports",
        sa.Column("scan_id", sa.String(64), sa.ForeignKey("scans.scan_id"), primary_key=True),
        sa.Column("report_json", postgresql.JSONB, nullable=False),
        sa.Column("html", sa.Text, nullable=False),
        sa.Column("pdf", sa.LargeBinary, nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "remediation_cache",
        sa.Column("cache_key", sa.String(64), primary_key=True),
        sa.Column("rule", sa.String(64), nullable=False),
        sa.Column("stack", sa.String(128), nullable=False),
        sa.Column("language", sa.String(16), nullable=False),
        sa.Column("prompt_version", sa.String(32), nullable=False),
        sa.Column("content", postgresql.JSONB, nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    for table in (
        "remediation_cache",
        "reports",
        "stage_progress",
        "processed_messages",
        "findings",
        "scans",
    ):
        op.drop_table(table)
