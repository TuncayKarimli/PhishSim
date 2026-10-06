"""Baseline PhishSim v3.0 schema migration.

Revision ID: 0001_baseline_v3
Revises: None
Create Date: 2026-09-30 22:45:00
"""
from sqlalchemy import inspect, text

try:
    from alembic import op
    import sqlalchemy as sa
except ImportError:
    op = None  # type: ignore
    sa = None  # type: ignore

revision = "0001_baseline_v3"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Alembic baseline upgrade creating all PhishSim v3.0 tables."""
    if op is None or sa is None:
        return

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("role", sa.String(length=20), nullable=False, server_default="admin"),
        sa.Column("sso_provider", sa.String(length=40), server_default=""),
        sa.Column("sso_subject", sa.String(length=255), server_default=""),
        sa.Column("totp_secret", sa.String(length=64), server_default=""),
        sa.Column("totp_enabled", sa.Boolean(), server_default=sa.text("0")),
    )

    op.create_table(
        "smtp_profiles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False, server_default="localhost"),
        sa.Column("port", sa.Integer(), nullable=False, server_default="1025"),
        sa.Column("username", sa.String(length=255), server_default=""),
        sa.Column("password", sa.String(length=255), server_default=""),
        sa.Column("use_tls", sa.Boolean(), server_default=sa.text("0")),
        sa.Column("from_address", sa.String(length=255), server_default=""),
        sa.Column("is_default", sa.Boolean(), server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime()),
    )

    op.create_table(
        "landing_pages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("slug", sa.String(length=120), nullable=False, unique=True),
        sa.Column("html_body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime()),
    )

    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("sender", sa.String(length=255), nullable=False),
        sa.Column("difficulty", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("email_body", sa.Text(), nullable=False),
        sa.Column("landing_type", sa.String(length=20), nullable=False, server_default="credentials"),
        sa.Column("landing_page", sa.String(length=30), nullable=False, server_default="custom"),
        sa.Column("landing_company", sa.String(length=255), server_default=""),
        sa.Column("smtp_profile_id", sa.Integer(), sa.ForeignKey("smtp_profiles.id"), nullable=True),
        sa.Column("custom_landing_id", sa.Integer(), sa.ForeignKey("landing_pages.id"), nullable=True),
        sa.Column("attachment_type", sa.String(length=20), server_default="none"),
        sa.Column("attachment_name", sa.String(length=255), server_default=""),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="draft"),
        sa.Column("scheduled_at", sa.DateTime(), nullable=True),
        sa.Column("batch_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("batch_interval", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_batch_at", sa.DateTime(), nullable=True),
        sa.Column("is_followup", sa.Boolean(), server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime()),
    )

    op.create_table(
        "targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("campaign_id", sa.Integer(), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("first_name", sa.String(length=120), server_default=""),
        sa.Column("last_name", sa.String(length=120), server_default=""),
        sa.Column("department", sa.String(length=120), server_default=""),
        sa.Column("location", sa.String(length=120), server_default=""),
        sa.Column("business_unit", sa.String(length=120), server_default=""),
        sa.Column("followup_enrolled", sa.Boolean(), server_default=sa.text("0")),
        sa.Column("token", sa.String(length=64), nullable=False, unique=True),
    )

    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("event_type", sa.String(length=30), nullable=False),
        sa.Column("timestamp", sa.DateTime()),
        sa.Column("ip", sa.String(length=64), server_default=""),
        sa.Column("user_agent", sa.String(length=255), server_default=""),
    )

    op.create_table(
        "templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("difficulty", sa.String(length=20), server_default="medium"),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime()),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_email", sa.String(length=255), server_default="system"),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("details", sa.Text(), server_default=""),
        sa.Column("ip", sa.String(length=64), server_default=""),
        sa.Column("created_at", sa.DateTime()),
    )


def downgrade() -> None:
    if op is None:
        return
    for tbl in (
        "audit_logs",
        "templates",
        "events",
        "targets",
        "campaigns",
        "landing_pages",
        "smtp_profiles",
        "users",
    ):
        op.drop_table(tbl)


def ensure_v3_schema(db) -> None:
    """Idempotently apply any missing v3.0 columns when upgrading an existing v1/v2 database."""
    inspector = inspect(db.engine)
    existing_tables = set(inspector.get_table_names())

    table_migrations = {
        "users": [
            ("sso_provider", "VARCHAR(40) DEFAULT ''"),
            ("sso_subject", "VARCHAR(255) DEFAULT ''"),
            ("totp_secret", "VARCHAR(64) DEFAULT ''"),
            ("totp_enabled", "BOOLEAN DEFAULT 0"),
        ],
        "campaigns": [
            ("difficulty", "VARCHAR(20) DEFAULT 'medium'"),
            ("landing_page", "VARCHAR(30) DEFAULT 'custom'"),
            ("landing_company", "VARCHAR(255) DEFAULT ''"),
            ("smtp_profile_id", "INTEGER"),
            ("custom_landing_id", "INTEGER"),
            ("attachment_type", "VARCHAR(20) DEFAULT 'none'"),
            ("attachment_name", "VARCHAR(255) DEFAULT ''"),
            ("status", "VARCHAR(20) DEFAULT 'draft'"),
            ("scheduled_at", "DATETIME"),
            ("batch_size", "INTEGER DEFAULT 0"),
            ("batch_interval", "INTEGER DEFAULT 0"),
            ("last_batch_at", "DATETIME"),
            ("is_followup", "BOOLEAN DEFAULT 0"),
        ],
        "targets": [
            ("department", "VARCHAR(120) DEFAULT ''"),
            ("location", "VARCHAR(120) DEFAULT ''"),
            ("business_unit", "VARCHAR(120) DEFAULT ''"),
            ("followup_enrolled", "BOOLEAN DEFAULT 0"),
        ],
    }

    for table_name, columns in table_migrations.items():
        if table_name in existing_tables:
            existing_cols = {c["name"] for c in inspector.get_columns(table_name)}
            for col_name, col_def in columns:
                if col_name not in existing_cols:
                    db.session.execute(
                        text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_def}")
                    )
    db.session.commit()
