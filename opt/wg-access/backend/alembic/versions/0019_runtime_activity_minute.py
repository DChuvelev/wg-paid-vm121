"""Anonymous minute-level runtime activity observations.

Revision ID: 0019_runtime_activity_minute
Revises: 0018_config_routing_override
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0019_runtime_activity_minute"
down_revision = "0018_config_routing_override"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runtime_activity_minute",
        sa.Column("minute_utc", sa.DateTime(timezone=True), primary_key=True),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("valid_sample_count", sa.Integer(), nullable=False),
        sa.Column("expected_sample_count", sa.Integer(), nullable=False),
        sa.Column("coverage_ratio", sa.Float(), nullable=False),
        sa.Column("coverage_status", sa.String(16), nullable=False),
        sa.Column("active_configurations_peak", sa.Integer(), nullable=True),
        sa.Column("active_configurations_mean", sa.Float(), nullable=True),
        sa.Column("active_users_peak", sa.Integer(), nullable=True),
        sa.Column("active_users_mean", sa.Float(), nullable=True),
        sa.Column("selector_peak", postgresql.JSONB(), nullable=False),
        sa.Column("selector_mean", postgresql.JSONB(), nullable=False),
        sa.Column("unmatched_rows_total", sa.Integer(), nullable=False),
        sa.Column("conflicted_slots_total", sa.Integer(), nullable=False),
        sa.Column("first_received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.CheckConstraint("sample_count > 0", name="runtime_activity_sample_positive"),
        sa.CheckConstraint("valid_sample_count BETWEEN 0 AND sample_count", name="runtime_activity_valid_sample_range"),
        sa.CheckConstraint("expected_sample_count > 0", name="runtime_activity_expected_positive"),
        sa.CheckConstraint("coverage_ratio BETWEEN 0 AND 1", name="runtime_activity_coverage_range"),
        sa.CheckConstraint("coverage_status IN ('complete','partial','unknown')", name="runtime_activity_coverage_status_allowed"),
        schema="public",
    )


def downgrade() -> None:
    # This revision owns only a new telemetry table. Dropping it cannot
    # roll back unrelated payments, users or commercial state.
    op.drop_table("runtime_activity_minute", schema="public")
