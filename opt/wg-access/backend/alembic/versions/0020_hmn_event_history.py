"""Sanitized HMN history, source coverage, idempotent ingestion.

Revision ID: 0020_hmn_event_history
Revises: 0019_runtime_activity_minute
"""
from alembic import op
import sqlalchemy as sa

revision = "0020_hmn_event_history"
down_revision = "0019_runtime_activity_minute"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hmn_ingest_batch",
        sa.Column("batch_id", sa.String(64), primary_key=True),
        sa.Column("source_stream", sa.String(16), nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("collected_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_events", sa.Integer(), nullable=False),
        sa.CheckConstraint("source_stream IN ('health','recovery')", name="hmn_batch_stream_allowed"),
        schema="public",
    )
    op.create_index("ix_hmn_batch_ingested", "hmn_ingest_batch", ["ingested_at_utc"], schema="public")
    op.create_table(
        "hmn_event",
        sa.Column("event_id", sa.String(64), primary_key=True),
        sa.Column("source_stream", sa.String(16), nullable=False),
        sa.Column("source_generation", sa.String(32), nullable=False),
        sa.Column("source_record_index", sa.BigInteger(), nullable=False),
        sa.Column("source_coverage_epoch", sa.String(32), nullable=False),
        sa.Column("event_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("egress_slot", sa.SmallInteger(), nullable=True),
        sa.Column("provenance", sa.String(32), nullable=False),
        sa.Column("event_payload_sha256", sa.String(64), nullable=False),
        sa.UniqueConstraint("source_stream", "source_generation", "source_record_index", name="uq_hmn_stream_generation_record"),
        sa.CheckConstraint("source_stream IN ('health','recovery')", name="hmn_event_stream_allowed"),
        sa.CheckConstraint("egress_slot BETWEEN 1 AND 5 OR egress_slot IS NULL", name="hmn_event_slot_allowed"),
        sa.CheckConstraint("provenance IN ('forward_live','historical_retained_only')", name="hmn_event_provenance_allowed"),
        schema="public",
    )
    op.create_index("ix_hmn_event_at", "hmn_event", ["event_at_utc"], schema="public")
    op.create_index("ix_hmn_event_stream_at", "hmn_event", ["source_stream", "event_at_utc"], schema="public")
    op.create_table(
        "hmn_stream_coverage",
        sa.Column("source_stream", sa.String(16), primary_key=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("continuity", sa.String(24), nullable=False),
        sa.Column("last_coverage_epoch", sa.String(32), nullable=False),
        sa.Column("last_gap_first_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_gap_last_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("gap_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("unknown_lines_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("heartbeat_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("ingested_events_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.CheckConstraint("source_stream IN ('health','recovery')", name="hmn_coverage_stream_allowed"),
        sa.CheckConstraint("continuity IN ('continuous','gap_detected','initial_unknown','stale','error')", name="hmn_coverage_state_allowed"),
        schema="public",
    )


def downgrade() -> None:
    op.drop_table("hmn_stream_coverage", schema="public")
    op.drop_index("ix_hmn_event_stream_at", table_name="hmn_event", schema="public")
    op.drop_index("ix_hmn_event_at", table_name="hmn_event", schema="public")
    op.drop_table("hmn_event", schema="public")
    op.drop_index("ix_hmn_batch_ingested", table_name="hmn_ingest_batch", schema="public")
    op.drop_table("hmn_ingest_batch", schema="public")
