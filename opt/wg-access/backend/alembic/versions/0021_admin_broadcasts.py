"""Private Admin broadcasts; immutable recipient snapshots.

Revision ID: 0021_admin_broadcasts
Revises: 0020_hmn_event_history
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
from alembic import op

revision = "0021_admin_broadcasts"
down_revision = "0020_hmn_event_history"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_broadcasts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("audience", sa.String(16), nullable=False),
        sa.Column("subject", sa.String(200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("recipient_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True)),
        sa.Column("test_attempted_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("audience IN ('active','all')", name="admin_broadcast_audience_allowed"),
        sa.CheckConstraint("state IN ('draft','queued','sending','paused','completed','completed_with_uncertain')", name="admin_broadcast_state_allowed"),
        sa.CheckConstraint("recipient_count >= 0", name="admin_broadcast_count_nonnegative"),
    )
    op.create_index("ix_admin_broadcasts_created_at", "admin_broadcasts", ["created_at"])
    op.create_table(
        "admin_broadcast_recipients",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("broadcast_id", UUID(as_uuid=True), sa.ForeignKey("admin_broadcasts.id", ondelete="CASCADE"), nullable=False),
        # Accepted legacy users.id cannot be used as a new FK target.
        # Keep the optional UUID as a service-validated soft reference.
        sa.Column("user_id", UUID(as_uuid=True)),
        sa.Column("normalized_email", sa.String(320), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("accepted_at", sa.DateTime(timezone=True)),
        sa.Column("failure_category", sa.String(40)),
        sa.UniqueConstraint("broadcast_id", "normalized_email", name="uq_admin_broadcast_recipient_email"),
        sa.CheckConstraint("state IN ('pending','in_flight','smtp_accepted','uncertain','skipped')", name="admin_broadcast_recipient_state_allowed"),
    )
    op.create_index("ix_admin_broadcast_recipients_broadcast_id", "admin_broadcast_recipients", ["broadcast_id"])
    op.create_index("ix_admin_broadcast_recipients_state", "admin_broadcast_recipients", ["state"])
    op.create_index("ix_admin_broadcast_recipients_claimed_at", "admin_broadcast_recipients", ["claimed_at"])


def downgrade() -> None:
    op.drop_index("ix_admin_broadcast_recipients_claimed_at", "admin_broadcast_recipients")
    op.drop_index("ix_admin_broadcast_recipients_state", "admin_broadcast_recipients")
    op.drop_index("ix_admin_broadcast_recipients_broadcast_id", "admin_broadcast_recipients")
    op.drop_table("admin_broadcast_recipients")
    op.drop_index("ix_admin_broadcasts_created_at", "admin_broadcasts")
    op.drop_table("admin_broadcasts")
