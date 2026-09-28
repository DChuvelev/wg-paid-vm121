"""configuration-scoped forced routing override

Revision ID: 0018_config_routing_override
Revises: 0017_commercial_quantity_periods
"""

from alembic import op
import sqlalchemy as sa


revision = "0018_config_routing_override"
down_revision = "0017_commercial_quantity_periods"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "connection_slots",
        sa.Column("forced_selector", sa.Integer(), nullable=True),
        schema="public",
    )
    op.add_column(
        "connection_slots",
        sa.Column("forced_until", sa.DateTime(timezone=True), nullable=True),
        schema="public",
    )
    op.create_check_constraint(
        "connection_slots_forced_routing_shape",
        "connection_slots",
        "(forced_selector IS NULL AND forced_until IS NULL) OR "
        "(forced_selector IS NOT NULL AND forced_until IS NOT NULL)",
        schema="public",
    )
    op.create_check_constraint(
        "connection_slots_forced_selector_range",
        "connection_slots",
        "forced_selector IS NULL OR forced_selector BETWEEN 1 AND 5",
        schema="public",
    )
    op.create_index(
        "ix_connection_slots_forced_until",
        "connection_slots",
        ["forced_until"],
        schema="public",
    )


def downgrade() -> None:
    raise RuntimeError(
        "0018_config_routing_override is forward-only; restore the verified pre-migration database backup for rollback"
    )
