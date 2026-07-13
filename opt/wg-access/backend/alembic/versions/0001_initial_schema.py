"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-07-04
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "invite_codes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column("used_count", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_invite_codes_code", "invite_codes", ["code"], unique=True)

    op.create_table(
        "orders",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("plan_code", sa.String(length=64), nullable=False),
        sa.Column("months", sa.Integer(), nullable=False),
        sa.Column("amount_rub", sa.Numeric(10, 2), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("yookassa_payment_id", sa.String(length=128), nullable=True),
        sa.Column("idempotence_key", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_orders_user_id", "orders", ["user_id"])
    op.create_index("ix_orders_status", "orders", ["status"])
    op.create_unique_constraint("uq_orders_yookassa_payment_id", "orders", ["yookassa_payment_id"])
    op.create_unique_constraint("uq_orders_idempotence_key", "orders", ["idempotence_key"])

    op.create_table(
        "subscriptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("plan_code", sa.String(length=64), nullable=False),
        sa.Column("auto_renew", sa.Boolean(), nullable=False),
        sa.Column("paid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payment_method_id", sa.String(length=128), nullable=True),
        sa.Column("next_charge_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canceled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_subscriptions_user_id", "subscriptions", ["user_id"])
    op.create_index("ix_subscriptions_status", "subscriptions", ["status"])

    op.create_table(
        "peers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("node_id", sa.String(length=64), nullable=False),
        sa.Column("public_key", sa.String(length=128), nullable=False),
        sa.Column("preshared_key", sa.String(length=128), nullable=False),
        sa.Column("tunnel_ip", sa.String(length=64), nullable=False),
        sa.Column("paid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("node_id", "tunnel_ip", name="uq_peers_node_tunnel_ip"),
    )
    op.create_index("ix_peers_user_id", "peers", ["user_id"])
    op.create_index("ix_peers_node_id", "peers", ["node_id"])
    op.create_index("ix_peers_enabled", "peers", ["enabled"])
    op.create_unique_constraint("uq_peers_public_key", "peers", ["public_key"])

    op.create_table(
        "provisioning_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("node_id", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("peer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("peers.id"), nullable=True),
        sa.Column("payload_json", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
    )
    op.create_index("ix_provisioning_jobs_node_id", "provisioning_jobs", ["node_id"])
    op.create_index("ix_provisioning_jobs_status", "provisioning_jobs", ["status"])
    op.create_index("ix_provisioning_jobs_peer_id", "provisioning_jobs", ["peer_id"])


def downgrade() -> None:
    op.drop_table("provisioning_jobs")
    op.drop_table("peers")
    op.drop_table("subscriptions")
    op.drop_table("orders")
    op.drop_table("invite_codes")
    op.drop_table("users")
