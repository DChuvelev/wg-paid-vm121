"""Domain V2 schema foundation.

Revision ID: 0003_domain_v2_schema
Revises: 0002_live_drift_bridge
Create Date: 2026-08-10

This revision intentionally contains schema only. It does not migrate or recreate
retired legacy development rows and it does not seed product/business data.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003_domain_v2_schema"
down_revision = "0002_live_drift_bridge"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Domain V2 User identity. Live business data is empty at the P22B baseline,
    # so verified normalized identity can become the only valid new User shape.
    op.add_column("users", sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.alter_column("users", "email", existing_type=sa.String(length=320), nullable=False)
    op.alter_column("users", "email_verified_at", existing_type=sa.DateTime(timezone=True), nullable=False)
    op.drop_index("ix_users_email", table_name="users")
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "plans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=160), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("default_wireguard_limit", sa.Integer(), nullable=False, server_default=sa.text("3")),
        sa.Column("default_amneziawg_limit", sa.Integer(), nullable=False, server_default=sa.text("3")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("default_wireguard_limit >= 0", name="plans_default_wireguard_limit_nonnegative"),
        sa.CheckConstraint("default_amneziawg_limit >= 0", name="plans_default_amneziawg_limit_nonnegative"),
        sa.UniqueConstraint("code", name="uq_plans_code"),
    )

    op.create_table(
        "access_grants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("plans.id"), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_ref", sa.String(length=160), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("source_type", "source_ref", name="uq_access_grants_source"),
    )
    op.create_index("ix_access_grants_user_id", "access_grants", ["user_id"])
    op.create_index("ix_access_grants_status", "access_grants", ["status"])

    op.create_table(
        "access_grant_protocol_limits",
        sa.Column("access_grant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("access_grants.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("protocol", sa.String(length=32), primary_key=True),
        sa.Column("profile_limit", sa.Integer(), nullable=False),
        sa.CheckConstraint("protocol IN ('wireguard','amneziawg')", name="access_grant_protocol_limits_protocol_check"),
        sa.CheckConstraint("profile_limit >= 0", name="access_grant_protocol_limits_profile_limit_nonnegative"),
    )

    op.create_table(
        "invites",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("intended_email", sa.String(length=320), nullable=True),
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("plans.id"), nullable=True),
        sa.Column("max_uses", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("used_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("max_uses >= 1", name="invites_max_uses_positive"),
        sa.CheckConstraint("used_count >= 0 AND used_count <= max_uses", name="invites_used_count_range"),
        sa.UniqueConstraint("token_hash", name="uq_invites_token_hash"),
    )

    op.create_table(
        "invite_redemptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("invite_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("invites.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("redeemed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("invite_id", "user_id", name="uq_invite_redemptions_invite_user"),
    )
    op.create_index("ix_invite_redemptions_user_id", "invite_redemptions", ["user_id"])

    op.create_table(
        "magic_link_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("token_hash", name="uq_magic_link_tokens_token_hash"),
    )
    op.create_index("ix_magic_link_tokens_email", "magic_link_tokens", ["email"])
    op.create_index("ix_magic_link_tokens_user_id", "magic_link_tokens", ["user_id"])

    op.create_table(
        "auth_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("token_hash", name="uq_auth_sessions_token_hash"),
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])

    op.create_table(
        "connection_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("access_grant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("access_grants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("node_id", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=160), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("protocol IN ('wireguard','amneziawg')", name="connection_profiles_protocol_check"),
    )
    op.create_index("ix_connection_profiles_user_id", "connection_profiles", ["user_id"])
    op.create_index("ix_connection_profiles_access_grant_id", "connection_profiles", ["access_grant_id"])
    op.create_index("ix_connection_profiles_status", "connection_profiles", ["status"])

    op.create_table(
        "peer_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("connection_profile_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("connection_profiles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("public_key", sa.String(length=128), nullable=True),
        sa.Column("secret_ciphertext", sa.Text(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("revision >= 1", name="peer_credentials_revision_positive"),
        sa.CheckConstraint("key_version >= 1", name="peer_credentials_key_version_positive"),
        sa.UniqueConstraint("connection_profile_id", "revision", name="uq_peer_credentials_profile_revision"),
        sa.UniqueConstraint("public_key", name="uq_peer_credentials_public_key"),
    )
    op.create_index("ix_peer_credentials_connection_profile_id", "peer_credentials", ["connection_profile_id"])

    # Extend the legacy empty job table in a backward-compatible way. Old agent
    # columns remain present until Domain V2 service integration is activated.
    op.add_column("provisioning_jobs", sa.Column("connection_profile_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("provisioning_jobs", sa.Column("operation_id", sa.String(length=128), nullable=True))
    op.add_column("provisioning_jobs", sa.Column("desired_generation", sa.String(length=128), nullable=True))
    op.add_column("provisioning_jobs", sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True))
    op.create_foreign_key(
        "provisioning_jobs_connection_profile_id_fkey",
        "provisioning_jobs",
        "connection_profiles",
        ["connection_profile_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_unique_constraint("uq_provisioning_jobs_operation_id", "provisioning_jobs", ["operation_id"])
    op.create_index("ix_provisioning_jobs_connection_profile_id", "provisioning_jobs", ["connection_profile_id"])
    op.create_index("ix_provisioning_jobs_next_attempt_at", "provisioning_jobs", ["next_attempt_at"])

    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("actor_kind", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=96), nullable=False),
        sa.Column("object_type", sa.String(length=64), nullable=True),
        sa.Column("object_id", sa.String(length=160), nullable=True),
        sa.Column("request_id", sa.String(length=128), nullable=True),
        sa.Column("payload_json", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("ix_audit_events_actor_user_id", "audit_events", ["actor_user_id"])
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])
    op.create_index("ix_audit_events_occurred_at", "audit_events", ["occurred_at"])
    op.create_index("ix_audit_events_request_id", "audit_events", ["request_id"])

    # Future payment/order implementations can point to the entitlement they
    # created or extended without making payment records entitlement authority.
    op.add_column("orders", sa.Column("access_grant_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        "orders_access_grant_id_fkey",
        "orders",
        "access_grants",
        ["access_grant_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_orders_access_grant_id", "orders", ["access_grant_id"])


def downgrade() -> None:
    raise RuntimeError(
        "0003_domain_v2_schema is intentionally forward-only; restore the encrypted pre-migration backup for rollback instead of destructive Alembic downgrade"
    )
