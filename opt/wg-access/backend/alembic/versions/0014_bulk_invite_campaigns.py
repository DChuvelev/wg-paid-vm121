"""Admin-only reusable bulk invite campaigns with isolated child invites.

Revision ID: 0014_bulk_invite_campaigns
Revises: 0013_user_referral_policy
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0014_bulk_invite_campaigns"
down_revision = "0013_user_referral_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "bulk_invite_campaigns",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("label", sa.String(length=160), nullable=False),
        # Soft reference by design: do not introduce a new FK to historical plans.id.
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("max_registrations", sa.Integer(), nullable=False),
        sa.Column("used_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("trial_days", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("max_registrations >= 1", name="bulk_invite_campaigns_max_positive"),
        sa.CheckConstraint(
            "used_count >= 0 AND used_count <= max_registrations",
            name="bulk_invite_campaigns_used_count_range",
        ),
        sa.CheckConstraint("trial_days >= 1", name="bulk_invite_campaigns_trial_days_positive"),
        sa.PrimaryKeyConstraint("id", name="bulk_invite_campaigns_pkey"),
        sa.UniqueConstraint("token_hash", name="bulk_invite_campaigns_token_hash_key"),
        schema="public",
    )
    op.create_index(
        "ix_bulk_invite_campaigns_plan_id",
        "bulk_invite_campaigns",
        ["plan_id"],
        unique=False,
        schema="public",
    )
    op.create_index(
        "ix_bulk_invite_campaigns_expires_at",
        "bulk_invite_campaigns",
        ["expires_at"],
        unique=False,
        schema="public",
    )

    op.add_column(
        "invites",
        sa.Column("bulk_campaign_id", postgresql.UUID(as_uuid=True), nullable=True),
        schema="public",
    )
    op.create_foreign_key(
        "invites_bulk_campaign_id_fkey",
        "invites",
        "bulk_invite_campaigns",
        ["bulk_campaign_id"],
        ["id"],
        source_schema="public",
        referent_schema="public",
    )
    op.create_index(
        "ix_invites_bulk_campaign_id",
        "invites",
        ["bulk_campaign_id"],
        unique=False,
        schema="public",
    )
    op.create_unique_constraint(
        "uq_invites_bulk_campaign_email",
        "invites",
        ["bulk_campaign_id", "intended_email"],
        schema="public",
    )
    op.create_check_constraint(
        "invites_bulk_child_shape_check",
        "invites",
        "bulk_campaign_id IS NULL OR (intended_email IS NOT NULL AND created_by_kind = 'system' AND created_by_user_id IS NULL AND max_uses = 1)",
        schema="public",
    )


def downgrade() -> None:
    raise RuntimeError(
        "0014_bulk_invite_campaigns is forward-only; restore the verified pre-migration database backup for rollback"
    )
