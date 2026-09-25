"""Recipient referral policy for admin invites and bulk campaigns.

Revision ID: 0015_recipient_referral_policy
Revises: 0014_bulk_invite_campaigns
"""

from alembic import op
import sqlalchemy as sa

revision = "0015_recipient_referral_policy"
down_revision = "0014_bulk_invite_campaigns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "invites",
        sa.Column("recipient_referrals_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        schema="public",
    )
    op.add_column(
        "invites",
        sa.Column("recipient_referral_limit", sa.Integer(), server_default=sa.text("3"), nullable=False),
        schema="public",
    )
    op.create_check_constraint(
        "invites_recipient_referral_limit_nonnegative",
        "invites",
        "recipient_referral_limit >= 0",
        schema="public",
    )

    op.add_column(
        "bulk_invite_campaigns",
        sa.Column("recipient_referrals_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        schema="public",
    )
    op.add_column(
        "bulk_invite_campaigns",
        sa.Column("recipient_referral_limit", sa.Integer(), server_default=sa.text("3"), nullable=False),
        schema="public",
    )
    op.create_check_constraint(
        "bulk_invite_campaigns_recipient_referral_limit_nonnegative",
        "bulk_invite_campaigns",
        "recipient_referral_limit >= 0",
        schema="public",
    )


def downgrade() -> None:
    raise RuntimeError(
        "0015_recipient_referral_policy is forward-only; restore the verified pre-migration database backup for rollback"
    )
