"""Admin override for ordinary Commercial invite trial duration.

Revision ID: 0016_admin_invite_trial
Revises: 0015_recipient_referral_policy
"""

from alembic import op
import sqlalchemy as sa

revision = "0016_admin_invite_trial"
down_revision = "0015_recipient_referral_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "invites",
        sa.Column("trial_days_override", sa.Integer(), nullable=True),
        schema="public",
    )
    op.create_check_constraint(
        "invites_trial_days_override_shape",
        "invites",
        "trial_days_override IS NULL OR (trial_days_override >= 1 AND trial_days_override <= 30 AND created_by_kind = 'admin' AND created_by_user_id IS NULL AND bulk_campaign_id IS NULL)",
        schema="public",
    )


def downgrade() -> None:
    raise RuntimeError(
        "0016_admin_invite_trial is forward-only; restore the verified pre-migration database backup for rollback"
    )
