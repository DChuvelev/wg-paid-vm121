"""Per-user referral enablement and active-invite limit.

Revision ID: 0013_user_referral_policy
Revises: 0012_billing_payment_retention
"""

from alembic import op
import sqlalchemy as sa

revision = "0013_user_referral_policy"
down_revision = "0012_billing_payment_retention"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("referrals_enabled", sa.Boolean(), nullable=True, server_default=sa.text("false")),
        schema="public",
    )
    op.add_column(
        "users",
        sa.Column("referral_limit", sa.Integer(), nullable=True, server_default=sa.text("3")),
        schema="public",
    )
    op.execute(
        sa.text(
            "UPDATE public.users "
            "SET referrals_enabled = false, referral_limit = 3 "
            "WHERE referrals_enabled IS NULL OR referral_limit IS NULL"
        )
    )
    op.alter_column(
        "users",
        "referrals_enabled",
        existing_type=sa.Boolean(),
        nullable=False,
        server_default=sa.text("false"),
        schema="public",
    )
    op.alter_column(
        "users",
        "referral_limit",
        existing_type=sa.Integer(),
        nullable=False,
        server_default=sa.text("3"),
        schema="public",
    )
    op.create_check_constraint(
        "users_referral_limit_nonnegative",
        "users",
        "referral_limit >= 0",
        schema="public",
    )


def downgrade() -> None:
    raise RuntimeError(
        "0013_user_referral_policy is forward-only; restore the verified pre-migration database backup for rollback"
    )
