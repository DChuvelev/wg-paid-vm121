"""Add invite registration lifecycle state and WireGuard limit snapshot.

Revision ID: 0009_invite_reg_lifecycle
Revises: 0008_user_account_metadata
Create Date: 2026-09-10
"""

from alembic import op
import sqlalchemy as sa

revision = "0009_invite_reg_lifecycle"
down_revision = "0008_user_account_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Additive schema only: do not rewrite existing invite business rows.
    # New invites always snapshot the limit. Legacy invites keep NULL and
    # consume falls back to the plan default that governed them previously.
    op.add_column(
        "invites",
        sa.Column("pending_email", sa.String(length=320), nullable=True),
    )
    op.add_column(
        "invites",
        sa.Column("wireguard_profile_limit", sa.Integer(), nullable=True),
    )
    op.create_check_constraint(
        "invites_wireguard_profile_limit_nonnegative",
        "invites",
        "wireguard_profile_limit >= 0",
    )

def downgrade() -> None:
    op.drop_constraint(
        "invites_wireguard_profile_limit_nonnegative",
        "invites",
        type_="check",
    )
    op.drop_column("invites", "wireguard_profile_limit")
    op.drop_column("invites", "pending_email")
