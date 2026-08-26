"""Admin staged user deletion marker.

Revision ID: 0006_admin_user_deletion
Revises: 0005_registration_invite_binding
"""

from alembic import op
import sqlalchemy as sa

revision = "0006_admin_user_deletion"
down_revision = "0005_registration_invite_binding"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("deletion_requested_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_users_deletion_requested_at",
        "users",
        ["deletion_requested_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_users_deletion_requested_at", table_name="users")
    op.drop_column("users", "deletion_requested_at")
