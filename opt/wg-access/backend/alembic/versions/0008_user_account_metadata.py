"""Add optional user display name and private admin note.

Revision ID: 0008_user_account_metadata
Revises: 0007_invite_issuer_provenance
Create Date: 2026-09-04
"""

from alembic import op
import sqlalchemy as sa

revision = "0008_user_account_metadata"
down_revision = "0007_invite_issuer_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("display_name", sa.String(length=160), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("admin_note", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "admin_note")
    op.drop_column("users", "display_name")
