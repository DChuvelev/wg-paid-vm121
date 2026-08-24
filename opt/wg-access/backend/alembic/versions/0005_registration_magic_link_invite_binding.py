"""Bind registration magic-link tokens to invitations.

Revision ID: 0005_registration_invite_binding
Revises: 0004_profile_provisioning
Create Date: 2026-08-24

This is a narrow forward-only schema extension. Existing login tokens remain
unchanged because invite_id is nullable.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005_registration_invite_binding"
down_revision = "0004_profile_provisioning"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "magic_link_tokens",
        sa.Column("invite_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "magic_link_tokens_invite_id_fkey",
        "magic_link_tokens",
        "invites",
        ["invite_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_magic_link_tokens_invite_id",
        "magic_link_tokens",
        ["invite_id"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "0005_registration_invite_binding is forward-only; restore the encrypted pre-migration backup for rollback"
    )
