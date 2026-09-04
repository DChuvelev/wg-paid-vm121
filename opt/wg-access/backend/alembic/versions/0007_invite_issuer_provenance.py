"""Persist durable invite issuer provenance for admin/user-issued invites.

Revision ID: 0007_invite_issuer_provenance
Revises: 0006_admin_user_deletion
Create Date: 2026-09-04

Existing rows are backfilled without guessing registration ownership: rows that
already reference a creator user retain that user provenance and snapshot the
current user email; rows without a creator user are the currently-supported
admin-issued invites and are backfilled as Admin.
"""

from alembic import op
import sqlalchemy as sa

revision = "0007_invite_issuer_provenance"
down_revision = "0006_admin_user_deletion"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "invites",
        sa.Column("created_by_kind", sa.String(length=16), nullable=True),
    )
    op.add_column(
        "invites",
        sa.Column("created_by_label", sa.String(length=320), nullable=True),
    )

    op.execute(
        """
        UPDATE invites AS i
        SET created_by_kind = 'user', created_by_label = u.email
        FROM users AS u
        WHERE i.created_by_user_id = u.id
        """
    )
    op.execute(
        """
        UPDATE invites
        SET created_by_kind = 'admin', created_by_label = 'Admin'
        WHERE created_by_kind IS NULL
        """
    )

    op.alter_column("invites", "created_by_kind", nullable=False)
    op.alter_column("invites", "created_by_label", nullable=False)
    op.create_check_constraint(
        "invites_created_by_kind_check",
        "invites",
        "created_by_kind IN ('admin','user','system')",
    )


def downgrade() -> None:
    op.drop_constraint("invites_created_by_kind_check", "invites", type_="check")
    op.drop_column("invites", "created_by_label")
    op.drop_column("invites", "created_by_kind")
