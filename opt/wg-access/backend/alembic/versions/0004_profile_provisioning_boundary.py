"""Durable Domain V2 profile provisioning boundary.

Revision ID: 0004_profile_provisioning
Revises: 0003_domain_v2_schema
Create Date: 2026-08-16

The tunnel IP remains reserved while non-NULL. Release happens only after a
confirmed VM100 disable ACK, at which point the service clears tunnel_ip.
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_profile_provisioning"
down_revision = "0003_domain_v2_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("connection_profiles", sa.Column("tunnel_ip", sa.String(length=64), nullable=True))
    op.add_column("connection_profiles", sa.Column("tunnel_ip_reserved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("connection_profiles", sa.Column("tunnel_ip_released_at", sa.DateTime(timezone=True), nullable=True))
    op.execute(
        "CREATE UNIQUE INDEX uq_connection_profiles_node_tunnel_ip_reserved "
        "ON public.connection_profiles USING btree (node_id, tunnel_ip) "
        "WHERE tunnel_ip IS NOT NULL"
    )


def downgrade() -> None:
    raise RuntimeError(
        "0004_profile_provisioning is forward-only; restore the encrypted pre-migration backup for rollback"
    )
