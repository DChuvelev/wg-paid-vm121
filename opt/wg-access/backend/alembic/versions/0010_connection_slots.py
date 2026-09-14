"""Logical user configuration slots with paired WG/AWG variants.

Revision ID: 0010_connection_slots
Revises: 0009_invite_reg_lifecycle
Create Date: 2026-09-14

The live WireGuard state is the migration source of truth. Every existing WG
profile becomes one logical user configuration slot and receives one AWG child
profile. Commercial quota remains one logical slot limit; legacy protocol-limit
rows are retained only as mirrored compatibility storage.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0010_connection_slots"
down_revision = "0009_invite_reg_lifecycle"
branch_labels = None
depends_on = None



def _validate_legacy_slot_lineage() -> None:
    """Validate only lineage required to pair each historical WG profile.

    Legacy production data may legitimately reference users that have already
    been deleted.  P28F0 does not repair that historical ownership metadata.
    It only requires every profile to retain an existing access grant and that
    the profile/grant owner UUIDs agree, preventing cross-user entitlement
    attachment while preserving orphaned owner UUIDs as soft references.
    """
    op.execute("""
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1
            FROM public.connection_profiles cp
            LEFT JOIN public.access_grants ag ON ag.id = cp.access_grant_id
            WHERE ag.id IS NULL
          ) THEN
            RAISE EXCEPTION 'P28F0 connection profile without access grant';
          END IF;
          IF EXISTS (
            SELECT 1
            FROM public.connection_profiles cp
            JOIN public.access_grants ag ON ag.id = cp.access_grant_id
            WHERE cp.user_id IS DISTINCT FROM ag.user_id
          ) THEN
            RAISE EXCEPTION 'P28F0 profile/access-grant owner mismatch';
          END IF;
        END $$;
    """)


def upgrade() -> None:
    _validate_legacy_slot_lineage()
    op.create_table(
        "connection_slots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("access_grant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("public.access_grants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("node_id", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=160), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        schema="public",
    )
    op.create_index("ix_connection_slots_user_id", "connection_slots", ["user_id"], schema="public")
    op.create_index("ix_connection_slots_access_grant_id", "connection_slots", ["access_grant_id"], schema="public")
    op.create_index("ix_connection_slots_disabled_at", "connection_slots", ["disabled_at"], schema="public")
    op.add_column("connection_profiles", sa.Column("connection_slot_id", postgresql.UUID(as_uuid=True), nullable=True), schema="public")

    op.execute("""
        INSERT INTO public.connection_slots (
            id, user_id, access_grant_id, node_id, label, expires_at,
            created_at, updated_at, disabled_at
        )
        SELECT
            cp.id, cp.user_id, cp.access_grant_id, cp.node_id, cp.label, cp.expires_at,
            cp.created_at, cp.updated_at,
            CASE WHEN cp.status = 'disabled' THEN COALESCE(cp.disabled_at, cp.updated_at) ELSE NULL END
        FROM public.connection_profiles AS cp
        WHERE cp.protocol = 'wireguard'
    """)
    op.execute("UPDATE public.connection_profiles SET connection_slot_id = id WHERE protocol = 'wireguard'")
    op.alter_column("connection_profiles", "connection_slot_id", nullable=False, schema="public")
    op.create_foreign_key(
        "connection_profiles_connection_slot_id_fkey",
        "connection_profiles", "connection_slots",
        ["connection_slot_id"], ["id"], ondelete="CASCADE", source_schema="public", referent_schema="public",
    )
    op.create_index("ix_connection_profiles_connection_slot_id", "connection_profiles", ["connection_slot_id"], schema="public")
    op.create_unique_constraint(
        "uq_connection_profiles_slot_protocol", "connection_profiles", ["connection_slot_id", "protocol"], schema="public"
    )

    # WG is the migration source of truth. If a historical grant lost its WG
    # limit row, preserve exactly its currently-consumed capacity and grant no
    # additional unused capacity.
    op.execute("""
        INSERT INTO public.access_grant_protocol_limits (access_grant_id, protocol, profile_limit)
        SELECT
            g.id,
            'wireguard',
            COALESCE((
                SELECT COUNT(*)::integer
                FROM public.connection_profiles AS cp
                WHERE cp.access_grant_id = g.id
                  AND cp.protocol = 'wireguard'
                  AND cp.status IN ('requested','provisioning','active','disabling','provisioning_failed')
            ), 0)
        FROM public.access_grants AS g
        WHERE NOT EXISTS (
            SELECT 1 FROM public.access_grant_protocol_limits AS wg
            WHERE wg.access_grant_id = g.id AND wg.protocol = 'wireguard'
        )
    """)

    op.execute(
        "UPDATE public.plans SET default_amneziawg_limit = default_wireguard_limit "
        "WHERE default_amneziawg_limit IS DISTINCT FROM default_wireguard_limit"
    )
    op.execute("""
        INSERT INTO public.access_grant_protocol_limits (access_grant_id, protocol, profile_limit)
        SELECT wg.access_grant_id, 'amneziawg', wg.profile_limit
        FROM public.access_grant_protocol_limits AS wg
        WHERE wg.protocol = 'wireguard'
          AND NOT EXISTS (
              SELECT 1 FROM public.access_grant_protocol_limits AS awg
              WHERE awg.access_grant_id = wg.access_grant_id
                AND awg.protocol = 'amneziawg'
          )
    """)
    op.execute("""
        UPDATE public.access_grant_protocol_limits AS awg
        SET profile_limit = wg.profile_limit
        FROM public.access_grant_protocol_limits AS wg
        WHERE awg.access_grant_id = wg.access_grant_id
          AND awg.protocol = 'amneziawg'
          AND wg.protocol = 'wireguard'
          AND awg.profile_limit IS DISTINCT FROM wg.profile_limit
    """)

    # Every historical WG slot gets one AWG child. Runtime preparation happens
    # immediately after alembic via the accepted application service so keys,
    # encrypted credentials, tunnel-IP allocation and jobs use canonical code.
    op.execute("""
        INSERT INTO public.connection_profiles (
            id, connection_slot_id, user_id, access_grant_id, protocol, node_id,
            label, status, tunnel_ip, tunnel_ip_reserved_at, tunnel_ip_released_at,
            expires_at, created_at, updated_at, disabled_at
        )
        SELECT
            gen_random_uuid(),
            wg.connection_slot_id,
            wg.user_id,
            wg.access_grant_id,
            'amneziawg',
            wg.node_id,
            wg.label,
            CASE WHEN wg.status IN ('disabled','disabling') THEN 'disabled' ELSE 'requested' END,
            NULL, NULL, NULL,
            wg.expires_at,
            wg.created_at,
            wg.updated_at,
            CASE
                WHEN wg.status IN ('disabled','disabling') THEN COALESCE(wg.disabled_at, wg.updated_at)
                ELSE NULL
            END
        FROM public.connection_profiles AS wg
        WHERE wg.protocol = 'wireguard'
          AND NOT EXISTS (
              SELECT 1 FROM public.connection_profiles AS awg
              WHERE awg.connection_slot_id = wg.connection_slot_id
                AND awg.protocol = 'amneziawg'
          )
    """)


def downgrade() -> None:
    raise RuntimeError(
        "0010_connection_slots is forward-only; restore the verified pre-migration database backup for rollback"
    )
