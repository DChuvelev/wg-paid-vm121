"""bridge unversioned live drift into Alembic history

Revision ID: 0002_live_drift_bridge
Revises: 0001_initial_schema
Create Date: 2026-08-09

This revision is deliberately PostgreSQL-specific.  It supports two starting
states:

1. a clean database produced by 0001_initial_schema; or
2. the captured VM121 live database where the three historical egress tables
   and the enabled-only tunnel-IP index already exist outside Alembic history.

Existing historical egress objects are preserved.  This revision does not
introduce Domain V2 objects and does not migrate user identities/entitlements.
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_live_drift_bridge"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def _rows(sql: str, **params):
    return op.get_bind().execute(sa.text(sql), params).fetchall()


def _scalar(sql: str, **params):
    return op.get_bind().execute(sa.text(sql), params).scalar()


def _table_exists(name: str) -> bool:
    return _scalar("SELECT to_regclass(:name) IS NOT NULL", name=f"public.{name}") is True


def _column_names(table: str) -> set[str]:
    return {
        row[0]
        for row in _rows(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema='public' AND table_name=:table
            ORDER BY ordinal_position
            """,
            table=table,
        )
    }


def _constraint_names(table: str) -> set[str]:
    return {
        row[0]
        for row in _rows(
            """
            SELECT c.conname
            FROM pg_constraint c
            JOIN pg_class r ON r.oid=c.conrelid
            JOIN pg_namespace n ON n.oid=r.relnamespace
            WHERE n.nspname='public' AND r.relname=:table
            ORDER BY c.conname
            """,
            table=table,
        )
    }


def _index_names(table: str) -> set[str]:
    return {
        row[0]
        for row in _rows(
            """
            SELECT indexname
            FROM pg_indexes
            WHERE schemaname='public' AND tablename=:table
            ORDER BY indexname
            """,
            table=table,
        )
    }


def _require_exact(actual: set[str], expected: set[str], label: str) -> None:
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise RuntimeError(f"bridge schema mismatch for {label}: missing={missing} extra={extra}")


def _validate_existing_egress_allocator_settings() -> None:
    _require_exact(
        _column_names("egress_allocator_settings"),
        {"key", "value_text", "value_int", "description", "updated_at"},
        "egress_allocator_settings.columns",
    )
    _require_exact(
        _constraint_names("egress_allocator_settings"),
        {"egress_allocator_settings_pkey"},
        "egress_allocator_settings.constraints",
    )
    _require_exact(
        _index_names("egress_allocator_settings"),
        {"egress_allocator_settings_pkey"},
        "egress_allocator_settings.indexes",
    )


def _validate_existing_egress_targets() -> None:
    _require_exact(
        _column_names("egress_targets"),
        {
            "id", "egress_class", "route_table", "fwmark", "interface_name",
            "kind", "status", "weight", "is_emergency", "description",
            "created_at", "updated_at",
        },
        "egress_targets.columns",
    )
    _require_exact(
        _constraint_names("egress_targets"),
        {
            "egress_targets_egress_class_check",
            "egress_targets_egress_class_key",
            "egress_targets_kind_check",
            "egress_targets_pkey",
            "egress_targets_status_check",
        },
        "egress_targets.constraints",
    )
    _require_exact(
        _index_names("egress_targets"),
        {"egress_targets_egress_class_key", "egress_targets_pkey"},
        "egress_targets.indexes",
    )


def _validate_existing_peer_egress_leases() -> None:
    _require_exact(
        _column_names("peer_egress_leases"),
        {
            "id", "peer_id", "tunnel_ip", "egress_class", "target_id",
            "assigned_at", "last_activity_at", "last_rx_packets",
            "last_tx_packets", "last_rx_bytes", "last_tx_bytes", "state",
            "assignment_source", "forced", "reason", "cooldown_until",
            "updated_at",
        },
        "peer_egress_leases.columns",
    )
    _require_exact(
        _constraint_names("peer_egress_leases"),
        {
            "peer_egress_leases_assignment_source_check",
            "peer_egress_leases_egress_class_check",
            "peer_egress_leases_peer_id_fkey",
            "peer_egress_leases_pkey",
            "peer_egress_leases_state_check",
            "peer_egress_leases_target_id_fkey",
        },
        "peer_egress_leases.constraints",
    )
    _require_exact(
        _index_names("peer_egress_leases"),
        {
            "peer_egress_leases_class_state_idx",
            "peer_egress_leases_forced_idx",
            "peer_egress_leases_peer_id_uq",
            "peer_egress_leases_pkey",
            "peer_egress_leases_target_id_idx",
            "peer_egress_leases_tunnel_ip_uq",
            "peer_egress_leases_updated_at_idx",
        },
        "peer_egress_leases.indexes",
    )


def _bridge_peer_tunnel_uniqueness() -> None:
    constraints = _constraint_names("peers")
    indexes = _index_names("peers")
    full_constraint = "uq_peers_node_tunnel_ip" in constraints
    partial_index = "uq_peers_node_tunnel_ip_enabled" in indexes

    if full_constraint:
        op.drop_constraint("uq_peers_node_tunnel_ip", "peers", type_="unique")

    if not partial_index:
        duplicate_enabled = int(
            _scalar(
                """
                SELECT count(*) FROM (
                  SELECT node_id, tunnel_ip
                  FROM public.peers
                  WHERE enabled IS TRUE
                  GROUP BY node_id, tunnel_ip
                  HAVING count(*) > 1
                ) d
                """
            )
            or 0
        )
        if duplicate_enabled != 0:
            raise RuntimeError("cannot create enabled-only tunnel-IP unique index: enabled duplicates exist")
        op.execute(
            "CREATE UNIQUE INDEX uq_peers_node_tunnel_ip_enabled "
            "ON public.peers USING btree (node_id, tunnel_ip) WHERE (enabled = true)"
        )
    else:
        indexdef = str(
            _scalar(
                """
                SELECT indexdef FROM pg_indexes
                WHERE schemaname='public' AND tablename='peers'
                  AND indexname='uq_peers_node_tunnel_ip_enabled'
                """
            )
            or ""
        ).lower()
        required = (
            "create unique index",
            "(node_id, tunnel_ip)",
            "where (enabled = true)",
        )
        if not all(token in indexdef for token in required):
            raise RuntimeError(f"unexpected uq_peers_node_tunnel_ip_enabled definition: {indexdef}")


def _create_egress_allocator_settings() -> None:
    op.execute(
        """
        CREATE TABLE public.egress_allocator_settings (
          key text NOT NULL,
          value_text text NOT NULL,
          value_int integer,
          description text DEFAULT ''::text NOT NULL,
          updated_at timestamp with time zone DEFAULT now() NOT NULL,
          CONSTRAINT egress_allocator_settings_pkey PRIMARY KEY (key)
        )
        """
    )


def _create_egress_targets() -> None:
    op.execute(
        """
        CREATE TABLE public.egress_targets (
          id text NOT NULL,
          egress_class text,
          route_table integer,
          fwmark text,
          interface_name text NOT NULL,
          kind text DEFAULT 'vpn'::text NOT NULL,
          status text DEFAULT 'enabled'::text NOT NULL,
          weight integer DEFAULT 100 NOT NULL,
          is_emergency boolean DEFAULT false NOT NULL,
          description text DEFAULT ''::text NOT NULL,
          created_at timestamp with time zone DEFAULT now() NOT NULL,
          updated_at timestamp with time zone DEFAULT now() NOT NULL,
          CONSTRAINT egress_targets_pkey PRIMARY KEY (id),
          CONSTRAINT egress_targets_egress_class_key UNIQUE (egress_class),
          CONSTRAINT egress_targets_egress_class_check CHECK ((egress_class IS NULL) OR (egress_class = ANY (ARRAY['cs1'::text, 'cs2'::text, 'cs3'::text, 'cs4'::text, 'cs5'::text]))),
          CONSTRAINT egress_targets_kind_check CHECK (kind = ANY (ARRAY['vpn'::text, 'direct'::text, 'emergency'::text, 'custom'::text])),
          CONSTRAINT egress_targets_status_check CHECK (status = ANY (ARRAY['enabled'::text, 'disabled'::text, 'maintenance'::text]))
        )
        """
    )


def _create_peer_egress_leases() -> None:
    op.execute(
        """
        CREATE TABLE public.peer_egress_leases (
          id uuid DEFAULT gen_random_uuid() NOT NULL,
          peer_id uuid NOT NULL,
          tunnel_ip inet NOT NULL,
          egress_class text NOT NULL,
          target_id text,
          assigned_at timestamp with time zone DEFAULT now() NOT NULL,
          last_activity_at timestamp with time zone,
          last_rx_packets bigint DEFAULT 0 NOT NULL,
          last_tx_packets bigint DEFAULT 0 NOT NULL,
          last_rx_bytes bigint DEFAULT 0 NOT NULL,
          last_tx_bytes bigint DEFAULT 0 NOT NULL,
          state text DEFAULT 'idle'::text NOT NULL,
          assignment_source text DEFAULT 'bootstrap'::text NOT NULL,
          forced boolean DEFAULT false NOT NULL,
          reason text DEFAULT 'bootstrap'::text NOT NULL,
          cooldown_until timestamp with time zone,
          updated_at timestamp with time zone DEFAULT now() NOT NULL,
          CONSTRAINT peer_egress_leases_pkey PRIMARY KEY (id),
          CONSTRAINT peer_egress_leases_peer_id_fkey FOREIGN KEY (peer_id) REFERENCES public.peers(id) ON DELETE CASCADE,
          CONSTRAINT peer_egress_leases_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.egress_targets(id),
          CONSTRAINT peer_egress_leases_egress_class_check CHECK (egress_class = ANY (ARRAY['cs1'::text, 'cs2'::text, 'cs3'::text, 'cs4'::text, 'cs5'::text])),
          CONSTRAINT peer_egress_leases_state_check CHECK (state = ANY (ARRAY['active'::text, 'idle'::text, 'expired'::text])),
          CONSTRAINT peer_egress_leases_assignment_source_check CHECK (assignment_source = ANY (ARRAY['bootstrap'::text, 'allocator'::text, 'manual_override'::text, 'emergency_override'::text, 'maintenance_override'::text]))
        )
        """
    )
    op.execute("CREATE UNIQUE INDEX peer_egress_leases_peer_id_uq ON public.peer_egress_leases USING btree (peer_id)")
    op.execute("CREATE UNIQUE INDEX peer_egress_leases_tunnel_ip_uq ON public.peer_egress_leases USING btree (tunnel_ip)")
    op.execute("CREATE INDEX peer_egress_leases_class_state_idx ON public.peer_egress_leases USING btree (egress_class, state)")
    op.execute("CREATE INDEX peer_egress_leases_forced_idx ON public.peer_egress_leases USING btree (forced)")
    op.execute("CREATE INDEX peer_egress_leases_target_id_idx ON public.peer_egress_leases USING btree (target_id)")
    op.execute("CREATE INDEX peer_egress_leases_updated_at_idx ON public.peer_egress_leases USING btree (updated_at)")


def upgrade() -> None:
    _bridge_peer_tunnel_uniqueness()

    if _table_exists("egress_allocator_settings"):
        _validate_existing_egress_allocator_settings()
    else:
        _create_egress_allocator_settings()

    if _table_exists("egress_targets"):
        _validate_existing_egress_targets()
    else:
        _create_egress_targets()

    if _table_exists("peer_egress_leases"):
        _validate_existing_peer_egress_leases()
    else:
        _create_peer_egress_leases()


def downgrade() -> None:
    raise RuntimeError(
        "0002_live_drift_bridge is intentionally irreversible; restore the encrypted pre-migration backup instead of destructive Alembic downgrade"
    )
