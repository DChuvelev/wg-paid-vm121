"""Commercial quantity periods, one-next-period state and scheduled retirement.

Revision ID: 0017_commercial_quantity_periods
Revises: 0016_admin_invite_trial
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0017_commercial_quantity_periods"
down_revision = "0016_admin_invite_trial"
branch_labels = None
depends_on = None


def _eq(a, b) -> bool:
    return a == b


def upgrade() -> None:
    bind = op.get_bind()

    inflight = int(bind.execute(sa.text(
        "SELECT count(*) FROM public.billing_payments WHERE status IN ('created','pending')"
    )).scalar_one())
    if inflight != 0:
        raise RuntimeError(f"0017 requires zero in-flight billing payments; found {inflight}")

    legacy_pending = int(bind.execute(sa.text(
        "SELECT count(*) FROM public.billing_accounts WHERE pending_slot_quantity IS NOT NULL"
    )).scalar_one())
    if legacy_pending != 0:
        raise RuntimeError(
            f"0017 requires legacy pending_slot_quantity to be unused before backfill; found {legacy_pending}"
        )

    for table_name, column_name in (
        ("billing_accounts", "quantity_period_start"),
        ("billing_accounts", "quantity_period_end"),
        ("billing_accounts", "pending_period_start"),
        ("billing_accounts", "pending_period_end"),
        ("billing_payments", "calculation_json"),
    ):
        present = int(bind.execute(sa.text(
            """SELECT count(*) FROM information_schema.columns
               WHERE table_schema='public' AND table_name=:t AND column_name=:c"""
        ), {"t": table_name, "c": column_name}).scalar_one())
        if present:
            raise RuntimeError(f"0017 target column already exists: {table_name}.{column_name}")

    table_present = int(bind.execute(sa.text(
        """SELECT count(*) FROM information_schema.tables
           WHERE table_schema='public' AND table_name='billing_scheduled_retirements'"""
    )).scalar_one())
    if table_present:
        raise RuntimeError("0017 target table already exists: billing_scheduled_retirements")

    op.add_column(
        "billing_accounts",
        sa.Column("quantity_period_start", sa.DateTime(timezone=True), nullable=True),
        schema="public",
    )
    op.add_column(
        "billing_accounts",
        sa.Column("quantity_period_end", sa.DateTime(timezone=True), nullable=True),
        schema="public",
    )
    op.add_column(
        "billing_accounts",
        sa.Column("pending_period_start", sa.DateTime(timezone=True), nullable=True),
        schema="public",
    )
    op.add_column(
        "billing_accounts",
        sa.Column("pending_period_end", sa.DateTime(timezone=True), nullable=True),
        schema="public",
    )
    op.add_column(
        "billing_payments",
        sa.Column("calculation_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        schema="public",
    )

    point = bind.execute(sa.text("SELECT now()")).scalar_one()
    accounts = bind.execute(sa.text(
        """SELECT id, status, slot_quantity, current_period_start, current_period_end
           FROM public.billing_accounts ORDER BY created_at, id"""
    )).mappings().all()

    for account in accounts:
        account_id = account["id"]
        status = str(account["status"])
        cps = account["current_period_start"]
        cpe = account["current_period_end"]
        qps = cps
        qpe = cpe
        pending_q = None
        pending_start = None
        pending_end = None

        periods = bind.execute(sa.text(
            """SELECT id, kind, quantity_after, target_period_start, target_period_end
               FROM public.billing_payments
               WHERE billing_account_id=:account_id
                 AND status='succeeded'
                 AND target_period_start IS NOT NULL
                 AND target_period_end IS NOT NULL
               ORDER BY target_period_start, target_period_end, created_at, id"""
        ), {"account_id": account_id}).mappings().all()

        if status == "trial":
            if periods:
                raise RuntimeError(
                    f"0017 trial account unexpectedly has succeeded paid periods: {account_id}"
                )
        elif status == "active_paid":
            active = [
                r for r in periods
                if r["target_period_start"] <= point < r["target_period_end"]
            ]
            future = [r for r in periods if r["target_period_start"] > point]
            if len(active) > 1 or len(future) > 1:
                raise RuntimeError(
                    f"0017 refuses multi-period ambiguity for account {account_id}: "
                    f"active={len(active)} future={len(future)}"
                )
            if active:
                cur = active[0]
                qps = cur["target_period_start"]
                qpe = cur["target_period_end"]
                if int(cur["quantity_after"]) != int(account["slot_quantity"]):
                    raise RuntimeError(
                        f"0017 current quantity/payment drift for account {account_id}"
                    )
                if future:
                    nxt = future[0]
                    if not _eq(nxt["target_period_start"], qpe):
                        raise RuntimeError(
                            f"0017 future period is not contiguous for account {account_id}"
                        )
                    if not _eq(cpe, nxt["target_period_end"]):
                        raise RuntimeError(
                            f"0017 paid-through edge/future payment drift for account {account_id}"
                        )
                    pending_q = int(nxt["quantity_after"])
                    pending_start = nxt["target_period_start"]
                    pending_end = nxt["target_period_end"]
                elif not _eq(cpe, qpe):
                    raise RuntimeError(
                        f"0017 paid-through edge/current payment drift for account {account_id}"
                    )
            elif future:
                # Accepted P29E state: payment succeeded during the preserved trial tail.
                nxt = future[0]
                if not (cps < nxt["target_period_start"]):
                    raise RuntimeError(
                        f"0017 preserved-trial boundary is invalid for account {account_id}"
                    )
                if not _eq(cpe, nxt["target_period_end"]):
                    raise RuntimeError(
                        f"0017 preserved-trial paid-through drift for account {account_id}"
                    )
                qps = cps
                qpe = nxt["target_period_start"]
                pending_q = int(nxt["quantity_after"])
                pending_start = nxt["target_period_start"]
                pending_end = nxt["target_period_end"]
            else:
                raise RuntimeError(
                    f"0017 active_paid account has no current/future succeeded payment: {account_id}"
                )
        elif status in {"expired", "past_due"}:
            # No P29F quantity scheduler exists yet. Preserve the accepted finite window.
            qps = cps
            qpe = cpe
        else:
            raise RuntimeError(
                f"0017 unsupported billing account status {status!r} for {account_id}"
            )

        if not (qpe > qps):
            raise RuntimeError(f"0017 non-positive quantity period for account {account_id}")
        expected_paid_through = pending_end if pending_end is not None else qpe
        if not _eq(cpe, expected_paid_through):
            raise RuntimeError(f"0017 paid-through invariant failed for account {account_id}")

        bind.execute(sa.text(
            """UPDATE public.billing_accounts
               SET quantity_period_start=:qps, quantity_period_end=:qpe,
                   pending_slot_quantity=:pending_q,
                   pending_period_start=:pending_start, pending_period_end=:pending_end
               WHERE id=:account_id"""
        ), {
            "qps": qps,
            "qpe": qpe,
            "pending_q": pending_q,
            "pending_start": pending_start,
            "pending_end": pending_end,
            "account_id": account_id,
        })

    op.alter_column(
        "billing_accounts", "quantity_period_start", nullable=False, schema="public"
    )
    op.alter_column(
        "billing_accounts", "quantity_period_end", nullable=False, schema="public"
    )
    op.create_check_constraint(
        "billing_accounts_quantity_period_positive",
        "billing_accounts",
        "quantity_period_end > quantity_period_start",
        schema="public",
    )
    op.create_check_constraint(
        "billing_accounts_pending_period_shape",
        "billing_accounts",
        "(pending_slot_quantity IS NULL AND pending_period_start IS NULL AND pending_period_end IS NULL) OR "
        "(pending_slot_quantity IS NOT NULL AND pending_period_start IS NOT NULL AND pending_period_end IS NOT NULL "
        "AND pending_period_start = quantity_period_end AND pending_period_end > pending_period_start)",
        schema="public",
    )
    op.create_check_constraint(
        "billing_accounts_paid_through_shape",
        "billing_accounts",
        "current_period_end = COALESCE(pending_period_end, quantity_period_end)",
        schema="public",
    )

    op.create_table(
        "billing_scheduled_retirements",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "billing_account_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("public.billing_accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "connection_slot_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("public.connection_slots.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "billing_account_id",
            "connection_slot_id",
            name="uq_billing_scheduled_retirements_account_slot",
        ),
        schema="public",
    )
    op.create_index(
        "ix_billing_scheduled_retirements_account_id",
        "billing_scheduled_retirements",
        ["billing_account_id"],
        schema="public",
    )
    op.create_index(
        "ix_billing_scheduled_retirements_slot_id",
        "billing_scheduled_retirements",
        ["connection_slot_id"],
        schema="public",
    )
    op.create_index(
        "ix_billing_scheduled_retirements_effective_at",
        "billing_scheduled_retirements",
        ["effective_at"],
        schema="public",
    )


def downgrade() -> None:
    raise RuntimeError(
        "0017_commercial_quantity_periods is forward-only; restore the verified pre-migration database backup for rollback"
    )
