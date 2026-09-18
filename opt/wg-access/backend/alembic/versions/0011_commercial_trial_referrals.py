"""Commercial offer/account/payment foundation and referral-trial seed.

Revision ID: 0011_commercial_trial_referrals
Revises: 0010_connection_slots
Create Date: 2026-09-17

P29C adds the first commercial-domain schema above the accepted AccessGrant /
ConnectionSlot authority.  BillingPayment is introduced here (before provider
integration) because referral eligibility must have durable proof of a user's
own successful payment rather than an editable has_paid flag.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0011_commercial_trial_referrals"
down_revision = "0010_connection_slots"
branch_labels = None
depends_on = None

COMMERCIAL_PLAN_ID = "7ac5b9f8-3263-5567-8425-3b0971f3b311"
COMMERCIAL_OFFER_ID = "310ddec6-c82c-5484-ad28-8ecee170bc1d"
COMMERCIAL_CODE = "commercial-rub-v1"


def upgrade() -> None:
    op.create_table(
        "billing_offers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("currency", sa.String(length=3), nullable=False, server_default=sa.text("'RUB'")),
        sa.Column("base_slot_quantity", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("base_monthly_kopeks", sa.Integer(), nullable=False),
        sa.Column("extra_slot_monthly_kopeks", sa.Integer(), nullable=False),
        sa.Column("trial_days", sa.Integer(), nullable=False, server_default=sa.text("7")),
        sa.Column("max_slot_quantity", sa.Integer(), nullable=False, server_default=sa.text("3")),
        sa.Column("active_referral_invite_limit", sa.Integer(), nullable=False, server_default=sa.text("3")),
        # Deliberately no database FK to public.plans.id here. The accepted live
        # plans table has historical constraint drift and does not expose id as a
        # PostgreSQL referenced key. P29C does not repair unrelated legacy
        # PK/FK/UNIQUE drift; the deterministic plan UUID/code and application
        # boundary provide the commercial offer linkage.
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("currency = 'RUB'", name="billing_offers_currency_rub"),
        sa.CheckConstraint("base_slot_quantity >= 1", name="billing_offers_base_slot_quantity_positive"),
        sa.CheckConstraint("base_monthly_kopeks >= 0", name="billing_offers_base_monthly_kopeks_nonnegative"),
        sa.CheckConstraint("extra_slot_monthly_kopeks >= 0", name="billing_offers_extra_slot_monthly_kopeks_nonnegative"),
        sa.CheckConstraint("trial_days >= 1", name="billing_offers_trial_days_positive"),
        sa.CheckConstraint("max_slot_quantity >= base_slot_quantity", name="billing_offers_max_slot_quantity_valid"),
        sa.CheckConstraint("active_referral_invite_limit >= 0", name="billing_offers_referral_limit_nonnegative"),
        sa.UniqueConstraint("code", name="uq_billing_offers_code"),
        sa.UniqueConstraint("plan_id", name="uq_billing_offers_plan_id"),
        schema="public",
    )
    op.create_index("ix_billing_offers_plan_id", "billing_offers", ["plan_id"], schema="public")

    op.create_table(
        "billing_accounts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        # Accepted production users.id has historical referenced-key drift. Keep
        # this as a soft UUID reference and validate identity at the service boundary.
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        # access_grants.id is an accepted referenced key (P28F0 lineage).
        # Keep this linkage enforced in PostgreSQL; only legacy users/plans stay soft.
        sa.Column("access_grant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("public.access_grants.id"), nullable=False),
        sa.Column("offer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("public.billing_offers.id"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("billing_mode", sa.String(length=16), nullable=False),
        sa.Column("slot_quantity", sa.Integer(), nullable=False),
        sa.Column("pending_slot_quantity", sa.Integer(), nullable=True),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("grace_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payment_method_id", sa.String(length=128), nullable=True),
        sa.Column("cancel_at_period_end", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("next_charge_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("status IN ('trial','active_paid','past_due','expired')", name="billing_accounts_status_check"),
        sa.CheckConstraint("billing_mode IN ('manual','recurring')", name="billing_accounts_mode_check"),
        sa.CheckConstraint("slot_quantity >= 1", name="billing_accounts_slot_quantity_positive"),
        sa.CheckConstraint("pending_slot_quantity IS NULL OR pending_slot_quantity >= 1", name="billing_accounts_pending_slot_quantity_positive"),
        sa.CheckConstraint("current_period_end > current_period_start", name="billing_accounts_period_positive"),
        sa.UniqueConstraint("user_id", name="uq_billing_accounts_user_id"),
        sa.UniqueConstraint("access_grant_id", name="uq_billing_accounts_access_grant_id"),
        schema="public",
    )
    op.create_index("ix_billing_accounts_user_id", "billing_accounts", ["user_id"], schema="public")
    op.create_index("ix_billing_accounts_access_grant_id", "billing_accounts", ["access_grant_id"], schema="public")
    op.create_index("ix_billing_accounts_offer_id", "billing_accounts", ["offer_id"], schema="public")
    op.create_index("ix_billing_accounts_status", "billing_accounts", ["status"], schema="public")

    op.create_table(
        "billing_payments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("billing_account_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("public.billing_accounts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False, server_default=sa.text("'yookassa'")),
        sa.Column("provider_payment_id", sa.String(length=128), nullable=True),
        sa.Column("idempotence_key", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("provider_status", sa.String(length=64), nullable=True),
        sa.Column("amount_kopeks", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False, server_default=sa.text("'RUB'")),
        sa.Column("quantity_before", sa.Integer(), nullable=False),
        sa.Column("quantity_after", sa.Integer(), nullable=False),
        sa.Column("target_period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("target_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("succeeded_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("provider = 'yookassa'", name="billing_payments_provider_yookassa"),
        sa.CheckConstraint("kind IN ('initial','manual_renewal','auto_renewal','upgrade')", name="billing_payments_kind_check"),
        sa.CheckConstraint("status IN ('created','pending','succeeded','canceled')", name="billing_payments_status_check"),
        sa.CheckConstraint("amount_kopeks >= 0", name="billing_payments_amount_nonnegative"),
        sa.CheckConstraint("currency = 'RUB'", name="billing_payments_currency_rub"),
        sa.CheckConstraint("quantity_before >= 1", name="billing_payments_quantity_before_positive"),
        sa.CheckConstraint("quantity_after >= 1", name="billing_payments_quantity_after_positive"),
        sa.UniqueConstraint("provider_payment_id", name="uq_billing_payments_provider_payment_id"),
        sa.UniqueConstraint("idempotence_key", name="uq_billing_payments_idempotence_key"),
        schema="public",
    )
    op.create_index("ix_billing_payments_billing_account_id", "billing_payments", ["billing_account_id"], schema="public")
    op.create_index("ix_billing_payments_status", "billing_payments", ["status"], schema="public")

    # P29C owns the first internal commercial plan. It is deliberately hidden
    # from the legacy Admin plan picker by the application boundary.
    op.execute(
        sa.text(
            """
            INSERT INTO public.plans (
                id, code, display_name, active,
                default_wireguard_limit, default_amneziawg_limit,
                created_at, updated_at
            ) VALUES (
                CAST(:plan_id AS uuid), :code, 'Commercial RUB v1 (internal)', true,
                1, 1, now(), now()
            )
            """
        ).bindparams(plan_id=COMMERCIAL_PLAN_ID, code=COMMERCIAL_CODE)
    )
    op.execute(
        sa.text(
            """
            INSERT INTO public.billing_offers (
                id, code, active, currency, base_slot_quantity,
                base_monthly_kopeks, extra_slot_monthly_kopeks,
                trial_days, max_slot_quantity, active_referral_invite_limit,
                plan_id, created_at
            ) VALUES (
                CAST(:offer_id AS uuid), :code, true, 'RUB', 1,
                29900, 10000, 7, 3, 3,
                CAST(:plan_id AS uuid), now()
            )
            """
        ).bindparams(offer_id=COMMERCIAL_OFFER_ID, code=COMMERCIAL_CODE, plan_id=COMMERCIAL_PLAN_ID)
    )


def downgrade() -> None:
    raise RuntimeError(
        "0011_commercial_trial_referrals is forward-only; restore the verified pre-migration database backup for rollback"
    )
