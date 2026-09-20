from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0012_billing_payment_retention"
down_revision = "0011_commercial_trial_referrals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    fk_rows = bind.execute(
        sa.text(
            """
            SELECT c.conname, pg_get_constraintdef(c.oid)
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE n.nspname = 'public'
              AND t.relname = 'billing_payments'
              AND c.contype = 'f'
              AND pg_get_constraintdef(c.oid) LIKE 'FOREIGN KEY (billing_account_id)%billing_accounts%'
            """
        )
    ).all()
    if len(fk_rows) != 1:
        raise RuntimeError(f"expected exactly one billing_account_id FK, found {len(fk_rows)}")
    fk_name, fk_definition = fk_rows[0]
    if 'ON DELETE CASCADE' not in str(fk_definition):
        raise RuntimeError(f"unexpected existing billing_account_id FK: {fk_definition}")

    op.drop_constraint(fk_name, "billing_payments", schema="public", type_="foreignkey")
    op.alter_column(
        "billing_payments",
        "billing_account_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
        schema="public",
    )
    op.create_foreign_key(
        "fk_billing_payments_billing_account_id_retained",
        "billing_payments",
        "billing_accounts",
        ["billing_account_id"],
        ["id"],
        source_schema="public",
        referent_schema="public",
        ondelete="SET NULL",
    )


def downgrade() -> None:
    raise RuntimeError(
        "0012_billing_payment_retention is forward-only; restore the verified pre-migration database backup for rollback"
    )
