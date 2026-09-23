from __future__ import annotations

from calendar import monthrange
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import re
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import (
    AccessGrant,
    BillingAccount,
    BillingOffer,
    BillingPayment,
    ConnectionProfile,
    ConnectionSlot,
    User,
)
from app.services.domain_v2 import (
    ConfigurationRequestResult,
    create_configuration_request,
    logical_slot_count,
    mirrored_configuration_limit,
    record_audit_event,
    utcnow,
)
from app.services.yookassa import get_payment


_IDEMPOTENCE_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
KNOWN_PROVIDER_STATES = {"pending", "waiting_for_capture", "succeeded", "canceled"}


class BillingError(RuntimeError):
    pass


class BillingUnavailable(BillingError):
    pass


class BillingConflict(BillingError):
    pass


class BillingProviderMismatch(BillingError):
    pass


@dataclass(frozen=True)
class PaymentIntent:
    payment: BillingPayment
    account: BillingAccount
    offer: BillingOffer
    created: bool


@dataclass(frozen=True)
class ReconcileResult:
    payment: BillingPayment
    state_changed: bool
    configuration: ConfigurationRequestResult | None


def validate_idempotence_key(value: str) -> str:
    key = str(value or "").strip()
    if not _IDEMPOTENCE_RE.fullmatch(key):
        raise BillingError("Idempotency-Key must be 1-64 safe ASCII characters")
    return key


def add_calendar_month(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise BillingError("calendar-month anchor must be timezone-aware")
    year = value.year + (1 if value.month == 12 else 0)
    month = 1 if value.month == 12 else value.month + 1
    day = min(value.day, monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def _monthly_amount_kopeks(offer: BillingOffer, quantity: int) -> int:
    q = int(quantity)
    if q < int(offer.base_slot_quantity) or q > int(offer.max_slot_quantity):
        raise BillingConflict("commercial quantity is outside the active offer")
    return int(offer.base_monthly_kopeks) + max(0, q - int(offer.base_slot_quantity)) * int(
        offer.extra_slot_monthly_kopeks
    )


def monthly_amount_kopeks(offer: BillingOffer, quantity: int) -> int:
    return _monthly_amount_kopeks(offer, quantity)


def _commercial_account_for_user(
    db: Session,
    *,
    user: User,
    for_update: bool,
) -> tuple[BillingAccount, BillingOffer, AccessGrant]:
    query = select(BillingAccount).where(BillingAccount.user_id == user.id)
    if for_update:
        query = query.with_for_update()
    account = db.execute(query).scalar_one_or_none()
    if account is None:
        raise BillingUnavailable("commercial account is unavailable")
    offer = db.get(BillingOffer, account.offer_id)
    if offer is None or not offer.active:
        raise BillingUnavailable("commercial offer is unavailable")
    grant = db.execute(
        select(AccessGrant).where(AccessGrant.id == account.access_grant_id).with_for_update()
    ).scalar_one_or_none()
    if grant is None or grant.user_id != user.id or grant.plan_id != offer.plan_id:
        raise BillingConflict("commercial entitlement linkage is invalid")
    if user.deletion_requested_at is not None:
        raise BillingConflict("user deletion is in progress")
    return account, offer, grant


def prepare_manual_payment_intent(
    db: Session,
    *,
    user: User,
    idempotence_key: str,
    now: datetime | None = None,
) -> PaymentIntent:
    point = now or utcnow()
    key = validate_idempotence_key(idempotence_key)
    account, offer, grant = _commercial_account_for_user(db, user=user, for_update=True)

    # An Idempotency-Key identifies the original local payment intent for its
    # lifetime.  Return that same intent before re-deriving kind/amount from a
    # commercial account that may already have changed because the original
    # payment succeeded.  The account row lock is the per-account serializer;
    # no second payment-row lock is required just to return immutable intent.
    existing = db.execute(
        select(BillingPayment).where(BillingPayment.idempotence_key == key)
    ).scalar_one_or_none()
    if existing is not None:
        if existing.billing_account_id != account.id:
            raise BillingConflict("Idempotency-Key already belongs to another commercial account")
        if existing.provider != "yookassa":
            raise BillingConflict("Idempotency-Key belongs to another payment provider")
        return PaymentIntent(payment=existing, account=account, offer=offer, created=False)

    if account.billing_mode != "manual":
        raise BillingConflict("P29D supports manual billing only")
    if account.status == "past_due":
        raise BillingConflict("past-due renewal belongs to P29F")
    if account.status not in {"trial", "active_paid", "expired"}:
        raise BillingConflict("unsupported commercial account state")
    if account.status in {"trial", "active_paid"} and account.current_period_start > point:
        raise BillingConflict("commercial paid/trial period has not started")
    if account.status in {"trial", "active_paid"} and account.current_period_end <= point:
        raise BillingConflict("commercial expiry is still settling; retry after expiry reconciliation")

    quantity = int(account.slot_quantity)
    amount = _monthly_amount_kopeks(offer, quantity)
    kind = "manual_renewal" if account.status == "active_paid" else "initial"

    payment = BillingPayment(
        id=uuid.uuid4(),
        billing_account_id=account.id,
        provider="yookassa",
        provider_payment_id=None,
        idempotence_key=key,
        kind=kind,
        status="created",
        provider_status=None,
        amount_kopeks=amount,
        currency=offer.currency,
        quantity_before=quantity,
        quantity_after=quantity,
        target_period_start=None,
        target_period_end=None,
        created_at=point,
        updated_at=point,
        succeeded_at=None,
    )
    db.add(payment)
    db.flush()
    record_audit_event(
        db,
        event_type="billing.payment.created",
        actor_kind="user",
        actor_user_id=user.id,
        object_type="billing_payment",
        object_id=str(payment.id),
        payload={
            "kind": kind,
            "amount_kopeks": amount,
            "currency": offer.currency,
            "quantity": quantity,
        },
    )
    return PaymentIntent(payment=payment, account=account, offer=offer, created=True)


def bind_provider_create_response(
    db: Session,
    *,
    payment_id: uuid.UUID,
    provider: dict,
    now: datetime | None = None,
) -> BillingPayment:
    payment = db.execute(
        select(BillingPayment).where(BillingPayment.id == payment_id).with_for_update()
    ).scalar_one_or_none()
    if payment is None:
        raise BillingUnavailable("billing payment is unavailable")
    _verify_provider_object(payment=payment, account_id=payment.billing_account_id, provider=provider)
    provider_id = str(provider.get("id") or "")
    status = str(provider.get("status") or "")
    if payment.provider_payment_id and payment.provider_payment_id != provider_id:
        raise BillingProviderMismatch("provider payment id changed for one local payment")
    if payment.status == "succeeded" and status != "succeeded":
        raise BillingProviderMismatch("provider status regressed after local success")
    if payment.status == "canceled" and status != "canceled":
        raise BillingProviderMismatch("provider status regressed after local cancellation")
    payment.provider_payment_id = provider_id
    payment.provider_status = status
    if status == "canceled":
        payment.status = "canceled"
    elif payment.status == "created":
        payment.status = "pending"
    payment.updated_at = now or utcnow()
    db.flush()
    return payment


def _parse_provider_datetime(value: object, *, field: str) -> datetime:
    text = str(value or "")
    if not text:
        raise BillingProviderMismatch(f"provider {field} is missing")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BillingProviderMismatch(f"provider {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise BillingProviderMismatch(f"provider {field} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _provider_amount_kopeks(provider: dict) -> tuple[int, str]:
    amount = provider.get("amount") or {}
    currency = str(amount.get("currency") or "")
    raw = str(amount.get("value") or "")
    try:
        value = Decimal(raw)
    except InvalidOperation as exc:
        raise BillingProviderMismatch("provider amount is invalid") from exc
    kopeks = value * Decimal("100")
    if kopeks != kopeks.to_integral_value():
        raise BillingProviderMismatch("provider amount has unsupported precision")
    return int(kopeks), currency


def _verify_provider_object(
    *,
    payment: BillingPayment,
    account_id: uuid.UUID | None,
    provider: dict,
) -> None:
    provider_id = str(provider.get("id") or "")
    if not provider_id:
        raise BillingProviderMismatch("provider payment id is missing")
    if payment.provider_payment_id is not None and payment.provider_payment_id != provider_id:
        raise BillingProviderMismatch("provider payment id mismatch")
    if bool(provider.get("test")) is not bool(settings.yookassa_expected_test):
        raise BillingProviderMismatch("provider test/live mode mismatch")
    status = str(provider.get("status") or "")
    if status not in KNOWN_PROVIDER_STATES:
        raise BillingProviderMismatch("unknown provider payment status")
    amount_kopeks, currency = _provider_amount_kopeks(provider)
    if amount_kopeks != int(payment.amount_kopeks) or currency != payment.currency:
        raise BillingProviderMismatch("provider amount/currency mismatch")
    metadata = provider.get("metadata") or {}
    if str(metadata.get("billing_payment_id") or "") != str(payment.id):
        raise BillingProviderMismatch("provider billing_payment_id metadata mismatch")
    if str(metadata.get("kind") or "") != payment.kind:
        raise BillingProviderMismatch("provider payment kind metadata mismatch")
    if account_id is not None and str(metadata.get("billing_account_id") or "") != str(account_id):
        raise BillingProviderMismatch("provider billing_account_id metadata mismatch")


def _active_configuration_rows(
    db: Session,
    *,
    account: BillingAccount,
) -> tuple[list[ConnectionSlot], list[ConnectionProfile]]:
    slots = list(
        db.execute(
            select(ConnectionSlot)
            .where(
                ConnectionSlot.access_grant_id == account.access_grant_id,
                ConnectionSlot.user_id == account.user_id,
                ConnectionSlot.disabled_at.is_(None),
            )
            .order_by(ConnectionSlot.created_at.asc())
            .with_for_update()
        ).scalars().all()
    )
    profiles = list(
        db.execute(
            select(ConnectionProfile)
            .where(
                ConnectionProfile.access_grant_id == account.access_grant_id,
                ConnectionProfile.user_id == account.user_id,
                ConnectionProfile.status != "disabled",
            )
            .order_by(ConnectionProfile.created_at.asc())
            .with_for_update()
        ).scalars().all()
    )
    return slots, profiles


def _extend_live_mirror(
    db: Session,
    *,
    account: BillingAccount,
    grant: AccessGrant,
    period_end: datetime,
) -> None:
    slots, profiles = _active_configuration_rows(db, account=account)
    if len(slots) != int(account.slot_quantity):
        raise BillingConflict("active configuration count does not match commercial quantity")
    if len(profiles) != len(slots) * 2:
        raise BillingConflict("active WG/AWG profile pair is incomplete")
    for slot in slots:
        slot.expires_at = period_end
        slot.updated_at = utcnow()
    for profile in profiles:
        profile.expires_at = period_end
        profile.updated_at = utcnow()
    grant.valid_until = period_end
    grant.updated_at = utcnow()


def _apply_succeeded_payment(
    db: Session,
    *,
    payment: BillingPayment,
    account: BillingAccount,
    captured_at: datetime,
) -> ConfigurationRequestResult | None:
    offer = db.get(BillingOffer, account.offer_id)
    if offer is None or not offer.active:
        raise BillingUnavailable("commercial offer is unavailable")
    user = db.execute(select(User).where(User.id == account.user_id).with_for_update()).scalar_one_or_none()
    if user is None or user.deletion_requested_at is not None:
        raise BillingConflict("commercial user is unavailable")
    grant = db.execute(
        select(AccessGrant).where(AccessGrant.id == account.access_grant_id).with_for_update()
    ).scalar_one_or_none()
    if grant is None or grant.user_id != user.id or grant.plan_id != offer.plan_id:
        raise BillingConflict("commercial entitlement linkage is invalid")

    if account.status == "active_paid" and account.current_period_end > captured_at:
        target_start = account.current_period_end
        target_end = add_calendar_month(target_start)
        # Keep current_period_start unchanged so the already-paid interval remains
        # active/referral-eligible until its boundary; only the paid-through edge moves.
        account.current_period_end = target_end
        _extend_live_mirror(db, account=account, grant=grant, period_end=target_end)
        configuration = None
    elif account.status == "trial" and account.current_period_end > captured_at:
        # Preserve the unused trial tail. The paid month begins at the existing
        # trial boundary, while the already-active entitlement window keeps its
        # original start so access and paid-account eligibility remain continuous.
        target_start = account.current_period_end
        target_end = add_calendar_month(target_start)
        account.current_period_end = target_end
        account.status = "active_paid"
        account.grace_until = None
        account.cancel_at_period_end = False
        grant.status = "active"
        _extend_live_mirror(db, account=account, grant=grant, period_end=target_end)
        configuration = None
    elif account.status == "expired" or account.current_period_end <= captured_at:
        if logical_slot_count(db, grant_id=grant.id, user_id=user.id) != 0:
            raise BillingConflict("expired runtime retirement is not yet settled")
        if int(account.slot_quantity) != 1 or int(offer.base_slot_quantity) != 1:
            raise BillingConflict("P29D expired reactivation supports one base Configuration")
        if mirrored_configuration_limit(db, grant_id=grant.id, for_update=True) < 1:
            raise BillingConflict("commercial grant has no configuration allowance")
        target_start = captured_at
        target_end = add_calendar_month(target_start)
        grant.status = "active"
        grant.valid_from = target_start
        grant.valid_until = target_end
        grant.updated_at = utcnow()
        account.current_period_start = target_start
        account.current_period_end = target_end
        account.status = "active_paid"
        account.grace_until = None
        account.cancel_at_period_end = False
        configuration = create_configuration_request(
            db,
            user=user,
            grant_id=grant.id,
            node_id=settings.wg_default_node_id,
            label=None,
            now=captured_at,
        )
    else:
        raise BillingConflict("payment success is not applicable to this commercial state")

    account.billing_mode = "manual"
    account.next_charge_at = None
    account.updated_at = utcnow()
    payment.target_period_start = target_start
    payment.target_period_end = target_end
    return configuration


def reconcile_payment(
    db: Session,
    *,
    payment_id: uuid.UUID,
    provider_payment_id_hint: str | None = None,
) -> ReconcileResult:
    pre = db.get(BillingPayment, payment_id)
    if pre is None:
        raise BillingUnavailable("billing payment is unavailable")
    provider_id = str(pre.provider_payment_id or provider_payment_id_hint or "").strip()
    if not provider_id:
        raise BillingConflict("provider payment is not yet bound; retry creation with the same Idempotency-Key")
    provider = get_payment(provider_id)
    if str(provider.get("id") or "") != provider_id:
        raise BillingProviderMismatch("provider lookup returned a different payment id")

    payment = db.execute(
        select(BillingPayment).where(BillingPayment.id == payment_id).with_for_update()
    ).scalar_one_or_none()
    if payment is None:
        raise BillingUnavailable("billing payment is unavailable")
    if payment.provider_payment_id is None:
        other = db.execute(
            select(BillingPayment.id).where(
                BillingPayment.provider_payment_id == provider_id,
                BillingPayment.id != payment.id,
            )
        ).scalar_one_or_none()
        if other is not None:
            raise BillingProviderMismatch("provider payment id already belongs to another local payment")
        payment.provider_payment_id = provider_id
    elif payment.provider_payment_id != provider_id:
        raise BillingProviderMismatch("provider payment id mismatch")
    account = None
    if payment.billing_account_id is not None:
        account = db.execute(
            select(BillingAccount)
            .where(BillingAccount.id == payment.billing_account_id)
            .with_for_update()
        ).scalar_one_or_none()
    _verify_provider_object(
        payment=payment,
        account_id=payment.billing_account_id,
        provider=provider,
    )
    provider_status = str(provider.get("status"))
    point = utcnow()
    if payment.status == "succeeded" and provider_status != "succeeded":
        raise BillingProviderMismatch("provider status regressed after local success")
    if payment.status == "canceled" and provider_status != "canceled":
        raise BillingProviderMismatch("provider status regressed after local cancellation")
    payment.provider_status = provider_status
    payment.updated_at = point

    if provider_status in {"pending", "waiting_for_capture"}:
        if payment.status not in {"succeeded", "canceled"}:
            payment.status = "pending"
        db.flush()
        return ReconcileResult(payment=payment, state_changed=False, configuration=None)

    if provider_status == "canceled":
        if payment.status == "succeeded":
            raise BillingProviderMismatch("provider canceled a locally succeeded payment")
        changed = payment.status != "canceled"
        payment.status = "canceled"
        db.flush()
        return ReconcileResult(payment=payment, state_changed=changed, configuration=None)

    captured_at = _parse_provider_datetime(provider.get("captured_at"), field="captured_at")
    if payment.status == "canceled":
        raise BillingProviderMismatch("provider succeeded a locally canceled payment")
    if payment.status == "succeeded":
        if payment.succeeded_at != captured_at:
            raise BillingProviderMismatch("provider captured_at changed after success")
        return ReconcileResult(payment=payment, state_changed=False, configuration=None)

    if account is None:
        # Retained payment history after user/account deletion may still converge
        # to terminal provider truth, but it is never allowed to recreate access.
        payment.status = "succeeded"
        payment.succeeded_at = captured_at
        db.flush()
        return ReconcileResult(payment=payment, state_changed=True, configuration=None)

    configuration = _apply_succeeded_payment(
        db,
        payment=payment,
        account=account,
        captured_at=captured_at,
    )
    payment.status = "succeeded"
    payment.succeeded_at = captured_at
    payment.updated_at = point
    record_audit_event(
        db,
        event_type="billing.payment.succeeded",
        actor_kind="system",
        actor_user_id=account.user_id,
        object_type="billing_payment",
        object_id=str(payment.id),
        payload={
            "kind": payment.kind,
            "amount_kopeks": int(payment.amount_kopeks),
            "currency": payment.currency,
            "target_period_start": payment.target_period_start.isoformat(),
            "target_period_end": payment.target_period_end.isoformat(),
            "provisioned_new_configuration": configuration is not None,
        },
    )
    db.flush()
    return ReconcileResult(payment=payment, state_changed=True, configuration=configuration)
