from __future__ import annotations

from calendar import monthrange
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import re
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import (
    AccessGrant,
    AccessGrantProtocolLimit,
    BillingAccount,
    BillingOffer,
    BillingPayment,
    BillingScheduledRetirement,
    ConnectionProfile,
    ConnectionSlot,
    User,
)
from app.services.domain_v2 import (
    ConfigurationRequestResult,
    DomainV2Error,
    create_configuration_request,
    logical_slot_count,
    mirrored_configuration_limit,
    record_audit_event,
    request_configuration_disable,
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
    confirmation_url: str | None = None


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


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_calc_datetime(value: object, *, field: str) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise BillingConflict(f"frozen payment {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise BillingConflict(f"frozen payment {field} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _account_snapshot(account: BillingAccount) -> dict[str, object]:
    return {
        "status": account.status,
        "slot_quantity": int(account.slot_quantity),
        "quantity_period_start": _iso(account.quantity_period_start),
        "quantity_period_end": _iso(account.quantity_period_end),
        "pending_slot_quantity": (
            int(account.pending_slot_quantity)
            if account.pending_slot_quantity is not None
            else None
        ),
        "pending_period_start": _iso(account.pending_period_start),
        "pending_period_end": _iso(account.pending_period_end),
        "paid_through": _iso(account.current_period_end),
    }


def _assert_account_snapshot(account: BillingAccount, expected: dict[str, object]) -> None:
    actual = _account_snapshot(account)
    if actual != expected:
        raise BillingConflict("commercial account changed after payment intent creation")


def _prorated_upgrade_kopeks(
    offer: BillingOffer,
    *,
    quantity_before: int,
    quantity_after: int,
    point: datetime,
    period_start: datetime,
    period_end: datetime,
) -> int:
    before = int(quantity_before)
    after = int(quantity_after)
    if after <= before:
        raise BillingConflict("proration requires a positive quantity increase")
    if point < period_start or point >= period_end:
        raise BillingConflict("current quantity period is not eligible for proration")
    period_seconds = Decimal(str((period_end - period_start).total_seconds()))
    remaining_seconds = Decimal(str((period_end - point).total_seconds()))
    if period_seconds <= 0 or remaining_seconds <= 0:
        raise BillingConflict("quantity period duration is invalid")
    raw = (
        Decimal(int(offer.extra_slot_monthly_kopeks))
        * Decimal(after - before)
        * remaining_seconds
        / period_seconds
    )
    return int(raw.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _active_slot_ids(db: Session, *, account: BillingAccount) -> list[uuid.UUID]:
    return list(
        db.execute(
            select(ConnectionSlot.id)
            .where(
                ConnectionSlot.access_grant_id == account.access_grant_id,
                ConnectionSlot.user_id == account.user_id,
                ConnectionSlot.disabled_at.is_(None),
            )
            .order_by(ConnectionSlot.created_at.asc(), ConnectionSlot.id.asc())
            .with_for_update()
        ).scalars().all()
    )


def _validate_retirement_selection(
    db: Session,
    *,
    account: BillingAccount,
    selected_ids: list[uuid.UUID],
    required_count: int,
    planned_new_ids: list[uuid.UUID] | None = None,
) -> list[uuid.UUID]:
    selected = list(selected_ids)
    if len(set(selected)) != len(selected):
        raise BillingConflict("duplicate retirement Configuration ids")
    if len(selected) != int(required_count):
        raise BillingConflict(
            f"exactly {int(required_count)} Configuration(s) must be selected for retirement"
        )
    eligible = set(_active_slot_ids(db, account=account))
    eligible.update(planned_new_ids or [])
    if any(slot_id not in eligible for slot_id in selected):
        raise BillingConflict("retirement target is not an eligible Configuration")
    return selected


def _current_quantity_period_is_paid(
    db: Session,
    *,
    account: BillingAccount,
    point: datetime,
) -> bool:
    if account.status != "active_paid":
        return False
    return db.execute(
        select(BillingPayment.id).where(
            BillingPayment.billing_account_id == account.id,
            BillingPayment.status == "succeeded",
            BillingPayment.target_period_start.is_not(None),
            BillingPayment.target_period_end.is_not(None),
            BillingPayment.target_period_start <= point,
            BillingPayment.target_period_end > point,
        )
    ).scalar_one_or_none() is not None


def current_quantity_period_is_paid(
    db: Session,
    *,
    account: BillingAccount,
    now: datetime | None = None,
) -> bool:
    return _current_quantity_period_is_paid(db, account=account, point=now or utcnow())


def _ensure_no_other_inflight_payment(db: Session, *, account: BillingAccount) -> None:
    existing = db.execute(
        select(BillingPayment.id).where(
            BillingPayment.billing_account_id == account.id,
            BillingPayment.status.in_(("created", "pending")),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise BillingConflict("another commercial payment is still in progress")


def _calculation_line(
    *,
    kind: str,
    period_start: datetime | None,
    period_end: datetime | None,
    quantity_before: int,
    quantity_after: int,
    amount_kopeks: int,
) -> dict[str, object]:
    return {
        "kind": kind,
        "period_start": _iso(period_start),
        "period_end": _iso(period_end),
        "quantity_before": int(quantity_before),
        "quantity_after": int(quantity_after),
        "amount_kopeks": int(amount_kopeks),
    }


def prepare_manual_payment_intent(
    db: Session,
    *,
    user: User,
    idempotence_key: str,
    action: str = "renew",
    target_quantity: int | None = None,
    apply_now: bool = False,
    future_choice: str | None = None,
    retire_configuration_ids: list[uuid.UUID] | None = None,
    retire_new_configuration_ordinals: list[int] | None = None,
    now: datetime | None = None,
) -> PaymentIntent:
    point = now or utcnow()
    key = validate_idempotence_key(idempotence_key)
    account, offer, grant = _commercial_account_for_user(db, user=user, for_update=True)

    # Preserve the accepted idempotence rule: the key owns its original frozen
    # local intent even after that intent has changed the account state.
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
        raise BillingConflict("P29G supports manual billing only")
    if account.status == "past_due":
        raise BillingConflict("past-due renewal belongs to P29F")
    if account.status not in {"trial", "active_paid", "expired"}:
        raise BillingConflict("unsupported commercial account state")
    if account.status in {"trial", "active_paid"} and account.quantity_period_start > point:
        raise BillingConflict("commercial quantity period has not started")
    if account.status in {"trial", "active_paid"} and account.quantity_period_end <= point:
        raise BillingConflict("commercial quantity boundary is still settling")

    _ensure_no_other_inflight_payment(db, account=account)

    action = str(action or "renew").strip().casefold()
    if action not in {"renew", "add_now", "top_up_next"}:
        raise BillingConflict("unsupported commercial payment action")
    selected_existing = list(retire_configuration_ids or [])
    selected_new_ordinals = [int(value) for value in (retire_new_configuration_ordinals or [])]
    if len(set(selected_new_ordinals)) != len(selected_new_ordinals):
        raise BillingConflict("duplicate new-Configuration retirement ordinals")
    current_q = int(account.slot_quantity)
    target_q = current_q if target_quantity is None else int(target_quantity)
    _monthly_amount_kopeks(offer, target_q)  # quantity range authority

    expected = _account_snapshot(account)
    lines: list[dict[str, object]] = []
    planned_new_ids: list[uuid.UUID] = []
    selected: list[uuid.UUID] = list(selected_existing)
    target_start: datetime | None = None
    target_end: datetime | None = None
    kind = "upgrade"
    quantity_before = current_q
    quantity_after = target_q
    normalized_future_choice = str(future_choice).strip().casefold() if future_choice else None

    if action == "renew":
        if selected_new_ordinals:
            raise BillingConflict("new-Configuration retirement ordinals are not valid for renewal")
        if account.pending_slot_quantity is not None:
            raise BillingConflict("the next commercial month is already paid")
        if normalized_future_choice is not None:
            raise BillingConflict("future choice is not valid for ordinary renewal")

        if account.status == "expired":
            if apply_now:
                raise BillingConflict("expired reactivation has no separate apply-now component")
            if selected:
                raise BillingConflict("expired reactivation has no retirement selection")
            amount = _monthly_amount_kopeks(offer, target_q)
            lines.append(
                _calculation_line(
                    kind="reactivation_period",
                    period_start=None,
                    period_end=None,
                    quantity_before=current_q,
                    quantity_after=target_q,
                    amount_kopeks=amount,
                )
            )
            kind = "initial"
        else:
            target_start = account.quantity_period_end
            target_end = add_calendar_month(target_start)
            amount = _monthly_amount_kopeks(offer, target_q)
            lines.append(
                _calculation_line(
                    kind="next_period",
                    period_start=target_start,
                    period_end=target_end,
                    quantity_before=0,
                    quantity_after=target_q,
                    amount_kopeks=amount,
                )
            )
            if target_q < current_q:
                _validate_retirement_selection(
                    db,
                    account=account,
                    selected_ids=selected,
                    required_count=current_q - target_q,
                )
            elif selected:
                raise BillingConflict("retirement Configuration ids are not needed")

            if apply_now:
                if account.status != "active_paid":
                    raise BillingConflict("trial quantity cannot be increased immediately")
                if target_q <= current_q:
                    raise BillingConflict("apply-now requires a higher next-period quantity")
                if not _current_quantity_period_is_paid(db, account=account, point=point):
                    raise BillingConflict("current quantity period is not a paid period")
                prorated = _prorated_upgrade_kopeks(
                    offer,
                    quantity_before=current_q,
                    quantity_after=target_q,
                    point=point,
                    period_start=account.quantity_period_start,
                    period_end=account.quantity_period_end,
                )
                lines.append(
                    _calculation_line(
                        kind="current_proration",
                        period_start=point,
                        period_end=account.quantity_period_end,
                        quantity_before=current_q,
                        quantity_after=target_q,
                        amount_kopeks=prorated,
                    )
                )
                planned_new_ids = [uuid.uuid4() for _ in range(target_q - current_q)]
            kind = "manual_renewal" if account.status == "active_paid" else "initial"

    elif action == "add_now":
        if account.status != "active_paid":
            raise BillingConflict("immediate quantity increase requires active paid access")
        if target_quantity is None or target_q <= current_q:
            raise BillingConflict("immediate quantity target must be higher than current quantity")
        if apply_now:
            raise BillingConflict("add_now is already an immediate action")
        if not _current_quantity_period_is_paid(db, account=account, point=point):
            raise BillingConflict("current quantity period is not a paid period")

        prorated = _prorated_upgrade_kopeks(
            offer,
            quantity_before=current_q,
            quantity_after=target_q,
            point=point,
            period_start=account.quantity_period_start,
            period_end=account.quantity_period_end,
        )
        lines.append(
            _calculation_line(
                kind="current_proration",
                period_start=point,
                period_end=account.quantity_period_end,
                quantity_before=current_q,
                quantity_after=target_q,
                amount_kopeks=prorated,
            )
        )
        planned_new_ids = [uuid.uuid4() for _ in range(target_q - current_q)]
        if any(value < 1 or value > len(planned_new_ids) for value in selected_new_ordinals):
            raise BillingConflict("new-Configuration retirement ordinal is outside the immediate add set")
        selected = list(selected_existing) + [
            planned_new_ids[value - 1] for value in selected_new_ordinals
        ]
        if len(set(selected)) != len(selected):
            raise BillingConflict("duplicate retirement Configuration ids")
        target_start = account.quantity_period_start
        target_end = account.quantity_period_end

        if account.pending_slot_quantity is not None:
            pending_q = int(account.pending_slot_quantity)
            if pending_q < target_q:
                if normalized_future_choice not in {"preserve", "keep_paid"}:
                    raise BillingConflict(
                        "choose whether to preserve the higher quantity next month or keep the already-paid lower quantity"
                    )
                if normalized_future_choice == "preserve":
                    if selected:
                        raise BillingConflict("retirement Configuration ids conflict with preserve choice")
                    future_delta = _monthly_amount_kopeks(offer, target_q) - _monthly_amount_kopeks(offer, pending_q)
                    lines.append(
                        _calculation_line(
                            kind="next_period_top_up",
                            period_start=account.pending_period_start,
                            period_end=account.pending_period_end,
                            quantity_before=pending_q,
                            quantity_after=target_q,
                            amount_kopeks=future_delta,
                        )
                    )
                else:
                    _validate_retirement_selection(
                        db,
                        account=account,
                        selected_ids=selected,
                        required_count=target_q - pending_q,
                        planned_new_ids=planned_new_ids,
                    )
            else:
                if normalized_future_choice is not None:
                    raise BillingConflict("future choice is not needed for this already-paid next quantity")
                if selected:
                    raise BillingConflict("retirement Configuration ids are not needed")
        else:
            if normalized_future_choice is not None or selected:
                raise BillingConflict("no next paid month requires a future quantity choice")

    else:  # top_up_next
        if selected_new_ordinals:
            raise BillingConflict("new-Configuration retirement ordinals are not valid for next-period top-up")
        if account.pending_slot_quantity is None:
            raise BillingConflict("there is no already-paid next month to top up")
        pending_q = int(account.pending_slot_quantity)
        if target_quantity is None or target_q <= pending_q:
            raise BillingConflict("next-period top-up target must be higher than the paid next quantity")
        if apply_now or normalized_future_choice is not None:
            raise BillingConflict("next-period top-up does not accept apply-now/future-choice flags")
        amount = _monthly_amount_kopeks(offer, target_q) - _monthly_amount_kopeks(offer, pending_q)
        lines.append(
            _calculation_line(
                kind="next_period_top_up",
                period_start=account.pending_period_start,
                period_end=account.pending_period_end,
                quantity_before=pending_q,
                quantity_after=target_q,
                amount_kopeks=amount,
            )
        )
        quantity_before = pending_q
        target_start = account.pending_period_start
        target_end = account.pending_period_end
        required_retirements = max(0, current_q - target_q)
        if required_retirements:
            _validate_retirement_selection(
                db,
                account=account,
                selected_ids=selected,
                required_count=required_retirements,
            )
        elif selected:
            raise BillingConflict("retirement Configuration ids are not needed")

    amount_kopeks = sum(int(line["amount_kopeks"]) for line in lines)
    if amount_kopeks <= 0:
        raise BillingConflict("commercial payment amount must be positive")

    calculation = {
        "version": 1,
        "action": action,
        "created_at": _iso(point),
        "expected_account": expected,
        "target_quantity": target_q,
        "apply_now": bool(apply_now),
        "future_choice": normalized_future_choice,
        "planned_configuration_ids": [str(value) for value in planned_new_ids],
        "retire_configuration_ids": [str(value) for value in selected],
        "retire_new_configuration_ordinals": selected_new_ordinals,
        "lines": lines,
    }

    payment = BillingPayment(
        id=uuid.uuid4(),
        billing_account_id=account.id,
        provider="yookassa",
        provider_payment_id=None,
        idempotence_key=key,
        kind=kind,
        status="created",
        provider_status=None,
        amount_kopeks=amount_kopeks,
        currency=offer.currency,
        quantity_before=quantity_before,
        quantity_after=quantity_after,
        target_period_start=target_start,
        target_period_end=target_end,
        calculation_json=calculation,
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
            "action": action,
            "amount_kopeks": amount_kopeks,
            "currency": offer.currency,
            "quantity_before": quantity_before,
            "quantity_after": quantity_after,
            "line_count": len(lines),
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


def _set_mirrored_configuration_limit(
    db: Session,
    *,
    grant_id: uuid.UUID,
    quantity: int,
) -> None:
    rows = list(
        db.execute(
            select(AccessGrantProtocolLimit)
            .where(
                AccessGrantProtocolLimit.access_grant_id == grant_id,
                AccessGrantProtocolLimit.protocol.in_(("wireguard", "amneziawg")),
            )
            .with_for_update()
        ).scalars().all()
    )
    by_protocol = {row.protocol: row for row in rows}
    if set(by_protocol) != {"wireguard", "amneziawg"}:
        raise BillingConflict("commercial configuration limit mirror is incomplete")
    for row in rows:
        row.profile_limit = int(quantity)


def _scheduled_retirement_rows(
    db: Session,
    *,
    account: BillingAccount,
) -> list[BillingScheduledRetirement]:
    return list(
        db.execute(
            select(BillingScheduledRetirement)
            .where(BillingScheduledRetirement.billing_account_id == account.id)
            .order_by(
                BillingScheduledRetirement.created_at.asc(),
                BillingScheduledRetirement.id.asc(),
            )
            .with_for_update()
        ).scalars().all()
    )


def scheduled_retirement_configuration_ids(
    db: Session,
    *,
    account: BillingAccount,
) -> list[uuid.UUID]:
    return [row.connection_slot_id for row in _scheduled_retirement_rows(db, account=account)]


def _replace_scheduled_retirements(
    db: Session,
    *,
    account: BillingAccount,
    selected_ids: list[uuid.UUID],
    effective_at: datetime | None,
    now: datetime,
) -> None:
    rows = _scheduled_retirement_rows(db, account=account)
    for row in rows:
        db.delete(row)
    db.flush()
    if not selected_ids:
        return
    if effective_at is None:
        raise BillingConflict("retirement boundary is missing")
    for slot_id in selected_ids:
        db.add(
            BillingScheduledRetirement(
                id=uuid.uuid4(),
                billing_account_id=account.id,
                connection_slot_id=slot_id,
                effective_at=effective_at,
                created_at=now,
            )
        )
    db.flush()


def update_scheduled_retirement_selection(
    db: Session,
    *,
    user: User,
    configuration_ids: list[uuid.UUID],
    now: datetime | None = None,
) -> list[uuid.UUID]:
    point = now or utcnow()
    account, offer, grant = _commercial_account_for_user(db, user=user, for_update=True)
    if account.pending_slot_quantity is None or account.pending_period_start is None:
        raise BillingConflict("there is no pending quantity decrease")
    if int(account.pending_slot_quantity) >= int(account.slot_quantity):
        raise BillingConflict("there is no pending quantity decrease")
    if account.pending_period_start <= point:
        raise BillingConflict("pending quantity transition is already due")
    _ensure_no_other_inflight_payment(db, account=account)
    required = int(account.slot_quantity) - int(account.pending_slot_quantity)
    selected = _validate_retirement_selection(
        db,
        account=account,
        selected_ids=list(configuration_ids),
        required_count=required,
    )
    _replace_scheduled_retirements(
        db,
        account=account,
        selected_ids=selected,
        effective_at=account.pending_period_start,
        now=point,
    )
    record_audit_event(
        db,
        event_type="billing.quantity.retirement_selection.updated",
        actor_kind="user",
        actor_user_id=user.id,
        object_type="billing_account",
        object_id=str(account.id),
        payload={
            "pending_slot_quantity": int(account.pending_slot_quantity),
            "effective_at": _iso(account.pending_period_start),
            "configuration_ids": [str(value) for value in selected],
        },
    )
    return selected


def _create_missing_configurations(
    db: Session,
    *,
    user: User,
    grant: AccessGrant,
    count: int,
    now: datetime,
    planned_ids: list[uuid.UUID] | None = None,
) -> list[ConfigurationRequestResult]:
    planned = list(planned_ids or [])
    if planned and len(planned) != int(count):
        raise BillingConflict("frozen planned Configuration count is invalid")
    created: list[ConfigurationRequestResult] = []
    for index in range(int(count)):
        created.append(
            create_configuration_request(
                db,
                user=user,
                grant_id=grant.id,
                node_id=settings.wg_default_node_id,
                label=None,
                now=now,
                slot_id=planned[index] if planned else None,
            )
        )
    return created


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
    user = db.execute(
        select(User).where(User.id == account.user_id).with_for_update()
    ).scalar_one_or_none()
    if user is None or user.deletion_requested_at is not None:
        raise BillingConflict("commercial user is unavailable")
    grant = db.execute(
        select(AccessGrant).where(AccessGrant.id == account.access_grant_id).with_for_update()
    ).scalar_one_or_none()
    if grant is None or grant.user_id != user.id or grant.plan_id != offer.plan_id:
        raise BillingConflict("commercial entitlement linkage is invalid")

    calculation = payment.calculation_json
    if not isinstance(calculation, dict) or int(calculation.get("version") or 0) != 1:
        raise BillingConflict("commercial payment has no frozen P29G calculation")
    expected = calculation.get("expected_account")
    if not isinstance(expected, dict):
        raise BillingConflict("commercial payment expected-account snapshot is missing")
    _assert_account_snapshot(account, expected)

    action = str(calculation.get("action") or "")
    target_q = int(calculation.get("target_quantity") or payment.quantity_after)
    _monthly_amount_kopeks(offer, target_q)
    planned_ids = [uuid.UUID(str(value)) for value in calculation.get("planned_configuration_ids") or []]
    retire_ids = [uuid.UUID(str(value)) for value in calculation.get("retire_configuration_ids") or []]
    first_configuration: ConfigurationRequestResult | None = None

    if action == "renew":
        if account.status == "expired":
            if logical_slot_count(db, grant_id=grant.id, user_id=user.id) != 0:
                raise BillingConflict("expired runtime retirement is not yet settled")
            target_start = captured_at
            target_end = add_calendar_month(target_start)
            _set_mirrored_configuration_limit(db, grant_id=grant.id, quantity=target_q)
            grant.status = "active"
            grant.valid_from = target_start
            grant.valid_until = target_end
            grant.updated_at = utcnow()
            account.slot_quantity = target_q
            account.pending_slot_quantity = None
            account.quantity_period_start = target_start
            account.quantity_period_end = target_end
            account.pending_period_start = None
            account.pending_period_end = None
            account.current_period_start = target_start
            account.current_period_end = target_end
            account.status = "active_paid"
            account.grace_until = None
            account.cancel_at_period_end = False
            created = _create_missing_configurations(
                db,
                user=user,
                grant=grant,
                count=target_q,
                now=captured_at,
            )
            first_configuration = created[0] if created else None
            _replace_scheduled_retirements(
                db,
                account=account,
                selected_ids=[],
                effective_at=None,
                now=captured_at,
            )
            payment.target_period_start = target_start
            payment.target_period_end = target_end
        else:
            if account.pending_slot_quantity is not None:
                raise BillingConflict("the next commercial month became paid before this payment settled")
            target_start = _parse_calc_datetime(payment.target_period_start, field="target_period_start")
            target_end = _parse_calc_datetime(payment.target_period_end, field="target_period_end")
            if target_start is None or target_end is None:
                raise BillingConflict("frozen next-period boundary is missing")
            if target_start != account.quantity_period_end or target_end != add_calendar_month(target_start):
                raise BillingConflict("frozen next-period boundary no longer matches the account")

            account.pending_slot_quantity = target_q
            account.pending_period_start = target_start
            account.pending_period_end = target_end
            account.current_period_end = target_end
            account.status = "active_paid"
            account.grace_until = None
            account.cancel_at_period_end = False
            grant.status = "active"
            _extend_live_mirror(db, account=account, grant=grant, period_end=target_end)

            if bool(calculation.get("apply_now")):
                if target_q <= int(account.slot_quantity):
                    raise BillingConflict("frozen apply-now quantity is invalid")
                before = int(account.slot_quantity)
                _set_mirrored_configuration_limit(db, grant_id=grant.id, quantity=target_q)
                account.slot_quantity = target_q
                created = _create_missing_configurations(
                    db,
                    user=user,
                    grant=grant,
                    count=target_q - before,
                    now=captured_at,
                    planned_ids=planned_ids,
                )
                first_configuration = created[0] if created else None
                _extend_live_mirror(db, account=account, grant=grant, period_end=target_end)

            required = max(0, int(account.slot_quantity) - target_q)
            if required:
                _validate_retirement_selection(
                    db,
                    account=account,
                    selected_ids=retire_ids,
                    required_count=required,
                )
            elif retire_ids:
                raise BillingConflict("frozen retirement selection is no longer required")
            _replace_scheduled_retirements(
                db,
                account=account,
                selected_ids=retire_ids,
                effective_at=target_start if retire_ids else None,
                now=captured_at,
            )

    elif action == "add_now":
        before = int(account.slot_quantity)
        if target_q <= before:
            raise BillingConflict("frozen immediate quantity target is invalid")
        _set_mirrored_configuration_limit(db, grant_id=grant.id, quantity=target_q)
        account.slot_quantity = target_q
        created = _create_missing_configurations(
            db,
            user=user,
            grant=grant,
            count=target_q - before,
            now=captured_at,
            planned_ids=planned_ids,
        )
        first_configuration = created[0] if created else None

        future_choice = calculation.get("future_choice")
        if account.pending_slot_quantity is not None and int(account.pending_slot_quantity) < target_q:
            if future_choice == "preserve":
                account.pending_slot_quantity = target_q
                retire_ids = []
            elif future_choice == "keep_paid":
                required = target_q - int(account.pending_slot_quantity)
                _validate_retirement_selection(
                    db,
                    account=account,
                    selected_ids=retire_ids,
                    required_count=required,
                )
            else:
                raise BillingConflict("frozen future quantity choice is invalid")
        elif future_choice is not None:
            raise BillingConflict("frozen future choice is no longer applicable")

        _replace_scheduled_retirements(
            db,
            account=account,
            selected_ids=retire_ids,
            effective_at=account.pending_period_start if retire_ids else None,
            now=captured_at,
        )
        _extend_live_mirror(db, account=account, grant=grant, period_end=account.current_period_end)

    elif action == "top_up_next":
        if account.pending_slot_quantity is None:
            raise BillingConflict("next paid month disappeared before top-up success")
        if target_q <= int(account.pending_slot_quantity):
            raise BillingConflict("frozen next-period top-up target is invalid")
        account.pending_slot_quantity = target_q
        required = max(0, int(account.slot_quantity) - target_q)
        if required:
            _validate_retirement_selection(
                db,
                account=account,
                selected_ids=retire_ids,
                required_count=required,
            )
        elif retire_ids:
            raise BillingConflict("frozen retirement selection is no longer required")
        _replace_scheduled_retirements(
            db,
            account=account,
            selected_ids=retire_ids,
            effective_at=account.pending_period_start if retire_ids else None,
            now=captured_at,
        )
    else:
        raise BillingConflict("unsupported frozen commercial payment action")

    account.billing_mode = "manual"
    account.next_charge_at = None
    account.updated_at = utcnow()
    return first_configuration


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
    confirmation = provider.get("confirmation") or {}
    confirmation_url = str(confirmation.get("confirmation_url") or "").strip() or None

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
        return ReconcileResult(
            payment=payment,
            state_changed=False,
            configuration=None,
            confirmation_url=confirmation_url,
        )

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

@dataclass(frozen=True)
class QuantityTransitionResult:
    account_id: uuid.UUID
    quantity_before: int
    quantity_after: int
    configurations_created: int
    retirements_requested: int
    agent_wakeup_needed: bool


def apply_due_quantity_transitions(
    db: Session,
    *,
    now: datetime | None = None,
) -> list[QuantityTransitionResult]:
    point = now or utcnow()
    account_ids = list(
        db.execute(
            select(BillingAccount.id)
            .where(
                BillingAccount.pending_period_start.is_not(None),
                BillingAccount.pending_period_start <= point,
            )
            .order_by(BillingAccount.pending_period_start.asc(), BillingAccount.id.asc())
        ).scalars().all()
    )
    results: list[QuantityTransitionResult] = []
    for account_id in account_ids:
        account = db.execute(
            select(BillingAccount).where(BillingAccount.id == account_id).with_for_update()
        ).scalar_one_or_none()
        if (
            account is None
            or account.pending_slot_quantity is None
            or account.pending_period_start is None
            or account.pending_period_end is None
            or account.pending_period_start > point
        ):
            continue
        inflight = db.execute(
            select(BillingPayment.id).where(
                BillingPayment.billing_account_id == account.id,
                BillingPayment.status.in_(("created", "pending")),
            )
        ).scalar_one_or_none()
        if inflight is not None:
            raise BillingConflict(
                f"quantity transition is due while billing payment is in progress for account {account.id}"
            )
        offer = db.get(BillingOffer, account.offer_id)
        user = db.get(User, account.user_id)
        grant = db.execute(
            select(AccessGrant).where(AccessGrant.id == account.access_grant_id).with_for_update()
        ).scalar_one_or_none()
        if offer is None or not offer.active or user is None or grant is None:
            raise BillingConflict("due commercial quantity transition linkage is unavailable")

        before = int(account.slot_quantity)
        after = int(account.pending_slot_quantity)
        _monthly_amount_kopeks(offer, after)
        scheduled = _scheduled_retirement_rows(db, account=account)
        selected_ids = [row.connection_slot_id for row in scheduled]
        created_count = 0
        retirement_jobs = 0
        wakeup = False

        if after < before:
            if len(selected_ids) != before - after:
                raise BillingConflict(
                    f"due quantity decrease lacks exact retirement targets for account {account.id}"
                )
            eligible = set(_active_slot_ids(db, account=account))
            if any(slot_id not in eligible for slot_id in selected_ids):
                raise BillingConflict("scheduled retirement target is no longer an active Configuration")
            for slot_id in selected_ids:
                try:
                    disable_results = request_configuration_disable(db, slot_id=slot_id)
                except DomainV2Error as exc:
                    raise BillingConflict("scheduled Configuration cannot be retired") from exc
                retirement_jobs += sum(int(created) for _, _, created in disable_results)
                wakeup = True
            _set_mirrored_configuration_limit(db, grant_id=grant.id, quantity=after)
        elif after > before:
            if selected_ids:
                raise BillingConflict("quantity increase cannot have scheduled retirement targets")
            _set_mirrored_configuration_limit(db, grant_id=grant.id, quantity=after)
            created = _create_missing_configurations(
                db,
                user=user,
                grant=grant,
                count=after - before,
                now=point,
            )
            created_count = len(created)
            wakeup = bool(created)
        elif selected_ids:
            raise BillingConflict("unchanged quantity cannot have scheduled retirement targets")

        for row in scheduled:
            db.delete(row)

        account.slot_quantity = after
        account.quantity_period_start = account.pending_period_start
        account.quantity_period_end = account.pending_period_end
        account.pending_slot_quantity = None
        account.pending_period_start = None
        account.pending_period_end = None
        account.current_period_end = account.quantity_period_end
        account.updated_at = point
        record_audit_event(
            db,
            event_type="billing.quantity.period_transitioned",
            actor_kind="system",
            actor_user_id=user.id,
            object_type="billing_account",
            object_id=str(account.id),
            payload={
                "quantity_before": before,
                "quantity_after": after,
                "quantity_period_start": _iso(account.quantity_period_start),
                "quantity_period_end": _iso(account.quantity_period_end),
                "retire_configuration_ids": [str(value) for value in selected_ids],
                "retirement_jobs_created": retirement_jobs,
                "configurations_created": created_count,
            },
        )
        db.flush()
        results.append(
            QuantityTransitionResult(
                account_id=account.id,
                quantity_before=before,
                quantity_after=after,
                configurations_created=created_count,
                retirements_requested=len(selected_ids),
                agent_wakeup_needed=wakeup,
            )
        )
    return results
