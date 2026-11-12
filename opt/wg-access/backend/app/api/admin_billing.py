"""Read-only commercial billing projections for the authenticated private Admin UI.

Never reconcile provider payments, issue tokens, send mail, or modify the DB here.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import IntEnum
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import String, and_, cast, func, or_, select
from sqlalchemy.orm import Session

from app.api.auth_v2 import _require_admin, YOOKASSA_REVIEW_OFFER_CODE
from app.db.session import get_db
from app.models import AccessGrant, AuditEvent, BillingAccount, BillingOffer, BillingPayment, User

router = APIRouter(prefix="/v2/admin/billing", tags=["admin-billing"], dependencies=[Depends(_require_admin)])
Scope = Literal["commercial", "review", "all"]
AccountStatus = Literal["all", "trial", "active_paid", "past_due", "expired"]
PaymentStatus = Literal["all", "created", "pending", "succeeded", "canceled"]


class LookbackDays(IntEnum):
    days_30 = 30
    days_90 = 90
    days_365 = 365


def _headers(response: Response):
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _scope_clause(scope: Scope):
    if scope == "review":
        return BillingOffer.code == YOOKASSA_REVIEW_OFFER_CODE
    if scope == "commercial":
        return BillingOffer.code != YOOKASSA_REVIEW_OFFER_CODE
    return None


def _category(offer_code: str | None) -> str:
    if offer_code is None:
        return "unattributed"
    return "review" if offer_code == YOOKASSA_REVIEW_OFFER_CODE else "commercial"


def _reminder_period(ev: AuditEvent) -> datetime | None:
    if not isinstance(ev.payload_json, dict):
        return None
    raw = ev.payload_json.get("current_period_end")
    if not isinstance(raw, str):
        return None
    try:
        return _as_utc(datetime.fromisoformat(raw.replace("Z", "+00:00")))
    except ValueError:
        return None


def _account_reminders(db: Session, account: BillingAccount, *, limit: int = 200):
    # Match the exact account-id prefix; do not infer a reminder from a generic login.
    prefix = f"{account.id}:"
    return db.execute(
        select(AuditEvent)
        .where(AuditEvent.event_type == "billing.renewal_reminder.sent")
        .where(AuditEvent.object_type == "billing_account_period")
        .where(AuditEvent.object_id.like(prefix + "%"))
        .where(AuditEvent.actor_user_id == account.user_id)
        .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
        .limit(limit + 1)
    ).scalars().all()


def _last_success(db: Session, account_id: UUID) -> BillingPayment | None:
    return db.execute(
        select(BillingPayment)
        .where(BillingPayment.billing_account_id == account_id, BillingPayment.status == "succeeded")
        .order_by(BillingPayment.succeeded_at.desc(), BillingPayment.id.desc())
        .limit(1)
    ).scalar_one_or_none()


def _account_row(db: Session, account: BillingAccount, user: User | None,
                 offer: BillingOffer, grant: AccessGrant | None, now: datetime) -> dict:
    last_payment = _last_success(db, account.id)
    reminders = _account_reminders(db, account)
    valid = [ev for ev in reminders if _reminder_period(ev) is not None]
    current = next((ev for ev in valid if _reminder_period(ev) == _as_utc(account.current_period_end)), None)
    end = _as_utc(account.current_period_end)
    return {
        "billing_account_id": account.id,
        "user_id": account.user_id,
        "email": user.email if user else None,
        "display_name": user.display_name if user else None,
        "registered_at_utc": _as_utc(user.created_at) if user else None,
        "category": _category(offer.code),
        "status": account.status,
        "billing_mode": account.billing_mode,
        "access_grant_status": grant.status if grant else None,
        "slot_quantity": account.slot_quantity,
        "pending_slot_quantity": account.pending_slot_quantity,
        "current_period_start_utc": _as_utc(account.current_period_start),
        "current_period_end_utc": end,
        "quantity_period_end_utc": _as_utc(account.quantity_period_end),
        "last_succeeded_payment_at_utc": _as_utc(last_payment.succeeded_at) if last_payment else None,
        "last_succeeded_payment_amount_kopeks": last_payment.amount_kopeks if last_payment else None,
        "last_reminder_sent_at_utc": _as_utc(valid[0].occurred_at) if valid else None,
        "current_period_reminder_sent_at_utc": _as_utc(current.occurred_at) if current else None,
        "reminder_evidence_truncated": len(reminders) > 200,
        "due_within_3_days": bool(account.status == "active_paid" and end and now < end <= now + timedelta(days=3)),
    }


def _account_query(scope: Scope):
    query = (
        select(BillingAccount, User, BillingOffer, AccessGrant)
        .join(BillingOffer, BillingOffer.id == BillingAccount.offer_id)
        .outerjoin(User, User.id == BillingAccount.user_id)
        .outerjoin(AccessGrant, AccessGrant.id == BillingAccount.access_grant_id)
    )
    clause = _scope_clause(scope)
    return query.where(clause) if clause is not None else query


def _account_totals_query(scope: Scope):
    query = select(BillingAccount.status, func.count(BillingAccount.id)).join(
        BillingOffer, BillingOffer.id == BillingAccount.offer_id
    )
    clause = _scope_clause(scope)
    if clause is not None:
        query = query.where(clause)
    return query.group_by(BillingAccount.status)


def _payment_query(scope: Scope):
    query = (
        select(BillingPayment, BillingAccount, BillingOffer, User)
        .outerjoin(BillingAccount, BillingAccount.id == BillingPayment.billing_account_id)
        .outerjoin(BillingOffer, BillingOffer.id == BillingAccount.offer_id)
        .outerjoin(User, User.id == BillingAccount.user_id)
    )
    clause = _scope_clause(scope)
    if clause is not None:
        query = query.where(clause)
    return query


def _payment_row(row):
    payment, account, offer, user = row
    return {
        "payment_id": payment.id,
        "billing_account_id": payment.billing_account_id,
        "user_id": account.user_id if account is not None else None,
        "email": user.email if user else None,
        "category": _category(offer.code if offer is not None else None),
        "kind": payment.kind,
        "status": payment.status,
        "provider_status": payment.provider_status,
        "amount_kopeks": payment.amount_kopeks,
        "currency": payment.currency,
        "quantity_before": payment.quantity_before,
        "quantity_after": payment.quantity_after,
        "created_at_utc": _as_utc(payment.created_at),
        "succeeded_at_utc": _as_utc(payment.succeeded_at),
        "target_period_start_utc": _as_utc(payment.target_period_start),
        "target_period_end_utc": _as_utc(payment.target_period_end),
    }


class BillingAccountRow(BaseModel):
    billing_account_id: UUID
    user_id: UUID
    email: str | None
    display_name: str | None
    registered_at_utc: datetime | None
    category: Literal["commercial", "review"]
    status: str
    billing_mode: str
    access_grant_status: str | None
    slot_quantity: int
    pending_slot_quantity: int | None
    current_period_start_utc: datetime
    current_period_end_utc: datetime
    quantity_period_end_utc: datetime
    last_succeeded_payment_at_utc: datetime | None
    last_succeeded_payment_amount_kopeks: int | None
    last_reminder_sent_at_utc: datetime | None
    current_period_reminder_sent_at_utc: datetime | None
    reminder_evidence_truncated: bool
    due_within_3_days: bool


class AccountsResponse(BaseModel):
    as_of_utc: datetime
    scope: Scope
    total: int
    limit: int
    offset: int
    has_more: bool
    rows: list[BillingAccountRow]


class BillingPaymentRow(BaseModel):
    payment_id: UUID
    billing_account_id: UUID | None
    user_id: UUID | None
    email: str | None
    category: Literal["commercial", "review", "unattributed"]
    kind: str
    status: str
    provider_status: str | None
    amount_kopeks: int
    currency: str
    quantity_before: int
    quantity_after: int
    created_at_utc: datetime
    succeeded_at_utc: datetime | None
    target_period_start_utc: datetime | None
    target_period_end_utc: datetime | None


class PaymentsResponse(BaseModel):
    as_of_utc: datetime
    scope: Scope
    days: int
    status: PaymentStatus
    total: int
    limit: int
    offset: int
    has_more: bool
    rows: list[BillingPaymentRow]


class TimelineEvent(BaseModel):
    type: str
    at_utc: datetime | None
    evidence_source: Literal["billing_payments", "audit_events"]
    payment_id: UUID | None = None
    amount_kopeks: int | None = None
    kind: str | None = None
    period_end_utc: datetime | None = None
    target_period_end_utc: datetime | None = None


class AccountDetailResponse(BaseModel):
    as_of_utc: datetime
    account: BillingAccountRow
    timeline: list[TimelineEvent]
    timeline_truncated: bool
    reminder_delivery_read_tracking: bool


class Overview(BaseModel):
    as_of_utc: datetime
    period_start_utc: datetime
    period_end_utc: datetime
    scope: Scope
    accounts_by_status: dict[str, int]
    active_paid_due_within_3_days: int
    ever_paid_accounts: int
    succeeded_count: int
    succeeded_gross_kopeks: int
    created_count: int
    pending_count: int
    canceled_count: int
    unattributed_succeeded_count: int | None
    unattributed_succeeded_kopeks: int | None
    reminder_sent_count: int
    money_note: str = "Gross confirmed payments before refunds, chargebacks, fees; not net revenue."


@router.get("/overview", response_model=Overview)
def overview(response: Response, days: LookbackDays = LookbackDays.days_30,
             scope: Scope = "commercial", db: Session = Depends(get_db)):
    _headers(response)
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    counts = {state: 0 for state in ("trial", "active_paid", "past_due", "expired")}
    counts.update({state: int(count) for state, count in db.execute(_account_totals_query(scope))})
    due_query = select(func.count(BillingAccount.id)).join(BillingOffer).where(
        BillingAccount.status == "active_paid", BillingAccount.current_period_end > now,
        BillingAccount.current_period_end <= now + timedelta(days=3),
    )
    clause = _scope_clause(scope)
    if clause is not None:
        due_query = due_query.where(clause)
    due = db.execute(due_query).scalar_one()
    ever_query = select(func.count(func.distinct(BillingPayment.billing_account_id))).select_from(BillingPayment).join(
        BillingAccount, BillingAccount.id == BillingPayment.billing_account_id
    ).join(BillingOffer, BillingOffer.id == BillingAccount.offer_id).where(BillingPayment.status == "succeeded")
    if clause is not None:
        ever_query = ever_query.where(clause)
    ever_paid = db.execute(ever_query).scalar_one()

    # No provider call: only locally persisted authoritative payment states.
    # Use explicit ledger join to avoid accidental double-counting from accounts/audit events.
    sums = _payment_query(scope).where(
        BillingPayment.status == "succeeded", BillingPayment.succeeded_at >= start,
        BillingPayment.succeeded_at <= now,
    ).with_only_columns(func.count(BillingPayment.id), func.coalesce(func.sum(BillingPayment.amount_kopeks), 0))
    succeeded_count, amount = db.execute(sums).one()
    other_counts = {}
    for status in ("created", "pending", "canceled"):
        statement = _payment_query(scope).where(
            BillingPayment.status == status, BillingPayment.created_at >= start,
            BillingPayment.created_at <= now,
        ).with_only_columns(func.count(BillingPayment.id))
        other_counts[status] = db.execute(statement).scalar_one()

    detached = select(func.count(BillingPayment.id), func.coalesce(func.sum(BillingPayment.amount_kopeks), 0)).where(
        BillingPayment.billing_account_id.is_(None), BillingPayment.status == "succeeded",
        BillingPayment.succeeded_at >= start, BillingPayment.succeeded_at <= now,
    )
    detached_count, detached_sum = db.execute(detached).one()
    # Count committed SMTP-success events; for scoped views verify the exact
    # billing-account ID stored in the event payload, not just the user ID.
    reminder_query = select(func.count(AuditEvent.id)).where(
        AuditEvent.event_type == "billing.renewal_reminder.sent",
        AuditEvent.object_type == "billing_account_period",
        AuditEvent.occurred_at >= start, AuditEvent.occurred_at <= now,
    )
    if scope != "all":
        normalized_event_id = func.replace(AuditEvent.payload_json["billing_account_id"].as_string(), "-", "")
        normalized_account_id = func.replace(cast(BillingAccount.id, String), "-", "")
        reminder_query = reminder_query.join(
            BillingAccount,
            (AuditEvent.actor_user_id == BillingAccount.user_id) &
            (normalized_event_id == normalized_account_id),
        ).join(BillingOffer, BillingOffer.id == BillingAccount.offer_id).where(clause)
    reminder_count = db.execute(reminder_query).scalar_one()
    return Overview(
        as_of_utc=now, period_start_utc=start, period_end_utc=now, scope=scope,
        accounts_by_status=counts, active_paid_due_within_3_days=due,
        ever_paid_accounts=ever_paid, succeeded_count=succeeded_count,
        succeeded_gross_kopeks=amount,
        created_count=other_counts["created"], pending_count=other_counts["pending"],
        canceled_count=other_counts["canceled"],
        unattributed_succeeded_count=detached_count if scope == "all" else None,
        unattributed_succeeded_kopeks=detached_sum if scope == "all" else None,
        reminder_sent_count=reminder_count,
    )


@router.get("/accounts", response_model=AccountsResponse)
def accounts(response: Response, scope: Scope = "commercial", status: AccountStatus = "all",
             query: str = Query("", max_length=120), limit: int = Query(50, ge=1, le=100),
             offset: int = Query(0, ge=0, le=5000), db: Session = Depends(get_db)):
    _headers(response)
    base = _account_query(scope)
    if status != "all":
        base = base.where(BillingAccount.status == status)
    cleaned = query.strip().lower()
    if cleaned:
        # Escape wildcard characters: search is literal substring rather than SQL LIKE syntax.
        escaped = cleaned.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        base = base.where(func.lower(User.email).like(f"%{escaped}%", escape="\\"))
    count_stmt = base.with_only_columns(func.count(BillingAccount.id)).order_by(None)
    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(base.order_by(BillingAccount.current_period_end.asc(), BillingAccount.id.asc()).limit(limit).offset(offset)).all()
    now = datetime.now(timezone.utc)
    return {"as_of_utc": now, "scope": scope, "total": total, "limit": limit, "offset": offset,
            "has_more": offset + len(rows) < total,
            "rows": [_account_row(db, account, user, offer, grant, now) for account, user, offer, grant in rows]}


@router.get("/accounts/{account_id}", response_model=AccountDetailResponse)
def account_detail(account_id: UUID, response: Response, limit: int = Query(50, ge=1, le=100),
                   db: Session = Depends(get_db)):
    _headers(response)
    row = db.execute(_account_query("all").where(BillingAccount.id == account_id)).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="billing_account_not_found")
    account, user, offer, grant = row
    now = datetime.now(timezone.utc)
    item = _account_row(db, account, user, offer, grant, now)
    payments = db.execute(select(BillingPayment).where(BillingPayment.billing_account_id == account.id)
                          .order_by(BillingPayment.created_at.desc(), BillingPayment.id.desc()).limit(limit + 1)).scalars().all()
    timeline: list[dict] = []
    for payment in payments[:limit]:
        typ = "payment_succeeded" if payment.status == "succeeded" else "payment_" + payment.status
        timeline.append({"type": typ,
                         "at_utc": _as_utc(payment.succeeded_at if payment.status == "succeeded" else payment.created_at),
                         "evidence_source": "billing_payments", "payment_id": payment.id,
                         "amount_kopeks": payment.amount_kopeks, "kind": payment.kind,
                         "target_period_end_utc": _as_utc(payment.target_period_end)})
    sent_rows = _account_reminders(db, account, limit=200)
    issued = db.execute(select(AuditEvent).where(
        AuditEvent.event_type == "billing.renewal_reminder.magic_link_issued",
        AuditEvent.actor_user_id == account.user_id,
        AuditEvent.request_id.like(f"renewal-reminder:{account.id}:%"),
    ).order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc()).limit(201)).scalars().all()
    # Only tokens from a committed reminder's exact period count as confirmed link use.
    sent_periods = {_reminder_period(ev) for ev in sent_rows[:200] if _reminder_period(ev) is not None}
    issued_tokens: dict[str, datetime] = {}
    for ev in issued[:200]:
        suffix = (ev.request_id or "").removeprefix(f"renewal-reminder:{account.id}:")
        try:
            period_end = _as_utc(datetime.fromisoformat(suffix.replace("Z", "+00:00")))
        except ValueError:
            continue
        if period_end in sent_periods and ev.object_type == "magic_link_token" and ev.object_id:
            issued_tokens[ev.object_id] = period_end
    for ev in sent_rows[:200]:
        if _reminder_period(ev) is not None:
            timeline.append({"type": "reminder_smtp_accepted", "at_utc": _as_utc(ev.occurred_at),
                             "evidence_source": "audit_events", "period_end_utc": _reminder_period(ev)})
    if issued_tokens:
        consumed = db.execute(select(AuditEvent).where(
            AuditEvent.event_type == "auth.magic_link.consumed",
            AuditEvent.object_type == "magic_link_token",
            AuditEvent.object_id.in_(list(issued_tokens)),
            AuditEvent.actor_user_id == account.user_id,
        ).order_by(AuditEvent.occurred_at.desc()).limit(201)).scalars().all()
        for ev in consumed[:200]:
            if isinstance(ev.payload_json, dict) and ev.payload_json.get("purpose") == "renewal_login":
                timeline.append({"type": "reminder_link_used", "at_utc": _as_utc(ev.occurred_at),
                                 "evidence_source": "audit_events", "period_end_utc": issued_tokens[ev.object_id]})
    timeline.sort(key=lambda value: value["at_utc"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return {"as_of_utc": now, "account": item, "timeline": timeline[:300],
            "timeline_truncated": (len(timeline) > 300 or len(payments) > limit or len(sent_rows) > 200 or len(issued) > 200),
            "reminder_delivery_read_tracking": False}


@router.get("/payments", response_model=PaymentsResponse)
def payments(response: Response, days: LookbackDays = LookbackDays.days_30, scope: Scope = "commercial",
             status: PaymentStatus = "all", limit: int = Query(50, ge=1, le=100),
             offset: int = Query(0, ge=0, le=5000), db: Session = Depends(get_db)):
    _headers(response)
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    base = _payment_query(scope)
    if status != "all":
        base = base.where(BillingPayment.status == status)
    # A delayed succeeded payment belongs to the period of confirmation, even
    # when its payment intent was created before the selected window.
    if status == "succeeded":
        base = base.where(BillingPayment.succeeded_at >= start, BillingPayment.succeeded_at <= now)
    elif status == "all":
        base = base.where(or_(
            and_(BillingPayment.status == "succeeded", BillingPayment.succeeded_at >= start,
                 BillingPayment.succeeded_at <= now),
            and_(BillingPayment.status != "succeeded", BillingPayment.created_at >= start,
                 BillingPayment.created_at <= now),
        ))
    else:
        base = base.where(BillingPayment.created_at >= start, BillingPayment.created_at <= now)
    total = db.execute(base.with_only_columns(func.count(BillingPayment.id)).order_by(None)).scalar_one()
    rows = db.execute(base.order_by(BillingPayment.created_at.desc(), BillingPayment.id.desc()).limit(limit).offset(offset)).all()
    return {"as_of_utc": now, "scope": scope, "days": days, "status": status,
            "total": total, "limit": limit, "offset": offset, "has_more": offset + len(rows) < total,
            "rows": [_payment_row(row) for row in rows]}
