"""Recipient eligibility, durable drafting and broadcast state helpers.

No SMTP transport or public API is implemented here.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from sqlalchemy import select, func, exists, or_
from sqlalchemy.orm import Session

from app.models import User, AccessGrant, Plan, AdminBroadcast, AdminBroadcastRecipient
from app.services.domain_v2 import InvalidIdentity, normalize_email, record_audit_event, utcnow
from app.api.auth_v2 import YOOKASSA_REVIEW_EMAIL, YOOKASSA_REVIEW_PLAN_CODE

DRAFT_TTL = timedelta(minutes=15)


class BroadcastRejected(RuntimeError):
    pass


def validate_message(subject: str, body: str) -> tuple[str, str]:
    title = str(subject).strip()
    message = str(body)
    if not 1 <= len(title) <= 200 or any(ord(c) < 32 or ord(c) == 127 for c in title):
        raise BroadcastRejected("invalid_subject")
    if not 1 <= len(message) <= 10000 or "\x00" in message:
        raise BroadcastRejected("invalid_body")
    return title, message


def _active_access(user_id, now: datetime):
    return exists(select(AccessGrant.id).where(
        AccessGrant.user_id == user_id,
        AccessGrant.status == "active",
        AccessGrant.valid_from <= now,
        or_(AccessGrant.valid_until.is_(None), AccessGrant.valid_until > now),
    ))


def _is_review(user_id):
    return exists(
        select(AccessGrant.id).join(Plan, Plan.id == AccessGrant.plan_id).where(
            AccessGrant.user_id == user_id,
            Plan.code == YOOKASSA_REVIEW_PLAN_CODE,
        )
    )


def eligible_addresses(db: Session, audience: str, *, now: datetime | None = None) -> dict[str, UUID]:
    if audience not in {"active", "all"}:
        raise BroadcastRejected("invalid_audience")
    point = now or utcnow()
    query = select(User).where(
        User.email_verified_at.is_not(None),
        User.deletion_requested_at.is_(None),
        func.lower(User.email) != YOOKASSA_REVIEW_EMAIL,
        ~_is_review(User.id),
    ).order_by(User.created_at, User.id)
    if audience == "active":
        query = query.where(_active_access(User.id, point))
    result: dict[str, UUID] = {}
    for user in db.execute(query).scalars():
        try:
            normalized = normalize_email(user.email)
        except InvalidIdentity:
            # Legacy invalid addresses cannot be used as SMTP recipients.
            continue
        result.setdefault(normalized, user.id)
    return result


def recipient_is_eligible(db: Session, recipient: AdminBroadcastRecipient, audience: str, *, now: datetime | None = None) -> bool:
    if recipient.user_id is None:
        return False
    user = db.get(User, recipient.user_id)
    if user is None or user.email_verified_at is None or user.deletion_requested_at is not None:
        return False
    try:
        if normalize_email(user.email) != recipient.normalized_email:
            return False
    except InvalidIdentity:
        return False
    if user.email.casefold() == YOOKASSA_REVIEW_EMAIL:
        return False
    if db.scalar(select(_is_review(user.id))):
        return False
    if audience == "active" and not db.scalar(select(_active_access(user.id, now or utcnow()))):
        return False
    return True


def recipient_counts(db: Session, campaign_id: UUID) -> dict[str, int]:
    rows = db.execute(
        select(AdminBroadcastRecipient.state, func.count(AdminBroadcastRecipient.id))
        .where(AdminBroadcastRecipient.broadcast_id == campaign_id)
        .group_by(AdminBroadcastRecipient.state)
    ).all()
    return {str(k): int(v) for k, v in rows}


def create_draft(db: Session, *, audience: str, subject: str, body: str, request_id: str) -> AdminBroadcast:
    title, message = validate_message(subject, body)
    addresses = eligible_addresses(db, audience)
    point = utcnow()
    campaign = AdminBroadcast(
        id=uuid4(), audience=audience, subject=title, body=message,
        state="draft", recipient_count=len(addresses), created_at=point, updated_at=point,
    )
    db.add(campaign)
    db.flush()
    db.add_all(AdminBroadcastRecipient(
        id=uuid4(), broadcast_id=campaign.id, user_id=user_id,
        normalized_email=email, state="pending",
    ) for email, user_id in addresses.items())
    record_audit_event(
        db, event_type="admin.broadcast.draft_created", actor_kind="admin",
        object_type="admin_broadcast", object_id=str(campaign.id),
        request_id=request_id, payload={"audience": audience, "recipient_count": len(addresses)},
    )
    return campaign


def confirm_send(db: Session, *, campaign_id: UUID, expected_count: int, request_id: str) -> AdminBroadcast:
    campaign = db.scalar(select(AdminBroadcast).where(AdminBroadcast.id == campaign_id).with_for_update())
    if campaign is None:
        raise BroadcastRejected("not_found")
    if campaign.state != "draft":
        # Repeated confirmation is a harmless read of the existing campaign.
        if campaign.confirmed_at is not None and campaign.recipient_count == expected_count:
            return campaign
        raise BroadcastRejected("already_modified")
    now = utcnow()
    if now - campaign.created_at.replace(tzinfo=campaign.created_at.tzinfo or timezone.utc) > DRAFT_TTL:
        raise BroadcastRejected("stale_draft")
    if not campaign.recipient_count or campaign.recipient_count != expected_count:
        raise BroadcastRejected("recipient_count_mismatch")
    addresses = eligible_addresses(db, campaign.audience, now=now)
    snapshot = dict(db.execute(
        select(AdminBroadcastRecipient.normalized_email, AdminBroadcastRecipient.user_id)
        .where(AdminBroadcastRecipient.broadcast_id == campaign.id)
    ).all())
    if snapshot != addresses:
        raise BroadcastRejected("recipient_snapshot_changed")
    campaign.state = "queued"
    campaign.confirmed_at = now
    campaign.updated_at = now
    record_audit_event(
        db, event_type="admin.broadcast.confirmed", actor_kind="admin",
        object_type="admin_broadcast", object_id=str(campaign.id), request_id=request_id,
        payload={"audience": campaign.audience, "recipient_count": campaign.recipient_count},
    )
    return campaign
