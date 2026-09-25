from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import uuid

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import (
    AccessGrant,
    AuditEvent,
    AuthSession,
    BulkInviteCampaign,
    Invite,
    InviteRedemption,
    MagicLinkToken,
    Plan,
    User,
)
from app.services.commercial import (
    CommercialRegistrationRejected,
    ReferralNotEligible,
    active_offer_for_plan,
    commercial_invite_is_effective,
    commercial_referral_invite_is_effective,
    create_commercial_trial_registration,
    require_referral_eligible,
)
from app.services.domain_v2 import (
    InvalidIdentity,
    create_grant_from_plan,
    create_profile_request,
    ensure_verified_user,
    normalize_email,
    protocol_limit,
    record_audit_event,
    utcnow,
)


class AuthV2Error(RuntimeError):
    pass


class InviteRejected(AuthV2Error):
    pass


class BulkInviteRejected(AuthV2Error):
    pass


class MagicLinkRejected(AuthV2Error):
    pass


class SessionRejected(AuthV2Error):
    pass


class RateLimitExceeded(AuthV2Error):
    pass


class InviteResendTooSoon(AuthV2Error):
    def __init__(self, retry_after_seconds: int):
        super().__init__("invite resend cooldown is active")
        self.retry_after_seconds = max(int(retry_after_seconds), 1)


@dataclass(frozen=True)
class SecretToken:
    raw: str
    digest: str


@dataclass(frozen=True)
class InviteIssueResult:
    invite: Invite
    token: str


@dataclass(frozen=True)
class BulkInviteCampaignIssueResult:
    campaign: BulkInviteCampaign
    token: str


@dataclass(frozen=True)
class MagicLinkIssueResult:
    row: MagicLinkToken | None
    token: str | None


@dataclass(frozen=True)
class ExpiredRegistrationMagicLink:
    row: MagicLinkToken
    invite: Invite
    email: str
    resend_available_at: datetime | None
    can_resend: bool
    ttl_seconds: int


@dataclass(frozen=True)
class SessionIssueResult:
    session: AuthSession
    token: str
    agent_wakeup_needed: bool = False


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def secret_token() -> SecretToken:
    raw = secrets.token_urlsafe(32)
    return SecretToken(raw=raw, digest=_sha256_text(raw))


def fingerprint(value: str) -> str:
    return _sha256_text(str(value or ""))


def email_fingerprint(value: str) -> str:
    try:
        normalized = normalize_email(value)
    except InvalidIdentity:
        normalized = str(value or "").strip().casefold()
    return fingerprint(normalized)


def request_id_or_new(value: str | None) -> str:
    text_value = str(value or "").strip()
    return text_value[:128] if text_value else uuid.uuid4().hex


def issue_invite(
    db: Session,
    *,
    intended_email: str | None,
    ttl_seconds: int,
    plan_id: uuid.UUID,
    wireguard_profile_limit: int | None = None,
    recipient_referrals_enabled: bool = True,
    recipient_referral_limit: int = 3,
    created_by_kind: str = "admin",
    created_by_user_id: uuid.UUID | None = None,
    created_by_label: str | None = None,
    request_id: str | None = None,
) -> InviteIssueResult:
    normalized = normalize_email(intended_email) if intended_email else None
    if ttl_seconds < 60:
        raise AuthV2Error("invite ttl is too short")
    plan = db.get(Plan, plan_id)
    if plan is None or not plan.active:
        raise AuthV2Error("plan is unavailable")

    issuer_kind = str(created_by_kind or "").strip().casefold()
    recipient_referral_limit = int(recipient_referral_limit)
    if recipient_referral_limit < 0:
        raise AuthV2Error("recipient referral limit is invalid")
    if issuer_kind not in {"admin", "user", "system"}:
        raise AuthV2Error("invite issuer kind is invalid")
    issuer_user_id = created_by_user_id
    now = utcnow()
    offer = active_offer_for_plan(db, plan_id=plan.id)

    if issuer_kind == "user":
        if issuer_user_id is None:
            raise AuthV2Error("invite issuer user is required")
        issuer = db.get(User, issuer_user_id)
        if issuer is None:
            raise AuthV2Error("invite issuer user is unavailable")
        if offer is None:
            raise AuthV2Error("user referrals require a commercial plan")
        if normalized is not None:
            raise AuthV2Error("user referral invite must remain transferable")
        try:
            eligibility = require_referral_eligible(
                db,
                user_id=issuer.id,
                now=now,
                lock_account=True,
            )
        except ReferralNotEligible as exc:
            raise AuthV2Error("referral privilege is unavailable") from exc
        if eligibility.offer.id != offer.id:
            raise AuthV2Error("user commercial offer mismatch")
        if int(plan.default_wireguard_limit) != int(offer.base_slot_quantity) or int(plan.default_amneziawg_limit) != int(offer.base_slot_quantity):
            raise AuthV2Error("commercial plan configuration limit drift")
        if wireguard_profile_limit is not None and int(wireguard_profile_limit) != int(offer.base_slot_quantity):
            raise AuthV2Error("commercial referral configuration limit is fixed")
        wg_limit = int(offer.base_slot_quantity)
        active_count = int(db.execute(
            select(func.count(Invite.id)).where(
                Invite.created_by_kind == "user",
                Invite.created_by_user_id == issuer.id,
                Invite.revoked_at.is_(None),
                Invite.used_count < Invite.max_uses,
                (Invite.expires_at.is_(None) | (Invite.expires_at > now)),
            )
        ).scalar_one())
        referral_limit = int(eligibility.owner.referral_limit)
        if referral_limit < 0:
            raise AuthV2Error("referral invite limit is invalid")
        if referral_limit != 0 and active_count >= referral_limit:
            raise AuthV2Error("active referral invite limit reached")
        issuer_label = normalize_email(issuer.email)
        # User-created referral recipients always inherit the product default.
        # The referring user cannot delegate or suppress this policy.
        recipient_referrals_enabled = True
        recipient_referral_limit = 3
    else:
        if issuer_user_id is not None:
            raise AuthV2Error("non-user invite issuer cannot have a user id")
        if offer is not None:
            if int(plan.default_wireguard_limit) != int(offer.base_slot_quantity) or int(plan.default_amneziawg_limit) != int(offer.base_slot_quantity):
                raise AuthV2Error("commercial plan configuration limit drift")
            if wireguard_profile_limit is not None and int(wireguard_profile_limit) != int(offer.base_slot_quantity):
                raise AuthV2Error("commercial onboarding configuration limit is fixed")
            wg_limit = int(offer.base_slot_quantity)
        else:
            wg_limit = plan.default_wireguard_limit if wireguard_profile_limit is None else int(wireguard_profile_limit)
            if wg_limit < 0:
                raise AuthV2Error("wireguard profile limit is invalid")
        issuer_label = str(created_by_label or ("Admin" if issuer_kind == "admin" else "System")).strip()
        if not issuer_label or len(issuer_label) > 320:
            raise AuthV2Error("invite issuer label is invalid")

    tok = secret_token()
    row = Invite(
        id=uuid.uuid4(),
        token_hash=tok.digest,
        created_by_user_id=issuer_user_id,
        created_by_kind=issuer_kind,
        created_by_label=issuer_label,
        intended_email=normalized,
        pending_email=None,
        wireguard_profile_limit=wg_limit,
        plan_id=plan_id,
        bulk_campaign_id=None,
        recipient_referrals_enabled=bool(recipient_referrals_enabled),
        recipient_referral_limit=recipient_referral_limit,
        max_uses=1,
        used_count=0,
        expires_at=now + timedelta(seconds=ttl_seconds),
        revoked_at=None,
        created_at=now,
    )
    db.add(row)
    db.flush()
    record_audit_event(
        db,
        event_type="auth.invite.issued",
        actor_kind=issuer_kind,
        actor_user_id=issuer_user_id,
        object_type="invite",
        object_id=str(row.id),
        request_id=request_id_or_new(request_id),
        payload={
            "email_bound": normalized is not None,
            "email_hash": email_fingerprint(normalized) if normalized else None,
            "plan_id": str(plan_id) if plan_id else None,
            "wireguard_profile_limit": wg_limit,
            "max_uses": 1,
            "created_by_kind": issuer_kind,
            "commercial_onboarding": offer is not None,
            "commercial_referral": issuer_kind == "user" and offer is not None,
            "recipient_referrals_enabled": bool(recipient_referrals_enabled),
            "recipient_referral_limit": recipient_referral_limit,
        },
    )
    return InviteIssueResult(invite=row, token=tok.raw)



def bulk_invite_campaign_state(campaign: BulkInviteCampaign, *, now: datetime | None = None) -> str:
    point = now or utcnow()
    if campaign.revoked_at is not None:
        return "revoked"
    if campaign.expires_at <= point:
        return "expired"
    if int(campaign.used_count) >= int(campaign.max_registrations):
        return "full"
    return "active"


def issue_bulk_invite_campaign(
    db: Session,
    *,
    label: str,
    plan_id: uuid.UUID,
    max_registrations: int,
    trial_days: int,
    expires_at: datetime,
    recipient_referrals_enabled: bool = True,
    recipient_referral_limit: int = 3,
    request_id: str | None = None,
) -> BulkInviteCampaignIssueResult:
    clean_label = str(label or "").strip()
    if not clean_label or len(clean_label) > 160:
        raise BulkInviteRejected("bulk invite label is invalid")
    if int(max_registrations) < 1:
        raise BulkInviteRejected("bulk invite capacity is invalid")
    if int(trial_days) < 1:
        raise BulkInviteRejected("bulk invite trial is invalid")
    recipient_referral_limit = int(recipient_referral_limit)
    if recipient_referral_limit < 0:
        raise BulkInviteRejected("bulk invite recipient referral limit is invalid")
    now = utcnow()
    if expires_at.tzinfo is None or expires_at <= now:
        raise BulkInviteRejected("bulk invite expiry is invalid")
    plan = db.get(Plan, plan_id)
    if plan is None or not plan.active:
        raise BulkInviteRejected("bulk invite plan is unavailable")
    offer = active_offer_for_plan(db, plan_id=plan.id)
    if offer is None:
        raise BulkInviteRejected("bulk invite requires a commercial plan")
    if int(offer.base_slot_quantity) != 1:
        raise BulkInviteRejected("bulk invite requires one base configuration")
    if int(plan.default_wireguard_limit) != int(offer.base_slot_quantity) or int(plan.default_amneziawg_limit) != int(offer.base_slot_quantity):
        raise BulkInviteRejected("commercial plan configuration limit drift")
    tok = secret_token()
    row = BulkInviteCampaign(
        id=uuid.uuid4(),
        token_hash=tok.digest,
        label=clean_label,
        plan_id=plan.id,
        max_registrations=int(max_registrations),
        used_count=0,
        trial_days=int(trial_days),
        recipient_referrals_enabled=bool(recipient_referrals_enabled),
        recipient_referral_limit=recipient_referral_limit,
        expires_at=expires_at,
        revoked_at=None,
        created_at=now,
    )
    db.add(row)
    db.flush()
    record_audit_event(
        db,
        event_type="auth.bulk_invite.issued",
        actor_kind="admin",
        object_type="bulk_invite_campaign",
        object_id=str(row.id),
        request_id=request_id_or_new(request_id),
        payload={
            "label": clean_label,
            "plan_id": str(plan.id),
            "max_registrations": int(max_registrations),
            "trial_days": int(trial_days),
            "recipient_referrals_enabled": bool(recipient_referrals_enabled),
            "recipient_referral_limit": recipient_referral_limit,
            "expires_at": expires_at.isoformat(),
        },
    )
    return BulkInviteCampaignIssueResult(campaign=row, token=tok.raw)


def inspect_bulk_invite_campaign(db: Session, *, token: str) -> BulkInviteCampaign:
    digest = _sha256_text(str(token or ""))
    row = db.execute(
        select(BulkInviteCampaign).where(BulkInviteCampaign.token_hash == digest)
    ).scalar_one_or_none()
    if row is None:
        raise BulkInviteRejected("invalid bulk invite")
    return row


def revoke_bulk_invite_campaign(
    db: Session,
    *,
    campaign_id: uuid.UUID,
    request_id: str | None = None,
) -> BulkInviteCampaign:
    row = db.execute(
        select(BulkInviteCampaign).where(BulkInviteCampaign.id == campaign_id).with_for_update()
    ).scalar_one_or_none()
    if row is None:
        raise BulkInviteRejected("bulk invite not found")
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        record_audit_event(
            db,
            event_type="auth.bulk_invite.revoked",
            actor_kind="admin",
            object_type="bulk_invite_campaign",
            object_id=str(row.id),
            request_id=request_id_or_new(request_id),
            payload={"used_count": int(row.used_count), "max_registrations": int(row.max_registrations)},
        )
    return row


def _bulk_campaign_for_child(db: Session, *, invite: Invite, now: datetime) -> BulkInviteCampaign | None:
    if invite.bulk_campaign_id is None:
        return None
    campaign = db.get(BulkInviteCampaign, invite.bulk_campaign_id)
    if campaign is None or campaign.plan_id != invite.plan_id:
        raise InviteRejected("invalid invite")
    if bulk_invite_campaign_state(campaign, now=now) != "active":
        raise InviteRejected("invalid invite")
    return campaign


def _invite_by_token(
    db: Session,
    *,
    token: str,
    lock: bool,
) -> Invite:
    digest = _sha256_text(str(token or ""))
    query = select(Invite).where(Invite.token_hash == digest)
    if lock:
        query = query.with_for_update()
    invite = db.execute(query).scalar_one_or_none()
    if invite is None:
        raise InviteRejected("invalid invite")
    return invite


def _assert_invite_active(db: Session, *, invite: Invite, now: datetime) -> Plan:
    if invite.revoked_at is not None:
        raise InviteRejected("invalid invite")
    if invite.expires_at is not None and invite.expires_at <= now:
        raise InviteRejected("invalid invite")
    if invite.used_count >= invite.max_uses:
        raise InviteRejected("invalid invite")
    if invite.plan_id is None:
        raise InviteRejected("invalid invite")
    _bulk_campaign_for_child(db, invite=invite, now=now)
    plan = db.get(Plan, invite.plan_id)
    if plan is None or not plan.active:
        raise InviteRejected("invalid invite")
    offer = active_offer_for_plan(db, plan_id=plan.id)
    if offer is not None:
        if not commercial_invite_is_effective(db, invite=invite, now=now):
            raise InviteRejected("invalid invite")
    elif invite.created_by_kind == "user":
        # User-generated invites are commercial referrals only. Do not let a
        # malformed/stale user invite escape into the pilot/admin plan path.
        raise InviteRejected("invalid invite")
    return plan


def inspect_invite(db: Session, *, token: str) -> Invite:
    return _invite_by_token(db, token=token, lock=False)


def _latest_registration_token(
    db: Session,
    *,
    invite_id: uuid.UUID,
    lock: bool = False,
) -> MagicLinkToken | None:
    query = (
        select(MagicLinkToken)
        .where(
            MagicLinkToken.invite_id == invite_id,
            MagicLinkToken.purpose == "registration",
        )
        .order_by(MagicLinkToken.created_at.desc(), MagicLinkToken.id.desc())
        .limit(1)
    )
    if lock:
        query = query.with_for_update()
    return db.execute(query).scalars().first()


def latest_registration_token(db: Session, *, invite_id: uuid.UUID) -> MagicLinkToken | None:
    return _latest_registration_token(db, invite_id=invite_id, lock=False)


def inspect_expired_registration_magic_link(
    db: Session,
    *,
    token: str,
    cooldown_seconds: int,
    lock: bool = False,
) -> ExpiredRegistrationMagicLink:
    if cooldown_seconds < 0:
        raise AuthV2Error("invalid registration resend settings")
    now = utcnow()
    digest = _sha256_text(str(token or ""))
    query = select(MagicLinkToken).where(MagicLinkToken.token_hash == digest)
    if lock:
        query = query.with_for_update()
    row = db.execute(query).scalar_one_or_none()
    if (
        row is None
        or row.purpose != "registration"
        or row.user_id is not None
        or row.invite_id is None
        or row.consumed_at is not None
        or row.expires_at > now
    ):
        raise MagicLinkRejected("expired registration magic link unavailable")

    invite_query = select(Invite).where(Invite.id == row.invite_id)
    if lock:
        invite_query = invite_query.with_for_update()
    invite = db.execute(invite_query).scalar_one_or_none()
    if invite is None:
        raise MagicLinkRejected("expired registration magic link unavailable")
    try:
        _assert_invite_active(db, invite=invite, now=now)
    except InviteRejected as exc:
        raise MagicLinkRejected("expired registration magic link unavailable") from exc

    if not invite.pending_email:
        raise MagicLinkRejected("expired registration magic link unavailable")
    normalized = normalize_email(invite.pending_email)
    if normalize_email(row.email) != normalized:
        raise MagicLinkRejected("expired registration magic link unavailable")
    if invite.intended_email and normalize_email(invite.intended_email) != normalized:
        raise MagicLinkRejected("expired registration magic link unavailable")

    latest = _latest_registration_token(db, invite_id=invite.id, lock=lock)
    if latest is None or latest.id != row.id:
        # An old superseded email must never be able to churn or reveal the
        # recipient of a newer registration attempt.
        raise MagicLinkRejected("expired registration magic link unavailable")

    resend_available_at = None
    if cooldown_seconds:
        resend_available_at = latest.created_at + timedelta(seconds=cooldown_seconds)
    ttl_seconds = max(60, int((row.expires_at - row.created_at).total_seconds()))
    return ExpiredRegistrationMagicLink(
        row=row,
        invite=invite,
        email=normalized,
        resend_available_at=resend_available_at,
        can_resend=(resend_available_at is None or resend_available_at <= now),
        ttl_seconds=ttl_seconds,
    )


def resend_expired_registration_magic_link(
    db: Session,
    *,
    token: str,
    ttl_seconds: int,
    cooldown_seconds: int,
    request_id: str | None = None,
) -> MagicLinkIssueResult:
    if ttl_seconds < 60 or cooldown_seconds < 0:
        raise AuthV2Error("invalid registration resend settings")
    context = inspect_expired_registration_magic_link(
        db,
        token=token,
        cooldown_seconds=cooldown_seconds,
        lock=True,
    )
    now = utcnow()
    if not context.can_resend and context.resend_available_at is not None:
        remaining = int((context.resend_available_at - now).total_seconds())
        if context.resend_available_at > now + timedelta(seconds=remaining):
            remaining += 1
        raise InviteResendTooSoon(remaining)

    req = request_id_or_new(request_id)
    existing_login = _existing_user_login_for_invite(
        db,
        invite=context.invite,
        normalized_email=context.email,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )
    if existing_login is not None:
        return existing_login

    return _issue_registration_token(
        db,
        invite=context.invite,
        normalized_email=context.email,
        now=now,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )


def _live_registration_token(
    db: Session,
    *,
    invite_id: uuid.UUID,
    now: datetime,
    lock: bool = False,
) -> MagicLinkToken | None:
    query = (
        select(MagicLinkToken)
        .where(
            MagicLinkToken.invite_id == invite_id,
            MagicLinkToken.purpose == "registration",
            MagicLinkToken.consumed_at.is_(None),
            MagicLinkToken.expires_at > now,
        )
        .order_by(MagicLinkToken.created_at.desc(), MagicLinkToken.id.desc())
        .limit(1)
    )
    if lock:
        query = query.with_for_update()
    return db.execute(query).scalars().first()


def invalidate_registration_tokens(
    db: Session,
    *,
    invite: Invite,
    now: datetime,
    request_id: str,
    reason: str,
    keep_token_id: uuid.UUID | None = None,
) -> int:
    filters = [
        MagicLinkToken.invite_id == invite.id,
        MagicLinkToken.purpose == "registration",
        MagicLinkToken.consumed_at.is_(None),
    ]
    if keep_token_id is not None:
        filters.append(MagicLinkToken.id != keep_token_id)
    rows = db.execute(
        select(MagicLinkToken)
        .where(*filters)
        .with_for_update()
    ).scalars().all()
    for row in rows:
        row.consumed_at = now
        record_audit_event(
            db,
            event_type="auth.registration_magic_link.superseded",
            actor_kind="system",
            object_type="magic_link_token",
            object_id=str(row.id),
            request_id=request_id,
            payload={"invite_id": str(invite.id), "reason": reason},
        )
    return len(rows)


def _issue_registration_token(
    db: Session,
    *,
    invite: Invite,
    normalized_email: str,
    now: datetime,
    ttl_seconds: int,
    request_id: str,
) -> MagicLinkIssueResult:
    tok = secret_token()
    row = MagicLinkToken(
        id=uuid.uuid4(),
        token_hash=tok.digest,
        email=normalized_email,
        user_id=None,
        invite_id=invite.id,
        purpose="registration",
        expires_at=now + timedelta(seconds=ttl_seconds),
        consumed_at=None,
        created_at=now,
    )
    db.add(row)
    db.flush()
    record_audit_event(
        db,
        event_type="auth.registration_magic_link.issued",
        actor_kind="system",
        object_type="magic_link_token",
        object_id=str(row.id),
        request_id=request_id,
        payload={
            "email_hash": email_fingerprint(normalized_email),
            "invite_id": str(invite.id),
        },
    )
    return MagicLinkIssueResult(row=row, token=tok.raw)


def _existing_user_login_for_invite(
    db: Session,
    *,
    invite: Invite,
    normalized_email: str,
    ttl_seconds: int,
    request_id: str,
) -> MagicLinkIssueResult | None:
    existing_user = db.execute(
        select(User).where(User.email == normalized_email)
    ).scalar_one_or_none()
    if existing_user is None:
        return None
    record_audit_event(
        db,
        event_type="auth.invite.existing_user_login",
        actor_kind="anonymous",
        object_type="invite",
        object_id=str(invite.id),
        request_id=request_id,
        payload={"email_hash": email_fingerprint(normalized_email)},
    )
    return issue_magic_link_for_email(
        db,
        email=normalized_email,
        ttl_seconds=ttl_seconds,
        request_id=request_id,
    )


def _request_invite_registration_for_row(
    db: Session,
    *,
    invite: Invite,
    email: str,
    ttl_seconds: int,
    request_id: str | None = None,
) -> MagicLinkIssueResult:
    """Run the accepted one-recipient registration state machine for a locked Invite row."""
    if ttl_seconds < 60:
        raise AuthV2Error("magic-link ttl is too short")
    normalized = normalize_email(email)
    now = utcnow()
    _assert_invite_active(db, invite=invite, now=now)
    if invite.intended_email and normalize_email(invite.intended_email) != normalized:
        raise InviteRejected("invalid invite")
    req = request_id_or_new(request_id)

    existing_login = _existing_user_login_for_invite(
        db,
        invite=invite,
        normalized_email=normalized,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )
    if existing_login is not None:
        return existing_login

    live = _live_registration_token(db, invite_id=invite.id, now=now, lock=True)
    if invite.pending_email is not None:
        pending = normalize_email(invite.pending_email)
        if pending != normalized:
            raise InviteRejected("pending email differs; use explicit change-email")
        if live is not None:
            if normalize_email(live.email) != normalized:
                raise InviteRejected("pending registration token email mismatch")
            record_audit_event(
                db,
                event_type="auth.registration_magic_link.reused",
                actor_kind="anonymous",
                object_type="magic_link_token",
                object_id=str(live.id),
                request_id=req,
                payload={
                    "email_hash": email_fingerprint(normalized),
                    "invite_id": str(invite.id),
                    "reason": "idempotent_repeat_submit",
                },
            )
            return MagicLinkIssueResult(row=None, token=None)
    else:
        if live is not None:
            if normalize_email(live.email) != normalized:
                raise InviteRejected("pending email differs; use explicit change-email")
            invite.pending_email = normalized
            record_audit_event(
                db,
                event_type="auth.registration_magic_link.reused",
                actor_kind="anonymous",
                object_type="magic_link_token",
                object_id=str(live.id),
                request_id=req,
                payload={
                    "email_hash": email_fingerprint(normalized),
                    "invite_id": str(invite.id),
                    "reason": "legacy_live_token_adopted",
                },
            )
            return MagicLinkIssueResult(row=None, token=None)
        invite.pending_email = normalized

    invalidate_registration_tokens(
        db,
        invite=invite,
        now=now,
        request_id=req,
        reason="replace_nonlive_before_issue",
    )
    return _issue_registration_token(
        db,
        invite=invite,
        normalized_email=normalized,
        now=now,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )


def request_invite_registration(
    db: Session,
    *,
    token: str,
    email: str,
    ttl_seconds: int,
    request_id: str | None = None,
) -> MagicLinkIssueResult:
    if ttl_seconds < 60:
        raise AuthV2Error("magic-link ttl is too short")
    invite = _invite_by_token(db, token=token, lock=True)
    return _request_invite_registration_for_row(
        db,
        invite=invite,
        email=email,
        ttl_seconds=ttl_seconds,
        request_id=request_id,
    )


def request_bulk_invite_registration(
    db: Session,
    *,
    campaign_token: str,
    email: str,
    ttl_seconds: int,
    request_id: str | None = None,
) -> MagicLinkIssueResult:
    if ttl_seconds < 60:
        raise AuthV2Error("magic-link ttl is too short")
    normalized = normalize_email(email)
    now = utcnow()
    campaign = inspect_bulk_invite_campaign(db, token=campaign_token)
    if bulk_invite_campaign_state(campaign, now=now) != "active":
        raise BulkInviteRejected("bulk invite unavailable")
    req = request_id_or_new(request_id)

    existing_user = db.execute(select(User).where(User.email == normalized)).scalar_one_or_none()
    if existing_user is not None:
        record_audit_event(
            db,
            event_type="auth.bulk_invite.existing_user_login",
            actor_kind="anonymous",
            object_type="bulk_invite_campaign",
            object_id=str(campaign.id),
            request_id=req,
            payload={"email_hash": email_fingerprint(normalized)},
        )
        return issue_magic_link_for_email(
            db,
            email=normalized,
            ttl_seconds=ttl_seconds,
            request_id=req,
        )

    offer = active_offer_for_plan(db, plan_id=campaign.plan_id)
    plan = db.get(Plan, campaign.plan_id)
    if plan is None or not plan.active or offer is None:
        raise BulkInviteRejected("bulk invite unavailable")
    child_token = secret_token()
    child_id = uuid.uuid4()
    insert_stmt = (
        pg_insert(Invite)
        .values(
            id=child_id,
            token_hash=child_token.digest,
            created_by_user_id=None,
            created_by_kind="system",
            created_by_label=campaign.label,
            intended_email=normalized,
            pending_email=None,
            wireguard_profile_limit=int(offer.base_slot_quantity),
            plan_id=campaign.plan_id,
            bulk_campaign_id=campaign.id,
            recipient_referrals_enabled=bool(campaign.recipient_referrals_enabled),
            recipient_referral_limit=int(campaign.recipient_referral_limit),
            max_uses=1,
            used_count=0,
            expires_at=campaign.expires_at,
            revoked_at=None,
            created_at=now,
        )
        .on_conflict_do_nothing(index_elements=[Invite.bulk_campaign_id, Invite.intended_email])
        .returning(Invite.id)
    )
    inserted_id = db.execute(insert_stmt).scalar_one_or_none()
    invite = db.execute(
        select(Invite)
        .where(Invite.bulk_campaign_id == campaign.id, Invite.intended_email == normalized)
        .with_for_update()
    ).scalar_one_or_none()
    if invite is None:
        raise BulkInviteRejected("bulk invite child creation failed")
    if inserted_id is not None:
        record_audit_event(
            db,
            event_type="auth.bulk_invite.child_created",
            actor_kind="system",
            object_type="invite",
            object_id=str(invite.id),
            request_id=req,
            payload={
                "bulk_campaign_id": str(campaign.id),
                "email_hash": email_fingerprint(normalized),
                "plan_id": str(campaign.plan_id),
                "recipient_referrals_enabled": bool(campaign.recipient_referrals_enabled),
                "recipient_referral_limit": int(campaign.recipient_referral_limit),
            },
        )
    return _request_invite_registration_for_row(
        db,
        invite=invite,
        email=normalized,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )


def resend_invite_registration(
    db: Session,
    *,
    token: str,
    ttl_seconds: int,
    cooldown_seconds: int,
    request_id: str | None = None,
) -> MagicLinkIssueResult:
    if ttl_seconds < 60 or cooldown_seconds < 0:
        raise AuthV2Error("invalid registration resend settings")
    now = utcnow()
    invite = _invite_by_token(db, token=token, lock=True)
    _assert_invite_active(db, invite=invite, now=now)
    req = request_id_or_new(request_id)
    latest = _latest_registration_token(db, invite_id=invite.id, lock=True)
    if not invite.pending_email:
        if latest is None:
            raise InviteRejected("registration email is not pending")
        invite.pending_email = normalize_email(latest.email)
    normalized = normalize_email(invite.pending_email)

    if latest is not None and cooldown_seconds:
        available_at = latest.created_at + timedelta(seconds=cooldown_seconds)
        if available_at > now:
            remaining = int((available_at - now).total_seconds())
            if available_at > now + timedelta(seconds=remaining):
                remaining += 1
            raise InviteResendTooSoon(remaining)

    existing_login = _existing_user_login_for_invite(
        db,
        invite=invite,
        normalized_email=normalized,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )
    if existing_login is not None:
        return existing_login

    return _issue_registration_token(
        db,
        invite=invite,
        normalized_email=normalized,
        now=now,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )


def change_invite_registration_email(
    db: Session,
    *,
    token: str,
    email: str,
    ttl_seconds: int,
    request_id: str | None = None,
) -> MagicLinkIssueResult:
    if ttl_seconds < 60:
        raise AuthV2Error("magic-link ttl is too short")
    normalized = normalize_email(email)
    now = utcnow()
    invite = _invite_by_token(db, token=token, lock=True)
    _assert_invite_active(db, invite=invite, now=now)
    if invite.intended_email is not None:
        raise InviteRejected("email-bound invite cannot be changed by recipient")
    req = request_id_or_new(request_id)

    if invite.pending_email and normalize_email(invite.pending_email) == normalized:
        live = _live_registration_token(db, invite_id=invite.id, now=now, lock=True)
        if live is not None:
            return MagicLinkIssueResult(row=None, token=None)

    invalidate_registration_tokens(
        db,
        invite=invite,
        now=now,
        request_id=req,
        reason="explicit_email_change",
    )
    invite.pending_email = normalized

    existing_login = _existing_user_login_for_invite(
        db,
        invite=invite,
        normalized_email=normalized,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )
    if existing_login is not None:
        invite.pending_email = None
        return existing_login

    record_audit_event(
        db,
        event_type="auth.invite.pending_email_changed",
        actor_kind="anonymous",
        object_type="invite",
        object_id=str(invite.id),
        request_id=req,
        payload={"email_hash": email_fingerprint(normalized)},
    )
    return _issue_registration_token(
        db,
        invite=invite,
        normalized_email=normalized,
        now=now,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )


def admin_replace_invite_email(
    db: Session,
    *,
    invite_id: uuid.UUID,
    email: str | None,
    ttl_seconds: int,
    request_id: str | None = None,
) -> tuple[Invite, MagicLinkIssueResult]:
    if ttl_seconds < 60:
        raise AuthV2Error("magic-link ttl is too short")
    now = utcnow()
    invite = db.execute(
        select(Invite).where(Invite.id == invite_id).with_for_update()
    ).scalar_one_or_none()
    if invite is None:
        raise InviteRejected("invalid invite")
    if invite.created_by_kind == "user":
        raise InviteRejected("user referral invite is not admin-mutable")
    if invite.bulk_campaign_id is not None:
        raise InviteRejected("bulk child invite is not admin-mutable")
    _assert_invite_active(db, invite=invite, now=now)
    req = request_id_or_new(request_id)
    normalized = normalize_email(email) if email else None

    invalidate_registration_tokens(
        db,
        invite=invite,
        now=now,
        request_id=req,
        reason="admin_recipient_change",
    )
    invite.intended_email = normalized
    invite.pending_email = None

    if normalized is None:
        record_audit_event(
            db,
            event_type="auth.invite.recipient_cleared",
            actor_kind="admin",
            object_type="invite",
            object_id=str(invite.id),
            request_id=req,
            payload={},
        )
        return invite, MagicLinkIssueResult(row=None, token=None)

    existing_login = _existing_user_login_for_invite(
        db,
        invite=invite,
        normalized_email=normalized,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )
    if existing_login is not None:
        record_audit_event(
            db,
            event_type="auth.invite.recipient_changed",
            actor_kind="admin",
            object_type="invite",
            object_id=str(invite.id),
            request_id=req,
            payload={"email_hash": email_fingerprint(normalized), "existing_user": True},
        )
        return invite, existing_login

    invite.pending_email = normalized
    record_audit_event(
        db,
        event_type="auth.invite.recipient_changed",
        actor_kind="admin",
        object_type="invite",
        object_id=str(invite.id),
        request_id=req,
        payload={"email_hash": email_fingerprint(normalized), "existing_user": False},
    )
    return invite, _issue_registration_token(
        db,
        invite=invite,
        normalized_email=normalized,
        now=now,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )


def admin_reissue_transferable_invite_token(
    db: Session,
    *,
    invite_id: uuid.UUID,
    request_id: str | None = None,
) -> tuple[Invite, str]:
    now = utcnow()
    invite = db.execute(
        select(Invite).where(Invite.id == invite_id).with_for_update()
    ).scalar_one_or_none()
    if invite is None:
        raise InviteRejected("invalid invite")
    if invite.created_by_kind == "user":
        raise InviteRejected("user referral invite is not admin-mutable")
    if invite.bulk_campaign_id is not None:
        raise InviteRejected("bulk child invite is not admin-mutable")
    _assert_invite_active(db, invite=invite, now=now)
    live_registration = _live_registration_token(
        db,
        invite_id=invite.id,
        now=now,
        lock=True,
    )
    if (
        invite.intended_email is not None
        or invite.pending_email is not None
        or live_registration is not None
    ):
        raise InviteRejected("invite is not transferable")

    req = request_id_or_new(request_id)
    token = secret_token()
    invite.token_hash = token.digest
    record_audit_event(
        db,
        event_type="auth.invite.share_token.reissued",
        actor_kind="admin",
        object_type="invite",
        object_id=str(invite.id),
        request_id=req,
        payload={},
    )
    return invite, token.raw



def user_reissue_referral_invite_token(
    db: Session,
    *,
    user: User,
    invite_id: uuid.UUID,
    request_id: str | None = None,
) -> tuple[Invite, str]:
    now = utcnow()
    require_referral_eligible(db, user_id=user.id, now=now, lock_account=True)
    invite = db.execute(
        select(Invite).where(Invite.id == invite_id).with_for_update()
    ).scalar_one_or_none()
    if invite is None or invite.created_by_kind != "user" or invite.created_by_user_id != user.id:
        raise InviteRejected("invalid referral invite")
    _assert_invite_active(db, invite=invite, now=now)
    live_registration = _live_registration_token(db, invite_id=invite.id, now=now, lock=True)
    if invite.intended_email is not None or invite.pending_email is not None or live_registration is not None:
        raise InviteRejected("referral invite is not transferable")
    token = secret_token()
    invite.token_hash = token.digest
    record_audit_event(
        db,
        event_type="auth.referral.share_token.reissued",
        actor_kind="user",
        actor_user_id=user.id,
        object_type="invite",
        object_id=str(invite.id),
        request_id=request_id_or_new(request_id),
        payload={},
    )
    return invite, token.raw


def user_revoke_referral_invite(
    db: Session,
    *,
    user: User,
    invite_id: uuid.UUID,
    request_id: str | None = None,
) -> Invite:
    now = utcnow()
    invite = db.execute(
        select(Invite).where(Invite.id == invite_id).with_for_update()
    ).scalar_one_or_none()
    if invite is None or invite.created_by_kind != "user" or invite.created_by_user_id != user.id:
        raise InviteRejected("invalid referral invite")
    if invite.used_count >= invite.max_uses:
        raise InviteRejected("used referral invite cannot be revoked")
    if invite.expires_at is not None and invite.expires_at <= now:
        raise InviteRejected("expired referral invite cannot be revoked")
    if invite.revoked_at is None:
        req = request_id_or_new(request_id)
        invalidate_registration_tokens(
            db,
            invite=invite,
            now=now,
            request_id=req,
            reason="user_referral_revoke",
        )
        invite.revoked_at = now
        record_audit_event(
            db,
            event_type="auth.referral.revoked",
            actor_kind="user",
            actor_user_id=user.id,
            object_type="invite",
            object_id=str(invite.id),
            request_id=req,
            payload={"used_count": invite.used_count, "max_uses": invite.max_uses},
        )
    return invite


def admin_resend_invite_registration(
    db: Session,
    *,
    invite_id: uuid.UUID,
    ttl_seconds: int,
    cooldown_seconds: int,
    request_id: str | None = None,
) -> MagicLinkIssueResult:
    if ttl_seconds < 60 or cooldown_seconds < 0:
        raise AuthV2Error("invalid registration resend settings")
    now = utcnow()
    invite = db.execute(
        select(Invite).where(Invite.id == invite_id).with_for_update()
    ).scalar_one_or_none()
    if invite is None:
        raise InviteRejected("invalid invite")
    if invite.created_by_kind == "user":
        raise InviteRejected("user referral invite is not admin-mutable")
    if invite.bulk_campaign_id is not None:
        raise InviteRejected("bulk child invite is not admin-mutable")
    _assert_invite_active(db, invite=invite, now=now)
    req = request_id_or_new(request_id)
    latest = _latest_registration_token(db, invite_id=invite.id, lock=True)
    if not invite.pending_email:
        if latest is None:
            raise InviteRejected("registration email is not pending")
        invite.pending_email = normalize_email(latest.email)
    normalized = normalize_email(invite.pending_email)

    if latest is not None and cooldown_seconds:
        available_at = latest.created_at + timedelta(seconds=cooldown_seconds)
        if available_at > now:
            remaining = int((available_at - now).total_seconds())
            if available_at > now + timedelta(seconds=remaining):
                remaining += 1
            raise InviteResendTooSoon(remaining)

    existing_login = _existing_user_login_for_invite(
        db,
        invite=invite,
        normalized_email=normalized,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )
    if existing_login is not None:
        return existing_login

    return _issue_registration_token(
        db,
        invite=invite,
        normalized_email=normalized,
        now=now,
        ttl_seconds=ttl_seconds,
        request_id=req,
    )


def issue_magic_link_for_email(
    db: Session,
    *,
    email: str,
    ttl_seconds: int,
    request_id: str | None = None,
) -> MagicLinkIssueResult:
    if ttl_seconds < 60:
        raise AuthV2Error("magic-link ttl is too short")
    normalized = normalize_email(email)
    user = db.execute(select(User).where(User.email == normalized)).scalar_one_or_none()
    req = request_id_or_new(request_id)
    record_audit_event(
        db,
        event_type="auth.login.requested",
        actor_kind="anonymous",
        actor_user_id=None,
        object_type="identity",
        object_id=None,
        request_id=req,
        payload={"email_hash": email_fingerprint(normalized)},
    )
    if user is None or user.deletion_requested_at is not None:
        return MagicLinkIssueResult(row=None, token=None)

    now = utcnow()
    prior = db.execute(
        select(MagicLinkToken)
        .where(
            MagicLinkToken.email == normalized,
            MagicLinkToken.purpose == "login",
            MagicLinkToken.consumed_at.is_(None),
        )
        .with_for_update()
    ).scalars().all()
    for row in prior:
        row.consumed_at = now

    tok = secret_token()
    row = MagicLinkToken(
        id=uuid.uuid4(),
        token_hash=tok.digest,
        email=normalized,
        user_id=user.id,
        invite_id=None,
        purpose="login",
        expires_at=now + timedelta(seconds=ttl_seconds),
        consumed_at=None,
        created_at=now,
    )
    db.add(row)
    db.flush()
    record_audit_event(
        db,
        event_type="auth.magic_link.issued",
        actor_kind="system",
        actor_user_id=user.id,
        object_type="magic_link_token",
        object_id=str(row.id),
        request_id=req,
        payload={"email_hash": email_fingerprint(normalized)},
    )
    return MagicLinkIssueResult(row=row, token=tok.raw)


def _issue_session_for_user(
    db: Session,
    *,
    user: User,
    now: datetime,
    session_ttl_seconds: int,
) -> SessionIssueResult:
    tok = secret_token()
    session = AuthSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=tok.digest,
        created_at=now,
        expires_at=now + timedelta(seconds=session_ttl_seconds),
        last_seen_at=None,
        revoked_at=None,
    )
    db.add(session)
    db.flush()
    return SessionIssueResult(session=session, token=tok.raw)



def _claim_bulk_invite_capacity(
    db: Session,
    *,
    invite: Invite,
    now: datetime,
    request_id: str,
) -> bool:
    if invite.bulk_campaign_id is None:
        return False
    stmt = (
        update(BulkInviteCampaign)
        .where(
            BulkInviteCampaign.id == invite.bulk_campaign_id,
            BulkInviteCampaign.revoked_at.is_(None),
            BulkInviteCampaign.expires_at > now,
            BulkInviteCampaign.used_count < BulkInviteCampaign.max_registrations,
        )
        .values(used_count=BulkInviteCampaign.used_count + 1)
        .returning(BulkInviteCampaign.used_count)
    )
    new_used_count = db.execute(stmt).scalar_one_or_none()
    if new_used_count is None:
        raise MagicLinkRejected("invalid magic link")
    record_audit_event(
        db,
        event_type="auth.bulk_invite.capacity_claimed",
        actor_kind="system",
        object_type="bulk_invite_campaign",
        object_id=str(invite.bulk_campaign_id),
        request_id=request_id,
        payload={"invite_id": str(invite.id), "used_count": int(new_used_count)},
    )
    return True


def consume_magic_link(
    db: Session,
    *,
    token: str,
    session_ttl_seconds: int,
    wg_node_id: str,
    request_id: str | None = None,
) -> SessionIssueResult:
    if session_ttl_seconds < 60:
        raise AuthV2Error("session ttl is too short")
    digest = _sha256_text(str(token or ""))
    now = utcnow()
    row = db.execute(
        select(MagicLinkToken).where(MagicLinkToken.token_hash == digest).with_for_update()
    ).scalar_one_or_none()
    if row is None or row.consumed_at is not None or row.expires_at <= now:
        raise MagicLinkRejected("invalid magic link")

    req = request_id_or_new(request_id)
    agent_wakeup_needed = False

    if row.purpose == "login":
        if row.user_id is None or row.invite_id is not None:
            raise MagicLinkRejected("invalid magic link")
        user = db.get(User, row.user_id)
        if user is None or user.email_verified_at is None or user.deletion_requested_at is not None:
            raise MagicLinkRejected("invalid magic link")
        row.consumed_at = now
        result = _issue_session_for_user(
            db, user=user, now=now, session_ttl_seconds=session_ttl_seconds
        )
    elif row.purpose == "registration":
        if row.user_id is not None or row.invite_id is None:
            raise MagicLinkRejected("invalid magic link")
        invite = db.execute(
            select(Invite).where(Invite.id == row.invite_id).with_for_update()
        ).scalar_one_or_none()
        if invite is None:
            raise MagicLinkRejected("invalid magic link")
        try:
            _assert_invite_active(db, invite=invite, now=now)
        except InviteRejected as exc:
            raise MagicLinkRejected("invalid magic link") from exc
        normalized = normalize_email(row.email)
        if invite.intended_email and normalize_email(invite.intended_email) != normalized:
            raise MagicLinkRejected("invalid magic link")
        if invite.pending_email and normalize_email(invite.pending_email) != normalized:
            raise MagicLinkRejected("invalid magic link")
        if db.execute(select(User).where(User.email == normalized)).scalar_one_or_none() is not None:
            raise MagicLinkRejected("invalid magic link")

        bulk_capacity_claimed = _claim_bulk_invite_capacity(
            db,
            invite=invite,
            now=now,
            request_id=req,
        )
        user = ensure_verified_user(db, normalized, verified_at=now)
        # This registration path creates a new user only: existing users were
        # diverted to login before a registration token can be consumed.
        user.referrals_enabled = bool(invite.recipient_referrals_enabled)
        user.referral_limit = int(invite.recipient_referral_limit)
        redemption = InviteRedemption(
            id=uuid.uuid4(),
            invite_id=invite.id,
            user_id=user.id,
            redeemed_at=now,
        )
        db.add(redemption)
        invite.used_count += 1

        grant = None
        effective_wg_limit = None
        if invite.plan_id is not None:
            plan = db.get(Plan, invite.plan_id)
            if plan is None or not plan.active:
                raise MagicLinkRejected("invalid magic link")
            offer = active_offer_for_plan(db, plan_id=plan.id)
            if offer is not None:
                try:
                    trial = create_commercial_trial_registration(
                        db,
                        user=user,
                        invite=invite,
                        wg_node_id=wg_node_id,
                        now=now,
                        request_id=req,
                        bulk_capacity_claimed=bulk_capacity_claimed,
                    )
                except CommercialRegistrationRejected as exc:
                    raise MagicLinkRejected("invalid magic link") from exc
                grant = trial.grant
                effective_wg_limit = int(offer.base_slot_quantity)
                if any(trial.configuration.created_jobs.values()):
                    agent_wakeup_needed = True
            else:
                grant = create_grant_from_plan(
                    db,
                    user=user,
                    plan=plan,
                    source_type="invite",
                    source_ref=str(invite.id),
                    valid_from=now,
                    valid_until=None,
                )

                slot_limit = (
                    int(invite.wireguard_profile_limit)
                    if invite.wireguard_profile_limit is not None
                    else int(plan.default_wireguard_limit)
                )
                for protocol_name in ("wireguard", "amneziawg"):
                    protocol_limit(db, grant_id=grant.id, protocol=protocol_name).profile_limit = slot_limit
                db.flush()
                effective_wg_limit = slot_limit
                if slot_limit > 0:
                    profile_result = create_profile_request(
                        db,
                        user=user,
                        grant_id=grant.id,
                        protocol="wireguard",
                        node_id=wg_node_id,
                        label=None,
                        now=now,
                    )
                    if profile_result.created_job:
                        agent_wakeup_needed = True
                    record_audit_event(
                        db,
                        event_type="profile.requested",
                        actor_kind="system",
                        actor_user_id=user.id,
                        object_type="connection_profile",
                        object_id=str(profile_result.profile.id),
                        request_id=req,
                        payload={"protocol": "wireguard", "paired_protocol": "amneziawg", "reason": "initial_registration"},
                    )

        row.user_id = user.id
        row.consumed_at = now
        result = _issue_session_for_user(
            db, user=user, now=now, session_ttl_seconds=session_ttl_seconds
        )
        record_audit_event(
            db,
            event_type="auth.invite.redeemed",
            actor_kind="user",
            actor_user_id=user.id,
            object_type="invite",
            object_id=str(invite.id),
            request_id=req,
            payload={
                "email_hash": email_fingerprint(normalized),
                "bulk_campaign_id": str(invite.bulk_campaign_id) if invite.bulk_campaign_id else None,
                "recipient_referrals_enabled": bool(invite.recipient_referrals_enabled),
                "recipient_referral_limit": int(invite.recipient_referral_limit),
            },
        )
        record_audit_event(
            db,
            event_type="auth.registration.completed",
            actor_kind="user",
            actor_user_id=user.id,
            object_type="magic_link_token",
            object_id=str(row.id),
            request_id=req,
            payload={
                "grant_created": grant is not None,
                "wireguard_profile_limit": effective_wg_limit,
                "bulk_campaign_id": str(invite.bulk_campaign_id) if invite.bulk_campaign_id else None,
                "recipient_referrals_enabled": bool(user.referrals_enabled),
                "recipient_referral_limit": int(user.referral_limit),
            },
        )
    else:
        raise MagicLinkRejected("invalid magic link")

    record_audit_event(
        db,
        event_type="auth.magic_link.consumed",
        actor_kind="user",
        actor_user_id=result.session.user_id,
        object_type="magic_link_token",
        object_id=str(row.id),
        request_id=req,
        payload={"purpose": row.purpose},
    )
    record_audit_event(
        db,
        event_type="auth.session.created",
        actor_kind="user",
        actor_user_id=result.session.user_id,
        object_type="auth_session",
        object_id=str(result.session.id),
        request_id=req,
        payload={},
    )
    return SessionIssueResult(
        session=result.session,
        token=result.token,
        agent_wakeup_needed=agent_wakeup_needed,
    )

def authenticate_session(db: Session, *, token: str) -> tuple[AuthSession, User]:
    digest = _sha256_text(str(token or ""))
    now = utcnow()
    session = db.execute(
        select(AuthSession).where(AuthSession.token_hash == digest)
    ).scalar_one_or_none()
    if session is None or session.revoked_at is not None or session.expires_at <= now:
        raise SessionRejected("invalid session")
    user = db.get(User, session.user_id)
    if user is None or user.deletion_requested_at is not None:
        raise SessionRejected("invalid session")
    return session, user


def revoke_session(
    db: Session,
    *,
    session: AuthSession,
    user: User,
    request_id: str | None = None,
) -> None:
    if session.revoked_at is None:
        session.revoked_at = utcnow()
    record_audit_event(
        db,
        event_type="auth.session.revoked",
        actor_kind="user",
        actor_user_id=user.id,
        object_type="auth_session",
        object_id=str(session.id),
        request_id=request_id_or_new(request_id),
        payload={},
    )
    db.flush()


def enforce_rate_limit(
    db: Session,
    *,
    scope: str,
    subject: str,
    limit: int,
    window_seconds: int,
    request_id: str | None = None,
) -> None:
    limit = max(1, int(limit))
    window_seconds = max(1, int(window_seconds))
    rate_key = fingerprint(f"{scope}|{subject}")
    lock_raw = hashlib.sha256(f"wg-paid/auth-rate/{rate_key}".encode("utf-8")).digest()[:8]
    lock_key = int.from_bytes(lock_raw, "big", signed=False)
    if lock_key >= (1 << 63):
        lock_key -= 1 << 64
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})
    cutoff = utcnow() - timedelta(seconds=window_seconds)
    count = db.execute(
        select(func.count(AuditEvent.id)).where(
            AuditEvent.event_type == "auth.rate.hit",
            AuditEvent.occurred_at >= cutoff,
            AuditEvent.payload_json.contains({"rate_key": rate_key}),
        )
    ).scalar_one()
    record_audit_event(
        db,
        event_type="auth.rate.hit",
        actor_kind="anonymous",
        object_type="rate_limit",
        object_id=scope,
        request_id=request_id_or_new(request_id),
        payload={"rate_key": rate_key, "scope": scope},
    )
    if int(count) >= limit:
        raise RateLimitExceeded("rate limit exceeded")
