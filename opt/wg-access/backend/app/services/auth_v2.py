from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import uuid

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.models import (
    AccessGrant,
    AuditEvent,
    AuthSession,
    Invite,
    InviteRedemption,
    MagicLinkToken,
    Plan,
    User,
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


class MagicLinkRejected(AuthV2Error):
    pass


class SessionRejected(AuthV2Error):
    pass


class RateLimitExceeded(AuthV2Error):
    pass


@dataclass(frozen=True)
class SecretToken:
    raw: str
    digest: str


@dataclass(frozen=True)
class InviteIssueResult:
    invite: Invite
    token: str


@dataclass(frozen=True)
class MagicLinkIssueResult:
    row: MagicLinkToken | None
    token: str | None


@dataclass(frozen=True)
class SessionIssueResult:
    session: AuthSession
    token: str


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
    request_id: str | None = None,
) -> InviteIssueResult:
    normalized = normalize_email(intended_email) if intended_email else None
    if ttl_seconds < 60:
        raise AuthV2Error("invite ttl is too short")
    plan = db.get(Plan, plan_id)
    if plan is None or not plan.active:
        raise AuthV2Error("plan is unavailable")

    tok = secret_token()
    now = utcnow()
    row = Invite(
        id=uuid.uuid4(),
        token_hash=tok.digest,
        created_by_user_id=None,
        intended_email=normalized,
        plan_id=plan_id,
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
        actor_kind="admin",
        object_type="invite",
        object_id=str(row.id),
        request_id=request_id_or_new(request_id),
        payload={
            "email_bound": normalized is not None,
            "email_hash": email_fingerprint(normalized) if normalized else None,
            "plan_id": str(plan_id) if plan_id else None,
            "max_uses": 1,
        },
    )
    return InviteIssueResult(invite=row, token=tok.raw)


def _validated_invite_for_registration(
    db: Session,
    *,
    token: str,
    email: str,
) -> tuple[Invite, str, datetime]:
    normalized = normalize_email(email)
    digest = _sha256_text(str(token or ""))
    now = utcnow()
    invite = db.execute(
        select(Invite).where(Invite.token_hash == digest).with_for_update()
    ).scalar_one_or_none()
    if invite is None:
        raise InviteRejected("invalid invite")
    if invite.revoked_at is not None:
        raise InviteRejected("invalid invite")
    if invite.expires_at is not None and invite.expires_at <= now:
        raise InviteRejected("invalid invite")
    if invite.used_count >= invite.max_uses:
        raise InviteRejected("invalid invite")
    if invite.intended_email and normalize_email(invite.intended_email) != normalized:
        raise InviteRejected("invalid invite")
    if invite.plan_id is None:
        raise InviteRejected("invalid invite")
    plan = db.get(Plan, invite.plan_id)
    if plan is None or not plan.active:
        raise InviteRejected("invalid invite")
    return invite, normalized, now


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
    invite, normalized, now = _validated_invite_for_registration(
        db, token=token, email=email
    )
    req = request_id_or_new(request_id)

    # An already registered address follows the ordinary login path. The invite
    # remains unused so invite possession does not alter existing entitlement.
    existing_user = db.execute(
        select(User).where(User.email == normalized)
    ).scalar_one_or_none()
    if existing_user is not None:
        record_audit_event(
            db,
            event_type="auth.invite.existing_user_login",
            actor_kind="anonymous",
            object_type="invite",
            object_id=str(invite.id),
            request_id=req,
            payload={"email_hash": email_fingerprint(normalized)},
        )
        return issue_magic_link_for_email(
            db,
            email=normalized,
            ttl_seconds=ttl_seconds,
            request_id=req,
        )

    # Reissuing for the same invite+email invalidates only older tokens for the
    # same pending registration. Different recipients may hold pending tokens;
    # the first valid consume wins the one-use invite transactionally.
    prior = db.execute(
        select(MagicLinkToken)
        .where(
            MagicLinkToken.invite_id == invite.id,
            MagicLinkToken.email == normalized,
            MagicLinkToken.purpose == "registration",
            MagicLinkToken.consumed_at.is_(None),
        )
        .with_for_update()
    ).scalars().all()
    for old in prior:
        old.consumed_at = now

    tok = secret_token()
    row = MagicLinkToken(
        id=uuid.uuid4(),
        token_hash=tok.digest,
        email=normalized,
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
        request_id=req,
        payload={
            "email_hash": email_fingerprint(normalized),
            "invite_id": str(invite.id),
        },
    )
    return MagicLinkIssueResult(row=row, token=tok.raw)

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
        if invite is None or invite.revoked_at is not None:
            raise MagicLinkRejected("invalid magic link")
        if invite.expires_at is not None and invite.expires_at <= now:
            raise MagicLinkRejected("invalid magic link")
        if invite.used_count >= invite.max_uses:
            raise MagicLinkRejected("invalid magic link")
        normalized = normalize_email(row.email)
        if invite.intended_email and normalize_email(invite.intended_email) != normalized:
            raise MagicLinkRejected("invalid magic link")
        if db.execute(select(User).where(User.email == normalized)).scalar_one_or_none() is not None:
            raise MagicLinkRejected("invalid magic link")

        user = ensure_verified_user(db, normalized, verified_at=now)
        redemption = InviteRedemption(
            id=uuid.uuid4(),
            invite_id=invite.id,
            user_id=user.id,
            redeemed_at=now,
        )
        db.add(redemption)
        invite.used_count += 1

        grant = None
        if invite.plan_id is not None:
            plan = db.get(Plan, invite.plan_id)
            if plan is None or not plan.active:
                raise MagicLinkRejected("invalid magic link")
            grant = create_grant_from_plan(
                db,
                user=user,
                plan=plan,
                source_type="invite",
                source_ref=str(invite.id),
                valid_from=now,
                valid_until=None,
            )

            wg_limit = protocol_limit(db, grant_id=grant.id, protocol="wireguard")
            if wg_limit.profile_limit > 0:
                profile_result = create_profile_request(
                    db,
                    user=user,
                    grant_id=grant.id,
                    protocol="wireguard",
                    node_id=wg_node_id,
                    label=None,
                    now=now,
                )
                record_audit_event(
                    db,
                    event_type="profile.requested",
                    actor_kind="system",
                    actor_user_id=user.id,
                    object_type="connection_profile",
                    object_id=str(profile_result.profile.id),
                    request_id=req,
                    payload={"protocol": "wireguard", "reason": "initial_registration"},
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
            payload={"email_hash": email_fingerprint(normalized)},
        )
        record_audit_event(
            db,
            event_type="auth.registration.completed",
            actor_kind="user",
            actor_user_id=user.id,
            object_type="magic_link_token",
            object_id=str(row.id),
            request_id=req,
            payload={"grant_created": grant is not None},
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
    return result

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
