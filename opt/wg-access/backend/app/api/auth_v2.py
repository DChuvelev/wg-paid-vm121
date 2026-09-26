from __future__ import annotations

from datetime import datetime, timedelta
import logging
import base64
import hashlib
import hmac
import secrets
import time
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.config import settings
from app.services.admin_auth import AdminAuthorizationUnavailable, admin_token_matches, load_admin_token
from app.agent_trigger import trigger_wg_access_agent_best_effort
from app.services.mail_delivery import MailDeliveryError, deliver_magic_link_email
from app.db.session import get_db
from app.models import (
    AccessGrant,
    AccessGrantProtocolLimit,
    AuthSession,
    BillingAccount,
    BillingOffer,
    BillingPayment,
    BulkInviteCampaign,
    ConnectionProfile,
    ConnectionSlot,
    Invite,
    InviteRedemption,
    MagicLinkToken,
    Plan,
    User,
)
from app.services.auth_v2 import (
    AuthV2Error,
    BulkInviteRejected,
    InviteRejected,
    InviteResendTooSoon,
    MagicLinkIssueResult,
    MagicLinkRejected,
    RateLimitExceeded,
    SessionRejected,
    admin_replace_invite_email,
    admin_reissue_transferable_invite_token,
    admin_resend_invite_registration,
    authenticate_session,
    bulk_invite_campaign_state,
    change_invite_registration_email,
    consume_magic_link,
    email_fingerprint,
    enforce_rate_limit,
    issue_bulk_invite_campaign,
    issue_invite,
    inspect_bulk_invite_campaign,
    inspect_expired_registration_magic_link,
    inspect_invite,
    invalidate_registration_tokens,
    issue_magic_link_for_email,
    latest_registration_token,
    request_bulk_invite_registration,
    request_invite_registration,
    request_id_or_new,
    resend_expired_registration_magic_link,
    resend_invite_registration,
    revoke_bulk_invite_campaign,
    revoke_session,
    terminalize_terminal_bulk_campaign_children,
    user_reissue_referral_invite_token,
    user_revoke_referral_invite,
)
from app.services.billing import (
    BillingConflict,
    BillingError,
    BillingProviderMismatch,
    BillingUnavailable,
    bind_provider_create_response,
    monthly_amount_kopeks,
    prepare_manual_payment_intent,
    reconcile_payment,
)
from app.services.yookassa import (
    YooKassaError,
    YooKassaRejected,
    YooKassaUnavailable,
    create_payment as yookassa_create_payment,
)
from app.services.commercial import (
    ReferralNotEligible,
    TRUSTED_PILOT_PLAN_CODE,
    active_offer_for_plan,
    commercial_referral_invite_is_effective,
    referral_capability,
    require_referral_eligible,
)
from app.services.domain_v2 import (
    DomainV2Error,
    InvalidIdentity,
    PROFILE_QUOTA_STATUSES,
    grant_is_active,
    logical_slot_count,
    mirrored_configuration_limit,
    record_audit_event,
    request_configuration_disable,
    request_profile_disable,
    utcnow,
)

from app.services.user_deletion import UserDeletionError, request_admin_user_deletion
from app.services.runtime_snapshot import get_runtime_snapshot

from app.services.profile_delivery import (
    ProfileNotReady,
    ProfileSurfaceError,
    ProfileUnavailable,
    build_owned_profile_config,
    build_qr_svg,
    create_owned_configuration,
    create_owned_profile,
    list_owned_profiles,
    profile_slot_ordinal,
    update_owned_configuration_label,
    update_owned_profile_label,
)

router = APIRouter(prefix="/v2", tags=["domain-v2-auth"])

SESSION_COOKIE = "wg_access_session"
CSRF_COOKIE = "wg_access_csrf"
CSRF_HEADER = "x-csrf-token"
ADMIN_SESSION_COOKIE = "wg_admin_session"
ADMIN_CSRF_COOKIE = "wg_admin_csrf"
ADMIN_CSRF_HEADER = "x-admin-csrf-token"
ADMIN_SESSION_TTL_SECONDS = 8 * 60 * 60
GENERIC_LOGIN_RESPONSE = {"status": "accepted"}
PROFILE_CONFIG_DOWNLOAD_VERSION = "v1"
logger = logging.getLogger(__name__)


def _deliver_magic_link_result(db: Session, *, result: MagicLinkIssueResult, request_id: str) -> bool:
    if result.row is None or result.token is None:
        return False
    try:
        deliver_magic_link_email(
            to_email=result.row.email,
            token=result.token,
            issued_at=result.row.created_at,
        )
        record_audit_event(
            db,
            event_type="auth.magic_link.delivered",
            actor_kind="system",
            object_type="magic_link_token",
            object_id=str(result.row.id),
            request_id=request_id,
            payload={
                "email_hash": email_fingerprint(result.row.email),
                "purpose": result.row.purpose,
            },
        )
        return True
    except MailDeliveryError as exc:
        # Never log recipient, token, SMTP response text, or credentials.
        cause = exc.__cause__
        cause_type = type(cause).__name__ if cause is not None else type(exc).__name__
        smtp_code = getattr(cause, "smtp_code", None)
        os_errno = getattr(cause, "errno", None)
        if not isinstance(smtp_code, int):
            smtp_code = None
        if not isinstance(os_errno, int):
            os_errno = None
        logger.error(
            "magic-link delivery failed request_id=%s cause_type=%s smtp_code=%s errno=%s",
            request_id, cause_type, smtp_code, os_errno,
        )
        # The newly issued token is unusable after a failed delivery.
        # For resend flows, the prior live token is deliberately preserved.
        result.row.consumed_at = utcnow()
        record_audit_event(
            db,
            event_type="auth.magic_link.delivery_failed",
            actor_kind="system",
            object_type="magic_link_token",
            object_id=str(result.row.id),
            request_id=request_id,
            payload={
                "email_hash": email_fingerprint(result.row.email),
                "purpose": result.row.purpose,
                "cause_type": cause_type,
                "smtp_code": smtp_code,
                "errno": os_errno,
            },
        )
        return False


def _mask_email(value: str | None) -> str | None:
    text_value = str(value or "").strip()
    if not text_value or "@" not in text_value:
        return None
    local, domain = text_value.rsplit("@", 1)
    if not local or not domain:
        return None
    domain_head = domain.split(".", 1)[0]
    if not domain_head:
        return None
    suffix = domain.rsplit(".", 1)[1] if "." in domain and domain.rsplit(".", 1)[1] else ""
    masked_domain = f"{domain_head[:1]}***"
    if suffix:
        masked_domain = f"{masked_domain}.{suffix}"
    return f"{local[:1]}***@{masked_domain}"


def _invite_lifecycle_state(invite: Invite, *, now: datetime | None = None) -> str:
    point = now or utcnow()
    if invite.revoked_at is not None:
        return "revoked"
    if invite.expires_at is not None and invite.expires_at <= point:
        return "expired"
    if invite.used_count >= invite.max_uses:
        return "used"
    if invite.pending_email:
        return "awaiting_confirmation"
    return "active"


def _request_id(request: Request) -> str:
    return request_id_or_new(request.headers.get("x-request-id"))


def _client_key(request: Request) -> str:
    host = request.client.host if request.client else "unknown"
    return str(host or "unknown")


def _require_external_onboarding() -> None:
    if not settings.external_onboarding_active:
        raise HTTPException(status_code=404, detail="not found")


def _admin_session_signature(body: str) -> str:
    try:
        secret = load_admin_token().encode("utf-8")
    except AdminAuthorizationUnavailable as exc:
        raise HTTPException(status_code=503, detail="admin authorization is not configured") from exc
    digest = hmac.new(secret, body.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _issue_admin_session_token() -> str:
    expires_at = int(time.time()) + ADMIN_SESSION_TTL_SECONDS
    nonce = secrets.token_urlsafe(24)
    body = f"v1.{expires_at}.{nonce}"
    return f"{body}.{_admin_session_signature(body)}"


def _profile_config_download_signature(
    session: AuthSession,
    *,
    profile_id: UUID,
    body: str,
) -> str:
    digest = hmac.new(
        session.token_hash.encode("ascii"),
        f"{body}.{profile_id}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _issue_profile_config_download_token(session: AuthSession, *, profile_id: UUID) -> str:
    now = int(time.time())
    expires_at = min(
        now + max(1, int(settings.auth_profile_config_download_ttl_seconds)),
        int(session.expires_at.timestamp()),
    )
    if expires_at <= now:
        raise SessionRejected("session expired")
    body = f"{PROFILE_CONFIG_DOWNLOAD_VERSION}.{session.id.hex}.{expires_at}"
    signature = _profile_config_download_signature(
        session,
        profile_id=profile_id,
        body=body,
    )
    return f"{body}.{signature}"


def _profile_config_download_user(
    db: Session,
    *,
    profile_id: UUID,
    token: str,
) -> User:
    try:
        version, session_hex, expires_text, signature = token.split(".", 3)
        session_id = UUID(hex=session_hex)
        expires_at = int(expires_text)
    except (TypeError, ValueError):
        raise SessionRejected("invalid config download token")

    now_epoch = int(time.time())
    if version != PROFILE_CONFIG_DOWNLOAD_VERSION or expires_at <= now_epoch or not signature:
        raise SessionRejected("invalid config download token")

    session = db.get(AuthSession, session_id)
    now = utcnow()
    if session is None or session.revoked_at is not None or session.expires_at <= now:
        raise SessionRejected("invalid config download token")
    if expires_at > int(session.expires_at.timestamp()):
        raise SessionRejected("invalid config download token")

    body = f"{version}.{session.id.hex}.{expires_at}"
    expected = _profile_config_download_signature(
        session,
        profile_id=profile_id,
        body=body,
    )
    if not secrets.compare_digest(signature, expected):
        raise SessionRejected("invalid config download token")

    user = db.get(User, session.user_id)
    if user is None or user.deletion_requested_at is not None:
        raise SessionRejected("invalid config download token")
    return user


def _admin_session_is_valid(token: str | None) -> bool:
    if not token:
        return False
    try:
        version, expires_text, nonce, signature = token.split(".", 3)
        expires_at = int(expires_text)
    except (TypeError, ValueError):
        return False
    if version != "v1" or not nonce or expires_at <= int(time.time()):
        return False
    body = f"{version}.{expires_at}.{nonce}"
    expected = _admin_session_signature(body)
    return secrets.compare_digest(signature, expected)


def _require_admin(
    request: Request,
    x_admin_token: str | None = Header(default=None),
    wg_admin_session: str | None = Cookie(default=None),
    wg_admin_csrf: str | None = Cookie(default=None),
) -> None:
    if x_admin_token is not None:
        try:
            matched = admin_token_matches(x_admin_token)
        except AdminAuthorizationUnavailable as exc:
            raise HTTPException(status_code=503, detail="admin authorization is not configured") from exc
        if not matched:
            raise HTTPException(status_code=401, detail="unauthorized")
        return

    if not _admin_session_is_valid(wg_admin_session):
        raise HTTPException(status_code=401, detail="unauthorized")

    if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        header = request.headers.get(ADMIN_CSRF_HEADER)
        if not wg_admin_csrf or not header or not secrets.compare_digest(wg_admin_csrf, header):
            raise HTTPException(status_code=403, detail="admin csrf validation failed")


def _set_admin_session_cookies(response: Response, *, session_token: str, csrf_token: str) -> None:
    response.set_cookie(
        ADMIN_SESSION_COOKIE,
        session_token,
        max_age=ADMIN_SESSION_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        ADMIN_CSRF_COOKIE,
        csrf_token,
        max_age=ADMIN_SESSION_TTL_SECONDS,
        httponly=False,
        secure=True,
        samesite="strict",
        path="/",
    )


def _clear_admin_session_cookies(response: Response) -> None:
    response.delete_cookie(ADMIN_SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    response.delete_cookie(ADMIN_CSRF_COOKIE, path="/", secure=True, httponly=False, samesite="strict")


def _session_cookie_value(wg_access_session: str | None = Cookie(default=None)) -> str:
    if not wg_access_session:
        raise HTTPException(status_code=401, detail="unauthorized")
    return wg_access_session


def _current_session(
    token: str = Depends(_session_cookie_value),
    db: Session = Depends(get_db),
) -> tuple[AuthSession, User]:
    try:
        return authenticate_session(db, token=token)
    except SessionRejected as exc:
        raise HTTPException(status_code=401, detail="unauthorized") from exc


def _require_csrf(
    request: Request,
    wg_access_csrf: str | None = Cookie(default=None),
) -> None:
    header = request.headers.get(CSRF_HEADER)
    if not wg_access_csrf or not header or not secrets.compare_digest(wg_access_csrf, header):
        raise HTTPException(status_code=403, detail="csrf validation failed")


def _set_session_cookies(response: Response, *, session_token: str, csrf_token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        max_age=settings.auth_session_ttl_seconds,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=settings.auth_session_ttl_seconds,
        httponly=False,
        secure=True,
        samesite="lax",
        path="/",
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=True, httponly=False, samesite="lax")


class AdminSessionLoginRequest(BaseModel):
    token: str = Field(min_length=32, max_length=4096)


@router.post("/admin/session/login")
def admin_session_login(payload: AdminSessionLoginRequest, response: Response):
    try:
        matched = admin_token_matches(payload.token)
    except AdminAuthorizationUnavailable as exc:
        raise HTTPException(status_code=503, detail="admin authorization is not configured") from exc
    if not matched:
        raise HTTPException(status_code=401, detail="unauthorized")
    session_token = _issue_admin_session_token()
    csrf_token = secrets.token_urlsafe(24)
    _set_admin_session_cookies(response, session_token=session_token, csrf_token=csrf_token)
    return {"status": "authenticated", "expires_in": ADMIN_SESSION_TTL_SECONDS}


@router.get(
    "/admin/session",
    dependencies=[Depends(_require_admin)],
)
def admin_session_status():
    return {"authenticated": True}


@router.post(
    "/admin/session/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(_require_admin)],
)
def admin_session_logout(response: Response):
    _clear_admin_session_cookies(response)
    return None


class AdminInviteRequest(BaseModel):
    intended_email: EmailStr | None = None
    plan_id: UUID
    wireguard_profile_limit: int | None = Field(default=None, ge=0)
    recipient_referrals_enabled: bool = True
    recipient_referral_limit: int = Field(default=3, ge=0)
    trial_days: int | None = Field(default=None, ge=1, le=30)


class AdminInviteResponse(BaseModel):
    invite_id: UUID
    invite_token: str
    expires_at: datetime | None
    intended_email: str | None
    wireguard_profile_limit: int
    recipient_referrals_enabled: bool
    recipient_referral_limit: int
    trial_days: int | None
    email_sent: bool


@router.post(
    "/admin/invites",
    response_model=AdminInviteResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_require_admin)],
)
def admin_create_invite(
    payload: AdminInviteRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    req = _request_id(request)
    email_sent = False
    try:
        result = issue_invite(
            db,
            intended_email=str(payload.intended_email) if payload.intended_email else None,
            ttl_seconds=settings.auth_invite_ttl_seconds,
            plan_id=payload.plan_id,
            wireguard_profile_limit=payload.wireguard_profile_limit,
            recipient_referrals_enabled=payload.recipient_referrals_enabled,
            recipient_referral_limit=payload.recipient_referral_limit,
            trial_days_override=payload.trial_days,
            created_by_kind="admin",
            created_by_user_id=None,
            created_by_label="Admin",
            request_id=req,
        )
        if payload.intended_email:
            mail_result = request_invite_registration(
                db,
                token=result.token,
                email=str(payload.intended_email),
                ttl_seconds=settings.auth_magic_link_ttl_seconds,
                request_id=req,
            )
            email_sent = _deliver_magic_link_result(db, result=mail_result, request_id=req)
        db.commit()
        db.refresh(result.invite)
    except (AuthV2Error, InvalidIdentity) as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail="invite cannot be issued") from exc
    offer = active_offer_for_plan(db, plan_id=result.invite.plan_id) if result.invite.plan_id is not None else None
    return AdminInviteResponse(
        invite_id=result.invite.id,
        invite_token=result.token,
        expires_at=result.invite.expires_at,
        intended_email=result.invite.intended_email,
        wireguard_profile_limit=result.invite.wireguard_profile_limit,
        recipient_referrals_enabled=bool(result.invite.recipient_referrals_enabled),
        recipient_referral_limit=int(result.invite.recipient_referral_limit),
        trial_days=(
            int(result.invite.trial_days_override)
            if result.invite.trial_days_override is not None
            else int(offer.trial_days) if offer is not None else None
        ),
        email_sent=email_sent,
    )


class InviteRedeemRequest(BaseModel):
    invite_token: str
    email: EmailStr


@router.post("/auth/invites/redeem", status_code=status.HTTP_202_ACCEPTED)
def redeem_invite_route(
    payload: InviteRedeemRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    req = _request_id(request)
    try:
        enforce_rate_limit(
            db,
            scope="invite_redeem",
            subject=f"{_client_key(request)}|{payload.invite_token[:16]}",
            limit=settings.auth_redeem_rate_limit,
            window_seconds=settings.auth_rate_window_seconds,
            request_id=req,
        )
        db.commit()
    except RateLimitExceeded as exc:
        db.commit()
        raise HTTPException(status_code=429, detail="too many requests") from exc

    try:
        result = request_invite_registration(
            db,
            token=payload.invite_token,
            email=str(payload.email),
            ttl_seconds=settings.auth_magic_link_ttl_seconds,
            request_id=req,
        )
        _deliver_magic_link_result(db, result=result, request_id=req)
        db.commit()
    except (InviteRejected, InvalidIdentity) as exc:
        db.rollback()
        record_audit_event(
            db,
            event_type="auth.invite.redeem_rejected",
            actor_kind="anonymous",
            request_id=req,
            payload={"email_hash": email_fingerprint(str(payload.email))},
        )
        db.commit()
        raise HTTPException(status_code=400, detail="invalid invite") from exc
    return GENERIC_LOGIN_RESPONSE


class InviteInspectRequest(BaseModel):
    invite_token: str


class InviteInspectResponse(BaseModel):
    state: Literal["active", "awaiting_confirmation", "used", "revoked", "expired"]
    email_bound: bool
    pending_email_masked: str | None
    magic_link_sent_at: datetime | None
    magic_link_expires_at: datetime | None
    resend_available_at: datetime | None
    can_resend: bool
    can_change_email: bool


def _public_invite_inspect(db: Session, *, invite: Invite, now: datetime) -> InviteInspectResponse:
    state = _invite_lifecycle_state(invite, now=now)
    if state in {"active", "awaiting_confirmation"} and invite.created_by_kind == "user":
        if not commercial_referral_invite_is_effective(db, invite=invite, now=now):
            state = "revoked"
    latest = latest_registration_token(db, invite_id=invite.id)
    live = (
        latest
        if latest is not None and latest.consumed_at is None and latest.expires_at > now
        else None
    )
    effective_pending_email = invite.pending_email or (live.email if live is not None else None)
    if state == "active" and effective_pending_email is not None:
        state = "awaiting_confirmation"
    resend_available_at = None
    if effective_pending_email and latest is not None:
        resend_available_at = latest.created_at + timedelta(
            seconds=settings.auth_registration_resend_cooldown_seconds
        )
    can_resend = (
        state == "awaiting_confirmation"
        and effective_pending_email is not None
        and (resend_available_at is None or resend_available_at <= now)
    )
    return InviteInspectResponse(
        state=state,
        email_bound=invite.intended_email is not None,
        pending_email_masked=_mask_email(effective_pending_email),
        magic_link_sent_at=latest.created_at if latest is not None else None,
        magic_link_expires_at=live.expires_at if live is not None else None,
        resend_available_at=resend_available_at,
        can_resend=can_resend,
        can_change_email=(state == "awaiting_confirmation" and invite.intended_email is None),
    )


@router.post("/auth/invites/inspect", response_model=InviteInspectResponse)
def inspect_invite_route(
    payload: InviteInspectRequest,
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    try:
        invite = inspect_invite(db, token=payload.invite_token)
    except InviteRejected as exc:
        raise HTTPException(status_code=404, detail="invite not found") from exc
    return _public_invite_inspect(db, invite=invite, now=utcnow())


class BulkInviteInspectRequest(BaseModel):
    campaign_token: str


class BulkInviteInspectResponse(BaseModel):
    state: Literal["active", "full", "expired", "revoked"]


@router.post("/auth/bulk-invites/inspect", response_model=BulkInviteInspectResponse)
def inspect_bulk_invite_route(
    payload: BulkInviteInspectRequest,
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    try:
        campaign = inspect_bulk_invite_campaign(db, token=payload.campaign_token)
    except BulkInviteRejected as exc:
        raise HTTPException(status_code=404, detail="bulk invite not found") from exc
    return BulkInviteInspectResponse(state=bulk_invite_campaign_state(campaign, now=utcnow()))


class BulkInviteRedeemRequest(BaseModel):
    campaign_token: str
    email: EmailStr


@router.post("/auth/bulk-invites/redeem", status_code=status.HTTP_202_ACCEPTED)
def redeem_bulk_invite_route(
    payload: BulkInviteRedeemRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    req = _request_id(request)
    try:
        enforce_rate_limit(
            db,
            scope="bulk_invite_redeem",
            subject=f"{_client_key(request)}|{payload.campaign_token[:16]}",
            limit=settings.auth_redeem_rate_limit,
            window_seconds=settings.auth_rate_window_seconds,
            request_id=req,
        )
        db.commit()
    except RateLimitExceeded as exc:
        db.commit()
        raise HTTPException(status_code=429, detail="too many requests") from exc

    try:
        result = request_bulk_invite_registration(
            db,
            campaign_token=payload.campaign_token,
            email=str(payload.email),
            ttl_seconds=settings.auth_magic_link_ttl_seconds,
            request_id=req,
        )
        _deliver_magic_link_result(db, result=result, request_id=req)
        db.commit()
    except (BulkInviteRejected, InviteRejected, InvalidIdentity) as exc:
        db.rollback()
        record_audit_event(
            db,
            event_type="auth.bulk_invite.redeem_rejected",
            actor_kind="anonymous",
            request_id=req,
            payload={"email_hash": email_fingerprint(str(payload.email))},
        )
        db.commit()
        raise HTTPException(status_code=400, detail="bulk invite unavailable") from exc
    return GENERIC_LOGIN_RESPONSE


class InviteResendRequest(BaseModel):
    invite_token: str


@router.post("/auth/invites/resend", status_code=status.HTTP_202_ACCEPTED)
def resend_invite_route(
    payload: InviteResendRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    req = _request_id(request)
    try:
        enforce_rate_limit(
            db,
            scope="invite_resend",
            subject=f"{_client_key(request)}|{payload.invite_token[:16]}",
            limit=settings.auth_redeem_rate_limit,
            window_seconds=settings.auth_rate_window_seconds,
            request_id=req,
        )
        db.commit()
    except RateLimitExceeded as exc:
        db.commit()
        raise HTTPException(status_code=429, detail="too many requests") from exc

    try:
        result = resend_invite_registration(
            db,
            token=payload.invite_token,
            ttl_seconds=settings.auth_magic_link_ttl_seconds,
            cooldown_seconds=settings.auth_registration_resend_cooldown_seconds,
            request_id=req,
        )
        delivered = _deliver_magic_link_result(db, result=result, request_id=req)
        if delivered and result.row is not None:
            invite = db.get(Invite, result.row.invite_id) if result.row.invite_id is not None else None
            if invite is not None:
                invalidate_registration_tokens(
                    db,
                    invite=invite,
                    now=utcnow(),
                    request_id=req,
                    reason="explicit_resend",
                    keep_token_id=result.row.id if result.row.purpose == "registration" else None,
                )
        db.commit()
    except InviteResendTooSoon as exc:
        db.rollback()
        raise HTTPException(
            status_code=429,
            detail="resend cooldown",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except (InviteRejected, InvalidIdentity) as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail="invalid invite") from exc
    return GENERIC_LOGIN_RESPONSE


class InviteChangeEmailRequest(BaseModel):
    invite_token: str
    email: EmailStr


@router.post("/auth/invites/change-email", status_code=status.HTTP_202_ACCEPTED)
def change_invite_email_route(
    payload: InviteChangeEmailRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    req = _request_id(request)
    try:
        enforce_rate_limit(
            db,
            scope="invite_change_email",
            subject=f"{_client_key(request)}|{payload.invite_token[:16]}",
            limit=settings.auth_redeem_rate_limit,
            window_seconds=settings.auth_rate_window_seconds,
            request_id=req,
        )
        db.commit()
    except RateLimitExceeded as exc:
        db.commit()
        raise HTTPException(status_code=429, detail="too many requests") from exc

    try:
        result = change_invite_registration_email(
            db,
            token=payload.invite_token,
            email=str(payload.email),
            ttl_seconds=settings.auth_magic_link_ttl_seconds,
            request_id=req,
        )
        _deliver_magic_link_result(db, result=result, request_id=req)
        db.commit()
    except (InviteRejected, InvalidIdentity) as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail="invalid invite") from exc
    return GENERIC_LOGIN_RESPONSE


class LoginRequest(BaseModel):
    email: str


@router.post("/auth/login/request", status_code=status.HTTP_202_ACCEPTED)
def login_request(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    req = _request_id(request)
    subject = f"{_client_key(request)}|{email_fingerprint(payload.email)}"
    try:
        enforce_rate_limit(
            db,
            scope="login_request",
            subject=subject,
            limit=settings.auth_login_rate_limit,
            window_seconds=settings.auth_rate_window_seconds,
            request_id=req,
        )
        db.commit()
    except RateLimitExceeded as exc:
        db.commit()
        raise HTTPException(status_code=429, detail="too many requests") from exc

    try:
        result = issue_magic_link_for_email(
            db,
            email=payload.email,
            ttl_seconds=settings.auth_magic_link_ttl_seconds,
            request_id=req,
        )
        _deliver_magic_link_result(db, result=result, request_id=req)
        db.commit()
    except InvalidIdentity:
        db.rollback()
        record_audit_event(
            db,
            event_type="auth.login.requested",
            actor_kind="anonymous",
            request_id=req,
            payload={"email_hash": email_fingerprint(payload.email)},
        )
        db.commit()
    return GENERIC_LOGIN_RESPONSE


class MagicLinkRecoveryRequest(BaseModel):
    token: str


class MagicLinkRecoveryResponse(BaseModel):
    state: Literal["expired_registration"]
    pending_email_masked: str
    resend_available_at: datetime | None
    can_resend: bool
    magic_link_ttl_seconds: int


@router.post("/auth/magic-link/recovery", response_model=MagicLinkRecoveryResponse)
def inspect_magic_link_recovery_route(
    payload: MagicLinkRecoveryRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    req = _request_id(request)
    try:
        enforce_rate_limit(
            db,
            scope="magic_recovery_inspect",
            subject=f"{_client_key(request)}|{payload.token[:16]}",
            limit=settings.auth_magic_consume_rate_limit,
            window_seconds=settings.auth_rate_window_seconds,
            request_id=req,
        )
        db.commit()
    except RateLimitExceeded as exc:
        db.commit()
        raise HTTPException(status_code=429, detail="too many requests") from exc

    try:
        recovery = inspect_expired_registration_magic_link(
            db,
            token=payload.token,
            cooldown_seconds=settings.auth_registration_resend_cooldown_seconds,
        )
    except (MagicLinkRejected, InviteRejected, InvalidIdentity) as exc:
        raise HTTPException(status_code=404, detail="recovery unavailable") from exc
    masked = _mask_email(recovery.email)
    if masked is None:
        raise HTTPException(status_code=404, detail="recovery unavailable")
    return MagicLinkRecoveryResponse(
        state="expired_registration",
        pending_email_masked=masked,
        resend_available_at=recovery.resend_available_at,
        can_resend=recovery.can_resend,
        magic_link_ttl_seconds=recovery.ttl_seconds,
    )


@router.post("/auth/magic-link/resend", status_code=status.HTTP_202_ACCEPTED)
def resend_expired_magic_link_route(
    payload: MagicLinkRecoveryRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    req = _request_id(request)
    try:
        enforce_rate_limit(
            db,
            scope="magic_recovery_resend",
            subject=f"{_client_key(request)}|{payload.token[:16]}",
            limit=settings.auth_redeem_rate_limit,
            window_seconds=settings.auth_rate_window_seconds,
            request_id=req,
        )
        db.commit()
    except RateLimitExceeded as exc:
        db.commit()
        raise HTTPException(status_code=429, detail="too many requests") from exc

    try:
        result = resend_expired_registration_magic_link(
            db,
            token=payload.token,
            ttl_seconds=settings.auth_magic_link_ttl_seconds,
            cooldown_seconds=settings.auth_registration_resend_cooldown_seconds,
            request_id=req,
        )
        delivered = _deliver_magic_link_result(db, result=result, request_id=req)
        if delivered and result.row is not None and result.row.purpose == "registration" and result.row.invite_id is not None:
            invite = db.get(Invite, result.row.invite_id)
            if invite is not None:
                invalidate_registration_tokens(
                    db,
                    invite=invite,
                    now=utcnow(),
                    request_id=req,
                    reason="expired_magic_link_self_service_resend",
                    keep_token_id=result.row.id,
                )
        db.commit()
    except InviteResendTooSoon as exc:
        db.rollback()
        raise HTTPException(
            status_code=429,
            detail="resend cooldown",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except (MagicLinkRejected, InviteRejected, InvalidIdentity) as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail="recovery unavailable") from exc
    return GENERIC_LOGIN_RESPONSE


class MagicLinkConsumeRequest(BaseModel):
    token: str


@router.post("/auth/magic-link/consume")
def consume_magic_link_route(
    payload: MagicLinkConsumeRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    req = _request_id(request)
    try:
        enforce_rate_limit(
            db,
            scope="magic_consume",
            subject=f"{_client_key(request)}|{payload.token[:16]}",
            limit=settings.auth_magic_consume_rate_limit,
            window_seconds=settings.auth_rate_window_seconds,
            request_id=req,
        )
        db.commit()
    except RateLimitExceeded as exc:
        db.commit()
        raise HTTPException(status_code=429, detail="too many requests") from exc

    try:
        result = consume_magic_link(
            db,
            token=payload.token,
            session_ttl_seconds=settings.auth_session_ttl_seconds,
            wg_node_id=settings.wg_default_node_id,
            request_id=req,
        )
        db.commit()
        if result.bulk_campaign_cleanup_id is not None:
            try:
                cleanup = terminalize_terminal_bulk_campaign_children(
                    db,
                    campaign_id=result.bulk_campaign_cleanup_id,
                    request_id=req,
                    reason="campaign_full",
                )
                db.commit()
                logger.info(
                    "bulk campaign full child cleanup campaign=%s invites=%s tokens=%s",
                    cleanup.campaign_id,
                    cleanup.revoked_invites,
                    cleanup.invalidated_tokens,
                )
            except Exception:
                db.rollback()
                logger.exception(
                    "bulk campaign full child cleanup failed campaign=%s",
                    result.bulk_campaign_cleanup_id,
                )
        if result.agent_wakeup_needed:
            trigger_wg_access_agent_best_effort()
    except MagicLinkRejected as exc:
        db.rollback()
        record_audit_event(
            db,
            event_type="auth.magic_link.rejected",
            actor_kind="anonymous",
            request_id=req,
            payload={},
        )
        db.commit()
        raise HTTPException(status_code=400, detail="invalid magic link") from exc

    csrf_token = secrets.token_urlsafe(24)
    _set_session_cookies(response, session_token=result.token, csrf_token=csrf_token)
    return {"status": "authenticated"}


class GrantProtocolLimitSummary(BaseModel):
    protocol: str
    profile_limit: int
    profile_count: int
    can_create: bool


class GrantSummary(BaseModel):
    id: UUID
    status: str
    plan_id: UUID | None
    valid_until: datetime | None
    configuration_limit: int
    configuration_count: int
    can_create_configuration: bool
    protocol_limits: list[GrantProtocolLimitSummary]


class BillingAccountSummary(BaseModel):
    status: Literal["trial", "active_paid", "past_due", "expired"]
    current_period_start: datetime
    current_period_end: datetime
    slot_quantity: int
    monthly_amount_kopeks: int
    currency: str


class ReferralCapabilitySummary(BaseModel):
    enabled: bool
    limit: int
    active_count: int
    remaining_count: int | None
    can_create: bool


class AccountMeResponse(BaseModel):
    user_id: UUID
    email: str
    display_name: str | None
    account_surface: Literal["pilot", "commercial"]
    grants: list[GrantSummary]
    billing: BillingAccountSummary | None
    referrals: ReferralCapabilitySummary


class AccountMetadataUpdateRequest(BaseModel):
    display_name: str | None = Field(max_length=160)


def _grant_summary(
    db: Session,
    *,
    grant: AccessGrant,
    limits: list[AccessGrantProtocolLimit],
    configuration_count: int,
) -> GrantSummary:
    configuration_limit = mirrored_configuration_limit(db, grant_id=grant.id)
    return GrantSummary(
        id=grant.id,
        status=grant.status,
        plan_id=grant.plan_id,
        valid_until=grant.valid_until,
        configuration_limit=configuration_limit,
        configuration_count=configuration_count,
        can_create_configuration=(
            grant_is_active(grant) and configuration_count < configuration_limit
        ),
        protocol_limits=[
            GrantProtocolLimitSummary(
                protocol=limit.protocol,
                profile_limit=limit.profile_limit,
                profile_count=configuration_count,
                can_create=(
                    limit.protocol in {"wireguard", "amneziawg"}
                    and grant_is_active(grant)
                    and configuration_count < limit.profile_limit
                ),
            )
            for limit in limits
        ],
    )


def _account_billing_summary(db: Session, *, user: User) -> BillingAccountSummary | None:
    account = db.execute(
        select(BillingAccount).where(BillingAccount.user_id == user.id)
    ).scalar_one_or_none()
    if account is None:
        return None
    offer = db.get(BillingOffer, account.offer_id)
    grant = db.get(AccessGrant, account.access_grant_id)
    if (
        offer is None
        or not offer.active
        or grant is None
        or grant.user_id != user.id
        or grant.plan_id != offer.plan_id
        or user.deletion_requested_at is not None
    ):
        raise HTTPException(status_code=409, detail="commercial billing state unavailable")
    return BillingAccountSummary(
        status=account.status,
        current_period_start=account.current_period_start,
        current_period_end=account.current_period_end,
        slot_quantity=int(account.slot_quantity),
        monthly_amount_kopeks=monthly_amount_kopeks(offer, int(account.slot_quantity)),
        currency=offer.currency,
    )


def _account_surface(db: Session, *, user: User, grants: list[AccessGrant]) -> Literal["pilot", "commercial"]:
    if db.execute(select(BillingAccount.id).where(BillingAccount.user_id == user.id)).scalar_one_or_none() is not None:
        return "commercial"
    plan_ids = {grant.plan_id for grant in grants if grant.plan_id is not None}
    if plan_ids:
        plan_codes = set(db.execute(select(Plan.code).where(Plan.id.in_(plan_ids))).scalars().all())
        if TRUSTED_PILOT_PLAN_CODE in plan_codes:
            return "pilot"
    raise HTTPException(status_code=409, detail="account surface is unavailable")


def _account_referral_summary(db: Session, *, user: User) -> ReferralCapabilitySummary:
    try:
        capability = referral_capability(db, user_id=user.id, now=utcnow())
    except ReferralNotEligible as exc:
        raise HTTPException(status_code=409, detail="referral capability is unavailable") from exc
    return ReferralCapabilitySummary(
        enabled=capability.enabled,
        limit=capability.limit,
        active_count=capability.active_count,
        remaining_count=capability.remaining_count,
        can_create=capability.can_create,
    )


def _account_me_response(db: Session, *, user: User) -> AccountMeResponse:
    grants = db.execute(
        select(AccessGrant).where(AccessGrant.user_id == user.id).order_by(AccessGrant.created_at.asc())
    ).scalars().all()

    limits_by_grant: dict[UUID, list[AccessGrantProtocolLimit]] = {}
    configuration_count_by_grant: dict[UUID, int] = {}
    grant_ids = [g.id for g in grants]
    if grant_ids:
        limit_rows = db.execute(
            select(AccessGrantProtocolLimit)
            .where(AccessGrantProtocolLimit.access_grant_id.in_(grant_ids))
            .order_by(
                AccessGrantProtocolLimit.access_grant_id.asc(),
                AccessGrantProtocolLimit.protocol.asc(),
            )
        ).scalars().all()
        for row in limit_rows:
            limits_by_grant.setdefault(row.access_grant_id, []).append(row)

        usage_rows = db.execute(
            select(ConnectionSlot.access_grant_id, func.count(ConnectionSlot.id))
            .where(
                ConnectionSlot.user_id == user.id,
                ConnectionSlot.access_grant_id.in_(grant_ids),
                ConnectionSlot.disabled_at.is_(None),
            )
            .group_by(ConnectionSlot.access_grant_id)
        ).all()
        configuration_count_by_grant = {
            grant_id: int(count)
            for grant_id, count in usage_rows
        }

    billing = _account_billing_summary(db, user=user)
    return AccountMeResponse(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        account_surface=_account_surface(db, user=user, grants=grants),
        grants=[
            _grant_summary(
                db,
                grant=g,
                limits=limits_by_grant.get(g.id, []),
                configuration_count=configuration_count_by_grant.get(g.id, 0),
            )
            for g in grants
        ],
        billing=billing,
        referrals=_account_referral_summary(db, user=user),
    )


@router.get("/account/me", response_model=AccountMeResponse)
def account_me(
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    _, user = current
    return _account_me_response(db, user=user)


@router.patch("/account/me", response_model=AccountMeResponse)
def account_me_update(
    payload: AccountMetadataUpdateRequest,
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    _, user = current
    normalized = str(payload.display_name).strip() if payload.display_name is not None else ""
    user.display_name = normalized or None
    record_audit_event(
        db,
        event_type="account.display_name.updated",
        actor_kind="user",
        actor_user_id=user.id,
        object_type="user",
        object_id=str(user.id),
        request_id=_request_id(request),
        payload={"display_name_set": user.display_name is not None},
    )
    db.commit()
    db.refresh(user)
    return _account_me_response(db, user=user)


class BillingPaymentSummary(BaseModel):
    payment_id: UUID
    status: Literal["created", "pending", "succeeded", "canceled"]
    provider_status: str | None
    kind: Literal["initial", "manual_renewal", "auto_renewal", "upgrade"]
    amount_kopeks: int
    currency: str
    target_period_start: datetime | None
    target_period_end: datetime | None
    created_at: datetime
    updated_at: datetime
    succeeded_at: datetime | None
    confirmation_url: str | None = None


def _billing_payment_summary(payment: BillingPayment, *, confirmation_url: str | None = None) -> BillingPaymentSummary:
    return BillingPaymentSummary(
        payment_id=payment.id,
        status=payment.status,
        provider_status=payment.provider_status,
        kind=payment.kind,
        amount_kopeks=int(payment.amount_kopeks),
        currency=payment.currency,
        target_period_start=payment.target_period_start,
        target_period_end=payment.target_period_end,
        created_at=payment.created_at,
        updated_at=payment.updated_at,
        succeeded_at=payment.succeeded_at,
        confirmation_url=confirmation_url,
    )


def _provider_confirmation_url(provider: dict) -> str | None:
    confirmation = provider.get("confirmation") or {}
    value = str(confirmation.get("confirmation_url") or "").strip()
    return value or None


@router.post(
    "/account/billing/payments",
    response_model=BillingPaymentSummary,
    status_code=status.HTTP_201_CREATED,
)
def account_billing_payment_create(
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    _, user = current
    try:
        intent = prepare_manual_payment_intent(
            db,
            user=user,
            idempotence_key=idempotency_key,
            now=utcnow(),
        )
        db.commit()
        db.refresh(intent.payment)
    except BillingError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="payment cannot be created") from exc

    payment = intent.payment
    if payment.status == "succeeded" or payment.status == "canceled":
        return _billing_payment_summary(payment)

    try:
        provider = yookassa_create_payment(
            idempotence_key=payment.idempotence_key,
            amount_kopeks=int(payment.amount_kopeks),
            currency=payment.currency,
            description="Secret Studio — доступ на один месяц",
            billing_payment_id=str(payment.id),
            billing_account_id=str(payment.billing_account_id),
            kind=payment.kind,
        )
        payment = bind_provider_create_response(
            db,
            payment_id=payment.id,
            provider=provider,
            now=utcnow(),
        )
        db.commit()
        db.refresh(payment)
        confirmation_url = _provider_confirmation_url(provider)

        if str(provider.get("status") or "") == "succeeded":
            result = reconcile_payment(db, payment_id=payment.id)
            db.commit()
            db.refresh(result.payment)
            if result.configuration is not None:
                trigger_wg_access_agent_best_effort()
            payment = result.payment
        return _billing_payment_summary(payment, confirmation_url=confirmation_url)
    except YooKassaRejected as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail="payment provider rejected the request") from exc
    except YooKassaUnavailable as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="payment provider unavailable; retry with the same Idempotency-Key",
        ) from exc
    except (BillingError, YooKassaError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="payment provider state mismatch") from exc


@router.get("/account/billing/payments", response_model=list[BillingPaymentSummary])
def account_billing_payments(
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    _, user = current
    account = db.execute(select(BillingAccount).where(BillingAccount.user_id == user.id)).scalar_one_or_none()
    if account is None:
        return []
    rows = list(
        db.execute(
            select(BillingPayment)
            .where(BillingPayment.billing_account_id == account.id)
            .order_by(BillingPayment.created_at.desc(), BillingPayment.id.desc())
        ).scalars().all()
    )
    return [_billing_payment_summary(row) for row in rows]


@router.get("/account/billing/payments/{payment_id}", response_model=BillingPaymentSummary)
def account_billing_payment(
    payment_id: UUID,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    _, user = current
    account = db.execute(select(BillingAccount).where(BillingAccount.user_id == user.id)).scalar_one_or_none()
    if account is None:
        raise HTTPException(status_code=404, detail="payment not found")
    payment = db.execute(
        select(BillingPayment).where(
            BillingPayment.id == payment_id,
            BillingPayment.billing_account_id == account.id,
        )
    ).scalar_one_or_none()
    if payment is None:
        raise HTTPException(status_code=404, detail="payment not found")

    confirmation_url = None
    if payment.provider_payment_id and payment.status in {"created", "pending"}:
        try:
            result = reconcile_payment(db, payment_id=payment.id)
            db.commit()
            db.refresh(result.payment)
            if result.configuration is not None:
                trigger_wg_access_agent_best_effort()
            payment = result.payment
            confirmation_url = result.confirmation_url
        except YooKassaUnavailable as exc:
            db.rollback()
            raise HTTPException(status_code=503, detail="payment provider unavailable") from exc
        except (BillingError, YooKassaError) as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="payment provider state mismatch") from exc
    return _billing_payment_summary(payment, confirmation_url=confirmation_url)


@router.post("/billing/yookassa/webhook")
async def yookassa_webhook(request: Request, db: Session = Depends(get_db)):
    try:
        event = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid webhook body") from exc
    event_type = str(event.get("event") or "")
    if event_type not in {"payment.succeeded", "payment.canceled"}:
        return {"status": "ignored"}
    obj = event.get("object") or {}
    provider_id = str(obj.get("id") or "")
    metadata = obj.get("metadata") or {}
    payment = None
    if provider_id:
        payment = db.execute(
            select(BillingPayment).where(BillingPayment.provider_payment_id == provider_id)
        ).scalar_one_or_none()
    if payment is None:
        raw_local_id = str(metadata.get("billing_payment_id") or "")
        try:
            local_id = UUID(raw_local_id)
        except (ValueError, TypeError):
            return {"status": "ignored"}
        payment = db.get(BillingPayment, local_id)
    if payment is None:
        return {"status": "ignored"}
    try:
        result = reconcile_payment(
            db,
            payment_id=payment.id,
            provider_payment_id_hint=provider_id or None,
        )
        db.commit()
        if result.configuration is not None:
            trigger_wg_access_agent_best_effort()
    except YooKassaUnavailable as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="provider reconciliation unavailable") from exc
    except (BillingError, YooKassaError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="provider reconciliation mismatch") from exc
    return {"status": "ok"}


class ReferralInviteSummary(BaseModel):
    invite_id: UUID
    state: Literal["active", "awaiting_confirmation", "used", "revoked", "expired"]
    created_at: datetime
    expires_at: datetime | None
    used_count: int
    max_uses: int
    can_reissue_share_link: bool


class ReferralInviteCreateResponse(BaseModel):
    invite: ReferralInviteSummary
    invite_token: str


def _referral_invite_summary(db: Session, invite: Invite, *, now: datetime) -> ReferralInviteSummary:
    state = _invite_lifecycle_state(invite, now=now)
    effective = commercial_referral_invite_is_effective(db, invite=invite, now=now)
    if state in {"active", "awaiting_confirmation"} and not effective:
        state = "revoked"
    live_registration = latest_registration_token(db, invite_id=invite.id)
    can_reissue = (
        state == "active"
        and effective
        and invite.intended_email is None
        and invite.pending_email is None
        and (
            live_registration is None
            or live_registration.consumed_at is not None
            or live_registration.expires_at <= now
        )
    )
    return ReferralInviteSummary(
        invite_id=invite.id,
        state=state,
        created_at=invite.created_at,
        expires_at=invite.expires_at,
        used_count=invite.used_count,
        max_uses=invite.max_uses,
        can_reissue_share_link=can_reissue,
    )


@router.get("/account/referrals", response_model=list[ReferralInviteSummary])
def account_referrals(
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    _, user = current
    rows = db.execute(
        select(Invite)
        .where(Invite.created_by_kind == "user", Invite.created_by_user_id == user.id)
        .order_by(Invite.created_at.desc(), Invite.id.desc())
    ).scalars().all()
    point = utcnow()
    return [_referral_invite_summary(db, row, now=point) for row in rows]


@router.post(
    "/account/referrals",
    response_model=ReferralInviteCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def account_referral_create(
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    _, user = current
    req = _request_id(request)
    try:
        eligibility = require_referral_eligible(db, user_id=user.id, now=utcnow(), lock_account=True)
        result = issue_invite(
            db,
            intended_email=None,
            ttl_seconds=settings.auth_invite_ttl_seconds,
            plan_id=eligibility.offer.plan_id,
            wireguard_profile_limit=eligibility.offer.base_slot_quantity,
            created_by_kind="user",
            created_by_user_id=user.id,
            request_id=req,
        )
        db.commit()
        db.refresh(result.invite)
    except (AuthV2Error, ReferralNotEligible) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="referral invite cannot be issued") from exc
    return ReferralInviteCreateResponse(
        invite=_referral_invite_summary(db, result.invite, now=utcnow()),
        invite_token=result.token,
    )


@router.post(
    "/account/referrals/{invite_id}/share-token/reissue",
    response_model=ReferralInviteCreateResponse,
)
def account_referral_reissue(
    invite_id: UUID,
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    _, user = current
    try:
        invite, token = user_reissue_referral_invite_token(
            db,
            user=user,
            invite_id=invite_id,
            request_id=_request_id(request),
        )
        db.commit()
        db.refresh(invite)
    except (InviteRejected, ReferralNotEligible) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="referral share link cannot be reissued") from exc
    return ReferralInviteCreateResponse(
        invite=_referral_invite_summary(db, invite, now=utcnow()),
        invite_token=token,
    )


@router.post(
    "/account/referrals/{invite_id}/revoke",
    response_model=ReferralInviteSummary,
)
def account_referral_revoke(
    invite_id: UUID,
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    _, user = current
    try:
        invite = user_revoke_referral_invite(
            db,
            user=user,
            invite_id=invite_id,
            request_id=_request_id(request),
        )
        db.commit()
        db.refresh(invite)
    except InviteRejected as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="referral invite cannot be revoked") from exc
    return _referral_invite_summary(db, invite, now=utcnow())


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    session, user = current
    revoke_session(db, session=session, user=user, request_id=_request_id(request))
    db.commit()
    _clear_session_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return None


def _private_no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"


class ProfileSummary(BaseModel):
    id: UUID
    access_grant_id: UUID
    protocol: str
    status: str
    tunnel_ip: str | None
    label: str | None
    created_at: datetime
    updated_at: datetime


class ProfileMutationResponse(BaseModel):
    profile: ProfileSummary
    job_id: UUID
    job_created: bool


class ProfileCreateRequest(BaseModel):
    grant_id: UUID
    protocol: Literal["wireguard", "amneziawg"] = "wireguard"
    label: str | None = Field(default=None, max_length=160)


class ProfileLabelUpdateRequest(BaseModel):
    label: str | None = Field(max_length=160)


class ConfigurationVariantSummary(BaseModel):
    protocol: Literal["wireguard", "amneziawg"]
    profile_id: UUID
    status: str
    tunnel_ip: str | None
    ready: bool
    created_at: datetime
    updated_at: datetime


class ConfigurationSummary(BaseModel):
    configuration_id: UUID
    ordinal: int
    access_grant_id: UUID
    label: str | None
    created_at: datetime
    updated_at: datetime
    variants: list[ConfigurationVariantSummary]


class ConfigurationCreateRequest(BaseModel):
    grant_id: UUID
    label: str | None = Field(default=None, max_length=160)


class ConfigurationVariantMutation(BaseModel):
    protocol: Literal["wireguard", "amneziawg"]
    profile: ProfileSummary
    job_id: UUID
    job_created: bool


class AccountConfigurationCreateResponse(BaseModel):
    configuration_id: UUID
    access_grant_id: UUID
    label: str | None
    variants: list[ConfigurationVariantMutation]


class ProfileConfigDownloadResponse(BaseModel):
    download_url: str


def _profile_summary(profile) -> ProfileSummary:
    return ProfileSummary(
        id=profile.id,
        access_grant_id=profile.access_grant_id,
        protocol=profile.protocol,
        status=profile.status,
        tunnel_ip=profile.tunnel_ip,
        label=profile.label,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


def _configuration_summaries(
    db: Session,
    *,
    user: User,
    include_disabled: bool = False,
) -> list[ConfigurationSummary]:
    slots = db.execute(
        select(ConnectionSlot)
        .where(ConnectionSlot.user_id == user.id)
        .order_by(ConnectionSlot.created_at.asc(), ConnectionSlot.id.asc())
    ).scalars().all()
    slot_ids = [slot.id for slot in slots]
    profiles_by_slot: dict[UUID, dict[str, ConnectionProfile]] = {}
    if slot_ids:
        profiles = db.execute(
            select(ConnectionProfile)
            .where(ConnectionProfile.connection_slot_id.in_(slot_ids))
            .order_by(ConnectionProfile.created_at.asc(), ConnectionProfile.id.asc())
        ).scalars().all()
        for profile in profiles:
            profiles_by_slot.setdefault(profile.connection_slot_id, {})[profile.protocol] = profile

    result: list[ConfigurationSummary] = []
    for ordinal, slot in enumerate(slots, start=1):
        if slot.disabled_at is not None and not include_disabled:
            continue
        variants: list[ConfigurationVariantSummary] = []
        by_protocol = profiles_by_slot.get(slot.id, {})
        for protocol in ("wireguard", "amneziawg"):
            profile = by_protocol.get(protocol)
            if profile is None:
                continue
            variants.append(
                ConfigurationVariantSummary(
                    protocol=protocol,
                    profile_id=profile.id,
                    status=profile.status,
                    tunnel_ip=profile.tunnel_ip,
                    ready=(profile.status == "active" and bool(profile.tunnel_ip)),
                    created_at=profile.created_at,
                    updated_at=profile.updated_at,
                )
            )
        result.append(
            ConfigurationSummary(
                configuration_id=slot.id,
                ordinal=ordinal,
                access_grant_id=slot.access_grant_id,
                label=slot.label,
                created_at=slot.created_at,
                updated_at=slot.updated_at,
                variants=variants,
            )
        )
    return result


@router.get("/account/profiles", response_model=list[ProfileSummary])
def account_profiles(
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    _, user = current
    rows = list_owned_profiles(db, user=user)
    return [
        _profile_summary(row)
        for row in rows
        if row.protocol == "wireguard" and row.status in PROFILE_QUOTA_STATUSES
    ]


@router.get(
    "/account/profiles/configurations",
    response_model=list[ConfigurationSummary],
)
def account_configurations(
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    _, user = current
    return _configuration_summaries(db, user=user)


@router.post(
    "/account/profiles/configurations",
    response_model=AccountConfigurationCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def account_configuration_create(
    payload: ConfigurationCreateRequest,
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    _, user = current
    try:
        result = create_owned_configuration(
            db,
            user=user,
            grant_id=payload.grant_id,
            node_id=settings.wg_default_node_id,
            label=(str(payload.label).strip() or None) if payload.label is not None else None,
            request_id=_request_id(request),
        )
        db.commit()
        for profile in result.profiles.values():
            db.refresh(profile)
        db.refresh(result.slot)
        trigger_wg_access_agent_best_effort()
    except ProfileSurfaceError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail="configuration cannot be created") from exc
    return AccountConfigurationCreateResponse(
        configuration_id=result.slot.id,
        access_grant_id=result.slot.access_grant_id,
        label=result.slot.label,
        variants=[
            ConfigurationVariantMutation(
                protocol=protocol,
                profile=_profile_summary(result.profiles[protocol]),
                job_id=result.jobs[protocol].id,
                job_created=result.created_jobs[protocol],
            )
            for protocol in ("wireguard", "amneziawg")
        ],
    )


@router.patch(
    "/account/profiles/configurations/{configuration_id}",
    response_model=ConfigurationSummary,
)
def account_configuration_update_label(
    configuration_id: UUID,
    payload: ProfileLabelUpdateRequest,
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    _, user = current
    try:
        update_owned_configuration_label(
            db,
            user=user,
            configuration_id=configuration_id,
            label=payload.label,
            request_id=_request_id(request),
        )
        db.commit()
    except ProfileUnavailable as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="configuration unavailable") from exc
    summary = next(
        (
            row
            for row in _configuration_summaries(db, user=user, include_disabled=True)
            if row.configuration_id == configuration_id
        ),
        None,
    )
    if summary is None:
        raise HTTPException(status_code=404, detail="configuration unavailable")
    return summary


@router.post(
    "/account/profiles",
    response_model=ProfileMutationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def account_profile_create(
    payload: ProfileCreateRequest,
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    _, user = current
    req = _request_id(request)
    try:
        result = create_owned_profile(
            db,
            user=user,
            grant_id=payload.grant_id,
            protocol=payload.protocol,
            node_id=settings.wg_default_node_id,
            label=(str(payload.label).strip() or None) if payload.label is not None else None,
            request_id=req,
        )
        db.commit()
        db.refresh(result.profile)
        trigger_wg_access_agent_best_effort()
    except ProfileSurfaceError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail="profile cannot be created") from exc
    return ProfileMutationResponse(
        profile=_profile_summary(result.profile),
        job_id=result.job.id,
        job_created=result.created_job,
    )


@router.patch("/account/profiles/{profile_id}", response_model=ProfileSummary)
def account_profile_update_label(
    profile_id: UUID,
    payload: ProfileLabelUpdateRequest,
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    _, user = current
    try:
        profile = update_owned_profile_label(
            db,
            user=user,
            profile_id=profile_id,
            label=payload.label,
            request_id=_request_id(request),
        )
        db.commit()
        db.refresh(profile)
    except ProfileUnavailable as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="profile unavailable") from exc
    return _profile_summary(profile)


@router.post(
    "/account/profiles/{profile_id}/config-download",
    response_model=ProfileConfigDownloadResponse,
)
def account_profile_config_download_create(
    profile_id: UUID,
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    session, user = current
    owned = next(
        (profile for profile in list_owned_profiles(db, user=user) if profile.id == profile_id),
        None,
    )
    if owned is None:
        raise HTTPException(status_code=404, detail="profile not found")
    if owned.protocol not in {"wireguard", "amneziawg"} or owned.status != "active" or not owned.tunnel_ip:
        raise HTTPException(status_code=409, detail="profile is not ready")

    try:
        token = _issue_profile_config_download_token(session, profile_id=profile_id)
    except SessionRejected as exc:
        raise HTTPException(status_code=401, detail="unauthorized") from exc

    request_id = _request_id(request)
    record_audit_event(
        db,
        event_type="profile.config_download.issued",
        actor_kind="user",
        actor_user_id=user.id,
        object_type="connection_profile",
        object_id=str(profile_id),
        request_id=request_id,
        payload={"ttl_seconds": int(settings.auth_profile_config_download_ttl_seconds)},
    )
    db.commit()
    return ProfileConfigDownloadResponse(
        download_url=f"/v2/account/profiles/{profile_id}/config-download/{token}"
    )


@router.get("/account/profiles/{profile_id}/config-download/{download_token}")
def account_profile_config_download(
    profile_id: UUID,
    download_token: str,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    try:
        user = _profile_config_download_user(
            db,
            profile_id=profile_id,
            token=download_token,
        )
    except SessionRejected as exc:
        raise HTTPException(status_code=404, detail="download unavailable") from exc

    try:
        config_text = build_owned_profile_config(
            db,
            user=user,
            profile_id=profile_id,
            request_id=_request_id(request),
        )
        profile_ordinal = profile_slot_ordinal(db, user=user, profile_id=profile_id)
        if profile_ordinal == 0:
            raise ProfileUnavailable("profile unavailable")
        db.commit()
    except ProfileUnavailable as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="profile not found") from exc
    except ProfileNotReady as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="profile is not ready") from exc

    response = Response(
        content=config_text,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="SecretStudio-{profile_ordinal:02d}.conf"'},
    )
    _private_no_store(response)
    return response


@router.get("/account/profiles/{profile_id}/config")
def account_profile_config(
    profile_id: UUID,
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    _, user = current
    try:
        config_text = build_owned_profile_config(
            db,
            user=user,
            profile_id=profile_id,
            request_id=_request_id(request),
        )
        profile_ordinal = profile_slot_ordinal(db, user=user, profile_id=profile_id)
        if profile_ordinal == 0:
            raise ProfileUnavailable("profile unavailable")
        db.commit()
    except ProfileUnavailable as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="profile not found") from exc
    except ProfileNotReady as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="profile is not ready") from exc
    response = Response(
        content=config_text,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="SecretStudio-{profile_ordinal:02d}.conf"'},
    )
    _private_no_store(response)
    return response


@router.get("/account/profiles/{profile_id}/qr.svg")
def account_profile_qr(
    profile_id: UUID,
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    _, user = current
    try:
        config_text = build_owned_profile_config(
            db,
            user=user,
            profile_id=profile_id,
            request_id=_request_id(request),
            audit_event="profile.qr.delivered",
        )
        qr_svg = build_qr_svg(config_text)
        db.commit()
    except ProfileUnavailable as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="profile not found") from exc
    except ProfileNotReady as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="profile is not ready") from exc
    response = Response(content=qr_svg, media_type="image/svg+xml; charset=utf-8")
    _private_no_store(response)
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return response


# ---------------------------------------------------------------------------
# Private Domain V2 admin surface.
# These routes remain absent from the public VM103 proxy. The existing
# X-Admin-Token authorization root stays authoritative; browser-specific admin
# session UX belongs to the later private-admin ingress step.
# ---------------------------------------------------------------------------

class AdminPlanSummary(BaseModel):
    id: UUID
    code: str
    display_name: str
    active: bool
    default_wireguard_limit: int
    default_amneziawg_limit: int
    trial_days: int | None


class AdminInviteSummary(BaseModel):
    invite_id: UUID
    origin: Literal["user", "admin", "campaign"]
    bulk_campaign_id: UUID | None
    bulk_campaign_label: str | None
    intended_email: str | None
    pending_email: str | None
    plan_id: UUID | None
    wireguard_profile_limit: int
    recipient_referrals_enabled: bool
    recipient_referral_limit: int
    trial_days: int | None
    max_uses: int
    used_count: int
    expires_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime
    created_by_kind: str
    created_by_user_id: UUID | None
    created_by_label: str
    state: Literal["active", "awaiting_confirmation", "used", "revoked", "expired"]
    magic_link_sent_at: datetime | None
    magic_link_expires_at: datetime | None
    resend_available_at: datetime | None
    can_resend: bool
    can_change_email: bool
    can_reissue_share_link: bool
    can_revoke: bool


class AdminBulkInviteSummary(BaseModel):
    campaign_id: UUID
    label: str
    plan_id: UUID
    max_registrations: int
    used_count: int
    trial_days: int
    recipient_referrals_enabled: bool
    recipient_referral_limit: int
    expires_at: datetime
    revoked_at: datetime | None
    created_at: datetime
    state: Literal["active", "full", "expired", "revoked"]


class AdminBulkInviteCreateRequest(BaseModel):
    label: str = Field(min_length=1, max_length=160)
    plan_id: UUID
    max_registrations: int = Field(ge=1, le=10000)
    trial_days: int = Field(ge=1, le=30)
    recipient_referrals_enabled: bool = True
    recipient_referral_limit: int = Field(default=3, ge=0)
    expires_at: datetime


class AdminBulkInviteCreateResponse(BaseModel):
    campaign: AdminBulkInviteSummary
    campaign_token: str


class AdminUserSummary(BaseModel):
    user_id: UUID
    email: str
    display_name: str | None
    admin_note: str | None
    referrals_enabled: bool
    referral_limit: int
    email_verified_at: datetime
    created_at: datetime
    deletion_requested_at: datetime | None
    registration_invite_id: UUID | None
    invite_issued_at: datetime | None
    invite_redeemed_at: datetime | None
    invited_by_kind: str | None
    invited_by_origin: Literal["admin", "user", "campaign"] | None
    invited_by_user_id: UUID | None
    invited_by_label: str | None
    invited_by_campaign_id: UUID | None
    grants: list[GrantSummary]
    configurations: list[ConfigurationSummary]
    profiles: list[ProfileSummary]


class AdminRuntimeConnectionRow(BaseModel):
    user_id: UUID
    email: str
    display_name: str | None
    configuration_id: UUID
    configuration_ordinal: int
    configuration_label: str | None
    profile_id: UUID
    protocol: Literal["wireguard", "amneziawg"]
    profile_label: str | None
    tunnel_ip: str
    selector: str
    active_now: bool
    active_state: bool
    last_active_at: datetime | None
    last_reassign_at: datetime | None
    last_handshake_at: datetime | None
    rx_bytes: int
    tx_bytes: int
    rx_bytes_per_second: float
    tx_bytes_per_second: float


class AdminRuntimeConnectionsResponse(BaseModel):
    generated_at: datetime | None
    received_at: datetime | None
    snapshot_age_seconds: float | None
    stale: bool
    sample_interval_seconds: float | None
    unmatched_runtime_rows_count: int
    rows: list[AdminRuntimeConnectionRow]


class AdminUserMetadataUpdateRequest(BaseModel):
    admin_note: str | None = Field(max_length=4000)


class AdminUserMetadataUpdateResponse(BaseModel):
    user_id: UUID
    display_name: str | None
    admin_note: str | None


class AdminUserReferralPolicyUpdateRequest(BaseModel):
    enabled: bool
    limit: int = Field(ge=0)


class AdminUserReferralPolicyResponse(BaseModel):
    user_id: UUID
    enabled: bool
    limit: int


class AdminUserDeleteResponse(BaseModel):
    user_id: UUID
    email: str
    status: Literal["deleting", "deleted", "blocked_legacy_dependencies"]
    disable_jobs_created: int
    remaining_profiles: int
    legacy_dependency_count: int


class AdminProtocolLimitUpdateRequest(BaseModel):
    profile_limit: int = Field(ge=0)
    retire_profile_ids: list[UUID] = Field(default_factory=list)


class AdminProtocolLimitUpdateResponse(BaseModel):
    access_grant_id: UUID
    protocol: str
    profile_limit: int
    profile_count: int
    can_create: bool
    retire_profile_ids: list[UUID]
    disable_jobs_created: int
    retirement_in_progress: bool


class AdminConfigurationCreateRequest(BaseModel):
    label: str | None = Field(default=None, max_length=160)


class AdminConfigurationCreateResponse(BaseModel):
    configuration_id: UUID
    access_grant_id: UUID
    label: str | None
    variants: list[ConfigurationVariantMutation]


def _admin_invite_summary(db: Session, invite: Invite, *, now: datetime | None = None) -> AdminInviteSummary:
    point = now or utcnow()
    state = _invite_lifecycle_state(invite, now=point)
    campaign = db.get(BulkInviteCampaign, invite.bulk_campaign_id) if invite.bulk_campaign_id is not None else None
    origin: Literal["user", "admin", "campaign"]
    if invite.bulk_campaign_id is not None:
        origin = "campaign"
    elif invite.created_by_kind == "user":
        origin = "user"
    else:
        origin = "admin"
    admin_mutable = invite.bulk_campaign_id is None
    latest = latest_registration_token(db, invite_id=invite.id)
    live = (
        latest
        if latest is not None and latest.consumed_at is None and latest.expires_at > point
        else None
    )
    effective_pending_email = invite.pending_email or (live.email if live is not None else None)
    if state == "active" and effective_pending_email is not None:
        state = "awaiting_confirmation"

    if campaign is not None and invite.used_count < invite.max_uses and state in {"active", "awaiting_confirmation"}:
        parent_state = bulk_invite_campaign_state(campaign, now=point)
        if parent_state in {"revoked", "full"}:
            state = "revoked"
        elif parent_state == "expired":
            state = "expired"
    if state not in {"active", "awaiting_confirmation"}:
        live = None

    resend_available_at = None
    if state == "awaiting_confirmation" and effective_pending_email and latest is not None:
        resend_available_at = latest.created_at + timedelta(
            seconds=settings.auth_registration_resend_cooldown_seconds
        )
    plan = db.get(Plan, invite.plan_id) if invite.plan_id is not None else None
    effective_limit = (
        int(invite.wireguard_profile_limit)
        if invite.wireguard_profile_limit is not None
        else int(plan.default_wireguard_limit) if plan is not None else 0
    )
    offer = active_offer_for_plan(db, plan_id=invite.plan_id) if invite.plan_id is not None else None
    if campaign is not None:
        effective_trial_days = int(campaign.trial_days)
    elif invite.trial_days_override is not None:
        effective_trial_days = int(invite.trial_days_override)
    elif offer is not None:
        effective_trial_days = int(offer.trial_days)
    else:
        effective_trial_days = None
    return AdminInviteSummary(
        invite_id=invite.id,
        origin=origin,
        bulk_campaign_id=invite.bulk_campaign_id,
        bulk_campaign_label=campaign.label if campaign is not None else None,
        intended_email=invite.intended_email,
        pending_email=effective_pending_email,
        plan_id=invite.plan_id,
        wireguard_profile_limit=effective_limit,
        recipient_referrals_enabled=bool(invite.recipient_referrals_enabled),
        recipient_referral_limit=int(invite.recipient_referral_limit),
        trial_days=effective_trial_days,
        max_uses=invite.max_uses,
        used_count=invite.used_count,
        expires_at=invite.expires_at,
        revoked_at=invite.revoked_at,
        created_at=invite.created_at,
        created_by_kind=invite.created_by_kind,
        created_by_user_id=invite.created_by_user_id,
        created_by_label=invite.created_by_label,
        state=state,
        magic_link_sent_at=latest.created_at if latest is not None else None,
        magic_link_expires_at=live.expires_at if live is not None else None,
        resend_available_at=resend_available_at,
        can_resend=(
            admin_mutable
            and state == "awaiting_confirmation"
            and effective_pending_email is not None
            and (resend_available_at is None or resend_available_at <= point)
        ),
        can_change_email=(admin_mutable and state in {"active", "awaiting_confirmation"}),
        can_reissue_share_link=(
            admin_mutable
            and state == "active"
            and invite.intended_email is None
            and effective_pending_email is None
        ),
        can_revoke=(admin_mutable and state in {"active", "awaiting_confirmation"}),
    )


def _admin_bulk_invite_summary(campaign: BulkInviteCampaign, *, now: datetime | None = None) -> AdminBulkInviteSummary:
    return AdminBulkInviteSummary(
        campaign_id=campaign.id,
        label=campaign.label,
        plan_id=campaign.plan_id,
        max_registrations=int(campaign.max_registrations),
        used_count=int(campaign.used_count),
        trial_days=int(campaign.trial_days),
        recipient_referrals_enabled=bool(campaign.recipient_referrals_enabled),
        recipient_referral_limit=int(campaign.recipient_referral_limit),
        expires_at=campaign.expires_at,
        revoked_at=campaign.revoked_at,
        created_at=campaign.created_at,
        state=bulk_invite_campaign_state(campaign, now=now),
    )


def _admin_grant_summaries(db: Session, *, user: User) -> list[GrantSummary]:
    grants = db.execute(
        select(AccessGrant)
        .where(AccessGrant.user_id == user.id)
        .order_by(AccessGrant.created_at.asc())
    ).scalars().all()
    grant_ids = [grant.id for grant in grants]
    limits_by_grant: dict[UUID, list[AccessGrantProtocolLimit]] = {}
    configuration_count_by_grant: dict[UUID, int] = {}

    if grant_ids:
        limit_rows = db.execute(
            select(AccessGrantProtocolLimit)
            .where(AccessGrantProtocolLimit.access_grant_id.in_(grant_ids))
            .order_by(
                AccessGrantProtocolLimit.access_grant_id.asc(),
                AccessGrantProtocolLimit.protocol.asc(),
            )
        ).scalars().all()
        for row in limit_rows:
            limits_by_grant.setdefault(row.access_grant_id, []).append(row)

        usage_rows = db.execute(
            select(ConnectionSlot.access_grant_id, func.count(ConnectionSlot.id))
            .where(
                ConnectionSlot.user_id == user.id,
                ConnectionSlot.access_grant_id.in_(grant_ids),
                ConnectionSlot.disabled_at.is_(None),
            )
            .group_by(ConnectionSlot.access_grant_id)
        ).all()
        configuration_count_by_grant = {
            grant_id: int(count)
            for grant_id, count in usage_rows
        }

    return [
        _grant_summary(
            db,
            grant=grant,
            limits=limits_by_grant.get(grant.id, []),
            configuration_count=configuration_count_by_grant.get(grant.id, 0),
        )
        for grant in grants
    ]


@router.get(
    "/admin/plans",
    response_model=list[AdminPlanSummary],
    dependencies=[Depends(_require_admin)],
)
def admin_list_plans(db: Session = Depends(get_db)):
    rows = db.execute(
        select(Plan).order_by(Plan.created_at.asc())
    ).scalars().all()
    result: list[AdminPlanSummary] = []
    for row in rows:
        offer = active_offer_for_plan(db, plan_id=row.id)
        result.append(AdminPlanSummary(
            id=row.id,
            code=row.code,
            display_name=row.display_name,
            active=row.active,
            default_wireguard_limit=row.default_wireguard_limit,
            default_amneziawg_limit=row.default_amneziawg_limit,
            trial_days=int(offer.trial_days) if offer is not None else None,
        ))
    return result


@router.post(
    "/admin/bulk-invites",
    response_model=AdminBulkInviteCreateResponse,
    dependencies=[Depends(_require_admin)],
)
def admin_create_bulk_invite(
    payload: AdminBulkInviteCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        result = issue_bulk_invite_campaign(
            db,
            label=payload.label,
            plan_id=payload.plan_id,
            max_registrations=payload.max_registrations,
            trial_days=payload.trial_days,
            expires_at=payload.expires_at,
            recipient_referrals_enabled=payload.recipient_referrals_enabled,
            recipient_referral_limit=payload.recipient_referral_limit,
            request_id=_request_id(request),
        )
        db.commit()
        db.refresh(result.campaign)
    except BulkInviteRejected as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="bulk invite cannot be created") from exc
    return AdminBulkInviteCreateResponse(
        campaign=_admin_bulk_invite_summary(result.campaign, now=utcnow()),
        campaign_token=result.token,
    )


@router.get(
    "/admin/bulk-invites",
    response_model=list[AdminBulkInviteSummary],
    dependencies=[Depends(_require_admin)],
)
def admin_list_bulk_invites(db: Session = Depends(get_db)):
    rows = db.execute(
        select(BulkInviteCampaign).order_by(BulkInviteCampaign.created_at.desc())
    ).scalars().all()
    point = utcnow()
    return [_admin_bulk_invite_summary(row, now=point) for row in rows]


@router.post(
    "/admin/bulk-invites/{campaign_id}/revoke",
    response_model=AdminBulkInviteSummary,
    dependencies=[Depends(_require_admin)],
)
def admin_revoke_bulk_invite(
    campaign_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    req = _request_id(request)
    try:
        campaign = revoke_bulk_invite_campaign(
            db,
            campaign_id=campaign_id,
            request_id=req,
        )
        db.commit()
        db.refresh(campaign)
    except BulkInviteRejected as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="bulk invite not found") from exc

    try:
        cleanup = terminalize_terminal_bulk_campaign_children(
            db,
            campaign_id=campaign_id,
            request_id=req,
            reason="campaign_revoked",
        )
        db.commit()
        logger.info(
            "bulk campaign revoke child cleanup campaign=%s invites=%s tokens=%s",
            cleanup.campaign_id,
            cleanup.revoked_invites,
            cleanup.invalidated_tokens,
        )
    except Exception:
        db.rollback()
        logger.exception("bulk campaign revoke child cleanup failed campaign=%s", campaign_id)
    campaign = db.get(BulkInviteCampaign, campaign_id) or campaign
    return _admin_bulk_invite_summary(campaign, now=utcnow())


@router.get(
    "/admin/invites",
    response_model=list[AdminInviteSummary],
    dependencies=[Depends(_require_admin)],
)
def admin_list_invites(
    origin: list[Literal["user", "admin", "campaign"]] | None = Query(default=None),
    db: Session = Depends(get_db),
):
    requested = set(origin or ("user", "admin"))
    predicates = []
    if "user" in requested:
        predicates.append(
            and_(Invite.bulk_campaign_id.is_(None), Invite.created_by_kind == "user")
        )
    if "admin" in requested:
        predicates.append(
            and_(Invite.bulk_campaign_id.is_(None), Invite.created_by_kind == "admin")
        )
    if "campaign" in requested:
        predicates.append(Invite.bulk_campaign_id.is_not(None))

    if not predicates:
        return []

    rows = db.execute(
        select(Invite)
        .where(or_(*predicates))
        .order_by(Invite.created_at.desc())
    ).scalars().all()
    point = utcnow()
    return [_admin_invite_summary(db, row, now=point) for row in rows]


class AdminInviteRecipientUpdateRequest(BaseModel):
    email: EmailStr | None = None


class AdminInviteLimitUpdateRequest(BaseModel):
    profile_limit: int = Field(ge=0)


class AdminInviteShareTokenResponse(BaseModel):
    invite_id: UUID
    invite_token: str


@router.patch(
    "/admin/invites/{invite_id}/recipient",
    response_model=AdminInviteSummary,
    dependencies=[Depends(_require_admin)],
)
def admin_update_invite_recipient(
    invite_id: UUID,
    payload: AdminInviteRecipientUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    req = _request_id(request)
    try:
        invite, mail_result = admin_replace_invite_email(
            db,
            invite_id=invite_id,
            email=str(payload.email) if payload.email is not None else None,
            ttl_seconds=settings.auth_magic_link_ttl_seconds,
            request_id=req,
        )
        _deliver_magic_link_result(db, result=mail_result, request_id=req)
        db.commit()
        db.refresh(invite)
    except (InviteRejected, InvalidIdentity) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="invite cannot be updated") from exc
    return _admin_invite_summary(db, invite, now=utcnow())


@router.post(
    "/admin/invites/{invite_id}/share-token/reissue",
    response_model=AdminInviteShareTokenResponse,
    dependencies=[Depends(_require_admin)],
)
def admin_reissue_invite_share_token(
    invite_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    req = _request_id(request)
    try:
        invite, invite_token = admin_reissue_transferable_invite_token(
            db,
            invite_id=invite_id,
            request_id=req,
        )
        db.commit()
        db.refresh(invite)
    except InviteRejected as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="transferable invite share link cannot be reissued") from exc
    return AdminInviteShareTokenResponse(
        invite_id=invite.id,
        invite_token=invite_token,
    )


@router.patch(
    "/admin/invites/{invite_id}/wireguard-limit",
    response_model=AdminInviteSummary,
    dependencies=[Depends(_require_admin)],
)
def admin_update_invite_wireguard_limit(
    invite_id: UUID,
    payload: AdminInviteLimitUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    invite = db.execute(
        select(Invite).where(Invite.id == invite_id).with_for_update()
    ).scalar_one_or_none()
    if invite is None:
        raise HTTPException(status_code=404, detail="invite not found")
    if invite.bulk_campaign_id is not None:
        db.rollback()
        raise HTTPException(status_code=409, detail="bulk child invite is not admin-mutable")
    if invite.created_by_kind == "user":
        db.rollback()
        raise HTTPException(status_code=409, detail="user referral invite is not admin-mutable")
    offer = active_offer_for_plan(db, plan_id=invite.plan_id) if invite.plan_id is not None else None
    if offer is not None and int(payload.profile_limit) != int(offer.base_slot_quantity):
        db.rollback()
        raise HTTPException(status_code=409, detail="commercial onboarding configuration limit is fixed")
    now = utcnow()
    if _invite_lifecycle_state(invite, now=now) not in {"active", "awaiting_confirmation"}:
        db.rollback()
        raise HTTPException(status_code=409, detail="invite cannot be updated")
    invite.wireguard_profile_limit = int(payload.profile_limit)
    record_audit_event(
        db,
        event_type="auth.invite.wireguard_limit_changed",
        actor_kind="admin",
        object_type="invite",
        object_id=str(invite.id),
        request_id=_request_id(request),
        payload={"wireguard_profile_limit": int(payload.profile_limit)},
    )
    db.commit()
    db.refresh(invite)
    return _admin_invite_summary(db, invite, now=now)


@router.post(
    "/admin/invites/{invite_id}/resend",
    response_model=AdminInviteSummary,
    dependencies=[Depends(_require_admin)],
)
def admin_resend_invite(
    invite_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    req = _request_id(request)
    try:
        result = admin_resend_invite_registration(
            db,
            invite_id=invite_id,
            ttl_seconds=settings.auth_magic_link_ttl_seconds,
            cooldown_seconds=settings.auth_registration_resend_cooldown_seconds,
            request_id=req,
        )
        delivered = _deliver_magic_link_result(db, result=result, request_id=req)
        invite = db.get(Invite, invite_id)
        assert invite is not None
        if delivered and result.row is not None:
            invalidate_registration_tokens(
                db,
                invite=invite,
                now=utcnow(),
                request_id=req,
                reason=(
                    "admin_explicit_resend"
                    if result.row.purpose == "registration"
                    else "admin_resend_recipient_became_existing_user"
                ),
                keep_token_id=result.row.id if result.row.purpose == "registration" else None,
            )
        db.commit()
        if not delivered:
            raise HTTPException(status_code=502, detail="email delivery failed")
    except InviteResendTooSoon as exc:
        db.rollback()
        raise HTTPException(
            status_code=429,
            detail="resend cooldown",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except (InviteRejected, InvalidIdentity) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="invite cannot be resent") from exc
    return _admin_invite_summary(db, invite, now=utcnow())


@router.post(
    "/admin/invites/{invite_id}/revoke",
    response_model=AdminInviteSummary,
    dependencies=[Depends(_require_admin)],
)
def admin_revoke_invite(
    invite_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    invite = db.execute(
        select(Invite).where(Invite.id == invite_id).with_for_update()
    ).scalar_one_or_none()
    if invite is None:
        raise HTTPException(status_code=404, detail="invite not found")
    if invite.bulk_campaign_id is not None:
        db.rollback()
        raise HTTPException(status_code=409, detail="bulk child invite is not admin-mutable")
    now = utcnow()
    state = _invite_lifecycle_state(invite, now=now)
    if state == "used":
        db.rollback()
        raise HTTPException(status_code=409, detail="used invite cannot be revoked")
    if state == "expired":
        db.rollback()
        raise HTTPException(status_code=409, detail="expired invite cannot be revoked")
    if invite.revoked_at is None:
        req = _request_id(request)
        invalidate_registration_tokens(
            db,
            invite=invite,
            now=now,
            request_id=req,
            reason="admin_revoke",
        )
        invite.revoked_at = now
        record_audit_event(
            db,
            event_type="auth.invite.revoked",
            actor_kind="admin",
            object_type="invite",
            object_id=str(invite.id),
            request_id=req,
            payload={"used_count": invite.used_count, "max_uses": invite.max_uses},
        )
    db.commit()
    db.refresh(invite)
    return _admin_invite_summary(db, invite, now=now)


@router.post(
    "/admin/grants/{grant_id}/configurations",
    response_model=AdminConfigurationCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(_require_admin)],
)
def admin_create_configuration(
    grant_id: UUID,
    payload: AdminConfigurationCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    grant = db.get(AccessGrant, grant_id)
    if grant is None:
        raise HTTPException(status_code=404, detail="grant not found")
    user = db.get(User, grant.user_id)
    if user is None or user.deletion_requested_at is not None:
        raise HTTPException(status_code=404, detail="grant not found")
    try:
        result = create_owned_configuration(
            db,
            user=user,
            grant_id=grant.id,
            node_id=settings.wg_default_node_id,
            label=(str(payload.label).strip() or None) if payload.label is not None else None,
            request_id=_request_id(request),
            actor_kind="admin",
        )
        db.commit()
        for profile in result.profiles.values():
            db.refresh(profile)
        db.refresh(result.slot)
        trigger_wg_access_agent_best_effort()
    except ProfileSurfaceError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="configuration cannot be created") from exc
    return AdminConfigurationCreateResponse(
        configuration_id=result.slot.id,
        access_grant_id=result.slot.access_grant_id,
        label=result.slot.label,
        variants=[
            ConfigurationVariantMutation(
                protocol=protocol,
                profile=_profile_summary(result.profiles[protocol]),
                job_id=result.jobs[protocol].id,
                job_created=result.created_jobs[protocol],
            )
            for protocol in ("wireguard", "amneziawg")
        ],
    )


@router.get(
    "/admin/profiles/{profile_id}/config",
    dependencies=[Depends(_require_admin)],
)
def admin_profile_config_download(
    profile_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    profile = db.get(ConnectionProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="profile not found")
    user = db.get(User, profile.user_id)
    if user is None or user.deletion_requested_at is not None:
        raise HTTPException(status_code=404, detail="profile not found")
    if profile.protocol not in {"wireguard", "amneziawg"} or profile.status != "active" or not profile.tunnel_ip:
        raise HTTPException(status_code=409, detail="profile is not ready")
    try:
        config_text = build_owned_profile_config(
            db,
            user=user,
            profile_id=profile_id,
            request_id=_request_id(request),
            audit_event="admin.profile.config.delivered",
            audit_actor_kind="admin",
        )
        profile_ordinal = profile_slot_ordinal(db, user=user, profile_id=profile_id)
        if profile_ordinal == 0:
            raise ProfileUnavailable("profile unavailable")
        db.commit()
    except ProfileUnavailable as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="profile not found") from exc
    except ProfileNotReady as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="profile is not ready") from exc
    response = Response(
        content=config_text,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="SecretStudio-{profile_ordinal:02d}.conf"'},
    )
    _private_no_store(response)
    return response


@router.get(
    "/admin/runtime/connections",
    response_model=AdminRuntimeConnectionsResponse,
    dependencies=[Depends(_require_admin)],
)
def admin_runtime_connections(db: Session = Depends(get_db)):
    snapshot, received_at = get_runtime_snapshot()
    if snapshot is None or received_at is None:
        return AdminRuntimeConnectionsResponse(
            generated_at=None,
            received_at=None,
            snapshot_age_seconds=None,
            stale=True,
            sample_interval_seconds=None,
            unmatched_runtime_rows_count=0,
            rows=[],
        )

    now = utcnow()
    age_seconds = max(0.0, (now - received_at).total_seconds())
    runtime_rows = list(snapshot.get("rows") or [])
    profile_ids = [row.get("profile_id") for row in runtime_rows if row.get("profile_id") is not None]
    profiles = {
        profile.id: profile
        for profile in db.execute(
            select(ConnectionProfile).where(ConnectionProfile.id.in_(profile_ids))
        ).scalars().all()
    } if profile_ids else {}
    user_ids = {profile.user_id for profile in profiles.values()}
    users = {
        user.id: user
        for user in db.execute(select(User).where(User.id.in_(user_ids))).scalars().all()
    } if user_ids else {}
    slots = db.execute(
        select(ConnectionSlot)
        .where(ConnectionSlot.user_id.in_(user_ids))
        .order_by(ConnectionSlot.user_id.asc(), ConnectionSlot.created_at.asc(), ConnectionSlot.id.asc())
    ).scalars().all() if user_ids else []
    slots_by_id = {slot.id: slot for slot in slots}
    slot_ordinals: dict[UUID, int] = {}
    ordinal_by_user: dict[UUID, int] = {}
    for slot in slots:
        ordinal = ordinal_by_user.get(slot.user_id, 0) + 1
        ordinal_by_user[slot.user_id] = ordinal
        slot_ordinals[slot.id] = ordinal

    rows: list[AdminRuntimeConnectionRow] = []
    unmatched = 0
    for runtime in runtime_rows:
        profile = profiles.get(runtime.get("profile_id"))
        if profile is None:
            unmatched += 1
            continue
        user = users.get(profile.user_id)
        slot = slots_by_id.get(profile.connection_slot_id)
        runtime_protocol = str(runtime.get("protocol") or "")
        if (
            user is None
            or slot is None
            or slot.user_id != user.id
            or runtime_protocol != profile.protocol
        ):
            unmatched += 1
            continue
        rows.append(AdminRuntimeConnectionRow(
            user_id=user.id,
            email=user.email,
            display_name=user.display_name,
            configuration_id=slot.id,
            configuration_ordinal=slot_ordinals[slot.id],
            configuration_label=slot.label,
            profile_id=profile.id,
            protocol=profile.protocol,
            profile_label=profile.label,
            tunnel_ip=str(runtime["tunnel_ip"]),
            selector=str(runtime["selector"]),
            active_now=bool(runtime["active_now"]),
            active_state=bool(runtime["active_state"]),
            last_active_at=runtime.get("last_active_at"),
            last_reassign_at=runtime.get("last_reassign_at"),
            last_handshake_at=runtime.get("last_handshake_at"),
            rx_bytes=int(runtime["rx_bytes"]),
            tx_bytes=int(runtime["tx_bytes"]),
            rx_bytes_per_second=float(runtime["rx_bytes_per_second"]),
            tx_bytes_per_second=float(runtime["tx_bytes_per_second"]),
        ))

    return AdminRuntimeConnectionsResponse(
        generated_at=snapshot.get("generated_at"),
        received_at=received_at,
        snapshot_age_seconds=age_seconds,
        stale=age_seconds > max(1, int(settings.runtime_snapshot_stale_seconds)),
        sample_interval_seconds=float(snapshot.get("sample_interval_seconds")),
        unmatched_runtime_rows_count=unmatched,
        rows=rows,
    )


@router.get(
    "/admin/users",
    response_model=list[AdminUserSummary],
    dependencies=[Depends(_require_admin)],
)
def admin_list_users(
    email: str | None = None,
    query: str | None = None,
    limit: int = 100,
    offset: int = 0,
    sort_by: Literal[
        "email",
        "display_name",
        "created_at",
        "invite_issued_at",
        "invite_redeemed_at",
        "invited_by_label",
    ] = "created_at",
    sort_dir: Literal["asc", "desc"] = "desc",
    db: Session = Depends(get_db),
):
    bounded_limit = min(max(int(limit), 1), 200)
    bounded_offset = max(int(offset), 0)

    registration_ranked = (
        select(
            InviteRedemption.user_id.label("user_id"),
            InviteRedemption.invite_id.label("invite_id"),
            InviteRedemption.redeemed_at.label("redeemed_at"),
            func.row_number().over(
                partition_by=InviteRedemption.user_id,
                order_by=(InviteRedemption.redeemed_at.asc(), InviteRedemption.id.asc()),
            ).label("registration_rank"),
        )
        .subquery()
    )
    stmt = (
        select(User)
        .outerjoin(
            registration_ranked,
            and_(
                registration_ranked.c.user_id == User.id,
                registration_ranked.c.registration_rank == 1,
            ),
        )
        .outerjoin(Invite, Invite.id == registration_ranked.c.invite_id)
    )
    if email is not None and str(email).strip():
        stmt = stmt.where(User.email == str(email).strip().casefold())
    if query is not None and str(query).strip():
        search_query = str(query).strip().casefold()
        stmt = stmt.where(
            or_(
                func.lower(User.email).contains(search_query, autoescape=True),
                func.lower(User.display_name).contains(search_query, autoescape=True),
            )
        )

    sort_columns = {
        "email": User.email,
        "display_name": func.lower(User.display_name),
        "created_at": User.created_at,
        "invite_issued_at": Invite.created_at,
        "invite_redeemed_at": registration_ranked.c.redeemed_at,
        "invited_by_label": func.lower(Invite.created_by_label),
    }
    sort_column = sort_columns[sort_by]
    if sort_dir == "asc":
        stmt = stmt.order_by(sort_column.asc().nulls_last(), User.id.asc())
    else:
        stmt = stmt.order_by(sort_column.desc().nulls_last(), User.id.desc())

    users = db.execute(stmt.offset(bounded_offset).limit(bounded_limit)).scalars().all()
    result: list[AdminUserSummary] = []
    for user in users:
        profiles = db.execute(
            select(ConnectionProfile)
            .where(ConnectionProfile.user_id == user.id)
            .order_by(ConnectionProfile.created_at.asc())
        ).scalars().all()
        registration = db.execute(
            select(InviteRedemption, Invite)
            .join(Invite, Invite.id == InviteRedemption.invite_id)
            .where(InviteRedemption.user_id == user.id)
            .order_by(InviteRedemption.redeemed_at.asc(), InviteRedemption.id.asc())
            .limit(1)
        ).first()
        redemption = registration[0] if registration else None
        invite = registration[1] if registration else None
        result.append(
            AdminUserSummary(
                user_id=user.id,
                email=user.email,
                display_name=user.display_name,
                admin_note=user.admin_note,
                referrals_enabled=bool(user.referrals_enabled),
                referral_limit=int(user.referral_limit),
                email_verified_at=user.email_verified_at,
                created_at=user.created_at,
                deletion_requested_at=user.deletion_requested_at,
                registration_invite_id=invite.id if invite else None,
                invite_issued_at=invite.created_at if invite else None,
                invite_redeemed_at=redemption.redeemed_at if redemption else None,
                invited_by_kind=invite.created_by_kind if invite else None,
                invited_by_origin=(
                    "campaign" if invite and invite.bulk_campaign_id is not None
                    else "user" if invite and invite.created_by_kind == "user"
                    else "admin" if invite is not None
                    else None
                ),
                invited_by_user_id=invite.created_by_user_id if invite else None,
                invited_by_label=invite.created_by_label if invite else None,
                invited_by_campaign_id=invite.bulk_campaign_id if invite else None,
                grants=_admin_grant_summaries(db, user=user),
                configurations=_configuration_summaries(db, user=user),
                profiles=[_profile_summary(profile) for profile in profiles],
            )
        )
    return result


@router.patch(
    "/admin/users/{user_id}",
    response_model=AdminUserMetadataUpdateResponse,
    dependencies=[Depends(_require_admin)],
)
def admin_update_user_metadata(
    user_id: UUID,
    payload: AdminUserMetadataUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    user = db.execute(
        select(User).where(User.id == user_id).with_for_update()
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    normalized = str(payload.admin_note).strip() if payload.admin_note is not None else ""
    user.admin_note = normalized or None
    record_audit_event(
        db,
        event_type="admin.user_note.updated",
        actor_kind="admin",
        actor_user_id=None,
        object_type="user",
        object_id=str(user.id),
        request_id=_request_id(request),
        payload={"admin_note_set": user.admin_note is not None},
    )
    db.commit()
    db.refresh(user)
    return AdminUserMetadataUpdateResponse(
        user_id=user.id,
        display_name=user.display_name,
        admin_note=user.admin_note,
    )


@router.patch(
    "/admin/users/{user_id}/referral-policy",
    response_model=AdminUserReferralPolicyResponse,
    dependencies=[Depends(_require_admin)],
)
def admin_update_user_referral_policy(
    user_id: UUID,
    payload: AdminUserReferralPolicyUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    user = db.execute(
        select(User).where(User.id == user_id).with_for_update()
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    before_enabled = bool(user.referrals_enabled)
    before_limit = int(user.referral_limit)
    user.referrals_enabled = bool(payload.enabled)
    user.referral_limit = int(payload.limit)
    record_audit_event(
        db,
        event_type="admin.user_referral_policy.updated",
        actor_kind="admin",
        actor_user_id=None,
        object_type="user",
        object_id=str(user.id),
        request_id=_request_id(request),
        payload={
            "enabled_before": before_enabled,
            "enabled_after": bool(user.referrals_enabled),
            "limit_before": before_limit,
            "limit_after": int(user.referral_limit),
            "existing_invites_revoked": False,
        },
    )
    db.commit()
    db.refresh(user)
    return AdminUserReferralPolicyResponse(
        user_id=user.id,
        enabled=bool(user.referrals_enabled),
        limit=int(user.referral_limit),
    )


@router.delete(
    "/admin/users/{user_id}",
    response_model=AdminUserDeleteResponse,
    dependencies=[Depends(_require_admin)],
)
def admin_delete_user(
    user_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        result = request_admin_user_deletion(
            db,
            user_id=user_id,
            request_id=_request_id(request),
        )
        db.commit()
    except UserDeletionError as exc:
        db.rollback()
        if str(exc) == "user not found":
            raise HTTPException(status_code=404, detail="user not found") from exc
        raise HTTPException(status_code=409, detail="user cannot be deleted") from exc
    trigger_wg_access_agent_best_effort()
    return AdminUserDeleteResponse(
        user_id=result.user_id,
        email=result.email,
        status=result.status,
        disable_jobs_created=result.disable_jobs_created,
        remaining_profiles=result.remaining_profiles,
        legacy_dependency_count=result.legacy_dependency_count,
    )


@router.put(
    "/admin/grants/{grant_id}/protocol-limits/{protocol}",
    response_model=AdminProtocolLimitUpdateResponse,
    dependencies=[Depends(_require_admin)],
)
def admin_set_protocol_limit(
    grant_id: UUID,
    protocol: str,
    payload: AdminProtocolLimitUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    # Compatibility route name retained until the Admin UI is converted to one
    # configuration limit. Both stored protocol rows are always updated together.
    if protocol not in {"wireguard", "amneziawg"}:
        raise HTTPException(status_code=400, detail="unsupported protocol")
    grant = db.execute(
        select(AccessGrant).where(AccessGrant.id == grant_id).with_for_update()
    ).scalar_one_or_none()
    if grant is None:
        raise HTTPException(status_code=404, detail="grant not found")

    limit_rows = db.execute(
        select(AccessGrantProtocolLimit)
        .where(
            AccessGrantProtocolLimit.access_grant_id == grant.id,
            AccessGrantProtocolLimit.protocol.in_(("wireguard", "amneziawg")),
        )
        .with_for_update()
    ).scalars().all()
    by_protocol = {row.protocol: row for row in limit_rows}
    if set(by_protocol) != {"wireguard", "amneziawg"}:
        raise HTTPException(status_code=409, detail="configuration limit mirror is incomplete")
    prior_limit = mirrored_configuration_limit(db, grant_id=grant.id)
    new_limit = int(payload.profile_limit)

    selected_ids = list(payload.retire_profile_ids)
    if len(set(selected_ids)) != len(selected_ids):
        raise HTTPException(status_code=400, detail="duplicate retirement profile ids")

    quota_slots = db.execute(
        select(ConnectionSlot)
        .where(
            ConnectionSlot.access_grant_id == grant.id,
            ConnectionSlot.disabled_at.is_(None),
        )
        .order_by(ConnectionSlot.created_at.asc(), ConnectionSlot.id.asc())
        .with_for_update()
    ).scalars().all()
    current_count = len(quota_slots)
    required_reduction = max(0, current_count - new_limit)

    selected_slot_ids: list[UUID] = []
    if required_reduction == 0:
        if selected_ids:
            raise HTTPException(
                status_code=400,
                detail="retirement profile ids are not allowed when no reduction is required",
            )
    else:
        if len(selected_ids) != required_reduction:
            raise HTTPException(
                status_code=409,
                detail=f"exactly {required_reduction} configuration(s) must be selected for retirement",
            )
        selected_profiles = db.execute(
            select(ConnectionProfile)
            .where(ConnectionProfile.id.in_(selected_ids))
            .with_for_update()
        ).scalars().all()
        if len(selected_profiles) != len(selected_ids):
            raise HTTPException(status_code=409, detail="selected profile not found")
        eligible_slot_ids = {slot.id for slot in quota_slots}
        for selected in selected_profiles:
            if selected.access_grant_id != grant.id or selected.connection_slot_id not in eligible_slot_ids:
                raise HTTPException(
                    status_code=409,
                    detail="selected profiles must belong to active configurations of this grant",
                )
            selected_slot_ids.append(selected.connection_slot_id)
        if len(set(selected_slot_ids)) != required_reduction:
            raise HTTPException(
                status_code=409,
                detail="selected profiles must identify distinct configurations",
            )

    disable_jobs_created = 0
    req = _request_id(request)
    for slot_id in selected_slot_ids:
        try:
            disable_results = request_configuration_disable(db, slot_id=slot_id)
        except DomainV2Error as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="selected configuration cannot be retired in its current state",
            ) from exc
        disable_jobs_created += sum(int(created) for _, _, created in disable_results)
        record_audit_event(
            db,
            event_type="configuration.retirement.requested",
            actor_kind="admin",
            object_type="connection_slot",
            object_id=str(slot_id),
            request_id=req,
            payload={
                "access_grant_id": str(grant.id),
                "variant_jobs": [
                    {
                        "protocol": profile_row.protocol,
                        "job_id": str(job.id),
                        "job_created": bool(created),
                    }
                    for profile_row, job, created in disable_results
                ],
            },
        )

    for row in by_protocol.values():
        row.profile_limit = new_limit
    record_audit_event(
        db,
        event_type="grant.configuration_limit.updated",
        actor_kind="admin",
        object_type="access_grant",
        object_id=str(grant.id),
        request_id=req,
        payload={
            "prior_profile_limit": prior_limit,
            "profile_limit": new_limit,
            "configuration_count_before": current_count,
            "required_reduction": required_reduction,
            "retire_profile_ids": [str(profile_id) for profile_id in selected_ids],
            "retire_configuration_ids": [str(slot_id) for slot_id in selected_slot_ids],
            "disable_jobs_created": disable_jobs_created,
        },
    )
    db.commit()
    for row in by_protocol.values():
        db.refresh(row)
    if selected_slot_ids:
        trigger_wg_access_agent_best_effort()
    return AdminProtocolLimitUpdateResponse(
        access_grant_id=grant.id,
        protocol=protocol,
        profile_limit=new_limit,
        profile_count=current_count,
        can_create=(grant_is_active(grant) and current_count < new_limit),
        retire_profile_ids=selected_ids,
        disable_jobs_created=disable_jobs_created,
        retirement_in_progress=bool(selected_slot_ids),
    )
