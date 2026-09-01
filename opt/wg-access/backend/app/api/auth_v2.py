from __future__ import annotations

from datetime import datetime
import base64
import hashlib
import hmac
import secrets
import time
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.services.admin_auth import AdminAuthorizationUnavailable, admin_token_matches, load_admin_token
from app.agent_trigger import trigger_wg_access_agent_best_effort
from app.services.mail_delivery import MailDeliveryError, deliver_magic_link_email
from app.db.session import get_db
from app.models import AccessGrant, AccessGrantProtocolLimit, AuthSession, ConnectionProfile, Invite, Plan, User
from app.services.auth_v2 import (
    AuthV2Error,
    InviteRejected,
    MagicLinkRejected,
    RateLimitExceeded,
    SessionRejected,
    authenticate_session,
    consume_magic_link,
    email_fingerprint,
    enforce_rate_limit,
    issue_invite,
    issue_magic_link_for_email,
    request_invite_registration,
    request_id_or_new,
    revoke_session,
)
from app.services.domain_v2 import (
    DomainV2Error,
    InvalidIdentity,
    PROFILE_QUOTA_STATUSES,
    grant_is_active,
    record_audit_event,
    request_profile_disable,
    utcnow,
)

from app.services.user_deletion import UserDeletionError, request_admin_user_deletion

from app.services.profile_delivery import (
    ProfileNotReady,
    ProfileSurfaceError,
    ProfileUnavailable,
    build_owned_wireguard_config,
    build_qr_svg,
    create_owned_profile,
    list_owned_profiles,
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


class AdminInviteResponse(BaseModel):
    invite_id: UUID
    invite_token: str
    expires_at: datetime | None


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
    try:
        result = issue_invite(
            db,
            intended_email=str(payload.intended_email) if payload.intended_email else None,
            ttl_seconds=settings.auth_invite_ttl_seconds,
            plan_id=payload.plan_id,
            request_id=req,
        )
        db.commit()
        db.refresh(result.invite)
    except (AuthV2Error, InvalidIdentity) as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail="invite cannot be issued") from exc
    return AdminInviteResponse(
        invite_id=result.invite.id,
        invite_token=result.token,
        expires_at=result.invite.expires_at,
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
        if result.row is not None and result.token is not None:
            try:
                deliver_magic_link_email(
                    to_email=result.row.email,
                    token=result.token,
                )
                record_audit_event(
                    db,
                    event_type="auth.magic_link.delivered",
                    actor_kind="system",
                    object_type="magic_link_token",
                    object_id=str(result.row.id),
                    request_id=req,
                    payload={
                        "email_hash": email_fingerprint(result.row.email),
                        "purpose": result.row.purpose,
                    },
                )
            except MailDeliveryError:
                result.row.consumed_at = utcnow()
                record_audit_event(
                    db,
                    event_type="auth.magic_link.delivery_failed",
                    actor_kind="system",
                    object_type="magic_link_token",
                    object_id=str(result.row.id),
                    request_id=req,
                    payload={
                        "email_hash": email_fingerprint(result.row.email),
                        "purpose": result.row.purpose,
                    },
                )
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
        if result.row is not None and result.token is not None:
            try:
                deliver_magic_link_email(
                    to_email=result.row.email,
                    token=result.token,
                )
                record_audit_event(
                    db,
                    event_type="auth.magic_link.delivered",
                    actor_kind="system",
                    object_type="magic_link_token",
                    object_id=str(result.row.id),
                    request_id=req,
                    payload={"email_hash": email_fingerprint(result.row.email)},
                )
            except MailDeliveryError:
                # An undelivered token must not remain usable. The public response
                # stays generic so delivery state cannot become an enumeration oracle.
                result.row.consumed_at = utcnow()
                record_audit_event(
                    db,
                    event_type="auth.magic_link.delivery_failed",
                    actor_kind="system",
                    object_type="magic_link_token",
                    object_id=str(result.row.id),
                    request_id=req,
                    payload={"email_hash": email_fingerprint(result.row.email)},
                )
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
    protocol_limits: list[GrantProtocolLimitSummary]


class AccountMeResponse(BaseModel):
    user_id: UUID
    email: str
    grants: list[GrantSummary]


@router.get("/account/me", response_model=AccountMeResponse)
def account_me(
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
):
    _, user = current
    grants = db.execute(
        select(AccessGrant).where(AccessGrant.user_id == user.id).order_by(AccessGrant.created_at.asc())
    ).scalars().all()

    limits_by_grant: dict[UUID, list[AccessGrantProtocolLimit]] = {}
    usage_by_grant_protocol: dict[tuple[UUID, str], int] = {}
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
            select(
                ConnectionProfile.access_grant_id,
                ConnectionProfile.protocol,
                func.count(ConnectionProfile.id),
            )
            .where(
                ConnectionProfile.user_id == user.id,
                ConnectionProfile.access_grant_id.in_(grant_ids),
                ConnectionProfile.status.in_(PROFILE_QUOTA_STATUSES),
            )
            .group_by(ConnectionProfile.access_grant_id, ConnectionProfile.protocol)
        ).all()
        usage_by_grant_protocol = {
            (grant_id, protocol): int(count)
            for grant_id, protocol, count in usage_rows
        }

    return AccountMeResponse(
        user_id=user.id,
        email=user.email,
        grants=[
            GrantSummary(
                id=g.id,
                status=g.status,
                plan_id=g.plan_id,
                valid_until=g.valid_until,
                protocol_limits=[
                    GrantProtocolLimitSummary(
                        protocol=limit.protocol,
                        profile_limit=limit.profile_limit,
                        profile_count=usage_by_grant_protocol.get((g.id, limit.protocol), 0),
                        can_create=(
                            limit.protocol == "wireguard"
                            and grant_is_active(g)
                            and usage_by_grant_protocol.get((g.id, limit.protocol), 0) < limit.profile_limit
                        ),
                    )
                    for limit in limits_by_grant.get(g.id, [])
                ],
            )
            for g in grants
        ],
    )


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
    protocol: Literal["wireguard"] = "wireguard"
    label: str | None = None


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
        if row.status in PROFILE_QUOTA_STATUSES
    ]


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
            label=payload.label,
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
        config_text = build_owned_wireguard_config(
            db,
            user=user,
            profile_id=profile_id,
            request_id=_request_id(request),
        )
        profile_ordinal = next(
            (index for index, owned in enumerate(list_owned_profiles(db, user=user), start=1) if owned.id == profile_id),
            0,
        )
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
        config_text = build_owned_wireguard_config(
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


class AdminInviteSummary(BaseModel):
    invite_id: UUID
    intended_email: str | None
    plan_id: UUID | None
    max_uses: int
    used_count: int
    expires_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime
    state: str


class AdminUserSummary(BaseModel):
    user_id: UUID
    email: str
    email_verified_at: datetime
    created_at: datetime
    deletion_requested_at: datetime | None
    grants: list[GrantSummary]
    profiles: list[ProfileSummary]


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


def _admin_invite_state(invite: Invite, *, now: datetime | None = None) -> str:
    point = now or utcnow()
    if invite.revoked_at is not None:
        return "revoked"
    if invite.expires_at is not None and invite.expires_at <= point:
        return "expired"
    if invite.used_count >= invite.max_uses:
        return "used"
    return "active"


def _admin_invite_summary(invite: Invite, *, now: datetime | None = None) -> AdminInviteSummary:
    return AdminInviteSummary(
        invite_id=invite.id,
        intended_email=invite.intended_email,
        plan_id=invite.plan_id,
        max_uses=invite.max_uses,
        used_count=invite.used_count,
        expires_at=invite.expires_at,
        revoked_at=invite.revoked_at,
        created_at=invite.created_at,
        state=_admin_invite_state(invite, now=now),
    )


def _admin_grant_summaries(db: Session, *, user: User) -> list[GrantSummary]:
    grants = db.execute(
        select(AccessGrant)
        .where(AccessGrant.user_id == user.id)
        .order_by(AccessGrant.created_at.asc())
    ).scalars().all()
    grant_ids = [grant.id for grant in grants]
    limits_by_grant: dict[UUID, list[AccessGrantProtocolLimit]] = {}
    usage_by_grant_protocol: dict[tuple[UUID, str], int] = {}

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
            select(
                ConnectionProfile.access_grant_id,
                ConnectionProfile.protocol,
                func.count(ConnectionProfile.id),
            )
            .where(
                ConnectionProfile.user_id == user.id,
                ConnectionProfile.access_grant_id.in_(grant_ids),
                ConnectionProfile.status.in_(PROFILE_QUOTA_STATUSES),
            )
            .group_by(ConnectionProfile.access_grant_id, ConnectionProfile.protocol)
        ).all()
        usage_by_grant_protocol = {
            (grant_id, protocol): int(count)
            for grant_id, protocol, count in usage_rows
        }

    return [
        GrantSummary(
            id=grant.id,
            status=grant.status,
            plan_id=grant.plan_id,
            valid_until=grant.valid_until,
            protocol_limits=[
                GrantProtocolLimitSummary(
                    protocol=limit.protocol,
                    profile_limit=limit.profile_limit,
                    profile_count=usage_by_grant_protocol.get((grant.id, limit.protocol), 0),
                    can_create=(
                        limit.protocol == "wireguard"
                        and grant_is_active(grant)
                        and usage_by_grant_protocol.get((grant.id, limit.protocol), 0) < limit.profile_limit
                    ),
                )
                for limit in limits_by_grant.get(grant.id, [])
            ],
        )
        for grant in grants
    ]


@router.get(
    "/admin/plans",
    response_model=list[AdminPlanSummary],
    dependencies=[Depends(_require_admin)],
)
def admin_list_plans(db: Session = Depends(get_db)):
    rows = db.execute(select(Plan).order_by(Plan.created_at.asc())).scalars().all()
    return [
        AdminPlanSummary(
            id=row.id,
            code=row.code,
            display_name=row.display_name,
            active=row.active,
            default_wireguard_limit=row.default_wireguard_limit,
            default_amneziawg_limit=row.default_amneziawg_limit,
        )
        for row in rows
    ]


@router.get(
    "/admin/invites",
    response_model=list[AdminInviteSummary],
    dependencies=[Depends(_require_admin)],
)
def admin_list_invites(db: Session = Depends(get_db)):
    rows = db.execute(select(Invite).order_by(Invite.created_at.desc())).scalars().all()
    point = utcnow()
    return [_admin_invite_summary(row, now=point) for row in rows]


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
    now = utcnow()
    if invite.revoked_at is None:
        invite.revoked_at = now
        record_audit_event(
            db,
            event_type="auth.invite.revoked",
            actor_kind="admin",
            object_type="invite",
            object_id=str(invite.id),
            request_id=_request_id(request),
            payload={"used_count": invite.used_count, "max_uses": invite.max_uses},
        )
    db.commit()
    db.refresh(invite)
    return _admin_invite_summary(invite, now=now)


@router.get(
    "/admin/users",
    response_model=list[AdminUserSummary],
    dependencies=[Depends(_require_admin)],
)
def admin_list_users(
    email: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    bounded_limit = min(max(int(limit), 1), 200)
    stmt = select(User).order_by(User.created_at.desc())
    if email is not None and str(email).strip():
        stmt = stmt.where(User.email == str(email).strip().casefold())
    users = db.execute(stmt.limit(bounded_limit)).scalars().all()
    result: list[AdminUserSummary] = []
    for user in users:
        profiles = db.execute(
            select(ConnectionProfile)
            .where(ConnectionProfile.user_id == user.id)
            .order_by(ConnectionProfile.created_at.asc())
        ).scalars().all()
        result.append(
            AdminUserSummary(
                user_id=user.id,
                email=user.email,
                email_verified_at=user.email_verified_at,
                created_at=user.created_at,
                deletion_requested_at=user.deletion_requested_at,
                grants=_admin_grant_summaries(db, user=user),
                profiles=[_profile_summary(profile) for profile in profiles],
            )
        )
    return result


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
    if protocol not in {"wireguard", "amneziawg"}:
        raise HTTPException(status_code=400, detail="unsupported protocol")
    grant = db.execute(
        select(AccessGrant).where(AccessGrant.id == grant_id).with_for_update()
    ).scalar_one_or_none()
    if grant is None:
        raise HTTPException(status_code=404, detail="grant not found")
    limit_row = db.execute(
        select(AccessGrantProtocolLimit)
        .where(
            AccessGrantProtocolLimit.access_grant_id == grant.id,
            AccessGrantProtocolLimit.protocol == protocol,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if limit_row is None:
        raise HTTPException(status_code=404, detail="protocol limit not found")

    prior_limit = int(limit_row.profile_limit)
    new_limit = int(payload.profile_limit)
    selected_ids = list(payload.retire_profile_ids)
    if len(set(selected_ids)) != len(selected_ids):
        raise HTTPException(status_code=400, detail="duplicate retirement profile ids")

    quota_profiles = db.execute(
        select(ConnectionProfile)
        .where(
            ConnectionProfile.access_grant_id == grant.id,
            ConnectionProfile.protocol == protocol,
            ConnectionProfile.status.in_(PROFILE_QUOTA_STATUSES),
        )
        .order_by(ConnectionProfile.created_at.asc(), ConnectionProfile.id.asc())
        .with_for_update()
    ).scalars().all()
    current_count = len(quota_profiles)
    required_reduction = max(0, current_count - new_limit)

    if required_reduction == 0:
        if selected_ids:
            raise HTTPException(
                status_code=400,
                detail="retirement profile ids are not allowed when no reduction is required",
            )
    else:
        if protocol != "wireguard":
            raise HTTPException(
                status_code=409,
                detail="profile retirement is not supported for this protocol",
            )
        if len(selected_ids) != required_reduction:
            raise HTTPException(
                status_code=409,
                detail=f"exactly {required_reduction} profile(s) must be selected for retirement",
            )
        eligible_ids = {profile.id for profile in quota_profiles}
        if any(profile_id not in eligible_ids for profile_id in selected_ids):
            raise HTTPException(
                status_code=409,
                detail="selected profiles must belong to this grant/protocol and consume quota",
            )

    disable_jobs_created = 0
    req = _request_id(request)
    for profile_id in selected_ids:
        try:
            profile, job, created = request_profile_disable(db, profile_id=profile_id)
        except DomainV2Error as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="selected profile cannot be retired in its current state",
            ) from exc
        disable_jobs_created += int(created)
        record_audit_event(
            db,
            event_type="profile.retirement.requested",
            actor_kind="admin",
            object_type="connection_profile",
            object_id=str(profile.id),
            request_id=req,
            payload={
                "access_grant_id": str(grant.id),
                "protocol": protocol,
                "job_id": str(job.id),
                "job_created": bool(created),
            },
        )

    limit_row.profile_limit = new_limit
    record_audit_event(
        db,
        event_type="grant.protocol_limit.updated",
        actor_kind="admin",
        object_type="access_grant",
        object_id=str(grant.id),
        request_id=req,
        payload={
            "protocol": protocol,
            "prior_profile_limit": prior_limit,
            "profile_limit": new_limit,
            "profile_count_before": current_count,
            "required_reduction": required_reduction,
            "retire_profile_ids": [str(profile_id) for profile_id in selected_ids],
            "disable_jobs_created": disable_jobs_created,
        },
    )
    db.commit()
    db.refresh(limit_row)
    if selected_ids:
        trigger_wg_access_agent_best_effort()
    return AdminProtocolLimitUpdateResponse(
        access_grant_id=grant.id,
        protocol=protocol,
        profile_limit=int(limit_row.profile_limit),
        profile_count=current_count,
        can_create=(
            protocol == "wireguard"
            and grant_is_active(grant)
            and current_count < int(limit_row.profile_limit)
        ),
        retire_profile_ids=selected_ids,
        disable_jobs_created=disable_jobs_created,
        retirement_in_progress=bool(selected_ids),
    )

