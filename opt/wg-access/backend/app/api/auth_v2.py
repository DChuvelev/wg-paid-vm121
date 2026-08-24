from __future__ import annotations

from datetime import datetime
import secrets
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.services.admin_auth import AdminAuthorizationUnavailable, admin_token_matches
from app.services.mail_delivery import MailDeliveryError, deliver_magic_link_email
from app.db.session import get_db
from app.models import AccessGrant, AccessGrantProtocolLimit, AuthSession, ConnectionProfile, User
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
    InvalidIdentity,
    PROFILE_QUOTA_STATUSES,
    grant_is_active,
    record_audit_event,
    utcnow,
)

from app.services.profile_delivery import (
    ProfileNotReady,
    ProfileSurfaceError,
    ProfileUnavailable,
    build_owned_wireguard_config,
    build_qr_svg,
    create_owned_profile,
    list_owned_profiles,
    reissue_owned_profile,
    revoke_owned_profile,
)

router = APIRouter(prefix="/v2", tags=["domain-v2-auth"])

SESSION_COOKIE = "wg_access_session"
CSRF_COOKIE = "wg_access_csrf"
CSRF_HEADER = "x-csrf-token"
GENERIC_LOGIN_RESPONSE = {"status": "accepted"}


def _request_id(request: Request) -> str:
    return request_id_or_new(request.headers.get("x-request-id"))


def _client_key(request: Request) -> str:
    host = request.client.host if request.client else "unknown"
    return str(host or "unknown")


def _require_external_onboarding() -> None:
    if not settings.external_onboarding_active:
        raise HTTPException(status_code=404, detail="not found")


def _require_admin(x_admin_token: str | None = Header(default=None)) -> None:
    try:
        matched = admin_token_matches(x_admin_token)
    except AdminAuthorizationUnavailable as exc:
        raise HTTPException(status_code=503, detail="admin authorization is not configured") from exc
    if not matched:
        raise HTTPException(status_code=401, detail="unauthorized")


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
    return [_profile_summary(row) for row in rows]


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
        db.commit()
    except ProfileUnavailable as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="profile not found") from exc
    except ProfileNotReady as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="profile is not ready") from exc
    response = Response(content=config_text, media_type="text/plain; charset=utf-8")
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


@router.post(
    "/account/profiles/{profile_id}/revoke",
    response_model=ProfileMutationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def account_profile_revoke(
    profile_id: UUID,
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    _, user = current
    try:
        profile, job, created = revoke_owned_profile(
            db,
            user=user,
            profile_id=profile_id,
            request_id=_request_id(request),
        )
        db.commit()
        db.refresh(profile)
    except ProfileUnavailable as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="profile not found") from exc
    except ProfileSurfaceError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="profile cannot be revoked") from exc
    return ProfileMutationResponse(
        profile=_profile_summary(profile),
        job_id=job.id,
        job_created=created,
    )


@router.post(
    "/account/profiles/{profile_id}/reissue",
    response_model=ProfileMutationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def account_profile_reissue(
    profile_id: UUID,
    request: Request,
    current: tuple[AuthSession, User] = Depends(_current_session),
    db: Session = Depends(get_db),
    _: None = Depends(_require_external_onboarding),
    __: None = Depends(_require_csrf),
):
    _, user = current
    try:
        profile, job, created = reissue_owned_profile(
            db,
            user=user,
            profile_id=profile_id,
            request_id=_request_id(request),
        )
        db.commit()
        db.refresh(profile)
    except ProfileUnavailable as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="profile not found") from exc
    except ProfileSurfaceError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="profile cannot be reissued") from exc
    return ProfileMutationResponse(
        profile=_profile_summary(profile),
        job_id=job.id,
        job_created=created,
    )
