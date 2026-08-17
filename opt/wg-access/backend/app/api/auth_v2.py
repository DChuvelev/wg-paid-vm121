from __future__ import annotations

from datetime import datetime
import secrets
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.session import get_db
from app.models import AccessGrant, AuthSession, User
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
    redeem_invite,
    request_id_or_new,
    revoke_session,
)
from app.services.domain_v2 import InvalidIdentity, record_audit_event

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
    expected = settings.auth_admin_token
    if not expected:
        raise HTTPException(status_code=503, detail="admin authorization is not configured")
    if not x_admin_token or not secrets.compare_digest(x_admin_token, expected):
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
    intended_email: EmailStr
    plan_id: UUID | None = None


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
            intended_email=str(payload.intended_email),
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
        user = redeem_invite(
            db,
            token=payload.invite_token,
            email=str(payload.email),
            request_id=req,
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
    return {"status": "accepted", "user_id": str(user.id)}


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
        issue_magic_link_for_email(
            db,
            email=payload.email,
            ttl_seconds=settings.auth_magic_link_ttl_seconds,
            request_id=req,
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


class GrantSummary(BaseModel):
    id: UUID
    status: str
    plan_id: UUID | None
    valid_until: datetime | None


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
    return AccountMeResponse(
        user_id=user.id,
        email=user.email,
        grants=[
            GrantSummary(id=g.id, status=g.status, plan_id=g.plan_id, valid_until=g.valid_until)
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
