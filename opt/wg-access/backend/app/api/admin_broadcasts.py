"""Private, CSRF-guarded Admin informational broadcast API."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import AdminBroadcast
from app.api.auth_v2 import _require_admin, _request_id
from app.services.admin_broadcast import (
    BroadcastRejected, eligible_addresses, create_draft, confirm_send,
    recipient_counts, validate_message,
)
from app.services.domain_v2 import record_audit_event, utcnow
from app.services.mail_delivery import MailDeliveryError, SUPPORT_EMAIL, deliver_admin_broadcast_email

router = APIRouter(prefix="/v2/admin/broadcasts", tags=["admin-broadcasts"], dependencies=[Depends(_require_admin)])


class Compose(BaseModel):
    audience: Literal["active", "all"]
    subject: str = Field(min_length=1, max_length=220)
    body: str = Field(min_length=1, max_length=10000)


class ComposePreview(BaseModel):
    audience: Literal["active", "all"]
    subject: str
    body: str
    recipient_count: int


class DraftSummary(BaseModel):
    id: UUID
    audience: str
    state: str
    subject: str
    body: str
    recipient_count: int
    created_at: datetime
    confirmed_at: datetime | None
    test_attempted_at: datetime | None
    counts: dict[str, int]


class ConfirmRequest(BaseModel):
    confirmed_recipient_count: int = Field(ge=1)


def _no_store(response: Response):
    response.headers["Cache-Control"] = "no-store"


def _draft_response(db: Session, c: AdminBroadcast) -> DraftSummary:
    return DraftSummary(
        id=c.id, audience=c.audience, state=c.state, subject=c.subject,
        body=c.body, recipient_count=c.recipient_count, created_at=c.created_at,
        confirmed_at=c.confirmed_at, test_attempted_at=c.test_attempted_at, counts=recipient_counts(db, c.id),
    )


@router.post("/preview", response_model=ComposePreview)
def preview(payload: Compose, response: Response, db: Session = Depends(get_db)):
    _no_store(response)
    try:
        subject, body = validate_message(payload.subject, payload.body)
        addresses = eligible_addresses(db, payload.audience)
    except BroadcastRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ComposePreview(audience=payload.audience, subject=subject, body=body, recipient_count=len(addresses))


@router.post("", response_model=DraftSummary)
def draft(payload: Compose, request: Request, response: Response, db: Session = Depends(get_db)):
    _no_store(response)
    try:
        c = create_draft(db, audience=payload.audience, subject=payload.subject, body=payload.body, request_id=_request_id(request))
        db.commit()
        return _draft_response(db, c)
    except BroadcastRejected as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("", response_model=list[DraftSummary])
def history(response: Response, limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    _no_store(response)
    rows = db.scalars(select(AdminBroadcast).order_by(AdminBroadcast.created_at.desc()).limit(limit)).all()
    return [_draft_response(db, c) for c in rows]


@router.get("/{campaign_id}", response_model=DraftSummary)
def detail(campaign_id: UUID, response: Response, db: Session = Depends(get_db)):
    _no_store(response)
    c = db.get(AdminBroadcast, campaign_id)
    if c is None:
        raise HTTPException(status_code=404, detail="not_found")
    return _draft_response(db, c)


@router.post("/{campaign_id}/test")
def test_send(campaign_id: UUID, request: Request, response: Response, db: Session = Depends(get_db)):
    """Exactly one test attempt per draft, to the established private support inbox.

    Persist the attempt BEFORE handing off to SMTP, so timeout/repeat clicks cannot
    silently create multiple test emails. A failed/unknown test requires a new draft.
    """
    _no_store(response)
    c = db.scalar(select(AdminBroadcast).where(AdminBroadcast.id == campaign_id).with_for_update())
    if c is None:
        raise HTTPException(status_code=404, detail="not_found")
    if c.state != "draft" or c.test_attempted_at is not None:
        raise HTTPException(status_code=409, detail="test_already_attempted_or_not_draft")
    c.test_attempted_at = utcnow()
    record_audit_event(db, event_type="admin.broadcast.test_attempted", actor_kind="admin",
                       object_type="admin_broadcast", object_id=str(c.id),
                       request_id=_request_id(request), payload={"audience": c.audience})
    subject, body = c.subject, c.body
    db.commit()  # SMTP external write must not occur inside an open SQL transaction.
    try:
        deliver_admin_broadcast_email(to_email=SUPPORT_EMAIL, subject=subject, body=body, test=True)
    except MailDeliveryError as exc:
        record_audit_event(db, event_type="admin.broadcast.test_uncertain", actor_kind="admin",
                           object_type="admin_broadcast", object_id=str(c.id),
                           request_id=_request_id(request), payload={"failure_category": "smtp_unknown"})
        db.commit()
        raise HTTPException(status_code=503, detail="test_smtp_result_unknown") from exc
    record_audit_event(db, event_type="admin.broadcast.test_accepted", actor_kind="admin",
                       object_type="admin_broadcast", object_id=str(c.id),
                       request_id=_request_id(request), payload={})
    db.commit()
    return {"status": "smtp_accepted", "recipient": "configured_support_inbox"}


@router.post("/{campaign_id}/send", response_model=DraftSummary)
def send(campaign_id: UUID, payload: ConfirmRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    _no_store(response)
    try:
        c = confirm_send(db, campaign_id=campaign_id, expected_count=payload.confirmed_recipient_count, request_id=_request_id(request))
        db.commit()
    except BroadcastRejected as exc:
        db.rollback()
        raise HTTPException(status_code=404 if str(exc) == "not_found" else 409, detail=str(exc)) from exc
    return _draft_response(db, c)


def _transition(campaign_id: UUID, action: str, request: Request, db: Session) -> AdminBroadcast:
    c = db.scalar(select(AdminBroadcast).where(AdminBroadcast.id == campaign_id).with_for_update())
    if c is None:
        raise HTTPException(status_code=404, detail="not_found")
    if action == "pause":
        if c.state in {"queued", "sending"}:
            c.state = "paused"
        elif c.state != "paused":
            raise HTTPException(status_code=409, detail="not_running")
    else:
        if c.state != "paused":
            raise HTTPException(status_code=409, detail="not_paused")
        c.state = "queued"
    c.updated_at = utcnow()
    record_audit_event(db, event_type="admin.broadcast." + action, actor_kind="admin", object_type="admin_broadcast", object_id=str(c.id), request_id=_request_id(request), payload={"audience": c.audience, "recipient_count": c.recipient_count})
    db.commit()
    return c


@router.post("/{campaign_id}/pause", response_model=DraftSummary)
def pause(campaign_id: UUID, request: Request, response: Response, db: Session = Depends(get_db)):
    _no_store(response)
    return _draft_response(db, _transition(campaign_id, "pause", request, db))


@router.post("/{campaign_id}/resume", response_model=DraftSummary)
def resume(campaign_id: UUID, request: Request, response: Response, db: Session = Depends(get_db)):
    _no_store(response)
    return _draft_response(db, _transition(campaign_id, "resume", request, db))
