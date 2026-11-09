"""Private Admin diagnostic capture API. This module NEVER invokes SSH or shell."""
from __future__ import annotations

from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.auth_v2 import _require_admin, _request_id
from app.services.domain_v2 import record_audit_event
from app.services.admin_diagnostics import enqueue, get_visible, READY_STATES, utcnow, is_past
from hashlib import sha256

router = APIRouter(prefix="/v2/admin/diagnostics", tags=["admin-diagnostics"], dependencies=[Depends(_require_admin)])


class JobPublic(BaseModel):
    request_id: UUID
    state: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    expires_at: datetime
    capture_status: str | None
    error_code: str | None
    artifact_size: int | None


def _public(job) -> JobPublic:
    return JobPublic(
        request_id=job.id, state=job.state, created_at=job.created_at,
        started_at=job.started_at, completed_at=job.completed_at,
        expires_at=job.expires_at, capture_status=job.capture_status,
        error_code=job.error_code, artifact_size=job.artifact_size,
    )


def _private_headers(response: Response) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"


@router.post("", response_model=JobPublic)
def create(request: Request, response: Response, db: Session = Depends(get_db)):
    job, created = enqueue(db)
    record_audit_event(db, event_type="admin.diagnostics.request", actor_kind="admin",
                       object_type="admin_diagnostic_job", object_id=str(job.id),
                       request_id=_request_id(request), payload={"created": created})
    db.commit()
    response.status_code = 202 if created else 200
    _private_headers(response)
    return _public(job)


@router.get("/{request_id}", response_model=JobPublic)
def status(request_id: UUID, response: Response, db: Session = Depends(get_db)):
    _private_headers(response)
    job = get_visible(db, request_id)
    if job is None:
        raise HTTPException(status_code=404, detail="not_found")
    out = _public(job)
    if out.state in READY_STATES and is_past(out.expires_at, utcnow()):
        out.state = "expired"
        out.artifact_size = None
    return out


@router.get("/{request_id}/download")
def download(request_id: UUID, request: Request, db: Session = Depends(get_db)):
    job = get_visible(db, request_id)
    if job is None:
        raise HTTPException(status_code=404, detail="not_found")
    if job.state == "expired" or (job.state in READY_STATES and is_past(job.expires_at, utcnow())):
        raise HTTPException(status_code=410, detail="expired")
    if job.state not in READY_STATES:
        raise HTTPException(status_code=409, detail="not_ready")
    payload = bytes(job.artifact or b"")
    if len(payload) != job.artifact_size or sha256(payload).hexdigest() != job.artifact_sha256:
        raise HTTPException(status_code=503, detail="integrity_failure")
    record_audit_event(db, event_type="admin.diagnostics.download", actor_kind="admin",
                       object_type="admin_diagnostic_job", object_id=str(job.id),
                       request_id=_request_id(request),
                       payload={"bytes": len(payload), "capture_status": job.capture_status})
    db.commit()
    return Response(
        content=payload, media_type="application/zip",
        headers={
            "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff",
            "Content-Disposition": f'attachment; filename="WG_PAID_MGTS_DIAGNOSTICS_{job.id.hex}.zip"',
        },
    )
