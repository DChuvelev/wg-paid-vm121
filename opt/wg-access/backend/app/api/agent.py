from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.session import get_db
from app.models import ConnectionProfile, Peer, PeerCredential, ProvisioningJob
from app.services.user_deletion import finalize_user_deletion_if_ready
from app.services.credential_service import CredentialServiceError, decrypt_profile_credential
from app.services.domain_v2 import (
    DomainV2Error,
    acknowledge_profile_job,
    record_profile_job_failure,
)

router = APIRouter(prefix="/agent", tags=["agent"])


def check_agent_token(x_agent_token: str | None = Header(default=None)):
    if not x_agent_token or x_agent_token != settings.agent_token:
        raise HTTPException(status_code=401, detail="invalid agent token")


class AgentPeerResponse(BaseModel):
    id: UUID
    node_id: str
    public_key: str
    preshared_key: str
    tunnel_ip: str
    paid_until: datetime | None
    enabled: bool

    class Config:
        from_attributes = True


@router.get("/peers", response_model=list[AgentPeerResponse])
def get_enabled_peers(
    node_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(check_agent_token),
):
    result: list[AgentPeerResponse] = []

    legacy = db.execute(
        select(Peer)
        .where(Peer.node_id == node_id)
        .where(Peer.enabled == True)
        .order_by(Peer.created_at.asc())
    ).scalars().all()
    for row in legacy:
        result.append(AgentPeerResponse.model_validate(row))

    profiles = db.execute(
        select(ConnectionProfile)
        .where(ConnectionProfile.node_id == node_id)
        .where(ConnectionProfile.protocol == "wireguard")
        .where(ConnectionProfile.status.in_(("provisioning", "active")))
        .where(ConnectionProfile.tunnel_ip.is_not(None))
        .order_by(ConnectionProfile.created_at.asc())
    ).scalars().all()
    for profile in profiles:
        credential = db.execute(
            select(PeerCredential)
            .where(
                PeerCredential.connection_profile_id == profile.id,
                PeerCredential.revoked_at.is_(None),
            )
            .order_by(PeerCredential.revision.desc())
        ).scalars().first()
        if credential is None or not credential.public_key:
            raise HTTPException(status_code=409, detail="profile credential is unavailable")
        try:
            secret = decrypt_profile_credential(credential)
        except CredentialServiceError as exc:
            raise HTTPException(status_code=503, detail="profile credential decrypt failed") from exc
        psk = secret.get("preshared_key")
        if not psk:
            raise HTTPException(status_code=409, detail="profile credential PSK is unavailable")
        result.append(
            AgentPeerResponse(
                id=profile.id,
                node_id=profile.node_id,
                public_key=credential.public_key,
                preshared_key=psk,
                tunnel_ip=profile.tunnel_ip,
                paid_until=profile.expires_at,
                enabled=True,
            )
        )
    return result


class AgentJobResponse(BaseModel):
    id: UUID
    node_id: str
    action: str
    peer_id: UUID | None
    connection_profile_id: UUID | None
    operation_id: str | None
    desired_generation: str | None
    next_attempt_at: datetime | None
    payload_json: dict
    status: str
    attempts: int
    created_at: datetime

    class Config:
        from_attributes = True


class FailRequest(BaseModel):
    error: str


@router.get("/jobs", response_model=list[AgentJobResponse])
def get_pending_jobs(
    node_id: str,
    limit: int = 10,
    db: Session = Depends(get_db),
    _: None = Depends(check_agent_token),
):
    now = datetime.now(timezone.utc)
    rows = db.execute(
        select(ProvisioningJob)
        .where(ProvisioningJob.node_id == node_id)
        .where(ProvisioningJob.status == "pending")
        .where(or_(ProvisioningJob.next_attempt_at.is_(None), ProvisioningJob.next_attempt_at <= now))
        .order_by(ProvisioningJob.created_at.asc())
        .limit(limit)
    ).scalars().all()
    return rows


@router.post("/jobs/{job_id}/start", response_model=AgentJobResponse)
def start_job(
    job_id: UUID,
    db: Session = Depends(get_db),
    _: None = Depends(check_agent_token),
):
    job = db.execute(
        select(ProvisioningJob).where(ProvisioningJob.id == job_id).with_for_update()
    ).scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.status != "pending":
        raise HTTPException(status_code=409, detail=f"job status is {job.status}")
    now = datetime.now(timezone.utc)
    if job.next_attempt_at is not None and job.next_attempt_at > now:
        raise HTTPException(status_code=409, detail="job retry is not due")

    job.status = "running"
    job.started_at = now
    job.next_attempt_at = None
    job.attempts += 1
    db.commit()
    db.refresh(job)
    return job


@router.post("/jobs/{job_id}/complete", response_model=AgentJobResponse)
def complete_job(
    job_id: UUID,
    db: Session = Depends(get_db),
    _: None = Depends(check_agent_token),
):
    job = db.execute(
        select(ProvisioningJob).where(ProvisioningJob.id == job_id).with_for_update()
    ).scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.status not in ("pending", "running"):
        raise HTTPException(status_code=409, detail=f"job status is {job.status}")
    try:
        acknowledge_profile_job(db, job=job)
    except DomainV2Error as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    profile_user_id = None
    if job.connection_profile_id is not None:
        profile = db.get(ConnectionProfile, job.connection_profile_id)
        if profile is not None:
            profile_user_id = profile.user_id

    job.status = "completed"
    job.completed_at = datetime.now(timezone.utc)
    job.next_attempt_at = None
    job.last_error = None
    db.commit()
    db.refresh(job)
    response = AgentJobResponse.model_validate(job)

    if profile_user_id is not None:
        if finalize_user_deletion_if_ready(db, user_id=profile_user_id):
            db.commit()
        else:
            db.rollback()
    return response


@router.post("/jobs/{job_id}/fail", response_model=AgentJobResponse)
def fail_job(
    job_id: UUID,
    payload: FailRequest,
    db: Session = Depends(get_db),
    _: None = Depends(check_agent_token),
):
    job = db.execute(
        select(ProvisioningJob).where(ProvisioningJob.id == job_id).with_for_update()
    ).scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.status not in ("pending", "running"):
        raise HTTPException(status_code=409, detail=f"job status is {job.status}")

    retried = record_profile_job_failure(db, job=job, error_text=payload.error)
    if job.connection_profile_id is None:
        job.status = "failed"
        job.completed_at = datetime.now(timezone.utc)
        job.last_error = str(payload.error or "agent failure")[:1000]
    elif not retried:
        job.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(job)
    return job
