from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.session import get_db
from app.models import Peer, ProvisioningJob

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
    paid_until: datetime
    enabled: bool

    class Config:
        from_attributes = True


@router.get("/peers", response_model=list[AgentPeerResponse])
def get_enabled_peers(
    node_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(check_agent_token),
):
    rows = db.execute(
        select(Peer)
        .where(Peer.node_id == node_id)
        .where(Peer.enabled == True)
        .order_by(Peer.created_at.asc())
    ).scalars().all()
    return rows



class AgentJobResponse(BaseModel):
    id: UUID
    node_id: str
    action: str
    peer_id: UUID | None
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
    rows = db.execute(
        select(ProvisioningJob)
        .where(ProvisioningJob.node_id == node_id)
        .where(ProvisioningJob.status == "pending")
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
    job = db.get(ProvisioningJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.status != "pending":
        raise HTTPException(status_code=409, detail=f"job status is {job.status}")

    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
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
    job = db.get(ProvisioningJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.status not in ("pending", "running"):
        raise HTTPException(status_code=409, detail=f"job status is {job.status}")

    job.status = "completed"
    job.completed_at = datetime.now(timezone.utc)
    job.last_error = None

    db.commit()
    db.refresh(job)
    return job


@router.post("/jobs/{job_id}/fail", response_model=AgentJobResponse)
def fail_job(
    job_id: UUID,
    payload: FailRequest,
    db: Session = Depends(get_db),
    _: None = Depends(check_agent_token),
):
    job = db.get(ProvisioningJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.status not in ("pending", "running"):
        raise HTTPException(status_code=409, detail=f"job status is {job.status}")

    job.status = "failed"
    job.completed_at = datetime.now(timezone.utc)
    job.last_error = payload.error

    db.commit()
    db.refresh(job)
    return job
