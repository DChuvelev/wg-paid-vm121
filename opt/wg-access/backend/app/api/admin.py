from datetime import datetime, timezone, timedelta
from uuid import UUID
import secrets
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import InviteCode, User, Subscription, Peer, ProvisioningJob
from app.services.wireguard import (
    generate_wg_keypair,
    generate_wg_psk,
    next_tunnel_ip,
    build_client_config,
)
from app.agent_trigger import trigger_wg_access_agent_best_effort  # STEP_042C2_AGENT_EVENT_TRIGGER_IMPORT

router = APIRouter(prefix="/admin", tags=["admin"])


class InviteCreateRequest(BaseModel):
    note: str | None = None
    max_uses: int = 1


class InviteResponse(BaseModel):
    id: UUID
    code: str
    note: str | None
    max_uses: int
    used_count: int
    active: bool
    created_at: datetime

    class Config:
        from_attributes = True


@router.post("/invites", response_model=InviteResponse)
def create_invite(payload: InviteCreateRequest, db: Session = Depends(get_db)):
    code = "INV-" + secrets.token_urlsafe(12).replace("-", "").replace("_", "")[:16].upper()
    invite = InviteCode(
        code=code,
        note=payload.note,
        max_uses=payload.max_uses,
        used_count=0,
        active=True,
    )
    db.add(invite)
    db.commit()
    trigger_wg_access_agent_best_effort()  # STEP_042C2_AGENT_TRIGGER_AFTER_COMMIT
    db.refresh(invite)
    return invite


@router.get("/invites", response_model=list[InviteResponse])
def list_invites(db: Session = Depends(get_db)):
    rows = db.execute(select(InviteCode).order_by(InviteCode.created_at.desc())).scalars().all()
    return rows


class PeerResponse(BaseModel):
    id: UUID
    user_id: UUID
    node_id: str
    public_key: str
    tunnel_ip: str
    paid_until: datetime
    enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/peers", response_model=list[PeerResponse])
def list_peers(db: Session = Depends(get_db)):
    rows = db.execute(select(Peer).order_by(Peer.created_at.desc())).scalars().all()
    return rows



class SubscriptionCreateRequest(BaseModel):
    email: EmailStr | None = None
    months: int = Field(default=1, ge=1, le=36)
    plan_code: str = "manual"
    node_id: str = "ddn-test"
    auto_renew: bool = False


class SubscriptionCreateResponse(BaseModel):
    user_id: UUID
    subscription_id: UUID
    peer_id: UUID
    job_id: UUID
    node_id: str
    tunnel_ip: str
    paid_until: datetime
    private_key: str
    public_key: str
    preshared_key: str
    client_config: str


@router.post("/subscriptions", response_model=SubscriptionCreateResponse)
def create_subscription(payload: SubscriptionCreateRequest, db: Session = Depends(get_db)):
    # MVP admin/manual subscription endpoint.
    # It creates a user, an active subscription, a WG peer and a pending enable_peer job.
    # The private key is intentionally returned once and not stored in DB.
    paid_until = datetime.now(timezone.utc) + timedelta(days=30 * payload.months)

    user = User(email=payload.email)
    db.add(user)
    db.flush()

    subscription = Subscription(
        user_id=user.id,
        status="active",
        plan_code=payload.plan_code,
        auto_renew=payload.auto_renew,
        paid_until=paid_until,
    )
    db.add(subscription)
    db.flush()

    tunnel_ip = next_tunnel_ip(db, payload.node_id)
    private_key, public_key = generate_wg_keypair()
    preshared_key = generate_wg_psk()
    client_config = build_client_config(private_key, tunnel_ip, preshared_key)

    peer = Peer(
        user_id=user.id,
        node_id=payload.node_id,
        public_key=public_key,
        preshared_key=preshared_key,
        tunnel_ip=tunnel_ip,
        paid_until=paid_until,
        enabled=True,
    )
    db.add(peer)
    db.flush()

    job = ProvisioningJob(
        node_id=payload.node_id,
        action="enable_peer",
        peer_id=peer.id,
        payload_json={
            "public_key": peer.public_key,
            "preshared_key": peer.preshared_key,
            "tunnel_ip": peer.tunnel_ip,
            "paid_until": peer.paid_until.isoformat(),
        },
        status="pending",
        attempts=0,
    )
    db.add(job)

    db.commit()
    trigger_wg_access_agent_best_effort()  # STEP_042C2_AGENT_TRIGGER_AFTER_COMMIT
    db.refresh(subscription)
    db.refresh(peer)
    db.refresh(job)

    return SubscriptionCreateResponse(
        user_id=user.id,
        subscription_id=subscription.id,
        peer_id=peer.id,
        job_id=job.id,
        node_id=peer.node_id,
        tunnel_ip=peer.tunnel_ip,
        paid_until=peer.paid_until,
        private_key=private_key,
        public_key=peer.public_key,
        preshared_key=peer.preshared_key,
        client_config=client_config,
    )




class ExpireSubscriptionsResponse(BaseModel):
    expired_subscription_count: int
    disabled_peer_count: int
    job_ids: list[UUID]
    subscription_ids: list[UUID]


@router.post("/maintenance/expire-subscriptions", response_model=ExpireSubscriptionsResponse)
def expire_subscriptions(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)

    expired_subscriptions = db.execute(
        select(Subscription)
        .where(Subscription.status == "active")
        .where(Subscription.paid_until <= now)
        .order_by(Subscription.paid_until.asc())
    ).scalars().all()

    jobs = []
    disabled_peer_count = 0

    for subscription in expired_subscriptions:
        subscription.status = "expired"
        subscription.auto_renew = False

        enabled_peers = db.execute(
            select(Peer)
            .where(Peer.user_id == subscription.user_id)
            .where(Peer.enabled == True)  # noqa: E712
            .order_by(Peer.created_at.desc())
        ).scalars().all()

        for peer in enabled_peers:
            peer.enabled = False
            peer.disabled_at = now
            disabled_peer_count += 1

            job = ProvisioningJob(
                node_id=peer.node_id,
                action="disable_peer",
                peer_id=peer.id,
                payload_json={
                    "public_key": peer.public_key,
                    "tunnel_ip": peer.tunnel_ip,
                },
                status="pending",
                attempts=0,
            )
            db.add(job)
            jobs.append(job)

    db.commit()
    trigger_wg_access_agent_best_effort()  # STEP_042C2_AGENT_TRIGGER_AFTER_COMMIT

    for job in jobs:
        db.refresh(job)

    return ExpireSubscriptionsResponse(
        expired_subscription_count=len(expired_subscriptions),
        disabled_peer_count=disabled_peer_count,
        job_ids=[job.id for job in jobs],
        subscription_ids=[subscription.id for subscription in expired_subscriptions],
    )


class CancelSubscriptionResponse(BaseModel):
    subscription_id: UUID
    user_id: UUID
    status: str
    canceled_at: datetime | None
    disabled_peer_count: int
    job_ids: list[UUID]


@router.post("/subscriptions/{subscription_id}/cancel", response_model=CancelSubscriptionResponse)
def cancel_subscription(subscription_id: UUID, db: Session = Depends(get_db)):
    subscription = db.get(Subscription, subscription_id)
    if not subscription:
        raise HTTPException(status_code=404, detail="subscription not found")

    now = datetime.now(timezone.utc)

    # Idempotent business-level cancel:
    # cancel subscription once, then disable any currently enabled peers for this user.
    subscription.status = "canceled"
    subscription.auto_renew = False
    if subscription.canceled_at is None:
        subscription.canceled_at = now

    enabled_peers = db.execute(
        select(Peer)
        .where(Peer.user_id == subscription.user_id)
        .where(Peer.enabled == True)  # noqa: E712
        .order_by(Peer.created_at.desc())
    ).scalars().all()

    jobs = []
    for peer in enabled_peers:
        peer.enabled = False
        peer.disabled_at = now

        job = ProvisioningJob(
            node_id=peer.node_id,
            action="disable_peer",
            peer_id=peer.id,
            payload_json={
                "public_key": peer.public_key,
                "tunnel_ip": peer.tunnel_ip,
            },
            status="pending",
            attempts=0,
        )
        db.add(job)
        jobs.append(job)

    db.commit()
    trigger_wg_access_agent_best_effort()  # STEP_042C2_AGENT_TRIGGER_AFTER_COMMIT
    db.refresh(subscription)
    for job in jobs:
        db.refresh(job)

    return CancelSubscriptionResponse(
        subscription_id=subscription.id,
        user_id=subscription.user_id,
        status=subscription.status,
        canceled_at=subscription.canceled_at,
        disabled_peer_count=len(enabled_peers),
        job_ids=[job.id for job in jobs],
    )


class DisablePeerResponse(BaseModel):
    peer_id: UUID
    job_id: UUID
    node_id: str
    public_key: str
    tunnel_ip: str
    enabled: bool


@router.post("/peers/{peer_id}/disable", response_model=DisablePeerResponse)
def disable_peer(peer_id: UUID, db: Session = Depends(get_db)):
    peer = db.get(Peer, peer_id)
    if not peer:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="peer not found")

    peer.enabled = False
    peer.disabled_at = datetime.now(timezone.utc)

    job = ProvisioningJob(
        node_id=peer.node_id,
        action="disable_peer",
        peer_id=peer.id,
        payload_json={
            "public_key": peer.public_key,
            "tunnel_ip": peer.tunnel_ip,
        },
        status="pending",
        attempts=0,
    )
    db.add(job)
    db.commit()
    trigger_wg_access_agent_best_effort()  # STEP_042C2_AGENT_TRIGGER_AFTER_COMMIT
    db.refresh(peer)
    db.refresh(job)

    return DisablePeerResponse(
        peer_id=peer.id,
        job_id=job.id,
        node_id=peer.node_id,
        public_key=peer.public_key,
        tunnel_ip=peer.tunnel_ip,
        enabled=peer.enabled,
    )



class JobResponse(BaseModel):
    id: UUID
    node_id: str
    action: str
    status: str
    attempts: int
    created_at: datetime
    last_error: str | None

    class Config:
        from_attributes = True


@router.get("/jobs", response_model=list[JobResponse])
def list_jobs(db: Session = Depends(get_db)):
    rows = db.execute(select(ProvisioningJob).order_by(ProvisioningJob.created_at.desc())).scalars().all()
    return rows


class AdminSubscriptionResponse(BaseModel):
    id: UUID
    user_id: UUID
    status: str
    plan_code: str
    auto_renew: bool
    paid_until: datetime
    created_at: datetime
    canceled_at: datetime | None

    class Config:
        from_attributes = True


class AdminUserPeerResponse(BaseModel):
    id: UUID
    user_id: UUID
    node_id: str
    public_key: str
    tunnel_ip: str
    paid_until: datetime
    enabled: bool
    created_at: datetime
    disabled_at: datetime | None

    class Config:
        from_attributes = True


class AdminUserJobResponse(BaseModel):
    id: UUID
    node_id: str
    action: str
    peer_id: UUID | None
    status: str
    attempts: int
    created_at: datetime
    last_error: str | None

    class Config:
        from_attributes = True


class AdminUserSummaryResponse(BaseModel):
    id: UUID
    email: str | None
    created_at: datetime
    subscriptions_count: int
    peers_count: int
    enabled_peers_count: int

    class Config:
        from_attributes = True


class AdminUserDetailResponse(BaseModel):
    id: UUID
    email: str | None
    created_at: datetime
    subscriptions: list[AdminSubscriptionResponse]
    peers: list[AdminUserPeerResponse]
    jobs: list[AdminUserJobResponse]


@router.get("/users", response_model=list[AdminUserSummaryResponse])
def list_users(db: Session = Depends(get_db)):
    users = db.execute(select(User).order_by(User.created_at.desc())).scalars().all()

    result = []
    for user in users:
        subscriptions = db.execute(
            select(Subscription).where(Subscription.user_id == user.id)
        ).scalars().all()

        peers = db.execute(
            select(Peer).where(Peer.user_id == user.id)
        ).scalars().all()

        result.append(AdminUserSummaryResponse(
            id=user.id,
            email=user.email,
            created_at=user.created_at,
            subscriptions_count=len(subscriptions),
            peers_count=len(peers),
            enabled_peers_count=len([p for p in peers if p.enabled]),
        ))

    return result


def build_admin_user_detail(user: User, db: Session) -> AdminUserDetailResponse:
    subscriptions = db.execute(
        select(Subscription)
        .where(Subscription.user_id == user.id)
        .order_by(Subscription.created_at.desc())
    ).scalars().all()

    peers = db.execute(
        select(Peer)
        .where(Peer.user_id == user.id)
        .order_by(Peer.created_at.desc())
    ).scalars().all()

    peer_ids = [p.id for p in peers]
    if peer_ids:
        jobs = db.execute(
            select(ProvisioningJob)
            .where(ProvisioningJob.peer_id.in_(peer_ids))
            .order_by(ProvisioningJob.created_at.desc())
        ).scalars().all()
    else:
        jobs = []

    return AdminUserDetailResponse(
        id=user.id,
        email=user.email,
        created_at=user.created_at,
        subscriptions=subscriptions,
        peers=peers,
        jobs=jobs,
    )


@router.get("/users/by-email/{email}", response_model=AdminUserDetailResponse)
def get_user_by_email(email: str, db: Session = Depends(get_db)):
    decoded_email = unquote(email)

    user = db.execute(
        select(User)
        .where(User.email == decoded_email)
        .order_by(User.created_at.desc())
    ).scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="user not found")

    return build_admin_user_detail(user, db)


@router.get("/users/{user_id}", response_model=AdminUserDetailResponse)
def get_user(user_id: UUID, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")

    return build_admin_user_detail(user, db)
