from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.config import settings
from app.db.session import get_db
from app.models import User, Peer, ProvisioningJob
from app.services.wireguard import (
    generate_wg_keypair,
    generate_wg_psk,
    next_tunnel_ip,
    build_client_config,
)

router = APIRouter(prefix="/dev", tags=["dev"])

def require_dev_environment():
    if settings.environment != "dev":
        raise HTTPException(status_code=404, detail="not found")



class TestPeerRequest(BaseModel):
    email: EmailStr | None = None
    months: int = 2
    node_id: str = "ddn-test"


class TestPeerResponse(BaseModel):
    user_id: UUID
    peer_id: UUID
    job_id: UUID
    tunnel_ip: str
    paid_until: datetime
    private_key: str
    public_key: str
    preshared_key: str
    client_config: str


@router.post("/create-test-peer", response_model=TestPeerResponse)
def create_test_peer(
    payload: TestPeerRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_dev_environment),
):
    # Dev-only endpoint.
    # It intentionally mirrors the minimal old behavior but now uses shared WG helpers.
    # The private key is returned once and is not stored in DB.
    user = User(email=payload.email)
    db.add(user)
    db.flush()

    paid_until = datetime.now(timezone.utc) + timedelta(days=30 * payload.months)
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
    db.refresh(peer)
    db.refresh(job)

    return TestPeerResponse(
        user_id=user.id,
        peer_id=peer.id,
        job_id=job.id,
        tunnel_ip=peer.tunnel_ip,
        paid_until=peer.paid_until,
        private_key=private_key,
        public_key=peer.public_key,
        preshared_key=peer.preshared_key,
        client_config=client_config,
    )
