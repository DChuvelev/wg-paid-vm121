from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from app.config import settings

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
    _: None = Depends(require_dev_environment),
):
    # P22B established an empty clean business baseline and P23B activates
    # Domain V2 schema ownership. Recreating the legacy User -> Peer -> legacy
    # ProvisioningJob write path would make that retired model authoritative
    # again. Keep the route only as an explicit compatibility fence until the
    # Domain V2 onboarding/provisioning API is implemented in later phases.
    raise HTTPException(
        status_code=410,
        detail="legacy test-peer writer retired; Domain V2 provisioning is not active yet",
    )
