import base64
import ipaddress
import os
import secrets

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Peer


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def generate_wg_keypair() -> tuple[str, str]:
    # WireGuard-compatible X25519 private scalar.
    private_raw = bytearray(secrets.token_bytes(32))
    private_raw[0] &= 248
    private_raw[31] &= 127
    private_raw[31] |= 64
    private_raw = bytes(private_raw)

    private_key = x25519.X25519PrivateKey.from_private_bytes(private_raw)
    public_key = private_key.public_key()

    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return b64(private_raw), b64(public_raw)


def generate_wg_psk() -> str:
    return b64(secrets.token_bytes(32))


def next_tunnel_ip(db: Session, node_id: str) -> str:
    # MVP allocator:
    # - pool is /16 by default: 10.253.0.0/16
    # - client addresses start at 10.253.1.10
    # - only enabled peers reserve addresses
    # - disabled peers keep history but their addresses can be reused
    pool_cidr = os.environ.get("WG_CLIENT_POOL_CIDR", "10.253.0.0/16").strip()
    first_client_ip = os.environ.get("WG_CLIENT_FIRST_IP", "10.253.1.10").strip()

    pool = ipaddress.ip_network(pool_cidr, strict=False)
    first_ip = ipaddress.ip_address(first_client_ip)

    if first_ip not in pool:
        raise RuntimeError(f"WG_CLIENT_FIRST_IP {first_client_ip} is outside {pool_cidr}")

    used = set(
        db.execute(
            select(Peer.tunnel_ip).where(
                Peer.node_id == node_id,
                Peer.enabled.is_(True),
            )
        ).scalars().all()
    )

    current = first_ip
    last_ip = pool.broadcast_address - 1

    while current <= last_ip:
        ip_text = str(current)
        if ip_text not in used:
            return ip_text
        current += 1

    raise RuntimeError(f"No free tunnel IPs left in pool {pool_cidr}")


def build_client_config(private_key: str, tunnel_ip: str, preshared_key: str) -> str:
    server_public_key = os.environ.get("WG_SERVER_PUBLIC_KEY", "").strip()
    endpoint = os.environ.get("WG_CLIENT_ENDPOINT", "").strip()
    allowed_ips = os.environ.get("WG_CLIENT_ALLOWED_IPS", "10.253.1.1/32").strip()
    dns = os.environ.get("WG_CLIENT_DNS", "").strip()

    if not server_public_key:
        raise RuntimeError("WG_SERVER_PUBLIC_KEY is not configured")
    if not endpoint:
        raise RuntimeError("WG_CLIENT_ENDPOINT is not configured")

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {tunnel_ip}/32",
    ]

    if dns:
        lines.append(f"DNS = {dns}")

    lines.extend([
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        f"PresharedKey = {preshared_key}",
        f"Endpoint = {endpoint}",
        f"AllowedIPs = {allowed_ips}",
        "PersistentKeepalive = 25",
        "",
    ])

    return "\n".join(lines)
