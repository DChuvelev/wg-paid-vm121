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


def wireguard_client_pool() -> tuple[ipaddress.IPv4Network, ipaddress.IPv4Address]:
    """Return the canonical WireGuard client pool configured for this backend.

    Domain V2 and the legacy allocator intentionally share these exact settings.
    """
    pool_cidr = os.environ.get("WG_CLIENT_POOL_CIDR", "10.253.0.0/16").strip()
    first_client_ip = os.environ.get("WG_CLIENT_FIRST_IP", "10.253.1.10").strip()
    pool = ipaddress.ip_network(pool_cidr, strict=False)
    first_ip = ipaddress.ip_address(first_client_ip)
    if pool.version != 4 or first_ip.version != 4:
        raise RuntimeError("WireGuard client pool must be IPv4")
    if first_ip not in pool:
        raise RuntimeError(f"WG_CLIENT_FIRST_IP {first_client_ip} is outside {pool_cidr}")
    if first_ip >= pool.broadcast_address:
        raise RuntimeError("WG_CLIENT_FIRST_IP leaves no usable client addresses")
    return pool, first_ip


def iter_wireguard_client_ips():
    pool, current = wireguard_client_pool()
    last_ip = pool.broadcast_address - 1
    while current <= last_ip:
        yield str(current)
        current += 1


def next_tunnel_ip(db: Session, node_id: str) -> str:
    # Legacy allocator retained for compatibility. It now consumes the same
    # pool iterator as Domain V2, so the pool boundary is defined only once.
    used = set(
        db.execute(
            select(Peer.tunnel_ip).where(
                Peer.node_id == node_id,
                Peer.enabled.is_(True),
            )
        ).scalars().all()
    )
    for ip_text in iter_wireguard_client_ips():
        if ip_text not in used:
            return ip_text
    pool, _ = wireguard_client_pool()
    raise RuntimeError(f"No free tunnel IPs left in pool {pool}")


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
