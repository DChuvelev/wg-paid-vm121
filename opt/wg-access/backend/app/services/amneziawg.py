from __future__ import annotations

import ipaddress
import os


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is not configured")
    return value


def amneziawg_client_pool() -> tuple[ipaddress.IPv4Network, ipaddress.IPv4Address]:
    pool_cidr = _required("AWG_CLIENT_POOL_CIDR")
    first_client_ip = _required("AWG_CLIENT_FIRST_IP")
    pool = ipaddress.ip_network(pool_cidr, strict=False)
    first_ip = ipaddress.ip_address(first_client_ip)
    if pool.version != 4 or first_ip.version != 4:
        raise RuntimeError("AmneziaWG client pool must be IPv4")
    if first_ip not in pool:
        raise RuntimeError(f"AWG_CLIENT_FIRST_IP {first_client_ip} is outside {pool_cidr}")
    if first_ip >= pool.broadcast_address:
        raise RuntimeError("AWG_CLIENT_FIRST_IP leaves no usable client addresses")
    return pool, first_ip


def iter_amneziawg_client_ips():
    pool, current = amneziawg_client_pool()
    last_ip = pool.broadcast_address - 1
    while current <= last_ip:
        yield str(current)
        current += 1


def build_client_config(private_key: str, tunnel_ip: str, preshared_key: str) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {tunnel_ip}/32",
        f"DNS = {_required('AWG_CLIENT_DNS')}",
        f"MTU = {_required('AWG_CLIENT_MTU')}",
        f"Jc = {_required('AWG_JC')}",
        f"Jmin = {_required('AWG_JMIN')}",
        f"Jmax = {_required('AWG_JMAX')}",
        f"S1 = {_required('AWG_S1')}",
        f"S2 = {_required('AWG_S2')}",
        f"S3 = {_required('AWG_S3')}",
        f"S4 = {_required('AWG_S4')}",
        f"H1 = {_required('AWG_H1')}",
        f"H2 = {_required('AWG_H2')}",
        f"H3 = {_required('AWG_H3')}",
        f"H4 = {_required('AWG_H4')}",
        f"I1 = {_required('AWG_I1')}",
        f"HeaderProtectionKey = {_required('AWG_HEADER_PROTECTION_KEY')}",
        f"RekeyAfterTime = {_required('AWG_REKEY_AFTER_TIME')}",
        f"RekeyTimeout = {_required('AWG_REKEY_TIMEOUT')}",
        f"RejectAfterTime = {_required('AWG_REJECT_AFTER_TIME')}",
        f"KeepaliveTimeout = {_required('AWG_KEEPALIVE_TIMEOUT')}",
        f"MaxHandshakeAttempts = {_required('AWG_MAX_HANDSHAKE_ATTEMPTS')}",
        f"RandomTrailers = {_required('AWG_RANDOM_TRAILERS')}",
        f"DisableCookies = {_required('AWG_DISABLE_COOKIES')}",
        "",
        "[Peer]",
        f"PublicKey = {_required('AWG_SERVER_PUBLIC_KEY')}",
        f"PresharedKey = {preshared_key}",
        f"Endpoint = {_required('AWG_CLIENT_ENDPOINT')}",
        f"AllowedIPs = {_required('AWG_CLIENT_ALLOWED_IPS')}",
        f"PersistentKeepalive = {_required('AWG_PERSISTENT_KEEPALIVE')}",
        "",
    ]
    return "\n".join(lines)
