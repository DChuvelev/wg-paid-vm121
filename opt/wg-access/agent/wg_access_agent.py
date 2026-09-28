#!/usr/bin/env python3

import hashlib
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from urllib import request, parse, error


WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_env(path):
    env = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


ENV_PATH = os.environ.get("WG_ACCESS_AGENT_ENV", "/opt/wg-access/agent/agent.env")
env = load_env(ENV_PATH)

BACKEND_URL = env["BACKEND_URL"].rstrip("/")
NODE_ID = env["NODE_ID"]
AGENT_TOKEN = env["AGENT_TOKEN"]
STATE_FILE = Path(env["STATE_FILE"])
LOG_FILE = Path(env["LOG_FILE"])

REMOTE_HOST = env["REMOTE_HOST"]
REMOTE_USER = env.get("REMOTE_USER", "root")
REMOTE_SSH_KEY = env["REMOTE_SSH_KEY"]
REMOTE_LIFECYCLE_COMMAND = env.get(
    "REMOTE_LIFECYCLE_COMMAND",
    "/usr/local/sbin/router-wgpay-peer-lifecycle.sh",
)
REMOTE_REGISTRY_FILE = env.get(
    "REMOTE_REGISTRY_FILE",
    "/etc/router-wgpay-peer-state/registry.tsv",
)
REMOTE_FORCED_EGRESS_COMMAND = env.get(
    "REMOTE_FORCED_EGRESS_COMMAND",
    "/usr/local/sbin/router-wgpay-forced-egress.sh",
)
MANAGED_PROTOCOLS = ("wireguard", "amneziawg")
ROUTING_OVERRIDE_PREFIX = "cfg:"


def log(msg):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    line = f"[{utc_now()}] {msg}"
    print(line)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def http_json(method, path, payload=None):
    url = BACKEND_URL + path
    data = None
    headers = {
        "X-Agent-Token": AGENT_TOKEN,
        "Accept": "application/json",
    }

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(url, data=data, headers=headers, method=method)

    try:
        with request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else None
    except error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} {url}: {body}") from e


def load_state():
    if not STATE_FILE.exists():
        return {
            "node_id": NODE_ID,
            "updated_at": None,
            "peers": {},
        }
    with STATE_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise RuntimeError("invalid agent state")
    return data


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    state["node_id"] = NODE_ID
    state["updated_at"] = utc_now()

    safe_peers = {}
    for public_key, row in (state.get("peers") or {}).items():
        if not isinstance(row, dict):
            continue
        safe_peers[public_key] = {
            k: v
            for k, v in row.items()
            if k not in {"preshared_key", "private_key", "client_config"}
        }
    state["peers"] = safe_peers

    tmp = STATE_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    os.chmod(tmp, 0o600)
    tmp.replace(STATE_FILE)


def require_wg_key(name, value):
    if not isinstance(value, str) or not WG_KEY_RE.match(value):
        raise RuntimeError(f"invalid WireGuard key in {name}")
    return value


def require_tunnel_ip(value):
    ip = ipaddress.ip_address(str(value))
    if ip.version != 4:
        raise RuntimeError("only IPv4 tunnel_ip is supported")
    return str(ip)


def require_protocol(value, *, expected=None):
    protocol = str(value or "").strip()
    if protocol not in MANAGED_PROTOCOLS:
        raise RuntimeError(f"unsupported managed protocol: {protocol or 'missing'}")
    if expected is not None and protocol != expected:
        raise RuntimeError(
            f"backend protocol mismatch expected={expected} actual={protocol}"
        )
    return protocol


def normalize_peer_payload(peer, *, expected_protocol):
    protocol = require_protocol(peer.get("protocol"), expected=expected_protocol)
    public_key = require_wg_key("public_key", peer["public_key"])
    preshared_key = require_wg_key("preshared_key", peer["preshared_key"])
    tunnel_ip = require_tunnel_ip(peer["tunnel_ip"])

    peer_id = str(peer.get("id") or peer.get("peer_id") or "")
    if not peer_id:
        raise RuntimeError("peer id is required")

    return {
        "id": peer_id,
        "node_id": peer.get("node_id", NODE_ID),
        "protocol": protocol,
        "public_key": public_key,
        "preshared_key": preshared_key,
        "tunnel_ip": tunnel_ip,
        "allowed_ips": f"{tunnel_ip}/32",
        "paid_until": peer.get("paid_until"),
        "enabled": bool(peer.get("enabled", True)),
    }


def remote_command(script, stdin_text=None, *, log_output=True):
    cmd = [
        "ssh",
        "-i", REMOTE_SSH_KEY,
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        f"{REMOTE_USER}@{REMOTE_HOST}",
        script,
    ]

    res = subprocess.run(
        cmd,
        input=(stdin_text.encode("utf-8") if stdin_text is not None else None),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=45,
        check=False,
    )

    stdout = res.stdout.decode("utf-8", errors="replace").strip()
    stderr = res.stderr.decode("utf-8", errors="replace").strip()

    if log_output and stdout:
        log(f"remote stdout: {stdout}")
    if log_output and stderr:
        log(f"remote stderr: {stderr}")

    if res.returncode != 0:
        raise RuntimeError(
            f"remote command failed rc={res.returncode}: {stderr or stdout}"
        )

    return stdout


LIFECYCLE_LOCK_RETRY_DELAYS_SEC = (0.2, 0.4, 0.8, 1.2, 1.8, 2.6)
LIFECYCLE_LOCK_RC_MARKER = "remote command failed rc=75:"
LIFECYCLE_LOCK_RESULT_MARKER = "RESULT=NOOP_PEER_LIFECYCLE_LOCKED"


def remote_lifecycle_command(script, stdin_text, *, operation):
    max_attempts = len(LIFECYCLE_LOCK_RETRY_DELAYS_SEC) + 1
    for attempt in range(1, max_attempts + 1):
        try:
            return remote_command(script, stdin_text)
        except RuntimeError as exc:
            message = str(exc)
            lock_contention = (
                LIFECYCLE_LOCK_RC_MARKER in message
                and LIFECYCLE_LOCK_RESULT_MARKER in message
            )
            if not lock_contention or attempt >= max_attempts:
                raise

            delay = LIFECYCLE_LOCK_RETRY_DELAYS_SEC[attempt - 1]
            log(
                "VM100 lifecycle lock contention "
                f"operation={operation} attempt={attempt}/{max_attempts} "
                f"retry_in={delay:.1f}s"
            )
            time.sleep(delay)

    raise RuntimeError("unreachable lifecycle retry state")


def desired_generation(peer):
    material = "|".join([
        str(peer["id"]),
        peer["protocol"],
        peer["public_key"],
        peer["tunnel_ip"],
        str(peer.get("paid_until") or ""),
        "1" if peer.get("enabled", True) else "0",
    ]).encode("utf-8")
    return str(int.from_bytes(hashlib.sha256(material).digest()[:8], "big"))


def operation_id(action, peer, profile_id):
    material = "|".join([
        action,
        str(peer["id"]),
        profile_id,
        peer["public_key"],
        peer["tunnel_ip"],
        desired_generation(peer),
    ]).encode("utf-8")
    suffix = hashlib.sha256(material).hexdigest()[:10]
    prefix = "sync-enable" if action == "enable" else "sync-disable"
    return f"{prefix}-{profile_id}-{suffix}"[:80]


def parse_registry(text):
    rows = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 10:
            raise RuntimeError("invalid VM100 lifecycle registry row")
        rows.append({
            "profile_id": parts[0],
            "protocol": parts[1],
            "interface": parts[2],
            "public_key": parts[3],
            "tunnel_ip": parts[4],
            "normal_selector": parts[5],
            "active_selector": parts[6],
            "desired_generation": parts[7],
            "created_epoch": parts[8],
            "updated_epoch": parts[9],
        })
    return rows


def remote_registry():
    command = "cat " + shlex.quote(REMOTE_REGISTRY_FILE)
    return parse_registry(remote_command(command, log_output=False))


def find_registry_profile(peer, rows):
    key_rows = [row for row in rows if row["public_key"] == peer["public_key"]]
    ip_rows = [row for row in rows if row["tunnel_ip"] == peer["tunnel_ip"]]

    if not key_rows and not ip_rows:
        return None

    if len(key_rows) != 1 or len(ip_rows) != 1 or key_rows[0] is not ip_rows[0]:
        raise RuntimeError(
            f"VM100 registry conflict for peer_id={peer['id']} tunnel_ip={peer['tunnel_ip']}"
        )

    row = key_rows[0]
    if row["protocol"] != peer["protocol"]:
        raise RuntimeError(
            f"VM100 registry protocol conflict for peer_id={peer['id']}"
        )
    return row


def lifecycle_enable_or_ensure(peer, registry_rows=None):
    rows = remote_registry() if registry_rows is None else registry_rows
    existing = find_registry_profile(peer, rows)
    if existing is None:
        profile_id = peer["id"]
        mode = "--enable"
    else:
        profile_id = existing["profile_id"]
        mode = "--ensure"

    op_id = operation_id("enable", peer, profile_id)
    generation = desired_generation(peer)
    stdin_text = "\n".join([
        op_id,
        profile_id,
        peer["protocol"],
        peer["public_key"],
        peer["tunnel_ip"],
        generation,
        peer["preshared_key"],
        "",
    ])

    script = r'''set -eu
umask 077
req="$(mktemp /tmp/wg_access_lifecycle_req.XXXXXX)"
psk="$(mktemp /tmp/wg_access_lifecycle_psk.XXXXXX)"
trap 'rm -f "$req" "$psk"' EXIT INT TERM
IFS= read -r operation_id
IFS= read -r profile_id
IFS= read -r protocol
IFS= read -r public_key
IFS= read -r tunnel_ip
IFS= read -r desired_generation
IFS= read -r preshared_key
{
  echo "operation_id=$operation_id"
  echo "profile_id=$profile_id"
  echo "protocol=$protocol"
  echo "public_key=$public_key"
  echo "tunnel_ip=$tunnel_ip"
  echo "desired_generation=$desired_generation"
} > "$req"
printf '%s\n' "$preshared_key" > "$psk"
''' + shlex.quote(REMOTE_LIFECYCLE_COMMAND) + " " + mode + ' "$req" "$psk"\n'

    out = remote_lifecycle_command(
        script,
        stdin_text,
        operation=f"{mode} peer_id={peer['id']} tunnel_ip={peer['tunnel_ip']}",
    )
    accepted = (
        "RESULT=PASS_PEER_ENABLE" in out
        or "RESULT=PASS_PEER_RUNTIME_ENSURE" in out
        or "result=PASS_PEER_ENABLE" in out
    )
    if not accepted:
        raise RuntimeError(
            f"VM100 lifecycle {mode} did not return an accepted result"
        )
    return profile_id, mode


def lifecycle_disable_profile(profile_id, *, reason_seed):
    generation_material = f"{profile_id}|{reason_seed}|disable".encode("utf-8")
    generation = str(
        int.from_bytes(hashlib.sha256(generation_material).digest()[:8], "big")
    )
    suffix = hashlib.sha256(generation_material).hexdigest()[:10]
    operation = f"sync-disable-{profile_id}-{suffix}"[:80]
    stdin_text = "\n".join([operation, profile_id, generation, ""])

    script = r'''set -eu
umask 077
req="$(mktemp /tmp/wg_access_lifecycle_req.XXXXXX)"
trap 'rm -f "$req"' EXIT INT TERM
IFS= read -r operation_id
IFS= read -r profile_id
IFS= read -r desired_generation
{
  echo "operation_id=$operation_id"
  echo "profile_id=$profile_id"
  echo "desired_generation=$desired_generation"
} > "$req"
''' + shlex.quote(REMOTE_LIFECYCLE_COMMAND) + ' --disable "$req"\n'

    out = remote_lifecycle_command(
        script,
        stdin_text,
        operation=f"--disable profile_id={profile_id}",
    )
    accepted = (
        "RESULT=PASS_PEER_DISABLE" in out
        or "result=PASS_PEER_DISABLE" in out
    )
    if not accepted:
        raise RuntimeError("VM100 lifecycle disable did not return an accepted result")


def fetch_enabled_peers_for_protocol(protocol):
    protocol = require_protocol(protocol)
    query = parse.urlencode({"node_id": NODE_ID, "protocol": protocol})
    rows = http_json("GET", f"/agent/peers?{query}") or []
    desired = {}
    for row in rows:
        peer = normalize_peer_payload(row, expected_protocol=protocol)
        public_key = peer["public_key"]
        if public_key in desired:
            raise RuntimeError(f"duplicate public key in {protocol} desired state")
        desired[public_key] = peer
    return desired


def fetch_enabled_peers():
    desired = {}

    for protocol in MANAGED_PROTOCOLS:
        protocol_desired = fetch_enabled_peers_for_protocol(protocol)
        for public_key, peer in protocol_desired.items():
            if public_key in desired:
                raise RuntimeError(
                    "duplicate public key across managed protocol desired state"
                )
            desired[public_key] = peer
        log(
            f"sync desired enabled peers protocol={protocol}: "
            f"{len(protocol_desired)}"
        )

    return desired


def sync_enabled_peers():
    desired = fetch_enabled_peers()
    log(f"sync desired enabled peers total: {len(desired)}")

    registry_before = remote_registry()
    log(f"sync VM100 lifecycle registry peers before: {len(registry_before)}")
    changed = False

    for public_key in sorted(desired):
        peer = desired[public_key]
        existing = find_registry_profile(peer, registry_before)
        if (
            existing is not None
            and existing["protocol"] == peer["protocol"]
            and existing["desired_generation"] == desired_generation(peer)
        ):
            continue
        profile_id, mode = lifecycle_enable_or_ensure(
            peer, registry_rows=registry_before
        )
        changed = True
        log(
            "sync lifecycle "
            f"{mode} protocol={peer['protocol']} peer_id={peer['id']} "
            f"profile_id={profile_id} tunnel_ip={peer['tunnel_ip']}"
        )

    for row in sorted(registry_before, key=lambda item: item["profile_id"]):
        if row["protocol"] not in MANAGED_PROTOCOLS:
            continue
        peer = desired.get(row["public_key"])
        if peer is not None and peer["protocol"] == row["protocol"]:
            continue
        lifecycle_disable_profile(
            row["profile_id"],
            reason_seed=(
                f"{row['protocol']}|{row['public_key']}|{row['tunnel_ip']}"
            ),
        )
        changed = True
        log(
            "sync lifecycle --disable "
            f"protocol={row['protocol']} profile_id={row['profile_id']} "
            f"tunnel_ip={row['tunnel_ip']}"
        )

    registry_after = remote_registry() if changed else registry_before
    actual = {
        (row["protocol"], row["public_key"], row["tunnel_ip"])
        for row in registry_after
        if row["protocol"] in MANAGED_PROTOCOLS
    }
    expected = {
        (peer["protocol"], peer["public_key"], peer["tunnel_ip"])
        for peer in desired.values()
    }
    if actual != expected:
        raise RuntimeError(
            f"VM100 lifecycle registry mismatch after reconcile "
            f"expected={len(expected)} actual={len(actual)}"
        )

    state = load_state()
    state["peers"] = {}
    for public_key, peer in desired.items():
        state["peers"][public_key] = {
            "peer_id": peer["id"],
            "public_key": public_key,
            "protocol": peer["protocol"],
            "tunnel_ip": peer["tunnel_ip"],
            "paid_until": peer["paid_until"],
            "enabled": True,
            "last_action": "sync_enabled_peers_via_vm100_lifecycle",
            "updated_at": utc_now(),
        }
    save_state(state)

    log(
        f"sync VM100 lifecycle registry peers after: {len(registry_after)} "
        f"changed={1 if changed else 0}"
    )
    return desired, registry_after



def parse_iso8601_epoch(value):
    text = str(value or "").strip()
    if not text:
        raise RuntimeError("routing override expires_at is required")
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("routing override expires_at is invalid") from exc
    if dt.tzinfo is None:
        raise RuntimeError("routing override expires_at must be timezone-aware")
    return int(dt.timestamp())


def normalize_routing_override(row):
    configuration_id = str(row.get("configuration_id") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", configuration_id):
        raise RuntimeError("routing override configuration_id is invalid")

    selector_number = row.get("selector")
    if not isinstance(selector_number, int) or selector_number not in {1, 2, 3, 4, 5}:
        raise RuntimeError("routing override selector must be 1..5")

    expires_epoch = parse_iso8601_epoch(row.get("expires_at"))
    variants = row.get("variants")
    if not isinstance(variants, list):
        raise RuntimeError("routing override variants must be a list")

    tunnel_ips = []
    variant_summary = []
    seen_ips = set()
    seen_protocols = set()
    for variant in variants:
        if not isinstance(variant, dict):
            raise RuntimeError("routing override variant is invalid")
        protocol = require_protocol(variant.get("protocol"))
        if protocol in seen_protocols:
            raise RuntimeError(
                f"duplicate routing override protocol configuration_id={configuration_id}"
            )
        seen_protocols.add(protocol)
        tunnel_ip = require_tunnel_ip(variant.get("tunnel_ip"))
        if tunnel_ip in seen_ips:
            raise RuntimeError(
                f"duplicate routing override tunnel_ip configuration_id={configuration_id}"
            )
        seen_ips.add(tunnel_ip)
        tunnel_ips.append(tunnel_ip)
        variant_summary.append({
            "protocol": protocol,
            "profile_id": str(variant.get("profile_id") or ""),
            "tunnel_ip": tunnel_ip,
        })

    return {
        "configuration_id": configuration_id,
        "override_id": ROUTING_OVERRIDE_PREFIX + configuration_id,
        "selector": f"cs{selector_number}",
        "selector_number": selector_number,
        "expires_epoch": expires_epoch,
        "tunnel_ips": sorted(tunnel_ips, key=ipaddress.ip_address),
        "variants": variant_summary,
    }


def fetch_routing_overrides():
    query = parse.urlencode({"node_id": NODE_ID})
    rows = http_json("GET", f"/agent/routing-overrides?{query}") or []
    if not isinstance(rows, list):
        raise RuntimeError("routing override desired state must be a list")

    desired = {}
    for row in rows:
        item = normalize_routing_override(row)
        override_id = item["override_id"]
        if override_id in desired:
            raise RuntimeError(f"duplicate routing override id: {override_id}")
        desired[override_id] = item
    return desired


def parse_remote_forced_status(text):
    groups = {}
    accepted = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line == "RESULT=PASS_FORCED_EGRESS_STATUS":
            accepted = True
            continue
        parts = line.split("\t")
        if not parts or parts[0] != "override":
            continue
        if len(parts) != 5:
            raise RuntimeError("invalid VM100 forced-egress status row")
        _, override_id, selector, expires_text, tunnel_ip = parts
        if not override_id.startswith(ROUTING_OVERRIDE_PREFIX):
            continue
        if not re.fullmatch(r"cfg:[0-9a-fA-F-]{36}", override_id):
            raise RuntimeError("invalid managed VM100 forced override id")
        if selector not in {"cs1", "cs2", "cs3", "cs4", "cs5"}:
            raise RuntimeError("invalid VM100 forced selector")
        if not expires_text.isdigit():
            raise RuntimeError("invalid VM100 forced expiry")
        tunnel_ip = require_tunnel_ip(tunnel_ip)
        expires_epoch = int(expires_text)

        group = groups.setdefault(
            override_id,
            {"selector": selector, "expires_epoch": expires_epoch, "tunnel_ips": []},
        )
        if group["selector"] != selector or group["expires_epoch"] != expires_epoch:
            raise RuntimeError("inconsistent VM100 forced override group")
        if tunnel_ip in group["tunnel_ips"]:
            raise RuntimeError("duplicate VM100 forced override tunnel_ip")
        group["tunnel_ips"].append(tunnel_ip)

    if not accepted:
        raise RuntimeError("VM100 forced-egress status did not return PASS")
    for group in groups.values():
        group["tunnel_ips"] = sorted(group["tunnel_ips"], key=ipaddress.ip_address)
    return groups


def remote_forced_status():
    command = shlex.quote(REMOTE_FORCED_EGRESS_COMMAND) + " --status"
    return parse_remote_forced_status(remote_command(command, log_output=False))


def remote_forced_set_until(item):
    args = [
        REMOTE_FORCED_EGRESS_COMMAND,
        "--set-until",
        item["override_id"],
        item["selector"],
        str(item["expires_epoch"]),
        *item["tunnel_ips"],
    ]
    command = " ".join(shlex.quote(str(value)) for value in args)
    out = remote_command(command)
    if "RESULT=PASS_FORCED_EGRESS_SET_UNTIL" not in out:
        raise RuntimeError(
            f"VM100 forced-egress set-until not accepted override={item['override_id']}"
        )


def remote_forced_clear(override_id):
    command = " ".join(
        shlex.quote(str(value))
        for value in [REMOTE_FORCED_EGRESS_COMMAND, "--clear", override_id]
    )
    out = remote_command(command)
    accepted = (
        "RESULT=PASS_FORCED_EGRESS_CLEARED" in out
        or "RESULT=NOOP_FORCED_EGRESS_ALREADY_AUTOMATIC" in out
    )
    if not accepted:
        raise RuntimeError(
            f"VM100 forced-egress clear not accepted override={override_id}"
        )


def routing_runtime_equivalent(current, desired):
    return (
        current.get("selector") == desired["selector"]
        and current.get("expires_epoch") == desired["expires_epoch"]
        and current.get("tunnel_ips") == desired["tunnel_ips"]
    )


def sync_routing_overrides():
    desired = fetch_routing_overrides()
    now_epoch = int(time.time())

    # A desired row can age out between backend serialization and this agent
    # cycle. Treat near-expiry rows as Automatic; VM100 remains protected by
    # its own absolute nft timeout.
    active_desired = {
        override_id: item
        for override_id, item in desired.items()
        if item["expires_epoch"] > now_epoch + 2
    }
    current = remote_forced_status()

    log(
        "routing desired overrides="
        f"{len(active_desired)} current_managed_overrides={len(current)}"
    )

    changed = False

    # First remove managed runtime that is no longer desired. This covers
    # Automatic, expiry, Configuration disablement, and configurations whose
    # active variant set became empty.
    for override_id in sorted(current):
        item = active_desired.get(override_id)
        if item is not None and item["tunnel_ips"]:
            continue
        remote_forced_clear(override_id)
        changed = True
        log(f"routing clear override={override_id}")

    # Then converge every non-empty desired Configuration to one exact absolute
    # deadline. Re-running this with the same expires_epoch never extends TTL.
    for override_id in sorted(active_desired):
        item = active_desired[override_id]
        if not item["tunnel_ips"]:
            continue
        actual = current.get(override_id)
        if actual is not None and routing_runtime_equivalent(actual, item):
            continue
        remote_forced_set_until(item)
        changed = True
        log(
            f"routing set-until override={override_id} selector={item['selector']} "
            f"expires_epoch={item['expires_epoch']} tunnel_ip_count={len(item['tunnel_ips'])}"
        )

    after = remote_forced_status() if changed else current
    expected = {
        override_id: {
            "selector": item["selector"],
            "expires_epoch": item["expires_epoch"],
            "tunnel_ips": item["tunnel_ips"],
        }
        for override_id, item in active_desired.items()
        if item["tunnel_ips"]
    }

    owned_after = {
        override_id: value
        for override_id, value in after.items()
        if override_id.startswith(ROUTING_OVERRIDE_PREFIX)
    }
    if owned_after != expected:
        raise RuntimeError(
            "VM100 forced routing mismatch after reconcile "
            f"expected={len(expected)} actual={len(owned_after)}"
        )

    state = load_state()
    state["routing_overrides"] = {
        override_id: {
            "configuration_id": item["configuration_id"],
            "selector": item["selector"],
            "expires_epoch": item["expires_epoch"],
            "tunnel_ips": item["tunnel_ips"],
            "variant_count": len(item["variants"]),
        }
        for override_id, item in active_desired.items()
    }
    save_state(state)

    log(
        "routing reconcile complete "
        f"desired={len(active_desired)} runtime={len(owned_after)} "
        f"changed={1 if changed else 0}"
    )
    return active_desired, owned_after



def resolve_job_protocol(job, *, expected_protocol):
    payload = job.get("payload_json") or {}
    payload_protocol = payload.get("protocol")

    if payload_protocol is None:
        # Legacy Peer jobs predate ConnectionProfile.protocol. They are part of
        # the WireGuard compatibility surface only.
        if expected_protocol == "wireguard" and not job.get("connection_profile_id"):
            return "wireguard"
        raise RuntimeError("profile job is missing payload protocol")

    return require_protocol(payload_protocol, expected=expected_protocol)


def fetch_pending_jobs():
    pending = []
    seen = set()

    for protocol in MANAGED_PROTOCOLS:
        query = parse.urlencode({
            "node_id": NODE_ID,
            "protocol": protocol,
            "limit": 20,
        })
        rows = http_json("GET", f"/agent/jobs?{query}") or []
        for job in rows:
            job_id = str(job.get("id") or "")
            if not job_id:
                raise RuntimeError("job id is required")
            if job_id in seen:
                raise RuntimeError(f"duplicate job across protocol queues: {job_id}")
            resolve_job_protocol(job, expected_protocol=protocol)
            seen.add(job_id)
            pending.append((protocol, job))
        log(f"pending jobs protocol={protocol}: {len(rows)}")

    return pending


def targeted_peer_for_job(job, *, expected_protocol):
    protocol = resolve_job_protocol(job, expected_protocol=expected_protocol)
    payload = job.get("payload_json") or {}
    peer_id = str(job.get("connection_profile_id") or job.get("peer_id") or "")
    public_key = require_wg_key("public_key", payload["public_key"])
    tunnel_ip = require_tunnel_ip(payload["tunnel_ip"])

    desired = fetch_enabled_peers_for_protocol(protocol)
    peer = desired.get(public_key)
    if (
        peer is None
        or str(peer["id"]) != peer_id
        or peer["tunnel_ip"] != tunnel_ip
    ):
        raise RuntimeError(
            f"targeted desired peer mismatch protocol={protocol} peer_id={peer_id}"
        )
    return peer


def apply_targeted_job(job, *, expected_protocol):
    action = job["action"]
    payload = job.get("payload_json") or {}
    protocol = resolve_job_protocol(job, expected_protocol=expected_protocol)
    profile_id = str(
        job.get("connection_profile_id")
        or job.get("peer_id")
        or payload.get("profile_id")
        or ""
    )
    if not profile_id:
        raise RuntimeError("job profile/peer id is required")

    if action in {"enable_peer", "provision_profile"}:
        peer = targeted_peer_for_job(job, expected_protocol=protocol)
        registry_before = remote_registry()
        runtime_profile_id, mode = lifecycle_enable_or_ensure(
            peer, registry_rows=registry_before
        )
        registry_after = remote_registry()
        row = find_registry_profile(peer, registry_after)
        if (
            row is None
            or row["profile_id"] != runtime_profile_id
            or row["desired_generation"] != desired_generation(peer)
        ):
            raise RuntimeError(
                f"targeted enable verification failed peer_id={profile_id}"
            )
        log(
            f"REAL {action} targeted via VM100 lifecycle "
            f"mode={mode} protocol={protocol} peer_id={profile_id} "
            f"tunnel_ip={peer['tunnel_ip']}"
        )
        return

    if action in {"disable_peer", "disable_profile"}:
        public_key = require_wg_key("public_key", payload["public_key"])
        tunnel_ip = require_tunnel_ip(payload["tunnel_ip"])
        lifecycle_disable_profile(
            profile_id,
            reason_seed=f"{protocol}|{public_key}|{tunnel_ip}",
        )
        registry_after = remote_registry()
        if any(
            row["protocol"] == protocol
            and (row["profile_id"] == profile_id or row["public_key"] == public_key)
            for row in registry_after
        ):
            raise RuntimeError(
                f"targeted disable verification failed peer_id={profile_id}"
            )
        log(
            f"REAL {action} targeted via VM100 lifecycle "
            f"protocol={protocol} peer_id={profile_id}"
        )
        return

    raise RuntimeError(f"unsupported action: {action}")


def process_pending_jobs(pending):
    log(f"fetched pending jobs total: {len(pending)}")

    for protocol, job in pending:
        job_id = job["id"]
        log(
            f"starting job_id={job_id} protocol={protocol} "
            f"action={job['action']}"
        )

        try:
            started = http_json("POST", f"/agent/jobs/{job_id}/start")
            apply_targeted_job(started, expected_protocol=protocol)
            completed = http_json("POST", f"/agent/jobs/{job_id}/complete")
            log(
                f"completed job_id={completed['id']} protocol={protocol} "
                f"status={completed['status']} attempts={completed['attempts']}"
            )
        except Exception as exc:
            err = "".join(traceback.format_exception_only(type(exc), exc)).strip()
            log(f"failed job_id={job_id} protocol={protocol}: {err}")
            try:
                http_json("POST", f"/agent/jobs/{job_id}/fail", {"error": err})
            except Exception as fail_exc:
                log(f"failed to report failure job_id={job_id}: {fail_exc}")


def run_once():
    # Durable profile jobs stay first so a newly-active WG/AWG sibling can join
    # an already-forced Configuration in this same agent invocation.
    pending = fetch_pending_jobs()
    if pending:
        process_pending_jobs(pending)
    else:
        # No due job exists: retain the existing desired-state reconcile as the
        # periodic/fallback convergence mechanism. Unchanged peers are verified
        # from one registry snapshot and do not receive redundant lifecycle --ensure.
        log("no pending jobs; running fallback reconcile")
        sync_enabled_peers()

    # Configuration-level routing is desired state, not a provisioning job.
    # Reconcile it every invocation so routing PUT wakeups are immediate while
    # the timer remains the fallback convergence path.
    sync_routing_overrides()
    return 0


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--routing-only":
        sync_routing_overrides()
        return 0
    if len(sys.argv) != 1:
        raise RuntimeError("usage: wg_access_agent.py [--routing-only]")
    return run_once()


if __name__ == "__main__":
    sys.exit(main())
