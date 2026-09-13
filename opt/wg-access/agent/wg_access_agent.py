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
MANAGED_PROTOCOLS = ("wireguard", "amneziawg")


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


def lifecycle_enable_or_ensure(peer):
    rows = remote_registry()
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


def fetch_enabled_peers():
    desired = {}

    for protocol in MANAGED_PROTOCOLS:
        query = parse.urlencode({"node_id": NODE_ID, "protocol": protocol})
        rows = http_json("GET", f"/agent/peers?{query}") or []

        for row in rows:
            peer = normalize_peer_payload(row, expected_protocol=protocol)
            public_key = peer["public_key"]
            if public_key in desired:
                raise RuntimeError(
                    "duplicate public key across managed protocol desired state"
                )
            desired[public_key] = peer

        log(f"sync desired enabled peers protocol={protocol}: {len(rows)}")

    return desired


def sync_enabled_peers():
    desired = fetch_enabled_peers()
    log(f"sync desired enabled peers total: {len(desired)}")

    registry_before = remote_registry()
    log(f"sync VM100 lifecycle registry peers before: {len(registry_before)}")

    for public_key in sorted(desired):
        peer = desired[public_key]
        profile_id, mode = lifecycle_enable_or_ensure(peer)
        log(
            "sync lifecycle "
            f"{mode} protocol={peer['protocol']} peer_id={peer['id']} "
            f"profile_id={profile_id} tunnel_ip={peer['tunnel_ip']}"
        )

    registry_mid = remote_registry()
    for row in sorted(registry_mid, key=lambda item: item["profile_id"]):
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
        log(
            "sync lifecycle --disable "
            f"protocol={row['protocol']} profile_id={row['profile_id']} "
            f"tunnel_ip={row['tunnel_ip']}"
        )

    registry_after = remote_registry()
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

    log(f"sync VM100 lifecycle registry peers after: {len(registry_after)}")
    return desired, registry_after


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


def verify_job_against_reconciled_state(
    job,
    desired,
    registry_rows,
    *,
    expected_protocol,
):
    action = job["action"]
    payload = job["payload_json"]
    protocol = resolve_job_protocol(job, expected_protocol=expected_protocol)
    peer_id = str(job.get("peer_id") or job.get("connection_profile_id") or "")

    if action in {"enable_peer", "provision_profile"}:
        public_key = require_wg_key("public_key", payload["public_key"])
        tunnel_ip = require_tunnel_ip(payload["tunnel_ip"])
        row = next(
            (
                item
                for item in registry_rows
                if item["public_key"] == public_key
                and item["tunnel_ip"] == tunnel_ip
                and item["protocol"] == protocol
            ),
            None,
        )
        desired_peer = desired.get(public_key)
        if (
            row is None
            or desired_peer is None
            or desired_peer["protocol"] != protocol
        ):
            raise RuntimeError(
                f"enable job not satisfied by lifecycle reconcile peer_id={peer_id}"
            )
        log(
            f"REAL {action} verified via VM100 lifecycle "
            f"protocol={protocol} peer_id={peer_id} tunnel_ip={tunnel_ip}"
        )
        return

    if action in {"disable_peer", "disable_profile"}:
        public_key = require_wg_key("public_key", payload["public_key"])
        if any(
            item["protocol"] == protocol and item["public_key"] == public_key
            for item in registry_rows
        ):
            raise RuntimeError(
                f"disable job still present in VM100 lifecycle registry peer_id={peer_id}"
            )
        log(
            f"REAL {action} verified via VM100 lifecycle "
            f"protocol={protocol} peer_id={peer_id}"
        )
        return

    raise RuntimeError(f"unsupported action: {action}")


def run_once():
    # VM121 owns desired membership only. VM100 lifecycle owns runtime peer +
    # selector membership transaction. The agent never executes direct runtime writes.
    desired, registry_rows = sync_enabled_peers()
    pending = fetch_pending_jobs()

    if not pending:
        log("no pending jobs")
        return 0

    log(f"fetched pending jobs total: {len(pending)}")

    for protocol, job in pending:
        job_id = job["id"]
        log(
            f"starting job_id={job_id} protocol={protocol} "
            f"action={job['action']}"
        )

        try:
            started = http_json("POST", f"/agent/jobs/{job_id}/start")
            verify_job_against_reconciled_state(
                started,
                desired,
                registry_rows,
                expected_protocol=protocol,
            )
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

    return 0


if __name__ == "__main__":
    sys.exit(run_once())
