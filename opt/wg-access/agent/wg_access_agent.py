#!/usr/bin/env python3

import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
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
REMOTE_WG_INTERFACE = env["REMOTE_WG_INTERFACE"]


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
        return json.load(f)


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    state["node_id"] = NODE_ID
    state["updated_at"] = utc_now()

    tmp = STATE_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
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


def normalize_peer_payload(peer):
    public_key = require_wg_key("public_key", peer["public_key"])
    preshared_key = require_wg_key("preshared_key", peer["preshared_key"])
    tunnel_ip = require_tunnel_ip(peer["tunnel_ip"])

    return {
        "id": str(peer.get("id") or peer.get("peer_id") or ""),
        "node_id": peer.get("node_id", NODE_ID),
        "public_key": public_key,
        "preshared_key": preshared_key,
        "tunnel_ip": tunnel_ip,
        "allowed_ips": f"{tunnel_ip}/32",
        "paid_until": peer.get("paid_until"),
        "enabled": bool(peer.get("enabled", True)),
    }


def remote_wg(script, stdin_text=None):
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
        timeout=30,
        check=False,
    )

    stdout = res.stdout.decode("utf-8", errors="replace").strip()
    stderr = res.stderr.decode("utf-8", errors="replace").strip()

    if stdout:
        log(f"remote stdout: {stdout}")
    if stderr:
        log(f"remote stderr: {stderr}")

    if res.returncode != 0:
        raise RuntimeError(f"remote command failed rc={res.returncode}: {stderr or stdout}")

    return stdout


def remote_current_allowed_ips():
    out = remote_wg("wg show " + shlex.quote(REMOTE_WG_INTERFACE) + " allowed-ips")
    current = {}

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            current[parts[0]] = parts[1:]

    return current


def remote_set_peer(peer):
    script = "\n".join([
        "set -eu",
        'tmp="$(mktemp /tmp/wg_access_psk.XXXXXX)"',
        'trap \'rm -f "$tmp"\' EXIT',
        'cat > "$tmp"',
        "wg set "
        + shlex.quote(REMOTE_WG_INTERFACE)
        + " peer "
        + shlex.quote(peer["public_key"])
        + ' preshared-key "$tmp" allowed-ips '
        + shlex.quote(peer["allowed_ips"]),
    ])
    remote_wg(script, peer["preshared_key"] + "\n")


def remote_remove_peer(public_key):
    script = (
        "set -eu\n"
        + "wg set "
        + shlex.quote(REMOTE_WG_INTERFACE)
        + " peer "
        + shlex.quote(public_key)
        + " remove"
    )
    remote_wg(script)


def sync_enabled_peers():
    query = parse.urlencode({"node_id": NODE_ID})
    rows = http_json("GET", f"/agent/peers?{query}") or []
    desired = {}

    for row in rows:
        peer = normalize_peer_payload(row)
        desired[peer["public_key"]] = peer

    log(f"sync desired enabled peers: {len(desired)}")

    current = remote_current_allowed_ips()
    log(f"sync current runtime peers: {len(current)}")

    for public_key, peer in desired.items():
        current_allowed = current.get(public_key)
        if current_allowed == [peer["allowed_ips"]]:
            log(f"sync keep peer tunnel_ip={peer['tunnel_ip']}")
            continue

        remote_set_peer(peer)
        log(f"sync set peer tunnel_ip={peer['tunnel_ip']}")

    for public_key in sorted(set(current.keys()) - set(desired.keys())):
        remote_remove_peer(public_key)
        log(f"sync removed extra runtime peer public_key={public_key}")

    # Финальная проверка для лога.
    remote_wg("wg show " + shlex.quote(REMOTE_WG_INTERFACE))

    state = load_state()
    state["peers"] = {}
    for public_key, peer in desired.items():
        state["peers"][public_key] = {
            "peer_id": peer["id"],
            "public_key": public_key,
            "preshared_key": peer["preshared_key"],
            "tunnel_ip": peer["tunnel_ip"],
            "paid_until": peer["paid_until"],
            "enabled": True,
            "last_action": "sync_enabled_peers",
            "updated_at": utc_now(),
        }
    save_state(state)


def apply_job_real(job):
    action = job["action"]
    payload = job["payload_json"]
    peer_id = str(job.get("peer_id") or "")

    if action == "enable_peer":
        peer = normalize_peer_payload({
            "id": peer_id,
            "node_id": NODE_ID,
            "public_key": payload["public_key"],
            "preshared_key": payload["preshared_key"],
            "tunnel_ip": payload["tunnel_ip"],
            "paid_until": payload.get("paid_until"),
            "enabled": True,
        })

        remote_set_peer(peer)
        remote_wg("wg show " + shlex.quote(REMOTE_WG_INTERFACE))

        state = load_state()
        state["peers"][peer["public_key"]] = {
            "peer_id": peer_id,
            "public_key": peer["public_key"],
            "preshared_key": peer["preshared_key"],
            "tunnel_ip": peer["tunnel_ip"],
            "paid_until": peer["paid_until"],
            "enabled": True,
            "last_action": action,
            "last_job_id": job["id"],
            "updated_at": utc_now(),
        }
        save_state(state)
        log(f"REAL enable_peer peer_id={peer_id} tunnel_ip={peer['tunnel_ip']}")
        return

    if action == "disable_peer":
        public_key = require_wg_key("public_key", payload["public_key"])

        remote_remove_peer(public_key)
        remote_wg("wg show " + shlex.quote(REMOTE_WG_INTERFACE))

        state = load_state()
        if public_key not in state["peers"]:
            state["peers"][public_key] = {
                "peer_id": peer_id,
                "public_key": public_key,
            }

        state["peers"][public_key]["enabled"] = False
        state["peers"][public_key]["last_action"] = action
        state["peers"][public_key]["last_job_id"] = job["id"]
        state["peers"][public_key]["updated_at"] = utc_now()

        save_state(state)
        log(f"REAL disable_peer peer_id={peer_id}")
        return

    raise RuntimeError(f"unsupported action: {action}")


def run_once():
    # Reconciliation first: VM100 wg_paid runtime state must match backend enabled peers.
    sync_enabled_peers()

    query = parse.urlencode({"node_id": NODE_ID, "limit": 20})
    jobs = http_json("GET", f"/agent/jobs?{query}") or []

    if not jobs:
        log("no pending jobs")
        return 0

    log(f"fetched pending jobs: {len(jobs)}")

    for job in jobs:
        job_id = job["id"]
        log(f"starting job_id={job_id} action={job['action']}")

        try:
            started = http_json("POST", f"/agent/jobs/{job_id}/start")
            apply_job_real(started)
            completed = http_json("POST", f"/agent/jobs/{job_id}/complete")
            log(f"completed job_id={completed['id']} status={completed['status']} attempts={completed['attempts']}")
        except Exception as exc:
            err = "".join(traceback.format_exception_only(type(exc), exc)).strip()
            log(f"failed job_id={job_id}: {err}")
            try:
                http_json("POST", f"/agent/jobs/{job_id}/fail", {"error": err})
            except Exception as fail_exc:
                log(f"failed to report failure job_id={job_id}: {fail_exc}")

    return 0


if __name__ == "__main__":
    sys.exit(run_once())
