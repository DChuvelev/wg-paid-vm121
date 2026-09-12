#!/usr/bin/env python3

import json
import os
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, request


def utc_now():
    return datetime.now(timezone.utc)


def iso_utc(dt):
    return dt.isoformat()


def epoch_to_iso(value):
    try:
        epoch = int(value)
    except (TypeError, ValueError):
        return None
    if epoch <= 0:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def load_env(path):
    env = {}
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip()
    return env


ENV_PATH = os.environ.get("WG_ACCESS_AGENT_ENV", "/opt/wg-access/agent/agent.env")
env = load_env(ENV_PATH)
BACKEND_URL = env["BACKEND_URL"].rstrip("/")
AGENT_TOKEN = env["AGENT_TOKEN"]
REMOTE_HOST = env["REMOTE_HOST"]
REMOTE_USER = env.get("REMOTE_USER", "root")
REMOTE_SSH_KEY = env["REMOTE_SSH_KEY"]
REMOTE_REGISTRY_FILE = env.get("REMOTE_REGISTRY_FILE", "/etc/router-wgpay-peer-state/registry.tsv")
REMOTE_EGRESS_STATE_FILE = env.get("REMOTE_EGRESS_STATE_FILE", "/var/lib/router-wgpay-egress/state.kv")
REMOTE_WG_INTERFACE = env.get("REMOTE_WG_INTERFACE", "wg_paid")
SAMPLE_INTERVAL_SECONDS = float(env.get("RUNTIME_TELEMETRY_INTERVAL_SECONDS", "5"))
if SAMPLE_INTERVAL_SECONDS <= 0 or SAMPLE_INTERVAL_SECONDS > 60:
    raise RuntimeError("invalid RUNTIME_TELEMETRY_INTERVAL_SECONDS")


def http_post_json(path, payload):
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = request.Request(
        BACKEND_URL + path,
        data=body,
        headers={
            "X-Agent-Token": AGENT_TOKEN,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8")
            return json.loads(data) if data else None
    except error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {text}") from exc


def remote_snapshot_text():
    registry = shlex.quote(REMOTE_REGISTRY_FILE)
    state = shlex.quote(REMOTE_EGRESS_STATE_FILE)
    interface = shlex.quote(REMOTE_WG_INTERFACE)
    remote_script = f"""set -eu
printf '%s\\n' '__REGISTRY_BEGIN__'
cat {registry}
printf '%s\\n' '__REGISTRY_END__'
printf '%s\\n' '__STATE_BEGIN__'
cat {state}
printf '%s\\n' '__STATE_END__'
printf '%s\\n' '__WG_BEGIN__'
wg show {interface} dump | awk 'NR > 1 {{print $1 "\\t" $5 "\\t" $6 "\\t" $7}}'
printf '%s\\n' '__WG_END__'
"""
    cmd = [
        "ssh",
        "-i", REMOTE_SSH_KEY,
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=8",
        f"{REMOTE_USER}@{REMOTE_HOST}",
        "sh -s",
    ]
    result = subprocess.run(
        cmd,
        input=remote_script.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"remote snapshot failed rc={result.returncode}: {stderr or stdout}")
    return result.stdout.decode("utf-8", errors="strict")


def framed_section(text, name):
    begin = f"__{name}_BEGIN__"
    end = f"__{name}_END__"
    lines = text.splitlines()
    try:
        start = lines.index(begin) + 1
        stop = lines.index(end, start)
    except ValueError as exc:
        raise RuntimeError(f"missing remote snapshot section {name}") from exc
    return lines[start:stop]


def parse_registry(lines):
    rows = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 10:
            raise RuntimeError("invalid registry row")
        row = {
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
        }
        if row["protocol"] == "wireguard" and row["interface"] == REMOTE_WG_INTERFACE:
            rows.append(row)
    return rows


def parse_state(lines):
    state = {}
    prefix = "peer."
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not key.startswith(prefix):
            continue
        rest = key[len(prefix):]
        ip, sep, field = rest.rpartition(".")
        if not sep or not ip or not field:
            continue
        state.setdefault(ip, {})[field] = value
    return state


def parse_wg(lines):
    peers = {}
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != 4:
            raise RuntimeError("invalid sanitized WireGuard row")
        public_key, handshake, rx_bytes, tx_bytes = parts
        peers[public_key] = {
            "last_handshake_epoch": int(handshake),
            "rx_bytes": max(0, int(rx_bytes)),
            "tx_bytes": max(0, int(tx_bytes)),
        }
    return peers


def true_value(value):
    return str(value).lower() == "true"


def nonnegative_int(value):
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def build_payload(text, previous, previous_sample_monotonic, now_monotonic):
    registry = parse_registry(framed_section(text, "REGISTRY"))
    state = parse_state(framed_section(text, "STATE"))
    wg = parse_wg(framed_section(text, "WG"))
    elapsed = SAMPLE_INTERVAL_SECONDS
    if previous_sample_monotonic is not None:
        elapsed = max(0.001, now_monotonic - previous_sample_monotonic)

    rows = []
    next_previous = {}
    for reg in registry:
        selector = reg["active_selector"]
        if selector not in {"cs1", "cs2", "cs3", "cs4", "cs5"}:
            continue
        activity = state.get(reg["tunnel_ip"], {})
        runtime = wg.get(reg["public_key"], {})
        rx = nonnegative_int(runtime.get("rx_bytes"))
        tx = nonnegative_int(runtime.get("tx_bytes"))
        previous_row = previous.get(reg["profile_id"])
        rx_rate = 0.0
        tx_rate = 0.0
        if previous_row and previous_row.get("public_key") == reg["public_key"]:
            old_rx = nonnegative_int(previous_row.get("rx_bytes"))
            old_tx = nonnegative_int(previous_row.get("tx_bytes"))
            if rx >= old_rx and tx >= old_tx:
                rx_rate = (rx - old_rx) / elapsed
                tx_rate = (tx - old_tx) / elapsed

        rows.append({
            "profile_id": reg["profile_id"],
            "tunnel_ip": reg["tunnel_ip"],
            "selector": selector,
            "active_now": true_value(activity.get("active_now")),
            "active_state": true_value(activity.get("active_state")),
            "last_active_at": epoch_to_iso(activity.get("last_active_epoch")),
            "last_reassign_at": epoch_to_iso(activity.get("last_reassign_epoch")),
            "last_handshake_at": epoch_to_iso(runtime.get("last_handshake_epoch")),
            "rx_bytes": rx,
            "tx_bytes": tx,
            "rx_bytes_per_second": rx_rate,
            "tx_bytes_per_second": tx_rate,
        })
        next_previous[reg["profile_id"]] = {
            "public_key": reg["public_key"],
            "rx_bytes": rx,
            "tx_bytes": tx,
        }

    payload = {
        "generated_at": iso_utc(utc_now()),
        "sample_interval_seconds": elapsed,
        "rows": rows,
    }
    return payload, next_previous


def run_forever():
    previous = {}
    previous_sample_monotonic = None
    while True:
        started = time.monotonic()
        try:
            text = remote_snapshot_text()
            payload, next_previous = build_payload(
                text,
                previous,
                previous_sample_monotonic,
                started,
            )
            accepted = http_post_json("/agent/runtime-snapshot", payload)
            previous = next_previous
            previous_sample_monotonic = started
            print(
                f"runtime snapshot accepted rows={len(payload['rows'])} "
                f"received_at={(accepted or {}).get('received_at', 'unknown')}",
                flush=True,
            )
        except Exception as exc:
            print(f"runtime snapshot error: {exc}", flush=True)
        spent = time.monotonic() - started
        time.sleep(max(0.2, SAMPLE_INTERVAL_SECONDS - spent))


if __name__ == "__main__":
    run_forever()
