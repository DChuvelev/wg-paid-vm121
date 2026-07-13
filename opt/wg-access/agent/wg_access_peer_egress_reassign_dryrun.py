#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "wg-access-peer-egress-reassign-dryrun-handler-v1"
REQUIRED_PAYLOAD_KEYS = [
    "tunnel_ip",
    "from_target_id",
    "to_target_id",
    "from_egress_class",
    "to_egress_class",
    "reason",
    "requested_by",
    "rebalancer",
]
FORBIDDEN_PAYLOAD_KEYS = [
    "private_key",
    "preshared_key",
    "client_config",
    "config",
    "qr",
    "access_code",
    "token",
    "password",
]

def run(cmd, input_text=None, timeout=120):
    p = subprocess.run(cmd, input=input_text, text=True, capture_output=True, timeout=timeout)
    return {"rc": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}

def psql_json(sql):
    pg_r = run(["sh", "-lc", "docker ps --format '{{.Names}}' | grep -E '^wgaccess-postgres$|postgres' | head -1"], timeout=15)
    pg = pg_r["stdout"].strip()
    if not pg:
        raise RuntimeError("postgres container not found")

    p = run(
        ["docker", "exec", "-i", pg, "sh", "-lc",
         'psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}" -At'],
        input_text=sql,
        timeout=120,
    )
    if p["rc"] != 0:
        raise RuntimeError(p["stderr"] or p["stdout"])
    return json.loads(p["stdout"] or "null")

def sql_quote(value):
    if value is None:
        return "NULL"
    return "'" + str(value).replace("'", "''") + "'"

def read_job(path):
    if path == "-":
        text = sys.stdin.read()
    else:
        text = Path(path).read_text(errors="replace")
    return json.loads(text)

def write_output(obj, path):
    data = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path == "-":
        print(data, end="")
    else:
        Path(path).write_text(data, encoding="utf-8")

def validate_uuid(value):
    return bool(re.match(r"^[0-9a-fA-F-]{36}$", str(value or "")))

def main():
    ap = argparse.ArgumentParser(description="Dry-run validator/plan builder for WG Access peer_egress_reassign jobs")
    ap.add_argument("--job-json", required=True, help="job JSON path or '-' for stdin")
    ap.add_argument("--json-out", default="-")
    args = ap.parse_args()

    job = read_job(args.job_json)
    payload = job.get("payload_json") or {}

    peer_id = job.get("peer_id")
    node_id = job.get("node_id")
    action = job.get("action")
    status = job.get("status")
    attempts = job.get("attempts")

    validation = {
        "action_is_peer_egress_reassign": action == "peer_egress_reassign",
        "status_is_pending": status == "pending",
        "attempts_is_zero": attempts == 0,
        "peer_id_present": bool(peer_id),
        "peer_id_uuid_like": validate_uuid(peer_id),
        "node_id_present": bool(node_id),
        "payload_required_keys_present": all(k in payload for k in REQUIRED_PAYLOAD_KEYS),
        "payload_forbidden_keys_absent": not any(k in payload for k in FORBIDDEN_PAYLOAD_KEYS),
        "payload_rebalancer_true": payload.get("rebalancer") is True,
        "payload_has_tunnel_ip": bool(payload.get("tunnel_ip")),
        "payload_has_target_change": bool(payload.get("from_target_id")) and bool(payload.get("to_target_id")) and payload.get("from_target_id") != payload.get("to_target_id"),
        "payload_has_class_change": bool(payload.get("from_egress_class")) and bool(payload.get("to_egress_class")) and payload.get("from_egress_class") != payload.get("to_egress_class"),
    }

    db_peer = None
    db_targets = []
    db_summary = {}
    errors = []

    try:
        db_peer = psql_json(f"""
SELECT jsonb_build_object(
  'peer_id', p.id::text,
  'node_id', p.node_id::text,
  'enabled', p.enabled,
  'tunnel_ip', host(l.tunnel_ip)::text,
  'target_id', l.target_id,
  'egress_class', l.egress_class,
  'state', l.state,
  'forced', l.forced,
  'assignment_source', l.assignment_source,
  'reason', l.reason,
  'cooldown_until', l.cooldown_until::text
)
FROM public.peer_egress_leases l
JOIN public.peers p ON p.id = l.peer_id
WHERE p.id = {sql_quote(peer_id)}::uuid;
""")
    except Exception as e:
        errors.append("peer_lookup_failed: " + str(e))

    try:
        db_targets = psql_json(f"""
SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id::text), '[]'::jsonb)
FROM public.egress_targets t
WHERE t.id::text IN ({sql_quote(payload.get("from_target_id"))}, {sql_quote(payload.get("to_target_id"))});
""") or []
    except Exception as e:
        errors.append("target_lookup_failed: " + str(e))

    try:
        db_summary = psql_json("""
SELECT jsonb_build_object(
  'enabled_peers', (SELECT count(*) FROM public.peers WHERE enabled=true),
  'lease_rows', (SELECT count(*) FROM public.peer_egress_leases),
  'active_leases', (SELECT count(*) FROM public.peer_egress_leases WHERE state='active'),
  'idle_leases', (SELECT count(*) FROM public.peer_egress_leases WHERE state='idle'),
  'forced_leases', (SELECT count(*) FROM public.peer_egress_leases WHERE forced=true),
  'pending_jobs', (
    SELECT count(*) FROM public.provisioning_jobs
    WHERE lower(status::text) IN ('pending','queued','running','in_progress','processing','new')
  )
);
""") or {}
    except Exception as e:
        errors.append("summary_lookup_failed: " + str(e))

    target_by_id = {str(t.get("id")): t for t in db_targets}

    validation.update({
        "db_peer_found": bool(db_peer),
        "db_peer_enabled": bool(db_peer and db_peer.get("enabled") is True),
        "db_node_id_matches": bool(db_peer and db_peer.get("node_id") == node_id),
        "db_tunnel_ip_matches": bool(db_peer and db_peer.get("tunnel_ip") == payload.get("tunnel_ip")),
        "db_current_target_matches_from": bool(db_peer and db_peer.get("target_id") == payload.get("from_target_id")),
        "db_current_class_matches_from": bool(db_peer and db_peer.get("egress_class") == payload.get("from_egress_class")),
        "db_peer_is_idle": bool(db_peer and db_peer.get("state") == "idle"),
        "db_peer_not_forced": bool(db_peer and db_peer.get("forced") is not True),
        "from_target_exists": payload.get("from_target_id") in target_by_id,
        "to_target_exists": payload.get("to_target_id") in target_by_id,
        "to_target_class_matches_payload": bool(
            payload.get("to_target_id") in target_by_id
            and target_by_id[payload.get("to_target_id")].get("egress_class") == payload.get("to_egress_class")
        ),
        "db_pending_jobs_zero": db_summary.get("pending_jobs") == 0,
    })

    selector_file = "/etc/router-wgpay-selector.d/peers.conf"
    tunnel_ip = payload.get("tunnel_ip")
    from_class = payload.get("from_egress_class")
    to_class = payload.get("to_egress_class")

    planned = {
        "scope": "dry-run only: one peer egress selector reassignment",
        "db_update_preview": {
            "would_update_peer_egress_leases": True,
            "peer_id": peer_id,
            "set_target_id": payload.get("to_target_id"),
            "set_egress_class": to_class,
            "set_assignment_source": "rebalancer",
            "set_reason": "rebalancer_idle_reassign",
            "preserve_activity_baselines": True,
        },
        "selector_update_preview": {
            "would_edit_vm100_selector_file": True,
            "selector_file": selector_file,
            "replace_entry_for_tunnel_ip": tunnel_ip,
            "from_line_prefix": f"{tunnel_ip} {from_class}",
            "to_line_prefix": f"{tunnel_ip} {to_class}",
            "would_run_existing_selector_apply_path": True,
        },
        "job_marking_preview": {
            "would_increment_attempts": True,
            "would_set_started_at": True,
            "would_set_completed_at_on_success": True,
            "would_store_last_error_on_failure": True,
        },
        "explicit_non_changes": {
            "would_not_change_wg_keys": True,
            "would_not_add_or_remove_wg_peer": True,
            "would_not_touch_vm101_slots": True,
            "would_not_recreate_wg_paid": True,
            "would_not_publish_client_config": True,
        },
    }

    validation["all_ok"] = all(validation.values()) and not errors

    out = {
        "schema": SCHEMA,
        "mode": "dryrun-no-write",
        "handler_version": "step046c-v1",
        "job_shape": {
            "id": job.get("id"),
            "node_id": node_id,
            "peer_id": peer_id,
            "action": action,
            "status": status,
            "attempts": attempts,
            "payload_keys": sorted(payload.keys()),
        },
        "validation": validation,
        "db_peer": db_peer,
        "db_targets": db_targets,
        "db_summary": db_summary,
        "planned": planned,
        "errors": errors,
        "safety": {
            "db_written": False,
            "jobs_created": False,
            "job_status_changed": False,
            "selector_changed": False,
            "wg_runtime_changed": False,
            "vm101_changed": False,
            "private_material_required": False,
            "client_config_published": False,
            "production_service_hooked": False,
        },
    }

    write_output(out, args.json_out)
    return 0 if validation["all_ok"] else 44

if __name__ == "__main__":
    sys.exit(main())
