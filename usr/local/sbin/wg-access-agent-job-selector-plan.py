#!/usr/bin/env python3
import argparse
import json
import subprocess
import tempfile
from pathlib import Path

def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))

def flatten_job(job):
    payload = job.get("payload", {})
    peer = payload.get("peer", {})
    selector = payload.get("selector", {})
    provider = payload.get("provider", {})

    return {
        "job_type": job.get("job_type", ""),
        "dry_run": True,
        "peer_id": peer.get("peer_id", payload.get("peer_id", "")),
        "subscription_id": peer.get("subscription_id", payload.get("subscription_id", "")),
        "tunnel_ip": peer.get("tunnel_ip", payload.get("tunnel_ip", "")),
        "slot_code": selector.get("slot_code", payload.get("slot_code", "")),
        "selector_class": selector.get("selector_class", payload.get("selector_class", "")),
        "selector_label": selector.get("selector_label", payload.get("selector_label", "")),
        "fwmark": selector.get("fwmark", payload.get("fwmark", "")),
        "table_id": selector.get("table_id", payload.get("table_id", "")),
        "interface_name": selector.get("interface_name", payload.get("interface_name", "")),
        "provider_type": provider.get("provider_type", payload.get("provider_type", "")),
        "manager_id": provider.get("manager_id", payload.get("manager_id", "")),
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--job", required=True)
    parser.add_argument("--selector-file", required=True)
    parser.add_argument("--slot-status-json", required=True)
    parser.add_argument("--selector-helper", default="/usr/local/sbin/wg-access-agent-selector-apply.py")
    parser.add_argument("--mode", choices=["dry-run"], default="dry-run")
    parser.add_argument("--output-json", action="store_true")
    args = parser.parse_args()

    job = load_json(args.job)
    flat = flatten_job(job)

    result = {
        "schema": "wg-access-agent-job-selector-plan-v1",
        "mode": args.mode,
        "job": {
            "schema": job.get("schema", ""),
            "job_id": job.get("job_id", ""),
            "job_type": job.get("job_type", ""),
            "dry_run": bool(job.get("dry_run", False)),
        },
        "flattened_payload": flat,
        "selector_helper": args.selector_helper,
        "selector_plan_rc": None,
        "selector_plan": None,
        "apply_performed": False,
    }

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
        json.dump(flat, tmp, ensure_ascii=False, indent=2, sort_keys=True)
        tmp_payload = tmp.name

    cmd = [
        args.selector_helper,
        "--payload", tmp_payload,
        "--selector-file", args.selector_file,
        "--slot-status-json", args.slot_status_json,
        "--mode", "dry-run",
        "--output-json",
    ]

    proc = subprocess.run(cmd, text=True, capture_output=True)
    result["selector_plan_rc"] = proc.returncode
    result["selector_plan_stdout"] = proc.stdout
    result["selector_plan_stderr"] = proc.stderr

    try:
        plan = json.loads(proc.stdout)
    except Exception as e:
        plan = {
            "schema": "parse-error",
            "contract_valid": False,
            "errors": ["selector_plan_json_parse_error:" + type(e).__name__],
        }

    result["selector_plan"] = plan
    result["contract_valid"] = bool(plan.get("contract_valid", False))
    result["action"] = plan.get("action", "")
    result["would_append"] = bool(plan.get("would_append", False))
    result["idempotent_noop"] = bool(plan.get("idempotent_noop", False))
    result["selector_entry_count_before"] = plan.get("selector_entry_count_before")
    result["selector_entry_count_after_planned"] = plan.get("selector_entry_count_after_planned")
    result["errors"] = plan.get("errors", [])
    result["error_count"] = len(result["errors"])
    result["apply_performed"] = bool(plan.get("apply_performed", False))

    if args.output_json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print("contract_valid=" + ("YES" if result["contract_valid"] else "NO"))
        print("action=" + str(result["action"]))
        print("selector_plan_rc=" + str(result["selector_plan_rc"]))

    return 0 if result["contract_valid"] else 2

if __name__ == "__main__":
    raise SystemExit(main())
