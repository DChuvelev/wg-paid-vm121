#!/usr/bin/env python3
import argparse
import ipaddress
import json
import re
from pathlib import Path

EXPECTED = {
    "vpn1": {"selector_class": "cs4", "selector_label": "canary_vpn1", "fwmark": "0x201", "table_id": 201, "interface_name": "vpn1"},
    "vpn2": {"selector_class": "cs5", "selector_label": "canary_vpn2", "fwmark": "0x202", "table_id": 202, "interface_name": "vpn2"},
    "vpn3": {"selector_class": "cs1", "selector_label": "canary_vpn3", "fwmark": "0x203", "table_id": 203, "interface_name": "vpn3"},
    "vpn4": {"selector_class": "cs2", "selector_label": "canary_vpn4", "fwmark": "0x204", "table_id": 204, "interface_name": "vpn4"},
    "vpn5": {"selector_class": "cs3", "selector_label": "canary_vpn5", "fwmark": "0x205", "table_id": 205, "interface_name": "vpn5"},
}

def load_selector(path: Path):
    entries = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            entries.append({"raw": line, "valid": False})
            continue
        entries.append({
            "raw": line,
            "valid": True,
            "tunnel_ip": parts[0],
            "selector_class": parts[1],
            "selector_label": parts[2],
        })
    return entries

def load_status(path: Path):
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    return {s.get("slot_code"): s for s in data.get("slots", [])}

def bool_text(v):
    return "YES" if v else "NO"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload", required=True)
    ap.add_argument("--selector-file", required=True)
    ap.add_argument("--slot-status-json", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    payload = json.loads(Path(args.payload).read_text(encoding="utf-8", errors="replace"))
    entries = load_selector(Path(args.selector_file))
    slots = load_status(Path(args.slot_status_json))

    errors = []
    warnings = []

    tunnel_ip = str(payload.get("tunnel_ip", ""))
    slot_code = str(payload.get("slot_code", ""))
    selector_class = str(payload.get("selector_class", ""))
    selector_label = str(payload.get("selector_label", ""))
    fwmark = str(payload.get("fwmark", ""))
    table_id = payload.get("table_id")
    interface_name = str(payload.get("interface_name", ""))
    dry_run_allow_missing_peer = bool(payload.get("dry_run_allow_missing_peer", False))

    try:
        ipaddress.ip_address(tunnel_ip)
    except Exception:
        errors.append("invalid_tunnel_ip")

    expected = EXPECTED.get(slot_code)
    if not expected:
        errors.append("unknown_slot_code")
    else:
        for key in ("selector_class", "selector_label", "fwmark", "table_id", "interface_name"):
            if payload.get(key) != expected[key]:
                errors.append(f"mapping_mismatch_{key}")

    slot_status = slots.get(slot_code)
    if not slot_status:
        errors.append("slot_status_missing")
    else:
        if slot_status.get("status") != "healthy":
            errors.append("slot_not_healthy")
        for key in ("selector_class", "fwmark", "table_id", "interface_name"):
            if slot_status.get(key) != payload.get(key):
                errors.append(f"slot_status_mismatch_{key}")

    exact_line = f"{tunnel_ip} {selector_class} {selector_label}"

    valid_entries = [e for e in entries if e.get("valid")]
    exact_present = any(e["raw"] == exact_line for e in valid_entries)

    same_ip_conflicts = [
        e for e in valid_entries
        if e.get("tunnel_ip") == tunnel_ip and e["raw"] != exact_line
    ]
    same_class_conflicts = [
        e for e in valid_entries
        if e.get("selector_class") == selector_class and e["raw"] != exact_line
    ]
    same_label_conflicts = [
        e for e in valid_entries
        if e.get("selector_label") == selector_label and e["raw"] != exact_line
    ]

    if same_ip_conflicts:
        errors.append("same_ip_conflict")
    if same_class_conflicts:
        errors.append("same_selector_class_conflict")
    if same_label_conflicts:
        errors.append("same_selector_label_conflict")

    would_append = not exact_present and not errors
    idempotent_noop = exact_present and not errors

    simulated_entries = len(valid_entries) + (1 if would_append else 0)

    result = {
        "schema": "wg-access-agent-selector-contract-dry-run-v1",
        "contract_valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "payload": payload,
        "exact_line": exact_line,
        "selector_entry_count_before": len(valid_entries),
        "selector_entry_count_after_simulated": simulated_entries,
        "exact_present": exact_present,
        "would_append": would_append,
        "idempotent_noop": idempotent_noop,
        "dry_run_allow_missing_peer": dry_run_allow_missing_peer,
        "slot_status": slot_status.get("status") if slot_status else "",
        "same_ip_conflict_count": len(same_ip_conflicts),
        "same_selector_class_conflict_count": len(same_class_conflicts),
        "same_selector_label_conflict_count": len(same_label_conflicts),
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        for k, v in result.items():
            if isinstance(v, (dict, list)):
                continue
            print(f"{k}={v}")

    raise SystemExit(0 if not errors else 2)

if __name__ == "__main__":
    main()
