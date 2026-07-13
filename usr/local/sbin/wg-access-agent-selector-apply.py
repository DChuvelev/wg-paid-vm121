#!/usr/bin/env python3
import argparse
import ipaddress
import json
import sys
from pathlib import Path

EXPECTED = {
    "vpn1": {"selector_class": "cs4", "selector_label": "canary_vpn1", "fwmark": "0x201", "table_id": 201, "interface_name": "vpn1"},
    "vpn2": {"selector_class": "cs5", "selector_label": "canary_vpn2", "fwmark": "0x202", "table_id": 202, "interface_name": "vpn2"},
    "vpn3": {"selector_class": "cs1", "selector_label": "canary_vpn3", "fwmark": "0x203", "table_id": 203, "interface_name": "vpn3"},
    "vpn4": {"selector_class": "cs2", "selector_label": "canary_vpn4", "fwmark": "0x204", "table_id": 204, "interface_name": "vpn4"},
    "vpn5": {"selector_class": "cs3", "selector_label": "canary_vpn5", "fwmark": "0x205", "table_id": 205, "interface_name": "vpn5"},
}

def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))

def parse_selector(path):
    entries = []
    raw_lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    for line_no, raw in enumerate(raw_lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            entries.append({"line_no": line_no, "raw": line, "valid": False})
            continue
        entries.append({
            "line_no": line_no,
            "raw": line,
            "valid": True,
            "tunnel_ip": parts[0],
            "selector_class": parts[1],
            "selector_label": parts[2],
        })
    return entries

def load_slots(status_json):
    data = load_json(status_json)
    return {slot.get("slot_code"): slot for slot in data.get("slots", [])}

def validate_and_plan(payload, selector_entries, slots, require_peer_visible=False, peer_visible=False):
    errors = []
    warnings = []

    tunnel_ip = str(payload.get("tunnel_ip", ""))
    slot_code = str(payload.get("slot_code", ""))
    selector_class = str(payload.get("selector_class", ""))
    selector_label = str(payload.get("selector_label", ""))
    fwmark = str(payload.get("fwmark", ""))
    table_id = payload.get("table_id")
    interface_name = str(payload.get("interface_name", ""))

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

    slot = slots.get(slot_code)
    if not slot:
        errors.append("slot_status_missing")
    else:
        if slot.get("status") != "healthy":
            errors.append("slot_not_healthy")
        for key in ("selector_class", "fwmark", "table_id", "interface_name"):
            if slot.get(key) != payload.get(key):
                errors.append(f"slot_status_mismatch_{key}")

    if require_peer_visible and not peer_visible:
        errors.append("wg_peer_not_visible")

    exact_line = f"{tunnel_ip} {selector_class} {selector_label}"

    valid_entries = [entry for entry in selector_entries if entry.get("valid")]
    exact_present = any(entry["raw"] == exact_line for entry in valid_entries)

    same_ip_conflicts = [
        entry for entry in valid_entries
        if entry.get("tunnel_ip") == tunnel_ip and entry["raw"] != exact_line
    ]
    same_class_conflicts = [
        entry for entry in valid_entries
        if entry.get("selector_class") == selector_class and entry["raw"] != exact_line
    ]
    same_label_conflicts = [
        entry for entry in valid_entries
        if entry.get("selector_label") == selector_label and entry["raw"] != exact_line
    ]

    if same_ip_conflicts:
        errors.append("same_ip_conflict")
    if same_class_conflicts:
        errors.append("same_selector_class_conflict")
    if same_label_conflicts:
        errors.append("same_selector_label_conflict")

    if errors:
        action = "error"
    elif exact_present:
        action = "noop"
    else:
        action = "append"

    return {
        "schema": "wg-access-agent-selector-apply-plan-v1",
        "contract_valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "action": action,
        "exact_line": exact_line,
        "selector_entry_count_before": len(valid_entries),
        "selector_entry_count_after_planned": len(valid_entries) + (1 if action == "append" else 0),
        "exact_present": exact_present,
        "would_append": action == "append",
        "idempotent_noop": action == "noop",
        "same_ip_conflict_count": len(same_ip_conflicts),
        "same_selector_class_conflict_count": len(same_class_conflicts),
        "same_selector_label_conflict_count": len(same_label_conflicts),
        "slot_status": slot.get("status") if slot else "",
        "payload_summary": {
            "peer_id": payload.get("peer_id", ""),
            "subscription_id": payload.get("subscription_id", ""),
            "tunnel_ip": tunnel_ip,
            "slot_code": slot_code,
            "selector_class": selector_class,
            "selector_label": selector_label,
            "fwmark": fwmark,
            "table_id": table_id,
            "interface_name": interface_name,
            "provider_type": payload.get("provider_type", ""),
            "manager_id": payload.get("manager_id", ""),
        },
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", required=True)
    parser.add_argument("--selector-file", required=True)
    parser.add_argument("--slot-status-json", required=True)
    parser.add_argument("--mode", choices=["dry-run", "apply-local"], default="dry-run")
    parser.add_argument("--output-json", action="store_true")
    args = parser.parse_args()

    payload = load_json(args.payload)
    selector_entries = parse_selector(Path(args.selector_file))
    slots = load_slots(Path(args.slot_status_json))

    plan = validate_and_plan(payload, selector_entries, slots)

    plan["mode"] = args.mode
    plan["apply_performed"] = False

    if args.mode == "apply-local":
        if not plan["contract_valid"]:
            pass
        elif plan["action"] == "append":
            selector_path = Path(args.selector_file)
            text = selector_path.read_text(encoding="utf-8", errors="replace")
            if text and not text.endswith("\n"):
                text += "\n"
            text += plan["exact_line"] + "\n"
            selector_path.write_text(text, encoding="utf-8")
            plan["apply_performed"] = True
        elif plan["action"] == "noop":
            plan["apply_performed"] = False

    if args.output_json:
        print(json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        for key, value in plan.items():
            if isinstance(value, (dict, list)):
                continue
            print(f"{key}={value}")

    return 0 if plan["contract_valid"] else 2

if __name__ == "__main__":
    raise SystemExit(main())
