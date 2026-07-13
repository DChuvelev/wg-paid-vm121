#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path

ORDER = ["vpn1", "vpn2", "vpn3", "vpn4", "vpn5"]

def parse_selector(path: Path):
    used_classes = set()
    used_slots_by_label = set()
    entries = []

    if not path.exists():
        return used_classes, used_slots_by_label, entries

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        tunnel_ip = parts[0]
        selector_class = parts[1]
        label = parts[2] if len(parts) >= 3 else ""

        used_classes.add(selector_class)

        m = re.search(r"(vpn[1-5])", label)
        if m:
            used_slots_by_label.add(m.group(1))

        entries.append({
            "tunnel_ip": tunnel_ip,
            "selector_class": selector_class,
            "label": label,
        })

    return used_classes, used_slots_by_label, entries

def choose_slot(status_json: Path, selector_file: Path, strategy: str):
    data = json.loads(status_json.read_text(encoding="utf-8", errors="replace"))
    slots = data.get("slots", [])

    used_classes, used_slots_by_label, selector_entries = parse_selector(selector_file)

    candidates = []
    rejected = []

    for slot in slots:
        code = slot.get("slot_code", "")
        cls = slot.get("selector_class", "")
        status = slot.get("status", "")
        enabled = slot.get("enabled", 0)

        reason = []

        if enabled != 1:
            reason.append("disabled")
        if status != "healthy":
            reason.append(f"status_{status}")
        if cls in used_classes:
            reason.append("selector_class_already_assigned")
        if code in used_slots_by_label:
            reason.append("slot_label_already_assigned")

        if reason:
            rejected.append({
                "slot_code": code,
                "selector_class": cls,
                "status": status,
                "reason": ",".join(reason),
            })
        else:
            candidates.append(slot)

    if strategy == "first_free_ordered":
        candidates.sort(key=lambda s: ORDER.index(s.get("slot_code")) if s.get("slot_code") in ORDER else 999)
    elif strategy == "highest_weight_then_order":
        candidates.sort(
            key=lambda s: (
                -int(s.get("allocation_weight", 0)),
                ORDER.index(s.get("slot_code")) if s.get("slot_code") in ORDER else 999,
            )
        )
    else:
        raise ValueError(f"unsupported strategy: {strategy}")

    selected = candidates[0] if candidates else None

    return {
        "schema": "wg-access-slot-allocation-dry-run-v1",
        "strategy": strategy,
        "source_status_schema": data.get("schema"),
        "selector_entry_count": len(selector_entries),
        "used_selector_classes": sorted(used_classes),
        "used_slots_by_label": sorted(used_slots_by_label),
        "candidate_count": len(candidates),
        "rejected_count": len(rejected),
        "rejected": rejected,
        "selected": selected,
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--status-json", required=True)
    ap.add_argument("--selector-file", required=True)
    ap.add_argument("--strategy", default="first_free_ordered")
    args = ap.parse_args()

    result = choose_slot(
        Path(args.status_json),
        Path(args.selector_file),
        args.strategy,
    )

    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
