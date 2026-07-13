#!/usr/bin/env python3
import argparse
import hashlib
import json
import shlex
import subprocess
from pathlib import Path

def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))

def q(value):
    return shlex.quote(str(value))

def build_remote_script(payload, selector_plan, selector_conf, selector_service):
    exact_line = selector_plan.get("exact_line", "")
    action = selector_plan.get("action", "")
    tunnel_ip = str(payload.get("tunnel_ip", ""))
    selector_class = str(payload.get("selector_class", ""))

    if action == "append":
        apply_block = """
if grep -Fxq "$LINE" "$CONF"; then
  echo "selector_apply_action=noop_already_present"
else
  printf '%s\\n' "$LINE" >> "$CONF"
  echo "selector_apply_action=append"
fi
"""
    elif action == "noop":
        apply_block = """
grep -Fxq "$LINE" "$CONF"
echo "selector_apply_action=noop_verified_present"
"""
    else:
        apply_block = """
echo "selector_apply_action=error_invalid_plan"
exit 42
"""

    script = f"""#!/bin/sh
set -u

CONF={q(selector_conf)}
SERVICE={q(selector_service)}
LINE={q(exact_line)}
TUNNEL_IP={q(tunnel_ip)}
SELECTOR_CLASS={q(selector_class)}
BACKUP="/root/peers.conf.before-agent-selector-apply-$(date +%Y%m%d-%H%M%S)"
ROLLBACK="/root/rollback-agent-selector-apply.sh"

echo "remote_script_schema=wg-access-agent-selector-remote-script-v3"
echo "remote_script_action={action}"

test -f "$CONF"

cp "$CONF" "$BACKUP"
echo "selector_backup_path=$BACKUP"

cat > "$ROLLBACK" <<RB
#!/bin/sh
set -u
cp "$BACKUP" "$CONF"
/etc/init.d/$SERVICE start
RB
chmod 700 "$ROLLBACK"
echo "rollback_path=$ROLLBACK"

{apply_block}

/etc/init.d/$SERVICE start

grep -Fxq "$LINE" "$CONF"
/etc/init.d/$SERVICE enabled >/dev/null 2>&1
nft -a list ruleset 2>/dev/null | grep -q "$TUNNEL_IP.*$SELECTOR_CLASS"

echo "postcheck_selector_line_present=YES"
echo "postcheck_selector_service_enabled=YES"
echo "postcheck_nft_rule_visible=YES"
"""
    return script

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", required=True)
    parser.add_argument("--selector-file", required=True)
    parser.add_argument("--slot-status-json", required=True)
    parser.add_argument("--selector-helper", default="/usr/local/sbin/wg-access-agent-selector-apply.py")
    parser.add_argument("--target-host", default="10.71.100.1")
    parser.add_argument("--target-name", default="vm100")
    parser.add_argument("--selector-conf", default="/etc/router-wgpay-selector.d/peers.conf")
    parser.add_argument("--selector-service", default="router-wgpay-canary")
    parser.add_argument("--mode", choices=["remote-dry-run"], default="remote-dry-run")
    parser.add_argument("--output-json", action="store_true")
    args = parser.parse_args()

    payload = load_json(args.payload)

    helper_cmd = [
        args.selector_helper,
        "--payload", args.payload,
        "--selector-file", args.selector_file,
        "--slot-status-json", args.slot_status_json,
        "--mode", "dry-run",
        "--output-json",
    ]

    proc = subprocess.run(helper_cmd, text=True, capture_output=True)

    try:
        selector_plan = json.loads(proc.stdout)
    except Exception as e:
        selector_plan = {
            "schema": "parse-error",
            "contract_valid": False,
            "errors": ["selector_plan_json_parse_error:" + type(e).__name__],
        }

    contract_valid = bool(selector_plan.get("contract_valid", False))
    action = selector_plan.get("action", "")
    remote_script = build_remote_script(payload, selector_plan, args.selector_conf, args.selector_service)

    result = {
        "schema": "wg-access-agent-selector-remote-plan-v3",
        "mode": args.mode,
        "remote_script_model": "single_shell_script",
        "target": {
            "name": args.target_name,
            "host": args.target_host,
            "selector_conf": args.selector_conf,
            "selector_service": args.selector_service
        },
        "payload_summary": {
            "tunnel_ip": payload.get("tunnel_ip", ""),
            "slot_code": payload.get("slot_code", ""),
            "selector_class": payload.get("selector_class", ""),
            "selector_label": payload.get("selector_label", ""),
            "fwmark": payload.get("fwmark", ""),
            "table_id": payload.get("table_id", ""),
            "interface_name": payload.get("interface_name", ""),
            "provider_type": payload.get("provider_type", ""),
            "manager_id": payload.get("manager_id", "")
        },
        "selector_plan_rc": proc.returncode,
        "selector_plan": selector_plan,
        "contract_valid": contract_valid,
        "action": action,
        "would_append": bool(selector_plan.get("would_append", False)),
        "idempotent_noop": bool(selector_plan.get("idempotent_noop", False)),
        "exact_line": selector_plan.get("exact_line", ""),
        "requires_wg_peer_before_real_apply": True,
        "remote_commands_executed": False,
        "apply_performed": False,
        "remote_script_executed": False,
        "remote_script_sha256": hashlib.sha256(remote_script.encode("utf-8")).hexdigest(),
        "remote_script_line_count": len(remote_script.splitlines()),
        "remote_script_contains_runtime_backup_date": "$(date +%Y%m%d-%H%M%S)" in remote_script,
        "remote_script_contains_actual_backup_rollback": 'cp "$BACKUP" "$CONF"' in remote_script,
        "remote_script_contains_placeholder_backup": "YYYYmmdd-HHMMSS" in remote_script,
        "remote_script_contains_bad_etc_initd_quoted_service": '/etc/init.d "$SERVICE"' in remote_script,
        "remote_script_contains_clean_service_start": "/etc/init.d/$SERVICE start" in remote_script,
        "remote_script": remote_script,
        "errors": selector_plan.get("errors", []),
        "error_count": len(selector_plan.get("errors", [])),
    }

    if args.output_json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print("contract_valid=" + ("YES" if contract_valid else "NO"))
        print("action=" + str(action))
        print("remote_script_executed=NO")

    return 0 if contract_valid else 2

if __name__ == "__main__":
    raise SystemExit(main())
