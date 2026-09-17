"""
Containment actions for the Capstone SOC Assistant.

Modes (CONTAINMENT_MODE in .env):
  simulated  — default. Persist blocks to local JSON only (demo list).
  dry_run    — log intended actions; do not change the block list.
  stub       — call an optional HTTP stub (CONTAINMENT_STUB_URL) then
               persist locally like simulated. If URL is empty, log a
               stub payload only (still no real firewall).

This is intentionally honest: none of these modes are a production firewall
or SOAR connector unless you point stub at a real control plane later.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

DATA_DIR = Path("data")
BLOCKED_FILE = DATA_DIR / "blocked_entities.json"
AUDIT_FILE = DATA_DIR / "containment_audit.jsonl"

VALID_MODES = {"simulated", "dry_run", "stub"}


def get_mode() -> str:
    mode = (os.environ.get("CONTAINMENT_MODE") or "simulated").strip().lower()
    if mode not in VALID_MODES:
        return "simulated"
    return mode


def get_mode_label() -> str:
    """Short operator-facing label (no eng/config jargon)."""
    return {
        "simulated": "Simulation mode",
        "dry_run": "Preview mode",
        "stub": "Integrated response mode",
    }[get_mode()]


def get_ui_notice() -> str:
    """One clean sentence for the SOC UI."""
    return {
        "simulated": "Containment actions are recorded in this console for demonstration. They do not change production network controls.",
        "dry_run": "Preview mode is on. Actions are logged for review and are not applied to the block list.",
        "stub": "Response actions are sent through the configured integration endpoint, then reflected in this console.",
    }[get_mode()]


def _empty() -> Dict[str, list]:
    return {"ips": [], "users": []}


def load_blocked() -> Dict[str, list]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not BLOCKED_FILE.exists():
        return _empty()
    try:
        data = json.loads(BLOCKED_FILE.read_text(encoding="utf-8"))
        return {
            "ips": list(data.get("ips") or []),
            "users": list(data.get("users") or []),
        }
    except Exception:
        return _empty()


def save_blocked(data: Dict[str, list]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BLOCKED_FILE.write_text(json.dumps(data, indent=4), encoding="utf-8")


def _audit(event: str, target_type: str, target: str, result: str, extra: Optional[dict] = None) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    row = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": get_mode(),
        "event": event,
        "target_type": target_type,
        "target": target,
        "result": result,
    }
    if extra:
        row["extra"] = extra
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


def _stub_call(action: str, target_type: str, target: str) -> Dict[str, Any]:
    """Optional HTTP stub. Never claims success on a real firewall unless URL responds."""
    url = (os.environ.get("CONTAINMENT_STUB_URL") or "").strip()
    payload = {
        "action": action,
        "target_type": target_type,
        "target": target,
        "source": "soc_assistant_capstone",
    }
    if not url:
        return {"ok": True, "stub": "log_only", "payload": payload}
    try:
        resp = requests.post(url, json=payload, timeout=5)
        return {
            "ok": 200 <= resp.status_code < 300,
            "stub": "http",
            "status_code": resp.status_code,
            "payload": payload,
            "body": resp.text[:500],
        }
    except Exception as e:
        return {"ok": False, "stub": "http", "error": str(e), "payload": payload}


def block_ip(ip: str) -> Dict[str, Any]:
    ip = (ip or "").strip()
    mode = get_mode()
    if not ip:
        return {"ok": False, "mode": mode, "message": "Empty IP"}

    if mode == "dry_run":
        _audit("block", "ip", ip, "dry_run")
        msg = f"[Preview] Block IP queued for review: {ip}"
        print(msg)
        return {"ok": True, "mode": mode, "message": msg, "changed": False}

    stub_info = None
    if mode == "stub":
        stub_info = _stub_call("block", "ip", ip)
        if not stub_info.get("ok"):
            _audit("block", "ip", ip, "stub_failed", stub_info)
            msg = f"[STUB FAILED] IP {ip}: {stub_info}"
            print(msg)
            return {"ok": False, "mode": mode, "message": msg, "changed": False, "stub": stub_info}

    data = load_blocked()
    changed = ip not in data["ips"]
    if changed:
        data["ips"].append(ip)
        save_blocked(data)
    _audit("block", "ip", ip, "applied", {"stub": stub_info} if stub_info else None)
    label = {"simulated":"Simulation","dry_run":"Preview","stub":"Integration"}.get(mode, mode.title())
    msg = f"[{label}] IP blocked in console: {ip}"
    print(msg)
    return {"ok": True, "mode": mode, "message": msg, "changed": changed, "stub": stub_info}


def unblock_ip(ip: str) -> Dict[str, Any]:
    ip = (ip or "").strip()
    mode = get_mode()
    if not ip:
        return {"ok": False, "mode": mode, "message": "Empty IP"}

    if mode == "dry_run":
        _audit("unblock", "ip", ip, "dry_run")
        msg = f"[Preview] Unblock IP queued for review: {ip}"
        print(msg)
        return {"ok": True, "mode": mode, "message": msg, "changed": False}

    stub_info = None
    if mode == "stub":
        stub_info = _stub_call("unblock", "ip", ip)
        if not stub_info.get("ok"):
            _audit("unblock", "ip", ip, "stub_failed", stub_info)
            return {"ok": False, "mode": mode, "message": f"[STUB FAILED] {stub_info}", "changed": False}

    data = load_blocked()
    changed = ip in data["ips"]
    if changed:
        data["ips"].remove(ip)
        save_blocked(data)
    _audit("unblock", "ip", ip, "applied", {"stub": stub_info} if stub_info else None)
    label = {"simulated":"Simulation","dry_run":"Preview","stub":"Integration"}.get(mode, mode.title())
    msg = f"[{label}] Unblocked IP {ip}"
    print(msg)
    return {"ok": True, "mode": mode, "message": msg, "changed": changed, "stub": stub_info}


def block_user(user: str) -> Dict[str, Any]:
    user = (user or "").strip()
    mode = get_mode()
    if not user:
        return {"ok": False, "mode": mode, "message": "Empty user"}

    if mode == "dry_run":
        _audit("block", "user", user, "dry_run")
        msg = f"[Preview] Block user queued for review: {user}"
        print(msg)
        return {"ok": True, "mode": mode, "message": msg, "changed": False}

    stub_info = None
    if mode == "stub":
        stub_info = _stub_call("block", "user", user)
        if not stub_info.get("ok"):
            _audit("block", "user", user, "stub_failed", stub_info)
            return {"ok": False, "mode": mode, "message": f"[STUB FAILED] {stub_info}", "changed": False}

    data = load_blocked()
    changed = user not in data["users"]
    if changed:
        data["users"].append(user)
        save_blocked(data)
    _audit("block", "user", user, "applied", {"stub": stub_info} if stub_info else None)
    label = {"simulated":"Simulation","dry_run":"Preview","stub":"Integration"}.get(mode, mode.title())
    msg = f"[{label}] User blocked in console: {user}"
    print(msg)
    return {"ok": True, "mode": mode, "message": msg, "changed": changed, "stub": stub_info}


def unblock_user(user: str) -> Dict[str, Any]:
    user = (user or "").strip()
    mode = get_mode()
    if not user:
        return {"ok": False, "mode": mode, "message": "Empty user"}

    if mode == "dry_run":
        _audit("unblock", "user", user, "dry_run")
        msg = f"[Preview] Unblock user queued for review: {user}"
        print(msg)
        return {"ok": True, "mode": mode, "message": msg, "changed": False}

    stub_info = None
    if mode == "stub":
        stub_info = _stub_call("unblock", "user", user)
        if not stub_info.get("ok"):
            _audit("unblock", "user", user, "stub_failed", stub_info)
            return {"ok": False, "mode": mode, "message": f"[STUB FAILED] {stub_info}", "changed": False}

    data = load_blocked()
    changed = user in data["users"]
    if changed:
        data["users"].remove(user)
        save_blocked(data)
    _audit("unblock", "user", user, "applied", {"stub": stub_info} if stub_info else None)
    label = {"simulated":"Simulation","dry_run":"Preview","stub":"Integration"}.get(mode, mode.title())
    msg = f"[{label}] Unblocked user {user}"
    print(msg)
    return {"ok": True, "mode": mode, "message": msg, "changed": changed, "stub": stub_info}


# Back-compat aliases used by CLI/dashboard
def execute_block_ip(ip: str):
    return block_ip(ip)


def execute_block_user(user: str):
    return block_user(user)


def execute_unblock_ip(ip: str):
    return unblock_ip(ip)


def execute_unblock_user(user: str):
    return unblock_user(user)
