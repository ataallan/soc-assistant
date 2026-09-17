"""
Containment actions for the AI SOC Assistant.

Modes (CONTAINMENT_MODE in .env):
  simulated  — default. Persist blocks to SQLite only (demo list).
  dry_run    — log intended actions; do not change the block list.
  stub       — call an optional HTTP stub (CONTAINMENT_STUB_URL) then
               persist locally like simulated. If URL is empty, log a
               stub payload only (still no real firewall).

Blocks and audit live in SQLite (see db.py). Legacy JSON/JSONL files are
imported once on startup when the DB tables are empty.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

from db import (  # noqa: E402
    append_audit,
    ensure_db_ready,
    load_blocks,
    remove_block,
    save_block,
)

# Legacy paths kept for migration helpers / docs only
DATA_DIR = Path("data")
BLOCKED_FILE = DATA_DIR / "blocked_entities.json"
AUDIT_FILE = DATA_DIR / "containment_audit.jsonl"

VALID_MODES = {"simulated", "dry_run", "stub"}

_db_ready = False


def _ensure_storage() -> None:
    global _db_ready
    if not _db_ready:
        ensure_db_ready()
        _db_ready = True


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
    """Load blocked IPs/users from SQLite."""
    try:
        _ensure_storage()
        return load_blocks()
    except Exception:
        return _empty()


def save_blocked(data: Dict[str, list]) -> None:
    """
    Replace-style save used by older callers.

    Syncs the desired ips/users lists into SQLite (add missing, remove extras).
    Prefer block_ip / unblock_ip for normal operations.
    """
    _ensure_storage()
    desired_ips = set(str(x).strip() for x in (data.get("ips") or []) if str(x).strip())
    desired_users = set(str(x).strip() for x in (data.get("users") or []) if str(x).strip())
    current = load_blocks()
    mode = get_mode()

    for ip in desired_ips:
        if ip not in current["ips"]:
            save_block("ip", ip, mode=mode, note="save_blocked sync")
    for ip in list(current["ips"]):
        if ip not in desired_ips:
            remove_block("ip", ip)

    for user in desired_users:
        if user not in current["users"]:
            save_block("user", user, mode=mode, note="save_blocked sync")
    for user in list(current["users"]):
        if user not in desired_users:
            remove_block("user", user)


def _audit(
    event: str,
    target_type: str,
    target: str,
    result: str,
    extra: Optional[dict] = None,
) -> None:
    _ensure_storage()
    detail: Dict[str, Any] = {"result": result}
    if extra:
        detail["extra"] = extra
    append_audit(
        event,
        target_type,
        target,
        mode=get_mode(),
        detail=detail,
    )


def _stub_call(action: str, target_type: str, target: str) -> Dict[str, Any]:
    """Optional HTTP stub. Never claims success on a real firewall unless URL responds."""
    url = (os.environ.get("CONTAINMENT_STUB_URL") or "").strip()
    payload = {
        "action": action,
        "target_type": target_type,
        "target": target,
        "source": "soc_assistant",
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

    _ensure_storage()
    changed = save_block("ip", ip, mode=mode, note="block_ip")
    _audit("block", "ip", ip, "applied", {"stub": stub_info} if stub_info else None)
    label = {"simulated": "Simulation", "dry_run": "Preview", "stub": "Integration"}.get(mode, mode.title())
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

    _ensure_storage()
    changed = remove_block("ip", ip)
    _audit("unblock", "ip", ip, "applied", {"stub": stub_info} if stub_info else None)
    label = {"simulated": "Simulation", "dry_run": "Preview", "stub": "Integration"}.get(mode, mode.title())
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

    _ensure_storage()
    changed = save_block("user", user, mode=mode, note="block_user")
    _audit("block", "user", user, "applied", {"stub": stub_info} if stub_info else None)
    label = {"simulated": "Simulation", "dry_run": "Preview", "stub": "Integration"}.get(mode, mode.title())
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

    _ensure_storage()
    changed = remove_block("user", user)
    _audit("unblock", "user", user, "applied", {"stub": stub_info} if stub_info else None)
    label = {"simulated": "Simulation", "dry_run": "Preview", "stub": "Integration"}.get(mode, mode.title())
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
