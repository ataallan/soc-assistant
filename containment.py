"""
Containment actions for the AI SOC Assistant.

Modes (CONTAINMENT_MODE in .env):
  simulated  — default. Persist blocks to SQLite only (demo list).
  dry_run    — log intended actions; do not change the block list
               (UI label: Preview mode).
  stub|live  — call an optional HTTP stub (CONTAINMENT_STUB_URL) then
               persist locally like simulated. `live` is an alias of stub.
               Dashboard live path: preview → admin confirm → execute.
               If URL is empty, log a stub payload only (still no real firewall).

Blocks and audit live in SQLite (see db.py). Legacy JSON/JSONL files are
imported once on startup when the DB tables are empty.
"""

from __future__ import annotations

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

VALID_MODES = {"simulated", "dry_run", "stub", "live"}
INTEGRATION_MODES = frozenset({"stub", "live"})

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


def is_integration_mode(mode: Optional[str] = None) -> bool:
    """True for stub / live (HTTP integration) modes."""
    return (mode or get_mode()) in INTEGRATION_MODES


def get_mode_label() -> str:
    """Short operator-facing label (no eng/config jargon)."""
    return {
        "simulated": "Simulation mode",
        "dry_run": "Preview mode",
        "stub": "Integrated response mode",
        "live": "Integrated response mode",
    }[get_mode()]


def get_ui_notice() -> str:
    """One clean sentence for the SOC UI."""
    return {
        "simulated": (
            "Containment actions are recorded in this console for demonstration. "
            "They do not change production network controls."
        ),
        "dry_run": (
            "Preview mode is on. Actions are logged for review and are not "
            "applied to the block list."
        ),
        "stub": (
            "Response actions are sent through the configured integration "
            "endpoint after admin confirmation, then reflected in this console."
        ),
        "live": (
            "Response actions are sent through the configured integration "
            "endpoint after admin confirmation, then reflected in this console."
        ),
    }[get_mode()]


def get_stub_url() -> str:
    return (os.environ.get("CONTAINMENT_STUB_URL") or "").strip()


def stub_token_configured() -> bool:
    """Whether a Bearer token is set (never returns the token)."""
    return bool((os.environ.get("CONTAINMENT_STUB_TOKEN") or "").strip())


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


def _mode_label_short(mode: str) -> str:
    return {
        "simulated": "Simulation",
        "dry_run": "Preview",
        "stub": "Integration",
        "live": "Integration",
    }.get(mode, mode.title())


def _build_payload(action: str, target_type: str, target: str) -> Dict[str, Any]:
    return {
        "action": action,
        "target_type": target_type,
        "target": target,
        "source": "soc_assistant",
    }


def _body_summary(action: str, target_type: str, target: str) -> Dict[str, Any]:
    """Operator-facing request summary — never includes secrets."""
    return {
        "action": action,
        "target_type": target_type,
        "target": target,
        "source": "soc_assistant",
        "auth": "bearer" if stub_token_configured() else "none",
    }


def _stub_headers() -> Dict[str, str]:
    """Build HTTP headers. Token is read from env and never returned/logged."""
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    token = (os.environ.get("CONTAINMENT_STUB_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _public_stub_result(info: Dict[str, Any]) -> Dict[str, Any]:
    """Strip anything that could leak secrets from stub call metadata."""
    out: Dict[str, Any] = {
        "ok": bool(info.get("ok")),
        "stub": info.get("stub"),
    }
    if "status_code" in info:
        out["status_code"] = info["status_code"]
    if "error" in info:
        out["error"] = str(info["error"])[:300]
    if "body" in info:
        # Truncated response text only — never request Authorization
        out["response_preview"] = str(info["body"])[:200]
    if info.get("auth_configured") is not None:
        out["auth_configured"] = bool(info["auth_configured"])
    return out


def _stub_call(action: str, target_type: str, target: str) -> Dict[str, Any]:
    """Optional HTTP stub. Never claims success on a real firewall unless URL responds."""
    url = get_stub_url()
    payload = _build_payload(action, target_type, target)
    auth_configured = stub_token_configured()
    if not url:
        return {
            "ok": True,
            "stub": "log_only",
            "payload": payload,
            "auth_configured": auth_configured,
        }
    try:
        resp = requests.post(url, json=payload, headers=_stub_headers(), timeout=5)
        return {
            "ok": 200 <= resp.status_code < 300,
            "stub": "http",
            "status_code": resp.status_code,
            "payload": payload,
            "body": resp.text[:500],
            "auth_configured": auth_configured,
        }
    except Exception as e:
        return {
            "ok": False,
            "stub": "http",
            "error": str(e),
            "payload": payload,
            "auth_configured": auth_configured,
        }


def _preview(
    action: str,
    target_type: str,
    target: str,
    *,
    actor_is_admin: bool = False,
) -> Dict[str, Any]:
    """
    Build an operator-friendly preview. Never performs network I/O.
    """
    target = (target or "").strip()
    mode = get_mode()
    live = is_integration_mode(mode)
    url = get_stub_url() if live else ""
    if not target:
        return {
            "ok": False,
            "action": action,
            "target_type": target_type,
            "target": "",
            "mode": mode,
            "would_call_url": url or None,
            "body_summary": {},
            "allowed": False,
            "requires_confirm": live,
            "message": f"Empty {target_type}",
        }

    allowed = (not live) or bool(actor_is_admin)
    return {
        "ok": True,
        "action": action,
        "target_type": target_type,
        "target": target,
        "mode": mode,
        "mode_label": get_mode_label(),
        "would_call_url": url or None,
        "body_summary": _body_summary(action, target_type, target),
        "allowed": allowed,
        "requires_confirm": live,
        "auth_configured": stub_token_configured() if live else False,
        "message": (
            f"Preview: {action} {target_type} {target}"
            + (" — confirmation required before live response." if live else "")
        ),
    }


def preview_block_ip(ip: str, *, actor_is_admin: bool = False) -> Dict[str, Any]:
    return _preview("block", "ip", ip, actor_is_admin=actor_is_admin)


def preview_block_user(user: str, *, actor_is_admin: bool = False) -> Dict[str, Any]:
    return _preview("block", "user", user, actor_is_admin=actor_is_admin)


def preview_unblock_ip(ip: str, *, actor_is_admin: bool = False) -> Dict[str, Any]:
    return _preview("unblock", "ip", ip, actor_is_admin=actor_is_admin)


def preview_unblock_user(user: str, *, actor_is_admin: bool = False) -> Dict[str, Any]:
    return _preview("unblock", "user", user, actor_is_admin=actor_is_admin)


def execute_confirmed(
    action: str,
    target_type: str,
    target: str,
    *,
    confirm: bool = False,
) -> Dict[str, Any]:
    """
    Live/stub execute path used by the dashboard after preview.

    Requires confirm=True when mode is stub|live. Simulated/dry_run callers
    should use block_*/unblock_* directly (one-click).
    """
    mode = get_mode()
    action = (action or "").strip().lower()
    target_type = (target_type or "").strip().lower()
    target = (target or "").strip()

    if action not in ("block", "unblock") or target_type not in ("ip", "user"):
        return {"ok": False, "mode": mode, "message": "Invalid action or target type"}

    if is_integration_mode(mode) and not confirm:
        return {
            "ok": False,
            "mode": mode,
            "message": "Confirm required for live response.",
            "requires_confirm": True,
            "changed": False,
        }

    if action == "block" and target_type == "ip":
        return block_ip(target)
    if action == "block" and target_type == "user":
        return block_user(target)
    if action == "unblock" and target_type == "ip":
        return unblock_ip(target)
    return unblock_user(target)


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
    if is_integration_mode(mode):
        stub_info = _stub_call("block", "ip", ip)
        public = _public_stub_result(stub_info)
        if not stub_info.get("ok"):
            _audit("block", "ip", ip, "stub_failed", public)
            msg = f"[STUB FAILED] IP {ip}: {public}"
            print(msg)
            return {
                "ok": False,
                "mode": mode,
                "message": msg,
                "changed": False,
                "stub": public,
            }

    _ensure_storage()
    changed = save_block("ip", ip, mode=mode, note="block_ip")
    public = _public_stub_result(stub_info) if stub_info else None
    _audit("block", "ip", ip, "applied", {"stub": public} if public else None)
    label = _mode_label_short(mode)
    msg = f"[{label}] IP blocked in console: {ip}"
    print(msg)
    return {"ok": True, "mode": mode, "message": msg, "changed": changed, "stub": public}


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
    if is_integration_mode(mode):
        stub_info = _stub_call("unblock", "ip", ip)
        public = _public_stub_result(stub_info)
        if not stub_info.get("ok"):
            _audit("unblock", "ip", ip, "stub_failed", public)
            return {
                "ok": False,
                "mode": mode,
                "message": f"[STUB FAILED] {public}",
                "changed": False,
                "stub": public,
            }

    _ensure_storage()
    changed = remove_block("ip", ip)
    public = _public_stub_result(stub_info) if stub_info else None
    _audit("unblock", "ip", ip, "applied", {"stub": public} if public else None)
    label = _mode_label_short(mode)
    msg = f"[{label}] Unblocked IP {ip}"
    print(msg)
    return {"ok": True, "mode": mode, "message": msg, "changed": changed, "stub": public}


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
    if is_integration_mode(mode):
        stub_info = _stub_call("block", "user", user)
        public = _public_stub_result(stub_info)
        if not stub_info.get("ok"):
            _audit("block", "user", user, "stub_failed", public)
            return {
                "ok": False,
                "mode": mode,
                "message": f"[STUB FAILED] {public}",
                "changed": False,
                "stub": public,
            }

    _ensure_storage()
    changed = save_block("user", user, mode=mode, note="block_user")
    public = _public_stub_result(stub_info) if stub_info else None
    _audit("block", "user", user, "applied", {"stub": public} if public else None)
    label = _mode_label_short(mode)
    msg = f"[{label}] User blocked in console: {user}"
    print(msg)
    return {"ok": True, "mode": mode, "message": msg, "changed": changed, "stub": public}


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
    if is_integration_mode(mode):
        stub_info = _stub_call("unblock", "user", user)
        public = _public_stub_result(stub_info)
        if not stub_info.get("ok"):
            _audit("unblock", "user", user, "stub_failed", public)
            return {
                "ok": False,
                "mode": mode,
                "message": f"[STUB FAILED] {public}",
                "changed": False,
                "stub": public,
            }

    _ensure_storage()
    changed = remove_block("user", user)
    public = _public_stub_result(stub_info) if stub_info else None
    _audit("unblock", "user", user, "applied", {"stub": public} if public else None)
    label = _mode_label_short(mode)
    msg = f"[{label}] Unblocked user {user}"
    print(msg)
    return {"ok": True, "mode": mode, "message": msg, "changed": changed, "stub": public}


# Back-compat aliases used by CLI/dashboard
def execute_block_ip(ip: str):
    return block_ip(ip)


def execute_block_user(user: str):
    return block_user(user)


def execute_unblock_ip(ip: str):
    return unblock_ip(ip)


def execute_unblock_user(user: str):
    return unblock_user(user)
