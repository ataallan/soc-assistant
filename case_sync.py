"""
External ticket sync adapter for SOC cases.

Modes (CASE_SYNC_MODE in .env):
  simulated — default. Allocate a local synthetic ticket id; no HTTP.
  stub      — optional HTTP POST to CASE_SYNC_STUB_URL, then store ids.
              If URL is empty, log_only stub (still no network).
  jira      — like stub but labels external_system=jira; optional
              JIRA_BASE_URL used to build browse URL when no stub response.

Never logs secrets (CASE_SYNC_STUB_TOKEN / JIRA_API_TOKEN).
"""

from __future__ import annotations

import os
import uuid
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

from db import append_audit, ensure_db_ready, get_case, update_case_external  # noqa: E402

VALID_MODES = frozenset({"simulated", "stub", "jira"})


def get_mode() -> str:
    mode = (os.environ.get("CASE_SYNC_MODE") or "simulated").strip().lower()
    if mode not in VALID_MODES:
        return "simulated"
    return mode


def get_stub_url() -> str:
    return (os.environ.get("CASE_SYNC_STUB_URL") or "").strip()


def get_jira_base_url() -> str:
    return (os.environ.get("JIRA_BASE_URL") or "").strip().rstrip("/")


def stub_token_configured() -> bool:
    """Whether a Bearer token is set (never returns the token)."""
    return bool(
        (os.environ.get("CASE_SYNC_STUB_TOKEN") or "").strip()
        or (os.environ.get("JIRA_API_TOKEN") or "").strip()
    )


def get_mode_label() -> str:
    return {
        "simulated": "Simulated ticket sync",
        "stub": "Stub ticket sync",
        "jira": "Jira ticket sync",
    }[get_mode()]


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
        out["response_preview"] = str(info["body"])[:200]
    if info.get("auth_configured") is not None:
        out["auth_configured"] = bool(info["auth_configured"])
    if info.get("external_ticket_id"):
        out["external_ticket_id"] = info["external_ticket_id"]
    return out


def _stub_headers() -> Dict[str, str]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    token = (
        (os.environ.get("CASE_SYNC_STUB_TOKEN") or "").strip()
        or (os.environ.get("JIRA_API_TOKEN") or "").strip()
    )
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _build_payload(case: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "action": "create_or_sync_ticket",
        "source": "soc_assistant",
        "case_id": case.get("id"),
        "title": case.get("title"),
        "severity": case.get("severity"),
        "status": case.get("status"),
        "summary": (case.get("summary") or "")[:500],
        "ip": case.get("ip"),
        "user_entity": case.get("user_entity"),
        "assignee": case.get("assignee"),
    }


def _body_summary(case: Dict[str, Any]) -> Dict[str, Any]:
    """Operator-facing request summary — never includes secrets."""
    return {
        "action": "create_or_sync_ticket",
        "case_id": case.get("id"),
        "title": case.get("title"),
        "severity": case.get("severity"),
        "source": "soc_assistant",
        "auth": "bearer" if stub_token_configured() else "none",
    }


def _parse_ticket_from_response(body: str, fallback_id: str) -> str:
    text = (body or "").strip()
    if not text:
        return fallback_id
    # Prefer simple JSON keys if present
    try:
        import json

        data = json.loads(text)
        for key in ("key", "id", "ticket_id", "external_ticket_id"):
            if data.get(key):
                return str(data[key])
    except Exception:
        pass
    return fallback_id


def _http_sync(case: Dict[str, Any], *, system: str) -> Dict[str, Any]:
    url = get_stub_url()
    payload = _build_payload(case)
    auth_configured = stub_token_configured()
    fallback_id = f"{system.upper()}-{case.get('id')}-{uuid.uuid4().hex[:8]}"
    if not url:
        return {
            "ok": True,
            "stub": "log_only",
            "payload": payload,
            "auth_configured": auth_configured,
            "external_ticket_id": fallback_id,
            "external_url": None,
        }
    try:
        resp = requests.post(url, json=payload, headers=_stub_headers(), timeout=5)
        ticket_id = _parse_ticket_from_response(resp.text, fallback_id)
        return {
            "ok": 200 <= resp.status_code < 300,
            "stub": "http",
            "status_code": resp.status_code,
            "payload": payload,
            "body": resp.text[:500],
            "auth_configured": auth_configured,
            "external_ticket_id": ticket_id,
            "external_url": None,
        }
    except Exception as e:
        return {
            "ok": False,
            "stub": "http",
            "error": str(e),
            "payload": payload,
            "auth_configured": auth_configured,
            "external_ticket_id": None,
            "external_url": None,
        }


def _browse_url(system: str, ticket_id: str) -> Optional[str]:
    if not ticket_id:
        return None
    if system == "jira":
        base = get_jira_base_url()
        if base:
            return f"{base}/browse/{ticket_id}"
    stub = get_stub_url()
    if stub and system == "stub":
        return f"{stub.rstrip('/')}/tickets/{ticket_id}"
    return None


def _audit(action: str, case_id: int, result: Dict[str, Any], mode: str) -> None:
    try:
        ensure_db_ready()
        public = _public_stub_result(result)
        append_audit(
            action,
            "case",
            str(case_id),
            mode=mode,
            detail={"result": public},
        )
    except Exception:
        # Audit is best-effort; never fail the sync path on audit errors.
        pass


def sync_case(
    case_id: int,
    *,
    db_path=None,
    actor: Optional[str] = None,
) -> Dict[str, Any]:
    """Sync a case to the configured external ticket system.

    Returns a public dict (no secrets) with ok, mode, message, and ticket fields.
    """
    case = get_case(int(case_id), include_notes=False, db_path=db_path)
    if case is None:
        return {"ok": False, "message": f"Case #{case_id} not found.", "mode": get_mode()}

    mode = get_mode()
    system = mode if mode != "simulated" else "simulated"

    if mode == "simulated":
        ticket_id = f"SIM-{case['id']}-{uuid.uuid4().hex[:8]}"
        external_url = None
        stub_info = {
            "ok": True,
            "stub": "simulated",
            "external_ticket_id": ticket_id,
            "auth_configured": False,
        }
        ok = True
        message = f"Simulated ticket {ticket_id} linked to case #{case_id}."
    else:
        stub_info = _http_sync(case, system=system)
        ok = bool(stub_info.get("ok"))
        ticket_id = stub_info.get("external_ticket_id")
        external_url = stub_info.get("external_url")
        if ok and ticket_id and not external_url:
            external_url = _browse_url(system, ticket_id)
        if ok:
            message = f"Synced case #{case_id} → {system}:{ticket_id}."
        else:
            err = stub_info.get("error") or f"HTTP {stub_info.get('status_code')}"
            message = f"Ticket sync failed: {err}"

    if ok and ticket_id:
        updated = update_case_external(
            int(case_id),
            external_ticket_id=str(ticket_id),
            external_system=system,
            external_url=external_url,
            db_path=db_path,
        )
    else:
        updated = case

    _audit("case_ticket_sync", int(case_id), stub_info, mode)

    out: Dict[str, Any] = {
        "ok": ok,
        "mode": mode,
        "mode_label": get_mode_label(),
        "message": message,
        "case_id": int(case_id),
        "external_ticket_id": updated.get("external_ticket_id") if ok else None,
        "external_system": updated.get("external_system") if ok else None,
        "external_url": updated.get("external_url") if ok else None,
        "stub": _public_stub_result(stub_info),
        "body_summary": _body_summary(case),
        "would_call_url": get_stub_url() or None,
        "auth_configured": stub_token_configured(),
        "actor": actor,
    }
    return out
