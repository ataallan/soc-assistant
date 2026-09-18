"""
Wazuh API integration for Wazuh 4.x (including 4.14).

Keeps the working approach:
- JWT auth via /security/user/authenticate
- Auto-refresh on 401
- Multi-endpoint alert probing
- Credentials from environment (.env)

Refinements:
- Brief cache of the working alert endpoint
- Structured alert dicts (rule/agent/severity) plus string list for compatibility
- Clearer message when WAZUH_PASS is missing
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Union

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_API = os.getenv("WAZUH_API", "https://localhost:55000").rstrip("/")
API_USER = os.getenv("WAZUH_USER", "wazuh")
API_PASS = os.getenv("WAZUH_PASS", "")

_TOKEN: Optional[str] = None
_TOKEN_EXP = 0.0
_LAST_AUTH_ERROR: Optional[str] = None
_CACHED_ENDPOINT: Optional[str] = None
_CACHED_ENDPOINT_EXP = 0.0
_ENDPOINT_CACHE_TTL = 300  # seconds

_ALERT_ENDPOINT_CANDIDATES = [
    "/manager/logs",
    "/manager/alerts",
    "/alerts",
    "/manager/agents/{agent}/logs",
    "/agents/{agent}/alerts",
]


def _url(path: str) -> str:
    if path.startswith("/"):
        return f"{WAZUH_API}{path}"
    return f"{WAZUH_API}/{path}"


def _credentials_ok() -> bool:
    global _LAST_AUTH_ERROR
    if not API_PASS:
        _LAST_AUTH_ERROR = "Wazuh password is not set. Add WAZUH_PASS to .env to enable live authentication."
        print("⚠️ WAZUH_PASS is not set. Add it to your .env to enable live Wazuh auth.")
        return False
    return True


def get_last_auth_error() -> Optional[str]:
    """Soft operator message from the most recent auth attempt (if any)."""
    return _LAST_AUTH_ERROR


def wazuh_api_host() -> str:
    """Return host[:port] only from WAZUH_API (no credentials)."""
    raw = (WAZUH_API or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    return raw.split("/", 1)[0] or "unknown"


def get_token(force_refresh: bool = False) -> Optional[str]:
    """Authenticate with Wazuh and return a cached JWT."""
    global _TOKEN, _TOKEN_EXP, _LAST_AUTH_ERROR
    if not _credentials_ok():
        return None

    if _TOKEN and not force_refresh and (_TOKEN_EXP == 0 or time.time() < _TOKEN_EXP):
        _LAST_AUTH_ERROR = None
        return _TOKEN

    auth_url = _url("/security/user/authenticate")
    try:
        resp = requests.get(auth_url, auth=(API_USER, API_PASS), verify=False, timeout=10)
        if resp.status_code == 200:
            token = resp.json().get("data", {}).get("token")
            if token:
                _TOKEN = token
                _TOKEN_EXP = time.time() + (50 * 60)
                _LAST_AUTH_ERROR = None
                return _TOKEN
            _LAST_AUTH_ERROR = "Authentication succeeded but no token was returned."
            print("⚠️ Authentication succeeded but no token found in response.")
            return None
        soft = f"Wazuh authentication failed (HTTP {resp.status_code})."
        _LAST_AUTH_ERROR = soft
        print(f"⚠️ Wazuh authenticate failed ({resp.status_code}): {resp.text}")
        return None
    except Exception as e:
        _LAST_AUTH_ERROR = f"Could not reach Wazuh API: {e}"
        print(f"⚠️ Error getting Wazuh token: {e}")
        return None


def _probe_endpoint(path: str, token: Optional[str]) -> bool:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = requests.get(_url(path), headers=headers, verify=False, timeout=8)
        return 200 <= r.status_code < 300
    except Exception:
        return False


def _detect_working_alert_endpoint(token: Optional[str]) -> Optional[str]:
    global _CACHED_ENDPOINT, _CACHED_ENDPOINT_EXP
    now = time.time()
    if _CACHED_ENDPOINT and now < _CACHED_ENDPOINT_EXP:
        return _CACHED_ENDPOINT

    for candidate in _ALERT_ENDPOINT_CANDIDATES:
        if "{agent}" in candidate:
            continue
        if _probe_endpoint(candidate, token):
            _CACHED_ENDPOINT = candidate
            _CACHED_ENDPOINT_EXP = now + _ENDPOINT_CACHE_TTL
            return candidate
    return None


def wazuh_level_to_severity(level: Any) -> str:
    """Map Wazuh rule level (0-15) to coarse severity."""
    try:
        lvl = int(level)
    except (TypeError, ValueError):
        return "low"
    if lvl >= 12:
        return "critical"
    if lvl >= 10:
        return "high"
    if lvl >= 7:
        return "medium"
    return "low"


def _extract_items(resp_json: Any) -> List[Any]:
    if not isinstance(resp_json, dict):
        return [resp_json]
    data = resp_json.get("data", resp_json)
    items = None
    if isinstance(data, dict):
        items = (
            data.get("affected_items")
            or data.get("items")
            or data.get("affectedItems")
            or data.get("events")
        )
    elif isinstance(data, list):
        items = data
    if not items:
        items = (
            resp_json.get("items")
            or resp_json.get("affected_items")
            or resp_json.get("affectedItems")
        )
    return items or []


def _first_nonempty(*values: Any) -> Optional[Any]:
    for v in values:
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        return v
    return None


def _dig_dict(obj: Any, *paths: str) -> Any:
    """Return first non-empty value for dotted paths within dicts."""
    for path in paths:
        cur = obj
        ok = True
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                ok = False
                break
            cur = cur[part]
        if not ok:
            continue
        if cur is None or cur == "":
            continue
        return cur
    return None


def _derive_alert_entities(it: Dict[str, Any], agent: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Preserve/derive canonical src_ip, dst_ip, user, host from Wazuh JSON."""
    data = it.get("data") if isinstance(it.get("data"), dict) else {}

    src_ip = _first_nonempty(
        it.get("src_ip"),
        it.get("srcip"),
        it.get("source_ip"),
        data.get("srcip"),
        data.get("src_ip"),
        data.get("srcip"),
        _dig_dict(it, "data.srcip", "data.src_ip", "data.srcip"),
        _dig_dict(it, "win.eventdata.ipAddress", "win.eventdata.IpAddress"),
        _dig_dict(data, "win.eventdata.ipAddress", "win.eventdata.IpAddress"),
        data.get("ipAddress"),
        data.get("IpAddress"),
    )
    dst_ip = _first_nonempty(
        it.get("dst_ip"),
        it.get("dstip"),
        it.get("destination_ip"),
        data.get("dstip"),
        data.get("dst_ip"),
        _dig_dict(it, "data.dstip", "data.dst_ip"),
        _dig_dict(it, "win.eventdata.destAddress", "win.eventdata.DestAddress"),
        data.get("destAddress"),
        data.get("DestAddress"),
    )
    user = _first_nonempty(
        it.get("user"),
        it.get("username"),
        data.get("srcuser"),
        data.get("dstuser"),
        data.get("user"),
        _dig_dict(it, "data.srcuser", "data.dstuser", "data.user"),
        _dig_dict(it, "win.eventdata.targetUserName", "win.eventdata.TargetUserName",
                  "win.eventdata.subjectUserName", "win.eventdata.SubjectUserName"),
        _dig_dict(data, "win.eventdata.targetUserName", "win.eventdata.TargetUserName",
                  "win.eventdata.subjectUserName", "win.eventdata.SubjectUserName"),
        data.get("targetUserName"),
        data.get("TargetUserName"),
        data.get("subjectUserName"),
        data.get("SubjectUserName"),
    )
    host = _first_nonempty(
        it.get("host"),
        it.get("hostname"),
        agent.get("name"),
        agent.get("id"),
        agent.get("ip"),
        _dig_dict(it, "agent.name", "agent.id"),
    )

    def _as_opt_str(v: Any) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip()
        return s or None

    return {
        "src_ip": _as_opt_str(src_ip),
        "dst_ip": _as_opt_str(dst_ip),
        "user": _as_opt_str(user),
        "host": _as_opt_str(host),
    }


def _structure_alert(it: Any) -> Dict[str, Any]:
    if not isinstance(it, dict):
        text = str(it)
        return {
            "timestamp": None,
            "agent": None,
            "rule_id": None,
            "rule_level": None,
            "rule_description": None,
            "severity": "low",
            "full_log": text,
            "summary": text,
            "src_ip": None,
            "dst_ip": None,
            "user": None,
            "host": None,
        }

    rule = it.get("rule") if isinstance(it.get("rule"), dict) else {}
    agent = it.get("agent") if isinstance(it.get("agent"), dict) else {}
    level = rule.get("level")
    desc = rule.get("description") or rule.get("id")
    agent_name = agent.get("name") or agent.get("id")
    full_log = it.get("full_log") or it.get("raw") or it.get("full_log_plain") or ""
    timestamp = it.get("timestamp")
    entities = _derive_alert_entities(it, agent)

    pieces = [p for p in [timestamp, agent_name, desc, full_log] if p]
    summary = " | ".join(str(p) for p in pieces) if pieces else str(it)

    return {
        "timestamp": timestamp,
        "agent": agent_name,
        "rule_id": rule.get("id"),
        "rule_level": level,
        "rule_description": desc,
        "severity": wazuh_level_to_severity(level),
        "full_log": full_log or summary,
        "summary": summary,
        "src_ip": entities["src_ip"],
        "dst_ip": entities["dst_ip"],
        "user": entities["user"],
        "host": entities["host"] or (str(agent_name).strip() if agent_name else None),
    }


def _parse_alerts_structured(resp_json: Any) -> List[Dict[str, Any]]:
    items = _extract_items(resp_json)
    if not items:
        return [{"timestamp": None, "agent": None, "rule_id": None, "rule_level": None,
                 "rule_description": None, "severity": "low", "full_log": str(resp_json),
                 "summary": str(resp_json), "src_ip": None, "dst_ip": None,
                 "user": None, "host": None}]
    return [_structure_alert(it) for it in items]


def _request_alerts_json(limit: int) -> Optional[Any]:
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    endpoint = _detect_working_alert_endpoint(token)

    if not endpoint:
        try:
            resp = requests.get(
                _url("/alerts"),
                auth=(API_USER, API_PASS) if API_PASS else None,
                verify=False,
                params={"limit": limit},
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
            print(f"⚠️ No working alert endpoint and /alerts returned {resp.status_code}: {resp.text}")
            return None
        except Exception as e:
            print(f"⚠️ Error fetching /alerts fallback: {e}")
            return None

    url = _url(endpoint)
    try:
        resp = requests.get(url, headers=headers, verify=False, params={"limit": limit}, timeout=10)
        if resp.status_code == 401:
            global _CACHED_ENDPOINT, _CACHED_ENDPOINT_EXP
            _CACHED_ENDPOINT = None
            _CACHED_ENDPOINT_EXP = 0
            token = get_token(force_refresh=True)
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            resp = requests.get(url, headers=headers, verify=False, params={"limit": limit}, timeout=10)

        if resp.status_code != 200:
            print(f"⚠️ Failed to fetch Wazuh alerts from {endpoint}: {resp.status_code} {resp.text}")
            return None
        return resp.json()
    except Exception as e:
        print(f"⚠️ Error connecting to Wazuh at {url}: {e}")
        return None


def fetch_wazuh_alert_details(limit: int = 5) -> List[Dict[str, Any]]:
    """Return structured alert dicts for UI / triage."""
    payload = _request_alerts_json(limit)
    if payload is None:
        return []
    return _parse_alerts_structured(payload)


def fetch_wazuh_alerts(limit: int = 5) -> List[str]:
    """Backward-compatible: list of alert summary strings."""
    return [a.get("summary") or a.get("full_log") or str(a) for a in fetch_wazuh_alert_details(limit)]
