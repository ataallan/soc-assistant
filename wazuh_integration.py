# wazuh_integration.py
"""
Robust Wazuh API integration for Wazuh 4.x (including 4.14).

Features:
- Authenticates once with /security/user/authenticate (JWT)
- Auto-refreshes token on 401
- Tries multiple likely endpoints for alerts (auto-detect)
- Returns a list of alert strings (best-effort)
- Reads credentials from environment variables if provided
"""

import os
import requests
import time
from typing import List, Any, Optional

# disable insecure warning (local/dev only)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==== Configuration (override with env vars in production) ====
WAZUH_API = os.getenv("WAZUH_API", "https://localhost:55000")
API_USER = os.getenv("WAZUH_USER", "wazuh")
API_PASS = os.getenv("WAZUH_PASS", "")  # required via env for live Wazuh
_TOKEN = None
_TOKEN_EXP = 0.0  # optional expiry time if needed

# endpoints to try (in order). We'll stop on first working one.
_ALERT_ENDPOINT_CANDIDATES = [
    "/manager/logs",         # used in many 4.14 setups (manager logs/events)
    "/manager/alerts",       # older/alternate
    "/alerts",               # older versions
    #"/manager/events",       # alternative
   # "/events",
    "/manager/agents/{agent}/logs",   # per-agent (needs agent id)
    "/agents/{agent}/alerts"          # per-agent older
]

# helper: full url builder
def _url(path: str) -> str:
    if path.startswith("/"):
        return f"{WAZUH_API}{path}"
    return f"{WAZUH_API}/{path}"

# --------------------
# Authentication
# --------------------
def get_token(force_refresh: bool = False) -> Optional[str]:
    """
    Authenticate with Wazuh and return JWT token. Caches token in-module.
    If force_refresh=True, always re-request.
    """
    global _TOKEN, _TOKEN_EXP
    if _TOKEN and not force_refresh:
        # simple expiry guard - could add real expiry parsing if JWT used
        # we use a naive 50-minute reuse safe window if _TOKEN_EXP set
        if _TOKEN_EXP == 0 or time.time() < _TOKEN_EXP:
            return _TOKEN

    auth_url = _url("/security/user/authenticate")
    try:
        resp = requests.get(auth_url, auth=(API_USER, API_PASS), verify=False, timeout=10)
        if resp.status_code == 200:
            j = resp.json()
            token = j.get("data", {}).get("token")
            if token:
                _TOKEN = token
                # Many Wazuh tokens last about 1 hour; set safe expiry (50 min)
                _TOKEN_EXP = time.time() + (50 * 60)
                return _TOKEN
            else:
                print("⚠️ Authentication succeeded but no token found in response.")
                return None
        else:
            print(f"⚠️ Wazuh authenticate failed ({resp.status_code}): {resp.text}")
            return None
    except Exception as e:
        print(f"⚠️ Error getting Wazuh token: {e}")
        return None

# --------------------
# Endpoint detection
# --------------------
def _probe_endpoint(path: str, token: Optional[str]) -> bool:
    """
    Return True if endpoint gives 200 (or 2xx) and a JSON structure we can use.
    """
    url = _url(path)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = requests.get(url, headers=headers, verify=False, timeout=8)
        return 200 <= r.status_code < 300
    except Exception:
        return False

def _detect_working_alert_endpoint(token: Optional[str]) -> Optional[str]:
    """
    Try candidate endpoints and return the first one that responds OK.
    Caches nothing in file — quick probe each call is fine for small uses.
    """
    # prefer manager/logs first
    for candidate in _ALERT_ENDPOINT_CANDIDATES:
        # if candidate requires an agent placeholder skip here (we don't probe per-agent)
        if "{agent}" in candidate:
            continue
        if _probe_endpoint(candidate, token):
            return candidate
    return None

# --------------------
# Fetch alerts
# --------------------
def fetch_wazuh_alerts(limit: int = 5) -> List[str]:
    """
    Fetch alerts (best-effort) and return a list of strings (one per alert).
    Tries token authentication first, falls back to basic auth if needed.
    """
    # get token (preferred)
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    # pick endpoint
    endpoint = _detect_working_alert_endpoint(token)
    if not endpoint:
        # fallback: try /alerts using basic auth (older installs)
        try:
            resp = requests.get(_url("/alerts"), auth=(API_USER, API_PASS), verify=False, params={"limit": limit}, timeout=10)
            if resp.status_code == 200:
                return _parse_alerts_response(resp.json())
            else:
                print(f"⚠️ No working alert endpoint detected and /alerts returned {resp.status_code}: {resp.text}")
                return []
        except Exception as e:
            print(f"⚠️ Error fetching /alerts fallback: {e}")
            return []

    url = _url(endpoint)
    try:
        resp = requests.get(url, headers=headers, verify=False, params={"limit": limit}, timeout=10)
        # handle unauthorized -> refresh token once
        if resp.status_code == 401:
            token = get_token(force_refresh=True)
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            resp = requests.get(url, headers=headers, verify=False, params={"limit": limit}, timeout=10)

        if resp.status_code != 200:
            print(f"⚠️ Failed to fetch Wazuh alerts from {endpoint}: {resp.status_code} {resp.text}")
            return []

        return _parse_alerts_response(resp.json())
    except Exception as e:
        print(f"⚠️ Error connecting to Wazuh at {url}: {e}")
        return []

def _parse_alerts_response(resp_json: Any) -> List[str]:
    """
    Normalize the JSON response to a list of useful alert strings.
    Attempts several common response shapes.
    """
    results: List[str] = []
    if not isinstance(resp_json, dict):
        return [str(resp_json)]

    # Common Wazuh shapes:
    # 1) {"data": {"affected_items": [ {...}, ...]}}
    # 2) {"data": {"items": [ {...}, ...]}}
    # 3) {"data": [ {...}, ... ]}
    # We'll try those, and extract a "full_log" or "raw" or stringify fallback.

    data = resp_json.get("data", resp_json)

    items = None
    if isinstance(data, dict):
        items = data.get("affected_items") or data.get("items") or data.get("affectedItems") or data.get("events")
    elif isinstance(data, list):
        items = data

    if not items:
        # maybe the root contains 'items' top-level
        items = resp_json.get("items") or resp_json.get("affected_items") or resp_json.get("affectedItems")

    if not items:
        # no list found — fallback: stringify entire json
        return [str(resp_json)]

    # iterate items
    for it in items:
        if isinstance(it, dict):
            # common fields that hold a readable message
            if it.get("full_log"):
                results.append(it.get("full_log"))
            elif it.get("raw"):
                results.append(it.get("raw"))
            elif it.get("full_log_plain"):
                results.append(it.get("full_log_plain"))
            else:
                # try to combine some useful fields
                # timestamps and rule/agent info often helpful
                pieces = []
                if it.get("timestamp"):
                    pieces.append(str(it.get("timestamp")))
                if it.get("agent") and isinstance(it.get("agent"), dict):
                    pieces.append(it["agent"].get("name") or it["agent"].get("id"))
                # include rule or decoder if present
                if it.get("rule") and isinstance(it.get("rule"), dict):
                    pieces.append(it["rule"].get("description") or it["rule"].get("id"))
                # fallback to stringified dict
                if not pieces:
                    results.append(str(it))
                else:
                    pieces.append(it.get("full_log") or str(it))
                    results.append(" | ".join([p for p in pieces if p]))
        else:
            results.append(str(it))

    return results
