"""Normalize heterogeneous alert inputs into a stable internal alert dict.

Never raises on bad input; returns a defensive default structure.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional


STABLE_FIELDS = (
    "tenant_id",
    "source",
    "event_id",
    "timestamp",
    "rule_id",
    "rule_description",
    "severity_hint",
    "src_ip",
    "dst_ip",
    "user",
    "host",
    "mitre_technique",
    "raw_message",
    "extras",
)


def _blank_alert() -> Dict[str, Any]:
    return {
        "tenant_id": "local",
        "source": "unknown",
        "event_id": None,
        "timestamp": None,
        "rule_id": None,
        "rule_description": None,
        "severity_hint": None,
        "src_ip": None,
        "dst_ip": None,
        "user": None,
        "host": None,
        "mitre_technique": None,
        "raw_message": "",
        "extras": {},
    }


def _as_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        if isinstance(value, float) and value != value:  # NaN
            return None
    except Exception:
        pass
    text = str(value).strip()
    if not text or text.lower() in ("nan", "none", "null"):
        return None
    return text


def _dig(obj: Any, *paths: str) -> Any:
    """Return first non-empty value for dotted paths (dict-only)."""
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


def _infer_source(raw: Dict[str, Any]) -> str:
    explicit = _as_str(raw.get("source"))
    if explicit:
        return explicit.lower()
    if any(k in raw for k in ("full_log", "rule", "agent", "rule_id", "rule_level")):
        return "wazuh"
    if any(k in raw for k in ("event_type", "description", "source_ip", "username")):
        return "csv"
    if "log" in raw or "raw_message" in raw:
        return "log"
    return "unknown"


def _build_raw_message(raw: Dict[str, Any], fields: Dict[str, Any]) -> str:
    candidates = [
        raw.get("raw_message"),
        raw.get("full_log"),
        raw.get("summary"),
        raw.get("log"),
        raw.get("message"),
        raw.get("description"),
    ]
    for c in candidates:
        s = _as_str(c)
        if s:
            return s

    parts = []
    for key in ("event_type", "description", "username", "source_ip"):
        val = _as_str(raw.get(key))
        if val:
            parts.append(val)
    if parts:
        return " ".join(parts)

    # Last resort: compact known fields
    bits = []
    for k in ("rule_description", "host", "user", "src_ip"):
        if fields.get(k):
            bits.append(str(fields[k]))
    return " ".join(bits) if bits else ""


def normalize_alert(raw: Any, *, tenant_id: str = "local") -> Dict[str, Any]:
    """Convert Wazuh-ish dicts, CSV rows, or plain strings into a stable alert.

    Always returns a dict with STABLE_FIELDS; never raises.
    """
    out = _blank_alert()
    try:
        out["tenant_id"] = _as_str(tenant_id) or "local"

        if raw is None:
            return out

        if isinstance(raw, str):
            out["source"] = "log"
            out["raw_message"] = raw.strip()
            out["timestamp"] = datetime.now(timezone.utc).isoformat()
            return out

        # pandas Series / mapping-like
        if hasattr(raw, "to_dict") and callable(getattr(raw, "to_dict")):
            try:
                raw = raw.to_dict()
            except Exception:
                raw = dict(raw) if hasattr(raw, "items") else {"raw_message": str(raw)}

        if not isinstance(raw, dict):
            out["raw_message"] = str(raw)
            out["source"] = "log"
            return out

        out["source"] = _infer_source(raw)
        out["tenant_id"] = _as_str(raw.get("tenant_id")) or out["tenant_id"]

        out["event_id"] = _as_str(
            _dig(raw, "event_id", "id", "alert_id") or raw.get("event_id")
        )
        out["timestamp"] = _as_str(
            _dig(raw, "timestamp", "time", "@timestamp") or raw.get("timestamp")
        )

        rule_id = _dig(raw, "rule.id", "rule_id") or raw.get("rule_id")
        out["rule_id"] = _as_str(rule_id)

        rule_desc = (
            _dig(raw, "rule.description", "rule_description")
            or raw.get("rule_description")
            or raw.get("description")
            or raw.get("event_type")
        )
        out["rule_description"] = _as_str(rule_desc)

        sev_hint = (
            raw.get("severity_hint")
            or raw.get("severity")
            or raw.get("wazuh_severity")
            or _dig(raw, "rule.level")
            or raw.get("rule_level")
        )
        out["severity_hint"] = _as_str(sev_hint)

        src_ip = (
            raw.get("src_ip")
            or raw.get("source_ip")
            or raw.get("srcip")
            or _dig(raw, "data.srcip", "data.src_ip")
            or raw.get("ip")
        )
        out["src_ip"] = _as_str(src_ip)

        dst_ip = (
            raw.get("dst_ip")
            or raw.get("destination_ip")
            or raw.get("dstip")
            or _dig(raw, "data.dstip", "data.dst_ip")
        )
        out["dst_ip"] = _as_str(dst_ip)

        user = (
            raw.get("user")
            or raw.get("username")
            or _dig(raw, "data.srcuser", "data.dstuser", "data.user")
        )
        out["user"] = _as_str(user)

        host = (
            raw.get("host")
            or raw.get("agent")
            or raw.get("hostname")
            or _dig(raw, "agent.name", "agent.id")
        )
        if isinstance(host, dict):
            host = host.get("name") or host.get("id")
        out["host"] = _as_str(host)

        mitre = (
            raw.get("mitre_technique")
            or raw.get("mitre")
            or _dig(raw, "rule.mitre.id", "rule.mitre.technique")
        )
        if isinstance(mitre, list):
            mitre = ",".join(str(x) for x in mitre if x)
        out["mitre_technique"] = _as_str(mitre)

        out["raw_message"] = _build_raw_message(raw, out)

        # Preserve unknown keys lightly (no huge nested dumps)
        known = {
            "tenant_id",
            "source",
            "event_id",
            "id",
            "alert_id",
            "timestamp",
            "time",
            "@timestamp",
            "rule_id",
            "rule_description",
            "rule",
            "severity_hint",
            "severity",
            "wazuh_severity",
            "rule_level",
            "src_ip",
            "source_ip",
            "srcip",
            "dst_ip",
            "destination_ip",
            "dstip",
            "user",
            "username",
            "host",
            "agent",
            "hostname",
            "mitre_technique",
            "mitre",
            "raw_message",
            "full_log",
            "summary",
            "log",
            "message",
            "description",
            "event_type",
            "data",
            "extras",
            "ip",
        }
        extras: Dict[str, Any] = {}
        if isinstance(raw.get("extras"), dict):
            extras.update(raw["extras"])
        for k, v in raw.items():
            if k in known:
                continue
            if isinstance(v, (str, int, float, bool)) or v is None:
                extras[str(k)] = v
        # Useful nested snippets
        if isinstance(raw.get("rule"), dict):
            lvl = raw["rule"].get("level")
            if lvl is not None:
                extras.setdefault("rule_level", lvl)
        if isinstance(raw.get("data"), dict):
            for dk in ("srcip", "dstip", "srcuser", "dstuser"):
                if raw["data"].get(dk) is not None:
                    extras.setdefault(dk, raw["data"].get(dk))
        out["extras"] = extras

        if not out["timestamp"]:
            out["timestamp"] = datetime.now(timezone.utc).isoformat()

        return out
    except Exception:
        # Absolute last resort — never crash callers
        fallback = _blank_alert()
        try:
            fallback["raw_message"] = str(raw) if raw is not None else ""
        except Exception:
            fallback["raw_message"] = ""
        return fallback
