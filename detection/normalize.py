"""Normalize heterogeneous alert inputs into a stable internal alert dict.

Never raises on bad input; returns a defensive default structure.
"""

from __future__ import annotations

import re
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
    "file_hash",
    "domain",
    "cve",
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
        "file_hash": None,
        "domain": None,
        "cve": None,
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


_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Conservative auth-log user phrases; avoid matching hostnames or long tokens.
_USER_PHRASE_RES = (
    re.compile(r"\binvalid user\s+([A-Za-z0-9._-]{1,64})\b", re.IGNORECASE),
    re.compile(r"\bfor user\s+([A-Za-z0-9._-]{1,64})\b", re.IGNORECASE),
    re.compile(
        r"\bfailed password for (?:invalid user\s+)?([A-Za-z0-9._-]{1,64})\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bAccepted (?:password|publickey) for ([A-Za-z0-9._-]{1,64})\b",
        re.IGNORECASE,
    ),
    re.compile(r"\buser[=:]\s*([A-Za-z0-9._-]{1,64})\b", re.IGNORECASE),
)


def _ipv4_from_text(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    m = _IPV4_RE.search(text)
    return m.group(0) if m else None


def _user_from_text(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    for rx in _USER_PHRASE_RES:
        m = rx.search(text)
        if m:
            return m.group(1)
    return None



_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _extract_file_hash(raw: Dict[str, Any]) -> Optional[str]:
    """Pull md5/sha1/sha256 from syscheck / data / top-level Wazuh fields."""
    direct = _as_str(
        raw.get("file_hash")
        or raw.get("md5")
        or raw.get("sha1")
        or raw.get("sha256")
        or _dig(
            raw,
            "syscheck.sha256",
            "syscheck.md5",
            "syscheck.sha1",
            "syscheck.sha256_after",
            "syscheck.md5_after",
            "syscheck.sha1_after",
            "data.sha256",
            "data.md5",
            "data.sha1",
        )
    )
    if direct:
        return direct
    syscheck = raw.get("syscheck") if isinstance(raw.get("syscheck"), dict) else {}
    for key in ("sha256", "md5", "sha1", "sha256_after", "md5_after", "sha1_after"):
        val = _as_str(syscheck.get(key))
        if val:
            return val
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    for key in ("sha256", "md5", "sha1"):
        val = _as_str(data.get(key))
        if val:
            return val
    return None


def _extract_domain(raw: Dict[str, Any]) -> Optional[str]:
    """DNS query / hostname-style domain from Wazuh data fields."""
    direct = _as_str(
        raw.get("domain")
        or raw.get("dns_query")
        or raw.get("query")
        or _dig(
            raw,
            "data.dns.question.name",
            "data.query",
            "data.dnsquery",
            "data.domain",
            "data.url",
            "data.hostname",
        )
    )
    if not direct:
        return None
    if "://" in direct:
        direct = direct.split("://", 1)[1]
    direct = direct.split("/", 1)[0].strip(".")
    if direct and not re.match(r"^\d+\.\d+\.\d+\.\d+$", direct):
        return direct
    return None


def _extract_cve(raw: Dict[str, Any]) -> Optional[str]:
    """CVE id from vulnerability detector fields or free text."""
    direct = _as_str(
        raw.get("cve")
        or _dig(
            raw,
            "data.vulnerability.cve",
            "vulnerability.cve",
            "data.cve",
            "data.vulnerability.CVE",
        )
    )
    if direct:
        m = _CVE_RE.search(direct)
        if m:
            return m.group(0).upper()
        if direct.upper().startswith("CVE-"):
            return direct.upper()
        return direct
    for key in ("rule_description", "full_log", "summary", "raw_message", "description"):
        blob = _as_str(raw.get(key))
        if not blob:
            continue
        m = _CVE_RE.search(blob)
        if m:
            return m.group(0).upper()
    return None


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
            or raw.get("attacker_ip")
            or raw.get("client_ip")
            or _dig(
                raw,
                "data.srcip",
                "data.src_ip",
                "data.srcIp",
                "win.eventdata.ipAddress",
                "win.eventdata.IpAddress",
                "data.win.eventdata.ipAddress",
                "data.win.eventdata.IpAddress",
            )
            or raw.get("ip")
        )
        out["src_ip"] = _as_str(src_ip)

        dst_ip = (
            raw.get("dst_ip")
            or raw.get("destination_ip")
            or raw.get("dstip")
            or raw.get("dest_ip")
            or _dig(
                raw,
                "data.dstip",
                "data.dst_ip",
                "data.dstIp",
                "win.eventdata.destAddress",
                "win.eventdata.DestAddress",
            )
        )
        out["dst_ip"] = _as_str(dst_ip)

        user = (
            raw.get("user")
            or raw.get("username")
            or raw.get("srcuser")
            or raw.get("dstuser")
            or raw.get("src_user")
            or _dig(
                raw,
                "data.srcuser",
                "data.dstuser",
                "data.user",
                "win.eventdata.targetUserName",
                "win.eventdata.TargetUserName",
                "win.eventdata.subjectUserName",
                "win.eventdata.SubjectUserName",
                "data.win.eventdata.TargetUserName",
            )
        )
        out["user"] = _as_str(user)

        host = (
            raw.get("host")
            or raw.get("agent")
            or raw.get("hostname")
            or raw.get("agent_name")
            or _dig(raw, "agent.name", "agent.id", "agent.ip")
        )
        if isinstance(host, dict):
            host = host.get("name") or host.get("id") or host.get("ip")
        out["host"] = _as_str(host)

        out["file_hash"] = _extract_file_hash(raw)
        out["domain"] = _extract_domain(raw)
        out["cve"] = _extract_cve(raw)
        pkg = _as_str(
            _dig(raw, "data.package.name", "data.package", "package.name")
            or raw.get("package")
        )
        if pkg:
            raw = dict(raw)
            extras_seed = dict(raw.get("extras") or {}) if isinstance(raw.get("extras"), dict) else {}
            extras_seed.setdefault("package", pkg)
            raw["extras"] = extras_seed

        mitre = (
            raw.get("mitre_technique")
            or raw.get("mitre")
            or _dig(raw, "rule.mitre.id", "rule.mitre.technique")
        )
        if isinstance(mitre, list):
            mitre = ",".join(str(x) for x in mitre if x)
        out["mitre_technique"] = _as_str(mitre)

        out["raw_message"] = _build_raw_message(raw, out)

        # Safe full_log / message regex fallbacks when structured fields missing
        if not out["src_ip"]:
            out["src_ip"] = _ipv4_from_text(out.get("raw_message"))
        if not out["user"]:
            out["user"] = _user_from_text(out.get("raw_message"))

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
            "attacker_ip",
            "client_ip",
            "srcuser",
            "dstuser",
            "src_user",
            "dest_ip",
            "agent_name",
            "win",
            "file_hash",
            "domain",
            "cve",
            "syscheck",
            "package",
            "md5",
            "sha1",
            "sha256",
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
            win_ed = _dig(raw, "data.win.eventdata", "win.eventdata")
            if isinstance(win_ed, dict):
                for dk in (
                    "IpAddress",
                    "ipAddress",
                    "TargetUserName",
                    "targetUserName",
                    "SubjectUserName",
                    "subjectUserName",
                    "DestAddress",
                    "destAddress",
                ):
                    if win_ed.get(dk) is not None:
                        extras.setdefault(dk, win_ed.get(dk))
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
