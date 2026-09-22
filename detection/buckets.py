"""Similarity buckets for suppress, mute, and FP review.

A bucket is the rule key plus host and user. When both host and user are
missing, a short log fingerprint is added so one noisy line is not treated as
every host. Suppressing one bucket does not cover other hosts unless the
operator explicitly chooses the entire rule.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Optional, Tuple

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SPACE_RE = re.compile(r"[^a-z#]+")


def _parse_raw(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            payload = json.loads(raw)
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}
    return {}


def _first(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() not in {"none", "null", "nan"}:
            return text
    return ""


def _clean_rule(value: Any) -> str:
    text = _first(value)
    if not text:
        return "unknown"
    text = text.replace("|", "/").replace("\n", " ").replace("\r", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:80] or "unknown"


def _clean_name(value: Any) -> str:
    text = _first(value).lower()
    if not text:
        return ""
    text = text.replace("|", "/").replace("\n", " ").replace("\r", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:80]


def _clean_fp(value: Any) -> str:
    text = _first(value).lower()
    text = re.sub(r"[^a-z0-9]", "", text)
    return text[:16]


def log_fingerprint(log: str) -> str:
    """Stable short fingerprint. Digits and IPs collapse so timestamps do not split a line."""
    text = (log or "").lower()
    text = _IP_RE.sub("#", text)
    text = re.sub(r"\d+", "#", text)
    text = _SPACE_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()[:160]
    if not text:
        text = "-"
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:10]


def dimensions_from_event(event: Dict[str, Any]) -> Dict[str, str]:
    """Pull host, user, ip, and log from a triage row or normalized alert. Never invents fields."""
    if not isinstance(event, dict):
        return {"host": "", "user": "", "ip": "", "log": ""}
    payload = _parse_raw(event.get("raw_json"))
    alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
    extras = event.get("extras") if isinstance(event.get("extras"), dict) else {}
    host = _clean_name(
        _first(
            event.get("host"),
            event.get("hostname"),
            event.get("agent_name"),
            payload.get("host"),
            alert.get("host"),
            alert.get("agent_name"),
            extras.get("host"),
        )
    )
    user = _clean_name(
        _first(
            event.get("user"),
            event.get("username"),
            event.get("user_entity"),
            payload.get("user"),
            alert.get("user"),
            alert.get("username"),
            extras.get("user"),
        )
    )
    ip = _first(
        event.get("ip"),
        event.get("src_ip"),
        event.get("source_ip"),
        payload.get("ip"),
        payload.get("src_ip"),
        alert.get("src_ip"),
        alert.get("ip"),
        extras.get("src_ip"),
    )
    log = _first(
        event.get("log"),
        event.get("raw_message"),
        payload.get("log"),
        payload.get("raw_message"),
        alert.get("raw_message"),
        event.get("summary"),
        event.get("title"),
    )
    return {"host": host, "user": user, "ip": ip.strip(), "log": log}


def make_bucket(
    *,
    rule_key: Any,
    host: Any = "",
    user: Any = "",
    log: Any = "",
    fingerprint: Any = "",
) -> Dict[str, str]:
    """Build the default similarity bucket. Fingerprint is used only when host and user are both empty."""
    rule = _clean_rule(rule_key)
    host_n = _clean_name(host)
    user_n = _clean_name(user)
    if not host_n and not user_n:
        fp = _clean_fp(fingerprint) or log_fingerprint(str(log or ""))
        bucket_key = f"r:{rule}|fp:{fp}"
    else:
        fp = ""
        bucket_key = f"r:{rule}|h:{host_n or '-'}|u:{user_n or '-'}"
    return {
        "bucket_key": bucket_key,
        "rule_key": rule,
        "host": host_n,
        "user": user_n,
        "fingerprint": fp,
    }


def most_specific(*, ip: str = "", user: str = "", host: str = "", rule_key: str = "") -> Tuple[str, str]:
    """Prefer the narrowest dimension that is actually present. Does not invent values."""
    ip_text = (ip or "").strip()
    if ip_text:
        return "ip", ip_text
    if user:
        return "user", user
    if host:
        return "host", host
    if rule_key and rule_key != "unknown":
        return "rule_id", rule_key
    return "log", ""


def dimension_summary(dimension: str, value: str) -> str:
    if dimension == "ip" and value:
        return f"IP {value}"
    if dimension == "user" and value:
        return f"User {value}"
    if dimension == "host" and value:
        return f"Host {value}"
    if dimension == "rule_id" and value:
        return f"Rule {value}"
    return "This log pattern"


def bucket_for_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Bucket a stored triage row or case-like dict."""
    from detection.fp_review import extract_rule_key

    dims = dimensions_from_event(event)
    bucket = make_bucket(
        rule_key=extract_rule_key(event if isinstance(event, dict) else {}),
        host=dims["host"],
        user=dims["user"],
        log=dims["log"],
    )
    dimension, value = most_specific(
        ip=dims["ip"],
        user=bucket["user"],
        host=bucket["host"],
        rule_key=bucket["rule_key"],
    )
    sample = (dims["log"] or "")[:240]
    event_id = ""
    if isinstance(event, dict) and event.get("id") not in (None, ""):
        event_id = str(event.get("id"))
    return {
        **bucket,
        "ip": dims["ip"],
        "dimension": dimension,
        "dimension_value": value,
        "summary": dimension_summary(dimension, value),
        "sample": sample,
        "event_id": event_id,
        "entire_rule_ok": bucket["rule_key"] != "unknown",
    }


def bucket_for_alert(alert: Dict[str, Any], matched_rule_id: Optional[str] = None) -> Dict[str, Any]:
    """Bucket a normalized alert, preferring the YAML match id the same way FP review does."""
    if not isinstance(alert, dict):
        alert = {}
    synthetic = {
        "matched_rule_id": matched_rule_id,
        "rule_id": alert.get("rule_id"),
        "log": alert.get("raw_message") or "",
        "host": alert.get("host"),
        "user": alert.get("user"),
        "ip": alert.get("src_ip") or alert.get("ip"),
        "raw_json": {
            "matched_rule_id": matched_rule_id,
            "rule_id": alert.get("rule_id"),
            "log": alert.get("raw_message") or "",
        },
    }
    extras = alert.get("extras") if isinstance(alert.get("extras"), dict) else {}
    if not synthetic["rule_id"] and extras.get("rule_id"):
        synthetic["rule_id"] = extras.get("rule_id")
    return bucket_for_event(synthetic)
