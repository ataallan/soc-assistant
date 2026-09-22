"""Aggregate noisy similarity buckets from triage_events for the FP review UI."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional

# Prefer explicit matched_rule_id; fall back to Wazuh-ish rule id in raw_json / log text.
_RULE_ID_IN_TEXT = re.compile(
    r"(?:rule[_ ]?id|wazuh(?:\s+rule)?)\s*[:=#]?\s*['\"]?(\d{3,6})",
    re.IGNORECASE,
)
_DET_RULE_IN_TEXT = re.compile(r"\b(DET-[A-Z0-9-]+)\b")


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


def extract_rule_key(event: Dict[str, Any]) -> str:
    """Best-effort rule key for grouping noisy triage rows."""
    if not isinstance(event, dict):
        return "unknown"

    for key in ("matched_rule_id", "rule_id"):
        val = event.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()

    payload = _parse_raw(event.get("raw_json"))
    for key in ("matched_rule_id", "rule_id"):
        val = payload.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()

    alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
    for key in ("rule_id", "matched_rule_id"):
        val = alert.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()

    matched = payload.get("matched_rules") or event.get("matched_rules")
    if isinstance(matched, list) and matched:
        first = matched[0]
        if isinstance(first, dict) and first.get("id"):
            return str(first.get("id")).strip()

    log = str(event.get("log") or payload.get("log") or "")
    m = _DET_RULE_IN_TEXT.search(log)
    if m:
        return m.group(1)
    m = _RULE_ID_IN_TEXT.search(log)
    if m:
        return m.group(1)

    return "unknown"


def _is_low_or_ignore(event: Dict[str, Any]) -> bool:
    sev = str(event.get("severity") or "").strip().lower()
    rec = str(event.get("rule_based") or event.get("recommendation") or "").strip().lower()
    if sev in ("low", "info"):
        return True
    if rec in ("ignore", "monitor"):
        return True
    return False


def aggregate_noisy_rules(
    events: Iterable[Dict[str, Any]],
    *,
    limit_events: int = 1000,
    top_n: int = 50,
) -> List[Dict[str, Any]]:
    """Group recent triage events by similarity bucket and rank by volume.

    A bucket is rule key + host + user, plus a log fingerprint when host and
    user are both missing. Rows still include ``rule_key`` for developer enqueue.

    Returns rows: bucket_key, rule_key, host, user, count, low_ignore_count,
    pct_low_ignore, sample_log, and the suggested suppress dimension.
    """
    from detection.buckets import bucket_for_event, dimensions_from_event

    rows = list(events or [])
    if limit_events is not None and limit_events >= 0:
        rows = rows[: int(limit_events)]

    buckets: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "count": 0,
            "low_ignore_count": 0,
            "sample_log": "",
            "sample_event_id": "",
            "ip": "",
            "ip_ready": False,
            "ip_consistent": True,
            "proposal": None,
        }
    )

    for event in rows:
        if not isinstance(event, dict):
            continue
        proposal = bucket_for_event(event)
        dims = dimensions_from_event(event)
        key = proposal["bucket_key"]
        bucket = buckets[key]
        bucket["count"] += 1
        bucket["proposal"] = proposal
        if _is_low_or_ignore(event):
            bucket["low_ignore_count"] += 1
        ip = dims.get("ip") or ""
        if not bucket["ip_ready"]:
            bucket["ip"] = ip
            bucket["ip_ready"] = True
        elif (ip or "") != (bucket["ip"] or ""):
            bucket["ip_consistent"] = False
            bucket["ip"] = ""
        if not bucket["sample_log"]:
            sample = event.get("log") or proposal.get("sample") or ""
            if not sample:
                payload = _parse_raw(event.get("raw_json"))
                sample = payload.get("log") or payload.get("raw_message") or ""
            bucket["sample_log"] = str(sample)[:240]
        if not bucket["sample_event_id"] and event.get("id") not in (None, ""):
            bucket["sample_event_id"] = str(event.get("id"))

    out: List[Dict[str, Any]] = []
    for key, bucket in buckets.items():
        count = int(bucket["count"])
        low_n = int(bucket["low_ignore_count"])
        pct = round((100.0 * low_n / count), 1) if count else 0.0
        proposal = dict(bucket["proposal"] or {})
        ip = bucket["ip"] if bucket["ip_consistent"] else ""
        if ip != (proposal.get("ip") or ""):
            from detection.buckets import dimension_summary, most_specific

            dimension, value = most_specific(
                ip=ip,
                user=proposal.get("user") or "",
                host=proposal.get("host") or "",
                rule_key=proposal.get("rule_key") or "",
            )
            proposal["ip"] = ip
            proposal["dimension"] = dimension
            proposal["dimension_value"] = value
            proposal["summary"] = dimension_summary(dimension, value)
        out.append(
            {
                "rule_key": proposal.get("rule_key") or "unknown",
                "bucket_key": key,
                "host": proposal.get("host") or "",
                "user": proposal.get("user") or "",
                "fingerprint": proposal.get("fingerprint") or "",
                "ip": proposal.get("ip") or "",
                "dimension": proposal.get("dimension") or "",
                "dimension_value": proposal.get("dimension_value") or "",
                "summary": proposal.get("summary") or "",
                "count": count,
                "low_ignore_count": low_n,
                "pct_low_ignore": pct,
                "sample_log": bucket["sample_log"],
                "sample_event_id": bucket["sample_event_id"],
                "entire_rule_ok": (proposal.get("rule_key") or "") not in {"", "unknown"},
            }
        )

    out.sort(key=lambda r: (-int(r["count"]), str(r["bucket_key"])))
    if top_n is not None and top_n >= 0:
        out = out[: int(top_n)]
    return out
