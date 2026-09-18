"""Aggregate noisy rule ids from triage_events for the FP review UI."""

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
    """Group recent triage events by rule key and rank by volume.

    Returns rows: rule_key, count, low_ignore_count, pct_low_ignore, sample_log
    """
    rows = list(events or [])
    if limit_events is not None and limit_events >= 0:
        rows = rows[: int(limit_events)]

    buckets: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "low_ignore_count": 0, "sample_log": ""}
    )

    for event in rows:
        if not isinstance(event, dict):
            continue
        key = extract_rule_key(event)
        bucket = buckets[key]
        bucket["count"] += 1
        if _is_low_or_ignore(event):
            bucket["low_ignore_count"] += 1
        if not bucket["sample_log"]:
            sample = event.get("log") or ""
            if not sample:
                payload = _parse_raw(event.get("raw_json"))
                sample = payload.get("log") or payload.get("raw_message") or ""
            bucket["sample_log"] = str(sample)[:240]

    out: List[Dict[str, Any]] = []
    for key, bucket in buckets.items():
        count = int(bucket["count"])
        low_n = int(bucket["low_ignore_count"])
        pct = round((100.0 * low_n / count), 1) if count else 0.0
        out.append(
            {
                "rule_key": key,
                "count": count,
                "low_ignore_count": low_n,
                "pct_low_ignore": pct,
                "sample_log": bucket["sample_log"],
            }
        )

    out.sort(key=lambda r: (-int(r["count"]), str(r["rule_key"])))
    if top_n is not None and top_n >= 0:
        out = out[: int(top_n)]
    return out
