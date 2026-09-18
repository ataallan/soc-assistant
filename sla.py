"""Case SLA helpers: severity → response hours → due_at, overdue checks.

Defaults (overridable via env):
  critical 4h, high 8h, medium 24h, low 72h

Env vars:
  SLA_HOURS_CRITICAL, SLA_HOURS_HIGH, SLA_HOURS_MEDIUM, SLA_HOURS_LOW
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional, Union

DEFAULT_SLA_HOURS = {
    "critical": 4,
    "high": 8,
    "medium": 24,
    "low": 72,
}

_ENV_KEYS = {
    "critical": "SLA_HOURS_CRITICAL",
    "high": "SLA_HOURS_HIGH",
    "medium": "SLA_HOURS_MEDIUM",
    "low": "SLA_HOURS_LOW",
}


def sla_hours_map() -> dict[str, int]:
    """Return severity → hours mapping (env overrides with sensible defaults)."""
    out = dict(DEFAULT_SLA_HOURS)
    for sev, env_key in _ENV_KEYS.items():
        raw = (os.environ.get(env_key) or "").strip()
        if not raw:
            continue
        try:
            hours = int(raw)
            if hours > 0:
                out[sev] = hours
        except ValueError:
            continue
    return out


def hours_for_severity(severity: Optional[str]) -> int:
    sev = (severity or "medium").strip().lower()
    mapping = sla_hours_map()
    return int(mapping.get(sev, mapping["medium"]))


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    text = str(ts).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def compute_due_at(
    severity: Optional[str],
    *,
    created_at: Optional[Union[str, datetime]] = None,
) -> str:
    """Return ISO due_at for severity from created_at (default: now UTC)."""
    if isinstance(created_at, datetime):
        base = created_at
        if base.tzinfo is None:
            base = base.replace(tzinfo=timezone.utc)
        else:
            base = base.astimezone(timezone.utc)
    elif isinstance(created_at, str) and created_at.strip():
        parsed = _parse_iso(created_at)
        base = parsed if parsed is not None else datetime.now(timezone.utc)
    else:
        base = datetime.now(timezone.utc)
    hours = hours_for_severity(severity)
    return (base + timedelta(hours=hours)).isoformat()


def is_overdue(
    case: Mapping[str, Any],
    *,
    now: Optional[datetime] = None,
) -> bool:
    """True when due_at is in the past and the case is not closed.

    sla_breached is the same computed condition (no separate DB column).
    """
    status = (case.get("status") or "").strip().lower()
    if status == "closed":
        return False
    due = _parse_iso(case.get("due_at"))
    if due is None:
        return False
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    else:
        current = current.astimezone(timezone.utc)
    return current > due


def is_sla_breached(
    case: Mapping[str, Any],
    *,
    now: Optional[datetime] = None,
) -> bool:
    """Alias for is_overdue — breach is computed, not stored."""
    return is_overdue(case, now=now)
