"""Runtime suppresses and temporary mutes.

Git-tracked defaults stay in ``config/allowlists.yml``. Operator actions are
written to ``data/allowlists_runtime.yml`` (or ``FP_RUNTIME_ALLOWLIST_PATH``)
and merged on read. The in-process cache follows the file mtime, so a save
applies to the next triage without a process restart.
"""

from __future__ import annotations

import ipaddress
import os
import threading
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from detection.buckets import bucket_for_alert, bucket_for_event

_REPO_ROOT = Path(__file__).resolve().parent.parent
_LOCK = threading.Lock()
_CACHE_DOC: Optional[Dict[str, Any]] = None
_CACHE_STAMP: Optional[tuple] = None

_SCOPES = {"bucket", "rule", "ip", "user", "host"}
_MUTE_SCOPES = {"bucket", "rule"}
_GLOBAL_SCOPES = {"ip", "user", "host"}


def runtime_path() -> Path:
    raw = os.environ.get("FP_RUNTIME_ALLOWLIST_PATH", "").strip()
    if raw:
        return Path(raw)
    return _REPO_ROOT / "data" / "allowlists_runtime.yml"


def gate_threshold() -> int:
    try:
        value = int(os.environ.get("FP_SUPPRESS_GATE", "2"))
    except (TypeError, ValueError):
        value = 2
    return max(1, min(value, 50))


def draft_min_count() -> int:
    try:
        value = int(os.environ.get("FP_DRAFT_MIN_COUNT", "5"))
    except (TypeError, ValueError):
        value = 5
    return max(1, value)


def draft_min_pct() -> float:
    try:
        value = float(os.environ.get("FP_DRAFT_MIN_PCT", "80"))
    except (TypeError, ValueError):
        value = 80.0
    return max(0.0, min(value, 100.0))


def mute_max_hours() -> int:
    try:
        value = int(os.environ.get("FP_MUTE_MAX_HOURS", "720"))
    except (TypeError, ValueError):
        value = 720
    return max(1, min(value, 24 * 365))


def clear_suppress_cache() -> None:
    global _CACHE_DOC, _CACHE_STAMP
    with _LOCK:
        _CACHE_DOC = None
        _CACHE_STAMP = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _parse_iso(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_expiry(value: Any) -> str:
    parsed = _parse_iso(value)
    if parsed is None:
        return str(value or "")
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


def _stamp(path: Path) -> Optional[tuple]:
    try:
        stat = path.stat()
    except OSError:
        return None
    return (stat.st_mtime_ns, stat.st_size)


def _empty_doc() -> Dict[str, Any]:
    return {
        "version": 1,
        "ips": [],
        "cidrs": [],
        "users": [],
        "hosts": [],
        "suppress_wazuh_rule_ids": [],
        "suppresses": [],
        "mutes": [],
        "marks": [],
        "dismissed": [],
    }


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def _normalize_doc(data: Any) -> Dict[str, Any]:
    base = _empty_doc()
    if not isinstance(data, dict):
        return base
    for key in ("ips", "cidrs", "users", "hosts", "suppress_wazuh_rule_ids", "suppresses", "mutes", "marks", "dismissed"):
        base[key] = [item for item in _as_list(data.get(key)) if item not in (None, "")]
    return base


def _load_unlocked() -> Dict[str, Any]:
    global _CACHE_DOC, _CACHE_STAMP
    path = runtime_path()
    stamp = _stamp(path)
    if _CACHE_DOC is not None and _CACHE_STAMP == stamp:
        return deepcopy(_CACHE_DOC)
    data: Any = {}
    if yaml is not None and path.is_file():
        try:
            with open(path, "r", encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle)
            if isinstance(loaded, dict):
                data = loaded
        except Exception:
            data = {}
    doc = _normalize_doc(data)
    _CACHE_DOC = doc
    _CACHE_STAMP = stamp
    return deepcopy(doc)


def _save_unlocked(doc: Dict[str, Any]) -> None:
    global _CACHE_DOC, _CACHE_STAMP
    if yaml is None:
        raise RuntimeError("PyYAML is required to store suppresses")
    path = runtime_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _normalize_doc(doc)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False, allow_unicode=True)
    tmp.replace(path)
    _CACHE_DOC = deepcopy(payload)
    _CACHE_STAMP = _stamp(path)
    try:
        from detection.allowlists import clear_allowlist_cache

        clear_allowlist_cache()
    except Exception:
        pass


def load_doc() -> Dict[str, Any]:
    with _LOCK:
        return _load_unlocked()


def runtime_global_lists() -> Dict[str, List[str]]:
    """IP / user / host / rule-id entries to merge into the classic allowlist."""
    doc = load_doc()
    ips = [str(item).strip() for item in doc.get("ips") or [] if str(item).strip()]
    cidrs = [str(item).strip() for item in doc.get("cidrs") or [] if str(item).strip()]
    users = [str(item).strip() for item in doc.get("users") or [] if str(item).strip()]
    hosts = [str(item).strip() for item in doc.get("hosts") or [] if str(item).strip()]
    rules = [str(item).strip() for item in doc.get("suppress_wazuh_rule_ids") or [] if str(item).strip()]
    for entry in doc.get("suppresses") or []:
        if not isinstance(entry, dict):
            continue
        scope = str(entry.get("scope") or "")
        value = str(entry.get("value") or "").strip()
        if not value:
            continue
        if scope == "ip":
            ips.append(value)
        elif scope == "user":
            users.append(value)
        elif scope == "host":
            hosts.append(value)
        elif scope == "cidr":
            cidrs.append(value)
        elif scope == "wazuh_rule":
            rules.append(value)
    return {
        "ips": ips,
        "cidrs": cidrs,
        "users": users,
        "hosts": hosts,
        "suppress_wazuh_rule_ids": rules,
    }


def _actor_key(actor: str) -> str:
    return (actor or "").strip().lower()


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _result(ok: bool, message: str, **extra: Any) -> Dict[str, Any]:
    out = {"ok": ok, "message": message}
    out.update(extra)
    return out


def _bucket_from_parts(
    *,
    rule_key: str,
    host: str = "",
    user: str = "",
    fingerprint: str = "",
    log: str = "",
) -> Dict[str, str]:
    from detection.buckets import make_bucket

    return make_bucket(rule_key=rule_key, host=host, user=user, log=log, fingerprint=fingerprint)


def _mark_count(doc: Dict[str, Any], bucket_key: str) -> int:
    actors = set()
    for mark in doc.get("marks") or []:
        if not isinstance(mark, dict):
            continue
        if str(mark.get("bucket_key") or "") != bucket_key:
            continue
        key = _actor_key(str(mark.get("actor") or ""))
        if key:
            actors.add(key)
    return len(actors)


def record_mark(
    *,
    rule_key: str,
    host: str = "",
    user: str = "",
    fingerprint: str = "",
    actor: str,
    event_id: str = "",
    sample: str = "",
) -> Dict[str, Any]:
    """Record one analyst's false-positive / ignore mark on a bucket."""
    who = (actor or "").strip()
    if not who:
        return _result(False, "Sign in required.")
    bucket = _bucket_from_parts(rule_key=rule_key, host=host, user=user, fingerprint=fingerprint, log=sample)
    with _LOCK:
        doc = _load_unlocked()
        _upsert_mark(doc, bucket_key=bucket["bucket_key"], rule_key=bucket["rule_key"], actor=who, event_id=event_id)
        count = _mark_count(doc, bucket["bucket_key"])
        _save_unlocked(doc)
    return _result(True, "Marked false positive.", mark_count=count, gate=gate_threshold(), bucket_key=bucket["bucket_key"])


def _upsert_mark(doc: Dict[str, Any], *, bucket_key: str, rule_key: str, actor: str, event_id: str = "") -> None:
    key = _actor_key(actor)
    now = _iso(_utcnow())
    for mark in doc["marks"]:
        if not isinstance(mark, dict):
            continue
        if str(mark.get("bucket_key") or "") == bucket_key and _actor_key(str(mark.get("actor") or "")) == key:
            mark["updated_at"] = now
            if event_id:
                mark["event_id"] = str(event_id)
            return
    doc["marks"].append(
        {
            "bucket_key": bucket_key,
            "rule_key": rule_key,
            "actor": actor.strip(),
            "event_id": str(event_id or ""),
            "created_at": now,
        }
    )
    if len(doc["marks"]) > 2000:
        doc["marks"] = doc["marks"][-2000:]


def _find_suppress(doc: Dict[str, Any], *, scope: str, bucket_key: str, rule_key: str, value: str) -> Optional[Dict[str, Any]]:
    for entry in doc.get("suppresses") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("scope") or "") != scope:
            continue
        if scope == "bucket" and str(entry.get("bucket_key") or "") == bucket_key:
            return entry
        if scope == "rule" and str(entry.get("rule_key") or "") == rule_key:
            return entry
        if scope in _GLOBAL_SCOPES and str(entry.get("value") or "").strip().lower() == value.strip().lower():
            return entry
    return None


def _find_mute(doc: Dict[str, Any], *, scope: str, bucket_key: str, rule_key: str) -> Optional[Dict[str, Any]]:
    for entry in doc.get("mutes") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("scope") or "") != scope:
            continue
        if scope == "bucket" and str(entry.get("bucket_key") or "") == bucket_key:
            return entry
        if scope == "rule" and str(entry.get("rule_key") or "") == rule_key:
            return entry
    return None


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def create_permanent(
    *,
    rule_key: str,
    host: str = "",
    user: str = "",
    fingerprint: str = "",
    ip: str = "",
    scope: str = "bucket",
    actor: str,
    can_confirm: bool = False,
    confirmed: bool = False,
    event_id: str = "",
    note: str = "",
    sample: str = "",
    origin: str = "",
) -> Dict[str, Any]:
    """Durable suppress. Bucket is the default scope. Permanent and entire-rule need the gate."""
    who = (actor or "").strip()
    if not who:
        return _result(False, "Sign in required.")
    scope_name = (scope or "bucket").strip().lower()
    if scope_name not in _SCOPES:
        return _result(False, "Choose a suppress scope.")
    bucket = _bucket_from_parts(
        rule_key=rule_key, host=host, user=user, fingerprint=fingerprint, log=sample
    )
    ip_text = (ip or "").strip()
    value = ""
    if scope_name == "bucket":
        value = bucket["bucket_key"]
    elif scope_name == "rule":
        if bucket["rule_key"] == "unknown":
            return _result(False, "This rule is not specific enough to suppress everywhere.")
        value = bucket["rule_key"]
    elif scope_name == "ip":
        if not ip_text or not _valid_ip(ip_text):
            return _result(False, "That field is not on this alert.")
        value = ip_text
    elif scope_name == "user":
        if not bucket["user"]:
            return _result(False, "That field is not on this alert.")
        value = bucket["user"]
    elif scope_name == "host":
        if not bucket["host"]:
            return _result(False, "That field is not on this alert.")
        value = bucket["host"]

    with _LOCK:
        doc = _load_unlocked()
        existing = _find_suppress(
            doc, scope=scope_name, bucket_key=bucket["bucket_key"], rule_key=bucket["rule_key"], value=value
        )
        if existing:
            return _result(True, "Already suppressed.", id=existing.get("id"), bucket_key=bucket["bucket_key"])
        _upsert_mark(
            doc,
            bucket_key=bucket["bucket_key"],
            rule_key=bucket["rule_key"],
            actor=who,
            event_id=event_id,
        )
        count = _mark_count(doc, bucket["bucket_key"])
        gate = gate_threshold()
        allowed = count >= gate or (bool(can_confirm) and bool(confirmed))
        if not allowed:
            _save_unlocked(doc)
            return _result(
                False,
                "Needs confirmation before a permanent suppress.",
                reason="needs_confirmation",
                mark_count=count,
                gate=gate,
                bucket_key=bucket["bucket_key"],
            )
        entry = {
            "id": _new_id(),
            "scope": scope_name,
            "value": value,
            "bucket_key": bucket["bucket_key"],
            "rule_key": bucket["rule_key"],
            "host": bucket["host"],
            "user": bucket["user"],
            "fingerprint": bucket["fingerprint"],
            "ip": ip_text,
            "created_by": who,
            "created_at": _iso(_utcnow()),
            "note": (note or "").strip()[:200],
            "origin": (origin or "").strip()[:40],
            "sample": (sample or "")[:240],
        }
        doc["suppresses"].append(entry)
        _save_unlocked(doc)
    return _result(True, "Suppressed.", id=entry["id"], bucket_key=bucket["bucket_key"], mark_count=count, gate=gate)


def create_mute(
    *,
    rule_key: str,
    host: str = "",
    user: str = "",
    fingerprint: str = "",
    scope: str = "bucket",
    hours: Any = 24,
    actor: str,
    event_id: str = "",
    sample: str = "",
    origin: str = "",
) -> Dict[str, Any]:
    """Temporary mute. Analysts can create these without the permanent-suppress gate."""
    who = (actor or "").strip()
    if not who:
        return _result(False, "Sign in required.")
    scope_name = (scope or "bucket").strip().lower()
    if scope_name not in _MUTE_SCOPES:
        scope_name = "bucket"
    try:
        hours_value = float(hours)
    except (TypeError, ValueError):
        return _result(False, f"Enter hours between 1 and {mute_max_hours()}.")
    max_hours = mute_max_hours()
    if hours_value < 1 or hours_value > max_hours:
        return _result(False, f"Enter hours between 1 and {max_hours}.")
    bucket = _bucket_from_parts(rule_key=rule_key, host=host, user=user, fingerprint=fingerprint, log=sample)
    if scope_name == "rule" and bucket["rule_key"] == "unknown":
        return _result(False, "This rule is not specific enough to suppress everywhere.")
    expires = _utcnow() + timedelta(hours=hours_value)
    expires_text = _iso(expires)
    with _LOCK:
        doc = _load_unlocked()
        existing = _find_mute(doc, scope=scope_name, bucket_key=bucket["bucket_key"], rule_key=bucket["rule_key"])
        if existing:
            existing["expires_at"] = expires_text
            existing["hours"] = hours_value
            existing["created_by"] = who
            existing["created_at"] = _iso(_utcnow())
            entry_id = existing.get("id")
            _save_unlocked(doc)
        else:
            entry = {
                "id": _new_id(),
                "scope": scope_name,
                "bucket_key": bucket["bucket_key"],
                "rule_key": bucket["rule_key"],
                "host": bucket["host"],
                "user": bucket["user"],
                "fingerprint": bucket["fingerprint"],
                "expires_at": expires_text,
                "hours": hours_value,
                "created_by": who,
                "created_at": _iso(_utcnow()),
                "event_id": str(event_id or ""),
                "origin": (origin or "").strip()[:40],
                "sample": (sample or "")[:240],
            }
            doc["mutes"].append(entry)
            entry_id = entry["id"]
            _save_unlocked(doc)
    return _result(
        True,
        f"Muted until {format_expiry(expires_text)}.",
        id=entry_id,
        expires_at=expires_text,
        bucket_key=bucket["bucket_key"],
    )


def remove_mute(mute_id: str, *, actor: str = "") -> Dict[str, Any]:
    target = (mute_id or "").strip()
    if not target:
        return _result(False, "Not found.")
    with _LOCK:
        doc = _load_unlocked()
        kept = []
        removed = False
        for entry in doc.get("mutes") or []:
            if isinstance(entry, dict) and str(entry.get("id") or "") == target:
                removed = True
                continue
            kept.append(entry)
        if not removed:
            return _result(False, "Not found.")
        doc["mutes"] = kept
        _save_unlocked(doc)
    return _result(True, "Unmuted.")


def remove_suppress(entry_id: str, *, actor: str = "") -> Dict[str, Any]:
    target = (entry_id or "").strip()
    if not target:
        return _result(False, "Not found.")
    with _LOCK:
        doc = _load_unlocked()
        kept = []
        removed = False
        for entry in doc.get("suppresses") or []:
            if isinstance(entry, dict) and str(entry.get("id") or "") == target:
                removed = True
                continue
            kept.append(entry)
        if not removed:
            return _result(False, "Not found.")
        doc["suppresses"] = kept
        _save_unlocked(doc)
    return _result(True, "Removed.")


def dismiss_draft(
    *,
    rule_key: str,
    host: str = "",
    user: str = "",
    fingerprint: str = "",
    actor: str,
    sample: str = "",
) -> Dict[str, Any]:
    who = (actor or "").strip()
    if not who:
        return _result(False, "Sign in required.")
    bucket = _bucket_from_parts(rule_key=rule_key, host=host, user=user, fingerprint=fingerprint, log=sample)
    with _LOCK:
        doc = _load_unlocked()
        for row in doc.get("dismissed") or []:
            if isinstance(row, dict) and str(row.get("bucket_key") or "") == bucket["bucket_key"]:
                return _result(True, "Dismissed.", bucket_key=bucket["bucket_key"])
        doc["dismissed"].append(
            {
                "bucket_key": bucket["bucket_key"],
                "dismissed_by": who,
                "dismissed_at": _iso(_utcnow()),
            }
        )
        if len(doc["dismissed"]) > 2000:
            doc["dismissed"] = doc["dismissed"][-2000:]
        _save_unlocked(doc)
    return _result(True, "Dismissed.", bucket_key=bucket["bucket_key"])


def _matches_scope(entry: Dict[str, Any], *, bucket_key: str, rule_key: str) -> bool:
    scope = str(entry.get("scope") or "")
    if scope == "bucket":
        return str(entry.get("bucket_key") or "") == bucket_key and bool(bucket_key)
    if scope == "rule":
        rule = str(entry.get("rule_key") or "")
        return bool(rule) and rule != "unknown" and rule == rule_key
    return False


def _mute_live(entry: Dict[str, Any], now: datetime) -> bool:
    expires = _parse_iso(entry.get("expires_at"))
    if expires is None:
        return False
    return expires > now


def _covers(entry: Dict[str, Any], proposal: Dict[str, Any]) -> bool:
    scope = str(entry.get("scope") or "")
    if scope in {"bucket", "rule"}:
        return _matches_scope(entry, bucket_key=str(proposal.get("bucket_key") or ""), rule_key=str(proposal.get("rule_key") or ""))
    value = str(entry.get("value") or "").strip().lower()
    if not value:
        return False
    if scope == "ip":
        return value == str(proposal.get("ip") or "").strip().lower() and bool(proposal.get("ip"))
    if scope == "user":
        return value == str(proposal.get("user") or "").strip().lower() and bool(proposal.get("user"))
    if scope == "host":
        return value == str(proposal.get("host") or "").strip().lower() and bool(proposal.get("host"))
    return False


def coverage_status(doc: Dict[str, Any], proposal: Dict[str, Any], *, now: Optional[datetime] = None) -> Dict[str, Any]:
    moment = now or _utcnow()
    for entry in doc.get("suppresses") or []:
        if isinstance(entry, dict) and _covers(entry, proposal):
            return {"label": "Suppressed", "kind": "suppress", "id": str(entry.get("id") or ""), "mute_id": ""}
    for entry in doc.get("mutes") or []:
        if not isinstance(entry, dict) or not _mute_live(entry, moment):
            continue
        if _covers(entry, proposal):
            return {
                "label": f"Muted until {format_expiry(entry.get('expires_at'))}",
                "kind": "mute",
                "id": str(entry.get("id") or ""),
                "mute_id": str(entry.get("id") or ""),
            }
    return {"label": "", "kind": None, "id": "", "mute_id": ""}


def _scope_options(proposal: Dict[str, Any]) -> List[Dict[str, str]]:
    options = [{"value": "bucket", "label": "This bucket"}]
    if proposal.get("entire_rule_ok"):
        options.append({"value": "rule", "label": "All hosts for this rule"})
    if proposal.get("ip"):
        options.append({"value": "ip", "label": f"Only IP {proposal['ip']}"})
    if proposal.get("user"):
        options.append({"value": "user", "label": f"Only user {proposal['user']}"})
    if proposal.get("host"):
        options.append({"value": "host", "label": f"Only host {proposal['host']}"})
    return options


def _form_id(proposal: Dict[str, Any]) -> str:
    if proposal.get("event_id"):
        return f"e{proposal['event_id']}"
    import hashlib

    digest = hashlib.sha1(str(proposal.get("bucket_key") or "").encode("utf-8")).hexdigest()[:8]
    return f"b{digest}"


def _enrich_proposal(doc: Dict[str, Any], proposal: Dict[str, Any], *, now: Optional[datetime] = None) -> Dict[str, Any]:
    out = dict(proposal)
    status = coverage_status(doc, out, now=now)
    count = _mark_count(doc, str(out.get("bucket_key") or ""))
    gate = gate_threshold()
    out.update(
        {
            "mark_count": count,
            "gate": gate,
            "needs_confirmation": count < gate,
            "covered_label": status.get("label") or "",
            "mute_id": status.get("mute_id") or "",
            "scope_options": _scope_options(out),
            "form_id": _form_id(out),
        }
    )
    return out


def proposal_from_event(event: Dict[str, Any]) -> Dict[str, Any]:
    return bucket_for_event(event or {})


def attach_proposals(rows: List[Dict[str, Any]], *, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    doc = load_doc()
    enriched = []
    for row in rows or []:
        item = dict(row)
        item["proposal"] = _enrich_proposal(doc, proposal_from_event(item), now=now)
        enriched.append(item)
    return enriched


def decorate_fp_rows(rows: List[Dict[str, Any]], *, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Add draft / mute / mark fields for the FP review table."""
    doc = load_doc()
    moment = now or _utcnow()
    min_count = draft_min_count()
    min_pct = draft_min_pct()
    dismissed = {
        str(row.get("bucket_key") or "")
        for row in (doc.get("dismissed") or [])
        if isinstance(row, dict)
    }
    out = []
    for row in rows or []:
        item = dict(row)
        proposal = {
            "bucket_key": item.get("bucket_key") or "",
            "rule_key": item.get("rule_key") or "",
            "host": item.get("host") or "",
            "user": item.get("user") or "",
            "fingerprint": item.get("fingerprint") or "",
            "ip": item.get("ip") or "",
            "dimension": item.get("dimension") or "",
            "dimension_value": item.get("dimension_value") or "",
            "summary": item.get("summary") or "",
            "sample": item.get("sample_log") or "",
            "event_id": item.get("sample_event_id") or "",
            "entire_rule_ok": (item.get("rule_key") or "") not in {"", "unknown"},
        }
        enriched = _enrich_proposal(doc, proposal, now=moment)
        covered = bool(enriched.get("covered_label"))
        draft = (
            not covered
            and enriched["bucket_key"] not in dismissed
            and int(item.get("count") or 0) >= min_count
            and float(item.get("pct_low_ignore") or 0) >= min_pct
        )
        item.update(enriched)
        item["draft"] = draft
        item["dismissed"] = enriched["bucket_key"] in dismissed and not covered
        out.append(item)
    return out


_SCOPE_LABELS = {
    "bucket": "This bucket",
    "rule": "All hosts for this rule",
    "ip": "IP",
    "user": "User",
    "host": "Host",
    "cidr": "Network",
    "wazuh_rule": "Rule",
}


def list_panel(*, now: Optional[datetime] = None) -> Dict[str, List[Dict[str, Any]]]:
    doc = load_doc()
    moment = now or _utcnow()
    suppresses = []
    for entry in doc.get("suppresses") or []:
        if not isinstance(entry, dict):
            continue
        scope = str(entry.get("scope") or "")
        detail = entry.get("bucket_key") if scope == "bucket" else (entry.get("value") or entry.get("rule_key") or "")
        if scope == "rule":
            detail = entry.get("rule_key") or detail
        suppresses.append(
            {
                "id": str(entry.get("id") or ""),
                "scope": scope,
                "scope_label": _SCOPE_LABELS.get(scope, scope),
                "detail": detail,
                "summary": entry.get("sample") or "",
                "who": entry.get("created_by") or "",
                "when": format_expiry(entry.get("created_at")),
                "removable": bool(entry.get("id")),
            }
        )
    mutes = []
    for entry in doc.get("mutes") or []:
        if not isinstance(entry, dict) or not _mute_live(entry, moment):
            continue
        scope = str(entry.get("scope") or "bucket")
        detail = entry.get("bucket_key") if scope == "bucket" else (entry.get("rule_key") or "")
        mutes.append(
            {
                "id": str(entry.get("id") or ""),
                "scope": scope,
                "scope_label": _SCOPE_LABELS.get(scope, scope),
                "detail": detail,
                "who": entry.get("created_by") or "",
                "when": format_expiry(entry.get("created_at")),
                "expires_label": format_expiry(entry.get("expires_at")),
                "expires_at": entry.get("expires_at") or "",
            }
        )
    return {"suppresses": suppresses, "mutes": mutes}


def match_scoped(
    alert: Dict[str, Any],
    *,
    matched_rule_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Match bucket/rule suppresses and live mutes. Global IP/user/host stays in allowlist match."""
    bucket = bucket_for_alert(alert, matched_rule_id=matched_rule_id)
    doc = load_doc()
    moment = now or _utcnow()
    reasons: List[str] = []
    kind = None
    expires_at = None
    for entry in doc.get("suppresses") or []:
        if isinstance(entry, dict) and _matches_scope(
            entry, bucket_key=bucket["bucket_key"], rule_key=bucket["rule_key"]
        ):
            scope = str(entry.get("scope") or "bucket")
            reasons.append(f"suppress_{scope}:{entry.get('value') or bucket['bucket_key']}")
            kind = "suppress"
    for entry in doc.get("mutes") or []:
        if not isinstance(entry, dict) or not _mute_live(entry, moment):
            continue
        if _matches_scope(entry, bucket_key=bucket["bucket_key"], rule_key=bucket["rule_key"]):
            scope = str(entry.get("scope") or "bucket")
            token = bucket["bucket_key"] if scope == "bucket" else bucket["rule_key"]
            reasons.append(f"mute_{scope}:{token}")
            if kind is None:
                kind = "mute"
            expires_at = entry.get("expires_at")
    return {
        "matched": bool(reasons),
        "reasons": reasons,
        "kind": kind,
        "expires_at": expires_at,
        "bucket": bucket,
    }


def explain_scoped(match_result: Dict[str, Any]) -> str:
    reasons = match_result.get("reasons") or []
    joined = ", ".join(str(item) for item in reasons) if reasons else "suppress"
    if match_result.get("kind") == "mute":
        return (
            f"Muted until {format_expiry(match_result.get('expires_at'))} ({joined}) — "
            "severity forced low; recommendation ignore."
        )
    return (
        f"Suppress matched ({joined}) — "
        "severity forced low; recommendation ignore."
    )
