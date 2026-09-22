"""Developer/lab labeling helpers: enqueue, CSV ingest, disagreement, FP samples.

Customer consoles do not call these paths. Storage is the same label_queue /
alerts_labeled tables used by the Labeling page.
"""

from __future__ import annotations

import csv
import io
import os
from typing import Any, Dict, Iterable, List, Optional

import db
from rbac import parse_developer_emails, training_console_enabled

VALID_SEVERITIES = db.VALID_LABEL_SEVERITIES
TRAINING_COLUMNS = list(db.LABELED_CSV_FIELDS)
DISAGREEMENT_SOURCE = "disagreement"
LOW_CONFIDENCE_SOURCE = "low_confidence"


def normalize_severity(value: Any) -> Optional[str]:
    sev = str(value or "").strip().lower()
    if sev in VALID_SEVERITIES:
        return sev
    return None


def developer_training_configured() -> bool:
    """True when this install is a lab that may auto-queue training rows.

    Customer installs leave SOC_DEVELOPER_EMAILS and SOC_DEV_TRAINING unset and
    have no stored developer account, so this stays false.
    """
    if training_console_enabled():
        return True
    if parse_developer_emails():
        return True
    try:
        from accounts import account_is_active, list_accounts

        for row in list_accounts():
            if str(row.get("role") or "").lower() != "developer":
                continue
            if account_is_active(row):
                return True
    except Exception:
        return False
    return False


def disagreement_cap() -> int:
    raw = os.environ.get("LABEL_DISAGREEMENT_CAP", "20")
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 20


def _parse_raw(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            import json

            payload = json.loads(raw)
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}
    return {}


def rule_severity_of(event: Dict[str, Any]) -> Optional[str]:
    direct = normalize_severity(event.get("rule_severity"))
    if direct:
        return direct
    raw = _parse_raw(event.get("raw_json"))
    from_raw = normalize_severity(raw.get("rule_severity"))
    if from_raw:
        return from_raw
    source = str(event.get("severity_source") or "").strip().lower()
    if source in {"", "rules", "allowlist", "hybrid"}:
        return normalize_severity(event.get("severity"))
    return None


def classify_label_source(
    event: Dict[str, Any],
    *,
    threshold: Optional[float] = None,
) -> Optional[str]:
    """Return disagreement / low_confidence, or None when ML and rules align."""
    if threshold is None:
        try:
            from triage_engine import get_ml_confidence_threshold

            threshold = get_ml_confidence_threshold()
        except Exception:
            threshold = 0.70
    ml = normalize_severity(event.get("ml_prediction") or event.get("ml_severity"))
    rule = rule_severity_of(event)
    try:
        conf = float(event.get("ml_confidence") or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    if ml and rule and ml != rule:
        return DISAGREEMENT_SOURCE
    if ml is not None and conf < float(threshold):
        return LOW_CONFIDENCE_SOURCE
    return None


def item_from_triage(event: Dict[str, Any]) -> Dict[str, Any]:
    raw = _parse_raw(event.get("raw_json"))
    log = str(event.get("log") or raw.get("log") or "").strip()
    summary = log[:500] if log else str(event.get("summary") or "triage event")
    rule_id = event.get("matched_rule_id") or event.get("rule_id") or raw.get("matched_rule_id") or raw.get("rule_id")
    event_type = str(event.get("event_type") or "").strip()
    if not event_type:
        event_type = f"rule_{rule_id}" if rule_id else "triage_event"
    return {
        "summary": summary,
        "full_log": log or summary,
        "agent": event.get("host") or event.get("agent"),
        "rule_id": rule_id,
        "severity": event.get("severity"),
        "source_ip": event.get("ip") or event.get("source_ip") or "",
        "username": event.get("user") or event.get("username") or "",
        "event_type": event_type,
        "event_timestamp": event.get("timestamp"),
        "triage_event_id": event.get("id"),
    }


def item_from_case(case: Dict[str, Any]) -> Dict[str, Any]:
    summary = str(case.get("summary") or case.get("title") or "").strip() or f"case {case.get('id')}"
    return {
        "summary": summary[:500],
        "full_log": summary,
        "agent": case.get("host"),
        "severity": case.get("severity"),
        "source_ip": case.get("ip") or "",
        "username": case.get("user_entity") or "",
        "event_type": "case",
        "event_timestamp": case.get("created_at"),
        "case_id": case.get("id"),
        "triage_event_id": case.get("triage_event_id"),
    }


def enqueue_for_label(
    item: Dict[str, Any],
    source: str,
    *,
    db_path=None,
) -> Dict[str, Any]:
    payload = dict(item)
    payload["source"] = source
    return db.insert_label_queue_items([payload], source=source, db_path=db_path)


def submit_correct_label(
    item: Dict[str, Any],
    severity: str,
    *,
    source: str,
    notes: Optional[str] = None,
    db_path=None,
) -> Dict[str, Any]:
    """Enqueue (deduped) and store the analyst severity as a training row."""
    sev = normalize_severity(severity)
    if sev is None:
        raise ValueError(f"Invalid severity: {severity}")
    payload = dict(item)
    payload["source"] = source
    result = db.insert_label_queue_items([payload], source=source, db_path=db_path)
    queue_id = None
    if result.get("ids"):
        queue_id = result["ids"][0]
    elif result.get("duplicate_ids"):
        queue_id = result["duplicate_ids"][0]
    labeled = False
    if queue_id is not None:
        try:
            db.save_label(int(queue_id), sev, notes=notes, db_path=db_path)
            labeled = True
        except ValueError:
            labeled = False
    out = dict(result)
    out["queue_id"] = queue_id
    out["labeled"] = labeled
    out["severity"] = sev
    return out


def maybe_auto_queue_disagreement(
    event: Dict[str, Any],
    *,
    db_path=None,
    enabled: Optional[bool] = None,
    cap: Optional[int] = None,
    threshold: Optional[float] = None,
) -> Dict[str, Any]:
    """Queue a modest number of ML/rules disagreements. Low confidence stays manual."""
    if enabled is None:
        enabled = developer_training_configured()
    if not enabled:
        return {"inserted": 0, "skipped_dupes": 0, "total_seen": 0, "reason": "disabled"}
    kind = classify_label_source(event, threshold=threshold)
    if kind != DISAGREEMENT_SOURCE:
        return {
            "inserted": 0,
            "skipped_dupes": 0,
            "total_seen": 0,
            "reason": kind or "none",
        }
    limit = disagreement_cap() if cap is None else int(cap)
    pending = db.count_label_queue(status="pending", source=DISAGREEMENT_SOURCE, db_path=db_path)
    if pending >= limit:
        return {"inserted": 0, "skipped_dupes": 0, "total_seen": 0, "reason": "capped"}
    result = enqueue_for_label(item_from_triage(event), DISAGREEMENT_SOURCE, db_path=db_path)
    result["reason"] = DISAGREEMENT_SOURCE
    return result


def import_labeled_csv_text(
    text: str,
    *,
    db_path=None,
    label_source: str = "csv",
) -> Dict[str, Any]:
    """Validate a labeling CSV and merge accepted rows into training data."""
    sample = text if text is not None else ""
    if sample.startswith("\ufeff"):
        sample = sample.lstrip("\ufeff")
    reader = csv.DictReader(io.StringIO(sample))
    fieldnames = reader.fieldnames or []
    fields = {}
    for name in fieldnames:
        if not name:
            continue
        fields[name.strip().lower()] = name
    missing = [col for col in TRAINING_COLUMNS if col not in fields]
    if missing or not fieldnames:
        return {
            "ok": False,
            "accepted": 0,
            "rejected": 0,
            "skipped_dupes": 0,
            "message": "Missing columns",
            "errors": missing,
        }

    accepted: List[Dict[str, Any]] = []
    rejected = 0
    errors: List[str] = []
    for index, raw in enumerate(reader, start=2):
        if raw is None:
            continue
        row = {col: str(raw.get(fields[col]) or "").strip() for col in TRAINING_COLUMNS}
        sev = normalize_severity(row["severity"])
        if sev is None:
            rejected += 1
            if len(errors) < 8:
                errors.append(f"row {index}: severity")
            continue
        if not row["description"] and not row["event_type"]:
            rejected += 1
            if len(errors) < 8:
                errors.append(f"row {index}: empty")
            continue
        row["severity"] = sev
        src = label_source
        if "label_source" in fields:
            custom = str(raw.get(fields["label_source"]) or "").strip()
            if custom:
                src = custom
        accepted.append({**row, "label_source": src})

    written = db.insert_labeled_training_rows(accepted, db_path=db_path, append_csv=True)
    return {
        "ok": True,
        "accepted": int(written.get("inserted") or 0),
        "rejected": rejected,
        "skipped_dupes": int(written.get("skipped_dupes") or 0),
        "message": f"Accepted {int(written.get('inserted') or 0)}, rejected {rejected}.",
        "errors": errors,
    }


def enqueue_fp_samples(
    events: Iterable[Dict[str, Any]],
    rule_key: str,
    *,
    limit: int = 5,
    db_path=None,
) -> Dict[str, Any]:
    """Enqueue up to ``limit`` distinct recent events for one noisy rule."""
    from detection.fp_review import extract_rule_key

    key = str(rule_key or "").strip()
    if not key:
        return {"inserted": 0, "skipped_dupes": 0, "total_seen": 0, "reason": "missing_rule"}
    cap = max(1, min(int(limit or 5), 25))
    items: List[Dict[str, Any]] = []
    seen_logs = set()
    for event in events or []:
        if not isinstance(event, dict):
            continue
        if extract_rule_key(event) != key:
            continue
        item = item_from_triage(event)
        marker = (item.get("full_log") or "").strip()
        if not marker or marker in seen_logs:
            continue
        seen_logs.add(marker)
        item["source"] = "fp_review"
        items.append(item)
        if len(items) >= cap:
            break
    if not items:
        return {"inserted": 0, "skipped_dupes": 0, "total_seen": 0, "reason": "no_samples"}
    result = db.insert_label_queue_items(items, source="fp_review", db_path=db_path)
    result["reason"] = "fp_review"
    return result


def apply_bulk_labels(
    ids: Iterable[Any],
    action: str,
    severity: Optional[str] = None,
    *,
    db_path=None,
) -> Dict[str, Any]:
    act = (action or "").strip().lower()
    updated = 0
    failed = 0
    for raw_id in ids or []:
        try:
            queue_id = int(raw_id)
        except (TypeError, ValueError):
            failed += 1
            continue
        try:
            if act == "skip":
                db.skip_label(queue_id, db_path=db_path)
            elif act == "label":
                sev = normalize_severity(severity)
                if sev is None:
                    raise ValueError("severity required")
                db.save_label(queue_id, sev, db_path=db_path)
            else:
                raise ValueError("unknown action")
            updated += 1
        except Exception:
            failed += 1
    return {"ok": failed == 0 and updated > 0, "updated": updated, "failed": failed}
