"""
SQLite storage for the AI SOC Assistant.

Source of truth for triage events, containment blocks, and containment audit.
CSV / JSON files remain for one-time migration and optional export only.

Env:
  SOC_DB_PATH  — default data/soc_assistant.db

Thread safety: check_same_thread=False + RLock; WAL mode enabled.
Schema is plain SQL (SQLAlchemy-friendly column names for a future Postgres move).
"""

from __future__ import annotations

import csv
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None

# Legacy file paths (migration / optional export only)
DATA_DIR = Path("data")
LEGACY_TRIAGE_CSV = DATA_DIR / "triage_report.csv"
LEGACY_BLOCKED_JSON = DATA_DIR / "blocked_entities.json"
LEGACY_AUDIT_JSONL = DATA_DIR / "containment_audit.jsonl"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS triage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    log TEXT,
    severity TEXT,
    ml_prediction TEXT,
    ml_confidence REAL,
    rule_based TEXT,
    "user" TEXT,
    ip TEXT,
    containment_decision TEXT,
    containment_note TEXT,
    source TEXT,
    raw_json TEXT
);

CREATE TABLE IF NOT EXISTS containment_blocks (
    entity_type TEXT NOT NULL CHECK(entity_type IN ('ip', 'user')),
    entity_value TEXT NOT NULL,
    created_at TEXT NOT NULL,
    mode TEXT,
    note TEXT,
    PRIMARY KEY (entity_type, entity_value)
);

CREATE TABLE IF NOT EXISTS containment_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_value TEXT,
    mode TEXT,
    detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_triage_timestamp ON triage_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_triage_severity ON triage_events(severity);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON containment_audit(ts);
"""

TRIAGE_COLUMNS = [
    "id",
    "timestamp",
    "log",
    "severity",
    "ml_prediction",
    "ml_confidence",
    "rule_based",
    "user",
    "ip",
    "containment_decision",
    "containment_note",
    "source",
    "raw_json",
]


def get_db_path() -> Path:
    raw = (os.environ.get("SOC_DB_PATH") or "data/soc_assistant.db").strip()
    return Path(raw)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_connection(db_path: Optional[Path | str] = None) -> sqlite3.Connection:
    """Return a process-wide connection (or a one-off for a custom path in tests)."""
    global _conn
    path = Path(db_path) if db_path is not None else get_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    with _lock:
        # Dedicated connection when caller passes an explicit path (unit tests)
        if db_path is not None:
            conn = sqlite3.connect(str(path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            return conn

        if _conn is None:
            _conn = sqlite3.connect(str(path), check_same_thread=False)
            _conn.row_factory = sqlite3.Row
            _conn.execute("PRAGMA journal_mode=WAL")
            _conn.execute("PRAGMA foreign_keys=ON")
        return _conn


def reset_connection() -> None:
    """Close and clear the global connection (tests / path changes)."""
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None


def init_db(db_path: Optional[Path | str] = None) -> Path:
    """Create tables if needed. Returns the DB path used."""
    path = Path(db_path) if db_path is not None else get_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if db_path is not None:
        conn = get_connection(path)
        try:
            with _lock:
                conn.executescript(SCHEMA_SQL)
                conn.commit()
        finally:
            conn.close()
    else:
        conn = get_connection()
        with _lock:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
    return path


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {k: row[k] for k in row.keys()}


# ---------------------------------------------------------------------------
# Triage events
# ---------------------------------------------------------------------------

def insert_triage_event(
    event: Dict[str, Any],
    *,
    db_path: Optional[Path | str] = None,
    source: Optional[str] = None,
) -> int:
    """Insert one triage event. Returns new row id."""
    path = Path(db_path) if db_path is not None else None
    if path is not None:
        init_db(path)
        conn = get_connection(path)
        own = True
    else:
        init_db()
        conn = get_connection()
        own = False

    ts = event.get("timestamp")
    if hasattr(ts, "isoformat"):
        ts = ts.isoformat()
    elif ts is not None:
        ts = str(ts)

    ml_conf = event.get("ml_confidence")
    try:
        ml_conf = float(ml_conf) if ml_conf is not None and ml_conf != "" else None
    except (TypeError, ValueError):
        ml_conf = None

    src = source if source is not None else event.get("source")
    raw = event.get("raw_json")
    if raw is None:
        try:
            raw = json.dumps(event, default=str)
        except Exception:
            raw = None

    sql = """
        INSERT INTO triage_events (
            timestamp, log, severity, ml_prediction, ml_confidence,
            rule_based, "user", ip, containment_decision, containment_note,
            source, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    values = (
        ts,
        event.get("log"),
        event.get("severity"),
        event.get("ml_prediction"),
        ml_conf,
        event.get("rule_based"),
        event.get("user"),
        event.get("ip"),
        event.get("containment_decision"),
        event.get("containment_note"),
        src,
        raw,
    )
    with _lock:
        cur = conn.execute(sql, values)
        conn.commit()
        row_id = int(cur.lastrowid)
    if own:
        conn.close()
    return row_id


def list_triage_events(
    *,
    view: str = "total",
    limit: Optional[int] = None,
    severity: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> List[Dict[str, Any]]:
    """
    List triage events newest-first.

    view: total | severe | escalated (same semantics as report_filters).
    Optional severity exact filter (case-insensitive) applied before view filter.
    """
    path = Path(db_path) if db_path is not None else None
    if path is not None:
        init_db(path)
        conn = get_connection(path)
        own = True
    else:
        init_db()
        conn = get_connection()
        own = False

    with _lock:
        rows = conn.execute(
            """
            SELECT id, timestamp, log, severity, ml_prediction, ml_confidence,
                   rule_based, "user", ip, containment_decision, containment_note,
                   source, raw_json
            FROM triage_events
            ORDER BY timestamp DESC, id DESC
            """
        ).fetchall()
    if own:
        conn.close()

    events = [_row_to_dict(r) for r in rows]

    if severity:
        sev = severity.strip().lower()
        events = [e for e in events if str(e.get("severity") or "").strip().lower() == sev]

    view_key = (view or "total").strip().lower()
    if view_key in ("severe", "escalated"):
        try:
            import pandas as pd
            from report_filters import filter_report_df

            if events:
                df = pd.DataFrame(events)
                df = filter_report_df(df, view_key)
                events = df.to_dict(orient="records")
            else:
                events = []
        except Exception:
            # Fallback without pandas: severe ≈ high/critical
            if view_key == "severe":
                events = [
                    e
                    for e in events
                    if str(e.get("severity") or "").lower() in ("high", "critical")
                ]
            elif view_key == "escalated":
                events = [
                    e
                    for e in events
                    if str(e.get("rule_based") or "").lower() == "escalate"
                    or str(e.get("ml_prediction") or "").lower()
                    in ("high", "critical", "high risk", "high_risk", "escalate")
                ]

    if limit is not None and limit >= 0:
        events = events[: int(limit)]
    return events


def count_alerts(db_path: Optional[Path | str] = None) -> Dict[str, int]:
    """Return total / severe / escalated counts for dashboard badges."""
    events = list_triage_events(view="total", db_path=db_path)
    try:
        import pandas as pd
        from report_filters import compute_alert_counts

        if not events:
            return compute_alert_counts(pd.DataFrame())
        return compute_alert_counts(pd.DataFrame(events))
    except Exception:
        n = len(events)
        severe = sum(
            1
            for e in events
            if str(e.get("severity") or "").lower() in ("high", "critical")
        )
        escalated = sum(
            1
            for e in events
            if str(e.get("rule_based") or "").lower() == "escalate"
        )
        return {
            "total_alerts": n,
            "report_rows": n,
            "severe_alerts": severe,
            "escalated_events": escalated,
        }


def triage_event_count(db_path: Optional[Path | str] = None) -> int:
    path = Path(db_path) if db_path is not None else None
    if path is not None:
        init_db(path)
        conn = get_connection(path)
        own = True
    else:
        init_db()
        conn = get_connection()
        own = False
    with _lock:
        n = int(conn.execute("SELECT COUNT(*) FROM triage_events").fetchone()[0])
    if own:
        conn.close()
    return n


# ---------------------------------------------------------------------------
# Containment blocks
# ---------------------------------------------------------------------------

def load_blocks(db_path: Optional[Path | str] = None) -> Dict[str, list]:
    path = Path(db_path) if db_path is not None else None
    if path is not None:
        init_db(path)
        conn = get_connection(path)
        own = True
    else:
        init_db()
        conn = get_connection()
        own = False
    with _lock:
        rows = conn.execute(
            "SELECT entity_type, entity_value FROM containment_blocks"
        ).fetchall()
    if own:
        conn.close()
    out: Dict[str, list] = {"ips": [], "users": []}
    for r in rows:
        if r["entity_type"] == "ip":
            out["ips"].append(r["entity_value"])
        elif r["entity_type"] == "user":
            out["users"].append(r["entity_value"])
    return out


def save_block(
    entity_type: str,
    entity_value: str,
    *,
    mode: Optional[str] = None,
    note: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> bool:
    """Upsert a block. Returns True if newly inserted."""
    entity_type = (entity_type or "").strip().lower()
    entity_value = (entity_value or "").strip()
    if entity_type not in ("ip", "user") or not entity_value:
        return False

    path = Path(db_path) if db_path is not None else None
    if path is not None:
        init_db(path)
        conn = get_connection(path)
        own = True
    else:
        init_db()
        conn = get_connection()
        own = False

    with _lock:
        existing = conn.execute(
            "SELECT 1 FROM containment_blocks WHERE entity_type=? AND entity_value=?",
            (entity_type, entity_value),
        ).fetchone()
        if existing:
            changed = False
        else:
            conn.execute(
                """
                INSERT INTO containment_blocks
                    (entity_type, entity_value, created_at, mode, note)
                VALUES (?, ?, ?, ?, ?)
                """,
                (entity_type, entity_value, _utc_now_iso(), mode, note),
            )
            conn.commit()
            changed = True
    if own:
        conn.close()
    return changed


def remove_block(
    entity_type: str,
    entity_value: str,
    *,
    db_path: Optional[Path | str] = None,
) -> bool:
    """Remove a block. Returns True if a row was deleted."""
    entity_type = (entity_type or "").strip().lower()
    entity_value = (entity_value or "").strip()
    if entity_type not in ("ip", "user") or not entity_value:
        return False

    path = Path(db_path) if db_path is not None else None
    if path is not None:
        init_db(path)
        conn = get_connection(path)
        own = True
    else:
        init_db()
        conn = get_connection()
        own = False

    with _lock:
        cur = conn.execute(
            "DELETE FROM containment_blocks WHERE entity_type=? AND entity_value=?",
            (entity_type, entity_value),
        )
        conn.commit()
        changed = cur.rowcount > 0
    if own:
        conn.close()
    return changed


def append_audit(
    action: str,
    entity_type: str,
    entity_value: str,
    *,
    mode: Optional[str] = None,
    detail: Optional[Any] = None,
    db_path: Optional[Path | str] = None,
) -> int:
    """Append a containment audit row. Returns new id."""
    path = Path(db_path) if db_path is not None else None
    if path is not None:
        init_db(path)
        conn = get_connection(path)
        own = True
    else:
        init_db()
        conn = get_connection()
        own = False

    if detail is not None and not isinstance(detail, str):
        try:
            detail = json.dumps(detail, default=str)
        except Exception:
            detail = str(detail)

    with _lock:
        cur = conn.execute(
            """
            INSERT INTO containment_audit (ts, action, entity_type, entity_value, mode, detail)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                _utc_now_iso(),
                action,
                entity_type,
                entity_value,
                mode,
                detail,
            ),
        )
        conn.commit()
        row_id = int(cur.lastrowid)
    if own:
        conn.close()
    return row_id


def list_audit(
    *,
    limit: int = 100,
    db_path: Optional[Path | str] = None,
) -> List[Dict[str, Any]]:
    path = Path(db_path) if db_path is not None else None
    if path is not None:
        init_db(path)
        conn = get_connection(path)
        own = True
    else:
        init_db()
        conn = get_connection()
        own = False
    with _lock:
        rows = conn.execute(
            """
            SELECT id, ts, action, entity_type, entity_value, mode, detail
            FROM containment_audit
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    if own:
        conn.close()
    return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Migration from legacy CSV / JSON / JSONL
# ---------------------------------------------------------------------------

def _table_empty(conn: sqlite3.Connection, table: str) -> bool:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) == 0


def migrate_from_legacy_files(
    *,
    db_path: Optional[Path | str] = None,
    triage_csv: Optional[Path | str] = None,
    blocked_json: Optional[Path | str] = None,
    audit_jsonl: Optional[Path | str] = None,
) -> Dict[str, int]:
    """
    One-time import when DB tables are empty and legacy files exist.
    Returns counts: triage, blocks, audit.
    """
    path = Path(db_path) if db_path is not None else get_db_path()
    init_db(path)
    # Use a dedicated connection for migration so counts are consistent in tests
    conn = get_connection(path)
    triage_csv = Path(triage_csv) if triage_csv else LEGACY_TRIAGE_CSV
    blocked_json = Path(blocked_json) if blocked_json else LEGACY_BLOCKED_JSON
    audit_jsonl = Path(audit_jsonl) if audit_jsonl else LEGACY_AUDIT_JSONL

    counts = {"triage": 0, "blocks": 0, "audit": 0}

    try:
        with _lock:
            # --- triage CSV ---
            if _table_empty(conn, "triage_events") and triage_csv.exists():
                with triage_csv.open(newline="", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        ml_conf = row.get("ml_confidence")
                        try:
                            ml_conf_v = (
                                float(ml_conf)
                                if ml_conf not in (None, "")
                                else None
                            )
                        except (TypeError, ValueError):
                            ml_conf_v = None
                        conn.execute(
                            """
                            INSERT INTO triage_events (
                                timestamp, log, severity, ml_prediction, ml_confidence,
                                rule_based, "user", ip, containment_decision,
                                containment_note, source, raw_json
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                row.get("timestamp") or row.get("date"),
                                row.get("log"),
                                row.get("severity"),
                                row.get("ml_prediction"),
                                ml_conf_v,
                                row.get("rule_based") or row.get("recommendation"),
                                row.get("user"),
                                row.get("ip"),
                                row.get("containment_decision"),
                                row.get("containment_note"),
                                "legacy_csv",
                                json.dumps(row, default=str),
                            ),
                        )
                        counts["triage"] += 1
                conn.commit()

            # --- blocked JSON ---
            if _table_empty(conn, "containment_blocks") and blocked_json.exists():
                try:
                    data = json.loads(blocked_json.read_text(encoding="utf-8"))
                except Exception:
                    data = {}
                now = _utc_now_iso()
                for ip in data.get("ips") or []:
                    ip = str(ip).strip()
                    if not ip:
                        continue
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO containment_blocks
                            (entity_type, entity_value, created_at, mode, note)
                        VALUES ('ip', ?, ?, 'migrated', 'imported from blocked_entities.json')
                        """,
                        (ip, now),
                    )
                    counts["blocks"] += 1
                for user in data.get("users") or []:
                    user = str(user).strip()
                    if not user:
                        continue
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO containment_blocks
                            (entity_type, entity_value, created_at, mode, note)
                        VALUES ('user', ?, ?, 'migrated', 'imported from blocked_entities.json')
                        """,
                        (user, now),
                    )
                    counts["blocks"] += 1
                conn.commit()

            # --- audit JSONL ---
            if _table_empty(conn, "containment_audit") and audit_jsonl.exists():
                with audit_jsonl.open(encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            row = json.loads(line)
                        except Exception:
                            continue
                        detail = row.get("extra") or row.get("result")
                        if detail is not None and not isinstance(detail, str):
                            detail = json.dumps(detail, default=str)
                        # Prefer result in detail when extra missing
                        if row.get("result") and row.get("extra") is None:
                            detail = json.dumps(
                                {"result": row.get("result")}, default=str
                            )
                        conn.execute(
                            """
                            INSERT INTO containment_audit
                                (ts, action, entity_type, entity_value, mode, detail)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                row.get("timestamp") or row.get("ts") or _utc_now_iso(),
                                row.get("event") or row.get("action") or "unknown",
                                row.get("target_type") or row.get("entity_type"),
                                row.get("target") or row.get("entity_value"),
                                row.get("mode"),
                                detail,
                            ),
                        )
                        counts["audit"] += 1
                conn.commit()
    finally:
        conn.close()
        # If we migrated into the default path, reset global conn so it sees data
        if db_path is None or Path(db_path) == get_db_path():
            reset_connection()

    if any(counts.values()):
        logger.info(
            "Migrated legacy data into SQLite: triage=%s blocks=%s audit=%s → %s",
            counts["triage"],
            counts["blocks"],
            counts["audit"],
            path,
        )
        print(
            f"[storage] Migrated legacy files → SQLite "
            f"(triage={counts['triage']}, blocks={counts['blocks']}, "
            f"audit={counts['audit']}) at {path}"
        )
    return counts


def ensure_db_ready(db_path: Optional[Path | str] = None) -> Dict[str, int]:
    """Create schema and run one-time legacy migration if needed."""
    init_db(db_path)
    return migrate_from_legacy_files(db_path=db_path)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

EXPORT_FIELDS = [
    "timestamp",
    "log",
    "ip",
    "user",
    "severity",
    "rule_based",
    "ml_prediction",
    "ml_confidence",
    "containment_decision",
    "containment_note",
]


def export_triage_to_csv(
    dest: Path | str,
    *,
    db_path: Optional[Path | str] = None,
    view: str = "total",
    limit: Optional[int] = None,
) -> int:
    """Export triage events to CSV. Returns rows written."""
    events = list_triage_events(view=view, limit=limit, db_path=db_path)
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EXPORT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for e in events:
            writer.writerow({k: e.get(k) for k in EXPORT_FIELDS})
    return len(events)
