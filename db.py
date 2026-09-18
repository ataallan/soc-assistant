"""
Flexible storage for the AI SOC Assistant (SQLAlchemy 2.x).

Default backend: SQLite at data/soc_assistant.db (SOC_DB_PATH).
Optional: PostgreSQL when SOC_DATABASE_URL or DATABASE_URL is set.

Source of truth for triage events, containment blocks, and containment audit.
CSV / JSON files remain for one-time migration and optional export only.

Env:
  SOC_DB_PATH         — SQLite file path (default data/soc_assistant.db)
  SOC_DATABASE_URL    — preferred Postgres (or other) SQLAlchemy URL
  DATABASE_URL        — fallback URL (same semantics)

Thread safety: process RLock around writes; SQLite uses check_same_thread=False
and WAL mode. Postgres uses pool_pre_ping and modest pool sizing.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union

from sqlalchemy import (
    CheckConstraint,
    Float,
    Integer,
    MetaData,
    Text,
    create_engine,
    event,
    func,
    select,
)
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

logger = logging.getLogger(__name__)

_lock = threading.RLock()
_engines: Dict[str, Engine] = {}
_session_factories: Dict[str, sessionmaker] = {}

# Legacy file paths (migration / optional export only)
DATA_DIR = Path("data")
LEGACY_TRIAGE_CSV = DATA_DIR / "triage_report.csv"
LEGACY_BLOCKED_JSON = DATA_DIR / "blocked_entities.json"
LEGACY_AUDIT_JSONL = DATA_DIR / "containment_audit.jsonl"

convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=convention)


class TriageEvent(Base):
    __tablename__ = "triage_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[Optional[str]] = mapped_column(Text, nullable=True, index=True)
    log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(Text, nullable=True, index=True)
    ml_prediction: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ml_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    rule_based: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    user: Mapped[Optional[str]] = mapped_column("user", Text, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    containment_decision: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    containment_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity_source: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ml_assist: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)


class LabelQueue(Base):
    """Pending Wazuh (or other) alerts awaiting analyst severity labels."""

    __tablename__ = "label_queue"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'labeled', 'skipped')",
            name="label_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    source: Mapped[str] = mapped_column(Text, nullable=False, default="wazuh")
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    full_log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_level: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    wazuh_severity: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending", index=True)
    label_severity: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    labeled_at: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class AlertsLabeled(Base):
    """Analyst-labeled alerts in training-row shape."""

    __tablename__ = "alerts_labeled"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    event_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(Text, nullable=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    label_source: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    queue_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)


class ContainmentBlock(Base):
    __tablename__ = "containment_blocks"
    __table_args__ = (
        CheckConstraint(
            "entity_type IN ('ip', 'user')",
            name="entity_type",
        ),
    )

    entity_type: Mapped[str] = mapped_column(Text, primary_key=True)
    entity_value: Mapped[str] = mapped_column(Text, primary_key=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)
    mode: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ContainmentAudit(Base):
    __tablename__ = "containment_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    entity_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    entity_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mode: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)



class Case(Base):
    """Lightweight SOC case / ticket linked optionally to a triage event."""

    __tablename__ = "cases"
    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'investigating', 'contained', 'closed')",
            name="case_status",
        ),
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="case_severity",
        ),
        CheckConstraint(
            "source IN ('triage', 'manual', 'wazuh')",
            name="case_source",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    updated_at: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="open", index=True)
    severity: Mapped[str] = mapped_column(Text, nullable=False, default="medium", index=True)
    assignee: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    triage_event_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    source: Mapped[str] = mapped_column(Text, nullable=False, default="manual")
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    user_entity: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Soft-migrated columns (SLA + external ticket sync)
    due_at: Mapped[Optional[str]] = mapped_column(Text, nullable=True, index=True)
    external_ticket_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    external_system: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    external_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class CaseNote(Base):
    """Chronological analyst notes on a case."""

    __tablename__ = "case_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)


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
    "severity_source",
    "ml_assist",
]


def get_db_path() -> Path:
    raw = (os.environ.get("SOC_DB_PATH") or "data/soc_assistant.db").strip()
    return Path(raw)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_database_url(url: str) -> str:
    """Normalize common Postgres URL forms to a SQLAlchemy 2.x URL."""
    url = url.strip()
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    # Prefer psycopg3 driver when no driver is specified
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


def get_database_url(db_path: Optional[Path | str] = None) -> str:
    """
    Resolve the SQLAlchemy database URL.

    - Explicit db_path (tests / one-off) → always SQLite for that file
    - Else SOC_DATABASE_URL or DATABASE_URL → Postgres (or whatever URL says)
    - Else SQLite via SOC_DB_PATH
    """
    if db_path is not None:
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{path.resolve().as_posix()}"

    env_url = (
        (os.environ.get("SOC_DATABASE_URL") or "").strip()
        or (os.environ.get("DATABASE_URL") or "").strip()
    )
    if env_url:
        return _normalize_database_url(env_url)

    path = get_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{path.resolve().as_posix()}"


def resolve_database_url(db_path: Optional[Path | str] = None) -> str:
    """Alias for get_database_url (public helper)."""
    return get_database_url(db_path)


def is_postgres_url(url: Optional[str] = None) -> bool:
    raw = url if url is not None else get_database_url()
    try:
        return make_url(raw).get_backend_name() == "postgresql"
    except Exception:
        return raw.startswith("postgresql")


def _create_engine(url: str) -> Engine:
    backend = make_url(url).get_backend_name()
    if backend == "sqlite":
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            pool_pre_ping=True,
        )

        @event.listens_for(engine, "connect")
        def _sqlite_on_connect(dbapi_conn, _connection_record):  # noqa: ANN001
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    # Postgres (and other server backends): sensible pool defaults
    return create_engine(
        url,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=1800,
    )


def get_engine(db_path: Optional[Path | str] = None) -> Engine:
    """Return a cached Engine for the resolved URL (or explicit SQLite path)."""
    url = get_database_url(db_path)
    with _lock:
        if url not in _engines:
            _engines[url] = _create_engine(url)
            _session_factories[url] = sessionmaker(
                bind=_engines[url],
                autoflush=False,
                autocommit=False,
                expire_on_commit=False,
            )
        return _engines[url]


def _session_factory(db_path: Optional[Path | str] = None) -> sessionmaker:
    url = get_database_url(db_path)
    get_engine(db_path)  # ensure cached
    return _session_factories[url]


@contextmanager
def session_scope(
    db_path: Optional[Path | str] = None,
) -> Generator[Session, None, None]:
    """Provide a transactional scope around a series of operations."""
    factory = _session_factory(db_path)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_connection() -> None:
    """Dispose and clear cached engines (tests / path or URL changes)."""
    global _engines, _session_factories
    with _lock:
        for eng in _engines.values():
            try:
                eng.dispose()
            except Exception:
                pass
        _engines = {}
        _session_factories = {}


def reset_engine() -> None:
    """Alias for reset_connection."""
    reset_connection()


def init_db(db_path: Optional[Path | str] = None) -> Union[Path, str]:
    """Create tables if needed. Returns SQLite Path or database URL string."""
    engine = get_engine(db_path)
    with _lock:
        Base.metadata.create_all(engine)
        _soft_migrate_columns(engine)
    url = get_database_url(db_path)
    if make_url(url).get_backend_name() == "sqlite":
        return Path(db_path) if db_path is not None else get_db_path()
    return url


def _soft_migrate_columns(engine: Engine) -> None:
    """Add newly introduced columns on existing SQLite DBs (create_all will not)."""
    try:
        backend = make_url(str(engine.url)).get_backend_name()
    except Exception:
        backend = "sqlite"
    if backend != "sqlite":
        # Postgres: rely on create_all for new tables; ALTER for known columns.
        stmts = [
            "ALTER TABLE triage_events ADD COLUMN IF NOT EXISTS severity_source TEXT",
            "ALTER TABLE triage_events ADD COLUMN IF NOT EXISTS ml_assist INTEGER",
            "ALTER TABLE cases ADD COLUMN IF NOT EXISTS due_at TEXT",
            "ALTER TABLE cases ADD COLUMN IF NOT EXISTS external_ticket_id TEXT",
            "ALTER TABLE cases ADD COLUMN IF NOT EXISTS external_system TEXT",
            "ALTER TABLE cases ADD COLUMN IF NOT EXISTS external_url TEXT",
        ]
        try:
            with engine.begin() as conn:
                for stmt in stmts:
                    try:
                        conn.exec_driver_sql(stmt)
                    except Exception as exc:
                        logger.debug("soft migrate skip: %s (%s)", stmt, exc)
        except Exception as exc:
            logger.debug("soft migrate postgres skipped: %s", exc)
        return

    wanted = {
        "triage_events": {
            "severity_source": "TEXT",
            "ml_assist": "INTEGER",
        },
        "cases": {
            "due_at": "TEXT",
            "external_ticket_id": "TEXT",
            "external_system": "TEXT",
            "external_url": "TEXT",
        },
    }
    with engine.begin() as conn:
        for table, cols in wanted.items():
            try:
                rows = conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
            except Exception:
                continue
            existing = {r[1] for r in rows}  # name is index 1
            for col, coltype in cols.items():
                if col in existing:
                    continue
                try:
                    conn.exec_driver_sql(
                        f"ALTER TABLE {table} ADD COLUMN {col} {coltype}"
                    )
                except Exception as exc:
                    logger.debug("soft migrate %s.%s: %s", table, col, exc)


def _triage_to_dict(row: TriageEvent) -> Dict[str, Any]:
    return {
        "id": row.id,
        "timestamp": row.timestamp,
        "log": row.log,
        "severity": row.severity,
        "ml_prediction": row.ml_prediction,
        "ml_confidence": row.ml_confidence,
        "rule_based": row.rule_based,
        "user": row.user,
        "ip": row.ip,
        "containment_decision": row.containment_decision,
        "containment_note": row.containment_note,
        "source": row.source,
        "raw_json": row.raw_json,
        "severity_source": getattr(row, "severity_source", None),
        "ml_assist": getattr(row, "ml_assist", None),
    }


def _audit_to_dict(row: ContainmentAudit) -> Dict[str, Any]:
    return {
        "id": row.id,
        "ts": row.ts,
        "action": row.action,
        "entity_type": row.entity_type,
        "entity_value": row.entity_value,
        "mode": row.mode,
        "detail": row.detail,
    }


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
    init_db(db_path)

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

    ml_assist_val = event.get("ml_assist")
    if ml_assist_val is None:
        ml_assist_int = None
    else:
        ml_assist_int = 1 if bool(ml_assist_val) else 0

    row = TriageEvent(
        timestamp=ts,
        log=event.get("log"),
        severity=event.get("severity"),
        ml_prediction=event.get("ml_prediction"),
        ml_confidence=ml_conf,
        rule_based=event.get("rule_based"),
        user=event.get("user"),
        ip=event.get("ip"),
        containment_decision=event.get("containment_decision"),
        containment_note=event.get("containment_note"),
        source=src,
        raw_json=raw,
        severity_source=event.get("severity_source"),
        ml_assist=ml_assist_int,
    )
    with _lock:
        with session_scope(db_path) as session:
            session.add(row)
            session.flush()
            row_id = int(row.id)
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
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            rows = session.scalars(
                select(TriageEvent).order_by(
                    TriageEvent.timestamp.desc(),
                    TriageEvent.id.desc(),
                )
            ).all()
            events = [_triage_to_dict(r) for r in rows]

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
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            n = int(session.scalar(select(func.count()).select_from(TriageEvent)) or 0)
    return n


# ---------------------------------------------------------------------------
# Containment blocks
# ---------------------------------------------------------------------------

def load_blocks(db_path: Optional[Path | str] = None) -> Dict[str, list]:
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            rows = session.scalars(select(ContainmentBlock)).all()
            out: Dict[str, list] = {"ips": [], "users": []}
            for r in rows:
                if r.entity_type == "ip":
                    out["ips"].append(r.entity_value)
                elif r.entity_type == "user":
                    out["users"].append(r.entity_value)
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

    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            existing = session.get(ContainmentBlock, (entity_type, entity_value))
            if existing:
                return False
            session.add(
                ContainmentBlock(
                    entity_type=entity_type,
                    entity_value=entity_value,
                    created_at=_utc_now_iso(),
                    mode=mode,
                    note=note,
                )
            )
    return True


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

    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            existing = session.get(ContainmentBlock, (entity_type, entity_value))
            if not existing:
                return False
            session.delete(existing)
    return True


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
    init_db(db_path)

    if detail is not None and not isinstance(detail, str):
        try:
            detail = json.dumps(detail, default=str)
        except Exception:
            detail = str(detail)

    row = ContainmentAudit(
        ts=_utc_now_iso(),
        action=action,
        entity_type=entity_type,
        entity_value=entity_value,
        mode=mode,
        detail=detail,
    )
    with _lock:
        with session_scope(db_path) as session:
            session.add(row)
            session.flush()
            row_id = int(row.id)
    return row_id


def list_audit(
    *,
    limit: int = 100,
    db_path: Optional[Path | str] = None,
) -> List[Dict[str, Any]]:
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            rows = session.scalars(
                select(ContainmentAudit)
                .order_by(ContainmentAudit.id.desc())
                .limit(int(limit))
            ).all()
            return [_audit_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Migration from legacy CSV / JSON / JSONL
# ---------------------------------------------------------------------------

def _table_empty(session: Session, model) -> bool:
    n = session.scalar(select(func.count()).select_from(model))
    return int(n or 0) == 0


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
    init_db(db_path)
    triage_csv = Path(triage_csv) if triage_csv else LEGACY_TRIAGE_CSV
    blocked_json = Path(blocked_json) if blocked_json else LEGACY_BLOCKED_JSON
    audit_jsonl = Path(audit_jsonl) if audit_jsonl else LEGACY_AUDIT_JSONL

    counts = {"triage": 0, "blocks": 0, "audit": 0}
    url = get_database_url(db_path)
    label = str(Path(db_path) if db_path is not None else (
        get_db_path() if not is_postgres_url(url) else url
    ))

    with _lock:
        with session_scope(db_path) as session:
            # --- triage CSV ---
            if _table_empty(session, TriageEvent) and triage_csv.exists():
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
                        session.add(
                            TriageEvent(
                                timestamp=row.get("timestamp") or row.get("date"),
                                log=row.get("log"),
                                severity=row.get("severity"),
                                ml_prediction=row.get("ml_prediction"),
                                ml_confidence=ml_conf_v,
                                rule_based=row.get("rule_based")
                                or row.get("recommendation"),
                                user=row.get("user"),
                                ip=row.get("ip"),
                                containment_decision=row.get("containment_decision"),
                                containment_note=row.get("containment_note"),
                                source="legacy_csv",
                                raw_json=json.dumps(row, default=str),
                            )
                        )
                        counts["triage"] += 1

            # --- blocked JSON ---
            if _table_empty(session, ContainmentBlock) and blocked_json.exists():
                try:
                    data = json.loads(blocked_json.read_text(encoding="utf-8"))
                except Exception:
                    data = {}
                now = _utc_now_iso()
                for ip in data.get("ips") or []:
                    ip = str(ip).strip()
                    if not ip:
                        continue
                    if session.get(ContainmentBlock, ("ip", ip)):
                        continue
                    session.add(
                        ContainmentBlock(
                            entity_type="ip",
                            entity_value=ip,
                            created_at=now,
                            mode="migrated",
                            note="imported from blocked_entities.json",
                        )
                    )
                    counts["blocks"] += 1
                for user in data.get("users") or []:
                    user = str(user).strip()
                    if not user:
                        continue
                    if session.get(ContainmentBlock, ("user", user)):
                        continue
                    session.add(
                        ContainmentBlock(
                            entity_type="user",
                            entity_value=user,
                            created_at=now,
                            mode="migrated",
                            note="imported from blocked_entities.json",
                        )
                    )
                    counts["blocks"] += 1

            # --- audit JSONL ---
            if _table_empty(session, ContainmentAudit) and audit_jsonl.exists():
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
                        if row.get("result") and row.get("extra") is None:
                            detail = json.dumps(
                                {"result": row.get("result")}, default=str
                            )
                        session.add(
                            ContainmentAudit(
                                ts=row.get("timestamp")
                                or row.get("ts")
                                or _utc_now_iso(),
                                action=row.get("event")
                                or row.get("action")
                                or "unknown",
                                entity_type=row.get("target_type")
                                or row.get("entity_type"),
                                entity_value=row.get("target")
                                or row.get("entity_value"),
                                mode=row.get("mode"),
                                detail=detail,
                            )
                        )
                        counts["audit"] += 1

    if any(counts.values()):
        logger.info(
            "Migrated legacy data into DB: triage=%s blocks=%s audit=%s → %s",
            counts["triage"],
            counts["blocks"],
            counts["audit"],
            label,
        )
        print(
            f"[storage] Migrated legacy files → DB "
            f"(triage={counts['triage']}, blocks={counts['blocks']}, "
            f"audit={counts['audit']}) at {label}"
        )
    return counts


def ensure_db_ready(db_path: Optional[Path | str] = None) -> Dict[str, int]:
    """Create schema and run one-time legacy migration if needed."""
    init_db(db_path)
    return migrate_from_legacy_files(db_path=db_path)



# ---------------------------------------------------------------------------
# Label queue (live Wazuh labeling pipeline)
# ---------------------------------------------------------------------------

LABELED_CSV_PATH = DATA_DIR / "labeled_alerts.csv"
LABELED_CSV_FIELDS = [
    "timestamp",
    "source_ip",
    "username",
    "event_type",
    "severity",
    "description",
]
VALID_LABEL_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


def _label_queue_to_dict(row: LabelQueue) -> Dict[str, Any]:
    return {
        "id": row.id,
        "created_at": row.created_at,
        "source": row.source,
        "summary": row.summary,
        "full_log": row.full_log,
        "agent": row.agent,
        "rule_id": row.rule_id,
        "rule_level": row.rule_level,
        "wazuh_severity": row.wazuh_severity,
        "status": row.status,
        "label_severity": row.label_severity,
        "labeled_at": row.labeled_at,
        "notes": row.notes,
    }


def _dedupe_key(summary: Optional[str], full_log: Optional[str]) -> str:
    s = (summary or "").strip()
    f = (full_log or "").strip()
    return f"{s}\n{f}"


def insert_label_queue_items(
    items: List[Dict[str, Any]],
    *,
    db_path: Optional[Path | str] = None,
    source: str = "wazuh",
) -> Dict[str, int]:
    """Insert new pending label-queue rows; dedupe by summary+full_log.

    Returns counts: inserted, skipped_dupes, total_seen.
    """
    init_db(db_path)
    inserted = 0
    skipped = 0
    seen = 0
    with _lock:
        with session_scope(db_path) as session:
            existing_rows = session.scalars(select(LabelQueue)).all()
            existing_keys = {
                _dedupe_key(r.summary, r.full_log) for r in existing_rows
            }
            for item in items or []:
                seen += 1
                summary = item.get("summary") or item.get("rule_description")
                full_log = item.get("full_log") or item.get("summary") or ""
                key = _dedupe_key(summary, full_log)
                if not key.strip() or key in existing_keys:
                    skipped += 1
                    continue
                existing_keys.add(key)
                level = item.get("rule_level")
                row = LabelQueue(
                    created_at=_utc_now_iso(),
                    source=source or item.get("source") or "wazuh",
                    summary=summary,
                    full_log=full_log,
                    agent=item.get("agent"),
                    rule_id=str(item.get("rule_id")) if item.get("rule_id") is not None else None,
                    rule_level=str(level) if level is not None else None,
                    wazuh_severity=item.get("severity") or item.get("wazuh_severity"),
                    status="pending",
                )
                session.add(row)
                inserted += 1
    return {"inserted": inserted, "skipped_dupes": skipped, "total_seen": seen}


def list_label_queue(
    *,
    status: str = "pending",
    limit: Optional[int] = None,
    db_path: Optional[Path | str] = None,
) -> List[Dict[str, Any]]:
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            stmt = select(LabelQueue).order_by(LabelQueue.id.desc())
            if status and status != "all":
                stmt = stmt.where(LabelQueue.status == status)
            rows = session.scalars(stmt).all()
            out = [_label_queue_to_dict(r) for r in rows]
    if limit is not None and limit >= 0:
        out = out[: int(limit)]
    return out


def _append_labeled_csv(row: Dict[str, Any], csv_path: Path | str = None) -> None:
    dest = Path(csv_path) if csv_path is not None else LABELED_CSV_PATH
    dest.parent.mkdir(parents=True, exist_ok=True)
    write_header = not dest.exists() or dest.stat().st_size == 0
    with dest.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=LABELED_CSV_FIELDS, extrasaction="ignore")
        if write_header:
            writer.writeheader()
        writer.writerow({k: row.get(k) for k in LABELED_CSV_FIELDS})


def save_label(
    queue_id: int,
    label_severity: str,
    *,
    notes: Optional[str] = None,
    db_path: Optional[Path | str] = None,
    append_csv: bool = True,
) -> Dict[str, Any]:
    """Mark a queue item labeled; write alerts_labeled + optional CSV row."""
    sev = (label_severity or "").strip().lower()
    if sev not in VALID_LABEL_SEVERITIES:
        raise ValueError(f"Invalid label_severity: {label_severity}")

    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            row = session.get(LabelQueue, int(queue_id))
            if row is None:
                raise KeyError(f"label_queue id {queue_id} not found")
            if row.status != "pending":
                raise ValueError(f"Queue item {queue_id} is already {row.status}")

            now = _utc_now_iso()
            row.status = "labeled"
            row.label_severity = sev
            row.labeled_at = now
            if notes is not None:
                row.notes = notes

            summary = row.summary or row.full_log or ""
            training = {
                "timestamp": now,
                "source_ip": "",
                "username": "",
                "event_type": f"wazuh_rule_{row.rule_id}" if row.rule_id else "wazuh_alert",
                "severity": sev,
                "description": summary,
            }
            # Best-effort IP/user extraction from text
            try:
                from nlp_utils import extract_ip, extract_user
                text_blob = f"{row.full_log or ''} {row.summary or ''}"
                training["source_ip"] = extract_ip(text_blob) or ""
                training["username"] = extract_user(text_blob) or ""
            except Exception:
                pass

            labeled = AlertsLabeled(
                timestamp=training["timestamp"],
                source_ip=training["source_ip"] or None,
                username=training["username"] or None,
                event_type=training["event_type"],
                severity=sev,
                description=training["description"],
                label_source=row.source or "wazuh",
                queue_id=row.id,
                created_at=now,
            )
            session.add(labeled)
            session.flush()
            result = {
                "ok": True,
                "id": row.id,
                "label_severity": sev,
                "training_row": training,
                "alerts_labeled_id": int(labeled.id),
            }

    if append_csv:
        _append_labeled_csv(result["training_row"])
    return result


def skip_label(
    queue_id: int,
    *,
    notes: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> Dict[str, Any]:
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            row = session.get(LabelQueue, int(queue_id))
            if row is None:
                raise KeyError(f"label_queue id {queue_id} not found")
            if row.status != "pending":
                raise ValueError(f"Queue item {queue_id} is already {row.status}")
            row.status = "skipped"
            row.labeled_at = _utc_now_iso()
            if notes is not None:
                row.notes = notes
            return {"ok": True, "id": row.id, "status": "skipped"}


def export_labeled_alerts_csv(
    dest: Path | str = None,
    *,
    db_path: Optional[Path | str] = None,
) -> int:
    """Export alerts_labeled table to training CSV. Returns rows written."""
    init_db(db_path)
    dest = Path(dest) if dest is not None else LABELED_CSV_PATH
    dest.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        with session_scope(db_path) as session:
            rows = session.scalars(select(AlertsLabeled).order_by(AlertsLabeled.id.asc())).all()
            records = [
                {
                    "timestamp": r.timestamp,
                    "source_ip": r.source_ip or "",
                    "username": r.username or "",
                    "event_type": r.event_type or "",
                    "severity": r.severity or "",
                    "description": r.description or "",
                }
                for r in rows
            ]
    with dest.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=LABELED_CSV_FIELDS)
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)
    return len(records)


def label_queue_counts(db_path: Optional[Path | str] = None) -> Dict[str, int]:
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            pending = int(
                session.scalar(
                    select(func.count()).select_from(LabelQueue).where(LabelQueue.status == "pending")
                )
                or 0
            )
            labeled = int(
                session.scalar(
                    select(func.count()).select_from(LabelQueue).where(LabelQueue.status == "labeled")
                )
                or 0
            )
            skipped = int(
                session.scalar(
                    select(func.count()).select_from(LabelQueue).where(LabelQueue.status == "skipped")
                )
                or 0
            )
            alerts_n = int(
                session.scalar(select(func.count()).select_from(AlertsLabeled)) or 0
            )
    return {
        "pending": pending,
        "labeled": labeled,
        "skipped": skipped,
        "alerts_labeled": alerts_n,
    }



# ---------------------------------------------------------------------------
# Cases (lightweight SOC ticket workflow)
# ---------------------------------------------------------------------------

VALID_CASE_STATUSES = frozenset({"open", "investigating", "contained", "closed"})
VALID_CASE_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
VALID_CASE_SOURCES = frozenset({"triage", "manual", "wazuh"})


def _case_to_dict(row: Case) -> Dict[str, Any]:
    due_at = getattr(row, "due_at", None)
    out = {
        "id": row.id,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "title": row.title,
        "status": row.status,
        "severity": row.severity,
        "assignee": row.assignee,
        "triage_event_id": row.triage_event_id,
        "source": row.source,
        "summary": row.summary,
        "ip": row.ip,
        "user_entity": row.user_entity,
        "resolution_notes": row.resolution_notes,
        "due_at": due_at,
        "external_ticket_id": getattr(row, "external_ticket_id", None),
        "external_system": getattr(row, "external_system", None),
        "external_url": getattr(row, "external_url", None),
    }
    # Computed (not stored): sla_breached / overdue
    try:
        from sla import is_overdue

        out["is_overdue"] = is_overdue(out)
        out["sla_breached"] = out["is_overdue"]
    except Exception:
        out["is_overdue"] = False
        out["sla_breached"] = False
    return out


def _case_note_to_dict(row: CaseNote) -> Dict[str, Any]:
    return {
        "id": row.id,
        "case_id": row.case_id,
        "created_at": row.created_at,
        "author": row.author,
        "body": row.body,
    }


def create_case(
    *,
    title: Optional[str] = None,
    status: str = "open",
    severity: str = "medium",
    assignee: Optional[str] = None,
    triage_event_id: Optional[int] = None,
    source: str = "manual",
    summary: Optional[str] = None,
    ip: Optional[str] = None,
    user_entity: Optional[str] = None,
    resolution_notes: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> Dict[str, Any]:
    """Create a case manually or from a triage event id.

    When triage_event_id is set and title/summary/ip/user/severity are omitted,
    fields are filled from the triage event. Source defaults to triage in that case.
    """
    st = (status or "open").strip().lower()
    if st not in VALID_CASE_STATUSES:
        raise ValueError(f"Invalid case status: {status}")
    sev = (severity or "medium").strip().lower()
    if sev not in VALID_CASE_SEVERITIES:
        raise ValueError(f"Invalid case severity: {severity}")
    src = (source or "manual").strip().lower()
    if src not in VALID_CASE_SOURCES:
        raise ValueError(f"Invalid case source: {source}")

    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            if triage_event_id is not None:
                event = session.get(TriageEvent, int(triage_event_id))
                if event is None:
                    raise KeyError(f"triage_event id {triage_event_id} not found")
                if not title:
                    log_snip = (event.log or "").strip()
                    title = (log_snip[:120] + ("…" if len(log_snip) > 120 else "")) or f"Triage #{event.id}"
                if summary is None:
                    summary = event.log
                if ip is None:
                    ip = event.ip
                if user_entity is None:
                    user_entity = event.user
                if severity == "medium" and event.severity:
                    ev_sev = (event.severity or "").strip().lower()
                    if ev_sev in VALID_CASE_SEVERITIES:
                        sev = ev_sev
                if src == "manual":
                    src = "triage"

            title_final = (title or "").strip() or "Untitled case"
            now = _utc_now_iso()
            try:
                from sla import compute_due_at

                due_at = compute_due_at(sev, created_at=now)
            except Exception:
                due_at = None
            row = Case(
                created_at=now,
                updated_at=now,
                title=title_final,
                status=st,
                severity=sev,
                assignee=(assignee or "").strip() or None,
                triage_event_id=int(triage_event_id) if triage_event_id is not None else None,
                source=src,
                summary=summary,
                ip=ip,
                user_entity=user_entity,
                resolution_notes=resolution_notes,
                due_at=due_at,
            )
            session.add(row)
            session.flush()
            return _case_to_dict(row)


def list_cases(
    *,
    status: Optional[str] = None,
    assignee: Optional[str] = None,
    overdue: bool = False,
    mine: Optional[str] = None,
    limit: Optional[int] = None,
    db_path: Optional[Path | str] = None,
) -> List[Dict[str, Any]]:
    """List cases newest-first.

    Filters:
      status=None/'all' — every status
      assignee / mine — case-insensitive exact match on assignee email
      overdue=True — due_at in the past and status != closed (computed)
    """
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            stmt = select(Case).order_by(Case.id.desc())
            if status and status != "all":
                st = status.strip().lower()
                if st not in VALID_CASE_STATUSES:
                    raise ValueError(f"Invalid case status filter: {status}")
                stmt = stmt.where(Case.status == st)
            assignee_filter = (mine if mine is not None else assignee)
            if assignee_filter is not None and str(assignee_filter).strip():
                # SQLite/Postgres: compare lower(assignee)
                needle = str(assignee_filter).strip().lower()
                stmt = stmt.where(func.lower(Case.assignee) == needle)
            rows = session.scalars(stmt).all()
            out = [_case_to_dict(r) for r in rows]
    if overdue:
        out = [c for c in out if c.get("is_overdue")]
    if limit is not None and limit >= 0:
        out = out[: int(limit)]
    return out


def get_case(
    case_id: int,
    *,
    include_notes: bool = True,
    db_path: Optional[Path | str] = None,
) -> Optional[Dict[str, Any]]:
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            row = session.get(Case, int(case_id))
            if row is None:
                return None
            out = _case_to_dict(row)
            if include_notes:
                notes = session.scalars(
                    select(CaseNote)
                    .where(CaseNote.case_id == int(case_id))
                    .order_by(CaseNote.id.asc())
                ).all()
                out["notes"] = [_case_note_to_dict(n) for n in notes]
            return out


def add_note(
    case_id: int,
    body: str,
    *,
    author: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> Dict[str, Any]:
    text_body = (body or "").strip()
    if not text_body:
        raise ValueError("Note body is required")
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            case = session.get(Case, int(case_id))
            if case is None:
                raise KeyError(f"case id {case_id} not found")
            now = _utc_now_iso()
            note = CaseNote(
                case_id=int(case_id),
                created_at=now,
                author=(author or "").strip() or None,
                body=text_body,
            )
            case.updated_at = now
            session.add(note)
            session.flush()
            return _case_note_to_dict(note)


def update_case_status(
    case_id: int,
    status: str,
    *,
    resolution_notes: Optional[str] = None,
    assignee: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> Dict[str, Any]:
    st = (status or "").strip().lower()
    if st not in VALID_CASE_STATUSES:
        raise ValueError(f"Invalid case status: {status}")
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            case = session.get(Case, int(case_id))
            if case is None:
                raise KeyError(f"case id {case_id} not found")
            case.status = st
            case.updated_at = _utc_now_iso()
            if resolution_notes is not None:
                case.resolution_notes = resolution_notes
            if assignee is not None:
                case.assignee = (assignee or "").strip() or None
            session.flush()
            return _case_to_dict(case)


def update_case_external(
    case_id: int,
    *,
    external_ticket_id: Optional[str] = None,
    external_system: Optional[str] = None,
    external_url: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> Dict[str, Any]:
    """Store external ticket linkage fields on a case."""
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            case = session.get(Case, int(case_id))
            if case is None:
                raise KeyError(f"case id {case_id} not found")
            if external_ticket_id is not None:
                case.external_ticket_id = (external_ticket_id or "").strip() or None
            if external_system is not None:
                case.external_system = (external_system or "").strip() or None
            if external_url is not None:
                case.external_url = (external_url or "").strip() or None
            case.updated_at = _utc_now_iso()
            session.flush()
            return _case_to_dict(case)


def counts_by_status(db_path: Optional[Path | str] = None) -> Dict[str, int]:
    init_db(db_path)
    with _lock:
        with session_scope(db_path) as session:
            counts = {s: 0 for s in ("open", "investigating", "contained", "closed")}
            rows = session.execute(
                select(Case.status, func.count()).group_by(Case.status)
            ).all()
            for status, n in rows:
                key = (status or "").strip().lower()
                if key in counts:
                    counts[key] = int(n or 0)
            counts["total"] = sum(counts[s] for s in ("open", "investigating", "contained", "closed"))
            return counts


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
    "severity_source",
    "ml_assist",
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


# ---------------------------------------------------------------------------
# SQLite backup + storage status (ops health)
# ---------------------------------------------------------------------------

BACKUP_KEEP_DEFAULT = 10


def get_storage_status(db_path: Optional[Path | str] = None) -> Dict[str, Any]:
    """
    Operator-facing storage summary (no credentials).

    Returns backend (sqlite|postgres|…), safe location (path or host/db),
    triage_events count, and total blocks count.
    """
    url = get_database_url(db_path)
    try:
        parsed = make_url(url)
        backend_name = parsed.get_backend_name()
    except Exception:
        backend_name = "unknown"
        parsed = None

    if backend_name == "sqlite":
        backend = "sqlite"
        location = str(Path(db_path) if db_path is not None else get_db_path())
    elif backend_name == "postgresql":
        backend = "postgres"
        if parsed is not None:
            host = parsed.host or "localhost"
            port = parsed.port
            database = parsed.database or ""
            if port:
                location = f"{host}:{port}/{database}"
            else:
                location = f"{host}/{database}"
        else:
            location = "(postgres)"
    else:
        backend = backend_name or "unknown"
        location = "(configured)"

    triage_n = triage_event_count(db_path)
    blocks = load_blocks(db_path)
    blocks_n = len(blocks.get("ips") or []) + len(blocks.get("users") or [])

    return {
        "backend": backend,
        "location": location,
        "triage_events": triage_n,
        "blocks": blocks_n,
    }


def backup_sqlite(
    dest_dir: Path | str = "data/backups",
    *,
    keep: int = BACKUP_KEEP_DEFAULT,
    db_path: Optional[Path | str] = None,
) -> Dict[str, Any]:
    """
    Copy the SQLite database into dest_dir and rotate older backups.

    When the active backend is PostgreSQL, returns ok=False with a clear
    operator message (no-op). Uses the SQLite online backup API so WAL
    databases are consistent.
    """
    import sqlite3

    url = get_database_url(db_path)
    if is_postgres_url(url):
        return {
            "ok": False,
            "backend": "postgres",
            "path": None,
            "kept": 0,
            "message": (
                "SQLite file backup is not available while PostgreSQL is in use. "
                "Use pg_dump or your host's Postgres backup tools instead."
            ),
        }

    try:
        backend = make_url(url).get_backend_name()
    except Exception:
        backend = "sqlite"
    if backend != "sqlite":
        return {
            "ok": False,
            "backend": backend,
            "path": None,
            "kept": 0,
            "message": f"Backup is only supported for SQLite (current backend: {backend}).",
        }

    src = Path(db_path) if db_path is not None else get_db_path()
    if not src.exists():
        # Ensure schema exists so an empty DB can still be backed up
        init_db(db_path)
    if not src.exists():
        return {
            "ok": False,
            "backend": "sqlite",
            "path": None,
            "kept": 0,
            "message": f"SQLite database file not found: {src}",
        }

    dest_root = Path(dest_dir)
    dest_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = dest_root / f"soc_assistant_{stamp}.db"
    # Avoid rare collisions within the same microsecond
    if dest.exists():
        n = 1
        while True:
            candidate = dest_root / f"soc_assistant_{stamp}_{n}.db"
            if not candidate.exists():
                dest = candidate
                break
            n += 1

    with _lock:
        # Online backup API — safer than raw copy when WAL is enabled
        src_conn = sqlite3.connect(str(src))
        try:
            dst_conn = sqlite3.connect(str(dest))
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
        finally:
            src_conn.close()

    keep_n = max(1, int(keep))
    backups = sorted(
        dest_root.glob("soc_assistant_*.db"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    removed = 0
    for old in backups[keep_n:]:
        try:
            old.unlink(missing_ok=True)
            removed += 1
        except OSError as exc:
            logger.warning("Could not remove old backup %s: %s", old, exc)

    remaining = len(list(dest_root.glob("soc_assistant_*.db")))
    return {
        "ok": True,
        "backend": "sqlite",
        "path": str(dest),
        "kept": remaining,
        "removed": removed,
        "message": f"Backup saved to {dest} (keeping last {keep_n}).",
    }
