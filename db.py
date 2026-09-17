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
    url = get_database_url(db_path)
    if make_url(url).get_backend_name() == "sqlite":
        return Path(db_path) if db_path is not None else get_db_path()
    return url


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
