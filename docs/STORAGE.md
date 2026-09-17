# Storage — SQLite as source of truth

## Why SQLite now

The product is no longer CSV/JSON-first. Runtime state for triage and containment needs:

- Durable, queryable storage (filters, counts, audit)
- Safe concurrent reads from the Flask dashboard and CLI watchers
- A clear path to PostgreSQL later without rewriting business logic

**SQLite** (`data/soc_assistant.db` by default) is the source of truth for:

| Table | Replaces |
| --- | --- |
| `triage_events` | `data/triage_report.csv` (primary) |
| `containment_blocks` | `data/blocked_entities.json` |
| `containment_audit` | `data/containment_audit.jsonl` |

CSV remains for **import** (one-time migration) and **export** (demos / ML labeling). Optional CSV/JSONL mirrors may still be written for compatibility; do not treat them as authoritative.

## Configuration

```bash
# .env
SOC_DB_PATH=data/soc_assistant.db
```

- Relative paths are resolved from the process working directory (project root).
- Absolute paths are fine for shared or CI environments.
- The `*.db` files are gitignored; schema is created on startup (`db.init_db` / `ensure_db_ready`).

## Startup migration

On first run (empty tables), `ensure_db_ready()` imports legacy files if present:

1. `data/triage_report.csv` → `triage_events`
2. `data/blocked_entities.json` → `containment_blocks`
3. `data/containment_audit.jsonl` → `containment_audit`

Migrated counts are logged to the console. Old files are left in place as backup.

## Export

- **Dashboard:** `GET /report/export` (optional `?view=severe|escalated|total`)
- **CLI:** menu option *Export Report CSV*, or:

```bash
python -c "from db import export_triage_to_csv; print(export_triage_to_csv('data/triage_export.csv'))"
```

## Module API (`db.py`)

- `insert_triage_event`, `list_triage_events(view=..., limit=...)`, `count_alerts`
- `load_blocks`, `save_block`, `remove_block`, `append_audit`
- `migrate_from_legacy_files`, `ensure_db_ready`, `export_triage_to_csv`

Thread safety: `check_same_thread=False`, process `RLock`, and `PRAGMA journal_mode=WAL`.

## Path to PostgreSQL (later)

The schema uses plain SQL with SQLAlchemy-friendly names (`triage_events`, `containment_blocks`, `containment_audit`). A future move:

1. Map the three tables to SQLAlchemy models (same columns; quote or rename `"user"` → `username` if desired).
2. Point `SOC_DB_PATH` / a new `DATABASE_URL` at Postgres.
3. Keep `db.py` helpers as a thin repository layer so the dashboard and CLI stay unchanged.

No ORM is required today; SQLite keeps demos offline and dependency-light.
