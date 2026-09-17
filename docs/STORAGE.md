# Storage — SQLite by default, PostgreSQL optional

## Why this layout

Runtime state for triage and containment needs:

- Durable, queryable storage (filters, counts, audit)
- Safe concurrent reads from the Flask dashboard and CLI watchers
- A clear path to multi-user / non-capstone deployments on PostgreSQL

**Default:** SQLite (`data/soc_assistant.db` via `SOC_DB_PATH`) — works offline with no extra services.

**Optional:** PostgreSQL when `SOC_DATABASE_URL` or `DATABASE_URL` is set.

| Table | Replaces |
| --- | --- |
| `triage_events` | `data/triage_report.csv` (primary) |
| `containment_blocks` | `data/blocked_entities.json` |
| `containment_audit` | `data/containment_audit.jsonl` |

CSV remains for **import** (one-time migration) and **export** (demos / ML labeling). Optional CSV/JSONL mirrors may still be written for compatibility; do not treat them as authoritative.

Implementation: SQLAlchemy 2.x in `db.py` with the same helper API used by the dashboard, containment, and CLI.

## Configuration (SQLite — default)

```bash
# .env
SOC_DB_PATH=data/soc_assistant.db
# Leave SOC_DATABASE_URL / DATABASE_URL unset
```

- Relative paths are resolved from the process working directory (project root).
- Absolute paths are fine for shared or CI environments.
- `*.db` files are gitignored; schema is created on startup (`db.init_db` / `ensure_db_ready`).
- SQLite uses WAL mode and `check_same_thread=False` for concurrent dashboard/CLI access.

## Configuration (PostgreSQL — optional)

Set either URL (prefer `SOC_DATABASE_URL`):

```bash
# .env
SOC_DATABASE_URL=postgresql+psycopg://soc:soc@localhost:5432/soc_assistant
# or
# DATABASE_URL=postgresql+psycopg://soc:soc@localhost:5432/soc_assistant
```

`postgres://` and bare `postgresql://` URLs are normalized to `postgresql+psycopg://` automatically.

### Local Postgres with Docker (one-liner)

```bash
docker run --name soc-pg -e POSTGRES_USER=soc -e POSTGRES_PASSWORD=soc \
  -e POSTGRES_DB=soc_assistant -p 5432:5432 -d postgres:16
```

Then in `.env`:

```bash
SOC_DATABASE_URL=postgresql+psycopg://soc:soc@localhost:5432/soc_assistant
```

Install deps (`pip install -r requirements.txt` includes `sqlalchemy` and `psycopg`), start the app as usual. Tables are created automatically on startup — **you do not need Postgres to keep using the app**; omit the URL to stay on SQLite.

### Migration note (SQLite → Postgres)

1. Export triage if you want a CSV backup:  
   `python -c "from db import export_triage_to_csv; print(export_triage_to_csv('data/triage_export.csv'))"`
2. Point `SOC_DATABASE_URL` at the new database and restart (schema via `create_all`).
3. There is no automatic row copy from an existing SQLite file into Postgres. For a one-off move, export/import CSV or use a DB dump/load tool. Legacy CSV/JSON import still runs when Postgres tables are **empty** and legacy files exist under `data/`.

## Startup migration (legacy files)

On first run (empty tables), `ensure_db_ready()` imports legacy files if present:

1. `data/triage_report.csv` → `triage_events`
2. `data/blocked_entities.json` → `containment_blocks`
3. `data/containment_audit.jsonl` → `containment_audit`

Migrated counts are logged to the console. Old files are left in place as backup. Works for both SQLite and Postgres backends.


## SQLite backups

While you stay on SQLite, create file backups of `data/soc_assistant.db`:

```bash
# Script
python backup_db.py
# or
python -c "from db import backup_sqlite; print(backup_sqlite())"

# CLI menu: option 7 — Backup SQLite Database
```

- Default destination: `data/backups/soc_assistant_YYYYMMDDTHHMMSSZ.db`
- Rotation keeps the **last 10** backups
- Dashboard: **System** → **Back up database** (`POST /backup`, login required)
- If PostgreSQL is configured, backup returns a clear message and does nothing (use `pg_dump` / host tools)

## Export

- **Dashboard:** `GET /report/export` (optional `?view=severe|escalated|total`)
- **CLI:** menu option *Export Report CSV*, or:

```bash
python -c "from db import export_triage_to_csv; print(export_triage_to_csv('data/triage_export.csv'))"
```

## Module API (`db.py`)

- `get_engine`, `get_database_url` / `resolve_database_url`, `init_db`, `ensure_db_ready`
- `insert_triage_event`, `list_triage_events(view=..., limit=...)`, `count_alerts`, `triage_event_count`
- `load_blocks`, `save_block`, `remove_block`, `append_audit`, `list_audit`
- `get_storage_status`, `backup_sqlite(dest_dir=..., keep=10)`
- `migrate_from_legacy_files`, `export_triage_to_csv`

Backend selection: explicit `db_path=` (tests) always uses SQLite for that file; otherwise `SOC_DATABASE_URL` / `DATABASE_URL` win; else SQLite via `SOC_DB_PATH`.
