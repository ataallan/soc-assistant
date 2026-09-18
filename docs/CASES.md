# SOC cases (ticket workflow)

Lightweight case console for analysts: open a ticket from a triage event (or manually), add notes, assign an owner, move status, close, meet SLA due times, and optionally sync an external ticket.

## Statuses

| Status | Meaning |
|--------|---------|
| `open` | Newly created; not yet actively worked |
| `investigating` | Analyst is working the case |
| `contained` | Immediate risk addressed; wrap-up pending |
| `closed` | Investigation complete |

## SLA

On create, `due_at` is set from severity → response hours (env-overridable):

| Severity | Default hours | Env override |
|----------|---------------|--------------|
| critical | 4 | `SLA_HOURS_CRITICAL` |
| high | 8 | `SLA_HOURS_HIGH` |
| medium | 24 | `SLA_HOURS_MEDIUM` |
| low | 72 | `SLA_HOURS_LOW` |

`is_overdue` / `sla_breached` are **computed** (due_at in the past and status ≠ closed). The list and detail pages show an **OVERDUE** badge. Use the **Overdue** filter tab to list breached open work.

Helpers: `sla.py` (`hours_for_severity`, `compute_due_at`, `is_overdue`).

## Assignees

Assignee `<select>` options come from `SOC_ANALYST_EMAILS` + `SOC_ADMIN_EMAILS` (comma-separated, case-insensitive). The **My cases** filter shows cases where `assignee` matches the logged-in user email.

## External ticket sync

`case_sync.py` mirrors the containment adapter style. Modes (`CASE_SYNC_MODE`):

| Mode | Behavior |
|------|----------|
| `simulated` (default) | Local synthetic ticket id (`SIM-…`); no HTTP |
| `stub` | Optional POST to `CASE_SYNC_STUB_URL`; if URL empty → log_only stub |
| `jira` | Same HTTP path; stores `external_system=jira`; browse URL from `JIRA_BASE_URL` when set |

Stores on the case: `external_ticket_id`, `external_system`, `external_url`. Detail page has a **Sync ticket** button and an **Open linked ticket** link when `external_url` is set.

Secrets (`CASE_SYNC_STUB_TOKEN`, `JIRA_API_TOKEN`) are read from the environment only and **never** written to audit logs, UI, or responses (`auth` is reported as `bearer` / `none`).

## How to use

1. Log into the dashboard and open **Cases** in the navbar.
2. Create a case with **New case**, or click **Open case** on a Triage Report row (uses that triage event id).
3. On the case detail page: add notes, change status (open → investigating → contained → closed), set assignee from the roster, and optionally **Sync ticket**.
4. Filter the list with Open / Investigating / Contained / Closed / All, plus **My cases** and **Overdue**. Count tiles show Open, Investigating, Contained, and Closed.

### Try My cases

1. Set `SOC_ADMIN_EMAILS` / `SOC_ANALYST_EMAILS` in `.env` to include your login email.
2. Create or assign a case to yourself via the assignee dropdown.
3. Open **Cases → My cases**.

### Try sync (stub, no network)

```bash
CASE_SYNC_MODE=stub
# leave CASE_SYNC_STUB_URL empty → log_only stub, still stores ticket id
```

Restart the dashboard, open a case, click **Sync ticket**. Confirm `external_ticket_id` appears and audit has `case_ticket_sync` (no tokens).

## Data

Tables in the default SQLite DB (`data/soc_assistant.db`):

- `cases` — title, status, severity, assignee, optional `triage_event_id`, source (`triage` \| `manual` \| `wazuh`), summary, ip, user_entity, resolution_notes, `due_at`, `external_ticket_id`, `external_system`, `external_url`
- `case_notes` — chronological notes (`author`, `body`)

New columns soft-migrate on existing SQLite DBs via `init_db`.

Helpers in `db.py`: `create_case`, `list_cases` (status / mine / overdue), `get_case`, `add_note`, `update_case_status`, `update_case_external`, `counts_by_status`.

## Routes

- `GET /cases` — list + status / mine / overdue filters
- `GET /cases/<id>` — detail + notes + status actions + sync
- `POST /cases/create` — manual or from `triage_event_id`
- `POST /cases/<id>/note`
- `POST /cases/<id>/status`
- `POST /cases/<id>/sync` — external ticket sync

ML remains assist-only; cases do not change triage severity logic.
