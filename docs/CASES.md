# SOC cases (ticket workflow)

Lightweight case console for analysts: open a ticket from a triage event (or manually), add notes, assign an owner, move status, and close.

## Statuses

| Status | Meaning |
|--------|---------|
| `open` | Newly created; not yet actively worked |
| `investigating` | Analyst is working the case |
| `contained` | Immediate risk addressed; wrap-up pending |
| `closed` | Investigation complete |

## How to use

1. Log into the dashboard and open **Cases** in the navbar.
2. Create a case with **New case**, or click **Open case** on a Triage Report row (uses that triage event id).
3. On the case detail page: add notes, change status (open → investigating → contained → closed), and set assignee / resolution notes.
4. Filter the list with the Open / Investigating / Contained / Closed / All tabs. Count tiles show Open, Investigating, Contained, and Closed.

## Data

Tables in the default SQLite DB (`data/soc_assistant.db`):

- `cases` — title, status, severity, assignee, optional `triage_event_id`, source (`triage` \| `manual` \| `wazuh`), summary, ip, user_entity, resolution_notes
- `case_notes` — chronological notes (`author`, `body`)

Helpers in `db.py`: `create_case`, `list_cases`, `get_case`, `add_note`, `update_case_status`, `counts_by_status`.

## Routes

- `GET /cases` — list + status filter
- `GET /cases/<id>` — detail + notes + status actions
- `POST /cases/create` — manual or from `triage_event_id`
- `POST /cases/<id>/note`
- `POST /cases/<id>/status`

ML remains assist-only; cases do not change triage severity logic.
