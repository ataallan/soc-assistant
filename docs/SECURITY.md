# Security notes

Lightweight hardening for the Flask SOC dashboard. This is a demo / lab console — treat production deploy as a separate hardening exercise.

## Roles (RBAC)

Set admin emails in `.env`:

```bash
SOC_ADMIN_EMAILS=admin@example.com,other-admin@example.com
```

Matching is **case-insensitive** against the login username/email. Users not in the list are **analysts**.

| Capability | Analyst | Admin |
|---|---|---|
| Dashboards, reports, health | yes | yes |
| Cases (create / notes / status) | yes | yes |
| Labeling (pull / label / skip) | yes | yes |
| Start / stop watchers | yes | yes |
| View containment block list | yes | yes |
| Train / retrain ML model | no | yes |
| SQLite backup | no | yes |
| Stub-mode containment execute (block/unblock) | no | yes |
| Simulated/dry-run containment execute | yes | yes |

The navbar shows a role chip (`admin` / `analyst`). Admin-only buttons are hidden for analysts; the server still returns **403** (JSON) or a redirect + toast if called directly.

## Session cookies

Configured in `dashboard.py`:

- `SESSION_COOKIE_HTTPONLY=True` (not readable from JavaScript)
- `SESSION_COOKIE_SAMESITE=Lax` (mitigates classic CSRF from other sites)
- `SESSION_COOKIE_SECURE` — set `SESSION_COOKIE_SECURE=true` in `.env` when the app is served over **HTTPS**

## CSRF

`Flask-WTF` `CSRFProtect` validates POST form bodies (`csrf_token` field) and JSON/fetch POSTs (`X-CSRFToken` header). SameSite=Lax remains a second line of defense for cookie-authenticated requests.

## Security headers

Responses include:

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`

## Secrets

Never commit `.env`, database files, or mail / Wazuh passwords. Rotate `SECRET_KEY` if it may have leaked.
