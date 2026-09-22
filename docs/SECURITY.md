# Security notes

Lightweight hardening for the Flask SOC dashboard. This is a demo / lab console — treat production deploy as a separate hardening exercise.

## Accounts and approval

There is **no default password** and no seeded `operator` / `changeme` user. Accounts live in `data/users.csv` (override with `SOC_USERS_FILE`).

| Who registers | Result |
|---|---|
| First **Create account** | Role `admin`, approved immediately |
| Later **Create account** | Role `analyst`, `approved=false`, status `pending` |

Pending, rejected, and deactivated users can sign in far enough to see that message on `/pending`. They do not get an email login code, and console routes (home, health, cases, containment, and the rest) redirect back to `/pending`.

An admin approves people on **Accounts** (`/accounts`): **Approve**, **Reject**, or **Deactivate**. A stored `developer` role can use that page too. The last active administrator cannot be rejected or deactivated, and you cannot deactivate yourself.

After approval, sign-in sends a one-time code through the existing mail path (Resend when `RESEND_API_KEY` is set, otherwise `MAIL_USERNAME` / `MAIL_PASSWORD`). The code is never shown in the browser. The console session must include `email_2fa_ok` when `SOC_EMAIL_2FA` is on (the default). A session that skipped the code is cleared and sent back to login.

Set `SOC_EMAIL_2FA=false` only for local debugging. Pending users still cannot open the console.

### Wipe accounts and create a new first admin

1. Stop the dashboard.
2. Delete the account file (`data/users.csv`, or whatever `SOC_USERS_FILE` points to).
3. Start the dashboard and use **Create account** once. That person is the site admin.

This does not delete `data/soc_assistant.db` (cases, triage, containment). To drop those too, stop the app and delete the database file as well, then start again.

## Roles (RBAC)

Set extra admin emails in `.env`:

```bash
SOC_ADMIN_EMAILS=admin@example.com,other-admin@example.com
```

Matching is **case-insensitive** against the login username/email. A stored account role of `admin` is also an admin (this is how the first registered user is an admin without editing `.env`). Users not in the list and without a stored admin role are **analysts**. `SOC_ADMIN_EMAILS` does not bypass approval: that account must be approved before it can open the console.

| Capability | Analyst | Admin |
|---|---|---|
| Dashboards, reports, health | yes | yes |
| Cases (create / notes / status) | yes | yes |
| Labeling, CSV import, train / activate | no | no |
| Start / stop watchers | yes | yes |
| View containment block list | yes | yes |
| SQLite backup | no | yes |
| Integrated (stub/live) containment preview | yes | yes |
| Integrated (stub/live) containment execute (confirm required) | no | yes |
| Simulated / preview-mode containment execute | yes | yes |
| Accounts (approve / reject / deactivate) | no | yes |

The navbar shows a role chip (`admin` / `analyst` / `developer`). Admin-only buttons are hidden for analysts; the server still returns **403** (JSON) or a redirect + toast if called directly.

Labeling, CSV import, and train / activate are **developer / lab only** (stored role `developer`, `SOC_DEVELOPER_EMAILS`, or `SOC_DEV_TRAINING` on a lab host). Customer admins do not get those controls. See [LABELING.md](LABELING.md).

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
