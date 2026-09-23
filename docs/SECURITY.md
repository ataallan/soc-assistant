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

### Password reset

**Forgot password?** on the login page opens `/forgot-password`. The form accepts the account email. The page does not say whether that email exists.

A reset link is issued only for an **approved and active** account. Pending, rejected, inactive, and unknown emails get the same on-page response and no usable token. The token is stored as a SHA-256 hash with an expiry (`SOC_RESET_TOKEN_MINUTES`, default 45). It is single-use.

Mail uses the same path as login codes. If Resend or SMTP accepts the message, the page shows a generic line and does not claim the account exists. If mail is not configured, the page says delivery is not configured and does not claim an email was sent. If the provider is configured but delivery fails, the page says the email was not sent. The reset URL is written to the server log whenever it is issued for an eligible account. Set `SOC_AUTH_SHOW_RESET_URL=1` to also show that URL on the page when mail is not configured.

`/reset-password?token=…` sets a new password (at least 8 characters, confirmation must match) and clears the token. Reset does not approve the account and does not skip the email login code. The next sign-in still follows those gates.

Forgot-password posts are limited per account (`SOC_RESET_MIN_INTERVAL_SECONDS`, default 60) and per IP (`SOC_RESET_IP_LIMIT`, default 8 per 15 minutes) so the form cannot be used to spam mail.

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

## Sign-in lifetime

Two clocks end a sign-in. The next request clears the auth cookie keys and opens `/login` with **Sign in again to continue**. The following sign-in still follows approval and the email code when those are on.

| Control | Default | Behavior |
|---|---|---|
| `SESSION_IDLE_MINUTES` | 15 | No authenticated request for longer than this ends the sign-in. Each authenticated request, including `/notifications` and other console polls, resets the clock. |
| `SESSION_HOURS` | 12 | Longest sign-in, measured from sign-in. `SESSION_HOURS=0` leaves only the idle limit. |

A cookie with no epoch, or with an epoch that does not match this process, is ended the same way. The epoch is `APP_SESSION_EPOCH` when that variable is set, otherwise the `VERSION` file next to `dashboard.py`.

Customer setup writes a new `VERSION` into each `AIPoweredSOCAssistantSetup.exe` (`scripts/stage_installer_payload.py`). After an upgrade, a hard refresh still sends the old cookie, and the dashboard asks for sign-in again. Leave `APP_SESSION_EPOCH` unset on those PCs so the setup program's `VERSION` stamp is the one that is checked. Set `APP_SESSION_EPOCH` when a lab or Capstone host should force sign-in without rebuilding the installer.

## CSRF

`Flask-WTF` `CSRFProtect` validates POST form bodies (`csrf_token` field) and JSON/fetch POSTs (`X-CSRFToken` header). SameSite=Lax remains a second line of defense for cookie-authenticated requests.

## Security headers

Responses include:

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`

## Secrets

Never commit `.env`, database files, or mail / Wazuh passwords. Rotate `SECRET_KEY` if it may have leaked.
