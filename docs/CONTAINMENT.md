# Containment adapter

Honest containment for the capstone SOC console: local simulation by default, optional HTTP integration with an admin-confirmed live path.

## Modes (`CONTAINMENT_MODE`)

| Mode | UI label | Behavior |
| --- | --- | --- |
| `simulated` (default) | Simulation mode | One-click block/unblock updates SQLite `containment_blocks` only. No outbound HTTP. |
| `dry_run` | Preview mode | Audits the intended action; does **not** change the block list. |
| `stub` or `live` | Integrated response mode | Two-step UI: **Preview response** → **Confirm live response**. Admin-only execute. Optional POST to `CONTAINMENT_STUB_URL`, then SQLite. |

`live` is an alias of `stub`.

None of these are a production firewall unless you intentionally point the stub URL at a real control-plane API.

## Preview → confirm (integrated mode)

1. Analyst or admin opens **Containment**.
2. Admin clicks **Preview response** (or Unblock). `POST /blocks/preview` returns JSON:
   - `action`, `target`, `mode`, `would_call_url`, `body_summary` (no secrets), `allowed`, `requires_confirm`
   - Preview **never** calls the network.
3. Admin clicks **Confirm live response**. `POST /blocks/execute` with `confirm=1`:
   - Rejects analysts (403)
   - Rejects missing `confirm` (400)
   - Calls the stub URL (if set), writes audit with HTTP status / ok (never logs the Bearer token), updates SQLite on success

Simulation mode keeps the classic one-click forms (`POST /block/ip`, `/block/user`, `/unblock`).

## Environment

```bash
CONTAINMENT_MODE=simulated   # or dry_run | stub | live
CONTAINMENT_STUB_URL=        # optional HTTPS endpoint for stub/live
CONTAINMENT_STUB_TOKEN=      # optional; sent as Authorization: Bearer <token>
```

- Token is read from the environment only and is **never** written to audit logs, previews, or UI.
- `body_summary.auth` is `"bearer"` or `"none"` so operators can see whether auth is configured.

## Point the stub at a test endpoint

**webhook.site / webhook.tester**

1. Open a catcher URL (e.g. `https://webhook.site/<uuid>`).
2. Set in `.env`:
   ```bash
   CONTAINMENT_MODE=stub
   CONTAINMENT_STUB_URL=https://webhook.site/<uuid>
   # optional:
   CONTAINMENT_STUB_TOKEN=demo-token
   ```
3. Restart the dashboard, sign in as an admin listed in `SOC_ADMIN_EMAILS`.
4. On Containment: Preview → Confirm. Inspect the catcher for the JSON body.

**Local Flask echo**

```python
# echo_stub.py — run: python echo_stub.py
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.post("/contain")
def contain():
    auth = request.headers.get("Authorization", "")
    print("auth_present=", auth.startswith("Bearer "))
    print("json=", request.get_json(silent=True))
    return jsonify({"ok": True, "echo": request.get_json(silent=True)}), 200

if __name__ == "__main__":
    app.run(port=9099)
```

```bash
CONTAINMENT_MODE=live
CONTAINMENT_STUB_URL=http://127.0.0.1:9099/contain
CONTAINMENT_STUB_TOKEN=lab-secret
```

## RBAC

| Action | Analyst | Admin |
| --- | --- | --- |
| View block list | yes | yes |
| Simulated / preview-mode execute | yes | yes |
| Integrated preview (`/blocks/preview`) | yes | yes |
| Integrated execute (`/blocks/execute`) | no | yes |

See also [SECURITY.md](SECURITY.md) and [ARCHITECTURE.md](ARCHITECTURE.md).
