# AI SOC Assistant (Capstone)

Allan Munyira's capstone project: an **AI-assisted SOC triage** toolkit that combines rule-based analysis with a scikit-learn model, a Flask dashboard (login + email OTP), a CLI watcher for CSV logs, and optional Wazuh API integration.

## Features

- Train an ML severity model from sample security logs
- CLI menu to train, watch CSV/Wazuh feeds, view reports, and manage blocks
- Flask dashboard for training, watchers, reports, blocks, and analytics
- Email notifications for high/critical events (Gmail SMTP / App Password)
- Optional Wazuh 4.x API alert fetch

## Setup

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env   # Windows
# cp .env.example .env   # macOS / Linux
```

Edit `.env` and set `SECRET_KEY`, mail credentials, and (optionally) Wazuh values. **Never commit `.env`.**

## Train the model

```bash
python train_model.py
```

This reads `data/sample_logs.csv` and writes `soc_model.pkl`, `vectorizer.pkl`, `scaler.pkl`, and `label_encoder.pkl` in the project root.

## Run the CLI

```bash
python soc_triage_cli.py
```

Menu options: train, watch CSV, watch Wazuh, view report, unblock entities, exit.

## Run the dashboard

```bash
python dashboard.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). Register with an email address (used for OTP), then log in.

Flask templates live under `templates/` (login, register, 2FA, home, reports, etc.).

## Wazuh (optional)

Set in `.env`:

- `WAZUH_API` (default `https://localhost:55000`)
- `WAZUH_USER` (default `wazuh`)
- `WAZUH_PASS` (**required** for live auth; empty disables usable authentication)

Without a password, Wazuh calls will fail gracefully and return no alerts.

## Security notes

- Secrets are loaded from environment variables via `python-dotenv` (`.env`).
- **Rotate any previously exposed Gmail App Password** (and Wazuh API password if it was shared in older copies of this project).
- Do not commit real passwords, App Passwords, or API tokens.
- Treat this as a **local demo / academic** project, not production SOC tooling.

## Project layout

| Path | Role |
|------|------|
| `dashboard.py` | Flask web UI |
| `soc_triage_cli.py` | Interactive CLI + triage pipeline |
| `train_model.py` | ML training |
| `triage_engine.py` | Rule + ML analysis helpers |
| `wazuh_integration.py` | Wazuh API client |
| `nlp_utils.py` | IP/user extraction helpers |
| `data/sample_logs.csv` | Sample training / watch data |

## Known limitations

- **Import / name mismatches:** The dashboard imports symbols such as `train_ml_model`, `watch_csv`, `watch_wazuh`, and `blocked_entities` from `soc_triage_cli`. If you rename CLI exports without updating the dashboard (or vice versa), the UI falls back with `SOC import error` and related routes break. Full alignment may need a larger refactor.
- **`apply_triage.py` directory:** On some Capstone checkouts, `apply_triage.py` is a **directory** (misnamed package folder), not a runnable script. Prefer `soc_triage_cli.py` / `triage_engine.py` instead of treating it as an entrypoint.
- **Dashboard bind / debug:** `dashboard.py` runs with `debug=True` and `host="0.0.0.0"` for local demos. That exposes the app on all interfaces with the Flask debugger — use only on trusted networks, or change to `host="127.0.0.1"` and `debug=False` for safer local use.
- **Templates / static assets:** A complete UI needs the `templates/` (and any `static/`) folders from the original Desktop project; this public repo focuses on cleaned Python sources and sample data.
- **Email OTP:** Registration expects an email username; SMTP must be configured or login 2FA email will fail.

## License

Capstone / academic use. Contact the author for other licensing.
