# Live demo script — AI SOC Assistant (~6–8 minutes)

Use this for capstone defense, hiring screens, or a short portfolio video.

## Before you start (2 minutes, off-camera OK)

```bash
cd soc_assistant
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
copy .env.example .env          # set SECRET_KEY; mail optional for OTP demo
python evaluate_model.py        # refreshes metrics report
pytest -q                       # expect green
python train_model.py           # ensure .pkl artifacts exist
python dashboard.py             # http://127.0.0.1:5000
```

Optional second terminal for CLI:

```bash
python soc_triage_cli.py
```

**Talking point:** Secrets live in `.env`. Block/unblock is **simulated containment** (local JSON), not a live firewall.

---

## Minute 0–1 — Problem & architecture

Say:

> Analysts drown in alerts. This Capstone assistant triages CSV or Wazuh events with rules + ML, writes a report, and supports simulated containment from a Flask SOC dashboard.

Show: `docs/ARCHITECTURE.md` (or the diagram in the README).

---

## Demo A — Evaluation proof (45–60 sec)

```bash
python evaluate_model.py
```

Show `docs/evaluation_report.md` (accuracy / F1 / confusion matrix).

Say:

> Metrics are reproducible on a labeled hold-out split. Scores look strong on this small clean demo set — that’s a baseline, not production proof. Next step would be messier real SOC labels.

Also flash: `pytest -q` → tests for rules, NLP extractors, Wazuh parsing.

---

## Demo B — Three triage stories (3 minutes)

Use the dashboard **CSV logs / Start CSV Watcher / Report**, or CLI option **Watch CSV Logs**.

### 1) High — unauthorized access
- Example from sample data: `alice.smith` / `10.0.0.23` / unauthorized_access  
- Expect: elevated severity, escalate / investigate path, possible **simulated** block entry

### 2) Medium — failed logins
- Example: `john.doe` / `192.168.1.50` / multiple failed logins  
- Expect: medium severity, monitor/investigate — not automatic “critical”

### 3) High / critical-class content — malware or privilege escalation
- Pick a `malware_alert` or `privilege_escalation` row from `data/sample_logs.csv`  
- Expect: rules fire on phrases; report row appears with rule + ML fields

**Show:** Report page + Analytics counts. Mention dual signal: **rules + ML**.

---

## Demo C — Simulated containment (45 sec)

Open **Blocked Entities** and point at the mode banner (`CONTAINMENT_MODE` in `.env`).

Optionally set `CONTAINMENT_MODE=dry_run`, block an IP, and show `data/containment_audit.jsonl` with no list change — then switch back to `simulated`.

Point at the yellow banner:

> This list is intentional Capstone scope — we record containment decisions locally so we can demo the workflow without touching production controls.

Block an IP from the UI, refresh, unblock it.

---

## Demo D — Wazuh (optional, 1 minute)

If Wazuh is reachable and `.env` has `WAZUH_API` / `WAZUH_USER` / `WAZUH_PASS`:

1. Start **Wazuh watcher**
2. Open **Wazuh Alerts** table (severity badges, agent, rule)
3. Note JWT auth + endpoint cache from `wazuh_integration.py`

If Wazuh is offline: say the integration degrades cleanly when env is empty / API down.

---

## Close (30 sec)

Leave them with three bullets:

1. End-to-end SOC triage loop (ingest → decide → report → simulated contain)  
2. Professional packaging: architecture, evaluation report, tests, secret hygiene  
3. Honest limits: demo dataset size, simulated containment, local Flask debug mode  

Point to repo: https://github.com/ataallan/soc-assistant

---

## Recording tips (2-minute portfolio clip)

1. Architecture diagram (10s)  
2. `evaluate_model.py` + report snippet (20s)  
3. Dashboard report + one high alert (40s)  
4. Blocks page with simulated banner (20s)  
5. Wazuh table *or* pytest green (20s)  
6. End card with GitHub URL (10s)

Save captures under `docs/screenshots/` using the names in `docs/screenshots/README.md`.
