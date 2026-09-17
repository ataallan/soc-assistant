# Model assessment — AI SOC Assistant (capstone)

**Verdict for Allan:** The ML severity model is **good enough for a capstone demo**, not for real SOC triage in production. Perfect hold-out scores on ~111 rows are a red flag (easy separability / memorization), not proof of operational readiness.

---

## What the model is

| Piece | Detail |
| --- | --- |
| Task | Multi-class **severity** prediction: `high` / `medium` / `low` |
| Algorithm | `sklearn.linear_model.LogisticRegression` (`max_iter=500`, `class_weight='balanced'`) |
| Text features | TF-IDF over `event_type + description + username` |
| Numeric features | Unix timestamp + IPv4-as-int, `StandardScaler` |
| Artifacts | `soc_model.pkl`, `vectorizer.pkl`, `scaler.pkl`, `label_encoder.pkl` |
| Training data | `data/sample_logs.csv` (**111** labeled rows) |
| Training entrypoints | `train_model.py` (fit on full split), `evaluate_model.py` (honest hold-out + rewrites report/artifacts) |

Class balance (full CSV):

```
high      55
medium    34
low       22
```

There is **no `critical` class** in the labeled CSV; critical comes from **rule-based** phrase/numeric logic in `triage_engine.classify_severity`.

---

## Metrics on hold-out

From `python evaluate_model.py` (30% stratified hold-out, `random_state=42`, TF-IDF/scaler fit on **train only**):

| Metric | Value |
| --- | --- |
| Accuracy | **1.000** |
| Macro F1 | **1.000** |
| Weighted F1 | **1.000** |
| Train / test size | 77 / 34 |

See [evaluation_report.md](evaluation_report.md) for the full classification report and confusion matrix (all diagonal).

### How to read a perfect score

On a tiny, synthetic-looking sample set, **1.0 accuracy is not evidence the model generalizes**. Likely contributors:

1. **Tiny N** — 34 test rows; one lucky split can look flawless.
2. **Strong lexical cues** — `event_type` / `description` strings (e.g. `brute_force`, “Multiple failed login…”) are almost labels in disguise; TF-IDF can separate classes with little real “understanding.”
3. **Possible leakage-like effects** — repeated phrasings / usernames / IPs across rows; numeric IP/timestamp features can memorize demo patterns rather than attack semantics.
4. **Imbalance** — `high` dominates; without more diverse `low`/`medium` examples, metrics overstate readiness for noisy SIEM traffic.

Treat the report as a **reproducible demo metric**, not a SOC SLA.

---

## How the model is used at inference vs rules

### `triage_engine.py`

- Loads artifacts at import (`load_ml_model`).
- `analyze_log()` prefers **`ml_predict_severity(...)`**; if artifacts are missing, falls back to **`classify_severity(log)`** (keyword / numeric rules).
- **`recommendation`** (`escalate` / `investigate` / `ignore`) always comes from **`rule_based_triage(log)`**, which itself uses rule severity — not the ML label.

So ML can drive the reported **severity** field while **action recommendation** stays rule-driven. That split is fine for a demo but must be documented for operators.

### `soc_triage_cli.py`

- `analyze_and_predict()` runs a **second, parallel ML path** (load pkl → TF-IDF + scaler → predict) and logs `ml_prediction`.
- It also calls `analyze_log()` (which may run ML again) and uses that result’s severity for block/email decisions.
- High/critical severity → simulated containment + email.

### Dashboard

- Starts watchers / shows reports that include `severity`, `ml_prediction`, and `rule_based` columns from the same pipeline; analytics count severities from CSV reports.

**Bottom line:** Live triage is a **rules + ML hybrid**. Rules provide explainable escalate/ignore behavior and critical phrases; ML adds a learned severity on CSV-shaped fields. Wazuh alerts are stringified / field-mapped into that same pipeline — there is **no labeled Wazuh ground truth** in this repo.

---

## Production-ready?

| Question | Answer |
| --- | --- |
| Capstone / portfolio demo? | **Yes** — clear pipeline, artifacts, eval script, hybrid design. |
| Real SOC auto-triage / auto-block? | **No.** |
| Why not? | ~100 rows; perfect scores unreliable; no external validation; no calibration; no concept drift monitoring; IP-as-int and timestamps are weak security features; blocking on model output would be unsafe. |

**Honest one-liner for Allan’s defense:**  
*“The model demonstrates an end-to-end ML triage pipeline on a small labeled set. Perfect hold-out metrics reflect the demo dataset, not production generalization. For a real SOC I would keep rules as the safety net and retrain only after collecting thousands of analyst-labeled alerts.”*

---

## Concrete next steps to improve

1. **More labeled data** — target thousands of alerts with analyst severity (and `critical`); stratify by source (Wazuh rule id, MITRE tactic).
2. **Proper validation** — stratified k-fold CV; a time-based split (train past → test future) to reduce leakage from temporal/IP reuse.
3. **Feature hygiene** — drop or bucket raw IP/timestamp; add rule_id, agent role, geo/ASN, failure counts; avoid putting the label text into features.
4. **Calibration & thresholds** — `CalibratedClassifierCV` or temperature scaling; tune escalate threshold for precision on `high`/`critical`.
5. **Rule + ML ensemble** — e.g. rules veto for known critical TTPs; ML only ranks medium/unknown; require agreement before auto-containment.
6. **Separate recommendation from severity** — train or map both explicitly so report columns stay consistent.
7. **Ops** — drift checks, human-in-the-loop, never auto-block solely on ML until precision is measured on live Wazuh labels.

---

## Reproduce

```bash
source .venv/bin/activate   # or .venv\Scripts\activate
python evaluate_model.py
pytest -q
```

Related: [evaluation_report.md](evaluation_report.md), [ARCHITECTURE.md](ARCHITECTURE.md), [DEMO.md](DEMO.md).
