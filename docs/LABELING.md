# Alert labeling workflow

Use this process to grow the training set with analyst-reviewed severity labels.

## Live Wazuh labeling (dashboard)

1. Sign in to the SOC dashboard.
2. Open **Labeling** in the navbar (`/labels`).
3. Click **Pull from Wazuh** to enqueue recent alert details (deduped by summary + full log).
4. For each pending row, choose **low / medium / high / critical** (or **Skip**).
5. Saves update:
   - `label_queue` (status → labeled/skipped)
   - `alerts_labeled` table
   - `data/labeled_alerts.csv` (training columns: `timestamp,source_ip,username,event_type,severity,description`)
6. Click **Retrain model** (`POST /labels/retrain`) to train on `sample_logs.csv` + `labeled_alerts.csv` and refresh model artifacts. A toast shows CV macro F1 and sample count.

ML stays **assist-only** by default (`ML_ASSIST_ONLY=true`): rules remain the operator-facing severity; ML is shown as assist with confidence (or “Low confidence — not used”).

## Manual CSV labeling (offline)

### 1. Export alerts to label

- Copy `data/labeling_template.csv` (or export recent rows from triage / Wazuh into the same column shape).
- Required columns for training: `timestamp`, `source_ip`, `username`, `event_type`, `severity`, `description`.
- Optional: `analyst_notes`, `label_source` (e.g. `human`, `wazuh`, `template`).

### 2. Fill severity

For each row, set `severity` to one of:

`low` · `medium` · `high` · `critical`

Tips:

- Prefer the **final** analyst judgment over the model’s first guess.
- Leave a short note in `analyst_notes` when the label is non-obvious.
- Do not invent IPs or users you did not observe — keep fields empty if unknown.

### 3. Merge into training data

Either:

- Append labeled rows into `data/sample_logs.csv` (same core columns), **or**
- Save as `data/labeled_alerts.csv` and use dashboard **Retrain** / `train_ml_model(..., combine_labeled=True)`.

### 4. Retrain and evaluate

```bash
python train_model.py
# or from the dashboard: Train model / Labeling → Retrain

python evaluate_model.py
```

Review `docs/evaluation_report.md` and `docs/MODEL_ASSESSMENT.md` before treating scores as production-ready.

### 5. Watch again

Restart the CSV or Wazuh watcher so new events use the updated model artifacts (`soc_model.pkl`, `vectorizer.pkl`, `scaler.pkl`, `label_encoder.pkl`).
