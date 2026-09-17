# Alert labeling workflow

Use this process to grow the training set with analyst-reviewed severity labels.

## 1. Export alerts to label

- Copy `data/labeling_template.csv` (or export recent rows from `data/triage_report.csv` / Wazuh into the same column shape).
- Required columns for training: `timestamp`, `source_ip`, `username`, `event_type`, `severity`, `description`.
- Optional: `analyst_notes`, `label_source` (e.g. `human`, `wazuh`, `template`).

## 2. Fill severity

For each row, set `severity` to one of:

`low` · `medium` · `high` · `critical`

Tips:

- Prefer the **final** analyst judgment over the model’s first guess.
- Leave a short note in `analyst_notes` when the label is non-obvious.
- Do not invent IPs or users you did not observe — keep fields empty if unknown.

## 3. Merge into training data

Either:

- Append labeled rows into `data/sample_logs.csv` (same core columns), **or**
- Save a dedicated file (e.g. `data/labeled_logs.csv`) and point training at it.

Example merge (CSV with matching headers):

```bash
# After reviewing labeling_template.csv → data/labeled_batch.csv
python - <<'PY'
import pandas as pd
base = pd.read_csv("data/sample_logs.csv")
batch = pd.read_csv("data/labeled_batch.csv")
# Keep training columns only
cols = ["timestamp","source_ip","username","event_type","severity","description"]
merged = pd.concat([base[cols], batch[cols]], ignore_index=True)
merged.to_csv("data/sample_logs.csv", index=False)
print("rows:", len(merged))
PY
```

## 4. Retrain and evaluate

```bash
python train_model.py
# or from the dashboard: Train ML Model

python evaluate_model.py
```

Review `docs/evaluation_report.md` and `docs/MODEL_ASSESSMENT.md` before treating scores as production-ready.

## 5. Watch again

Restart the CSV or Wazuh watcher so new events use the updated model artifacts (`soc_model.pkl`, `vectorizer.pkl`, `scaler.pkl`, `label_encoder.pkl`).
