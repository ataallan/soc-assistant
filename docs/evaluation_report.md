# Model evaluation report

Generated: **2026-09-17 19:08 UTC**

## Dataset

- Source: `data/sample_logs.csv`
- Rows: **111**
- Label column: `severity`
- **Primary split reported:** time-ordered hold-out (last 30% by timestamp)

### Class distribution (full dataset)

```
severity
high      55
medium    34
low       22
```

## Primary metrics — time-ordered hold-out (honest)

Rows sorted by ``timestamp``; **last 30%** held out as test.
Selected estimator (CV on train): **logreg** (train CV macro F1=1.000)

| Metric | Value |
| --- | --- |
| Accuracy | 1.000 |
| Macro F1 | 1.000 |
| Weighted F1 | 1.000 |
| Train size | 78 |
| Test size | 33 |

### Classification report (time-ordered)

```
              precision    recall  f1-score   support

        high       1.00      1.00      1.00        18
         low       1.00      1.00      1.00         8
      medium       1.00      1.00      1.00         7

    accuracy                           1.00        33
   macro avg       1.00      1.00      1.00        33
weighted avg       1.00      1.00      1.00        33

```

### Confusion matrix (time-ordered)

| actual \ predicted | high | low | medium |
|---|---|---|---|
| high | 18 | 0 | 0 |
| low | 0 | 8 | 0 |
| medium | 0 | 0 | 7 |


## Comparison — random stratified hold-out

Hold-out: **30%** test / **70%** train (`random_state=42`, stratified when possible).
Selected estimator (CV on train): **logreg** (train CV macro F1=1.000)

| Metric | Value |
| --- | --- |
| Accuracy | 1.000 |
| Macro F1 | 1.000 |
| Weighted F1 | 1.000 |
| Train size | 77 |
| Test size | 34 |

### Classification report (random stratified)

```
              precision    recall  f1-score   support

        high       1.00      1.00      1.00        17
         low       1.00      1.00      1.00         7
      medium       1.00      1.00      1.00        10

    accuracy                           1.00        34
   macro avg       1.00      1.00      1.00        34
weighted avg       1.00      1.00      1.00        34

```

### Confusion matrix (random stratified)

| actual \ predicted | high | low | medium |
|---|---|---|---|
| high | 17 | 0 | 0 |
| low | 0 | 7 | 0 |
| medium | 0 | 0 | 10 |

## How to reproduce

```bash
python evaluate_model.py
```

## Notes / limitations

- This is a **capstone-scale** dataset (111 labeled rows). Metrics will move as more labeled SOC data is added.
- **Time-ordered metrics are preferred** when timestamps parse — they better reflect “train on past, score on future” and reduce leakage from reused IPs/usernames. Random stratified remains for comparison.
- **Perfect (1.0) scores are not production proof** — with a small test split and strong lexical cues in `event_type`/`description`, the model can still look strong. See [MODEL_ASSESSMENT.md](MODEL_ASSESSMENT.md).
- Features: TF-IDF (`ngram_range=(1,2)`, `max_features=5000`) over `event_type + description + username`, plus scaled **hour-of-day** only (raw Unix timestamp and `source_ip_num` dropped to reduce memorization).
- Model selection: LogisticRegression / RandomForest / CalibratedClassifierCV via stratified CV macro-F1; this report scores the winner on each hold-out.
- Production artifacts (`soc_model.pkl`, etc.) are written by **`train_model.py`** after a **full-data refit**. This script does **not** overwrite them — it is the honest hold-out.
- Inference is a **rules + ML hybrid** (`triage_engine`): rules keep `critical`; auto-containment requires rule+ML agreement (or rules-critical) with `ML_CONFIDENCE_THRESHOLD` (default 0.70).
- Wazuh live alerts are triaged with the same hybrid; this report measures the **labeled CSV severity task**, not live Wazuh ground truth.
- **Not production-ready** for unattended SOC triage or auto-containment; suitable as a capstone demo of the pipeline.
