# Model evaluation report

Generated: **2026-09-17 18:47 UTC**

## Dataset

- Source: `data/sample_logs.csv`
- Rows: **111**
- Hold-out: **30%** test / **70%** train (`random_state=42`, stratified when possible)
- Label column: `severity`

### Class distribution (full dataset)

```
severity
high      55
medium    34
low       22
```

## Metrics (hold-out test set)

| Metric | Value |
| --- | --- |
| Accuracy | 1.000 |
| Macro F1 | 1.000 |
| Weighted F1 | 1.000 |
| Train size | 77 |
| Test size | 34 |

### Classification report

```
              precision    recall  f1-score   support

        high       1.00      1.00      1.00        17
         low       1.00      1.00      1.00         7
      medium       1.00      1.00      1.00        10

    accuracy                           1.00        34
   macro avg       1.00      1.00      1.00        34
weighted avg       1.00      1.00      1.00        34

```

### Confusion matrix

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
- **Perfect (1.0) scores are not production proof** — with ~34 test rows and strong lexical cues in `event_type`/`description`, the model can memorize the demo set. See [MODEL_ASSESSMENT.md](MODEL_ASSESSMENT.md) for the honest capstone-vs-SOC verdict.
- Features: TF-IDF over `event_type + description + username`, plus scaled timestamp and source IP integer.
- Model: logistic regression with `class_weight='balanced'`.
- Inference is a **rules + ML hybrid** (`triage_engine` / CLI): ML predicts severity when artifacts exist; escalate/investigate/ignore recommendations stay rule-based; critical phrases are rule-only (no `critical` label in the CSV).
- Wazuh live alerts are triaged with the same model + rule engine; this report measures the **labeled CSV severity task**, not live Wazuh ground truth (which requires analyst labels).
- **Not production-ready** for unattended SOC triage or auto-containment; suitable as a capstone demo of the pipeline.
