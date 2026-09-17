"""
Hold-out evaluation for the SOC triage severity model.

Uses the same feature pipeline as train_model.py, trains on a train split,
scores on a held-out test split, and writes docs/evaluation_report.md.

Does **not** overwrite production artifacts (those are full-data refits from
train_model.py). This script is the honest hold-out report.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from train_model import (
    RANDOM_STATE,
    build_features,
    select_best_estimator,
    _clone_fresh,
)

DATA_PATH = Path("data/sample_logs.csv")
REPORT_PATH = Path("docs/evaluation_report.md")
TEST_SIZE = 0.3


def main() -> int:
    if not DATA_PATH.exists():
        print(f"Missing {DATA_PATH}")
        return 1

    df = pd.read_csv(DATA_PATH)
    required = ["event_type", "description", "username", "severity", "timestamp", "source_ip"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        print(f"CSV missing columns: {missing}")
        return 1

    df["severity"] = df["severity"].fillna("unknown").astype(str)
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df["severity"])

    # Split rows first so TF-IDF is fit on train only (honest hold-out)
    stratify = y if df["severity"].value_counts().min() >= 2 else None
    train_df, test_df, y_train, y_test = train_test_split(
        df,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=stratify,
    )

    X_train, vectorizer, scaler = build_features(train_df, fit=True)
    X_test, _, _ = build_features(test_df, vectorizer=vectorizer, scaler=scaler, fit=False)

    # Same candidate pool as train_model; pick by CV on train only, then score test
    best_name, _, cv_f1 = select_best_estimator(X_train, y_train)
    model = _clone_fresh(best_name)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    labels = list(range(len(label_encoder.classes_)))
    report_txt = classification_report(
        y_test,
        y_pred,
        labels=labels,
        target_names=label_encoder.classes_,
        zero_division=0,
    )
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    cm_rows = []
    header = "| actual \\ predicted | " + " | ".join(label_encoder.classes_) + " |"
    sep = "|" + "|".join(["---"] * (len(label_encoder.classes_) + 1)) + "|"
    cm_rows.append(header)
    cm_rows.append(sep)
    for i, name in enumerate(label_encoder.classes_):
        row = "| " + name + " | " + " | ".join(str(x) for x in cm[i]) + " |"
        cm_rows.append(row)

    class_counts = df["severity"].value_counts().to_string()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    md = f"""# Model evaluation report

Generated: **{generated}**

## Dataset

- Source: `{DATA_PATH.as_posix()}`
- Rows: **{len(df)}**
- Hold-out: **{int(TEST_SIZE * 100)}%** test / **{int((1 - TEST_SIZE) * 100)}%** train (`random_state={RANDOM_STATE}`, stratified when possible)
- Label column: `severity`
- Selected estimator (CV on train): **{best_name}** (train CV macro F1={cv_f1:.3f})

### Class distribution (full dataset)

```
{class_counts}
```

## Metrics (hold-out test set)

| Metric | Value |
| --- | --- |
| Accuracy | {acc:.3f} |
| Macro F1 | {f1_macro:.3f} |
| Weighted F1 | {f1_weighted:.3f} |
| Train size | {len(train_df)} |
| Test size | {len(test_df)} |

### Classification report

```
{report_txt}
```

### Confusion matrix

{chr(10).join(cm_rows)}

## How to reproduce

```bash
python evaluate_model.py
```

## Notes / limitations

- This is a **capstone-scale** dataset ({len(df)} labeled rows). Metrics will move as more labeled SOC data is added.
- **Perfect (1.0) scores are not production proof** — with a small test split and strong lexical cues in `event_type`/`description`, the model can still look strong. See [MODEL_ASSESSMENT.md](MODEL_ASSESSMENT.md).
- Features: TF-IDF (`ngram_range=(1,2)`, `max_features=5000`) over `event_type + description + username`, plus scaled **hour-of-day** only (raw Unix timestamp and `source_ip_num` dropped to reduce memorization).
- Model selection: LogisticRegression / RandomForest / CalibratedClassifierCV via stratified CV macro-F1; this report scores the winner on the hold-out.
- Production artifacts (`soc_model.pkl`, etc.) are written by **`train_model.py`** after a **full-data refit**. This script does **not** overwrite them — it is the honest hold-out.
- Inference is a **rules + ML hybrid** (`triage_engine`): rules keep `critical`; low ML confidence falls back to rules.
- Wazuh live alerts are triaged with the same hybrid; this report measures the **labeled CSV severity task**, not live Wazuh ground truth.
- **Not production-ready** for unattended SOC triage or auto-containment; suitable as a capstone demo of the pipeline.
"""

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(md)
    print(report_txt)
    print(f"\nAccuracy={acc:.3f}  macro_F1={f1_macro:.3f}  weighted_F1={f1_weighted:.3f}")
    print(f"Selected={best_name}  Wrote {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
