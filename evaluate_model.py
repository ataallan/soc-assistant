"""
Hold-out evaluation for the SOC triage severity model.

Uses the same feature pipeline as train_model.py, trains on a train split,
scores on a held-out test split, and writes docs/evaluation_report.md.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from train_model import ip_to_int

DATA_PATH = Path("data/sample_logs.csv")
REPORT_PATH = Path("docs/evaluation_report.md")
RANDOM_STATE = 42
TEST_SIZE = 0.3


def build_features(df: pd.DataFrame, vectorizer=None, scaler=None, fit: bool = True):
    text = (
        df["event_type"].astype(str)
        + " "
        + df["description"].astype(str)
        + " "
        + df["username"].astype(str)
    )
    if fit or vectorizer is None:
        vectorizer = TfidfVectorizer()
        X_text = vectorizer.fit_transform(text)
    else:
        X_text = vectorizer.transform(text)

    ts = pd.to_datetime(df["timestamp"], errors="coerce")
    ts_num = ts.astype("int64", errors="ignore") // 10**9
    # pandas may yield float NaNs
    ts_num = pd.to_numeric(ts_num, errors="coerce").fillna(0)
    ip_num = df["source_ip"].apply(ip_to_int)
    numeric = pd.DataFrame({"timestamp_num": ts_num, "source_ip_num": ip_num})

    if fit or scaler is None:
        scaler = StandardScaler()
        X_num = scaler.fit_transform(numeric)
    else:
        X_num = scaler.transform(numeric)

    return hstack([X_text, X_num]), vectorizer, scaler


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
    train_df, test_df, y_train, y_test = train_test_split(
        df,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y if df["severity"].value_counts().min() >= 2 else None,
    )

    X_train, vectorizer, scaler = build_features(train_df, fit=True)
    X_test, _, _ = build_features(test_df, vectorizer=vectorizer, scaler=scaler, fit=False)

    model = LogisticRegression(max_iter=500, class_weight="balanced")
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

    # Optional: refresh on-disk artifacts so CLI/dashboard match this run
    joblib.dump(model, "soc_model.pkl")
    joblib.dump(vectorizer, "vectorizer.pkl")
    joblib.dump(scaler, "scaler.pkl")
    joblib.dump(label_encoder, "label_encoder.pkl")

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
- Features: TF-IDF over `event_type + description + username`, plus scaled timestamp and source IP integer.
- Model: logistic regression with `class_weight='balanced'`.
- Wazuh live alerts are triaged with the same model + rule engine; this report measures the **labeled CSV severity task**, not live Wazuh ground truth (which requires analyst labels).
"""

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(md)
    print(report_txt)
    print(f"\nAccuracy={acc:.3f}  macro_F1={f1_macro:.3f}  weighted_F1={f1_weighted:.3f}")
    print(f"Wrote {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
