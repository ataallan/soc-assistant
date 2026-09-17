"""
Hold-out evaluation for the SOC triage severity model.

Uses the same feature pipeline as train_model.py, trains on a train split,
scores on a held-out test split, and writes docs/evaluation_report.md.

Does **not** overwrite production artifacts (those are full-data refits from
train_model.py). This script is the honest hold-out report.

Splits:
  - **Time-ordered** (preferred / primary when ``timestamp`` parses): sort by
    time, last 30% as test. Reports as the honest metric when available.
  - **Random stratified**: classic stratified hold-out (also reported for
    comparison).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

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


def _cm_markdown(cm, class_names) -> str:
    cm_rows = []
    header = "| actual \\ predicted | " + " | ".join(class_names) + " |"
    sep = "|" + "|".join(["---"] * (len(class_names) + 1)) + "|"
    cm_rows.append(header)
    cm_rows.append(sep)
    for i, name in enumerate(class_names):
        row = "| " + name + " | " + " | ".join(str(x) for x in cm[i]) + " |"
        cm_rows.append(row)
    return "\n".join(cm_rows)


def _run_split(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    y_train,
    y_test,
    label_encoder: LabelEncoder,
) -> Dict[str, Any]:
    X_train, vectorizer, scaler = build_features(train_df, fit=True)
    X_test, _, _ = build_features(test_df, vectorizer=vectorizer, scaler=scaler, fit=False)

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
    return {
        "best_name": best_name,
        "cv_f1": cv_f1,
        "acc": accuracy_score(y_test, y_pred),
        "f1_macro": f1_score(y_test, y_pred, average="macro", zero_division=0),
        "f1_weighted": f1_score(y_test, y_pred, average="weighted", zero_division=0),
        "report_txt": report_txt,
        "cm_md": _cm_markdown(cm, label_encoder.classes_),
        "train_size": len(train_df),
        "test_size": len(test_df),
    }


def _time_ordered_split(
    df: pd.DataFrame, y, test_size: float = TEST_SIZE
) -> Optional[Tuple[pd.DataFrame, pd.DataFrame, Any, Any]]:
    """Sort by timestamp; last ``test_size`` fraction is the test set."""
    if "timestamp" not in df.columns:
        return None
    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    if ts.isna().all():
        return None
    # Rows with unparseable timestamps go first (treated as oldest / unknown)
    order = ts.fillna(pd.Timestamp.min.tz_localize("UTC")).argsort(kind="mergesort")
    df_sorted = df.iloc[order].reset_index(drop=True)
    y_sorted = y[order.to_numpy()] if hasattr(y, "__getitem__") else y[order]

    n = len(df_sorted)
    n_test = max(1, int(round(n * test_size)))
    n_train = n - n_test
    if n_train < 1:
        return None

    train_df = df_sorted.iloc[:n_train]
    test_df = df_sorted.iloc[n_train:]
    y_train = y_sorted[:n_train]
    y_test = y_sorted[n_train:]
    return train_df, test_df, y_train, y_test


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

    # --- Random stratified split ---
    stratify = y if df["severity"].value_counts().min() >= 2 else None
    train_df_r, test_df_r, y_train_r, y_test_r = train_test_split(
        df,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=stratify,
    )
    random_metrics = _run_split(train_df_r, test_df_r, y_train_r, y_test_r, label_encoder)

    # --- Time-ordered holdout (preferred when timestamps work) ---
    time_split = _time_ordered_split(df, y, TEST_SIZE)
    time_metrics = None
    if time_split is not None:
        train_df_t, test_df_t, y_train_t, y_test_t = time_split
        time_metrics = _run_split(train_df_t, test_df_t, y_train_t, y_test_t, label_encoder)

    primary = time_metrics if time_metrics is not None else random_metrics
    primary_label = (
        "time-ordered hold-out (last 30% by timestamp)"
        if time_metrics is not None
        else "random stratified hold-out"
    )

    class_counts = df["severity"].value_counts().to_string()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    time_section = ""
    if time_metrics is not None:
        time_section = f"""
## Primary metrics — time-ordered hold-out (honest)

Rows sorted by ``timestamp``; **last {int(TEST_SIZE * 100)}%** held out as test.
Selected estimator (CV on train): **{time_metrics["best_name"]}** (train CV macro F1={time_metrics["cv_f1"]:.3f})

| Metric | Value |
| --- | --- |
| Accuracy | {time_metrics["acc"]:.3f} |
| Macro F1 | {time_metrics["f1_macro"]:.3f} |
| Weighted F1 | {time_metrics["f1_weighted"]:.3f} |
| Train size | {time_metrics["train_size"]} |
| Test size | {time_metrics["test_size"]} |

### Classification report (time-ordered)

```
{time_metrics["report_txt"]}
```

### Confusion matrix (time-ordered)

{time_metrics["cm_md"]}
"""
    else:
        time_section = """
## Primary metrics — time-ordered hold-out

**Unavailable** — ``timestamp`` column missing or unparseable. Falling back to random stratified as primary.
"""

    random_section = f"""
## Comparison — random stratified hold-out

Hold-out: **{int(TEST_SIZE * 100)}%** test / **{int((1 - TEST_SIZE) * 100)}%** train (`random_state={RANDOM_STATE}`, stratified when possible).
Selected estimator (CV on train): **{random_metrics["best_name"]}** (train CV macro F1={random_metrics["cv_f1"]:.3f})

| Metric | Value |
| --- | --- |
| Accuracy | {random_metrics["acc"]:.3f} |
| Macro F1 | {random_metrics["f1_macro"]:.3f} |
| Weighted F1 | {random_metrics["f1_weighted"]:.3f} |
| Train size | {random_metrics["train_size"]} |
| Test size | {random_metrics["test_size"]} |

### Classification report (random stratified)

```
{random_metrics["report_txt"]}
```

### Confusion matrix (random stratified)

{random_metrics["cm_md"]}
"""

    md = f"""# Model evaluation report

Generated: **{generated}**

## Dataset

- Source: `{DATA_PATH.as_posix()}`
- Rows: **{len(df)}**
- Label column: `severity`
- **Primary split reported:** {primary_label}

### Class distribution (full dataset)

```
{class_counts}
```
{time_section}
{random_section}
## How to reproduce

```bash
python evaluate_model.py
```

## Notes / limitations

- This is a **capstone-scale** dataset ({len(df)} labeled rows). Metrics will move as more labeled SOC data is added.
- **Time-ordered metrics are preferred** when timestamps parse — they better reflect “train on past, score on future” and reduce leakage from reused IPs/usernames. Random stratified remains for comparison.
- **Perfect (1.0) scores are not production proof** — with a small test split and strong lexical cues in `event_type`/`description`, the model can still look strong. See [MODEL_ASSESSMENT.md](MODEL_ASSESSMENT.md).
- Features: TF-IDF (`ngram_range=(1,2)`, `max_features=5000`) over `event_type + description + username`, plus scaled **hour-of-day** only (raw Unix timestamp and `source_ip_num` dropped to reduce memorization).
- Model selection: LogisticRegression / RandomForest / CalibratedClassifierCV via stratified CV macro-F1; this report scores the winner on each hold-out.
- Production artifacts (`soc_model.pkl`, etc.) are written by **`train_model.py`** after a **full-data refit**. This script does **not** overwrite them — it is the honest hold-out.
- Inference is a **rules + ML hybrid** (`triage_engine`): rules keep `critical`; auto-containment requires rule+ML agreement (or rules-critical) with `ML_CONFIDENCE_THRESHOLD` (default 0.70).
- Wazuh live alerts are triaged with the same hybrid; this report measures the **labeled CSV severity task**, not live Wazuh ground truth.
- **Not production-ready** for unattended SOC triage or auto-containment; suitable as a capstone demo of the pipeline.
"""

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(md)
    print("=== Primary:", primary_label, "===")
    print(primary["report_txt"])
    print(
        f"\nAccuracy={primary['acc']:.3f}  macro_F1={primary['f1_macro']:.3f}  "
        f"weighted_F1={primary['f1_weighted']:.3f}"
    )
    print(f"Selected={primary['best_name']}  Wrote {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
