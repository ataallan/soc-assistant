"""Train SOC severity model (text-first, small-data honest pipeline).

Saved artifacts are fit on the **full** labeled CSV after model selection via
stratified CV. Use ``evaluate_model.py`` for an honest hold-out report.
"""

from __future__ import annotations

import os
import socket
import struct

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

MODEL_FILE = "soc_model.pkl"
VECTORIZER_FILE = "vectorizer.pkl"
SCALER_FILE = "scaler.pkl"
LABEL_ENCODER_FILE = "label_encoder.pkl"

RANDOM_STATE = 42
ML_CONFIDENCE_THRESHOLD = 0.55  # used by triage_engine fallback docs


def ip_to_int(ip):
    """Convert IPv4 string to integer (legacy helper; not used in new features)."""
    try:
        return struct.unpack("!I", socket.inet_aton(str(ip)))[0]
    except Exception:
        return 0


def hour_of_day_series(timestamps) -> np.ndarray:
    """Weak numeric feature: hour-of-day (0–23). Avoids raw Unix timestamp memorization."""
    ts = pd.to_datetime(timestamps, errors="coerce", utc=True)
    hours = ts.dt.hour.fillna(0).astype(float).to_numpy().reshape(-1, 1)
    return hours


def make_text_series(df: pd.DataFrame) -> pd.Series:
    return (
        df["event_type"].astype(str)
        + " "
        + df["description"].astype(str)
        + " "
        + df["username"].astype(str)
    )


def build_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=1,
        max_features=5000,
    )


def build_features(df: pd.DataFrame, vectorizer=None, scaler=None, fit: bool = True):
    """TF-IDF text + scaled hour-of-day (no source_ip_num / raw timestamp)."""
    text = make_text_series(df)
    if fit or vectorizer is None:
        vectorizer = build_vectorizer()
        X_text = vectorizer.fit_transform(text)
    else:
        X_text = vectorizer.transform(text)

    hours = hour_of_day_series(df["timestamp"])
    if fit or scaler is None:
        scaler = StandardScaler()
        X_num = scaler.fit_transform(hours)
    else:
        X_num = scaler.transform(hours)

    return hstack([X_text, X_num]), vectorizer, scaler


def _candidate_models():
    """Sklearn-only candidates; pick by stratified CV macro-F1."""
    logreg = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE)
    return [
        ("logreg", logreg),
        (
            "random_forest",
            RandomForestClassifier(
                n_estimators=100,
                class_weight="balanced",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
        ),
        (
            "calibrated_logreg",
            CalibratedClassifierCV(logreg, cv=3),
        ),
    ]


def select_best_estimator(X, y):
    """Return (name, unfitted_estimator, mean_cv_f1) via stratified CV."""
    class_counts = np.bincount(y)
    min_class = int(class_counts.min()) if len(class_counts) else 0
    n_splits = min(5, min_class) if min_class >= 2 else 2
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)

    best_name, best_score, best_est = None, -1.0, None
    print(f"\n🔍 Stratified CV ({n_splits}-fold) model selection (macro F1):\n")
    for name, est in _candidate_models():
        try:
            scores = cross_val_score(est, X, y, cv=skf, scoring="f1_macro")
            mean_f1 = float(scores.mean())
            print(f"  {name:20s}  mean_macro_F1={mean_f1:.3f}  (±{scores.std():.3f})")
            if mean_f1 > best_score:
                best_name, best_score, best_est = name, mean_f1, est
        except Exception as e:
            print(f"  {name:20s}  skipped ({e})")

    if best_est is None:
        best_name = "logreg"
        best_est = LogisticRegression(
            max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE
        )
        best_score = 0.0
    print(f"\n✅ Selected: {best_name} (CV macro F1={best_score:.3f})")
    return best_name, best_est, best_score


def load_training_frame(
    sample_path: str = "data/sample_logs.csv",
    labeled_path: str = "data/labeled_alerts.csv",
) -> pd.DataFrame:
    """Combine base sample logs with analyst-labeled alerts (same training columns)."""
    cols = ["timestamp", "source_ip", "username", "event_type", "severity", "description"]
    frames = []
    for path in (sample_path, labeled_path):
        if not path or not os.path.exists(path):
            continue
        try:
            part = pd.read_csv(path)
        except Exception as exc:
            print(f"⚠️ Could not read {path}: {exc}")
            continue
        for c in cols:
            if c not in part.columns:
                part[c] = ""
        frames.append(part[cols])
    if not frames:
        return pd.DataFrame(columns=cols)
    return pd.concat(frames, ignore_index=True)


def train_ml_model(
    file_path="data/sample_logs.csv",
    model_file=MODEL_FILE,
    vectorizer_file=VECTORIZER_FILE,
    scaler_file=SCALER_FILE,
    label_encoder_file=LABEL_ENCODER_FILE,
    labeled_path: str | None = "data/labeled_alerts.csv",
    combine_labeled: bool = True,
):
    """Train severity model. Returns metrics dict (or None on hard failure)."""
    if combine_labeled and labeled_path:
        df = load_training_frame(file_path, labeled_path)
        if df.empty and os.path.exists(file_path):
            df = pd.read_csv(file_path)
    else:
        if not os.path.exists(file_path):
            print(f"⚠️ File not found: {file_path}")
            return None
        df = pd.read_csv(file_path)

    required_columns = ["event_type", "description", "username", "severity", "timestamp", "source_ip"]
    for col in required_columns:
        if col not in df.columns:
            print(f"⚠️ CSV must contain '{col}' column.")
            return None

    df["severity"] = df["severity"].fillna("unknown").astype(str)
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df["severity"])

    # Quick stratified hold-out print for the operator (honest peek; artifacts refit on full data)
    stratify = y if pd.Series(df["severity"]).value_counts().min() >= 2 else None
    train_df, test_df, y_train, y_test = train_test_split(
        df, y, test_size=0.3, random_state=RANDOM_STATE, stratify=stratify
    )
    X_train, vectorizer, scaler = build_features(train_df, fit=True)
    X_test, _, _ = build_features(test_df, vectorizer=vectorizer, scaler=scaler, fit=False)

    # Select on full-feature matrix built consistently (fit vectorizer on all for selection CV)
    X_all, vectorizer_full, scaler_full = build_features(df, fit=True)
    best_name, best_est, cv_f1 = select_best_estimator(X_all, y)

    # Fit selected model on train split for a quick classification report
    report_model = _clone_fresh(best_name)
    report_model.fit(X_train, y_train)
    y_pred = report_model.predict(X_test)
    print("\n📊 Hold-out peek (artifacts will be refit on FULL data):\n")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=label_encoder.classes_,
            zero_division=0,
        )
    )

    # Refit best estimator + vectorizer/scaler on FULL data for saved artifacts
    final_model = _clone_fresh(best_name)
    final_model.fit(X_all, y)

    joblib.dump(final_model, model_file)
    joblib.dump(vectorizer_full, vectorizer_file)
    joblib.dump(scaler_full, scaler_file)
    joblib.dump(label_encoder, label_encoder_file)

    report_text = classification_report(
        y_test,
        y_pred,
        target_names=label_encoder.classes_,
        zero_division=0,
        output_dict=True,
    )
    print(f"\n✅ Best model ({best_name}) refit on full data and saved: {model_file}")
    print(f"✅ Vectorizer saved: {vectorizer_file}")
    print(f"✅ Scaler saved: {scaler_file}")
    print(f"✅ Label encoder saved: {label_encoder_file}")
    print("ℹ️ For honest hold-out metrics, run: python evaluate_model.py")
    print(f"ℹ️ CV macro F1 during selection: {cv_f1:.3f} (N={len(df)}; not production-ready)")

    return {
        "ok": True,
        "model": best_name,
        "cv_macro_f1": float(cv_f1),
        "n_samples": int(len(df)),
        "classes": list(label_encoder.classes_),
        "holdout_macro_f1": float(report_text.get("macro avg", {}).get("f1-score") or 0.0),
        "holdout_accuracy": float(report_text.get("accuracy") or 0.0),
        "artifacts": {
            "model": model_file,
            "vectorizer": vectorizer_file,
            "scaler": scaler_file,
            "label_encoder": label_encoder_file,
        },
    }


def _clone_fresh(name: str):
    """Return a fresh unfitted estimator matching the selected name."""
    mapping = {n: e for n, e in _candidate_models()}
    # Recreate so we don't reuse a fitted instance from CV internals
    if name == "logreg":
        return LogisticRegression(
            max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE
        )
    if name == "random_forest":
        return RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
    if name == "calibrated_logreg":
        base = LogisticRegression(
            max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE
        )
        return CalibratedClassifierCV(base, cv=3)
    return mapping.get(name) or LogisticRegression(
        max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train the SOC severity model")
    parser.add_argument(
        "--candidate",
        action="store_true",
        help="Write a versioned checkpoint and leave the active model in place",
    )
    parser.add_argument(
        "--activate",
        metavar="ID",
        help="Promote a checkpoint id to the live triage artifacts",
    )
    args = parser.parse_args()
    if args.activate:
        from model_registry import activate_checkpoint

        activate_checkpoint(args.activate)
    elif args.candidate:
        from model_registry import train_candidate

        train_candidate()
    else:
        metrics = train_ml_model()
        if metrics:
            from model_registry import register_live_as_checkpoint

            register_live_as_checkpoint(metrics)
