"""Helpers to filter triage report rows and compute dashboard alert counts."""

from __future__ import annotations

from typing import Any

import pandas as pd

VIEW_LABELS = {
    "total": "All triage alerts",
    "severe": "Severe alerts",
    "escalated": "Escalated alerts",
}

VALID_VIEWS = frozenset(VIEW_LABELS.keys())


def _col_lower(df: pd.DataFrame, name: str) -> pd.Series | None:
    if name not in df.columns:
        return None
    return df[name].astype(str).str.strip().str.lower()


def _severity_missing_mask(df: pd.DataFrame) -> pd.Series:
    if "severity" not in df.columns:
        return pd.Series(True, index=df.index)
    raw = df["severity"]
    sev = raw.astype(str).str.strip().str.lower()
    return raw.isna() | sev.isin(["", "nan", "none", "null"])


def severe_mask(df: pd.DataFrame) -> pd.Series:
    """Rows with severity critical/high, or missing severity + escalate recommendation."""
    if df is None or df.empty:
        return pd.Series(dtype=bool)

    mask = pd.Series(False, index=df.index)
    sev = _col_lower(df, "severity")
    if sev is not None:
        mask = mask | sev.isin(["critical", "high"])

    missing = _severity_missing_mask(df)
    for col in ("rule_based", "recommendation"):
        rb = _col_lower(df, col)
        if rb is not None:
            mask = mask | (missing & (rb == "escalate"))
            break
    return mask


def escalated_mask(df: pd.DataFrame) -> pd.Series:
    """Escalate recommendations, or ML high/escalate signals; severity fallback if no rec col."""
    if df is None or df.empty:
        return pd.Series(dtype=bool)

    mask = pd.Series(False, index=df.index)
    found_rec = False
    for col in ("rule_based", "recommendation"):
        rb = _col_lower(df, col)
        if rb is not None:
            found_rec = True
            mask = mask | (rb == "escalate")

    ml = _col_lower(df, "ml_prediction")
    if ml is not None:
        mask = mask | ml.isin(
            ["high", "critical", "high risk", "high_risk", "escalate"]
        )

    if not found_rec:
        sev = _col_lower(df, "severity")
        if sev is not None:
            mask = mask | sev.isin(["high", "critical"])
    return mask


def filter_report_df(df: pd.DataFrame, view: str = "total") -> pd.DataFrame:
    """Filter triage dataframe by dashboard view query param."""
    if df is None or df.empty:
        return df if df is not None else pd.DataFrame()

    view = (view or "total").strip().lower()
    if view not in VALID_VIEWS:
        view = "total"
    if view == "total":
        return df
    if view == "severe":
        return df.loc[severe_mask(df)].copy()
    if view == "escalated":
        return df.loc[escalated_mask(df)].copy()
    return df


def compute_alert_counts(df: pd.DataFrame | None) -> dict[str, Any]:
    """Counts for /notifications and dashboard badges."""
    if df is None or df.empty:
        return {
            "total_alerts": 0,
            "report_rows": 0,
            "severe_alerts": 0,
            "escalated_events": 0,
        }
    n = int(len(df))
    return {
        "total_alerts": n,
        "report_rows": n,
        "severe_alerts": int(severe_mask(df).sum()),
        "escalated_events": int(escalated_mask(df).sum()),
    }


def normalize_view(view: str | None) -> tuple[str, str]:
    """Return (view_key, view_label)."""
    key = (view or "total").strip().lower()
    if key not in VALID_VIEWS:
        key = "total"
    return key, VIEW_LABELS[key]
