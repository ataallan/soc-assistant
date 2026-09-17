"""Tests for triage report view filters and alert count helpers."""

import pandas as pd

from report_filters import (
    VIEW_LABELS,
    compute_alert_counts,
    escalated_mask,
    filter_report_df,
    normalize_view,
    severe_mask,
)


def _sample_df():
    return pd.DataFrame(
        [
            {
                "timestamp": "t1",
                "severity": "low",
                "rule_based": "monitor",
                "ml_prediction": "low",
            },
            {
                "timestamp": "t2",
                "severity": "HIGH",
                "rule_based": "escalate",
                "ml_prediction": "medium",
            },
            {
                "timestamp": "t3",
                "severity": "critical",
                "rule_based": "monitor",
                "ml_prediction": "critical",
            },
            {
                "timestamp": "t4",
                "severity": None,
                "rule_based": "escalate",
                "ml_prediction": "low",
            },
            {
                "timestamp": "t5",
                "severity": "medium",
                "rule_based": "monitor",
                "ml_prediction": "high",
            },
        ]
    )


def test_normalize_view_defaults():
    assert normalize_view(None) == ("total", VIEW_LABELS["total"])
    assert normalize_view("SEVERE") == ("severe", VIEW_LABELS["severe"])
    assert normalize_view("nope") == ("total", VIEW_LABELS["total"])


def test_severe_includes_high_critical_and_missing_escalate():
    df = _sample_df()
    mask = severe_mask(df)
    # high, critical, missing+escalate
    assert list(df.loc[mask, "timestamp"]) == ["t2", "t3", "t4"]


def test_escalated_uses_rule_based_and_ml():
    df = _sample_df()
    mask = escalated_mask(df)
    # escalate rows t2,t4 + ml high t5 + ml critical t3
    assert set(df.loc[mask, "timestamp"]) == {"t2", "t3", "t4", "t5"}


def test_filter_report_views():
    df = _sample_df()
    assert len(filter_report_df(df, "total")) == 5
    assert len(filter_report_df(df, "severe")) == 3
    assert len(filter_report_df(df, "escalated")) == 4
    assert len(filter_report_df(df, "unknown")) == 5


def test_compute_alert_counts():
    counts = compute_alert_counts(_sample_df())
    assert counts["total_alerts"] == 5
    assert counts["report_rows"] == 5
    assert counts["severe_alerts"] == 3
    assert counts["escalated_events"] == 4


def test_escalated_falls_back_to_severity_when_no_rec_column():
    df = pd.DataFrame(
        [
            {"severity": "high", "ml_prediction": "low"},
            {"severity": "low", "ml_prediction": "low"},
            {"severity": "critical", "ml_prediction": None},
        ]
    )
    mask = escalated_mask(df)
    assert list(df.loc[mask, "severity"]) == ["high", "critical"]


def test_empty_df_counts():
    counts = compute_alert_counts(pd.DataFrame())
    assert counts == {
        "total_alerts": 0,
        "report_rows": 0,
        "severe_alerts": 0,
        "escalated_events": 0,
    }
