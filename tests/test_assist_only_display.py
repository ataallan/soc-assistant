"""Unit tests for honest ML assist-only severity display helpers."""

import triage_engine as te


def test_assist_only_keeps_rules_severity_even_with_confident_ml(monkeypatch):
    monkeypatch.setenv("ML_ASSIST_ONLY", "true")
    monkeypatch.setenv("ML_CONFIDENCE_THRESHOLD", "0.70")
    resolved = te.resolve_display_severity(
        "medium", "high", 0.95, assist_only=True, threshold=0.70
    )
    assert resolved["severity"] == "medium"
    assert resolved["severity_source"] == "rules"
    assert resolved["ml_assist"] is True
    assert resolved["ml_used_for_display"] is False


def test_low_confidence_never_overrides(monkeypatch):
    monkeypatch.setenv("ML_ASSIST_ONLY", "false")
    resolved = te.resolve_display_severity(
        "low", "high", 0.40, assist_only=False, threshold=0.70
    )
    assert resolved["severity"] == "low"
    assert resolved["severity_source"] == "rules"
    assert resolved["low_confidence"] is True


def test_override_mode_uses_ml_when_confident(monkeypatch):
    monkeypatch.setenv("ML_ASSIST_ONLY", "false")
    resolved = te.resolve_display_severity(
        "medium", "high", 0.90, assist_only=False, threshold=0.70
    )
    assert resolved["severity"] == "high"
    assert resolved["severity_source"] == "ml"
    assert resolved["ml_used_for_display"] is True


def test_hybrid_when_ml_matches_rules(monkeypatch):
    monkeypatch.setenv("ML_ASSIST_ONLY", "false")
    resolved = te.resolve_display_severity(
        "high", "high", 0.88, assist_only=False, threshold=0.70
    )
    assert resolved["severity"] == "high"
    assert resolved["severity_source"] == "hybrid"


def test_rules_critical_always_wins(monkeypatch):
    monkeypatch.setenv("ML_ASSIST_ONLY", "false")
    resolved = te.resolve_display_severity(
        "critical", "low", 0.99, assist_only=False, threshold=0.70
    )
    assert resolved["severity"] == "critical"
    assert resolved["severity_source"] == "rules"


def test_format_low_confidence_label():
    disp = te.format_ml_assist_display("high", 0.45, threshold=0.70, assist_only=True)
    assert disp["low_confidence"] is True
    assert disp["used"] is False
    assert "not used" in disp["label"].lower()
    assert "45" in disp["label"]


def test_format_assist_high_confidence_not_used_when_assist_only():
    disp = te.format_ml_assist_display("high", 0.85, threshold=0.70, assist_only=True)
    assert disp["low_confidence"] is False
    assert disp["used"] is False
    assert "ml assist" in disp["label"].lower()
    assert "85" in disp["label"]


def test_analyze_log_assist_only_defaults(monkeypatch):
    monkeypatch.setenv("ML_ASSIST_ONLY", "true")

    def fake_ml(*args, **kwargs):
        return "high", 0.99

    monkeypatch.setattr(te, "ml_predict_severity", fake_ml)
    result = te.analyze_log("User opened a ticket about printer jam")
    assert result["severity"] == "low"
    assert result["severity_source"] == "rules"
    assert result["ml_assist"] is True
    assert result["ml_severity"] == "high"
    assert result["ml_confidence"] == 0.99
