"""Unit tests for rule+ML auto-containment agreement gate."""

from triage_engine import should_auto_contain


def test_agree_high_allows():
    r = should_auto_contain("high", ml_severity="high", ml_confidence=0.85, threshold=0.70)
    assert r["allow"] is True
    assert r["reason"] == "agreement"


def test_disagree_denies():
    r = should_auto_contain("high", ml_severity="low", ml_confidence=0.95, threshold=0.70)
    assert r["allow"] is False
    assert r["reason"] == "disagreement"
    assert "did not agree" in r["operator_note"].lower()


def test_low_confidence_denies():
    r = should_auto_contain("high", ml_severity="high", ml_confidence=0.40, threshold=0.70)
    assert r["allow"] is False
    assert r["reason"] == "low_confidence"
    assert "confidence" in r["operator_note"].lower()


def test_rules_critical_allows_without_ml_agreement():
    r = should_auto_contain("critical", ml_severity="low", ml_confidence=0.99, threshold=0.70)
    assert r["allow"] is True
    assert r["reason"] == "rules_critical"


def test_rules_critical_allows_when_ml_missing():
    r = should_auto_contain("critical", ml_severity=None, ml_confidence=0.0, threshold=0.70)
    assert r["allow"] is True
    assert r["reason"] == "rules_critical"


def test_rules_only_when_ml_missing_on_high():
    r = should_auto_contain("high", ml_severity=None, ml_confidence=0.0, threshold=0.70)
    assert r["allow"] is True
    assert r["reason"] == "rules_only"


def test_medium_rules_no_contain():
    r = should_auto_contain("medium", ml_severity="high", ml_confidence=0.99, threshold=0.70)
    assert r["allow"] is False
    assert r["reason"] == "rules_not_escalate"


def test_ml_critical_mapped_agrees_with_high_rules():
    """If ML somehow emits critical, treat as agreement with rules-high."""
    r = should_auto_contain("high", ml_severity="critical", ml_confidence=0.80, threshold=0.70)
    assert r["allow"] is True
    assert r["reason"] == "agreement"


def test_threshold_from_arg_boundary():
    r = should_auto_contain("high", ml_severity="high", ml_confidence=0.70, threshold=0.70)
    assert r["allow"] is True
    r2 = should_auto_contain("high", ml_severity="high", ml_confidence=0.699, threshold=0.70)
    assert r2["allow"] is False
    assert r2["reason"] == "low_confidence"
