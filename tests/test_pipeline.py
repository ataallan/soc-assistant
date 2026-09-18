"""Pipeline smoke tests — offline, no network."""

import os

from detection.pipeline import process_alert


def test_pipeline_brute_force_smoke(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    monkeypatch.setenv("ML_ASSIST_ONLY", "true")
    result = process_alert(
        {
            "event_type": "brute_force",
            "description": "Possible brute-force attack detected",
            "username": "bob.jones",
            "source_ip": "172.16.5.12",
            "timestamp": "2025-11-23T13:20:10Z",
            "severity": "high",
        }
    )
    assert result["severity"] in ("critical", "high", "medium", "low")
    assert "matched_rules" in result
    assert result["ml_assist"] is True or result.get("severity_source") == "rules"
    assert result["alert"]["src_ip"] == "172.16.5.12"
    assert result["enrichment"]["src_ip"]["classification"] == "private"


def test_pipeline_malware_yaml_and_explain(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setenv("ML_ASSIST_ONLY", "true")
    result = process_alert("ransomware encrypting shares on host")
    assert result["rule_severity"] == "critical"
    assert result["severity"] == "critical"
    assert result["matched_rule_id"]
    assert result["rule_explain"]
    assert result["recommendation"] == "escalate"


def test_pipeline_benign_low(monkeypatch):
    monkeypatch.setenv("ML_ASSIST_ONLY", "true")
    result = process_alert("User opened a ticket about printer jam")
    assert result["severity"] == "low"
    assert result["recommendation"] == "ignore"
    assert result["matched_rules"] == []


def test_pipeline_never_crashes_on_none():
    result = process_alert(None)
    assert "severity" in result
    assert "matched_rules" in result
