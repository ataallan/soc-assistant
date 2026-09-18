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


def test_pipeline_structured_wazuh_keeps_src_ip_user(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setenv("ML_ASSIST_ONLY", "true")
    from wazuh_integration import _structure_alert

    raw = {
        "timestamp": "2026-01-01T00:00:00Z",
        "agent": {"name": "vpn01", "id": "002"},
        "rule": {"id": "5503", "level": 10, "description": "Login failed"},
        "full_log": "sshd: Failed password for root from 203.0.113.44 port 22",
        "data": {"srcip": "203.0.113.44", "srcuser": "root"},
    }
    structured = _structure_alert(raw)
    assert structured["src_ip"] == "203.0.113.44"
    assert structured["user"] == "root"

    result = process_alert(structured)
    assert result["alert"]["src_ip"] == "203.0.113.44"
    assert result["alert"]["user"] == "root"
    assert result["ip"] == "203.0.113.44"
    assert result["user"] == "root"


def test_pipeline_allowlisted_alert_forced_low_ignore(tmp_path, monkeypatch):
    """Allowlisted IP → low/ignore even if text would otherwise escalate."""
    import yaml
    from detection.allowlists import clear_allowlist_cache

    monkeypatch.setenv("ML_ASSIST_ONLY", "true")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    clear_allowlist_cache()
    al = tmp_path / "al.yml"
    al.write_text(
        yaml.safe_dump(
            {
                "ips": ["203.0.113.50"],
                "cidrs": [],
                "users": [],
                "hosts": [],
                "suppress_wazuh_rule_ids": [],
            }
        ),
        encoding="utf-8",
    )
    result = process_alert(
        {
            "description": "Possible brute-force attack detected",
            "event_type": "brute_force",
            "source_ip": "203.0.113.50",
            "username": "root",
        },
        allowlist_path=al,
    )
    assert result["allowlisted"] is True
    assert result["severity"] == "low"
    assert result["recommendation"] == "ignore"
    assert result["severity_source"] == "allowlist"
    assert result["allowlist_reasons"]


def test_pipeline_suppress_wazuh_rule_id(tmp_path, monkeypatch):
    import yaml
    from detection.allowlists import clear_allowlist_cache

    monkeypatch.setenv("ML_ASSIST_ONLY", "true")
    clear_allowlist_cache()
    al = tmp_path / "al.yml"
    al.write_text(
        yaml.safe_dump(
            {
                "ips": [],
                "cidrs": [],
                "users": [],
                "hosts": [],
                "suppress_wazuh_rule_ids": ["2902"],
            }
        ),
        encoding="utf-8",
    )
    result = process_alert(
        {
            "rule_id": "2902",
            "full_log": "dpkg: package foo installed",
            "agent": {"name": "ubuntu-lab"},
        },
        allowlist_path=al,
    )
    assert result["allowlisted"] is True
    assert result["severity"] == "low"
    assert result["recommendation"] == "ignore"
