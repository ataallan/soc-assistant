"""Tests for detection.normalize — defensive stable alert shaping."""

from detection.normalize import normalize_alert


def test_normalize_string_log():
    alert = normalize_alert("failed login user=alice from 10.0.0.5")
    assert alert["tenant_id"] == "local"
    assert alert["source"] == "log"
    assert "failed login" in alert["raw_message"]
    assert isinstance(alert["extras"], dict)


def test_normalize_csv_row():
    row = {
        "timestamp": "2025-11-23T13:12:01Z",
        "source_ip": "192.168.1.50",
        "username": "john.doe",
        "event_type": "failed_login",
        "description": "Multiple failed login attempts detected",
        "severity": "medium",
    }
    alert = normalize_alert(row)
    assert alert["source"] == "csv"
    assert alert["src_ip"] == "192.168.1.50"
    assert alert["user"] == "john.doe"
    assert alert["severity_hint"] == "medium"
    assert "failed login" in alert["raw_message"].lower() or "Multiple" in alert["raw_message"]


def test_normalize_wazuh_ish_dict():
    raw = {
        "timestamp": "2026-01-01T00:00:00Z",
        "agent": {"name": "dc01", "id": "001"},
        "rule": {"id": "5710", "level": 10, "description": "sshd: brute force"},
        "full_log": "sshd: Failed password for root from 203.0.113.9",
        "data": {"srcip": "203.0.113.9", "srcuser": "root"},
    }
    alert = normalize_alert(raw)
    assert alert["source"] == "wazuh"
    assert alert["rule_id"] == "5710"
    assert alert["host"] == "dc01"
    assert alert["src_ip"] == "203.0.113.9"
    assert alert["user"] == "root"
    assert "brute force" in (alert["rule_description"] or "").lower()


def test_normalize_none_and_garbage_never_crash():
    assert normalize_alert(None)["raw_message"] == ""
    assert normalize_alert(12345)["raw_message"] == "12345"
    assert normalize_alert({"weird": object()})["tenant_id"] == "local"


def test_normalize_tenant_override():
    alert = normalize_alert("ping", tenant_id="acme")
    assert alert["tenant_id"] == "acme"
