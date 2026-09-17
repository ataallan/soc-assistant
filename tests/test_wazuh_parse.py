from wazuh_integration import (
    _structure_alert,
    _parse_alerts_structured,
    wazuh_level_to_severity,
)


def test_level_mapping():
    assert wazuh_level_to_severity(3) == "low"
    assert wazuh_level_to_severity(8) == "medium"
    assert wazuh_level_to_severity(11) == "high"
    assert wazuh_level_to_severity(14) == "critical"


def test_structure_alert_from_wazuh_shape():
    item = {
        "timestamp": "2026-01-01T00:00:00Z",
        "agent": {"name": "agent-1", "id": "001"},
        "rule": {"id": "5503", "level": 10, "description": "Login failed"},
        "full_log": "sshd: Failed password for alice",
    }
    alert = _structure_alert(item)
    assert alert["agent"] == "agent-1"
    assert alert["rule_id"] == "5503"
    assert alert["severity"] == "high"
    assert "Failed password" in alert["full_log"]
    assert "Login failed" in alert["summary"] or "alice" in alert["summary"]


def test_parse_affected_items_envelope():
    payload = {
        "data": {
            "affected_items": [
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "agent": {"name": "web01"},
                    "rule": {"id": "1002", "level": 5, "description": "Unknown"},
                    "full_log": "noise event",
                }
            ]
        }
    }
    alerts = _parse_alerts_structured(payload)
    assert len(alerts) == 1
    assert alerts[0]["agent"] == "web01"
    assert alerts[0]["severity"] == "low"
