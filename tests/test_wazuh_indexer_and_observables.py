"""Indexer preference, manager-log rejection, YAML rules, and observables."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

import wazuh_integration as wi
from detection.normalize import normalize_alert
from detection.pipeline import process_alert
from rules.engine import evaluate_rules, load_rules
import db


@pytest.fixture(autouse=True)
def _reset_wazuh(monkeypatch):
    monkeypatch.setattr(wi, "WAZUH_API", "https://wazuh.test:55000")
    monkeypatch.setattr(wi, "API_USER", "wazuh")
    monkeypatch.setattr(wi, "API_PASS", "test-password")
    monkeypatch.setattr(wi, "INDEXER_URL", "https://127.0.0.1:9200")
    monkeypatch.setattr(wi, "INDEXER_USER", "admin")
    monkeypatch.setattr(wi, "INDEXER_PASS", "")
    monkeypatch.setattr(wi, "INDEXER_VIA_WSL", False)
    monkeypatch.setattr(wi, "_TOKEN", None)
    monkeypatch.setattr(wi, "_TOKEN_EXP", 0.0)
    monkeypatch.setattr(wi, "_CACHED_ENDPOINT", None)
    monkeypatch.setattr(wi, "_CACHED_ENDPOINT_EXP", 0.0)
    monkeypatch.setattr(wi, "_LAST_ALERT_SOURCE", None)
    monkeypatch.setattr(wi, "_LAST_INDEXER_ERROR", None)
    yield


def test_manager_logs_not_in_endpoint_candidates():
    for c in wi._ALERT_ENDPOINT_CANDIDATES:
        assert "/manager/logs" not in c


def test_manager_log_shaped_items_rejected():
    item = {
        "timestamp": "2026-01-01T00:00:00Z",
        "tag": "wazuh-modulesd:syscollector",
        "level": "info",
        "description": "Evaluation finished.",
    }
    assert wi.is_manager_log_item(item) is True
    payload = {"data": {"affected_items": [item]}}
    parsed = wi._parse_alerts_structured(payload)
    # Manager-log-only payload must not surface as a security alert with that description
    assert not any(
        (a.get("rule_description") == "Evaluation finished.")
        or (a.get("full_log") or "").startswith("Evaluation finished")
        for a in parsed
        if a.get("rule_id")
    )
    # Prefer empty list after filter; accept empty-items fallback only without rule_id
    assert all(not a.get("rule_id") for a in parsed)


def test_structure_indexer_source_keeps_src_ip_and_host():
    source = {
        "timestamp": "2026-01-01T12:00:00.000Z",
        "agent": {"name": "win-lab-01", "id": "003"},
        "rule": {"id": "5710", "level": 10, "description": "sshd: authentication failed"},
        "full_log": "Failed password for root from 203.0.113.50",
        "data": {"srcip": "203.0.113.50", "srcuser": "root"},
    }
    alert = wi._structure_alert(source)
    assert alert["src_ip"] == "203.0.113.50"
    assert alert["host"] == "win-lab-01"
    assert alert["user"] == "root"
    assert alert["rule_id"] == "5710"


def test_fetch_prefers_indexer_when_configured(monkeypatch):
    monkeypatch.setattr(wi, "INDEXER_PASS", "indexer-secret")
    indexer_payload = {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "timestamp": "2026-01-01T12:00:00Z",
                        "agent": {"name": "edge01"},
                        "rule": {"id": "5503", "level": 8, "description": "Login failed"},
                        "full_log": "sshd fail",
                        "data": {"srcip": "198.51.100.9", "srcuser": "bob"},
                    }
                }
            ]
        }
    }

    def fake_post(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = indexer_payload
        resp.text = "{}"
        return resp

    with patch.object(wi.requests, "post", side_effect=fake_post) as mock_post:
        with patch.object(wi.requests, "get") as mock_get:
            alerts = wi.fetch_wazuh_alert_details(limit=5)

    assert len(alerts) == 1
    assert alerts[0]["src_ip"] == "198.51.100.9"
    assert alerts[0]["host"] == "edge01"
    assert wi.get_last_alert_source() == "indexer"
    mock_post.assert_called()
    # Manager API should not be required when indexer succeeds
    assert mock_get.call_count == 0


def test_yaml_rules_malware_cve_dns_fim():
    load_rules(force_reload=True)

    def ctx(text, **extra):
        alert = {
            "raw_message": text,
            "rule_description": text,
            "text": text,
            "host": extra.get("host", "lab"),
            "rule_id": extra.get("rule_id"),
        }
        return alert, {}

    m = evaluate_rules(*ctx("ransomware encrypting shares"))
    assert any(x["id"] == "DET-MALWARE-001" for x in m["matched_rules"])

    v = evaluate_rules(*ctx("CVE-2024-3094 vulnerability detector hit on xz-utils", host="pkg01"))
    assert any(x["id"] == "DET-VULN-001" for x in v["matched_rules"])

    d = evaluate_rules(*ctx("suspicious domain DNS query blocked"))
    assert any(x["id"] == "DET-DNS-001" for x in d["matched_rules"])

    f = evaluate_rules(*ctx("Integrity checksum changed for /etc/passwd"))
    assert any(x["id"] == "DET-FIM-001" for x in f["matched_rules"])

    rid = evaluate_rules(*ctx("rootcheck hit", rule_id="512"))
    assert any(x["id"] == "DET-MALWARE-002" for x in rid["matched_rules"])


def test_normalize_observables_hash_domain_cve():
    fim = normalize_alert(
        {
            "agent": {"name": "lab-agent"},
            "rule": {"id": "550", "level": 7, "description": "Integrity checksum changed."},
            "syscheck": {"sha256_after": "a" * 64, "path": "/bin/ls"},
            "full_log": "Integrity checksum changed",
        }
    )
    assert fim["host"] == "lab-agent"
    assert fim["file_hash"] == "a" * 64

    dns = normalize_alert(
        {
            "agent": {"name": "dns01"},
            "data": {"dns": {"question": {"name": "bad.example.org"}}},
            "full_log": "DNS query",
        }
    )
    assert dns["domain"] == "bad.example.org"

    vuln = normalize_alert(
        {
            "agent": {"name": "srv1"},
            "data": {"vulnerability": {"cve": "CVE-2024-3094"}, "package": {"name": "xz-utils"}},
            "full_log": "vulnerability",
        }
    )
    assert vuln["cve"] == "CVE-2024-3094"
    assert vuln["extras"].get("package") == "xz-utils"


def test_observables_on_case_from_triage(tmp_path, monkeypatch):
    db_path = tmp_path / "obs.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db.reset_connection()
    db.init_db(db_path)

    eid = db.insert_triage_event(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "log": "FIM change",
            "severity": "medium",
            "host": "lab-agent",
            "file_hash": "deadbeef" * 8,
            "cve": None,
            "domain": None,
            "ip": None,
            "user": None,
        },
        db_path=db_path,
        source="test",
    )
    case = db.create_case(triage_event_id=eid, db_path=db_path)
    assert case["host"] == "lab-agent"
    assert case["file_hash"] == "deadbeef" * 8
    assert case["ip"] is None


def test_pipeline_exposes_observables(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setenv("ML_ASSIST_ONLY", "true")
    result = process_alert(
        {
            "agent": {"name": "lab1"},
            "rule": {"id": "550", "level": 7, "description": "Integrity checksum changed"},
            "syscheck": {"md5_after": "d41d8cd98f00b204e9800998ecf8427e"},
            "full_log": "Integrity checksum changed",
        }
    )
    assert result["host"] == "lab1"
    assert result["file_hash"] == "d41d8cd98f00b204e9800998ecf8427e"
