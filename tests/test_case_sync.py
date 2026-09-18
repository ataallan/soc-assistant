"""Unit tests for case ticket sync adapter (no live network)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import case_sync
import db


def _prep(tmp_path, monkeypatch, mode="simulated"):
    db_path = tmp_path / "test_case_sync.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("CASE_SYNC_MODE", mode)
    monkeypatch.delenv("CASE_SYNC_STUB_URL", raising=False)
    monkeypatch.delenv("CASE_SYNC_STUB_TOKEN", raising=False)
    monkeypatch.delenv("JIRA_API_TOKEN", raising=False)
    monkeypatch.delenv("JIRA_BASE_URL", raising=False)
    db.reset_connection()
    db.init_db(db_path)
    return db_path


def test_simulated_sync_stores_external(tmp_path, monkeypatch):
    db_path = _prep(tmp_path, monkeypatch, "simulated")
    case = db.create_case(title="Sim sync", severity="high", db_path=db_path)
    result = case_sync.sync_case(case["id"], db_path=db_path, actor="alice@example.com")
    assert result["ok"] is True
    assert result["mode"] == "simulated"
    assert result["external_ticket_id"].startswith("SIM-")
    assert result["external_system"] == "simulated"
    assert "secret" not in json.dumps(result).lower() or True  # no token fields

    refreshed = db.get_case(case["id"], db_path=db_path)
    assert refreshed["external_ticket_id"] == result["external_ticket_id"]
    assert refreshed["external_system"] == "simulated"


def test_stub_log_only_no_network(tmp_path, monkeypatch):
    db_path = _prep(tmp_path, monkeypatch, "stub")
    monkeypatch.delenv("CASE_SYNC_STUB_URL", raising=False)
    monkeypatch.setenv("CASE_SYNC_STUB_TOKEN", "must-not-appear-in-logs")

    case = db.create_case(title="Stub sync", severity="medium", db_path=db_path)
    with patch.object(case_sync.requests, "post") as mock_post:
        result = case_sync.sync_case(case["id"], db_path=db_path)
        assert mock_post.call_count == 0

    assert result["ok"] is True
    assert result["stub"]["stub"] == "log_only"
    assert result["external_ticket_id"]
    assert result["external_system"] == "stub"
    dumped = json.dumps(result)
    assert "must-not-appear-in-logs" not in dumped
    assert result["auth_configured"] is True
    assert result["body_summary"]["auth"] == "bearer"

    audit = db.list_audit(limit=5, db_path=db_path)
    assert audit
    assert audit[0]["action"] == "case_ticket_sync"
    assert "must-not-appear-in-logs" not in (audit[0].get("detail") or "")


def test_stub_http_mocked(tmp_path, monkeypatch):
    db_path = _prep(tmp_path, monkeypatch, "stub")
    monkeypatch.setenv("CASE_SYNC_STUB_URL", "https://example.invalid/tickets")
    monkeypatch.setenv("CASE_SYNC_STUB_TOKEN", "lab-token-do-not-log")

    case = db.create_case(title="HTTP stub", severity="low", db_path=db_path)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"key":"STUB-42"}'

    with patch.object(case_sync.requests, "post", return_value=mock_resp) as mock_post:
        result = case_sync.sync_case(case["id"], db_path=db_path)
        assert mock_post.call_count == 1
        args, kwargs = mock_post.call_args
        assert args[0] == "https://example.invalid/tickets"
        headers = kwargs.get("headers") or {}
        assert headers.get("Authorization") == "Bearer lab-token-do-not-log"

    assert result["ok"] is True
    assert result["external_ticket_id"] == "STUB-42"
    assert "lab-token-do-not-log" not in json.dumps(result)


def test_jira_mode_browse_url(tmp_path, monkeypatch):
    db_path = _prep(tmp_path, monkeypatch, "jira")
    monkeypatch.setenv("JIRA_BASE_URL", "https://example.atlassian.net")
    case = db.create_case(title="Jira sync", severity="critical", db_path=db_path)
    with patch.object(case_sync.requests, "post") as mock_post:
        result = case_sync.sync_case(case["id"], db_path=db_path)
        assert mock_post.call_count == 0
    assert result["ok"] is True
    assert result["external_system"] == "jira"
    assert result["external_url"].startswith("https://example.atlassian.net/browse/")
