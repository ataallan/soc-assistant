import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import containment
import db


def _prep(tmp_path, monkeypatch, mode="simulated"):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CONTAINMENT_MODE", mode)
    (tmp_path / "data").mkdir()
    db_path = tmp_path / "data" / "soc_assistant.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("CONTAINMENT_STUB_URL", raising=False)
    monkeypatch.delenv("CONTAINMENT_STUB_TOKEN", raising=False)
    db.reset_connection()
    db.init_db(db_path)
    containment._db_ready = True  # skip ensure_db_ready side effects in unit tests
    monkeypatch.setattr(containment, "DATA_DIR", Path("data"))
    monkeypatch.setattr(containment, "BLOCKED_FILE", Path("data") / "blocked_entities.json")
    monkeypatch.setattr(containment, "AUDIT_FILE", Path("data") / "containment_audit.jsonl")
    return db_path


def test_simulated_block_persists(tmp_path, monkeypatch):
    db_path = _prep(tmp_path, monkeypatch, "simulated")

    r = containment.block_ip("203.0.113.10")
    assert r["ok"] is True
    data = containment.load_blocked()
    assert "203.0.113.10" in data["ips"]
    audit = db.list_audit(limit=5, db_path=db_path)
    assert audit
    detail = audit[0]["detail"]
    assert "applied" in (detail or "")


def test_dry_run_does_not_persist(tmp_path, monkeypatch):
    db_path = _prep(tmp_path, monkeypatch, "dry_run")

    r = containment.block_ip("198.51.100.7")
    assert r["ok"] is True
    assert r["changed"] is False
    assert containment.load_blocked()["ips"] == []
    audit = db.list_audit(limit=5, db_path=db_path)
    assert audit
    assert "dry_run" in (audit[0]["detail"] or "")


def test_stub_log_only_then_persists(tmp_path, monkeypatch):
    _prep(tmp_path, monkeypatch, "stub")
    monkeypatch.delenv("CONTAINMENT_STUB_URL", raising=False)

    r = containment.block_user("alice")
    assert r["ok"] is True
    assert "alice" in containment.load_blocked()["users"]


def test_live_alias_is_integration_mode(tmp_path, monkeypatch):
    _prep(tmp_path, monkeypatch, "live")
    assert containment.is_integration_mode() is True
    assert containment.get_mode() == "live"
    assert "Integrated" in containment.get_mode_label()


def test_preview_never_calls_network(tmp_path, monkeypatch):
    _prep(tmp_path, monkeypatch, "stub")
    monkeypatch.setenv("CONTAINMENT_STUB_URL", "https://example.invalid/contain")
    monkeypatch.setenv("CONTAINMENT_STUB_TOKEN", "super-secret-token")

    with patch.object(containment.requests, "post") as mock_post:
        preview = containment.preview_block_ip("203.0.113.55", actor_is_admin=True)
        assert mock_post.call_count == 0

    assert preview["ok"] is True
    assert preview["action"] == "block"
    assert preview["target"] == "203.0.113.55"
    assert preview["mode"] == "stub"
    assert preview["would_call_url"] == "https://example.invalid/contain"
    assert preview["allowed"] is True
    assert preview["requires_confirm"] is True
    assert preview["body_summary"]["auth"] == "bearer"
    assert "super-secret-token" not in json.dumps(preview)

    preview_analyst = containment.preview_block_ip("203.0.113.55", actor_is_admin=False)
    assert preview_analyst["allowed"] is False


def test_execute_confirmed_requires_confirm(tmp_path, monkeypatch):
    _prep(tmp_path, monkeypatch, "stub")
    r = containment.execute_confirmed("block", "ip", "203.0.113.1", confirm=False)
    assert r["ok"] is False
    assert r.get("requires_confirm") is True
    assert containment.load_blocked()["ips"] == []


def test_execute_stub_mode_mocked_requests(tmp_path, monkeypatch):
    db_path = _prep(tmp_path, monkeypatch, "stub")
    monkeypatch.setenv("CONTAINMENT_STUB_URL", "https://example.invalid/contain")
    monkeypatch.setenv("CONTAINMENT_STUB_TOKEN", "lab-token-do-not-log")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"ok":true}'

    with patch.object(containment.requests, "post", return_value=mock_resp) as mock_post:
        denied = containment.execute_confirmed("block", "ip", "198.51.100.9", confirm=False)
        assert denied["ok"] is False
        assert mock_post.call_count == 0

        r = containment.execute_confirmed("block", "ip", "198.51.100.9", confirm=True)
        assert r["ok"] is True
        assert mock_post.call_count == 1
        args, kwargs = mock_post.call_args
        assert args[0] == "https://example.invalid/contain"
        headers = kwargs.get("headers") or {}
        assert headers.get("Authorization") == "Bearer lab-token-do-not-log"
        assert kwargs.get("json", {}).get("target") == "198.51.100.9"

    assert "198.51.100.9" in containment.load_blocked()["ips"]
    audit = db.list_audit(limit=5, db_path=db_path)
    assert audit
    blob = json.dumps(audit)
    assert "lab-token-do-not-log" not in blob
    assert "applied" in (audit[0]["detail"] or "")


def test_preview_unblock_helpers(tmp_path, monkeypatch):
    _prep(tmp_path, monkeypatch, "simulated")
    p = containment.preview_unblock_user("bob", actor_is_admin=True)
    assert p["action"] == "unblock"
    assert p["target_type"] == "user"
    assert p["requires_confirm"] is False
    assert p["would_call_url"] is None
