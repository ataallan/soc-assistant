import json
import os
from pathlib import Path

import containment
import db


def _prep(tmp_path, monkeypatch, mode="simulated"):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CONTAINMENT_MODE", mode)
    (tmp_path / "data").mkdir()
    db_path = tmp_path / "data" / "soc_assistant.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
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
