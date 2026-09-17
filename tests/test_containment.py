import json
import os
from pathlib import Path

import containment


def test_simulated_block_persists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CONTAINMENT_MODE", "simulated")
    (tmp_path / "data").mkdir()
    # reload paths relative to cwd
    monkeypatch.setattr(containment, "DATA_DIR", Path("data"))
    monkeypatch.setattr(containment, "BLOCKED_FILE", Path("data") / "blocked_entities.json")
    monkeypatch.setattr(containment, "AUDIT_FILE", Path("data") / "containment_audit.jsonl")

    r = containment.block_ip("203.0.113.10")
    assert r["ok"] is True
    data = containment.load_blocked()
    assert "203.0.113.10" in data["ips"]
    audit = Path("data/containment_audit.jsonl").read_text().strip().splitlines()
    assert json.loads(audit[-1])["result"] == "applied"


def test_dry_run_does_not_persist(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CONTAINMENT_MODE", "dry_run")
    (tmp_path / "data").mkdir()
    monkeypatch.setattr(containment, "DATA_DIR", Path("data"))
    monkeypatch.setattr(containment, "BLOCKED_FILE", Path("data") / "blocked_entities.json")
    monkeypatch.setattr(containment, "AUDIT_FILE", Path("data") / "containment_audit.jsonl")

    r = containment.block_ip("198.51.100.7")
    assert r["ok"] is True
    assert r["changed"] is False
    assert containment.load_blocked()["ips"] == []
    audit = json.loads(Path("data/containment_audit.jsonl").read_text().strip().splitlines()[-1])
    assert audit["result"] == "dry_run"


def test_stub_log_only_then_persists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CONTAINMENT_MODE", "stub")
    monkeypatch.delenv("CONTAINMENT_STUB_URL", raising=False)
    (tmp_path / "data").mkdir()
    monkeypatch.setattr(containment, "DATA_DIR", Path("data"))
    monkeypatch.setattr(containment, "BLOCKED_FILE", Path("data") / "blocked_entities.json")
    monkeypatch.setattr(containment, "AUDIT_FILE", Path("data") / "containment_audit.jsonl")

    r = containment.block_user("alice")
    assert r["ok"] is True
    assert "alice" in containment.load_blocked()["users"]
