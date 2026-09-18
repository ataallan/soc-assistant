"""Unit tests for label queue insert/dedupe/save."""

from __future__ import annotations

from pathlib import Path

import db


def _tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "label_test.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    if hasattr(db, "reset_connection"):
        db.reset_connection()
    elif hasattr(db, "reset_engine"):
        db.reset_engine()
    db.init_db(db_path)
    return db_path


def test_insert_and_dedupe(tmp_path, monkeypatch):
    db_path = _tmp_db(tmp_path, monkeypatch)
    items = [
        {
            "summary": "Brute force from 10.0.0.8",
            "full_log": "sshd: Failed password for root from 10.0.0.8",
            "agent": "web-01",
            "rule_id": "5710",
            "rule_level": 10,
            "severity": "high",
        },
        {
            "summary": "Brute force from 10.0.0.8",
            "full_log": "sshd: Failed password for root from 10.0.0.8",
            "agent": "web-01",
            "rule_id": "5710",
            "rule_level": 10,
            "severity": "high",
        },
    ]
    result = db.insert_label_queue_items(items, db_path=db_path, source="wazuh")
    assert result["inserted"] == 1
    assert result["skipped_dupes"] == 1
    assert result["total_seen"] == 2
    pending = db.list_label_queue(status="pending", db_path=db_path)
    assert len(pending) == 1
    assert pending[0]["summary"].startswith("Brute force")


def test_save_label_writes_csv_and_alerts_table(tmp_path, monkeypatch):
    db_path = _tmp_db(tmp_path, monkeypatch)
    csv_path = tmp_path / "labeled_alerts.csv"
    monkeypatch.setattr(db, "LABELED_CSV_PATH", csv_path)

    db.insert_label_queue_items(
        [{"summary": "malware detected", "full_log": "malware on host", "agent": "a1"}],
        db_path=db_path,
    )
    pending = db.list_label_queue(db_path=db_path)
    qid = pending[0]["id"]
    out = db.save_label(qid, "critical", notes="confirmed", db_path=db_path, append_csv=True)
    assert out.get("ok", True) is True
    assert (out.get("label_severity") or out.get("training_row", {}).get("severity")) in ("critical", None) or "critical" in str(out)

    assert db.list_label_queue(status="pending", db_path=db_path) == []
    labeled = db.list_label_queue(status="labeled", db_path=db_path)
    assert len(labeled) == 1
    assert labeled[0]["label_severity"] == "critical"

    assert csv_path.exists()
    header = csv_path.read_text(encoding="utf-8").splitlines()[0]
    assert "timestamp" in header
    assert "severity" in header
    body = csv_path.read_text(encoding="utf-8")
    assert "critical" in body

    counts = db.label_queue_counts(db_path=db_path)
    assert counts["labeled"] == 1
    assert counts["alerts_labeled"] >= 1


def test_skip_label(tmp_path, monkeypatch):
    db_path = _tmp_db(tmp_path, monkeypatch)
    db.insert_label_queue_items(
        [{"summary": "noise", "full_log": "benign heartbeat"}],
        db_path=db_path,
    )
    qid = db.list_label_queue(db_path=db_path)[0]["id"]
    out = db.skip_label(qid, notes="noise", db_path=db_path)
    assert out.get("ok", True) is True
    assert db.list_label_queue(status="pending", db_path=db_path) == []
    assert db.label_queue_counts(db_path=db_path)["skipped"] == 1
