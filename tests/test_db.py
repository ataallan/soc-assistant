"""Unit tests for SQLite storage helpers and legacy migration."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import db


def _temp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test_soc.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    db.reset_connection()
    db.init_db(db_path)
    return db_path


def test_insert_and_list_triage(tmp_path, monkeypatch):
    db_path = _temp_db(tmp_path, monkeypatch)
    row_id = db.insert_triage_event(
        {
            "timestamp": "2026-01-01T12:00:00",
            "log": "failed login from 10.0.0.1",
            "severity": "high",
            "ml_prediction": "high",
            "ml_confidence": 0.91,
            "rule_based": "escalate",
            "user": "alice",
            "ip": "10.0.0.1",
            "containment_decision": "rules_critical",
            "containment_note": "blocked",
        },
        db_path=db_path,
        source="test",
    )
    assert row_id >= 1
    rows = db.list_triage_events(db_path=db_path)
    assert len(rows) == 1
    assert rows[0]["user"] == "alice"
    assert rows[0]["severity"] == "high"
    assert rows[0]["source"] == "test"


def test_list_filter_views_and_limit(tmp_path, monkeypatch):
    db_path = _temp_db(tmp_path, monkeypatch)
    samples = [
        {"timestamp": "t1", "log": "a", "severity": "low", "rule_based": "monitor", "ml_prediction": "low"},
        {"timestamp": "t2", "log": "b", "severity": "high", "rule_based": "escalate", "ml_prediction": "medium"},
        {"timestamp": "t3", "log": "c", "severity": "critical", "rule_based": "monitor", "ml_prediction": "critical"},
        {"timestamp": "t4", "log": "d", "severity": "medium", "rule_based": "monitor", "ml_prediction": "high"},
    ]
    for s in samples:
        db.insert_triage_event(s, db_path=db_path)

    assert len(db.list_triage_events(view="total", db_path=db_path)) == 4
    severe = db.list_triage_events(view="severe", db_path=db_path)
    assert len(severe) == 2
    escalated = db.list_triage_events(view="escalated", db_path=db_path)
    assert len(escalated) >= 2
    limited = db.list_triage_events(view="total", limit=2, db_path=db_path)
    assert len(limited) == 2


def test_count_alerts(tmp_path, monkeypatch):
    db_path = _temp_db(tmp_path, monkeypatch)
    db.insert_triage_event(
        {"timestamp": "t1", "log": "x", "severity": "low", "rule_based": "monitor", "ml_prediction": "low"},
        db_path=db_path,
    )
    db.insert_triage_event(
        {"timestamp": "t2", "log": "y", "severity": "high", "rule_based": "escalate", "ml_prediction": "high"},
        db_path=db_path,
    )
    counts = db.count_alerts(db_path=db_path)
    assert counts["total_alerts"] == 2
    assert counts["report_rows"] == 2
    assert counts["severe_alerts"] == 1
    assert counts["escalated_events"] >= 1


def test_blocks_and_audit(tmp_path, monkeypatch):
    db_path = _temp_db(tmp_path, monkeypatch)
    assert db.save_block("ip", "203.0.113.10", mode="simulated", db_path=db_path) is True
    assert db.save_block("ip", "203.0.113.10", mode="simulated", db_path=db_path) is False
    assert db.save_block("user", "bob", mode="simulated", db_path=db_path) is True
    blocks = db.load_blocks(db_path=db_path)
    assert "203.0.113.10" in blocks["ips"]
    assert "bob" in blocks["users"]
    assert db.remove_block("ip", "203.0.113.10", db_path=db_path) is True
    assert "203.0.113.10" not in db.load_blocks(db_path=db_path)["ips"]

    aid = db.append_audit(
        "block", "user", "bob", mode="simulated", detail={"result": "applied"}, db_path=db_path
    )
    assert aid >= 1
    audit = db.list_audit(limit=5, db_path=db_path)
    assert audit[0]["action"] == "block"
    assert audit[0]["entity_value"] == "bob"


def test_migrate_from_legacy_files(tmp_path, monkeypatch):
    db_path = tmp_path / "migrated.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    db.reset_connection()

    csv_path = tmp_path / "triage_report.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp",
                "log",
                "ip",
                "user",
                "severity",
                "rule_based",
                "ml_prediction",
                "ml_confidence",
                "containment_decision",
                "containment_note",
            ],
        )
        w.writeheader()
        w.writerow(
            {
                "timestamp": "2026-02-01T00:00:00",
                "log": "legacy event",
                "ip": "192.0.2.1",
                "user": "carol",
                "severity": "medium",
                "rule_based": "monitor",
                "ml_prediction": "medium",
                "ml_confidence": "0.55",
                "containment_decision": "n/a",
                "containment_note": "",
            }
        )

    blocked = tmp_path / "blocked_entities.json"
    blocked.write_text(
        json.dumps({"ips": ["198.51.100.1"], "users": ["dave"]}),
        encoding="utf-8",
    )

    audit = tmp_path / "containment_audit.jsonl"
    audit.write_text(
        json.dumps(
            {
                "timestamp": "2026-02-01T01:00:00Z",
                "mode": "simulated",
                "event": "block",
                "target_type": "ip",
                "target": "198.51.100.1",
                "result": "applied",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    counts = db.migrate_from_legacy_files(
        db_path=db_path,
        triage_csv=csv_path,
        blocked_json=blocked,
        audit_jsonl=audit,
    )
    assert counts["triage"] == 1
    assert counts["blocks"] == 2
    assert counts["audit"] == 1

    # Second run should not double-import (tables non-empty)
    counts2 = db.migrate_from_legacy_files(
        db_path=db_path,
        triage_csv=csv_path,
        blocked_json=blocked,
        audit_jsonl=audit,
    )
    assert counts2 == {"triage": 0, "blocks": 0, "audit": 0}

    rows = db.list_triage_events(db_path=db_path)
    assert rows[0]["log"] == "legacy event"
    blocks = db.load_blocks(db_path=db_path)
    assert "198.51.100.1" in blocks["ips"]
    assert "dave" in blocks["users"]


def test_export_triage_to_csv(tmp_path, monkeypatch):
    db_path = _temp_db(tmp_path, monkeypatch)
    db.insert_triage_event(
        {
            "timestamp": "2026-03-01T00:00:00",
            "log": "export me",
            "severity": "low",
            "rule_based": "monitor",
            "user": "erin",
            "ip": "203.0.113.5",
        },
        db_path=db_path,
    )
    out = tmp_path / "out.csv"
    n = db.export_triage_to_csv(out, db_path=db_path)
    assert n == 1
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "export me" in content
    assert "erin" in content
