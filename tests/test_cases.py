"""Unit tests for SOC case / ticket workflow helpers."""

from __future__ import annotations

import db


def _temp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test_cases.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db.reset_connection()
    db.init_db(db_path)
    return db_path


def test_create_list_and_counts(tmp_path, monkeypatch):
    db_path = _temp_db(tmp_path, monkeypatch)
    c1 = db.create_case(
        title="Brute force on vpn",
        severity="high",
        assignee="alice@example.com",
        source="manual",
        summary="Multiple failures",
        ip="10.0.0.5",
        user_entity="bob",
        db_path=db_path,
    )
    assert c1["id"] >= 1
    assert c1["status"] == "open"
    assert c1["severity"] == "high"
    assert c1["assignee"] == "alice@example.com"

    c2 = db.create_case(
        title="Phish click",
        severity="medium",
        status="investigating",
        assignee="carol",
        db_path=db_path,
    )
    assert c2["status"] == "investigating"

    all_cases = db.list_cases(status="all", db_path=db_path)
    assert len(all_cases) == 2
    open_only = db.list_cases(status="open", db_path=db_path)
    assert len(open_only) == 1
    assert open_only[0]["title"] == "Brute force on vpn"

    counts = db.counts_by_status(db_path=db_path)
    assert counts["open"] == 1
    assert counts["investigating"] == 1
    assert counts["contained"] == 0
    assert counts["closed"] == 0
    assert counts["total"] == 2


def test_create_from_triage_event(tmp_path, monkeypatch):
    db_path = _temp_db(tmp_path, monkeypatch)
    eid = db.insert_triage_event(
        {
            "timestamp": "2026-09-17T12:00:00",
            "log": "suspicious login from 203.0.113.9 for user dave",
            "severity": "critical",
            "user": "dave",
            "ip": "203.0.113.9",
            "rule_based": "escalate",
        },
        db_path=db_path,
        source="test",
    )
    case = db.create_case(triage_event_id=eid, assignee="analyst1", db_path=db_path)
    assert case["triage_event_id"] == eid
    assert case["source"] == "triage"
    assert case["severity"] == "critical"
    assert case["ip"] == "203.0.113.9"
    assert case["user_entity"] == "dave"
    assert "suspicious login" in (case["summary"] or "")
    assert case["title"]


def test_add_note_and_update_status(tmp_path, monkeypatch):
    db_path = _temp_db(tmp_path, monkeypatch)
    case = db.create_case(title="Malware beacon", severity="high", db_path=db_path)
    cid = case["id"]

    note = db.add_note(cid, "Checked EDR — host isolated", author="allan", db_path=db_path)
    assert note["case_id"] == cid
    assert "EDR" in note["body"]
    assert note["author"] == "allan"

    updated = db.update_case_status(
        cid,
        "investigating",
        assignee="allan",
        db_path=db_path,
    )
    assert updated["status"] == "investigating"
    assert updated["assignee"] == "allan"

    closed = db.update_case_status(
        cid,
        "closed",
        resolution_notes="False positive after deeper review",
        db_path=db_path,
    )
    assert closed["status"] == "closed"
    assert "False positive" in (closed["resolution_notes"] or "")

    full = db.get_case(cid, include_notes=True, db_path=db_path)
    assert full is not None
    assert len(full["notes"]) == 1
    assert full["notes"][0]["body"].startswith("Checked EDR")
    assert full["status"] == "closed"

    counts = db.counts_by_status(db_path=db_path)
    assert counts["closed"] == 1
    assert counts["open"] == 0


def test_invalid_status_and_missing_case(tmp_path, monkeypatch):
    db_path = _temp_db(tmp_path, monkeypatch)
    try:
        db.create_case(title="x", status="nope", db_path=db_path)
        assert False, "expected ValueError"
    except ValueError:
        pass

    case = db.create_case(title="y", db_path=db_path)
    try:
        db.update_case_status(case["id"], "bogus", db_path=db_path)
        assert False, "expected ValueError"
    except ValueError:
        pass

    try:
        db.add_note(99999, "ghost", db_path=db_path)
        assert False, "expected KeyError"
    except KeyError:
        pass

    assert db.get_case(99999, db_path=db_path) is None
