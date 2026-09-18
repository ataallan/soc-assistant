"""Unit tests for case SLA helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import sla


def test_default_sla_hours():
    m = sla.sla_hours_map()
    assert m["critical"] == 4
    assert m["high"] == 8
    assert m["medium"] == 24
    assert m["low"] == 72
    assert sla.hours_for_severity("critical") == 4
    assert sla.hours_for_severity("HIGH") == 8
    assert sla.hours_for_severity(None) == 24


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("SLA_HOURS_CRITICAL", "2")
    monkeypatch.setenv("SLA_HOURS_LOW", "100")
    assert sla.hours_for_severity("critical") == 2
    assert sla.hours_for_severity("low") == 100
    # invalid ignored
    monkeypatch.setenv("SLA_HOURS_HIGH", "nope")
    assert sla.hours_for_severity("high") == 8


def test_compute_due_at_from_created():
    created = datetime(2026, 9, 17, 12, 0, 0, tzinfo=timezone.utc)
    due = sla.compute_due_at("critical", created_at=created)
    parsed = datetime.fromisoformat(due)
    assert parsed == created + timedelta(hours=4)

    due_med = sla.compute_due_at("medium", created_at=created.isoformat())
    assert datetime.fromisoformat(due_med) == created + timedelta(hours=24)


def test_is_overdue_and_closed_exempt():
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(hours=5)).isoformat()
    assert sla.is_overdue({"due_at": past, "status": "open"}) is True
    assert sla.is_sla_breached({"due_at": past, "status": "investigating"}) is True
    assert sla.is_overdue({"due_at": past, "status": "closed"}) is False
    assert sla.is_overdue({"due_at": future, "status": "open"}) is False
    assert sla.is_overdue({"due_at": None, "status": "open"}) is False
