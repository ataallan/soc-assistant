"""Runtime suppresses, mutes, buckets, and the permanent-suppress gate."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from detection.allowlists import clear_allowlist_cache, load_allowlists, match
from detection.buckets import bucket_for_event, most_specific
from detection.suppressions import (
    clear_suppress_cache,
    create_mute,
    create_permanent,
    decorate_fp_rows,
    dismiss_draft,
    list_panel,
    match_scoped,
    record_mark,
    remove_mute,
    remove_suppress,
)


@pytest.fixture()
def runtime(tmp_path, monkeypatch):
    path = tmp_path / "allowlists_runtime.yml"
    monkeypatch.setenv("FP_RUNTIME_ALLOWLIST_PATH", str(path))
    monkeypatch.setenv("FP_SUPPRESS_GATE", "2")
    monkeypatch.setenv("FP_DRAFT_MIN_COUNT", "5")
    monkeypatch.setenv("FP_DRAFT_MIN_PCT", "80")
    clear_suppress_cache()
    clear_allowlist_cache()
    yield path
    clear_suppress_cache()
    clear_allowlist_cache()


def _row(**extra):
    base = {
        "rule_key": "2902",
        "bucket_key": "r:2902|h:web01|u:alice",
        "host": "web01",
        "user": "alice",
        "fingerprint": "",
        "ip": "",
        "dimension": "user",
        "dimension_value": "alice",
        "summary": "User alice",
        "count": 6,
        "low_ignore_count": 6,
        "pct_low_ignore": 100.0,
        "sample_log": "dpkg install foo",
        "sample_event_id": "9",
        "entire_rule_ok": True,
    }
    base.update(extra)
    return base


def test_most_specific_never_invents_a_missing_field():
    event = {"matched_rule_id": "2902", "host": "Web01", "user": "Alice", "log": "dpkg"}
    proposal = bucket_for_event(event)
    assert proposal["dimension"] == "user"
    assert proposal["ip"] == ""
    assert proposal["bucket_key"] == "r:2902|h:web01|u:alice"
    assert most_specific(ip="", user="", host="", rule_key="unknown") == ("log", "")


def test_mute_expires_and_bucket_does_not_cover_other_host(runtime):
    created = create_mute(
        rule_key="5710",
        host="web01",
        user="alice",
        hours=1,
        actor="analyst@example.com",
        sample="failed password",
    )
    assert created["ok"] is True
    assert "Muted until" in created["message"]
    web = {"rule_id": "5710", "host": "web01", "user": "alice", "raw_message": "failed password"}
    other = {"rule_id": "5710", "host": "db01", "user": "alice", "raw_message": "failed password"}
    start = datetime.now(timezone.utc)
    assert match_scoped(web, now=start)["matched"] is True
    assert match_scoped(web, now=start)["kind"] == "mute"
    assert match_scoped(other, now=start)["matched"] is False
    later = start + timedelta(hours=2)
    assert match_scoped(web, now=later)["matched"] is False
    panel = list_panel(now=later)
    assert panel["mutes"] == []
    assert list_panel(now=start)["mutes"][0]["expires_label"]


def test_unmute_and_remove(runtime):
    muted = create_mute(rule_key="5710", host="web01", user="alice", hours=24, actor="analyst@example.com")
    assert remove_mute(muted["id"])["ok"] is True
    assert match_scoped({"rule_id": "5710", "host": "web01", "user": "alice", "raw_message": "x"})["matched"] is False

    saved = create_permanent(
        rule_key="5710",
        host="web01",
        user="alice",
        scope="bucket",
        actor="admin@example.com",
        can_confirm=True,
        confirmed=True,
    )
    assert saved["ok"] is True
    assert match_scoped({"rule_id": "5710", "host": "web01", "user": "alice", "raw_message": "x"})["kind"] == "suppress"
    assert remove_suppress(saved["id"])["message"] == "Removed."
    assert match_scoped({"rule_id": "5710", "host": "web01", "user": "alice", "raw_message": "x"})["matched"] is False


def test_gate_requires_two_analysts_or_admin_confirm(runtime):
    kwargs = dict(rule_key="5710", host="web01", user="alice", scope="bucket", sample="noise")
    blocked = create_permanent(actor="analyst@example.com", can_confirm=False, confirmed=True, **kwargs)
    assert blocked["ok"] is False
    assert blocked["reason"] == "needs_confirmation"
    assert match_scoped({"rule_id": "5710", "host": "web01", "user": "alice", "raw_message": "noise"})["matched"] is False

    marked = record_mark(
        actor="second@example.com",
        event_id="2",
        rule_key=kwargs["rule_key"],
        host=kwargs["host"],
        user=kwargs["user"],
        sample=kwargs["sample"],
    )
    assert marked["mark_count"] == 2
    opened = create_permanent(actor="analyst@example.com", can_confirm=False, confirmed=False, **kwargs)
    assert opened["ok"] is True
    assert opened["message"] == "Suppressed."


def test_analyst_mute_skips_gate_and_entire_rule_is_explicit(runtime):
    muted = create_mute(rule_key="5710", host="web01", user="alice", scope="rule", hours=24, actor="analyst@example.com")
    assert muted["ok"] is True
    assert match_scoped({"rule_id": "5710", "host": "db01", "user": "bob", "raw_message": "x"})["matched"] is True
    bucket_only = {"rule_id": "5712", "host": "web01", "user": "alice", "raw_message": "x"}
    assert match_scoped(bucket_only)["matched"] is False

    denied = create_permanent(
        rule_key="5712",
        host="web01",
        user="alice",
        scope="rule",
        actor="analyst@example.com",
        can_confirm=False,
        confirmed=False,
    )
    assert denied["ok"] is False
    confirmed = create_permanent(
        rule_key="5712",
        host="web01",
        user="alice",
        scope="rule",
        actor="admin@example.com",
        can_confirm=True,
        confirmed=True,
    )
    assert confirmed["ok"] is True
    assert match_scoped({"rule_id": "5712", "host": "other", "user": "zoe", "raw_message": "x"})["matched"] is True


def test_runtime_ip_merges_and_reloads_without_restart(runtime):
    saved = create_permanent(
        rule_key="5710",
        host="web01",
        user="alice",
        ip="203.0.113.77",
        scope="ip",
        actor="admin@example.com",
        can_confirm=True,
        confirmed=True,
    )
    assert saved["ok"] is True
    clear_allowlist_cache()
    hit = match({"src_ip": "203.0.113.77"})
    miss = match({"src_ip": "198.51.100.8"})
    assert hit["matched"] is True
    assert miss["matched"] is False

    # External edit is picked up from mtime without clearing the suppress cache.
    doc = yaml.safe_load(runtime.read_text(encoding="utf-8"))
    doc["suppresses"].append(
        {
            "id": "hand",
            "scope": "bucket",
            "value": "r:5718|h:lab|u:root",
            "bucket_key": "r:5718|h:lab|u:root",
            "rule_key": "5718",
            "host": "lab",
            "user": "root",
            "created_by": "hand",
            "created_at": "2026-09-22T00:00:00+00:00",
        }
    )
    runtime.write_text(yaml.safe_dump(doc), encoding="utf-8")
    future = datetime.now(timezone.utc).timestamp() + 10
    os.utime(runtime, (future, future))
    assert match_scoped({"rule_id": "5718", "host": "lab", "user": "root", "raw_message": "x"})["matched"] is True
    loaded = load_allowlists(force_reload=True)
    assert "203.0.113.77" in loaded["ips"]


def test_draft_hides_while_muted_and_returns_after_expiry(runtime):
    row = _row()
    shown = decorate_fp_rows([row])
    assert shown[0]["draft"] is True
    assert shown[0]["summary"] == "User alice"

    create_mute(rule_key="2902", host="web01", user="alice", hours=1, actor="analyst@example.com")
    hidden = decorate_fp_rows([row])
    assert hidden[0]["draft"] is False
    assert hidden[0]["covered_label"].startswith("Muted until")

    later = datetime.now(timezone.utc) + timedelta(hours=3)
    again = decorate_fp_rows([row], now=later)
    assert again[0]["draft"] is True

    dismiss_draft(rule_key="2902", host="web01", user="alice", actor="analyst@example.com")
    dismissed = decorate_fp_rows([row], now=later)
    assert dismissed[0]["draft"] is False
    assert dismissed[0]["dismissed"] is True


def test_pipeline_bucket_mute_and_ml_cannot_raise_severity(runtime, monkeypatch):
    monkeypatch.setenv("ML_ASSIST_ONLY", "false")
    monkeypatch.setenv("ML_CONFIDENCE_THRESHOLD", "0.70")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    def fake_analyze(*_args, **_kwargs):
        return {
            "severity": "critical",
            "rule_severity": "low",
            "recommendation": "ignore",
            "ml_severity": "critical",
            "ml_confidence": 0.99,
            "severity_source": "ml",
            "ml_assist": False,
            "ip": "198.51.100.40",
            "user": "alice",
        }

    monkeypatch.setattr("triage_engine.analyze_log", fake_analyze)
    from detection.pipeline import process_alert

    alert = {
        "rule_id": "5710",
        "host": "web01",
        "user": "alice",
        "source_ip": "198.51.100.40",
        "description": "User opened a ticket about printer jam",
    }
    before = process_alert(alert)
    assert before["severity"] == "critical"
    assert before["ml_used_for_display"] is True
    assert before["muted"] is False

    bucket = before["suppress_bucket"]
    create_mute(
        rule_key=bucket["rule_key"],
        host=bucket["host"],
        user=bucket["user"],
        fingerprint=bucket["fingerprint"],
        hours=24,
        actor="analyst@example.com",
    )
    muted = process_alert(alert)
    assert muted["severity"] == "low"
    assert muted["recommendation"] == "ignore"
    assert muted["severity_source"] == "mute"
    assert muted["muted"] is True
    assert muted["ml_used_for_display"] is False
    assert muted["ml_assist"] is True
    assert muted["ml_severity"] == "critical"

    other = process_alert({**alert, "host": "db01"})
    assert other["muted"] is False
    assert other["severity"] == "critical"

    create_permanent(
        rule_key=bucket["rule_key"],
        host="db01",
        user=bucket["user"],
        scope="rule",
        actor="admin@example.com",
        can_confirm=True,
        confirmed=True,
    )
    entire = process_alert({**alert, "host": "files01"})
    assert entire["severity"] == "low"
    assert entire["allowlisted"] is True
    assert entire["ml_used_for_display"] is False
    assert entire["severity_source"] == "allowlist"
