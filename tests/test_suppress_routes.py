"""Dashboard routes for suppress, mute, and FP-review drafts."""

from __future__ import annotations

import importlib

import pytest

import db


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "suppress.db"
    runtime = tmp_path / "allowlists_runtime.yml"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv("SOC_USERS_FILE", str(tmp_path / "users.csv"))
    monkeypatch.setenv("SOC_ADMIN_EMAILS", "admin@example.com")
    monkeypatch.setenv("SOC_DEVELOPER_EMAILS", "dev@example.com")
    monkeypatch.setenv("SOC_DEV_TRAINING", "false")
    monkeypatch.setenv("FP_RUNTIME_ALLOWLIST_PATH", str(runtime))
    monkeypatch.setenv("FP_SUPPRESS_GATE", "2")
    monkeypatch.setenv("FP_DRAFT_MIN_COUNT", "2")
    monkeypatch.setenv("FP_DRAFT_MIN_PCT", "80")
    db.reset_connection()
    db.init_db(db_path)
    import dashboard

    importlib.reload(dashboard)
    dashboard.app.config["TESTING"] = True
    dashboard.app.config["WTF_CSRF_ENABLED"] = False
    from detection.allowlists import clear_allowlist_cache
    from detection.suppressions import clear_suppress_cache

    clear_suppress_cache()
    clear_allowlist_cache()
    return dashboard.app.test_client()


def _login(client, user):
    with client.session_transaction() as sess:
        sess["user"] = user
        sess["email_2fa_ok"] = True


def _headers():
    return {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}


def _seed_buckets():
    for host, count in (("web01", 3), ("db01", 1)):
        for _ in range(count):
            db.insert_triage_event(
                {
                    "timestamp": "2026-09-22T12:00:00+00:00",
                    "log": f"dpkg: status installed foo on {host}",
                    "severity": "low",
                    "rule_based": "ignore",
                    "user": "alice",
                    "host": host,
                    "ip": "203.0.113.10",
                    "matched_rule_id": "2902",
                },
                source="test",
            )


def test_mute_and_gate_routes(client):
    anon = client.post("/fp/mute", data={"rule_key": "5710", "host": "web01", "user": "alice", "hours": "24"})
    assert anon.status_code in (302, 401)
    assert "/login" in (anon.headers.get("Location") or "")

    _login(client, "analyst@example.com")
    muted = client.post(
        "/fp/mute",
        data={"rule_key": "5710", "host": "web01", "user": "alice", "hours": "24", "next": "/fp-review"},
        headers=_headers(),
    )
    assert muted.status_code == 200
    body = muted.get_json()
    assert body["ok"] is True
    assert "Muted until" in body["message"]

    denied = client.post(
        "/fp/suppress",
        data={
            "rule_key": "5710",
            "host": "db01",
            "user": "alice",
            "scope": "bucket",
            "admin_confirm": "yes",
        },
        headers=_headers(),
    )
    assert denied.status_code == 400
    assert denied.get_json()["reason"] == "needs_confirmation"

    _login(client, "lead@example.com")
    marked = client.post(
        "/fp/mark",
        data={"rule_key": "5710", "host": "db01", "user": "alice", "event_id": "4"},
        headers=_headers(),
    )
    assert marked.status_code == 200
    assert marked.get_json()["mark_count"] == 2

    _login(client, "analyst@example.com")
    saved = client.post(
        "/fp/suppress",
        data={"rule_key": "5710", "host": "db01", "user": "alice", "scope": "rule"},
        headers=_headers(),
    )
    assert saved.status_code == 200
    assert saved.get_json()["message"] == "Suppressed."

    _login(client, "admin@example.com")
    confirmed = client.post(
        "/fp/suppress",
        data={
            "rule_key": "5800",
            "host": "web01",
            "user": "root",
            "scope": "bucket",
            "admin_confirm": "yes",
        },
        headers=_headers(),
    )
    assert confirmed.status_code == 200
    assert confirmed.get_json()["ok"] is True


def test_fp_review_shows_buckets_and_draft_accept(client):
    _seed_buckets()
    _login(client, "analyst@example.com")
    page = client.get("/fp-review")
    assert page.status_code == 200
    html = page.data.decode("utf-8")
    assert "r:2902|h:web01|u:alice" in html
    assert "r:2902|h:db01|u:alice" in html
    assert "Accept" in html
    assert "Dismiss" in html
    assert "Mute 24h" in html
    assert "Needs confirmation" in html
    assert "Enqueue" not in html
    assert "Active suppresses" in html
    for phrase in ("allowlists.yml", "How it works", "confirm=1", "Phase 3"):
        assert phrase not in html

    _login(client, "dev@example.com")
    dev = client.get("/fp-review")
    dev_html = dev.data.decode("utf-8")
    assert "Enqueue" in dev_html
    assert "Confirm permanent suppress" in dev_html

    _login(client, "analyst@example.com")
    report = client.get("/report")
    report_html = report.data.decode("utf-8")
    assert "Suppress similar" in report_html
    assert "Mute 7d" in report_html
    assert "r:2902|h:web01|u:alice" in report_html
    assert 'href="/labels"' not in report_html
