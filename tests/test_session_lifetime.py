"""Idle timeout, activity refresh, and build-epoch session invalidation."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "session_soc.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.delenv("SOC_ADMIN_EMAILS", raising=False)
    monkeypatch.delenv("SOC_EMAIL_2FA", raising=False)
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    monkeypatch.delenv("APP_SESSION_EPOCH", raising=False)
    monkeypatch.delenv("SESSION_IDLE_MINUTES", raising=False)
    monkeypatch.delenv("SESSION_HOURS", raising=False)
    monkeypatch.setenv("MAIL_USERNAME", "")
    monkeypatch.setenv("MAIL_PASSWORD", "")
    monkeypatch.setenv("SOC_USERS_FILE", str(tmp_path / "users.csv"))
    monkeypatch.setenv("CONTAINMENT_MODE", "simulated")

    import db

    db.reset_connection()
    db.init_db(db_path)

    import importlib
    import dashboard

    importlib.reload(dashboard)
    dashboard.app.config["TESTING"] = True
    dashboard.app.config["WTF_CSRF_ENABLED"] = False
    return dashboard.app.test_client(), dashboard


def _plant(http, dashboard, user="ops@example.com", **extra):
    with http.session_transaction() as sess:
        dashboard.stamp_auth_session(sess, user, **extra)


def _age(http, seconds: float) -> None:
    with http.session_transaction() as sess:
        sess["last_activity"] = time.time() - seconds


def test_current_epoch_prefers_env_over_version_file(client, monkeypatch):
    _, dashboard = client
    monkeypatch.delenv("APP_SESSION_EPOCH", raising=False)
    assert dashboard.current_session_epoch() == (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    monkeypatch.setenv("APP_SESSION_EPOCH", "capstone-build")
    assert dashboard.current_session_epoch() == "capstone-build"


def test_activity_inside_15_minutes_refreshes_and_keeps_the_session(client):
    http, dashboard = client
    _plant(http, dashboard)
    stale = time.time() - (14 * 60)
    with http.session_transaction() as sess:
        sess["last_activity"] = stale

    resp = http.get(
        "/notifications",
        headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
    )
    assert resp.status_code == 200
    assert "blocked_count" in resp.get_json()
    with http.session_transaction() as sess:
        assert sess["user"] == "ops@example.com"
        assert sess["last_activity"] > stale + 60
        refreshed = sess["last_activity"]

    again = http.get("/health.json")
    assert again.status_code == 200
    with http.session_transaction() as sess:
        assert sess["last_activity"] >= refreshed
        assert sess["session_epoch"] == dashboard.current_session_epoch()


def test_idle_over_15_minutes_clears_auth_and_asks_for_sign_in(client):
    http, dashboard = client
    _plant(
        http,
        dashboard,
        email_2fa_ok=True,
        pending_user="leftover@example.com",
        otp="000111",
        role="analyst",
    )
    _age(http, 15 * 60 + 30)

    resp = http.get(
        "/notifications",
        headers={"X-Requested-With": "XMLHttpRequest"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/login" in (resp.headers.get("Location") or "")
    with http.session_transaction() as sess:
        for key in (
            "user",
            "role",
            "email_2fa_ok",
            "pending_user",
            "otp",
            "session_epoch",
            "last_activity",
            "session_started",
            "account_limited",
        ):
            assert not sess.get(key), key
        assert sess.get("login_notice") == "Sign in again to continue"

    page = http.get("/login")
    assert page.status_code == 200
    assert "Sign in again to continue" in page.get_data(as_text=True)
    with http.session_transaction() as sess:
        assert "login_notice" not in sess


def test_request_just_inside_the_idle_window_stays_signed_in(client):
    http, dashboard = client
    _plant(http, dashboard)
    _age(http, 15 * 60 - 30)
    resp = http.get("/health.json")
    assert resp.status_code == 200
    with http.session_transaction() as sess:
        assert sess["user"] == "ops@example.com"


def test_epoch_mismatch_and_missing_epoch_reject_the_cookie(client, monkeypatch):
    http, dashboard = client
    _plant(http, dashboard, email_2fa_ok=True)
    with http.session_transaction() as sess:
        sess["session_epoch"] = "older-build"
        sess["last_activity"] = time.time()

    resp = http.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in (resp.headers.get("Location") or "")
    with http.session_transaction() as sess:
        assert "user" not in sess
        assert "email_2fa_ok" not in sess

    # Cookie from a build that did not stamp an epoch.
    with http.session_transaction() as sess:
        sess.clear()
        sess["user"] = "ops@example.com"
        sess["email_2fa_ok"] = True
        sess["last_activity"] = time.time()
        sess["session_started"] = time.time()
    resp = http.get("/health.json", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in (resp.headers.get("Location") or "")
    with http.session_transaction() as sess:
        assert "user" not in sess

    monkeypatch.setenv("APP_SESSION_EPOCH", "next-setup")
    _plant(http, dashboard, email_2fa_ok=True)
    with http.session_transaction() as sess:
        assert sess["session_epoch"] == "next-setup"
    assert http.get("/health.json").status_code == 200
    monkeypatch.setenv("APP_SESSION_EPOCH", "after-upgrade")
    blocked = http.get("/", follow_redirects=True)
    assert blocked.status_code == 200
    assert "Sign in again to continue" in blocked.get_data(as_text=True)
    with http.session_transaction() as sess:
        assert "user" not in sess


def test_idle_clears_pending_email_code_and_limited_account(client):
    http, dashboard = client
    http.post("/register", data={"username": "admin@example.com", "password": "correct-horse"})
    http.post("/register", data={"username": "analyst@example.com", "password": "another-pass"})

    with http.session_transaction() as sess:
        dashboard.stamp_auth_session(sess)
        sess.pop("user", None)
        sess["pending_user"] = "admin@example.com"
        sess["otp"] = "654321"
        sess["otp_time"] = time.time()
        sess["otp_emailed"] = False
        sess["otp_email_hint"] = "a***@example.com"
    _age(http, 16 * 60)
    resp = http.get("/2fa", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in (resp.headers.get("Location") or "")
    with http.session_transaction() as sess:
        assert "pending_user" not in sess
        assert "otp" not in sess
        assert "otp_time" not in sess
        assert "otp_email_hint" not in sess

    with patch.object(dashboard, "deliver_otp") as mock_send:
        pending = http.post(
            "/login",
            data={"username": "analyst@example.com", "password": "another-pass"},
            follow_redirects=False,
        )
    mock_send.assert_not_called()
    assert "/pending" in (pending.headers.get("Location") or "")
    _age(http, 16 * 60)
    blocked = http.get("/pending", follow_redirects=False)
    assert blocked.status_code == 302
    assert "/login" in (blocked.headers.get("Location") or "")
    with http.session_transaction() as sess:
        assert "user" not in sess
        assert not sess.get("account_limited")
        assert sess.get("login_notice") == "Sign in again to continue"


def test_epoch_change_still_requires_email_code_on_the_next_sign_in(client, monkeypatch):
    http, dashboard = client
    http.post("/register", data={"username": "admin@example.com", "password": "correct-horse"})
    with patch.object(dashboard, "deliver_otp", return_value=True) as mock_send:
        first = http.post(
            "/login",
            data={"username": "admin@example.com", "password": "correct-horse"},
            follow_redirects=False,
        )
    assert "/2fa" in (first.headers.get("Location") or "")
    with http.session_transaction() as sess:
        code = sess["otp"]
        assert sess.get("user") is None
        assert sess.get("session_epoch")
    ok = http.post("/2fa", data={"code": code}, follow_redirects=False)
    assert (ok.headers.get("Location") or "").endswith("/")
    assert http.get("/").status_code == 200
    with http.session_transaction() as sess:
        assert sess["email_2fa_ok"] is True
        assert sess["session_epoch"] == dashboard.current_session_epoch()

    monkeypatch.setenv("APP_SESSION_EPOCH", "capstone-build-2")
    page = http.get("/cases", follow_redirects=True)
    assert "Sign in again to continue" in page.get_data(as_text=True)

    with patch.object(dashboard, "deliver_otp", return_value=True) as mock_send:
        again = http.post(
            "/login",
            data={"username": "admin@example.com", "password": "correct-horse"},
            follow_redirects=False,
        )
    assert "/2fa" in (again.headers.get("Location") or "")
    mock_send.assert_called_once()
    with http.session_transaction() as sess:
        assert "user" not in sess
        code = sess["otp"]
    home = http.post("/2fa", data={"code": code}, follow_redirects=True)
    assert home.status_code == 200
    with http.session_transaction() as sess:
        assert sess["user"] == "admin@example.com"
        assert sess["email_2fa_ok"] is True
        assert sess["session_epoch"] == "capstone-build-2"


def test_absolute_session_hours_and_disable(client, monkeypatch):
    http, dashboard = client
    monkeypatch.setenv("SESSION_HOURS", "1")
    _plant(http, dashboard)
    with http.session_transaction() as sess:
        sess["session_started"] = time.time() - 3601
        sess["last_activity"] = time.time()
    resp = http.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in (resp.headers.get("Location") or "")

    monkeypatch.setenv("SESSION_HOURS", "0")
    _plant(http, dashboard)
    with http.session_transaction() as sess:
        sess["session_started"] = time.time() - (48 * 3600)
        sess["last_activity"] = time.time()
    assert http.get("/health.json").status_code == 200


def test_expired_cookie_does_not_block_a_new_login_post(client):
    http, dashboard = client
    http.post("/register", data={"username": "admin@example.com", "password": "correct-horse"})
    _plant(http, dashboard, user="admin@example.com", email_2fa_ok=True)
    _age(http, 16 * 60)
    with patch.object(dashboard, "deliver_otp", return_value=True):
        resp = http.post(
            "/login",
            data={"username": "admin@example.com", "password": "correct-horse"},
            follow_redirects=False,
        )
    assert resp.status_code == 302
    assert "/2fa" in (resp.headers.get("Location") or "")
    with http.session_transaction() as sess:
        assert sess.get("pending_user") == "admin@example.com"
        assert sess.get("login_notice") in (None, "")


def test_installer_session_epoch_changes_with_the_build_stamp():
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    import stage_installer_payload

    when = datetime(2026, 9, 23, 1, 2, 3, tzinfo=timezone.utc)
    assert stage_installer_payload.installer_session_epoch("1.0.0\n", when) == "1.0.0+20260923010203"
    assert stage_installer_payload.installer_session_epoch("", when) == "0+20260923010203"
