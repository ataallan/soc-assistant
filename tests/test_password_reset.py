"""Forgot-password and reset-password flow."""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from werkzeug.security import check_password_hash, generate_password_hash


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "reset_soc.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.delenv("SOC_ADMIN_EMAILS", raising=False)
    monkeypatch.delenv("SOC_EMAIL_2FA", raising=False)
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    monkeypatch.delenv("SOC_AUTH_SHOW_RESET_URL", raising=False)
    monkeypatch.setenv("MAIL_USERNAME", "")
    monkeypatch.setenv("MAIL_PASSWORD", "")
    monkeypatch.setenv("SOC_USERS_FILE", str(tmp_path / "users.csv"))
    monkeypatch.setenv("CONTAINMENT_MODE", "simulated")
    monkeypatch.setenv("SOC_RESET_IP_LIMIT", "30")

    import db

    db.reset_connection()
    db.init_db(db_path)

    import importlib
    import dashboard

    importlib.reload(dashboard)
    dashboard.app.config["TESTING"] = True
    dashboard.app.config["WTF_CSRF_ENABLED"] = False
    return dashboard.app.test_client(), dashboard


def _token_from(body: str) -> str:
    match = re.search(r"/reset-password\?token=([A-Za-z0-9_\-]+)", body)
    assert match, body
    return match.group(1)


def _register_admin(http, email="admin@example.com", password="correct-horse"):
    resp = http.post("/register", data={"username": email, "password": password})
    assert resp.status_code in (200, 302)
    return email, password


def test_login_links_to_forgot_password(client):
    http, _ = client
    body = http.get("/login").get_data(as_text=True)
    assert "Forgot password?" in body
    assert 'href="/forgot-password"' in body
    page = http.get("/forgot-password")
    assert page.status_code == 200
    assert "Forgot password" in page.get_data(as_text=True)
    assert 'type="password"' not in page.get_data(as_text=True)


def test_forgot_password_stays_public_for_half_session(client):
    http, dashboard = client
    _register_admin(http)
    with http.session_transaction() as sess:
        dashboard.stamp_auth_session(
            sess,
            "admin@example.com",
            role="admin",
            email_2fa_ok=False,
        )

    page = http.get("/forgot-password", follow_redirects=False)
    assert page.status_code == 200
    blocked = http.get("/", follow_redirects=False)
    assert blocked.status_code == 302
    assert "/login" in (blocked.headers.get("Location") or "")


def test_unknown_and_pending_get_the_same_neutral_response(client, monkeypatch):
    http, _ = client
    monkeypatch.setenv("SOC_AUTH_SHOW_RESET_URL", "1")
    _register_admin(http)
    http.post("/register", data={"username": "analyst@example.com", "password": "another-pass"})

    unknown = http.post(
        "/forgot-password",
        data={"username": "nobody@example.com"},
    ).get_data(as_text=True)
    pending = http.post(
        "/forgot-password",
        data={"username": "analyst@example.com"},
    ).get_data(as_text=True)

    for body in (unknown, pending):
        assert "Email delivery is not configured" in body
        assert "email sent" not in body.lower()
        assert "reset-password?token=" not in body
        assert "does not exist" not in body.lower()
        assert "no account" not in body.lower()
        assert "pending" not in body.lower()

    from accounts import get_account

    analyst = get_account("analyst@example.com")
    assert not analyst["reset_token_hash"]
    assert get_account("nobody@example.com") is None


def test_inactive_account_does_not_get_a_token(client, monkeypatch):
    http, _ = client
    monkeypatch.setenv("SOC_AUTH_SHOW_RESET_URL", "1")
    _register_admin(http)
    http.post("/register", data={"username": "analyst@example.com", "password": "another-pass"})

    import accounts as accounts_mod

    with accounts_mod._lock:
        accounts = accounts_mod._load_unlocked()
        accounts["analyst@example.com"]["approved"] = False
        accounts["analyst@example.com"]["status"] = "inactive"
        accounts_mod._save_unlocked(accounts)

    body = http.post(
        "/forgot-password",
        data={"username": "analyst@example.com"},
    ).get_data(as_text=True)
    assert "reset-password?token=" not in body
    assert not accounts_mod.get_account("analyst@example.com")["reset_token_hash"]


def test_eligible_account_gets_hashed_token_and_logs_url(client, monkeypatch, capsys):
    http, dashboard = client
    monkeypatch.setenv("SOC_AUTH_SHOW_RESET_URL", "1")
    _register_admin(http)

    body = http.post(
        "/forgot-password",
        data={"username": "Admin@Example.com"},
    ).get_data(as_text=True)
    assert "Email delivery is not configured" in body
    assert "email sent" not in body.lower()
    assert "A one-time reset link is shown below." in body
    token = _token_from(body)

    from accounts import get_account

    account = get_account("admin@example.com")
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert account["reset_token_hash"] == digest
    users = Path(dashboard.os.environ["SOC_USERS_FILE"]).read_text(encoding="utf-8")
    assert token not in users
    assert digest in users
    assert float(account["reset_expires"]) > time.time() + 40 * 60
    logged = capsys.readouterr().out
    assert f"reset-password?token={token}" in logged

    hidden = http.post(
        "/forgot-password",
        data={"username": "admin@example.com"},
    )
    # Identity throttle: no second token, and the flag cannot reveal a new URL.
    again = hidden.get_data(as_text=True)
    assert "reset-password?token=" not in again
    assert get_account("admin@example.com")["reset_token_hash"] == digest


def test_flag_off_does_not_print_url_on_the_page(client):
    http, _ = client
    _register_admin(http)
    body = http.post(
        "/forgot-password",
        data={"username": "admin@example.com"},
    ).get_data(as_text=True)
    assert "Email delivery is not configured" in body
    assert "reset-password?token=" not in body


def test_configured_mail_uses_neutral_success_and_hides_url(client, monkeypatch):
    http, dashboard = client
    monkeypatch.setenv("RESEND_API_KEY", "test-key")
    monkeypatch.setenv("SOC_AUTH_SHOW_RESET_URL", "1")
    _register_admin(http)
    with patch.object(dashboard, "deliver_reset_email", return_value="sent") as mock_send:
        body = http.post(
            "/forgot-password",
            data={"username": "admin@example.com"},
        ).get_data(as_text=True)
    mock_send.assert_called_once()
    assert "instructions will arrive shortly" in body
    assert "Email delivery is not configured" not in body
    assert "reset-password?token=" not in body
    assert "email sent" not in body.lower()


def test_mail_failure_does_not_claim_the_email_was_sent(client, monkeypatch):
    http, dashboard = client
    monkeypatch.setenv("RESEND_API_KEY", "test-key")
    _register_admin(http)
    with patch.object(dashboard, "deliver_reset_email", return_value="failed"):
        body = http.post(
            "/forgot-password",
            data={"username": "admin@example.com"},
        ).get_data(as_text=True)
    assert "Email delivery failed" in body
    assert "was not sent" in body
    assert "instructions will arrive shortly" not in body
    assert "email sent" not in body.lower()


def test_unknown_with_mail_configured_stays_neutral(client, monkeypatch):
    http, dashboard = client
    monkeypatch.setenv("RESEND_API_KEY", "test-key")
    with patch.object(dashboard, "deliver_reset_email") as mock_send:
        body = http.post(
            "/forgot-password",
            data={"username": "nobody@example.com"},
        ).get_data(as_text=True)
    mock_send.assert_not_called()
    assert "instructions will arrive shortly" in body
    assert "reset-password?token=" not in body


def test_identity_throttle_does_not_send_again(client, monkeypatch):
    http, dashboard = client
    monkeypatch.setenv("RESEND_API_KEY", "test-key")
    monkeypatch.setenv("SOC_RESET_MIN_INTERVAL_SECONDS", "60")
    _register_admin(http)
    with patch.object(dashboard, "deliver_reset_email", return_value="sent") as mock_send:
        first = http.post("/forgot-password", data={"username": "admin@example.com"})
        second = http.post("/forgot-password", data={"username": "admin@example.com"})
    assert mock_send.call_count == 1
    assert "instructions will arrive shortly" in first.get_data(as_text=True)
    assert "instructions will arrive shortly" in second.get_data(as_text=True)


def test_ip_throttle_blocks_further_mail(client, monkeypatch):
    http, dashboard = client
    monkeypatch.setenv("RESEND_API_KEY", "test-key")
    monkeypatch.setenv("SOC_RESET_IP_LIMIT", "1")
    _register_admin(http)
    with patch.object(dashboard, "deliver_reset_email", return_value="sent") as mock_send:
        http.post("/forgot-password", data={"username": "admin@example.com"})
        blocked = http.post("/forgot-password", data={"username": "other@example.com"})
    assert mock_send.call_count == 1
    body = blocked.get_data(as_text=True)
    assert "Please wait a few minutes" in body
    assert "instructions will arrive shortly" not in body


def test_expired_and_invalid_tokens_are_rejected(client, monkeypatch):
    http, _ = client
    monkeypatch.setenv("SOC_AUTH_SHOW_RESET_URL", "1")
    _register_admin(http)
    body = http.post(
        "/forgot-password",
        data={"username": "admin@example.com"},
    ).get_data(as_text=True)
    token = _token_from(body)

    invalid = http.get("/reset-password?token=not-a-real-token", follow_redirects=True)
    assert "invalid or has expired" in invalid.get_data(as_text=True)

    import accounts as accounts_mod

    with accounts_mod._lock:
        accounts = accounts_mod._load_unlocked()
        accounts["admin@example.com"]["reset_expires"] = str(int(time.time()) - 30)
        accounts_mod._save_unlocked(accounts)

    expired = http.get(f"/reset-password?token={token}", follow_redirects=True)
    assert "invalid or has expired" in expired.get_data(as_text=True)


def test_reset_updates_hash_clears_token_and_still_requires_2fa(client, monkeypatch):
    http, dashboard = client
    monkeypatch.setenv("SOC_AUTH_SHOW_RESET_URL", "1")
    email, old_password = _register_admin(http)
    body = http.post("/forgot-password", data={"username": email}).get_data(as_text=True)
    token = _token_from(body)

    from accounts import get_account

    before = get_account(email)
    short = http.post(
        "/reset-password",
        data={"token": token, "password": "short", "confirm_password": "short"},
    )
    assert "at least 8 characters" in short.get_data(as_text=True)
    mismatch = http.post(
        "/reset-password",
        data={"token": token, "password": "new-password-1", "confirm_password": "new-password-2"},
    )
    assert "do not match" in mismatch.get_data(as_text=True)
    assert get_account(email)["password_hash"] == before["password_hash"]
    assert get_account(email)["reset_token_hash"] == before["reset_token_hash"]

    page = http.get(f"/reset-password?token={token}").get_data(as_text=True)
    assert 'data-toggle-password="reset-password"' in page
    assert 'data-toggle-password="reset-confirm"' in page
    assert "Show password" in page
    assert "Show confirm password" in page
    assert "auth.js" in page
    assert email in page

    updated = http.post(
        "/reset-password",
        data={"token": token, "password": "new-password-1", "confirm_password": "new-password-1"},
        follow_redirects=True,
    )
    assert "Password updated" in updated.get_data(as_text=True)
    with http.session_transaction() as sess:
        assert "user" not in sess
        assert not sess.get("email_2fa_ok")

    account = get_account(email)
    assert account["password_hash"] != before["password_hash"]
    assert check_password_hash(account["password_hash"], "new-password-1")
    assert not account["reset_token_hash"]
    assert account["approved"] is True
    assert account["status"] == "active"
    assert account["two_factor"] is True
    assert account["role"] == "admin"

    reused = http.post(
        "/reset-password",
        data={"token": token, "password": "other-password", "confirm_password": "other-password"},
        follow_redirects=True,
    )
    assert "invalid or has expired" in reused.get_data(as_text=True)
    assert check_password_hash(get_account(email)["password_hash"], "new-password-1")

    bad = http.post("/login", data={"username": email, "password": old_password})
    assert "Invalid username or password" in bad.get_data(as_text=True)

    with patch.object(dashboard, "deliver_otp", return_value=True):
        resp = http.post(
            "/login",
            data={"username": email, "password": "new-password-1"},
            follow_redirects=False,
        )
    assert resp.status_code == 302
    assert "/2fa" in (resp.headers.get("Location") or "")
    with http.session_transaction() as sess:
        assert "user" not in sess
        assert not sess.get("email_2fa_ok")
        code = sess.get("otp")
    blocked = http.get("/", follow_redirects=False)
    assert "/2fa" in (blocked.headers.get("Location") or "")
    ok = http.post("/2fa", data={"code": code}, follow_redirects=False)
    assert (ok.headers.get("Location") or "").endswith("/")
    with http.session_transaction() as sess:
        assert sess["email_2fa_ok"] is True
    assert http.get("/").status_code == 200


def test_planted_token_on_pending_account_cannot_open_console(client):
    http, _ = client
    _register_admin(http)
    http.post("/register", data={"username": "analyst@example.com", "password": "another-pass"})

    import accounts as accounts_mod

    token = "planted-token-value"
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with accounts_mod._lock:
        accounts = accounts_mod._load_unlocked()
        accounts["analyst@example.com"]["reset_token_hash"] = digest
        accounts["analyst@example.com"]["reset_expires"] = str(int(time.time()) + 3600)
        accounts_mod._save_unlocked(accounts)

    page = http.get(f"/reset-password?token={token}", follow_redirects=True)
    assert "invalid or has expired" in page.get_data(as_text=True)
    posted = http.post(
        "/reset-password",
        data={"token": token, "password": "new-password-1", "confirm_password": "new-password-1"},
        follow_redirects=False,
    )
    assert "/forgot-password" in (posted.headers.get("Location") or "")
    analyst = accounts_mod.get_account("analyst@example.com")
    assert analyst["status"] == "pending"
    assert analyst["approved"] is False
    assert check_password_hash(analyst["password_hash"], "another-pass")

    login = http.post(
        "/login",
        data={"username": "analyst@example.com", "password": "another-pass"},
        follow_redirects=False,
    )
    assert "/pending" in (login.headers.get("Location") or "")
    home = http.get("/", follow_redirects=False)
    assert "/pending" in (home.headers.get("Location") or "")


def test_deactivate_clears_an_outstanding_token(client, monkeypatch):
    http, _ = client
    monkeypatch.setenv("SOC_AUTH_SHOW_RESET_URL", "1")
    _register_admin(http)
    http.post("/register", data={"username": "analyst@example.com", "password": "another-pass"})

    from accounts import apply_account_action, get_account

    assert apply_account_action("admin@example.com", "approve", "analyst@example.com")[0] is True
    body = http.post(
        "/forgot-password",
        data={"username": "analyst@example.com"},
    ).get_data(as_text=True)
    token = _token_from(body)
    assert get_account("analyst@example.com")["reset_token_hash"]

    ok, _message = apply_account_action("admin@example.com", "deactivate", "analyst@example.com")
    assert ok is True
    assert not get_account("analyst@example.com")["reset_token_hash"]
    page = http.get(f"/reset-password?token={token}", follow_redirects=True)
    assert "invalid or has expired" in page.get_data(as_text=True)


def test_legacy_csv_gains_reset_columns_on_write(tmp_path, monkeypatch):
    path = tmp_path / "legacy.csv"
    password_hash = generate_password_hash("correct-horse")
    path.write_text(
        "username,password_hash,role,approved,status,two_factor\n"
        f"admin@example.com,{password_hash},admin,true,active,true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SOC_USERS_FILE", str(path))
    from accounts import get_account, issue_reset_token

    status, token = issue_reset_token("admin@example.com", ttl_minutes=45, min_interval_seconds=0)
    assert status == "issued"
    assert token
    header = path.read_text(encoding="utf-8").splitlines()[0]
    assert "reset_token_hash" in header
    assert "reset_expires" in header
    account = get_account("admin@example.com")
    assert account["role"] == "admin"
    assert account["approved"] is True
    assert account["reset_token_hash"] == hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert token not in path.read_text(encoding="utf-8")
