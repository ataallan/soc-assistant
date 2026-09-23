"""Account approval gate and email login-code flow."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest
from werkzeug.security import generate_password_hash


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "gate_soc.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.delenv("SOC_ADMIN_EMAILS", raising=False)
    monkeypatch.delenv("SOC_EMAIL_2FA", raising=False)
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
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


def _login_code(client, dashboard, email, password, *, emailed=True):
    with patch.object(dashboard, "deliver_otp", return_value=emailed) as mock_send:
        resp = client.post(
            "/login",
            data={"username": email, "password": password},
            follow_redirects=False,
        )
    assert resp.status_code == 302
    assert "/2fa" in (resp.headers.get("Location") or "")
    mock_send.assert_called_once()
    sent_user, sent_code = mock_send.call_args.args[:2]
    assert sent_user == email.strip().lower()
    assert len(sent_code) == 6 and sent_code.isdigit()
    with client.session_transaction() as sess:
        assert sess.get("user") is None
        assert sess.get("email_2fa_ok") in (None, False)
        assert sess.get("otp") == sent_code
    return sent_code


def test_no_seeded_default_account(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_USERS_FILE", str(tmp_path / "empty.csv"))
    from accounts import list_accounts

    assert list_accounts() == []
    source = Path("accounts.py").read_text(encoding="utf-8").lower()
    assert "changeme" not in source
    assert "operator/" not in source


def test_first_account_admin_later_pending(client):
    http, _ = client
    resp = http.post(
        "/register",
        data={"username": "Admin@Example.com", "password": "correct-horse"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "registered=admin" in (resp.headers.get("Location") or "")

    resp = http.post(
        "/register",
        data={"username": "analyst@example.com", "password": "another-pass"},
        follow_redirects=False,
    )
    assert "registered=pending" in (resp.headers.get("Location") or "")

    from accounts import get_account

    admin = get_account("admin@example.com")
    analyst = get_account("analyst@example.com")
    assert admin["role"] == "admin"
    assert admin["approved"] is True
    assert admin["status"] == "active"
    assert analyst["role"] == "analyst"
    assert analyst["approved"] is False
    assert analyst["status"] == "pending"


def test_pending_user_skips_otp_and_cannot_open_console(client):
    http, dashboard = client
    http.post("/register", data={"username": "admin@example.com", "password": "correct-horse"})
    http.post("/register", data={"username": "analyst@example.com", "password": "another-pass"})

    with patch.object(dashboard, "deliver_otp") as mock_send:
        resp = http.post(
            "/login",
            data={"username": "analyst@example.com", "password": "another-pass"},
            follow_redirects=False,
        )
    mock_send.assert_not_called()
    assert resp.status_code == 302
    assert "/pending" in (resp.headers.get("Location") or "")

    for path in ("/", "/health.json", "/notifications", "/cases"):
        blocked = http.get(path, follow_redirects=False)
        assert blocked.status_code == 302
        assert "/pending" in (blocked.headers.get("Location") or "")

    page = http.get("/pending")
    assert page.status_code == 200
    body = page.get_data(as_text=True).lower()
    assert "approv" in body
    assert "console" in body


def test_approved_login_requires_email_code_and_marker(client):
    http, dashboard = client
    http.post("/register", data={"username": "admin@example.com", "password": "correct-horse"})

    code = _login_code(http, dashboard, "admin@example.com", "correct-horse")

    blocked = http.get("/", follow_redirects=False)
    assert blocked.status_code == 302
    assert "/2fa" in (blocked.headers.get("Location") or "")

    bad = http.post("/2fa", data={"code": "000000"}, follow_redirects=False)
    assert bad.status_code == 200
    assert "Invalid code" in bad.get_data(as_text=True)
    with http.session_transaction() as sess:
        assert "user" not in sess
        assert not sess.get("email_2fa_ok")

    page = http.get("/2fa", follow_redirects=False)
    assert code not in page.get_data(as_text=True)
    assert "requestSubmit" in (Path("static/js/auth.js").read_text(encoding="utf-8"))

    ok = http.post("/2fa", data={"code": code}, follow_redirects=False)
    assert ok.status_code == 302
    assert (ok.headers.get("Location") or "").endswith("/")
    with http.session_transaction() as sess:
        assert sess["user"] == "admin@example.com"
        assert sess["email_2fa_ok"] is True
        assert sess["role"] == "admin"

    home = http.get("/")
    assert home.status_code == 200
    assert "role-admin" in home.get_data(as_text=True)


def test_session_without_email_2fa_ok_is_cleared(client):
    http, dashboard = client
    http.post("/register", data={"username": "admin@example.com", "password": "correct-horse"})
    with http.session_transaction() as sess:
        dashboard.stamp_auth_session(
            sess,
            "admin@example.com",
            role="admin",
            email_2fa_ok=False,
        )

    resp = http.get("/health.json", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in (resp.headers.get("Location") or "")
    with http.session_transaction() as sess:
        assert "user" not in sess
        assert not sess.get("email_2fa_ok")


def test_admin_approves_then_user_gets_email_code(client):
    http, dashboard = client
    http.post("/register", data={"username": "admin@example.com", "password": "correct-horse"})
    http.post("/register", data={"username": "analyst@example.com", "password": "another-pass"})
    code = _login_code(http, dashboard, "admin@example.com", "correct-horse")
    http.post("/2fa", data={"code": code})

    page = http.get("/accounts")
    assert page.status_code == 200
    assert "analyst@example.com" in page.get_data(as_text=True)
    assert ">Approve<" in page.get_data(as_text=True)

    resp = http.post(
        "/accounts/approve",
        data={"username": "analyst@example.com"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/accounts" in (resp.headers.get("Location") or "")

    from accounts import get_account

    assert get_account("analyst@example.com")["approved"] is True
    assert get_account("analyst@example.com")["status"] == "active"

    http.get("/logout")
    _login_code(http, dashboard, "analyst@example.com", "another-pass")
    with http.session_transaction() as sess:
        assert "user" not in sess


def test_reject_and_deactivate_block_console(client):
    http, dashboard = client
    http.post("/register", data={"username": "admin@example.com", "password": "correct-horse"})
    http.post("/register", data={"username": "analyst@example.com", "password": "another-pass"})
    code = _login_code(http, dashboard, "admin@example.com", "correct-horse")
    http.post("/2fa", data={"code": code})

    http.post("/accounts/reject", data={"username": "analyst@example.com"})
    http.get("/logout")
    with patch.object(dashboard, "deliver_otp") as mock_send:
        resp = http.post(
            "/login",
            data={"username": "analyst@example.com", "password": "another-pass"},
            follow_redirects=False,
        )
    mock_send.assert_not_called()
    assert "/pending" in (resp.headers.get("Location") or "")
    body = http.get("/pending").get_data(as_text=True).lower()
    assert "not approved" in body
    assert http.get("/").status_code == 302

    # Restore, then deactivate.
    http.get("/logout")
    code = _login_code(http, dashboard, "admin@example.com", "correct-horse")
    http.post("/2fa", data={"code": code})
    http.post("/accounts/approve", data={"username": "analyst@example.com"})
    http.post("/accounts/deactivate", data={"username": "analyst@example.com"})
    http.get("/logout")
    with patch.object(dashboard, "deliver_otp") as mock_send:
        resp = http.post(
            "/login",
            data={"username": "analyst@example.com", "password": "another-pass"},
            follow_redirects=True,
        )
    mock_send.assert_not_called()
    assert "deactivated" in resp.get_data(as_text=True).lower()
    assert http.get("/health").status_code == 302


def test_last_admin_and_self_cannot_be_removed(client):
    http, dashboard = client
    http.post("/register", data={"username": "admin@example.com", "password": "correct-horse"})
    code = _login_code(http, dashboard, "admin@example.com", "correct-horse")
    http.post("/2fa", data={"code": code})

    http.post("/accounts/deactivate", data={"username": "admin@example.com"})
    page = http.get("/accounts")
    text = page.get_data(as_text=True)
    assert "cannot deactivate your own account" in text

    http.post("/accounts/reject", data={"username": "admin@example.com"})
    page = http.get("/accounts")
    assert "last active administrator" in page.get_data(as_text=True)

    from accounts import get_account

    assert get_account("admin@example.com")["status"] == "active"


def test_analyst_cannot_open_accounts(client):
    http, dashboard = client
    http.post("/register", data={"username": "admin@example.com", "password": "correct-horse"})
    http.post("/register", data={"username": "analyst@example.com", "password": "another-pass"})
    code = _login_code(http, dashboard, "admin@example.com", "correct-horse")
    http.post("/2fa", data={"code": code})
    http.post("/accounts/approve", data={"username": "analyst@example.com"})
    http.get("/logout")
    code = _login_code(http, dashboard, "analyst@example.com", "another-pass")
    http.post("/2fa", data={"code": code})

    resp = http.get("/accounts", follow_redirects=False)
    assert resp.status_code == 302
    assert (resp.headers.get("Location") or "").endswith("/")
    home = http.get("/")
    assert "Admin role required to manage accounts" in home.get_data(as_text=True)
    assert 'href="/accounts"' not in home.get_data(as_text=True)


def test_email_2fa_can_be_disabled(client, monkeypatch):
    http, dashboard = client
    http.post("/register", data={"username": "admin@example.com", "password": "correct-horse"})
    monkeypatch.setenv("SOC_EMAIL_2FA", "false")
    with patch.object(dashboard, "deliver_otp") as mock_send:
        resp = http.post(
            "/login",
            data={"username": "admin@example.com", "password": "correct-horse"},
            follow_redirects=False,
        )
    mock_send.assert_not_called()
    assert (resp.headers.get("Location") or "").endswith("/")
    home = http.get("/")
    assert home.status_code == 200


def test_login_uses_resend_helper(client, monkeypatch):
    http, dashboard = client
    http.post("/register", data={"username": "admin@example.com", "password": "correct-horse"})
    monkeypatch.setenv("RESEND_API_KEY", "test-key")
    with patch.object(dashboard, "_send_otp_resend", return_value=True) as mock_resend:
        resp = http.post(
            "/login",
            data={"username": "admin@example.com", "password": "correct-horse"},
            follow_redirects=True,
        )
    mock_resend.assert_called_once()
    username, otp, subject = mock_resend.call_args.args
    assert username == "admin@example.com"
    assert len(otp) == 6 and otp.isdigit()
    assert "Verification" in subject
    assert otp not in resp.get_data(as_text=True)


def test_login_and_code_templates_harden_input(client):
    http, dashboard = client
    login = http.get("/login").get_data(as_text=True)
    assert 'autocomplete="off"' in login
    assert "data-autofill-guard" in login
    assert 'data-toggle-password="login-password"' in login
    assert "Show password" in login
    register = http.get("/register").get_data(as_text=True)
    assert 'data-toggle-password="register-password"' in register

    with http.session_transaction() as sess:
        dashboard.stamp_auth_session(sess)
        sess["pending_user"] = "admin@example.com"
        sess["otp"] = "123456"
        sess["otp_time"] = time.time()
        sess["otp_email_hint"] = "a***@example.com"
    page = http.get("/2fa").get_data(as_text=True)
    assert 'id="otp-code"' in page
    assert 'id="otp-form"' in page
    assert "auth.js" in page
    script = Path("static/js/auth.js").read_text(encoding="utf-8")
    assert "requestSubmit" in script
    assert 'slice(0, 6)' in script


def test_legacy_csv_keeps_access_and_promotes_admin(tmp_path, monkeypatch):
    path = tmp_path / "legacy.csv"
    path.write_text(
        "username,password_hash\nfirst@example.com,hash1\nsecond@example.com,hash2\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SOC_USERS_FILE", str(path))
    monkeypatch.delenv("SOC_ADMIN_EMAILS", raising=False)
    from accounts import list_accounts

    rows = list_accounts()
    assert rows[0]["username"] == "first@example.com"
    assert rows[0]["role"] == "admin"
    assert rows[0]["approved"] is True
    assert rows[1]["role"] == "analyst"
    assert rows[1]["approved"] is True
    # Read path does not rewrite the legacy file.
    assert "role" not in path.read_text(encoding="utf-8").splitlines()[0]


def test_developer_role_can_approve(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_USERS_FILE", str(tmp_path / "users.csv"))
    monkeypatch.delenv("SOC_ADMIN_EMAILS", raising=False)
    import accounts as accounts_mod
    from accounts import apply_account_action, can_manage_accounts, get_account, register_account

    register_account("dev@example.com", generate_password_hash("password1"))
    register_account("new@example.com", generate_password_hash("password2"))
    stored = accounts_mod.load_accounts()
    stored["dev@example.com"]["role"] = "developer"
    with accounts_mod._lock:
        accounts_mod._save_unlocked(stored)

    assert can_manage_accounts("dev@example.com") is True
    assert can_manage_accounts("new@example.com") is False
    ok, _message = apply_account_action("new@example.com", "approve", "dev@example.com")
    assert ok is False
    ok, message = apply_account_action("dev@example.com", "approve", "new@example.com")
    assert ok is True
    assert "Approved" in message
    assert get_account("new@example.com")["status"] == "active"
    assert get_account("new@example.com")["approved"] is True
