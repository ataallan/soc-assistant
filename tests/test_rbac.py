"""RBAC: admin email parsing and require_admin enforcement."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from rbac import parse_admin_emails, role_for_identity, ROLE_ADMIN, ROLE_ANALYST


def test_parse_admin_emails_empty():
    assert parse_admin_emails("") == set()
    assert parse_admin_emails(None) == set() or isinstance(parse_admin_emails(None), set)


def test_parse_admin_emails_comma_and_case():
    got = parse_admin_emails(" Admin@Example.COM , other@x.io,,  ")
    assert got == {"admin@example.com", "other@x.io"}


def test_role_for_identity_admin_and_analyst():
    admins = {"boss@soc.local", "lead@soc.local"}
    assert role_for_identity("Boss@SOC.Local", admins) == ROLE_ADMIN
    assert role_for_identity("analyst@soc.local", admins) == ROLE_ANALYST
    assert role_for_identity(None, admins) == ROLE_ANALYST
    assert role_for_identity("", admins) == ROLE_ANALYST


@pytest.fixture()
def rbac_client(tmp_path, monkeypatch):
    db_path = tmp_path / "rbac_soc.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv("SOC_ADMIN_EMAILS", "admin@example.com, Lead@Example.COM")
    monkeypatch.setenv("CONTAINMENT_MODE", "simulated")

    import db

    db.reset_connection()
    db.init_db(db_path)

    import importlib
    import dashboard

    importlib.reload(dashboard)
    dashboard.app.config["TESTING"] = True
    dashboard.app.config["WTF_CSRF_ENABLED"] = False
    client = dashboard.app.test_client()
    return client, dashboard


def test_require_admin_blocks_analyst_train(rbac_client):
    client, _ = rbac_client
    with client.session_transaction() as sess:
        sess["user"] = "analyst@example.com"
        sess["role"] = "analyst"

    resp = client.post(
        "/train-model",
        headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
    )
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["ok"] is False
    assert "admin" in data["message"].lower()


def test_require_admin_allows_admin_backup(rbac_client):
    client, dashboard = rbac_client
    with client.session_transaction() as sess:
        sess["user"] = "admin@example.com"
        sess["role"] = "admin"

    with patch.object(
        dashboard,
        "backup_sqlite",
        return_value={"ok": True, "message": "Backup complete.", "path": "data/backups/x.db"},
    ):
        resp = client.post(
            "/backup?format=json",
            headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
        )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True


def test_require_admin_blocks_analyst_backup(rbac_client):
    client, _ = rbac_client
    with client.session_transaction() as sess:
        sess["user"] = "ops@example.com"

    resp = client.post(
        "/backup",
        headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
    )
    assert resp.status_code == 403


def test_admin_email_case_insensitive_login_role(rbac_client):
    client, dashboard = rbac_client
    # LEAD@example.com is in SOC_ADMIN_EMAILS as Lead@Example.COM
    with client.session_transaction() as sess:
        sess["user"] = "LEAD@example.com"
    with client.application.test_request_context():
        with client.session_transaction():
            pass
    # Hit a page that syncs role
    with patch.object(dashboard, "get_token", return_value=None), patch.object(
        dashboard, "get_last_auth_error", return_value=None
    ), patch.object(dashboard, "wazuh_api_host", return_value="localhost"):
        resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.data.decode("utf-8")
    assert "role-admin" in body or ">admin<" in body.lower()


def _stub_dashboard_client(tmp_path, monkeypatch, mode="stub"):
    db_path = tmp_path / "stub_soc.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv("SOC_ADMIN_EMAILS", "admin@example.com")
    monkeypatch.setenv("CONTAINMENT_MODE", mode)
    monkeypatch.delenv("CONTAINMENT_STUB_URL", raising=False)
    monkeypatch.delenv("CONTAINMENT_STUB_TOKEN", raising=False)

    import db
    import importlib
    import dashboard
    import containment

    db.reset_connection()
    db.init_db(db_path)
    containment._db_ready = True
    importlib.reload(dashboard)
    dashboard.app.config["TESTING"] = True
    dashboard.app.config["WTF_CSRF_ENABLED"] = False
    return dashboard.app.test_client(), dashboard, db_path


def test_stub_containment_execute_admin_only(tmp_path, monkeypatch):
    client, dashboard, _ = _stub_dashboard_client(tmp_path, monkeypatch, "stub")

    with client.session_transaction() as sess:
        sess["user"] = "analyst@example.com"

    resp = client.post(
        "/blocks/execute",
        json={"action": "block", "target_type": "ip", "target": "203.0.113.10", "confirm": 1},
        headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
        follow_redirects=False,
    )
    assert resp.status_code == 403

    # Legacy route also denies analyst
    resp = client.post(
        "/block/ip",
        data={"ip": "203.0.113.10"},
        headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
        follow_redirects=False,
    )
    assert resp.status_code == 403

    with client.session_transaction() as sess:
        sess["user"] = "admin@example.com"

    # Missing confirm → 400
    resp = client.post(
        "/blocks/execute",
        json={"action": "block", "target_type": "ip", "target": "203.0.113.10"},
        headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
    )
    assert resp.status_code == 400
    assert resp.get_json().get("requires_confirm") is True

    with patch.object(dashboard, "execute_confirmed", return_value={"ok": True, "message": "ok"}) as mock_exec:
        resp = client.post(
            "/blocks/execute",
            json={
                "action": "block",
                "target_type": "ip",
                "target": "203.0.113.10",
                "confirm": 1,
            },
            headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
        )
    assert resp.status_code == 200
    mock_exec.assert_called_once_with("block", "ip", "203.0.113.10", confirm=True)


def test_blocks_preview_json_for_analyst(tmp_path, monkeypatch):
    client, _, _ = _stub_dashboard_client(tmp_path, monkeypatch, "live")

    with client.session_transaction() as sess:
        sess["user"] = "analyst@example.com"

    resp = client.post(
        "/blocks/preview",
        json={"action": "block", "target_type": "ip", "target": "192.0.2.1"},
        headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["allowed"] is False
    assert data["requires_confirm"] is True


def test_security_headers_present(rbac_client):
    client, _ = rbac_client
    with client.session_transaction() as sess:
        sess["user"] = "analyst@example.com"
    resp = client.get("/")
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Referrer-Policy" in resp.headers


def test_session_cookie_flags(rbac_client):
    _, dashboard = rbac_client
    assert dashboard.app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert dashboard.app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
