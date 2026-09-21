"""Health endpoint JSON shape and login gating."""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    db_path = tmp_path / "health_soc.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv("SOC_USERS_FILE", str(tmp_path / "users.csv"))

    import db

    db.reset_connection()
    db.init_db(db_path)
    db.insert_triage_event(
        {
            "timestamp": "2026-09-17T12:00:00",
            "log": "health probe",
            "severity": "low",
            "rule_based": "monitor",
            "ml_prediction": "low",
        },
        db_path=db_path,
        source="test",
    )
    db.save_block("ip", "203.0.113.50", mode="simulated", db_path=db_path)

    import importlib
    import dashboard

    importlib.reload(dashboard)
    dashboard.app.config["TESTING"] = True
    dashboard.app.config["WTF_CSRF_ENABLED"] = False
    client = dashboard.app.test_client()
    return client, dashboard


def test_health_json_requires_login(app_client):
    client, _ = app_client
    resp = client.get("/health.json")
    assert resp.status_code in (302, 301)
    assert "/login" in (resp.headers.get("Location") or "")


def test_health_json_shape(app_client):
    client, dashboard = app_client
    with client.session_transaction() as sess:
        sess["user"] = "ops@example.com"

    with patch.object(dashboard, "get_token", return_value=None), patch.object(
        dashboard, "get_last_auth_error", return_value="Wazuh password is not set."
    ), patch.object(dashboard, "wazuh_api_host", return_value="localhost:55000"):
        resp = client.get("/health.json")

    assert resp.status_code == 200
    data = resp.get_json()
    assert set(data.keys()) >= {"storage", "wazuh", "watchers"}

    storage = data["storage"]
    assert storage["backend"] == "sqlite"
    assert "location" in storage
    assert isinstance(storage["triage_events"], int)
    assert storage["triage_events"] >= 1
    assert isinstance(storage["blocks"], int)
    assert storage["blocks"] >= 1

    wazuh = data["wazuh"]
    assert wazuh["authenticated"] is False
    assert wazuh["api_host"] == "localhost:55000"
    assert wazuh["last_error"]
    # Soft operator message only — never include credentials/secrets
    assert "wazuh-pass" not in (wazuh.get("last_error") or "").lower()

    watchers = data["watchers"]
    assert "csv" in watchers and "wazuh" in watchers
    assert watchers["csv"] is False
    assert watchers["wazuh"] is False


def test_health_page_renders(app_client):
    client, dashboard = app_client
    with client.session_transaction() as sess:
        sess["user"] = "ops@example.com"
    with patch.object(dashboard, "get_token", return_value="tok"), patch.object(
        dashboard, "get_last_auth_error", return_value=None
    ):
        resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.data.decode("utf-8")
    assert "System Health" in body
    assert "Storage" in body
