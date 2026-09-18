"""Unit tests for wazuh_integration client — network is fully mocked."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import wazuh_integration as wi


@pytest.fixture(autouse=True)
def _reset_wazuh_client_state(monkeypatch):
    """Isolate module globals and provide fake credentials (no live network)."""
    monkeypatch.setattr(wi, "WAZUH_API", "https://wazuh.test:55000")
    monkeypatch.setattr(wi, "API_USER", "wazuh")
    monkeypatch.setattr(wi, "API_PASS", "test-password")
    monkeypatch.setattr(wi, "_TOKEN", None)
    monkeypatch.setattr(wi, "_TOKEN_EXP", 0.0)
    monkeypatch.setattr(wi, "_CACHED_ENDPOINT", None)
    monkeypatch.setattr(wi, "_CACHED_ENDPOINT_EXP", 0.0)
    yield


def _json_response(status_code: int, payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = payload
    resp.text = str(payload)
    return resp


# ---------------------------------------------------------------------------
# get_token
# ---------------------------------------------------------------------------


def test_get_token_success():
    auth_payload = {"data": {"token": "jwt-demo-token"}}
    with patch.object(wi.requests, "get", return_value=_json_response(200, auth_payload)) as mock_get:
        token = wi.get_token()
    assert token == "jwt-demo-token"
    assert wi._TOKEN == "jwt-demo-token"
    mock_get.assert_called_once()
    args, kwargs = mock_get.call_args
    assert args[0].endswith("/security/user/authenticate")
    assert kwargs["auth"] == ("wazuh", "test-password")


def test_get_token_uses_cache():
    wi._TOKEN = "cached-token"
    wi._TOKEN_EXP = 9999999999.0  # far future
    with patch.object(wi.requests, "get") as mock_get:
        token = wi.get_token()
    assert token == "cached-token"
    mock_get.assert_not_called()


def test_get_token_failure_bad_status():
    with patch.object(wi.requests, "get", return_value=_json_response(401, {"error": 1})):
        token = wi.get_token()
    assert token is None
    assert wi._TOKEN is None


def test_get_token_missing_token_in_body():
    with patch.object(wi.requests, "get", return_value=_json_response(200, {"data": {}})):
        token = wi.get_token()
    assert token is None


def test_get_token_missing_credentials(monkeypatch):
    monkeypatch.setattr(wi, "API_PASS", "")
    with patch.object(wi.requests, "get") as mock_get:
        token = wi.get_token()
    assert token is None
    mock_get.assert_not_called()


def test_get_token_network_exception():
    with patch.object(wi.requests, "get", side_effect=ConnectionError("refused")):
        token = wi.get_token()
    assert token is None


# ---------------------------------------------------------------------------
# fetch_wazuh_alert_details / fetch_wazuh_alerts
# ---------------------------------------------------------------------------


WAZUH_ALERTS_PAYLOAD = {
    "data": {
        "affected_items": [
            {
                "timestamp": "2026-01-15T12:00:00Z",
                "agent": {"name": "web01", "id": "001"},
                "rule": {
                    "id": "5710",
                    "level": 10,
                    "description": "sshd: attempt to login using a non-existent user",
                },
                "full_log": "sshd[123]: Failed password for invalid user root from 203.0.113.9",
            },
            {
                "timestamp": "2026-01-15T12:01:00Z",
                "agent": {"name": "db01", "id": "002"},
                "rule": {"id": "1002", "level": 5, "description": "Unknown problem"},
                "full_log": "noise event",
            },
        ],
        "total_affected_items": 2,
    }
}


def test_fetch_alert_details_with_mocked_json():
    """Probe finds /alerts; GET returns Wazuh-like affected_items envelope."""

    def fake_get(url, **kwargs):
        if url.endswith("/security/user/authenticate"):
            return _json_response(200, {"data": {"token": "tok"}})
        # endpoint probe or alert fetch
        if "/alerts" in url or "/manager/logs" in url or "/manager/alerts" in url:
            return _json_response(200, WAZUH_ALERTS_PAYLOAD)
        return _json_response(404, {"error": "not found"})

    with patch.object(wi.requests, "get", side_effect=fake_get):
        alerts = wi.fetch_wazuh_alert_details(limit=5)

    assert len(alerts) == 2
    assert alerts[0]["agent"] == "web01"
    assert alerts[0]["rule_id"] == "5710"
    assert alerts[0]["severity"] == "high"
    assert "Failed password" in alerts[0]["full_log"]
    assert alerts[1]["severity"] == "low"


def test_fetch_wazuh_alerts_returns_summary_strings():
    def fake_get(url, **kwargs):
        if url.endswith("/security/user/authenticate"):
            return _json_response(200, {"data": {"token": "tok"}})
        return _json_response(200, WAZUH_ALERTS_PAYLOAD)

    with patch.object(wi.requests, "get", side_effect=fake_get):
        summaries = wi.fetch_wazuh_alerts(limit=5)

    assert isinstance(summaries, list)
    assert len(summaries) == 2
    assert all(isinstance(s, str) for s in summaries)
    assert any("web01" in s or "Failed password" in s or "sshd" in s for s in summaries)


def test_fetch_returns_empty_list_when_request_fails():
    def fake_get(url, **kwargs):
        if url.endswith("/security/user/authenticate"):
            return _json_response(200, {"data": {"token": "tok"}})
        resp = MagicMock()
        resp.status_code = 500
        resp.text = "internal error"
        resp.json.side_effect = ValueError("no json")
        return resp

    with patch.object(wi.requests, "get", side_effect=fake_get):
        # probes fail (non-2xx), fallback /alerts also 500 → None → []
        alerts = wi.fetch_wazuh_alert_details(limit=5)

    assert alerts == []


def test_fetch_401_retries_with_refreshed_token():
    """On 401 from alert endpoint, client refreshes JWT and retries once."""
    call_log = []

    def fake_get(url, **kwargs):
        call_log.append(url)
        if url.endswith("/security/user/authenticate"):
            return _json_response(200, {"data": {"token": f"tok-{len(call_log)}"}})
        # First successful probe caches /manager/alerts (never /manager/logs)
        if "/manager/alerts" in url:
            mgr_calls = [u for u in call_log if "/manager/alerts" in u]
            if len(mgr_calls) == 1:
                # probe — success so endpoint is cached
                return _json_response(200, {"data": {"affected_items": []}})
            if len(mgr_calls) == 2:
                # first real fetch — 401
                resp = MagicMock()
                resp.status_code = 401
                resp.text = "unauthorized"
                resp.json.return_value = {"error": 401}
                return resp
            # retry after force_refresh
            return _json_response(200, WAZUH_ALERTS_PAYLOAD)
        return _json_response(404, {})

    with patch.object(wi.requests, "get", side_effect=fake_get):
        alerts = wi.fetch_wazuh_alert_details(limit=5)

    assert len(alerts) == 2
    # Auth called at least twice (initial + force_refresh on 401)
    auth_calls = [u for u in call_log if u.endswith("/security/user/authenticate")]
    assert len(auth_calls) >= 2


def test_fetch_empty_affected_items_still_parses():
    """Empty affected_items → parse falls back to wrapping raw payload as one low alert."""
    empty_payload = {"data": {"affected_items": []}}

    def fake_get(url, **kwargs):
        if url.endswith("/security/user/authenticate"):
            return _json_response(200, {"data": {"token": "tok"}})
        return _json_response(200, empty_payload)

    with patch.object(wi.requests, "get", side_effect=fake_get):
        alerts = wi.fetch_wazuh_alert_details(limit=5)

    # _parse_alerts_structured returns a single fallback dict when items empty
    assert isinstance(alerts, list)
    assert len(alerts) >= 1
    assert alerts[0]["severity"] == "low"


def test_no_network_when_credentials_missing(monkeypatch):
    monkeypatch.setattr(wi, "API_PASS", "")
    with patch.object(wi.requests, "get") as mock_get:
        # Without password, get_token is None; probes/fallback may still call requests
        # Force fallback path by leaving probes unable to succeed without mocking —
        # but with empty pass, auth=(user, pass) is None on fallback. Still may hit network.
        # Ensure get_token short-circuits and we return empty when everything fails.
        mock_get.return_value = _json_response(403, {"error": "forbidden"})
        alerts = wi.fetch_wazuh_alert_details(limit=3)
    assert alerts == []
    # Auth endpoint must NOT have been called (credentials gate)
    for call in mock_get.call_args_list:
        url = call[0][0] if call[0] else ""
        assert "/security/user/authenticate" not in url
