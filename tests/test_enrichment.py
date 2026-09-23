"""Offline enrichment tests — no network."""

import os

from detection.enrichment import (
    classify_ip,
    enrich_alert,
    load_asset_inventory,
    lookup_asset,
)
from detection.normalize import normalize_alert


def test_classify_private_rfc1918():
    for ip in ("10.0.0.1", "192.168.1.50", "172.16.5.12"):
        meta = classify_ip(ip)
        assert meta["valid"] is True
        assert meta["is_private"] is True
        assert meta["classification"] == "private"


def test_documentation_ranges_are_not_rfc1918(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    for ip in ("198.51.100.44", "192.0.2.1", "203.0.113.5", "2001:db8::44"):
        meta = classify_ip(ip)
        assert meta["valid"] is True
        assert meta["classification"] == "documentation"
        assert meta["is_private"] is False
        assert meta["is_documentation"] is True

    alert = normalize_alert(
        {
            "source_ip": "198.51.100.44",
            "description": "Invalid user admin from 198.51.100.44",
        }
    )
    enrichment, notes = enrich_alert(alert)
    assert enrichment["src_ip"]["classification"] == "documentation"
    joined = " ".join(notes).lower()
    assert "documentation" in joined
    assert "rfc1918" not in joined


def test_classify_public_and_invalid():
    pub = classify_ip("8.8.8.8")
    assert pub["classification"] == "public"
    assert classify_ip("not-an-ip")["classification"] == "invalid"
    assert classify_ip(None)["classification"] == "missing"


def test_asset_inventory_lookup():
    load_asset_inventory(force_reload=True)
    asset = lookup_asset(ip="10.0.0.10")
    assert asset is not None
    assert asset["criticality"] == "critical"


def test_enrich_alert_private_notes(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    load_asset_inventory(force_reload=True)
    alert = normalize_alert(
        {
            "source_ip": "10.0.0.10",
            "description": "admin login",
            "username": "admin",
            "host": "dc01.lab.local",
        }
    )
    enrichment, notes = enrich_alert(alert)
    assert enrichment["src_ip"]["classification"] == "private"
    assert enrichment["asset"] is not None
    assert enrichment["abuseipdb"] is None
    assert any("private" in n.lower() or "asset" in n.lower() for n in notes)


def test_enrichment_disabled(monkeypatch):
    monkeypatch.setenv("ENRICHMENT_ENABLED", "false")
    alert = normalize_alert({"source_ip": "10.0.0.1", "description": "x"})
    enrichment, notes = enrich_alert(alert)
    assert enrichment["enabled"] is False
    assert any("disabled" in n.lower() for n in notes)
