"""YAML rule engine match / no-match tests (offline)."""

from rules.engine import evaluate_rules, load_rules


def _ctx(text, **kwargs):
    alert = {
        "raw_message": text,
        "rule_description": text,
        "src_ip": kwargs.get("src_ip", "10.0.0.1"),
        "user": kwargs.get("user", "alice"),
        "host": kwargs.get("host", "ws1"),
        "severity_hint": kwargs.get("severity_hint"),
        "text": text,
    }
    enrichment = kwargs.get("enrichment") or {
        "src_ip": {"classification": kwargs.get("src_class", "private"), "is_private": True},
        "asset": kwargs.get("asset"),
    }
    return alert, enrichment


def test_load_sample_rules():
    rules = load_rules(force_reload=True)
    assert len(rules) >= 5
    ids = {r["id"] for r in rules}
    assert "DET-BRUTE-001" in ids
    assert "DET-MALWARE-001" in ids


def test_brute_force_match():
    alert, enrichment = _ctx("Possible brute force authentication storm from VPN")
    result = evaluate_rules(alert, enrichment, rules=load_rules(force_reload=True))
    ids = [m["id"] for m in result["matched_rules"]]
    assert "DET-BRUTE-001" in ids
    assert result["recommended_severity"] in ("high", "critical")
    assert any(m.get("explain") for m in result["matched_rules"])


def test_malware_match_critical():
    alert, enrichment = _ctx("ransomware encrypting shares on file server")
    result = evaluate_rules(alert, enrichment, rules=load_rules(force_reload=True))
    ids = [m["id"] for m in result["matched_rules"]]
    assert "DET-MALWARE-001" in ids
    assert result["recommended_severity"] == "critical"


def test_no_match_benign():
    alert, enrichment = _ctx("User opened a ticket about printer jam")
    result = evaluate_rules(alert, enrichment, rules=load_rules(force_reload=True))
    assert result["matched_rules"] == []
    assert result["recommended_severity"] is None


def test_critical_asset_high_sev_match():
    alert, enrichment = _ctx(
        "elevated alert on domain controller",
        severity_hint="high",
        enrichment={
            "src_ip": {"classification": "private", "is_private": True},
            "asset": {"name": "dc01.lab.local", "criticality": "critical"},
        },
    )
    # Also expose asset fields like pipeline context helpers
    alert["severity_hint"] = "high"
    result = evaluate_rules(alert, enrichment, rules=load_rules(force_reload=True))
    ids = [m["id"] for m in result["matched_rules"]]
    assert "DET-ASSET-001" in ids
