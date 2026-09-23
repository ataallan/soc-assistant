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


def test_wazuh_5710_rule_id_matches_medium():
    alert, enrichment = _ctx(
        "sshd: Attempt to login using a non-existent user",
        src_ip="198.51.100.44",
        user="admin",
    )
    alert["rule_id"] = "5710"
    result = evaluate_rules(alert, enrichment, rules=load_rules(force_reload=True))
    ids = [m["id"] for m in result["matched_rules"]]
    assert "DET-AUTH-5710" in ids
    assert result["recommended_severity"] == "medium"


def test_sshd_invalid_user_wording_matches_medium():
    rules = load_rules(force_reload=True)
    samples = (
        "Failed password for invalid user guest from 198.51.100.44 port 22 ssh2",
        "Invalid user admin from 203.0.113.10 port 22",
        "sshd: Attempt to login using a non-existent user",
    )
    for text in samples:
        alert, enrichment = _ctx(text, src_ip="198.51.100.44")
        result = evaluate_rules(alert, enrichment, rules=rules)
        ids = [m["id"] for m in result["matched_rules"]]
        assert "DET-AUTH-002" in ids
        assert result["recommended_severity"] == "medium"


def test_dpkg_noise_stays_low_and_does_not_match_invalid_user():
    alert, enrichment = _ctx("dpkg: status installed foo")
    alert["rule_id"] = "2902"
    result = evaluate_rules(alert, enrichment, rules=load_rules(force_reload=True))
    ids = [m["id"] for m in result["matched_rules"]]
    assert "DET-PKG-001" in ids
    assert "DET-AUTH-5710" not in ids
    assert "DET-AUTH-002" not in ids
    assert result["recommended_severity"] == "low"


def test_admin_login_still_high_but_invalid_user_admin_is_not():
    rules = load_rules(force_reload=True)
    admin_login, enrichment = _ctx("admin login from console", user="admin")
    hit = evaluate_rules(admin_login, enrichment, rules=rules)
    assert "DET-ADMIN-001" in [m["id"] for m in hit["matched_rules"]]
    assert hit["recommended_severity"] == "high"

    alert, enrichment = _ctx(
        "sshd[2222]: Invalid user admin from 198.51.100.44 port 22 "
        "sshd: Attempt to login using a non-existent user.",
        src_ip="198.51.100.44",
        user="admin",
    )
    alert["rule_id"] = "5710"
    result = evaluate_rules(alert, enrichment, rules=rules)
    ids = [m["id"] for m in result["matched_rules"]]
    assert "DET-AUTH-5710" in ids
    assert "DET-ADMIN-001" not in ids
    assert result["recommended_severity"] == "medium"


def test_invalid_user_plus_brute_force_stays_high():
    alert, enrichment = _ctx(
        "Failed password for invalid user admin from 198.51.100.44 brute force",
        src_ip="198.51.100.44",
    )
    alert["rule_id"] = "5710"
    result = evaluate_rules(alert, enrichment, rules=load_rules(force_reload=True))
    ids = [m["id"] for m in result["matched_rules"]]
    assert "DET-AUTH-5710" in ids
    assert "DET-BRUTE-001" in ids
    assert result["recommended_severity"] == "high"


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
