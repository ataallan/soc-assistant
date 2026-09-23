from detection.pipeline import process_alert
from triage_engine import classify_severity, rule_based_triage, analyze_log


def test_critical_ransomware_phrase():
    assert classify_severity("Ransomware detected on host") == "critical"


def test_critical_mimikatz():
    assert classify_severity("mimikatz credential dumping observed") == "critical"


def test_critical_reverse_shell():
    assert classify_severity("reverse shell established to C2") == "critical"


def test_high_brute_force_phrase():
    assert classify_severity("Possible brute force authentication storm") == "high"


def test_high_password_spraying():
    assert classify_severity("password spraying against VPN gateway") == "high"


def test_failed_login_medium():
    assert classify_severity("Single failed login from workstation") == "medium"


def test_unknown_is_low():
    assert classify_severity("User opened a ticket about printer jam") == "low"


def test_numeric_attempts_critical():
    assert classify_severity("Observed 12 failures from same IP") == "critical"


def test_numeric_attempts_high():
    assert classify_severity("Observed 6 attempts from same IP") == "high"


def test_rule_based_escalate_on_high():
    assert rule_based_triage("mimikatz credential dumping") == "escalate"


def test_rule_based_investigate_medium():
    assert rule_based_triage("failed login on workstation") == "investigate"


def test_rule_based_ignore_low():
    assert rule_based_triage("routine heartbeat check") == "ignore"


def test_analyze_log_extracts_fields():
    result = analyze_log(
        "failed login user=alice from 10.0.0.5",
        event_type="failed_login",
        description="failed login",
        username="alice",
        source_ip="10.0.0.5",
    )
    assert result["ip"] == "10.0.0.5"
    assert result["user"] in ("alice", None) or result["user"] == "alice"
    assert "severity" in result
    assert "recommendation" in result
    assert result["severity"] in ("critical", "high", "medium", "low")


def test_analyze_log_recommendation_aligned_with_rules():
    result = analyze_log(
        "ransomware encrypting shares",
        event_type="malware",
        description="ransomware",
    )
    assert result["recommendation"] == "escalate"


def test_analyze_log_rules_critical_overrides_ml():
    """Rules saying critical must keep critical even if ML would differ."""
    result = analyze_log(
        "ransomware encrypting shares",
        event_type="benign_looking",
        description="routine check",
        username="alice",
    )
    assert result["severity"] == "critical"
    assert result["recommendation"] == "escalate"


def test_invalid_user_wording_is_medium_investigate():
    samples = (
        "Failed password for invalid user admin from 198.51.100.44 port 22 ssh2",
        "Invalid user admin from 198.51.100.44 port 22",
        "sshd: Attempt to login using a non-existent user",
    )
    for text in samples:
        assert classify_severity(text) == "medium"
        assert rule_based_triage(text) == "investigate"


def test_invalid_username_login_form_stays_low():
    assert classify_severity("Invalid username or password") == "low"
    assert rule_based_triage("Invalid username or password") == "ignore"


def test_invalid_user_does_not_outrank_brute_force():
    text = "Failed password for invalid user admin brute force"
    assert classify_severity(text) == "high"
    assert rule_based_triage(text) == "escalate"


def test_wazuh_5710_structured_alert_investigates(monkeypatch):
    monkeypatch.setenv("ML_ASSIST_ONLY", "true")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    result = process_alert(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "agent": {"name": "edge01", "id": "004"},
            "rule": {
                "id": "5710",
                "level": 5,
                "description": "sshd: Attempt to login using a non-existent user.",
            },
            "full_log": "sshd[2222]: Invalid user admin from 198.51.100.44 port 22",
            "data": {"srcip": "198.51.100.44", "srcuser": "admin"},
        }
    )
    assert result["alert"]["rule_id"] == "5710"
    assert result["alert"]["src_ip"] == "198.51.100.44"
    assert result["ip"] == "198.51.100.44"
    assert result["severity"] == "medium"
    assert result["recommendation"] == "investigate"
    assert result["rule_based"] == "investigate"
    ids = [m["id"] for m in result["matched_rules"]]
    assert "DET-AUTH-5710" in ids


def test_plain_invalid_user_log_investigates(monkeypatch):
    monkeypatch.setenv("ML_ASSIST_ONLY", "true")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    samples = (
        "Failed password for invalid user guest from 198.51.100.44 port 22 ssh2",
        "Invalid user bob from 203.0.113.10 port 22",
    )
    for text in samples:
        result = process_alert(text)
        assert result["severity"] == "medium"
        assert result["recommendation"] == "investigate"
        assert result["rule_based"] == "investigate"
        assert result["ip"]


def test_dpkg_2902_2904_still_ignore(monkeypatch, tmp_path):
    monkeypatch.setenv("ML_ASSIST_ONLY", "true")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("ALLOWLIST_PATH", raising=False)
    monkeypatch.setenv("FP_RUNTIME_ALLOWLIST_PATH", str(tmp_path / "runtime.yml"))
    from detection.allowlists import clear_allowlist_cache

    clear_allowlist_cache()
    samples = (
        ("2902", "dpkg: status installed foo"),
        ("2904", "wazuh rule 2904 dpkg half-configured bar"),
    )
    for rule_id, log in samples:
        result = process_alert(
            {
                "rule_id": rule_id,
                "full_log": log,
                "agent": {"name": "ubuntu-lab"},
            }
        )
        assert result["allowlisted"] is True
        assert result["severity"] == "low"
        assert result["recommendation"] == "ignore"
        assert result["rule_based"] == "ignore"


def test_analyze_log_low_ml_confidence_falls_back_to_rules(monkeypatch):
    import triage_engine as te

    def fake_ml(*args, **kwargs):
        return "high", 0.20  # below threshold

    monkeypatch.setattr(te, "ml_predict_severity", fake_ml)
    result = te.analyze_log("User opened a ticket about printer jam")
    assert result["severity"] == "low"  # rules classify as low
