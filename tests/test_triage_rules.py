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
