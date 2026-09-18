"""FP review aggregation helper tests."""

from detection.fp_review import aggregate_noisy_rules, extract_rule_key


def test_extract_rule_key_prefers_matched_rule_id():
    assert extract_rule_key({"matched_rule_id": "DET-PKG-001", "rule_id": "2902"}) == "DET-PKG-001"


def test_extract_rule_key_from_raw_json():
    import json

    event = {
        "log": "something",
        "raw_json": json.dumps({"matched_rule_id": "DET-MALWARE-001", "rule_id": "591"}),
    }
    assert extract_rule_key(event) == "DET-MALWARE-001"


def test_extract_rule_key_from_log_text():
    assert extract_rule_key({"log": "Wazuh rule id: 2902 dpkg install"}) == "2902"


def test_aggregate_noisy_rules_counts_and_pct():
    events = [
        {"matched_rule_id": "2902", "severity": "low", "rule_based": "ignore", "log": "dpkg a"},
        {"matched_rule_id": "2902", "severity": "low", "rule_based": "ignore", "log": "dpkg b"},
        {"matched_rule_id": "2902", "severity": "high", "rule_based": "escalate", "log": "dpkg c"},
        {"matched_rule_id": "DET-MALWARE-001", "severity": "critical", "rule_based": "escalate", "log": "malware"},
    ]
    rows = aggregate_noisy_rules(events, limit_events=100, top_n=10)
    assert rows[0]["rule_key"] == "2902"
    assert rows[0]["count"] == 3
    assert rows[0]["low_ignore_count"] == 2
    assert rows[0]["pct_low_ignore"] == 66.7
    assert rows[0]["sample_log"]
    keys = [r["rule_key"] for r in rows]
    assert "DET-MALWARE-001" in keys
