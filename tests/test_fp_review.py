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


def test_aggregate_groups_same_host_and_user():
    events = [
        {"matched_rule_id": "2902", "host": "web01", "user": "alice", "severity": "low", "rule_based": "ignore", "log": "dpkg a"},
        {"matched_rule_id": "2902", "host": "web01", "user": "Alice", "severity": "low", "rule_based": "ignore", "log": "dpkg b"},
        {"matched_rule_id": "2902", "host": "web01", "user": "alice", "severity": "high", "rule_based": "escalate", "log": "dpkg c"},
        {"matched_rule_id": "DET-MALWARE-001", "host": "web01", "user": "alice", "severity": "critical", "rule_based": "escalate", "log": "malware"},
    ]
    rows = aggregate_noisy_rules(events, limit_events=100, top_n=10)
    top = rows[0]
    assert top["rule_key"] == "2902"
    assert top["bucket_key"] == "r:2902|h:web01|u:alice"
    assert top["count"] == 3
    assert top["low_ignore_count"] == 2
    assert top["pct_low_ignore"] == 66.7
    assert top["sample_log"]
    keys = [r["rule_key"] for r in rows]
    assert "DET-MALWARE-001" in keys


def test_aggregate_splits_hosts_and_uses_fingerprint_when_identity_missing():
    events = [
        {"matched_rule_id": "2902", "host": "web01", "user": "alice", "log": "dpkg install foo", "severity": "low", "rule_based": "ignore"},
        {"matched_rule_id": "2902", "host": "db01", "user": "alice", "log": "dpkg install foo", "severity": "low", "rule_based": "ignore"},
        {"matched_rule_id": "2902", "log": "dpkg install foo", "severity": "low", "rule_based": "ignore"},
        {"matched_rule_id": "2902", "log": "sshd failed password", "severity": "high", "rule_based": "escalate"},
    ]
    rows = aggregate_noisy_rules(events, limit_events=100, top_n=10)
    keys = {row["bucket_key"] for row in rows}
    assert "r:2902|h:web01|u:alice" in keys
    assert "r:2902|h:db01|u:alice" in keys
    fingerprints = [row for row in rows if row["fingerprint"]]
    assert len(fingerprints) == 2
    assert len({row["bucket_key"] for row in fingerprints}) == 2
