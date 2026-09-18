"""Allowlist loader + match unit tests (offline)."""

from pathlib import Path

import yaml

from detection.allowlists import clear_allowlist_cache, load_allowlists, match


def _write_allowlist(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "allowlists.yml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_allowlist_ip_match(tmp_path):
    clear_allowlist_cache()
    path = _write_allowlist(tmp_path, {"ips": ["203.0.113.10"], "cidrs": [], "users": [], "hosts": [], "suppress_wazuh_rule_ids": []})
    hit = match({"src_ip": "203.0.113.10"}, path=path)
    miss = match({"src_ip": "198.51.100.1"}, path=path)
    assert hit["matched"] is True
    assert any(r.startswith("ip:") for r in hit["reasons"])
    assert miss["matched"] is False


def test_allowlist_cidr_match(tmp_path):
    clear_allowlist_cache()
    path = _write_allowlist(tmp_path, {"ips": [], "cidrs": ["10.0.0.0/8"], "users": [], "hosts": [], "suppress_wazuh_rule_ids": []})
    hit = match({"src_ip": "10.1.2.3"}, path=path)
    miss = match({"src_ip": "11.0.0.1"}, path=path)
    assert hit["matched"] is True
    assert any("cidr:" in r for r in hit["reasons"])
    assert miss["matched"] is False


def test_allowlist_user_and_host_case_insensitive(tmp_path):
    clear_allowlist_cache()
    path = _write_allowlist(
        tmp_path,
        {"ips": [], "cidrs": [], "users": ["Vagrant"], "hosts": ["Lab-Scanner"], "suppress_wazuh_rule_ids": []},
    )
    user_hit = match({"user": "vagrant", "src_ip": "1.2.3.4"}, path=path)
    host_hit = match({"host": "lab-scanner"}, path=path)
    assert user_hit["matched"] is True
    assert any(r.startswith("user:") for r in user_hit["reasons"])
    assert host_hit["matched"] is True
    assert any(r.startswith("host:") for r in host_hit["reasons"])


def test_allowlist_suppress_wazuh_rule_id(tmp_path):
    clear_allowlist_cache()
    path = _write_allowlist(
        tmp_path,
        {"ips": [], "cidrs": [], "users": [], "hosts": [], "suppress_wazuh_rule_ids": ["2902", "2904"]},
    )
    hit = match({"rule_id": "2902", "src_ip": "8.8.8.8"}, path=path)
    miss = match({"rule_id": "5710"}, path=path)
    assert hit["matched"] is True
    assert hit["suppress_rule"] is True
    assert any("suppress_wazuh_rule_id:2902" in r for r in hit["reasons"])
    assert miss["matched"] is False


def test_default_shipped_allowlist_loads():
    clear_allowlist_cache()
    cfg = load_allowlists(force_reload=True)
    assert "2902" in cfg["suppress_wazuh_rule_ids"]
    assert "2904" in cfg["suppress_wazuh_rule_ids"]
