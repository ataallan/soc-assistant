"""Allowlist / noise-suppress loader for the detection pipeline."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_ALLOWLIST_PATH = _REPO_ROOT / "config" / "allowlists.yml"

_CACHE: Optional[Dict[str, Any]] = None
_CACHE_PATH: Optional[str] = None
_CACHE_STAMP: Optional[tuple] = None


def allowlist_path() -> Path:
    raw = os.environ.get("ALLOWLIST_PATH", "").strip()
    if raw:
        return Path(raw)
    return _DEFAULT_ALLOWLIST_PATH


def _as_str_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for item in value:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                out.append(text)
        return out
    text = str(value).strip()
    return [text] if text else []


def _normalize_config(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        data = {}
    ips = [ip.strip() for ip in _as_str_list(data.get("ips")) if ip.strip()]
    cidrs_raw = _as_str_list(data.get("cidrs"))
    cidrs: List[Any] = []
    for c in cidrs_raw:
        try:
            cidrs.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    users = {u.lower() for u in _as_str_list(data.get("users"))}
    hosts = {h.lower() for h in _as_str_list(data.get("hosts"))}
    suppress = {str(r).strip() for r in _as_str_list(data.get("suppress_wazuh_rule_ids")) if str(r).strip()}
    notes = data.get("notes")
    notes_text = str(notes).strip() if notes is not None else ""
    return {
        "ips": set(ips),
        "cidrs": cidrs,
        "users": users,
        "hosts": hosts,
        "suppress_wazuh_rule_ids": suppress,
        "notes": notes_text,
        "raw_ips": ips,
        "raw_cidrs": cidrs_raw,
    }


def _runtime_stamp() -> Optional[tuple]:
    try:
        from detection.suppressions import runtime_path

        path = runtime_path()
        if not path.is_file():
            return ("", None, 0)
        stat = path.stat()
        return (str(path), stat.st_mtime_ns, stat.st_size)
    except Exception:
        return ("", None, 0)


def _merge_runtime_globals(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Union operator runtime IP/user/host/rule entries into a classic allowlist."""
    try:
        from detection.suppressions import runtime_global_lists

        extra = runtime_global_lists()
    except Exception:
        return cfg
    if not extra:
        return cfg
    ips = set(cfg.get("ips") or [])
    for ip in extra.get("ips") or []:
        text = str(ip).strip()
        if text:
            ips.add(text)
    cfg["ips"] = ips
    cidrs = list(cfg.get("cidrs") or [])
    existing_nets = {str(net) for net in cidrs}
    raw_cidrs = list(cfg.get("raw_cidrs") or [])
    for raw in extra.get("cidrs") or []:
        text = str(raw).strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue
        if str(net) not in existing_nets:
            cidrs.append(net)
            existing_nets.add(str(net))
            raw_cidrs.append(text)
    cfg["cidrs"] = cidrs
    cfg["raw_cidrs"] = raw_cidrs
    users = set(cfg.get("users") or [])
    for user in extra.get("users") or []:
        text = str(user).strip().lower()
        if text:
            users.add(text)
    cfg["users"] = users
    hosts = set(cfg.get("hosts") or [])
    for host in extra.get("hosts") or []:
        text = str(host).strip().lower()
        if text:
            hosts.add(text)
    cfg["hosts"] = hosts
    rules = set(cfg.get("suppress_wazuh_rule_ids") or [])
    for rule in extra.get("suppress_wazuh_rule_ids") or []:
        text = str(rule).strip()
        if text:
            rules.add(text)
    cfg["suppress_wazuh_rule_ids"] = rules
    return cfg


def load_allowlists(
    path: Optional[Path | str] = None,
    *,
    force_reload: bool = False,
) -> Dict[str, Any]:
    """Load and cache allowlist YAML. Missing/invalid file → empty allowlists.

    The default path also merges ``FP_RUNTIME_ALLOWLIST_PATH`` globals and
    reloads when that file's mtime changes.
    """
    global _CACHE, _CACHE_PATH, _CACHE_STAMP
    target = Path(path) if path is not None else allowlist_path()
    target_key = str(target.resolve()) if target.exists() else str(target)
    stamp = _runtime_stamp() if path is None else None

    if (
        _CACHE is not None
        and not force_reload
        and path is None
        and _CACHE_PATH == target_key
        and _CACHE_STAMP == stamp
    ):
        return _CACHE

    data: Any = {}
    if yaml is not None and target.is_file():
        try:
            with open(target, "r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh)
            if isinstance(loaded, dict):
                data = loaded
        except Exception:
            data = {}

    cfg = _normalize_config(data)
    if path is None:
        cfg = _merge_runtime_globals(cfg)
        _CACHE = cfg
        _CACHE_PATH = target_key
        _CACHE_STAMP = stamp
    return cfg


def clear_allowlist_cache() -> None:
    global _CACHE, _CACHE_PATH, _CACHE_STAMP
    _CACHE = None
    _CACHE_PATH = None
    _CACHE_STAMP = None


def _ip_in_allowlist(ip: Optional[str], cfg: Dict[str, Any]) -> Optional[str]:
    if not ip or not isinstance(ip, str):
        return None
    text = ip.strip()
    if not text:
        return None
    if text in cfg["ips"]:
        return f"ip:{text}"
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    for net in cfg["cidrs"]:
        try:
            if addr in net:
                return f"cidr:{net}"
        except Exception:
            continue
    return None


def _extract_rule_id(alert: Dict[str, Any]) -> Optional[str]:
    if not isinstance(alert, dict):
        return None
    for key in ("rule_id", "wazuh_rule_id"):
        val = alert.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    extras = alert.get("extras") if isinstance(alert.get("extras"), dict) else {}
    for key in ("rule_id", "wazuh_rule_id"):
        val = extras.get(key) if extras else None
        if val is not None and str(val).strip():
            return str(val).strip()
    return None


def match(
    alert: Dict[str, Any],
    *,
    path: Optional[Path | str] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return whether an alert is allowlisted / rule-suppressed.

    Result: ``{"matched": bool, "reasons": [str, ...], "suppress_rule": bool}``
    """
    cfg = config if config is not None else load_allowlists(path)
    reasons: List[str] = []
    suppress_rule = False

    if not isinstance(alert, dict):
        return {"matched": False, "reasons": [], "suppress_rule": False}

    src_ip = alert.get("src_ip") or alert.get("ip") or alert.get("source_ip")
    ip_reason = _ip_in_allowlist(src_ip if isinstance(src_ip, str) else None, cfg)
    if ip_reason:
        reasons.append(ip_reason)

    user = alert.get("user") or alert.get("username")
    if user and str(user).strip().lower() in cfg["users"]:
        reasons.append(f"user:{str(user).strip()}")

    host = alert.get("host") or alert.get("hostname") or alert.get("agent_name")
    if host and str(host).strip().lower() in cfg["hosts"]:
        reasons.append(f"host:{str(host).strip()}")

    rule_id = _extract_rule_id(alert)
    if rule_id and rule_id in cfg["suppress_wazuh_rule_ids"]:
        reasons.append(f"suppress_wazuh_rule_id:{rule_id}")
        suppress_rule = True

    return {
        "matched": bool(reasons),
        "reasons": reasons,
        "suppress_rule": suppress_rule,
    }


def explain_note(match_result: Dict[str, Any]) -> str:
    reasons = match_result.get("reasons") or []
    joined = ", ".join(str(r) for r in reasons) if reasons else "allowlist"
    return (
        f"Allowlist / noise suppress matched ({joined}) — "
        "severity forced low; recommendation ignore. "
        "YAML matches may still be recorded for explainability."
    )
