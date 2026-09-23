"""Offline-first alert enrichment (IP class, assets, optional AbuseIPDB)."""

from __future__ import annotations

import csv
import ipaddress
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_ASSETS_YML = _REPO_ROOT / "config" / "assets.yml"
_DEFAULT_ASSETS_CSV = _REPO_ROOT / "data" / "asset_inventory.csv"

# RFC 5737 TEST-NET and RFC 3849 documentation prefixes.
# CPython marks these is_private (IANA special-purpose). They are not RFC1918.
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

# Cached inventory: keyed by lowercased ip / hostname
_INVENTORY_CACHE: Optional[Dict[str, Dict[str, Any]]] = None


def enrichment_enabled() -> bool:
    raw = os.environ.get("ENRICHMENT_ENABLED", "true")
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _is_documentation_addr(addr: ipaddress._BaseAddress) -> bool:
    return any(addr in net for net in _DOCUMENTATION_NETWORKS)


def classify_ip(ip: Optional[str]) -> Dict[str, Any]:
    """Classify an IP (RFC1918 private, documentation, loopback, public, etc.)."""
    result = {
        "ip": ip,
        "valid": False,
        "version": None,
        "is_private": False,
        "is_documentation": False,
        "is_loopback": False,
        "is_link_local": False,
        "is_multicast": False,
        "is_reserved": False,
        "is_global": False,
        "classification": "unknown",
    }
    if not ip or not isinstance(ip, str):
        result["classification"] = "missing"
        return result
    text = ip.strip()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        result["classification"] = "invalid"
        return result

    result["valid"] = True
    result["version"] = addr.version
    result["is_private"] = bool(addr.is_private)
    result["is_loopback"] = bool(addr.is_loopback)
    result["is_link_local"] = bool(addr.is_link_local)
    result["is_multicast"] = bool(addr.is_multicast)
    result["is_reserved"] = bool(getattr(addr, "is_reserved", False))
    result["is_global"] = bool(getattr(addr, "is_global", False))

    if _is_documentation_addr(addr):
        # Do not inherit CPython's is_private flag for TEST-NET / documentation.
        result["is_private"] = False
        result["is_documentation"] = True
        result["classification"] = "documentation"
    elif addr.is_loopback:
        result["classification"] = "loopback"
    elif addr.is_link_local:
        result["classification"] = "link_local"
    elif addr.is_multicast:
        result["classification"] = "multicast"
    elif addr.is_private:
        result["classification"] = "private"  # RFC1918 / ULA
    elif getattr(addr, "is_reserved", False):
        result["classification"] = "reserved"
    elif getattr(addr, "is_global", False):
        result["classification"] = "public"
    else:
        result["classification"] = "other"
    return result


def _load_assets_yml(path: Path) -> Dict[str, Dict[str, Any]]:
    inv: Dict[str, Dict[str, Any]] = {}
    if yaml is None or not path.is_file():
        return inv
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:
        return inv

    assets = data.get("assets") if isinstance(data, dict) else None
    if not isinstance(assets, list):
        return inv

    for item in assets:
        if not isinstance(item, dict):
            continue
        entry = {
            "name": item.get("name") or item.get("hostname") or item.get("ip"),
            "hostname": item.get("hostname") or item.get("name"),
            "ip": item.get("ip"),
            "criticality": str(item.get("criticality") or item.get("tier") or "normal").lower(),
            "owner": item.get("owner"),
            "tags": item.get("tags") or [],
            "role": item.get("role"),
        }
        for key in (entry.get("ip"), entry.get("hostname"), entry.get("name")):
            if key:
                inv[str(key).strip().lower()] = entry
    return inv


def _load_assets_csv(path: Path) -> Dict[str, Dict[str, Any]]:
    inv: Dict[str, Dict[str, Any]] = {}
    if not path.is_file():
        return inv
    try:
        with open(path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                if not row:
                    continue
                entry = {
                    "name": (row.get("name") or row.get("hostname") or row.get("ip") or "").strip(),
                    "hostname": (row.get("hostname") or row.get("name") or "").strip() or None,
                    "ip": (row.get("ip") or "").strip() or None,
                    "criticality": (row.get("criticality") or row.get("tier") or "normal").strip().lower(),
                    "owner": (row.get("owner") or "").strip() or None,
                    "tags": [t.strip() for t in (row.get("tags") or "").split(",") if t.strip()],
                    "role": (row.get("role") or "").strip() or None,
                }
                for key in (entry.get("ip"), entry.get("hostname"), entry.get("name")):
                    if key:
                        inv[str(key).strip().lower()] = entry
    except Exception:
        return inv
    return inv


def load_asset_inventory(
    *,
    yml_path: Optional[Path] = None,
    csv_path: Optional[Path] = None,
    force_reload: bool = False,
) -> Dict[str, Dict[str, Any]]:
    """Load optional asset inventory (YAML preferred, CSV merge)."""
    global _INVENTORY_CACHE
    if _INVENTORY_CACHE is not None and not force_reload:
        return _INVENTORY_CACHE

    inv: Dict[str, Dict[str, Any]] = {}
    inv.update(_load_assets_yml(Path(yml_path) if yml_path else _DEFAULT_ASSETS_YML))
    # CSV fills gaps / overrides by key
    inv.update(_load_assets_csv(Path(csv_path) if csv_path else _DEFAULT_ASSETS_CSV))
    _INVENTORY_CACHE = inv
    return inv


def lookup_asset(
    *,
    ip: Optional[str] = None,
    host: Optional[str] = None,
    inventory: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    inv = inventory if inventory is not None else load_asset_inventory()
    for key in (ip, host):
        if not key:
            continue
        hit = inv.get(str(key).strip().lower())
        if hit:
            return dict(hit)
    return None


def abuseipdb_lookup(ip: Optional[str]) -> Optional[Dict[str, Any]]:
    """Optional AbuseIPDB check. Skips when no API key or in tests.

    Never called automatically without ABUSEIPDB_API_KEY. Network errors are
    swallowed and returned as notes by the caller.
    """
    api_key = (os.environ.get("ABUSEIPDB_API_KEY") or "").strip()
    if not api_key or not ip:
        return None
    # Explicit skip in pytest / offline
    if os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("ENRICHMENT_OFFLINE") == "1":
        return None
    if classify_ip(ip).get("classification") in (
        "private",
        "documentation",
        "loopback",
        "link_local",
        "missing",
        "invalid",
    ):
        return None

    try:
        import requests

        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        if resp.status_code != 200:
            return {"error": f"http_{resp.status_code}", "ip": ip}
        data = resp.json().get("data") or {}
        return {
            "ip": ip,
            "abuse_confidence": data.get("abuseConfidenceScore"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "country": data.get("countryCode"),
            "total_reports": data.get("totalReports"),
        }
    except Exception as exc:
        return {"error": str(exc), "ip": ip}


def enrich_alert(alert: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Attach enrichment dict + human notes. Offline-first; never raises."""
    notes: List[str] = []
    enrichment: Dict[str, Any] = {
        "enabled": enrichment_enabled(),
        "src_ip": None,
        "dst_ip": None,
        "asset": None,
        "dst_asset": None,
        "abuseipdb": None,
    }

    if not enrichment["enabled"]:
        notes.append("Enrichment disabled via ENRICHMENT_ENABLED")
        return enrichment, notes

    try:
        src = alert.get("src_ip")
        dst = alert.get("dst_ip")
        host = alert.get("host")

        enrichment["src_ip"] = classify_ip(src)
        src_class = enrichment["src_ip"].get("classification")
        if src and src_class == "private":
            notes.append(f"Source IP {src} is RFC1918/private")
        elif src and src_class == "documentation":
            notes.append(f"Source IP {src} is a documentation address")
        elif src and src_class == "public":
            notes.append(f"Source IP {src} is public")

        if dst:
            enrichment["dst_ip"] = classify_ip(dst)

        inventory = load_asset_inventory()
        asset = lookup_asset(ip=src, host=host, inventory=inventory)
        if asset:
            enrichment["asset"] = asset
            crit = asset.get("criticality") or "normal"
            notes.append(
                f"Asset match: {asset.get('name') or asset.get('hostname') or src} "
                f"(criticality={crit})"
            )
            if crit in ("critical", "high"):
                notes.append("Alert involves a high/critical asset")

        if dst:
            dst_asset = lookup_asset(ip=dst, host=None, inventory=inventory)
            if dst_asset:
                enrichment["dst_asset"] = dst_asset

        # Optional external intel — only with key and public IP
        abuse = abuseipdb_lookup(src)
        if abuse is not None:
            enrichment["abuseipdb"] = abuse
            if abuse.get("error"):
                notes.append(f"AbuseIPDB skipped/error: {abuse.get('error')}")
            else:
                conf = abuse.get("abuse_confidence")
                notes.append(f"AbuseIPDB confidence={conf}")
    except Exception as exc:
        notes.append(f"Enrichment error (ignored): {exc}")

    return enrichment, notes
