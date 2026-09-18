"""YAML detection rule loader and evaluator."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise ImportError("PyYAML is required for the YAML rule engine. pip install PyYAML") from exc

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_RULES_DIR = Path(__file__).resolve().parent

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_RULE_CACHE: Optional[List[Dict[str, Any]]] = None


def severity_rank(sev: Optional[str]) -> int:
    if not sev:
        return 0
    return SEVERITY_RANK.get(str(sev).strip().lower(), 0)


def max_severity(severities: List[Optional[str]]) -> str:
    best = "low"
    best_rank = -1
    for s in severities:
        r = severity_rank(s)
        if r > best_rank:
            best_rank = r
            best = str(s).strip().lower() if s else "low"
    if best_rank < 0:
        return "low"
    return best


def get_by_path(obj: Any, path: str) -> Any:
    """Resolve dotted path; supports enrichment.asset.criticality style."""
    if not path:
        return None
    cur = obj
    for part in str(path).split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _coerce_str(val: Any) -> str:
    if val is None:
        return ""
    return str(val)


def eval_condition(alert_ctx: Dict[str, Any], cond: Dict[str, Any]) -> bool:
    """Evaluate a single condition against alert context.

    Supported ops: eq, contains, regex, in_list, exists
    Keys: field (dotted path), op, value / values
    """
    if not isinstance(cond, dict):
        return False
    field = cond.get("field") or cond.get("path")
    op = str(cond.get("op") or cond.get("operator") or "eq").strip().lower()
    value = cond.get("value")
    values = cond.get("values")

    actual = get_by_path(alert_ctx, field) if field else None

    if op == "exists":
        expect = True if value is None else bool(value)
        present = actual is not None and actual != ""
        return present if expect else not present

    if op == "eq":
        if actual is None and value is None:
            return True
        return _coerce_str(actual).lower() == _coerce_str(value).lower()

    if op == "contains":
        hay = _coerce_str(actual).lower()
        needle = _coerce_str(value).lower()
        return bool(needle) and needle in hay

    if op == "regex":
        try:
            pattern = _coerce_str(value)
            if not pattern:
                return False
            return re.search(pattern, _coerce_str(actual), re.IGNORECASE) is not None
        except re.error:
            return False

    if op == "in_list":
        opts = values if isinstance(values, list) else value
        if not isinstance(opts, list):
            opts = [opts]
        actual_l = _coerce_str(actual).lower()
        return any(actual_l == _coerce_str(o).lower() for o in opts)

    return False


def eval_conditions(alert_ctx: Dict[str, Any], conditions: Any) -> bool:
    """All conditions must match (AND). Empty list → no match."""
    if not conditions:
        return False
    if not isinstance(conditions, list):
        conditions = [conditions]
    return all(eval_condition(alert_ctx, c) for c in conditions)


def _render_explain(template: Optional[str], alert_ctx: Dict[str, Any], rule: Dict[str, Any]) -> str:
    text = template or rule.get("name") or rule.get("id") or "matched"
    # Simple {field} substitution from alert context top-level + nested via dots
    def repl(match: re.Match) -> str:
        key = match.group(1)
        if key == "rule_id":
            return str(rule.get("id") or "")
        if key == "rule_name":
            return str(rule.get("name") or "")
        val = get_by_path(alert_ctx, key)
        return "" if val is None else str(val)

    try:
        return re.sub(r"\{([a-zA-Z0-9_.]+)\}", repl, str(text))
    except Exception:
        return str(text)


def load_rules(
    rules_dir: Optional[Path] = None,
    *,
    force_reload: bool = False,
) -> List[Dict[str, Any]]:
    """Load all *.yml / *.yaml rule files from rules_dir."""
    global _RULE_CACHE
    if _RULE_CACHE is not None and not force_reload and rules_dir is None:
        return _RULE_CACHE

    directory = Path(rules_dir) if rules_dir else _DEFAULT_RULES_DIR
    loaded: List[Dict[str, Any]] = []
    if not directory.is_dir():
        return loaded

    for path in sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml")):
        # Skip non-rule docs if any
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except Exception:
            continue

        rules_list: List[Any] = []
        if isinstance(data, dict) and "rules" in data:
            rules_list = data.get("rules") or []
        elif isinstance(data, dict) and data.get("id"):
            rules_list = [data]
        elif isinstance(data, list):
            rules_list = data
        else:
            continue

        for rule in rules_list:
            if not isinstance(rule, dict) or not rule.get("id"):
                continue
            rule = dict(rule)
            rule["_source_file"] = str(path.name)
            loaded.append(rule)

    if rules_dir is None:
        _RULE_CACHE = loaded
    return loaded


def evaluate_rules(
    alert: Dict[str, Any],
    enrichment: Optional[Dict[str, Any]] = None,
    *,
    rules: Optional[List[Dict[str, Any]]] = None,
    rules_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Evaluate YAML rules against normalized alert (+ enrichment).

    Returns:
      matched_rules: list of {id, name, severity, priority, mitre, explain}
      recommended_severity: max severity among matches (or None if none)
    """
    rule_list = rules if rules is not None else load_rules(rules_dir)

    # Flatten context: alert fields + enrichment nested
    ctx: Dict[str, Any] = dict(alert) if isinstance(alert, dict) else {}
    if enrichment:
        ctx["enrichment"] = enrichment
        # Convenience aliases for rules
        src_meta = enrichment.get("src_ip") or {}
        if isinstance(src_meta, dict):
            ctx.setdefault("src_ip_class", src_meta.get("classification"))
            ctx.setdefault("src_is_private", src_meta.get("is_private"))
        asset = enrichment.get("asset") or {}
        if isinstance(asset, dict):
            ctx.setdefault("asset_criticality", asset.get("criticality"))
            ctx.setdefault("asset_name", asset.get("name") or asset.get("hostname"))

    # Also search raw_message / rule_description as text blob helpers
    ctx.setdefault(
        "text",
        " ".join(
            str(x)
            for x in (
                alert.get("raw_message"),
                alert.get("rule_description"),
                alert.get("user"),
                alert.get("host"),
            )
            if x
        ),
    )

    matched: List[Dict[str, Any]] = []
    for rule in rule_list:
        if rule.get("enabled") is False:
            continue
        conditions = rule.get("conditions") or []
        try:
            if not eval_conditions(ctx, conditions):
                continue
        except Exception:
            continue

        explain = _render_explain(rule.get("explain"), ctx, rule)
        matched.append(
            {
                "id": rule.get("id"),
                "name": rule.get("name"),
                "severity": str(rule.get("severity") or "medium").lower(),
                "priority": int(rule.get("priority") or 0),
                "mitre": rule.get("mitre"),
                "explain": explain,
            }
        )

    # Highest priority first, then severity
    matched.sort(
        key=lambda m: (int(m.get("priority") or 0), severity_rank(m.get("severity"))),
        reverse=True,
    )

    recommended = None
    if matched:
        recommended = max_severity([m.get("severity") for m in matched])

    return {
        "matched_rules": matched,
        "recommended_severity": recommended,
    }
