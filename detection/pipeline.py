"""Detection pipeline: normalize → enrich → allowlist → YAML rules → scoped suppress/mute → triage compose."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from detection.allowlists import explain_note, match as allowlist_match
from detection.enrichment import enrich_alert
from detection.normalize import normalize_alert
from rules.engine import evaluate_rules, max_severity


def _recommendation_for(severity: str) -> str:
    sev = (severity or "low").lower()
    if sev in ("high", "critical"):
        return "escalate"
    if sev == "medium":
        return "investigate"
    return "ignore"


def process_alert(
    raw: Any,
    *,
    tenant_id: str = "local",
    run_ml: bool = True,
    rules_dir: Optional[Any] = None,
    allowlist_path: Optional[Any] = None,
) -> Dict[str, Any]:
    """Run Phase A detection and compose with existing triage_engine.

    Returns a result dict including:
      severity, recommendation, rule_severity, matched_rules, enrichment,
      ml_* assist fields, normalized alert, notes, allowlist match info.
    """
    alert = normalize_alert(raw, tenant_id=tenant_id)
    enrichment, notes = enrich_alert(alert)

    # Allowlist / Wazuh rule-id suppress (after normalize+enrich; before escalation).
    # An explicit allowlist_path keeps unit tests off the operator runtime file.
    al_match = allowlist_match(alert, path=allowlist_path)
    classic_allowlisted = bool(al_match.get("matched"))

    yaml_result = evaluate_rules(
        alert,
        enrichment,
        rules_dir=rules_dir,
    )
    matched_rules: List[Dict[str, Any]] = yaml_result.get("matched_rules") or []
    yaml_sev = yaml_result.get("recommended_severity")
    top_rule_early = matched_rules[0].get("id") if matched_rules else None

    scoped: Dict[str, Any] = {"matched": False, "reasons": [], "kind": None, "expires_at": None, "bucket": {}}
    if allowlist_path is None:
        try:
            from detection.suppressions import match_scoped

            scoped = match_scoped(alert, matched_rule_id=top_rule_early)
        except Exception:
            notes.append("Suppress check unavailable.")

    muted = bool(scoped.get("matched")) and scoped.get("kind") == "mute" and not classic_allowlisted
    allowlisted = classic_allowlisted or (
        bool(scoped.get("matched")) and scoped.get("kind") != "mute"
    )
    suppressed = classic_allowlisted or bool(scoped.get("matched"))
    if classic_allowlisted:
        notes.append(explain_note(al_match))
    if scoped.get("matched"):
        try:
            from detection.suppressions import explain_scoped

            notes.append(explain_scoped(scoped))
        except Exception:
            notes.append("Suppress matched — severity forced low; recommendation ignore.")

    # Compose with existing keyword + ML triage (assist-only preserved inside)
    triage: Dict[str, Any] = {}
    if run_ml:
        try:
            from triage_engine import (
                analyze_log,
                format_ml_assist_display,
                get_ml_assist_only,
                get_ml_confidence_threshold,
                resolve_display_severity,
            )

            triage = analyze_log(
                alert.get("raw_message") or "",
                event_type=alert.get("rule_description") or alert.get("extras", {}).get("event_type") or "",
                description=alert.get("rule_description") or alert.get("raw_message") or "",
                username=alert.get("user") or "",
                timestamp=alert.get("timestamp"),
                source_ip=alert.get("src_ip") or "",
            )
        except Exception as exc:
            notes.append(f"triage_engine unavailable: {exc}")
            triage = {}
    else:
        from triage_engine import classify_severity

        keyword_sev = classify_severity(alert.get("raw_message") or "")
        triage = {
            "severity": keyword_sev,
            "rule_severity": keyword_sev,
            "recommendation": _recommendation_for(keyword_sev),
            "ml_severity": None,
            "ml_confidence": 0.0,
            "severity_source": "rules",
            "ml_assist": True,
            "ip": alert.get("src_ip"),
            "user": alert.get("user"),
        }

    keyword_sev = (triage.get("rule_severity") or triage.get("severity") or "low")
    # Combined rule severity = max(YAML, keyword rules) — skipped when allowlisted
    candidates = [keyword_sev]
    if yaml_sev:
        candidates.append(yaml_sev)

    if suppressed:
        combined_rule_sev = "low"
    else:
        combined_rule_sev = max_severity(candidates)

    ml_sev = triage.get("ml_severity")
    ml_conf = triage.get("ml_confidence") or 0.0

    try:
        from triage_engine import (
            format_ml_assist_display,
            get_ml_assist_only,
            get_ml_confidence_threshold,
            resolve_display_severity,
        )

        if suppressed:
            # Keep ML assist display fields, but never let ML raise severity for suppressed noise.
            resolved = {
                "severity": "low",
                "severity_source": "mute" if muted else "allowlist",
                "ml_assist": True,
                "ml_used_for_display": False,
                "low_confidence": True,
            }
            ml_display = format_ml_assist_display(
                ml_sev,
                ml_conf,
                threshold=get_ml_confidence_threshold(),
                assist_only=True,
            )
        else:
            resolved = resolve_display_severity(
                combined_rule_sev,
                ml_sev,
                ml_conf,
                threshold=get_ml_confidence_threshold(),
                assist_only=get_ml_assist_only(),
            )
            ml_display = format_ml_assist_display(
                ml_sev,
                ml_conf,
                threshold=get_ml_confidence_threshold(),
                assist_only=get_ml_assist_only(),
            )
    except Exception:
        resolved = {
            "severity": "low" if suppressed else combined_rule_sev,
            "severity_source": ("mute" if muted else "allowlist") if suppressed else "rules",
            "ml_assist": True,
            "ml_used_for_display": False,
            "low_confidence": True,
        }
        ml_display = {
            "label": "ML unavailable",
            "confidence_pct": 0,
            "used": False,
            "low_confidence": True,
            "assist_only": True,
            "ml_severity": None,
        }

    recommendation = "ignore" if suppressed else _recommendation_for(combined_rule_sev)

    # Prefer extracted fields from normalize; fall back to triage NLP
    ip = alert.get("src_ip") or triage.get("ip")
    user = alert.get("user") or triage.get("user")

    top_explain = None
    top_rule_id = None
    if matched_rules:
        top_rule_id = matched_rules[0].get("id")
        top_explain = matched_rules[0].get("explain")
    if suppressed:
        note_parts = []
        if classic_allowlisted:
            note_parts.append(explain_note(al_match))
        if scoped.get("matched"):
            try:
                from detection.suppressions import explain_scoped

                note_parts.append(explain_scoped(scoped))
            except Exception:
                note_parts.append("Suppress matched — severity forced low; recommendation ignore.")
        if note_parts:
            prefix = " ".join(note_parts)
            top_explain = prefix + (f" | {top_explain}" if top_explain else "")

    result = {
        "log": alert.get("raw_message") or triage.get("log") or "",
        "ip": ip,
        "user": user,
        "host": alert.get("host"),
        "file_hash": alert.get("file_hash"),
        "domain": alert.get("domain"),
        "cve": alert.get("cve"),
        "severity": "low" if suppressed else resolved["severity"],
        "recommendation": recommendation,
        "rule_based": recommendation,
        "rule_severity": combined_rule_sev,
        "yaml_severity": yaml_sev,
        "keyword_severity": str(keyword_sev).lower() if keyword_sev else None,
        "ml_severity": ml_sev,
        "ml_prediction": ml_sev,
        "ml_confidence": ml_conf,
        "severity_source": resolved.get("severity_source") or (("mute" if muted else "allowlist") if suppressed else "rules"),
        "ml_assist": resolved.get("ml_assist", True),
        "ml_display_label": ml_display.get("label"),
        "ml_used_for_display": resolved.get("ml_used_for_display", False),
        "low_confidence": resolved.get("low_confidence", True),
        "matched_rules": matched_rules,
        "matched_rule_id": top_rule_id,
        "rule_explain": top_explain,
        "enrichment": enrichment,
        "enrichment_notes": notes,
        "allowlisted": allowlisted,
        "muted": bool(scoped.get("matched")) and scoped.get("kind") == "mute",
        "allowlist_reasons": list(al_match.get("reasons") or []) + list(scoped.get("reasons") or []),
        "suppress_bucket": (scoped.get("bucket") or None),
        "alert": alert,
        "tenant_id": alert.get("tenant_id") or tenant_id,
        "source": alert.get("source"),
        "timestamp": alert.get("timestamp"),
    }
    return result
