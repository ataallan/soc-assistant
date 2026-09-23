import os
import joblib
import re
import pandas as pd
from nlp_utils import extract_ip, extract_user
from scipy.sparse import hstack
import numpy as np

MODEL_FILE = "soc_model.pkl"
VECTORIZER_FILE = "vectorizer.pkl"
SCALER_FILE = "scaler.pkl"
LABEL_ENCODER_FILE = "label_encoder.pkl"

# Default ML confidence for hybrid severity + auto-containment (override via env).
def get_ml_confidence_threshold() -> float:
    """Read ML_CONFIDENCE_THRESHOLD from env; default 0.70."""
    raw = os.environ.get("ML_CONFIDENCE_THRESHOLD", "0.70")
    try:
        val = float(raw)
        if 0.0 <= val <= 1.0:
            return val
    except (TypeError, ValueError):
        pass
    return 0.70


# Back-compat module attribute (tests / callers may read it).
ML_CONFIDENCE_THRESHOLD = get_ml_confidence_threshold()


def get_ml_assist_only() -> bool:
    """Read ML_ASSIST_ONLY from env; default True (honest assist-only mode)."""
    raw = os.environ.get("ML_ASSIST_ONLY", "true")
    if raw is None:
        return True
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


ML_ASSIST_ONLY = get_ml_assist_only()


def resolve_display_severity(
    rule_severity: str,
    ml_severity=None,
    ml_confidence: float = 0.0,
    *,
    threshold: float = None,
    assist_only: bool = None,
) -> dict:
    """Choose operator-facing severity and honesty metadata.

    Policy:
    - Always keep ML prediction + confidence for analytics (caller stores them).
    - Rules ``critical`` always wins for displayed severity.
    - If ``assist_only`` (default) OR confidence < threshold OR ML missing:
      displayed severity = rules; ``severity_source=rules``; ``ml_assist=True``.
    - Else (override mode with confident ML): displayed = ML;
      ``severity_source=ml`` (or ``hybrid`` when equal to rules).
    """
    if threshold is None:
        threshold = get_ml_confidence_threshold()
    if assist_only is None:
        assist_only = get_ml_assist_only()

    rule_sev = (rule_severity or "low").strip().lower()
    ml_sev = None if ml_severity is None else str(ml_severity).strip().lower()
    try:
        conf = float(ml_confidence or 0.0)
    except (TypeError, ValueError):
        conf = 0.0

    if rule_sev == "critical":
        source = "rules"
        if ml_sev == "critical" and conf >= float(threshold) and not assist_only:
            source = "hybrid"
        return {
            "severity": "critical",
            "severity_source": source,
            "ml_assist": True if assist_only else (source != "ml"),
            "ml_used_for_display": False if assist_only or source == "rules" else True,
            "low_confidence": conf < float(threshold) if ml_sev is not None else True,
        }

    low_conf = ml_sev is None or conf < float(threshold)
    if assist_only or low_conf:
        return {
            "severity": rule_sev,
            "severity_source": "rules",
            "ml_assist": True,
            "ml_used_for_display": False,
            "low_confidence": True if ml_sev is None else low_conf,
        }

    source = "hybrid" if ml_sev == rule_sev else "ml"
    return {
        "severity": ml_sev,
        "severity_source": source,
        "ml_assist": False,
        "ml_used_for_display": True,
        "low_confidence": False,
    }


def format_ml_assist_display(
    ml_severity=None,
    ml_confidence: float = 0.0,
    *,
    threshold: float = None,
    assist_only: bool = None,
) -> dict:
    """UI-facing ML assist label (never a bold wrong primary severity).

    Returns: label, confidence_pct, used, low_confidence, assist_only, ml_severity.
    """
    if threshold is None:
        threshold = get_ml_confidence_threshold()
    if assist_only is None:
        assist_only = get_ml_assist_only()

    try:
        conf = float(ml_confidence or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    pct = int(round(max(0.0, min(1.0, conf)) * 100))
    ml_sev = None if ml_severity is None else str(ml_severity).strip().lower()

    if ml_sev is None:
        return {
            "label": "ML unavailable",
            "confidence_pct": 0,
            "used": False,
            "low_confidence": True,
            "assist_only": bool(assist_only),
            "ml_severity": None,
        }

    low = conf < float(threshold)
    if low:
        label = f"Low confidence — not used ({pct}%)"
        used = False
    else:
        label = f"ML assist: {ml_sev} ({pct}%)"
        used = not assist_only

    return {
        "label": label,
        "confidence_pct": pct,
        "used": used,
        "low_confidence": low,
        "assist_only": bool(assist_only),
        "ml_severity": ml_sev,
    }


# -------------------- Helper Functions --------------------

def _artifact_paths():
    """Live artifact paths. SOC_MODEL_ROOT overrides the process working directory."""
    root = (os.environ.get("SOC_MODEL_ROOT") or "").strip()
    names = (MODEL_FILE, VECTORIZER_FILE, SCALER_FILE, LABEL_ENCODER_FILE)
    if not root:
        return names
    base = os.path.abspath(root)
    return tuple(os.path.join(base, name) for name in names)


def load_ml_model():
    """Load trained ML model and preprocessing objects."""
    paths = _artifact_paths()
    if not all(os.path.exists(f) for f in paths):
        print("⚠️ ML model or dependencies not found. Falling back to rule-based.")
        return None, None, None, None

    model = joblib.load(paths[0])
    vectorizer = joblib.load(paths[1])
    scaler = joblib.load(paths[2])
    label_encoder = joblib.load(paths[3])
    return model, vectorizer, scaler, label_encoder


def reload_ml_model():
    """Reload live artifacts after a checkpoint is activated."""
    global ML_MODEL, VECTORIZER, SCALER, LABEL_ENCODER
    ML_MODEL, VECTORIZER, SCALER, LABEL_ENCODER = load_ml_model()
    return ML_MODEL is not None

# Load model at import
ML_MODEL, VECTORIZER, SCALER, LABEL_ENCODER = load_ml_model()

# -------------------- Rule-based logic --------------------

def classify_severity(log: str) -> str:
    log_l = log.lower()

    CRITICAL = [
        "root login", "domain admin", "privilege escalation", "lateral movement",
        "mimikatz", "credential dumping", "data exfiltration", "ransomware",
        "malware", "reverse shell", "c2 communication", "command and control",
        "persistence established"
    ]

    HIGH = [
        "brute force", "excessive authentication failures", "multiple authentication failures",
        "rdp authentication", "vpn gateway rejected", "login failure spikes",
        "foreign ip login", "multiple failed login attempts", "password spraying",
        "authentication storm"
    ]

    # Numeric brute-force detection
    number_pattern = r"(\d+)\s+(attempts|times|failures?)"
    numbers = re.findall(number_pattern, log_l)
    if numbers:
        counts = [int(n) for n, _ in numbers]
        max_attempts = max(counts)
        if max_attempts >= 10:
            return "critical"
        elif max_attempts >= 5:
            return "high"

    # Phrase-based detection
    for phrase in CRITICAL:
        if phrase in log_l:
            return "critical"
    for phrase in HIGH:
        if phrase in log_l:
            return "high"

    # sshd invalid-user wording does not contain the phrase "failed login".
    # Word-boundary so "invalid username" (login-form copy) stays low.
    if (
        "failed login" in log_l
        or "non-existent user" in log_l
        or "nonexistent user" in log_l
        or re.search(r"\binvalid user\b", log_l)
    ):
        return "medium"

    return "low"

def rule_based_triage(log: str) -> str:
    sev = classify_severity(log)
    if sev in ["high", "critical"]:
        return "escalate"
    if sev == "medium":
        return "investigate"
    return "ignore"

# -------------------- ML-based triage --------------------

def _hour_from_timestamp(timestamp) -> float:
    if timestamp is None:
        return 0.0
    try:
        ts = pd.to_datetime(timestamp, errors="coerce", utc=True)
        if pd.isna(ts):
            return 0.0
        return float(ts.hour)
    except Exception:
        return 0.0


def ml_predict_severity(event_type="", description="", username="", timestamp=None, source_ip=""):
    """Predict severity using ML model.

    Returns (severity, confidence) or (None, 0.0) if model unavailable.
    Confidence is max predicted class probability when available.
    """
    if ML_MODEL is None or VECTORIZER is None or SCALER is None or LABEL_ENCODER is None:
        return None, 0.0

    text = f"{event_type} {description} {username}"
    X_text_vec = VECTORIZER.transform([text])

    hour = _hour_from_timestamp(timestamp)
    X_numeric_scaled = SCALER.transform(np.array([[hour]], dtype=float))

    X_combined = hstack([X_text_vec, X_numeric_scaled])

    y_pred = ML_MODEL.predict(X_combined)
    severity = LABEL_ENCODER.inverse_transform(y_pred)[0]

    confidence = 0.0
    if hasattr(ML_MODEL, "predict_proba"):
        try:
            proba = ML_MODEL.predict_proba(X_combined)[0]
            confidence = float(np.max(proba))
        except Exception:
            confidence = 0.0

    return severity, confidence

# -------------------- Main analysis --------------------

def analyze_log(log: str, event_type="", description="", username="", timestamp=None, source_ip="") -> dict:
    """Returns structured analysis: log, ip, user, severity, recommendation.

    Honest assist-only policy (default ``ML_ASSIST_ONLY=true``):
    - Rules severity/recommendation are the primary operator-facing fields.
    - ML prediction + confidence are always computed for analytics.
    - If assist-only OR confidence < threshold: ML does not override displayed severity.
    - Rules saying ``critical`` always win.
    - When assist-only is disabled and confidence is high, ML may set displayed severity
      (``severity_source`` = ml|hybrid).
    """

    try:
        ip = extract_ip(log) if not source_ip else source_ip
    except Exception:
        ip = source_ip or None

    try:
        user = extract_user(log) if not username else username
    except Exception:
        user = username or None

    rule_severity = classify_severity(log)
    ml_severity, ml_confidence = ml_predict_severity(
        event_type, description, username, timestamp, ip
    )

    resolved = resolve_display_severity(
        rule_severity,
        ml_severity,
        ml_confidence,
        threshold=get_ml_confidence_threshold(),
        assist_only=get_ml_assist_only(),
    )
    severity = resolved["severity"]
    recommendation = rule_based_triage(log)  # always rules-based
    ml_display = format_ml_assist_display(
        ml_severity,
        ml_confidence,
        threshold=get_ml_confidence_threshold(),
        assist_only=get_ml_assist_only(),
    )

    return {
        "log": log,
        "ip": ip,
        "user": user,
        "severity": severity,
        "recommendation": recommendation,
        "ml_confidence": ml_confidence,
        "ml_severity": ml_severity,
        "rule_severity": rule_severity,
        "severity_source": resolved["severity_source"],
        "ml_assist": resolved["ml_assist"],
        "ml_display_label": ml_display["label"],
        "ml_used_for_display": resolved["ml_used_for_display"],
        "low_confidence": resolved["low_confidence"],
    }


# -------------------- Auto-containment agreement gate --------------------

_ESCALATE_SEVERITIES = frozenset({"high", "critical"})
_ML_HIGH_AGREE = frozenset({"high", "critical"})  # ML has no critical class; map both


def should_auto_contain(
    rule_severity: str,
    ml_severity=None,
    ml_confidence: float = 0.0,
    threshold: float = None,
) -> dict:
    """Decide whether automatic containment is allowed.

    Policy:
    - Rules must escalate (high/critical).
    - Rules ``critical`` alone may contain (audit: rules_critical).
    - Otherwise ML must agree on high/critical with confidence >= threshold.
    - If ML is missing: rules-only escalate may contain (audit: rules_only).
    - Disagreement or low confidence → do not contain.

    Returns dict: allow, reason, operator_note, threshold, rule_severity,
    ml_severity, ml_confidence.
    """
    if threshold is None:
        threshold = get_ml_confidence_threshold()

    rule_sev = (rule_severity or "low").strip().lower()
    ml_sev = None if ml_severity is None else str(ml_severity).strip().lower()
    try:
        conf = float(ml_confidence or 0.0)
    except (TypeError, ValueError):
        conf = 0.0

    base = {
        "rule_severity": rule_sev,
        "ml_severity": ml_sev,
        "ml_confidence": conf,
        "threshold": float(threshold),
    }

    if rule_sev not in _ESCALATE_SEVERITIES:
        return {
            **base,
            "allow": False,
            "reason": "rules_not_escalate",
            "operator_note": "Containment skipped — rules did not call for escalation.",
        }

    # Critical from rules: allow without requiring ML agreement.
    if rule_sev == "critical":
        return {
            **base,
            "allow": True,
            "reason": "rules_critical",
            "operator_note": "Containment allowed — rules marked critical (rules-only override).",
        }

    # ML unavailable → rules-only for escalate (high).
    if ml_sev is None:
        return {
            **base,
            "allow": True,
            "reason": "rules_only",
            "operator_note": "Containment allowed — rules escalate; ML model unavailable (rules_only).",
        }

    if conf < float(threshold):
        return {
            **base,
            "allow": False,
            "reason": "low_confidence",
            "operator_note": "Containment skipped — model confidence below threshold.",
        }

    if ml_sev not in _ML_HIGH_AGREE:
        return {
            **base,
            "allow": False,
            "reason": "disagreement",
            "operator_note": "Containment skipped — model and rules did not agree.",
        }

    return {
        **base,
        "allow": True,
        "reason": "agreement",
        "operator_note": "Containment allowed — rules and model agree on high severity.",
    }

