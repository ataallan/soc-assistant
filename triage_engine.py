import os
import joblib
import re
import pandas as pd
from nlp_utils import extract_ip, extract_user
from datetime import datetime
import socket
import struct
from scipy.sparse import hstack

MODEL_FILE = "soc_model.pkl"
VECTORIZER_FILE = "vectorizer.pkl"
SCALER_FILE = "scaler.pkl"
LABEL_ENCODER_FILE = "label_encoder.pkl"

# -------------------- Helper Functions --------------------

def ip_to_int(ip):
    """Convert IPv4 string to integer."""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return 0

def load_ml_model():
    """Load trained ML model and preprocessing objects."""
    if not all(os.path.exists(f) for f in [MODEL_FILE, VECTORIZER_FILE, SCALER_FILE, LABEL_ENCODER_FILE]):
        print("⚠️ ML model or dependencies not found. Falling back to rule-based.")
        return None, None, None, None

    model = joblib.load(MODEL_FILE)
    vectorizer = joblib.load(VECTORIZER_FILE)
    scaler = joblib.load(SCALER_FILE)
    label_encoder = joblib.load(LABEL_ENCODER_FILE)
    return model, vectorizer, scaler, label_encoder

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

    if "failed login" in log_l:
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

def ml_predict_severity(event_type="", description="", username="", timestamp=None, source_ip="") -> str:
    """Predict severity using ML model."""
    if ML_MODEL is None:
        return None  # fallback to rule-based

    # Prepare text
    text = f"{event_type} {description} {username}"

    # Vectorize text
    X_text_vec = VECTORIZER.transform([text])

    # Numeric features
    if timestamp is None:
        timestamp_num = 0
    else:
        try:
            timestamp_num = int(pd.to_datetime(timestamp).timestamp())
        except:
            timestamp_num = 0

    source_ip_num = ip_to_int(source_ip)

    X_numeric_scaled = SCALER.transform([[timestamp_num, source_ip_num]])

    # Combine features
    X_combined = hstack([X_text_vec, X_numeric_scaled])

    # Predict
    y_pred = ML_MODEL.predict(X_combined)
    severity = LABEL_ENCODER.inverse_transform(y_pred)[0]
    return severity

# -------------------- Main analysis --------------------

def analyze_log(log: str, event_type="", description="", username="", timestamp=None, source_ip="") -> dict:
    """Returns structured analysis: log, ip, user, severity, recommendation"""

    try:
        ip = extract_ip(log) if not source_ip else source_ip
    except:
        ip = source_ip or None

    try:
        user = extract_user(log) if not username else username
    except:
        user = username or None

    # ML prediction (fallback to rule-based)
    severity = ml_predict_severity(event_type, description, username, timestamp, ip)
    if severity is None:
        severity = classify_severity(log)

    recommendation = rule_based_triage(log)

    return {
        "log": log,
        "ip": ip,
        "user": user,
        "severity": severity,
        "recommendation": recommendation
    }
