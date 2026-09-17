import os
import time
import threading
import json
import pandas as pd
import joblib
from datetime import datetime
import smtplib
from email.message import EmailMessage
import socket
import struct
from scipy.sparse import hstack
from dotenv import load_dotenv

load_dotenv()

from containment import (
    execute_block_ip as _contain_block_ip,
    execute_block_user as _contain_block_user,
    execute_unblock_ip as _contain_unblock_ip,
    execute_unblock_user as _contain_unblock_user,
    load_blocked,
    get_mode_label,
)

# ------------------------------------------------------------
# UNIFIED TRIAGE REPORT SCHEMA
# ------------------------------------------------------------
REPORT_FIELDS = [
    "timestamp",
    "log",
    "ip",
    "user",
    "severity",
    "rule_based",
    "ml_prediction"
]

def normalize_report_row(result: dict):
    """Force every saved triage row to use the same schema."""
    normalized = {}
    for field in REPORT_FIELDS:
        normalized[field] = result.get(field, None)
    return normalized

# ------------------------------------------------------------------------
# SAFE IMPORTS
# ------------------------------------------------------------------------
try:
    from triage_engine import analyze_log
except Exception:
    def analyze_log(log, **kwargs):
        return {"severity": "low", "recommendation": "monitor", "user": None, "ip": None}

try:
    from train_model import train_ml_model
except Exception:
    def train_ml_model(path):
        print("⚠ train_ml_model fallback — no training performed for:", path)

try:
    from wazuh_integration import fetch_wazuh_alerts, fetch_wazuh_alert_details
except Exception:
    def fetch_wazuh_alerts(limit=50):
        return []
    def fetch_wazuh_alert_details(limit=50):
        return []

# ------------------------------------------------------------------------
# FILE PATHS
# ------------------------------------------------------------------------
DATA_DIR = "data"
REPORT_FILE_CSV = os.path.join(DATA_DIR, "triage_report.csv")
REPORT_FILE_JSONL = os.path.join(DATA_DIR, "triage_report.jsonl")
HIGH_RISK_FILE_CSV = os.path.join(DATA_DIR, "high_risk_events.csv")
BLOCKED_ENTITIES_FILE = os.path.join(DATA_DIR, "blocked_entities.json")

os.makedirs(DATA_DIR, exist_ok=True)

# ------------------------------------------------------------------------
# BLOCK TRACKER
# ------------------------------------------------------------------------
blocked_entities = load_blocked()

def save_blocked_entities():
    from containment import save_blocked
    save_blocked(blocked_entities)


# ------------------------------------------------------------------------
# EMAIL SETTINGS
# ------------------------------------------------------------------------
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
RECIPIENT_EMAIL = os.environ.get("RECIPIENT_EMAIL", "")

def send_email(subject: str, body: str, recipient_email: str = None):
    recipient_email = recipient_email or RECIPIENT_EMAIL
    if not SMTP_USER or not SMTP_PASS or not recipient_email:
        print("⚠ Email skipped: set SMTP_USER, SMTP_PASS, and RECIPIENT_EMAIL in .env")
        return
    try:
        msg = EmailMessage()
        msg["From"] = SMTP_USER
        msg["To"] = recipient_email
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        print(f"📧 Email sent: {subject}")
    except Exception as e:
        print(f"⚠ Email failed: {e}")

# ------------------------------------------------------------------------
# ML MODEL (FULL PIPELINE)
# ------------------------------------------------------------------------
MODEL = None
VECTORIZER = None
SCALER = None
LABEL_ENCODER = None

def load_model_once():
    """Load model, vectorizer, scaler, and label encoder exactly like train_model.py."""
    global MODEL, VECTORIZER, SCALER, LABEL_ENCODER

    if MODEL is None:
        try:
            if os.path.exists("soc_model.pkl"):
                MODEL = joblib.load("soc_model.pkl")
            if os.path.exists("vectorizer.pkl"):
                VECTORIZER = joblib.load("vectorizer.pkl")
            if os.path.exists("scaler.pkl"):
                SCALER = joblib.load("scaler.pkl")
            if os.path.exists("label_encoder.pkl"):
                LABEL_ENCODER = joblib.load("label_encoder.pkl")

            print("🤖 ML components loaded (model + vectorizer + scaler + label_encoder)")
        except Exception as e:
            print("⚠ Error loading ML components:", e)

# ------------------------------------------------------------------------
# BLOCKING OPERATIONS
# ------------------------------------------------------------------------
def execute_block_ip(ip: str):
    result = _contain_block_ip(ip)
    blocked_entities.clear()
    blocked_entities.update(load_blocked())
    return result


def execute_block_user(user: str):
    result = _contain_block_user(user)
    blocked_entities.clear()
    blocked_entities.update(load_blocked())
    return result


def execute_unblock_ip(ip: str):
    result = _contain_unblock_ip(ip)
    blocked_entities.clear()
    blocked_entities.update(load_blocked())
    return result


def execute_unblock_user(user: str):
    result = _contain_unblock_user(user)
    blocked_entities.clear()
    blocked_entities.update(load_blocked())
    return result


# ------------------------------------------------------------------------
# UNBLOCK MENU
# ------------------------------------------------------------------------
def unblock_entity():
    print("\n--- BLOCKED ENTITIES ---")
    print("Blocked IPs:", blocked_entities["ips"])
    print("Blocked Users:", blocked_entities["users"])

    target = input("\nEnter IP/User to UNBLOCK: ").strip()

    if target in blocked_entities["ips"]:
        execute_unblock_ip(target)
        return

    if target in blocked_entities["users"]:
        execute_unblock_user(target)
        return

    print("⚠ Target is NOT currently blocked.")

# ------------------------------------------------------------------------
# VIEW REPORT
# ------------------------------------------------------------------------
def view_report():
    if not os.path.exists(REPORT_FILE_CSV):
        print("⚠ No report found.")
        return

    df = pd.read_csv(REPORT_FILE_CSV)
    if df.empty:
        print("⚠ Report is empty.")
        return

    print("\n📊 Last 10 Triage Entries:")
    print(df.tail(10).to_string(index=False))

# ------------------------------------------------------------------------
# MAIN ANALYSIS PIPELINE (WITH MATCHED ML PREDICTION)
# ------------------------------------------------------------------------
def analyze_and_predict(log: str, event_type="", description="", username="", timestamp=None, source_ip=""):
    print(f"\n📝 LOG: {log}")

    # -----------------------------
    # ML Prediction Block
    # -----------------------------
    ml_pred = None
    try:
        load_model_once()

        if MODEL and VECTORIZER and SCALER and LABEL_ENCODER:
            text_input = f"{event_type} {description} {username}"

            X_text = VECTORIZER.transform([str(text_input)])
            # Weak numeric feature: hour-of-day only (avoid memorizing raw IP/timestamp)
            try:
                ts = pd.to_datetime(timestamp, errors="coerce")
                hour_val = float(ts.hour) if pd.notna(ts) else 0.0
            except Exception:
                hour_val = 0.0

            X_numeric = SCALER.transform([[hour_val]])

            # Combine TF-IDF + hour
            X_final = hstack([X_text, X_numeric])

            y_raw = MODEL.predict(X_final)[0]
            ml_pred = LABEL_ENCODER.inverse_transform([y_raw])[0]

            print(f"🤖 ML Prediction: {ml_pred}")

    except Exception as e:
        print("⚠ ML Error:", e)

    # -------------------------------------------------------
    # RULE-BASED ANALYSIS
    # -------------------------------------------------------
    result = analyze_log(log, event_type=event_type, description=description,
                         username=username, timestamp=timestamp, source_ip=source_ip)

    severity = str(result.get("severity", "low")).lower()
    recommendation = result.get("recommendation", "")
    user = result.get("user")
    ip = result.get("ip")

    # HIGH / CRITICAL → BLOCK
    if severity in ["high", "critical"]:
        print("🚨 HIGH/CRITICAL → IMMEDIATE BLOCK")

        if ip:
            execute_block_ip(ip)
        if user:
            execute_block_user(user)

        send_email(
            f"🚨 Immediate Block ({severity.upper()})",
            f"Severity: {severity}\nUser: {user}\nIP: {ip}\n\nLog:\n{log}"
        )

        entry = {
            "timestamp": datetime.now(),
            "severity": severity,
            "user": user,
            "ip": ip,
            "log": log
        }

        try:
            df_new = pd.DataFrame([entry])
            if os.path.exists(HIGH_RISK_FILE_CSV):
                df_old = pd.read_csv(HIGH_RISK_FILE_CSV)
                df_all = pd.concat([df_old, df_new], ignore_index=True)
            else:
                df_all = df_new
            df_all.to_csv(HIGH_RISK_FILE_CSV, index=False)
        except Exception as e:
            print("⚠ High risk logging error:", e)

        recommendation = "escalate"

    elif recommendation == "escalate":
        print("⚠ Escalation — Monitor and review.")

    elif severity == "medium":
        print("🔍 Medium severity — monitor.")

    else:
        print("ℹ Low severity — no action.")

    # SAVE RESULT
    save_to_reports({
        "timestamp": datetime.now(),
        "log": log,
        "ml_prediction": ml_pred,
        "rule_based": recommendation,
        "severity": severity,
        "user": user,
        "ip": ip
    })

# ------------------------------------------------------------------------
# SAVE REPORT
# ------------------------------------------------------------------------
def save_to_reports(result: dict):
    """Save triage results in CSV & JSONL with unified schema."""
    clean_row = normalize_report_row(result)

    try:
        df_new = pd.DataFrame([clean_row])
        if os.path.exists(REPORT_FILE_CSV):
            df_old = pd.read_csv(REPORT_FILE_CSV)
            for field in REPORT_FIELDS:
                if field not in df_old.columns:
                    df_old[field] = None
            df_old = df_old[REPORT_FIELDS]
            df_all = pd.concat([df_old, df_new], ignore_index=True)
        else:
            df_all = df_new
        df_all.to_csv(REPORT_FILE_CSV, index=False)
    except Exception as e:
        print("⚠ Error saving CSV:", e)

    try:
        with open(REPORT_FILE_JSONL, "a") as f:
            f.write(json.dumps(clean_row, default=str) + "\n")
    except Exception as e:
        print("⚠ Error saving JSONL:", e)

# ------------------------------------------------------------------------
# WATCHERS (stoppable via Event / dashboard Stop buttons)
# ------------------------------------------------------------------------
_csv_stop = threading.Event()
_wazuh_stop = threading.Event()


def stop_csv_watcher():
    """Signal the CSV watcher loop to exit."""
    _csv_stop.set()


def stop_wazuh_watcher():
    """Signal the Wazuh watcher loop to exit."""
    _wazuh_stop.set()


def _interruptible_sleep(seconds, stop_event, chunk=0.5):
    """Sleep in short chunks so stop_event is checked responsively.

    Returns True if stop was requested during the wait.
    """
    if seconds <= 0:
        return bool(stop_event and stop_event.is_set())
    elapsed = 0.0
    while elapsed < seconds:
        if stop_event is not None and stop_event.is_set():
            return True
        step = min(chunk, seconds - elapsed)
        time.sleep(step)
        elapsed += step
    return bool(stop_event and stop_event.is_set())


def watch_csv(file_path, interval=5, stop_event=None):
    """Watch a CSV for new rows. Pass stop_event (or use stop_csv_watcher) to stop."""
    print(f"📂 Watching CSV: {file_path}")
    seen_rows = 0
    stop = stop_event if stop_event is not None else _csv_stop
    stop.clear()

    try:
        while not stop.is_set():
            if not os.path.exists(file_path):
                if _interruptible_sleep(interval, stop):
                    break
                continue

            df = pd.read_csv(file_path)
            if df.empty:
                if _interruptible_sleep(interval, stop):
                    break
                continue

            required_cols = ["event_type", "description", "username", "timestamp", "source_ip"]
            for col in required_cols:
                if col not in df.columns:
                    print(f"⚠ CSV missing column: {col}")
                    return

            new_rows = df.iloc[seen_rows:]
            for _, row in new_rows.iterrows():
                if stop.is_set():
                    break
                log_text = f"{row['event_type']} {row['description']} {row['username']}"
                analyze_and_predict(
                    log=log_text,
                    event_type=row.get("event_type", ""),
                    description=row.get("description", ""),
                    username=row.get("username", ""),
                    timestamp=row.get("timestamp", None),
                    source_ip=row.get("source_ip", "")
                )

            seen_rows = len(df)
            if _interruptible_sleep(interval, stop):
                break

    except KeyboardInterrupt:
        print("🛑 CSV watcher stopped.")
        stop.set()
    except Exception as e:
        print("⚠ CSV watcher error:", e)
    else:
        if stop.is_set():
            print("🛑 CSV watcher stopped.")


def watch_wazuh(interval=10, stop_event=None):
    """Poll Wazuh alerts with bounded dedup and backoff. Stop via stop_wazuh_watcher()."""
    print("🔗 Watching Wazuh alerts...")
    seen = set()
    max_seen = 5000
    failures = 0
    stop = stop_event if stop_event is not None else _wazuh_stop
    stop.clear()

    try:
        while not stop.is_set():
            try:
                details = fetch_wazuh_alert_details(limit=10)
                failures = 0
            except Exception as e:
                failures += 1
                wait = min(interval * (2 ** min(failures, 4)), 120)
                print(f"⚠ Wazuh fetch failed ({e}); retry in {wait}s")
                if _interruptible_sleep(wait, stop):
                    break
                continue

            if not details:
                if _interruptible_sleep(interval, stop):
                    break
                continue

            for alert in details:
                if stop.is_set():
                    break
                summary = alert.get("summary") or alert.get("full_log") or str(alert)
                key = summary
                if key in seen:
                    continue
                seen.add(key)
                if len(seen) > max_seen:
                    # drop oldest-ish by rebuilding from a tail slice
                    seen = set(list(seen)[-max_seen // 2:])

                # Enrich triage input with Wazuh rule context when present
                rule_bits = []
                if alert.get("rule_id") is not None:
                    rule_bits.append(f"rule_id={alert.get('rule_id')}")
                if alert.get("rule_level") is not None:
                    rule_bits.append(f"rule_level={alert.get('rule_level')}")
                if alert.get("severity"):
                    rule_bits.append(f"wazuh_severity={alert.get('severity')}")
                if alert.get("agent"):
                    rule_bits.append(f"agent={alert.get('agent')}")
                enriched = summary
                if rule_bits:
                    enriched = f"{summary} ({', '.join(rule_bits)})"

                analyze_and_predict(enriched)

            if _interruptible_sleep(interval, stop):
                break
    except KeyboardInterrupt:
        print("🛑 Wazuh watcher stopped.")
        stop.set()
    except Exception as e:
        print("⚠ Wazuh watcher error:", e)
    else:
        if stop.is_set():
            print("🛑 Wazuh watcher stopped.")


# ------------------------------------------------------------------------
# CLI MENU
# ------------------------------------------------------------------------
def cli_menu():
    while True:
        print("\n=== SOC TRIAGE CLI ===")
        print("1. Train ML Model")
        print("2. Watch CSV Logs")
        print("3. Watch Wazuh Alerts")
        print("4. View Report")
        print("5. Unblock IP/User")
        print("6. Exit\n")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            train_ml_model("data/sample_logs.csv")
        elif choice == "2":
            watch_csv("data/sample_logs.csv")
        elif choice == "3":
            watch_wazuh()
        elif choice == "4":
            view_report()
        elif choice == "5":
            unblock_entity()
        elif choice == "6":
            print("👋 Goodbye.")
            break
        else:
            print("Invalid choice.")

# ------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------
if __name__ == "__main__":
    cli_menu()
