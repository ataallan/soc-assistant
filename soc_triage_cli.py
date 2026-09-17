import os
import time
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
    from wazuh_integration import fetch_wazuh_alerts
except Exception:
    def fetch_wazuh_alerts(limit=50):
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
blocked_entities = {"ips": [], "users": []}
if os.path.exists(BLOCKED_ENTITIES_FILE):
    try:
        blocked_entities = json.load(open(BLOCKED_ENTITIES_FILE))
    except:
        blocked_entities = {"ips": [], "users": []}

def save_blocked_entities():
    with open(BLOCKED_ENTITIES_FILE, "w") as f:
        json.dump(blocked_entities, f, indent=4)

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
    print(f"🛑 BLOCKED IP: {ip}")
    if ip not in blocked_entities["ips"]:
        blocked_entities["ips"].append(ip)
        save_blocked_entities()

def execute_block_user(user: str):
    print(f"🛑 BLOCKED USER: {user}")
    if user not in blocked_entities["users"]:
        blocked_entities["users"].append(user)
        save_blocked_entities()

def execute_unblock_ip(ip: str):
    print(f"♻️ UNBLOCKED IP: {ip}")
    if ip in blocked_entities["ips"]:
        blocked_entities["ips"].remove(ip)
        save_blocked_entities()

def execute_unblock_user(user: str):
    print(f"♻️ UNBLOCKED USER: {user}")
    if user in blocked_entities["users"]:
        blocked_entities["users"].remove(user)
        save_blocked_entities()

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
            # Convert timestamp
            try:
                ts_val = pd.to_datetime(timestamp, errors="coerce").view('int64') // 10**9
            except:
                try:
                    ts_val = int(pd.to_datetime(timestamp, errors="coerce").astype('int64') // 10**9)
                except:
                    ts_val = 0

            # Convert IP
            try:
                ip_val = struct.unpack("!I", socket.inet_aton(str(source_ip)))[0]
            except:
                ip_val = 0

            # SCALE USING NUMPY (NO WARNINGS)
            X_numeric = SCALER.transform([[ts_val, ip_val]])

            # Combine TF-IDF + numeric
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
# WATCHERS
# ------------------------------------------------------------------------
def watch_csv(file_path, interval=5):
    print(f"📂 Watching CSV: {file_path}")
    seen_rows = 0

    try:
        while True:
            if not os.path.exists(file_path):
                time.sleep(interval)
                continue

            df = pd.read_csv(file_path)
            if df.empty:
                time.sleep(interval)
                continue

            required_cols = ["event_type", "description", "username", "timestamp", "source_ip"]
            for col in required_cols:
                if col not in df.columns:
                    print(f"⚠ CSV missing column: {col}")
                    return

            new_rows = df.iloc[seen_rows:]
            for _, row in new_rows.iterrows():
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
            time.sleep(interval)

    except KeyboardInterrupt:
        print("🛑 CSV watcher stopped.")
    except Exception as e:
        print("⚠ CSV watcher error:", e)

def watch_wazuh(interval=10):
    print("🔗 Watching Wazuh alerts...")
    seen = set()

    try:
        while True:
            alerts = fetch_wazuh_alerts(limit=10)
            for alert in alerts:
                key = str(alert)
                if key not in seen:
                    analyze_and_predict(key)
                    seen.add(key)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("🛑 Wazuh watcher stopped.")
    except Exception as e:
        print("⚠ Wazuh watcher error:", e)

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
