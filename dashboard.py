from flask import Flask, render_template, request, jsonify, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import pandas as pd
import os
import random
import time
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

from containment import get_mode, get_mode_label, get_ui_notice, load_blocked
from report_filters import (
    compute_alert_counts,
    filter_report_df,
    normalize_view,
)

# -------------------------------------------------
# EMAIL (Flask-Mail)
# -------------------------------------------------
from flask_mail import Mail, Message

# -------------------------------------------------
# IMPORT REAL CLI FUNCTIONS
# -------------------------------------------------
try:
    from soc_triage_cli import (
        train_ml_model,
        watch_csv,
        watch_wazuh,
        stop_csv_watcher,
        stop_wazuh_watcher,
        execute_block_ip,
        execute_block_user,
        execute_unblock_ip,
        execute_unblock_user,
        blocked_entities,
        REPORT_FILE_CSV
    )
except Exception as e:
    print("SOC import error:", e)

# -------------------------------------------------
# WAZUH FALLBACK
# -------------------------------------------------
try:
    from wazuh_integration import fetch_wazuh_alerts, fetch_wazuh_alert_details
except Exception:
    def fetch_wazuh_alerts(limit=50): return []
    def fetch_wazuh_alert_details(limit=50): return []

# -------------------------------------------------
# FLASK
# -------------------------------------------------
app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")

# -------------------------------------------------
# EMAIL CONFIG
# -------------------------------------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '').strip()
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '').strip()
# Flask-Mail requires a default sender when Message(...) has no sender / empty sender
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME'] or 'noreply@localhost'

mail = Mail(app)


def mail_configured() -> bool:
    return bool(app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD'])


def deliver_otp(username: str, otp: str, subject: str = "Your Verification Code") -> str:
    """Send OTP by email when configured; otherwise print + return code for local demo UI."""
    body = f"Your verification code is: {otp}. It expires in 5 minutes."
    if mail_configured():
        msg = Message(
            subject,
            sender=app.config['MAIL_USERNAME'],
            recipients=[username],
        )
        msg.body = body
        mail.send(msg)
        print(f"OTP emailed to {username}")
        return ""
    # Local / Capstone demo fallback — no crash when .env mail is empty
    print(f"[DEMO OTP] user={username} code={otp} (MAIL_USERNAME/MAIL_PASSWORD not set in .env)")
    return otp

# -------------------------------------------------
# USER DATABASE
# -------------------------------------------------
USERS_FILE = "data/users.csv"
os.makedirs("data", exist_ok=True)

if os.path.exists(USERS_FILE):
    df = pd.read_csv(USERS_FILE)
    users_db = dict(zip(df["username"], df["password_hash"]))
else:
    users_db = {}

def save_user(username, password_hash):
    users_db[username] = password_hash
    df = pd.DataFrame(list(users_db.items()), columns=["username", "password_hash"])
    df.to_csv(USERS_FILE, index=False)

# -------------------------------------------------
# LOGIN REQUIRED
# -------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

# -------------------------------------------------
# AUTH
# -------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]  # MUST be email
        password = request.form["password"]
        if username in users_db:
            return render_template("register.html", error="User already exists")
        save_user(username, generate_password_hash(password))
        return redirect("/login")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username not in users_db or not check_password_hash(users_db[username], password):
            return render_template("login.html", error="Invalid username or password")

        # Generate OTP
        otp = str(random.randint(100000, 999999))

        # Save OTP temporarily
        session["pending_user"] = username
        session["otp"] = otp
        session["otp_time"] = time.time()

        demo_otp = deliver_otp(username, otp)
        session["demo_otp"] = demo_otp  # shown on /2fa only when mail is not configured
        return redirect("/2fa")

    return render_template("login.html")


@app.route("/2fa", methods=["GET", "POST"])
def two_factor():
    if "pending_user" not in session:
        return redirect("/login")

    if request.method == "POST":
        code = request.form["code"]

        # Check expiration (5 mins)
        if time.time() - session.get("otp_time", 0) > 300:
            session.pop("pending_user", None)
            session.pop("otp", None)
            session.pop("otp_time", None)
            return render_template("2fa.html", error="Code expired. Please login again.", demo_otp="")

        if code == session.get("otp"):
            session["user"] = session["pending_user"]
            session.pop("pending_user", None)
            session.pop("otp", None)
            session.pop("otp_time", None)
            session.pop("demo_otp", None)
            return redirect("/")

        return render_template(
            "2fa.html",
            error="Invalid code",
            demo_otp=session.get("demo_otp") or "",
        )

    return render_template(
        "2fa.html",
        demo_otp=session.get("demo_otp") or "",
    )


# ✅ NEW: RESEND OTP
@app.route("/2fa/resend", methods=["POST"])
def resend_otp():
    if "pending_user" not in session:
        return redirect("/login")

    username = session["pending_user"]

    # Generate new OTP
    otp = str(random.randint(100000, 999999))
    session["otp"] = otp
    session["otp_time"] = time.time()

    demo_otp = deliver_otp(username, otp, subject="Your New Verification Code")
    session["demo_otp"] = demo_otp
    msg = "A new code has been sent to your email." if mail_configured() else "A new verification code is shown below."
    return render_template("2fa.html", message=msg, demo_otp=demo_otp)

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")

# -------------------------------------------------
# HOME
# -------------------------------------------------
@app.route("/")
@login_required
def home():
    return render_template("index.html", user=session["user"])

# -------------------------------------------------
# TRAIN MODEL
# -------------------------------------------------
@app.route("/train-model", methods=["POST"])
@login_required
def train_model_route():
    train_ml_model("data/sample_logs.csv")
    return jsonify({"status": "Training complete"})

# -------------------------------------------------
# WATCHER THREADS
# -------------------------------------------------
watcher_threads = {"csv": None, "wazuh": None}

@app.route("/watch-csv/start", methods=["POST"])
@login_required
def start_csv_watch():
    if watcher_threads["csv"] and watcher_threads["csv"].is_alive():
        return jsonify({"status": "Already running"})
    t = threading.Thread(
        target=watch_csv,
        kwargs={"file_path": "data/sample_logs.csv"},
        daemon=True,
    )
    t.start()
    watcher_threads["csv"] = t
    return jsonify({"status": "CSV watcher started"})


@app.route("/watch-csv/stop", methods=["POST"])
@login_required
def stop_csv_watch():
    stop_csv_watcher()
    t = watcher_threads.get("csv")
    if t is not None and t.is_alive():
        t.join(timeout=2.0)
    if t is not None and not t.is_alive():
        watcher_threads["csv"] = None
    return jsonify({"status": "CSV watcher stopped"})


@app.route("/watch-wazuh/start", methods=["POST"])
@login_required
def start_wazuh_watch():
    if watcher_threads["wazuh"] and watcher_threads["wazuh"].is_alive():
        return jsonify({"status": "Already running"})
    t = threading.Thread(target=watch_wazuh, daemon=True)
    t.start()
    watcher_threads["wazuh"] = t
    return jsonify({"status": "Wazuh watcher started"})


@app.route("/watch-wazuh/stop", methods=["POST"])
@login_required
def stop_wazuh_watch():
    stop_wazuh_watcher()
    t = watcher_threads.get("wazuh")
    if t is not None and t.is_alive():
        t.join(timeout=2.0)
    if t is not None and not t.is_alive():
        watcher_threads["wazuh"] = None
    return jsonify({"status": "Wazuh watcher stopped"})

# -------------------------------------------------
# REPORTS
# -------------------------------------------------
@app.route("/report")
@login_required
def report():
    view, view_label = normalize_view(request.args.get("view"))

    if not os.path.exists(REPORT_FILE_CSV):
        return render_template(
            "report.html",
            rows=[],
            view=view,
            view_label=view_label,
        )

    df = pd.read_csv(REPORT_FILE_CSV)

    if "timestamp" in df.columns:
        df = df.sort_values(by="timestamp", ascending=False)
    elif "date" in df.columns:
        df = df.sort_values(by="date", ascending=False)

    df = filter_report_df(df, view)
    rows = df.to_dict(orient="records")
    return render_template(
        "report.html",
        rows=rows,
        view=view,
        view_label=view_label,
    )

# -------------------------------------------------
# CSV LOG VIEW
# -------------------------------------------------
@app.route("/logs/csv")
@login_required
def view_csv_logs():
    p = "data/sample_logs.csv"
    if not os.path.exists(p):
        return render_template("csv_logs.html", rows=[])
    df = pd.read_csv(p)
    return render_template("csv_logs.html", rows=df.to_dict(orient="records"))

# -------------------------------------------------
# WAZUH LOG VIEW
# -------------------------------------------------
@app.route("/logs/wazuh")
@login_required
def view_wazuh_logs():
    details = fetch_wazuh_alert_details(limit=50)
    # Keep string list available for older template fallbacks
    logs = [d.get("summary") or d.get("full_log") or str(d) for d in details]
    return render_template("wazuh_logs.html", alerts=details, logs=logs)


# -------------------------------------------------
# BLOCK / UNBLOCK
# -------------------------------------------------
@app.route("/blocks")
@login_required
def view_blocks():
    blocks = load_blocked()
    blocked_entities.clear()
    blocked_entities.update(blocks)
    return render_template(
        "blocks.html",
        blocks=blocks,
        containment_mode=get_mode(),
        containment_label=get_mode_label(),
        containment_notice=get_ui_notice(),
    )

@app.route("/block/ip", methods=["POST"])
@login_required
def block_ip():
    execute_block_ip(request.form["ip"])
    return redirect("/blocks")

@app.route("/block/user", methods=["POST"])
@login_required
def block_user():
    execute_block_user(request.form["user"])
    return redirect("/blocks")

@app.route("/unblock", methods=["POST"])
@login_required
def unblock():
    target = request.form["target"]

    if target in blocked_entities["ips"]:
        execute_unblock_ip(target)

    if target in blocked_entities["users"]:
        execute_unblock_user(target)

    return redirect("/blocks")

# -------------------------------------------------
# ANALYTICS
# -------------------------------------------------
@app.route("/analytics")
@login_required
def analytics():
    if not os.path.exists(REPORT_FILE_CSV):
        return render_template("analytics.html", rows=[])
    df = pd.read_csv(REPORT_FILE_CSV)
    return render_template("analytics.html", rows=df.to_dict(orient="records"))

# -------------------------------------------------
# NOTIFICATIONS
# -------------------------------------------------
@app.route("/notifications")
@login_required
def notifications():
    blocks = load_blocked()
    data = {
        "blocked_count": len(blocks.get("ips", [])) + len(blocks.get("users", [])),
        "severe_alerts": 0,
        "escalated_events": 0,
        "total_alerts": 0,
        "report_rows": 0,
        "wazuh_running": watcher_threads["wazuh"] is not None and watcher_threads["wazuh"].is_alive(),
        "csv_running": watcher_threads["csv"] is not None and watcher_threads["csv"].is_alive(),
        "ml_training": getattr(app, "ml_training", False),
    }

    if os.path.exists(REPORT_FILE_CSV):
        df = pd.read_csv(REPORT_FILE_CSV)
        counts = compute_alert_counts(df)
        data.update(counts)

    return jsonify(data)

# -------------------------------------------------
# RUN
# -------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
