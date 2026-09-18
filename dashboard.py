from flask import Flask, render_template, request, jsonify, redirect, session, send_file, g
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import pandas as pd
import os
import random
import time
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

from flask_wtf.csrf import CSRFProtect

from containment import (
    execute_confirmed,
    get_mode,
    get_mode_label,
    get_ui_notice,
    is_integration_mode,
    load_blocked,
    preview_block_ip,
    preview_block_user,
    preview_unblock_ip,
    preview_unblock_user,
)
from rbac import ROLE_ADMIN, role_for_identity
from report_filters import (
    compute_alert_counts,
    filter_report_df,
    normalize_view,
)
from db import (
    add_note,
    backup_sqlite,
    count_alerts,
    counts_by_status,
    create_case,
    ensure_db_ready,
    export_triage_to_csv,
    get_case,
    get_db_path,
    get_storage_status,
    insert_label_queue_items,
    label_queue_counts,
    list_cases,
    list_label_queue,
    list_triage_events,
    save_label,
    skip_label,
    update_case_status,
)
from triage_engine import (
    format_ml_assist_display,
    get_ml_assist_only,
    get_ml_confidence_threshold,
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
    from wazuh_integration import (
        fetch_wazuh_alerts,
        fetch_wazuh_alert_details,
        get_last_auth_error,
        get_token,
        wazuh_api_host,
    )
except Exception:
    def fetch_wazuh_alerts(limit=50): return []
    def fetch_wazuh_alert_details(limit=50): return []
    def get_token(force_refresh=False): return None
    def get_last_auth_error(): return "Wazuh integration unavailable."
    def wazuh_api_host(): return "unknown"

# -------------------------------------------------
# FLASK
# -------------------------------------------------
app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")

# Session cookie hardening (HttpOnly is Flask default True; keep explicit)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set SESSION_COOKIE_SECURE=true behind HTTPS (see docs/SECURITY.md)
_secure = (os.environ.get("SESSION_COOKIE_SECURE") or "").strip().lower()
app.config["SESSION_COOKIE_SECURE"] = _secure in ("1", "true", "yes", "on")

# CSRF for POST forms + JSON (X-CSRFToken header). Disable in unit tests via TESTING.
app.config["WTF_CSRF_HEADERS"] = ["X-CSRFToken", "X-CSRF-Token"]
csrf = CSRFProtect(app)

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
# SQLITE STORAGE (source of truth)
# -------------------------------------------------
ensure_db_ready()

# -------------------------------------------------
# RBAC + LOGIN
# -------------------------------------------------
def _wants_json() -> bool:
    return bool(
        request.is_json
        or request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.args.get("format") == "json"
    )


def current_role() -> str:
    """Recompute role from the logged-in email/username each call."""
    return role_for_identity(session.get("user"))


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        # Keep session role in sync (email list may change without re-login)
        session["role"] = current_role()
        return f(*args, **kwargs)
    return decorated


def _safe_internal_redirect(fallback: str = "/"):
    """Prefer same-host referrer path; never redirect off-site."""
    ref = request.referrer
    if not ref:
        return fallback
    try:
        parsed = urlparse(ref)
        if parsed.netloc and parsed.netloc != request.host:
            return fallback
        path = parsed.path or fallback
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path
    except Exception:
        return fallback


def require_admin(f):
    """Block analysts from admin-only actions (403 JSON or redirect + toast)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        session["role"] = current_role()
        if current_role() != ROLE_ADMIN:
            msg = "Admin role required for this action."
            if _wants_json():
                return jsonify({"ok": False, "status": "Forbidden", "message": msg}), 403
            session["auth_flash"] = {"ok": False, "message": msg}
            return redirect(_safe_internal_redirect("/"))
        return f(*args, **kwargs)
    return decorated


def _deny_stub_containment_if_analyst():
    """Live/stub containment execute is admin-only; analysts may still view blocks."""
    if not is_integration_mode():
        return None
    if current_role() == ROLE_ADMIN:
        return None
    msg = "Admin role required to execute containment in integrated response mode."
    if _wants_json():
        return jsonify({"ok": False, "status": "Forbidden", "message": msg}), 403
    session["auth_flash"] = {"ok": False, "message": msg}
    return redirect("/blocks")


def _request_confirm_flag() -> bool:
    """True when form/JSON includes confirm=1 (or true/yes)."""
    raw = None
    if request.is_json:
        body = request.get_json(silent=True) or {}
        raw = body.get("confirm")
    if raw is None:
        raw = request.form.get("confirm")
    if raw is None:
        raw = request.args.get("confirm")
    if raw is None:
        return False
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _request_json_or_form(*keys, default=None):
    data = {}
    if request.is_json:
        data = request.get_json(silent=True) or {}
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
        if key in request.form and request.form.get(key) is not None:
            return request.form.get(key)
    return default


@app.before_request
def _sync_role_on_request():
    if "user" in session:
        session["role"] = current_role()
        g.current_role = session["role"]
        g.is_admin = session["role"] == ROLE_ADMIN
    else:
        g.current_role = None
        g.is_admin = False


@app.context_processor
def inject_rbac_context():
    role = current_role() if "user" in session else None
    flash = session.pop("auth_flash", None)
    return {
        "session_user": session.get("user"),
        "current_user_role": role,
        "is_admin": role == ROLE_ADMIN,
        "auth_flash": flash,
        "containment_mode": get_mode(),
    }


@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


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
            username = session["pending_user"]
            session["user"] = username
            session["role"] = role_for_identity(username)
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
    session.pop("role", None)
    return redirect("/login")

# -------------------------------------------------
# HOME
# -------------------------------------------------
@app.route("/")
@login_required
def home():
    return render_template(
        "index.html",
        user=session["user"],
        ml_assist_only=get_ml_assist_only(),
        ml_threshold=get_ml_confidence_threshold(),
    )

# -------------------------------------------------
# TRAIN MODEL
# -------------------------------------------------
@app.route("/train-model", methods=["POST"])
@login_required
@require_admin
def train_model_route():
    metrics = train_ml_model("data/sample_logs.csv", combine_labeled=True)
    if not metrics:
        return jsonify({"status": "Training failed", "ok": False}), 400
    return jsonify({
        "status": "Training complete",
        "ok": True,
        "metrics": metrics,
    })

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

def enrich_triage_rows(rows):
    """Attach honest ML assist display fields for templates."""
    threshold = get_ml_confidence_threshold()
    assist_only = get_ml_assist_only()
    enriched = []
    for row in rows or []:
        r = dict(row)
        ml_pred = r.get("ml_prediction")
        try:
            conf = float(r.get("ml_confidence") or 0.0)
        except (TypeError, ValueError):
            conf = 0.0
        disp = format_ml_assist_display(
            ml_pred, conf, threshold=threshold, assist_only=assist_only
        )
        r["ml_assist_label"] = disp["label"]
        r["ml_confidence_pct"] = disp["confidence_pct"]
        r["ml_low_confidence"] = disp["low_confidence"]
        r["ml_used"] = disp["used"]
        if r.get("severity_source") is None:
            r["severity_source"] = "rules" if assist_only or disp["low_confidence"] else "ml"
        if r.get("ml_assist") is None:
            r["ml_assist"] = True if assist_only else (not disp["used"])
        enriched.append(r)
    return enriched


@app.route("/report")
@login_required
def report():
    view, view_label = normalize_view(request.args.get("view"))
    rows = enrich_triage_rows(list_triage_events(view=view))
    return render_template(
        "report.html",
        rows=rows,
        view=view,
        view_label=view_label,
        ml_assist_only=get_ml_assist_only(),
        ml_threshold=get_ml_confidence_threshold(),
    )


@app.route("/report/export")
@login_required
def report_export():
    """Download triage events as CSV (from SQLite)."""
    view, _ = normalize_view(request.args.get("view"))
    out_path = os.path.join("data", "triage_export.csv")
    export_triage_to_csv(out_path, view=view)
    return send_file(
        out_path,
        mimetype="text/csv",
        as_attachment=True,
        download_name="triage_report.csv",
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
    mode = get_mode()
    live = is_integration_mode(mode)
    can_execute = (current_role() == ROLE_ADMIN) or (not live)
    return render_template(
        "blocks.html",
        blocks=blocks,
        containment_mode=mode,
        containment_label=get_mode_label(),
        containment_notice=get_ui_notice(),
        can_execute_containment=can_execute,
        requires_live_confirm=live,
    )


@app.route("/blocks/preview", methods=["POST"])
@login_required
def blocks_preview():
    """Return a containment preview (never calls the integration network)."""
    action = str(_request_json_or_form("action", default="") or "").strip().lower()
    target_type = str(_request_json_or_form("target_type", "type", default="") or "").strip().lower()
    target = str(_request_json_or_form("target", "ip", "user", default="") or "").strip()
    # Convenience: /blocks/preview with ip= or user= alone
    if not target_type and _request_json_or_form("ip"):
        target_type = "ip"
        target = str(_request_json_or_form("ip") or "").strip()
        action = action or "block"
    if not target_type and _request_json_or_form("user"):
        target_type = "user"
        target = str(_request_json_or_form("user") or "").strip()
        action = action or "block"

    actor_admin = current_role() == ROLE_ADMIN
    if action == "block" and target_type == "ip":
        preview = preview_block_ip(target, actor_is_admin=actor_admin)
    elif action == "block" and target_type == "user":
        preview = preview_block_user(target, actor_is_admin=actor_admin)
    elif action == "unblock" and target_type == "ip":
        preview = preview_unblock_ip(target, actor_is_admin=actor_admin)
    elif action == "unblock" and target_type == "user":
        preview = preview_unblock_user(target, actor_is_admin=actor_admin)
    else:
        return jsonify({
            "ok": False,
            "message": "Provide action (block|unblock) and target_type (ip|user).",
        }), 400

    status = 200 if preview.get("ok") else 400
    return jsonify(preview), status


@app.route("/blocks/execute", methods=["POST"])
@login_required
def blocks_execute():
    """Admin-confirmed live/stub execute. Requires confirm=1."""
    denied = _deny_stub_containment_if_analyst()
    if denied is not None:
        return denied

    if not is_integration_mode():
        msg = "Live execute is only available in integrated response mode."
        if _wants_json():
            return jsonify({"ok": False, "message": msg}), 400
        session["auth_flash"] = {"ok": False, "message": msg}
        return redirect("/blocks")

    if not _request_confirm_flag():
        msg = "Confirm required for live response (confirm=1)."
        if _wants_json():
            return jsonify({"ok": False, "message": msg, "requires_confirm": True}), 400
        session["auth_flash"] = {"ok": False, "message": msg}
        return redirect("/blocks")

    action = str(_request_json_or_form("action", default="") or "").strip().lower()
    target_type = str(_request_json_or_form("target_type", "type", default="") or "").strip().lower()
    target = str(_request_json_or_form("target", "ip", "user", default="") or "").strip()
    if not target_type and _request_json_or_form("ip"):
        target_type = "ip"
        target = str(_request_json_or_form("ip") or "").strip()
        action = action or "block"
    if not target_type and _request_json_or_form("user"):
        target_type = "user"
        target = str(_request_json_or_form("user") or "").strip()
        action = action or "block"

    result = execute_confirmed(action, target_type, target, confirm=True)
    # Keep in-memory mirror used by legacy unblock route
    blocks = load_blocked()
    blocked_entities.clear()
    blocked_entities.update(blocks)

    if _wants_json() or request.is_json:
        status = 200 if result.get("ok") else 400
        return jsonify(result), status
    session["auth_flash"] = {
        "ok": bool(result.get("ok")),
        "message": result.get("message") or ("Response applied." if result.get("ok") else "Response failed."),
    }
    return redirect("/blocks")


@app.route("/block/ip", methods=["POST"])
@login_required
def block_ip():
    denied = _deny_stub_containment_if_analyst()
    if denied is not None:
        return denied
    # Integrated mode: prefer preview → /blocks/execute; keep one-click for simulation.
    if is_integration_mode():
        if not _request_confirm_flag():
            msg = "Use Preview response, then Confirm live response."
            if _wants_json():
                return jsonify({"ok": False, "message": msg, "requires_confirm": True}), 400
            session["auth_flash"] = {"ok": False, "message": msg}
            return redirect("/blocks")
        result = execute_confirmed("block", "ip", request.form.get("ip") or "", confirm=True)
        if _wants_json():
            return jsonify(result), (200 if result.get("ok") else 400)
        return redirect("/blocks")
    execute_block_ip(request.form["ip"])
    return redirect("/blocks")


@app.route("/block/user", methods=["POST"])
@login_required
def block_user():
    denied = _deny_stub_containment_if_analyst()
    if denied is not None:
        return denied
    if is_integration_mode():
        if not _request_confirm_flag():
            msg = "Use Preview response, then Confirm live response."
            if _wants_json():
                return jsonify({"ok": False, "message": msg, "requires_confirm": True}), 400
            session["auth_flash"] = {"ok": False, "message": msg}
            return redirect("/blocks")
        result = execute_confirmed("block", "user", request.form.get("user") or "", confirm=True)
        if _wants_json():
            return jsonify(result), (200 if result.get("ok") else 400)
        return redirect("/blocks")
    execute_block_user(request.form["user"])
    return redirect("/blocks")


@app.route("/unblock", methods=["POST"])
@login_required
def unblock():
    denied = _deny_stub_containment_if_analyst()
    if denied is not None:
        return denied
    target = request.form.get("target") or ""
    if is_integration_mode():
        if not _request_confirm_flag():
            msg = "Use Preview response, then Confirm live response."
            if _wants_json():
                return jsonify({"ok": False, "message": msg, "requires_confirm": True}), 400
            session["auth_flash"] = {"ok": False, "message": msg}
            return redirect("/blocks")
        blocks = load_blocked()
        if target in blocks.get("ips", []):
            result = execute_confirmed("unblock", "ip", target, confirm=True)
        elif target in blocks.get("users", []):
            result = execute_confirmed("unblock", "user", target, confirm=True)
        else:
            result = {"ok": False, "message": "Target not found in block list."}
        if _wants_json():
            return jsonify(result), (200 if result.get("ok") else 400)
        return redirect("/blocks")

    if target in blocked_entities["ips"]:
        execute_unblock_ip(target)

    if target in blocked_entities["users"]:
        execute_unblock_user(target)

    return redirect("/blocks")


# -------------------------------------------------
# OPS HEALTH
# -------------------------------------------------
def _watcher_running(name: str) -> bool:
    t = watcher_threads.get(name)
    return t is not None and t.is_alive()


def collect_health() -> dict:
    """Build operator-friendly health payload (no secrets)."""
    storage = get_storage_status()

    authenticated = False
    wazuh_error = None
    try:
        authenticated = bool(get_token())
        wazuh_error = get_last_auth_error()
    except Exception as exc:
        authenticated = False
        wazuh_error = f"Could not check Wazuh authentication: {exc}"

    try:
        labels = label_queue_counts()
    except Exception:
        labels = {"pending": 0, "labeled": 0, "skipped": 0, "alerts_labeled": 0}

    return {
        "storage": {
            "backend": storage.get("backend"),
            "location": storage.get("location"),
            "triage_events": storage.get("triage_events", 0),
            "blocks": storage.get("blocks", 0),
        },
        "wazuh": {
            "authenticated": authenticated,
            "api_host": wazuh_api_host(),
            "last_error": wazuh_error,
        },
        "watchers": {
            "csv": _watcher_running("csv"),
            "wazuh": _watcher_running("wazuh"),
        },
        "ml": {
            "assist_only": get_ml_assist_only(),
            "confidence_threshold": get_ml_confidence_threshold(),
            "note": "ML is assist-only until more live labels are trained.",
        },
        "labeling": labels,
    }


@app.route("/health")
@login_required
def health_page():
    health = collect_health()
    flash = session.pop("health_flash", None)
    return render_template(
        "health.html",
        user=session.get("user"),
        health=health,
        flash=flash,
        can_backup=(health["storage"]["backend"] == "sqlite" and current_role() == ROLE_ADMIN),
    )


@app.route("/health.json")
@login_required
def health_json():
    return jsonify(collect_health())


@app.route("/backup", methods=["POST"])
@login_required
@require_admin
def backup_route():
    result = backup_sqlite(dest_dir="data/backups", keep=10)
    wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.args.get("format") == "json"
    )
    if wants_json:
        status = 200 if result.get("ok") else 400
        return jsonify(result), status

    session["health_flash"] = {
        "ok": bool(result.get("ok")),
        "message": result.get("message") or ("Backup complete." if result.get("ok") else "Backup unavailable."),
    }
    return redirect("/health")

# -------------------------------------------------
# ANALYTICS
# -------------------------------------------------
@app.route("/analytics")
@login_required
def analytics():
    rows = list_triage_events(view="total")
    return render_template("analytics.html", rows=rows)

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
    data.update(count_alerts())
    return jsonify(data)


# -------------------------------------------------
# LABELING (live Wazuh analyst queue)
# -------------------------------------------------
@app.route("/labels")
@login_required
def labels_page():
    pending = list_label_queue(status="pending")
    counts = label_queue_counts()
    flash = session.pop("labels_flash", None)
    return render_template(
        "labels.html",
        user=session.get("user"),
        pending=pending,
        counts=counts,
        flash=flash,
        ml_assist_only=get_ml_assist_only(),
    )


@app.route("/labels/pull", methods=["POST"])
@login_required
def labels_pull():
    limit = 50
    try:
        if request.is_json and request.json:
            limit = int(request.json.get("limit") or 50)
        elif request.form.get("limit"):
            limit = int(request.form.get("limit"))
    except (TypeError, ValueError):
        limit = 50
    limit = max(1, min(limit, 200))

    details = fetch_wazuh_alert_details(limit=limit) or []
    items = []
    for d in details:
        items.append({
            "summary": d.get("summary") or d.get("rule_description") or "",
            "full_log": d.get("full_log") or d.get("summary") or "",
            "agent": d.get("agent"),
            "rule_id": d.get("rule_id"),
            "rule_level": d.get("rule_level"),
            "severity": d.get("severity"),
            "wazuh_severity": d.get("severity"),
            "source": "wazuh",
        })
    result = insert_label_queue_items(items, source="wazuh")
    msg = (
        f"Pulled {result.get('total_seen', 0)} Wazuh alerts; "
        f"inserted {result.get('inserted', 0)} new; "
        f"skipped {result.get('skipped_dupes', 0)} duplicates."
    )
    wants_json = (
        request.is_json
        or request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.args.get("format") == "json"
    )
    if wants_json:
        return jsonify({"ok": True, "message": msg, **result})
    session["labels_flash"] = {"ok": True, "message": msg}
    return redirect("/labels")


@app.route("/labels/save", methods=["POST"])
@login_required
def labels_save():
    queue_id = request.form.get("id") or (request.json or {}).get("id")
    severity = request.form.get("severity") or (request.json or {}).get("severity")
    notes = request.form.get("notes") or (request.json or {}).get("notes")
    try:
        out = save_label(int(queue_id), severity, notes=notes)
        msg = f"Labeled #{queue_id} as {severity}."
        ok = True
    except Exception as exc:
        out = {"ok": False, "error": str(exc)}
        msg = f"Could not label #{queue_id}: {exc}"
        ok = False
    wants_json = (
        request.is_json
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.args.get("format") == "json"
    )
    if wants_json:
        status = 200 if ok else 400
        return jsonify({"ok": ok, "message": msg, **out}), status
    session["labels_flash"] = {"ok": ok, "message": msg}
    return redirect("/labels")


@app.route("/labels/skip", methods=["POST"])
@login_required
def labels_skip():
    queue_id = request.form.get("id") or (request.json or {}).get("id")
    notes = request.form.get("notes") or (request.json or {}).get("notes")
    try:
        out = skip_label(int(queue_id), notes=notes)
        msg = f"Skipped #{queue_id}."
        ok = True
    except Exception as exc:
        out = {"ok": False, "error": str(exc)}
        msg = f"Could not skip #{queue_id}: {exc}"
        ok = False
    wants_json = (
        request.is_json
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.args.get("format") == "json"
    )
    if wants_json:
        status = 200 if ok else 400
        return jsonify({"ok": ok, "message": msg, **out}), status
    session["labels_flash"] = {"ok": ok, "message": msg}
    return redirect("/labels")


@app.route("/labels/retrain", methods=["POST"])
@login_required
@require_admin
def labels_retrain():
    """Retrain on sample_logs.csv + labeled_alerts.csv; return metrics toast/JSON."""
    try:
        metrics = train_ml_model(
            "data/sample_logs.csv",
            labeled_path="data/labeled_alerts.csv",
            combine_labeled=True,
        )
        if not metrics:
            payload = {"ok": False, "message": "Retrain failed — check training data."}
            status = 400
        else:
            payload = {
                "ok": True,
                "message": (
                    f"Retrain complete — {metrics.get('model')} · "
                    f"CV macro F1={metrics.get('cv_macro_f1', 0):.3f} · "
                    f"N={metrics.get('n_samples')}"
                ),
                "metrics": metrics,
            }
            status = 200
    except Exception as exc:
        payload = {"ok": False, "message": f"Retrain error: {exc}"}
        status = 500

    wants_json = (
        request.is_json
        or request.accept_mimetypes.best == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.args.get("format") == "json"
        or True  # always JSON for toast UX
    )
    if wants_json:
        return jsonify(payload), status
    session["labels_flash"] = {"ok": payload["ok"], "message": payload["message"]}
    return redirect("/labels")



# -------------------------------------------------
# CASES (lightweight SOC ticket workflow)
# -------------------------------------------------
@app.route("/cases")
@login_required
def cases_page():
    status = (request.args.get("status") or "open").strip().lower()
    if status not in ("all", "open", "investigating", "contained", "closed"):
        status = "open"
    cases = list_cases(status=status if status != "all" else "all")
    counts = counts_by_status()
    flash = session.pop("cases_flash", None)
    return render_template(
        "cases.html",
        user=session.get("user"),
        cases=cases,
        counts=counts,
        status=status,
        flash=flash,
        ml_assist_only=get_ml_assist_only(),
    )


@app.route("/cases/<int:case_id>")
@login_required
def case_detail(case_id: int):
    case = get_case(case_id, include_notes=True)
    if case is None:
        session["cases_flash"] = {"ok": False, "message": f"Case #{case_id} not found."}
        return redirect("/cases")
    flash = session.pop("cases_flash", None)
    return render_template(
        "case_detail.html",
        user=session.get("user"),
        case=case,
        flash=flash,
        ml_assist_only=get_ml_assist_only(),
    )


@app.route("/cases/create", methods=["POST"])
@login_required
def cases_create():
    data = request.form if request.form else (request.json or {})
    triage_raw = data.get("triage_event_id") or data.get("triage_id")
    triage_event_id = None
    if triage_raw not in (None, ""):
        try:
            triage_event_id = int(triage_raw)
        except (TypeError, ValueError):
            session["cases_flash"] = {"ok": False, "message": "Invalid triage event id."}
            return redirect("/cases")

    title = (data.get("title") or "").strip() or None
    summary = data.get("summary")
    severity = (data.get("severity") or "medium").strip().lower()
    assignee = (data.get("assignee") or session.get("user") or "").strip() or None
    source = (data.get("source") or ("triage" if triage_event_id else "manual")).strip().lower()
    ip = data.get("ip")
    user_entity = data.get("user_entity") or data.get("user")

    try:
        case = create_case(
            title=title,
            severity=severity,
            assignee=assignee,
            triage_event_id=triage_event_id,
            source=source,
            summary=summary,
            ip=ip,
            user_entity=user_entity,
        )
        msg = f"Opened case #{case['id']}."
        ok = True
        case_id = case["id"]
    except Exception as exc:
        msg = f"Could not create case: {exc}"
        ok = False
        case_id = None

    if _wants_json():
        payload = {"ok": ok, "message": msg}
        if case_id is not None:
            payload["id"] = case_id
        return jsonify(payload), (200 if ok else 400)

    session["cases_flash"] = {"ok": ok, "message": msg}
    if ok and case_id is not None:
        return redirect(f"/cases/{case_id}")
    return redirect("/cases")


@app.route("/cases/<int:case_id>/note", methods=["POST"])
@login_required
def cases_add_note(case_id: int):
    data = request.form if request.form else (request.json or {})
    body = data.get("body") or data.get("note") or ""
    author = (data.get("author") or session.get("user") or "").strip() or None
    try:
        note = add_note(case_id, body, author=author)
        msg = "Note added."
        ok = True
        out = note
    except Exception as exc:
        msg = f"Could not add note: {exc}"
        ok = False
        out = {"error": str(exc)}

    if _wants_json():
        return jsonify({"ok": ok, "message": msg, **out}), (200 if ok else 400)
    session["cases_flash"] = {"ok": ok, "message": msg}
    return redirect(f"/cases/{case_id}")


@app.route("/cases/<int:case_id>/status", methods=["POST"])
@login_required
def cases_update_status(case_id: int):
    data = request.form if request.form else (request.json or {})
    status = data.get("status")
    resolution_notes = data.get("resolution_notes")
    assignee = data.get("assignee")
    # Only pass assignee when the field is present in the form/json
    kwargs = {}
    if "resolution_notes" in data:
        kwargs["resolution_notes"] = resolution_notes
    if "assignee" in data:
        kwargs["assignee"] = assignee
    try:
        case = update_case_status(case_id, status, **kwargs)
        msg = f"Case #{case_id} → {case['status']}."
        ok = True
        out = case
    except Exception as exc:
        msg = f"Could not update status: {exc}"
        ok = False
        out = {"error": str(exc)}

    if _wants_json():
        return jsonify({"ok": ok, "message": msg, **out}), (200 if ok else 400)
    session["cases_flash"] = {"ok": ok, "message": msg}
    return redirect(f"/cases/{case_id}")


# -------------------------------------------------
# RUN
# -------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
