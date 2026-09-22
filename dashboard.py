from flask import Flask, render_template, request, jsonify, redirect, session, send_file, g
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import pandas as pd
import os
import random
import secrets
import time
from functools import wraps
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from flask_wtf.csrf import CSRFProtect

from containment import (
    execute_confirmed,
    get_mode,
    get_mode_label,
    is_integration_mode,
    load_blocked,
    preview_block_ip,
    preview_block_user,
    preview_unblock_ip,
    preview_unblock_user,
)
from rbac import (
    ROLE_ADMIN,
    ROLE_DEVELOPER,
    assignee_emails,
    is_developer_identity,
    role_for_identity,
)
from accounts import (
    AccountExists,
    account_is_active,
    apply_account_action,
    can_manage_accounts,
    email_2fa_required,
    get_account,
    list_accounts,
    register_account,
)
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
    get_triage_event,
    insert_label_queue_items,
    label_queue_counts,
    list_cases,
    list_label_queue,
    list_triage_events,
    save_label,
    skip_label,
    update_case_status,
)
from case_sync import (
    get_mode as get_case_sync_mode,
    get_mode_label as get_case_sync_mode_label,
    sync_case,
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
        alert_ingest_status,
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
    def alert_ingest_status(): return {"preferred": "manager_api", "indexer_configured": False, "note": "Wazuh integration unavailable."}

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


def resend_configured() -> bool:
    return bool((os.environ.get("RESEND_API_KEY") or "").strip())


def mask_login_email(email: str) -> str:
    """Mask an email for on-page hints (always the account currently signing in)."""
    email = (email or "").strip()
    if "@" not in email:
        return (email[:1] + "***") if email else ""
    local, _, domain = email.partition("@")
    if not local:
        return "***@" + domain
    return f"{local[0]}***@{domain}"



def mail_configured() -> bool:
    """True when any email OTP channel is configured (Resend preferred, else Gmail SMTP)."""
    return resend_configured() or bool(app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD'])


def _send_otp_resend(username: str, otp: str, subject: str) -> bool:
    """Send OTP via Resend API (same provider as muncyber.com). Returns True on success."""
    import json
    import urllib.error
    import urllib.request

    api_key = (os.environ.get("RESEND_API_KEY") or "").strip()
    if not api_key:
        return False
    from_addr = (os.environ.get("RESEND_FROM") or "Mun Cyber Technologies <info@muncyber.com>").strip()
    body = (
        f"Your AI-Powered SOC Assistant verification code is: {otp}\n\n"
        f"It expires in 5 minutes. If you did not try to sign in, ignore this email."
    )
    html = (
        f"<p>Your AI-Powered SOC Assistant verification code is:</p>"
        f"<p style=\"font-size:24px;font-weight:700;letter-spacing:4px\">{otp}</p>"
        f"<p>It expires in 5 minutes. If you did not try to sign in, ignore this email.</p>"
    )
    payload = json.dumps({
        "from": from_addr,
        "to": [username],
        "subject": subject,
        "text": body,
        "html": html,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            # Cloudflare in front of Resend rejects Python-urllib's default User-Agent (1010)
            "User-Agent": "MunCyber-SOC-Assistant/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            if 200 <= resp.status < 300:
                print(f"OTP emailed via Resend to {username}")
                return True
            print(f"Resend OTP unexpected status {resp.status}")
            return False
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", errors="replace")[:300]
        print(f"Resend OTP failed: {err.code} {detail}")
        return False
    except Exception as err:
        print(f"Resend OTP error: {err}")
        return False


def deliver_otp(username: str, otp: str, subject: str = "Your Verification Code") -> bool:
    """Email the OTP. Never returns the code for on-page display (email only).

    Order: Resend (preferred, same as muncyber.com) → Flask-Mail SMTP → console log only.
    Returns True if an email was sent, False if only logged locally.
    """
    body = f"Your verification code is: {otp}. It expires in 5 minutes."
    if resend_configured():
        if _send_otp_resend(username, otp, subject):
            return True
        print("Resend failed; trying SMTP fallback if configured")
    if app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD']:
        try:
            msg = Message(
                subject,
                sender=app.config['MAIL_USERNAME'],
                recipients=[username],
            )
            msg.body = body
            mail.send(msg)
            print(f"OTP emailed via SMTP to {username}")
            return True
        except Exception as err:
            print(f"SMTP OTP failed: {err}")
    # Local fallback: log to server console only — never show on the website
    print(f"[OTP not emailed] user={username} code={otp} (set RESEND_API_KEY or MAIL_* in .env)")
    return False

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


_AUTH_SESSION_KEYS = (
    "user",
    "role",
    "pending_user",
    "otp",
    "otp_time",
    "otp_emailed",
    "otp_email_hint",
    "demo_otp",
    "email_2fa_ok",
    "account_limited",
)

_AUTH_PUBLIC_PATHS = {"/login", "/register", "/logout", "/2fa", "/2fa/resend", "/pending"}


def _clear_auth_session() -> None:
    for key in _AUTH_SESSION_KEYS:
        session.pop(key, None)


def _stored_account_role(identity: str) -> str:
    account = get_account(identity) if identity else None
    if not account:
        return ""
    return str(account.get("role") or "").strip().lower()


def is_developer_user() -> bool:
    """Lab training console. Customer admins and analysts are excluded."""
    identity = session.get("user")
    if not identity:
        return False
    return is_developer_identity(identity, stored_role=_stored_account_role(identity))


def current_role() -> str:
    """Recompute role from SOC_ADMIN_EMAILS or the stored account role."""
    identity = session.get("user")
    if role_for_identity(identity) == ROLE_ADMIN:
        return ROLE_ADMIN
    stored = _stored_account_role(identity) if identity else ""
    if stored == ROLE_ADMIN:
        return ROLE_ADMIN
    if is_developer_identity(identity, stored_role=stored, training_enabled=False):
        return ROLE_DEVELOPER
    return role_for_identity(identity)


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


def require_developer(f):
    """Lab training console only. Customer admins and analysts are refused."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        session["role"] = current_role()
        if not is_developer_user():
            msg = "Developer role required for this action."
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


def _account_gate_response():
    """Block console routes until the account is approved and email 2FA is satisfied.

    Accounts with no stored row (legacy test sessions) are left alone.
    Pending users may keep a limited session for ``/pending`` only.
    When email 2FA is required, a session without ``email_2fa_ok`` is cleared.
    """
    path = request.path or "/"
    if path.startswith("/static/") or path in _AUTH_PUBLIC_PATHS:
        return None

    user = session.get("user")
    if not user:
        if session.get("pending_user"):
            return redirect("/2fa")
        return None

    account = get_account(user)
    if account is None:
        return None

    if not account_is_active(account):
        return redirect("/pending")

    if email_2fa_required(account) and not session.get("email_2fa_ok"):
        _clear_auth_session()
        return redirect("/login")
    return None


@app.before_request
def _sync_role_on_request():
    if "user" in session:
        session["role"] = current_role()
        g.current_role = session["role"]
        g.is_admin = session["role"] == ROLE_ADMIN
        g.is_developer = is_developer_user()
    else:
        g.current_role = None
        g.is_admin = False
        g.is_developer = False
    g.can_manage_accounts = can_manage_accounts(session.get("user")) if session.get("user") else False
    return _account_gate_response()


@app.context_processor
def inject_rbac_context():
    role = current_role() if "user" in session else None
    flash = session.pop("auth_flash", None)
    identity = session.get("user")
    return {
        "session_user": identity,
        "current_user_role": role,
        "is_admin": role == ROLE_ADMIN,
        "is_developer": is_developer_user() if "user" in session else False,
        "can_manage_accounts": can_manage_accounts(identity) if identity else False,
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
def _digits(value: str) -> str:
    return "".join(ch for ch in (value or "") if ch.isdigit())


def _otp_matches(code: str) -> bool:
    expected = str(session.get("otp") or "")
    code = _digits(code)
    if not expected or len(code) != len(expected):
        return False
    return secrets.compare_digest(code, expected)


def _begin_email_otp(username: str, *, subject: str = "Your Verification Code") -> bool:
    """Store a one-time email code for ``username`` and send it. Does not open the console."""
    otp = f"{secrets.randbelow(1_000_000):06d}"
    session["pending_user"] = username
    session["otp"] = otp
    session["otp_time"] = time.time()
    session.pop("user", None)
    session.pop("role", None)
    session.pop("email_2fa_ok", None)
    session.pop("account_limited", None)
    emailed = deliver_otp(username, otp, subject=subject)
    session["otp_emailed"] = bool(emailed)
    session["otp_email_hint"] = mask_login_email(username)
    session.pop("demo_otp", None)
    return bool(emailed)


def _establish_session(username: str, *, email_2fa_ok: bool) -> None:
    session["user"] = username
    session["email_2fa_ok"] = bool(email_2fa_ok)
    session["role"] = current_role()
    session.pop("pending_user", None)
    session.pop("otp", None)
    session.pop("otp_time", None)
    session.pop("demo_otp", None)
    session.pop("otp_emailed", None)
    session.pop("otp_email_hint", None)
    session.pop("account_limited", None)


def _render_2fa(error: str = "", message: str = ""):
    return render_template(
        "2fa.html",
        error=error or None,
        message=message or None,
        otp_emailed=bool(session.get("otp_emailed")),
        otp_email_hint=session.get("otp_email_hint") or mask_login_email(session.get("pending_user") or ""),
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if len(password) < 8:
            return render_template("register.html", error="Password must be at least 8 characters.")
        try:
            record = register_account(username, generate_password_hash(password))
        except AccountExists:
            return render_template("register.html", error="User already exists")
        except ValueError as exc:
            return render_template("register.html", error=str(exc))
        created = "admin" if record.get("approved") else "pending"
        return redirect(f"/login?registered={created}")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    registered = request.args.get("registered") if request.method == "GET" else None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        account = get_account(username)
        if not account or not check_password_hash(account["password_hash"], password):
            return render_template("login.html", error="Invalid username or password")

        _clear_auth_session()
        if not account_is_active(account):
            # Limited session only: pending / rejected / deactivated skip email 2FA.
            session["user"] = account["username"]
            session["account_limited"] = True
            session["role"] = current_role()
            return redirect("/pending")

        if email_2fa_required(account):
            _begin_email_otp(account["username"])
            return redirect("/2fa")

        _establish_session(account["username"], email_2fa_ok=False)
        return redirect("/")

    return render_template("login.html", registered=registered)


@app.route("/2fa", methods=["GET", "POST"])
def two_factor():
    if "pending_user" not in session:
        return redirect("/login")

    if request.method == "POST":
        code = request.form.get("code") or ""

        if time.time() - session.get("otp_time", 0) > 300:
            session.pop("pending_user", None)
            session.pop("otp", None)
            session.pop("otp_time", None)
            return render_template(
                "2fa.html",
                error="Code expired. Please login again.",
                otp_emailed=False,
                otp_email_hint="",
            )

        if _otp_matches(code):
            username = session["pending_user"]
            account = get_account(username)
            if account and not account_is_active(account):
                _clear_auth_session()
                session["user"] = account["username"]
                session["account_limited"] = True
                return redirect("/pending")
            _establish_session(username, email_2fa_ok=True)
            return redirect("/")

        return _render_2fa(error="Invalid code")

    return _render_2fa()


@app.route("/2fa/resend", methods=["POST"])
def resend_otp():
    if "pending_user" not in session:
        return redirect("/login")

    username = session["pending_user"]
    emailed = _begin_email_otp(username, subject="Your New Verification Code")
    hint = session.get("otp_email_hint") or mask_login_email(username)
    if emailed:
        msg = f"A new code has been sent to {hint}."
    else:
        msg = "Email delivery is not configured. Ask your admin to set RESEND_API_KEY (or check the server log)."
    return _render_2fa(message=msg)


@app.route("/pending")
def pending_account():
    user = session.get("user")
    if not user:
        return redirect("/login")
    account = get_account(user)
    if account and account_is_active(account):
        if email_2fa_required(account) and not session.get("email_2fa_ok"):
            _clear_auth_session()
            return redirect("/login")
        return redirect("/")
    status = (account or {}).get("status") or "pending"
    return render_template("pending.html", status=status, username=user)


@app.route("/logout")
def logout():
    _clear_auth_session()
    return redirect("/login")


def _deny_unless_account_manager():
    if "user" not in session:
        return redirect("/login")
    if can_manage_accounts(session.get("user")):
        return None
    msg = "Admin role required to manage accounts."
    if _wants_json():
        return jsonify({"ok": False, "status": "Forbidden", "message": msg}), 403
    session["auth_flash"] = {"ok": False, "message": msg}
    return redirect("/")


@app.route("/accounts", methods=["GET"])
@login_required
def accounts_page():
    denied = _deny_unless_account_manager()
    if denied is not None:
        return denied
    return render_template(
        "accounts.html",
        accounts=list_accounts(),
    )


@app.route("/accounts/<action>", methods=["POST"])
@login_required
def accounts_action(action: str):
    denied = _deny_unless_account_manager()
    if denied is not None:
        return denied
    target = (request.form.get("username") or "").strip()
    ok, message = apply_account_action(session.get("user") or "", action, target)
    session["auth_flash"] = {"ok": ok, "message": message}
    return redirect("/accounts")

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
@require_developer
def train_model_route():
    """Train a candidate checkpoint. Does not replace the live model."""
    from model_registry import train_candidate

    metrics = train_candidate("data/sample_logs.csv", "data/labeled_alerts.csv")
    if not metrics:
        return jsonify({"status": "Training failed", "ok": False}), 400
    return jsonify({
        "status": "Candidate trained",
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
    import json as _json

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
        try:
            from labeling import classify_label_source

            r["label_hint"] = classify_label_source(
                r, threshold=threshold
            )
        except Exception:
            r["label_hint"] = None

        # Surface YAML detection match from raw_json when present
        if not r.get("matched_rule_id") or not r.get("rule_explain"):
            raw = r.get("raw_json")
            if raw:
                try:
                    payload = _json.loads(raw) if isinstance(raw, str) else raw
                    if isinstance(payload, dict):
                        r.setdefault("matched_rule_id", payload.get("matched_rule_id"))
                        r.setdefault("rule_explain", payload.get("rule_explain"))
                        if not r.get("matched_rules"):
                            r["matched_rules"] = payload.get("matched_rules")
                except Exception:
                    pass
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
            "message": "Choose an action and a target.",
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
        msg = "Confirm the response before it is sent."
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
        print(f"Wazuh auth check failed: {exc}")
        wazuh_error = "Could not check Wazuh authentication."

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
            "ingest": alert_ingest_status(),
        },
        "watchers": {
            "csv": _watcher_running("csv"),
            "wazuh": _watcher_running("wazuh"),
        },
        "ml": {
            "assist_only": get_ml_assist_only(),
            "confidence_threshold": get_ml_confidence_threshold(),
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
# FALSE-POSITIVE REVIEW (noisy rule aggregation)
# -------------------------------------------------
@app.route("/fp-review")
@login_required
def fp_review_page():
    """Show top noisy rule ids from recent triage_events."""
    from detection.fp_review import aggregate_noisy_rules

    try:
        limit = int(request.args.get("limit") or 1000)
    except (TypeError, ValueError):
        limit = 1000
    limit = max(100, min(limit, 2000))

    events = list_triage_events(view="total", limit=limit)
    rows = aggregate_noisy_rules(events, limit_events=limit, top_n=50)
    flash = session.pop("fp_flash", None)
    return render_template(
        "fp_review.html",
        user=session.get("user"),
        rows=rows,
        event_limit=limit,
        event_count=len(events),
        ml_assist_only=get_ml_assist_only(),
        flash=flash,
    )


@app.route("/fp-review/enqueue", methods=["POST"])
@login_required
@require_developer
def fp_review_enqueue():
    from labeling import enqueue_fp_samples

    rule_key = (request.form.get("rule_key") or "").strip()
    try:
        window = int(request.form.get("limit") or 1000)
    except (TypeError, ValueError):
        window = 1000
    window = max(100, min(window, 2000))
    events = list_triage_events(view="total", limit=window)
    result = enqueue_fp_samples(events, rule_key, limit=5)
    inserted = int(result.get("inserted") or 0)
    skipped = int(result.get("skipped_dupes") or 0)
    if result.get("reason") == "no_samples":
        msg = "No samples."
        ok = False
    else:
        msg = f"Queued {inserted}."
        if skipped:
            msg = f"Queued {inserted}, skipped {skipped}."
        ok = True
    session["fp_flash"] = {"ok": ok, "message": msg}
    return redirect(f"/fp-review?limit={window}")


# -------------------------------------------------
# LABELING (live Wazuh analyst queue)
# -------------------------------------------------
@app.route("/labels")
@login_required
@require_developer
def labels_page():
    from model_registry import checkpoint_status

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
        model_status=checkpoint_status(),
    )


@app.route("/labels/pull", methods=["POST"])
@login_required
@require_developer
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
@require_developer
def labels_save():
    body = request.get_json(silent=True) or {}
    queue_id = request.form.get("id") or body.get("id")
    severity = request.form.get("severity") or body.get("severity")
    notes = request.form.get("notes") or body.get("notes")
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
@require_developer
def labels_skip():
    body = request.get_json(silent=True) or {}
    queue_id = request.form.get("id") or body.get("id")
    notes = request.form.get("notes") or body.get("notes")
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
@require_developer
def labels_retrain():
    """Train a candidate checkpoint. Live triage keeps the active model."""
    from model_registry import train_candidate

    try:
        metrics = train_candidate("data/sample_logs.csv", "data/labeled_alerts.csv")
        if not metrics:
            payload = {"ok": False, "message": "Train failed."}
            status = 400
        else:
            payload = {
                "ok": True,
                "message": "Candidate trained.",
                "metrics": metrics,
            }
            status = 200
    except Exception as exc:
        print(f"Train candidate failed: {exc}")
        payload = {"ok": False, "message": "Train failed."}
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


@app.route("/labels/activate", methods=["POST"])
@login_required
@require_developer
def labels_activate():
    """Promote a trained checkpoint to the artifacts live triage loads."""
    from model_registry import activate_checkpoint, latest_checkpoint

    body = request.get_json(silent=True) or {}
    checkpoint_id = (request.form.get("id") or body.get("id") or "").strip()
    if not checkpoint_id:
        latest = latest_checkpoint()
        checkpoint_id = str((latest or {}).get("id") or "")
    if not checkpoint_id:
        payload = {"ok": False, "message": "No candidate."}
        status = 400
    else:
        try:
            meta = activate_checkpoint(checkpoint_id)
            payload = {"ok": True, "message": "Activated.", "active": meta.get("id")}
            status = 200
        except Exception as exc:
            print(f"Activate failed: {exc}")
            payload = {"ok": False, "message": "Activate failed."}
            status = 400
    wants_json = (
        request.is_json
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.args.get("format") == "json"
        or True
    )
    if wants_json:
        return jsonify(payload), status
    session["labels_flash"] = {"ok": payload["ok"], "message": payload["message"]}
    return redirect("/labels")


@app.route("/labels/upload", methods=["POST"])
@login_required
@require_developer
def labels_upload():
    """Merge a labeling CSV into training rows. Developer console only."""
    from labeling import import_labeled_csv_text

    upload = request.files.get("file")
    if upload is None or not (upload.filename or "").strip():
        session["labels_flash"] = {"ok": False, "message": "No file."}
        return redirect("/labels")
    raw = upload.read(2_000_001)
    if len(raw) > 2_000_000:
        session["labels_flash"] = {"ok": False, "message": "File too large."}
        return redirect("/labels")
    text = raw.decode("utf-8-sig", errors="replace")
    result = import_labeled_csv_text(text)
    session["labels_flash"] = {
        "ok": bool(result.get("ok")),
        "message": result.get("message") or "Import failed.",
    }
    return redirect("/labels")


@app.route("/labels/bulk", methods=["POST"])
@login_required
@require_developer
def labels_bulk():
    from labeling import apply_bulk_labels

    body = request.get_json(silent=True) or {}
    ids = body.get("ids") if isinstance(body, dict) else None
    if not ids:
        ids = request.form.getlist("ids")
    action = (body.get("action") if isinstance(body, dict) else None) or request.form.get("action")
    severity = (body.get("severity") if isinstance(body, dict) else None) or request.form.get("severity")
    result = apply_bulk_labels(ids or [], action or "", severity)
    msg = f"Updated {result.get('updated', 0)}."
    wants_json = (
        request.is_json
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.args.get("format") == "json"
    )
    if wants_json:
        return jsonify({"ok": bool(result.get("updated")), "message": msg, **result})
    session["labels_flash"] = {"ok": bool(result.get("updated")), "message": msg}
    return redirect("/labels")


def _labels_redirect_back(default: str = "/labels"):
    wants_json = (
        request.is_json
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.args.get("format") == "json"
    )
    return wants_json, default


@app.route("/labels/from-event", methods=["POST"])
@login_required
@require_developer
def labels_from_event():
    from labeling import classify_label_source, enqueue_for_label, item_from_triage, submit_correct_label

    body = request.get_json(silent=True) or {}
    raw_id = request.form.get("triage_event_id") or body.get("triage_event_id") or body.get("id")
    severity = request.form.get("severity") or body.get("severity")
    queue_only = str(request.form.get("queue_only") or body.get("queue_only") or "").strip().lower() in {
        "1", "true", "yes", "on",
    }
    try:
        event = get_triage_event(int(raw_id))
    except (TypeError, ValueError):
        event = None
    if not event:
        session["labels_flash"] = {"ok": False, "message": "Event not found."}
        return redirect(_safe_internal_redirect("/report"))
    item = item_from_triage(event)
    try:
        if queue_only or not (severity or "").strip():
            source = classify_label_source(event) or "triage"
            result = enqueue_for_label(item, source)
            if result.get("inserted"):
                msg = "Queued."
            else:
                msg = "Already queued."
            ok = True
        else:
            displayed = str(event.get("severity") or "").strip().lower()
            source = "correction" if str(severity).strip().lower() != displayed else "triage"
            result = submit_correct_label(item, severity, source=source)
            msg = "Labeled." if result.get("labeled") else "Already labeled."
            ok = True
    except Exception as exc:
        result = {"ok": False}
        msg = f"Could not queue: {exc}"
        ok = False
    wants_json, _default = _labels_redirect_back("/report")
    if wants_json:
        return jsonify({"ok": ok, "message": msg, **result}), (200 if ok else 400)
    session["auth_flash"] = {"ok": ok, "message": msg}
    return redirect(_safe_internal_redirect("/report"))


@app.route("/labels/from-case", methods=["POST"])
@login_required
@require_developer
def labels_from_case():
    from labeling import enqueue_for_label, item_from_case, submit_correct_label

    body = request.get_json(silent=True) or {}
    raw_id = request.form.get("case_id") or body.get("case_id")
    severity = request.form.get("severity") or body.get("severity")
    queue_only = str(request.form.get("queue_only") or body.get("queue_only") or "").strip().lower() in {
        "1", "true", "yes", "on",
    }
    try:
        case = get_case(int(raw_id), include_notes=False)
    except (TypeError, ValueError):
        case = None
    if not case:
        session["cases_flash"] = {"ok": False, "message": "Case not found."}
        return redirect("/cases")
    item = item_from_case(case)
    back = f"/cases/{case['id']}"
    try:
        if queue_only or not (severity or "").strip():
            result = enqueue_for_label(item, "case")
            msg = "Queued." if result.get("inserted") else "Already queued."
            ok = True
        else:
            displayed = str(case.get("severity") or "").strip().lower()
            source = "correction" if str(severity).strip().lower() != displayed else "case"
            result = submit_correct_label(item, severity, source=source)
            msg = "Labeled." if result.get("labeled") else "Already labeled."
            ok = True
    except Exception as exc:
        result = {}
        msg = f"Could not queue: {exc}"
        ok = False
    wants_json, _default = _labels_redirect_back(back)
    if wants_json:
        return jsonify({"ok": ok, "message": msg, **result}), (200 if ok else 400)
    session["cases_flash"] = {"ok": ok, "message": msg}
    return redirect(back)


# -------------------------------------------------
# CASES (lightweight SOC ticket workflow)
# -------------------------------------------------
@app.route("/cases")
@login_required
def cases_page():
    status = (request.args.get("status") or "open").strip().lower()
    filter_name = (request.args.get("filter") or "").strip().lower()
    mine = request.args.get("mine", "").strip().lower() in ("1", "true", "yes") or filter_name == "mine"
    overdue = (
        request.args.get("overdue", "").strip().lower() in ("1", "true", "yes")
        or filter_name == "overdue"
        or status == "overdue"
    )
    if status == "overdue":
        status = "all"
        overdue = True
    if status not in ("all", "open", "investigating", "contained", "closed"):
        status = "open"
    # My cases / Overdue default to all statuses unless status is explicit in query
    if (mine or overdue) and "status" not in request.args:
        status = "all"

    kwargs = {"status": status if status != "all" else "all", "overdue": overdue}
    if mine:
        kwargs["mine"] = session.get("user")
    cases = list_cases(**kwargs)
    counts = counts_by_status()
    flash = session.pop("cases_flash", None)
    user = session.get("user")
    return render_template(
        "cases.html",
        user=user,
        cases=cases,
        counts=counts,
        status=status,
        filter_mine=mine,
        filter_overdue=overdue,
        assignee_options=assignee_emails(include=user),
        flash=flash,
        ml_assist_only=get_ml_assist_only(),
        case_sync_mode=get_case_sync_mode(),
        case_sync_mode_label=get_case_sync_mode_label(),
    )


@app.route("/cases/<int:case_id>")
@login_required
def case_detail(case_id: int):
    case = get_case(case_id, include_notes=True)
    if case is None:
        session["cases_flash"] = {"ok": False, "message": f"Case #{case_id} not found."}
        return redirect("/cases")
    flash = session.pop("cases_flash", None)
    user = session.get("user")
    return render_template(
        "case_detail.html",
        user=user,
        case=case,
        flash=flash,
        assignee_options=assignee_emails(include=case.get("assignee") or user),
        ml_assist_only=get_ml_assist_only(),
        case_sync_mode=get_case_sync_mode(),
        case_sync_mode_label=get_case_sync_mode_label(),
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
            host=data.get("host"),
            file_hash=data.get("file_hash"),
            domain=data.get("domain"),
            cve=data.get("cve"),
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


@app.route("/cases/<int:case_id>/sync", methods=["POST"])
@login_required
def cases_sync(case_id: int):
    try:
        result = sync_case(case_id, actor=session.get("user"))
        msg = result.get("message") or ("Synced." if result.get("ok") else "Sync failed.")
        ok = bool(result.get("ok"))
        out = result
    except Exception as exc:
        msg = f"Could not sync ticket: {exc}"
        ok = False
        out = {"error": str(exc)}

    if _wants_json():
        return jsonify({"ok": ok, "message": msg, **out}), (200 if ok else 400)
    session["cases_flash"] = {"ok": ok, "message": msg}
    return redirect(f"/cases/{case_id}")


# -------------------------------------------------
# RUN
# -------------------------------------------------
def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _standalone_login_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/login"


def _should_open_browser() -> bool:
    """Open a browser only for the branded launcher, and only once.

    ``Start AI-Powered SOC Assistant.bat`` sets SOC_OPEN_BROWSER=1.
    Flask's reloader executes this module in a child process too
    (WERKZEUG_RUN_MAIN=true); the outer process opens the login page.
    """
    if not _env_bool("SOC_OPEN_BROWSER", False):
        return False
    return os.environ.get("WERKZEUG_RUN_MAIN") != "true"


def _open_browser_later(port: int) -> None:
    if not _should_open_browser():
        return
    import webbrowser

    url = _standalone_login_url(port)

    def _open() -> None:
        time.sleep(1.25)
        webbrowser.open(url)

    threading.Thread(target=_open, daemon=True).start()


if __name__ == "__main__":
    # Always-on scheduled task sets SOC_ALWAYS_ON=1 (no debug/reloader).
    # Dev mode (start_dev.ps1) leaves reloader on so file saves apply without restarts.
    # The standalone shortcut sets SOC_FLASK_DEBUG=0 and SOC_OPEN_BROWSER=1.
    always_on = _env_bool("SOC_ALWAYS_ON", False)
    debug = False if always_on else _env_bool("SOC_FLASK_DEBUG", True)
    use_reloader = False if always_on else _env_bool("SOC_USE_RELOADER", debug)
    host = os.getenv("SOC_FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("SOC_FLASK_PORT", "5000"))
    _open_browser_later(port)
    app.run(host=host, port=port, debug=debug, use_reloader=use_reloader)
