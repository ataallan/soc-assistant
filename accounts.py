"""Local account store for the SOC console (CSV, no seeded passwords).

The first account created is the site administrator and is approved immediately.
Later accounts stay pending until an admin (or a developer, if that role is
stored on the account) approves them. There is no built-in default password.

Account file: ``SOC_USERS_FILE`` (default ``data/users.csv``).
Email login codes are controlled separately by ``SOC_EMAIL_2FA`` (default on).
"""

from __future__ import annotations

import csv
import hashlib
import os
import secrets
import threading
import time
from typing import Dict, List, Optional, Tuple

from rbac import ROLE_ADMIN, role_for_identity

STATUS_PENDING = "pending"
STATUS_ACTIVE = "active"
STATUS_REJECTED = "rejected"
STATUS_INACTIVE = "inactive"

_APPROVER_ROLES = {ROLE_ADMIN, "developer"}
_COLUMNS = [
    "username",
    "password_hash",
    "role",
    "approved",
    "status",
    "two_factor",
    "reset_token_hash",
    "reset_expires",
    "reset_issued_at",
]

RESET_TOKEN_MINUTES_DEFAULT = 45
RESET_MIN_INTERVAL_SECONDS_DEFAULT = 60

_lock = threading.Lock()


class AccountExists(ValueError):
    """Raised when registering an email that is already stored."""


def users_path() -> str:
    return (os.environ.get("SOC_USERS_FILE") or "data/users.csv").strip() or "data/users.csv"


def email_2fa_globally_enabled() -> bool:
    """True unless SOC_EMAIL_2FA is explicitly disabled."""
    raw = os.environ.get("SOC_EMAIL_2FA")
    if raw is None or str(raw).strip() == "":
        return True
    return str(raw).strip().lower() not in {"0", "false", "no", "off"}


def _key(username: Optional[str]) -> str:
    return (username or "").strip().lower()


def _parse_bool(value, default: bool = False) -> bool:
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _valid_email(username: str) -> bool:
    if not username or " " in username or "@" not in username or len(username) > 254:
        return False
    local, _, domain = username.partition("@")
    return bool(local and domain and "." in domain and "/" not in username)


def account_is_active(account: Optional[dict]) -> bool:
    if not account:
        return False
    if not account.get("approved"):
        return False
    return str(account.get("status") or "").lower() == STATUS_ACTIVE


def email_2fa_required(account: Optional[dict]) -> bool:
    """Approved active accounts require an email login code when SOC_EMAIL_2FA is on.

    Pending, rejected, and deactivated accounts skip the challenge.
    """
    if not account_is_active(account):
        return False
    if not email_2fa_globally_enabled():
        return False
    return _parse_bool((account or {}).get("two_factor"), default=True)


def _is_approver_role(account: dict) -> bool:
    role = str(account.get("role") or "").lower()
    if role in _APPROVER_ROLES:
        return True
    return role_for_identity(account.get("username")) == ROLE_ADMIN


def can_manage_accounts(identity: Optional[str]) -> bool:
    """Admins and stored developer accounts may approve or deactivate users."""
    if not identity or not str(identity).strip():
        return False
    account = get_account(identity)
    if account is not None and not account_is_active(account):
        return False
    if role_for_identity(identity) == ROLE_ADMIN:
        return True
    if account and str(account.get("role") or "").lower() in _APPROVER_ROLES:
        return True
    return False


def _blank_store() -> Dict[str, dict]:
    return {}


def _load_unlocked() -> Dict[str, dict]:
    path = users_path()
    if not os.path.exists(path):
        return _blank_store()
    try:
        with open(path, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            fieldnames = [name.strip() for name in (reader.fieldnames or []) if name]
            legacy = "role" not in fieldnames or "approved" not in fieldnames
            rows = list(reader)
    except OSError:
        return _blank_store()

    accounts: Dict[str, dict] = {}
    for row in rows:
        username = _key(row.get("username"))
        password_hash = (row.get("password_hash") or "").strip()
        if not username or not password_hash:
            continue
        if legacy:
            role = ROLE_ADMIN if role_for_identity(username) == ROLE_ADMIN else "analyst"
            approved = True
            status = STATUS_ACTIVE
            two_factor = True
        else:
            role = (row.get("role") or "analyst").strip().lower() or "analyst"
            approved = _parse_bool(row.get("approved"), default=False)
            status = (row.get("status") or (STATUS_ACTIVE if approved else STATUS_PENDING)).strip().lower()
            if status not in {STATUS_PENDING, STATUS_ACTIVE, STATUS_REJECTED, STATUS_INACTIVE}:
                status = STATUS_ACTIVE if approved else STATUS_PENDING
            two_factor = _parse_bool(row.get("two_factor"), default=True)
        accounts[username] = {
            "username": username,
            "password_hash": password_hash,
            "role": role,
            "approved": approved,
            "status": status,
            "two_factor": two_factor,
            "reset_token_hash": (row.get("reset_token_hash") or "").strip(),
            "reset_expires": (row.get("reset_expires") or "").strip(),
            "reset_issued_at": (row.get("reset_issued_at") or "").strip(),
        }

    if legacy:
        _promote_first_legacy_admin(accounts)
    return accounts


def _promote_first_legacy_admin(accounts: Dict[str, dict]) -> None:
    """Old username/password files had no role column. Keep them approved and ensure one admin."""
    if not accounts:
        return
    for account in accounts.values():
        if str(account.get("role") or "").lower() == ROLE_ADMIN:
            return
        if role_for_identity(account.get("username")) == ROLE_ADMIN:
            return
    first = next(iter(accounts.values()))
    first["role"] = ROLE_ADMIN
    first["approved"] = True
    first["status"] = STATUS_ACTIVE


def _save_unlocked(accounts: Dict[str, dict]) -> None:
    path = users_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=_COLUMNS, lineterminator="\n")
        writer.writeheader()
        for account in accounts.values():
            writer.writerow(
                {
                    "username": account["username"],
                    "password_hash": account["password_hash"],
                    "role": account.get("role") or "analyst",
                    "approved": "true" if account.get("approved") else "false",
                    "status": account.get("status") or STATUS_PENDING,
                    "two_factor": "true" if account.get("two_factor", True) else "false",
                    "reset_token_hash": account.get("reset_token_hash") or "",
                    "reset_expires": account.get("reset_expires") or "",
                    "reset_issued_at": account.get("reset_issued_at") or "",
                }
            )


def load_accounts() -> Dict[str, dict]:
    with _lock:
        return _load_unlocked()


def list_accounts() -> List[dict]:
    """Accounts in file order (oldest first). Password hashes are omitted."""
    safe: List[dict] = []
    for account in load_accounts().values():
        safe.append(
            {
                "username": account["username"],
                "role": account.get("role") or "analyst",
                "approved": bool(account.get("approved")),
                "status": account.get("status") or STATUS_PENDING,
                "two_factor": bool(account.get("two_factor", True)),
            }
        )
    return safe


def get_account(username: Optional[str]) -> Optional[dict]:
    if not username:
        return None
    return load_accounts().get(_key(username))


def register_account(username: str, password_hash: str) -> dict:
    """Create an account. The first one is an approved admin; later ones are pending analysts.

    ``password_hash`` must already be a password hash. This module never stores
    a plaintext password and never seeds a default account.
    """
    email = _key(username)
    if not _valid_email(email):
        raise ValueError("Username must be an email address.")
    if not password_hash or not str(password_hash).strip():
        raise ValueError("Password is required.")

    with _lock:
        accounts = _load_unlocked()
        if email in accounts:
            raise AccountExists("User already exists")
        first = len(accounts) == 0
        record = {
            "username": email,
            "password_hash": str(password_hash),
            "role": ROLE_ADMIN if first else "analyst",
            "approved": True if first else False,
            "status": STATUS_ACTIVE if first else STATUS_PENDING,
            "two_factor": True,
            "reset_token_hash": "",
            "reset_expires": "",
            "reset_issued_at": "",
        }
        accounts[email] = record
        _save_unlocked(accounts)
        return dict(record)


def _active_admin_count(accounts: Dict[str, dict]) -> int:
    count = 0
    for account in accounts.values():
        if not account_is_active(account):
            continue
        role = str(account.get("role") or "").lower()
        if role == ROLE_ADMIN or role_for_identity(account.get("username")) == ROLE_ADMIN:
            count += 1
    return count


def apply_account_action(actor: str, action: str, target: str) -> Tuple[bool, str]:
    """Approve, reject, or deactivate ``target`` on behalf of ``actor``.

    Returns ``(ok, message)``. Does not change passwords.
    """
    action = (action or "").strip().lower()
    if action not in {"approve", "reject", "deactivate"}:
        return False, "Unknown account action."

    actor_key = _key(actor)
    target_key = _key(target)
    if not actor_key or not target_key:
        return False, "Account not found."
    if not can_manage_accounts(actor_key):
        return False, "Admin role required to manage accounts."

    with _lock:
        accounts = _load_unlocked()
        account = accounts.get(target_key)
        if not account:
            return False, "Account not found."

        if action in {"reject", "deactivate"}:
            if target_key == actor_key and action == "deactivate":
                return False, "You cannot deactivate your own account."
            role = str(account.get("role") or "").lower()
            is_admin_account = role == ROLE_ADMIN or role_for_identity(account.get("username")) == ROLE_ADMIN
            if is_admin_account and account_is_active(account) and _active_admin_count(accounts) <= 1:
                return False, "The last active administrator cannot be deactivated or rejected."

        if action == "approve":
            account["approved"] = True
            account["status"] = STATUS_ACTIVE
            message = f"Approved {target_key}."
        elif action == "reject":
            account["approved"] = False
            account["status"] = STATUS_REJECTED
            _clear_reset_fields(account)
            message = f"Rejected {target_key}."
        else:
            account["approved"] = False
            account["status"] = STATUS_INACTIVE
            _clear_reset_fields(account)
            message = f"Deactivated {target_key}."

        accounts[target_key] = account
        _save_unlocked(accounts)
        return True, message


def _clear_reset_token(account: dict) -> None:
    account["reset_token_hash"] = ""
    account["reset_expires"] = ""


def _clear_reset_fields(account: dict) -> None:
    _clear_reset_token(account)
    account["reset_issued_at"] = ""


def _reset_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _reset_expiry(account: dict) -> float:
    try:
        return float(account.get("reset_expires") or 0)
    except (TypeError, ValueError):
        return 0.0


def _reset_issued_at(account: dict) -> float:
    try:
        return float(account.get("reset_issued_at") or 0)
    except (TypeError, ValueError):
        return 0.0


def _find_reset_account(accounts: Dict[str, dict], token: str) -> Optional[dict]:
    token = (token or "").strip()
    if not token:
        return None
    digest = _reset_token_hash(token)
    for account in accounts.values():
        stored = (account.get("reset_token_hash") or "").strip()
        if len(stored) != len(digest):
            continue
        if secrets.compare_digest(stored, digest):
            return account
    return None


def _reset_token_usable(account: Optional[dict], now: Optional[float] = None) -> bool:
    if not account or not account_is_active(account):
        return False
    moment = time.time() if now is None else now
    return _reset_expiry(account) >= moment


def issue_reset_token(
    username: str,
    *,
    ttl_minutes: int = RESET_TOKEN_MINUTES_DEFAULT,
    min_interval_seconds: int = RESET_MIN_INTERVAL_SECONDS_DEFAULT,
) -> Tuple[str, Optional[str]]:
    """Issue a one-time reset token for an approved, active account.

    Returns ``(status, token)``. ``status`` is ``issued``, ``throttled``, or
    ``ineligible``. The raw token is returned only for ``issued``; the account
    file stores its SHA-256 hash and expiry. Pending, rejected, inactive, and
    unknown identities are ``ineligible`` and do not get a token.
    """
    email = _key(username)
    if not email:
        return "ineligible", None
    try:
        ttl = int(ttl_minutes)
    except (TypeError, ValueError):
        ttl = RESET_TOKEN_MINUTES_DEFAULT
    if ttl <= 0:
        ttl = RESET_TOKEN_MINUTES_DEFAULT
    try:
        interval = int(min_interval_seconds)
    except (TypeError, ValueError):
        interval = RESET_MIN_INTERVAL_SECONDS_DEFAULT
    if interval < 0:
        interval = 0

    with _lock:
        accounts = _load_unlocked()
        account = accounts.get(email)
        if not account or not account_is_active(account):
            return "ineligible", None
        issued_at = _reset_issued_at(account)
        if interval and issued_at and (time.time() - issued_at) < interval:
            return "throttled", None
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        account["reset_token_hash"] = _reset_token_hash(token)
        account["reset_expires"] = str(now + ttl * 60)
        account["reset_issued_at"] = str(now)
        accounts[email] = account
        _save_unlocked(accounts)
        return "issued", token


def account_for_reset_token(token: str) -> Optional[dict]:
    """Return the approved active account for a live reset token, if any."""
    with _lock:
        account = _find_reset_account(_load_unlocked(), token)
        if not _reset_token_usable(account):
            return None
        return dict(account)


def consume_reset_token(token: str, password_hash: str) -> Optional[dict]:
    """Set a new password hash and clear the reset token.

    ``password_hash`` must already be a password hash. Returns the updated
    account, or ``None`` when the token is missing, expired, or the account
    is not approved and active. Does not change approval, status, or 2FA.
    """
    if not password_hash or not str(password_hash).strip():
        return None
    with _lock:
        accounts = _load_unlocked()
        account = _find_reset_account(accounts, token)
        if not _reset_token_usable(account):
            return None
        assert account is not None
        account["password_hash"] = str(password_hash)
        _clear_reset_token(account)
        accounts[account["username"]] = account
        _save_unlocked(accounts)
        return dict(account)
