"""Simple email-based RBAC for the SOC dashboard.

Admins are listed in SOC_ADMIN_EMAILS (comma-separated, case-insensitive).
Analysts may be listed in SOC_ANALYST_EMAILS (optional roster for assignee UI).
Everyone else who can log in is an analyst.
"""

from __future__ import annotations

import os
from typing import Iterable, List, Optional, Set


ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_DEVELOPER = "developer"


def _parse_email_list(value: Optional[str]) -> Set[str]:
    if not value:
        return set()
    return {part.strip().lower() for part in str(value).split(",") if part.strip()}


def parse_admin_emails(value: Optional[str] = None) -> Set[str]:
    """Parse SOC_ADMIN_EMAILS into a lowercase set of emails/usernames."""
    if value is None:
        value = os.environ.get("SOC_ADMIN_EMAILS", "")
    return _parse_email_list(value)


def parse_developer_emails(value: Optional[str] = None) -> Set[str]:
    """Parse SOC_DEVELOPER_EMAILS into a lowercase set.

    These identities may open the lab training console. Admin emails are not
    included unless they are listed here as well.
    """
    if value is None:
        value = os.environ.get("SOC_DEVELOPER_EMAILS", "")
    return _parse_email_list(value)


def training_console_enabled(value: Optional[str] = None) -> bool:
    """Lab switch SOC_DEV_TRAINING. Off by default so customer installs stay closed."""
    if value is None:
        value = os.environ.get("SOC_DEV_TRAINING", "")
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def is_developer_identity(
    identity: Optional[str],
    *,
    stored_role: Optional[str] = None,
    developer_emails: Optional[Iterable[str]] = None,
    training_enabled: Optional[bool] = None,
) -> bool:
    """True for lab training access.

    Granted by a stored ``developer`` role, ``SOC_DEVELOPER_EMAILS``, or the
    lab-wide ``SOC_DEV_TRAINING`` switch. Customer admins and analysts are not
    developers unless one of those is set.
    """
    if training_enabled is None:
        training_enabled = training_console_enabled()
    if training_enabled and identity and str(identity).strip():
        return True
    emails = (
        {e.strip().lower() for e in developer_emails if e and str(e).strip()}
        if developer_emails is not None
        else parse_developer_emails()
    )
    if identity and identity.strip().lower() in emails:
        return True
    if stored_role is not None and str(stored_role).strip().lower() == ROLE_DEVELOPER:
        return True
    return False


def parse_analyst_emails(value: Optional[str] = None) -> Set[str]:
    """Parse SOC_ANALYST_EMAILS into a lowercase set of emails/usernames."""
    if value is None:
        value = os.environ.get("SOC_ANALYST_EMAILS", "")
    return _parse_email_list(value)


def role_for_identity(identity: Optional[str], admin_emails: Optional[Iterable[str]] = None) -> str:
    """Return 'admin' if identity is in the admin list, else 'analyst'."""
    if not identity:
        return ROLE_ANALYST
    emails = (
        {e.strip().lower() for e in admin_emails if e and str(e).strip()}
        if admin_emails is not None
        else parse_admin_emails()
    )
    if identity.strip().lower() in emails:
        return ROLE_ADMIN
    return ROLE_ANALYST


def is_admin_identity(identity: Optional[str], admin_emails: Optional[Iterable[str]] = None) -> bool:
    return role_for_identity(identity, admin_emails=admin_emails) == ROLE_ADMIN


def assignee_emails(
    *,
    admin_emails: Optional[Iterable[str]] = None,
    analyst_emails: Optional[Iterable[str]] = None,
    include: Optional[str] = None,
) -> List[str]:
    """Sorted unique emails from SOC_ADMIN_EMAILS + SOC_ANALYST_EMAILS.

    Optionally include an extra identity (e.g. current case assignee / session user)
    so the <select> still shows an existing value even if not in the roster.
    """
    admins = (
        {e.strip().lower() for e in admin_emails if e and str(e).strip()}
        if admin_emails is not None
        else parse_admin_emails()
    )
    analysts = (
        {e.strip().lower() for e in analyst_emails if e and str(e).strip()}
        if analyst_emails is not None
        else parse_analyst_emails()
    )
    combined = set(admins) | set(analysts)
    if include and str(include).strip():
        combined.add(str(include).strip().lower())
    return sorted(combined)
