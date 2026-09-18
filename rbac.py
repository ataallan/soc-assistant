"""Simple email-based RBAC for the SOC dashboard.

Admins are listed in SOC_ADMIN_EMAILS (comma-separated, case-insensitive).
Everyone else who can log in is an analyst.
"""

from __future__ import annotations

import os
from typing import Iterable, Optional, Set


ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"


def parse_admin_emails(value: Optional[str] = None) -> Set[str]:
    """Parse SOC_ADMIN_EMAILS into a lowercase set of emails/usernames."""
    if value is None:
        value = os.environ.get("SOC_ADMIN_EMAILS", "")
    if not value:
        return set()
    return {part.strip().lower() for part in str(value).split(",") if part.strip()}


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
