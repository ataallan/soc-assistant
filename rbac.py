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


def _parse_email_list(value: Optional[str]) -> Set[str]:
    if not value:
        return set()
    return {part.strip().lower() for part in str(value).split(",") if part.strip()}


def parse_admin_emails(value: Optional[str] = None) -> Set[str]:
    """Parse SOC_ADMIN_EMAILS into a lowercase set of emails/usernames."""
    if value is None:
        value = os.environ.get("SOC_ADMIN_EMAILS", "")
    return _parse_email_list(value)


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
