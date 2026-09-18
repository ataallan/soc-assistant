import re

def extract_ip(log: str):
    if not log:
        return None
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", log)
    return match.group(0) if match else None

def extract_user(log: str):
    """Extract a username from common auth / syslog phrases.

    Keeps the original user=TOKEN form and adds a few conservative auth-log
    patterns. Avoids greedy matches that would swallow hostnames or paths.
    """
    if not log:
        return None
    patterns = (
        r"user=(\w+)",
        r"\binvalid user\s+([A-Za-z0-9._-]{1,64})\b",
        r"\bfor user\s+([A-Za-z0-9._-]{1,64})\b",
        r"\bfailed password for (?:invalid user\s+)?([A-Za-z0-9._-]{1,64})\b",
        r"\bAccepted (?:password|publickey) for ([A-Za-z0-9._-]{1,64})\b",
        r"\buser:\s*([A-Za-z0-9._-]{1,64})\b",
    )
    for pat in patterns:
        match = re.search(pat, log, re.IGNORECASE)
        if match:
            return match.group(1)
    return None
