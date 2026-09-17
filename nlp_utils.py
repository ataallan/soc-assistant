import re

def extract_ip(log: str):
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", log)
    return match.group(0) if match else None

def extract_user(log: str):
    match = re.search(r"user=(\w+)", log)
    return match.group(1) if match else None
