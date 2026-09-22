#!/usr/bin/env python3
"""Build AI-Powered-SOC-Assistant-standalone.zip without secrets or a local venv.

Usage (from repo root):
    python scripts/build_standalone_zip.py
"""

from __future__ import annotations

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "AI-Powered-SOC-Assistant-standalone.zip"

SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "htmlcov",
    ".cursor",
    "ultralytics",
    "runs",
}
SKIP_FILE_NAMES = {
    ".env",
    ".env.local",
    ".coverage",
    "install.log",
    "users.csv",
    "AI-Powered-SOC-Assistant-standalone.zip",
}
SKIP_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".lnk",
    ".pem",
    ".key",
    ".db",
    ".db-journal",
    ".db-wal",
    ".db-shm",
    ".token",
}

# Names that would ship a tunnel client, token, or helper script.
TUNNEL_NAME_PARTS = ("cloudflared", "ngrok", "tunnel")

# Files a customer unzip needs in order to install and to launch from the icon.
REQUIRED_ZIP_PATHS = (
    "install_and_run.bat",
    "install_and_run.ps1",
    "Start AI-Powered SOC Assistant.bat",
    "start_dashboard.ps1",
    "scripts/standalone_support.py",
    "scripts/build_icon.py",
    "static/img/ai-powered-soc-assistant.ico",
    "static/img/company-logo.png",
    "requirements.txt",
    "dashboard.py",
    ".env.example",
    "docs/STANDALONE.md",
)


def _is_tunnel_artifact(path: Path) -> bool:
    lowered = path.name.lower()
    if not any(part in lowered for part in TUNNEL_NAME_PARTS):
        return False
    # Product docs may mention tunnels in prose. Rule YAML does not use these names.
    if path.suffix.lower() in {".md", ".txt", ".png", ".csv"}:
        return False
    return True


def should_skip(path: Path, root: Path = ROOT) -> bool:
    rel_parts = path.relative_to(root).parts
    if any(part in SKIP_DIR_NAMES for part in rel_parts):
        return True
    if path.name in SKIP_FILE_NAMES:
        return True
    if path.suffix.lower() in SKIP_SUFFIXES:
        return True
    if _is_tunnel_artifact(path):
        return True
    return False


def iter_package_files(root: Path) -> list[Path]:
    files = [path for path in root.rglob("*") if path.is_file() and not should_skip(path, root)]
    return sorted(files)


def missing_required(root: Path) -> list[str]:
    return [rel for rel in REQUIRED_ZIP_PATHS if not (root / rel).is_file()]


def build_zip(root: Path, dest: Path) -> int:
    missing = missing_required(root)
    if missing:
        raise SystemExit("Standalone zip is missing required files: " + ", ".join(missing))
    dest = dest.resolve()
    files = [path for path in iter_package_files(root) if path.resolve() != dest]
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            zf.write(path, path.relative_to(root).as_posix())
    return len(files)


def main() -> None:
    count = build_zip(ROOT, OUT)
    print(f"Wrote {OUT} ({count} files)")
    print("Included the icon, Start AI-Powered SOC Assistant launcher, and install scripts")
    print("Excluded .venv, __pycache__, .git, real .env, install.log, .lnk shortcuts, and tunnel tokens")


if __name__ == "__main__":
    main()
