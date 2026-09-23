#!/usr/bin/env python3
"""Stage the folder tree packed into AIPoweredSOCAssistantSetup.exe.

Usage (from the repo root):
    python scripts/stage_installer_payload.py

The Inno Setup script installs this directory. It contains the application
and the Setup launcher. It omits secrets, a local virtual environment, and
the unzip-folder installer (that one creates its own Desktop shortcut).
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_standalone_zip  # noqa: E402

DEFAULT_DEST = ROOT / "dist" / "installer-payload"
LAUNCHER_NAME = "Launch AI-Powered SOC Assistant.bat"

# Copied after the tree walk. The installer directory is not packed whole:
# the .iss file is a build input, not a file the customer runs.
RUNTIME_FILES = (
    "installer/bootstrap_embedded_python.ps1",
    "installer/launch_app.ps1",
)

# Repo tests are not part of the installed app.
PAYLOAD_SKIP_DIR_NAMES = {"tests"}

# Unzip-folder entry points. Packing them would leave a second installer
# that creates another Desktop shortcut next to the Setup.exe icon.
PAYLOAD_SKIP_FILES = {
    "install_and_run.bat",
    "install_and_run.ps1",
    "Start AI-Powered SOC Assistant.bat",
    "start_dashboard.bat",
    "start_dashboard.ps1",
    "scripts/build_icon.py",
    "scripts/build_standalone_zip.py",
    "scripts/build_windows_installer.ps1",
    "scripts/stage_installer_payload.py",
}

REQUIRED_PAYLOAD_PATHS = (
    LAUNCHER_NAME,
    "installer/bootstrap_embedded_python.ps1",
    "installer/launch_app.ps1",
    "scripts/standalone_support.py",
    "static/img/ai-powered-soc-assistant.ico",
    "dashboard.py",
    "requirements.txt",
    ".env.example",
    "docs/INSTALLER.md",
    "VERSION",
)


def installer_session_epoch(base: str, when: datetime | None = None) -> str:
    """Epoch written into a Setup.exe payload. Changes on every stage."""
    lines = (base or "").strip().splitlines()
    label = lines[0].strip() if lines else ""
    label = label or "0"
    moment = when or datetime.now(timezone.utc)
    return f"{label}+{moment.strftime('%Y%m%d%H%M%S')}"


def should_skip_payload(path: Path, root: Path, dest: Path) -> bool:
    resolved = path.resolve()
    dest_resolved = dest.resolve()
    if resolved == dest_resolved or dest_resolved in resolved.parents:
        return True
    if build_standalone_zip.should_skip(path, root):
        return True
    rel = path.relative_to(root)
    if any(part in PAYLOAD_SKIP_DIR_NAMES for part in rel.parts):
        return True
    return rel.as_posix() in PAYLOAD_SKIP_FILES


def iter_payload_files(root: Path, dest: Path) -> list[Path]:
    files = [
        path
        for path in root.rglob("*")
        if path.is_file() and not should_skip_payload(path, root, dest)
    ]
    return sorted(files)


def missing_required(dest: Path) -> list[str]:
    return [rel for rel in REQUIRED_PAYLOAD_PATHS if not (dest / rel).is_file()]


def stage(root: Path, dest: Path) -> int:
    root = root.resolve()
    dest = dest.resolve()
    if dest == root or dest in root.parents:
        raise SystemExit("Refusing to stage over the source tree.")
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    count = 0
    for path in iter_payload_files(root, dest):
        target = dest / path.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        count += 1
    launcher_source = root / "installer" / LAUNCHER_NAME
    shutil.copy2(launcher_source, dest / LAUNCHER_NAME)
    count += 1
    for rel in RUNTIME_FILES:
        source = root / rel
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        count += 1
    source_version = ""
    version_path = root / "VERSION"
    if version_path.is_file():
        source_version = version_path.read_text(encoding="utf-8")
    (dest / "VERSION").write_text(installer_session_epoch(source_version) + "\n", encoding="utf-8")
    missing = missing_required(dest)
    if missing:
        raise SystemExit("Installer payload is missing required files: " + ", ".join(missing))
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage the AI-Powered SOC Assistant Setup payload")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    args = parser.parse_args()
    count = stage(args.root, args.dest)
    print(f"Staged {count} files in {args.dest}")


if __name__ == "__main__":
    main()
