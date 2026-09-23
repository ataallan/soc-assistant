"""Windows Setup.exe sources: payload, launcher, icon, and Inno Setup script."""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_standalone_zip  # noqa: E402
import stage_installer_payload  # noqa: E402
import standalone_support  # noqa: E402

ISS = ROOT / "installer" / "AIPoweredSOCAssistant.iss"
BOOTSTRAP = ROOT / "installer" / "bootstrap_embedded_python.ps1"
LAUNCHER_PS1 = ROOT / "installer" / "launch_app.ps1"
LAUNCHER_BAT = ROOT / "installer" / "Launch AI-Powered SOC Assistant.bat"
BUILD_PS1 = ROOT / "scripts" / "build_windows_installer.ps1"
ICON = ROOT / "static" / "img" / "ai-powered-soc-assistant.ico"

WINDOWS_TEXT_FILES = (
    BOOTSTRAP,
    LAUNCHER_PS1,
    LAUNCHER_BAT,
    BUILD_PS1,
)


def _crlf(path: Path) -> None:
    data = path.read_bytes()
    assert b"\r\n" in data, path.name
    assert b"\n" not in data.replace(b"\r\n", b""), path.name


def test_windows_installer_scripts_use_crlf():
    for path in WINDOWS_TEXT_FILES:
        _crlf(path)


def test_embedded_python_pin_matches_bootstrap():
    text = BOOTSTRAP.read_text(encoding="utf-8")
    assert standalone_support.EMBEDDED_PYTHON_URL in text
    assert standalone_support.EMBEDDED_PYTHON_SHA256 in text
    assert standalone_support.GET_PIP_URL in text
    assert standalone_support.EMBEDDED_PYTHON_SHA256 == (
        "156c7eea90d58cd7e91a23f28a0056616b13e9f4cf4901b7b99b837b7848c6da"
    )
    assert standalone_support.EMBEDDED_PYTHON_URL.startswith("https://www.python.org/ftp/python/")


def test_render_embedded_pth_enables_site_packages():
    original = "python312.zip\r\n.\r\n\r\n# Uncomment to run site.main() automatically\r\n#import site\r\n"
    rendered = standalone_support.render_embedded_pth(original)
    assert rendered == "python312.zip\r\n.\r\nLib\\site-packages\r\nimport site\r\n"
    assert standalone_support.render_embedded_pth(rendered) == rendered


def test_write_pth_command_rewrites_embeddable_file(tmp_path: Path):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    pth = runtime / "python312._pth"
    pth.write_text("python312.zip\r\n.\r\n#import site\r\n", encoding="ascii")
    code = standalone_support.main(["write-pth", str(runtime)])
    assert code == 0
    assert pth.read_bytes() == b"python312.zip\r\n.\r\nLib\\site-packages\r\nimport site\r\n"


def test_embeddable_python_exe_is_found_after_venv_layout(tmp_path: Path):
    runtime = tmp_path / "runtime"
    exe = runtime / "python.exe"
    exe.parent.mkdir()
    exe.write_text("embed\n", encoding="utf-8")
    assert standalone_support.venv_python(runtime) == exe

    scripts = runtime / "Scripts" / "python.exe"
    scripts.parent.mkdir()
    scripts.write_text("venv\n", encoding="utf-8")
    assert standalone_support.venv_python(runtime) == scripts


def test_setup_script_installs_one_desktop_icon_and_uninstaller():
    text = ISS.read_text(encoding="utf-8")
    assert text.count("{autodesktop}") == 1
    assert r"{localappdata}\AIPoweredSOCAssistant" in text
    assert "AIPoweredSOCAssistantSetup" in text
    assert "ai-powered-soc-assistant.ico" in text
    assert "bootstrap_embedded_python.ps1" in text
    assert "Launch AI-Powered SOC Assistant.bat" in text
    assert "Uninstall {#AppName}" in text
    assert "PrivilegesRequired=lowest" in text
    assert "ArchitecturesAllowed=x64compatible" in text
    assert "install_and_run" not in text
    assert "SOC_EMAIL_2FA=false" not in text
    assert "ngrok" not in text.lower()
    assert "cloudflared" not in text.lower()


def test_launcher_opens_login_on_port_5000_without_reinstall():
    bat = LAUNCHER_BAT.read_text(encoding="utf-8")
    ps1 = LAUNCHER_PS1.read_text(encoding="utf-8")
    assert "launch_app.ps1" in bat
    assert 'SOC_OPEN_BROWSER = "1"' in ps1
    assert 'SOC_FLASK_HOST = "127.0.0.1"' in ps1
    assert 'SOC_FLASK_PORT = "5000"' in ps1
    assert "http://127.0.0.1:5000/login" in ps1
    assert "dashboard.py" in ps1
    assert "install_and_run" not in ps1
    assert "SOC_EMAIL_2FA=false" not in ps1
    lowered = ps1.lower()
    assert "pip install" not in lowered
    assert ".venv" not in lowered


def test_bootstrap_reuses_support_helpers_and_keeps_customer_copy_clean():
    text = BOOTSTRAP.read_text(encoding="utf-8")
    assert "write-pth" in text
    assert "scrub-optional" in text
    assert " assess " in text
    assert "SECRET_KEY=change-me-to-a-long-random-string" in text
    assert "SOC_EMAIL_2FA=false" not in text
    assert "ngrok" not in text.lower()
    assert "cloudflared" not in text.lower()
    for line in text.splitlines():
        if "Write-Host" not in line or "$line" in line or "Exception" in line:
            continue
        lowered = line.lower()
        assert ".venv" not in lowered
        assert "requirements.txt" not in lowered
        assert "unzip" not in lowered


def test_build_script_compiles_setup_exe():
    text = BUILD_PS1.read_text(encoding="utf-8")
    assert "ISCC.exe" in text
    assert "AIPoweredSOCAssistantSetup.exe" in text
    assert "stage_installer_payload.py" in text
    assert "jrsoftware.org/isdl.php" in text
    assert "Session stamp for this setup" in text


def test_staged_payload_has_icon_launcher_and_no_secrets(tmp_path: Path):
    dest = tmp_path / "payload"
    count = stage_installer_payload.stage(ROOT, dest)
    assert count > 0
    assert stage_installer_payload.missing_required(dest) == []
    icon = dest / "static" / "img" / "ai-powered-soc-assistant.ico"
    assert icon.read_bytes() == ICON.read_bytes()
    names = {path.relative_to(dest).as_posix() for path in dest.rglob("*") if path.is_file()}
    assert "install_and_run.ps1" not in names
    assert "install_and_run.bat" not in names
    assert "Start AI-Powered SOC Assistant.bat" not in names
    assert "installer/AIPoweredSOCAssistant.iss" not in names
    assert ".env" not in names
    assert "users.csv" not in names
    assert not any(name.endswith(".lnk") for name in names)
    assert not any(name.endswith(".token") or name.endswith(".pem") for name in names)
    assert not any("cloudflared" in name.lower() or "ngrok" in name.lower() for name in names)
    assert not any(name.startswith(".venv/") or "/.venv/" in name for name in names)
    assert "tests/test_health.py" not in names
    launcher = (dest / "Launch AI-Powered SOC Assistant.bat").read_text(encoding="utf-8")
    assert "launch_app.ps1" in launcher
    source = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    stamped = (dest / "VERSION").read_text(encoding="utf-8").strip()
    assert stamped.startswith(source + "+")
    assert stamped != source
    assert len(stamped.rsplit("+", 1)[1]) == 14


def test_customer_zip_stays_a_folder_install_without_the_setup_compiler(tmp_path: Path):
    dest = tmp_path / "AI-Powered-SOC-Assistant-standalone.zip"
    build_standalone_zip.build_zip(ROOT, dest)
    with zipfile.ZipFile(dest) as archive:
        names = set(archive.namelist())
    assert "install_and_run.bat" in names
    assert "installer/AIPoweredSOCAssistant.iss" not in names
    assert "installer/bootstrap_embedded_python.ps1" not in names
    assert not any(name.startswith(".github/") for name in names)


def test_workflow_builds_setup_exe_on_windows():
    text = (ROOT / ".github" / "workflows" / "windows-installer.yml").read_text(encoding="utf-8")
    assert "windows-latest" in text
    assert "build_windows_installer.ps1" in text
    assert "AIPoweredSOCAssistantSetup.exe" in text
    assert "innosetup" in text


def test_installer_doc_covers_customer_and_build_steps():
    text = (ROOT / "docs" / "INSTALLER.md").read_text(encoding="utf-8")
    assert "AIPoweredSOCAssistantSetup.exe" in text
    assert r"%LocalAppData%\AIPoweredSOCAssistant" in text
    assert "127.0.0.1:5000/login" in text
    assert "build_windows_installer.ps1" in text
    assert "windows-installer.yml" in text
    assert "VERSION" in text
    assert "email" in text.lower()
    assert "SOC_EMAIL_2FA" in text
    assert "false" not in text.split("SOC_EMAIL_2FA", 1)[1][:80]
