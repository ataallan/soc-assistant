"""Windows standalone icon, venv repair rules, and customer zip contents."""

from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_standalone_zip  # noqa: E402
import standalone_support  # noqa: E402

ICO = ROOT / "static" / "img" / "ai-powered-soc-assistant.ico"


def _write_python(venv: Path, import_exit: int, boot_exit: int = 0) -> None:
    exe = venv / "Scripts" / "python.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "code = sys.argv[2] if len(sys.argv) >= 3 and sys.argv[1] == '-c' else ''\n"
        "if code.strip() == 'import sys':\n"
        f"    raise SystemExit({boot_exit})\n"
        "if 'flask' in code:\n"
        f"    raise SystemExit({import_exit})\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    exe.chmod(0o755)


def _site(venv: Path) -> Path:
    path = venv / "Lib" / "site-packages"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _icon_entries(data: bytes) -> list[tuple[int, int, int, bytes]]:
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    assert reserved == 0
    assert kind == 1
    entries = []
    for index in range(count):
        width, _height, _colors, _reserved, planes, bits, size, offset = struct.unpack_from(
            "<BBBBHHII", data, 6 + index * 16
        )
        blob = data[offset : offset + size]
        entries.append((width or 256, planes, bits, blob))
    return entries


def test_icon_contains_standard_png_sizes():
    entries = _icon_entries(ICO.read_bytes())
    assert len(entries) >= 4
    widths = []
    for width, planes, bits, blob in entries:
        widths.append(width)
        assert planes == 1
        assert bits == 32
        assert blob[:8] == b"\x89PNG\r\n\x1a\n"
        # IHDR color type 6 is RGBA, so the transparent logo background is kept.
        assert blob[25] == 6
    for expected in (16, 24, 32, 48, 64, 128, 256):
        assert expected in widths


def test_committed_icon_matches_logo_builder(tmp_path: Path):
    pytest.importorskip("PIL")
    import build_icon

    built = build_icon.build_icon(dest=tmp_path / "ai-powered-soc-assistant.ico")
    assert built.read_bytes() == ICO.read_bytes()


def test_optional_ml_names_cover_pip_tilde_leftovers():
    assert standalone_support.is_optional_ml_name("~orch")
    assert standalone_support.is_optional_ml_name("~orch-2.2.0.dist-info")
    assert standalone_support.is_optional_ml_name("~orchvision")
    assert standalone_support.is_optional_ml_name("~ltralytics")
    assert standalone_support.is_optional_ml_name("ultralytics-8.0.0.dist-info")
    assert not standalone_support.is_optional_ml_name("~umpy")
    assert not standalone_support.is_optional_ml_name("~lask")
    assert not standalone_support.is_optional_ml_name("~klearn")
    assert not standalone_support.is_optional_ml_name("flask-3.0.0.dist-info")
    assert not standalone_support.is_optional_ml_name("scikit_learn-1.5.0.dist-info")


def test_healthy_metadata_is_not_a_corrupt_marker(tmp_path: Path):
    info = tmp_path / "flask-3.0.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text("Metadata-Version: 2.1\n", encoding="utf-8")
    assert standalone_support.distribution_marker(info) is None


def test_missing_venv_is_recreated(tmp_path: Path):
    report = standalone_support.assess_venv(tmp_path / ".venv")
    assert report["action"] == "recreate"
    assert report["reason"] == "missing"


def test_missing_core_imports_install_without_deleting(tmp_path: Path):
    venv = tmp_path / ".venv"
    _write_python(venv, import_exit=1)
    _site(venv)
    report = standalone_support.assess_venv(venv)
    assert report["action"] == "install"
    assert report["reason"] == "incomplete"


def test_torch_tilde_leftover_with_healthy_imports_is_scrubbed(tmp_path: Path):
    venv = tmp_path / ".venv"
    _write_python(venv, import_exit=0)
    site = _site(venv)
    (site / "~orch").mkdir()
    (site / "flask").mkdir()
    report = standalone_support.assess_venv(venv)
    assert report["action"] == "scrub_optional"
    assert "~orch" in report["markers"]

    removed = standalone_support.scrub_optional(venv)
    assert removed == ["~orch"]
    assert not (site / "~orch").exists()
    assert (site / "flask").is_dir()
    assert standalone_support.assess_venv(venv)["action"] == "ready"


def test_torch_tilde_leftover_with_failed_imports_recreates(tmp_path: Path):
    venv = tmp_path / ".venv"
    _write_python(venv, import_exit=1)
    site = _site(venv)
    (site / "~orch").mkdir()
    (site / "~ltralytics").mkdir()
    report = standalone_support.assess_venv(venv)
    assert report["action"] == "recreate"
    assert report["reason"] == "damaged"
    assert "~orch" in report["markers"]


def test_core_tilde_leftover_recreates_even_when_imports_work(tmp_path: Path):
    venv = tmp_path / ".venv"
    _write_python(venv, import_exit=0)
    site = _site(venv)
    (site / "~lask").mkdir()
    report = standalone_support.assess_venv(venv)
    assert report["action"] == "recreate"
    assert report["reason"] == "damaged"


def test_invalid_optional_dist_info_is_scrubbed(tmp_path: Path):
    venv = tmp_path / ".venv"
    _write_python(venv, import_exit=0)
    site = _site(venv)
    (site / "ultralytics-8.3.0.dist-info").mkdir()
    report = standalone_support.assess_venv(venv)
    assert report["action"] == "scrub_optional"
    removed = standalone_support.scrub_optional(venv)
    assert removed == ["ultralytics-8.3.0.dist-info"]


def test_invalid_core_dist_info_recreates(tmp_path: Path):
    venv = tmp_path / ".venv"
    _write_python(venv, import_exit=0)
    site = _site(venv)
    (site / "flask-3.0.0.dist-info").mkdir()
    report = standalone_support.assess_venv(venv)
    assert report["action"] == "recreate"


def test_broken_interpreter_recreates(tmp_path: Path):
    venv = tmp_path / ".venv"
    _write_python(venv, import_exit=0, boot_exit=1)
    report = standalone_support.assess_venv(venv)
    assert report["action"] == "recreate"
    assert report["reason"] == "damaged"


def test_desktop_or_onedrive_path_asks_for_local_copy():
    assert standalone_support.cloud_locked_install_path(
        r"C:\Users\a\OneDrive\Desktop\MunCyberSOC"
    )
    assert standalone_support.cloud_locked_install_path(
        r"C:\Users\a\OneDrive - Mun\Desktop\AI-Powered SOC Assistant"
    )
    assert standalone_support.cloud_locked_install_path(
        r"C:\Users\a\Desktop\AI-Powered SOC Assistant",
        desktop_path=r"C:\Users\a\Desktop",
    )
    assert standalone_support.cloud_locked_install_path(r"C:\Users\a\Desktop\soc")
    assert not standalone_support.cloud_locked_install_path(r"C:\MunCyberSOC")
    assert not standalone_support.cloud_locked_install_path(r"D:\labs\soc-assistant")


def test_requirements_keep_core_stack_and_leave_torch_out():
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    lowered = text.lower()
    assert "scikit-learn" in lowered
    assert "psycopg" in lowered
    assert "flask-mail" in lowered
    assert "pyyaml" in lowered
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assert "ultralytics" not in stripped
        assert not stripped.startswith("torch")
        assert "tensorflow" not in stripped


def test_launchers_check_core_imports_and_skip_reinstall():
    statement = standalone_support.CRITICAL_IMPORT_STATEMENT
    bat = (ROOT / "Start AI-Powered SOC Assistant.bat").read_text(encoding="utf-8")
    ps1 = (ROOT / "start_dashboard.ps1").read_text(encoding="utf-8")
    assert statement in bat
    assert statement in ps1
    assert "pip" not in bat.lower()
    assert "SOC_OPEN_BROWSER=1" in bat
    assert 'SOC_OPEN_BROWSER = "1"' in ps1
    assert "dashboard.py" in bat
    assert "5000" in bat


def test_installer_wires_shortcuts_log_and_self_heal():
    ps1 = (ROOT / "install_and_run.ps1").read_text(encoding="utf-8")
    assert "IconLocation" in ps1
    assert "WorkingDirectory" in ps1
    assert "install.log" in ps1
    assert r"C:\MunCyberSOC" in ps1
    assert "Start only" in ps1
    assert "scrub-optional" in ps1
    assert "standalone_support.py" in ps1
    assert "AI-Powered SOC Assistant.lnk" in ps1
    assert "Start AI-Powered SOC Assistant.bat" in ps1
    assert "ai-powered-soc-assistant.ico,0" in ps1
    assert "SECRET_KEY" in ps1
    wrapper = (ROOT / "install_and_run.bat").read_text(encoding="utf-8")
    assert "ExecutionPolicy Bypass" in wrapper
    assert "install_and_run.ps1" in wrapper


def test_windows_scripts_use_crlf():
    for name in (
        "install_and_run.bat",
        "install_and_run.ps1",
        "Start AI-Powered SOC Assistant.bat",
        "start_dashboard.ps1",
    ):
        data = (ROOT / name).read_bytes()
        assert b"\r\n" in data, name
        assert b"\n" not in data.replace(b"\r\n", b""), name


def test_should_skip_logs_shortcuts_secrets_and_tunnels(tmp_path: Path):
    (tmp_path / "install.log").write_text("pip\n", encoding="utf-8")
    (tmp_path / "AI-Powered SOC Assistant.lnk").write_bytes(b"lnk")
    (tmp_path / ".env").write_text("RESEND_API_KEY=secret\n", encoding="utf-8")
    (tmp_path / "users.csv").write_text("email\n", encoding="utf-8")
    (tmp_path / "cloudflared.exe").write_bytes(b"x")
    (tmp_path / "ngrok.yml").write_text("token: secret\n", encoding="utf-8")
    (tmp_path / "tunnel.token").write_text("secret\n", encoding="utf-8")
    (tmp_path / "keep.txt").write_text("ok\n", encoding="utf-8")
    assert build_standalone_zip.should_skip(tmp_path / "install.log", tmp_path)
    assert build_standalone_zip.should_skip(tmp_path / "AI-Powered SOC Assistant.lnk", tmp_path)
    assert build_standalone_zip.should_skip(tmp_path / ".env", tmp_path)
    assert build_standalone_zip.should_skip(tmp_path / "users.csv", tmp_path)
    assert build_standalone_zip.should_skip(tmp_path / "cloudflared.exe", tmp_path)
    assert build_standalone_zip.should_skip(tmp_path / "ngrok.yml", tmp_path)
    assert build_standalone_zip.should_skip(tmp_path / "tunnel.token", tmp_path)
    assert not build_standalone_zip.should_skip(tmp_path / "keep.txt", tmp_path)


def test_missing_required_names_customer_files(tmp_path: Path):
    missing = build_standalone_zip.missing_required(tmp_path)
    assert "static/img/ai-powered-soc-assistant.ico" in missing
    assert "Start AI-Powered SOC Assistant.bat" in missing
    assert "start_dashboard.ps1" in missing
    assert "install_and_run.bat" in missing


def test_customer_zip_contains_icon_and_launchers(tmp_path: Path):
    dest = tmp_path / "AI-Powered-SOC-Assistant-standalone.zip"
    count = build_standalone_zip.build_zip(ROOT, dest)
    assert count > 0
    with zipfile.ZipFile(dest) as archive:
        names = set(archive.namelist())
    for rel in build_standalone_zip.REQUIRED_ZIP_PATHS:
        assert rel in names
    assert ".env" not in names
    assert "install.log" not in names
    assert "users.csv" not in names
    assert not any(name.endswith(".lnk") for name in names)
    assert not any(name.endswith(".token") for name in names)
    assert not any("cloudflared" in name.lower() or "ngrok" in name.lower() for name in names)
    assert not any(name.startswith(".venv/") or name.startswith(".git/") for name in names)


def test_build_zip_refuses_incomplete_tree(tmp_path: Path):
    with pytest.raises(SystemExit):
        build_standalone_zip.build_zip(tmp_path, tmp_path / "out.zip")


def test_standalone_browser_flag_opens_login_once(monkeypatch):
    import dashboard

    monkeypatch.delenv("SOC_OPEN_BROWSER", raising=False)
    monkeypatch.delenv("WERKZEUG_RUN_MAIN", raising=False)
    assert dashboard._should_open_browser() is False
    monkeypatch.setenv("SOC_OPEN_BROWSER", "1")
    assert dashboard._should_open_browser() is True
    assert dashboard._standalone_login_url(5000) == "http://127.0.0.1:5000/login"
    monkeypatch.setenv("WERKZEUG_RUN_MAIN", "true")
    assert dashboard._should_open_browser() is False
