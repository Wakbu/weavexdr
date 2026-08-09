import hashlib
import json
import logging
import subprocess
import zipfile
from pathlib import Path

from xdr_graph.logging_setup import configure_rotating_logging
from xdr_graph.desktop import verify_embedded_server
from xdr_graph.release_validation import validate_windows_package
from xdr_graph.update_manager import apply_update, rollback_update
from xdr_graph.windows_service import SERVICE_NAME


PROJECT_ROOT = Path(__file__).parents[1]


def test_embedded_uvicorn_server_returns_health():
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse

    app = FastAPI()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/dashboard")
    def dashboard():
        return HTMLResponse("<title>WeaveXDR</title>")

    verify_embedded_server(app)


def test_log_rotation_limits_backup_files_and_preserves_utf8(tmp_path):
    logger = configure_rotating_logging(tmp_path, max_bytes=160, backup_count=2)
    for index in range(30):
        logger.info("보안 사건 security incident %s", index)
    for handler in logger.handlers:
        handler.flush()
    log_files = list(tmp_path.glob("weavexdr.log*"))
    assert 1 < len(log_files) <= 3
    assert all(path.stat().st_size < 300 for path in log_files)


def test_checksum_verified_update_and_rollback(tmp_path):
    install = tmp_path / "current"
    rollback = tmp_path / "rollback"
    install.mkdir()
    (install / "version.txt").write_text("old", encoding="utf-8")
    archive = tmp_path / "update.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("weavexdr-release.json", json.dumps({"version": "20260809.1"}))
        package.writestr("version.txt", "new")
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()

    assert apply_update(archive, install, rollback, expected_sha256=checksum) == "20260809.1"
    assert (install / "version.txt").read_text(encoding="utf-8") == "new"
    assert (rollback / "version.txt").read_text(encoding="utf-8") == "old"
    rollback_update(install, rollback)
    assert (install / "version.txt").read_text(encoding="utf-8") == "old"


def test_update_rejects_checksum_mismatch_without_touching_installation(tmp_path):
    install = tmp_path / "current"
    install.mkdir()
    (install / "marker.txt").write_text("safe", encoding="utf-8")
    archive = tmp_path / "update.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("weavexdr-release.json", "{}")
    try:
        apply_update(archive, install, tmp_path / "rollback", expected_sha256="0" * 64)
    except ValueError:
        pass
    else:
        raise AssertionError("checksum mismatch must reject the update")
    assert (install / "marker.txt").read_text(encoding="utf-8") == "safe"


def test_windows_service_name_and_installer_scripts_are_valid_powershell():
    assert SERVICE_NAME == "WeaveXDR"
    for script_name in (
        "install.ps1",
        "uninstall.ps1",
        "build_windows_package.ps1",
        "configure_sysmon_access.ps1",
    ):
        script_path = PROJECT_ROOT / "scripts" / script_name
        command = (
            "$tokens=$null; $errors=$null; "
            f"[System.Management.Automation.Language.Parser]::ParseFile('{script_path}', [ref]$tokens, [ref]$errors) | Out-Null; "
            "if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_ }; exit 1 }"
        )
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        assert completed.returncode == 0, completed.stderr


def test_windows_package_validation_checks_version_and_required_files(tmp_path):
    package_path = tmp_path / "weavexdr.zip"
    with zipfile.ZipFile(package_path, "w") as package:
        package.writestr("install.ps1", "Write-Host 'install'")
        package.writestr("uninstall.ps1", "Write-Host 'uninstall'")
        package.writestr("configure_sysmon_access.ps1", "Write-Host 'configure'")
        package.writestr("WeaveXDR.exe", b"portable executable placeholder")
        package.writestr("personal_xdr_graph-0.1.0.whl", b"placeholder")
        package.writestr("weavexdr-release.json", json.dumps({"version": "20260809.1"}))
    assert validate_windows_package(package_path) == []


def test_sysmon_access_script_is_powershell5_safe_and_reads_acl_attribute():
    script_path = PROJECT_ROOT / "scripts" / "configure_sysmon_access.ps1"
    script_bytes = script_path.read_bytes()
    script_text = script_bytes.decode("utf-8-sig")

    # Windows PowerShell 5는 BOM 없는 UTF-8의 한글을 시스템 ANSI 코드페이지로
    # 오해하므로 배포 스크립트는 UTF-8 BOM을 반드시 유지한다.
    assert script_bytes.startswith(b"\xef\xbb\xbf")
    assert "@channelAccess" in script_text
    assert "[switch]$CheckOnly" in script_text
