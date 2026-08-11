from __future__ import annotations

import hashlib
import json
import base64
import shutil
import tempfile
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Event, RLock
from typing import Any


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def version_key(value: str) -> tuple[int, int]:
    normalized = value.removesuffix("-dev")
    date_part, separator, patch_part = normalized.partition(".")
    if not separator or len(date_part) != 8 or not date_part.isdigit() or not patch_part.isdigit():
        raise ValueError("version must use YYYYMMDD.PATCH")
    return int(date_part), int(patch_part)


def verify_manifest_signature(manifest: dict[str, Any], public_key_base64: str) -> bool:
    """Ed25519 공개 키가 설정된 배포에서는 매니페스트 변조를 별도로 차단한다."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        signature = base64.b64decode(str(manifest["signature"]), validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_base64, validate=True))
        payload = {key: value for key, value in manifest.items() if key != "signature"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        public_key.verify(signature, canonical)
        return True
    except (KeyError, ValueError, TypeError, ImportError):
        return False


@dataclass(frozen=True)
class UpdateStatus:
    state: str
    current_version: str
    latest_version: str | None = None
    package_url: str | None = None
    package_sha256: str | None = None
    release_url: str | None = None
    signature: str = "not_configured"
    downloaded_path: str | None = None
    progress_percent: int = 0
    error: str | None = None


class GitHubUpdateService:
    """고정 GitHub 저장소의 릴리스 매니페스트만 확인하고 검증된 ZIP을 보관한다."""

    def __init__(self, current_version: str, staging_root: str | Path, *, repository: str = "Wakbu/weavexdr", public_key_base64: str = "") -> None:
        self.current_version = current_version
        self.staging_root = Path(staging_root).resolve()
        self.repository = repository
        self.public_key_base64 = public_key_base64.strip()
        self._lock = RLock()
        self._cancel = Event()
        self._status = UpdateStatus("idle", current_version)

    def status(self) -> dict[str, object]:
        with self._lock:
            return asdict(self._status)

    def check_latest(self) -> dict[str, object]:
        try:
            release = self._json(f"https://api.github.com/repos/{self.repository}/releases/latest")
            latest = str(release["tag_name"]).removeprefix("v")
            assets = {str(item["name"]): item for item in release.get("assets", [])}
            manifest_name = f"weavexdr-{latest}-manifest.json"
            package_name = f"weavexdr-{latest}-windows.zip"
            if manifest_name not in assets or package_name not in assets:
                raise ValueError("latest release is missing update manifest or Windows package")
            manifest = self._json(str(assets[manifest_name]["browser_download_url"]))
            if str(manifest.get("version")) != latest or str(manifest.get("package_name")) != package_name:
                raise ValueError("release manifest does not match release assets")
            signature_state = "verified" if self.public_key_base64 and verify_manifest_signature(manifest, self.public_key_base64) else "not_configured" if not self.public_key_base64 else "invalid"
            if signature_state == "invalid":
                raise ValueError("release manifest signature verification failed")
            available = version_key(latest) > version_key(self.current_version)
            status = UpdateStatus("available" if available else "current", self.current_version, latest, str(assets[package_name]["browser_download_url"]), str(manifest["package_sha256"]).casefold(), str(release["html_url"]), signature_state)
        except Exception as error:
            status = UpdateStatus("error", self.current_version, error=str(error))
        with self._lock:
            self._status = status
        return asdict(status)

    def download_latest(self) -> dict[str, object]:
        self._cancel.clear()
        current = self.check_latest()
        if current["state"] != "available":
            return current
        self.staging_root.mkdir(parents=True, exist_ok=True)
        destination = self.staging_root / f"weavexdr-{current['latest_version']}-windows.zip"
        temporary = destination.with_suffix(".download")
        try:
            request = urllib.request.Request(str(current["package_url"]), headers={"User-Agent": "WeaveXDR-Updater/1"})
            with urllib.request.urlopen(request, timeout=30) as response, temporary.open("wb") as output:
                expected_length = int(response.headers.get("Content-Length") or 0)
                received = 0
                while chunk := response.read(1024 * 256):
                    if self._cancel.is_set():
                        raise InterruptedError("update download cancelled")
                    received += len(chunk)
                    if received > 1024 * 1024 * 500:
                        raise ValueError("update package exceeds 500 MiB limit")
                    output.write(chunk)
                    with self._lock:
                        self._status = UpdateStatus("downloading", self.current_version, str(current["latest_version"]), str(current["package_url"]), str(current["package_sha256"]), str(current["release_url"]), str(current["signature"]), progress_percent=min(99, int(received * 100 / expected_length)) if expected_length else 0)
            if sha256_file(temporary) != str(current["package_sha256"]):
                raise ValueError("downloaded update checksum mismatch")
            temporary.replace(destination)
            status = UpdateStatus("downloaded", self.current_version, str(current["latest_version"]), str(current["package_url"]), str(current["package_sha256"]), str(current["release_url"]), str(current["signature"]), str(destination), 100)
        except Exception as error:
            temporary.unlink(missing_ok=True)
            status = UpdateStatus("error", self.current_version, error=str(error))
        with self._lock:
            self._status = status
        return asdict(status)

    def cancel_download(self) -> dict[str, object]:
        """다운로드 스레드가 다음 청크 경계에서 안전하게 임시 파일을 폐기하게 한다."""
        self._cancel.set()
        with self._lock:
            current = self._status
            if current.state == "downloading":
                self._status = UpdateStatus(
                    "cancelling", self.current_version, current.latest_version,
                    current.package_url, current.package_sha256, current.release_url,
                    current.signature, progress_percent=current.progress_percent,
                )
            return asdict(self._status)

    @staticmethod
    def _json(url: str) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={"User-Agent": "WeaveXDR-Updater/1", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(request, timeout=15) as response:
            if int(response.headers.get("Content-Length") or 0) > 1024 * 1024:
                raise ValueError("update metadata exceeds size limit")
            return json.loads(response.read(1024 * 1024).decode("utf-8"))


def apply_update(
    archive_path: str | Path,
    install_dir: str | Path,
    rollback_dir: str | Path,
    *,
    expected_sha256: str,
    current_version: str | None = None,
    allow_downgrade: bool = False,
) -> str:
    archive = Path(archive_path).resolve()
    install = Path(install_dir).resolve()
    rollback = Path(rollback_dir).resolve()
    if not install.is_dir():
        raise FileNotFoundError("current installation does not exist")
    if rollback.exists():
        raise FileExistsError("rollback directory already exists")
    if not expected_sha256 or sha256_file(archive) != expected_sha256.casefold():
        raise ValueError("update archive checksum mismatch")

    staging = Path(tempfile.mkdtemp(prefix="weavexdr-update-", dir=install.parent))
    try:
        with zipfile.ZipFile(archive) as package:
            for item in package.infolist():
                destination = (staging / item.filename).resolve()
                # ZIP 경로 탈출을 막아 업데이트가 설치 폴더 밖을 덮어쓰지 못하게 한다.
                if staging not in destination.parents and destination != staging:
                    raise ValueError("update archive contains an unsafe path")
            package.extractall(staging)
        manifest_path = staging / "weavexdr-release.json"
        # Windows PowerShell 5.1의 UTF-8 출력은 BOM을 포함할 수 있으므로 둘 다 허용한다.
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        version = str(manifest["version"])
        if current_version and not allow_downgrade and version_key(version) <= version_key(current_version):
            raise ValueError("update version must be newer than the installed version")

        # 같은 볼륨의 디렉터리 이름 변경을 사용해 현재 버전을 통째로 보존한다.
        # 새 버전 시작 실패 시 rollback_update가 원래 디렉터리를 복구한다.
        install.rename(rollback)
        try:
            staging.rename(install)
        except Exception:
            rollback.rename(install)
            raise
        return version
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def rollback_update(install_dir: str | Path, rollback_dir: str | Path) -> None:
    install = Path(install_dir).resolve()
    rollback = Path(rollback_dir).resolve()
    if not rollback.is_dir():
        raise FileNotFoundError("rollback installation does not exist")
    failed_dir = install.with_name(f"{install.name}.failed")
    if failed_dir.exists():
        raise FileExistsError("failed-version directory already exists")
    if install.exists():
        install.rename(failed_dir)
    try:
        rollback.rename(install)
    except Exception:
        if failed_dir.exists():
            failed_dir.rename(install)
        raise
    if failed_dir.exists():
        shutil.rmtree(failed_dir)
