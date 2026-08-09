from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def apply_update(
    archive_path: str | Path,
    install_dir: str | Path,
    rollback_dir: str | Path,
    *,
    expected_sha256: str,
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
