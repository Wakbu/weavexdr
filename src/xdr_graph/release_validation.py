from __future__ import annotations

from pathlib import Path
import json
import re
import zipfile

from xdr_graph.runtime_security import validate_configuration


REQUIRED_DOCUMENTS = (
    "README.md",
    "PROJECT_ROADMAP.md",
    "docs/SECURITY.md",
    "docs/OPERATIONS.md",
)
REQUIRED_WINDOWS_PACKAGE_FILES = {
    "WeaveXDR.exe",
    "install.ps1",
    "uninstall.ps1",
    "configure_sysmon_access.ps1",
    "weavexdr-release.json",
}


def validate_release_tree(project_root: str | Path) -> list[str]:
    root = Path(project_root)
    errors = validate_configuration(root / "config")
    for relative_path in REQUIRED_DOCUMENTS:
        path = root / relative_path
        if not path.is_file():
            errors.append(f"missing required document: {relative_path}")
            continue
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"document is not valid UTF-8: {relative_path}")
    return errors


def validate_windows_package(package_path: str | Path) -> list[str]:
    errors: list[str] = []
    try:
        with zipfile.ZipFile(package_path) as package:
            names = set(package.namelist())
            missing = sorted(REQUIRED_WINDOWS_PACKAGE_FILES - names)
            errors.extend(f"package is missing: {name}" for name in missing)
            if not any(name.endswith(".whl") for name in names):
                errors.append("package is missing a Python wheel")
            if "weavexdr-release.json" in names:
                manifest = json.loads(package.read("weavexdr-release.json").decode("utf-8-sig"))
                if not re.fullmatch(r"\d{8}\.\d+", str(manifest.get("version", ""))):
                    errors.append("package version must use YYYYMMDD.PATCH")
            for script_name in ("install.ps1", "uninstall.ps1", "configure_sysmon_access.ps1"):
                if script_name in names:
                    package.read(script_name).decode("utf-8-sig")
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError, json.JSONDecodeError) as error:
        errors.append(f"invalid Windows package: {error}")
    return errors
