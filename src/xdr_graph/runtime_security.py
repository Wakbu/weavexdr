from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


SECRET_FIELD_NAMES = {"api_token", "password", "secret", "privacy_salt", "private_key"}
ELEVATED_ACTIONS = {"block_network", "install_service", "uninstall_service"}


@dataclass(frozen=True)
class RuntimeSecrets:
    api_token: str
    privacy_salt: str

    @classmethod
    def from_environment(cls) -> "RuntimeSecrets":
        api_token = os.environ.get("WEAVEXDR_API_TOKEN", "")
        privacy_salt = os.environ.get("WEAVEXDR_PRIVACY_SALT", "")
        if len(api_token) < 32:
            raise ValueError("WEAVEXDR_API_TOKEN must contain at least 32 characters")
        if len(privacy_salt) < 16:
            raise ValueError("WEAVEXDR_PRIVACY_SALT must contain at least 16 characters")
        return cls(api_token=api_token, privacy_salt=privacy_salt)

    def redacted(self) -> dict[str, str]:
        # 로그와 진단 화면은 값의 존재만 알려야 하며 일부 문자도 노출하지 않는다.
        return {"api_token": "<configured>", "privacy_salt": "<configured>"}


@dataclass(frozen=True)
class PrivilegeBoundary:
    active_response_enabled: bool = False
    elevated_check: Callable[[], bool] = lambda: False

    def authorize(self, action: str) -> tuple[bool, str]:
        if not self.active_response_enabled:
            return False, "active response is disabled by default"
        if action in ELEVATED_ACTIONS and not self.elevated_check():
            return False, "action requires an elevated worker"
        return True, "authorized within the configured privilege boundary"


def validate_configuration(config_dir: str | Path) -> list[str]:
    root = Path(config_dir)
    errors: list[str] = []
    for path in sorted(root.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"{path.name}: invalid JSON: {error}")
            continue
        for field_name in _walk_field_names(payload):
            if field_name.casefold() in SECRET_FIELD_NAMES:
                errors.append(f"{path.name}: secret field must be supplied at runtime: {field_name}")

    response_path = root / "response-policy.json"
    if response_path.exists():
        response = json.loads(response_path.read_text(encoding="utf-8"))
        approval_required = set(response.get("approval_required_actions", []))
        dangerous = {"terminate_process", "quarantine_file", "block_network"}
        missing = sorted(dangerous - approval_required)
        if missing:
            errors.append(f"response-policy.json: approval missing for {', '.join(missing)}")
    return errors


def _walk_field_names(value) -> list[str]:
    names: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            names.append(str(key))
            names.extend(_walk_field_names(nested))
    elif isinstance(value, list):
        for nested in value:
            names.extend(_walk_field_names(nested))
    return names
