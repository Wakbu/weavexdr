from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

from xdr_graph.security import protect_user_secret, unprotect_user_secret


@dataclass(frozen=True)
class InstanceRecord:
    pid: int
    port: int
    version: str
    token: str
    state: str


class InstanceCoordinator:
    """Per-user single instance ownership and authenticated reopen handshake."""

    def __init__(self, data_root: Path, *, mutex_name: str = "Local\\WeaveXDR.SingleInstance") -> None:
        self.data_root = data_root
        self.record_path = data_root / "instance.json"
        self.lock_path = data_root / "instance.lock"
        self._mutex = None
        self._lock_fd: int | None = None
        self._mutex_name = mutex_name

    def acquire(self) -> bool:
        self.data_root.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            kernel32 = ctypes.windll.kernel32
            self._mutex = kernel32.CreateMutexW(None, False, self._mutex_name)
            if not self._mutex:
                raise OSError("single instance mutex could not be created")
            return kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS
        try:
            self._lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            return True
        except FileExistsError:
            return False

    def publish(self, record: InstanceRecord) -> None:
        # 중간에 종료되어도 반쪽 JSON을 다음 실행이 읽지 않도록 원자적으로 교체한다.
        temporary_path = self.record_path.with_suffix(".tmp")
        payload = asdict(record)
        payload["token_protected"] = protect_user_secret(payload.pop("token"))
        temporary_path.write_text(json.dumps(payload), encoding="utf-8")
        try:
            os.chmod(temporary_path, 0o600)
        except OSError:
            pass
        os.replace(temporary_path, self.record_path)

    def read(self) -> InstanceRecord | None:
        try:
            payload = json.loads(self.record_path.read_text(encoding="utf-8"))
            if "token_protected" in payload:
                payload["token"] = unprotect_user_secret(payload.pop("token_protected"))
            return InstanceRecord(**payload)
        except (OSError, ValueError, TypeError):
            return None

    def request_existing_dashboard(self, timeout: float = 2.0) -> bool:
        record = self.read()
        if record is None:
            return False
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(18)
        signed = f"{record.pid}:{record.port}:{record.version}:{timestamp}:{nonce}".encode()
        signature = hmac.new(record.token.encode(), signed, hashlib.sha256).hexdigest()
        request = urllib.request.Request(
            f"http://127.0.0.1:{record.port}/instance/open",
            method="POST",
            headers={
                "X-WeaveXDR-Timestamp": timestamp,
                "X-WeaveXDR-Nonce": nonce,
                "X-WeaveXDR-Signature": signature,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
                # PID·버전을 같이 검증해 다른 loopback 서버를 기존 인스턴스로 오인하지 않는다.
                return (
                    response.status == 200
                    and payload.get("pid") == record.pid
                    and payload.get("version") == record.version
                )
        except (OSError, urllib.error.URLError, ValueError):
            return False

    def clear(self) -> None:
        try:
            self.record_path.unlink(missing_ok=True)
        finally:
            if os.name == "nt" and self._mutex:
                ctypes.windll.kernel32.CloseHandle(self._mutex)
                self._mutex = None
            elif self._lock_fd is not None:
                os.close(self._lock_fd)
                self._lock_fd = None
                self.lock_path.unlink(missing_ok=True)
