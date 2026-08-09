from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

import yara

from xdr_graph.models import Finding


PowerShellRunner = Callable[[str, Path, float], str]


@dataclass(frozen=True)
class FileMetadata:
    path: str
    size_bytes: int
    modified_at: datetime
    mime_type: str | None
    sha256: str


@dataclass(frozen=True)
class SignatureResult:
    status: Literal["valid", "not_signed", "invalid", "unavailable", "error", "unknown"]
    signer: str | None = None
    timestamp_signer: str | None = None
    message: str | None = None


@dataclass(frozen=True)
class YaraRuleMatch:
    rule: str
    namespace: str
    severity: int
    description: str


@dataclass(frozen=True)
class DefenderResult:
    scanned: bool
    threat_names: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class FileInspectionResult:
    metadata: FileMetadata
    signature: SignatureResult
    yara_matches: tuple[YaraRuleMatch, ...]
    defender: DefenderResult
    findings: tuple[Finding, ...]


def _run_powershell_json(script: str, target_path: Path, timeout: float) -> str:
    """고정 스크립트를 실행하고 대상 경로는 환경 변수로 안전하게 전달한다."""

    # 파일 경로를 PowerShell 코드에 이어 붙이면 따옴표나 세미콜론이 포함된
    # 경로가 명령 주입으로 바뀔 수 있다. 스크립트는 Base64로 고정하고 경로는
    # 별도 환경 변수로 전달해 데이터와 코드를 분리한다.
    encoded_script = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    command_environment = os.environ.copy()
    command_environment["XDR_TARGET_FILE"] = str(target_path)
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded_script,
        ],
        capture_output=True,
        text=True,
        # Windows PowerShell의 리디렉션 출력은 시스템 cp949 설정과 달리 UTF-8을
        # 내보낼 수 있다. 명시적으로 해석해 한글 오류 메시지에서도 reader가 죽지 않게 한다.
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=command_environment,
        check=False,
    )
    if completed.returncode != 0:
        error_message = (completed.stderr or "").strip() or (completed.stdout or "").strip()
        raise RuntimeError(error_message or f"PowerShell exited with {completed.returncode}")
    return completed.stdout.strip()


class AuthenticodeInspector:
    """Windows Authenticode 상태를 읽되 파일을 변경하지 않는다."""

    _SCRIPT = """
$signature = Get-AuthenticodeSignature -LiteralPath $env:XDR_TARGET_FILE
[pscustomobject]@{
    Status = [string]$signature.Status
    StatusMessage = $signature.StatusMessage
    Signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    TimestampSigner = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Subject } else { $null }
} | ConvertTo-Json -Compress
"""

    def __init__(self, runner: PowerShellRunner = _run_powershell_json) -> None:
        self._runner = runner

    def inspect(self, target_path: Path, *, timeout: float = 10.0) -> SignatureResult:
        if os.name != "nt" and self._runner is _run_powershell_json:
            return SignatureResult(status="unavailable", message="Authenticode requires Windows")
        try:
            payload = json.loads(self._runner(self._SCRIPT, target_path, timeout))
        except (OSError, subprocess.TimeoutExpired, RuntimeError, json.JSONDecodeError) as error:
            # 서명 조회 실패를 파일 악성 판정으로 오인하지 않고 별도 상태로 남긴다.
            return SignatureResult(status="error", message=str(error))

        raw_status = str(payload.get("Status", "Unknown"))
        status_map = {
            "Valid": "valid",
            "NotSigned": "not_signed",
            "HashMismatch": "invalid",
            "NotTrusted": "invalid",
            "UnknownError": "error",
        }
        return SignatureResult(
            status=status_map.get(raw_status, "unknown"),
            signer=payload.get("Signer"),
            timestamp_signer=payload.get("TimestampSigner"),
            message=payload.get("StatusMessage"),
        )


class YaraScanner:
    """한 개 이상의 YARA 규칙 파일을 미리 컴파일해 반복 검사한다."""

    def __init__(self, rule_paths: list[str | Path]) -> None:
        if not rule_paths:
            raise ValueError("at least one YARA rule file is required")
        # yara-python의 Windows 파일 경로 처리는 비 ASCII 프로젝트 경로에서
        # 실패할 수 있다. Python이 UTF-8로 읽은 규칙 본문을 넘겨 한글 경로와
        # 무관하게 같은 규칙을 컴파일한다.
        rule_sources = {
            f"rules_{index}": Path(rule_path).read_text(encoding="utf-8")
            for index, rule_path in enumerate(rule_paths)
        }
        self._rules = yara.compile(sources=rule_sources)

    def scan(self, target_path: Path, *, timeout: int = 10) -> tuple[YaraRuleMatch, ...]:
        # 규칙과 동일하게 YARA의 Windows 경로 API가 한글을 열지 못하므로
        # Python으로 읽은 바이트를 검사한다. 파일 크기 제한은 다음 안정화 단계에서 적용한다.
        matches = self._rules.match(data=target_path.read_bytes(), timeout=timeout)
        normalized: list[YaraRuleMatch] = []
        for match in matches:
            raw_severity = match.meta.get("severity", 70)
            severity = max(0, min(100, int(raw_severity)))
            normalized.append(
                YaraRuleMatch(
                    rule=match.rule,
                    namespace=match.namespace,
                    severity=severity,
                    description=str(match.meta.get("description", match.rule)),
                )
            )
        return tuple(normalized)


class DefenderScanner:
    """Microsoft Defender 사용자 지정 검사를 실행하고 해당 파일 탐지를 조회한다."""

    _SCRIPT = """
$target = [System.IO.Path]::GetFullPath($env:XDR_TARGET_FILE)
Start-MpScan -ScanType CustomScan -ScanPath $target -ErrorAction Stop
$detections = Get-MpThreatDetection -ErrorAction Stop | Where-Object {
    $_.Resources | Where-Object { $_ -like "*$target*" }
}
[pscustomobject]@{
    ThreatNames = @($detections | ForEach-Object { $_.ThreatName } | Sort-Object -Unique)
} | ConvertTo-Json -Compress
"""

    def __init__(self, runner: PowerShellRunner = _run_powershell_json) -> None:
        self._runner = runner

    def scan(self, target_path: Path, *, timeout: float = 120.0) -> DefenderResult:
        if os.name != "nt" and self._runner is _run_powershell_json:
            return DefenderResult(scanned=False, error="Microsoft Defender requires Windows")
        try:
            payload = json.loads(self._runner(self._SCRIPT, target_path, timeout))
            names = tuple(str(name) for name in payload.get("ThreatNames", []) if name)
            return DefenderResult(scanned=True, threat_names=names)
        except (OSError, subprocess.TimeoutExpired, RuntimeError, json.JSONDecodeError) as error:
            # Defender 장애 시 깨끗하다고 간주하면 탐지 공백이 생기므로 scanned=False로 구분한다.
            return DefenderResult(scanned=False, error=str(error))


class FileInspectionEngine:
    """파일의 정적 정보와 외부 검사 결과를 공통 Finding으로 합친다."""

    def __init__(
        self,
        yara_scanner: YaraScanner,
        *,
        signature_inspector: AuthenticodeInspector | None = None,
        defender_scanner: DefenderScanner | None = None,
    ) -> None:
        self.yara_scanner = yara_scanner
        self.signature_inspector = signature_inspector or AuthenticodeInspector()
        self.defender_scanner = defender_scanner or DefenderScanner()

    def inspect(self, file_path: str | Path, *, event_id: str) -> FileInspectionResult:
        target_path = Path(file_path).resolve(strict=True)
        if not target_path.is_file():
            raise ValueError(f"inspection target is not a regular file: {target_path}")

        metadata = self._collect_metadata(target_path)
        signature = self.signature_inspector.inspect(target_path)
        yara_matches = self.yara_scanner.scan(target_path)
        defender = self.defender_scanner.scan(target_path)
        findings = self._to_findings(event_id, signature, yara_matches, defender)
        return FileInspectionResult(
            metadata=metadata,
            signature=signature,
            yara_matches=yara_matches,
            defender=defender,
            findings=findings,
        )

    @staticmethod
    def _collect_metadata(target_path: Path) -> FileMetadata:
        digest = hashlib.sha256()
        # 큰 파일을 한 번에 메모리에 올리지 않도록 고정 크기 블록으로 읽는다.
        with target_path.open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                digest.update(chunk)
        file_stat = target_path.stat()
        return FileMetadata(
            path=str(target_path),
            size_bytes=file_stat.st_size,
            modified_at=datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc),
            mime_type=mimetypes.guess_type(target_path.name)[0],
            sha256=digest.hexdigest(),
        )

    @staticmethod
    def _to_findings(
        event_id: str,
        signature: SignatureResult,
        yara_matches: tuple[YaraRuleMatch, ...],
        defender: DefenderResult,
    ) -> tuple[Finding, ...]:
        findings = [
            Finding(
                source="file",
                rule_id=f"YARA-{match.rule}",
                severity=match.severity,
                reason=match.description,
                event_ids=[event_id],
            )
            for match in yara_matches
        ]
        for threat_name in defender.threat_names:
            findings.append(
                Finding(
                    source="file",
                    rule_id="DEFENDER-MALWARE",
                    severity=100,
                    reason=f"Microsoft Defender detected {threat_name}",
                    event_ids=[event_id],
                )
            )
        # 서명 없음은 흔하므로 단독 탐지로 취급하지 않는다. 서명이 존재하지만
        # 검증에 실패한 경우만 변조 가능성을 나타내는 낮은 가중치의 근거로 남긴다.
        if signature.status == "invalid":
            findings.append(
                Finding(
                    source="file",
                    rule_id="SIGNATURE-INVALID",
                    severity=35,
                    reason="Authenticode signature validation failed",
                    event_ids=[event_id],
                )
            )
        return tuple(findings)
