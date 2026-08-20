"""개별 파일의 메타데이터·서명·YARA·Defender 근거를 하나의 판정으로 합친다.

검사기 하나의 실패를 정상 판정으로 바꾸지 않고 `errors`와 `scanned=False`로 보존한다.
해시 계산은 고정 블록 스트리밍을 사용하며, 외부 PowerShell·Defender 호출은 제한 시간과
프로필 플래그로 통제해 대량 검사에서 프로세스 생성 비용이 폭증하지 않게 한다.
"""

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
    errors: tuple[str, ...]


class FileTooLargeError(ValueError):
    """설정된 최대 크기를 넘어 메모리·검사 시간을 과도하게 쓸 파일이다."""


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
        # GUI EXE에서 파일마다 PowerShell 콘솔 창이 깜빡이지 않도록 자식 프로세스를
        # 창 없는 모드로 실행한다. 비 Windows에서는 플래그가 0이어서 동작이 동일하다.
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
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
        max_file_size_bytes: int = 100 * 1024 * 1024,
        signature_timeout: float = 10.0,
        yara_timeout: int = 10,
        defender_timeout: float = 120.0,
    ) -> None:
        if max_file_size_bytes < 1:
            raise ValueError("max_file_size_bytes must be at least 1")
        if signature_timeout <= 0 or yara_timeout <= 0 or defender_timeout <= 0:
            raise ValueError("inspection timeouts must be positive")
        self.yara_scanner = yara_scanner
        self.signature_inspector = signature_inspector or AuthenticodeInspector()
        self.defender_scanner = defender_scanner or DefenderScanner()
        self.max_file_size_bytes = max_file_size_bytes
        self.signature_timeout = signature_timeout
        self.yara_timeout = yara_timeout
        self.defender_timeout = defender_timeout

    def inspect(
        self,
        file_path: str | Path,
        *,
        event_id: str,
        include_signature: bool = True,
        include_defender: bool = True,
    ) -> FileInspectionResult:
        """파일 하나를 검증하고 독립 검사 결과를 공통 Finding으로 합친다.

        순서는 ① 정규화된 실재 파일 확인, ② 메모리 안전 크기 제한, ③ 스트리밍 해시와
        메타데이터, ④ 선택적 Authenticode, ⑤ YARA, ⑥ 선택적 Defender, ⑦ Finding 변환이다.
        서명·YARA·Defender는 서로 대체하지 않으며 일부 실패에도 나머지 근거를 반환한다.

        `include_signature`와 `include_defender`는 상위 배치 검사기가 같은 검사를 한 번에
        수행했을 때 중복 외부 프로세스를 피하기 위한 플래그이지 보안 실패를 숨기는 값이 아니다.
        """
        target_path = Path(file_path).resolve(strict=True)
        if not target_path.is_file():
            raise ValueError(f"inspection target is not a regular file: {target_path}")
        file_size = target_path.stat().st_size
        if file_size > self.max_file_size_bytes:
            # 현재 YARA 경로는 파일 바이트를 메모리로 읽으므로 검사 전에 제한해야
            # 대형 파일 하나가 수집 프로세스의 메모리를 고갈시키는 일을 막을 수 있다.
            raise FileTooLargeError(
                f"file exceeds inspection limit: {file_size}/{self.max_file_size_bytes} bytes"
            )

        metadata = self._collect_metadata(target_path)
        errors: list[str] = []
        # 대량 검사에서는 파일마다 PowerShell과 Defender 프로세스를 시작하면
        # 수천 파일이 수천 초로 늘어난다. 호출자가 배치 Defender 검사를 사용하거나
        # 서명 가치가 낮은 일반 파일을 검사할 때 외부 호출만 생략할 수 있게 한다.
        signature = (
            self.signature_inspector.inspect(target_path, timeout=self.signature_timeout)
            if include_signature
            else SignatureResult(status="unavailable", message="skipped by scan profile")
        )
        if signature.status == "error":
            errors.append(f"signature: {signature.message or 'inspection failed'}")

        try:
            yara_matches = self.yara_scanner.scan(
                target_path, timeout=self.yara_timeout
            )
        except (OSError, ValueError, yara.Error, yara.TimeoutError) as error:
            # 한 검사기의 실패가 나머지 증거 수집까지 중단시키지 않도록 부분 결과를 보존한다.
            yara_matches = ()
            errors.append(f"yara: {error}")

        defender = (
            self.defender_scanner.scan(target_path, timeout=self.defender_timeout)
            if include_defender
            else DefenderResult(scanned=True)
        )
        if not defender.scanned:
            errors.append(f"defender: {defender.error or 'scan failed'}")
        findings = self._to_findings(event_id, signature, yara_matches, defender)
        return FileInspectionResult(
            metadata=metadata,
            signature=signature,
            yara_matches=yara_matches,
            defender=defender,
            findings=findings,
            errors=tuple(errors),
        )

    @staticmethod
    def _collect_metadata(target_path: Path) -> FileMetadata:
        """파일을 1 MiB 블록으로 읽어 O(1) 추가 메모리로 SHA-256을 계산한다."""
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
        """검사기별 고유 결과를 사건 엔진이 이해하는 Finding으로 정규화한다.

        YARA 심각도는 규칙 메타데이터를 유지하고 Defender 악성코드는 최고 심각도로
        올린다. 단순 미서명은 악성의 충분조건이 아니므로 별도 고위험 Finding을 만들지 않는다.
        """
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
