from __future__ import annotations

import hashlib
import math
import os
import sqlite3
import struct
import tempfile
import threading
import zipfile
import json
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from xdr_graph.file_scanner import DefenderResult, FileInspectionEngine, YaraScanner


class YaraRuleManager:
    """서명된 매니페스트와 컴파일 검증을 통과한 YARA 후보만 활성화한다."""

    def __init__(self, active_path: str | Path) -> None:
        self.active_path = Path(active_path)
        self.previous_path = self.active_path.with_suffix(self.active_path.suffix + ".previous")
        self.version: str | None = None

    def activate(
        self,
        candidate_path: str | Path,
        manifest_path: str | Path,
        *,
        verify_signature: Callable[[bytes, str], bool],
    ) -> str:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        candidate = Path(candidate_path).read_bytes()
        signed_payload = f"{manifest['version']}:{manifest['sha256']}".encode("utf-8")
        if not verify_signature(signed_payload, str(manifest.get("signature", ""))):
            raise ValueError("YARA manifest signature verification failed")
        if hashlib.sha256(candidate).hexdigest().lower() != str(manifest["sha256"]).lower():
            raise ValueError("YARA candidate SHA-256 mismatch")
        # 활성 파일 교체 전에 후보 자체를 컴파일해 문법 오류로 보호가 중단되지 않게 한다.
        YaraScanner([candidate_path])
        if self.active_path.exists():
            shutil.copy2(self.active_path, self.previous_path)
        shutil.copy2(candidate_path, self.active_path)
        self.version = str(manifest["version"])
        return self.version

    def rollback(self) -> None:
        if not self.previous_path.exists():
            raise RuntimeError("no previous YARA rules are available")
        YaraScanner([self.previous_path])
        shutil.copy2(self.previous_path, self.active_path)


class ScanPolicy(BaseModel):
    excluded_paths: list[str] = Field(default_factory=list)
    excluded_signers: list[str] = Field(default_factory=list)
    excluded_hashes: list[str] = Field(default_factory=list)
    max_file_size_bytes: int = 100 * 1024 * 1024
    network_paths: Literal["skip", "allow"] = "skip"
    locked_files: Literal["report", "skip"] = "report"
    archive_max_entries: int = 2_000
    archive_max_uncompressed_bytes: int = 500 * 1024 * 1024
    archive_max_ratio: float = 200.0
    archive_max_depth: int = 3


class AdvancedInspection(BaseModel):
    path: str
    sha256: str
    size_bytes: int
    cached: bool = False
    excluded_reason: str | None = None
    signature: dict[str, object] = Field(default_factory=dict)
    yara_matches: list[dict[str, object]] = Field(default_factory=list)
    defender: dict[str, object] = Field(default_factory=dict)
    findings: list[dict[str, object]] = Field(default_factory=list)
    pe: dict[str, object] | None = None
    office: dict[str, object] | None = None
    archive: dict[str, object] | None = None
    errors: list[str] = Field(default_factory=list)


class InspectionCache:
    def __init__(self, database_path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(str(database_path), check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS file_inspection_cache(
                    path TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL, modified_ns INTEGER NOT NULL,
                    sha256 TEXT NOT NULL, result_json TEXT NOT NULL, inspected_at TEXT NOT NULL
                )
                """
            )

    def get(self, path: Path) -> AdvancedInspection | None:
        stat = path.stat()
        with self._lock:
            row = self._connection.execute("SELECT * FROM file_inspection_cache WHERE path=?", (str(path),)).fetchone()
        if not row or row["size_bytes"] != stat.st_size or row["modified_ns"] != stat.st_mtime_ns:
            return None
        return AdvancedInspection.model_validate_json(row["result_json"]).model_copy(update={"cached": True})

    def put(self, path: Path, result: AdvancedInspection) -> None:
        stat = path.stat()
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO file_inspection_cache VALUES(?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET size_bytes=excluded.size_bytes,modified_ns=excluded.modified_ns,sha256=excluded.sha256,result_json=excluded.result_json,inspected_at=excluded.inspected_at",
                (str(path), stat.st_size, stat.st_mtime_ns, result.sha256, result.model_dump_json(), datetime.now(UTC).isoformat()),
            )


class PEAnalyzer:
    PACKER_MARKERS = (b"UPX0", b"UPX1", b"ASPack", b"MPRESS", b"Themida")

    def analyze(self, path: Path) -> dict[str, object] | None:
        data = path.read_bytes()[:32 * 1024 * 1024]
        if len(data) < 64 or data[:2] != b"MZ":
            return None
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
            return {"valid": False, "error": "invalid PE header"}
        machine, sections, _, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
        section_offset = pe_offset + 24 + optional_size
        section_details = []
        high_entropy = False
        for index in range(min(sections, 96)):
            offset = section_offset + index * 40
            if offset + 40 > len(data):
                break
            name = data[offset:offset + 8].rstrip(b"\0").decode("ascii", errors="replace")
            raw_size, raw_pointer = struct.unpack_from("<II", data, offset + 16)
            raw = data[raw_pointer:raw_pointer + raw_size]
            entropy = self._entropy(raw)
            high_entropy = high_entropy or entropy >= 7.2
            section_details.append({"name": name, "size": raw_size, "entropy": round(entropy, 3)})
        imports = sorted({match.decode("ascii", errors="ignore") for match in self._ascii_tokens(data) if match.lower().endswith(b".dll")})[:100]
        markers = [marker.decode("ascii") for marker in self.PACKER_MARKERS if marker.lower() in data.lower()]
        return {"valid": True, "machine": machine, "characteristics": characteristics, "sections": section_details, "imports": imports, "high_entropy": high_entropy, "packer_markers": markers, "packed_suspected": bool(markers or high_entropy)}

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts if count)

    @staticmethod
    def _ascii_tokens(data: bytes) -> set[bytes]:
        import re
        return set(re.findall(rb"[A-Za-z0-9_.-]{4,80}", data))


class OfficeAnalyzer:
    OFFICE_SUFFIXES = {".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".pptx"}

    def analyze(self, path: Path) -> dict[str, object] | None:
        if path.suffix.lower() not in self.OFFICE_SUFFIXES or not zipfile.is_zipfile(path):
            return None
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            macro_parts = [name for name in names if name.lower().endswith("vbaproject.bin")]
            script_parts = [name for name in names if name.lower().endswith((".js", ".vbs", ".ps1"))]
            external_targets: list[str] = []
            for name in names:
                if name.lower().endswith(".rels"):
                    content = archive.read(name)[:2_000_000].decode("utf-8", errors="ignore")
                    import re
                    external_targets.extend(re.findall(r'Target="(https?://[^"]+)"', content, flags=re.I))
            return {"macro_parts": macro_parts, "script_parts": script_parts, "external_templates": external_targets[:100], "suspicious": bool(macro_parts or script_parts or external_targets)}


class ArchiveAnalyzer:
    def analyze(self, path: Path, policy: ScanPolicy, *, depth: int = 0) -> dict[str, object] | None:
        if not zipfile.is_zipfile(path):
            return None
        if depth >= policy.archive_max_depth:
            return {"blocked": True, "reason": "archive nesting limit", "depth": depth}
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            total = sum(entry.file_size for entry in entries)
            compressed = max(1, sum(entry.compress_size for entry in entries))
            unsafe = [entry.filename for entry in entries if Path(entry.filename).is_absolute() or ".." in Path(entry.filename).parts]
            blocked = len(entries) > policy.archive_max_entries or total > policy.archive_max_uncompressed_bytes or total / compressed > policy.archive_max_ratio or bool(unsafe)
            return {"entries": len(entries), "uncompressed_bytes": total, "compression_ratio": round(total / compressed, 2), "unsafe_paths": unsafe[:20], "blocked": blocked, "reason": "archive bomb or unsafe path" if blocked else None}


class AdvancedFileScanner:
    SIGNATURE_SUFFIXES = {".exe", ".dll", ".sys", ".msi", ".ps1", ".psm1", ".cat"}

    def __init__(self, engine: FileInspectionEngine, *, cache: InspectionCache | None = None, policy: ScanPolicy | None = None) -> None:
        self.engine = engine
        self.cache = cache or InspectionCache()
        self.policy = policy or ScanPolicy()
        self.pe, self.office, self.archive = PEAnalyzer(), OfficeAnalyzer(), ArchiveAnalyzer()

    def inspect(
        self,
        file_path: str | Path,
        *,
        event_id: str,
        use_cache: bool = True,
        scan_profile: str | None = None,
        batch_defender: bool = False,
    ) -> AdvancedInspection:
        path = Path(file_path).resolve(strict=True)
        if path.stat().st_size > self.policy.max_file_size_bytes:
            raise ValueError("file exceeds scan policy size limit")
        exclusion = self._excluded(path)
        if exclusion:
            return AdvancedInspection(path=str(path), sha256="", size_bytes=path.stat().st_size, excluded_reason=exclusion)
        if use_cache and (cached := self.cache.get(path)):
            return cached
        if isinstance(self.engine, FileInspectionEngine) and scan_profile is not None:
            base = self.engine.inspect(
                path,
                event_id=event_id,
                # 빠른 검사는 YARA·메타데이터·배치 Defender에 집중한다. 실행 파일마다
                # PowerShell Authenticode 조회를 띄우면 다시 파일당 약 1초 병목이 생긴다.
                include_signature=scan_profile != "quick",
                include_defender=not batch_defender,
            )
        else:
            base = self.engine.inspect(path, event_id=event_id)
        result = AdvancedInspection(
            path=str(path), sha256=base.metadata.sha256, size_bytes=base.metadata.size_bytes,
            signature=asdict(base.signature), yara_matches=[asdict(value) for value in base.yara_matches],
            defender=asdict(base.defender), findings=[value.model_dump(mode="json") for value in base.findings],
            pe=self.pe.analyze(path), office=self.office.analyze(path), archive=self.archive.analyze(path, self.policy), errors=list(base.errors),
        )
        signer = str(result.signature.get("signer") or "").lower()
        if signer and any(value.lower() in signer for value in self.policy.excluded_signers):
            # 서명자 예외는 서명 검증 결과를 확보한 뒤 적용해야 파일명 위장으로 우회할 수 없다.
            result = result.model_copy(update={"excluded_reason": "excluded signer", "findings": []})
        self.cache.put(path, result)
        return result

    def _excluded(self, path: Path) -> str | None:
        lowered = str(path).lower()
        if self.policy.network_paths == "skip" and lowered.startswith(("\\\\", "//")):
            return "network path policy"
        if any(lowered.startswith(str(Path(value)).lower()) for value in self.policy.excluded_paths):
            return "excluded path"
        # 해시 예외가 없는데도 제외 확인과 본 검사에서 같은 파일을 두 번 읽지 않는다.
        # 대형 디렉터리 빠른 검사에서 이 중복 I/O가 전체 시간을 크게 늘릴 수 있다.
        if self.policy.excluded_hashes:
            digest = hashlib.sha256()
            with path.open("rb") as file_handle:
                for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest().lower() in {value.lower() for value in self.policy.excluded_hashes}:
                return "excluded hash"
        return None

    def scan_roots_with_defender(self, roots: list[Path]) -> DefenderResult:
        """Run Defender once per requested root instead of once per discovered file."""
        if not isinstance(self.engine, FileInspectionEngine):
            return DefenderResult(scanned=True)
        threats: set[str] = set()
        errors: list[str] = []
        for root in roots:
            result = self.engine.defender_scanner.scan(root, timeout=self.engine.defender_timeout)
            threats.update(result.threat_names)
            if not result.scanned:
                errors.append(result.error or "Defender scan failed")
        return DefenderResult(scanned=not errors, threat_names=tuple(sorted(threats)), error="; ".join(errors) or None)


class ScanJob(BaseModel):
    job_id: str
    profile: Literal["quick", "full", "custom"]
    state: Literal["queued", "running", "completed", "cancelled", "failed"] = "queued"
    total_files: int = 0
    scanned_files: int = 0
    findings: int = 0
    current_path: str | None = None
    phase: Literal["queued", "enumerating", "scanning", "defender", "completed"] = "queued"
    files_per_second: float = 0.0
    estimated_seconds_remaining: int | None = None
    cache_hits: int = 0
    defender_scanned: bool = False
    defender_threats: list[str] = Field(default_factory=list)
    requested_paths: int = 0
    resolved_roots: int = 0
    error: str | None = None
    results: list[AdvancedInspection] = Field(default_factory=list)


class ScanJobManager:
    QUICK_SUFFIXES = {
        ".exe", ".dll", ".sys", ".msi", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1",
        ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".lnk", ".iso", ".img",
        ".zip", ".rar", ".7z", ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
    }
    QUICK_SKIP_DIRECTORIES = {".git", "node_modules", "__pycache__", "cache", "code cache", "gpucache"}

    def __init__(
        self,
        scanner: AdvancedFileScanner,
        *,
        on_result: Callable[[AdvancedInspection], None] | None = None,
        file_workers: int | None = None,
    ) -> None:
        self.scanner, self.on_result = scanner, on_result
        self._jobs: dict[str, ScanJob] = {}
        self._cancel: dict[str, threading.Event] = {}
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="weavexdr-scan")
        self._defender_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="weavexdr-defender")
        self.file_workers = max(2, min(file_workers or (os.cpu_count() or 4), 8))

    def start(self, paths: list[str], *, profile: Literal["quick", "full", "custom"] = "custom") -> ScanJob:
        job = ScanJob(job_id=f"scan-{uuid4().hex[:12]}", profile=profile, requested_paths=len(paths))
        with self._lock:
            self._jobs[job.job_id] = job
            self._cancel[job.job_id] = threading.Event()
        # 파일 열거도 큰 임시 폴더에서는 오래 걸릴 수 있으므로 API 요청 스레드에서 분리한다.
        self._executor.submit(self._run, job.job_id, paths, profile)
        return job

    def get(self, job_id: str) -> ScanJob:
        with self._lock:
            if job_id not in self._jobs:
                raise KeyError(job_id)
            return self._jobs[job_id].model_copy(deep=True)

    def cancel(self, job_id: str) -> ScanJob:
        self.get(job_id)
        self._cancel[job_id].set()
        return self.get(job_id)

    def _run(self, job_id: str, paths: list[str], profile: str) -> None:
        self._update(job_id, state="running", phase="enumerating")
        try:
            roots = self._profile_roots(paths, profile)
            if paths and not roots:
                raise ValueError("no requested scan path is accessible")
            files = self._expand_roots(roots, profile)
            self._update(job_id, total_files=len(files), resolved_roots=len(roots), phase="scanning")
            defender_future = self._defender_executor.submit(self.scanner.scan_roots_with_defender, roots)
            started = datetime.now(UTC)

            def inspect_path(index_and_path: tuple[int, Path]) -> AdvancedInspection:
                index, path = index_and_path
                return self.scanner.inspect(
                    path,
                    event_id=f"{job_id}-{index}",
                    scan_profile=profile,
                    batch_defender=True,
                )

            with ThreadPoolExecutor(max_workers=self.file_workers, thread_name_prefix="weavexdr-file") as file_pool:
                futures = {file_pool.submit(inspect_path, item): item[1] for item in enumerate(files)}
                for future in as_completed(futures):
                    path = futures[future]
                    if self._cancel[job_id].is_set():
                        for pending in futures:
                            pending.cancel()
                        self._update(job_id, state="cancelled")
                        return
                    self._update(job_id, current_path=str(path))
                    result: AdvancedInspection
                    try:
                        result = future.result()
                    except (OSError, ValueError) as error:
                        result = AdvancedInspection(path=str(path), sha256="", size_bytes=0, errors=[str(error)])
                    elapsed = max(.001, (datetime.now(UTC) - started).total_seconds())
                    callback = None
                    with self._lock:
                        job = self._jobs[job_id]
                        job.results.append(result)
                        del job.results[:-500]
                        job.scanned_files += 1
                        job.findings += len(result.findings)
                        job.cache_hits += int(result.cached)
                        job.files_per_second = round(job.scanned_files / elapsed, 2)
                        remaining = max(0, job.total_files - job.scanned_files)
                        job.estimated_seconds_remaining = int(remaining / job.files_per_second) if job.files_per_second else None
                        callback = self.on_result if result.findings else None
                    if callback:
                        callback(result)

            if not defender_future.done():
                self._update(job_id, phase="defender", current_path=None)
            defender = defender_future.result()
            self._update(
                job_id,
                state="completed",
                phase="completed",
                current_path=None,
                estimated_seconds_remaining=0,
                defender_scanned=defender.scanned,
                defender_threats=list(defender.threat_names),
                error=defender.error,
            )
        except Exception as error:
            self._update(job_id, state="failed", error=str(error))

    def close(self) -> None:
        for event in self._cancel.values():
            event.set()
        self._executor.shutdown(wait=False, cancel_futures=True)
        self._defender_executor.shutdown(wait=False, cancel_futures=True)

    @staticmethod
    def _profile_roots(paths: list[str], profile: str) -> list[Path]:
        if profile == "quick" and not paths:
            paths = [str(Path.home() / "Downloads"), tempfile.gettempdir()]
        elif profile == "full" and not paths:
            paths = [os.environ.get("SystemDrive", "C:") + "\\"]
        roots: list[Path] = []
        for value in paths:
            try:
                # PyInstaller one-file 실행과 대괄호·비 ASCII 경로에서도 현재 작업
                # 디렉터리의 wildcard 해석 없이 절대 경로 문자열을 그대로 보존한다.
                root = Path(os.path.abspath(os.path.expandvars(os.path.expanduser(value))))
            except OSError:
                continue
            if root.exists() and root not in roots:
                roots.append(root)
        return roots

    @classmethod
    def _expand_roots(cls, roots: list[Path], profile: str) -> list[Path]:
        files: list[Path] = []
        seen: set[str] = set()
        recent_cutoff = datetime.now(UTC).timestamp() - 30 * 86400
        for root in roots:
            if root.is_file() and not root.is_symlink():
                candidates = [root]
            elif root.is_dir():
                candidates = []
                for directory, directory_names, file_names in os.walk(root, onerror=lambda _error: None):
                    if profile == "quick":
                        directory_names[:] = [name for name in directory_names if name.lower() not in cls.QUICK_SKIP_DIRECTORIES]
                    for name in file_names:
                        candidates.append(Path(directory) / name)
            else:
                continue
            for entry in candidates:
                try:
                    if entry.is_symlink() or not entry.is_file():
                        continue
                    stat = entry.stat()
                except OSError:
                    continue
                if profile == "quick" and (entry.suffix.lower() not in cls.QUICK_SUFFIXES or stat.st_mtime < recent_cutoff):
                    continue
                key = os.path.normcase(str(entry))
                if key not in seen:
                    seen.add(key)
                    files.append(entry)
        return files

    def _update(self, job_id: str, **changes: object) -> None:
        with self._lock:
            self._jobs[job_id] = self._jobs[job_id].model_copy(update=changes)

    @classmethod
    def _expand(cls, paths: list[str], profile: str) -> list[Path]:
        """Compatibility wrapper used by tests and callers that need only enumeration."""
        return cls._expand_roots(cls._profile_roots(paths, profile), profile)
