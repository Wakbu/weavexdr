from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import sqlite3
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Literal

from pydantic import BaseModel, Field

from xdr_graph.detection import DetectionRule, RuleMatch


OFFICIAL_CONTENT_SOURCES = {
    "mitre_enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}
SIGMA_REFERENCE_SOURCE = "https://github.com/SigmaHQ/sigma"

# OWASP는 웹/애플리케이션 위험 분류, ATT&CK는 엔드포인트 행위·기술 매핑에만 쓴다.
FRAMEWORK_ROLES = {"owasp": "web_application", "owasp_genai": "genai_application", "mitre_attack": "endpoint_behavior", "cisa_kev": "exploited_vulnerability"}


class IOCRecord(BaseModel):
    indicator: str = Field(min_length=1)
    indicator_type: Literal["sha256", "ipv4", "ipv6", "domain", "url"]
    source: str = Field(min_length=1)
    confidence: int = Field(default=50, ge=0, le=100)
    expires_at: datetime | None = None
    false_positive: bool = False


class ThreatIntelStore:
    """IOC 출처·만료·신뢰도·오탐 상태를 로컬에 보관한다."""

    def __init__(self, database_path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(str(database_path), check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._connection:
            self._connection.execute("""CREATE TABLE IF NOT EXISTS threat_iocs(
                indicator TEXT NOT NULL, indicator_type TEXT NOT NULL, source TEXT NOT NULL,
                confidence INTEGER NOT NULL, expires_at TEXT, false_positive INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(indicator, source))""")

    def upsert(self, records: list[IOCRecord]) -> int:
        with self._lock, self._connection:
            self._connection.executemany("""INSERT INTO threat_iocs VALUES(?,?,?,?,?,?)
                ON CONFLICT(indicator,source) DO UPDATE SET indicator_type=excluded.indicator_type,
                confidence=excluded.confidence, expires_at=excluded.expires_at,
                false_positive=excluded.false_positive""",
                [(r.indicator.lower(), r.indicator_type, r.source, r.confidence,
                  r.expires_at.isoformat() if r.expires_at else None, int(r.false_positive)) for r in records])
        return len(records)

    def import_stix(self, payload: str | bytes, *, source: str = "stix") -> int:
        document = json.loads(payload)
        records: list[IOCRecord] = []
        markers = (("file:hashes.'SHA-256' = '", "sha256"), ("domain-name:value = '", "domain"),
                   ("ipv4-addr:value = '", "ipv4"), ("ipv6-addr:value = '", "ipv6"), ("url:value = '", "url"))
        for item in document.get("objects", []):
            if item.get("type") != "indicator": continue
            pattern = str(item.get("pattern", ""))
            for marker, kind in markers:
                if marker in pattern:
                    records.append(IOCRecord(indicator=pattern.split(marker, 1)[1].split("'", 1)[0], indicator_type=kind, source=source))
                    break
        return self.upsert(records)

    def import_taxii_bundle(self, payload: str | bytes, *, collection: str) -> int:
        # TAXII 전송 계층과 STIX 데이터 계층을 분리해 오프라인 내보내기도 동일하게 검증한다.
        return self.import_stix(payload, source=f"taxii:{collection}")

    def match(self, indicator: str) -> list[IOCRecord]:
        now = datetime.now(UTC)
        with self._lock:
            rows = self._connection.execute("SELECT * FROM threat_iocs WHERE indicator=? AND false_positive=0", (indicator.lower(),)).fetchall()
        records = [IOCRecord(indicator=row["indicator"], indicator_type=row["indicator_type"], source=row["source"], confidence=row["confidence"], expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None, false_positive=bool(row["false_positive"])) for row in rows]
        return [record for record in records if not record.expires_at or record.expires_at > now]

    def mark_false_positive(self, indicator: str, source: str, value: bool = True) -> None:
        with self._lock, self._connection:
            self._connection.execute("UPDATE threat_iocs SET false_positive=? WHERE indicator=? AND source=?", (int(value), indicator.lower(), source))


class GeoIPStore:
    """주소를 외부에 보내지 않는 로컬 최장 접두사 GeoIP/ASN 조회."""

    def __init__(self) -> None:
        self._networks: list[tuple[object, str, int | None]] = []

    def import_csv(self, path: str | Path) -> int:
        rows = []
        with Path(path).open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                rows.append((ipaddress.ip_network(row["network"]), row.get("country", ""), int(row["asn"]) if row.get("asn") else None))
        self._networks = sorted(rows, key=lambda item: item[0].prefixlen, reverse=True)
        return len(rows)

    def lookup(self, address: str) -> dict[str, object] | None:
        ip = ipaddress.ip_address(address)
        for network, country, asn in self._networks:
            if ip.version == network.version and ip in network:
                return {"network": str(network), "country": country, "asn": asn}
        return None


class SigmaImporter:
    """지원 가능한 Sigma selection만 검증·변환하고 기본 비활성화한다."""

    FIELD_MAP = {"Image": "process_name", "ParentImage": "parent_process", "CommandLine": "command_line", "TargetFilename": "file_path", "TargetObject": "target"}

    def parse(self, payload: str) -> list[DetectionRule]:
        import yaml
        rules = []
        for document in (value for value in yaml.safe_load_all(payload) if value):
            detection = document.get("detection", {})
            selections = [value for key, value in detection.items() if key != "condition" and isinstance(value, dict)]
            if not document.get("title") or not selections: raise ValueError("Sigma rule requires title and selection")
            service = str(document.get("logsource", {}).get("service", "")).lower()
            category = str(document.get("logsource", {}).get("category", "")).lower()
            event_type = "powershell_script" if service == "powershell" else "file_create" if category == "file_event" else "network_connect" if category == "network_connection" else "process_start"
            match = RuleMatch(event_type=event_type)
            for raw_field, raw_value in selections[0].items():
                field, _, modifier = raw_field.partition("|")
                if not (mapped := self.FIELD_MAP.get(field)): continue
                values = [str(v) for v in raw_value] if isinstance(raw_value, list) else [str(raw_value)]
                if modifier in {"contains", "endswith", "startswith"}: match.field_contains_any[mapped] = values
                else: match.field_equals[mapped] = values[0]
            rule_id = str(document.get("id") or hashlib.sha256(document["title"].encode()).hexdigest()[:16])
            severity = {"low": 25, "medium": 50, "high": 75, "critical": 95}.get(str(document.get("level")).lower(), 50)
            rules.append(DetectionRule(rule_id=f"SIGMA-{rule_id}", source="behavior", severity=severity, reason=document["title"], enabled=False, match=match))
        return rules


class ContentUpdateManager:
    """사용자가 가져온 JSON 후보를 검증 후 활성화하고 직전본으로 롤백한다."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root); self.root.mkdir(parents=True, exist_ok=True)
        self._previous: dict[str, bytes] = {}

    def activate_file(self, source: str, candidate_path: str | Path, *, expected_sha256: str | None = None, validator: Callable[[bytes], dict[str, int]] | None = None) -> dict[str, object]:
        if source not in OFFICIAL_CONTENT_SOURCES: raise ValueError("unknown content source")
        payload = Path(candidate_path).read_bytes()
        if len(payload) > 200 * 1024 * 1024: raise ValueError("content exceeds update limit")
        digest = hashlib.sha256(payload).hexdigest()
        if expected_sha256 and digest.lower() != expected_sha256.lower(): raise ValueError("content SHA-256 mismatch")
        json.loads(payload)
        metrics = validator(payload) if validator else {"detections": 0, "false_positives": 0}
        if metrics.get("false_positives", 0) > metrics.get("detections", 0) + 10: raise ValueError("regression gate rejected candidate")
        target = self.root / f"{source}.json"
        if target.exists(): self._previous[source] = target.read_bytes()
        target.write_bytes(payload)
        return {"source": source, "sha256": digest, "metrics": metrics, "source_url": OFFICIAL_CONTENT_SOURCES[source]}

    def activate_bytes(self, source: str, payload: bytes, *, validator: Callable[[bytes], dict[str, int]] | None = None) -> dict[str, object]:
        if source not in OFFICIAL_CONTENT_SOURCES: raise ValueError("unknown content source")
        if len(payload) > 200 * 1024 * 1024: raise ValueError("content exceeds update limit")
        json.loads(payload)
        metrics = validator(payload) if validator else {"detections": 0, "false_positives": 0}
        if metrics.get("false_positives", 0) > metrics.get("detections", 0) + 10: raise ValueError("regression gate rejected candidate")
        target = self.root / f"{source}.json"
        if target.exists(): self._previous[source] = target.read_bytes()
        target.write_bytes(payload)
        return {"source": source, "sha256": hashlib.sha256(payload).hexdigest(), "metrics": metrics, "source_url": OFFICIAL_CONTENT_SOURCES[source]}

    def rollback(self, source: str) -> None:
        if source not in self._previous: raise RuntimeError("no previous content is available")
        (self.root / f"{source}.json").write_bytes(self._previous.pop(source))


class ContentSyncService:
    """호스트가 승인·구성한 가져오기 어댑터로 공식 콘텐츠를 주기 동기화한다."""

    def __init__(self, manager: ContentUpdateManager, fetcher: Callable[[str], bytes]) -> None:
        self.manager, self.fetcher = manager, fetcher

    def sync_once(self, sources: list[str]) -> list[dict[str, object]]:
        results = []
        for source in sources:
            if source not in OFFICIAL_CONTENT_SOURCES: raise ValueError("unknown content source")
            results.append(self.manager.activate_bytes(source, self.fetcher(OFFICIAL_CONTENT_SOURCES[source])))
        return results


class KevCatalog:
    def __init__(self, payload: str | bytes) -> None:
        document = json.loads(payload)
        self._entries = {str(item["cveID"]).upper(): item for item in document.get("vulnerabilities", []) if item.get("cveID")}

    def lookup(self, cve_id: str) -> dict[str, object] | None:
        return self._entries.get(cve_id.upper())


class ReputationGateway:
    """명시적 동의와 해시 전용 제약을 강제한 뒤, 사용자가 구성한 공급자 어댑터를 호출한다."""

    def __init__(self, adapter: Callable[[str], dict[str, object]], *, consent: bool = False, requests_per_minute: int = 4, clock: Callable[[], float] = time.monotonic) -> None:
        self.adapter, self.consent = adapter, consent
        self._minimum_interval = 60 / max(1, requests_per_minute)
        self._clock, self._last_request = clock, 0.0

    def lookup_hash(self, sha256: str) -> dict[str, object]:
        if not self.consent: raise PermissionError("external reputation consent is required")
        if len(sha256) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in sha256): raise ValueError("reputation lookup accepts SHA-256 only")
        now = self._clock()
        if self._last_request and now - self._last_request < self._minimum_interval:
            raise RuntimeError("reputation provider rate limit")
        result = self.adapter(sha256.lower())
        self._last_request = now
        return result
