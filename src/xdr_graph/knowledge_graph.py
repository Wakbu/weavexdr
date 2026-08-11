from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import deque
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from xdr_graph.models import (
    FileCreateEvent,
    IncidentReport,
    NetworkConnectEvent,
    ProcessStartEvent,
)


EntityType = Literal["Host", "User", "Process", "File", "IP", "Alert"]


class GraphEntity(BaseModel):
    entity_id: str
    entity_type: EntityType
    key: str
    properties: dict[str, object] = Field(default_factory=dict)


# 엔티티별 고정 타입은 향후 전용 그래프 DB로 마이그레이션할 때 라벨 계약으로 사용한다.
class HostEntity(GraphEntity):
    entity_type: Literal["Host"] = "Host"


class UserEntity(GraphEntity):
    entity_type: Literal["User"] = "User"


class ProcessEntity(GraphEntity):
    entity_type: Literal["Process"] = "Process"


class FileEntity(GraphEntity):
    entity_type: Literal["File"] = "File"


class IpEntity(GraphEntity):
    entity_type: Literal["IP"] = "IP"


class AlertEntity(GraphEntity):
    entity_type: Literal["Alert"] = "Alert"


class GraphEdge(BaseModel):
    source_id: str
    target_id: str
    relationship: str
    incident_id: str


class SimilarIncident(BaseModel):
    incident_id: str
    shared_entities: int


class AttackPath(BaseModel):
    entity_ids: list[str]
    relationships: list[str]


class GraphDetection(BaseModel):
    rule_id: str
    incident_id: str
    process_id: str
    evidence_entities: list[str]
    reason: str


class KnowledgeGraphAssessment(BaseModel):
    node_count: int
    edge_count: int
    estimated_bytes: int
    recommended_backend: Literal["sqlite", "dedicated_graph_database"]
    reason: str


class MemoryRetentionPolicy(BaseModel):
    """Bound long-term graph memory by verdict and explicitly retained entities."""

    benign_days: int = Field(default=30, ge=1)
    needs_review_days: int = Field(default=90, ge=1)
    suspicious_days: int = Field(default=180, ge=1)
    remembered_entity_types: tuple[EntityType, ...] = ("Host", "User", "Process", "File", "IP", "Alert")
    excluded_properties: tuple[str, ...] = ("command_line", "file_content", "credential", "token")

    def retention_days(self, verdict: str) -> int:
        return {"benign": self.benign_days, "needs_review": self.needs_review_days, "suspicious": self.suspicious_days}.get(verdict, self.needs_review_days)


class MemoryPurgeResult(BaseModel):
    removed_incidents: int
    removed_by_verdict: dict[str, int]
    remaining_incidents: int


class KnowledgeGraphStore:
    """개인용 XDR 규모에 맞춘 SQLite 속성 그래프 저장소.

    초기 단계부터 별도 그래프 서버를 운영하면 설치와 복구 부담이 커진다.
    따라서 현재 사건 DB와 같은 프로세스에서 동작하되, 노드·엣지 계약은
    유지하여 규모가 커졌을 때 전용 그래프 DB로 옮길 수 있게 한다.
    """

    def __init__(self, path: str | Path, *, privacy_salt: str = "weavexdr-local") -> None:
        self.connection = sqlite3.connect(str(path), check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.privacy_salt = privacy_salt
        self._create_schema()
        # 장기 기억은 저장소를 열 때 기본 정책으로 자동 만료한다. 사용 중인
        # 사건을 즉시 삭제하지 않고 판정별 30/90/180일 경계를 적용한다.
        self.purge_expired_memory()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS graph_nodes (
                entity_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                properties_json TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(entity_type, entity_key)
            );
            CREATE TABLE IF NOT EXISTS graph_edges (
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                relationship TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY(source_id, target_id, relationship, incident_id)
            );
            CREATE TABLE IF NOT EXISTS graph_incident_entities (
                incident_id TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                PRIMARY KEY(incident_id, entity_id)
            );
            CREATE TABLE IF NOT EXISTS graph_incidents (
                incident_id TEXT PRIMARY KEY,
                observed_at TEXT NOT NULL,
                verdict TEXT NOT NULL DEFAULT 'needs_review'
            );
            CREATE INDEX IF NOT EXISTS ix_graph_edges_incident ON graph_edges(incident_id);
            CREATE INDEX IF NOT EXISTS ix_graph_incident_entity ON graph_incident_entities(entity_id);
            """
        )
        columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(graph_incidents)")}
        if "verdict" not in columns:
            # 기존 로컬 그래프는 안전하게 중간 보존 기간을 적용한 뒤 새 사건부터 실제 판정을 기록한다.
            self.connection.execute("ALTER TABLE graph_incidents ADD COLUMN verdict TEXT NOT NULL DEFAULT 'needs_review'")
        self.connection.commit()

    def ingest_report(self, report: IncidentReport) -> None:
        observed_at = datetime.now(UTC).isoformat()
        self.connection.execute(
            "INSERT OR REPLACE INTO graph_incidents(incident_id, observed_at, verdict) VALUES (?, ?, ?)",
            (report.incident_id, observed_at, report.verdict),
        )
        alert = self._entity("Alert", report.incident_id, {"verdict": report.verdict, "risk_score": report.risk_score})
        self._upsert_node(alert, observed_at, report.incident_id)

        processes: dict[str, GraphEntity] = {}
        for event in report.source_events:
            host = self._entity("Host", event.host_id, {})
            self._upsert_node(host, observed_at, report.incident_id)

            process = self._process_entity(event)
            if process:
                processes[event.event_id] = process
                self._upsert_node(process, observed_at, report.incident_id)
                self._upsert_edge(host, process, "RUNS", report.incident_id, observed_at)
                self._upsert_edge(alert, process, "OBSERVED", report.incident_id, observed_at)

            user_name = getattr(event, "user", None)
            if user_name and process:
                # 사용자명 원문은 장기 그래프에 남기지 않는다. 같은 사용자 여부만
                # 비교할 수 있는 로컬 salt 기반 단방향 식별자를 사용한다.
                user_key = hashlib.sha256(f"{self.privacy_salt}:{user_name}".encode()).hexdigest()
                user = self._entity("User", user_key, {"pseudonymized": True})
                self._upsert_node(user, observed_at, report.incident_id)
                self._upsert_edge(user, process, "EXECUTES", report.incident_id, observed_at)

            if isinstance(event, FileCreateEvent):
                file_entity = self._entity("File", event.file_path.casefold(), {"path": event.file_path})
                self._upsert_node(file_entity, observed_at, report.incident_id)
                if process:
                    self._upsert_edge(process, file_entity, "CREATED", report.incident_id, observed_at)
            elif isinstance(event, NetworkConnectEvent):
                ip_entity = self._entity("IP", event.destination_ip, {"address": event.destination_ip})
                self._upsert_node(ip_entity, observed_at, report.incident_id)
                if process:
                    self._upsert_edge(process, ip_entity, "CONNECTED_TO", report.incident_id, observed_at)

        for event in report.source_events:
            if isinstance(event, ProcessStartEvent) and event.parent_process_guid:
                child = processes.get(event.event_id)
                parent = self._entity("Process", event.parent_process_guid, {})
                if child:
                    self._upsert_node(parent, observed_at, report.incident_id)
                    self._upsert_edge(parent, child, "SPAWNED", report.incident_id, observed_at)
        self.connection.commit()

    def find_similar_incidents(self, incident_id: str, *, limit: int = 10) -> list[SimilarIncident]:
        rows = self.connection.execute(
            """
            SELECT candidate.incident_id, COUNT(*) AS shared_entities
            FROM graph_incident_entities source
            JOIN graph_incident_entities candidate ON source.entity_id = candidate.entity_id
            WHERE source.incident_id = ? AND candidate.incident_id <> ?
            GROUP BY candidate.incident_id
            ORDER BY shared_entities DESC, candidate.incident_id
            LIMIT ?
            """,
            (incident_id, incident_id, limit),
        ).fetchall()
        return [SimilarIncident(**dict(row)) for row in rows]

    def get_entity_id(self, entity_type: EntityType, key: str) -> str | None:
        row = self.connection.execute(
            "SELECT entity_id FROM graph_nodes WHERE entity_type = ? AND entity_key = ?",
            (entity_type, key),
        ).fetchone()
        return row["entity_id"] if row else None

    def find_attack_paths(self, start_id: str, end_id: str, *, max_hops: int = 5) -> list[AttackPath]:
        paths: list[AttackPath] = []
        pending = deque([(start_id, [start_id], [])])
        while pending:
            current, entities, relationships = pending.popleft()
            if len(relationships) >= max_hops:
                continue
            rows = self.connection.execute(
                "SELECT target_id, relationship FROM graph_edges WHERE source_id = ?",
                (current,),
            ).fetchall()
            for row in rows:
                target = row["target_id"]
                if target in entities:
                    continue
                next_entities = [*entities, target]
                next_relationships = [*relationships, row["relationship"]]
                if target == end_id:
                    paths.append(AttackPath(entity_ids=next_entities, relationships=next_relationships))
                else:
                    pending.append((target, next_entities, next_relationships))
        return paths

    def detect_process_file_network_chains(self, incident_id: str) -> list[GraphDetection]:
        rows = self.connection.execute(
            """
            SELECT file_edge.source_id AS process_id,
                   file_edge.target_id AS file_id,
                   network_edge.target_id AS ip_id,
                   ip_node.entity_key AS address
            FROM graph_edges file_edge
            JOIN graph_edges network_edge ON file_edge.source_id = network_edge.source_id
            JOIN graph_nodes ip_node ON network_edge.target_id = ip_node.entity_id
            WHERE file_edge.incident_id = ? AND network_edge.incident_id = ?
              AND file_edge.relationship = 'CREATED'
              AND network_edge.relationship = 'CONNECTED_TO'
            """,
            (incident_id, incident_id),
        ).fetchall()
        detections = []
        for row in rows:
            if not ip_address(row["address"]).is_global:
                continue
            detections.append(
                GraphDetection(
                    rule_id="GRAPH-PROCESS-FILE-PUBLIC-IP",
                    incident_id=incident_id,
                    process_id=row["process_id"],
                    evidence_entities=[row["file_id"], row["ip_id"]],
                    reason="한 프로세스가 파일을 생성하고 공인 IP에 연결함",
                )
            )
        return detections

    def assess_scale(self, *, dedicated_threshold_nodes: int = 1_000_000) -> KnowledgeGraphAssessment:
        node_count = self.connection.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
        edge_count = self.connection.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]
        page_size = self.connection.execute("PRAGMA page_size").fetchone()[0]
        page_count = self.connection.execute("PRAGMA page_count").fetchone()[0]
        dedicated = node_count >= dedicated_threshold_nodes
        return KnowledgeGraphAssessment(
            node_count=node_count,
            edge_count=edge_count,
            estimated_bytes=page_size * page_count,
            recommended_backend="dedicated_graph_database" if dedicated else "sqlite",
            reason="노드가 임계값 이상이므로 전용 그래프 DB 검토" if dedicated else "개인용 단일 호스트 규모에서는 SQLite 운영 복잡도가 가장 낮음",
        )

    def purge_incidents_before(self, cutoff: datetime) -> int:
        if cutoff.tzinfo is None or cutoff.utcoffset() is None:
            raise ValueError("cutoff must include a timezone offset")
        incident_rows = self.connection.execute(
            "SELECT incident_id FROM graph_incidents WHERE observed_at < ?",
            (cutoff.astimezone(UTC).isoformat(),),
        ).fetchall()
        incident_ids = [row["incident_id"] for row in incident_rows]
        for incident_id in incident_ids:
            self.connection.execute("DELETE FROM graph_edges WHERE incident_id = ?", (incident_id,))
            self.connection.execute("DELETE FROM graph_incident_entities WHERE incident_id = ?", (incident_id,))
            self.connection.execute("DELETE FROM graph_incidents WHERE incident_id = ?", (incident_id,))
        # 다른 사건에서도 쓰는 엔티티는 보존하고, 참조가 완전히 사라진 노드만 지운다.
        self.connection.execute(
            "DELETE FROM graph_nodes WHERE entity_id NOT IN (SELECT entity_id FROM graph_incident_entities)"
        )
        self.connection.commit()
        return len(incident_ids)

    def purge_expired_memory(self, *, now: datetime | None = None, policy: MemoryRetentionPolicy | None = None) -> MemoryPurgeResult:
        current = now or datetime.now(UTC)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("now must include a timezone offset")
        retention = policy or MemoryRetentionPolicy()
        rows = self.connection.execute("SELECT incident_id, observed_at, verdict FROM graph_incidents").fetchall()
        expired: list[sqlite3.Row] = []
        for row in rows:
            observed_at = datetime.fromisoformat(row["observed_at"])
            if observed_at < current.astimezone(UTC) - timedelta(days=retention.retention_days(row["verdict"])):
                expired.append(row)
        removed_by_verdict: dict[str, int] = {}
        for row in expired:
            incident_id, verdict = row["incident_id"], row["verdict"]
            removed_by_verdict[verdict] = removed_by_verdict.get(verdict, 0) + 1
            self.connection.execute("DELETE FROM graph_edges WHERE incident_id = ?", (incident_id,))
            self.connection.execute("DELETE FROM graph_incident_entities WHERE incident_id = ?", (incident_id,))
            self.connection.execute("DELETE FROM graph_incidents WHERE incident_id = ?", (incident_id,))
        # 공유 엔티티는 남기고 만료 사건에서만 쓰인 고아 노드만 함께 정리한다.
        self.connection.execute("DELETE FROM graph_nodes WHERE entity_id NOT IN (SELECT entity_id FROM graph_incident_entities)")
        self.connection.commit()
        remaining = self.connection.execute("SELECT COUNT(*) FROM graph_incidents").fetchone()[0]
        return MemoryPurgeResult(removed_incidents=len(expired), removed_by_verdict=removed_by_verdict, remaining_incidents=remaining)

    def _process_entity(self, event) -> GraphEntity | None:
        process_name = getattr(event, "process_name", None)
        if not process_name:
            return None
        process_key = getattr(event, "process_guid", None)
        if not process_key:
            process_key = f"{event.host_id}:{getattr(event, 'process_id', None)}:{getattr(event, 'process_start_time', None)}"
        return self._entity("Process", process_key, {"name": process_name, "image_path": getattr(event, "image_path", None)})

    @staticmethod
    def _entity(entity_type: EntityType, key: str, properties: dict[str, object]) -> GraphEntity:
        entity_id = f"{entity_type.lower()}:{hashlib.sha256(key.encode()).hexdigest()[:24]}"
        return GraphEntity(entity_id=entity_id, entity_type=entity_type, key=key, properties=properties)

    def _upsert_node(self, entity: GraphEntity, observed_at: str, incident_id: str) -> None:
        self.connection.execute(
            """INSERT INTO graph_nodes(entity_id, entity_type, entity_key, properties_json, last_seen)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(entity_id) DO UPDATE SET properties_json=excluded.properties_json, last_seen=excluded.last_seen""",
            (entity.entity_id, entity.entity_type, entity.key, json.dumps(entity.properties, ensure_ascii=False), observed_at),
        )
        self.connection.execute(
            "INSERT OR IGNORE INTO graph_incident_entities(incident_id, entity_id) VALUES (?, ?)",
            (incident_id, entity.entity_id),
        )

    def _upsert_edge(self, source: GraphEntity, target: GraphEntity, relationship: str, incident_id: str, observed_at: str) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO graph_edges(source_id, target_id, relationship, incident_id, observed_at) VALUES (?, ?, ?, ?, ?)",
            (source.entity_id, target.entity_id, relationship, incident_id, observed_at),
        )

    def close(self) -> None:
        self.connection.close()
