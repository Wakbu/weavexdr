from __future__ import annotations

import re
import time
from dataclasses import dataclass

from pydantic import BaseModel, Field

from xdr_graph.knowledge_graph import KnowledgeGraphStore


class IncidentMemoryDocument(BaseModel):
    incident_id: str
    summary: str


class RetrievalCase(BaseModel):
    query: str
    source_incident_id: str
    expected_incident_id: str


class RetrievalComparison(BaseModel):
    case_count: int
    keyword_hits: int
    graph_hits: int
    keyword_recall: float = Field(ge=0, le=1)
    graph_recall: float = Field(ge=0, le=1)
    keyword_latency_ms: float = Field(ge=0)
    graph_latency_ms: float = Field(ge=0)
    graph_rag_ready: bool
    recommendation: str


@dataclass
class GraphRetrievalExperiment:
    graph: KnowledgeGraphStore
    documents: list[IncidentMemoryDocument]

    def keyword_search(self, query: str, *, limit: int = 5) -> list[str]:
        query_terms = self._terms(query)
        ranked = []
        for document in self.documents:
            overlap = len(query_terms & self._terms(document.summary))
            if overlap:
                ranked.append((overlap, document.incident_id))
        ranked.sort(key=lambda item: (-item[0], item[1]))
        return [incident_id for _, incident_id in ranked[:limit]]

    def graph_search(self, source_incident_id: str, *, limit: int = 5) -> list[str]:
        return [
            match.incident_id
            for match in self.graph.find_similar_incidents(source_incident_id, limit=limit)
        ]

    def compare(self, cases: list[RetrievalCase], *, limit: int = 5) -> RetrievalComparison:
        if not cases:
            raise ValueError("at least one retrieval case is required")
        keyword_started = time.perf_counter()
        keyword_hits = sum(case.expected_incident_id in self.keyword_search(case.query, limit=limit) for case in cases)
        keyword_latency_ms = (time.perf_counter() - keyword_started) * 1000 / len(cases)
        graph_started = time.perf_counter()
        graph_hits = sum(case.expected_incident_id in self.graph_search(case.source_incident_id, limit=limit) for case in cases)
        graph_latency_ms = (time.perf_counter() - graph_started) * 1000 / len(cases)
        graph_recall = graph_hits / len(cases)
        keyword_recall = keyword_hits / len(cases)
        # 로컬 MVP는 생성형 답변보다 근거 사건 ID를 정확히 돌려주는 것이 중요하다.
        # 그래프 검색이 개선되지 않으면 GraphRAG용 LLM 호출을 추가하지 않는다.
        graph_rag_ready = graph_recall > keyword_recall and graph_latency_ms <= max(keyword_latency_ms * 10, 25)
        recommendation = "use_graph_retrieval_without_llm" if graph_rag_ready else "keep_keyword_retrieval_and_collect_more_evidence"
        return RetrievalComparison(
            case_count=len(cases),
            keyword_hits=keyword_hits,
            graph_hits=graph_hits,
            keyword_recall=keyword_recall,
            graph_recall=graph_recall,
            keyword_latency_ms=round(keyword_latency_ms, 3),
            graph_latency_ms=round(graph_latency_ms, 3),
            graph_rag_ready=graph_rag_ready,
            recommendation=recommendation,
        )

    @staticmethod
    def _terms(text: str) -> set[str]:
        return {term.casefold() for term in re.findall(r"[\w.-]+", text) if len(term) > 1}
