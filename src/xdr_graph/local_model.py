from __future__ import annotations

import ctypes
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.request import Request, urlopen


_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,79}$")
MODEL_REQUIREMENTS = {
    "qwen3:1.7b": {"memory_gib": 4, "cpu_threads": 4, "gpu_vram_gib": 0, "profile": "low", "latency_budget_ms": 12000, "summary": "저사양 PC용 빠른 보조 분석"},
    "qwen3:4b": {"memory_gib": 8, "cpu_threads": 6, "gpu_vram_gib": 4, "profile": "balanced", "latency_budget_ms": 20000, "summary": "속도와 설명 품질의 균형"},
    "qwen3:8b": {"memory_gib": 16, "cpu_threads": 8, "gpu_vram_gib": 8, "profile": "high", "latency_budget_ms": 30000, "summary": "고사양 PC용 상세 보조 분석"},
}


@dataclass(frozen=True)
class ResourceProfile:
    name: str
    cpu_threads: int
    memory_gib: float
    recommended_model: str
    context_tokens: int


def total_memory_gib() -> float:
    if os.name != "nt":
        return 0.0
    class MemoryStatus(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ulong), ("memory_load", ctypes.c_ulong), ("total_phys", ctypes.c_ulonglong), ("avail_phys", ctypes.c_ulonglong), ("total_page", ctypes.c_ulonglong), ("avail_page", ctypes.c_ulonglong), ("total_virtual", ctypes.c_ulonglong), ("avail_virtual", ctypes.c_ulonglong), ("avail_extended", ctypes.c_ulonglong)]
    status = MemoryStatus(); status.length = ctypes.sizeof(status)
    return round(status.total_phys / 1024**3, 1) if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)) else 0.0


def detect_resource_profile() -> ResourceProfile:
    threads, memory = os.cpu_count() or 1, total_memory_gib()
    if memory and memory < 12 or threads < 6:
        return ResourceProfile("low", threads, memory, "qwen3:1.7b", 2048)
    if memory and memory < 24 or threads < 12:
        return ResourceProfile("balanced", threads, memory, "qwen3:4b", 4096)
    return ResourceProfile("high", threads, memory, "qwen3:8b", 8192)


class OllamaModelManager:
    """루프백 Ollama만 조회하고 선택 모델을 최소 JSON 설정으로 보존한다."""

    def __init__(self, settings_path: str | Path, endpoint: str = "http://127.0.0.1:11434") -> None:
        self.settings_path = Path(settings_path).resolve(); self.endpoint = endpoint.rstrip("/"); self._lock = RLock()
        self.profile = detect_resource_profile(); self.selected_model = self.profile.recommended_model
        self._cached_status: tuple[float, dict[str, Any]] | None = None
        if self.settings_path.is_file():
            try: self.selected_model = self._validate(json.loads(self.settings_path.read_text(encoding="utf-8"))["selected_model"])
            except (KeyError, ValueError, OSError, json.JSONDecodeError): pass

    def _validate(self, model: str) -> str:
        if not _MODEL_NAME.fullmatch(model): raise ValueError("invalid local model name")
        return model

    def status(self, *, force: bool = False) -> dict[str, Any]:
        if self._cached_status and not force:
            cache_seconds = 5 if self._cached_status[1].get("available") else 30
            if time.monotonic() - self._cached_status[0] < cache_seconds:
                return dict(self._cached_status[1])
        models: list[str] = []; available = False; error = None
        try:
            with urlopen(Request(f"{self.endpoint}/api/tags", headers={"Accept": "application/json"}), timeout=2) as response:
                payload = json.loads(response.read(2_000_000)); models = [str(item["name"]) for item in payload.get("models", [])]; available = True
        except Exception as exc: error = str(exc)
        status = {"provider": "ollama", "available": available, "selected_model": self.selected_model, "installed_models": models, "selected_installed": self.selected_model in models, "fallback": "rules", "resource_profile": asdict(self.profile), "model_requirements": MODEL_REQUIREMENTS, "selected_requirements": MODEL_REQUIREMENTS.get(self.selected_model), "purpose": "규칙 탐지 결과를 다시 읽어 사건 요약, 근거 설명과 불확실성을 보조합니다. 차단·격리 결정이나 위험 점수는 규칙 정책이 최종 결정합니다.", "error": error}
        self._cached_status = (time.monotonic(), status)
        return dict(status)

    def select(self, model: str) -> dict[str, Any]:
        selected = self._validate(model)
        with self._lock:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.settings_path.with_suffix(".tmp"); temporary.write_text(json.dumps({"selected_model": selected}, ensure_ascii=False, indent=2), encoding="utf-8"); os.replace(temporary, self.settings_path); self.selected_model = selected
            self._cached_status = None
        return self.status(force=True)

    def install(self, model: str) -> dict[str, Any]:
        selected = self._validate(model)
        request = Request(f"{self.endpoint}/api/pull", data=json.dumps({"model": selected, "stream": False}).encode(), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=1800) as response: json.loads(response.read(2_000_000))
        except Exception as exc: raise RuntimeError(f"local model installation failed: {exc}") from exc
        return self.select(selected)

    def chat(self, question: str, context: str) -> dict[str, Any]:
        """Ask the selected loopback model for read-only security guidance."""
        question = question.strip()
        if not question or len(question) > 1_000:
            raise ValueError("question must be between 1 and 1000 characters")
        model_status = self.status()
        if not model_status["available"] or not model_status["selected_installed"]:
            return {
                "answer": "현재 로컬 AI 모델이 준비되지 않았습니다. AI 모델 화면에서 이 PC 권장 모델을 설치하면 사건 요약과 조사 방향을 대화형으로 확인할 수 있습니다. 탐지와 위험 점수 계산은 지금도 규칙 엔진으로 계속 동작합니다.",
                "provider": "rules",
                "model": None,
            }
        system = (
            "당신은 개인용 XDR의 읽기 전용 한국어 보안 분석 보조자다. 제공된 로컬 상태만 근거로 답하고 "
            "모르는 내용은 모른다고 말한다. 명령 실행, 파일 변경, 차단, 격리 또는 설정 변경을 수행하거나 "
            "수행했다고 주장하지 않는다. 위험한 조치는 반드시 사용자가 사건 화면에서 검토하도록 안내한다."
        )
        payload = json.dumps({
            "model": self.selected_model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": f"로컬 XDR 상태:\n{context[:24_000]}\n\n질문:\n{question}"},
            ],
            "options": {"temperature": 0.2, "num_ctx": min(self.profile.context_tokens, 8192)},
        }, ensure_ascii=False).encode("utf-8")
        budget_ms = int(MODEL_REQUIREMENTS.get(self.selected_model, {}).get("latency_budget_ms", 20_000))
        request = Request(f"{self.endpoint}/api/chat", data=payload, headers={"Content-Type": "application/json"}, method="POST")
        started_at = time.perf_counter()
        try:
            with urlopen(request, timeout=max(5, budget_ms / 1000)) as response:
                body = json.loads(response.read(1_000_000))
            answer = str(body.get("message", {}).get("content", "")).strip()
            if not answer:
                raise RuntimeError("local model returned an empty answer")
        except Exception as exc:
            # Ollama가 모델 적재 중이거나 종료 직전 연결을 먼저 닫더라도 대화 UI를
            # 503으로 끝내지 않는다. 원본 문맥은 외부로 보내지 않고 최소 사건 수와
            # 규칙 판정만 이용한 읽기 전용 안내로 즉시 강등한다.
            try:
                incidents = json.loads(context)
            except json.JSONDecodeError:
                incidents = []
            high_risk = sum(1 for item in incidents if item.get("verdict") == "suspicious")
            answer = (
                "로컬 AI 모델 응답이 일시적으로 중단되어 규칙 기반 안내로 전환했습니다. "
                f"현재 문맥에는 최근 사건 {len(incidents)}건, 고위험 사건 {high_risk}건이 있습니다. "
                "사건 화면에서 위험 점수가 높은 항목의 탐지 근거와 연결된 프로세스·파일·네트워크 순서로 확인하세요. "
                "모델 상태는 AI 모델 화면에서 다시 확인할 수 있습니다."
            )
            return {
                "answer": answer,
                "provider": "rules",
                "model": self.selected_model,
                "degraded": True,
                "degraded_reason": type(exc).__name__,
                "latency_ms": round((time.perf_counter() - started_at) * 1000, 2),
                "latency_budget_ms": budget_ms,
            }
        return {"answer": answer[:8_000], "provider": "ollama", "model": self.selected_model, "latency_ms": round((time.perf_counter() - started_at) * 1000, 2), "latency_budget_ms": budget_ms}
