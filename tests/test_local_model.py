import json

import pytest

from xdr_graph.local_model import OllamaModelManager


class Response:
    def __init__(self, payload): self.payload = payload
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def read(self, limit=None): return json.dumps(self.payload).encode()


def test_model_manager_lists_selects_and_persists_models(tmp_path, monkeypatch):
    monkeypatch.setattr("xdr_graph.local_model.urlopen", lambda request, timeout: Response({"models": [{"name": "qwen3:4b"}]}))
    path = tmp_path / "models.json"; manager = OllamaModelManager(path)
    status = manager.select("qwen3:4b")
    assert status["available"] is True and status["selected_installed"] is True
    assert OllamaModelManager(path).selected_model == "qwen3:4b"


def test_model_manager_rejects_command_like_model_names(tmp_path):
    manager = OllamaModelManager(tmp_path / "models.json")
    with pytest.raises(ValueError, match="invalid"):
        manager.select("qwen3:4b; powershell")


def test_local_assistant_uses_selected_loopback_model_without_tools(tmp_path, monkeypatch):
    def fake_urlopen(request, timeout):
        if request.full_url.endswith("/api/tags"):
            return Response({"models": [{"name": "qwen3:4b"}]})
        payload = json.loads(request.data)
        assert request.full_url == "http://127.0.0.1:11434/api/chat"
        assert payload["model"] == "qwen3:4b"
        assert payload["keep_alive"] == "10m"
        assert "tools" not in payload
        assert "명령 실행" in payload["messages"][0]["content"]
        return Response({"message": {"content": "가장 높은 위험 사건부터 확인하세요."}})

    monkeypatch.setattr("xdr_graph.local_model.urlopen", fake_urlopen)
    manager = OllamaModelManager(tmp_path / "models.json")
    manager.select("qwen3:4b")
    answer = manager.chat("무엇부터 볼까?", '[{"risk_score": 90}]')
    assert answer["provider"] == "ollama"
    assert answer["answer"].startswith("가장 높은")


def test_local_assistant_keeps_rule_based_guidance_when_model_is_unavailable(tmp_path, monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("offline")

    monkeypatch.setattr("xdr_graph.local_model.urlopen", unavailable)
    answer = OllamaModelManager(tmp_path / "models.json").chat("상태 알려줘", "[]")
    assert answer["provider"] == "rules"
    assert "규칙 엔진" in answer["answer"]


def test_local_assistant_degrades_to_rules_when_installed_model_request_breaks(tmp_path, monkeypatch):
    def flaky_urlopen(request, timeout):
        if request.full_url.endswith("/api/tags"):
            return Response({"models": [{"name": "qwen3:4b"}]})
        raise TimeoutError("model load timed out")

    monkeypatch.setattr("xdr_graph.local_model.urlopen", flaky_urlopen)
    manager = OllamaModelManager(tmp_path / "models.json")
    manager.select("qwen3:4b")
    answer = manager.chat("최근 사건 요약", '[{"verdict":"suspicious"}]')
    assert answer["provider"] == "rules"
    assert answer["degraded"] is True
    assert "고위험 사건 1건" in answer["answer"]
    assert "일시적으로 중단" not in answer["answer"]
