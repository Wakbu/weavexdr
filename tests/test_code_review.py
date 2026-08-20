from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_generator():
    path = ROOT / "scripts" / "generate_code_review.py"
    spec = importlib.util.spec_from_file_location("generate_code_review", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_code_review_report_covers_every_python_module() -> None:
    generator = _load_generator()
    report = generator.build_report()
    expected = {
        path.stem
        for path in (ROOT / "src" / "xdr_graph").glob("*.py")
        if path.stem != "__init__"
    }
    actual = {module["id"] for module in report["modules"]}

    assert actual == expected
    assert set(generator.MODULE_GUIDES) == expected
    assert all(set(module["dependencies"]) <= actual for module in report["modules"])
    assert all(module["summary"] and module["flow"] for module in report["modules"])
    # 정적 집계는 매개변수화된 실행 사례가 아니라 작성된 test_* 함수 수를 센다.
    assert report["summary"]["testCount"] >= 180


def test_code_review_template_exposes_required_drill_down_views() -> None:
    template = (ROOT / "docs" / "code-review-template.html").read_text(encoding="utf-8")

    assert "/*__CODE_REVIEW_DATA__*/" in template
    assert "구조·로직" in template
    assert "함수·클래스" in template
    assert "실제 코드" in template
    assert "실행 커버리지" in template
    assert "tok-function" in template
    assert "tok-variable" in template
    assert "symbol-doc" in template
    assert "grid-template-rows:minmax(0,1fr) auto" in template
    legend_rule = template.split(".legend {", 1)[1].split("}", 1)[0]
    assert "position:absolute" not in legend_rule


def test_code_review_includes_nested_routes_and_methods() -> None:
    generator = _load_generator()
    report = generator.build_report()
    api = next(module for module in report["modules"] if module["id"] == "api")
    response = next(module for module in report["modules"] if module["id"] == "response_execution")

    assert any(symbol["name"] == "create_app.local_assistant_chat" for symbol in api["symbols"])
    assert any(symbol["name"] == "ActualResponseService.execute" for symbol in response["symbols"])


def test_static_assets_are_cached_after_first_read() -> None:
    from xdr_graph.static_assets import load_dashboard_html, load_world_map_svg

    load_dashboard_html.cache_clear()
    load_world_map_svg.cache_clear()
    assert load_dashboard_html()
    assert load_dashboard_html()
    assert load_world_map_svg()
    assert load_world_map_svg()
    assert load_dashboard_html.cache_info().misses == 1
    assert load_dashboard_html.cache_info().hits == 1
    assert load_world_map_svg.cache_info().misses == 1
    assert load_world_map_svg.cache_info().hits == 1
