from pathlib import Path

from scripts.validate_ui_contract import validate_dashboard


PROJECT_ROOT = Path(__file__).parents[1]


def test_dashboard_static_contract_covers_viewport_and_scale_matrix():
    result = validate_dashboard(PROJECT_ROOT / "src" / "xdr_graph" / "static" / "dashboard.html")

    assert result["passed"] is True
    assert result["duplicate_ids"] == []
    assert result["unlabeled_controls"] == []
    assert result["contrast"]["text_on_bg"] >= 4.5
    assert result["contrast"]["muted_on_bg"] >= 4.5
    assert len(result["viewport_matrix"]) == 12
    assert {entry["width"] for entry in result["viewport_matrix"]} == {640, 900, 1280, 1920}
    assert {entry["scale"] for entry in result["viewport_matrix"]} == {100, 125, 150}


def test_sidebar_home_and_function_pages_are_explicitly_separated():
    html = (PROJECT_ROOT / "src" / "xdr_graph" / "static" / "dashboard.html").read_text(encoding="utf-8")
    assert 'id="brand-home"' in html and "navigate('overview')" in html
    assert 'aria-expanded="true"' in html and ".sidebar-toggle::before" in html
    assert "button.setAttribute('aria-expanded',String(!collapsed))" in html
    assert ".shell.sidebar-collapsed .nav button { width:44px" in html
    for page in ("operations", "models", "content", "settings"):
        assert f'id="page-{page}"' in html and f'data-nav="{page}"' in html
    assert "organizeFeaturePages();" in html


def test_investigation_model_content_and_assistant_ux_contracts():
    html = (PROJECT_ROOT / "src" / "xdr_graph" / "static" / "dashboard.html").read_text(encoding="utf-8")
    assert ".activity-panel {" in html and "height:485px" in html
    assert ".activity-list {" in html and "overflow-y:auto" in html
    assert '<select id="model-selection"' in html and '<input id="model-selection"' not in html
    assert 'id="model-recommendation"' in html and 'id="model-catalog"' in html
    assert 'id="sigma-example"' in html and "loadSigmaExample" in html
    assert 'id="assistant-launcher"' in html and 'id="assistant-panel"' in html
    assert "'/assistant/chat'" in html
