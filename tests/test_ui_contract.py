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
    assert result["ui_preferences"]["density_modes"] == ["simple", "comfortable", "compact", "detailed"]


def test_sidebar_home_and_function_pages_are_explicitly_separated():
    html = (PROJECT_ROOT / "src" / "xdr_graph" / "static" / "dashboard.html").read_text(encoding="utf-8")
    assert 'id="brand-home"' in html and "navigate('overview')" in html
    assert 'aria-expanded="true"' in html and ".sidebar-toggle::before" in html
    assert "button.setAttribute('aria-expanded',String(!collapsed))" in html
    assert ".sidebar-toggle { position:absolute; inset:0 -6px 0 auto" in html
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
    assert 'class="assistant-pet"' in html and 'class="assistant-ear left"' in html
    assert "'/assistant/chat'" in html
    assert '<body class="booting">' in html and 'id="startup-overlay"' in html
    assert "result.degraded?'concerned':'happy'" in html
    assert "assistant-ponder" in html and "assistant-thought" in html
    assert "bindAssistantDrag" in html and "weavexdr-assistant-position" in html
    assert "assistantBusy:false" in html
    assert "if(state.assistantBusy)" in html
    assert "sendAssistantQuestion(question)" in html
    assert "profiles={beginner:{hiddenColumns:" in html
    assert "beginner:{density:" not in html
    assert "body.dataset.profile=profile" in html
    assert "if(error instanceof TypeError||/failed to fetch/i.test(error.message))accepted=true" in html
    assert html.index('id="system-notices"') > html.index('id="page-overview"')
    assert "paused:'수집 일시정지'" in html and ".connection.paused" in html
    assert 'id="density-select"' in html and 'id="incident-column-options"' in html
    assert 'id="table-layout-select"' in html and "data-layout" in html
    assert ".column-options label" in html and "white-space:nowrap" in html
    assert ".column-visibility-field{grid-column:1/-1}" in html
    assert "grid-template-columns:repeat(3,minmax(0,1fr))" in html
    assert ".shell.sidebar-collapsed .content { max-width:none" in html
    assert "weavexdr-ui-preferences" in html and "applyUiPreferences" in html
    assert 'id="help-drawer"' in html and "renderHelp" in html
