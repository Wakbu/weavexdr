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
