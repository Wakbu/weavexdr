import json
from pathlib import Path

from xdr_graph.custom_detection import CustomDetectionService
from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore


SAMPLE_BATCH = Path(__file__).parents[1] / "samples" / "suspicious_office_batch.json"


def test_saved_hunt_runs_as_bounded_shadow_detection_and_can_activate():
    store = SQLiteEventStore(":memory:")
    try:
        PersistentIngestionService(store).submit(
            NormalizedEventBatch.model_validate(json.loads(SAMPLE_BATCH.read_text(encoding="utf-8")))
        )
        saved = store.save_search("PowerShell 고위험", {"window": "168", "risk": "70", "query": "powershell"})
        detection = store.save_custom_detection(saved["search_id"], saved["name"], 15)
        result = CustomDetectionService(store).run(detection["detection_id"])

        assert result["state"] == "shadow"
        assert result["last_match_count"] == 1
        assert result["estimated_daily_matches"] == round(24 / 168, 2)
        assert result["sample_incident_ids"] == ["incident-001"]
        assert store.set_custom_detection_state(result["detection_id"], "active")["state"] == "active"
    finally:
        store.close()


def test_custom_detection_interval_and_state_are_restricted():
    store = SQLiteEventStore(":memory:")
    try:
        saved = store.save_search("restricted", {"window": "24"})
        try:
            store.save_custom_detection(saved["search_id"], saved["name"], 1)
        except ValueError as error:
            assert "interval" in str(error)
        else:
            raise AssertionError("unsupported interval must be rejected")
    finally:
        store.close()
