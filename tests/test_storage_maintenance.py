from __future__ import annotations

import gzip
import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from xdr_graph.storage import EventBuffer, PersistentIngestionService, SQLiteEventStore
from xdr_graph.storage_maintenance import DatabaseLifecycleManager, Migration
from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.runtime_health import RuntimeHealthMonitor
from tests.test_storage import make_batch


def test_database_health_backup_and_index_query_plan(tmp_path):
    database = tmp_path / "weavexdr.db"
    with SQLiteEventStore(database) as store:
        PersistentIngestionService(store).submit(make_batch("maintenance-batch", [0, 1]))

    manager = DatabaseLifecycleManager(database, backup_root=tmp_path / "backups", retention_days=30)
    health = manager.health(daily_growth_bytes=1024)
    backup = manager.backup()
    plan = manager.query_plan(
        "SELECT * FROM incidents WHERE verdict=? ORDER BY risk_score DESC, updated_at DESC",
        ("suspicious",),
    )

    assert health.integrity_ok is True
    assert health.database_bytes > 0
    assert health.estimated_days_remaining and health.estimated_days_remaining > 0
    assert backup.is_file()
    assert any("idx_incidents_verdict_risk_time" in row for row in plan)


def test_restore_rejects_unconfirmed_or_corrupt_backup_and_keeps_rollback(tmp_path):
    database = tmp_path / "weavexdr.db"
    with SQLiteEventStore(database):
        pass
    manager = DatabaseLifecycleManager(database, backup_root=tmp_path / "backups")
    backup = manager.backup()

    with pytest.raises(PermissionError):
        manager.restore(backup, confirmed=False)

    corrupt = manager.backup_root / "corrupt.db"
    corrupt.write_bytes(b"not sqlite")
    with pytest.raises(ValueError, match="integrity"):
        manager.restore(corrupt, confirmed=True)

    rollback = manager.restore(backup, confirmed=True)
    assert rollback.is_file()
    assert manager.health().integrity_ok is True


def test_failed_schema_migration_rolls_back_all_statements(tmp_path):
    database = tmp_path / "weavexdr.db"
    with SQLiteEventStore(database):
        pass
    manager = DatabaseLifecycleManager(database, backup_root=tmp_path / "backups")

    with pytest.raises(sqlite3.DatabaseError):
        manager.apply_migrations([
            Migration(2, ("CREATE TABLE migration_probe(value TEXT)", "INVALID SQL")),
        ])

    with sqlite3.connect(database) as connection:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='migration_probe'"
        ).fetchone()
        version = connection.execute(
            "SELECT value FROM storage_metadata WHERE key='schema_version'"
        ).fetchone()[0]
    assert table is None
    assert version == "1"


def test_event_buffer_reports_backpressure_before_rejecting():
    class Sink:
        def submit(self, batch):
            raise AssertionError("not used")

    buffer = EventBuffer(Sink(), capacity=10)
    buffer.enqueue(make_batch("pressure", [0, 1, 2]))

    status = buffer.status()
    assert status.queued_events == 3
    assert status.pressure_ratio == pytest.approx(.3)
    assert status.state == "normal"


def test_expired_archive_backup_listing_and_staged_restore(tmp_path):
    database = tmp_path / "weavexdr.db"
    old_time = datetime.now(UTC) - timedelta(days=60)
    with SQLiteEventStore(database, clock=lambda: old_time) as store:
        PersistentIngestionService(store).submit(make_batch("archived-batch", [0, 1]))
    manager = DatabaseLifecycleManager(
        database,
        backup_root=tmp_path / "backups",
        archive_root=tmp_path / "archives",
        retention_days=30,
    )
    backup = manager.backup()
    archive = manager.archive_expired(now=datetime.now(UTC))

    assert manager.list_backups()[0].file_name == backup.name
    assert manager.list_backups()[0].integrity_ok is True
    with gzip.open(manager.archive_root / archive.file_name, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)
    assert payload["format"] == "weavexdr-archive-v1"
    assert archive.incidents == 1
    assert archive.events == 2

    status = manager.stage_restore(backup.name, confirmed=True)
    assert status.pending_restore is True
    assert manager.apply_pending_restore() is True
    assert manager.recovery_status().rollback_available is True


def test_low_priority_sampling_preserves_capacity_and_reports_loss():
    class Sink:
        def submit(self, batch):
            raise AssertionError("not used")

    now = datetime.now(UTC)
    batch = NormalizedEventBatch.model_validate({
        "batch_id": "dns-pressure",
        "incident_id": "dns-pressure",
        "collector_id": "windows",
        "received_at": now.isoformat(),
        "events": [
            {
                "event_id": f"dns-{index}", "event_type": "dns_query",
                "timestamp": now.isoformat(), "host_id": "local", "source": "windows_event_log",
                "windows_event_id": 3008, "channel": "DNS Client", "action": "query", "target": f"host-{index}.test",
            }
            for index in range(5)
        ],
    })
    buffer = EventBuffer(Sink(), capacity=3, overflow_policy="sample_low_priority")
    buffer.enqueue(batch)

    status = buffer.status()
    assert status.queued_events == 3
    assert status.dropped_events == 2
    assert status.sampled_batches == 1


def test_runtime_health_monitor_reports_process_and_disk_state(tmp_path):
    sample = RuntimeHealthMonitor(tmp_path).sample(collector_delay_seconds=1.5)
    assert 0 <= sample.cpu_percent <= 100
    assert sample.memory_bytes >= 0
    assert sample.disk_free_bytes > 0
    assert sample.collector_delay_seconds == 1.5
