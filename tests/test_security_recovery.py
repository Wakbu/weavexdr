import hashlib
import hmac
import json
import os
import sqlite3
import time

from fastapi.testclient import TestClient

from xdr_graph.api import ApiRuntime, create_app
from xdr_graph.instance import InstanceCoordinator, InstanceRecord
from xdr_graph.response import ApprovalService, DryRunResponseService
from xdr_graph.runtime_health import RuntimeHealthMonitor
from xdr_graph.runtime_recovery import RuntimeRecoveryManager
from xdr_graph.security import protect_user_secret, unprotect_user_secret
from xdr_graph.storage import SQLiteEventStore
from xdr_graph.storage_maintenance import DatabaseLifecycleManager
from xdr_graph.version import APP_VERSION


TOKEN = "security-test-token-with-at-least-thirty-two-characters"


def test_user_secret_round_trip_and_instance_record_hides_plaintext(tmp_path):
    protected = protect_user_secret("runtime-secret")
    assert protected != "runtime-secret"
    assert unprotect_user_secret(protected) == "runtime-secret"

    coordinator = InstanceCoordinator(tmp_path)
    record = InstanceRecord(os.getpid(), 18765, APP_VERSION, "never-store-this-token", "protecting")
    coordinator.publish(record)
    raw = coordinator.record_path.read_text(encoding="utf-8")
    assert "never-store-this-token" not in raw
    assert "token_protected" in raw
    assert coordinator.read() == record


def test_instance_handshake_is_timestamped_signed_and_replay_safe():
    store = SQLiteEventStore(":memory:")
    runtime = ApiRuntime(
        event_store=store,
        dry_run_service=DryRunResponseService(),
        approval_service=ApprovalService(),
        instance_token="instance-handshake-secret",
        instance_port=18765,
    )
    client = TestClient(create_app(runtime, api_token=TOKEN, enforce_loopback=False))
    try:
        timestamp = str(int(time.time()))
        nonce = "one-time-nonce"
        signed = f"{os.getpid()}:18765:{APP_VERSION}:{timestamp}:{nonce}".encode()
        signature = hmac.new(b"instance-handshake-secret", signed, hashlib.sha256).hexdigest()
        headers = {
            "X-WeaveXDR-Timestamp": timestamp,
            "X-WeaveXDR-Nonce": nonce,
            "X-WeaveXDR-Signature": signature,
        }
        assert client.post("/instance/open", headers=headers).status_code == 200
        assert client.post("/instance/open", headers=headers).status_code == 401
        assert client.get("/health").headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in client.get("/health").headers["content-security-policy"]
    finally:
        store.close()


def test_unclean_shutdown_creates_verified_recovery_backup(tmp_path):
    database = tmp_path / "weavexdr.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sample(value TEXT)")
        connection.execute("INSERT INTO sample VALUES('preserved')")
    storage = DatabaseLifecycleManager(database, backup_root=tmp_path / "backups")
    recovery = RuntimeRecoveryManager(tmp_path, storage)
    recovery.marker_path.write_text(json.dumps({"pid": 1}), encoding="utf-8")

    report = recovery.begin()

    assert report.unclean_shutdown_detected is True
    assert report.database_integrity_ok is True
    assert report.recovery_action == "verified_backup_created"
    assert report.recovery_backup
    assert (tmp_path / "backups" / report.recovery_backup).is_file()
    recovery.complete()
    assert not recovery.marker_path.exists()


def test_low_power_mode_slows_only_file_watcher_polling(tmp_path, monkeypatch):
    monitor = RuntimeHealthMonitor(tmp_path)
    monkeypatch.setattr(monitor, "power_state", lambda: ("low_power", True, 20))
    assert monitor.watcher_poll_interval() == 8.0
    health = monitor.sample()
    assert health.power_mode == "low_power"
    assert health.on_battery is True
    assert health.battery_percent == 20
