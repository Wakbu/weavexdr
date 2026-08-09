import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from xdr_graph.correlation import EventCorrelationEngine
from xdr_graph.models import (
    FileCreateEvent,
    IncidentInput,
    NetworkConnectEvent,
    ProcessStartEvent,
)


SAMPLE_BATCH = Path(__file__).parents[1] / "samples" / "suspicious_office_batch.json"


def test_process_file_and_network_events_form_one_time_bounded_chain():
    raw_batch = json.loads(SAMPLE_BATCH.read_text(encoding="utf-8"))
    incident = IncidentInput(
        incident_id=raw_batch["incident_id"], events=raw_batch["events"]
    )

    chains, findings = EventCorrelationEngine().correlate(incident.events)

    assert len(chains) == 1
    assert chains[0].event_types == ["file_create", "network_connect", "process_start"]
    assert chains[0].evidence_event_ids == ["event-001", "event-002", "event-003"]
    assert findings[0].rule_id == "CORR-001"
    assert findings[0].severity == 0
    assert findings[0].event_ids == chains[0].evidence_event_ids


def test_parent_and_child_process_guids_build_one_attack_tree():
    start_time = datetime(2026, 8, 9, 1, 0, tzinfo=timezone.utc)
    parent = ProcessStartEvent(
        event_id="process-parent",
        event_type="process_start",
        timestamp=start_time,
        process_name="winword.exe",
        process_id=100,
        process_start_time=start_time,
        process_guid="{PARENT}",
    )
    child = ProcessStartEvent(
        event_id="process-child",
        event_type="process_start",
        timestamp=start_time + timedelta(seconds=1),
        process_name="powershell.exe",
        process_id=200,
        process_start_time=start_time + timedelta(seconds=1),
        process_guid="{CHILD}",
        parent_process_guid="{PARENT}",
    )
    file_event = FileCreateEvent(
        event_id="file-child",
        event_type="file_create",
        timestamp=start_time + timedelta(seconds=2),
        process_id=200,
        process_start_time=start_time + timedelta(seconds=1),
        process_guid="{CHILD}",
        file_path="C:\\Temp\\payload.exe",
    )
    network_event = NetworkConnectEvent(
        event_id="network-child",
        event_type="network_connect",
        timestamp=start_time + timedelta(seconds=3),
        process_id=200,
        process_start_time=start_time + timedelta(seconds=1),
        process_guid="{CHILD}",
        destination_ip="8.8.8.8",
        destination_port=443,
        protocol="tcp",
    )

    chains, _ = EventCorrelationEngine().correlate(
        [parent, child, file_event, network_event]
    )

    assert len(chains) == 1
    assert chains[0].root_process_event_id == "process-parent"
    assert chains[0].process_event_ids == ["process-parent", "process-child"]
    assert chains[0].evidence_event_ids == [
        "process-parent",
        "process-child",
        "file-child",
        "network-child",
    ]


def test_events_outside_the_time_window_are_not_joined_as_attack_evidence():
    start_time = datetime(2026, 8, 9, 1, 0, tzinfo=timezone.utc)
    process_event = ProcessStartEvent(
        event_id="process-event",
        event_type="process_start",
        timestamp=start_time,
        process_name="powershell.exe",
        process_id=300,
        process_start_time=start_time,
    )
    late_file = FileCreateEvent(
        event_id="late-file",
        event_type="file_create",
        timestamp=start_time + timedelta(minutes=10),
        process_id=300,
        process_start_time=start_time,
        file_path="C:\\Temp\\late.exe",
    )

    chains, findings = EventCorrelationEngine(
        time_window=timedelta(minutes=5)
    ).correlate([process_event, late_file])

    assert chains == []
    assert findings == []
