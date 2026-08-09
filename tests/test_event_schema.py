from datetime import datetime

import pytest
from pydantic import ValidationError

from xdr_graph.models import (
    FileCreateEvent,
    IncidentInput,
    NetworkConnectEvent,
    ProcessStartEvent,
)


def test_event_type_selects_the_correct_schema():
    incident = IncidentInput.model_validate(
        {
            "incident_id": "schema-test",
            "events": [
                {
                    "event_id": "p1",
                    "event_type": "process_start",
                    "timestamp": "2026-08-08T10:00:00+09:00",
                    "process_name": "powershell.exe",
                },
                {
                    "event_id": "f1",
                    "event_type": "file_create",
                    "timestamp": "2026-08-08T10:00:01+09:00",
                    "file_path": "C:\\Temp\\sample.exe",
                },
                {
                    "event_id": "n1",
                    "event_type": "network_connect",
                    "timestamp": "2026-08-08T10:00:02+09:00",
                    "destination_ip": "8.8.8.8",
                    "destination_port": 443,
                    "protocol": "tcp",
                },
            ],
        }
    )

    # 판별 유니온이 각 이벤트를 구체 타입으로 만들었는지 확인한다.
    assert isinstance(incident.events[0], ProcessStartEvent)
    assert isinstance(incident.events[1], FileCreateEvent)
    assert isinstance(incident.events[2], NetworkConnectEvent)
    assert incident.events[0].schema_version == "1.0"
    assert incident.events[0].source == "sample"


def test_timestamp_without_timezone_is_rejected():
    with pytest.raises(ValidationError, match="timezone offset"):
        IncidentInput.model_validate(
            {
                "incident_id": "missing-timezone",
                "events": [
                    {
                        "event_id": "p1",
                        "event_type": "process_start",
                        "timestamp": "2026-08-08T10:00:00",
                        "process_name": "notepad.exe",
                    }
                ],
            }
        )


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [("process_id", -1), ("destination_port", 70000)],
)
def test_invalid_numeric_boundaries_are_rejected(field_name, invalid_value):
    event = {
        "event_id": "n1",
        "event_type": "network_connect",
        "timestamp": "2026-08-08T10:00:00+09:00",
        "destination_ip": "8.8.8.8",
        field_name: invalid_value,
    }
    with pytest.raises(ValidationError):
        IncidentInput.model_validate({"incident_id": "bad-range", "events": [event]})


def test_invalid_ip_and_unknown_fields_are_rejected():
    event = {
        "event_id": "n1",
        "event_type": "network_connect",
        "timestamp": "2026-08-08T10:00:00+09:00",
        "destination_ip": "not-an-ip",
        "unexpected_field": "value",
    }
    with pytest.raises(ValidationError):
        IncidentInput.model_validate({"incident_id": "bad-network", "events": [event]})


def test_json_dump_keeps_an_iso_timestamp():
    incident = IncidentInput.model_validate(
        {
            "incident_id": "json-test",
            "events": [
                {
                    "event_id": "p1",
                    "event_type": "process_start",
                    "timestamp": "2026-08-08T10:00:00+09:00",
                    "process_name": "notepad.exe",
                }
            ],
        }
    )

    serialized = incident.model_dump(mode="json")
    assert serialized["events"][0]["timestamp"] == "2026-08-08T10:00:00+09:00"
    assert isinstance(incident.events[0].timestamp, datetime)
