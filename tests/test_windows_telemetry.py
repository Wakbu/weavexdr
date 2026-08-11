from xdr_graph.windows_telemetry import WINDOWS_SOURCE_SPECS, WindowsTelemetryParser


def _xml(event_id: int, record_id: int, data: dict[str, str]) -> str:
    fields = "".join(f'<Data Name="{key}">{value}</Data>' for key, value in data.items())
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
    <EventID>{event_id}</EventID><EventRecordID>{record_id}</EventRecordID>
    <TimeCreated SystemTime="2026-08-09T01:02:03Z"/><Computer>desk</Computer></System>
    <EventData>{fields}</EventData></Event>'''


def test_security_failure_is_normalized() -> None:
    event = WindowsTelemetryParser().parse(WINDOWS_SOURCE_SPECS[0], _xml(4625, 7, {"TargetUserName": "alice", "IpAddress": "10.0.0.8"}))
    assert event.event_type == "authentication"
    assert event.action == "logon_failed"
    assert event.outcome == "failure"
    assert event.source_ip == "10.0.0.8"


def test_sysmon_driver_and_powershell_are_specialized_and_bounded() -> None:
    parser = WindowsTelemetryParser()
    driver = parser.parse(WINDOWS_SOURCE_SPECS[9], _xml(6, 8, {"Image": "driver.sys"}))
    script = parser.parse(WINDOWS_SOURCE_SPECS[4], _xml(4104, 9, {"ScriptBlockText": "x" * 5000}))
    assert driver.event_type == "driver_install"
    assert script.action == "powershell_script_block"
    assert len(script.command_line or "") == 4096
    assert "ScriptBlockText" not in script.details
