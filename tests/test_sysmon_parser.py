from datetime import datetime, timezone
from xml.etree import ElementTree

import pytest

from xdr_graph.models import FileCreateEvent, NetworkConnectEvent, ProcessStartEvent
from xdr_graph.sysmon_parser import (
    SysmonGraphPipeline,
    SysmonXmlParser,
    UnsupportedSysmonEvent,
)


EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
PROCESS_GUID = "{11111111-2222-3333-4444-555555555555}"


def build_sysmon_xml(event_id: int, record_id: int, fields: dict[str, str]) -> str:
    """실제 Windows Event XML과 같은 namespace·Data 구조의 테스트 문서를 만든다."""

    root = ElementTree.Element("Event", xmlns=EVENT_NAMESPACE)
    system = ElementTree.SubElement(root, "System")
    ElementTree.SubElement(system, "Provider", Name="Microsoft-Windows-Sysmon")
    ElementTree.SubElement(system, "EventID").text = str(event_id)
    ElementTree.SubElement(system, "EventRecordID").text = str(record_id)
    ElementTree.SubElement(system, "Computer").text = "DESKTOP-TEST"
    event_data = ElementTree.SubElement(root, "EventData")
    for name, value in fields.items():
        ElementTree.SubElement(event_data, "Data", Name=name).text = value
    return ElementTree.tostring(root, encoding="unicode")


def process_create_xml() -> str:
    return build_sysmon_xml(
        1,
        1001,
        {
            "UtcTime": "2026-08-09 01:00:00.123",
            "ProcessGuid": PROCESS_GUID,
            "ProcessId": "4242",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgA",
            "User": "DESKTOP-TEST\\user",
            "Hashes": "SHA256=ABCDEF,IMPHASH=123456",
            "Signature": "Microsoft Windows Publisher",
            "SignatureStatus": "Valid",
            "ParentProcessGuid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            "ParentProcessId": "3000",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        },
    )


def network_connect_xml() -> str:
    return build_sysmon_xml(
        3,
        1002,
        {
            "UtcTime": "2026-08-09 01:00:05.000",
            "ProcessGuid": PROCESS_GUID,
            "ProcessId": "4242",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "User": "DESKTOP-TEST\\user",
            "Protocol": "tcp",
            "Initiated": "true",
            "SourceIp": "192.168.0.10",
            "SourcePort": "53001",
            "DestinationIp": "8.8.8.8",
            "DestinationPort": "443",
            "DestinationHostname": "dns.google",
        },
    )


def file_create_xml() -> str:
    return build_sysmon_xml(
        11,
        1003,
        {
            "UtcTime": "2026-08-09 01:00:03.000",
            "ProcessGuid": PROCESS_GUID,
            "ProcessId": "4242",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "TargetFilename": "C:\\Users\\user\\AppData\\Local\\Temp\\payload.exe",
            "User": "DESKTOP-TEST\\user",
        },
    )


def test_process_create_is_normalized_with_hashes_and_parent():
    event = SysmonXmlParser().parse(process_create_xml())

    assert isinstance(event, ProcessStartEvent)
    assert event.event_id == "sysmon:DESKTOP-TEST:1001"
    assert event.process_name == "powershell.exe"
    assert event.parent_process == "WINWORD.EXE"
    assert event.process_id == 4242
    assert event.process_guid == PROCESS_GUID
    assert event.file_hashes == {"SHA256": "abcdef", "IMPHASH": "123456"}
    assert event.file_signer == "Microsoft Windows Publisher"
    assert event.signature_status == "Valid"
    assert event.timestamp.tzinfo == timezone.utc


def test_process_guid_enriches_network_and_file_events():
    parser = SysmonXmlParser()
    process_event = parser.parse(process_create_xml())
    network_event = parser.parse(network_connect_xml())
    file_event = parser.parse(file_create_xml())

    assert isinstance(network_event, NetworkConnectEvent)
    assert isinstance(file_event, FileCreateEvent)
    assert network_event.process_start_time == process_event.process_start_time
    assert file_event.process_start_time == process_event.process_start_time
    assert network_event.destination_port == 443
    assert network_event.source_ip == "192.168.0.10"
    assert network_event.source_port == 53001
    assert network_event.destination_hostname == "dns.google"
    assert network_event.initiated is True
    assert file_event.file_path.endswith("payload.exe")


def test_unsupported_sysmon_event_is_rejected():
    unsupported_xml = build_sysmon_xml(
        7,
        1004,
        {"UtcTime": "2026-08-09 01:00:10.000"},
    )

    with pytest.raises(UnsupportedSysmonEvent, match="Event ID 7"):
        SysmonXmlParser().parse(unsupported_xml)


def test_sysmon_batch_reaches_the_analysis_graph():
    receipt = SysmonGraphPipeline().submit_xml_batch(
        [process_create_xml(), file_create_xml(), network_connect_xml()],
        batch_id="sysmon-batch-001",
        incident_id="sysmon-incident-001",
        received_at=datetime(2026, 8, 9, 1, 0, 10, tzinfo=timezone.utc),
    )

    assert receipt.accepted_event_count == 3
    assert receipt.report.verdict == "suspicious"
    assert receipt.report.risk_score == 100
    assert receipt.report.validation.passed is True
