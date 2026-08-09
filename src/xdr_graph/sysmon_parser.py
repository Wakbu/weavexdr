from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Iterable
from xml.etree import ElementTree

from xdr_graph.ingestion import (
    EventBatchSink,
    GraphIngestionService,
    IngestionReceipt,
    NormalizedEventBatch,
)
from xdr_graph.models import (
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessStartEvent,
    SecurityEvent,
)


WINDOWS_EVENT_NAMESPACE = {"event": "http://schemas.microsoft.com/win/2004/08/events/event"}


class UnsupportedSysmonEvent(ValueError):
    """현재 수집 파이프라인이 처리하지 않는 Sysmon 이벤트를 나타낸다."""


@dataclass(frozen=True)
class ProcessContext:
    """ProcessGuid로 후속 파일·네트워크 이벤트에 보강할 프로세스 정보."""

    process_id: int
    process_name: str
    image_path: str
    process_start_time: datetime


class ProcessCorrelationIndex:
    """한 실행 세션에서 확인한 ProcessGuid와 프로세스 시작 정보를 보관한다."""

    def __init__(self) -> None:
        self._processes: dict[str, ProcessContext] = {}

    @staticmethod
    def normalize_guid(process_guid: str) -> str:
        # Sysmon GUID는 대소문자 차이가 의미 없으므로 조회 키를 통일한다.
        return process_guid.strip().lower()

    def remember(self, event: ProcessStartEvent) -> None:
        if not event.process_guid or event.process_id is None or not event.image_path:
            return
        self._processes[self.normalize_guid(event.process_guid)] = ProcessContext(
            process_id=event.process_id,
            process_name=event.process_name,
            image_path=event.image_path,
            process_start_time=event.process_start_time or event.timestamp,
        )

    def find(self, process_guid: str | None) -> ProcessContext | None:
        if not process_guid:
            return None
        return self._processes.get(self.normalize_guid(process_guid))


class SysmonXmlParser:
    """Windows Event XML을 공통 보안 이벤트 스키마 1.0으로 변환한다."""

    def __init__(self, process_index: ProcessCorrelationIndex | None = None) -> None:
        self.process_index = process_index or ProcessCorrelationIndex()

    def parse(self, xml_document: str) -> SecurityEvent:
        root = ElementTree.fromstring(xml_document)
        event_id = self._required_system_text(root, "EventID")
        record_id = self._required_system_text(root, "EventRecordID")
        computer_name = self._required_system_text(root, "Computer")
        fields = self._event_fields(root)
        common_fields = {
            "event_id": f"sysmon:{computer_name}:{record_id}",
            "timestamp": self._parse_utc_time(fields["UtcTime"]),
            "host_id": computer_name,
            "source": "sysmon",
        }

        if event_id == "1":
            event = self._parse_process_create(fields, common_fields)
            self.process_index.remember(event)
            return event
        if event_id == "3":
            return self._parse_network_connect(fields, common_fields)
        if event_id == "11":
            return self._parse_file_create(fields, common_fields)
        raise UnsupportedSysmonEvent(f"Sysmon Event ID {event_id} is not supported")

    def _parse_process_create(self, fields: dict[str, str], common: dict) -> ProcessStartEvent:
        image_path = fields["Image"]
        return ProcessStartEvent(
            **common,
            event_type="process_start",
            process_name=self._image_name(image_path),
            process_id=self._parse_int(fields.get("ProcessId")),
            process_start_time=common["timestamp"],
            process_guid=fields.get("ProcessGuid"),
            image_path=image_path,
            user=fields.get("User"),
            file_hashes=self._parse_hashes(fields.get("Hashes", "")),
            parent_process=self._image_name(fields.get("ParentImage")),
            parent_process_id=self._parse_int(fields.get("ParentProcessId")),
            parent_process_guid=fields.get("ParentProcessGuid"),
            command_line=fields.get("CommandLine"),
        )

    def _parse_network_connect(self, fields: dict[str, str], common: dict) -> NetworkConnectEvent:
        process_guid = fields.get("ProcessGuid")
        context = self.process_index.find(process_guid)
        image_path = fields.get("Image") or (context.image_path if context else None)
        return NetworkConnectEvent(
            **common,
            event_type="network_connect",
            process_name=self._image_name(image_path) or (context.process_name if context else None),
            process_id=self._parse_int(fields.get("ProcessId"))
            or (context.process_id if context else None),
            process_start_time=context.process_start_time if context else None,
            process_guid=process_guid,
            image_path=image_path,
            user=fields.get("User"),
            destination_ip=fields["DestinationIp"],
            destination_port=self._parse_int(fields.get("DestinationPort")),
            protocol=self._protocol(fields.get("Protocol")),
        )

    def _parse_file_create(self, fields: dict[str, str], common: dict) -> FileCreateEvent:
        process_guid = fields.get("ProcessGuid")
        context = self.process_index.find(process_guid)
        image_path = fields.get("Image") or (context.image_path if context else None)
        return FileCreateEvent(
            **common,
            event_type="file_create",
            process_name=self._image_name(image_path) or (context.process_name if context else None),
            process_id=self._parse_int(fields.get("ProcessId"))
            or (context.process_id if context else None),
            process_start_time=context.process_start_time if context else None,
            process_guid=process_guid,
            image_path=image_path,
            user=fields.get("User"),
            file_path=fields["TargetFilename"],
        )

    @staticmethod
    def _required_system_text(root: ElementTree.Element, field_name: str) -> str:
        value = root.findtext(
            f"./event:System/event:{field_name}", namespaces=WINDOWS_EVENT_NAMESPACE
        )
        if not value:
            raise ValueError(f"Sysmon System/{field_name} is required")
        return value

    @staticmethod
    def _event_fields(root: ElementTree.Element) -> dict[str, str]:
        fields: dict[str, str] = {}
        for element in root.findall(
            "./event:EventData/event:Data", namespaces=WINDOWS_EVENT_NAMESPACE
        ):
            name = element.attrib.get("Name")
            if name:
                fields[name] = element.text or ""
        return fields

    @staticmethod
    def _parse_utc_time(value: str) -> datetime:
        # Sysmon UtcTime은 ISO 8601의 T와 오프셋 없이 UTC 시각으로 기록된다.
        # 일부 버전의 소수점 자릿수 차이를 허용한 뒤 UTC 시간대를 명시한다.
        normalized = value.strip().replace(" ", "T")
        parsed = datetime.fromisoformat(normalized)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed

    @staticmethod
    def _parse_int(value: str | None) -> int | None:
        if value is None or not value.strip():
            return None
        return int(value, 0)

    @staticmethod
    def _image_name(image_path: str | None) -> str | None:
        if not image_path:
            return None
        return PureWindowsPath(image_path).name

    @staticmethod
    def _parse_hashes(value: str) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for item in value.split(","):
            algorithm, separator, digest = item.partition("=")
            if separator and algorithm.strip() and digest.strip():
                hashes[algorithm.strip().upper()] = digest.strip().lower()
        return hashes

    @staticmethod
    def _protocol(value: str | None) -> str:
        normalized = (value or "unknown").lower()
        return normalized if normalized in {"tcp", "udp"} else "unknown"


class SysmonGraphPipeline:
    """Sysmon XML 묶음을 파싱하고 기존 그래프 입력 포트까지 전달한다."""

    def __init__(
        self,
        parser: SysmonXmlParser | None = None,
        ingestion_service: EventBatchSink | None = None,
    ) -> None:
        self.parser = parser or SysmonXmlParser()
        self.ingestion_service = ingestion_service or GraphIngestionService()

    def submit_xml_batch(
        self,
        xml_documents: Iterable[str],
        *,
        batch_id: str,
        incident_id: str,
        collector_id: str = "sysmon-local",
        received_at: datetime | None = None,
    ) -> IngestionReceipt:
        # 입력 순서를 유지해야 Event ID 1에서 기억한 ProcessGuid를 뒤따르는
        # Event ID 3·11에 보강할 수 있다. 실제 수집기는 시간순 정렬 후 호출한다.
        normalized_events = [self.parser.parse(document) for document in xml_documents]
        batch = NormalizedEventBatch(
            batch_id=batch_id,
            incident_id=incident_id,
            collector_id=collector_id,
            received_at=received_at or datetime.now(timezone.utc),
            events=normalized_events,
        )
        return self.ingestion_service.submit(batch)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate exported Sysmon event XML files")
    parser.add_argument("xml_files", type=Path, nargs="+")
    args = parser.parse_args()

    sysmon_parser = SysmonXmlParser()
    normalized_events = [
        sysmon_parser.parse(path.read_text(encoding="utf-8")) for path in args.xml_files
    ]
    # 실제 명령줄과 사용자 경로는 출력하지 않고 호환성 확인 정보만 보여준다.
    summary = {
        "parsed": len(normalized_events),
        "event_types": [event.event_type for event in normalized_events],
        "event_ids": [event.event_id for event in normalized_events],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
