from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Event, Thread
from typing import Callable, Protocol
from xml.etree import ElementTree

from xdr_graph.ingestion import EventBatchSink, NormalizedEventBatch
from xdr_graph.models import WindowsTelemetryEvent


EVENT_NS = {"event": "http://schemas.microsoft.com/win/2004/08/events/event"}


@dataclass(frozen=True)
class WindowsSourceSpec:
    name: str
    channel: str
    event_ids: tuple[int, ...]
    event_type: str


WINDOWS_SOURCE_SPECS = (
    WindowsSourceSpec("Security authentication", "Security", (4624, 4625, 4672), "authentication"),
    WindowsSourceSpec("Security accounts", "Security", (4720, 4722, 4728, 4732, 4756), "account_change"),
    WindowsSourceSpec("Security remote access", "Security", (4648, 4778, 4779, 5140), "remote_access"),
    WindowsSourceSpec("Windows firewall", "Security", (5156, 5157), "firewall_connection"),
    WindowsSourceSpec("PowerShell", "Microsoft-Windows-PowerShell/Operational", (4103, 4104), "powershell_script"),
    WindowsSourceSpec("Microsoft Defender", "Microsoft-Windows-Windows Defender/Operational", (1000, 1001, 1116, 1117, 1118, 1119, 1121), "defender_detection"),
    WindowsSourceSpec("DNS Client", "Microsoft-Windows-DNS-Client/Operational", (3008, 3010, 3020), "dns_query"),
    WindowsSourceSpec("Task Scheduler", "Microsoft-Windows-TaskScheduler/Operational", (106, 140, 141), "scheduled_task"),
    WindowsSourceSpec("System services", "System", (7045,), "service_install"),
    WindowsSourceSpec("Sysmon persistence", "Microsoft-Windows-Sysmon/Operational", (6, 12, 13, 14, 19, 20, 21), "registry_persistence"),
    WindowsSourceSpec("USB devices", "Microsoft-Windows-DriverFrameworks-UserMode/Operational", (2003, 2102), "usb_device"),
    WindowsSourceSpec("Windows Remote Management", "Microsoft-Windows-WinRM/Operational", (6, 91, 142, 169), "remote_access"),
)


@dataclass(frozen=True)
class RawWindowsEvent:
    record_id: int
    xml: str


class ChannelReader(Protocol):
    def latest_record_id(self) -> int: ...
    def read_after(self, record_id: int) -> list[RawWindowsEvent]: ...


class WindowsChannelReader:
    def __init__(self, spec: WindowsSourceSpec) -> None:
        import pywintypes
        import win32evtlog

        self.spec = spec
        self._event_log = win32evtlog
        self._windows_error = pywintypes.error

    def latest_record_id(self) -> int:
        handle = self._event_log.EvtQuery(
            self.spec.channel,
            self._event_log.EvtQueryChannelPath | self._event_log.EvtQueryReverseDirection,
            "*[System[EventRecordID > 0]]",
        )
        try:
            events = self._next(handle, 1)
            if not events:
                return 0
            try:
                xml = self._event_log.EvtRender(events[0], self._event_log.EvtRenderEventXml)
                return WindowsTelemetryParser.record_id(xml)
            finally:
                for event in events:
                    self._close(event)
        finally:
            self._close(handle)

    def read_after(self, record_id: int) -> list[RawWindowsEvent]:
        event_query = " or ".join(f"EventID={value}" for value in self.spec.event_ids)
        query = f"*[System[({event_query}) and EventRecordID > {record_id}]]"
        handle = self._event_log.EvtQuery(
            self.spec.channel,
            self._event_log.EvtQueryChannelPath | self._event_log.EvtQueryForwardDirection,
            query,
        )
        records: list[RawWindowsEvent] = []
        try:
            while True:
                events = self._next(handle, 64)
                if not events:
                    break
                for event in events:
                    try:
                        xml = self._event_log.EvtRender(event, self._event_log.EvtRenderEventXml)
                        records.append(RawWindowsEvent(WindowsTelemetryParser.record_id(xml), xml))
                    finally:
                        self._close(event)
            return records
        finally:
            self._close(handle)

    def _next(self, handle, count: int) -> list:
        try:
            return list(self._event_log.EvtNext(handle, count, 0, 0))
        except self._windows_error as error:
            if (getattr(error, "winerror", None) or error.args[0]) == 259:
                return []
            raise

    @staticmethod
    def _close(handle) -> None:
        close = getattr(handle, "Close", None)
        if close:
            close()


class WindowsTelemetryParser:
    """Normalize selected Windows channels without retaining secret script bodies in logs."""

    @staticmethod
    def record_id(xml: str) -> int:
        root = ElementTree.fromstring(xml)
        value = root.findtext("./event:System/event:EventRecordID", namespaces=EVENT_NS)
        if not value:
            raise ValueError("Windows EventRecordID is required")
        return int(value)

    def parse(self, spec: WindowsSourceSpec, xml: str) -> WindowsTelemetryEvent:
        root = ElementTree.fromstring(xml)
        system = root.find("event:System", EVENT_NS)
        if system is None:
            raise ValueError("Windows System element is required")
        event_id = int(system.findtext("event:EventID", namespaces=EVENT_NS) or 0)
        record_id = int(system.findtext("event:EventRecordID", namespaces=EVENT_NS) or 0)
        created = system.find("event:TimeCreated", EVENT_NS)
        timestamp = datetime.fromisoformat((created.attrib.get("SystemTime") if created is not None else "").replace("Z", "+00:00"))
        computer = system.findtext("event:Computer", namespaces=EVENT_NS) or "local-host"
        data: dict[str, str] = {}
        for node in root.findall("./event:EventData/event:Data", EVENT_NS):
            name = node.attrib.get("Name")
            if name and node.text is not None:
                data[name] = node.text
        event_type = self._specialized_type(spec.event_type, event_id, data)
        action = self._action(event_type, event_id, data)
        process_id = self._integer(data.get("ProcessId") or data.get("NewProcessId"))
        return WindowsTelemetryEvent(
            event_id=f"win-{spec.name.lower().replace(' ', '-')}-{record_id}",
            event_type=event_type,
            timestamp=timestamp,
            host_id=computer,
            source="windows_event_log",
            windows_event_id=event_id,
            channel=spec.channel,
            action=action,
            user=data.get("TargetUserName") or data.get("SubjectUserName") or data.get("User"),
            process_name=data.get("ProcessName") or data.get("Image") or data.get("Application"),
            process_id=process_id,
            command_line=self._bounded(data.get("ScriptBlockText") or data.get("Payload") or data.get("CommandLine"), 4096),
            target=data.get("TargetObject") or data.get("ServiceName") or data.get("TaskName") or data.get("DeviceDescription") or data.get("QueryName"),
            source_ip=self._clean_ip(data.get("IpAddress") or data.get("SourceAddress")),
            destination_ip=self._clean_ip(data.get("DestAddress") or data.get("DestinationAddress")),
            destination_port=self._integer(data.get("DestPort") or data.get("DestinationPort")),
            protocol=data.get("Protocol"),
            outcome="failure" if event_id in {4625, 5157} else "success",
            details={key: self._bounded(value, 1024) or "" for key, value in data.items() if key not in {"ScriptBlockText", "Payload"}},
        )

    @staticmethod
    def _specialized_type(default: str, event_id: int, data: dict[str, str]) -> str:
        if default == "authentication" and event_id == 4672:
            return "privilege_use"
        if default == "registry_persistence":
            if event_id == 6:
                return "driver_install"
            if event_id in {19, 20, 21}:
                return "wmi_subscription"
        return default

    @staticmethod
    def _action(event_type: str, event_id: int, data: dict[str, str]) -> str:
        actions = {
            4624: "logon", 4625: "logon_failed", 4672: "special_privileges",
            1116: "malware_detected", 1117: "defender_action", 5156: "allowed", 5157: "blocked",
            4103: "powershell_module", 4104: "powershell_script_block", 7045: "service_created",
        }
        return actions.get(event_id, data.get("Operation") or event_type)

    @staticmethod
    def _integer(value: str | None) -> int | None:
        if not value or value == "-":
            return None
        try:
            return int(value, 0)
        except ValueError:
            return None

    @staticmethod
    def _clean_ip(value: str | None) -> str | None:
        return None if not value or value in {"-", "::1", "127.0.0.1"} else value

    @staticmethod
    def _bounded(value: str | None, limit: int) -> str | None:
        return value[:limit] if value else None


class WindowsTelemetryCollector:
    def __init__(
        self,
        sink: EventBatchSink,
        *,
        specs: tuple[WindowsSourceSpec, ...] = WINDOWS_SOURCE_SPECS,
        reader_factory: Callable[[WindowsSourceSpec], ChannelReader] = WindowsChannelReader,
        status_callback: Callable[[dict[str, object]], None] | None = None,
        poll_interval: float = 2.0,
        logger: logging.Logger | None = None,
    ) -> None:
        self.sink, self.specs, self.reader_factory = sink, specs, reader_factory
        self.status_callback, self.poll_interval = status_callback, poll_interval
        self.logger = logger or logging.getLogger(__name__)
        self._stop = Event()
        self._pause = Event()
        self._thread: Thread | None = None
        self._parser = WindowsTelemetryParser()
        self._states: dict[str, dict[str, object]] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = Thread(target=self._run, name="weavexdr-windows-telemetry", daemon=True)
        self._thread.start()

    def pause(self) -> None:
        self._pause.set()

    def resume(self) -> None:
        self._pause.clear()

    def stop(self, timeout: float = 15.0) -> bool:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)
        return not self._thread or not self._thread.is_alive()

    def _run(self) -> None:
        readers: dict[str, ChannelReader] = {}
        cursors: dict[str, int] = {}
        while not self._stop.is_set():
            if self._pause.is_set():
                self._stop.wait(self.poll_interval)
                continue
            for spec in self.specs:
                try:
                    if spec.name not in readers:
                        readers[spec.name] = self.reader_factory(spec)
                    reader = readers[spec.name]
                    if spec.name not in cursors:
                        cursors[spec.name] = reader.latest_record_id()
                    for record in reader.read_after(cursors[spec.name]):
                        lost = max(0, record.record_id - cursors[spec.name] - 1)
                        event = self._parser.parse(spec, record.xml)
                        batch = NormalizedEventBatch(
                            batch_id=f"windows-{spec.name.lower().replace(' ', '-')}-{record.record_id}",
                            incident_id=self._incident_id(event),
                            collector_id=f"windows-{spec.name.lower().replace(' ', '-')}",
                            received_at=datetime.now(UTC),
                            events=[event],
                        )
                        self.sink.submit(batch)
                        cursors[spec.name] = record.record_id
                        self._states[spec.name] = {"state": "running", "last_event_at": event.timestamp.isoformat(), "last_healthy_at": datetime.now(UTC).isoformat(), "loss_count": lost, "delay_seconds": max(0, (datetime.now(UTC) - event.timestamp.astimezone(UTC)).total_seconds())}
                    self._states.setdefault(spec.name, {"state": "running", "last_healthy_at": datetime.now(UTC).isoformat(), "loss_count": 0, "delay_seconds": 0})
                except Exception as error:
                    readers.pop(spec.name, None)
                    self._states[spec.name] = {"state": "error", "error": type(error).__name__}
            self._publish()
            self._stop.wait(self.poll_interval)

    def _publish(self) -> None:
        if self.status_callback:
            healthy = [name for name, value in self._states.items() if value.get("state") == "running"]
            self.status_callback({"state": "running" if healthy else "error", "label": f"Windows 확장 수집 {len(healthy)}/{len(self.specs)}", "source": "Windows extended", "sources": healthy, "source_health": self._states})

    @staticmethod
    def _incident_id(event: WindowsTelemetryEvent) -> str:
        key = event.user or event.process_name or event.target or event.source_ip or event.event_id
        safe = re.sub(r"[^a-zA-Z0-9]+", "-", key).strip("-").lower()[:80]
        return f"windows-{event.host_id.lower()}-{safe}"
