from __future__ import annotations

import os
import secrets
import socket
import sys
import threading
import time
import webbrowser
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.request import urlopen
from urllib.parse import urlencode

import uvicorn

from xdr_graph.api import ApiRuntime, create_app
from xdr_graph.allowlist import load_default_allowlist_engine
from xdr_graph.detection import load_default_detection_engine
from xdr_graph.logging_setup import configure_rotating_logging
from xdr_graph.response import ApprovalService, DryRunResponseService
from xdr_graph.response_execution import ActualResponseService, RecoveryRegistry
from xdr_graph.response_playbook import ResponsePlaybookService
from xdr_graph.audit import SQLiteAuditLog
from xdr_graph.quarantine import QuarantineStore
from xdr_graph.risk_policy import load_default_risk_policy
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore
from xdr_graph.storage_maintenance import DatabaseLifecycleManager
from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.models import FileCreateEvent, Finding, IncidentReport, ValidationResult
from xdr_graph.threat_intelligence import ContentUpdateManager, ThreatIntelStore
from xdr_graph.sysmon_collector import SysmonCollector
from xdr_graph.instance import InstanceCoordinator, InstanceRecord
from xdr_graph.tray import WindowsTray
from xdr_graph.version import APP_VERSION
from xdr_graph.windows_telemetry import WindowsTelemetryCollector
from xdr_graph.runtime_health import RuntimeHealthMonitor
from xdr_graph.runtime_recovery import RuntimeRecoveryManager, StartupRecoveryReport
from xdr_graph.antivirus import AdvancedFileScanner, InspectionCache, ScanJobManager
from xdr_graph.file_scanner import FileInspectionEngine, YaraScanner
from xdr_graph.file_watcher import DirectoryFileWatcher, default_watch_directories, removable_watch_directories
from xdr_graph.native_dialogs import select_scan_paths
from xdr_graph.security import harden_data_permissions


FORCED_SHUTDOWN_TIMEOUT_SECONDS = 20.0


def request_collector_access_setup() -> None:
    """번들된 설정 스크립트를 Windows UAC 승인 흐름으로 실행한다."""

    if os.name != "nt":
        raise RuntimeError("collector access setup is only available on Windows")
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        script_path = Path(sys._MEIPASS) / "xdr_graph" / "tools" / "configure_sysmon_access.ps1"
    else:
        script_path = Path(__file__).parents[2] / "scripts" / "configure_sysmon_access.ps1"
    if not script_path.is_file():
        raise FileNotFoundError(f"collector setup script was not found: {script_path}")

    # ShellExecute의 runas 동사는 Windows가 신뢰 경계인 UAC 확인창을 직접
    # 표시하게 한다. API 토큰이나 사용자 입력을 명령행에 넣지 않는다.
    import ctypes

    arguments = f'-NoProfile -ExecutionPolicy Bypass -File "{script_path}"'
    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        "powershell.exe",
        arguments,
        str(script_path.parent),
        1,
    )
    if result <= 32:
        raise RuntimeError(f"Windows refused collector setup elevation: {result}")


def build_embedded_server(app, *, port: int) -> uvicorn.Server:
    # smoke와 실제 실행이 같은 설정을 사용해야 검증에서 통과한 경로가 운영에서
    # 달라지는 문제를 막을 수 있다. PyInstaller에서 동적 선택도 피한다.
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        loop="asyncio",
        http="h11",
        lifespan="off",
        log_config=None,
        access_log=False,
        timeout_graceful_shutdown=5,
    )
    return uvicorn.Server(config)


def choose_server_port(configured_port: str | None) -> int:
    """포터블 실행에 사용할 loopback 포트를 결정한다."""

    if configured_port:
        try:
            port = int(configured_port)
        except ValueError as error:
            raise ValueError("WEAVEXDR_PORT must be a number") from error
        if not 1024 <= port <= 65535:
            raise ValueError("WEAVEXDR_PORT must be between 1024 and 65535")
        return port

    # 이전 실행이나 다른 프로그램이 8765를 점유해도 사용자가 프로세스와 토큰을
    # 직접 정리하게 하지 않는다. 운영 기본 포트를 먼저 시도하고 사용 중이면 OS가
    # 배정한 빈 포트로 새 인스턴스를 열어 정확한 자동 인증 URL을 브라우저에 전달한다.
    with socket.socket() as preferred_port_probe:
        try:
            preferred_port_probe.bind(("127.0.0.1", 8765))
            return 8765
        except OSError:
            pass
    with socket.socket() as available_port_probe:
        available_port_probe.bind(("127.0.0.1", 0))
        return int(available_port_probe.getsockname()[1])


def verify_embedded_server(app) -> None:
    """번들 안의 Uvicorn 동적 모듈과 실제 HTTP 응답까지 확인한다."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = build_embedded_server(app, port=port)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    deadline = time.monotonic() + 10
    try:
        while not server.started and server_thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not server.started:
            raise RuntimeError("embedded Uvicorn server did not start")
        with urlopen(f"http://127.0.0.1:{port}/health", timeout=3) as response:
            if response.status != 200 or response.read() != b'{"status":"ok"}':
                raise RuntimeError("embedded server health check failed")
        with urlopen(f"http://127.0.0.1:{port}/dashboard", timeout=3) as response:
            dashboard_body = response.read().decode("utf-8")
            if response.status != 200 or "<title>WeaveXDR</title>" not in dashboard_body:
                raise RuntimeError("embedded dashboard check failed")
    finally:
        server.should_exit = True
        server_thread.join(timeout=5)
    if server_thread.is_alive():
        raise RuntimeError("embedded Uvicorn server did not stop")


def main() -> None:
    data_root = Path(os.environ.get("LOCALAPPDATA", Path.cwd())) / "WeaveXDR"
    data_root.mkdir(parents=True, exist_ok=True)
    logger = configure_rotating_logging(data_root / "logs")
    try:
        harden_data_permissions(data_root)
    except Exception as error:
        # 보호 실패를 숨기지는 않되 기존 로컬 데이터를 잠가 앱 자체를 사용할 수
        # 없게 만드는 것보다 회전 로그에 명확히 남기고 제한 모드로 계속 시작한다.
        logger.warning("data ACL hardening failed: %s", error)
    smoke_test = os.environ.get("WEAVEXDR_SMOKE_TEST") == "1"
    test_instance_name = os.environ.get("WEAVEXDR_TEST_INSTANCE_NAME", "").strip()
    if test_instance_name and not all(character.isalnum() or character in "-_" for character in test_instance_name):
        raise ValueError("WEAVEXDR_TEST_INSTANCE_NAME contains unsupported characters")
    mutex_name = f"Local\\WeaveXDR.Test.{test_instance_name}" if test_instance_name else "Local\\WeaveXDR.SingleInstance"
    instance = InstanceCoordinator(data_root, mutex_name=mutex_name)
    if not smoke_test and not instance.acquire():
        if instance.request_existing_dashboard():
            logger.info("existing desktop instance reopened")
            return
        raise RuntimeError("기존 WeaveXDR 인스턴스가 응답하지 않습니다. 잠시 후 다시 실행하세요.")

    # 실행할 때마다 새 토큰을 만들어 파일이나 실행 인자에 비밀이 남지 않게 한다.
    # URL fragment는 HTTP 요청에 포함되지 않으며 대시보드가 읽은 즉시 주소에서 제거한다.
    configured_token = os.environ.get("WEAVEXDR_API_TOKEN", "").strip()
    # 자동화 검사와 고정 토큰이 필요한 운영 환경에서는 환경 변수만 허용한다.
    # 짧은 값은 추측 공격에 취약하므로 기존 API 정책과 동일하게 32자 이상을 요구한다.
    if configured_token and len(configured_token) < 32:
        raise ValueError("WEAVEXDR_API_TOKEN must contain at least 32 characters")
    api_token = configured_token or secrets.token_urlsafe(32)
    server_port = choose_server_port(os.environ.get("WEAVEXDR_PORT"))
    database_path = data_root / "weavexdr.db"
    storage_manager = DatabaseLifecycleManager(
        database_path,
        backup_root=data_root / "backups",
        archive_root=data_root / "archives",
        retention_days=30,
    )
    runtime_recovery = RuntimeRecoveryManager(data_root, storage_manager)
    # 실행 중 열린 SQLite 파일을 교체하지 않고, 다음 실행에서 DB 연결을 만들기
    # 전에 검증된 복원 후보만 원자적으로 적용한다.
    if not smoke_test and storage_manager.apply_pending_restore():
        logger.warning("verified pending database restore applied before startup")
    recovery_report = runtime_recovery.begin() if not smoke_test else StartupRecoveryReport()
    if recovery_report.unclean_shutdown_detected:
        logger.warning("unclean shutdown recovery: %s", recovery_report.recovery_action)
    store = SQLiteEventStore(database_path)
    dry_run_service = DryRunResponseService()
    approval_service = ApprovalService()
    runtime_monitor = RuntimeHealthMonitor(data_root)
    runtime = ApiRuntime(
        event_store=store,
        dry_run_service=dry_run_service,
        approval_service=approval_service,
        storage_manager=storage_manager,
        runtime_monitor=runtime_monitor,
        recovery_state=asdict(recovery_report),
        scan_path_picker=select_scan_paths,
    )
    response_resources: tuple[ActualResponseService, QuarantineStore, SQLiteAuditLog] | None = None
    # 실제 시스템 변경 기능은 구현되어 있어도 명시적 로컬 설정 없이는 절대 켜지지 않는다.
    # UI의 dry-run과 영향 미리보기는 기본 모드에서도 계속 사용할 수 있다.
    if os.environ.get("WEAVEXDR_ENABLE_ACTIVE_RESPONSE") == "1":
        audit_log = SQLiteAuditLog(data_root / "weavexdr.db")
        quarantine_store = QuarantineStore(data_root / "quarantine", data_root / "weavexdr.db")
        actual_response = ActualResponseService(
            dry_run_service,
            approval_service,
            audit_log,
            quarantine_store,
            recovery_registry=RecoveryRegistry(data_root / "weavexdr.db"),
        )
        runtime.actual_response_service = actual_response
        runtime.playbook_service = ResponsePlaybookService(actual_response)
        response_resources = (actual_response, quarantine_store, audit_log)
    runtime.threat_intel_store = ThreatIntelStore(data_root / "threat-intel.db")
    runtime.content_manager = ContentUpdateManager(data_root / "content")
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        yara_rules_path = Path(sys._MEIPASS) / "xdr_graph" / "rules" / "file_scan.yar"
    else:
        yara_rules_path = Path(__file__).parents[2] / "rules" / "file_scan.yar"
    # 수동·실시간 검사가 동일한 해시 캐시와 정책을 사용해 결과 불일치를 만들지 않게 한다.
    file_scanner = AdvancedFileScanner(
        FileInspectionEngine(YaraScanner([yara_rules_path])),
        cache=InspectionCache(data_root / "file-cache.db"),
    )
    def publish_scan_finding(result) -> None:
        findings = [Finding.model_validate(value) for value in result.findings]
        if not findings:
            return
        event = FileCreateEvent(
            event_id=f"manual-scan-{result.sha256[:16]}", event_type="file_create",
            timestamp=datetime.now(UTC), host_id=os.environ.get("COMPUTERNAME", "local-host"),
            source="windows_event_log", file_path=result.path,
        )
        risk = max(finding.severity for finding in findings)
        report = IncidentReport(
            incident_id=f"antivirus-{result.sha256[:24]}",
            verdict="suspicious" if risk >= 70 else "needs_review", risk_score=risk,
            evidence=[finding.reason for finding in findings],
            recommended_actions=["quarantine_file"],
            validation=ValidationResult(passed=True, errors=[], review_count=0),
            findings=findings, source_events=[event],
        )
        store.save_manual_incident(report)
        runtime.event_broker.publish(report)

    runtime.scan_manager = ScanJobManager(file_scanner, on_result=publish_scan_finding)
    instance_token = secrets.token_urlsafe(32)
    runtime.instance_token = instance_token
    runtime.instance_port = server_port
    app = create_app(runtime, api_token=api_token)
    if smoke_test:
        # EXE에서 누락되기 쉬운 Uvicorn 동적 import와 실제 HTTP 응답까지 검증한다.
        load_default_detection_engine()
        load_default_allowlist_engine()
        load_default_risk_policy()
        verify_embedded_server(app)
        runtime.scan_manager.close()
        if response_resources:
            response_resources[0].close()
            response_resources[1].close()
            response_resources[2].close()
        store.close()
        logger.info("desktop runtime smoke test passed")
        return
    dashboard_url = f"http://127.0.0.1:{server_port}/dashboard#{urlencode({'token': api_token})}"
    open_dashboard = lambda: webbrowser.open(dashboard_url)
    runtime.open_dashboard_callback = open_dashboard
    instance.publish(InstanceRecord(os.getpid(), server_port, APP_VERSION, instance_token, "starting"))
    if os.environ.get("WEAVEXDR_NO_BROWSER") != "1":
        threading.Timer(1.0, open_dashboard).start()
    logger.info("desktop runtime started")
    server = build_embedded_server(app, port=server_port)
    shutdown_completed = threading.Event()

    def request_shutdown() -> None:
        server.should_exit = True

        # 정상 종료가 스트림·Windows 이벤트 API·번들 런타임 문제로 멈추더라도
        # 사용자가 명시적으로 종료한 EXE가 무기한 남지 않게 최종 안전망을 둔다.
        # 정상 경로는 DB와 수집기를 먼저 닫고 아래 이벤트를 설정하므로 강제 종료는
        # 제한 시간 안에 정리되지 않은 비정상 상황에서만 실행된다.
        def enforce_shutdown_deadline() -> None:
            if not shutdown_completed.wait(FORCED_SHUTDOWN_TIMEOUT_SECONDS):
                logger.error("graceful shutdown timed out; terminating desktop runtime")
                os._exit(0)

        threading.Thread(
            target=enforce_shutdown_deadline,
            name="weavexdr-shutdown-watchdog",
            daemon=True,
        ).start()

    runtime.shutdown_callback = request_shutdown
    runtime.collector_setup_callback = request_collector_access_setup
    ingestion_service = PersistentIngestionService(
        store,
        event_publisher=runtime.event_broker,
    )
    watcher_stop = threading.Event()
    watcher_thread: threading.Thread | None = None
    watch_roots = default_watch_directories() + removable_watch_directories()
    if watch_roots:
        watcher = DirectoryFileWatcher(file_scanner.engine, watch_roots, recursive=False)

        def publish_watched_file(result) -> None:
            batch = NormalizedEventBatch(
                batch_id=f"realtime-{result.event.event_id}",
                incident_id=f"realtime-file-{Path(result.event.file_path).name.lower()}",
                collector_id="realtime-file-watcher",
                received_at=datetime.now(UTC),
                events=[result.event],
            )
            ingestion_service.submit(batch)

        def run_file_watcher() -> None:
            # 저전력 모드에서는 파일 시스템 폴링만 늦추고 보안 이벤트 로그 수집은
            # 유지해 탐지 공백 없이 배터리·게임 부하를 줄인다.
            watcher.watch(
                watcher_stop,
                publish_watched_file,
                interval_provider=runtime_monitor.watcher_poll_interval,
            )

        watcher_thread = threading.Thread(
            target=run_file_watcher,
            name="weavexdr-file-watcher",
            daemon=True,
        )
        watcher_thread.start()

    collector_sources: dict[str, dict[str, object]] = {}

    def update_collector_status(status: dict[str, object]) -> None:
        # API 요청과 수집 스레드가 같은 상태 객체를 동시에 읽고 쓰지 않도록
        # 런타임 잠금 아래에서 완성된 상태 사전으로 교체한다.
        source_name = str(status.get("source") or "unknown")
        collector_sources[source_name] = status
        with runtime.lock:
            healthy = [name for name, value in collector_sources.items() if value.get("state") in {"starting", "running", "paused"}]
            runtime.collector_status = {
                "state": "paused" if healthy and all(value.get("state") == "paused" for value in collector_sources.values()) else "running" if healthy else "error",
                "label": f"보안 수집 소스 {len(healthy)}개 연결",
                "sources": healthy,
                "source_health": {name: dict(value) for name, value in collector_sources.items()},
                "processed_events": sum(int(value.get("processed_events", 0)) for value in collector_sources.values()),
            }

    collector = SysmonCollector(
        ingestion_service,
        status_callback=update_collector_status,
        logger=logger,
    )
    windows_collector = WindowsTelemetryCollector(
        ingestion_service,
        status_callback=update_collector_status,
        logger=logger,
    )
    def toggle_collection() -> bool:
        paused = not collector.paused
        collector.pause() if paused else collector.resume()
        windows_collector.pause() if paused else windows_collector.resume()
        runtime.lifecycle_state = "paused" if paused else "protecting"
        tray.update_status("일시정지" if paused else "보호 중")
        return paused

    tray = WindowsTray(
        open_dashboard=open_dashboard,
        toggle_collection=toggle_collection,
        shutdown=request_shutdown,
    )

    def control_collection(paused: bool) -> None:
        collector.pause() if paused else collector.resume()
        windows_collector.pause() if paused else windows_collector.resume()
        runtime.lifecycle_state = "paused" if paused else "protecting"
        tray.update_status("일시정지" if paused else "보호 중")

    runtime.collector_pause_callback = control_collection
    response_expiry_stop = threading.Event()
    response_expiry_thread: threading.Thread | None = None
    if runtime.actual_response_service:
        def expire_response_blocks() -> None:
            # 만료 해제는 외부 연결 없이 로컬 방화벽과 복구 레지스트리만 사용한다.
            while not response_expiry_stop.wait(30):
                try:
                    runtime.actual_response_service.expire_network_blocks()
                except Exception as error:
                    logger.warning("network block expiry failed: %s", error)

        response_expiry_thread = threading.Thread(
            target=expire_response_blocks,
            name="weavexdr-response-expiry",
            daemon=True,
        )
        response_expiry_thread.start()
    collector.start()
    windows_collector.start()
    runtime.lifecycle_state = "protecting"
    instance.publish(InstanceRecord(os.getpid(), server_port, APP_VERSION, instance_token, "protecting"))
    tray.start()
    tray.update_status("보호 중")
    try:
        server.run()
    finally:
        runtime.lifecycle_state = "stopping"
        tray.update_status("종료 중")
        tray.stop()
        if not collector.stop():
            logger.warning("Sysmon collector did not stop within the shutdown timeout")
        if not windows_collector.stop():
            logger.warning("Windows extended collector did not stop within the shutdown timeout")
        watcher_stop.set()
        if watcher_thread:
            watcher_thread.join(timeout=5)
        response_expiry_stop.set()
        if response_expiry_thread:
            response_expiry_thread.join(timeout=5)
        runtime.scan_manager.close()
        # 종료 버튼과 예외 종료 모두 DB 핸들을 닫아 업데이트·백업 시 파일 잠금이 남지 않게 한다.
        if response_resources:
            response_resources[0].close()
            response_resources[1].close()
            response_resources[2].close()
        store.close()
        runtime_recovery.complete()
        logger.info("desktop runtime stopped")
        shutdown_completed.set()
        instance.clear()


if __name__ == "__main__":
    main()
