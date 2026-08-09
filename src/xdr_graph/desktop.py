from __future__ import annotations

import os
import secrets
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path
from urllib.request import urlopen
from urllib.parse import urlencode

import uvicorn

from xdr_graph.api import ApiRuntime, create_app
from xdr_graph.allowlist import load_default_allowlist_engine
from xdr_graph.detection import load_default_detection_engine
from xdr_graph.logging_setup import configure_rotating_logging
from xdr_graph.response import ApprovalService, DryRunResponseService
from xdr_graph.risk_policy import load_default_risk_policy
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore
from xdr_graph.sysmon_collector import SysmonCollector


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

    # 실행할 때마다 새 토큰을 만들어 파일이나 실행 인자에 비밀이 남지 않게 한다.
    # URL fragment는 HTTP 요청에 포함되지 않으며 대시보드가 읽은 즉시 주소에서 제거한다.
    configured_token = os.environ.get("WEAVEXDR_API_TOKEN", "").strip()
    # 자동화 검사와 고정 토큰이 필요한 운영 환경에서는 환경 변수만 허용한다.
    # 짧은 값은 추측 공격에 취약하므로 기존 API 정책과 동일하게 32자 이상을 요구한다.
    if configured_token and len(configured_token) < 32:
        raise ValueError("WEAVEXDR_API_TOKEN must contain at least 32 characters")
    api_token = configured_token or secrets.token_urlsafe(32)
    server_port = choose_server_port(os.environ.get("WEAVEXDR_PORT"))
    store = SQLiteEventStore(data_root / "weavexdr.db")
    runtime = ApiRuntime(
        event_store=store,
        dry_run_service=DryRunResponseService(),
        approval_service=ApprovalService(),
    )
    app = create_app(runtime, api_token=api_token)
    if os.environ.get("WEAVEXDR_SMOKE_TEST") == "1":
        # EXE에서 누락되기 쉬운 Uvicorn 동적 import와 실제 HTTP 응답까지 검증한다.
        load_default_detection_engine()
        load_default_allowlist_engine()
        load_default_risk_policy()
        verify_embedded_server(app)
        store.close()
        logger.info("desktop runtime smoke test passed")
        return
    dashboard_url = f"http://127.0.0.1:{server_port}/dashboard#{urlencode({'token': api_token})}"
    if os.environ.get("WEAVEXDR_NO_BROWSER") != "1":
        threading.Timer(1.0, lambda: webbrowser.open(dashboard_url)).start()
    logger.info("desktop runtime started")
    server = build_embedded_server(app, port=server_port)
    runtime.shutdown_callback = lambda: setattr(server, "should_exit", True)
    runtime.collector_setup_callback = request_collector_access_setup
    ingestion_service = PersistentIngestionService(
        store,
        event_publisher=runtime.event_broker,
    )

    def update_collector_status(status: dict[str, object]) -> None:
        # API 요청과 수집 스레드가 같은 상태 객체를 동시에 읽고 쓰지 않도록
        # 런타임 잠금 아래에서 완성된 상태 사전으로 교체한다.
        with runtime.lock:
            runtime.collector_status = status

    collector = SysmonCollector(
        ingestion_service,
        status_callback=update_collector_status,
        logger=logger,
    )
    collector.start()
    try:
        server.run()
    finally:
        if not collector.stop():
            logger.warning("Sysmon collector did not stop within the shutdown timeout")
        # 종료 버튼과 예외 종료 모두 DB 핸들을 닫아 업데이트·백업 시 파일 잠금이 남지 않게 한다.
        store.close()
        logger.info("desktop runtime stopped")


if __name__ == "__main__":
    main()
