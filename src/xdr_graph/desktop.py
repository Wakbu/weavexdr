from __future__ import annotations

import os
import secrets
import socket
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
from xdr_graph.storage import SQLiteEventStore


def verify_embedded_server(app) -> None:
    """번들 안의 Uvicorn 동적 모듈과 실제 HTTP 응답까지 확인한다."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
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
    server = uvicorn.Server(config)
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
    api_token = secrets.token_urlsafe(32)
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
    dashboard_url = f"http://127.0.0.1:8765/dashboard#{urlencode({'token': api_token})}"
    threading.Timer(1.0, lambda: webbrowser.open(dashboard_url)).start()
    logger.info("desktop runtime started")
    uvicorn.run(app, host="127.0.0.1", port=8765, log_config=None)


if __name__ == "__main__":
    main()
