from __future__ import annotations

import os
import secrets
import threading
import webbrowser
from pathlib import Path
from urllib.parse import urlencode

import uvicorn

from xdr_graph.api import ApiRuntime, create_app
from xdr_graph.allowlist import load_default_allowlist_engine
from xdr_graph.detection import load_default_detection_engine
from xdr_graph.logging_setup import configure_rotating_logging
from xdr_graph.response import ApprovalService, DryRunResponseService
from xdr_graph.risk_policy import load_default_risk_policy
from xdr_graph.storage import SQLiteEventStore


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
        # 패키지 검증 모드는 서버를 열지 않고 번들 정책과 DB 초기화까지만 확인한다.
        load_default_detection_engine()
        load_default_allowlist_engine()
        load_default_risk_policy()
        store.close()
        logger.info("desktop runtime smoke test passed")
        return
    dashboard_url = f"http://127.0.0.1:8765/dashboard#{urlencode({'token': api_token})}"
    threading.Timer(1.0, lambda: webbrowser.open(dashboard_url)).start()
    logger.info("desktop runtime started")
    uvicorn.run(app, host="127.0.0.1", port=8765, log_config=None)


if __name__ == "__main__":
    main()
