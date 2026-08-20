from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path


def _static_path(file_name: str) -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        # one-file EXE에서는 정적 파일이 임시 번들 루트에 풀리므로 소스
        # 경로가 아닌 PyInstaller가 제공한 신뢰 가능한 루트만 사용한다.
        return Path(sys._MEIPASS) / "xdr_graph" / "static" / file_name
    return Path(__file__).parent / "static" / file_name


# 정적 자원은 실행 중 바뀌지 않는다. 앱 검증과 서버 생성이 반복되어도 큰
# 대시보드 HTML과 지도를 디스크에서 다시 읽지 않도록 프로세스당 한 번 캐시한다.
@lru_cache(maxsize=1)
def load_dashboard_html() -> str:
    return _static_path("dashboard.html").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def load_world_map_svg() -> str:
    return _static_path("world-map.svg").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def load_brand_icon_svg() -> str:
    return _static_path("weavexdr.svg").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def load_brand_icon_ico() -> bytes:
    return _static_path("weavexdr.ico").read_bytes()
