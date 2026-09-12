"""실제 공격 없이 WeaveXDR 조사 화면을 검증하는 합성 이벤트 파일.

이 모듈은 프로세스 실행, 파일 생성, 외부 유입, 인증 실패와 지속성 등록을
데이터로만 표현한다. 프로세스를 띄우거나 파일·레지스트리·네트워크를 변경하지 않는다.
문서용 TEST-NET 주소와 존재하지 않는 전용 경로를 써 실제 대상과도 분리한다.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from xdr_graph.ingestion import NormalizedEventBatch


def build_safe_attack_simulation(
    *, now: datetime | None = None, simulation_key: str | None = None
) -> NormalizedEventBatch:
    """공격처럼 보이는 연쇄를 정규화 이벤트로만 반환한다."""
    started_at = now or datetime.now(UTC)
    if started_at.tzinfo is None or started_at.utcoffset() is None:
        raise ValueError("safe simulation time must include a timezone offset")
    key = simulation_key or uuid4().hex[:12]
    process_start = (started_at + timedelta(seconds=2)).isoformat()
    base = {
        "host_id": "local-safe-simulation-host",
        "source": "sample",
    }
    return NormalizedEventBatch.model_validate({
        "schema_version": "1.0",
        "batch_id": f"safe-simulation-batch-{key}",
        "incident_id": f"demo-incident-{key}",
        "collector_id": "weavexdr-safe-simulation",
        "received_at": (started_at + timedelta(seconds=8)).isoformat(),
        "events": [
            {
                **base, "event_id": f"safe-auth-{key}", "event_type": "authentication",
                "timestamp": started_at.isoformat(), "windows_event_id": 4625,
                "channel": "Security", "action": "logon_failed", "user": "SAFE_SIMULATION\\analyst",
                "source_ip": "203.0.113.77", "outcome": "failure",
                "details": {"safety": "synthetic event only"},
            },
            {
                **base, "event_id": f"safe-network-{key}", "event_type": "network_connect",
                "timestamp": (started_at + timedelta(seconds=1)).isoformat(),
                "process_name": "powershell.exe", "process_id": 4242,
                "process_start_time": process_start, "source_ip": "203.0.113.77",
                "source_port": 49152, "destination_ip": "192.0.2.10", "destination_port": 445,
                "initiated": False, "protocol": "tcp",
            },
            {
                **base, "event_id": f"safe-process-{key}", "event_type": "process_start",
                "timestamp": process_start, "process_name": "powershell.exe", "process_id": 4242,
                "process_start_time": process_start, "parent_process": "WINWORD.EXE",
                # 탐지 규칙은 인코딩 실행 형태를 보지만 이 문자열은 실행되지 않고
                # 정규화 이벤트 필드에만 들어간다.
                "command_line": "powershell.exe -NoProfile -enc SAFE_SIMULATION_ONLY",
                "image_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            },
            {
                **base, "event_id": f"safe-file-{key}", "event_type": "file_create",
                "timestamp": (started_at + timedelta(seconds=4)).isoformat(),
                "process_name": "powershell.exe", "process_id": 4242,
                "process_start_time": process_start,
                "file_path": r"C:\Users\SafeSimulation\AppData\Local\Temp\harmless-update.exe",
            },
            {
                **base, "event_id": f"safe-persistence-{key}", "event_type": "registry_persistence",
                "timestamp": (started_at + timedelta(seconds=6)).isoformat(),
                "windows_event_id": 13, "channel": "Synthetic", "action": "would_set_run_key",
                "process_name": "powershell.exe", "process_id": 4242,
                "target": r"HKCU\Software\WeaveXDR\SafeSimulation\Run",
                "details": {"safety": "registry was not accessed"},
            },
        ],
    })
