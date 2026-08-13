from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import socket
import time
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path


def working_set_bytes(pid: int) -> int | None:
    if platform.system() != "Windows":
        return None
    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong), ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
    handle = ctypes.windll.kernel32.OpenProcess(0x1000 | 0x0010, False, pid)
    if not handle:
        return None
    try:
        counters = Counters(); counters.cb = ctypes.sizeof(counters)
        return int(counters.WorkingSetSize) if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb) else None
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def process_alive(pid: int) -> bool:
    if platform.system() != "Windows":
        return pid == os.getpid() or Path(f"/proc/{pid}").exists()
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    ctypes.windll.kernel32.CloseHandle(handle)
    return True


def power_status() -> dict[str, object]:
    if platform.system() != "Windows":
        return {"ac": None, "battery_percent": None}
    class Status(ctypes.Structure):
        _fields_ = [("ac", ctypes.c_ubyte), ("battery_flag", ctypes.c_ubyte), ("battery_percent", ctypes.c_ubyte), ("reserved", ctypes.c_ubyte), ("lifetime", ctypes.c_ulong), ("full_lifetime", ctypes.c_ulong)]
    status = Status()
    if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
        return {"ac": None, "battery_percent": None}
    return {"ac": status.ac == 1, "battery_percent": None if status.battery_percent == 255 else int(status.battery_percent)}


def memory_growth_per_hour(samples: list[dict[str, object]]) -> float | None:
    usable = [sample for sample in samples if isinstance(sample.get("working_set_bytes"), int)]
    if len(usable) < 2:
        return None
    elapsed = float(usable[-1]["elapsed_seconds"]) - float(usable[0]["elapsed_seconds"])
    if elapsed <= 0:
        return 0.0
    return round((int(usable[-1]["working_set_bytes"]) - int(usable[0]["working_set_bytes"])) * 3600 / elapsed, 2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Record repeatable soak/resume/session validation evidence.")
    parser.add_argument("--duration-seconds", type=int, default=60)
    parser.add_argument("--sample-seconds", type=float, default=1)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pid", type=int, default=os.getpid(), help="Process whose working set is sampled.")
    parser.add_argument("--scenario", choices=("baseline", "sleep-resume", "user-switch", "network-change", "install-update-remove"), default="baseline")
    parser.add_argument("--max-growth-mib-per-hour", type=float, default=128, help="Fail evidence when working-set growth exceeds this rate.")
    args = parser.parse_args()
    if args.duration_seconds < 1 or args.sample_seconds <= 0:
        raise SystemExit("durations must be positive")
    tracemalloc.start()
    started = time.monotonic(); previous_wall = time.time(); previous_monotonic = started; samples: list[dict[str, object]] = []; discontinuities: list[dict[str, float]] = []
    while time.monotonic() - started < args.duration_seconds:
        current, peak = tracemalloc.get_traced_memory()
        now_wall, now_monotonic = time.time(), time.monotonic(); gap=abs((now_wall-previous_wall)-(now_monotonic-previous_monotonic))
        if gap > 2: discontinuities.append({"elapsed_seconds":round(now_monotonic-started,3),"clock_gap_seconds":round(gap,3)})
        samples.append({"elapsed_seconds": round(now_monotonic-started, 3), "python_bytes": current, "python_peak_bytes": peak, "working_set_bytes": working_set_bytes(args.pid), "process_alive": process_alive(args.pid), "power": power_status()})
        previous_wall,previous_monotonic=now_wall,now_monotonic
        time.sleep(min(args.sample_seconds, max(.01, args.duration_seconds-(time.monotonic()-started))))
    current, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    # 시작 시 변동을 시간당 값으로 환산하면 과대평가되므로 장기 판정은 1분 이상 증적에만 적용한다.
    growth=memory_growth_per_hour(samples);growth_gate_applied=args.duration_seconds>=60
    passed=all(bool(sample["process_alive"]) for sample in samples) and (not growth_gate_applied or growth is None or growth <= args.max_growth_mib_per_hour*1024*1024)
    payload = {"generated_at": datetime.now(UTC).isoformat(), "platform": platform.platform(), "windows_release": platform.release(), "windows_version": platform.version(), "hostname": socket.gethostname(), "user_session": {"username": os.environ.get("USERNAME") or os.environ.get("USER"), "session_name": os.environ.get("SESSIONNAME")}, "scenario": args.scenario, "pid": args.pid, "duration_seconds": round(time.monotonic()-started, 3), "samples": samples, "clock_discontinuities": discontinuities, "memory_growth_bytes_per_hour": growth, "growth_limit_mib_per_hour": args.max_growth_mib_per_hour, "growth_gate_applied": growth_gate_applied, "final_bytes": current, "peak_bytes": peak, "status": "passed" if passed else "failed"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    raise SystemExit(0 if passed else 2)


if __name__ == "__main__":
    main()
