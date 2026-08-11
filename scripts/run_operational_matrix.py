from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Record repeatable soak/resume/session validation evidence.")
    parser.add_argument("--duration-seconds", type=int, default=60)
    parser.add_argument("--sample-seconds", type=float, default=1)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pid", type=int, default=os.getpid(), help="Process whose working set is sampled.")
    args = parser.parse_args()
    if args.duration_seconds < 1 or args.sample_seconds <= 0:
        raise SystemExit("durations must be positive")
    tracemalloc.start()
    started = time.monotonic(); samples: list[dict[str, object]] = []
    while time.monotonic() - started < args.duration_seconds:
        current, peak = tracemalloc.get_traced_memory()
        samples.append({"elapsed_seconds": round(time.monotonic()-started, 3), "python_bytes": current, "python_peak_bytes": peak, "working_set_bytes": working_set_bytes(args.pid)})
        time.sleep(min(args.sample_seconds, max(.01, args.duration_seconds-(time.monotonic()-started))))
    current, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    payload = {"generated_at": datetime.now(UTC).isoformat(), "platform": platform.platform(), "pid": args.pid, "duration_seconds": round(time.monotonic()-started, 3), "samples": samples, "final_bytes": current, "peak_bytes": peak, "status": "completed"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
