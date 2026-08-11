from __future__ import annotations

import ctypes
import os
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock

from pydantic import BaseModel


class RuntimeHealth(BaseModel):
    cpu_percent: float
    memory_bytes: int
    disk_free_bytes: int
    uptime_seconds: int
    collector_delay_seconds: float | None = None
    power_mode: str = "balanced"
    on_battery: bool | None = None
    battery_percent: int | None = None
    suspected_resume_count: int = 0
    last_resume_at: datetime | None = None


class RuntimeHealthMonitor:
    """Collect lightweight process and disk health without another runtime dependency."""

    def __init__(self, data_root: str | Path) -> None:
        self.data_root = Path(data_root)
        self._started = time.monotonic()
        self._last_wall = self._started
        self._last_cpu = time.process_time()
        self._last_sample = self._started
        self._resume_count = 0
        self._last_resume_at: datetime | None = None
        self._lock = RLock()

    @staticmethod
    def power_state() -> tuple[str, bool | None, int | None]:
        if os.name != "nt":
            return "balanced", None, None

        class SystemPowerStatus(ctypes.Structure):
            _fields_ = [
                ("ACLineStatus", ctypes.c_byte), ("BatteryFlag", ctypes.c_byte),
                ("BatteryLifePercent", ctypes.c_byte), ("SystemStatusFlag", ctypes.c_byte),
                ("BatteryLifeTime", ctypes.c_ulong), ("BatteryFullLifeTime", ctypes.c_ulong),
            ]

        status = SystemPowerStatus()
        if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
            return "balanced", None, None
        on_battery = status.ACLineStatus == 0
        percent = int(status.BatteryLifePercent) if 0 <= status.BatteryLifePercent <= 100 else None
        low_power = on_battery and percent is not None and percent <= 30
        return "low_power" if low_power else "balanced", on_battery, percent

    def watcher_poll_interval(self) -> float:
        return 8.0 if self.power_state()[0] == "low_power" else 2.0

    @staticmethod
    def _memory_bytes() -> int:
        if os.name == "nt":
            class ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return int(counters.WorkingSetSize)
        try:
            import resource
            usage = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
            return usage if os.uname().sysname == "Darwin" else usage * 1024
        except (ImportError, AttributeError):
            return 0

    def sample(self, *, collector_delay_seconds: float | None = None) -> RuntimeHealth:
        with self._lock:
            now = time.monotonic()
            cpu_now = time.process_time()
            elapsed = max(.001, now - self._last_wall)
            cpu_delta = max(0.0, cpu_now - self._last_cpu)
            cpu_percent = min(100.0, cpu_delta / elapsed / max(1, os.cpu_count() or 1) * 100)
            if now - self._last_sample > 120:
                self._resume_count += 1
                self._last_resume_at = datetime.now(UTC)
            self._last_sample = now
            self._last_wall, self._last_cpu = now, cpu_now
        power_mode, on_battery, battery_percent = self.power_state()
        return RuntimeHealth(
            cpu_percent=round(cpu_percent, 2),
            memory_bytes=self._memory_bytes(),
            disk_free_bytes=shutil.disk_usage(self.data_root).free,
            uptime_seconds=int(now - self._started),
            collector_delay_seconds=collector_delay_seconds,
            power_mode=power_mode,
            on_battery=on_battery,
            battery_percent=battery_percent,
            suspected_resume_count=self._resume_count,
            last_resume_at=self._last_resume_at,
        )
