from __future__ import annotations

import argparse
import tempfile
import time
from pathlib import Path

from xdr_graph.antivirus import AdvancedFileScanner, InspectionCache, ScanJobManager
from xdr_graph.file_scanner import DefenderResult, FileInspectionEngine, YaraScanner


class BenchmarkDefender:
    """The benchmark measures per-file work; production Defender runs once per root."""

    def scan(self, _target_path: Path, *, timeout: float) -> DefenderResult:
        return DefenderResult(scanned=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the optimized quick-scan per-file pipeline")
    parser.add_argument("--files", type=int, default=7_000)
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()
    project_root = Path(__file__).parents[1]
    with tempfile.TemporaryDirectory(prefix="weavexdr-quick-benchmark-") as temporary:
        root = Path(temporary)
        for index in range(args.files):
            (root / f"sample-{index:05d}.ps1").write_text("Write-Output 'safe'", encoding="utf-8")
        engine = FileInspectionEngine(
            YaraScanner([project_root / "rules" / "file_scan.yar"]),
            defender_scanner=BenchmarkDefender(),
        )
        manager = ScanJobManager(
            AdvancedFileScanner(engine, cache=InspectionCache(root.parent / f"{root.name}-cache.db"))
        )
        started = time.monotonic()
        job = manager.start([str(root)], profile="quick")
        while time.monotonic() - started < args.timeout:
            job = manager.get(job.job_id)
            if job.state in {"completed", "failed", "cancelled"}:
                break
            time.sleep(.05)
        elapsed = time.monotonic() - started
        manager.close()
        if job.state != "completed" or job.scanned_files != args.files:
            raise SystemExit(f"quick scan benchmark failed: state={job.state} scanned={job.scanned_files}/{args.files}")
        print(f"files={args.files} elapsed={elapsed:.3f}s rate={args.files / elapsed:.2f}/s")


if __name__ == "__main__":
    main()
