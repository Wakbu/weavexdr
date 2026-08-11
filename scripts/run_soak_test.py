from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path

from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore
from xdr_graph.storage_maintenance import DatabaseLifecycleManager


def main() -> int:
    parser = argparse.ArgumentParser(description="Repeat local ingestion for stability checks.")
    parser.add_argument("--duration-seconds", type=int, default=60)
    parser.add_argument("--max-iterations", type=int, default=0)
    args = parser.parse_args()
    sample_path = Path(__file__).parents[1] / "samples" / "suspicious_office_batch.json"
    batch = NormalizedEventBatch.model_validate(json.loads(sample_path.read_text(encoding="utf-8")))
    deadline = time.monotonic() + max(1, args.duration_seconds)
    iterations = 0
    with tempfile.TemporaryDirectory(prefix="weavexdr-soak-") as temporary:
        database = Path(temporary) / "soak.db"
        store = SQLiteEventStore(database)
        try:
            service = PersistentIngestionService(store)
            while time.monotonic() < deadline and (not args.max_iterations or iterations < args.max_iterations):
                # 같은 이벤트를 반복 입력해 중복 억제와 DB 수명 주기를 함께 압박한다.
                service.submit(batch)
                iterations += 1
            if not DatabaseLifecycleManager(database, backup_root=Path(temporary) / "backups").live_integrity_ok():
                raise RuntimeError("soak database integrity check failed")
        finally:
            store.close()
    print(f"soak passed: {iterations} iterations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
