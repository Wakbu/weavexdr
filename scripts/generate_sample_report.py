from __future__ import annotations

import json
from pathlib import Path

from xdr_graph.ingestion import NormalizedEventBatch
from xdr_graph.reporting import IncidentReportExporter
from xdr_graph.storage import PersistentIngestionService, SQLiteEventStore


def main() -> int:
    root = Path(__file__).parents[1]
    sample = json.loads((root / "samples" / "suspicious_office_batch.json").read_text(encoding="utf-8"))
    store = SQLiteEventStore(":memory:")
    try:
        report = PersistentIngestionService(store).submit(NormalizedEventBatch.model_validate(sample)).report
        artifact = IncidentReportExporter(root / "output" / "pdf").export(report, {"status": "new"}, "pdf")
        print(artifact.path)
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
