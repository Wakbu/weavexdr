from __future__ import annotations

import json
import time

from xdr_graph.storage import SQLiteEventStore


INCIDENT_COUNT = 100_000


def main() -> None:
    """Validate that a 100k incident queue stays server-paged and bounded."""
    with SQLiteEventStore(":memory:") as store:
        report = json.dumps(
            {
                "incident_id": "placeholder",
                "verdict": "needs_review",
                "risk_score": 50,
                "evidence": [],
                "recommended_actions": [],
                "validation": {"passed": True, "errors": [], "review_count": 0},
                "findings": [], "suppressed_findings": [], "attack_chains": [], "source_events": [],
            }
        )
        rows = [
            (f"perf-{index:06d}", "benchmark", "needs_review", 50, report.replace("placeholder", f"perf-{index:06d}"), f"2026-08-09T00:{index % 60:02d}:00+00:00")
            for index in range(INCIDENT_COUNT)
        ]
        with store._lock, store._connection:  # Benchmark fixture bypasses the analysis graph intentionally.
            store._connection.executemany(
                "INSERT INTO incidents(incident_id,last_batch_id,verdict,risk_score,report_json,updated_at) VALUES (?,?,?,?,?,?)",
                rows,
            )
        started = time.perf_counter()
        page = store.list_incident_views(limit=100, offset=99_900, sort="updated_desc")
        elapsed = time.perf_counter() - started
        if len(page) != 100 or elapsed > 2.0:
            raise SystemExit(f"pagination benchmark failed: rows={len(page)} elapsed={elapsed:.3f}s")
        print(f"100k incident pagination: {elapsed:.3f}s, bounded rows={len(page)}")


if __name__ == "__main__":
    main()
