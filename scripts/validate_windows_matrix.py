from __future__ import annotations

import argparse
import json
from pathlib import Path


SCENARIOS = ("sleep-resume", "user-switch")


def windows_family(payload: dict[str, object]) -> str | None:
    source = " ".join(
        str(payload.get(key, "")) for key in ("platform", "windows_release", "windows_version", "windows_edition")
    ).casefold()
    if "windows 10" in source or "windows-10" in source:
        return "windows-10"
    if "windows 11" in source or "windows-11" in source:
        return "windows-11"
    return None


def validate_matrix(root: Path) -> dict[str, object]:
    evidence: list[tuple[Path, dict[str, object]]] = []
    for path in sorted(root.rglob("*.json")) if root.exists() else []:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("status") == "passed":
            evidence.append((path, payload))

    systems: dict[str, dict[str, bool]] = {}
    for family in ("windows-10", "windows-11"):
        matching = [payload for _, payload in evidence if windows_family(payload) == family]
        systems[family] = {
            "24h": any(float(item.get("duration_seconds", 0)) >= 86_400 for item in matching),
            "7d": any(float(item.get("duration_seconds", 0)) >= 604_800 for item in matching),
            **{scenario: any(item.get("scenario") == scenario for item in matching) for scenario in SCENARIOS},
        }
    missing = [f"{family}:{name}" for family, checks in systems.items() for name, passed in checks.items() if not passed]
    return {
        "status": "passed" if not missing else "incomplete",
        "evidence_files": len(evidence),
        "systems": systems,
        "missing": missing,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate the required Windows 10/11 operational evidence matrix.")
    parser.add_argument("evidence_root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate_matrix(args.evidence_root)
    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded)
    raise SystemExit(0 if report["status"] == "passed" else 2)


if __name__ == "__main__":
    main()
