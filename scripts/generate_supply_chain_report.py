from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from datetime import UTC, datetime
from pathlib import Path


def package_record(distribution: importlib.metadata.Distribution) -> dict[str, object]:
    metadata = distribution.metadata
    name = metadata.get("Name") or "unknown"
    license_name = metadata.get("License") or next(
        (item.removeprefix("License :: ") for item in metadata.get_all("Classifier", []) if item.startswith("License :: ")), "UNKNOWN"
    )
    return {"name": name, "version": distribution.version, "licenses": [{"license": {"name": license_name}}]}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a deterministic WeaveXDR SBOM and release hash inventory.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--asset", type=Path, action="append", default=[])
    arguments = parser.parse_args()
    packages = sorted((package_record(item) for item in importlib.metadata.distributions()), key=lambda item: (str(item["name"]).casefold(), str(item["version"])))
    payload = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"timestamp": datetime.now(UTC).isoformat(), "component": {"type": "application", "name": "WeaveXDR"}},
        "components": [{"type": "library", **item} for item in packages],
        "properties": [{"name": "weavexdr:asset", "value": f"{path.name}:{sha256(path)}"} for path in arguments.asset if path.is_file()],
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
