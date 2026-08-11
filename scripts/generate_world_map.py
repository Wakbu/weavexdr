from __future__ import annotations

import argparse
import json
from pathlib import Path


def iter_polygons(geometry: dict[str, object]):
    coordinates = geometry["coordinates"]
    if geometry["type"] == "Polygon":
        yield coordinates
    elif geometry["type"] == "MultiPolygon":
        yield from coordinates


def ring_path(ring: list[list[float]]) -> str:
    points = [f"{longitude + 180:.1f},{90 - latitude:.1f}" for longitude, latitude in ring]
    return "M" + "L".join(points) + "Z"


def build_svg(source: Path) -> str:
    collection = json.loads(source.read_text(encoding="utf-8"))
    paths: list[str] = []
    for feature in collection["features"]:
        properties = feature.get("properties", {})
        iso_code = str(properties.get("ISO_A3") or properties.get("ADM0_A3") or "").lower()
        if iso_code == "ata":
            # 작은 운영 패널에서는 남극이 화면을 차지하므로 제외한다.
            continue
        path_data = "".join(
            ring_path(ring)
            for polygon in iter_polygons(feature["geometry"])
            for ring in polygon
        )
        paths.append(f'<path class="country country-{iso_code}" d="{path_data}"/>')

    return "\n".join(
        [
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 360 180" role="presentation">',
            "<!-- Natural Earth 1:110m Admin 0 countries, public domain. -->",
            "<style>",
            ".country{fill:#242c33;stroke:#46525d;stroke-width:.32;vector-effect:non-scaling-stroke}",
            ".country-kor,.country-jpn{fill:#34414a;stroke:#9aabb6;stroke-width:.7}",
            "</style>",
            *paths,
            "</svg>",
            "",
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the bundled Natural Earth world map SVG")
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(build_svg(args.source), encoding="utf-8")


if __name__ == "__main__":
    main()
