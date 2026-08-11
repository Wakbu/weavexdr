from __future__ import annotations

import argparse
import json
import re
from html.parser import HTMLParser
from pathlib import Path


class IdCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.labels_for: set[str] = set()
        self.controls: list[tuple[str, bool]] = []

    def handle_starttag(self, _tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.append(str(attributes["id"]))
        if _tag == "label" and attributes.get("for"):
            self.labels_for.add(str(attributes["for"]))
        if _tag in {"input", "select", "textarea"} and attributes.get("id"):
            self.controls.append((str(attributes["id"]), bool(attributes.get("aria-label"))))


def _rgb(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    if len(value) == 3:
        value = "".join(character * 2 for character in value)
    return tuple(int(value[index:index + 2], 16) for index in (0, 2, 4))


def _contrast(foreground: str, background: str) -> float:
    def luminance(color: str) -> float:
        channels = []
        for component in _rgb(color):
            normalized = component / 255
            channels.append(normalized / 12.92 if normalized <= .04045 else ((normalized + .055) / 1.055) ** 2.4)
        return .2126 * channels[0] + .7152 * channels[1] + .0722 * channels[2]

    first, second = sorted((luminance(foreground), luminance(background)), reverse=True)
    return round((first + .05) / (second + .05), 2)


def validate_dashboard(path: Path) -> dict[str, object]:
    html = path.read_text(encoding="utf-8")
    collector = IdCollector()
    collector.feed(html)
    duplicates = sorted(identifier for identifier in set(collector.ids) if collector.ids.count(identifier) > 1)
    unlabeled_controls = sorted(identifier for identifier, has_aria in collector.controls if not has_aria and identifier not in collector.labels_for)
    breakpoints = sorted({int(value) for value in re.findall(r"max-width:(\d+)px", html)})
    colors = {name: values[-1] for name in ("bg", "text", "muted") if (values := re.findall(rf"--{name}:\s*(#[0-9a-fA-F]{{3,6}})", html))}
    contrast = {
        "text_on_bg": _contrast(colors["text"], colors["bg"]) if {"text", "bg"} <= colors.keys() else 0,
        "muted_on_bg": _contrast(colors["muted"], colors["bg"]) if {"muted", "bg"} <= colors.keys() else 0,
    }
    required = {
        "runtime_diagnostics": "weavexdrUiDiagnostics" in html,
        "mobile_640": 640 in breakpoints,
        "tablet_900": 900 in breakpoints,
        "desktop_default": ".shell { min-height:100vh" in html,
        "control_min_height": "min-height:40px" in html,
        "keyboard_graph": "ArrowLeft" in html,
        "favicon": "/assets/weavexdr.svg" in html,
        "natural_earth_map": "/assets/world-map.svg" in html,
        "accessible_names": not unlabeled_controls,
        "text_contrast": contrast["text_on_bg"] >= 4.5 and contrast["muted_on_bg"] >= 4.5,
    }
    errors = [name for name, passed in required.items() if not passed]
    if duplicates:
        errors.append("duplicate_ids")
    return {
        "passed": not errors,
        "errors": errors,
        "breakpoints": breakpoints,
        "duplicate_ids": duplicates,
        "unlabeled_controls": unlabeled_controls,
        "contrast": contrast,
        "viewport_matrix": [
            {"width": width, "scale": scale}
            for width in (640, 900, 1280, 1920)
            for scale in (100, 125, 150)
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate static WeaveXDR UI regression contracts")
    parser.add_argument("dashboard", type=Path)
    args = parser.parse_args()
    result = validate_dashboard(args.dashboard)
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
