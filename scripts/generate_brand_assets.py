from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw


SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-label="WeaveXDR">
  <rect x="4" y="4" width="120" height="120" rx="27" fill="#10171e" stroke="#31414d" stroke-width="4"/>
  <path d="M64 17 105 32v30c0 24-16 43-41 52C39 105 23 86 23 62V32z" fill="#16242c" stroke="#59d0c8" stroke-width="6" stroke-linejoin="round"/>
  <path d="m36 43 14 42 14-30 14 30 14-42" fill="none" stroke="#f4f7f9" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="36" cy="43" r="5" fill="#67ded4"/><circle cx="64" cy="55" r="5" fill="#76a7ff"/><circle cx="92" cy="43" r="5" fill="#67ded4"/>
</svg>
"""


def draw_icon(size: int = 1024) -> Image.Image:
    scale = size / 128
    point = lambda x, y: (round(x * scale), round(y * scale))
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        [point(4, 4), point(124, 124)],
        radius=round(27 * scale),
        fill="#10171e",
        outline="#31414d",
        width=max(1, round(4 * scale)),
    )
    shield = [point(64, 17), point(105, 32), point(105, 62), point(101, 80), point(88, 99), point(64, 114), point(40, 99), point(27, 80), point(23, 62), point(23, 32)]
    draw.polygon(shield, fill="#16242c")
    draw.line(shield + [shield[0]], fill="#59d0c8", width=round(6 * scale), joint="curve")
    weave = [point(36, 43), point(50, 85), point(64, 55), point(78, 85), point(92, 43)]
    draw.line(weave, fill="#f4f7f9", width=round(8 * scale), joint="curve")
    radius = round(5 * scale)
    for x, y, color in ((36, 43, "#67ded4"), (64, 55, "#76a7ff"), (92, 43, "#67ded4")):
        cx, cy = point(x, y)
        draw.ellipse([cx - radius, cy - radius, cx + radius, cy + radius], fill=color)
    return image


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the shared WeaveXDR web and Windows icons")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "weavexdr.svg").write_text(SVG, encoding="utf-8")
    image = draw_icon()
    image.save(
        args.output / "weavexdr.ico",
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )


if __name__ == "__main__":
    main()
