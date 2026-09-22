#!/usr/bin/env python3
"""Build the multi-size AI-Powered SOC Assistant icon from the company logo.

The source is ``static/img/company-logo.png`` (the Mun Cyber Technologies
mark: four triangles and the shield). That file already has a transparent
background. This script keeps that alpha, centers the mark in a square,
and writes PNG-compressed ICO entries at 16, 24, 32, 48, 64, 128, and 256.

Customers receive ``static/img/ai-powered-soc-assistant.ico`` already built.
Run this from the repo root only when the logo artwork changes::

    python scripts/build_icon.py
"""

from __future__ import annotations

import io
import struct
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
LOGO = ROOT / "static" / "img" / "company-logo.png"
ICO = ROOT / "static" / "img" / "ai-powered-soc-assistant.ico"
SIZES = (16, 24, 32, 48, 64, 128, 256)


def _mark(src: Image.Image) -> Image.Image:
    """Crop to the visible logo and keep its alpha channel."""
    logo = src.convert("RGBA")
    alpha = logo.getchannel("A")
    mask = alpha.point(lambda value: 255 if value > 8 else 0)
    bbox = mask.getbbox()
    if bbox is None:
        return logo
    return logo.crop(bbox)


def _render(mark: Image.Image, size: int) -> Image.Image:
    """Center the mark on a transparent square without stretching it."""
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    margin = max(0, round(size * 0.04))
    inner = max(1, size - margin * 2)
    width, height = mark.size
    scale = min(inner / width, inner / height)
    fitted_w = max(1, round(width * scale))
    fitted_h = max(1, round(height * scale))
    fitted = mark.resize((fitted_w, fitted_h), Image.Resampling.LANCZOS)
    left = (size - fitted_w) // 2
    top = (size - fitted_h) // 2
    canvas.paste(fitted, (left, top), fitted)
    return canvas


def write_png_ico(icons: list[Image.Image], dest: Path) -> None:
    """Write an ICO whose entries are PNG payloads Windows shortcuts can read.

    Width/height 0 means 256. Planes 1 and bit count 32 match what Explorer
    expects even when the image bytes are PNG rather than a BMP DIB.
    """
    blobs: list[bytes] = []
    for icon in icons:
        buffer = io.BytesIO()
        icon.save(buffer, format="PNG")
        blobs.append(buffer.getvalue())
    count = len(icons)
    header = struct.pack("<HHH", 0, 1, count)
    entries = bytearray()
    offset = 6 + count * 16
    for icon, blob in zip(icons, blobs):
        width = 0 if icon.width >= 256 else icon.width
        height = 0 if icon.height >= 256 else icon.height
        entries += struct.pack("<BBBBHHII", width, height, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(header + bytes(entries) + b"".join(blobs))


def build_icon(logo: Path = LOGO, dest: Path = ICO) -> Path:
    mark = _mark(Image.open(logo))
    icons = [_render(mark, size) for size in SIZES]
    write_png_ico(icons, dest)
    return dest


def main() -> None:
    path = build_icon()
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
