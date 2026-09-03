#!/usr/bin/env python3
"""Render the GitHub social preview card (1280x640) from the current results.

The numbers come out of harness/results-latest.json rather than being typed in, so the
card cannot drift away from what the harness actually measured.

    python3 tools/make_social_preview.py [-o docs/social-preview.png]

Upload the result under Settings > General > Social preview.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent.parent
RESULTS = REPO / "harness" / "results-latest.json"

W, H = 1280, 640
BG = (13, 17, 23)          # GitHub dark
FG = (230, 237, 243)
MUTED = (125, 133, 144)
ACCENT = (255, 123, 114)   # the failing number
OK = (63, 185, 80)
RULE = (33, 38, 45)

FONT_DIRS = ("/System/Library/Fonts", "/System/Library/Fonts/Supplemental", "/Library/Fonts")
SANS = ("SFNSDisplay.ttf", "Helvetica.ttc", "Arial.ttf", "Supplemental/Arial.ttf")
MONO = ("SFNSMono.ttf", "Menlo.ttc", "Courier New.ttf", "Monaco.ttf")


def font(names: tuple[str, ...], size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    for d in FONT_DIRS:
        for n in names:
            p = Path(d) / n
            if p.is_file():
                try:
                    return ImageFont.truetype(str(p), size, index=1 if (bold and p.suffix == ".ttc") else 0)
                except OSError:
                    continue
    return ImageFont.load_default()


def load_rows() -> list[tuple[str, str, str, bool]]:
    """(name, recall, pairs, is_failure) straight from the results file."""
    data = json.loads(RESULTS.read_text(encoding="utf-8"))
    rows = []
    for a in data.get("adapters", []):
        counts = a.get("counts")
        if not counts:
            continue
        scored = a.get("pairs_scored", 0)
        if not scored and counts.get("errors"):
            rows.append((a["adapter"], "", "crashes on every case", True))
            continue
        if not scored:
            continue
        recall = a.get("recall")
        disc = a.get("pairs_discriminated", 0)
        rows.append((a["adapter"],
                     f"{recall * 100:.0f}%" if recall is not None else "",
                     f"{disc} of {scored}",
                     disc * 2 < scored))
    rows.sort(key=lambda r: (not r[3], r[0]))     # failures first
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-o", "--out", type=Path, default=REPO / "docs" / "social-preview.png")
    ns = ap.parse_args()

    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    title = font(SANS, 46, bold=True)
    lede = font(SANS, 27)
    mono = font(MONO, 25)
    mono_small = font(MONO, 21)
    small = font(SANS, 21)

    d.text((70, 62), "MCP Scanner Benchmark", font=title, fill=FG)
    d.text((70, 126), "Can a scanner tell a vulnerability from its fix?", font=lede, fill=MUTED)
    d.line([(70, 182), (W - 70, 182)], fill=RULE, width=2)

    y = 210
    d.text((70, y), "scanner", font=small, fill=MUTED)
    d.text((640, y), "recall", font=small, fill=MUTED)
    d.text((830, y), "pairs it told apart", font=small, fill=MUTED)
    y += 40

    for name, recall, pairs, failing in load_rows()[:5]:
        colour = ACCENT if failing else OK
        d.text((70, y), name[:40], font=mono_small, fill=FG)
        d.text((640, y), recall, font=mono, fill=FG if recall else MUTED)
        d.text((830, y), pairs, font=mono, fill=colour)
        y += 44

    d.line([(70, y + 14), (W - 70, y + 14)], fill=RULE, width=2)
    d.text((70, y + 40),
           "Every case has a safe twin: the same file with the bug fixed.",
           font=small, fill=MUTED)
    d.text((70, y + 70),
           "Flag both and you have detected nothing. Recall will not tell you.",
           font=small, fill=MUTED)

    d.text((70, H - 52), "github.com/ElnatanAnbelu/mcp-scanner-benchmark",
           font=mono_small, fill=(88, 96, 105))

    ns.out.parent.mkdir(parents=True, exist_ok=True)
    img.save(ns.out, "PNG")
    print(f"wrote {ns.out} ({ns.out.stat().st_size // 1024} KB, {W}x{H})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
