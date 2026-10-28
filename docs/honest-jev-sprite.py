#!/usr/bin/env python3
"""Generate docs/honest-jev.svg: a 16-bit pixel-art Abe Lincoln mascot,
Mario-Bros-sprite style (big head, stovepipe hat, chin-strap beard, broad
shoulders, stubby legs) built out of a crisp-edged <rect> grid.

Edit CHAR_MAP / PALETTE below and re-run:
    python3 docs/honest-jev-sprite.py
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Palette (~9 sprite colours + 1 background card colour)
# ---------------------------------------------------------------------------
PALETTE = {
    "K": "#15110c",  # near-black: hat, coat, shoes, eyes, bow tie
    "C": "#241c14",  # hat crown/brim shading (slightly lighter near-black)
    "T": "#8a6a46",  # leather trim: hat band, belt
    "D": "#c9a37e",  # skin shadow (gaunt cheek/temple, nose bridge)
    "S": "#e8c9a8",  # skin light
    "R": "#3a2c1f",  # beard dark brown (chin-strap only, no moustache)
    "Q": "#55402c",  # beard highlight brown
    "W": "#f2ede4",  # white collar / bow-tie knot
}
BG = "#2b2118"  # rounded card background

# ---------------------------------------------------------------------------
# Sprite grid: 32 cols wide, rows = len(HALF_ROWS). The character is
# left/right symmetric, so each row is authored as a 16-cell run-length
# half (col 0 = outer edge, col 15 = centre-adjacent) and mirrored to build
# the full 32-wide row. Each tuple is (count, char); '.' is transparent.
# Counts per row MUST sum to 16.
# ---------------------------------------------------------------------------
HALF_ROWS = [
    [(11, "."), (5, "K")],                            #  0 crown (flat-top stovepipe)
    [(11, "."), (5, "K")],                            #  1 crown
    [(11, "."), (5, "K")],                            #  2 crown
    [(11, "."), (5, "K")],                            #  3 crown
    [(11, "."), (5, "K")],                            #  4 crown
    [(11, "."), (5, "K")],                            #  5 crown
    [(11, "."), (5, "K")],                            #  6 crown
    [(11, "."), (5, "K")],                            #  7 crown
    [(11, "."), (5, "K")],                            #  8 crown
    [(11, "."), (5, "K")],                            #  9 crown
    [(10, "."), (6, "T")],                            # 10 hat band
    [(7, "."), (9, "K")],                             # 11 brim top
    [(7, "."), (9, "C")],                             # 12 brim underside
    [(10, "."), (1, "D"), (5, "S")],                  # 13 forehead
    [(11, "."), (1, "D"), (4, "S")],                  # 14 forehead taper
    [(11, "."), (1, "D"), (1, "S"), (2, "K"), (1, "S")],  # 15 brow
    [(11, "."), (1, "D"), (1, "S"), (1, "K"), (2, "S")],  # 16 eyes
    [(12, "."), (1, "R"), (3, "S")],                  # 17 cheek / sideburn
    [(12, "."), (1, "R"), (1, "S"), (1, "D"), (1, "S")],  # 18 nose
    [(12, "."), (1, "R"), (3, "S")],                  # 19 lower cheek (elongate)
    [(12, "."), (2, "R"), (2, "S")],                  # 20 mouth (bare, no moustache)
    [(13, "."), (2, "R"), (1, "S")],                  # 21 jaw upper
    [(13, "."), (3, "R")],                            # 22 chin (full beard wrap)
    [(14, "."), (2, "R")],                            # 23 chin point
    [(14, "."), (1, "Q"), (1, "R")],                  # 24 chin tip
    [(14, "."), (2, "S")],                            # 25 neck
    [(13, "."), (1, "W"), (2, "S")],                  # 26 neck + collar
    [(12, "."), (2, "W"), (2, "K")],                  # 27 collar + bow tie
    [(7, "."), (9, "K")],                             # 28 shoulders
    [(8, "."), (7, "K"), (1, "C")],                   # 29 torso + seam
    [(8, "."), (7, "K"), (1, "C")],                   # 30 torso + seam
    [(6, "."), (2, "S"), (7, "K"), (1, "C")],          # 31 torso + hand + seam
    [(6, "."), (2, "S"), (7, "K"), (1, "C")],          # 32 torso + hand + seam
    [(8, "."), (7, "K"), (1, "C")],                   # 33 torso + seam
    [(9, "."), (7, "T")],                             # 34 belt
    [(10, "."), (5, "K"), (1, ".")],                  # 35 hip / leg gap
    [(10, "."), (5, "K"), (1, ".")],                  # 36 leg
    [(10, "."), (5, "K"), (1, ".")],                  # 37 leg
    [(10, "."), (5, "K"), (1, ".")],                  # 38 leg
    [(10, "."), (5, "K"), (1, ".")],                  # 39 leg
    [(10, "."), (5, "K"), (1, ".")],                  # 40 leg
    [(9, "."), (6, "K"), (1, ".")],                   # 41 shoe top
    [(8, "."), (7, "K"), (1, ".")],                   # 42 shoe sole
]

GRID_W, GRID_H = 32, len(HALF_ROWS)
PAD = 2  # transparent margin cells around the figure
CANVAS_W, CANVAS_H = GRID_W + PAD * 2, GRID_H + PAD * 2


def expand_half(run_length):
    chars = []
    for count, ch in run_length:
        chars.extend([ch] * count)
    assert len(chars) == 16, f"half row must sum to 16, got {len(chars)}"
    return chars


def build_rows():
    rows = []
    for half in HALF_ROWS:
        left = expand_half(half)
        right = list(reversed(left))
        rows.append(left + right)
    assert len(rows) == GRID_H
    for row in rows:
        assert len(row) == GRID_W
    return rows


def row_to_rects(row, y):
    """Run-length encode a row into merged <rect> cells."""
    rects = []
    x = 0
    n = len(row)
    while x < n:
        ch = row[x]
        if ch == ".":
            x += 1
            continue
        start = x
        while x < n and row[x] == ch:
            x += 1
        width = x - start
        rects.append((start, y, width, ch))
    return rects


def build_svg():
    rows = build_rows()
    rects = []
    for y, row in enumerate(rows):
        rects.extend(row_to_rects(row, y))

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {CANVAS_W} {CANVAS_H}" '
        f'width="{CANVAS_W * 8}" height="{CANVAS_H * 8}">',
        "  <!-- Honest Jev: 16-bit pixel-art Abe Lincoln mascot (Mario-sprite style) -->",
        f'  <rect width="{CANVAS_W}" height="{CANVAS_H}" rx="4" fill="{BG}"/>',
        f'  <g shape-rendering="crispEdges">',
    ]
    for gx, gy, gw, ch in rects:
        x, y = gx + PAD, gy + PAD
        parts.append(f'    <rect x="{x}" y="{y}" width="{gw}" height="1" fill="{PALETTE[ch]}"/>')
    parts.append("  </g>")
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main():
    svg = build_svg()
    out = HERE / "honest-jev.svg"
    out.write_text(svg)
    size_kb = len(svg.encode("utf-8")) / 1024
    print(f"wrote {out} ({size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
