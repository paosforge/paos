#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""PaOS 8x16 bitmap glyph tables from the vendored Spleen 8x16 BDF (deterministic, host-only).

Source: Spleen 8x16 2.1.0, (c) 2018-2024 Frederic Cambus, BSD-2-Clause, vendored unmodified at
third_party/fonts/spleen/spleen-8x16.bdf (pins in third_party/fonts/spleen/SOURCE.md). Nothing is redrawn: every
inked cell is a Spleen cell, placed in the 16-row cell by the BDF's own BBX/ascent (MSB = leftmost pixel).

Outputs (existing byte-index offsets and ASCII cells are unchanged):
  font8x16.inc  the whole src/gui/font8x16.inc (`font_8x16`): 384 cells U+0000..U+017F: ASCII, 32 blank C1 cells, 224 Spleen Latin cells.
                U+0020..U+007E are Spleen. FALLBACK: U+0001..U+001F (the retired table's CP437 dingbats) are blank
                cells, because the source BDF encodes no C0 glyphs; U+0000 stays blank; U+007F is Spleen's own blank
                cell. The Spleen cp437/ variant is deliberately not used for C0: 11 of its 31 C0 cells are
                byte-identical to the retired IBM VGA cells. U+0080..U+009F stay blank.
                `font_8x16_ext_a` starts at byte 4096, U+0100; `font_8x16_end` at byte 6144.
                New Unicode consumers use those labels; byte consumers keep their original offsets.
  manager.inc   the 128 `; U+xxxx` rows of src/bootmgr/paos_bootmgr.asm `face_ocr_font` (U+0020..U+007E Spleen,
                control rows and U+007F blank).
  bootmenu.inc  the 22 indexed rows of src/boot/boot_menu.asm `bm_face_ocr_font`, in BOOT_MENU_ORDER.
  bootface.inc  the 41 rows of src/boot/boot_face.asm `bf_font` (the public loading face's version text):
                U+002B..U+0039 then U+0061..U+007A, in BOOT_FACE_ORDER.

usage:
  font_build.py [--bdf PATH] --emit OUTDIR     write the four outputs into OUTDIR
  font_build.py [--bdf PATH] --write           rewrite src/gui/font8x16.inc in place
  font_build.py [--bdf PATH] --check           exit 0 iff all four shipped tables equal the outputs
Verification: python3 -m unittest discover -s tools/fonts -p test_font_build.py.
Requires Python 3.10+ standard library only; no network or factory inputs.
Generated comments retain historical factory paths to preserve exact shipped bytes.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
BDF_DEFAULT = ROOT / "third_party/fonts/spleen/spleen-8x16.bdf"
BDF_SHA256 = "b2b05484ba4380c9c6854cc57637235a9fb039c65b5ba38a65289540f8fab7dc"
GUI = ROOT / "src/gui/font8x16.inc"
BOOT_MENU = (ROOT / "src/boot/boot_menu.asm", "bm_face_ocr_font:")
MANAGER = (ROOT / "src/bootmgr/paos_bootmgr.asm", "face_ocr_font:")
BOOT_FACE = (ROOT / "src/boot/boot_face.asm", "bf_font:")

BOOT_MENU_ORDER = [0x20, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x4C, 0x4F, 0x50, 0x53, 0x5B, 0x5C, 0x5D,
                   0x61, 0x64, 0x67, 0x69, 0x6E, 0x6F, 0x73, 0x76, 0x7C]
# Public loading face (T6-1): '+' ',' '-' '.' '/' '0'..'9', then 'a'..'z'; boot_face.asm indexes these two runs.
BOOT_FACE_ORDER = list(range(0x2B, 0x3A)) + list(range(0x61, 0x7B))

BLANK = bytes(16)


def parse_bdf(data: bytes) -> dict[int, bytes]:
    """ENCODING 0..0x17F of an 8-wide, 16-high (ascent 12, descent 4) BDF -> 16-byte cells."""
    lines = data.decode("ascii").splitlines()
    ascent = descent = None
    fbb = None
    glyphs: dict[int, bytes] = {}
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("FONTBOUNDINGBOX"):
            fbb = tuple(int(v) for v in ln.split()[1:])
        elif ln.startswith("FONT_ASCENT"):
            ascent = int(ln.split()[1])
        elif ln.startswith("FONT_DESCENT"):
            descent = int(ln.split()[1])
        elif ln.startswith("STARTCHAR"):
            enc = bbx = None
            rows: list[int] = []
            i += 1
            while not lines[i].startswith("ENDCHAR"):
                t = lines[i]
                if t.startswith("ENCODING"):
                    enc = int(t.split()[1])
                elif t.startswith("BBX"):
                    bbx = tuple(int(v) for v in t.split()[1:])
                elif t == "BITMAP":
                    i += 1
                    while not lines[i].startswith("ENDCHAR"):
                        rows.append(int(lines[i], 16))
                        i += 1
                    break
                i += 1
            if enc is not None and 0 <= enc <= 0x17F:
                w, h, xo, yo = bbx
                if ((ascent, descent) != (12, 4) or fbb != (8, 16, 0, -4)
                        or not 0 < w <= 8 or xo < 0 or xo + w > 8
                        or len(rows) != h or enc in glyphs):
                    raise ValueError(f"invalid Spleen cell geometry/rows: {enc}, {bbx}")
                cell = [0] * 16
                top = ascent - (yo + h)          # row of the glyph's first bitmap row in the 16-row cell
                for r, v in enumerate(rows):
                    y = top + r
                    if not 0 <= y < 16 or not 0 <= v <= 255:
                        raise ValueError(f"invalid Spleen bitmap row: {enc}, {bbx}")
                    cell[y] = (v >> xo) & 0xFF
                glyphs[enc] = bytes(cell)
        i += 1
    return glyphs


def load_bdf(path: Path) -> dict[int, bytes]:
    return parse_bdf(path.read_bytes())


def ascii_cells(glyphs: dict[int, bytes]) -> list[bytes]:
    """The 128 cells U+0000..U+007F: Spleen printable, blank fallback for C0, Spleen's (blank) U+007F."""
    missing = [cp for cp in range(0x20, 0x7F) if cp not in glyphs]
    if missing:
        raise ValueError(f"source lacks printable ASCII {missing}")
    printable = [glyphs[cp] for cp in range(0x20, 0x7F)]
    if len(set(printable)) != 95:
        raise ValueError("Spleen printable glyphs are not pairwise distinct")
    return [glyphs[cp] if 0x20 <= cp <= 0x7E else BLANK for cp in range(0x80)]


def face_row(bitmap: bytes, cp: int) -> str:
    return "    db " + ",".join(f"0x{b:02x}" for b in bitmap) + f" ; U+{cp:04x}"


def gui_label(cp: int) -> str:
    return f"'{chr(cp)}'" if 0x20 <= cp <= 0x7E else f"0x{cp:02X}"


def gui_inc(cells: list[bytes], bdf_sha: str, glyphs: dict[int, bytes]) -> str:
    out = [
        "; gui/font8x16.inc - 8x16 GUI bitmap font. GENERATED by gauntlet_v2/tools/font_build.py --write; do not edit.",
        "; Source: Spleen 8x16 2.1.0, (c) 2018-2024 Frederic Cambus, https://github.com/fcambus/spleen (tag 2.1.0),",
        f";   vendored unmodified at third_party/fonts/spleen/spleen-8x16.bdf, sha256 {bdf_sha}.",
        "; Licence: BSD-2-Clause (SPDX-License-Identifier: BSD-2-Clause); third_party/fonts/spleen/LICENSE and",
        ";   third_party/fonts/THIRD_PARTY_NOTICES.md. Provenance gate: gauntlet_v2/tests/test_font_provenance_host.py.",
        "; 128 glyphs U+0000..U+007F x 16 rows, MSB = leftmost pixel. U+0020..U+007E are Spleen cells; U+0000..U+001F",
        ";   are blank (fallback: the source encodes no C0 glyphs) and U+007F is Spleen's blank cell; U+0080..U+009F remain blank.",
        "; U+00A0..U+017F are complete Spleen cells; font_8x16_ext_a = font_8x16 + 4096 (U+0100).",
        "align 16",
        "font_8x16:",
    ]
    for cp, cell in enumerate(cells):
        out.append("    db " + ",".join(f"0x{b:02X}" for b in cell) + "  ; " + gui_label(cp))
    out.append("    times 32 * 16 db 0                  ; U+0080..U+009F: blank C1 cells")
    for cp in range(0xA0, 0x180):
        if cp == 0x100:
            out.append("font_8x16_ext_a:")
        out.append("    db " + ",".join(f"0x{b:02X}" for b in glyphs[cp]) + f"  ; U+{cp:04X}")
    out.append("font_8x16_end:")
    return "\n".join(out) + "\n"


def build(bdf: Path) -> dict[str, str]:
    data = bdf.read_bytes()
    bdf_sha = hashlib.sha256(data).hexdigest()
    if bdf_sha != BDF_SHA256:
        raise SystemExit(f"font_build: {bdf} sha256 {bdf_sha} is not the pinned Spleen 2.1.0 spleen-8x16.bdf")
    glyphs = parse_bdf(data)
    cells = ascii_cells(glyphs)
    missing = [cp for cp in range(0xA0, 0x180) if cp not in glyphs]
    if missing:
        raise SystemExit(f"font_build: source lacks Latin cells {missing}")
    return {
        "font8x16.inc": gui_inc(cells, bdf_sha, glyphs),
        "manager.inc": "\n".join(face_row(cells[cp], cp) for cp in range(0x80)) + "\n",
        "bootmenu.inc": "\n".join(face_row(glyphs[cp], cp) for cp in BOOT_MENU_ORDER) + "\n",
        "bootface.inc": "\n".join(face_row(glyphs[cp], cp) for cp in BOOT_FACE_ORDER) + "\n",
    }


def shipped_rows(path: Path, label: str) -> list[str]:
    lines = path.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(label))
    rows = []
    for line in lines[start + 1:]:
        if not (line.lstrip().startswith("db ") and "; U+" in line):
            break
        rows.append(line.strip())
    return rows


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bdf", type=Path, default=BDF_DEFAULT)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--emit", type=Path, metavar="OUTDIR")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    out = build(args.bdf)
    if args.emit:
        args.emit.mkdir(parents=True, exist_ok=True)
        for name, text in sorted(out.items()):
            (args.emit / name).write_bytes(text.encode("utf-8"))
        print("font_build: emitted", ", ".join(sorted(out)))
        return 0
    if args.write:
        GUI.write_bytes(out["font8x16.inc"].encode("utf-8"))
        print(f"font_build: wrote {GUI.relative_to(ROOT)}")
        return 0
    bad = []
    if GUI.read_bytes() != out["font8x16.inc"].encode("utf-8"):
        bad.append(str(GUI.relative_to(ROOT)))
    for (path, label), name in ((BOOT_MENU, "bootmenu.inc"), (MANAGER, "manager.inc"), (BOOT_FACE, "bootface.inc")):
        if shipped_rows(path, label) != [l.strip() for l in out[name].splitlines() if l.strip()]:
            bad.append(f"{path.relative_to(ROOT)} {label}")
    print("font_build: check", "OK" if not bad else f"DIFFERS {bad}")
    return 0 if not bad else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, IndexError, TypeError, StopIteration) as exc:
        print(f"font_build: {exc}", file=sys.stderr)
        raise SystemExit(1)
