#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the exact delivered Terminal glyph table, offline (Python 3.10+).

Glyph DATA and mappings remain OFL-1.1; see third_party/fonts/terminal/SOURCE.md.
Fixed coverage preserves the existing Unicode-15.0 selection without depending
on the running Python Unicode database. This does not regenerate vt_tables.inc.
Historical generated comments are retained for byte identity.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
INPUT = "third_party/fonts/terminal/"
EXPECTED = "e3716cefd014aee251378756ad13730346422d63228fdd5741549406804932a1"
PINS = {
    "Uni2-Terminus16.psf.gz": "76b38323e80e09cd44a4ca4b0eaa681101874f208b8b5ba00c8c594cfd3b91c2",
    "Uni2-TerminusBold16.psf.gz": "e47636ab76907452e449194dd4c3cd47f7a2c72afcdd9597d3eb8c8f95a0ebed",
    "vt-unifont.hex": "b6f750fb28ea9d84e948f0b7bfbe6a68e04d8a2bc48971cd18b90a7545d9b5e7",
    "coverage.json": "2a9fa6dd704b7a2fb0f2e3f10bfe83d0982310f22d4e2869fca6512877474474",
    "Terminus.NOTICE": "c5aecee192f48b9d736f52516dfd4fde776be2fd7b5ae37067fa73cd5843efa2",
    "Unifont.COPYING": "5a65797606332f2f63057fd81ea0ff35f74043583515bf900ee9b42efa8176a6",
    "OFL-1.1.txt": "869692af094c57fb7258c57fe26820c759319603321d0ffeb278de3651763ded",
    "NOTICE.md": "c30582331cecd28fc51a5086d5781244eba08771ae12a987b3cd7bb59be47ab3",
    "SOURCE.md": "149e795fdf67a7837fc19257c7a2e2f510e46ea9d0e90e5190e2cc15c5740ba5"
}


def local(name):
    path = ROOT
    for part in Path(name).parts:
        if part in ("..", ".", "") or Path(name).is_absolute():
            raise ValueError("unsafe source path")
        path = path / part
        if path.is_symlink():
            raise ValueError("source path escapes through symlink: " + name)
    if not path.is_file():
        raise ValueError("missing source/license/recipe: " + name)
    return path


def inputs():
    for name, expected in PINS.items():
        path = local(INPUT + name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("source/license/recipe differs from pinned bytes: " + name)
    return json.loads(local(INPUT + "coverage.json").read_bytes())


def psf(path):
    d = gzip.open(path).read()
    if d[:2] != b"\x36\x04" or d[3] != 16:
        raise ValueError("invalid 8x16 PSF source")
    mode, h = d[2], d[3]
    n = 512 if mode & 1 else 256
    glyphs = [d[4 + i * h:4 + (i + 1) * h] for i in range(n)]
    table = struct.unpack("<%dH" % ((len(d) - 4 - n * h) // 2), d[4 + n * h:4 + n * h + ((len(d) - 4 - n * h) // 2) * 2])
    out, gi, seq = {}, 0, False
    for w in table:
        if w == 0xFFFF:
            gi += 1; seq = False
        elif w == 0xFFFE:
            seq = True
        elif not seq:
            out.setdefault(w, glyphs[gi])
    return out


def unifont_wide(path):
    """Full 16x16 Unifont glyphs (32 bytes: row-major, 2 bytes per row)."""
    out = {}
    for line in open(path):
        cp, bits = line.strip().split(":")
        if len(bits) == 64:
            out[int(cp, 16)] = bytes.fromhex(bits)
    return out


def unifont(path):
    out = {}
    for line in open(path):
        cp, bits = line.strip().split(":")
        cp = int(cp, 16)
        if len(bits) == 32:
            out[cp] = bytes.fromhex(bits)
        elif len(bits) == 64:
            rows = bytes.fromhex(bits)
            squeezed = bytearray()
            for r in range(16):                       # 16x16 -> 8x16: OR each pixel pair
                word = (rows[2 * r] << 8) | rows[2 * r + 1]
                b = 0
                for i in range(8):
                    if word & (0xc000 >> (2 * i)):
                        b |= 0x80 >> i
                squeezed.append(b)
            out[cp] = bytes(squeezed)
    return out


def block(cp):
    """U+2580..259F exact 8x16 geometry."""
    rows = [0] * 16
    def fill(x0, x1, y0, y1, pat=None):
        for y in range(y0, y1):
            for x in range(x0, x1):
                if pat is None or pat(x, y):
                    rows[y] |= 0x80 >> x
    o = cp - 0x2580
    if o == 0: fill(0, 8, 0, 8)
    elif 1 <= o <= 8: fill(0, 8, 16 - 2 * o, 16)                   # lower 1/8..8/8
    elif 9 <= o <= 0xf: fill(0, 8 - (o - 8), 0, 16)                 # left 7/8..1/8
    elif o == 0x10: fill(4, 8, 0, 16)                              # right half
    elif o == 0x11: fill(0, 8, 0, 16, lambda x, y: (x + y) % 4 == 0)
    elif o == 0x12: fill(0, 8, 0, 16, lambda x, y: (x + y) % 2 == 0)
    elif o == 0x13: fill(0, 8, 0, 16, lambda x, y: (x + y) % 4 != 0)
    elif o == 0x14: fill(0, 8, 0, 2)                               # upper 1/8
    elif o == 0x15: fill(7, 8, 0, 16)                              # right 1/8
    else:
        q = {0x16: "3", 0x17: "4", 0x18: "1", 0x19: "134", 0x1a: "14", 0x1b: "123",
             0x1c: "124", 0x1d: "2", 0x1e: "23", 0x1f: "234"}[o]
        quads = {"1": (0, 4, 0, 8), "2": (4, 8, 0, 8), "3": (0, 4, 8, 16), "4": (4, 8, 8, 16)}
        for k in q:
            fill(*quads[k])
    return bytes(rows)


def braille(cp):
    bits = cp - 0x2800
    rows = [0] * 16
    dots = [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2), (0, 3), (1, 3)]
    for i, (cx, cy) in enumerate(dots):
        if bits & (1 << i):
            x0, y0 = 1 + cx * 4, 1 + cy * 4
            for y in range(y0, y0 + 2):
                rows[y] |= (0xc0 >> x0)
    return bytes(rows)


def build():
    coverage = inputs()
    TERMINUS = local(INPUT + "Uni2-Terminus16.psf.gz")
    TERMINUS_BOLD = local(INPUT + "Uni2-TerminusBold16.psf.gz")
    UNIFONT = local(INPUT + "vt-unifont.hex")
    term, term_bold, uni = psf(TERMINUS), psf(TERMINUS_BOLD), unifont(UNIFONT)
    uni_wide = unifont_wide(UNIFONT)
    wide = {cp: uni_wide[cp] for cp in coverage["wide"]}
    glyphs, source = {}, {}
    for cp in coverage["regular"]:
        if 0x2580 <= cp <= 0x259f:
            glyphs[cp], source[cp] = block(cp), "procedural"
        elif 0x2800 <= cp <= 0x28ff:
            glyphs[cp], source[cp] = braille(cp), "procedural"
        elif cp in term:
            glyphs[cp], source[cp] = term[cp], "terminus"
        else:
            glyphs[cp], source[cp] = uni[cp], "unifont"
    cps = sorted(glyphs)
    bold_cps = sorted(c for c in cps if c in term_bold and c < 0x2000)
    counts = {k: sum(1 for c in cps if source[c] == k) for k in ("terminus", "unifont", "procedural")}
    out = ["; SPDX-License-Identifier: OFL-1.1",
           "; GENERATED by gauntlet_v2/tools/vt/gen_vt_font.py - do not edit",
           "; Glyphs: Terminus (SIL OFL 1.1) %(terminus)d, GNU Unifont 15.1 (SIL OFL 1.1 /"
           " GPL-2+ font exception) %(unifont)d, procedural %(procedural)d" % counts,
           "; Terminus Font: Copyright (c) 2010 Dimitar Toshkov Zhekov, Reserved Font Name \"Terminus Font\"",
           "; (this table is a modified subset and is not named Terminus). GNU Unifont: Roman Czyborra,",
           "; Paul Hardy et al.; this table elects Unifont's SIL OFL 1.1 option. See THIRD_PARTY_NOTICES.md.",
           "align 4", "vt_font_count: dd %d" % len(cps), "vt_font_cps:"]
    for i in range(0, len(cps), 12):
        out.append("    dd " + ",".join("0x%x" % c for c in cps[i:i + 12]))
    out.append("vt_font_glyphs:")
    for c in cps:
        out.append("    db " + ",".join("0x%02x" % b for b in glyphs[c]) + "  ; U+%04X" % c)
    out += ["align 4", "vt_font_bold_count: dd %d" % len(bold_cps), "vt_font_bold_cps:"]
    for i in range(0, len(bold_cps), 12):
        out.append("    dd " + ",".join("0x%x" % c for c in bold_cps[i:i + 12]))
    out.append("vt_font_bold_glyphs:")
    for c in bold_cps:
        out.append("    db " + ",".join("0x%02x" % b for b in term_bold[c]))
    wcps = sorted(wide)
    out += ["align 4", "vt_font_wide_count: dd %d" % len(wcps), "vt_font_wide_cps:"]
    for i in range(0, len(wcps), 12):
        out.append("    dd " + ",".join("0x%x" % c for c in wcps[i:i + 12]))
    out.append("vt_font_wide_glyphs:                ; 32 bytes: 16 rows x 16 px")
    for c in wcps:
        out.append("    db " + ",".join("0x%02x" % b for b in wide[c]) + "  ; U+%04X" % c)
    # Unmodified, transparent nonspacing glyphs; never use a spacing fallback.
    # Each slot is 32 bytes; narrow uses first 16, Japanese uses all 32.
    marks = coverage["marks"]
    original = {}
    for line in open(UNIFONT):
        key, bits = line.strip().split(":")
        cp = int(key, 16)
        if cp in marks:
            original[cp] = bytes.fromhex(bits)
    if set(original) != set(marks):
        raise ValueError("source lacks combining marks")
    out += ["align 4", "vt_font_mark_count: dd %d" % len(marks), "vt_font_mark_cps:",
            "    dd " + ",".join(hex(cp) for cp in marks), "vt_font_mark_widths:",
            "    db " + ",".join(str(len(original[cp]) // 16) for cp in marks),
            "vt_font_mark_glyphs:"]
    for cp in marks:
        bits = original[cp].ljust(32, b"\0")
        out.append("    db " + ",".join("0x%02x" % b for b in bits) + " ; U+%04X" % cp)
    result = ("\n".join(out) + "\n").encode("ascii")
    if hashlib.sha256(result).hexdigest() != EXPECTED:
        raise ValueError("regenerated glyph bytes differ from the pinned Terminal table")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--emit", type=Path, metavar="OUTDIR")
    args = parser.parse_args()
    try:
        result = build()  # Complete admission and conversion before creating output.
        if args.check:
            if local("src/gui/vt/vt_font.inc").read_bytes() != result:
                raise ValueError("shipped vt_font.inc differs from regenerated source")
            print("Terminal glyphs: exact current 3452 regular, 476 bold, 41 wide, 17 marks")
        elif args.emit:
            args.emit.mkdir(parents=True, exist_ok=True)
            (args.emit / "vt_font.inc").write_bytes(result)
        else:
            sys.stdout.buffer.write(result)
    except (OSError, ValueError, KeyError, IndexError, struct.error) as exc:
        print("gen_vt_font: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
