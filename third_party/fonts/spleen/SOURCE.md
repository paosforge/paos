# Spleen 8x16 (vendored, unmodified)

| Field | Value |
|---|---|
| Project | Spleen, a monospaced bitmap font, by Frederic Cambus |
| Upstream URL | https://github.com/fcambus/spleen |
| Release tag | `2.1.0` |
| Tag commit | `c3b655c5718757863e828c02115e96b149281159` (`git ls-remote https://github.com/fcambus/spleen refs/tags/2.1.0`) |
| Release tarball | https://github.com/fcambus/spleen/releases/download/2.1.0/spleen-2.1.0.tar.gz |
| Tarball SHA-256 | `8b47c56f1a6eb858fbcf9e34530557404b02fbb3455e38e64fb84473fd0c372f` |
| Vendored file | `spleen-8x16.bdf` (tarball path `spleen-2.1.0/spleen-8x16.bdf`), unmodified |
| File SHA-256 | `b2b05484ba4380c9c6854cc57637235a9fb039c65b5ba38a65289540f8fab7dc` |
| Licence | BSD-2-Clause (SPDX-License-Identifier: `BSD-2-Clause`) |
| Licence file | `LICENSE`, verbatim from the tarball (`spleen-2.1.0/LICENSE`), SHA-256 `3cb3f3f5a795547d329828df881c80d923bfc75f65065c44ffa703ad78c678bd` |

Both vendored files were re-verified byte-identical (`cmp`) against a fresh download of the release tarball on
2026-10-03; the tarball hash matched the pin above.

## Used for

| Table | File / label | Cells |
|---|---|---|
| GUI font | `src/gui/font8x16.inc` `font_8x16` | U+0020..U+007E Spleen; U+0000..U+001F blank fallback; U+007F Spleen's blank cell; U+0080..U+009F blank; U+00A0..U+017F Spleen (224 cells) |
| Boot Manager face | `src/bootmgr/paos_bootmgr.asm` `face_ocr_font` | 128 rows, U+0020..U+007E Spleen, the rest blank |
| PaOS boot-menu face | `src/boot/boot_menu.asm` `bm_face_ocr_font` | 22 indexed rows (same cells as the Manager face) |

## Offline regeneration (public source)

From the delivered source root, with Python 3.10+ (standard library only):

```sh
python3 tools/fonts/font_build.py --check
python3 tools/fonts/font_build.py --emit /tmp/paos-spleen-tables
python3 -m unittest discover -s tools/fonts -p test_font_build.py
```

`--emit` writes `font8x16.inc` (the complete GUI include), `manager.inc` (128
rows) and `bootmenu.inc` (22 rows). Compare the GUI include byte for byte with
`src/gui/font8x16.inc`; the face files equal the consecutive `db ... ; U+xxxx`
rows immediately following the labels in the table above. `--check` performs
all three comparisons without writing source. Outputs use UTF-8 with LF on every
host. `--bdf PATH` accepts another copy only if its SHA-256 equals the pin above.
A missing, malformed or differently pinned BDF fails before creating output.
No download, credentials, private factory directory, compiler or signing is needed.

The public shared converter places each BDF cell by BBX/ascent into 16 rows,
MSB = leftmost pixel. Nothing is redrawn. The emitted GUI header deliberately
retains its historical generator/gate path comments so the existing table remains
byte-identical; those comments are provenance, not runtime dependencies. The
factory compatibility command delegates to this same public implementation.
The recipe covers only these three Spleen tables, not other PaOS fonts or a
complete public PaOS/Manager build. It does not change Manager growth semantics.

- **Not used:** the release's `cp437/spleen-8x16-ibm-437.bdf`. Its C0 cells (CP437 dingbats) would have kept the
  retired table's U+0001..U+001F coverage, but 11 of those 31 cells are byte-identical to the retired IBM VGA cells,
  so the GUI font keeps the C0 range blank instead (no PaOS caller draws C0 bytes through `font_8x16`).
- **Why:** the Manager/boot-menu tables replaced Ubuntu Mono Bold (Ubuntu Font Licence) under PETER RULING
  2026-10-01 14:10, Manager growth grant (a). The GUI font replaced IBM VGA/CP437 data (provenance audit
  2026-10-01; ROADMAP LICENSE CLEANUP item 2) for the 0.0.55 candidate.
- **Notices:** `../THIRD_PARTY_NOTICES.md` (this directory's parent) and the repository `THIRD_PARTY_NOTICES.md`.
