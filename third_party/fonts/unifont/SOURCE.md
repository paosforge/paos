# GNU Unifont 15.1.01: the UI glyph subset (vendored excerpt)

| Field | Value |
|---|---|
| Project | GNU Unifont, by Roman Czyborra, Paul Hardy and the Unifont contributors |
| Upstream URL | https://unifoundry.com/unifont/ |
| Version | 15.1.01, as packaged by Ubuntu: `unifont` 1:15.1.01-1build1 |
| Package | `unifont_1%3a15.1.01-1build1_all.deb`, SHA-256 `f5d7516c5a430dc6ee8266fd333cc49339407865916462d608b8478b1e3a84a1` |
| Input file | `usr/share/unifont/unifont.hex` from that package, SHA-256 `341bc797b532c269a0b8e75dce05c98f2a5d04de08a5af1eef4a0aa7587ce31c` |
| Vendored file | `unifont-ui-subset.hex`: 5195 lines of that file, unmodified, in code-point order |
| File SHA-256 | `6c4b16cf4cb8f53e3d8d9bf8da012271547c10bf0fb2bec60dfebac042b42d73` |
| Licence | SIL OFL 1.1, elected (upstream dual-licenses OFL 1.1 or GPL-2.0+ with the font embedding exception), SPDX `OFL-1.1` |
| Licence file | `LICENSE`, identical to `LICENSES/OFL-1.1.txt`, SHA-256 `ddd1809be6c7da406c9969515f6877ecdccf2bc194a2ff21088398565c2863fd` |

These are the same package and input file the Terminal's `vt_font` pins (`THIRD_PARTY_NOTICES.md`, "Terminus Font and
GNU Unifont glyphs"). Nothing was downloaded for this excerpt.

## Used for

| Table | File / label | Glyphs |
|---|---|---|
| UI glyph subset (RCQ-38 l10n L2) | `src/gui/l10n_glyphs.inc` `l10n_glyph_cps` / `l10n_glyph_bits`, included once by `src/gui/l10n_paint.asm` | 5195 16x16 glyphs: every wide scalar of the six UI catalogs (`gauntlet_v2/docs/localization/catalog.rc1.v1.json`), of offline Help (`catalog.offline-help.en.v1.json`) and of the Terminal help lines (`catalog.l5.v1.json`, whose wide cells the Terminal takes from this subset), U+FF08 FF09 FF0C FF1A FF1B FF1F 3002, the endonyms 日本語 / 简体中文, and the whole hiragana U+3041-3096 and katakana U+30A1-30FA blocks (kana R2, for the IME), and every JIS X 0208 / GB2312 level-1 ideograph (step B, for IME candidates) |

- **How:** `python3 gauntlet_v2/tools/l10n_bind_check.py subset --unifont <unifont.hex>` refuses any input but the
  pinned file and cuts the closure's lines verbatim; `l10n_bind_check.py emit` converts them (32 B a glyph, 16 rows of
  2 bytes, MSB = leftmost pixel). Nothing is redrawn.
- **Gates:** `make lint` (`l10n_bind_check.py check`: the include equals a fresh emit; the excerpt holds exactly the
  closure, so a catalog scalar without a glyph fails the build) and
  `gauntlet_v2/tests/test_rcq38_l10n_bind_check_host.py` (re-cuts the excerpt from the pinned package; byte-identity).
- **Known issue (RC1):** Japanese text uses unified Han glyph forms for 67 shared characters (root 2026-10-11 01:42:35).

## Public offline regeneration (2026-10-15)

`python3 tools/l10n/gen_ui.py --emit NEW_DIRECTORY` regenerates the existing
UI table (520 cells then; 739 since 2026-10-16, below) and English UI/help include exactly, plus the six PCAT1
catalogs. `--check` compares both native includes. Selected public declarations,
helper identities and the precise recipe are in `third_party/localization/`.
The original subset above remains unchanged and was rechecked line by line
against the exact full input hash above. All source lines retain their original
scalar identities and pixels; no font is redrawn or taken from the host.
`Unifont.COPYING` and `OFL-1.1.txt` are the complete original upstream 15.1.01
grants, retained verbatim from archive SHA256
`e15f4209a2f7937951681f4522b21a4deb9fb36220c82f8b8cb66e2b1466cdb7`
(https://unifoundry.com/pub/unifont/unifont-15.1.01/unifont-15.1.01.tar.gz).
The elected font license remains OFL-1.1. Original copyrights and license
alternatives are preserved, as for the accepted Terminal source delivery.

## Help and Terminal help glyphs (2026-10-16)

The closure now also covers offline Help and the Terminal help lines (L5), the
two other catalogs the image paints: a translated ja/zh-Hans record with an
ideograph the subset lacked painted as English (l10n_paint's whole-record
fallback). That adds 219 lines (ja 95 / zh-Hans 154 scalars, overlapping), cut
verbatim from the same pinned `unifont.hex` by the same `subset` command; the
original 520 lines are unchanged. 739 x 36 B = 26,604 B of table data.
The RC1 known issue widens with it: Unifont has one form per code point, so
Japanese shows the unified Han form of the 129 ideographs that both ja and
zh-Hans use across the three catalogs (69 in the UI catalogs alone).

## JIS X 0208 / GB2312 level-1 ideographs (2026-10-16, step B)

Root 2026-10-16 19:12:27: the subset also holds every JIS X 0208 level-1 and
GB2312 level-1 ideograph, so IME candidates paint and not only catalog text.
The selection is Unicode 15.1.0 Unihan's normative IRG sources, J0 rows 16-47
(2965) and G0 rows 16-55 (3755), 5009 in all, all in U+4E00-9FFF; every one has
a 16x16 cell in the pinned `unifont.hex`. The 553 catalog ideographs are all in
level 1, so 4456 lines are added (5195 lines, 5195 x 36 B = 187,020 B of table
data), cut verbatim by the same `subset` command; the 739 lines above are
unchanged. The selection lines are vendored in
`third_party/localization/Unihan_IRGSources.level1.txt` (`c5442d5bcf916d7682f5f0567dae30183df9950e7fc8b5e3d295dd1719a0a865`,
Unicode-3.0; see THIRD_PARTY_NOTICES.md). Level 2 (JIS X 0208 rows 48-84, GB2312
rows 56-87) waits for a font pack. Unified Han forms remain as above: there is
no locale-form claim.
