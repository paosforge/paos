# Public Terminal glyph regeneration

This bounded recipe regenerates the existing `src/gui/vt/vt_font.inc`, including
3452 regular cells (765 Terminus, 2399 Unifont, 288 procedural), 476 Terminus
bold cells, 41 Unifont wide cells and 17 transparent combining-mark cells.
The expected SHA-256 is
`e3716cefd014aee251378756ad13730346422d63228fdd5741549406804932a1`.

From a prepared public source checkout, with Python 3.10+ standard library only:

```sh
python3 tools/fonts/gen_vt_font.py --check
python3 tools/fonts/gen_vt_font.py --emit /tmp/terminal-rebuild-a
python3 tools/fonts/gen_vt_font.py --emit /tmp/terminal-rebuild-b
cmp /tmp/terminal-rebuild-a/vt_font.inc /tmp/terminal-rebuild-b/vt_font.inc
cmp src/gui/vt/vt_font.inc /tmp/terminal-rebuild-a/vt_font.inc
python3 -m unittest discover -s tools/fonts -p test_vt_font.py
```

The converter defaults to stdout for the historical factory wrapper. It reads
only this directory's pinned inputs, grants, notices and recipe; `--check` also
reads the delivered include. It never reads system fonts, environment overrides,
private build tools or network inputs. Missing/changed source, license or recipe
and symlink escapes fail before an emitted directory is created. The converter
and these tests are delivered under public `tools/fonts/`. Historical generated
comments retain the old factory path solely to preserve byte identity.

## Exact origin and license election

See `NOTICE.md`, the complete `Terminus.NOTICE`, `Unifont.COPYING` and
`OFL-1.1.txt`. PaOS elects SIL OFL 1.1 for font data, preserves copyright/RFN
notices, and names the modified combined font `vt_font`.

The two PSFs are exact bytes of Ubuntu 24.04 console-setup-linux 1.226ubuntu1.
The complete Terminus section was extracted verbatim from
`console-setup/copyright.fonts` (whole-file SHA-256
`adeb95d45c8f1b944dc21032e74ea2e5636e0f4a34a63783fd37044af9852dcb`)
in [console-setup_1.226ubuntu1.tar.xz](https://archive.ubuntu.com/ubuntu/pool/main/c/console-setup/console-setup_1.226ubuntu1.tar.xz),
archive SHA-256 `efa5899294f656f7d1c1450acf55c4a56c01ad8a9416bb175a81a7f18336f2f0`.
These are the same PSF inputs pinned by the prior Terminal provenance gate.

`vt-unifont.hex` is the minimal sufficient set of 2457 verbatim source lines
from Ubuntu unifont 1:15.1.01-1build1's full `unifont.hex` (SHA-256
`341bc797b532c269a0b8e75dce05c98f2a5d04de08a5af1eef4a0aa7587ce31c`).
The original package SHA-256 is
`f5d7516c5a430dc6ee8266fd333cc49339407865916462d608b8478b1e3a84a1`.
Only regular cells that fall through Terminus/procedural selection, wide cells
and combining marks are retained, in original order, with no bitmap edits.
Every retained cell was also compared to the original upstream plane00 inputs
(`unifont-base.hex`, `spaces.hex`, `plane00-nonprinting.hex`,
`plane00-unassigned.hex`) with exact equality.

The upstream archive is
[unifont-15.1.01.tar.gz](https://unifoundry.com/pub/unifont/unifont-15.1.01/unifont-15.1.01.tar.gz),
SHA-256 `e15f4209a2f7937951681f4522b21a4deb9fb36220c82f8b8cb66e2b1466cdb7`.
Its complete COPYING grant explicitly dual-licenses font files under SIL OFL
1.1 or GPL-2-or-later with font embedding exception. PaOS elects OFL-1.1.
Both source archives and grant hashes were rechecked against the prior
provenance record when preparing this delivery. Regeneration needs no download.

## Fixed coverage and unchanged behavior

`coverage.json` freezes the finite glyph selection made by the pinned original
converter with Python Unicode 15.0.0. Its regular and wide codepoint sets match
those in the pinned include independently; the 17 combining marks retain the
original explicit order. This avoids changes when Python's Unicode database is
updated. It is font subset mapping data, not a replacement Unicode database.
The public converter uses that fixed selection and the original PSF mapping,
Terminus-first fallback, Unifont cells, procedural geometry and output layout.

`vt_tables.inc`, general Unicode properties/widths, and their source/license
closure remain separate unresolved components. This recipe does not change
runtime Unicode behavior, font design or the full public-build clearance state.

## Delivered input pins

| File | SHA-256 |
| --- | --- |
| `Uni2-Terminus16.psf.gz` | `76b38323e80e09cd44a4ca4b0eaa681101874f208b8b5ba00c8c594cfd3b91c2` |
| `Uni2-TerminusBold16.psf.gz` | `e47636ab76907452e449194dd4c3cd47f7a2c72afcdd9597d3eb8c8f95a0ebed` |
| `vt-unifont.hex` | `b6f750fb28ea9d84e948f0b7bfbe6a68e04d8a2bc48971cd18b90a7545d9b5e7` |
| `coverage.json` | `2a9fa6dd704b7a2fb0f2e3f10bfe83d0982310f22d4e2869fca6512877474474` |
| `Terminus.NOTICE` | `c5aecee192f48b9d736f52516dfd4fde776be2fd7b5ae37067fa73cd5843efa2` |
| `Unifont.COPYING` | `5a65797606332f2f63057fd81ea0ff35f74043583515bf900ee9b42efa8176a6` |
| `OFL-1.1.txt` | `869692af094c57fb7258c57fe26820c759319603321d0ffeb278de3651763ded` |
| `NOTICE.md` | `c30582331cecd28fc51a5086d5781244eba08771ae12a987b3cd7bb59be47ab3` |
