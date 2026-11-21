# Third-party notices: vendored fonts

Each vendored font keeps its own licence. This file is the notice text for the fonts under `third_party/fonts/`; the
repository-wide list is `THIRD_PARTY_NOTICES.md` at the repository root (it also covers the Terminal's `vt_font`,
whose Terminus/Unifont inputs and complete grants are now delivered under `terminal/`).

## Spleen 8x16 2.1.0 (BSD-2-Clause)

- **Files:** `spleen/spleen-8x16.bdf` (unmodified), `spleen/LICENSE` (verbatim), `spleen/SOURCE.md` (URL, tag,
  commit, SHA-256 pins).
- **Embedded in PaOS binaries as converted glyph cells:**
  - the PaOS payload: `src/gui/font8x16.inc` `font_8x16` (the GUI font: ASCII and U+00A0..U+017F, including `font_8x16_ext_a`) and `src/boot/boot_menu.asm`
    `bm_face_ocr_font` (the boot-menu face) and `src/boot/boot_face.asm` `bf_font` (the public loading face's version
    text);
  - the Boot Manager: `src/bootmgr/paos_bootmgr.asm` `face_ocr_font`.
- **Conversion:** `tools/fonts/font_build.py` (deterministic, cell for cell), with the public
  recipe in `spleen/SOURCE.md` and checks in `tools/fonts/test_font_build.py`.
- **Binary redistribution:** this notice (copyright, conditions and disclaimer below) must accompany every
  distributed PaOS payload or Boot Manager image, in its documentation or other materials (BSD-2-Clause condition 2).

```
Copyright (c) 2018-2024, Frederic Cambus
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

## GNU Unifont 15.1.01 UI glyph subset (SIL OFL 1.1)

- **Files:** `unifont/unifont-ui-subset.hex` (lines of the pinned `unifont.hex`, unmodified), `unifont/LICENSE`
  (the SIL OFL 1.1 text), `unifont/SOURCE.md` (package, file and SHA-256 pins).
- **Embedded in the PaOS payload as converted glyphs:** `src/gui/l10n_glyphs.inc` (16x16, included by
  `src/gui/l10n_paint.asm`). Conversion: `gauntlet_v2/tools/l10n_bind_check.py` (deterministic).
- **Binary redistribution:** the SIL OFL 1.1 text and the Unifont copyright notices in `THIRD_PARTY_NOTICES.md` at the
  repository root ("GNU Unifont glyphs (SIL OFL 1.1): the UI glyph subset") accompany every distributed payload.

## Terminal glyph data (SIL OFL 1.1 election)

`terminal/` contains the exact two Terminus Font PSFs, minimal verbatim GNU
Unifont 15.1.01 cells, and fixed existing font coverage. `terminal/NOTICE.md`
retains copyrights, the Terminus Reserved Font Name, and the OFL election;
`terminal/Terminus.NOTICE`, `terminal/Unifont.COPYING` and `terminal/OFL-1.1.txt`
retain complete original grants. Preserve them with font source/binary copies.
The modified combined table is named `vt_font`. See `terminal/SOURCE.md` and
`tools/fonts/gen_vt_font.py` for the public byte-exact recipe and pinned inputs.
This does not close the separate Unicode property/width/table source gap.
