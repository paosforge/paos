# Third-party notices for PaOS

PaOS uses MPL-2.0 for PaOS-owned core and Apache-2.0 for app interfaces, SDK,
verb registry definitions and Forge tools (project policy of October 1, 2026). See `LICENSE`.
Third-party components retain their own terms. This notice inventory remains
incomplete for a final distribution: file origins, flagged native NIC derivations,
nested component sources and selected artifact bindings still require review.
This snapshot is a source preview, not a release distribution.

## Spleen 8x16 bitmap font (BSD-2-Clause)

- **Used in:**
  - `src/gui/font8x16.inc` `font_8x16`: the GUI font (0.0.55; it replaces IBM VGA/CP437 data). U+0020..U+007E are
    Spleen cells; U+0000..U+001F are blank (the source encodes no C0 glyphs) and U+007F is Spleen's blank cell;
    0x80..0xFF are blank;
  - `src/bootmgr/paos_bootmgr.asm` `face_ocr_font`: the Boot Manager face glyphs U+0020..U+007E; the control rows are
    blank cells;
  - `src/boot/boot_menu.asm` `bm_face_ocr_font`: the 22-glyph compact copy of the same face;
  - `src/boot/boot_face.asm` `bf_font`: the 41-glyph copy (U+002B..U+0039, U+0061..U+007A) for the public loading
    face's version text.
- **Source:** Spleen 2.1.0 by Frederic Cambus, https://github.com/fcambus/spleen (tag `2.1.0`, commit
  `c3b655c5718757863e828c02115e96b149281159`), release tarball `spleen-2.1.0.tar.gz`
  (SHA-256 `8b47c56f1a6eb858fbcf9e34530557404b02fbb3455e38e64fb84473fd0c372f`), file `spleen-8x16.bdf`
  (SHA-256 `b2b05484ba4380c9c6854cc57637235a9fb039c65b5ba38a65289540f8fab7dc`).
- **How:** the BDF is vendored unmodified in `third_party/fonts/spleen/` with its LICENSE and a SOURCE.md, and
  converted cell for cell into 16-byte rows by `tools/fonts/font_build.py` (`gen_spleen_face_tables.py` is a
  compatibility entry point into it). `test_font_provenance_host.py` regenerates all three tables and requires an
  exact match; `test_manager_face_font_provenance.py` still gates the two face tables. Notice text for the vendored
  fonts: `third_party/fonts/THIRD_PARTY_NOTICES.md`.
- **Why:** it replaces Ubuntu Mono Bold glyphs (Ubuntu Font Licence) in the Manager/boot-menu face, per a project decision of
  2026-10-01, and the IBM VGA/CP437 GUI font (provenance audit 2026-10-01,
  ROADMAP LICENSE CLEANUP item 2).

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

## Terminus Font and GNU Unifont glyphs (SIL OFL 1.1): the Terminal's font

- **Used in:** `src/gui/vt/vt_font.inc`, the 8x16 tables of the Terminal (`src/gui/terminal_app.asm`, hub packet
  0009). It holds 3452 regular glyphs: Terminus 765, GNU Unifont 2399, procedural 288 (U+2580..259F block elements
  and U+2800..28FF braille, drawn from their geometry). It also holds 476 bold glyphs (Terminus Bold) and 41 16x16
  wide glyphs (Unifont). The file carries `SPDX-License-Identifier: OFL-1.1`.
- **Sources** (exact PSFs and minimal verbatim Unifont cells now vendored in
  `third_party/fonts/terminal/`; the public recipe pins every delivered input):
  - Terminus Font by Dimitar Toshkov Zhekov, as the PSF builds in Ubuntu 24.04 `console-setup-linux`
    1.226ubuntu1:
    - `/usr/share/consolefonts/Uni2-Terminus16.psf.gz`
      (`76b38323e80e09cd44a4ca4b0eaa681101874f208b8b5ba00c8c594cfd3b91c2`);
    - `Uni2-TerminusBold16.psf.gz` (`e47636ab76907452e449194dd4c3cd47f7a2c72afcdd9597d3eb8c8f95a0ebed`).

    That package's `copyright.fonts` states: "Terminus Font is licensed under the SIL Open Font License,
    Version 1.1. Copyright (c) 2010 Dimitar Toshkov Zhekov, with Reserved Font Name "Terminus Font"."
  - GNU Unifont 15.1.01 (Roman Czyborra, Paul Hardy and the Unifont contributors), from the Ubuntu package
    `unifont` 1:15.1.01-1build1:
    - `unifont_1%3a15.1.01-1build1_all.deb` (`f5d7516c5a430dc6ee8266fd333cc49339407865916462d608b8478b1e3a84a1`);
    - its `usr/share/unifont/unifont.hex` (`341bc797b532c269a0b8e75dce05c98f2a5d04de08a5af1eef4a0aa7587ce31c`).

    Upstream (https://unifoundry.com/unifont/) has dual-licensed the fonts since 13.0.04: SIL OFL 1.1, or GNU
    GPL 2+ with the font embedding exception. **PaOS elects the SIL OFL 1.1.**
    - The historical terminal-font receipt records the exact upstream 15.1.01 archive
      SHA-256 `e15f4209a2f7937951681f4522b21a4deb9fb36220c82f8b8cb66e2b1466cdb7`,
      its COPYING/OFL grant, and regeneration from upstream glyphs. Its generated
      table hash `50c929c9d803b6a20bff35a1db5ccc751a77dda9e58d0ea6ff976b22badae82d`
      predates the current combining-mark tables. The current exact table SHA-256 is
      `e3716cefd014aee251378756ad13730346422d63228fdd5741549406804932a1`.
      See the preserved `TERMINAL_FONT_PRIOR_RECEIPT.json` and
      `NOTICE_BINDINGS.json` in `gauntlet_v2/docs/rc_standing_source/RCQ-31-notices/`.
      The public Terminal delivery rechecked both original source archive and grant hashes.
      Its recipe requires no downloads; no new font design or glyph bytes were introduced.
- **How:** `tools/fonts/gen_vt_font.py` regenerates the exact delivered table offline; see
  `third_party/fonts/terminal/SOURCE.md` for source archive/input hashes, license election and commands.
  The two PSFs are unmodified, and `vt-unifont.hex` is 2457 verbatim source lines, each checked against
  upstream 15.1.01. `Terminus.NOTICE`, `Unifont.COPYING` and `OFL-1.1.txt` retain the complete grants.
  Fixed font coverage preserves the original Unicode-15.0 selection without using a host Unicode database.
  Nothing is redrawn. The modified combined subset is `vt_font`, never "Terminus Font".
  The old factory entry point delegates to the same public converter. Unicode property/width table
  regeneration and its source/license closure remain a separate unresolved component.
- **Not distributed:** the host-only grading tools (`gauntlet_v2/tools/vtref/vtref.c` and
  `gauntlet_v2/tools/vt/vt_keytest.c`) link libvterm 0.3.3 (MIT), and `vt_tmuxref.py` drives tmux (ISC). None of this
  is in the PaOS image.

```
Terminus Font: Copyright (c) 2010 Dimitar Toshkov Zhekov, with Reserved Font Name "Terminus Font".
GNU Unifont glyph copyright notices retained from the source-package inventory: Copyright 1998-? Jungshik Shin, 1998-2014 Roman Czyborra, 2004-2013 Qianqian
Fang, 2005 Luis Alejandro Gonzalez Miranda, 2007-2019 Paul Hardy, 2013-2014 Andrew Miller, 2017-2019 David
Corbett, 2018 Johnnie Weaver.

SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
-----------------------------------------------------------

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created
using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```


## GNU Unifont glyphs (SIL OFL 1.1): the UI glyph subset

- **Used in:** `src/gui/l10n_glyphs.inc`, the 16x16 glyphs `gui/l10n_paint.asm` paints catalog text with (RCQ-38
  l10n L2). It holds 5195 wide glyphs: every wide scalar of the six UI, offline Help and Terminal help (L5) catalogs,
  the CJK full-width punctuation set,
  the language endonyms, the whole hiragana and katakana blocks, and every JIS X 0208 / GB2312 level-1 ideograph
  (5009, for IME candidates; the selection is Unicode Unihan data, below). Han characters use Unifont's default forms.
- **Source** (vendored as an excerpt): `third_party/fonts/unifont/unifont-ui-subset.hex`
  (`6c4b16cf4cb8f53e3d8d9bf8da012271547c10bf0fb2bec60dfebac042b42d73`), 5195 lines cut verbatim from the same
  pinned GNU Unifont 15.1.01 input as the Terminal's font above: the Ubuntu package `unifont` 1:15.1.01-1build1, `unifont_1%3a15.1.01-1build1_all.deb`
  (`f5d7516c5a430dc6ee8266fd333cc49339407865916462d608b8478b1e3a84a1`), its `usr/share/unifont/unifont.hex`
  (`341bc797b532c269a0b8e75dce05c98f2a5d04de08a5af1eef4a0aa7587ce31c`). **PaOS elects the SIL OFL 1.1.**
  `third_party/fonts/unifont/SOURCE.md` records the pins; `third_party/fonts/unifont/LICENSE` is the OFL text.
- **How:** `gauntlet_v2/tools/l10n_bind_check.py subset` cuts the excerpt from the pinned `unifont.hex` and `emit`
  converts it into the include. Nothing is redrawn. The table is a modified subset and is not named "Unifont".
  `make lint` (`l10n_bind_check.py check`) requires the include to equal a fresh emit, and
  `gauntlet_v2/tests/test_rcq38_l10n_bind_check_host.py` re-cuts the excerpt from the pinned package and requires
  byte-identity.
- **Level-1 selection (Unicode Unihan, Unicode-3.0):** `third_party/localization/Unihan_IRGSources.level1.txt`
  (`c5442d5bcf916d7682f5f0567dae30183df9950e7fc8b5e3d295dd1719a0a865`) is an excerpt of Unicode 15.1.0 `Unihan_IRGSources.txt`
  (`a3bcdfd405e1ace254ab7f88ead8dc424f112123fb940c32cb6374c02102dc6e`, the member of
  `https://www.unicode.org/Public/15.1.0/ucd/Unihan.zip`, `a0226610e324bcf784ac380e11f4cbf533ee1e6b3d028b0991bf8c0dc3f85853`;
  byte-identical to Ubuntu `unicode-data` 15.1.0-1): its 11-line header with the Unicode copyright notice, then the
  6720 `kIRG_JSource` J0 rows 16-47 and `kIRG_GSource` G0 rows 16-55 lines, verbatim and in file order. It only
  selects which Unifont cells are cut; no Unicode data is compiled into the image. Terms:
  [LICENSES/Unicode-3.0.txt](LICENSES/Unicode-3.0.txt). `l10n_bind_check.py level1 --unihan` re-cuts it from the
  pinned file, and the host suite requires byte-identity.

```
GNU Unifont glyph copyright notices retained from the source-package inventory: Copyright 1998-? Jungshik Shin, 1998-2014 Roman Czyborra, 2004-2013 Qianqian
Fang, 2005 Luis Alejandro Gonzalez Miranda, 2007-2019 Paul Hardy, 2013-2014 Andrew Miller, 2017-2019 David
Corbett, 2018 Johnnie Weaver.

SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
-----------------------------------------------------------

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created
using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```

## DejaVu Sans Mono / Bitstream Vera

`src/gui/font_aa9x19.inc` is rasterized from the exact Ubuntu DejaVu Sans Mono
2.37-8 font. The complete original font grants (including Arev) and preferred
editable SFD source accompany the exact TTF in `third_party/fonts/dejavu/`.
Its offline public recipe `tools/fonts/gen_aa.py` builds FreeType 2.14.1 from
the delivered full source archive, with its FTL election and complete notices.
Portions of this software are copyright © 1996-2025 The FreeType Project
(www.freetype.org). All rights reserved. This is a source build dependency,
not a new native PaOS library. See `third_party/fonts/dejavu/SOURCE.md`.
The existing 95-cell atlas, clipping, grayscale coverage and KAT stay exact.
Copyright (c) 2003 by Bitstream, Inc. All Rights Reserved.
Bitstream Vera is a trademark of Bitstream, Inc. DejaVu changes are in public domain.
The full permission notice, conditions and disclaimer are in
[LICENSES/Bitstream-Vera.txt](LICENSES/Bitstream-Vera.txt). Keep that file with
source and binary distributions containing the rasterized glyphs.

## TweetNaCl

`src/core/lib/x25519.asm` and `src/core/lib/ed25519.asm` identify TweetNaCl as
an implementation source. TweetNaCl is public domain, by Daniel J. Bernstein,
Bernard van Gastel, Wesley Janssen, Tanja Lange, Peter Schwabe and Sjaak Smetsers.
Upstream: https://tweetnacl.cr.yp.to/ . The courtesy declaration is in
[LICENSES/LicenseRef-TweetNaCl-Public-Domain.txt](LICENSES/LicenseRef-TweetNaCl-Public-Domain.txt).
Original public-domain material is distinct from PaOS-owned modifications.

## Unicode 15.0.0 width data

`src/gui/vt/vt_tables.inc` retains the historical Unicode 15.0.0 bytes. Its
public recipe now reads exact pinned UCD 15.0.0 DATA, independently matched to
the original Python database over every code point. The editor retains UCD
15.1.0, and keyboard layout DATA retains CLDR43, with their complete grants
in LICENSES/Unicode-15.1-DATA.txt and LICENSES/Unicode-DFS-2016.txt.
The source inputs and offline recipe are in
[third_party/unicode/SOURCE.md](third_party/unicode/SOURCE.md). Retain the release
notice in [LICENSES/Unicode-15.0.0-NOTICE.txt](LICENSES/Unicode-15.0.0-NOTICE.txt)
and the full terms in [LICENSES/Unicode-3.0.txt](LICENSES/Unicode-3.0.txt).
No Unicode font or code-chart image is included by this notice.

## Native I219 and RTL8168 replacement-source notices

The current tree includes both drivers. The completed fact records are
`gauntlet_v2/docs/CLEANROOM_E1000E_SPEC.md` and `CLEANROOM_RTL8168_SPEC.md`.
Their notice packet is retained in [LICENSES/I219_NOTICES.md](LICENSES/I219_NOTICES.md)
and [LICENSES/RTL8168_NOTICES.md](LICENSES/RTL8168_NOTICES.md), with original
upstream URLs, pinned revisions, copyright notices and all conditions.
I219 references Intel BSD-3-Clause, FreeBSD BSD-2-Clause and DPDK BSD-3-Clause
material. RTL8168 references include Bill Paul's **BSD-4-Clause** terms and
BSD-3-Clause/USL notices. The required advertising acknowledgment is:

> This product includes software developed by Bill Paul.

Retain it in applicable advertising materials mentioning features or use of the
covered software. Placement in the eventual release/site materials still needs
review. The fact-record hashes match the prior packet; current driver hashes
have changed and need selected-binary binding. Peter116520 / ROOT116522 (11/12):
RTL8168 complies with its notices permanently, including the advertising
acknowledgment; no RTL8168 derivation check or counsel dependency. This does not
clear I219 or other unresolved provenance leads. AX88179, RTL8125/RTL8126 and the
other provenance leads remain unresolved; none receives an MPL grant by virtue
of this file.

## Native RTL8125 and RTL8126 OpenBSD rge(4) notices (ISC)

`src/dev/net/rtl8125.asm`, `src/dev/net/rtl8126.asm` and
`src/dev/net/rtl8126_bsd_facts.inc` reference the pinned OpenBSD rge(4)
sources `sys/dev/pci/if_rge.c` and `sys/dev/pci/if_rgereg.h` (ISC):

> Copyright (c) 2019, 2020, 2023-2025 Kevin Lo <kevlo@openbsd.org>
> Copyright (c) 2019, 2020, 2025 Kevin Lo <kevlo@openbsd.org>

Both notices, with the full ISC permission and disclaimer text, upstream URLs
and pinned revisions, are retained in
[LICENSES/RGE_OPENBSD_ISC_NOTICES.md](LICENSES/RGE_OPENBSD_ISC_NOTICES.md).
This is notice compliance only (ROOT118591): RTL8125/RTL8126 provenance and
similarity review remain unresolved, and no MPL grant follows from this entry.

## Mozc romaji preedit conversion table (BSD-3-Clause)

- **Used in:** `packaging/public_build_inputs/ime/ja.inc`, label `ime_ja_table`:
  the compiled-in romaji preedit conversion DATA linked into `paos.efi` by
  I3b-1 when `IME_BUILT=1`. The 322-row table is 2,844 assembled bytes.
- **Source:** [Google Mozc](https://github.com/google/mozc), commit
  `18e76511af9371a9a4409b1d13c3e30884b53e9c`, file
  `src/data/preedit/romanji-hiragana.tsv` (upstream spelling), SHA-256
  `fcb900e311d32ced05499c86e236d1084fb0c0937398deb6311fc6c7287a7821`.
  Its exact retained copy is `packaging/public_build_inputs/ime/romaji-hiragana.tsv`.
- **How:** `gauntlet_v2/tools/rcq38_ime_tables.py` packs the pinned mappings
  and carry rules into sorted keys and a scalar pool. The include is emitted
  from the same bytes as `ja.bin`; I3b-1 includes it unchanged. The include's
  SHA-256 is `f3d0c1040a861349ae0440e750a3f8f7f0fb5e89c7f0f0048f113fe9d5156906`;
  the assembled DATA SHA-256 is
  `57c2ee1e390e865e53caba9c681e099cef604ed5828c8ef720b80675a42ad324`.
- **License:** Copyright 2010-2018, Google Inc.; BSD-3-Clause. The complete
  upstream [MOZC-LICENSE.txt](packaging/public_build_inputs/ime/MOZC-LICENSE.txt)
  is retained verbatim, SHA-256
  `44cdd923b91ea9199293abecc2762c70c87dbf1e581c027a94c416368d1a648c`.
  Its dictionary-specific sections remain in that file; I3b-1 uses the
  preedit table, without the Mozc engine or those dictionaries. Keep this
  notice and the full license with source and binary distributions containing
  the table. The applicable Google copyright, conditions and disclaimer are:

```
Copyright 2010-2018, Google Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following disclaimer
    in the documentation and/or other materials provided with the
    distribution.
  * Neither the name of Google Inc. nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Rime pinyin-simp syllable inventory (Apache-2.0)

- **Used in:** `packaging/public_build_inputs/ime/zh.inc`, label `ime_zh_table`:
  the compiled-in Pinyin syllable-validation DATA linked into `paos.efi` by
  I3b-1 when `IME_BUILT=1`. The 415-syllable table is 1,724 assembled bytes.
- **Source:** [Rime rime-pinyin-simp](https://github.com/rime/rime-pinyin-simp),
  commit `0c6861ef7420ee780270ca6d993d18d4101049d0`, file
  `pinyin_simp.dict.yaml`, SHA-256
  `e341598343a0f0f2035bb1aafc34a7f3bb7887deeecb3f60796262aaa2983e6b`.
  The original header attributes the dictionary to the Android Open Source
  Project's PinyinIME; its exact attribution is retained in
  [PINYIN-SOURCE-HEADER.txt](packaging/public_build_inputs/ime/PINYIN-SOURCE-HEADER.txt):

  > Derived from android open source project:
  > http://android.git.kernel.org/?p=platform/packages/inputmethods/PinyinIME.git

- **How:** `gauntlet_v2/tools/rcq38_ime_tables.py` extracts the union of
  readings, normalizes ü/u: to ASCII v, sorts and deduplicates the syllables,
  and packs six-letter keys. The derived inventory is retained in
  `packaging/public_build_inputs/ime/pinyin-syllables.txt`. The include is emitted
  from the same bytes as `zh.bin`; I3b-1 includes it unchanged. The include's
  SHA-256 is `2346396915b947d32df4ed2c262ac5cdd10c9ad17882be11e847b9afcf81a391`;
  the assembled DATA SHA-256 is
  `df138bde43f28da29d8417c89e5bb93246223c6e86c7ede55fd23930eeb6ff7f`.
  I3b-1 includes these syllable keys, without a PDCT dictionary shard or a
  `res_pack` dictionary reader.
- **License:** Apache License, Version 2.0. The full upstream license is
  retained verbatim in
  [PINYIN-APACHE.txt](packaging/public_build_inputs/ime/PINYIN-APACHE.txt), SHA-256
  `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.
  The upstream [PINYIN-README.txt](packaging/public_build_inputs/ime/PINYIN-README.txt)
  and source header retain the original source attribution. Keep this notice,
  the full license and those attribution files with distributions containing
  the table. The generated inventory and packed representation are PaOS's
  transformations of the pinned upstream DATA, as described above.

The exact source and output bindings for both tables are recorded in
manifest.json (internal, not in this snapshot); the accepted
DATA/consumer contract is TABLES.md (internal, not in this snapshot). These
entries cover the compiled-in tables and do not qualify a later dictionary
pack, engine or external resource distribution.

## Nested binaries and other inputs still under review

Rescue, Linux guests, GRUB, shim, static libraries, browser inputs, firmware,
models, images and bundled host tools need an exact selected-component inventory,
license/notice map and corresponding source/relink inputs where applicable.
Peter116520 / ROOT116522: ship complete corresponding source next to every
binary with GPL code (GPLv2 3(a)); no written source offer or counsel check.
This file is not the corresponding source. Public source curation must exclude the
private development factory, vendor ACPI fixtures and serial-bearing lab data.
The readiness gates remain red until their evidence is complete.

## Xiph Opus range entropy primitives (BSD-2-Clause)

- **Used in:** `src/media/opus_range.asm`, an assembly port of the range decoder
  and fractional bit-accounting thresholds from Xiph Opus 1.5.2
  `celt/entdec.c` and `celt/entcode.c`. This module is currently unwired.
- **Source:** [official Opus 1.5.2 release](https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz),
  SHA-256 `65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
- **Terms:** copyright and complete grant/disclaimer retained in the assembly
  and [Xiph range notice](LICENSES/XIPH_OPUS_RANGE.txt). Include that notice
  with any binary distribution containing this port. No codec synthesis or
  other Xiph source is incorporated by this change.
- **Host tests:** compile the unmodified release's range encoder/decoder as an
  independent oracle; it is external test material, not linked into PaOS.


## Xiph Opus CELT band energy (BSD-2-Clause)

- **Used in:** `src/media/opus_celt_energy.asm`, a fixed-point assembly port of
  the standard CELT coarse/fine/final energy reconstruction, exact probability
  tables and Laplace energy-delta decoder from Opus 1.5.2 `celt/quant_bands.c`
  and `celt/laplace.c`. The module is currently unwired.
- **Source:** the official Opus 1.5.2 archive identified above; source hashes
  and the stage ABI are recorded in [the energy documentation](docs/OPUS_NATIVE_CELT_ENERGY.md).
- **Terms:** CSIRO 2007 / 2007–2008, Xiph.Org Foundation 2007–2009; written by
  Jean-Marc Valin. Copyright, complete grant and disclaimer are retained in
  the assembly and [energy notice](LICENSES/XIPH_OPUS_CELT_ENERGY.txt). Include
  this notice in distributions containing the port.
- **Host tests:** compile unmodified upstream fixed-point energy functions and
  encoders from external, hash-pinned source. Those C functions are oracle
  material and are not linked into PaOS. This stage supplies no PVQ, synthesis
  or PCM playback.

## Xiph Opus CWRS/PVQ pulse vectors (BSD-2-Clause)

- **Used in:** `src/media/opus_cwrs.asm`, an unwired assembly port of the
  integer U-row recurrence and signed pulse-vector unranking from Opus 1.5.2
  `celt/cwrs.c`. The entropy stage calls the existing native range helper.
- **Source:** [official Opus 1.5.2 release](https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz),
  SHA-256 `65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`;
  `cwrs.c` SHA-256 `2080bc580870ef59b4382400ea79cbf0c4041d93e3e53175b01c1ac981ac4a8b`.
- **Terms:** copyright and full BSD grant/disclaimer retained in the assembly
  and [Xiph CWRS notice](LICENSES/XIPH_OPUS_CWRS.txt). Include the notice with
  binary distributions containing this port.
- **Host tests:** compile unmodified upstream CWRS and entropy encoder/decoder
  implementations in default and SMALL_FOOTPRINT configurations. They remain
  external test material. This slice does not implement complete PCM synthesis.

## Xiph Opus fixed-point PVQ band shapes (BSD-2-Clause)

- **Used in:** `src/media/opus_pvq.asm`, an unwired assembly port of Opus 1.5.2
  `vq.c` residual normalization, inverse spreading rotations and collapse mask,
  with the exact fixed-point reciprocal, reciprocal square root and cosine
  from `mathops.c`/`mathops.h`. Entropy decoding composes the native CWRS helper.
- **Source:** the official Opus 1.5.2 archive identified above. Exact source
  hashes and the bounded API are in [the PVQ documentation](docs/OPUS_NATIVE_PVQ.md).
- **Terms:** copyright Jean-Marc Valin 2002–2008, CSIRO 2007–2008 and Xiph.Org
  Foundation 2007–2009. Full copyright, grant and disclaimer are retained in
  the assembly and [Xiph PVQ notice](LICENSES/XIPH_OPUS_PVQ.txt). Include this
  notice in distributions containing the port.
- **Host tests:** compile the unmodified official fixed-point `alg_unquant`,
  normalization, rotation and entropy encoder as external oracle material.
  These C functions are not linked into PaOS. This stage supplies band shapes;
  full CELT allocation, transforms and PCM synthesis remain separate.

## Xiph Opus CELT time-frequency flags (BSD-2-Clause)

- **Used in:** `src/media/opus_tf.asm`, an unwired assembly port of Opus1.5.2
  `celt_decoder.c`'s `tf_decode` and `celt.c`'s exact signed selection table.
  The stage composes the native range decoder.
- **Source:** the official Opus1.5.2 archive identified above; hashes and the
  bounded ABI are recorded in [the TF documentation](docs/OPUS_NATIVE_TF.md).
- **Terms:** CSIRO 2007–2008, Xiph.Org Foundation 2007–2010, Gregory Maxwell
  2008; written by Jean-Marc Valin and Gregory Maxwell. Full copyright, grant
  and disclaimer are in the assembly and [Xiph TF notice](LICENSES/XIPH_OPUS_TF.txt).
  Include this notice in binary distributions containing the port.
- **Host tests:** compile unmodified official `tf_decode`, `tf_encode` and
  entropy implementations as external oracle material. They are not linked
  into PaOS. Per-band flags do not implement band transforms or PCM synthesis.

## Xiph Opus CELT Haar/Hadamard sample primitives (BSD-2-Clause)

- **Used in:** `src/media/opus_tf_shape.asm`, an unwired fixed-point assembly
  port of Opus1.5.2 `bands.c`'s `haar1`, `deinterleave_hadamard`,
  `interleave_hadamard` and exact inverted Gray ordering table.
- **Source:** the official Opus1.5.2 archive identified above; exact source pins
  and the bounded API are recorded in [the sample documentation](docs/OPUS_NATIVE_TF_SHAPE.md).
- **Terms:** upstream copyright, complete grant and disclaimer are retained
  in the assembly and [Xiph sample notice](LICENSES/XIPH_OPUS_TF_SHAPE.txt).
  Include the notice in distributions containing this port.
- **Host tests:** compile unmodified official fixed-point `bands.c` functions
  as external oracle material. They are not linked into PaOS. These primitives
  do not implement band allocation, full band orchestration or PCM synthesis.


## Xiph Opus CELT pulse budgets and caps (BSD-2-Clause)

- **Used in:** `src/media/opus_rate.asm`, an unwired assembly port of Opus1.5.2
  `rate.h`'s pseudo-pulse mapping and exact cache search, `celt.c`'s caps formula,
  and standard 48k mode bands/cache/index/caps constants from `modes.c` and
  generated `static_modes_fixed.h`.
- **Source:** official Opus1.5.2 archive identified above. Exact consumed pins
  and the bounded APIs are in [the rate documentation](docs/OPUS_NATIVE_RATE.md).
- **Terms:** CSIRO 2007–2008, Xiph.Org Foundation 2007–2010, Gregory Maxwell
  2008; original attribution and complete BSD grant/disclaimer are retained
  in the assembly and [Xiph rate notice](LICENSES/XIPH_OPUS_RATE.txt).
  Include the notice with binary distributions containing this port.
- **Host tests:** compile unmodified official `rate.h`, standard static mode and
  `init_caps` as external oracle material. They are not linked into PaOS.
  These helpers do not implement full allocation or PCM synthesis.


## Xiph Opus CELT allocation decode (BSD-2-Clause)

- **Used in:** `src/media/opus_allocation.asm`, an unwired port of standard-mode
  `clt_compute_allocation`/`interp_bits2pulses`, allocation/log/cap tables, and
  `init_caps` from Opus 1.5.2 `celt/rate.c`, `modes.c`, `static_modes_fixed.h`
  and `celt.c`.
- **Source:** the official Opus 1.5.2 archive identified above; exact source pins
  and an unmodified compiled encoder/decoder oracle are recorded in the SOURCE
  evidence. This helper does not provide complete frame/PCM playback.
- **Copyright:** 2007–2008 CSIRO; 2007–2010 Xiph.Org Foundation; 2008 Gregory
  Maxwell. Written by Jean-Marc Valin and Gregory Maxwell.
- **License:** the complete original notices, redistribution terms and disclaimer
  are retained in [LICENSES/XIPH_OPUS_ALLOCATION.txt](LICENSES/XIPH_OPUS_ALLOCATION.txt)
  and the assembly source.


## Xiph Opus CELT stereo reconstruction (BSD-2-Clause)

- **Used in:** `src/media/opus_stereo.asm`, an unwired fixed-point assembly
  port of Opus1.5.2 `bands.c:stereo_merge` and `mathops.c:celt_rsqrt_norm`.
- **Source:** the official Opus1.5.2 archive identified above. The bounded
  API and exact source hashes are in [the stereo documentation](docs/OPUS_NATIVE_STEREO.md).
- **Terms:** complete upstream copyright, grant and disclaimer are retained
  in the assembly and [stereo notice](LICENSES/XIPH_OPUS_STEREO.txt).
  Include the notice in distributions containing this port.
- **Host tests:** compile unchanged official fixed-point sources as an external
  oracle. They are not linked into PaOS. Full band decoding and PCM synthesis
  remain separate work.


## Xiph Opus CELT spectral denormalization (BSD-2-Clause)

- **Used in:** `src/media/opus_denorm.asm`, an unwired fixed-point port of
  Opus1.5.2 `bands.c:denormalise_bands`, `mathops.h:celt_exp2_frac`, and immutable
  standard-mode band boundaries and mean energies from `modes.c`/`quant_bands.c`.
- **Source:** the official Opus1.5.2 archive identified above; exact scope and
  source provenance are in [the spectral documentation](docs/OPUS_NATIVE_DENORM.md).
- **Terms:** full upstream copyrights, grants and disclaimers are retained in
  the assembly and [denormalization notice](LICENSES/XIPH_OPUS_DENORM.txt).
  Include the notice in distributions containing this port.
- **Host tests:** unchanged official fixed-point C sources and actual standard
  mode serve as external oracle material. They are not linked into PaOS.


## Xiph Opus CELT transient anti-collapse (BSD-2-Clause)

- **Used in:** `src/media/opus_collapse.asm`, an unwired fixed-point port of
  Opus1.5.2 anti-collapse noise filling, vector renormalization, reciprocal
  square root, fractional exponential and standard band boundaries.
- **Source:** unchanged official `bands.c`, `vq.c`, `mathops.c`/`mathops.h`
  and `modes.c` from the archive identified above. Exact finite API and
  provenance are in [the anti-collapse documentation](docs/OPUS_NATIVE_COLLAPSE.md).
- **Terms:** complete upstream copyrights, grants and disclaimers are retained
  in the assembly and [Xiph anti-collapse notice](LICENSES/XIPH_OPUS_COLLAPSE.txt).
  Include the notice in distributions containing this port.
- **Host tests:** unchanged official fixed-point C and its actual standard mode
  serve as external oracle material. They are not linked into PaOS.


### Native CELT split-angle decode

`src/media/opus_theta.asm` ports Opus1.5.2 `bands.c` split-angle decoding,
bit-exact gain math, standard-mode logN and signed division semantics. Complete
upstream notices and terms are retained in `LICENSES/XIPH_OPUS_THETA.txt` and
in the assembly. The unchanged official C reference is external host-test input.



## Xiph Opus CELT unsplit partition decoding (BSD-2-Clause)

- **Used in:** `src/media/opus_partition.asm`, an unwired fixed-point port of
  Opus 1.5.2 `bands.c:quant_partition`'s no-split decoding/resynthesis branch,
  `vq.c:renormalise_vector`, `mathops.c:celt_rsqrt_norm` and standard band widths.
- **Source:** official Opus 1.5.2 archive identified above; exact scope and
  provenance are in [the partition documentation](docs/OPUS_NATIVE_PARTITION.md).
- **Terms:** full upstream copyrights, grant and disclaimer are retained in the
  assembly and [partition notice](LICENSES/XIPH_OPUS_PARTITION.txt). Include
  the notice in distributions containing this port.
- **Host tests:** unchanged official sources and actual standard mode serve as
  external oracle material. They are not linked into PaOS. Recursive splitting,
  complete frame decoding and PCM playback remain separate work.



## Xiph Opus CELT deemphasis and PCM conversion (BSD-2-Clause)

- **Used in:** `src/media/opus_deemphasis.asm`, an unwired fixed-point port of
  Opus 1.5.2 `celt_decoder.c:deemphasis` and its stereo fast path, generic signed
  PCM rounding/saturation and the actual standard-mode feedback coefficient.
- **Source:** official Opus 1.5.2 archive identified above; scope and source
  provenance are in [the deemphasis documentation](docs/OPUS_NATIVE_DEEMPHASIS.md).
- **Terms:** full upstream copyrights, grant and disclaimer are retained in the
  assembly and [deemphasis notice](LICENSES/XIPH_OPUS_DEEMPHASIS.txt). Include
  the notice in distributions containing this port.
- **Host tests:** whole unchanged decoder/mode sources serve as an external
  oracle alongside an independent integer model. They are not linked into PaOS.
  Synthesis transforms, complete decoding and playback remain separate work.

## Xiph Opus CELT fixed-point pitch postfilter (BSD-style)

`src/media/opus_postfilter.asm` ports in-place `comb_filter` and its scalar
constant-filter behavior from official Opus1.5.2 `celt/celt.c`, with fixed-point
operations from `fixed_generic.h`/`arch.h` and the standard120-sample mode window.
Original copyright, conditions and disclaimer are retained in the source and
`LICENSES/XIPH_OPUS_POSTFILTER.txt`. Release provenance and accepted bounds are in
`docs/OPUS_NATIVE_POSTFILTER.md`; upstream comparison uses unchanged source from
the pinned official archive. The helper remains unwired to runtime playback.

## Xiph Opus CELT inverse MDCT and KISS FFT (BSD-3-Clause / BSD-2-Clause)

`src/media/opus_imdct.asm` ports Opus 1.5.2 scalar inverse MDCT, KISS FFT
butterflies and standard generated transform/window tables from `celt/mdct.c`,
`kiss_fft.c`, `_kiss_fft_guts.h`, `static_modes_fixed.h` and fixed-point macros.
Mark Borgerding, Jean-Marc Valin, Xiph.Org Foundation, CSIRO and Gregory Maxwell
hold the upstream copyrights. Complete applicable terms and source attribution
are retained in the assembly and [license](LICENSES/XIPH_OPUS_IMDCT.txt).
The official release archive identified above supplies the pinned sources;
[documentation](docs/OPUS_NATIVE_IMDCT.md) describes the bounded, unwired scope.

## Xiph Opus CELT recursive partition decoding (BSD-2-Clause)

`src/media/opus_partition_recursive.asm` ports Opus 1.5.2
`bands.c:quant_partition` recursive split allocation, gains, visitation order,
budget redistribution and collapse propagation. It composes the existing
rate, theta and unsplit helpers. The complete upstream copyrights, grant and
disclaimer are retained in the assembly and `LICENSES/XIPH_OPUS_PARTITION.txt`.
The official archive is identified above; bounded ABI and provenance are in
[the recursive partition documentation](docs/OPUS_NATIVE_PARTITION_RECURSIVE.md).
Unchanged official sources serve as external host-test inputs and are not
linked into PaOS. This addition supplies no full decoder or playback wiring.

## Xiph Opus CELT single-band TF consumer (BSD-2-Clause)

`src/media/opus_band.asm` ports Opus 1.5.2 `bands.c:quant_band` single-band
decoding/resynthesis orchestration and `mathops.c:celt_sqrt` folding scale.
It composes existing TF and recursive partition helpers without changing them.
Complete upstream copyrights, grant and disclaimer are retained in the assembly
and `LICENSES/XIPH_OPUS_PARTITION.txt`; include the notice with distributions.
The official archive is identified above; exact ABI, bounds and provenance
are in [the single-band documentation](docs/OPUS_NATIVE_BAND.md). Unchanged
upstream sources are external host-test inputs, not linked into PaOS.

## Xiph Opus CELT stereo-band consumer (BSD-2-Clause)

`src/media/opus_stereo_band.asm` ports Opus 1.5.2
`celt/bands.c:quant_band_stereo` fixed-point decoding/resynthesis orchestration,
composing the original theta, mono single-band, recursive partition and stereo
merge helpers. It uses the official archive pinned above. Complete upstream
copyrights, grant and disclaimer appear in the assembly and
`LICENSES/XIPH_OPUS_STEREO.txt` / `LICENSES/XIPH_OPUS_PARTITION.txt`; retain them
in source and binary distributions. See `docs/OPUS_NATIVE_STEREO_BAND.md` for
ABI, supported domain, exact transaction behavior and primary-source controls.

## Xiph Opus CELT multiband spectral consumer (BSD-2-Clause)

`src/media/opus_multiband.asm` ports Opus 1.5.2
`celt/bands.c:quant_all_bands`, `special_hybrid_folding` and the N=1 decode path,
composing the original entropy and mono/stereo band helpers. The official
archive is pinned above. Complete upstream copyrights, grant and disclaimer
are retained in the assembly and `LICENSES/XIPH_OPUS_PARTITION.txt` /
`LICENSES/XIPH_OPUS_STEREO.txt`; include them in source and binary distributions.
See `docs/OPUS_NATIVE_MULTIBAND.md` for ABI, supported bounds, transaction and
primary-source controls. Whole official sources are external host-test inputs.

## Xiph Opus CELT frame synthesis composition (BSD-2-Clause)

`src/media/opus_synthesis.asm` ports the standard fixed-point `celt_synthesis`
and normal decoded-frame history/filter/deemphasis sequence from official
Opus1.5.2 `celt/celt_decoder.c`, composing the native denorm, MDCT, postfilter
and deemphasis helpers. The original copyrights, terms and disclaimer are
retained in the assembly and [license](LICENSES/XIPH_OPUS_SYNTHESIS.txt).
[Scope and provenance](docs/OPUS_NATIVE_SYNTHESIS.md) describe the bounded,
unwired consumer; the underlying helpers' existing notices remain applicable.

## Xiph Opus CELT normal frame decoder (BSD-2-Clause)

`src/media/opus_frame.asm` ports Opus1.5.2 `celt/celt_decoder.c` normal
compressed-frame orchestration, composing the original native framing,
entropy, energy, allocation, spectral and synthesis stages. The official
release archive is pinned above. Complete original copyrights, terms and
disclaimer remain in the assembly and [license](LICENSES/XIPH_OPUS_FRAME.txt).
[ABI, source and bounded scope](docs/OPUS_NATIVE_FRAME.md) describe the real
packet-to-PCM transaction. Whole unchanged upstream sources are external host
verification inputs; they are not linked into PaOS.
## Public UI Unifont/catalog regeneration delivery (2026-10-15)

The existing 520-cell UI Unifont subset and both native localization includes
now have a selected offline source recipe: `tools/l10n/gen_ui.py`, with exact
public UI/help catalogs, reviewed-site DATA and glossary declarations under
`third_party/localization/`. See its SOURCE.md/SOURCES.json and
`third_party/fonts/unifont/SOURCE.md`. All glyphs match the exact original
15.1.01 input cells. Complete original Unifont.COPYING and OFL-1.1.txt are
retained verbatim alongside the unchanged subset; the elected OFL-1.1 terms,
original copyrights and prior glyph provenance remain. No upstream programs
are copied. Selected authored catalog/site/emitter helpers and localization
DATA retain MPL-2.0; the public admission driver/tests are Apache-2.0.
Fixed UCD15.0 lookup uses the previously delivered public Unicode DATA/grants.
Only bounded unifont-ui regeneration delivery is newly established. Existing
localization/IME/runtime reviewers and other unresolved source gaps remain.

## Xiph Opus Ogg file producer output gain (BSD-2-Clause)

`src/media/opus_producer.asm` ports the fixed-point output gain from official
Opus 1.5.2 `src/opus_decoder.c` and `celt/mathops.h:celt_exp2`. Complete original
copyrights, conditions and disclaimer remain in the assembly and
[license](LICENSES/XIPH_OPUS_OGG.txt); retain them in distributions.
`src/media/ogg_opus.asm` implements RFC 3533 and RFC 7845 container admission.
[ABI and provenance](docs/OPUS_NATIVE_OGG.md) describe the bounded native path.
External unchanged Opus 1.5.2, opusfile 0.12 and libogg provide independent host
fixtures and whole-file verification; they are not linked into PaOS.

## musl 1.2.4-2 complete public source and distribution delta

The complete musl source archive, original Debian/Ubuntu 1.2.4-2 delta (including
static-PIE patch and BSD fts import), descriptor and complete original notices
are delivered in `third_party/musl/`. Upstream `COPYRIGHT` and distribution
`debian-copyright`, all constituent in-file grants and patch authorship remain
verbatim. See `third_party/musl/SOURCE.md` for exact public archive origins and
`tools/release/build_musl_runtime.py` (not included in this source preview) for the source-built static runtime recipe.
Musl as a whole uses MIT; its retained constituent grants and header/startup
exception are stated in those original texts. No blanket relicensing is made.
The Linux kit's existing full distribution notice is unchanged. The new local
runtime is for future packaging: exact historical distribution libc/archive
reproduction remains unresolved, and no frozen candidate or GCC-runtime
source/license status is replaced or cleared.

## Xiph Opus native SILK speech decoder (BSD-3-Clause)

`src/media/opus_silk.asm` contains readable integer-only native assembly lowered
from 47 fixed-point SILK decode/stereo/resampler source units in the official pinned
Opus 1.5.2 archive. The regeneration script verifies the original archive and
consumed sources/headers; product builds use NASM without libopus or libc.
Full original copyright grants and disclaimers for consumed sources and headers
are retained in [the license](LICENSES/XIPH_OPUS_SILK.txt); include them in
source and binary distributions. [Scope and provenance](docs/OPUS_NATIVE_SILK.md)
describe the finite normal narrowband/mediumband/wideband mono10/20/40/60ms speech-to-PCM profiles, native
48k conversion and private Ogg producer selection. Existing CELT notices apply
to the retained path. Whole upstream libraries and recorded speech inputs are
external host-test inputs and are not shipped in PaOS.

## Public selected IME DATA regeneration (2026-10-15)

`tools/ime/gen_tables.py` extracts the existing PaOS MPL-2.0 DATA parsing,
canonical binary validator and NASM serializer; its public source and full MPL
text are delivered. Independent new public tests use Apache-2.0. Imported DATA
retains its original terms. Mozc's exact preedit romaji table at commit
18e76511af9371a9a4409b1d13c3e30884b53e9c retains Google 2010-2018 copyright,
BSD-3-Clause conditions and disclaimer, with the entire original root LICENSE
in `packaging/public_build_inputs/ime/MOZC-LICENSE.txt`. Its separate
src/data/dictionary* NAIST/ICOT/Okinawa provisions remain verbatim; those
separate dictionaries and Mozc engine are not selected here.

The complete original Rime pinyin-simp dictionary at commit
0c6861ef7420ee780270ca6d993d18d4101049d0 is delivered under `third_party/ime/`
as the primary build input for extracting the 415-syllable union. Its complete
Apache-2.0 grant, original README and Android/AOSP PinyinIME ancestry header
remain in the adjacent public input notices. Neither words, frequencies nor
engine code are compiled into the unchanged native table. See
`third_party/ime/SOURCE.md` and `SOURCES.json` for primary paths and exact pins.
Only selected DATA regeneration is established; existing runtime/release owners
and all unrelated unresolved source deliveries remain unchanged.

## Limited starter dictionary DATA (2026-10-16)

`third_party/ime/starter/` contains bounded single-ideograph derivatives of
Mozc dictionary00..09 at commit `18e76511af9371a9a4409b1d13c3e30884b53e9c`
and rime-pinyin-simp at commit `0c6861ef7420ee780270ca6d993d18d4101049d0`.
The exact public source pins, transformations and glyph dependency are recorded
in its `starter-dictionary-provenance.json` and `HOST_BUILD_RECEIPT.json`.
The adjacent complete `mozc-license.txt`, `mozc-dictionary-notices.txt`,
`pinyin-apache.txt`, `pinyin-readme.txt` and `conversion-cecbca2942015e09.json`
retain the BSD-3-Clause, NAIST/IPAdic/ICOT, Okinawa and Apache-2.0 terms and the
original Pinyin/AOSP ancestry header. Only DATA is selected; neither upstream
engine is included. Readings and scores remain from the pinned sources;
selection removes unsupported/multiple-character surfaces and applies explicit
size/reading limits. See `packaging/public_build_inputs/STARTER_DICTIONARY.md`
and the maintained builder `tools/ime/rcq38_starter_dictionary.py`.

## Complete selected GCC runtime corresponding source (2026-10-15)

`third_party/gcc-runtime/` delivers the complete original Ubuntu GCC13 source
package at13.3.0-6ubuntu2~24.04.1, its distribution patch/build-rule archive and
signed descriptor. Exact selected libgcc archives and startup object hashes,
package identity and observed compiler configuration are declared separately.
Original `COPYING.RUNTIME` (GCC Runtime Library Exception3.1), GPLv3/GPLv2 and
LGPL texts and the full distribution copyright file are retained verbatim, as
are all source-file notices inside the complete archives. Preserve each file's
terms; the runtime exception is conditional and does not relicense the entire
compiler. No GPL source offer or historic binary reconstruction is asserted.

The bounded public source preparation and optional actual Linux kit source
sidecar deliver and verify these inputs without executing received helpers.
See `third_party/gcc-runtime/SOURCE.md` for authoritative origins, exact source
pins, distribution rebuild commands/prerequisites and explicit residual limits.
Selected setup bits and existing kit grants/profiles remain unchanged. Historical
GCC archive reproduction and whole release source/license clearance stay open.


## Native MP3 local corresponding source (2026-10-15)

`third_party/mp3/minimp3/mini_inst.h` delivers the exact already-used local
instrumented minimp3 reference. Its original CC0/public-domain dedication and
no-warranty notice are retained verbatim in that header and `minimp3/NOTICE`.
This header is a source/facts input and is not linked into the PaOS image.
No new codec acquisition occurred. AAC/H.264/H.265 remain user-installed guest
codecs. Current native adaptations remain subject to the existing MPL policy
and third-party terms, without granting rights the original sources do not grant.

The relevant original Classic routines, coefficient spans and generator source
are delivered separately, with exact whole-file hashes and extraction intervals
in `third_party/mp3/ORIGINS.json`. No PCM/golden arrays or unrelated Classic
kernel are included. The Classic excerpts have no individual license headers;
the pinned Classic tree has no LICENSE file. Their exact source-owner license
attestation remains unresolved. The CC0 header notice does not silently clear
Classic-written transformations. The local instrumented header's upstream
revision/patch history and local-only synthesis input custody limits are also
explicit. See `third_party/mp3/SOURCE.md` for the exact deterministic preparation,
shipped-table transformations and remaining limitations. Source delivery and
coefficient regeneration are not whole candidate or codec qualification.

## Stock wallpapers: Unsplash photographs (Unsplash License)

Seven of the nine stock wallpapers in `src/gui/wallpapers/` are photographs
published on Unsplash under the Unsplash License, <https://unsplash.com/license>.
They are third-party works, not PaOS project source, and are not licensed under
the project's MPL-2.0 or Apache-2.0 terms. The Unsplash License permits copying,
modifying and redistributing the photos. It does not permit selling unmodified
copies, or compiling photos from Unsplash to replicate a similar or competing
service. PaOS ships them only as desktop wallpapers. The credits below are
copied from `src/gui/wallpapers/STOCK.JSN`, which also records each delivered
file's size and SHA-256.

| File | Photo | Photographer | Unsplash page |
|---|---|---|---|
| `W01.JPG` | White blossoms | Mink Mingle | <https://unsplash.com/photos/white-petaled-flowers-during-day-96JD67agngE> |
| `W02.JPG` | Infinite ferns | Teemu Paananen | <https://unsplash.com/photos/photo-of-green-fern-plant-OOE4xAnBhKo> |
| `W03.JPG` | Water ripples | Mink Mingle | <https://unsplash.com/photos/a-view-of-the-water-from-the-bottom-of-a-swimming-pool-AlEyuIKuSmc> |
| `W04.JPG` | City waterfront | CHUTTERSNAP | <https://unsplash.com/photos/landscape-photography-of-city-skyline-at-night-JH0wCegJsrQ> |
| `W07.JPG` | Lake at dawn | Intricate Explorer | <https://unsplash.com/photos/majestic-mountains-reflected-in-a-serene-lake-at-sunrise-gjI-YoxuFys> |
| `W08.JPG` | Misty ridges | Willian Justen de Vasconcellos | <https://unsplash.com/photos/landscape-photography-of-mountains-with-fog-_MMP5j_fCqw> |
| `W09.JPG` | Painted light | Nathan Broadbent | <https://unsplash.com/photos/abstract-textured-painting-with-blue-and-yellow-strokes-DkO2Isk9tjo> |

The other two stock wallpapers are not Unsplash photos. They were generated with
AI for PaOS (`STOCK.JSN` source "PaOS original") and are identified here as
generated material, as CONTRIBUTING.md asks. Each JPEG is a baseline delivery
encoding of a retained PNG original (Pillow 12.1.0, quality 88, 4:2:0, no crop,
resize or edits; Peter 10/31), recorded in the `conversions` list of `STOCK.JSN`:

- `W05.JPG` "Wildflower Dusk": AI-generated for PaOS; JPEG SHA-256 `24268efc05035b32625391219a7b0beac4eb9e778877b0ac20ad2e954b1fb1f2`, converted from the retained PNG original SHA-256 `8d9fca4738defafa6e4d93eb190e65723d722c59a4971b65f4eac63a6846f76b`.
- `W06.JPG` "Midnight Skyline": AI-generated for PaOS; JPEG SHA-256 `26afbe0054477edf48979b819862f82c0f09fb83b92095c38a0afac16fa4efee`, converted from the retained PNG original SHA-256 `9f09dd103225c6fee32c6b1696ff8d54c9530ac72edcaab1a32f445afa279b8e`.
