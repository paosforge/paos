# Public Unicode table regeneration

This is the bounded source delivery for three existing tables. It preserves their
independent versions: editor Unicode 15.1.0, Terminal widths Unicode 15.0.0, and
four CLDR release-43 Windows layouts at commit
66d15bfc1b4762b38bf1330319534e237d4670a3. SOURCES.json binds exact upstream
bytes, URLs, versions and complete original notices. Inputs are DATA, never code.
The 15.1 and CLDR bytes are the retained canonical inputs originally fetched on
2026-10-10; the two 15.0 files were obtained from the named Unicode release.
No system Unicode database, fonts, factory directory or network is read by the
recipe. Python 3.8+ standard library is sufficient.

From any directory, with a public source tree at SOURCE:

    python3 -I -S -B SOURCE/tools/unicode/gen_unicode_tables.py --check
    python3 -I -S -B SOURCE/tools/unicode/gen_unicode_tables.py --emit /tmp/unicode-a
    python3 -I -S -B SOURCE/tools/unicode/gen_unicode_tables.py --emit /tmp/unicode-b
    diff -r /tmp/unicode-a /tmp/unicode-b
    python3 -I -S -B -m unittest discover -s SOURCE/tools/unicode -p 'test_*.py'

--emit requires a new directory. The complete input and notice admission and
all conversions finish before output is created. --check compares against the
actual shipped full VT table and embedded editor/layout blocks. Outputs include
unicode_properties.inc, vt_tables.inc, keyboard_layout_data.inc,
keyboard_layout.bin and keyboard_layout_provenance.json. The old layout generator
SHA in the emitted comment/provenance identifies the original authored recipe;
it is deliberately retained so the existing embedded section remains exact.

Editor: default width one, Mn/Me/Cf zero, W/F two; GCB low bits, EP flag, InCB
bits and terminal sentinel retain the existing format. Hangul LV/LVT remains
algorithmic in native code. GraphemeBreakTest is retained for source/oracle
coverage, including GB9c, without a Unicode version upgrade.

Terminal: the shipped generator starts ranges at U+0300 and skips surrogates;
zero width overrides East Asian width, U+00AD stays one, U+1160..11FF is zero.
Unlisted category is Cn and unlisted East Asian width is N, exactly as the
pinned 15.0 files specify. Inclusive sorted ranges and the DEC map are unchanged.
All category/EAW values were independently compared over U+0000..10FFFF with
the original Python Unicode-15.0 database before removing that dependency.

Layout: source XML is bounded; its one known external DTD declaration is stripped
and never resolved. No DTD is needed. The original ISO/HID mapping, Caps XOR,
AltGr layers, transform=no, dead-key union, authored cedilla+c/C supplement,
neutral keypad and alias policies remain in tools/unicode/keyboard.py. The
four-layout KLT1 byte blob and original per-map/transform provenance are exact.

Code moved from the PaOS-authored converters retains MPL-2.0 terms; new recipe
and tests use Apache-2.0. UCD DATA retains Unicode-3.0, with the original 2022/2023 copyright notices
verbatim in the upstream DATA headers and the 15.0 release notice in
LICENSES/Unicode-15.0.0-NOTICE.txt. The retained UCD license,
LICENSES/Unicode-3.0.txt and Unicode-15.1-DATA.txt supply the full V3 grant
(the retained license fetch is dated 2026; no older grant text is fabricated). CLDR DATA
retains the exact 1991-2023 Unicode-DFS-2016 grant both with its input and in
LICENSES/Unicode-DFS-2016.txt. Preserve these notices with redistribution.

This closes only these three source recipes. Other font, dictionary, runtime,
SDK, driver and whole-source export issues retain their existing evidence and
owners. It does not qualify runtime behavior, a public build or a release.
