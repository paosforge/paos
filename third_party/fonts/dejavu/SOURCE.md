# Selected PaOS DejaVu AA atlas

This directory delivers the exact input font, preferred editable SFD source,
original font grants, immutable upstream/distribution source references,
and the complete FreeType 2.14.1 source archive and grants. See SOURCES.json for
immutable upstream locations, versions, sizes and hashes. No font or rasterizer
is downloaded by the build. Keep every source and grant together.

The actual historical font is **Ubuntu fonts-dejavu-mono 2.37-8**, not the Debian
binary with the same version or the upstream TTF release. Extracted path:
usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf, 343140 bytes, SHA256
c805f9436dbc268644c1d9584f01a601a653e028e08fd74b9b949f6cf8304d88.
The SFD is unmodified DejaVu tag version_2_37, commit
0eda8a319c08835009849583cd090bb5b141ce25, also independently extracted from
fonts-dejavu_2.37.orig.tar.bz2. The Debian source diff contains the distribution
build instructions and two documentation/fontconfig patches, not glyph changes.
The full upstream and distribution source archives are identified by public URL
and hash in SOURCES.json. This bounded recipe consumes the delivered exact TTF, rather
than claiming a byte-identical FontForge rebuild of the distribution package.
All original outlines, hint instructions and licenses are retained in the SFD.
The font has not been modified. The atlas is its existing grayscale ASCII
rasterization, not a renamed or redrawn outline font. Arev terms in LICENSE
are retained in full even though the selected ASCII cells are Vera-derived.

Run offline, on Linux x86-64 with Python 3.12+ (standard library), a C99 compiler
at /usr/bin/cc, GNU make at /usr/bin/make, and POSIX build utilities in
/usr/bin:/bin:

    python3 -I -S -B tools/fonts/gen_aa.py --check
    python3 -I -S -B tools/fonts/gen_aa.py --emit /tmp/paos-aa
    python3 -I -S -B tools/fonts/test_aa.py

The Python entry point admits every pinned source, helper, recipe and grant
before executing anything. It extracts the admitted FreeType source into a
fresh temporary root, builds only a static library with zlib/bzip2/png/harfbuzz/
brotli disabled, and compiles raster_aa.c against that library. Neither host
font discovery nor host FreeType/Pillow/shaping libraries are used. Compiler,
make and libc are host build prerequisites; the exact rasterizer source and
configuration are part of this recipe. Temporary binaries are never inputs to
a later run. No cache or environment variable changes rasterizer selection.

Historical policy: 15 px, 9x19 cell, baseline y=14, integral x=0, ASCII 32..126,
8-bit grayscale, normal TrueType hinting and normal grayscale rendering.
FreeType's left/top bearings place each cell; clipping retains the original
9x19 bounds. Each original Pillow call shaped one isolated printable ASCII
character, so no shaping operation is required. Every resulting byte has been
compared to the original Pillow 12.1.0 / FreeType 2.14.1 / raqm 0.10.3 /
HarfBuzz 12.3.0 / FriBidi 1.0.13 output. The historical header (including its
factory path and Pillow identity) is preserved as an artifact identity, not
an executable dependency. The public converter is new PaOS Apache-2.0 code.
No renderer, fallback, blend, native assembly or KAT constant is changed.

The independent public tests parse SFD encodings/widths, TTF Unicode cmap and
metrics, atlas geometry and all glyph identities, compare each glyph to an
independently bound per-cell expectation, require meaningful partial coverage,
and recompute the actual assembly KAT's blended 'A' FNV-1a (0xE28477FE).
The complete output SHA256 is
099427b2e8688fa303eb5a4366e50396b012fdf062b2a5009b688311816c0958.

FreeType is used under its FreeType License (FTL); retain FreeType-FTL.txt and
FreeType-LICENSE.txt. Portions of this software are copyright © 1996-2025
The FreeType Project (www.freetype.org). All rights reserved. The complete
archive also retains its constituent source notices and alternative grants.
This closes only the selected dejavu-aa source recipe. The seven other nested
source gaps, general export/privacy/build readiness and physical qualification
retain their existing owners and unresolved status.
