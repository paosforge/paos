# Local MP3 corresponding source

This package contains only locally authorized source already used by the native
PaOS port. It has no network acquisition step. `ORIGINS.json` maps every original
input or exact excerpt to its whole-file SHA256 and zero-based byte interval
[start,end). It also pins the five original author provenance manifests that were
actually read. Extracted files are verbatim; they are not silently given new grants.

`classic/native/` contains the original relevant Classic routines. References to
Classic globals are retained for comparison; these archival excerpts are not a
standalone build. The adapted, bounded current implementation is delivered under
`src/media/mp3_{math,producer,header_private,bits_private}.asm`. The port's existing
MPL-2.0 policy and third-party exceptions remain in effect.

`classic/mp3_huff_tables.inc` and `mp3_imdct_tables.inc` are the exact original
files at Classic commit 0cabd75f8653ae3f8778ad0af51469a4f20adf25. `alias.inc` and
`synthesis.inc` contain only the original immutable coefficient spans, excluding
all input and golden arrays. The small original generator spans preserve the
Huffman read/emit logic, alias formulae, 512 recovered synthesis-window doubles
and cosine matrix formula. No original generator is executed by this recipe.

`minimp3/mini_inst.h` is the exact already-local instrumented CC0 reference,
SHA256 c2f0980e2a3292641d36dd78000f7f383670ffdfc35f91ee54f37a9620782071.
Its original dedication is preserved both in the header and `minimp3/NOTICE`.
It is corresponding source and facts input, never linked into the production
image by this preparation. Installed FFmpeg/mpg123 and test PCM are not delivered.

From a public source root, using Python 3.12 on the documented Linux host:

```
python3 -I -B tools/media/prepare_mp3_source.py --source-root . --output /tmp/mp3-source-one
python3 -I -B tools/media/prepare_mp3_source.py --source-root . --output /tmp/mp3-source-two
python3 -I -B tools/media/test_mp3_source.py
```

Both output paths must be fresh. `--local-root /path/to/original/Classic` additionally
re-extracts the finite named original files after checking their full hashes; it
reads no other files from that tree and never copies the monolithic kernel.
It does not fall back to downloading or discovering a replacement header.
Prepared file tables/results are independent of paths, timestamps and umask.
Only declared source, original notices, recipe and equal regenerated include
are written. Symlinks, hardlinks, special files, changed/missing/extra package
members and unsafe paths refuse before output. Existing output is not overwritten.

The recipe regenerates all 90477 source bytes of `src/media/mp3_tables.inc`:
original table concatenation and label namespace substitution; CC0 accumulated
long-band positions, zero-padded short/mixed rows and preflag facts; documented
8k mixed-band correction; finite start/stop/short sine windows and cosine matrix;
LSF partition cells, relative offsets and 65 powers of two. It independently checks
all five Huffman arrays against the original header. Tests check original cosine,
window, alias, synthesis D and partition facts and the assembled table bytes.
Libm-dependent fresh trigonometric results must equal the pinned output or refuse;
this does not promise identical libm rounding on every host.

Delivery limitations are concrete. The header has no pinned upstream commit or
separate local instrumentation patch history. Classic's local synthesis include
and generator are absent from the claimed Git tree; exact local hashes/spans are
preserved without claiming Git custody. The Classic excerpts have no individual
license headers and that pinned tree has no LICENSE file. The original source
owner's exact grant/attestation for those excerpts is still required: the CC0
notice on minimp3 is not a blanket clearance for Classic-written transformations.
The corresponding local source is delivered, but origin/license clearance stays
unresolved. The original empirical recovery campaign is not rerun, and this source
preparation proves neither full historical candidate reproduction nor codec or
hardware qualification. AAC/H.264/H.265 remain guest codecs.
