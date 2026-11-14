Native GIF still-image slice
===========================

The common img_probe/img_decode contract now recognizes GIF (format4) and
returns top-down straight RGBA8888 at the logical-screen dimensions. It accepts
GIF87a/89a with one image, a global or local RGB table, 1..8-bit palette indices, 2..8-bit initial
LZW code size, four-pass interlace, comments and GIF89a GCE transparency.
Unused palette RGB is retained for transparent pixels; alpha is0 or255.

An opaque image may occupy any positive rectangle wholly inside the logical
screen. Pixels outside it use the declared global-table background color with
alpha255, even when a different local table supplies the image pixels. The
logical screen controls allocation, stride and canvas initialization; the image
rectangle controls LZW pixel count, row wrapping and the four interlace passes.
Both axes are widened before checking position+size. A full-screen image keeps
the existing local-only palette and transparency behavior. Partial rectangles
with transparency or without a global color table explicitly refuse for now.

GIF89a may carry one NETSCAPE2.0 or ANIMEXTS1.0 application extension before
the image. The 11-byte identifier must match exactly, followed by one 3-byte
sub-block (type1 plus a little-endian u16 loop count) and a zero terminator.
Every count0..65535 is inert for a still image: it never drives iteration or
creates a timer. Comments and the sole GCE may surround the metadata before
the image. Duplicate or malformed loop metadata refuses; metadata after the
image refuses. All other application identifiers remain unsupported.

This slice explicitly refuses a second image,
unknown application/plain-text extensions, user-input controls, reserved disposal
methods and nonzero pixel-aspect metadata. It is not full GIF/animation support.
GIF87a extensions refuse. A GCE must precede the sole image and be unique;
reserved bits refuse. A missing palette, out-of-range index, extra output,
missing output, invalid code/prefix or trailing bytes refuse. The first code
must be CLEAR. EOI must be the final code in its data sub-blocks, followed by
the zero terminator; unused bits of its last byte are ignored. Palette sort,
GCE delay and disposal0..3 do not alter the sole still raster.

Limits are the common4096 per dimension and4194304 total pixels,32MiB source,
a4096-entry dictionary and4096-byte expansion stack. A full dictionary freezes
until CLEAR, including deferred CLEAR streams. Probe validates structure and
LZW without allocation. A single decode allocation holds RGBA and a private
source copy. SHA256 before allocation binds that copy to pre-allocation bytes;
the owned file is revalidated and its dimensions matched before any RGBA write.
Pixels are never published on failure. Refusal/release clears parser workspace.
The common allocator's LIFO retirement and contention behavior are unchanged;
this does not claim general physical heap reclamation.

The host suite executes the actual NASM GIF/common/cache/SHA bodies using
read/write guard pages. Literal pixels and Pillow independently check output;
synthetic code vectors check KwKwK, width growth/reset and frozen dictionaries.
The canvas suite also checks offsets, nonzero background indices, differing
global/local palettes, extreme axes, exact frame counts and private geometry.
Pillow checks decoded frame pixels; outside-frame golden pixels follow GIF89a
logical-screen background semantics. Pillow initializes its first canvas to
index0 and thus is not an oracle for nonzero background indices or differing
local/global background colors.
It exercises bounds, framing, source mutation, private reads, OOM, exact
retirement, cache publication and the x86-64 nonvolatile/DF/FP ABI. Source and
host controls do not establish QEMU, display, Secure Boot or bare-metal proof.

The loop-metadata suite adds independent single-image Pillow encoder/decoder
checks, both exact identifiers and all count boundaries, palette/transparency/
interlace/canvas composition, each identifier-byte mutation, fixed framing and
all truncations, duplicate/late/87a metadata, second-frame refusal, legal count
mutation during allocation, owned-copy reads, OOM and cache reuse.

Format reference: CompuServe GIF89a Programming Reference (31 July1990),
https://www.w3.org/Graphics/GIF/spec-gif89a.txt . Graphics Interchange Format
is the copyright property of CompuServe Incorporated; GIF is its service mark.
Loop grammar references: giflib's What's In A GIF application-extension notes,
https://giflib.sourceforge.net/whatsinagif/bits_and_bytes.html ; Google's Wuffs
decode_ae implementation recognizes both identifiers and the 03/01/u16 syntax,
https://github.com/google/wuffs/blob/main/std/gif/decode_gif.wuffs .
