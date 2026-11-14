# Native Opus packet boundary

`src/media/opus_packet.asm` supplies a private, unwired elementary Opus packet
framing primitive for the native decoder work. Classic's audio decode essence
documents WAV/FLAC/MP3 and has no Opus implementation to port. This first boundary
provides validated frame spans and duration accounting before entropy decoding.
It does not produce PCM or register a producer or command.

```text
media_opus_packet_parse(source, source_bytes, result416)
RDI                    RSI           RDX
RAX = 0 success, -1 malformed/pointer/overlap, -4 packet work limit
```

The caller serializes the call and guarantees truthful stable mapped capacities.
Source and the 416-byte result must be disjoint, nonnull lower-canonical spans;
the result is four-byte aligned. Length arithmetic uses full 64-bit addresses.
The source length is 1..65536 bytes, an explicit finite work bound including
padding. Every refusal leaves source and result unchanged. A previous result
does not authorize consuming a failed call. SysV nonvolatile GPR/RSP survive,
DF is clear on return, and the function does not touch floating-point state.

The result starts with eight unsigned little-endian 32-bit fields:

| Index | Field |
| --- | --- |
| 0 | Actual TOC byte |
| 1 | Coded channels, one or two |
| 2 | Frame count, one through 48 |
| 3 | Samples per frame at the 48000 Hz timebase |
| 4 | Packet samples at that timebase, at most 5760 |
| 5 | Payload offset after all framing headers |
| 6 | Trailing padding bytes, excluding padding-length headers |
| 7 | Reserved zero |

The remaining 48 rows are `{u32 source_offset, u32 byte_count}`. Unused rows
are zero. Rows describe the original input and contain no borrowed pointers.
An accepted zero-byte frame may have its offset at the source end; it permits
no byte read. The caller retains the source for any subsequent frame decoding.

All four framing codes are admitted: one frame, equal-size two-frame CBR,
two-frame VBR, and arbitrary-count CBR/VBR with optional padding. The parser
checks each frame's 1275-byte bound, encoded one/two-byte sizes, the 255 padding
continuation convention, exact payload coverage, and the 120 ms packet duration
limit across SILK, hybrid and CELT TOC configurations. Padding bytes are opaque.
Entropy validity, FEC, PLC, Ogg demux, multistream self-delimiting framing,
pre-skip/gain, actual decoding and producer wiring remain separate work.

`gauntlet_v2/tests/test_opus_packet_host.py` assembles and executes this actual
source as a host ELF. Its independent oracle is the installed libopus
`opus_packet_parse` and `opus_packet_get_samples_per_frame` public API from
`/usr/include/opus/opus.h`. The library is used only by tests; the native source
has no external library dependency. Every returned frame offset/size, channel
count, TOC, payload offset and duration is compared with the independent API.
The suite includes all 256 TOC bytes, VBR length and padding boundaries,
oversized/zero-duration packets, 4000 deterministic adversarial packets,
65000 padding bytes, unchanged failure buffers, high-address/wrapped spans,
a guard page after a TOC-only packet, and an assembled SysV/DF/FP-control probe.

Host agreement establishes packet framing under this bound. It establishes no
Opus PCM decoding, native playback, QEMU, audible or hardware qualification.
