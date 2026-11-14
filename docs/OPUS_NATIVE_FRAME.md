# Native CELT normal compressed frame decoding

`src/media/opus_frame.asm` exports `media_opus_frame_decode`, a private native
fixed-point Opus 1.5.2 standard 48 kHz CELT normal-frame decoder. It consumes
actual Opus packet bytes through the existing packet parser and selects one
normal compressed frame. TOC-derived channel count, bandwidth and duration,
and range-decoded controls drive the existing native codec stages. Successful
calls return interleaved signed i16 PCM plus the complete persistent state for
this normal-frame domain. No caller-supplied energy, allocation, TF, spectrum,
pitch or other decoded controls substitute for compressed input.

## ABI and state

SysV `RDI=readonly config80*`; RAX is samples per output channel on success,
or -1 on malformed, unsupported, capacity, arithmetic or downstream refusal.
The ten qwords use their full 64 bits:

| Offset | Field |
| --- | --- |
| 0 | Immutable complete elementary Opus packet pointer |
| 8 | Truthful packet bytes, 1..65536 |
| 16 | Mutable persistent state pointer |
| 24 | Truthful state capacity, at least 448+8672*CC bytes |
| 32 | Mutable interleaved i16 PCM pointer |
| 40 | Truthful PCM capacity, at least 2*CC*(120<<LM)/downsample |
| 48 | Output channels CC, 1 or 2, fixed for this state |
| 56 | Downsample factor, 1, 2, 3, 4 or 6 |
| 64 | Accumulate into existing PCM, 0 or 1 |
| 72 | Selected frame index, less than the actual parsed frame count |

Packets can use all four native framing codes, VBR/CBR and padding. This entry
decodes one selected frame; callers process frames in sequence with the same
state. It does not reorder packets or infer missing frames. The parser supplies
the exact frame span; frames shorter than two bytes are refused because upstream
routes them to PLC. SILK and hybrid TOCs are refused. CELT TOCs supply LM0..3,
coded mono/stereo and the actual NB/WB/SWB/FB ends 13/17/19/21, always start0.
Output channels may differ from coded channels; downsampling follows the exact
upstream synthesis and deemphasis behavior. Stereo inversion is disabled for
CC=1, matching the upstream decoder default.

The state has no borrowed pointer. It uses this little-endian layout:

| Offset | Field |
| --- | --- |
| 0 | Qword magic 0x31465243 |
| 8 | Qword holding uint32 final range/random state; upper bits zero |
| 16 | i16 oldBandE[42], Q10, channel-major |
| 100 | i16 oldLogE[42], Q10 |
| 184 | i16 oldLogE2[42], Q10 |
| 268 | i16 backgroundLogE[42], Q10 |
| 352..383 | Reserved zero |
| 384 | Existing native synthesis state, 64+8672*CC bytes |

Initialize the minimal state to zero, set the magic, set all 42 entries in
both oldLogE arrays to -28672, and set the synthesis state's first qword at
384 to CC. Its remaining fields, including feedback/history, initially stay
zero. The synthesis documentation defines that embedded record, including its
current/old pitch, gain, tapsets, both feedback cells and all 2168 i32 history
samples per output channel. The unused second feedback cell is preserved for
mono. Both channels of all four energy histories remain present for coded
channel changes and mono's stereo-history maximum. This record covers normal
frames; it contains no LPC, packet-loss concealment or recovery state.

Config and state require eight-byte alignment, PCM two-byte alignment; packet
bytes need no alignment. All four full declared spans are mutually disjoint,
including readonly pairs and capacity tails. Checks cover full-width arithmetic,
carry, nonnull/nonempty extents and lower-canonical last bytes before copying
state or reading packet bytes. Callers supply stable truthful mappings, writable
state/PCM, sufficient stack and serialized access. Arithmetic checks do not
establish mappings or concurrency safety.

## Actual decode order and transaction

The decoder snapshots config, parses the actual packet, initializes a private
range decoder for the selected frame, stages the complete persistent state,
and performs the upstream mono energy maximum. It decodes silence, pitch
postfilter octave/raw pitch/gain/tapset, transient and intra flags in actual
entropy order. It then calls coarse energy and TF decoding, parses spreading,
dynamic allocation with real caps/quanta and signed reservation accounting,
and trim. It reserves the anti-collapse bit, computes actual allocation and
stereo controls, refines energies and decodes the full multiband spectrum with
shared range and random state. It reads the reserved anti-collapse bit, finalizes
energies with the remaining physical budget and applies actual seeded
anti-collapse when enabled. No private compressed wire format is introduced.

Synthesis shifts the actual decode history, denormalizes and inverse-transforms
long or short blocks, clips the current signal exactly, applies the two pitch
filter transitions and deemphasis/PCM saturation. Accumulation uses a private
copy of the caller's existing PCM. Mono energy duplication, transient/nontransient
history updates, background floor increments, inactive-band resets and final
range publication follow `celt_decoder.c`. Entropy error and final physical
budget checks precede all publication.

For actual silence, upstream forces accounting to the full physical bit count;
all subsequent energy/allocation/spectral work has no entropy budget, and the
spectrum is discarded by silent synthesis. This entry performs that same
accounting, forces coded energies to -28 Q10 and supplies zero spectra directly
to silent synthesis. The complete upstream decoder comparisons cover final
range, all four energy histories, filter state, every history/overlap cell,
feedback and PCM for this optimization, including accumulated output.

Every refusal leaves config, packet, the entire declared state and the entire
PCM capacity unchanged, including refusals after spectral work, anti-collapse,
both channel transforms or a late filter/deemphasis failure. Success publishes
only the minimal state and exact output extent. Tails remain unchanged. Copies
require caller serialization; publication is not concurrent atomicity.

## Supported bounds and practical coverage

Normal frames in all four LM modes, both coded/output channel counts and all
four standard CELT bandwidths are exercised with real encoder-produced input.
This bounded decoder inherits the published native stages' arithmetic and
geometry fences. It can refuse a valid upstream packet: positive TF must leave
nonzero recombination blocks, transformed folding and stereo merge energies
must satisfy their existing bounds, anti-collapse depth must be <=255 and
input band energy <=2^29, postfilter history/current signal must fit +/-300M,
and deemphasis input/initial feedback must fit +/-2^27 and +/-2^30 respectively.
Energy refinement must fit its signed intermediates and i16 history. A refusal
never substitutes zero PCM or claims a successful decode. The multiband unsafe
hybrid slice start19/end21 cannot occur here because CELT-only starts at zero.
No new geometry fence or compressed format is invented by this orchestration.

In the diagnostic 384-frame independently encoded ordinary corpus, the first
actual refusals were 12 mono-band calls and 23 deemphasis calls. These are
inherited bounds, not claims that upstream packets are malformed. Other real
accepted frames cover silence, transients, intra/inter energy prediction,
pitch-filter controls, stereo intensity/inversion behavior, dynamic allocation,
fine/final energy and anti-collapse. The broad suite records accepted/refused
counts; explicit ordinary positive fixtures require success. Payload bit
mutations and truncations are compared if accepted and checked for complete
purity if refused. Opus has no general payload checksum, and entropy decoding
permits implicit zero padding, so a changed or truncated payload is not assumed
to be detectable corruption.

The root private frame is 31432 bytes plus 48 saved registers and a return
address. With the deepest existing synthesis composition, less than 84 KiB
of private stack is conservative; provide 96 KiB plus caller frames. Exact
guarded tests check the bottom 8 KiB remains untouched. Work is bounded by the
native 65536-byte packet parser, one <=1275-byte frame, 21 dynamic-allocation
bands and their finite caps, at most 21 spectral bands, inherited depth-four
partition recursion, at most sixteen short transforms and fixed 2048/120-sample
history operations. There is no heap allocation, mutable global, floating point
or device access. SysV nonvolatiles/RSP and x87/MXCSR are preserved; DF is clear
on every exit.

## Provenance and verification

Primary source: official Opus 1.5.2 fixed-point `celt/celt_decoder.c` normal
`celt_decode_with_ec_dred` path, `celt/celt.h` tables and actual standard mode.
Archive `https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
The original copyright, grant and disclaimer remain in the assembly and
`LICENSES/XIPH_OPUS_FRAME.txt`; dependencies retain their existing notices.

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 python3 -B -m unittest \
  gauntlet_v2.tests.test_opus_frame_host -v
```

The harness verifies the archive and all 394 C/header files, then compiles whole
unchanged upstream CELT encoder/decoder sources and actual packet parser with
fixed-point scalar semantics. The encoder independently produces compressed
normal frames from PCM. A boundary adapter imports/exports persistent state;
it calls the actual complete upstream decoder and contains no duplicate entropy,
allocation, spectral or DSP algorithm. It compares every PCM and state byte,
including unchanged tails. The native packet parser's selected offsets/lengths
are independently compared to upstream for all framing codes and unequal VBR
lengths. Sequential tests carry state across frame duration, coded channel,
bandwidth, filtering, transient/silence and accumulation changes. Nonzero history
and low bitrate cases expose anti-collapse noise and budget pressure.

Every functional native call checks SysV nonvolatiles, DF1-to-DF0 and unchanged
FP control state. Negative tests cover full-width scalars, bad pointers,
capacities, state controls, all span pairs, aliases through extra declared tails,
adjacency, readonly config/packet, both-end exact guards and bounded private
stack. Separate SOURCE evidence retains exact-base parser fail-first, semantic
assertion mutants, real late-helper counter traces and retained dependency
checks. The fail-first adapter returns the actual assigned-base parser result;
framing success fails the proposed positive PCM assertion. No fake failure
return is used. Counter instruments are diagnostic-only and absent from product
assembly.

This source result supplies no SILK/hybrid, PLC/FEC, Ogg/container, runtime
playback, hardware audio, QEMU, metal or release qualification. Original SOURCE
reviews for the composed band and synthesis dependencies remain in force;
only this new frame consumer delta is submitted. Current builds and physical
operators retain their work.
