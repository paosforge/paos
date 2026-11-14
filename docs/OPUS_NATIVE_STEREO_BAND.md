# Native CELT stereo-band decoding

`src/media/opus_stereo_band.asm` exports `media_opus_stereo_band_decode`, an
unwired fixed-point port of Opus 1.5.2 `celt/bands.c:quant_band_stereo` decoding
and resynthesis. It composes the existing stereo theta, mono single-band,
recursive partition, entropy and stereo merge helpers without changing them.
It supplies the N=2 orthogonal-sign case, mid/side allocation, larger-budget
first ordering, unused-bit rebalance, normalized mid folding, scaled side,
collapse mask union and final merge/inversion.

## ABI and domain

`RDI=range64*`, `RSI=readonly config192*`; RAX is 0 on success or -1 on refusal.
Config consists of twenty-four full-width qwords. LM and TF are signed.

| Offset | Meaning |
| --- | --- |
| 0 | Standard-mode band index, 0..20 |
| 8 | LM, -1..3 |
| 16 | Stereo band allocation, 0..81600 eighth-bits |
| 24 | Initial short-block count B, 1/2/4/8, divides N |
| 32 | Spreading, 0..3 |
| 40 | Reserved gain, must be 0; stereo chooses its own gains |
| 48 | Initial remaining budget, 0..81600 eighth-bits |
| 56 | Unsigned 32-bit seed |
| 64 | Fill mask, 0..(1<<B)-1 |
| 72 | Absolute cumulative fractional entropy cap |
| 80 | Mutable left-channel i16[N] pointer |
| 88 | Left capacity, at least 2*N bytes |
| 96 | Optional readonly i16 lowband[N] pointer, or 0 |
| 104 | Lowband capacity, at least 2*N bytes, or 0 when absent |
| 112 | Mutable six-u32 metadata pointer |
| 120 | Metadata capacity, at least 24 bytes |
| 128 | TF change, -3..3 |
| 136 | Optional mutable i16 lowband_out[N] pointer, or 0 |
| 144 | lowband_out capacity, at least 2*N bytes, or 0 when absent |
| 152 | Reserved, must be 0 |
| 160 | Mutable right-channel i16[N] pointer |
| 168 | Right capacity, at least 2*N bytes |
| 176 | Intensity band boundary, 0..21 |
| 184 | Disable inversion, 0 or 1 |

N is the actual standard-mode band width scaled by LM (halved for LM=-1),
2..176 with a valid existing rate cache. Both channels inherit the mono TF
domain: positive recombine must leave a block, the upstream time-division
loop must result in at most 8 partition blocks, and the resulting block count
shifted left by recombine must be at most 16. See `OPUS_NATIVE_BAND.md`.
N=1, other modes, complete frames and PCM synthesis are outside this entry.

Metadata is six u32: **N, root itheta (0..16384), total charged cost,
signed remaining_after bits, seed_after, final collapse mask**. The second
field is the stereo angle, not mono's root pulse index. Cost includes theta,
the N=2 raw sign bit when present, and both mono charges. Remaining_after may
be negative. Callers must handle that signed result before another root call.
The fractional cap must not exceed frame_bytes*64; initial and final tell_frac
must fit it, and final whole-bit consumption must fit the frame. Equality at
the fractional cap succeeds. The entropy state is the existing range64 ABI.

## Exact stereo behavior

The stereo theta call receives the original B as both B and B0. For N=2 an
interior angle consumes one actual raw range-decoder bit. The dominant vector
is Y iff itheta>8192; it receives original fill, lowband and optional folding
output even when it is Y. Orthogonal reconstruction, Q15 scaling and sum/
difference follow upstream signed shifts and i16 extraction exactly.

For larger bands, C signed division and clamp produce mbits/sbits. The larger
allocation decodes first, with ties choosing mid. An unused allocation above
24 eighth-bits transfers its excess to the other channel except at the
corresponding endpoint angle. Mid uses Q15ONE and retains normalized folding
output; side uses the decoded side gain with no lowband or folding output and
fill shifted by original B. Collapse masks combine with OR. Existing
`media_opus_stereo_merge` performs fixed-point normalization, then the right
channel is negated when theta requests inversion.

The public mono entry accepts nonnegative budgets. A private adapter maps a
negative child allocation or shared remaining value to zero for that call;
these select the same zero-pulse path. It subtracts the returned actual charge
from the original signed shared remaining, and propagates seed and masks.
It never substitutes a clamped remaining value for the signed stereo state.
No mono or recursive predecessor code was modified.

## Transaction and bounds

Config/state are 8-byte aligned, samples 2-byte aligned and metadata 4-byte
aligned. All eight possible caller spans (config, state, left, metadata,
frame, lowband, folding output and right) must be disjoint across their full
declared capacities. Every span uses full 64-bit capacity, carry and lower
canonical last-byte checks. Absent optional pointers require zero capacity.
Truthful stable mapped spans, writable ownership, serialization and sufficient
stack are caller obligations; mapping and concurrent custody are not inferred.

Entropy state, both channel arrays, folding output and metadata remain private
through all calls and final entropy checks. Any refusal preserves every caller
byte, including after one channel succeeds and the second refuses. Success
writes only the active sample/metadata/state extents, preserving capacity tails.
Publication requires serialization; it is not concurrently atomic. The existing
transformed per-leaf folding fence `sum((abs(low)+4)^2)<=2^29` and merge input
energy fences remain in effect.

There is no allocator, mutable global, FP, device access or runtime wiring.
The root frame is 4328 bytes plus 48 saved-register bytes and a return address;
the private channel adapter adds 16 bytes including its return address before
the mono call. Including bounded mono/recursive dependencies, 24 KiB of private
stack is conservative. Controls use a guarded 40 KiB stack and verify its bottom
16 KiB remains untouched. SysV nonvolatiles and x87/MXCSR are preserved; DF is
clear on every return.

## Source, license and controls

Primary source is the whole unchanged official Opus 1.5.2 archive:
`https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
The port follows `bands.c:quant_band_stereo`, with fixed-point semantics from
`fixed_generic.h`; composed helpers retain their original source provenance.
Complete copyrights, BSD grant and disclaimer are retained in the assembly,
`LICENSES/XIPH_OPUS_STEREO.txt` and `LICENSES/XIPH_OPUS_PARTITION.txt`. Include
those notices with distributions.

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 python3 -B -m unittest \
  gauntlet_v2.tests.test_opus_stereo_band_host -v
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 python3 -B -m unittest \
  gauntlet_v2.tests.test_opus_band_host -v
```

The harness checks all 394 C/header files against the pinned official archive,
compiles whole unchanged upstream sources and calls real quant_band_stereo
through host adapters with actual standard mode and entropy state. It compares
both channels, folding output, metadata, masks, seed, remaining budget and all
entropy state fields. Controls include actual encoder-produced frames, both
N=2 signs/dominant channels, intensity/inversion override, both first-channel
orders/rebalances, depth-four recursive trees, legal TF/transient schedules,
fold/no-fold/zero fill, exact caps, edge remaining budgets, interleaved entropy
and consecutive folding/state propagation. Additional controls cover malformed
state, full-width scalars/capacities, full declared-span aliases/tails, read-only
sources, exact spans against guard pages at both ends, a guarded private stack
and late refusals. Functional calls check ABI/DF/FP preservation. The old mono
entry fails the stereo positive assertion. External SOURCE evidence records
semantic mutation results, guarded counts, explicit second-channel refusal
tracing and exact assembly/source/archive pins.

This slice supplies stereo band decoding only. It makes no complete Opus,
playback, QEMU, physical audio or release qualification claim. Original
predecessor reviews and current build and physical owners retain their work.
