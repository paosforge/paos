# Native CELT single-band TF decoding

`src/media/opus_band.asm` exports `media_opus_band_decode`, an unwired,
fixed-point Opus 1.5.2 `bands.c:quant_band` decoding/resynthesis consumer.
It composes the recursive partition and TF sample primitives. It supplies the missing orchestration of lowband Haar passes,
fill remapping, deinterleaving, recursive entropy decoding, inverse sample
reordering, time/frequency reconstruction, collapse remapping and optional
output scaled for later folding.

## ABI and supported domain

`RDI=range64*`, `RSI=readonly config160*`; RAX is 0 on success or -1 on refusal.
The range state is the existing `opus_range.asm` state. Config consists of
twenty full-width qwords; LM and TF change are signed two's-complement values.

| Offset | Meaning |
| --- | --- |
| 0 | Standard-mode band index, 0..20 |
| 8 | LM, -1..3 |
| 16 | Band allocation b, 0..81600 eighth-bits |
| 24 | Initial short-block count B, 1/2/4/8, divides N |
| 32 | Spreading, 0..3 |
| 40 | Q15 gain, 0..32767 |
| 48 | Initial remaining budget, 0..81600 eighth-bits |
| 56 | Unsigned 32-bit seed |
| 64 | Fill mask, 0..(1<<B)-1 |
| 72 | Absolute cumulative fractional entropy cap |
| 80 | Mutable i16 output[N] pointer |
| 88 | Output capacity, at least 2*N bytes |
| 96 | Optional readonly i16 lowband[N] pointer, or 0 |
| 104 | Lowband capacity, at least 2*N bytes, or 0 with absent pointer |
| 112 | Mutable six-u32 metadata pointer |
| 120 | Metadata capacity, at least 24 bytes |
| 128 | TF change, -3..3 |
| 136 | Optional mutable i16 lowband_out[N] pointer, or 0 |
| 144 | lowband_out capacity, at least 2*N bytes, or 0 with absent pointer |
| 152 | Reserved, must be 0 |

N is the standard-mode band width scaled by LM (halved for LM=-1), with
2<=N<=176 and a valid existing rate cache. Recombine=max(TF change,0) must
leave at least one block. Apply upstream's time-division loop while N/B is
even and TF change is negative; the resulting partition block count must be
at most 16 and its value shifted left by recombine must be at most 16. The
partition, recursive theta and PVQ helpers admit the resulting 16-block
geometry. Initial B remains at most 8; an initial B=8 may now time-divide
into 16 blocks. Schedules requiring more than 16 working blocks refuse.
N=1, stereo `quant_band_stereo`, other modes, complete frames and PCM synthesis
are outside this entry. Input remaining budget must be nonnegative; internal
and returned remaining budget may be negative, matching recursive decoding.
Callers must handle that returned signed value before another root call.

Metadata is the existing six-u32 layout: N, root q (UINT32_MAX for a split),
total charged cost, signed remaining_after bits, seed_after, final collapse
mask. Cost includes theta and leaf charges. Entropy state, budget and seed
come from the exact partition path; TF operations consume no entropy. The cap
must not exceed frame_bytes*64, initial tell_frac must fit it, and final whole
bit consumption must fit the frame. Equality at the fractional cap succeeds.

## Transaction and bounds

Config and state require 8-byte alignment, sample pointers 2-byte alignment,
metadata 4-byte alignment. Every declared span is validated at full 64-bit
width, including arithmetic carry and lower-canonical last byte. All seven
possible caller spans (config, state, output, metadata, frame, lowband and
lowband_out) must be disjoint across their **full declared capacities**.
An absent optional pointer requires zero capacity. Truthful, stable, mapped
spans, ownership of writable storage, serialization and sufficient stack are
caller obligations; this helper cannot establish mappings or concurrent custody.

The helper copies entropy state and the lowband into private storage. Every
Haar/reordering pass uses the existing TF helper with private input/output and
scratch. Recursive decoding and both final sample arrays are staged privately.
Only a completely successful operation publishes output, optional lowband_out,
metadata and range state. Publication is serialized, not concurrently atomic.
Any refusal, including after transforms or entropy work, preserves every caller
byte, including capacity tails and readonly sources. Capacity tails are never
written on success either. The existing per-leaf folding energy fence
`sum((abs(low)+4)^2)<=2^29` applies to the transformed lowband at each actually
used zero-pulse folding leaf; a violating leaf refuses transactionally.

The module uses no allocator, mutable globals, FP, devices or runtime wiring.
Its own frame is 4328 bytes plus 48 saved-register bytes and return address;
TF adapters add at most 16 bytes before their callee. Including bounded
recursive dependencies, 20 KiB of private stack is conservative. Host controls
use a 32 KiB guard-backed stack and verify its bottom 12 KiB remains untouched.
SysV nonvolatiles and x87/MXCSR are preserved and DF is clear on every return.

## Exact source and validation

The primary source is the whole unchanged official Opus 1.5.2 archive:
`https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
The implementation follows `celt/bands.c:quant_band` and `mathops.c:celt_sqrt`,
with fixed-point extraction/shift semantics from `fixed_generic.h`. Complete
upstream copyrights, grant and disclaimer are retained in the assembly and
`LICENSES/XIPH_OPUS_PARTITION.txt`; include them with distributions. The SOURCE
handoff pins the source files, all composed assembly and the original recursive
handoff. Original dependency reviews remain responsible for their own deltas.

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 python3 -B -m unittest \
  gauntlet_v2.tests.test_opus_band_host -v
```

The harness checks all 394 C/header files against the pinned archive, compiles
the whole unchanged `bands.c` and actual standard mode, and calls the real
`quant_band` through a host-only adapter. It compares exact samples, optional
scaled folding output, collapse masks, budgets, seed and every entropy state
field against assembled production code. Legal geometry/TF schedules,
transient/nontransient paths, all spreads, zero-pulse folds/noise/silence,
recursive depth four, actual encoder-produced frames, interleaved entropy,
exact fractional boundaries and independent mask/folding anchors are covered.
Every functional call checks ABI/DF/FP state. Additional controls exercise
full-width scalars and capacities, aliases including capacity-only tails,
readonly/both-end guard spans, a guarded private stack, malformed state and
late refusal. The unchanged old recursive-only entry fails the same positive
single-band control by an output assertion. Semantic mutations and exact
counts/logs are recorded in the external SOURCE handoff.

This source addition is not a complete Opus decoder, playback or hardware
qualification. Existing synthesis, review, build and physical audio owners
retain their work.
