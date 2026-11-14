# Native CELT multiband spectral decoding

`src/media/opus_multiband.asm` exports `media_opus_multiband_decode`, an unwired
fixed-point Opus 1.5.2 `celt/bands.c:quant_all_bands` decode consumer. It connects
the existing allocation and TF output records to the mono/stereo band helpers.
The entire active spectrum, normalization history, collapse masks, seed and
entropy state stay private until every band and final entropy check succeeds.
No predecessor implementation or runtime decoder is changed.

## ABI

`RDI=range64*`, `RSI=readonly config192*`; RAX is 0 on success or -1 on refusal.
The config contains 24 full-width qwords:

| Offset | Meaning |
| --- | --- |
| 0 | Start band, 0..20 |
| 8 | Exclusive end band, start+1..21 |
| 16 | Channels, 1 or 2 |
| 24 | LM, 0..3 |
| 32 | Transient flag, 0 or 1 |
| 40 | Spreading, 0..3 |
| 48 | Spectral total budget, 0..81600 eighth-bits |
| 56 | Unsigned 32-bit seed |
| 64 | Disable stereo inversion, 0 or 1 |
| 72 | Absolute cumulative fractional entropy cap |
| 80 | Readonly actual allocation record pointer |
| 88 | Allocation capacity, at least 288 bytes |
| 96 | Readonly packed signed i32 TF results pointer |
| 104 | TF capacity, at least 4*(end-start) bytes |
| 112 | Mutable packed left i16 coefficients pointer |
| 120 | Left capacity, at least 2*Nspan bytes |
| 128 | Mutable packed right i16 coefficients pointer; zero for mono |
| 136 | Right capacity, at least 2*Nspan bytes; zero for mono |
| 144 | Mutable packed u8 collapse masks pointer |
| 152 | Mask capacity, at least (end-start)*channels bytes |
| 160 | Mutable eight-u32 metadata pointer |
| 168 | Metadata capacity, at least 32 bytes |
| 176,184 | Reserved zero |

`M=1<<LM`, `Nspan=M*(eBands[end]-eBands[start])`, at most 800 coefficients
per channel. Outputs start at the first active band, with no prefix for bands
below start. Masks use band-major channel order. TF inputs use the existing
`media_opus_tf_decode` packed ABI: TF[0] corresponds to start, not band zero.

The allocation record is exactly the output of
`media_opus_celt_allocation_decode`: four qwords for codedBands, signed balance,
intensity and dual_stereo; 21 i32 pulses at byte32, 21 i32 fine-energy counts at
116, 21 i32 fine priorities at 200, and four zero reserved bytes at 284.
Admission requires codedBands in start+1..end, balance in -81600..81600,
intensity in 0..21, dual_stereo in 0..1 (zero for mono), pulse budgets in
0..81600, fine counts in 0..8 and priorities in 0..1. All inactive array entries
must be zero. Fine counts and priorities are validated but not consumed by this
spectral stage. It consumes the supplied entropy position; energy refinement
and other frame phases remain the caller's responsibility. This entry neither
parses a packet nor invents a compressed wire format.

Metadata comprises eight u32 values: **start, end, channels, Nspan, seed_after,
signed final balance, final tell_frac, final dual_stereo**. Interpret balance as
i32. Its bounded telescoping value is initial_balance + sum(active pulses) +
initial_tell_frac. The entropy cap is cumulative from the range state, must not
exceed frame_bytes*64, and admits exact equality. Final rounded whole-bit
consumption must also fit the physical frame. It is separate from the spectral
budget, which determines allocation and may already be below tell_frac.

## Supported domain and loop

The only mode is the actual standard 48 kHz 21-band mode. Every active band has
N=M*width. B is M for transients and 1 otherwise. N=1 uses the actual raw sign
path: one bit per channel iff signed remaining>=8, charge eight eighth-bits,
coefficient +/-16384 and folding value coefficient>>4. It ignores band budget,
TF and fill as upstream does, after validating TF lies in -3..3.

For N>=2, existing mono/stereo geometry, cache and arithmetic fences apply.
Positive TF recombination must leave a nonzero B; subsequent time division
must leave at most eight partition blocks and block count shifted by recombine
at most sixteen. A transformed folding leaf must satisfy
`sum((abs(low)+4)^2)<=2^29`, and stereo merge energy bounds remain enforced.
Unsupported geometry refuses the whole transaction, even if detected late.

The slice start=19/end=21 is explicitly refused. In unchanged upstream,
normalization capacity per channel is M*(eBands[20]-eBands[19])=18*M, while
special_hybrid_folding copies through 22*M entries on the second band. In
stereo this overlaps norm2's prefix and exceeds the combined allocation.
The harness demonstrates both 32-element overwrites for M=8 using the real
upstream helper on an enlarged diagnostic array. It never invokes the whole
upstream loop on that unsafe slice. Other slice offsets are swept normally.

The loop carries signed balance, recomputes true signed remaining from the
shared entropy position, divides balance by min(3,codedBands-i) with C signed
truncation, clamps b to 0..16383, and uses zero allocation beyond codedBands.
It updates lowband offsets only at the upstream energy threshold, applies
special hybrid copying, computes conservative masks over the exact folding
range, and supplies seeded noise when folding is unavailable. Dual stereo uses
separate normalized histories and b/2 per channel. At i==intensity it averages
prior histories with a signed shift and continues joint stereo. Joint decoding
unions the input masks and publishes the same resulting mask for both channels.

A private adapter maps negative signed remaining to zero for public band calls,
then subtracts their actual charge from the original signed value. Seed remains
shared. Lowband input is copied before calling a helper because upstream hybrid
folding can overlap its input with the current normalized output, whereas the
public band ABI forbids aliases. Last-band normalized output is unnecessary.

## Transaction, memory and stack

Config/state/allocation require eight-byte alignment, TF/metadata four-byte
alignment, samples two-byte alignment; masks and frame require byte alignment.
All nine possible nonempty spans (config, state, allocation, TF, left, right,
masks, metadata, frame) must be mutually disjoint over full declared capacities,
including readonly pairs and capacity tails. Mono requires both right fields
zero. Full 64-bit extent, carry and lower-canonical last-byte checks precede
input copying. Stable truthful mapped spans, writable outputs, serialization
and adequate stack remain caller obligations.

Any refusal preserves all caller bytes, including after earlier bands or the
first dual channel succeed. Success writes exactly the active samples, masks,
32-byte metadata and 64-byte range state. Capacity tails and inputs are
preserved. Publication consists of serialized copies, not concurrent atomicity.

The root frame is 8808 bytes plus 48 saved-register bytes and a return address.
The private adapter adds sixteen bytes including its return address. Existing
stereo/mono/recursive dependencies are bounded at 24 KiB; 36 KiB of private
stack is conservative for the composition. Guards provide 64 KiB and check the
bottom 28 KiB remains untouched. Work is bounded by 21 bands, at most two band
calls each, and the inherited depth-four, at most 31-node recursive partition
per mono call (62 for stereo). There is no allocator, mutable global, device
access or FP use. SysV nonvolatiles and x87/MXCSR are preserved and DF is clear
on every return.

## Provenance and controls

Primary source: whole official Opus 1.5.2 archive,
`https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
The port follows all of `bands.c:quant_all_bands`, special_hybrid_folding and
the decode-side N=1 path, with `entcode.h:celt_sudiv` and fixed-point semantics.
Original copyrights, conditions and disclaimer remain in the assembly and
`LICENSES/XIPH_OPUS_PARTITION.txt` / `LICENSES/XIPH_OPUS_STEREO.txt`; include
the notices with distributions.

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 python3 -B -m unittest \
  gauntlet_v2.tests.test_opus_multiband_host -v
```

The harness verifies all 394 C/header files against the pinned archive and
compiles whole upstream sources. Adapters call actual quant_all_bands,
tf_decode and clt_compute_allocation with the actual mode and entropy coder.
It compares all coefficients, masks, metadata, seed and complete entropy fields.
Coverage includes mono/stereo, LM/transients, every safe standard band slice,
N=1 raw-sign thresholds, signed balances, coded-band skips, intensity changes,
folding, encoder-produced streams, real native TF/allocation outputs, exact
caps and interleaved/short entropy. The actual predecessor stereo entry fails
the positive assertion. Structural, full-span alias, readonly, both-end exact
guard-page and private-stack controls accompany functional ABI/DF/FP checks.
External SOURCE evidence records semantic mutants and separately instrumented
late-band/right-channel refusal traces. Original mono, stereo, recursive,
allocation and TF suites are retained.

This consumer supplies a spectral backend only. Complete frame parsing,
energy/synthesis integration, PCM, playback, QEMU, hardware audio and release
qualification remain separate work. Original dependency reviews, current
builds and physical owners retain their work.
