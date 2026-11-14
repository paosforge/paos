# Native CELT split-angle decoding

`src/media/opus_theta.asm` implements the fixed-point Opus1.5.2 decode path of
`bands.c:compute_theta`, including `compute_qn`, all three entropy distributions,
stereo inversion, exact cosine/log2tan gains and the mid/side allocation delta.
It is an independent, unwired consumer of the existing range decoder. Recursive
band reconstruction, IMDCT and complete PCM playback remain separate work.

Call `media_opus_theta_decode(RDI=range64*, RSI=readonly config128*)`, returning
0 on success or -1 on refusal. The sixteen configuration fields are eight bytes
each; all are unsigned except the signed 64-bit LM field:

| Offset | Field | Admitted values |
|---:|---|---|
| 0 | N | 2..176 coefficients |
| 8 | b | 0..81600 eighth-bits allocated to this split |
| 16 | B | 1, 2, 4, 8 or 16 blocks for fill masking |
| 24 | B0 | 1, 2, 4, 8 or 16 original blocks for PDF selection |
| 32 | LM | -1..3, including recursive half-band resolution |
| 40 | stereo | 0 or 1 |
| 48 | band | Standard mode band 0..20 |
| 56 | intensity | First intensity band, 0..21 |
| 64 | disable_inv | 0 or 1 |
| 72 | remaining_bits | 0..81600 eighth-bits; upstream inversion gate input |
| 80 | fill | 0..65535 input mask |
| 88 | limit | Cumulative entropy cap in eighth-bits |
| 96 | output | Writable eight-i32 result |
| 104 | output_bytes | At least 32; extra declared capacity remains untouched |
| 112 | reserved0 | Zero |
| 120 | reserved1 | Zero |

The result contains `inv, imid, iside, delta, itheta, qalloc, b_after, fill_after`.
Angles span 0..16384 and gains follow upstream Q15 conventions. `qalloc` is the
actual fractional entropy cost, and `b_after=b-qalloc` can be negative, as in
upstream. `remaining_bits` is an input to this operation and is not decremented
by `compute_theta`. N, band and block inputs are bounded independently; this
helper does not prove that their combination comes from a valid CELT frame.

The standard mode's 21 `logN` entries and eight fractional exp2 values determine
qn. Signed division truncates toward zero. The decoder selects the stereo step
PDF for stereo N>2, the uniform PDF for B0>1 or stereo N=2, and the symmetric
triangular PDF otherwise. The triangular decoder scans at most 257 exact
cumulative intervals, producing the same symbol and range update as upstream's
integer-square-root inverse. No floating-point approximation is used.

At or above the intensity band, stereo forces qn=1. With qn=1 the inversion flag
is coded only when both b and remaining_bits exceed 16. `disable_inv` forces the
result to zero after consuming the coded flag. Endpoint angles select the exact
zero/unit gains and mask either half of fill; interior angles retain fill and
use the upstream bit-exact polynomials and positive-bias rounding.

Config and range state require eight-byte alignment, output four. Every full
declared span (config, state, output and nonempty readonly frame) must be pairwise
disjoint and lower canonical without carry. Admission uses all 64 bits. Callers
provide stable, truthful, mapped spans and serialize access; the helper does not
probe mappings or make publication concurrently atomic. The range state must be
valid with error zero. The cumulative cap must cover the initial consumed bits
and be at most frame_bytes*64. Final whole-bit and fractional consumption must
fit the physical frame and the caller cap, with no sticky entropy error.

State and result are staged locally. Every refusal leaves all caller storage
unchanged, including after a partially decoded symbol or late budget failure.
Success publishes exactly 32 result bytes and the range state. Config and frame
remain readonly; extra output capacity is untouched. SysV nonvolatile registers
and floating-point state are preserved, and DF clears on every return.

The oracle builds unchanged official `bands.c`, `modes.c`, `vq.c`, `mathops.c`
and entropy C sources with the actual `mode48000_960_120`. It verifies all 394
C/header files against the official archive before compilation. The archive is
`https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
The reference is host-only and is never linked into PaOS. Licenses are retained
in the assembly and [Xiph notice](../LICENSES/XIPH_OPUS_THETA.txt).

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
  python3 gauntlet_v2/tests/test_opus_theta_host.py -v
```

Controls cover every admitted N, all signed LM values, all bit-budget values,
actual encoded symbols at every discovered qn resolution for all three PDFs,
all band/intensity boundaries, mixed entropy preludes, inversion consumption and
overrides, every interior cosine argument, positive reachable log2tan pairs,
full-width structural and alias refusals, and late transactional budget failures.
Exact guarded spans exercise both edges with readonly config/frame. The handoff
records fail-first and assertion-caught mutation evidence. These are source
results; they establish no runtime, acoustic, device or full-RC result.
