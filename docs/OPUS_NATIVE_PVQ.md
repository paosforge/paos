# Native Opus fixed-point PVQ band shapes

`src/media/opus_pvq.asm` implements the fixed-point band-shape stage of Xiph
Opus 1.5.2 `alg_unquant`: integer pulse normalization, inverse spreading
rotations, and the collapse mask. It is unwired. The entropy entry composes
`media_opus_cwrs_decode` and the accepted range helper. No allocator, global
state, FP instructions, device access or runtime wiring is added.

The official archive is `https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`,
SHA256 `65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
The reference files are unmodified external test material:

| File | SHA256 |
| --- | --- |
| `celt/vq.c` | `6bcac75293c49b302112546f84d088888e2e413634c6144fa7e0eabc1220c0ab` |
| `celt/vq.h` | `7ae88b5432a9ddd666ab61c9a608107535a7ecc7126df5a42787147049abc1ae` |
| `celt/mathops.c` | `ae290fb07e3a10b7a93af524898a5b738e6cb48c5b1e7d24e7fb44fb6249d903` |
| `celt/mathops.h` | `18969073f5f53798a5e9f37d05fcf6a26ad4cc8c9ffb3e5d88d8bc0523c17960` |
| `celt/arch.h` | `f68968ce97da945db33f844374ffc31f9200be229bf9da1b56735eb8e969ee00` |

Copyright and the complete BSD grant/disclaimer are in the assembly and
`LICENSES/XIPH_OPUS_PVQ.txt`; include the notice with binary distributions.

## ABI and finite domain

Both entries return RAX=0 on success, -1 on refusal. `media_opus_pvq_shape`
takes RDI=readonly config pointer. `media_opus_pvq_decode` takes RDI=mutable
64-byte range state and RSI=readonly config pointer. The config is 96 bytes,
twelve full-width unsigned qwords:

| Offset | Meaning |
| --- | --- |
| 0 | N, 2..176 |
| 8 | K, 1..128, with exact CWRS cardinality V(N,K) <= UINT32_MAX |
| 16 | Gain, Q15 integer 0..32767 |
| 24 | Spread, 0:none, 1:light, 2:normal, 3:aggressive |
| 32 | B, 1/2/4/8/16, dividing N |
| 40 | Decode: cumulative eighth-bit budget; shape: must be zero |
| 48 | Shape: readonly i32 pulse[N] pointer; decode: must be zero |
| 56 | Mutable i16 shape[N] output pointer |
| 64 | Exact output byte length, 2*N |
| 72 | Mutable u32 collapse-mask pointer |
| 80 | Mutable scratch pointer |
| 88 | Exact scratch byte length, 10*N+4*K+12 |

N=1 is excluded: upstream `alg_unquant` asserts N>1. Zero pulses, fractional
block lengths, gains outside this Q15 domain and overflowing codebooks refuse.
This includes 1,659 admitted (N,K) pairs. The gain-scaled output uses CELT's
fixed-point `celt_norm` representation (Q14 at unit Q15 gain).

Config and state require 8-byte alignment; pulses, mask and scratch 4-byte;
output 2-byte. All nonempty spans must be truthful, stable, mapped and in the
lower canonical 47-bit address space. The helper checks full 64-bit arguments,
addition carry and final-byte canonicality before accessing a span. It cannot
validate that arbitrary mapped memory belongs to the caller. Caller
serialization is required.

Output, mask, scratch and (for decode) state must be pairwise disjoint, and
must not overlap readonly config, pulse input or nonempty entropy frame.
Readonly spans may overlap each other. Entropy frame length and state
invariants retain the range helper's 0..1275-byte bound. A zero-length frame
has no borrowed span. Reserved/errored/stale state refuses.

Scratch contains CWRS work `4*(N+K+2)`, pulse staging `4*N`, a norm u32 and shape
staging `2*N`, in that order. Only shape staging needs 2-byte alignment. For
odd N the exact scratch length is 2 modulo 4; the base still requires 4-byte
alignment. A scalar upper bound is 2,284 bytes. This module's own frame,
including saved registers and return address, is 544 bytes; called helpers
have their separately documented stack requirements.

## Exact fixed-point behavior

For pulse norm Ryy, k=floor(log2(Ryy))/2, t=Ryy<<(14-2*k),
g=MULT16_16_P15(celt_rsqrt_norm(t),gain), and
X[j]=PSHR32(g*iy[j],k+1). The port keeps upstream signed extraction and rounding,
including negative ties and reciprocal-square-root polynomial/Householder
casts. Pulse L1 must equal K and each magnitude is bounded before its square;
Ryy is positive and at most K*K, at most 16384.

Spreading skips for spread=0 or 2*K>=N. Otherwise the factors are 15/10/5,
the divisor N+factor*K, and the LP64 fixed-point `celt_div` uses the exact
upstream reciprocal/Newton iterations. Cosine coefficients and rounding are
ported without substituting floating point or ordinary integer division.
For each contiguous block N/B, the inverse second-stride rotation (when
N>=8*B) precedes stride 1. Both forward and backward sweeps use the original
pair values, upstream PSHR rounding and signed 16-bit extraction. The second
stride is the least positive i with (i*i+i)*B+(B>>2)>=N.

Collapse bit b is set when any original integer pulse in block b is nonzero.
It is computed before normalization and spreading. Thus zero gain and tiny
negative pulses can produce an all-zero output with a nonzero collapse mask.

## Transactions and limits

On refusal, output, mask, entropy state and all readonly inputs are unchanged.
Structural argument/alias checks finish before any scratch write. A late
codebook/pulse/budget/error refusal may leave scratch residuals. Entropy is
decoded on a local state copy; shape and mask are staged until all checks pass.
Success then publishes the shape, mask and state. This is a serialized
transactional API, not a concurrent atomic publication primitive.

Decode budget is cumulative `ec_tell_frac` in eighth-bits, checked before and
after decoding, and cannot exceed frame bytes*64. Physical whole-bit bounds
and sticky entropy errors retain the CWRS/range checks. Xiph implicit zero
padding is preserved; this is not complete frame validation and cannot detect
every truncated frame. DF is cleared on every return, SysV nonvolatiles are
preserved, and x87/MXCSR state is untouched.

## Host verification

Run with the pinned extracted release:

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 python3 -B -m unittest \
  gauntlet_v2.tests.test_opus_pvq_host \
  gauntlet_v2.tests.test_opus_packet_host -v
```

The harness inherits 17 CWRS/range controls and retains six packet controls.
Seven new methods compile and execute the actual unmodified fixed-point
`alg_unquant`, `normalise_residual`, `exp_rotation` and collapse extraction.
All 394 official C/header hashes are checked by the parent harness. Tests cover
all admitted pairs, all spread modes, legal block counts, selected boundary
gains, every gain for a signed unit vector, exhaustive small codebooks,
independently encoded random signed pulse vectors and interleaved tail bits.
Private math probes cover all 49,152 normalized rsqrt inputs, all 32,768 cosine
inputs in the used quadrant, and reciprocal divisors 1..2099.

Malformed/stale/full-width/alias checks, both-end guard-backed spans, ABI/DF/FP
checks, error/truncation transactions and exact fractional-budget boundaries
exercise refusal. For odd N the scratch end guard has two alignment-padding
bytes, checked as canaries. Test-only exports do not expand the production ABI.
Fail-first and assertion-caught semantic mutants are recorded in the SOURCE
handoff evidence; compiler failures and crashes are not counted as detections.

This is band-shape source evidence. Allocation/pulse selection, band recursion,
energy application, transforms, overlap, SILK, full frame synthesis and PCM
playback remain separate. QEMU, metal, audio and candidate ownership are
unchanged; this helper claims none of those qualifications.
