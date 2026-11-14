# Native CELT Haar/Hadamard sample primitives

`src/media/opus_tf_shape.asm` provides exact fixed-point `haar1`,
`deinterleave_hadamard` and `interleave_hadamard` operations from official
Opus1.5.2 `celt/bands.c`, including its inverted bit-reversed Gray ordering table.
The module is unwired, with no imports, allocation, entropy state, FP, globals
or device access. The primitives support later CELT band reconstruction.

## API and domain

`media_opus_tf_shape(RDI=readonly config80*)` returns RAX=0 or -1. Config has
ten full-width unsigned qwords:

| Offset | Meaning |
| --- | --- |
| 0 | N0, positive per-lane element count |
| 8 | Stride, 1/2/4/8/16 |
| 16 | Operation: 0 Haar pass, 1 deinterleave, 2 interleave |
| 24 | Hadamard ordering, 0/1 |
| 32 | Readonly i16 input[N0*stride] pointer |
| 40 | Mutable i16 output[N0*stride] pointer |
| 48 | Exact byte length of both input and output, 2*N0*stride |
| 56 | Mutable scratch pointer |
| 64 | Exact scratch byte length, 2*N0*stride |
| 72 | Reserved, must be zero |

N0*stride must be at most 176; operation 0 requires hadamard=0; hadamard=1
requires stride>=2. There are 341 admitted dimension pairs and 1,353
operation/ordering/dimension combinations. This is a finite primitive domain,
not a claim that all combinations occur in standard CELT frames.

Config is 8-byte aligned and all sample arrays 2-byte aligned. Spans must be
truthful, stable, mapped lower-canonical 47-bit memory, with writable ownership
of mutable arrays. Every address, exact length and scalar is checked at full
64-bit width, including addition carry and last-byte canonicality. The helper
cannot establish arbitrary memory mappings or ownership. Caller serialization
is required.

Input and output may have exactly equal bases and lengths for in-place
operation. Any partial overlap refuses. Output and scratch must be disjoint
from config; scratch must also be disjoint from input and output. Readonly
input/config overlap is permitted. All structural checks finish before writes;
any refusal leaves config, input, output and scratch unchanged. On success,
input is preserved unless it is the exact output span. Scratch holds the staged
result before publication. Publication is serialized, not concurrently atomic.

Maximum scratch is 352 bytes. This module's own stack, including saved
registers and return address, is 288 bytes. SysV nonvolatiles are preserved,
DF clears on all returns, and x87/MXCSR state is untouched.

## Exact operations

For each lane i and pair j, Haar reads a=X[2*j*stride+i] and
b=X[(2*j+1)*stride+i]. It writes the signed i16 extractions of
`((23170*a+23170*b+16384)>>15)` and
`((23170*a-23170*b+16384)>>15)`, with arithmetic shifts. Integer intermediates
fit signed i32 across the full signed i16 input domain. Extraction intentionally
wraps instead of saturating, matching upstream. N0 is halved with truncation;
for odd N0 the last stride samples remain unchanged. N0=1 is an exact identity.
This single Haar pass is not claimed to be an exactly reversible integer map.

For reorder operations, natural index is j*stride+i and ordered index is
order[i]*N0+j. Without Hadamard, order[i]=i. With Hadamard, the exact table
starts at stride-2 in the upstream concatenated 2/4/8/16 table. Deinterleave
assigns output[ordered]=input[natural]; interleave reverses that mapping. These
permutations are exact inverses, including in-place calls through scratch.

## Reference and host controls

The external official archive is
`https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
Exact consumed `bands.c`, `bands.h`, `arch.h` and `fixed_generic.h` hashes are
recorded in the SOURCE handoff. All 394 official C/header hashes are checked
by the inherited host harness. Full upstream copyright, BSD grant and
disclaimer are retained in the assembly and `LICENSES/XIPH_OPUS_TF_SHAPE.txt`;
include the notice with binary distributions.

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 python3 -B -m unittest \
  gauntlet_v2.tests.test_opus_tf_shape_host \
  gauntlet_v2.tests.test_opus_packet_host -v
```

Five new methods execute production assembly and compile the actual unmodified
fixed-point `bands.c` functions through a small adapter. Ordinary hidden-section
garbage collection drops unrelated functions; no reference source is rewritten.
Controls cover every admitted dimension/operation/ordering, both in-place and
separate output, all 65,536 signed amplitudes with independently varied partner
values, literal rounding anchors, odd tails, independent permutation indexing,
inverse permutations and repeated Haar schedules. Full-width, malformed, alias,
reserved-field, ABI/DF/FP and exact both-end guard-backed spans exercise refusal.
Partial-alias mutation controls use oversized owners so execution remains in
truthful mapped spans. Seventeen CWRS/range and six packet controls remain.
Fail-first and assertion-caught semantic mutation evidence is in the handoff.

Allocation, band recursion/orchestration, collapse handling, denormalization,
MDCT/overlap, SILK and complete PCM synthesis remain separate. There is no
runtime, candidate, QEMU, metal or audio qualification claim. Existing owners
retain their work and device windows.
