# Native Opus CWRS pulse vectors

`src/media/opus_cwrs.asm` is an unwired integer decoding stage for signed CELT
PVQ pulse vectors. It ports the `SMALL_FOOTPRINT` recurrence and `cwrsi` ordering
from the official Opus 1.5.2 `celt/cwrs.c`; the range-coded entry calls the
accepted native `media_opus_range_uint`, `tell` and `tell_frac` primitives.
No runtime dispatch, device, allocation, mutable global or floating-point state
is involved. Band allocation, gain/normalization, spreading/rotations, transforms,
overlap, SILK, Ogg and complete Opus-to-PCM orchestration remain separate work.

## Exact admitted domain

Every pair `1 <= N <= 176`, `1 <= K <= 128` whose mathematical codebook count
`V(N,K) <= 0xffffffff` is admitted. Every other pair is refused. No modulo,
count truncation or approximate quantization is used. These limits follow the
standard-mode maximum dimension and pulse limit documented above Xiph's U table;
the generic recurrence admits intermediate dimensions as well as standard bands.

`U(N,0)=0` for positive N; `U(1,K)=1` for positive K. The initial U2 row is
`0,1,3,5,...`. Each subsequent term follows
`U(n,k)=U(n-1,k)+U(n,k-1)+U(n-1,k-1)`.
`V(n,k)=U(n,k)+U(n,k+1)`. Every sum is checked in 64 bits before narrowing.
All earlier row entries are monotone and bounded by the final U entries, so a
refusal on overflow cannot exclude a pair whose V fits u32. Unranking removes
one coordinate at a time, reproduces the upstream sign threshold and index
ordering, then computes the previous U row by subtraction. The unused final
previous-row computation is omitted. The squared norm is exact and bounded by
`K*K <= 16384`; subtraction, residual index and remaining K are checked.

N=1 uses the U base case explicitly documented by upstream: index0 is `+K`,
index1 is `-K`, count2. This is a mathematical low-dimensional helper case;
it does not claim that the outer CELT band decoder calls `decode_pulses` with
N=1. Other anchors are N2/K1: `(+1,0),(0,+1),(0,-1),(-1,0)`.

## Caller ABI

SysV x86-64; full64 arguments and pointers; RAX returns full64 -1 on refusal.
All nonvolatile GPRs and RSP are preserved; DF is clear on all returns; FP
control/MXCSR state is untouched. Mapping is the caller's responsibility:
canonicality checks do not probe whether memory is mapped. Callers serialize
access and keep immutable spans stable for the call.

| Entry | Inputs | Success |
| --- | --- | --- |
| `media_opus_cwrs_count` | RDI=N, RSI=K, RDX=u32 scratch pointer, RCX=exact scratch bytes `4*(K+2)` | RAX=unsigned V, including counts above INT32_MAX |
| `media_opus_cwrs_unrank` | RDI=readonly config64 pointer | RAX=0; signed i32 vector and u32 norm published |
| `media_opus_cwrs_decode` | RDI=initialized native range64 pointer, RSI=readonly config64 pointer | RAX=0; range state, signed vector and norm published |

Config is eight u64 fields, aligned8:

| Offset | Value |
| --- | --- |
| 0 | N |
| 8 | K |
| 16 | Unrank: index in `[0,V)`; decode: cumulative budget in eighth-bits |
| 24 | Signed i32 output pointer, N entries |
| 32 | Exact output byte length `4*N` |
| 40 | u32 squared-norm output pointer |
| 48 | u32 scratch pointer |
| 56 | Exact scratch byte length `4*(N+K+2)` |

Output, norm and scratch align4. Range state and config align8. All nonempty
spans must have nonzero lower-canonical starts, nonwrapping ends and entirely
lower-canonical bytes. The fixed structures and every full64 size are validated
before dereference/write. Every mutable span is pairwise disjoint and disjoint
from immutable config and entropy frame; readonly config/frame overlap is legal.
The accepted range helper validates its state64 and frame invariants unchanged.
No borrowed pointer is retained beyond the call. Scratch is the U row followed
by a staged vector; its maximum is 1224 bytes, with a 368-byte stack footprint
including saved GPRs and return address (nested helper calls use additional
bounded stack as described by the range module).

On refusal, output, norm, config, frame and public range state stay unchanged.
Scratch residuals may remain after arithmetic/index/entropy/budget refusals.
Structural size/alignment/alias failures occur before scratch mutation. On
success, publication follows all checks; this is transactional refusal behavior,
not a concurrent atomic multi-span update.

Decode copies state64 to the stack, decodes one uint index, checks sticky error,
physical consumed-bit bound and the caller's eighth-bit budget, then unpacks
into scratch. The budget must not exceed `frame_bytes*64` and must cover both
initial and final `tell_frac`; final `tell <= frame_bytes*8` is also required.
It is cumulative from entropy initialization, not an allowance to add per call.
Xiph intentionally pads exhausted entropy/raw reads with zeros. Some truncated
prefixes can pass these stage bounds: success does not prove whole-frame validity.

## Reproduction and evidence

Use an extracted unmodified official release; tests never fetch source or open
a device:

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
python3 -B -m unittest gauntlet_v2.tests.test_opus_cwrs_host \
  gauntlet_v2.tests.test_opus_packet_host -v
```

The harness verifies 394 official C/header hashes, compiles unmodified `cwrs.c`
in two configurations plus actual upstream entropy encoder/decoder, and assembles
this production source with the accepted range source. SMALL_FOOTPRINT provides
the oracle for the entire admitted domain. The default precomputed table omits
some generic pairs; both oracles are checked only when both initial U cells are
present in its documented row bounds. N1 uses the documented base case in a test
adapter around unmodified small `cwrsi`, with a one-bit sign encoder adapter.
No upstream source rewriting or substitute decoder is used.

Controls cover every bounded N/K cardinality including overflow refusals,
exhaustive small indices and independently enumerated vector sets, first/last,
sign/tie and deterministic random indices for every admitted pair, independent
vectors encoded into interleaved entropy/raw streams, state/tell/tell_frac,
malformed clamped uint and sticky error, exact budgets, independently encoded
truncated prefixes, guarded exact spans at both ends, full64 sizes/aliases and
ABI/DF/FP sentinels. The inherited nine range and six packet methods remain.
The concrete evidence directory records exact-base absence, -1 stub positive
failures and assertion-caught semantic mutants; assembly/compiler failures or
crashes are not counted as mutation kills.

Copyright and complete upstream terms are retained in the assembly,
`LICENSES/XIPH_OPUS_CWRS.txt` and `THIRD_PARTY_NOTICES.md`.
