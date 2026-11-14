# Native CELT standard-mode pulse budgets

`src/media/opus_rate.asm` supplies exact scalar pulse-budget helpers from
Opus1.5.2 `rate.h`, standard 48k mode cache constants, and `celt.c`'s `init_caps`
formula. It is unwired. No caller memory, allocator, entropy state, mutable
globals, FP or devices are used. These helpers select pseudo pulse indices and
integer K for the separate native CWRS/PVQ stages.

## APIs and finite domains

All arguments are full-width 64-bit register values and every export returns
RAX=-1 on refusal. Successful results are nonnegative integers.

| Export | Arguments | Success |
| --- | --- | --- |
| `media_opus_rate_get_pulses` | RDI=pseudo index 0..40 | Integer K, 0..128 |
| `media_opus_rate_bits_to_pulses` | RDI=band0..20, RSI=signed LM -1..3, RDX=eighth-bit budget0..81600 | Pseudo index 0..cache-row maximum |
| `media_opus_rate_pulses_to_bits` | Same band/LM, RDX=pseudo0..cache-row maximum | Eighth-bit cost |
| `media_opus_rate_cap` | RDI=band0..20, RSI=LM0..3, RDX=channels1/2 | Eighth-bit cap |

LM=-1 is encoded as the full 64-bit signed value -1 (`UINT64_MAX`); no other
negative or high-width alias is admitted. LM=-1/bands0..7 have cache index -1
and refuse before any cache access. There are 97 valid band/LM cache pairs.
Caps cover 168 band/LM/channel triples. The maximum admitted budget is the
physical 1275-byte Opus frame bound in eighth-bits; this bounds the helper's
input domain, not a claim that each per-band budget is a real frame allocation.
Only the official standard 48k/960 static mode is supported, not custom modes.

There are no borrowed pointers or public mutable spans. SysV nonvolatiles and
RSP are preserved, DF clears on every return, and x87/MXCSR state is untouched.
The implementation uses volatile GPRs with no stack frame or calls. The caller
must not mutate the module's private constants. Scalar results do not validate
an entropy frame, nor do they perform complete allocation.

## Exact formulas and table semantics

`get_pulses(i)` is i for i<8, otherwise `(8+(i&7))<<((i>>3)-1)`.
Index zero maps to K=0: the caller must handle the zero-pulse band separately;
positive native CWRS decode does not admit K=0.

Cache selection uses the exact signed i16 index at `(LM+1)*21+band`. The
392-byte cost cache stores its maximum pseudo index in byte zero and
cost-minus-one for positive indices. `pulses_to_bits(0)` returns zero; positive
indices return cache[index]+1 and must not exceed the row maximum.

`bits_to_pulses` decrements the supplied budget and executes exactly six
upstream binary-search iterations. The final comparison treats the lower
zero-pulse cost as -1 and chooses the lower index at an exact midpoint. This
preserves duplicate-cost plateaus and saturation behavior: for the N=1 row,
budget8 maps to index1 while budget9 maps to index40. Replacing this search with
a generic nearest-cost function can change results.

Caps use the exact 168-byte cache_caps array and 22 signed i16 band endpoints:
`((cache_caps[(2*LM+C-1)*21+band]+64)*C*N)>>2`, where
`N=(eBands[band+1]-eBands[band])<<LM`. Products fit i32 throughout the admitted
domain. All constants are directly extracted from unmodified official source;
no caller-supplied cache can bypass admission checks.

## Source, license and controls

The external archive is
`https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
Exact `rate.h`, `modes.c`, `static_modes_fixed.h` and `celt.c` source hashes,
extracted arrays and extraction script are in the SOURCE handoff. Full original
copyright, BSD grant and disclaimer are retained in the assembly and
`LICENSES/XIPH_OPUS_RATE.txt`; include the notice with binary distributions.

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 python3 -B -m unittest \
  gauntlet_v2.tests.test_opus_rate_host \
  gauntlet_v2.tests.test_opus_packet_host -v
```

Four new methods execute assembled production functions against actual
unmodified `rate.h`, official static mode definitions included through
`modes.c`, and actual `init_caps`. Ordinary hidden-section garbage collection
discards unrelated functions; no upstream source is rewritten. The inherited
harness verifies all 394 official C/header hashes. Seventeen CWRS/range controls
and six packet controls are retained.

Tests compare every one of 7,915,297 valid cache/budget inputs, every admitted
pseudo index/cost, all 41 K mappings and all caps. Independent linear cost
bracketing checks ties, first-upper/last-lower duplicate-cost behavior and
saturation through budget512. Literal plateau and caps anchors, full-width
and negative-domain refusal, ABI/DF/FP and assertion-caught semantic mutants
are recorded in the handoff. Every positive cached K is also admitted by the
existing native CWRS count helper for the corresponding standard band size.

Complete bit allocation/stereo decisions, band recursion, zero-pulse filling,
energy application, transforms/overlap, SILK and PCM synthesis remain separate.
This is source evidence; candidate/build/QEMU/metal/audio owners retain their
work. No runtime or playback qualification is claimed.
