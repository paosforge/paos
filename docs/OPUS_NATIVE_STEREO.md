# Native CELT stereo reconstruction

`src/media/opus_stereo.asm` independently ports the fixed-point Opus1.5.2
`bands.c:stereo_merge` operation and its reciprocal square root. It is unwired.
Band recursion, pulse/energy orchestration, transforms and PCM synthesis still
need implementation; this helper establishes no playback or hardware result.

Call `media_opus_stereo_merge(RDI=config64*)`, returning RAX=0 on success or -1
on refusal. The configuration consists of eight unsigned 64-bit fields:

| Offset | Field | Contract |
|---:|---|---|
| 0 | N | 1 through 176 coefficients |
| 8 | mid | 0 through 32767, Q15 |
| 16 | left | In-place signed i16 Q14 mid vector |
| 24 | right | In-place signed i16 Q14 side vector |
| 32 | left_bytes | At least 2*N |
| 40 | right_bytes | At least 2*N |
| 48 | scratch | Temporary storage for both resulting vectors |
| 56 | scratch_bytes | At least 4*N |

The configuration is aligned to eight bytes; channel arrays and scratch to two.
All four complete declared spans must be disjoint, nonempty and entirely in the
lower canonical address range. Capacities use all 64 bits, including in carry
and alias checks. Extra capacity is permitted and its contents are untouched.
Callers supply truthful, stable, mapped, caller-owned spans and serialize calls.
The helper cannot establish page mappings or defend against concurrent mutation.

Each input vector's sum of squares must be at most 2^29. Both sums are checked
with wide arithmetic before any scratch write. This finite normalized-input
domain excludes unnormalized values for which upstream signed arithmetic could
overflow. The cross product is bounded by 2^29; after mid scaling its magnitude
is at most 2^29. Consequently mid2^2 + side +/- 2*xp fits signed 32 bits
(the upper bound is below 1,879,048,193). Negative results take the upstream
fallback. The norm formula intentionally uses the normalized mid assumption,
rather than substituting the actual left input energy.

The port preserves the exact signed arithmetic shifts, Q15 mid multiplication,
int16 sum/difference wrapping, reciprocal square root and positive-bias PSHR32
rounding. If either reconstructed channel energy is below 161061 in Q28, the
left vector is copied to the right and left is retained. Otherwise both
reconstructed vectors are staged in scratch and then copied to their channels.
Refusal leaves configuration, channels and scratch unchanged. Publication is
serialized, rather than a guarantee of atomic visibility to concurrent readers.
SysV nonvolatile registers and FP state are preserved, and every return clears DF.

The upstream archive is
`https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
Relevant source hashes:

| Source | SHA256 |
|---|---|
| celt/bands.c | `4f17c6b37cd2897d0ed879c46fe2ac104bf20deb1d7a07d8099f83dddc2f1cde` |
| celt/mathops.c | `ae290fb07e3a10b7a93af524898a5b738e6cb48c5b1e7d24e7fb44fb6249d903` |
| celt/fixed_generic.h | `0185be2436b154667da33fc7bd8af6c07290980681c767fb2d3c89985cf7d308` |
| celt/pitch.h | `9104a47681a39cb58051869434af85557fe0d31aab16d73ddb4ca508b6cb5877` |
| celt/arch.h | `f68968ce97da945db33f844374ffc31f9200be229bf9da1b56735eb8e969ee00` |

Run the host suite with the extracted official archive and its unchanged sibling
`opus-1.5.2.tar.gz` (or set `PAOS_OPUS_REFERENCE_ARCHIVE`):

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
  python3 gauntlet_v2/tests/test_opus_stereo_host.py -v
```

The suite verifies the archive and all included C/header bytes before compiling
whole unchanged `bands.c`, `mathops.c` and `entcode.c`, with ordinary section
collection to discard unrelated functions. It compares every mid value,
all supported dimensions, all 46,341 admitted single-coordinate amplitudes,
degeneracy thresholds, sign/wrap boundaries, energy boundaries, full-width
admission, declared-span aliases and guarded exact storage. ABI checks cover
success and refusal with incoming DF set. Independent zero/degenerate anchors
supplement the upstream oracle. A source-only handoff retains preimplementation
fail-first and assertion-caught mutation evidence. No full image or device is
needed to execute this independent helper's host controls.

Full upstream terms are in [the stereo notice](../LICENSES/XIPH_OPUS_STEREO.txt).
