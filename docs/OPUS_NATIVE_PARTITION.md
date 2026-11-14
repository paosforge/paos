# Native CELT unsplit partition decoding

`src/media/opus_partition.asm` ports the fixed-point decode/resynthesis branch
of Opus 1.5.2 `bands.c:quant_partition` for partitions that do not split. It
composes the existing rate-cache and PVQ decoders, reduces pseudo-pulses against
the remaining budget, and reconstructs zero-pulse bands with exact noise or
lowband folding and gain normalization. It is independent and unwired.

Call `media_opus_partition_decode(RDI=range64*, RSI=config128*)` using the
existing range decoder state. RAX is 0 on success or -1 on refusal. Configuration
contains 16 full-width unsigned 64-bit fields, except signed LM:

| Offset | Field | Contract |
|---:|---|---|
| 0 | band | Standard 48 kHz mode band, 0..20 |
| 8 | LM | Signed -1..3 |
| 16 | b | Local allocation in eighth-bits, 0..81600 |
| 24 | B | 1, 2, 4, 8 or 16, dividing N |
| 32 | spread | 0..3 |
| 40 | gain | Q15, 0..32767 |
| 48 | remaining | Remaining frame allocation in eighth-bits, 0..81600 |
| 56 | seed | uint32 random state |
| 64 | fill | uint16 collapse/folding mask |
| 72 | cap | Cumulative entropy limit in eighth-bits |
| 80 | output | Writable i16[N] vector |
| 88 | output_bytes | At least 2*N |
| 96 | lowband | Optional readonly i16[N] vector |
| 104 | lowband_bytes | At least 2*N when present; zero when absent |
| 112 | meta | Writable six-u32 result |
| 120 | meta_bytes | At least 24 |

N is the actual standard-mode band width scaled by 2^LM (halved for LM=-1).
This helper admits N=2..176 and requires a valid rate-cache entry. It refuses
exactly the upstream split condition: LM!=-1, N>2 and b>cache[last]+12. Thus the
entire 0..81600 budget domain is available for valid N=2 or LM=-1 partitions;
other combinations stop at the upstream no-split boundary. Admission of these
independent bounds does not establish a valid complete CELT frame.

Metadata is `N, q, curr_bits, remaining_after, seed_after, collapse_mask`, six
consecutive u32 values. First q is chosen by `bits2pulses(b)`. Its cost is
subtracted from remaining; q decreases until the cost fits, exactly as upstream.
For positive q, accepted `media_opus_pvq_decode` consumes the pulse symbol and
reconstructs the vector with B, spread and gain. For zero q, masked fill zero
produces zero samples without advancing seed. Otherwise every coefficient
advances the uint32 LCG. An absent lowband produces signed noise and all-B
collapse bits. A present lowband produces the upstream +/-4 dither and retains
the masked fill bits. Both filled paths use exact `renormalise_vector` semantics,
including EPSILON=1, fixed-point reciprocal square root and rounding.

For a zero-pulse, nonempty fill using lowband, the conservative input fence
`sum((abs(lowband[j])+4)^2)<=2^29` prevents signed sample wrap and bounds the
renormalization energy. Unused lowband samples are not energy-restricted.
Noise energy is independently bounded below 2^30 for N<=176. Gain zero and
full-range uint32 seeds are supported.

Configuration/state align to eight bytes, output/lowband to two, and metadata
to four. All full declared spans, including nonempty readonly frame bytes,
must be pairwise disjoint, lower canonical and without pointer addition carry.
A missing lowband requires both pointer and capacity zero. Truthful larger
capacities are admitted and their tails remain unchanged. Callers supply stable,
mapped storage and serialize calls; the primitive cannot establish mapping or
protect against concurrent changes. Publication is not concurrently atomic.

Range error must be clear. The cumulative cap must be at least initial
`tell_frac` and at most physical frame bytes*64. Final whole-bit and fractional
limits are checked. All work uses private bounded stack storage (3144 bytes in
the public entry, plus bounded helper call frames); no allocator, caller scratch,
mutable globals or FP is used. Any refusal preserves every caller span,
including after a late PVQ/entropy failure. Success publishes the vector,
metadata and range state only after all checks. SysV nonvolatile registers and
FP state are preserved; DF clears on every return.

Source is the official archive
`https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
The external oracle compiles whole unchanged fixed-point `bands.c`, `modes.c`,
`vq.c`, `cwrs.c`, `mathops.c` and entropy sources using the actual standard mode.
Every C/header byte (394 files) is checked against the archive before compilation.
No reference C is linked into PaOS. Full source hashes and the exact-base control
are retained in the SOURCE evidence. Complete attribution, grant and disclaimer
are in the assembly, [partition notice](../LICENSES/XIPH_OPUS_PARTITION.txt)
and third-party notices.

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
  python3 gauntlet_v2/tests/test_opus_partition_host.py -v
```

Place the unchanged release archive alongside the extraction or set
`PAOS_OPUS_REFERENCE_ARCHIVE`. Eleven methods compare all valid mode/cache
pairs, every N=2 budget, all 32768 gains, mask/seed/block/spread combinations,
actual upstream pulse-encoder frames, exact split/cost boundaries, entropy
preludes, short/empty frames, late refusals, fold-energy limits and full-width
span/alias rules. Four additional upstream comparisons use exact guarded pages
with readonly configuration/frame/lowband. ABI checks wrap every native call.
Fail-first and compiled assertion-caught mutation evidence accompany the handoff.

Recursive splitting, N=1 band special cases, band orchestration, transforms and
PCM synthesis remain separate work. This helper supplies no device, runtime,
playback, acoustic or full-RC result.
