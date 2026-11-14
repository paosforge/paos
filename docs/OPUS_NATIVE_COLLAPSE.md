# Native CELT transient anti-collapse

`src/media/opus_collapse.asm` ports fixed-point Opus1.5.2 `bands.c:anti_collapse`
and `vq.c:renormalise_vector`, including the exact gain polynomial, reciprocal
square root, seeded noise and rounding. It serves the standard 21-band CELT mode
with short MDCT size 120. It is independent and unwired; band recursion, synthesis
and full PCM decoding still need implementation.

Call `media_opus_anti_collapse(RDI=config152*)`, returning RAX=0 or -1. The
configuration has nineteen unsigned 64-bit fields:

| Offset | Field | Contract |
|---:|---|---|
| 0 | LM | 0..3; M=1<<LM, N=120*M coefficients per channel |
| 8 | channels | 1 or 2 |
| 16 | start | First band, 0..21 |
| 24 | end | Exclusive end, start..21; empty slices allowed |
| 32 | seed | uint32 random seed, taken by value |
| 40 | x | In-place i16 normalized spectra, channels*N entries |
| 48 | mask | Readonly u8 masks, band-major, 21*channels entries |
| 56 | pulses | Readonly i32 eighth-bit allocation values, 21 entries |
| 64 | log_energy | Readonly i16 Q10 current energies, 21*channels entries |
| 72 | prev1 | Readonly i16 Q10 previous energies, 42 entries |
| 80 | prev2 | Readonly i16 Q10 second previous energies, 42 entries |
| 88 | x_bytes | At least 2*N*channels |
| 96 | mask_bytes | At least 21*channels |
| 104 | pulse_bytes | At least 84 |
| 112 | log_bytes | At least 42*channels |
| 120 | prev1_bytes | At least 84, including for mono |
| 128 | prev2_bytes | At least 84, including for mono |
| 136 | scratch | Writable staged i16 spectra |
| 144 | scratch_bytes | At least 2*N*channels |

Config alignment is eight bytes, pulses four, spectra/logs/scratch two. Byte
masks need no alignment. All eight full declared spans must be disjoint,
nonnull, nonempty and lower canonical without carry. Capacities and scalars use
all 64 bits. Extra truthful capacity is admitted and its contents are untouched.
Callers own storage, supply stable mapped spans and serialize access. This
helper cannot establish page mappings or defend against concurrent mutation.

All 21 pulse values must be in 0..81600. In each selected band,
depth=floor((1+pulses)/N0)>>LM must be at most 255, where N0 is the standard
band width. This finite domain keeps the negated Q10 depth argument in signed
i16 range; it does not establish that every combination is a valid CELT frame.
Current and previous log energies cover the full signed i16 range. Each selected
band/channel input energy must be at most 2^29. Unselected coefficients are
copied unchanged, including the standard mode's final 20*M unused coefficients.

The helper checks every structural condition, all pulse bounds and every selected
input energy before writing scratch. Refusal changes no spans, including scratch.
Success stages the full frame and then publishes X. Config, masks, pulse values
and all energy inputs are readonly. Publication requires serialization and is
not concurrently atomic. SysV nonvolatile registers and FP state are preserved;
DF clears on every return.

For each band, the upstream algorithm derives the noise threshold from pulse
depth, computes the largest previous energy in each stereo history when current
output is mono, then compares current energy to the smaller history. LM3 applies
the exact sqrt(2) adjustment. A clear mask bit causes noise to fill that short
block at indices row*M+block, advancing seed=(1664525*seed+1013904223) mod 2^32
once per coefficient. Bit 0x8000 chooses its sign. Seed advances even when the
noise amplitude is zero. Like upstream, the seed is passed by value; its final
local value is not returned to the caller.

Any band/channel with a missing block is renormalized, even if injected noise
is zero. Normalization uses E=1+sum(x*x), the upstream reciprocal square root,
Q15 gain rounding and positive-bias sample rounding. The noise amplitude is
at most 8191/2^k, with k=floor(log2(N0*M)/2). Since N0*M<4^(k+1), injected energy
is less than 4*8191^2<2^28. Replacing coefficients cannot add more than that to
the original admitted 2^29, so E remains below 2^30 and signed i32 inner products
are safe. Accumulation for admission uses i64. These bounds exclude arbitrary
unnormalized upstream inputs whose signed arithmetic could overflow.

The external archive is `https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`,
SHA256 `65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
The host suite verifies it and all 394 included C/header files before compiling
whole unchanged `bands.c`, `modes.c`, `vq.c` and `mathops.c` with the actual static
standard mode. Unrelated functions are discarded using ordinary compiler/linker
section collection. No reference source is rewritten or linked into PaOS.
Exact consumed hashes and the full source manifest are retained in the handoff.
Complete terms are retained in the assembly and [Xiph notice](../LICENSES/XIPH_OPUS_COLLAPSE.txt).

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
  python3 gauntlet_v2/tests/test_opus_collapse_host.py -v
```

Place the unchanged archive beside the extracted source or set
`PAOS_OPUS_REFERENCE_ARCHIVE`. Controls cover all band slices, all LM/channel
modes, all 256 mask byte values, seed extremes and progression, every 0..65535
energy difference, 32770 tiny-amplitude normalization cases, near-unit
normalization boundaries, depth boundaries,
mono stereo-history selection, all 28 span alias pairs and full-width refusal.
Guarded exact storage checks readonly inputs and both frame edges. Independent
LCG sign/no-op/zero/near-unit anchors supplement the actual upstream oracle;
the standard band table is compared directly to the actual static mode. The
handoff retains fail-first and assertion-caught mutation evidence. This source
helper establishes no runtime, device, acoustic or full-RC result.
