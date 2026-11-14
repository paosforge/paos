# Native CELT spectral denormalization

`src/media/opus_denorm.asm` ports the fixed-point Opus1.5.2
`bands.c:denormalise_bands` and `mathops.h:celt_exp2_frac`. It restores spectral
magnitudes for the standard 48 kHz CELT mode (21 bands, short MDCT size 120).
It is independent and unwired; band recursion, synthesis transforms and full
PCM decoding remain separate work.

Call `media_opus_denormalise_bands(RDI=config104*)`, returning RAX=0 or -1.
All configuration fields are unsigned 64-bit values:

| Offset | Field | Contract |
|---:|---|---|
| 0 | LM | 0..3, with M=1<<LM and N=120*M |
| 8 | start | First band, 0..21 |
| 16 | end | Exclusive end, start..21; empty slices allowed |
| 24 | downsample | 1, 2, 3, 4 or 6 |
| 32 | silence | 0 or 1 |
| 40 | input | Readonly i16 Q14 normalized spectrum, N entries |
| 48 | log_energy | Readonly i16 Q10 energies, 21 entries |
| 56 | output | Writable i32 fixed-point spectrum, N entries |
| 64 | input_bytes | At least 2*N |
| 72 | log_bytes | At least 42 |
| 80 | output_bytes | At least 4*N |
| 88 | scratch | Writable i32 staged spectrum, N entries |
| 96 | scratch_bytes | At least 4*N |

The configuration is aligned to eight bytes, input/energies to two, and
output/scratch to four. All five full declared spans must be disjoint, positive,
nonnull and lower canonical without carry. Full 64-bit capacities are checked;
larger truthful capacities are admitted and their tails remain untouched.
Callers own storage, supply stable mapped spans and serialize calls. Mapping
and concurrent changes cannot be established by this primitive.

All structural checks finish before any scratch write. Refusal leaves every
span unchanged, including scratch. Success stages all N coefficients before
publishing output. Config and both inputs are readonly. SysV nonvolatile
registers and FP state are preserved, and DF clears on every return.

The immutable eBands and eMeans values come from unchanged upstream `modes.c`
and `quant_bands.c`. For each band, the Q10 log energy is saturated to i16 after
adding eMeans*64. The integer part determines the shift and the fractional part
uses the exact Q15 cubic polynomial. Underflows with shift>31 produce zero;
shift<=-2 caps gain to 16384 with shift=-2, equivalent to the upstream log gain
cap of 18. Signed i16 samples and energies are admitted across their full ranges,
including the extreme result -2147483648. This bounded scaling needs no FP.

Leading bands are zeroed. The spectral tail is zero from the smaller of
M*eBands[end] and N/downsample. Silence and empty slices produce complete zero
spectra. Bands above a downsample cutoff are finally cleared exactly as upstream;
this function restores spectral amplitudes and does not implement a resampler.
The finite function domain includes combinations a later packet parser may
restrict further; admission does not establish a valid complete CELT frame.

The official archive is `https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`,
SHA256 `65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
Tests check that archive and every included C/header file before compiling whole
unchanged `bands.c`, `modes.c` and `quant_bands.c`, using the actual static mode.
Unrelated source sections are discarded through ordinary compiler/linker options;
no reference source is rewritten and no reference C is linked into PaOS.
Exact consumed source hashes and the 394-file manifest are retained in the
SOURCE evidence. Complete upstream terms are retained in the assembly,
[denormalization notice](../LICENSES/XIPH_OPUS_DENORM.txt) and third-party notices.

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
  python3 gauntlet_v2/tests/test_opus_denorm_host.py -v
```

Place the unchanged release archive beside the extracted tree, or set
`PAOS_OPUS_REFERENCE_ARCHIVE`. Controls cover all 253 empty/nonempty band slices,
all four LM modes, five downsample factors and both silence values; all 65,536
i16 log energies against both upstream and an independent integer formula; all
1,024 fractional gains with extreme signed samples; literal gain/underflow/cap
anchors; guarded exact spans, readonly pages, full-width sizes and all ten span
alias pairs. ABI checks cover success and refusal with DF initially set. Alias
mutation fixtures keep oversized mapped owners even when fences are removed.
Fail-first and assertion-caught semantic mutation evidence are in the handoff.
This source helper supplies no runtime, device, audio or full-RC result.
