# Native CELT inverse MDCT

`src/media/opus_imdct.asm` ports Opus 1.5.2 `clt_mdct_backward_c` and the
scalar `opus_fft_impl` radix 2/3/4/5 butterflies. It converts standard 48 kHz
CELT spectral coefficients into the raw time-domain overlap buffer. The helper
is independent and unwired. A full decoder still needs band recursion, frame
composition and synthesis clipping before the postfilter and PCM stages.

Call `media_opus_imdct(RDI=config48*)`, returning RAX=0 or -1. Six unsigned
64-bit fields describe one inverse transform:

| Offset | Field | Contract |
|---:|---|---|
| 0 | input | Readonly signed32 coefficients, aligned4 |
| 8 | input_bytes | At least `4*((N-1)*stride+1)` |
| 16 | output | Writable signed32 overlap buffer, aligned4 |
| 24 | output_bytes | At least `4*(N+60)` |
| 32 | shift | 0..3; `N=960>>shift` |
| 40 | stride | 1, 2, 4 or 8, in input samples |

The first 60 output samples contain the previous overlap history on entry.
Success replaces exactly the first N+60 samples; samples N through N+59 become
the overlap history for the next call. The remaining initial output samples
need not be initialized. The input and configuration stay unchanged, including
strided holes and declared capacity tails. Transform size and stride follow
the upstream primitive; admitting a combination does not establish a valid
complete CELT frame. For transient synthesis, call shift3 repeatedly on
interleaved spectra with stride B and successive output offsets of 120 samples.
Each call's full declared input, output and configuration spans must be disjoint.

The configuration is aligned8. All full declared spans must be nonnull, mapped,
stable, lower canonical and pairwise disjoint without overflow. Capacities and
scalar admission use full 64-bit values. Callers supply truthful mapped storage
and serialize calls. Structural checks finish before any output read or write.
All refusal paths leave every caller byte unchanged. Success computes into a
private stack buffer before publishing the output; capacity tails stay intact.
Private stack storage is 4600 bytes plus 48 bytes of saved registers. There are
no nested calls, mutable globals, allocator, entropy, FP, device or runtime use.
SysV nonvolatile registers and FP control state are preserved; DF clears on
both success and refusal. The helper cannot validate mappings or concurrent
changes to caller storage.

The pre-rotation stores swapped real/imaginary components directly in upstream
bit-reversed order. The FFT uses the exact four standard factor sequences and
shared 480-entry complex Q15 twiddle table. Radix4's final unity stage bypasses
multiplication; radix2 uses exact unity, swap/negation and the pinned23170
45-degree constant. The post-rotation de-shuffles pairs from both ends before
120-sample time-domain alias cancellation with the standard window. Immutable
bit-reversal, MDCT twiddle and window values are copied from the pinned mode.

All signed32 input and overlap values are admitted. Each signed16-by-signed32
product is formed in signed64 and arithmetically truncated by15, then reduced
to signed32. Each upstream ADD32_ovflw, SUB32_ovflw and negation wraps separately
at32 bits; radix3's HALF_OF is an arithmetic shift. No FFT scaling, saturation
or rounded multiplication is introduced. The host C oracle uses `-fwrapv` to
make its one ordinary signed unary negation deterministic at INT32_MIN. This
is the raw inverse transform, so later composition must apply the actual
`celt_synthesis` saturation to SIG_SAT=300000000 before pitch postfiltering,
and must independently satisfy every downstream helper's admission bounds.

The official archive is `https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`,
SHA256 `65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
Tests verify it and all 394 C/header members before compiling unchanged whole
`mdct.c`, `kiss_fft.c` and `modes.c`. Export filtering and section collection
remove unrelated routines; reference C is never linked into PaOS. Full source
terms are retained in the assembly, [license](../LICENSES/XIPH_OPUS_IMDCT.txt)
and third-party notices. Source hashes and manifest are in the SOURCE evidence.

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
  python3 gauntlet_v2/tests/test_opus_imdct_host.py -v
```

Place the unchanged archive beside the extracted tree or set
`PAOS_OPUS_REFERENCE_ARCHIVE`. Tests compare every output sample for impulses
at every coefficient of all four sizes, extreme signed32 values, all strides,
random spectra and history, changing-size continuation and eight interleaved
short blocks. They compare all embedded tables, independently crosscheck a
floating complex DFT within a quantization tolerance, and exercise exact
adjacent spans, capacity tails, every alias pair, full-width scalar refusal,
readonly input/config and guarded exact edges. The ABI wrapper starts with DF
set on every call. Fail-first and compiled assertion-caught semantic mutations
are retained in the handoff. This source provides no full decoder, audible
output, device, VM or metal acceptance.
