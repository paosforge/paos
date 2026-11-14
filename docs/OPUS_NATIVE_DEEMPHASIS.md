# Native CELT deemphasis and PCM output

`src/media/opus_deemphasis.asm` ports Opus 1.5.2's standard fixed-point
`celt_decoder.c:deemphasis` and its stereo fast path. It converts planar i32
CELT synthesis samples to interleaved signed i16 PCM while maintaining per-channel
feedback. Decimation and saturating accumulation match the upstream function.
The helper is independent and unwired; the synthesis transform and full packet
or PCM decoder remain separate work.

Call `media_opus_deemphasis(RDI=config80*)`, returning RAX=0 or -1. All ten
configuration fields are full-width unsigned 64-bit values:

| Offset | Field | Contract |
|---:|---|---|
| 0 | N | Input samples per channel, 1..960 |
| 8 | C | Channels, 1 or 2 |
| 16 | downsample | 1, 2, 3, 4 or 6, dividing N |
| 24 | accum | 0 replaces PCM; 1 saturating accumulation |
| 32 | input | Readonly planar i32[C][N] synthesis samples |
| 40 | input_bytes | At least 4*N*C |
| 48 | output | Writable interleaved i16[C*N/downsample] PCM |
| 56 | output_bytes | At least 2*N*C/downsample |
| 64 | memory | Writable persistent i32[C] feedback |
| 72 | memory_bytes | At least 4*C |

Input samples must satisfy abs(x)<=2^27 and initial feedback abs(m)<=2^30.
The actual standard-mode coefficient is 27853, read from upstream static mode
by the oracle. The recurrence `tmp=x+m; m=(27853*tmp)>>15` uses arithmetic floor
without rounding. These magnitude limits keep the largest absolute tmp at
9*2^27 and feedback at most 1,026,772,992, within the admitted feedback bound.
Every integer operation, including adding the PCM rounding bias, stays defined.
Admission scans every sample and channel before any public write.

For selected samples, PCM is `(tmp+2048)>>12`, saturated to -32768..32767.
Accumulation then adds the original i16 output and saturates again. Decimation
selects j=0,downsample,2*downsample,... while advancing feedback through every
input sample. All channels retain independent feedback. Splitting a stream into
chunks divisible by downsample preserves the same output and final feedback.
This implements upstream decimation, which does not supply a separate antialias
resampler.

Configuration aligns to eight bytes, input/feedback to four, and PCM to two.
All four full declared spans must be pairwise disjoint, lower canonical and
without pointer addition carry. Larger truthful capacities are admitted and
all tails remain unchanged. Callers own stable mapped storage and serialize
calls. Mapping and concurrent mutation cannot be established by this primitive;
publication is not concurrently atomic.

A fixed 4008-byte private frame stages all PCM and feedback, plus validation
metadata. Refusal preserves configuration, input, output and feedback, including
when the last sample or last channel fails magnitude admission. Success publishes
only after complete reconstruction. No allocator, caller scratch, mutable
globals, entropy, FP or device access is used. SysV nonvolatile registers and FP
state are preserved; DF clears on every return.

Upstream source is the official archive
`https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
The host oracle includes unchanged whole `celt_decoder.c` and `modes.c`, then
calls actual `deemphasis` with the actual standard-mode coefficients. Ordinary
function-section collection and a linker export map discard unrelated decoder
code; reference sources are never rewritten. All 394 C/header files are verified
against the archive before compilation. No reference C is linked into PaOS.
Full pins and exact-base controls are in SOURCE evidence. Copyright notices,
complete grant and disclaimer are retained in the assembly,
[deemphasis notice](../LICENSES/XIPH_OPUS_DEEMPHASIS.txt) and third-party notices.

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
  python3 gauntlet_v2/tests/test_opus_deemphasis_host.py -v
```

Place the release archive beside the extraction or set
`PAOS_OPUS_REFERENCE_ARCHIVE`. Eight methods cover every N, both channels and
accumulation modes, all admitted decimators, every i16 PCM value, all 4096
rounding residues near clipping/zero, all 65536 low feedback bits with both
signs, extreme feedback/input, stream continuity, full-width fields and declared
span aliases. Sixteen additional upstream comparisons use exact guarded spans
and readonly configuration/input pages. Every native call checks SysV, DF and
FP preservation. An independent integer model checks PCM and feedback against
the actual upstream function. Fail-first and compiled assertion-caught mutations
accompany the source handoff. This helper supplies no runtime or playback proof.
