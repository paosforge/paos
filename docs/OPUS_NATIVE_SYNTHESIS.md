# Native CELT frame synthesis

`src/media/opus_synthesis.asm` composes the accepted native denormalisation,
inverse MDCT, pitch postfilter and deemphasis helpers. It ports standard 48 kHz
fixed-point Opus 1.5.2 `celt_synthesis` and the normal decoded-frame history,
filter transition and PCM path in `celt_decoder.c`. It accepts already decoded
spectra and final energies. Packet parsing, entropy and energy decoding,
anti-collapse, PLC/prefilter-and-fold, SILK, runtime playback and device
qualification remain outside this unwired helper.

Call `media_opus_synthesis(RDI=config160*)`, returning RAX=0 on complete success
or -1 on refusal. The 20 fields are full-width unsigned64 except the explicitly
sign-extended gain. All offsets and lengths are bytes.

| Offset | Field | Admission |
|---:|---|---|
| 0 | LM | 0..3, N=120<<LM |
| 8 | start | 0..21 |
| 16 | effective end | start..21, empty allowed |
| 24 | coded channels C | 1 or 2 |
| 32 | output channels CC | 1 or 2, fixed by persistent state |
| 40 | transient | 0 or 1 |
| 48 | downsample | 1,2,3,4,6 |
| 56 | silence | 0 or 1 |
| 64 | accumulate PCM | 0 or 1 |
| 72 | newly decoded pitch period | 0..1024 |
| 80 | newly decoded gain | sign-extended signed16 |
| 88 | newly decoded tapset | 0..2 |
| 96 | spectra | readonly planar signed16 Q14[C][N] |
| 104 | spectra capacity | >=2*C*N |
| 112 | final log energies | readonly planar signed16 Q10[C][21] |
| 120 | energy capacity | >=42*C |
| 128 | persistent state | mutable layout below, aligned8 |
| 136 | state capacity | >=64+8672*CC |
| 144 | PCM | mutable interleaved signed16[CC*N/downsample] |
| 152 | PCM capacity | >=2*CC*N/downsample |

The 64-byte persistent header is followed immediately by exactly CC planar
arrays of 2168 signed32 samples (2048 decode history +120 overlap capacity).

| Offset | Field | Admission |
|---:|---|---|
| 0 | output channels | unsigned64, must equal CC |
| 8 | current period | unsigned64 0..1024 |
| 16 | old period | unsigned64 0..1024 |
| 24 | current gain | sign-extended signed16 in64 bits |
| 32 | old gain | sign-extended signed16 in64 bits |
| 40 | current tapset | unsigned64 0..2 |
| 48 | old tapset | unsigned64 0..2 |
| 56 | feedback channel0 | signed32 |
| 60 | feedback channel1 | signed32; retained untouched for CC1 |
| 64 | decode memory | signed32[CC][2168] |

Initialize all state bytes to zero and set its first qword to CC. Output
channels stay fixed; coded channels, LM, transient flag and decimation may vary
between calls. Callers own compatibility of decoded parameters with their
stream. The bounded filter ABI admits the underlying primitives' signed gain
and period domain, including a wider set than the normal packet decoder emits.
This does not declare those combinations valid Opus packets.

The config is aligned8, spectra/energies/PCM aligned2 and state aligned8. All
five **full declared** spans, including unused capacity tails, must be nonnull,
truthful, stable, mapped, lower canonical, nonwrapping and pairwise disjoint.
Scalar and span admission uses all64 bits. Adjacent spans are admitted. The
caller serializes access; the helper cannot validate mappings or concurrent
changes. Config and inputs stay unchanged; state and PCM capacity tails stay
unchanged. Success returns0, not a sample count; N/downsample is known from LM.

The whole state and PCM result are private until every real helper succeeds.
Postfilter admission bounds every sample in its minimal
`max(15,T0,T1)+2` history plus current segment to +/-300000000. Raw inverse
MDCT accepts full signed32 overlap and wraps exactly as its documented ABI;
synthesis clips only the current N samples to +/-300000000, leaving the next
60 raw overlap samples intact. Deemphasis then requires each postfiltered
current sample within +/-2^27 and each active initial feedback within +/-2^30.
A late failure of either bound refuses the entire frame, preserving every
caller byte, even after prior channels or filter stages succeeded. The admitted recurrence keeps active feedback within its initial bound. These
limits are inherited from the composed primitives rather than an assertion of
full-domain packet decoding.

Each channel's history shifts forward by N with the exact upstream
`2168-N` move. Synthesis starts at decode-memory offset `2048-N`. Mono duplication
uses one denormalised spectrum and each output's independent overlap; stereo
downmix arithmetically halves **each** denormalised signed32 coefficient before
adding. Normal synthesis uses shift3-LM, stride1, one transform of N samples.
Transient synthesis uses B=1<<LM, B transforms of120 samples, shift3, stride B,
and successive output offsets120. The native MDCT preserves its input, allowing
the same read-only spectrum to serve both mono duplication channels; upstream's
destructive temporary-output copy is unnecessary and produces the same final
2168-sample memory.

Periods retained in state are clamped to15 before the first120-sample filter
transition from old to current controls. If LM>0, a second transition applies
from current to newly decoded controls across the remaining N-120 samples.
LM0 delays those new controls until the next frame. State updates reproduce
upstream's distinct LM0 versus LM>0 old/current assignments. Deemphasis receives
contiguous planar postfiltered samples and persistent independent channel
feedback, decimates after advancing feedback at every sample, and optionally
saturating-accumulates interleaved PCM. No additional gain, rounding, saturation
or resampling is inserted.

There is no allocator, mutable global, floating point, entropy, runtime or
device access. SysV nonvolatile registers and FP control state are preserved;
DF clears on success and refusal. The consumer's private frame is41208 bytes
plus48 saved register bytes; the deepest nested helper needs less than51 KiB
in total. The caller must supply that stack, independently of its own frames.
Guard tests use64 KiB with an untouched bottom8 KiB.

The official archive is `https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`,
SHA256 `65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
Copyright, grant and disclaimer are retained in the assembly and
[license](../LICENSES/XIPH_OPUS_SYNTHESIS.txt); distributions also retain the four
underlying helpers' licenses. Host tests verify all394 C/header members against
the unchanged archive and compile whole decoder, band, MDCT, FFT, filter, mode
and energy sources with fixed-point scalar settings and `-fwrapv`. The oracle
calls unchanged `celt_synthesis`, `comb_filter` and `deemphasis`; its small bridge
copies the normal decoder's move/control sequence and the native helpers'
admission limits. Reference C is never linked into PaOS.

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
  python3 gauntlet_v2/tests/test_opus_synthesis_host.py -v
```

Tests compare every PCM and persistent-state byte through sequential frame
size/channel/filter transitions, all LM/channel/transient/decimation controls,
all253 effective band slices including empty slices, signed spectra/energy
extremes, raw overlap, clipping, downmix rounding, full-width refusal and
capacity tails. Constructed past history cancels enough of clipped signals to
admit deemphasis and expose exact +/-300000000 clipping in successful state
commits, including alternating signed neighbors. Both-end exact guarded spans,
readonly inputs/config and a
guarded private stack cover accepted and late-refused frames. Fail-first and
compiled semantic mutants are recorded in the SOURCE evidence. This backend
supplies no full packet, audible output, QEMU, metal or release acceptance.
