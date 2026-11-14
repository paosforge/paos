# Native bounded SILK speech decoder

`src/media/opus_silk.asm` decodes actual compressed speech into persistent,
mono or interleaved stereo S16LE 48000 Hz PCM. The private Ogg producer selects it for the finite
SILK profiles below and retains its original CELT decoder. These source helpers
have no device I/O, playback registration, allocator or scheduling themselves.
The [native file consumer](OPUS_NATIVE_PLAYBACK.md) now calls the producer.
SOURCE validation makes no target, acoustic or complete Opus claim.

## Admitted profile

Normal SILK-only mono or stereo, 10/20/40/60 ms per Opus coded frame:

| Profile | Internal rate | Opus configurations (10/20/40/60 ms) | `(TOC & 252)` (10/20/40/60 ms) | Internal samples per 20 ms | LPC order |
| --- | --- | --- | --- | --- | --- |
| Narrowband | 8000 Hz | 0 / 1 / 2 / 3 | 0 / 8 / 16 / 24 | 160 | 10 |
| Mediumband | 12000 Hz | 4 / 5 / 6 / 7 | 32 / 40 / 48 / 56 | 240 | 10 |
| Wideband | 16000 Hz | 8 / 9 / 10 / 11 | 64 / 72 / 80 / 88 | 320 | 16 |

The TOCs in the table describe mono packets; stereo adds bit 2 (value 4).
The actual native packet parser admits codes 0/1/2/3, CBR/VBR and valid padding.
Packets contain 1..12/6/3/2 coded frames at 10/20/40/60 ms, up to 120 ms total.
Each call selects one full-width frame index through the parsed offset/length;
it initializes a new entropy decoder for that payload and retains predictor,
resampler and stereo history across calls. The selected payload is 2..1275 bytes;
whole packet 3..65536 bytes.
Successful 10/20/40/60 ms calls emit exactly 480/960/1920/2880 samples per channel through the genuine fixed-point
SILK 8-to-48, 12-to-48 or 16-to-48 kHz IIR/FIR resampler, preserving its history and API
delay. Mediumband uses the shared upstream NB/MB order-10 NLSF book,
six-symbol pitch low bits, duration-matched MB/WB pitch contours and
the real 12-to-48 kHz resampler (inverse ratio Q16 32768, input delay 4).
Wideband uses the actual upstream WB NLSF book, pitch distributions,
LPC order and resampler geometry.

The 10 ms path uses two 5 ms subframes and the actual upstream 10 ms NB or
MB/WB pitch-contour iCDF and lag tables. LTP memory remains 20 ms at all rates,
so normal 10 ms frames retain and shift the older predictor history. The
20 ms path keeps four subframes and its original serialized format.

A 40/60 ms Opus coded frame contains two/three internal 20 ms SILK frames.
All VAD flags precede one packet LBRR flag. A single entropy decoder spans the
entire payload; the first internal frame uses independent coding and later
frames use conditional coding. Decoder indices, predictor history, two API
input samples and resampler state advance after every internal frame. All
internal PCM is concatenated privately. Packet termination is checked only
after the last internal frame. Caller-visible PCM and state are published only
on complete success.

Stereo lowers the actual upstream `dec_API.c`, `stereo_decode_pred.c` and
`stereo_MS_to_LR.c`. It reads both channels' packet VAD/LBRR headers, reconstructs
stereo predictors, decodes the conditional mid-only flag, resets a returning
side channel and uses the upstream conditional/no-LTP-scaling coding rules.
Mid/side prediction interpolation and saturated left/right reconstruction run
before separate persistent resamplers and interleaving. There is one range
coder for both channels and every internal frame. The complete normal API consumes
both channels' redundant predictors, indices and pulses before primary audio. Stereo uses a 16-bit
termination allowance for all supported bands/durations.

The implementation consumes real VAD, indices, gains, pulses, signs, NLSF,
LTP and LPC prediction and inverse quantization. Normal no-VAD frames update
and consume upstream comfort-noise state. No silence or cached fixture replaces
these algorithms. Normal PLC bookkeeping runs as upstream requires; the public
path always passes normal decode and never invokes loss concealment.

Normal primary playback accepts packets with LBRR/in-band FEC. Mono consumes the
upstream per-frame redundancy mask, then redundant indices and pulses using their
own conditional chain before primary decoding. Stereo uses the complete upstream
API for this grammar. Redundant audio is not returned or used for loss recovery.
PLC/empty payload, hybrid,
and channel/NB/MB/WB/CELT switching histories refuse. Mono same-band 10↔20 ms
continuations are supported; all other duration switches still refuse. There is no
recovery decoder or mode-switch conversion. The retained CELT helper has its
own finite admission rules. Ogg admits that same bounded mono duration transition.

SILK arithmetic decoding legitimately uses zero extension at packet termination.
The finite path bounds `ec_tell <= payload_bits + 8` for 20 ms NB and
`ec_tell <= payload_bits + 16` for all 10/40/60 ms profiles and 20 ms MB/WB. These are explicit admission bounds,
not limits imposed by upstream SILK. Actual normal encoded 10 ms NB speech
and MB/WB frames exceed the older 8-bit allowance. Each 10/40/60 ms profile exercises
the adjacent 16-bit accepted / 17-bit refused boundary and requires exact
upstream PCM/state for accepted payloads. The path also
refuses the upstream redundancy condition `ec_tell + 17 <= payload_bits`. Range errors refuse before
publication. Opus has no payload checksum: some altered or shortened payloads
remain decodable, and accepted ones must match upstream exactly. This bound
does not promise to detect every truncation. The Ogg layer independently checks
page CRC, lacing, lengths, sequence and granule bounds before decoding.

## Transaction ABI

`media_opus_silk_decode(RDI=request80)` returns 480/960/1920/2880 for 10/20/40/60 ms on success, -1 on refusal.
SysV callee-saved registers survive; DF is zero on return, including an incoming
DF of one. No floating-point or SIMD instructions, x87/MXCSR changes, writable
globals, native libc, libopus dependency or runtime C compiler.

The ten request qwords, compatible with the CELT frame request, are:

| Offset | Meaning |
| --- | --- |
| 0, 8 | Encoded packet pointer, full declared byte count |
| 16, 24 | State pointer, full capacity 9120..65536 |
| 32, 40 | PCM pointer, full capacity 960..262144 (mono 10/20/40/60 ms needs at least 960/1920/3840/5760 bytes; stereo needs twice that) |
| 48, 56 | Channels = 1 or 2, downsample = 1 |
| 64, 72 | Accumulate = 0, coded frame index in 0..parsed frame count-1 (full qword) |

Request and state align to 8, PCM to 2; encoded input may be byte aligned.
All four complete declared spans must be nonnull, lower canonical, mapped,
truthful, stable and pairwise disjoint. Mapping/stability and serialized access
are caller obligations; numeric span checks cannot establish page mappings.
Capacity tails never change. No caller-owned request, encoded, state or PCM
byte changes on any refusal. All state and PCM processing occurs in private
stack storage, followed by the two bounded successful publications. The host
suite exercises a 96 KiB usable guarded stack; integration must provide a
sufficient stack before wiring this helper into a runtime.

Fresh state is exactly 9120 zero bytes. Continuations use the opaque 9120-byte
serialized state, preserving normal decode, predictor, resampler and comfort
noise history. State is relocatable: no process address survives serialization.

| State offset | Content |
| --- | --- |
| 0 | 20 ms magic: `0x314b4c53` NB, `0x334b4c53` MB, `0x324b4c53` WB; 10/40/60 ms adds `0x03000000`/`0x06000000`/`0x09000000` |
| 8 | Successful coded frame count (one increment after all its internal frames succeed), 1..0xfffffffe on continuation input |
| 16 | Final 32-bit range state in a qword |
| 24 | FNV-1a over all 9120 bytes except 24..31 |
| 32..4327 | Fixed-point decoder state, pointer members cleared |
| 4328..4331 | Two API input-history samples |
| 4332..9119 | Zero padding/reserved |

The table above remains the mono format. Stereo adds `0x10000000` to the
matching mono magic. Its bytes 32..4327 and 4328..8623 hold the two complete
4296-byte decoder states; 8624..8635 hold upstream predictor, mid and side
history; 8636/8640/8644 hold API channels=2, internal channels=2 and previous
mid-only flag (0 or 1). Bytes 8648..9119 are zero reserved tail. Both decoder
states have pointers removed. Both channels' geometry, resamplers and history
are validated before use. A never-coded side may retain exactly upstream's
initial CNG/PLC geometry and `first_frame_after_reset=1` while its packet and
resampler state advance; that exception requires the mid-only flag and initial
gain/lag/index values. Relocation preserves both channels' complete history.
Mono/stereo state cannot be interchanged, including after relabeling/rechecksum.

FNV is a corruption detector, not authentication. State is an opaque product
of this decoder; callers must preserve it. Before using continuation state the
helper verifies previous supported profile magic, counter/range width, checksum,
geometry, pointer absence, gain/lag bounds, normal loss history and resampler
parameters. Immutable codebook pointers are rebound to invocation-local/native
tables and removed before publication. Checks cover full state bytes including
reserved tail. Reserved bytes must be zero even after recomputing the checksum.
Prior 20 ms NB/MB/WB states remain byte compatible. On a mono same-band
10↔20 ms transition, validate the old geometry first, then set `nb_subfr` and
call upstream `silk_decoder_set_fs` on private staged state, preserving predictor,
CNG/PLC, mid-sample and resampler histories. Relabeled/rehashed
cross-duration or cross-bandwidth state refuses on geometry before DSP. Both
decoder and PLC subframe geometry are checked against the internal frame duration;
`nFramesDecoded` and `nFramesPerPacket` must equal 1/1/2/3 for 10/20/40/60 ms. Adversarially manufactured arbitrary
internal DSP state is not a supported input format.

## Ogg producer selection and custody

Demux header qword 104 is codec kind: CELT = 0; 20 ms NB/WB/MB = 1/2/3;
10 ms NB/WB/MB = 4/5/6; 40 ms = 7/8/9; 60 ms = 10/11/12;
stereo adds 12 to the corresponding mono kind (13..24);
mixed mono 10/20 ms NB/WB/MB uses 25/26/27;
112 and 120 remain zero. SILK requires original OpusHead channels = coded channels.
Each packet may contain multiple coded frames, with the parser enforcing the
120 ms total duration limit. Whole-file supported history selection happens before any
frame decode. The existing source snapshot, full context/generation/epoch
comparison, exact byte comparison, capacities, quotas, cancellation, trimming,
Head gain, late-refusal purity and current READY receipt remain in force.

Begin uses all-zero private SILK state. Each step calls the actual native SILK
decoder once per coded frame, consuming all its internal frames. Intermediate PCM and state remain private; final success alone
publishes trimmed/gained PCM and the 9120-byte persistent state. Capacity tails
remain unchanged even with the producer's larger maximum state capacity.
A late malformed/refused coded frame cannot publish an earlier decoded prefix,
including earlier frames in the same packet. After a
negative step, cancel or discard as required by the retained producer contract.
See [Ogg ABI](OPUS_NATIVE_OGG.md) for context, enlarged private workspace and error codes.

## Primary source and reproducible native lowering

Official [Opus 1.5.2 archive](https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz)
SHA256 `65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
`tools/generate_opus_silk.py` verifies all 394 upstream C/header files against
that archive, compiles 47 actual fixed-point SILK source units plus the scoped
`tools/opus_silk/profile.c` glue to integer-only PIC assembly, then translates
GCC Intel assembly directives/operands to readable native NASM. Product builds
consume this checked-in assembly directly. There is no opaque machine-code blob.

The exact lowering used GCC 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), no red zone,
fixed point, `-fwrapv`, general registers only, no builtins/stack protector/jump
tables, PIC and hidden symbols; the script records all flags and consumed-source
and header hashes. Mechanical specializations remove unused encoder functions
and absolute pointer tables, replace LTP pointer selection with native addresses,
and bind the matching NB/MB or WB NLSF book on the stack. Numerical decode/resampler
code is upstream. Entropy bridges call the retained native range decoder for every
iCDF/bit operation. Memory calls use canonical repository `memcpy`/`memset`;
local overlap copying restores DF. All tables are immutable, with only PC-relative
relocations. Full consumed-source/header copyright grants and disclaimers are
retained in [the license](../LICENSES/XIPH_OPUS_SILK.txt).

```
python3 tools/generate_opus_silk.py /path/to/opus-1.5.2 --manifest /tmp/upstream.json
```

## Independent host verification

Use the upstream/reference setup in [Ogg reproduction](OPUS_NATIVE_OGG.md), then:

```
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
PAOS_OGG_REFERENCE_ROOT=/path/to/ogg-reference \
python3 -B gauntlet_v2/tests/test_opus_silk_host.py -v

PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
PAOS_OGG_REFERENCE_ROOT=/path/to/ogg-reference \
python3 -B gauntlet_v2/tests/test_opus_silk_wideband_host.py -v

PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
PAOS_OGG_REFERENCE_ROOT=/path/to/ogg-reference \
python3 -B gauntlet_v2/tests/test_opus_silk_mediumband_host.py -v

PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
PAOS_OGG_REFERENCE_ROOT=/path/to/ogg-reference \
python3 -B gauntlet_v2/tests/test_opus_silk_10ms_host.py -v

PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
PAOS_OGG_REFERENCE_ROOT=/path/to/ogg-reference \
python3 -B gauntlet_v2/tests/test_opus_silk_long_host.py -v

PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
PAOS_OGG_REFERENCE_ROOT=/path/to/ogg-reference \
python3 -B gauntlet_v2/tests/test_opus_silk_stereo_host.py -v

PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
PAOS_OGG_REFERENCE_ROOT=/path/to/ogg-reference \
python3 -B gauntlet_v2/tests/test_opus_silk_multiframe_host.py -v
```

The unchanged complete upstream `silk_Decode` supplies every persistent state
byte and whole-packet PCM, called two/three times on the same range decoder for
40/60 ms. Complete fixed-point `opus_decode` independently
checks that PCM, and complete opusfile checks whole-file PCM, pre-skip, EOS
trimming and Head gain. Libogg supplies actual encoded containers. The reference
adapter only translates the state format; it does not reuse the lowered native
DSP or entropy bridge. Original upstream C/header bytes are archive-verified.
Reference-library objects are external, test-only inputs, never native runtime
link dependencies.

The retained 20 ms NB corpus includes four bitrates, and MB/WB five
(8000..32000 bit/s). The 10 ms corpus covers five bitrates per bandwidth,
asserts actual encoder TOCs, tests all 30 ordered pairs of incompatible
profile histories (including rehashed magic), and compares short Ogg files
with pre-skip and tail trim at 480-sample boundaries. FEC tests also assert
actual bandwidth; the WB primary-playback corpus uses 48000 bit/s. Any one-byte
DTX payload retains its existing pure refusal, with both test histories reset
before checking the next primary run. All cover
real encoded recorded speech, silence, voiced/unvoiced noise, impulses and
transitions. The six 40/60 ms profiles cover five bitrates each, assert actual
encoder TOCs, exercise all 132 ordered pairs of the 12 duration/bandwidth
histories, pre-skip/trim within and across internal frames, and packet-level
refusal after all internal frames decoded without exposing earlier PCM.
The maintained `test_opus_silk_duration_host.py` additionally covers repeated
mono same-band 10↔20 ms transitions in all three bands against complete upstream
PCM and serialized state, real mixed-duration Ogg files against opusfile, old
geometry validation despite rehashed magic, and current source/generation/epoch,
cancellation and late refusal without prefix publication. The former all-switch
refusal controls now admit only these six ordered same-band transitions.
Other coverage includes state relocation, all bytes of
PCM/state, malformed/truncated/mutated payloads, actual encoder FEC, unsupported
profiles, all span pairs/capacity tails, corrupted and rehashed state controls,
adjacent accepted/refused entropy boundaries, guard pages, ABI, stale
generation/epoch/source, cancellation and late failure.
Default recorded input is the externally installed alsa-utils Front_Center.wav,
converted by ffmpeg to S16LE48k mono. No recorded sample is distributed here;
`PAOS_SILK_SPEECH_WAV` can select another actual S16LE48k mono WAV corpus.

Task evidence records exact assigned-base packet/range admission, behavioral
refusal by the composed prior frame/Ogg producer, successful new whole PCM/state,
assertion-killed production-assembly mutations, byte-exact regeneration, flat
NASM composition, no new absolute-pointer findings and retained CELT, WAV, FLAC,
PCM and original HDA host suites. Original dependency reviews and physical,
runtime, audio and guest owners remain separate.

Stereo verification uses actual forced-stereo upstream encoder packets with
different left/right sine, noise, impulse and anti-phase inputs, alternating
mid-only and side activity, and recorded speech with a delayed/scaled second
channel. It compares all interleaved PCM and all serialized state bytes against
complete upstream SILK and libopus, and complete file PCM against opusfile.
All 24 mono/stereo bandwidth/duration profiles participate in 552 ordered
incompatible-history controls, including relabeled/rehashed states. Stereo
capacity tests include a full 60 ms packet, the exact 9120-byte state minimum,
prior workspace refusal, span pairs, both LBRR headers, late entropy refusal,
source/identity custody, READY transfer and cancellation. These are host SOURCE
checks; device playback and physical acceptance retain their existing owners.
The multiple-coded-frame corpus repacketizes real encoded mono/stereo speech
for all 24 profiles with the unchanged official repacketizer. It checks every
selected PCM/state byte against the complete upstream SILK API, compares each
whole packet against one full libopus call, and each whole Ogg file against
opusfile. Coverage includes CBR/VBR codes 0/1/2/3, the 120 ms limits, padding,
full-width invalid indices, selected-frame capacities, relocated history,
guarded input/stack, cancellation/stale inputs, gain and trimming across coded
frames, and final-frame entropy refusal with no partial publication.

`test_opus_silk_lbrr_host.py` additionally checks real encoder redundancy in every
supported profile, exact primary PCM and all serialized state bytes against the
unchanged upstream API and libopus, and indexed padded Ogg streams against
opusfile. Intermediate PCM/state stay private, with gain and trim applied only
at successful completion. Loss concealment and recovery remain outside this API.
