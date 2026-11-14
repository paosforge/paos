# Native bounded Ogg Opus file ingress

`src/media/ogg_opus.asm` and `src/media/opus_producer.asm` are private native
helpers, now called by [native file playback](OPUS_NATIVE_PLAYBACK.md). They compose the actual packet parser, normal CELT frame
decoder and bounded mono/stereo NB/MB/WB SILK decoder into finite-file S16LE 48 kHz
PCM. See [SILK scope and ABI](OPUS_NATIVE_SILK.md). They perform no device I/O,
allocation, scheduling, playback or runtime registration. Existing frame and
synthesis bounds still apply: valid CELT packets can refuse transactionally.
This provides SOURCE coverage, with no QEMU, metal, acoustic or full Opus claim.

Primary sources consumed: [Ogg RFC 3533](https://www.rfc-editor.org/rfc/rfc3533),
[Ogg Opus RFC 7845](https://www.rfc-editor.org/rfc/rfc7845), official
[Opus 1.5.2](https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz) and
[opusfile 0.12](https://downloads.xiph.org/releases/opus/opusfile-0.12.tar.gz).
Archive SHA256 respectively:
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1` and
`118d8601c12dd6a44f52423e68ca9083cc9f2bfe72da7a8c1acb22a80ae3550b`.
The Ogg producer output-gain polynomial and rounding port upstream code;
its original BSD notices remain in the assembly and `LICENSES/XIPH_OPUS_OGG.txt`.
Existing CELT helper attributions remain applicable.

## Supported file profile

A complete single serial stream, sequence starting at zero, exact BOS and final
EOS, CRC-valid Ogg pages, no gaps or resynchronization. Head version exactly 1,
exactly 19 bytes, mapping family 0, one or two original output channels. Future
compatible Head versions are explicitly outside this bounded implementation.
Head alone occupies the first page. Tags may span pages; their terminating
packet finishes its page. Vendor and every comment length are bounded; trailing
Tags padding is permitted. No interpretation of tag gain or other metadata.

Packets retain their exact original bytes. The actual native packet parser
supplies frame count, duration and individual frame lengths. Every audio frame
must carry at least two bytes of payload. SILK admits mono/stereo narrowband, mediumband or wideband
10/20/40/60 ms per coded frame, multiple coded frames up to 120 ms per packet,
original Head matching coded channels, normal decode without
FEC. All packets must retain codec mode, bandwidth and channels. Mono SILK same-band
10↔20 ms histories are admitted (mixed NB/WB/MB kinds 25/26/27); all other
duration changes, NB/MB/WB and channel history switches refuse. A 40/60 ms coded frame
contains two/three internal 20 ms SILK frames sharing one entropy payload. Hybrid, PLC/empty
frames, unsupported SILK profiles, chained/multiplexed streams and other
mappings refuse; no substitute PCM.
For CELT, original Head output channels remain fixed across coded-channel changes.
Input sample rate remains metadata; actual output is always 48000 Hz.

Pages completing no packet have granule -1; header-completing pages have zero.
The initial audio granule establishes an optional nonnegative timeline offset;
subsequent non-EOS audio granules equal that offset plus cumulative decoded
samples. EOS may trim the last completed page, cannot move behind the preceding
granule, and cannot exceed decoded duration. A first audio page also being EOS
can have a shorter granule than its decoded duration (offset zero). An empty
EOS page can repeat the previous audio granule. Granule arithmetic is checked.
Output keeps exactly `[pre_skip, final_granule-initial_offset)`. All frames,
including discarded prefix and suffix, advance decoder state. Zero-frame PCM
output is legal when the interval is empty. Signed Q7.8 dB Head gain follows the
fixed-point Opus gain rounding and saturation exactly, independent of state.

Bounds: file 27..307200 bytes; 1024 pages; 512 audio packets; 65536 bytes per
logical packet (including each header); 131072 decoded samples per channel.
The producer additionally bounds final PCM to 192000 bytes. Full declared
workspace/result/state capacities are checked, even where the used prefix is
smaller. Quotas are checked before the corresponding write or native decode.

## Demux ABI

`media_ogg_opus_parse(RDI=config64)` returns 0 success, -1 malformed/span,
-2 unsupported, -3 capacity, -4 work quota. The eight qwords are source pointer,
source bytes, result pointer, result capacity, scratch pointer, scratch capacity,
zero, zero. Result capacity >=16512; scratch >=323712; each <=1048576 bytes.
Config/result/scratch align to 8; source may be byte aligned. All four full
spans must be nonnull, truthful, stable, disjoint and lower canonical.

Result has 128 header bytes then 512 rows of 32 bytes. Header qwords in order:
magic `0x314f4747`, original channels, pre-skip, original input rate, signed
gain, serial, page count, audio packet count, total decoded samples/channel,
initial offset, final granule, output frames, packed bytes, codec kind
(0 CELT; 20 ms NB/WB/MB SILK = 1/2/3; 10 ms NB/WB/MB = 4/5/6; 40 ms = 7/8/9; 60 ms = 10/11/12; stereo adds 12 to these SILK kinds), zero, zero.
Each row is scratch-relative packet offset, byte count, sample count/channel,
frame count. Unused rows are zero. Packed logical bytes, including Head and
Tags, follow the first 16512 scratch bytes. Offsets address original audio
packets there. Both source and config are unchanged; result is published only
on complete success. On refusal scratch can be dirty and must be discarded.

## Producer ABI and custody

Each entry takes RDI=context192, RSI=expected nonzero generation, RDX=expected
nonzero epoch. Context fields:

| Offset | Field |
| --- | --- |
| 0,4 | u32 version=1, phase EMPTY0/DECODING1/READY2/CANCELLED3 |
| 8,16 | u64 generation, epoch |
| 24,32 | source pointer, bytes |
| 40,48 | public owned PCM pointer, capacity 2..192000 (align2) |
| 56,64 | private workspace pointer, bytes 869120..1048576 (align8) |
| 72,80 | public owned native frame state pointer, bytes 9120..65536 (align8) |
| 88,96 | output frames, bytes |
| 104,108 | u32 output rate, original channels |
| 112,116 | u32 original input rate, serial |
| 120,128,136,144,152 | u64 pre-skip, initial offset, final granule, decoded samples, integrity |
| 160..191 | four reserved zero qwords |

Initialize phase and all fields from offset88 onward to zero. The context
aligns to8; its full span and all four declared buffers must be disjoint,
stable, mapped and lower canonical. Caller serializes every operation, owns
private workspace exclusively, keeps source immutable, and provides >=96 KiB
private stack for the complete nested real decoder. Public state must fit
9120 bytes for SILK, or `448+8672*original_channels` for CELT; it is a fresh complete stream state, never
an externally supplied initial history.

`media_opus_producer_begin` copies the complete file privately, admits the
whole container, checks exact output capacities, initializes private state and
returns0/DECODING. `step` decodes one real Opus coded frame (all internal SILK frames) and returns0 until all packets
and frames have completed. Every live call revalidates all192 context bytes,
both expected identities and every original encoded byte against the bound
snapshots, including READY and CANCELLED calls. The final successful step
publishes exact PCM and minimal state, then metadata and READY, returning1.
Public capacity tails stay unchanged. Intermediate calls publish no PCM or
state prefix. A repeated READY step returns1 only after current identity checks.

`cancel` during DECODING returns2 and records CANCELLED without publishing.
Cancelled steps return2 after validation. Cancelling READY refuses because
output already belongs to the caller. Return codes: 0 progress, 1 current
READY custody receipt, 2 cancelled; -1 invalid, -2 identity/phase/unsupported,
-3 capacity, -4 quota, -5 native frame refusal. Begin also propagates demux
errors. Every negative preserves context, original source, public PCM and
public state; private workspace may be dirty. After ANY negative, caller must
cancel or discard the transaction; retrying dirty workspace is unsupported.
A retained phase field alone never admits a handoff. Only a current return1
permits transfer into the existing PCM stream custody convention. On stale
READY refusal, previously published bytes remain caller-owned but cannot be
claimed as a new successful result. Zero output cannot start a nonempty PCM
stream and must be handled as an empty completed file by its caller.

Workspace layout: snapshot0..191; identity/control192..255; source256;
demux result307456; demux scratch323968; native state647680; frame PCM665472;
trimmed PCM676992; temporary config868992. Minimum869120. The private
frame PCM buffer holds 11520 bytes for a full 60 ms stereo packet. Earlier
861440/863360-byte workspace allocations refuse before use; callers must allocate
the new minimum. Public PCM and file quotas remain unchanged. No hidden global
state, allocator, floating-point operations or hardware access. SysV
nonvolatiles preserved, DF cleared on every ingress/producer return; x87 and
MXCSR unchanged. The existing PCM stream test uses its standard DF0 ABI.

## Host reproduction

Set `PAOS_OPUS_REFERENCE_ROOT` to the unchanged official Opus1.5.2 source and
`PAOS_OGG_REFERENCE_ROOT` to a directory containing `opusfile-0.12.tar.gz`, its
unchanged extracted tree and an out-of-tree `fixed-build`. Build the complete
Opus library there with its `configure --enable-fixed-point --disable-float-api
--disable-doc --disable-extra-programs --disable-intrinsics --enable-shared`,
then `make -j2`. Supply `config.h` in the evidence directory defining
`OP_DISABLE_HTTP 1` and `HAVE_LRINTF 1`. System libogg development headers and
library, NASM and a C compiler are required. Run:

```
python3 -B gauntlet_v2/tests/test_ogg_opus_host.py
```

The harness verifies upstream C/header bytes against official archives and
builds unchanged complete opusfile with `OP_FIXED_POINT`. Libogg creates pages
and independently recovers exact packets; the complete fixed-point encoder
creates real nonzero and silent CELT packets. Complete opusfile supplies whole
PCM and metadata. A separate complete upstream CELT decoder checks all native
persistent state bytes at each file boundary. All production assembly stages
are real. Tests include all frame sizes, mono/stereo and coded-channel changes,
continued packets, 255 termination, large Tags, multiple packets per page,
gain, timeline offsets, prefix/suffix trimming, malformed containers, quotas,
all span pairs, stale identities, cancellation, actual late decode refusal,
public purity, guard pages and ABI. Evidence includes exact-base fail-first
and assertion-killed semantic mutants. This is bounded source validation;
physical audio and the existing HDA/source-review owners remain unchanged.
