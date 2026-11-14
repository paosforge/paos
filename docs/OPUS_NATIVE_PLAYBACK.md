# Native Ogg/Opus file playback

`OPUSPLAY <wiring> <path>` binds the accepted native Ogg/CELT/SILK producer to
the maintained HDA owner and its actual `snd_ops` stream. The shipped image now
includes the decoder and consumer. Initialization registers the command only;
it does not discover a device, open a stream or play audio at boot.
The product include binds generated SILK read-only tables into PaOS's single
mapped PE section; standalone ELF controls retain their original sections.

Use the existing owner/MUTATE command dispatcher from a live unlocked owner
session. First explicitly `HDALOOP OPEN <bdf> <epoch>`, collect the real graph,
pins and connections, and `HDALOOP SELECT ...` to reach READY. Then issue
`OPUSPLAY 1 short.opus` for confirmed self-loop wiring, or wiring2 for an
operator-confirmed line-out/line-in patch. The path resolves on the selected VFS
mount. Existing jack presence, analog path, speaker exclusion, DID3 enforcing
receipt, controller ownership and route restrictions remain mandatory. These
commands describe the runtime interface; they do not authorize target actions.

The typed reply reports OK/accepted1 and the current owner epoch when the file
job is queued. Acceptance is not playback success. `HDALOOP STAT <epoch>`
reports the same real owner and eventual COMPLETE/FAILED/UNCERTAIN state.
`HDALOOP CANCEL <epoch>` uses its existing cooperative cleanup; RELEASE requires
verified retirement. `fixture_id=0` identifies file PCM, so operators must not
grade it as the fixed corpus ID1. Phase0 denotes an explicitly opened file
stream awaiting PCM submission. RUN1 refuses while the file callback owns the
job. The first implementation permits one pinned file/controller lifetime per
boot, including failed jobs; no automatic retry or buffer recycling.

The finite playback profile accepts mono or stereo, nonempty, and at most2048 native frames
at44100Hz (about46ms after pre-skip and final-granule trim). VFS paths are1..255
bytes and files27..307200 bytes. Longer files refuse before stream
open. Existing codec restrictions still apply: supported CELT or homogeneous
SILK NB/MB/WB profiles, no hybrid, one-byte DTX, PLC or unsupported mode/channel/
duration/bandwidth switching histories. Primary SILK packets carrying LBRR/FEC
remain supported without decoding recovery audio. This consumer does not change
the original decoder reviews or turn earlier refusals into passes.

The existing named HDA cadence loads at most4096 file bytes per turn. It retains
the selected mount and VFS write generation throughout the complete read, then
owns an immutable copied file snapshot. Later disk writes do not alter that
snapshot. The producer checks those exact source bytes, generation and owner
epoch on every live turn, including after READY. A phase flag alone never grants
a submission. One native frame is decoded per turn on a pinned private96KiB
stack, then at most1024 frames per turn are resampled using the existing integer
48000-to-44100 resampler. Mono applies a fixed arithmetic shift by5 for about-30dB
gain. Stereo converts both channels with one common rational phase into a pinned
4096-byte scratch buffer, then computes `floor((left + right) / 64)` using a signed
32-bit sum. This explicitly downmixes the stereo mean into the existing mono
stream with the same fixed gain; physical stereo separation is not provided by
this finite loopback seam. Conversion and downmix each handle at most1024 frames
per turn. No command amplitude or raw-pointer input exists.

After preparation the same HDA owner opens its actual mono S16 stream once.
Every feed turn uses that already-open handle, requests at most1024 frames and
advances only by the returned whole-frame prefix. Zero and negative acceptance
preserve the cursor under the existing finite deadline; oversized or odd positive
acceptance faults and never replays the uncertain submit. Input and output start
only after the complete finite PCM is queued. Existing sense refresh, native
stereo DMA duplication, drain, capture, stop/readback, graph reset and retirement
then execute through the maintained backend. Captured principal, authority epoch,
key handle, unlock state and owner epoch must remain current. Revocation cancels
through the same owner, retaining all source, state, PCM and DMA custody.

Two cleanup defects exposed by this real consumer are corrected in this slice:
idle PCM halt samples the current owned clock after deferred preparation, and
backend cleanup services the requested output stop before input codec restoration
can consume its deadline. Both retain bounded child operations, actual stop
readbacks and sticky uncertainty. Neither fabricates quiescence or releases DMA.

`gauntlet_v2/tests/test_opus_playback_host.py` composes the actual production
command, consumer, native owner, backend, graph/codec/PCM/input/output code with
inert PCI/MMIO/time/VFS fixtures. Real CELT and SILK Ogg files match independent
opusfile PCM and complete decoder state, then match the actual native DMA bytes
and retire. Controls cover partial/refused/uncertain submit prefixes, source and
generation/epoch changes, mount/VFS changes, live session loss during DMA, finite
bounds, owner gating, malformed commands, second activation and cancellation.
The original codec controls and security boundaries remain applicable. Host
results and unsigned assembly provide no QEMU, hardware or acoustic qualification;
admin and the existing QEMU/target owners retain those journeys.
