# Native CELT band-energy reconstruction

`src/media/opus_celt_energy.asm` ports Xiph Opus 1.5.2 fixed-point
`unquant_coarse_energy`, `unquant_fine_energy`, `unquant_energy_finalise` and
`ec_laplace_decode`. It uses the accepted native range state and the new split
interval decode/update routines. This is an unwired decoding stage, alongside
the packet and entropy modules. No PCM or hardware acceptance is claimed.

Supported mode: standard 48 kHz CELT, 21 bands, one or two channels, LM0..3
(2.5/5/10/20 ms), either coarse prediction mode. Custom modes and more channels
are outside the ABI. Exact 336-byte upstream probability tables and Q15
prediction coefficients are retained. No approximate probability model is used.

## ABI and publication

`media_opus_celt_energy(RDI=range64*, RSI=history*, RDX=config64*)` returns
0 or full-width -1. History is signed int16 log2 energy Q10, channel-major,
21 entries per channel (42 or84 bytes). The caller initializes and preserves
history across frames and decodes the intra flag before calling coarse.
Only selected bands change; other history entries remain intact.

Config is 64 bytes, eight u64 fields:

| Offset | Field | Constraint |
| --- | --- | --- |
| 0 | fine_quant pointer | int32[21], each 0..8 for fine/final; zero for coarse |
| 8 | fine_priority pointer | int32[21], each 0..1 for final; zero otherwise |
| 16 | stage | 0 coarse, 1 fine, 2 final |
| 24 | start band | 0..end |
| 32 | exclusive end band | start..21 |
| 40 | channels | 1..2 |
| 48 | option | coarse LM0..3; fine zero; final bits_left0..10200 |
| 56 | intra | coarse 0..1; fine/final zero |

Every scalar is checked at full64 width. The caller truthfully supplies stable
mapped spans, serialized for the entire call. All pointers are lower canonical;
range/config align8, history align2, int32 tables align4. Mutable range/history
must be disjoint from each other, the frame, config and tables. Read-only spans
may alias each other. All21 table entries are validated, including entries
outside the selected bands. No allocation, writable global or device is used.

The stage validates the original range state, requires sticky error0 and
initial `tell<=storage*8`, and copies state plus history into bounded stack
storage. Coarse uses the upstream remaining-budget branches (Laplace at15+
bits, the exact three-symbol ICDF at2+, logp1 at1+, otherwise delta -1).
Fine reads the allocated raw bits. Final visits priorities0 then1, skips
fine_quant8 and consumes a channel group only while bits_left>=channels.
Final tell must also be within the physical storage budget. Any failed check
leaves original state, history, config, tables and frame unchanged. Publication
is transactional on refusal; concurrent readers/writers are outside this
serialized ABI. SysV nonvolatile GPRs/RSP and FP state are preserved; DF is0.

Arithmetic uses exact upstream Q formats: histories and deltas Q10, prediction
and beta Q15, predictor/previous accumulators Q17. PSHR rounding adds half a
unit before arithmetic shift. Intermediate mathematical sums must fit int32,
and published history must fit int16. Extreme malformed deltas refuse instead
of depending on signed overflow or narrowing wrap. This is a deliberate
admission bound around the upstream fixed-point functions.

`media_opus_laplace(RDI=range64*, RSI=fs0, RDX=decay)` supplies the standalone
primitive. fs0 is Q15 in1..32736; decay is Q14 in0..16384. Return is a
**zero-extended signed32 delta**, or full64 -1 on refusal: a valid delta -1
returns `0x00000000ffffffff`. The primitive retains the range layer's implicit
zero padding and sticky-error behavior, with caller-owned bit budgeting.
The energy wrapper distinguishes refusal before sign-extending the delta.

## Provenance and controls

Official archive: `opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.

| Source | SHA256 |
| --- | --- |
| celt/quant_bands.c | 17c2db926b90cc5984a5885a9c4bcd491b85320ddaffb2880094b4470888ad57 |
| celt/laplace.c | 6a33bdc5bf3a3350f51f92aafa281e4163fdffc88c9e7b0718f6eb770dc595e7 |

Upstream licenses are retained in the assembly and
[energy notice](../LICENSES/XIPH_OPUS_CELT_ENERGY.txt), with an entry in
[third-party notices](../THIRD_PARTY_NOTICES.md).

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 python3 -B -m unittest gauntlet_v2.tests.test_opus_celt_energy_host gauntlet_v2.tests.test_opus_packet_host -v
```

The test pins every official C/header file, includes unmodified quant_bands.c
and compiles the fixed-point functions with the unmodified entropy/Laplace
sources. Linker section collection removes unused codec functions. Upstream
coarse/fine/final encoders produce nontrivial independent streams; the native
and reference decoders compare history and every relevant entropy state field,
rounded tell and fractional tell after each stage. Both predictions, every LM,
channel count and selected band boundaries are covered. Split interval tests
compare general totals and independent interval encodings; Laplace tests cover
signs, tails, parameter boundaries and zero padding. Budget0/1/2/14/15/16 edges,
raw-bit overruns, overflow, aliases, full-width arguments, guarded exact spans
and SysV/DF/FP controls check admission and unchanged refusals. Accepted range
and packet parent controls remain in the run.

Implicit padding means a truncated byte sequence is not automatically invalid;
this stage enforces its own bit budget and arithmetic bounds, not complete
Opus frame validity. The next missing CELT stage is band allocation and PVQ
spectral decoding (followed by transforms, overlap and synthesis). SILK,
packet-to-PCM orchestration, Ogg, playback wiring and hardware proof remain
separate work. Later codec work must enforce its complete frame contract.
