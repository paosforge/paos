# Native CELT time-frequency resolution flags

`src/media/opus_tf.asm` ports the exact `tf_decode` control flow from official
Opus1.5.2 `celt/celt_decoder.c` and the signed `tf_select_table` from `celt/celt.c`.
It composes the native range helper, with bounded caller spans and transactional
state/output. It is unwired and adds no allocation, FP, mutable globals,
devices or runtime flow. The output consists of resolution flags for later
band processing; it does not transform band samples.

## API

`media_opus_tf_decode(RDI=range64*,RSI=readonly config64*)` returns RAX=0 or -1.
Config is eight full-width unsigned qwords:

| Offset | Field |
| --- | --- |
| 0 | Start band, 0..20 |
| 8 | Exclusive end band, start+1..21 |
| 16 | Transient flag, 0/1 |
| 24 | LM, 0..3 |
| 32 | Cumulative eighth-bit budget cap |
| 40 | Mutable i32 output[end-start] pointer |
| 48 | Exact output byte count, 4*(end-start) |
| 56 | Reserved, must be zero |

Output is packed starting at element zero; element j describes band start+j.
The finite function domain covers all 231 nonempty slices of the standard
21-band array and eight LM/transient combinations. This includes function
arguments that a full frame parser may constrain further (e.g. LM0/transient1).
It is not an assertion that every function argument combination is an actual
CELT frame mode. Values lie in -3..3, with positive values indicating better
frequency resolution and negative values better time resolution.

Config/state are 8-byte aligned, output 4-byte aligned. All nonempty spans
must be truthful, stable, mapped lower-canonical 47-bit memory. The helper
checks null/alignment, carry, final-byte canonicality, full-width scalar fields,
exact sizes and aliases. State and output are mutually disjoint and disjoint
from readonly config and the nonempty frame. Readonly config/frame may overlap.
The range helper retains its 0..1275-byte physical frame and state invariants.
Caller serialization and writable ownership of mutable spans are required;
the helper cannot verify arbitrary pointers' mapping/ownership.

There is no caller scratch. A 64-byte copied entropy state and at most 84 bytes
of staged flags live on the bounded local stack. This module's own stack,
including saved registers and return address, is 448 bytes; the range callee
has its own bounded frame. SysV nonvolatiles are preserved, DF clears on every
return, and x87/MXCSR state is untouched.

## Upstream gates and transactions

The upstream physical budget is frame bytes*8, using rounded whole-bit
`ec_tell`. The initial logp is transient?2:4, later logp transient?4:5.
If LM>0 and tell+initial_logp+1<=physical_budget, one bit is reserved for the
selection decision and removed from the per-band budget. Each admitted symbol
XORs the current flag; a skipped symbol retains it. `tf_changed` ORs all current
flags when a symbol is decoded. The selection bit is read only if reserved and
the table alternatives differ for tf_changed. The final table index is
8*LM+4*transient+2*selection+per_band_flag; signed extraction is required.

The caller's eighth-bit cap admits or refuses the complete operation. It does
not replace the upstream whole-bit budget or alter symbol selection. Initial
and final `ec_tell_frac` must fit the cap, which cannot exceed frame bytes*64.
Sticky errors, invalid/stale state and physical whole-bit overrun refuse.
A zero-byte frame cannot admit the initial one-bit entropy accounting and
therefore refuses even though range initialization itself supports zero bytes.

All checks and decoding operate before publication; every refusal preserves
original state, output, config and frame. Success publishes flags and state.
Publication is serialized, not concurrently atomic. Xiph zero padding is
retained; these checks do not establish whole-frame validity or detect every
truncated input.

## Reference and validation

The external official release archive is
`https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
Exact consumed source hashes are pinned in the SOURCE handoff and checked
against all 394 official C/header pins inherited by the host harness.
Full copyright and BSD grant/disclaimer are retained in the assembly and
`LICENSES/XIPH_OPUS_TF.txt`; include the notice in binary distributions.

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 python3 -B -m unittest \
  gauntlet_v2.tests.test_opus_tf_host \
  gauntlet_v2.tests.test_opus_packet_host -v
```

Six new methods execute assembled production code against unmodified upstream
`tf_decode` and `tf_encode`, included separately from the official C files.
Their unrelated functions are discarded by ordinary section garbage collection;
no reference source is rewritten. Actual entropy encoders produce independent
streams with random flags, selection decisions and interleaved tail bits.
Tests cover all band slices/modes, literal table anchors, every repeated-byte
value in one- and two-byte frames, whole-bit reservation thresholds, fractional
cap equality, truncated prefixes, stale/full-width/alias negatives, both-end
guard pages, ABI/DF/FP, and transactional output. Seventeen CWRS/range controls
and six packet controls remain. The SOURCE evidence also records fail-first
controls and assertion-caught semantic mutants.

Band allocation, PVQ band orchestration, actual time-frequency sample transforms,
MDCT/overlap, SILK and complete PCM synthesis remain separate. This is source
qualification only; candidate/build/QEMU/metal/audio ownership is unchanged.
