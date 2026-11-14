# Native CELT allocation decode

`src/media/opus_allocation.asm` ports the decode path of Opus 1.5.2
`clt_compute_allocation` and `interp_bits2pulses` for the standard 48 kHz mode.
It derives the original caps and preserves allocation-vector search, six-step
interpolation, backward band skipping, intensity and dual-stereo decisions,
fine-energy rounding/priority, and carried balance. It is an unwired helper;
complete band decoding, transforms, synthesis, SILK and PCM playback remain open.

`media_opus_celt_allocation_decode(RDI=range64*, RSI=config96*)` returns 0 or -1.
It uses the existing range-state ABI from `OPUS_NATIVE_RANGE.md`. The configuration
contains these twelve unsigned 64-bit fields in order:

| Offset | Field | Admitted value |
|---|---|---|
| 0 | start | 0..20 |
| 8 | end | start+1..21 |
| 16 | channels | 1 or 2 |
| 24 | LM | 0..3 |
| 32 | allocation trim | 0..10 |
| 40 | total allocation | 0..81600 eighth bits |
| 48 | cumulative entropy cap | At most frame bytes times 64 |
| 56 | offsets | Pointer to 21 signed 32-bit values, all 0..81600 |
| 64 | offsets bytes | Exactly 84 |
| 72 | output | Pointer to 288 bytes |
| 80 | output bytes | Exactly 288 |
| 88 | reserved | Zero |

The output starts with four qwords: coded-band end, sign-extended signed balance,
intensity band, and dual-stereo flag. Three arrays of 21 signed 32-bit values
follow: pulse budgets at byte 32, fine-energy counts at 116, and fine priorities
at 200. The trailing four bytes and array positions outside `[start,end)` are
zero. Pulse values are eighth-bit budgets, suitable for subsequent pulse-cache
mapping; they are not decoded pulse counts or samples. Fine-energy counts are
0..8, and priorities are 0 or 1. Intensity may be zero even when start is nonzero.

State, configuration and output must be 8-byte aligned; offsets must be 4-byte
aligned. Callers supply truthful, stable, mapped lower-canonical spans and serialize
access. The helper checks complete 64-bit bounds, pointer carry/canonicality and
all span overlaps involving mutable state/output. Readonly spans may overlap.
It snapshots the offsets, copies the range state, and stages the complete output
in a bounded 1128-byte local frame (1184 bytes including saved registers and
return address). Every refusal preserves all caller bytes. It preserves SysV
nonvolatile registers, clears DF, and never changes x87 or MXCSR control state.
There is no allocator, caller scratch, floating-point work or device access.

The total allocation is independent of the cumulative entropy cap. The cap admits
or refuses the whole result; it does not alter upstream decisions or reserve all
allocated pulse/fine bits in advance. Initial and final fractional entropy use,
final whole-bit physical use, range validity and sticky error are checked. The
later consumers must enforce their own budgets. Negative offsets/custom modes,
encoder hysteresis and runtime integration are outside this interface.

The source is pinned to the official Opus 1.5.2 archive, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
Original `rate.c`, `modes.c`, `static_modes_fixed.h` and `celt.c` supply the
algorithm, allocation/log/cap tables and `init_caps` formula. Copyright and the
full BSD grant/disclaimer are retained in the assembly,
`LICENSES/XIPH_OPUS_ALLOCATION.txt`, and `THIRD_PARTY_NOTICES.md`.

Run the inert host oracle with the already unpacked official sources:

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 python3 -m unittest \
  gauntlet_v2.tests.test_opus_allocation_host \
  gauntlet_v2.tests.test_opus_packet_host
```

The harness verifies all 394 official C/header hashes using the retained CWRS
harness, then compiles unmodified `rate.c` and `modes.c` with actual entropy and
`celt.c` functions. Only wrapper symbols are exported; unused upstream sections
are collected, with no unresolved symbols or source rewriting. It compares all
288 output bytes and every entropy-state field against the actual decoder.
Actual upstream encoder streams include raw tail bits between allocations.
Independent one-band controls cover all 81601 totals at N=1 and conservation
across every band/LM. Further controls cover band slices/modes/trim, boosted
bands, fractional boundaries, short physical frames, stale states, full-width
arguments, aliases, exact guarded spans and ABI/DF/FP preservation. SOURCE evidence
records the exact-base fail-first seam and assertion-caught source mutants.
These are host source controls, with no full-image, QEMU, metal or audio credit.
