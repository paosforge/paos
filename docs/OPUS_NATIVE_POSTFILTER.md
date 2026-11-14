# Native CELT pitch postfilter (unwired)

`src/media/opus_postfilter.asm` ports scalar fixed-point `comb_filter` from official
Xiph Opus1.5.2 `celt/celt.c`. The native decoder calls this after synthesis and
before deemphasis (`celt_decoder.c:1305,1309`). This helper supplies the in-place
filter operation; packet/frame orchestration and synthesis remain separate work.
It does not provide native Opus playback or physical audio qualification.
Future composition must also honor downstream magnitude and feedback bounds;
this helper's `SIG_SAT` domain does not broaden other helpers' admission ranges.

`media_opus_postfilter` takes RDI pointing to an88-byte readonly configuration.
All fields are64-bit; gains use sign-extended signed integers:

| Offset | Field | Accepted values |
| --- | --- | --- |
| 0 | samples | Writable signed32 buffer, aligned4 |
| 8 | sample_bytes | Full declared capacity, at least `4*(history+N)` |
| 16 | history | 17..1026, at least `max(15,T0,T1)+2` |
| 24 | N | 1..960 current samples |
| 32 / 40 | T0 / T1 | 0..1024, clamped to15 for filtering |
| 48 / 56 | g0 / g1 | -32768..32767, signed Q15 |
| 64 / 72 | tapset0 / tapset1 | 0..2 |
| 80 | overlap | 0..min(N,120), standard120-sample mode window |

The buffer holds `history` preceding samples followed by `N` current samples.
Every used sample must have magnitude at most300000000 (`SIG_SAT`), including
history and bypassed samples. Full64-bit dimensions, capacities and gains are
checked before access. Configuration alignment is8. Its88-byte span and the full
declared sample span must be disjoint, nonempty, nonwrapping and lower canonical
(end at most2^47). Callers own truthful, stable mappings and serialize access.

Return0 publishes exactly the `N` filtered current samples. History, capacity
tails and configuration remain unchanged. Return-1 changes no caller memory,
including when a late sample fails the magnitude bound. The implementation uses
8088 bytes of private stack plus saved registers and return addresses; callers
must supply that stack budget. It allocates no memory, performs no FP operations
and preserves SysV nonvolatile registers and FP controls, returning with DF clear.

Coefficient gain multiplication uses rounded `MULT16_16_P15`; interpolation and
signal products use arithmetic Q15 truncation. Old/new tapsets are interpolated
with the exact squared standard window and complement32767-f. An unchanged
filter skips overlap. Both zero gains bypass; zero new gain bypasses the tail.
Each computed sample saturates to ±300000000. Its result becomes available to
later delayed taps, preserving the upstream in-place recurrence. Since periods
are at least15, each delayed tap refers to a previous, fully computed sample;
reloading those taps is equivalent to upstream's rolling five-value window.

Signed32 pair sums have magnitude at most600000000. Each tapset's sum of absolute
coefficients including paired taps is at most32768 after rounded gain scaling.
Interpolated coefficients have conservative combined absolute sum at most65536,
so the unsaturated signal sum stays within±900000000. Private signed64 products
and accumulation preserve all defined upstream results; published feedback stays
within `SIG_SAT`. This bound avoids signed C overflow in the reference domain.

`gauntlet_v2/tests/test_opus_postfilter_host.py` compiles unchanged whole upstream
`celt.c` and `modes.c` in fixed-point mode, using section GC and an export map to
retain only the actual filter and standard-window oracle. The official release
archive and every394 C/header file must match. Run with
`PAOS_OPUS_REFERENCE_ROOT` pointing to the verified extracted1.5.2 release and,
optionally, `PAOS_OPUS_REFERENCE_ARCHIVE` pointing to its verified tarball.

The suite compares all signed16 gains, all periods, all N, all overlaps, tapsets,
zero/negative gains, clipping, random interpolation and recursive history against
upstream. A separate Python integer model covers fixed-point behavior and
stream continuation. Refusal controls exercise wide fields, full-capacity aliases,
late sample bounds and unchanged memory; guard pages and readonly configurations
check exact access bounds and the ABI. Source review evidence carries fail-first
and compiled assertion-mutant results. No target action or old audio replay occurs.

Source, copyright and redistribution terms are retained in
`LICENSES/XIPH_OPUS_POSTFILTER.txt` and in the assembly. This is an independent
unwired helper and preserves all existing codec/source/build/audio owners.
