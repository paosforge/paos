# Native CELT recursive partition decoding

`src/media/opus_partition_recursive.asm` supplies the previously missing split
branch of fixed-point Opus 1.5.2 `bands.c:quant_partition`. It composes the
accepted rate-cache, split-angle and unsplit partition decoders. It is an
independent, unwired helper; it does not supply full frame decoding or playback.

Call `media_opus_partition_recursive_decode(RDI=range64*, RSI=config128*)`.
RAX is 0 on success or -1 on refusal. Configuration, span requirements and
unsplit results are exactly the [original partition ABI](OPUS_NATIVE_PARTITION.md).
The `media_opus_partition_decode` entry retains its existing ABI.
For a split, the six u32 metadata fields are:

| Field | Meaning |
|---|---|
| N | Root coefficient count |
| q | UINT32_MAX, indicating a recursive partition |
| cost | Sum of angle qalloc and final leaf pulse costs |
| remaining_after | Signed int32 result, stored as its u32 bit pattern |
| seed_after | Final uint32 LCG state |
| collapse_mask | Combined transient collapse bits |

Root band 0..20 and signed LM -1..3 derive N from the actual standard 48 kHz
mode. N must be 2..176 and the actual rate cache must exist. Root b and
remaining are independently bounded to 0..81600 eighth-bits, the maximum
1275-byte Opus entropy span times 64. B is 1/2/4/8/16 and divides N, spread 0..3,
Q15 gain 0..32767, seed uint32 and fill uint16. The cumulative fractional cap
cannot exceed physical frame capacity and must admit initial entropy state.
The root remaining input retains the original nonnegative domain; a negative
returned remaining value describes exhausted allocation and is not an admitted
input for a later call to this bounded entry.

The split condition is exactly `LM!=-1 && N>2 && b>cache[last]+12`. The rate
helper's largest cost includes the upstream +1, so the comparison uses that
cost plus 11. Each split halves N, decrements LM, duplicates active mono fill
when B=1, and changes B to `(B+1)/2`. The public theta decoder consumes the
actual mono uniform/triangular angle distribution. Its fixed-point gains,
qalloc, delta and endpoint masks feed the original transient delta adjustment,
signed division toward zero, larger-allocation child first, tie-to-mid order,
24-eighth-bit redistribution reserve and endpoint exceptions. Child gains use
upstream rounded Q15 products; side collapse bits shift by B0/2.

Only the low B fill bits can affect a node. Masking inactive bits before mono
fill duplication preserves upstream output while keeping every theta call's
fill within uint16. Original high bits can only shift toward higher inactive
positions; the side child consumes only its active B bits. Tests cover every
uint16 root fill value and both noise/folding paths.

Angle charges can make shared remaining negative even when root remaining was
zero. Internal bookkeeping remains signed. A negative-budget leaf invokes the
original helper with remaining=0, which forces q=0/cost=0, then preserves the
actual negative shared remaining. Mono theta has no remaining-dependent
inversion bit, so clamping its validation-only remaining input also preserves
upstream behavior. Seed updates follow actual child visitation order.

LM decreases to -1, so there are at most four splits along a path, five active
nodes, 16 leaves and 31 total nodes. Child geometry comes from the same actual
band/LM, with no arbitrary dimensions or cache extension. Child B continues
to divide N. Local b never exceeds root b: redistribution transfers unused
first-child allocation minus a positive reserve. Angle and leaf charges fit
signed 32-bit arithmetic; shared arithmetic uses signed 64-bit storage.

The public entry reserves 3144 private stack bytes plus six saved registers.
Each recursive activation reserves 440 bytes plus six saved registers and
fixed call overhead. There is no caller scratch or dynamic allocation. A
conservative bound including all active nodes, original 3144-byte leaf frame,
PVQ (488 bytes), CWRS (312 bytes), saved registers and entropy/math call frames
is 12 KiB below public-entry RSP. Tests place the real call on a guarded
16 KiB stack and require its bottom 4 KiB to remain untouched.

All full declared configuration, state, vector, metadata, optional lowband and
nonempty entropy-frame spans must be lower canonical, aligned and pairwise
disjoint, with no addition carry. These checks precede recursive work. Caller
storage must be truthfully mapped, stable and serialized. Work stages entropy
state, all N coefficients and metadata privately. A late angle, pulse, folding
or entropy refusal publishes nothing. Success publishes only after final error,
whole-bit and fractional checks. Larger declared capacity tails remain unchanged.
Each active folded leaf retains the original conservative energy fence
`sum((abs(low[j])+4)^2)<=2^29`; unused lowband samples are unrestricted.
SysV nonvolatile registers and FP controls are preserved, and DF clears.
Publication across separate output spans is not concurrently atomic.

The port consumes the unchanged official Opus 1.5.2 release archive:
`https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz`, SHA256
`65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
Whole `bands.c`, actual `modes.c`/`static_modes_fixed.h`, `rate.h`, `vq.c`,
`mathops.c` and entropy/CWRS sources supply the algorithm and independent oracle.
The tests verify all 394 C/header members against that archive before compiling
whole unchanged reference sources. Compiler function-entry profiling counts
actual recursive calls without changing upstream source bytes. No oracle C is
linked into PaOS. Complete notices are retained in the assembly and
[partition license](../LICENSES/XIPH_OPUS_PARTITION.txt).

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 \
  python3 gauntlet_v2/tests/test_opus_partition_recursive_host.py -v
```

The suite covers split thresholds, all valid mode/cache geometries and block
counts, signed delta and masking, all four depths, full trees, every root fill,
seed/gain/spread boundaries, negative internal remaining, actual encoder-produced
frames, interleaved entropy operations and consecutive partitions. It compares
every coefficient, all six metadata fields and every entropy-state field.
Guarded pages cover exact configuration/state/frame/output/metadata/lowband
spans and readonly inputs. Short/empty frames, strict caps, late child failures,
fold-energy refusals, full-width invalid values and declared-tail aliases check
transactional refusal. Every native call runs an ABI/DF/FP wrapper.

The SOURCE evidence retains an exact-original split-positive failure and
compiled semantic mutation controls. Set `PAOS_OPUS_RECURSIVE_ENTRY=old` to run
the positive control against the unchanged original entry; it must fail by
assertion. `PAOS_OPUS_RECURSIVE_SOURCE` selects an external mutated assembly
copy; normal tests assemble the repository source.

N=1 band special cases, outer band/TF orchestration, stereo band allocation,
full packet-to-frame decoding and PCM/playback wiring remain separate work.
Existing HDA review and physical qualification records retain their owners.
