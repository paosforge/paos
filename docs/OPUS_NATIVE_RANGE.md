# Native Opus range entropy primitives

`src/media/opus_range.asm` ports the integer range decoder and bit-accounting
thresholds from Xiph Opus 1.5.2. It is currently unwired, alongside the accepted
packet parser. This supplies entropy operations for later SILK/CELT decoding;
it produces symbols, without PCM, Ogg parsing, playback or hardware proof.

The port follows [RFC 6716 section 4.1](https://www.rfc-editor.org/rfc/rfc6716#section-4.1)
and the [Xiph decoder](https://github.com/xiph/opus/blob/v1.5.2/celt/entdec.c).
Upstream attribution, grant and disclaimer are retained in the source and
[notice](../LICENSES/XIPH_OPUS_RANGE.txt).

All operations take a stable caller-owned 64-byte state in RDI, return a
nonnegative result or -1, preserve SysV nonvolatile registers/RSP and FP state,
and clear DF. Refusal makes no state or input write. The caller serializes use
and supplies truthful mapped spans. Pointers are full-width lower canonical;
state is 8-byte aligned and disjoint from the stable frame and ICDF table.
No allocation, global cursor, device operation or unbounded table scan occurs.

| Routine prefix `media_opus_range_` | Additional arguments | Result |
| --- | --- | --- |
| `init` | RSI frame, RDX length 0..1275 | 0 |
| `bit` | RSI log probability 1..15 | 0 or 1 |
| `icdf` | RSI u8 table, RDX count 1..256, RCX precision 1..8 | Symbol index |
| `uint` | RSI exclusive bound 2..4294967295 | Symbol below bound |
| `bits` | RSI raw-bit count 1..25 | Unsigned raw value |
| `tell` | None | Rounded bits used |
| `tell_frac` | None | Eighth-bits used |
| `decode` | RSI total 2..65536 | Cumulative symbol, without mutation |
| `update` | RSI low, RDX high, RCX total 2..65536 | 0 |

State layout is u64 frame pointer and length, then u32 forward offset, reverse
offset, raw window, available raw bits, total bits, range, value, saved byte,
sticky error, magic, reserved0 and reserved1. Reserved fields stay zero. Current
range is normalized to (2^23,2^31], value is below range, offsets stay within
length and raw available bits stay at most31. The accounting guard refuses
above 0x0fffff00 total bits, well before signed/fractional overflow.

An ICDF has nonincreasing entries at most 2^precision and a final zero; equal
entries and zero probability symbols are valid. The whole count-bounded table
is checked before mutation. All byte reads stay inside their respective spans.

Opus entropy input deliberately uses implicit zero padding after storage ends.
A zero-length frame therefore initializes without reading input; a null frame
is valid only at length0. Forward entropy and reverse raw-bit readers may
overlap bytes, as the reference decoder does. Physical byte exhaustion is not
a malformed-packet test. Future codec consumers must enforce actual symbol
and bit budgets and mode-specific validity.

A uint encoding outside its exclusive bound clamps to bound-1 and latches
state error1, matching Xiph. Later operations retain the error. Consumers must
reject an errored frame before publication; a successful primitive never grants
packet or PCM acceptance. ICDF16 and PVQ operations are not supplied yet.

The split `decode`/`update` interface recomputes `rng/total` and the current
cumulative symbol during update, refusing unless `0<=low<high<=total` contains
that symbol. First intervals retain the division remainder, matching Xiph.
The caller serializes the pair, with no intervening entropy operation; decode
has no write, and no pending factor is stored in the reserved state bytes.
For power-of-two totals the division equals Xiph's `ec_decode_bin` shift.
The [CELT energy stage](OPUS_NATIVE_CELT_ENERGY.md) uses total32768 for Laplace;
its transactional caller enforces the physical frame bit budget.

For host verification, extract the [official 1.5.2 archive](https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz),
SHA-256 `65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`,
and run:

```sh
PAOS_OPUS_REFERENCE_ROOT=/path/to/opus-1.5.2 python3 -B -m unittest gauntlet_v2.tests.test_opus_range_host -v
```

The test compiles the unmodified release range encoder/decoder as an oracle,
checks exact source hashes, and assembles the production NASM module. It
compares returned symbols, every relevant state field and both bit counts
after mixed operations, including malformed inputs. Independent encoder
round trips exercise interleaved range symbols and reverse raw bits. Guard
pages, full-width arguments, unchanged refusals, sticky errors and ABI controls
cover the host boundary. No network or hardware action occurs in the tests.
