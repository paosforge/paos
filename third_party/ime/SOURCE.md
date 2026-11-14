# Selected IME DATA: offline regeneration

Run `python3 -I -B tools/ime/gen_tables.py --check`, or use `--emit NEW_DIR`
to regenerate ten DATA/notice files without reading the shipped generated
includes. Python 3 standard library is the only prerequisite. The recipe reads
only its delivered, pinned primary inputs, complete grants and this declaration;
no network, installed dictionary, YAML package, host Unicode database, private
factory, or sibling tree is used. Output must be a new non-symlink directory.

Mozc: https://github.com/google/mozc at
`18e76511af9371a9a4409b1d13c3e30884b53e9c`, exact
`src/data/preedit/romanji-hiragana.tsv` (upstream spelling) is delivered as
`packaging/public_build_inputs/ime/romaji-hiragana.tsv`.
Its entire 2963-byte primary table is retained. The adjacent 5734-byte
`MOZC-LICENSE.txt` is the complete original root LICENSE, including Copyright
2010-2018 Google Inc., BSD-3-Clause conditions and disclaimer. Its separate
`src/data/dictionary*` NAIST/ICOT/Okinawa clauses remain verbatim; that dictionary
is not this selected preedit table. Neither Mozc engine nor those dictionaries
are shipped by this selection. No imported DATA is relicensed.

Rime: https://github.com/rime/rime-pinyin-simp at
`0c6861ef7420ee780270ca6d993d18d4101049d0`, exact `pinyin_simp.dict.yaml`
is delivered here as a build source. Full upstream root LICENSE and README.md
are retained as `packaging/public_build_inputs/ime/PINYIN-APACHE.txt` and
`PINYIN-README.txt`. The YAML header explicitly derives from Android Open Source
Project PinyinIME and is retained intact, including its original URL, both in
this primary file and the existing `PINYIN-SOURCE-HEADER.txt`.
The entire primary file is needed to re-extract the syllable union; no words,
frequencies, dictionary engine or Rime code are compiled into the native table.
The Apache-2.0 terms remain those of the original DATA, not a new grant.

`SOURCES.json` binds sizes, hashes, immutable URLs and full notices. The driver
also independently pins the five primary file sizes/hashes; the manifest itself
is hash-bound in the driver. No output include or derived syllable file is an
input to generation. Altered or absent primary files/notices fail before output.

The PaOS MPL-2.0 parsing, canonical binary ABI validator and NASM serializer
were extracted from `gauntlet_v2/tools/rcq38_ime_tables.py` at integration
`40950dd66d203d61c64c4fd8ee8f9fe760cd2226`; original MPL terms remain.
Only these DATA transformations are selected. The private host runtime oracle,
segmentation engine and golden trace generator are excluded. The public recipe
preserves the existing include comments as exact output identities; comments
are not file inputs. Independent tests assemble the DATA includes with NASM,
read the binary using the actual native ABI offsets, and compare primary rows,
literal examples and full hashes. This is not native runtime qualification.

Algorithm: split all Mozc tab records into key/output/optional carry. Identical
key duplicates collapse; conflicts refuse. BMP non-control scalars only, one to
three per rule; carry must be a proper key suffix. Lexically sorted 322 rules
use four 7-bit key groups, three one-based indices into the sorted 102-scalar
UTF-16 pool, and one consumed-byte count. Rime body starts after the YAML `...`
line. Union every ASCII lowercase syllable in the second tab column, split on
spaces, then sort all 415 unique syllables; six 5-bit groups encode a=1..z=26.
The v1 64-byte headers bind each complete original primary source hash.
Both blobs total 4568 bytes. No normalization, new aliases or rule changes are
introduced. Runtime handling of spelling aliases remains in `src/gui/ime_core.asm`.

The existing unsigned image recipe stages unchanged selected includes through
its established private-path aliases inside isolated build work only. Its input
manifest now also includes the public regeneration closure. Source export and
recipe discovery select this public tool and primary inputs. Only bounded mozc
and rime source-regeneration delivery is closed here. Historical musl binary
reproduction, GCC runtime, classifier, minimp3, historical setup, whole-source
privacy/origin/release and all runtime/physical qualification gaps remain.
