#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Offline primary IME DATA -> existing canonical native includes.

Parsing, binary ABI validation and emission adapted from the original PaOS
MPL-2.0 table generator. No upstream engine code. Imported DATA and notices
retain their own terms; see third_party/ime/SOURCE.md.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
INPUT = 'third_party/ime/'
MANIFEST_SHA = '4118423ac9241640a75dd876277dd40c985ce1ba7ee434ab1f5abccf4b9043e7'
PATHS = {
    'ja_source': 'packaging/public_build_inputs/ime/romaji-hiragana.tsv',
    'ja_license': 'packaging/public_build_inputs/ime/MOZC-LICENSE.txt',
    'zh_source': INPUT + 'pinyin_simp.dict.yaml',
    'zh_license': 'packaging/public_build_inputs/ime/PINYIN-APACHE.txt',
    'zh_readme': 'packaging/public_build_inputs/ime/PINYIN-README.txt',
}


class TableError(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise TableError(message)


HEADER = struct.Struct('<8s10HBB2s32s')
JA_ROW = struct.Struct('<I3BB')
JA_SHA = 'fcb900e311d32ced05499c86e236d1084fb0c0937398deb6311fc6c7287a7821'
ZH_SHA = 'e341598343a0f0f2035bb1aafc34a7f3bb7887deeecb3f60796262aaa2983e6b'
PINS = {
    'ja_source': (2963, JA_SHA),
    'ja_license': (5734, '44cdd923b91ea9199293abecc2762c70c87dbf1e581c027a94c416368d1a648c'),
    'zh_source': (1266216, ZH_SHA),
    'zh_license': (11358, 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'),
    'zh_readme': (255, 'bc51038baf2408cc5ec9eba680634cfd4ec07f905a636644839daff1a94055c9'),
}
JA_ALPHABET = "',-./[]abcdefghijklmnopqrstuvwxyz~"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def scalar_ok(c):
    return 0x20 <= c <= 0xffff and not 0x7f <= c <= 0x9f and not 0xd800 <= c <= 0xdfff


def pack_key(key, language):
    need(language in (1, 2), 'language')
    width, bits = (4, 7) if language == 1 else (6, 5)
    alphabet = JA_ALPHABET if language == 1 else 'abcdefghijklmnopqrstuvwxyz'
    need(0 < len(key) <= width and all(c in alphabet for c in key), 'key alphabet/length')
    result = 0
    for c in key.ljust(width, '\0'):
        code = 0 if c == '\0' else ord(c) if language == 1 else ord(c) - 96
        result = (result << bits) | code
    return result


def unpack_key(value, language):
    need(language in (1, 2), 'language')
    width, bits = (4, 7) if language == 1 else (6, 5)
    need(value >> (width * bits) == 0, 'key high bits')
    result, padding = '', False
    for shift in range((width - 1) * bits, -1, -bits):
        code = (value >> shift) & ((1 << bits) - 1)
        if code == 0:
            padding = True
        else:
            need(not padding, 'key noncontiguous')
            if language == 2:
                need(code <= 26, 'key letter')
            result += chr(code if language == 1 else code + 96)
    need(pack_key(result, language) == value, 'key canonical')
    return result


def parse_ja(data):
    rows = {}
    for line in data.decode('utf-8').splitlines():
        parts = line.split('\t')
        need(len(parts) in (2, 3), 'romaji columns')
        key, output = parts[:2]
        carry = parts[2] if len(parts) == 3 else ''
        pack_key(key, 1)
        need(1 <= len(output) <= 3 and all(scalar_ok(ord(c)) for c in output), 'romaji scalar')
        need(len(carry) < len(key) and key.endswith(carry), 'romaji carry')
        value = (output, len(key) - len(carry))
        need(key not in rows or rows[key] == value, 'conflicting duplicate')
        rows[key] = value
    need(rows, 'empty romaji')
    return dict(sorted(rows.items()))


def parse_zh(data):
    text = data.decode('utf-8')
    need('\n...\n' in text, 'pinyin header')
    header, body = text.split('\n...\n', 1)
    syllables = set()
    for line in body.splitlines():
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        need(len(parts) >= 2 and parts[0] and parts[1], 'pinyin columns')
        for syllable in parts[1].split(' '):
            pack_key(syllable, 2)
            syllables.add(syllable)
    need(syllables, 'empty pinyin')
    return sorted(syllables), (header + '\n...\n').encode('utf-8')


def encode(rows, language, source_sha):
    need(language in (1, 2), 'language')
    keys = sorted(rows)
    need(0 < len(keys) <= 65535 and len(set(keys)) == len(keys), 'row count')
    pool = sorted({ord(c) for out, _ in rows.values() for c in out}) if language == 1 else []
    need(len(pool) <= 255, 'pool index overflow')
    index = {c: i + 1 for i, c in enumerate(pool)}
    size = 8 if language == 1 else 4
    pool_offset = 64 + len(keys) * size
    total = pool_offset + len(pool) * 2
    need(total <= 65535, 'blob overflow')
    blob = HEADER.pack(b'PIMEJA1\0' if language == 1 else b'PIMEZH1\0',
                       1, language, 64, size, len(keys), 64, pool_offset,
                       len(pool), total, language, 4 if language == 1 else 6,
                       3 if language == 1 else 0, b'\0\0', bytes.fromhex(source_sha))
    for key in keys:
        packed = pack_key(key, language)
        if language == 1:
            output, consumed = rows[key]
            need(1 <= len(output) <= 3, 'output length')
            indices = [index[ord(c)] for c in output]
            blob += JA_ROW.pack(packed, *(indices + [0] * (3 - len(indices))), consumed)
        else:
            blob += struct.pack('<I', packed)
    blob += b''.join(struct.pack('<H', c) for c in pool)
    decode(blob, language, source_sha)
    return blob


def decode(blob, language, source_sha):
    """Validate exact canonical blob and return source-equivalent rows."""
    need(isinstance(blob, (bytes, bytearray)) and language in (1, 2)
         and 64 <= len(blob) <= 65535, 'blob bytes/length/language')
    fields = HEADER.unpack_from(blob)
    magic, version, lang, hs, rs, count, ro, po, pc, total, policy, mk, mo, reserved, sha = fields
    need(magic == (b'PIMEJA1\0' if language == 1 else b'PIMEZH1\0'), 'magic')
    need((version, lang, hs, rs, ro, policy, mk, mo, reserved) ==
         (1, language, 64, 8 if language == 1 else 4, 64, language,
          4 if language == 1 else 6, 3 if language == 1 else 0, b'\0\0'), 'header constants')
    need(sha.hex() == source_sha, 'compiled source pin')
    need(count > 0 and pc <= 255 and (pc > 0 if language == 1 else pc == 0), 'counts')
    need(po == 64 + count * rs and total == po + pc * 2 and total == len(blob), 'offset/length')
    pool = [struct.unpack_from('<H', blob, po + 2 * i)[0] for i in range(pc)]
    need(all(scalar_ok(c) for c in pool) and pool == sorted(set(pool)), 'pool scalars/order')
    result, last, used = {}, -1, set()
    for i in range(count):
        offset = ro + i * rs
        packed = struct.unpack_from('<I', blob, offset)[0]
        need(packed > last, 'row order/duplicate')
        last = packed
        key = unpack_key(packed, language)
        if language == 1:
            _, a, b, c, consumed = JA_ROW.unpack_from(blob, offset)
            indices = [a, b, c]
            need(a != 0 and all(x <= pc for x in indices), 'output index')
            seen_zero = False
            for x in indices:
                if not x:
                    seen_zero = True
                else:
                    need(not seen_zero, 'output noncontiguous')
                    used.add(x)
            need(1 <= consumed <= len(key), 'consumed')
            result[key] = (''.join(chr(pool[x - 1]) for x in indices if x), consumed)
        else:
            result[key] = None
    need(language == 2 or used == set(range(1, pc + 1)), 'unused scalar pool')
    return result if language == 1 else list(result)


def nasm(blob, language):
    tag = 'JA' if language == 1 else 'ZH'
    fields = HEADER.unpack_from(blob)
    text = [f';; MODULE core/ime_{tag.lower()}_table', ';; LAYER 1',
            f';; EXPORTS ime_{tag.lower()}_table', ';; IMPORTS', ';; CAPS',
            ';; OWNER rc-codex-relops', ';; CONTEXT: immutable_data',
            '; Generated immutable DATA; upstream notices are adjacent.',
            '; No include, native code, absolute pointer or dq label.',
            f'IME_{tag}_SIZE equ {len(blob)}', f'IME_{tag}_COUNT equ {fields[5]}',
            f'IME_{tag}_ROWS_OFFSET equ {fields[6]}', f'IME_{tag}_ROW_SIZE equ {fields[4]}',
            f'IME_{tag}_POOL_OFFSET equ {fields[7]}', f'IME_{tag}_POOL_COUNT equ {fields[8]}',
            f'ime_{tag.lower()}_table:']
    text += ['    db ' + ','.join(f'0x{x:02x}' for x in blob[i:i + 16]) for i in range(0, len(blob), 16)]
    return ('\n'.join(text) + '\n').encode('ascii')


def local(name):
    path = Path(name)
    need(not path.is_absolute() and '..' not in path.parts and bool(path.parts), 'unsafe input path')
    path = ROOT / path
    need(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
         'missing or redirected input: ' + name)
    return path


def admitted(name, size, sha):
    path = local(name)
    need(path.stat().st_size == size, 'input size: ' + name)
    data = path.read_bytes()
    need(len(data) == size and digest(data) == sha, 'input hash: ' + name)
    return data


def inputs():
    raw = local(INPUT + 'SOURCES.json').read_bytes()
    need(len(raw) < 16384 and digest(raw) == MANIFEST_SHA, 'source manifest pin')
    manifest = json.loads(raw)
    need(manifest['schema'] == 'paos.ime-primary-source.v1', 'source schema')
    required = set(PATHS.values()) | {INPUT + 'SOURCE.md', 'LICENSES/MPL-2.0.txt'}
    need(set(manifest['files']) == required, 'source/license omission or extra input')
    data = {name: admitted(name, row['bytes'], row['sha256']) for name, row in manifest['files'].items()}
    result = {key: data[name] for key, name in PATHS.items()}
    for key, value in result.items():
        size, sha = PINS[key]
        need(len(value) == size and digest(value) == sha, 'primary pin: ' + key)
    return result


def build():
    data = inputs()
    ja = parse_ja(data['ja_source'])
    zh, header = parse_zh(data['zh_source'])
    ja_blob, zh_blob = encode(ja, 1, JA_SHA), encode(zh, 2, ZH_SHA)
    need(len(ja_blob) + len(zh_blob) <= 5120, 'combined 5KiB budget')
    need(decode(ja_blob, 1, JA_SHA) == ja and decode(zh_blob, 2, ZH_SHA) == zh, 'source roundtrip')
    return {'ja.bin': ja_blob, 'zh.bin': zh_blob, 'ja.inc': nasm(ja_blob, 1),
            'zh.inc': nasm(zh_blob, 2), 'MOZC-LICENSE.txt': data['ja_license'],
            'PINYIN-APACHE.txt': data['zh_license'], 'PINYIN-README.txt': data['zh_readme'],
            'PINYIN-SOURCE-HEADER.txt': header, 'romaji-hiragana.tsv': data['ja_source'],
            'pinyin-syllables.txt': ('\n'.join(zh) + '\n').encode('ascii')}


def emit(out, outputs):
    out = out.absolute()
    need(not any(p.is_symlink() for p in (out, *out.parents)), 'output symlink')
    need(not out.exists(), 'output must be new directory')
    out.mkdir(parents=True)
    for name, value in outputs.items():
        (out / name).write_bytes(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--emit', type=Path)
    args = parser.parse_args()
    try:
        outputs = build()
        if args.check:
            for name, data in outputs.items():
                if name.endswith('.bin'):
                    continue
                need(local('packaging/public_build_inputs/ime/' + name).read_bytes() == data,
                     'shipped DATA/notice differs: ' + name)
            print('IME DATA: exact 322 romaji rules / 415 pinyin syllables; 4568 binary bytes')
        else:
            emit(args.emit, outputs)
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        print('gen_tables: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
