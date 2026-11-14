#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent primary-row/native DATA ABI, full-output and refusal controls."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / 'tools/ime/gen_tables.py'
PUBLIC = ROOT / 'packaging/public_build_inputs/ime'


def load():
    spec = importlib.util.spec_from_file_location('public_ime', TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_rows(blob, language):
    """Read offsets as used by src/gui/ime_core.asm; no generator decoder."""
    u16 = lambda pos: int.from_bytes(blob[pos:pos + 2], 'little')
    count, stride, pool_offset = u16(16), u16(14), u16(20)
    rows = {}
    for row in range(count):
        pos = 64 + row * stride
        key = int.from_bytes(blob[pos:pos + 4], 'little')
        if language == 1:
            text = ''.join(chr((key >> shift) & 127) for shift in (21, 14, 7, 0)).rstrip('\0')
            out = ''.join(chr(u16(pool_offset + (index - 1) * 2)) for index in blob[pos + 4:pos + 7] if index)
            rows[text] = (out, blob[pos + 7])
        else:
            rows[''.join(chr(96 + ((key >> shift) & 31)) for shift in (25, 20, 15, 10, 5, 0)
                         if ((key >> shift) & 31))] = None
    return rows


class PrimaryTests(unittest.TestCase):
    def setUp(self):
        self.g = load()
        self.outputs = self.g.build()

    def test_all_primary_romaji_records(self):
        rows = native_rows(self.outputs['ja.bin'], 1)
        primary = (PUBLIC / 'romaji-hiragana.tsv').read_text().splitlines()
        keys = set()
        for number, line in enumerate(primary, 1):
            fields = line.split('\t')
            key, out = fields[:2]
            carry = fields[2] if len(fields) == 3 else ''
            with self.subTest(primary_line=number, key=key):
                self.assertEqual(rows[key], (out, len(key) - len(carry)))
            keys.add(key)
        self.assertEqual(set(rows), keys)
        self.assertEqual(len(rows), 322)
        self.assertEqual(len({ord(c) for out, _ in rows.values() for c in out}), 102)

    def test_all_pinyin_primary_extraction_provenance(self):
        text = (ROOT / 'third_party/ime/pinyin_simp.dict.yaml').read_text()
        lines = text.splitlines()
        witnesses = {}
        for number in range(lines.index('...') + 1, len(lines)):
            line = lines[number]
            if line and not line.startswith('#'):
                word, readings, *_ = line.split('\t')
                for spelling in readings.split():
                    witnesses.setdefault(spelling, []).append((number + 1, word, readings))
        rows = native_rows(self.outputs['zh.bin'], 2)
        self.assertEqual(set(rows), set(witnesses))
        self.assertEqual(len(rows), 415)
        self.assertEqual(self.outputs['pinyin-syllables.txt'].decode().splitlines(), sorted(witnesses))
        self.assertGreater(sum(map(len, witnesses.values())), 50000)
        self.assertEqual(self.outputs['PINYIN-SOURCE-HEADER.txt'],
                         (PUBLIC / 'PINYIN-SOURCE-HEADER.txt').read_bytes())
        self.assertIn(b'platform/packages/inputmethods/PinyinIME.git', self.outputs['PINYIN-SOURCE-HEADER.txt'])

    def test_literal_primary_rules_and_native_packing(self):
        rows = native_rows(self.outputs['ja.bin'], 1)
        for key, value in {'a': ('あ', 1), 'n': ('ん', 1), 'nn': ('ん', 2),
                           'kk': ('っ', 1), 'xtsu': ('っ', 4), 'www': ('w', 1),
                           'z/': ('・', 2), 'zh': ('←', 2), '~': ('〜', 1)}.items():
            self.assertEqual(rows[key], value, key)
        zh = native_rows(self.outputs['zh.bin'], 2)
        for spelling in ('hm', 'm', 'n', 'ng', 'nv', 'lv', 'nue', 'lue', 'xian', 'zhong'):
            self.assertIn(spelling, zh)
        self.assertFalse({'nve', 'lve', 'ü', 'u:'} & set(zh))
        self.assertEqual(self.g.pack_key('ka', 1), (107 << 21) + (97 << 14))
        self.assertEqual(self.g.pack_key('zhong', 2), (26 << 25) + (8 << 20) + (15 << 15) + (14 << 10) + (7 << 5))

    def test_fixed_headers_and_whole_outputs(self):
        for lang, name, count, size, pool in ((1, 'ja', 322, 8, 102), (2, 'zh', 415, 4, 0)):
            blob = self.outputs[name + '.bin']
            self.assertEqual(blob[:8], b'PIMEJA1\0' if lang == 1 else b'PIMEZH1\0')
            header = [int.from_bytes(blob[i:i + 2], 'little') for i in range(8, 28, 2)]
            self.assertEqual(header, [1, lang, 64, size, count, 64, 64 + count * size, pool, len(blob), lang])
            self.assertEqual(blob[28:32], bytes((4, 3, 0, 0)) if lang == 1 else bytes((6, 0, 0, 0)))
            primary = PUBLIC / 'romaji-hiragana.tsv' if lang == 1 else ROOT / 'third_party/ime/pinyin_simp.dict.yaml'
            self.assertEqual(blob[32:64], hashlib.sha256(primary.read_bytes()).digest())
        for name, sha in {'ja.bin': '57c2ee1e390e865e53caba9c681e099cef604ed5828c8ef720b80675a42ad324',
                          'zh.bin': 'df138bde43f28da29d8417c89e5bb93246223c6e86c7ede55fd23930eeb6ff7f',
                          'ja.inc': 'f3d0c1040a861349ae0440e750a3f8f7f0fb5e89c7f0f0048f113fe9d5156906',
                          'zh.inc': '2346396915b947d32df4ed2c262ac5cdd10c9ad17882be11e847b9afcf81a391'}.items():
            self.assertEqual(hashlib.sha256(self.outputs[name]).hexdigest(), sha)
        for name, value in self.outputs.items():
            if not name.endswith('.bin'):
                self.assertEqual(value, (PUBLIC / name).read_bytes(), name)

    @unittest.skipUnless(shutil.which('nasm'), 'NASM required for native DATA assembly witness')
    def test_native_assembled_data_and_symbols(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, count, size, pool in [('ja', 322, 2844, 102), ('zh', 415, 1724, 0)]:
                tag = name.upper()
                # Assemble the actual generated include; assert the native symbol constants.
                source = self.outputs[name + '.inc'] + (f'\n%if IME_{tag}_COUNT != {count} || IME_{tag}_SIZE != {size} || IME_{tag}_POOL_COUNT != {pool}\n%error native ABI\n%endif\n').encode()
                (root / 'table.asm').write_bytes(source)
                p = subprocess.run(['nasm', '-f', 'bin', 'table.asm', '-o', 'table.bin'], cwd=root, capture_output=True)
                self.assertEqual(p.returncode, 0, p.stderr.decode())
                self.assertEqual((root / 'table.bin').read_bytes(), self.outputs[name + '.bin'])

    def test_duplicate_order_and_carry(self):
        raw = (PUBLIC / 'romaji-hiragana.tsv').read_bytes()
        self.assertEqual(self.g.parse_ja(raw + raw), self.g.parse_ja(raw))
        self.assertEqual(self.g.parse_ja(b'\n'.join(reversed(raw.splitlines()))), self.g.parse_ja(raw))
        self.assertEqual(self.g.parse_ja(b'kk\t\xe3\x81\xa3\tk'), {'kk': ('っ', 1)})
        for raw in (b'a\tx\na\ty', b'kk\tx\tkx', b'a\tx\ta', b'ka\tx\tk', b'a\tx\t\textra'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.g.parse_ja(raw)
        sample = b'---\n...\n\xe4\xb8\xad\tzhong guo\t1\n\xe5\x9b\xbd\tguo\t2\n'
        self.assertEqual(self.g.parse_zh(sample)[0], ['guo', 'zhong'])
        reordered = b'---\n...\n\xe5\x9b\xbd\tguo\t2\n\xe4\xb8\xad\tzhong guo\t1\n'
        self.assertEqual(self.g.parse_zh(reordered), self.g.parse_zh(sample))

    def test_unicode_alphabet_length_refusals(self):
        for cp in (0, 0x1f, 0x7f, 0x9f, 0xd800, 0x10000, 0x1f600):
            with self.subTest(cp=cp), self.assertRaises(ValueError):
                self.g.parse_ja(('a\t' + chr(cp)).encode('utf-8', errors='surrogatepass'))
        for raw in (b'', b'A\tx', b'abcde\tx', b'a', b'a\t', b'a\t1234', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.g.parse_ja(raw)
        for raw in (b'', b'---\n...\n', b'---\n...\nx\tA', b'---\n...\nx\tabcdefg',
                    b'---\n...\nx\ta  b', b'---\n...\n\tx', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.g.parse_zh(raw)
        for language in (0, 3):
            with self.assertRaisesRegex(ValueError, 'language'):
                self.g.pack_key('a', language)
        for language, value in [(1, (97 << 21) | 98), (1, 1 << 28), (2, 27 << 25), (2, 1 << 30)]:
            with self.assertRaises(ValueError):
                self.g.unpack_key(value, language)

    def test_canonical_corrupt_blob_refusals(self):
        blob = self.outputs['ja.bin']
        for offset in (0, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 29, 30, 32, 64, 68, 71, 2640):
            bad = bytearray(blob)
            bad[offset] ^= 255
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.g.decode(bad, 1, self.g.JA_SHA)
        for bad in (blob[:-1], blob + b'\0'):
            with self.assertRaises(ValueError):
                self.g.decode(bad, 1, self.g.JA_SHA)
        for language in (1, 2):
            with self.assertRaises(ValueError):
                self.g.encode({}, language, self.g.JA_SHA)


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.g = load()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        manifest = json.loads((ROOT / 'third_party/ime/SOURCES.json').read_bytes())
        self.names = ['third_party/ime/SOURCES.json', *manifest['files']]
        for name in self.names:
            dst = self.root / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes((ROOT / name).read_bytes())
        self.g.ROOT = self.root

    def test_every_primary_notice_and_manifest_missing_changed(self):
        for name in self.names:
            target = self.root / name
            raw = target.read_bytes()
            target.unlink()
            with self.subTest(name=name, mode='missing'), self.assertRaises(ValueError):
                self.g.build()
            target.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
            with self.subTest(name=name, mode='same-size changed'), self.assertRaises(ValueError):
                self.g.build()
            target.write_bytes(raw)
        self.assertEqual(len(self.g.build()['ja.bin']), 2844)

    def test_manifest_required_set_beyond_manifest_hash(self):
        path = self.root / 'third_party/ime/SOURCES.json'
        original = path.read_bytes()
        for name in json.loads(original)['files']:
            data = json.loads(original)
            del data['files'][name]
            path.write_text(json.dumps(data))
            self.g.MANIFEST_SHA = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'omission'):
                self.g.inputs()

    def test_manifest_whitespace_change_refuses(self):
        path = self.root / 'third_party/ime/SOURCES.json'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'manifest pin'):
            self.g.inputs()

    def test_direct_admission_same_size_hash(self):
        path = self.root / self.g.PATHS['ja_source']
        data = path.read_bytes()
        path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        size, sha = self.g.PINS['ja_source']
        with self.assertRaisesRegex(ValueError, 'input hash'):
            self.g.admitted(self.g.PATHS['ja_source'], size, sha)

    def test_primary_pin_beyond_manifest_hash(self):
        path = self.root / self.g.PATHS['ja_source']
        path.write_bytes(path.read_bytes().replace(b'\ta', b'\tb', 1) + b'x')
        manifest_path = self.root / 'third_party/ime/SOURCES.json'
        m = json.loads(manifest_path.read_bytes())
        m['files'][self.g.PATHS['ja_source']].update(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        manifest_path.write_text(json.dumps(m))
        self.g.MANIFEST_SHA = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'primary pin'):
            self.g.inputs()

    def test_symlink_inputs_and_parent(self):
        target = self.root / self.g.PATHS['ja_source']
        raw = target.read_bytes()
        saved = self.root / 'saved.tsv'
        saved.write_bytes(raw)
        target.unlink()
        target.symlink_to(saved)
        with self.assertRaisesRegex(ValueError, 'redirected'):
            self.g.build()
        target.unlink()
        target.write_bytes(raw)
        directory = self.root / 'packaging/public_build_inputs/ime'
        directory.rename(directory.with_name('retained'))
        directory.symlink_to(directory.with_name('retained'), target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'redirected'):
            self.g.build()

    def test_emit_without_generated_input_and_output_refusals(self):
        # This root deliberately has no includes or derived pinyin inventory.
        outputs = self.g.build()
        out = Path(self.temp.name) / 'out'
        self.g.emit(out, outputs)
        self.assertEqual({p.name for p in out.iterdir()}, set(outputs))
        with self.assertRaisesRegex(ValueError, 'new directory'):
            self.g.emit(out, outputs)
        redirect = Path(self.temp.name) / 'link'
        redirect.symlink_to(out, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.g.emit(redirect / 'child', outputs)
        self.assertFalse((out / 'child').exists())


class PublicCompositionTests(unittest.TestCase):
    def test_actual_unsigned_input_and_alias_closure(self):
        spec = importlib.util.spec_from_file_location('image', ROOT / 'tools/release/build_unsigned_public_image.py')
        image = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(image)
        names = image.input_paths(ROOT)
        for name in ('tools/ime/gen_tables.py', 'third_party/ime/pinyin_simp.dict.yaml', 'third_party/ime/SOURCES.json'):
            self.assertIn(name, names)
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            for name in image.BUILD_ALIASES.values():
                out = work / name
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes((ROOT / name).read_bytes())
            aliases = image.stage_aliases(work)
            rebuilt = load().build()
            for tag in ('ja', 'zh'):
                name = 'gauntlet_v2/docs/ime/generated/' + tag + '.inc'
                self.assertEqual((work / name).read_bytes(), rebuilt[tag + '.inc'])
                self.assertEqual(aliases[name]['sha256'], hashlib.sha256(rebuilt[tag + '.inc']).hexdigest())
            with self.assertRaises(ValueError):
                image.stage_aliases(work)


if __name__ == '__main__':
    unittest.main()
