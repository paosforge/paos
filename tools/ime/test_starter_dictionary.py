#!/usr/bin/env python3
"""Finite source-selection and PDCT refusal controls. SPDX-License-Identifier: MPL-2.0"""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[0]))
import rcq38_product_dictionary as d


def row(key, surface, cost=0, weight=0, left=0):
    return (key.encode(), surface.encode(), left, 0, cost, weight, 0)


class StarterDictionary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import rcq38_starter_dictionary as s
        cls.s = s

    def test_source_scores_and_pos_preserved_best_surface_reading(self):
        rows = [row('あ', '亜', 100, left=2), row('あ', '亜', -9, left=7),
                row('あ', '井', -5), row('あ', '井', -5)]
        selected, stats = self.s.select(rows, 'ja', {0x4e9c, 0x4e95})
        self.assertEqual(selected, sorted([rows[1], rows[2]]))
        self.assertEqual(stats['drops']['exact_duplicate'], 1)
        self.assertEqual(stats['drops']['same_reading_surface'], 1)
        self.assertEqual(sum(stats['drops'].values()) + stats['selected_rows'], len(rows))
        raw = d.b.dictionary_shards(selected, 'ja', b'fixture')[0][0][0]
        self.assertEqual(list(d.decode_rows(raw, 'ja')), selected)
        index = d.index_bytes([raw], 'ja')
        self.assertEqual(d.lookup(index, [raw], 'ja', 'あ'.encode()), [rows[1], rows[2]])

    def test_glyph_and_real_single_character_reading_filters(self):
        rows = [row('あ', '亜'), row('い', '井'), row('あ', '亜井'),
                row('あ', 'A'), row('a', '亜'), row('あ', '😀')]
        selected, stats = self.s.select(rows, 'ja', {0x4e9c})
        self.assertEqual(selected, rows[:1])
        self.assertEqual(stats['drops']['glyph_missing'], 1)
        self.assertEqual(stats['drops']['not_single_ideograph'], 3)
        self.assertEqual(stats['drops']['reading_unavailable'], 1)

    def test_chinese_unsigned_source_frequency_and_single_syllable(self):
        rows = [row('a', '亜', weight=1), row('a', '井', weight=0xffffffff),
                row('a a', '亜', weight=50)]
        selected, stats = self.s.select(rows, 'zh-Hans', {0x4e9c, 0x4e95})
        self.assertEqual(selected, sorted(rows[:2]))
        self.assertEqual(stats['drops']['reading_unavailable'], 1)
        limited, _ = self.s.select(rows, 'zh-Hans', {0x4e9c, 0x4e95}, key_limit=1)
        self.assertEqual(limited, [rows[1]])

    def test_budget_boundaries_no_partial_row_and_determinism(self):
        rows = [row('あ', '亜', -1), row('い', '井', 2)]
        one = 192 + 36 + 3 + 3
        selected, stats = self.s.select(rows, 'ja', {0x4e9c, 0x4e95}, byte_limit=one)
        self.assertEqual(selected, rows[:1])
        self.assertEqual(stats['pack_bytes'], one)
        self.assertEqual(stats['drops']['byte_limit'], 1)
        self.assertEqual(self.s.select(list(reversed(rows)), 'ja', {0x4e9c, 0x4e95}, byte_limit=one),
                         (selected, stats))
        with self.assertRaises(d.p.PackError):
            self.s.select(rows, 'ja', {0x4e9c}, byte_limit=one - 1)

    def test_explicit_reading_and_surface_caps(self):
        rows = [row('あ', '亜', -3), row('い', '亜', -2), row('あ', '井', -1)]
        selected, stats = self.s.select(rows, 'ja', {0x4e9c, 0x4e95}, key_limit=1, surface_limit=1)
        self.assertEqual(selected, rows[:1])
        self.assertEqual(stats['drops']['surface_limit'], 1)
        self.assertEqual(stats['drops']['key_limit'], 1)
        for args in [dict(key_limit=0), dict(key_limit=513), dict(surface_limit=0), dict(byte_limit=99999999)]:
            with self.subTest(args=args), self.assertRaises(d.p.PackError):
                self.s.select(rows, 'ja', {0x4e9c}, **args)

    def test_exact_glyph_bytes_and_malformed_bitmap_refusals(self):
        good = b'4E95:' + b'01' * 32 + b'\n4E9C:' + b'FF' * 32 + b'\n'
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'glyphs.hex'
            path.write_bytes(good)
            coverage, pin = self.s.glyph_coverage(path, d.p.digest(good).hex())
            self.assertEqual(coverage, {0x4e95, 0x4e9c})
            self.assertEqual(pin['bytes'], len(good))
            for raw, digest in [(good, '00' * 32), (good + good, None),
                                (good.replace(b'01', b'GG', 1), None),
                                (b'D800:' + b'FF' * 32 + b'\n', None),
                                (b'4E95:' + b'00' * 32 + b'\n', None)]:
                path.write_bytes(raw)
                with self.subTest(raw=raw[:8]), self.assertRaises(d.p.PackError):
                    self.s.glyph_coverage(path, digest or d.p.digest(raw).hex())

    def test_unknown_locale_and_no_supported_candidates_refuse(self):
        for locale, rows in [('xx', [row('あ', '亜')]), ('ja', [row('あ', 'A')])]:
            with self.subTest(locale=locale), self.assertRaises(d.p.PackError):
                self.s.select(rows, locale, {0x4e9c})

    def test_full_notice_and_source_refusals_precede_output(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); glyph = base / 'glyph.hex'
            raw = b'4E9C:' + b'FF' * 32 + b'\n'; glyph.write_bytes(raw)
            for failed_name in ['dictionary00.txt', 'mozc-license.txt']:
                output = base / ('out-' + failed_name)
                def pinned(inputs, source):
                    if source['name'] == failed_name:
                        raise d.p.PackError('source hash/size')
                    if source['name'] == 'pinyin_simp.dict.yaml':
                        return b'# ancestry\n...\n' + '亜\ta\t1\n'.encode()
                    if source['name'].startswith('dictionary'):
                        return 'あ\t0\t0\t-1\t亜\n'.encode()
                    return b'full notice\n'
                with patch.object(d.b, 'pinned_bytes', side_effect=pinned), self.assertRaises(d.p.PackError):
                    self.s.generate(base, glyph, d.p.digest(raw).hex(), '11' * 32, 2, 'B', output)
                self.assertFalse(output.exists())

    def test_committed_alternative_generation_and_reading_examples(self):
        root = Path(__file__).resolve().parents[2]
        directory = root / 'third_party/ime/starter'
        manifest, artifacts = d.p.read_host_set(directory, directory / 'HOST_TEST_MANIFEST.json',
                                               '11' * 32, 2, 'B')
        receipt = d.p.parse_json((directory / 'HOST_BUILD_RECEIPT.json').read_bytes())
        provenance = d.p.parse_json(artifacts['starter-dictionary-provenance.json'])
        self.assertEqual(provenance['glyph_subset']['sha256'],
                         '6c4b16cf4cb8f53e3d8d9bf8da012271547c10bf0fb2bec60dfebac042b42d73')
        for locale, family, key, expected, row_count in [
                ('ja', 'ja', 'にち', '日', 2857), ('zh-Hans', 'pinyin', 'ni', '你', 3106)]:
            raw = artifacts[family + '-full-000.pdct']
            rows = list(d.decode_rows(raw, locale))
            self.assertEqual(len(rows), row_count)
            self.assertTrue(all(len(row[1].decode()) == 1 for row in rows))
            self.assertLessEqual(len(raw), 128 * 1024)
            index = d.index_bytes([raw], locale)
            self.assertIn(expected.encode(), [r[1] for r in d.lookup(index, [raw], locale, key.encode())])
            stats = receipt['locales'][locale]
            self.assertEqual(sum(stats['drops'].values()) + row_count, stats['input_rows'])
        for name, raw in artifacts.items():
            self.assertEqual(receipt['artifacts'][name], dict(bytes=len(raw), sha256=d.p.digest(raw).hex()))


if __name__ == '__main__':
    unittest.main()
