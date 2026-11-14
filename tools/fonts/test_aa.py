# SPDX-License-Identifier: Apache-2.0
"""Independent glyph/source, grayscale geometry, native KAT and admission controls."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
TOOL = Path('tools/fonts/gen_aa.py')
INPUT = Path('third_party/fonts/dejavu')
FONT = Path('src/gui/font_aa9x19.inc')
ASM = Path('src/gui/font_aa.asm')
EXPECTED = '099427b2e8688fa303eb5a4366e50396b012fdf062b2a5009b688311816c0958'
CELL_HASHES = ['41c77c1739e8ed68f37930c031f36cba4618b62ac737e92584490a5df9fd10d4', '4d8a12557adebe95f547a1a2107c9a8ef3a26e7b042015fe2db09acab5dbeaa0', 'ec235f01817360ef863f585ca9fea38324a1c70776852d8e9a0815c148ed7d81', '6711b76602641c79a0f75b4bb4ac581b46a7968a8303f4b912d2b60e006e55ad', '22541279dee26f824bac5268666c41ec95094fe3c136a4f95fbc3698ddce42da', 'ee7b9a5fbea05f06829ae993797f212161a0f60b7f301787e28f24c5a335de92', 'a7e4c1445e2c7eee6b0cb8a7faa6e66e126171d72f5e7f469cbfe7a681a87e6c', '0667439895d891a6fdf86b80d4c852bc04c4e53f9053d74af09c1dd60eb8c289', '0e146a51c08f3f6ee4d11629d9122f7e4c69f7768e3691203164c2a7ab7d9c2b', '042b09ae90f254332db5f50443406977ea324f5e82127f91ab60f2f686b4fbb0', 'c6612454992bd0e354caff15b615693175e7adc3c00481b0552f1b9487696128', 'f85395445da3cb4d8e45afcb9e2305b1df918c1f9a0b3c2259ede6b60eded04c', '8b18e65937b0a2f1de0362caacd16e2e39a5cb6912aba8ab6c06e4711e06b237', '13aed2e1e1f9b01f355756ccd78bb04702b7ac59a599eb55213373d730b02bd6', '93458dec363015236054428d231db608247aae4acad9bb4c4be4427cc814e9d0', 'e5843b0368ae0052a5f72fa04ac0ca1d446a32fd94586a981126e563d6b9dc3e', 'f47c3e3c2018c1aef0cc42425ed493aeb4c141092da302578592cfd594f96ab2', 'bd2f2176206a44358d1f53d802ef368d4e8c0bb34440ec4772987e5ba478a960', '65091727bf7f9f8a2eb5bc285d61c83345edeac48c26ed85d944cec059b890f6', 'd5d6eed8bbcedfcbe64361d19d71c14459a33ec06eead2368ad120ba5d8ad7c4', 'e3cc5d37358721cd5739d38337af3d06e6a7d408e71a8699cf06bb874a4df1b2', 'ccb71324a5b902c8ae49e92388ffec3d00a37ce4fda7ceef6493d9b143e7e8e6', 'd19b54b8ef4043096c24f1479c2186923838830450319f51a94508984843f9c2', '7b48bcacdb2ba7bce65a4b522e910e2ac99a09d924652489ca82a81623d60db4', '1588595065f20e92fc7be716bbaab6f2493889babd1d6d853b840e3a75f61275', 'e0a9041ba029345f65f0a5a12673aa918c43389687bf8c11f259ae97103f4924', '39dbbfd7cb2216f5bb7c0533261f991082d17b0ae466ac3a0bd63a5536a16df7', 'afd70a0c43b4cd930b4374460c3ad547c7f58583685e9a4f888b4d1642a23b09', '5e24eadf40b83389db76d337f7bb05b9dbf9ce8d6b8904990a1d10acbe809bf5', 'f7ed8eb6d09ed2aa2cbca815123669ca22eb1b2b8f8ed763b2cd2b196ffe6a53', '2b26c8032555dcb21940b0b2ad793a1ee941c32e7129f426c82a8fd542a6b24c', 'f01eff6834f37dc2e3e9cccc135db951ad17366a334cb5b4745485c5c29a0f0d', 'dc64a594b23158eebe6143f6072c47f9c28fd7318ba0fe2be7eb0f0131def755', '5a0c74ea35c220baceb158e4623c58ac1ef8ef9a1a00d41216a506b487e3dba1', '8fca6e5b7f0ed906e6139f20675726b7bf3ce3d9f3135e797307c7a48c034f13', 'a2e3b495272580c8e670fa4716a59ed0276dcb81ff0ebee16a517ee988969ffa', 'e3d4a22c3a2103c4ec2f68c8447874c4f9a2161093dd2eda0a3c91f7cde26de0', '4c95e95be9aba9883dfcea382f307904bba03dab20e978a7bcff19c6baf3fee9', 'fc8a662d21e27a6bf0499edc30aec78935abcbcac38c99698af26043c0d7123e', '3cd432d256a25481619b01317b9fdf7597c0ad6913ed33b062968691798e6a08', 'c31c70cde146fb56f2d3f4b5671129ffd196a8c076cd37c4ca9cee448cfb15c1', '62ce4d753ed3dfa346973f87df9fe8701f8f3f2c62994047cd83bac075a2e454', '043a6185dc8f11efe2cf58275cc62a08b1260213a1ca66dce00fd61f57ce86c7', '48b0561232449cf98880b653d99edebfb97d88e0d8aa12571698a89db542be31', '6a3f282e737b7097ddca494d9b7141ab6a921f11f293f2156a2a47fe9bbb79c1', '35fdb8e556d820759d2b5071c26975c3e01b853699642d9b59668e61e852cece', '964d4fbdf0150ab47ce26f2880edafa31e95261415987b94fb4137551d3d0e34', '165769d93b454452fdcb1d9c467394e8f7771e736f11c37b94abacabd57bf5bf', '5156381f1a3434c6ea95f862a8b2bfe5b33961600a640a32990c673b5fa5aa21', '388ab53aa116288c7c34add2f5f694cb487d992454b8af2db67af2356fe3fe68', '2fc58eb27696220cfa3069ab8b3b0d806d528059f0c63af122c5afa7203750b4', 'dc1eeb13e6a61ada739971d871afffe175fd34fa67ba8e41301ac571eba701e9', 'f5264db2472fb9189b30863ccf13fadca89d44080c7e3d66fbafaf24b1de13d0', 'e42ea8c49ccd75b7388e9d3562d983316b75bfa835911df691567591a1745920', '89d9abb7725477b5096986a038349e388a8d1b77b568c1d90900d863c68dcc31', 'f035a8b96878b916ab32fab0ec43418ccaba58c5832dbf015039624a03058ab2', 'bade3e55c7cb1377a61361363dfd4b66590ff07a76f9a10f940c35a4f5f80ddf', 'a38f803c0a0117b6248982c1fe665f6f117dae440ac95b12e9c6b7f46ef6cc75', '64ff713fb43780b3abf1957247900d7bdf0a59122b6dade15ee3873ee7dc2e14', '797080bcd2ed8c40d650e231bc138fb6a8c76e86e8a6869076ed374bf01919a6', '92bef90cc49e7f808f5a5c8411a9c0d28dcf490eab95d9aef25e179c43045f23', '45eea8304240a502e1046ed170463952a430923aa9a9367adb44e293a254f806', 'ce3ad4666ec5f5c6e19e76a2ba547a338bbcbf54a276739d209475e88ac44ff2', '80c7acfbafdc6cf12276d97b3ea56ccb57cb037695e2f72d78bce2add2a7ed58', '1e4b37886ab2ec1bafa9af6029b65694f89d558f4bfc5c4004ed4ca8481202cc', '8d12c134345b9203e1c6aca4b9c86dd8169e358732cb81952d18154bca94f806', 'af9197d301ec211f7d3c7f83916be42359567c896e84e39855997e1b97d59d8e', '3241432e30658cc22f03abdccb9a036c73a13fe440f88ff17449ed4029dda131', 'ad51937361df69e5e4d0360bb2bbfc6a66ef94fa44c630a4c9661e7d004b449d', '8ec59a3a3a91a129a9b7cdf8abcfa573435c2b3cca8acaa415b9a6c8e0d9a293', '215c4193362de1e646c81e543a971f03ffbf5323d301da24c599c8a669d4a18e', 'afe38187fa827f1453285585ab995c49e55a1774d26082b0c9e04c3000e574b5', 'f938c73d46a57016c3d529023f8d5e52b3d1354c0db5ace67d9241787a941fe8', '2bdfef24534e73485611f4713d15a0103b65291e6210d554c9511db8cf5b98f3', 'b6ad3a0f8e59924425ae82f660e48e578c301cdbd0797167008a1c474c944e46', '896e3ebbb0357ecd92bd82bcad9e577b9433342047b4ddd8a8cffc536e39c777', '82d981fd3e60d98d43319678ee4101a60a07ca95ee18e6cc63a1c8d80fdf3aea', '96128e3947366e15726ebcc6dc55b4415eb40e4f565e04219cb618b53c6c215b', '1a68ff61ecacdbdf541b1f7bd39f6f3bc444f0d1fd5a55c9c9d70644d3a6517f', 'cea511ebd34cacb08dcc9b7b5efd7bfc71c1a047efcc563bac393a43ee385c04', '4e975a96b6261a5daf39be3cb1975043ad1a1d94a912a23313661d9d1cdfbcb6', 'f66e9bee3faf816ba311e9d9c19a5cbb996e06eb078422819e31f4b6e1aa3700', 'ebf02d59ce2542c7d760b67f5c80210b978fda20100668f0e2fd46474db0c72e', 'f849815936de490c1d1097132c297a874ec0acbb351544272c8790e5cb0f65f2', '1a722a492af6cc01fc1e9c53a37e8d1a67f763e22060153727d443808bd17e6b', '84af6aa524c6cfaa25376ac46a5353306f5036fda963d7660f54e414fa947f13', 'fd83fb322398ea12f08976d81a9f2805fe017ed5b26d9c8ea954bb3fa7e95f2c', '54bbed6b91b876255bb9571092be6d6cff97d24de8d646308c718cae8c7c113c', '469680bed0e7a95d615db60167d8e9a66484583a079a8a3e9d382b4dd0364577', '70c314baca71c505184057cb4d2f276cd95a0b04b6360ec1674016220f793e09', 'c91005bec84a9c4debf2f74237877a8a956e944db3e6ee629820ce17af666e6a', 'd91f763e09ff91d517f34e2882e567842b364957cafa47c805275877957e2e25', '69152376955e19eadebfeb75eb3c9ef35ec88f41c3888dac42a1004cb3a277b3', 'ecf3fb7a72cf05b64aac123780d9023cfacf1c6e8dd9ad3f25b7e6344be26a7e', '77634b77330c8355316b778a6ccb1617d55ba4882d845a16d7f37b3daca89cae']
CLOSURE = (TOOL, Path('tools/fonts/raster_aa.c'), Path('tools/fonts/test_aa.py'), FONT, ASM,
           Path('LICENSE'), *(p.relative_to(ROOT) for p in sorted((ROOT / INPUT).rglob('*')) if p.is_file()))


def load(root=ROOT):
    spec = importlib.util.spec_from_file_location('public_aa', root / TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.ROOT = root
    return mod


def table(data, tag):
    count = struct.unpack_from('>H', data, 4)[0]
    for i in range(count):
        pos = 12 + i * 16
        if data[pos:pos + 4] == tag:
            off, length = struct.unpack_from('>II', data, pos + 8)
            return data[off:off + length]
    raise AssertionError('missing TTF table ' + repr(tag))


def cmap(data):
    # Independent Unicode format-12 parser: no FreeType or production helpers.
    cm = table(data, b'cmap')
    for i in range(struct.unpack_from('>H', cm, 2)[0]):
        platform, encoding, off = struct.unpack_from('>HHI', cm, 4 + i * 8)
        if (platform, encoding) == (3, 10):
            if struct.unpack_from('>H', cm, off)[0] != 12:
                raise AssertionError('format12 required')
            count = struct.unpack_from('>I', cm, off + 12)[0]
            result = {}
            for j in range(count):
                first, last, gid = struct.unpack_from('>III', cm, off + 16 + j * 12)
                for cp in range(max(first, 32), min(last, 126) + 1):
                    result[cp] = gid + cp - first
            return result
    raise AssertionError('Unicode cmap missing')


class PublicAA(unittest.TestCase):
    def test_public_entry_point(self):
        self.assertTrue((ROOT / TOOL).is_file(), 'public AA recipe missing')
        self.assertTrue((ROOT / INPUT / 'SOURCES.json').is_file())

    def test_all_required_inputs_admitted(self):
        m = load()
        manifest = json.loads((ROOT / INPUT / 'SOURCES.json').read_bytes())
        self.assertEqual(set(m.inputs()), set(manifest['files']))
        self.assertTrue({'tools/fonts/raster_aa.c', str(INPUT / 'LICENSE'), str(INPUT / 'SOURCE.md'),
                         str(INPUT / 'DejaVuSansMono.sfd'), str(INPUT / 'DejaVuSansMono.ttf'),
                         str(INPUT / 'FreeType-FTL.txt'), str(INPUT / 'FreeType-LICENSE.txt'),
                         str(INPUT / 'freetype-2.14.1.tar.xz')} <= set(manifest['files']))

    def test_every_source_license_recipe_hash_and_omission(self):
        m = load()
        names = [str(INPUT / 'SOURCES.json'), *m.inputs()]
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                for src in names:
                    dst = root / src
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / src, dst)
                target = root / name
                original = target.read_bytes()
                target.unlink()
                with mock.patch.object(m, 'ROOT', root), self.assertRaisesRegex(ValueError, 'missing source/license/recipe'):
                    m.inputs()
                target.write_bytes(original + b'corrupt')
                with mock.patch.object(m, 'ROOT', root), self.assertRaisesRegex(ValueError, 'hash'):
                    m.inputs()

    def test_versions_enforced_beyond_manifest_hash(self):
        m = load()
        original = m.admitted
        for key in ('schema', 'font_version', 'freetype_version'):
            value = json.loads((ROOT / INPUT / 'SOURCES.json').read_bytes())
            value[key] = 'wrong-version'
            def read(name, pin):
                return json.dumps(value).encode() if name.endswith('SOURCES.json') else original(name, pin)
            with self.subTest(key=key), mock.patch.object(m, 'admitted', side_effect=read), self.assertRaisesRegex(ValueError, 'version'):
                m.inputs()

    def test_required_recipe_and_grant_omissions(self):
        m = load()
        original = m.admitted
        source = json.loads((ROOT / INPUT / 'SOURCES.json').read_bytes())
        for name in source['files']:
            value = json.loads(json.dumps(source))
            del value['files'][name]
            def read(path, pin):
                return json.dumps(value).encode() if path.endswith('SOURCES.json') else original(path, pin)
            with self.subTest(name=name), mock.patch.object(m, 'admitted', side_effect=read), self.assertRaisesRegex(ValueError, 'omission'):
                m.inputs()

    def test_symlink_source_and_parent(self):
        m = load()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'font').symlink_to(ROOT / INPUT / 'DejaVuSansMono.ttf')
            (root / 'linked').symlink_to(ROOT / INPUT, target_is_directory=True)
            with mock.patch.object(m, 'ROOT', root):
                for name in ('font', 'linked/DejaVuSansMono.ttf', '../font', '/font'):
                    with self.subTest(name=name), self.assertRaises(ValueError): m.local(name)

    def test_output_no_existing_or_linked_directory(self):
        m = load()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'dest').mkdir()
            (root / 'link').symlink_to(root / 'dest', target_is_directory=True)
            for p in (root / 'dest', root / 'link/out'):
                with self.subTest(path=p), self.assertRaises(ValueError): m.emit(p, b'abc')
            self.assertEqual(list((root / 'dest').iterdir()), [])

    def test_coverage_length_refused(self):
        m = load()
        for n in (0, 171, 16244, 16246):
            with self.subTest(n=n), self.assertRaises(ValueError): m.serialize(bytes(n))

    def test_rasterizer_output_count_checked(self):
        # Real admission, no external program runs in this one control.
        m = load()
        original = m.command
        def run(argv, cwd, env):
            if str(argv[0]).endswith('/raster'): return b'bad'
            return b''
        with mock.patch.object(m, 'command', side_effect=run), self.assertRaisesRegex(ValueError, 'coverage count'):
            m.raster(m.inputs())

    def test_upstream_preferred_source_ascii(self):
        source = (ROOT / INPUT / 'DejaVuSansMono.sfd').read_text()
        self.assertIn('Version: 2.37\n', source)
        found = {}
        for block in source.split('StartChar: ')[1:]:
            match = re.search(r'^Encoding: (-?\d+) (-?\d+) (-?\d+)$', block, re.M)
            if match and 32 <= int(match[2]) <= 126:
                cp = int(match[2])
                self.assertNotIn(cp, found)
                self.assertIn('Width: 1233\n', block)
                found[cp] = block.splitlines()[0]
        self.assertEqual(set(found), set(range(32, 127)))
        self.assertEqual([found[x] for x in (32, 63, 65, 103)], ['space', 'question', 'A', 'g'])

    def test_ttf_unicode_origin_and_metrics(self):
        data = (ROOT / INPUT / 'DejaVuSansMono.ttf').read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), 'c805f9436dbc268644c1d9584f01a601a653e028e08fd74b9b949f6cf8304d88')
        mapping = cmap(data)
        self.assertEqual(mapping, {cp: cp - 29 for cp in range(32, 127)})
        self.assertEqual(struct.unpack_from('>H', table(data, b'head'), 18)[0], 2048)
        self.assertEqual(struct.unpack_from('>hhh', table(data, b'hhea'), 4), (1901, -483, 0))
        metrics = table(data, b'hmtx')
        count = struct.unpack_from('>H', table(data, b'hhea'), 34)[0]
        for cp, gid in mapping.items():
            self.assertEqual(struct.unpack_from('>H', metrics, min(gid, count - 1) * 4)[0], 1233, hex(cp))


class RenderedAA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load()
        # Do not use the production full-output hash guard as the semantic oracle.
        # All pixel/identity/layout expectations below are independently fixed.
        cls.coverage = cls.mod.raster(cls.mod.inputs())
        cls.result = cls.mod.serialize(cls.coverage)

    def test_all_95_glyph_identities_and_pixels(self):
        self.assertEqual(len(self.coverage), 16245)
        self.assertEqual(len(CELL_HASHES), 95)
        for i, expected in enumerate(CELL_HASHES):
            cell = self.coverage[i * 171:(i + 1) * 171]
            self.assertEqual(hashlib.sha256(cell).hexdigest(), expected, 'glyph ' + chr(32 + i))

    def test_geometry_baseline_and_partial_coverage(self):
        cells = [self.coverage[i * 171:(i + 1) * 171] for i in range(95)]
        self.assertEqual(cells[0], bytes(171))
        for cp, cell in zip(range(32, 127), cells):
            if cp != 32:
                self.assertTrue(any(cell), hex(cp))
                if cp != 95: self.assertTrue(any(0 < n < 255 for n in cell), hex(cp))
        def box(cp):
            ink = [(i % 9, i // 9) for i, n in enumerate(cells[cp - 32]) if n]
            return min(x for x,y in ink), min(y for x,y in ink), max(x for x,y in ink), max(y for x,y in ink)
        self.assertEqual(box(65), (0, 3, 8, 13))
        self.assertEqual(box(103), (0, 6, 7, 16))
        self.assertEqual(box(95), (0, 17, 8, 17))
        self.assertIn(b'cell 9x19, baseline 14, ASCII 32..126, 8-bit coverage.', self.result)
        self.assertEqual(len(re.findall(rb'^    ; +\d+ ', self.result, re.M)), 95)
        self.assertEqual(len(re.findall(rb'^    db ', self.result, re.M)), 95 * 19)

    def test_downstream_native_blended_A_kat(self):
        asm = (ROOT / ASM).read_text()
        golden = int(re.search(r'FAKAT_GOLDEN_FNV\s+equ\s+(0x[0-9A-F]+)', asm)[1], 16)
        self.assertEqual(golden, 0xE28477FE)
        h = 0x811C9DC5
        for alpha in self.coverage[(65 - 32) * 171:(66 - 32) * 171]:
            value = (255 * alpha + 12 * (255 - alpha) + 127) // 255
            for b in (value, value, value, 0): h = ((h ^ b) * 0x01000193) & 0xffffffff
        self.assertEqual(h, golden)
        self.assertIn("mov  eax, '?'", asm)
        self.assertIn('cmp  eax, FONT_AA_FIRST', asm)
        self.assertIn('cmp  eax, FONT_AA_LAST', asm)

    def test_exact_shipped_and_full_output_hash(self):
        self.assertEqual(self.result, (ROOT / FONT).read_bytes())
        self.assertEqual(hashlib.sha256(self.result).hexdigest(), EXPECTED)

    def test_final_output_hash_guard(self):
        with mock.patch.object(self.mod, 'raster', return_value=bytes(16245)), self.assertRaisesRegex(ValueError, 'original coverage/header'):
            self.mod.build()


if __name__ == '__main__': unittest.main()
