# SPDX-License-Identifier: Apache-2.0
"""Public Spleen recipe: exact delivered tables and independent source controls."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOL = Path('tools/fonts/font_build.py')
BDF = Path('third_party/fonts/spleen/spleen-8x16.bdf')
GUI = Path('src/gui/font8x16.inc')
BOOT = Path('src/boot/boot_menu.asm')
MANAGER = Path('src/bootmgr/paos_bootmgr.asm')
CLOSURE = (TOOL, Path('tools/fonts/test_font_build.py'), BDF, GUI, BOOT, MANAGER,
           Path('third_party/fonts/spleen/SOURCE.md'), Path('third_party/fonts/spleen/LICENSE'),
           Path('third_party/fonts/THIRD_PARTY_NOTICES.md'), Path('THIRD_PARTY_NOTICES.md'))


class PublicSpleen(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='public-spleen-')
        self.addCleanup(self.tmp.cleanup)
        self.tree = Path(self.tmp.name) / 'source'
        self.tree.mkdir()
        # Real public inputs only; no private factory, Git metadata or credentials.
        for name in CLOSURE:
            if (ROOT / name).is_file():
                dst = self.tree / name
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, dst)

    def run_tool(self, *args, optimized=False):
        return subprocess.run([sys.executable, *(['-O'] if optimized else []),
                               str(self.tree / TOOL), *map(str, args)],
                              cwd=self.tmp.name, capture_output=True, timeout=15)

    def emit(self, name='out'):
        out = Path(self.tmp.name) / name
        p = self.run_tool('--emit', out)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        return out

    def refused(self, *args):
        p = self.run_tool(*args)
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn(b'Traceback', p.stderr)
        self.assertIn(b'font_build:', p.stderr + p.stdout)
        return p

    def test_public_entry_point_delivered(self):
        self.assertTrue((self.tree / TOOL).is_file(), 'public converter missing')
        self.assertFalse((self.tree / 'gauntlet_v2').exists())

    def test_check_from_unrelated_directory(self):
        p = self.run_tool('--check')
        self.assertEqual(p.returncode, 0, p.stderr.decode())

    def test_check_optimized(self):
        p = self.run_tool('--check', optimized=True)
        self.assertEqual(p.returncode, 0, p.stderr.decode())

    def test_gui_exact_current_bytes(self):
        out = self.emit()
        self.assertEqual((out / 'font8x16.inc').read_bytes(), (ROOT / GUI).read_bytes())
        self.assertEqual(hashlib.sha256((out / 'font8x16.inc').read_bytes()).hexdigest(),
                         '9e34992016ddb093b51b018da14e73dd4ebdd37e937d6b04a14a9175db84dd48')

    def test_two_clean_emits(self):
        a, b = self.emit('a'), self.emit('b')
        self.assertEqual(sorted(p.name for p in a.iterdir()), ['bootmenu.inc', 'font8x16.inc', 'manager.inc'])
        for p in a.iterdir():
            self.assertEqual(p.read_bytes(), (b / p.name).read_bytes())
            self.assertNotIn(b'\r', p.read_bytes())

    def test_faces_exact_current_rows(self):
        out = self.emit()
        for file, label, result, count in ((BOOT, 'bm_face_ocr_font:', 'bootmenu.inc', 22),
                                           (MANAGER, 'face_ocr_font:', 'manager.inc', 128)):
            text = (ROOT / file).read_text().split(label+'\n', 1)[1]
            rows = []
            for line in text.splitlines():
                if not re.fullmatch(r'\s*db .* ; U\+[0-9a-f]{4}', line):
                    break
                rows.append(line.strip())
            self.assertEqual(len(rows), count)
            self.assertEqual(rows, [l.strip() for l in (out / result).read_text().splitlines()])

    def test_independent_bdf_cells(self):
        # The pinned source uses full 8x16 cells. Decode separately, without converter imports.
        blocks = (ROOT / BDF).read_text().split('STARTCHAR ')[1:]
        cells = {}
        for block in blocks:
            cp = int(re.search(r'^ENCODING (\d+)$', block, re.M)[1])
            self.assertIn('BBX 8 16 0 -4\n', block)
            bitmap = block.split('BITMAP\n', 1)[1].split('ENDCHAR', 1)[0]
            cells[cp] = bytes.fromhex(bitmap)
        out = self.emit()
        lines = (out / 'font8x16.inc').read_text().splitlines()
        rows = [bytes(int(h, 16) for h in re.findall(r'0x([0-9A-F]{2})', l.split(';')[0]))
                for l in lines if l.strip().startswith('db ')]
        self.assertEqual(len(rows), 352)
        for index, cp in enumerate([*range(128), *range(0xa0, 0x180)]):
            self.assertEqual(rows[index], cells[cp] if cp >= 0x20 else bytes(16), hex(cp))
        self.assertIn('    times 32 * 16 db 0                  ; U+0080..U+009F: blank C1 cells', lines)
        self.assertIn('font_8x16_ext_a:', lines)
        self.assertIn('font_8x16:', lines)
        self.assertEqual(lines.index('font_8x16_ext_a:') - lines.index('font_8x16:'), 226)

    def test_pin_mismatch_creates_no_output(self):
        path = self.tree / BDF
        path.write_bytes(path.read_bytes() + b'\n')
        out = Path(self.tmp.name) / 'out'
        p = self.refused('--emit', out)
        self.assertIn(b'not the pinned Spleen', p.stderr)
        self.assertFalse(out.exists())

    def test_malformed_refused_without_output(self):
        (self.tree / BDF).write_bytes(b'STARTFONT 2.1\nSTARTCHAR broken\nBITMAP\nZZ\n')
        out = Path(self.tmp.name) / 'out'
        self.refused('--emit', out)
        self.assertFalse(out.exists())

    def test_missing_source_refused(self):
        (self.tree / BDF).unlink()
        self.refused('--check')

    def test_gui_drift_refused_without_rewrite(self):
        p = self.tree / GUI
        bad = p.read_bytes().replace(b'0x00', b'0x01', 1)
        p.write_bytes(bad)
        self.refused('--check')
        self.assertEqual(p.read_bytes(), bad)

    def test_boot_drift_refused(self):
        p = self.tree / BOOT
        text = p.read_text(); before, after = text.split('bm_face_ocr_font:\n', 1)
        p.write_text(before + 'bm_face_ocr_font:\n' + after.replace('0x00', '0x01', 1))
        self.refused('--check')

    def test_manager_drift_refused(self):
        p = self.tree / MANAGER
        text = p.read_text(); before, after = text.split('face_ocr_font:\n', 1)
        p.write_text(before + 'face_ocr_font:\n' + after.replace('0x00', '0x01', 1))
        self.refused('--check')

    def test_missing_label_refused(self):
        p = self.tree / MANAGER
        p.write_text(p.read_text().replace('face_ocr_font:', 'removed_face:'))
        self.refused('--check')

    def test_explicit_bdf(self):
        other = Path(self.tmp.name) / 'input.bdf'
        shutil.copyfile(self.tree / BDF, other)
        p = self.run_tool('--bdf', other, '--check')
        self.assertEqual(p.returncode, 0, p.stderr.decode())

    def test_public_recipe_and_required_closure(self):
        recipe = (self.tree / 'third_party/fonts/spleen/SOURCE.md').read_text()
        self.assertIn('python3 tools/fonts/font_build.py --check', recipe)
        self.assertIn('python3 tools/fonts/font_build.py --emit', recipe)
        sys.path.insert(0, str(ROOT / 'tools/release'))
        import rc_source_export as export
        for name in CLOSURE:
            self.assertTrue(export.allowed(name.as_posix()), name)
            self.assertIn(name.as_posix(), export.REQUIRED)


if __name__ == '__main__':
    unittest.main()
