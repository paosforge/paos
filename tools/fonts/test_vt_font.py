# SPDX-License-Identifier: Apache-2.0
"""Public Terminal glyph recipe: exact cells and refusal controls, no host font inputs."""
import gzip
import hashlib
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOL = Path('tools/fonts/gen_vt_font.py')
FONT = Path('src/gui/vt/vt_font.inc')
INPUT = Path('third_party/fonts/terminal')
SOURCES = ('Uni2-Terminus16.psf.gz', 'Uni2-TerminusBold16.psf.gz', 'vt-unifont.hex', 'coverage.json')
DOCUMENTS = ('SOURCE.md', 'Terminus.NOTICE', 'Unifont.COPYING', 'OFL-1.1.txt', 'NOTICE.md')
CLOSURE = (TOOL, Path('tools/fonts/test_vt_font.py'), FONT,
           *(INPUT / n for n in (*SOURCES, *DOCUMENTS)))
EXPECTED = 'e3716cefd014aee251378756ad13730346422d63228fdd5741549406804932a1'


class PublicTerminal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='public-terminal-')
        self.addCleanup(self.tmp.cleanup)
        self.tree = Path(self.tmp.name) / 'source'
        self.tree.mkdir()
        for name in CLOSURE:
            if (ROOT / name).is_file():
                dst = self.tree / name
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, dst)

    def run_tool(self, *args, optimized=False):
        return subprocess.run([sys.executable, '-I', '-S', '-B', *(['-O'] if optimized else []),
                               str(self.tree / TOOL), *map(str, args)],
                              cwd=self.tmp.name, capture_output=True, timeout=15)

    def emit(self, name='out'):
        out = Path(self.tmp.name) / name
        p = self.run_tool('--emit', out)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        return (out / 'vt_font.inc').read_bytes()

    def refused(self, *args):
        p = self.run_tool(*args)
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn(b'Traceback', p.stderr)
        self.assertIn(b'gen_vt_font:', p.stderr)
        return p

    def test_public_entry_point_delivered(self):
        self.assertTrue((self.tree / TOOL).is_file(), 'public Terminal converter missing')
        self.assertFalse((self.tree / 'gauntlet_v2').exists())

    def test_exact_current_bytes(self):
        data = self.emit()
        self.assertEqual(data, (ROOT / FONT).read_bytes())
        self.assertEqual(hashlib.sha256(data).hexdigest(), EXPECTED)
        self.assertNotIn(b'\r', data)

    def test_two_clean_emits(self):
        self.assertEqual(self.emit('a'), self.emit('b'))

    def test_check_from_unrelated_directory(self):
        p = self.run_tool('--check')
        self.assertEqual(p.returncode, 0, p.stderr.decode())

    def test_optimized_check(self):
        p = self.run_tool('--check', optimized=True)
        self.assertEqual(p.returncode, 0, p.stderr.decode())

    def test_stdout_compatibility(self):
        p = self.run_tool()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertEqual(p.stdout, (ROOT / FONT).read_bytes())

    def test_counts_and_source_cells_independently(self):
        # Decode source PSF mappings independently; compare every regular/bold/wide/mark cell.
        def psf(name):
            data = gzip.decompress((self.tree / INPUT / name).read_bytes())
            count = 512 if data[2] & 1 else 256
            self.assertEqual(data[3], 16)
            glyphs = [data[4+i*16:20+i*16] for i in range(count)]
            result = {}
            table=data[4+count*16:]
            words=struct.unpack('<'+'H'*(len(table)//2),table)
            i=0; sequence=False
            for cp in words:
                if cp==0xffff:
                    i+=1; sequence=False
                elif cp==0xfffe:
                    sequence=True
                elif not sequence:
                    result.setdefault(cp,glyphs[i])
            return result
        term = psf(SOURCES[0]); bold = psf(SOURCES[1])
        uni = {int(k,16):bytes.fromhex(v) for k,v in
               (line.split(':') for line in (self.tree / INPUT / SOURCES[2]).read_text().splitlines())}
        text = self.emit().decode()
        def table(label, next_label):
            section = text.split(label+':',1)[1].split(next_label,1)[0]
            return [bytes(int(h,16) for h in re.findall(r'0x([0-9a-f]{2})',l.split(';')[0]))
                    for l in section.splitlines() if l.strip().startswith('db ')]
        cps = [int(h,16) for h in re.findall('0x([0-9a-f]+)',text.split('vt_font_cps:\n',1)[1].split('vt_font_glyphs:',1)[0])]
        rows = table('vt_font_glyphs','align 4')
        self.assertEqual(len(cps),3452); self.assertEqual(len(rows),3452)
        counts = {'terminus':0,'unifont':0,'procedural':0}
        for cp,row in zip(cps,rows):
            if 0x2580 <= cp <= 0x259f or 0x2800 <= cp <= 0x28ff:
                counts['procedural'] += 1
                continue
            origin = 'terminus' if cp in term else 'unifont'; counts[origin] += 1
            expected=term[cp] if origin=='terminus' else uni[cp]
            if len(expected)==32:
                expected=bytes(sum((bool(int.from_bytes(expected[y:y+2],'big') & (3 << (14-2*x)))) << (7-x) for x in range(8)) for y in range(0,32,2))
            self.assertEqual(row,expected,hex(cp))
        self.assertEqual(counts,{'terminus':765,'unifont':2399,'procedural':288})
        cells=dict(zip(cps,rows))
        self.assertEqual(cells[0x2588],bytes([255])*16)
        self.assertEqual(cells[0x2800],bytes(16))
        self.assertEqual(cells[0x2801],bytes([0,96,96]+[0]*13))
        bcps = [int(h,16) for h in re.findall('0x([0-9a-f]+)',text.split('vt_font_bold_cps:\n',1)[1].split('vt_font_bold_glyphs:',1)[0])]
        self.assertEqual(len(bcps),476)
        self.assertEqual(table('vt_font_bold_glyphs','align 4'),[bold[c] for c in bcps])
        wide = table('vt_font_wide_glyphs','align 4'); self.assertEqual(len(wide),41)
        wcps = [int(h,16) for h in re.findall('0x([0-9a-f]+)',text.split('vt_font_wide_cps:\n',1)[1].split('vt_font_wide_glyphs:',1)[0])]
        self.assertEqual(wide,[uni[c] for c in wcps])
        marks = list(range(0x300,0x30d))+[0x327,0x328,0x3099,0x309a]
        self.assertEqual(table('vt_font_mark_glyphs','not-present'),[uni[c].ljust(32,b'\0') for c in marks])
        # No unused Unifont input cells are delivered.
        self.assertEqual(set(uni),{cp for cp in cps if cp not in term and cp not in range(0x2580,0x25a0) and cp not in range(0x2800,0x2900)}|set(wcps)|set(marks))

    def test_missing_sources(self):
        for name in SOURCES:
            with self.subTest(name=name):
                p=self.tree/INPUT/name; original=p.read_bytes(); p.unlink()
                out=Path(self.tmp.name)/'out'
                self.refused('--emit',out); self.assertFalse(out.exists())
                p.write_bytes(original)

    def test_corrupt_sources(self):
        for name in SOURCES:
            with self.subTest(name=name):
                p=self.tree/INPUT/name; original=p.read_bytes(); p.write_bytes(original+b'\n')
                out=Path(self.tmp.name)/'out'
                self.refused('--emit',out); self.assertFalse(out.exists())
                p.write_bytes(original)

    def test_exact_source_bytes_even_when_glyphs_unchanged(self):
        # Gzip mtime and hex letter case do not affect cells, but do change custody.
        for name in SOURCES[:3]:
            with self.subTest(name=name):
                path = self.tree / INPUT / name
                original = path.read_bytes()
                if name.endswith('.gz'):
                    bad = bytearray(original)
                    bad[4] ^= 1
                    bad = bytes(bad)
                else:
                    bad = original.lower()
                self.assertNotEqual(bad, original)
                path.write_bytes(bad)
                out = Path(self.tmp.name) / 'out'
                self.refused('--emit', out)
                self.assertFalse(out.exists())
                path.write_bytes(original)

    def test_no_host_unicode_database_needed(self):
        tool = str(self.tree / TOOL)
        script = ("import sys,runpy; sys.modules['unicodedata']=None; "
                  "sys.argv=[sys.argv[1],'--check']; runpy.run_path(sys.argv[0],run_name='__main__')")
        p = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script, tool],
                           cwd=self.tmp.name, capture_output=True, timeout=15)
        self.assertEqual(p.returncode, 0, p.stderr.decode())

    def test_missing_grants_and_recipe(self):
        for name in DOCUMENTS:
            with self.subTest(name=name):
                p=self.tree/INPUT/name; original=p.read_bytes(); p.unlink()
                out=Path(self.tmp.name)/'out'
                self.refused('--emit',out); self.assertFalse(out.exists()); p.write_bytes(original)

    def test_corrupt_grants_and_recipe(self):
        for name in DOCUMENTS:
            with self.subTest(name=name):
                p=self.tree/INPUT/name; original=p.read_bytes(); p.write_bytes(original+b'\n')
                out=Path(self.tmp.name)/'out'
                self.refused('--emit',out); self.assertFalse(out.exists()); p.write_bytes(original)

    def test_file_escape(self):
        p=self.tree/INPUT/SOURCES[0]; outside=Path(self.tmp.name)/'external.psf.gz'
        p.rename(outside); p.symlink_to(outside)
        out=Path(self.tmp.name)/'out'
        self.refused('--emit',out); self.assertFalse(out.exists())

    def test_parent_escape(self):
        p=self.tree/INPUT; outside=Path(self.tmp.name)/'external-inputs'
        p.rename(outside); p.symlink_to(outside,target_is_directory=True)
        out=Path(self.tmp.name)/'out'
        self.refused('--emit',out); self.assertFalse(out.exists())

    def test_checked_output_escape(self):
        p=self.tree/FONT; outside=Path(self.tmp.name)/'external-font'
        p.rename(outside); p.symlink_to(outside)
        self.refused('--check')

    def test_drift_refused_without_rewrite(self):
        p=self.tree/FONT; bad=p.read_bytes().replace(b'0x00',b'0x01',1); p.write_bytes(bad)
        self.refused('--check'); self.assertEqual(p.read_bytes(),bad)

    def test_recipe_and_required_closure(self):
        recipe=(self.tree/INPUT/'SOURCE.md').read_text()
        self.assertIn('python3 tools/fonts/gen_vt_font.py --check',recipe)
        self.assertIn('python3 tools/fonts/gen_vt_font.py --emit',recipe)
        sys.path.insert(0,str(ROOT/'tools/release'))
        import rc_source_export as export
        for path in CLOSURE:
            self.assertTrue(export.allowed(path.as_posix()),path)
            self.assertIn(path.as_posix(),export.REQUIRED)


if __name__ == '__main__':
    unittest.main()
