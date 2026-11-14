# SPDX-License-Identifier: Apache-2.0
"""Public recipe controls and independent table/source oracles."""
from array import array
import hashlib
import json
from pathlib import Path
import re
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOL = Path('tools/unicode/gen_unicode_tables.py')
INPUT = Path('third_party/unicode')
DATA = {
 'ucd-15.0.0': ('DerivedGeneralCategory.txt','EastAsianWidth.txt'),
 'ucd-15.1.0': ('DerivedCoreProperties.txt','DerivedGeneralCategory.txt','EastAsianWidth.txt',
                'GraphemeBreakProperty.txt','GraphemeBreakTest.txt','emoji-data.txt','unicode-license.txt'),
 'cldr-43': ('en-t-k0-windows.xml','es-t-k0-windows.xml','fr-t-k0-windows.xml','de-t-k0-windows.xml','unicode-license.txt')}
NOTICES = ('LICENSES/MPL-2.0.txt','LICENSES/Unicode-3.0.txt','LICENSES/Unicode-15.0.0-NOTICE.txt',
           'LICENSES/Unicode-15.1-DATA.txt','LICENSES/Unicode-DFS-2016.txt')
SOURCES = (INPUT/'SOURCES.json',INPUT/'SOURCE.md',*(INPUT/f/n for f,ns in DATA.items() for n in ns),*map(Path,NOTICES))
CLOSURE = (TOOL, *(Path('tools/unicode')/n for n in ('properties.py','keyboard.py','widths.py','test_unicode_tables.py')),
           *SOURCES,Path('src/core/unicode_edit.asm'),Path('src/core/keyboard_layout.asm'),Path('src/gui/vt/vt_tables.inc'))


def fields(text):
    """Independent source parser used by the scalar oracles, never converter code."""
    for row in text.splitlines():
        row = row.partition('#')[0].strip()
        if row:
            span,*values = map(str.strip,row.split(';'))
            bounds = [int(x,16) for x in span.split('..')]
            yield bounds[0],bounds[-1]+1,values


class UnicodeTables(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cache = tempfile.TemporaryDirectory(prefix='unicode-reference-')
        cls.addClassCleanup(cls.cache.cleanup)
        cls.reference = Path(cls.cache.name)/'out'
        if (ROOT/TOOL).is_file():
            p=subprocess.run([sys.executable,'-I','-S','-B',str(ROOT/TOOL),'--emit',str(cls.reference)],capture_output=True)
            cls.generation_error=p.stderr.decode()

    def setUp(self):
        if self._testMethodName in ('test_complete_independent_hashes','test_editor_complete_scalar_oracle','test_vt_complete_scalar_oracle','test_layout_independent_decode'):
            self.assertTrue(self.reference.is_dir(),getattr(self,'generation_error','public converter absent'))
        self.tmp=tempfile.TemporaryDirectory(prefix='public-unicode-');self.addCleanup(self.tmp.cleanup)
        self.tree=Path(self.tmp.name)/'source';self.tree.mkdir()
        for name in CLOSURE:
            if (ROOT/name).is_file():
                target=self.tree/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
        if (self.tree/TOOL).is_file():
            self.api=runpy.run_path(str(self.tree/TOOL))

    def call(self,*args,optimized=False):
        return subprocess.run([sys.executable,'-I','-S','-B',*(['-O'] if optimized else []),str(self.tree/TOOL),*map(str,args)],cwd=self.tmp.name,capture_output=True,timeout=30)

    def refuse(self,*args):
        p=self.call(*args);self.assertEqual(p.returncode,1,p.stderr.decode());self.assertNotIn(b'Traceback',p.stderr)
        self.assertIn(b'gen_unicode_tables:',p.stderr)

    def test_public_closure(self):
        for name in CLOSURE:self.assertTrue((self.tree/name).is_file(),str(name)+' public source missing')
        self.assertFalse((self.tree/'gauntlet_v2').exists())

    def test_export_requires_the_complete_recipe(self):
        sys.path.insert(0,str(ROOT/'tools/release'))
        import rc_source_export
        self.assertFalse({str(n) for n in CLOSURE}-rc_source_export.REQUIRED)
        self.assertTrue(all(rc_source_export.allowed(str(n)) for n in CLOSURE))

    def test_current_sections(self):
        p=self.call('--check');self.assertEqual(p.returncode,0,p.stderr.decode())
        p=self.call('--check',optimized=True);self.assertEqual(p.returncode,0,p.stderr.decode())

    def test_two_clean_builds(self):
        a=Path(self.tmp.name)/'a';b=Path(self.tmp.name)/'b'
        for out in (a,b):
            p=self.call('--emit',out);self.assertEqual(p.returncode,0,p.stderr.decode())
        self.assertEqual(sorted(x.name for x in a.iterdir()),sorted(x.name for x in b.iterdir()))
        for p in a.iterdir():self.assertEqual(p.read_bytes(),(b/p.name).read_bytes())

    def test_complete_independent_hashes(self):
        expected={'unicode_properties.inc':'539550d2e54067f913eb4f5054b0e543f49a5e38beecc77aa3280608be4de081',
                  'vt_tables.inc':'d3f0e950825306da1987e684726edf5346462b7f463406122c16316433d661dd',
                  'keyboard_layout.bin':'463f755de539c967b9712d2d9351acbbfa36baa1d8bc1efaa3ab22551d102f05',
                  'keyboard_layout_data.inc':'9fd74edd6655148120d77dd995108bc317bea8b4f3c4443fcbc70a8606de3b91',
                  'keyboard_layout_provenance.json':'07efac94b873ec2a9527951c992de762f879826825b4aceab32354cd38959613'}
        for name,pin in expected.items():self.assertEqual(hashlib.sha256((self.reference/name).read_bytes()).hexdigest(),pin,name)

    def test_all_inputs_and_grants_admitted_before_output(self):
        for name in SOURCES:
            path=self.tree/name;original=path.read_bytes()
            for kind in ('missing','corrupt'):
                with self.subTest(path=str(name),kind=kind):
                    if kind=='missing':path.unlink()
                    else:path.write_bytes(original+b'!')
                    with self.assertRaises((ValueError,OSError)):self.api['admit']()
                    path.write_bytes(original)
        path=self.tree/NOTICES[-1];path.unlink();out=Path(self.tmp.name)/'out'
        self.refuse('--emit',out);self.assertFalse(out.exists())

    def test_version_is_checked_independently_of_manifest_pin(self):
        path=self.tree/INPUT/'SOURCES.json';doc=json.loads(path.read_text());doc['families']['ucd-15.0.0']['version']='15.1.0'
        path.write_text(json.dumps(doc));self.api['admit'].__globals__['MANIFEST_SHA']=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError,'version'):self.api['admit']()

    def test_manifest_path_escape(self):
        path=self.tree/INPUT/'SOURCES.json';doc=json.loads(path.read_text());doc['notices']['../escape']='0'*64
        path.write_text(json.dumps(doc));self.api['admit'].__globals__['MANIFEST_SHA']=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError,'path escape'):self.api['admit']()

    def test_file_symlink_refused(self):
        path=self.tree/INPUT/'ucd-15.0.0/EastAsianWidth.txt';outside=Path(self.tmp.name)/'outside';path.rename(outside);path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError,'symlink'):self.api['admit']()

    def test_parent_symlink_refused(self):
        path=self.tree/INPUT/'ucd-15.0.0';outside=Path(self.tmp.name)/'outside';path.rename(outside);path.symlink_to(outside,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'symlink'):self.api['admit']()

    def test_output_escape_and_existing_output(self):
        outside=Path(self.tmp.name)/'outside';outside.mkdir();link=Path(self.tmp.name)/'link';link.symlink_to(outside,target_is_directory=True)
        self.refuse('--emit',link/'child');self.assertFalse((outside/'child').exists())
        self.refuse('--emit',outside);self.assertEqual(list(outside.iterdir()),[])

    def test_actual_shipped_corruption_refuses(self):
        for n in ('src/core/unicode_edit.asm','src/core/keyboard_layout.asm','src/gui/vt/vt_tables.inc'):
            path=self.tree/n;original=path.read_bytes()
            # Change an emitted cell inside each generated section, not an ignored code comment.
            where=original.index(b'    d', original.index(b'ue_properties:') if 'unicode_edit' in n else original.index(b'kbd_builtin_data:') if 'keyboard' in n else 0)
            raw=original[:where]+original[where:].replace(b'0x',b'0X',1);path.write_bytes(raw)
            self.refuse('--check');path.write_bytes(original)

    def test_width_samples_and_range_edges(self):
        m=runpy.run_path(str(self.tree/'tools/unicode/widths.py'));m['configure'](self.api['admit']()['ucd-15.0.0'])
        for cp,w in [(0xad,1),(0x301,0),(0x1160,0),(0x200b,0),(0x4e00,2),(0x378,1),(0xd800,1),(0x10ffff,1),(0xa1,1)]:
            self.assertEqual(m['width'](cp),w,hex(cp))
        # Force a synthetic true predicate on both sides of the surrogate gap:
        # the original ranges() skips the gap, preserving its inclusive bridge.
        class Synthetic:
            def category(self,ch):return 'Mn' if ord(ch) in (0xd7ff,0xe000) else 'Lo'
        m['ranges'].__globals__['unicodedata']=Synthetic()
        self.assertEqual(m['ranges']('marks'),[(0xd7ff,0xe000)])

    def test_xml_rejections_and_literal_dead_key(self):
        m=runpy.run_path(str(self.tree/'tools/unicode/keyboard.py'))
        for raw in (b'<!ENTITY a "x">',b'<!DOCTYPE keyboard SYSTEM "file:///bad"><keyboard/>',b'<keyboard/>'):
            with self.assertRaises(ValueError):m['parse'](raw)
        with self.assertRaises(ValueError):m['decode'](r'\u{D800}')
        raw=('<keyboard>'+''.join('<keyMap'+(' modifiers="'+mod+'"' if mod else '')+'><map iso="C01" to="^" transform="no"/></keyMap>' for mod in ('','shift','caps','caps+shift'))+'<transforms type="simple"><transform from="^a" to="&#226;"/></transforms></keyboard>').encode()
        blob,_=m['build']([raw]*4);ns,nc=struct.unpack_from('<HH',blob,12);at=32+4*ns+6+3*nc
        self.assertLess(blob[at+2],240)

    def test_editor_complete_scalar_oracle(self):
        n=0x110000;gcb=bytearray(n);incb=bytearray(n);ep=bytearray(n);width=bytearray([1])*n
        directory=ROOT/INPUT/'ucd-15.1.0'
        for lo,hi,p in fields((directory/'EastAsianWidth.txt').read_text()):
            if p[0] in ('W','F'):width[lo:hi]=bytes([2])*(hi-lo)
        for lo,hi,p in fields((directory/'DerivedGeneralCategory.txt').read_text()):
            if p[0] in ('Mn','Me','Cf'):width[lo:hi]=bytes(hi-lo)
        ids={'CR':1,'LF':2,'Control':3,'Extend':4,'ZWJ':5,'Regional_Indicator':6,'Prepend':7,'SpacingMark':8,'L':9,'V':10,'T':11,'LV':12,'LVT':13}
        for lo,hi,p in fields((directory/'GraphemeBreakProperty.txt').read_text()):
            if p[0] not in ('LV','LVT'):gcb[lo:hi]=bytes([ids[p[0]]])*(hi-lo)
        for lo,hi,p in fields((directory/'DerivedCoreProperties.txt').read_text()):
            if p[0]=='InCB':incb[lo:hi]=bytes([{'Consonant':1,'Extend':2,'Linker':3}[p[1]]])*(hi-lo)
        for lo,hi,p in fields((directory/'emoji-data.txt').read_text()):
            if p[0]=='Extended_Pictographic':ep[lo:hi]=bytes([1])*(hi-lo)
        values=[int(v,16) for v in re.findall(r'0x([0-9a-f]{8})',(self.reference/'unicode_properties.inc').read_text())]
        self.assertEqual(values[0]>>9,0);self.assertEqual(values[-1],n<<9)
        starts=[v>>9 for v in values];self.assertEqual(starts,sorted(set(starts)))
        actual=array('H',[0])*n
        for a,b in zip(values,values[1:]):actual[a>>9:b>>9]=array('H',[a&511])*((b>>9)-(a>>9))
        expected=array('H',(gcb[c]+16*ep[c]+32*width[c]+128*incb[c] for c in range(n)))
        self.assertEqual(actual,expected)
        for cp in (0x378,0xd800,0xdfff,0x10ffff):self.assertEqual(actual[cp],32)
        self.assertEqual(actual[0xac00]&15,0);self.assertEqual(actual[0x94d]>>7,3)
        self.assertEqual(len(values)*4,5400)

    def test_vt_complete_scalar_oracle(self):
        n=0x110000;cats=['Cn']*n;eaw=['N']*n;directory=ROOT/INPUT/'ucd-15.0.0'
        for name,target in [('DerivedGeneralCategory.txt',cats),('EastAsianWidth.txt',eaw)]:
            for lo,hi,p in fields((directory/name).read_text()):target[lo:hi]=[p[0]]*(hi-lo)
        text=(self.reference/'vt_tables.inc').read_text()
        for table in ('vt_width0','vt_width2','vt_marks'):
            body=text.split(table+':')[1].split('_count:')[0].splitlines()[1:]
            nums=[int(v,16) for v in re.findall(r'0x([0-9a-f]+)','\n'.join(body))]
            pairs=list(zip(nums[::2],nums[1::2]));actual=bytearray(n)
            self.assertEqual(pairs,sorted(pairs));self.assertTrue(all(a<=b and (i==0 or a>pairs[i-1][1]) for i,(a,b) in enumerate(pairs)))
            self.assertEqual(int(re.search(table+r'_count: dd (\d+)',text)[1]),len(pairs))
            for a,b in pairs:actual[a:b+1]=bytes([1])*(b-a+1)
            expected=bytearray(n)
            for cp in range(0x300,n):
                if 0xd800<=cp<=0xdfff:continue
                zero=cats[cp] in ('Mn','Me','Cf') or 0x1160<=cp<=0x11ff or cp==0x200b
                expected[cp]= cats[cp] in ('Mn','Me') if table=='vt_marks' else zero if table=='vt_width0' else not zero and eaw[cp] in ('W','F')
            # No generated surrogate entries in the pinned ranges.
            self.assertEqual(actual,expected,table)
        self.assertIn('0x25c6,0x2592,0x2409',text)

    def test_layout_independent_decode(self):
        blob=(self.reference/'keyboard_layout.bin').read_bytes();magic,size,version,count,nscalar,ncomp,*tail=struct.unpack('<II4H4HQ',blob[:32])
        self.assertEqual((magic,size,version,count),(0x31544c4b,2415,1,4));self.assertEqual(ncomp,51);self.assertEqual(tail[-1],0)
        scalars=struct.unpack('<%dI'%nscalar,blob[32:32+4*nscalar]);self.assertTrue(all(cp<0x110000 and not 0xd800<=cp<=0xdfff for cp in scalars))
        at=32+4*nscalar+6+3*ncomp;layouts=[]
        for rows in tail[:4]:
            rows=[tuple(blob[i:i+6]) for i in range(at,at+6*rows,6)];at+=6*len(rows);layouts.append({r[0]:r[1:] for r in rows})
            self.assertEqual([r[0] for r in rows],sorted(set(r[0] for r in rows)))
            self.assertTrue(all(r[1] in (0,1) and all(v<nscalar or 241<=v<=246 for v in r[2:]) for r in rows))
            self.assertEqual(next(r[1:] for r in rows if r[0]==0x31),next(r[1:] for r in rows if r[0]==0x32))
        self.assertEqual(at,len(blob))
        for layout,usage,value in [(0,0x14,'q'),(1,0x33,'ñ'),(2,0x14,'a'),(3,0x1d,'y')]:
            row=layouts[layout][usage];self.assertEqual(chr(scalars[row[1]]),value);self.assertEqual(row[0],1)
        for rows in layouts:
            self.assertEqual(chr(scalars[rows[0x63][1]]),'.')
        comp_start=32+4*nscalar+6
        triples=[tuple(blob[i:i+3]) for i in range(comp_start,comp_start+3*ncomp,3)]
        self.assertEqual(triples,sorted(triples));self.assertIn((6,scalars.index(ord('c')),scalars.index(ord('ç'))),triples)
        provenance=json.loads((self.reference/'keyboard_layout_provenance.json').read_text());self.assertEqual(provenance['data_sha256'],hashlib.sha256(blob).hexdigest())
        self.assertEqual([t['file'] for t in provenance['tables']],list(DATA['cldr-43'][:4]))


if __name__=='__main__':unittest.main()
