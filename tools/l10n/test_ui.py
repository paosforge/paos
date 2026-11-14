# SPDX-License-Identifier: Apache-2.0
"""Actual public UI recipe and independent scalar/cell/PCAT1 oracles."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOL = Path('tools/l10n/gen_ui.py')
INPUT = Path('third_party/localization')
PINS = json.loads((ROOT / INPUT / 'SOURCES.json').read_bytes()) if (ROOT / INPUT / 'SOURCES.json').is_file() else {'files': {}}
SOURCES = tuple(map(Path, PINS['files'])) + (INPUT / 'SOURCES.json', INPUT / 'SOURCE.md')
CLOSURE = (TOOL, Path('tools/l10n/test_ui.py'), *SOURCES,
           Path('src/gui/l10n_catalog.inc'), Path('src/gui/l10n_glyphs.inc'))


class PublicUI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='public-ui-')
        self.addCleanup(self.tmp.cleanup)
        self.tree = Path(self.tmp.name) / 'source'
        self.tree.mkdir()
        for name in CLOSURE:
            if (ROOT / name).is_file():
                p = self.tree / name
                p.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, p)

    def run_tool(self, *args):
        return subprocess.run([sys.executable, '-I', '-S', '-B', str(self.tree / TOOL), *map(str,args)],
                              cwd=self.tmp.name, capture_output=True, timeout=30)

    def emit(self, name='out'):
        out = Path(self.tmp.name) / name
        p = self.run_tool('--emit', out)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        return {p.name:p.read_bytes() for p in out.iterdir()}

    def refused(self):
        out = Path(self.tmp.name) / 'rejected'
        p = self.run_tool('--emit', out)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b'gen_ui:', p.stderr)
        self.assertNotIn(b'Traceback', p.stderr)
        self.assertFalse(out.exists())
        return p.stderr.decode()

    def test_public_entry_missing_factory(self):
        self.assertTrue((self.tree / TOOL).is_file(), 'public UI recipe missing')
        self.assertFalse((self.tree / 'gauntlet_v2').exists())

    def test_exact_native_bytes(self):
        out = self.emit()
        for name in ('l10n_catalog.inc','l10n_glyphs.inc'):
            self.assertEqual(out[name],(ROOT/'src/gui'/name).read_bytes())

    def test_two_clean_rebuilds(self):
        self.assertEqual(self.emit('a'),self.emit('b'))

    def test_current_explorer_and_ssh_public_pcat_bytes(self):
        # Independent PCAT1 wire parsing and product literals, not emitter IDs
        # or a copy of its expected-output hashes.
        expected={718:b'name incomplete or invalid',1264:
                  b'ssh: usage: ssh USER@HOST[:PORT] or ssh --exec USER@HOST[:PORT] -- COMMAND'}
        outputs=self.emit()
        for locale in ('en','de','es','fr','ja','zh-Hans'):
            raw=outputs[locale+'.pcat']
            self.assertEqual(raw[:8],b'PCAT1\0\0\0')
            count=struct.unpack_from('<I',raw,20)[0]
            rows={}
            for pos in range(count):
                ident,start,length,flags=struct.unpack_from('<IIII',raw,64+pos*16)
                rows[ident]=raw[start:start+length]
            for ident,text in expected.items():
                self.assertIn(ident,rows)
                if locale=='en':self.assertEqual(rows[ident],text)
            for syntax in (b'ssh USER@HOST[:PORT]',b'ssh --exec USER@HOST[:PORT] -- COMMAND'):
                self.assertIn(syntax,rows[1264])
            self.assertNotIn(b'IPv4',rows[1264])
            self.assertNotIn(b'sshclikey',rows[1264])

    def test_check_unrelated_directory(self):
        p=self.run_tool('--check');self.assertEqual(p.returncode,0,p.stderr.decode())

    def test_glyph_cells_independent(self):
        text=self.emit()['l10n_glyphs.inc'].decode('ascii')
        head,body=text.split('l10n_glyph_bits:')
        cps=[int(v,16) for line in head.splitlines() if line.startswith('    dd ') for v in line[7:].split(',')]
        subset={int(cp,16):bytes.fromhex(bits) for cp,bits in
                (l.split(':') for l in (self.tree/'third_party/fonts/unifont/unifont-ui-subset.hex').read_text().splitlines())}
        self.assertEqual(cps,sorted(subset));self.assertEqual(len(cps),5195)
        rows=re.findall(r'    db (.+) ; U\+([0-9A-F]+)',body)
        self.assertEqual(len(rows),5195)
        for ident,(vals,cp) in zip(cps,rows):
            cell=bytes(int(v,16) for v in vals.split(','))
            self.assertEqual(int(cp,16),ident);self.assertEqual(cell,subset[ident])
            self.assertEqual(len(cell),32)
            # Explicit 16x16 MSB-first pixel identity for every glyph.
            pixels=[[bool(cell[y*2+x//8] & (0x80>>(x%8))) for x in range(16)] for y in range(16)]
            src=subset[ident]
            self.assertEqual(pixels,[[bool(int.from_bytes(src[y*2:y*2+2],'big')&(1<<(15-x))) for x in range(16)] for y in range(16)])
        self.assertTrue(set(range(0x3041,0x3097))<=set(cps));self.assertTrue(set(range(0x30a1,0x30fb))<=set(cps))
        self.assertTrue({0xff08,0xff09,0xff0c,0xff1a,0xff1b,0xff1f,0x3002}<=set(cps))

    def test_catalogs_independent(self):
        out=self.emit();source=json.loads((self.tree/INPUT/'catalog.rc1.v1.json').read_bytes())
        active={m['id']:m for m in source['messages'] if not m.get('tombstone',False)}
        coverage=json.loads(out['coverage.json'])
        for ordinal,locale in enumerate(('en','es','fr','de','ja','zh-Hans')):
            raw=out[locale+'.pcat'];magic,version,lang,flags,revision,count,offset,digest,total=struct.unpack_from('<8sHHIIII32sI',raw)
            self.assertEqual((magic,version,lang,flags,revision,total),(b'PCAT1\0\0\0',1,ordinal,0,source['revision'],len(raw)))
            selected=sorted(i for i,m in active.items() if m['key'] in source['locales'][locale])
            self.assertEqual(count,len(selected));self.assertEqual(offset,64+16*count)
            contract={k:source[k] for k in ('schema','revision')};contract['messages']=sorted(source['messages'],key=lambda m:m['id']);contract['sites_sha256']=source['sites_sha256']
            expected=hashlib.sha256((json.dumps(contract,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()).digest()
            self.assertEqual(digest,expected);next_offset=offset
            for pos,ident in enumerate(selected):
                got,start,length,critical=struct.unpack_from('<IIII',raw,64+pos*16)
                m=active[ident];text=source['locales'][locale][m['key']].encode('utf-8')
                self.assertEqual((got,start,length,critical),(ident,next_offset,len(text),int(m['critical'])))
                self.assertEqual(raw[start:start+length],text);next_offset+=length
            self.assertEqual(next_offset,len(raw));self.assertEqual(coverage['locales'][locale]['sha256'],hashlib.sha256(raw).hexdigest())

    def test_native_catalog_expectations_and_ids(self):
        out=self.emit();text=out['l10n_catalog.inc'].decode();source=json.loads((self.tree/INPUT/'catalog.rc1.v1.json').read_bytes());sites=json.loads((self.tree/INPUT/'source_sites.v1.json').read_bytes())
        active={m['id']:m for m in source['messages'] if not m.get('tombstone',False)}
        rows={s['id']:s for s in sites['sites']};counts={}
        for i in active:counts[rows[i]['label']]=counts.get(rows[i]['label'],0)+1
        expected={('L10N_ID_'+rows[i]['label']+('' if counts[rows[i]['label']]==1 else '_'+str(rows[i]['literal_ordinal']))):i for i in active}
        got={name:int(ident) for name,ident in re.findall(r'^(L10N_ID_\w+) equ (\d+)$',text,re.M)}
        self.assertEqual(got,expected)
        def db(label,tail):
            part=text.split(label+':',1)[1].split(tail,1)[0]
            return bytes(int(v,16) for v in re.findall(r'0x([0-9a-f]{2})',part))
        en=out['en.pcat']
        self.assertEqual(db('l10n_cat_en_expect','; help'),en[28:60]+hashlib.sha256(en).digest())
        self.assertEqual(db('l10n_cat_en','l10n_cat_help_en:'),en)
        help_raw=db('l10n_cat_help_en','l10n_catalog_end:');help_source=json.loads((self.tree/INPUT/'catalog.offline-help.en.v1.json').read_bytes())
        count=struct.unpack_from('<I',help_raw,20)[0];messages=sorted((m for m in help_source['messages'] if not m.get('tombstone',False)),key=lambda m:m['id'])
        self.assertEqual(count,len(messages))
        for pos,m in enumerate(messages):
            ident,start,length,critical=struct.unpack_from('<IIII',help_raw,64+pos*16)
            self.assertEqual((ident,critical),(m['id'],int(m['critical'])));self.assertEqual(help_raw[start:start+length],m['english'].encode())

    def test_missing_each_input_helper_notice(self):
        for name in SOURCES:
            with self.subTest(name=name):
                p=self.tree/name;raw=p.read_bytes();p.unlink();self.refused();p.write_bytes(raw)

    def test_recovery_failure_guidance_is_in_public_help(self):
        source=json.loads((self.tree/INPUT/'catalog.offline-help.en.v1.json').read_bytes())
        messages={m['id']:m for m in source['messages']}
        keys=['help.offline.recovery.failure_'+suffix for suffix in
              ('retained','readout','support_read','meaning','limits')]
        self.assertEqual([messages.get(i,{}).get('key') for i in range(6040,6045)],keys)
        pages=json.loads((self.tree/INPUT/'offline_help.pages.v1.json').read_bytes())
        blocks=[b for page in pages['pages'] for b in page['blocks']]
        self.assertEqual([b['message_key'] for b in blocks if b['message_key'] in keys],keys)
        # These delivered records use the existing English fallback; syncing
        # public declarations must not invent translations or new authority.
        for key in keys:
            self.assertIn(key,source['locales']['en'])
            for locale,texts in source['locales'].items():
                if locale!='en':self.assertNotIn(key,texts)
        include=self.emit()['l10n_catalog.inc'].decode()
        raw=bytes(int(v,16) for v in re.findall(r'0x([0-9a-f]{2})',
                  include.split('l10n_cat_help_en:',1)[1].split('l10n_catalog_end:',1)[0]))
        count=struct.unpack_from('<I',raw,20)[0]
        decoded={}
        for pos in range(count):
            ident,start,length,_=struct.unpack_from('<IIII',raw,64+16*pos)
            decoded[ident]=raw[start:start+length].decode('utf-8')
        for ident in range(6040,6045):self.assertEqual(decoded[ident],messages[ident]['english'])

    def test_missing_and_extra_subset_cells(self):
        p=self.tree/'third_party/fonts/unifont/unifont-ui-subset.hex';raw=p.read_bytes()
        for changed in (b'\n'.join(raw.splitlines()[1:])+b'\n',raw+b'100000:'+b'00'*32+b'\n'):
            p.write_bytes(changed)
            m=self.tree/INPUT/'SOURCES.json';doc=json.loads(m.read_bytes());doc['files'][str(p.relative_to(self.tree))]=hashlib.sha256(changed).hexdigest();m.write_text(json.dumps(doc));self.repin_manifest()
            self.assertIn('exact closure',self.refused())

    def test_corrupt_each_input_helper_notice(self):
        for name in SOURCES:
            with self.subTest(name=name):
                p=self.tree/name;raw=p.read_bytes();p.write_bytes(raw+b'!');self.refused();p.write_bytes(raw)

    def repin_manifest(self):
        p=self.tree/INPUT/'SOURCES.json';driver=self.tree/TOOL
        raw=driver.read_text();raw=re.sub(r"MANIFEST_SHA = '[0-9a-f]+'", "MANIFEST_SHA = '"+hashlib.sha256(p.read_bytes()).hexdigest()+"'",raw);driver.write_text(raw)

    def test_version_independent_of_hash(self):
        p=self.tree/INPUT/'SOURCES.json';d=json.loads(p.read_bytes());d['unifont_version']='16.0.0';p.write_text(json.dumps(d));self.repin_manifest();self.assertIn('version',self.refused())

    def test_version_tamper(self):
        p=self.tree/INPUT/'SOURCES.json';d=json.loads(p.read_bytes());d['unifont_version']='16.0.0';p.write_text(json.dumps(d));self.refused()

    def test_file_symlink_escape(self):
        p=self.tree/INPUT/'catalog.rc1.v1.json';outside=Path(self.tmp.name)/'outside';p.rename(outside);p.symlink_to(outside);self.assertIn('symlink',self.refused())

    def test_parent_symlink_escape(self):
        p=self.tree/INPUT;outside=Path(self.tmp.name)/'outside';p.rename(outside);p.symlink_to(outside,target_is_directory=True);self.assertIn('symlink',self.refused())

    def test_output_parent_escape(self):
        outside=Path(self.tmp.name)/'outside';outside.mkdir();link=Path(self.tmp.name)/'link';link.symlink_to(outside,target_is_directory=True)
        p=self.run_tool('--emit',link/'out');self.assertNotEqual(p.returncode,0);self.assertFalse((outside/'out').exists())

    def test_checked_in_tamper(self):
        (self.tree/'src/gui/l10n_glyphs.inc').write_bytes(b'drift');p=self.run_tool('--check');self.assertNotEqual(p.returncode,0)

    def api(self, code):
        prefix='import sys;sys.path.insert(0,'+repr(str(self.tree/'tools/l10n'))+');import emitter as B;import catalog as K;from pathlib import Path;'
        prefix += 'import runpy;U=runpy.run_path('+repr(str(self.tree/'tools/unicode/widths.py'))+')["UnicodeData"]({n:Path('+repr(str(self.tree/'third_party/unicode/ucd-15.0.0'))+').joinpath(n).read_text() for n in ("DerivedGeneralCategory.txt","EastAsianWidth.txt")});K.unicodedata=B.unicodedata=U;'
        return subprocess.run([sys.executable,'-I','-S','-B','-c',prefix+code],capture_output=True,timeout=20)

    def test_hex_syntax_duplicate_scalar_and_missing(self):
        p=self.tree/'third_party/fonts/unifont/unifont-ui-subset.hex';raw=p.read_text();first=raw.splitlines()[0]
        for bad in ('bad\n',raw+first+'\n','110000:'+('00'*32)+'\n','D800:'+('00'*32)+'\n'):
            with self.subTest(bad=bad[-70:]):
                p.write_text(bad);r=self.api('B.read_hex(Path('+repr(str(p))+'))');self.assertNotEqual(r.returncode,0)
        p.write_text(raw)

    def test_duplicate_catalog_and_site_identity(self):
        r=self.api("s=K.load_json(Path("+repr(str(self.tree/INPUT/'catalog.rc1.v1.json'))+"));s['messages'].append(s['messages'][0]);K.validate_source(s)")
        self.assertNotEqual(r.returncode,0);self.assertIn(b'duplicate message',r.stderr)

    def test_catalog_forbidden_format_scalar(self):
        r=self.api("K.text_bytes('a'+chr(0x200e))")
        self.assertNotEqual(r.returncode,0)

    def test_duplicate_sites(self):
        r=self.api('import site_map;s=K.load_json(Path('+repr(str(self.tree/INPUT/'source_sites.v1.json'))+"));s['sites'].append(s['sites'][0]);site_map.validate_sites(s)")
        self.assertNotEqual(r.returncode,0);self.assertIn(b'duplicate site',r.stderr)

    def test_cells_independent(self):
        # Read the versioned range DATA independently of the production lookup class.
        ranges={}
        for n in ('DerivedGeneralCategory.txt','EastAsianWidth.txt'):
            rows=[]
            for line in (self.tree/'third_party/unicode/ucd-15.0.0'/n).read_text().splitlines():
                body=line.split('#')[0].strip()
                if body:
                    field,value=body.split(';');ends=field.strip().split('..');rows.append((int(ends[0],16),int(ends[-1],16),value.strip()))
            ranges[n]=rows
        src=json.loads((self.tree/INPUT/'catalog.rc1.v1.json').read_bytes())
        cps=sorted({ord(c) for texts in src['locales'].values() for text in texts.values() for c in text}|{0x300,0x200e,0x00ad,0x3000,0xff08})
        expected=[]
        for cp in cps:
            cat=next((v for lo,hi,v in ranges['DerivedGeneralCategory.txt'] if lo<=cp<=hi),'Cn')
            eaw=next((v for lo,hi,v in ranges['EastAsianWidth.txt'] if lo<=cp<=hi),'N')
            expected.append(0 if cat in ('Mn','Me','Cf') else 2 if eaw in ('W','F') else 1)
        r=self.api('import json;print(json.dumps([B.cell(chr(c)) for c in '+repr(cps)+']))')
        self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(json.loads(r.stdout),expected)

    def test_malformed_json_and_out_of_range_id(self):
        r=self.api("K.uint(0x100000000)");self.assertNotEqual(r.returncode,0)
        p=self.tree/INPUT/'catalog.rc1.v1.json';p.write_text('{"schema":1,"schema":2}')
        r=self.api('K.load_json(Path('+repr(str(p))+'))');self.assertNotEqual(r.returncode,0);self.assertIn(b'duplicate JSON key',r.stderr)

    def test_helper_symlink(self):
        p=self.tree/'tools/l10n/emitter.py';outside=Path(self.tmp.name)/'helper';p.rename(outside);p.symlink_to(outside);self.assertIn('symlink',self.refused())

    def test_manifest_path_escape(self):
        p=self.tree/INPUT/'SOURCES.json';d=json.loads(p.read_bytes());d['files']['../escape']='a'*64;p.write_text(json.dumps(d));self.repin_manifest();self.assertIn('path escape',self.refused())

    def test_existing_output_refused(self):
        p=Path(self.tmp.name)/'exists';p.mkdir();(p/'keep').write_text('keep');r=self.run_tool('--emit',p);self.assertNotEqual(r.returncode,0);self.assertEqual((p/'keep').read_text(),'keep')


if __name__=='__main__':unittest.main()
