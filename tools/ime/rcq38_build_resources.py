#!/usr/bin/env python3
"""Reproducible host font/dictionary DATA; no native build, signing or target IO."""
from __future__ import annotations
import argparse
import hashlib
import io
from pathlib import Path
import re
import sys
import urllib.request

import rcq38_resource_pack as pack

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT/'third_party/ime/starter/sources.v1.json'
FREEZE = ROOT/'third_party/ime/starter/SOURCE_FREEZE.json'
REGISTRY_SHA256 = 'b41c51f975736c1bf5d44711c3087386800ad89cc2b0ae36f7a92964fd21b279'
JA_LICENSE = 'BSD-3-Clause AND LicenseRef-NAIST-IPAdic-ICOT AND LicenseRef-Okinawa-Public-Domain'
LICENSES = {'noto-cjk':'OFL-1.1','noto-latin':'OFL-1.1','rime-pinyin':'Apache-2.0','mozc':JA_LICENSE}
SOURCE_CAP = 20*1024**2
UPSTREAM = {'noto-cjk':('notofonts/noto-cjk','523d033d6cb47f4a80c58a35753646f5c3608a78'),
            'noto-latin':('notofonts/noto-fonts','ffebf8c1ee449e544955a7e813c54f9b73848eac'),
            'rime-pinyin':('rime/rime-pinyin-simp','0c6861ef7420ee780270ca6d993d18d4101049d0'),
            'mozc':('google/mozc','18e76511af9371a9a4409b1d13c3e30884b53e9c')}
SOURCE_IDENTITIES = {
    'font-jp':('noto-cjk','NotoSansCJKjp-Regular.otf','Sans/OTF/Japanese/NotoSansCJKjp-Regular.otf'),
    'font-zh-hans':('noto-cjk','NotoSansCJKsc-Regular.otf','Sans/OTF/SimplifiedChinese/NotoSansCJKsc-Regular.otf'),
    'font-latin':('noto-latin','NotoSansMono-Regular.ttf','hinted/ttf/NotoSansMono/NotoSansMono-Regular.ttf'),
    'pinyin':('rime-pinyin','pinyin_simp.dict.yaml','pinyin_simp.dict.yaml'),
    **{f'mozc-{i:02d}':('mozc',f'dictionary{i:02d}.txt',f'src/data/dictionary_oss/dictionary{i:02d}.txt') for i in range(10)}}
NOTICE_IDENTITIES = {'mozc-dictionary-notices.txt':('mozc','src/data/dictionary_oss/README.txt'),
                     'mozc-license.txt':('mozc','LICENSE'),'noto-cjk-ofl.txt':('noto-cjk','LICENSE'),
                     'noto-latin-ofl.txt':('noto-latin','LICENSE'),'pinyin-apache.txt':('rime-pinyin','LICENSE'),
                     'pinyin-readme.txt':('rime-pinyin','README.md')}

def registry(path=REGISTRY):
    raw=pack.read_bounded(path,pack.MAX_JSON)
    r=validate_registry(pack.parse_json(raw))
    frozen=pack.parse_json(pack.read_bounded(FREEZE,pack.MAX_JSON))
    pack.need(type(frozen) is dict and type(frozen.get('contracts')) is dict
              and frozen['contracts'].get('sources.v1.json')==REGISTRY_SHA256,'frozen registry pin')
    pack.need(pack.digest(raw).hex()==REGISTRY_SHA256,'registry bytes differ from frozen source pin')
    return r

def validate_registry(r):
    """Semantic provenance checks independently testable from the frozen-byte pin."""
    pack.fields(r,('schema','revision','sources','notices','font_copyright','pinyin_ancestry','excluded'))
    pack.need(r['schema']=='paos.resources.source-registry.v1' and r['revision']==1,'source registry version')
    pack.need(type(r['sources']) is list and len(r['sources'])==14,'source registry count')
    ids,names=set(),set()
    for row in r['sources']:
        pack.fields(row,('id','group','name','repo','commit','path','url','bytes','sha256','license'))
        pack.need(type(row['id']) is str and row['id'] not in ids,'duplicate source ID')
        pack.need(type(row['group']) is str and row['group'] in LICENSES and row['license']==LICENSES[row['group']], 'unreviewed/GPL/LGPL source licence')
        pack.need(SOURCE_IDENTITIES.get(row['id'])==(row['group'],row['name'],row['path']),'source ID/group/path provenance')
        pack.need((row['repo'],row['commit'])==UPSTREAM[row['group']],'source group/upstream provenance')
        pack.need(type(row['commit']) is str and re.fullmatch('[0-9a-f]{40}',row['commit']), 'source commit pin')
        pack.need(row['url']=='https://raw.githubusercontent.com/'+row['repo']+'/'+row['commit']+'/'+row['path'],'source URL pin')
        safe_source_name(row['name']);pack.need(row['name'] not in names,'duplicate source filename')
        pack.sha_bytes(row['sha256']);pack.integer(row['bytes'],1,SOURCE_CAP)
        ids.add(row['id']);names.add(row['name'])
    pack.need(ids=={'font-jp','font-zh-hans','font-latin','pinyin'}|{f'mozc-{i:02d}' for i in range(10)},'source identity set')
    pack.need(type(r['notices']) is list and len(r['notices'])==6,'source notice set')
    notice_names=set()
    for row in r['notices']:
        pack.fields(row,('group','name','url','bytes','sha256'));safe_source_name(row['name'])
        pack.need(type(row['group']) is str and row['group'] in LICENSES and row['name'] not in notice_names,'notice group/duplicate')
        identity=NOTICE_IDENTITIES.get(row['name'])
        pack.need(identity is not None and identity[0]==row['group'],'notice identity/group provenance')
        repo,commit=UPSTREAM[row['group']]
        pack.need(row['url']=='https://raw.githubusercontent.com/'+repo+'/'+commit+'/'+identity[1],'notice/source commit provenance')
        pack.sha_bytes(row['sha256']);pack.integer(row['bytes'],1,pack.MAX_JSON);notice_names.add(row['name'])
    pack.need({x['group'] for x in r['notices']}==set(LICENSES),'missing licence group notice')
    return r

def safe_source_name(name):
    pack.need(type(name) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,95}',name)
              and '..' not in name,'source basename')

def pinned_bytes(inputs, row):
    raw=pack.read_bounded(Path(inputs)/row['name'],SOURCE_CAP)
    pack.need(len(raw)==row['bytes'] and pack.digest(raw).hex()==row['sha256'],'source hash/size: '+row['name'])
    return raw

def fetch_sources(r, inputs):
    inputs=Path(inputs);inputs.mkdir(parents=True,exist_ok=True)
    for row in r['sources']+r['notices']:
        dest=inputs/row['name']
        if dest.exists():pinned_bytes(inputs,row);continue
        req=urllib.request.Request(row['url'],headers={'User-Agent':'PaOS-RCQ38-host-data'})
        with urllib.request.urlopen(req,timeout=60) as stream:raw=stream.read(SOURCE_CAP+1)
        pack.need(len(raw)==row['bytes'] and pack.digest(raw).hex()==row['sha256'],'download hash/size')
        dest.write_bytes(raw)

def source_contract(rows):
    return pack.canonical(sorted(rows,key=lambda r:r['id']))

def codes(codec, rows):
    out=set()
    for a in rows:
        for b in range(0xa1,0xff):
            try:out.update(map(ord,bytes([a,b]).decode(codec)))
            except UnicodeError:pass
    return out

def repertoire(face):
    if face==1:
        return set(range(0x20,0x7f))|set(range(0xa0,0x180))|{0x1e9e,0x20ac,0x2019,0x201c,0x201d,0x2026,0xfffd}
    if face==2:return codes('euc_jp',range(0xb0,0xd0))
    if face==3:return codes('gb2312',range(0xb0,0xd8))
    raise pack.PackError('font face')

def font_pack(raw_font, face, mode, *, required=None, subset=None, intentional_blanks=None):
    # Outline parsing/rasterization is host-only, with exact build-tool versions.
    import PIL,fontTools
    from PIL import Image,ImageDraw,ImageFont
    from fontTools.ttLib import TTFont
    pack.need((PIL.__version__,fontTools.__version__,ImageFont.core.freetype2_version)==
              ('12.1.0','4.61.1','2.14.1'),'unqualified rasterizer versions')
    pack.need(mode in ('aa','vt'),'font mode')
    w,h,bpp,px,baseline = ((9 if face==1 else 18),19,8,15,15 if face==1 else 14) if mode=='aa' else (
        (8 if face==1 else 16),16,1,13 if face==1 else 14,13)
    custom = required is not None
    if custom:
        pack.need(type(required) is list and 0<len(required)<=32768 and required==sorted(set(required)),
                  'explicit font repertoire must be sorted/unique/bounded')
        for cp in required:pack.scalar(cp)
        pack.need((face,subset) in {(1,4),(2,5),(3,6)},'explicit font profile pairing')
        pack.need(type(intentional_blanks) is list and intentional_blanks==sorted(set(intentional_blanks))
                  and set(intentional_blanks)<=set(required),'explicit intentional blank repertoire')
    else:
        pack.need(subset is None and intentional_blanks is None,'legacy font profile is frozen')
        required=sorted(repertoire(face));subset=face
    with TTFont(io.BytesIO(raw_font)) as outline:
        cmap=outline.getBestCmap()
        if custom:cmap={cp:name for cp,name in cmap.items() if name!='.notdef' and outline.getGlyphID(name)!=0}
    missing=[cp for cp in required if cp not in cmap]
    fonts={size:ImageFont.truetype(io.BytesIO(raw_font),size,layout_engine=ImageFont.Layout.BASIC) for size in range(7,17)}
    glyphs=[];clipped=[];adjustments=[];naive=[];blanks=[]
    for cp in required:
        if cp in missing:continue
        ch=chr(cp)
        if face!=1 and mode=='vt':
            old=fonts[16];bb=old.getbbox(ch,anchor='ls');ox=max(0,(w-round(old.getlength(ch)))//2)
            if bb[0]+ox<0 or bb[2]+ox>w or bb[1]+14<0 or bb[3]+14>h:naive.append(cp)
        font=fonts[px];bb=font.getbbox(ch,anchor='ls');x=max(0,(w-round(font.getlength(ch)))//2);y=baseline;selected=px
        if bb[0]+x<0 or bb[2]+x>w or bb[1]+y<0 or bb[3]+y>h:
            # Fit actual glyph at the largest available size; record every change.
            found=False
            for size in range(px,6,-1):
                candidate=fonts[size];box=candidate.getbbox(ch,anchor='ls')
                if box[2]-box[0]<=w and box[3]-box[1]<=h:
                    font,bb,selected=candidate,box,size
                    x=max(-bb[0],min((w-round(font.getlength(ch)))//2,w-bb[2]))
                    y=max(-bb[1],min(baseline,h-bb[3]));found=True;break
            if not found:clipped.append(cp);continue
            adjustments.append({'scalar':cp,'font_px':selected,'x':x,'baseline':y,'bbox':list(bb)})
        if bb[0]+x<0 or bb[2]+x>w or bb[1]+y<0 or bb[3]+y>h:clipped.append(cp);continue
        # Independent large-canvas ink check avoids merely cropping into a cell.
        margin=64;large=Image.new('L',(w+2*margin,h+2*margin))
        ImageDraw.Draw(large).text((margin+x,margin+y),ch,font=font,fill=255,anchor='ls')
        ink=large.getbbox()
        if ink and (ink[0]<margin or ink[1]<margin or ink[2]>margin+w or ink[3]>margin+h):
            clipped.append(cp);continue
        cell=large.crop((margin,margin,margin+w,margin+h))
        if bpp==8:raw=cell.tobytes()
        else:
            data=bytearray()
            for yy in range(h):
                for start in range(0,w,8):
                    value=0
                    for bit in range(8):
                        if start+bit<w and cell.getpixel((start+bit,yy))>=128:value|=1<<(7-bit)
                    data.append(value)
            raw=bytes(data)
        if custom and bpp==1 and not any(raw) and cp not in intentional_blanks:
            # A thin real outline can vanish at threshold128 at the nominal size.
            # Try the qualified bounded sizes without cropping or changing threshold.
            for size in range(16,6,-1):
                candidate=fonts[size];box=candidate.getbbox(ch,anchor='ls')
                if box[2]-box[0]>w or box[3]-box[1]>h:continue
                cx=max(-box[0],min((w-round(candidate.getlength(ch)))//2,w-box[2]))
                cy=max(-box[1],min(baseline,h-box[3]))
                canvas=Image.new('L',(w+2*margin,h+2*margin))
                ImageDraw.Draw(canvas).text((margin+cx,margin+cy),ch,font=candidate,fill=255,anchor='ls')
                bounds=canvas.getbbox()
                if bounds and (bounds[0]<margin or bounds[1]<margin or bounds[2]>margin+w or bounds[3]>margin+h):continue
                fitted=canvas.crop((margin,margin,margin+w,margin+h));bits=bytearray()
                for yy in range(h):
                    for start in range(0,w,8):
                        value=0
                        for bit in range(8):
                            if start+bit<w and fitted.getpixel((start+bit,yy))>=128:value|=1<<(7-bit)
                        bits.append(value)
                if any(bits):
                    raw=bytes(bits)
                    adjustments.append({'scalar':cp,'font_px':size,'x':cx,'baseline':cy,'bbox':list(box),
                                        'reason':'mono nominal threshold produced empty bitmap'})
                    break
        if custom and not any(raw):blanks.append(cp)
        glyphs.append((cp,raw))
    report={'face':face,'subset':subset,'mode':mode,'requested':len(required),'missing':missing,'clipped':clipped,
            'fitted':adjustments,'cell':[w,h],'nominal_px':px,'nominal_baseline':baseline,
            'naive_16px_baseline14_clipped':naive,'source_sha256':pack.digest(raw_font).hex(),
            'rasterizer':{'pillow':PIL.__version__,'fonttools':fontTools.__version__,'freetype':ImageFont.core.freetype2_version,'layout':'BASIC'}}
    if custom:
        report.update(intentional_blanks=intentional_blanks,blank_glyphs=blanks,
                      unexpected_blank_glyphs=sorted(set(blanks)-set(intentional_blanks)),
                      repertoire_sha256=pack.digest(b''.join(pack.FONT_ROW.pack(cp,0)[:4] for cp in required)).hex())
    if missing or clipped or (custom and report['unexpected_blank_glyphs']):return None,report
    stride=(w+7)//8 if bpp==1 else w;gstride=stride*h;boff=192+len(glyphs)*8
    index=b''.join(pack.FONT_ROW.pack(cp,boff+i*gstride) for i,(cp,raw) in enumerate(glyphs))
    blob=b''.join(raw for cp,raw in glyphs)
    meta=pack.FONT_META.pack(w,h,bpp,stride,px,baseline,128 if bpp==1 else 0,face,gstride,subset,0,0,pack.digest(raw_font))
    result=pack.envelope(1,meta,len(glyphs),blob,index)
    pack.validate_pack(result);report.update(bytes=len(result),sha256=pack.digest(result).hex())
    return result,report

def parse_dictionary(raw, family):
    try:source=raw.decode('utf-8',errors='strict')
    except UnicodeError as e:raise pack.PackError('dictionary source UTF-8') from e
    if family=='pinyin':
        pack.need(source.count('\n...\n')==1,'Pinyin source header')
        source=source.split('\n...\n',1)[1]
    else:pack.need(family=='ja','dictionary family')
    rows=[]
    for line in source.split('\n'):
        if not line or line.startswith('#'):continue
        f=line.split('\t')
        if family=='pinyin':
            pack.need(len(f)==3 and re.fullmatch('[a-z]+(?: [a-z]+)*',f[1]) and re.fullmatch('[0-9]+',f[2]),'Pinyin row format')
            surface,key,weight=f;cost=left=right=attributes=0;weight=pack.integer(int(weight))
        else:
            pack.need(len(f) in (5,6) and all(re.fullmatch('-?[0-9]+',x) for x in f[1:4]),'Japanese row format')
            key,left,right,cost,surface=f[:5];left=pack.integer(int(left));right=pack.integer(int(right))
            cost=pack.integer(int(cost),-0x80000000,0x7fffffff);weight=0;attributes=0
            if len(f)==6:
                pack.need(f[5]=='SPELLING_CORRECTION','unknown Japanese source attribute');attributes=1
        key,surface=key.encode('utf-8'),surface.encode('utf-8');pack.text(key,128);pack.text(surface,256)
        rows.append((key,surface,left,right,cost,weight,attributes))
    pack.need(bool(rows),'empty dictionary source')
    return rows

def dictionary_shards(rows, family, contract):
    pack.need(family in ('pinyin','ja'),'dictionary family')
    meta=pack.DICT_META.pack(b'zh-Hans' if family=='pinyin' else b'ja',1 if family=='pinyin' else 2,1,128,pack.digest(contract),b'\0'*16)
    sorted_rows=sorted(set(rows));groups=[];group=[];size=192
    for row in sorted_rows:
        cost=pack.DICT_ROW.size+len(row[0])+len(row[1])
        if group and (size+cost>pack.MAX_DICT or len(group)==250000):groups.append(group);group=[];size=192
        group.append(row);size+=cost
    if group:groups.append(group)
    packs=[]
    for group in groups:
        index=bytearray();blob=bytearray();boff=192+len(group)*pack.DICT_ROW.size
        for key,surface,left,right,cost,weight,attributes in group:
            off=boff+len(blob);index.extend(pack.DICT_ROW.pack(off,len(key),off+len(key),len(surface),cost,left,right,weight,attributes));blob.extend(key);blob.extend(surface)
        result=pack.envelope(2,meta,len(group),blob,index)
        info=pack.validate_pack(result);packs.append((result,info))
    return packs,{'input_records':len(rows),'records':len(sorted_rows),'exact_duplicates_removed':len(rows)-len(sorted_rows),
                  'shards':len(packs),'pack_bytes':sum(len(raw) for raw,info in packs),
                  'attribute_spelling_correction_records':sum(bool(r[-1]) for r in sorted_rows),
                  'surface_scalars':sorted({ord(ch) for row in sorted_rows for ch in row[1].decode('utf-8')})}

def notice_artifacts(r, inputs, sources):
    groups={s['group'] for s in sources};out={}
    for row in r['notices']:
        if row['group'] in groups:out[row['name']]=pinned_bytes(inputs,row)
    credits={'schema':'paos.resources.conversion-notices.v1','sources':sources,
             'font_copyright':{key:val for key,val in r['font_copyright'].items() if key in {s['id'] for s in sources}},
             'changes':'PaOS fixed bitmap or weighted lookup derivative; no upstream engine/code. Bitmap metrics/fit and dictionary dedup/shards recorded in build receipt.',
             'pinyin_ancestry':r['pinyin_ancestry'] if 'rime-pinyin' in groups else None}
    if 'rime-pinyin' in groups:
        source=next(s for s in sources if s['id']=='pinyin');raw=pinned_bytes(inputs,source)
        credits['pinyin_original_header']=raw.decode('utf-8').split('\n...\n',1)[0]+'\n...\n'
    out['conversion-'+pack.digest(source_contract(sources)).hex()[:16]+'.json']=pack.canonical(credits)
    return out

def finish(artifacts, r, inputs, sources, report, release, generation, slot, out, *, extra_notices=None):
    kinds={name:('font' if name.endswith('.pfnt') else 'dictionary') for name in artifacts}
    for name,raw in list(artifacts.items()):artifacts[name+'.pgh']=pack.page_table(raw);kinds[name+'.pgh']='pages'
    for name,raw in notice_artifacts(r,inputs,sources).items():artifacts[name]=raw;kinds[name]='notice'
    for name,raw in (extra_notices or {}).items():
        pack.artifact_name(name);pack.need(name not in artifacts,'extra notice name collision')
        pack.need(type(raw) is bytes and 0<len(raw)<=pack.MAX_JSON,'extra notice bounds')
        artifacts[name]=raw;kinds[name]='notice'
    manifest=pack.manifest(artifacts,kinds,release,generation,slot)
    pack.verify_set(manifest,artifacts,release,generation,slot)
    report.update(schema='paos.resources.build-receipt.v1',release_sha256=release,generation=generation,slot=slot,
                  total_bytes=len(manifest)+sum(map(len,artifacts.values())),manifest_sha256=pack.digest(manifest).hex(),
                  artifacts={name:{'bytes':len(raw),'sha256':pack.digest(raw).hex()} for name,raw in sorted(artifacts.items())})
    out=Path(out);pack.need(not out.exists(),'output must be a new host build directory')
    out.mkdir(parents=True)
    for name,raw in artifacts.items():(out/name).write_bytes(raw)
    (out/'manifest.json').write_bytes(manifest);(out/'receipt.json').write_bytes(pack.canonical(report))
    return report

def combine(parts, release, generation, slot, out):
    artifacts={};kinds={};pins=[]
    for part in parts:
        raw,incoming=pack.read_host_set(part,Path(part)/'manifest.json',release,generation,slot)
        manifest=pack.parse_json(raw);pins.append(pack.digest(raw).hex())
        for row in manifest['artifacts']:
            name=row['name'];data=incoming[name]
            pack.need(name not in artifacts or (artifacts[name]==data and kinds[name]==row['kind']),'part filename collision')
            artifacts[name]=data;kinds[name]=row['kind']
    manifest=pack.manifest(artifacts,kinds,release,generation,slot)
    pack.verify_set(manifest,artifacts,release,generation,slot)
    report={'schema':'paos.resources.combined-receipt.v1','part_manifest_sha256':sorted(pins),
            'release_sha256':release,'generation':generation,'slot':slot,
            'manifest_sha256':pack.digest(manifest).hex(),'total_bytes':len(manifest)+sum(map(len,artifacts.values())),
            'artifacts':{name:{'bytes':len(raw),'sha256':pack.digest(raw).hex()} for name,raw in sorted(artifacts.items())}}
    out=Path(out);pack.need(not out.exists(),'output must be a new host build directory');out.mkdir(parents=True)
    for name,raw in artifacts.items():(out/name).write_bytes(raw)
    (out/'manifest.json').write_bytes(manifest);(out/'receipt.json').write_bytes(pack.canonical(report));return report

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--registry',default=str(REGISTRY))
    sub=p.add_subparsers(dest='command',required=True)
    f=sub.add_parser('fetch');f.add_argument('--inputs',required=True)
    c=sub.add_parser('combine');c.add_argument('--part',action='append',required=True);c.add_argument('--out',required=True)
    c.add_argument('--release',required=True);c.add_argument('--generation',required=True,type=int);c.add_argument('--slot',required=True,choices=['A','B'])
    for command in ['fonts','dictionary']:
        c=sub.add_parser(command);c.add_argument('--inputs',required=True);c.add_argument('--out',required=True)
        c.add_argument('--release',required=True);c.add_argument('--generation',required=True,type=int);c.add_argument('--slot',required=True,choices=['A','B'])
        if command=='dictionary':c.add_argument('--family',required=True,choices=['pinyin','ja']);c.add_argument('--scope',choices=['one','full'],default='full')
    a=p.parse_args(argv)
    try:
        r=registry(a.registry)
        if a.command=='fetch':fetch_sources(r,a.inputs);print('{"ok":true,"sources":14,"notices":6}');return 0
        pack.sha_bytes(a.release);pack.integer(a.generation,1)
        if a.command=='combine':
            result=combine(a.part,a.release,a.generation,a.slot,a.out)
        elif a.command=='fonts':
            sources=[s for s in r['sources'] if s['id'].startswith('font-')];artifacts={};reports=[]
            for source in sources:
                face={'font-latin':1,'font-jp':2,'font-zh-hans':3}[source['id']]
                for mode in ['aa','vt']:
                    raw,report=font_pack(pinned_bytes(a.inputs,source),face,mode);reports.append(report)
                    pack.need(raw is not None,'font coverage/clipping defects: '+pack.canonical(report).decode())
                    artifacts[source['id']+'-'+mode+'.pfnt']=raw
            result=finish(artifacts,r,a.inputs,sources,{'fonts':reports,'product_coverage':'Latin326 + JA2965/zh-Hans3755 L1 only, not complete native/font acceptance'},a.release,a.generation,a.slot,a.out)
        else:
            sources=[s for s in r['sources'] if s['id']=='pinyin'] if a.family=='pinyin' else [s for s in r['sources'] if s['group']=='mozc' and (a.scope=='full' or s['id']=='mozc-00')]
            rows=[]
            for source in sources:rows.extend(parse_dictionary(pinned_bytes(a.inputs,source),a.family))
            chunks,report=dictionary_shards(rows,a.family,source_contract(sources))
            artifacts={a.family+'-'+a.scope+'-'+str(i).zfill(3)+'.pdct':raw for i,(raw,info) in enumerate(chunks)}
            report.update(family=a.family,scope=a.scope,source_files=len(sources),source_bytes=sum(s['bytes'] for s in sources),
                          product_quality='Weighted lexical lookup DATA, no connection matrix/segmentation/IME; Pinyin includes traditional/rare surfaces and is not zh-Hans-only certified.')
            result=finish(artifacts,r,a.inputs,sources,report,a.release,a.generation,a.slot,a.out)
        print(pack.canonical({'ok':True,'total_bytes':result['total_bytes'],'manifest_sha256':result['manifest_sha256']}).decode(),end='');return 0
    except (pack.PackError,OSError,UnicodeError,ValueError,TypeError,KeyError) as e:
        print(pack.canonical({'ok':False,'error':str(e)}).decode(),end='');return 2

if __name__=='__main__':sys.exit(main())
