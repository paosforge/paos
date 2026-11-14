#!/usr/bin/env python3
"""Fixed host DATA packs. Hash verification is not signature verification."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import unicodedata

HEADER = struct.Struct('<8sHH11I32s32s8s')
FONT_META = struct.Struct('<8H4I32s')
DICT_META = struct.Struct('<8sHHI32s16s')
FONT_ROW = struct.Struct('<II')
DICT_ROW = struct.Struct('<IIIIiIIII')
PAGE_HEADER = struct.Struct('<8sHHIII32s8s')
PAGE_SIZE = 4096
MAX_FONT = 16 * 1024**2
MAX_DICT = 8 * 1024**2
MAX_SET = 128 * 1024**2
MAX_JSON = 65536
MAGICS = {1:b'PFNT1\0\0\0',2:b'PDCT1\0\0\0'}
FONT_IDENTITIES = {(1,1),(2,2),(3,3),(1,4),(2,5),(3,6)}
FONT_PROVENANCE_IDENTITIES = {(2,5)}  # Metadata32 is contract SHA only for this pair.
SHA = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[a-z][a-z0-9_.-]{0,95}(?<!\.)\Z')  # FAT aliases a trailing dot.

class PackError(ValueError): pass

def need(ok, message):
    if not ok: raise PackError(message)

def integer(n, low=0, high=0xffffffff):
    need(type(n) is int and low <= n <= high, 'integer bounds')
    return n

def digest(raw): return hashlib.sha256(raw).digest()

def canonical(obj):
    return (json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('utf-8')

def fields(obj, required, optional=()):
    need(type(obj) is dict and set(required) <= obj.keys() <= set(required)|set(optional), 'object fields')

def _pairs(pairs):
    result={}
    for k,v in pairs:
        need(k not in result,'duplicate JSON key');result[k]=v
    return result

def _manifest_uint(token):
    need(len(token)<=10 and token.isascii() and token.isdigit(),'manifest unsigned u32 syntax')
    return integer(int(token))

def _manifest_noninteger(token):
    raise PackError('manifest fractions/exponents forbidden')

def parse_json(raw, limit=MAX_JSON, *, manifest_subset=False):
    need(type(raw) is bytes and len(raw)<=limit,'JSON byte limit')
    if manifest_subset:
        need(raw.isascii() and b'\\' not in raw,'manifest ASCII/no-escape subset')
        need(b'\x7f' not in raw,'manifest DEL forbidden; string bytes must be printable ASCII')
        depth=0;quoted=False
        for value in raw:
            if value==34:quoted=not quoted
            elif not quoted:
                if value in (91,123):
                    depth+=1;need(depth<=4,'manifest nesting depth')
                elif value in (93,125):depth-=1
    try:
        result=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(PackError('nonfinite JSON')),
                          **({'parse_int':_manifest_uint,'parse_float':_manifest_noninteger} if manifest_subset else {}))
        if manifest_subset:
            pending=[result]
            while pending:
                value=pending.pop()
                if type(value) is dict:pending.extend(value.values())
                elif type(value) is list:pending.extend(value)
                else:need(type(value) in (str,int),'manifest booleans/null forbidden')
        return result
    except (ValueError,UnicodeError,RecursionError) as e: raise PackError('invalid JSON: '+str(e)) from e

def read_bounded(path, maximum):
    with Path(path).open('rb') as f: raw=f.read(maximum+1)
    need(len(raw)<=maximum,'file byte limit');return raw

def sha_bytes(value):
    need(type(value) is str and SHA.fullmatch(value) is not None,'SHA256 hex required')
    return bytes.fromhex(value)

def scalar(value):
    integer(value,0,0x10ffff);need(not 0xd800<=value<=0xdfff,'surrogate scalar');return value

def text(raw, maximum):
    need(unicodedata.unidata_version=='15.0.0','Unicode table version must be 15.0.0')
    need(0<len(raw)<=maximum,'text byte bounds')
    try: s=raw.decode('utf-8',errors='strict')
    except UnicodeError as e: raise PackError('invalid UTF-8') from e
    need(not any(ord(c)<32 or 127<=ord(c)<160 or ord(c)==0x034f
                 or unicodedata.category(c)=='Cf' for c in s),'text control/bidi/format')
    return s

def envelope(kind, meta, count, blob, index):
    need(kind in MAGICS and len(meta)==64,'pack kind/metadata')
    size=FONT_ROW.size if kind==1 else DICT_ROW.size
    total=192+len(index)+len(blob)
    need(len(index)==count*size,'index length')
    need(total <= (MAX_FONT if kind==1 else MAX_DICT),'pack byte limit')
    return HEADER.pack(MAGICS[kind],1,kind,128,total,0,128,64,192,count,size,
                       192+len(index),len(blob),0,b'\0'*32,digest(meta),b'\0'*8)+meta+index+blob

def header(raw):
    need(type(raw) is bytes and 192<=len(raw)<=MAX_FONT,'pack size')
    (magic,version,kind,hsize,total,flags,moff,mlen,ioff,count,esize,boff,blen,
     gen,image_hash,meta_hash,reserved)=HEADER.unpack_from(raw)
    need(kind in MAGICS and magic==MAGICS[kind] and version==1,'pack magic/version/kind')
    need(hsize==128 and flags==0 and reserved==b'\0'*8,'pack flags/header')
    need(total==len(raw) and total<=(MAX_FONT if kind==1 else MAX_DICT),'pack total bounds')
    need(moff==128 and mlen==64 and ioff==192,'metadata/index placement')
    need(1<=count<=(32768 if kind==1 else 250000),'pack count')
    need(esize==(8 if kind==1 else 36) and boff==192+count*esize
         and boff<=total and blen==total-boff,'pack index/blob bounds')
    need(gen==0 and image_hash==b'\0'*32,'nonzero reserved release/generation bytes')
    meta=raw[128:192];need(digest(meta)==meta_hash,'metadata hash')
    return kind,count,boff,meta

def validate_pack(raw):
    kind,count,boff,meta=header(raw)
    if kind==1:
        w,h,bpp,stride,px,baseline,threshold,face,gstride,subset,r0,r1,source=FONT_META.unpack(meta)
        need(1<=w<=64 and 1<=h<=64 and bpp in (1,8) and 1<=px<=64 and baseline<=h,'font metrics')
        need(stride==((w+7)//8 if bpp==1 else w) and gstride==stride*h,'font stride')
        need(threshold==(128 if bpp==1 else 0) and (face,subset) in FONT_IDENTITIES
             and r0==r1==0 and source!=b'\0'*32,'font identity/flags')
        need(len(raw)-boff==count*gstride,'font payload length')
        previous=-1
        for i in range(count):
            cp,off=FONT_ROW.unpack_from(raw,192+i*8);scalar(cp)
            need(cp>previous and off==boff+i*gstride,'font scalar order/offset');previous=cp
            if bpp==1 and w%8:
                mask=(1<<(8-w%8))-1
                need(all(raw[off+y*stride+stride-1]&mask==0 for y in range(h)),'nonzero mono padding')
        result={'kind':'font','count':count,'width':w,'height':h,'bpp':bpp,'face':face,'subset':subset}
        if subset>=4:
            result['repertoire_sha256']=digest(b''.join(raw[192+i*8:196+i*8] for i in range(count))).hex()
        if (face,subset) in FONT_PROVENANCE_IDENTITIES:result['provenance_sha256']=source.hex()
        return result
    locale,source_kind,codec,maxkey,provenance,reserved=DICT_META.unpack(meta)
    need((locale,source_kind) in [(b'ja\0\0\0\0\0\0',2),(b'zh-Hans\0',1)] and codec==1
         and maxkey==128 and provenance!=b'\0'*32 and reserved==b'\0'*16,'dictionary metadata')
    end=boff;previous=None
    for i in range(count):
        ko,kl,so,sl,cost,left,right,weight,attributes=DICT_ROW.unpack_from(raw,192+i*36)
        need(ko==end and 0<kl<=128 and so==ko+kl and 0<sl<=256 and sl<=len(raw)-so,'dictionary span')
        key,surface=raw[ko:ko+kl],raw[so:so+sl];text(key,128);text(surface,256)
        row=(key,surface,left,right,cost,weight,attributes)
        need(previous is None or previous<row,'dictionary sort/duplicate')
        need((source_kind==1 and cost==left==right==attributes==0) or
             (source_kind==2 and weight==0 and attributes in (0,1)),'dictionary unused score/attribute fields')
        end=so+sl;previous=row
    need(end==len(raw),'dictionary trailing bytes')
    return {'kind':'dictionary','count':count,'locale':locale.rstrip(b'\0').decode('ascii')}

def page_table(raw):
    need(0<len(raw)<=MAX_FONT,'page pack bounds')
    n=(len(raw)+PAGE_SIZE-1)//PAGE_SIZE
    return PAGE_HEADER.pack(b'PPGH1\0\0\0',1,64,PAGE_SIZE,len(raw),n,digest(raw),b'\0'*8)+b''.join(
        digest(raw[i:i+PAGE_SIZE]) for i in range(0,len(raw),PAGE_SIZE))

def verify_pages(table, raw):
    need(64<=len(table)<=64+32*(MAX_FONT//PAGE_SIZE),'page table size')
    magic,version,hsize,psize,size,count,whole,reserved=PAGE_HEADER.unpack_from(table)
    need(magic==b'PPGH1\0\0\0' and version==1 and hsize==64 and psize==PAGE_SIZE and reserved==b'\0'*8,'page header')
    need(0<size<=MAX_FONT and size==len(raw) and count==(size+PAGE_SIZE-1)//PAGE_SIZE
         and len(table)==64+32*count,'page count/size')
    need(whole==digest(raw),'page whole-pack hash')
    for i in range(count):
        need(table[64+i*32:96+i*32]==digest(raw[i*PAGE_SIZE:(i+1)*PAGE_SIZE]),'page hash')

def artifact_name(name):
    need(type(name) is str and NAME.fullmatch(name) is not None and '..' not in name,'artifact basename')
    return name

def manifest(artifacts, kinds, release, generation, slot):
    sha_bytes(release);integer(generation,1);need(slot in ('A','B'),'slot')
    need(set(artifacts)==set(kinds),'artifact type coverage')
    rows=[]
    for name in sorted(artifacts):
        artifact_name(name);raw=artifacts[name];kind=kinds[name]
        need(kind in ('font','dictionary','pages','notice'),'artifact kind')
        row={'name':name,'kind':kind,'bytes':len(raw),'sha256':digest(raw).hex()}
        if kind in ('font','dictionary'):
            row['pages']=name+'.pgh';row['identity']=validate_pack(raw)
        rows.append(row)
    result={'schema':'paos.resources.manifest.v1','release_sha256':release,'generation':generation,'slot':slot,'artifacts':rows}
    validate_manifest(canonical(result),release,generation,slot)
    return canonical(result)

def validate_manifest(raw, release, generation, slot):
    result=parse_json(raw,manifest_subset=True);fields(result,('schema','release_sha256','generation','slot','artifacts'))
    # All schema keys and permitted values are ASCII. Require exactly the host
    # encoding: sorted keys, compact separators, integer decimals, one final LF.
    # No escape grammar is needed by a native consumer of this subset.
    need(raw.isascii() and b'\\' not in raw and raw==canonical(result),'manifest canonical ASCII subset')
    sha_bytes(release);integer(generation,1);need(slot in ('A','B'),'expected slot')
    need(result['schema']=='paos.resources.manifest.v1' and result['release_sha256']==release
         and type(result['generation']) is int and result['generation']==generation and result['slot']==slot,'manifest wrong release/generation/slot')
    rows=result['artifacts'];need(type(rows) is list and 0<len(rows)<=64,'manifest count')
    names=set();total=0;previous='';pages=set()
    for row in rows:
        fields(row,('name','kind','bytes','sha256'),('pages','identity'))
        name=artifact_name(row['name']);need(name>previous and name not in names,'manifest name order/duplicate')
        kind=row['kind'];need(kind in ('font','dictionary','pages','notice'),'manifest kind')
        cap={'font':MAX_FONT,'dictionary':MAX_DICT,'pages':131136,'notice':MAX_JSON}[kind]
        total+=integer(row['bytes'],1,cap);sha_bytes(row['sha256'])
        if kind in ('font','dictionary'):
            need(row.get('pages')==name+'.pgh','manifest page table binding');pages.add(row['pages'])
            identity=row.get('identity')
            if kind=='font':
                fields(identity,('kind','count','width','height','bpp','face','subset'),('repertoire_sha256','provenance_sha256'))
                if (identity['face'],identity['subset']) in FONT_PROVENANCE_IDENTITIES:
                    need('provenance_sha256' in identity,'Japanese provenance digest required')
                    sha_bytes(identity['provenance_sha256'])
                else:need('provenance_sha256' not in identity,'unexpected font provenance digest')
                if type(identity['subset']) is int and identity['subset']>=4:
                    need('repertoire_sha256' in identity,'new font repertoire digest required')
                    sha_bytes(identity['repertoire_sha256']);need(generation>=2,'expanded font generation must exceed frozen1')
                else:need('repertoire_sha256' not in identity,'legacy font identity is frozen')
                integer(identity['count'],1,32768);integer(identity['width'],1,64);integer(identity['height'],1,64)
                need(type(identity['bpp']) is int and identity['bpp'] in (1,8) and
                     type(identity['face']) is int and type(identity['subset']) is int and
                     (identity['face'],identity['subset']) in FONT_IDENTITIES,'manifest font identity')
            else:
                fields(identity,('kind','count','locale'));integer(identity['count'],1,250000)
                need(identity['locale'] in ('ja','zh-Hans'),'manifest dictionary identity')
            need(identity['kind']==kind,'manifest identity kind')
        else:need('pages' not in row and 'identity' not in row,'unexpected page table/identity')
        names.add(name);previous=name
    by_name={r['name']:r for r in rows}
    need(pages=={r['name'] for r in rows if r['kind']=='pages'},'unbound/missing page table')
    need(all(by_name[n]['kind']=='pages' for n in pages),'page table kind')
    need(total+len(raw)<=MAX_SET,'generation size cap')
    return result

def validate_font_provenance(raw, scalars, rows, artifacts, source_pins):
    """Structural provenance and notice binding; approval is the requested digest."""
    c=parse_json(raw);need(raw==canonical(c),'font provenance canonical encoding')
    fields(c,('schema','face','subset','repertoire_sha256','intentional_blanks','sources'))
    need(c['schema']=='paos.font-provenance.v1' and type(c['face']) is int and c['face']==2
         and type(c['subset']) is int and c['subset']==5,'font provenance profile')
    need(c['repertoire_sha256']==digest(b''.join(struct.pack('<I',cp) for cp in scalars)).hex(),
         'font provenance repertoire digest')
    blanks=c['intentional_blanks'];spaces={0x20,0xA0,0x1680,*range(0x2000,0x200B),0x202F,0x205F,0x3000}
    need(type(blanks) is list and all(type(cp) is int for cp in blanks)
         and blanks==sorted(set(blanks)) and set(blanks)<=set(scalars)&spaces,'font provenance blank policy')
    need(type(c['sources']) is list and 1<=len(c['sources'])<=8,'font provenance source count')
    seen=set();ids=[];hashes=set()
    for s in c['sources']:
        fields(s,('id','bytes','sha256','origin','license','notice','copyright','scalars'))
        artifact_name(s['id'])
        need(s['id'] in source_pins and {k:v for k,v in s.items() if k!='scalars'}==source_pins[s['id']],
             'font provenance source registry pin')
        artifact_name(s['id']);ids.append(s['id']);integer(s['bytes'],1,20*1024**2);sha_bytes(s['sha256'])
        need(s['sha256'] not in hashes,'duplicate font provenance source');hashes.add(s['sha256'])
        need(s['license'] in ('OFL-1.1','Bitstream-Vera AND LicenseRef-DejaVu-Public-Domain AND LicenseRef-Arev'),
             'font provenance license')
        for key in ('origin','copyright'):
            need(type(s[key]) is str and 0<len(s[key])<=2048,'font provenance source text')
        assigned=s['scalars'];need(type(assigned) is list and assigned and len(assigned)<=32768
            and all(type(cp) is int for cp in assigned) and assigned==sorted(set(assigned)),
            'font provenance scalar list')
        for cp in assigned:scalar(cp)
        need(not seen.intersection(assigned),'overlapping font provenance assignments');seen.update(assigned)
        n=s['notice'];fields(n,('name','bytes','sha256'));artifact_name(n['name'])
        integer(n['bytes'],1,MAX_JSON);sha_bytes(n['sha256'])
        need(n['name'] in rows and rows[n['name']]['kind']=='notice'
             and len(artifacts[n['name']])==n['bytes'] and digest(artifacts[n['name']]).hex()==n['sha256'],
             'font provenance license notice binding')
    need(ids==sorted(set(ids)) and seen==set(scalars),'font provenance assignment union/order')
    return c

def verify_set(raw_manifest, artifacts, release, generation, slot, expected_identities=None):
    """Caller must authenticate manifest separately; all artifacts are owned bytes."""
    m=validate_manifest(raw_manifest,release,generation,slot)
    if expected_identities is not None:need(type(expected_identities) is dict,'requested identity object')
    need(type(artifacts) is dict and set(artifacts)=={r['name'] for r in m['artifacts']},'artifact set mismatch')
    rows={r['name']:r for r in m['artifacts']}
    for name,row in rows.items():
        raw=artifacts[name]
        need(type(raw) is bytes and len(raw)==row['bytes'] and digest(raw).hex()==row['sha256'],'artifact hash/size')
    results={}
    for name,row in rows.items():
        if row['kind'] in ('font','dictionary'):
            verify_pages(artifacts[row['pages']],artifacts[name])
            info=validate_pack(artifacts[name])
            need(info==row['identity'],'manifest pack identity mismatch')
            if (info.get('face'),info.get('subset')) in FONT_PROVENANCE_IDENTITIES:
                matches=[n for n,r in rows.items() if r['kind']=='notice' and r['sha256']==info['provenance_sha256']]
                need(len(matches)==1,'unique Japanese provenance artifact required')
                scalars=[FONT_ROW.unpack_from(artifacts[name],192+i*8)[0] for i in range(info['count'])]
                from rcq38_multisource_font_packs import approved_source_rows
                validate_font_provenance(artifacts[matches[0]],scalars,rows,artifacts,approved_source_rows())
            if expected_identities is not None and name in expected_identities:
                expected=expected_identities[name]
                need(type(expected) is dict,'requested resource identity object')
                if info['kind']=='font' and info['subset']>=4:
                    need('repertoire_sha256' in expected,'requested expanded font repertoire digest required')
                if (info.get('face'),info.get('subset')) in FONT_PROVENANCE_IDENTITIES:
                    need('provenance_sha256' in expected,'requested Japanese font provenance digest required')
                need(type(expected) is dict and expected.keys()<=info.keys() and
                     all(info[key]==val and type(info[key]) is type(val) for key,val in expected.items()),
                     'requested resource identity mismatch')
            results[name]=info
        elif row['kind']=='notice':
            try:artifacts[name].decode('utf-8',errors='strict')
            except UnicodeError as e:raise PackError('notice UTF-8') from e
    if expected_identities is not None:
        need(type(expected_identities) is dict and expected_identities.keys()<=results.keys(),'requested resource absent')
    return results

def read_host_set(directory, manifest_path, release, generation, slot):
    raw=read_bounded(manifest_path,MAX_JSON)
    m=validate_manifest(raw,release,generation,slot);directory=Path(directory)
    need(directory.is_dir() and not directory.is_symlink(),'host resource directory')
    artifacts={}
    for row in m['artifacts']:
        path=directory/row['name']
        need(path.is_file() and not path.is_symlink(),'missing/symlink host artifact')
        artifacts[row['name']]=read_bounded(path,row['bytes'])
    verify_set(raw,artifacts,release,generation,slot)
    return raw,artifacts

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',required=True);parser.add_argument('--directory',required=True)
    parser.add_argument('--release',required=True);parser.add_argument('--generation',required=True,type=int)
    parser.add_argument('--slot',required=True,choices=('A','B'));parser.add_argument('--expect')
    a=parser.parse_args(argv)
    try:
        raw,artifacts=read_host_set(a.directory,a.manifest,a.release,a.generation,a.slot)
        expected=parse_json(read_bounded(a.expect,MAX_JSON)) if a.expect else None
        result=verify_set(raw,artifacts,a.release,a.generation,a.slot,expected)
        print(canonical({'integrity_ok':True,'signature_verified_by_this_tool':False,'packs':result}).decode(),end='');return 0
    except (ValueError,OSError,TypeError,UnicodeError,struct.error) as e:
        print(canonical({'integrity_ok':False,'error':str(e)}).decode(),end='');return 2

if __name__=='__main__':sys.exit(main())
