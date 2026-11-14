#!/usr/bin/env python3
"""Product PDCT DATA generator and derived resident directory reference.

SPDX-License-Identifier: MPL-2.0
No signing, network, image build, or native admission occurs here.
"""
from __future__ import annotations
import argparse
from bisect import bisect_left
from collections import Counter
from itertools import chain, groupby
from pathlib import Path
import struct
import sys

import rcq38_build_resources as b
import rcq38_resource_pack as p

LOCALES = {'ja': ('ja', 2, 128, 1048576, 512),
           'zh-Hans': ('pinyin', 3, 64, 262144, 192)}
INDEX_HEADER = struct.Struct('<8sHH10I76s')       # 128 B, I1 PIDX1 contract
INDEX_SHARD = struct.Struct('<6I24s')            # 48 B
INDEX_ANCHOR = struct.Struct('<IIHH')           # 12 B
MAX_MATCHES = 512
CONTROL_BYTES = 4096
SLOT_BYTES = 16
CANDIDATE_BYTES = MAX_MATCHES * 8


class ProductError(p.PackError):
    """Typed generator refusal; never a candidate-filtering signal."""
    def __init__(self, code, detail):
        self.code = code
        super().__init__(code + ': ' + detail)


def require(ok, code, detail):
    if not ok:
        raise ProductError(code, detail)


def decode_rows(raw, locale):
    info = p.validate_pack(raw)
    require(info['kind'] == 'dictionary' and info['locale'] == locale,
            'PDCT_LOCALE', locale)
    for i in range(info['count']):
        ko, kl, so, sl, cost, left, right, weight, attr = p.DICT_ROW.unpack_from(raw, 192 + 36*i)
        yield (raw[ko:ko+kl], raw[so:so+sl], left, right, cost, weight, attr)


def surface_closure(rows, locale, coverage):
    scalars = {ord(c) for row in rows for c in row[1].decode('utf-8')}
    missing = sorted(scalars - coverage)
    require(not missing, 'GLYPH_CLOSURE', locale + ' ' + ','.join(f'U+{cp:04X}' for cp in missing))
    return {'count': len(scalars), 'u32le_sha256': p.digest(b''.join(struct.pack('<I', cp) for cp in sorted(scalars))).hex()}


def glyph_coverage(config):
    p.fields(config, ('schema', 'profiles'))
    p.need(config['schema'] == 'paos.product-dictionary.glyph-inputs.v1', 'glyph input schema')
    profiles = config['profiles']
    p.need(type(profiles) is list and 3 <= len(profiles) <= 7, 'glyph profile count')
    seen = set(); by_face = {1: set(), 2: set(), 3: set()}; pins = []; repertoires = {}
    for row in profiles:
        p.fields(row, ('path', 'bytes', 'sha256', 'face', 'subset', 'repertoire_sha256'))
        p.sha_bytes(row['sha256']); p.sha_bytes(row['repertoire_sha256'])
        raw = p.read_bounded(row['path'], p.MAX_FONT)
        require(len(raw) == row['bytes'] and p.digest(raw).hex() == row['sha256'], 'GLYPH_PIN', row['path'])
        info = p.validate_pack(raw)
        identity = (info.get('face'), info.get('subset'), info.get('bpp'))
        p.need(info['kind'] == 'font' and identity not in seen, 'glyph profile kind/duplicate')
        p.need((info['face'], info['subset']) in {(1,1), (1,4), (2,5), (3,6)}, 'product glyph profile')
        p.need((info['face'], info['subset']) == (row['face'], row['subset']), 'glyph requested profile')
        scalars = [p.FONT_ROW.unpack_from(raw, 192+i*8)[0] for i in range(info['count'])]
        rep = p.digest(b''.join(struct.pack('<I', cp) for cp in scalars)).hex()
        require(rep == row['repertoire_sha256'], 'GLYPH_REPERTOIRE_PIN', str(identity))
        profile = identity[:2]
        require(profile not in repertoires or repertoires[profile] == rep,
                'GLYPH_PROFILE_REPERTOIRE', str(profile))
        repertoires[profile] = rep
        seen.add(identity); by_face[info['face']].update(scalars)
        pins.append({k: row[k] for k in ('bytes','sha256','face','subset','repertoire_sha256')})
    p.need(all(by_face.values()), 'JA/SC/shared font profiles required')
    shared = by_face[1] | set(range(32, 127))
    return {loc: by_face[spec[1]] | shared for loc, spec in LOCALES.items()}, sorted(pins, key=lambda r: (r['face'],r['subset'],r['sha256']))


def ranking(row, locale, global_row):
    # Numeric signed JA cost; descending unsigned source frequency for Pinyin.
    score = row[4] if locale == 'ja' else -row[5]
    return (score, global_row)


def candidate_view(indexed_rows, locale):
    require(len(indexed_rows) <= MAX_MATCHES, 'MATCH_BUDGET', locale)
    ordered = sorted(indexed_rows, key=lambda item:ranking(item[1],locale,item[0]))
    seen = set(); candidates = []
    for global_row,row in ordered:
        if row[1] not in seen:
            seen.add(row[1]);candidates.append((global_row,row))
    return {'candidates':candidates,'rows':len(indexed_rows),'merged':len(indexed_rows)-len(candidates)}


def memory_layout(shard_count, anchor_count, key_bytes, ppgh_bytes, locale):
    *_, budget, slots = LOCALES[locale]
    sizes = [('header',128), ('shard_table',48*shard_count), ('anchors',12*anchor_count),
             ('key_pool',key_bytes), ('page_hash_tables',ppgh_bytes),
             ('page_slot_metadata',slots*SLOT_BYTES), ('candidate_handles',CANDIDATE_BYTES),
             ('control_and_hash_scratch',CONTROL_BYTES)]
    regions = []; offset = 0
    for name,size in sizes:
        offset = (offset+4095)//4096*4096
        regions.append({'name':name,'offset':offset,'bytes':size});offset += size
    require(offset <= budget, 'RESIDENT_BUDGET', locale)
    return {'budget':budget,'used':offset,'spare':budget-offset,'regions':regions,
            'page_size':4096,'cache_slots':slots,'cache_bytes':slots*4096,
            'index_authority':'derived from verified PDCT; reference snapshot is not shipped'}


def index_bytes(shards, locale):
    """Derived cache snapshot, NOT a new authority or an on-DATA artifact."""
    family, face, stride, budget, slots = LOCALES[locale]
    p.need(0 < len(shards) <= 32, 'directory shard count')
    rows = [list(decode_rows(raw, locale)) for raw in shards]
    flat_last = None
    for group in rows:
        require(flat_last is None or flat_last < group[0], 'GLOBAL_ORDER', locale)
        flat_last = group[-1]
    count = sum((len(group)+stride-1)//stride for group in rows)
    anchor_blob = bytearray(); pool = bytearray(); table = bytearray(); first = global_first = pg_offset = 0
    page_tables = []
    for raw, group in zip(shards, rows):
        n = (len(group)+stride-1)//stride
        pages = p.page_table(raw);page_tables.append(pages)
        table.extend(INDEX_SHARD.pack(global_first,len(group),len(raw),(len(raw)+4095)//4096,pg_offset,first,b'\0'*24))
        for i in range(0, len(group), stride):
            key = group[i][0]
            anchor_blob.extend(INDEX_ANCHOR.pack(global_first+i,len(pool),len(key),0))
            pool.extend(key)
        first += n
        global_first += len(group);pg_offset += len(pages)
    layout = memory_layout(len(shards),count,len(pool),pg_offset,locale)
    offsets = {row['name']:row['offset'] for row in layout['regions']}
    header = INDEX_HEADER.pack(b'PIDX1\0\0\0',1,1 if locale=='ja' else 2,stride,len(shards),count,len(pool),
                               *(offsets[name] for name in ('shard_table','anchors','key_pool','page_hash_tables','page_slot_metadata','candidate_handles')),
                               b'\0'*76)
    raw = bytearray(budget)
    for name,data in [('header',header),('shard_table',table),('anchors',anchor_blob),('key_pool',pool),('page_hash_tables',b''.join(page_tables))]:
        off = offsets[name];raw[off:off+len(data)] = data
    return bytes(raw)


def validate_index(raw, shards, locale):
    # A derived snapshot must equal authenticated PDCT, not merely self-hash.
    require(raw == index_bytes(shards, locale), 'INDEX_BINDING', locale)
    return raw


def lookup(raw_index, shards, locale, key):
    """Reference sparse lookup. Native caller must supply verified owned pages."""
    p.text(key,128)
    validate_index(raw_index, shards, locale)
    header = INDEX_HEADER.unpack_from(raw_index)
    shard_base,anchor_base,pool_base = header[7:10]
    anchors = [INDEX_ANCHOR.unpack_from(raw_index,anchor_base+12*i) for i in range(header[5])]
    keys = [raw_index[pool_base+off:pool_base+off+length] for _,off,length,_ in anchors]
    pos = bisect_left(keys,key)
    start = anchors[max(0,pos-1)][0]
    result = []
    for si, raw in enumerate(shards):
        global_first,nrows,_,_,_,first,_ = INDEX_SHARD.unpack_from(raw_index,shard_base+48*si)
        if global_first+nrows <= start:continue
        # A key may span an anchor or a shard boundary; never stop at a page.
        for ri in range(max(0,start-global_first),nrows):
            ko,kl,so,sl,cost,left,right,weight,attr = p.DICT_ROW.unpack_from(raw,192+ri*36)
            current = raw[ko:ko+kl]
            if current > key:
                return [row for _,row in candidate_view(result,locale)['candidates']]
            if current == key:
                result.append((global_first+ri,(current,raw[so:so+sl],left,right,cost,weight,attr)))
    return [row for _,row in candidate_view(result,locale)['candidates']]


def resident_layout(index, shards, locale):
    header = INDEX_HEADER.unpack_from(index)
    return memory_layout(len(shards),header[5],header[6],sum(len(p.page_table(raw)) for raw in shards),locale)


def write_candidate_goldens(shards, locale, path):
    """Every exact key, source scores, unique surfaces and explicit merge count.

    Host oracle only, outside the DATA generation and the resident arena.
    """
    rows = enumerate(chain.from_iterable(decode_rows(raw,locale) for raw in shards))
    totals = {'keys':0,'rows':0,'candidates':0,'merged':0,'max_candidates':0}
    with Path(path).open('xb') as stream:
        for key,group in groupby(rows,key=lambda item:item[1][0]):
            view = candidate_view(list(group),locale)
            line = {'key':key.decode('utf-8'),'rows':view['rows'],'merged':view['merged'],
                    'candidates':[{'row':index,'surface':row[1].decode('utf-8'),'cost':row[4],'weight':row[5]}
                                  for index,row in view['candidates']]}
            stream.write(p.canonical(line))
            totals['keys'] += 1;totals['rows'] += view['rows'];totals['merged'] += view['merged']
            totals['candidates'] += len(view['candidates']);totals['max_candidates'] = max(totals['max_candidates'],len(view['candidates']))
    return totals


def generate(inputs, glyph_config, release, generation, slot, output):
    r = b.registry(); coverage, font_pins = glyph_coverage(glyph_config)
    sources = [row for row in r['sources'] if row['group'] in ('mozc','rime-pinyin')]
    artifacts = {}; reports = {}; directories = {}
    for locale, (family,*_) in LOCALES.items():
        selected = [row for row in sources if row['group'] == ('mozc' if locale=='ja' else 'rime-pinyin')]
        rows = []
        for source in selected:
            rows.extend(b.parse_dictionary(b.pinned_bytes(inputs,source),family))
        closure = surface_closure(rows,locale,coverage[locale])  # refuse BEFORE any writes
        counts = Counter(row[0] for row in set(rows))
        require(max(counts.values()) <= MAX_MATCHES, 'MATCH_BUDGET', locale)
        chunks, report = b.dictionary_shards(rows,family,b.source_contract(selected))
        shards = [raw for raw,info in chunks]
        directory = index_bytes(shards,locale)
        directories[locale] = directory
        report.update(unique_keys=len(counts),max_candidates=max(counts.values()),surface_closure=closure,
                      resident=resident_layout(directory,shards,locale),directory_sha256=p.digest(directory).hex())
        reports[locale] = report
        for i,raw in enumerate(shards):artifacts[f'{family}-full-{i:03d}.pdct'] = raw
    notices = b.notice_artifacts(r,inputs,sources)  # validate full licence pins before publishing
    provenance = {'schema':'paos.product-dictionary.provenance.v1','source_registry_sha256':b.REGISTRY_SHA256,
                  'source_contract_sha256':p.digest(b.source_contract(sources)).hex(),
                  'sources':sources,'glyph_profiles':font_pins,
                  'notice_pins':{n:{'bytes':len(raw),'sha256':p.digest(raw).hex()} for n,raw in sorted(notices.items())},
                  'ranking':{'ja':'signed cost ascending, then global row ascending',
                             'zh-Hans':'source weight descending, then global row ascending'},
                  'deduplication':'PDCT exact identical rows only; candidate view merges equal surfaces keeping best-ranked row',
                  'format':'PDCT1/PPGH1 unchanged; host-derived PIDX1 snapshots are outside the generation'}
    report = b.finish(artifacts,r,inputs,sources,{'locales':reports},release,generation,slot,output,
                      extra_notices={'product-dictionary-provenance.json':p.canonical(provenance)})
    return report,directories


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs',type=Path,required=True)
    parser.add_argument('--glyph-config',type=Path,required=True)
    parser.add_argument('--glyph-config-sha256',required=True)
    parser.add_argument('--release-sha256',required=True)
    parser.add_argument('--generation',type=int,required=True)
    parser.add_argument('--slot',choices=['A','B'],required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--reference-index-output',type=Path,required=True)
    args = parser.parse_args()
    p.need(not args.output.exists() and not args.reference_index_output.exists(),'new output paths required')
    require(args.output.resolve() != args.reference_index_output.resolve()
            and args.output.resolve() not in args.reference_index_output.resolve().parents
            and args.reference_index_output.resolve() not in args.output.resolve().parents,
            'REFERENCE_PATH','reference snapshots must be outside DATA generation')
    raw = p.read_bounded(args.glyph_config,p.MAX_JSON);p.sha_bytes(args.glyph_config_sha256)
    require(p.digest(raw).hex()==args.glyph_config_sha256,'GLYPH_CONFIG_PIN',str(args.glyph_config))
    report,dirs = generate(args.inputs,p.parse_json(raw),args.release_sha256,args.generation,args.slot,args.output)
    args.reference_index_output.mkdir(parents=True)
    for locale,data in dirs.items():
        (args.reference_index_output/(locale+'.pidx')).write_bytes(data)
        family = LOCALES[locale][0]
        shards = [path.read_bytes() for path in sorted(args.output.glob(family+'-full-*.pdct'))]
        write_candidate_goldens(shards,locale,args.reference_index_output/(locale+'.golden.jsonl'))
    print(p.canonical({k:v for k,v in report.items() if k not in ('artifacts','locales')}).decode(),end='')


if __name__ == '__main__':
    try:main()
    except (p.PackError,OSError) as error:
        print('PRODUCT_DICTIONARY_REFUSED: '+str(error),file=sys.stderr);sys.exit(2)
