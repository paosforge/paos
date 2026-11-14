# SPDX-License-Identifier: MPL-2.0
"""Existing reviewed DATA site identity grammar; no image/factory reader."""
import hashlib
from pathlib import Path
import re
from catalog import fields, require, uint, canonical

MAX_SITES = 16384

SHA = re.compile('[0-9a-f]{64}\\Z')

SCOPES = ('src/gui/','src/svc/','src/boot/','src/bootmgr/','src/rescue/',
          'src/sec/','src/security/','src/config/','src/dev/input/','src/core/abi/')

def validate_sites(sites):
    fields(sites, ('schema', 'revision', 'inventory_snapshot', 'implementation_base',
                   'inventory_sha256', 'source_files', 'sites'))
    require(sites['schema'] == 'paos.localization.sites.v1', 'unknown site schema')
    uint(sites['revision'], minimum=1)
    for name in ['inventory_snapshot','implementation_base']:
        require(type(sites[name]) is str and re.fullmatch('[0-9a-f]{40}',sites[name]) is not None,'invalid source commit pin')
    require(type(sites['inventory_sha256']) is str and SHA.fullmatch(sites['inventory_sha256']) is not None,'invalid inventory pin')
    require(type(sites['sites']) is list and 0 < len(sites['sites']) <= MAX_SITES, 'invalid site count')
    require(type(sites['source_files']) is dict, 'invalid source pins')
    for path,pin in sites['source_files'].items():
        require(type(path) is str and path.startswith(SCOPES) and '..' not in Path(path).parts,'unscoped source pin')
        fields(pin,('inventory_sha256','current_sha256'))
        require(all(type(pin[k]) is str and SHA.fullmatch(pin[k]) is not None for k in pin),'invalid source pin digest')
    ids, keys = set(), set()
    for row in sites['sites']:
        fields(row, ('id', 'key', 'path', 'line', 'label', 'literal_ordinal', 'english',
                     'encoding', 'category', 'domain', 'decision', 'rationale',
                     'runtime_eligible', 'source_sha256', 'current_source_sha256', 'anchor_status'),
                    ('parent_id','literal_component','catalog_retired','replacement_ids'))
        uint(row['id'], minimum=1); uint(row['line'], minimum=1); uint(row['literal_ordinal'])
        require(row['id'] not in ids and row['key'] not in keys, 'duplicate site ID/key')
        require(type(row['english']) is str and bool(row['english']), 'invalid source literal')
        require(type(row['rationale']) is str and bool(row['rationale']), 'missing adjudication rationale')
        require(type(row['runtime_eligible']) is bool, 'runtime eligibility must be boolean')
        require(row['domain'] in ['native', 'manager', 'rescue'], 'unknown image domain')
        require(row['encoding'] in ['utf8', 'utf16le'], 'unknown literal encoding')
        require(row['decision'] in ['translate', 'structured_message', 'form_container',
                                     'machine_contract', 'fixture_data', 'tombstone'], 'unknown adjudication decision')
        if 'catalog_retired' in row:
            require(type(row['catalog_retired']) is bool and row['catalog_retired'] and not row['runtime_eligible'], 'retired site cannot be eligible')
        if row['decision']=='tombstone':
            require(row.get('catalog_retired') is True, 'tombstone requires retired message contract')
        if 'parent_id' in row or 'literal_component' in row:
            require('parent_id' in row and 'literal_component' in row, 'incomplete component identity')
            uint(row['parent_id'], minimum=1);uint(row['literal_component'],maximum=1)
        if 'replacement_ids' in row:
            require(row['decision']=='tombstone' and type(row['replacement_ids']) is list
                    and 0<len(row['replacement_ids'])<=16, 'invalid tombstone replacements')
            require(all(type(i) is int and 0<i<=0xffffffff for i in row['replacement_ids'])
                    and len(set(row['replacement_ids']))==len(row['replacement_ids']), 'invalid replacement ID')
        require(not row['runtime_eligible'] or (row['decision'] == 'translate' and
                row['anchor_status'] == 'same_literal'), 'ineligible source site')
        require(row['anchor_status'] in ['same_literal','source_drift'], 'unknown source anchor status')
        require(row['path'] in sites['source_files'] and not row['path'].startswith('src/dev/net/'), 'unscoped source path')
        pin = sites['source_files'][row['path']]
        fields(pin, ('inventory_sha256', 'current_sha256'))
        require(row['source_sha256'] == pin['inventory_sha256'] and
                row['current_source_sha256'] == pin['current_sha256'], 'site/source pin mismatch')
        require(type(row['key']) is str and re.fullmatch('[a-z][a-z0-9_.-]{0,127}',row['key']) is not None, 'invalid stable key')
        require(all(type(row[k]) is str and SHA.fullmatch(row[k]) for k in ['source_sha256','current_source_sha256']), 'invalid source digest')
        ids.add(row['id']); keys.add(row['key'])
    result={r['id']: r for r in sites['sites']}
    for row in result.values():
        if 'parent_id' in row:
            require(row['parent_id'] in result and result[row['parent_id']]['decision']=='tombstone'
                    and row['id'] in result[row['parent_id']].get('replacement_ids',[]), 'component/tombstone linkage')
        if 'replacement_ids' in row:
            require(all(i in result and result[i].get('parent_id')==row['id'] for i in row['replacement_ids']), 'missing replacement record')
    return result

def site_digest(sites):
    validate_sites(sites)
    return hashlib.sha256(canonical(sites)).digest()
