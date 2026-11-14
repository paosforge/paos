# SPDX-License-Identifier: MPL-2.0
"""Existing PCAT1 compiler/validator, selected public deterministic API."""
unicodedata = None


from collections import Counter

import hashlib

import json

from pathlib import Path

import re

import struct

LOCALES = ('en', 'es', 'fr', 'de', 'ja', 'zh-Hans')

MAX_CATALOG = 1024 * 1024

MAX_ENTRIES = 16384

MAX_TEXT = 8192

MAX_SOURCE = 16 * 1024 * 1024

HEADER = struct.Struct('<8sHHIIII32sI')

ENTRY = struct.Struct('<IIII')

MAGIC = b'PCAT1\0\0\0'

KEY = re.compile(r'[a-z][a-z0-9_.-]{0,127}\Z')

PARAM = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')

TEMPLATE = re.compile(r'\{\{|\}\}|\{([A-Za-z_][A-Za-z0-9_]{0,63})\}')

PARAM_TYPES = {'text', 'uint', 'path', 'fingerprint'}

class CatalogError(ValueError):
    pass

def require(ok, detail):
    if not ok:
        raise CatalogError(detail)

def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')

def _object(pairs):
    result = {}
    for k, v in pairs:
        require(k not in result, f'duplicate JSON key: {k}')
        result[k] = v
    return result

def load_json(path, limit=MAX_SOURCE):
    with Path(path).open('rb') as f:
        raw = f.read(limit + 1)
    require(len(raw) <= limit, 'JSON exceeds byte limit')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_object,
                          parse_constant=lambda x: (_ for _ in ()).throw(CatalogError('nonfinite JSON')))
    except (UnicodeError, ValueError, RecursionError) as e:
        raise CatalogError(f'invalid UTF-8 JSON: {e}') from e

def fields(obj, required, optional=()):
    require(type(obj) is dict, 'expected object')
    require(set(required) <= obj.keys() <= set(required) | set(optional),
            f'object fields must be {sorted(required)}; optional {sorted(optional)}')

def uint(value, maximum=0xffffffff, minimum=0):
    require(type(value) is int and minimum <= value <= maximum, 'integer out of range')
    return value

def text_bytes(text):
    require(type(text) is str and bool(text), 'message must be nonempty text')
    try:
        raw = text.encode('utf-8', errors='strict')
    except UnicodeError as e:
        raise CatalogError('message contains invalid Unicode scalar') from e
    require(len(raw) <= MAX_TEXT, 'message exceeds byte limit')
    require(not any((ord(c) < 32 and c != '\n') or 127 <= ord(c) < 160
                    or unicodedata.category(c) == 'Cf' or ord(c) == 0x034f
                    for c in text), 'message contains forbidden control or bidi override')
    return raw

def placeholders(text):
    text_bytes(text)
    result = Counter()
    remainder = TEMPLATE.sub('', text)
    require('{' not in remainder and '}' not in remainder,
            'placeholder requires {name} or escaped braces, without format/conversion')
    for match in TEMPLATE.finditer(text):
        if match.group(1) is not None: result[match.group(1)] += 1
    return result

def validate_source(source):
    fields(source, ('schema', 'revision', 'messages', 'locales'), ('sites_sha256',))
    require(source['schema'] == 'paos.pcat.source.v1', 'unknown source schema')
    uint(source['revision'], minimum=1)
    if 'sites_sha256' in source:
        require(type(source['sites_sha256']) is str and re.fullmatch('[0-9a-f]{64}',source['sites_sha256']) is not None,
                'invalid reviewed-site digest')
    messages = source['messages']
    require(type(messages) is list and 0 < len(messages) <= MAX_ENTRIES, 'invalid message count')
    ids, keys = set(), set()
    for m in messages:
        fields(m, ('id', 'key', 'english', 'params', 'critical'), ('notes', 'tombstone'))
        uint(m['id'], minimum=1)
        require(m['id'] not in ids, 'duplicate message ID')
        require(type(m['key']) is str and KEY.fullmatch(m['key']) is not None, 'invalid message key')
        require(m['key'] not in keys, 'duplicate message key')
        require(type(m['critical']) is bool, 'critical must be boolean')
        require(type(m.get('tombstone', False)) is bool, 'tombstone must be boolean')
        require(type(m['params']) is dict, 'params must be object')
        for name, kind in m['params'].items():
            require(type(name) is str and PARAM.fullmatch(name) is not None and
                    type(kind) is str and kind in PARAM_TYPES, 'invalid typed parameter')
        require(set(placeholders(m['english'])) == set(m['params']), 'English parameter declarations differ')
        if 'notes' in m:
            require(type(m['notes']) is str and len(m['notes'].encode('utf-8')) <= MAX_TEXT, 'invalid notes')
        ids.add(m['id']); keys.add(m['key'])
    require(type(source['locales']) is dict and set(source['locales']) == set(LOCALES), 'exactly six locale objects required')
    by_key = {m['key']: m for m in messages if not m.get('tombstone', False)}
    active_keys = set(by_key)
    for locale, translations in source['locales'].items():
        require(type(translations) is dict and translations.keys() <= active_keys, 'unknown or retired translation key')
        if locale == 'en':
            require(translations.keys() == active_keys, 'English coverage must be complete')
        for key, text in translations.items():
            require(placeholders(text) == placeholders(by_key[key]['english']), 'translation placeholder multiset differs')
            if locale == 'en':
                require(text == by_key[key]['english'], 'English translation differs from native fallback')
    return sorted(messages, key=lambda m: m['id'])

def schema_digest(source):
    messages = validate_source(source)
    contract = {'schema': source['schema'], 'revision': source['revision'], 'messages': messages}
    if 'sites_sha256' in source: contract['sites_sha256'] = source['sites_sha256']
    return hashlib.sha256(canonical(contract)).digest()

def compile_catalog(source, locale, require_complete=False):
    messages = [m for m in validate_source(source) if not m.get('tombstone', False)]
    require(locale in LOCALES, 'unknown locale')
    strings = source['locales'][locale]
    missing = [m['key'] for m in messages if m['key'] not in strings]
    require(not require_complete or not missing, 'incomplete translation coverage')
    selected = [m for m in messages if m['key'] in strings]
    offset = HEADER.size + ENTRY.size * len(selected)
    table, blob = bytearray(), bytearray()
    for m in selected:
        raw = text_bytes(strings[m['key']])
        table.extend(ENTRY.pack(m['id'], offset + len(blob), len(raw), int(m['critical'])))
        blob.extend(raw)
    total = offset + len(blob)
    require(total <= MAX_CATALOG, 'catalog exceeds byte limit')
    result = HEADER.pack(MAGIC, 1, LOCALES.index(locale), 0, source['revision'],
                         len(selected), offset, schema_digest(source), total) + table + blob
    return bytes(result), missing

def decode_catalog(raw, source):
    """Validate structurally AND against the supplied reviewed authoring schema."""
    messages = validate_source(source)
    require(HEADER.size <= len(raw) <= MAX_CATALOG, 'invalid catalog size')
    magic, version, locale_id, flags, revision, count, blob_off, digest, total = HEADER.unpack_from(raw)
    require(magic == MAGIC and version == 1 and locale_id < len(LOCALES) and flags == 0, 'invalid catalog header')
    require(revision == source['revision'] and digest == schema_digest(source), 'catalog schema/revision mismatch')
    require(total == len(raw) and count <= MAX_ENTRIES and blob_off == HEADER.size + count * ENTRY.size
            and blob_off <= total, 'invalid catalog bounds')
    by_id = {m['id']: m for m in messages if not m.get('tombstone', False)}
    previous, end, result = 0, blob_off, {}
    for i in range(count):
        ident, offset, size, entry_flags = ENTRY.unpack_from(raw, HEADER.size + i * ENTRY.size)
        require(ident > previous and ident in by_id, 'duplicate, unsorted or unknown ID')
        m = by_id[ident]
        require(entry_flags == int(m['critical']), 'message flags mismatch')
        require(offset == end and 0 < size <= MAX_TEXT and size <= total - offset, 'invalid message span')
        try:
            text = raw[offset:offset + size].decode('utf-8', errors='strict')
        except UnicodeError as e:
            raise CatalogError('invalid catalog UTF-8') from e
        require(placeholders(text) == placeholders(m['english']), 'catalog placeholder multiset differs')
        if locale_id == 0:
            require(text == m['english'], 'English catalog differs from fallback')
        result[ident] = text
        previous, end = ident, offset + size
    require(end == total, 'catalog trailing bytes')
    if locale_id == 0:
        require(len(result) == len(by_id), 'English catalog incomplete')
    return LOCALES[locale_id], result

def validate_revision(previous, source):
    old = {m['id']: m for m in validate_source(previous)}
    new = {m['id']: m for m in validate_source(source)}
    require(source['revision'] == previous['revision'] + 1, 'catalog revision must advance by one')
    require(old.keys() <= new.keys(), 'retain retired IDs as reserved records')
    for ident,m in old.items():
        require(all(m[k] == new[ident][k] for k in ['key','english','params','critical']), 'message ID reused for a different contract')
        require(not m.get('tombstone', False) or new[ident].get('tombstone', False), 'retired message ID cannot be revived')
    require(all(ident > max(old, default=0) for ident in new.keys()-old.keys()), 'new message IDs must advance the high-water mark')

def site_critical(row):
    return row['category']=='security_consent' or row['path'].endswith(('power_exec.asm','start_programs.asm'))

def bind_source_sites(source, sites):
    from site_map import validate_sites, site_digest
    require(source.get('sites_sha256') == site_digest(sites).hex(), 'catalog/reviewed-site map mismatch')
    rows = validate_sites(sites)
    messages = validate_source(source)
    require({m['id'] for m in messages if m.get('tombstone', False)} ==
            {i for i,r in rows.items() if r.get('catalog_retired', False)},
            'catalog omits or adds reserved tombstone IDs')
    require({m['id'] for m in source['messages'] if not m.get('tombstone', False)} == {i for i,r in rows.items() if r['runtime_eligible']},
            'catalog omits or adds reviewed display IDs')
    for m in messages:
        require(m['id'] in rows, 'catalog ID missing in reviewed-site map')
        r = rows[m['id']]
        require(r['runtime_eligible'] != m.get('tombstone', False), 'catalog eligibility/tombstone differs from site map')
        require(m['key'] == r['key'] and m['english'] == r['english'], 'catalog message differs from reviewed source site')
        require(not site_critical(r) or m['critical'], 'catalog downgrades a critical display message')

def build(source, require_complete=False, previous=None, sites=None):
    validate_source(source)
    if 'sites_sha256' in source:
        require(sites is not None, 'catalog requires reviewed-site map')
        bind_source_sites(source,sites)
    else:
        require(sites is None, 'catalog has no reviewed-site binding')
    if source['revision'] != 1:
        require(previous is not None, 'catalog revision requires previous reviewed schema')
        validate_revision(previous,source)
    else:
        require(previous is None, 'initial revision cannot have previous schema')
    artifacts, coverage = {}, {}
    active_count = sum(not m.get('tombstone', False) for m in source['messages'])
    for locale in LOCALES:
        raw, missing = compile_catalog(source, locale, require_complete)
        artifacts[locale + '.pcat'] = raw
        coverage[locale] = {'translated': active_count - len(missing),
                            'total': active_count, 'reserved': len(source['messages'])-active_count, 'missing': missing,
                            'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    artifacts['coverage.json'] = canonical({'schema': 'paos.pcat.coverage.v1',
                                           'complete': all(not x['missing'] for x in coverage.values()),
                                           'locales': coverage})
    return artifacts
