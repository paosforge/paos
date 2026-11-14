# SPDX-License-Identifier: MPL-2.0
"""Selected existing UI/help catalog and Unifont emitter; original native bytes preserved.
Historical factory path strings in generated comments and DATA pins are identities,
not filesystem inputs. Only third_party/localization is read for those identities.
"""
import hashlib
import json
from pathlib import Path
import re
import catalog as K
unicodedata = None

def legacy(name):
    return name.replace('third_party/localization/', 'gauntlet_v2/docs/localization/')

SOURCE = 'third_party/localization/catalog.rc1.v1.json'


SITES = 'third_party/localization/source_sites.v1.json'


GLYPH_HEX = 'third_party/fonts/unifont/unifont-ui-subset.hex'


HELP_SOURCE = 'third_party/localization/catalog.offline-help.en.v1.json'


HELP_PAGES = 'third_party/localization/offline_help.pages.v1.json'


HELP_BAND = (6000, 6099)


HELP_PREFIX = 'help.offline.'


HELP_KINDS = ('instruction', 'advice', 'explanation', 'limitation')


HELP_VALUE_MAX = 64


HELP_RENDERED_MAX = 255


L5_SOURCE = 'third_party/localization/catalog.l5.v1.json'


GLOSSARY = 'third_party/localization/glossary.rc1.v1.json'


GLOSSARY_MOK = 'third_party/localization/glossary.installer-mok.rc1.v1.json'


DNT_MAX = 64


PUNCTUATION = (0xFF08, 0xFF09, 0xFF0C, 0xFF1A, 0xFF1B, 0xFF1F, 0x3002)


ENDONYMS = ('日本語', '简体中文')


KANA = (*range(0x3041, 0x3097), *range(0x30A1, 0x30FB))

# RCQ-38 step B (root 2026-10-16 19:12:27): every JIS X 0208 level-1 and GB2312 level-1 ideograph, so an IME candidate
# paints from the subset and not only the catalogs' own ideographs. The set is Unicode 15.1.0 Unihan's normative IRG
# sources J0 (JIS X 0208, rows 16-47) and G0 (GB2312, rows 16-55); LEVEL1 holds those lines verbatim, each source
# exactly its standard count, cut from the pinned upstream file by `level1 --unihan` (bind_check) / the recipe.
LEVEL1 = 'third_party/localization/Unihan_IRGSources.level1.txt'
UNIHAN_IRG_SHA256 = 'a3bcdfd405e1ace254ab7f88ead8dc424f112123fb940c32cb6374c02102dc6e'   # Unihan.zip 15.1.0 member
LEVEL1_SETS = {'kIRG_JSource': ('J0', 16, 47, 2965), 'kIRG_GSource': ('G0', 16, 55, 3755)}
LEVEL1_HEADER = 11                          # upstream's leading comment lines: name, date, version, copyright, terms
LEVEL1_LINE = re.compile(r'U\+([0-9A-F]{4,5})\t(kIRG_[JG]Source)\t([JG]0)-([0-9A-F]{2})([0-9A-F]{2})')


LABEL = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')


class BindError(ValueError):
    pass


def need(ok, detail):
    if not ok:
        raise BindError(detail)


def load(root):
    source = K.load_json(root / SOURCE)
    sites = K.load_json(root / SITES)
    rows = {r['id']: r for r in sites['sites']}
    active = [m for m in K.validate_source(source) if not m.get('tombstone', False)]
    return source, sites, rows, active


def id_names(active, rows):
    """Message id -> L10N_ID_ name. A label with several census literals takes its ordinal as a suffix."""
    counts = {}
    for m in active:
        label = rows[m['id']]['label']
        counts[label] = counts.get(label, 0) + 1
    names = {}
    for m in active:
        r = rows[m['id']]
        need(LABEL.fullmatch(r['label']) is not None, f"id {m['id']}: label {r['label']!r} is not a nasm name")
        names[m['id']] = (f"L10N_ID_{r['label']}" if counts[r['label']] == 1
                          else f"L10N_ID_{r['label']}_{r['literal_ordinal']}")
    need(len(set(names.values())) == len(names), 'two records share an id name')
    return names


def db(raw):
    return ['    db ' + ','.join(f'0x{b:02x}' for b in raw[i:i + 16]) for i in range(0, len(raw), 16)]


def load_help(root):
    """The help catalog source (unbound: no reviewed-site map), its active records and the pages file."""
    source = K.load_json(root / HELP_SOURCE)
    active = [m for m in K.validate_source(source) if not m.get('tombstone', False)]
    pages = K.load_json(root / HELP_PAGES)
    return source, active, pages


def help_name(key):
    need(key.startswith(HELP_PREFIX), f'help key {key!r} is not {HELP_PREFIX}*')
    name = 'L10N_HELP_ID_' + key[len(HELP_PREFIX):].replace('.', '_')
    need(LABEL.fullmatch(name) is not None, f'help key {key!r} makes no nasm name')
    return name


def help_tables(source, active, pages):
    """(pages [(title id, first block, n blocks)], blocks [(msg id, kind, first param, n params)],
    params [(name, value)]) in the accepted DATA order. Refuses a pages file that does not match the catalog."""
    need(pages.get('schema') == 'paos.offline_help.pages.v1', 'unknown pages schema')
    need(pages.get('catalog') == Path(HELP_SOURCE).name, f"pages file names catalog {pages.get('catalog')!r}")
    alloc = pages.get('numeric_id_allocation', {})
    need((alloc.get('first'), alloc.get('proposed_range_last')) == HELP_BAND,
         f'pages file id allocation {alloc.get("first")}..{alloc.get("proposed_range_last")} != band {HELP_BAND}')
    by_key = {m['key']: m for m in active}
    used, out_pages, out_blocks, out_params = [], [], [], []
    for page in pages['pages']:
        need(page['title_key'] in by_key, f"page {page['id']}: no record {page['title_key']}")
        used.append(page['title_key'])
        need(not template_names(by_key[page['title_key']]['english'], {}),
             f"page {page['id']}: title has a template without static values")
        need(page['blocks'] and len(out_blocks) + len(page['blocks']) <= 255, f"page {page['id']}: block count")
        out_pages.append((by_key[page['title_key']]['id'], len(out_blocks), len(page['blocks'])))
        for b in page['blocks']:
            m = by_key.get(b['message_key'])
            need(m is not None, f"page {page['id']}: no record {b['message_key']}")
            used.append(b['message_key'])
            need(b['kind'] in HELP_KINDS, f"{b['message_key']}: kind {b['kind']!r} has no L10N_HELP_KIND constant")
            values = b['static_params']
            need(set(values) == set(m['params']), f"{b['message_key']}: static values {sorted(values)} != "
                                                  f"parameters {sorted(m['params'])}")
            bad = template_names(m['english'], values)
            need(not bad, f"{b['message_key']}: {bad}")
            for name, v in values.items():
                need(type(name) is str and 0 < len(name) <= HELP_VALUE_MAX and name.isascii()
                     and name.isprintable() and '\\' not in name,
                     f"{b['message_key']}: parameter name is not 1..{HELP_VALUE_MAX} B of printable ASCII without a backslash")
                val = v['value']
                need(v.get('translate_value') is False and v.get('escape_for_display') is True,
                     f"{b['message_key']}: {name} must be untranslated and escaped for display")
                need(type(val) is str and 0 < len(val) <= HELP_VALUE_MAX and val.isascii() and val.isprintable()
                     and '\\' not in val, f"{b['message_key']}: {name} value is not 1..{HELP_VALUE_MAX} B of "
                                           'printable ASCII without a backslash')
            rendered = compose_help(m['english'], values)
            need(len(rendered.encode('utf-8')) <= HELP_RENDERED_MAX,
                 f"{b['message_key']}: rendered {len(rendered.encode('utf-8'))} B > {HELP_RENDERED_MAX}")
            need(len(out_params) + len(values) <= 255, 'parameter count')
            out_blocks.append((m['id'], HELP_KINDS.index(b['kind']) + 1, len(out_params), len(values)))
            out_params += list(values.items())
    dup = sorted({k for k in used if used.count(k) > 1})
    need(not dup, f'pages use a record more than once: {dup}')
    unused = sorted(set(by_key) - set(used))
    need(not unused, f'pages leave records unused: {unused}')
    return out_pages, out_blocks, [(n, v['value']) for n, v in out_params]


def template_names(text, values):
    """(H1b) what l10n_paint_fmt would refuse in a help template: a '{' or '}' outside a {name} (escaped braces
    included: the formatter takes none), and a {name} with no static value. '' when it composes."""
    names = re.findall(r'\{([^{}]*)\}', text)
    if '{' in re.sub(r'\{[^{}]*\}', '', text) or '}' in re.sub(r'\{[^{}]*\}', '', text):
        return 'a brace outside a {name} (the formatter takes no escaped braces)'
    unknown = sorted(set(n for n in names if n not in values))
    return f'{{{unknown[0]}}} has no static value' if unknown else ''


def compose_help(text, values):
    """Substitute original template occurrences once; braces in values stay literal, as in the native formatter."""
    return re.sub(r'\{([^{}]*)\}', lambda g: values[g[1]]['value'], text)


def help_rendered(source, active, pages):
    """(H1b) [(message id, the text l10n_paint_fmt composes)] for every title and block, in DATA order. A value is
    printable ASCII without a backslash (help_tables refuses any other), so its escape is itself."""
    by_key = {m['key']: m for m in active}
    out = []
    for page in pages['pages']:
        out.append((by_key[page['title_key']]['id'], by_key[page['title_key']]['english']))
        for b in page['blocks']:
            m = by_key[b['message_key']]
            text = compose_help(m['english'], b['static_params'])
            out.append((m['id'], text))
    return out


def dnt_spans(root, pages):
    """(H1, root 2026-10-11 04:00:26) the glossary's multi-word do-not-translate spans, as DATA for H1b's wrap:
    glossary.rc1's preserve_exact (the glossary the pages file pins by SHA-256) and the installer-mok companion's
    do_not_translate terms (it extends that same SHA-256). Longest first, then by bytes. Refuses an unpinned
    glossary, a DNT term whose renderings differ from its English, and a span that is not printable ASCII."""
    raw = (root / GLOSSARY).read_bytes()
    pin = pages.get('glossary', {})
    need(pin.get('path') == legacy(GLOSSARY) and pin.get('sha256') == hashlib.sha256(raw).hexdigest(),
         f'{legacy(HELP_PAGES)} does not pin {legacy(GLOSSARY)} at its current SHA-256')
    core, mok = json.loads(raw), K.load_json(root / GLOSSARY_MOK)
    ext = mok.get('extends', {})
    need(ext.get('file') == Path(GLOSSARY).name and ext.get('sha256') == pin['sha256'],
         f'{legacy(GLOSSARY_MOK)} does not extend {legacy(GLOSSARY)} at its current SHA-256')
    spans = list(core['preserve_exact'])
    for t in mok['terms']:
        if t.get('do_not_translate') is True:
            need(set(t['renderings'].values()) == {t['en']}, f"DNT term {t['id']}: a rendering differs from {t['en']!r}")
            spans.append(t['en'])
    out = sorted({x for x in spans if ' ' in x}, key=lambda x: (-len(x), x))
    for x in out:
        need(len(x) <= DNT_MAX and x.isascii() and x.isprintable() and x == x.strip() and '  ' not in x,
             f'DNT span {x!r} is not 1..{DNT_MAX} B of printable ASCII with single inner spaces')
    return out


def dnt_list(root):
    """The DNT spans of the tree at root (what l10n_wrap reads from the include)."""
    return dnt_spans(root, K.load_json(root / HELP_PAGES))


def help_emit(root):
    """(lines outside the trusted range, lines inside it, the help PCAT1, names)."""
    source, active, pages = load_help(root)
    need(all(HELP_BAND[0] <= m['id'] <= HELP_BAND[1] for m in active), 'a help record is outside the help band')
    en = K.build(source)['en.pcat']
    names = {m['id']: help_name(m['key']) for m in active}
    need(len(set(names.values())) == len(names), 'two help records share an id name')
    t_pages, t_blocks, t_params = help_tables(source, active, pages)
    strtab, offs = bytearray(), {}
    for s in [n for n, _ in t_params] + [v for _, v in t_params]:
        if s not in offs:
            offs[s] = len(strtab)
            strtab += s.encode('ascii') + b'\0'
    need(len(strtab) <= 0xFFFF, 'help string table exceeds 64 KiB')
    src_sha = hashlib.sha256((root / HELP_SOURCE).read_bytes()).hexdigest()
    pages_sha = hashlib.sha256((root / HELP_PAGES).read_bytes()).hexdigest()
    out = [f'; help   {legacy(HELP_SOURCE)} sha256 {src_sha}',
           f'; pages  {legacy(HELP_PAGES)} sha256 {pages_sha}',
           '; RCQ-38 offline-help H1: the English help PCAT1 lies INSIDE the trusted range, after the UI catalog;',
           '; its expectations and the page/block/parameter tables lie outside it. Tables hold ids, indexes and',
           '; string-table offsets, never a label pointer. Static values are data: painted escaped (t5).',
           f"L10N_HELP_REVISION  equ {source['revision']}",
           f'L10N_HELP_EN_BYTES  equ {len(en)}',
           f'L10N_HELP_ID_FIRST  equ {HELP_BAND[0]}',
           f'L10N_HELP_ID_LAST   equ {HELP_BAND[1]}',
           f'L10N_HELP_PAGES     equ {len(t_pages)}',
           f'L10N_HELP_BLOCKS    equ {len(t_blocks)}',
           f'L10N_HELP_PARAMS    equ {len(t_params)}']
    out += [f'L10N_HELP_KIND_{k.upper()} equ {i + 1}' for i, k in enumerate(HELP_KINDS)]
    out += [f'{names[ident]} equ {ident}' for ident in sorted(names)]
    out += ['align 8, db 0',
            'l10n_help_en_expect:                    ; schema SHA-256 (32) then artifact SHA-256 (32): context +8..+72']
    out += db(K.schema_digest(source) + hashlib.sha256(en).digest())
    out += ['l10n_help_pages:                        ; per page: dw title id, db first block, db block count']
    out += [f'    dw {t}\n    db {f}, {n}' for t, f, n in t_pages]
    out += ['l10n_help_blocks:                       ; per block: dw message id, db kind, db first parameter, db count']
    out += [f'    dw {i}\n    db {k}, {f}, {n}' for i, k, f, n in t_blocks]
    out += ['l10n_help_params:                       ; per parameter: dw name, dw value (l10n_help_strtab offsets)']
    out += [f'    dw {offs[n]}, {offs[v]}' for n, v in t_params]
    out += ['l10n_help_strtab:                       ; NUL-terminated printable ASCII']
    out += db(bytes(strtab))
    spans = dnt_spans(root, pages)
    out += [f'; DNT    {legacy(GLOSSARY)} preserve_exact + {legacy(GLOSSARY_MOK)} do_not_translate, multi-word only.',
            '; l10n_wrap (gui/l10n_paint) never breaks inside one that fits a row (H1b, root 2026-10-11 04:00:26).',
            f'L10N_DNT_SPANS      equ {len(spans)}',
            'l10n_dnt_spans:                         ; per span: db length, its bytes; longest first; db 0 ends']
    for x in spans:
        out += [f'    db {len(x)}'] + db(x.encode('ascii'))
    out += ['    db 0']
    return out, ['l10n_cat_help_en:'] + db(en), en, names


LOCALE_TAGS = ('es', 'fr', 'de', 'ja', 'zh-Hans')      # lang_prefs ordinals 1..5 == PCAT1 locale ids


def locale_emit(root, source, sites, en, help_en):
    """(RCQ-38 catalogs, root 2026-10-16 19:12:27) (lines outside the trusted range, lines inside it) for the five
    other locales. Their UI and help PCAT1 follow the English pair inside the range. Outside it, per selection
    1..5: the UI then help schema + artifact SHA-256, and numeric offsets from l10n_catalog_start with byte counts
    (never a label operand: the image is org 0)."""
    need(tuple(K.LOCALES[1:]) == LOCALE_TAGS, 'PCAT1 locale ids are not the lang_prefs ordinals')
    help_source = load_help(root)[0]
    ui, hp = K.build(source, sites=sites), K.build(help_source)
    ui_schema, help_schema = K.schema_digest(source), K.schema_digest(help_source)
    at = len(en) + len(help_en)
    expect, table, inside = [], [], []
    for loc in LOCALE_TAGS:
        u, h = ui[loc + '.pcat'], hp[loc + '.pcat']
        name = loc.lower().replace('-', '_')
        table.append(f'    dd {at}, {len(u)}, {at + len(u)}, {len(h)}')
        expect += db(ui_schema + hashlib.sha256(u).digest() + help_schema + hashlib.sha256(h).digest())
        inside += [f'l10n_cat_{name}:'] + db(u) + [f'l10n_cat_help_{name}:'] + db(h)
        at += len(u) + len(h)
    out = ['; RCQ-38 catalogs (root 2026-10-16 19:12:27): the PCAT1 of the five other locales, UI then help, lie INSIDE',
           '; the trusted range after the English pair. Outside it, per selection 1..5 (lang_prefs ordinal == PCAT1',
           '; locale id): UI schema + artifact SHA-256, help schema + artifact SHA-256, and a row of numeric offsets',
           '; from l10n_catalog_start and byte counts, never a label operand.',
           f'L10N_LOCALES        equ {len(LOCALE_TAGS)}',
           f'L10N_LOC_BYTES      equ {at - len(en) - len(help_en)}',
           'align 8, db 0',
           'l10n_loc_expect:                        ; per selection 1..5: 128 B (UI pair, then help pair)']
    out += expect
    out += ['l10n_loc_table:                         ; per selection 1..5: dd UI offset, UI bytes, help offset, help bytes']
    out += table
    return out, inside


def emit_text(root):
    source, sites, rows, active = load(root)
    artifacts = K.build(source, sites=sites)
    en = artifacts['en.pcat']
    schema = K.schema_digest(source)
    need(not any(HELP_BAND[0] <= m['id'] <= HELP_BAND[1] for m in active),
         f'a UI record uses the help band {HELP_BAND[0]}..{HELP_BAND[1]}')
    names = id_names(active, rows)
    help_out, help_in, help_en, _ = help_emit(root)
    loc_out, loc_in = locale_emit(root, source, sites, en, help_en)

    src_sha = hashlib.sha256((root / SOURCE).read_bytes()).hexdigest()
    sites_sha = hashlib.sha256((root / SITES).read_bytes()).hexdigest()
    out = ['; GENERATED by gauntlet_v2/tools/l10n_bind_check.py emit. Do not edit: make lint refuses any drift.',
           f'; source {legacy(SOURCE)} sha256 {src_sha}',
           f'; sites  {legacy(SITES)} sha256 {sites_sha}',
           '; RCQ-38 l10n L1: the embedded English PCAT1 (locale 0), its validator expectations and the',
           '; compile-time message ids. Included once, from gui/res_pack_boot.asm, outside every WDATA block.',
           f"L10N_CAT_REVISION   equ {source['revision']}",
           f'L10N_CAT_EN_BYTES   equ {len(en)}']
    for ident in sorted(names):
        out.append(f'{names[ident]} equ {ident}')
    out += ['align 8, db 0',
            'l10n_cat_en_expect:                     ; schema SHA-256 (32) then artifact SHA-256 (32): context +8..+72']
    out += db(schema + hashlib.sha256(en).digest())
    out += help_out
    out += loc_out
    out += ['align 8, db 0', 'l10n_catalog_start:', 'l10n_cat_en:']
    out += db(en)
    out += help_in
    out += loc_in
    out += ['l10n_catalog_end:', '']
    return '\n'.join(out), en, names


def cell(ch):
    """Cells of one scalar, as ue_cell_width counts them (a row proves the two agree on every catalog scalar)."""
    if unicodedata.category(ch) in ('Mn', 'Me', 'Cf'):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in 'WF' else 1


def closure(source, active, *more):
    """(wide scalars the subset must hold, every other non-ASCII scalar) over the six UI catalogs' active records,
    plus each further (source, active records) pair in more."""
    wide, other = set(PUNCTUATION) | {ord(c) for t in ENDONYMS for c in t} | set(KANA), set()
    for source, active in ((source, active), *more):
        for m in active:
            for recs in source['locales'].values():
                for ch in recs.get(m['key'], ''):
                    if cell(ch) == 2:
                        wide.add(ord(ch))
                    elif ord(ch) > 0x7E:
                        other.add(ord(ch))
    return sorted(wide), sorted(other)


def level1_key(line):
    """(field, scalar) when a Unihan_IRGSources line is a level-1 J0 / G0 source, else None."""
    m = LEVEL1_LINE.fullmatch(line)
    if m is None or m[2] not in LEVEL1_SETS:
        return None
    src, lo, hi, _ = LEVEL1_SETS[m[2]]
    if m[3] != src or not lo <= int(m[4], 16) - 0x20 <= hi or not 0x21 <= int(m[5], 16) <= 0x7E:
        return None
    return m[2], int(m[1], 16)


def level1(root):
    """The level-1 ideographs from the vendored excerpt: upstream's header, then only level-1 lines, no duplicate,
    each source exactly its standard count (a truncated or widened excerpt fails without the full file)."""
    lines = (root / LEVEL1).read_text(encoding='utf-8').split('\n')
    need(lines[-1] == '' and len(lines) > LEVEL1_HEADER + 1 and all(x.startswith('#') for x in lines[:LEVEL1_HEADER])
         and lines[3] == '# Unicode version: 15.1.0', f'{LEVEL1}: not the Unihan 15.1.0 header')
    seen = {k: set() for k in LEVEL1_SETS}
    for n, line in enumerate(lines[LEVEL1_HEADER:-1], LEVEL1_HEADER + 1):
        k = level1_key(line)
        need(k is not None, f'{LEVEL1}:{n}: not a level-1 J0/G0 source line')
        need(k[1] not in seen[k[0]], f'{LEVEL1}:{n}: duplicate {k[0]} U+{k[1]:04X}')
        seen[k[0]].add(k[1])
    for k, (src, _, _, count) in LEVEL1_SETS.items():
        need(len(seen[k]) == count, f'{LEVEL1}: {len(seen[k])} {src} level-1 ideographs, not {count}')
    return seen['kIRG_JSource'] | seen['kIRG_GSource']


def painted(root, source, active):
    """The closure over every catalog the image paints: UI, offline Help and Terminal help (L5), plus level 1."""
    help_source, help_active, _ = load_help(root)
    l5 = K.load_json(root / L5_SOURCE)
    l5_active = [m for m in K.validate_source(l5) if not m.get('tombstone', False) and not m.get('reserved', False)]
    wide, other = closure(source, active, (help_source, help_active), (l5, l5_active))
    return sorted(set(wide) | level1(root)), other


def read_hex(path):
    """A Unifont .hex file -> {scalar: 32 B} for its 16x16 lines (8x16 lines are skipped)."""
    out, seen = {}, set()
    for n, line in enumerate(path.read_text(encoding='ascii').splitlines(), 1):
        cp, sep, bits = line.partition(':')
        need(sep == ':' and re.fullmatch(r'[0-9A-F]{4,6}', cp) and re.fullmatch(r'[0-9A-F]{32}|[0-9A-F]{64}', bits),
             f'{path.name}:{n}: not a Unifont hex line')
        value = int(cp, 16)
        need(0 <= value <= 0x10FFFF and not 0xD800 <= value <= 0xDFFF, 'non-scalar glyph')
        need(value not in seen, 'duplicate glyph')
        seen.add(value)
        if len(bits) == 64:
            out[int(cp, 16)] = bytes.fromhex(bits)
    return out


def emit_glyphs(root):
    source, sites, rows, active = load(root)
    wide, _ = painted(root, source, active)
    hexd = read_hex(root / GLYPH_HEX)
    need(set(hexd) == set(wide), 'glyph repertoire differs from exact closure')
    missing = [c for c in wide if c not in hexd]
    need(not missing, 'missing from the glyph subset: ' + ' '.join(f'U+{c:04X}' for c in missing))
    hex_sha = hashlib.sha256((root / GLYPH_HEX).read_bytes()).hexdigest()
    out = ['; GENERATED by gauntlet_v2/tools/l10n_bind_check.py emit. Do not edit: make lint refuses any drift.',
           f'; source {GLYPH_HEX} sha256 {hex_sha}',
           '; RCQ-38 l10n L2: the 16x16 1bpp UI glyph subset, GNU Unifont 15.1.01 (SIL OFL 1.1, THIRD_PARTY_NOTICES.md):',
           '; every wide scalar of the six UI, offline Help and Terminal help (L5) catalogs, the CJK punctuation set,',
           '; the endonyms, the full hiragana U+3041-3096 and katakana U+30A1-30FA blocks (kana R2) and every',
           '; JIS X 0208 / GB2312 level-1 ideograph (Unicode 15.1 Unihan J0/G0, IME candidates). Sorted code points,',
           '; then 32 B a glyph (16 rows of 2 bytes, MSB = leftmost pixel). Included once, from gui/l10n_paint.asm.',
           f'L10N_GLYPH_COUNT equ {len(wide)}',
           'align 4, db 0',
           'l10n_glyph_cps:']
    out += ['    dd ' + ','.join(f'0x{c:04X}' for c in wide[i:i + 8]) for i in range(0, len(wide), 8)]
    out.append('l10n_glyph_bits:')
    out += ['    db ' + ','.join(f'0x{b:02x}' for b in hexd[c]) + f' ; U+{c:04X}' for c in wide]
    out.append('')
    return '\n'.join(out)
