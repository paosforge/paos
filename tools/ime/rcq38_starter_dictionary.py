#!/usr/bin/env python3
"""Build limited single-ideograph PDCT1 DATA from the frozen Mozc/Rime sources.

SPDX-License-Identifier: MPL-2.0
Host DATA only. No fetching, signing, image modification or native admission.
"""
from __future__ import annotations
import argparse
from collections import Counter
from pathlib import Path
import re
import sys

import rcq38_product_dictionary as d

BYTE_LIMIT = 128 * 1024                 # Each PDCT, including its header.
KEY_LIMIT = 32                         # Well below the unchanged I1 raw-row bound.
SURFACE_LIMIT = 4                      # At most four source readings per ideograph.
DROP_REASONS = ('exact_duplicate', 'not_single_ideograph', 'glyph_missing',
                'reading_unavailable', 'same_reading_surface', 'key_limit',
                'surface_limit', 'byte_limit')


def glyph_coverage(path, expected_sha256):
    """Admit the exact shipped 16x16 Unifont subset, never a claimed repertoire."""
    d.p.sha_bytes(expected_sha256)
    raw = d.p.read_bounded(path, 2 * 1024 * 1024)
    d.p.need(d.p.digest(raw).hex() == expected_sha256, 'starter glyph pin')
    lines = raw.splitlines()
    d.p.need(0 < len(lines) <= 16384 and raw.endswith(b'\n'), 'starter glyph bounds')
    previous = -1; coverage = set()
    for line in lines:
        d.p.need(re.fullmatch(rb'[0-9A-F]{4,6}:[0-9A-F]{64}', line) is not None,
                 'starter glyph record')
        cp = int(line.split(b':')[0], 16); d.p.scalar(cp)
        d.p.need(cp > previous, 'starter glyph order/duplicate')
        previous = cp
        # Blank spacing cells are valid, but cannot demonstrate an ideograph.
        if 0x4e00 <= cp <= 0x9fff:
            d.p.need(any(bytes.fromhex(line.split(b':')[1].decode())), 'blank ideograph')
        coverage.add(cp)
    repertoire = b''.join(cp.to_bytes(4, 'little') for cp in sorted(coverage))
    return coverage, dict(bytes=len(raw), sha256=expected_sha256, glyphs=len(coverage),
                          repertoire_sha256=d.p.digest(repertoire).hex())


def select(rows, locale, coverage, *, byte_limit=BYTE_LIMIT, key_limit=KEY_LIMIT,
           surface_limit=SURFACE_LIMIT):
    d.p.need(locale in d.LOCALES, 'starter locale')
    d.p.integer(byte_limit, 193, BYTE_LIMIT)
    d.p.integer(key_limit, 1, KEY_LIMIT)
    d.p.integer(surface_limit, 1, SURFACE_LIMIT)
    unique = sorted(set(rows)); drops = Counter({name: 0 for name in DROP_REASONS})
    drops['exact_duplicate'] = len(rows) - len(unique)
    eligible = []
    for index, row in enumerate(unique):
        key, surface = row[:2]
        d.p.text(key, 128); d.p.text(surface, 256)
        text = surface.decode('utf-8')
        if len(text) != 1 or not 0x4e00 <= ord(text) <= 0x9fff:
            drops['not_single_ideograph'] += 1
        elif ord(text) not in coverage:
            drops['glyph_missing'] += 1
        elif (locale == 'ja' and re.fullmatch('[\u3041-\u3096ー]{1,16}', key.decode()) is None
              or locale == 'zh-Hans' and re.fullmatch(rb'[a-z]+', key) is None):
            drops['reading_unavailable'] += 1
        else:
            eligible.append((index, row))
    # Exactly the existing source score/global-row ordering, before selection.
    eligible.sort(key=lambda item: d.ranking(item[1], locale, item[0]))
    pairs = set(); keys = Counter(); surfaces = Counter(); selected = []; used = 192
    for _, row in eligible:
        key, surface = row[:2]; pair = (key, surface)
        if pair in pairs:
            drops['same_reading_surface'] += 1; continue
        pairs.add(pair)
        size = d.p.DICT_ROW.size + len(key) + len(surface)
        if keys[key] >= key_limit:
            drops['key_limit'] += 1
        elif surfaces[surface] >= surface_limit:
            drops['surface_limit'] += 1
        elif used + size > byte_limit:
            drops['byte_limit'] += 1
        else:
            selected.append(row); keys[key] += 1; surfaces[surface] += 1; used += size
    d.p.need(bool(selected), 'starter has no supported candidates')
    d.p.need(sum(drops.values()) + len(selected) == len(rows), 'starter accounting')
    return sorted(selected), dict(input_rows=len(rows), selected_rows=len(selected),
                                  drops=dict(drops), pack_bytes=used, keys=len(keys),
                                  ideographs=len(surfaces), max_rows_per_key=max(keys.values()),
                                  max_readings_per_ideograph=max(surfaces.values()))


def generate(inputs, glyph_path, glyph_sha256, release, generation, slot, output):
    registry = d.b.registry()
    coverage, glyph_pin = glyph_coverage(glyph_path, glyph_sha256)
    sources = [r for r in registry['sources'] if r['group'] in ('mozc', 'rime-pinyin')]
    # All full notices and original Pinyin ancestry must validate before output.
    notices = d.b.notice_artifacts(registry, inputs, sources)
    policy = dict(byte_limit=BYTE_LIMIT, key_limit=KEY_LIMIT, surface_limit=SURFACE_LIMIT,
                  surface='one U+4E00..U+9FFF ideograph present in exact glyph subset',
                  reading='source hiragana/long mark (1..16 chars) or one ASCII pinyin syllable',
                  ranking='existing source score then original sorted full-row index',
                  merging='best original row per reading/surface; POS/cost/weight/attributes retained')
    provenance = dict(schema='paos.starter-dictionary.provenance.v1',
                      source_registry_sha256=d.b.REGISTRY_SHA256, sources=sources,
                      glyph_subset=glyph_pin, selection=policy,
                      notice_pins={n: dict(bytes=len(raw), sha256=d.p.digest(raw).hex())
                                   for n, raw in sorted(notices.items())},
                      scope='limited single-character conversion; full dictionaries use authenticated packs')
    contract = d.p.canonical(provenance)
    artifacts = {}; reports = {}
    for locale, (family, *_) in d.LOCALES.items():
        group = 'mozc' if locale == 'ja' else 'rime-pinyin'
        rows = []
        for source in sources:
            if source['group'] == group:
                rows.extend(d.b.parse_dictionary(d.b.pinned_bytes(inputs, source), family))
        selected, report = select(rows, locale, coverage)
        packs, _ = d.b.dictionary_shards(selected, family, contract)
        d.p.need(len(packs) == 1 and len(packs[0][0]) == report['pack_bytes'], 'starter pack budget')
        # Keep the I1 resource name contract; this is an alternative generation.
        artifacts[family + '-full-000.pdct'] = packs[0][0]
        report['surface_closure'] = d.surface_closure(selected, locale, coverage)
        reports[locale] = report
    return d.b.finish(artifacts, registry, inputs, sources, dict(locales=reports),
                      release, generation, slot, output,
                      extra_notices={'starter-dictionary-provenance.json': contract})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inputs', 'glyph-subset', 'glyph-sha256', 'release-sha256', 'slot', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--generation', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        report = generate(args.inputs, args.glyph_subset, args.glyph_sha256,
                          args.release_sha256, args.generation, args.slot, args.output)
    except (d.p.PackError, OSError, UnicodeError) as error:
        print(str(error), file=sys.stderr); return 2
    print(d.p.canonical(report).decode(), end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
