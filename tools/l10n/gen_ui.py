#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reproduce existing UI catalog and Unifont cells from pinned public sources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import types
import sys

ROOT = Path(__file__).absolute().parents[2]
INPUT = 'third_party/localization/'
MANIFEST_SHA = 'ab2e65324d5918d5823e819de3fde3c7427aae0865b0d57db0fc0bb23db32c3d'
RECIPE_SHA = 'c98e32b3b18f274e204bca241fbfd87c79ebf12a942bddcbade5da81bbb9370a'
EXPECTED = {
    'l10n_catalog.inc': '0d2010311e2e3a9525e95081b3039db45c360d0a7ce3e7d29ef48548cf46e1bf',
    'l10n_glyphs.inc': 'fa810fbb41c33c4094e5d86cb38a39d27133f96befe0d14270e5c987a4148376',
}


def safe(path):
    path = Path(os.path.abspath(path))
    for part in (*reversed(path.parents), path):
        if part.is_symlink():
            raise ValueError('symlink path refused')
    return path


def read(name, pin):
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('source path escape')
    p = safe(ROOT / relative)
    if not p.is_file() or p.stat().st_size > 16_000_000:
        raise ValueError('missing/oversized source: ' + name)
    raw = p.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('source/notice/helper pin mismatch: ' + name)
    return raw


def admit():
    manifest = json.loads(read(INPUT + 'SOURCES.json', MANIFEST_SHA))
    read(INPUT + 'SOURCE.md', RECIPE_SHA)
    if manifest['format'] != 1 or manifest['unifont_version'] != '15.1.01' or manifest['unicode_version'] != '15.0.0':
        raise ValueError('source manifest version')
    return {name: read(name, pin) for name, pin in manifest['files'].items()}


def generate():
    data = admit()  # Admit the entire closure before executing selected helpers.
    modules = {}
    for name in ('catalog', 'site_map', 'emitter'):
        module = types.ModuleType(name)
        sys.modules[name] = module
        path = 'tools/l10n/' + name + '.py'
        exec(compile(data[path], str(ROOT / path), 'exec'), module.__dict__)
        modules[name] = module
    catalog, emitter = modules['catalog'], modules['emitter']
    widths = {}
    exec(compile(data['tools/unicode/widths.py'], 'tools/unicode/widths.py', 'exec'), widths)
    ucd = widths['UnicodeData']({
        name: data['third_party/unicode/ucd-15.0.0/' + name].decode('utf-8')
        for name in ('DerivedGeneralCategory.txt', 'EastAsianWidth.txt')})
    catalog.unicodedata = emitter.unicodedata = ucd
    text, _, _ = emitter.emit_text(ROOT)
    glyphs = emitter.emit_glyphs(ROOT)
    source, sites, _, _ = emitter.load(ROOT)
    outputs = catalog.build(source, sites=sites)
    outputs.update({'l10n_catalog.inc': text.encode('utf-8'), 'l10n_glyphs.inc': glyphs.encode('ascii')})
    for name, pin in EXPECTED.items():
        if hashlib.sha256(outputs[name]).hexdigest() != pin:
            raise ValueError('generated shipped bytes differ: ' + name)
    return outputs


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    actions = p.add_mutually_exclusive_group(required=True)
    actions.add_argument('--check', action='store_true')
    actions.add_argument('--emit', type=Path, metavar='NEW_DIRECTORY')
    args = p.parse_args(argv)
    try:
        outputs = generate()
        if args.check:
            for name in EXPECTED:
                if safe(ROOT / 'src/gui' / name).read_bytes() != outputs[name]:
                    raise ValueError('checked-in include differs: ' + name)
        else:
            out = safe(args.emit)
            if out.exists():
                raise ValueError('output already exists')
            out.mkdir(parents=True)
            for name, raw in outputs.items():
                (out / name).write_bytes(raw)
        print(json.dumps({name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(outputs.items())}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('gen_ui: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
