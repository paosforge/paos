#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the existing three Unicode table families from pinned public DATA."""
import argparse
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).absolute().parents[2]
INPUT = 'third_party/unicode/'
MANIFEST_SHA = 'd743e196949d62c064477b29ff9ab1fa745d9aaf1a8182218a9f86cdeb78c145'
RECIPE_SHA = 'da8e3c58483388f8e6a92a2e97e458d41ce060f6712a48bef03abb58bea4de86'
LEGACY_LAYOUT_GENERATOR = 'd6df3b114ae112b4dd5f67a87ee09951dddbf7d7ed4ee7ae103b72dd1fd7c11f'
EXPECTED = {
    'unicode_properties.inc': '539550d2e54067f913eb4f5054b0e543f49a5e38beecc77aa3280608be4de081',
    'vt_tables.inc': 'd3f0e950825306da1987e684726edf5346462b7f463406122c16316433d661dd',
    'keyboard_layout.bin': '463f755de539c967b9712d2d9351acbbfa36baa1d8bc1efaa3ab22551d102f05',
    'keyboard_layout_data.inc': '9fd74edd6655148120d77dd995108bc317bea8b4f3c4443fcbc70a8606de3b91',
    'keyboard_layout_provenance.json': '07efac94b873ec2a9527951c992de762f879826825b4aceab32354cd38959613',
}


def safe(path):
    """Reject traversal and symlinks in every component before reading/writing."""
    path = Path(os.path.abspath(path))
    for part in (*reversed(path.parents), path):
        if part.is_symlink():
            raise ValueError('symlink path refused')
    return path


def read(name, wanted):
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('source path escape')
    path = safe(ROOT / relative)
    if not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError('missing/oversized source: ' + name)
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != wanted:
        raise ValueError('source/notice pin mismatch: ' + name)
    return data


def admit():
    manifest = json.loads(read(INPUT + 'SOURCES.json', MANIFEST_SHA))
    read(INPUT + 'SOURCE.md', RECIPE_SHA)
    if manifest['format'] != 1:
        raise ValueError('source manifest version')
    versions = {'ucd-15.0.0': '15.0.0', 'ucd-15.1.0': '15.1.0', 'cldr-43': '43'}
    if {k:v['version'] for k,v in manifest['families'].items()} != versions:
        raise ValueError('Unicode/CLDR version differs')
    for name, pin in manifest['notices'].items():
        read(name, pin)
    return {family: {name: read(INPUT + family + '/' + name, pin).decode('utf-8')
                     for name, pin in info['files'].items()}
            for family, info in manifest['families'].items()}


def generate():
    data = admit()
    props = runpy.run_path(str(safe(ROOT / 'tools/unicode/properties.py')))
    keyboard = runpy.run_path(str(safe(ROOT / 'tools/unicode/keyboard.py')))
    widths = runpy.run_path(str(safe(ROOT / 'tools/unicode/widths.py')))
    block = props['render'](props['transitions'](data['ucd-15.1.0'])).encode('ascii')
    widths['configure'](data['ucd-15.0.0'])
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        widths['main']()
    raw, provenance = keyboard['build']([data['cldr-43'][name].encode('utf-8')
                                       for name in keyboard['PINS']])
    layout = '; generator SHA256 ' + LEGACY_LAYOUT_GENERATOR + '\n' + keyboard['nasm'](raw)
    provenance = dict(generator_sha256=LEGACY_LAYOUT_GENERATOR,
                      data_sha256=hashlib.sha256(raw).hexdigest(),
                      data_bytes=len(raw), tables=provenance)
    outputs = {'unicode_properties.inc': block, 'vt_tables.inc': stdout.getvalue().encode('ascii'),
               'keyboard_layout_data.inc': layout.encode('ascii'), 'keyboard_layout.bin': raw,
               'keyboard_layout_provenance.json': (json.dumps(provenance, ensure_ascii=False, indent=2)+'\n').encode('utf-8')}
    for name, blob in outputs.items():
        if hashlib.sha256(blob).hexdigest() != EXPECTED[name]:
            raise ValueError('regenerated output differs: ' + name)
    return outputs


def check(outputs):
    editor = safe(ROOT / 'src/core/unicode_edit.asm').read_bytes()
    begin = b'; BEGIN GENERATED UNICODE 15.1 DATA'
    end = b'; END GENERATED UNICODE 15.1 DATA'
    if editor.count(begin) != 1 or editor.count(end) != 1:
        raise ValueError('editor markers')
    block = editor[editor.index(begin):editor.index(end)+len(end)] + b'\n'
    layout = safe(ROOT / 'src/core/keyboard_layout.asm').read_bytes()
    marker = b'; BEGIN OWN DATA\n'
    if layout.count(marker) != 1:
        raise ValueError('layout marker')
    expected = {'unicode_properties.inc': block,
                'keyboard_layout_data.inc': layout.split(marker)[1],
                'vt_tables.inc': safe(ROOT / 'src/gui/vt/vt_tables.inc').read_bytes()}
    for name, blob in expected.items():
        if outputs[name] != blob:
            raise ValueError('shipped section differs: ' + name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--check', action='store_true')
    modes.add_argument('--emit', type=Path, metavar='NEW_DIRECTORY')
    parser.add_argument('--family', choices=('properties', 'widths', 'layout'), default='widths',
                        help='stdout family when neither --check nor --emit is supplied')
    args = parser.parse_args(argv)
    try:
        outputs = generate()
        if args.check:
            check(outputs)
            print('Unicode editor 15.1 / VT 15.0 / CLDR43: exact shipped sections')
        elif args.emit:
            out = safe(args.emit)
            out.mkdir(parents=True, exist_ok=False)
            for name, blob in outputs.items():
                (out / name).write_bytes(blob)
        else:
            name = {'properties':'unicode_properties.inc','widths':'vt_tables.inc',
                    'layout':'keyboard_layout_data.inc'}[args.family]
            sys.stdout.buffer.write(outputs[name])
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print('gen_unicode_tables: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
