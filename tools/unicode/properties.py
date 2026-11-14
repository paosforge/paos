# SPDX-License-Identifier: MPL-2.0
"""Pinned Unicode 15.1 DATA -> compact transition table. Run with python3 -I."""
import argparse
import hashlib
import json
from pathlib import Path
import re

PINS = {
    'DerivedCoreProperties.txt': 'f55d0db69123431a7317868725b1fcbf1eab6b265d756d1bd7f0f6d9f9ee108b',
    'GraphemeBreakTest.txt': 'ed9c5e92fd0911ccbeeb63c97cb19c519ea272ff1112ce843abd991582dd848f',
    'DerivedGeneralCategory.txt': '760720ac034f96b630a3055879a744e0907184e8aa811e89ba34583a7a487e85',
    'EastAsianWidth.txt': 'b08191401dc125f4e84ef262a95754faae6b737c79538e17ea9664a63434e94e',
    'emoji-data.txt': 'd7aef489c8fe4c14f09ea5695200277c6b93ac82ac60845cdd2161b0d6835cc1',
    'GraphemeBreakProperty.txt': 'a7e52eee647e52dc210b8719b4d7037276f4b353810293d69377fc46374cec3f',
    'unicode-license.txt': 'e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96',
}
GCB = dict(zip(('Other','CR','LF','Control','Extend','ZWJ','Regional_Indicator',
                'Prepend','SpacingMark','L','V','T','LV','LVT'), range(14)))
INCB = {'Consonant': 1, 'Extend': 2, 'Linker': 3}
LIMIT = 0x110000
BEGIN = '; BEGIN GENERATED UNICODE 15.1 DATA'
END = '; END GENERATED UNICODE 15.1 DATA'


def verified(root):
    result = {}
    for name, wanted in PINS.items():
        p = root / name
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 2_000_000:
            raise ValueError('unsafe DATA file: ' + name)
        raw = p.read_bytes()
        if hashlib.sha256(raw).hexdigest() != wanted:
            raise ValueError('pin mismatch: ' + name)
        result[name] = raw.decode('utf-8', errors='strict')
    return result


def records(text):
    for number, line in enumerate(text.splitlines(), 1):
        body = line.split('#', 1)[0].strip()
        if not body:
            continue
        parts = [s.strip() for s in body.split(';')]
        if len(parts) < 2 or not re.fullmatch(r'[0-9A-F]{4,6}(?:\.\.[0-9A-F]{4,6})?', parts[0]):
            raise ValueError('bad DATA line: ' + str(number))
        pair = parts[0].split('..')
        a, b = int(pair[0],16), int(pair[-1],16)
        if not 0 <= a <= b < LIMIT:
            raise ValueError('bad scalar range')
        yield a, b, parts[1:]


def transitions(data):
    """Flags: GCB[0:4], EP[4], width[5:7], InCB[7:9]."""
    flags = [0x20] * LIMIT
    for a,b,p in records(data['EastAsianWidth.txt']):
        if p[0] in ('W','F'):
            for i in range(a,b+1): flags[i] = (flags[i] & ~0x60) | 0x40
    for a,b,p in records(data['DerivedGeneralCategory.txt']):
        if p[0] in ('Mn','Me','Cf'):
            for i in range(a,b+1): flags[i] &= ~0x60
    for a,b,p in records(data['GraphemeBreakProperty.txt']):
        if p[0] not in GCB: raise ValueError('unknown GCB')
        # Hangul syllable LV/LVT is computed modulo 28 in native code.
        if p[0] in ('LV','LVT'): continue
        for i in range(a,b+1): flags[i] = (flags[i] & ~15) | GCB[p[0]]
    for a,b,p in records(data['emoji-data.txt']):
        if p[0] == 'Extended_Pictographic':
            for i in range(a,b+1): flags[i] |= 16
    if 'DerivedCoreProperties.txt' in data:
        for a,b,p in records(data['DerivedCoreProperties.txt']):
            if p[0] == 'InCB':
                if len(p) != 2 or p[1] not in INCB: raise ValueError('unknown InCB')
                for i in range(a,b+1): flags[i] |= INCB[p[1]] << 7
    else:
        raise ValueError('GB9c DATA is required')
    out = []
    previous = -1
    for cp, f in enumerate(flags):
        if f != previous:
            out.append((cp << 9) | f)
            previous = f
    out.append(LIMIT << 9)  # terminal sentinel, not a valid scalar
    if len(out)*4 >= 8192: raise ValueError('table size target exceeded')
    return out


def render(values):
    lines = [BEGIN, 'ue_properties:']
    for n in range(0,len(values),8):
        lines.append('    dd ' + ', '.join(f'0x{x:08x}' for x in values[n:n+8]))
    lines += ['ue_properties_end:', f'UE_PROP_COUNT equ {len(values)-1}', END]
    return '\n'.join(lines) + '\n'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('data', type=Path)
    p.add_argument('--source', type=Path)
    p.add_argument('--write', action='store_true')
    args = p.parse_args()
    values = transitions(verified(args.data)); block = render(values)
    if args.source:
        text = args.source.read_text()
        if text.count(BEGIN) != 1 or text.count(END) != 1: raise ValueError('markers')
        a = text.index(BEGIN); b = text.index(END)+len(END)
        updated = text[:a] + block.rstrip('\n') + text[b:]
        if args.write: args.source.write_text(updated)
        elif updated != text: raise ValueError('generated DATA differs')
    else: print(block,end='')
    print(json.dumps({'transitions':len(values)-1,'table_bytes':len(values)*4}),file=__import__('sys').stderr)

if __name__ == '__main__': main()
