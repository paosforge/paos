# SPDX-License-Identifier: MPL-2.0
"""Pinned CLDR43 XML DATA -> include-free KLT1 NASM bytes. No network.
Creator rc-codex-relops. SPDX-License-Identifier: MPL-2.0.
Output DATA: Unicode-DFS-2016; retain KEYBOARD_LAYOUT.md notice.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import xml.etree.ElementTree as ET

PINS={
'en-t-k0-windows.xml':'3a5b8bb3931a5672cec7b271be1746de27de9e3c6c6677158859f114ce557a0b',
'es-t-k0-windows.xml':'af5a172b94686ecc9a912f89fe879206dcd0d3db337e0ac591747d00bbb2b997',
'fr-t-k0-windows.xml':'96c8b474463fa9bdc6042650f33c7f52b9b8222a85c0815301d07fbfca8552fa',
'de-t-k0-windows.xml':'37568b0cd7984fc8181724da89b850f43514240767bde8d8cb647db2ff5a2607',
}
SPACING='´' + chr(96) + '^¨~¸'
# Own transcription of ISO physical positions to USB HID usage page7.
ISO={'E00':0x35,'E11':0x2d,'E12':0x2e,'D11':0x2f,'D12':0x30,
     'C10':0x33,'C11':0x34,'C12':0x31,'B00':0x64,'A03':0x2c}
ISO.update({f'E{i:02}':0x1d+i for i in range(1,11)})
for prefix,letters in [('D','qwertyuiop'),('C','asdfghjkl'),('B','zxcvbnm')]:
    ISO.update({f'{prefix}{i:02}':4+ord(ch)-ord('a') for i,ch in enumerate(letters,1)})
ISO.update({'B08':0x36,'B09':0x37,'B10':0x38})
MODS=['','shift','caps','caps+shift','altR+caps? ctrl+alt+caps?',
      'altR+shift+caps? ctrl+alt+shift+caps?']
def decode(value):
    value=re.sub(r'\\u\{([0-9A-Fa-f]{1,6})\}',lambda m:chr(int(m[1],16)),value)
    if any(0xd800<=ord(ch)<=0xdfff for ch in value):raise ValueError('surrogate')
    return value
def parse(raw):
    if len(raw)>65536 or b'<!ENTITY' in raw:raise ValueError('XML bounds/entity')
    raw=raw.replace(b'<!DOCTYPE keyboard SYSTEM "../dtd/ldmlKeyboard.dtd">',b'')
    if b'<!DOCTYPE' in raw:raise ValueError('unexpected DTD')
    root=ET.fromstring(raw)
    if root.tag!='keyboard':raise ValueError('root')
    maps={}
    for keymap in root.findall('keyMap'):
        modifier=keymap.get('modifiers','')
        if modifier not in MODS:continue
        if modifier in maps:raise ValueError('duplicate map')
        rows={}
        for item in keymap.findall('map'):
            iso=item.get('iso')
            if iso not in ISO or iso in rows:raise ValueError('unknown/duplicate position')
            value=decode(item.attrib['to'])
            if len(value)!=1 or ord(value)<32:raise ValueError('map scalar')
            rows[iso]=(value,item.get('transform')!='no')
        maps[modifier]=rows
    if any(x not in maps for x in MODS[:4]):raise ValueError('missing base/caps layer')
    transforms={}
    for group in root.findall('transforms'):
        if group.get('type')!='simple':raise ValueError('transform type')
        for item in group.findall('transform'):
            before=decode(item.attrib['from']);after=decode(item.attrib['to'])
            if len(before)!=2 or len(after)!=1 or before[0] not in SPACING:raise ValueError('transform shape')
            if before in transforms and transforms[before]!=after:raise ValueError('conflicting transform')
            transforms[before]=after
    return maps,transforms
def build(raws):
    if len(raws)!=4:raise ValueError('four layouts required')
    parsed=[parse(raw) for raw in raws]
    scalars=[0];indices={}
    def scalar(ch):
        cp=ord(ch)
        if cp not in indices:
            if len(scalars)>=240:raise ValueError('scalar dictionary capacity')
            indices[cp]=len(scalars);scalars.append(cp)
        return indices[cp]
    spaces=[scalar(ch) for ch in SPACING]
    transforms={}
    for _,ts in parsed:
        for before,after in ts.items():
            if before in transforms and transforms[before]!=after:raise ValueError('transform conflict')
            transforms[before]=after
    # Own canonical Unicode cedilla pairs supplement direct national ç/Ç keys.
    transforms.update({'¸c':'ç','¸C':'Ç'})
    compose=[]
    for before,after in sorted(transforms.items()):
        if before[1]==' ':
            if after!=before[0]:raise ValueError('space transform')
            continue
        compose.append((SPACING.index(before[0])+1,scalar(before[1]),scalar(after)))
    compose.sort(key=lambda x:(x[0],x[1]))
    layouts=[];provenance=[]
    for (name,_),(maps,ts) in zip(PINS.items(),parsed):
        dead={before[0] for before in ts}
        def token(value):
            if value is None:return 0
            ch,enabled=value
            return 241+SPACING.index(ch) if enabled and ch in dead else scalar(ch)
        rows=[];used=[]
        for iso,usage in ISO.items():
            vals=[maps.get(mod,{}).get(iso) for mod in MODS]
            normal,shift,caps,caps_shift,alt,alt_shift=vals
            if all(x is None for x in vals):continue
            if (caps,caps_shift)==(normal,shift):flag=0
            elif (caps,caps_shift)==(shift,normal):flag=1
            else:raise ValueError('caps cannot encode '+name+':'+iso)
            row=(usage,flag,*map(token,[normal,shift,alt,alt_shift]))
            rows.append(row)
            used.append(dict(iso=iso,usage=usage,values=vals,caps_xor=flag))
            if iso=='C12':rows.append((0x32,*row[1:]))
        # PaOS neutral keypad policy, authored here; not present in CLDR files.
        for usage,ch in [(0x54,'/'),(0x55,'*'),(0x56,'-'),(0x57,'+')]+list(zip(range(0x59,0x63),'1234567890'))+[(0x63,'.')]:
            rows.append((usage,0,*([scalar(ch)]*4)))
        rows.sort()
        if len(rows)>128 or len({r[0] for r in rows})!=len(rows):raise ValueError('row bounds')
        layouts.append(rows)
        provenance.append(dict(file=name,sha256=PINS[name],maps=used,transforms=ts))
    tail=struct.pack('<%dI'%len(scalars),*scalars)+bytes(spaces)+bytes(v for r in compose for v in r)+b''.join(bytes(r) for rows in layouts for r in rows)
    out=struct.pack('<II4H4HQ',0x31544c4b,32+len(tail),1,4,len(scalars),len(compose),*[len(r) for r in layouts],0)+tail
    if len(out)>=4096:raise ValueError('DATA size target')
    return out,provenance
def load(directory):
    raws=[]
    for name,want in PINS.items():
        p=directory/name
        if p.stat().st_size>65536:raise ValueError('input too large')
        raw=p.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=want:raise ValueError('pin mismatch '+name)
        raws.append(raw)
    return raws
def nasm(data):
    return 'kbd_builtin_data:\n'+''.join('    db '+','.join('0x%02x'%v for v in data[i:i+24])+'\n' for i in range(0,len(data),24))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--provenance',type=Path,required=True);a=p.parse_args()
    data,provenance=build(load(a.inputs))
    digest=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.write_text('; generator SHA256 '+digest+'\n'+nasm(data))
    a.provenance.write_text(json.dumps(dict(generator_sha256=digest,data_sha256=hashlib.sha256(data).hexdigest(),data_bytes=len(data),tables=provenance),ensure_ascii=False,indent=2)+'\n')
