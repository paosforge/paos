#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Public-only fixed sample prefixes and external detached signature assembly."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[2]/'tools/release'))
import paos_script_sdk as sdk

def prefix(public):
    sdk.public_numbers(public)
    members=[(kind,name,sdk.member_read(HERE,name)) for kind,name in
             [('script','main.sh'),('form','main.frm'),('grants','grants')]]
    icons=HERE.parent/'script-icon-check'
    members += [(kind,name,sdk.member_read(icons,name,kind=kind)) for kind,name in
                [('icon','icon.png'),('icon2x','icon@2x.png'),('notices','NOTICES.json')]]
    return sdk.sharing_unsigned(dict(id='org.example.temperature',entry='main.sh',icon='icon.png',
        data_dir='data',name='Temperature converter',version='1.0.0'),members,public)

def build(public,signature=None):
    raw=prefix(public)
    return raw if signature is None else sdk.sharing_assemble(raw,signature)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--public-key',type=Path,required=True)
    p.add_argument('--signature',type=Path)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:
        raw=build(sdk.read_regular(a.public_key,4096),
                  sdk.read_regular(a.signature,256) if a.signature else None)
        with a.output.open('xb') as f:f.write(raw)
        print(json.dumps(dict(schema='paos.temperature-example.v1',bytes=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),signed=a.signature is not None,
            installed=False,runtime='UNOBSERVED')))
        return 0
    except (OSError,ValueError) as e:
        print(str(e),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
