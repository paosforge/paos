#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reconstruct the signed development example from fixed public inputs only."""
import argparse,hashlib,json,os,re,stat,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
PREFIX='sdk/examples/system-check/'
MEMBERS={PREFIX+'manifest.txt':2048,PREFIX+'recipes.txt':8192,
         PREFIX+'dev-public.pem':4096,PREFIX+'signature.bin':256,
         PREFIX+'build.py':16384,'tools/release/paos_app_sdk.py':65536}

class BuildRefusal(ValueError):pass

def require(condition,message):
    if not condition:raise BuildRefusal(message)

def public_member(name,limit):
    path=ROOT/name
    require(all(not p.is_symlink() for p in (path,*path.parents) if p!=ROOT.parent),'public input symlink refused')
    # Do not wait for a FIFO writer before discovering that it is not a file.
    # O_BINARY preserves exact public bytes on Windows; POSIX additionally
    # refuses a last-component symlink substituted after the check above.
    flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NONBLOCK',0)|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(path,flags)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode),'nonregular public input refused')
        require(before.st_size<=limit,'public input exceeds bound')
        with os.fdopen(fd,'rb',closefd=False) as stream:data=stream.read(limit+1)
        after=os.fstat(fd)
        require(len(data)<=limit,'public input exceeds bound')
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(len(data)==before.st_size and identity(before)==identity(after),'public input changed while reading')
        return data
    finally:os.close(fd)

def unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'duplicate public input metadata key')
        result[key]=value
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();sdk=None
    try:
        expected=json.loads(public_member(PREFIX+'EXPECTED.json',16384),object_pairs_hook=unique)
        require(isinstance(expected,dict) and set(expected)=={'schema','id','development_only','inputs','bundle_sha256'},'public input metadata schema refused')
        require(expected['schema']=='paos.sdk-example-public-inputs.v1' and expected['id']=='org.example.system-check' and expected['development_only'] is True,'public input metadata schema refused')
        pins=expected['inputs'];require(isinstance(pins,dict) and set(pins)==set(MEMBERS),'fixed public input closure required')
        require(all(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) for v in [*pins.values(),expected['bundle_sha256']]),'public input digest invalid')
        data={name:public_member(name,limit) for name,limit in MEMBERS.items()}
        require(all(hashlib.sha256(raw).hexdigest()==pins[name] for name,raw in data.items()),'public input identity changed')
        # Verify the exact producer source before importing it. No operator gate,
        # history, target descriptor, private corpus or signing key is an input.
        sdk=types.ModuleType('public_app_sdk')
        sdk.__file__=str(ROOT/'tools/release/paos_app_sdk.py')
        exec(compile(data['tools/release/paos_app_sdk.py'],sdk.__file__,'exec'),sdk.__dict__)
        bundle=sdk.assemble(data[PREFIX+'manifest.txt'],data[PREFIX+'recipes.txt'],b'',data[PREFIX+'dev-public.pem'],data[PREFIX+'signature.bin'])
        require(hashlib.sha256(bundle).hexdigest()==expected['bundle_sha256'],'public output identity changed')
        receipt=sdk.inspect_bundle(bundle,data[PREFIX+'dev-public.pem'])
        require(receipt['id']==expected['id'],'public example identity changed')
        sdk.write_new(args.output,bundle)
        print(json.dumps({'ok':True,'development_only':True,**receipt},sort_keys=True));return 0
    except (OSError,ValueError,TypeError,ImportError) as exc:
        known=isinstance(exc,BuildRefusal) or (sdk is not None and isinstance(exc,sdk.Refusal))
        print(json.dumps({'ok':False,'refusal':str(exc) if known else type(exc).__name__,'runnable':False,'official_signature':False},sort_keys=True));return 1

if __name__=='__main__':raise SystemExit(main())
