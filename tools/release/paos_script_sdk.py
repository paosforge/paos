#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Public-only authoring for the native PAOSAPP1 container-2 bash snapshot.

No key enrollment, private key loading, execution, extraction or VM claim.
The native consumer is src/svc/app_script.asm; recipe container-1 is unchanged.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

if __package__:
    from .paos_app_sdk import HEADER, MAGIC, DIGEST_INFO, Refusal, public_numbers, require
else:
    from paos_app_sdk import HEADER, MAGIC, DIGEST_INFO, Refusal, public_numbers, require

MAX_BUNDLE = 65536
MEMBER = struct.Struct('<IIII64s')
KINDS = {'script': 1, 'form': 2, 'icon': 3, 'data': 4, 'grants': 5, 'icon2x': 6, 'notices': 7, 'image': 8}

MEMBER_CAPS = {3: 12288, 6: 40960, 8: 40960}
# widgets-01 A4: up to four app images, one flat images/ segment, extension
# named by its leading bytes. The native decoder (img_source) validates the rest.
IMAGE_PATTERN = r'images/[a-z0-9_-]+\.(png|bmp|jpg|gif)'
IMAGE_MAGIC = {'png': (b'\x89PNG\r\n\x1a\n',), 'bmp': (b'BM',), 'jpg': (b'\xff\xd8',),
               'gif': (b'GIF87a', b'GIF89a')}
IMAGE_MAX = 4
RESERVED_MEMBERS = {6: 'icon@2x.png', 7: 'NOTICES.json'}


def fixed(text, width, *, bundle_id=False, optional=False, member_kind=None):
    require(type(text) is str, 'text required')
    if optional and text == '':
        return bytes(width)
    if member_kind in RESERVED_MEMBERS:
        require(text == RESERVED_MEMBERS[member_kind], 'reserved member path')
        return text.encode('ascii').ljust(width, b'\0')
    if member_kind == 8:
        require(re.fullmatch(IMAGE_PATTERN, text) is not None, 'image member path')
        return text.encode('ascii').ljust(width, b'\0')
    pattern = r'[a-z0-9][a-z0-9.-]{2,62}' if bundle_id else r'[a-z0-9_-]+(?:[./][a-z0-9_-]+)*'
    require(re.fullmatch(pattern, text) and len(text) < width, 'invalid id/path')
    return text.encode('ascii').ljust(width, b'\0')


def field(raw, **kwargs):
    text, sep, tail = raw.partition(b'\0')
    require(sep and not any(tail), 'noncanonical padded text')
    try:
        value = text.decode('ascii')
    except UnicodeError as exc:
        raise Refusal('invalid text') from exc
    require(fixed(value, len(raw), **kwargs) == raw, 'invalid text')
    return value


def validate(manifest, index, assets):
    sharing = len(manifest) == 512 and manifest[:8] == b'BASHAPP2'
    require(sharing or (len(manifest) == 256 and manifest[:8] == b'BASHAPP1'), 'script manifest')
    require(struct.unpack_from('<II', manifest, 8) == (1, 1), 'script contract/runtime')
    require(struct.unpack_from('<IIII', manifest, 240) == (1, 1, 0, 0), 'forms/verbs contract/flags')
    metadata = {}
    if sharing:
        metadata = dict(name=display_field(manifest[256:352]), version=version_field(manifest[352:384]))
        require(not any(manifest[384:512]), 'manifest reserved')
    app_id = field(manifest[16:80], bundle_id=True)
    entry = field(manifest[80:144])
    icon = field(manifest[144:208], optional=True)
    require(icon in ('', 'icon.png'), 'canonical PNG icon path')
    data_dir = field(manifest[208:240])
    require(len(index) % 80 == 0 and 1 <= len(index)//80 <= 16, 'member count')
    seen = set(); counts = [0]*9; offset = 0; members = []
    for pos in range(0, len(index), 80):
        kind, start, size, reserved, name = MEMBER.unpack_from(index, pos)
        require(1 <= kind <= 8 and reserved == 0, 'member type/reserved')
        path = field(name, member_kind=kind)
        require(path not in seen, 'member duplicate')
        require(start == offset and 1 <= size <= MEMBER_CAPS.get(kind, 8192) and start+size <= len(assets), 'member bounds')
        body = assets[start:start+size]
        counts[kind] += 1; seen.add(path); offset += size
        if kind == 1:
            require(path == entry and counts[kind] == 1 and body.endswith(b'\n') and
                    all(b in (9, 10) or 32 <= b <= 126 for b in body), 'bash entry')
        elif kind == 2:
            require(counts[kind] <= 4 and size <= 4096 and path.endswith('.frm') and
                    body.endswith(b'\n') and all(b == 10 or 32 <= b <= 126 for b in body), 'form data')
        elif kind == 3:
            require(counts[kind] == 1 and path == icon, '48 PNG icon')
            png_header(body, 48)
        elif kind == 4:
            require(path.startswith(data_dir+'/'), 'data outside namespace')
            if sharing:
                require(all(b in (9, 10) or 32 <= b <= 126 for b in body), 'sharing initial text data')
        elif kind == 6:
            require(counts[kind] == 1, 'duplicate96 icon')
            png_header(body, 96)
        elif kind == 7:
            require(counts[kind] == 1, 'duplicate notices')
            notices_json(body)
        elif kind == 8:
            require(counts[kind] <= IMAGE_MAX, 'image member count')
            require(body.startswith(IMAGE_MAGIC[path.rsplit('.', 1)[1]]), 'image magic/extension')
        else:
            require(counts[kind] == 1 and path == 'grants' and size == 4 and
                    all(b <= 2 for b in body), 'WAIT policy requests')
        members.append({'kind': kind, 'path': path, 'offset': start, 'bytes': size})
    require(offset == len(assets) and counts[1] == counts[5] == 1 and
            counts[3] == bool(icon) and counts[6] <= counts[3] and
            (not icon or counts[7] == 1), 'missing member/unindexed bytes')
    return dict(**metadata, id=app_id, entry=entry, icon=icon, data_dir=data_dir, members=members,
                runtime='bash', forms_contract=1, verbs_contract=1)


def png_header(body, dimension):
    """Authoring header/cap lint; native existing img decoder validates all bytes.

    Strict IHDR dimensions before native decode bound allocation even for a
    signed decompression bomb. No independent SDK PNG decoder is introduced.
    """
    require(33 <= len(body) <= (12288 if dimension == 48 else 40960), 'PNG source cap')
    require(body[:16] == b'\x89PNG\r\n\x1a\n\0\0\0\rIHDR' and
            struct.unpack_from('>IIBBBBB', body, 16) in
            ((dimension, dimension, 8, 6, 0, 0, 0), (dimension, dimension, 8, 6, 0, 0, 1)),
            'RGBA8 PNG exact dimensions')


def notices_json(body):
    """Bounded JSON credits lint. Native retains signed opaque metadata only."""
    def constant(_):
        raise ValueError('non-JSON number')
    try:
        data = json.loads(body.decode('utf-8'), parse_constant=constant)
    except (ValueError, RecursionError) as exc:
        raise Refusal('NOTICES.json syntax') from exc
    require(type(data) in (dict, list), 'NOTICES.json object/array')


def display_fixed(text):
    require(type(text) is str and re.fullmatch(r'[!-~](?:[ -~]{0,93}[!-~])?', text),
            'display name: 1..95 ASCII, no leading/trailing space')
    return text.encode('ascii').ljust(96, b'\0')


def version_fixed(text):
    require(type(text) is str and re.fullmatch(r'(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){2}', text)
            and all(int(n) <= 65535 for n in text.split('.')), 'canonical uint16 version triple')
    return text.encode('ascii').ljust(32, b'\0')


def display_field(raw):
    text, sep, tail = raw.partition(b'\0')
    require(sep and not any(tail), 'display name padding')
    value = text.decode('ascii', errors='strict')
    require(display_fixed(value) == raw, 'display name')
    return value


def version_field(raw):
    text, sep, tail = raw.partition(b'\0')
    require(sep and not any(tail), 'version padding')
    value = text.decode('ascii', errors='strict')
    require(version_fixed(value) == raw, 'version')
    return value


def sharing_unsigned(spec, members, pem=None):
    """Unsigned whole file, or exact prefix for an external detached signer.

    Supplying a public key declares a mandatory signature: the returned prefix
    is incomplete until sharing_assemble appends and verifies that signature.
    Never loads a private key or claims installation, trust or runtime proof.
    """
    require(type(spec) is dict and set(spec) == {'id','entry','icon','data_dir','name','version'}, 'sharing spec fields')
    manifest = (b'BASHAPP2' + struct.pack('<II', 1, 1) + fixed(spec['id'], 64, bundle_id=True) +
                fixed(spec['entry'], 64) + fixed(spec['icon'], 64, optional=True) +
                fixed(spec['data_dir'], 32) + struct.pack('<4I', 1, 1, 0, 0) +
                display_fixed(spec['name']) + version_fixed(spec['version']) + bytes(128))
    require(type(members) in (list, tuple) and 2 <= len(members) <= 16, 'member count')
    index = bytearray(); assets = bytearray()
    for kind, path, body in members:
        require(type(kind) is str and kind in KINDS and type(body) is bytes, 'member input')
        index += MEMBER.pack(KINDS[kind], len(assets), len(body), 0, fixed(path,64,member_kind=KINDS[kind]))
        assets += body
    validate(manifest,index,assets)
    public = b''; key_id = bytes(16)
    if pem is not None:
        modulus, key_id = public_numbers(pem)
        public = modulus.to_bytes(256,'big')
    ao = 576+len(index)
    total = ao+len(assets)+(544 if public else 32)
    require(total <= MAX_BUNDLE, 'bundle size')
    prefix = (HEADER.pack(MAGIC,2,64,total,64,512,576,len(index),ao,len(assets),
                          3 if public else 1,0,key_id) + manifest + index + assets)
    return prefix + hashlib.sha256(prefix).digest() + public


def sharing_inspect(bundle, enrolled_public_keys=()):
    """Verify carried author material; explicit public anchors only classify.

    Host classification observes these supplied public anchors. It never
    enrolls one or substitutes for the native current owner/trust check.
    """
    require(type(bundle) is bytes and 769 <= len(bundle) <= MAX_BUNDLE, 'bundle size')
    magic,v,hs,total,mo,ml,io,il,ao,al,flags,reserved,kid = HEADER.unpack_from(bundle)
    require((magic,v,hs,total,mo,ml,io,reserved) ==
            (MAGIC,2,64,len(bundle),64,512,576,0) and flags in (1,3), 'sharing header')
    require(160 <= il <= 1280 and il % 80 == 0 and ao == 576+il and
            al <= MAX_BUNDLE and ao+al+(544 if flags==3 else 32)==total, 'sharing bounds')
    end = ao+al
    require(hashlib.sha256(bundle[:end]).digest()==bundle[end:end+32], 'bad content hash')
    known = False
    if flags == 1:
        require(kid==bytes(16), 'unsigned key id')
    else:
        public = bundle[end+32:end+288]
        modulus = int.from_bytes(public,'big')
        require(modulus.bit_length()==2048 and modulus&1 and
                hashlib.sha256(public).digest()[:16]==kid, 'bad public key binding')
        representative = int.from_bytes(bundle[-256:],'big')
        digest = hashlib.sha256(bundle[:-256]).digest()
        expected = b'\0\1'+b'\xff'*(256-3-len(DIGEST_INFO)-32)+b'\0'+DIGEST_INFO+digest
        require(representative < modulus and pow(representative,65537,modulus).to_bytes(256,'big')==expected,
                'bad signature')
        known = any(public_numbers(pem)[0] == modulus for pem in enrolled_public_keys)
    return {**validate(bundle[64:576],bundle[io:ao],bundle[ao:end]),
            'sha256':hashlib.sha256(bundle).hexdigest(), 'key_id':kid.hex(),
            'signature_verified':flags==3, 'author':'enrolled' if known else 'unknown',
            'runnable':False, 'installed':False, 'native_binding':False,
            'form_semantics_validated':False}


def sharing_assemble(prefix, signature):
    require(type(prefix) is bytes and type(signature) is bytes and len(signature)==256, 'detached signature size')
    require(len(prefix)>=64 and struct.unpack_from('<I',prefix,40)[0]==3, 'signed sharing prefix required')
    result = prefix+signature
    sharing_inspect(result)
    return result


def unsigned(spec, members, pem):
    """members are (kind, canonical path, exact bytes); spec is checked data."""
    require(type(spec) is dict and set(spec) == {'id', 'entry', 'icon', 'data_dir'}, 'spec fields')
    manifest = (b'BASHAPP1' + struct.pack('<II', 1, 1) + fixed(spec['id'], 64, bundle_id=True) +
                fixed(spec['entry'], 64) + fixed(spec['icon'], 64, optional=True) +
                fixed(spec['data_dir'], 32) + struct.pack('<IIII', 1, 1, 0, 0))
    require(1 <= len(members) <= 16, 'member count')
    index = bytearray(); assets = bytearray()
    for kind, path, body in members:
        require(kind in KINDS and type(body) is bytes, 'member input')
        index += MEMBER.pack(KINDS[kind], len(assets), len(body), 0, fixed(path, 64, member_kind=KINDS[kind]))
        assets += body
    validate(manifest, index, assets)
    _, key_id = public_numbers(pem)
    total = 64+256+len(index)+len(assets)+256
    require(total <= MAX_BUNDLE, 'bundle size')
    return HEADER.pack(MAGIC, 2, 64, total, 64, 256, 320, len(index),
                       320+len(index), len(assets), 0, 0, key_id) + manifest + index + assets


def inspect(bundle, pem):
    require(type(bundle) is bytes and 320 <= len(bundle) <= MAX_BUNDLE, 'bundle size')
    magic, version, hs, total, mo, ml, io, il, ao, al, flags, reserved, kid = HEADER.unpack_from(bundle)
    require((magic, version, hs, total, mo, ml, io, flags, reserved) ==
            (MAGIC, 2, 64, len(bundle), 64, 256, 320, 0, 0), 'container header')
    require(80 <= il <= 1280 and il % 80 == 0 and ao == 320+il and
            al <= MAX_BUNDLE and ao+al+256 == total, 'container bounds')
    modulus, expected_id = public_numbers(pem)
    require(kid == expected_id, 'untrusted key')
    representative = int.from_bytes(bundle[-256:], 'big')
    digest = hashlib.sha256(bundle[:-256]).digest()
    em = b'\0\1' + b'\xff'*(256-3-len(DIGEST_INFO)-32) + b'\0' + DIGEST_INFO + digest
    require(representative < modulus and pow(representative, 65537, modulus).to_bytes(256, 'big') == em,
            'bad signature')
    return {**validate(bundle[64:320], bundle[io:ao], bundle[ao:-256]),
            'sha256': hashlib.sha256(bundle).hexdigest(), 'key_id': kid.hex(),
            'signature_verified': True, 'runnable': False, 'native_binding': False}


def read_regular(path, limit):
    """Bounded nofollow read; directory traversal policy belongs to member_read."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'regular bounded input required')
        chunks = bytearray()
        while len(chunks) <= limit:
            part = os.read(fd, min(8192, limit+1-len(chunks)))
            if not part:
                break
            chunks += part
        after = os.fstat(fd)
        require(len(chunks) == before.st_size and len(chunks) <= limit and
                (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'changed input')
        return bytes(chunks)
    finally:
        os.close(fd)


def member_read(root, relative, *, kind=None):
    # Only the exact reserved leaf for its role escapes the ordinary grammar.
    member_kind = KINDS.get(kind)
    if relative not in RESERVED_MEMBERS.values():
        member_kind = None
    fixed(relative, 64, member_kind=member_kind)
    limit = MEMBER_CAPS.get(KINDS.get(kind), 8192)
    # Opening every directory component via dir_fd closes symlink-ancestor and
    # rename races. The signed member bytes are the snapshot actually read.
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = relative.split('/')
        for component in parts[:-1]:
            newfd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = newfd
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            st = os.fstat(leaf)
            require(stat.S_ISREG(st.st_mode) and 1 <= st.st_size <= limit, 'member file size/type')
            data = bytearray()
            while len(data) <= limit:
                chunk = os.read(leaf, min(8192, limit+1-len(data)))
                if not chunk:
                    break
                data += chunk
            end = os.fstat(leaf)
            require(len(data) == st.st_size and (st.st_size,st.st_mtime_ns,st.st_ctime_ns) ==
                    (end.st_size,end.st_mtime_ns,end.st_ctime_ns), 'changed member')
            return bytes(data)
        finally:
            os.close(leaf)
    finally:
        os.close(fd)


def spec_unsigned(path, pem, *, sharing=False):
    def unique(pairs):
        obj = {}
        for k, v in pairs:
            require(k not in obj, 'duplicate JSON field')
            obj[k] = v
        return obj
    try:
        spec = json.loads(read_regular(path,16384), object_pairs_hook=unique)
    except (ValueError, RecursionError) as exc:
        raise Refusal('invalid spec JSON') from exc
    keys = {'id','entry','icon','data_dir','members'} | ({'name','version'} if sharing else set())
    require(type(spec) is dict and set(spec) == keys, 'spec fields')
    members = spec.pop('members')
    require(type(members) is list and 1 <= len(members) <= 16, 'member count')
    result = []
    for item in members:
        require(type(item) is dict and set(item) == {'kind','path','source'}, 'member fields')
        require(type(item['kind']) is str and item['kind'] in KINDS, 'member kind')
        result.append((item['kind'],item['path'],member_read(path.parent,item['source'],kind=item['kind'])))
    return sharing_unsigned(spec,result,pem) if sharing else unsigned(spec,result,pem)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    subs = ap.add_subparsers(dest='operation',required=True)
    analysis=subs.add_parser('share-analyze')
    analysis.add_argument('input',type=Path)
    analysis.add_argument('--registry',required=True,type=Path,
                          help='public JSON array of [name,cap,argt,selk,destr] in actual registry order')
    for name in ('unsigned','assemble','inspect','share-unsigned','share-assemble','share-inspect'):
        sub = subs.add_parser(name)
        sub.add_argument('input',type=Path)
        sub.add_argument('--public-key',required=not name.startswith('share-'),type=Path)
        if not name.endswith('inspect'):
            sub.add_argument('--output',required=True,type=Path)
        if name.endswith('assemble'):
            sub.add_argument('--signature',required=True,type=Path)
        if name == 'share-inspect':
            sub.add_argument('--enrolled-public-key',action='append',type=Path,default=[])
    ns = ap.parse_args()
    try:
        if ns.operation=='share-analyze':
            from paos_package_analysis import analyze, public_report
            registry=json.loads(read_regular(ns.registry,65536))
            require(type(registry) is list and len(registry)<=426,'registry array')
            require(all(type(row) is list and len(row)==5 and type(row[0]) is str and
                        all(type(n) is int and 0<=n<2**64 for n in row[1:]) for row in registry),'registry row')
            print(json.dumps(public_report(analyze(read_regular(ns.input,MAX_BUNDLE),registry)),sort_keys=True))
            return
        pem = read_regular(ns.public_key,4096) if ns.public_key else None
        if ns.operation.endswith('unsigned'):
            result = spec_unsigned(ns.input,pem,sharing=ns.operation.startswith('share-'))
        else:
            result = read_regular(ns.input,MAX_BUNDLE)
            if ns.operation.endswith('assemble'):
                signature = read_regular(ns.signature,256)
                require(len(signature) == 256, 'signature size')
                result = sharing_assemble(result,signature) if ns.operation.startswith('share-') else result+signature
            if ns.operation.startswith('share-'):
                anchors = [read_regular(p,4096) for p in getattr(ns,'enrolled_public_key',[])]
                report = sharing_inspect(result,anchors)
                if pem is not None:
                    require(report['signature_verified'] and report['key_id']==public_numbers(pem)[1].hex(), 'explicit author mismatch')
            else:
                report = inspect(result,pem)
            if ns.operation.endswith('inspect'):
                print(json.dumps(report, sort_keys=True))
                return
        with ns.output.open('xb') as f:
            f.write(result)
    except (OSError, ValueError) as exc:
        ap.exit(1, str(exc)+'\n')


if __name__ == '__main__':
    main()
