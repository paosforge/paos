#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebuild fixed development script-app fixtures with the maintained SDK.

Default: public inputs + saved detached development signatures. --prefixes-only
prepares the same inputs for a separately selected author; it never signs,
enrolls, installs or executes anything. Negative fixtures are deliberately invalid.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools/release'))
import paos_script_sdk as sdk

POSITIVES = ('install48', 'install96', 'installnone', 'runtime48', 'runtime96', 'runtimenone')
NEGATIVES = ('wrong48', 'missingcredits')
NAMES = POSITIVES + NEGATIVES


def prefix(name: str, public: bytes) -> bytes:
    """Exact fixed example; no arbitrary manifest, input path or private key."""
    if name not in NAMES:
        raise sdk.Refusal('unknown example')
    mode = '48' if name in NEGATIVES else name.removeprefix('install').removeprefix('runtime')
    spec = dict(id='org.example.icon' + mode, entry='main.sh',
                icon='' if mode == 'none' else 'icon.png', data_dir='data')
    members = [('script', 'main.sh', sdk.member_read(HERE, 'main.sh')),
               ('form', 'main.frm', sdk.member_read(HERE, 'main.frm')),
               ('grants', 'grants', sdk.member_read(HERE, 'grants'))]
    if mode != 'none':
        members += [('icon', 'icon.png', sdk.member_read(HERE, 'icon.png', kind='icon')),
                    ('notices', 'NOTICES.json', sdk.member_read(HERE, 'NOTICES.json', kind='notices'))]
    if mode == '96':
        members.append(('icon2x', 'icon@2x.png', sdk.member_read(HERE, 'icon@2x.png', kind='icon2x')))
    if name.startswith('install'):
        spec.update(name='Script icon check ' + mode, version='1.0.0')
        return sdk.sharing_unsigned(spec, members, public)
    raw = bytearray(sdk.unsigned(spec, members, public))
    if name in NEGATIVES:
        # Mutate just one fixed already-encoded fixture before detached signing.
        # This intentionally bypasses author lint for the two refusal controls;
        # production construction and verification remain in paos_script_sdk.
        io, il, ao = struct.unpack_from('<III', raw, 24)
        for at in range(io, io + il, sdk.MEMBER.size):
            kind, off, size, reserved, path = sdk.MEMBER.unpack_from(raw, at)
            if name == 'wrong48' and kind == 3:
                image = ao + off
                struct.pack_into('>I', raw, image + 16, 49)
                struct.pack_into('>I', raw, image + 29, zlib.crc32(raw[image+12:image+29]))
            elif name == 'missingcredits' and kind == 7:
                sdk.MEMBER.pack_into(raw, at, 4, off, size, reserved,
                                     b'data/notices.json'.ljust(64, b'\0'))
    return bytes(raw)


def build(output: Path, *, public: bytes | None = None, prefixes_only: bool = False) -> dict:
    if public is not None and not prefixes_only:
        raise sdk.Refusal('selected author requires --prefixes-only and external detached signing')
    public = public if public is not None else sdk.read_regular(HERE / 'dev-public.pem', 4096)
    sdk.public_numbers(public)
    signatures = {} if prefixes_only else json.loads(sdk.read_regular(HERE / 'SIGNATURES.json', 16384))
    if not prefixes_only and set(signatures) != set(NAMES):
        raise sdk.Refusal('fixed detached signature set')
    files = {}
    # Verify all inputs before creating the new directory; never overwrite output.
    for name in NAMES:
        data = prefix(name, public)
        if not prefixes_only:
            signature = bytes.fromhex(signatures[name])
            if len(signature) != 256:
                raise sdk.Refusal('detached signature size')
            data += signature
            if name in POSITIVES:
                if name.startswith('install'):
                    sdk.sharing_inspect(data, [public])
                else:
                    sdk.inspect(data, public)
            else:
                # Independently verify malformed fixtures' signatures: a refusal
                # must exercise content validation rather than a corrupt signature.
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import padding
                serialization.load_pem_public_key(public).verify(signature, data[:-256],
                    padding.PKCS1v15(), hashes.SHA256())
        files[name + ('.prefix' if prefixes_only else '.pax')] = data
    receipt = dict(schema='paos.sdk-script-icon-example.v1', development_only=True,
                   native_qualified=False, runnable=False, installed=False,
                   author_key_id=sdk.public_numbers(public)[1].hex(),
                   mode='external-detached-prefixes' if prefixes_only else 'saved-development-signatures',
                   files={name: dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                       expected='refuse content' if name.split('.')[0] in NEGATIVES else 'checked program/data; native authority required')
                          for name, data in files.items()})
    output.mkdir()
    for name, data in files.items():
        with (output / name).open('xb') as stream:
            stream.write(data)
    (output / 'RECEIPT.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--public-key', type=Path)
    parser.add_argument('--prefixes-only', action='store_true')
    args = parser.parse_args()
    try:
        public = sdk.read_regular(args.public_key, 4096) if args.public_key else None
        print(json.dumps(build(args.output_dir, public=public, prefixes_only=args.prefixes_only), sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(json.dumps(dict(ok=False, error=str(error), runnable=False)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
