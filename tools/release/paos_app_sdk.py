#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build/inspect PaOS v1 bundles, diagnose recipes and decode replies offline.

assemble needs only public inputs: manifest, recipes, assets, public key and an
existing detached signature. dev-sign generates a fresh RSA key in memory and
never saves/loads a private key. Native trust requires owner enrollment of the
public modulus; verifying here neither enrolls a key nor qualifies a candidate.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

MAGIC = b'PAOSAPP1'
CAPABILITIES = frozenset(('sys.read', 'net.read', 'fs.read', 'gui.read', 'gui.write'))
MAX_BUNDLE = 16384
# Caller-supplied task reports are offline authoring input, never authority.
MAX_TASK_TRACE = 8192
# Offline consumer resource limit, not an additional native wire-format promise.
MAX_REPLY_BODY = 16384
# Accepted native descriptor capacity; independent of the host body size limit.
MAX_HOOK_EDGES = 128
REPLY_SELECTORS = ('STATUS', 'HOOK LIST', 'HOOK GET net', 'HOOK DESCRIBE net',
                   'HOOK GET fs', 'HOOK DESCRIBE fs', 'HOOK DESCRIBE audio')
CATALOG_SELECTOR = re.compile(r'HOOK CATALOG(?: (0|[1-9][0-9]{0,2}))?')
AUDIO_SELECTOR = re.compile(r'HOOK GET audio playback [0-9a-f]{16}')
# Native NETCFG staging includes a storage NUL, which is not a body byte.
NET_MEMBERS_CAP = 832
NET_DECIMAL = rb'(?:0|[1-9][0-9]{0,9})'
NET_NAME = rb'(?:[A-Za-z0-9_.-]{1,15}|\?)'
NET_MEMBER = re.compile(
    rb'M=([0-7]):(' + NET_NAME + rb'):(' + NET_NAME +
    rb'):(-|[0-9a-f]{12}):(' + NET_DECIMAL +
    rb'):(ok|degraded|absent|dead|h' + NET_DECIMAL +
    rb'):(0|1):(-|down|err|up' + NET_DECIMAL + rb')')
HOOK_OPERATIONS = ('LIST', 'DESCRIBE', 'GET', 'SET', 'INPUT', 'OBSERVE', 'CANCEL', 'EVENTS')
HOOK_ENTRY = re.compile(rb'([a-z_][a-z0-9_]*):(app|widget|service|storage|job|network|vm|device|power|session|desktop)')
HEADER = struct.Struct('<8sHH9I16s')
DIGEST_INFO = bytes.fromhex('3031300d060960864801650304020105000420')
NAME = re.compile(r'[a-z][a-z0-9_-]{0,31}')


class Refusal(ValueError):
    pass


def require(condition, marker='[app.bundle.malformed]'):
    if not condition:
        raise Refusal(marker)


def lines(data: bytes, limit: int, marker: str) -> list[str]:
    require(1 <= len(data) <= limit, marker)
    require(data.endswith(b'\n'), marker)
    require(all(b == 10 or 32 <= b <= 126 for b in data), marker)
    result = data[:-1].decode('ascii').split('\n')
    require(all(result), marker)
    return result


def validate_text(manifest: bytes, recipes: bytes) -> dict:
    # SDK is line one and is refused predictably, including missing terminal LF.
    require(manifest.startswith(b'sdk=1\n'), '[app.contract.unsupported] layer=sdk')
    mlines = lines(manifest, 2048, '[app.bundle.malformed] why=manifest')
    values = {}
    for line in mlines:
        key, sep, value = line.partition('=')
        require(sep and key in ('sdk','id','version','caps','entry') and key not in values, '[app.bundle.malformed] why=manifest')
        values[key] = value
    require(set(values) == {'sdk','id','version','caps','entry'}, '[app.bundle.malformed] why=manifest')
    require(re.fullmatch(r'[a-z0-9.-]{3,63}', values['id']), '[app.bundle.malformed] why=manifest')
    version = values['version'].split('.')
    require(len(version) == 3 and all(re.fullmatch(r'[0-9]{1,5}', v) and int(v) <= 65535 for v in version), '[app.bundle.malformed] why=manifest')
    caps = values['caps'].split(',') if values['caps'] else []
    require(len(caps) <= 8 and len(set(caps)) == len(caps) and all(c in CAPABILITIES for c in caps), '[app.bundle.malformed] why=manifest')
    entries = values['entry'].split(',')
    require(1 <= len(entries) <= 4 and len(set(entries)) == len(entries) and all(NAME.fullmatch(n) for n in entries), '[app.bundle.malformed] why=manifest')
    rlines = lines(recipes, 8192, '[app.bundle.malformed] why=recipe')
    defined = {}; current = None
    for line in rlines:
        require(len(line) <= 160, '[app.bundle.malformed] why=recipe')
        if line.startswith('recipe '):
            name = line[7:]
            require(current is None and NAME.fullmatch(name) and name not in defined and len(defined) < 4, '[app.bundle.malformed] why=recipe')
            current = name; defined[name] = []
        elif line.startswith('step '):
            require(current is not None and len(defined[current]) < 16, '[app.bundle.malformed] why=recipe')
            require(re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}(?: [ -~]*)?', line[5:]), '[app.bundle.malformed] why=recipe')
            defined[current].append(line[5:])
        elif line == 'end':
            require(current is not None and defined[current], '[app.bundle.malformed] why=recipe')
            current = None
        else:
            raise Refusal('[app.bundle.malformed] why=recipe')
    require(current is None and defined, '[app.bundle.malformed] why=recipe')
    # Match native app_check_entries after all recipe syntax has been validated.
    require(all(n in defined for n in entries), '[app.bundle.malformed] why=manifest')
    return {'id':values['id'], 'version':values['version'], 'caps':caps, 'entries':entries, 'recipes':defined}


def gui_selector(command: str):
    """Mirror only the native APP named patterns; this grants no authority."""
    if command in ('HOOK GET forms', 'HOOK DESCRIBE forms', 'HOOK DESCRIBE form',
                   'HOOK DESCRIBE widget', 'HOOK CATALOG'):
        return command, 'sys.read'
    if command == 'HOOK LIST widget':
        return command, 'gui.read'
    decimal = r'(0|[1-9][0-9]{0,9})'
    match = re.fullmatch(r'HOOK CATALOG '+decimal, command)
    if match and int(match[1]) <= 128:
        return command, 'sys.read'
    match = re.fullmatch(r'HOOK LIST widget '+decimal, command)
    if match and int(match[1]) <= 2147483647:
        return command, 'gui.read'
    match = re.fullmatch(r'HOOK (?:GET|OBSERVE) widget:'+decimal+
                         r' (?:role|label|intent|intent_seq|value|min|max|step|sel)', command)
    if match and int(match[1]) <= 2147483647:
        return command, 'gui.read'
    match = re.fullmatch(r'HOOK SET widget:'+decimal+r' value '+decimal, command)
    if match and all(int(n) <= 2147483647 for n in match.groups()):
        return command, 'gui.write'
    match = re.fullmatch(r'HOOK GET form:[a-z][a-z0-9_]{0,30} page '+decimal+
                         ' read '+decimal+' '+decimal, command)
    if match and 1 <= int(match[1]) <= 4294967295 and int(match[2]) <= 1280 and 1 <= int(match[3]) <= 384:
        return command, 'sys.read'
    return None


def diagnose_selectors(manifest: bytes, recipes: bytes) -> dict:
    """Report the documented v1 selectors; never authorize or dispatch.

    Syntax validation is shared with assembly/inspection. This optional report
    does not consult the live registry or alter which bundles are loadable.
    """
    require(isinstance(manifest, bytes) and isinstance(recipes, bytes),
            'manifest and recipe bytes required')
    meta = validate_text(manifest, recipes)
    result = []
    for name, commands in meta['recipes'].items():
        steps = []
        for index, command in enumerate(commands, 1):
            # app_bundle_run splits at the first literal space. app_match_row
            # compares both the verb and the entire remaining args string.
            verb, _, args = command.partition(' ')
            row = {('STATUS', ''): ('STATUS', 'sys.read'),
                   ('HOOK', 'LIST'): ('HOOK LIST', 'sys.read'),
                   ('HOOK', 'GET net'): ('HOOK GET net', 'net.read'),
                   ('HOOK', 'DESCRIBE net'): ('HOOK DESCRIBE net', 'sys.read'),
                   ('HOOK', 'GET fs'): ('HOOK GET fs', 'fs.read'),
                   ('HOOK', 'DESCRIBE fs'): ('HOOK DESCRIBE fs', 'sys.read'),
                   ('HOOK', 'DESCRIBE audio'): ('HOOK DESCRIBE audio', 'sys.read')}.get((verb, args))
            if AUDIO_SELECTOR.fullmatch(command):
                row = (command, 'sys.read')
            row = row or gui_selector(command)
            selector, permission = row if row else (None, None)
            declared = permission in meta['caps'] if selector else None
            steps.append({'step': index, 'command': command,
                          'command_base64': base64.b64encode(command.encode('ascii')).decode('ascii'),
                          'documented_selector': selector,
                          'required_permission': permission,
                          'permission_declared': declared,
                          'diagnostic': ('documented-selector' if declared else 'missing-declared-permission')
                                        if selector else 'undocumented-selector'})
        result.append({'name': name, 'steps': steps})
    return {'schema': 'paos.sdk-recipe-selector-diagnostics.v1', 'diagnostic_only': True,
            'declared_permissions': meta['caps'], 'entries': meta['entries'], 'recipes': result,
            'selectors_checked': False, 'runnable': False,
            'native_qualified': False, 'official_signature': False}


def capture_recipe(trace: bytes, app_id: str, version: str, entry: str) -> dict:
    """Draft native v1 text from reported completed calls, without executing.

    A trace is an untrusted caller report, not proof that a task ran or passed
    native authorization. Only the existing SDK's documented observation rows
    are captured; its grammar, selector comparison and permission names apply.
    """
    marker = '[app.recipe.capture.refused]'
    require(type(trace) is bytes and 1 <= len(trace) <= MAX_TASK_TRACE, marker)
    require(all(type(v) is str and 1 <= len(v) <= 63
                for v in (app_id, version, entry)), marker)

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, marker)
            result[key] = value
        return result

    def no_constant(value):
        raise Refusal(marker)

    try:
        report = json.loads(trace.decode('utf-8'), object_pairs_hook=unique_object,
                            parse_constant=no_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Refusal(marker) from exc
    require(type(report) is dict and set(report) == {'schema', 'status', 'steps'}, marker)
    require(report['schema'] == 'paos.assistant-task-trace.v1' and
            report['status'] == 'completed', marker)
    steps = report['steps']
    require(type(steps) is list and 1 <= len(steps) <= 16, marker)
    calls = []
    for step in steps:
        require(type(step) is dict and set(step) == {'command', 'code'}, marker)
        require(type(step['code']) is int and step['code'] == 0, marker)
        call = step['command']
        require(type(call) is str and 1 <= len(call) <= 155 and
                all(32 <= ord(c) <= 126 for c in call), marker)
        calls.append(call)

    def manifest(caps):
        return (f'sdk=1\nid={app_id}\nversion={version}\ncaps={",".join(caps)}\n'
                f'entry={entry}\n').encode('ascii')

    # Build only native text, then share the existing SDK validator/diagnostic.
    # No provider output, identity or capability assertion is copied into it.
    try:
        recipes = (f'recipe {entry}\n' + ''.join(f'step {c}\n' for c in calls) +
                   'end\n').encode('ascii')
        diagnostic = diagnose_selectors(manifest(sorted(CAPABILITIES)), recipes)
    except UnicodeError as exc:
        raise Refusal(marker) from exc
    permissions = []
    for step in diagnostic['recipes'][0]['steps']:
        permission = step['required_permission']
        require(permission is not None, marker)
        if permission not in permissions:
            permissions.append(permission)
    manifest_bytes = manifest(permissions)
    diagnostic = diagnose_selectors(manifest_bytes, recipes)
    return {'schema': 'paos.assistant-recipe-draft.v1', 'diagnostic_only': True,
            'source_success': 'caller-reported', 'source_success_verified': False,
            'trace_sha256': hashlib.sha256(trace).hexdigest(),
            'manifest_text': manifest_bytes.decode('ascii'),
            'recipes_text': recipes.decode('ascii'), 'step_count': len(calls),
            'declared_permissions': permissions, 'selector_diagnostics': diagnostic,
            'selectors_checked': False, 'runnable': False,
            'native_qualified': False, 'official_signature': False}


def public_numbers(pem: bytes) -> tuple[int, bytes]:
    # Public-only armor, one bounded block. No private key deserializer exists.
    require(len(pem) <= 4096 and re.fullmatch(rb'-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?', pem), 'public RSA-2048 key required')
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    try:
        key = serialization.load_pem_public_key(pem)
        require(isinstance(key, rsa.RSAPublicKey), 'public RSA-2048 key required')
        numbers = key.public_numbers()
        require(numbers.e == 65537 and numbers.n.bit_length() == 2048 and numbers.n & 1, 'RSA-2048 exponent 65537 required')
    except (ValueError, TypeError) as exc:
        raise Refusal('public RSA-2048 key required') from exc
    return numbers.n, hashlib.sha256(numbers.n.to_bytes(256,'big')).digest()[:16]


def unsigned(manifest: bytes, recipes: bytes, assets: bytes, pem: bytes) -> bytes:
    validate_text(manifest, recipes)
    _, key_id = public_numbers(pem)
    total = 64 + len(manifest) + len(recipes) + len(assets) + 256
    require(total <= MAX_BUNDLE, '[app.bundle.malformed] why=size')
    header = HEADER.pack(MAGIC,1,64,total,64,len(manifest),64+len(manifest),len(recipes),64+len(manifest)+len(recipes),len(assets),0,0,key_id)
    return header + manifest + recipes + assets


def inspect_bundle(bundle: bytes, pem: bytes) -> dict:
    require(320 < len(bundle) <= MAX_BUNDLE and bundle[:8] == MAGIC, '[app.bundle.malformed] why=size|magic')
    magic, container, header, total, mo, ml, ro, rl, ao, al, flags, reserved, key_id = HEADER.unpack_from(bundle)
    require(container == 1, '[app.contract.unsupported] layer=container')
    require(header == 64 and total == len(bundle) and mo == 64 and 1 <= ml <= 2048 and ro == mo+ml and 1 <= rl <= 8192 and ao == ro+rl and al == total-256-ao and flags == 0 and reserved == 0, '[app.bundle.malformed] why=header')
    modulus, expected_id = public_numbers(pem)
    require(key_id == expected_id, '[app.sig.untrusted]')
    signature = bundle[-256:]
    representative = int.from_bytes(signature,'big')
    require(representative < modulus, '[app.sig.bad]')
    # Strict PKCS#1 v1.5 SHA-256: exact-length FF padding and DigestInfo.
    expected = b'\0\x01' + b'\xff'*(256-3-len(DIGEST_INFO)-32) + b'\0' + DIGEST_INFO + hashlib.sha256(bundle[:-256]).digest()
    require(pow(representative,65537,modulus).to_bytes(256,'big') == expected, '[app.sig.bad]')
    meta = validate_text(bundle[mo:ro], bundle[ro:ao])
    return {**meta,'key_id':key_id.hex(),'bundle_sha256':hashlib.sha256(bundle).hexdigest(), 'signature_verified':True, 'runnable':False, 'selectors_checked':False, 'native_qualified':False,'official_signature':False}


def assemble(manifest: bytes, recipes: bytes, assets: bytes, pem: bytes, signature: bytes) -> bytes:
    require(len(signature) == 256, '[app.sig.bad]')
    bundle = unsigned(manifest, recipes, assets, pem) + signature
    inspect_bundle(bundle, pem)
    return bundle


def dev_sign(manifest: bytes, recipes: bytes, assets: bytes) -> tuple[bytes, bytes, bytes]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    validate_text(manifest, recipes)
    # Key exists only in process memory. No secret import or serialization.
    key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    public = key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    prefix = unsigned(manifest, recipes, assets, public)
    signature = key.sign(prefix,padding.PKCS1v15(),hashes.SHA256())
    bundle = assemble(manifest, recipes, assets, public, signature)
    return bundle, public, signature


def read_input(path: Path, limit: int) -> bytes:
    # Known secret aliases are refused before any content is read.
    name = path.name.casefold()
    require(not (name.startswith('id_') or name.endswith(('.key','.p12','.pfx','private.pem')) or name.startswith('ssh_host_')), 'private-key input forbidden')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'nonregular input forbidden')
        require(before.st_size <= limit, 'input exceeds bound')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit+1)
        after = os.fstat(fd)
        require(len(data) <= limit, 'input exceeds bound')
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(len(data) == before.st_size and identity(before) == identity(after),
                'input changed while reading')
        return data
    finally:
        os.close(fd)


def decode_reply(selector: str, body: bytes) -> dict:
    """Decode an already unframed v1 body; never authenticate or dispatch it.

    STATUS and DESCRIBE net are opaque. HOOK LIST follows contract-v1/VERBS.md
    without normalizing whitespace or sorting profiles; legacy decimal spelling
    remains intact. CATALOG pages bind their canonical cursor and complete entries.
    GET net checks the complete native member grammar and preserves unknowns.
    GET fs follows complete ordered FSINFO; descriptions check their literal schema.
    Audio playback follows complete ordered v2 bytes and the exact request nonce.
    JSON carries original bytes in base64; the native authority token is data.
    """
    require(isinstance(selector, str) and
            (selector in REPLY_SELECTORS or AUDIO_SELECTOR.fullmatch(selector) or
             _catalog_cursor(selector) is not None),
            'unsupported reply selector')
    require(isinstance(body, bytes), 'reply body bytes required')
    require(len(body) <= MAX_REPLY_BODY, 'reply body exceeds bound')
    result = {'selector': selector, 'body_base64': base64.b64encode(body).decode('ascii'),
              'native_qualified': False, 'runnable': False,
              'selectors_checked': False, 'official_signature': False}
    if selector == 'STATUS':
        return {'schema': 'paos.sdk-opaque-status.v1', **result}
    if selector in ('HOOK GET net', 'HOOK DESCRIBE net'):
        # Claimed native bytes have no authenticated source or response code.
        result.update(provenance='saved-unauthenticated', authenticated=False)
        if selector == 'HOOK DESCRIBE net':
            return {'schema': 'paos.sdk-opaque-net-description.v1', **result}
        return {**_decode_net_members(body), **result}
    if selector in ('HOOK GET fs', 'HOOK DESCRIBE fs'):
        result.update(provenance='saved-unauthenticated', authenticated=False)
        return {**(_decode_fsinfo(body) if selector == 'HOOK GET fs'
                   else _decode_fs_description(body)), **result}
    if selector == 'HOOK DESCRIBE audio' or AUDIO_SELECTOR.fullmatch(selector):
        result.update(provenance='saved-unauthenticated', authenticated=False)
        return {**(_decode_audio_description(body) if selector == 'HOOK DESCRIBE audio'
                   else _decode_audio_playback(body, selector[-16:])), **result}
    if selector.startswith('HOOK CATALOG') or body.startswith(b' hook catalog '):
        return {**_decode_hook_page(body, _catalog_cursor(selector) or 0), **result,
                'provenance': 'saved-unauthenticated', 'authenticated': False}
    marker = '[app.reply.malformed] why=hook-list'
    # Split on literal space only: no strip(), splitlines(), newline or envelope
    # guessing. Every token is either exact ASCII or matched by an ASCII pattern.
    parts = body.split(b' ')
    require(len(parts) >= 6 and parts[:3] == [b'', b'hook', b'v=1'], marker)
    require(parts[-2:] == [b'ops=' + ','.join(HOOK_OPERATIONS).encode('ascii'),
                           b'authority=native'], marker)
    require(re.fullmatch(rb'edges=[0-9]+', parts[3]) is not None, marker)
    count_text = parts[3][6:].lstrip(b'0') or b'0'
    # Avoid unbounded integer conversion while permitting any decimal spelling
    # within the body size bound, including leading zeroes.
    require(len(count_text) <= 3, marker)
    count = int(count_text)
    require(count <= MAX_HOOK_EDGES and len(parts[4:-2]) == count, marker)
    entries = []
    for token in parts[4:-2]:
        match = HOOK_ENTRY.fullmatch(token)
        require(match is not None, marker)
        entries.append({'name': match[1].decode('ascii'), 'kind': match[2].decode('ascii')})
    return {'schema': 'paos.sdk-hook-catalog.v1', 'version': 1, 'edge_count': count,
            'edges': entries, 'operations': list(HOOK_OPERATIONS), 'authority': 'native', **result}


def _catalog_cursor(selector: str):
    match = CATALOG_SELECTOR.fullmatch(selector)
    if match is None:
        return None
    value = int(match[1] or '0')
    return value if value <= MAX_HOOK_EDGES else None


def _decode_hook_page(body: bytes, requested: int) -> dict:
    """Decode one saved page, retaining stream position rather than completeness."""
    marker = '[app.reply.malformed] why=hook-catalog-page'
    require(len(body) <= 1023, marker)
    parts = body.split(b' ')
    footer = b'ops=CATALOG,' + ','.join(HOOK_OPERATIONS).encode('ascii')
    require(len(parts) >= 10 and parts[:4] == [b'', b'hook', b'catalog', b'v=1'] and
            parts[-2:] == [footer, b'authority=native'], marker)
    values = []
    for key, token in zip((b'edges=', b'from=', b'next='), parts[4:7]):
        require(token.startswith(key), marker)
        digits = token[len(key):]
        require(re.fullmatch(rb'(?:0|[1-9][0-9]{0,2})', digits) is not None, marker)
        value = int(digits)
        require(value <= MAX_HOOK_EDGES, marker)
        values.append(value)
    total, start, end = values
    require(parts[7] in (b'more=0', b'more=1') and start == requested and
            start <= end <= total and (end > start or end == total), marker)
    more = parts[7] == b'more=1'
    require(more == (end < total), marker)
    entries = []
    for token in parts[8:-2]:
        match = HOOK_ENTRY.fullmatch(token)
        require(match is not None, marker)
        entries.append(dict(name=match[1].decode('ascii'), kind=match[2].decode('ascii')))
    require(len(entries) == end-start and
            len({row['name'] for row in entries}) == len(entries), marker)
    return dict(schema='paos.sdk-hook-catalog-page.v1', version=1, edge_count=total,
                start=start, next=end, more=more, returned=len(entries), edges=entries,
                operations=['CATALOG', *HOOK_OPERATIONS], authority='native')


def _decode_net_members(body: bytes) -> dict:
    """Internal grammar parser matching native hnm_record, not its authority.

    No inference from error text or missing members. The native post filter also
    checks response code/count, staging extent and one-use owner-UDP custody;
    none of those facts can be recovered from an unauthenticated saved body.
    """
    marker = '[app.reply.malformed] why=net-members'
    require(len(body) < NET_MEMBERS_CAP, marker)
    if body == b' hook err=net_members_reply_unavailable':
        return {'schema': 'paos.sdk-net-members.v1', 'observation': 'unavailable'}
    parts = body.split(b' ')
    require(len(parts) >= 4 and parts[:2] == [b'NETCFG', b'MEMBERS'], marker)
    require(re.fullmatch(rb'n=[0-8]', parts[2]) is not None, marker)
    require(re.fullmatch(rb'sel=(?:-|[0-7])', parts[3]) is not None, marker)
    count = int(parts[2][2:])
    selected = None if parts[3] == b'sel=-' else int(parts[3][4:])
    require(len(parts[4:]) == count, marker)
    members = []
    previous = -1
    for token in parts[4:]:
        match = NET_MEMBER.fullmatch(token)
        require(match is not None, marker)
        slot, name, driver, mac, priority, health, chosen, link = match.groups()
        slot, priority = int(slot), int(priority)
        require(slot > previous and priority <= 0xffffffff, marker)
        previous = slot
        if health.startswith(b'h'):
            require(3 <= int(health[1:]) <= 0xffffffff, marker)
        require((chosen == b'1') == (slot == selected), marker)
        speed = int(link[2:]) if link.startswith(b'up') else None
        require(speed is None or speed <= 0xffffff, marker)
        members.append({'slot': slot, 'name': name.decode('ascii'),
                        'driver': driver.decode('ascii'), 'mac': mac.decode('ascii'),
                        'priority': priority, 'health': health.decode('ascii'),
                        'selected': chosen == b'1', 'link': link.decode('ascii'),
                        'link_speed_mbps': speed})
    require(selected is None or any(m['slot'] == selected for m in members), marker)
    return {'schema': 'paos.sdk-net-members.v1', 'observation': 'members',
            'member_count': count, 'selected_slot': selected, 'members': members}


# Native FSINFO staging includes a terminating storage NUL, not a body byte.
FSINFO_CAP = 1408
FS_DESCRIPTION_CAP = 1024
FS_DESCRIPTION = (
    b' hook describe edge=fs kind=storage inst=none|<abs path, no spaces> list=FSLS(<dir>|/) get=FSI'
    b'NFO{VOL,BACKEND,CLUSTER,TOTAL,FREE,ORPHANS,DEV,PART_START,PART_SECTORS,SCHEME}|FSSTAT{NAME,SIZ'
    b'E,DIR}|hash:FSHASH{SIZE,SHA256}|read:<offset>:<length>:FSREAD{NONCE,OFF,LEN,SHA256,DATA}(lengt'
    b'h=1..256;native-u64-parser;owner-MUTATE) observe=SIZE,DIR,SHA256,FREE,ORPHANS,ERR,OFF,LEN,DATA'
    b',VOL,BACKEND,CLUSTER,TOTAL,DEV,PART_START,PART_SECTORS,SCHEME set=rename '
    b'<canonical-abs-dst>:FSREN <inst-src> <dst> <nonce>(native-owner-MUTATE;native-armed-backend;no'
    b'-auto-arm)|create:<hex>:FSNEW|delete:FSDEL|write:<hex>:FSWRITE|write_at:<offset>:<hex>:FSWRITE'
    b'(native-supported-range;canonical-scratch;no-auto-arm;nonempty-even-hex;native-u64-parser)|mkd'
    b'ir:FSMKDIR|rmdir:FSRMDIR <inst-path> <nonce> input=na cancel=na'
)
FSINFO = re.compile(
    rb'FSINFO NONCE=([0-9A-Fa-f]{16}) VOL=([0-9A-Fa-f]{8}) BACKEND=([!-~]+)'
    rb' CLUSTER=([0-9]+) TOTAL=([0-9]+) FREE=([0-9]+|unsupported)'
    rb' ORPHANS=([0-9]+|unsupported) DEV=([A-Za-z0-9_.:-]{1,63}|unavailable)'
    rb' PART_START=([0-9]+|unavailable) PART_SECTORS=([0-9]+|unavailable)'
    rb' SCHEME=(gpt|mbr|superfloppy|unavailable)')


def _decode_fsinfo(body: bytes) -> dict:
    """Parse complete native observations, without claiming native custody.

    No cross-field equality, geometry consistency or canonical decimal/hex
    spelling check: the producer supplies no such public validation contract.
    Original spelling remains recoverable from body_base64.
    """
    marker = '[app.reply.malformed] why=fsinfo'
    require(len(body) < FSINFO_CAP, marker)
    if body == b'FSINFO ERR no_data_mount':
        return {'schema': 'paos.sdk-fsinfo.v1', 'observation': 'unavailable',
                'reason': 'no_data_mount'}
    match = FSINFO.fullmatch(body)
    require(match is not None, marker)
    nonce, volume, backend, cluster, total, free, orphans, device, start, sectors, scheme = match.groups()
    def number(value, bits, missing=None):
        if value == missing:
            return value.decode('ascii')
        # Bound conversion even for noncanonical, zero-prefixed saved tokens.
        digits = value.lstrip(b'0') or b'0'
        require(len(digits) <= (10 if bits == 32 else 20), marker)
        result = int(digits)
        require(result < (1 << bits), marker)
        return result
    return {'schema': 'paos.sdk-fsinfo.v1', 'observation': 'filesystem',
            'nonce': nonce.decode('ascii'), 'volume_id': volume.decode('ascii'),
            'backend': backend.decode('ascii'), 'cluster_bytes': number(cluster,32),
            'total_sectors': number(total,64), 'free_clusters': number(free,64,b'unsupported'),
            'orphans': number(orphans,64,b'unsupported'), 'device': device.decode('ascii'),
            'part_start': number(start,64,b'unavailable'),
            'part_sectors': number(sectors,64,b'unavailable'), 'scheme': scheme.decode('ascii')}


def _decode_fs_description(body: bytes) -> dict:
    # The current producer emits this fixed complete literal. Described native
    # path/mutation operations do not become app-callable or authorized here.
    require(len(body) < FS_DESCRIPTION_CAP and body == FS_DESCRIPTION,
            '[app.reply.malformed] why=fs-description')
    return {'schema': 'paos.sdk-fs-description.v1', 'edge': 'fs', 'kind': 'storage',
            'description': body[len(b' hook describe edge=fs kind=storage '):].decode('ascii')}


# WPI1 staging is 512 bytes including NUL. The typed post replaces its
# five-byte head with this 23-byte head; the body excludes the storage NUL.
AUDIO_PLAYBACK_CAP = 530
AUDIO_DESCRIPTION_CAP = 1024
AUDIO_DESCRIPTION = (b' hook describe edge=audio kind=device '
                     b'v=1 common=op,owner_phase,owner_error,loop_phase,loop_error,native_epoch,bdf,serial,pin_count,played,captured,channels,rate,format,boot,route0..7,build pin=codec,group,nid,caps,pin_caps,config,sense,known,query node=node_count,codec,group,nid,caps,pin_caps,config,conn_len,reserved edge=edge_count,edge_index,codec,group,nid,connection_index,target,reserved route=codec,AFG,outpin,DAC,inpin,ADC,input_channels,VRef inst=explicit-u16-epoch get=stat|pin row|node row|edge row row=u16+native-count authority=HDALOOP-owner+MUTATE native-phase-epoch-row-gates=decisive record=complete-HL1 fields=u32-except-epoch-serial-played-captured:u64 observe=whole-selected-diagnostic scope=saved-software acoustic-evidence=no playback=get:playback+16lowerhexnonce,WPI1,v2,software-only list=na set=WAVPLAY-play(1|2,absolute-path;native-owner;admission-only) input=na cancel=WAVPLAY-CANCEL(inst=none,args=none;native-bound-owner;state=cleanup|retired;software-only)')
# Keep the current native literal above and preserve older saved responses.
# These aliases describe saved bytes; they add no application selector.
AUDIO_DESCRIPTION_CURRENT = AUDIO_DESCRIPTION
AUDIO_DESCRIPTION_LEGACY = (
    AUDIO_DESCRIPTION.removesuffix(
        b' list=na set=WAVPLAY-play(1|2,absolute-path;native-owner;admission-only)'
        b' input=na cancel=WAVPLAY-CANCEL(inst=none,args=none;native-bound-owner;'
        b'state=cleanup|retired;software-only)') +
    b' list=na set=na input=na cancel=na')
AUDIO_FIELDS = ('epoch', 'controller', 'serial', 'stage', 'stage_id', 'error',
                'loaded', 'size', 'frames_known', 'frames', 'producer_phase',
                'decoded_bytes', 'prepared', 'submitted', 'loop', 'backend',
                'cleanup', 'retired', 'uncertain')
AUDIO_U32 = frozenset(('controller', 'stage_id', 'error', 'producer_phase', 'loop', 'backend'))
AUDIO_FLAGS = frozenset(('frames_known', 'cleanup', 'retired', 'uncertain'))
AUDIO_STAGES = frozenset(('accepted', 'preparing', 'playing', 'retired', 'fault', 'cleanup', 'uncertain'))


def _decode_audio_playback(body: bytes, nonce: str) -> dict:
    """Complete ordered native v2 bytes, without reconstructing owner custody.

    Stage/flags remain native supplied data. Their relationships, scalar reply
    code and one-use publication cannot be authenticated from saved bytes.
    There is no native refused/unavailable v2 record to infer from errors.
    """
    marker = '[app.reply.malformed] why=audio-playback'
    require(len(body) < AUDIO_PLAYBACK_CAP, marker)
    parts = body.split(b' ')
    require(len(parts) == 26 and parts[:4] == [b'', b'audio', b'v=2', b'view=playback']
            and parts[4] == b'nonce=' + nonce.encode('ascii')
            and parts[-2:] == [b'scope=software', b'acoustic=unverified'], marker)
    values = {}
    for field, token in zip(AUDIO_FIELDS, parts[5:-2]):
        key, sep, value = token.partition(b'=')
        require(sep and key == field.encode('ascii'), marker)
        if field == 'stage':
            require(value.decode('ascii', errors='replace') in AUDIO_STAGES, marker)
            values[field] = value.decode('ascii')
            continue
        require(re.fullmatch(rb'[0-9]+', value) is not None, marker)
        digits = value.lstrip(b'0') or b'0'
        require(len(digits) <= (10 if field in AUDIO_U32 else 20), marker)
        number = int(digits)
        require(number < (1 << (32 if field in AUDIO_U32 else 64)), marker)
        require(field not in AUDIO_FLAGS or number in (0, 1), marker)
        require(field != 'stage_id' or number <= 7, marker)
        values[field] = number
    return {'schema': 'paos.sdk-audio-playback.v2', 'version': 2, 'view': 'playback',
            'nonce': nonce, **values, 'scope': 'software', 'acoustic': 'unverified'}


def _decode_audio_description(body: bytes) -> dict:
    require(len(body) < AUDIO_DESCRIPTION_CAP and
            body in (AUDIO_DESCRIPTION_CURRENT, AUDIO_DESCRIPTION_LEGACY),
            '[app.reply.malformed] why=audio-description')
    return {'schema': 'paos.sdk-audio-description.v1', 'edge': 'audio', 'kind': 'device',
            'description': body[len(b' hook describe edge=audio kind=device '):].decode('ascii')}


def reply_selector(value: str) -> str:
    if (value not in REPLY_SELECTORS and not AUDIO_SELECTOR.fullmatch(value) and
            _catalog_cursor(value) is None):
        raise argparse.ArgumentTypeError('unsupported reply selector')
    return value


def write_new(path: Path, data: bytes) -> None:
    with path.open('xb') as stream:
        stream.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command',required=True)
    for name in ('assemble','dev-sign'):
        sub = commands.add_parser(name)
        sub.add_argument('--manifest',type=Path,required=True)
        sub.add_argument('--recipes',type=Path,required=True)
        sub.add_argument('--assets',type=Path)
        if name == 'assemble':
            sub.add_argument('--public-key',type=Path,required=True)
            sub.add_argument('--signature',type=Path,required=True)
            sub.add_argument('--output',type=Path,required=True)
        else:
            sub.add_argument('--output-dir',type=Path,required=True)
    inspect = commands.add_parser('inspect')
    inspect.add_argument('--bundle',type=Path,required=True)
    inspect.add_argument('--public-key',type=Path,required=True)
    reply = commands.add_parser('decode-reply', description='Decode a saved, already unframed reply body offline')
    reply.add_argument('--selector', type=reply_selector, required=True,
                       help='saved-body selector, HOOK CATALOG [0..128], or HOOK GET audio playback <16lowerhexnonce>')
    reply.add_argument('--body', type=Path, required=True)
    diagnostic = commands.add_parser('diagnose-selectors', description='Diagnose documented recipe selectors offline; no runtime authorization')
    diagnostic.add_argument('--manifest', type=Path, required=True)
    diagnostic.add_argument('--recipes', type=Path, required=True)
    capture = commands.add_parser('capture-recipe', description='Draft native recipe text from a caller-reported completed task offline')
    capture.add_argument('--trace', type=Path, required=True)
    capture.add_argument('--id', required=True)
    capture.add_argument('--version', required=True)
    capture.add_argument('--entry', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'capture-recipe':
            receipt = capture_recipe(read_input(args.trace, MAX_TASK_TRACE), args.id,
                                     args.version, args.entry)
        elif args.command == 'diagnose-selectors':
            receipt = diagnose_selectors(read_input(args.manifest, 2048), read_input(args.recipes, 8192))
        elif args.command == 'decode-reply':
            receipt = decode_reply(args.selector, read_input(args.body, MAX_REPLY_BODY))
        elif args.command == 'inspect':
            receipt = inspect_bundle(read_input(args.bundle,MAX_BUNDLE),read_input(args.public_key,4096))
        else:
            manifest = read_input(args.manifest,2048); recipes = read_input(args.recipes,8192)
            assets = read_input(args.assets,MAX_BUNDLE) if args.assets else b''
            if args.command == 'assemble':
                pem = read_input(args.public_key,4096)
                bundle = assemble(manifest,recipes,assets,pem,read_input(args.signature,256))
                write_new(args.output,bundle)
                receipt = inspect_bundle(bundle,pem)
            else:
                require(not args.output_dir.exists(), 'fresh output directory required')
                bundle,pem,signature = dev_sign(manifest,recipes,assets)
                receipt = inspect_bundle(bundle,pem)
                receipt.update(private_key_saved=False,development_only=True)
                args.output_dir.mkdir(mode=0o700)
                for name,data in (('app.paosapp',bundle),('dev-public.pem',pem),('signature.bin',signature),('DEV_RECEIPT.json',(json.dumps(receipt,indent=2,sort_keys=True)+'\n').encode())):
                    write_new(args.output_dir/name,data)
        print(json.dumps({'ok':True,**receipt},sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,ImportError) as exc:
        print(json.dumps({'ok':False,'refusal':str(exc) if isinstance(exc,Refusal) else type(exc).__name__,'native_qualified':False,'official_signature':False},sort_keys=True))
        return 1


if __name__=='__main__': raise SystemExit(main())
