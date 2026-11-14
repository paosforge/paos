<!-- SPDX-License-Identifier: Apache-2.0 -->
# SDK v1 request and reply boundaries

SDK contract v1 published; runtime compatibility not yet qualified; no certified builds

These boundaries follow the native selector owner and the HOOK owner, with the
STATUS response decision adopted on October 9, 2026. They describe the intended
v1 consumer contract. Candidate-bound native execution and trust evidence remain
required before runtime compatibility is claimed.

## Request framing

The signed recipe stores each command as `step ` followed by literal command
text and a terminating LF. The `step ` prefix and LF delimit the recipe line;
the command text is the verb and its exact arguments. The
[manifest and recipe grammar](MANIFEST.md) defines character and size bounds.

| Recipe line | Exact command text | SDK manifest permission |
|---|---|---|
| `step STATUS` followed by LF | `STATUS`, no arguments | `sys.read` |
| `step HOOK LIST` followed by LF | `HOOK LIST`, no edge or other arguments | `sys.read` |
| `step HOOK GET net` followed by LF | `HOOK GET net`, no instance or other arguments | `net.read` |
| `step HOOK DESCRIBE net` followed by LF | `HOOK DESCRIBE net`, no instance or other arguments | `sys.read` |
| `step HOOK GET fs` followed by LF | `HOOK GET fs`, no instance or other arguments | `fs.read` |
| `step HOOK DESCRIBE fs` followed by LF | `HOOK DESCRIBE fs`, no instance or other arguments | `sys.read` |
| `step HOOK DESCRIBE audio` followed by LF | `HOOK DESCRIBE audio`, no instance or other arguments | `sys.read` |
| `step HOOK GET audio playback <nonce>` followed by LF | Literal `HOOK GET audio playback ` then exactly 16 lowercase hex digits, no suffix or instance | `sys.read` |

### Forms, widgets and bounded discovery

These additive selectors use existing native HOOK handlers. All decimal tokens
below are canonical: `0` or a nonzero digit followed by digits, without signs
or leading zeroes. Each complete command must match with literal single spaces
and no trailing suffix. The signed recipe line bound remains 160 bytes.

| Command text | SDK permission | Bounds |
|---|---|---|
| `HOOK GET forms` | `sys.read` | Exact native FORMLIST view |
| `HOOK DESCRIBE forms`, `HOOK DESCRIBE form`, `HOOK DESCRIBE widget` | `sys.read` | Exact schema selectors |
| `HOOK CATALOG` or `HOOK CATALOG <cursor>` | `sys.read` | Cursor 0..128; omission means zero |
| `HOOK GET form:<name> page <page> read <offset> <length>` | `sys.read` | Name `[a-z][a-z0-9_]{0,30}`, page 1..4294967295, offset 0..1280, length 1..384 |
| `HOOK LIST widget` or `HOOK LIST widget <cursor>` | `gui.read` | Cursor 0..2147483647; native capacity/existence checks still apply |
| `HOOK GET widget:<id> <field>` or `HOOK OBSERVE widget:<id> <field>` | `gui.read` | ID 0..2147483647; field exactly `role`, `label`, `intent`, `intent_seq`, `value`, `min`, `max`, `step` or `sel` |
| `HOOK SET widget:<id> value <number>` | `gui.write` | ID and number 0..2147483647 |

The ID bound is syntactic, not a promise of that many live widgets. Native
instance, type, page and range checks remain unchanged; unsupported fields keep
native error/body semantics. Form reads return native bounded hex chunks and
fresh observations, not an atomic multipage snapshot. Opaque bundle assets do
not become installed forms and FORMLOAD is not admitted.

Numeric SET reaches WIDGETSET's existing type vtable. Scalars share the GUI's
live model, clamp and step alignment; other types retain their existing value
setter semantics. Recipe code neither rewrites values nor normalizes native
status or intent events. Text feeding, actions, geometry and creation are not
admitted. Owner/session/lock/ticket gates and secret redaction remain decisive.
The invoking request context is unchanged. A remote APP has already spent its
outer ticket and cannot reuse it for a protected step.

APP RUN preserves its step code/value report; it does not return the nested
HOOK body. Direct HOOK calls retain complete original bodies, including
redaction and legacy errors. No new offline widget reply decoder or runtime
qualification is implied by selector diagnostics. The unsigned
[form/widget example](../examples/form-widget-check/README.md) ships in the SDK kit.

The loader checks the entire selector. For example, `STATUS 5` and
`HOOK LIST fs:/` gain no callable row from these declarations. The SDK authoring
tool checks signed grammar and reports `selectors_checked: false`; the native
consumer owns the selector check. A manifest permission supplies no native
authority. Dispatch retains the invoking principal, source and capability;
native authorization and the outer APP gate continue to apply.

## STATUS reply

The v1 result is the native STATUS reply as opaque bytes. Preserve those bytes
without decoding fields, trimming whitespace, rewriting line endings or sorting
tokens. The contract makes no stable typed-field or field-order promise. Native
STATUS output evolves, including boot-gate stamps; applications must not infer
a stable schema from a sampled reply.

A typed STATUS result needs a separately reviewed, versioned schema from the
STATUS owner and admin. The opaque boundary permits carrying or displaying the
reply; it supplies no assertion that a field agrees with another native service.
Agreement with Network Monitor and actual request/reply handling require
candidate-bound runtime observations.

## HOOK LIST reply

The HOOK owner specifies one ASCII catalog line with this body:

```text
 hook v=1 edges=<n> <name>:<kind>... ops=LIST,DESCRIBE,GET,SET,INPUT,OBSERVE,CANCEL,EVENTS authority=native
```

The initial space is part of the body. Angle-bracket terms and `...` are grammar
notation. `v=1`, the operation list and `authority=native` are fixed tokens.
`edges` is the decimal entry count, from zero through the
SDK-supported descriptor capacity of 128. The integration profile currently
declares 64 entries. Each name matches `[a-z_][a-z0-9_]*` (including
`throttle_log` and `c2recovery`);
each kind is one of `app`, `widget`, `service`, `storage`, `job`, `network` or
`vm`, or `device`, `power`, `session` or `desktop`. Entries occur in native
registration order, following the boot profile's descriptor declarations;
GUI and service entries need not form separate groups.
Count, names and kinds vary with the native profile; applications must
not require the sampled desktop's eight-entry catalog. This body grammar adds
no promise about an outer transport envelope or a trailing line delimiter.

The current native staging buffer holds 1,024 bytes including its terminating
NUL, so a complete emitted body fits within 1,023 bytes. The NUL is storage
termination, not a body token. Its bounded appender can truncate oversized
output; a partial entry or missing fixed suffix is not a valid catalog. The
offline SDK's separate 16,384-byte host read bound does not enlarge this native
buffer or prove that saved bytes came from a native emitter. The decoder
preserves complete original bytes, order and decimal spelling; it does not
impose additional canonical-decimal, name-uniqueness or fixed-profile checks.

Bare native `HOOK` and `HOOK LIST` have the same catalog response, but this SDK
application selector is exactly `HOOK LIST`. Reading the catalog has no native
side effects and consumes no authorization ticket. The SDK still requires its declared
`sys.read` permission. Other HOOK selectors retain their individually registered
permissions and native authorization checks.

### Saved catalog pages

The accepted native paging profile increases descriptor capacity to 128. It
emits complete entries in this alternate body when requested with `HOOK CATALOG`
or `HOOK CATALOG <cursor>`, and uses page zero as the `HOOK LIST` fallback when
the legacy body would exceed its buffer:

```text
 hook catalog v=1 edges=<total> from=<start> next=<end> more=<0|1> <name>:<kind>... ops=CATALOG,LIST,DESCRIBE,GET,SET,INPUT,OBSERVE,CANCEL,EVENTS authority=native
```

Each separator is one literal space. Numeric fields are canonical decimal from
0 through 128. `start <= end <= total`, the number of returned entries equals
`end - start`, and `more` is exactly whether `end < total`. A nonterminal page
must advance; an empty terminal page has `start = end = total`. Entry names
are unique within a page and follow the legacy name/kind grammar. The whole body
fits in 1,023 bytes; no partial entry, missing suffix, NUL or trailing delimiter
is valid.

The offline `decode-reply` command accepts `HOOK CATALOG` and `HOOK CATALOG N`
with canonical decimal `N` from 0 through 128. It binds `from` to the requested
cursor (zero when omitted), including for a saved `HOOK LIST` fallback. Its JSON
schema `paos.sdk-hook-catalog-page.v1` includes `edge_count` for the total,
`start`, `next`, boolean `more`, `returned`, and ordered `edges`. It preserves the
original bytes in `body_base64`. One decoded page does not establish a complete
or consistent inventory across separate saved responses. Provenance remains
`saved-unauthenticated`; the native authority token authenticates nothing.

APP additionally admits bounded CATALOG selectors above with `sys.read`.
Native admission and authorization remain unchanged. Legacy saved bodies retain
their existing decimal-spelling and duplicate-name compatibility.

The public [system-check example](../examples/system-check/README.md) uses
`STATUS` and `HOOK LIST`. Its host builder and inspector reconstruct and verify bundle
bytes; they do not run commands, interpret replies or qualify this boundary.

## HOOK GET net reply

The existing native selector delegates to NETCFG MEMBERS. Its complete ASCII
body has no initial space, trailing LF or storage NUL:

```text
NETCFG MEMBERS n=<count> sel=<slot|-> M=<slot>:<name>:<driver>:<mac>:<priority>:<health>:<selected>:<link>...
```

There is exactly one literal space between tokens. `n` is 0..8; the following
`M=` rows must agree with that count. Slots are 0..7, strictly increasing and
unique. `sel=-` means no selected member; otherwise its slot must occur and that
row alone must have `selected=1`. All other rows have `selected=0`. An empty
listing is exactly `NETCFG MEMBERS n=0 sel=-`.

Names and drivers are 1..15 ASCII characters from `[A-Za-z0-9_.-]`, or the
literal `?` for an unavailable name. Native serialization clips longer names
and replaces unsafe characters before publication; decoding does not recover
the original names. MAC is exactly 12 lowercase hexadecimal digits, or `-` for
unavailable. Priority is an unsigned 32-bit decimal. Health is `ok`, `degraded`,
`absent`, `dead`, or `h` followed by an unknown numeric health value 3..4294967295.
An unknown value stays unknown; `absent` is distinct from a degraded device.
Link is `-` (unprobed), `down`, `err`, or `up` followed by a decimal speed in
Mb/s from 0..16777215. All decimals use native canonical spelling: zero is `0`,
otherwise a nonzero first digit and no sign or leading zeroes.

Native staging holds 832 bytes including NUL; a body must fit within 831 bytes.
Before publication the native hook checks the complete grammar, accepted result,
response count, staging extent and one-use custody, and retires staging even on
failure. The native producer publishes only for an owner-signed UDP request with
a consumed owner ticket. The manifest's `net.read` does not replace these native
checks. The offline decoder neither performs nor establishes them.

The exact body ` hook err=net_members_reply_unavailable` is an unavailable
observation, **not an empty successful listing**. Other refusal bodies, malformed
or incomplete records and transport envelopes are refused as member listings;
no response code or successful network operation is inferred from saved text.
The API checks complete grammar but cannot authenticate saved bytes or detect an
alteration/truncation that leaves another valid record (for example `up1000`
shortened to `up100`). No authentication, NIC probe or dispatch occurs.

## HOOK DESCRIBE net reply

Preserve the existing native description as opaque bytes. The offline wrapper
`paos.sdk-opaque-net-description.v1` is versioned; the description fields have no
new typed schema or stable-order promise. It may carry unavailable or refusal
text without turning that text into a successful network observation.

## HOOK GET fs reply

This additive exact selector observes the currently selected filesystem through
native FSINFO. It takes no instance, path or extra argument. `HOOK GET fs:/`,
`HOOK GET fs read 0 1`, other FS operations and a trailing space have no APP row.
Native APP preflight, registry, session, source, principal, capability and owner
checks remain authoritative. Manifest `fs.read` supplies no native ticket; a
remote APP's single-use EXTENSION ticket is consumed by its outer dispatch and
cannot authorize a nested nonpublic FSINFO read. This adds no public storage
allowlist, selection, mounting, path reading/listing/stat/hash or mutation.

The complete ordered ASCII body is:

```text
FSINFO NONCE=<16 hex> VOL=<8 hex> BACKEND=<token> CLUSTER=<u32> TOTAL=<u64> FREE=<u64|unsupported> ORPHANS=<u64|unsupported> DEV=<token|unavailable> PART_START=<u64|unavailable> PART_SECTORS=<u64|unavailable> SCHEME=<gpt|mbr|superfloppy|unavailable>
```

There is exactly one space between fields, no initial space, transport envelope,
trailing newline or storage NUL. Native staging holds 1,408 bytes including NUL;
a complete body is at most 1,407 bytes. NONCE is a fresh correlation token;
VOL is only the low 32-bit diagnostic identifier, not an ownership identity.
BACKEND is a nonempty printable ASCII token without spaces. DEV is a complete
1..63 character registered-device token from `[A-Za-z0-9_.:-]`, or literal
`unavailable`; it is resolved from this observation, not substituted from another
selected device. PART_START and PART_SECTORS retain full 64-bit geometry. The
producer emits unavailable for missing, zero-length or overflowing extents and
for unknown schemes. FREE and ORPHANS use `unsupported` when their backend
reports the unsigned-64 sentinel. These markers remain distinct strings.

The decoder requires every field once, in that order, with its lexical and
numeric bounds. It preserves original spelling and bytes, accepts decimal
leading zeroes and either hex case, and imposes no cross-field equality,
geometry consistency, paired-unavailable or canonical-spelling policy. In
particular it does not prove that saved geometry matches a current selection.
The exact native `FSINFO ERR no_data_mount` body is an unavailable observation;
other errors or malformed/incomplete bodies are refused as filesystem records.
A native response code is not recoverable from saved body bytes.

The offline `paos.sdk-fsinfo.v1` wrapper carries `observation: "filesystem"`,
literal `nonce`, `volume_id`, `backend`, `device`, `scheme`, integer
`cluster_bytes` and `total_sectors`, and integer-or-literal `free_clusters`,
`orphans`, `part_start`, `part_sectors`. The unavailable response instead has
`observation: "unavailable"` and `reason: "no_data_mount"`, with no geometry.
All filesystem wrappers carry exact `body_base64`, `provenance:
"saved-unauthenticated"`, `authenticated: false` and the four false qualification
flags. Parsing saved bytes cannot authenticate their origin, qualify a volume,
select it, grant authority or detect an alteration that leaves another valid
record. No storage I/O or native dispatch occurs in the offline tool.

## HOOK DESCRIBE fs reply

The native hook emits its complete literal description beginning with
` hook describe edge=fs kind=storage `, including that initial space, followed
by the current `inst=none|<abs path, no spaces>` schema through `input=na cancel=na`.
The offline `paos.sdk-fs-description.v1` wrapper checks the complete current
literal (embedded as `FS_DESCRIPTION` in the delivered public tool), within the
1,024-byte native buffer including NUL, and returns `edge: "fs"`, `kind:
"storage"` and the unchanged `description` string. Partial, altered, refusal,
extra-argument or differently framed descriptions are refused. This finite
schema lists native path/mutation operations for discovery; it grants none of
them an APP row or authority. Future schema changes require an updated decoder
contract. Native description has no FS backend call. Original bytes, unauthenticated
provenance and all false qualification flags are retained as for GET fs.

## Original-owned WAV playback observation

The audio playback row matches the entire literal prefix and exactly 16 nonce
characters from `0-9a-f`, followed by the command's terminal NUL. The recipe LF
is framing, not a nonce character. `HOOK GET audio`, audio instances, extra
spaces/arguments, uppercase nonce digits, OBSERVE, SET, play, cancel and direct
WAVPLAY commands gain no APP row. The existing six rows retain their meanings.
For an interface evidence declaration, the additional exact row uses
`arguments: "DESCRIBE audio", match: "exact", sdk_permission: "sys.read"`;
the sole fixed-nonce family uses `arguments: "GET audio playback <nonce>",
match: "lowerhex16-nonce", sdk_permission: "sys.read"`. This named family is
not a general prefix or pattern grammar.

Manifest `sys.read` only permits an attempt. APP forwards the original source,
principal, capability and idempotence unchanged through the native dispatcher.
The outer APP owner/EXTENSION gate and nested WAVPLAY MUTATE gate remain in
force. A manifest permission supplies no ticket or native ownership. Native
INFO requires the retained original job/session principal, authority epoch and
key, selected controller/map serial, full-width native epochs and owner binding.
It does not acquire an owner, prepare, advance, play or cancel media. Native
one-use publication and retirement on success/refusal remain authoritative.

APP's ordinary response reports scalar `code` and `val` for each step. It does
not relay the typed audio body. `decode-reply` consumes saved **direct HOOK**
body bytes after the caller has separated the response framing/code. Never feed
APP step text or a transport envelope as an audio body. The complete success
body is ordered, begins with one space and ends without LF/NUL:

```
 audio v=2 view=playback nonce=<16lowerhex> epoch=<u64> controller=<u32> serial=<u64> stage=<name> stage_id=<0..7> error=<u32> loaded=<u64> size=<u64> frames_known=<0|1> frames=<u64> producer_phase=<u32> decoded_bytes=<u64> prepared=<u64> submitted=<u64> loop=<u32> backend=<u32> cleanup=<0|1> retired=<0|1> uncertain=<0|1> scope=software acoustic=unverified
```

Stage names are `accepted`, `preparing`, `playing`, `retired`, `fault`, `cleanup`
and `uncertain`. The JSON schema is `paos.sdk-audio-playback.v2`, with integer
numeric fields (including the four flags), string stage/nonce, `version: 2`,
`view: "playback"`, `scope: "software"` and `acoustic: "unverified"`. Nonce
must echo the supplied exact selector. WPI1 storage holds at most 511 body
bytes; replacing its five-byte head with the 23-byte typed head gives at most
529 typed body bytes. The consumer rejects 530 bytes or more, incomplete,
reordered, duplicate, extra or out-of-range fields. Decimal leading zeroes are
accepted within this body bound; no additional canonical spelling or
cross-field consistency rule is imposed on saved data. Native stage/flags are
retained individually. `frames_known: 0` records unknown frame count; it does
not establish silence or failure. Native errors remain in the response code
and hint/envelope: there is no refused/unavailable audio v2 success grammar.
The decoder refuses those error bodies rather than inventing such a record.

`HOOK DESCRIBE audio` decodes the complete current literal device schema as
`paos.sdk-audio-description.v1`, with `edge: "audio"`, `kind: "device"` and
`description` retaining all schema text. Its body is bounded by the native
1024-byte buffer including storage NUL. Operations named in that native schema
are not thereby callable from APP. The saved-body decoder accepts both the
original literal ending `list=na set=na input=na cancel=na` and the current
987-byte literal advertising native WAVPLAY play admission and bound-owner
cancel cleanup/retirement. It requires the entire matching literal, including
operation order and scope tags; it does not accept arbitrary operation text.
These added description fields grant no SDK application recipe selector.

Both audio decoders preserve original bytes in `body_base64`, report
`provenance: "saved-unauthenticated"` and `authenticated: false`, and keep
`selectors_checked`, `runnable`, `native_qualified` and `official_signature`
false. Saved software facts cannot authenticate an owner, prove acoustic
output, grant authority or qualify a candidate/bundle. Original AV/RESOURCE
and runtime owners remain responsible for their own evidence.
