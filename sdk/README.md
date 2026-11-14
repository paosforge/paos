<!-- SPDX-License-Identifier: Apache-2.0 -->
# PaOS recipe SDK development tools

SDK contract v1 published; runtime compatibility not yet qualified; no certified builds

The unsigned [form/widget example](examples/form-widget-check/README.md) ships
bounded native form discovery, widget inventory and typed reads. Additive GUI
permissions and numeric value SET are defined in [VERBS](contract-v1/VERBS.md).
These selectors retain native owner/session checks, redaction and result
semantics; APP RUN still reports step code/value rather than nested reply bodies.

The [v1 container](contract-v1/BUNDLE_FORMAT.md) and [signed text grammar](contract-v1/MANIFEST.md) describe one architecture-neutral bundle. The same app bytes are intended for every CPU runtime implementing this contract. Public SDK tooling is Apache-2.0. Python 3 and the `cryptography` package provide public-key parsing and development signing; container verification also checks strict RSA padding independently.

The [system-check public example](examples/system-check/README.md) reconstructs an exact signed development bundle from public inputs and invokes STATUS plus bare HOOK LIST under sys.read.

The [v1 request and reply boundaries](contract-v1/VERBS.md) define the exact
commands. STATUS replies remain opaque native bytes, preserved without a typed
field or stable field-order promise. HOOK LIST has a reviewed catalog grammar
whose entries vary with the native profile. The existing network-read selectors
are `HOOK GET net` (`net.read`) and `HOOK DESCRIBE net` (`sys.read`); native
authority continues to apply independently of these manifest permissions.

Consume a saved reply body offline with the same tool, including in an unpacked
SDK kit:

```
python3 tools/release/paos_app_sdk.py decode-reply --selector 'HOOK LIST' --body saved-hook-body.bin
python3 tools/release/paos_app_sdk.py decode-reply --selector STATUS --body saved-status-body.bin
python3 tools/release/paos_app_sdk.py decode-reply --selector 'HOOK GET net' --body saved-members-body.bin
python3 tools/release/paos_app_sdk.py decode-reply --selector 'HOOK DESCRIBE net' --body saved-description-body.bin
```

The input must be a saved regular file containing an **already unframed body**.
The CLI reads a stable snapshot of at most 16,384 bytes and writes only a JSON
receipt to stdout. This is a host resource limit, not a native transport bound.
No transport headers or line delimiters are guessed, removed or added. In
particular, the HOOK LIST body's initial space is required and an appended LF is
refused. NETCFG MEMBERS has no initial space and also refuses an appended LF. Supply exactly the body defined in the v1 contract.

The reusable pure API is `decode_reply(selector, body: bytes)` in
`paos_app_sdk.py`, with selectors exactly `HOOK LIST`, `STATUS`, `HOOK GET net`,
`HOOK DESCRIBE net`, `HOOK GET fs`, `HOOK DESCRIBE fs`, `HOOK DESCRIBE audio`
or `HOOK GET audio playback <16lowerhexnonce>` and the same host size bound. `HOOK LIST` returns `paos.sdk-hook-catalog.v1`: integer `version`
and `edge_count`, ordered `edges` objects with `name` and `kind`, `operations`
and the declared `authority` token. Counts from zero through the current native
descriptor capacity of 52, lowercase names containing underscores, all current
native kinds (including device, power, session and desktop), and
profile-dependent registration order are supported. The decoder checks the
reviewed grammar, without asserting that the catalog matches a live profile.
The current native emitter stages at most 1,023 body bytes plus a storage NUL;
the decoder refuses partial/truncated catalogs and never invents missing fields.
Its separate host read bound does not change the native staging capacity.
`STATUS` returns only the `paos.sdk-opaque-status.v1` wrapper and no typed reply
fields. Empty STATUS bodies and arbitrary byte values remain opaque.

All results retain the complete original body in `body_base64` (standard
base64), alongside the selector and false qualification flags. Decode that
field to recover the exact bytes, including whitespace and line endings;
the wrapper schema does not introduce a STATUS field schema. Parsing a saved
catalog does not authenticate its `authority=native` claim, grant permissions,
execute selectors or recipes, or establish runtime compatibility. Native
qualification, runnable, selector-check and official-signature flags stay false.

`HOOK GET net` returns `paos.sdk-net-members.v1`. A complete listing has
`observation: "members"`, integer `member_count`, nullable `selected_slot` and
ordered `members`. Each member contains `slot`, literal `name`, `driver` and
`mac` strings (including `?`/`-` placeholders), integer `priority`, literal
`health` and `link` strings, boolean `selected` and nullable `link_speed_mbps`.
The last field is an integer only for `up<N>`, including `up0`; unprobed, down
and error observations retain their distinct strings and a null speed. Unknown
`h<N>` health values stay literal unknown observations. The decoder checks all
native field limits, canonical decimals, row count, slot order/uniqueness and
selected-slot agreement, and accepts at most 831 body bytes. See VERBS for the
complete grammar and native staging boundary.

The exact native unavailable body yields `observation: "unavailable"` with no
member count or members. Other errors and incomplete/malformed listings are
refused, never synthesized into successful empty lists. Syntax alone cannot
detect truncation that leaves another valid decimal or authenticate a saved
listing. `HOOK DESCRIBE net` returns `paos.sdk-opaque-net-description.v1` with no
typed fields, preserving any description/refusal bytes, including an empty body.
Both network wrappers explicitly carry `provenance: "saved-unauthenticated"`
and `authenticated: false`. All four qualification flags remain false. No
transport, probing, native command execution or authorization is provided.

`HOOK GET fs` returns `paos.sdk-fsinfo.v1`: the complete current selected
filesystem observation, with lossless bytes, full-width integer geometry and
literal `unsupported`/`unavailable` values. `FSINFO ERR no_data_mount` yields an
unavailable observation without geometry. `HOOK DESCRIBE fs` returns
`paos.sdk-fs-description.v1` after checking the complete native literal schema,
with `edge`, `kind` and unchanged `description`. See [VERBS](contract-v1/VERBS.md)
for exact fields and bounds. Both wrappers explicitly carry unauthenticated
saved-byte provenance and four false qualification flags. They cannot select,
qualify or authorize a volume. Only exact no-instance APP observation rows are
added: no path operation, mount, selection or storage authority is granted.

```sh
python3 tools/release/paos_app_sdk.py decode-reply --selector 'HOOK GET fs' --body saved-fsinfo-body.bin
python3 tools/release/paos_app_sdk.py decode-reply --selector 'HOOK DESCRIBE fs' --body saved-fs-schema-body.bin
```

Optionally diagnose recipe selectors before constructing a bundle, including
from an unpacked SDK kit:

```
python3 tools/release/paos_app_sdk.py diagnose-selectors --manifest app.manifest --recipes app.recipes
```

The pure API is `diagnose_selectors(manifest: bytes, recipes: bytes)`. Both paths
reuse the bundle's existing text grammar. The CLI reads stable regular files
bounded to 2,048 manifest bytes and 8,192 recipe bytes and writes JSON to stdout.
Malformed syntax is refused. Valid syntax returns a diagnostic even when a
selector is unknown or its required permission is missing. No key, signature,
assets, source checkout or output file is needed.

The `paos.sdk-recipe-selector-diagnostics.v1` report preserves manifest `entries`
and `declared_permissions` order. Its `recipes` list follows definition order,
including recipes absent from `entries`; each contains its `name` and ordered
`steps`, including duplicates. A step has a one-based `step` number, exact ASCII
`command` and standard-base64 `command_base64`. These command bytes exclude only
the recipe's `step ` prefix and terminating LF; spaces are preserved.

Matching follows the native loader's split at the **first literal space** and
case-sensitive comparison of the verb and whole remaining argument text; only
the named audio playback row accepts its fixed 16-digit lowercase hex nonce.
The selectors documented in v1 VERBS are reported: STATUS with empty
arguments and HOOK with arguments exactly `LIST`, `GET net`, `DESCRIBE net`,
`GET fs`, `DESCRIBE fs` or `DESCRIBE audio`, plus the whole bounded
`GET audio playback <16lowerhexnonce>` family. `GET net` requires `net.read`, `GET fs` requires
`fs.read`, and the others require `sys.read`.
Consequently `STATUS ` also matches the empty-argument row, while `STATUS  `,
`STATUS 5`, `HOOK  LIST` and `HOOK LIST ` do not match these rows. Recognized steps
carry `documented_selector`, the corresponding `required_permission`, a boolean
`permission_declared` and either `documented-selector` or
`missing-declared-permission` in `diagnostic`. Other commands carry
`undocumented-selector` with those three selector/permission fields null. This
means outside this finite documented surface, not necessarily unsupported by a
native runtime; for example, other HOOK argument forms remain valid text grammar.

This is an optional source diagnostic, never automatically invoked by assembly
or inspection and never a build/load gate or runtime allowlist. It does not
verify a signature, consult the current registry, authenticate a principal or
capability, or decide native authorization. A match and a declared permission
establish none of those facts. `diagnostic_only` is true, while `selectors_checked`,
`runnable`, `native_qualified` and `official_signature` remain false.

Save a caller-reported successful assistant task as an unsigned native recipe
draft, without invoking a model, command, provider or signing operation:

```json
{"schema":"paos.assistant-task-trace.v1","status":"completed","steps":[{"command":"STATUS","code":0},{"command":"HOOK LIST","code":0}]}
```

```sh
python3 tools/release/paos_app_sdk.py capture-recipe --trace task.json --id org.example.saved --version 1.0.0 --entry check
```

The pure API is `capture_recipe(trace: bytes, app_id: str, version: str,
entry: str)`. The CLI reads one stable regular file, bounded to 8,192 bytes,
and emits one JSON draft to stdout; it creates no files. Save that JSON through
the caller's normal file operation. Its `manifest_text` and `recipes_text` are
the existing native v1 text inputs for the SDK's assembly/signing workflow, not
a new executable format. Inspect them before using that separate workflow.

The trace envelope has exactly the three keys shown above. It must report
`completed` and contain 1..16 ordered steps, each with exactly `command` and
`code`; every code must be the integer zero. Boolean, floating and string codes,
failed/cancelled/pending tasks, duplicate JSON keys, nonfinite numbers, unknown
fields and malformed input refuse without a partial draft. This narrow input
contains no command replies, provider content, credentials or authority fields.

Calls retain their exact printable ASCII bytes, order and duplicates. Capture
reuses the SDK's native grammar validation and documented selector diagnostics;
only those documented observation rows are captured. Other valid native text
remains authorable through the existing SDK, outside this capture helper. No
whitespace normalization, argument substitution or provider text interpretation
occurs. Manifest identity/version/entry use the existing grammar. Declared
permissions are the distinct required SDK permissions in first-use order.

The draft schema is `paos.assistant-recipe-draft.v1`. It includes the exact input
`trace_sha256`, step count, declared permissions and `selector_diagnostics`.
The trace is **an untrusted caller report**, not authenticated evidence that
commands ran or succeeded: `source_success` is `caller-reported` and
`source_success_verified` is false. A caller may fabricate this input. Hashes,
reported zero result codes and manifest permission declarations grant no
authority. `diagnostic_only` is true; `selectors_checked`, `runnable`,
`native_qualified` and `official_signature` remain false. Native trust, the APP
gate and each nested command's original authority checks still apply on replay.
This adds offline capture only. Automatic task recording, UI save, scheduling,
triggers, production replay and candidate/metal journeys remain open.

The owned WAV observation decoder returns `paos.sdk-audio-playback.v2`,
including every ordered native field, full-width integers, stage and flags,
and explicit `scope: "software"`, `acoustic: "unverified"`. It checks complete
bounded bytes and the selector's nonce echo. It preserves unknown frame count
(`frames_known: 0`) without inferring acoustic output. `HOOK DESCRIBE audio`
returns `paos.sdk-audio-description.v1` for the complete native literal schema.
Both retain original bytes in `body_base64`, mark saved data unauthenticated,
and keep all qualification/authority flags false. Native errors have no audio
v2 success body and are refused by this decoder. See the
[complete audio grammar and authority boundary](contract-v1/VERBS.md#original-owned-wav-playback-observation).

```
python3 tools/release/paos_app_sdk.py decode-reply --selector 'HOOK GET audio playback 0123456789abcdef' --body saved-direct-hook-audio-body.bin
python3 tools/release/paos_app_sdk.py decode-reply --selector 'HOOK DESCRIBE audio' --body saved-audio-schema-body.bin
```

APP reports scalar step status only; these commands consume already separated
saved **direct HOOK** bodies. Manifest `sys.read` supplies no native MUTATE
ticket or ownership and cannot initiate playback. Native original owner,
session, controller, map and full-width epoch checks remain decisive.

Create a development bundle from your own manifest/recipes, with an optional opaque assets file:

```
python3 tools/release/paos_app_sdk.py dev-sign --manifest app.manifest --recipes app.recipes --output-dir dev-output
```

This generates a fresh RSA-2048 key only in process memory. It writes the app, public PEM, detached signature and development receipt to a new directory; it never reads or saves a private key. A later invocation uses a new key. This is an ephemeral development workflow, not official release signing or persistent developer key custody.

Anyone with the same public inputs can reconstruct the exact signed app without a private key:

```
python3 tools/release/paos_app_sdk.py assemble --manifest app.manifest --recipes app.recipes --public-key dev-output/dev-public.pem --signature dev-output/signature.bin --output rebuilt.paosapp
python3 tools/release/paos_app_sdk.py inspect --bundle rebuilt.paosapp --public-key dev-output/dev-public.pem
```

Supply the same `--assets FILE` to both commands when assets are present. Outputs are created exclusively; existing paths are refused. The development receipt and inspect output always say `native_qualified: false`, `official_signature: false`, `runnable: false` and `selectors_checked: false`. Local verification proves signed byte integrity and load-time grammar under the supplied public key: **loadable, not runnable**. Selector registration and runtime permission checks are not performed by the SDK. Native execution additionally requires owner trust and the native permission gates.

The loader, its per-install owner trust, registry integration and candidate-bound positive/version/permission/signature receipts are separate review gates. Source publication and host controls earn no SDK runtime acceptance. No upload, publication, official signing or target operation is performed by these tools.
