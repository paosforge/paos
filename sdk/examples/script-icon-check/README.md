<!-- SPDX-License-Identifier: Apache-2.0 -->
# Script app with PNG icons

This example supplies a bounded bash program, a real `main.frm`, requested WAIT
BEGIN/POLL permissions, original 48x48 and 96x96 RGBA8 PNG artwork, and its credits.
The four request bytes are `0,1,1,0`: BEGIN/POLL requested, STATUS/CANCEL denied. Only the
owner's actual install choice and native runtime binding can grant access.

Every positive variant contains exactly one FORM, declaring `iconcheck` with a
small stock window and label. The program obtains its actual window with
`paos WINDOW`, then calls `paos WAIT BEGIN "$window" "$cursor" 5000` and polls a
pending token. Accepted BEGIN is the native launch flow's readiness signal that
reveals the staged form. Events and overrun update the cursor; timeout begins
another bounded wait. Refusal stops the program. It uses only bash built-ins and
the runtime's `paos` helper, and stays alive while the app is open.

From the repository root:

```sh
python3 sdk/examples/script-icon-check/build.py --output-dir /tmp/script-icon-example
python3 tools/release/paos_script_sdk.py share-inspect /tmp/script-icon-example/install96.pax
python3 tools/release/paos_script_sdk.py inspect /tmp/script-icon-example/runtime96.pax --public-key sdk/examples/script-icon-check/dev-public.pem
```

The builder uses the maintained SDK and fixed public development key/detached
signatures. It creates a new directory exclusively. It reads no private key,
enrolls no key, and performs no install or execution. `app.json` follows
`script-bundle-v2.json`; `install.json` follows `script-package-sharing-v1.json`.
These two manifests also work with the SDK's `unsigned`/`share-unsigned` and
`assemble`/`share-assemble` commands and an explicitly selected author's public
key and external detached signature.

`install48`, `install96`, and `installnone` are signed **BASHAPP2** packages for
`APPINSTALL /path` on the local owner's console. The last has no icon and
exercises text fallback; the first has no optional 96px icon. The card must show
the actual author/permissions, and installation needs the native provisioned
DATA role. This development key starts unknown; the card's unknown-author
warning is expected. The SDK does not turn it into an owner or official key.

`runtime48`, `runtime96`, and `runtimenone` contain the same program/request
members in **BASHAPP1**, for the existing native `APPSCRIPT /path` route and its
real launcher/runtime. Execution still needs an owner-trusted author (the
native owner-only `APPKEY` workflow), local owner action, a compatible signed
native payload and matched APKERN/APINIT/profile. No enrollment is automatic.
On the original SDK source base, the loader accepts BASHAPP1 only. VM owns the
separate native installed BASHAPP2 consumer correction: on a compatible payload,
read the numeric, nonreused installed entry ID for this installation from the
actual authenticated installed catalog, then launch with `APPRUN <installed-entry-id>`
using its original BASHAPP2 bytes and actual installed authority. The bundle
identifier `org.example.icon96` remains a label, never the `APPRUN` operand.
After reinstalling, read the fresh entry ID from the authenticated catalog;
the old entry ID remains retired. A BASHAPP1 companion is never an
installed-app identity substitute. Installation alone is **not** proof of launch
or show. The formats have distinct whole-bundle hashes; installed identities and
permissions never transfer between them.

For the already selected author's public key, prepare signing inputs without
creating another key or signing anything:

```sh
python3 sdk/examples/script-icon-check/build.py --prefixes-only --public-key selected-author-public.pem --output-dir /tmp/script-icon-prefixes
```

The output includes `.prefix` files; the existing author/signing path supplies
RSA-2048 PKCS#1 v1.5 SHA-256 signatures. For positive inputs, use the SDK assembly
commands with the corresponding manifest and selected signature; the source
example demonstrates the pure API for variants. Keep the deliberately invalid
`wrong48` and `missingcredits` files as refusal controls. Their signatures are
valid under the development key; malformed content is what must refuse.

[RUNTIME_CASES.json](RUNTIME_CASES.json) gives VM the actual negative operations:
retain the real runtime descriptor across remove/reinstall, and attempt the
Settings confirmation from injected input. Those need live native identities;
there is no serialized permission token or guest/agent removal API in this
example. Do not substitute an unsupported command for the real confirmation
gate. VM owns real install/restart/catalog/REMOVE execution; Q owns its selected
twin with REL's candidate binding. Runtime and restart are unobserved here.

Program, tooling and original artwork are Apache-2.0, by Codex / rc-qemu-claude.
FORM and BEGIN/POLL correction: Codex / rc-input-claude. [OUTPUT_PINS.json](OUTPUT_PINS.json)
pins all eight corrected development bundles, the public key, form and program.
Use this coherent fixture set; the earlier STATUS-only bundles have no FORM and
cannot pass the existing launcher. The artwork and NOTICES are unchanged.
Only public development key/signatures are retained; the generating key existed
only in memory and was discarded. The builder's receipt reports
`runnable:false`, `installed:false`, `native_qualified:false` until actual native
qualification is supplied independently.

The focused HOST suite executes the actual verifier/snapshot/PNG/cache APIs
through the actual launcher publication and staged-form entry, checks the exact
FORM bytes, and refuses signed zero/two-FORM controls and stale authority. Form
parser/allocator/WM and VM boundaries remain modeled. A separate helper model
executes the actual bash program's WINDOW/BEGIN/POLL/error flow. These are HOST
checks; actual installed authority, guest execution and show timestamps remain
VM's live producer observations, including the refused-BEGIN control.
