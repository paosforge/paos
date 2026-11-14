<!-- SPDX-License-Identifier: Apache-2.0 -->
# Manifest and recipes, SDK interface v1

SDK contract v1 published; runtime compatibility not yet qualified; no certified builds

Manifest and recipe sections contain printable ASCII bytes 0x20..0x7e and LF only. Every line ends with LF; blank lines, CR, tabs and NUL are invalid. The manifest contains exactly five keys, each once, with `sdk=1` first and no unknown keys:

```
sdk=1
id=org.example.system-check
version=1.0.0
caps=sys.read
entry=check
```

`id` is 3..63 bytes from `[a-z0-9.-]`. `version` has exactly three decimal components, each containing 1..5 digits and representing 0..65535. `entry` is one comma-separated list of 1..4 unique recipe names. A name is `[a-z][a-z0-9_-]{0,31}`. Every entry must name a defined recipe. Lists have no spaces or empty/trailing items. `caps` is required and may be empty; otherwise it contains up to eight unique names from the SDK permission vocabulary.

These names are **SDK recipe allowlist permissions**, not PaOS native capability words. The native dispatcher still checks the invoking source, principal, numeric capability, ticket and owner/session gates. A manifest declaration never supplies authority, raises a principal, or makes a native refusal succeed.

| SDK allowlist name | Native selector mapping | Runtime state |
|---|---|---|
| `sys.read` | `STATUS`, bare `HOOK LIST`, bounded catalog/form metadata and exact schema selectors in VERBS | Runtime pending; only the documented complete selectors |
| `net.read` | Individually registered network-read selectors such as `HOOK GET net`, delegating to `NETCFG MEMBERS` | Runtime pending; native owner authorization still required. Not used by the ordinary public example |
| `gui.read` | Bounded widget inventory, GET and OBSERVE fields in VERBS | Runtime pending; native secrecy and instance checks remain decisive |
| `gui.write` | Bounded numeric `HOOK SET widget:<id> value <u31>` | Runtime pending; native owner/session/ticket gates still apply |

`fs.read` permits the exact no-instance `HOOK GET fs` recipe step, delegating to native FSINFO. `HOOK DESCRIBE fs` requires `sys.read`. Neither grants native storage authority, a native ticket, selection, mounting or any path operation. The vocabulary and exact selectors were bound by the native owner on 2026-10-08 at 19:46. The vocabulary matches the accepted unwired loader seam. Exact app-callable rows and their response boundaries are bound with their native owners before the SDK interface/evidence manifest is marked reviewed. Other HOOK operations and edge arguments gain no app permission from this table. The HOOK owner bound its v1 surface on 2026-10-08 to the RCQ-15 stack ending in `e4c726aca`; integration and candidate evidence must bind the actual bytes.

Recipes use only these forms:

```
recipe check
step HOOK LIST
step STATUS
end
```

There are 1..4 unique recipes, each with 1..16 steps. Every line is at most 160 bytes excluding LF, including its prefix. Recipe and entry names share the grammar above. Each step names an uppercase registered verb, optionally followed by a space and literal printable arguments. There are no variables, substitution, loops or executable code sections. The authoring tool checks load-time syntax and signed bytes. Its verified result means **loadable, not runnable**: it does not check selectors against the current registry or app allowlist. Inspection and development receipts report `runnable: false` and `selectors_checked: false`. Native running resolves the registry, exact selector and app permissions.

At runtime an unlisted selector answers `[app.verb.unlisted]`, a missing declared SDK permission answers `[app.cap.denied]`, and neither dispatches that step. The first non-OK native result stops execution with `[app.step.failed]`. A successful entry answers `[app.run.ok]`; replies are bounded to the native 4 KiB staging limit. Every nested request retains its invoker's source, principal, capability and idempotency context. Owner registration of a development key and the outer APP authorization remain necessary.

The [public system-check example](../examples/system-check/README.md) uses `STATUS` plus bare `HOOK LIST`. `HOOK GET net` requires native owner authorization. The [v1 request and reply boundaries](VERBS.md) preserve STATUS replies as opaque native bytes and HOOK LIST's variable catalog grammar. The unsigned [form/widget example](../examples/form-widget-check/README.md) adds bounded native discovery and typed reads. Only numeric widget value SET is admitted for writes; input, general mutation hooks and cross-app messages gain no recipe permission.

The exact `HOOK DESCRIBE audio` and bounded
`HOOK GET audio playback <16lowerhexnonce>` recipe selectors also require
`sys.read`. The nonce is exactly 16 lowercase hexadecimal digits; the whole
literal prefix and terminal NUL must match. This permits observing an already
owned native WAV job only after the original registry/session/MUTATE/owner
checks. It grants no ticket, owner acquisition, playback, cancellation, audio
instance, OBSERVE/SET or arbitrary argument access. See [VERBS.md](VERBS.md).
