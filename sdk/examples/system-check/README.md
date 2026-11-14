<!-- SPDX-License-Identifier: Apache-2.0 -->
# System check public recipe example

SDK contract v1 published; runtime compatibility not yet qualified; no certified builds

This development example invokes exactly two registered verbs: bare STATUS and bare HOOK LIST. It declares only the SDK sys.read permission. The manifest supplies no native authority; owner trust, the outer APP gate and native verb permissions still apply. There are no CPU code or opaque asset sections.

The [v1 reply contract](../../contract-v1/VERBS.md) treats STATUS as opaque native
bytes and HOOK LIST as a catalog whose entries vary with the native profile.
This example's builder and inspector do not execute either command or parse its
reply. Applications preserve STATUS bytes without assuming stable fields or
field order.

From the repository root, with Python 3 and cryptography installed:

```
mkdir -p build
python3 sdk/examples/system-check/build.py --output build/system-check.paosapp
python3 tools/release/paos_app_sdk.py inspect --bundle build/system-check.paosapp --public-key sdk/examples/system-check/dev-public.pem
```

The builder verifies a fixed public input closure and expected bundle digest, then creates a new output exclusively. EXPECTED.json pins the manifest, recipe, public key, detached signature, builder and producer source. The verified producer source is loaded directly, without a bytecode-cache input. No Git history, operator deny policy, target record, private corpus or signing key is needed. The same public inputs reconstruct the same signed architecture-neutral bytes.

The initial development signature was generated with a fresh RAM-only RSA key, then only its public key and detached signature were retained. That key is not an owner key or an official release key. Modifying the recipe requires a new development signature; run the SDK dev-sign workflow to make a separate example. Existing outputs are never overwritten.

Host verification means loadable, not runnable. The receipt reports runnable:false and selectors_checked:false. Native execution and owner enrollment are separate steps owned by the runtime lane. This example has no native execution or product acceptance receipt yet.

Manifest, recipes, EXPECTED metadata, builder and documentation are Apache-2.0. The public key and detached signature are generated development data for this example.
