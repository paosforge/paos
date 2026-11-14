<!-- SPDX-License-Identifier: Apache-2.0 -->
# PaOS recipe bundle container v1

SDK contract v1 published; runtime compatibility not yet qualified; no certified builds

This development format follows the native consumer seam accepted on 2026-10-08, commits `4aa90fe81` and `4ec8fa49c`. It contains a text manifest, bounded literal recipes and opaque data. The loader never executes assets or CPU instructions from a bundle. General compute, bytecode and native app code are outside RC1. PMOD remains an internal experimental system extension outside the public app compatibility promise.

All container integers are unsigned little-endian. The file has exactly one 64-byte header, contiguous sections with no gaps, and a final 256-byte signature. Total size is at least 322 and at most 16384 bytes.

| Offset | Bytes | Meaning |
|---|---|---|
| 0 | 8 | ASCII `PAOSAPP1` |
| 8 | 2 | Container version, exactly 1 |
| 10 | 2 | Header size, exactly 64 |
| 12 | 4 | Exact total file size |
| 16, 20 | 4 each | Manifest offset 64; length 1..2048 |
| 24, 28 | 4 each | Recipes offset immediately after manifest; length 1..8192 |
| 32, 36 | 4 each | Assets offset immediately after recipes; length zero or more |
| 40, 44 | 4 each | Flags and reserved, both zero |
| 48 | 16 | First 16 SHA-256 bytes of the signer's 256-byte **big-endian** RSA modulus |

Assets end exactly 256 bytes before EOF. The signature is RSA-2048, fixed exponent 65537, strict PKCS#1 v1.5 SHA-256 over every preceding byte, represented as 256 big-endian bytes. There is no archive, compression, executable section or embedded signing key.

Native loading checks size/magic, container version and all header bounds, resolves the key identifier through the owner's trust set, verifies the signature, and only then parses manifest/recipes. Unsupported container or SDK versions answer `[app.contract.unsupported]`; unknown keys answer `[app.sig.untrusted]`; invalid signatures answer `[app.sig.bad]`. Other structural errors answer `[app.bundle.malformed]`. A successful native load answers `[app.loaded]`. Development inspection verifies against the explicitly supplied public key; it does not enroll or trust that key on any machine.

Trust belongs to the per-install owner and owner-added app keys, never the publisher. An unowned public machine has no app signing authority. Native wiring must meet that trust boundary and the reviewed per-edge permission rules before runtime acceptance. The native APP verb's existing authority checks remain; making APP public is not an authorization workaround.

The [manifest and recipe grammar](MANIFEST.md) defines the signed text. Future supported SDK versions must preserve promised stable behavior or use the compatibility/deprecation process in APP_COMPATIBILITY.md. No candidate has earned runtime compatibility through this document or through a host-only tool result.
