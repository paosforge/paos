# GCC runtime corresponding source

The selected retained Linux setup links Ubuntu `libgcc-13-dev:amd64`
`13.3.0-6ubuntu2~24.04.1`. `SELECTED_RUNTIME.json` binds the actual four link
inputs, retained setup identity, source package and complete observed compiler
configuration. All four hashes were compared with the installed package; these
are binary identity observations, not files offered as source.

Complete, unmodified corresponding source was fetched from the authoritative
Ubuntu pool https://archive.ubuntu.com/ubuntu/pool/main/g/gcc-13/ :
`gcc-13_13.3.0.orig.tar.gz`, `gcc-13_13.3.0-6ubuntu2~24.04.1.debian.tar.xz`
and the signed `.dsc`. The descriptor's SHA-256 and size entries match both
archives. The original archive contains the complete gcc13.3.0 source tarball
and bundled newlib source. The distribution archive contains all patches,
configuration/build rules, dependency declarations and original notices.
No generated object or archive is substituted for source. Acquisition uses
HTTPS and exact pinned digests; no new signature-trust assertion is made.

`COPYING.RUNTIME` is the verbatim GCC Runtime Library Exception3.1. `COPYING3`,
`COPYING3.LIB`, `COPYING`, `COPYING.LIB` and `debian-copyright` are complete
original grants/notices copied from those archives. Preserve source-file terms
and exceptions: GCC is not uniformly under the runtime exception, and the
exception's eligibility conditions still apply. The installed kit's existing
GCC notice is exactly the retained distribution copyright file.

Prepare offline from an exported public source tree, using a fresh isolated
output directory:

```sh
python3 -B tools/release/prepare_gcc_runtime_source.py --source-root "$PWD" --output-dir /tmp/gcc-source-one
python3 -B tools/release/prepare_gcc_runtime_source.py --source-root "$PWD" --output-dir /tmp/gcc-source-two
cmp /tmp/gcc-source-one/PREPARE_RESULT.json /tmp/gcc-source-two/PREPARE_RESULT.json
```

This bounded recipe verifies every declared input, descriptor archive digests,
original notices and source version; safely unpacks the complete source package
and inner upstream GCC source; and records every prepared regular file's digest
and normalized executable mode. It never imports source-tree helpers or invokes
Make/compiler/network. Independent fresh preparations compare precise complete
file tables, not directory timestamps. `package/` retains the original complete
distribution input, with `debian/` ready for its own rules; `upstream/` is a
separate unmodified source view. No distribution patch application is claimed.

For a complete distribution binary rebuild, provision an Ubuntu noble amd64
build environment satisfying **all** Build-Depends and Build-Depends-Indep in
the `.dsc`, then run `dpkg-buildpackage -us -uc -b` from
`package/gcc-13-13.3.0`. This executes the delivered distribution rules, including
architecture-specific patch selection, generated defaults and bootstrap/LTO
configuration; it is deliberately not replaced by a different configure command.
That full bootstrap has not been executed here. Historical archive/object
reproduction, matching its original build environment, remains unresolved.
The compiler configuration in SELECTED_RUNTIME is evidence, not a substitute
for those rules or an assertion that a new compiler is bit identical.

The optional `assemble_linux_kit.py --gcc-source-root /public/tree` path adds
`gcc-source/`, deterministic `gcc-source.tar` and `GCC_SOURCE_RESULT.json` beside
the unchanged executable kit. It refuses unless the build's recorded GCC runtime
archive/startup set exactly matches this selected version and hashes. It stages
every declared original input, notice and the public preparation recipe/dependency,
without executing received helpers. Its result binds the kit's compiler table
and source archive. Legacy assembly without this option remains supported and
makes no new source-delivery claim. An unsupported or future GCC runtime needs
its own corresponding-source selection; an arbitrary archive is never relabeled.

Full source/license/release clearance, public upload, signing and native runtime
qualification are separate and remain unclaimed. No selected setup bits change.
