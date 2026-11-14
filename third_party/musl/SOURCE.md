# musl 1.2.4-2 sources and local static runtime recipe

The complete upstream musl 1.2.4 archive is byte-identical at
https://musl.libc.org/releases/musl-1.2.4.tar.gz and Ubuntu's retained
https://archive.ubuntu.com/ubuntu/pool/universe/m/musl/musl_1.2.4.orig.tar.gz.
The complete distribution delta and original signed descriptor are retained as
`musl_1.2.4-2.debian.tar.xz` and `musl_1.2.4-2.dsc` from that same Ubuntu pool.
SOURCES.json pins all consumed bytes. The descriptor's archive size and SHA256
entries agree; no signature authentication or complete toolchain delivery is
claimed here. Downloads are unnecessary when building the delivered source.

The selected static setup's 38 musl input hashes in
`release/selected-candidate/ARTIFACT_BINDINGS.json` match the installed
musl-dev 1.2.4-2 and all corresponding files in Ubuntu's published
`musl-dev_1.2.4-2_amd64.deb` (SHA256
4b451ecb6a0f8469883058cf22a807f3bd9cc16d115cc08b7efc35fe8eb44db2).
The original installed distribution notice already retained by the Linux kit
is byte-identical to `debian/copyright`. It stays unchanged.

`COPYRIGHT` is the complete upstream grant and contributor/exception notice;
`debian-copyright` is the complete distribution notice, including constituent
licenses and the BSD fts import. The original in-file grants remain in both
complete archives. This is MIT with the actual retained constituent grants,
not a new blanket license assignment. Distribution `debian/patches/series`
contains exactly `static-pie.patch`; its authorship, upstream mail and Debian
bug reference are retained verbatim in the archive and extracted patch.
The original distribution recipe also copies `debian/musl-fts/{fts.c,config.h}`
into src/fts and fts.h into include. The public recipe does the same. All three
imported source files and their original grants are in the distribution archive.
No distribution patch or imported body is replaced by metadata.

The two `tools/release/` recipe scripts below are not included in this source preview yet.
Run from an ordinary public source checkout, using fresh absolute local outputs:

```
python3 -B tools/release/build_musl_runtime.py --source-root "$PWD" --output-dir /tmp/musl-new
python3 -B tools/release/build_linux_setup.py --source-root "$PWD" --compiler /tmp/musl-new/runtime/bin/musl-gcc --output-dir /tmp/setup-new
```

These commands compile and link only. Do not execute paos-setup for this check.
`make install` inside the runtime recipe stages only under the isolated local
output transaction; it never installs into the host /usr or /lib. The output
contains complete source, applied patch, config.mak, compiler logs, installed
headers, startup objects, static archives and the selector accepted by the
existing setup compiler consumer. There is no installed-musl input/fallback,
private factory, network fetch, prebuilt runtime or target dependency.

Prerequisites: Linux x86-64, CPython 3.12+ standard library, GCC at /usr/bin/gcc,
GNU binutils (ar, ranlib, nm, strip), GNU make, patch, POSIX sh and standard
utilities under /usr/bin:/bin. GCC's compiler headers and libgcc are declared
prerequisites, not newly delivered corresponding GCC source. Host glibc may run
these tools; it is not linked into the produced runtime/setup. The recipe
clears caller compiler/include/library environment overrides. BUILD_CONFIG.json
is admitted and consumed: x86_64-linux-gnu, static only, GCC wrapper, -O2,
complete distribution patch series and fts import. A consumed source-prefix map
(`-ffile-prefix-map=<extracted-source>=musl-1.2.4`) keeps assertion filenames
stable without deleting assertions or changing upstream sources. GCC must
support -ffile-prefix-map. No optional configuration
is inferred from a private host. The result binds source/config, compiler tools,
config.mak, every installed file, archive members and global symbol output.
Different declared compiler versions may produce different runtime bytes.

This is a new source-built compatible static runtime for future setup packaging.
The historical distribution used --enable-debug, Debian hardening=+all and its
then-current build toolchain; that complete historical build environment is not
reconstructed by this recipe. Exact reproduction of the selected historical
libc archive and all startup/member bytes is not asserted. Archive and member,
symbol, header and startup comparisons must distinguish equal bytes from
compatible but different bytes. The musl selection remains precisely unresolved
for historical binary reproduction; full corresponding source/patches/notices
and a tested future build path are now delivered. No frozen candidate ELF,
archive, producer receipt or original binding is replaced or relabeled.
GCC-runtime, selected-native-setup, other unresolved components, original font
reviews, build/metal owners and whole-release/license status remain separate.
