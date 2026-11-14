# Guest chat executable build

Creator: Codex / rc-codex-av.

The Makefile builds the static adapter and fixed native portal. The adapter
uses its maintained CPU supervisor and LIVE snapshot codec; the portal uses
the shared SHA256 implementation. Every included source and the Makefile are
prerequisites of the executable that uses them. Run from this directory or
use `make -C guest/ai_chat` from the repository root.

```sh
make -C guest/ai_chat CC=/retained/toolchain/bin/gcc \
  OUT=/existing/build-output/paos-chat-adapter \
  PORTAL_OUT=/existing/build-output/paos-chat-portal
```

The default `all` builds both executables. `make adapter` or `make portal`
builds one. `OUT` retains its adapter meaning; `PORTAL_OUT` selects the portal
output. Select distinct output paths in existing directories. `make clean`
removes only those two selected outputs.

Select the retained static Linux toolchain explicitly for a carrying image.
Record the actual compiler, source inputs and output hashes with the image's
existing build receipt. `CC=cc` can be used for HOST qualification; a HOST build
does not establish shipping provenance or guest operation. This build requires
the maintained VM `portal.c` (LEDGER87481 and restart amendment87538) alongside
the integrated adapter and LIVE codec. ADMIN adopts those dependencies first.

The build compiles executables without executing them, fetching inputs, staging
a model or constructing an image. The verified app's fixed `chat.sh` starts
`/bin/paos-chat-portal` for each question. That portal passes the exact admitted
native frame to `/bin/paos-chat-adapter`; the adapter executes the existing
pinned `/bin/llama-simple` with `/model.gguf`. Cloud routes remain unavailable.

Use the maintained emitter's explicit asset group described in
CHAT_RUNTIME_ASSETS (internal, not in this snapshot) to carry both
outputs, the pinned runtime and model on the existing app-bash rail. The actual
resolved kernel must support memfd and shared memory; the compiler checks RAM
and actual packed extents. Native SEC/INPUT/VM Send admission, original START
identity, cancellation, result fencing and guest readiness remain separate
from compilation. See the adapter contract (internal, not in this snapshot)
and the portal contract (internal, not in this snapshot).
