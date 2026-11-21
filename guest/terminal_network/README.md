# Terminal CONNECT adapter

Creator: Codex / rc-codex-av. This is guest compatibility code for the separate
PaOS tools VM. Native VM admission, owner authority, hostname policy, DNS,
public-address selection, TCP custody, TLS ClientHello/SNI and revocation remain
native responsibilities. Changing or replacing this helper grants no authority.

`terminal-connect --serve` opens only `127.0.0.1:3128` and requests Linux I/O
permission for scalar32 ports `0x50f0`/`0x50f4`. Run it only inside the admitted
tools guest. With no arguments it prints usage before accessing PIO or sockets.
The guest service currently retains its guest root privilege; packaging and
guest privilege confinement belong to the VM lane. No real PIO was run on gpu.

The service accepts HTTP/1.0 or HTTP/1.1 CONNECT authority form, canonical DNS
hostname and literal port 443 only. It rejects IP literals, malformed names,
other methods/ports and folded or nonprintable headers. It has four fixed client
slots, 8192-byte headers, 1024-byte SEND and output buffers, a 10-second
header/open deadline and a bounded turn per client. It reads exactly through
CRLFCRLF so coalesced TLS bytes remain in the socket. HTTP 200 follows native
phase 4 (ClientHello readiness), before opaque TLS relay. Socket EOF closes the
whole native stream; this helper does not implement independent half-close.

All clients share one serial, nonwrapping u64 request sequence. Every frame is
transmitted once. Explicit native BUSY admits zero bytes and permits a later
SEND with a new sequence; partial/failed SEND is never replayed. Unexpected PIO
progress, framing, reply sequence, handle, padding or acknowledgement latches
the whole driver dead. CLOSE PENDING retains the original native handle and
occupies its client slot until CLOSE OK. Output backpressure holds the existing
buffer and prevents another native READ.

The helper must be started once per fresh native tools START. Process restart
inside an existing START cannot recover its request sequence. VM supervision
must stop/retire the tools binding after service death or uncertain transport,
and await native retirement before a replacement START. Guest process exit
alone does not fence native queued bytes. No launcher, supervisor, image
recipe, device admission or cutover is changed by this source unit.

`run-proxied COMMAND [ARG ...]` preserves HOME and arguments, sets both cases of
HTTP_PROXY/HTTPS_PROXY to the loopback service, clears ALL_PROXY/all_proxy and
empties NO_PROXY/no_proxy. The VM launcher must explicitly invoke it after the
service is alive. These variables provide CLI compatibility, while the tools
VM's absent raw network device and native broker provide enforcement. There
is no alternate proxy, DNS or direct-network fallback in the helper. Pinned
Claude/Codex CLI compatibility still needs the actual admitted guest journey.

`tools/gen_tools_stream_abi.py` generates `stream_abi.h` from the VM-authored
`src/hv/tools_stream_abi.inc`; `--check` verifies the copy. HOST tests compile
actual `stream.c` and `proxy.c`, inject scalar PIO replies and use real local
socket pairs. They prove guest parser/relay behavior, not native authority,
actual PIO, guest boot, provider access, credentials or bare-metal acceptance.

Build with an explicitly selected static Linux toolchain using `make`; set OUT
to an external artifact path. Run HOST controls with
`python3 -m unittest gauntlet_v2.tests.test_terminal_network_guest_host`.
