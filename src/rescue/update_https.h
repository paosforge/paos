#ifndef PAOS_RESCUE_UPDATE_HTTPS_H
#define PAOS_RESCUE_UPDATE_HTTPS_H
#include <stddef.h>
#include <stdint.h>

#define PRC_HTTPS_UPDATE_V1 1
#define PRC_HTTPS_BUNDLE_MAX (UINT64_C(67108864) + 1024)

/* Replaceable worker transport, not an update authorization or STAGED result.
 * The trusted bridge supplies the installed channel's exact URL and CA PEM;
 * no environment/default trust, URL discovery or unauthenticated caller config.
 * Single-threaded Linux worker only (bounded resolver child, always reaped).
 * HTTPS DNS/IPv4 host, optional port, absolute ASCII path/query. The original
 * entry points refuse redirects; the explicit policy API below is opt-in.
 * cancel_fd=-1 or a pollable cancellation fd: readable/error/hangup cancels.
 * deadline_ms is the ORIGINAL absolute CLOCK_MONOTONIC deadline, never renewed.
 * Success: caller owns fd, sealed against write/grow/shrink, exact full bundle
 * PBMF[1024] + payload[512..64MiB]. Close after prc_stage_local_update imports it
 * to fresh private staging. Existing signed bundle/release/route verification
 * and released inactive-slot writer remain mandatory, with live authority.
 * No ESP/STATE/reboot effects. Every failure closes partial RAM files, returns
 * fd=-1/bytes=0. No automatic retry. Missing channel/trust is unavailable.
 */
struct prc_https_channel {
    const char *url;
    const uint8_t *ca_pem;
    size_t ca_size;
};
struct prc_https_control { uint64_t deadline_ms; int cancel_fd; };
struct prc_https_bundle { int fd; uint64_t bytes; };
enum prc_https_status {
    PRC_HTTPS_OK = 0, PRC_HTTPS_REFUSED = -1,
    PRC_HTTPS_CANCELLED = -2, PRC_HTTPS_TIMEOUT = -3
};
/* Optional per-invocation byte transport below the SAME verified TLS pipeline.
 * No native pointer, route, authority or NIC is conveyed by its opaque token.
 * Trusted native mediation must supply the actual qualified provider; merely
 * implementing this worker ABI does not qualify any native endpoint.
 *
 * open receives the exact parsed installed URL host and port, ONCE. It returns
 * 0 with a nonzero token after connection, or a prc_https_status failure. A
 * token assigned even on partial-open failure is closed exactly once.
 * read/write are bounded NONBLOCKING operations: positive admitted-prefix
 * count <= capacity, read 0 = EOF, negative prc_https_status = terminal failure,
 * PRC_HTTPS_STREAM_AGAIN = explicitly no bytes admitted. write 0 refuses.
 * wait(writing=0/1) waits only for progress of this SAME connection under the
 * original control, returning 0 or a terminal prc_https_status. Never replay an
 * ambiguous exchange or renew the deadline. Every callback receives original
 * deadline/cancel operands; worker also checks them before/after callbacks.
 * close must be bounded, nonblocking and retire/quarantine original custody
 * even when cancelled/expired; no reconnect or claimed native cleanup receipt.
 * No callback retains buffer/control/host pointers beyond its call.
 * Missing/invalid explicitly selected provider REFUSES: never POSIX fallback.
 */
#define PRC_HTTPS_STREAM_V1 1
#define PRC_HTTPS_STREAM_AGAIN (-4)
struct prc_https_stream {
    unsigned version;
    void *context;
    int (*open)(void *, const char *, uint16_t,
                const struct prc_https_control *, uint64_t *);
    int (*read)(void *, uint64_t, void *, int, const struct prc_https_control *);
    int (*write)(void *, uint64_t, const void *, int, const struct prc_https_control *);
    int (*wait)(void *, uint64_t, int, const struct prc_https_control *);
    void (*close)(void *, uint64_t, const struct prc_https_control *);
};
/* Check only: exactly1024 signed successor bytes, still unverified input.
 * Trusted caller uses its installed metadata URL and authenticates the result
 * with existing manifest/release policy readers before displaying a version.
 * Same control, seals, ownership and refusal rules; no full payload download. */
int prc_https_update_metadata_fetch(const struct prc_https_channel *,
    const struct prc_https_control *, struct prc_https_bundle *);
int prc_https_update_fetch(const struct prc_https_channel *,
    const struct prc_https_control *, struct prc_https_bundle *);
/* Signed-channel worker inputs only:1024B PCF1 feed and full raw payload.
 * Same TLS/deadline/cancel/seal rules, still no content authorization. */
int prc_https_update_feed_fetch(const struct prc_https_channel *,
    const struct prc_https_control *, struct prc_https_bundle *);
int prc_https_update_payload_fetch(const struct prc_https_channel *,
    const struct prc_https_control *, struct prc_https_bundle *);
/* Explicit opaque-provider counterparts. Same input lengths/trust/seals as
 * above; old entry points retain their existing POSIX transport. */
int prc_https_update_fetch_stream(const struct prc_https_channel *,
    const struct prc_https_control *, const struct prc_https_stream *, struct prc_https_bundle *);
int prc_https_update_metadata_fetch_stream(const struct prc_https_channel *,
    const struct prc_https_control *, const struct prc_https_stream *, struct prc_https_bundle *);
int prc_https_update_feed_fetch_stream(const struct prc_https_channel *,
    const struct prc_https_control *, const struct prc_https_stream *, struct prc_https_bundle *);
int prc_https_update_payload_fetch_stream(const struct prc_https_channel *,
    const struct prc_https_control *, const struct prc_https_stream *, struct prc_https_bundle *);

/* Trusted installed policy only, immutable for this synchronous invocation.
 * A redirect never supplies policy or CA bytes. origin is EXACT https://host
 * or https://host:port, without a trailing slash, userinfo or wildcard. Prefix
 * is an absolute path, without query/escapes/dot segments. It matches complete
 * path segments (a trailing slash matches descendants). Each absolute Location
 * needs one matching installed destination, even when it names the old host.
 * Root-relative /path?query inherits ONLY the already admitted origin/CA and
 * its path restriction. Other relative forms, //authority, escaped paths and
 * dot segments refuse. Query escapes are accepted; fragments/controls refuse.
 * Up to8 unique origins, at most3 redirects; loops refuse before reconnecting.
 * Every hop rebuilds minimal unauthenticated GET headers and validates TLS
 * identity under that destination's own CA. One original deadline/cancel and
 * explicit provider span all hops, including retirement. No automatic retry.
 * policy/stream missing or malformed refuses; no fallback. Old channel struct
 * and entry points are unchanged. out has the same ownership/seal semantics.
 * The caller retains the ORIGINAL channel URL for signed PCF1 identity checks;
 * the final URL is never substituted or returned as release authority. Final
 * bytes remain untrusted until the existing full signed size/hash verifier.
 * This interface provisions no actual destinations and does not extend native
 * network admission. C/W/native configuration must compose those explicitly
 * from independently installed inputs before using it on the product path.
 */
#define PRC_HTTPS_REDIRECT_V1 1
#define PRC_HTTPS_REDIRECT_MAX 3
#define PRC_HTTPS_DESTINATIONS_MAX 8
struct prc_https_destination {
    const char *origin;
    const char *path_prefix;
    const uint8_t *ca_pem;
    size_t ca_size;
};
struct prc_https_redirect_policy {
    unsigned version, count;
    const struct prc_https_destination *destinations;
};
enum prc_https_object {
    PRC_HTTPS_OBJECT_BUNDLE = 0, PRC_HTTPS_OBJECT_METADATA = 1,
    PRC_HTTPS_OBJECT_FEED = 2, PRC_HTTPS_OBJECT_PAYLOAD = 3
};
int prc_https_update_fetch_redirects(const struct prc_https_channel *,
    const struct prc_https_control *, const struct prc_https_redirect_policy *,
    unsigned object, struct prc_https_bundle *);
int prc_https_update_fetch_stream_redirects(const struct prc_https_channel *,
    const struct prc_https_control *, const struct prc_https_stream *,
    const struct prc_https_redirect_policy *, unsigned object, struct prc_https_bundle *);
#endif
