#define _GNU_SOURCE
#include "update_channel.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#ifdef PAOS_RESCUE_UPDATE_CHANNEL_HEADER
#include PAOS_RESCUE_UPDATE_CHANNEL_HEADER
#else
static const struct prc_update_channel_config prc_installed_update_channel = {0};
#endif

static int current(const struct prc_https_control *c) {
    if (!c || c->cancel_fd < -1) return PRC_HTTPS_REFUSED;
    struct pollfd p = {c->cancel_fd, POLLIN, 0};
    if (c->cancel_fd >= 0) {
        int n = poll(&p, 1, 0);
        if (n > 0 && p.revents) return PRC_HTTPS_CANCELLED;
        if (n < 0 && errno != EINTR) return PRC_HTTPS_REFUSED;
    }
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) || t.tv_sec < 0) return PRC_HTTPS_REFUSED;
    uint64_t now = (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
    return now >= c->deadline_ms ? PRC_HTTPS_TIMEOUT : 0;
}

static int configured(void) {
    const struct prc_update_channel_config *c = &prc_installed_update_channel;
    if (c->format != 1 || !c->channel || !c->feed.url || !c->asset.url ||
        !c->feed.ca_pem || !c->asset.ca_pem || !c->feed.ca_size || !c->asset.ca_size ||
        strchr(c->feed.url, '?') || strchr(c->feed.url, '#')) return 0;
    size_t n = strnlen(c->channel, 33);
    if (!n || n > 31 || c->channel[0] < 'a' || c->channel[0] > 'z') return 0;
    for (size_t i = 0; i < n; ++i) {
        char v = c->channel[i];
        if ((v < 'a' || v > 'z') && (v < '0' || v > '9') && v != '-') return 0;
    }
    uint8_t installed[32];
    prc_release_installed_identity(installed);
    return !CRYPTO_memcmp(installed, c->policy_sha256, 32);
}

int prc_update_channel_owner_successor(const struct prc_https_control *control,
    uint8_t out[1024]) {
    if (!out) return PRC_HTTPS_REFUSED;
    memset(out, 0, 1024);
    int rc = current(control);
    if (rc) return rc;
#ifdef PRC_INSTALLED_OWNER_SUCCESSOR_V1
    uint8_t digest[32];
    if (!configured() || PRC_INSTALLED_OWNER_SUCCESSOR_V1 != 1 ||
        sizeof(prc_channel_owner_successor) != 1024 ||
        sizeof(prc_channel_owner_successor_sha256) != 32 ||
        memcmp(prc_channel_owner_successor, "PBMF\x01\x00\x00\x04", 8) ||
        !SHA256(prc_channel_owner_successor, sizeof(prc_channel_owner_successor), digest) ||
        CRYPTO_memcmp(digest, prc_channel_owner_successor_sha256, 32))
        return PRC_HTTPS_REFUSED;
    rc = current(control);
    if (!rc) memcpy(out, prc_channel_owner_successor, 1024);
    return rc;
#else
    return PRC_HTTPS_REFUSED;
#endif
}

/* No independent signature/floor implementation. Future offered records go
 * through the SAME installed PRL1 authority and current mapping engine. */
static int classify(const uint8_t feed[1024], const uint8_t current_sha[32],
    uint64_t current_size, struct prc_release_result *out, const uint8_t *current_record) {
    struct prc_release_result active = {0};
    if (!configured() || prc_release_installed_current_record(current_record, current_sha, current_size, &active) ||
        prc_release_installed_feed_check_current(current_record, feed, prc_installed_update_channel.channel,
            prc_installed_update_channel.asset.url, current_sha, current_size, out)) return -1;
    for (unsigned i = 0; i < 3; ++i) {
        if (out->version[i] != active.version[i])
            return out->version[i] > active.version[i] ? PRC_UPDATE_AVAILABLE : -1;
    }
    /* Equal product versions alone prove nothing. Require the exact signed
     * installed release, including build/security metadata and payload bytes.
     * The shared feed check above still enforces candidate floors/revocation. */
    if (out->payload_size != active.payload_size ||
        CRYPTO_memcmp(out->payload_sha256, active.payload_sha256, 32) ||
        CRYPTO_memcmp(out->record_sha256, active.record_sha256, 32)) return -1;
    return PRC_UPDATE_CURRENT;
}

static int admit(const uint8_t feed[1024], const uint8_t current_sha[32],
    uint64_t current_size, struct prc_release_result *out, const uint8_t *current_record) {
    return classify(feed, current_sha, current_size, out, current_record) ==
        PRC_UPDATE_AVAILABLE ? 0 : -1;
}

int prc_update_channel_offer_check_current(const uint8_t *current_record,
    const uint8_t current_sha[32], uint64_t current_size,
    const uint8_t feed[1024], struct prc_release_result *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !feed) return -1;
    struct prc_release_result release = {0};
    if (admit(feed, current_sha, current_size, &release, current_record)) return -1;
    *out = release;
    return 0;
}

static int check_status(const uint8_t *current_record,
    const uint8_t current_sha[32], uint64_t current_size,
    const struct prc_https_control *control, const struct prc_https_stream *stream, int explicit_stream,
    struct prc_update_offer *out, unsigned *status) {
    if (out) memset(out, 0, sizeof(*out));
    if (status) *status = 0;
    if (!out || !status || !control || (explicit_stream && !stream)) return PRC_HTTPS_REFUSED;
    const struct prc_https_control frozen = *control;
    control = &frozen;
    int rc = current(control);
    if (rc) return rc;
    struct prc_release_result active = {0};
    if (!configured() || prc_release_installed_current_record(current_record, current_sha, current_size, &active))
        return PRC_HTTPS_REFUSED;
    char url[2400];
    int n = snprintf(url, sizeof(url), "%s?version=%u.%u.%u&channel=%s",
        prc_installed_update_channel.feed.url, active.version[0], active.version[1],
        active.version[2], prc_installed_update_channel.channel);
    if (n < 0 || (size_t)n >= sizeof(url)) return PRC_HTTPS_REFUSED;
    struct prc_https_channel feed = prc_installed_update_channel.feed;
    feed.url = url;
    struct prc_https_bundle input = {.fd = -1};
    rc = explicit_stream ? prc_https_update_feed_fetch_stream(&feed, control, stream, &input) :
        prc_https_update_feed_fetch(&feed, control, &input);
    if (rc) return rc;
    struct prc_update_offer offer = {0};
    ssize_t count = pread(input.fd, offer.feed, sizeof(offer.feed), 0);
    close(input.fd);
    if (count != sizeof(offer.feed) || input.bytes != sizeof(offer.feed)) return PRC_HTTPS_REFUSED;
    int classification = classify(offer.feed, current_sha, current_size, &offer.release, current_record);
    if (classification < 0) return PRC_HTTPS_REFUSED;
    rc = current(control);
    if (!rc) { *out = offer; *status = (unsigned)classification; }
    return rc;
}

/* Explicit stream selection is per invocation. Even NULL/invalid providers
 * refuse; there is no global setter, POSIX fallback, reopen or new deadline. */
int prc_update_channel_check_status_current_stream(const uint8_t *record,
    const uint8_t sha[32], uint64_t size, const struct prc_https_control *control,
    const struct prc_https_stream *stream, struct prc_update_offer *out, unsigned *status) {
    return check_status(record, sha, size, control, stream, 1, out, status);
}
int prc_update_channel_check_status_current(const uint8_t *record,
    const uint8_t sha[32], uint64_t size, const struct prc_https_control *control,
    struct prc_update_offer *out, unsigned *status) {
    return check_status(record, sha, size, control, NULL, 0, out, status);
}
int prc_update_channel_check_current_stream(const uint8_t *record,
    const uint8_t sha[32], uint64_t size, const struct prc_https_control *control,
    const struct prc_https_stream *stream, struct prc_update_offer *out) {
    unsigned status = 0;
    int rc = check_status(record, sha, size, control, stream, 1, out, &status);
    if (!rc && status != PRC_UPDATE_AVAILABLE) {
        memset(out, 0, sizeof(*out));
        return PRC_HTTPS_REFUSED;
    }
    return rc;
}

int prc_update_channel_check_current(const uint8_t *current_record,
    const uint8_t current_sha[32], uint64_t current_size,
    const struct prc_https_control *control, struct prc_update_offer *out) {
    unsigned status = 0;
    int rc = prc_update_channel_check_status_current(current_record, current_sha,
        current_size, control, out, &status);
    if (!rc && status != PRC_UPDATE_AVAILABLE) {
        memset(out, 0, sizeof(*out));
        return PRC_HTTPS_REFUSED;
    }
    return rc;
}

static int download(const uint8_t *current_record,
    const uint8_t current_sha[32], uint64_t current_size,
    const struct prc_update_offer *offer, const struct prc_https_control *control,
    const struct prc_https_stream *stream, int explicit_stream, struct prc_https_bundle *out) {
    if (out) { out->fd = -1; out->bytes = 0; }
    if (!out || !offer || !control || (explicit_stream && !stream)) return PRC_HTTPS_REFUSED;
    const struct prc_https_control frozen = *control;
    control = &frozen;
    int rc = current(control);
    if (rc) return rc;
    struct prc_release_result release = {0};
    if (admit(offer->feed, current_sha, current_size, &release, current_record) ||
        memcmp(&release, &offer->release, sizeof(release))) return PRC_HTTPS_REFUSED;
    struct prc_https_bundle input = {.fd = -1};
    rc = explicit_stream ? prc_https_update_payload_fetch_stream(
        &prc_installed_update_channel.asset, control, stream, &input) :
        prc_https_update_payload_fetch(&prc_installed_update_channel.asset, control, &input);
    if (rc) return rc;
    rc = PRC_HTTPS_REFUSED;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    if (input.bytes != release.payload_size || !hash ||
        EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) goto done;
    uint8_t buffer[65536], digest[32];
    for (uint64_t offset = 0; offset < input.bytes;) {
        rc = current(control);
        if (rc) goto done;
        size_t want = input.bytes-offset < sizeof(buffer) ? (size_t)(input.bytes-offset) : sizeof(buffer);
        ssize_t count = pread(input.fd, buffer, want, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || EVP_DigestUpdate(hash, buffer, (size_t)count) != 1) {
            rc = PRC_HTTPS_REFUSED; goto done;
        }
        offset += (unsigned)count;
    }
    unsigned length = 0;
    if (EVP_DigestFinal_ex(hash, digest, &length) != 1 || length != 32 ||
        CRYPTO_memcmp(digest, release.payload_sha256, 32)) { rc = PRC_HTTPS_REFUSED; goto done; }
    rc = current(control);
    if (!rc) { *out = input; input.fd = -1; }
done:
    EVP_MD_CTX_free(hash);
    if (input.fd >= 0) close(input.fd);
    return rc;
}

int prc_update_channel_download_current_stream(const uint8_t *record,
    const uint8_t sha[32], uint64_t size, const struct prc_update_offer *offer,
    const struct prc_https_control *control, const struct prc_https_stream *stream,
    struct prc_https_bundle *out) {
    return download(record, sha, size, offer, control, stream, 1, out);
}
int prc_update_channel_download_current(const uint8_t *record,
    const uint8_t sha[32], uint64_t size, const struct prc_update_offer *offer,
    const struct prc_https_control *control, struct prc_https_bundle *out) {
    return download(record, sha, size, offer, control, NULL, 0, out);
}

/* Original catalog-only ABI stays strict for all existing callers. */
int prc_update_channel_check_status(const uint8_t sha[32], uint64_t size,
    const struct prc_https_control *control, struct prc_update_offer *out, unsigned *status) {
    return prc_update_channel_check_status_current(NULL, sha, size, control, out, status);
}

int prc_update_channel_offer_check(const uint8_t sha[32], uint64_t size,
    const uint8_t feed[1024], struct prc_release_result *out) {
    return prc_update_channel_offer_check_current(NULL, sha, size, feed, out);
}
int prc_update_channel_check(const uint8_t sha[32], uint64_t size,
    const struct prc_https_control *control, struct prc_update_offer *out) {
    return prc_update_channel_check_current(NULL, sha, size, control, out);
}
int prc_update_channel_download(const uint8_t sha[32], uint64_t size,
    const struct prc_update_offer *offer, const struct prc_https_control *control,
    struct prc_https_bundle *out) {
    return prc_update_channel_download_current(NULL, sha, size, offer, control, out);
}
