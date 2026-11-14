#define _GNU_SOURCE
#include "update_https.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

struct endpoint { char host[254], service[6], authority[261], path[2049]; };
struct addresses { unsigned count; struct sockaddr_storage addr[8]; socklen_t len[8]; };

static uint64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) || t.tv_sec < 0) return UINT64_MAX;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static int current(const struct prc_https_control *c) {
    struct pollfd p = {c->cancel_fd, POLLIN, 0};
    if (c->cancel_fd >= 0) {
        int n = poll(&p, 1, 0);
        if (n > 0 && p.revents) return PRC_HTTPS_CANCELLED;
        if (n < 0 && errno != EINTR) return PRC_HTTPS_REFUSED;
    }
    return now_ms() >= c->deadline_ms ? PRC_HTTPS_TIMEOUT : 0;
}
static int wait_ready(int fd, short events, const struct prc_https_control *c) {
    for (;;) {
        int rc = current(c);
        if (rc) return rc;
        uint64_t left = c->deadline_ms - now_ms();
        if (!left || left > INT_MAX) return PRC_HTTPS_TIMEOUT;
        struct pollfd p[2] = {{fd, events, 0}, {c->cancel_fd, POLLIN, 0}};
        int n = poll(p, 2, (int)left);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return PRC_HTTPS_REFUSED;
        rc = current(c);
        if (rc) return rc;
        if (p[0].revents & events) return 0;
        if (p[0].revents) return PRC_HTTPS_REFUSED;
    }
}

static int endpoint(const char *url, struct endpoint *e) {
    if (!url || strnlen(url, 2400) >= 2400 || strncmp(url, "https://", 8)) return -1;
    const char *a = url + 8, *slash = strchr(a, '/');
    if (!slash || slash == a || (size_t)(slash-a) >= sizeof(e->authority) ||
        strlen(slash) >= sizeof(e->path)) return -1;
    for (const char *p = a; *p; ++p)
        if ((unsigned char)*p < 33 || (unsigned char)*p > 126 || *p == '#' || *p == '\\') return -1;
    memcpy(e->authority, a, (size_t)(slash-a));
    e->authority[slash-a] = 0;
    const char *colon = memchr(a, ':', (size_t)(slash-a));
    size_t hlen = colon ? (size_t)(colon-a) : (size_t)(slash-a);
    if (!hlen || hlen >= sizeof(e->host)) return -1;
    for (size_t i = 0; i < hlen; ++i)
        if (!isalnum((unsigned char)a[i]) && a[i] != '.' && a[i] != '-') return -1;
    memcpy(e->host, a, hlen); e->host[hlen] = 0;
    strcpy(e->service, "443");
    if (colon) {
        size_t plen = (size_t)(slash-colon-1);
        unsigned port = 0;
        if (!plen || plen > 5) return -1;
        for (size_t i = 0; i < plen; ++i) {
            unsigned char ch = (unsigned char)colon[1+i];
            if (ch < '0' || ch > '9') return -1;
            port = port*10 + ch-'0';
        }
        if (!port || port > 65535) return -1;
        memcpy(e->service, colon+1, plen); e->service[plen] = 0;
    }
    strcpy(e->path, slash);
    return 0;
}

/* libc DNS has no deadline API. Isolate only resolution, no shell/program,
 * with a fixed-size result pipe. The parent owns the original cancellation
 * and deadline across DNS, every address, TLS and the entire body. */
static int resolve(const struct endpoint *e, const struct prc_https_control *c,
                   struct addresses *out) {
    struct in_addr ipv4;
    if (inet_pton(AF_INET, e->host, &ipv4) == 1) {
        struct sockaddr_in *a = (struct sockaddr_in *)&out->addr[0];
        a->sin_family = AF_INET; a->sin_addr = ipv4;
        a->sin_port = htons((uint16_t)strtoul(e->service, NULL, 10));
        out->len[0] = sizeof(*a); out->count = 1; return current(c);
    }
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK)) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (!pid) {
        close(pipefd[0]);
        struct addrinfo hints = {0}, *list = NULL;
        struct addresses found = {0};
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        if (!getaddrinfo(e->host, e->service, &hints, &list)) {
            for (struct addrinfo *p = list; p && found.count < 8; p = p->ai_next) {
                if ((p->ai_family != AF_INET && p->ai_family != AF_INET6) ||
                    p->ai_addrlen > sizeof(found.addr[0])) continue;
                memcpy(&found.addr[found.count], p->ai_addr, p->ai_addrlen);
                found.len[found.count++] = p->ai_addrlen;
            }
            freeaddrinfo(list);
        }
        ssize_t n = write(pipefd[1], &found, sizeof(found));
        close(pipefd[1]); _exit(n == sizeof(found) ? 0 : 1);
    }
    close(pipefd[1]);
    int rc = wait_ready(pipefd[0], POLLIN, c);
    if (!rc && read(pipefd[0], out, sizeof(*out)) != sizeof(*out)) rc = -1;
    close(pipefd[0]);
    kill(pid, SIGKILL);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
    if (!rc && (!out->count || out->count > 8)) rc = -1;
    return rc;
}
static int connect_to(const struct addresses *a, const struct prc_https_control *c, int *fd) {
    for (unsigned i = 0; i < a->count; ++i) {
        int rc = current(c);
        if (rc) return rc;
        int s = socket(a->addr[i].ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (s < 0) continue;
        int ok = connect(s, (const struct sockaddr *)&a->addr[i], a->len[i]);
        if (ok && errno == EINPROGRESS) {
            rc = wait_ready(s, POLLOUT, c);
            int error = 0; socklen_t len = sizeof(error);
            ok = rc || getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &len) || error;
        }
        if (!ok) { *fd = s; return 0; }
        close(s);
        if (rc == PRC_HTTPS_CANCELLED || rc == PRC_HTTPS_TIMEOUT) return rc;
    }
    return -1;
}

/* Keep the existing POSIX policy behind the same per-invocation byte API.
 * Only this default provider calls resolver/socket/send/recv. */
static int posix_open(void *context, const char *host, uint16_t port,
                      const struct prc_https_control *c, uint64_t *token) {
    (void)context;
    struct endpoint e = {0}; struct addresses a = {0}; int fd = -1;
    strcpy(e.host, host);
    snprintf(e.service, sizeof(e.service), "%u", (unsigned)port);
    int rc = resolve(&e, c, &a);
    if (!rc) rc = connect_to(&a, c, &fd);
    if (!rc) *token = (uint64_t)fd + 1; /* fd0 is legal, token0 is absent */
    return rc;
}
static int posix_read(void *context, uint64_t token, void *buf, int len,
                      const struct prc_https_control *c) {
    (void)context; (void)c;
    int n = (int)recv((int)(token-1), buf, (size_t)len, 0);
    return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ?
        PRC_HTTPS_STREAM_AGAIN : n;
}
/* No process-global SIGPIPE disposition change, including on peer abort. */
static int posix_write(void *context, uint64_t token, const void *buf, int len,
                       const struct prc_https_control *c) {
    (void)context; (void)c;
    int n = (int)send((int)(token-1), buf, (size_t)len, MSG_NOSIGNAL);
    return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ?
        PRC_HTTPS_STREAM_AGAIN : n;
}
static int posix_wait(void *context, uint64_t token, int writing,
                      const struct prc_https_control *c) {
    (void)context;
    return wait_ready((int)(token-1), writing ? POLLOUT : POLLIN, c);
}
static void posix_close(void *context, uint64_t token, const struct prc_https_control *c) {
    (void)context; (void)c; close((int)(token-1));
}
static const struct prc_https_stream posix_stream = {
    PRC_HTTPS_STREAM_V1, NULL, posix_open, posix_read, posix_write, posix_wait, posix_close
};
struct stream_io {
    const struct prc_https_stream *provider;
    const struct prc_https_control *control;
    uint64_t token;
    int error;
};
static int terminal_status(int n) {
    return n == PRC_HTTPS_CANCELLED || n == PRC_HTTPS_TIMEOUT ? n : PRC_HTTPS_REFUSED;
}
static int bio_transfer(BIO *b, void *buf, int len, int writing) {
    struct stream_io *io = BIO_get_data(b);
    BIO_clear_retry_flags(b);
    if (io->error) return -1;
    if ((io->error = current(io->control))) return -1;
    if (len <= 0) { io->error = PRC_HTTPS_REFUSED; return -1; }
    const struct prc_https_stream *p = io->provider;
    int n = writing ? p->write(p->context, io->token, buf, len, io->control) :
                      p->read(p->context, io->token, buf, len, io->control);
    if ((io->error = current(io->control))) return -1;
    if (n == PRC_HTTPS_STREAM_AGAIN) {
        if (writing) BIO_set_retry_write(b); else BIO_set_retry_read(b);
        return -1;
    }
    if (n < 0 || n > len || (writing && !n)) {
        io->error = terminal_status(n); return -1;
    }
    return n;
}
static int bio_write(BIO *b, const char *buf, int len) {
    return bio_transfer(b, (void *)buf, len, 1);
}
static int bio_read(BIO *b, char *buf, int len) {
    return bio_transfer(b, buf, len, 0);
}
static long bio_ctrl(BIO *b, int cmd, long arg, void *ptr) {
    (void)b; (void)arg; (void)ptr; return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}
static int tls_wait(SSL *ssl, int result, struct stream_io *io) {
    int error = SSL_get_error(ssl, result);
    if (io->error) return io->error;
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return -1;
    int rc = current(io->control);
    if (rc) return rc;
    const struct prc_https_stream *p = io->provider;
    rc = p->wait(p->context, io->token, error == SSL_ERROR_WANT_WRITE, io->control);
    int after = current(io->control);
    return after ? after : (rc ? terminal_status(rc) : 0);
}
static int read_tls(SSL *ssl, struct stream_io *io, void *buffer, int size) {
    for (;;) {
        int rc = current(io->control);
        if (rc) return rc;
        ERR_clear_error();
        int n = SSL_read(ssl, buffer, size);
        if ((rc = current(io->control))) return rc;
        if (n > 0) return n;
        if (SSL_get_error(ssl, n) == SSL_ERROR_ZERO_RETURN) return 0;
        rc = tls_wait(ssl, n, io);
        if (rc) return rc;
    }
}
static int load_ca(SSL_CTX *ctx, const uint8_t *bytes, size_t size) {
    if (!bytes || !size || size > 65536) return -1;
    size_t pos = 0; unsigned count = 0;
    while (pos < size) {
        while (pos < size && isspace(bytes[pos])) ++pos;
        if (pos == size) break;
        static const char begin[] = "-----BEGIN CERTIFICATE-----";
        if (size-pos < sizeof(begin)-1 || memcmp(bytes+pos, begin, sizeof(begin)-1)) return -1;
        BIO *bio = BIO_new_mem_buf(bytes+pos, (int)(size-pos));
        if (!bio) return -1;
        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        size_t used = size-pos-(size_t)BIO_ctrl_pending(bio);
        BIO_free(bio);
        int ok = cert && X509_check_ca(cert) > 0 &&
            X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert) == 1;
        X509_free(cert);
        if (!ok || !used || ++count > 16) return -1;
        pos += used;
    }
    return count ? 0 : -1;
}

static int content_length(char *header, uint64_t minimum, uint64_t maximum, uint64_t *length) {
    char *line = strstr(header, "\r\n");
    if (!line || (strncmp(header, "HTTP/1.1 200 ", 13) && strncmp(header, "HTTP/1.0 200 ", 13))) return -1;
    for (char *p = header; p < line; ++p)
        if (*p == '\r' || *p == '\n' || *p == '\t') return -1;
    unsigned seen = 0;
    line += 2;
    while (*line) {
        char *end = strstr(line, "\r\n");
        if (!end) return -1;
        if (end == line) break;
        for (char *p = line; p < end; ++p)
            if (*p == '\r' || *p == '\n') return -1;
        *end = 0;
        char *colon = strchr(line, ':');
        if (!colon || colon == line) return -1;
        for (char *p = line; p < colon; ++p)
            if (!isalnum((unsigned char)*p) && *p != '-') return -1;
        *colon++ = 0;
        while (*colon == ' ' || *colon == '\t') ++colon;
        if (!strcasecmp(line, "Transfer-Encoding") || !strcasecmp(line, "Content-Encoding")) return -1;
        if (!strcasecmp(line, "Content-Length")) {
            if (seen++ || !*colon) return -1;
            uint64_t n = 0;
            for (char *p = colon; *p; ++p) {
                if (*p < '0' || *p > '9' || n > maximum/10) return -1;
                n = n*10 + (unsigned)(*p-'0');
                if (n > maximum) return -1;
            }
            if (n < minimum) return -1;
            *length = n;
        }
        line = end+2;
    }
    return seen == 1 ? 0 : -1;
}

/* Inspect redirect headers without modifying the final200 parser's input.
 * No redirect body is admitted to RAM or treated as a release payload. */
static int redirect_location(const char *header, char location[2400]) {
    const char *line = strstr(header, "\r\n");
    if (!line || line-header < 13 ||
        (strncmp(header, "HTTP/1.1 ", 9) && strncmp(header, "HTTP/1.0 ", 9))) return -1;
    int final = !strncmp(header+9, "200 ", 4);
    if (!final && strncmp(header+9, "301 ", 4) && strncmp(header+9, "302 ", 4) &&
        strncmp(header+9, "303 ", 4) && strncmp(header+9, "307 ", 4) &&
        strncmp(header+9, "308 ", 4)) return -1;
    for (const char *p = header; p < line; ++p)
        if (*p == '\r' || *p == '\n' || *p == '\t') return -1;
    unsigned seen = 0, lengths = 0;
    line += 2;
    while (*line) {
        const char *end = strstr(line, "\r\n");
        if (!end) return -1;
        if (end == line) return final ? (seen ? -1 : 0) : (seen == 1 ? 1 : -1);
        const char *colon = memchr(line, ':', (size_t)(end-line));
        if (!colon || colon == line) return -1;
        for (const char *p = line; p < colon; ++p)
            if (!isalnum((unsigned char)*p) && *p != '-') return -1;
        for (const char *p = colon+1; p < end; ++p)
            if (*p == '\r' || *p == '\n') return -1;
        size_t key = (size_t)(colon-line);
        const char *value = colon+1;
        while (value < end && (*value == ' ' || *value == '\t')) ++value;
        size_t size = (size_t)(end-value);
        if ((key == 17 && !strncasecmp(line, "Transfer-Encoding", key)) ||
            (key == 16 && !strncasecmp(line, "Content-Encoding", key))) return -1;
        if (key == 8 && !strncasecmp(line, "Location", key)) {
            if (seen++ || !size || size >= 2400) return -1;
            memcpy(location, value, size); location[size] = 0;
        }
        if (key == 14 && !strncasecmp(line, "Content-Length", key)) {
            if (lengths++ || !size) return -1;
            uint64_t length = 0;
            for (const char *p = value; p < end; ++p) {
                if (*p < '0' || *p > '9' || length > PRC_HTTPS_BUNDLE_MAX/10) return -1;
                length = length*10+(unsigned)(*p-'0');
                if (length > PRC_HTTPS_BUNDLE_MAX) return -1;
            }
        }
        line = end+2;
    }
    return -1;
}

static int fetch_once(const struct prc_https_channel *channel,
    const struct prc_https_control *control, const struct prc_https_stream *stream,
    struct prc_https_bundle *out, uint64_t minimum, uint64_t maximum,
    char *location) {
    if (!out) return -1;
    out->fd = -1; out->bytes = 0;
    if (!channel || !control || !stream || stream->version != PRC_HTTPS_STREAM_V1 ||
        !stream->open || !stream->read || !stream->write || !stream->wait || !stream->close) return -1;
    /* Freeze the caller's original cutoff/cancel operands across the whole
     * operation; never ask the provider to choose trust or renew a deadline. */
    struct prc_https_control original = *control;
    control = &original;
    struct prc_https_stream provider_copy = *stream;
    stream = &provider_copy;
    struct stream_io io = {stream, control, 0, 0};
    int rc = current(control);
    if (rc) return rc;
    struct endpoint e = {0};
    if (endpoint(channel->url, &e)) return -1;
    int ram = -1;
    uint64_t completed = 0;
    OSSL_LIB_CTX *lib = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *provider = lib ? OSSL_PROVIDER_load(lib, "default") : NULL;
    SSL_CTX *ctx = provider ? SSL_CTX_new_ex(lib, NULL, TLS_client_method()) : NULL;
    SSL *ssl = NULL; BIO_METHOD *method = NULL;
    rc = -1;
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) ||
        load_ca(ctx, channel->ca_pem, channel->ca_size)) goto done;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if ((rc = current(control))) goto done;
    rc = stream->open(stream->context, e.host, (uint16_t)strtoul(e.service, NULL, 10), control, &io.token);
    int after_open = current(control);
    if (after_open) { rc = after_open; goto done; }
    if (rc || !io.token) { rc = terminal_status(rc); goto done; }
    rc = -1;
    ssl = SSL_new(ctx);
    method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "PaOS update byte stream");
    if (!ssl || !method || !BIO_meth_set_write(method, bio_write) ||
        !BIO_meth_set_read(method, bio_read) || !BIO_meth_set_ctrl(method, bio_ctrl)) goto done;
    BIO *bio = BIO_new(method);
    if (!bio) goto done;
    BIO_set_data(bio, &io); BIO_set_init(bio, 1);
    SSL_set_bio(ssl, bio, bio);
    struct in_addr ipv4;
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (inet_pton(AF_INET, e.host, &ipv4) == 1) {
        if (!X509_VERIFY_PARAM_set1_ip_asc(param, e.host)) goto done;
    } else if (!SSL_set1_host(ssl, e.host) || !SSL_set_tlsext_host_name(ssl, e.host)) goto done;
    for (;;) {
        if ((rc = current(control))) goto done;
        ERR_clear_error(); int n = SSL_connect(ssl);
        if (n == 1) break;
        if ((rc = tls_wait(ssl, n, &io))) goto done;
    }
    rc = -1;
    if (SSL_get_verify_result(ssl) != X509_V_OK) goto done;
    char request[2500];
    int size = snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\n"
        "Connection: close\r\nAccept: application/octet-stream\r\nAccept-Encoding: identity\r\n\r\n", e.path, e.authority);
    if (size < 0 || size >= (int)sizeof(request)) goto done;
    for (int sent = 0; sent < size;) {
        if ((rc = current(control))) goto done;
        ERR_clear_error(); int n = SSL_write(ssl, request+sent, size-sent);
        if (n > 0) sent += n;
        else if ((rc = tls_wait(ssl, n, &io))) goto done;
    }
    /* Bytewise bounded header avoids ever treating body bytes as headers. */
    char header[8193]; unsigned used = 0;
    while (used < sizeof(header)-1) {
        int n = read_tls(ssl, &io, header+used, 1);
        if (n != 1) { rc = n < 0 ? n : -1; goto done; }
        unsigned char ch = (unsigned char)header[used++];
        if (!ch || (ch < 32 && ch != '\r' && ch != '\n' && ch != '\t') || ch > 126) { rc=-1; goto done; }
        if (used >= 4 && !memcmp(header+used-4, "\r\n\r\n", 4)) break;
    }
    header[used] = 0;
    uint64_t length = 0;
    rc = -1;
    if (used < 4 || memcmp(header+used-4, "\r\n\r\n", 4)) goto done;
    if (location) {
        int redirect = redirect_location(header, location);
        if (redirect < 0) goto done;
        if (redirect) { rc = 1; goto done; }
    }
    if (content_length(header, minimum, maximum, &length)) goto done;
    ram = memfd_create("paos-update-full", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (ram < 0 || fchmod(ram, 0600)) goto done;
    uint8_t buffer[65536]; uint64_t copied = 0;
    while (copied < length) {
        int want = length-copied < sizeof(buffer) ? (int)(length-copied) : (int)sizeof(buffer);
        int n = read_tls(ssl, &io, buffer, want);
        if (n <= 0) { rc = n < 0 ? n : -1; goto done; }
        for (int written = 0; written < n;) {
            if ((rc = current(control))) goto done;
            ssize_t count = write(ram, buffer+written, (size_t)(n-written));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { rc=-1; goto done; }
            written += (int)count;
        }
        copied += (unsigned)n;
    }
    /* Require clean authenticated EOF, reject truncated TLS and extra bytes. */
    int n = read_tls(ssl, &io, buffer, 1);
    if (n) { rc = n < 0 ? n : -1; goto done; }
    rc = current(control);
    if (rc) goto done;
    if (fcntl(ram, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) ||
        lseek(ram, 0, SEEK_SET) != 0) { rc=-1; goto done; }
    completed = copied;
    rc = 0;
done:
    SSL_free(ssl); BIO_meth_free(method); SSL_CTX_free(ctx);
    if (provider) OSSL_PROVIDER_unload(provider);
    OSSL_LIB_CTX_free(lib);
    if (io.token) stream->close(stream->context, io.token, control);
    /* Retirement is part of this original operation. Keep the sealed body
     * private until its last callback completes and the original is current. */
    if (rc >= 0) {
        int after = current(control);
        if (after) rc = after;
    }
    if (!rc) { out->fd = ram; out->bytes = completed; ram = -1; }
    if (ram >= 0) close(ram);
    return rc;
}

static int fetch(const struct prc_https_channel *channel,
    const struct prc_https_control *control, const struct prc_https_stream *stream,
    struct prc_https_bundle *out, uint64_t minimum, uint64_t maximum) {
    return fetch_once(channel, control, stream, out, minimum, maximum, NULL);
}

/* Conservative path grammar: never normalize an authority, dot segment or
 * escaped path into an admitted prefix. Encoded query bytes remain opaque. */
static int redirect_path(const char *path, int prefix) {
    if (!path || path[0] != '/' || path[1] == '/' || strnlen(path, 2049) >= 2049) return -1;
    const char *end = strchr(path, '?');
    if (prefix && end) return -1;
    if (!end) end = path+strlen(path);
    const char *segment = path+1;
    for (const char *p = path; p < end; ++p) {
        if ((unsigned char)*p < 33 || (unsigned char)*p > 126 ||
            *p == '%' || *p == '#' || *p == '\\') return -1;
        if (*p == '/' && p > path) {
            if ((p-segment == 1 && segment[0] == '.') ||
                (p-segment == 2 && segment[0] == '.' && segment[1] == '.')) return -1;
            segment = p+1;
        }
    }
    if ((end-segment == 1 && segment[0] == '.') ||
        (end-segment == 2 && segment[0] == '.' && segment[1] == '.')) return -1;
    for (const char *p = end; *p; ++p) {
        if ((unsigned char)*p < 33 || (unsigned char)*p > 126 || *p == '#' || *p == '\\') return -1;
        if (*p == '%') {
            if (!p[1] || !p[2] || !isxdigit((unsigned char)p[1]) || !isxdigit((unsigned char)p[2])) return -1;
            p += 2;
        }
    }
    return 0;
}
static int path_admitted(const char *path, const char *prefix) {
    size_t n = strlen(prefix);
    return !strncmp(path, prefix, n) &&
        (prefix[n-1] == '/' || path[n] == 0 || path[n] == '/' || path[n] == '?');
}

int prc_https_update_fetch_stream_redirects(const struct prc_https_channel *channel,
    const struct prc_https_control *control, const struct prc_https_stream *stream,
    const struct prc_https_redirect_policy *policy, unsigned object,
    struct prc_https_bundle *out) {
    if (!out) return -1;
    out->fd = -1; out->bytes = 0;
    if (!channel || !control || !stream || !policy ||
        policy->version != PRC_HTTPS_REDIRECT_V1 || policy->count > PRC_HTTPS_DESTINATIONS_MAX ||
        (policy->count && !policy->destinations) || object > PRC_HTTPS_OBJECT_PAYLOAD) return -1;
    struct prc_https_control original = *control;
    struct prc_https_stream provider = *stream;
    struct endpoint admitted[PRC_HTTPS_DESTINATIONS_MAX];
    struct prc_https_destination rules[PRC_HTTPS_DESTINATIONS_MAX];
    char prefixes[PRC_HTTPS_DESTINATIONS_MAX][2049];
    unsigned count = policy->count;
    for (unsigned i = 0; i < count; ++i) {
        rules[i] = policy->destinations[i];
        char origin[280];
        if (!rules[i].origin || strnlen(rules[i].origin, sizeof(origin)-1) >= sizeof(origin)-1 ||
            !rules[i].ca_pem || !rules[i].ca_size || rules[i].ca_size > 65536 ||
            redirect_path(rules[i].path_prefix, 1)) return -1;
        snprintf(origin, sizeof(origin), "%s/", rules[i].origin);
        if (endpoint(origin, &admitted[i]) || strcmp(admitted[i].path, "/")) return -1;
        strcpy(prefixes[i], rules[i].path_prefix);
        for (unsigned j = 0; j < i; ++j)
            if (!strcmp(admitted[i].authority, admitted[j].authority)) return -1;
    }
    struct endpoint e = {0};
    if (endpoint(channel->url, &e) || redirect_path(e.path, 0)) return -1;
    char urls[PRC_HTTPS_REDIRECT_MAX+1][2400];
    strcpy(urls[0], channel->url);
    const char *prefix = "/";
    struct prc_https_channel hop = {urls[0], channel->ca_pem, channel->ca_size};
    uint64_t minimum = object == PRC_HTTPS_OBJECT_BUNDLE ? 1536 :
        object == PRC_HTTPS_OBJECT_PAYLOAD ? 512 : 1024;
    uint64_t maximum = object == PRC_HTTPS_OBJECT_BUNDLE ? PRC_HTTPS_BUNDLE_MAX :
        object == PRC_HTTPS_OBJECT_PAYLOAD ? UINT64_C(67108864) : 1024;
    for (unsigned step = 0; ; ++step) {
        char location[2400];
        int rc = fetch_once(&hop, &original, &provider, out, minimum, maximum, location);
        if (rc != 1) return rc;
        if (step == PRC_HTTPS_REDIRECT_MAX) return -1;
        char *next = urls[step+1];
        if (location[0] == '/' && location[1] != '/') {
            int n = snprintf(next, sizeof(urls[0]), "https://%s%s", e.authority, location);
            if (n < 0 || n >= (int)sizeof(urls[0]) || redirect_path(location, 0) ||
                !path_admitted(location, prefix)) return -1;
        } else {
            if (endpoint(location, &e) || redirect_path(e.path, 0)) return -1;
            unsigned i;
            for (i = 0; i < count; ++i)
                if (!strcmp(e.authority, admitted[i].authority) && path_admitted(e.path, prefixes[i])) break;
            if (i == count) return -1;
            hop.ca_pem = rules[i].ca_pem; hop.ca_size = rules[i].ca_size;
            prefix = prefixes[i];
            strcpy(next, location);
        }
        if (endpoint(next, &e)) return -1;
        for (unsigned i = 0; i <= step; ++i)
            if (!strcmp(next, urls[i])) return -1;
        hop.url = next;
    }
}

int prc_https_update_fetch_redirects(const struct prc_https_channel *channel,
    const struct prc_https_control *control, const struct prc_https_redirect_policy *policy,
    unsigned object, struct prc_https_bundle *out) {
    return prc_https_update_fetch_stream_redirects(channel, control, &posix_stream, policy, object, out);
}

int prc_https_update_fetch(const struct prc_https_channel *channel,
    const struct prc_https_control *control, struct prc_https_bundle *out) {
    return fetch(channel, control, &posix_stream, out, 1536, PRC_HTTPS_BUNDLE_MAX);
}
int prc_https_update_metadata_fetch(const struct prc_https_channel *channel,
    const struct prc_https_control *control, struct prc_https_bundle *out) {
    return fetch(channel, control, &posix_stream, out, 1024, 1024);
}
int prc_https_update_feed_fetch(const struct prc_https_channel *channel,
    const struct prc_https_control *control, struct prc_https_bundle *out) {
    return fetch(channel, control, &posix_stream, out, 1024, 1024);
}
int prc_https_update_payload_fetch(const struct prc_https_channel *channel,
    const struct prc_https_control *control, struct prc_https_bundle *out) {
    return fetch(channel, control, &posix_stream, out, 512, UINT64_C(67108864));
}

int prc_https_update_fetch_stream(const struct prc_https_channel *channel,
    const struct prc_https_control *control, const struct prc_https_stream *stream,
    struct prc_https_bundle *out) {
    return fetch(channel, control, stream, out, 1536, PRC_HTTPS_BUNDLE_MAX);
}
int prc_https_update_metadata_fetch_stream(const struct prc_https_channel *channel,
    const struct prc_https_control *control, const struct prc_https_stream *stream,
    struct prc_https_bundle *out) {
    return fetch(channel, control, stream, out, 1024, 1024);
}
int prc_https_update_feed_fetch_stream(const struct prc_https_channel *channel,
    const struct prc_https_control *control, const struct prc_https_stream *stream,
    struct prc_https_bundle *out) {
    return fetch(channel, control, stream, out, 1024, 1024);
}
int prc_https_update_payload_fetch_stream(const struct prc_https_channel *channel,
    const struct prc_https_control *control, const struct prc_https_stream *stream,
    struct prc_https_bundle *out) {
    return fetch(channel, control, stream, out, 512, UINT64_C(67108864));
}
