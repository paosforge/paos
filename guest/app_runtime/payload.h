/* Defensive guest decoding only. RSA/trust and authority are native-owned. */
#ifndef PAOS_APP_RUNTIME_PAYLOAD_H
#define PAOS_APP_RUNTIME_PAYLOAD_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define APP_MAX 65536u
#define APP_MEMBERS 16u
struct app_member { uint32_t kind, offset, length; const char *path; };
struct app_payload {
    const char *entry, *data_dir;
    uint32_t count;
    struct app_member members[APP_MEMBERS];
};
struct app_ingress {
    void *context;
    uint32_t (*length)(void *);
    void (*select)(void *, uint32_t);
    unsigned char (*byte)(void *);
};
static size_t app_receive(unsigned char *destination, const struct app_ingress *io) {
    uint32_t n = io->length(io->context);
    if (!n || n > APP_MAX) return 0;
    for (uint32_t i = 0; i < n; ++i) {
        io->select(io->context, i);
        destination[i] = io->byte(io->context);
    }
    return io->length(io->context) == n ? n : 0;
}
static uint32_t app_u32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static int app_zero(const unsigned char *p, size_t n) {
    while (n--) if (*p++) return 0;
    return 1;
}
static int app_fixed(const char *s, size_t cap, int path) {
    size_t i = 0;
    int component = 0;
    for (; i < cap && s[i]; ++i) {
        unsigned char b = (unsigned char)s[i];
        int atom = (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || (path && b == '_');
        if (atom) component = 1;
        else if ((b == '.' || (path && b == '/')) && (!path || component)) component = 0;
        else return 0;
    }
    if (!i || i == cap || (path && !component) || !app_zero((const unsigned char *)s+i, cap-i)) return 0;
    if (!path && (i < 3 || i > 63 || !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9')))) return 0;
    return 1;
}
static int app_text(const unsigned char *p, uint32_t n) {
    if (!n || p[n-1] != '\n') return 0;
    for (uint32_t i = 0; i < n; ++i)
        if (p[i] != '\t' && p[i] != '\n' && (p[i] < 32 || p[i] > 126)) return 0;
    return 1;
}
/* Native already checked RSA and full PNG CRC/grammar/deflate. Keep the
 * defensive guest envelope aligned without decoding pixels a second time. */
static int app_png(const unsigned char *p, uint32_t n, uint32_t side) {
    if (n < 33 || memcmp(p, "\211PNG\r\n\032\n", 8) ||
        memcmp(p+8, "\0\0\0\015IHDR", 8)) return 0;
    for (uint32_t i = 0; i < 2; ++i) {
        const unsigned char *d = p+16+4*i;
        if (d[0] || d[1] || d[2] || d[3] != side) return 0;
    }
    return p[24] == 8 && p[25] == 6 && !p[26] && !p[27] && p[28] <= 1;
}
/* Kind 8 (App Format Q-4), exactly as the native installer admits it
 * (svc/app_script.asm .image): images/<seg>.<ext>, <seg> non-empty with no '.'
 * or '/', <ext> one of png/bmp/jpg/gif ending the name, leading bytes naming
 * the extension. The general path grammar is checked by the caller. */
static int app_image(const char *path, const unsigned char *p, uint32_t n) {
    if (memcmp(path, "images/", 7)) return 0;
    size_t i = 7;
    while (path[i] && path[i] != '.' && path[i] != '/') ++i;
    if (i == 7 || path[i] != '.') return 0;
    const char *ext = path+i+1;             /* app_fixed proved a NUL inside the 64-byte field */
    if (strlen(ext) != 3) return 0;
    if (!memcmp(ext, "png", 3)) return n >= 8 && !memcmp(p, "\211PNG\r\n\032\n", 8);
    if (!memcmp(ext, "bmp", 3)) return n >= 2 && p[0] == 'B' && p[1] == 'M';
    if (!memcmp(ext, "jpg", 3)) return n >= 2 && p[0] == 0xff && p[1] == 0xd8;
    if (!memcmp(ext, "gif", 3)) return n >= 6 && (!memcmp(p, "GIF87a", 6) || !memcmp(p, "GIF89a", 6));
    return 0;
}
static int app_reserved(const char *path, const char *name) {
    size_t n = strlen(name);
    return !memcmp(path, name, n) && app_zero((const unsigned char *)path+n, 64-n);
}
/* PAOSAPP1 container 2 in its two native forms:
 * - owner script bundle: BASHAPP1 manifest (256) at 64, index at 320, flags and
 *   reserved zero, 256-byte signature trailer;
 * - sharing package (.paosapp, App Format 0.1): BASHAPP2 manifest (512) at 64,
 *   index at 576, flags 1 (SHA-256 trailer, 32 bytes) or 3 (SHA-256, modulus and
 *   signature, 544 bytes), reserved u32 at 44 zero, manifest bytes 384..511 zero.
 * Native verified the trailer and trust before staging; this only bounds the
 * layout. Fields 256..383 of BASHAPP2 (display name, version) are native's. */
static int app_decode(const unsigned char *p, size_t n, struct app_payload *out) {
    struct app_payload v = {0};
    if (n < 64 || n > APP_MAX || memcmp(p, "PAOSAPP1", 8)) return 0;
    int sharing = app_u32(p+20) == 512;
    uint32_t base = sharing ? 576 : 320, flags = app_u32(p+40);
    uint32_t trailer = !sharing ? (app_zero(p+40, 8) ? 256 : 0) :
                       !app_zero(p+44, 4) ? 0 : flags == 1 ? 32 : flags == 3 ? 544 : 0;
    if (!trailer || n < base+2*80+trailer ||
        p[8] != 2 || p[9] || p[10] != 64 || p[11] || app_u32(p+12) != n ||
        app_u32(p+16) != 64 || app_u32(p+20) != base-64 || app_u32(p+24) != base) return 0;
    uint32_t indexlen = app_u32(p+28), asset = app_u32(p+32), bytes = app_u32(p+36);
    /* Header key-id is opaque here. It was verified against native owner trust. */
    if (indexlen % 80 || indexlen < 160 || indexlen > APP_MEMBERS*80 ||
        asset != base+indexlen || asset > n-trailer || bytes != n-trailer-asset) return 0;
    const unsigned char *m = p+64;
    if (memcmp(m, sharing ? "BASHAPP2" : "BASHAPP1", 8) || app_u32(m+8) != 1 || app_u32(m+12) != 1 ||
        !app_fixed((const char *)m+16, 64, 0) || !app_fixed((const char *)m+80, 64, 1) ||
        !app_fixed((const char *)m+208, 32, 1) ||
        app_u32(m+240) != 1 || app_u32(m+244) != 1 || !app_zero(m+248, 8) ||
        (sharing && !app_zero(m+384, 128))) return 0;
    int has_icon = m[144] != 0;
    if (has_icon ? !app_fixed((const char *)m+144, 64, 1) : !app_zero(m+144, 64)) return 0;
    v.entry = (const char *)m+80;
    v.data_dir = (const char *)m+208;
    v.count = indexlen/80;
    uint32_t cursor = 0, scripts = 0, forms = 0, icons = 0, grants = 0, icons2 = 0, notices = 0, images = 0;
    for (uint32_t i = 0; i < v.count; ++i) {
        const unsigned char *r = p+base+80*i;
        uint32_t kind = app_u32(r), off = app_u32(r+4), len = app_u32(r+8);
        const char *path = (const char *)r+16;
        uint32_t cap = kind == 3 ? 12288 : kind == 6 || kind == 8 ? 40960 : 8192;
        int name_ok = kind == 6 ? app_reserved(path, "icon@2x.png") :
                      kind == 7 ? app_reserved(path, "NOTICES.json") : app_fixed(path, 64, 1);
        if (kind < 1 || kind > 8 || off != cursor || off > bytes || !len || len > cap || len > bytes-off ||
            !app_zero(r+12, 4) || !name_ok) return 0;
        for (uint32_t j = 0; j < i; ++j) if (!strcmp(path, v.members[j].path)) return 0;
        const unsigned char *data = p+asset+off;
        if (kind == 1 && (++scripts != 1 || strcmp(path, v.entry) || len > 8192 || !app_text(data, len))) return 0;
        if (kind == 2) {
            size_t length = strlen(path);
            if (++forms > 4 || length < 4 || strcmp(path+length-4, ".frm") || len > 4096 || !app_text(data, len)) return 0;
            for (uint32_t j = 0; j < len; ++j) if (data[j] == '\t') return 0;
        }
        if (kind == 3 && (++icons != 1 || !has_icon || strcmp(path, (const char *)m+144) || !app_png(data, len, 48))) return 0;
        if (kind == 6 && (++icons2 != 1 || !app_png(data, len, 96))) return 0;
        if (kind == 7 && ++notices != 1) return 0;
        if (kind == 8 && (++images > 4 || !app_image(path, data, len))) return 0;
        if (kind == 4) {
            size_t length = strlen(v.data_dir);
            if (len > 8192 || strncmp(path, v.data_dir, length) || path[length] != '/') return 0;
        }
        if (kind == 5) {
            if (++grants != 1 || strcmp(path, "grants") || len != 4) return 0;
            for (uint32_t j = 0; j < 4; ++j) if (data[j] > 2) return 0;
        }
        v.members[i] = (struct app_member){kind, asset+off, len, path};
        cursor += len;
    }
    if (cursor != bytes || scripts != 1 || grants != 1 || icons != (uint32_t)has_icon ||
        icons2 > icons || (icons && notices != 1)) return 0;
    *out = v;
    return 1;
}
#endif
