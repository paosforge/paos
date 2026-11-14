/* QR Code Model 2 encoder for the local Rescue report view: byte mode, error
 * correction M, versions 1-10 (up to 213 bytes). Static storage, no allocation.
 * Checked against an independent encoder by test_rescue_report_qr_host.py. */
#ifndef PAOS_RESCUE_QR_H
#define PAOS_RESCUE_QR_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PRC_QR_MAX_SIZE 57      /* version 10 */
#define PRC_QR_MAX_CODEWORDS 346

struct prc_qr {
    int size;
    uint8_t dark[PRC_QR_MAX_SIZE][PRC_QR_MAX_SIZE];
    uint8_t fixed[PRC_QR_MAX_SIZE][PRC_QR_MAX_SIZE];
};

static const uint8_t prc_qr_ecc_per_block[11] = {0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26};
static const uint8_t prc_qr_blocks[11] = {0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5};

static unsigned prc_qr_raw_codewords(int version) {
    unsigned bits = (16u * (unsigned)version + 128u) * (unsigned)version + 64u;
    if (version >= 2) {
        unsigned align = (unsigned)version / 7u + 2u;
        bits -= (25u * align - 10u) * align - 55u;
        if (version >= 7) bits -= 36u;
    }
    return bits / 8u;
}

static unsigned prc_qr_data_capacity(int version) {
    return prc_qr_raw_codewords(version) -
           (unsigned)prc_qr_ecc_per_block[version] * prc_qr_blocks[version];
}

static uint8_t prc_qr_mul(uint8_t a, uint8_t b) {
    unsigned z = 0;
    for (int i = 7; i >= 0; --i) {
        z = (z << 1) ^ ((z >> 7) * 0x11Du);
        z ^= ((b >> i) & 1u) * a;
    }
    return (uint8_t)z;
}

static void prc_qr_ecc(const uint8_t *data, unsigned length, unsigned degree, uint8_t *out) {
    uint8_t divisor[32] = {0};
    divisor[degree - 1] = 1;
    uint8_t root = 1;
    for (unsigned i = 0; i < degree; ++i) {
        for (unsigned j = 0; j < degree; ++j) {
            divisor[j] = prc_qr_mul(divisor[j], root);
            if (j + 1 < degree) divisor[j] ^= divisor[j + 1];
        }
        root = prc_qr_mul(root, 2);
    }
    memset(out, 0, degree);
    for (unsigned i = 0; i < length; ++i) {
        uint8_t factor = data[i] ^ out[0];
        memmove(out, out + 1, degree - 1);
        out[degree - 1] = 0;
        for (unsigned j = 0; j < degree; ++j) out[j] ^= prc_qr_mul(divisor[j], factor);
    }
}

static void prc_qr_put(struct prc_qr *q, int x, int y, int dark) {
    q->dark[y][x] = (uint8_t)dark;
    q->fixed[y][x] = 1;
}

static void prc_qr_finder(struct prc_qr *q, int cx, int cy) {
    for (int dy = -4; dy <= 4; ++dy)
        for (int dx = -4; dx <= 4; ++dx) {
            int x = cx + dx, y = cy + dy, ax = dx < 0 ? -dx : dx, ay = dy < 0 ? -dy : dy;
            int dist = ax > ay ? ax : ay;
            if (x >= 0 && x < q->size && y >= 0 && y < q->size)
                prc_qr_put(q, x, y, dist != 2 && dist != 4);
        }
}

static void prc_qr_format(struct prc_qr *q, int mask) {
    unsigned data = (0u << 3) | (unsigned)mask;      /* M = 00 */
    unsigned rem = data;
    for (int i = 0; i < 10; ++i) rem = (rem << 1) ^ ((rem >> 9) * 0x537u);
    unsigned bits = ((data << 10) | rem) ^ 0x5412u;
#define PRC_QR_BIT(i) ((int)((bits >> (i)) & 1u))
    for (int i = 0; i <= 5; ++i) prc_qr_put(q, 8, i, PRC_QR_BIT(i));
    prc_qr_put(q, 8, 7, PRC_QR_BIT(6));
    prc_qr_put(q, 8, 8, PRC_QR_BIT(7));
    prc_qr_put(q, 7, 8, PRC_QR_BIT(8));
    for (int i = 9; i < 15; ++i) prc_qr_put(q, 14 - i, 8, PRC_QR_BIT(i));
    for (int i = 0; i < 8; ++i) prc_qr_put(q, q->size - 1 - i, 8, PRC_QR_BIT(i));
    for (int i = 8; i < 15; ++i) prc_qr_put(q, 8, q->size - 15 + i, PRC_QR_BIT(i));
    prc_qr_put(q, 8, q->size - 8, 1);
#undef PRC_QR_BIT
}

static void prc_qr_function_patterns(struct prc_qr *q, int version) {
    for (int i = 0; i < q->size; ++i) {
        prc_qr_put(q, 6, i, i % 2 == 0);
        prc_qr_put(q, i, 6, i % 2 == 0);
    }
    prc_qr_finder(q, 3, 3);
    prc_qr_finder(q, q->size - 4, 3);
    prc_qr_finder(q, 3, q->size - 4);
    if (version >= 2) {
        int count = version / 7 + 2, step = (version * 8 + count * 3 + 5) / (count * 4 - 4) * 2, pos[7];
        for (int i = count - 1, p = q->size - 7; i >= 1; --i, p -= step) pos[i] = p;
        pos[0] = 6;
        for (int i = 0; i < count; ++i)
            for (int j = 0; j < count; ++j) {
                if ((i == 0 && j == 0) || (i == 0 && j == count - 1) || (i == count - 1 && j == 0)) continue;
                for (int dy = -2; dy <= 2; ++dy)
                    for (int dx = -2; dx <= 2; ++dx) {
                        int ax = dx < 0 ? -dx : dx, ay = dy < 0 ? -dy : dy;
                        prc_qr_put(q, pos[i] + dx, pos[j] + dy, (ax > ay ? ax : ay) != 1);
                    }
            }
    }
    prc_qr_format(q, 0);
    if (version >= 7) {
        unsigned rem = (unsigned)version;
        for (int i = 0; i < 12; ++i) rem = (rem << 1) ^ ((rem >> 11) * 0x1F25u);
        unsigned bits = ((unsigned)version << 12) | rem;
        for (int i = 0; i < 18; ++i) {
            int bit = (int)((bits >> i) & 1u), a = q->size - 11 + i % 3, b = i / 3;
            prc_qr_put(q, a, b, bit);
            prc_qr_put(q, b, a, bit);
        }
    }
}

static int prc_qr_mask_bit(int mask, int x, int y) {
    switch (mask) {
    case 0: return (x + y) % 2 == 0;
    case 1: return y % 2 == 0;
    case 2: return x % 3 == 0;
    case 3: return (x + y) % 3 == 0;
    case 4: return (x / 3 + y / 2) % 2 == 0;
    case 5: return x * y % 2 + x * y % 3 == 0;
    case 6: return (x * y % 2 + x * y % 3) % 2 == 0;
    default: return ((x + y) % 2 + x * y % 3) % 2 == 0;
    }
}

static void prc_qr_apply_mask(struct prc_qr *q, int mask) {
    for (int y = 0; y < q->size; ++y)
        for (int x = 0; x < q->size; ++x)
            if (!q->fixed[y][x] && prc_qr_mask_bit(mask, x, y)) q->dark[y][x] ^= 1;
}

/* A finder-like 1:1:3:1:1 run with four light modules on one side. */
static long prc_qr_line_penalty(const struct prc_qr *q, int line, int vertical) {
    long score = 0;
    int run = 0, last = -1;
    uint32_t window = 0;
    for (int i = 0; i < q->size + 8; ++i) {
        int dark = 0;
        if (i < q->size) dark = vertical ? q->dark[i][line] : q->dark[line][i];
        if (i < q->size) {
            if (dark == last) {
                if (++run == 5) score += 3;
                else if (run > 5) score += 1;
            } else {
                last = dark;
                run = 1;
            }
        }
        window = ((window << 1) | (uint32_t)dark) & 0x7FFu;
        if (i >= 10 && (window == 0x5D0u || window == 0x05Du)) score += 40;
    }
    /* The pattern may start in the four light modules before the symbol. */
    window = 0;
    for (int i = 0; i < 11 && i < q->size; ++i) {
        int dark = vertical ? q->dark[i][line] : q->dark[line][i];
        window = (window << 1) | (uint32_t)dark;
        if (i == 6 && window == 0x5Du) score += 40;
    }
    return score;
}

static long prc_qr_penalty(const struct prc_qr *q) {
    long score = 0, dark = 0;
    for (int i = 0; i < q->size; ++i)
        score += prc_qr_line_penalty(q, i, 0) + prc_qr_line_penalty(q, i, 1);
    for (int y = 0; y < q->size; ++y)
        for (int x = 0; x < q->size; ++x) {
            dark += q->dark[y][x];
            if (y + 1 < q->size && x + 1 < q->size && q->dark[y][x] == q->dark[y][x + 1] &&
                q->dark[y][x] == q->dark[y + 1][x] && q->dark[y][x] == q->dark[y + 1][x + 1])
                score += 3;
        }
    long total = (long)q->size * q->size;
    long k = ((dark * 20 - total * 10) < 0 ? total * 10 - dark * 20 : dark * 20 - total * 10);
    score += ((k + total - 1) / total - 1) * 10;
    return score;
}

/* 0 on success. Text longer than version 10 holds is refused, never truncated. */
static int prc_qr_encode(struct prc_qr *q, const char *text, size_t length) {
    int version = 1;
    while (version <= 10) {
        unsigned count_bits = version < 10 ? 8u : 16u;
        if (4u + count_bits + length * 8u <= prc_qr_data_capacity(version) * 8u) break;
        ++version;
    }
    if (version > 10) return -1;
    memset(q, 0, sizeof(*q));
    q->size = version * 4 + 17;
    unsigned capacity = prc_qr_data_capacity(version), bit = 0;
    uint8_t data[PRC_QR_MAX_CODEWORDS] = {0}, out[PRC_QR_MAX_CODEWORDS];
#define PRC_QR_APPEND(value, width) \
    for (int b_ = (int)(width) - 1; b_ >= 0; --b_, ++bit) \
        data[bit >> 3] |= (uint8_t)((((unsigned)(value) >> b_) & 1u) << (7u - (bit & 7u)))
    PRC_QR_APPEND(4u, 4);
    PRC_QR_APPEND(length, version < 10 ? 8 : 16);
    for (size_t i = 0; i < length; ++i) PRC_QR_APPEND((uint8_t)text[i], 8);
    unsigned terminator = capacity * 8u - bit < 4u ? capacity * 8u - bit : 4u;
    bit += terminator;
    bit = (bit + 7u) & ~7u;
    for (uint8_t pad = 0xEC; bit < capacity * 8u; pad ^= 0xEC ^ 0x11) PRC_QR_APPEND(pad, 8);
#undef PRC_QR_APPEND
    unsigned blocks = prc_qr_blocks[version], degree = prc_qr_ecc_per_block[version];
    unsigned raw = prc_qr_raw_codewords(version), short_blocks = blocks - raw % blocks;
    unsigned short_data = raw / blocks - degree;
    static uint8_t ecc[8][32];
    unsigned offset = 0;
    for (unsigned b = 0; b < blocks; ++b) {
        unsigned n = short_data + (b >= short_blocks);
        prc_qr_ecc(data + offset, n, degree, ecc[b]);
        offset += n;
    }
    unsigned used = 0;
    for (unsigned i = 0; i <= short_data; ++i) {
        offset = 0;
        for (unsigned b = 0; b < blocks; ++b) {
            unsigned n = short_data + (b >= short_blocks);
            if (i < n) out[used++] = data[offset + i];
            offset += n;
        }
    }
    for (unsigned i = 0; i < degree; ++i)
        for (unsigned b = 0; b < blocks; ++b) out[used++] = ecc[b][i];
    prc_qr_function_patterns(q, version);
    unsigned index = 0;
    for (int right = q->size - 1; right >= 1; right -= 2) {
        if (right == 6) right = 5;
        for (int vert = 0; vert < q->size; ++vert)
            for (int j = 0; j < 2; ++j) {
                int x = right - j, upward = ((right + 1) & 2) == 0;
                int y = upward ? q->size - 1 - vert : vert;
                if (!q->fixed[y][x] && index < raw * 8u) {
                    q->dark[y][x] = (out[index >> 3] >> (7u - (index & 7u))) & 1u;
                    ++index;
                }
            }
    }
    int best = 0;
    long lowest = 0;
    for (int mask = 0; mask < 8; ++mask) {
        prc_qr_apply_mask(q, mask);
        prc_qr_format(q, mask);
        long score = prc_qr_penalty(q);
        if (mask == 0 || score < lowest) { lowest = score; best = mask; }
        prc_qr_apply_mask(q, mask);
    }
    prc_qr_apply_mask(q, best);
    prc_qr_format(q, best);
    return 0;
}
#endif
