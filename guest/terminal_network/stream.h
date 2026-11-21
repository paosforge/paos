/* Creator: Codex / rc-codex-av. Guest compatibility only; no native authority. */
#ifndef PAOS_TERMINAL_STREAM_H
#define PAOS_TERMINAL_STREAM_H
#include <stddef.h>
#include <stdint.h>
#include "stream_abi.h"

struct tn_io {
    uint32_t (*read32)(void *, uint16_t);
    void (*write32)(void *, uint16_t, uint32_t);
    void *opaque;
};
/* One object for the whole process, shared serially by all four clients.
 * Once dead, no retry or PIO is possible. New process requires fresh native START. */
struct tn_stream { struct tn_io io; uint64_t sequence; int dead; };
struct tn_reply { uint64_t handle; uint32_t length; unsigned char data[1024]; };
void tn_stream_init(struct tn_stream *, const struct tn_io *);
int tn_call(struct tn_stream *, unsigned op, uint64_t handle,
            const void *payload, size_t length, struct tn_reply *);
/* Returns canonical length or zero. Output unchanged on refusal. */
size_t tn_domain(const unsigned char *, size_t, unsigned char out[254]);
/* Strict, complete CONNECT header -> canonical host or zero. */
size_t tn_connect_host(const unsigned char *, size_t, unsigned char out[254]);
#endif
