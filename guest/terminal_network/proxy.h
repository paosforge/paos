/* Creator: Codex / rc-codex-av. Fixed-size, single-threaded CONNECT relay. */
#ifndef PAOS_TERMINAL_PROXY_H
#define PAOS_TERMINAL_PROXY_H
#include "stream.h"
enum tn_client_state { TN_FREE, TN_HEADER, TN_OPENING, TN_CONFIRM, TN_RELAY, TN_ERROR, TN_CLOSING };
struct tn_client {
    int fd, state;
    uint64_t handle, deadline;
    size_t header_length, send_length, output_length, output_at;
    unsigned char header[8192], pending[1024], output[1024];
};
/* fd ownership transfers on success; requires a nonblocking socket. */
int tn_client_init(struct tn_client *, int fd, uint64_t now_ms);
/* Bounded one turn, no wait. Return -1 only for terminal transport failure. */
int tn_client_step(struct tn_client *, struct tn_stream *, uint64_t now_ms);
void tn_client_abort(struct tn_client *);
#endif
