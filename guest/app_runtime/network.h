#ifndef PAOS_APP_NETWORK_H
#define PAOS_APP_NETWORK_H
#include <stddef.h>
#include <stdint.h>

/* App-private transport, not an authorization API or secret sink. Keep the
 * scalar wire layout in sync with src/hv/app_network.inc. No native pointers.
 */
enum { APP_NET_OPEN=1, APP_NET_SEND, APP_NET_READ, APP_NET_CLOSE, APP_NET_STATUS };
enum { APP_NET_OK, APP_NET_DENY, APP_NET_PENDING, APP_NET_BUSY,
       APP_NET_EOF, APP_NET_FAULT };
enum { APP_NET_HEADER=32, APP_NET_DATA=1024, APP_NET_HOST=253 };
struct app_net_frame {
    uint32_t version, operation;
    uint64_t sequence;
    uint32_t port, count;
    uint64_t reserved;
    unsigned char body[APP_NET_DATA];
};
_Static_assert(sizeof(struct app_net_frame) == 1056, "native frame layout");
_Static_assert(offsetof(struct app_net_frame, body) == APP_NET_HEADER, "native header layout");
struct app_net_io {
    void *context;
    /* One original exchange. Never replay a submitted request after an
     * ambiguous completion. Output capacity is input/output byte length. */
    int (*exchange)(void *, const struct app_net_frame *, size_t,
                    struct app_net_frame *, size_t *);
};
int app_net_session(int, const struct app_net_io *, uint64_t *);
/* PID1 only. Starts one app-local loopback worker, returns its PID or 0 if
 * unavailable. A no-network runtime still launches ordinary apps. */
int app_net_start(void);
#endif
