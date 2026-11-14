#define _GNU_SOURCE
#include "settings_native_exchange.h"
#include <limits.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef PAOS_SETTINGS_NATIVE_EXCHANGE_HOST
#include <sys/io.h>
#define port_in(p) inl(p)
#define port_out(v,p) outl((v),(p))
#define allow_ports() ioperm(0x50e0,16,1)
#define pid_one() (getpid()==1 && syscall(SYS_gettid)==1)
#else
/* Inert HOST instruction boundary only; production has no installable hook. */
extern unsigned prc_native_host_in(unsigned);
extern void prc_native_host_out(unsigned,unsigned);
extern int prc_native_host_allow(void),prc_native_host_pid(void);
#define port_in(p) prc_native_host_in(p)
#define port_out(v,p) prc_native_host_out((v),(p))
#define allow_ports() prc_native_host_allow()
#define pid_one() prc_native_host_pid()
#endif
_Static_assert(sizeof(struct prc_esp_request)==48,"native request48");
_Static_assert(sizeof(struct prc_esp_reply)==48,"native reply48");
enum { SERVICE=0x50e0, ORIGINAL=0x50e4, CONTROL=0x50e8, DATA=0x50ec };
static int attempted,opened,busy,poisoned,budget_attempted;
static uint64_t last_sequence, budget_deadline;
static uint8_t original40[40];
static uint8_t reply_data[PRC_ESP_CHUNK];
static int bad(void) { poisoned=1;memset(reply_data,0,sizeof(reply_data));return -1; }
static int service_current(void) {
    port_out(2,SERVICE);
    return port_in(SERVICE)==1;
}
static uint64_t u64(const uint8_t *p) { uint64_t n;memcpy(&n,p,8);return n; }
static uint32_t u32(const uint8_t *p) { uint32_t n;memcpy(&n,p,4);return n; }
int prc_settings_native_open(uint8_t original[40]) {
    if(attempted || !original) return -1;
    attempted=1;
    if(!pid_one() || allow_ports()) return bad();
    uint8_t value[40]={0};
    port_out(1,SERVICE);
    if(port_in(SERVICE)!=1) return bad();
    for(unsigned i=0;i<40;i+=4) {
        if(port_in(SERVICE)!=1) return bad();
        uint32_t word=port_in(ORIGINAL);
        memcpy(value+i,&word,4);
        if(port_in(SERVICE)!=1) return bad();
    }
    /* Validation is only fail-closed framing, not authority construction. Native
     * retains its own independently current original and never accepts this copy. */
    if(!u64(value) || u32(value+8)<1 || u32(value+8)>4 || u32(value+12)!=1 ||
        !u64(value+16) || !u64(value+24) || !u64(value+32) || !service_current()) return bad();
    memcpy(original40,value,40);memcpy(original,value,40);opened=1;return 0;
}
/* Different epochs: never put native boot_ms into a Linux timeout. Read
 * local time BEFORE the native sample; using this earlier time plus sampled
 * native remaining time deliberately underestimates the remaining budget. */
static int local_monotonic(uint64_t *out) {
#ifdef PAOS_SETTINGS_NATIVE_BUDGET_HOST
    extern int prc_native_host_monotonic(uint64_t *);
    return prc_native_host_monotonic(out);
#else
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t) || t.tv_sec<0 ||
        t.tv_nsec<0 || t.tv_nsec>=1000000000 ||
        (uint64_t)t.tv_sec>(UINT64_MAX-999)/1000) return -1;
    *out=(uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
    return 0;
#endif
}
int prc_settings_native_deadline(uint64_t *out) {
    if(!out || !opened || !pid_one() || busy || poisoned || budget_attempted) return -1;
    budget_attempted=1;busy=1;
    uint64_t before=0,after=0,deadline=0;
    uint8_t frame[32]={0};
    if(local_monotonic(&before) || !service_current()) goto lost;
    port_out(3,SERVICE);
    if(port_in(SERVICE)!=1) goto lost;
    for(unsigned i=0;i<sizeof(frame);i+=4) {
        if(port_in(SERVICE)!=1) goto lost;
        uint32_t word=port_in(ORIGINAL);memcpy(frame+i,&word,4);
        if(port_in(SERVICE)!=1) goto lost;
    }
    if(u32(frame)!=1 || u32(frame+4)!=sizeof(frame) ||
        u64(frame+8)!=u64(original40) || u64(frame+16)!=u64(original40+32) ||
        u64(frame+24)>=u64(frame+16)) goto lost;
    uint64_t remaining=u64(frame+16)-u64(frame+24);
    if(before>UINT64_MAX-remaining) goto lost;
    deadline=before+remaining;
    if(!service_current() || local_monotonic(&after) || after<before || after>=deadline) goto lost;
    budget_deadline=deadline;*out=deadline;busy=0;return 0;
lost:
    busy=0;return bad();
}
/* Private same-original network observation; no new FETCH, budget or grant.
 * Native CURRENT repeats role/closed-exit/original40 authority independently.
 * Failure never refreshes a budget, resets poison or borrows an app approval. */
int prc_settings_native_network_current(const uint8_t original[40], uint64_t deadline) {
    if (!original || !opened || !budget_attempted || !budget_deadline ||
        deadline != budget_deadline || memcmp(original, original40, 40) ||
        !pid_one() || busy || poisoned) return 0;
    return service_current();
}
int prc_settings_native_uncertain(void) { return poisoned; }
static int phase(unsigned wanted) { return port_in(CONTROL)==wanted; }
static int restore_or_close(const struct prc_esp_request *q) {
    return (q->operation==PRC_ESP_SET_RO && q->readonly==1) || q->operation==PRC_ESP_CLOSE;
}
static int request_valid(const struct prc_esp_request *q,const void *in,void *out) {
    if(!q || q->version!=1 || last_sequence==UINT64_MAX || q->sequence!=last_sequence+1 ||
        q->operation<PRC_ESP_CURRENT || q->operation>PRC_ESP_FINISH ||
        q->count>PRC_ESP_CHUNK || q->offset>PRC_ESP_LIMIT || q->file>8 || q->directory>3 ||
        q->readonly>2) return 0;
    if(q->operation==PRC_ESP_FEED || q->operation==PRC_ESP_FINISH) {
        if(q->object || q->offset || q->file || q->directory || q->readonly || out)
            return 0;
        return q->operation==PRC_ESP_FEED ? (in && q->count==1024) : (!in && !q->count);
    }
    if(q->operation==PRC_ESP_READ) return out && q->count && !in;
    if(q->operation==PRC_ESP_APPEND) return in && q->count && !out;
    return !in && !out && !q->count;
}
static int reply_valid(const struct prc_esp_request *q,const struct prc_esp_reply *r) {
    if(r->version!=1 || r->sequence!=q->sequence || r->reserved ||
        r->status>PRC_ESP_UNCERTAIN || r->size>PRC_ESP_LIMIT || r->count>q->count ||
        (q->object && r->object!=q->object)) return 0;
    if(r->status!=PRC_ESP_OK) return !r->count;
    if(q->operation==PRC_ESP_FEED || q->operation==PRC_ESP_FINISH)
        return !r->object && !r->change && !r->count && r->size>=1 &&
            r->size<=(q->operation==PRC_ESP_FEED?2U:3U);
    if((q->operation==PRC_ESP_OPEN || q->operation==PRC_ESP_TEMP) && (!r->object || !r->change))return 0;
    if(q->operation==PRC_ESP_STAT && (!r->change || r->change>INT64_MAX)) return 0;
    if(q->operation!=PRC_ESP_READ && q->operation!=PRC_ESP_APPEND && r->count)return 0;
    return 1;
}
static int transfer(const struct prc_esp_request *q,const void *in,void *out,
        struct prc_esp_reply *result) {
    /* No clock conversion, waiting or retries. Each instruction causes the
     * qualified closed native exit to recheck original168 and absolute deadline.
     * A partial frame cannot be resynchronized. Even restoration is sent only
     * from actual native idle; terminal freeze/lease reconciliation stays native. */
    if(!service_current() || !phase(0)) return bad();
    port_out(1,CONTROL);
    if(!phase(2)) return bad();
    for(unsigned i=0;i<48;i+=4) {
        uint32_t word;memcpy(&word,(const uint8_t *)q+i,4);
        port_out(word,DATA);
        if(!phase(2)) return bad();
    }
    if(q->operation==PRC_ESP_APPEND || q->operation==PRC_ESP_FEED) {
        for(unsigned i=0;i<q->count;i+=4) {
            unsigned n=q->count-i<4?q->count-i:4;
            uint32_t word=0;memcpy(&word,(const uint8_t *)in+i,n);
            port_out(word,DATA);
            if(!phase(2)) return bad();
        }
    }
    last_sequence=q->sequence; /* consumed BEFORE native effects */
    port_out(2,CONTROL);
    if(!phase(1)) return bad();
    struct prc_esp_reply reply={0};
    for(unsigned i=0;i<48;i+=4) {
        if(!phase(1)) return bad();
        uint32_t word=port_in(DATA);memcpy((uint8_t *)&reply+i,&word,4);
        if(i<44 && !phase(1)) return bad();
    }
    if(!reply_valid(q,&reply)) return bad();
    unsigned count=q->operation==PRC_ESP_READ?reply.count:0;
    if(!phase(count?1:0)) return bad();
    for(unsigned i=0;i<count;i+=4) {
        if(!phase(1)) return bad();
        uint32_t word=port_in(DATA);
        unsigned n=count-i<4?count-i:4;
        memcpy(reply_data+i,&word,n);
        if(n<4 && (word>>(8*n))) return bad();
        if(!phase(i+n==count?0:1)) return bad();
    }
    if(!service_current()) return bad();
    if(count)memcpy(out,reply_data,count);
    memcpy(result,&reply,sizeof(reply));
    memset(reply_data,0,sizeof(reply_data));
    if(reply.status==PRC_ESP_UNCERTAIN) poisoned=1;
    return 0;
}
int prc_settings_native_exchange(void *unused,const struct prc_esp_request *q,
        const void *in,void *out,struct prc_esp_reply *result) {
    (void)unused;
    if(!opened || !pid_one() || busy || !result || !request_valid(q,in,out) ||
        (poisoned && !restore_or_close(q))) return -1;
    busy=1;
    /* Freeze private request before the first native exit. A public callback
     * cannot replace operands between the frame and the reply check. */
    const struct prc_esp_request frozen=*q;
    int rc=transfer(&frozen,in,out,result);
    busy=0;return rc;
}
