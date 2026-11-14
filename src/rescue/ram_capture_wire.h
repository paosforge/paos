/* SPDX-License-Identifier: GPL-2.0 */
/* v1 wire layout shared with the opt-in Manager capture. No persisted pointers. */
#ifndef PAOS_RAM_CAPTURE_WIRE_H
#define PAOS_RAM_CAPTURE_WIRE_H
#define PAOS_CAPTURE_BASE 0x20000000ULL
#define PAOS_CAPTURE_BYTES 0x200000U
#define PAOS_CAPTURE_HEADER_BYTES 0x1000U
#define PAOS_CAPTURE_TRACE_BYTES 0x10000U
#define PAOS_CAPTURE_CAPACITY (PAOS_CAPTURE_TRACE_BYTES - 64U)
#define PAOS_CAPTURE_TRACE_MAGIC 0x3145434152544b50ULL /* PKTRACE1 */
#define PAOS_CAPTURE_MAGIC 0x314d415250414350ULL /* PCAPRAM1 */
struct paos_capture_header {
 unsigned long long magic, nonce, inverse, base, bytes;
 unsigned int state, tco, written, capacity, flags, version;
};
_Static_assert(sizeof(struct paos_capture_header) == 64, "capture header");
static inline int paos_capture_valid(const volatile struct paos_capture_header *h)
{
 return h->magic == PAOS_CAPTURE_MAGIC && h->nonce == PAOS_RAM_CAPTURE_NONCE &&
  h->inverse == ~PAOS_RAM_CAPTURE_NONCE && h->base == PAOS_CAPTURE_BASE &&
  h->bytes == PAOS_CAPTURE_BYTES && h->state == 1 && h->tco == 1 &&
  h->flags == 0 && h->version == 1;
}
struct paos_capture_trace {
 unsigned long long magic, nonce, written, phase, inverse, bytes, flags, reserved;
};
_Static_assert(sizeof(struct paos_capture_trace) == 64, "trace header");
static inline int paos_trace_valid(const volatile struct paos_capture_trace *t)
{
 return t->magic == PAOS_CAPTURE_TRACE_MAGIC && t->nonce == PAOS_RAM_CAPTURE_NONCE &&
  t->inverse == ~PAOS_RAM_CAPTURE_NONCE && t->bytes == PAOS_CAPTURE_TRACE_BYTES &&
  t->written <= PAOS_CAPTURE_CAPACITY && t->flags == 0 && t->reserved == 0;
}
/* Explicit DRAM writeback before publishing length. Warm-reset retention still
 * depends on the platform firmware; QEMU proof cannot establish MSI retention. */
static inline void paos_capture_flush(const volatile void *p, unsigned long n)
{
 unsigned long a = (unsigned long)p & ~63UL;
 unsigned long end = (unsigned long)p + n;
 for (; a < end; a += 64)
  __asm__ __volatile__("clflush (%0)" : : "r"(a) : "memory");
 __asm__ __volatile__("mfence" : : : "memory");
}
#endif
