/* SPDX-License-Identifier: GPL-2.0 */
/* Included after efistub.h; memory-only, no firmware writes or allocations. */
#include "paos-ram-capture-wire.h"
static volatile struct paos_capture_header *paos_capture_efi;
static void paos_capture_stub_init(void)
{
 efi_guid_t guid = EFI_GUID(0x9f8346e1, 0x72b3, 0x4c91,
    0x9f, 0x6a, 0x70, 0xae, 0xb1, 0x24, 0x39, 0x91);
 void *table;
 unsigned int a = 1, b, c, d;
 if (!efi_is_native())
  return;
 __asm__ __volatile__("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
 if (!(d & (1U << 19))) /* CLFLUSH before any use */
  return;
 table = get_efi_config_table(guid);
 /* Manager installs this table only after reserving the exact range. Never
  * read arbitrary physical RAM just because a kernel build is diagnostic. */
 if ((unsigned long)table != PAOS_CAPTURE_BASE)
  return;
 if (paos_capture_valid(table)) {
  volatile struct paos_capture_trace *t = table + PAOS_CAPTURE_HEADER_BYTES;
  /* Manager clears the region once before this boot; initialize only the
   * separate kernel-owned trace, never Manager state or a persisted pointer. */
  if (t->magic || t->nonce || t->written || t->phase || t->inverse ||
      t->bytes || t->flags || t->reserved)
   return;
  t->nonce = PAOS_RAM_CAPTURE_NONCE;
  t->inverse = ~PAOS_RAM_CAPTURE_NONCE;
  t->bytes = PAOS_CAPTURE_TRACE_BYTES;
  t->magic = PAOS_CAPTURE_TRACE_MAGIC;
  paos_capture_flush(t, sizeof(*t));
  paos_capture_efi = table;
 }
}
static void paos_capture_stub_write(const char *s)
{
 volatile struct paos_capture_header *h = paos_capture_efi;
 volatile struct paos_capture_trace *t;
 unsigned int start, n;
 volatile unsigned char *dst;
 if (!h || !paos_capture_valid(h))
  return;
 t = (volatile void *)h + PAOS_CAPTURE_HEADER_BYTES;
 if (!paos_trace_valid(t))
  return;
 start = t->written;
 n = 0;
 dst = (volatile unsigned char *)t + sizeof(*t);
 while (s[n] && n < PAOS_CAPTURE_CAPACITY - start) {
  dst[start + n] = s[n];
  n++;
 }
 if (!n)
  return;
 paos_capture_flush(dst + start, n);
 t->written = start + n;
 paos_capture_flush(t, sizeof(*t));
}
static void paos_capture_stub_phase(unsigned long long phase, const char *s)
{
 volatile struct paos_capture_trace *t;
 if (!paos_capture_efi)
  return;
 paos_capture_stub_write(s);
 t = (volatile void *)paos_capture_efi + PAOS_CAPTURE_HEADER_BYTES;
 if (paos_trace_valid(t)) {
  t->phase = phase;
  paos_capture_flush(t, sizeof(*t));
 }
}
