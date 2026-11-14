// SPDX-License-Identifier: GPL-2.0
/* Isolated opt-in diagnostic boot console. Existing efifb/UART stay selected. */
#include <linux/console.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/processor.h>
#include <asm/cpufeature.h>
#include "paos-ram-capture-wire.h"

static void *paos_ram_mapping;
static bool paos_ram_active;
static bool paos_ram_mapping_done;
static bool paos_ram_late_hang;

/* 4KiB header plus 64KiB trace fit separate early fixmap slots. Never map
 * the entire 2MiB capture using early_memremap.
 * Like EFI earlycon, the retained writer intentionally references init-only
 * mapping helpers. The early initcall below sets mapping_done on both success
 * and failure: subsequent writes use the permanent map or return before those
 * helpers, so no early mapping call can survive init-memory reclamation. */
static __ref void paos_ram_write(struct console *con, const char *s, unsigned int n)
{
 volatile struct paos_capture_trace *t;
 unsigned int pos, len;
 if (!paos_ram_active || (paos_ram_mapping_done && !paos_ram_mapping))
  return;
 t = paos_ram_mapping ? paos_ram_mapping :
  early_memremap(PAOS_CAPTURE_BASE + PAOS_CAPTURE_HEADER_BYTES, PAOS_CAPTURE_TRACE_BYTES);
 if (!t)
  return;
 if (!paos_trace_valid(t))
  goto out;
 pos = t->written;
 len = min(n, PAOS_CAPTURE_CAPACITY - pos);
 if (len) {
  memcpy((void *)t + sizeof(*t) + pos, s, len);
  paos_capture_flush((void *)t + sizeof(*t) + pos, len);
  t->written = pos + len;
  t->phase = 10; /* native early bootconsole writer reached */
  paos_capture_flush(t, sizeof(*t));
 }
out:
 if (!paos_ram_mapping)
  early_memunmap((void *)t, PAOS_CAPTURE_TRACE_BYTES);
}

static struct console paos_ram_console = {
 .name = "paosram", .write = paos_ram_write,
 .flags = CON_PRINTBUFFER | CON_BOOT, .index = -1,
};
static int __init paos_ram_setup(char *s)
{
 volatile struct paos_capture_header *h;
 volatile struct paos_capture_trace *t;
 if (!s || strcmp(s, "1") || paos_ram_active || !boot_cpu_has(X86_FEATURE_CLFLUSH))
  return 0;
 h = early_memremap(PAOS_CAPTURE_BASE, 4096);
 if (!h)
  return 0;
 paos_ram_active = paos_capture_valid(h);
 early_memunmap((void *)h, 4096);
 if (!paos_ram_active)
  return 0;
 t = early_memremap(PAOS_CAPTURE_BASE + PAOS_CAPTURE_HEADER_BYTES, PAOS_CAPTURE_TRACE_BYTES);
 paos_ram_active = t && paos_trace_valid(t);
 if (t)
  early_memunmap((void *)t, PAOS_CAPTURE_TRACE_BYTES);
 if (!paos_ram_active)
  return 0;
 register_console(&paos_ram_console);
 pr_emerg("PAOS_RAM_CAPTURE_NATIVE early-param nonce=%016llx\n", PAOS_RAM_CAPTURE_NONCE);
 return 0;
}
early_param("paos_ram_capture", paos_ram_setup);

static int __init paos_ram_hang(char *s)
{
 if (!s || !paos_ram_active)
  return 0;
 if (!strcmp(s, "late")) {
  paos_ram_late_hang = true;
  return 0;
 }
 if (strcmp(s, "early"))
  return 0;
 pr_emerg("PAOS_RAM_CAPTURE_FORCED_HANG nonce=%016llx\n", PAOS_RAM_CAPTURE_NONCE);
 /* Explicit signed command-line control, never panic/reboot or QMP reset.
  * The chipset watchdog must independently reset this CPU. */
 local_irq_disable();
 for (;;)
  cpu_relax();
}
early_param("paos_ram_hang", paos_ram_hang);

static int __init paos_ram_remap(void)
{
 if (paos_ram_active && console_is_registered(&paos_ram_console))
  paos_ram_mapping = memremap(PAOS_CAPTURE_BASE + PAOS_CAPTURE_HEADER_BYTES, PAOS_CAPTURE_TRACE_BYTES, MEMREMAP_WB);
 paos_ram_mapping_done = true;
 return 0; /* Capture failure never changes boot or claims a log. */
}
early_initcall(paos_ram_remap);

static int __init paos_ram_hang_after_pstore(void)
{
 if (!paos_ram_late_hang)
  return 0;
 pr_emerg("PAOS_RAM_CAPTURE_FORCED_HANG late nonce=%016llx\n", PAOS_RAM_CAPTURE_NONCE);
 local_irq_disable();
 for (;;)
  cpu_relax();
}
late_initcall(paos_ram_hang_after_pstore);
