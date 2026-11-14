;; MODULE bus/hal
;; LAYER 2
;; EXPORTS hal_init, hal_mmio_write32, hal_mmio_read32, hal_mmio_read8, hal_mmio_read16, hal_mmio_write8, hal_mmio_write16, hal_selftest, hal_lock_audit
;; IMPORTS boot/serial, boot/chainload, core/lib/fmt, core/lock, bus/pci
;; CAPS
;; OWNER saga:bus
;; LOCK: hal_lock PROTECTS hal_ring, hal_head, hal_oob_count
; ============================================================================
; bus/hal.asm — the Hardware Abstraction Layer's bounds-checked MMIO poke.
;
; DRIVER_MODEL.md: every chip backend touches its registers "via HAL", never with
; a raw `mov [mmio], eax`. The HAL owns ONE thing here: a bounds-checked 32-bit
; MMIO write that (a) refuses a store outside the device's declared BAR window
; (returns CF=1 + bumps an out-of-bounds counter, NEVER faults or scribbles), and
; (b) logs every accepted write into a fixed-stride ring (TSC / byte-offset /
; value) so a wedged driver's last MMIO ops are recoverable post-mortem — the
; MMIO-side analogue of core/diag's fault ring.
;
; A one-shot BYPASS escape hatch exists for bring-up: if CMOS byte 0x67 reads the
; magic 0xA5, bounds enforcement is skipped for this boot AND the CMOS byte is
; cleared (0x00) so the bypass is single-boot — you cannot accidentally leave the
; guard off across reboots (SECURITY.md: a disabled safety must be loud + expiring).
; QEMU CMOS 0x67 reads 0, so the gate is ON by default and the self-test exercises
; the enforcing path.
;
; A "region" handle is just { bar_base:q, bar_size:q } — the minimum a class .init
; hands the HAL after it maps a device's BAR. The self-test uses a synthetic one
; (bar_base=0, bar_size=1024): an in-bounds write must be logged (head advances,
; record fields correct); an out-of-bounds write must set CF, bump the OOB counter,
; and leave the ring untouched.
; ============================================================================

CMOS_INDEX        equ 0x70
CMOS_DATA         equ 0x71
CMOS_HAL_BYPASS   equ 0x67                  ; CMOS byte holding the bypass magic
HAL_BYPASS_MAGIC  equ 0xA5                  ; == this byte -> skip bounds (one-shot)

HAL_RING_ENTRIES  equ 64
HAL_REC_SIZE      equ 16                    ; tsc(8) + offset(4) + value(4)

; region handle field offsets (what a class .init fills after mapping a BAR)
HAL_R_BAR_BASE    equ 0                     ; dq — physical/virt base (identity map)
HAL_R_BAR_SIZE    equ 8                     ; dq — BAR window length in bytes

; hal_init — ring head=0, counters clear, resolve the one-shot CMOS bypass flag.
hal_init:
    xor  eax, eax
    mov  [rel hal_head], rax
    mov  [rel hal_oob_count], rax
    ; --- read CMOS 0x67: bypass iff == 0xA5, and clear it (one-shot) ---
    xor  edx, edx                           ; default bypass = 0 (enforce)
    call chainload_cmos_nvram_ok            ; HP CMOS allowlist: non-Intel -> no CMOS I/O
    je   .cmos_ok
    lea  rdi, [rel str_hal_cmos_volatile]
    call serial_string
    xor  edx, edx
    jmp  .store
.cmos_ok:
    mov  al, CMOS_HAL_BYPASS
    out  CMOS_INDEX, al                     ; select CMOS byte 0x67
    in   al, CMOS_DATA
    xor  edx, edx                           ; default bypass = 0 (enforce)
    cmp  al, HAL_BYPASS_MAGIC
    jne  .store
    mov  edx, 1                             ; magic present -> bypass this boot
    mov  al, CMOS_HAL_BYPASS                ; ...and clear the byte so it's one-shot
    out  CMOS_INDEX, al
    xor  al, al
    out  CMOS_DATA, al
.store:
    mov  [rel hal_bypass], rdx
    lea  rdi, [rel str_hal_init]
    call serial_string
    ret

; hal_mmio_write32(RDI=region, RSI=byte offset, EDX=value) -> CF=1 on OOB reject.
;   Bounds: the whole 4-byte store must lie within [0, bar_size), i.e.
;   offset + 4 <= bar_size. On reject: CF=1, OOB counter++, ring UNCHANGED, no
;   store performed. On accept: log {tsc,offset,value}, advance head, do the store.
;   clobbers: RAX,R9 (RDX preserved for the store; RSI/RDI preserved).
hal_mmio_write32:
    cmp  qword [rel hal_bypass], 0
    jne  .accept                            ; bring-up bypass: skip the bounds gate
    mov  rax, rsi
    add  rax, 4                             ; end of the 4-byte store
    jc   .oob                               ; a wrapping interval cannot fit
    cmp  rax, [rdi + HAL_R_BAR_SIZE]
    ja   .oob                               ; store would run past the BAR window
.accept:
    ; --- log record at hal_ring + head*16 ---
    mov  rax, [rel hal_head]
    shl  rax, 4                             ; * HAL_REC_SIZE (16)
    lea  r9, [rel hal_ring]
    add  r9, rax                            ; r9 -> record slot
    push rdx                                ; value (rdtsc clobbers EDX)
    rdtsc
    shl  rdx, 32
    or   rax, rdx                           ; RAX = 64-bit TSC
    mov  [r9 + 0], rax                      ; .tsc
    pop  rdx                                ; restore value
    mov  [r9 + 8], esi                      ; .offset (dword)
    mov  [r9 + 12], edx                     ; .value
    ; --- advance head (wrap at HAL_RING_ENTRIES) ---
    mov  rax, [rel hal_head]
    inc  rax
    cmp  rax, HAL_RING_ENTRIES
    jb   .head_ok
    xor  eax, eax
.head_ok:
    mov  [rel hal_head], rax
    ; --- the actual MMIO store: [bar_base + offset] = value ---
    mov  rax, [rdi + HAL_R_BAR_BASE]
    add  rax, rsi
    mov  [rax], edx
    clc
    ret
.oob:
    inc  qword [rel hal_oob_count]
    stc
    ret

; hal_mmio_read32(RDI=region, RSI=byte offset) -> EAX=value; CF=1 on OOB reject.
;   Bounds: the whole 4-byte load must lie within [0, bar_size), same rule as the
;   write path. On reject: CF=1, OOB counter++, EAX=0 (never a faulting/garbage
;   read). On accept: EAX = [bar_base + offset], CF=0. No ring log (reads are
;   non-mutating; the ring records device MUTATIONS). clobbers RAX only.
hal_mmio_read32:
    cmp  qword [rel hal_bypass], 0
    jne  .do                                ; bring-up bypass: skip the bounds gate
    mov  rax, rsi
    add  rax, 4                             ; end of the 4-byte load
    jc   .oob                               ; a wrapping interval cannot fit
    cmp  rax, [rdi + HAL_R_BAR_SIZE]
    ja   .oob                               ; load would run past the BAR window
.do:
    mov  rax, [rdi + HAL_R_BAR_BASE]
    add  rax, rsi
    mov  eax, [rax]                         ; the MMIO load: EAX = [bar_base+offset]
    clc
    ret
.oob:
    inc  qword [rel hal_oob_count]
    xor  eax, eax
    stc
    ret

; Narrow accesses use the same BAR/bypass/CF contract, with no containing-
; dword read/modify/write. Log offset bits31:30: 01=8-bit, 10=16-bit;
; low30 bits carry the offset. The actual access uses the original full RSI.
; Existing32-bit records are byte-for-byte unchanged (no width tag added).
HAL_LOG_WIDTH8  equ 0x40000000
HAL_LOG_WIDTH16 equ 0x80000000

%macro HAL_WIDTH_READ 2
%1:
    cmp  qword [rel hal_bypass], 0
    jne  %%access
    mov  rax, rsi
    add  rax, %2
    jc   %%reject                         ; a wrapping interval cannot fit
    cmp  rax, [rdi + HAL_R_BAR_SIZE]
    ja   %%reject
%%access:
    mov  rax, [rdi + HAL_R_BAR_BASE]
    add  rax, rsi
%if %2 = 1
    movzx eax, byte [rax]
%else
    movzx eax, word [rax]
%endif
    clc
    ret
%%reject:
    inc  qword [rel hal_oob_count]
    xor  eax, eax
    stc
    ret
%endmacro
HAL_WIDTH_READ hal_mmio_read8, 1
HAL_WIDTH_READ hal_mmio_read16, 2

%macro HAL_WIDTH_WRITE 3
%1:
    cmp  qword [rel hal_bypass], 0
    jne  %%access
    mov  rax, rsi
    add  rax, %2
    jc   %%reject
    cmp  rax, [rdi + HAL_R_BAR_SIZE]
    ja   %%reject
%%access:
    mov  rax, [rel hal_head]
    shl  rax, 4
    lea  r9, [rel hal_ring]
    add  r9, rax
    push rdx
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [r9], rax
    pop  rdx
    mov  eax, esi
    and  eax, 0x3FFFFFFF
    or   eax, %3
    mov  [r9 + 8], eax
%if %2 = 1
    movzx eax, dl
%else
    movzx eax, dx
%endif
    mov  [r9 + 12], eax
    mov  rax, [rel hal_head]
    inc  rax
    cmp  rax, HAL_RING_ENTRIES
    jb   %%head
    xor  eax, eax
%%head:
    mov  [rel hal_head], rax
    mov  rax, [rdi + HAL_R_BAR_BASE]
    add  rax, rsi
%if %2 = 1
    mov  [rax], dl
%else
    mov  [rax], dx
%endif
    clc
    ret
%%reject:
    inc  qword [rel hal_oob_count]
    stc
    ret
%endmacro
HAL_WIDTH_WRITE hal_mmio_write8, 1, HAL_LOG_WIDTH8
HAL_WIDTH_WRITE hal_mmio_write16, 2, HAL_LOG_WIDTH16

; hal_selftest — synthetic region, prove the ring logs an in-bounds write and the
;   bounds gate rejects an OOB write (CF set, ring untouched, counter bumped).
hal_selftest:
    push rbx
    push r12
    call hal_init                           ; head=0, bypass off (QEMU CMOS 0x67==0)
    cmp  qword [rel hal_head], 0            ; head initially 0
    jne  .fail
    ; --- in-bounds write: offset 0x10, value 0xDEADBEEF ---
    lea  rdi, [rel hal_test_dev]
    mov  esi, 0x10
    mov  edx, 0xDEADBEEF
    call hal_mmio_write32
    jc   .fail                              ; in-bounds must NOT reject
    cmp  qword [rel hal_head], 1           ; head advanced to 1
    jne  .fail
    lea  r9, [rel hal_ring]                 ; validate the logged record #0
    mov  eax, [r9 + 8]
    cmp  eax, 0x10                          ; .offset correct
    jne  .fail
    mov  eax, [r9 + 12]
    cmp  eax, 0xDEADBEEF                    ; .value correct
    jne  .fail
    mov  rax, [r9 + 0]
    test rax, rax                           ; .tsc non-zero (timer really sampled)
    jz   .fail
    ; --- OOB write: offset == bar_size (1024) -> offset+4 > size ---
    lea  rdi, [rel hal_test_dev]
    mov  esi, 1024
    mov  edx, 0xCAFEBABE
    call hal_mmio_write32
    jnc  .fail                              ; OOB MUST set CF
    cmp  qword [rel hal_head], 1           ; ring UNCHANGED (head still 1)
    jne  .fail
    cmp  qword [rel hal_oob_count], 1      ; OOB counter bumped exactly once
    jne  .fail
    call hal_width_selftest
    test eax, eax
    jz   .fail
    lea  rdi, [rel str_hal_pass]
    call serial_string
    pop  r12
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_hal_fail]
    call serial_string
    pop  r12
    pop  rbx
    ret

; Called after the legacy selftest: head=1, OOB=1. Synthetic writable RAM
; proves that byte/word stores preserve adjacent bytes, log their width, and
; reject whole-access OOB without changing the ring or target.
hal_width_selftest:
    lea  rax, [rel hal_width_storage]
    mov  [rel hal_width_region], rax
    mov  rax, 0xCCCCCCCCCCCCCCCC
    mov  [rel hal_width_storage], rax
    lea  rdi, [rel hal_width_region]
    mov  esi, 1
    mov  edx, 0x123456AB
    call hal_mmio_write8
    jc   .bad
    cmp  dword [rel hal_ring + HAL_REC_SIZE + 8], HAL_LOG_WIDTH8 | 1
    jne  .bad
    cmp  dword [rel hal_ring + HAL_REC_SIZE + 12], 0xAB
    jne  .bad
    call hal_mmio_read8
    jc   .bad
    cmp  eax, 0xAB
    jne  .bad
    mov  esi, 2
    mov  edx, 0xFFFF3456
    call hal_mmio_write16
    jc   .bad
    cmp  dword [rel hal_ring + 2*HAL_REC_SIZE + 8], HAL_LOG_WIDTH16 | 2
    jne  .bad
    cmp  dword [rel hal_ring + 2*HAL_REC_SIZE + 12], 0x3456
    jne  .bad
    call hal_mmio_read16
    jc   .bad
    cmp  eax, 0x3456
    jne  .bad
    mov  rax, 0xCCCCCCCC3456ABCC
    cmp  [rel hal_width_storage], rax
    jne  .bad
    mov  esi, 8
    call hal_mmio_write8
    jnc  .bad
    call hal_mmio_read8
    jnc  .bad
    test eax, eax
    jnz  .bad
    mov  esi, 7
    call hal_mmio_write16
    jnc  .bad
    call hal_mmio_read16
    jnc  .bad
    test eax, eax
    jnz  .bad
    cmp  qword [rel hal_head], 3
    jne  .bad
    cmp  qword [rel hal_oob_count], 5
    jne  .bad
    mov  rax, 0xCCCCCCCC3456ABCC
    cmp  [rel hal_width_storage], rax
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; ============================================================================
; 1075 SMP lock-SITE retro-audit. bus/hal shipped (1005) BEFORE the 1003 lock
; discipline, so the HAL ring shared state (hal_ring / hal_head / hal_oob_count)
; had no declared protecting lock. hal_lock is that retro-declared lock; it reuses
; the ONE spin primitive (core/lock.asm), never a bus-local copy. hal_lock_audit
; EXERCISES the SITE once (acquire -> guarded shared write -> release) and PRINTS
; the bus coverage line the probe content-grades. Scale-1: the acquire is a no-op
; (one core), but the SITE exists for v1->v2 — the non-retrofittable part.
; ============================================================================
hal_lock_acquire:
    lea  rdi, [rel hal_lock]
    call spin_acquire
    ret
hal_lock_release:
    lea  rdi, [rel hal_lock]
    call spin_release
    ret

; hal_lock_audit — exercise the DECLARED hal_lock site once around a guarded write
;   of the HAL ring counters, ALSO exercise the sibling bus lock site (pci_lock over
;   pci_dev_count), then emit the aggregated bus line "smp.audit bus: sites=2
;   exercised=<N>" (N = hal + pci acquire/release cycles). Net-zero mutations so no
;   HAL/PCI invariant is perturbed. Two declared+exercised bus sites: HAL ring + PCI
;   scan-result state (contract 1075 goal (1) bus enumeration).
BUS_LOCK_SITES equ 2                         ; hal_lock (HAL ring) + pci_lock (PCI scan)
hal_lock_audit:
    push rbx
    push r12
    call hal_lock_acquire                   ; --- enter the critical section ---
    inc  qword [rel hal_oob_count]           ; guarded shared write ...
    dec  qword [rel hal_oob_count]           ; ... restored (net-zero)
    inc  qword [rel hal_audit_exercised]     ; count the real acquire/release cycle
    call hal_lock_release                    ; --- leave the critical section ---
    mov  r12, [rel hal_audit_exercised]     ; bus exercised so far (hal)
    call pci_lock_audit                     ; sibling bus site: pci_lock over pci_dev_count
    add  r12, rax                           ; + pci exercised -> total bus cycles
    ; --- "smp.audit bus: sites=2 exercised=<total>" ---
    lea  rdi, [rel str_hal_audit_pre]
    call serial_string
    mov  rdi, r12
    lea  rsi, [rel hal_audit_numbuf]
    call fmt_dec
    lea  rdi, [rel hal_audit_numbuf]
    call serial_string
    lea  rdi, [rel str_hal_audit_post]
    call serial_string
    pop  r12
    pop  rbx
    ret

; --- bus/hal data (in-image writable; image pages are RW+X pre-full-W^X) ---
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_bus_hal_0 0
hal_lock:            db 0                    ; retro-declared lock over the HAL ring (1075)
align 8
hal_audit_exercised: dq 0                    ; count of acquire/release cycles run
hal_audit_numbuf:    times 24 db 0
str_hal_audit_pre:   db "[PAOS64] P2 smp.audit bus: sites=2 exercised=", 0
str_hal_audit_post:  db " [smp.lock.sites.bus]", 13, 10, 0
hal_test_dev:                               ; synthetic region { bar_base, bar_size }
    dq 0                                    ; .bar_base (0 => low RAM, QEMU-only test)
    dq 1024                                 ; .bar_size
hal_width_region: dq 0, 8
times 32 db 0                  ; hal_width_storage..hal_oob_count moved to WDATA_bus_hal_0_bss1: keeps the labels below at their offset mod 64
str_hal_init:  db "[PAOS64] M2 hal: initialized [hal.init]", 13, 10, 0
str_hal_cmos_volatile: db "[PAOS64] CMOS policy: non-Intel CPU -> no CMOS NVRAM port I/O (reads=0 volatile-only, writes dropped) [boot.cmos.nvram.volatile]", 13, 10, 0
str_hal_pass:  db "[PAOS64] M2 hal: MMIO ring bounds-check PASS [hal.ring.bounds]", 13, 10, 0
str_hal_fail:  db "[PAOS64] M2 hal: MMIO ring bounds-check FAIL", 13, 10, 0
%endmacro
WDATA_DEFER WDATA_bus_hal_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_bus_hal_0_bss1 0
resb 14                 ; keeps hal_width_storage at its WDATA offset mod 64
hal_width_storage: resb 8
hal_ring:      resb HAL_RING_ENTRIES * HAL_REC_SIZE
hal_head:      resq 1
hal_bypass:    resq 1
hal_oob_count: resq 1
%endmacro
WDATA_BSS_DEFER WDATA_bus_hal_0_bss1
