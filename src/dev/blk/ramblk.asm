;; MODULE dev/blk/ramblk
;; LAYER 3
;; EXPORTS ramblk_create, ramblk_create_4kn, ramblk_optional_create, ramblk_optional_dev, ramblk_wedge
;; IMPORTS fs/blockdev, core/heap
;; CAPS
;; OWNER saga:storage
; ============================================================================
; dev/blk/ramblk.asm — the FAKE/RAM block backend, and by charter the REFERENCE
; implementation of the blk_ops vtable (DRIVER_MODEL §7). BOTH (a) the QEMU-no-
; hardware regression target — always present, zero silicon — AND (b) the ops-
; contract documentation nvme/ahci match byte-for-byte. Write the fake first; it
; defines the semantics (known_trap: every backend's ops signature matches this).
;
; It backs a small RAM region (kmalloc'd), pre-filled at create with a
; deterministic pattern so a read returns KNOWN bytes (content-grade, not zeros).
; A .wedged flag models a hung ring: while set, every op returns -1 (degrade,
; never hang — DRIVER_MODEL §1). identify() clears it — that IS the idempotent
; re-runnable init the class core's reinit contract drives.
;
; The `call blk_register` is the ONE sanctioned L3->L4 upward edge (DRIVER_MODEL
; §5) — modlint whitelists it for dev/blk backends.
; ============================================================================

RAMBLK_512_NSEC   equ 64                    ; 32 KiB backing store
RAMBLK_512_SECSZ  equ 512
RAMBLK_4KN_NSEC   equ 16                    ; 64 KiB backing store
RAMBLK_4KN_SECSZ  equ 4096
RAMBLK_PHYS_BYTES equ 4096
RAMBLK_MAX_XFER   equ 8

struc ramblk_priv
  .buf:     resq 1                          ; -> kmalloc'd backing store
  .wedged:  resd 1                          ; 1 = hung ring simulated
  .nsec:    resd 1                          ; sector count
  .sector_bytes: resd 1                     ; instance geometry (512 or 4096)
  .seed:    resd 1                          ; deterministic image discriminator
  ; --- the reinit contract's declared state partition (1065, RESILIENCE §3) ---
  ;   ring_ctr is RESETTABLE runtime scratch: it counts ops and the idempotent init
  ;   (identify) WIPES it to 0 — so a reinit visibly resets it (proves not a no-op).
  ;   canary is PRESERVED config/identity: identify does NOT touch it, so a marked
  ;   value survives a live restart byte-for-byte. This partition IS the seam.
  .ring_ctr: resq 1                         ; RESETTABLE (wiped by identify/reinit)
  .canary:   resb 48                        ; PRESERVED (survives identify/reinit)
endstruc

; ramblk_create() -> RAX = REG_OK/REG_REJECT. Builds the vtable at RUNTIME (lea->
;   mov: pointers must be runtime VAs; a static `dq ramblk_read` bakes the org-0
;   RVA — the PE ImageBase is not applied to baked dq symbols), fills the uniform
;   struct dev, allocates + pattern-fills the backing store, and registers.
ramblk_build_ops:
    push rbx
    ; --- build the blk_ops vtable in place (runtime VAs) -------------------
    lea  rbx, [rel ramblk_ops]
    lea  rax, [rel ramblk_identify]
    mov  [rbx + blk_ops.identify], rax
    lea  rax, [rel ramblk_read]
    mov  [rbx + blk_ops.read], rax
    lea  rax, [rel ramblk_write]
    mov  [rbx + blk_ops.write], rax
    lea  rax, [rel ramblk_flush]
    mov  [rbx + blk_ops.flush], rax
    pop  rbx
    ret

; Build one independent reference medium.  RDI=dev, RSI=info, RDX=priv,
; RCX=name, R8D=logical bytes, R9D=sector count, R10D=pattern seed, R11D=priority.
ramblk_create_one:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  ebx, r8d
    mov  ebp, r9d
    push r10
    push r11
    push 0                                ; retain SysV call alignment

    ; --- allocate + pattern-fill the backing store (pattern A) -------------
    mov  eax, ebx
    mul  ebp
    test edx, edx
    jnz  .reject
    mov  rdi, rax
    call kmalloc                            ; RAX = buffer
    test rax, rax
    jz   .reject
    mov  [r14 + ramblk_priv.buf], rax
    mov  dword [r14 + ramblk_priv.wedged], 0
    mov  dword [r14 + ramblk_priv.nsec], ebp
    mov  dword [r14 + ramblk_priv.sector_bytes], ebx
    mov  r10, [rsp + 16]
    mov  dword [r14 + ramblk_priv.seed], r10d
    mov  qword [r14 + ramblk_priv.ring_ctr], 0
    mov  byte  [r14 + ramblk_priv.canary], 0

    ; --- fill blk_info -----------------------------------------------------
    mov  [r13 + blk_info.name], r15
    mov  dword [r13 + blk_info.sector_size], ebx
    mov  eax, ebp
    dec  rax
    mov  qword [r13 + blk_info.lba_max], rax
    mov  byte  [r13 + blk_info.dma_mask], 64
    mov  byte  [r13 + blk_info.removable], 0
    mov  dword [r13 + blk_info.flags], 0
    xor  eax, eax
    cmp  ebx, RAMBLK_4KN_SECSZ
    sete al
    mov  dword [r13 + blk_info.unit], eax     ; diagnostic only; never selection policy
    mov  dword [r13 + blk_info.logical_sector_bytes], ebx
    mov  dword [r13 + blk_info.physical_sector_bytes], RAMBLK_PHYS_BYTES
    mov  dword [r13 + blk_info.physical_alignment_bytes], 0
    mov  dword [r13 + blk_info.max_transfer_sectors], RAMBLK_MAX_XFER
    mov  qword [r13 + blk_info.capabilities], BLKCAP_ALL_IO
    mov  qword [r13 + blk_info.media_generation], 0 ; class assigns fresh at registration

    ; --- fill the uniform struct dev header --------------------------------
    lea  rax, [rel ramblk_ops]
    mov  [r12 + dev.ops], rax
    mov  [r12 + dev.info], r13
    mov  [r12 + dev.priv], r14
    mov  eax, [rsp + 8]
    mov  dword [r12 + dev.prio], eax
    mov  dword [r12 + dev.health], HEALTH_OK
    mov  dword [r12 + dev.class], CLASS_BLOCK
    mov  dword [r12 + dev.flags], 0
    mov  qword [r12 + dev.next], 0
    mov  [r12 + dev.name], r15

    mov  rdi, r12
    call ramblk_fill_pattern_a

    ; --- register (the sanctioned L3->L4 upward edge) ----------------------
    mov  rdi, r12
    call blk_register
    jmp  .out
.reject:
    mov  eax, REG_REJECT
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

ramblk_create:
    sub  rsp, 8
    call ramblk_build_ops
    add  rsp, 8
    lea  rdi, [rel ramblk_dev]
    lea  rsi, [rel ramblk_info]
    lea  rdx, [rel ramblk_privd]
    lea  rcx, [rel str_ramblk_name]
    mov  r8d, RAMBLK_512_SECSZ
    mov  r9d, RAMBLK_512_NSEC
    mov  r10d, 0x5A
    mov  r11d, PRIO_DOMAIN
    jmp  ramblk_create_one

ramblk_create_4kn:
    sub  rsp, 8
    call ramblk_build_ops
    add  rsp, 8
    lea  rdi, [rel ramblk_4kn_dev]
    lea  rsi, [rel ramblk_4kn_info]
    lea  rdx, [rel ramblk_4kn_privd]
    lea  rcx, [rel str_ramblk_4kn_name]
    mov  r8d, RAMBLK_4KN_SECSZ
    mov  r9d, RAMBLK_4KN_NSEC
    mov  r10d, 0xA7
    mov  r11d, PRIO_DOMAIN
    jmp  ramblk_create_one

; Dedicated disposable optional medium. It is a RAM reference device, never
; physical storage or the filesystem's ledger. Lowest priority leaves ordinary
; storage selection unchanged. Created once by the authenticated runtime probe.
ramblk_optional_create:
    sub  rsp, 8
    call ramblk_build_ops
    add  rsp, 8
    lea  rdi, [rel ramblk_optional_dev]
    lea  rsi, [rel ramblk_optional_info]
    lea  rdx, [rel ramblk_optional_priv]
    lea  rcx, [rel str_ramblk_optional_name]
    mov  r8d, RAMBLK_512_SECSZ
    mov  r9d, RAMBLK_512_NSEC
    mov  r10d, 0x39
    xor  r11d, r11d
    jmp  ramblk_create_one

; ramblk_fill_pattern_a(RDI=dev) — backing store <-
; byte(S,O)=(S*131 + O*7 + instance_seed)&0xff.  The 512e seed preserves the
; shipped content KAT while the 4Kn seed makes the witnesses discriminating.
ramblk_fill_pattern_a:
    mov  r11, [rdi + dev.priv]
    mov  r8, [r11 + ramblk_priv.buf]
    xor  r9, r9                             ; S
.sec:
    mov  eax, [r11 + ramblk_priv.nsec]
    cmp  r9, rax
    jae  .done
    xor  r10, r10                           ; O
.byte:
    mov  eax, [r11 + ramblk_priv.sector_bytes]
    cmp  r10, rax
    jae  .nextsec
    mov  rax, r9
    imul rax, rax, 131
    mov  rcx, r10
    imul rcx, rcx, 7
    add  rax, rcx
    mov  ecx, [r11 + ramblk_priv.seed]
    add  rax, rcx
    mov  rcx, r9
    mov  edx, [r11 + ramblk_priv.sector_bytes]
    imul rcx, rdx
    add  rcx, r10                           ; linear offset = S*512 + O
    mov  [r8 + rcx], al
    inc  r10
    jmp  .byte
.nextsec:
    inc  r9
    jmp  .sec
.done:
    ret

; --- blk_ops implementations (the reference semantics) -----------------------
; identify(self) -> 0. Idempotent (re-runnable) init: clears the wedge. This is
;   the re-init primitive the class core's reinit contract calls.
ramblk_identify:
    mov  rax, [rdi + dev.priv]
    mov  dword [rax + ramblk_priv.wedged], 0
    ; idempotent init WIPES the resettable runtime state (the reinit contract's
    ; "resettable" partition) but leaves the PRESERVED canary untouched (1065).
    mov  qword [rax + ramblk_priv.ring_ctr], 0
    xor  eax, eax
    ret

; read(self, RSI=lba, RDX=count, RCX=buf) -> 0/-1. Degrades to -1 while wedged.
ramblk_read:
    mov  r8, [rdi + dev.priv]
    cmp  dword [r8 + ramblk_priv.wedged], 0
    jne  .wedged
    ; bounds: lba + count <= nsec
    mov  rax, rsi
    add  rax, rdx
    jc   .oob
    mov  r9d, dword [r8 + ramblk_priv.nsec]
    cmp  rax, r9
    ja   .oob
    ; src = buf_base + lba*logical ; nbytes = count*logical
    mov  r10d, [r8 + ramblk_priv.sector_bytes]
    mov  rax, rsi
    imul rax, r10
    add  rax, [r8 + ramblk_priv.buf]        ; rax = src
    mov  r9, rdx
    imul r9, r10                            ; r9 = nbytes
    xor  r11, r11
.cp:
    cmp  r11, r9
    jae  .ok
    mov  r10b, [rax + r11]
    mov  [rcx + r11], r10b
    inc  r11
    jmp  .cp
.ok:
    inc  qword [r8 + ramblk_priv.ring_ctr]  ; runtime activity -> resettable state (reinit wipes)
    xor  eax, eax
    ret
.wedged:
.oob:
    mov  eax, -1
    ret

; write(self, RSI=lba, RDX=count, RCX=buf) -> 0/-1. Degrades to -1 while wedged.
ramblk_write:
    mov  r8, [rdi + dev.priv]
    cmp  dword [r8 + ramblk_priv.wedged], 0
    jne  .wedged
    mov  rax, rsi
    add  rax, rdx
    jc   .oob
    mov  r9d, dword [r8 + ramblk_priv.nsec]
    cmp  rax, r9
    ja   .oob
    mov  r10d, [r8 + ramblk_priv.sector_bytes]
    mov  rax, rsi
    imul rax, r10
    add  rax, [r8 + ramblk_priv.buf]        ; rax = dst
    mov  r9, rdx
    imul r9, r10
    xor  r11, r11
.cp:
    cmp  r11, r9
    jae  .ok
    mov  r10b, [rcx + r11]
    mov  [rax + r11], r10b
    inc  r11
    jmp  .cp
.ok:
    inc  qword [r8 + ramblk_priv.ring_ctr]  ; runtime activity -> resettable state (reinit wipes)
    xor  eax, eax
    ret
.wedged:
.oob:
    mov  eax, -1
    ret

; flush(self) -> 0/-1. A RAM store has nothing to flush, but must honour the
;   wedge (a flush on a hung device fails) — that models FUA firing on real HW.
ramblk_flush:
    mov  r8, [rdi + dev.priv]
    cmp  dword [r8 + ramblk_priv.wedged], 0
    jne  .wedged
    xor  eax, eax
    ret
.wedged:
    mov  eax, -1
    ret

; ramblk_wedge(self) -> 0. Test hook: simulate a hung ring (all ops -> -1 until
;   identify()/reinit clears it). Not a vtable op — the selftest calls it directly.
ramblk_wedge:
    mov  rax, [rdi + dev.priv]
    mov  dword [rax + ramblk_priv.wedged], 1
    xor  eax, eax
    ret

; --- ramblk data (in-image writable; migrates to BSS under full W^X) ---------
ramblk_dev:     times dev_size db 0
ramblk_ops:     times blk_ops_size db 0
ramblk_info:    times blk_info_size db 0
ramblk_privd:   times ramblk_priv_size db 0
ramblk_4kn_dev:   times dev_size db 0
ramblk_4kn_info:  times blk_info_size db 0
ramblk_4kn_privd: times ramblk_priv_size db 0
ramblk_optional_dev: times dev_size db 0
ramblk_optional_info: times blk_info_size db 0
ramblk_optional_priv: times ramblk_priv_size db 0
str_ramblk_optional_name: db "optblk", 0
str_ramblk_name:     db "ramblk", 0
str_ramblk_4kn_name: db "ledger", 0
