;; MODULE boot/gdt
;; LAYER 0
;; EXPORTS gdt_init, gdt_percpu_prepare, gdt_percpu_load, gdt_percpu_ready
;; IMPORTS boot/serial
;; CAPS
;; OWNER saga:boot
; ============================================================================

GDT_PERCPU_MAX        equ 8
GDT_PERCPU_TABLE_SIZE equ 40              ; null + code + data + 16-byte TSS
GDT_PERCPU_GDTR_SIZE  equ 16              ; 10 used, padded for dense indexing
GDT_PERCPU_TSS_SIZE   equ 104
GDT_PERCPU_IST_SIZE   equ 4096
; boot/gdt.asm — load PaOS's own GDT (stop depending on the firmware GDT).
;
; Ported from the old tree's proven gdt_load (MIGRATION.md §1) MINUS the TSS:
; the M1 scope is a minimal 64-bit GDT — null, kernel code 0x08, kernel data
; 0x10. (The TSS descriptor + ltr come back with the ring-3 / IST work; not M1.)
;
; WHY now: core/idt.asm builds gates against the CURRENT CS (firmware's), and the
; firmware GDT only *happens* to persist across ExitBootServices + our CR3 load.
; Owning the GDT removes that dependency. gdt_init runs AFTER paging and BEFORE
; idt_init, so the IDT's selectors reference OUR code segment (0x08), not the
; firmware's.
;
; Descriptors (long-mode):
;   0x08 code: Access 0x9A (P,DPL0,S,Exec/Read), Flags 0xA (G=1,L=1,D=0)
;   0x10 data: Access 0x92 (P,DPL0,S,Read/Write), Flags 0xC (G=1,D=1,L=0)
; Base/limit are ignored for 64-bit code/data; set conventionally (base 0, our
; identity map). The GDT base in the lgdt pointer is filled at RUNTIME via lea
; (load-VA safe — never `dq gdt_start`, the absolute-symbol hazard, MODULES §3.2).
; ============================================================================

; gdt_init — lgdt our table, far-reload CS to 0x08, load SS/DS/ES/FS/GS with
;   0x10, then verify CS==0x08 (and SS==0x10) before emitting the marker.
gdt_init:
    push rax
    push rbx

    ; --- set the lgdt pointer base at runtime (lea, not dq — load-VA safe) ---
    lea  rax, [rel gdt_start]
    mov  [rel gdt_pointer + 2], rax
    lgdt [rel gdt_pointer]

    ; --- load the data/stack segments with the kernel data selector 0x10 ---
    mov  ax, 0x10
    mov  ds, ax
    mov  es, ax
    mov  ss, ax
    mov  fs, ax
    mov  gs, ax

    ; --- far-reload CS with the kernel code selector 0x08 via a retfq trampoline
    ;     (push selector + target RIP, far return pops RIP then CS) ---
    lea  rax, [rel .reload_cs]
    push qword 0x08
    push rax
    retfq

.reload_cs:
    ; --- acceptance: read CS back and confirm it is the new code selector ---
    mov  ax, cs
    cmp  ax, 0x08
    jne  .fail
    mov  bx, ss
    cmp  bx, 0x10
    jne  .fail
    lea  rdi, [rel str_gdt_ok]
    call serial_string

    ; --- install the host TSS: fill the descriptor base at RUNTIME (load-VA
    ;     safe — scatter the 64-bit base across the split fields), then ltr.
    ;     A valid non-zero host TR is MANDATORY VMCS host-state for VMLAUNCH
    ;     (1095) and the landing pad for IST/#DF fault stacks. If the descriptor
    ;     is malformed, ltr #GPs here and the boot fails loudly (QEMU-provable).
    lea  rax, [rel tss_struct]           ; rax = TSS base VA
    lea  rbx, [rel tss_desc]             ; rbx = &descriptor
    mov  [rbx + 2], ax                   ; Base 15:0
    shr  rax, 16
    mov  [rbx + 4], al                   ; Base 23:16
    mov  [rbx + 7], ah                   ; Base 31:24
    shr  rax, 16
    mov  [rbx + 8], eax                  ; Base 63:32

    ; --- 9702: fill IST1 with a dedicated #DF stack BEFORE ltr, so a double
    ;     fault whose trigger was "the current stack is unusable" (the class
    ;     that otherwise TRIPLE-faults — the CPU can't even push the #DF frame)
    ;     lands on a known-good stack. Runtime lea (never dq — MODULES §3.2).
    ;     core/idt.asm points IDT gate 8 at IST1. ---
    xor  edi, edi
    call percpu_stack_kernel_top
    mov  [rel tss_struct + 4], rax       ; bootstrap RSP0 already uses CPU0 owner
    call percpu_stack_ist_top
    mov  [rel tss_struct + 0x24], rax    ; guarded CPU0 IST before private GDT

    mov  ax, 0x18
    ltr  ax                              ; TR = 0x18 (busy bit set by CPU)
    lea  rdi, [rel str_tss_ok]
    call serial_string

    pop  rbx
    pop  rax
    ret
.fail:
    lea  rdi, [rel str_gdt_fail]
    call serial_string
    pop  rbx
    pop  rax
    ret

; gdt_percpu_prepare(EDI=logical CPU, RSI=private kernel stack top) -> CF
; Build a private GDT/TSS/IST image.  Every embedded address is written from a
; runtime LEA; no static dq-symbol pointer survives relocation.
gdt_percpu_prepare:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13, rsi
    cmp  r12d, GDT_PERCPU_MAX
    jae  .bad

    mov  eax, r12d
    imul rax, GDT_PERCPU_TABLE_SIZE
    lea  rbx, [rel gdt_percpu_tables]
    add  rbx, rax
    mov  r14, rbx
    lea  rsi, [rel gdt_start]
    mov  rdi, rbx
    mov  ecx, 24                         ; null/code/data descriptors
    cld
    rep  movsb
    xor  eax, eax
    mov  ecx, 16
    rep  stosb                           ; clear private TSS descriptor

    mov  eax, r12d
    imul rax, GDT_PERCPU_TSS_SIZE
    lea  rbx, [rel gdt_percpu_tss]
    add  rbx, rax                        ; RBX = private TSS
    mov  rdi, rbx
    xor  eax, eax
    mov  ecx, GDT_PERCPU_TSS_SIZE
    rep  stosb
    mov  [rbx + 4], r13                  ; TSS.RSP0
    mov  edi, r12d
    call percpu_stack_ist_top
    mov  rdx, rax                        ; private page-backed guarded IST1
    mov  [rbx + 0x24], rdx               ; TSS.IST1

    lea  rdi, [r14 + 24]
    mov  word [rdi], 0x0067
    mov  rax, rbx
    mov  [rdi + 2], ax
    shr  rax, 16
    mov  [rdi + 4], al
    mov  byte [rdi + 5], 0x89            ; available 64-bit TSS
    mov  byte [rdi + 6], 0
    mov  [rdi + 7], ah
    shr  rax, 16
    mov  [rdi + 8], eax
    mov  dword [rdi + 12], 0

    mov  eax, r12d
    imul rax, GDT_PERCPU_GDTR_SIZE
    lea  rdi, [rel gdt_percpu_gdtr]
    add  rdi, rax
    mov  word [rdi], GDT_PERCPU_TABLE_SIZE - 1
    mov  [rdi + 2], r14
    lea  rax, [rel gdt_percpu_ready]
    mov  byte [rax + r12], 7              ; stack + TSS + IST prepared
    clc
    jmp  .out
.bad:
    stc
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; gdt_percpu_load(EDI=logical CPU) -> CF.  The caller is already executing on
; that CPU's private stack.  Each CPU loads a distinct descriptor, so the TSS
; busy bit and IST state can never alias another processor.
gdt_percpu_load:
    cmp  edi, GDT_PERCPU_MAX
    jae  .bad
    mov  eax, edi
    imul rax, GDT_PERCPU_GDTR_SIZE
    lea  rdx, [rel gdt_percpu_gdtr]
    add  rdx, rax
    lgdt [rdx]
    push qword 0x08
    lea  rax, [rel .cs_loaded]
    push rax
    retfq
.cs_loaded:
    mov  ax, 0x10
    mov  ds, ax
    mov  es, ax
    mov  ss, ax
    mov  fs, ax
    mov  gs, ax
    mov  ax, 0x18
    ltr  ax
    clc
    ret
.bad:
    stc
    ret

; --- GDT table (static descriptors; base 0 = our identity map) ---
align 16
gdt_start:
    dq 0x0000000000000000               ; 0x00 null descriptor

    ; 0x08 kernel code (long mode): Limit=0xFFFFF, Access=0x9A, Flags=0xA
    dw 0xFFFF                            ; Limit 15:0
    dw 0x0000                            ; Base 15:0
    db 0x00                             ; Base 23:16
    db 0x9A                             ; Access: P=1 DPL=0 S=1 Type=Exec/Read
    db 0xAF                             ; Flags=0xA (G=1 L=1 D=0) | Limit 19:16=0xF
    db 0x00                             ; Base 31:24

    ; 0x10 kernel data: Limit=0xFFFFF, Access=0x92, Flags=0xC
    dw 0xFFFF                            ; Limit 15:0
    dw 0x0000                            ; Base 15:0
    db 0x00                             ; Base 23:16
    db 0x92                             ; Access: P=1 DPL=0 S=1 Type=Read/Write
    db 0xCF                             ; Flags=0xC (G=1 D=1 L=0) | Limit 19:16=0xF
    db 0x00                             ; Base 31:24

    ; 0x18 host TSS (64-bit, 16-byte system descriptor). Base is filled at
    ; RUNTIME in gdt_init via lea (never `dq tss_struct` — absolute-symbol
    ; hazard, MODULES §3.2). Limit = sizeof(TSS)-1 = 0x67 (104 bytes).
tss_desc:
    dw 0x0067                           ; Limit 15:0 (104 - 1)
    dw 0x0000                            ; Base 15:0  (runtime)
    db 0x00                             ; Base 23:16 (runtime)
    db 0x89                             ; Access: P=1 DPL=0 Type=0x9 (avail 64-bit TSS)
    db 0x00                             ; Flags G=0 | Limit 19:16=0
    db 0x00                             ; Base 31:24 (runtime)
    dd 0x00000000                        ; Base 63:32 (runtime)
    dd 0x00000000                        ; reserved (must be 0)
gdt_end:

; lgdt pointer (10 bytes: 2-byte limit + 8-byte base; base filled at runtime)
gdt_pointer:
    dw gdt_end - gdt_start - 1          ; Limit (size - 1)
    dq 0                                ; Base (filled at runtime by gdt_init)

str_gdt_ok:   db "[PAOS64] M1 gdt: own GDT loaded, CS+SS reloaded", 13, 10, 0
str_gdt_fail: db "[PAOS64] M1 gdt: FAILED (CS/SS not our selectors)", 13, 10, 0
str_tss_ok:   db "[PAOS64] M1 gdt: TSS descriptor installed + TR loaded (0x18) [m1.tss.loaded]", 13, 10, 0

; --- host Task-State Segment (64-bit): 104 bytes, zero-initialised. Inert
;     until ring-3/IST/#DF and the hypervisor guest launch (1095) use it;
;     RSP0/IST fields are filled by those features. Referenced only via the
;     runtime-filled tss_desc base above. ---
align 16
tss_struct:
    times 104 db 0                       ; sizeof(64-bit TSS) = 0x68 (limit=0x67)

; CPU0's guarded arena IST is used from the first host TR load. The later
; private per-CPU GDT changes its descriptor owner, never the stack lifetime.
align 16
gdt_percpu_tables: times GDT_PERCPU_MAX * GDT_PERCPU_TABLE_SIZE db 0
align 16
gdt_percpu_gdtr:   times GDT_PERCPU_MAX * GDT_PERCPU_GDTR_SIZE db 0
align 16
gdt_percpu_tss:    times GDT_PERCPU_MAX * GDT_PERCPU_TSS_SIZE db 0
align 16
gdt_percpu_ready:  times GDT_PERCPU_MAX db 0
