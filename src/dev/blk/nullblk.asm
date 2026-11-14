;; MODULE dev/blk/nullblk
;; LAYER 3
;; EXPORTS nullblk_create
;; IMPORTS fs/blockdev, boot/serial
;; CAPS
;; OWNER saga:storage
; ============================================================================
; dev/blk/nullblk.asm — the DEGENERATE-Nth block backend (1027, §9.4 seam proof).
; A pure discard/zero device that registers behind the SAME blk_ops vtable via the
; SAME blk_register upward edge — with ZERO edit to the class core (fs/blockdev.asm
; register/select/dispatch/reinit). Its whole job is to prove the storage class
; seam accepts more than one concrete backend without the core learning about it:
; that invariance IS the seam test (DRIVER_MODEL §7 / FOUNDATION_CHECKLIST §2
; degenerate-2nd). It self-marks a LOW priority so selection still prefers the
; ramblk reference / a real native NVMe — nullblk is only ever the seam witness.
;
; ops semantics: identify -> ok; read -> zero-fill the buffer (a "null" source);
; write -> accept + discard; flush -> ok. Never wedges, never crashes.
; ============================================================================

nullblk_create:
    push rbx
    ; --- build the blk_ops vtable at RUNTIME (lea->mov: runtime VAs) --------
    lea  rbx, [rel nullblk_ops]
    lea  rax, [rel nullblk_identify]
    mov  [rbx + blk_ops.identify], rax
    lea  rax, [rel nullblk_read]
    mov  [rbx + blk_ops.read], rax
    lea  rax, [rel nullblk_write]
    mov  [rbx + blk_ops.write], rax
    lea  rax, [rel nullblk_flush]
    mov  [rbx + blk_ops.flush], rax

    ; --- fill blk_info -----------------------------------------------------
    lea  rbx, [rel nullblk_info]
    lea  rax, [rel str_nullblk_name]
    mov  [rbx + blk_info.name], rax
    mov  dword [rbx + blk_info.sector_size], 512
    mov  qword [rbx + blk_info.lba_max], 0x00100000   ; sparse/nominal capacity (1M sectors)
    mov  byte  [rbx + blk_info.dma_mask], 64
    mov  byte  [rbx + blk_info.removable], 0
    mov  dword [rbx + blk_info.flags], 0

    ; --- fill the uniform struct dev header --------------------------------
    lea  rbx, [rel nullblk_dev]
    lea  rax, [rel nullblk_ops]
    mov  [rbx + dev.ops], rax
    lea  rax, [rel nullblk_info]
    mov  [rbx + dev.info], rax
    mov  qword [rbx + dev.priv], 0
    mov  dword [rbx + dev.prio], PRIO_DOMAIN         ; low: only ever the seam witness
    mov  dword [rbx + dev.health], HEALTH_OK
    mov  dword [rbx + dev.class], CLASS_BLOCK
    mov  dword [rbx + dev.flags], 0
    lea  rax, [rel str_nullblk_name]
    mov  [rbx + dev.name], rax

    ; --- register (the sanctioned L3->L4 upward edge — no core edit) --------
    mov  rdi, rbx
    call blk_register

    ; --- marker: the class seam accepted a 2nd concrete backend ------------
    lea  rdi, [rel str_nullblk_reg]
    call serial_string
    pop  rbx
    ret

; identify(self) -> 0
nullblk_identify:
    xor  eax, eax
    ret

; read(self, RSI=lba, RDX=count, RCX=buf) -> 0. Zero-fill count*512 bytes.
nullblk_read:
    mov  rax, rdx
    imul rax, rax, 512                       ; nbytes
    xor  r8, r8
.z:
    cmp  r8, rax
    jae  .done
    mov  byte [rcx + r8], 0
    inc  r8
    jmp  .z
.done:
    xor  eax, eax
    ret

; write(self, RSI=lba, RDX=count, RCX=buf) -> 0. Accept + discard.
nullblk_write:
    xor  eax, eax
    ret

; flush(self) -> 0
nullblk_flush:
    xor  eax, eax
    ret

; ---- nullblk data -----------------------------------------------------------
nullblk_dev:     times dev_size db 0
nullblk_ops:     times blk_ops_size db 0
nullblk_info:    times blk_info_size db 0
str_nullblk_name: db "nullblk", 0
str_nullblk_reg:  db "[PAOS64] P3 blk: nullblk seam-2nd backend registered [blk.nullblk.registered]", 13, 10, 0
