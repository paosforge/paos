;; MODULE bus/superio
;; LAYER 2
;; EXPORTS superio_init, superio_identity
;; IMPORTS boot/serial
;; CAPS
;; OWNER saga:board_sensors
; BS0 / 3418. PORT: Classic paos.asm sio_enter_config/sio_read_reg/
; sio_exit_config (13097..13132), nct_init's bounded 0xfff0 family mask.
; ITE extension: Linux 6.6.32 drivers/hwmon/it87.c __superio_enter and
; superio_exit: the fourth unlock byte is 0xaa at 0x4e; ITE also needs
; config-control reg 0x02 <- 0x02 to leave configuration mode. Always finish
; BOTH protocols with Classic's 0xaa. No LDN selection, enable/base, or HWM I/O.
;
; Init is boot-only and idempotent (UDP registration can run again). Live
; queries only read the cache. Fixtures substitute byte I/O, never discovery,
; family decode, fallback, or cleanup. No fixture selector persists globally.

; superio_init() — prove cleanup KAT, then discover once; clobbers caller-saved.
superio_init:
    cmp  byte [rel superio_initialized], 0
    jne  .done
    push rbx
    sub  rsp, 16                         ; private identity + synthetic I/O record
    lea  rbx, [rel superio_cases]
.kat:
    mov  rdi, rsp
    lea  rsi, [rsp + 8]
    mov  eax, [rbx]                      ; independent IDs for 0x2e and 0x4e
    mov  [rsi], eax
    mov  dword [rsi + 4], 0              ; last index, AA count, ITE exit count, reads
    call superio_scan
    mov  al, [rbx + 4]
    cmp  [rdi + 5], al                   ; expected family (0 = absent/unknown)
    jne  .failed
    mov  al, [rbx + 5]
    cmp  [rdi], al                       ; expected selected port, 0 on degrade
    jne  .failed
    xor  eax, eax
    xor  ecx, ecx
    cmp  byte [rbx + 4], 0
    je   .identity
    mov  ax, [rbx]
    cmp  byte [rbx + 5], 0x2e
    je   .vendor
    mov  ax, [rbx + 2]
.vendor:
    mov  cl, 1
    cmp  byte [rbx + 4], 4
    jne  .identity
    inc  ecx
.identity:
    cmp  [rdi + 2], ax                   ; cache must contain the measured ID
    jne  .failed
    cmp  [rdi + 4], cl
    jne  .failed
    cmp  byte [rdi + 6], 1
    jne  .failed
    cmp  byte [rsi + 4], 0xaa             ; observe actual final output byte
    jne  .failed
    mov  al, [rbx + 6]
    cmp  [rsi + 5], al                   ; all exits, plus ITE 0x4e unlock AA
    jne  .failed
    mov  al, [rbx + 7]
    cmp  [rsi + 6], al                   ; ITE config-control exit writes
    jne  .failed
    mov  al, [rbx + 8]
    cmp  [rsi + 7], al                   ; real high/low register reads per attempt
    jne  .failed
    add  rbx, 9
    lea  rax, [rel superio_cases_end]
    cmp  rbx, rax
    jb   .kat
    lea  rdi, [rel str_superio_kat]
    call serial_string
    lea  rdi, [rel superio_identity]
    xor  esi, esi                        ; live backend; fixtures cannot leak to cache
    pushfq
    cli                                  ; bounded four attempts, no concurrent port user
    call superio_scan
    popfq
    cmp  byte [rel superio_identity + 5], 0
    lea  rdi, [rel str_superio_present]
    jne  .report
    lea  rdi, [rel str_superio_degraded]
    jmp  .report
.failed:
    ; Leave the live cache empty, do not touch hardware, and never earn PASS.
    lea  rdi, [rel str_superio_failed]
.report:
    call serial_string
    mov  byte [rel superio_initialized], 1
    add  rsp, 16
    pop  rbx
.done:
    ret

; RDI=8-byte result, RSI=0 for hardware or 8-byte fixture record. At most
; two protocols at each of 0x2e, 0x4e. Stop at the first supported identity.
; Output offsets: 0 port:u16, 2 chip:u16, 4 vendor:u8, 5 family:u8, 6 exit:u8.
; Vendor: 0 unknown, 1 Nuvoton, 2 ITE. Family: 0 unknown, 1 6686, 2 6683,
; 3 6687, 4 IT8688E. PRESENT/DEGRADED derive solely from family.
superio_scan:
    mov  qword [rdi], 0
    mov  dx, 0x2e
.port:
    xor  r8d, r8d                        ; Nuvoton, then ITE
.attempt:
    call superio_attempt
    test eax, eax
    jnz  .found
    inc  r8d
    cmp  r8d, 2
    jb   .attempt
    cmp  dx, 0x4e
    je   .done
    mov  dx, 0x4e
    jmp  .port
.found:
    mov  [rdi], dx
    mov  [rdi + 2], r10w
    inc  r8d
    mov  [rdi + 4], r8b
    mov  [rdi + 5], al
.done:
    ret

; DX=index, R8D=protocol. EAX=decoded family; R10W=measured ID.
; There is one unconditional cleanup edge BEFORE any classification/return.
superio_attempt:
    mov  byte [rdi + 6], 0
    mov  al, 0x87
    call superio_index_out
    test r8d, r8d
    jz   .nuvoton
    mov  al, 0x01
    call superio_index_out
    mov  al, 0x55
    call superio_index_out
    cmp  dx, 0x4e
    jne  .enter_last
    mov  al, 0xaa                       ; ITE secondary-port unlock (Linux)
    jmp  .enter_last
.nuvoton:
    mov  al, 0x87
.enter_last:
    call superio_index_out
    mov  al, 0x20
    call superio_read_reg
    movzx r10d, al
    shl  r10d, 8
    mov  al, 0x21
    call superio_read_reg
    movzx eax, al
    or   r10d, eax
    call superio_exit_config
    ; Port the proven masked families, not the overly broad prose 0xc7xx.
    xor  eax, eax
    test r8d, r8d
    jnz  .ite
    cmp  r10w, 0xd441
    je   .nct6686
    mov  ecx, r10d
    and  ecx, 0xfff0
    cmp  ecx, 0xc730
    je   .nct6683
    cmp  ecx, 0xd590
    jne  .done
    mov  al, 3
    ret
.nct6686:
    mov  al, 1
    ret
.nct6683:
    mov  al, 2
    ret
.ite:
    cmp  r10w, 0x8688
    jne  .done
    mov  al, 4
.done:
    ret

; Single exit for success/unknown/absent: ITE config-control, then mandatory
; 0xaa on the index port. CONFIG_EXIT records completion of this sequence,
; not a claim of readback (there is no generic config-mode status register).
superio_exit_config:
    test r8d, r8d
    jz   .aa
    mov  al, 0x02
    call superio_index_out
    test rsi, rsi
    jnz  .fixture
    inc  dx
    out  dx, al                          ; ITE config-control EXIT, never LDN/base
    dec  dx
    jmp  .aa
.fixture:
    cmp  byte [rsi + 4], 0x02
    jne  .aa
    cmp  al, 0x02
    jne  .aa
    inc  byte [rsi + 6]
.aa:
    mov  al, 0xaa
    call superio_index_out
    mov  byte [rdi + 6], 1
    ret

; Byte-I/O seam. RSI=0 issues the Classic OUT/IN instructions. Fixture
; observes written bytes and serves the selected register on the selected port.
superio_index_out:
    test rsi, rsi
    jnz  .fixture
    out  dx, al
    ret
.fixture:
    mov  [rsi + 4], al
    cmp  al, 0xaa
    jne  .done
    inc  byte [rsi + 5]
.done:
    ret

superio_read_reg:
    call superio_index_out
    test rsi, rsi
    jnz  .fixture
    inc  dx
    in   al, dx
    dec  dx
    ret
.fixture:
    inc  byte [rsi + 7]
    mov  ax, [rsi]
    cmp  dx, 0x2e
    je   .reg
    mov  ax, [rsi + 2]
.reg:
    cmp  byte [rsi + 4], 0x20
    jne  .low
    shr  ax, 8
.low:
    ret

; superio_identity — immutable after init; only identity + cleanup receipt.
superio_identity: dq 0
superio_initialized: db 0

; IDs on each port; expected family, port, AA writes, ITE exits, ID-byte reads.
; Sentinel-zero/all-ones, garbage, family edges, both protocols, and fallback.
superio_cases:
    dw 0x0000, 0xffff
    db 0, 0, 5, 2, 8
    dw 0x1234, 0x5678
    db 0, 0, 5, 2, 8
    dw 0xc72f, 0xc740
    db 0, 0, 5, 2, 8
    dw 0xd58f, 0xd5a0
    db 0, 0, 5, 2, 8
    dw 0x8687, 0x8689
    db 0, 0, 5, 2, 8
    dw 0xd441, 0xc730
    db 1, 0x2e, 1, 0, 2
    dw 0xc73f, 0xffff
    db 2, 0x2e, 1, 0, 2
    dw 0x0000, 0xd59f
    db 3, 0x4e, 3, 1, 6
    dw 0x8688, 0xd441
    db 4, 0x2e, 2, 1, 4
    dw 0xffff, 0x8688
    db 4, 0x4e, 5, 2, 8
superio_cases_end:
str_superio_kat: db "[PAOS64] M2 superio: absent/unknown degrade and config-exit KAT PASS [superio.detect]",13,10,0
str_superio_present: db "[PAOS64] M2 superio: present, configuration exited",13,10,0
str_superio_degraded: db "[PAOS64] M2 superio: DEGRADED absent/unknown, configuration exited",13,10,0
str_superio_failed: db "[PAOS64] M2 superio: DEGRADED cleanup KAT FAIL, discovery disabled",13,10,0
