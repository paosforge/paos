;; MODULE core/idle_prof
;; LAYER 1
;; EXPORTS idle_prof_mark, idle_prof_tab, idle_prof_passes, idle_prof_state
;; IMPORTS boot/serial, boot/header, core/time
;; CAPS
;; OWNER saga:boot
;;
;; BSP idle-loop owner profile, measurement only (rc-boot DHCP plan 2026-10-17 21:12:55, step 2).
;;
;; Lenovo cold cohorts put the DHCP REQUEST ~0.7 s after the OFFER reached the NIC: DHCP RX is ingested only in
;; command_udp_poll, once per idle pass, so some idle owner holds a pass that long. This names it without
;; changing any owner or grade. header.asm's idle loop carries IDLE_PROF_MARK n before every owner call
;; (n in loop order, 0 = pass start). For IDLE_PROF_WINDOW_MS after the first mark, the time from mark k to the
;; next executed mark is owner k's (its call, plus any branch that skips later marks); each owner keeps its
;; longest segment and that segment's start TSC. When the window closes, one serial line lists the four
;; longest; from then on a mark costs one compare (inside pushfq/popfq).
;;
;;   [PAOS64] idle pass profile 5000ms passes=N top id:us@ms 12:701234@1520 ... [boot.idle.profile]
;;
;; us = segment length in microseconds, ms = its start in boot ms (boot_ms_now's clock). Without a TSC rate the
;; profile is skipped and says so. Preserves flags and every register, so a mark may sit anywhere in the loop.

IDLE_PROF_WINDOW_MS equ 5000
IDLE_PROF_TOP       equ 4

idle_prof_mark:
    pushfq                              ; first: the state compare below must not reach the caller's flags
    cmp  byte [rel idle_prof_state], 2
    je   .fast
    push rax
    push rcx
    push rdx
    push rsi
    rdtsc
    shl  rdx, 32
    or   rax, rdx                       ; rax = now (raw TSC)
    cmp  byte [rel idle_prof_state], 1
    je   .active
    mov  rcx, [rel tsc_khz]             ; first mark: open the window
    test rcx, rcx
    jz   .no_rate
    imul rcx, rcx, IDLE_PROF_WINDOW_MS
    add  rcx, rax
    mov  [rel idle_prof_end], rcx
    mov  byte [rel idle_prof_state], 1
    jmp  .open
.active:
    mov  rcx, rax
    sub  rcx, [rel idle_prof_last]      ; segment length, owned by the previous mark
    movzx esi, byte [rel idle_prof_last_id]
    shl  esi, 4
    lea  rdx, [rel idle_prof_tab]
    cmp  rcx, [rdx + rsi]
    jbe  .counted
    mov  [rdx + rsi], rcx
    mov  rcx, [rel idle_prof_last]
    mov  [rdx + rsi + 8], rcx
.counted:
    test edi, edi
    jnz  .open
    inc  qword [rel idle_prof_passes]
.open:
    mov  [rel idle_prof_last], rax
    mov  [rel idle_prof_last_id], dil
    cmp  rax, [rel idle_prof_end]
    jb   .out
    mov  byte [rel idle_prof_state], 2
    call idle_prof_report
    jmp  .out
.no_rate:
    mov  byte [rel idle_prof_state], 2
    push rdi
    push r8
    push r9
    push r10
    push r11
    lea  rdi, [rel str_idle_prof_skip]
    call serial_string
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
.out:
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
.fast:
    popfq
    ret

; idle_prof_report — the window closed: print passes and the IDLE_PROF_TOP longest owners. Saves what it uses
; beyond idle_prof_mark's own saves (rax/rcx/rdx/rsi/flags).
idle_prof_report:
    push rbx
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    lea  rdi, [rel str_idle_prof_pre]
    call serial_string
    mov  rax, [rel idle_prof_passes]
    call idle_prof_dec
    lea  rdi, [rel str_idle_prof_top]
    call serial_string
    xor  r12d, r12d                     ; owners already printed (bit per id)
    mov  r13d, IDLE_PROF_TOP
.pick:
    xor  ebx, ebx                       ; best length
    mov  r14d, -1                       ; best id (callee-saved: survives serial_string)
    xor  ecx, ecx
    lea  rsi, [rel idle_prof_tab]
.scan:
    bt   r12, rcx
    jc   .next
    mov  rdx, rcx
    shl  rdx, 4
    mov  rax, [rsi + rdx]
    cmp  rax, rbx
    jbe  .next
    mov  rbx, rax
    mov  r14d, ecx
.next:
    inc  ecx
    cmp  ecx, IDLE_PROF_OWNERS
    jb   .scan
    test rbx, rbx
    jz   .done                          ; fewer owners ran than the top size
    bts  r12, r14
    lea  rdi, [rel str_idle_prof_sp]
    call serial_string
    mov  eax, r14d
    call idle_prof_dec
    lea  rdi, [rel str_idle_prof_colon]
    call serial_string
    mov  rax, rbx                       ; us = tsc * 1000 / tsc_khz
    imul rax, rax, 1000
    xor  edx, edx
    div  qword [rel tsc_khz]
    call idle_prof_dec
    lea  rdi, [rel str_idle_prof_at]
    call serial_string
    mov  edx, r14d
    shl  edx, 4
    lea  rsi, [rel idle_prof_tab]
    mov  rax, [rsi + rdx + 8]           ; start ms = (start - boot_tsc_start) / tsc_khz
    sub  rax, [rel boot_tsc_start]
    jae  .at_ok
    xor  eax, eax
.at_ok:
    xor  edx, edx
    div  qword [rel tsc_khz]
    call idle_prof_dec
    dec  r13d
    jnz  .pick
.done:
    lea  rdi, [rel str_idle_prof_post]
    call serial_string
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rbx
    ret

; idle_prof_dec — rax unsigned -> decimal on serial. Clobbers rax, rcx, rdx, rdi, r8-r11.
idle_prof_dec:
    sub  rsp, 24
    lea  rdi, [rsp + 20]
    mov  byte [rdi], 0
    mov  ecx, 10
.digit:
    xor  edx, edx
    div  rcx
    add  dl, '0'
    dec  rdi
    mov  [rdi], dl
    test rax, rax
    jnz  .digit
    call serial_string
    add  rsp, 24
    ret

str_idle_prof_pre:   db "[PAOS64] idle pass profile 5000ms passes=", 0
str_idle_prof_top:   db " top id:us@ms", 0
str_idle_prof_sp:    db " ", 0
str_idle_prof_colon: db ":", 0
str_idle_prof_at:    db "@", 0
str_idle_prof_post:  db " [boot.idle.profile]", 13, 10, 0
str_idle_prof_skip:  db "[PAOS64] idle pass profile skipped (no TSC rate) [boot.idle.profile]", 13, 10, 0

%macro WDATA_boot_idle_prof 0
idle_prof_tab:     resq 2 * IDLE_PROF_OWNERS ; per owner: longest segment (TSC), its start (TSC)
idle_prof_passes:  resq 1
idle_prof_last:    resq 1
idle_prof_end:     resq 1
idle_prof_last_id: resb 1
idle_prof_state:   resb 1          ; 0 = not started, 1 = window open, 2 = done
%endmacro
WDATA_BSS_DEFER WDATA_boot_idle_prof
