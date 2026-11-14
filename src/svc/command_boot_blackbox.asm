;; MODULE svc/command_boot_blackbox
;; LAYER 5
;; EXPORTS boot_blackbox_declare, c6bb_out_buf, c6bb_out_cur, c6bb_out_ready
;; IMPORTS boot/boot_v2_health, svc/command
;; CAPS
;; OWNER saga:boot_v2_ge_c6_boot_black_box_delta
; Read-only projection of the exact PBMH-v2 black-box copy that normal context
; wrote and read back.  It never reads EFI variables itself and owns no write,
; boot-selection, recovery, or target-mutation authority.

C6BB_OUT_CAP equ 384

boot_blackbox_declare:
    mov  byte [rel c6bb_out_ready], 0
    lea  rdi, [rel str_c6bb_verb]
    lea  rsi, [rel cmd_verb_c6blackbox]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9                         ; action-free observation
    call command_register_verb
    ret

cmd_verb_c6blackbox:
    call cmd_handler_prologue
    push r12
    push r13
    mov  r12, rsi
    call c6bb_out_reset
    lea  rdi, [rel str_c6bb_prefix]
    call c6bb_out_str
    cmp  byte [rel pbm_blackbox_last_valid], 1
    jne  .unavailable
    lea  rdi, [rel pbm_blackbox_record]
    call boot_v2_blackbox_validate
    test eax, eax
    jnz  .unavailable
    cmp  word [rel pbm_blackbox_record + PBM_BB_HDR_COUNT_OFF], 0
    je   .unavailable

    lea  rdi, [rel str_c6bb_valid]
    call c6bb_out_str
    lea  rdi, [rel str_c6bb_generation]
    call c6bb_out_str
    mov  rdi, [rel pbm_blackbox_record + PBM_BB_HDR_GENERATION_OFF]
    call c6bb_out_hex64
    lea  rdi, [rel str_c6bb_count]
    call c6bb_out_str
    movzx edi, word [rel pbm_blackbox_record + PBM_BB_HDR_COUNT_OFF]
    call c6bb_out_hex8
    lea  rdi, [rel str_c6bb_index]
    call c6bb_out_str
    movzx r13d, word [rel pbm_blackbox_record + PBM_BB_HDR_WRITE_INDEX_OFF]
    mov  edi, r13d
    call c6bb_out_hex8
    imul r13d, r13d, PBM_BB_SLOT_SIZE
    lea  rax, [rel pbm_blackbox_record + PBM_BB_HEADER_SIZE]
    add  r13, rax
    lea  rdi, [rel str_c6bb_reset]
    call c6bb_out_str
    movzx edi, byte [r13 + PBM_BB_SLOT_RESET_CAUSE_OFF]
    call c6bb_out_hex8
    lea  rdi, [rel str_c6bb_policy]
    call c6bb_out_str
    mov  byte [rel c6bb_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  qword [r12 + RSP_VAL], 1
    jmp  .out

.unavailable:
    lea  rdi, [rel str_c6bb_unavailable]
    call c6bb_out_str
    mov  byte [rel c6bb_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  qword [r12 + RSP_VAL], 0
.out:
    pop  r13
    pop  r12
    ret

c6bb_out_reset:
    lea  rax, [rel c6bb_out_buf]
    mov  [rel c6bb_out_cur], rax
    mov  byte [rax], 0
    ret

c6bb_out_str:
    mov  rsi, [rel c6bb_out_cur]
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rdi
    inc  rsi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel c6bb_out_cur], rsi
    ret

c6bb_out_hex8:
    mov  rsi, [rel c6bb_out_cur]
    lea  r8, [rel c6bb_hex]
    mov  byte [rsi], '0'
    mov  byte [rsi + 1], 'x'
    mov  eax, edi
    mov  edx, eax
    shr  eax, 4
    and  eax, 0x0F
    mov  al, [r8 + rax]
    mov  [rsi + 2], al
    and  edx, 0x0F
    mov  dl, [r8 + rdx]
    mov  [rsi + 3], dl
    mov  byte [rsi + 4], 0
    add  rsi, 4
    mov  [rel c6bb_out_cur], rsi
    ret

c6bb_out_hex64:
    mov  rsi, [rel c6bb_out_cur]
    lea  r8, [rel c6bb_hex]
    mov  byte [rsi], '0'
    mov  byte [rsi + 1], 'x'
    add  rsi, 2
    mov  rax, rdi
    mov  ecx, 16
.nibble:
    rol  rax, 4
    mov  rdx, rax
    and  edx, 0x0F
    mov  dl, [r8 + rdx]
    mov  [rsi], dl
    inc  rsi
    dec  ecx
    jnz  .nibble
    mov  byte [rsi], 0
    mov  [rel c6bb_out_cur], rsi
    ret

align 8
c6bb_out_cur:   dq 0
c6bb_out_ready: db 0
c6bb_out_buf:   times C6BB_OUT_CAP db 0
c6bb_hex:       db "0123456789abcdef"
str_c6bb_verb:  db "C6BLACKBOX",0
str_c6bb_prefix: db " c6_blackbox status=",0
str_c6bb_valid: db "valid pbmh_v2=2 ring_capacity=0x08 copies=0x02",0
str_c6bb_unavailable: db "unavailable pbmh_v2=2 ring_capacity=0x08 copies=0x02",0
str_c6bb_generation: db " generation=",0
str_c6bb_count: db " count=",0
str_c6bb_index: db " write_index=",0
str_c6bb_reset: db " reset_cause=",0
str_c6bb_policy: db " newest_valid=1 slot_crc=ok ring_crc=ok readback=exact selection=serial-half-range projection=read-only",0
