;; MODULE svc/command_health_verdict
;; LAYER 5
;; EXPORTS health_verdict_declare, c7hv_out_buf, c7hv_out_cur, c7hv_out_ready
;; IMPORTS boot/boot_v2_handoff, boot/boot_v2_health, boot/paging, core/build_id, core/heap, core/lib/fmt, svc/command, svc/optional_fault
;; CAPS
;; OWNER saga:boot_v2_ge_c7_multidimensional_health_verdicts
; Read-only projection of the exact PBMH-v2 record already written and read
; back by normal boot context. It does not read EFI variables, change policy,
; or mint promotion authority; PaOSBootReady remains the sole compact token.

; Longest current line: 798 bytes + NUL, including unmeasured build state,
; 20-digit heap/optional epoch and 10-digit optional state. Retain margin;
; every append independently reserves its terminator inside this allocation.
C7HV_OUT_CAP equ 1024

health_verdict_declare:
    mov  byte [rel c7hv_out_ready], 0
    lea  rdi, [rel str_c7hv_verb]
    lea  rsi, [rel cmd_verb_c7health]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9                         ; action-free observation
    call command_register_verb
    ret

cmd_verb_c7health:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  r12, rsi
    call c7hv_out_reset
    lea  rdi, [rel str_c7hv_prefix]
    call c7hv_out_str
    cmp  byte [rel pbm_health_vector_published], 1
    jne  .unavailable
    call boot_v2_health_vector_core_valid
    test eax, eax
    jz   .unavailable
    mov  ebx, [rel pbm_health_vector_record + PBM_MH_CRC32]
    lea  rdi, [rel pbm_health_vector_record]
    mov  esi, PBM_MH_CRC32
    call pbm_crc32
    cmp  eax, ebx
    jne  .unavailable
    cmp  byte [rel pbm_strong_health_published], 1
    jne  .unavailable

    lea  rdi, [rel str_c7hv_valid]
    call c7hv_out_str
    lea  rdi, [rel str_c7hv_entry]
    call c7hv_out_str
    movzx edi, byte [rel pbm_health_vector_record + PBM_MH_ENTRY_OFF]
    call c7hv_out_hex8
    lea  rdi, [rel str_c7hv_nonce]
    call c7hv_out_str
    mov  rdi, [rel pbm_health_vector_record + PBM_MH_ATTEMPT_NONCE_OFF]
    call c7hv_out_hex64
    lea  rdi, [rel str_c7hv_sequence]
    call c7hv_out_str
    mov  rdi, [rel pbm_health_vector_record + PBM_MH_MANAGER_SEQ_OFF]
    call c7hv_out_hex64
    lea  rdi, [rel str_c7hv_state_generation]
    call c7hv_out_str
    mov  rdi, [rel pbm_health_vector_record + PBM_MH_STATE_GEN_OFF]
    call c7hv_out_hex64
    lea  rdi, [rel str_c7hv_init_generation]
    call c7hv_out_str
    mov  rdi, [rel pbm_health_vector_record + PBM_MH_INIT_GEN_OFF]
    call c7hv_out_hex64
    lea  rdi, [rel str_c7hv_payload]
    call c7hv_out_str
    lea  rdi, [rel pbm_health_vector_record + PBM_MH_PAYLOAD_SHA_OFF]
    mov  ecx, 32
    call c7hv_out_hex_bytes
    ; SEC-pbh1: payload_sha256 above is the CRC-only handoff CLAIM (copied into
    ; the record). build_id is the running image's own measurement.
    lea  rdi, [rel str_c7hv_build_id]
    call c7hv_out_str
    lea  rdi, [rel paos_build_hex]
    call c7hv_out_str
    lea  rdi, [rel str_c7hv_bid]
    call c7hv_out_str
    call build_id_state_text
    call c7hv_out_str

    lea  rdi, [rel str_c7hv_image]
    call c7hv_out_str
    movzx edi, byte [rel pbm_health_vector_record + PBM_MH_IMAGE_OFF]
    call c7hv_out_status
    lea  rdi, [rel str_c7hv_core]
    call c7hv_out_str
    movzx edi, byte [rel pbm_health_vector_record + PBM_MH_CORE_OFF]
    call c7hv_out_status
    lea  rdi, [rel str_c7hv_desktop]
    call c7hv_out_str
    movzx edi, byte [rel pbm_health_vector_record + PBM_MH_DESKTOP_OFF]
    call c7hv_out_status
    lea  rdi, [rel str_c7hv_command]
    call c7hv_out_str
    movzx edi, byte [rel pbm_health_vector_record + PBM_MH_COMMAND_OFF]
    call c7hv_out_status
    lea  rdi, [rel str_c7hv_storage]
    call c7hv_out_str
    movzx edi, byte [rel pbm_health_vector_record + PBM_MH_STORAGE_OFF]
    call c7hv_out_status
    lea  rdi, [rel str_c7hv_network]
    call c7hv_out_str
    movzx edi, byte [rel pbm_health_vector_record + PBM_MH_NETWORK_OFF]
    call c7hv_out_status
    lea  rdi, [rel str_c7hv_display]
    call c7hv_out_str
    movzx edi, byte [rel pbm_health_vector_record + PBM_MH_DISPLAY_OFF]
    call c7hv_out_status
    lea  rdi, [rel str_c7hv_machine]
    call c7hv_out_str
    movzx edi, byte [rel pbm_health_vector_record + PBM_MH_MACHINE_OFF]
    call c7hv_out_status

    test word [rel pbm_health_vector_record + PBM_MH_FLAGS_OFF], PBM_MH_F_OPTIONAL_DEGRADED
    lea  rdi, [rel str_c7hv_optional_ready]
    jz   .optional
    lea  rdi, [rel str_c7hv_optional_degraded]
.optional:
    call c7hv_out_str
    test word [rel pbm_health_vector_record + PBM_MH_FLAGS_OFF], PBM_MH_F_DISPLAY_ESTABLISHED
    lea  rdi, [rel str_c7hv_display_degraded]
    jz   .display_content
    lea  rdi, [rel str_c7hv_display_established]
.display_content:
    call c7hv_out_str
    lea  rdi, [rel str_c7hv_policy]
    call c7hv_out_str
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  qword [r12 + RSP_VAL], 1
    jmp  .ready

.unavailable:
    lea  rdi, [rel str_c7hv_unavailable]
    call c7hv_out_str
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  qword [r12 + RSP_VAL], 0
.ready:
    ; RCQ-38 S2 (root 08:58:21, C2): the general heap's bump use, live, on both
    ; paths. Owner-authenticated only; public SRVSTAT stays coarse.
    lea  rdi, [rel str_c7hv_heap_used]
    call c7hv_out_str
    call c7hv_heap_used
    mov  rdi, rax
    call c7hv_out_dec
    ; The cached boot dimensions above remain immutable. These three fields
    ; describe ONLY the current optional RAM device, not aggregate boot health.
    lea  rdi, [rel str_c7hv_optblk]
    call c7hv_out_str
    call optional_fault_health
    lea  rdi, [rel str_c7hv_unavailable_value]
    cmp  eax, HEALTH_DEAD
    je   .opt_health
    lea  rdi, [rel str_c7hv_degraded_value]
    cmp  eax, HEALTH_OK
    jne  .opt_health
    lea  rdi, [rel str_c7hv_ready_value]
.opt_health:
    call c7hv_out_str
    lea  rdi, [rel str_c7hv_opt_epoch]
    call c7hv_out_str
    mov  rdi, [rel opt_epoch]
    call c7hv_out_dec
    lea  rdi, [rel str_c7hv_opt_state]
    call c7hv_out_str
    mov  edi, [rel opt_state]
    call c7hv_out_dec
    cmp  byte [rel c7hv_out_overflow], 0
    je   .publish
    ; Never publish a partial status=valid line or its promotion-token text.
    ; Retire it and return a defined read-only unavailable observation instead.
    call c7hv_out_reset
    lea  rdi, [rel str_c7hv_truncated]
    call c7hv_out_str
    mov  qword [r12 + RSP_VAL], 0
    cmp  byte [rel c7hv_out_overflow], 0
    jne  .out                         ; even the refusal must fit completely
.publish:
    mov  byte [rel c7hv_out_ready], 1
.out:
    pop  r12
    pop  rbx
    ret

; RAX = heap_next - heap_base, or 0 unless the allocator's own invariants hold
; (base and next set, base <= next <= end), as in heap_init / kmalloc.
c7hv_heap_used:
    xor  eax, eax
    mov  rcx, [rel heap_base]
    mov  rdx, [rel heap_next]
    test rcx, rcx
    jz   .out
    test rdx, rdx
    jz   .out
    cmp  rdx, rcx
    jb   .out
    cmp  rdx, [rel heap_end]
    ja   .out
    mov  rax, rdx
    sub  rax, rcx
.out:
    ret

; RDI = value: at most 20 decimal digits + NUL (fmt_dec).
c7hv_out_dec:
    ; fmt_dec has no destination bound. Render into a private 21-byte scratch
    ; first, then use the same bounded append as every other string.
    sub  rsp, 24
    mov  rsi, rsp
    call fmt_dec
    mov  rdi, rsp
    call c7hv_out_str
    add  rsp, 24
    ret

c7hv_out_reset:
    mov  byte [rel c7hv_out_ready], 0
    mov  byte [rel c7hv_out_overflow], 0
    lea  rax, [rel c7hv_out_buf]
    mov  [rel c7hv_out_cur], rax
    mov  byte [rax], 0
    ret

; RDX = bytes excluding NUL. Return RSI=cursor, CF=0 iff the entire append
; plus NUL fits. Subtraction after checking cursor avoids pointer-add wrap.
; A refusal is sticky until reset; no caller writes after CF=1.
c7hv_out_reserve:
    cmp  byte [rel c7hv_out_overflow], 0
    jne  .full
    mov  rsi, [rel c7hv_out_cur]
    lea  rax, [rel c7hv_out_buf]
    cmp  rsi, rax
    jb   .full
    lea  rax, [rel c7hv_out_buf + C7HV_OUT_CAP - 1]
    cmp  rsi, rax
    ja   .full
    sub  rax, rsi
    cmp  rdx, rax
    ja   .full
    clc
    ret
.full:
    mov  byte [rel c7hv_out_overflow], 1
    stc
    ret

c7hv_out_str:
.copy:
    cmp  byte [rdi], 0
    jz   .done
    mov  edx, 1
    call c7hv_out_reserve
    jc   .done
    mov  al, [rdi]
    mov  [rsi], al
    inc  rdi
    inc  rsi
    mov  byte [rsi], 0
    mov  [rel c7hv_out_cur], rsi
    jmp  .copy
.done:
    ret

c7hv_out_status:
    mov  eax, edi
    lea  rdi, [rel str_c7hv_unavailable_value]
    cmp  eax, PBM_MH_UNAVAILABLE
    je   c7hv_out_str
    lea  rdi, [rel str_c7hv_degraded_value]
    cmp  eax, PBM_MH_DEGRADED
    je   c7hv_out_str
    lea  rdi, [rel str_c7hv_ready_value]
    jmp  c7hv_out_str

c7hv_out_hex8:
    mov  edx, 4
    call c7hv_out_reserve
    jc   .out
    lea  r8, [rel c7hv_hex]
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
    mov  [rel c7hv_out_cur], rsi
.out:
    ret

c7hv_out_hex64:
    mov  edx, 18
    call c7hv_out_reserve
    jc   .out
    lea  r8, [rel c7hv_hex]
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
    mov  [rel c7hv_out_cur], rsi
.out:
    ret

c7hv_out_hex_bytes:
    mov  edx, ecx
    shl  rdx, 1                       ; widen before doubling uint32 count
    call c7hv_out_reserve
    jc   .out
    test ecx, ecx
    jz   .done                        ; empty input never reads its pointer
    lea  r8, [rel c7hv_hex]
.byte:
    movzx eax, byte [rdi]
    mov  edx, eax
    shr  eax, 4
    mov  al, [r8 + rax]
    mov  [rsi], al
    and  edx, 0x0F
    mov  dl, [r8 + rdx]
    mov  [rsi + 1], dl
    inc  rdi
    add  rsi, 2
    dec  ecx
    jnz  .byte
.done:
    mov  byte [rsi], 0
    mov  [rel c7hv_out_cur], rsi
.out:
    ret

align 8
c7hv_out_cur:   dq 0
c7hv_out_ready: db 0
c7hv_out_overflow: db 0
c7hv_out_buf:   times C7HV_OUT_CAP db 0
c7hv_hex:       db "0123456789abcdef"
str_c7hv_verb:  db "C7HEALTH",0
str_c7hv_prefix: db " c7_health status=",0
str_c7hv_valid: db "valid schema=0x02 identity=slot-nonce-manifest profile=normal core_checkpoint=strong readback=exact",0
str_c7hv_unavailable: db "unavailable schema=0x02 projection=read-only",0
str_c7hv_truncated: db " c7_health status=unavailable schema=0x02 projection=read-only output=truncated",0
str_c7hv_entry: db " entry=",0
str_c7hv_nonce: db " nonce=",0
str_c7hv_sequence: db " manager_seq=",0
str_c7hv_state_generation: db " state_generation=",0
str_c7hv_init_generation: db " init_generation=",0
str_c7hv_payload: db " payload_sha256=",0
str_c7hv_build_id: db " build_id=",0
str_c7hv_bid: db " bid=",0
str_c7hv_heap_used: db " heap_used=",0
str_c7hv_image: db " image=",0
str_c7hv_core: db " core=",0
str_c7hv_desktop: db " desktop=",0
str_c7hv_command: db " command=",0
str_c7hv_storage: db " storage=",0
str_c7hv_network: db " network=",0
str_c7hv_display: db " display=",0
str_c7hv_machine: db " machine=",0
str_c7hv_ready_value: db "ready",0
str_c7hv_degraded_value: db "degraded",0
str_c7hv_unavailable_value: db "unavailable",0
str_c7hv_optional_ready: db " optional=ready",0
str_c7hv_optional_degraded: db " optional=degraded",0
str_c7hv_display_established: db " display_content=established",0
str_c7hv_display_degraded: db " display_content=degraded",0
str_c7hv_policy: db " promotion_token=published external_authority=none projection=read-only",0

str_c7hv_optblk: db " optblk=", 0
str_c7hv_opt_epoch: db " opt_epoch=", 0
str_c7hv_opt_state: db " opt_state=", 0
