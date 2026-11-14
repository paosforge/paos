;; MODULE svc/boot_clock
;; LAYER 5
;; EXPORTS boot_clock_declare, boot_clock_verb, boot_clock_snapshot, boot_clock_ms_checked, boot_clock_boot_ms, boot_clock_format, boot_clock_reply_retire, bc_reply_req, bc_reply_arg, bc_reply_build, bc_reply_boot, bc_reply_rsp, bc_reply_len, bc_reply_body, bc_reply_valid, bc_reply_generation, irq0_observation_verb, irq0_observation_format
;; IMPORTS boot/header, core/time, core/log, core/lib/fmt, svc/command, svc/command_auth, svc/boot_gates, svc/command_udp, config/keep_config, core/build_id, sec/ucode_preload, sec/cpu_microcode_boot
;; CAPS
;; OWNER saga:rcq28_boot_clock
; Read-only observation, origin = payload EFI entry (NOT power-on). No producer,
; calibration, deadline, health, wait or policy writes. Legacy gate0 stays0.

BC_OK equ 0
BC_NOT_REACHED equ 1
BC_UNCALIBRATED equ 2
BC_ORIGIN_MISSING equ 3
BC_REGRESSED equ 4
BC_FUTURE equ 5
BC_CHANGED equ 6
BC_CAL_INVALID equ 7
BC_STATE_INVALID equ 8
BC_TRUNCATED equ 10
BC_NONCE_INVALID equ 11
BC_NONCE_MAX equ 64
BC_TRUNCATED_BYTES equ 22

BC_ORIGIN equ 0
BC_SCALE equ 8
BC_SOURCE equ 16
BC_REASON equ 24
BC_PRESENTATION equ 32
BC_TIMELINE_COUNT equ 40
BC_END equ 48
BC_EBS equ 56
BC_READY equ 64
BC_ACK equ 72
BC_PIXEL equ 80
BC_KBD equ 88
BC_PTR equ 96
BC_INPUT equ 104
BC_UDP equ 112
BC_SSH equ 120
BC_TERMINAL equ 128
BC_NIC equ 136
BC_FOUNDATION equ 144
BC_NIC_PRESENT equ 152
BC_FOUNDATION_PRESENT equ 160
BC_COST_PAIRS equ 168
BC_COST_DONE equ 248
BC_SETTLE_TSC equ 288                   ; four settled producers, raw TSC
BC_SETTLE_STATE equ 320                 ; four states: 0 pending, 1 complete, 2 not-required
BC_SETTLE_SLOTS equ 4
BC_DHCP equ 352                         ; v6: first usable DHCP lease (timeline boot.dhcp.bound)
; v7 appended facts; all preceding private offsets and v1..v6 wire schemas retained.
BC_CPU_COST_PAIRS equ 360              ; preload/BSP raw start,end (not AP or VM cost)
BC_CPU_COST_DONE equ 392               ; two independent completion observations
BC_COMPARE_BYTES equ 408
BC_NOW equ 408
BC_STATUS equ 416
BC_BEGIN equ 424
BC_SIZE equ 432

%macro WDATA_boot_clock_reply 0
bc_reply_req: times REQ_SZ db 0
bc_reply_arg: times 65 db 0
bc_reply_build: times 64 db 0
bc_reply_boot: dd 0
bc_reply_rsp: times RSP_SZ db 0
bc_reply_len: dq 0
bc_reply_body: times 1280 db 0
bc_reply_valid: db 0
bc_reply_generation: dq 0                 ; monotonic; retirement preserves it
%endmacro
WDATA_DEFER WDATA_boot_clock_reply

boot_clock_declare:
    lea rdi, [rel str_bc_verb]
    lea rsi, [rel boot_clock_verb]
    xor edx, edx
    mov ecx, ARGT_TEXT
    xor r8d, r8d
    xor r9d, r9d
    call command_register_verb
    lea rdi, [rel str_irq0_verb]
    lea rsi, [rel irq0_observation_verb]
    xor edx, edx
    mov ecx, ARGT_TEXT
    xor r8d, r8d
    xor r9d, r9d
    jmp command_register_verb

; Independent typed read-only record; existing BOOTCLOCK v1..v7 and its legacy
; hook projection retain their exact schemas. No snapshot or transport policy
; writes. Identity is native build + boot_nonce, plus caller's fresh nonce;
; operators still bracket with the normal STATUS boot-session identity.
irq0_observation_verb:
    call cmd_handler_prologue
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    mov byte [rel command_auth_out_ready], 0
    mov rdx, [rbx + REQ_ARG]
    lea rdi, [rel command_auth_out_buf]
    mov esi, AUTH_OUT_MAX
    call irq0_observation_format
    mov qword [r12 + RSP_CODE], CMDE_OK
    test edx, edx
    jz .reply
    mov qword [r12 + RSP_CODE], CMDE_BADARG
    mov [r12 + RSP_EXPECTED], rcx
    lea rax, [rel command_auth_out_buf]
    mov [r12 + RSP_HINT], rax
.reply:
    mov rax, [rbx + REQ_ARG]
    mov [r12 + RSP_VAL], rax
    mov byte [rel command_auth_out_ready], 1
    pop r12
    pop rbx
    ret

; Same span/nonce/ABI contract as boot_clock_format, with a separate v1 wire.
; Snapshot occupies stack bytes0..31; nonce32, status40. All values are raw
; counts/enums, independent of TSC calibration. Pending is never positive.
irq0_observation_format:
    pushfq
    cld
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48
    mov rbx, rsp
    mov r12, rdi
    mov r14, rdi
    mov r13, rdi
    xor r15d, r15d
    mov [rbx + 32], rdx
    mov qword [rbx + 40], BC_OK
    test rdi, rdi
    jz .no_span
    test rsi, rsi
    jz .no_span
    add r13, rsi
    jc .no_span
    dec r13
    mov byte [r12], 0
    mov rdi, rdx
    call boot_clock_nonce
    test eax, eax
    jz .capture
    mov qword [rbx + 40], BC_NONCE_INVALID
    lea rdi, [rel str_irq0_nonce_bad]
    call bc_put_str
    jmp .finish
.capture:
    mov rdi, rbx
    call timer_irq0_snapshot
    lea rdi, [rel str_irq0_head]
    call bc_put_str
    mov rdi, [rbx + 32]
    test rdi, rdi
    jz .identity
    call bc_put_str
.identity:
    lea rdi, [rel str_irq0_build]
    call bc_put_str
    lea rdi, [rel paos_build_hex]
    call bc_put_str
    lea rdi, [rel str_irq0_boot]
    call bc_put_str
    mov edi, [rel boot_nonce]
    call bc_put_dec
    lea rdi, [rel str_irq0_state]
    call bc_put_str
    mov rdi, [rbx]
    call bc_put_dec
    lea rdi, [rel str_irq0_result]
    call bc_put_str
    mov rdi, [rbx + 8]
    call bc_put_dec
    lea rdi, [rel str_irq0_before]
    call bc_put_str
    mov rdi, [rbx + 16]
    call bc_put_dec
    lea rdi, [rel str_irq0_after]
    call bc_put_str
    mov rdi, [rbx + 24]
    call bc_put_dec
    lea rdi, [rel str_bc_complete]
    call bc_put_str
.finish:
    lea rcx, [r15 + 1]
    mov rax, r14
    sub rax, r12
    cmp rax, r15
    jne .truncated
    mov edx, [rbx + 40]
    jmp .out
.truncated:
    mov r10, rcx
    mov byte [r12], 0
    xor eax, eax
    mov rcx, r13
    sub rcx, r12
    inc rcx
    cmp rcx, str_irq0_truncated_end - str_irq0_truncated
    jb .short
    lea rsi, [rel str_irq0_truncated]
    mov rdi, r12
    mov ecx, str_irq0_truncated_end - str_irq0_truncated
    rep movsb
    mov eax, str_irq0_truncated_end - str_irq0_truncated - 1
.short:
    mov rcx, r10
    mov edx, BC_TRUNCATED
    jmp .out
.no_span:
    xor eax, eax
    xor ecx, ecx
    mov edx, BC_TRUNCATED
.out:
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    popfq
    ret

; Same typed nonce envelope as BOOTREPORT; current request's existing shared
; text rail supplies UDP/SSH/serial/local projection and request retirement.
boot_clock_verb:
    call cmd_handler_prologue
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    call boot_clock_reply_begin
    mov byte [rel command_auth_out_ready], 0
    mov rdx, [rbx + REQ_ARG]
    lea rdi, [rel command_auth_out_buf]
    mov esi, AUTH_OUT_MAX
    call boot_clock_format
    mov [rel bc_reply_len], rax
    mov qword [r12 + RSP_CODE], CMDE_OK
    test edx, edx
    jz .reply
    mov qword [r12 + RSP_CODE], CMDE_BADARG
    mov [r12 + RSP_EXPECTED], rcx
    lea rax, [rel command_auth_out_buf]
    mov [r12 + RSP_HINT], rax
.reply:
    mov rax, [rbx + REQ_ARG]
    mov [r12 + RSP_VAL], rax
    mov byte [rel command_auth_out_ready], 1
    call boot_clock_reply_publish
    pop r12
    pop rbx
    ret

; Private pure converter. RDI=stamp, RSI=origin, RDX=ticks/ms, RCX=current
; upper sample, R8D=present, R9D=snapshot reason. RAX=ms (0 on refusal),
; EDX=BC_*; clobbers R10. No multiplication: high dividend is explicitly0,
; nonzero divisor => full64 quotient always fits, including extreme scales.
boot_clock_ms_checked:
    mov r10, rdx
    xor eax, eax
    mov edx, r9d
    test edx, edx
    jnz .out
    mov edx, BC_NOT_REACHED
    test r8d, r8d
    jz .out
    mov edx, BC_ORIGIN_MISSING
    test rsi, rsi
    jz .out
    mov edx, BC_UNCALIBRATED
    test r10, r10
    jz .out
    mov edx, BC_REGRESSED
    cmp rcx, rsi
    jb .out
    cmp rdi, rsi
    jb .out
    mov edx, BC_FUTURE
    cmp rdi, rcx
    ja .out
    mov rax, rdi
    sub rax, rsi
    xor edx, edx
    div r10
    xor edx, edx
.out:
    ret

; Copy only existing facts. Packed timeline rows are first-arrival records;
; use their existing bounded reader, and bind its count in the double collect.
boot_clock_collect:
    push rbx
    mov rbx, rdi
    mov rax, [rel boot_tsc_start]
    mov [rbx + BC_ORIGIN], rax
    mov rax, [rel tsc_khz]
    mov [rbx + BC_SCALE], rax
    movzx eax, byte [rel tsc_calibration_source]
    mov [rbx + BC_SOURCE], rax
    movzx eax, byte [rel tsc_calibration_reason]
    mov [rbx + BC_REASON], rax
    movzx eax, byte [rel keep_presentation_target]
    mov [rbx + BC_PRESENTATION], rax
    mov eax, [rel boot_timeline_count]
    mov [rbx + BC_TIMELINE_COUNT], rax
    mov rax, [rel boot_tsc_end]
    mov [rbx + BC_END], rax
    mov rax, [rel boot_bg4_ebs_tsc]
    mov [rbx + BC_EBS], rax
    mov rax, [rel boot_bg5_ready_tsc]
    mov [rbx + BC_READY], rax
    mov rax, [rel boot_bg5b_ack_tsc]
    mov [rbx + BC_ACK], rax
    mov rax, [rel boot_bg6_pixel_tsc]
    cmp qword [rbx + BC_PRESENTATION], PRESENTATION_CLI
    jne .pixel
    mov rax, [rel boot_p7_tsc]
.pixel:
    mov [rbx + BC_PIXEL], rax
    mov edi, BOOT_TIMELINE_ID_INPUT_KBD_LIVE
    call bg_timeline_tsc
    mov [rbx + BC_KBD], rax
    mov edi, BOOT_TIMELINE_ID_INPUT_PTR_LIVE
    call bg_timeline_tsc
    mov [rbx + BC_PTR], rax
    mov rcx, [rbx + BC_KBD]
    test rcx, rcx
    jz .input
    test rax, rax
    jz .kbd
    cmp rax, rcx
    jbe .input
.kbd:
    mov rax, rcx
.input:
    mov [rbx + BC_INPUT], rax
    mov rax, [rel udp_first_reply_tsc]
    mov [rbx + BC_UDP], rax
    ; Existing first-arrival timeline facts only: serviced listener and unlocked
    ; visible/bound GUI Terminal with keyboard route live. No readiness policy.
    mov edi, BOOT_TIMELINE_ID_SSH_READY
    call bg_timeline_tsc
    mov [rbx + BC_SSH], rax
    mov edi, BOOT_TIMELINE_ID_TERMINAL_USABLE
    call bg_timeline_tsc
    mov [rbx + BC_TERMINAL], rax
    ; Presence is published after raw stamps, and retained across link changes.
    ; Capture both flags and raw values in the fixed double-collect comparison.
    movzx eax, byte [rel boot_nic_ready_observed]
    mov [rbx + BC_NIC_PRESENT], rax
    mov rax, [rel boot_nic_ready_tsc]
    mov [rbx + BC_NIC], rax
    movzx eax, byte [rel boot_hv_foundation_ready]
    mov [rbx + BC_FOUNDATION_PRESENT], rax
    mov rax, [rel boot_hv_foundation_ready_tsc]
    mov [rbx + BC_FOUNDATION], rax
    mov rax, [rel boot_native_cost_tsc + 0]
    mov [rbx + BC_COST_PAIRS + 0], rax
    mov rax, [rel boot_native_cost_tsc + 8]
    mov [rbx + BC_COST_PAIRS + 8], rax
    mov rax, [rel boot_native_cost_tsc + 16]
    mov [rbx + BC_COST_PAIRS + 16], rax
    mov rax, [rel boot_native_cost_tsc + 24]
    mov [rbx + BC_COST_PAIRS + 24], rax
    mov rax, [rel boot_native_cost_tsc + 32]
    mov [rbx + BC_COST_PAIRS + 32], rax
    mov rax, [rel boot_native_cost_tsc + 40]
    mov [rbx + BC_COST_PAIRS + 40], rax
    mov rax, [rel boot_native_cost_tsc + 48]
    mov [rbx + BC_COST_PAIRS + 48], rax
    mov rax, [rel boot_native_cost_tsc + 56]
    mov [rbx + BC_COST_PAIRS + 56], rax
    mov rax, [rel boot_native_cost_tsc + 64]
    mov [rbx + BC_COST_PAIRS + 64], rax
    mov rax, [rel boot_native_cost_tsc + 72]
    mov [rbx + BC_COST_PAIRS + 72], rax
    mov rax, [rel boot_native_cost_done + 0]
    mov [rbx + BC_COST_DONE + 0], rax
    mov rax, [rel boot_native_cost_done + 8]
    mov [rbx + BC_COST_DONE + 8], rax
    mov rax, [rel boot_native_cost_done + 16]
    mov [rbx + BC_COST_DONE + 16], rax
    mov rax, [rel boot_native_cost_done + 24]
    mov [rbx + BC_COST_DONE + 24], rax
    mov rax, [rel boot_native_cost_done + 32]
    mov [rbx + BC_COST_DONE + 32], rax
    ; Read only retained one-shot producer facts. Preload publishes its exit
    ; stamp last (after its outcome); zero exit is absent/unfinished, never an
    ; inferred completion from a start/outcome alone. A valid zero duration has
    ; equal nonzero endpoints and remains independently present.
    mov rax, [rel ucp_tsc_start]
    mov [rbx + BC_CPU_COST_PAIRS], rax
    mov rax, [rel ucp_tsc_end]
    mov [rbx + BC_CPU_COST_PAIRS + 8], rax
    xor edx, edx
    test rax, rax
    setnz dl
    mov [rbx + BC_CPU_COST_DONE], rdx
    ; Deployed checked BSP publishes MCB_DONE after staging its final stamp.
    ; Compatibility-prefix observation is elapsed attempt time only, not a
    ; claim that any update succeeded, or that checked I/O completed.
    mov rax, [rel mcb_state + MCB_TSC_START]
    mov [rbx + BC_CPU_COST_PAIRS + 16], rax
    mov rax, [rel mcb_state + MCB_TSC_END]
    mov [rbx + BC_CPU_COST_PAIRS + 24], rax
    mov eax, [rel mcb_state + MCB_DONE]
    mov [rbx + BC_CPU_COST_DONE + 8], rax
    ; v5 settled producers: raw stamp and state per slot, inside the compare.
    xor ecx, ecx
.settle:
    lea rax, [rel boot_settle_tsc]
    mov rax, [rax + rcx*8]
    mov [rbx + rcx*8 + BC_SETTLE_TSC], rax
    lea rax, [rel boot_settle_state]
    movzx eax, byte [rax + rcx]
    mov [rbx + rcx*8 + BC_SETTLE_STATE], rax
    inc ecx
    cmp ecx, BC_SETTLE_SLOTS
    jb .settle
    ; v6: first lease the command layer projected and armed (dhcp_wire_mark_bound).
    mov edi, BOOT_TIMELINE_ID_DHCP_BOUND
    call bg_timeline_tsc
    mov [rbx + BC_DHCP], rax
    pop rbx
    ret

; RDI=caller-owned BC_SIZE bytes. Two fixed collects, no retry/poll/producer
; locks. Reject any differing fact, invalid bounded record metadata, changed
; calibration or regressed sample. Only nonvolatile GPRs are preserved here.
; Producers publish once on the BSP; this is a checked observation window,
; not an ABA-proof transaction against arbitrary concurrent memory writes.
boot_clock_snapshot:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, BC_SIZE
    mov rbx, rdi
    mov r14, rsp
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r12, rax
    call boot_clock_collect
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r13, rax
    mov rdi, r14
    call boot_clock_collect
    mov [rbx + BC_NOW], r13
    mov [rbx + BC_BEGIN], r12
    mov qword [rbx + BC_STATUS], BC_CHANGED
    mov rdi, rbx
    mov rsi, r14
    mov ecx, BC_COMPARE_BYTES / 8
.compare:
    mov rax, [rdi]
    cmp rax, [rsi]
    jne .out
    add rdi, 8
    add rsi, 8
    dec ecx
    jnz .compare
    mov qword [rbx + BC_STATUS], BC_STATE_INVALID
    cmp qword [rbx + BC_NIC_PRESENT], 1
    ja .out
    cmp qword [rbx + BC_FOUNDATION_PRESENT], 1
    ja .out
    cmp qword [rbx + BC_COST_DONE + 0], 1
    ja .out
    cmp qword [rbx + BC_COST_DONE + 8], 1
    ja .out
    cmp qword [rbx + BC_COST_DONE + 16], 1
    ja .out
    cmp qword [rbx + BC_COST_DONE + 24], 1
    ja .out
    cmp qword [rbx + BC_COST_DONE + 32], 1
    ja .out
    cmp qword [rbx + BC_CPU_COST_DONE + 8], 1
    ja .out
    cmp qword [rbx + BC_SETTLE_STATE + 0], 1   ; cpus and census are always required
    ja .out
    cmp qword [rbx + BC_SETTLE_STATE + 8], 2
    ja .out
    cmp qword [rbx + BC_SETTLE_STATE + 16], 1
    ja .out
    cmp qword [rbx + BC_SETTLE_STATE + 24], 2
    ja .out
    cmp qword [rbx + BC_TIMELINE_COUNT], BOOT_TIMELINE_MAX
    ja .out
    cmp qword [rbx + BC_PRESENTATION], PRESENTATION_CLI
    ja .out
    mov qword [rbx + BC_STATUS], BC_CAL_INVALID
    cmp qword [rbx + BC_SOURCE], TSC_CAL_SOURCE_CPUID15
    ja .out
    cmp qword [rbx + BC_REASON], TSC_CAL_REASON_IMPLAUS_HIGH
    ja .out
    cmp qword [rbx + BC_SOURCE], TSC_CAL_SOURCE_CPUID15
    jne .origin
    cmp qword [rbx + BC_REASON], TSC_CAL_REASON_NONE
    jne .out
.origin:
    mov qword [rbx + BC_STATUS], BC_ORIGIN_MISSING
    cmp qword [rbx + BC_ORIGIN], 0
    je .out
    mov qword [rbx + BC_STATUS], BC_UNCALIBRATED
    cmp qword [rbx + BC_SCALE], 0
    je .out
    mov qword [rbx + BC_STATUS], BC_REGRESSED
    cmp r13, r12
    jb .out
    cmp r12, [rbx + BC_ORIGIN]
    jb .out
    cmp r13, [rbx + BC_ORIGIN]
    jb .out
    mov qword [rbx + BC_STATUS], BC_OK
.out:
    mov rax, [rbx + BC_STATUS]
    add rsp, BC_SIZE
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI=actual boot_tsc_end. Shared capture + converter, legacy invalid0.
; Preserves flags/DF and all GPRs except RAX/RCX/RDX; no FP instructions.
boot_clock_boot_ms:
    pushfq
    push rbx
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    sub rsp, BC_SIZE
    mov rbx, rdi
    mov rdi, rsp
    call boot_clock_snapshot
    mov rdi, rbx
    mov rsi, [rsp + BC_ORIGIN]
    mov rdx, [rsp + BC_SCALE]
    mov rcx, [rsp + BC_NOW]
    mov r8d, 1
    mov r9d, [rsp + BC_STATUS]
    call boot_clock_ms_checked
    add rsp, BC_SIZE
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rbx
    popfq
    ret

; NULL/empty or 1..64 ASCII token bytes: letters, digits, . _ : - .
; No timestamps/selectors supplied by caller; no whitespace/control reflection.
boot_clock_nonce:
    xor eax, eax
    test rdi, rdi
    jz .out
    mov ecx, BC_NONCE_MAX + 1
.scan:
    movzx edx, byte [rdi]
    test edx, edx
    jz .out
    dec ecx
    jz .bad
    cmp dl, '0'
    jb .punct
    cmp dl, '9'
    jbe .next
    cmp dl, 'A'
    jb .punct
    cmp dl, 'Z'
    jbe .next
    cmp dl, 'a'
    jb .punct
    cmp dl, 'z'
    jbe .next
.punct:
    cmp dl, '.'
    je .next
    cmp dl, '_'
    je .next
    cmp dl, ':'
    je .next
    cmp dl, '-'
    jne .bad
.next:
    inc rdi
    jmp .scan
.bad:
    mov eax, BC_NONCE_INVALID
.out:
    ret

; RDI=buf, RSI=full64 capacity, RDX=nonce. RAX=written length, EDX=0/10/11,
; RCX=required bytes incl NUL (0 if no usable span). Nonvolatile GPRs/FP/DF
; preserved. Too-small buffers contain explicit truncated=1 if that fits,
; otherwise empty; no partial plausible success. No writes for cap0/bad span.
boot_clock_format:
    pushfq
    cld
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, BC_SIZE + 16
    mov rbx, rsp
    mov r12, rdi
    mov r14, rdi
    mov r13, rdi
    xor r15d, r15d
    mov [rbx + BC_SIZE], rdx
    mov qword [rbx + BC_SIZE + 8], BC_OK
    test rdi, rdi
    jz .no_span
    test rsi, rsi
    jz .no_span
    add r13, rsi
    jc .no_span
    dec r13
    mov byte [r12], 0
    mov rdi, rdx
    call boot_clock_nonce
    test eax, eax
    jz .capture
    mov qword [rbx + BC_SIZE + 8], BC_NONCE_INVALID
    lea rdi, [rel str_bc_nonce_bad]
    call bc_put_str
    jmp .finish
.capture:
    mov rdi, rbx
    call boot_clock_snapshot
    lea rdi, [rel str_bc_head]
    call bc_put_str
    mov rdi, [rbx + BC_SIZE]
    test rdi, rdi
    jz .scope
    call bc_put_str
.scope:
    lea rdi, [rel str_bc_scope]
    call bc_put_str
    mov edx, [rbx + BC_STATUS]
    call bc_put_reason
    lea rdi, [rel str_bc_source]
    call bc_put_str
    lea rdi, [rel str_bc_source_unknown]
    cmp qword [rbx + BC_SOURCE], TSC_CAL_SOURCE_CPUID15
    ja .source
    lea rdi, [rel str_bc_source_pit]
    jne .source
    lea rdi, [rel str_bc_source_cpuid]
.source:
    call bc_put_str
    lea rdi, [rel str_bc_cal_reason]
    call bc_put_str
    mov rdi, [rbx + BC_REASON]
    call bc_put_dec
    lea rdi, [rel str_bc_scale]
    call bc_put_str
    mov rdi, [rbx + BC_SCALE]
    call bc_put_dec
    lea rdi, [rel str_bc_pixel_source]
    call bc_put_str
    lea rdi, [rel str_bc_pixel_unknown]
    cmp qword [rbx + BC_PRESENTATION], PRESENTATION_CLI
    ja .pixel_source
    lea rdi, [rel str_bc_pixel_gui]
    jne .pixel_source
    lea rdi, [rel str_bc_pixel_cli]
.pixel_source:
    call bc_put_str
    lea rdi, [rel str_bc_now]
    mov rsi, [rbx + BC_NOW]
    mov r8d, 1                         ; a sample was taken, even when its value0
    call bc_put_row
    lea rdi, [rel str_bc_end]
    mov rsi, [rbx + BC_END]
    call bc_put_stamp
    lea rdi, [rel str_bc_ebs]
    mov rsi, [rbx + BC_EBS]
    call bc_put_stamp
    lea rdi, [rel str_bc_ready]
    mov rsi, [rbx + BC_READY]
    call bc_put_stamp
    lea rdi, [rel str_bc_ack]
    mov rsi, [rbx + BC_ACK]
    call bc_put_stamp
    lea rdi, [rel str_bc_pixel]
    mov rsi, [rbx + BC_PIXEL]
    call bc_put_stamp
    lea rdi, [rel str_bc_kbd]
    mov rsi, [rbx + BC_KBD]
    call bc_put_stamp
    lea rdi, [rel str_bc_ptr]
    mov rsi, [rbx + BC_PTR]
    call bc_put_stamp
    lea rdi, [rel str_bc_input]
    mov rsi, [rbx + BC_INPUT]
    call bc_put_stamp
    lea rdi, [rel str_bc_udp]
    mov rsi, [rbx + BC_UDP]
    call bc_put_stamp
    lea rdi, [rel str_bc_ssh]
    mov rsi, [rbx + BC_SSH]
    call bc_put_stamp
    lea rdi, [rel str_bc_terminal]
    mov rsi, [rbx + BC_TERMINAL]
    call bc_put_stamp
    lea rdi, [rel str_bc_nic]
    mov rsi, [rbx + BC_NIC]
    xor r8d, r8d
    cmp qword [rbx + BC_NIC_PRESENT], 0
    setne r8b
    call bc_put_row
    lea rdi, [rel str_bc_foundation]
    mov rsi, [rbx + BC_FOUNDATION]
    xor r8d, r8d
    cmp qword [rbx + BC_FOUNDATION_PRESENT], 0
    setne r8b
    call bc_put_row
    lea rdi, [rel str_bc_hv_cost]
    mov esi, 0
    call bc_put_cost
    lea rdi, [rel str_bc_nic_cost]
    mov esi, 1
    call bc_put_cost
    lea rdi, [rel str_bc_vtd_cost]
    mov esi, 2
    call bc_put_cost
    lea rdi, [rel str_bc_amdvi_cost]
    mov esi, 3
    call bc_put_cost
    lea rdi, [rel str_bc_airlock_cost]
    mov esi, 4
    call bc_put_cost
    lea rdi, [rel str_bc_cpus]
    mov esi, 0
    call bc_put_settle
    lea rdi, [rel str_bc_storage]
    mov esi, 1
    call bc_put_settle
    lea rdi, [rel str_bc_census]
    mov esi, 2
    call bc_put_settle
    lea rdi, [rel str_bc_checks]
    mov esi, 3
    call bc_put_settle
    lea rdi, [rel str_bc_settled]
    call bc_put_settled
    lea rdi, [rel str_bc_dhcp]
    mov rsi, [rbx + BC_DHCP]
    call bc_put_stamp
    lea rdi, [rel str_bc_ucp_cost]
    mov esi, 5
    call bc_put_cost
    lea rdi, [rel str_bc_bsp_cost]
    mov esi, 6
    call bc_put_cost
    lea rdi, [rel str_bc_complete]
    call bc_put_str
.finish:
    lea rcx, [r15 + 1]
    mov rax, r14
    sub rax, r12
    cmp rax, r15
    jne .truncated
    mov edx, [rbx + BC_SIZE + 8]
    jmp .out
.truncated:
    mov r10, rcx
    mov byte [r12], 0
    xor eax, eax
    mov rcx, r13
    sub rcx, r12
    inc rcx
    cmp rcx, BC_TRUNCATED_BYTES
    jb .short
    lea rsi, [rel str_bc_truncated]
    mov rdi, r12
    mov ecx, BC_TRUNCATED_BYTES
    rep movsb
    mov eax, BC_TRUNCATED_BYTES - 1
.short:
    mov rcx, r10
    mov edx, BC_TRUNCATED
    jmp .out
.no_span:
    xor eax, eax
    xor ecx, ecx
    mov edx, BC_TRUNCATED
.out:
    add rsp, BC_SIZE + 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    popfq
    ret

; Formatting cursor is entirely caller-stack/register owned; canonical fmt_dec
; is integer-only. Count the required length even when capacity is exhausted.
bc_put_str:
    mov al, [rdi]
    test al, al
    jz .out
    inc r15
    cmp r14, r13
    jae .next
    mov [r14], al
    inc r14
.next:
    inc rdi
    jmp bc_put_str
.out:
    mov byte [r14], 0
    ret

bc_put_dec:
    sub rsp, 32
    mov rsi, rsp
    call fmt_dec
    mov rdi, rsp
    call bc_put_str
    add rsp, 32
    ret

bc_put_reason:
    lea rdi, [rel str_bc_changed]
    cmp edx, BC_OK
    jne .missing
    lea rdi, [rel str_bc_ok]
    jmp bc_put_str
.missing:
    cmp edx, BC_NOT_REACHED
    jne .uncal
    lea rdi, [rel str_bc_missing]
    jmp bc_put_str
.uncal:
    cmp edx, BC_UNCALIBRATED
    jne .origin
    lea rdi, [rel str_bc_uncal]
    jmp bc_put_str
.origin:
    cmp edx, BC_ORIGIN_MISSING
    jne .regressed
    lea rdi, [rel str_bc_origin]
    jmp bc_put_str
.regressed:
    cmp edx, BC_REGRESSED
    jne .future
    lea rdi, [rel str_bc_regressed]
    jmp bc_put_str
.future:
    cmp edx, BC_FUTURE
    jne .cal
    lea rdi, [rel str_bc_future]
    jmp bc_put_str
.cal:
    cmp edx, BC_CAL_INVALID
    jne .state
    lea rdi, [rel str_bc_cal_invalid]
    jmp bc_put_str
.state:
    cmp edx, BC_STATE_INVALID
    jne .emit
    lea rdi, [rel str_bc_state_invalid]
.emit:
    jmp bc_put_str

bc_put_stamp:
    xor r8d, r8d
    test rsi, rsi
    setnz r8b
    jmp bc_put_row

; Row is present/reason/ms. Invalid durations are always0 and independently
; typed; equal-origin and sub-ms durations are present/ok/0.
bc_put_row:
    push rsi
    push r8
    call bc_put_str
    mov rdi, [rsp]
    call bc_put_dec
    lea rdi, [rel str_bc_slash]
    call bc_put_str
    mov rdi, [rsp + 8]
    mov r8, [rsp]
    mov rsi, [rbx + BC_ORIGIN]
    mov rdx, [rbx + BC_SCALE]
    mov rcx, [rbx + BC_NOW]
    mov r9d, [rbx + BC_STATUS]
    call boot_clock_ms_checked
    push rax
    call bc_put_reason
    lea rdi, [rel str_bc_slash]
    call bc_put_str
    pop rdi
    call bc_put_dec
    add rsp, 16
    ret

str_irq0_verb: db "IRQ0OBS",0
str_irq0_head: db "IRQ0OBS v=1 nonce=",0
str_irq0_build: db " build=",0
str_irq0_boot: db " boot_nonce=",0
str_irq0_state: db " state=",0
str_irq0_result: db " result=",0
str_irq0_before: db " before=",0
str_irq0_after: db " after=",0
str_irq0_nonce_bad: db "IRQ0OBS refused=nonce",0
str_irq0_truncated: db "IRQ0OBS truncated=1",0
str_irq0_truncated_end:
str_bc_verb: db "BOOTCLOCK",0
str_bc_head: db "BOOTCLOCK v=7 nonce=",0
str_bc_scope: db " origin=efi-entry unit=ms resolution=tsc-khz-floor clock=",0
str_bc_source: db " source=",0
str_bc_source_pit: db "pit",0
str_bc_source_cpuid: db "cpuid15",0
str_bc_source_unknown: db "unknown",0
str_bc_cal_reason: db " cal_reason=",0
str_bc_scale: db " ticks_per_ms=",0
str_bc_pixel_source: db " pixel_source=",0
str_bc_pixel_gui: db "signin",0
str_bc_pixel_cli: db "cli-login",0
str_bc_pixel_unknown: db "unknown",0
str_bc_now: db " now=",0
str_bc_end: db " boot_end=",0
str_bc_ebs: db " ebs=",0
str_bc_ready: db " ready=",0
str_bc_ack: db " ack=",0
str_bc_pixel: db " pixel=",0
str_bc_kbd: db " kbd=",0
str_bc_ptr: db " ptr=",0
str_bc_input: db " input=",0
str_bc_udp: db " udp=",0
str_bc_ssh: db " ssh=",0
str_bc_terminal: db " terminal=",0
str_bc_nic: db " nic=",0
str_bc_foundation: db " foundation=",0
str_bc_slash: db "/",0
str_bc_ok: db "ok",0
str_bc_missing: db "not-reached",0
str_bc_uncal: db "uncalibrated",0
str_bc_origin: db "origin-missing",0
str_bc_regressed: db "regressed",0
str_bc_future: db "future",0
str_bc_changed: db "snapshot-changed",0
str_bc_cal_invalid: db "calibration-invalid",0
str_bc_state_invalid: db "state-invalid",0
str_bc_nonce_bad: db "BOOTCLOCK refused=nonce",0
str_bc_complete: db " truncated=0",0
str_bc_truncated: db "BOOTCLOCK truncated=1",0
str_bc_truncated_end:
%if str_bc_truncated_end - str_bc_truncated != BC_TRUNCATED_BYTES
    %error "BOOTCLOCK truncated marker length drift"
%endif

str_bc_hv_cost: db " hv_cost=",0
str_bc_nic_cost: db " nic_cost=",0
str_bc_vtd_cost: db " vtd_cost=",0
str_bc_amdvi_cost: db " amdvi_cost=",0
str_bc_airlock_cost: db " airlock_cost=",0
str_bc_cpus: db " cpus=",0
str_bc_storage: db " storage=",0
str_bc_census: db " census=",0
str_bc_checks: db " checks=",0
str_bc_settled: db " settled=",0
str_bc_dhcp: db " dhcp=",0
str_bc_ucp_cost: db " ucp_cost=",0
str_bc_bsp_cost: db " bsp_cost=",0
str_bc_not_required_row: db "0/not-required/0",0

; RDI=key, ESI=settled producer slot0..3. Complete = present raw stamp through
; the shared checked converter; pending = not-reached; not-required is typed
; explicitly, but only on a valid clock (otherwise the common reason wins).
bc_put_settle:
    mov rax, [rbx + rsi*8 + BC_SETTLE_STATE]
    cmp rax, 2
    jne .row
    cmp qword [rbx + BC_STATUS], BC_OK
    jne .row
    call bc_put_str
    lea rdi, [rel str_bc_not_required_row]
    jmp bc_put_str
.row:
    xor r8d, r8d
    cmp rax, 1
    sete r8b
    mov rsi, [rbx + rsi*8 + BC_SETTLE_TSC]
    jmp bc_put_row

; RDI=key. Settled is present only when every producer is decided (complete or
; not-required); cpus and census are always required, so one has completed. Its
; stamp is the latest complete raw TSC. A complete stamp before origin is carried
; instead, so the converter reports it regressed rather than a later one hiding it.
bc_put_settled:
    xor r8d, r8d
    xor esi, esi
    xor ecx, ecx
.decided:
    cmp qword [rbx + rcx*8 + BC_SETTLE_STATE], 0
    je bc_put_row                        ; a pending producer: settled not reached
    inc ecx
    cmp ecx, BC_SETTLE_SLOTS
    jb .decided
    xor ecx, ecx
.scan:
    cmp qword [rbx + rcx*8 + BC_SETTLE_STATE], 1
    jne .next
    mov r8d, 1
    mov rdx, [rbx + rcx*8 + BC_SETTLE_TSC]
    cmp rdx, [rbx + BC_ORIGIN]
    jb .early
    cmp rdx, rsi
    jbe .next
    mov rsi, rdx
.next:
    inc ecx
    cmp ecx, BC_SETTLE_SLOTS
    jb .scan
    jmp bc_put_row
.early:
    mov rsi, rdx
    jmp bc_put_row

; RDI=coherent private snapshot, ESI=fixed cost slot0..6. RAX=floor ms,
; EDX=reason, R8D=completion presence. Never subtract independently rounded
; milestone ms. Snapshot validation owns common origin/calibration/sample facts.
boot_clock_cost_checked:
    xor r8d, r8d
    xor eax, eax
    mov edx, BC_STATE_INVALID
    cmp esi, 7
    jae .out
    lea r10, [rdi + BC_COST_PAIRS]
    lea r11, [rdi + BC_COST_DONE]
    cmp esi, 5
    jb .slot
    sub esi, 5
    lea r10, [rdi + BC_CPU_COST_PAIRS]
    lea r11, [rdi + BC_CPU_COST_DONE]
.slot:
    cmp qword [r11 + rsi*8], 0
    setne r8b
    mov edx, [rdi + BC_STATUS]
    test edx, edx
    jnz .out
    mov edx, BC_NOT_REACHED
    test r8, r8
    jz .out
    shl esi, 4
    mov r11, [r10 + rsi + 8]
    mov r10, [r10 + rsi]
    mov edx, BC_REGRESSED
    cmp r10, [rdi + BC_ORIGIN]
    jb .out
    cmp r11, r10
    jb .out
    mov edx, BC_FUTURE
    cmp r11, [rdi + BC_NOW]
    ja .out
    mov rax, r11
    sub rax, r10
    xor edx, edx
    div qword [rdi + BC_SCALE]
    xor edx, edx
.out:
    ret

; RDI=key, ESI=fixed slot. Same public present/reason/ms grammar; the key
; identifies elapsed call time, not a timestamp or readiness/guest verdict.
bc_put_cost:
    push rsi
    call bc_put_str
    pop rsi
    mov rdi, rbx
    call boot_clock_cost_checked
    push rax
    push rdx
    mov rdi, r8
    call bc_put_dec
    lea rdi, [rel str_bc_slash]
    call bc_put_str
    pop rdx
    call bc_put_reason
    lea rdi, [rel str_bc_slash]
    call bc_put_str
    pop rdi
    jmp bc_put_dec


; Bounded one-use custody only; existing registry/admission and clock producers
; are unchanged. Serialized BSP request lifetime, not an authority token.
boot_clock_reply_begin:
    sub rsp, 8
    call boot_clock_reply_retire
    add rsp, 8
    cmp qword [rel bc_reply_generation], -1
    je .out                              ; never reuse a wrapped generation
    inc qword [rel bc_reply_generation]
    lea rdi, [rel bc_reply_req]
    mov rsi, rbx
    mov ecx, REQ_SZ
    rep movsb
    mov rsi, [rbx + REQ_ARG]
    test rsi, rsi
    jz .identity                         ; NULL and empty are native-valid
    lea rdi, [rel bc_reply_arg]
    mov ecx, BC_NONCE_MAX + 1
.arg:
    lodsb
    stosb
    test al, al
    jz .identity
    loop .arg
    ret                                  ; unterminated/overlong: not publishable
.identity:
    lea rsi, [rel paos_build_hex]
    lea rdi, [rel bc_reply_build]
    mov ecx, 64
    rep movsb
    mov eax, [rel boot_nonce]
    mov [rel bc_reply_boot], eax
    mov byte [rel bc_reply_valid], 2       ; captured, not yet published
.out:
    ret

boot_clock_reply_publish:
    cmp byte [rel bc_reply_valid], 2
    jne .out
    cmp qword [rel bc_reply_len], AUTH_OUT_MAX
    jae .invalid
    lea rsi, [rel command_auth_out_buf]
    lea rdi, [rel bc_reply_body]
    mov rcx, [rel bc_reply_len]
    inc rcx                              ; own the exact terminating NUL too
    rep movsb
    mov rsi, r12
    lea rdi, [rel bc_reply_rsp]
    mov ecx, RSP_SZ
    rep movsb
    mov byte [rel bc_reply_valid], 1
.out:
    ret
.invalid:
    mov byte [rel bc_reply_valid], 0
    ret

boot_clock_reply_retire:
    lea rdi, [rel bc_reply_req]
    xor eax, eax
    mov ecx, REQ_SZ + 65 + 64 + 4 + RSP_SZ + 8 + 1280 + 1
    rep stosb
    ret
