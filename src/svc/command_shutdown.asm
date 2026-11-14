;; MODULE svc/command_shutdown
;; LAYER 5
;; EXPORTS command_shutdown_request, command_shutdown_take, command_shutdown_failed, command_power_return_bootwin, command_power_return_commit, command_power_return_trace, command_power_return_ahci, command_power_return_nvme, command_power_return_nvme_lifetime, command_power_return_nvme_completion, command_power_return_nic, command_power_return_nic_warm, command_power_return_native_nic, command_power_return_work, command_power_return_pci, command_power_return_usb, command_power_return_event, command_power_return_local_begin, command_power_return_local_answer, command_power_return_terminal, power_button_presses_routed, power_button_presses_logged
;; IMPORTS core/lib/fmt, boot/header, boot/beacon, core/build_id, svc/command_auth, boot/boot_v2_handoff, boot/boot_v2_health, boot/serial, core/time
;; CAPS
;; OWNER saga:rc_power
; ============================================================================
; svc/command_shutdown.asm: the remote, owner-signed power-off request (RCQ-27).
;
; The root-authorized S5 windows need a remote way to reach ACPI S5; REBOOT
; only warm-resets. svc/command_udp routes the pre-registry intercept
;
;   SHUTDOWN <nonce> [force-trial]
;
; here after command_auth_route_gate admitted it (exact cap MUTATE, replay
; floor consumed). This module decides and stages the reply; it never powers
; anything off. gui/power_button's idle-loop tick takes an accepted request
; only after the UDP frame that carried "SHUTDOWN accepted <nonce>" has
; returned, and runs power_execute(POWER_SHUTDOWN): exactly the Start > Power
; path (storage quiesce, ACPI S5, else firmware shutdown, else stays up).
;
; Refusals (one reply line each, no state change):
;   grammar        nonce 1..32 of [0-9A-Za-z_-], then nothing or " force-trial"
;   owner          the gate-consumed ticket does not name OWNER. The gate alone
;                  is not enough: PRIN_SYSTEM_CAPS includes MUTATE.
;   busy           another nonce is accepted and not yet resolved
;   trial-pending  this boot is a Boot-v2 Trial whose strong health is not yet
;                  published (power-off now would count as a failed Trial);
;                  "force-trial" in the signed line overrides
; One shot per nonce: the nonce of the last accepted request never executes
; twice. Repeating it reports its state: "accepted <nonce> pending" or
; "failed <nonce> <reason>" (power_execute returned, nothing was powered off).
; A new nonce may be accepted after a failure.
; ============================================================================
SD_NONCE_MAX   equ 32
SD_IDLE        equ 0
SD_PENDING     equ 1                    ; accepted, not yet taken by the tick
SD_EXECUTING   equ 2                    ; the tick is running power_execute
SD_FAILED      equ 3                    ; power_execute returned: sd_reason says why

; command_shutdown_request(RDI = argument text) -> RAX = the reply line (NUL-
;   terminated, in sd_out_buf). Called inside the UDP request bracket, after the
;   route gate. Preserves RBX, R12-R15.
command_shutdown_request:
    push rbx
    push r12
    mov  rbx, rdi
    lea  rax, [rel sd_out_buf]
    mov  [rel sd_out_cur], rax
    lea  rdi, [rel sd_s_head]           ; "SHUTDOWN "
    call sd_out_str
    mov  rdi, rbx
    call command_power_return_request  ; finite opt-in return plan; no effect here
    test rax, rax
    jnz  .out
    ; --- grammar: <nonce> [force-trial] ---
    xor  ecx, ecx
.nonce:
    movzx eax, byte [rbx + rcx]
    call sd_nonce_char
    jc   .nonce_end
    cmp  ecx, SD_NONCE_MAX
    jae  .grammar
    lea  rdx, [rel sd_req_nonce]
    mov  [rdx + rcx], al
    inc  ecx
    jmp  .nonce
.nonce_end:
    test ecx, ecx
    jz   .grammar
    lea  rdx, [rel sd_req_nonce]
    mov  byte [rdx + rcx], 0
    mov  byte [rel sd_req_force], 0
    lea  rsi, [rbx + rcx]
    cmp  byte [rsi], 0
    je   .parsed
    lea  rdi, [rel sd_s_force_arg]      ; " force-trial", exactly, then the end
    call sd_streq
    test eax, eax
    jz   .grammar
    mov  byte [rel sd_req_force], 1
.parsed:
    call command_auth_owner_request     ; 0 = no owner authority in THIS request
    test eax, eax
    jz   .owner
    ; --- one shot per nonce ---
    cmp  byte [rel sd_state], SD_IDLE
    je   .fresh
    lea  rdi, [rel sd_req_nonce]
    lea  rsi, [rel sd_nonce]
    call sd_streq
    test eax, eax
    jz   .other_nonce
    cmp  byte [rel sd_state], SD_FAILED
    je   .report_failed
    lea  rdi, [rel sd_s_accepted]       ; "accepted "
    call sd_out_str
    lea  rdi, [rel sd_nonce]
    call sd_out_str
    lea  rdi, [rel sd_s_pending]        ; " pending"
    call sd_out_str
    jmp  .out
.report_failed:
    lea  rdi, [rel sd_s_failed]         ; "failed "
    call sd_out_str
    lea  rdi, [rel sd_nonce]
    call sd_out_str
    lea  rdi, [rel sd_s_space]
    call sd_out_str
    mov  rdi, [rel sd_reason]
    call sd_out_line                    ; reason text up to its CR/LF
    jmp  .out
.other_nonce:
    cmp  byte [rel sd_state], SD_FAILED
    jne  .busy                          ; pending or executing: one at a time
.fresh:
    call command_power_return_busy
    test eax, eax
    jnz  .busy
    ; --- Boot-v2 Trial still pending its strong-health checkpoint ---
    cmp  byte [rel sd_req_force], 1
    je   .accept
    cmp  byte [rel pbm_manager_launch], 1
    jne  .accept
    cmp  byte [rel pbm_reason], PBM_REASON_TRIAL
    jne  .accept
    cmp  byte [rel pbm_strong_health_published], 1
    jne  .trial
.accept:
    lea  rdi, [rel sd_nonce]
    lea  rsi, [rel sd_req_nonce]
    mov  ecx, SD_NONCE_MAX + 1
.copy:
    mov  al, [rsi]
    mov  [rdi], al
    inc  rsi
    inc  rdi
    dec  ecx
    jnz  .copy
    mov  al, [rel sd_req_force]
    mov  [rel sd_force], al
    mov  qword [rel sd_reason], 0
    mov  byte [rel sd_state], SD_PENDING
    mov  byte [rel sd_kind], 3          ; legacy SHUTDOWN keeps POWER_SHUTDOWN
    inc  dword [rel sd_accepted_count]
    lea  rdi, [rel sd_s_accepted]
    call sd_out_str
    lea  rdi, [rel sd_nonce]
    call sd_out_str
    lea  rdi, [rel sd_s_log_accepted]   ; "[PAOS64] power.remote.shutdown accepted nonce="
    call serial_string
    lea  rdi, [rel sd_nonce]
    call serial_string
    lea  rdi, [rel sd_s_log_force]      ; " force_trial="
    call serial_string
    movzx edi, byte [rel sd_force]
    call serial_hex64
    lea  rdi, [rel sd_s_crlf]
    call serial_string
    jmp  .out
.grammar:
    lea  r12, [rel sd_s_r_grammar]
    jmp  .refused
.owner:
    lea  r12, [rel sd_s_r_owner]
    jmp  .refused
.busy:
    lea  r12, [rel sd_s_r_busy]
    jmp  .refused
.trial:
    lea  r12, [rel sd_s_r_trial]
.refused:
    inc  dword [rel sd_refused_count]
    lea  rdi, [rel sd_s_refused]        ; "refused "
    call sd_out_str
    mov  rdi, r12
    call sd_out_str
.out:
    lea  rax, [rel sd_out_buf]
    pop  r12
    pop  rbx
    ret

; command_shutdown_take -> EAX 1 when an accepted request was waiting (it is
;   now EXECUTING), else 0. EDX = actual POWER_RESTART(2)/SHUTDOWN(3).
command_shutdown_take:
    xor  eax, eax
    cmp  byte [rel sd_state], SD_PENDING
    jne  .out
    mov  byte [rel sd_state], SD_EXECUTING
    mov edi,2
    call command_power_return_event
    movzx edx, byte [rel sd_kind]
    mov  eax, 1
.out:
    ret

; command_shutdown_failed(RDI = power_execute's reason text): nothing powered
;   off. The nonce now reports "failed <nonce> <reason>".
command_shutdown_failed:
    push rdi
    mov edi,7
    call command_power_return_event
    pop rdi
    mov byte [rel pr_state],PR_EXPIRED ; returned executor cannot label a later request
    mov  [rel sd_reason], rdi
    mov  byte [rel sd_state], SD_FAILED
    ret

; AL = byte -> CF clear when it is a nonce character [0-9A-Za-z_-].
sd_nonce_char:
    cmp  al, '-'
    je   .yes
    cmp  al, '_'
    je   .yes
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .yes
    cmp  al, 'A'
    jb   .no
    cmp  al, 'Z'
    jbe  .yes
    cmp  al, 'a'
    jb   .no
    cmp  al, 'z'
    jbe  .yes
.no:
    stc
    ret
.yes:
    clc
    ret

; sd_streq(RDI, RSI) -> EAX 1 when the two NUL-terminated strings are equal.
sd_streq:
    xor  ecx, ecx
.l:
    mov  al, [rdi + rcx]
    cmp  al, [rsi + rcx]
    jne  .ne
    test al, al
    jz   .eq
    inc  ecx
    cmp  ecx, 64
    jb   .l
.ne:
    xor  eax, eax
    ret
.eq:
    mov  eax, 1
    ret

; sd_out_str(RDI = cstr): append, bounded by sd_out_buf; clobbers RAX, RDX, RDI.
sd_out_str:
    mov  rdx, [rel sd_out_cur]
.l:
    lea  rax, [rel sd_out_buf + SD_OUT_MAX - 1]
    cmp  rdx, rax
    jae  .d
    mov  al, [rdi]
    test al, al
    jz   .d
    mov  [rdx], al
    inc  rdx
    inc  rdi
    jmp  .l
.d:
    mov  byte [rdx], 0
    mov  [rel sd_out_cur], rdx
    ret

; sd_out_line(RDI = cstr or 0): append up to the first CR/LF/NUL.
sd_out_line:
    test rdi, rdi
    jz   .unknown
    mov  rdx, [rel sd_out_cur]
.l:
    lea  rax, [rel sd_out_buf + SD_OUT_MAX - 1]
    cmp  rdx, rax
    jae  .d
    mov  al, [rdi]
    test al, al
    jz   .d
    cmp  al, 13
    je   .d
    cmp  al, 10
    je   .d
    mov  [rdx], al
    inc  rdx
    inc  rdi
    jmp  .l
.d:
    mov  byte [rdx], 0
    mov  [rel sd_out_cur], rdx
    ret
.unknown:
    lea  rdi, [rel sd_s_unknown]
    jmp  sd_out_str

SD_OUT_MAX equ 160
sd_s_head:          db "SHUTDOWN ", 0
sd_s_force_arg:     db " force-trial", 0
sd_s_accepted:      db "accepted ", 0
sd_s_pending:       db " pending", 0
sd_s_failed:        db "failed ", 0
sd_s_space:         db " ", 0
sd_s_unknown:       db "unknown", 0
sd_s_refused:       db "refused ", 0
sd_s_r_grammar:     db "grammar SHUTDOWN <nonce 1..32 of 0-9A-Za-z_-> [force-trial]", 0
sd_s_r_owner:       db "owner (the owner principal only; MUTATE alone is not enough)", 0
sd_s_r_busy:        db "busy (another nonce is accepted and not yet resolved)", 0
sd_s_r_trial:       db "trial-pending (Boot-v2 Trial before strong health; sign force-trial to override)", 0
sd_s_log_accepted:  db "[PAOS64] power.remote.shutdown accepted nonce=", 0
sd_s_log_force:     db " force_trial=", 0
sd_s_crlf:          db 13, 10, 0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
%macro WDATA_svc_command_shutdown_0 0
alignb 8
sd_out_cur:         resq 1
sd_reason:          resq 1
; Generic button policy owns increments; this shared service owns observation storage.
power_button_presses_routed: resd 1
power_button_presses_logged: resd 1
sd_accepted_count:  resd 1
sd_refused_count:   resd 1
sd_state:           resb 1
sd_force:           resb 1
sd_req_force:       resb 1
sd_kind:            resb 1
sd_nonce:           resb SD_NONCE_MAX + 1
sd_req_nonce:       resb SD_NONCE_MAX + 1
sd_out_buf:         resb SD_OUT_MAX
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_shutdown_0
%if SD_IDLE != 0
    %error "sd_state is zero-filled: SD_IDLE must stay 0"
%endif

%include "svc/command_power_return.inc"
%include "svc/command_power_pci.inc"
%include "svc/command_power_usb.inc"
