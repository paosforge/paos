;; MODULE svc/command_srvstat
;; LAYER 5
;; EXPORTS command_srvstat_init, command_srvstat_report_ready, cmd_verb_srvstat, str_verb_srvstat, srvstat_out_buf, srvstat_out_ready
;; IMPORTS boot/serial, boot/paging, core/heap, core/lib/fmt, lib/safe_buffer, net/dns, svc/command, svc/command_auth, svc/command_udp, svc/command_fs
;; CAPS
;; OWNER saga:headless_file_server
; Task3040: one public registry verb, one complete bounded semantic record.
; Diagnostic self-attestation only: RAM is sampled unallocated allocator space,
; NET counters use STATUS's reply-member software statistics (or unknown), and policy is read from
; the live auth classifier. None of these independently proves a capability.
; No allocator, FS resolver, boot-target setting, or bulk-session state is owned
; here. Task2505/HF1/HF3 replace only their respective field providers below.
;
; Grammar: SRVSTAT [nonce], nonce = 1..64 ASCII alnum / '.' / '_' / '-'.
; Omitted nonce is ARG=none. No whitespace, controls, field injection, or partial
; success on refusal. Every append is bounded; publish only after the entire
; record fits. UDP consumes this staged record through its ordinary reply path.

SRVSTAT_NONCE_MAX equ 64
SRVSTAT_OUT_CAP   equ 1024
srvstat_image_begin:

; Ordinary registry initialization, before other services add their rows.
command_srvstat_init:
    sub  rsp, 8
    lea  rdi, [rel str_verb_srvstat]
    lea  rsi, [rel cmd_verb_srvstat]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    xor  r9d, r9d
    call command_register_verb
    add  rsp, 8
    ret

; Report the live public row only after the idle pump can accept requests.
; Registration runs much earlier than UDP startup; emitting there would race
; the observer's first STATUS against boot/DNS bootstrap's input gate. This
; marker still earns no wire credit: the observer must exercise the real verb.
command_srvstat_report_ready:
    cmp  byte [rel srvstat_ready_reported], 1
    je   .done
    cmp  qword [rel udp_nic_handle], 0
    je   .done
    cmp  qword [rel udp_rx_poll_fn], 0
    je   .done
    sub  rsp, 8
    call dns_wire_bootstrap_pending
    test eax, eax
    jnz  .out
    lea  rdi, [rel str_verb_srvstat]
    call command_auth_registry_name_is_public
    test eax, eax
    jz   .out
    mov  byte [rel srvstat_ready_reported], 1
    lea  rdi, [rel str_srvstat_ready]
    call serial_string
.out:
    add  rsp, 8
.done:
    ret

; cmd_verb_srvstat(RDI=request, RSI=response): validate before sampling/output.
cmd_verb_srvstat:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    sub  rsp, 48                          ; fixed offsets, no indexed stack stores
    mov  rbx, rsi
    mov  r12, [rdi + REQ_ARG]
    mov  byte [rel srvstat_out_ready], 0
    call srvstat_out_reset
    test r12, r12
    jz   .no_nonce
    mov  rdi, r12
    mov  esi, SRVSTAT_NONCE_MAX + 1
    call safe_capped_len
    test edx, edx
    jnz  .bad_nonce
    test eax, eax
    jz   .no_nonce
    mov  r13d, eax
    xor  ecx, ecx
.nonce_byte:
    movzx eax, byte [r12 + rcx]
    cmp  al, '.'
    je   .nonce_next
    cmp  al, '_'
    je   .nonce_next
    cmp  al, '-'
    je   .nonce_next
    cmp  al, '0'
    jb   .bad_nonce
    cmp  al, '9'
    jbe  .nonce_next
    or   al, 0x20
    cmp  al, 'a'
    jb   .bad_nonce
    cmp  al, 'z'
    ja   .bad_nonce
.nonce_next:
    inc  ecx
    cmp  ecx, r13d
    jb   .nonce_byte
    jmp  .sample
.no_nonce:
    lea  r12, [rel str_srvstat_none]
.sample:
    call command_udp_status_snapshot
    mov  [rsp], rax                       ; uptime seconds
    mov  [rsp + 8], rdx                   ; STATUS TX frames
    mov  [rsp + 16], rcx                  ; STATUS RX frames
    mov  [rsp + 32], r8d                 ; separate availability from u64 values
    call srvstat_ram_free_kb
    mov  [rsp + 24], rax
    lea  rdi, [rel str_srvstat_head]
    call srvstat_puts
    mov  rdi, r12
    call srvstat_puts
    lea  rdi, [rel str_srvstat_uptime]
    call srvstat_puts
    mov  rdi, [rsp]
    call srvstat_putdec
    lea  rdi, [rel str_srvstat_boot]
    call srvstat_puts
    call srvstat_boot_target
    call srvstat_puts
    lea  rdi, [rel str_srvstat_ram]
    call srvstat_puts
    mov  rdi, [rsp + 24]
    call srvstat_putdec
    lea  rdi, [rel str_srvstat_tx]
    call srvstat_puts
    mov  rdi, [rsp + 8]
    mov  esi, [rsp + 32]
    call srvstat_put_frame_count
    lea  rdi, [rel str_srvstat_rx]
    call srvstat_puts
    mov  rdi, [rsp + 16]
    mov  esi, [rsp + 32]
    call srvstat_put_frame_count
    call srvstat_share_fields
    lea  rdi, [rel str_srvstat_bulk]
    call srvstat_puts
    call srvstat_bulk_sessions
    mov  rdi, rax
    call srvstat_putdec
    ; State the measurement scope on the wire, not merely in source comments.
    lea  rdi, [rel str_srvstat_scope]
    call srvstat_puts
    call srvstat_progress_fields
    cmp  byte [rel srvstat_out_failed], 0
    jne  .bounds
    mov  qword [rbx + RSP_CODE], CMDE_OK
    mov  qword [rbx + RSP_ACCEPTED], 1
    jmp  .publish
.bad_nonce:
    lea  r13, [rel str_srvstat_bad_nonce]
    jmp  .refuse
.bounds:
    lea  r13, [rel str_srvstat_bounds]
.refuse:
    call srvstat_out_reset                 ; discard ALL partial success bytes
    mov  rdi, r13
    call srvstat_puts
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    mov  qword [rbx + RSP_EXPECTED], SRVSTAT_NONCE_MAX
    mov  [rbx + RSP_HINT], r13
.publish:
    mov  byte [rel srvstat_out_ready], 1
    mov  rax, [rbx + RSP_CODE]
    add  rsp, 48
    pop  r13
    pop  r12
    pop  rbx
    ret

; One coherent command/health observation. All fields are bounded u64 decimal;
; maximum nonce + all numeric fields at UINT64_MAX fits the 1024-byte arena.
; No diagnostic latch is consumed/reset, so a nested SRVSTAT sees itself active.
srvstat_progress_fields:
    sub  rsp, 104                        ; 96-byte snapshot + call alignment
    mov  rdi, rsp
    call command_udp_progress_snapshot
    lea  rdi, [rel str_csp_state]
    call srvstat_puts
    mov  rdi, [rsp + 0]
    call srvstat_putdec
    lea  rdi, [rel str_csp_enter]
    call srvstat_puts
    mov  rdi, [rsp + 8]
    call srvstat_putdec
    lea  rdi, [rel str_csp_done]
    call srvstat_puts
    mov  rdi, [rsp + 16]
    call srvstat_putdec
    lea  rdi, [rel str_csp_entries]
    call srvstat_puts
    mov  rdi, [rsp + 24]
    call srvstat_putdec
    lea  rdi, [rel str_csp_returns]
    call srvstat_puts
    mov  rdi, [rsp + 32]
    call srvstat_putdec
    lea  rdi, [rel str_csp_active]
    call srvstat_puts
    mov  rdi, [rsp + 40]
    call srvstat_putdec
    lea  rdi, [rel str_csp_polls]
    call srvstat_puts
    mov  rdi, [rsp + 48]
    call srvstat_putdec
    lea  rdi, [rel str_csp_rx_slot]
    call srvstat_puts
    mov  rdi, [rsp + 56]
    call srvstat_putdec
    lea  rdi, [rel str_csp_rx_gen]
    call srvstat_puts
    mov  rdi, [rsp + 64]
    call srvstat_putdec
    lea  rdi, [rel str_csp_rx_state]
    call srvstat_puts
    mov  rdi, [rsp + 72]
    call srvstat_putdec
    lea  rdi, [rel str_csp_rx_side]
    call srvstat_puts
    mov  rdi, [rsp + 80]
    call srvstat_putdec
    lea  rdi, [rel str_csp_health]
    call srvstat_puts
    mov  rdi, [rsp + 88]
    call srvstat_putdec
    add  rsp, 104
    ret

; Task2505 owns the effective boot target. No record exists in this tree yet.
srvstat_boot_target:
    lea  rdi, [rel str_srvstat_unsupported]
    ret

; HF1 owns provisioning/enforcement. Query FSREAD's actual registry metadata and
; the production classifier, so shipped owner-only vs lab legacy access remains
; honest without inventing another policy flag. A missing verb is unsupported.
srvstat_share_fields:
    sub  rsp, 8
    lea  rdi, [rel str_srvstat_share]
    call srvstat_puts
    lea  rdi, [rel str_fsread]
    call command_lookup
    cmp  eax, -1
    je   .unsupported
    mov  edi, eax
    call command_auth_registry_id_is_public
    test eax, eax
    jz   .owner
    lea  rdi, [rel str_srvstat_legacy]
    jmp  .emit
.owner:
    lea  rdi, [rel str_srvstat_owner]
    jmp  .emit
.unsupported:
    lea  rdi, [rel str_srvstat_unsupported]
.emit:
    call srvstat_puts
    add  rsp, 8
    ret

; HF3 owns bulk sessions; none are implemented yet (SCREEN is not a file stream).
srvstat_bulk_sessions:
    xor  eax, eax
    ret

; Sample the existing kernel + model allocator arenas, without allocating or
; counting firmware-map free pages which PaOS cannot currently allocate from.
; Each bump is atomic; these are observations, not a reservation or guarantee.
srvstat_ram_free_kb:
    push rbx
    mov  rdi, [rel heap_base]
    mov  rsi, [rel heap_next]
    mov  rdx, [rel heap_end]
    call srvstat_arena_free
    mov  rbx, rax
    mov  rdi, [rel model_heap_base]
    mov  rsi, [rel model_heap_next]
    mov  rdx, [rel model_heap_end]
    call srvstat_arena_free
    add  rax, rbx
    jnc  .kb
    xor  eax, eax                         ; invalid arithmetic is never free RAM
.kb:
    shr  rax, 10
    pop  rbx
    ret

; RDI=arena base, RSI=current bump, RDX=end -> RAX=allocatable remainder.
; Match the allocator's own guard invariants; a missing/degraded arena adds 0.
srvstat_arena_free:
    xor  eax, eax
    test rdi, rdi
    jz   .out
    test rsi, rsi
    jz   .out
    test sil, 15
    jnz  .out
    cmp  rsi, rdi
    jb   .out
    cmp  rsi, rdx
    ja   .out
    mov  rax, rdx
    sub  rax, rsi
.out:
    ret

srvstat_out_reset:
    mov  dword [rel srvstat_out_len], 0
    mov  byte [rel srvstat_out_buf], 0
    mov  byte [rel srvstat_out_failed], 0
    ret

; Bounded append using the shared safe-buffer primitive. Once failed, no more
; bytes are appended; the handler replaces the entire record with a refusal.
srvstat_puts:
    push rbx
    cmp  byte [rel srvstat_out_failed], 0
    jne  .out
    mov  rbx, rdi
    mov  esi, SRVSTAT_OUT_CAP
    call safe_capped_len
    test edx, edx
    jnz  .bad
    mov  rcx, rax
    mov  rdx, rbx
    mov  eax, [rel srvstat_out_len]
    cmp  eax, SRVSTAT_OUT_CAP
    jae  .bad
    lea  rdi, [rel srvstat_out_buf]
    add  rdi, rax
    mov  esi, SRVSTAT_OUT_CAP
    sub  esi, eax
    cmp  rcx, rsi                          ; includes the terminating NUL slot
    jae  .bad
    call safe_copy
    test eax, eax
    jnz  .bad
    add  [rel srvstat_out_len], edx
    jmp  .out
.bad:
    mov  byte [rel srvstat_out_failed], 1
.out:
    pop  rbx
    ret

; RDI=u64 count, ESI=0 known / -1 unavailable. Preserve legitimate UINT64_MAX.
srvstat_put_frame_count:
    test esi, esi
    jz   srvstat_putdec
    lea  rdi, [rel str_srvstat_unknown]
    jmp  srvstat_puts

srvstat_putdec:
    sub  rsp, 8
    lea  rsi, [rel srvstat_number]
    call fmt_dec                          ; at most 20 decimal digits + NUL
    lea  rdi, [rel srvstat_number]
    call srvstat_puts
    add  rsp, 8
    ret

srvstat_out_ready:  db 0
srvstat_out_failed: db 0
srvstat_ready_reported: db 0             ; diagnostic marker latch, not provider state
align 4
srvstat_out_len:    dd 0
srvstat_number:     times 24 db 0
srvstat_out_buf:    times SRVSTAT_OUT_CAP db 0
str_verb_srvstat:   db "SRVSTAT", 0
str_srvstat_head:   db "SRVSTAT OK ARG=", 0
str_srvstat_unknown: db "unknown", 0
str_srvstat_none:   db "none", 0
str_srvstat_uptime: db " UPTIME_S=", 0
str_srvstat_boot:   db " BOOT_TARGET=", 0
str_srvstat_ram:    db " RAM_FREE_KB=", 0
str_srvstat_tx:     db " NET_TX=", 0
str_srvstat_rx:     db " NET_RX=", 0
str_srvstat_share:  db " SHARE_ROOT=/SHARE SHARE_STATE=unprovisioned SHARE_POLICY=", 0
str_srvstat_bulk:   db " BULK_SESSIONS=", 0
str_srvstat_scope:  db " RAM_SCOPE=allocator_arenas NET_SOURCE=reply_member", 0
str_srvstat_unsupported: db "unsupported", 0
str_srvstat_legacy: db "legacy_unrestricted", 0
str_srvstat_owner:  db "owner_only", 0
str_srvstat_bad_nonce: db "SRVSTAT ERR reason=bad_nonce expected=1_to_64_alnum_dot_dash_underscore", 0
str_srvstat_bounds: db "SRVSTAT ERR reason=reply_bounds", 0
str_srvstat_ready:  db "[PAOS64] M2 srvstat: public bounded status verb registered PASS [srvstat.verb.ready]", 13, 10, 0
str_csp_state: db " CSP_STATE=", 0
str_csp_enter: db " CSP_ENTER=", 0
str_csp_done: db " CSP_DONE=", 0
str_csp_entries: db " CSP_ENTRIES=", 0
str_csp_returns: db " CSP_RETURNS=", 0
str_csp_active: db " CSP_ACTIVE=", 0
str_csp_polls: db " CSP_POLLS=", 0
str_csp_rx_slot: db " CSP_RX_SLOT=", 0
str_csp_rx_gen: db " CSP_RX_GEN=", 0
str_csp_rx_state: db " CSP_RX_STATE=", 0
str_csp_rx_side: db " CSP_RX_SIDE=", 0
str_csp_health: db " CSP_HEALTH=", 0
srvstat_image_end:
; Assembly fails if this module leaves insufficient room for the registry and
; projection additions within the contract's 4 KiB total growth budget.
%if (srvstat_image_end - srvstat_image_begin) + 512 > 4096
    %error "Task3040 status module and registry/UDP wiring exceed 4 KiB"
%endif
