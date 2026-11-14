;; MODULE sec/principal_probe
;; LAYER 5
;; EXPORTS principal_probe_request_append, principal_probe_row
;; IMPORTS sec/principal, svc/command
;; CAPS
;; OWNER saga:sec
; Observation only. The original request remains on the handler stack. No
; principal, ticket, key, capability, row, session or replay state is changed.
principal_probe_request_append:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel str_pr_probe_source]
    call prin_out_str
    mov  rdi, [rbx + REQ_SOURCE]
    call prin_out_dec
    lea  rdi, [rel str_pr_probe_principal]
    call prin_out_str
    mov  rdi, [rbx + REQ_PRINCIPAL]
    call prin_out_dec
    pop  rbx
    ret
str_pr_probe_source: db " request_source=",0
str_pr_probe_principal: db " request_principal=",0

; RDI=actual request, R14=requested target. Separate bounded diagnostic rows;
; no unknown/unbound actor, no foreign read or write, no ambient-PID fallback.
principal_probe_row:
    xor  eax, eax
    cmp  r14, [rdi + REQ_PRINCIPAL]
    jne  .out
    cmp  r14, PRIN_OWNER
    je   .owner
    cmp  r14, PRIN_SYSTEM
    jne  .out
    lea  rax, [rel prin_system_row]
    ret
.owner:
    lea  rax, [rel prin_row_pid]
.out:
    ret
