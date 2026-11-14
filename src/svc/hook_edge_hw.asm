;; MODULE svc/hook_edge_hw
;; LAYER 5
;; EXPORTS hook_hw_edge_declare, hook_hw_plan, hook_hw_post
;; IMPORTS core/lib/fmt, svc/command, svc/command_hook, svc/command_compat, svc/hw_report
;; CAPS
;; OWNER saga:live
; ============================================================================
; svc/hook_edge_hw.asm -- RCQ-29: the typed `hw` HOOK edge over the hardware
; report (svc/hw_report), registered from its owner's module (rc-ai 2026-10-08).
;
;   hw  (device)  the hardware report   native COMPAT <nonce> HW [<class>]
;
;   GET     hw            COMPAT <nonce> HW            (the summary)
;   GET     hw:<class>    COMPAT <nonce> HW <class>    (summary cpu gpu nic storage usb input battery)
;   LIST    hw            COMPAT <nonce> HW summary    (names every class and its counts)
;   OBSERVE hw[:<class>]  the GET, answered as a witness over the record
;   SET / INPUT / CANCEL  "hook na": the report is read-only
;
; As every edge, this one only PLANS: svc/command_hook dispatches COMPAT with
; the caller's own source, principal, capability and idempotency key, so the
; native verb decides. COMPAT HW itself asks a remote caller for an owner
; envelope and stays public locally; the edge adds nothing to that.
;
; The nonce is this edge's own boot-local counter (16 hex), a correlation token
; COMPAT echoes and nothing else. The post filter stages the record's body, the
; hw_report text after "COMPAT nonce=<n>" (" hw=<class> ..."), as the hook reply:
;   * the UDP reply chain sends compat_out_buf only under a COMPAT verb, so
;     under HOOK the record would otherwise never reach the caller (the hook
;     reply follows the UDP status line, as every hook answer does), and
;   * OBSERVE hashes the staged reply whole, so a witness changes only when the
;     report does, never on the next request's nonce.
; The record is staged only when the native verb accepted the request and the
; record carries exactly the nonce this request planned; a native refusal
; passes through as COMPAT's own code and hint. Nothing else is rewritten.
; ============================================================================

; The staged hook reply is a suffix of the COMPAT record, so it always fits the
; hook buffer: assemble-time check (a negative count fails the build).
hhw_fits_hook_out equ HOOK_OUT_MAX - COMPAT_HW_CAP

; hook_hw_edge_declare -- bind the descriptor (lea at init, ESSENCE S10) and
;   register it after the RCQ-15 edges. clobbers: caller-saved.
hook_hw_edge_declare:
    push rbx
    lea  rbx, [rel hook_edge_hw]
    lea  rax, [rel str_hhw_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hhw_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hhw_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_hw_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_hw_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0         ; the post filter's staged record is the only reply
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0      ; hash that whole record (it carries no nonce)
    mov  rdi, rbx
    call command_hook_edge_register
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; hw edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
; ---------------------------------------------------------------------------
hook_hw_plan:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    cmp  ebx, HOP_GET
    je   .get
    cmp  ebx, HOP_LIST
    je   .list
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.list:
    cmp  byte [r12], 0
    jne  .bad                             ; LIST takes no instance
    lea  r12, [rel str_hhw_summary]
    jmp  .args
.get:
    cmp  byte [r12], 0
    je   .args                            ; GET hw: the summary
    mov  rdi, r12
    call hw_report_class_id               ; exactly one class name
    cmp  eax, -1
    je   .bad
.args:
    cmp  byte [r13], 0
    jne  .bad                             ; no argument after the instance
    call command_hook_arg_reset
    call hhw_arg_nonce
    lea  rdi, [rel str_hhw_word_hw]
    call command_hook_arg_str
    cmp  byte [r12], 0
    je   .verb
    lea  rdi, [rel str_hhw_sp]
    call command_hook_arg_str
    mov  rdi, r12
    call command_hook_arg_str
.verb:
    lea  rax, [rel str_verb_compat]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; hhw_arg_nonce -- append a fresh 16-hex nonce to the planned argument.
;   clobbers: caller-saved.
hhw_arg_nonce:
    mov  rdi, [rel hhw_nonce_ctr]
    inc  rdi
    mov  [rel hhw_nonce_ctr], rdi
    lea  rsi, [rel hhw_nonce_buf]
    mov  edx, 16
    call fmt_hex
    lea  rdi, [rel hhw_nonce_buf]
    jmp  command_hook_arg_str

; hook_hw_post(EDI op, RSI inst, RDX rest, RCX rsp) -> EAX 1 = the COMPAT record's
;   body staged as the hook reply, 0 = nothing staged.
;   clobbers: caller-saved.
hook_hw_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .none                            ; a refusal passes through unchanged
    cmp  byte [rel compat_out_ready], 1
    jne  .none
    lea  rdi, [rel compat_out_buf]
    lea  rsi, [rel str_hhw_head]
    call hhw_skip_prefix                  ; "COMPAT nonce="
    test rax, rax
    jz   .none
    mov  rdi, rax
    lea  rsi, [rel hhw_nonce_buf]
    call hhw_skip_prefix                  ; exactly this request's nonce
    test rax, rax
    jz   .none
    cmp  byte [rax], ' '
    jne  .none
    push rax                              ; " hw=<class> ..."
    mov  byte [rel compat_out_ready], 0   ; consumed: the hook reply carries it
    call command_hook_out_reset
    pop  rdi
    call command_hook_out_str
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

; hhw_skip_prefix(RDI = cstr, RSI = prefix) -> RAX = RDI past the prefix, or 0.
;   clobbers: RAX, RCX, RDX
hhw_skip_prefix:
    xor  ecx, ecx
.l:
    movzx edx, byte [rsi + rcx]
    test edx, edx
    jz   .yes
    cmp  dl, [rdi + rcx]
    jne  .no
    inc  ecx
    jmp  .l
.yes:
    lea  rax, [rdi + rcx]
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
str_hhw_name:     db "hw", 0
str_hhw_kind:     db "device", 0
str_hhw_schema:   db "inst=none|summary|cpu|gpu|nic|storage|usb|input|battery|system|memory get=COMPAT <nonce> HW [<inst>](remote: owner envelope){hw=<class>,...; the record after its nonce; system=retained BIOS only; memory=retained DIMMs+EFI type totals, not allocator free} list=COMPAT <nonce> HW summary observe=that record set=na input=na cancel=na", 0
str_hhw_summary:  db "summary", 0
str_hhw_word_hw:  db " HW", 0
str_hhw_sp:       db " ", 0
str_hhw_head:     db "COMPAT nonce=", 0

align 8
hook_edge_hw:     times (HE_SZ / 8) dq 0
hhw_nonce_ctr:    dq 0
hhw_nonce_buf:    times 24 db 0
hhw_fits:         times hhw_fits_hook_out db 0
