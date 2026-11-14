;; MODULE gui/form_events
;; LAYER 6
;; EXPORTS form_events_declare, form_events_name_valid, form_events_bind, form_events_reset, form_events_click, form_events_wait, form_events_cmd, form_events_configure_guest, form_events_lifetime, form_events_first_begin
;; IMPORTS gui/widget, gui/window, gui/window_mgmt, gui/chat_app, sec/session, sec/principal, hv/guest_request, svc/command, core/time, core/lib/str, core/lib/mem
;; CAPS
;; OWNER saga:gui_foundation_ladder
;
; T6-3: data events, never button-to-command dispatch. BSP-only; neither click
; nor WAIT yields or spins. An authorized caller polls a bounded pending wait.
; The widget hook observes only a successful left-button hit, before the stock
; click chain. It never records input values, labels, keys or pointer reports.

FE_NAME_MAX equ 32
FE_RING equ 8
FE_ROW_SZ equ 80                     ; sequence, monotonic us, action[32], id[32]
FE_OWNER equ 0
FE_IDENT equ 8
FE_EPOCH equ 16
FE_SEQ equ 24
FE_TOKEN equ 32
FE_CURSOR equ 40
FE_DEADLINE equ 48
FE_ACTIVE equ 56
FE_GEN equ 64
FE_FIRST_BEGIN equ 72               ; native accepted guest BEGIN, monotonic us
FE_ROWS equ 80
FE_SZ equ FE_ROWS + FE_RING * FE_ROW_SZ
FE_READY equ 0
FE_PENDING equ 1
FE_EVENT equ 2
FE_TIMEOUT equ 3
FE_CANCELLED equ 4
FE_OVERRUN equ 5
FE_BUSY equ 6
FE_MAX_MS equ 5000
FE_KEY_SZ equ 136                    ; subject[120], policy generation, token

form_events_declare:
    lea  rax, [rel form_events_click]
    mov  [rel wgt_form_event_hook], rax
    lea  rax, [rel form_events_reset]
    mov  [rel wmx_owner_reset_op], rax
    lea  rdi, [rel fe_verb]
    lea  rsi, [rel form_events_cmd]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    xor  r9d, r9d
    jmp  command_register_verb         ; existing non-public auth floor

; RDI cstr -> EAX 0 valid, 1 invalid. ASCII identifier, 1..31 bytes.
form_events_name_valid:
    xor  ecx, ecx
    test rdi, rdi
    jz   .bad
.next:
    movzx eax, byte [rdi + rcx]
    test eax, eax
    jz   .end
    cmp  ecx, FE_NAME_MAX-1
    jae  .bad
    cmp  al, '_'
    je   .yes
    cmp  al, 'A'
    jb   .digit
    cmp  al, 'Z'
    jbe  .yes
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'z'
    jbe  .yes
.digit:
    test ecx, ecx
    jz   .bad
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    ja   .bad
.yes:
    inc  ecx
    jmp  .next
.end:
    test ecx, ecx
    jz   .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

; EDI slot -> RAX state (0 if not live/owned or locked), ECX window-id.
; Reconcile first: lock/rebind epoch or slot reuse destroys old events/waits.
; No owner override; ownership authorization is done by the consumer below.
fe_context:
    xor  eax, eax
    jmp  fe_context_start
; Private entry only after exact-request native resolution; no ambient bypass.
fe_guest_context:
    mov  eax, 1
fe_context_start:
    push rbx
    push r12
    push r13
    push r14
    mov  ebx, edi
    cmp  ebx, WM_MAX
    jae  .no
    cmp  qword [rel tsc_khz], 0
    je   .no
    test eax, eax
    jnz  .read
    call session_shell_require_unlocked
    test eax, eax
    jnz  .no
.read:
    mov  edi, ebx
    call wmx_window_id
    test eax, eax
    jz   .no
    mov  r12d, eax
    lea  rax, [rel wm_gen]
    mov  r14d, [rax + rbx*4]             ; full raw32, not packed/truncated
    lea  rax, [rel wm_owner]
    mov  r13, [rax + rbx*8]
    test r13, r13
    jz   .no
    cmp  r13, WM_OWNER_CHROME
    je   .no
    call principal_execution_snapshot   ; only its epoch, never ambient PID
    test rdx, rdx
    jz   .no
    cmp  rdx, -1
    je   .no
    imul ebx, FE_SZ
    lea  rax, [rel fe_windows]
    add  rbx, rax
    cmp  [rbx + FE_OWNER], r13
    jne  .reset
    cmp  [rbx + FE_IDENT], r12
    jne  .reset
    cmp  [rbx + FE_GEN], r14
    jne  .reset
    cmp  [rbx + FE_EPOCH], rdx
    je   .have
.reset:
    push rdx
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, FE_SZ
    call memset
    pop  rdx
    mov  [rbx + FE_OWNER], r13
    mov  [rbx + FE_IDENT], r12
    mov  [rbx + FE_EPOCH], rdx
    mov  [rbx + FE_GEN], r14
.have:
    mov  ecx, r12d
    mov  rax, rbx
    jmp  .out
.no:
    xor  eax, eax
    xor  ecx, ecx
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI widget, RSI optional on_click. Called on EVERY form allocation after the
; stable WGI_ID is installed; null clears a recycled binding. Fields are copied
; out of parser scratch. Binding grants nothing and does not invoke the name.
form_events_bind:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13, rsi
    cmp  r12d, WGT_MAX
    jae  .out
    mov  ebx, r12d
    shl  ebx, 6
    lea  rax, [rel fe_bindings]
    add  rbx, rax
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, 64
    call memset
    test r13, r13
    jz   .out
    mov  rdi, r13
    call form_events_name_valid
    test eax, eax
    jnz  .out
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], WGT_TYPE_BUTTON
    jne  .out
    mov  r14, [rax + WGI_ID]
    test r14, r14
    jz   .out
    mov  edi, [rax + WGI_WIN]
    call fe_context
    test rax, rax
    jz   .out
    mov  [rbx], r14
    mov  rdx, [rax + FE_OWNER]
    mov  [rbx + 8], rdx
    mov  [rbx + 16], rcx
    mov  rdx, [rax + FE_GEN]
    mov  [rbx + 24], rdx
    lea  rdi, [rbx + 32]
    mov  rsi, r13
    call fe_copy_name
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Zero-fill first: the canonical bounded copy does not clear a prior tail.
fe_copy_name:
    push rdi
    push rsi
    xor  esi, esi
    mov  edx, FE_NAME_MAX
    call memset
    pop  rsi
    pop  rdi
    mov  edx, FE_NAME_MAX
    jmp  strcpy_s

; Called once before materializing a fresh/replacement form, including adopted
; shells. It retires undisclosed events and tokens even if owner/gen are kept.
form_events_reset:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    cmp  edi, WM_MAX
    jae  .out
    mov  ebx, edi
    lea  rax, [rel fe_reset_serial]
    cmp  qword [rax + rbx*8], -1
    je   .serial_closed
    inc  qword [rax + rbx*8]          ; saturation permanently closes guest scope
.serial_closed:
    imul edi, FE_KEY_SZ
    lea  rax, [rel fe_guest_keys]
    add  rdi, rax
    xor  esi, esi
    mov  edx, FE_KEY_SZ
    call memset
    mov  edi, ebx
    imul edi, FE_SZ
    lea  rax, [rel fe_windows]
    add  rdi, rax
    xor  esi, esi
    mov  edx, FE_SZ
    call memset
    lea  r12, [rel fe_bindings]
.next:
    movzx eax, byte [r12 + 16]         ; window slot from binding identity
    cmp  eax, ebx
    jne  .skip
    mov  rdi, r12
    xor  esi, esi
    mov  edx, 64
    call memset
.skip:
    add  r12, 64
    lea  rax, [rel fe_bindings + WGT_MAX * 64]
    cmp  r12, rax
    jb   .next
.out:
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

; Native-only initialization: resolver(exact request)->RAX read-only160B
; APP_GRANTS descriptor, RDX current nonzero policy generation. Both refer to
; native enforced identity, never guest fields. Missing resolver always DENY.
; Reconfiguration retires every event handle/binding before changing the seam.
form_events_configure_guest:
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .busy
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
.next:
    mov  edi, ebx
    call form_events_reset
    inc  ebx
    cmp  ebx, WM_MAX
    jb   .next
    mov  [rel fe_guest_resolver], r12
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.busy:
    xor  eax, eax
    ret

; Native metadata only, no authority: exact window ID -> reset lifetime or0.
; Zero-initialized counter denotes lifetime1. Every synchronous reset advances
; it, including same-owner stamps and raw generation aliases; never wraps.
form_events_lifetime:
    push rbx
    mov  ebx, edi
    movzx edi, bl
    call wmx_window_id
    cmp  eax, ebx
    jne  .no
    test eax, eax
    jz   .no
    movzx ebx, bl
    lea  rax, [rel fe_reset_serial]
    mov  rax, [rax + rbx*8]
    inc  rax
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Native read-only observation. RDI=exact packed window, RSI=reset lifetime,
; RDX=full enforced app principal -> first accepted guest BEGIN time, or0.
; No command/guest setter, no authorization and no local WAIT substitution.
; The normal context reconciliation clears this field on epoch/gen/owner drift.
form_events_first_begin:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12,rsi
    mov r13,rdx
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    test r12,r12
    jz .bad
    call form_events_lifetime
    cmp rax,r12
    jne .bad
    movzx edi,bl
    call fe_context
    test rax,rax
    jz .bad
    cmp ecx,ebx
    jne .bad
    cmp [rax+FE_OWNER],r13
    jne .bad
    mov rax,[rax+FE_FIRST_BEGIN]
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Protect our result registers against the maintained clock's R8 divisor and
; tsc_now scratch footprint. No timing implementation is duplicated here.
fe_now:
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    call time_monotonic_now_us
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    ret

; EDI hit widget; stock hit-test/physical routing already happened. Recheck
; live button, visible/enabled, binding and current lifetime before publishing.
form_events_click:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  edi, WGT_MAX
    jae  .out
    mov  r12d, edi
    call wgt_slot_ptr
    mov  r14, rax
    cmp  dword [r14 + WGI_TYPE], WGT_TYPE_BUTTON
    jne  .out
    test dword [r14 + WGI_FLAGS], 1
    jz   .out
    test dword [r14 + WGI_EDIT], WGT_EDIT_DISABLED
    jnz  .out
    mov  r13d, r12d
    shl  r13d, 6
    lea  rax, [rel fe_bindings]
    add  r13, rax
    cmp  byte [r13 + 32], 0
    je   .out
    mov  rax, [r14 + WGI_ID]
    test rax, rax
    jz   .out
    cmp  [r13], rax
    jne  .out
    mov  edi, [r14 + WGI_WIN]
    call fe_context
    test rax, rax
    jz   .out
    mov  rbx, rax
    cmp  [r13 + 16], rcx
    jne  .out
    mov  rax, [rbx + FE_GEN]
    cmp  [r13 + 24], rax
    jne  .out
    mov  rax, [rbx + FE_OWNER]
    cmp  [r13 + 8], rax
    jne  .out
    mov  r15, [rbx + FE_SEQ]
    cmp  r15, -1                       ; saturate, never wrap a cursor
    je   .out
    mov  eax, r15d
    and  eax, FE_RING-1
    imul eax, FE_ROW_SZ
    lea  r12, [rbx + rax + FE_ROWS]
    inc  r15
    mov  [r12], r15
    call fe_now
    mov  [r12 + 8], rax
    lea  rdi, [r12 + 16]
    lea  rsi, [r13 + 32]
    call fe_copy_name
    lea  rdi, [r12 + 48]
    mov  rsi, [r14 + WGI_ID]
    call fe_copy_name
    mov  [rbx + FE_SEQ], r15            ; publish only after the row is complete
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Native core: EDI op(0 STATUS,1 BEGIN,2 POLL,3 CANCEL), ESI exact window-id,
; RDX cursor/token, RCX timeout-ms, R8 full verified request principal.
; EAX CMDE, EDX FE state, R8 token, R9 cursor/sequence, R10 event row or0.
; One pending wait per window, fixed8 rows, no spin/sleep/scheduler allocation.
; Completion consumes token. A delayed poll cannot receive a post-deadline hit.
form_events_wait:
    xor  r9d, r9d
    jmp  fe_wait_common
; Private exact-request guest entry, parsed by the ONE maintained handler.
fe_wait_guest:
fe_wait_common:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 192
    mov  [rsp + 176], r8                ; verified PID
    mov  [rsp + 168], r9                ; exact native request or0
    mov  r12d, edi
    mov  r15d, esi
    mov  r13, rdx
    mov  r14, rcx
    cmp  r12d, 3
    ja   .bad
    test r8, r8
    jz   .deny
    test r9, r9
    jz   .local_context
    cmp  qword [r9 + REQ_SOURCE], CMD_SOURCE_GUEST
    jne  .deny
    cmp  [r9 + REQ_PRINCIPAL], r8
    jne  .deny
    mov  rax, [rel fe_guest_resolver]
    test rax, rax
    jz   .deny
    mov  rdi, r9
    call rax
    test rax, rax
    jz   .deny
    test rdx, rdx
    jz   .deny
    mov  [rsp + 160], rdx
    mov  rsi, rax
    mov  rdi, rsp
    mov  ecx, 20
    rep  movsq                          ; private descriptor, no retained pointer
    cmp  qword [rsp], 1
    jne  .deny
    mov  rax, [rsp + 176]
    cmp  [rsp + 8], rax
    jne  .deny
    cmp  [rsp + 48], rax
    jne  .deny
    mov  eax, r12d
    inc  eax
    cmp  [rsp + 120], rax
    jne  .deny
    mov  eax, r15d
    cmp  [rsp + 56], rax
    jne  .deny
    cmp  [rsp + 136], r13
    jne  .deny
    cmp  [rsp + 144], r14
    jne  .deny
    cmp  qword [rsp + 152], 0
    jne  .deny
    mov  rax, [rsp + 168]
    mov  rax, [rax + REQ_IDEM]
    test rax, rax
    jz   .deny
    cmp  [rsp + 128], rax
    jne  .deny
    mov  edi, r15d
    call form_events_lifetime
    test rax, rax
    jz   .deny
    cmp  [rsp + 72], rax
    jne  .deny
    movzx edi, r15b
    call fe_guest_context
    jmp  .context
.local_context:
    movzx edi, r15b
    call fe_context
.context:
    test rax, rax
    jz   .deny
    mov  rbx, rax
    cmp  ecx, r15d
    jne  .deny
    mov  rax, [rsp + 176]
    cmp  [rbx + FE_OWNER], rax           ; full64, no PRIN_OWNER exception
    jne  .deny
    cmp  qword [rsp + 168], 0
    je   .authorized
    mov  rax, [rbx + FE_EPOCH]
    cmp  [rsp + 40], rax
    jne  .deny
    mov  rax, [rbx + FE_GEN]
    cmp  [rsp + 64], rax
    jne  .deny
    movzx eax, r15b
    imul eax, FE_KEY_SZ
    lea  rdx, [rel fe_guest_keys]
    add  rax, rdx
    mov  [rsp + 184], rax
    mov  rdi, [rsp + 168]
    call guest_request_revalidate       ; FINAL proof before state read/effect
    test eax, eax
    jnz  .deny
    mov  rdi, [rsp + 184]
    cmp  qword [rbx + FE_ACTIVE], 1
    jne  .authorized
    mov  rax, [rbx + FE_TOKEN]
    cmp  [rdi + 128], rax
    jne  .retire_mismatch
    mov  rsi, rsp
    mov  ecx, 15                       ; stable subject excludes typed operation
    repe cmpsq
    jne  .retire_mismatch
    mov  rax, [rsp + 160]
    cmp  [rdi], rax                     ; policy generation includes all revokes
    je   .authorized
.retire_mismatch:
    mov  qword [rbx + FE_ACTIVE], 0
    mov  rdi, [rsp + 184]
    xor  esi, esi
    mov  edx, FE_KEY_SZ
    call memset
    cmp  r12d, 1
    ja   .deny
.authorized:
    xor  r10d, r10d
    mov  r9, [rbx + FE_SEQ]
    xor  r8d, r8d
    xor  edx, edx                      ; STATUS = READY/current cursor
    test r12d, r12d
    jz   .ok
    cmp  r12d, 1
    je   .begin
    cmp  qword [rbx + FE_ACTIVE], 1
    jne  .bad
    test r13, r13
    jz   .bad
    cmp  [rbx + FE_TOKEN], r13
    jne  .bad
    mov  r8, r13
    cmp  r12d, 3
    jne  .evaluate
    mov  qword [rbx + FE_ACTIVE], 0
    mov  edx, FE_CANCELLED
    jmp  .ok
.begin:
    cmp  r14, FE_MAX_MS
    ja   .bad
    cmp  r13, r9
    ja   .bad
    call fe_now
    cmp  qword [rbx + FE_ACTIVE], 1
    jne  .new
    cmp  rax, [rbx + FE_DEADLINE]
    jb   .busy
.new:
    imul r14, 1000
    add  r14, rax
    jc   .bad
    cmp  qword [rel fe_next_token], -1
    je   .bad
    inc  qword [rel fe_next_token]
    mov  r8, [rel fe_next_token]
    cmp  qword [rsp + 168], 0
    je   .local_token
    mov  rdi, [rsp + 184]
    mov  rsi, rsp
    mov  ecx, 15                       ; first120 subject excludes typed operation
    rep  movsq
    mov  rax, [rsp + 160]
    mov  [rdi], rax
    mov  [rdi + 8], r8
.local_token:
    mov  [rbx + FE_TOKEN], r8
    mov  [rbx + FE_DEADLINE], r14
    mov  [rbx + FE_CURSOR], r13
    mov  qword [rbx + FE_ACTIVE], 1
    cmp  qword [rsp + 168], 0           ; only the fully admitted guest path
    je   .evaluate
    cmp  qword [rbx + FE_FIRST_BEGIN], 0
    jne  .evaluate
    call fe_now                         ; accepted token, not STATUS/BUSY/refusal
    mov  [rbx + FE_FIRST_BEGIN], rax
.evaluate:
    mov  r13, [rbx + FE_CURSOR]
    mov  r9, [rbx + FE_SEQ]
    mov  rax, r9
    sub  rax, r13
    cmp  rax, FE_RING
    ja   .overrun
    test rax, rax
    jz   .clock
    mov  eax, r13d
    and  eax, FE_RING-1
    imul eax, FE_ROW_SZ
    lea  r10, [rbx + rax + FE_ROWS]
    mov  rax, [r10 + 8]
    cmp  rax, [rbx + FE_DEADLINE]
    ja   .timeout
    mov  r9, [r10]
    mov  edx, FE_EVENT
    jmp  .complete
.clock:
    call fe_now
    cmp  rax, [rbx + FE_DEADLINE]
    jae  .timeout
    mov  edx, FE_PENDING
    jmp  .ok
.timeout:
    xor  r10d, r10d
    mov  edx, FE_TIMEOUT
    jmp  .complete
.overrun:
    mov  edx, FE_OVERRUN
.complete:
    mov  qword [rbx + FE_ACTIVE], 0
    jmp  .ok
.busy:
    xor  r8d, r8d
    mov  edx, FE_BUSY
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, CMDE_BADARG
    jmp  .error
.deny:
    mov  eax, CMDE_AUTHDENY
.error:
    xor  edx, edx
    xor  r8d, r8d
    xor  r9d, r9d
    xor  r10d, r10d
.out:
    add  rsp, 192
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Parse a canonical unsigned decimal at RSI, to whitespace/end. EAX status,
; RDX value, RSI next byte. Refuses overflow and leading zeros. No mutation of
; the request text; no unbounded strlen, no generic command execution.
fe_number:
    xor  edx, edx
    cmp  byte [rsi], '0'
    jb   .bad
    cmp  byte [rsi], '9'
    ja   .bad
    cmp  byte [rsi], '0'
    jne  .digit
    mov  al, [rsi + 1]
    cmp  al, '0'
    jb   .digit
    cmp  al, '9'
    jbe  .bad
.digit:
    movzx eax, byte [rsi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .end
    mov  r11, 1844674407370955161
    cmp  rdx, r11
    ja   .bad
    jne  .add
    cmp  eax, 5
    ja   .bad
.add:
    imul rdx, 10
    add  rdx, rax
    inc  rsi
    jmp  .digit
.end:
    cmp  byte [rsi], 0
    je   .ok
    cmp  byte [rsi], ' '
    jne  .bad
.ok:
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

; WAIT STATUS id | BEGIN id cursor ms | POLL id token | CANCEL id token.
; Request principal is resolved through the maintained authenticated-frame
; helper, not REQ_PRINCIPAL borrowed from an unsigned remote frame.
form_events_cmd:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    mov  r12, rdi
    mov  r13, rsi
    call chat_out_reset
    mov  byte [rel chat_out_ready], 0
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    mov  qword [r13 + RSP_VAL], 0
    mov  rsi, [r12 + REQ_ARG]
    test rsi, rsi
    jz   .out
    ; The longest accepted command is well under96 bytes. Bound even malformed
    ; input before prefix reads, parsing or output; there is no shared scratch.
    xor  ecx, ecx
.length:
    cmp  ecx, 96
    jae  .out
    cmp  byte [rsi + rcx], 0
    je   .op
    inc  ecx
    jmp  .length
.op:
    xor  r14d, r14d
    lea  rbx, [rel fe_ops]
.find:
    mov  rdi, [rbx + r14*8]
    ; Image-relative differences, never low flat-image dq symbol addresses.
    add  rdi, rbx
    mov  rsi, [r12 + REQ_ARG]
.match:
    mov  al, [rdi]
    test al, al
    jz   .matched
    cmp  al, [rsi]
    jne  .next_op
    inc  rdi
    inc  rsi
    jmp  .match
.next_op:
    inc  r14d
    cmp  r14d, 4
    jb   .find
    jmp  .out
.matched:
    call fe_number
    test eax, eax
    jnz  .out
    mov  rax, rdx
    shr  rax, 32
    jnz  .out
    mov  [rsp], rdx                     ; window-id
    mov  qword [rsp + 8], 0
    mov  qword [rsp + 16], 0
    test r14d, r14d
    jz   .end
    cmp  byte [rsi], ' '
    jne  .out
    inc  rsi
    call fe_number
    test eax, eax
    jnz  .out
    mov  [rsp + 8], rdx                 ; cursor/token
    cmp  r14d, 1
    jne  .end
    cmp  byte [rsi], ' '
    jne  .out
    inc  rsi
    call fe_number
    test eax, eax
    jnz  .out
    mov  [rsp + 16], rdx                ; timeout
.end:
    cmp  byte [rsi], 0
    jne  .out
    cmp  qword [r12 + REQ_SOURCE], CMD_SOURCE_GUEST
    je   .guest
    mov  rdi, r12
    call session_shell_request_principal
    mov  r8, rax
    mov  edi, r14d
    mov  esi, [rsp]
    mov  rdx, [rsp + 8]
    mov  rcx, [rsp + 16]
    call form_events_wait
    mov  [r13 + RSP_CODE], rax
    test eax, eax
    jnz  .out
    mov  [r13 + RSP_VAL], rdx
    mov  [rsp + 24], rdx
    mov  [rsp + 32], r8
    mov  [rsp + 40], r9
    mov  r15, r10
    lea  rdi, [rel fe_reply]
    call chat_put_str
    mov  rdi, [rsp + 24]
    call chat_put_dec
    lea  rdi, [rel fe_id]
    call chat_put_str
    mov  rdi, [rsp]
    call chat_put_dec
    lea  rdi, [rel fe_token]
    call chat_put_str
    mov  rdi, [rsp + 32]
    call chat_put_dec
    lea  rdi, [rel fe_seq]
    call chat_put_str
    mov  rdi, [rsp + 40]
    call chat_put_dec
    test r15, r15
    jz   .ready
    lea  rdi, [rel fe_action]
    call chat_put_str
    lea  rdi, [r15 + 16]
    call chat_put_str
    lea  rdi, [rel fe_widget]
    call chat_put_str
    lea  rdi, [r15 + 48]
    call chat_put_str
.ready:
    mov  byte [rel chat_out_ready], 1
    jmp  .out
.guest:
    mov  r8, [r12 + REQ_PRINCIPAL]
    mov  r9, r12
    mov  edi, r14d
    mov  esi, [rsp]
    mov  rdx, [rsp + 8]
    mov  rcx, [rsp + 16]
    call fe_wait_guest
    mov  [r13 + RSP_CODE], rax
    test eax, eax
    jnz  .out
    mov  [rsp + 24], rdx
    mov  rdi, r12
    mov  esi, edx
    mov  rdx, r8
    mov  rcx, r9
    mov  r8, r10
    call guest_request_capture_wait
    test eax, eax
    jnz  .capture_refused
    mov  rax, [rsp + 24]
    mov  [r13 + RSP_VAL], rax
    jmp  .out
.capture_refused:
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
.out:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fe_verb: db 'WAIT',0
fe_ops: dq fe_status-fe_ops, fe_begin-fe_ops, fe_poll-fe_ops, fe_cancel-fe_ops
fe_status: db 'STATUS ',0
fe_begin: db 'BEGIN ',0
fe_poll: db 'POLL ',0
fe_cancel: db 'CANCEL ',0
fe_reply: db 'WAIT v=1 state=',0
fe_id: db ' window=',0
fe_token: db ' token=',0
fe_seq: db ' seq=',0
fe_action: db ' action=',0
fe_widget: db ' widget=',0

%include "core/abi/wdata.inc"
%macro WDATA_form_events 0
alignb 8
fe_next_token: resq 1
fe_guest_resolver: resq 1
fe_reset_serial: resq WM_MAX
fe_guest_keys: resb (WM_MAX * FE_KEY_SZ)
fe_windows: resb (WM_MAX * FE_SZ)
fe_bindings: resb (WGT_MAX * 64)
%endmacro
WDATA_BSS_DEFER WDATA_form_events
