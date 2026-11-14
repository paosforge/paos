;; MODULE gui/guest_media_producer_private
;; LAYER 6
;; EXPORTS media_guest_producer_bind, media_guest_producer_frame, media_guest_producer_retry, media_guest_producer_control, media_guest_producer_release, media_guest_producer_drop, media_guest_producer_unbind
;; IMPORTS gui/guest_media_owner_private, gui/video_player_private, media/pmr1_host_private
;; CAPS
;; OWNER rc-vm
; G3b independent W1 producer seam; unincluded/unhooked until whole owner gates.
; Sole cooperative native owner, stable owned PMH context, stopped vCPU. No
; guest address/identity is used as W1 authority. W1 owns all source readers;
; its exact ACK must succeed before the held PMH slot is released by identity.
%include "hv/guest_media_contract.inc"
%if RCQ37_MEDIA_PROFILE

; RDI must be the retained initialized owner PMH context. Refresh after a
; completed SEEK/reopen, only with no pending or W1-owned source. Refusal keeps
; prior binding intact; the receipt is identity, never admission/authority.
media_guest_producer_bind:
    push rbx
    cmp  byte [rel mgp_state], 1
    ja   .busy
    mov  rbx, rdi
    test rbx, rbx
    jz   .shape
    cmp  rbx, [rel mg_pool]
    jne  .shape
    lea  rdi, [rel mgp_receipt]
    mov  esi, 32
    call video_player_identity_receipt
    test eax, eax
    jnz  .out
    cmp  dword [rel mgp_receipt], 1
    jne  .shape
    cmp  dword [rel mgp_receipt + 4], 32
    jne  .shape
    lea  rsi, [rel mgp_receipt]
    lea  rdi, [rel mgp_identity]
    mov  ecx, 32
    cld
    rep  movsb
    mov  [rel mgp_ctx], rbx
    mov  rax, [rbx + pmh.epoch]
    mov  [rel mgp_pmh_epoch], rax
    mov  byte [rel mgp_state], 1
    xor  eax, eax
    jmp  .out
.busy:
    mov  eax, 2
    jmp  .out
.shape:
    mov  eax, 4
.out:
    pop  rbx
    ret

; EDI=native held slot0..2. Host-only staged FRAME128, never a guest descriptor
; passed through. Busy retains this exact record/source and consumes no further
; frame/lease ID on retry. W1 returns0 only when it accepts the source lease.
media_guest_producer_frame:
    push rbx
    push r12
    push r13
    cmp  byte [rel mgp_state], 1
    jne  .busy
    mov  r12d, edi
    cmp  r12d, PMH_FRAME_SLOTS
    jae  .shape
    mov  rbx, [rel mgp_ctx]
    cmp  rbx, [rel mg_pool]
    jne  .shape
    cmp  dword [rbx + pmh.state], PMH_S_OPEN
    jne  .busy
    cmp  byte [rbx + pmh.nstate + r12], 2
    jne  .shape
    mov  rax, [rbx + pmh.epoch]
    cmp  rax, [rel mgp_pmh_epoch]
    jne  .stale
    lea  rdi, [rel mgp_receipt]
    mov  esi, 32
    call video_player_identity_receipt
    test eax, eax
    jnz  .out
    lea  rsi, [rel mgp_receipt]
    lea  rdi, [rel mgp_identity]
    mov  ecx, 4
    cld
    repe cmpsq
    jne  .stale
    mov  r13, [rel mgp_lease_seq]
    inc  r13
    jz   .wrap
    ; Ensure the source is the actual host slot in our retained allocation.
    imul eax, r12d, PMH_NATIVE_SLOT
    lea  rdx, [rbx + MG_FRAMES + rax]
    cmp  rdx, [rbx + pmh.native + r12*8]
    jne  .shape
    mov  [rel mgp_frame + 48], rdx
    mov  eax, r12d
    shl  eax, 7
    lea  rsi, [rbx + pmh.pub_desc + rax]
    mov  rax, [rsi + 32]
    cmp  rax, [rel mgp_pmh_epoch]
    jne  .stale
    mov  dword [rel mgp_frame], 1
    mov  dword [rel mgp_frame + 4], 128
    mov  dword [rel mgp_frame + 8], 2
    mov  dword [rel mgp_frame + 12], PMH_BGRX
    mov  rax, [rel mgp_identity + 8]
    mov  [rel mgp_frame + 16], rax
    mov  rax, [rel mgp_identity + 16]
    mov  [rel mgp_frame + 24], rax
    mov  rax, [rel mgp_identity + 24]
    mov  [rel mgp_frame + 32], rax
    mov  rax, [rsi + 40]
    mov  [rel mgp_frame + 40], rax
    mov  [rel mgp_frame + 104], rax          ; S2b completion equals source sequence
    mov  qword [rel mgp_frame + 56], PMH_NATIVE_SLOT
    mov  rax, [rsi + 64]                   ; admitted width/height
    mov  [rel mgp_frame + 64], rax
    mov  eax, [rsi + 72]
    mov  [rel mgp_frame + 72], eax
    mov  dword [rel mgp_frame + 76], 0
    mov  rax, [rsi + 88]
    mov  [rel mgp_frame + 80], rax
    mov  rax, [rsi + 96]
    mov  [rel mgp_frame + 88], rax
    mov  rax, [rsi + 104]
    mov  [rel mgp_frame + 96], rax
    mov  [rel mgp_frame + 112], r13
    mov  qword [rel mgp_frame + 120], 0
    mov  [rel mgp_lease_seq], r13
    mov  [rel mgp_slot], r12d
    mov  byte [rel mgp_state], 2
    call media_guest_producer_retry
    jmp  .out
.busy:
    mov  eax, 2
    jmp  .out
.shape:
    mov  eax, 4
    jmp  .out
.stale:
    mov  eax, 13
    jmp  .out
.wrap:
    mov  eax, 6
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Only the staged immutable record is retried; no source recopy or receipt
; refresh while a pending frame or old source lease owns its captured tuple.
media_guest_producer_retry:
    cmp  byte [rel mgp_state], 2
    jne  .busy
    lea  rdi, [rel mgp_frame]
    sub  rsp, 8
    call video_player_frame
    add  rsp, 8
    test eax, eax
    jnz  .out
    mov  byte [rel mgp_state], 3
.out:
    ret
.busy:
    mov  eax, 2
    ret

; EDI=owned W1 op, RSI=argument. All producer W1 requests share one strictly
; increasing counter, including ACKs. Guest records never supply these fields.
; No PMH CONTROL is issued here; whole-owner OPEN_OK sequencing is still owed.
media_guest_producer_control:
    push rbx
    push r12
    push r13
    cmp  byte [rel mgp_state], 0
    je   .busy
    lea  eax, [rdi - 1]
    cmp  eax, 7
    ja   .shape
    cmp  edi, 6
    je   .shape                            ; only exact held-source release may ACK
    mov  r12d, edi
    mov  r13, rsi
    mov  rbx, [rel mgp_request_seq]
    inc  rbx
    jz   .wrap
    lea  rdi, [rel mgp_control]
    xor  eax, eax
    mov  ecx, 12
    cld
    rep  stosq
    mov  dword [rel mgp_control], 1
    mov  dword [rel mgp_control + 4], 96
    mov  [rel mgp_control + 8], r12d
    lea  rsi, [rel mgp_identity + 8]
    lea  rdi, [rel mgp_control + 16]
    mov  ecx, 3
    rep  movsq
    mov  [rel mgp_control + 40], r13
    mov  [rel mgp_control + 72], rbx
    lea  rdi, [rel mgp_control]
    call video_player_control
    test eax, eax
    jnz  .out
    mov  [rel mgp_request_seq], rbx
    jmp  .out
.busy:
    mov  eax, 2
    jmp  .out
.shape:
    mov  eax, 4
    jmp  .out
.wrap:
    mov  eax, 6
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Poll after W1's real owner turn, or during W1 drain. ACK carries the OLD
; accepted frame tuple even after authority/epoch changes. W1's real queue
; rejects it until no source reader remains (11); retain and retry then. A
; successful ACK is never repeated even if PMH's identity release refuses.
media_guest_producer_release:
    push rbx
    mov  al, [rel mgp_state]
    cmp  al, 4
    je   .native
    cmp  al, 3
    jne  .busy
    mov  rbx, [rel mgp_request_seq]
    inc  rbx
    jz   .wrap
    lea  rdi, [rel mgp_control]
    xor  eax, eax
    mov  ecx, 12
    cld
    rep  stosq
    mov  dword [rel mgp_control], 1
    mov  dword [rel mgp_control + 4], 96
    mov  dword [rel mgp_control + 8], 6
    lea  rsi, [rel mgp_frame + 16]
    lea  rdi, [rel mgp_control + 16]
    mov  ecx, 3
    rep  movsq                            ; principal/old epoch/incarnation
    mov  rax, [rel mgp_frame + 40]
    mov  [rel mgp_control + 40], rax
    mov  rax, [rel mgp_frame + 112]
    mov  [rel mgp_control + 48], rax
    mov  rax, [rel mgp_frame + 48]
    mov  [rel mgp_control + 56], rax
    mov  rax, [rel mgp_frame + 56]
    mov  [rel mgp_control + 64], rax
    mov  [rel mgp_control + 72], rbx
    lea  rdi, [rel mgp_control]
    call video_player_control
    cmp  eax, 11
    je   .busy                            ; no source-release publication yet
    test eax, eax
    jnz  .out
    mov  [rel mgp_request_seq], rbx
    mov  byte [rel mgp_state], 4
.native:
    mov  rdi, [rel mgp_ctx]
    mov  esi, [rel mgp_slot]
    call pmr1h_native_release
    test eax, eax
    jnz  .out                             ; pin after W1 ACK; never manufacture PMH release
    mov  byte [rel mgp_state], 1
    jmp  .out
.busy:
    mov  eax, 2
    jmp  .out
.wrap:
    mov  eax, 6
.out:
    pop  rbx
    ret

; Explicit drop only before W1 acceptance. An accepted source MUST take the
; real W1 ACK path above. Whole-owner STOP/lease drain remains a separate gate.
media_guest_producer_drop:
    cmp  byte [rel mgp_state], 2
    jne  .busy
    mov  rdi, [rel mgp_ctx]
    mov  esi, [rel mgp_slot]
    sub  rsp, 8
    call pmr1h_native_release
    add  rsp, 8
    test eax, eax
    jnz  .out
    mov  byte [rel mgp_state], 1
.out:
    ret
.busy:
    mov  eax, 2
    ret

; Cannot forget an accepted/pending source or reset nonwrapping counters.
media_guest_producer_unbind:
    cmp  byte [rel mgp_state], 1
    ja   .busy
    mov  byte [rel mgp_state], 0
    mov  qword [rel mgp_ctx], 0
    xor  eax, eax
    ret
.busy:
    mov  eax, 2
    ret

%include "core/abi/wdata.inc"
%macro WDATA_gui_guest_media_producer 0
align 8
mgp_ctx: dq 0
mgp_pmh_epoch: dq 0
mgp_lease_seq: dq 0
mgp_request_seq: dq 0
mgp_identity: times 32 db 0
mgp_receipt: times 32 db 0
mgp_frame: times 128 db 0
mgp_control: times 96 db 0
mgp_slot: dd 0
mgp_state: db 0                          ; 0unbound,1idle,2staged,3W1lease,4ACKed/native held
%endmacro
WDATA_DEFER WDATA_gui_guest_media_producer
%endif
