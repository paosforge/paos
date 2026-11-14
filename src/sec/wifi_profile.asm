;; MODULE sec/wifi_profile
;; LAYER 5
;; EXPORTS wifi_profile_validate, wifi_profile_replace_local, wifi_profile_prepare_local, wifi_profile_consume_local, wifi_profile_reconcile_local, wifi_profile_cancel
;; IMPORTS sec/wifi_store, sec/session, svc/command, boot/boot_v2_handoff, core/csprng, core/lib/mem, boot/header, hv/wifi_channel
;; CAPS
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
; Private kernel interface, never a command/serial/public configuration getter.
; WFP1/1/256: revision64@8, committed ownerhash32@16, generation64@48,
; node digest32@56, random id16@88, mode32@104, ssidlen32@108,
; binary SSID32@112 (zero tail), binary WPA2 PSK32@144, zero80@176.
; A PSK is already derived; PBKDF2-SHA256 is NOT WiFi passphrase derivation.
; Status0 success,1 missing(read only),2 unavailable,3 refused,4 uncertain.
; SEC owns authenticated storage, native committed context and final effect gate.
; This leaf retains no secret between calls and exposes no secret output. Its
; opaque local intent is not a VM grant. Only the original native wfc snapshot
; and submit interface supplies the fixed private recipient and START binding.

WFP_SIZE equ 256
WFP_DRAFT_SIZE equ 80
WFP_CTX_SIZE equ 128
WFP_INTENT_SIZE equ 184
WFP_MODE_PSK32 equ 1

; Pure schema checker, RDI=private complete record, RSI=exact size ->0/3.
; Owner/node equality, authenticated source and revision continuity are separate
; native store checks; merely passing this function conveys no authority.
wifi_profile_validate:
    test rdi, rdi
    jz .bad
    cmp rsi, WFP_SIZE
    jne .bad
    cmp dword [rdi], 'WFP1'
    jne .bad
    cmp word [rdi+4], 1
    jne .bad
    cmp word [rdi+6], WFP_SIZE
    jne .bad
    cmp qword [rdi+8], 0
    je .bad
    cmp qword [rdi+48], 0
    je .bad
    mov rax, [rdi+16]
    or rax, [rdi+24]
    or rax, [rdi+32]
    or rax, [rdi+40]
    jz .bad
    mov rax, [rdi+56]
    or rax, [rdi+64]
    or rax, [rdi+72]
    or rax, [rdi+80]
    jz .bad
    mov rax, [rdi+88]
    or rax, [rdi+96]
    jz .bad
    cmp dword [rdi+104], WFP_MODE_PSK32
    jne .bad
    mov ecx, [rdi+108]
    cmp ecx, 1
    jb .bad
    cmp ecx, 32
    ja .bad
.tail:
    cmp ecx, 32
    jae .reserved
    cmp byte [rdi+rcx+112], 0
    jne .bad
    inc ecx
    jmp .tail
.reserved:
    mov ecx, 176
.zero:
    cmp byte [rdi+rcx], 0
    jne .bad
    inc ecx
    cmp ecx, WFP_SIZE
    jb .zero
    xor eax, eax
    ret
.bad:
    mov eax, 3
    ret

; Cancellation may be called by native lock/owner/profile/STOP hooks even from
; a nested callback. It never clears busy/uncertain or an in-flight store buffer.
; Sequence exhaustion fails closed until reset, without wrapping old intents.
wifi_profile_cancel:
    push rbx
    cmp qword [rel wfp_cancel_sequence], -1
    je .wipe
    inc qword [rel wfp_cancel_sequence]
.wipe:
    mov byte [rel wfp_intent_active], 0
    lea rdi, [rel wfp_intent]
    xor esi, esi
    mov edx, WFP_INTENT_SIZE
    call memset
    ; Immediate native revocation; this does not clear custody/uncertainty or
    ; release RAM/NIC. Native owns exact original STOP and retirement.
    call wfc_cancel
    pop rbx
    ret

; Private local Apply. RDI=draft80, RSI=80, RDX=captured OWNER,
; RCX=captured authority epoch. Draft WFR1/1/80: mode32@8,len32@12,
; binary paddedSSID32@16, binaryPSK32@48. Caller owns/wipes its own draft.
wifi_profile_replace_local:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    call wfp_begin
    test eax, eax
    jnz .out
    test r12, r12
    jz .refused
    cmp r13, WFP_DRAFT_SIZE
    jne .refused
    lea rdi, [rel wfp_request]
    mov rsi, r12
    mov edx, WFP_DRAFT_SIZE
    call memcpy
    cmp dword [rel wfp_request], 'WFR1'
    jne .refused
    cmp word [rel wfp_request+4], 1
    jne .refused
    cmp word [rel wfp_request+6], WFP_DRAFT_SIZE
    jne .refused
    call wfp_snapshot
    test eax, eax
    jnz .finish
    call wfp_read
    cmp eax, 1
    je .missing
    test eax, eax
    jnz .finish
    ; An unchanged confirmed authenticated record does not cause a write.
    lea rdi, [rel wfp_old+104]
    lea rsi, [rel wfp_request+8]
    mov edx, 72
    call memcmp
    test eax, eax
    jz .unchanged
    mov rbp, [rel wfp_old+8]
    cmp rbp, -1
    je .refused
    inc rbp
    lea rdi, [rel wfp_new+88]
    lea rsi, [rel wfp_old+88]
    mov edx, 16
    call memcpy
    jmp .build
.missing:
    mov ebp, 1
    lea rdi, [rel wfp_new+88]
    mov esi, 16
    call csprng_generate
    test eax, eax
    jnz .unavailable
.build:
    mov dword [rel wfp_new], 'WFP1'
    mov word [rel wfp_new+4], 1
    mov word [rel wfp_new+6], WFP_SIZE
    mov [rel wfp_new+8], rbp
    lea rdi, [rel wfp_new+16]
    lea rsi, [rel wfp_context+32]
    mov edx, 32
    call memcpy
    mov rax, [rel wfp_context+24]
    mov [rel wfp_new+48], rax
    lea rdi, [rel wfp_new+56]
    lea rsi, [rel wfp_context+64]
    mov edx, 32
    call memcpy
    lea rdi, [rel wfp_new+104]
    lea rsi, [rel wfp_request+8]
    mov edx, 72
    call memcpy
    lea rdi, [rel wfp_new]
    mov esi, WFP_SIZE
    call wifi_profile_validate
    test eax, eax
    jnz .refused
    call wfp_current
    test eax, eax
    jnz .finish
    lea rdi, [rel wfp_context]
    lea rsi, [rel wfp_new]
    mov edx, WFP_SIZE
    call wifi_store_replace_local
    cmp eax, 4
    jne .store_result
    mov byte [rel wfp_uncertain], 1
.store_result:
    ; Unexpected store statuses are refusals, never successful retries.
    cmp eax, 1
    je .refused
    cmp eax, 4
    jbe .finish
    jmp .refused
.unchanged:
    call wfp_current
    jmp .finish
.unavailable:
    mov eax, 2
    jmp .finish
.refused:
    mov eax, 3
.finish:
    call wfp_finish
.out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI=private out32,RSI=32,RDX=capturedOWNER,RCX=captured epoch ->status.
; Replaces any prior local intent. No SSID, key, secret hash or store plaintext
; is returned. No consumer/caller may treat this token as a selection/START grant.
wifi_profile_prepare_local:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    test r12, r12
    jz .refused_out
    cmp r13, 32
    jne .refused_out
    mov rdi, r12
    xor esi, esi
    mov edx, 32
    call memset
    call wfp_begin
    test eax, eax
    jnz .out
    call wfp_snapshot
    test eax, eax
    jnz .finish
    call wfp_read
    test eax, eax
    jnz .finish
    lea rdi, [rel wfp_token]
    mov esi, 32
    call csprng_generate
    test eax, eax
    jnz .unavailable
    ; No deterministic/zero fallback if randomness is unavailable.
    mov rax, [rel wfp_token]
    or rax, [rel wfp_token+8]
    or rax, [rel wfp_token+16]
    or rax, [rel wfp_token+24]
    jz .unavailable
    call wfp_current
    test eax, eax
    jnz .finish
    lea rdi, [rel wfp_intent]
    lea rsi, [rel wfp_context]
    mov edx, WFP_CTX_SIZE
    call memcpy
    lea rdi, [rel wfp_intent+128]
    lea rsi, [rel wfp_old+88]
    mov edx, 16
    call memcpy
    mov rax, [rel wfp_old+8]
    mov [rel wfp_intent+144], rax
    lea rdi, [rel wfp_intent+152]
    lea rsi, [rel wfp_token]
    mov edx, 32
    call memcpy
    mov byte [rel wfp_intent_active], 1
    mov rdi, r12
    lea rsi, [rel wfp_token]
    mov edx, 32
    call memcpy
    xor eax, eax
    jmp .finish
.unavailable:
    mov eax, 2
.finish:
    call wfp_finish
    jmp .out
.refused_out:
    mov eax, 3
.out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Private single-use delivery. RDI=opaque token32,RSI=32,RDX=captured OWNER,
; RCX=captured epoch ->0 queued,1 missing,2 unavailable,3 refusal,4 uncertain.
; No secret output. Native snapshot/submit owns actual selected START/receiver,
; cutoff, one-shot state and original CPU+DMA retirement. Never use wfp_begin:
; that helper deliberately revokes the intent we must consume here.
wifi_profile_consume_local:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    cmp byte [rel wfp_busy], 0
    jne .unavailable_out
    mov byte [rel wfp_busy], 1
    mov rbx, [rel wfp_cancel_sequence]
    cmp rbx, -1
    je .refused
    cmp byte [rel wfp_uncertain], 0
    jne .uncertain
    call wfp_local
    test eax, eax
    jnz .refused
    test r12, r12
    jz .refused
    cmp r13, 32
    jne .refused
    cmp byte [rel wfp_intent_active], 1
    jne .refused
    lea rdi, [rel wfp_request]
    mov rsi, r12
    mov edx, 32
    call memcpy
    lea rdi, [rel wfp_request]
    lea rsi, [rel wfp_intent+152]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .refused
    ; One-use BEFORE any callback/profile read/secret copy. Retain only its
    ; metadata for equality checks until this owned call wipes it on exit.
    mov byte [rel wfp_intent_active], 0
    call wfp_snapshot
    test eax, eax
    jnz .failed
    lea rdi, [rel wfp_context]
    lea rsi, [rel wfp_intent]
    mov edx, WFP_CTX_SIZE
    call memcmp
    test eax, eax
    jnz .refused
    call wfp_read
    test eax, eax
    jnz .failed
    call wfp_consume_current
    test eax, eax
    jnz .failed
    ; Reuse the existing private new-record scratch as the receiver frame.
    ; Native offers metadata only; this callback never receives the profile.
    lea rdi, [rel wfp_new]
    mov esi, 256
    mov rdx, r14
    mov rcx, r15
    call wfc_snapshot
    test eax, eax
    jnz .refused
    call wfp_consume_current
    test eax, eax
    jnz .failed
    cmp dword [rel wfp_new], 'WFA1'
    jne .refused
    cmp dword [rel wfp_new+4], (256<<16)|1
    jne .refused
    cmp dword [rel wfp_new+52], WFP_MODE_PSK32
    jne .refused
    cmp r15, [rel wfp_new+56]
    jne .refused
    lea rdi, [rel wfp_new+168]
    lea rsi, [rel wfp_context+32]
    mov edx, 64                       ; exact committed ownerhash and node
    call memcmp
    test eax, eax
    jnz .refused
    call boot_ms_now
    test rax, rax
    jz .refused
    mov rbp, [rel wfp_new+64]         ; preserve native absolute deadline
    sub rbp, rax
    jbe .refused
    shr rbp, 1                       ; leave native submit/callback headroom
    jz .refused
    cmp rbp, 30000
    jbe .budget
    mov ebp, 30000
.budget:
    call wfp_consume_current          ; charge/recheck after clock callback
    test eax, eax
    jnz .failed
    ; Copy ONLY the designated profile region72..167. No pending owner or
    ; caller-supplied identity, cutoff, START, nonce or transport fields.
    lea rdi, [rel wfp_new+72]
    lea rsi, [rel wfp_old+88]
    mov edx, 16
    call memcpy
    mov rax, [rel wfp_old+8]
    mov [rel wfp_new+88], rax
    mov eax, [rel wfp_old+108]
    mov [rel wfp_new+96], eax
    mov [rel wfp_new+100], ebp
    lea rdi, [rel wfp_new+104]
    lea rsi, [rel wfp_old+112]
    mov edx, 64                       ; padded binary SSID and binary PSK32
    call memcpy
    lea rdi, [rel wfp_new]
    mov esi, 256
    call wfc_submit
    ; Even refusal/unknown result after this attempted effect is conservative
    ; uncertainty. Never reconstruct a token or resend. Native terminal state
    ; owns when another START can exist; storage reconcile cannot reset it.
    test eax, eax
    jnz .uncertain
    call wfp_consume_current
    test eax, eax
    jnz .uncertain
    xor eax, eax                      ; queue acceptance only, not association
    jmp .finish
.refused:
    mov eax, 3
    jmp .failed
.uncertain:
    mov eax, 4
.failed:
    mov r13d, eax
    call wfc_cancel                   ; original STOP/scrub, never custody release
    mov eax, r13d
.finish:
    mov r13d, eax
    mov byte [rel wfp_intent_active], 0
    lea rdi, [rel wfp_intent]
    xor esi, esi
    mov edx, WFP_INTENT_SIZE
    call memset
    mov eax, r13d
    call wfp_finish                   ; wipes all880, including token and frame
    jmp .out
.unavailable_out:
    mov eax, 2                       ; nested call must not disturb outer state
.out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Current intent lineage and read profile must still match after every seam.
; wfp_current compares full128 SEC context and cancellation sequence. Local
; authority is checked AGAIN after that callback, before secret copy/effect.
wfp_consume_current:
    push rbp
    call wfp_current
    test eax, eax
    jnz .out
    call wfp_local
    test eax, eax
    jnz .out
    lea rdi, [rel wfp_context]
    lea rsi, [rel wfp_intent]
    mov edx, WFP_CTX_SIZE
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rel wfp_old+88]
    lea rsi, [rel wfp_intent+128]
    mov edx, 16
    call memcmp
    test eax, eax
    jnz .bad
    mov rax, [rel wfp_old+8]
    cmp rax, [rel wfp_intent+144]
    jne .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, 3
.out:
    pop rbp
    ret

; Explicit read-only reconciliation, never an automatic resend. RDI=captured
; OWNER,RSI=epoch ->status. Only SEC's actual uncertain-record reconciler and a
; fresh authenticated current profile may clear this leaf's sticky latch.
; No intent is retained/recreated; a later fresh local selection is still needed.
wifi_profile_reconcile_local:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r14, rdi
    mov r15, rsi
    cmp byte [rel wfp_busy], 0
    jne .unavailable
    mov byte [rel wfp_busy], 1
    call wifi_profile_cancel
    mov rbx, [rel wfp_cancel_sequence]
    cmp rbx, -1
    je .refused
    call wfp_local
    test eax, eax
    jnz .finish
    call wfp_snapshot
    test eax, eax
    jnz .finish
    lea rdi, [rel wfp_context]
    call wifi_store_reconcile_local
    test eax, eax
    jnz .status
    call wfp_read
    test eax, eax
    jnz .finish
    call wfp_current
    test eax, eax
    jnz .finish
    mov byte [rel wfp_uncertain], 0
    xor eax, eax
    jmp .finish
.status:
    cmp eax, 4
    jne .range
    mov byte [rel wfp_uncertain], 1
.range:
    cmp eax, 1
    je .refused
    cmp eax, 4
    jbe .finish
.refused:
    mov eax, 3
.finish:
    call wfp_finish
    jmp .out
.unavailable:
    mov eax, 2
.out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Internal helpers preserve the caller's R12..R15. RBX is cancellation sequence.
wfp_local:
    push rbp
    cmp byte [rel pbm_try_media], 0
    jne .bad
    cmp dword [rel cmd_dispatch_depth], 0
    jne .bad
    call session_shell_local_authority
    cmp rax, 1
    jne .bad
    cmp rax, r14
    jne .bad
    test rdx, rdx
    jz .bad
    cmp rdx, r15
    jne .bad
    xor eax, eax
    pop rbp
    ret
.bad:
    mov eax, 3
    pop rbp
    ret

wfp_begin:
    push rbp
    cmp byte [rel wfp_busy], 0
    jne .unavailable
    mov byte [rel wfp_busy], 1
    call wifi_profile_cancel
    mov rbx, [rel wfp_cancel_sequence]
    cmp rbx, -1
    je .refused
    cmp byte [rel wfp_uncertain], 0
    jne .uncertain
    call wfp_local
    test eax, eax
    jnz .refused
    xor eax, eax
    pop rbp
    ret
.uncertain:
    mov eax, 4
    jmp .end
.refused:
    mov eax, 3
.end:
    call wfp_finish
    pop rbp
    ret
.unavailable:
    mov eax, 2
    pop rbp
    ret

wfp_snapshot:
    push rbp
    lea rdi, [rel wfp_context]
    mov esi, WFP_CTX_SIZE
    call wifi_owner_context_snapshot
    test eax, eax
    jnz wfp_snapshot_status
    ; Fresh context must reflect the actual captured local action, too.
    cmp qword [rel wfp_context+8], 1
    jne wfp_helper_refused
    mov rax, [rel wfp_context+16]
    cmp rax, r15
    jne wfp_helper_refused
    xor eax, eax
    pop rbp
    ret

wfp_read:
    push rbp
    lea rdi, [rel wfp_context]
    lea rsi, [rel wfp_old]
    mov edx, WFP_SIZE
    call wifi_store_open_local
    test eax, eax
    jnz wfp_helper_status
    lea rdi, [rel wfp_old]
    mov esi, WFP_SIZE
    call wifi_profile_validate
    test eax, eax
    jnz wfp_helper_refused
    lea rdi, [rel wfp_old+16]
    lea rsi, [rel wfp_context+32]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz wfp_helper_refused
    mov rax, [rel wfp_old+48]
    cmp rax, [rel wfp_context+24]
    jne wfp_helper_refused
    lea rdi, [rel wfp_old+56]
    lea rsi, [rel wfp_context+64]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz wfp_helper_refused
    xor eax, eax
    pop rbp
    ret

wfp_current:
    push rbp
    cmp rbx, [rel wfp_cancel_sequence]
    jne wfp_helper_refused
    call wfp_local
    test eax, eax
    jnz wfp_helper_refused
    lea rdi, [rel wfp_check]
    mov esi, WFP_CTX_SIZE
    call wifi_owner_context_snapshot
    test eax, eax
    jnz wfp_snapshot_status
    lea rdi, [rel wfp_context]
    lea rsi, [rel wfp_check]
    mov edx, WFP_CTX_SIZE
    call memcmp
    test eax, eax
    jnz wfp_helper_refused
    ; A cancellation inside snapshot must not publish a new intent/effect.
    cmp rbx, [rel wfp_cancel_sequence]
    jne wfp_helper_refused
    xor eax, eax
    pop rbp
    ret

wfp_snapshot_status:
    cmp eax, 1
    je wfp_helper_refused
wfp_helper_status:
    cmp eax, 4
    jne .range
    mov byte [rel wfp_uncertain], 1
.range:
    cmp eax, 4
    jbe .out
    mov eax, 3
.out:
    pop rbp
    ret
wfp_helper_refused:
    mov eax, 3
    pop rbp
    ret

wfp_finish:
    push rax
    lea rdi, [rel wfp_scratch]
    xor esi, esi
    mov edx, wfp_scratch_end-wfp_scratch
    call memset
    mov byte [rel wfp_busy], 0
    pop rax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_sec_wifi_profile 0
align 8
wfp_cancel_sequence: dq 0
wfp_busy: db 0
wfp_uncertain: db 0
wfp_intent_active: db 0
align 8
wfp_intent: times WFP_INTENT_SIZE db 0
wfp_intent_end:
wfp_scratch:
wfp_context: times WFP_CTX_SIZE db 0
wfp_check: times WFP_CTX_SIZE db 0
wfp_old: times WFP_SIZE db 0
wfp_new: times WFP_SIZE db 0
wfp_request: times WFP_DRAFT_SIZE db 0
wfp_token: times 32 db 0
wfp_scratch_end:
%endmacro
WDATA_DEFER WDATA_sec_wifi_profile
