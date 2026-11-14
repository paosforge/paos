;; MODULE svc/lab_return
;; LAYER 5
;; EXPORTS lab_return_init, lab_return_tick, lab_return_contact, lab_return_report
;; IMPORTS core/time, core/diag, boot/boot_v2_handoff, svc/command_auth
;; CAPS
;; OWNER saga:boot
; Lab first-contact timer (desktop root MSI recovery ruling 2026-10-18).
; No firmware, disk, reset, selection or health publication here. Tick claims
; one expiry; the depth-zero boot loop owns quiesce/reset. All calls are BSP.
; This is cooperative recovery, not a hardware deadman or a hard-hang remedy.
%ifndef PAOS_LAB_RETURN_SECONDS
%define PAOS_LAB_RETURN_SECONDS 0
%endif
%if PAOS_LAB_RETURN_SECONDS != 0
%if PAOS_LAB_RETURN_SECONDS < 30 || PAOS_LAB_RETURN_SECONDS > 1800
%error "PAOS_LAB_RETURN_SECONDS must be 0 or 30..1800"
%endif
%if PAOS_PUBLIC_BUILD
%error "public images cannot enable the lab return timer"
%endif
%endif

; lab_return_init: once at the live command-loop handoff. Repeated calls never
; renew the deadline or resurrect a cancelled/expired timer. Default is inert.
; Clobbers caller-saved registers and flags. States: 0 off, 1 armed,
; 2 owner contact, 3 expiry claimed, 4 clock unavailable/regressed/overflow.
lab_return_init:
%if PAOS_LAB_RETURN_SECONDS
    cmp byte [rel lab_return_state], 0
    jne .out
    cmp qword [rel tsc_khz], 0
    je .clock_bad
    call time_monotonic_now_us
    test rax, rax
    jz .clock_bad
    mov [rel lab_return_last_us], rax
    add rax, PAOS_LAB_RETURN_SECONDS * 1000000
    jc .clock_bad
    mov [rel lab_return_deadline_us], rax
    mov byte [rel lab_return_state], 1
.out:
%endif
    ret
%if PAOS_LAB_RETURN_SECONDS
.clock_bad:
    mov byte [rel lab_return_state], 4
    ret
%endif

; lab_return_sample -> RAX current monotonic us, CF clear; CF set on a missing
; or regressed clock. Called only while armed. No wall time or tick-count guess.
lab_return_sample:
    cmp qword [rel tsc_khz], 0
    je .bad
    call time_monotonic_now_us
    test rax, rax
    jz .bad
    cmp rax, [rel lab_return_last_us]
    jb .bad
    mov [rel lab_return_last_us], rax
    clc
    ret
.bad:
    mov byte [rel lab_return_state], 4
    stc
    ret

; lab_return_tick -> EAX 1 once, at/after the absolute deadline; otherwise 0.
; Caller must act only at depth zero, with no request/driver frame in flight.
; A failed quiesce is terminal for this attempt: never repeatedly reset/flush.
lab_return_tick:
%if PAOS_LAB_RETURN_SECONDS
    cmp byte [rel lab_return_state], 1
    jne .no
    call lab_return_sample
    jc .no
    cmp rax, [rel lab_return_deadline_us]
    jb .no
    mov byte [rel lab_return_state], 3
    mov eax, 1
    ret
.no:
%endif
    xor eax, eax
    ret

; lab_return_contact: in remote_end before its ticket is retired. Preserve all
; GP registers and flags for every projection. Only this in-flight consumed
; owner ticket or an unrestricted enrolled-owner SSH request cancels. Unsigned
; traffic, unconsumed signed public reads, wrong/old tickets and lab injection
; confer no authority. A late contact never moves or cancels the deadline.
lab_return_contact:
%if PAOS_LAB_RETURN_SECONDS
    pushfq
    push rax
    push rcx
    push rdx
    push r8
    cmp byte [rel lab_return_state], 1
    jne .out
    call command_auth_owner_request
    test eax, eax
    jz .out
    call lab_return_sample
    jc .out
    cmp rax, [rel lab_return_deadline_us]
    jae .out
    mov byte [rel lab_return_state], 2
.out:
    pop r8
    pop rdx
    pop rcx
    pop rax
    popfq
%endif
    ret

; EDI=1 expiry/no timely owner contact, 2 quiesce refused, 3 reset attempted.
; Diagnostic only: no channel/root-cause claim, health/journal/EFI write or retry.
; The power caller reports expiry BEFORE quiesce, then one terminal outcome.
; Claim each attempt before append: an unavailable/busy ring stays missing.
; A/B use the timer's existing monotonic domain; C is Manager generation (0
; when unavailable). The retained header supplies boot/sequence. Warm-only,
; bounded/best-effort retention is not an EFI archive or reset success proof.
; Clobbers caller-saved registers/flags. Default/public timer-off stays inert.
lab_return_report:
%if PAOS_LAB_RETURN_SECONDS
    cmp byte [rel lab_return_state], 3
    jne .out
    cmp edi, 1
    je .expiry
    cmp edi, 2
    je .outcome
    cmp edi, 3
    jne .out
.outcome:
    cmp byte [rel lab_return_reported], 1
    jne .out
    mov byte [rel lab_return_reported], 2
    jmp .append
.expiry:
    cmp byte [rel lab_return_reported], 0
    jne .out
    mov byte [rel lab_return_reported], 1
.append:
    mov esi, edi
    mov edi, DIAG_K_LAB_RETURN
    mov rdx, [rel lab_return_deadline_us]
    mov rcx, [rel lab_return_last_us]
    mov r8, [rel pbm_state_generation]
    lea r9, [rel lab_return_reason_tag]
    sub rsp, 8
    call diag_ring_append
    add rsp, 8
.out:
%endif
    ret

%if PAOS_LAB_RETURN_SECONDS
lab_return_reason_tag: db 'lab-return:no-contact',0
%endif

%include "core/abi/wdata.inc"
%macro WDATA_lab_return 0
lab_return_deadline_us: dq 0
lab_return_last_us: dq 0
lab_return_state: db 0
lab_return_reported: db 0
%endmacro
WDATA_DEFER WDATA_lab_return
