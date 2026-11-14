;; MODULE hv/driver_domain_return
;; LAYER 5
;; EXPORTS nd_quiesce, nd_return_prepare, nd_return_record, nd_return_empty, nd_return_guest_stop, nd_return_sequence
;; IMPORTS hv/driver_domain, hv/vmx, hv/guest_power, core/sched, boot/header, hv/driver_domain_contained
;; CAPS extension
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Authorized return owner calls once after request frames unwind and before CLI.
; This is quiescence, not a reset or a persistence implementation. No network
; reply can certify it: stopping this domain can remove the sole endpoint.
; EAX: 0 exact clean before120s,1 no domain,2 clean late,3 unsafe,4 local budget,
; 5 quarantined, contained (SEC110010: never reused, only a CF9 platform reset).
; The fixed128 native observation is consumed by the original return owner.
nd_return_prepare:
    cmp byte [rel nd_return_once],0
    jne .cached
    mov byte [rel nd_return_once],1
    lea rdi,[rel nd_return_record]
    jmp nd_quiesce
.cached:
    mov eax,[rel nd_return_record+44]
    ret

; Exact current generation, one STOP offer, independent local4s observation.
; Only the original return/restart owner calls this sequentially. No cached
; receipt may stand in for a different generation's actual retirement.
; RDI=private128-byte output. Does not grant restart/reset authority.
; nd_return_sequence counts actual runs (SEC110015 (2)): a caller that reads it
; before nd_return_prepare and sees it unchanged after holds a cached record.
nd_quiesce:
    inc qword [rel nd_return_sequence]
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r15,rdi
    mov rdi,r15
    xor eax,eax
    mov ecx,16
    cld
    rep stosq
    mov rax,0x0000314e5452444e       ; NDRTN1 followed by two zeros
    mov [r15],rax
    mov dword [r15+8],1
    mov dword [r15+12],128
    mov r12,[rel nd_generation]
    mov [r15+16],r12
    lea rdi,[r15+24]
    lea rsi,[rel nd_nonce]
    mov ecx,16
    rep movsb
    lea rdi,[rel nd_return_nonce]
    lea rsi,[rel nd_nonce]
    mov ecx,17
    rep movsb
    mov eax,[rel nd_bdf]
    mov [r15+40],eax
    call boot_ms_now
    mov r13,rax
    mov [r15+48],rax
    mov [r15+56],rax
    test rax,rax
    jz .u_clock_zero
    mov r14d,4096                  ; finite even if a damaged clock stalls
    mov eax,[rel nd_state]
    test eax,eax
    jz .idle
    cmp eax,5
    je .idle
    cmp eax,6
    jae .u_quarantine
    test r12,r12
    jz .u_no_generation
    cmp eax,4
    je .poll
    mov edi,[rel hv_linux_start_gen]
    cmp rdi,r12
    jne .u_start_moved
    mov rdi,r12
    lea rsi,[rel nd_return_nonce]
    call nd_stop                   ; exactly one original request, no retry
    test eax,eax
    jnz .u_stop_refused
.poll:
    mov rax,[rel nd_generation]
    cmp rax,r12
    jne .u_generation_changed
    mov eax,[rel hv_linux_start_gen]
    cmp rax,r12
    jne .u_start_changed
    lea rdi,[rel nd_nonce]
    lea rsi,[r15+24]
    mov ecx,16
    cld
    repe cmpsb
    jne .u_nonce_changed
    call boot_ms_now
    cmp rax,[r15+56]
    jb .u_clock_back
    mov [r15+56],rax
    sub rax,r13
    cmp rax,ND_CALL_MS
    jae .b_time
    cmp dword [rel nd_state],6
    je .u_quarantined_polling
    cmp dword [rel nd_state],4
    jne .yield
    cmp dword [rel nd_terminal],1
    jne .u_not_terminal
    cmp dword [rel nd_released],1
    jne .u_not_released
    call nd_return_empty
    test eax,eax
    jz .yield
    xor ebx,ebx
    cmp qword [r15+56],ND_BOOT_MS
    jb .record
    mov ebx,2                      ; actual safe retirement, missed boot oracle
    jmp .record
.yield:
    dec r14d
    jz .b_turns
    call sched_yield               ; original native task owns CPU/DMA/RAM exit
    jmp .poll
.idle:
    call nd_return_empty
    test eax,eax
    jz .u_idle_not_empty
    mov ebx,1
    jmp .record
; ROOT109962 (2a): byte +112 names the exit of every refused result (3/4), so a
; refusal is never silent. Safe results (0/1/2) leave +112..+119 zero, as before.
; 1 clock zero, 2 quarantined at entry, 3 no generation, 4 START moved before
; STOP, 5 STOP refused, 6 generation changed, 7 START changed, 8 nonce changed,
; 9 clock backward, 10 quarantined while polling, 11 not terminal, 12 not
; released, 13 idle but not empty, 14 local time budget, 15 turn budget.
; On codes 2 and 10, +113 is nd_contained's first failed predicate (1..11).
; Result 5 leaves +112..+119 zero, like every other non-refused result.
.u_clock_zero:
    mov byte [r15+112],1
    jmp .unsafe
.u_quarantine:
    test r12,r12
    jz .q_entry_refused
    mov rdi,r12
    call nd_contained
    test eax,eax
    jz .contained
    mov [r15+113],al
.q_entry_refused:
    mov byte [r15+112],2
    jmp .unsafe
.u_no_generation:
    mov byte [r15+112],3
    jmp .unsafe
.u_start_moved:
    mov byte [r15+112],4
    jmp .unsafe
.u_stop_refused:
    mov byte [r15+112],5
    jmp .unsafe
.u_generation_changed:
    mov byte [r15+112],6
    jmp .unsafe
.u_start_changed:
    mov byte [r15+112],7
    jmp .unsafe
.u_nonce_changed:
    mov byte [r15+112],8
    jmp .unsafe
.u_clock_back:
    mov byte [r15+112],9
    jmp .unsafe
.u_quarantined_polling:
    mov rdi,r12
    call nd_contained
    test eax,eax
    jz .contained
    mov [r15+113],al
    mov byte [r15+112],10
    jmp .unsafe
.contained:
    mov ebx,5                      ; SEC110010: every predicate read now; +112..+119 stay zero
    jmp .record
.u_not_terminal:
    mov byte [r15+112],11
    jmp .unsafe
.u_not_released:
    mov byte [r15+112],12
    jmp .unsafe
.u_idle_not_empty:
    mov byte [r15+112],13
.unsafe:
    mov ebx,3
    jmp .record
.b_time:
    mov byte [r15+112],14
    jmp .budget
.b_turns:
    mov byte [r15+112],15
.budget:
    mov ebx,4
.record:
    mov [r15+44],ebx
    mov eax,[rel nd_state]
    mov [r15+64],eax
    mov eax,[rel nd_terminal]
    mov [r15+68],eax
    mov eax,[rel nd_released]
    mov [r15+72],eax
    mov eax,[rel nd_fault]
    mov [r15+76],eax
    mov eax,[rel hv_linux_start_gen]
    mov [r15+80],eax
    mov eax,[rel hv_linux_start_consumed]
    mov [r15+84],eax
    mov al,[rel hv_linux_running]
    mov [r15+88],al
    mov al,[rel hv_linux_start_active]
    mov [r15+89],al
    mov al,[rel hv_linux_vmx_live]
    mov [r15+90],al
    mov al,[rel hv_linux_run_req]
    mov [r15+91],al
    mov rax,[rel hv_svm_cur_vmcb]
    mov [r15+96],rax
    mov rax,[rel hv_linux_ram]
    mov [r15+104],rax
    mov rax,[rel hv_linux_region]
    mov [r15+120],rax
    mov eax,[r15+44]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Zero CPU and actual allocator span, not the earlier STOP ACK or NIC receipt.
; hv_linux_ram_bytes is a size selector with a nonzero static default: it owns
; nothing and is never cleared, so it cannot be part of this test or the record.
nd_return_empty:
    mov al,[rel hv_linux_running]
    or al,[rel hv_linux_start_active]
    or al,[rel hv_linux_vmx_live]
    or al,[rel hv_linux_run_req]
    jnz .bad
    mov rax,[rel hv_svm_cur_vmcb]
    or rax,[rel hv_linux_ram]
    or rax,[rel hv_linux_region_resident]
    or rax,[rel hv_linux_region]
    or rax,[rel hv_linux_region_capacity]
    or rax,[rel hv_linux_mb_token]
    jnz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; ROOT109558 (1): a reset request with a live NON-domain guest. The caller is
; BOOT's svc admit, with IF set, before BootNext/CMOS or any reply, so a guest
; that cannot be retired refuses the verb honestly instead of 'queued' then no
; reset. One ordinary STOP (the GUESTVM STOP request), then a bounded readback
; of nd_return_empty, the same predicate the reset path re-checks. Retirement is
; the existing vCPU exit chain; nothing is torn down here. Not cached and never
; touches nd_return_once: a refused verb may be retried.
; EAX 0 nothing live, no write. 1 stopped and read back empty.
;     2 the guest is the driver domain (nd_state 1-4/6+): no write; R-U owns it.
;     3 refused, no STOP written; EDX = first blocker:
;       1 power-fenced  2 fixture-deferred span  3 START in progress
;       4 media owner   5 clock unusable         6 IF clear
;     4 STOP requested, no empty readback within ND_CALL_MS / 4096 yields.
; A STOP already pending (an earlier GUESTVM STOP) is observed: no byte is
; written, blockers still refuse first, and the readback has the same one bound.
nd_return_guest_stop:
    push rbx
    push r12
    push r13
    mov eax,[rel nd_state]
    test eax,eax
    jz .not_domain
    cmp eax,5
    jne .domain
.not_domain:
    call nd_return_empty
    test eax,eax
    jz .live
    xor eax,eax                    ; EAX 0: nothing live
    xor edx,edx
    jmp .out
.live:
    pushfq
    pop rax
    mov edx,6
    test eax,0x200                 ; never yield with interrupts excluded
    jz .refused
    mov edx,1
    cmp byte [rel hv_guest_power_fenced],0
    jne .refused                   ; parked vCPU never consumes a STOP
    mov edx,2
    cmp byte [rel hv_linux_release_deferred],0
    jne .refused                   ; span stays until its fixture reads it
    mov edx,3
    cmp byte [rel hv_linux_start_active],0
    je .not_starting
    cmp byte [rel hv_linux_running],0
    je .refused                    ; launch clears stop_req before entry
.not_starting:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    mov edx,4
    cmp byte [rel hv_vcon_pmr_bound],0
    jne .refused                   ; GUESTVM STOP never stops the media owner
%endif
%endif
    call boot_ms_now
    mov edx,5
    test rax,rax
    jz .refused
    mov r12,rax                    ; start
    mov r13,rax                    ; last observed
    ; A STOP already pending (an earlier authorised GUESTVM STOP) is observed:
    ; no byte is written, and the same single bound applies (SEC109656).
    cmp byte [rel hv_linux_stop_req],0
    jne .poll                      ; a pending STOP is observed
    ; The one STOP: the GUESTVM STOP request bytes, nothing else.
    mov byte [rel hv_linux_run_req],0
    cmp byte [rel hv_linux_running],1
    jne .poll
    mov byte [rel hv_linux_stop_req],1
.poll:
    mov ebx,4096                   ; finite even if a damaged clock stalls
.again:
    call nd_return_empty           ; sampled only inside the bound (rc-review109748)
    test eax,eax
    jz .wait
    mov eax,1
    xor edx,edx
    jmp .out
.wait:
    dec ebx
    jz .budget
    call sched_yield
    ; Deadline and rollback BEFORE the next readback: a guest that retires
    ; after the bound is a 4, never a late 1.
    call boot_ms_now
    cmp rax,r13
    jb .budget                     ; rollback never extends the bound
    mov r13,rax
    sub rax,r12
    cmp rax,ND_CALL_MS
    jae .budget
    jmp .again
.budget:
    mov eax,4
    xor edx,edx
    jmp .out
.domain:
    mov eax,2
    xor edx,edx
    jmp .out
.refused:
    mov eax,3
.out:
    pop r13
    pop r12
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_hv_driver_domain_return 0
alignb 8
nd_return_record: resb 128
nd_return_once: resb 1
nd_return_nonce: resb 17
alignb 8
nd_return_sequence: resq 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_driver_domain_return
