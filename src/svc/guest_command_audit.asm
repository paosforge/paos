;; MODULE svc/guest_command_audit
;; LAYER 5
;; PURPOSE Bounded checked-driver history, separate from verified-principal GD1.
;; EXPORTS audit_guest_command_record, audit_guest_command_refusal, audit_guest_command_unbound, audit_guest_command_snapshot
;; IMPORTS hv/guest_request, svc/command_audit, core/time
;; OWNER saga:guest_command_audit
; Private native producer only. No generic principal/guest pointer API and no
; eligibility change to audit_sec_event. Single serialized BSP writer.
AG_CAP equ 8
AG_ROW equ 160
AG_BYTES equ 1856                     ; GCA1 v2: header, 8 accepted, 2 refused, GCF1
; C11n (T5-1.C11, SEC 106351 R1-R5): refused submits get their own bounded
; share. A refusal never takes an accepted slot, and accepted-only history keeps
; its v1 ring, sequence and header bytes. Refusal rows carry native binding
; identity, the raw op and sequence only, and their own nonwrapping sequence.
AG_REF_CAP equ 2
AG_REF_REASONS equ 9                  ; GRR_SIZE..GRR_CONFIRMATION, hv/guest_request
AG_REF_ROWS_OFF equ 1408
AG_TAIL_OFF equ 1728
AG_ROW_REFUSED equ 4                  ; row flags bit: refused before dispatch
AG_REPEAT_ONE equ 0x100               ; meta bits 8..39: saturating repeat count

audit_guest_command_record:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov r15,rbx                       ; original final native response
    cmp byte [rel gr_busy],1
    jne .out
    lea rax,[rel guest_request_endpoint]
    cmp rax,[rel gr_context+GR_ENDPOINT]
    jne .out
    cmp qword [rel gr_req+REQ_SOURCE],CMD_SOURCE_GUEST
    jne .out
    mov rax,[rel gr_context+GR_BINDING]
    test rax,rax
    jz .out
    cmp rax,0x7fffffff
    ja .out
    cmp rax,[rel gr_serial]
    jne .out
    mov rdx,0x4755455300000000
    or rax,rdx
    cmp rax,[rel gr_context+GR_PID]
    jne .out
    cmp rax,[rel gr_req+REQ_PRINCIPAL]
    jne .out
    cmp rax,[rel gr_ticket+AUTH_T_PRINCIPAL]
    jne .out
    mov rax,[rel gr_frame+8]
    test rax,rax
    jz .out
    cmp rax,[rel gr_req+REQ_IDEM]
    jne .out
    cmp rax,[rel gr_ticket+AUTH_T_SEQ]
    jne .out
    mov rax,[rel gr_context+GR_OP]
    dec rax
    cmp rax,3
    ja .out
    cmp qword [rel ag_revision],-2
    jae .exhausted
    inc qword [rel ag_revision]
    mov rax,[rel ag_head]
    imul rax,AG_ROW
    lea r14,[rel ag_ring]
    add r14,rax
    mov rdi,r14
    xor eax,eax
    mov ecx,AG_ROW/8
    cld
    rep stosq
    mov rax,[rel ag_revision]
    mov [r14],rax
    mov rax,[rel gr_context+GR_PID]
    mov [r14+8],rax
    mov rax,[rel gr_context+GR_BINDING]
    mov [r14+16],rax
    mov rax,[rel gr_context+GR_START]
    mov [r14+24],rax
    mov rax,[rel gr_context+GR_VM_EPOCH]
    mov [r14+32],rax
    mov rax,[rel gr_context+GR_SESSION]
    mov [r14+40],rax
    mov rax,[rel gr_frame+8]
    mov [r14+48],rax
    mov rax,[rel gr_context+GR_OP]
    mov [r14+56],rax
    mov rax,[rel gr_context+GR_TARGET]
    mov [r14+64],rax
    mov rax,[rel gr_call_setting_generation]
    mov [r14+72],rax
    mov rax,[rel gr_receipt_policy]
    mov [r14+80],rax
    mov rax,[rel gr_receipt_decision]
    mov [r14+88],rax
    mov rax,[rel gr_receipt_authorized]
    mov [r14+96],rax
    mov rax,[r15+RSP_CODE]
    mov [r14+104],rax
    mov rdi,r15
    mov esi,1                         ; actual existing VERB response mapping
    call audit_sec_rsp_meta
    mov [r14+112],rax
    call time_monotonic_now_us         ; raw observation, never a held old time
    mov qword [r14+144],1              ; synchronous envelope only
    test rax,rax
    jz .clock_unknown
    cmp rax,-1
    jne .clock_known
.clock_unknown:
    xor eax,eax
    or qword [r14+144],2
.clock_known:
    mov [r14+120],rax
    mov rax,[rel gr_context+GR_DEADLINE]
    mov [r14+128],rax
    xor eax,eax
    cmp qword [r15+RSP_ACCEPTED],0
    setne al
    mov [r14+136],rax                  ; job admission is NOT job completion
    inc qword [rel ag_head]
    and qword [rel ag_head],AG_CAP-1
    cmp qword [rel ag_retained],AG_CAP
    jae .overwrite
    inc qword [rel ag_retained]
    jmp .out
.overwrite:
    cmp qword [rel ag_overwritten],-1
    je .out
    inc qword [rel ag_overwritten]
    jmp .out
.exhausted:
    mov qword [rel ag_revision],-1     ; never mint MAX or wrap an identity
    cmp qword [rel ag_lost],-1
    je .out
    inc qword [rel ag_lost]
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

;; audit_guest_command_refusal(EDI=raw op u32, RSI=frame sequence or 0,
; EDX=GRR_* reason 1..9, ECX=unchanged CMDE refusal code). Private: called only
; by guest_request_submit after gr_binding_current succeeded in that same
; submit, so the binding globals ARE this guest's identity. No frame byte other
; than op and sequence is retained. Preserves all registers and flags.
audit_guest_command_refusal:
    pushfq
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
    push r13
    push r14
    push r15
    mov r12d,edi                      ; raw op, zero-extended
    mov r13,rsi
    mov r14d,edx
    mov r15d,ecx
    cmp r14d,1
    jb .out
    cmp r14d,AG_REF_REASONS
    ja .out
    ; Per-binding counters reset lazily on the first refusal of a new identity.
    call ag_ref_counter_current
    test eax,eax
    jnz .counted
    lea rdi,[rel ag_ref_total]
    xor eax,eax
    mov ecx,2+AG_REF_REASONS
    cld
    rep stosq
    mov rax,[rel gr_pid]
    mov [rel ag_ref_id],rax
    mov rax,[rel gr_serial]
    mov [rel ag_ref_id+8],rax
    mov eax,[rel gr_start]
    mov [rel ag_ref_id+16],rax
    mov rax,[rel gr_bound_vm_epoch]
    mov [rel ag_ref_id+24],rax
    mov rax,[rel gr_session]
    mov [rel ag_ref_id+32],rax
.counted:
    lea rdi,[rel ag_ref_total]
    call ag_sat_inc
    lea rdi,[rel ag_ref_reason]
    lea rdi,[rdi+r14*8-8]
    call ag_sat_inc
    lea rdi,[rel ag_ref_change]
    call ag_sat_inc
    ; Coalesce an exact repeat of the newest refusal row (identity/op/reason/code).
    cmp qword [rel ag_ref_retained],0
    je .new
    mov rax,[rel ag_ref_head]
    dec rax
    and rax,AG_REF_CAP-1
    imul rax,AG_ROW
    lea rbx,[rel ag_ref_ring]
    add rbx,rax
    call ag_row_matches
    test eax,eax
    jz .new
    cmp [rbx+56],r12
    jne .new
    cmp [rbx+104],r15
    jne .new
    movzx eax,byte [rbx+112]
    cmp eax,r14d
    jne .new
    mov [rbx+48],r13
    mov rax,[rbx+112]
    shr rax,8
    cmp eax,0xffffffff
    je .restamp
    add qword [rbx+112],AG_REPEAT_ONE
.restamp:
    call ag_ref_stamp
    jmp .out
.new:
    cmp qword [rel ag_ref_revision],-2
    jae .out                          ; counted; never mint MAX or wrap a row id
    inc qword [rel ag_ref_revision]
    mov rax,[rel ag_ref_head]
    imul rax,AG_ROW
    lea rbx,[rel ag_ref_ring]
    add rbx,rax
    cmp qword [rel ag_ref_retained],AG_REF_CAP
    jb .fill
    call ag_row_matches               ; only this binding's lost rows count here
    test eax,eax
    jz .zero
    lea rdi,[rel ag_ref_overwritten]
    call ag_sat_inc
    jmp .zero
.fill:
    inc qword [rel ag_ref_retained]
.zero:
    mov rdi,rbx
    xor eax,eax
    mov ecx,AG_ROW/8
    cld
    rep stosq
    mov rax,[rel ag_ref_revision]
    mov [rbx],rax
    mov rax,[rel gr_pid]
    mov [rbx+8],rax
    mov rax,[rel gr_serial]
    mov [rbx+16],rax
    mov eax,[rel gr_start]
    mov [rbx+24],rax
    mov rax,[rel gr_bound_vm_epoch]
    mov [rbx+32],rax
    mov rax,[rel gr_session]
    mov [rbx+40],rax
    mov [rbx+48],r13
    mov [rbx+56],r12
    mov rax,[rel gr_cp_generation]
    mov [rbx+72],rax
    mov rax,[rel ag_revision]         ; newest accepted audit_sequence, for order
    mov [rbx+80],rax
    mov [rbx+104],r15
    mov eax,r14d
    or eax,AG_REPEAT_ONE
    mov [rbx+112],rax
    call ag_ref_stamp
    inc qword [rel ag_ref_head]
    and qword [rel ag_ref_head],AG_REF_CAP-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    ret

; Busy/remote/depth or no current binding: no identity was established and
; another dispatch may own the row writer, so only a boot-global counter moves.
audit_guest_command_unbound:
    pushfq
    push rdi
    lea rdi,[rel ag_ref_unbound]
    call ag_sat_inc
    lea rdi,[rel ag_ref_change]
    call ag_sat_inc
    pop rdi
    popfq
    ret

; RDI -> u64 counter: increment unless already MAX. Clobbers flags only.
ag_sat_inc:
    cmp qword [rdi],-1
    je .out
    inc qword [rdi]
.out:
    ret

; RBX refusal row: native clock into observed_us, refused (+clock unknown) flags.
ag_ref_stamp:
    call time_monotonic_now_us
    mov qword [rbx+144],AG_ROW_REFUSED
    test rax,rax
    jz .unknown
    cmp rax,-1
    jne .known
.unknown:
    xor eax,eax
    or qword [rbx+144],2
.known:
    mov [rbx+120],rax
    ret

; EAX=1 iff the per-binding refusal counters belong to the current binding.
ag_ref_counter_current:
    cmp qword [rel ag_ref_id],0
    je .no
    mov rax,[rel gr_pid]
    cmp rax,[rel ag_ref_id]
    jne .no
    mov rax,[rel gr_serial]
    cmp rax,[rel ag_ref_id+8]
    jne .no
    mov eax,[rel gr_start]
    cmp rax,[rel ag_ref_id+16]
    jne .no
    mov rax,[rel gr_bound_vm_epoch]
    cmp rax,[rel ag_ref_id+24]
    jne .no
    mov rax,[rel gr_session]
    cmp rax,[rel ag_ref_id+32]
    jne .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; RDI validated native output1856 (GCA1 v2). Called only by the current-binding getter.
; Snapshot identity is actual current binding; older lifetimes stay private.
; No clock ->0 without destination writes. No yield/allocation/consume/clear.
audit_guest_command_snapshot:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    mov r13,rax
    ; Validate the current clock against every matching original before any
    ; destination write. History is not limited by the dispatch deadline.
    lea rbx,[rel ag_ring]
    mov r14d,AG_CAP
.preflight:
    call ag_row_matches
    test eax,eax
    jz .pre_next
    cmp r13,[rbx+120]
    jb .bad
.pre_next:
    add rbx,AG_ROW
    dec r14d
    jnz .preflight
    lea rbx,[rel ag_ref_ring]
    mov r14d,AG_REF_CAP
.ref_preflight:
    call ag_row_matches
    test eax,eax
    jz .ref_pre_next
    cmp r13,[rbx+120]
    jb .bad
.ref_pre_next:
    add rbx,AG_ROW
    dec r14d
    jnz .ref_preflight
    mov rdi,r12
    xor eax,eax
    mov ecx,AG_BYTES/8
    cld
    rep stosq
    mov rax,0x0740000231414347         ; GCA1,u16v2,u16size1856
    mov [r12],rax
    mov rax,[rel gr_pid]
    mov [r12+8],rax
    mov rax,[rel gr_serial]
    mov [r12+16],rax
    mov eax,[rel gr_start]
    mov [r12+24],rax
    mov rax,[rel gr_bound_vm_epoch]
    mov [r12+32],rax
    mov rax,[rel gr_session]
    mov [r12+40],rax
    mov rax,[rel ag_revision]
    mov [r12+48],rax
    cmp rax,-1
    jne .total
    dec rax
.total:
    mov [r12+56],rax
    mov rax,[rel ag_overwritten]
    mov [r12+64],rax
    mov rax,[rel ag_lost]
    mov [r12+72],rax
    mov [r12+88],r13
    mov qword [r12+96],AG_CAP
    mov qword [r12+104],AG_ROW
    mov eax,1
    cmp qword [rel ag_revision],-1
    jne .not_exhausted
    or eax,2
.not_exhausted:
    cmp qword [rel ag_lost],-1
    jne .flags
    or eax,4
.flags:
    mov [r12+112],rax
    mov r14,[rel ag_head]
    xor r15d,r15d
    mov r13d,AG_CAP
.rows:
    mov rax,r14
    imul rax,AG_ROW
    lea rbx,[rel ag_ring]
    add rbx,rax
    call ag_row_matches
    test eax,eax
    jz .next
    mov rax,r15
    imul rax,AG_ROW
    lea rdi,[r12+rax+128]
    mov rsi,rbx
    mov ecx,AG_ROW/8
    rep movsq
    inc r15
.next:
    inc r14
    and r14,AG_CAP-1
    dec r13d
    jnz .rows
    mov [r12+80],r15
    ; Refused share, oldest first, after the unchanged accepted region.
    mov r14,[rel ag_ref_head]
    xor r15d,r15d
    mov r13d,AG_REF_CAP
.ref_rows:
    mov rax,r14
    imul rax,AG_ROW
    lea rbx,[rel ag_ref_ring]
    add rbx,rax
    call ag_row_matches
    test eax,eax
    jz .ref_next
    mov rax,r15
    imul rax,AG_ROW
    lea rdi,[r12+rax+AG_REF_ROWS_OFF]
    mov rsi,rbx
    mov ecx,AG_ROW/8
    rep movsq
    inc r15
.ref_next:
    inc r14
    and r14,AG_REF_CAP-1
    dec r13d
    jnz .ref_rows
    ; GCF1 counters: per-binding ones only for this binding; unbound is global.
    mov rax,0x0080000131464347         ; GCF1,u16v1,u16size128
    mov [r12+AG_TAIL_OFF],rax
    mov rax,[rel ag_ref_unbound]
    mov [r12+AG_TAIL_OFF+24],rax
    call ag_ref_counter_current
    test eax,eax
    jz .tail_done
    mov rax,[rel ag_ref_total]
    mov [r12+AG_TAIL_OFF+8],rax
    mov rax,[rel ag_ref_overwritten]
    mov [r12+AG_TAIL_OFF+16],rax
    lea rsi,[rel ag_ref_reason]
    lea rdi,[r12+AG_TAIL_OFF+32]
    mov ecx,AG_REF_REASONS
    rep movsq
.tail_done:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RBX actual retained row; only canonical current identity is exposed.
ag_row_matches:
    cmp qword [rbx],0
    je .no
    mov rax,[rel gr_pid]
    cmp rax,[rbx+8]
    jne .no
    mov rax,[rel gr_serial]
    cmp rax,[rbx+16]
    jne .no
    mov eax,[rel gr_start]
    cmp rax,[rbx+24]
    jne .no
    mov rax,[rel gr_bound_vm_epoch]
    cmp rax,[rbx+32]
    jne .no
    mov rax,[rel gr_session]
    cmp rax,[rbx+40]
    jne .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_guest_command_audit 0
alignb 8
ag_revision: resq 1
ag_head: resq 1
ag_retained: resq 1
ag_overwritten: resq 1
ag_lost: resq 1
ag_ring: resb AG_CAP*AG_ROW
ag_ref_revision: resq 1
ag_ref_head: resq 1
ag_ref_retained: resq 1
ag_ref_change: resq 1                 ; any refusal state change, for stream checks
ag_ref_unbound: resq 1
ag_ref_id: resq 5                     ; identity owning the per-binding counters
ag_ref_total: resq 1                  ; these 2+REASONS are zeroed together
ag_ref_overwritten: resq 1
ag_ref_reason: resq AG_REF_REASONS
ag_ref_ring: resb AG_REF_CAP*AG_ROW
%endmacro
WDATA_BSS_DEFER WDATA_guest_command_audit
