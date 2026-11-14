;; MODULE fs/format_job
;; LAYER 4
;; PURPOSE One native confirmed removable-format job; transport remains F2.
;; EXPORTS format_job_prepare, format_job_start, format_job_tick, format_job_cancel, format_job_snapshot, format_job_observe, format_job_proof, format_job_observe_named, format_job_proof_named
;; IMPORTS fs/fs_format, fs/guest_volume, hv/filesystem_domain, hv/filesystem_wire, hv/vm_profile, sec/session, sec/principal, core/smp, core/time, core/csprng, boot/header, boot/beacon
;; OWNER saga:storage
;; CONTEXT: bsp_only
; Only the original local card (its native BSP, depth-zero gate) can prepare/start. A frame is an observation,
; never authority: F2 owns START binding and its lease, F1 owns native proof.
; No private F1/F2 access, disk write, guest implementation or borrowed copy job.
; Phases: 0 empty,1 prepared,2 running,3 retiring,4 terminal.
; Snapshot32: stateD,reservedD,doneQ,totalQ,kindD,F1 outcomeD.
FJ_LIFE_US equ 300000000
FJ_CANCEL_US equ 5000000

fj_guard:
    call smp_current_logical
    test eax,eax
    jnz .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    test rdx,rdx
    jz .bad
    cmp rdx,-1
    je .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Read-only native original offer tuple, before any password/decision.
format_job_prepare:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    cmp dword [rel fj_phase],2
    je .bad
    cmp dword [rel fj_phase],3
    je .bad
    call fj_guard
    cmp eax,1
    jne .bad
    mov r14,rdx
    lea rdi,[rel fj_data]
    mov ecx,(fj_data_end-fj_data)/8
    xor eax,eax
    cld
    rep stosq
    mov [rel fj_epoch],r14
    mov dword [rel fj_outcome],-1
    mov rdi,rbx
    mov rsi,r12
    mov rdx,r13
    lea rcx,[rel fj_class]
    call fs_format_classify
    test eax,eax
    jnz .bad
    ; Classification just verified this registered descriptor. Copy its public
    ; name now; no departing device/name is dereferenced by an observer later.
    ; An unnamed/oversize descriptor keeps the original direct-pointer API.
    mov rsi,[rbx+dev.name]
    test rsi,rsi
    jnz .name_scan
    mov rax,[rbx+dev.info]
    test rax,rax
    jz .name_done
    mov rsi,[rax+blk_info.name]
    test rsi,rsi
    jz .name_done
.name_scan:
    xor ecx,ecx
.name_byte:
    cmp byte [rsi+rcx],0
    je .name_copy
    inc ecx
    cmp ecx,64
    jb .name_byte
    jmp .name_done
.name_copy:
    mov [rel fj_name_len],ecx
    lea rdi,[rel fj_device_name]
    cld
    rep movsb
.name_done:
    lea rdi,[rel fj_profile_name]
    call vm_profile_find
    test rax,rax
    jz .bad
    mov [rel fj_profile],rax
    cmp qword [rel boot_tsc_start],0
    je .bad
    cmp dword [rel boot_nonce],0
    je .bad
    lea rdi,[rel fj_random]
    mov esi,48
    call csprng_generate
    test eax,eax
    jnz .bad
    mov [rel fj_desc],rbx
    mov rax,[rel fj_class+24]
    test rax,rax
    jz .bad
    mov [rel fj_desc+8],rax
    lea rsi,[rel fj_class]
    lea rdi,[rel fj_desc+16]
    mov ecx,2
    rep movsq
    movzx edi,byte [rel fj_class+32]
    call guest_volume_format_scheme ; sole native/F2 translation site
    cmp rax,-1
    je .bad
    mov [rel fj_desc+136],eax
    movzx eax,byte [rel fj_class+33]
    test eax,eax
    jz .bad
    mov [rel fj_desc+140],eax
    cmp byte [rel fj_class+32],2
    je .gpt
    mov eax,[rel fj_class+36]
    mov [rel fj_desc+32],eax
    jmp .identity
.gpt:
    lea rdi,[rel fj_desc+32]
    lea rsi,[rel fj_class+48]
    mov ecx,4
    rep movsq
.identity:
    mov qword [rel fj_desc+64],PRIN_OWNER
    lea rdi,[rel fj_desc+80]
    lea rsi,[rel fj_random+16]
    mov ecx,2
    rep movsq
    lea rdi,[rel fj_desc+96]
    lea rsi,[rel fj_random]
    mov ecx,2
    rep movsq
    lea rdi,[rel fj_desc+112]
    lea rsi,[rel fj_random+32]
    mov ecx,2
    rep movsq
    mov qword [rel fj_desc+128],1
    mov dword [rel fj_phase],1
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Original successful F1 begin hands confirmation16,kind,label,len here.
; Start owns this custody even on refusal; every attempt consumes preparation.
format_job_start:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov rbx,rdi
    mov r12d,esi
    mov r13,rdx
    mov r14d,ecx
    cmp dword [rel fj_phase],1
    jne .bad_start
    mov dword [rel fj_phase],4
    call fj_guard
    cmp eax,1
    jne .not_started
    cmp rdx,[rel fj_epoch]
    jne .not_started
    test rbx,rbx
    jz .not_started
    mov edi,r12d
    mov rsi,r13
    mov edx,r14d
    call fs_format_label_valid
    test eax,eax
    jnz .not_started
    lea rdi,[rel fj_desc]
    call fs_format_custody
    test eax,eax
    jnz .not_started
    lea rdi,[rel fj_grant]
    mov ecx,40
    xor eax,eax
    cld
    rep stosq
    mov dword [rel fj_grant],0x31475346
    mov dword [rel fj_grant+4],0x00020001 ; FSG1 v1, format kind2
    lea rdi,[rel fj_grant+8]
    lea rsi,[rel fj_desc+96]
    mov ecx,2
    rep movsq
    lea rdi,[rel fj_grant+24]
    lea rsi,[rel fj_desc+80]
    mov ecx,2
    rep movsq
    lea rdi,[rel fj_grant+40]
    lea rsi,[rel fj_desc+64]
    mov ecx,2
    rep movsq
    lea rdi,[rel fj_grant+56]
    lea rsi,[rel fj_desc+112]
    mov ecx,2
    rep movsq
    mov qword [rel fj_grant+72],1
    mov [rel fj_grant+80],r12d
    mov [rel fj_grant+84],r14d
    mov dword [rel fj_grant+88],300000
    mov rax,[rel fj_desc+16]
    mov [rel fj_grant+96],rax
    lea rdi,[rel fj_grant+104]
    mov rsi,r13
    mov ecx,r14d
    rep movsb
    lea rdi,[rel fj_grant+184]
    mov rsi,rbx
    mov ecx,2
    rep movsq
    mov eax,[rel fj_desc+136]
    mov [rel fj_grant+200],al
    mov eax,[rel fj_desc+140]
    mov [rel fj_grant+201],al
    mov rax,[rel boot_tsc_start]
    mov [rel fj_grant+264],rax
    mov eax,[rel boot_nonce]
    mov [rel fj_grant+272],eax
    mov rax,[rel fj_desc+24]
    mov rdx,rax
    shr rdx,55
    jnz .not_started
    shl rax,9
    mov [rel fj_grant+280],rax
    lea rdi,[rel fj_request]
    mov ecx,32
    xor eax,eax
    rep stosq
    mov dword [rel fj_request],0x31435346
    mov dword [rel fj_request+4],0x00010003 ; FSC1 v3 START
    lea rdi,[rel fj_request+8]
    lea rsi,[rel fj_grant+8]
    mov ecx,9
    rep movsq
    mov [rel fj_request+80],r12w
    mov [rel fj_request+82],r14w
    lea rdi,[rel fj_request+88]
    lea rsi,[rel fj_grant+104]
    mov ecx,10
    rep movsq
    lea rdi,[rel fj_request+168]
    lea rsi,[rel fj_grant+184]
    mov ecx,2
    rep movsq
    mov qword [rel fj_request+248],1
    call time_monotonic_now_us
    test rax,rax
    jz .not_started
    mov [rel fj_clock],rax
    add rax,FJ_LIFE_US
    jc .not_started
    mov [rel fj_deadline],rax
    mov dword [rel fj_transport],1    ; uncertain until exact clean FINISH
    mov dword [rel fj_status],1
    mov dword [rel fj_phase],2
    mov rdi,[rel fj_profile]
    lea rsi,[rel fj_desc]
    lea rdx,[rel fj_grant]
    lea rcx,[rel fj_request]
    call fsg_begin
    test rax,rax
    jz .not_started
    mov [rel fj_generation],rax
    ; Accepted F2 START used this exact immutable F3 profile on the BSP.
    ; Retain bytes now; later registry changes cannot rewrite this job's proof.
    lea rdi,[rel fj_profile_seen]
    mov rsi,[rel fj_profile]
    mov ecx,35
    cld
    rep movsq
    or dword [rel fj_proof_flags],1
    mov rax,[rel fj_clock]           ; original START request time, not a host estimate
    mov [rel fj_start_us],rax
    mov [rel fj_event_clock],rax
    call fs_format_state             ; actual F1 HELD/bound state after accepted F2 START
    mov [rel fj_custody_seen],eax
    mov dword [rel fj_pending],1
    xor eax,eax
    jmp .out
.not_started:
    mov dword [rel fj_transport],3
    call fj_end
.bad_start:
    mov eax,-1
.out:
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Memory-only hook: no stop/IO from session wipe or WM retirement.
format_job_cancel:
    cmp dword [rel fj_phase],2
    jne .out
    mov dword [rel fj_cancel],1
.out:
    ret

; Original BSP idle tick, even after the card has been closed. At most one
; poll/submit or retire per tick; no waiting loop and no deadline extension.
format_job_tick:
    push rbx
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp dword [rel fj_phase],3
    je .retire
    cmp dword [rel fj_phase],2
    jne .out
    call fj_guard
    cmp eax,1
    jne .cancel
    cmp rdx,[rel fj_epoch]
    jne .cancel
    call time_monotonic_now_us
    cmp rax,[rel fj_clock]
    jb .fault
    cmp rax,[rel fj_deadline]
    jae .fault
    mov [rel fj_clock],rax
    cmp dword [rel fj_cancel],0
    je .poll
    cmp qword [rel fj_cancel_deadline],0
    jne .cancel_bounded
    add rax,FJ_CANCEL_US
    jc .fault
    mov [rel fj_cancel_deadline],rax
.cancel_bounded:
    mov rax,[rel fj_clock]
    cmp rax,[rel fj_cancel_deadline]
    jae .cancel
.poll:
    cmp dword [rel fj_pending],1
    jne .out
    mov rdi,[rel fj_generation]
    lea rsi,[rel fj_reply]
    call fsg_poll
    test rax,rax
    jz .out
    cmp rax,256
    jne .fault
    mov dword [rel fj_pending],0
    lea rdi,[rel fj_reply]
    lea rsi,[rel fj_request]
    call fsc_wire_reply
    test eax,eax
    jnz .fault
    cmp word [rel fj_reply+4],3
    jne .fault
    cmp dword [rel fj_reply+64],7
    jne .normal_reply
    ; Canonical pre-tool refusal has identity/sequence plus state7,error1,
    ; all other public operands zero. STOP/retire still precedes native end.
    mov rax,0x100000007
    cmp [rel fj_reply+64],rax
    jne .fault
    lea rdi,[rel fj_reply+72]
    mov ecx,4
    xor eax,eax
    cld
    repe scasq
    jne .fault
    lea rdi,[rel fj_reply+112]
    mov ecx,11
    repe scasq
    jne .fault
    mov dword [rel fj_transport],3
    jmp .stop
.normal_reply:
    mov eax,[rel fj_grant+80]
    cmp [rel fj_reply+112],ax
    jne .fault
    cmp qword [rel fj_reply+80],1
    jne .fault
    cmp qword [rel fj_reply+72],1
    ja .fault
    mov rax,[rel fj_reply+72]
    cmp rax,[rel fj_done]
    jb .fault
    mov [rel fj_done],rax
    test dword [rel fj_reply+88],-16 ; v3 never grants cleanup bits4/5
    jnz .fault
    cmp dword [rel fj_finishing],1
    je .finish_reply
    mov eax,[rel fj_reply+64]
    cmp eax,1
    jb .fault
    cmp eax,7
    jae .fault                       ; canonical refusal has total0; never success
    mov [rel fj_status],eax
    cmp eax,4
    jae .terminal
    cmp dword [rel fj_reply+68],0
    jne .fault
    mov edi,2
    cmp dword [rel fj_cancel],0
    je .submit
    cmp dword [rel fj_cancel_sent],0
    jne .submit
    mov dword [rel fj_cancel_sent],1
    mov edi,3                        ; one CANCEL after the pending reply drains
    jmp .submit
.terminal:
    lea rdi,[rel fj_terminal]
    lea rsi,[rel fj_reply]
    mov ecx,32
    cld
    rep movsq
    mov dword [rel fj_finishing],1
    mov dword [rel fj_status],3
    mov edi,4
.submit:
    mov word [rel fj_request+6],di
    lea rdi,[rel fj_request+80]
    mov ecx,21                       ; STATUS/FINISH have no START authority
    xor eax,eax
    rep stosq
    inc qword [rel fj_request+248]
    jz .fault
    mov rdi,[rel fj_generation]
    lea rsi,[rel fj_request]
    call fsg_submit
    test eax,eax
    jnz .fault
    mov dword [rel fj_pending],1
    jmp .out
.finish_reply:
    lea rdi,[rel fj_reply+64]
    lea rsi,[rel fj_terminal+64]
    mov ecx,4                         ; same state/error/done/total/flags/reserved
    cld
    repe cmpsq
    jne .fault
    mov rax,[rel fj_reply+96]
    cmp rax,[rel fj_terminal+96]
    jb .fault
    cmp word [rel fj_reply+114],0
    jne .uncertain
    cmp dword [rel fj_reply+64],4
    jne .fault
    cmp dword [rel fj_reply+68],0
    jne .fault
    cmp qword [rel fj_reply+72],1
    jne .fault
    cmp dword [rel fj_reply+88],7
    jne .fault
    mov eax,[rel fj_grant+80]
    cmp word [rel fj_reply+116],ax
    jne .uncertain
    mov eax,[rel fj_grant+84]
    cmp word [rel fj_reply+118],ax
    jne .uncertain
    lea rdi,[rel fj_reply+120]
    lea rsi,[rel fj_grant+104]
    mov ecx,80
    repe cmpsb
    jne .uncertain
    ; Retain only public fields after every actual FINISH validation above.
    ; No identity, request, confirmation, grant, principal or storage capability.
    lea rdi,[rel fj_finish_seen]
    lea rsi,[rel fj_reply+64]
    mov ecx,5
    cld
    rep movsq
    lea rsi,[rel fj_reply+112]
    mov ecx,11
    rep movsq
    or dword [rel fj_proof_flags],2
    mov dword [rel fj_transport],0
    jmp .stop
.uncertain:
    mov dword [rel fj_transport],1
    jmp .stop
.cancel:
    mov dword [rel fj_cancel],1
    mov dword [rel fj_transport],1
    jmp .stop
.fault:
    mov dword [rel fj_transport],2
.stop:
    call fj_observation_time
    mov [rel fj_stop_us],rax
    mov dword [rel fj_status],8
    mov dword [rel fj_phase],3
    mov rdi,[rel fj_generation]
    call fsg_stop
    test eax,eax
    jnz .quarantine
    jmp .out
.retire:
    ; Stop/retire is allowed after local authority vanished; it can only revoke
    ; this exact retained generation, never submit another guest operation.
    call smp_current_logical
    test eax,eax
    jnz .out
    mov rdi,[rel fj_generation]
    call fsg_retire
    cmp eax,1
    je .out
    test eax,eax
    jnz .quarantine
    call fj_observation_time
    mov [rel fj_retire_us],rax
    call fj_end
    jmp .out
.quarantine:
    mov dword [rel fj_transport],2
    call fj_end
.out:
    pop rbx
    ret

fj_end:
    sub rsp,8
    mov edi,[rel fj_transport]
    lea rsi,[rel fj_result]
    call fs_format_end                ; authoritative native re-probe and custody outcome
    mov [rel fj_outcome],eax
    mov dword [rel fj_phase],4
    mov edx,6                        ; uncertain
    cmp eax,0
    jne .not_done
    cmp dword [rel fj_transport],0
    jne .not_done
    mov edx,4
    jmp .status
.not_done:
    cmp eax,2
    jne .not_quarantine
    mov edx,7
    jmp .status
.not_quarantine:
    cmp eax,3
    jne .status
    mov edx,5
.status:
    mov [rel fj_status],edx
    call fs_format_state             ; retain the state of this exact native end, not a later job
    mov [rel fj_custody_seen],eax
    call fj_observation_time
    mov [rel fj_end_us],rax
    add rsp,8
    ret

; Observation only. Missing/backward time is zero and never changes job policy.
fj_observation_time:
    sub rsp,8
    call time_monotonic_now_us
    test rax,rax
    jz .out
    cmp rax,[rel fj_event_clock]
    jb .missing
    mov [rel fj_event_clock],rax
    jmp .out
.missing:
    xor eax,eax
.out:
    add rsp,8
    ret

; Copy only public progress, same original local authority epoch; no poll/IO.
format_job_snapshot:
    push rbx
    mov rbx,rdi
    cmp esi,32
    jb .none
    call fj_guard
    cmp eax,1
    jne .none
    cmp rdx,[rel fj_epoch]
    jne .none
    cmp dword [rel fj_phase],2
    jb .none
    mov eax,[rel fj_status]
    mov [rbx],eax
    mov dword [rbx+4],0
    mov rax,[rel fj_done]
    mov [rbx+8],rax
    mov qword [rbx+16],1
    mov eax,[rel fj_grant+80]
    mov [rbx+24],eax
    mov eax,[rel fj_outcome]
    mov [rbx+28],eax
    mov eax,32
    pop rbx
    ret
.none:
    xor eax,eax
    pop rbx
    ret

; format_job_observe(RDI=selected registered dev*, RSI=out, EDX=capacity)
; -> EAX=128 / 0. Version1 public memory copy; refusal leaves out untouched.
; Read-only remote OWNER requests may observe their own unlocked epoch. This
; does not use the local-only preparation gate and grants no card/START action.
; Custody is retained at actual F2 acceptance and this job's native F1 end.
format_job_observe:
    push rbx
    push r12
    push r13
    mov rbx,rsi
    mov r12,rdi
    cmp edx,128
    jb .none
    test rbx,rbx
    jz .none
    test r12,r12
    jz .none
    call smp_current_logical
    test eax,eax
    jnz .none
    call session_shell_require_unlocked
    test eax,eax
    jnz .none
    xor edi,edi
    call session_shell_request_principal
    cmp rax,PRIN_OWNER
    jne .none
    mov rdi,[rel fj_epoch]
    call session_shell_authority_validate
    test eax,eax
    jnz .none
    cmp dword [rel fj_phase],2
    jb .none
    cmp dword [rel fj_phase],4
    ja .none
    cmp r12,[rel fj_desc]
    jne .none
    mov rdi,rbx
    mov ecx,16
    xor eax,eax
    cld
    rep stosq
    mov dword [rbx],1
    mov eax,[rel fj_phase]
    mov [rbx+4],eax
    mov rax,[rel fj_generation]
    mov [rbx+8],rax
    mov rax,[rel fj_desc+8]
    mov [rbx+16],rax
    mov rax,[rel fj_desc+16]
    mov [rbx+24],rax
    mov rax,[rel fj_desc+24]
    mov [rbx+32],rax
    movzx eax,byte [rel fj_class+32]
    mov [rbx+40],eax
    movzx eax,byte [rel fj_class+33]
    mov [rbx+44],eax
    mov eax,[rel fj_grant+80]
    mov [rbx+48],eax
    mov eax,[rel fj_status]
    mov [rbx+52],eax
    mov eax,[rel fj_outcome]
    mov [rbx+56],eax
    mov eax,[rel fj_custody_seen]
    mov [rbx+60],eax
    mov rax,[rel fj_done]
    mov [rbx+64],rax
    mov rax,[rel fj_start_us]
    mov [rbx+80],rax
    mov rax,[rel fj_stop_us]
    mov [rbx+88],rax
    mov rax,[rel fj_retire_us]
    mov [rbx+96],rax
    mov rax,[rel fj_end_us]
    mov [rbx+104],rax
    mov eax,[rel fj_transport]
    mov [rbx+112],eax
    mov eax,[rel fj_cancel]
    mov [rbx+116],eax
    mov qword [rbx+72],1
    mov eax,128
    jmp .out
.none:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; format_job_proof(dev*, out, capacity) -> EAX=544 / 0.
; Exact public observe128 prefix, versionD=1, presence flagsD (profile=1,
; validated clean FINISH=2), accepted profile280, public FINISH128.
; FINISH128 = actual reply[64:104] + [112:200]. No authority fields.
; Reuses the complete original observer's OWNER/session/epoch/device/BSP gate.
; Capacity/null/authority refusal leaves the entire output untouched.
; No transport, poll, classification, custody or native job mutation.
format_job_proof:
    push rbx
    cmp edx,544
    jb .none
    mov rbx,rsi
    call format_job_observe
    cmp eax,128
    jne .none
    mov dword [rbx+128],1
    mov eax,[rel fj_proof_flags]
    mov [rbx+132],eax
    lea rdi,[rbx+136]
    lea rsi,[rel fj_profile_seen]
    mov ecx,51                      ; profile280 + FINISH128, contiguous
    cld
    rep movsq
    mov eax,544
    pop rbx
    ret
.none:
    xor eax,eax
    pop rbx
    ret

; Memory-only fallback for a device no longer in the registry. Exact saved
; name (1..63 bytes) selects only this one retained job. It grants no action.
; Both public wrappers tail-call the complete original observer/proof gate.
; RDI=name bytes, ESI=length, RDX=out, ECX=capacity -> EAX=size / 0.
format_job_observe_named:
    push rdx
    push rcx
    sub rsp,8
    call fj_named_descriptor
    add rsp,8
    pop rdx
    pop rsi
    mov rdi,rax
    jmp format_job_observe

format_job_proof_named:
    push rdx
    push rcx
    sub rsp,8
    call fj_named_descriptor
    add rsp,8
    pop rdx
    pop rsi
    mov rdi,rax
    jmp format_job_proof

fj_named_descriptor:
    test rdi,rdi
    jz .none
    test esi,esi
    jz .none
    cmp esi,63
    ja .none
    cmp esi,[rel fj_name_len]
    jne .none
    lea r8,[rel fj_device_name]
    xor ecx,ecx
.byte:
    mov al,[rdi+rcx]
    cmp al,[r8+rcx]
    jne .none
    inc ecx
    cmp ecx,esi
    jb .byte
    mov rax,[rel fj_desc]          ; opaque saved identity, never dereferenced
    ret
.none:
    xor eax,eax
    ret

fj_profile_name: db 'filesystem',0
%include "core/abi/wdata.inc"
%macro WDATA_fs_format_job 0
align 8
fj_data:
fj_phase: dd 0
fj_status: dd 0
fj_epoch: dq 0
fj_profile: dq 0
fj_generation: dq 0
fj_clock: dq 0
fj_deadline: dq 0
fj_cancel_deadline: dq 0
fj_done: dq 0
fj_cancel: dd 0
fj_cancel_sent: dd 0
    dd 0
fj_pending: dd 0
fj_finishing: dd 0
fj_transport: dd 0
fj_outcome: dd 0
    dd 0
fj_start_us: dq 0
fj_stop_us: dq 0
fj_retire_us: dq 0
fj_end_us: dq 0
fj_event_clock: dq 0
fj_custody_seen: dd 0
    dd 0
fj_class: times 80 db 0
fj_desc: times 144 db 0
fj_random: times 48 db 0
fj_grant: times 320 db 0
fj_request: times 256 db 0
fj_reply: times 256 db 0
fj_terminal: times 256 db 0
fj_result: times 64 db 0
fj_proof_flags: dd 0
    dd 0
fj_profile_seen: times 280 db 0
fj_finish_seen: times 128 db 0
fj_name_len: dd 0
    dd 0
fj_device_name: times 64 db 0
fj_data_end:
%endmacro
WDATA_DEFER WDATA_fs_format_job
