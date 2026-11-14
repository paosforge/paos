;; MODULE hv/terminal_transport
;; LAYER 5
;; PURPOSE Bounded stopped-driver-vCPU Terminal command/hook transport.
;; EXPORTS terminal_driver_pio, terminal_transport_configure, terminal_transport_retire, terminal_request_endpoint, terminal_frame_valid
;; IMPORTS sec/session, svc/command, svc/command_auth, core/smp
;; OWNER saga:terminal_transport
; Codex / rc-vm-claude. Native callback ABI: docs/TERMINAL_TRANSPORT.md.
; No app binding, claimed PID, capability, guest pointer or direct handler call.
TT_CONTROL equ 0x5070
TT_DATA equ 0x5074
TT_MAGIC equ 0x314d5254
TT_BYTES equ 1088

; RDI points to four native callbacks [probe,submit,read_guard,retire].
; Native init only. Copy before retiring the previous producer. Zero denies.
terminal_transport_configure:
    cmp byte [rel tt_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    test rdi,rdi
    jz .bad
    mov rax,rdi
    add rax,32
    jc .bad
    cmp qword [rdi],0
    je .bad
    cmp qword [rdi+8],0
    je .bad
    cmp qword [rdi+16],0
    je .bad
    cmp qword [rdi+24],0
    je .bad
    push rdi
    lea rdi,[rel terminal_transport_retire]
    call guest_request_configure_terminal_transport
    pop rdi
    test eax,eax
    jz .bad
    call terminal_transport_retire
    push rcx
    push rsi
    mov rsi,rdi
    lea rdi,[rel tt_ops]
    mov ecx,4
    cld
    rep movsq
    pop rsi
    pop rcx
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Preserve flags/registers. Never reset identity or the replay floor.
; Used by START/STOP and native policy revocation. Local clear is separate.
terminal_transport_retire:
    pushfq
    cmp byte [rel tt_busy],0
    je .notify
    mov byte [rel tt_cancelled],1   ; retirement inside any callback is final
.notify:
    cmp qword [rel tt_ops+24],0
    je .clear
    call [rel tt_ops+24]              ; same preservation contract
.clear:
    popfq
tt_clear:
    pushfq
    push rax
    push rcx
    push rdi
    mov dword [rel tt_count],0
    mov dword [rel tt_cursor],TT_BYTES
    mov byte [rel tt_receiving],0
    mov byte [rel tt_mode],0
    lea rdi,[rel tt_frame]
    xor eax,eax
    mov ecx,(2*TT_BYTES)/8
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    popfq
    ret

; EDI normalized VMX qualification, ESI guest EAX. Only actual driver exit.
; EAX claimed (0/1); EDX scalar IN data. Caller retains instruction custody.
terminal_driver_pio:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12d,esi
    mov r13d,edi
    shr r13d,16
    cmp r13d,TT_CONTROL
    je .ours
    cmp r13d,TT_DATA
    jne .other
.ours:
    cmp byte [rel tt_busy],0
    jne .refuse                    ; do not overwrite in-flight native copies
    cmp dword [rel vcb_handoff_active],0
    jne .invalidate
    call smp_current_logical
    test eax,eax
    jnz .invalidate
    mov eax,ebx
    and eax,0xffbf                 ; immediate/DX is immaterial; REP/string deny
    cmp eax,3
    je .width
    cmp eax,11
    jne .invalidate
.width:
    call tt_lifetime
    test eax,eax
    jz .invalidate
    test ebx,8
    jnz .input
    cmp r13d,TT_DATA
    je .data
    test r12d,r12d
    jz .clear
    cmp r12d,TT_BYTES
    je .begin
    cmp r12d,1
    je .submit
    cmp r12d,2
    je .floor
    jmp .invalidate
.clear:
    call tt_clear
    jmp .claimed
.begin:
    call tt_clear
    mov byte [rel tt_receiving],1
    jmp .claimed
.floor:
    call tt_clear
    mov dword [rel tt_reply],1
    mov rax,[rel tt_last_seq]
    mov [rel tt_reply+8],rax
    mov dword [rel tt_cursor],0
    mov byte [rel tt_mode],1
    jmp .claimed
.data:
    cmp byte [rel tt_receiving],1
    jne .invalidate
    mov eax,[rel tt_count]
    cmp eax,TT_BYTES
    jae .invalidate
    lea rdx,[rel tt_frame]
    mov [rdx+rax],r12d
    add dword [rel tt_count],4
    jmp .claimed
.submit:
    cmp byte [rel tt_receiving],1
    jne .invalidate
    mov byte [rel tt_receiving],0
    cmp dword [rel tt_count],TT_BYTES
    jne .invalidate
    lea rdi,[rel tt_frame]
    call terminal_frame_valid
    test eax,eax
    jz .invalidate
    mov rax,[rel tt_frame+8]
    cmp rax,[rel tt_last_seq]
    jbe .invalidate
    mov [rel tt_last_seq],rax       ; burned before dispatch, including DENY
    mov byte [rel tt_busy],1
    lea rdi,[rel terminal_request_endpoint]
    mov esi,[rel tt_start]
    lea rdx,[rel tt_frame]
    mov ecx,TT_BYTES
    lea r8,[rel tt_reply]
    call [rel tt_ops+8]
    mov r12d,eax
    call tt_current
    test eax,eax
    jz .lost
    cmp r12d,255
    ja .lost
    test r12d,r12d
    jz .success
    ; Never publish native error scratch, operands, pointers or stale results.
    lea rdi,[rel tt_reply]
    xor eax,eax
    mov ecx,TT_BYTES/8
    cld
    rep stosq
    mov dword [rel tt_reply],1
    mov [rel tt_reply+4],r12d
    mov rax,[rel tt_frame+8]
    mov [rel tt_reply+8],rax
    jmp .ready
.success:
    call tt_reply_valid
    test eax,eax
    jz .lost
.ready:
    mov byte [rel tt_mode],2
    mov dword [rel tt_cursor],0
    mov byte [rel tt_busy],0
    jmp .claimed
.lost:
    mov byte [rel tt_busy],0
    jmp .invalidate
.input:
    cmp r13d,TT_CONTROL
    je .magic
    mov ecx,[rel tt_cursor]
    cmp ecx,TT_BYTES
    jae .invalidate
    cmp byte [rel tt_mode],1
    je .word                      ; only the non-sensitive floor header
    cmp byte [rel tt_mode],2
    jne .invalidate
    mov byte [rel tt_busy],1
    lea rdi,[rel terminal_request_endpoint]
    mov esi,[rel tt_start]
    lea rdx,[rel tt_frame]
    lea r8,[rel tt_reply]
    call [rel tt_ops+16]           ; final original-result policy at every word
    mov r12d,eax
    call tt_current
    mov byte [rel tt_busy],0
    test eax,eax
    jz .invalidate
    cmp r12d,1
    jne .invalidate
.word:
    mov eax,[rel tt_cursor]
    lea rdx,[rel tt_reply]
    mov edx,[rdx+rax]
    add dword [rel tt_cursor],4
    jmp .value
.magic:
    mov edx,TT_MAGIC
    jmp .value
.invalidate:
    call terminal_transport_retire
.refuse:
    mov edx,-1
    jmp .value
.claimed:
    xor edx,edx
.value:
    mov eax,1
    jmp .out
.other:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Actual driver state only, never a guest-supplied binding or ambient OWNER.
tt_hardware_current:
    cmp byte [rel hv_linux_running],1
    jne .bad
    cmp byte [rel hv_linux_run_req],0
    jne .bad
    cmp byte [rel hv_linux_stop_req],0
    jne .bad
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    cmp qword [rel session_key_handle],0
    je .bad
    cmp qword [rel session_bound_pid],0
    je .bad
    mov eax,[rel hv_linux_start_consumed]
    test eax,eax
    jz .bad
    cmp eax,[rel hv_linux_start_gen]
    jne .bad
    mov rdx,[rel session_authority_epoch]
    test rdx,rdx
    jz .bad
    cmp rdx,-1
    je .bad
    cmp rdx,[rel session_authority]
    jne .bad
    ret                            ; EAX actual START, RDX session epoch
.bad:
    xor eax,eax
    ret

tt_lifetime:
    cmp qword [rel tt_ops],0
    je .bad
    call tt_hardware_current
    test eax,eax
    jz .bad
    push rax
    push rdx
    lea rdi,[rel terminal_request_endpoint]
    mov esi,eax
    mov byte [rel tt_cancelled],0
    mov byte [rel tt_busy],1
    call [rel tt_ops]
    mov byte [rel tt_busy],0
    mov rcx,rax
    pop rdx
    pop rax
    cmp byte [rel tt_cancelled],0
    jne .bad
    test rcx,rcx
    jz .bad
    cmp rcx,[rel tt_binding]
    jb .bad
    je .same
    call terminal_transport_retire
    mov [rel tt_binding],rcx
    mov [rel tt_start],eax
    mov [rel tt_session],rdx
.same:
    call tt_current_hardware
    ret
.bad:
    xor eax,eax
    ret

tt_current_hardware:
    call tt_hardware_current
    test eax,eax
    jz .bad
    cmp eax,[rel tt_start]
    jne .bad
    cmp rdx,[rel tt_session]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; After a callback, reprove the same binding and actual START/session.
tt_current:
    cmp byte [rel tt_cancelled],0
    jne .bad
    call tt_current_hardware
    test eax,eax
    jz .bad
    lea rdi,[rel terminal_request_endpoint]
    mov esi,[rel tt_start]
    call [rel tt_ops]
    cmp byte [rel tt_cancelled],0
    jne .bad
    test rax,rax
    jz .bad
    cmp rax,[rel tt_binding]
    jne .bad
    jmp tt_current_hardware
.bad:
    xor eax,eax
    ret

; RDI exactly1088 native bytes. No registry/policy decisions here.
terminal_frame_valid:
    cmp dword [rdi],1
    jne .bad
    cmp qword [rdi+8],0
    je .bad
    mov eax,[rdi+4]
    dec eax
    cmp eax,2
    ja .bad
    mov rax,[rdi+32]
    or rax,[rdi+40]
    or rax,[rdi+48]
    or rax,[rdi+56]
    jnz .bad
    mov ecx,[rdi+28]
    cmp dword [rdi+4],3
    je .page
    cmp qword [rdi+16],0
    jne .bad
    cmp dword [rdi+24],0
    jne .bad
    test ecx,ecx
    jz .bad
    cmp ecx,1023
    ja .bad
    xor edx,edx
.text:
    movzx eax,byte [rdi+64+rdx]
    sub eax,0x20
    cmp eax,0x5e
    ja .bad
    inc edx
    cmp edx,ecx
    jb .text
    jmp .padding
.page:
    cmp qword [rdi+16],0
    je .bad
    mov eax,[rdi+24]
    cmp eax,65536
    jae .bad
    test eax,1023
    jnz .bad
    test ecx,ecx
    jnz .bad
    xor edx,edx
.padding:
    cmp byte [rdi+64+rdx],0
    jne .bad
    inc edx
    cmp edx,1024
    jb .padding
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

tt_reply_valid:
    lea rdi,[rel tt_reply]
    cmp dword [rdi],1
    jne .bad
    cmp dword [rdi+4],0
    jne .bad
    mov rax,[rel tt_frame+8]
    cmp rax,[rdi+8]
    jne .bad
    cmp dword [rel tt_frame+4],3
    jne .id
    mov rax,[rel tt_frame+16]
.id:
    cmp rax,[rdi+16]
    jne .bad
    mov eax,[rel tt_frame+24]
    cmp eax,[rdi+24]
    jne .bad
    mov ecx,[rdi+28]
    cmp ecx,1024
    ja .bad
    mov edx,[rdi+32]
    cmp edx,65536
    ja .bad
    add eax,ecx
    cmp eax,edx
    ja .bad
    setb al
    movzx eax,al
    cmp eax,[rdi+36]
    jne .bad
    test eax,eax
    jz .last
    cmp ecx,1024                   ; finite progress; PAGE always aligned
    jne .bad
.last:
    mov rax,[rdi+40]
    or rax,[rdi+48]
    or rax,[rdi+56]
    jnz .bad
    mov edx,ecx
    cmp edx,1024
    je .ok
.padding:
    cmp byte [rdi+64+rdx],0
    jne .bad
    inc edx
    cmp edx,1024
    jb .padding
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

terminal_request_endpoint: dq 0x314d52544e49414d ; address is native endpoint
%include "core/abi/wdata.inc"
%macro WDATA_terminal_transport 0
alignb 8
tt_ops: resq 4
tt_binding: resq 1
tt_session: resq 1
tt_last_seq: resq 1
tt_start: resd 1
tt_count: resd 1
tt_cursor: resd 1
tt_busy: resb 1
tt_cancelled: resb 1
tt_receiving: resb 1
tt_mode: resb 1
alignb 8
tt_frame: resb TT_BYTES
tt_reply: resb TT_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_terminal_transport
