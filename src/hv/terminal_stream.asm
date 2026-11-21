;; MODULE hv/terminal_stream
;; LAYER 6
;; EXPORTS terminal_stream_submit, terminal_stream_retire
;; IMPORTS hv/tools_vm_devices, hv/terminal_network, sec/terminal_network_gate, sec/session, core/smp, svc/command
;; OWNER rc-codex-av
;; CONTEXT: bsp_only
; AV half of tools_stream_abi.inc. VM alone supplies disjoint fixed native
; request/reply arrays inside its stopped-vCPU tools exit. No guest pointers,
; identity assertions, callbacks, reset or lifecycle calls enter this parser.
; Native callbacks for the broker still require actual tools snapshot/current
; identity and authenticated policy; this parser alone cannot configure them.
%include "hv/tools_stream_abi.inc"
%include "core/abi/wdata.inc"

ts_local:
    cmp byte [rel cmd_in_dispatch],0
    jne .no
    cmp dword [rel cmd_dispatch_depth],0
    jne .no
    cmp byte [rel command_auth_remote_active],0
    jne .no
    sub rsp,8
    call smp_current_logical
    add rsp,8
    test eax,eax
    setz al
    movzx eax,al
    ret
.no:
    xor eax,eax
    ret

; Original binding must still be actual tools plus local unlocked owner.
ts_current:
    sub rsp,8
    call ts_local
    test eax,eax
    jz .no
    cmp byte [rel ts_fenced],0
    jne .no
    cmp byte [rel session_locked],0
    jne .no
    cmp byte [rel pbm_try_media],0
    jne .no
    call tools_vm_exit_endpoint
    test rax,rax
    jz .no
    cmp rax,[rel ts_endpoint]
    jne .no
    cmp edx,[rel ts_start]
    jne .no
    call session_shell_local_authority
    cmp rax,1
    jne .no
    cmp rax,[rel ts_owner]
    jne .no
    test rdx,rdx
    jz .no
    cmp rdx,[rel ts_session]
    jne .no
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

; Bind only the first actual tools START, or a strictly newer native START
; AFTER native retirement fenced the old one. Byte cleanup/guest requests can
; never reset the old counter. Fresh START has its own logical sequence1.
ts_bind:
    push rbx
    push r12
    sub rsp,8
    cmp byte [rel session_locked],0
    jne .no
    cmp byte [rel pbm_try_media],0
    jne .no
    call tools_vm_exit_endpoint
    test rax,rax
    jz .no
    test edx,edx
    jz .no
    mov rbx,rax
    mov r12d,edx
    cmp dword [rel ts_start],0
    je .new
    cmp byte [rel ts_fenced],0
    je .same
    cmp byte [rel ts_retired],1
    jne .no
    cmp r12d,[rel ts_start]
    jbe .no
.new:
    call session_shell_local_authority
    cmp rax,1
    jne .no
    test rdx,rdx
    jz .no
    mov [rel ts_owner],rax
    mov [rel ts_session],rdx
    mov [rel ts_endpoint],rbx
    mov [rel ts_start],r12d
    mov qword [rel ts_sequence],0
    mov byte [rel ts_fenced],0
    mov byte [rel ts_retired],0
    mov eax,1
    jmp .out
.same:
    cmp rbx,[rel ts_endpoint]
    jne .no
    cmp r12d,[rel ts_start]
    jne .no
    ; The endpoint was just sampled; current() below independently rechecks
    ; the owner/session before any request or broker effect is admitted.
    cmp byte [rel session_locked],0
    jne .no
    call session_shell_local_authority
    cmp rax,1
    jne .no
    cmp rax,[rel ts_owner]
    jne .no
    cmp rdx,[rel ts_session]
    jne .no
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; Return address of owned handle cell in RBX, or RBX0. All four broker handles
; remain native-generated and scoped to this original binding.
ts_find:
    lea rbx,[rel ts_handles]
    mov ecx,4
.next:
    cmp rdi,[rbx]
    je .out
    add rbx,8
    loop .next
    xor ebx,ebx
.out:
    ret

; VM request/len/reply fixed native arrays -> exact reply length, or0. Request
; syntax is checked before consuming the next sequence; a valid operation
; consumes it before ANY broker call, including busy/refused/uncertain effects.
terminal_stream_submit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13d,esi
    mov r14,rdx
    call ts_local
    test eax,eax
    jz .out_zero
    cmp byte [rel ts_busy],0
    jne .out_zero
    cmp r13d,TSTREAM_HEADER
    jb .out_zero
    cmp r13d,TSTREAM_RECORD_MAX
    ja .out_zero
    test r12,r12
    jz .out_zero
    test r14,r14
    jz .out_zero
    mov byte [rel ts_busy],1
    lea rdi,[rel ts_request]
    mov rsi,r12
    mov ecx,r13d
    cld
    rep movsb
    cmp dword [rel ts_request+TSTREAM_H_VERSION],TSTREAM_VERSION
    jne .drop
    cmp dword [rel ts_request+TSTREAM_H_RESERVED],0
    jne .drop
    mov eax,[rel ts_request+TSTREAM_H_LENGTH]
    cmp eax,TSTREAM_PAYLOAD_MAX
    ja .drop
    add eax,TSTREAM_HEADER
    cmp eax,r13d
    jne .drop
    mov r15d,[rel ts_request+TSTREAM_H_OPCODE]
    cmp r15d,TSTREAM_OPEN
    jb .drop
    cmp r15d,TSTREAM_STATUS
    ja .drop
    cmp r15d,TSTREAM_OPEN
    je .syntax_open
    cmp qword [rel ts_request+TSTREAM_H_HANDLE],0
    je .drop
    cmp r15d,TSTREAM_SEND
    je .syntax_send
    cmp dword [rel ts_request+TSTREAM_H_LENGTH],0
    jne .drop
    jmp .syntax_ok
.syntax_send:
    cmp dword [rel ts_request+TSTREAM_H_LENGTH],0
    je .drop
    jmp .syntax_ok
.syntax_open:
    cmp qword [rel ts_request+TSTREAM_H_HANDLE],0
    jne .drop
    cmp dword [rel ts_request+TSTREAM_H_LENGTH],5
    jb .drop
    cmp word [rel ts_request+TSTREAM_HEADER],443
    jne .drop
    movzx edx,word [rel ts_request+TSTREAM_HEADER+2]
    test edx,edx
    jz .drop
    cmp edx,253
    ja .drop
    lea eax,[rdx+4]
    cmp eax,[rel ts_request+TSTREAM_H_LENGTH]
    jne .drop
    lea rdi,[rel ts_canon]
    lea rsi,[rel ts_request+TSTREAM_HEADER+4]
    call terminal_network_host_canon
    movzx ecx,word [rel ts_request+TSTREAM_HEADER+2]
    cmp eax,ecx
    jne .drop
    lea rdi,[rel ts_canon]
    lea rsi,[rel ts_request+TSTREAM_HEADER+4]
    cld
    repe cmpsb
    jne .drop
.syntax_ok:
    call ts_bind
    test eax,eax
    jz .fence
    mov rax,[rel ts_request+TSTREAM_H_SEQUENCE]
    test rax,rax
    jz .drop
    cmp qword [rel ts_sequence],-1
    je .drop
    dec rax
    cmp rax,[rel ts_sequence]
    jne .drop
    inc rax
    mov [rel ts_sequence],rax
    mov dword [rel ts_reply+TSTREAM_H_VERSION],TSTREAM_VERSION
    mov dword [rel ts_reply+TSTREAM_H_OPCODE],TSTREAM_REFUSED_STATUS
    mov [rel ts_reply+TSTREAM_H_SEQUENCE],rax
    mov rax,[rel ts_request+TSTREAM_H_HANDLE]
    mov [rel ts_reply+TSTREAM_H_HANDLE],rax
    cmp r15d,TSTREAM_OPEN
    je .open_slot
    mov rdi,rax
    call ts_find
    test rbx,rbx
    jz .refused
    jmp .effect
.open_slot:
    xor edi,edi
    call ts_find
    test rbx,rbx
    jnz .effect
    mov dword [rel ts_reply+TSTREAM_H_OPCODE],TSTREAM_BUSY
    jmp .publish
.effect:
    call ts_current                  ; immediately before the native effect
    test eax,eax
    jz .fence
    cmp r15d,TSTREAM_OPEN
    je .open
    mov rdi,[rbx]
    cmp r15d,TSTREAM_SEND
    je .send
    cmp r15d,TSTREAM_READ
    je .read
    cmp r15d,TSTREAM_CLOSE
    je .close
    call terminal_network_status
    cmp eax,7
    ja .failed
    mov [rel ts_reply+TSTREAM_HEADER],eax
    mov dword [rel ts_reply+TSTREAM_H_LENGTH],4
    jmp .ok
.open:
    lea rdi,[rel ts_canon]
    movzx esi,word [rel ts_request+TSTREAM_HEADER+2]
    mov edx,443
    call terminal_network_open
    test rax,rax
    jz .refused
    mov [rbx],rax
    mov [rel ts_reply+TSTREAM_H_HANDLE],rax
    jmp .ok
.send:
    lea rsi,[rel ts_request+TSTREAM_HEADER]
    mov edx,[rel ts_request+TSTREAM_H_LENGTH]
    call terminal_network_send
    test rax,rax
    jz .busy
    mov edx,[rel ts_request+TSTREAM_H_LENGTH]
    cmp rax,rdx
    jne .failed
    mov [rel ts_reply+TSTREAM_HEADER],eax
    mov dword [rel ts_reply+TSTREAM_H_LENGTH],4
    jmp .ok
.read:
    lea rsi,[rel ts_reply+TSTREAM_HEADER]
    mov edx,TSTREAM_PAYLOAD_MAX
    call terminal_network_read
    test rax,rax
    jz .pending
    cmp rax,-2
    je .eof
    cmp rax,TSTREAM_PAYLOAD_MAX
    ja .failed
    mov [rel ts_reply+TSTREAM_H_LENGTH],eax
    jmp .ok
.eof:
    mov qword [rbx],0
    mov dword [rel ts_reply+TSTREAM_H_OPCODE],TSTREAM_EOF
    jmp .publish
.close:
    call terminal_network_close
    test eax,eax
    jz .pending
    cmp eax,1
    jne .failed
    mov qword [rbx],0
.ok:
    mov dword [rel ts_reply+TSTREAM_H_OPCODE],TSTREAM_OK
    jmp .publish
.pending:
    mov dword [rel ts_reply+TSTREAM_H_OPCODE],TSTREAM_PENDING
    jmp .publish
.busy:
    mov dword [rel ts_reply+TSTREAM_H_OPCODE],TSTREAM_BUSY
    jmp .publish
.failed:
    mov dword [rel ts_reply+TSTREAM_H_OPCODE],TSTREAM_FAILED
    jmp .publish
.refused:
    mov dword [rel ts_reply+TSTREAM_H_OPCODE],TSTREAM_REFUSED_STATUS
.publish:
    call ts_current                  ; no stale reply publication
    test eax,eax
    jz .fence
    mov r13d,[rel ts_reply+TSTREAM_H_LENGTH]
    add r13d,TSTREAM_HEADER
    mov rdi,r14
    lea rsi,[rel ts_reply]
    mov ecx,r13d
    cld
    rep movsb
    call ts_current                  ; wipe any failed final copyout
    test eax,eax
    jz .wipe_output
    call ts_wipe_scratch
    mov byte [rel ts_busy],0
    mov eax,r13d
    jmp .out
.wipe_output:
    mov rdi,r14
    xor eax,eax
    mov ecx,TSTREAM_RECORD_MAX
    cld
    rep stosb
.fence:
    mov byte [rel ts_fenced],1       ; observed loss never revives this START
    call terminal_network_retire     ; fence queued bytes before a later tick
.drop:
    call ts_wipe_scratch
    mov byte [rel ts_busy],0
.out_zero:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

ts_wipe_scratch:
    lea rdi,[rel ts_scratch]
    xor eax,eax
    mov ecx,ts_scratch_end-ts_scratch
    cld
    rep stosb
    ret

; VM lifecycle only, outside an open exit (VM checks before this call). Fences
; synchronously even when original TCP retirement retains a busy cookie. The
; broker owns that retiring cookie; no request can admit or copy bytes for it.
; This is not a release/CPU-retirement receipt and never calls VM lifecycle.
terminal_stream_retire:
    sub rsp,8
    call ts_local
    test eax,eax
    jz .no
    cmp byte [rel ts_busy],0
    jne .no
    mov byte [rel ts_fenced],1       ; fence before retiring original cookies
    call terminal_network_retire
    lea rdi,[rel ts_handles]
    xor eax,eax
    mov ecx,4
    cld
    rep stosq
    call ts_wipe_scratch
    mov byte [rel ts_retired],1      ; old handle cells cleared by lifecycle
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

%macro WDATA_hv_terminal_stream 0
align 8,db 0
ts_private:
ts_endpoint: dq 0
ts_owner: dq 0
ts_session: dq 0
ts_sequence: dq 0
ts_start: dd 0
ts_busy: db 0
ts_fenced: db 0
ts_retired: db 0
align 8,db 0
ts_handles: times 4 dq 0
ts_scratch:
ts_request: times TSTREAM_RECORD_MAX db 0
ts_reply: times TSTREAM_RECORD_MAX db 0
ts_canon: times 256 db 0
ts_scratch_end:
ts_private_end:
%endmacro
WDATA_DEFER WDATA_hv_terminal_stream
