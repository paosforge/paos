;; MODULE hv/tools_vm_stream
;; LAYER 5
;; EXPORTS tools_vm_stream_pio, tools_vm_stream_retire
;; IMPORTS hv/tools_vm_devices, hv/terminal_stream
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Claude / rc-vm-claude. VM half of the tools hostname stream
; (hv/tools_stream_abi.inc): scalar32 buffering of one request and one reply
; in fixed private native arrays, and actual-tools currentness before every
; scalar access, so also immediately before the one AV submission per frame.
; Reached only from the tools device dispatcher; the app/driver profiles have
; no route to these ports. AV owns record parsing, sequence, handles and every
; network effect. The guest supplies no pointer, GPA, capacity or identity.
%include "hv/tools_stream_abi.inc"
%include "core/abi/wdata.inc"

TVMS_IDLE equ 0
TVMS_RECEIVING equ 1
TVMS_REPLY equ 2
TVMS_TERMINAL equ 3
TVMS_BUFFER equ TSTREAM_RECORD_MAX+8   ; dword appends past an odd tail stay inside

; EDI actual normalized IO qualification, ESI actual guest EAX ->EAX 1 handled
; (EDX IN value) /0 terminal fault. A malformed scalar access is refused with no
; state change: IN reads all-ones, OUT is dropped. Nothing a guest writes can
; reset a partial request, replace an unread reply or reach AV early.
tools_vm_stream_pio:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12d,esi
    call tools_vm_exit_endpoint
    test rax,rax
    jz .bad
    cmp dword [rel tvms_state],TVMS_TERMINAL
    je .bad
    mov r13d,ebx
    shr r13d,16
    cmp r13d,TSTREAM_PORT_CONTROL
    je .port
    cmp r13d,TSTREAM_PORT_DATA
    jne .bad
.port:
    mov eax,ebx
    and eax,7
    cmp eax,3                       ; scalar 32-bit only
    jne .refuse
    test ebx,8
    jnz .in
    cmp r13d,TSTREAM_PORT_DATA
    je .append
    ; Control OUT32: declared length begins exactly one request from idle.
    cmp dword [rel tvms_state],TVMS_IDLE
    jne .refuse
    cmp r12d,TSTREAM_HEADER
    jb .refuse
    cmp r12d,TSTREAM_RECORD_MAX
    ja .refuse
    mov [rel tvms_expected],r12d
    mov dword [rel tvms_received],0
    mov dword [rel tvms_state],TVMS_RECEIVING
    jmp .ok
.append:
    cmp dword [rel tvms_state],TVMS_RECEIVING
    jne .refuse
    mov ecx,[rel tvms_expected]
    sub ecx,[rel tvms_received]
    cmp ecx,4
    jae .whole
    ; Final word: unused high bytes must be zero before anything is appended.
    shl ecx,3
    mov eax,r12d
    shr eax,cl
    test eax,eax
    jnz .refuse
    shr ecx,3
    jmp .store
.whole:
    mov ecx,4
.store:
    mov eax,[rel tvms_received]
    lea rdx,[rel tvms_request]
    mov [rdx+rax],r12d
    add eax,ecx
    mov [rel tvms_received],eax
    cmp eax,[rel tvms_expected]
    jne .ok
    call tvms_submit
    test eax,eax
    jz .bad
    jmp .ok
.in:
    cmp r13d,TSTREAM_PORT_DATA
    je .read
    xor edx,edx
    cmp dword [rel tvms_state],TVMS_IDLE
    je .ok
    cmp dword [rel tvms_state],TVMS_RECEIVING
    jne .reply_status
    mov edx,[rel tvms_received]
    or edx,TSTREAM_STATUS_RECEIVING
    jmp .ok
.reply_status:
    mov edx,[rel tvms_reply_len]
    sub edx,[rel tvms_cursor]
    or edx,TSTREAM_STATUS_REPLY
    jmp .ok
.read:
    cmp dword [rel tvms_state],TVMS_REPLY
    jne .refuse
    mov eax,[rel tvms_cursor]
    mov ecx,[rel tvms_reply_len]
    sub ecx,eax
    cmp ecx,4
    jb .tail
    mov ecx,4
.tail:
    lea rdx,[rel tvms_reply]
    mov edx,[rdx+rax]
    add eax,ecx
    mov [rel tvms_cursor],eax
    cmp ecx,4
    je .advanced
    shl ecx,3                       ; final word: high bytes read as zero
    mov r8d,1
    shl r8d,cl
    dec r8d
    and edx,r8d
.advanced:
    cmp eax,[rel tvms_reply_len]
    jne .ok
    push rdx
    call tvms_wipe_reply
    pop rdx
    mov dword [rel tvms_state],TVMS_IDLE
    jmp .ok
.refuse:
    mov edx,TSTREAM_REFUSED
.ok:
    test ebx,8
    jnz .handled
    xor edx,edx                     ; an OUT returns no value
.handled:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Complete frame, reached only from the final word's own currentness check
; with nothing between it and AV ->EAX 1 reply ready /0 transport terminal.
; The request bytes are wiped once AV has returned.
tvms_submit:
    sub rsp,8
    lea rdi,[rel tvms_request]
    mov esi,[rel tvms_expected]
    lea rdx,[rel tvms_reply]
    call terminal_stream_submit
    mov [rel tvms_reply_len],eax
    lea rdi,[rel tvms_request]
    call tvms_wipe
    mov dword [rel tvms_expected],0
    mov dword [rel tvms_received],0
    mov eax,[rel tvms_reply_len]
    cmp eax,TSTREAM_RECORD_MAX
    ja .terminal
    mov ecx,[rel tvms_reply+TSTREAM_H_LENGTH]
    add ecx,TSTREAM_HEADER          ; no carry and equal: also >= the header
    jc .terminal
    cmp ecx,eax
    jne .terminal
    mov dword [rel tvms_cursor],0
    mov dword [rel tvms_state],TVMS_REPLY
    mov eax,1
    add rsp,8
    ret
.terminal:
    call tvms_wipe_all
    mov dword [rel tvms_state],TVMS_TERMINAL
    xor eax,eax
    add rsp,8
    ret

; Native lifecycle only (never a guest, remote or command request), outside
; any open tools exit ->1 broker fenced and transport wiped /0 unchanged. The
; native sequence is AV's and survives; a replacement inherits nothing here.
tools_vm_stream_retire:
    cmp byte [rel tvm_exit_open],0
    jne .bad
    sub rsp,8
    call terminal_stream_retire
    add rsp,8
    cmp eax,1
    jne .bad
    sub rsp,8
    call tvms_wipe_all
    add rsp,8
    mov dword [rel tvms_state],TVMS_IDLE
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

tvms_wipe_all:
    lea rdi,[rel tvms_request]
    call tvms_wipe
    mov dword [rel tvms_expected],0
    mov dword [rel tvms_received],0
tvms_wipe_reply:
    lea rdi,[rel tvms_reply]
    call tvms_wipe
    mov dword [rel tvms_reply_len],0
    mov dword [rel tvms_cursor],0
    ret

; RDI one private TVMS_BUFFER array ->zeroed.
tvms_wipe:
    xor eax,eax
    mov ecx,TVMS_BUFFER/8
    rep stosq
    ret

%macro WDATA_hv_tools_vm_stream 0
align 8
tvms_state: dd 0
tvms_expected: dd 0
tvms_received: dd 0
tvms_reply_len: dd 0
tvms_cursor: dd 0
tvms_pad: dd 0                      ; explicit zero: the arrays stay 8-aligned
tvms_request: times TVMS_BUFFER db 0
tvms_reply: times TVMS_BUFFER db 0
%endmacro
WDATA_DEFER WDATA_hv_tools_vm_stream
