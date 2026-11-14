;; MODULE hv/app_widget_transport
;; LAYER 5
;; PURPOSE Closed app-vCPU PIO for typed widget text in the app's own window.
;; EXPORTS app_widget_transport_configure, app_widget_transport_retire, app_widget_app_pio
;; IMPORTS hv/guest_request, hv/app_vm
;; CAPS
;; OWNER saga:app_widget
;; CONTEXT: bsp_only
; Stopped-vCPU cooperative BSP only. No driver route, guest pointer or yield.
; Ports are an endpoint, not authority: gui/app_widget decides every request.
; Request328: dword version1, dword op, qword sequence, qword window, qword 0,
; qword value length, name32, value256. Reply288: dword version1, dword code,
; qword sequence, qword window, qword value length, value256.
AWT_CONTROL equ 0x5068
AWT_DATA equ 0x506c
AWT_MAGIC equ 0x31544741                ; AGT1
AWT_FRAME_BYTES equ 328
AWT_REPLY_BYTES equ 288

; Native init only. RDI=handler(RDI frame, RSI reply, RDX binding48) -> EAX code.
app_widget_transport_configure:
    mov [rel awt_handler],rdi
    jmp app_widget_transport_retire

; Register and flags preserving, inside the one adapter retirement. Keeps the
; binding serial and replay floor; erases every request and reply byte.
app_widget_transport_retire:
    pushfq
    push rax
    push rcx
    push rdi
    mov dword [rel awt_count],0
    mov dword [rel awt_cursor],0
    mov byte [rel awt_receiving],0
    mov byte [rel awt_replying],0
    lea rdi,[rel awt_frame]
    xor eax,eax
    mov ecx,(AWT_FRAME_BYTES+AWT_REPLY_BYTES)/8
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    popfq
    ret

; EDI=normalized PIO qualification from the actual app exit, ESI=guest EAX.
; -> EAX1 claimed with EDX IN value, or EAX0 and the dispatcher refuses.
app_widget_app_pio:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12d,esi
    call app_vm_exit_endpoint
    test rax,rax
    jz .unclaimed
    mov r13,rax
    mov [rel awt_start],edx
    cmp byte [rel awt_busy],0
    jne .refuse
    call smp_current_logical
    test eax,eax
    jnz .refuse
    mov eax,ebx
    and eax,0xffbf
    cmp ax,3
    je .width_ok
    cmp ax,11
    jne .invalidate
.width_ok:
    ; The whole native binding, on every port access, even for the magic.
    mov rdi,r13
    mov esi,[rel awt_start]
    lea rdx,[rel awt_binding]
    mov ecx,48
    call guest_request_binding_copy
    test eax,eax
    jz .invalidate
    mov rax,[rel awt_binding+8]
    cmp rax,[rel awt_seen_binding]
    jb .invalidate
    je .bound
    call app_widget_transport_retire
    mov [rel awt_seen_binding],rax
    mov qword [rel awt_floor],0
.bound:
    mov eax,ebx
    shr eax,16
    test ebx,8
    jnz .input
    cmp eax,AWT_DATA
    je .data
    cmp eax,AWT_CONTROL
    jne .invalidate
    test r12d,r12d
    jz .clear
    cmp r12d,AWT_FRAME_BYTES
    je .begin
    cmp r12d,1
    je .submit
    cmp r12d,2
    je .sequence
    jmp .invalidate
.clear:
    call app_widget_transport_retire
    jmp .claimed
.begin:
    call app_widget_transport_retire
    mov byte [rel awt_receiving],1
    jmp .claimed
.data:
    cmp byte [rel awt_receiving],1
    jne .invalidate
    mov eax,[rel awt_count]
    cmp eax,AWT_FRAME_BYTES
    jae .invalidate
    lea rdx,[rel awt_frame]
    mov [rdx+rax],r12d
    add dword [rel awt_count],4
    jmp .claimed
.sequence:
    call app_widget_transport_retire
    mov dword [rel awt_reply],1
    mov rax,[rel awt_floor]
    mov [rel awt_reply+8],rax
    mov byte [rel awt_replying],1
    jmp .claimed
.submit:
    cmp byte [rel awt_receiving],1
    jne .invalidate
    mov byte [rel awt_receiving],0
    cmp dword [rel awt_count],AWT_FRAME_BYTES
    jne .invalidate
    mov dword [rel awt_reply],1
    mov rax,[rel awt_frame+8]
    mov [rel awt_reply+8],rax
    mov ecx,CMDE_AUTHDENY
    test rax,rax
    jz .answer
    cmp rax,[rel awt_floor]
    jbe .answer
    mov [rel awt_floor],rax              ; a refused attempt still burns it
    cmp qword [rel awt_handler],0
    je .answer
    mov byte [rel awt_busy],1
    lea rdi,[rel awt_frame]
    lea rsi,[rel awt_reply]
    lea rdx,[rel awt_binding]
    call [rel awt_handler]
    mov byte [rel awt_busy],0
    mov ecx,eax
.answer:
    mov [rel awt_reply+4],ecx
    test ecx,ecx
    jz .scrub_frame
    ; A refusal leaves only version, code and sequence.
    lea rdi,[rel awt_reply+16]
    xor eax,eax
    mov ecx,(AWT_REPLY_BYTES-16)/8
    cld
    rep stosq
.scrub_frame:
    lea rdi,[rel awt_frame]
    xor eax,eax
    mov ecx,AWT_FRAME_BYTES/8
    cld
    rep stosq
    mov dword [rel awt_count],0
    mov dword [rel awt_cursor],0
    mov byte [rel awt_replying],1
    jmp .claimed
.input:
    cmp eax,AWT_CONTROL
    je .magic
    cmp eax,AWT_DATA
    jne .invalidate
    cmp byte [rel awt_replying],1
    jne .invalidate
    mov eax,[rel awt_cursor]
    cmp eax,AWT_REPLY_BYTES
    jae .invalidate
    lea rdx,[rel awt_reply]
    mov r12d,[rdx+rax]
    add eax,4
    mov [rel awt_cursor],eax
    cmp eax,AWT_REPLY_BYTES
    jb .word
    call app_widget_transport_retire     ; the last word leaves nothing behind
.word:
    mov edx,r12d
    jmp .claimed_edx
.magic:
    mov edx,AWT_MAGIC
    jmp .claimed_edx
.invalidate:
    call app_widget_transport_retire
.refuse:
.claimed:
    xor edx,edx
.claimed_edx:
    mov eax,1
    jmp .out
.unclaimed:
    call app_widget_transport_retire
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_app_widget_transport 0
alignb 8
awt_handler: resq 1
awt_seen_binding: resq 1
awt_floor: resq 1
awt_binding: resb 48
awt_frame: resb AWT_FRAME_BYTES
awt_reply: resb AWT_REPLY_BYTES
awt_count: resd 1
awt_cursor: resd 1
awt_start: resd 1
awt_busy: resb 1
awt_receiving: resb 1
awt_replying: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_app_widget_transport
