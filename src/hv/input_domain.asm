;; MODULE hv/input_domain
;; LAYER 5
;; EXPORTS pind_bind, pind_request, pind_pump, pind_receive, pind_take, pind_retire
;; IMPORTS
;; CAPS extension
;; OWNER saga:input
; Reverse PIN1 input-domain client. Inactive until the VM owner binds its
; exclusive existing console channel at a stopped-vCPU boundary. All calls,
; including receive and retirement, are serialized there; none yields/runs VM.
; Typed events are UNTRUSTED DOMAIN DATA, never HUMAN, owner presence, sign-in
; or submit authority. This module does not publish to physical input queues.
; Caller spans must be stable mapped owned memory, disjoint from this module.
; One request, <=256B complete response, fixed 2000ms absolute budget. Unknown
; send/malformed reply/time reversal poisons the binding, no automatic retry.

PIND_IDLE equ 1
PIND_TX equ 2
PIND_RX equ 3
PIND_READY equ 4
PIND_FAULT equ 5
PIND_STOPPED equ 6

; gen, epoch, session, send(bytes,len)->1 accepted /0 definitely not /other
pind_bind:
    cmp dword [rel pind_state],0
    jne .busy
    test rdi,rdi
    jz .invalid
    test rsi,rsi
    jz .invalid
    test rdx,rdx
    jz .invalid
    test rcx,rcx
    jz .invalid
    cmp rdi,[rel pind_last_gen]
    jbe .stale
    cmp rsi,[rel pind_last_epoch]
    jbe .stale
    mov [rel pind_gen],rdi
    mov [rel pind_last_gen],rdi
    mov [rel pind_epoch],rsi
    mov [rel pind_last_epoch],rsi
    mov [rel pind_session],rdx
    mov [rel pind_send],rcx
    mov dword [rel pind_state],PIND_IDLE
    xor eax,eax
    ret
.busy: mov eax,-16
    ret
.invalid: mov eax,-22
    ret
.stale: mov eax,-116
    ret

; gen, now_ms. READY still expires: delayed consumption grants no new budget.
pind_check:
    cmp rdi,[rel pind_gen]
    jne .stale
    cmp dword [rel pind_state],0
    je .stale
    cmp dword [rel pind_state],PIND_FAULT
    je .fault
    cmp rsi,[rel pind_now]
    jb .fault
    mov [rel pind_now],rsi
    cmp dword [rel pind_state],PIND_TX
    jb .ok
    cmp dword [rel pind_state],PIND_READY
    ja .ok
    cmp rsi,[rel pind_deadline]
    jae .timeout
.ok: xor eax,eax
    ret
.timeout: mov eax,-110
    jmp pind_poison
.fault: mov eax,-5
    jmp pind_poison
.stale: mov eax,-116
    ret

pind_poison:
    mov dword [rel pind_state],PIND_FAULT
    push rax
    push rdi
    push rcx
    pushfq
    cld
    lea rdi,[rel pind_tx]
    mov ecx,320
    xor eax,eax
    rep stosb
    mov dword [rel pind_received],0
    popfq
    pop rcx
    pop rdi
    pop rax
    ret

; gen, op (1 POLL/2 STOP), source (1 keyboard/2 pointer; STOP requires0), now
pind_request:
    push rbx
    push r12
    push r13
    mov ebx,esi
    mov r12d,edx
    mov r13,rcx
    mov rsi,rcx
    call pind_check
    test eax,eax
    jnz .out
    cmp dword [rel pind_state],PIND_IDLE
    jne .busy
    cmp ebx,1
    je .poll
    cmp ebx,2
    jne .invalid
    test r12d,r12d
    jnz .invalid
    jmp .queue
.poll:
    cmp r12d,1
    jb .invalid
    cmp r12d,2
    ja .invalid
.queue:
    cmp r13,-2001
    ja .invalid
    cmp qword [rel pind_sequence],65536
    jae .pipe
    inc qword [rel pind_sequence]
    pushfq
    cld
    lea rdi,[rel pind_tx]
    mov ecx,320
    xor eax,eax
    rep stosb
    popfq
    mov dword [rel pind_tx],'PIN1'
    mov word [rel pind_tx+4],1
    mov [rel pind_tx+6],bx
    mov rax,[rel pind_epoch]
    mov [rel pind_tx+8],rax
    mov rax,[rel pind_session]
    mov [rel pind_tx+16],rax
    mov rax,[rel pind_sequence]
    mov [rel pind_tx+24],rax
    mov [rel pind_tx+32],r12d
    lea rax,[r13+2000]
    mov [rel pind_deadline],rax
    mov dword [rel pind_received],0
    mov dword [rel pind_state],PIND_TX
    xor eax,eax
    jmp .out
.invalid: mov eax,-22
    jmp .out
.busy: mov eax,-16
    jmp .out
.pipe: mov eax,-32
.out:
    pop r13
    pop r12
    pop rbx
    ret

; gen, now. Exactly one64B send per service opportunity; no hidden retry.
pind_pump:
    push rbx
    push r12
    push r13
    call pind_check
    test eax,eax
    jnz .out
    xor eax,eax
    cmp dword [rel pind_state],PIND_TX
    jne .out
    mov rbx,rdi
    mov r12,[rel pind_sequence]
    lea rdi,[rel pind_tx]
    mov esi,64
    call [rel pind_send]
    cmp rbx,[rel pind_gen]
    jne .stale
    cmp r12,[rel pind_sequence]
    jne .stale
    cmp dword [rel pind_state],PIND_TX
    jne .stale
    test eax,eax
    jz .out
    cmp eax,1
    jne .uncertain
    mov dword [rel pind_state],PIND_RX
    mov eax,64
    jmp .out
.uncertain: mov eax,-5
    call pind_poison
    jmp .out
.stale: mov eax,-116
.out:
    pop r13
    pop r12
    pop rbx
    ret

; gen, now, private completed console bytes, length. 0 partial/1 ready/negative.
pind_receive:
    call pind_check
    test eax,eax
    jnz .out
    cmp dword [rel pind_state],PIND_RX
    jne .bad
    test rdx,rdx
    jz .bad
    test ecx,ecx
    jz .bad
    cmp ecx,256
    ja .bad
    mov eax,[rel pind_received]
    add eax,ecx
    cmp eax,256
    ja .bad
    pushfq
    push rdi
    push rsi
    cld
    mov esi,[rel pind_received]
    lea rdi,[rel pind_rx]
    add rdi,rsi
    mov rsi,rdx
    rep movsb
    pop rsi
    pop rdi
    popfq
    mov [rel pind_received],eax
    cmp eax,64
    jb .partial
    ; Exact header identity, opcode and reserved bytes before using count.
    cmp dword [rel pind_rx],'PIN1'
    jne .bad
    cmp word [rel pind_rx+4],1
    jne .bad
    mov ax,[rel pind_tx+6]
    or ax,0x8000
    cmp ax,[rel pind_rx+6]
    jne .bad
    mov rax,[rel pind_tx+8]
    cmp rax,[rel pind_rx+8]
    jne .bad
    mov rax,[rel pind_tx+16]
    cmp rax,[rel pind_rx+16]
    jne .bad
    mov rax,[rel pind_tx+24]
    cmp rax,[rel pind_rx+24]
    jne .bad
    mov eax,[rel pind_tx+32]
    cmp eax,[rel pind_rx+32]
    jne .bad
    cmp qword [rel pind_rx+44],0
    jne .bad
    cmp qword [rel pind_rx+52],0
    jne .bad
    cmp dword [rel pind_rx+60],0
    jne .bad
    mov ecx,[rel pind_rx+36]
    cmp ecx,24
    ja .bad
    cmp dword [rel pind_rx+40],0
    je .success
    ; Only a clean empty EAGAIN can be consumed and polled with a NEW ID.
    cmp dword [rel pind_rx+40],-11
    jne .bad
    cmp word [rel pind_tx+6],1
    jne .bad
    test ecx,ecx
    jnz .bad
    jmp .extent
.success:
    cmp word [rel pind_tx+6],2
    jne .packet
    test ecx,ecx
    jnz .bad
    jmp .extent
.packet:
    test ecx,ecx
    jz .bad
.extent:
    lea eax,[rcx*8+64]
    cmp eax,[rel pind_received]
    jb .bad
    ja .partial
    test ecx,ecx
    jz .ready
    ; Validate the WHOLE evdev packet before any publication. One final SYN.
    lea rdx,[rel pind_rx+64]
    xor r10d,r10d
.event:
    cmp ecx,1
    je .syn
    movzx eax,word [rdx]
    cmp eax,1
    je .key
    cmp dword [rel pind_rx+32],2
    jne .bad
    cmp eax,3
    je .absolute
    cmp eax,2
    jne .bad
    movzx eax,word [rdx+2]
    cmp eax,1
    ja .wheel
    mov r10d,1
    jmp .relative
.wheel:
    cmp eax,8                       ; vertical wheel
    jne .bad
.relative:
    cmp dword [rdx+4],32767
    jg .bad
    cmp dword [rdx+4],-32767
    jl .bad
    jmp .next
.absolute:
    test r10d,r10d
    jnz .bad
    cmp word [rdx+2],1
    ja .bad
    cmp dword [rdx+4],32767
    ja .bad
    ; Both ABS axes exactly once, immediately before SYN; no relative motion
    ; in the same packet (wheel remains independent). No partial coordinates.
    cmp ecx,3
    jne .bad
    cmp word [rdx+2],0
    jne .bad
    cmp dword [rdx+8],0x00010003
    jne .bad
    cmp dword [rdx+12],32767
    ja .bad
    add rdx,16
    mov ecx,1
    jmp .syn
.key:
    movzx eax,word [rdx+2]
    cmp dword [rel pind_rx+32],1
    jne .button
    test eax,eax
    jz .bad
    cmp eax,255
    ja .bad
    cmp dword [rdx+4],2
    ja .bad
    jmp .next
.button:
    cmp eax,272
    jb .bad
    cmp eax,274
    ja .bad
    cmp dword [rdx+4],1
    ja .bad
.next:
    add rdx,8
    dec ecx
    jmp .event
.syn:
    cmp qword [rdx],0
    jne .bad
.ready:
    mov dword [rel pind_state],PIND_READY
    mov eax,1
    ret
.partial: xor eax,eax
.out: ret
.bad: mov eax,-71
    jmp pind_poison

; gen, now, output, capacity. Output is complete PIN1, NEVER physical input.
; No partial copy, and no output on invalid/stale/not-ready/expired results.
pind_take:
    push rbx
    mov ebx,ecx
    call pind_check
    test eax,eax
    jnz .out
    xor eax,eax
    cmp dword [rel pind_state],PIND_READY
    jne .out
    test rdx,rdx
    jz .invalid
    mov eax,[rel pind_received]
    cmp ebx,eax
    jb .invalid
    mov ecx,eax
    mov r8,rdx
    add r8,rcx
    jc .invalid
    lea r9,[rel pind_storage_end]
    cmp rdx,r9
    jae .copy
    lea r9,[rel pind_storage]
    cmp r8,r9
    ja .invalid
.copy:
    mov ebx,eax
    mov dword [rel pind_state],PIND_IDLE
    cmp word [rel pind_tx+6],2
    jne .bytes
    mov dword [rel pind_state],PIND_STOPPED
.bytes:
    pushfq
    cld
    mov rdi,rdx
    lea rsi,[rel pind_rx]
    rep movsb
    lea rdi,[rel pind_tx]
    mov ecx,320
    xor eax,eax
    rep stosb
    popfq
    mov dword [rel pind_received],0
    mov eax,ebx
    jmp .out
.invalid: mov eax,-22
.out: pop rbx
    ret

; Exact gen only, AFTER actual VM stop/channel retirement. No stop claim here.
pind_retire:
    cmp rdi,[rel pind_gen]
    jne .stale
    cmp dword [rel pind_state],0
    je .stale
    pushfq
    cld
    lea rdi,[rel pind_private]
    mov ecx,pind_storage_end-pind_private
    xor eax,eax
    rep stosb
    popfq
    ret
.stale: mov eax,-116
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_input_domain 0
alignb 8
pind_storage:
pind_last_gen: resq 1
pind_last_epoch: resq 1
pind_private:
pind_gen: resq 1
pind_epoch: resq 1
pind_session: resq 1
pind_send: resq 1
pind_now: resq 1
pind_sequence: resq 1
pind_deadline: resq 1
pind_state: resd 1
pind_received: resd 1
pind_tx: resb 64
pind_rx: resb 256
pind_storage_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_input_domain
