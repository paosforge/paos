;; MODULE dev/usb/uac1_stream
;; LAYER 3
;; EXPORTS uac1_fs_stream_parse
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
; Pure UAC1 full-speed PCM16 stream candidate, not device binding or DMA.
; Input is one complete AS alternate setting, not an entire configuration:
; standard interface9, AS_GENERAL7, TypeI format, standard endpoint9, CS_EP7.
; RDI blob*, RSI bytes<=512, RDX direction0OUT/1IN, RCX rate8k..192k,
; R8 channels1/2, R9 caller-owned64B output. EAX0 success/-1 refusal.
; All refusal paths leave output untouched. No IO, allocation or global state.
; Caller still owns descriptor/terminal graph provenance, actual speed, EP0
; frequency negotiation, SET_INTERFACE and the future isochronous transport.
uac1_fs_stream_parse:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,64
    mov r12,rdi
    mov r13,rsi
    mov r14,r9
    mov r15,rcx
    mov ebx,edx
    mov rbp,r8
    test rdi,rdi
    jz .no
    cmp rsi,43                         ; minimum:9+7+11+9+7 =43
    jb .no
    cmp rsi,512
    ja .no
    mov rax,rdi
    add rax,rsi
    jc .no
    mov rcx,rax
    dec rcx
    shr rcx,47
    jnz .no
    test r9,r9
    jz .no
    mov r10,r9
    add r10,64
    jc .no
    mov rcx,r10
    dec rcx
    shr rcx,47
    jnz .no
    cmp rdi,r10
    jae .disjoint
    cmp r9,rax
    jb .no
.disjoint:
    cmp rdx,1
    ja .no
    cmp r15,8000
    jb .no
    cmp r15,192000
    ja .no
    cmp rbp,1
    jb .no
    cmp rbp,2
    ja .no
    cmp word [r12],0x0409
    jne .no
    cmp byte [r12+3],0                 ; nonzero alternate
    je .no
    cmp byte [r12+4],1                 ; no separate/implicit feedback endpoint
    jne .no
    cmp word [r12+5],0x0201            ; Audio / Streaming
    jne .no
    cmp byte [r12+7],0                 ; UAC1 protocol
    jne .no
    cmp word [r12+9],0x2407
    jne .no
    cmp byte [r12+11],1                ; AS_GENERAL
    jne .no
    cmp byte [r12+12],0
    je .no
    cmp word [r12+14],1                ; PCM TypeI format tag
    jne .no
    cmp word [r12+17],0x0224           ; CS_INTERFACE / FORMAT_TYPE
    jne .no
    cmp byte [r12+19],1                ; FORMAT_TYPE_I
    jne .no
    cmp byte [r12+20],bpl
    jne .no
    cmp word [r12+21],0x1002           ; 2-byte subframe /16 valid bits
    jne .no
    movzx r10d,byte [r12+16]           ; actual format length
    lea r11,[r10+32]                  ;9+7 + format +9+7
    cmp r11,r13
    jne .no                           ; rejects truncation AND extra descriptors
    movzx ecx,byte [r12+23]
    test ecx,ecx
    jz .continuous
    lea eax,[rcx+rcx*2+8]
    cmp eax,r10d
    jne .no
    xor edi,edi                       ; rate found
    lea rsi,[r12+24]
.frequency:
    movzx eax,word [rsi]
    movzx edx,byte [rsi+2]
    shl edx,16
    or eax,edx
    test eax,eax
    jz .no
    cmp eax,r15d
    jne .next_frequency
    mov edi,1
.next_frequency:
    add rsi,3
    dec ecx
    jnz .frequency
    test edi,edi
    jz .no
    jmp .endpoint
.continuous:
    cmp r10d,14
    jne .no
    movzx eax,word [r12+24]
    movzx edx,byte [r12+26]
    shl edx,16
    or eax,edx
    test eax,eax
    jz .no
    cmp eax,r15d
    ja .no
    movzx ecx,word [r12+27]
    movzx edx,byte [r12+29]
    shl edx,16
    or ecx,edx
    cmp eax,ecx
    ja .no
    cmp ecx,r15d
    jb .no
.endpoint:
    add r10,16                        ; endpoint offset
    lea rsi,[r12+r10]
    cmp word [rsi],0x0509
    jne .no
    movzx eax,byte [rsi+2]
    test al,0x70
    jnz .no
    mov edx,eax
    and edx,15
    jz .no
    shr eax,7
    cmp eax,ebx
    jne .no
    movzx edi,byte [rsi+3]
    mov eax,edi
    and eax,0xf3                      ; data endpoint, isochronous, no reserved bits
    cmp eax,1
    jne .no
    shr edi,2                        ; sync type1/2/3
    test edi,edi
    jz .no
    test ebx,ebx
    jnz .sync_ok
    cmp edi,1                        ; async OUT needs explicit feedback support
    je .no
.sync_ok:
    movzx ecx,word [rsi+4]
    test ecx,ecx
    jz .no
    cmp ecx,1023                      ; full-speed, no HS transaction bits
    ja .no
    mov eax,r15d
    add eax,999
    xor edx,edx
    mov r8d,1000
    div r8d                          ; ceil(rate/1000) WHOLE PCM frames/service
    imul eax,ebp
    add eax,eax                      ; frame count *channels*2
    cmp ecx,eax
    jb .no
    cmp byte [rsi+6],1
    jne .no
    cmp word [rsi+7],0                ; no refresh/feedback endpoint
    jne .no
    cmp word [rsi+9],0x2507
    jne .no
    cmp byte [rsi+11],1
    jne .no
    movzx edx,byte [rsi+12]
    test edx,0xfe                     ; no pitch/max-packet-only control
    jnz .no
    cmp byte [rsi+13],0                ; no lock-delay requirement in this subset
    jne .no
    cmp word [rsi+14],0
    jne .no
    ; Publish only after the complete supported profile has been validated.
    movzx eax,byte [r12+2]
    mov [rsp],eax                     ; interface
    movzx eax,byte [r12+3]
    mov [rsp+4],eax                   ; alternate
    movzx eax,byte [r12+12]
    mov [rsp+8],eax                   ; terminal link
    movzx eax,byte [rsi+2]
    mov [rsp+12],eax                  ; endpoint address
    mov [rsp+16],ecx                  ; max packet
    mov dword [rsp+20],1              ; interval
    mov [rsp+24],r15d                 ; rate
    mov [rsp+28],ebp                  ; channels
    mov dword [rsp+32],2              ; subframe
    mov dword [rsp+36],16             ; valid bits
    mov [rsp+40],edi                  ; sync type
    mov [rsp+44],edx                  ; sample frequency control advertised
    mov dword [rsp+48],16             ; format offset
    mov [rsp+52],r10d                 ; endpoint offset
    mov [rsp+56],r13d                 ; complete selected blob length
    mov dword [rsp+60],0              ; protocol UAC1
    mov rsi,rsp
    mov rdi,r14
    mov ecx,8
    cld
    rep movsq
    xor eax,eax
    jmp .out
.no: mov eax,-1
.out:
    add rsp,64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
