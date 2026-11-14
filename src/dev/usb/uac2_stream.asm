;; MODULE dev/usb/uac2_stream
;; LAYER 3
;; EXPORTS uac2_pcm16_stream_parse
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
; Pure exact UAC2 selected AS alternate. No graph/clock/binding/USB IO.
; RDI mapped46B span, RSI46, RDX speed1FS/2HS, RCX rate8k..192k,
; R8 channels1/2, R9 mapped disjoint96B output. EAX0/-1 unchanged on refusal.
; Supports one synchronous IN/OUT or adaptive OUT data EP, no feedback,
; one transaction/service, no lock delay or endpoint controls. HS interval1..4.
uac2_pcm16_stream_parse:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,96
    mov r12,rdi
    mov r13,rsi
    mov r14,r9
    mov r15,rcx
    mov rbx,rdx
    mov rbp,r8
    test rdi,rdi
    jz .no
    cmp rsi,46
    jne .no
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
    add r10,96
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
    cmp rbx,1
    jb .no
    cmp rbx,2
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
    cmp byte [r12+3],0
    je .no
    cmp byte [r12+4],1
    jne .no
    cmp word [r12+5],0x0201
    jne .no
    cmp byte [r12+7],0x20
    jne .no
    cmp word [r12+9],0x2410
    jne .no
    cmp byte [r12+11],1
    jne .no
    cmp byte [r12+12],0
    je .no
    test byte [r12+13],0xfa             ; read-only AS controls0/1 per pair
    jnz .no
    cmp byte [r12+14],1
    jne .no
    cmp dword [r12+15],1               ; PCM only, not PCM8/float/encoded
    jne .no
    cmp byte [r12+19],bpl
    jne .no
    mov eax,[r12+20]
    test eax,eax                       ; unspecified spatial positions allowed
    jz .cluster_ok
    cmp ebp,1
    jne .stereo
    cmp eax,4                          ; mono Front Center
    jne .no
    jmp .cluster_ok
.stereo:
    cmp eax,3                          ; Front Left/Front Right
    jne .no
.cluster_ok:
    cmp dword [r12+25],0x01022406      ; exact TypeI6B, no UAC1 frequency list
    jne .no
    cmp word [r12+29],0x1002           ; 2-byte subslot,16 valid bits
    jne .no
    cmp word [r12+31],0x0507
    jne .no
    movzx eax,byte [r12+33]
    test al,0x70
    jnz .no
    test al,15
    jz .no
    movzx edi,byte [r12+34]
    mov edx,edi
    and edx,0xf3                       ; isochronous data, no implicit feedback
    cmp edx,1
    jne .no
    shr edi,2
    cmp edi,3                          ; synchronous source or sink
    je .sync_ok
    cmp edi,2                          ; adaptive sink only (source needs feedback)
    jne .no
    test al,0x80
    jnz .no
.sync_ok:
    movzx r11d,word [r12+35]
    test r11d,r11d
    jz .no
    movzx ecx,byte [r12+37]
    cmp ebx,1
    jne .high_speed
    cmp ecx,1
    jne .no
    cmp r11d,1023
    ja .no
    mov r10d,1000
    jmp .interval_ok
.high_speed:
    cmp ecx,1
    jb .no
    cmp ecx,4
    ja .no
    cmp r11d,1024                      ; no high-bandwidth transaction bits
    ja .no
    dec ecx
    mov r10d,125
    shl r10d,cl
.interval_ok:
    cmp dword [r12+38],0x00012508      ; exact8B CS_EP; attrs zero for TypeI
    jne .no
    cmp dword [r12+42],0               ; no controls, lock-delay units or delay
    jne .no
    mov eax,r15d
    imul eax,r10d                      ; <=192000000, no 32-bit wrap
    xor edx,edx
    mov ecx,1000000
    div ecx
    mov [rsp+72],eax                   ; floor frames/service
    mov [rsp+84],edx                   ; fractional numerator /1000000
    test edx,edx
    jz .ceiling
    inc eax
.ceiling:
    mov [rsp+76],eax                   ; ceiling frames/service
    imul eax,ebp
    add eax,eax
    cmp r11d,eax
    jb .no                            ; bound complete PCM frames, not byte ceil
    mov [rsp+80],eax
    mov dword [rsp],1
    movzx eax,byte [r12+2]
    mov [rsp+4],eax
    movzx eax,byte [r12+3]
    mov [rsp+8],eax
    movzx eax,byte [r12+12]
    mov [rsp+12],eax
    movzx eax,byte [r12+33]
    mov [rsp+16],eax
    mov [rsp+20],ebx
    movzx eax,byte [r12+37]
    mov [rsp+24],eax
    mov [rsp+28],r10d
    mov [rsp+32],r11d
    mov [rsp+36],edi
    mov [rsp+40],r15d
    mov [rsp+44],ebp
    mov dword [rsp+48],2
    mov dword [rsp+52],16
    mov eax,[r12+20]
    mov [rsp+56],eax
    movzx eax,byte [r12+13]
    mov [rsp+60],eax
    mov dword [rsp+64],1
    mov [rsp+68],r13d
    mov qword [rsp+88],0
    mov rsi,rsp
    mov rdi,r14
    mov ecx,12
    cld
    rep movsq
    xor eax,eax
    jmp .out
.no:
    mov eax,-1
.out:
    add rsp,96
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret
