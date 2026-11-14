;; MODULE media/mp3_sideinfo_mono_private
;; LAYER 4
;; EXPORTS media_mp3_sideinfo_mono_parse
;; IMPORTS media/mp3_bits_private
;; CAPS
;; OWNER saga:audio
; Private UNWIRED raw mono MPEG1/L3 side-info port. See owned contract.
; RDI=trusted mapped source,RSI=full available span,RDX=aligned result160.
; 0 complete raw extraction,-1 immutable refusal. No semantic/PCM admission.
; Every external span and prospective active stack interval checked pre-push.
; 18 prefix +2*59 granule bits=136. Local ctx32/result160, max stack248.
%macro MP3SI_PREFIX 2
    mov rdi,r12
    mov esi,%1
    call media_mp3_bits_read
    test rax,rax
    jnz .failed
    mov [r13+%2],edx
%endmacro
%macro MP3SI_FIELD 2
    mov rdi,r12
    mov esi,%1
    call media_mp3_bits_read
    test rax,rax
    jnz .failed
    mov [r15+%2],edx
%endmacro
media_mp3_sideinfo_mono_parse:
    test rdi,rdi
    jz .bad_leaf
    cmp rsi,17
    jb .bad_leaf
    test rdx,rdx
    jz .bad_leaf
    test dl,7
    jnz .bad_leaf
    mov r8,rdi
    add r8,rsi
    jc .bad_leaf
    mov rax,r8
    dec rax
    shr rax,47
    jnz .bad_leaf
    mov r9,rdx
    add r9,160
    jc .bad_leaf
    mov rax,r9
    dec rax
    shr rax,47
    jnz .bad_leaf
    cmp rdi,r9
    jae .external_disjoint
    cmp rdx,r8
    jb .bad_leaf
.external_disjoint:
    mov r10,rsp
    sub r10,240                ; deepest nested reader return address
    jc .bad_leaf
    mov r11,rsp
    add r11,8                  ; including our entry return address
    jc .bad_leaf
    mov rax,r11
    dec rax
    shr rax,47
    jnz .bad_leaf
    cmp rdi,r11
    jae .source_stack_ok
    cmp r8,r10
    jbe .source_stack_ok
    jmp .bad_leaf
.source_stack_ok:
    cmp rdx,r11
    jae .output_stack_ok
    cmp r9,r10
    jbe .output_stack_ok
    jmp .bad_leaf
.output_stack_ok:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,192
    mov rbx,rdx
    mov r12,rsp
    mov [r12],rdi
    mov qword [r12+8],17
    mov qword [r12+16],0
    mov qword [r12+24],0
    lea r13,[rsp+32]
    mov rdi,r13
    xor eax,eax
    mov ecx,20
    rep stosq                  ; zero absent raw fields before local parse
    MP3SI_PREFIX 9,0
    MP3SI_PREFIX 5,4
    MP3SI_PREFIX 4,8
    xor r14d,r14d
    lea r15,[r13+16]
.granule:
    MP3SI_FIELD 12,0
    MP3SI_FIELD 9,4
    MP3SI_FIELD 8,8
    MP3SI_FIELD 4,12
    MP3SI_FIELD 1,16
    test edx,edx
    jnz .short
    MP3SI_FIELD 5,28
    MP3SI_FIELD 5,32
    MP3SI_FIELD 5,36
    MP3SI_FIELD 4,40
    MP3SI_FIELD 3,44
    jmp .tail
.short:
    MP3SI_FIELD 2,20
    MP3SI_FIELD 1,24
    MP3SI_FIELD 5,28
    MP3SI_FIELD 5,32
    MP3SI_FIELD 9,48            ; Classic reads all three gains together
    mov ecx,edx
    shr ecx,6
    mov [r15+48],ecx
    mov ecx,edx
    shr ecx,3
    and ecx,7
    mov [r15+52],ecx
    and edx,7
    mov [r15+56],edx
.tail:
    ; Classic9320e: these three bits belong to BOTH branches.
    MP3SI_FIELD 1,60
    MP3SI_FIELD 1,64
    MP3SI_FIELD 1,68
    add r15,72
    inc r14d
    cmp r14d,2
    jb .granule
    cmp qword [r12+16],136
    jne .failed
    mov dword [r13+12],136
    mov rsi,r13
    mov rdi,rbx
    mov ecx,20
    rep movsq                  ; only public store: complete result160
    xor eax,eax
.exit:
    add rsp,192
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.failed:
    mov rax,-1
    jmp .exit
.bad_leaf:
    mov rax,-1
    ret
%unmacro MP3SI_PREFIX 2
%unmacro MP3SI_FIELD 2
