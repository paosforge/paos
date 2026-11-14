;; MODULE media/av_clock_private
;; LAYER 4
;; EXPORTS media_av_clock_project, media_av_clock_fallback, media_av_clock_decide
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
; Pure, PRIVATE, UNWIRED. Contract committed first: f9c68ddc8/README.md.
; RDI=stable owned 192B snapshot, RSI=owned disjoint 64B result.
; RAX=0 complete result / -1 unchanged refusal. Physical bounds are injected.
; Preserves RBX/RBP/R12..R15/RSP/DF; no SIMD, allocation, clock/device read.
; Full unsigned counts; signed nanoseconds; outward rational rounding.

%define AVC_STATE   dword [r12+4]
%define AVC_FLAGS   qword [r12+8]
%define AVC_NOW     qword [r12+96]
%define AVC_UNTIL   qword [r12+104]
%define AVC_A       qword [r12+112]
%define AVC_B       qword [r12+120]
%define AVC_C       qword [r12+128]
%define AVC_D       qword [r12+136]
%define AVC_E       qword [r12+144]
%define AVC_F       qword [r12+152]
%define AVC_G       qword [r12+160]
%define AVC_H       qword [r12+168]

media_av_clock_project:
    xor r11d, r11d
    jmp avc_enter
media_av_clock_fallback:
    mov r11d, 1
    jmp avc_enter
media_av_clock_decide:
    mov r11d, 2
avc_enter:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov r12, rdi
    mov r13, rsi
    call avc_validate
    jc avc_bad
    test r11d, r11d
    jz avc_project
    cmp r11d, 1
    je avc_fallback
    jmp avc_decide

; Pointer extents before dereference; expected identities are owned authority.
avc_validate:
    test r12, r12
    jz .bad
    test r13, r13
    jz .bad
    mov rax, r12
    add rax, 192
    jc .bad
    mov rdx, r13
    add rdx, 64
    jc .bad
    cmp r13, rax
    jae .disjoint
    cmp r12, rdx
    jb .bad
.disjoint:
    cmp dword [r12], 1
    jne .bad
    cmp AVC_STATE, 8
    ja .bad
    test AVC_FLAGS, -8
    jnz .bad
    cmp qword [r12+16], 0
    je .bad
    cmp qword [r12+24], 0
    je .bad
    cmp qword [r12+48], 0
    je .bad
    lea rdx, [r12+16]
    mov ecx, 5
.identity:
    mov rax, [rdx]
    cmp rax, [rdx+40]
    jne .bad
    add rdx, 8
    loop .identity
    cmp qword [r12+176], 0
    jne .bad
    cmp qword [r12+184], 0
    jne .bad
    mov rax, [r12+32]
    test rax, rax
    jz .zero_backend
    cmp qword [r12+40], 0
    je .bad
    clc
    ret
.zero_backend:
    cmp qword [r12+40], 0
    jne .bad
    clc
    ret
.bad:
    stc
    ret

; CF=1 unavailable/expired: caller decides unchanged refusal versus FREEZE.
avc_active:
    mov rax, AVC_NOW
    cmp rax, AVC_UNTIL
    ja .bad
    cmp AVC_STATE, 4
    je .video_only
    cmp AVC_STATE, 2
    je .audio
    cmp AVC_STATE, 5
    jne .bad
.audio:
    cmp AVC_FLAGS, 7
    jne .bad
    cmp qword [r12+32], 0
    je .bad
    clc
    ret
.video_only:
    cmp AVC_FLAGS, 1
    jne .bad
    cmp qword [r12+32], 0
    jne .bad
    clc
    ret
.bad:
    stc
    ret

avc_project:
    cmp AVC_STATE, 2
    jne avc_bad
    call avc_active
    jc avc_bad
    mov rax, AVC_A
    cmp rax, AVC_B
    ja avc_bad
    cmp AVC_E, 1
    jb avc_bad
    cmp AVC_E, 384000
    ja avc_bad
    mov rax, AVC_F
    or rax, AVC_G
    or rax, AVC_H
    js avc_bad
    mov rax, AVC_G
    cmp rax, AVC_H
    ja avc_bad
    mov rax, AVC_A
    mov rcx, AVC_C
    mov r8, AVC_E
    xor r9d, r9d
    call avc_samples_ns
    jc avc_bad
    add rax, AVC_D
    jo avc_bad
    sub rax, AVC_F
    jo avc_bad
    add rax, AVC_G
    jo avc_bad
    mov rbx, rax
    mov rax, AVC_B
    mov rcx, AVC_C
    mov r8, AVC_E
    mov r9d, 1
    call avc_samples_ns
    jc avc_bad
    add rax, AVC_D
    jo avc_bad
    add rax, AVC_F
    jo avc_bad
    add rax, AVC_H
    jo avc_bad
    mov r14, rax
    cmp rbx, r14
    jg avc_bad
    xor r15d, r15d
    xor eax, eax
    jmp avc_publish

avc_fallback:
    call avc_active
    jc avc_bad
    cmp AVC_STATE, 4
    je .state_ok
    cmp AVC_STATE, 5
    jne avc_bad
.state_ok:
    mov rax, AVC_F
    or rax, AVC_G
    or rax, AVC_H
    jnz avc_bad
    cmp AVC_D, 1000000
    ja avc_bad
    cmp AVC_C, 10000000
    ja avc_bad
    mov rax, AVC_A
    cmp rax, AVC_E
    ja avc_bad
    mov rax, AVC_NOW
    cmp rax, AVC_E
    ja avc_bad
    sub rax, AVC_A
    jb avc_bad
    test rax, rax
    js avc_bad
    mov rbx, rax
    cmp AVC_STATE, 5
    jne .elapsed_ok
    cmp rbx, 100000000
    ja avc_bad
.elapsed_ok:
    mul AVC_D
    mov ecx, 1000000
    cmp rdx, rcx
    jae avc_bad
    div rcx
    test rdx, rdx
    jz .exact
    inc rax
    jz avc_bad
.exact:
    add rax, AVC_C
    jc avc_bad
    cmp rax, 10000000
    ja avc_bad
    mov r14, rax
    mov rax, rbx
    add rax, AVC_B
    jo avc_bad
    mov rbx, rax
    sub rbx, r14
    jo avc_bad
    add rax, r14
    jo avc_bad
    mov r14, rax
    xor r15d, r15d
    xor eax, eax
    jmp avc_publish

avc_decide:
    mov rbx, AVC_A
    mov r14, AVC_B
    cmp rbx, r14
    jg avc_bad
    cmp AVC_D, 0
    jle avc_bad
    mov rax, AVC_E
    test rax, rax
    jz avc_bad
    shr rax, 32
    jnz avc_bad
    mov rax, AVC_F
    test rax, rax
    jz avc_bad
    shr rax, 32
    jnz avc_bad
    cmp AVC_G, 0
    je avc_bad
    mov rax, AVC_G
    cmp rax, AVC_H
    jne avc_bad
    mov rax, AVC_E
    mov ecx, 1000000000
    mul rcx                       ; u32 numerator * 1e9 fits u64
    mov [rsp+8], rax
    mov rcx, rax
    mov rax, AVC_C
    add rax, AVC_D
    jo avc_bad
    mov r8, AVC_F
    mov r9d, 1
    call avc_ticks_ns              ; ensure final media endpoint is representable
    jc avc_bad
    mov rax, AVC_C
    mov rcx, [rsp+8]
    mov r8, AVC_F
    xor r9d, r9d
    call avc_ticks_ns
    jc avc_bad
    mov r15, rax                  ; Plo
    mov rax, AVC_C
    mov rcx, [rsp+8]
    mov r8, AVC_F
    mov r9d, 1
    call avc_ticks_ns
    jc avc_bad
    mov [rsp], rax                ; Phi
    sub rax, 5000000
    jo avc_bad
    mov rax, r15
    sub rax, 5000000
    jo avc_bad
    mov rax, [rsp]
    add rax, 20000000
    jo avc_bad
    mov rax, r15
    add rax, 20000000
    jo avc_bad
    call avc_active
    jc .freeze
    mov rax, r14
    sub rax, rbx                  ; mathematical unsigned width of ordered i64s
    cmp rax, 25000000
    ja .freeze
    mov rax, r15
    sub rax, 5000000
    cmp r14, rax
    jl .hold
    mov rax, [rsp]
    add rax, 20000000
    cmp rbx, rax
    jg .drop
    mov rax, [rsp]
    sub rax, 5000000
    cmp rbx, rax
    jl .hold
    mov rax, r15
    add rax, 20000000
    cmp r14, rax
    jg .hold
    mov eax, 2                    ; SHOW
    jmp .result
.hold:
    mov eax, 1
    jmp .result
.drop:
    mov eax, 3
    jmp .result
.freeze:
    mov eax, 4
.result:
    mov r15, AVC_G
    jmp avc_publish

; RAX=sample count, RCX=sample anchor, R8=rate, R9=0 floor/1 ceil.
avc_samples_ns:
    xor r10d, r10d
    cmp rax, rcx
    jae .positive
    sub rcx, rax
    mov rax, rcx
    mov r10d, 1
    jmp .magnitude
.positive:
    sub rax, rcx
.magnitude:
    mov ecx, 1000000000
    jmp avc_scale_magnitude

; RAX=i64 ticks, RCX=u64 factor, R8=denominator, R9=0 floor/1 ceil.
avc_ticks_ns:
    xor r10d, r10d
    test rax, rax
    jns avc_scale_magnitude
    neg rax                       ; INT64_MIN becomes unsigned magnitude 2^63
    mov r10d, 1
avc_scale_magnitude:
    xor r9d, r10d                 ; negative floor requires magnitude ceil
    mul rcx
    cmp rdx, r8                  ; DIV quotient overflow must refuse, never trap
    jae .bad
    div r8
    test r9d, r9d
    jz .rounded
    test rdx, rdx
    jz .rounded
    inc rax
    jz .bad
.rounded:
    test r10d, r10d
    jnz .negative
    test rax, rax
    js .bad
    clc
    ret
.negative:
    mov rdx, 0x8000000000000000
    cmp rax, rdx
    ja .bad
    neg rax
    clc
    ret
.bad:
    stc
    ret

avc_publish:
    mov [r13], rax
    mov [r13+8], rbx
    mov [r13+16], r14
    mov [r13+24], r15
    mov rax, [r12+16]
    mov [r13+32], rax
    mov rax, [r12+24]
    mov [r13+40], rax
    mov rax, [r12+48]
    mov [r13+48], rax
    mov qword [r13+56], 0
    xor eax, eax
    jmp avc_done
avc_bad:
    mov rax, -1
avc_done:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

%undef AVC_STATE
%undef AVC_FLAGS
%undef AVC_NOW
%undef AVC_UNTIL
%undef AVC_A
%undef AVC_B
%undef AVC_C
%undef AVC_D
%undef AVC_E
%undef AVC_F
%undef AVC_G
%undef AVC_H
