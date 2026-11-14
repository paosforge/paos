;; MODULE dev/usb/uac1_packet
;; LAYER 3
;; EXPORTS uac1_fs_packet_plan
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
; Pure one-millisecond full-speed PCM16 packet geometry, no USB authority.
; RDI rate8k..192k, RSI channels1/2, RDX endpoint MPS1..1023,
; RCX fractional phase0..999, R8 caller-owned16B output.
; EAX0 success/-1 refusal. Output u32: frames, bytes, next_phase, max_bytes.
; All scalars checked at full width, all refusals leave output untouched.
; Caller commits next_phase only on known transport admission. This is not
; a scheduler, feedback loop, stream binding, rate negotiation or clock.
uac1_fs_packet_plan:
    cmp rdi,8000
    jb .no
    cmp rdi,192000
    ja .no
    cmp rsi,1
    jb .no
    cmp rsi,2
    ja .no
    cmp rdx,1
    jb .no
    cmp rdx,1023
    ja .no
    cmp rcx,1000
    jae .no
    test r8,r8
    jz .no
    mov rax,r8
    add rax,15
    jc .no
    shr rax,47
    jnz .no
    mov r9d,edx                       ; endpoint maximum
    mov r10d,ecx                      ; caller's uncommitted phase
    lea r11d,[rsi+rsi]                ; PCM16 bytes per frame
    lea eax,[rdi+999]
    xor edx,edx
    mov ecx,1000
    div ecx
    imul eax,r11d                     ; ceil(rate/1000)*frame_bytes
    cmp eax,r9d                       ; require worst packet, not just current
    ja .no
    mov r9d,eax
    mov eax,edi
    add eax,r10d
    xor edx,edx
    div ecx                           ; frames and next phase
    mov edi,eax
    imul eax,r11d
    mov [r8],edi
    mov [r8+4],eax
    mov [r8+8],edx
    mov [r8+12],r9d
    xor eax,eax
    ret
.no:
    mov eax,-1
    ret
