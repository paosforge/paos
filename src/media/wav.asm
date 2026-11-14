;; MODULE media/wav
;; LAYER 4
;; EXPORTS media_wav_decode
;; IMPORTS core/lib/mem
;; CAPS
;; OWNER saga:audio

; RCQ-36 shared-media WAV slice 1, private and UNWIRED. Port of Classic
; audio_load_and_parse .alp_wav chunk walk: RIFF/WAVE, fmt/data, WORD padding
; and S16 frame accounting. VFS/allocation/globals become caller-owned buffers
; and context; admission is bounded and completed before any output store.
; This subset: PCM tag 1, S16LE interleaved mono/stereo, 8000..192000 Hz,
; fmt payload 16 or 18 bytes (PCM cbSize ignored), fmt before unique data.
; Unknown chunks are skipped; all chunk headers/payloads/padding must fit RIFF.
; No allocation, file I/O, resampling, mixer, device or presentation-clock work.

MEDIA_WAV_MAX_BYTES  equ 16777216
MEDIA_WAV_MAX_CHUNKS equ 256

struc media_wav_context
    .src:         resq 1       ; trusted stable mapped input
    .src_bytes:   resq 1       ; truthful complete file length
    .dst:         resq 1       ; caller-owned stable mapped output
    .dst_bytes:   resq 1       ; truthful output capacity
    .rate:        resd 1       ; outputs committed ONLY when return status is 0
    .channels:    resd 1
    .frames:      resq 1
    .pcm_bytes:   resq 1
    .data_offset: resq 1       ; byte offset in input; no borrowed output pointer
endstruc

; media_wav_decode(RDI=trusted stable context*) -> RAX:
;  0 success: exact S16LE PCM copied into owned dst, metadata committed;
; -1 malformed/truncated/pointer/overlap, -2 unsupported subset/order,
; -3 output capacity, -4 file/chunk work limit.
; On EVERY refusal, context, input and output are unchanged. Old metadata from
; a previous success is not authorization: caller MUST check this call's status.
; The context and source/output touched intervals must be disjoint. The caller
; serializes access and guarantees truthful capacities and mappings for the call.
; Full-frame bounds are not a scheduler budget; future wiring must cooperate.
media_wav_decode:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    test rdi, rdi
    jz .bad
    mov r12, rdi
    mov r13, [r12 + media_wav_context.src]
    mov r14, [r12 + media_wav_context.src_bytes]
    test r13, r13
    jz .bad
    cmp r14, MEDIA_WAV_MAX_BYTES
    ja .limit
    cmp r14, 12
    jb .bad
    mov r15, r13
    add r15, r14
    jc .bad
    mov rcx, r12
    add rcx, media_wav_context_size
    jc .bad
    cmp r12, r15
    jae .input_disjoint
    cmp r13, rcx
    jb .bad
.input_disjoint:
    cmp dword [r13], 'RIFF'
    jne .bad
    cmp dword [r13 + 8], 'WAVE'
    jne .bad
    mov eax, [r13 + 4]
    add rax, 8                     ; u32 RIFF size widened before addition
    cmp rax, r14
    jne .bad
    lea r10, [r13 + 12]
    xor ebx, ebx                   ; found fmt=1, data=2
    xor r11d, r11d                 ; chunk work bound includes unknown chunks
.chunk:
    cmp r10, r15
    je .done
    mov rax, r15
    sub rax, r10
    cmp rax, 8
    jb .bad
    inc r11d
    cmp r11d, MEDIA_WAV_MAX_CHUNKS
    ja .limit
    lea rdx, [r10 + 8]
    mov ecx, [r10 + 4]             ; unsigned chunk length, no signed wrap
    mov rax, r15
    sub rax, rdx
    cmp rcx, rax
    ja .bad
    lea r14, [rdx + rcx]
    mov eax, ecx
    and eax, 1
    add r14, rax                   ; pad is not counted as chunk payload
    jc .bad
    cmp r14, r15
    ja .bad
    cmp dword [r10], 'fmt '
    je .fmt
    cmp dword [r10], 'data'
    je .data
    jmp .next
.fmt:
    test ebx, 1
    jnz .bad
    cmp ecx, 16
    jb .bad
    je .fmt_size_ok
    cmp ecx, 18
    jne .unsupported
.fmt_size_ok:
    cmp word [rdx], 1
    jne .unsupported
    cmp word [rdx + 14], 16
    jne .unsupported
    movzx eax, word [rdx + 2]
    test eax, eax
    jz .unsupported
    cmp eax, 2
    ja .unsupported
    mov ecx, eax
    shl ecx, 1                     ; S16 frame = channels*2
    cmp [rdx + 12], cx
    jne .bad
    mov eax, [rdx + 4]
    cmp eax, 8000
    jb .unsupported
    cmp eax, 192000
    ja .unsupported
    imul eax, ecx                  ; <=192000*4, exact in 32 bits
    cmp [rdx + 8], eax
    jne .bad
    mov rbp, rdx
    or ebx, 1
    jmp .next
.data:
    test ebx, 1
    jz .unsupported                ; explicit first-slice order policy
    test ebx, 2
    jnz .bad
    mov r8, rdx
    mov r9d, ecx
    or ebx, 2
.next:
    mov r10, r14
    jmp .chunk
.done:
    cmp ebx, 3
    jne .bad
    test r9, r9
    jz .bad
    movzx ecx, word [rbp + 2]
    shl ecx, 1
    mov eax, r9d
    xor edx, edx
    div ecx
    test edx, edx
    jnz .bad
    mov r14, rax                   ; exact whole PCM frames
    cmp r9, [r12 + media_wav_context.dst_bytes]
    ja .capacity
    mov rdi, [r12 + media_wav_context.dst]
    test rdi, rdi
    jz .bad
    mov rax, rdi
    add rax, r9
    jc .bad
    cmp rdi, r15                   ; destination vs the entire source file
    jae .source_disjoint
    cmp r13, rax
    jb .bad
.source_disjoint:
    cmp r12, rax                   ; destination may not overwrite context
    jae .copy
    mov rcx, r12
    add rcx, media_wav_context_size
    jc .bad
    cmp rdi, rcx
    jb .bad
.copy:
    mov rsi, r8
    mov rdx, r9
    sub rsp, 8                     ; SysV alignment at the only call
    ; Canonical core/lib/mem contract9703 is stricter than SysV: r8/r9/rbp
    ; survive. They remain live here as PCM source/byte count/fmt pointer for
    ; the metadata stores below. A replacement memcpy must preserve that
    ; contract (strmem_kat checks it); ordinary SysV volatile rules do not.
    call memcpy                    ; canonical 9703 preserves r8-r15/rbp/rbx
    add rsp, 8
    mov eax, [rbp + 4]
    mov [r12 + media_wav_context.rate], eax
    movzx eax, word [rbp + 2]
    mov [r12 + media_wav_context.channels], eax
    mov [r12 + media_wav_context.frames], r14
    mov [r12 + media_wav_context.pcm_bytes], r9
    sub r8, r13
    mov [r12 + media_wav_context.data_offset], r8
    xor eax, eax
    jmp .out
.bad:
    mov rax, -1
    jmp .out
.unsupported:
    mov rax, -2
    jmp .out
.capacity:
    mov rax, -3
    jmp .out
.limit:
    mov rax, -4
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
