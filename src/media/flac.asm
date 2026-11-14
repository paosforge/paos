;; MODULE media/flac
;; LAYER 4
;; EXPORTS media_flac_probe
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; Private, UNWIRED shared-media admission seam. Port of native Classic PaOS
; 0cabd75 flac_parse_streaminfo field extraction and flac_decode_file metadata
; walk. Adds bounds and typed output. No frames, bit reader, PCM or CRC proof.

MEDIA_FLAC_MAX_BYTES equ 16*1024*1024
MEDIA_FLAC_MAX_BLOCKS equ 256

struc media_flac_info
    .src:               resq 1
    .src_bytes:         resq 1
    .sample_rate:       resd 1
    .channels:          resd 1
    .bits_per_sample:   resd 1
    .min_block_size:    resd 1
    .max_block_size:    resd 1
    .min_frame_bytes:   resd 1
    .max_frame_bytes:   resd 1
    .metadata_blocks:   resd 1
    .total_samples:     resq 1
    .audio_offset:      resq 1
    .stream_md5:        resb 16
endstruc

; media_flac_probe(RDI=trusted stable media_flac_info*) -> RAX:
;   0 = complete metadata admitted (NOT decoded audio)
;  -1 = invalid header/extent/fields/metadata/overlap
;  -4 = file or metadata-count limit
; Caller owns readable immutable src[0..src_bytes) and writable 80-byte info;
; their spans must be disjoint. Success publishes only output bytes16..79.
; Any refusal leaves the entire context and source unchanged, including old
; output: callers must honor this invocation's status. No allocator or globals.
; A metadata-only file is valid here; slice2 must admit frames and integrity.
; Total_samples=0 and frame-size=0 mean unspecified; MD5 bytes are unverified.
; Preserves RBX/RBP/R12..R15, clobbers ordinary SysV volatile registers.
media_flac_probe:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    test rdi, rdi
    jz .invalid
    mov r8, rdi
    add r8, media_flac_info_size
    jc .invalid
    mov r12, rdi
    mov r13, [r12 + media_flac_info.src]
    mov r14, [r12 + media_flac_info.src_bytes]
    test r13, r13
    jz .invalid
    cmp r14, 42
    jb .invalid
    cmp r14, MEDIA_FLAC_MAX_BYTES
    ja .limit
    mov r15, r13
    add r15, r14
    jc .invalid
    cmp r13, r8
    jae .disjoint
    cmp r12, r15
    jae .disjoint
    jmp .invalid
.disjoint:
    cmp dword [r13], 'fLaC'
    jne .invalid
    movzx eax, byte [r13+4]
    and eax, 0x7F
    test eax, eax
    jnz .invalid
    cmp word [r13+5], 0
    jne .invalid
    cmp byte [r13+7], 34
    jne .invalid
    movzx eax, word [r13+8]
    rol ax, 8
    movzx edx, word [r13+10]
    rol dx, 8
    cmp eax, 16
    jb .invalid
    cmp edx, 16
    jb .invalid
    cmp eax, edx
    ja .invalid
    ; Native Classic extraction: sample rate is the high20 bits at SI+10.
    movzx eax, byte [r13+18]
    shl eax, 12
    movzx ecx, byte [r13+19]
    shl ecx, 4
    or eax, ecx
    movzx ecx, byte [r13+20]
    shr ecx, 4
    or eax, ecx
    test eax, eax
    jz .invalid
    ; The packed3-bit channel field represents exactly1..8.
    movzx ecx, byte [r13+20]
    shr ecx, 1
    and ecx, 7
    inc ecx
    cmp ecx, 8
    ja .invalid
    ; Classic bps extraction: SI+12 lowbit and SI+13 highnibble, plus1.
    movzx eax, byte [r13+20]
    and eax, 1
    shl eax, 4
    movzx ecx, byte [r13+21]
    shr ecx, 4
    or eax, ecx
    inc eax
    cmp eax, 4
    jb .invalid
    cmp eax, 32
    ja .invalid

    mov ebx, 4
    xor ebp, ebp
.metadata:
    cmp ebp, MEDIA_FLAC_MAX_BLOCKS
    jae .limit
    mov rax, r14
    sub rax, rbx
    cmp rax, 4
    jb .invalid
    movzx edx, byte [r13+rbx]
    mov eax, edx
    and eax, 0x7F
    cmp eax, 127
    je .invalid
    test ebp, ebp
    jz .first_block
    test eax, eax
    jz .invalid                     ; duplicate STREAMINFO
.first_block:
    mov ecx, [r13+rbx]
    bswap ecx
    and ecx, 0x00FFFFFF
    add rbx, 4
    mov rax, r14
    sub rax, rbx
    cmp rcx, rax
    ja .invalid
    add rbx, rcx                    ; proved <= length, hence no overflow
    inc ebp
    test dl, 0x80
    jz .metadata                    ; EOF without LAST refuses above

    ; No stores until the complete metadata chain is admitted. Stable source
    ; permits reloading typed fields now; context/source disjointness checked.
    movzx eax, byte [r13+18]
    shl eax, 12
    movzx ecx, byte [r13+19]
    shl ecx, 4
    or eax, ecx
    movzx ecx, byte [r13+20]
    shr ecx, 4
    or eax, ecx
    mov [r12 + media_flac_info.sample_rate], eax
    movzx ecx, byte [r13+20]
    shr ecx, 1
    and ecx, 7
    inc ecx
    mov [r12 + media_flac_info.channels], ecx
    movzx eax, byte [r13+20]
    and eax, 1
    shl eax, 4
    movzx ecx, byte [r13+21]
    shr ecx, 4
    or eax, ecx
    inc eax
    mov [r12 + media_flac_info.bits_per_sample], eax
    movzx eax, word [r13+8]
    rol ax, 8
    mov [r12 + media_flac_info.min_block_size], eax
    movzx eax, word [r13+10]
    rol ax, 8
    mov [r12 + media_flac_info.max_block_size], eax
    mov eax, [r13+12]
    bswap eax
    shr eax, 8
    mov [r12 + media_flac_info.min_frame_bytes], eax
    mov eax, [r13+15]
    bswap eax
    shr eax, 8
    mov [r12 + media_flac_info.max_frame_bytes], eax
    mov [r12 + media_flac_info.metadata_blocks], ebp
    mov eax, [r13+22]
    bswap eax
    movzx ecx, byte [r13+21]
    and ecx, 15
    shl rcx, 32
    or rax, rcx
    mov [r12 + media_flac_info.total_samples], rax
    mov [r12 + media_flac_info.audio_offset], rbx
    mov rax, [r13+26]
    mov [r12 + media_flac_info.stream_md5], rax
    mov rax, [r13+34]
    mov [r12 + media_flac_info.stream_md5+8], rax
    xor eax, eax
    jmp .done
.invalid:
    mov rax, -1
    jmp .done
.limit:
    mov rax, -4
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
