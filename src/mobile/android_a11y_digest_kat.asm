;; MODULE mobile/android_a11y_digest_kat
;; LAYER 5
;; EXPORTS android_a11y_boot_init, android_a11y_kat
;; IMPORTS mobile/android_a11y_digest, hv/guest_class_kat, boot/serial, boot/beacon, core/lib/mem, core/lib/fmt, core/lib/sha256
;; CAPS
;; OWNER saga:android_guest
; Task3347: ordinary QEMU boot KAT. Exact input bytes are reconstructed from a
; bounded fixture codec, then passed to the PRODUCTION parser. Runtime SHA-256
; uses the shipped stream primitive, including a post-call input-immutability
; check. All result fields and the boot token are covered by a binding digest.
; No static runtime pointers, guest launch, live input, allocator or transport.

AK_INPUT         equ 16
AK_INPUT_BYTES   equ A11Y_INPUT_CAP + 1
AK_OUTPUT        equ 16432
AK_TOKEN         equ 24640
AK_INPUT_HASH    equ AK_TOKEN + 16
AK_OUTPUT_HASH   equ AK_INPUT_HASH + 32
AK_STATUS        equ AK_OUTPUT_HASH + 32
AK_NODES         equ AK_STATUS + 4
AK_BYTES         equ AK_NODES + 4
AK_INDEX         equ AK_BYTES + 4
AK_BIND_HASH     equ AK_INDEX + 4
AK_SHA           equ AK_BIND_HASH + 32
AK_FMT           equ AK_SHA + S256_CTX_SZ
AK_TEMP          equ 24960
AK_CAP           equ 24992
AK_FRAME         equ 25016
AK_GUARD         equ 0x7c16a93ed20845bf

; Preserve the pre-existing class-init/verb-registration path. The KAT has no
; effect on eligibility, runtime configuration, or non-QEMU boots.
android_a11y_boot_init:
    push rbx
    cmp byte [rel boot_budget_qemu_fixture], 1
    jne .done
    call android_a11y_kat
.done:
    pop rbx
    jmp guest_class_boot_init

; android_a11y_kat -> EAX=0 only after every golden and negative is exercised.
; This synchronous boot-only KAT uses 25 KiB fixed scratch on the boot stack,
; never a scheduler task's smaller stack. Product parser scratch is separate.
android_a11y_kat:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, AK_FRAME
    mov rbx, rsp
    lea r15, [rel ak_vectors]
    mov r12, r15
    xor r13d, r13d
    mov dword [rbx + AK_STATUS], 0
    ; Same measured token seam as shipped Task3346: boot beacon + invocation
    ; TSC. It is unpredictable before this boot, not a cryptographic key. The
    ; external candidate/runner receipt, not a timestamp, establishes freshness.
    mov eax, [rel boot_nonce]
    test eax, eax
    jz .fail
    mov [rbx + AK_TOKEN], rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    test rax, rax
    jz .fail
    mov [rbx + AK_TOKEN + 8], rax
.case:
    movsxd rsi, dword [r12]
    add rsi, r15
    mov edx, [r12 + 4]
    lea rdi, [rbx + AK_INPUT]
    mov ecx, AK_INPUT_BYTES
    call ak_unpack
    cmp rax, -1
    je .fail
    cmp eax, [r12 + 8]
    jne .fail
    ; Canaries sit immediately outside the actual input and output spans, not
    ; just the large scratch allocation. Poison output to catch silent no-ops.
    mov rax, AK_GUARD
    mov [rbx + AK_INPUT - 8], rax
    mov edx, [r12 + 8]
    lea rdi, [rbx + AK_INPUT]
    mov [rdi + rdx], rax
    mov ecx, [r12 + 12]
    cmp ecx, A11Y_OUTPUT_CAP
    jbe .cap
    mov ecx, A11Y_OUTPUT_CAP
.cap:
    mov [rbx + AK_CAP], rcx
    lea rdi, [rbx + AK_OUTPUT]
    mov [rdi - 8], rax
    mov [rdi + rcx], rax
    mov al, 0xa5
    rep stosb
    lea rdi, [rbx + AK_INPUT_HASH]
    lea rsi, [rbx + AK_INPUT]
    mov edx, [r12 + 8]
    call ak_hash
    test eax, eax
    jnz .fail

    lea rdi, [rbx + AK_INPUT]
    mov esi, [r12 + 8]
    lea rdx, [rbx + AK_OUTPUT]
    mov ecx, [r12 + 12]
    call android_a11y_digest
    mov [rbx + AK_STATUS], eax
    mov [rbx + AK_NODES], ecx
    mov [rbx + AK_BYTES], edx
    mov [rbx + AK_INDEX], r13d
    ; No argument-error vector is hidden in the XML hostile matrix.
    cmp eax, A11Y_LIMIT
    ja .fail
    cmp dword [r12 + 16], 0
    jne .refusal
    test eax, eax
    jnz .fail
    jmp .counts
.refusal:
    test eax, eax
    jz .fail
.counts:
    cmp ecx, [r12 + 20]
    jne .fail
    cmp edx, [r12 + 24]
    jne .fail
    cmp rdx, [rbx + AK_CAP]
    ja .fail
    mov rax, AK_GUARD
    cmp [rbx + AK_INPUT - 8], rax
    jne .fail
    mov ecx, [r12 + 8]
    lea rdi, [rbx + AK_INPUT]
    cmp [rdi + rcx], rax
    jne .fail
    lea rdi, [rbx + AK_OUTPUT]
    cmp [rdi - 8], rax
    jne .fail
    mov rcx, [rbx + AK_CAP]
    cmp [rdi + rcx], rax
    jne .fail
    ; Exact golden bytes, followed by zeros throughout the effective capacity.
    ; For refused calls this grades every byte, not merely output[0] or counts.
    movsxd rsi, dword [r12 + 28]
    add rsi, r15
    mov edx, [rbx + AK_BYTES]
    test edx, edx
    jz .zero_tail                     ; empty golden has no bytes to compare
    call memcmp
    test eax, eax
    jnz .fail
.zero_tail:
    lea rdi, [rbx + AK_OUTPUT]
    mov edx, [rbx + AK_BYTES]
    add rdi, rdx
    mov rcx, [rbx + AK_CAP]
    sub rcx, rdx
    xor eax, eax
    repe scasb
    jne .fail
    lea rdi, [rbx + AK_TEMP]
    lea rsi, [rbx + AK_INPUT]
    mov edx, [r12 + 8]
    call ak_hash
    test eax, eax
    jnz .fail
    lea rdi, [rbx + AK_TEMP]
    lea rsi, [rbx + AK_INPUT_HASH]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .fail
    lea rdi, [rbx + AK_OUTPUT_HASH]
    lea rsi, [rbx + AK_OUTPUT]
    mov edx, [rbx + AK_BYTES]
    call ak_hash
    test eax, eax
    jnz .fail
    lea rdi, [rbx + AK_BIND_HASH]
    lea rsi, [rbx + AK_TOKEN]
    mov edx, 96
    call ak_hash
    test eax, eax
    jnz .fail
    call ak_report
    inc r13d
    add r12, AK_ROW_BYTES
    cmp r13d, AK_CASE_COUNT
    jb .case
    call ak_prefix
    lea rdi, [rel ak_complete]
    call serial_string
    mov edi, r13d
    call ak_number
    lea rdi, [rel ak_newline]
    call serial_string
    lea rdi, [rel ak_pass]
    call serial_string
    xor eax, eax
    jmp .return
.fail:
    lea rdi, [rel ak_fail]
    call serial_string
    mov edi, r13d
    call ak_number
    lea rdi, [rel ak_status_text]
    call serial_string
    mov edi, [rbx + AK_STATUS]
    call ak_number
    lea rdi, [rel ak_newline]
    call serial_string
    mov eax, 1
.return:
    add rsp, AK_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; Trusted fixture codec still checks source/destination lengths before every
; read/copy/product. Op1=u16 literal length+bytes; op2=u16 repeats+u16 pattern
; length+bytes; op3=u16 distance+u16 length from prior output; op0=exact end.
; The op3 forward-copy sequence ports Classic paos.asm .huffman_dist_done /
; .huffman_copy (RFC1951 LZ77), with upfront subtraction-based bounds checks.
; Returns unpacked length or -1.
ak_unpack:
    mov r11, rsi
    add r11, rdx
    jc .bad
    mov rdx, rdi
    add rdx, rcx
    jc .bad
.op:
    cmp rsi, r11
    jae .bad
    lodsb
    test al, al
    jz .end
    cmp al, 1
    je .literal
    cmp al, 3
    je .backref
    cmp al, 2
    jne .bad
    mov rax, r11
    sub rax, rsi
    cmp rax, 4
    jb .bad
    movzx r8d, word [rsi]
    movzx r10d, word [rsi + 2]
    add rsi, 4
    test r8d, r8d
    jz .bad
    test r10d, r10d
    jz .bad
    mov rax, r11
    sub rax, rsi
    cmp r10, rax
    ja .bad
    mov eax, r8d
    imul rax, r10                      ; u16*u16 fits u64, then check capacity
    mov rcx, rdx
    sub rcx, rdi
    cmp rax, rcx
    ja .bad
    mov r9, rsi
.repeat:
    mov rsi, r9
    mov rcx, r10
    rep movsb
    dec r8d
    jnz .repeat
    jmp .op
.backref:
    mov rax, r11
    sub rax, rsi
    cmp rax, 4
    jb .bad
    movzx r8d, word [rsi]              ; distance into already produced bytes
    movzx ecx, word [rsi + 2]
    add rsi, 4
    test r8d, r8d
    jz .bad
    test ecx, ecx
    jz .bad
    lea rax, [rbx + AK_INPUT]
    mov r9, rdi
    sub r9, rax
    cmp r8, r9
    ja .bad                           ; cannot reference before output start
    mov rax, rdx
    sub rax, rdi
    cmp rcx, rax
    ja .bad                           ; entire expansion fits before any copy
    mov r9, rdi
    sub r9, r8
.copy_backref:
    ; Forward byte copy intentionally supports length greater than distance.
    mov al, [r9]
    mov [rdi], al
    inc r9
    inc rdi
    dec ecx
    jnz .copy_backref
    jmp .op
.literal:
    mov rax, r11
    sub rax, rsi
    cmp rax, 2
    jb .bad
    movzx ecx, word [rsi]
    add rsi, 2
    mov rax, r11
    sub rax, rsi
    cmp rcx, rax
    ja .bad
    mov rax, rdx
    sub rax, rdi
    cmp rcx, rax
    ja .bad
    rep movsb
    jmp .op
.end:
    cmp rsi, r11
    jne .bad
    lea rax, [rbx + AK_INPUT]
    sub rdi, rax
    mov rax, rdi
    ret
.bad:
    mov rax, -1
    ret

; Private streaming context, so input/output hashes cannot alias the shared
; one-shot hash scratch. RDI=out32,RSI=bytes,RDX=length, returns SHA status.
ak_hash:
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    lea rdi, [rbx + AK_SHA]
    call sha256_stream_init
    lea rdi, [rbx + AK_SHA]
    mov rsi, r13
    mov rdx, r14
    call sha256_stream_update
    test eax, eax
    jnz .done
    lea rdi, [rbx + AK_SHA]
    mov rsi, r12
    call sha256_stream_final
.done:
    pop r14
    pop r13
    pop r12
    ret

ak_number:
    sub rsp, 8
    lea rsi, [rbx + AK_FMT]
    call fmt_dec
    lea rdi, [rbx + AK_FMT]
    call serial_string
    add rsp, 8
    ret

ak_digest:
    push r12
    push r13
    sub rsp, 8
    mov r12, rdi
    mov r13d, 32
.byte:
    movzx edi, byte [r12]
    lea rsi, [rbx + AK_FMT]
    mov edx, 2
    call fmt_hex
    lea rdi, [rbx + AK_FMT]
    call serial_string
    inc r12
    dec r13d
    jnz .byte
    add rsp, 8
    pop r13
    pop r12
    ret

ak_prefix:
    sub rsp, 8
    lea rdi, [rel ak_prefix_text]
    call serial_string
    mov rdi, [rbx + AK_TOKEN]
    lea rsi, [rbx + AK_FMT]
    mov edx, 16
    call fmt_hex
    lea rdi, [rbx + AK_FMT]
    call serial_string
    mov rdi, [rbx + AK_TOKEN + 8]
    lea rsi, [rbx + AK_FMT]
    mov edx, 16
    call fmt_hex
    lea rdi, [rbx + AK_FMT]
    call serial_string
    add rsp, 8
    ret

ak_report:
    sub rsp, 8
    call ak_prefix
    lea rdi, [rel ak_case_text]
    call serial_string
    movsxd rdi, dword [r12 + 32]
    add rdi, r15
    call serial_string
    lea rdi, [rel ak_input_text]
    call serial_string
    lea rdi, [rbx + AK_INPUT_HASH]
    call ak_digest
    lea rdi, [rel ak_output_text]
    call serial_string
    lea rdi, [rbx + AK_OUTPUT_HASH]
    call ak_digest
    lea rdi, [rel ak_nodes_text]
    call serial_string
    mov edi, [rbx + AK_NODES]
    call ak_number
    lea rdi, [rel ak_bytes_text]
    call serial_string
    mov edi, [rbx + AK_BYTES]
    call ak_number
    lea rdi, [rel ak_status_text]
    call serial_string
    mov edi, [rbx + AK_STATUS]
    call ak_number
    lea rdi, [rel ak_binding_text]
    call serial_string
    lea rdi, [rbx + AK_BIND_HASH]
    call ak_digest
    lea rdi, [rel ak_newline]
    call serial_string
    add rsp, 8
    ret

ak_prefix_text: db 'A11YKAT token=',0
ak_case_text: db ' case=',0
ak_input_text: db ' input_sha256=',0
ak_output_text: db ' output_sha256=',0
ak_nodes_text: db ' nodes=',0
ak_bytes_text: db ' bytes=',0
ak_status_text: db ' status=',0
ak_binding_text: db ' guards=1 binding_sha256=',0
ak_complete: db ' complete cases=',0
ak_newline: db 13,10,0
ak_pass: db '[PAOS64] android: accessibility digest fixture KAT PASS [android.a11y.digest.kat]',13,10,0
ak_fail: db '[PAOS64] android: accessibility digest KAT FAIL case_index=',0

%include "android-a11y-vectors.inc"

; The complete added product/KAT/fixture image stays inside the contract's
; 32 KiB kernel-image delta. Scratch is fixed boot stack, never static BSS.
%if ($ - android_a11y_image_start) > 32768
    %error "Task3347 exceeds 32768-byte kernel image budget"
%endif
%if AK_FRAME + AD_FRAME + 1024 > 32768
    %error "Task3347 exceeds fixed boot scratch budget"
%endif
