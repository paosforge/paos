;; MODULE boot/model_volume_config
;; LAYER 0
;; EXPORTS boot_model_config_verify
;; IMPORTS boot/boot_v2_handoff, bootmgr/rsa2048_verify
;; CAPS
;; OWNER saga:cognition
;; CONTEXT: bsp_only
; PMV1: fixed 384-byte owner-signed model-volume configuration. The caller must
; first read exactly 384 bytes plus EOF. Only the boot owner's existing pinned
; RSA key is trusted; the data volume and its device paths remain untrusted.
; [0,128) signed header: magic/version/size, boot partition GUID at8,
; model partition GUID at24 (both GPT on-media bytes), fixed bytes at40,
; fixed SHA256 at48, purpose MODELRO1 at80, 40 zero bytes at88. Signature [128,384).
; No monotonic policy changes: this authorizes only reading the same fixed data
; object from one GUID on this boot volume; no write, code, key or capability.
%include "cognition/model_artifact.inc"

; RDI=384-byte record, RSI=16-byte captured boot GUID -> EAX 1 valid / 0 refuse.
boot_model_config_verify:
    push rbx
    mov rbx, rdi
    test rdi, rdi
    jz .bad
    test rsi, rsi
    jz .bad
    cmp dword [rbx], 0x31564d50       ; PMV1 (domain separation)
    jne .bad
    cmp word [rbx + 4], 1
    jne .bad
    cmp word [rbx + 6], 384
    jne .bad
    mov rax, 0x314f524c45444f4d    ; MODELRO1, explicit read-only data purpose
    cmp [rbx + 80], rax
    jne .bad
    mov rax, [rsi]
    or rax, [rsi + 8]
    jz .bad
    mov rax, [rsi]
    cmp [rbx + 8], rax
    jne .bad
    mov rax, [rsi + 8]
    cmp [rbx + 16], rax
    jne .bad
    mov rax, [rbx + 24]
    or rax, [rbx + 32]
    jz .bad
    cmp qword [rbx + 40], COG_FIXED_MODEL_BYTES
    jne .bad
    xor ecx, ecx
    lea rdx, [rel bmc_digest]
.hash:
    mov al, [rdx + rcx]
    cmp [rbx + 48 + rcx], al
    jne .bad
    inc ecx
    cmp ecx, 32
    jb .hash
    mov ecx, 88
.reserved:
    cmp byte [rbx + rcx], 0
    jne .bad
    inc ecx
    cmp ecx, 128
    jb .reserved
    lea rdi, [rbx + 128]
    mov rsi, rbx
    mov edx, 128
    lea rcx, [rel boot_v2_owner_modulus]
    call rsa2048_verify_sha256
    test eax, eax
    jnz .bad
    mov eax, 1
    pop rbx
    ret
.bad:
    xor eax, eax
    pop rbx
    ret
bmc_digest: db COG_FIXED_MODEL_SHA256_BYTES
