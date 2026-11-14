;; MODULE boot/model_preload
;; LAYER 0
;; EXPORTS boot_model_preload, boot_model_ready, boot_model_base, boot_model_size, boot_model_attempted
;; IMPORTS boot/header, boot/paging, boot/boot_esp_guid, boot/model_volume_config, core/lib/sha256
;; CAPS
;; OWNER saga:cognition
;; CONTEXT: bsp_only
; Fixed data object, read-only before EBS from the unique GPT volume named in
; boot-owner-signed PMV1 configuration on the verified boot volume. Firmware
; SFS handles are enumerated only after signature verification. No name/first
; match, no alternate volume, and no post-EBS fallback after an attempt.
; The existing EfiLoaderData arena owns only hash-verified resident bytes.
%include "cognition-model-identity.inc"
%include "cognition/model_artifact.inc"
; Legacy private descriptors default to enabled. Public builds must explicitly
; disable cognition and carry no disk-identity placeholders.
%ifndef COG_MODEL_ENABLED
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
%error "public build requires explicit COG_MODEL_ENABLED"
%endif
%endif
%define COG_MODEL_ENABLED 1
%endif
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0 && COG_MODEL_ENABLED != 0
%error "public build requires COG_MODEL_ENABLED=0"
%endif
%endif
%if COG_MODEL_ENABLED != 0 && COG_MODEL_ENABLED != 1
%error "COG_MODEL_ENABLED must be 0 or 1"
%endif

boot_model_preload:
%if COG_MODEL_ENABLED = 0
    xor eax, eax
    ret
%else
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and rsp, -16
    sub rsp, 64                       ; MS shadow, Open fifth arg, local success
    cld
    mov byte [rel boot_model_attempted], 1
    cmp byte [rel boot_model_ready], 1
    je .already
    mov qword [rsp + 48], 0
    mov qword [rel bm_root], 0
    mov qword [rel bm_file], 0
    mov qword [rel boot_model_base], 0
    mov qword [rel boot_model_size], 0
    cmp byte [rel boot_esp_part_guid_ok], 1
    jne .out
    mov r12, [rel model_heap_base]
    test r12, r12
    jz .out
    test r12, 0xFFF
    jnz .out
    mov r13, [rel model_heap_size]
    cmp r13, COG_FIXED_MODEL_RESERVE
    jb .out
    mov rax, r12
    add rax, r13
    jc .out
    mov rdx, 0x400000000               ; existing arena's identity-map limit
    cmp rax, rdx
    ja .out
    mov rbx, [rel boot_services]
    test rbx, rbx
    jz .out
    mov rcx, [rel image_handle]
    lea rdx, [rel bm_loaded_guid]
    lea r8, [rel bm_loaded]
    call [rbx + 0x98]
    test rax, rax
    jnz .out
    mov rax, [rel bm_loaded]
    test rax, rax
    jz .out
    mov r14, [rax + 24]                ; exact boot device; never LocateHandle
    test r14, r14
    jz .out
    mov rcx, r14
    lea rdx, [rel bm_dp_guid]
    lea r8, [rel bm_dp]
    call [rbx + 0x98]
    test rax, rax
    jnz .out
    mov rdi, [rel bm_dp]
    test rdi, rdi
    jz .out
    lea rsi, [rel bm_partition]
    call boot_esp_guid_parse
    cmp eax, 1
    jne .out
    mov rax, [rel bm_partition]
    cmp rax, [rel boot_esp_part_guid]
    jne .out
    mov rax, [rel bm_partition + 8]
    cmp rax, [rel boot_esp_part_guid + 8]
    jne .out
    ; Read and authenticate configuration from this exact boot handle first.
    call bm_config_load
    test eax, eax
    jz .out
    ; LocateHandleBuffer(ByProtocol, SFS), bounded and released before any model
    ; file opens. Every matching GUID is counted; duplicate GPT IDs refuse.
    mov qword [rel bm_handles], 0
    mov qword [rel bm_handle_count], 0
    mov qword [rel bm_selected], 0
    mov ecx, 2                       ; ByProtocol
    lea rdx, [rel bm_fs_guid]
    xor r8d, r8d
    lea r9, [rel bm_handle_count]
    lea rax, [rel bm_handles]
    mov [rsp + 32], rax
    call [rbx + 0x138]                ; LocateHandleBuffer
    test rax, rax
    jnz .free_handles_bad
    cmp qword [rel bm_handles], 0
    je .out
    cmp qword [rel bm_handle_count], 0
    je .free_handles_bad
    cmp qword [rel bm_handle_count], 128
    ja .free_handles_bad
    xor r15d, r15d
.find_volume:
    cmp r15, [rel bm_handle_count]
    jae .found_volume
    mov rax, [rel bm_handles]
    mov r14, [rax + r15*8]
    inc r15
    test r14, r14
    jz .find_volume
    mov qword [rel bm_dp], 0
    mov rcx, r14
    lea rdx, [rel bm_dp_guid]
    lea r8, [rel bm_dp]
    call [rbx + 0x98]
    test rax, rax
    jnz .find_volume
    mov rdi, [rel bm_dp]
    test rdi, rdi
    jz .find_volume
    lea rsi, [rel bm_partition]
    call boot_esp_guid_parse
    cmp eax, 1
    jne .find_volume
    mov rax, [rel bm_partition]
    cmp rax, [rel bm_config + 24]
    jne .find_volume
    mov rax, [rel bm_partition + 8]
    cmp rax, [rel bm_config + 32]
    jne .find_volume
    cmp qword [rel bm_selected], 0
    jne .free_handles_bad
    mov [rel bm_selected], r14
    jmp .find_volume
.found_volume:
    mov rcx, [rel bm_handles]
    call [rbx + 0x48]                 ; FreePool (no retained enumeration pool)
    mov qword [rel bm_handles], 0
    test rax, rax
    jnz .out
    mov rcx, [rel bm_selected]
    test rcx, rcx
    jz .out
    lea rdx, [rel bm_fs_guid]
    lea r8, [rel bm_fs]
    call [rbx + 0x98]
    test rax, rax
    jnz .out
    mov rcx, [rel bm_fs]
    test rcx, rcx
    jz .out
    lea rdx, [rel bm_root]
    call [rcx + 8]                     ; OpenVolume
    test rax, rax
    jnz .out
    mov rcx, [rel bm_root]
    test rcx, rcx
    jz .out
    lea rdx, [rel bm_file]
    lea r8, [rel bm_path]
    mov r9d, 1                        ; EFI_FILE_MODE_READ, attributes zero
    mov qword [rsp + 32], 0
    call [rcx + 8]
    test rax, rax
    jnz .close_root
    mov rcx, [rel bm_file]
    test rcx, rcx
    jz .close_root
    mov qword [rel bm_info_size], 512
    lea rdx, [rel bm_info_guid]
    lea r8, [rel bm_info_size]
    lea r9, [rel bm_info]
    call [rcx + 64]                    ; GetInfo, bounded fixed buffer
    test rax, rax
    jnz .close_file
    cmp qword [rel bm_info_size], 82
    jb .close_file
    cmp qword [rel bm_info_size], 512
    ja .close_file
    mov rax, [rel bm_info]
    cmp rax, 82
    jb .close_file
    cmp rax, [rel bm_info_size]
    ja .close_file
    cmp qword [rel bm_info + 8], COG_FIXED_MODEL_BYTES
    jne .close_file
    test byte [rel bm_info + 72], 0x10  ; refuse directories
    jnz .close_file
    xor r15d, r15d
.read:
    mov eax, COG_FIXED_MODEL_BYTES
    sub rax, r15
    jz .eof
    cmp rax, 0x100000
    jbe .chunk
    mov eax, 0x100000
.chunk:
    mov [rel bm_read_size], rax
    mov [rsp + 40], rax                ; requested bound survives MS ABI calls
    mov rcx, [rel bm_file]
    lea rdx, [rel bm_read_size]
    lea r8, [r12 + r15]
    call [rcx + 32]                    ; Read; short progress is allowed
    test rax, rax
    jnz .close_file
    mov rax, [rel bm_read_size]
    test rax, rax
    jz .close_file
    cmp rax, [rsp + 40]
    ja .close_file
    add r15, rax                       ; <= exact bytes, at most N iterations
    jmp .read
.eof:
    mov qword [rel bm_read_size], 1
    mov rcx, [rel bm_file]
    lea rdx, [rel bm_read_size]
    lea r8, [rel bm_eof_byte]           ; never write beyond the model buffer
    call [rcx + 32]
    test rax, rax
    jnz .close_file
    cmp qword [rel bm_read_size], 0
    jne .close_file
    lea rdi, [rel bm_digest]
    mov rsi, r12
    mov edx, COG_FIXED_MODEL_BYTES
    call sha256_hash                   ; hash the same retained bytes we infer
    test rax, rax
    jnz .close_file
    xor ecx, ecx
.hash:
    lea rdx, [rel bm_expected]
    mov al, [rdx + rcx]
    lea rdx, [rel bm_digest]
    cmp al, [rdx + rcx]
    jne .close_file
    inc ecx
    cmp ecx, 32
    jb .hash
    ; The fixed full hash authenticates every tensor descriptor as well as
    ; these supported dimensions. No model-controlled address is used earlier.
    cmp dword [r12], 0x32475850
    jne .close_file
    cmp dword [r12 + 4], 2
    jne .close_file
    cmp dword [r12 + 8], 6
    jne .close_file
    cmp dword [r12 + 12], 12
    jne .close_file
    cmp dword [r12 + 16], 768
    jne .close_file
    cmp dword [r12 + 20], 3072
    jne .close_file
    cmp dword [r12 + 24], 50257
    jne .close_file
    cmp dword [r12 + 28], 1024
    jne .close_file
    cmp dword [r12 + 32], 76
    jne .close_file
    mov qword [rsp + 48], 1
.close_file:
    mov rcx, [rel bm_file]
    call [rcx + 16]
    test rax, rax
    jz .close_root
    mov qword [rsp + 48], 0
.close_root:
    mov rcx, [rel bm_root]
    call [rcx + 16]
    test rax, rax
    jz .closed
    mov qword [rsp + 48], 0
.closed:
    cmp qword [rsp + 48], 1
    jne .out
    ; Firmware cannot allocate overlapping LoaderData. Remove the rounded blob
    ; from the bump arena before heap_init; the allocation remains owned over
    ; EBS and the complete original range stays inside the identity map.
    lea rax, [r12 + COG_FIXED_MODEL_RESERVE]
    mov [rel model_heap_base], rax
    sub r13, COG_FIXED_MODEL_RESERVE
    mov [rel model_heap_size], r13
    mov [rel boot_model_base], r12
    mov qword [rel boot_model_size], COG_FIXED_MODEL_BYTES
    mov byte [rel boot_model_ready], 1
.already:
    mov eax, 1
    jmp .return
.free_handles_bad:
    mov rcx, [rel bm_handles]
    test rcx, rcx
    jz .out
    call [rbx + 0x48]
    mov qword [rel bm_handles], 0
.out:
    xor eax, eax
.return:
    lea rsp, [rbp - 40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
%endif

%if COG_MODEL_ENABLED = 1
; RBX=boot services, R14=verified boot DeviceHandle. Self-aligned MS ABI.
; Closes both config handles successfully before publishing a selector. No heap.
bm_config_load:
    push rbp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 64
    mov qword [rsp + 48], 0
    mov qword [rel bm_root], 0
    mov qword [rel bm_file], 0
    mov rcx, r14
    lea rdx, [rel bm_fs_guid]
    lea r8, [rel bm_fs]
    call [rbx + 0x98]
    test rax, rax
    jnz .out
    mov rcx, [rel bm_fs]
    test rcx, rcx
    jz .out
    lea rdx, [rel bm_root]
    call [rcx + 8]
    test rax, rax
    jnz .out
    mov rcx, [rel bm_root]
    test rcx, rcx
    jz .out
    lea rdx, [rel bm_file]
    lea r8, [rel bm_config_path]
    mov r9d, 1
    mov qword [rsp + 32], 0
    call [rcx + 8]
    test rax, rax
    jnz .root
    mov rcx, [rel bm_file]
    test rcx, rcx
    jz .root
    mov qword [rel bm_info_size], 512
    lea rdx, [rel bm_info_guid]
    lea r8, [rel bm_info_size]
    lea r9, [rel bm_info]
    call [rcx + 64]
    test rax, rax
    jnz .file
    cmp qword [rel bm_info_size], 82
    jb .file
    cmp qword [rel bm_info_size], 512
    ja .file
    mov rax, [rel bm_info]
    cmp rax, 82
    jb .file
    cmp rax, [rel bm_info_size]
    ja .file
    cmp qword [rel bm_info + 8], 384
    jne .file
    test byte [rel bm_info + 72], 0x10
    jnz .file
    mov qword [rsp + 40], 0
.read:
    mov rax, 384
    sub rax, [rsp + 40]
    jz .eof
    mov [rel bm_read_size], rax
    mov [rsp + 56], rax
    mov rcx, [rel bm_file]
    lea rdx, [rel bm_read_size]
    lea r8, [rel bm_config]
    add r8, [rsp + 40]
    call [rcx + 32]
    test rax, rax
    jnz .file
    mov rax, [rel bm_read_size]
    test rax, rax
    jz .file
    cmp rax, [rsp + 56]
    ja .file
    add [rsp + 40], rax
    jmp .read
.eof:
    mov qword [rel bm_read_size], 1
    mov rcx, [rel bm_file]
    lea rdx, [rel bm_read_size]
    lea r8, [rel bm_eof_byte]
    call [rcx + 32]
    test rax, rax
    jnz .file
    cmp qword [rel bm_read_size], 0
    jne .file
    lea rdi, [rel bm_config]
    lea rsi, [rel boot_esp_part_guid]
    call boot_model_config_verify
    cmp eax, 1
    jne .file
    mov qword [rsp + 48], 1
.file:
    mov rcx, [rel bm_file]
    call [rcx + 16]
    test rax, rax
    jz .root
    mov qword [rsp + 48], 0
.root:
    mov rcx, [rel bm_root]
    call [rcx + 16]
    test rax, rax
    jz .out
    mov qword [rsp + 48], 0
.out:
    mov eax, [rsp + 48]
    mov rsp, rbp
    pop rbp
    ret
%endif

align 8
boot_model_base: dq 0
boot_model_size: dq 0
boot_model_ready: db 0
boot_model_attempted: db 0
%if COG_MODEL_ENABLED = 1
align 8
bm_loaded: dq 0
bm_dp: dq 0
bm_fs: dq 0
bm_root: dq 0
bm_file: dq 0
bm_info_size: dq 0
bm_read_size: dq 0
bm_handles: dq 0
bm_handle_count: dq 0
bm_selected: dq 0
bm_config: times 384 db 0
bm_partition: times 16 db 0
bm_digest: times 32 db 0
bm_expected: db COG_FIXED_MODEL_SHA256_BYTES
bm_info: times 512 db 0
bm_eof_byte: db 0
align 8
bm_loaded_guid: dd 0x5b1b31a1,0x11d29562,0xa0003f8e,0x3b7269c9
bm_dp_guid: dd 0x09576e91,0x11d26d3f,0xa000398e,0x3b7269c9
bm_fs_guid: dd 0x964e5b22,0x11d26459,0xa000398e,0x3b7269c9
bm_info_guid: dd 0x09576e92,0x11d26d3f,0xa000398e,0x3b7269c9
bm_config_path: dw __utf16__('\EFI\PaOS\model-volume-a10f8753605f4db4fd2ff0f3950c6f1a4364a5e8832fd074ff2787ef5d38a36c.bin'),0
bm_path: dw __utf16__('\EFI\PaOS\models\a10f8753605f4db4fd2ff0f3950c6f1a4364a5e8832fd074ff2787ef5d38a36c\MODEL.PXG'),0
%endif
