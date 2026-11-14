;; MODULE sec/ucode_preload
;; LAYER 2
;; EXPORTS ucode_preload, ucp_reason, ucp_size, ucp_tsc_start, ucp_tsc_end
;; IMPORTS boot/header, boot/boot_v2_handoff, core/lib/sha256, sec/cpu_microcode_boot
;; CAPS
;; OWNER saga:security
; RCQ-42 slice 2b-2: the pre-EBS read of the microcode pack the BSP apply
; (sec/cpu_microcode_boot) consumes. BOOT answer 02:49:41:
; - The path comes from the validated Manager handoff, never from
;   LoadedImage.FilePath (0 on PAX1 direct entry, and both slots share one
;   directory): PAOS_A reads \EFI\PaOS\slots\paos-a.ucd, PAOS_B paos-b.ucd.
;   A direct boot, a live Try medium, a non-NORMAL profile or any other entry
;   reads nothing.
; - Read only, right after pmod_preload: no WRMSR pre-EBS (early_trap resets).
; - Integrity is the image signature: the pack's SHA-256 is compiled in
;   (ucode-pack-digest.inc, PAOS_UCODE_PACK_DIGEST_INC). An all-zero digest
;   (every build without a pack) reads nothing. A missing, stale, oversized or
;   mismatched pack is a reason code and no apply, never a boot failure.
;
; The bytes stay in one EfiLoaderData pool, aligned up to 16 (Intel update
; data must be 16-byte aligned; pools are only 8), and are handed to
; mcb_pack_buf/mcb_pack_len only after the digest matched. Every other path
; frees the pool. Raw TSC at entry and exit for the boot budget.

UCP_MAX         equ 0x100000            ; 1 MiB bound; a read of exactly this may be truncated
UCP_MIN         equ 48                  ; one update header
UCP_ALIGN       equ 16

UCP_R_NOTRUN    equ 0                   ; BSS default: the reader never ran
UCP_R_OK        equ 1                   ; digest matched, pack handed to the BSP apply
UCP_R_NOBUILD   equ 2                   ; no digest compiled in: nothing read
UCP_R_DIRECT    equ 3                   ; not a Manager launch
UCP_R_TRY       equ 4                   ; live Try medium
UCP_R_PROFILE   equ 5                   ; Safe/other profile
UCP_R_ENTRY     equ 6                   ; handoff entry is not PAOS_A/PAOS_B
UCP_R_VOLUME    equ 7                   ; boot services, LoadedImage, SFS or OpenVolume failed
UCP_R_ALLOC     equ 8                   ; AllocatePool failed
UCP_R_ABSENT    equ 9                   ; Open failed (no pack staged)
UCP_R_READ      equ 10                  ; Read failed
UCP_R_SIZE      equ 11                  ; < UCP_MIN or >= UCP_MAX
UCP_R_DIGEST    equ 12                  ; hash failed or does not match the image's digest

%ifdef PAOS_UCODE_PACK_DIGEST_INC
%include "ucode-pack-digest.inc"        ; defines UCODE_PACK_DIGEST_BYTES (32 bytes)
%ifndef UCODE_PACK_DIGEST_BYTES
%error "ucode-pack-digest.inc must define UCODE_PACK_DIGEST_BYTES"
%endif
%endif

; ucode_preload: pre-EBS, boot services live. No return value; the outcome is
; ucp_reason plus mcb_pack_buf/len. Keeps RBX, RBP, R12-R15.
ucode_preload:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    and  rsp, -16                       ; firmware calls need RSP mod 16 = 0
    sub  rsp, 48                        ; shadow space + root.Open's fifth argument
    xor  ebx, ebx                       ; pool to free (0 = none)
    xor  r12d, r12d                     ; open root
    xor  r13d, r13d                     ; open file
    call ucode_preload_tsc
    mov  [rel ucp_tsc_start], rax
    mov  qword [rel mcb_pack_buf], 0
    mov  qword [rel mcb_pack_len], 0
    mov  qword [rel ucp_size], 0
    mov  r14d, UCP_R_NOBUILD
    mov  rax, [rel ucp_digest]
    or   rax, [rel ucp_digest + 8]
    or   rax, [rel ucp_digest + 16]
    or   rax, [rel ucp_digest + 24]
    jz   .done
    mov  r14d, UCP_R_DIRECT
    cmp  byte [rel pbm_manager_launch], 1
    jne  .done
    mov  r14d, UCP_R_TRY
    cmp  byte [rel pbm_try_media], 0
    jne  .done
    mov  r14d, UCP_R_PROFILE
    cmp  byte [rel pbm_profile], PBM_PROFILE_NORMAL
    jne  .done
    mov  r14d, UCP_R_ENTRY
    lea  rax, [rel ucp_path_a]
    cmp  byte [rel pbm_entry], PBM_ENTRY_PAOS_A
    je   .path
    lea  rax, [rel ucp_path_b]
    cmp  byte [rel pbm_entry], PBM_ENTRY_PAOS_B
    jne  .done
.path:
    mov  [rel ucp_path], rax

    mov  r14d, UCP_R_VOLUME
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .done
    mov  rcx, [rel image_handle]
    lea  rdx, [rel ucp_loaded_image_guid]
    lea  r8, [rel ucp_loaded_image]
    call [rax + 0x98]                   ; HandleProtocol(LoadedImage)
    test rax, rax
    jnz  .done
    mov  rax, [rel ucp_loaded_image]
    mov  rcx, [rax + 24]                ; LoadedImage.DeviceHandle
    mov  rax, [rel boot_services]
    lea  rdx, [rel ucp_simple_fs_guid]
    lea  r8, [rel ucp_simple_fs]
    call [rax + 0x98]                   ; HandleProtocol(SimpleFileSystem)
    test rax, rax
    jnz  .done
    mov  rcx, [rel ucp_simple_fs]
    lea  rdx, [rel ucp_root]
    call [rcx + 8]                      ; OpenVolume
    test rax, rax
    jnz  .done
    mov  r12, [rel ucp_root]

    mov  r14d, UCP_R_ALLOC
    mov  rax, [rel boot_services]
    mov  ecx, 2                         ; EfiLoaderData
    mov  edx, UCP_MAX + UCP_ALIGN
    lea  r8, [rel ucp_pool]
    call [rax + 0x40]                   ; AllocatePool
    test rax, rax
    jnz  .close
    mov  rbx, [rel ucp_pool]

    mov  r14d, UCP_R_ABSENT
    mov  rcx, r12
    lea  rdx, [rel ucp_file]
    mov  r8, [rel ucp_path]
    mov  r9d, 1                         ; EFI_FILE_MODE_READ
    mov  qword [rsp + 32], 0
    call [r12 + 8]                      ; root.Open
    test rax, rax
    jnz  .close
    mov  r13, [rel ucp_file]

    mov  r14d, UCP_R_READ
    lea  rax, [rbx + UCP_ALIGN - 1]
    and  rax, -UCP_ALIGN
    mov  [rel ucp_buf], rax
    mov  qword [rel ucp_size], UCP_MAX
    mov  rcx, r13
    lea  rdx, [rel ucp_size]
    mov  r8, rax
    call [r13 + 32]                     ; file.Read
    test rax, rax
    jnz  .close
    mov  r14d, UCP_R_SIZE
    mov  rax, [rel ucp_size]
    cmp  rax, UCP_MIN
    jb   .close
    cmp  rax, UCP_MAX
    jae  .close                         ; exact max may be truncated: reject

    mov  r14d, UCP_R_DIGEST
    lea  rdi, [rel ucp_sha]
    mov  rsi, [rel ucp_buf]
    mov  rdx, [rel ucp_size]
    call sha256_hash
    test rax, rax
    jnz  .close
    mov  rax, [rel ucp_sha]
    xor  rax, [rel ucp_digest]
    mov  rdx, [rel ucp_sha + 8]
    xor  rdx, [rel ucp_digest + 8]
    or   rax, rdx
    mov  rdx, [rel ucp_sha + 16]
    xor  rdx, [rel ucp_digest + 16]
    or   rax, rdx
    mov  rdx, [rel ucp_sha + 24]
    xor  rdx, [rel ucp_digest + 24]
    or   rax, rdx
    jnz  .close

    mov  r14d, UCP_R_OK
    mov  rax, [rel ucp_buf]
    mov  [rel mcb_pack_buf], rax
    mov  rax, [rel ucp_size]
    mov  [rel mcb_pack_len], rax
    xor  ebx, ebx                       ; the pool now holds the admitted pack
.close:
    test r13, r13
    jz   .root
    mov  rcx, r13
    call [r13 + 16]                     ; file.Close
.root:
    test r12, r12
    jz   .pool
    mov  rcx, r12
    call [r12 + 16]                     ; root.Close
.pool:
    test rbx, rbx
    jz   .done
    mov  rax, [rel boot_services]
    mov  rcx, rbx
    call [rax + 0x48]                   ; FreePool
.done:
    mov  [rel ucp_reason], r14d
    call ucode_preload_tsc
    mov  [rel ucp_tsc_end], rax
    lea  rsp, [rbp - 32]
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; Hardware adapter: tests replace only this body.
ucode_preload_tsc:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    ret

align 8
ucp_digest:
%ifdef UCODE_PACK_DIGEST_BYTES
    db UCODE_PACK_DIGEST_BYTES
    times -((($ - ucp_digest) - 32) * (($ - ucp_digest) - 32)) db 0  ; exactly 32 B, else an assembly error
%else
    times 32 db 0                       ; no pack built: all zero, nothing read
%endif
ucp_loaded_image_guid:
    dd 0x5B1B31A1
    dw 0x9562, 0x11D2
    db 0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B
ucp_simple_fs_guid:
    dd 0x964E5B22
    dw 0x6459, 0x11D2
    db 0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B
ucp_path_a: dw __utf16__('\EFI\PaOS\slots\paos-a.ucd'), 0
ucp_path_b: dw __utf16__('\EFI\PaOS\slots\paos-b.ucd'), 0

%macro WDATA_boot_ucode_preload 0
alignb 8
ucp_reason:       resd 1
                  resd 1
ucp_size:         resq 1                ; bytes read (EFI_FILE Read in/out)
ucp_tsc_start:    resq 1
ucp_tsc_end:      resq 1
ucp_path:         resq 1
ucp_buf:          resq 1
ucp_pool:         resq 1
ucp_loaded_image: resq 1
ucp_simple_fs:    resq 1
ucp_root:         resq 1
ucp_file:         resq 1
ucp_sha:          resb 32
%endmacro
WDATA_BSS_DEFER WDATA_boot_ucode_preload
