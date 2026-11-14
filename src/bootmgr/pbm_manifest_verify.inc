;; MODULE bootmgr/pbm_manifest_verify
;; LAYER 0
;; EXPORTS pbm_manifest_verify_anchored, manifest_struct_valid
;; IMPORTS boot/boot_v2_contract, bootmgr/rsa2048_verify
;; CAPS
;; OWNER saga:boot
; Exact shared Manager parser and anchored signature check. Pure native bytes:
; no file reads, allocation, trust enrollment, state change or authority grant.
; Include after boot/boot_v2_contract.inc. ADMIN/FS supply immutable BUILD key
; anchors and a private stable original; mutable owner-public/worker claims do
; not supply trust. This checks no selected-state/Active join or replay floor.
; The Manager names its existing locked independent RSA entry explicitly;
; native consumers use rsa2048_verify_sha256 with its own existing lock.

%ifndef PAOS_PBM_MANIFEST_VERIFY_INC
%define PAOS_PBM_MANIFEST_VERIFY_INC 1

; RDI=private original, RSI=exact1024, RDX=BUILD keyID32,
; RCX=BUILD RSA2048 modulus256 (little-endian). EAX=1 verified,0 refused.
; Native callers only. Inputs/anchors are read only and never retained.
pbm_manifest_verify_anchored:
    cmp rsi,PBM_MANIFEST_SIZE
    jne .early_bad
    test rdi,rdi
    jz .early_bad
    test rdx,rdx
    jz .early_bad
    test rcx,rcx
    jz .early_bad
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rdx
    mov rbx,rcx
    call manifest_struct_valid
    test eax,eax
    jz .bad
    lea rdi,[r12+32]
    mov rsi,r13
    mov ecx,4
    cld
    repe cmpsq
    jne .bad
    lea rdi,[r12+PBM_MANIFEST_SIGNATURE_OFF]
    mov rsi,r12
    mov edx,PBM_MANIFEST_SIGNED_SIZE
    mov rcx,rbx
%ifdef PBM_MANIFEST_RSA_VERIFY
    call PBM_MANIFEST_RSA_VERIFY
%else
    call rsa2048_verify_sha256
%endif
    test eax,eax
    setz al
    movzx eax,al
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret
.early_bad:
    xor eax,eax
    ret

; manifest_struct_valid(RDI=exact 1024-byte manifest) -> EAX=1/0.
; Signature and compiled-key identity are checked separately.
manifest_struct_valid:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    cmp  dword [r12], PBM_MANIFEST_MAGIC
    jne  .bad
    cmp  word [r12 + 4], PBM_MANIFEST_VERSION
    jne  .bad
    cmp  word [r12 + 6], PBM_MANIFEST_SIZE
    jne  .bad
    cmp  qword [r12 + 8], 0
    je   .bad
    cmp  word [r12 + 16], 1
    jne  .bad
    movzx r13d, byte [r12 + 18]
    cmp  r13d, 3
    jb   .bad
    cmp  r13d, PBM_MANIFEST_ENTRY_MAX
    ja   .bad
    movzx eax, byte [r12 + 19]
    cmp  eax, PBM_ENTRY_PAOS_A
    je   .default_ok
    cmp  eax, PBM_ENTRY_PAOS_B
    jne  .bad
.default_ok:
    movzx eax, byte [r12 + 20]
    cmp  eax, PBM_MENU_TIMEOUT_MIN
    jb   .bad
    cmp  eax, PBM_MENU_TIMEOUT_MAX
    ja   .bad
    cmp  byte [r12 + 21], 0
    jne  .bad
    lea  rsi, [r12 + 64]
    mov  ecx, 64
.header_zero:
    cmp  byte [rsi], 0
    jne  .bad
    inc  rsi
    dec  ecx
    jnz  .header_zero

    xor  ebx, ebx                    ; unique-entry bit mask
    lea  r14, [r12 + PBM_MANIFEST_ENTRY_OFF]
.entry:
    movzx eax, byte [r14]
    cmp  eax, PBM_ENTRY_PAOS_A
    jb   .bad
    cmp  eax, PBM_ENTRY_MAX
    ja   .bad
    mov  edx, 1
    mov  ecx, eax
    shl  edx, cl
    test ebx, edx
    jnz  .bad
    or   ebx, edx
    movzx edx, byte [r14 + 1]
    test edx, 0xFFFFFFF8
    jnz  .bad
    test edx, 2                    ; every v1 entry is explicitly bootable
    jz   .bad
    cmp  eax, PBM_ENTRY_RESCUE
    ja   .not_required
    test edx, 4
    jz   .bad
.not_required:
    cmp  byte [r14 + 3], 0
    jne  .bad
    mov  edx, [r14 + 4]
    cmp  edx, 512
    jb   .bad
    cmp  edx, 64 * 1024 * 1024
    ja   .bad
    cmp  eax, PBM_ENTRY_PAOS_B
    jbe  .paos_profile
    cmp  eax, PBM_ENTRY_RESCUE
    je   .rescue_profile
    cmp  byte [r14 + 2], 8
    jne  .bad
    jmp  .profile_ok
.paos_profile:
    cmp  byte [r14 + 2], 3
    jne  .bad
    jmp  .profile_ok
.rescue_profile:
    cmp  byte [r14 + 2], 4
    jne  .bad
.profile_ok:
    xor  edx, edx
    xor  ecx, ecx
.digest_nonzero:
    or   dl, [r14 + 16 + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .digest_nonzero
    test dl, dl
    jz   .bad
    movzx edx, word [r14 + 48]
    cmp  edx, 1
    jb   .bad
    cmp  edx, 37
    ja   .bad
    cmp  word [r14 + 50], 10
    jne  .bad
    cmp  word [r14 + 52], '\'
    jne  .bad
    xor  ecx, ecx
.path:
    movzx eax, word [r14 + 52 + rcx*2]
    cmp  ecx, edx
    je   .path_nul
    test ah, ah
    jnz  .bad
    cmp  al, 0x20
    jb   .bad
    cmp  al, 0x7E
    ja   .bad
    cmp  al, '/'
    je   .bad
    cmp  al, '.'
    jne  .path_next
    mov  esi, ecx
    inc  esi
    cmp  esi, edx
    jae  .path_next
    cmp  word [r14 + 52 + rsi*2], '.'
    je   .bad
.path_next:
    inc  ecx
    jmp  .path
.path_nul:
    test eax, eax
    jnz  .bad
    inc  ecx
.path_padding:
    cmp  ecx, 38
    jae  .entry_ok
    cmp  word [r14 + 52 + rcx*2], 0
    jne  .bad
    inc  ecx
    jmp  .path_padding
.entry_ok:
    add  r14, PBM_MANIFEST_ENTRY_SIZE
    dec  r13d
    jnz  .entry
    mov  eax, ebx
    and  eax, 0x0E                  ; A, B, Rescue must all exist
    cmp  eax, 0x0E
    jne  .bad
    mov  eax, PBM_MANIFEST_ENTRY_MAX
    movzx ecx, byte [r12 + 18]
    sub  eax, ecx
    imul eax, PBM_MANIFEST_ENTRY_SIZE
    mov  ecx, eax
    test ecx, ecx
    jz   .good
.unused_zero:
    cmp  byte [r14], 0
    jne  .bad
    inc  r14
    dec  ecx
    jnz  .unused_zero
.good:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%endif
