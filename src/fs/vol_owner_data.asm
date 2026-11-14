;; MODULE fs/vol_owner_data
;; LAYER 4
;; EXPORTS vol_owner_data_provision, vol_owner_data_identity, vol_owner_data_bind, vol_owner_data_check
;; IMPORTS fs/vol_owner, fs/storage_access
;; CAPS CAP_BLOCK_READ
;; OWNER saga:rcq20_filesystems
;; CONTEXT: bsp_only
; Included by vol_owner.asm: DATA role in the SAME sealed ownership record.
; No new credential, variable, disk selector or write backend. Old records
; have zero in these reserved bytes and confer no DATA-service authority.
VOE_DATA_ROLE equ 112
VO_DATA_ROLE equ 'DAT1'

; vo_data_entry -> RAX unique DATA entry / 0. Caller has checked vo_ready.
; Validate the complete role set even for an in-memory record.
vo_data_entry:
    xor r8d, r8d
    xor ecx, ecx
.scan:
    cmp ecx, VO_ENT_MAX
    jae .done
    mov eax, ecx
    shl eax, 7
    lea rdx, [rel vo_plain + VO_HDR_SIZE]
    add rdx, rax
    cmp dword [rdx + VOE_DATA_ROLE], 0
    je .next
    cmp dword [rdx + VOE_DATA_ROLE], VO_DATA_ROLE
    jne .no
    test r8, r8
    jnz .no
    cmp dword [rdx + VOE_MAGIC], 'VOE1'
    jne .no
    cmp byte [rdx + VOE_KIND], VO_KIND_FAT32
    jne .no
    cmp byte [rdx + VOE_SCHEME], VO_SCHEME_GPT
    jne .no
    cmp qword [rdx + VOE_ATTRS], 0
    jne .no
    mov rax, 0x4433b9e5ebd0a0a2
    cmp [rdx + VOE_TYPE], rax
    jne .no
    mov rax, 0xc79926b7b668c087
    cmp [rdx + VOE_TYPE + 8], rax
    jne .no
    mov rax, [rdx + VOE_DISK]
    or rax, [rdx + VOE_DISK + 8]
    jz .no
    mov rax, [rdx + VOE_PART]
    or rax, [rdx + VOE_PART + 8]
    jz .no
    cmp dword [rdx + VOE_FSID], 0
    je .no
    mov rax, [rdx + VOE_COUNT]
    test rax, rax
    jz .no
    add rax, [rdx + VOE_FIRST]
    jc .no
    mov r8, rdx
.next:
    inc ecx
    jmp .scan
.done:
    mov rax, r8
    ret
.no:
    xor eax, eax
    ret

; EDI=already-adopted mount -> EAX 0 / VO_E_*. Explicit verified OWNER
; SPECIAL provision only. Changes/revocations use vo_save's epoch clearing,
; authenticated persistence, readback/reopen and uncertainty semantics.
vol_owner_data_provision:
    push rbx
    push r12
    mov r12d, edi
    call storage_access_request_owner
    cmp eax, 1
    jne .denied
    call storage_access_request_intent
    cmp eax, SA_INTENT_SPECIAL
    jne .denied
    mov edi, r12d
    call vol_owner_bind_mount
    test rax, rax
    jz .binding
    ; bind_mount has re-probed the live media and exact adopted identity.
    movzx ebx, al
    dec ebx
    shl ebx, 6
    lea rdx, [rel vo_binds]
    mov ebx, [rdx + rbx + VOB_ENTRY]
    shl ebx, 7
    lea rdx, [rel vo_plain + VO_HDR_SIZE]
    add rdx, rbx
    cmp byte [rdx + VOE_KIND], VO_KIND_FAT32
    jne .type
    cmp byte [rdx + VOE_SCHEME], VO_SCHEME_GPT
    jne .type
    cmp qword [rdx + VOE_ATTRS], 0
    jne .type
    cmp dword [rdx + VOE_FSID], 0
    je .type
    cmp qword [rel vo_plain + VOH_GEN], -1
    je .exhausted
    call vo_new_from_plain
    xor ecx, ecx
.clear_roles:
    mov eax, ecx
    shl eax, 7
    lea rdx, [rel vo_new + VO_HDR_SIZE]
    mov dword [rdx + rax + VOE_DATA_ROLE], 0
    inc ecx
    cmp ecx, VO_ENT_MAX
    jb .clear_roles
    mov dword [rdx + rbx + VOE_DATA_ROLE], VO_DATA_ROLE
    inc qword [rel vo_new + VOH_GEN]
    call vo_save
    jmp .out
.denied:
    mov eax, VO_E_DENIED
    jmp .error
.type:
    mov eax, VO_E_TYPE
    jmp .error
.exhausted:
    mov eax, VO_E_EXHAUSTED
.error:
    call vo_fail
    jmp .out
.binding:
    call vol_owner_last_error
.out:
    pop r12
    pop rbx
    ret

; RDI=trusted kernel out64 -> 0 / -1, output unchanged on refusal.
; diskGUID16, partitionGUID16, first8, count8, FATvolumeID4, reserved12zero.
; Provisioned identity, NOT current-media proof or raw write authority.
vol_owner_data_identity:
    push rbx
    mov rbx, rdi
    test rbx, rbx
    jz .no
    call vo_ready
    test eax, eax
    jnz .no
    call vo_data_entry
    test rax, rax
    jz .no
    mov rdx, [rax + VOE_DISK]
    mov [rbx], rdx
    mov rdx, [rax + VOE_DISK + 8]
    mov [rbx + 8], rdx
    mov rdx, [rax + VOE_PART]
    mov [rbx + 16], rdx
    mov rdx, [rax + VOE_PART + 8]
    mov [rbx + 24], rdx
    mov rdx, [rax + VOE_FIRST]
    mov [rbx + 32], rdx
    mov rdx, [rax + VOE_COUNT]
    mov [rbx + 40], rdx
    mov edx, [rax + VOE_FSID]
    mov [rbx + 48], edx
    mov dword [rbx + 52], 0
    mov qword [rbx + 56], 0
    xor eax, eax
    pop rbx
    ret
.no:
    mov eax, -1
    pop rbx
    ret

; EDI=actual selected mount -> existing owned token / 0. No request grant.
; Full live probe and clone/geometry/epoch checks remain in bind_mount.
vol_owner_data_bind:
    push rbx
    call vol_owner_bind_mount
    test rax, rax
    jz .out
    mov rbx, rax
    call vo_data_entry
    test rax, rax
    jz .no
    movzx edx, bl
    dec edx
    shl edx, 6
    lea rcx, [rel vo_binds]
    mov edx, [rcx + rdx + VOB_ENTRY]
    shl edx, 7
    lea rcx, [rel vo_plain + VO_HDR_SIZE]
    add rcx, rdx
    cmp rax, rcx
    jne .no
    mov rax, rbx
.out:
    pop rbx
    ret
.no:
    xor eax, eax
    jmp .out

; RDI=dev, RSI=lba, RDX=n, RCX=owned token -> 0 / -1.
; Each service effect checks both live adoption and the current DATA role.
; This deliberately does NOT arm storage_access_write_admitted or raw IO.
vol_owner_data_check:
    push rbx
    mov rbx, rcx
    call vol_owner_live_check
    test eax, eax
    jnz .no
    call vo_data_entry
    test rax, rax
    jz .no
    movzx edx, bl
    dec edx
    shl edx, 6
    lea rcx, [rel vo_binds]
    mov edx, [rcx + rdx + VOB_ENTRY]
    shl edx, 7
    lea rcx, [rel vo_plain + VO_HDR_SIZE]
    add rcx, rdx
    cmp rax, rcx
    jne .no
    xor eax, eax
    pop rbx
    ret
.no:
    mov eax, -1
    pop rbx
    ret
