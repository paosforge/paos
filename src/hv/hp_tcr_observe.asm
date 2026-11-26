;; MODULE hv/hp_tcr_observe
;; LAYER 5
;; EXPORTS hp_tcr_observe
;; IMPORTS bus/pci_bdf, boot/paging, core/time
;; CAPS CAP_MMIO
;; OWNER rc-amd-claude
;; CONTEXT: bsp_only
; RDI=immutable native request96,RSI=private result128,RDX=exact128.
; EAX0 observation complete/2 refused. Dedicated observation envelope: no A1
; owner START, signed reset method, effect scope, reset phase or admission.
; VM owns actual caller/export, resident custody, original machine/boot/probe,
; immutable native census/map provenance and original deadline/return reserve.
; Correlation checks are not authentication. Not a public pointer/permission API.
; Full local ABI: gauntlet_v2/docs/hp_tcr_observe.md. Device/PDE writes: none.
; Exact HP10ec:8168 rev0E/subsystem103c:8617, function0; DASH peers read only
; by VM's independent full8function producer. No setting, ownership or mapping
; change. Resource+actual UC identity leaf and current config bracket TCR.

hp_tcr_observe:
    mov eax, 2
    cmp rdx, 128
    jne .early
    mov rax, rdi
    mov ecx, 96
    call hpt_range
    jc .reject
    mov r8, rdx                      ; request end
    mov rax, rsi
    mov ecx, 128
    call hpt_range
    jc .reject
    mov r9, rdx                      ; output end
    cmp rsi, r8
    jae .separate
    cmp rdi, r9
    jb .reject
.separate:
    cmp dword [rdi+64], 2176
    jne .reject
    cmp dword [rdi+80], 64
    jne .reject
    mov rax, [rdi+56]
    mov ecx, 2176
    call hpt_range
    jc .reject
    cmp rax, r9
    jae .census_separate
    cmp rdx, rsi
    ja .reject
.census_separate:
    mov rax, [rdi+72]
    mov ecx, 64
    call hpt_range
    jc .reject
    cmp rax, r9
    jae .map_separate
    cmp rdx, rsi
    ja .reject
.map_separate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 2376                    ; request96,map64,census2176,scratch40
    mov r13, rsi
    mov rsi, rdi
    mov rdi, rsp
    mov ecx, 12
    cld
    rep movsq
    mov r12, rsp
    mov rsi, [r12+72]
    lea rdi, [r12+96]
    mov ecx, 8
    rep movsq
    mov rsi, [r12+56]
    lea rdi, [r12+160]
    mov ecx, 272
    rep movsq                        ; no mutable nested descriptor after callbacks
    lea r15, [r12+160]
    mov rdi, r13
    xor eax, eax
    mov ecx, 16
    rep stosq
    mov dword [r13], 'A1HT'
    mov dword [r13+4], (128<<16)|1
    mov dword [r13+8], 2
    mov dword [r13+12], 1
    cmp dword [r12], 'A1HQ'
    jne .done
    cmp dword [r12+4], (96<<16)|1
    jne .done
    cmp dword [r12+12], 0
    jne .done
    cmp dword [r12+68], 0
    jne .done
    cmp dword [r12+84], 0
    jne .done
    mov r14d, [r12+8]
    cmp r14d, 65535
    ja .done
    test r14b, 7
    jnz .done
    mov [r13+16], r14d
    mov rax, [r12+16]
    test rax, rax
    jz .binding
    mov [r13+24], rax
    mov rax, [r12+24]
    test rax, rax
    jz .binding
    mov [r13+32], rax
    mov rax, [r12+88]
    test rax, rax
    jz .binding
    mov [r13+40], rax
    ; Correlate an actual complete native observation, never a reset scope.
    cmp dword [r15], 'A1CS'
    jne .census
    cmp dword [r15+4], (2176<<16)|1
    jne .census
    cmp qword [r15+8], 0             ; status0,reason0
    jne .census
    cmp [r15+16], r14d
    jne .binding
    mov rax, [r15+32]
    cmp rax, [r12+16]
    jne .binding
    mov rax, [r15+40]
    cmp rax, [r12+24]
    jne .binding
    cmp dword [r15+24], 255
    jne .census
    cmp dword [r15+28], 255
    jne .census
    cmp dword [r15+64], 1024
    jne .census
    cmp dword [r15+68], 2048
    jne .census
    mov ecx, 5
    lea rsi, [r15+88]
.census_reserved:
    cmp qword [rsi], 0
    jne .census
    add rsi, 8
    loop .census_reserved
    xor ebx, ebx
    xor edx, edx
.vendor:
    mov ecx, ebx
    shl ecx, 8
    movzx eax, word [r15+rcx+128]
    cmp eax, 65535
    je .vendor_next
    test eax, eax
    jz .census
    bts edx, ebx
.vendor_next:
    inc ebx
    cmp ebx, 8
    jb .vendor
    cmp edx, [r15+20]
    jne .census
    test edx, 1
    jz .census
    mov [r13+104], edx
    mov dword [r13+108], 1024
    bts dword [r13+20], 11
    cmp dword [r15+128], 0x816810ec
    jne .identity
    cmp dword [r15+128+8], 0x0200000e
    jne .identity
    cmp dword [r15+128+0x2c], 0x8617103c
    jne .identity
    mov eax, [r15+128+0xc]
    cmp eax, -1
    je .identity
    test eax, 0x007f0000
    jnz .identity
    mov rax, [r12+40]
    cmp rax, 100000
    jb .budget
    cmp rax, 10000000
    ja .budget
    cmp [r12+48], rax
    jb .budget
    imul rbx, rax, 100
    cmp [r12+48], rbx
    jae .budget
    call tsc_now
    mov [r13+48], rax
    mov [r13+56], rax
    cmp rax, [r15+56]
    jb .budget
    mov rcx, [r15+56]
    cmp rcx, [r15+48]
    jb .budget
    mov rcx, rax
    sub rcx, [r15+48]
    jc .budget
    cmp rcx, rbx                    ; freshness in original calibrated TSC domain
    ja .budget
    mov rcx, [r12+32]
    sub rcx, rax
    jbe .budget
    cmp rcx, rbx
    ja .budget
    call hpt_identity               ; live facts must match the native census
    jc .done
    lea rbx, [r12+96]
    cmp dword [rbx], 'A1HM'
    jne .map
    cmp dword [rbx+4], (64<<16)|1
    jne .map
    mov rax, [rbx+8]
    cmp rax, [r12+16]
    jne .binding
    mov rax, [rbx+16]
    cmp rax, [r12+24]
    jne .binding
    mov rax, [rbx+24]
    cmp rax, [r12+88]
    jne .binding
    cmp [rbx+48], r14d
    jne .binding
    cmp dword [rbx+52], 2
    jne .map
    cmp dword [rbx+56], 1             ; observation map READ only
    jne .map
    cmp dword [rbx+60], 0
    jne .map
    cmp qword [rbx+40], 0x44
    jb .map
    mov eax, [r13+80]
    test al, 1
    jnz .map
    mov edx, eax
    and edx, 6
    xor ebp, ebp
    cmp edx, 4
    je .wide
    test edx, edx
    jnz .map
    jmp .bar
.wide:
    mov ebp, [r13+84]
    shl rbp, 32
.bar:
    and eax, ~15
    or rbp, rax
    test rbp, rbp
    jz .map
    cmp rbp, [rbx+32]
    jne .map
    mov rax, rbp
    add rax, [rbx+40]
    jc .map
    shr rax, 34
    jnz .map
    test dword [r13+76], 2
    jz .map
    mov [r13+88], rbp
    lea rdi, [rbp+0x40]
    and rdi, -0x200000
    call pci_mmio_nonram_chunk
    test eax, eax
    jz .map
    lea rdi, [rbp+0x40]
    and rdi, -0x200000
    call paging_pd_entry_ptr
    test rax, rax
    jz .map
    mov rax, [rax]
    mov edx, eax
    and edx, 0x109b
    cmp edx, 0x9b
    jne .map
    mov rdx, 0x000fffffffe00000
    and rax, rdx
    lea rdx, [rbp+0x40]
    and rdx, -0x200000
    cmp rax, rdx
    jne .map
    bts dword [r13+20], 12
    call hpt_identity               ; preserve RBPs actual BAR base
    jc .done
    call hpt_budget
    jc .budget
    mov eax, [rbp+0x40]              ; sole non-read-to-clear TCR load
    mov [r13+96], eax
    bts dword [r13+20], 6
    test eax, eax
    jz .tcr
    cmp eax, -1
    je .tcr
    xor esi, esi
    call hpt_read
    jc .budget
    mov [r13+100], eax
    bts dword [r13+20], 7
    cmp eax, [r15+128]
    jne .final_identity
    call hpt_budget                 ; do not declare success after reserve expires
    jc .budget
    mov dword [r13+8], 0
    mov dword [r13+12], 0
    jmp .done
.final_identity:
    mov dword [r13+112], 0
    mov edx, [r15+128]
    mov [r13+116], edx
    mov [r13+120], eax
.identity:
    mov dword [r13+12], 5
    jmp .done
.binding:
    mov dword [r13+12], 2
    jmp .done
.census:
    mov dword [r13+12], 3
    jmp .done
.budget:
    mov dword [r13+12], 4
    jmp .done
.map:
    mov dword [r13+12], 6
    jmp .done
.tcr:
    mov dword [r13+12], 7
.done:
    mov eax, [r13+8]
    add rsp, 2376
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.reject:
    mov eax, 2
.early:
    ret

; RAX pointer,ECX fixed bytes -> RDX end; only volatile RDX/R10 changed.
; Residency is a native caller obligation; canonical is not a permission check.
hpt_range:
    test rax, rax
    jz .no
    test al, 7
    jnz .no
    mov rdx, rax
    add rdx, rcx
    jc .no
    mov r10, rax
    shl r10, 16
    sar r10, 16
    cmp r10, rax
    jne .no
    lea r10, [rdx-1]
    shl r10, 16
    sar r10, 16
    inc r10
    cmp r10, rdx
    jne .no
    clc
    ret
.no:
    stc
    ret

hpt_budget:
    sub rsp, 8
    call tsc_now
    lea rsp, [rsp+8]
    cmp rax, [r13+56]
    jb .no
    mov [r13+56], rax
    cmp rax, [r12+32]
    jae .no
    mov rdx, [r12+32]
    sub rdx, rax
    cmp rdx, [r12+48]
    jbe .no
    clc
    ret
.no:
    stc
    ret

hpt_read:
    push rsi
    call hpt_budget
    pop rsi
    jc .out
    mov edi, r14d
    sub rsp, 8
    call pci_bdf_read
    lea rsp, [rsp+8]
    clc
.out:
    ret

; Six fixed raw config facts; retain latest contradicting sample+offset/expected.
; Original census bytes stay immutable on the private stack throughout.
hpt_identity:
    push rbx
    push rbp
    sub rsp, 8
    lea rbx, [rel hpt_fields]
    xor ebp, ebp
.next:
    mov esi, [rbx]
    call hpt_read
    jc .budget
    mov edx, [rbx+4]
    mov [r13+rdx], eax
    bts dword [r13+20], ebp
    cmp eax, [r15+rsi+128]
    jne .identity
    add rbx, 8
    inc ebp
    cmp ebp, 6
    jb .next
    clc
    jmp .out
.identity:
    mov [r13+112], esi
    mov edx, [r15+rsi+128]
    mov [r13+116], edx
    mov [r13+120], eax
    mov dword [r13+12], 5
    stc
    jmp .out
.budget:
    mov dword [r13+12], 4
    stc
.out:
    lea rsp, [rsp+8]
    pop rbp
    pop rbx
    ret
align 8
hpt_fields:
    dd 0,64, 8,68, 0x2c,72, 4,76, 0x18,80, 0x1c,84
