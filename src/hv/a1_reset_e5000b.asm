;; MODULE hv/a1_reset_e5000b
;; LAYER 5
;; EXPORTS a1_reset_e5000b_probe
;; IMPORTS bus/pci_bdf, core/time
;; CAPS CAP_MMIO
;; OWNER rc-amd-claude
;; CONTEXT: bsp_only
; RDI=immutable resident original R2 request320, RSI=private result256, EDX=256.
; EAX=0 config observation complete or2 refused. ONLY op1, proposed40001,
; exact10ec:5000 Ethernet function0. Plain8126/8125/8168 are not substitutes.
; Current revision/subsystem are compared, never asserted qualified. VM owns
; authenticated mode/profile, complete topology/custody and original START/
; attempt/deadline. This leaf is not a public permission/pointer API.
; PCI config READS only: no BAR mapping, TCR/OCP/MMIO, sizing, PM/FLR/SBR,
; native driver calls, device/config data writes, wait or claim release.
; Completion is phase1/effects0, not reset qualification. Full conventional
; cap chain bounded32; complete PCIe/PM extents, no overlaps/cycles/duplicates.
; Result fixed16 slots; validity marks actual samples, reserved bytes stay0.
; Reasons1 operands,2 unsupported,3 identity,4 unavailable,5 cap chain,
; 8 original budget,10 capacity. Caller retains containment on every return.

a1_reset_e5000b_probe:
    mov eax, 2
    cmp edx, 256
    jne .early
    test rsi, rsi
    jz .early
    test rsi, 7
    jnz .early
    mov r8, rsi
    add r8, 256
    jc .early
    test rdi, rdi
    jz .early
    test rdi, 7
    jnz .early
    mov r9, rdi
    add r9, 320
    jc .early
    cmp rsi, r9
    jae .separate
    cmp rdi, r8
    jb .early
.separate:
    ; Refuse output aliases before clearing it: original scope remains an input.
    mov r10, [rdi+104]
    mov r11, r10
    add r11, 4
    jc .early
    cmp r10, r8
    jae .scope_extent_ok
    cmp r11, rsi
    ja .early
.scope_extent_ok:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 440                     ; request320 and bounded private scratch
    mov r13, rsi
    mov rsi, rdi
    mov rdi, rsp
    mov ecx, 40
    cld
    rep movsq                        ; no callback can mutate this request
    mov r12, rsp
    mov rdi, r13
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov dword [r13], 'A1RS'
    mov dword [r13+4], (256<<16)|1
    mov dword [r13+16], 2
    mov dword [r13+28], 1
    cmp dword [r12], 'A1RQ'
    jne .done
    cmp dword [r12+4], (320<<16)|1
    jne .done
    mov eax, [r12+8]
    mov [r13+8], eax
    mov eax, [r12+12]
    mov [r13+12], eax
    mov eax, [r12+24]
    mov [r13+32], eax
    mov rax, [r12+40]
    mov [r13+40], rax
    mov rax, [r12+48]
    mov [r13+48], rax
    mov rax, [r12+56]
    mov [r13+56], rax
    mov rax, [r12+296]
    mov [r13+64], rax
    mov dword [r13+28], 2
    cmp dword [r12+12], 1             ; unsupported ops never even read PCI
    jne .done
    cmp dword [r12+8], 0x40001
    jne .done
.method:
    mov dword [r13+28], 1
    cmp qword [r12+312], 0
    jne .done
    cmp qword [r12+40], 0
    je .done
    cmp qword [r12+48], 0
    je .done
    cmp qword [r12+56], 0
    je .done
    cmp qword [r12+296], 0
    je .done
    cmp dword [r12+20], 1
    jb .done
    cmp dword [r12+20], 4
    ja .done
    mov r14d, [r12+24]
    cmp r14d, 65535
    ja .done
    test r14b, 7                     ; function0 only, no historical fixed BDF
    jnz .done
    cmp dword [r12+28], 0x500010ec
    jne .identity
    mov eax, [r12+32]
    shr eax, 8
    cmp eax, 0x020000
    jne .identity
    cmp dword [r12+100], 1
    jne .done
    mov rax, [r12+104]
    test rax, rax
    jz .done
    test al, 3
    jnz .done
    mov rcx, rax
    add rcx, 4
    jc .done
    lea rdx, [r13+256]
    cmp rax, rdx
    jae .scope_separate
    cmp rcx, r13
    ja .done
.scope_separate:
    cmp [rax], r14d                  ; original caller-validated effect scope; no bus-domain inference
    jne .identity
    cmp qword [r12+72], 100000
    jb .done
    cmp qword [r12+72], 10000000
    ja .done
    mov qword [r12+424], 0         ; last checked TSC, monotonic original clock
    xor esi, esi
    xor ebx, ebx
    call a1e5_read
    jc .budget
    call a1e5_sample
    jc .done
    cmp eax, -1
    je .unavailable
    test eax, eax
    jz .unavailable
    cmp eax, [r12+28]
    jne .identity
    mov esi, 8
    mov ebx, 1
    call a1e5_read
    jc .budget
    call a1e5_sample
    jc .done
    cmp eax, [r12+32]
    jne .identity
    mov esi, 0x0c
    call a1e5_read
    jc .budget
    cmp eax, -1
    je .unavailable
    test eax, 0x007f0000             ; normal endpoint, multifunction permitted
    jnz .identity
    mov esi, 0x2c
    mov ebx, 2
    call a1e5_read
    jc .budget
    call a1e5_sample
    jc .done
    cmp eax, -1
    je .unavailable
    cmp eax, [r12+36]
    jne .identity
    mov esi, 4
    mov ebx, 3
    call a1e5_read
    jc .budget
    call a1e5_sample
    jc .done
    cmp eax, -1
    je .unavailable
    mov [r13+72], eax
    mov esi, 0x18
    mov ebx, 4
    call a1e5_read
    jc .budget
    call a1e5_sample
    jc .done
    cmp eax, -1
    je .unavailable
    ; Raw BARs only: never size, map, dereference or infer reset scope.
    mov esi, 0x1c
    mov ebx, 5
    call a1e5_read
    jc .budget
    call a1e5_sample
    jc .done
    cmp eax, -1
    je .unavailable
    mov qword [rsp+384], 0          ; visited/occupied dword bitmap
    mov dword [rsp+396], 0          ; PCIe offset, only final after full walk
    mov dword [rsp+400], 0          ; PM offset
    mov dword [rsp+408], 32         ; strict maximum, independent of TSC
    test dword [r13+72], 0x00100000
    jz .cap_done
    mov esi, 0x34
    call a1e5_read
    jc .budget
    cmp eax, -1
    je .unavailable
    movzx r15d, al
.cap_next:
    test r15d, r15d
    jz .cap_done
    cmp r15d, 0x40
    jb .bad_cap
    cmp r15d, 0xfc
    ja .bad_cap
    test r15b, 3
    jnz .bad_cap
    mov eax, r15d
    shr eax, 2
    bts qword [rsp+384], rax
    jc .bad_cap
    mov esi, r15d
    call a1e5_read
    jc .budget
    cmp eax, -1
    je .unavailable
    test al, al
    jz .bad_cap
    movzx edx, ah
    mov [rsp+404], edx
    cmp al, 0x10
    je .pcie
    cmp al, 1
    je .pm
    jmp .cap_continue
.pcie:
    cmp dword [rsp+396], 0
    jne .bad_cap
    mov [rsp+396], r15d
    mov ebx, 6
    call a1e5_sample
    jc .done
    mov edx, eax
    shr edx, 16
    and edx, 15
    cmp edx, 1
    jb .bad_cap
    cmp edx, 2
    ja .bad_cap
    test eax, 0x00f00000             ; endpoint only
    jnz .bad_cap
    mov ecx, 5                     ; PCI_CAP_EXP_ENDPOINT_SIZEOF_V1 =20
    cmp edx, 2
    jne .pcie_extent
    mov ecx, 13                    ; PCI_CAP_EXP_ENDPOINT_SIZEOF_V2 =0x34
.pcie_extent:
    call a1e5_cap_body               ; reserve full mandatory endpoint extent
    jc .bad_cap
    lea esi, [r15+4]
    call a1e5_read
    jc .budget
    mov ebx, 7
    call a1e5_sample                 ; DeviceCapabilities raw bit28, NOT proof
    jc .done
    cmp eax, -1
    je .unavailable
    jmp .cap_continue
.pm:
    cmp dword [rsp+400], 0
    jne .bad_cap
    mov [rsp+400], r15d
    mov ebx, 8
    call a1e5_sample
    jc .done
    mov edx, eax
    shr edx, 16
    and edx, 7
    cmp edx, 1
    jb .bad_cap
    cmp edx, 3
    ja .bad_cap
    mov ecx, 2                     ; PCI_PM_SIZEOF =8
    call a1e5_cap_body
    jc .bad_cap
    lea esi, [r15+4]
    call a1e5_read
    jc .budget
    mov ebx, 9
    call a1e5_sample                 ; PMCSR NoSoftReset is raw bit3, no PM write
    jc .done
    cmp eax, -1
    je .unavailable
.cap_continue:
    mov r15d, [rsp+404]
    test r15d, r15d
    jz .cap_done
    dec dword [rsp+408]
    jnz .cap_next
    jmp .bad_cap
.cap_done:
    mov eax, [rsp+396]
    mov esi, 0x20000000
    mov ebx, 10
    call a1e5_sample                 ; zero absent ONLY after complete valid walk
    jc .done
    mov eax, [rsp+400]
    mov esi, 0x20000001
    mov ebx, 11
    call a1e5_sample
    jc .done
    ; Fresh identity and command bracket this finite config observation.
    xor esi, esi
    mov ebx, 13
    call a1e5_recheck
    jc .budget
    cmp eax, [r12+28]
    jne .identity
    mov esi, 8
    mov ebx, 14
    call a1e5_recheck
    jc .budget
    cmp eax, [r12+32]
    jne .identity
    mov esi, 0x2c
    mov ebx, 15
    call a1e5_recheck
    jc .budget
    cmp eax, -1
    je .unavailable
    cmp eax, [r12+36]
    jne .identity
    mov esi, 4
    call a1e5_read
    jc .budget
    mov [r13+76], eax
    cmp eax, [r13+72]
    jne .identity
    call a1e5_budget                ; final read cannot consume return reserve
    jc .budget
    mov dword [r13+16], 0
    mov dword [r13+20], 1             ; discovery only, VM checked original scope
    mov dword [r13+28], 0
    jmp .done
.identity:
    mov dword [r13+28], 3
    jmp .done
.unavailable:
    mov dword [r13+28], 4
    jmp .done
.bad_cap:
    mov dword [r13+28], 5
    jmp .done
.budget:
    mov dword [r13+28], 8
    jmp .done
.done:
    mov eax, [r13+16]
    add rsp, 440
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
.early:
    ret

; Original absolute deadline, subtraction avoids reserve+now overflow.
; No local timeout or wait. All subroutines are private to the serialized leaf.
a1e5_budget:
    sub rsp, 8
    call tsc_now
    lea rsp, [rsp+8]
    cmp rax, [r12+424]
    jb .no
    mov [r12+424], rax
    cmp rax, [r12+64]
    jae .no
    mov rdx, [r12+64]
    sub rdx, rax
    cmp rdx, [r12+80]
    jbe .no
    clc
    ret
.no:
    stc
    ret

a1e5_read:
    push rsi                        ; tsc_now's ABI may clobber volatile inputs
    call a1e5_budget
    pop rsi
    jc .out
    mov edi, r14d
    sub rsp, 8
    call pci_bdf_read               ; canonical serialized CF8 READ, no data write
    lea rsp, [rsp+8]
    clc
.out:
    ret

a1e5_recheck:
    sub rsp, 8
    call a1e5_read
    jc .out
    or esi, 0x40000000
    call a1e5_sample
.out:
    lea rsp, [rsp+8]
    ret

; Reserve the full architectural capability extent, not just sampled dwords.
; ECX=extent in dwords (2 PM,5 PCIe v1,13 PCIe v2). The current header is
; already marked. Architectural sizes: installed linux/pci_regs.h UAPI.
; Called only during the chain walk; R12 remains the private stack base.
a1e5_cap_body:
    lea edx, [r15+rcx*4]
    cmp edx, 0x100
    ja .no
    mov edx, r15d
    shr edx, 2
    dec ecx
.next:
    inc edx
    bts qword [r12+384], rdx
    jc .no
    dec ecx
    jnz .next
    clc
    ret
.no:
    stc
    ret

; Fixed slots bound15 observations with both PCIe and PM; slot12 stays empty.
; A repeated final ID updates its slot; all other samples occupy distinct slots.
a1e5_sample:
    cmp ebx, 16
    jae .overflow
    mov [r13+rbx*8+96], esi
    mov [r13+rbx*8+100], eax
    bt dword [r13+92], ebx
    jc .existing
    inc dword [r13+88]
    bts dword [r13+92], ebx
.existing:
    clc
    ret
.overflow:
    mov dword [r13+28], 10
    stc
    ret
