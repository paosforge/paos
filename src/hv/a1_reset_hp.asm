;; MODULE hv/a1_reset_hp
;; LAYER 5
;; EXPORTS a1_reset_hp_probe
;; IMPORTS bus/pci_bdf, boot/paging, core/time
;; CAPS CAP_MMIO
;; OWNER rc-amd-claude
;; CONTEXT: bsp_only
; a1_reset_hp_probe(RDI=resident request320, RSI=private result256, EDX=256)
; -> EAX A1 status: 0 probe complete, 2 refused without hardware writes.
; R2 discovery ONLY: no operation2..5, no reset, no driver binding, no admission
; or hardware qualification. VM owns the dispatcher, signed mode/owner/profile,
; fresh machine identity, snapshot/claim/attempt validation and pointer custody.
; It calls this leaf only with immutable, resident native operands. Copies or
; guest pointers are never authority. This leaf adds no public entry/command.
;
; The request/output layout is VM116495 R2; local offsets intentionally do not
; define the VM-owned a1_reset.inc. Probe accepts candidate IDs10001/10002 only;
; the ID does NOT authorize a write or say that FLR/DASH is supported.
; Config selectors are their raw offsets. Selector20000000 holds the observed
; PCIe capability offset (0 means a completely walked list advertised none).
; 10000040=TCR raw, 10010040=TCR&7cf00000. 40000000|offset is a final identity
; recheck. Result validity bit N describes pair N, never a supported-method bit.
; Reasons:1 operands,2 unsupported op/method,3 identity conflict,4 unavailable
; config,5 malformed capability chain,6 no map,7 unsafe map,8 budget,9 TCR
; ambiguous,10 observation capacity. Available raw facts survive a refusal.
; No PHASE reset/ready bits. Native storage is nonoverlapping, per R2.
;
; TCR uses an existing BAR2 identity mapping, low16GiB, READ access bit0 of the
; R2 map descriptor. UC is checked in the ACTUAL PDE (PCD/PWT, PAT0), not trusted
; from a descriptor flag. A whole firmware MMIO/reserved resource leaf must
; cover it. No cache-bit/table/device write or new mapping is made. A valid
; original dispatcher map is still required; this is not a general MMIO reader.
; A physical bus fault/hot removal is not made recoverable by software checks.

a1_reset_hp_probe:
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
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 360                     ; request320 + bounded local scratch
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
    cmp dword [r12+8], 0x10001
    je .method
    cmp dword [r12+8], 0x10002
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
    cmp dword [r12+28], 0x816810ec
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
    cmp [rax], r14d                  ; VM validated complete census, not peers=0
    jne .identity
    cmp qword [r12+72], 100000
    jb .done
    cmp qword [r12+72], 10000000
    ja .done
    xor esi, esi
    call a1hp_read
    jc .budget
    call a1hp_sample
    jc .done
    cmp eax, -1
    je .unavailable
    test eax, eax
    jz .unavailable
    cmp eax, [r12+28]
    jne .identity
    mov esi, 8
    call a1hp_read
    jc .budget
    call a1hp_sample
    jc .done
    cmp eax, [r12+32]
    jne .identity
    mov esi, 0x0c
    call a1hp_read
    jc .budget
    call a1hp_sample
    jc .done
    test eax, 0x007f0000             ; normal endpoint, multifunction permitted
    jnz .identity
    mov esi, 0x2c
    call a1hp_read
    jc .budget
    call a1hp_sample
    jc .done
    cmp eax, [r12+36]
    jne .identity
    mov esi, 4
    call a1hp_read
    jc .budget
    call a1hp_sample
    jc .done
    cmp eax, -1
    je .unavailable
    mov [r13+72], eax
    mov esi, 0x18
    call a1hp_read
    jc .budget
    call a1hp_sample
    jc .done
    mov [rsp+328], eax               ; BAR2 raw, no sizing
    xor ebp, ebp
    test al, 1
    jnz .bad_map
    mov edx, eax
    and edx, 6
    cmp edx, 4
    je .wide_bar
    test edx, edx
    jnz .bad_map
    jmp .bar_ready
.wide_bar:
    mov esi, 0x1c
    call a1hp_read
    jc .budget
    call a1hp_sample
    jc .done
    mov ebp, eax
    shl rbp, 32
.bar_ready:
    mov eax, [rsp+328]
    and eax, ~15
    or rbp, rax
    mov [rsp+336], rbp               ; exact assigned BAR base
    xor ebx, ebx
    test dword [r13+72], 0x00100000
    jz .cap_done
    mov esi, 0x34
    call a1hp_read
    jc .budget
    cmp eax, -1
    je .unavailable
    movzx ebx, al
    mov qword [rsp+320], 0
    mov dword [rsp+348], 32
.cap_next:
    test ebx, ebx
    jz .cap_done
    cmp ebx, 0x40
    jb .bad_cap
    cmp ebx, 0xfc
    ja .bad_cap
    test bl, 3
    jnz .bad_cap
    mov eax, ebx
    shr eax, 2
    bts qword [rsp+320], rax
    jc .bad_cap
    mov esi, ebx
    call a1hp_read
    jc .budget
    cmp eax, -1
    je .unavailable
    test al, al
    jz .bad_cap
    cmp al, 0x10
    je .pcie
    movzx ebx, ah
    dec dword [rsp+348]
    jnz .cap_next
    jmp .bad_cap
.pcie:
    call a1hp_sample
    jc .done
    cmp ebx, 0xf8                    ; DeviceCapabilities must fit config256
    ja .bad_cap
    mov edx, eax
    shr edx, 16
    and edx, 15
    cmp edx, 1
    jb .bad_cap
    cmp edx, 2
    ja .bad_cap
    test eax, 0x00f00000             ; actual PCIe endpoint, no root/bridge type
    jnz .bad_cap
    lea esi, [rbx+4]
    call a1hp_read
    jc .budget
    call a1hp_sample                 ; raw bit28 is capability, NOT qualification
    jc .done
    cmp eax, -1
    je .unavailable
.cap_done:
    mov eax, ebx
    mov esi, 0x20000000
    call a1hp_sample                 ; distinguish absent from malformed/missing
    jc .done
    mov r15, [r12+112]
    test r15, r15
    jz .no_map
    cmp dword [r12+120], 64
    jne .bad_map
    test r15, 7
    jnz .bad_map
    mov rax, r15
    add rax, 64
    jc .bad_map
    cmp dword [r15], 'A1MP'
    jne .bad_map
    cmp dword [r15+4], (64<<16)|1
    jne .bad_map
    mov rax, [r15+8]
    cmp rax, [r12+304]
    jne .bad_map
    test rax, rax
    jz .bad_map
    mov rax, [r15+40]
    cmp rax, [r12+40]
    jne .bad_map
    cmp [r15+48], r14d
    jne .bad_map
    cmp dword [r15+32], 2
    jne .bad_map
    test dword [r15+36], 1            ; READ; UC independently checked below
    jz .bad_map
    cmp dword [r15+52], 0
    jne .bad_map
    cmp qword [r15+56], 0
    jne .bad_map
    cmp qword [r15+24], 0x44
    jb .bad_map
    test rbp, rbp
    jz .bad_map
    mov rax, rbp
    add rax, [r15+24]
    jc .bad_map
    shr rax, 34
    jnz .bad_map                     ; conservative existing identity-map slice
    cmp rbp, [r15+16]
    jne .bad_map
    test dword [r13+72], 2            ; never enable memory decoding
    jz .bad_map
    lea rdi, [rbp+0x40]              ; check the TCR leaf, including BAR end crossing
    and rdi, -0x200000
    call pci_mmio_resource_page
    test eax, eax
    jz .bad_map
    lea rdi, [rbp+0x40]
    and rdi, -0x200000
    call paging_pd_entry_ptr
    test rax, rax
    jz .bad_map
    mov rax, [rax]
    mov edx, eax
    and edx, 0x109b                 ; present/RW/large, PCD/PWT, PAT0
    cmp edx, 0x9b
    jne .bad_map
    mov rdx, 0x000fffffffe00000
    and rax, rdx
    lea rdx, [rbp+0x40]
    and rdx, -0x200000
    cmp rax, rdx
    jne .bad_map
    ; Re-read every BAR/command/identity fact used for the MMIO admission.
    xor esi, esi
    call a1hp_recheck
    jc .budget
    cmp eax, [r12+28]
    jne .identity
    mov esi, 8
    call a1hp_recheck
    jc .budget
    cmp eax, [r12+32]
    jne .identity
    mov esi, 0x2c
    call a1hp_recheck
    jc .budget
    cmp eax, [r12+36]
    jne .identity
    mov esi, 4
    call a1hp_read
    jc .budget
    mov [r13+76], eax
    cmp eax, [r13+72]
    jne .identity
    mov esi, 0x18
    call a1hp_read
    jc .budget
    cmp eax, [rsp+328]
    jne .identity
    test al, 4
    jz .tcr
    mov esi, 0x1c
    call a1hp_read
    jc .budget
    mov edx, eax
    mov rax, rbp
    shr rax, 32
    cmp eax, edx
    jne .identity
.tcr:
    call a1hp_budget
    jc .budget
    mov eax, [rbp+0x40]              ; one non-read-to-clear TCR load, no poll
    mov esi, 0x10000040
    call a1hp_sample
    jc .done
    mov ebx, eax
    and eax, 0x7cf00000
    mov esi, 0x10010040
    call a1hp_sample
    jc .done
    test ebx, ebx
    jz .ambiguous
    cmp ebx, -1
    je .ambiguous
    ; A final fresh ID brackets the load. It does not prove atomicity or reset.
    xor esi, esi
    call a1hp_recheck
    jc .budget
    cmp eax, [r12+28]
    jne .identity
    call a1hp_budget             ; final ID read must leave original reserve
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
.no_map:
    mov dword [r13+28], 6
    jmp .done
.bad_map:
    mov dword [r13+28], 7
    jmp .done
.budget:
    mov dword [r13+28], 8
    jmp .done
.ambiguous:
    mov dword [r13+28], 9
.done:
    mov eax, [r13+16]
    add rsp, 360
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
a1hp_budget:
    sub rsp, 8                      ; SysV: align before imported call
    call tsc_now
    lea rsp, [rsp+8]
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

a1hp_read:
    push rsi                        ; tsc_now's ABI may clobber volatile inputs
    call a1hp_budget
    pop rsi
    jc .out
    mov edi, r14d
    sub rsp, 8                      ; read helper entered with RSP%16=8
    call pci_bdf_read               ; canonical serialized CF8 READ, no data write
    lea rsp, [rsp+8]
    clc
.out:
    ret

a1hp_recheck:
    sub rsp, 8                      ; keep nested helper entries aligned
    call a1hp_read
    jc .out
    or esi, 0x40000000
    call a1hp_sample
.out:
    lea rsp, [rsp+8]                ; preserve refusal carry flag
    ret

; At most16 pairs on the longest path (64-bit BAR + PCIe + all rechecks).
; Capacity is checked; adding another sample must never silently truncate.
a1hp_sample:
    mov ecx, [r13+88]
    cmp ecx, 16
    jae .overflow
    mov [r13+rcx*8+96], esi
    mov [r13+rcx*8+100], eax
    bts dword [r13+92], ecx
    inc dword [r13+88]
    clc
    ret
.overflow:
    ; Never silently turn a truncated observation into successful discovery.
    mov dword [r13+28], 10
    stc
    ret
