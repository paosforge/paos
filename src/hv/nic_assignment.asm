;; MODULE hv/nic_assignment
;; LAYER 5
;; EXPORTS nic_assignment_attach, nic_assignment_attach_wifi, nic_assignment_release, nic_assignment_receipt, nic_assignment_owned, nic_assignment_admit, nic_assignment_irq, nic_assignment_vpci_in, nic_assignment_vpci_out, nic_assignment_state, nic_assignment_error
;; IMPORTS hv/vmx, hv/svm, hv/nic_selection, hv/pci_assign, hv/slat_mmio, hv/hv_ops, hv/amdvi_hda, hv/vtd, bus/pci_bdf, core/time
;; CAPS CAP_MMIO
;; OWNER rc-codex-av
;; CONTEXT: bsp_only
; Serialized native VM transaction, one selected segment0 NIC, no scanner.
; Include once; define PAOS_NIC_ASSIGNMENT before pci_assign/vtd_guest hooks.
; Attach(RDI SLATroot, RSI HSM32, RDX originalNICS592, RCX consumedSTART)
; -> EAX0/-1. Default is Ethernet020000; attach_wifi is opt-in028000 only.
; Both have the same four operands; neither accepts a caller class selector.
; Actual contiguous RAM comes from hv_linux_ram/bytes.
; Release(EDI exactBDF, RSI exactSTART) ->0/-1, only actual CPU-off flags.
; Receipt(RDI out64) ->1live/0, copied original backend shape only after join.
; Owned() ->1 while armed/live/releasing/poison; poisoned ownership never reset.
; Admit(EDI BDF, RSI START) ->1 only armed+reset for Intel's narrow class gate.
; Config ABI matches hv_vpci_*; IRQ polls real PCI Status.Interrupt, never Ready.
; Physical INTx/MSI/MSIX remain disabled. Guest sees fixed memory BARs only,
; one synthetic bridge + 00:01.0, no capability list. All six physical BARs
; (including I/O/64-bit upper halves) restored and read back after FLR.
; Unsupported FLR, INTx, memory shape or resource proof refuses, not no-IOMMU.
; No native driver unbind or compatibility-domain restoration is attempted.
NICA_IDLE equ 0
NICA_ARMED equ 1
NICA_LIVE equ 2
NICA_RELEASING equ 3
NICA_POISON equ 4
NICA_IRQ equ 6
NICA_BAR_GPA equ 0xE0000000
NICA_BAR_WINDOW equ 0x1000000
NICA_CMD_MASK equ 0x0547

nica_cpu_off:
    xor eax, eax
    cmp byte [rel hv_linux_running], 0
    jne .out
    cmp byte [rel hv_linux_vmx_live], 0
    jne .out
    cmp qword [rel hv_svm_cur_vmcb], 0
    jne .out
    mov eax, 1
.out: ret

nic_assignment_owned:
    xor eax, eax
    cmp byte [rel nic_assignment_state], NICA_IDLE
    setne al
    ret

nic_assignment_admit:
    xor eax, eax
    cmp byte [rel nic_assignment_state], NICA_ARMED
    jne .out
    cmp byte [rel nica_reset_ok], 1
    jne .out
    cmp edi, [rel nica_bdf]
    jne .out
    cmp rsi, [rel nica_gen]
    jne .out
    mov eax, 1
.out: ret

nic_assignment_attach:
    mov r8d, 0x020000                  ; preserve default Ethernet-only ABI
    jmp nica_attach_class

nic_assignment_attach_wifi:
    mov r8d, 0x028000                  ; explicit native entry, never a public flag
nica_attach_class:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 600                       ; staged current NICS plus private expected class
    mov [rsp+592], r8d                 ; callback-clobber-safe, no shared class state
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov dword [rel nic_assignment_error], 1
    cmp byte [rel nic_assignment_state], NICA_IDLE
    jne .bad
    cmp byte [rel pcia_state], 0
    jne .bad
    call nica_cpu_off
    test eax, eax
    jz .bad
    test r12, r12
    jz .bad
    test r12, 0xFFF
    jnz .bad
    test r13, r13
    jz .bad
    test r14, r14
    jz .bad
    test r15, r15
    jz .bad
    mov eax, [rel hv_linux_start_consumed]
    cmp r15, rax
    jne .bad
    cmp r15, [rel nica_gen]
    jbe .bad
    cmp qword [rel tsc_khz], 0
    je .bad
    mov rax, [r13]                     ; bounded SLAT pool, caller-owned control memory
    test rax, rax
    jz .bad
    test rax, 0xFFF
    jnz .bad
    mov ecx, [r13+8]
    test ecx, ecx
    jz .bad
    cmp ecx, 4096
    ja .bad
    cmp ecx, [r13+12]
    jb .bad
    test dword [r13+16], ~1
    jnz .bad
    shl rcx, 12
    add rcx, rax
    jc .bad
    cmp r12, rax
    jb .pool_ok
    cmp r12, rcx
    jb .bad
.pool_ok:
    cmp dword [r14], 'NICS'
    jne .bad
    cmp dword [r14+4], (592<<16)|1
    jne .bad
    mov edi, [r14+8]
    mov rsi, rsp
    mov edx, 592
    call nic_select_snapshot
    mov [rel nic_assignment_error], eax ; retain exact ISO/NICS reason on read-only refusal
    test eax, eax
    jnz .bad
    mov dword [rel nic_assignment_error], 2
    mov rsi, r14
    mov rdi, rsp
    mov ecx, 592/8
    cld
    repe cmpsq
    jne .bad
    mov dword [rel nic_assignment_error], 2
    mov eax, [rsp+16]
    shr eax, 8
    cmp eax, [rsp+592]                 ; exact entry-selected class, not a scanner
    jne .bad
    cmp byte [rsp+22], 1               ; advertised FLR, still independently found/read
    jne .bad
    cmp byte [rsp+23], 1
    jb .bad
    cmp byte [rsp+23], 4
    ja .bad
    ; A malformed/looping/duplicate MSI list cannot be treated as absence.
    test byte [rsp+64+6], 0x10
    jz .bad
    movzx esi, byte [rsp+64+0x34]
    xor r8d, r8d
    xor r9d, r9d
.cap_next:
    test esi, esi
    jz .caps_done
    cmp esi, 0x40
    jb .bad
    cmp esi, 0xFC
    ja .bad
    test esi, 3
    jnz .bad
    mov eax, esi
    shr eax, 2
    bts r8, rax
    jc .bad
    movzx eax, byte [rsp+rsi+64]
    test eax, eax
    jz .bad
    cmp eax, 0xFF
    je .bad
    xor edx, edx
    cmp eax, 5
    jne .not_msi
    mov edx, 1
.not_msi:
    cmp eax, 0x11
    jne .not_msix
    mov edx, 2
    cmp esi, 0xF4
    ja .bad
.not_msix:
    cmp eax, 0x10
    jne .cap_flags
    mov edx, 4
    cmp esi, 0xF4
    ja .bad
.cap_flags:
    test r9d, edx
    jnz .bad
    or r9d, edx
    movzx esi, byte [rsp+rsi+65]
    jmp .cap_next
.caps_done:
    test r9d, 4
    jz .bad
    mov ebx, [rsp+8]
    mov edi, ebx
    mov esi, 0x10
    call pci_find_cap
    cmp eax, 0x40
    jb .bad
    cmp eax, 0xF4
    ja .bad
    test al, 3
    jnz .bad
    mov ebp, eax
    mov edi, ebx
    lea esi, [rbp+4]
    call pci_bdf_read
    test eax, 1<<28
    jz .bad
    ; Existing common ATS reader: enabled/unavailable/ambiguous refuses.
    mov edi, ebx
    call amdvi_hda_ecam_uc
    mov edi, ebx
    call vtd_hda_ats_state
    cmp eax, 1
    ja .bad
    mov rax, [rel hv_linux_ram_bytes]
    test rax, rax
    jz .bad
    test rax, 0x1FFFFF
    jnz .bad
    mov rdx, [rel hv_linux_ram]
    test rdx, rdx
    jz .bad
    test rdx, 0x1FFFFF
    jnz .bad
    mov r8, rdx
    add r8, rax
    jc .bad
    mov r9, [r13]
    mov r10d, [r13+8]
    shl r10, 12
    add r10, r9
    cmp r9, r8
    jae .pool_ram_ok
    cmp r10, rdx
    ja .bad
.pool_ram_ok:
    mov r9, r12
    add r9, 4096
    jc .bad
    cmp r12, r8
    jae .root_ram_ok
    cmp r9, rdx
    ja .bad
.root_ram_ok:
    mov [rel nica_ram], rdx
    mov [rel nica_bytes], rax
    mov [rel nica_bdf], ebx
    mov [rel nica_cap], ebp
    mov [rel nica_gen], r15
    lea rdi, [rel nica_nics]
    mov rsi, rsp
    mov ecx, 592/8
    rep movsq
    lea rdi, [rel nica_bar_size]
    xor eax, eax
    mov ecx, (nica_bars_end-nica_bar_size)/8
    rep stosq
    mov byte [rel nica_reset_ok], 0
    mov byte [rel nic_assignment_state], NICA_ARMED ; exact custody before first write
    mov dword [rel nic_assignment_error], 3
    call nica_reset
    test eax, eax
    jz .poison
    call nica_size_bars
    test eax, eax
    jz .poison
    mov dword [rel nic_assignment_error], 4
    mov edi, [rel nica_bdf]
    mov rsi, [rel nica_bytes]
    mov rdx, [rel nica_ram]
    mov rcx, [rel nica_gen]
    call pcia_iommu_attach
    test eax, eax
    jnz .poison
    call nica_domain_ok
    test eax, eax
    jz .poison
    mov dword [rel nic_assignment_error], 5
    xor ebx, ebx
.map:
    lea rax, [rel nica_bar_size]
    mov ecx, [rax+rbx*4]
    test ecx, ecx
    jz .map_next
    lea rax, [rel nica_bar_host]
    mov rdx, [rax+rbx*8]
    lea rax, [rel nica_bar_gpa]
    mov esi, [rax+rbx*4]
    mov rdi, r12
    mov r8, r13
    call hv_slat_map_mmio
    test eax, eax
    jnz .poison
.map_next:
    inc ebx
    cmp ebx, 6
    jb .map
    mov dword [rel nica_addr], 0
    mov word [rel nica_command], 0
    mov byte [rel nic_assignment_state], NICA_LIVE
    mov dword [rel nic_assignment_error], 0
    xor eax, eax
    jmp .out
.poison:
    call nica_poison
.bad:
    mov eax, -1
.out:
    add rsp, 600
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Command is always written with status half zero; no RW1C acknowledgments.
nica_disable:
    push rbx
    mov edi, [rel nica_bdf]
    mov esi, 4
    mov edx, 0x400
    call pci_bdf_write
    mov edi, [rel nica_bdf]
    mov esi, 4
    call pci_bdf_read
    and eax, 0x407
    cmp eax, 0x400
    sete al
    movzx eax, al
    pop rbx
    ret

nica_poison:
    mov byte [rel nic_assignment_state], NICA_POISON
    mov byte [rel nica_reset_ok], 0
    jmp nica_disable                   ; retain BDF/gen/RAM/domain on uncertainty

; Find each standard MSI capability, disable and READ BACK. Capabilities are
; not forwarded to the guest. MSI-X table/PBA BARs may still be normal memory.
nica_interrupts_off:
    push rbx
    mov edi, [rel nica_bdf]
    mov esi, 5
    call pci_find_cap
    test eax, eax
    jz .msix
    mov ebx, eax
    cmp eax, 0x40
    jb .no
    cmp eax, 0xFC
    ja .no
    test al, 3
    jnz .no
    mov edi, [rel nica_bdf]
    mov esi, ebx
    call pci_bdf_read
    and eax, ~(1<<16)
    mov edx, eax
    mov edi, [rel nica_bdf]
    mov esi, ebx
    call pci_bdf_write
    mov edi, [rel nica_bdf]
    mov esi, ebx
    call pci_bdf_read
    test eax, 1<<16
    jnz .no
.msix:
    mov edi, [rel nica_bdf]
    mov esi, 0x11
    call pci_find_cap
    test eax, eax
    jz .yes
    mov ebx, eax
    cmp eax, 0x40
    jb .no
    cmp eax, 0xF4
    ja .no
    test al, 3
    jnz .no
    mov edi, [rel nica_bdf]
    mov esi, ebx
    call pci_bdf_read
    and eax, 0x7FFFFFFF
    or eax, 1<<30
    mov edx, eax
    mov edi, [rel nica_bdf]
    mov esi, ebx
    call pci_bdf_write
    mov edi, [rel nica_bdf]
    mov esi, ebx
    call pci_bdf_read
    and eax, 0xC0000000
    cmp eax, 0x40000000
    jne .no
.yes: mov eax, 1
    pop rbx
    ret
.no: xor eax, eax
    pop rbx
    ret

; FLR is the existing pcia_flr sequence, generalized to this owned snapshot.
; 100ms without any config reads after Initiate, then <=1s ID polling.
nica_reset:
    push rbx
    push r12
    push r13
    call nica_disable
    test eax, eax
    jz .no
    call nica_interrupts_off
    test eax, eax
    jz .no
    mov r13d, [rel nica_cap]
    mov ebx, 100
.tp:
    mov edi, [rel nica_bdf]
    lea esi, [r13+8]
    call pci_bdf_read
    test eax, 1<<21
    jz .initiate
    mov edi, 1000
    call tsc_delay_us
    dec ebx
    jnz .tp
    jmp .no
.initiate:
    and eax, 0xFFFF
    or eax, 0x8000
    mov edx, eax
    mov edi, [rel nica_bdf]
    lea esi, [r13+8]
    call pci_bdf_write
    mov edi, 100000
    call tsc_delay_us
    mov ebx, 1000
.id:
    mov edi, [rel nica_bdf]
    xor esi, esi
    call pci_bdf_read
    cmp eax, [rel nica_nics+64]
    je .restore
    mov edi, 1000
    call tsc_delay_us
    dec ebx
    jnz .id
    jmp .no
.restore:
    mov ebx, 0x0C
.next:
    lea rax, [rel nica_nics+64]
    mov edx, [rax+rbx]
    mov edi, [rel nica_bdf]
    mov esi, ebx
    call pci_bdf_write
    add ebx, 4
    cmp ebx, 0x28
    jb .next
    mov edi, [rel nica_bdf]
    mov esi, 0x3C
    movzx edx, byte [rel nica_nics+64+0x3C]
    call pci_bdf_write
    lea rax, [rel nica_nics+64]
    movzx edx, word [rax+r13+8]
    and edx, 0x7FFF
    mov edi, [rel nica_bdf]
    lea esi, [r13+8]
    call pci_bdf_write
    call nica_verify_bars
    test eax, eax
    jz .no
    mov edi, [rel nica_bdf]
    mov esi, 0x0C
    call pci_bdf_read
    cmp ax, [rel nica_nics+64+0x0C]
    jne .no
    mov edi, [rel nica_bdf]
    mov esi, 0x3C
    call pci_bdf_read
    cmp al, [rel nica_nics+64+0x3C]
    jne .no
    mov edi, [rel nica_bdf]
    lea esi, [r13+8]
    call pci_bdf_read
    and eax, 0x7FFF
    lea rdx, [rel nica_nics+64]
    movzx edx, word [rdx+r13+8]
    and edx, 0x7FFF
    cmp eax, edx
    jne .no
    call nica_interrupts_off
    test eax, eax
    jz .no
    call nica_disable
    test eax, eax
    jz .no
    mov byte [rel nica_reset_ok], 1
    mov eax, 1
    jmp .out
.no: xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

nica_verify_bars:
    push rbx
    mov ebx, 0x10
.next:
    mov edi, [rel nica_bdf]
    mov esi, ebx
    call pci_bdf_read
    lea rdx, [rel nica_nics+64]
    cmp eax, [rdx+rbx]
    jne .no
    add ebx, 4
    cmp ebx, 0x28
    jb .next
    mov eax, 1
    pop rbx
    ret
.no: xor eax, eax
    pop rbx
    ret

; Each BAR has a disjoint aligned 16MiB GPA window. I/O BARs are hidden,
; never forwarded/mapped. A 64-bit memory BAR retains type/prefetch bits and
; its upper slot; host base may be above4GiB, guest GPA is below4GiB.
; Require 4KiB..16MiB power-of-two BAR and whole reserved/MMIO resource leaves
; for every covered 2MiB HPA chunk, using the existing saved-map admission.
nica_size_bars:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    xor ebx, ebx
.next:
    lea rax, [rel nica_nics+64+0x10]
    mov r12d, [rax+rbx*4]
    test r12b, 1
    jnz .advance
    mov eax, r12d
    and eax, 6
    cmp eax, 4
    je .pair
    test eax, eax
    jnz .no
    xor ebp, ebp
    jmp .probe
.pair:
    cmp ebx, 5
    jae .no
    mov ebp, 1
    lea rax, [rel nica_nics+64+0x10]
    mov eax, [rax+rbx*4+4]
    shl rax, 32
    or r12, rax
.probe:
    lea esi, [rbx*4+0x10]
    mov edi, [rel nica_bdf]
    mov edx, -1
    call pci_bdf_write
    test ebp, ebp
    jz .read
    lea esi, [rbx*4+0x14]
    mov edi, [rel nica_bdf]
    mov edx, -1
    call pci_bdf_write
.read:
    lea esi, [rbx*4+0x10]
    mov edi, [rel nica_bdf]
    call pci_bdf_read
    mov r13d, eax
    and r13d, 0xFFFFFFF0
    test ebp, ebp
    jz .restore
    lea esi, [rbx*4+0x14]
    mov edi, [rel nica_bdf]
    call pci_bdf_read
    shl rax, 32
    or r13, rax
    ; Restore high first, then low, with decode already off.
    mov rdx, r12
    shr rdx, 32
    lea esi, [rbx*4+0x14]
    mov edi, [rel nica_bdf]
    call pci_bdf_write
.restore:
    mov edx, r12d
    lea esi, [rbx*4+0x10]
    mov edi, [rel nica_bdf]
    call pci_bdf_write
    test r13, r13
    jz .advance
    test ebp, ebp
    jnz .wide
    neg r13d
    jmp .size
.wide:
    neg r13
.size:
    cmp r13, 4096
    jb .no
    cmp r13, NICA_BAR_WINDOW
    ja .no
    lea rax, [r13-1]
    test r13, rax
    jnz .no
    mov r14, r12
    and r14, -16
    test r14, r14
    jz .no
    test r14, rax
    jnz .no
    ; The shared saved-map resource reader supports the low16GiB identity map.
    mov rax, r14
    add rax, r13
    jc .no
    mov rdx, 0x400000000
    cmp rax, rdx
    ja .no
    mov r12, r14
    and r12, -0x200000
.resource:
    mov rdi, r12
    call pci_mmio_resource_page
    test eax, eax
    jz .no
    add r12, 0x200000
    lea rax, [r14+r13]
    cmp r12, rax
    jb .resource
    lea rax, [rel nica_bar_size]
    mov [rax+rbx*4], r13d
    lea rax, [rel nica_bar_host]
    mov [rax+rbx*8], r14
    mov eax, ebx
    shl eax, 24
    add eax, NICA_BAR_GPA
    lea rdx, [rel nica_bar_gpa]
    mov [rdx+rbx*4], eax
    test ebp, ebp
    jz .advance
    lea rax, [rel nica_bar_upper]
    mov byte [rax+rbx+1], 1
    inc ebx
.advance:
    inc ebx
    cmp ebx, 6
    jb .next
    call nica_verify_bars
    test eax, eax
    jz .out
    lea rdx, [rel nica_bar_size]
    xor eax, eax
    mov ecx, 6
.any_memory:
    or eax, [rdx]
    add rdx, 4
    loop .any_memory
    test eax, eax
    setnz al
    movzx eax, al
    jmp .out
.no: xor eax, eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Full original backend receipt, joined to this START/BDF/RAM and interrupt
; policy. A count/ready bit alone never proves a domain. No caller writes it.
nica_domain_ok:
    sub rsp, 72
    mov rdi, rsp
    call pcia_iommu_receipt
    cmp eax, 1
    jne .bad_domain
    cmp qword [rsp], 1
    jne .bad_domain
    mov rax, [rsp+8]
    cmp rax, [rel nica_gen]
    jne .bad_domain
    mov eax, [rel nica_bdf]
    cmp [rsp+16], rax
    jne .bad_domain
    cmp qword [rsp+40], 1              ; Intel IR policy / AMD IntCtl=abort,QW2=1
    jne .bad_domain
    mov rax, [rel nica_bytes]
    shr rax, 21
    cmp [rsp+48], rax
    jne .bad_domain
    cmp qword [rsp+56], 0
    jne .bad_domain
    mov rax, [rel hv_linux_ram]
    cmp rax, [rel nica_ram]
    jne .bad_domain
    mov rax, [rel hv_linux_ram_bytes]
    cmp rax, [rel nica_bytes]
    jne .bad_domain
    mov eax, [rel hv_linux_start_consumed]
    cmp rax, [rel nica_gen]
    jne .bad_domain
    mov rsi, rsp
    lea rdi, [rel nica_receipt_cache]
    mov ecx, 8
    cld
    rep movsq
    mov eax, 1
    jmp .out
.bad_domain: xor eax, eax
.out: add rsp, 72
    ret

nic_assignment_receipt:
    push r12
    mov r12, rdi
    xor eax, eax
    mov ecx, 8
    cld
    rep stosq
    cmp byte [rel nic_assignment_state], NICA_LIVE
    jne .out
    call nica_domain_ok
    test eax, eax
    jz .poison_receipt
    mov rdi, r12
    lea rsi, [rel nica_receipt_cache]
    mov ecx, 8
    rep movsq
    mov eax, 1
    jmp .out
.poison_receipt:
    call nica_poison
    xor eax, eax
.out: pop r12
    ret

nic_assignment_release:
    push rbx
    mov ebx, edi
    cmp byte [rel nic_assignment_state], NICA_LIVE
    jne .bad_release
    cmp edi, [rel nica_bdf]
    jne .bad_release
    cmp rsi, [rel nica_gen]
    jne .bad_release
    call nica_cpu_off
    test eax, eax
    jz .bad_release
    call nica_domain_ok
    test eax, eax
    jz .poison
    mov byte [rel nic_assignment_state], NICA_RELEASING
    mov byte [rel nica_reset_ok], 0
    call nica_reset                    ; reset/restore while original DMA domain still holds NIC
    test eax, eax
    jz .poison
    mov edi, ebx
    mov rsi, [rel nica_gen]
    call pcia_iommu_detach
    test eax, eax
    jnz .poison
    sub rsp, 64
    mov rdi, rsp
    call pcia_iommu_receipt
    test eax, eax
    jnz .retire_failed
    cmp qword [rsp], 2
    jne .retire_failed
    mov rax, [rel nica_gen]
    cmp [rsp+8], rax
    jne .retire_failed
    mov eax, ebx
    cmp [rsp+16], rax
    jne .retire_failed
    cmp qword [rsp+48], 0
    jne .retire_failed
    cmp qword [rsp+56], 0
    jne .retire_failed
    add rsp, 64
    mov byte [rel nic_assignment_state], NICA_IDLE
    mov byte [rel nica_reset_ok], 0
    xor eax, eax
    pop rbx
    ret
.retire_failed:
    add rsp, 64
.poison:
    call nica_poison
.bad_release:
    mov eax, -1
    pop rbx
    ret

nic_assignment_irq:
    push rbx
    xor eax, eax
    cmp byte [rel nic_assignment_state], NICA_LIVE
    jne .out
    test word [rel nica_command], 0x400
    jnz .out
    call nica_domain_ok
    test eax, eax
    jz .poison
    mov edi, [rel nica_bdf]
    mov esi, 4
    call pci_bdf_read
    test eax, 0x400
    jz .poison
    test eax, 1<<19                   ; PCI Status.Interrupt, works while INTx disabled
    jz .none
    mov edi, NICA_IRQ
    call hv_pic_try_inject
    jmp .out
.none: xor eax, eax
    jmp .out
.poison:
    call nica_poison
    xor eax, eax
.out: pop rbx
    ret

; Existing pcia config encoder/access bounds, private NIC shadow/storage.
nica_target:
    mov  eax, [rel nica_addr]
    test eax, 0x80000000
    jz   .bad
    test eax, 0x7F000000                 ; reserved / AMD extended-register bits: never alias 0-0xFF
    jnz  .bad
    test eax, 0x00FF0700                 ; bus 0, function 0 only
    jnz  .bad
    mov  ecx, eax
    shr  ecx, 11
    and  ecx, 0x1F
    cmp  ecx, 1
    ja   .bad
    and  eax, 0xFC
    lea  eax, [rax + rdx - 0xCFC]
    test ecx, ecx
    jnz  .out
    or   eax, 0x100                      ; host bridge
.out:
    ret
.bad:
    mov  eax, -1
    ret

; ESI=dword-aligned offset (< 0x100) -> EAX=guest-visible dword.
nica_cfg_dword:
    cmp  esi, 0x04
    je   .cmd
    cmp  esi, 0x0C
    je   .hdr
    cmp  esi, 0x10
    jb   .real
    cmp  esi, 0x24
    jbe  .bar
    cmp  esi, 0x2C
    je   .real
    cmp  esi, 0x3C
    je   .irq
    jmp .zero
.real:
    lea  rdi, [rel nica_nics+64]
    mov  eax, [rdi + rsi]
    ret
.cmd:
    mov  eax, [rel nica_nics+64+4]
    and  eax, 0xFFEF0000                 ; real status, capability list hidden
    movzx edi, word [rel nica_command]
    or   eax, edi
    ret
.hdr:
    movzx eax, word [rel nica_nics+64+0x0C]
    ret
.irq:
    mov  eax, (1 << 8) | NICA_IRQ
    ret
.bar:
    mov edi, esi
    sub edi, 0x10
    shr edi, 2
    lea rax, [rel nica_bar_probe]
    movzx ecx, byte [rax+rdi]
    mov byte [rax+rdi], 0
    lea rax, [rel nica_bar_upper]
    cmp byte [rax+rdi], 1
    je .upper
    lea rax, [rel nica_bar_size]
    mov eax, [rax+rdi*4]
    test eax, eax
    jz .zero
    test ecx, ecx
    jz .value
    neg eax
    jmp .attrs
.value:
    lea rax, [rel nica_bar_gpa]
    mov eax, [rax+rdi*4]
.attrs:
    lea rdx, [rel nica_nics+64+0x10]
    mov edx, [rdx+rdi*4]
    and edx, 0xF
    or eax, edx
    ret
.upper:
    xor eax, eax
    test ecx, ecx
    jz .upper_out
    dec eax
.upper_out: ret
.zero:
    xor  eax, eax
    ret

nic_assignment_vpci_in:
    cmp  edx, 0xCF8
    jne  .data
    mov  ecx, [rel nica_addr]
    ret
.data:
    cmp byte [rel nic_assignment_state], NICA_LIVE
    jne .ones
    cmp  edx, 0xCFC
    jb   .ones
    cmp  edx, 0xCFF
    ja   .ones
    call nica_target
    test eax, eax
    js   .ones
    mov  ecx, eax
    and  ecx, 3
    shl  ecx, 3                          ; byte lane shift
    mov  esi, eax
    and  esi, 0xFC
    test eax, 0x100
    jnz  .bridge
    push rcx
    call nica_cfg_dword
    pop  rcx
    shr  eax, cl
    mov  ecx, eax
    ret
.bridge:
    xor  eax, eax
    test esi, esi
    jnz  .bridge_class
    mov  eax, 0x71908086                 ; hv/vtd's proven synthetic host bridge
    jmp  .bridge_out
.bridge_class:
    cmp  esi, 0x08
    jne  .bridge_out
    mov  eax, 0x06000000
.bridge_out:
    shr  eax, cl
    mov  ecx, eax
    ret
.ones:
    mov  ecx, 0xFFFFFFFF
    ret

nic_assignment_vpci_out:
    cmp byte [rel nic_assignment_state], NICA_LIVE
    jne .done
    cmp  edx, 0xCF8
    jne  .data
    mov  eax, [rel hv_linux_gpr]
    mov  [rel nica_addr], eax
    ret
.data:
    cmp  edx, 0xCFC
    jb   .done
    cmp  edx, 0xCFF
    ja   .done
    test r8d, 0x10
    jnz  .refused                        ; string OUTS: data is guest memory
    mov  r9d, r8d
    and  r9d, 7                          ; size - 1
    cmp  r9d, 2
    je   .refused
    cmp  r9d, 3
    ja   .refused
    call nica_target
    test eax, eax
    js   .done
    test eax, 0x100
    jnz  .done                           ; host bridge: read-only
    mov  ecx, eax
    and  ecx, 3
    add  ecx, r9d
    cmp  ecx, 3
    ja   .refused                        ; crosses its dword
    mov  esi, eax                        ; byte offset
    mov  ecx, [rel hv_linux_gpr]         ; value, low bytes significant
    cmp  esi, 0x40
    jae  .ignored
    cmp  esi, 0x10
    jb   .low
    cmp  esi, 0x27
    jbe  .bar
    jmp  .ignored                        ; 0x28..0x3F: fixed
.low:
    cmp  esi, 0x04
    jb   .ignored
    cmp  esi, 0x06
    jb   .cmd
    cmp  esi, 0x0C
    jb   .ignored                        ; status (RW1C) and class: fixed
    cmp  esi, 0x0E
    jb   .ignored                        ; cacheline / latency fixed
    jmp  .ignored
.cmd:
    ; Merge exactly the bytes written into the 16-bit command shadow.
    movzx eax, word [rel nica_command]
    cmp  esi, 0x05
    je   .cmd_hi
    cmp  r9d, 0
    je   .cmd_lo
    mov  ax, cx                          ; word or dword at 0x04
    jmp  .cmd_store
.cmd_lo:
    mov  al, cl
    jmp  .cmd_store
.cmd_hi:
    mov  ah, cl
.cmd_store:
    and eax, NICA_CMD_MASK
    mov [rel nica_command], ax
    jmp nica_forward_command

.bar:
    test esi, 3
    jnz  .refused
    cmp  r9d, 3
    jne  .refused                        ; BAR programming is dword-only
    mov  edi, esi
    sub  edi, 0x10
    shr  edi, 2
    cmp  ecx, 0xFFFFFFFF
    jne  .bar_value
    lea  rax, [rel nica_bar_probe]
    mov  byte [rax + rdi], 1
    ret
.bar_value:
    inc  dword [rel nica_bar_writes]
    lea  rax, [rel nica_bar_size]
    cmp  dword [rax + rdi*4], 0
    je   .bar_unused
    lea  rax, [rel nica_bar_gpa]
    mov  edx, ecx
    and  edx, 0xFFFFFFF0
    cmp  edx, [rax + rdi*4]
    je   .done                           ; restoring the presented address
    jmp  .bar_foreign
.bar_unused:
    test ecx, ecx
    jz   .done
.bar_foreign:
    inc  dword [rel nica_bar_foreign]    ; never moves the SLAT
    mov  [rel nica_bar_last], ecx
    ret
.ignored:
    inc  dword [rel nica_fixed_writes]
    ret
.refused:
    inc  dword [rel nica_refused_writes]
.done:
    ret


nica_forward_command:
    push rbx
    movzx ebx, word [rel nica_command]
    call nica_domain_ok
    test eax, eax
    jz .cmd_fail
    cmp byte [rel nic_assignment_state], NICA_LIVE
    jne .cmd_fail
    and ebx, 6
    or ebx, 0x400
    mov edx, ebx
    mov edi, [rel nica_bdf]
    mov esi, 4
    call pci_bdf_write
    mov edi, [rel nica_bdf]
    mov esi, 4
    call pci_bdf_read
    and eax, 0x407
    cmp eax, ebx
    jne .cmd_fail
    pop rbx
    ret
.cmd_fail:
    call nica_poison
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_hv_nic_assignment 0
alignb 8
nica_receipt_cache: resq 8
nica_gen: resq 1
nica_ram: resq 1
nica_bytes: resq 1
nica_nics: resb 592
nica_bdf: resd 1
nica_cap: resd 1
nic_assignment_error: resd 1
nica_addr: resd 1
nica_command: resw 1
nic_assignment_state: resb 1
nica_reset_ok: resb 1
alignb 8
nica_bar_size: resd 6
nica_bar_gpa: resd 6
nica_bar_host: resq 6
nica_bar_upper: resb 6
nica_bar_probe: resb 6
alignb 8
nica_bars_end:
nica_cmd_writes: resd 1
nica_bar_writes: resd 1
nica_bar_foreign: resd 1
nica_bar_last: resd 1
nica_fixed_writes: resd 1
nica_refused_writes: resd 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_nic_assignment
