;; MODULE hv/nic_assignment
;; LAYER 5
;; EXPORTS nica_grp_release, nica_grp_backend_detach_admit, nica_grp_quiesce, nica_grp_reset, nica_grp_backend_admit, nic_assignment_attach, nic_assignment_attach_wifi, nic_assignment_release, nic_assignment_receipt, nic_assignment_owned, nic_assignment_admit, nic_assignment_irq, nic_assignment_vpci_in, nic_assignment_vpci_out, nic_assignment_state, nic_assignment_error, nic_assignment_reset_observation, nic_assignment_link_observation, nic_assignment_retention_observation, nic_assignment_isolation_admit, nic_assignment_admission_observation, nic_assignment_admission_info
;; IMPORTS hv/vmx, hv/svm, hv/nic_selection, hv/pci_assign, hv/slat_mmio, hv/hv_ops, hv/amdvi_hda, hv/vtd, hv/amdvi, bus/pci_bdf, bus/acpi, boot/gop, core/time
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
; Release also retires this START's own failed attach (ROOT 107753, AV 107781):
; refused before custody holds nothing; poisoned by attach itself, one unwind
; re-resets and detaches a valid domain live for this START, or proves none by
; backend state and generation. Any other poison stays poison.
; Receipt(RDI out64) ->1live/0, copied original backend shape only after join.
; Owned() ->1 while armed/live/releasing/poison; poisoned ownership never reset,
; except the one unwind of the attach's own failure, which Release performs.
; Admit(EDI BDF, RSI START) ->1 only armed+reset for Intel's narrow class gate.
; Config ABI matches hv_vpci_*; IRQ polls real PCI Status.Interrupt, never Ready.
; Physical INTx/MSI/MSIX remain disabled. Guest sees fixed memory BARs only,
; one synthetic bridge + 00:01.0, no capability list. All six physical BARs
; (including I/O/64-bit upper halves) restored and read back after reset.
; Ethernet may use sole-function direct-root-bridge SBR when FLR is absent.
; An unproven reset domain, INTx, memory or resource proof still refuses.
; SEC117470 permits a selected firmware-unclaimed Ethernet endpoint's first
; attach this boot after marker-only SBR refusal and complete isolated restore.
; Its reset_ok remains zero; strict release/restart refusal is unchanged.
; No native driver unbind or compatibility-domain restoration is attempted.
NICA_IDLE equ 0
NICA_ARMED equ 1
NICA_LIVE equ 2
NICA_RELEASING equ 3
NICA_POISON equ 4
NICA_ARMED_UNPROVEN equ 5
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
    cmp byte [rel nica_unproven_latch], 0 ; boot-lifetime, both leaf entries
    jne .bad
    mov byte [rel nica_first_eligible], 0
    cmp qword [rel nica_gen], 0
    jne .previous
    cmp dword [rel nica_reset_attempt], 0
    jne .previous
    mov byte [rel nica_first_eligible], 1
.previous:
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
    cmp byte [rsp+22], 1               ; capability observation, not reset proof
    ja .bad
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
    cmp eax, -1
    je .bad                           ; unavailable capability is not FLR support
    shr eax, 28
    and eax, 1
    cmp al, [rsp+22]                   ; independent live capability must match
    jne .bad
    mov dword [rel nica_method], 1
    test eax, eax
    jnz .reset_selected
    cmp dword [rsp+592], 0x020000       ; WiFi entry remains FLR-only
    jne .bad
    mov edi, ebx
    call nica_sbr_bridge               ; complete group AND sole reset-domain proof
    test eax, eax
    jz .bad                           ; preflight is inert: no custody/device writes
    mov dword [rel nica_method], 2
.reset_selected:
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
    ; Freeze the original result before any later unwind replaces last-reset.
    push rax
    call nica_admission_capture
    pop rax
    test eax, eax
    jnz .reset_proven
    call nica_unproven_classify          ; fresh COMMAND is the first config access
    test eax, eax
    jz .marker_refused
    mov byte [rel nica_admission_kind], 2
    call nica_unproven_restore
    test eax, eax
    jz .preparation_failed
    mov dword [rel nica_admission_prepared], 1
    mov byte [rel nica_unproven_latch], 1
    mov byte [rel nic_assignment_state], NICA_ARMED_UNPROVEN
    jmp .prepared
.reset_proven:
    mov byte [rel nica_admission_kind], 1
    mov dword [rel nica_admission_prepared], 1
.prepared:
    mov dword [rel nic_assignment_error], 6 ; BAR admission (3 stays reset)
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
    jnz .poison_domain
    call nica_domain_ok
    test eax, eax
    jz .poison_domain
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
    jnz .poison_domain
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
.preparation_failed:
    mov dword [rel nica_admission_prepared], 2
    mov dword [rel nica_admission_failure], 10
    jmp .poison
.marker_refused:
    ; Positive original refusal provenance, before any BAR/domain exposure.
    ; Only an unsupported platform exclusion of the first-attach grant qualifies;
    ; preparation, config/readback and later BAR/domain failures never do.
    cmp byte [rel nica_admission_first_custody], 1
    jne .poison
    cmp dword [rel nica_method], 2
    jne .poison
    cmp dword [rel nica_admission_result], 0
    jne .poison
    cmp dword [rel nica_admission_phase], 9
    jne .poison
    mov eax, [rel nica_admission_command]
    cmp eax, -1
    je .poison
    and eax, 0x407
    cmp eax, 0x400                      ; original marker-only reset refusal
    jne .poison
    mov eax, [rel nica_nics+24]
    dec eax
    cmp eax, 1                         ; Intel1 / AMD2 now share the grant
    jbe .poison                        ; another grant premise failed, not exclusion
.capture_refusal:
    mov byte [rel nica_admission_pre_domain_refusal], 1
    jmp .poison
.poison_domain:
    call nica_poison
    mov byte [rel nica_attach_failed], 2 ; failed at/after the domain attach: a domain may exist
    jmp .bad
.poison:
    call nica_poison
    mov byte [rel nica_attach_failed], 1 ; failed before any domain attach (reset/BAR admission)
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

; First-attach v1, SEC109453 A1-A8. All authority below is private state;
; NAA1 is a passive renderer only. The common reset/release/unwinds stay strict.
nica_admission_capture:
    mov rax, [rel nica_gen]
    mov [rel nica_admission_start], rax
    mov eax, [rel nica_bdf]
    mov [rel nica_admission_bdf], eax
    mov eax, [rel nica_reset_record+56]
    mov [rel nica_admission_attempt], eax
    mov eax, [rel nica_reset_record+12]
    mov [rel nica_admission_result], eax
    mov eax, [rel nica_reset_record+60]
    mov [rel nica_admission_phase], eax
    mov eax, [rel nica_reset_record+52]
    mov [rel nica_admission_command], eax
    ; Freeze at actual custody, never from a later attach entry or NAA1 copy.
    ; The tuple and these premises survive release's consumable failure flag
    ; and last-reset replacement. VM still owes its complete fresh predicate.
    mov byte [rel nica_admission_first_custody], 0
    mov byte [rel nica_admission_pre_domain_refusal], 0
    cmp byte [rel nica_first_eligible], 1
    jne .captured
    cmp dword [rel nica_nics+48], 0 ; no earlier native claim, including FAILED
    jne .captured
    mov byte [rel nica_admission_first_custody], 1
.captured:
    mov byte [rel nica_admission_kind], 0
    mov dword [rel nica_admission_prepared], 0
    mov dword [rel nica_admission_failure], 0
    ret

; Exact selected endpoint, not a chip allowlist. The complete original NICS
; was freshly joined before custody; both summary fields must match its saved
; config. Read current immutable identity/class/revision again at admission.
nica_unproven_identity:
    sub rsp, 8
    mov eax, [rel nica_nics+64]
    test ax, ax
    jz .no
    cmp ax, 0xFFFF
    je .no
    cmp eax, [rel nica_nics+12]
    jne .no
    mov eax, [rel nica_nics+72]
    cmp eax, [rel nica_nics+16]
    jne .no
    shr eax, 8
    cmp eax, 0x020000
    jne .no
    mov edi, [rel nica_bdf]
    xor esi, esi
    call pci_bdf_read
    cmp eax, [rel nica_nics+64]
    jne .no
    mov edi, [rel nica_bdf]
    mov esi, 8
    call pci_bdf_read
    cmp eax, [rel nica_nics+72]
    jne .no
    mov eax, 1
    jmp .out
.no: xor eax, eax
.out: add rsp, 8
    ret

nica_unproven_classify:
    sub rsp, 8
    cmp byte [rel nica_first_eligible], 1
    jne .no
    mov eax, [rel nica_nics+24]
    dec eax
    cmp eax, 1                         ; locked NICS: Intel1 / AMD2 only
    ja .no
    ; The claim recorder never removes a BDF, even BOUND -> FAILED/released.
    ; nic_select_snapshot checked the complete locked census and dropped flag.
    ; Reject ANY earlier claim, not only a currently bound native owner.
    cmp dword [rel nica_nics+48], 0
    jne .no
    cmp dword [rel nica_method], 2
    jne .no
    cmp byte [rel nica_reset_ok], 0
    jne .no
    cmp dword [rel nica_reset_record+8], 2
    jne .no
    cmp dword [rel nica_reset_record+12], 0
    jne .no
    cmp dword [rel nica_reset_record+60], 9
    jne .no
    mov eax, [rel nica_reset_record+16]
    cmp eax, [rel nica_bdf]
    jne .no
    mov rax, [rel nica_reset_record+24]
    cmp rax, [rel nica_gen]
    jne .no
    mov eax, [rel nica_reset_record+56]
    test eax, eax
    jz .no
    cmp eax, [rel nica_reset_attempt]
    jne .no
    mov eax, [rel nica_reset_record+52]
    cmp eax, -1
    je .no
    and eax, 0x407
    cmp eax, 0x400
    jne .no
    ; A1: do not classify phase9 alone, or read only the saved image.
    mov edi, [rel nica_bdf]
    mov esi, 4
    call pci_bdf_read
    cmp eax, -1
    je .no
    and eax, 0x407
    cmp eax, 0x400                  ; fresh COMMAND must agree
    jne .no
    call nica_unproven_identity
    jmp .out
.no: xor eax, eax
.out: add rsp, 8
    ret

; The strict reset's marker refusal skipped stage10. Complete that exact
; restore here, without entering its success tail or rewriting its record.
nica_unproven_restore:
    push rbx
    push r13
    sub rsp, 8
    mov r13d, [rel nica_cap]
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
    ; FLR must also be clear on readback, not only masked on write.
    test eax, 0x8000
    jnz .no
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
    jmp .out
.no: xor eax, eax
.out: add rsp, 8
    pop r13
    pop rbx
    ret

; Backend join: Ethernet-only private prepared custody after strict Admit=0.
; Exact tuple/private preparation only; NAA1/NDS can never authorize it.
nic_assignment_isolation_admit:
    sub rsp, 8
    cmp byte [rel nic_assignment_state], NICA_ARMED_UNPROVEN
    jne .no
    cmp byte [rel nica_unproven_latch], 1
    jne .no
    cmp byte [rel nica_admission_kind], 2
    jne .no
    cmp byte [rel nica_reset_ok], 0
    jne .no
    cmp edi, [rel nica_bdf]
    jne .no
    cmp rsi, [rel nica_gen]
    jne .no
    cmp rsi, [rel nica_admission_start]
    jne .no
    cmp edi, [rel nica_admission_bdf]
    jne .no
    cmp dword [rel nica_admission_prepared], 1
    jne .no
    cmp dword [rel nica_admission_failure], 0
    jne .no
    cmp dword [rel nica_admission_result], 0
    jne .no
    cmp dword [rel nica_admission_phase], 9
    jne .no
    mov eax, [rel nica_admission_attempt]
    cmp eax, [rel nica_reset_attempt]
    jne .no
    mov eax, [rel nica_admission_command]
    and eax, 0x407
    cmp eax, 0x400
    jne .no
    mov rax, [rel hv_linux_ram]
    cmp rax, [rel nica_ram]
    jne .no
    mov rax, [rel hv_linux_ram_bytes]
    cmp rax, [rel nica_bytes]
    jne .no
    call nica_unproven_identity
    jmp .out
.no: xor eax, eax
.out: add rsp, 8
    ret

; Passive NDINFO2 fields; no PCI access or admission authority.
nic_assignment_admission_info:
    movzx eax, byte [rel nica_admission_kind]
    xor edx, edx
    cmp eax, 1
    sete dl
    movzx ecx, byte [rel nica_unproven_latch]
    ret

; RDI=out64. Passive bounded copy from private original admission, never PCI.
nic_assignment_admission_observation:
    mov dword [rdi], 'NAA1'
    mov dword [rdi+4], (64<<16)|1
    mov rax, [rel nica_admission_start]
    mov [rdi+8], rax
    mov eax, [rel nica_admission_bdf]
    mov [rdi+16], eax
    movzx eax, byte [rel nica_admission_kind]
    mov [rdi+20], eax
    mov eax, [rel nica_admission_attempt]
    mov [rdi+24], eax
    mov eax, [rel nica_admission_result]
    mov [rdi+28], eax
    mov eax, [rel nica_admission_phase]
    mov [rdi+32], eax
    mov eax, [rel nica_admission_command]
    mov [rdi+36], eax
    mov eax, [rel nica_admission_prepared]
    mov [rdi+40], eax
    mov eax, [rel nica_admission_failure]
    mov [rdi+44], eax
    movzx eax, byte [rel nica_unproven_latch]
    mov [rdi+48], eax
    xor eax, eax
    mov [rdi+52], eax
    mov [rdi+56], rax
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

; Fresh read-only SBR admission, supplementary to the unchanged common group
; gate. EDI=selected BDF -> EAX1 only for one direct bus-0 bridge, whose exact
; secondary=subordinate bus contains only that function. Unknown/duplicate/
; nested/shared windows refuse. No caller can shrink an isolation group.
nica_sbr_bridge:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov r12d, edi
    mov r15d, edi
    shr r15d, 8
    test r15d, r15d
    jz .no
    call pcia_group_gate
    test eax, eax
    jnz .no
    xor ebx, ebx
    xor r14d, r14d
.bridge:
    mov edi, ebx
    xor esi, esi
    call pci_bdf_read
    cmp eax, -1
    je .next
    test ax, ax
    jz .no
    cmp ax, -1
    je .no
    mov edi, ebx
    mov esi, 8
    call pci_bdf_read
    cmp eax, -1
    je .no
    shr eax, 16
    cmp eax, 0x0604
    jne .next
    mov edi, ebx
    mov esi, 0x18
    call pci_bdf_read
    cmp eax, -1
    je .no
    mov ecx, eax
    shr ecx, 8
    and ecx, 0xff
    cmp r15d, ecx
    jb .next
    mov edx, eax
    shr edx, 16
    and edx, 0xff
    cmp r15d, edx
    ja .next
    cmp ecx, r15d
    jne .no
    cmp edx, r15d
    jne .no
    test al, al                       ; direct root port primary bus must be zero
    jnz .no
    mov [rsp], eax
    inc r14d
    cmp r14d, 1
    jne .no
    mov r13d, ebx
    mov edi, ebx
    mov esi, 0x0c
    call pci_bdf_read
    cmp eax, -1
    je .no
    shr eax, 16
    and eax, 0x7f
    cmp eax, 1
    jne .no
    mov edi, ebx
    mov esi, 0x3c
    call pci_bdf_read
    cmp eax, -1
    je .no
    test eax, 0x400000                 ; never inherit an asserted reset
    jnz .no
    mov [rsp+4], eax
.next:
    inc ebx
    cmp ebx, 256
    jb .bridge
    cmp r14d, 1
    jne .no
    xor ebx, ebx
.function:
    mov edi, r15d
    shl edi, 8
    or edi, ebx
    mov [rsp+8], edi
    xor esi, esi
    call pci_bdf_read
    cmp [rsp+8], r12d
    je .target
    cmp eax, -1
    jne .no                           ; any other present OR unknown function refuses
    jmp .function_next
.target:
    test ax, ax
    jz .no
    cmp ax, -1
    je .no
.function_next:
    inc ebx
    cmp ebx, 256
    jb .function
    mov [rel nica_bridge], r13d
    mov eax, [rsp]
    mov [rel nica_bridge_buses], eax
    mov eax, [rsp+4]
    mov [rel nica_bridge_control], eax
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Passive original reset record. RDI=out64 native-owned buffer. No refresh,
; group scan, receipt acquisition, PCI access, lifecycle or resource mutation.
; u32 version,size,method,result,BDF,bridge; u64 START; u32 bridge_buses,
; bridge_control_before,actual_assert,actual_clear,Command_before,Command_after,
; attempt,error. Method1 FLR/2 SBR; result1 only after complete restore readback.
; Error1 disable,2 interrupts,3 TP,4 fresh group/reset-domain,5 marker,
; 6 assert,7 clear,8 identity,9 ignored reset,10 restore,11 attempt overflow.
nic_assignment_reset_observation:
    lea rsi, [rel nica_reset_record]
    mov ecx, 8
    cld
    rep movsq
    ret

; R2 (ROOT108305 B; AV108317/108320). Passive NLK1 copy, RDI=out64. No PCI
; access, reset, refresh, custody or lifecycle change.
; NLK1: 'NLK1',u16 1,u16 64; u64 START; u32 attempt,bridge; u16 cap,flags
; (bit0 DLLLA reporting capable, bit1 clock); u32 LNK dword before, after the
; full settle, deassert us, first DLLLA clear us, first DLLLA set after a clear
; us, first LT us, last window sample us (none=-1); u16 window samples,
; all-ones Link Status reads (window plus the before/after reads), worst gap
; us; u8 DLLLA 1->0 transitions; u8 label: 0 not reached,
; 1 transition observed, 2 no transition observed (complete coverage only),
; 3 incomplete, 4 no PCIe capability. Observations only: neither label is a
; reset proof or replaces the COMMAND marker check below.
nic_assignment_link_observation:
    lea rsi, [rel nica_link_record]
    mov ecx, 8
    cld
    rep movsq
    ret

; NLK1 helpers. Config READS of the reset bridge's PCIe Link Control/Status
; dword (cap+0x10) and Link Capabilities only: never a write, refusal, error
; or reset-record change. Times are measured us since the assert write.
NLK_NONE equ 0xffffffff
nica_link_begin:
    push rbx
    mov dword [rel nica_link_record], 'NLK1'
    mov word [rel nica_link_record+4], 1
    mov word [rel nica_link_record+6], 64
    mov rax, [rel nica_reset_record+24]
    mov [rel nica_link_record+8], rax
    mov eax, [rel nica_reset_record+56]
    mov [rel nica_link_record+16], eax
    mov eax, [rel nica_bridge]
    mov [rel nica_link_record+20], eax
    mov dword [rel nica_link_record+40], NLK_NONE
    mov dword [rel nica_link_record+44], NLK_NONE
    mov dword [rel nica_link_record+48], NLK_NONE
    xor ebx, ebx
    cmp qword [rel tsc_khz], 0
    je .clock_done
    or ebx, 2
.clock_done:
    mov edi, [rel nica_bridge]
    mov esi, 0x10
    call pci_find_cap
    cmp eax, 0x40
    jb .nocap
    cmp eax, 0xEC
    ja .nocap
    test al, 3
    jnz .nocap
    mov [rel nica_link_record+24], ax
    mov edi, [rel nica_bridge]
    lea esi, [rax+0x0c]
    call pci_bdf_read
    cmp eax, -1
    je .cap_done
    test eax, 1<<20
    jz .cap_done
    or ebx, 1
.cap_done:
    mov [rel nica_link_record+26], bx
    movzx esi, word [rel nica_link_record+24]
    add esi, 0x10
    mov edi, [rel nica_bridge]
    call pci_bdf_read
    mov [rel nica_link_record+28], eax
    xor ecx, ecx
    cmp eax, -1
    jne .before_valid
    inc word [rel nica_link_record+58]  ; an all-ones boundary read is invalid too
    jmp .prev
.before_valid:
    bt eax, 29
    setc cl
.prev:
    mov [rel nica_link_prev], cl
    pop rbx
    ret
.nocap:
    mov word [rel nica_link_record+24], 0
    mov [rel nica_link_record+26], bx
    mov byte [rel nica_link_record+63], 4
    pop rbx
    ret

; Right after the assert write: the origin of every recorded time.
nica_link_mark:
    sub rsp, 8
    call time_monotonic_now_us
    add rsp, 8
    mov [rel nica_link_t0], rax
    ret

; -> EAX measured us since the assert write, clamped to 0..0xfffffffe.
nica_link_elapsed:
    sub rsp, 8
    call time_monotonic_now_us
    add rsp, 8
    sub rax, [rel nica_link_t0]
    jae .positive
    xor eax, eax
    ret
.positive:
    mov rcx, 0xfffffffe
    cmp rax, rcx
    jbe .out
    mov rax, rcx
.out:
    ret

nica_link_deassert:
    movzx eax, word [rel nica_link_record+24]
    test eax, eax
    jz .out
    sub rsp, 8
    call nica_link_elapsed
    add rsp, 8
    mov [rel nica_link_record+36], eax
.out:
    ret

; EDI=samples, each followed by tsc_delay_us(100). Without a PCIe capability
; the same delays run unsampled.
nica_link_window:
    push rbx
    mov ebx, edi
.loop:
    call nica_link_sample
    mov edi, 100
    call tsc_delay_us
    dec ebx
    jnz .loop
    pop rbx
    ret

nica_link_sample:
    push rbx
    push r12
    push r13
    movzx eax, word [rel nica_link_record+24]
    test eax, eax
    jz .out
    call nica_link_elapsed
    mov r12d, eax
    movzx esi, word [rel nica_link_record+24]
    add esi, 0x10
    mov edi, [rel nica_bridge]
    call pci_bdf_read
    mov ebx, eax
    cmp word [rel nica_link_record+56], 0xffff
    je .counted
    inc word [rel nica_link_record+56]
.counted:
    mov eax, r12d
    sub eax, [rel nica_link_last]
    jae .gap_clamp
    xor eax, eax
.gap_clamp:
    cmp eax, 0xffff
    jbe .gap_max
    mov eax, 0xffff
.gap_max:
    cmp ax, [rel nica_link_record+60]
    jbe .gap_done
    mov [rel nica_link_record+60], ax
.gap_done:
    mov [rel nica_link_last], r12d
    mov [rel nica_link_record+52], r12d
    cmp ebx, -1
    jne .valid
    cmp word [rel nica_link_record+58], 0xffff
    je .out
    inc word [rel nica_link_record+58]
    jmp .out
.valid:
    test ebx, 1<<27
    jz .lt_done
    cmp dword [rel nica_link_record+48], NLK_NONE
    jne .lt_done
    mov [rel nica_link_record+48], r12d
.lt_done:
    test ebx, 1<<29
    jnz .up
    cmp dword [rel nica_link_record+40], NLK_NONE
    jne .down_seen
    mov [rel nica_link_record+40], r12d
.down_seen:
    cmp byte [rel nica_link_prev], 0
    je .down_done
    cmp byte [rel nica_link_record+62], 0xff
    je .down_done
    inc byte [rel nica_link_record+62]
.down_done:
    mov byte [rel nica_link_prev], 0
    jmp .out
.up:
    cmp dword [rel nica_link_record+40], NLK_NONE
    je .up_done
    cmp dword [rel nica_link_record+44], NLK_NONE
    jne .up_done
    mov [rel nica_link_record+44], r12d
.up_done:
    mov byte [rel nica_link_prev], 1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; After the full 120 ms settle: one read, then the label. 'No transition
; observed' needs support, clock, zero invalid reads (window and both boundary
; reads), worst gap <=500 us and samples through deassert+50 ms; anything less
; is incomplete.
nica_link_finish:
    push rbx
    movzx eax, word [rel nica_link_record+24]
    test eax, eax
    jz .out
    lea esi, [rax+0x10]
    mov edi, [rel nica_bridge]
    call pci_bdf_read
    mov [rel nica_link_record+32], eax
    cmp eax, -1
    jne .after_valid
    cmp word [rel nica_link_record+58], 0xffff
    je .after_valid
    inc word [rel nica_link_record+58]  ; an all-ones boundary read is invalid too
.after_valid:
    mov bl, 3
    movzx eax, word [rel nica_link_record+26]
    and eax, 3
    cmp eax, 3
    jne .label
    cmp dword [rel nica_link_record+40], NLK_NONE
    je .none
    cmp dword [rel nica_link_record+44], NLK_NONE
    je .label
    mov bl, 1
    jmp .label
.none:
    cmp word [rel nica_link_record+58], 0
    jne .label
    cmp word [rel nica_link_record+60], 500
    ja .label
    mov eax, [rel nica_link_record+52]
    sub eax, [rel nica_link_record+36]
    jb .label
    cmp eax, 50000
    jb .label
    mov bl, 2
.label:
    mov [rel nica_link_record+63], bl
.out:
    pop rbx
    ret

; R2b (ROOT108718, amended 108722). Passive NRT1 copy, RDI=out64. No PCI
; access, reset, refresh, custody or lifecycle change.
; NRT1: 'NRT1',u16 1,u16 64; u64 START; u32 attempt; u16 sampled, changed,
; invalid item masks; u16 MSI-X Message Control after; u32 x9 after-values:
; items 0..5 BAR0..5, 6 0x0C, 7 0x3C, 8 PCIe cap+8 (item 9 is MSI-X control).
; Baseline: the live QUIESCED values read just before the SBR assert (after
; nica_interrupts_off), never nica_nics+64. Compared bits only (Device Status
; and other volatile halves never count). Kept/changed only: changed is not a
; reset default, all kept means only the sampled config was retained, and no
; field is a reset proof or replaces the step-9 COMMAND marker check.
nic_assignment_retention_observation:
    lea rsi, [rel nica_retention_record]
    mov ecx, 8
    cld
    rep movsq
    ret

; RDI=out10 dwords -> EAX sampled item mask. Config READS of the endpoint only.
nica_retention_sample:
    push rbx
    push r12
    push r13
    mov r12, rdi
    xor ebx, ebx
    xor r13d, r13d
.bar:
    mov edi, [rel nica_bdf]
    lea esi, [rbx*4+0x10]
    call pci_bdf_read
    mov [r12+rbx*4], eax
    bts r13d, ebx
    inc ebx
    cmp ebx, 6
    jb .bar
    mov edi, [rel nica_bdf]
    mov esi, 0x0c
    call pci_bdf_read
    mov [r12+24], eax
    bts r13d, 6
    mov edi, [rel nica_bdf]
    mov esi, 0x3c
    call pci_bdf_read
    mov [r12+28], eax
    bts r13d, 7
    mov eax, [rel nica_cap]
    test eax, eax
    jz .msix
    lea esi, [rax+8]
    mov edi, [rel nica_bdf]
    call pci_bdf_read
    mov [r12+32], eax
    bts r13d, 8
.msix:
    mov edi, [rel nica_bdf]
    mov esi, 0x11
    call pci_find_cap
    cmp eax, 0x40
    jb .done
    cmp eax, 0xfc
    ja .done
    mov esi, eax
    mov edi, [rel nica_bdf]
    call pci_bdf_read
    mov [r12+36], eax
    bts r13d, 9
.done:
    mov eax, r13d
    pop r13
    pop r12
    pop rbx
    ret

; Step 9, after the COMMAND read: the same reads again and the NRT1 record.
; Runs only when this attempt took its quiesced baseline before the assert.
nica_retention_finish:
    cmp byte [rel nica_retention_armed], 0
    je .out
    push rbx
    push r12
    push r13
    push r14
    push rbp
    mov rbp, rsp
    sub rsp, 48
    and rsp, -16
    mov byte [rel nica_retention_armed], 0
    mov rdi, rsp
    call nica_retention_sample
    and eax, [rel nica_retention_pre_mask]
    mov dword [rel nica_retention_record], 'NRT1'
    mov word [rel nica_retention_record+4], 1
    mov word [rel nica_retention_record+6], 64
    mov rcx, [rel nica_reset_record+24]
    mov [rel nica_retention_record+8], rcx
    mov ecx, [rel nica_reset_record+56]
    mov [rel nica_retention_record+16], ecx
    mov [rel nica_retention_record+20], ax
    mov r12d, eax                       ; sampled
    xor r13d, r13d                      ; changed
    xor r14d, r14d                      ; invalid
    xor ebx, ebx
    lea rsi, [rel nica_retention_pre]
    lea rdi, [rel nica_retention_compare]
.item:
    bt r12d, ebx
    jnc .next
    mov eax, [rsp+rbx*4]
    mov edx, [rsi+rbx*4]
    cmp eax, -1
    je .invalid
    cmp edx, -1
    je .invalid
    xor eax, edx
    test eax, [rdi+rbx*4]
    jz .next
    bts r13d, ebx
    jmp .next
.invalid:
    bts r14d, ebx
.next:
    inc ebx
    cmp ebx, 10
    jb .item
    mov [rel nica_retention_record+22], r13w
    mov [rel nica_retention_record+24], r14w
    xor ebx, ebx
    lea rdi, [rel nica_retention_record+28]
.copy:
    bt r12d, ebx
    jnc .copied
    mov eax, [rsp+rbx*4]
    mov [rdi+rbx*4], eax
.copied:
    inc ebx
    cmp ebx, 9
    jb .copy
    bt r12d, 9
    jnc .done
    mov eax, [rsp+36]
    shr eax, 16
    mov [rel nica_retention_record+26], ax
.done:
    mov rsp, rbp
    pop rbp
    pop r14
    pop r13
    pop r12
    pop rbx
.out:
    ret

; Compared bits per item: BARs whole; 0x0C cache line size and latency timer;
; 0x3C interrupt line; cap+8 Device Control only; MSI-X Enable and Function Mask.
nica_retention_compare: dd 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x0000ffff, 0x000000ff, 0x0000ffff, 0xc0000000

; Bounded reset of this exact owned function; never a compatibility owner.
; FLR preserves its >=100ms quiet interval. SBR holds3ms, settles120ms, and
; requires the existing INTx-disable reset marker to clear. Each SBR rescans
; the complete common group AND sole reset domain before any bridge write.
nica_reset:
    push rbx
    push r12
    push r13
    lea rdi, [rel nica_reset_record]
    xor eax, eax
    mov ecx, 8
    cld
    rep stosq
    lea rdi, [rel nica_link_record]    ; R2 NLK1: last attempt wins, as above
    mov ecx, 8
    rep stosq
    lea rdi, [rel nica_retention_record] ; R2b NRT1: last attempt wins
    mov ecx, 8
    rep stosq
    mov [rel nica_retention_armed], al
    mov [rel nica_link_t0], rax
    mov [rel nica_link_last], eax
    mov [rel nica_link_prev], al
    mov dword [rel nica_reset_record], 1
    mov dword [rel nica_reset_record+4], 64
    mov eax, [rel nica_method]
    mov [rel nica_reset_record+8], eax
    mov eax, [rel nica_bdf]
    mov [rel nica_reset_record+16], eax
    mov dword [rel nica_reset_record+20], 0xffff
    mov rax, [rel nica_gen]
    mov [rel nica_reset_record+24], rax
    mov dword [rel nica_reset_record+60], 11
    cmp dword [rel nica_reset_attempt], -1
    je .no
    inc dword [rel nica_reset_attempt]
    mov eax, [rel nica_reset_attempt]
    mov [rel nica_reset_record+56], eax
    mov byte [rel nica_reset_ok], 0
    ; Legacy reset has exactly two methods. Reject future/unknown IDs before
    ; common COMMAND/IRQ writes; they must use their own qualified dispatcher.
    cmp dword [rel nica_method], 1
    je .method_known
    cmp dword [rel nica_method], 2
    je .method_known
    mov dword [rel nica_reset_record+60], 12 ; unsupported method, no device effect
    jmp .no
.method_known:
    mov dword [rel nica_reset_record+60], 1
    call nica_disable
    test eax, eax
    jz .no
    mov dword [rel nica_reset_record+60], 2
    call nica_interrupts_off
    test eax, eax
    jz .no
    mov edi, [rel nica_bdf]
    mov esi, 4
    call pci_bdf_read
    mov [rel nica_reset_record+48], eax
    cmp eax, -1
    je .no
    cmp dword [rel nica_method], 2
    jne .tp_begin
    mov dword [rel nica_reset_record+60], 5
    test eax, 0x400
    jz .no
.tp_begin:
    mov dword [rel nica_reset_record+60], 3
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
    cmp dword [rel nica_method], 2
    je .sbr
    and eax, 0xFFFF
    or eax, 0x8000
    mov edx, eax
    mov edi, [rel nica_bdf]
    lea esi, [r13+8]
    call pci_bdf_write
    mov edi, 100000
    call tsc_delay_us
    jmp .poll_begin
.sbr:
    mov dword [rel nica_reset_record+60], 4
    mov edi, [rel nica_bdf]
    call nica_sbr_bridge
    test eax, eax
    jz .no
    call nica_link_begin                ; R2: reads only
    lea rdi, [rel nica_retention_pre]   ; R2b: quiesced baseline, reads only
    call nica_retention_sample
    mov [rel nica_retention_pre_mask], eax
    mov byte [rel nica_retention_armed], 1
    mov eax, [rel nica_bridge]
    mov [rel nica_reset_record+20], eax
    mov eax, [rel nica_bridge_buses]
    mov [rel nica_reset_record+32], eax
    mov eax, [rel nica_bridge_control]
    mov [rel nica_reset_record+36], eax
    and eax, ~0x04000000               ; never replay Bridge Control W1C status
    or eax, 0x400000
    mov edx, eax
    mov edi, [rel nica_bridge]
    mov esi, 0x3c
    call pci_bdf_write
    call nica_link_mark
    mov edi, 30                        ; 3 ms hold: 30 x (read + 100 us)
    call nica_link_window
    mov edi, [rel nica_bridge]
    mov esi, 0x3c
    call pci_bdf_read
    mov [rel nica_reset_record+40], eax
    and eax, ~0x04000000
    mov edx, [rel nica_bridge_control]
    and edx, ~0x04000000
    or edx, 0x400000
    cmp eax, edx
    setne r12b
    movzx r12d, r12b
    ; Always deassert using the known original control even if assertion
    ; readback was unavailable. Uncertainty is retained; no device admission.
    mov edx, [rel nica_bridge_control]
    and edx, ~0x04000000
    mov edi, [rel nica_bridge]
    mov esi, 0x3c
    call pci_bdf_write
    call nica_link_deassert
    mov edi, 500                       ; 120 ms settle: 50 ms sampled ...
    call nica_link_window
    call nica_link_sample
    mov edi, 70000                     ; ... then the remaining 70 ms
    call tsc_delay_us
    call nica_link_finish
    mov edi, [rel nica_bridge]
    mov esi, 0x3c
    call pci_bdf_read
    mov [rel nica_reset_record+44], eax
    mov dword [rel nica_reset_record+60], 6
    test r12d, r12d
    jnz .no
    mov dword [rel nica_reset_record+60], 7
    and eax, ~0x04000000
    mov edx, [rel nica_bridge_control]
    and edx, ~0x04000000
    cmp eax, edx
    jne .no
.poll_begin:
    mov dword [rel nica_reset_record+60], 8
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
    mov edi, [rel nica_bdf]
    mov esi, 4
    call pci_bdf_read
    mov [rel nica_reset_record+52], eax
    push rax
    sub rsp, 8
    call nica_retention_finish          ; R2b: reads only, after the COMMAND read
    add rsp, 8
    pop rax
    mov dword [rel nica_reset_record+60], 9
    cmp eax, -1
    je .no
    test eax, 7                         ; reset must not have re-enabled DMA/decode
    jnz .no
    cmp dword [rel nica_method], 2
    jne .restore_begin
    test eax, 0x400                     ; unchanged reset-marker security check
    jnz .no
.restore_begin:
    mov dword [rel nica_reset_record+60], 10
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
    mov dword [rel nica_reset_record+12], 1
    mov dword [rel nica_reset_record+60], 0
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
; Require 4KiB..16MiB power-of-two BAR and a non-RAM proof for every covered
; 2MiB HPA chunk: the saved final map's boot-walk overlap rule (MMIO, UC
; reserved or an undescribed gap; never RAM or runtime), VM 106805. SEC
; 106822/106852: each BAR is also routed by every upstream bridge (code 7),
; an RCiEP needs a covering descriptor (never a gap), and no BAR overlaps a
; platform range (code 8). Code 6 is size/map/overlap.
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
    ; V1 (SEC 106822/106852): every upstream bridge routes the whole BAR to
    ; this subtree. EDX returns the bridges proven; 0 is an RCiEP.
    mov dword [rel nic_assignment_error], 7 ; routing (raw; grants nothing)
    mov rdi, r14
    mov rsi, r13
    lea rax, [rel nica_nics+64+0x10]
    mov edx, [rax+rbx*4]
    and edx, 8                          ; original BAR prefetchable bit
    call nica_bar_routed
    test eax, eax
    jz .no
    mov dword [rel nic_assignment_error], 6 ; map/overlap
    mov r12, r14
    and r12, -0x200000
    test edx, edx
    jnz .resource
.covered:
    ; RCiEP: no bridge window proves routing, so never a gap. Each chunk also
    ; needs the unchanged legacy covering reserved/MMIO row.
    mov rdi, r12
    call pci_mmio_resource_page
    test eax, eax
    jz .no
    add r12, 0x200000
    lea rax, [r14+r13]
    cmp r12, rax
    jb .covered
    mov r12, r14
    and r12, -0x200000
.resource:
    mov rdi, r12
    call pci_mmio_nonram_chunk
    test eax, eax
    jz .no
    add r12, 0x200000
    lea rax, [r14+r13]
    cmp r12, rax
    jb .resource
    ; V2: never a platform range, whatever the map says.
    mov dword [rel nic_assignment_error], 8 ; platform exclusion
    mov rdi, r14
    mov rsi, r13
    call nica_bar_clear
    test eax, eax
    jz .no
    mov dword [rel nic_assignment_error], 6
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


; ---- NIC BAR routing and platform exclusion (SEC 106822/106852, VM 106840) ----
; Read-only: config reads only, no pci_bdf_write, no store but the routine's
; own stack frame. Called only from nica_size_bars.
NICA_DA_ROOT equ 0xFF                   ; device_assignment parent sentinel
NICA_DA_BRIDGE equ 1                    ; device_assignment DA_K_BRIDGE
NICA_CHAIN_MAX equ 8                    ; device_assignment DA_CHAIN_MAX
NICA_AF_VALID equ 1                     ; bus/acpi AF_VALID
NICA_VTD_SPAN equ 0x5000                ; VT-d registers: IRO+16 <= 0x4000, FRO+256*16 <= 0x4FF0
NICA_AMDVI_SPAN equ 0x80000             ; amdvi AMDVI_MMIO_BYTES, the safe side of amdvi_mmio_span
NICA_DMAR_SNAP_MAX equ 2*4096           ; = vtd VTD_DMAR_SNAP_PAGES*4096; a larger length refuses

; nica_bar_routed(RDI=host base, RSI=size, EDX=prefetchable) -> EAX 1, EDX =
; bridges proven (0 = RCiEP), or EAX 0. The chain is the attach-rechecked
; NICS group facts (record 0 target, each parent up to DA_ROOT). Every bridge
; is read live: type-1 header, Command.Memory, and the whole BAR inside its
; memory window, or for a prefetchable BAR inside its prefetchable window.
nica_bar_routed:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24                         ; [0] bridge BDF, [8] pref dword, [16] upper base/limit
    mov r12, rdi
    lea r13, [rdi+rsi-1]                ; inclusive end; the caller bounds it below 16GiB
    mov r14d, edx
    xor r15d, r15d
    lea rbx, [rel nica_nics+320]
    movzx ecx, byte [rbx+3]             ; n_dev
    test ecx, ecx
    jz .no
    cmp ecx, 32
    ja .no
    movzx ebp, byte [rbx+4]             ; target record
    cmp ebp, ecx
    jae .no
.hop:
    movzx eax, byte [rbx+16+rbp*8+4]    ; parent index
    cmp eax, NICA_DA_ROOT
    je .yes
    movzx ecx, byte [rbx+3]
    cmp eax, ecx
    jae .no
    inc r15d
    cmp r15d, NICA_CHAIN_MAX
    ja .no
    mov ebp, eax
    cmp word [rbx+16+rbp*8], 0          ; segment 0 only
    jne .no
    cmp byte [rbx+16+rbp*8+5], NICA_DA_BRIDGE
    jne .no
    movzx eax, byte [rbx+16+rbp*8+2]    ; bus
    shl eax, 8
    mov al, [rbx+16+rbp*8+3]            ; devfn
    mov [rsp], eax
    mov edi, eax
    mov esi, 0x0C
    call pci_bdf_read
    shr eax, 16
    and eax, 0x7F
    cmp eax, 1                          ; live type-1 header (absent reads 0x7F)
    jne .no
    mov edi, [rsp]
    mov esi, 0x04
    call pci_bdf_read
    test al, 2                          ; Command.Memory: forwards memory at all
    jz .no
    mov edi, [rsp]
    mov esi, 0x20
    call pci_bdf_read
    mov ecx, eax
    and ecx, 0xFFF0
    shl rcx, 16                         ; memory base
    shr eax, 16
    and eax, 0xFFF0
    shl rax, 16
    or rax, 0xFFFFF                     ; memory limit, inclusive
    cmp r12, rcx
    jb .pref
    cmp r13, rax
    jbe .hop                            ; disabled window (base > limit) fails here
.pref:
    test r14d, r14d                     ; non-prefetchable: memory window only
    jz .no
    mov edi, [rsp]
    mov esi, 0x24
    call pci_bdf_read
    mov [rsp+8], eax
    mov ecx, eax
    and ecx, 0xF                        ; base type
    mov edx, eax
    shr edx, 16
    and edx, 0xF                        ; limit type
    cmp ecx, edx
    jne .no
    cmp ecx, 1                          ; 0 32-bit, 1 64-bit, others reserved
    ja .no
    mov qword [rsp+16], 0
    test ecx, ecx
    jz .pref_window
    mov edi, [rsp]
    mov esi, 0x28
    call pci_bdf_read
    mov [rsp+16], eax                   ; upper base
    mov edi, [rsp]
    mov esi, 0x2C
    call pci_bdf_read
    mov [rsp+20], eax                   ; upper limit
.pref_window:
    mov eax, [rsp+8]
    mov ecx, eax
    and ecx, 0xFFF0
    shl rcx, 16
    mov edx, [rsp+16]
    shl rdx, 32
    or rcx, rdx                         ; prefetchable base
    shr eax, 16
    and eax, 0xFFF0
    shl rax, 16
    or rax, 0xFFFFF
    mov edx, [rsp+20]
    shl rdx, 32
    or rax, rdx                         ; prefetchable limit, inclusive
    cmp r12, rcx
    jb .no
    cmp r13, rax
    ja .no
    jmp .hop
.yes:
    mov eax, 1
    mov edx, r15d
    jmp .out
.no:
    xor eax, eax
    xor edx, edx
.out:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RAX = live IA32_APIC_BASE page. BSP-only module; host suites replace it.
nica_lapic_page:
    mov ecx, 0x1B
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov rdx, 0x000FFFFFFFFFF000
    and rax, rdx
    ret

; [r12, r13) is the BAR; %1 = range start, %2 = exclusive range end.
%macro NICA_EXCLUDE 2
    cmp r12, %2
    jae %%clear
    cmp %1, r13
    jb .no
%%clear:
%endmacro

; nica_bar_clear(RDI=host base, RSI=size) -> EAX 1 when the BAR overlaps no
; platform range, else 0. PaOS's parsed values only; any unavailable source
; refuses. Ranges: [0xFEC00000,4G), the APIC_BASE page, each MADT IOAPIC page,
; the HPET page, every DMAR DRHD / the IVRS unit, each MCFG ECAM window and
; every GOP-reported framebuffer.
nica_bar_clear:
    push rbx
    push r12
    push r13
    mov r12, rdi
    lea r13, [rdi+rsi]                  ; exclusive end; the caller bounds it
    mov rax, 0xFEC00000
    mov rdx, 0x100000000
    NICA_EXCLUDE rax, rdx
    call nica_lapic_page
    test rax, rax
    jz .no
    lea rdx, [rax+0x1000]
    NICA_EXCLUDE rax, rdx
    ; MADT IOAPICs: only a complete parse of a valid MADT.
    cmp byte [rel acpi_table_state], NICA_AF_VALID
    jne .no
    cmp byte [rel acpi_irqmap_complete], 1
    jne .no
    mov ecx, [rel acpi_irqmap_io_count]
    test ecx, ecx
    jz .no
    cmp ecx, 8                          ; IRQMAP_MAX_IOAPICS
    ja .no
    lea rbx, [rel acpi_irqmap_io]
.ioapic:
    mov eax, [rbx]
    test eax, eax
    jz .no
    lea rdx, [rax+0x1000]
    NICA_EXCLUDE rax, rdx
    add rbx, 16
    dec ecx
    jnz .ioapic
    ; HPET: ACPI was parsed; a valid table needs a base; an absent table has none.
    cmp byte [rel acpi_root_state], NICA_AF_VALID
    jne .no
    movzx eax, byte [rel acpi_table_state+3]
    test eax, eax
    jz .hpet_done
    cmp eax, NICA_AF_VALID
    jne .no
    mov rax, [rel acpi_hpet_base]
    test rax, rax
    jz .no
    and rax, -0x1000
    lea rdx, [rax+0x1000]
    NICA_EXCLUDE rax, rdx
.hpet_done:
    ; MCFG: each window is base + start<<20 .. base + (end+1)<<20.
    cmp byte [rel acpi_table_state+1], NICA_AF_VALID
    jne .no
    mov ecx, [rel acpi_mcfg_count]
    test ecx, ecx
    jz .no
    cmp ecx, 4                          ; AF_MAX_MCFG
    ja .no
    lea rbx, [rel acpi_mcfg_entries]
.ecam:
    movzx eax, byte [rbx+10]
    shl rax, 20
    add rax, [rbx]
    movzx edx, byte [rbx+11]
    inc edx
    shl rdx, 20
    add rdx, [rbx]
    NICA_EXCLUDE rax, rdx
    add rbx, 16
    dec ecx
    jnz .ecam
    ; IOMMU units of the selected backend (NICS +24: 1 Intel, 2 AMD).
    mov eax, [rel nica_nics+24]
    cmp eax, 1
    je .intel
    cmp eax, 2
    jne .no
    ; AMD: no IVRS copy is retained. amdvi_mmio is set only after
    ; amdvi_ivrs_parse accepted, and it refuses unless every IVHD names this
    ; one segment-0 unit (.multi/.segment), so this is every AMD unit.
    mov rax, [rel amdvi_mmio]
    test rax, rax
    jz .no
    lea rdx, [rax+NICA_AMDVI_SPAN]
    NICA_EXCLUDE rax, rdx
    jmp .gop
.intel:
    call nica_dmar_units_clear
    test eax, eax
    jz .no
.gop:
    ; Every GOP-reported framebuffer (boot/gop retained copy, never repointed).
    lea rbx, [rel gop_fb_reported]
    mov ecx, 2
.fb:
    mov rax, [rbx]
    test rax, rax
    jz .fb_next
    mov rdx, [rbx+8]
    test rdx, rdx
    jz .no
    add rdx, rax
    jc .no
    NICA_EXCLUDE rax, rdx
.fb_next:
    add rbx, 16
    dec ecx
    jnz .fb
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Within nica_bar_clear (R12/R13 = BAR): walk the retained boot DMAR copy,
; bounded by its own header length, and exclude every DRHD register set:
; max(NICA_VTD_SPAN, 2^Size pages). A missing copy, a length that disagrees
; with the copy, a walk that does not end exactly at it, no DRHD, or a zero or
; unaligned base refuses. EAX 1 clear, 0 refuse.
nica_dmar_units_clear:
    push rbx
    push rbp
    mov ecx, [rel vtd_dmar_snap_len]
    cmp ecx, 48
    jb .no
    cmp ecx, NICA_DMAR_SNAP_MAX
    ja .no
    mov rbx, [rel vtd_dmar_snap]
    test rbx, rbx
    jz .no
    cmp dword [rbx], 'DMAR'
    jne .no
    cmp [rbx+4], ecx
    jne .no
    lea rbp, [rbx+rcx]                  ; exact end
    add rbx, 48
    xor r9d, r9d                        ; DRHDs seen
.struct:
    cmp rbx, rbp
    je .done
    lea rax, [rbx+4]
    cmp rax, rbp
    ja .no
    movzx edx, word [rbx+2]
    cmp edx, 4
    jb .no
    lea rax, [rbx+rdx]
    cmp rax, rbp
    ja .no
    cmp word [rbx], 0                   ; DRHD
    jne .next
    cmp edx, 16
    jb .no
    mov rax, [rbx+8]
    test rax, rax
    jz .no
    test eax, 0xFFF
    jnz .no
    movzx edx, byte [rbx+5]             ; Size: 2^N 4KiB pages (0 where reserved)
    cmp edx, 16
    ja .no
    mov r8d, 0x1000
    mov ecx, edx
    shl r8, cl
    cmp r8, NICA_VTD_SPAN
    jae .span
    mov r8d, NICA_VTD_SPAN
.span:
    lea rdx, [rax+r8]
    inc r9d
    cmp r12, rdx
    jae .next
    cmp rax, r13
    jb .no
.next:
    movzx edx, word [rbx+2]
    add rbx, rdx
    jmp .struct
.done:
    test r9d, r9d
    jz .no
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
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
    jne .not_live
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
.detach:
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
.not_live:
    ; ROOT 107753: a failed attach of this START is retired here, not left held.
    call nica_cpu_off
    test eax, eax
    jz .bad_release
    cmp byte [rel nic_assignment_state], NICA_IDLE
    jne .attach_poison
    ; Refused before custody: this START never armed (nica_gen stays older),
    ; so no device write and no domain. An already released START refuses.
    cmp rsi, [rel nica_gen]
    jbe .bad_release
    mov rdi, rsi
    call nica_domain_free
    test eax, eax
    jz .bad_release
    xor eax, eax
    pop rbx
    ret
.attach_poison:
    cmp byte [rel nic_assignment_state], NICA_POISON
    jne .bad_release
    movzx eax, byte [rel nica_attach_failed]
    test eax, eax
    jz .bad_release                    ; poison after LIVE stays sticky
    cmp edi, [rel nica_bdf]
    jne .bad_release
    cmp rsi, [rel nica_gen]
    jne .bad_release
    ; Eligibility is consumed before any recovery write: a refusal stays poison
    ; and a later release neither resets nor detaches (AV 107781).
    mov byte [rel nica_attach_failed], 0
    cmp eax, 2
    jne .attach_no_domain
    ; Domain phase: a domain live for this START must pass the full original
    ; join (generation, BDF, policy, leaves, faults, consumed START, RAM) and
    ; stays installed through the reset, then the exact detach and receipt.
    sub rsp, 64
    mov rdi, rsp
    call pcia_iommu_receipt
    mov rcx, [rsp]
    add rsp, 64
    cmp rcx, 1
    jne .attach_no_domain
    call nica_domain_ok
    test eax, eax
    jz .poison
    mov byte [rel nic_assignment_state], NICA_RELEASING
    mov byte [rel nica_reset_ok], 0
    call nica_reset                    ; reset/restore while the original domain still holds NIC
    test eax, eax
    jz .poison
    jmp .detach
.attach_no_domain:
    ; No domain for this START: positive proof by the backend's own state and
    ; generation, plus this attach's consumed START and RAM joins.
    mov rdi, [rel nica_gen]
    call nica_domain_free
    test eax, eax
    jz .poison
    call nica_joins_ok
    test eax, eax
    jz .poison
    mov byte [rel nic_assignment_state], NICA_RELEASING
    mov byte [rel nica_reset_ok], 0
    call nica_reset                    ; the same bounded reset and BAR restore as attach
    test eax, eax
    jz .poison
    mov rdi, [rel nica_gen]
    call nica_domain_free              ; unchanged across the reset
    test eax, eax
    jz .poison
    mov byte [rel nic_assignment_state], NICA_IDLE
    mov byte [rel nica_reset_ok], 0
    xor eax, eax
    pop rbx
    ret

; RDI = START generation -> EAX1 only when the IOMMU backend holds no domain of
; it: receipt not live, state unused or retired, generation older than RDI, no
; leaf, no fault. A zero receipt return alone is never proof (AV 107781).
nica_domain_free:
    push rbx
    mov rbx, rdi
    sub rsp, 64
    mov rdi, rsp
    call pcia_iommu_receipt
    test eax, eax
    jnz .busy
    cmp qword [rsp], 0
    je .state_ok
    cmp qword [rsp], 2
    jne .busy
.state_ok:
    cmp [rsp+8], rbx
    jae .busy
    cmp qword [rsp+48], 0
    jne .busy
    cmp qword [rsp+56], 0
    jne .busy
    mov eax, 1
    jmp .out
.busy:
    xor eax, eax
.out:
    add rsp, 64
    pop rbx
    ret

; This attach's consumed START and RAM base/bytes still join (nica_domain_ok's
; non-domain half) -> EAX1/0.
nica_joins_ok:
    xor eax, eax
    mov rdx, [rel hv_linux_ram]
    cmp rdx, [rel nica_ram]
    jne .out
    mov rdx, [rel hv_linux_ram_bytes]
    cmp rdx, [rel nica_bytes]
    jne .out
    mov edx, [rel hv_linux_start_consumed]
    cmp rdx, [rel nica_gen]
    jne .out
    mov eax, 1
.out:
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


; W4c-2 C1 original private primitives, wrapped by the public C4 entries.
; A's original exclusive-claim query must guard the eventual public wrapper;
; a well-shaped common record or this C capture alone is never A authority.
; First/new-START quiesce: RESERVED -> QUIESCED. Reset, outbound and final
; release use their separate original custody producers below.
%include "hv/pcia_grp.inc"
%include "hv/iommu_guest_group_member.inc"

nicag_shape_ok:
 lea rax,[rel pcia_grp]
 cmp rdi,rax
 jne .no
 mov eax,[rel hv_linux_start_consumed]
 test eax,eax
 jz .no
 cmp [rdi+PG_GEN],rax
 jne .no
 jmp nicag_shape_fields
.no: xor eax,eax
 ret

; Original completed C release, independent of the new common record.
; This alone supplies neither current A reservations nor original B proof.
nicag_saved_ok:
 lea rax,[rel nicag_identity]
 cmp rdi,rax
 jne .no
 lea rax,[rel pcia_grp]
 cmp rax,[rel nicag_record]
 jne .no
 cmp byte [rel nicag_state],9
 jne .no
 cmp byte [rel nicag_claims_retired],1
 jne .no
 cmp byte [rel nicag_failed],0
 jne .no
 cmp byte [rel nicag_out_failed],0
 jne .no
 mov rax,[rdi+PG_GEN]
 test rax,rax
 jz .no
 mov edx,[rel hv_linux_start_consumed]
 cmp rax,rdx
 jae .no
 movzx ecx,byte [rdi+PG_COUNT]
 cmp ecx,2
 jb .no
 cmp ecx,PCIA_GRP_MAX
 ja .no
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_quiesced]
 jne .no
 cmp al,[rel nicag_reset_in]
 jne .no
 cmp al,[rel nicag_out_quiesced]
 jne .no
 cmp al,[rel nicag_reset_out]
 jne .no
 jmp nicag_shape_fields
.no: xor eax,eax
 ret

nicag_shape_fields:
 push rbx
 cmp dword [rdi+PG_MAGIC],PCIA_GRP_MAGIC
 jne .no
 movzx ecx,byte [rdi+PG_COUNT]
 cmp ecx,2
 jb .no
 cmp ecx,PCIA_GRP_MAX
 ja .no
 movzx eax,byte [rdi+PG_SEL]
 cmp eax,ecx
 jae .no
 movzx eax,byte [rdi+PG_BACKEND]
 cmp eax,PGB_VTD
 jb .no
 cmp eax,PGB_AMDVI
 ja .no
 cmp word [rdi+PG_SEGMENT],0
 jne .no
 mov rax,[rdi+PG_RAM]
 test rax,rax
 jz .no
 test rax,(2<<20)-1
 jnz .no
 mov rdx,[rdi+PG_BYTES]
 test rdx,rdx
 jz .no
 test rdx,(2<<20)-1
 jnz .no
 mov rcx,1<<32
 cmp rdx,rcx
 ja .no
 add rax,rdx
 jc .no
 mov rcx,1<<47
 cmp rax,rcx
 ja .no
 cmp dword [rdi+PG_ATTEMPT],0
 je .no
 xor ecx,ecx
.members:
 mov eax,ecx
 shl eax,4
 lea r8,[rdi+rax+PG_MEMBERS]
 movzx edx,byte [rdi+PG_COUNT]
 cmp ecx,edx
 jae .unused
 cmp dword [r8+PGM_BK],ecx
 jne .no
 cmp word [r8+PGM_RSVD],0
 jne .no
 cmp word [r8+PGM_CLASS],0x0200
 je .role
 cmp word [r8+PGM_CLASS],0x0280
 jne .no
.role:
 movzx eax,byte [rdi+PG_SEL]
 xor edx,edx
 cmp eax,ecx
 setne dl
 cmp [r8+PGM_ROLE],dl
 jne .no
 test ecx,ecx
 jz .method
 mov ax,[r8+PGM_BDF]
 cmp ax,[r8-PGM_BYTES+PGM_BDF]
 jbe .no
.method:
 cmp byte [r8+PGM_RMETHOD],PGRM_FLR
 je .flr
 cmp byte [r8+PGM_RMETHOD],PGRM_SBR
 jne .no
 cmp word [r8+PGM_RDOMAIN],0xffff
 je .no
 jmp .next
.flr:
 cmp word [r8+PGM_RDOMAIN],0xffff
 jne .no
 jmp .next
.unused:
 cmp qword [r8],0
 jne .no
 cmp qword [r8+8],0
 jne .no
.next:
 inc ecx
 cmp ecx,PCIA_GRP_MAX
 jb .members
 mov eax,1
 jmp .out
.no: xor eax,eax
.out: pop rbx
 ret

nicag_identity_ok:
 push rbx
 cmp byte [rel nicag_state],0
 je .no
 call nicag_shape_ok
 test eax,eax
 jz .out
 cmp rdi,[rel nicag_record]
 jne .no
 lea rbx,[rel nicag_identity]
 mov eax,[rdi]
 cmp [rbx],eax
 jne .no
 mov eax,[rdi+5]
 cmp [rbx+5],eax
 jne .no
 mov rax,[rdi+PG_GEN]
 cmp [rbx+PG_GEN],rax
 jne .no
 mov rax,[rdi+PG_RAM]
 cmp [rbx+PG_RAM],rax
 jne .no
 mov rax,[rdi+PG_BYTES]
 cmp [rbx+PG_BYTES],rax
 jne .no
 mov eax,[rdi+PG_ATTEMPT]
 cmp [rbx+PG_ATTEMPT],eax
 jne .no
 mov ax,[rdi+PG_SEGMENT]
 cmp [rbx+PG_SEGMENT],ax
 jne .no
 xor ecx,ecx
.member:
 mov eax,ecx
 shl eax,4
 lea r8,[rdi+rax+PG_MEMBERS]
 lea r9,[rbx+rax+PG_MEMBERS]
 mov rax,[r8]
 cmp [r9],rax
 jne .no
 mov eax,[r8+PGM_RSVD]
 cmp [r9+PGM_RSVD],eax
 jne .no
 mov eax,[r8+PGM_BK]
 cmp [r9+PGM_BK],eax
 jne .no
 inc ecx
 cmp ecx,PCIA_GRP_MAX
 jb .member
 mov eax,1
 jmp .out
.no: xor eax,eax
.out: pop rbx
 ret


; RDI -> C-private frozen member. Disable COMMAND with Status half ZERO, then
; every MSI/MSI-X in the complete bounded, noncyclic conventional cap chain.
; The subsequent pure member census is a second fresh PCI observation.
nicag_member_off:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov r12,rdi
 movzx ebx,word [r12+PGM_BDF]
 mov edi,ebx
 xor esi,esi
 call pci_bdf_read
 test ax,ax
 jz .no
 cmp ax,0xffff
 je .no
 mov edi,ebx
 mov esi,0x0c
 call pci_bdf_read
 shr eax,16
 test al,0x7f
 jnz .no
 mov edi,ebx
 mov esi,8
 call pci_bdf_read
 shr eax,16
 cmp ax,[r12+PGM_CLASS]
 jne .no
 mov edi,ebx
 call vtd_hda_ats_state
 cmp eax,1
 ja .no
 mov edi,ebx
 mov esi,4
 call pci_bdf_read
 cmp eax,-1
 je .no
 and eax,0xffff
 and eax,~7
 or eax,0x400
 mov edx,eax
 mov edi,ebx
 mov esi,4
 call pci_bdf_write
 mov edi,ebx
 mov esi,4
 call pci_bdf_read
 cmp eax,-1
 je .no
 mov edx,eax
 and edx,0x407
 cmp edx,0x400
 jne .no
 test eax,1<<20
 jz .verify
 mov edi,ebx
 mov esi,0x34
 call pci_bdf_read
 cmp eax,-1
 je .no
 movzx ebp,al
 test ebp,ebp
 jz .no
 xor r13d,r13d
 xor r14d,r14d
.cap:
 test ebp,ebp
 jz .verify
 cmp ebp,0x40
 jb .no
 cmp ebp,0xfc
 ja .no
 test ebp,3
 jnz .no
 inc r14d
 cmp r14d,48
 ja .no
 mov ecx,ebp
 shr ecx,2
 bt r13,rcx
 jc .no
 bts r13,rcx
 mov edi,ebx
 mov esi,ebp
 call pci_bdf_read
 cmp eax,-1
 je .no
 mov r15d,eax
 cmp al,5
 je .msi
 cmp al,0x11
 jne .next
 cmp ebp,0xf4
 ja .no
 and eax,0x7fffffff
 or eax,1<<30
 jmp .write
.msi:
 and eax,~(1<<16)
.write:
 mov edx,eax
 mov edi,ebx
 mov esi,ebp
 call pci_bdf_write
 mov edi,ebx
 mov esi,ebp
 call pci_bdf_read
 cmp eax,-1
 je .no
 ; A changing capability identity/link invalidates the entire walk.
 cmp ax,r15w
 jne .no
 cmp al,5
 jne .msix_read
 test eax,1<<16
 jnz .no
 jmp .next
.msix_read:
 and eax,0xc0000000
 cmp eax,0x40000000
 jne .no
.next:
 mov eax,r15d
 movzx ebp,ah
 jmp .cap
.verify:
 mov rdi,r12
 call iommu_guest_group_member_quiet
 jmp .out
.no:
 xor eax,eax
.out:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Read-only partial census, never an admission gate. Every PRIVATE completed
; bit must still read quiet. Missing bits are checked by the publishing core.
; State3 here is the core's pessimistic in-progress/poison hold, never success.
nicag_completed_quiet:
 push rbx
 push r12
 push r13
 mov r12,rdi
 call nicag_identity_ok
 test eax,eax
 jz .no
 call nica_cpu_off
 test eax,eax
 jz .no
 cmp byte [rel nic_assignment_state],NICA_IDLE
 jne .no
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 not eax
 test al,[rel nicag_quiesced]
 jnz .no
 xor ebx,ebx
.member:
 bt dword [rel nicag_quiesced],ebx
 jnc .next
 mov eax,ebx
 shl eax,4
 lea rdi,[rel nicag_identity+PG_MEMBERS]
 add rdi,rax
 call iommu_guest_group_member_quiet
 test eax,eax
 jz .no
.next:
 inc ebx
 movzx eax,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,eax
 jb .member
 mov eax,1
 jmp .out
.no:
 xor eax,eax
.out:
 pop r13
 pop r12
 pop rbx
 ret

; RDI exact record, EAX0/-1. First-capture quiesce only; no re-arm/retry from
; LIVE/POISON. Original final release + newer A/B custody permits recapture.
; No return of claims or RAM; failure keeps the new complete identity.
nicag_quiesce_core:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov r12,rdi
 cmp byte [rel nicag_state],0
 je .initial
 call nicag_reuse_ok
 cmp eax,1
 jne .no
 mov rdi,r12
.initial:
 call nicag_shape_ok
 test eax,eax
 jz .no
 cmp byte [r12+PG_STATE],PGS_RESERVED
 jne .no
 call nica_cpu_off
 test eax,eax
 jz .no
 cmp byte [rel nic_assignment_state],NICA_IDLE
 jne .no
 mov [rel nicag_record],r12
 lea rdi,[rel nicag_identity]
 mov rsi,r12
 mov ecx,PCIA_GRP_BYTES
 cld
 rep movsb
 mov byte [rel nicag_state],3       ; new capture holds before any effect
 mov byte [rel nicag_quiesced],0
 mov byte [rel nicag_failed],0
 mov byte [rel nicag_reset_in],0
 mov byte [rel nicag_out_quiesced],0
 mov byte [rel nicag_reset_out],0
 mov byte [rel nicag_out_failed],0
 mov byte [rel nicag_claims_retired],0
 mov byte [rel nicag_requiet_done],0
 mov byte [rel nicag_requiet_phase],0
 mov byte [rel nicag_requiet_failed],0
 lea rdi,[rel nicag_config]
 mov ecx,PCIA_GRP_MAX*(256+16)/8 ; config and bridge capture are contiguous
 xor eax,eax
 rep stosq
 xor ebx,ebx
.member:
 mov rdi,r12
 call nicag_completed_quiet
 test eax,eax
 jz .poison
 cmp byte [r12+PG_STATE],PGS_RESERVED
 jne .poison
 mov eax,ebx
 shl eax,4
 lea rdi,[rel nicag_identity+PG_MEMBERS]
 add rdi,rax
 call nicag_member_off
 mov ebp,eax
 ; Neither a successful helper nor diagnostic flags can survive identity,
 ; START, CPU-state or a previous member's interrupt/COMMAND drift.
 mov rdi,r12
 call nicag_completed_quiet
 test eax,eax
 jz .poison
 cmp byte [r12+PG_STATE],PGS_RESERVED
 jne .poison
 test ebp,ebp
 jz .member_bad
 mov ecx,ebx
 mov eax,1
 shl eax,cl
 or [rel nicag_quiesced],al
 mov eax,ebx
 shl eax,4
 or byte [r12+rax+PG_MEMBERS+PGM_FLAGS],PGF_DISABLED
 mov byte [r12+rax+PG_MEMBERS+PGM_IRQ],PGI_INTX_OFF|PGI_MSI_OFF|PGI_MSIX_OFF|PGI_CAPS_READ
 jmp .next
.member_bad:
 mov byte [rel nicag_failed],1
 cmp byte [r12+PG_FAIL_STEP],0
 jne .next
 mov [r12+PG_FAIL_ORD],bl
 mov byte [r12+PG_FAIL_STEP],PGX_QUIESCE
.next:
 inc ebx
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,ecx
 jb .member
 cmp byte [rel nicag_failed],0
 jne .poison
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_quiesced]
 jne .poison
 mov ebx,0xff
 mov rdi,r12
 call nicag_completed_quiet
 test eax,eax
 jz .poison
 cmp byte [r12+PG_STATE],PGS_RESERVED
 jne .poison
 mov byte [rel nicag_state],1
 mov byte [r12+PG_STATE],PGS_QUIESCED
 xor eax,eax
 jmp .out
.poison:
 mov byte [rel nicag_state],3
 mov byte [r12+PG_STATE],PGS_POISON
 cmp byte [r12+PG_FAIL_STEP],0
 jne .no
 mov [r12+PG_FAIL_ORD],bl
 mov byte [r12+PG_FAIL_STEP],PGX_QUIESCE
.no:
 mov eax,-1
.out:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; W4c-2 C2 original inbound FLR producer. C4 consumes actual A reservations.
; The private C capture survives all failures. No implicit SBR authority.
; EAX1 requires current identity, phase and real CPU-off; no PCI writes here.
nicag_reset_safe:
 push rdi
 lea rdi,[rel pcia_grp]
 call nicag_identity_ok
 test eax,eax
 jz .out
 cmp byte [rel nicag_state],2
 je .inbound
 cmp byte [rel nicag_state],7
 jne .no
 cmp byte [rdi+PG_STATE],PGS_RELEASING
 jne .no
 jmp .cpu
.inbound:
 cmp byte [rdi+PG_STATE],PGS_QUIESCED
 jne .no
.cpu:
 cmp byte [rel nic_assignment_state],NICA_IDLE
 jne .no
 call nica_cpu_off
 jmp .out
.no: xor eax,eax
.out: pop rdi
 ret

; A full fresh census before/after each function, not diagnostic IRQ/flags.
nicag_reset_guard:
 push rdi
 call nicag_reset_safe
 test eax,eax
 jz .out
 lea rdi,[rel pcia_grp]
 call nicag_completed_quiet
 test eax,eax
 jz .out
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_quiesced]
 jne .no
 cmp byte [rel nicag_state],7
 jne .yes
 cmp al,[rel nicag_out_quiesced]
 jne .no
.yes:
 mov eax,1
 jmp .out
.no: xor eax,eax
.out: pop rdi
 ret

; RSI -> captured 256-byte type-0 config, EAX PCIe cap or 0. Complete
; conventional chain, unique PCIe, valid extent, FLR support, !TP. The entire
; group is captured/checked before any reset, so an unsupported peer is inert.
nicag_flr_cap:
 push rbx
 push rbp
 push r12
 push r13
 mov r12,rsi
 test dword [r12+4],1<<20
 jz .no
 movzx ebx,byte [r12+0x34]
 test ebx,ebx
 jz .no
 xor ebp,ebp
 xor r13d,r13d
.loop:
 test ebx,ebx
 jz .done
 cmp ebx,0x40
 jb .no
 cmp ebx,0xfc
 ja .no
 test ebx,3
 jnz .no
 mov ecx,ebx
 shr ecx,2
 bts r13,rcx
 jc .no
 mov eax,[r12+rbx]
 cmp eax,-1
 je .no
 test al,al
 jz .no
 cmp al,0xff
 je .no
 cmp al,0x10
 jne .next
 test ebp,ebp
 jnz .no
 cmp ebx,0xf4
 ja .no
 mov ebp,ebx
 mov eax,[r12+rbx+4]
 cmp eax,-1
 je .no
 test eax,1<<28
 jz .no
 mov eax,[r12+rbx+8]
 cmp eax,-1
 je .no
 ; Capability preflight refuses pending work; the fresh bounded poll below
 ; handles transactions which become pending after this observation.
 test eax,(1<<21)|0x8000
 jnz .no
.next:
 movzx ebx,byte [r12+rbx+1]
 jmp .loop
.done:
 mov eax,ebp
 jmp .out
.no: xor eax,eax
.out:
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; EDI ordinal. Requires the captured complete group and quiesce. No common
; success flags are read. Initiate FLR once, wait >=100ms, bounded identity
; poll, restore only the saved non-enabling configuration, and verify it.
nicag_flr_member:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov r15d,edi
 mov eax,edi
 shl eax,4
 lea r14,[rel nicag_identity+PG_MEMBERS]
 add r14,rax
 movzx ebx,word [r14+PGM_BDF]
 mov eax,r15d
 shl eax,8
 lea r12,[rel nicag_config]
 add r12,rax
 mov rsi,r12
 call nicag_flr_cap
 test eax,eax
 jz .no
 mov r13d,eax
 mov ebp,100
.pending:
 call nicag_reset_guard
 test eax,eax
 jz .no
 mov edi,ebx
 mov esi,r13d
 call pci_bdf_read
 cmp eax,[r12+r13]
 jne .no
 mov edi,ebx
 lea esi,[r13+4]
 call pci_bdf_read
 cmp eax,[r12+r13+4]
 jne .no
 mov edi,ebx
 lea esi,[r13+8]
 call pci_bdf_read
 cmp eax,-1
 je .no
 test eax,0x8000
 jnz .no
 movzx edx,word [r12+r13+8]
 cmp ax,dx
 jne .no
 test eax,1<<21
 jz .initiate
 mov edi,1000
 call tsc_delay_us
 dec ebp
 jnz .pending
 jmp .no
.initiate:
 ; Fresh authority after config reads, before the only reset write.
 call nicag_reset_guard
 test eax,eax
 jz .no
 movzx edx,word [r12+r13+8]
 or edx,0x8000                    ; Status upper half stays zero (RW1C)
 mov edi,ebx
 lea esi,[r13+8]
 call pci_bdf_write
 mov edi,100000
 call tsc_delay_us
 call nicag_reset_safe
 test eax,eax
 jz .no
 mov ebp,1000
.identity:
 mov edi,ebx
 xor esi,esi
 call pci_bdf_read
 cmp eax,[r12]
 je .returned
 mov edi,1000
 call tsc_delay_us
 call nicag_reset_safe
 test eax,eax
 jz .no
 dec ebp
 jnz .identity
 jmp .no
.returned:
 mov edi,ebx
 mov esi,8
 call pci_bdf_read
 cmp eax,[r12+8]
 jne .no
 mov edi,ebx
 mov esi,0x0c
 call pci_bdf_read
 cmp eax,-1
 je .no
 shr eax,16
 test al,0x7f
 jnz .no
 mov edi,ebx
 mov esi,r13d
 call pci_bdf_read
 cmp eax,[r12+r13]
 jne .no
 mov edi,ebx
 lea esi,[r13+4]
 call pci_bdf_read
 cmp eax,[r12+r13+4]
 jne .no
 mov edi,ebx
 lea esi,[r13+8]
 call pci_bdf_read
 cmp eax,-1
 je .no
 test eax,(1<<21)|0x8000
 jnz .no
 mov edi,ebx
 mov esi,4
 call pci_bdf_read
 cmp eax,-1
 je .no
 test eax,0x407                  ; FLR must clear the quiesced INTx marker
 jnz .no
 ; Re-establish interrupts/COMMAND quiet before restoring any BAR. An FLR
 ; may have cleared INTx-disable and MSI-X's mask; never restore enables.
 call nicag_reset_safe
 test eax,eax
 jz .no
 mov rdi,r14
 call nicag_member_off
 test eax,eax
 jz .no
 call nicag_reset_guard
 test eax,eax
 jz .no
 mov ebp,0x10
.bars:
 call nicag_reset_guard
 test eax,eax
 jz .no
 mov edx,[r12+rbp]
 mov edi,ebx
 mov esi,ebp
 call pci_bdf_write
 mov edi,ebx
 mov esi,ebp
 call pci_bdf_read
 cmp eax,[r12+rbp]
 jne .no
 add ebp,4
 cmp ebp,0x28
 jb .bars
 call nicag_reset_guard
 test eax,eax
 jz .no
 movzx edx,word [r12+0x0c]        ; preserve type-0 header (RO upper half)
 mov edi,ebx
 mov esi,0x0c
 call pci_bdf_write
 mov edi,ebx
 mov esi,0x0c
 call pci_bdf_read
 cmp ax,[r12+0x0c]
 jne .no
 call nicag_reset_guard
 test eax,eax
 jz .no
 movzx edx,byte [r12+0x3c]
 mov edi,ebx
 mov esi,0x3c
 call pci_bdf_write
 mov edi,ebx
 mov esi,0x3c
 call pci_bdf_read
 cmp al,[r12+0x3c]
 jne .no
 call nicag_reset_guard
 test eax,eax
 jz .no
 movzx edx,word [r12+r13+8]
 and edx,0x7fff
 mov edi,ebx
 lea esi,[r13+8]
 call pci_bdf_write
 mov edi,ebx
 lea esi,[r13+8]
 call pci_bdf_read
 cmp eax,-1
 je .no
 test eax,(1<<21)|0x8000
 jnz .no
 movzx edx,word [r12+r13+8]
 cmp ax,dx
 jne .no
 ; Recheck every saved restore target after the last write too.
 mov ebp,0x10
.verify:
 mov edi,ebx
 mov esi,ebp
 call pci_bdf_read
 cmp eax,[r12+rbp]
 jne .no
 add ebp,4
 cmp ebp,0x28
 jb .verify
 mov edi,ebx
 mov esi,0x0c
 call pci_bdf_read
 cmp ax,[r12+0x0c]
 jne .no
 mov edi,ebx
 mov esi,0x3c
 call pci_bdf_read
 cmp al,[r12+0x3c]
 jne .no
 call nicag_reset_guard
 jmp .out
.no: xor eax,eax
.out:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret


; C9 consumes VM's original root-scope provider. The separate capability
; lands only with that provider; absent means an unconditional refusal.
nicag_scope_provider:
%ifdef PAOS_PCIA_ROOT_SCOPE
 jmp pcia_root_scope
%else
 xor eax,eax
 ret
%endif

; EDI frozen ordinal -> EAX exact affected-member mask, or0. Pure with
; respect to C capture/lifecycle/devices. Provider output is stack-local.
; Require the complete bijection for the secondary bus, never just a subset.
nicag_sbr_scope:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,24
 mov r12d,edi
 lea rdi,[rel pcia_grp]
 call nicag_identity_ok
 test eax,eax
 jz .no
 movzx eax,byte [rel nicag_identity+PG_COUNT]
 cmp r12d,eax
 jae .no
 mov eax,r12d
 shl eax,4
 lea r13,[rel nicag_identity+PG_MEMBERS]
 add r13,rax
 cmp byte [r13+PGM_RMETHOD],PGRM_SBR
 jne .no
 movzx eax,word [r13+PGM_BDF]
 shr eax,8
 test eax,eax
 jz .no
 mov [rsp+16],eax
 lea rdi,[rel pcia_grp]
 call nicag_reservation_ok
 cmp eax,1
 jne .no
 call nica_cpu_off
 test eax,eax
 jz .no
 movzx edi,word [r13+PGM_RDOMAIN]
 mov rsi,rsp
 call nicag_scope_provider
 test eax,eax
 jz .no
 cmp eax,PCIA_GRP_MAX
 ja .no
 mov r15d,eax
 xor ebx,ebx
 xor ebp,ebp
.list:
 movzx r14d,word [rsp+rbx*2]
 mov eax,r14d
 shr eax,8
 cmp eax,[rsp+16]
 jne .no
 xor ecx,ecx
.find:
 mov eax,ecx
 shl eax,4
 lea rdx,[rel nicag_identity+PG_MEMBERS]
 cmp r14w,[rdx+rax+PGM_BDF]
 je .found
 inc ecx
 movzx eax,byte [rel nicag_identity+PG_COUNT]
 cmp ecx,eax
 jb .find
 jmp .no
.found:
 bts ebp,ecx
 jc .no
 inc ebx
 cmp ebx,r15d
 jb .list
 xor ebx,ebx
 xor r14d,r14d
.expected:
 mov eax,ebx
 shl eax,4
 lea rdx,[rel nicag_identity+PG_MEMBERS]
 movzx eax,word [rdx+rax+PGM_BDF]
 shr eax,8
 cmp eax,[rsp+16]
 jne .next
 bts r14d,ebx
.next:
 inc ebx
 movzx eax,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,eax
 jb .expected
 cmp r14d,ebp
 jne .no
 ; Provider and volatile A query cannot alter frozen identity or CPU state.
 lea rdi,[rel pcia_grp]
 call nicag_reservation_ok
 cmp eax,1
 jne .no
 lea rdi,[rel pcia_grp]
 call nicag_identity_ok
 test eax,eax
 jz .no
 call nica_cpu_off
 test eax,eax
 jz .no
 mov eax,ebp
 jmp .out
.no: xor eax,eax
.out:
 add rsp,24
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Capture bridge identity/topology/control once from the actual inbound
; producer, after every method has passed inert admission. Primary may be
; any provider-proven root bus. A bridge already in reset is never inherited.
nicag_sbr_capture:
 push rbx
 push r12
 push r13
 mov r12d,edi
 call nicag_sbr_scope
 test eax,eax
 jz .no
 mov eax,r12d
 shl eax,4
 lea r13,[rel nicag_bridges]
 add r13,rax
 lea rdx,[rel nicag_identity+PG_MEMBERS]
 movzx ebx,word [rdx+rax+PGM_RDOMAIN]
 mov edi,ebx
 xor esi,esi
 call pci_bdf_read
 cmp eax,-1
 je .no
 test ax,ax
 jz .no
 cmp ax,-1
 je .no
 mov [r13],eax
 mov edi,ebx
 mov esi,8
 call pci_bdf_read
 shr eax,16
 cmp eax,0x0604
 jne .no
 mov edi,ebx
 mov esi,0x0c
 call pci_bdf_read
 shr eax,16
 and eax,0x7f
 cmp eax,1
 jne .no
 mov edi,ebx
 mov esi,0x18
 call pci_bdf_read
 cmp eax,-1
 je .no
 mov [r13+4],eax
 mov edx,ebx
 shr edx,8
 cmp al,dl
 jne .no
 mov edx,r12d
 shl edx,4
 lea rcx,[rel nicag_identity+PG_MEMBERS]
 movzx edx,word [rcx+rdx+PGM_BDF]
 shr edx,8
 shr eax,8
 cmp al,dl
 jne .no
 shr eax,8
 cmp al,dl
 jne .no
 mov edi,ebx
 mov esi,0x3c
 call pci_bdf_read
 cmp eax,-1
 je .no
 test eax,1<<22
 jnz .no
 mov [r13+8],eax
 mov edi,r12d
 call nicag_sbr_scope
 test eax,eax
 setnz al
 movzx eax,al
 jmp .out
.no: xor eax,eax
.out:
 pop r13
 pop r12
 pop rbx
 ret

; Fresh provider scope plus exact original bridge identity, bus window and
; deasserted control. EAX affected mask/0; read-only, including refusal.
nicag_sbr_bridge_ok:
 push rbx
 push rbp
 push r12
 push r13
 sub rsp,8
 mov r12d,edi
 call nicag_sbr_scope
 test eax,eax
 jz .no
 mov ebp,eax
 mov eax,r12d
 shl eax,4
 lea r13,[rel nicag_bridges]
 add r13,rax
 lea rdx,[rel nicag_identity+PG_MEMBERS]
 movzx ebx,word [rdx+rax+PGM_RDOMAIN]
 mov edi,ebx
 xor esi,esi
 call pci_bdf_read
 cmp eax,[r13]
 jne .no
 mov edi,ebx
 mov esi,0x18
 call pci_bdf_read
 cmp eax,[r13+4]
 jne .no
 mov edi,ebx
 mov esi,0x3c
 call pci_bdf_read
 cmp eax,-1
 je .no
 xor eax,[r13+8]
 test eax,~0x04000000
 jnz .no
 mov edi,r12d
 call nicag_sbr_scope
 cmp eax,ebp
 jne .no
 mov eax,ebp
 jmp .out
.no: xor eax,eax
.out:
 add rsp,8
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; EDI ordinal, RSI original config -> appropriate PCIe parser. Only FLR
; requires DevCap FLR. SBR still requires a complete unique quiet PCIe cap.
nicag_member_cap:
 mov eax,edi
 shl eax,4
 lea rdx,[rel nicag_identity+PG_MEMBERS]
 cmp byte [rdx+rax+PGM_RMETHOD],PGRM_FLR
 je nicag_flr_cap
 jmp nicag_pcie_cap

; EDI ordinal, ESI invocation-local completed-domain mask -> EAX newly
; verified completion mask, or0. The caller starts this mask at0 on its own
; stack for each direction. No common flags, inbound/outbound masks or old
; START can suppress a physical reset. FLR remains independently per-member.
nicag_reset_member:
 push rbx
 push rbp
 push r12
 push r13
 sub rsp,8
 mov r12d,edi
 mov ebp,esi
 mov eax,edi
 shl eax,4
 lea rdx,[rel nicag_identity+PG_MEMBERS]
 cmp byte [rdx+rax+PGM_RMETHOD],PGRM_FLR
 jne .sbr
 call nicag_flr_member
 test eax,eax
 jz .no
 mov ecx,r12d
 mov eax,1
 shl eax,cl
 jmp .out
.sbr:
 cmp byte [rdx+rax+PGM_RMETHOD],PGRM_SBR
 jne .no
 movzx r13d,word [rdx+rax+PGM_RDOMAIN]
 bt ebp,r12d
 jc .completed
 call nicag_sbr_member
 test eax,eax
 jz .no
.completed:
 ; Even a previously completed domain needs fresh frozen scope/bridge,
 ; current A custody, CPU-off and all-member quiet before publication.
 mov edi,r12d
 call nicag_sbr_bridge_ok
 test eax,eax
 jz .no
 mov ebp,eax
 call nicag_reset_guard
 test eax,eax
 jz .no
 xor ebx,ebx
 xor eax,eax
 lea rdx,[rel nicag_identity+PG_MEMBERS]
.members:
 bt ebp,ebx
 jnc .next
 cmp byte [rdx+PGM_RMETHOD],PGRM_SBR
 jne .next
 cmp word [rdx+PGM_RDOMAIN],r13w
 jne .next
 bts eax,ebx
.next:
 add rdx,16
 inc ebx
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,ecx
 jb .members
 bt eax,r12d
 jc .out
.no: xor eax,eax
.out:
 add rsp,8
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; One physical SBR can affect several members. Every affected function must
; clear its reset marker before ANY affected function is restored. Quiet all
; affected interrupts again, then restore every saved non-enabling field.
; The caller remembers only same-SBR-domain ordinals after this whole operation.
nicag_sbr_member:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,24
 mov r15d,edi
 call nicag_reset_guard
 test eax,eax
 jz .no
 mov edi,r15d
 call nicag_sbr_bridge_ok
 test eax,eax
 jz .no
 mov r14d,eax
 xor ebx,ebx
.pending:
 bt r14d,ebx
 jnc .next_pending
 mov eax,ebx
 shl eax,8
 lea r12,[rel nicag_config]
 add r12,rax
 mov rsi,r12
 call nicag_pcie_cap
 test eax,eax
 jz .no
 mov ebp,eax
 mov eax,ebx
 shl eax,4
 lea rdx,[rel nicag_identity+PG_MEMBERS]
 movzx edi,word [rdx+rax+PGM_BDF]
 lea esi,[rbp+8]
 call pci_bdf_read
 cmp eax,-1
 je .no
 test eax,(1<<21)|0x8000
 jnz .no
 cmp ax,[r12+rbp+8]
 jne .no
.next_pending:
 inc ebx
 movzx eax,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,eax
 jb .pending
 call nicag_reset_guard
 test eax,eax
 jz .no
 mov edi,r15d
 call nicag_sbr_bridge_ok
 cmp eax,r14d
 jne .no
 mov eax,r15d
 shl eax,4
 lea r12,[rel nicag_bridges]
 add r12,rax
 lea rdx,[rel nicag_identity+PG_MEMBERS]
 movzx r13d,word [rdx+rax+PGM_RDOMAIN]
 mov edx,[r12+8]
 and edx,~0x04000000              ; never replay Bridge Control W1C status
 or edx,1<<22
 mov edi,r13d
 mov esi,0x3c
 call pci_bdf_write
 mov edi,3000
 call tsc_delay_us
 mov edi,r13d
 mov esi,0x3c
 call pci_bdf_read
 and eax,~0x04000000
 mov edx,[r12+8]
 and edx,~0x04000000
 or edx,1<<22
 cmp eax,edx
 setne bpl
 movzx ebp,bpl
 ; Always deassert the known original bridge, including failed assert reads.
 mov edx,[r12+8]
 and edx,~0x04000000
 mov edi,r13d
 mov esi,0x3c
 call pci_bdf_write
 mov edi,120000
 call tsc_delay_us
 test ebp,ebp
 jnz .no
 call nicag_reset_safe
 test eax,eax
 jz .no
 xor ebx,ebx
.identity_member:
 bt r14d,ebx
 jnc .next_identity
 mov ebp,1000
.identity_poll:
 call nicag_reset_safe
 test eax,eax
 jz .no
 mov eax,ebx
 shl eax,4
 lea rdx,[rel nicag_identity+PG_MEMBERS]
 movzx edi,word [rdx+rax+PGM_BDF]
 xor esi,esi
 call pci_bdf_read
 mov ecx,ebx
 shl ecx,8
 lea rdx,[rel nicag_config]
 cmp eax,[rdx+rcx]
 je .marker
 mov edi,1000
 call tsc_delay_us
 dec ebp
 jnz .identity_poll
 jmp .no
.marker:
 mov eax,ebx
 shl eax,4
 lea rdx,[rel nicag_identity+PG_MEMBERS]
 movzx edi,word [rdx+rax+PGM_BDF]
 mov esi,4
 call pci_bdf_read
 cmp eax,-1
 je .no
 test eax,0x407                  ; every affected function actually reset
 jnz .no
.next_identity:
 inc ebx
 movzx eax,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,eax
 jb .identity_member
 mov edi,r15d
 call nicag_sbr_bridge_ok
 cmp eax,r14d
 jne .no
 xor ebx,ebx
.quiet_member:
 bt r14d,ebx
 jnc .next_quiet
 call nicag_reset_safe
 test eax,eax
 jz .no
 mov eax,ebx
 shl eax,4
 lea rdi,[rel nicag_identity+PG_MEMBERS]
 add rdi,rax
 call nicag_member_off
 test eax,eax
 jz .no
.next_quiet:
 inc ebx
 movzx eax,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,eax
 jb .quiet_member
 call nicag_reset_guard
 test eax,eax
 jz .no
 xor ebx,ebx
.restore_member:
 bt r14d,ebx
 jnc .next_restore
 mov edi,r15d
 call nicag_sbr_bridge_ok
 cmp eax,r14d
 jne .no
 mov edi,ebx
 call nicag_sbr_restore
 test eax,eax
 jz .no
.next_restore:
 inc ebx
 movzx eax,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,eax
 jb .restore_member
 mov edi,r15d
 call nicag_sbr_bridge_ok
 cmp eax,r14d
 jne .no
 call nicag_reset_guard
 jmp .out
.no: xor eax,eax
.out:
 add rsp,24
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

nicag_pcie_cap:
 push rbx
 push rbp
 push r12
 push r13
 mov r12,rsi
 test dword [r12+4],1<<20
 jz .no
 movzx ebx,byte [r12+0x34]
 test ebx,ebx
 jz .no
 xor ebp,ebp
 xor r13d,r13d
.loop:
 test ebx,ebx
 jz .done
 cmp ebx,0x40
 jb .no
 cmp ebx,0xfc
 ja .no
 test ebx,3
 jnz .no
 mov ecx,ebx
 shr ecx,2
 bts r13,rcx
 jc .no
 mov eax,[r12+rbx]
 cmp eax,-1
 je .no
 test al,al
 jz .no
 cmp al,0xff
 je .no
 cmp al,0x10
 jne .next
 test ebp,ebp
 jnz .no
 cmp ebx,0xf4
 ja .no
 mov ebp,ebx
 mov eax,[r12+rbx+4]
 cmp eax,-1
 je .no
 mov eax,[r12+rbx+8]
 cmp eax,-1
 je .no
 ; Capability preflight refuses pending work; the fresh bounded poll below
 ; handles transactions which become pending after this observation.
 test eax,(1<<21)|0x8000
 jnz .no
.next:
 movzx ebx,byte [r12+rbx+1]
 jmp .loop
.done:
 mov eax,ebp
 jmp .out
.no: xor eax,eax
.out:
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

nicag_sbr_restore:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov r15d,edi
 mov eax,edi
 shl eax,4
 lea r14,[rel nicag_identity+PG_MEMBERS]
 add r14,rax
 movzx ebx,word [r14+PGM_BDF]
 mov eax,r15d
 shl eax,8
 lea r12,[rel nicag_config]
 add r12,rax
 mov rsi,r12
 call nicag_pcie_cap
 test eax,eax
 jz .no
 mov r13d,eax
 mov edi,ebx
 xor esi,esi
 call pci_bdf_read
 cmp eax,[r12]
 jne .no
 mov edi,ebx
 mov esi,8
 call pci_bdf_read
 cmp eax,[r12+8]
 jne .no
 mov edi,ebx
 mov esi,r13d
 call pci_bdf_read
 cmp eax,[r12+r13]
 jne .no
 mov edi,ebx
 lea esi,[r13+4]
 call pci_bdf_read
 cmp eax,[r12+r13+4]
 jne .no
 mov ebp,0x10
.bars:
 call nicag_reset_guard
 test eax,eax
 jz .no
 mov edx,[r12+rbp]
 mov edi,ebx
 mov esi,ebp
 call pci_bdf_write
 mov edi,ebx
 mov esi,ebp
 call pci_bdf_read
 cmp eax,[r12+rbp]
 jne .no
 add ebp,4
 cmp ebp,0x28
 jb .bars
 call nicag_reset_guard
 test eax,eax
 jz .no
 movzx edx,word [r12+0x0c]        ; preserve type-0 header (RO upper half)
 mov edi,ebx
 mov esi,0x0c
 call pci_bdf_write
 mov edi,ebx
 mov esi,0x0c
 call pci_bdf_read
 cmp ax,[r12+0x0c]
 jne .no
 call nicag_reset_guard
 test eax,eax
 jz .no
 movzx edx,byte [r12+0x3c]
 mov edi,ebx
 mov esi,0x3c
 call pci_bdf_write
 mov edi,ebx
 mov esi,0x3c
 call pci_bdf_read
 cmp al,[r12+0x3c]
 jne .no
 call nicag_reset_guard
 test eax,eax
 jz .no
 movzx edx,word [r12+r13+8]
 and edx,0x7fff
 mov edi,ebx
 lea esi,[r13+8]
 call pci_bdf_write
 mov edi,ebx
 lea esi,[r13+8]
 call pci_bdf_read
 cmp eax,-1
 je .no
 test eax,(1<<21)|0x8000
 jnz .no
 movzx edx,word [r12+r13+8]
 cmp ax,dx
 jne .no
 ; Recheck every saved restore target after the last write too.
 mov ebp,0x10
.verify:
 mov edi,ebx
 mov esi,ebp
 call pci_bdf_read
 cmp eax,[r12+rbp]
 jne .no
 add ebp,4
 cmp ebp,0x28
 jb .verify
 mov edi,ebx
 mov esi,0x0c
 call pci_bdf_read
 cmp ax,[r12+0x0c]
 jne .no
 mov edi,ebx
 mov esi,0x3c
 call pci_bdf_read
 cmp al,[r12+0x3c]
 jne .no
 call nicag_reset_guard
 jmp .out
.no: xor eax,eax
.out:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; First inbound reset only. EAX0/-1, exact captured native record required.
; Missing original SBR scope refuses before any reset/capture change. No partial retry.
nicag_reset_core:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov r12,rdi
 lea rax,[rel pcia_grp]
 cmp rdi,rax
 jne .no
 cmp byte [rel nicag_state],1
 jne .no
 mov ebx,0xff
 cmp byte [r12+PG_STATE],PGS_QUIESCED
 jne .poison
 xor ebx,ebx
 call nicag_identity_ok
 test eax,eax
 jz .poison
.methods:
 mov eax,ebx
 shl eax,4
 cmp byte [r12+rax+PG_MEMBERS+PGM_RMETHOD],PGRM_FLR
 je .method_next
 mov edi,ebx
 call nicag_sbr_scope
 test eax,eax
 jz .no
.method_next:
 inc ebx
 movzx eax,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,eax
 jb .methods
 mov byte [rel nicag_state],2
 mov byte [rel nicag_reset_in],0
 xor ebx,ebx
.capture_member:
 call nicag_reset_guard
 test eax,eax
 jz .poison
 mov eax,ebx
 shl eax,4
 lea r13,[rel nicag_identity+PG_MEMBERS]
 add r13,rax
 mov eax,ebx
 shl eax,8
 lea r14,[rel nicag_config]
 add r14,rax
 xor ebp,ebp
.capture_dword:
 movzx edi,word [r13+PGM_BDF]
 mov esi,ebp
 call pci_bdf_read
 cmp eax,-1
 je .poison
 mov [r14+rbp],eax
 add ebp,4
 cmp ebp,256
 jb .capture_dword
 mov rsi,r14
 mov edi,ebx
 call nicag_member_cap
 test eax,eax
 jz .poison
 mov eax,ebx
 shl eax,4
 cmp byte [r12+rax+PG_MEMBERS+PGM_RMETHOD],PGRM_SBR
 jne .captured
 mov edi,ebx
 call nicag_sbr_capture
 test eax,eax
 jz .poison
.captured:
 inc ebx
 movzx eax,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,eax
 jb .capture_member
 mov dword [rsp],0              ; fresh inbound physical-domain completions
 xor ebx,ebx
.reset_member:
 call nicag_reset_guard
 test eax,eax
 jz .poison
 mov edi,ebx
 mov esi,[rsp]
 call nicag_reset_member
 test eax,eax
 jz .poison
 or [rsp],eax
 mov ecx,ebx
 mov eax,1
 shl eax,cl
 or [rel nicag_reset_in],al
 mov eax,ebx
 shl eax,4
 or byte [r12+rax+PG_MEMBERS+PGM_FLAGS],PGF_RESET_IN
 inc ebx
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,ecx
 jb .reset_member
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_reset_in]
 jne .poison
 mov ebx,0xff
 call nicag_reset_guard
 test eax,eax
 jz .poison
 mov byte [rel nicag_state],4     ; private inbound reset complete; still held
 mov byte [r12+PG_STATE],PGS_RESET_IN
 xor eax,eax
 jmp .out
.poison:
 mov byte [rel nicag_state],3
 mov byte [r12+PG_STATE],PGS_POISON
 cmp byte [r12+PG_FAIL_STEP],0
 jne .no
 mov [r12+PG_FAIL_ORD],bl
 mov byte [r12+PG_FAIL_STEP],PGX_RESET
.no: mov eax,-1
.out:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; W4c-2 C3. A pure C-owned witness, not exclusive A reservation authority.
; RDI exact native group -> EAX1/0. No poison, diagnostic publication, reset,
; config write, delay or backend operation. Every peer must still match the
; configuration restored by C's actual original inbound reset producer.
nicag_backend_ready:
 push r12
 mov r12,rdi
 lea rax,[rel pcia_grp]
 cmp rdi,rax
 jne .no
 cmp byte [rel nicag_state],4
 jne .no
 cmp byte [r12+PG_STATE],PGS_RESET_IN
 jne .no
 call nicag_config_ready
 test eax,eax
 jz .out
 cmp byte [rel nicag_state],4
 jne .no
 cmp byte [r12+PG_STATE],PGS_RESET_IN
 jne .no
 mov eax,1
 jmp .out
.no: xor eax,eax
.out: pop r12
 ret

; Shared pure original-config reader; callers prove their own native phase.
nicag_config_ready:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov r12,rdi
 call nicag_identity_ok
 test eax,eax
 jz .no
 call nica_cpu_off
 test eax,eax
 jz .no
 cmp byte [rel nic_assignment_state],NICA_IDLE
 jne .no
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_quiesced]
 jne .no
 cmp al,[rel nicag_reset_in]
 jne .no
 xor ebx,ebx
.member:
 mov eax,ebx
 shl eax,4
 lea rdi,[rel nicag_identity+PG_MEMBERS]
 add rdi,rax
 call iommu_guest_group_member_quiet
 test eax,eax
 jz .no
 mov eax,ebx
 shl eax,4
 lea r13,[rel nicag_identity+PG_MEMBERS+PGM_BDF]
 add r13,rax
 movzx r13d,word [r13]
 mov eax,ebx
 shl eax,8
 lea r14,[rel nicag_config]
 add r14,rax
 mov rsi,r14
 mov edi,ebx
 call nicag_member_cap
 test eax,eax
 jz .no
 mov r15d,eax
 mov eax,ebx
 shl eax,4
 lea rdx,[rel nicag_identity+PG_MEMBERS]
 cmp byte [rdx+rax+PGM_RMETHOD],PGRM_SBR
 jne .bridge_ready
 mov edi,ebx
 call nicag_sbr_bridge_ok
 test eax,eax
 jz .no
.bridge_ready:
 mov edi,r13d
 xor esi,esi
 call pci_bdf_read
 cmp eax,[r14]
 jne .no
 mov edi,r13d
 mov esi,8
 call pci_bdf_read
 cmp eax,[r14+8]
 jne .no
 mov edi,r13d
 mov esi,0x0c
 call pci_bdf_read
 cmp eax,[r14+0x0c]
 jne .no
 mov ebp,0x10
.bars:
 mov edi,r13d
 mov esi,ebp
 call pci_bdf_read
 cmp eax,[r14+rbp]
 jne .no
 add ebp,4
 cmp ebp,0x28
 jb .bars
 mov edi,r13d
 mov esi,0x3c
 call pci_bdf_read
 cmp eax,-1
 je .no
 cmp al,[r14+0x3c]
 jne .no
 mov edi,r13d
 mov esi,r15d
 call pci_bdf_read
 cmp eax,[r14+r15]
 jne .no
 mov edi,r13d
 lea esi,[r15+4]
 call pci_bdf_read
 cmp eax,[r14+r15+4]
 jne .no
 mov edi,r13d
 lea esi,[r15+8]
 call pci_bdf_read
 cmp eax,-1
 je .no
 test eax,(1<<21)|0x8000
 jnz .no
 cmp ax,[r14+r15+8]
 jne .no
 inc ebx
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,ecx
 jb .member
 ; Recheck original identity/START/CPU/masks after all volatile PCI reads.
 mov rdi,r12
 call nicag_identity_ok
 test eax,eax
 jz .no
 call nica_cpu_off
 test eax,eax
 jz .no
 cmp byte [rel nic_assignment_state],NICA_IDLE
 jne .no
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_quiesced]
 jne .no
 cmp al,[rel nicag_reset_in]
 jne .no
 mov eax,1
 jmp .out
.no: xor eax,eax
.out:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Public C admission for B: both original C witness and original A exclusive
; reservations, never common flags. VM's A implementation defines the source
; capability PAOS_PCIA_GRP_AUTHORITY only when its actual query is present.
; Until then this public entry refuses unconditionally; it never invents A.
nica_grp_backend_admit:
%ifdef PAOS_PCIA_GRP_AUTHORITY
 push r12
 mov r12,rdi
 call nicag_backend_ready
 test eax,eax
 jz .out
 mov rdi,r12
 call pcia_grp_reserved
 cmp eax,1
 jne .no
 mov rdi,r12
 call nicag_backend_ready
 jmp .out
.no: xor eax,eax
.out: pop r12
 ret
%else
 xor eax,eax
 ret
%endif

; C4 additive public inbound entries. Actual A reservations are separate
; from C's capture; the absent-provider branch always refuses.
nicag_reservation_ok:
%ifdef PAOS_PCIA_GRP_AUTHORITY
 sub rsp,8
 call pcia_grp_reserved
 cmp eax,1
 sete al
 movzx eax,al
 add rsp,8
 ret
%else
 xor eax,eax
 ret
%endif

; New admission phase, original released C witness and CPU-off are all pure.
nicag_reuse_phase_ok:
 push r12
 mov r12,rdi
 call nicag_shape_ok
 test eax,eax
 jz .out
 cmp byte [r12+PG_STATE],PGS_RESERVED
 jne .no
 call nica_cpu_off
 test eax,eax
 jz .out
 cmp byte [rel nic_assignment_state],NICA_IDLE
 jne .no
 lea rdi,[rel nicag_identity]
 call nicag_saved_ok
 jmp .out
.no: xor eax,eax
.out: pop r12
 ret

; Positive new A reservations plus actual old B release proof precede every
; recapture. Never clear native C to FREE, assume release or reuse old masks.
nicag_reuse_ok:
 push r12
 mov r12,rdi
 call nicag_reuse_phase_ok
 cmp eax,1
 jne .no
 mov rdi,r12
 call nicag_reservation_ok
 cmp eax,1
 jne .no
 cmp byte [rel nicag_identity+PG_BACKEND],PGB_VTD
 je .vtd
 cmp byte [rel nicag_identity+PG_BACKEND],PGB_AMDVI
 jne .no
 mov rdi,r12
 call amdvi_guest_group_reuse_ready
 jmp .observed
.vtd:
 mov rdi,r12
 call vtd_guest_group_reuse_ready
.observed:
 test eax,eax
 jnz .no
 mov rdi,r12
 call nicag_reservation_ok
 cmp eax,1
 jne .no
 mov rdi,r12
 call nicag_reuse_phase_ok
 jmp .out
.no: xor eax,eax
.out: pop r12
 ret

; First/new-START RESERVED -> QUIESCED, or later-phase fresh C7 quiesce.
; EAX0/-1. Before capture, refusal is inert; after capture, uncertainty holds
; the entire original native C capture and publishes POISON.
nica_grp_quiesce:
 push r12
 mov r12,rdi
 call nicag_shape_ok
 test eax,eax
 jz .no
 cmp byte [rel nicag_state],0
 je .initial
 cmp byte [rel nicag_state],9
 jne .later
 mov rdi,r12
 call nicag_reuse_ok
 cmp eax,1
 jne .no
.initial:
 cmp byte [r12+PG_STATE],PGS_RESERVED
 jne .no
 call nica_cpu_off
 test eax,eax
 jz .no
 cmp byte [rel nic_assignment_state],NICA_IDLE
 jne .no
 mov rdi,r12
 call nicag_reservation_ok
 cmp eax,1
 jne .no
 mov rdi,r12
 call nicag_quiesce_core
 test eax,eax
 jnz .out
 mov rdi,r12
 call nicag_reservation_ok
 cmp eax,1
 jne .poison
 mov rdi,r12
 call nicag_completed_quiet
 test eax,eax
 jz .poison
 cmp byte [rel nicag_state],1
 jne .poison
 cmp byte [r12+PG_STATE],PGS_QUIESCED
 jne .poison
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_quiesced]
 jne .poison
 xor eax,eax
 jmp .out
.later:
 mov rdi,r12
 call nicag_requiet_core
 jmp .out
.poison:
 mov byte [rel nicag_state],3
 mov byte [r12+PG_STATE],PGS_POISON
 cmp byte [r12+PG_FAIL_STEP],0
 jne .no
 mov byte [r12+PG_FAIL_ORD],0xff
 mov byte [r12+PG_FAIL_STEP],PGX_QUIESCE
.no: mov eax,-1
.out:
 pop r12
 ret

; Original inbound reset only. No caller-built QUIESCED state authorizes it.
; Any lost A authority after the original C capture poisons without a reset.
; Missing original SBR provider refuses inertly with its original capture held.
nica_grp_reset:
 push r12
 mov r12,rdi
 lea rax,[rel pcia_grp]
 cmp rdi,rax
 jne .no
 cmp byte [rel nicag_state],1
 jne .no
 call nicag_reservation_ok
 cmp eax,1
 jne .poison
 mov rdi,r12
 call nicag_reset_core
 test eax,eax
 jnz .out
 mov rdi,r12
 call nicag_reservation_ok
 cmp eax,1
 jne .poison
 mov rdi,r12
 call nicag_backend_ready
 cmp eax,1
 jne .poison
 xor eax,eax
 jmp .out
.poison:
 mov byte [rel nicag_state],3
 mov byte [r12+PG_STATE],PGS_POISON
 cmp byte [r12+PG_FAIL_STEP],0
 jne .no
 mov byte [r12+PG_FAIL_ORD],0xff
 mov byte [r12+PG_FAIL_STEP],PGX_RESET
.no: mov eax,-1
.out:
 pop r12
 ret

; C5 original outbound custody. This produces reset/quiet evidence only;
; no B detach, claim retirement, allocation release or retry is performed.
; Pure observing guard for the fresh outbound completed-disable mask.
nicag_out_quiet:
 push rbx
 push r12
 push r13
 mov r12,rdi
 call nicag_identity_ok
 test eax,eax
 jz .no
 cmp byte [r12+PG_STATE],PGS_RELEASING
 jne .no
 movzx r13d,byte [rel nicag_state]
 cmp r13d,5
 jb .no
 cmp r13d,8
 ja .no
 call nica_cpu_off
 test eax,eax
 jz .no
 cmp byte [rel nic_assignment_state],NICA_IDLE
 jne .no
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_quiesced]
 jne .no
 cmp al,[rel nicag_reset_in]
 jne .no
 not eax
 test al,[rel nicag_out_quiesced]
 jnz .no
 mov rdi,r12
 call nicag_reservation_ok
 cmp eax,1
 jne .no
 xor ebx,ebx
.member:
 bt dword [rel nicag_out_quiesced],ebx
 jnc .next
 mov eax,ebx
 shl eax,4
 lea rdi,[rel nicag_identity+PG_MEMBERS]
 add rdi,rax
 call iommu_guest_group_member_quiet
 test eax,eax
 jz .no
.next:
 inc ebx
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,ecx
 jb .member
 mov rdi,r12
 call nicag_identity_ok
 test eax,eax
 jz .no
 cmp byte [r12+PG_STATE],PGS_RELEASING
 jne .no
 cmp r13b,[rel nicag_state]
 jne .no
 call nica_cpu_off
 test eax,eax
 jz .no
 cmp byte [rel nic_assignment_state],NICA_IDLE
 jne .no
 mov rdi,r12
 call nicag_reservation_ok
 cmp eax,1
 jne .no
 mov eax,1
 jmp .out
.no: xor eax,eax
.out:
 pop r13
 pop r12
 pop rbx
 ret

; Actual B's original all-member native liveness, not common LIVE or flags.
nicag_backend_live:
 push r12
 mov r12,rdi
 call nicag_identity_ok
 test eax,eax
 jz .out
 cmp byte [r12+PG_BACKEND],PGB_VTD
 je .vtd
 cmp byte [r12+PG_BACKEND],PGB_AMDVI
 jne .no
 mov rdi,r12
 call amdvi_guest_group_live
 jmp .result
.vtd:
 mov rdi,r12
 call vtd_guest_group_live
.result:
 test eax,eax
 setz al
 movzx eax,al
 jmp .out
.no: xor eax,eax
.out: pop r12
 ret

; Exact original inbound C capture, common LIVE, actual A held, CPUs off.
; SBR requires the original VM root-scope provider and saved bridge identity.
nicag_release_core:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov r12,rdi
 lea rax,[rel pcia_grp]
 cmp rdi,rax
 jne .no
 cmp byte [rel nicag_state],4
 jne .no
 cmp byte [r12+PG_STATE],PGS_LIVE
 jne .no
 mov ebx,0xff
 mov r15d,PGX_QUIESCE
 call nicag_identity_ok
 test eax,eax
 jz .poison
 call nica_cpu_off
 test eax,eax
 jz .poison
 cmp byte [rel nic_assignment_state],NICA_IDLE
 jne .poison
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_quiesced]
 jne .poison
 cmp al,[rel nicag_reset_in]
 jne .poison
 xor ebx,ebx
.methods:
 mov eax,ebx
 shl eax,4
 cmp byte [r12+rax+PG_MEMBERS+PGM_RMETHOD],PGRM_FLR
 je .method_next
 mov edi,ebx
 call nicag_sbr_scope
 test eax,eax
 jz .no
.method_next:
 inc ebx
 movzx eax,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,eax
 jb .methods
 mov ebx,0xff
 mov rdi,r12
 call nicag_reservation_ok
 cmp eax,1
 jne .poison
 mov rdi,r12
 call nicag_identity_ok
 test eax,eax
 jz .poison
 cmp byte [r12+PG_STATE],PGS_LIVE
 jne .poison
 call nica_cpu_off
 test eax,eax
 jz .poison
 mov byte [rel nicag_out_quiesced],0
 mov byte [rel nicag_reset_out],0
 mov byte [rel nicag_out_failed],0
 mov byte [rel nicag_state],5
 mov byte [r12+PG_STATE],PGS_RELEASING
 xor ebx,ebx
.quiesce_member:
 mov rdi,r12
 call nicag_out_quiet
 test eax,eax
 jz .poison
 mov eax,ebx
 shl eax,4
 lea rdi,[rel nicag_identity+PG_MEMBERS]
 add rdi,rax
 call nicag_member_off
 mov ebp,eax
 mov rdi,r12
 call nicag_out_quiet
 test eax,eax
 jz .poison
 test ebp,ebp
 jz .member_bad
 mov ecx,ebx
 mov eax,1
 shl eax,cl
 or [rel nicag_out_quiesced],al
 jmp .next_quiesce
.member_bad:
 mov byte [rel nicag_out_failed],1
 cmp byte [r12+PG_FAIL_STEP],0
 jne .next_quiesce
 mov [r12+PG_FAIL_ORD],bl
 mov byte [r12+PG_FAIL_STEP],PGX_QUIESCE
.next_quiesce:
 inc ebx
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,ecx
 jb .quiesce_member
 cmp byte [rel nicag_out_failed],0
 jne .poison
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_out_quiesced]
 jne .poison
 mov byte [rel nicag_state],6
 mov ebx,0xff
 mov r15d,PGX_READBACK
 mov rdi,r12
 call nicag_backend_live
 test eax,eax
 jz .poison
 mov rdi,r12
 call nicag_out_quiet
 test eax,eax
 jz .poison
 mov byte [rel nicag_state],7
 mov dword [rsp],0              ; fresh outbound; never borrow inbound proof
 xor ebx,ebx
.reset_member:
 mov r15d,PGX_RESET
 mov rdi,r12
 call nicag_out_quiet
 test eax,eax
 jz .poison
 mov edi,ebx
 mov esi,[rsp]
 call nicag_reset_member
 test eax,eax
 jz .poison
 or [rsp],eax
 mov rdi,r12
 call nicag_out_quiet
 test eax,eax
 jz .poison
 mov r15d,PGX_READBACK
 mov rdi,r12
 call nicag_backend_live
 test eax,eax
 jz .poison
 mov rdi,r12
 call nicag_out_quiet
 test eax,eax
 jz .poison
 mov ecx,ebx
 mov eax,1
 shl eax,cl
 or [rel nicag_reset_out],al
 mov eax,ebx
 shl eax,4
 or byte [r12+rax+PG_MEMBERS+PGM_FLAGS],PGF_RESET_OUT
 inc ebx
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,ecx
 jb .reset_member
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_reset_out]
 jne .poison
 mov byte [rel nicag_state],8
 mov ebx,0xff
 mov rdi,r12
 call nicag_detach_ready
 test eax,eax
 jz .poison
 mov rdi,r12
 call nicag_out_quiet
 test eax,eax
 jz .poison
 xor eax,eax
 jmp .out
.poison:
 mov byte [rel nicag_state],3
 mov byte [r12+PG_STATE],PGS_POISON
 cmp byte [r12+PG_FAIL_STEP],0
 jne .no
 mov [r12+PG_FAIL_ORD],bl
 mov [r12+PG_FAIL_STEP],r15b
.no: mov eax,-1
.out:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Pure completed outbound identity/phase/CPU and full private mask check.
nicag_out_complete:
 push r12
 mov r12,rdi
 lea rax,[rel pcia_grp]
 cmp rdi,rax
 jne .no
 cmp byte [rel nicag_state],8
 jne .no
 cmp byte [r12+PG_STATE],PGS_RELEASING
 jne .no
 call nicag_identity_ok
 test eax,eax
 jz .out
 call nica_cpu_off
 test eax,eax
 jz .out
 cmp byte [rel nic_assignment_state],NICA_IDLE
 jne .no
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_quiesced]
 jne .no
 cmp al,[rel nicag_reset_in]
 jne .no
 cmp al,[rel nicag_out_quiesced]
 jne .no
 cmp al,[rel nicag_reset_out]
 jne .no
 mov eax,1
 jmp .out
.no: xor eax,eax
.out: pop r12
 ret

; Pure C outbound witness; no A/B authority, diagnostics or release effects.
nicag_detach_ready:
 push r12
 mov r12,rdi
 call nicag_out_complete
 test eax,eax
 jz .out
 mov rdi,r12
 call nicag_config_ready
 test eax,eax
 jz .out
 mov rdi,r12
 call nicag_out_complete
.out: pop r12
 ret

; Public B detach admission additionally consumes actual A reservations.
nica_grp_backend_detach_admit:
%ifdef PAOS_PCIA_GRP_AUTHORITY
 push r12
 mov r12,rdi
 call nicag_detach_ready
 test eax,eax
 jz .out
 mov rdi,r12
 call pcia_grp_reserved
 cmp eax,1
 jne .no
 mov rdi,r12
 call nicag_detach_ready
 jmp .out
.no: xor eax,eax
.out: pop r12
 ret
%else
 xor eax,eax
 ret
%endif

; C7 observes original custody in one of the two legal later phases.
nicag_requiet_phase_ok:
 push r12
 mov r12,rdi
 call nicag_identity_ok
 test eax,eax
 jz .out
 call nica_cpu_off
 test eax,eax
 jz .out
 cmp byte [rel nic_assignment_state],NICA_IDLE
 jne .no
 mov al,[rel nicag_requiet_phase]
 cmp [r12+PG_STATE],al
 jne .no
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_quiesced]
 jne .no
 cmp al,[rel nicag_reset_in]
 jne .no
 cmp byte [rel nicag_requiet_phase],PGS_RESET_IN
 jne .outbound
 cmp byte [rel nicag_state],4
 jne .no
 jmp .yes
.outbound:
 cmp byte [rel nicag_requiet_phase],PGS_RELEASING
 jne .no
 cmp byte [rel nicag_state],8
 jne .no
 cmp al,[rel nicag_out_quiesced]
 jne .no
 cmp al,[rel nicag_reset_out]
 jne .no
.yes: mov eax,1
 jmp .out
.no: xor eax,eax
.out: pop r12
 ret

; Pure actual-A and current completed-peer observer, with final identity read.
nicag_requiet_guard:
 push rbx
 push r12
 mov r12,rdi
 call nicag_requiet_phase_ok
 test eax,eax
 jz .no
 mov rdi,r12
 call nicag_reservation_ok
 cmp eax,1
 jne .no
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 not eax
 test al,[rel nicag_requiet_done]
 jnz .no
 xor ebx,ebx
.member:
 bt dword [rel nicag_requiet_done],ebx
 jnc .next
 mov eax,ebx
 shl eax,4
 lea rdi,[rel nicag_identity+PG_MEMBERS]
 add rdi,rax
 call iommu_guest_group_member_quiet
 test eax,eax
 jz .no
.next:
 inc ebx
 movzx eax,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,eax
 jb .member
 mov rdi,r12
 call nicag_reservation_ok
 cmp eax,1
 jne .no
 mov rdi,r12
 call nicag_requiet_phase_ok
 jmp .out
.no: xor eax,eax
.out:
 pop r12
 pop rbx
 ret

; Fresh later-phase disables; never recapture/reset/release original custody.
; Preserve phase and all four original completion masks. Uncertainty holds.
nicag_requiet_core:
 push rbx
 push rbp
 push r12
 mov r12,rdi
 lea rax,[rel pcia_grp]
 cmp rdi,rax
 jne .no
 cmp byte [r12+PG_STATE],PGS_RESET_IN
 je .inbound
 cmp byte [r12+PG_STATE],PGS_RELEASING
 jne .no
 cmp byte [rel nicag_state],8
 jne .no
 jmp .cpu
.inbound:
 cmp byte [rel nicag_state],4
 jne .no
.cpu:
 call nica_cpu_off
 test eax,eax
 jz .no
 mov al,[r12+PG_STATE]
 mov [rel nicag_requiet_phase],al
 mov byte [rel nicag_requiet_done],0
 mov byte [rel nicag_requiet_failed],0
 mov ebx,0xff
 mov rdi,r12
 call nicag_requiet_guard
 test eax,eax
 jz .poison
 xor ebx,ebx
.member:
 mov rdi,r12
 call nicag_requiet_guard
 test eax,eax
 jz .poison
 mov eax,ebx
 shl eax,4
 lea rdi,[rel nicag_identity+PG_MEMBERS]
 add rdi,rax
 call nicag_member_off
 mov ebp,eax
 mov rdi,r12
 call nicag_requiet_guard
 test eax,eax
 jz .poison
 test ebp,ebp
 jz .member_bad
 mov ecx,ebx
 mov eax,1
 shl eax,cl
 or [rel nicag_requiet_done],al
 jmp .next
.member_bad:
 mov byte [rel nicag_requiet_failed],1
 cmp byte [r12+PG_FAIL_STEP],0
 jne .next
 mov [r12+PG_FAIL_ORD],bl
 mov byte [r12+PG_FAIL_STEP],PGX_QUIESCE
.next:
 inc ebx
 movzx ecx,byte [rel nicag_identity+PG_COUNT]
 cmp ebx,ecx
 jb .member
 cmp byte [rel nicag_requiet_failed],0
 jne .poison
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel nicag_requiet_done]
 jne .poison
 mov ebx,0xff
 mov rdi,r12
 call nicag_config_ready
 test eax,eax
 jz .poison
 mov rdi,r12
 call nicag_requiet_guard
 test eax,eax
 jz .poison
 xor eax,eax
 jmp .out
.poison:
 mov byte [rel nicag_state],3
 mov byte [r12+PG_STATE],PGS_POISON
 cmp byte [r12+PG_FAIL_STEP],0
 jne .no
 mov [r12+PG_FAIL_ORD],bl
 mov byte [r12+PG_FAIL_STEP],PGX_QUIESCE
.no: mov eax,-1
.out:
 pop r12
 pop rbp
 pop rbx
 ret

; C6 pure actual native retirement observation; no A/C release authority.
nicag_backend_retired:
 push r12
 mov r12,rdi
 call nicag_identity_ok
 test eax,eax
 jz .out
 cmp byte [r12+PG_BACKEND],PGB_VTD
 je .vtd
 cmp byte [r12+PG_BACKEND],PGB_AMDVI
 jne .no
 mov rdi,r12
 call amdvi_guest_group_retired
 jmp .result
.vtd:
 mov rdi,r12
 call vtd_guest_group_retired
.result:
 test eax,eax
 setz al
 movzx eax,al
 jmp .out
.no: xor eax,eax
.out: pop r12
 ret

; Public original release. A's actual dispatcher alone sets its detach latch;
; B's original retired census and C's outbound observation precede the atomic
; all-or-none A claim drop. After exact-one, only non-failing local publication
; remains, serialized BSP/IF0/CPU-off. No further hardware observation or call.
; The B released bytes are C-owned final-release custody (B held predicates).
nica_grp_release:
%ifdef PAOS_PCIA_GRP_AUTHORITY
 push r12
 push r13
 sub rsp,8
 mov r12,rdi
 lea rax,[rel pcia_grp]
 cmp rdi,rax
 jne .no
 cmp byte [rel nicag_state],4
 jne .no
 cmp byte [r12+PG_STATE],PGS_LIVE
 jne .no
 call nica_cpu_off
 test eax,eax
 jz .no
 mov rdi,r12
 call nicag_release_core
 test eax,eax
 jnz .out
 mov rdi,r12
 call pcia_grp_detach
 test eax,eax
 jnz .poison
 mov rdi,r12
 call nicag_backend_retired
 cmp eax,1
 jne .poison
 mov rdi,r12
 call nica_grp_backend_detach_admit
 cmp eax,1
 jne .poison
 lea r13,[rel vtdgg_released]
 cmp byte [r12+PG_BACKEND],PGB_VTD
 je .claims
 cmp byte [r12+PG_BACKEND],PGB_AMDVI
 jne .poison
 lea r13,[rel amdvg_released]
.claims:
 mov rdi,r12
 call pcia_grp_claims_retire
 cmp eax,1
 jne .poison
 mov byte [rel nicag_claims_retired],1
 mov byte [r13],1
 mov byte [rel nicag_state],9
 mov byte [r12+PG_STATE],PGS_RETIRED
 xor eax,eax
 jmp .out
.poison:
 mov byte [rel nicag_state],3
 mov byte [r12+PG_STATE],PGS_POISON
 cmp byte [r12+PG_FAIL_STEP],0
 jne .no
 mov byte [r12+PG_FAIL_ORD],0xff
 mov byte [r12+PG_FAIL_STEP],PGX_RETIRE
.no: mov eax,-1
.out:
 add rsp,8
 pop r13
 pop r12
 ret
%else
 mov eax,-1
 ret
%endif

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
nica_method: resd 1
nica_bridge: resd 1
nica_bridge_buses: resd 1
nica_bridge_control: resd 1
nica_reset_attempt: resd 1
alignb 8
nica_reset_record: resb 64
nic_assignment_error: resd 1
nica_addr: resd 1
nica_command: resw 1
nic_assignment_state: resb 1
nica_reset_ok: resb 1
nica_attach_failed: resb 1             ; set only by attach's own poison; within the existing pad
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
alignb 8
nica_link_record: resb 64              ; R2 NLK1 (ROOT108305 B)
nica_link_t0: resq 1
nica_link_last: resd 1
nica_link_prev: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_nic_assignment

%macro WDATA_BSS_hv_nic_assignment_retention 0
alignb 8
nica_retention_record: resb 64         ; R2b NRT1 (ROOT108718/108722)
nica_retention_pre: resd 10            ; quiesced pre-assert values
nica_retention_pre_mask: resd 1
nica_retention_armed: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_nic_assignment_retention

%macro WDATA_BSS_hv_nic_assignment_admission 0
alignb 8
nica_admission_start: resq 1
nica_admission_bdf: resd 1
nica_admission_attempt: resd 1
nica_admission_result: resd 1
nica_admission_phase: resd 1
nica_admission_command: resd 1
nica_admission_prepared: resd 1
nica_admission_failure: resd 1
nica_admission_kind: resb 1
nica_unproven_latch: resb 1
nica_first_eligible: resb 1
nica_admission_first_custody: resb 1   ; frozen original tuple, not a launch grant
nica_admission_pre_domain_refusal: resb 1 ; exact original marker-only exclusion
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_nic_assignment_admission

%macro WDATA_BSS_hv_nic_assignment_group 0
alignb 8
nicag_identity: resb PCIA_GRP_BYTES
nicag_record: resq 1
nicag_state: resb 1              ; 0 unused,1 quiet,2 reset-in pending,3 poison,4 reset-in
                                ; 5 out-quiesce,6 out-quiet,7 out-reset,8 out-done,9 claims-retired
nicag_quiesced: resb 1          ; actual per-member C completion, never flags
nicag_failed: resb 1
nicag_reset_in: resb 1          ; C-produced reset+restore completions, never flags
nicag_out_quiesced: resb 1      ; fresh outbound disables, never inbound mask
nicag_reset_out: resb 1         ; actual outbound reset+restore completions
nicag_out_failed: resb 1
nicag_claims_retired: resb 1
nicag_requiet_done: resb 1
nicag_requiet_phase: resb 1
nicag_requiet_failed: resb 1
alignb 8
nicag_config: resb PCIA_GRP_MAX*256 ; original quiesced config, pinned on failure
nicag_bridges: resb PCIA_GRP_MAX*16 ; C-captured bridge ID, buses, control per SBR member
alignb 8
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_nic_assignment_group
