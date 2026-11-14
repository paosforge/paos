;; MODULE hv/svm
;; LAYER 5
;; EXPORTS hv_svm_rec, hv_svm_detect, hv_svm_cpuid_supported, hv_svm_cpuid_read, hv_svm_detect_kat, hv_svm_enable, hv_svm_setup, hv_svm_map, hv_svm_launch, hv_svm_exit_dispatch, hv_svm_selftest, hv_svm_can_inject_extint, hv_svm_inject_extint, hv_svm_intr_window, hv_svm_slat_flush, hv_svm_slat_bits, hv_svm_guest_cr3, hv_svm_guest_read, hv_svm_guest_write, hv_svm_floor, hv_svm_floor_classify, hv_svm_linux_enter, hv_svm_msr_read, hv_svm_efer_write, hv_svm_cpuid_mask, hv_svm_cur_vmcb, hv_svm_exitcode, hv_svm_refuse, hv_svm_floor_in, hv_svm_stat_text, hv_svm_host_release, hv_svm_boundary_frame
;; IMPORTS hv/boundary_execution, hv/vcpu_svm_start, hv/vcpu_svm_record, hv/boundary, boot/serial, core/time, hv/vmx, hv/hv_ops, hv/guest_surface, hv/cdp_bridge
;; CAPS
;; OWNER saga:hv
%include "hv/boundary_transition.inc"
;; CONTEXT: bsp_only  (RCQ-18 S1b C-a: one vCPU. CLGI..VMRUN..STGI and every VMCB access run on the launching BSP's guest task; never reachable from an AP or IRQ entry - gauntlet_v2/tools/bsp_only_context_lint.py)
; ============================================================================
; AMD SVM/NPT backend (RCQ-18 S1b) for the thin Linux guest.
;
; Detection is CPUID-only. GUESTVM START runs a fail-closed floor before any SVM
; state changes (no EFER.SVME, VM_HSAVE_PA, VMCB, IOPM or MSRPM write on refusal),
; then the shared START path (hv_guest_linux_start) prepares the guest and calls
; hv_svm_linux_enter. Each #VMEXIT is normalised into the vendor-neutral exit
; record (VMX reason numbering and field encodings), and the proven VMX handlers
; serve it through hv_guest_read / hv_guest_write. Boot-time enable/setup/map do
; nothing on SVM: SVM is enabled per START, after the floor, and torn down after.
; ============================================================================

%include "hv/vcpu_svm_fields.inc"

; SVM pages in the host-only 2 MiB control area (DESIGN §5). Prepare zeroes 0..0x8FFF.
HV_SVM_HSAVE        equ 0x00000             ; VM_HSAVE_PA, processor-owned
HV_SVM_VMCB         equ 0x01000
HV_SVM_NPT          equ 0x02000             ; nCR3: the revoke paths clear [region + 0x2000]
HV_SVM_HOST         equ 0x1A000             ; host VMSAVE/VMLOAD area
HV_SVM_IOPM         equ 0x1B000             ; 12 KiB, all ones
HV_SVM_MSRPM        equ 0x1E000             ; 8 KiB, all ones except the passthrough MSRs
; Device register backing must never alias VMSAVE/VMLOAD or permission maps.
%if (HV_GUESTSND_PAGE < HV_SVM_HOST + 0x1000 && HV_GUESTSND_PAGE + 0x1000 > HV_SVM_HOST) || (HV_GUESTRNG_PAGE < HV_SVM_HOST + 0x1000 && HV_GUESTRNG_PAGE + 0x1000 > HV_SVM_HOST) || (HV_GUESTSND_PAGE < HV_SVM_IOPM + 0x3000 && HV_GUESTSND_PAGE + 0x1000 > HV_SVM_IOPM) || (HV_GUESTRNG_PAGE < HV_SVM_IOPM + 0x3000 && HV_GUESTRNG_PAGE + 0x1000 > HV_SVM_IOPM) || (HV_GUESTSND_PAGE < HV_SVM_MSRPM + 0x2000 && HV_GUESTSND_PAGE + 0x1000 > HV_SVM_MSRPM) || (HV_GUESTRNG_PAGE < HV_SVM_MSRPM + 0x2000 && HV_GUESTRNG_PAGE + 0x1000 > HV_SVM_MSRPM)
    %error "guest register pages overlap SVM control state"
%endif

HV_SVM_REASON_STOP  equ 0xFFFF              ; no VMX row: the shared dispatch stops (load_err 7)
HV_SVM_REASON_INVALID equ 0x80000021        ; VMEXIT_INVALID as a VM-entry failure (load_err 6)
HV_SVM_LOAD_ERR     equ 12                  ; GUESTVM START refused by the SVM floor
hv_svm_detect:
    sub  rsp, 24
    mov  rdi, rsp
    call hv_svm_cpuid_read
    call hv_svm_cpuid_supported
    add  rsp, 24
    ret

; RDI -> {vendor[12], max_extended:u32, extended_1_ecx:u32} filled from live CPUID.
; RDI is kept; clobbers RAX, RCX, RDX.
hv_svm_cpuid_read:
    push rbx
    xor  eax, eax
    cpuid
    mov  [rdi], ebx                       ; vendor order: EBX, EDX, ECX
    mov  [rdi + 4], edx
    mov  [rdi + 8], ecx
    mov  eax, 0x80000000
    xor  ecx, ecx
    cpuid
    mov  [rdi + 12], eax
    mov  dword [rdi + 16], 0
    cmp  eax, 0x80000001
    jb   .out
    mov  eax, 0x80000001
    xor  ecx, ecx
    cpuid
    mov  [rdi + 16], ecx                 ; SVM is ECX[2], NOT EDX
.out:
    pop  rbx
    ret

; RDI -> {vendor[12], max_extended:u32, extended_1_ecx:u32} -> EAX=0/1.
; Pure classifier shared by live CPUID and the negative KAT. Classic's
; vt_detect supplies the proven extended-leaf/ECX-bit sequence; require the
; complete AuthenticAMD vendor too. Leaf 8000000A alone earns no capability.
hv_svm_cpuid_supported:
    xor  eax, eax
    cmp  dword [rdi], 'Auth'
    jne  .out
    cmp  dword [rdi + 4], 'enti'
    jne  .out
    cmp  dword [rdi + 8], 'cAMD'
    jne  .out
    cmp  dword [rdi + 12], 0x80000001
    jb   .out
    bt   dword [rdi + 16], 2
    setc al
.out:
    ret

hv_svm_detect_kat:
    push rbx
    push r12
    sub  rsp, 8
    lea  rbx, [rel svm_detect_cases]
    mov  r12d, 7
.case:
    mov  rdi, rbx
    call hv_svm_cpuid_supported
    cmp  eax, [rbx + 20]
    jne  .fail
    add  rbx, 24
    dec  r12d
    jnz  .case
    lea  rdi, [rel str_svm_detect_pass]
    call serial_string
    mov  eax, 1
    jmp  .out
.fail:
    lea  rdi, [rel str_svm_detect_fail]
    call serial_string
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; RDI -> the floor inputs (hv_svm_floor_in layout): {vendor[12], max_extended,
; extended_1_ecx, vm_cr, 8000000A eax, ebx, ecx, edx, 7.0 ecx} -> EAX = 0 accept,
; else the first refusal in DESIGN §2 order: 1 no_svm, 2 no_svm_leaf,
; 3 svm_disabled, 4 no_npt, 5 asid, then 6 no_decode_assists (HV-XCR0 V5: PKU or
; KL enumerated, so CR4 writes exit, and no DecodeAssists to name their GPR).
; Pure: no CPUID, no MSR. NRIP-save is not required (RCQ-18 S2-1): without it
; the exit path decodes the fixed-length instructions.
hv_svm_floor_classify:
    call hv_svm_cpuid_supported
    test eax, eax
    mov  eax, 1
    jz   .out
    mov  eax, 2
    cmp  dword [rdi + 12], 0x8000000A
    jb   .out
    mov  eax, 3
    test byte [rdi + 20], 0x10           ; VM_CR.SVMDIS
    jnz  .out
    mov  eax, 4
    test byte [rdi + 36], 1              ; 8000000A EDX[0] NP
    jz   .out
    mov  eax, 5
    cmp  dword [rdi + 28], 2             ; 8000000A EBX: NASID (ASID 0 is the host's)
    jb   .out
    xor  eax, eax
    test dword [rdi + 40], SVM_CPUID7_PKX ; HV-XCR0 V5 (root 54435dfd): without PKU/KL the guest cannot set
    jz   .out                             ; CR4.PKE/KL and CR4 writes are not intercepted
    mov  eax, 6
    test byte [rdi + 36], 0x80           ; 8000000A EDX[7] DecodeAssists: the CR4 exit's GPR
    jz   .out
    xor  eax, eax
.out:
    ret

; GUESTVM START floor. Reads CPUID and, only once the vendor, SVM and leaf
; checks hold, VM_CR and CPUID 7.0 (when the highest basic leaf reaches 7). Writes no MSR and touches no control page. Prints exactly
; one line, [hv.svm.refused] or [hv.svm.floor.ok], with the raw bits.
; -> EAX = 0 accept, else the refusal reason (hv_linux_load_err = 12).
hv_svm_floor:
    push rbx
    lea  rdi, [rel hv_svm_floor_in]
    xor  eax, eax
    mov  ecx, 11
    rep  stosd
    lea  rdi, [rel hv_svm_floor_in]
    call hv_svm_cpuid_read
    call hv_svm_cpuid_supported
    test eax, eax
    jz   .classify
    cmp  dword [rdi + 12], 0x8000000A
    jb   .classify
    mov  ecx, 0xC0010114                  ; VM_CR: architectural once CPUID reports SVM
    rdmsr
    mov  [rel hv_svm_floor_in + 20], eax
    mov  eax, 0x8000000A
    xor  ecx, ecx
    cpuid
    mov  [rel hv_svm_floor_in + 24], eax
    mov  [rel hv_svm_floor_in + 28], ebx
    mov  [rel hv_svm_floor_in + 32], ecx
    mov  [rel hv_svm_floor_in + 36], edx
    xor  eax, eax                         ; EAX = the highest basic leaf
    cpuid
    cmp  eax, 7
    jb   .classify
    mov  eax, 7
    xor  ecx, ecx
    cpuid
    mov  [rel hv_svm_floor_in + 40], ecx  ; 7.0 ECX: PKU, KL (HV-XCR0 V5)
.classify:
    lea  rdi, [rel hv_svm_floor_in]
    call hv_svm_floor_classify
    mov  [rel hv_svm_refuse], al
    mov  cl, [rel hv_svm_floor_in + 36]
    and  cl, 8                            ; 8000000A EDX[3] NRIPS
    mov  [rel hv_svm_nrips], cl
    test eax, eax
    setz byte [rel hv_svm_floor_ok]
    mov  ebx, eax
    lea  rdi, [rel hv_svm_line]
    lea  rsi, [rel str_svm_floor_ok]
    test ebx, ebx
    jz   .bits
    mov  byte [rel hv_linux_load_err], HV_SVM_LOAD_ERR
    lea  rsi, [rel str_svm_refused]
    call svm_line_put
    lea  rsi, [rel svm_refuse_toks]
    mov  ecx, ebx
.tok:                                     ; RSI -> token number ECX (1-based)
    dec  ecx
    jz   .bits
.skip:
    lodsb
    test al, al
    jnz  .skip
    jmp  .tok
.bits:
    call svm_line_put
    lea  rsi, [rel str_svm_edx]
    call svm_line_put
    mov  edx, [rel hv_svm_floor_in + 36]
    call svm_line_hex
    lea  rsi, [rel str_svm_vmcr]
    call svm_line_put
    mov  edx, [rel hv_svm_floor_in + 20]
    call svm_line_hex
    lea  rsi, [rel str_svm_tag_ok]
    test ebx, ebx
    jnz  .refused_tag
    cmp  byte [rel hv_svm_nrips], 0
    jne  .tag
    lea  rsi, [rel str_svm_decode]
    call svm_line_put
    lea  rsi, [rel str_svm_tag_ok]
    jmp  .tag
.refused_tag:
    lea  rsi, [rel str_svm_tag_refused]
.tag:
    call svm_line_put
    lea  rdi, [rel hv_svm_line]
    call serial_string                    ; one transaction: the line is never spliced
    mov  eax, ebx
    pop  rbx
    ret

; GUESTVM STAT's copy of the last START floor result (RCQ-18 SVM metal plan: the
; Reatan's serial is dark, so the floor line's raw bits must reach the network
; reply). Pure: renders hv_svm_floor_in, hv_svm_refuse and hv_svm_nrips, which
; only hv_svm_floor writes, with the floor line's own tokens. vm_cr is bits 31:0
; of MSR C001_0114 (the floor keeps EAX only; bits 63:32 are reserved).
; -> RAX = " svm_floor=<ok|reason> cpuid8000000a_edx=0x.. vm_cr=0x..[ decode=fixed]",
;    or 0 while no floor has run (no vendor text yet: VMX, or AMD before a START).
; Clobbers RAX, RCX, RDX, RSI, RDI.
hv_svm_stat_text:
    xor  eax, eax
    cmp  dword [rel hv_svm_floor_in], 0
    je   .out
    lea  rdi, [rel hv_svm_stat_buf]
    lea  rsi, [rel str_svm_stat_floor]
    call svm_line_put
    lea  rsi, [rel str_svm_stat_ok]
    movzx ecx, byte [rel hv_svm_refuse]
    test ecx, ecx
    jz   .put
    lea  rsi, [rel svm_refuse_toks]
.tok:                                     ; RSI -> token number ECX (1-based)
    dec  ecx
    jz   .put
.skip:
    lodsb
    test al, al
    jnz  .skip
    jmp  .tok
.put:
    call svm_line_put
    lea  rsi, [rel str_svm_edx]
    call svm_line_put
    mov  edx, [rel hv_svm_floor_in + 36]
    call svm_line_hex
    lea  rsi, [rel str_svm_vmcr]
    call svm_line_put
    mov  edx, [rel hv_svm_floor_in + 20]
    call svm_line_hex
    cmp  byte [rel hv_svm_refuse], 0
    jne  .done
    cmp  byte [rel hv_svm_nrips], 0
    jne  .done
    lea  rsi, [rel str_svm_decode]
    call svm_line_put
.done:
    lea  rax, [rel hv_svm_stat_buf]
.out:
    ret

; RSI = NUL-terminated text, appended at RDI; RDI ends on the copied NUL. Clobbers AL.
svm_line_put:
    lodsb
    stosb
    test al, al
    jnz  svm_line_put
    dec  rdi
    ret

; EDX = value -> 8 lowercase hex digits at RDI (NUL after). Clobbers EAX, ECX, EDX.
svm_line_hex:
    mov  ecx, 8
.digit:
    rol  edx, 4
    mov  eax, edx
    and  eax, 0xF
    add  al, '0'
    cmp  al, '9'
    jbe  .put
    add  al, 'a' - '9' - 1
.put:
    stosb
    dec  ecx
    jnz  .digit
    mov  byte [rdi], 0
    ret

hv_svm_enable:
    mov  rax, -1
    ret

hv_svm_setup:
    mov  rax, -1
    ret

hv_svm_map:
    mov  rax, -1
    ret

; hv_ops LAUNCH. Only the thin Linux guest (launch mode 1) runs on SVM; the
; VMX-only bounded HLT launch has no SVM form, and GUESTVM STAT says so
; (RCQ-18 S2-2: last_launch=REFUSED field=svm_mode0).
hv_svm_launch:
    cmp  byte [rel hv_launch_mode], 1
    jne  .none
    mov  edi, 1                           ; the SVM floor and hv_svm_linux_enter
    jmp  hv_guest_linux_start
.none:
    mov  byte [rel hv_launch_refused], 1
    lea  rax, [rel str_svm_mode0]
    mov  [rel hv_val_field], rax
    mov  rax, -1
    ret

; Called by hv_guest_linux_start after the floor accepted and hv_linux_prepare
; built the NPT (r15-relative layout above). Runs the guest until a handler stops
; it, then restores the host exactly.
hv_svm_linux_enter:
    mov rax, [rel vm_profile_active]
    test rax, rax
    jz .legacy
    cmp dword [rax + 36], 2
    je vsm_enter
.legacy:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, HVB_SIZE
    mov  qword [rsp + HVB_ACTIVE], 0
    mov  qword [rsp + HVB_GUARD], 0
    mov  qword [rsp + HVB_REQUEST], 0
    mov  qword [rsp + HVB_LEASE], 0
    mov  qword [rsp + HVB_FRONTIER], 0
    mov  [rel hv_svm_boundary_frame], rsp ; single resident vCPU, cleared on every return
    mov  r15, [rel hv_linux_region]
    pushfq
    pop  rax
    mov  [rel hv_launch_rflags], rax
    cli
    mov  rdi, rsp
    call hv_boundary_arm
    ; Preserve the actual return and retained frame before teardown/guest GPR load.
    push rdi
    push rsi
    lea rdi, [rsp + 16]
    mov esi, 2
    call hv_boundary_observe
    pop rsi
    pop rdi
    test rax, rax
    jnz  .guard_refused
    mov  rax, cr0
    mov  [rel hv_launch_cr0], rax
    mov  [rel hv_launch_hcr0], rax
    mov  rax, cr4
    mov  [rel hv_launch_cr4], rax
    mov  [rel hv_launch_hcr4], rax
    call hv_linux_save_host_msrs          ; EFER before SVME: teardown clears it again
    call hv_linux_host_xsave              ; guest XSETBV runs in host context (shared .xsetbv)
    mov  ecx, 0xC0010117                  ; VM_HSAVE_PA
    rdmsr
    mov  [rel hv_svm_saved_hsave], eax
    mov  [rel hv_svm_saved_hsave + 4], edx
    lea  rax, [r15 + HV_SVM_HSAVE]
    call hv_linux_wrmsr_rax
    mov  ecx, 0xC0000080
    rdmsr
    or   eax, SVM_EFER_SVME
    wrmsr
    ; From here the NPT can be live on this CPU: the unflushed root clears in
    ; guest_surface/cdp_bridge test this flag, exactly as after VMXON.
    mov  byte [rel hv_linux_vmx_live], 1
    ; Architectural custody needs SVME already enabled; the old host-only
    ; acquisition before saved host state could never establish this fact.
    mov  rdi, rsp
    call hv_boundary_svm_acquire
    test eax, eax
    jnz  .boundary_refused
    call hv_svm_vmcb_build
    lea  rax, [r15 + HV_SVM_VMCB]
    mov  [rel hv_svm_cur_vmcb], rax       ; C2: set only once the VMCB is complete
    inc  dword [rel hv_launches]
    call hv_linux_arm_deadline
    mov  [rel hv_svm_slice_tsc], rax
    ; Linux 64-bit boot ABI: RSI = boot_params GPA, other guest GPRs zero.
    lea  rdi, [rel hv_linux_gpr]
    xor  eax, eax
    mov  ecx, 15
    rep  stosq
    mov  qword [rel hv_linux_gpr + 32], HV_LINUX_BP_GPA
    call hv_linux_vector_scrub            ; HV-XCR0 V3: no earlier guest's or host task's vector state

    ; The single VMRUN site (C2 / C-c / H9). CLGI controls architectural GIF;
    ; it does not prove NMI/firmware exclusion. STI makes IF = 1, which with
    ; V_INTR_MASKING is what lets a physical interrupt leave the guest (INTR).
.run:
    ; A host slice retired the exact lease/guard after full host restore.
    ; Resume arbitration has already allowed this entry. Take a new generation
    ; without rebuilding guest state or restarting the original run deadline.
    cmp  qword [rsp + HVB_GUARD], 0
    jne  .custody_ready
    mov  rdi, rsp
    call hv_svm_host_reacquire
    test eax, eax
    jnz  .boundary_refused
.custody_ready:
    mov  rax, [rel hv_svm_cur_vmcb]
    mov  rdx, [rel hv_linux_gpr + 0]
    mov  [rax + VMCB_RAX], rdx
    cli
    mov  rdi, rsp
    call hv_boundary_svm_prepare         ; HOST->PREPARED, CLGI inside provider
    mov  rdi, rsp
    call hv_boundary_enter
    ; Preserve the actual return and retained frame before teardown/guest GPR load.
    push rdi
    push rsi
    lea rdi, [rsp + 16]
    mov esi, 2
    call hv_boundary_observe
    pop rsi
    pop rdi
    test rax, rax
    jnz  .boundary_refused
    mov  rdi, rsp
    call hv_boundary_svm_transfer        ; only TRANSFER permits IF1/GIF0
    ; V_INTR_MASKING: host IF at VMRUN gates physical INTR, so it must be 1 for INTR exits (the host
    ; heartbeat); GIF remains0 through protected landing. The provider supplies
    ; architectural custody only under its documented native contract. STI follows CLGI,
    ; not right before VMRUN, so VMRUN never sits in the STI interrupt shadow (srcreview S1b C1).
    sti
    call hv_linux_xcr0_to_guest           ; HV-XCR0 V2: the guest's exact XCR0, under GIF=0 only (after S1b C1's STI)
    mov  rax, [rel hv_svm_host_pa]
    vmsave
    mov  rax, [rel hv_svm_cur_vmcb]
    vmload
    HV_BOUNDARY_FINAL
    mov  rax, [rel hv_svm_cur_vmcb]      ; frontier clobbers scratch; VMRUN needs PA
    mov  rbx, [rel hv_linux_gpr + 8]
    mov  rcx, [rel hv_linux_gpr + 16]
    mov  rdx, [rel hv_linux_gpr + 24]
    mov  rsi, [rel hv_linux_gpr + 32]
    mov  rdi, [rel hv_linux_gpr + 40]
    mov  rbp, [rel hv_linux_gpr + 48]
    mov  r8,  [rel hv_linux_gpr + 56]
    mov  r9,  [rel hv_linux_gpr + 64]
    mov  r10, [rel hv_linux_gpr + 72]
    mov  r11, [rel hv_linux_gpr + 80]
    mov  r12, [rel hv_linux_gpr + 88]
    mov  r13, [rel hv_linux_gpr + 96]
    mov  r14, [rel hv_linux_gpr + 104]
    mov  r15, [rel hv_linux_gpr + 112]
    vmrun
    ; #VMEXIT restored host RAX (the VMCB PA). A flush requested after this
    ; instruction is consumed by the next VMRUN, never dropped (C2 (ii)).
    mov  byte [rax + VMCB_TLB], 0
    mov  [rel hv_linux_gpr + 8], rbx
    mov  [rel hv_linux_gpr + 16], rcx
    mov  [rel hv_linux_gpr + 24], rdx
    mov  [rel hv_linux_gpr + 32], rsi
    mov  [rel hv_linux_gpr + 40], rdi
    mov  [rel hv_linux_gpr + 48], rbp
    mov  [rel hv_linux_gpr + 56], r8
    mov  [rel hv_linux_gpr + 64], r9
    mov  [rel hv_linux_gpr + 72], r10
    mov  [rel hv_linux_gpr + 80], r11
    mov  [rel hv_linux_gpr + 88], r12
    mov  [rel hv_linux_gpr + 96], r13
    mov  [rel hv_linux_gpr + 104], r14
    mov  [rel hv_linux_gpr + 112], r15
    vmsave
    mov  rdx, [rax + VMCB_RAX]
    mov  [rel hv_linux_gpr + 0], rdx
    mov  rdx, [rax + VMCB_CR2]            ; RCQ-18 S2-2: VMX never switches CR2, so the shared
    mov  cr2, rdx                         ; handlers read the guest's there; VMRUN reloads it
    mov  rax, [rel hv_svm_host_pa]
    vmload
    cli
    HV_BOUNDARY_LAND
    HV_BOUNDARY_HOST_XCR0
    mov  rdi, rsp
    call hv_boundary_svm_land            ; after protection, GPR and XCR0 custody
    mov  rdi, rsp
    call hv_boundary_exit
    mov rax,[rel hv_svm_cur_vmcb]
    mov rcx,[rax+VMCB_EXITCODE]
    mov rdi,rsp
    mov edx,2
    call hv_boundary_exec_svm
    mov  rdi, rsp
    call hv_boundary_svm_host            ; LANDED->HOST, STGI only after executor
    ; Asynchronous/unknown exits may not resume the guest. The ordinary SVM
    ; decoder below handles only known synchronous reasons and INTR/VINTR.
    mov  rax, [rel hv_svm_cur_vmcb]
    mov  rcx, [rax + VMCB_EXITCODE]
    cmp  rcx, 0x14                      ; known CR4 write
    je   .dispatch
    cmp  rcx, 0x40
    jb   .event_stop
    cmp  rcx, 0x60                      ; known exception or physical INTR
    jbe  .dispatch
    cmp  rcx, 0x64                      ; virtual interrupt window
    je   .dispatch
    cmp  rcx, 0x72                      ; CPUID
    je   .dispatch
    cmp  rcx, 0x78                      ; HLT
    je   .dispatch
    cmp  rcx, 0x7B                      ; IOIO
    je   .dispatch
    cmp  rcx, 0x7C                      ; MSR
    je   .dispatch
    cmp  rcx, 0x8D                      ; XSETBV
    je   .dispatch
    cmp  rcx, 0x400                     ; known NPF
    je   .dispatch
.event_stop:
    mov  byte [rel hv_linux_load_err], 7
    jmp  .teardown
.dispatch:
    ; A stream of handled synchronous exits must not depend on receiving a
    ; physical INTR to give the native command/desktop tasks their host slice.
    ; The protected exit is complete above; the actual host slice restores
    ; native state and releases custody. Keep decoder and power/STOP checks
    ; AFTER the yield, so host work can still refuse this resume. HLT retains
    ; its shared slice (or panic/fixture decision), without a second slice.
    cmp  rcx, 0x78
    je   .decode
    call hv_svm_host_slice_due
.decode:
    call hv_ops_exit_dispatch_active
    test eax, eax
    jnz  .run
.teardown:
    ; Teardown: the revokes flush through hv_slat_flush, so the VMCB stays
    ; current until both are done.
    call guest_surface_revoke_ept
    call cdp_bridge_revoke_ept
    mov  qword [rel hv_svm_cur_vmcb], 0
    mov  byte [rel hv_linux_vmx_live], 0
    call hv_svm_host_release              ; no-op if the last slice already restored/released
    push qword [rel hv_launch_rflags]
    popfq
    jmp  .out
.boundary_refused:
    ; Selection refused before an executor/guest entry. Host XCR0 is live,
    ; no paired context is active. Provider retires PREPARED GIF, if held.
    cli
    mov  rdi, rsp
    call hv_boundary_svm_host            ; clean PREPARED refusal or acquire0
    lea  rax, [rel str_svm_boundary_refused]
    mov  [rel hv_val_field], rax
    mov  byte [rel hv_linux_load_err], 6
    mov  byte [rel hv_launch_refused], 1
    jmp  .teardown
.guard_refused:
    lea  rax, [rel str_svm_guard_refused]
    mov  [rel hv_val_field], rax
    mov  byte [rel hv_linux_load_err], 6
    mov  byte [rel hv_launch_refused], 1
    push qword [rel hv_launch_rflags]
    popfq
.out:
    mov  qword [rel hv_svm_boundary_frame], 0
    add  rsp, HVB_SIZE
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; The shared VMX/SVM host scheduler calls this only at an exited boundary,
; with IF0. VMX has no resident SVM frame. For SVM, HOST opened the owner's
; GIF but still holds every AP in architectural custody: fully restore the
; owner before exact release, then disarm its guard before ordinary host work.
; Repeated slices before the next entry are harmless; any partial state stops.
hv_svm_host_release:
    push rbx
    mov  rbx, [rel hv_svm_boundary_frame]
    test rbx, rbx
    jz   .done
    cmp  qword [rbx + HVB_ACTIVE], 0
    jne  cpu_boundary_fail_stop
    cmp  qword [rbx + HVB_FRONTIER], 0
    jne  cpu_boundary_fail_stop
    cmp  qword [rbx + HVB_GUARD], 0
    jne  .restore
    cmp  qword [rbx + HVB_LEASE], 0
    jne  cpu_boundary_fail_stop
    jmp  .done
.restore:
    mov  eax, [rel hv_svm_saved_hsave]
    mov  edx, [rel hv_svm_saved_hsave + 4]
    mov  ecx, 0xC0010117
    wrmsr
    call hv_linux_restore_host_quiet       ; original CR/MSR/XCR0; IF0, guard held
    mov  rdi, rbx
    call hv_boundary_finish               ; exact AP drain before guard disarm
.done:
    pop  rbx
    ret

; RDI = retained resident frame, IF0, no guard/lease. Refresh the host snapshot
; under a fresh fault guard and acquire fresh architectural custody. This is
; NOT a new guest launch: preserve VMCB/GPRs, guest XCR0, START and deadline.
; Returns 0 on acquired, 1 on clean refusal; uncertainty never returns.
hv_svm_host_reacquire:
    push rbx
    mov  rbx, rdi
    cmp  qword [rbx + HVB_GUARD], 0
    jne  cpu_boundary_fail_stop
    cmp  qword [rbx + HVB_LEASE], 0
    jne  cpu_boundary_fail_stop
    cmp  qword [rbx + HVB_ACTIVE], 0
    jne  cpu_boundary_fail_stop
    cmp  qword [rbx + HVB_FRONTIER], 0
    jne  cpu_boundary_fail_stop
    call hv_boundary_arm
    test eax, eax
    jz   .armed
    ; Arm cleared the provider binding; a refused guard still retires as SVM,
    ; with no lease, or the shared host transition fail-stops on a clean refusal.
    mov  dword [rbx + HVB_SVM], 1
    jmp  .done
.armed:
    mov  rax, cr0
    mov  [rel hv_launch_cr0], rax
    mov  [rel hv_launch_hcr0], rax
    mov  rax, cr4
    mov  [rel hv_launch_cr4], rax
    mov  [rel hv_launch_hcr4], rax
    call hv_linux_save_host_msrs
    ; Capture the current host XCR0 without hv_linux_host_xsave's START-time
    ; guest initialization. Derive the exit superset from the live guest value.
    cmp  byte [rel hv_linux_xcr0_saved], 1
    jne  .hsave
    mov  rax, cr4
    or   rax, 1 << 18
    mov  cr4, rax
    mov  [rel hv_launch_hcr4], rax
    xor  ecx, ecx
    xgetbv
    mov  [rel hv_linux_saved_xcr0], eax
    mov  [rel hv_linux_saved_xcr0 + 4], edx
    mov  rdi, [rel hv_linux_guest_xcr0]
    call hv_linux_xcr0_apply
.hsave:
    mov  ecx, 0xC0010117
    rdmsr
    mov  [rel hv_svm_saved_hsave], eax
    mov  [rel hv_svm_saved_hsave + 4], edx
    mov  rax, [rel hv_linux_region]
    add  rax, HV_SVM_HSAVE
    call hv_linux_wrmsr_rax
    mov  ecx, 0xC0000080
    rdmsr
    or   eax, SVM_EFER_SVME
    wrmsr
    mov  rdi, rbx
    call hv_boundary_svm_acquire
.done:
    pop  rbx
    ret

; R15 = control base. The VMCB page was zeroed by hv_linux_prepare, so every
; reserved field and the clean bits are 0. Clobbers RAX, RCX, RDX, RDI.
hv_svm_vmcb_build:
    lea  rdi, [r15 + HV_SVM_HOST]
    mov  [rel hv_svm_host_pa], rdi
    xor  eax, eax
    mov  ecx, 0x1000 / 8
    rep  stosq
    dec  rax                              ; every port and every MSR exits by default
    mov  ecx, (0x3000 + 0x2000) / 8       ; IOPM then MSRPM, contiguous
    rep  stosq
    ; Hardware swaps these with VMLOAD/VMSAVE around every VMRUN, so no guest
    ; value is ever live in host context. EFER (0xC0000080) stays intercepted.
    lea  rdi, [r15 + HV_SVM_MSRPM]
    mov  byte [rdi + 0x05D], 0xC0         ; SYSENTER_CS/ESP/EIP (0x174-0x176)
    mov  byte [rdi + 0x820], 0x03         ; STAR, LSTAR, CSTAR (0xC0000081-83)
    mov  byte [rdi + 0x821], 0xFC         ; SFMASK (0xC0000084)
    mov  byte [rdi + 0x840], 0xC0         ; FS_BASE, GS_BASE, KERNEL_GS_BASE (0xC0000100-102)
    lea  rdi, [r15 + HV_SVM_VMCB]         ; RDI = the VMCB from here (RDMSR clobbers RDX)
    call hv_first_ud_bitmap_value         ; #DF, #MC (+ #UD in one diagnostic generation)
    mov  [rel hv_first_ud_bitmap_requested], eax
    mov  [rel hv_first_ud_bitmap_readback], eax   ; no VMREAD: the VMCB word is the effective bitmap
    mov  [rdi + VMCB_EXC], eax
    call hv_first_ud_latch_arm
    xor  eax, eax                         ; V5: SVM has no CR4 guest/host mask. With PKU or KL the
    test dword [rel hv_svm_floor_in + 40], SVM_CPUID7_PKX ; floor admitted DecodeAssists: every
    jz   .cr_icpt                         ; MOV to CR4 exits; without them neither bit can be set
    mov  eax, SVM_ICPT_CR4_WRITE
.cr_icpt:
    mov  [rdi + VMCB_CR_ICPT], eax
    mov  dword [rdi + VMCB_ICPT1], SVM_ICPT1
    mov  dword [rdi + VMCB_ICPT2], SVM_ICPT2
    lea  rax, [r15 + HV_SVM_IOPM]
    mov  [rdi + VMCB_IOPM], rax
    lea  rax, [r15 + HV_SVM_MSRPM]
    mov  [rdi + VMCB_MSRPM], rax
    mov  dword [rdi + VMCB_ASID], 1
    mov  byte [rdi + VMCB_TLB], 1         ; C2 (iii): every launch flushes all of ASID 1's past
    mov  dword [rdi + VMCB_VINTR], SVM_VINTR_MASKING
    mov  byte [rdi + VMCB_NP], 1
    mov  rax, [rel hv_linux_eptp]         ; region + 0x2000; HV_SLAT_ROOT bits are 0
    mov  [rdi + VMCB_NCR3], rax
    ; Guest state: the VMX const table's values in VMCB form.
    mov  rax, 0xFFFFFFFF0C930010          ; selector 0x10, data RW, 4 GiB
    mov  [rdi + VMCB_ES], rax
    mov  [rdi + VMCB_SS], rax
    mov  [rdi + VMCB_DS], rax
    mov  [rdi + VMCB_FS], rax
    mov  [rdi + VMCB_GS], rax
    mov  rax, 0xFFFFFFFF0A9B0008          ; selector 0x08, 64-bit code
    mov  [rdi + VMCB_CS], rax
    mov  rax, 0x00000067008B0018          ; selector 0x18, busy 64-bit TSS
    mov  [rdi + VMCB_TR], rax
    mov  rax, [rel hv_launch_hcr0]
    mov  [rdi + VMCB_CR0], rax
    mov  qword [rdi + VMCB_CR3], 0x1000
    mov  rax, [rel hv_launch_hcr4]
    and  rax, ~HV_CR4_GUEST_DENIED           ; V5: a host PKE/KL never leaks into the first guest CR4
    mov  [rdi + VMCB_CR4], rax
    mov  ecx, 0xC0000080                  ; host EFER, SVME set: VMRUN requires it
    rdmsr
    mov  [rdi + VMCB_EFER], eax
    mov  [rdi + VMCB_EFER + 4], edx
    mov  ecx, 0x277                       ; G_PAT = host PAT: the VMX guest's view
    rdmsr
    mov  [rdi + VMCB_GPAT], eax
    mov  [rdi + VMCB_GPAT + 4], edx
    mov  qword [rdi + VMCB_DR7], 0x400
    mov  dword [rdi + VMCB_DR6], 0xFFFF0FF0
    mov  qword [rdi + VMCB_RFLAGS], 2
    mov  qword [rdi + VMCB_RIP], HV_LINUX_KERN_GPA + 0x200
    mov  qword [rdi + VMCB_RSP], 0x8000
    ret

; The same 1 ms TSC budget as the former INTR-only gate, now checked on every
; known non-HLT exit. This is outside the protected transition and before
; decoder/resume arbitration. The shared slice still owns boot grace,
; warm-policy revocation, the DMA deadman and STI / scheduler / CLI.
hv_svm_host_slice_due:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rcx, rax
    sub  rax, [rel hv_svm_slice_tsc]
    mov  rdx, [rel tsc_khz]
    test rdx, rdx
    jnz  .slice_rate
    mov  edx, 3000000                     ; bounded degrade if calibration failed
.slice_rate:
    cmp  rax, rdx
    jb   .no_slice
    mov  [rel hv_svm_slice_tsc], rcx
    call hv_linux_host_slice
.no_slice:
    ret

; #VMEXIT -> the exit record (VMX numbering), then the shared VMX handlers.
; Next RIP comes from NRIP (CPUID/HLT/MSR/XSETBV; without NRIP-save, the exact
; fixed-length encoding), EXITINFO2 (IOIO), or the virtio decoder (NPF), and
; must lie 1-15 bytes ahead. Reason 52 (the VMX
; preemption timer) is never produced. Returns the shared dispatch's EAX.
hv_svm_exit_dispatch:
    mov rdi, [rel hv_svm_cur_vmcb]
    test rdi, rdi
    jz .no_vmcb
    mov rax, [rdi + VMCB_EXITCODE]
    mov [rel hv_svm_exitcode], rax
    lea rsi, [rel hv_svm_rec]
    lea rdx, [rel hv_linux_gpr]
    movzx ecx, byte [rel hv_svm_nrips]
    test ecx, ecx                         ; legacy field retains CPUID bit3 (8)
    setnz cl                              ; private API takes the canonical boolean
    call hv_svm_exit_record_at
    cmp eax, 2
    je .vintr
    cmp eax, 3
    je .intr
    cmp eax, 4
    je .decode
    cmp eax, 5
    je .cr4_apply
    test eax, eax
    jz .no_vmcb
.dispatch:
    jmp hv_linux_exit_dispatch
.vintr:
    xor edi, edi
    call hv_svm_intr_window
    jmp .dispatch
.intr:
    call hv_svm_host_release
    sti
    nop
    cli
    jmp .dispatch
.decode:
    mov esi, [rel hv_svm_rec + SVM_REC_REASON]
    call hv_svm_fixed_len
    lea ecx, [rax - 1]
    cmp ecx, 14
    ja .decode_refused
    mov [rel hv_svm_rec + SVM_REC_ILEN], eax
    jmp .dispatch
.decode_refused:
    lea rdi, [rel str_svm_decode_refused]
    call serial_string
    mov dword [rel hv_svm_rec + SVM_REC_REASON], HV_SVM_REASON_STOP
    jmp .dispatch
.cr4_apply:
    mov rdx, [rel hv_svm_cur_vmcb]
    mov [rdx + VMCB_CR4], r10
    call hv_svm_slat_flush
    jmp .dispatch
.no_vmcb:
    xor eax, eax
    ret

; RDI = owned VMCB, RSI = owned 32-byte record, RDX = owned GPR array,
; ECX = NRIP-save boolean. Pure normalization: no VM entry, host services,
; current-vCPU globals or VMCB/GPR writes. Record ownership/lifetime is the
; caller's contract. Returns EAX 0 absent, 1 record ready, 2 clear VINTR,
; 3 service host IRQ, 4 fixed-length decode needed, 5 apply CR4 value in R10.
; Actions 2-5 are requests only; the caller must finish them in its own context.
; Preserves callee-save GPRs, clobbers caller-save GPRs/flags.
hv_svm_fixed_len:
    lea  r10, [rel svm_fixed_enc]
.find:
    cmp  [r10], sil
    je   .found
    add  r10, 5
    cmp  byte [r10], 0
    jne  .find
    xor  eax, eax
    ret
.found:
    push r10
    mov  rdx, [rel hv_svm_cur_vmcb]
    mov  rdi, [rdx + VMCB_RIP]
    mov  rsi, [rdx + VMCB_CR3]
    movzx ecx, byte [r10 + 1]
    lea  rdx, [rel hv_svm_insn]
    mov  r8, [rel hv_linux_ram]
    mov  r9, [rel hv_linux_ram_bytes]
    call hv_linux_gva_copy_core
    pop  r10
    test eax, eax
    jz   .out
    movzx ecx, byte [r10 + 1]
    lea  rsi, [r10 + 2]
    lea  rdi, [rel hv_svm_insn]
    cld                                   ; the compare runs forward whatever DF the exit left
    repe cmpsb
    mov  eax, 0
    jne  .out
    movzx eax, byte [r10 + 1]
.out:
    ret

; Echoes the nonce only once the floor accepted this CPU at a START.
hv_svm_selftest:
    xor  eax, eax
    cmp  byte [rel hv_svm_floor_ok], 1
    jne  .out
    mov  rax, rdi
.out:
    ret

; Per-vCPU accessors (hv_ops slots 72-112). Each reads or writes the current
; VMCB and clobbers at most RAX, RCX, RDX, RSI, RDI, R11 (C1). With no current
; VMCB (C2) nothing is injected, armed, flushed or read.
hv_svm_can_inject_extint:
    mov  rax, [rel hv_svm_cur_vmcb]
    test rax, rax
    jz   .pending
    test byte [rax + VMCB_EVENTINJ + 3], 0x80   ; EVENTINJ.V: an event already queued
    jnz  .pending
    test dword [rax + VMCB_RFLAGS], 0x200
    jz   .if0
    test byte [rax + VMCB_SHADOW], 1
    jnz  .shadow
    xor  eax, eax
    ret
.pending:
    mov  eax, HV_INJ_BLOCK_PENDING
    ret
.if0:
    mov  eax, HV_INJ_BLOCK_IF
    ret
.shadow:
    mov  eax, HV_INJ_BLOCK_SHADOW
    ret

; EDI = vector -> EVENTINJ = vector | type 0 (INTR) | V, no error code.
hv_svm_inject_extint:
    mov  rax, [rel hv_svm_cur_vmcb]
    test rax, rax
    jz   .out
    mov  edx, edi
    or   edx, 0x80000000
    mov  [rax + VMCB_EVENTINJ], rdx
.out:
    ret

; EDI = 1 arms, 0 disarms the interrupt-window exit: V_IRQ (priority 15,
; ignoring TPR) plus the VINTR intercept.
hv_svm_intr_window:
    mov  rax, [rel hv_svm_cur_vmcb]
    test rax, rax
    jz   .out
    and  dword [rax + VMCB_ICPT1], ~SVM_ICPT1_VINTR
    and  dword [rax + VMCB_VINTR], ~SVM_VIRQ_BITS
    test edi, edi
    jz   .out
    or   dword [rax + VMCB_ICPT1], SVM_ICPT1_VINTR
    or   dword [rax + VMCB_VINTR], SVM_VIRQ_BITS
.out:
    ret

; -> EAX = 1 only with a current VMCB: TLB_CONTROL = 3 (FlushByAsid) or 1, which
; the next VMRUN, the only way back into the guest, consumes (C2 / D5 (i)-(iii)).
hv_svm_slat_flush:
    mov  rax, [rel hv_svm_cur_vmcb]
    test rax, rax
    jz   .out
    mov  dl, 1
    test byte [rel hv_svm_floor_in + 36], 0x40   ; 8000000A EDX[6] FlushByAsid
    jz   .all
    mov  dl, 3
.all:
    mov  [rax + VMCB_TLB], dl
    mov  eax, 1
.out:
    ret

; EDI = HV_SLAT_* -> RAX = the NPT bits for that entry kind (0 for an unknown kind).
hv_svm_slat_bits:
    xor  eax, eax
    mov  ecx, edi
    cmp  ecx, HV_SLAT_KINDS
    jae  .out
    lea  rax, [rel hv_svm_slat_tbl]
    mov  rax, [rax + rcx*8]
.out:
    ret

hv_svm_guest_cr3:
    mov  rax, [rel hv_svm_cur_vmcb]
    test rax, rax
    jz   .out
    mov  rax, [rax + VMCB_CR3]
.out:
    ret

; Exit record read: EDI = VMXF_* field -> RAX from the VMCB or the normalised
; exit. Clobbers RAX, R11, flags only (RCX is saved). Unknown fields read 0.
hv_svm_guest_read:
    push rdx
    mov  r11, [rel hv_svm_cur_vmcb]
    lea  rdx, [rel hv_svm_rec]
    call hv_svm_guest_read_at
    pop  rdx
    ret

; Explicit-state form for private vCPU callers: R11 = owned 4 KiB VMCB,
; RDX = owned 32-byte normalised exit record, EDI = full VMXF encoding.
; Clobbers only RAX/R11/flags, reads no current-vCPU globals and writes nothing.
; A null VMCB, null required record or unknown encoding reads zero. Non-null
; pointers are trusted host addresses; ownership/lifetime checks belong to the
; caller before dispatch. This module remains BSP-only until the AMD executor
; and its closed call graph are implemented and reviewed.
hv_svm_guest_write:
    mov  r11, [rel hv_svm_cur_vmcb]
    test r11, r11
    jz   hv_guest_write_refused
    call hv_svm_guest_write_at
    jc   hv_guest_write_refused
    ret

; Explicit-state form: R11 = owned VMCB, EDI = field, RSI = value.
; CF=0 on success; CF=1 refuses without any write or global counter update.
; Every GPR is preserved, including RAX and the supplied VMCB pointer. The
; legacy wrapper above alone counts failures in its single-vCPU ABI.
hv_svm_msr_read:
    mov  rdx, [rel hv_svm_cur_vmcb]
    xor  eax, eax
    test rdx, rdx
    jz   .out
    cmp  ecx, 0xC0000080
    je   .efer
    cmp  ecx, 0x277
    je   .pat
    cmp  ecx, 0xCE                        ; PLATFORM_INFO and MISC_ENABLE are Intel-only:
    je   .zero                            ; a host RDMSR of either #GPs the AMD host
    cmp  ecx, 0x1A0
    jne  .out
.zero:
    xor  edx, edx
    jmp  .put
.efer:
    mov  rdx, [rdx + VMCB_EFER]
    btr  rdx, 12                          ; SVME is the host's, never the guest's
    jmp  .put
.pat:
    mov  rdx, [rdx + VMCB_GPAT]
.put:
    mov  eax, edx
    mov  [rel hv_linux_gpr + 0], rax
    shr  rdx, 32
    mov  [rel hv_linux_gpr + 24], rdx
    mov  eax, 1
.out:
    ret

; Shared .wr_efer delta: the guest EFER lives in the VMCB. Keeps SCE, LME, LMA
; and NXE from the guest's value and forces SVME (VMRUN requires it).
; EAX = 1 handled; 0 not an SVM guest.
hv_svm_efer_write:
    mov  rdx, [rel hv_svm_cur_vmcb]
    xor  eax, eax
    test rdx, rdx
    jz   .out
    mov  ecx, [rel hv_linux_gpr + 0]
    and  ecx, 0xD01
    or   ecx, SVM_EFER_SVME
    mov  [rdx + VMCB_EFER], rcx
    mov  eax, 1
.out:
    ret

; Shared .cpuid delta. EDI = leaf, EAX..EDX = the result, masked in place for an
; SVM guest: no SVM (80000001 ECX[2]) and an all-zero leaf 8000000A.
hv_svm_cpuid_mask:
    cmp  qword [rel hv_svm_cur_vmcb], 0
    je   .out
    cmp  edi, 0x80000001
    jne  .leaf_a
    and  ecx, ~4
.leaf_a:
    cmp  edi, 0x8000000A
    jne  .out
    xor  eax, eax
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
.out:
    ret

; HV_SLAT_* order (DESIGN C3): TABLE, RAM_2M, TRAP_RO, FB_2M, ROOT, MMIO_4K. U=1
; at every level (nested walks are user accesses); NX on every non-executable
; kind; TRAP_RO and MMIO_4K select PAT index 3 (PWT+PCD), UC in the host PAT.
align 8
hv_svm_slat_tbl:
    dq 0x07, 0x87, 0x800000000000001D, 0x8000000000000087, 0, 0x800000000000001F

; hv_svm_guest_read map: dw VMXF field, dw (offset | size << 12 | record << 14).
; size: 0 qword, 1 dword, 2 word, 3 bit 0. record: offset into hv_svm_rec.
align 4
svm_fixed_enc:
    db 10, 2, 0x0F, 0xA2, 0
    db 12, 1, 0xF4, 0, 0
    db 31, 2, 0x0F, 0x32, 0
    db 32, 2, 0x0F, 0x30, 0
    db 55, 3, 0x0F, 0x01, 0xD1
    db 0

align 4
svm_detect_cases:
    dd 'Auth', 'enti', 'cAMD', 0x80000001, 4, 1
    dd 'Auth', 'enti', 'cAMD', 0x8000000A, 0, 0
    dd 'Auth', 'enti', 'cAMD', 0x80000000, 4, 0
    dd 'Genu', 'ineI', 'ntel', 0x8000000A, 4, 0
    dd 'Auth', 'enti', 'cAMX', 0x8000000A, 4, 0
    dd 'Auth', 'xxxx', 'cAMD', 0x8000000A, 4, 0
    dd 'xxxx', 'enti', 'cAMD', 0x8000000A, 4, 0
str_svm_detect_pass: db "[PAOS64] compat: AMD SVM CPUID detector KAT PASS [compat.amd.svm.detect.kat]",13,10,0
str_svm_detect_fail: db "[PAOS64] compat: AMD SVM CPUID detector KAT FAIL",13,10,0
str_svm_floor_ok:    db "[PAOS64] hv.svm: floor ok", 0
str_svm_refused:     db "[PAOS64] hv.svm: GUEST REFUSED reason=", 0
svm_refuse_toks:     db "no_svm", 0, "no_svm_leaf", 0, "svm_disabled", 0, "no_npt", 0, "asid", 0, "no_decode_assists", 0
str_svm_edx:         db " cpuid8000000a_edx=0x", 0
str_svm_vmcr:        db " vm_cr=0x", 0
str_svm_tag_refused: db " [hv.svm.refused]", 13, 10, 0
str_svm_tag_ok:      db " [hv.svm.floor.ok]", 13, 10, 0
str_svm_decode:      db " decode=fixed", 0
str_svm_decode_refused: db "[PAOS64] hv.svm: no NRIP and not the exact instruction [hv.svm.decode.refused]", 13, 10, 0
str_svm_mode0:       db "svm_mode0", 0
str_svm_guard_refused: db "svm_guard", 0
str_svm_boundary_refused: db "svm_boundary", 0
str_svm_stat_floor:  db " svm_floor=", 0
str_svm_stat_ok:     db "ok", 0

%include "core/abi/wdata.inc" ; WDATA_BSS_DEFER; standalone assemblies expand blocks in place
; Zero-initialised state with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER).
%macro WDATA_BSS_hv_svm 0
alignb 8
hv_svm_cur_vmcb:    resq 1                ; C2: the VMCB's PA while an SVM guest is launched, else 0
hv_svm_host_pa:     resq 1                ; host VMSAVE/VMLOAD area
hv_svm_exitcode:    resq 1                ; raw EXITCODE of the last #VMEXIT
hv_svm_slice_tsc:   resq 1                ; TSC of the last host slice
hv_svm_boundary_frame: resq 1              ; trusted single-vCPU frame, zero outside resident SVM
hv_svm_saved_hsave: resq 1                ; VM_HSAVE_PA before launch, restored at teardown
hv_svm_rec:         resq 4                ; the exit record (SVM_REC_*)
hv_svm_floor_in:    resd 11               ; floor inputs (hv_svm_floor_classify layout; +40 = CPUID 7.0 ECX)
hv_svm_refuse:      resb 1                ; last floor result: 0 accepted, else reason 1-6
hv_svm_nrips:       resb 1                ; 8 when the CPU has NRIP-save, 0: decode (S2-1)
hv_svm_insn:        resb 3                ; the guest bytes hv_svm_fixed_len compares
hv_svm_floor_ok:    resb 1                ; 1 once the floor accepted at a START
hv_svm_line:        resb 128              ; the one floor line
hv_svm_stat_buf:    resb 96               ; hv_svm_stat_text's tokens (at most 75 bytes)
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_svm
