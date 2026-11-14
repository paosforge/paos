;; MODULE hv/hv_ops
%include "hv/guest_power.inc"

;; LAYER 5
;; EXPORTS hv_ops_init, hv_ops_register_verbs, hv_ops_launch_active, hv_ops_exit_dispatch_active, hv_can_inject_extint, hv_inject_extint, hv_intr_window, hv_slat_flush, hv_slat_bits, hv_guest_cr3, hv_guest_read, hv_guest_write, hv_pic_try_inject, hv_ops_active, hv_ops_vmx, hv_ops_svm, hv_ops_perf_vm_exits, hv_ops_perf_host_cycles, hv_ops_vendor_split_ok, hv_ops_vmx_real_ok, hv_ops_svm_stub_ok, hv_ops_dispatch_selected_ok
;; IMPORTS hv/vcpu_ap_run, hv/vcpu_bsp, hv/guest_power, boot/serial, svc/command, hv/vmx, hv/svm
;; CAPS
;; OWNER saga:hv
; ============================================================================
; Vendor-neutral hypervisor operations seam (1067).
;
; Each backend publishes the same runtime-populated table. Function addresses
; are filled with LEA at boot: static `dq symbol` entries are PE RVAs, not usable
; runtime VAs in this image. Boot selects a table from CPUID vendor text, invokes
; the real Intel enable path through that table, and leaves unknown vendors with
; no active backend. Explicit backend calls never mutate the active selection.
; ============================================================================

HVOPS_NAME          equ 0
HVOPS_IMPL          equ 8
HVOPS_DETECT        equ 16
HVOPS_ENABLE        equ 24
HVOPS_SETUP         equ 32
HVOPS_MAP           equ 40
HVOPS_LAUNCH        equ 48
HVOPS_EXIT_DISPATCH equ 56
HVOPS_SELFTEST      equ 64
; Per-vCPU accessors (RCQ-18 S0): what the guest devices and the run loop need
; below launch, so no guest module issues a vendor instruction itself.
; Clobber contract (RCQ-18 S1 C1, normative for both backends): every per-vCPU
; entry in slots 72-112 may clobber only RAX, RCX, RDX, RSI, RDI and R11; flags
; are clobbered; RSP is balanced. Callers (vtd_rtl_try_inject_pending keeps R9)
; rely on every other register surviving.
HVOPS_CAN_INJECT    equ 72              ; -> EAX = 0, or the first HV_INJ_BLOCK_* that holds
HVOPS_INJECT        equ 80              ; EDI = vector: one external interrupt on the next entry
HVOPS_INTR_WINDOW   equ 88              ; EDI = 1 arm / 0 disarm the interrupt-window exit
HVOPS_SLAT_FLUSH    equ 96              ; -> EAX = 1: after EAX = 1, no stale guest-physical translation
                                        ; is usable at the next VMRUN / VM entry (both vendors; VMX
                                        ; INVEPTs now, SVM flushes at that entry). EAX = 0: not assured.
HVOPS_SLAT_BITS     equ 104             ; EDI = HV_SLAT_* -> RAX = entry bits (0: cannot map)
HVOPS_GUEST_CR3     equ 112             ; -> RAX = the guest's CR3
; Exit record (RCQ-18 S1a): the shared exit path reads exit information and guest
; state by VMX field encoding, the vendor-neutral namespace. VMX reads the VMCS;
; SVM serves the same encodings from its VMCB and normalised exit (S1b).
HVOPS_GUEST_READ    equ 120             ; EDI = VMXF_* field -> RAX; clobbers RAX, R11, flags only.
                                        ; Flags are not a result: callers never branch on them.
HVOPS_GUEST_WRITE   equ 128             ; EDI = VMXF_* field, RSI = value; a failed write counts in
                                        ; hv_vmwrite_fails; clobbers R11, flags only
HVOPS_ENT_SZ        equ 136

HVOPS_IMPL_STUB     equ 0
HVOPS_IMPL_REAL     equ 1

; can_inject_extint refusals, in the order every injection site has tested them.
HV_INJ_BLOCK_PENDING equ 1              ; an event is already queued for the next entry
HV_INJ_BLOCK_IF      equ 2              ; guest RFLAGS.IF = 0
HV_INJ_BLOCK_SHADOW  equ 4              ; STI / MOV SS interrupt shadow

; hv_pic_try_inject refusal reason (EDX when EAX = 0).
HV_PICINJ_PENDING   equ 1
HV_PICINJ_NOVEC     equ 2               ; the guest has not programmed the PIC vector base
HV_PICINJ_MASKED    equ 3
HV_PICINJ_IF        equ 4
HV_PICINJ_SHADOW    equ 5

; SLAT entry kinds for slat_bits. The backend owns the format (EPT on VMX).
HV_SLAT_TABLE       equ 0               ; non-leaf: points at the next-level table
HV_SLAT_RAM_2M      equ 1               ; 2 MiB guest RAM leaf, write-back
HV_SLAT_TRAP_RO     equ 2               ; 4 KiB register page: reads hit, writes exit
HV_SLAT_FB_2M       equ 3               ; 2 MiB framebuffer leaf: read/write, no execute, write-back
HV_SLAT_ROOT        equ 4               ; root-pointer attributes (EPTP)
HV_SLAT_MMIO_4K     equ 5               ; 4 KiB assigned-device BAR page: read/write, no execute, UC
HV_SLAT_KINDS       equ 6

; Populate both peer tables, select by the live CPUID vendor string, then invoke
; the selected backend's enable op through the vtable. Unknown is a clean no-op.
hv_ops_init:
    ; S7: backend/profile/topology stays frozen through full retirement.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    push rbx
    push r12

    ; Both peers from one offset table: every pointer is this routine's
    ; runtime VA plus a link-time constant, never a baked-in RVA. The VMX
    ; table is followed directly by the SVM table (HVOPS_ENT_SZ apart).
    lea  rsi, [rel hv_ops_fill]
    lea  rdx, [rel hv_ops_init]
    lea  rdi, [rel hv_ops_vmx]
    mov  ecx, HVOPS_ENT_SZ / 4              ; 2 tables x HVOPS_ENT_SZ/8 qwords
.fill:
    movsxd rax, dword [rsi]
    add  rax, rdx
    mov  [rdi], rax
    add  rsi, 4
    add  rdi, 8
    dec  ecx
    jnz  .fill
    mov  qword [rel hv_ops_vmx + HVOPS_IMPL], HVOPS_IMPL_REAL
    mov  qword [rel hv_ops_svm + HVOPS_IMPL], HVOPS_IMPL_REAL   ; RCQ-18 S1b

    mov  byte [rel hv_ops_vendor_split_ok], 1
    mov  byte [rel hv_ops_vmx_real_ok], 1
    mov  byte [rel hv_ops_svm_stub_ok], 1
    lea  rdi, [rel str_hvops_m_split]
    call serial_string
    lea  rdi, [rel str_hvops_m_vmx]
    call serial_string
    lea  rdi, [rel str_hvops_m_svm]
    call serial_string

    mov  qword [rel hv_ops_active], 0
    lea  rax, [rel str_hvops_vendor_unknown]
    mov  [rel hv_ops_vendor], rax
    xor  eax, eax
    cpuid
    cmp  ebx, 0x756E6547                    ; GenuineIntel: EBX='Genu'
    jne  .check_amd
    cmp  edx, 0x49656E69                    ; EDX='ineI'
    jne  .check_amd
    cmp  ecx, 0x6C65746E                    ; ECX='ntel'
    jne  .check_amd
    lea  r12, [rel hv_ops_vmx]
    lea  rax, [rel str_hvops_vendor_intel]
    jmp  .selected
.check_amd:
    cmp  ebx, 0x68747541                    ; AuthenticAMD: EBX='Auth'
    jne  .unknown
    cmp  edx, 0x69746E65                    ; EDX='enti'
    jne  .unknown
    cmp  ecx, 0x444D4163                    ; ECX='cAMD'
    jne  .unknown
    lea  r12, [rel hv_ops_svm]
    lea  rax, [rel str_hvops_vendor_amd]
.selected:
    mov  [rel hv_ops_active], r12
    mov  [rel hv_ops_vendor], rax
    mov  byte [rel hv_ops_dispatch_selected_ok], 1
    lea  rdi, [rel str_hvops_m_selected]
    call serial_string
    call qword [r12 + HVOPS_DETECT]
    mov  [rel hv_ops_detect_result], rax
    call qword [r12 + HVOPS_ENABLE]          ; real VMX path enters here indirectly
    mov  [rel hv_ops_enable_result], rax
    call qword [r12 + HVOPS_SETUP]
    mov  [rel hv_ops_setup_result], rax
    call qword [r12 + HVOPS_MAP]
    mov  [rel hv_ops_map_result], rax
.unknown:
    ; Preserve 1011's unconditional foundation-ran signal on every vendor path.
    lea  rdi, [rel str_hv_initdone]
    call serial_string
    pop  r12
    pop  rbx
    ret

; Launch the current vendor backend without exposing a vendor call at the caller.
; Unknown vendors degrade with RAX=-1. The existing GUESTVM verb uses this path.
hv_ops_launch_active:
    HV_POWER_CHECK hv_guest_power_admit, .unsupported
    mov  rax, [rel hv_ops_active]
    test rax, rax
    jz   .unsupported
    call qword [rax + HVOPS_LAUNCH]
    ret
.unsupported:
    mov  rax, -1
    ret

; VM-exit lands in the vendor-neutral dispatcher, which selects the backend's
; decoder. RAX=1 asks the launcher to resume; 0 asks it to tear down safely.
; Task1234 accounts at this common seam so the counters retain the same meaning
; for every real backend: VM exits are completed decoder/device-pump calls, and
; host cycles are fenced TSC ticks spent inside that call. The interval starts
; after the active-backend lookup and ends before guest GPR restore; it excludes
; VM transition and save/restore cost. One resident vCPU owns this path, so an
; atomic RMW would add measurement distortion without providing concurrency.
hv_ops_exit_dispatch_active:
    mov  rax, [rel hv_ops_active]
    test rax, rax
    jz   .unsupported
    mov  r10, [rax + HVOPS_EXIT_DISPATCH]
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel hv_ops_perf_exit_start_tsc], rax
    call r10
    mov  r11d, eax
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  r9, rax
    sub  rax, [rel hv_ops_perf_exit_start_tsc]
    add  [rel hv_ops_perf_host_cycles], rax
    inc  qword [rel hv_ops_perf_vm_exits]
    mov  [rel hv_guestcpu_last_progress_tsc], r9
    mov  eax, r11d
    test eax, eax
    jz .unsupported
    ; Both VMRESUME and VMRUN pass this saved-GPR, completed-decoder seam.
    jmp hv_guest_power_exit_gate
.unsupported:
    xor  eax, eax
    ret

; Per-vCPU accessors through the active backend. With no backend they refuse:
; nothing is injected, nothing is mapped, no flush is claimed. Each stays within
; the C1 clobber set above (R11 is the dispatcher's own).
hv_can_inject_extint:
    mov  r11, [rel hv_ops_active]
    test r11, r11
    jz   .none
    jmp  [r11 + HVOPS_CAN_INJECT] ; CONTEXT-TARGETS: hv_vmx_can_inject_extint, hv_svm_can_inject_extint
.none:
    mov  eax, HV_INJ_BLOCK_PENDING
    ret

hv_inject_extint:
    mov  r11, [rel hv_ops_active]
    test r11, r11
    jz   .none
    jmp  [r11 + HVOPS_INJECT] ; CONTEXT-TARGETS: hv_vmx_inject_extint, hv_svm_inject_extint
.none:
    ret

hv_intr_window:
    mov  r11, [rel hv_ops_active]
    test r11, r11
    jz   .none
    jmp  [r11 + HVOPS_INTR_WINDOW]
.none:
    ret

hv_slat_flush:
    mov  r11, [rel hv_ops_active]
    test r11, r11
    jz   .none
    jmp  [r11 + HVOPS_SLAT_FLUSH]
.none:
    xor  eax, eax
    ret

hv_slat_bits:
    mov  r11, [rel hv_ops_active]
    test r11, r11
    jz   .none
    jmp  [r11 + HVOPS_SLAT_BITS]
.none:
    xor  eax, eax
    ret

hv_guest_cr3:
    mov  r11, [rel hv_ops_active]
    test r11, r11
    jz   .none
    jmp  [r11 + HVOPS_GUEST_CR3] ; CONTEXT-TARGETS: hv_vmx_guest_cr3, hv_svm_guest_cr3
.none:
    xor  eax, eax
    ret

; The exit-record pair. Narrower than the other accessors: the shared exit path
; keeps live values in RBX, RCX, RDX, RSI and R8-R15 across them.
hv_guest_read:
    mov  r11, [rel hv_ops_active]
    test r11, r11
    jz   .none
    jmp  [r11 + HVOPS_GUEST_READ] ; CONTEXT-TARGETS: hv_vmx_guest_read, hv_svm_guest_read
.none:
    xor  eax, eax
    ret

hv_guest_write:
    mov  r11, [rel hv_ops_active]
    test r11, r11
    jz   hv_guest_write_refused
    jmp  [r11 + HVOPS_GUEST_WRITE] ; CONTEXT-TARGETS: hv_w, hv_svm_guest_write

; A write no backend takes (none selected, or a field SVM has no VMCB form for)
; is dropped and counted like a failed VMWRITE. RAX is kept.
hv_guest_write_refused:
    inc  dword [rel hv_vmwrite_fails]
    ret

; hv_pic_try_inject(EDI = master-PIC line 0..7) -> EAX = 1 when that line's
; vector is queued for the next entry. Otherwise EAX = 0 and EDX = the first
; HV_PICINJ_* refusal, in the order the console, tick, net, input and RTL
; paths each tested it: event pending, no vector base, line masked, IF = 0,
; interrupt shadow. Clobbers RAX, RCX, RDX, RSI, RDI, R11.
hv_pic_try_inject:
    push rbx
    mov  ebx, edi
    call hv_can_inject_extint
    mov  ecx, eax
    mov  edx, HV_PICINJ_PENDING
    test ecx, HV_INJ_BLOCK_PENDING
    jnz  .no
    movzx esi, byte [rel hv_pic_vec_base]
    mov  edx, HV_PICINJ_NOVEC
    test esi, esi
    jz   .no
    movzx eax, byte [rel hv_pic_mask]
    mov  edx, HV_PICINJ_MASKED
    bt   eax, ebx
    jc   .no
    call glapic_pic_blocked                  ; RCQ-50 S4: with a guest LAPIC the 8259 reaches the
    mov  edx, HV_PICINJ_MASKED               ; CPU only through LINT0 in ExtINT mode (EAX/EDX only)
    test eax, eax
    jnz  .no
    mov  edx, HV_PICINJ_IF
    test ecx, HV_INJ_BLOCK_IF
    jnz  .no
    mov  edx, HV_PICINJ_SHADOW
    test ecx, HV_INJ_BLOCK_SHADOW
    jnz  .no
    lea  edi, [rsi + rbx]
    call hv_inject_extint
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; Register the single HVOPS verb through the transport-neutral command registry.
hv_ops_register_verbs:
    lea  rdi, [rel str_verb_hvops]
    lea  rsi, [rel cmd_verb_hvops]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    call guestcpu_register_verb
    ret

; HVOPS active
; HVOPS query <backend>
; HVOPS call selftest <nonce> [--backend <backend>]
cmd_verb_hvops:
    push rbx
    push r12
    push r13
    push r14
    call cmd_handler_prologue
    mov  r12, [rdi + REQ_ARG]
    mov  r13, rsi
    call hv_out_reset

    mov  rdi, r12
    lea  rsi, [rel str_hvops_active]
    call hv_tok_is
    test al, al
    jnz  .active
    mov  rdi, r12
    lea  rsi, [rel str_hvops_query]
    call hv_tok_is
    test al, al
    jnz  .query
    mov  rdi, r12
    lea  rsi, [rel str_hvops_call]
    call hv_tok_is
    test al, al
    jnz  .call
    jmp  .bad_syntax

.active:
    lea  rdi, [rel str_hvops_r_active]
    call hv_out_str
    mov  rax, [rel hv_ops_active]
    test rax, rax
    jz   .active_unknown
    mov  rdi, [rax + HVOPS_NAME]
    call hv_out_str
    jmp  .active_vendor
.active_unknown:
    lea  rdi, [rel str_hvops_unsupported]
    call hv_out_str
.active_vendor:
    lea  rdi, [rel str_hvops_r_vendor]
    call hv_out_str
    mov  rdi, [rel hv_ops_vendor]
    call hv_out_str
    lea  rdi, [rel str_hvops_r_backends]
    call hv_out_str
    jmp  .ok

.query:
    mov  rdi, r12
    call hvops_after_token
    mov  r14, rax
    mov  rdi, r14
    call hvops_find_backend
    test rax, rax
    jz   .unknown_backend
    mov  rbx, rax
    lea  rdi, [rel str_hvops_r_query]
    call hv_out_str
    mov  rdi, [rbx + HVOPS_NAME]
    call hv_out_str
    lea  rdi, [rel str_hvops_r_registered]
    call hv_out_str
    cmp  qword [rbx + HVOPS_IMPL], HVOPS_IMPL_REAL
    jne  .query_stub
    lea  rdi, [rel str_hvops_r_real]
    call hv_out_str
    jmp  .ok
.query_stub:
    lea  rdi, [rel str_hvops_r_stub]
    call hv_out_str
    jmp  .ok

.call:
    mov  rdi, r12
    call hvops_after_token                  ; skip "call"
    mov  rdi, rax
    lea  rsi, [rel str_hvops_selftest]
    call hv_tok_is
    test al, al
    jz   .bad_syntax
    mov  rdi, r12
    call hvops_after_token
    mov  rdi, rax
    call hvops_after_token                  ; RAX -> caller nonce
    mov  r14, rax
    cmp  byte [r14], 0
    je   .bad_syntax
    mov  rdi, r14
    call hvops_after_token                  ; optional --backend
    mov  r12, rax
    mov  rbx, [rel hv_ops_active]
    cmp  byte [r12], 0
    je   .have_call_backend
    mov  rdi, r12
    lea  rsi, [rel str_hvops_backend_opt]
    call hv_tok_is
    test al, al
    jz   .bad_syntax
    mov  rdi, r12
    call hvops_after_token
    mov  r12, rax
    mov  rdi, rax
    call hvops_find_backend
    test rax, rax
    jz   .unknown_call_backend
    mov  rbx, rax
.have_call_backend:
    test rbx, rbx
    jz   .no_active_backend
    cmp  qword [rbx + HVOPS_IMPL], HVOPS_IMPL_REAL
    jne  .call_stub
    mov  rdi, r14
    call qword [rbx + HVOPS_SELFTEST]        ; content proof through selected entry
    test rax, rax
    jz   .call_unavailable
    lea  rdi, [rel str_hvops_r_call]
    call hv_out_str
    mov  rdi, [rbx + HVOPS_NAME]
    call hv_out_str
    lea  rdi, [rel str_hvops_r_real_nonce]
    call hv_out_str
    mov  rdi, r14
    call hvops_out_token
    jmp  .ok
.call_stub:
    mov  rdi, r14
    call qword [rbx + HVOPS_SELFTEST]        ; distinct SVM vtable entry, no echo
    lea  rdi, [rel str_hvops_r_call]
    call hv_out_str
    mov  rdi, [rbx + HVOPS_NAME]
    call hv_out_str
    lea  rdi, [rel str_hvops_r_stub_verdict]
    call hv_out_str
    jmp  .ok
.call_unavailable:
    lea  rdi, [rel str_hvops_r_call]
    call hv_out_str
    mov  rdi, [rbx + HVOPS_NAME]
    call hv_out_str
    lea  rdi, [rel str_hvops_r_call_unavail]
    call hv_out_str
    jmp  .error

.unknown_backend:
    lea  rdi, [rel str_hvops_r_unknown]
    call hv_out_str
    mov  rdi, r14
    call hvops_out_token
    jmp  .error
.unknown_call_backend:
    lea  rdi, [rel str_hvops_r_unknown]
    call hv_out_str
    mov  rdi, r12
    call hvops_out_token
    jmp  .error
.no_active_backend:
    lea  rdi, [rel str_hvops_r_no_active]
    call hv_out_str
    jmp  .error
.bad_syntax:
    lea  rdi, [rel str_hvops_r_syntax]
    call hv_out_str
.error:
    mov  qword [r13 + RSP_CODE], CMDE_BADSEL
    jmp  .finish
.ok:
    mov  qword [r13 + RSP_CODE], CMDE_OK
.finish:
    mov  byte [rel hv_out_ready], 1
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; hvops_after_token(RDI=text) -> RAX=first non-space after the leading token.
hvops_after_token:
    mov  rax, rdi
.scan:
    movzx ecx, byte [rax]
    test cl, cl
    jz   .done
    cmp  cl, ' '
    je   .spaces
    inc  rax
    jmp  .scan
.spaces:
    cmp  byte [rax], ' '
    jne  .done
    inc  rax
    jmp  .spaces
.done:
    ret

; hvops_find_backend(RDI=leading backend token) -> RAX=table or 0.
hvops_find_backend:
    push rdi
    lea  rsi, [rel str_hvops_vmx]
    call hv_tok_is
    pop  rdi
    test al, al
    jnz  .vmx
    lea  rsi, [rel str_hvops_svm]
    call hv_tok_is
    test al, al
    jnz  .svm
    xor  eax, eax
    ret
.vmx:
    lea  rax, [rel hv_ops_vmx]
    ret
.svm:
    lea  rax, [rel hv_ops_svm]
    ret

; Append one space/NUL-delimited token to the shared HV staged reply (bounded: hv_out_putc).
hvops_out_token:
.copy:
    mov  al, [rdi]
    test al, al
    jz   .end
    cmp  al, ' '
    je   .end
    call hv_out_putc
    inc  rdi
    jmp  .copy
.end:
    ret

; hv_ops_init's fill: per peer, one entry per qword in HVOPS_* slot order
; (NAME, IMPL placeholder, DETECT .. GUEST_WRITE). An entry count that does not
; match both tables fails the build (srcreview S0 F5: no slot is ever empty).
hv_ops_fill:
    dd str_hvops_vmx - hv_ops_init
    dd hv_ops_init - hv_ops_init
    dd hv_vmx_detect - hv_ops_init
    dd hv_vmx_enable - hv_ops_init
    dd hv_vmx_setup - hv_ops_init
    dd hv_vmx_map - hv_ops_init
    dd hv_vmx_launch - hv_ops_init
    dd hv_vmx_exit_dispatch - hv_ops_init
    dd hv_vmx_selftest - hv_ops_init
    dd hv_vmx_can_inject_extint - hv_ops_init
    dd hv_vmx_inject_extint - hv_ops_init
    dd hv_vmx_intr_window - hv_ops_init
    dd hv_vmx_slat_flush - hv_ops_init
    dd hv_vmx_slat_bits - hv_ops_init
    dd hv_vmx_guest_cr3 - hv_ops_init
    dd hv_vmx_guest_read - hv_ops_init
    dd hv_w - hv_ops_init
    dd str_hvops_svm - hv_ops_init
    dd hv_ops_init - hv_ops_init
    dd hv_svm_detect - hv_ops_init
    dd hv_svm_enable - hv_ops_init
    dd hv_svm_setup - hv_ops_init
    dd hv_svm_map - hv_ops_init
    dd hv_svm_launch - hv_ops_init
    dd hv_svm_exit_dispatch - hv_ops_init
    dd hv_svm_selftest - hv_ops_init
    dd hv_svm_can_inject_extint - hv_ops_init
    dd hv_svm_inject_extint - hv_ops_init
    dd hv_svm_intr_window - hv_ops_init
    dd hv_svm_slat_flush - hv_ops_init
    dd hv_svm_slat_bits - hv_ops_init
    dd hv_svm_guest_cr3 - hv_ops_init
    dd hv_svm_guest_read - hv_ops_init
    dd hv_svm_guest_write - hv_ops_init
    times ((($ - hv_ops_fill) == HVOPS_ENT_SZ) - 1) db 0

; Runtime tables and selection state. All pointer fields start zero and are
; populated by hv_ops_init; this avoids the PE static-symbol-pointer trap.
align 8
hv_ops_vmx:    times (HVOPS_ENT_SZ / 8) dq 0
hv_ops_svm:    times (HVOPS_ENT_SZ / 8) dq 0
hv_ops_active: dq 0
hv_ops_vendor: dq 0
hv_ops_detect_result: dq 0
hv_ops_enable_result: dq 0
hv_ops_setup_result:  dq 0
hv_ops_map_result:    dq 0
hv_ops_perf_vm_exits: dq 0              ; boot-monotonic completed dispatches
hv_ops_perf_host_cycles: dq 0            ; boot-monotonic fenced service TSC
hv_ops_perf_exit_start_tsc: dq 0         ; single resident-vCPU live interval
hv_ops_vendor_split_ok:      db 0
hv_ops_vmx_real_ok:          db 0
hv_ops_svm_stub_ok:          db 0
hv_ops_dispatch_selected_ok: db 0

str_verb_hvops: db "HVOPS", 0
str_hvops_vmx:  db "vmx", 0
str_hvops_svm:  db "svm", 0
str_hvops_active:      db "active", 0
str_hvops_query:       db "query", 0
str_hvops_call:        db "call", 0
str_hvops_selftest:    db "selftest", 0
str_hvops_backend_opt: db "--backend", 0
str_hvops_vendor_intel:   db "GenuineIntel", 0
str_hvops_vendor_amd:     db "AuthenticAMD", 0
str_hvops_vendor_unknown: db "unknown", 0
str_hvops_unsupported:    db "unsupported", 0

str_hvops_r_active:       db " HVOPS active=", 0
str_hvops_r_vendor:       db " vendor=", 0
str_hvops_r_backends:     db " backends=vmx,svm", 0
str_hvops_r_query:        db " HVOPS backend=", 0
str_hvops_r_registered:   db " registered=1", 0
str_hvops_r_real:         db " impl=real", 0
str_hvops_r_stub:         db " impl=stub degenerate=1", 0
str_hvops_r_call:         db " HVOPS call op=selftest backend=", 0
str_hvops_r_real_nonce:   db " impl=real nonce=", 0
str_hvops_r_stub_verdict: db " impl=stub verdict=not_implemented", 0
str_hvops_r_call_unavail: db " impl=real ERR not_available", 0
str_hvops_r_unknown:      db " HVOPS ERR unsupported backend=", 0
str_hvops_r_no_active:    db " HVOPS ERR unsupported active backend", 0
str_hvops_r_syntax:       db " HVOPS ERR syntax: active | query <backend> | call selftest <nonce> [--backend <backend>]", 0

str_hvops_m_split:    db "[PAOS64] P8 hv_ops: vmx + svm vtables registered [hv.ops.vendor_split]", 13, 10, 0
str_hvops_m_vmx:      db "[PAOS64] P8 hv_ops: Intel VMX backend is real [hv.ops.vmx.real]", 13, 10, 0
str_hvops_m_svm:      db "[PAOS64] P8 hv_ops: AMD SVM backend registered, guest gated by the START floor [hv.ops.svm.stub]", 13, 10, 0
str_hvops_m_selected: db "[PAOS64] P8 hv_ops: active backend selected from CPUID vendor [hv.ops.dispatch.selected]", 13, 10, 0
