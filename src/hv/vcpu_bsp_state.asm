;; MODULE hv/vcpu_bsp_state
;; LAYER 5
;; EXPORTS vcb_dr, vcb_debug, vcb_cr, vcb_cr0_cache, vcb_msr, vcb_xsetbv, vcb_lapic_msr, vcb_lapic_pick, vcb_cpuid, vcb_guest_msrs, vcb_efer_mask, vcb_entry_ctls, vcb_xcr0_allowed
;; IMPORTS hv/vcpu_svm_run, hv/vcpu_svm_dispatch, hv/vcpu_bsp, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_ap_mode, hv/vcpu_ap_efer, hv/vmx, hv/guest_lapic, hv/vcpu_cpuid
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Called only with READY1, both cores root,
; closed executors, IF0, and the selected vCPU's VMCS current on the BSP.
; START must freeze the three vCPU0 policy words, CPUID (48-bit linear
; addresses, no LA57), MSR list IDs/addresses and PAT/EFER swap controls.
; There is no READY publisher here. Only the CR0 fixed-bit MSRs are read;
; no host MSR or XCR0 write occurs.
%include "hv/vcpu_ap_xstate.inc"
%include "hv/vmx_cache.inc"

; MOV-DR exit qualification from the current selected VMCS. EAX1 done,
;2 #GP,3 #UD,4 GD #DB (no RIP advance). No physical debug instruction here.
; START hides RTM/bus-lock/debug extensions and fixes the 48-bit guest model.
; DR0..3 accept every64-bit value on Intel, including noncanonical addresses.
; VMCS saves/loads DR7; the entry engine switches private DR0..3 and DR6.
vcb_dr:
    cmp qword [rel vsr_enabled], 1
    je vsr_stop
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    cmp  dword [rel vcb_handoff_active], 1
    ja   vcb_fail_stop
    test rdi, ~0xF17
    jnz  vcb_fail_stop
    mov  r12d, edi
    mov  ebx, edi
    and  ebx, 7
    cmp  ebx, 4
    jb   .cpl
    cmp  ebx, 5
    ja   .cpl
    mov  edi, 0x6804
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    test eax, 8                       ; DR4/5 #UD precedes CPL and GD
    jnz  .ud
    add  ebx, 2                       ; legacy aliases of DR6/7
.cpl:
    mov  edi, 0x4818
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    test eax, 0x60
    jnz  .gp
    lea  r14, [rel vcb_debug]
    cmp  dword [rel vcb_handoff_active], 0
    je   .selected
    lea  r14, [rel vca_debug]
.selected:
    mov  edi, 0x681A
    vmread r15, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    test r15, 1 << 13
    jnz  .gd
    mov  edi, 0x4816
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    mov  r13d, eax                    ; actual CS.L selects operand width
    mov  eax, r12d
    shr  eax, 8
    and  eax, 0xF
    lea  rdx, [rel hv_linux_cr_gpr_map]
    movzx r15d, byte [rdx + rax]
    test r12d, 0x10
    jnz  .read
    cmp  r15d, 0xFF
    je   .source_rsp
    lea  rax, [rel hv_linux_gpr]
    mov  rsi, [rax + r15]
    jmp  .source
.source_rsp:
    mov  edi, 0x681C
    vmread rsi, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
.source:
    test r13d, 1 << 13
    jnz  .width
    mov  esi, esi                     ; all non64 modes use32-bit operands
.width:
    cmp  ebx, 6
    jb   .address_write
    mov  rax, rsi
    shr  rax, 32
    jnz  .gp                         ; DR6/7 bits63:32 are reserved
    cmp  ebx, 6
    jne  .dr7_write
    and  esi, 0xE00F
    or   esi, 0xFFFF0FF0              ; reserved/reset bits, no RTM/bus-lock
    mov  [r14 + 32], rsi
    jmp  .done
.dr7_write:
    and  esi, 0xFFFF23FF              ; hide RTM; bits12/14/15 read zero
    or   esi, 0x400                   ; bit10 reads one
    mov  edi, 0x681A
    vmwrite rdi, rsi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    jmp  .done
.address_write:
    mov  [r14 + rbx*8], rsi
    jmp  .done
.read:
    cmp  ebx, 7
    je   .dr7_read
    cmp  ebx, 6
    je   .dr6_read
    mov  rdx, [r14 + rbx*8]
    jmp  .dest
.dr6_read:
    mov  rdx, [r14 + 32]
    jmp  .dest
.dr7_read:
    mov  edi, 0x681A
    vmread rdx, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
.dest:
    test r13d, 1 << 13
    jnz  .dest_width
    mov  edx, edx
.dest_width:
    cmp  r15d, 0xFF
    je   .dest_rsp
    lea  rax, [rel hv_linux_gpr]
    mov  [rax + r15], rdx
    jmp  .done
.dest_rsp:
    mov  edi, 0x681C
    mov  rsi, rdx
    vmwrite rdi, rsi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    jmp  .done
.gd:
    mov  rsi, r15
    and  rsi, ~(1 << 13)
    mov  edi, 0x681A
    vmwrite rdi, rsi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    or   qword [r14 + 32], 1 << 13     ; private DR6.BD, never host DR6
    mov  eax, 4
    jmp  .out
.done:
    mov  eax, 1
    jmp  .out
.gp:
    mov  eax, 2
    jmp  .out
.ud:
    mov  eax, 3
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; S7 CR exits: START masks only CR0.CD/NW, CR3 load/store exiting off,
; and CR4 mask exactly these unadvertised features, with read shadow zero.
; Other CR0 changes normally run in hardware; a combined cache/mode write
; is emulated below. Only CD/NW may change in the frozen read-shadow record.
; START must hide LA57, VMX, KL, PKE and CET in the frozen guest CPUID.
VCB_CR4_DENIED equ (1 << 12) | (1 << 13) | (1 << 19) | (1 << 22) | (1 << 23)

; EDI actual exit qualification -> EAX1 emulated /2 #GP /3 #UD.
; Faults never advance RIP. Unexpected CR exits are internal failures.
; Both cores are root; the selected GPR image and VMCS are already installed.
vcb_cr:
    cmp qword [rel vsr_enabled], 1
    je vsm_cr
    push rbx
    push r12
    push r13
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    cmp  dword [rel vcb_handoff_active], 1
    ja   vcb_fail_stop
    test rdi, ~0xF3F                  ; only MOV type/GPR/CR bits are admitted
    jnz  vcb_fail_stop
    mov  r12d, edi
    mov  ebx, edi
    and  ebx, 0xF
    test ebx, ebx
    jz   .cr0
    cmp  ebx, 8
    je   .cr8_mode
    cmp  ebx, 4
    jne  vcb_fail_stop
    test r12d, 0x30                  ; CR4 read never traps with this mask
    jnz  vcb_fail_stop
    jmp  .cpl
.cr0:
    mov  rdi, r12
    call vcb_cr0_cache
    test eax, eax
    jz   vcb_fail_stop
    jmp  .out
.cr8_mode:
    test r12d, 0x20                  ; no CLTS/LMSW for CR8
    jnz  vcb_fail_stop
    mov  edi, 0x4816
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    test eax, 1 << 13                ; CR8 exists only in 64-bit mode
    jz   .ud
.cpl:
    mov  edi, 0x4818
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    test eax, 0x60
    jnz  .gp
    mov  eax, r12d
    shr  eax, 8
    and  eax, 0xF
    lea  rdx, [rel hv_linux_cr_gpr_map]
    movzx r13d, byte [rdx + rax]       ; RSP sentinel0xFF, all15 other GPRs
    test r12d, 0x10
    jnz  .cr8_read
    cmp  r13d, 0xFF
    je   .source_rsp
    lea  rax, [rel hv_linux_gpr]
    mov  rsi, [rax + r13]
    jmp  .source
.source_rsp:
    mov  edi, 0x681C
    vmread rsi, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
.source:
    cmp  ebx, 4
    je   .cr4
    test rsi, ~0xF
    jnz  .gp
    shl  esi, 4                      ; MOV CR8 clears TPR subpriority bits
    mov  edi, 0x808
    mov  edx, 1
    xor  ecx, ecx                    ; TPR has no timestamp input
    call vcb_lapic_msr
    cmp  eax, 1
    jne  vcb_fail_stop
    jmp  .done
.cr8_read:
    mov  edi, 0x808
    xor  edx, edx
    xor  ecx, ecx
    call vcb_lapic_msr
    cmp  eax, 1
    jne  vcb_fail_stop
    shr  edx, 4
    and  edx, 0xF
    cmp  r13d, 0xFF
    je   .dest_rsp
    lea  rax, [rel hv_linux_gpr]
    mov  [rax + r13], rdx
    jmp  .done
.dest_rsp:
    mov  edi, 0x681C
    mov  rsi, rdx
    vmwrite rdi, rsi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    jmp  .done
.cr4:
    mov  r12, rsi
    mov  edi, 0x6002
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    cmp  rax, VCB_CR4_DENIED
    jne  vcb_fail_stop
    mov  edi, 0x6006
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    test rax, rax
    jnz  vcb_fail_stop
    test r12, VCB_CR4_DENIED
    jnz  .gp                         ; an unadvertised feature was requested
    jmp  vcb_fail_stop               ; no denied bit -> impossible with this mask
.done:
    mov  eax, 1
    jmp  .out
.gp:
    mov  eax, 2
    jmp  .out
.ud:
    mov  eax, 3
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; MOV CR0 exit, either selected vCPU or legacy VMCS. RDI qualification.
; 1 committed /2 guest #GP /0 internal refusal (caller must never resume).
; Architectural CR0 checks happen before any VMCS write. Physical CR0 is
; never written here; VM entry ignores CD/NW and LAND clears them explicitly.
; CR0 fixed bits are sampled on this CPU; unrestricted guest relaxes PE/PG.
vcb_cr0_cache:
    push rbx
    push r12
    push r13
    push r14
    push r15
    test rdi, ~0xF00                   ; exactly MOV-to-CR0, one of16 source GPRs
    jnz  .bad
    mov  ebx, edi
    shr  ebx, 8
    mov  edi, 0x6000
    vmread rax, rdi
    jc   .bad
    jz   .bad
    cmp  rax, HV_CR0_CACHE_BITS
    jne  .bad
    mov  edi, 0x4818                   ; SS access rights: current privilege
    vmread rax, rdi
    jc   .bad
    jz   .bad
    test eax, 0x60
    jnz  .gp
    lea  rax, [rel hv_linux_cr_gpr_map]
    movzx eax, byte [rax + rbx]
    cmp  eax, 0xFF
    je   .rsp
    lea  rdx, [rel hv_linux_gpr]
    mov  r12, [rdx + rax]
    jmp  .value
.rsp:
    mov  edi, 0x681C
    vmread r12, rdi
    jc   .bad
    jz   .bad
.value:
    mov  rax, r12
    shr  rax, 32
    jnz  .gp                           ; CR0[63:32] are reserved
    and  r12d, 0xE005003F              ; lower reserved bits ignored, ET always1
    or   r12d, 1 << 4
    test r12d, 1 << 30
    jnz  .paging
    test r12d, 1 << 29
    jnz  .gp                           ; NW1/CD0 is illegal
.paging:
    bt   r12d, 31
    jnc  .fixed
    test r12b, 1
    jz   .gp                           ; PG requires PE
.fixed:
    mov  ecx, 0x486                   ; IA32_VMX_CR0_FIXED0
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  edx, 0x80000001
    not  rdx
    and  rax, rdx                    ; unrestricted guest allows PE/PG clear
    mov  rdx, r12
    not  rdx
    test rax, rdx
    jnz  .gp
    mov  ecx, 0x487                   ; IA32_VMX_CR0_FIXED1
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    not  rax
    test r12, rax
    jnz  .gp
    mov  edi, 0x6804
    vmread r13, rdi
    jc   .bad
    jz   .bad
    mov  edi, 0x2806
    vmread r14, rdi
    jc   .bad
    jz   .bad
    mov  edi, 0x4012
    vmread r15, rdi
    jc   .bad
    jz   .bad
    bt   r12d, 31
    jc   .pg_on
    test r13d, 1 << 17                ; PCIDE requires paging
    jnz  .gp
    mov  edi, 0x4816
    vmread rax, rdi
    jc   .bad
    jz   .bad
    test eax, 1 << 13                 ; cannot leave paging from a64-bit CS
    jnz  .gp
    jmp  .legacy_mode
.pg_on:
    test r14d, 1 << 8                 ; LME
    jz   .legacy_mode
    test r13d, 1 << 5                 ; IA32e activation requires PAE
    jz   .gp
    test r14d, 1 << 10
    jnz  .long_mode                    ; already active:64-bit CS is fine
    mov  edi, 0x4816
    vmread rax, rdi
    jc   .bad
    jz   .bad
    test eax, 1 << 13
    jnz  .gp
    mov  edi, 0x4822                  ; 16-bit TSS cannot activate IA32e
    vmread rax, rdi
    jc   .bad
    jz   .bad
    test eax, 8
    jz   .gp
.long_mode:
    or   r14d, 1 << 10
    or   r15d, 1 << 9
    jmp  .commit
.legacy_mode:
    and  r14, ~(1 << 10)
    and  r15, ~(1 << 9)
.commit:
    mov  edi, 0x6800
    mov  rsi, r12
    and  rsi, ~HV_CR0_CACHE_BITS
    vmwrite rdi, rsi
    jc   .bad
    jz   .bad
    mov  edi, 0x6004
    vmread rax, rdi
    jc   .bad
    jz   .bad
    and  rax, ~HV_CR0_CACHE_BITS
    mov  rsi, r12
    and  esi, HV_CR0_CACHE_BITS
    or   rsi, rax                      ; every non-cache shadow bit unchanged
    vmwrite rdi, rsi
    jc   .bad
    jz   .bad
    mov  edi, 0x2806
    mov  rsi, r14
    vmwrite rdi, rsi
    jc   .bad
    jz   .bad
    mov  edi, 0x4012
    mov  rsi, r15
    vmwrite rdi, rsi
    jc   .bad
    jz   .bad
    mov  eax, 1
    jmp  .out
.gp:
    mov  eax, 2
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI MSR, EDX 0 read /1 write, RSI write value -> EAX1 done /2 guest #GP;
; RDX read value. Internal failure is nonresuming, after VMCS retirement.
; The S7 model is closed: unimplemented MSRs fault instead of host passthrough.
vcb_msr:
    cmp qword [rel vsr_enabled], 1
    je vsm_msr
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 80                       ; mode tuple64, candidate8, write flag8
    mov  r12d, edi
    mov  r13, rsi
    mov  [rsp + 72], rdx
    cmp  edx, 1
    ja   vcb_fail_stop
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    cmp  dword [rel vcb_handoff_active], 1
    ja   vcb_fail_stop
    cmp  edi, 0xC0000080
    je   .efer
    cmp  edi, 0x277
    je   .pat
    xor  ebx, ebx
.find:
    lea  rax, [rel vcb_msr_ids]
    cmp  edi, [rax + rbx*4]
    je   .found
    inc  ebx
    cmp  ebx, 6
    jb   .find
    xor  ebx, ebx
.find_vmcs:
    lea  rax, [rel vcb_vmcs_msrs]
    cmp  r12d, [rax + rbx*8]
    je   .vmcs
    inc  ebx
    cmp  ebx, 5
    jb   .find_vmcs
    jmp  .gp
.vmcs:
    mov  r15d, [rax + rbx*8 + 4]
    cmp  qword [rsp + 72], 0
    je   .read_vmcs
    test ebx, ebx
    jz   .vmcs_width32
    mov  rax, r13
    shl  rax, 16
    sar  rax, 16
    cmp  rax, r13
    jne  .gp
    jmp  .write_vmcs
.vmcs_width32:
    mov  rax, r13
    shr  rax, 16
    jnz  .gp
.write_vmcs:
    mov  rdi, r15
    mov  rsi, r13
    vmwrite rdi, rsi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
.read_vmcs:
    mov  rdi, r15
    vmread rdx, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    jmp  .done
.found:
    lea  r14, [rel vcb_guest_msrs]
    cmp  dword [rel vcb_handoff_active], 0
    je   .list
    lea  r14, [rel vca_guest_msrs]
.list:
    shl  ebx, 4
    add  r14, rbx
    mov  eax, r12d
    cmp  [r14], rax                    ; ID32 and reserved32 must be exact
    jne  vcb_fail_stop
    cmp  qword [rsp + 72], 0
    je   .read_list
    cmp  r12d, 0xC0000084              ; FMASK has only low32 flag bits
    je   .width32
    cmp  r12d, 0xC0000103              ; TSC_AUX is32 bits
    je   .width32
    cmp  r12d, 0xC0000081              ; STAR low32 reserved on Intel
    je   .star
    mov  rax, r13                     ; LSTAR/CSTAR/KERNEL_GS_BASE canonical48
    shl  rax, 16
    sar  rax, 16
    cmp  rax, r13
    jne  .gp
    jmp  .store_list
.star:
    test r13d, r13d
    jnz  .gp
    jmp  .store_list
.width32:
    mov  rax, r13
    shr  rax, 32
    jnz  .gp
.store_list:
    mov  [r14 + 8], r13                ; commit only after all guest checks
.read_list:
    mov  rdx, [r14 + 8]
    jmp  .done
.pat:
    cmp  qword [rsp + 72], 0
    je   .read_pat
    mov  rax, r13
    mov  ecx, 8
.pat_byte:
    test al, 0xF8
    jnz  .gp
    cmp  al, 2
    je   .gp
    cmp  al, 3
    je   .gp
    shr  rax, 8
    loop .pat_byte
    mov  edi, 0x2804
    mov  rsi, r13
    vmwrite rdi, rsi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
.read_pat:
    mov  edi, 0x2804
    vmread rdx, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    jmp  .done
.efer:
    ; Re-read actual state, including hardware-saved LMA, before every write.
    mov  qword [rsp], 1
    mov  rax, [rel vcg_token]
    mov  [rsp + 8], rax
    mov  eax, [rel vcg_go]
    mov  [rsp + 16], rax
    xor  r15d, r15d
.mode:
    lea  rax, [rel vcb_mode_fields]
    mov  edi, [rax + r15*4]
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    mov  [rsp + r15*8 + 24], rax
    inc  r15d
    cmp  r15d, 5
    jb   .mode
    mov  ecx, [rel vcb_entry_ctls]
    mov  r14, [rel vcb_efer_mask]
    cmp  dword [rel vcb_handoff_active], 0
    je   .check_mode
    mov  rax, [rel vca_go_desc + 48]
    test rax, rax
    jz   vcb_fail_stop
    mov  ecx, [rax + 9*8]
    mov  r14, [rel vca_go_desc + 40]
.check_mode:
    mov  rdi, rsp
    mov  rsi, [rsp + 8]
    mov  rdx, [rsp + 16]
    mov  r8, r14
    call vcpu_ap_mode_check
    cmp  eax, 1
    jne  vcb_fail_stop
    cmp  qword [rsp + 72], 0
    je   .read_efer
    mov  rdi, rsp
    mov  rsi, r13
    lea  rdx, [rsp + 64]
    mov  rcx, r14
    call vcpu_ap_efer_write_check
    test eax, eax
    jz   .gp
    cmp  eax, 1
    jne  vcb_fail_stop
    mov  edi, 0x2806
    mov  rsi, [rsp + 64]
    vmwrite rdi, rsi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    mov  [rsp + 40], rsi
.read_efer:
    mov  rdx, [rsp + 40]
.done:
    mov  eax, 1
    jmp  .out
.gp:
    mov  eax, 2
    xor  edx, edx
.out:
    add  rsp, 80
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI guest XCR index, RSI value -> EAX0 accepted /1..8 #GP reason /9 #UD.
; EAX9 means #UD (guest OSXSAVE=0); CPL>0 faults with #GP.
; Only the private value changes; own entry/exit xstate machinery switches it.
vcb_xsetbv:
    cmp qword [rel vsr_enabled], 1
    je vsm_xsetbv
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    cmp  dword [rel vcb_handoff_active], 1
    ja   vcb_fail_stop
    mov  r10d, edi
    mov  r11, rsi
    mov  edi, 0x6804                    ; actual guest CR4
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    test eax, 1 << 18
    jz   .ud
    mov  edi, 0x4818                    ; guest SS access rights: current CPL
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    test eax, 0x60
    jnz  .gp
    mov  edi, r10d
    mov  rsi, r11
    mov  rdx, [rel vcb_xcr0_allowed]
    cmp  dword [rel vcb_handoff_active], 0
    je   .mask
    mov  rdx, [rel vca_xstate + VAX_ALLOWED]
.mask:
    test rdx, 1
    jz   vcb_fail_stop
    bt   rdx, 9
    jc   vcb_fail_stop                 ; PKRU is never admitted
    push rsi
    call hv_linux_xcr0_check
    pop  rsi
    test eax, eax
    jnz  .out
    mov  [rel hv_linux_guest_xcr0], rsi ; AP VALUE is swapped here for handoff
.out:
    ret
.ud:
    mov  eax, 9
    ret
.gp:
    mov  eax, 1
    ret

; These wrappers select the actual current vCPU's LAPIC, preserving arguments
; around glapic_instance. They never borrow vCPU0's record for a vCPU1 exit.
vcb_lapic_msr:
    push rdi
    push rsi
    push rdx
    push rcx
    sub  rsp, 8
    mov  edi, [rel vcb_handoff_active]
    cmp  edi, 1
    ja   vcb_fail_stop
    call glapic_instance
    test rax, rax
    jz   vcb_fail_stop
    mov  r8, rax
    add  rsp, 8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    jmp  glv_msr
vcb_lapic_pick:
    push rdi
    push rsi
    sub  rsp, 8
    mov  edi, [rel vcb_handoff_active]
    cmp  edi, 1
    ja   vcb_fail_stop
    call glapic_instance
    test rax, rax
    jz   vcb_fail_stop
    mov  r8, rax
    add  rsp, 8
    pop  rsi
    pop  rdi
    jmp  glv_inject_pick
vcb_cpuid:
    cmp qword [rel vsr_enabled], 1
    je vsm_cpuid
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    mov  r8d, [rel vcb_handoff_active]
    cmp  r8d, 1
    ja   vcb_fail_stop
    mov  eax, 0x6804                       ; actual selected guest CR4
    vmread rcx, rax
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    mov  rdx, [rel hv_linux_guest_xcr0]     ; selected by private handoff
    lea  r9, [rel vcb_cpuid_table]
    jmp  vcpuid_query

%macro WDATA_hv_vcpu_bsp_state 0
align 16, db 0
vcb_debug: dq 0,0,0,0,0xFFFF0FF0
align 16, db 0
vcb_guest_msrs:
    dq 0xC0000081, 0
    dq 0xC0000082, 0
    dq 0xC0000083, 0
    dq 0xC0000084, 0
    dq 0xC0000102, 0
    dq 0xC0000103, 0
vcb_efer_mask: dq 0
vcb_entry_ctls: dq 0
vcb_xcr0_allowed: dq 0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_bsp_state
align 4
vcb_msr_ids: dd 0xC0000081,0xC0000082,0xC0000083,0xC0000084,0xC0000102,0xC0000103
vcb_mode_fields: dd 0x6800,0x6804,0x2806,0x4816,0x4012

vcb_vmcs_msrs: dd 0x174,0x482A,0x175,0x6824,0x176,0x6826,0xC0000100,0x680E,0xC0000101,0x6810
