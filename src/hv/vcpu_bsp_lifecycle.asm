;; MODULE hv/vcpu_bsp_lifecycle
;; LAYER 5
;; EXPORTS vcl_service, vcl_poll, vcl_hlt, vcl_wake, vcl_check
;; IMPORTS hv/vcpu_svm_run, hv/vcpu_svm_dispatch, hv/vcpu_bsp, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_start_resources, hv/vcpu_start_vmcs, hv/vcpu_cpuid_sample, hv/vmx, hv/guest_lapic
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Virtual vCPU1 lifecycle on the agreed
; both-root path. BSP owns the cleared AP VMCS, epoch IDT and private GPR
; swap. No physical INIT/SIPI, native MSR/debug/vector access or guest entry.
; vCPU1 never consumes LAPIC startup requests on its physical AP: the one
; selected-vCPU executor on the BSP applies them after clear + exact GO ACK.
%include "hv/vcpu_ap_xstate.inc"
%include "hv/vmx_cache.inc"

; Return1 when a virtual INIT/SIPI invalidated the deferred exit, else0.
; Existing wait-for-SIPI remains inactive; a SIPI is the only wake from it.
vcl_service:
    push rbx
    push r12
    push r13
    call vcl_check
    cmp  byte [rel glapic_on], 1
    jne  vcb_fail_stop
    cmp  dword [rel glapic_vcpus], 2
    jne  vcb_fail_stop
    mov  edi, 1
    call glapic_instance
    test rax, rax
    jz   vcb_fail_stop
    mov  r8, rax
    call glv_startup_state
    cmp  eax, 4
    ja   vcb_fail_stop
    mov  r12d, eax
    call glv_take_startup
    mov  ebx, eax
    mov  r13d, edx
    cmp  r12d, 3                       ; INIT or INIT+SIPI, one closed reset
    jb   .startup
    call vcl_reset
.startup:
    cmp  ebx, 2
    je   .sipi
    cmp  ebx, 1
    je   .wait
    test ebx, ebx
    jnz  vcb_fail_stop
    test r12d, r12d
    jnz  vcb_fail_stop
    mov  edi, 0x4826
    call vcl_read
    cmp  rax, 1                        ; active0 or root-emulated HLT1
    ja   vcb_fail_stop
    xor  eax, eax
    jmp  .out
.wait:
    mov  edi, 0x4826
    call vcl_read
    cmp  rax, 3
    jne  vcb_fail_stop
    xor  eax, eax
    cmp  r12d, 3
    sete al
    jmp  .out
.sipi:
    cmp qword [rel vsr_enabled], 1
    je .svm_sipi
    cmp  r13d, 255
    ja   vcb_fail_stop
    mov  edi, 0x4826
    call vcl_read
    cmp  rax, 3                        ; never force active/running into SIPI
    jne  vcb_fail_stop
    mov  edi, 0x802                    ; real-mode CS selector = vector <<8
    mov  esi, r13d
    shl  esi, 8
    call vcl_write
    mov  edi, 0x6808                   ; CS base = vector <<12
    mov  esi, r13d
    shl  esi, 12
    call vcl_write
    mov  edi, 0x681E                   ; reset RIP and interrupt shadow
    xor  esi, esi
    call vcl_write
    mov  edi, 0x4824
    xor  esi, esi
    call vcl_write
    mov  edi, 0x4826                   ; actual activity0 LAST, virtual SIPI
    xor  esi, esi
    call vcl_write
    mov  eax, 1
    jmp .out
.svm_sipi:
    call vsm_sipi
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Poll a root-idle/local-timer cycle, never dispatch stale VM-exit fields.
vcl_poll:
    sub  rsp, 8
    call vcl_check
    mov  edi, 0x4826
    call vcl_read
    cmp  rax, 3
    je   .done                        ; no event may wake virtual wait-SIPI
    cmp  rax, 1
    ja   vcb_fail_stop
    call hv_glapic_try_inject          ; only this vCPU's LAPIC/timer
    call vcl_wake
.done:
    mov  eax, 1
    add  rsp, 8
    ret

; HLT instruction has already advanced RIP/cleared STI/MOVSS shadow.
; Only the AP handoff uses this; the established BSP idle loop is unchanged.
vcl_hlt:
    sub  rsp, 8
    call vcl_check
    mov  edi, 0x4826
    call vcl_read
    test rax, rax
    jnz  vcb_fail_stop
    mov  edi, 0x4826
    mov  esi, 1
    call vcl_write
    add  rsp, 8
    ret

; A checked queued interrupt/NMI wakes HLT. A kick or pending-but-masked
; LAPIC bit alone never activates it. No guest event can wake wait-SIPI.
vcl_wake:
    sub  rsp, 8
    call vcl_check
    mov  edi, 0x4826
    call vcl_read
    test rax, rax
    jz   .done
    cmp  rax, 3
    je   .done
    cmp  rax, 1
    jne  vcb_fail_stop
    mov  edi, 0x4016
    call vcl_read
    test eax, 1 << 31
    jz   .done
    mov  r10d, eax
    and  eax, 0x7FFFFF00
    test eax, eax
    jz   .external
    cmp  eax, 0x200
    jne  vcb_fail_stop
    cmp  r10b, 2
    jne  vcb_fail_stop
    mov  edi, 0x4824
    call vcl_read
    test eax, (1 << 1) | (1 << 3)
    jnz  vcb_fail_stop
    jmp  .activate
.external:
    cmp  r10b, 16
    jb   vcb_fail_stop
    mov  edi, 0x6820
    call vcl_read
    test eax, 1 << 9
    jz   vcb_fail_stop
    mov  edi, 0x4824
    call vcl_read
    test eax, 3
    jnz  vcb_fail_stop
.activate:
    mov  edi, 0x4826
    xor  esi, esi
    call vcl_write
.done:
    add  rsp, 8
    ret

; Exact generation-bound closed handoff, before any VMCS read or write.
vcl_check:
    cmp qword [rel vsr_enabled], 1
    je vsm_closed_check
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    cmp  dword [rel vcb_handoff_active], 1
    jne  vcb_fail_stop
    cmp  word [rel vcg_root], 0x101
    jne  vcb_fail_stop
    cmp  dword [rel vcg_abort], 0
    jne  vcb_fail_stop
    cmp  qword [rel vca_vmx + 56], 0
    jne  vcb_fail_stop
    cmp  qword [rel vca_xstate + VAX_SAVED], 0
    jne  vcb_fail_stop
    mov  rax, [rel hv_vmx_boundary_frame]
    test rax, rax
    jz   vcb_fail_stop
    cmp  qword [rax + HVB_ACTIVE], 0
    jne  vcb_fail_stop
    cmp  qword [rax + HVB_FRONTIER], 0
    jne  vcb_fail_stop
    mov  edx, [rel vcg_go]
    test edx, edx
    jz   vcb_fail_stop
    cmp  edx, [rel vcg_down]
    jne  vcb_fail_stop
    cmp  edx, [rel vcg_ack]
    jne  vcb_fail_stop
    cmp  rdx, [rel vca_go_desc + 24]
    jne  vcb_fail_stop
    mov  rdx, [rax + HVB_LEASE]
    test rdx, rdx
    jz   vcb_fail_stop
    cmp  rdx, -1
    je   vcb_fail_stop
    cmp  rdx, [rel vcg_token]
    jne  vcb_fail_stop
    cmp  rdx, [rel vca_go_desc + 16]
    jne  vcb_fail_stop
    mov  rax, [rel vca_reset]
    test rax, rax
    jz   vcb_fail_stop
    cmp  rax, [rel vca_go_desc + 8]
    jne  vcb_fail_stop
    sub  rsp, 8
    vmptrst [rsp]
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    mov  rax, [rsp]
    add  rsp, 8
    cmp  rax, [rel vca_vmx + 16]
    jne  vcb_fail_stop
    ret

; A virtual INIT cancels all private guest state/events under the same
; START policy. Preserve immutable MSR IDs, automatic host restore lists,
; capability templates and the monotonic reset generation until completion.
vcl_reset:
    cmp qword [rel vsr_enabled], 1
    je vsm_reset
    push rbx
    cmp  qword [rel vca_reset], -1
    je   vcb_fail_stop
    lea  rbx, [rel vst_reset_table]
.field:
    mov  edi, [rbx]
    cmp  edi, -1
    je   .dynamic
    mov  rsi, [rbx + 8]
    call vcl_write
    add  rbx, 16
    jmp  .field
.dynamic:
    mov  rsi, [rel vcs_ap_caps + 40]
    and  esi, 0x7FFFFFFE
    or   esi, 0x10                     ; physical CD/NW clear; reset shadow is separate
    mov  edi, 0x6800
    call vcl_write
    mov  rsi, [rel vst_ap_controls + 9*8]
    and  rsi, ~(1 << 9)                 ; reset LMA=0, every other bit exact
    mov  edi, 0x4012
    call vcl_write
    mov  rsi, [rel vst_ap_controls + 8]  ; cancel dynamic window requests
    mov  edi, 0x4002
    call vcl_write
    xor  esi, esi
    mov  edi, 0x4016
    call vcl_write
    mov  edi, 0x4018
    call vcl_write
    mov  edi, 0x401A
    call vcl_write
    lea  rdi, [rel hv_linux_gpr]         ; AP-selected records after swap
    xor  eax, eax
    mov  ecx, 15
    rep  stosq
    lea  rdi, [rel vca_debug]
    mov  ecx, 5
    rep  stosq
    mov  dword [rel vca_debug + 32], 0xFFFF0FF0
    mov  qword [rel vca_guest_cr2], 0
    lea  rdi, [rel vca_guest_msrs + 8]
    mov  ecx, 6
.msr:
    mov  [rdi], rax
    add  rdi, 16
    dec  ecx
    jnz  .msr
    mov  rdi, [rel vca_xstate + VAX_GUEST]
    test rdi, rdi
    jz   vcb_fail_stop
    cmp  qword [rel vca_xstate + VAX_CAPACITY], 65536
    jne  vcb_fail_stop
    mov  ecx, 65536 / 8
    rep  stosq
    mov  rdi, [rel vca_xstate + VAX_GUEST]
    mov  word [rdi], 0x037F
    mov  dword [rdi + 24], 0x1F80
    mov  qword [rel hv_linux_guest_xcr0], 3
    inc  qword [rel vca_reset]          ; no reuse/wrap; complete state first
    mov  rax, [rel vca_reset]
    mov  [rel vca_go_desc + 8], rax
    pop  rbx
    ret

vcl_read:
    cmp qword [rel vsr_enabled], 1
    je vsm_read
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    ret
vcl_write:
    cmp qword [rel vsr_enabled], 1
    je vsm_write
    vmwrite rdi, rsi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    ret
