;; MODULE hv/vcpu_ap
;; LAYER 5
;; EXPORTS vcpu_ap_pick, vcpu_ap_idt_build, vcpu_ap_gang_open, vcg_gang_go, vcg_bsp_abort_seen, vcg_stop_down, vcpu_ap_park_hook, vcg_entry_bsp, vcg_entry_ap, vcg_root, vcg_ap
;; IMPORTS hv/vcpu_svm_inputs, hv/vcpu_svm_sample, hv/vcpu_svm_run, hv/vcpu_svm_life, hv/vcpu_start_inputs, hv/vcpu_cpuid_sample, hv/vcpu_bsp_fault, hv/vcpu_ap_run, hv/vcpu_ap_vmx, hv/boundary, core/smp, core/idt, core/time, svc/command_sched
;; CAPS
;; OWNER saga:hv
; T1-5 S7: vCPU1 of a two-vCPU guest runs on one designated AP, only inside the
; custody epoch the BSP already holds (SEC RULING C1-C9, ADDENDUM_1 D1-D4).
; This module is AP context: it is not bsp_only and calls nothing in vmx.asm
; or svm.asm.
;
; The gang. The BSP owns vCPU0 and custody; every other peer parks as today.
; The designated AP serves vCPU1 from its park (vcpu_ap_park_hook) while the
; custody generation it parked under is the one the BSP opened the gang for.
;   vcg_go    BSP: a new run cycle. Published after the BSP's own boundary
;             entry and its LIDT of its epoch IDT, never before.
;   vcg_down  BSP: = vcg_go when the cycle must end (any vCPU0 exit).
;   vcg_ack   AP: = vcg_go once the cycle ended: guest exited, boundary exit
;             run, VMCS cleared. Only then may the BSP run anything outside
;             C1's W-BSP list, the executor included (one executor at a time).
;   vcg_root  per core (0 BSP, 1 AP): 1 = root mode. The FIRST store of every
;             VM-exit stub and of every abort entry; 0 is the last store
;             before the boundary's final sequence and the entry. (D1)
;   vcg_abort bit 0 ABORT, bits 1-2 the core that raised it. Never cleared:
;             an abort ends the session without returning to any guest.
;
; Abort (C7, D1, D2). While a gang is open each core runs on its own epoch IDT:
; vectors 0-31 go to that core's abort entry, 32-255 are not present (#NP,
; which is vector 11, the same stub). The entry stores the core's root flag,
; then the shared stub claims the first retained frame (cmpxchg), records
; its vector/error/RIP, raises
; ABORT, kicks the other core and spins with IF=0 until the other core's root
; flag is 1. It has no callees and never IRETs, so after an NMI entry NMIs
; stay blocked and nothing returns to a guest. Then it ends in the boundary
; stop (BOUNDSTOP, nonresuming). If the other core does not report within
; 10 ms the AP halts forever and the BSP poisons custody first (C5).
;
; E1: from a VM exit to that core's executor exit, only direct jumps (no RET,
; CALL or indirect branch): the W-BSP sequence is the inline VCG_GANG_DOWN
; (vcpu_ap.inc), and every stop path runs VCG_STOP_FLOOR before the stop.
%include "hv/vcpu_ap.inc"

VCG_IDT_BYTES     equ 4096             ; a VM exit loads limit 0xFFFF: a full table
VCG_ENTRY_STRIDE  equ 16
VCG_REASON_DOWN   equ 0x301            ; vCPU1 did not end its cycle in time (C5)
VCG_REASON_ABORT  equ 0x302            ; the other core aborted
VCG_REC_BYTES     equ 24               ; per core: vector + 1 (0 = none), error code, RIP

; vcpu_ap_pick -> EAX = logical index of vCPU1's AP, or -1: vcpus>1 refuses.
; D4. Candidates run down from ncores-2 and never include c0 (owner, the BSP),
; c1 (forge), ncores-1 (realtime), the scheduler's realtime home, or the BSP's
; SMT sibling. The sibling relation comes from the exact topology sample: an
; inexact sample or any unreadable package/core row refuses. It is never read
; as "not a sibling". Preserves RBX, R12-R15.
vcpu_ap_pick:
    push rbx
    push r12
    push r13
    push r14
    cmp  byte [rel smp_topology_exact], 1
    jne  .refuse
    mov  r12d, [rel smp_discovered_count]
    cmp  r12d, 4
    jb   .refuse
    cmp  r12d, MAXCORE
    ja   .refuse
    xor  ecx, ecx
.rows:
    lea  rax, [rel cpu_package]
    cmp  dword [rax + rcx*4], -1
    je   .refuse
    lea  rax, [rel cpu_core]
    cmp  dword [rax + rcx*4], -1
    je   .refuse
    inc  ecx
    cmp  ecx, r12d
    jb   .rows
    mov  r13d, [rel cpu_package]           ; the BSP is row 0
    mov  r14d, [rel cpu_core]
    lea  ebx, [r12 - 2]
.candidate:
    cmp  ebx, 2
    jb   .refuse
    mov  eax, [rel sched_ncores]
    dec  eax
    cmp  ebx, eax
    je   .next                             ; the realtime home
    lea  rax, [rel cpu_state]
    cmp  byte [rax + rbx], CPU_STATE_ONLINE
    jne  .next
    lea  rax, [rel cpu_package]
    cmp  [rax + rbx*4], r13d
    jne  .found
    lea  rax, [rel cpu_core]
    cmp  [rax + rbx*4], r14d
    jne  .found
.next:
    dec  ebx
    jmp  .candidate
.found:
    mov  eax, ebx
    jmp  .out
.refuse:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vcpu_ap_idt_build RDI = 4 KiB table, RSI = vcg_entry_bsp or vcg_entry_ap.
; Vectors 0-31 -> RSI + vector * 16 as present DPL0 interrupt gates on the
; current CS; #DF keeps IST1 (D2). 32-255 stay zero, not present. An IDT
; installer (bsp_only_context_lint IDT_INSTALLERS, handler in RSI).
; Clobbers RAX, RCX, RDX, RDI, R8.
vcpu_ap_idt_build:
    cmp  qword [rel vca_ready], 0
    jne  .done
    push rdi
    xor  eax, eax
    mov  ecx, VCG_IDT_BYTES / 8
    rep  stosq
    pop  rdi
    mov  r8, rsi
    xor  ecx, ecx
.gate:
    mov  rax, r8
    mov  [rdi], ax                         ; offset 15:0
    mov  dx, cs
    mov  [rdi + 2], dx
    xor  edx, edx
    cmp  ecx, 8
    jne  .ist
    mov  edx, 1                            ; #DF on IST1
.ist:
    mov  [rdi + 4], dl
    mov  byte [rdi + 5], 0x8E              ; present, DPL0, 64-bit interrupt gate
    shr  rax, 16
    mov  [rdi + 6], ax                     ; offset 31:16
    shr  rax, 16
    mov  [rdi + 8], eax                    ; offset 63:32
    mov  dword [rdi + 12], 0
    add  r8, VCG_ENTRY_STRIDE
    add  rdi, 16
    inc  ecx
    cmp  ecx, 32
    jb   .gate
.done:
    ret

; vcpu_ap_gang_open EDI = vCPU1's logical CPU, RSI = BSP epoch IDT page,
; RDX = AP epoch IDT page. BSP at START, before any custody epoch serves the
; gang, so every word here is frozen for the AP (C4). Builds both tables and
; records the shared IDTR the BSP returns to. -> EAX 1, or 0 on a bad CPU.
vcpu_ap_gang_open:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    xor  eax, eax
    cmp  qword [rel vca_ready], 0
    jne  .out
    cmp  ebx, 1
    jbe  .out
    cmp  ebx, [rel smp_discovered_count]
    jae  .out
    mov  rdi, r12
    lea  rsi, [rel vcg_entry_bsp]
    call vcpu_ap_idt_build
    mov  rdi, r13
    lea  rsi, [rel vcg_entry_ap]
    call vcpu_ap_idt_build
    mov  word [rel vcg_idtr_bsp], VCG_IDT_BYTES - 1
    mov  [rel vcg_idtr_bsp + 2], r12
    mov  word [rel vcg_idtr_ap], VCG_IDT_BYTES - 1
    mov  [rel vcg_idtr_ap + 2], r13
    sidt [rel vcg_idtr_shared]
    lea  rax, [rel cpu_apic_id]
    mov  ecx, [rax]
    mov  [rel vcg_apic], ecx
    mov  ecx, [rax + rbx*4]
    mov  [rel vcg_apic + 4], ecx
    xor  eax, eax
    mov  [rel vcg_go], eax
    mov  [rel vcg_down], eax
    mov  [rel vcg_ack], eax
    mov  [rel vcg_abort], eax
    mov  qword [rel vcg_token], 0
    lea  rdi, [rel vcg_rec]
    mov  ecx, VCG_REC_BYTES * 2 / 8
    rep  stosq
    mov  [rel vcg_first_frame], rax
    mov  [rel vcg_first_frame + 8], rax
    mov  byte [rel vcg_root], 1
    mov  byte [rel vcg_root + 1], 1
    mov  [rel vcg_ap], ebx                 ; last: the AP serves only from here on
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; vcg_gang_go RDI = the BSP's live custody token. BSP, IF0, after its own
; boundary entry returned. The epoch IDT goes live BEFORE the cycle is
; published, so no host NMI/#MC handler can run on the BSP beside vCPU1.
vcg_gang_go:
    lidt [rel vcg_idtr_bsp]
    mov  [rel vcg_token], rdi
    inc  dword [rel vcg_go]
    ret

; Stops reached from VCG_GANG_DOWN, before the BSP's executor exit (E1):
; direct jumps only, then the floor. Neither returns.
; vCPU1 did not end its cycle within VCG_WAIT_MS (C5): poison, stop.
vcg_stop_down:
    mov  dword [rel smp_core_custody_gate], 4 ; C5: peers never leave the park
    VCG_STOP_FLOOR
    mov  edi, VCG_REASON_DOWN
    jmp  cpu_boundary_fail_stop_reason

; The AP raised ABORT. Wait (bounded) for it to report root mode, poison
; custody, stop.
vcg_bsp_abort_seen:
    VCG_DEADLINE r9
.wait:
    cmp  byte [rel vcg_root + 1], 1
    je   .stop
    pause
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, r9
    jb   .wait
.stop:
    mov  dword [rel smp_core_custody_gate], 4
    VCG_STOP_FLOOR
    mov  edi, VCG_REASON_ABORT
    jmp  cpu_boundary_fail_stop_reason

; vcpu_ap_park_hook: smp_core_custody_park's hold loop, every iteration.
; EBX = this CPU's logical index, R12 = the custody request it parked under,
; R13 = its live park guard; IF0. Serves vCPU1 only for the designated AP, in
; guarded parking (every other peer parked), for the generation the BSP opened
; the gang under. Its own boundary frame is custody kind 4 (P2): a copy of
; that token and the park's guard, held-checked at bind; finish drops only the
; copy and leaves the guard to the park. Returns once that generation is
; released; the park then departs as before. Preserves RBX, RBP, R12-R15.
vcpu_ap_park_hook:
    cmp  ebx, [rel vcg_ap]
    jne  .ret
    cmp  r12, [rel vcg_token]
    jne  .ret
    cmp  dword [rel smp_cc_svm_mode], 2
    jne  .ret
    test r13, r13
    jz   .ret
    push rbp                             ; align every served AP helper call
    cmp  qword [rel vca_ready], 0
    je   .prestart
    mov  rdi, r12
    cmp qword [rel vsr_enabled], 1
    je .svm_inputs
    call vst_inputs_check               ; before any epoch IDTR use
    jmp .inputs_done
.svm_inputs:
    call vsm_inputs_check
.inputs_done:
    cmp  eax, 1
    jne  vca_stop
.prestart:
    sidt [rel vcg_idtr_ap_save]
    lidt [rel vcg_idtr_ap]
    lea  rdi, [rel vcg_frame]
    mov  rsi, r12
    mov  edx, ebx
    mov  rcx, r13
    cmp qword [rel vsr_enabled], 1
    je .svm_bind
    call hv_boundary_gang_bind
    jmp .serve
.svm_bind:
    call hv_boundary_svm_gang_bind
.serve:
    test dword [rel vcg_abort], VCG_ABORT_BIT
    jnz  vcg_ap_abort_seen
    cmp  r12, [rel smp_cc_release]
    je   .end
    mov  eax, [rel vcg_go]
    cmp  eax, [rel vcg_ack]
    je   .idle
    mov  ebp, eax                         ; cycle preserves the exact GO
    mov  edi, eax
    call vcpu_ap_cycle
    mov  [rel vcg_ack], ebp
    jmp  .serve
.idle:
    lea  rdi, [rel vcg_frame]
    mov  rsi, r12
    mov  edx, ebx
    cmp qword [rel vsr_enabled], 1
    je .svm_poll
    call vcs_ap_poll
    jmp .polled
.svm_poll:
    call vsmc_ap_poll
.polled:
    pause
    jmp  .serve
.end:
    cmp qword [rel vsr_enabled], 1
    je .svm_end
    lea  rdi, [rel vca_vmx]
    call vcpu_ap_vmx_end
    jmp .finish
.svm_end:
    cmp qword [rel vsr_ctx1 + 48], 0
    jne vsr_stop
    cmp qword [rel vsr_ctx1 + 56], 0
    jne vsr_stop
.finish:
    lea  rdi, [rel vcg_frame]
    call hv_boundary_finish
    call vcpu_ap_epoch_end
    lidt [rel vcg_idtr_ap_save]
    pop  rbp
.ret:
    ret

; The BSP raised ABORT and this AP did not fault: stay in root mode, never
; return to the park. An NMI here enters this core's abort entry.
vcg_ap_abort_seen:
    cli
.halt:
    hlt
    jmp  .halt

; vcpu_ap_cycle EDI = cycle: one vCPU1 run until vcg_down or a deferred exit,
; ending with its VMCS cleared. Runtime remains closed until BSP START
; publishes vca_ready after the complete S7 initialization/writer gates.
vcpu_ap_cycle:
    cmp qword [rel vsr_enabled], 1
    je .svm
    jmp  vcpu_ap_run
.svm:
    mov esi, edi
    lea rdi, [rel vcg_frame]
    jmp vsr_run1

; End of this AP's custody epoch, still parked with IF0: re-post each host
; vector the epoch consumed on ack-on-exit, once, so the handlers that would
; have run after today's park still run after depart (P6). Only the AP's own
; vectors are re-posted (E4): its timer, resched, timer re-arm and coherence.
; The kick (0xEA) means nothing after depart and is dropped; any other vector
; is counted in vcg_hostvec_odd, never re-posted. Clears the record.
vcpu_ap_epoch_end:
    push rbx
    xor  ebx, ebx
.vector:
    bt   [rel vcg_hostvec], ebx
    jnc  .next
    btr  [rel vcg_hostvec], ebx
    cmp  ebx, SMP_IDLE_WAKE_VECTOR
    je   .next
    cmp  ebx, SMP_TIMER_VECTOR
    je   .repost
    cmp  ebx, SMP_RESCHED_VECTOR
    je   .repost
    cmp  ebx, SMP_TIMER_REARM_VECTOR
    je   .repost
    cmp  ebx, SMP_COHERENCE_VECTOR
    je   .repost
    inc  dword [rel vcg_hostvec_odd]
    jmp  .next
.repost:
    mov  edi, [rel vcg_apic + 4]
    mov  esi, SMP_ICR_FIXED
    or   esi, ebx
    call smp_lapic_send_ipi
.next:
    inc  ebx
    cmp  ebx, 256
    jb   .vector
    pop  rbx
    ret

; Abort entries: one 16-byte entry per vector, per core. The first store is
; the core's root flag (D1); vectors without a hardware error code push 0.
%macro VCG_ENTRY 3                     ; core, vector, push a dummy error code
%%e:
    mov  byte [rel vcg_root + %1], 1
%if %3
    push 0
%endif
    push %2
    jmp  vcg_abort_%1
    times VCG_ENTRY_STRIDE - ($ - %%e) db 0xCC
%endmacro
%macro VCG_ENTRIES 1
    VCG_ENTRY %1, 0, 1
    VCG_ENTRY %1, 1, 1
    VCG_ENTRY %1, 2, 1
    VCG_ENTRY %1, 3, 1
    VCG_ENTRY %1, 4, 1
    VCG_ENTRY %1, 5, 1
    VCG_ENTRY %1, 6, 1
    VCG_ENTRY %1, 7, 1
    VCG_ENTRY %1, 8, 0
    VCG_ENTRY %1, 9, 1
    VCG_ENTRY %1, 10, 0
    VCG_ENTRY %1, 11, 0
    VCG_ENTRY %1, 12, 0
    VCG_ENTRY %1, 13, 0
    VCG_ENTRY %1, 14, 0
    VCG_ENTRY %1, 15, 1
    VCG_ENTRY %1, 16, 1
    VCG_ENTRY %1, 17, 0
    VCG_ENTRY %1, 18, 1
    VCG_ENTRY %1, 19, 1
    VCG_ENTRY %1, 20, 1
    VCG_ENTRY %1, 21, 0
    VCG_ENTRY %1, 22, 1
    VCG_ENTRY %1, 23, 1
    VCG_ENTRY %1, 24, 1
    VCG_ENTRY %1, 25, 1
    VCG_ENTRY %1, 26, 1
    VCG_ENTRY %1, 27, 1
    VCG_ENTRY %1, 28, 1
    VCG_ENTRY %1, 29, 0
    VCG_ENTRY %1, 30, 0
    VCG_ENTRY %1, 31, 1
%endmacro

; The abort stub of core %1 (the other core is %2). Frame: vector, error code,
; RIP. Direct jumps only, no callees, no IRET (E1); the floor precedes the stop.
%macro VCG_ABORT 2
vcg_abort_%1:
    cli
    mov  rcx, rsp
    xor  eax, eax
    lock cmpxchg [rel vcg_first_frame + %1 * 8], rcx
    cmovnz rcx, rax                    ; re-entry helps the FIRST frame only
    ; SEC R1: the atomic claim retains all three original stack words, not
    ; just the vector. No entry returns/IRETs, so the winning frame remains
    ; live on this core's private host/IST stack. A nested entry can finish
    ; publication at any instruction boundary without resuming its parent.
    mov  rax, [rcx]
    inc  rax
    mov  [rel vcg_rec + %1 * VCG_REC_BYTES], rax
    mov  rax, [rcx + 8]
    mov  [rel vcg_rec + %1 * VCG_REC_BYTES + 8], rax
    mov  rax, [rcx + 16]
    mov  [rel vcg_rec + %1 * VCG_REC_BYTES + 16], rax
    lock or dword [rel vcg_abort], VCG_ABORT_BIT | (2 << %1)
    ; Kick the other core: in guest mode an IPI is an external-interrupt exit.
    ; Repeat on re-entry: ABORT could have been published before the first
    ; entry sent its kick. The fixed kick and ABORT OR are idempotent.
    mov  edx, [rel vcg_apic + %2 * 4]
    mov  eax, SMP_ICR_FIXED | VCG_KICK_VECTOR
    cmp  byte [rel smp_lapic_mode], 0
    je   .xapic
    mov  ecx, X2APIC_MSR_BASE + (0x300 >> 4)
    wrmsr
    jmp  .spin
.xapic:
    shl  edx, 24
    mov  rcx, LAPIC_ICR_HI
    mov  [rcx], edx
    mov  rcx, LAPIC_ICR_LO
    mov  [rcx], eax
.spin:
    VCG_DEADLINE r8
.wait:
    cmp  byte [rel vcg_root + %2], 1
    je   .other_root
    pause
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, r8
    jb   .wait
%if %1 = 1
.halt:
    hlt                                ; the BSP takes C5 itself
    jmp  .halt
%else
    mov  dword [rel smp_core_custody_gate], 4
    jmp  .stop
%endif
.other_root:
%if %1 = 0
    mov  dword [rel smp_core_custody_gate], 4 ; C5: peers never leave the park
%endif
.stop:
    ; Report the first recorded fault, not a nested NMI's frame.
    mov  rax, [rel vcg_rec + %1 * VCG_REC_BYTES]
    test rax, rax
    jz   .emit
    dec  rax
    mov  [rsp], rax
    mov  rax, [rel vcg_rec + %1 * VCG_REC_BYTES + 8]
    mov  [rsp + 8], rax
    mov  rax, [rel vcg_rec + %1 * VCG_REC_BYTES + 16]
    mov  [rsp + 16], rax
.emit:
%if %1 = 0
    jmp  vcb_fault_stop                 ; BSP retires any deferred AP handoff
%else
    VCG_STOP_FLOOR
    jmp  cpu_boundary_fault_stop
%endif
%endmacro

align 16
vcg_entry_bsp:
    VCG_ENTRIES 0
vcg_entry_ap:
    VCG_ENTRIES 1
VCG_ABORT 0, 1
VCG_ABORT 1, 0

%macro WDATA_hv_vcpu_ap 0
align 8
align 16, db 0
vcg_frame: times HVB_SIZE db 0         ; the AP's kind-4 boundary frame (P2)
vcg_token: dq 0
vcg_ap: dd -1
vcg_apic: dd 0, 0                      ; BSP, AP
vcg_go: dd 0
vcg_down: dd 0
vcg_ack: dd 0
vcg_abort: dd 0
vcg_root: db 1, 1
align 8
vcg_rec: times VCG_REC_BYTES * 2 db 0
vcg_first_frame: dq 0, 0               ; atomic per-core first retained fault frame
vcg_hostvec: times 32 db 0             ; host vectors consumed this epoch (P6)
vcg_hostvec_odd: dd 0                  ; consumed vectors outside the re-post list (E4)
vcg_idtr_bsp: dw 0
    dq 0
vcg_idtr_ap: dw 0
    dq 0
vcg_idtr_shared: dw 0
    dq 0
vcg_idtr_ap_save: dw 0
    dq 0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_ap
