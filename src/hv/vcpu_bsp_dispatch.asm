;; MODULE hv/vcpu_bsp_dispatch
;; LAYER 5
;; EXPORTS vcd_dispatch, vcd_ops_check
;; IMPORTS hv/vcpu_svm_run, hv/vcpu_svm_dispatch, hv/vcpu_bsp, hv/vcpu_bsp_state, hv/vcpu_bsp_lifecycle, hv/vcpu_ap, hv/vcpu_ap_run, hv/hv_ops, hv/vmx, hv/guest_lapic
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Closed deferred AP exit service, no guest
; entry, host scheduling, generic device pump, physical IRQ window or PCI.
; Both cores root/ACKed, executors closed, IF0, AP VMCS selected on BSP,
; epoch IDT installed and private GPR/state swap already complete.
; The sealed thin-smp2 profile contains console, timer and two LAPICs only.
; Shared UART/PIC/PIT/console state is serviced serially on this BSP.
; START grants READY only after the exact private profile and sealed-input checks.

; Check the exact five finite accessor targets BEFORE AP VMCS acquisition,
; including idle cycles. No alias/custom backend or changed slot is admitted.
; Repeat at the deferred dispatch entry. IF0 and the closed callee census
; exclude a writer between this check and the accessor tail jumps.
vcd_ops_check:
    cmp qword [rel vsr_enabled], 1
    je vsm_ops_check
    cmp  qword [rel vca_ready], 1
    jne  vcb_fail_stop
    lea  r11, [rel hv_ops_vmx]
    cmp  [rel hv_ops_active], r11
    jne  vcb_fail_stop
    lea  rax, [rel hv_vmx_can_inject_extint]
    cmp  [r11 + HVOPS_CAN_INJECT], rax
    jne  vcb_fail_stop
    lea  rax, [rel hv_vmx_inject_extint]
    cmp  [r11 + HVOPS_INJECT], rax
    jne  vcb_fail_stop
    lea  rax, [rel hv_vmx_guest_cr3]
    cmp  [r11 + HVOPS_GUEST_CR3], rax
    jne  vcb_fail_stop
    lea  rax, [rel hv_vmx_guest_read]
    cmp  [r11 + HVOPS_GUEST_READ], rax
    jne  vcb_fail_stop
    lea  rax, [rel hv_w]
    cmp  [r11 + HVOPS_GUEST_WRITE], rax
    jne  vcb_fail_stop
    ret

vcd_dispatch:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call vcl_check
    call vcd_ops_check
    mov  edi, VMXF_EXIT_REASON
    call vcd_read
    test eax, 0x80000000
    jnz  .entry_fail
    and  eax, 0xFFFF
    mov  [rel hv_exit_reason], eax
    inc  dword [rel hv_linux_exits]
    cmp  eax, 1
    je   vcb_fail_stop                 ; AP consumes host external IRQs locally
    cmp  eax, 7
    je   .intrwin
    cmp  eax, 10
    je   .cpuid
    cmp  eax, 12
    je   .hlt
    cmp  eax, 28
    je   .craccess
    cmp  eax, 29
    je   .draccess
    cmp  eax, 30
    je   .pio
    cmp  eax, 31
    je   .rdmsr
    cmp  eax, 32
    je   .wrmsr
    cmp  eax, 48
    je   .eptviol
    cmp  eax, 55
    je   .xsetbv
    ; Reason0/unknown/physical-timer exits stop, never invent progress.
.bad:
    mov  byte [rel hv_linux_load_err], 7
    inc  qword [rel hv_guestcpu_faults]
    xor  eax, eax
    jmp  .out
.entry_fail:
    mov  byte [rel hv_linux_load_err], 6
    inc  qword [rel hv_guestcpu_faults]
    xor  eax, eax
    jmp  .out
.cpuid:
    mov  edi, [rel hv_linux_gpr]
    mov  esi, [rel hv_linux_gpr + 16]
    call vcb_cpuid
    mov  [rel hv_linux_gpr], rax
    mov  [rel hv_linux_gpr + 8], rbx
    mov  [rel hv_linux_gpr + 16], rcx
    mov  [rel hv_linux_gpr + 24], rdx
    jmp  .skip
.rdmsr:
    mov  ecx, [rel hv_linux_gpr + 16]
    xor  edx, edx
    call hv_glapic_msr
    cmp  eax, GLAPIC_MSR_DONE
    je   .rd_glapic
    ja   .gp
    mov  edi, [rel hv_linux_gpr + 16]
    xor  esi, esi
    xor  edx, edx
    call vcb_msr
    cmp  eax, 1
    jne  .gp
    mov  rax, rdx
    jmp  .rd_value
.rd_glapic:
    mov  rax, [rel glapic_msr_value]
.rd_value:
    mov  rdx, rax
    shr  rdx, 32
    mov  eax, eax
    mov  [rel hv_linux_gpr], rax
    mov  [rel hv_linux_gpr + 24], rdx
    jmp  .skip
.wrmsr:
    mov  ecx, [rel hv_linux_gpr + 16]
    mov  edx, 1
    call hv_glapic_msr
    cmp  eax, GLAPIC_MSR_DONE
    je   .skip
    ja   .gp
    mov  edi, [rel hv_linux_gpr + 16]
    mov  esi, [rel hv_linux_gpr]
    mov  eax, [rel hv_linux_gpr + 24]
    shl  rax, 32
    or   rsi, rax
    mov  edx, 1
    call vcb_msr
    cmp  eax, 1
    jne  .gp
    jmp  .skip
.craccess:
    mov  edi, VMXF_EXIT_QUAL
    call vcd_read
    mov  rdi, rax
    call vcb_cr
    jmp  .state_result
.draccess:
    mov  edi, VMXF_EXIT_QUAL
    call vcd_read
    mov  rdi, rax
    call vcb_dr
    cmp  eax, 4
    je   .db
.state_result:
    cmp  eax, 3
    je   .ud
    cmp  eax, 2
    je   .gp
    cmp  eax, 1
    jne  vcb_fail_stop
    jmp  .skip
.xsetbv:
    mov  edi, [rel hv_linux_gpr + 16]
    mov  esi, [rel hv_linux_gpr]
    mov  eax, [rel hv_linux_gpr + 24]
    shl  rax, 32
    or   rsi, rax
    call vcb_xsetbv
    cmp  eax, 9
    je   .ud
    test eax, eax
    jz   .skip
    inc  dword [rel hv_xsetbv_refused]
    mov  [rel hv_xsetbv_last_refusal], al
.gp:
    mov  edi, VMXF_ENTRY_ERRCODE
    xor  esi, esi
    call vcd_write
    mov  esi, HV_GUEST_GP_INFO
    jmp  .fault
.ud:
    mov  esi, 0x80000306
    jmp  .fault
.db:
    mov  esi, 0x80000301
.fault:
    mov  edi, VMXF_ENTRY_INTR
    call vcd_write
    jmp  .resume                       ; faults never advance RIP
.hlt:
    inc  dword [rel hv_hlt_exits]
    inc  qword [rel hv_guestcpu_halt_wakes]
    call vcd_skip
    call vcl_hlt                       ; only legal queued IRQ/NMI may wake it
    jmp  .resume
.intrwin:
    mov  edi, VMXF_PROC_CTLS
    call vcd_read
    and  eax, ~(1 << 2)
    mov  esi, eax
    call vcd_write                     ; only the allowed window bit changes
    jmp  .resume
.eptviol:
    call vcd_console_mmio
    test eax, eax
    jz   .bad
    jmp  .resume
.skip:
    call vcd_skip
    jmp  .resume

.pio:
    mov  edi, VMXF_EXIT_QUAL
    call vcd_read
    mov  r8d, eax                            ; size/direction in qualification
    test r8d, 0x30                           ; string/REP needs a real decoder
    jnz  .bad
    mov  ecx, r8d
    and  ecx, 7
    cmp  ecx, 3
    ja   .bad
    cmp  ecx, 2                              ; reserved size encoding
    je   .bad
    mov  edx, eax
    shr  edx, 16
    and  edx, 0xFFFF                         ; port
    test r8d, 8
    jnz  .pio_in
    cmp  edx, 0xCF8
    je   .pio_out_vtd
    cmp  edx, 0xCFC
    jb   .pio_out_normal
    cmp  edx, 0xCFF
    jbe  .pio_out_vtd
.pio_out_normal:
    mov  eax, edx
    sub  eax, 0x3F8
    cmp  eax, 8
    jae  .pio_out_pitpic                     ; non-UART OUT: proven PIC/PIT-lite
    test eax, eax
    jnz  .pio_reg_out
    test byte [rel hv_linux_uart + 3], 0x80  ; DLAB overlays divisor latch
    jnz  .pio_reg_out
    mov  al, [rel hv_linux_gpr + 0]
    mov  word [rel hv_uart_thre], 0          ; RCQ-36: THR drains at once, THRE reasserts
    call hv_vcon_run_tail_byte              ; RUN observes real UART TX as well as hvc0
    call hv_linux_console_char
    jmp  .pio_done
.pio_reg_out:
    mov  cl, [rel hv_linux_gpr + 0]
    lea  rdi, [rel hv_linux_uart]
    cmp  eax, 1
    jne  .pio_reg_store
    test byte [rdi + 3], 0x80                ; DLM, not IER
    jnz  .pio_reg_store
    test byte [rdi + 1], 2
    jnz  .pio_reg_store
    test cl, 2
    jz   .pio_reg_store
    mov  word [rel hv_uart_thre], 0          ; RCQ-36: ETBEI 0->1 with THR empty asserts THRE
.pio_reg_store:
    mov  [rdi + rax], cl
    jmp  .pio_done
.pio_out_vtd:
    ; No PCI device exists in this sealed profile: ignore the OUT.
    jmp  .pio_done
.pio_in:
    cmp  edx, 0xCF8
    je   .pio_in_vtd
    cmp  edx, 0xCFC
    jb   .pio_in_normal
    cmp  edx, 0xCFF
    jbe  .pio_in_vtd
.pio_in_normal:
    mov  eax, edx
    sub  eax, 0x3F8
    cmp  eax, 8
    jae  .pio_in_pitpic
    cmp  eax, 5
    je   .pio_lsr
    cmp  eax, 2
    je   .pio_iir
    lea  rdi, [rel hv_linux_uart]
    movzx ecx, byte [rdi + rax]
    jmp  .pio_store
.pio_lsr:
    mov  ecx, 0x60                           ; THR empty + transmitter empty
    jmp  .pio_store
.pio_iir:
    mov  ecx, 1                              ; no pending interrupt
    test byte [rel hv_linux_uart + 1], 2     ; RCQ-36: ETBEI (IER; IIR ignores DLAB)
    jz   .pio_store
    cmp  byte [rel hv_uart_thre], 0
    jne  .pio_store
    mov  byte [rel hv_uart_thre], 1          ; reading IIR clears a THRE source
    mov  ecx, 2                              ; THR empty
    jmp  .pio_store
.pio_in_vtd:
    mov  ecx, -1                            ; absent PCI function
    jmp  .pio_store
.pio_in_ff:
    mov  ecx, -1
.pio_store:
    mov  rax, [rel hv_linux_gpr + 0]
    mov  edx, r8d
    and  edx, 7
    cmp  edx, 0
    je   .pio_byte
    cmp  edx, 1
    je   .pio_word
    mov  eax, ecx                            ; dword IN zero-extends
    jmp  .pio_store_done
.pio_byte:
    and  rax, -256
    movzx ecx, cl
    or   rax, rcx
    jmp  .pio_store_done
.pio_word:
    and  rax, -65536
    movzx ecx, cx
    or   rax, rcx
.pio_store_done:
    mov  [rel hv_linux_gpr + 0], rax
.pio_done:
    call vcd_skip
    jmp  .resume

    ; Real 8259A/8254-lite state, ported from Classic's live appliance path.
    ; ICW2 supplies the guest vector base; OCW1 supplies the real IRQ gates.
.pio_out_pitpic:
    mov  al, [rel hv_linux_gpr + 0]
    cmp  edx, 0x20
    je   .pic_m_cmd
    cmp  edx, 0x21
    je   .pic_m_data
    cmp  edx, 0xA0
    je   .pic_s_cmd
    cmp  edx, 0xA1
    je   .pic_s_data
    cmp  edx, 0x43
    je   .pit_ctl_wr
    cmp  edx, 0x61
    je   .p61_wr
    mov  ecx, edx
    sub  ecx, 0x40
    cmp  ecx, 3
    jb   .pit_data_wr
    jmp  .pio_done
.pic_m_cmd:
    test al, 0x10
    jz   .pio_done                         ; statelessly accept OCW2/OCW3
    mov  [rel hv_pic_icw1_m], al
    mov  byte [rel hv_pic_state_m], 1
    jmp  .pio_done
.pic_m_data:
    movzx ecx, byte [rel hv_pic_state_m]
    test ecx, ecx
    jz   .pic_m_mask
    cmp  ecx, 1
    jne  .pic_m_seq
    and  al, 0xF8
    mov  [rel hv_pic_vec_base], al
.pic_m_seq:
    movzx ecx, byte [rel hv_pic_state_m]
    cmp  ecx, 3
    jae  .pic_m_done
    cmp  ecx, 1
    jne  .pic_m_to4
    test byte [rel hv_pic_icw1_m], 2
    jz   .pic_m_expect3
.pic_m_to4:
    test byte [rel hv_pic_icw1_m], 1
    jz   .pic_m_done
    mov  byte [rel hv_pic_state_m], 3
    jmp  .pio_done
.pic_m_expect3:
    mov  byte [rel hv_pic_state_m], 2
    jmp  .pio_done
.pic_m_done:
    mov  byte [rel hv_pic_state_m], 0
    jmp  .pio_done
.pic_m_mask:
    mov  [rel hv_pic_mask], al
    jmp  .pio_done
.pic_s_cmd:
    test al, 0x10
    jz   .pio_done
    mov  [rel hv_pic_icw1_s], al
    mov  byte [rel hv_pic_state_s], 1
    jmp  .pio_done
.pic_s_data:
    movzx ecx, byte [rel hv_pic_state_s]
    test ecx, ecx
    jz   .pic_s_mask
    cmp  ecx, 3
    jae  .pic_s_done
    cmp  ecx, 1
    jne  .pic_s_to4
    test byte [rel hv_pic_icw1_s], 2
    jz   .pic_s_expect3
.pic_s_to4:
    test byte [rel hv_pic_icw1_s], 1
    jz   .pic_s_done
    mov  byte [rel hv_pic_state_s], 3
    jmp  .pio_done
.pic_s_expect3:
    mov  byte [rel hv_pic_state_s], 2
    jmp  .pio_done
.pic_s_done:
    mov  byte [rel hv_pic_state_s], 0
    jmp  .pio_done
.pic_s_mask:
    mov  [rel hv_pic_mask_s], al
    jmp  .pio_done
.p61_wr:
    call hv_pit2_gate_write
    jmp  .pio_done
.pit_ctl_wr:
    movzx ecx, al
    shr  ecx, 6
    cmp  ecx, 3
    je   .pio_done
    test al, 0x30
    jz   .pit_latch_cmd
    lea  rdi, [rel hv_pit_ff]
    mov  byte [rdi + rcx], 0
    lea  rdi, [rel hv_pit_latched]
    mov  byte [rdi + rcx], 0
    cmp  ecx, 2
    jne  .pio_done
    ; Exact implemented form: binary channel 2, low/high bytes, mode 0.
    ; Other PIT modes retain their existing, separately unqualified model.
    mov  byte [rel hv_pit2_mode0], 0
    mov  byte [rel hv_pit2_armed], 0
    mov  qword [rel hv_pit2_remaining], 0
    and  byte [rel hv_port61], 0xDF
    and  al, 0x3F
    cmp  al, 0x30
    jne  .pio_done
    mov  byte [rel hv_pit2_mode0], 1
    jmp  .pio_done
.pit_latch_cmd:
    push rdx
    call hv_pit_cur
    pop  rdx
    lea  rdi, [rel hv_pit_latch]
    mov  [rdi + rcx*2], ax
    lea  rdi, [rel hv_pit_latched]
    mov  byte [rdi + rcx], 1
    lea  rdi, [rel hv_pit_ff]
    mov  byte [rdi + rcx], 0
    jmp  .pio_done
.pit_data_wr:
    lea  rdi, [rel hv_pit_ff]
    cmp  byte [rdi + rcx], 0
    jne  .pit_wr_hi
    lea  rdi, [rel hv_pit_reload]
    mov  [rdi + rcx*2], al
    lea  rdi, [rel hv_pit_ff]
    mov  byte [rdi + rcx], 1
    cmp  ecx, 2
    jne  .pio_done
    cmp  byte [rel hv_pit2_mode0], 1
    jne  .pio_done
    ; Mode 0 stops on the first byte and restarts after the second.
    mov  byte [rel hv_pit2_armed], 0
    mov  qword [rel hv_pit2_remaining], 0
    and  byte [rel hv_port61], 0xDF
    jmp  .pio_done
.pit_wr_hi:
    lea  rdi, [rel hv_pit_reload]
    mov  [rdi + rcx*2 + 1], al
    lea  rdi, [rel hv_pit_ff]
    mov  byte [rdi + rcx], 0
    cmp  ecx, 2
    jne  .pio_done
    call hv_pit2_load
    jmp  .pio_done

.pio_in_pitpic:
    ; thin-smp2 has no CMOS clock. Its byte data port is inactive: UIP=0,
    ; VRT=0, day/month=0 (invalid calendar), not an ff "updating" clock.
    ; Linux's early RTC probe otherwise spins on UIP for 10,000 iterations,
    ; each paying real closed guest exits. No clock/NMI/IRQ or CMOS access
    ; is granted; index/data OUT remain ignored and wide IN stays absent.
    cmp  edx, 0x71
    jne  .in_pitpic_ports
    test r8d, 7
    jnz  .pio_in_ff
    jmp  .in_zero
.in_pitpic_ports:
    cmp  edx, 0x21
    je   .in_maskm
    cmp  edx, 0xA1
    je   .in_masks
    cmp  edx, 0x20
    je   .in_zero
    cmp  edx, 0xA0
    je   .in_zero
    cmp  edx, 0x61
    je   .in_p61
    mov  ecx, edx
    sub  ecx, 0x40
    cmp  ecx, 3
    jb   .in_pit
    jmp  .pio_in_ff
.in_maskm:
    movzx ecx, byte [rel hv_pic_mask]
    jmp  .pio_store
.in_masks:
    movzx ecx, byte [rel hv_pic_mask_s]
    jmp  .pio_store
.in_zero:
    xor  ecx, ecx
    jmp  .pio_store
.in_p61:
    call hv_pit2_update
    movzx ecx, byte [rel hv_port61]
    jmp  .pio_store
.in_pit:
    lea  rdi, [rel hv_pit_latched]
    cmp  byte [rdi + rcx], 0
    je   .in_pit_live
    lea  rdi, [rel hv_pit_latch]
    movzx eax, word [rdi + rcx*2]
    jmp  .in_pit_ff
.in_pit_live:
    push rcx
    push rdx
    call hv_pit_cur
    pop  rdx
    pop  rcx
    movzx eax, ax
.in_pit_ff:
    lea  rdi, [rel hv_pit_ff]
    cmp  byte [rdi + rcx], 0
    jne  .in_pit_hi
    mov  byte [rdi + rcx], 1
    movzx ecx, al
    jmp  .pio_store
.in_pit_hi:
    mov  byte [rdi + rcx], 0
    lea  rdi, [rel hv_pit_latched]
    mov  byte [rdi + rcx], 0
    movzx ecx, ah
    jmp  .pio_store

.resume:
    call hv_linux_reinject_vectoring     ; interrupted event owns the next entry
    call hv_glapic_try_inject            ; only selected AP LAPIC/local timer
    cmp  byte [rel hv_linux_stop_req], 1
    jne  .budget
    mov  byte [rel hv_linux_stop_req], 0
    xor  eax, eax
    jmp  .out
.budget:
    cmp  byte [rel hv_linux_kboot], 1
    je   .writes
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, [rel hv_linux_deadline]
    jb   .writes
    mov  byte [rel hv_linux_load_err], 8
    xor  eax, eax
    jmp  .out
.writes:
    cmp  dword [rel hv_vmwrite_fails], 0
    jne  .bad
    mov  eax, 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Checked reads preserve VMREAD's only result RAX. Writes go through the
; central selected-VMCS field gate; any failed VMWRITE refuses continuation.
vcd_read:
    cmp qword [rel vsr_enabled], 1
    je vsm_read
    vmread rax, rdi
    jc   vcb_fail_stop
    jz   vcb_fail_stop
    ret
vcd_write:
    cmp qword [rel vsr_enabled], 1
    je vsm_write
    call hv_w
    cmp  dword [rel hv_vmwrite_fails], 0
    jne  vcb_fail_stop
    ret

vcd_skip:
    mov  edi, VMXF_EXIT_ILEN
    call vcd_read
    mov  rdi, rax
; RDI authoritative decoded length,1..15. Clear the ESSENCE E3 shadow for
; every emulated completed instruction, including EPT-decoded console stores.
vcd_advance:
    cmp  rdi, 1
    jb   vcb_fail_stop
    cmp  rdi, 15
    ja   vcb_fail_stop
    push rbx
    mov  rbx, rdi
    mov  edi, VMXF_G_RIP
    call vcd_read
    lea  rsi, [rax + rbx]
    mov  edi, VMXF_G_RIP
    call vcd_write
    mov  edi, VMXF_G_INTERRUPT
    call vcd_read
    and  rax, ~3
    mov  rsi, rax
    call vcd_write
    pop  rbx
    ret

; Only the console's 4KiB write-trapped page exists in thin-smp2. Reads use
; the already mapped register page. Reuse the actual bounded store decoder,
; validated virtqueue service and console identity/boot/capture consumers.
; No assigned BAR, PCI, net, input, sound, entropy or restore emulation.
vcd_console_mmio:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  edi, VMXF_G_PHYS_ADDR
    call vcd_read
    mov  r12, rax
    mov  edi, VMXF_EXIT_QUAL
    call vcd_read
    mov  r13, rax
    call hv_linux_ept_capture_instruction
    mov  edi, VMXF_EXIT_ILEN
    call vcd_read
    mov  edx, eax
    mov  rdi, r12
    mov  rsi, r13
    call hv_linux_ept_classify
    test eax, eax
    jz   .bad
    mov  r15, r12
    mov  ecx, HV_VCON_GPA
    sub  r15, rcx
    cmp  r15, 0x1000
    jae  .bad
    mov  eax, r13d
    and  eax, 7
    cmp  eax, 2                          ; supported MOV store, never RMW/execute
    jne  .bad
    call hv_vcon_decode_store
    mov  r14d, eax
    mov  ebx, ecx                        ; decoded length survives note/write
    mov  [rel hv_vcon_ilen], ecx
    mov  [rel hv_vcon_iwidth], r9d
    movzx edi, r8b
    cmp  r9d, 4                          ; only console writel is supported
    je   .width
    xor  edi, edi
.width:
    mov  esi, ebx
    call hv_linux_ept_note_decode
    test eax, eax
    jz   .bad
    cmp  ebx, 1
    jb   .bad
    cmp  ebx, 15
    ja   .bad
    mov  edi, r15d
    mov  esi, r14d
    call hv_vcon_write
    mov  edi, ebx                        ; raw EPT exit length may be zero
    call vcd_advance
    inc  dword [rel hv_vcon_wr_ct]
    mov  eax, 1
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
