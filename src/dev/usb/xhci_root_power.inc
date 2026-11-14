; Finite class-owned root power cycle. Internal native API, not a command.
; RDI=original hc*, ESI=root port, EDX=retained generation,
; RCX=retained16B topology, R8=separate caller-owned80B receipt (zero beforehand).
; Caller consumes its class incarnation before this one offer. No reoffer on
; uncertainty. Only the selected root leaf is touched; no reset/enumeration.
; EAX=receipt.status:0 complete logical cycle;1refused;2no PPC;3no off witness;
; 4unconfirmed retirement;5power restoration unconfirmed;6no reconnect witness.
; Attached reinit gate may return -1 without a receipt. Nonzero is never proof.
; Receipt schema,size,status,flags u32; hc u64; root,gen u32; topo[16];
; before,off,on,hcc,off_reads,on_reads,fence,reserved u32. Flags:1validated,
; 2off written,4PP0/CCS0 observed,8retirement confirmed,16on written,32PP1/CCS1.
; Raw CCS is a logical observation, not independent electrical VBUS evidence.
xhci_device_root_power_cycle:
    XHCI_POWER_GATE 1
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15, rcx
    mov  rbp, r8
    test rbp, rbp
    jz   .no_receipt
    mov  rdi, rbp
    xor  eax, eax
    mov  ecx, 10
    rep stosq
    mov  dword [rbp], 1
    mov  dword [rbp+4], 80
    mov  dword [rbp+8], 1
    mov  dword [rbp+72], -1
    test r15, r15
    jz   .out
    test r14d, r14d
    jz   .out
    mov  rdi, r12
    call xhci_hc_instance
    cmp  eax, -1
    je   .out
    mov  rdi, r12
    call xhci_inst_live_for
    cmp  r14d, [rel xhci_generation]
    jne  .out
    test r13d, r13d
    jz   .out
    cmp  r13d, [rel xhci_maxports]
    ja   .out
    cmp  r13d, XHCI_PORT_COUNT
    jae  .out
    bt   dword [rel xhci_port_quar], r13d
    jc   .out
    mov  esi, r13d
    call xhci_interrupt_slot_for_port
    test eax, eax
    jz   .out
    bt   dword [rel xhci_slot_quar], eax
    jc   .out
    mov  ebx, eax
    shl  eax, 4
    lea  rdx, [rel xhci_slot_topo]
    add  rdx, rax
    cmp  [rdx + usb_topo.slot], bl
    jne  .out
    cmp  [rdx + usb_topo.root], r13b
    jne  .out
    cmp  byte [rdx + usb_topo.depth], 0
    jne  .out
    cmp  dword [rdx + usb_topo.parent_slot], 0
    jne  .out
    cmp  dword [rdx + usb_topo.route], 0
    jne  .out
    cmp  word [rdx + usb_topo.hub_ports], 0
    jne  .out
    mov  rax, [rdx]
    cmp  rax, [r15]
    jne  .out
    mov  [rbp+32], rax
    mov  rax, [rdx+8]
    cmp  rax, [r15+8]
    jne  .out
    mov  [rbp+40], rax
    mov  [rbp+16], r12
    mov  [rbp+24], r13d
    mov  [rbp+28], r14d
    mov  esi, XHCI_HCCPARAMS1
    call xh_rd
    mov  [rbp+60], eax
    test eax, XHCI_HCC_PPC
    jz   .unsupported
    mov  edi, r13d
    call xhci_read_portsc_live
    mov  [rbp+48], eax
    mov  edx, eax
    and  edx, (XHCI_PORTSC_PP | XHCI_PORTSC_CCS)
    cmp  edx, (XHCI_PORTSC_PP | XHCI_PORTSC_CCS)
    jne  .out
    ; Original raw route validated before the first effect. Preserve only the
    ; spec's neutral writable state; PP0 must never acknowledge RW1C/PED/reset.
    mov  dword [rbp+12], 1
    mov  edi, r13d
    call xhci_portsc_off
    mov  [rsp], eax
    mov  esi, eax
    call xh_rd
    and  eax, (XHCI_PORTSC_NEUTRAL & ~XHCI_PORTSC_PP)
    mov  edx, eax
    mov  esi, [rsp]
    or   dword [rbp+12], 2
    call xh_wr
    mov  dword [rbp+8], 3
    mov  ebx, 100
.off_poll:
    mov  edi, r13d
    call xhci_read_portsc_live
    mov  [rbp+52], eax
    inc  dword [rbp+64]
    test eax, (XHCI_PORTSC_PP | XHCI_PORTSC_CCS)
    jz   .disconnected
    mov  edi, 1000
    call tsc_delay_us
    dec  ebx
    jnz  .off_poll
    jmp  .restore
.disconnected:
    or   dword [rbp+12], 4
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, r14d
    mov  rcx, r15
    call xhci_device_root_retire
    mov  [rbp+72], eax
    mov  dword [rbp+8], 4
    test eax, eax
    jnz  .restore
    or   dword [rbp+12], 8
    mov  dword [rbp+8], 0
.restore:
    ; Always restore after an off write, including missing-off or failed-fence
    ; paths. No second disable, class activation, retry or health reset follows.
    mov  esi, [rsp]
    call xh_rd
    and  eax, XHCI_PORTSC_NEUTRAL
    or   eax, XHCI_PORTSC_PP
    mov  edx, eax
    mov  esi, [rsp]
    or   dword [rbp+12], 16
    call xh_wr
    mov  edi, XHCI_PP_SETTLE_US
    call tsc_delay_us
    mov  ebx, 100
.on_poll:
    mov  edi, r13d
    call xhci_read_portsc_live
    mov  [rbp+56], eax
    inc  dword [rbp+68]
    mov  edx, eax
    and  edx, (XHCI_PORTSC_PP | XHCI_PORTSC_CCS)
    cmp  edx, (XHCI_PORTSC_PP | XHCI_PORTSC_CCS)
    je   .restored
    mov  edi, 1000
    call tsc_delay_us
    dec  ebx
    jnz  .on_poll
    ; Keep earlier off/fence failure if one already occurred. Receipt always
    ; retains independent restoration failure for the original caller.
    cmp  dword [rbp+8], 0
    jne  .out
    mov  dword [rbp+8], 5
    test dword [rbp+56], XHCI_PORTSC_PP
    jz   .out
    mov  dword [rbp+8], 6
    jmp  .out
.restored:
    or   dword [rbp+12], 32
    jmp  .out
.unsupported:
    mov  dword [rbp+8], 2
.out:
    mov  eax, [rbp+8]
    jmp  .return
.no_receipt:
    mov  eax, 1
.return:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
