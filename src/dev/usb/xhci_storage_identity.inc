; Included once by xhci.asm in the complete boot-policy composition.
; xhci_storage_bdf(RDI=exact registered usb_hc dev*) -> RAX segment0 BDF/-1.
; Read-only identity, no HAL/MMIO, swap, power admission or ownership change.
; The PCI scanner registers only segment0 backends. Other/unknown HC is denied.
; Preserves nonvolatile registers, clobbers caller-saved.
xhci_storage_bdf:
    sub rsp, 8
    cmp dword [rel xhci_inst_n], XHCI_INST_MAX
    ja .bad
    call xhci_hc_instance
    cmp eax, [rel xhci_inst_n]
    jae .bad
    mov ecx, [rel xhci_inst_cur]
    cmp ecx, [rel xhci_inst_n]
    jae .bad
    lea r8, [rel xhci_inst_r1]
    cmp eax, ecx
    je .state
    imul eax, XHCI_INST_BYTES
    lea r8, [rel xhci_inst_save]
    add r8, rax
.state:
    mov eax, [r8 + (xhci_bus - xhci_inst_r1)]
    cmp eax, 255
    ja .bad
    shl eax, 8
    mov ecx, [r8 + (xhci_dev - xhci_inst_r1)]
    cmp ecx, 31
    ja .bad
    shl ecx, 3
    or eax, ecx
    mov ecx, [r8 + (xhci_fn - xhci_inst_r1)]
    cmp ecx, 7
    ja .bad
    or eax, ecx
    add rsp, 8
    ret
.bad:
    mov rax, -1
    add rsp, 8
    ret
