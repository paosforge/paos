;; MODULE dev/net/e1000e_bus_route
;; LAYER 3
;; EXPORTS e1000e_bus_cfg_read32, e1000e_bus_cfg_write32, e1000e_bus_route_active, e1000e_bus_identity, e1000e_a1_native_gate
;; IMPORTS bus/pci, boot/serial, boot/smbios, boot/native_driver_gate, hv/a1_service_selection
;; CAPS
;; OWNER saga:net
; ============================================================================
; dev/net/e1000e_bus_route.asm — off-bus-0 routing for the proven e1000e driver.
;
; dev/net/e1000e.asm discovers its controller on PCI bus 0 only (the I219 of the
; Lenovo/Dell sits at 0:1f.6; QEMU's e1000 at bus 0). An add-in Intel CT 82574L
; behind a root port lives on another bus (MSI MS-7E19: 81:00.0) and was never
; found. Ported from the metal-proven MSI wrapper (paos_msi src/paos.asm
; msi_nic_cfg_read32/write32), but keyed on live PCI topology, not on a trial flag:
;
;   * If ANY Intel Ethernet controller (class 0x02 00) exists on bus 0, routing
;     stays OFF and both wrappers are exact tail-calls of pci_cfg_read32/write32:
;     Lenovo, Dell and every QEMU bus-0 NIC keep byte-identical behaviour.
;   * Otherwise, when EXACTLY ONE 82574L (8086:10d3) exists on another bus, the
;     driver's bus-0 config accesses for that dev/fn are redirected to it; every
;     other bus-0 dev/fn reads as absent, and the only permitted config write is
;     the PCI Command register of that one device. Register/DMA/reset logic in
;     e1000e.asm is untouched.
;   * HP CT (PETER 2026-09-30 06:22, AuthenticAMD only): after routing, every
;     bridge above the routed card gets Command MEM|BM if clear (e1kr_upstream_bridges);
;     GenuineIntel returns before any PCI access, so the MSI path is unchanged.
;
; paos.asm wraps ONLY the e1000e include with
;   %define pci_cfg_read32 e1000e_bus_cfg_read32 / pci_cfg_write32 ...
; so resolution calls the real functions (this module is included before it).
; Discovery is lazy (first wrapped access) and uses CF8/CFC port config cycles,
; valid both pre- and post-ExitBootServices.
; ============================================================================

%include "boot/native_driver_gate.inc"

E1KR_82574L_VENDEV equ 0x10D38086

e1000e_bus_route_resolve:
    cmp  byte [rel e1kr_resolved], 1
    je   .ret
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    push rax
    mov  byte [rel e1kr_resolved], 1
    mov  dword [rel e1kr_bus0_intel_eth], 0
    mov  dword [rel e1kr_matches], 0
    lea  rdi, [rel e1kr_scan_cb]
    call pci_scan_with_filter
    cmp  dword [rel e1kr_bus0_intel_eth], 0
    jne  .done
    cmp  dword [rel e1kr_matches], 1
    jne  .done
    mov  byte [rel e1000e_bus_route_active], 1
    lea  rdi, [rel str_e1kr_routed]
    call serial_string
    mov  edi, [rel e1kr_bus]
    call serial_hex64
    lea  rdi, [rel str_e1kr_routed_tail]
    call serial_string
    call e1kr_upstream_bridges
.done:
    pop  rax
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
.ret:
    ret

; pci_scan_with_filter callback(EDI=bus, ESI=dev, EDX=fn, ECX=vendev).
; May clobber caller-saved registers; must preserve RBX/RBP/R12-R15.
e1kr_scan_cb:
    A1_NATIVE_NIC_SKIP rdi,rsi,rdx,.out ; physical BDF, before bridge enables
    cmp  cx, 0x8086
    jne  .out
    test edi, edi
    jnz  .off_bus0
    mov  ecx, 0x08                         ; class code | revision
    call pci_cfg_read32
    shr  eax, 16
    cmp  ax, 0x0200                        ; Ethernet controller
    jne  .out
    inc  dword [rel e1kr_bus0_intel_eth]
    ret
.off_bus0:
    cmp  ecx, E1KR_82574L_VENDEV
    jne  .out
    inc  dword [rel e1kr_matches]
    mov  [rel e1kr_bus], edi
    mov  [rel e1kr_dev], esi
    mov  [rel e1kr_fn], edx
.out:
    ret

; e1kr_upstream_bridges — HP CT (AuthenticAMD + HP SMBIOS identity only; GenuineIntel
;   and other AMD machines return before any PCI access, so the MSI's routed path and
;   a non-HP AMD board's firmware bridge state are unchanged). The HP's add-in slots hang off
;   AMD GPP root ports and, for the chipset slots, a PCIe switch (the AX99100 sits on
;   bus 9); no PaOS code enables those bridges and a firmware that binds no driver to the
;   CT (no UEFI UNDI on a retail CT) may leave Memory Space / Bus Master clear. Every
;   type-1 bridge whose [secondary, subordinate] range contains the routed CT's bus gets
;   Command |= MEM|BM when either bit is clear (status half written as 0: RW1C-safe).
;   Reports bridges seen / enabled. Preserves RBX (callback preserves the rest it must).
e1kr_upstream_bridges:
    push rbx
    xor  eax, eax
    cpuid
    cmp  ebx, 0x68747541                   ; 'Auth'
    jne  .out
    cmp  edx, 0x69746E65                   ; 'enti'
    jne  .out
    cmp  ecx, 0x444D4163                   ; 'cAMD'
    jne  .out
    call smbios_hp_quirk_identity          ; the HP's slots, not every AMD board
    test eax, eax
    jz   .out
    mov  dword [rel e1kr_br_seen], 0
    mov  dword [rel e1kr_br_enabled], 0
    lea  rdi, [rel e1kr_bridge_cb]
    call pci_scan_with_filter
    lea  rdi, [rel str_e1kr_bridges]
    call serial_string
    mov  edi, [rel e1kr_br_seen]
    call serial_hex64
    lea  rdi, [rel str_e1kr_bridges_en]
    call serial_string
    mov  edi, [rel e1kr_br_enabled]
    call serial_hex64
    lea  rdi, [rel str_e1kr_bridges_tail]
    call serial_string
.out:
    pop  rbx
    ret

; pci_scan_with_filter callback(EDI=bus, ESI=dev, EDX=fn, ECX=vendev). pci_cfg_read32
;   clobbers RAX/R8/RDX and pci_cfg_write32 RAX/R9/RDX, so fn lives in R11.
e1kr_bridge_cb:
    mov  r11d, edx                         ; fn
    mov  ecx, 0x08                         ; class code | revision
    call pci_cfg_read32
    shr  eax, 16
    cmp  eax, 0x0604                       ; PCI-to-PCI bridge (type-1 header)
    jne  .out
    mov  edx, r11d
    mov  ecx, 0x18                         ; primary | secondary | subordinate
    call pci_cfg_read32
    mov  r10d, eax
    shr  r10d, 8
    and  r10d, 0xFF                        ; secondary bus
    shr  eax, 16
    and  eax, 0xFF                         ; subordinate bus
    mov  r9d, [rel e1kr_bus]
    cmp  r9d, r10d
    jb   .out
    cmp  r9d, eax
    ja   .out
    inc  dword [rel e1kr_br_seen]
    mov  edx, r11d
    mov  ecx, 0x04
    call pci_cfg_read32
    mov  r10d, eax
    and  eax, 0x06
    cmp  eax, 0x06
    je   .out                              ; MEM + BM already set: no write
    mov  r8d, r10d
    and  r8d, 0xFFFF                       ; Command only (Status RW1C bits <- 0)
    or   r8d, 0x06                         ; Memory Space + Bus Master
    mov  edx, r11d
    mov  ecx, 0x04
    call pci_cfg_write32
    inc  dword [rel e1kr_br_enabled]
.out:
    ret

; Read-only physical BDF qualification for an already-selected native device.
; ESI=logical bus0 device, EDX=function -> EAX=physical bus0..255, or -1.
; Never resolve/discover, enable bridges, read PCI, or change route state here.
; Settled routing metadata and the caller's bounded dev/fn must agree. Callers
; retain the returned bus with their existing dev/fn/BAR/lifetime identity.
e1000e_bus_identity:
    cmp esi, 32
    jae .bad
    cmp edx, 8
    jae .bad
    cmp byte [rel e1kr_resolved], 1
    jne .bad
    cmp byte [rel e1000e_bus_route_active], 0
    je .bus0
    cmp byte [rel e1000e_bus_route_active], 1
    jne .bad
    cmp dword [rel e1kr_bus0_intel_eth], 0
    jne .bad
    cmp dword [rel e1kr_matches], 1
    jne .bad
    cmp esi, [rel e1kr_dev]
    jne .bad
    cmp edx, [rel e1kr_fn]
    jne .bad
    mov eax, [rel e1kr_bus]
    test eax, eax
    jz .bad
    cmp eax, 255
    ja .bad
    ret
.bus0:
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; ESI/EDX logical dev/fn after config discovery -> CF1 skip/CF0 keep.
; Resolve is already complete. Match the physical routed bus, never bus0 alias.
; Every GPR survives, and this path does not discover or enable anything.
e1000e_a1_native_gate:
%ifdef PAOS_A1_SERVICE_LINKED
    push rax
    push rdi
    push rcx                         ; align nested calls, preserve all GPRs
    cmp dword [rel a1_service_state],1
    jne .allow
    call e1000e_bus_identity
    cmp eax,-1
    je .deny
    mov edi,eax
    call a1_native_nic_gate
    pop rcx
    pop rdi
    pop rax
    ret
.allow:
    pop rcx
    pop rdi
    pop rax
    clc
    ret
.deny:
    pop rcx
    pop rdi
    pop rax
    stc
    ret
%else
    clc
    ret
%endif

; Exact pci_cfg_read32 ABI: EDI=bus, ESI=dev, EDX=fn, ECX=offset -> EAX.
e1000e_bus_cfg_read32:
    call e1000e_bus_route_resolve
    cmp  byte [rel e1000e_bus_route_active], 1
    jne  pci_cfg_read32
    test edi, edi
    jnz  .absent                           ; the driver only ever addresses bus 0
    cmp  esi, [rel e1kr_dev]
    jne  .absent
    cmp  edx, [rel e1kr_fn]
    jne  .absent
    mov  edi, [rel e1kr_bus]
    jmp  pci_cfg_read32
.absent:
    mov  eax, -1
    ret

; Exact pci_cfg_write32 ABI: EDI=bus, ESI=dev, EDX=fn, ECX=offset, R8D=value.
; While routed, only the selected device's PCI Command register may be written.
e1000e_bus_cfg_write32:
    call e1000e_bus_route_resolve
    cmp  byte [rel e1000e_bus_route_active], 1
    jne  pci_cfg_write32
    test edi, edi
    jnz  .refuse
    cmp  esi, [rel e1kr_dev]
    jne  .refuse
    cmp  edx, [rel e1kr_fn]
    jne  .refuse
    cmp  ecx, 0x04
    jne  .refuse
    mov  edi, [rel e1kr_bus]
    jmp  pci_cfg_write32
.refuse:
    ret

e1kr_resolved:          db 0
e1000e_bus_route_active: db 0
align 4
e1kr_bus0_intel_eth:    dd 0
e1kr_matches:           dd 0
e1kr_bus:               dd 0
e1kr_dev:               dd 0
e1kr_fn:                dd 0
e1kr_br_seen:           dd 0
e1kr_br_enabled:        dd 0
str_e1kr_routed:        db "[PAOS64] L2 netdev: e1000e routed to the single off-bus-0 82574L bus=", 0
str_e1kr_routed_tail:   db " (no Intel Ethernet on bus 0) [netdev.e1000e.offbus.routed]", 13, 10, 0
str_e1kr_bridges:       db "[PAOS64] L2 netdev: e1000e routed 82574L upstream bridges (AuthenticAMD) seen=", 0
str_e1kr_bridges_en:    db " enabled=", 0
str_e1kr_bridges_tail:  db " [netdev.e1000e.offbus.bridges]", 13, 10, 0
