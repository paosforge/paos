;; MODULE svc/reinit_power_e1000e
;; LAYER 5
;; EXPORTS reinit_power_e1000e_s5, reinit_power_e1000e_snapshot, reinit_power_e1000e_register, reinit_power_e1000e_tx
;; IMPORTS svc/reinit_power, net/netdev, dev/net/e1000e, dev/net/e1000e_bus_route, bus/hal, bus/pci, core/lib/mem, core/time
;; CAPS mmio dma
;; OWNER saga:resource
;; CONTEXT: bsp_only
; Explicit retained polling Intel82574 attachment. Retained callbacks do not
; reset or change PCI power state. Separate terminal S5 entry below never resumes.
; No allocation/free, IOMMU change or boot invocation. The native DMA buffers and
; context remain pinned even on failure. BSP serializes registration/work.
; Hardware isolation is not introduced or claimed by this adapter.
%include "core/abi/driver_power.inc"

; Terminal BSP-only S5 leaf; caller holds IF clear after disk/ACPI preparation.
; RDI=trusted32-byte report -> EAX:0 other backend,1 confirmedD3,-1 no-effect
; refusal,-2 fenced/uncertain. Report8dwords:result,stage(0preflight,1fenced,
; 2master-stopped,3D3-requested,4D3-readback),PMCSRbefore/after,Commandafter,
; master polls,reserved0,reserved0. Caller must never resume after stage>=1,
; including a successful D3 followed by a returned PM1/firmware sleep request.
; Exact native8086:10d3, settled BDF/class generation/BAR/rings only. No scan,
; reset, buffer release/reuse, PHY/APM/filter/NVM write or D3->D0 rollback.
; Intel82574 datasheet rev3.4 §§3.1.3.10,5.4.4.2.3,9.1.3.4: fence producers,
; mask interrupts, drain TX, master-disable/ack BEFORE clearing BM/enteringD3.
; PMCSR's upper word is RO (unimplemented BSE/data); PME_Status is W1C and
; receives0. Disable PME_En while preserving Data_Select and unrelated fields.
reinit_power_e1000e_s5:
    cld
    test rdi,rdi
    jz .null
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,72                         ; snapshot64 + saved RCTL/TCTL
    mov rbx,rdi
    xor eax,eax
    mov ecx,4
    rep stosq
    cmp dword [rel ep_s5_latched],0
    je .first
    mov dword [rbx+4],1
    jmp .uncertain                     ; no duplicate PCI/MMIO even after failure
.first:
    cmp byte [rel e1000e_is_82574l],1
    jne .out
    cmp byte [rel e1000e_is_qemu],0
    jne .out
    mov rdi,rsp
    call reinit_power_e1000e_snapshot
    test eax,eax
    jnz .refused
    mov r14d,[rsp+24]                  ; walked PM capability, never guessed
    mov r15d,[rsp+32]
    mov [rbx+8],r15d
    test r15d,3                        ; only a live D0 function can be stopped
    jnz .refused
    cmp byte [rel e1000e_tx_busy],0
    jne .refused
    cmp byte [rel e1000e_rx_busy],0
    jne .refused
    mov r12d,1
    call reinit_power_e1000e_set        ; native ownership/BAR/DMA admission
    test rax,rax
    jnz .refused
    call reinit_power_e1000e_rings
    test rax,rax
    jnz .refused
    mov esi,E1000_IMS
    call reinit_power_e1000e_rd
    jc .refused
    test eax,eax                       ; only the native polling attachment
    jnz .refused
    mov esi,E1000_CTRL
    call reinit_power_e1000e_rd
    jc .refused
    test eax,E1000_CTRL_RST | E1000_CTRL_PHYRST
    jnz .refused
    mov r13d,eax
    mov esi,E1000_RCTL
    call reinit_power_e1000e_rd
    jc .refused
    mov [rsp+64],eax
    mov esi,E1000_TCTL
    call reinit_power_e1000e_rd
    jc .refused
    mov [rsp+68],eax
    xor r12d,r12d
    call reinit_power_e1000e_set        ; final route/PCI/BAR/pin revalidation
    test rax,rax
    jnz .refused
    lea rdi,[rel e1000e_dev]
    lea rsi,[rel e1000e_ops]
    call netdev_power_member
    test rax,rax
    jz .refused
    cmp rdx,[rsp+40]
    jne .refused
    mov esi,[rel e1000e_pci_dev]
    mov edx,[rel e1000e_pci_fn]
    call e1000e_bus_identity
    cmp eax,[rsp+8]
    jne .refused
    ; This is a terminal ownership latch, not a retained-plan pause. Keep
    ; every DMA allocation pinned and reject all native lifecycle/producers.
    mov dword [rel ep_s5_latched],1
    mov dword [rbx+4],1
    lea rax,[rel reinit_power_e1000e_s5_gate]
    mov [rel e1000e_power_gate],rax
    mov ebp,1000
.tx_wait:
    call reinit_power_e1000e_tx_drained
    test rax,rax
    jz .mask
    mov edi,100
    call tsc_delay_us
    dec ebp
    jnz .tx_wait
    jmp .uncertain
.mask:
    mov esi,E1000_IMC
    mov edx,-1
    call reinit_power_e1000e_wr
    jc .uncertain
    mov esi,E1000_IMS
    call reinit_power_e1000e_rd
    jc .uncertain
    test eax,eax
    jnz .uncertain
    mov esi,E1000_RCTL
    mov edx,[rsp+64]
    and edx,~E1000_RCTL_EN
    call reinit_power_e1000e_wr
    jc .uncertain
    mov esi,E1000_RCTL
    call reinit_power_e1000e_rd
    jc .uncertain
    mov edx,[rsp+64]
    and edx,~E1000_RCTL_EN
    cmp eax,edx
    jne .uncertain
    mov esi,E1000_TCTL
    mov edx,[rsp+68]
    and edx,~E1000_TCTL_EN
    call reinit_power_e1000e_wr
    jc .uncertain
    mov esi,E1000_TCTL
    call reinit_power_e1000e_rd
    jc .uncertain
    mov edx,[rsp+68]
    and edx,~E1000_TCTL_EN
    cmp eax,edx
    jne .uncertain
    mov esi,E1000_CTRL
    mov edx,r13d
    or edx,E1000_CTRL_GIO_MASTER_DISABLE
    call reinit_power_e1000e_wr
    jc .uncertain
    mov esi,E1000_CTRL
    call reinit_power_e1000e_rd
    jc .uncertain
    or r13d,E1000_CTRL_GIO_MASTER_DISABLE
    cmp eax,r13d
    jne .uncertain
    mov ebp,1000                       ; at most100ms nominal, no IRQ clock
.master_wait:
    inc dword [rbx+20]
    mov esi,E1000_STATUS
    call reinit_power_e1000e_rd
    jc .uncertain
    cmp eax,-1
    je .uncertain
    test eax,E1000_STATUS_GIO_MASTER_ENABLE
    jz .master_stopped
    mov edi,100
    call tsc_delay_us
    dec ebp
    jnz .master_wait
    jmp .uncertain
.master_stopped:
    mov dword [rbx+4],2
    xor ecx,ecx
    call reinit_power_e1000e_pci
    cmp eax,0x10d38086
    jne .uncertain
    mov ecx,4
    call reinit_power_e1000e_pci
    cmp eax,-1
    je .uncertain
    mov r8d,eax
    and r8d,0xfffb                     ; low Command only; Status W1C gets0
    mov ecx,4
    call reinit_power_e1000e_s5_pci_write
    mov ecx,4
    call reinit_power_e1000e_pci
    mov [rbx+16],eax
    test eax,4
    jnz .uncertain
    xor ecx,ecx
    call reinit_power_e1000e_pci
    cmp eax,0x10d38086
    jne .uncertain
    lea ecx,[r14+4]
    call reinit_power_e1000e_pci
    test eax,3
    jnz .uncertain
    mov r8d,eax
    and r8d,~0x8103                    ; no PME enable; never acknowledge PME_Status
    or r8d,3
    lea ecx,[r14+4]
    mov dword [rbx+4],3                ; latch BEFORE potentially lost write
    call reinit_power_e1000e_s5_pci_write
    ; No MMIO from this point: D3 can remove BAR decode immediately.
    lea ecx,[r14+4]
    call reinit_power_e1000e_pci
    mov [rbx+12],eax
    and eax,0x103
    cmp eax,3
    jne .uncertain
    mov ecx,4
    call reinit_power_e1000e_pci
    mov [rbx+16],eax
    test eax,7                         ; D3 disables IO/MEM; BM already cleared
    jnz .uncertain
    mov dword [rbx+4],4
    mov eax,1
    jmp .out
.refused:
    mov eax,-1
    jmp .out
.uncertain:
    mov eax,-2
.out:
    mov [rbx],eax
    add rsp,72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.null:
    mov eax,-1
    ret

reinit_power_e1000e_s5_gate:
    cld
    mov rax,DP_BUSY
    ret

reinit_power_e1000e_s5_pci_write:
    mov edi,[rel ep_bus]
    mov esi,[rel e1000e_pci_dev]
    mov edx,[rel e1000e_pci_fn]
    jmp pci_cfg_write32

; Terminal S5 observation, independent of opt-in retained power registration.
; RDI=trusted 64-byte kernel buffer -> EAX=result. Read-only PCI configuration
; of the already registered native 82574 and already settled physical BDF;
; never resolves/discovers, reads MMIO/PHY, resets, writes PMCSR/PME or stops DMA.
; No device-state conclusion follows from a failed/partial sample.
; Wire: u32 schema=1,result(0complete,1unavailable,2identity,3bad-chain,4no-PM),
; bus,devfn(dev<<8|fn),vendev,command_status,PMoffset,PMcap_dword,PMCSR_dword,
; read_count; u64 registration_generation,reserved0,reserved0. 64 bytes total.
; Bounded by the 48 aligned standard capability slots; a visited bitmap rejects
; cycles. Only type0 headers, exact8086:10d3 and PMcap+PMCSR within256 bytes.
reinit_power_e1000e_snapshot:
    test rdi, rdi
    jz .null
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    mov rbx, rdi
    mov rdi, rsp
    mov ecx, 8
    xor eax, eax
    cld
    rep stosq
    mov dword [rsp], 1
    mov dword [rsp+4], 1
    cmp byte [rel e1000e_is_82574l], 1
    jne .publish
    cmp byte [rel e1000e_is_qemu], 0
    jne .publish
    cmp byte [rel e1000e_nic_absent], 0
    jne .publish
    lea rdi, [rel e1000e_dev]
    lea rsi, [rel e1000e_ops]
    call netdev_power_member
    test rax, rax
    jz .publish
    mov [rsp+64], rax
    mov r15, rdx
    mov [rsp+40], rdx
    mov r13d, [rel e1000e_pci_dev]
    mov r14d, [rel e1000e_pci_fn]
    mov esi, r13d
    mov edx, r14d
    call e1000e_bus_identity                ; settled getter, zero discovery
    cmp eax, -1
    je .publish
    mov r12d, eax
    mov [rsp+8], eax
    mov eax, r13d
    shl eax, 8
    or eax, r14d
    mov [rsp+12], eax
    mov dword [rsp+4], 2
%macro EP_DIAG_PCI 1
    mov edi, r12d
    mov esi, r13d
    mov edx, r14d
%ifidni %1, ecx
%else
    mov ecx, %1
%endif
    call pci_cfg_read32
    inc dword [rsp+36]
%endmacro
    EP_DIAG_PCI 0
    mov [rsp+16], eax
    cmp eax, 0x10d38086
    jne .publish
    EP_DIAG_PCI 8
    shr eax, 16
    cmp eax, 0x0200
    jne .publish
    EP_DIAG_PCI 0x0c
    shr eax, 16
    and eax, 0x7f
    jnz .publish                           ; type0 standard header only
    EP_DIAG_PCI 4
    mov [rsp+20], eax
    mov dword [rsp+4], 4
    test eax, 1<<20                        ; PCI Status.CAP_LIST
    jz .publish
    EP_DIAG_PCI 0x34
    movzx ecx, al
    xor ebp, ebp                           ; one bit per standard dword slot
.cap:
    test ecx, ecx
    jz .publish                            ; end without PM cap -> no-PM
    mov dword [rsp+4], 3
    cmp ecx, 0x40
    jb .publish
    cmp ecx, 0xfc
    ja .publish
    test ecx, 3
    jnz .publish
    mov eax, ecx
    shr eax, 2
    bts rbp, rax
    jc .publish                            ; repeat/cycle, no polling
    EP_DIAG_PCI ecx
    cmp al, 1                              ; standard PCI Power Management
    je .pm
    shr eax, 8
    movzx ecx, al
    mov dword [rsp+4], 4
    jmp .cap
.pm:
    cmp ecx, 0xf8                          ; PMCSR must still fit below0x100
    ja .publish
    mov [rsp+24], ecx
    mov [rsp+28], eax
    add ecx, 4
    EP_DIAG_PCI ecx
    mov [rsp+32], eax
    mov dword [rsp+4], 2
    EP_DIAG_PCI 0
    cmp eax, [rsp+16]
    jne .publish
    ; Recheck class lifetime and route after the bounded reads. No MMIO
    ; follows any identity drift. Preserve the physical BDF in this sample.
    lea rdi, [rel e1000e_dev]
    lea rsi, [rel e1000e_ops]
    call netdev_power_member
    cmp rax, [rsp+64]
    jne .publish
    cmp rdx, r15
    jne .publish
    mov esi, r13d
    mov edx, r14d
    call e1000e_bus_identity
    cmp eax, r12d
    jne .publish
    mov dword [rsp+4], 0
.publish:
    mov rdi, rbx
    mov rsi, rsp
    mov ecx, 8
    rep movsq
    mov eax, [rsp+4]
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.null:
    mov eax, 1
    ret

; RDI=initialized plan, ESI=dependency kind bitmap of already registered participants.
; Existing class registration is mandatory; publishing admission is LAST.
reinit_power_e1000e_register:
    cld
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12d, esi
    mov [rel ep_dependencies], esi
    mov rax, DP_BUSY
    cmp qword [rel e1000e_power_gate], 0
    jne .out
    cmp qword [rel reinit_power_e1000e_context], 0
    jne .out
    lea rdi, [rel e1000e_dev]
    lea rsi, [rel e1000e_ops]
    call netdev_power_member
    test rax, rax
    jz .unsupported
    ; Bind the actual native operations, never a same-address replacement.
%macro EP_OP 1
    lea rax, [rel e1000e_%1]
    cmp [rel e1000e_ops+netdev_ops.%1], rax
    jne .unsupported
%endmacro
    EP_OP init
    EP_OP start
    EP_OP stop
    EP_OP tx
    EP_OP rx_poll
    EP_OP link_status
    EP_OP get_mac
    EP_OP recover
    mov r12d, 1
    call reinit_power_e1000e_set
    test rax, rax
    jnz .unsupported
    mov r12d, [rel ep_dependencies]
    call reinit_power_e1000e_live
    test rax, rax
    jnz .unsupported
    lea r13, [rel reinit_power_e1000e_declaration]
    lea rdi, [rel e1000e_dev]
    lea rsi, [rel e1000e_ops]
    call netdev_power_member
    mov dword [r13 + dp_driver.version], DP_VERSION
    mov dword [r13 + dp_driver.kind], DP_NETWORK
    lea rcx, [rel e1000e_dev]
    mov [r13 + dp_driver.owner], rcx
    mov [r13 + dp_driver.generation_ptr], rax
    mov [r13 + dp_driver.generation], rdx
    lea rcx, [rel reinit_power_e1000e_callback]
    mov [r13 + dp_driver.callback], rcx
    mov [r13 + dp_driver.dependencies], r12d
    mov dword [r13 + dp_driver.capabilities], DP_CAP_IRQ | DP_CAP_DMA
    mov rdi, rbx
    mov rsi, r13
    call reinit_power_register
    test rax, rax
    jnz .out
    mov eax, [rbx + dp_context.count]
    dec eax
    mov [rel reinit_power_e1000e_index], eax
    shl rax, 6
    lea rax, [rbx + rax + dp_context.slots]
    mov [rel reinit_power_e1000e_slot], rax
    lea rdi, [rel reinit_power_e1000e_ops]
    lea rsi, [rel e1000e_ops]
    mov edx, netdev_ops_size
    call memcpy
    mov [rel reinit_power_e1000e_context], rbx
    lea rax, [rel reinit_power_e1000e_gate]
    mov [rel e1000e_power_gate], rax
    xor eax, eax
    jmp .out
.unsupported:
    mov rax, DP_UNSUPPORTED
.out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

; Revalidate class membership BEFORE dereferencing its generation; immutable
; ops and declaration snapshots prevent same-handle replacement from earning
; a software stop/ready acknowledgement. No driver op or unbounded scan.
reinit_power_e1000e_identity:
    push rbx
    push r12
    sub rsp, 8
    mov rbx, [rel reinit_power_e1000e_context]
    test rbx, rbx
    jz .bad
    cmp dword [rbx + dp_context.version], DP_VERSION
    jne .bad
    mov eax, [rel reinit_power_e1000e_index]
    cmp dword [rbx + dp_context.count], DP_LIMIT
    ja .bad
    cmp eax, [rbx + dp_context.count]
    jae .bad
    lea rdi, [rel e1000e_dev]
    lea rsi, [rel e1000e_ops]
    call netdev_power_member
    cmp rax, [rel reinit_power_e1000e_declaration + dp_driver.generation_ptr]
    jne .bad
    test rax, rax
    jz .bad
    cmp rdx, [rel reinit_power_e1000e_declaration + dp_driver.generation]
    jne .bad
    mov rax, [rel reinit_power_e1000e_slot]
    lea rsi, [rel reinit_power_e1000e_declaration]
    cmp [rax + dp_slot.declaration], rsi
    jne .bad
    lea rdi, [rax + dp_slot.driver]
    mov edx, dp_driver_size
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rel e1000e_ops]
    lea rsi, [rel reinit_power_e1000e_ops]
    mov edx, netdev_ops_size
    call memcmp
    test eax, eax
    jnz .bad
    xor r12d, r12d
    call reinit_power_e1000e_set
    jmp .out
.bad:
    mov rax, DP_CHANGED
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret

; Pin immutable class/BAR/BDF/DMA identities, before any live controller read.
reinit_power_e1000e_pin:
    test r12d, r12d
    jnz memcpy
    jmp memcmp
%macro EP_PIN 2
    lea rdi, [rel ep_pin_%1]
    lea rsi, [rel %1]
    mov edx, %2
    call reinit_power_e1000e_pin
    test r12d, r12d
    jnz %%out
    test eax, eax
    jnz .bad
%%out:
%endmacro

reinit_power_e1000e_set:
    push rbx
    cmp byte [rel e1000e_is_82574l], 1
    jne .bad
    cmp byte [rel e1000e_is_qemu], 0
    jne .bad
    cmp dword [rel e1000e_devid], E1000_82574L_DEVID
    jne .bad
    cmp byte [rel e1000e_rings_ok], 1
    jne .bad
    cmp byte [rel e1000e_mac_ok], 1
    jne .bad
    cmp byte [rel e1000e_nic_absent], 0
    jne .bad
    cmp byte [rel e1000e_bar_bad], 0
    jne .bad
    cmp dword [rel e1000e_pci_dev], 32
    jae .bad
    cmp dword [rel e1000e_pci_fn], 8
    jae .bad
    mov esi, [rel e1000e_pci_dev]
    mov edx, [rel e1000e_pci_fn]
    call e1000e_bus_identity             ; settled/read-only, never discovers
    cmp eax, -1
    je .bad
    test r12d, r12d
    jz .compare_bus
    mov [rel ep_bus], eax
.compare_bus:
    cmp eax, [rel ep_bus]
    jne .bad                            ; reject route drift before PCI/MMIO
    cmp qword [rel e1000e_region+HAL_R_BAR_SIZE], 0x20000
    jne .bad
    mov rax, [rel e1000e_region+HAL_R_BAR_BASE]
    test rax, rax
    jz .bad
    test eax, 0x1ffff
    jnz .bad
    shr rax, 32
    jnz .bad
    lea rbx, [rel e1000e_tx_ring]
    xor ecx, ecx
.pages:
    mov rax, [rbx+rcx*8]
    test rax, rax
    jz .bad
    test eax, 4095
    jnz .bad
    lea r8, [rel ep_spans]
    mov r9, rax
    add r9, [r8+rcx*8]
    jc .bad
    xor edx, edx
.distinct:
    cmp edx, ecx
    jae .next
    mov r10, [rbx+rdx*8]
    mov r11, r10
    add r11, [r8+rdx*8]
    cmp rax, r11
    jae .separate
    cmp r9, r10
    ja .bad
.separate:
    inc edx
    jmp .distinct
.next:
    inc ecx
    cmp ecx, 4
    jb .pages
    EP_PIN e1000e_dev, dev_size
    EP_PIN e1000e_region, 16
    EP_PIN e1000e_pci_dev, 8
    EP_PIN e1000e_tx_ring, 32
    EP_PIN e1000e_mac, 6
    ; Raw PCI reads use the retained physical bus, not the driver's virtual0.
    xor ecx, ecx
    call reinit_power_e1000e_pci
    cmp eax, 0x10d38086
    jne .bad
    mov ecx, 0x10
    call reinit_power_e1000e_pci
    test eax, 7                       ; only original 32-bit memory BAR
    jnz .bad
    and eax, 0xfffffff0
    cmp rax, [rel e1000e_region]
    jne .bad
    mov ecx, 4
    call reinit_power_e1000e_pci
    movzx eax, ax
    mov edx, eax
    and edx, 6
    cmp edx, 6
    jne .bad
    test r12d, r12d
    jz .compare_command
    mov [rel ep_command], eax
.compare_command:
    cmp eax, [rel ep_command]
    jne .bad
    xor eax, eax
    pop rbx
    ret
.bad:
    mov rax, DP_CHANGED
    pop rbx
    ret

reinit_power_e1000e_pci:
    mov edi, [rel ep_bus]
    mov esi, [rel e1000e_pci_dev]
    mov edx, [rel e1000e_pci_fn]
    jmp pci_cfg_read32

; Only the adapter uses these HAL edges during the fenced transaction.
reinit_power_e1000e_rd:
    lea rdi, [rel e1000e_region]
    jmp hal_mmio_read32
reinit_power_e1000e_wr:
    lea rdi, [rel e1000e_region]
    jmp hal_mmio_write32

; Verify the actual programmed original rings, without rewinding any cursor.
reinit_power_e1000e_rings:
    push rbx
    mov esi, E1000_TDBAL
    call reinit_power_e1000e_rd
    jc .bad
    mov rbx, [rel e1000e_tx_ring]
    cmp eax, ebx
    jne .bad
    shr rbx, 32
    mov esi, E1000_TDBAH
    call reinit_power_e1000e_rd
    jc .bad
    cmp eax, ebx
    jne .bad
    mov esi, E1000_RDBAL
    call reinit_power_e1000e_rd
    jc .bad
    mov rbx, [rel e1000e_rx_ring]
    cmp eax, ebx
    jne .bad
    shr rbx, 32
    mov esi, E1000_RDBAH
    call reinit_power_e1000e_rd
    jc .bad
    cmp eax, ebx
    jne .bad
    mov esi, E1000_TDLEN
    call reinit_power_e1000e_rd
    jc .bad
    cmp eax, E1000_NUM_TX*E1000_DESC_SIZE
    jne .bad
    mov esi, E1000_RDLEN
    call reinit_power_e1000e_rd
    jc .bad
    cmp eax, E1000_NUM_RX*E1000_DESC_SIZE
    jne .bad
    mov esi, E1000_TDT
    call reinit_power_e1000e_rd
    jc .bad
    cmp eax, E1000_NUM_TX
    jae .bad
    cmp eax, [rel e1000e_tx_tail]
    jne .bad
    mov esi, E1000_RDT
    call reinit_power_e1000e_rd
    jc .bad
    cmp eax, E1000_NUM_RX
    jae .bad
    cmp dword [rel e1000e_rx_tail_sw], E1000_NUM_RX
    jae .bad
    xor eax, eax
    pop rbx
    ret
.bad:
    mov rax, DP_FAILED
    pop rbx
    ret

; Stable polling mode; native IRQ enables must remain masked throughout.
reinit_power_e1000e_live:
    sub rsp, 8
    call reinit_power_e1000e_rings
    test rax, rax
    jnz .out
    mov esi, E1000_IMS
    call reinit_power_e1000e_rd
    jc .bad
    test eax, eax
    jnz .bad
    mov esi, E1000_CTRL
    call reinit_power_e1000e_rd
    jc .bad
    test eax, E1000_CTRL_GIO_MASTER_DISABLE | E1000_CTRL_RST | E1000_CTRL_PHYRST
    jnz .bad
    mov esi, E1000_RCTL
    call reinit_power_e1000e_rd
    jc .bad
    test eax, E1000_RCTL_EN
    jz .bad
    mov esi, E1000_TCTL
    call reinit_power_e1000e_rd
    jc .bad
    test eax, E1000_TCTL_EN
    jz .bad
    xor eax, eax
    jmp .out
.bad:
    mov rax, DP_UNSUPPORTED
.out:
    add rsp, 8
    ret

; Native producer gate. Lifecycle replacement cannot borrow a new token.
reinit_power_e1000e_gate:
    cld
    cmp edi, 1
    je .busy
    push rbx
    mov ebx, edi
    call reinit_power_e1000e_identity
    test rax, rax
    jnz .out
    cmp ebx, 2
    jne .admit
    call reinit_power_e1000e_tx_drained
    test rax, rax
    jnz .out
.admit:
    mov rbx, [rel reinit_power_e1000e_context]
    mov rdi, rbx
    mov rsi, [rbx+dp_context.token]
    lea rdx, [rel e1000e_dev]
    mov rcx, [rel reinit_power_e1000e_declaration+dp_driver.generation]
    call reinit_power_admit
.out:
    pop rbx
    cld
    ret
.busy:
    mov rax, DP_BUSY
    ret

; The native driver has one shared bounce buffer. Never reuse it after a
; timed-out post until the actual descriptor reports completion.
reinit_power_e1000e_tx_drained:
    mov rdi, [rel e1000e_tx_ring]
    xor ecx, ecx
.next:
    cmp word [rdi+rcx+8], 0
    je .advance
    test byte [rdi+rcx+12], E1000_TXD_STA_DD
    jz .pending
.advance:
    add ecx, E1000_DESC_SIZE
    cmp ecx, E1000_NUM_TX*E1000_DESC_SIZE
    jb .next
    xor eax, eax
    ret
.pending:
    mov eax, DP_PENDING
    ret

; Queued callers carry the token under which they obtained their work.
reinit_power_e1000e_tx:
    cld
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    call reinit_power_e1000e_identity
    test rax, rax
    jnz .out
    mov rdi, [rel reinit_power_e1000e_context]
    mov rsi, rbx
    lea rdx, [rel e1000e_dev]
    mov rcx, [rel reinit_power_e1000e_declaration+dp_driver.generation]
    call reinit_power_admit
    test rax, rax
    jnz .out
    lea rdi, [rel e1000e_dev]
    mov rsi, r12
    mov rdx, r13
    call e1000e_tx
.out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

reinit_power_e1000e_callback:
    cld
    push rbx
    push r12
    push r13
    lea rax, [rel e1000e_dev]
    cmp rdi, rax
    jne .changed
    mov rbx, [rel reinit_power_e1000e_context]
    test rbx, rbx
    jz .changed
    cmp rcx, rbx
    jne .changed
    cmp byte [rbx+dp_context.busy], 1
    jne .changed
    cmp rdx, [rbx+dp_context.token]
    jne .changed
    cmp r8, [rel reinit_power_e1000e_declaration+dp_driver.generation]
    jne .changed
    cmp esi, [rbx+dp_context.phase]
    jne .changed
    mov r12d, esi
    mov r13, rdx
    call reinit_power_e1000e_identity
    test rax, rax
    jnz .changed
    cmp r12d, DP_FENCE
    je .fence
    cmp r12d, DP_STOP
    je .stop
    cmp dword [rbx+dp_context.state], DP_RESUMING
    je .resume_state
    cmp dword [rbx+dp_context.state], DP_RECOVERING
    jne .changed
.resume_state:
    cmp r12d, DP_VERIFY
    je .verify
    cmp r13, [rel reinit_power_e1000e_token]
    jne .changed
    cmp r12d, DP_RESTORE
    je .restore
    jmp .changed
.fence:
    cmp dword [rbx+dp_context.state], DP_QUIESCING
    jne .changed
    call reinit_power_e1000e_live
    test rax, rax
    jnz .unsupported
    mov [rel reinit_power_e1000e_token], r13
    mov dword [rel ep_stage], 0
    mov esi, E1000_CTRL
    call reinit_power_e1000e_rd
    jc .unsupported
    mov [rel ep_ctrl], eax
    mov esi, E1000_RCTL
    call reinit_power_e1000e_rd
    jc .unsupported
    mov [rel ep_rctl], eax
    mov esi, E1000_TCTL
    call reinit_power_e1000e_rd
    jc .unsupported
    mov [rel ep_tctl], eax
    mov edx, DP_ACK_FENCED
    jmp .ok
.stop:
    cmp dword [rbx+dp_context.state], DP_QUIESCING
    jne .changed
    cmp r13, [rel reinit_power_e1000e_token]
    jne .changed
    cmp dword [rel ep_stage], 0
    jne .stopping
    ; Every posted native TX requests DD. A timeout retains its original
    ; descriptor and bounce buffer until completion; never overwrite/retry it.
    call reinit_power_e1000e_tx_drained
    test rax, rax
    jnz .pending
    call reinit_power_e1000e_live
    test rax, rax
    jnz .unsupported
    mov dword [rel ep_stage], 1
    mov edx, [rel ep_rctl]
    and edx, ~E1000_RCTL_EN
    mov esi, E1000_RCTL
    call reinit_power_e1000e_wr
    jc .failed
    mov edx, [rel ep_tctl]
    and edx, ~E1000_TCTL_EN
    mov esi, E1000_TCTL
    call reinit_power_e1000e_wr
    jc .failed
    mov edx, [rel ep_ctrl]
    or edx, E1000_CTRL_GIO_MASTER_DISABLE
    mov esi, E1000_CTRL
    call reinit_power_e1000e_wr
    jc .failed
.stopping:
    call reinit_power_e1000e_stopped
    test rax, rax
    jnz .pending
    call reinit_power_e1000e_rings
    test rax, rax
    jnz .failed
    mov esi, E1000_RDT
    call reinit_power_e1000e_rd
    jc .failed
    mov [rel ep_rdt], eax
    mov esi, E1000_RDH
    call reinit_power_e1000e_rd
    jc .failed
    cmp eax, E1000_NUM_RX
    jae .failed
    mov [rel ep_rdh], eax
    mov esi, E1000_TDH
    call reinit_power_e1000e_rd
    jc .failed
    cmp eax, [rel e1000e_tx_tail]
    jne .failed
    mov [rel ep_tdh], eax
    mov dword [rel ep_stage], 2
    mov edx, DP_ACK_FENCED | DP_ACK_DRAINED | DP_ACK_IRQ_STOPPED | DP_ACK_DMA_STOPPED
    jmp .ok
.restore:
    cmp dword [rel ep_stage], 2
    jne .failed
    call reinit_power_e1000e_stopped
    test rax, rax
    jnz .failed
    call reinit_power_e1000e_rings
    test rax, rax
    jnz .failed
    mov esi, E1000_RDT
    call reinit_power_e1000e_rd
    jc .failed
    cmp eax, [rel ep_rdt]
    jne .failed
    mov esi, E1000_RDH
    call reinit_power_e1000e_rd
    jc .failed
    cmp eax, [rel ep_rdh]
    jne .failed
    mov esi, E1000_TDH
    call reinit_power_e1000e_rd
    jc .failed
    cmp eax, [rel ep_tdh]
    jne .failed
    mov edx, [rel ep_ctrl]
    mov esi, E1000_CTRL
    call reinit_power_e1000e_wr
    jc .failed
    mov esi, E1000_CTRL
    call reinit_power_e1000e_rd
    jc .failed
    cmp eax, [rel ep_ctrl]
    jne .failed
    mov edx, [rel ep_rctl]
    mov esi, E1000_RCTL
    call reinit_power_e1000e_wr
    jc .failed
    mov edx, [rel ep_tctl]
    mov esi, E1000_TCTL
    call reinit_power_e1000e_wr
    jc .failed
    mov dword [rel ep_stage], 3
    mov edx, DP_ACK_FENCED
    jmp .ok
.verify:
    cmp dword [rel ep_stage], 0
    jne .restored_verify
    ; Cancellation before STOP may verify an untouched participant. An
    ; attempted STOP is uncertain and cannot use this no-effect path.
    cmp dword [rbx+dp_context.state], DP_RECOVERING
    jne .failed
    mov rax, [rel reinit_power_e1000e_slot]
    test dword [rax+dp_slot.flags], DP_S_UNCERTAIN | DP_S_PAUSED
    jnz .failed
    call reinit_power_e1000e_live
    test rax, rax
    jnz .failed
    jmp .carrier
.restored_verify:
    cmp r13, [rel reinit_power_e1000e_token]
    jne .changed
    cmp dword [rel ep_stage], 3
    jne .failed
    call reinit_power_e1000e_live
    test rax, rax
    jnz .failed
    mov esi, E1000_RCTL
    call reinit_power_e1000e_rd
    jc .failed
    cmp eax, [rel ep_rctl]
    jne .failed
    mov esi, E1000_TCTL
    call reinit_power_e1000e_rd
    jc .failed
    cmp eax, [rel ep_tctl]
    jne .failed
.carrier:
    ; Independent live carrier readiness, without sending a synthetic packet.
    mov esi, E1000_STATUS
    call reinit_power_e1000e_rd
    jc .failed
    test eax, E1000_STATUS_LU
    jz .failed
    cmp eax, -1
    je .failed
    mov dword [rel ep_stage], 0
    mov edx, DP_ACK_FENCED | DP_ACK_READY
    jmp .ok
.pending:
    mov eax, DP_PENDING
    jmp .error
.unsupported:
    mov rax, DP_UNSUPPORTED
    jmp .error
.changed:
    mov rax, DP_CHANGED
    jmp .error
.failed:
    mov rax, DP_FAILED
.error:
    xor edx, edx
    jmp .out
.ok:
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

; Each observation is independent of the writes. Never infer completed DMA
; from a saved control value; STATUS.GIO must report all master requests gone.
reinit_power_e1000e_stopped:
    sub rsp, 8
    mov esi, E1000_IMS
    call reinit_power_e1000e_rd
    jc .bad
    test eax, eax
    jnz .bad
    mov esi, E1000_RCTL
    call reinit_power_e1000e_rd
    jc .bad
    mov edx, [rel ep_rctl]
    and edx, ~E1000_RCTL_EN
    cmp eax, edx
    jne .bad
    mov esi, E1000_TCTL
    call reinit_power_e1000e_rd
    jc .bad
    mov edx, [rel ep_tctl]
    and edx, ~E1000_TCTL_EN
    cmp eax, edx
    jne .bad
    mov esi, E1000_CTRL
    call reinit_power_e1000e_rd
    jc .bad
    mov edx, [rel ep_ctrl]
    or edx, E1000_CTRL_GIO_MASTER_DISABLE
    cmp eax, edx
    jne .bad
    mov esi, E1000_STATUS
    call reinit_power_e1000e_rd
    jc .bad
    test eax, E1000_STATUS_GIO_MASTER_ENABLE
    jnz .bad
    xor eax, eax
    jmp .out
.bad:
    mov rax, DP_PENDING
.out:
    add rsp, 8
    ret

%macro WDATA_svc_reinit_power_e1000e 0
align 8
reinit_power_e1000e_context: dq 0
ep_s5_latched: dd 0
align 8
reinit_power_e1000e_slot: dq 0
reinit_power_e1000e_declaration: times dp_driver_size db 0
reinit_power_e1000e_ops: times netdev_ops_size db 0
reinit_power_e1000e_token: dq 0
ep_spans: dq 4096, 4096, E1000_NUM_RX*E1000_RX_BUF, 4096
reinit_power_e1000e_index: dd 0
ep_dependencies: dd 0
ep_stage: dd 0
ep_ctrl: dd 0
ep_rctl: dd 0
ep_tctl: dd 0
ep_command: dd 0
ep_bus: dd 0
ep_rdt: dd 0
ep_rdh: dd 0
ep_tdh: dd 0
align 8
ep_pin_e1000e_dev: times dev_size db 0
ep_pin_e1000e_region: times 16 db 0
ep_pin_e1000e_pci_dev: times 8 db 0
ep_pin_e1000e_tx_ring: times 32 db 0
ep_pin_e1000e_mac: times 6 db 0
%endmacro
WDATA_DEFER WDATA_svc_reinit_power_e1000e
