;; MODULE svc/reinit_power_ahci
;; LAYER 5
;; EXPORTS reinit_power_ahci_register, reinit_power_ahci_admit, reinit_power_ahci_read
;; IMPORTS svc/reinit_power, fs/blockdev, dev/blk/ahci, bus/pci, core/lib/mem
;; CAPS mmio dma
;; OWNER saga:resource
;; CONTEXT: bsp_only
; Trusted opt-in ONLY. One immutable aggregate over this driver's complete HBA
; port set. No registration at boot, target selection, reset, allocation, wire
; command or S5 binding. Keep this sidecar, context and every DMA allocation
; pinned even after DEGRADED. No detach/retry/rebind entry point.
%include "core/abi/driver_power.inc"
AP_IE equ 0x14
AP_SACT equ 0x34
AP_FBS equ 0x40
AP_IS equ 0x08
AP_IRQ equ 2

; Capture/compare immutable driver-owned records; RSI=live, RDI=pinned, EDX=size.
; R12D=1 capture, otherwise compare. Only private registration uses capture.
reinit_power_ahci_pin:
    test r12d, r12d
    jnz memcpy
    xchg rdi, rsi
    jmp memcmp

%macro AP_PIN 2
    lea rsi, [rel %1]
    lea rdi, [rel ap_pin_%1]
    mov edx, %2
    call reinit_power_ahci_pin
    test r12d, r12d
    jnz %%ok
    test eax, eax
    jnz .bad
%%ok:
%endmacro

; All scans bounded; actual class membership, all full64 media generations,
; exact backend ops/geometry, BDF and queues are checked before any MMIO write.
; R12D=1 snapshot or 0 validate. Never trusts cached present as useful readiness.
reinit_power_ahci_set:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    cmp byte [rel ahci_present], 1
    jne .bad
    cmp byte [rel ahci_claim_legacy], 1
    jne .bad                             ; no proven child BDF for VMD yet
    cmp byte [rel ahci_vmd_child], 0
    jne .bad
    mov ebp, [rel ahci_port_count]
    test ebp, ebp
    jz .bad
    cmp ebp, AHCI_MAX_DISKS
    ja .bad
    AP_PIN ahci_bar5, 8
    AP_PIN ahci_cap, 4
    AP_PIN ahci_pi, 4
    AP_PIN ahci_busno, 12
    AP_PIN ahci_port_count, 4
    AP_PIN ahci_ports, AHCI_MAX_DISKS*4
    AP_PIN ahci_port_present, AHCI_MAX_DISKS
    AP_PIN ahci_pbases, AHCI_MAX_DISKS*8
    AP_PIN ahci_cls, AHCI_MAX_DISKS*8
    AP_PIN ahci_cts, AHCI_MAX_DISKS*8
    AP_PIN ahci_idbufs, AHCI_MAX_DISKS*8
    AP_PIN ahci_bounces, AHCI_MAX_DISKS*8
    AP_PIN ahci_lba_maxes, AHCI_MAX_DISKS*8
    AP_PIN ahci_ops, blk_ops_size
    ; Capturing a foreign vtable would leave unfenced producers in the class.
    lea rax, [rel ahci_op_identify]
    cmp [rel ahci_ops+blk_ops.identify], rax
    jne .bad
    lea rax, [rel ahci_op_read]
    cmp [rel ahci_ops+blk_ops.read], rax
    jne .bad
    lea rax, [rel ahci_op_write]
    cmp [rel ahci_ops+blk_ops.write], rax
    jne .bad
    lea rax, [rel ahci_op_flush]
    cmp [rel ahci_ops+blk_ops.flush], rax
    jne .bad
    mov rbx, [rel ahci_bar5]
    test rbx, rbx
    jz .bad
    mov eax, [rel ahci_cap]
    cmp eax, [rbx + AHCI_REG_CAP]
    jne .bad
    mov eax, [rel ahci_pi]
    cmp eax, [rbx + AHCI_REG_PI]
    jne .bad
    mov eax, [rbx + AHCI_REG_GHC]
    and eax, ~AP_IRQ
    cmp eax, AHCI_GHC_AE
    jne .bad                             ; no reset, enable/unknown GHC changes
    ; BDF config identity + BAR + Memory/Bus Master stay the same, no writes.
    xor ecx, ecx
    call reinit_power_ahci_cfg
    cmp ax, 0xFFFF
    je .bad
    test ax, ax
    jz .bad
    test r12d, r12d
    jz .cfg_compare
    mov [rel ap_pci_id], eax
.cfg_compare:
    cmp eax, [rel ap_pci_id]
    jne .bad
    mov ecx, 0x24
    call reinit_power_ahci_cfg
    and eax, 0xFFFFFFF0
    cmp rax, rbx
    jne .bad
    mov ecx, 4
    call reinit_power_ahci_cfg
    and eax, 6
    cmp eax, 6
    jne .bad
    call blk_registered_count
    cmp eax, BLK_REGISTRY_LIMIT
    ja .bad
    xor r13d, r13d
    xor r14d, r14d                       ; registered logical slots seen
    xor edi, edi
.registry:
    xor esi, esi
    xor edx, edx
    call blk_iter_after
    test rax, rax
    jz .registry_done
    mov r15, rax
    lea rdx, [rel ahci_ops]
    cmp [r15 + dev.ops], rdx
    je .ours
    lea rdx, [rel ahci_devs]
    cmp r15, rdx
    jb .next
    add rdx, AHCI_MAX_DISKS*dev_size
    cmp r15, rdx
    jb .bad                             ; owned handle with replaced ops
    jmp .next
.ours:
    mov rcx, [r15 + dev.priv]
    cmp rcx, rbp
    jae .bad
    bt r14d, ecx
    jc .bad
    bts r14d, ecx
    imul rax, rcx, dev_size
    lea rdx, [rel ahci_devs]
    add rax, rdx
    cmp rax, r15
    jne .bad
.next:
    mov rdi, r15
    inc r13d
    cmp r13d, BLK_REGISTRY_LIMIT
    jb .registry
    jmp .bad
.registry_done:
    mov ecx, ebp
    mov eax, 1
    shl eax, cl
    dec eax
    cmp eax, r14d
    jne .bad
    xor r13d, r13d
    xor r14d, r14d                       ; physical ports accounted for
.ports:
    cmp r13d, ebp
    jae .all_ports
    lea rax, [rel ahci_port_poisoned]
    cmp byte [rax+r13], 0
    jne .bad
    lea rax, [rel ahci_port_present]
    cmp byte [rax+r13], 1
    jne .bad
    lea rax, [rel ahci_ports]
    mov ecx, [rax+r13*4]
    cmp ecx, 32
    jae .bad
    bt r14d, ecx
    jc .bad
    bts r14d, ecx
    bt [rel ahci_pi], ecx
    jnc .bad
    shl ecx, 7
    lea r15, [rbx+rcx+AHCI_PORT_BASE]
    lea rax, [rel ahci_pbases]
    cmp [rax+r13*8], r15
    jne .bad
    mov eax, [r15+AHCI_PORT_SSTS]
    and eax, 0xF
    cmp eax, 3
    jne .bad
    test r12d, r12d
    jz .engines_bound
    mov eax, [r15+AHCI_PORT_CMD]
    and eax, AHCI_PXCMD_ST|AHCI_PXCMD_FRE
    cmp eax, AHCI_PXCMD_ST|AHCI_PXCMD_FRE
    jne .bad
.engines_bound:
    cmp dword [r15+AHCI_PORT_SIG], 0x101
    jne .bad
    cmp dword [r15+AP_FBS], 0
    jne .bad
    cmp dword [r15+AP_SACT], 0
    jne .bad
    lea rax, [rel ahci_cls]
    mov rax, [rax+r13*8]
    test rax, rax
    jz .bad
    test eax, 1023
    jnz .bad
    mov edx, [r15+AHCI_PORT_CLBU]
    shl rdx, 32
    mov ecx, [r15+AHCI_PORT_CLB]
    or rdx, rcx
    cmp rdx, rax
    jne .bad
    add rax, 0x400
    mov edx, [r15+AHCI_PORT_FBU]
    shl rdx, 32
    mov ecx, [r15+AHCI_PORT_FB]
    or rdx, rcx
    cmp rdx, rax
    jne .bad
    add rax, 0x100
    lea rdx, [rel ahci_cts]
    cmp [rdx+r13*8], rax
    jne .bad
    lea rax, [rel ahci_bounces]
    cmp qword [rax+r13*8], 0
    je .bad
    imul rax, r13, dev_size
    lea rsi, [rel ahci_devs]
    add rsi, rax
    cmp dword [rsi+dev.health], HEALTH_OK
    jne .bad
    cmp dword [rsi+dev.class], CLASS_BLOCK
    jne .bad
    lea rdi, [rel ap_devs]
    add rdi, rax
    mov edx, 40                         ; ops/info/priv/prio/health/class/flags
    call reinit_power_ahci_pin
    test r12d, r12d
    jnz .dev_ok
    test eax, eax
    jnz .bad
.dev_ok:
    imul rax, r13, blk_info_size
    lea rsi, [rel ahci_infos]
    add rsi, rax
    imul rdx, r13, dev_size
    lea rcx, [rel ahci_devs]
    cmp [rcx+rdx+dev.info], rsi
    jne .bad
    cmp dword [rsi+blk_info.logical_sector_bytes], 512
    jne .bad
    cmp qword [rsi+blk_info.media_generation], 0
    je .bad
    mov rdx, [rsi+blk_info.capabilities]
    and edx, BLKCAP_READ|BLKCAP_FLUSH
    cmp edx, BLKCAP_READ|BLKCAP_FLUSH
    jne .bad
    lea rdi, [rel ap_infos]
    add rdi, rax
    mov edx, blk_info_size
    call reinit_power_ahci_pin
    test r12d, r12d
    jnz .info_ok
    test eax, eax
    jnz .bad
.info_ok:
    inc r13d
    jmp .ports
.all_ports:
    ; Reject present/active/interrupt-owning unregistered ports, including
    ; ATAPI, failed init and beyond the table bound. Never mask their IRQs.
    mov eax, [rel ahci_pi]
    not r14d
    and r14d, eax
    xor ecx, ecx
.unowned:
    cmp ecx, 32
    jae .good
    bt r14d, ecx
    jnc .unext
    mov eax, ecx
    shl eax, 7
    lea rdx, [rbx+rax+AHCI_PORT_BASE]
    mov eax, [rdx+AHCI_PORT_SSTS]
    and eax, 0xF
    test eax, eax
    jnz .bad
    mov eax, [rdx+AHCI_PORT_CMD]
    test eax, AHCI_PXCMD_ST|AHCI_PXCMD_CR|AHCI_PXCMD_FRE|AHCI_PXCMD_FR
    jnz .bad
    mov eax, [rdx+AHCI_PORT_CI]
    or eax, [rdx+AP_IE]
    or eax, [rdx+AHCI_PORT_IS]
    or eax, [rdx+AP_SACT]
    jnz .bad
.unext:
    inc ecx
    jmp .unowned
.good:
    xor eax, eax
    jmp .out
.bad:
    mov rax, DP_CHANGED
.out:
    pop r15
    pop r14
    pop r13
    pop rbp
    pop rbx
    ret

reinit_power_ahci_cfg:
    mov edi, [rel ahci_busno]
    mov esi, [rel ahci_devno]
    mov edx, [rel ahci_fn]
    jmp pci_cfg_read32

; RDI=initialized pinned context; ESI=already registered dependency kind mask.
; AHCI takes DP_STORAGE, so a RAM storage reference in this plan refuses.
reinit_power_ahci_register:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r13d, esi
    mov rax, DP_BUSY
    cmp qword [rel ahci_power_gate], 0
    jne .out
    cmp qword [rel ap_context], 0
    jne .out
    mov r12d, 1
    call reinit_power_ahci_set
    test rax, rax
    jnz .out
    lea rsi, [rel ap_declaration]
    mov dword [rsi+dp_driver.version], DP_VERSION
    mov dword [rsi+dp_driver.kind], DP_STORAGE
    lea rax, [rel ahci_devs]
    mov [rsi+dp_driver.owner], rax
    lea rax, [rel ahci_infos+blk_info.media_generation]
    mov [rsi+dp_driver.generation_ptr], rax
    mov rax, [rax]
    mov [rsi+dp_driver.generation], rax
    lea rax, [rel reinit_power_ahci_callback]
    mov [rsi+dp_driver.callback], rax
    mov [rsi+dp_driver.dependencies], r13d
    mov dword [rsi+dp_driver.capabilities], 7
    mov rdi, rbx
    call reinit_power_register
    test rax, rax
    jnz .out
    mov [rel ap_context], rbx
    lea rax, [rel reinit_power_ahci_gate]
    mov [rel ahci_power_gate], rax
    lea rax, [rel reinit_power_ahci_command_gate]
    mov [rel ahci_power_command_gate], rax
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

reinit_power_ahci_identity:
    push r12
    xor r12d, r12d
    call reinit_power_ahci_set
    pop r12
    ret

; Explicit queued-work admission RDI=issued full64 token. Existing class ops
; also gate their current immediate lifetime. Stale queued tokens never renew.
reinit_power_ahci_admit:
    push rbx
    mov rbx, rdi
    call reinit_power_ahci_identity
    test rax, rax
    jnz .out
    mov rdi, [rel ap_context]
    mov rsi, rbx
    lea rdx, [rel ahci_devs]
    mov rcx, [rel ap_declaration+dp_driver.generation]
    call reinit_power_admit
.out:
    pop rbx
    cld
    ret
; Queued read submission: RDI=issued token, RSI=registered dev*, RDX=LBA,
; RCX=count, R8=buffer. Admission and actual existing class dispatch are one
; synchronous BSP call; a stale queued producer cannot renew its work token.
reinit_power_ahci_read:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    call reinit_power_ahci_admit
    test rax, rax
    jnz .out
    ; No arbitrary backend: exact owned handle required before class dispatch.
    lea rax, [rel ahci_devs]
    cmp r12, rax
    jb .changed
    sub r12, rax
    cmp r12, AHCI_MAX_DISKS*dev_size
    jae .changed
    mov rax, r12
    xor edx, edx
    mov ecx, dev_size
    div rcx
    test rdx, rdx
    jnz .changed
    cmp eax, [rel ahci_port_count]
    jae .changed
    lea rdi, [rel ahci_devs]
    add rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov rcx, r15
    call blk_read
    jmp .out
.changed:
    mov rax, DP_CHANGED
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    cld
    ret

reinit_power_ahci_gate:
    mov rdi, [rel ap_context]
    test rdi, rdi
    jz .bad
    mov rdi, [rdi+dp_context.token]
    jmp reinit_power_ahci_admit
.bad:
    mov rax, DP_CHANGED
    ret

; One-use exact internal command, only in the active coordinator callback.
; No write token/opcode, recovery or global 'ignore fence' flag is allowed.
reinit_power_ahci_command_gate:
    cmp byte [rel ap_permit], 1
    jne .bad
    mov byte [rel ap_permit], 0
    cmp edi, [rel ap_cursor]
    jne .bad
    cmp r10b, [rel ap_opcode]
    jne .bad
    test r11b, r11b
    jnz .bad
    test rsi, rsi
    jnz .bad
    cmp r10b, AHCI_ATA_FLUSH
    je .flush
    cmp r10b, AHCI_ATA_READ
    jne .bad
    cmp edx, 1
    jne .bad
    cmp r8d, 512
    jne .bad
    lea rax, [rel ahci_bounces]
    cmp rcx, [rax+rdi*8]
    jne .bad
    jmp .context
.flush:
    or rdx, rcx
    or rdx, r8
    jnz .bad
.context:
    mov rax, [rel ap_context]
    cmp byte [rax+dp_context.busy], 1
    jne .bad
    mov rdx, [rel ap_token]
    cmp [rax+dp_context.token], rdx
    jne .bad
    mov edx, [rax+dp_context.phase]
    cmp edx, DP_STOP
    je .ok
    cmp edx, DP_VERIFY
    jne .bad
.ok:
    xor eax, eax
    ret
.bad:
    mov rax, DP_CHANGED
    ret

; Callback does one state-machine edge for ONE port; no polling loops, reset,
; allocation or recovery. Pending STOP/RESTORE remains uncertain in coordinator.
reinit_power_ahci_callback:
    push rbx
    push r12
    push r13
    mov rbx, [rel ap_context]
    test rbx, rbx
    jz .changed
    cmp rcx, rbx
    jne .changed
    cmp byte [rbx+dp_context.busy], 1
    jne .changed
    cmp esi, [rbx+dp_context.phase]
    jne .changed
    cmp rdx, [rbx+dp_context.token]
    jne .changed
    cmp r8, [rel ap_declaration+dp_driver.generation]
    jne .changed
    lea rax, [rel ahci_devs]
    cmp rdi, rax
    jne .changed
    mov r12d, esi
    mov r13, rdx
    call reinit_power_ahci_identity
    test rax, rax
    jnz .changed
    cmp r12d, DP_FENCE
    je .fence
    cmp r13, [rel ap_token]
    je .same_token
    ; Cancellation before this participant fenced: verify fresh useful read,
    ; with no baseline comparison because no stop command has been attempted.
    cmp r12d, DP_VERIFY
    jne .changed
    mov [rel ap_token], r13
    mov dword [rel ap_cursor], 0
    mov dword [rel ap_stage], 0
    mov byte [rel ap_baseline], 0
    mov byte [rel ap_irq_saved], 0
.same_token:
    mov eax, [rel ap_cursor]
    cmp eax, [rel ahci_port_count]
    jae .phase_complete
    lea rdx, [rel ahci_pbases]
    mov r13, [rdx+rax*8]
    cmp r12d, DP_STOP
    je .stop
    cmp r12d, DP_RESTORE
    je .restore
    cmp r12d, DP_VERIFY
    je .verify
    jmp .changed
.fence:
    mov byte [rel ap_irq_saved], 1
    mov [rel ap_token], r13
    mov dword [rel ap_cursor], 0
    mov dword [rel ap_stage], 0
    mov byte [rel ap_baseline], 0
    mov rax, [rel ahci_bar5]
    mov eax, [rax+AHCI_REG_GHC]
    mov [rel ap_ghc], eax
    xor ecx, ecx
.save_ie:
    lea rax, [rel ahci_pbases]
    mov rax, [rax+rcx*8]
    mov eax, [rax+AP_IE]
    lea rdx, [rel ap_ie]
    mov [rdx+rcx*4], eax
    inc ecx
    cmp ecx, [rel ahci_port_count]
    jb .save_ie
    mov edx, DP_ACK_FENCED
    jmp .ok
.stop:
    mov eax, [rel ap_stage]
    cmp eax, 0
    je .drain
    cmp eax, 1
    je .baseline_done
    cmp eax, 2
    je .flush_done
    cmp eax, 3
    je .cr_done
    cmp eax, 4
    je .fr_done
    jmp .failed
.drain:
    cmp dword [r13+AHCI_PORT_CI], 0
    jne .pending
    call reinit_power_ahci_idle
    jnz .failed
    mov r10b, AHCI_ATA_READ
    call reinit_power_ahci_command
    test rax, rax
    jnz .failed
    mov dword [rel ap_stage], 1
    jmp .pending
.baseline_done:
    call reinit_power_ahci_complete
    jnz .pending_or_failed
    mov eax, [rel ap_cursor]
    lea rsi, [rel ahci_bounces]
    mov rsi, [rsi+rax*8]
    shl eax, 9
    lea rdi, [rel ap_before]
    add rdi, rax
    mov edx, 512
    call memcpy
    mov r10b, AHCI_ATA_FLUSH
    call reinit_power_ahci_command
    test rax, rax
    jnz .failed
    mov dword [rel ap_stage], 2
    jmp .pending
.flush_done:
    call reinit_power_ahci_complete
    jnz .pending_or_failed
    mov dword [r13+AP_IE], 0
    mov eax, [r13+AHCI_PORT_CMD]
    and eax, ~AHCI_PXCMD_ST
    mov [r13+AHCI_PORT_CMD], eax
    mov dword [rel ap_stage], 3
    jmp .pending
.cr_done:
    test dword [r13+AHCI_PORT_CMD], AHCI_PXCMD_ST|AHCI_PXCMD_CR
    jnz .pending
    cmp dword [r13+AHCI_PORT_CI], 0
    jne .failed
    mov eax, [r13+AHCI_PORT_CMD]
    and eax, ~AHCI_PXCMD_FRE
    mov [r13+AHCI_PORT_CMD], eax
    mov dword [rel ap_stage], 4
    jmp .pending
.fr_done:
    test dword [r13+AHCI_PORT_CMD], AHCI_PXCMD_ST|AHCI_PXCMD_CR|AHCI_PXCMD_FRE|AHCI_PXCMD_FR
    jnz .pending
    cmp dword [r13+AHCI_PORT_CI], 0
    jne .failed
    mov dword [r13+AHCI_PORT_IS], -1
    mov eax, [rel ap_cursor]
    lea rcx, [rel ahci_ports]
    mov ecx, [rcx+rax*4]
    mov eax, 1
    shl eax, cl
    mov rdx, [rel ahci_bar5]
    mov [rdx+AP_IS], eax
    jmp .next
.restore:
    mov eax, [rel ap_stage]
    cmp eax, 0
    je .fre
    cmp eax, 1
    je .start
    cmp eax, 2
    jne .failed
    mov eax, [r13+AHCI_PORT_CMD]
    and eax, AHCI_PXCMD_FRE|AHCI_PXCMD_ST
    cmp eax, AHCI_PXCMD_FRE|AHCI_PXCMD_ST
    jne .failed
    jmp .next
.fre:
    test dword [r13+AHCI_PORT_CMD], AHCI_PXCMD_ST|AHCI_PXCMD_CR|AHCI_PXCMD_FRE|AHCI_PXCMD_FR
    jnz .failed
    cmp dword [r13+AHCI_PORT_CI], 0
    jne .failed
    mov eax, [r13+AHCI_PORT_CMD]
    or eax, AHCI_PXCMD_FRE
    mov [r13+AHCI_PORT_CMD], eax
    mov dword [rel ap_stage], 1
    jmp .pending
.start:
    test dword [r13+AHCI_PORT_CMD], AHCI_PXCMD_CR|AHCI_PXCMD_ST
    jnz .failed
    test dword [r13+AHCI_PORT_CMD], AHCI_PXCMD_FRE
    jz .failed
    call reinit_power_ahci_idle
    jnz .failed
    mov eax, [r13+AHCI_PORT_CMD]
    or eax, AHCI_PXCMD_ST
    mov [r13+AHCI_PORT_CMD], eax
    mov dword [rel ap_stage], 2
    jmp .pending
.verify:
    cmp dword [rel ap_stage], 0
    jne .verify_done
    cmp dword [r13+AHCI_PORT_CI], 0
    jne .pending
    call reinit_power_ahci_idle
    jnz .failed
    mov eax, [r13+AHCI_PORT_CMD]
    and eax, AHCI_PXCMD_ST|AHCI_PXCMD_FRE
    cmp eax, AHCI_PXCMD_ST|AHCI_PXCMD_FRE
    jne .failed
    mov r10b, AHCI_ATA_READ
    call reinit_power_ahci_command
    test rax, rax
    jnz .failed
    mov dword [rel ap_stage], 1
    jmp .pending
.verify_done:
    call reinit_power_ahci_complete
    jnz .pending_or_failed
    cmp byte [rel ap_baseline], 1
    jne .next
    mov eax, [rel ap_cursor]
    lea rdi, [rel ahci_bounces]
    mov rdi, [rdi+rax*8]
    shl eax, 9
    lea rsi, [rel ap_before]
    add rsi, rax
    mov edx, 512
    call memcmp
    test eax, eax
    jnz .failed
.next:
    inc dword [rel ap_cursor]
    mov dword [rel ap_stage], 0
    jmp .pending
.phase_complete:
    cmp r12d, DP_STOP
    je .stopped
    cmp r12d, DP_RESTORE
    je .restored
    cmp r12d, DP_VERIFY
    jne .changed
    cmp byte [rel ap_irq_saved], 0
    je .verified
    ; Clear residual port status before HBA IS before re-enabling IRQ routing.
    xor ecx, ecx
.rearm:
    lea rax, [rel ahci_pbases]
    mov rdx, [rax+rcx*8]
    mov dword [rdx+AHCI_PORT_IS], -1
    inc ecx
    cmp ecx, [rel ahci_port_count]
    jb .rearm
    mov rdx, [rel ahci_bar5]
    mov eax, [rel ahci_pi]
    mov [rdx+AP_IS], eax
    cmp dword [rdx+AP_IS], 0
    jne .failed
    xor ecx, ecx
.irq_on:
    lea rax, [rel ahci_pbases]
    mov rdx, [rax+rcx*8]
    cmp dword [rdx+AHCI_PORT_IS], 0
    jne .failed
    lea rax, [rel ap_ie]
    mov eax, [rax+rcx*4]
    mov [rdx+AP_IE], eax
    cmp [rdx+AP_IE], eax
    jne .failed
    inc ecx
    cmp ecx, [rel ahci_port_count]
    jb .irq_on
    mov rdx, [rel ahci_bar5]
    mov eax, [rel ap_ghc]
    mov [rdx+AHCI_REG_GHC], eax
    cmp [rdx+AHCI_REG_GHC], eax
    jne .failed
    mov byte [rel ap_irq_saved], 0
.verified:
    mov edx, DP_ACK_FENCED|DP_ACK_READY
    jmp .ok
.stopped:
    mov rdx, [rel ahci_bar5]
    mov eax, [rdx+AHCI_REG_GHC]
    and eax, ~AP_IRQ
    mov [rdx+AHCI_REG_GHC], eax
    ; Final independent observation of ALL ports, not just a software cursor.
    xor ecx, ecx
.stop_observe:
    lea rax, [rel ahci_pbases]
    mov rdx, [rax+rcx*8]
    mov eax, [rdx+AHCI_PORT_CMD]
    and eax, AHCI_PXCMD_ST|AHCI_PXCMD_CR|AHCI_PXCMD_FRE|AHCI_PXCMD_FR
    or eax, [rdx+AHCI_PORT_CI]
    or eax, [rdx+AP_IE]
    or eax, [rdx+AHCI_PORT_IS]
    jnz .failed
    inc ecx
    cmp ecx, [rel ahci_port_count]
    jb .stop_observe
    mov rdx, [rel ahci_bar5]
    test dword [rdx+AHCI_REG_GHC], AP_IRQ
    jnz .failed
    cmp dword [rdx+AP_IS], 0
    jne .failed
    mov byte [rel ap_baseline], 1
    mov dword [rel ap_cursor], 0
    mov dword [rel ap_stage], 0
    mov edx, 31
    jmp .ok
.restored:
    mov dword [rel ap_cursor], 0
    mov dword [rel ap_stage], 0
    mov edx, DP_ACK_FENCED
.ok:
    xor eax, eax
    jmp .out
.pending_or_failed:
    cmp eax, DP_PENDING
    jne .failed
.pending:
    mov eax, DP_PENDING
    xor edx, edx
    jmp .out
.changed:
    mov rax, DP_CHANGED
    jmp .error
.failed:
    mov rax, DP_FAILED
.error:
    xor edx, edx
.out:
    mov byte [rel ap_permit], 0
    ; The coordinator validates the aggregate declaration; validate EVERY
    ; pinned medium/queue again after an actual callback operation as well.
    push rax
    push rdx
    call reinit_power_ahci_identity
    test rax, rax
    pop rdx
    pop rcx
    jz .post_identity_ok
    mov rax, DP_CHANGED
    xor edx, edx
    jmp .post_identity_out
.post_identity_ok:
    mov rax, rcx
.post_identity_out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

; ZF=1 only for an idle error-free device. BSY/DRQ/ERR/DF never earn acks.
reinit_power_ahci_idle:
    mov eax, [r13+AHCI_PORT_TFD]
    and eax, 0xA9
    ret
reinit_power_ahci_complete:
    mov eax, DP_FAILED
    test dword [r13+AHCI_PORT_IS], 0x7D800010
    jnz .out
    cmp dword [r13+AHCI_PORT_CI], 0
    jne .pending
    call reinit_power_ahci_idle
    test eax, eax
    jz .out
    mov eax, DP_FAILED
    test eax, eax
    ret
.pending:
    mov eax, DP_PENDING
.out:
    test eax, eax
    ret

reinit_power_ahci_command:
    mov [rel ap_opcode], r10b
    mov byte [rel ap_permit], 1
    mov edi, [rel ap_cursor]
    xor esi, esi
    xor edx, edx
    xor r8d, r8d
    xor ecx, ecx
    xor r11d, r11d
    cmp r10b, AHCI_ATA_FLUSH
    je .issue
    mov edx, 1
    mov r8d, 512
    lea rcx, [rel ahci_bounces]
    mov rcx, [rcx+rdi*8]
.issue:
    sub rsp, 8
    call ahci_issue_cooperative
    add rsp, 8
    mov byte [rel ap_permit], 0
    ret

%macro WDATA_svc_reinit_power_ahci 0
align 8
ap_context: dq 0
ap_declaration: times dp_driver_size db 0
ap_token: dq 0
ap_cursor: dd 0
ap_stage: dd 0
ap_irq_saved: db 0
ap_baseline: db 0
ap_permit: db 0
ap_opcode: db 0
align 4
ap_ghc: dd 0
ap_ie: times AHCI_MAX_DISKS dd 0
ap_pci_id: dd 0
ap_pin_ahci_bar5: dq 0
ap_pin_ahci_cap: dd 0
ap_pin_ahci_pi: dd 0
ap_pin_ahci_busno: times 3 dd 0
ap_pin_ahci_port_count: dd 0
ap_pin_ahci_ports: times AHCI_MAX_DISKS dd 0
ap_pin_ahci_port_present: times AHCI_MAX_DISKS db 0
ap_pin_ahci_pbases: times AHCI_MAX_DISKS dq 0
ap_pin_ahci_cls: times AHCI_MAX_DISKS dq 0
ap_pin_ahci_cts: times AHCI_MAX_DISKS dq 0
ap_pin_ahci_idbufs: times AHCI_MAX_DISKS dq 0
ap_pin_ahci_bounces: times AHCI_MAX_DISKS dq 0
ap_pin_ahci_lba_maxes: times AHCI_MAX_DISKS dq 0
ap_pin_ahci_ops: times blk_ops_size db 0
ap_devs: times AHCI_MAX_DISKS*dev_size db 0
ap_infos: times AHCI_MAX_DISKS*blk_info_size db 0
ap_before: times AHCI_MAX_DISKS*512 db 0
%endmacro
WDATA_DEFER WDATA_svc_reinit_power_ahci
