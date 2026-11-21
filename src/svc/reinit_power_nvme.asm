;; MODULE svc/reinit_power_nvme
;; LAYER 5
;; EXPORTS reinit_power_nvme_register, reinit_power_nvme_admit, reinit_power_nvme_read
;; IMPORTS svc/reinit_power, fs/blockdev, dev/blk/nvme, bus/pci, dev/blk/vmd, core/lib/mem
;; CAPS mmio dma
;; OWNER saga:resource
;; CONTEXT: bsp_only
; Trusted opt-in, one immutable NVMe namespace/controller lifetime. Controller
; stays ENABLED. No reset/shutdown/reprobe/allocation, IRQ mask or power-loss
; claim. Keep context, sidecar and every DMA page pinned even after DEGRADED.
; No detach/retry/rebind entry; no boot/command registration.
%include "core/abi/driver_power.inc"

reinit_power_nvme_pin:
    test r12d, r12d
    jnz memcpy
    xchg rdi, rsi
    jmp memcmp
%macro NP_PIN 2
    lea rsi, [rel %1]
    lea rdi, [rel np_pin_%1]
    mov edx, %2
    call reinit_power_nvme_pin
    test r12d, r12d
    jnz %%ok
    test eax, eax
    jnz .bad
%%ok:
%endmacro

; R12D=1 private registration capture, otherwise compare all immutable records.
; Mutable queue indices are validated separately, never restored from cache.
reinit_power_nvme_set:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    cld
    cmp byte [rel nvme_present], 1
    jne .bad
    cmp byte [rel nvme_io_poisoned], 0
    jne .bad
    cmp dword [rel nvme_health], HEALTH_OK
    jne .bad
    cmp dword [rel nvme_devs+dev.health], HEALTH_OK
    jne .bad
    cmp dword [rel nvme_devs+dev.class], CLASS_BLOCK
    jne .bad
    cmp qword [rel nvme_devs+dev.priv], 0
    jne .bad
    lea rax, [rel nvme_ops]
    cmp [rel nvme_devs+dev.ops], rax
    jne .bad
    lea rax, [rel nvme_info]
    cmp [rel nvme_devs+dev.info], rax
    jne .bad
    cmp qword [rel nvme_info+blk_info.media_generation], 0
    je .bad
    mov eax, [rel nvme_info+blk_info.capabilities]
    and eax, BLKCAP_READ|BLKCAP_FLUSH
    cmp eax, BLKCAP_READ|BLKCAP_FLUSH
    jne .bad
    lea rax, [rel nvme_op_identify]
    cmp [rel nvme_ops+blk_ops.identify], rax
    jne .bad
    lea rax, [rel nvme_op_read]
    cmp [rel nvme_ops+blk_ops.read], rax
    jne .bad
    lea rax, [rel nvme_op_write]
    cmp [rel nvme_ops+blk_ops.write], rax
    jne .bad
    lea rax, [rel nvme_op_flush]
    cmp [rel nvme_ops+blk_ops.flush], rax
    jne .bad
    NP_PIN nvme_bar0, 8
    NP_PIN nvme_cap, 8
    NP_PIN nvme_stride, 4
    NP_PIN nvme_claim_legacy, 1
    NP_PIN nvme_busno, 12
    NP_PIN nvme_vmd_child, 1
    NP_PIN nvme_vmd_cfg, 8
    NP_PIN nvme_sector_size, 4
    NP_PIN nvme_physical_size, 4
    NP_PIN nvme_identify_fields, 28
    NP_PIN nvme_lba_max, 8
    NP_PIN nvme_asq, 48
    NP_PIN nvme_ops, blk_ops_size
    NP_PIN nvme_devs, 40
    NP_PIN nvme_info, blk_info_size
    NP_PIN nvme_model, 48
    NP_PIN nvme_serial, 24
    test r12d, r12d
    jnz .hooks_ok
    lea rax, [rel reinit_power_nvme_gate]
    cmp [rel nvme_power_gate], rax
    jne .bad
    lea rax, [rel reinit_power_nvme_command_gate]
    cmp [rel nvme_power_command_gate], rax
    jne .bad
.hooks_ok:
    ; Six exclusive, page-aligned driver-owned allocations, no alias/reassign.
    lea r13, [rel nvme_asq]
    xor r14d, r14d
.pages:
    mov rax, [r13+r14*8]
    test rax, rax
    jz .bad
    test eax, 4095
    jnz .bad
    xor ecx, ecx
.distinct:
    cmp ecx, r14d
    jae .page_next
    cmp rax, [r13+rcx*8]
    je .bad
    inc ecx
    jmp .distinct
.page_next:
    inc r14d
    cmp r14d, 6
    jb .pages
    mov rbx, [rel nvme_bar0]
    test rbx, rbx
    jz .bad
    test ebx, 4095
    jnz .bad
    mov rax, [rbx]
    cmp rax, [rel nvme_cap]
    jne .bad
    cmp ax, NVME_ASIZE-1
    jb .bad
    bt rax, 37                           ; NVM command set supported
    jnc .bad
    mov rdx, rax
    shr rdx, 48
    test dl, 15                          ; MPSMIN=0 for existing 4KiB queues
    jnz .bad
    shr rax, 32
    and eax, 15
    mov ecx, eax
    mov eax, 4
    shl eax, cl
    cmp eax, [rel nvme_stride]
    jne .bad
    cmp dword [rbx+0x14], (4<<20)|(6<<16)|1
    jne .bad                             ; exact EN/CSS/MPS/AMS/SHN/queue sizes
    mov eax, [rbx+0x1c]
    and eax, 15
    cmp eax, 1                           ; RDY, no fatal or shutdown state
    jne .bad
    cmp dword [rbx+0x24], ((NVME_ASIZE-1)<<16)|(NVME_ASIZE-1)
    jne .bad
    mov rax, [rel nvme_asq]
    cmp [rbx+0x28], rax
    jne .bad
    mov rax, [rel nvme_acq]
    cmp [rbx+0x30], rax
    jne .bad
    cmp byte [rel nvme_vmd_child], 0
    jne .vmd
    cmp byte [rel nvme_claim_legacy], 1
    jne .bad
    cmp qword [rel nvme_vmd_cfg], 0
    jne .bad
    jmp .pci
.vmd:
    cmp byte [rel nvme_vmd_child], 1
    jne .bad
    cmp byte [rel nvme_claim_legacy], 0
    jne .bad
    cmp qword [rel nvme_vmd_cfg], 0
    je .bad
    mov edi, 0x010802
    call vmd_find_child
    cmp rax, rbx
    jne .bad
    cmp rdx, [rel nvme_vmd_cfg]
    jne .bad
.pci:
    xor ecx, ecx
    call reinit_power_nvme_cfg
    test ax, ax
    jz .bad
    cmp ax, 0xffff
    je .bad
    test r12d, r12d
    jz .pci_compare
    mov [rel np_pci_id], eax
.pci_compare:
    cmp eax, [rel np_pci_id]
    jne .bad
    mov ecx, 4
    call reinit_power_nvme_cfg
    and eax, 6
    cmp eax, 6
    jne .bad
    mov ecx, 0x10
    call reinit_power_nvme_cfg
    test eax, 1
    jnz .bad
    mov r13d, eax
    and r13d, 0xfffffff0
    and eax, 6
    cmp eax, 4
    je .bar64
    test eax, eax
    jnz .bad
    jmp .bar_compare
.bar64:
    mov ecx, 0x14
    call reinit_power_nvme_cfg
    shl rax, 32
    or r13, rax
.bar_compare:
    cmp r13, rbx
    jne .bad
    ; Registry membership and uniqueness of the actual fenced backend.
    xor edi, edi
    xor r13d, r13d
    xor r14d, r14d
.registry:
    xor esi, esi
    xor edx, edx
    call blk_iter_after
    test rax, rax
    jz .registry_done
    inc r13d
    cmp r13d, BLK_REGISTRY_LIMIT
    ja .bad
    lea rcx, [rel nvme_devs]
    cmp rax, rcx
    je .ours
    lea rcx, [rel nvme_ops]
    cmp [rax+dev.ops], rcx
    je .bad
    jmp .next
.ours:
    inc r14d
.next:
    mov rdi, rax
    jmp .registry
.registry_done:
    cmp r14d, 1
    jne .bad
    mov eax, [rel nvme_sector_size]
    cmp eax, 512                          ; 0.1: refuse4K before private commands
    jne .bad
.sector:
    cmp eax, [rel nvme_info+blk_info.logical_sector_bytes]
    jne .bad
    cmp eax, [rel nvme_info+blk_info.sector_size]
    jne .bad
    mov eax, [rel nvme_physical_size]
    cmp eax, [rel nvme_info+blk_info.physical_sector_bytes]
    jne .bad
    cmp dword [rel nvme_info+blk_info.physical_alignment_bytes], 0
    jne .bad
    cmp dword [rel nvme_info+blk_info.unit], 1
    jne .bad
    mov rax, [rel nvme_lba_max]
    cmp rax, [rel nvme_info+blk_info.lba_max]
    jne .bad
    ; Bind stable namespace identity/format, excluding changing NUSE bytes.
    mov rbx, [rel nvme_idbuf]
    mov rax, [rbx]
    test rax, rax
    jz .bad
    dec rax
    cmp rax, [rel nvme_lba_max]
    jne .bad
    mov rax, [rbx+8]
    test rax, rax
    jz .bad
    cmp rax, [rbx]
    ja .bad
    movzx eax, byte [rbx+26]
    test eax, 0xf0
    jnz .bad
    cmp byte [rbx+25], 15
    ja .bad
    cmp al, [rbx+25]
    ja .bad
    cmp byte [rbx+29], 0
    jne .bad
    lea eax, [rax*4+128]
    cmp word [rbx+rax], 0
    jne .bad
    movzx ecx, byte [rbx+rax+2]
    cmp ecx, 9
    je .format
    cmp ecx, 12
    jne .bad
.format:
    mov eax, 1
    shl eax, cl
    cmp eax, [rel nvme_sector_size]
    jne .bad
    mov ecx, eax
    call nvme_namespace_physical
    test eax, eax
    jz .bad
    cmp eax, [rel nvme_physical_size]
    jne .bad
    ; A new physical unit must remain bound to the exact same namespace page,
    ; including the raw evidence published by BLKINFO, throughout custody.
    cmp dword [rel nvme_identify_valid], 1
    jne .bad
%macro NP_RAW_FIELD 3
    movzx eax, %2 [rbx+%3]
    cmp eax, [rel nvme_identify_%1]
    jne .bad
%endmacro
    NP_RAW_FIELD flbas, byte, 26
    NP_RAW_FIELD nsfeat, byte, 24
    NP_RAW_FIELD npwg, word, 64
    NP_RAW_FIELD nows, word, 72
    NP_RAW_FIELD nawupf, word, 36
%unmacro NP_RAW_FIELD 3
    movzx eax, byte [rbx+26]
    and eax, 15
    mov eax, [rbx+rax*4+128]
    cmp eax, [rel nvme_identify_lbaf]
    jne .bad
    mov rsi, rbx
    lea rdi, [rel np_namespace]
    mov edx, 16
    call reinit_power_nvme_pin
    test r12d, r12d
    jnz .ns2
    test eax, eax
    jnz .bad
.ns2:
    lea rsi, [rbx+24]
    lea rdi, [rel np_namespace+24]
    mov edx, 8
    call reinit_power_nvme_pin
    test r12d, r12d
    jnz .ns3
    test eax, eax
    jnz .bad
.ns3:
    lea rsi, [rbx+32]
    lea rdi, [rel np_namespace+32]
    mov edx, 42                          ; atomic/preferred write fields through NOWS
    call reinit_power_nvme_pin
    test r12d, r12d
    jnz .ns4
    test eax, eax
    jnz .bad
.ns4:
    lea rsi, [rbx+104]
    lea rdi, [rel np_namespace+104]
    mov edx, 88                          ; NGUID/EUI64 and all 16 LBAF entries
    call reinit_power_nvme_pin
    test r12d, r12d
    jnz .queues
    test eax, eax
    jnz .bad
.queues:
    call reinit_power_nvme_queues
    test rax, rax
    jnz .bad
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
    cld
    ret

; Bounds, observed consumed SQ heads, pending ownership and phase publication.
; A matching phase without a tracked command is an unexpected/late completion.
reinit_power_nvme_queues:
    cmp byte [rel nvme_io_pending], 1
    ja .bad
    cmp byte [rel nvme_admin_pending], 1
    ja .bad
    cmp word [rel nvme_asq_tail], NVME_ASIZE
    jae .bad
    cmp word [rel nvme_acq_head], NVME_ASIZE
    jae .bad
    cmp byte [rel nvme_acq_phase], 1
    ja .bad
    cmp word [rel nvme_admin_sqhd], NVME_ASIZE
    jae .bad
    cmp word [rel nvme_iosq_tail], NVME_IOSIZE
    jae .bad
    cmp word [rel nvme_iocq_head], NVME_IOSIZE
    jae .bad
    cmp byte [rel nvme_iocq_phase], 1
    ja .bad
    cmp word [rel nvme_io_sqhd], NVME_IOSIZE
    jae .bad
    cmp byte [rel nvme_admin_pending], 0
    jne .io
    mov ax, [rel nvme_admin_sqhd]
    cmp ax, [rel nvme_asq_tail]
    jne .bad
    movzx ecx, word [rel nvme_acq_head]
    shl ecx, 4
    mov rdx, [rel nvme_acq]
    mov al, [rdx+rcx+14]
    and al, 1
    cmp al, [rel nvme_acq_phase]
    je .bad
.io:
    cmp byte [rel nvme_io_pending], 0
    jne .good
    mov ax, [rel nvme_io_sqhd]
    cmp ax, [rel nvme_iosq_tail]
    jne .bad
    movzx ecx, word [rel nvme_iocq_head]
    shl ecx, 4
    mov rdx, [rel nvme_iocq]
    mov al, [rdx+rcx+14]
    and al, 1
    cmp al, [rel nvme_iocq_phase]
    je .bad
.good:
    xor eax, eax
    ret
.bad:
    mov rax, DP_CHANGED
    ret

reinit_power_nvme_cfg:
    cmp byte [rel nvme_vmd_child], 0
    je .legacy
    mov rax, [rel nvme_vmd_cfg]
    mov eax, [rax+rcx]
    ret
.legacy:
    mov edi, [rel nvme_busno]
    mov esi, [rel nvme_devno]
    mov edx, [rel nvme_fn]
    jmp pci_cfg_read32

reinit_power_nvme_register:
    push rbx
    push r12
    push r13
    cld
    mov rbx, rdi
    mov r13d, esi
    mov rax, DP_BUSY
    cmp qword [rel np_context], 0
    jne .out
    cmp qword [rel nvme_power_gate], 0
    jne .out
    cmp qword [rel nvme_power_command_gate], 0
    jne .out
    cmp byte [rel nvme_io_pending], 0
    jne .changed
    cmp byte [rel nvme_admin_pending], 0
    jne .changed
    mov r12d, 1
    call reinit_power_nvme_set
    test rax, rax
    jnz .out
    lea rsi, [rel np_declaration]
    mov dword [rsi+dp_driver.version], DP_VERSION
    mov dword [rsi+dp_driver.kind], DP_STORAGE
    lea rax, [rel nvme_devs]
    mov [rsi+dp_driver.owner], rax
    lea rax, [rel nvme_info+blk_info.media_generation]
    mov [rsi+dp_driver.generation_ptr], rax
    mov rax, [rax]
    mov [rsi+dp_driver.generation], rax
    lea rax, [rel reinit_power_nvme_callback]
    mov [rsi+dp_driver.callback], rax
    mov [rsi+dp_driver.dependencies], r13d
    mov dword [rsi+dp_driver.capabilities], DP_CAP_DMA|DP_CAP_FLUSH
    mov rdi, rbx
    call reinit_power_register
    test rax, rax
    jnz .out
    mov [rel np_context], rbx
    lea rax, [rel reinit_power_nvme_gate]
    mov [rel nvme_power_gate], rax
    lea rax, [rel reinit_power_nvme_command_gate]
    mov [rel nvme_power_command_gate], rax
    xor eax, eax
    jmp .out
.changed:
    mov rax, DP_CHANGED
.out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

reinit_power_nvme_identity:
    push r12
    xor r12d, r12d
    call reinit_power_nvme_set
    pop r12
    ret

; Queued producers retain the issued full64 token. Ordinary synchronous class
; calls use the current immediate lifetime, only while RUNNING and no work owns
; either shared command/bounce buffer. Never renew an old queued token.
reinit_power_nvme_admit:
    push rbx
    mov rbx, rdi
    call reinit_power_nvme_identity
    test rax, rax
    jnz .out
    mov rdi, [rel np_context]
    mov rsi, rbx
    lea rdx, [rel nvme_devs]
    mov rcx, [rel np_declaration+dp_driver.generation]
    call reinit_power_admit
    test rax, rax
    jnz .out
    cmp byte [rel nvme_io_pending], 0
    jne .busy
    cmp byte [rel nvme_admin_pending], 0
    je .out
.busy:
    mov rax, DP_BUSY
.out:
    pop rbx
    cld
    ret
reinit_power_nvme_gate:
    mov rdi, [rel np_context]
    test rdi, rdi
    jz .bad
    mov rdi, [rdi+dp_context.token]
    jmp reinit_power_nvme_admit
.bad:
    mov rax, DP_CHANGED
    cld
    ret
reinit_power_nvme_read:
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    call reinit_power_nvme_admit
    test rax, rax
    jnz .out
    lea rdi, [rel nvme_devs]
    cmp rdi, r12
    jne .changed
    mov rsi, r13
    mov rdx, r14
    mov rcx, r15
    call blk_read
    jmp .out
.changed:
    mov rax, DP_CHANGED
.out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    cld
    ret

; One use, exact internal shape, only inside active coordinator callback.
; R11D mode is conveyed by backend power_check with original arguments intact.
reinit_power_nvme_command_gate:
    cmp r11d, 4
    je .running_poll
    movzx eax, byte [rel np_permit]
    mov byte [rel np_permit], 0
    cmp eax, r11d
    jne .bad
    test eax, eax
    jz .bad
    cmp byte [rel np_active], 1
    jne .bad
    mov r10, [rel np_context]
    cmp byte [r10+dp_context.busy], 1
    jne .bad
    mov rax, [rel np_token]
    cmp [r10+dp_context.token], rax
    jne .bad
    mov eax, [r10+dp_context.phase]
    cmp eax, DP_STOP
    je .phase_ok
    cmp eax, DP_VERIFY
    jne .bad
.phase_ok:
    cmp r11d, 3
    je .poll
    ; Snapshot is built privately from READ0, FLUSH or Namespace Identify only.
    lea rdi, [rel nvme_cmd]
    lea rsi, [rel np_expected]
    mov edx, NVME_SQ_ESZ
    sub rsp, 8
    call memcmp
    add rsp, 8
    test eax, eax
    jnz .bad
    xor eax, eax
    ret
.running_poll:
    mov r10, [rel np_context]
    test r10, r10
    jz .bad
    cmp dword [r10+dp_context.state], DP_RUNNING
    jne .bad
    cmp byte [r10+dp_context.busy], 0
    jne .bad
    ; Validate identity before observing an accepted synchronous command.
    push rdi
    push rsi
    push rdx
    push r8
    push r9
    call reinit_power_nvme_identity
    pop r9
    pop r8
    pop rdx
    pop rsi
    pop rdi
    test rax, rax
    jnz .bad
.poll:
    cmp r8d, NVME_ASIZE
    jne .bad
    cmp r9d, 1
    ja .bad
    test r9d, r9d
    jnz .io
    cmp byte [rel nvme_admin_pending], 1
    jne .bad
    cmp rdi, [rel nvme_acq]
    jne .bad
    lea rax, [rel nvme_acq_head]
    cmp rsi, rax
    jne .bad
    lea rax, [rel nvme_acq_phase]
    cmp rdx, rax
    jne .bad
    jmp .ok
.io:
    cmp byte [rel nvme_io_pending], 1
    jne .bad
    cmp rdi, [rel nvme_iocq]
    jne .bad
    lea rax, [rel nvme_iocq_head]
    cmp rsi, rax
    jne .bad
    lea rax, [rel nvme_iocq_phase]
    cmp rdx, rax
    jne .bad
.ok:
    xor eax, eax
    ret
.bad:
    mov rax, DP_CHANGED
    ret

; EAX=1 READ0 / 2 FLUSH / 3 Namespace Identify; all share owned DMA only.
reinit_power_nvme_command:
    mov r10, [rel np_context]
    test r10, r10
    jz .refused
    cmp byte [rel np_active], 1
    jne .refused
    cmp byte [r10+dp_context.busy], 1
    jne .refused
    mov r11, [rel np_token]
    cmp [r10+dp_context.token], r11
    jne .refused
    cmp dword [r10+dp_context.phase], DP_STOP
    je .admitted
    cmp dword [r10+dp_context.phase], DP_VERIFY
    jne .refused
.admitted:
    push rbx
    mov ebx, eax
    call nvme_cmd_clear
    mov dword [rel nvme_cmd+4], 1
    cmp ebx, 3
    je .identify
    cmp ebx, 2
    je .flush
    mov byte [rel nvme_cmd], NVME_OP_READ
    mov rax, [rel nvme_bounce]
    mov [rel nvme_cmd+24], rax
    jmp .io
.flush:
    mov byte [rel nvme_cmd], NVME_OP_FLUSH
.io:
    mov byte [rel np_permit], 1
    jmp .save
.identify:
    movzx eax, word [rel nvme_admin_cid]
    inc eax
    cmp eax, 0xffff
    jb .cid
    mov eax, 1
.cid:
    shl eax, 16
    or eax, NVME_OP_IDENTIFY
    mov [rel nvme_cmd], eax
    mov rax, [rel nvme_idbuf]
    mov [rel nvme_cmd+24], rax
    mov byte [rel np_permit], 2
.save:
    lea rsi, [rel nvme_cmd]
    lea rdi, [rel np_expected]
    mov edx, NVME_SQ_ESZ
    call memcpy
    cmp ebx, 3
    je .admin
    call nvme_io_exec_cooperative
    jmp .out
.admin:
    call nvme_admin_exec_cooperative
.out:
    mov byte [rel np_permit], 0
    pop rbx
    ret

.refused:
    mov rax, DP_CHANGED
    cld
    ret

; EDI=qid; at most ONE CQE observation per invocation, never a busy wait.
reinit_power_nvme_complete:
    mov byte [rel np_permit], 3
    sub rsp, 8
    call nvme_power_poll
    add rsp, 8
    mov byte [rel np_permit], 0
    cmp eax, 0x10000
    jne .out
    mov eax, DP_PENDING
    ret
.out:
    test rax, rax
    jz .ret
    mov rax, DP_FAILED
.ret:
    ret

reinit_power_nvme_callback:
    push rbx
    push r12
    push r13
    cld
    mov rbx, [rel np_context]
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
    cmp r8, [rel np_declaration+dp_driver.generation]
    jne .changed
    lea rax, [rel nvme_devs]
    cmp rdi, rax
    jne .changed
    mov r12d, esi
    mov r13, rdx
    ; A timeout cannot be turned into RUNNING by recovery's fresh read.
    ; Cancellation before STOP is independently recoverable; timeout is not.
    cmp dword [rbx+dp_context.error], DP_TIMEOUT
    je .failed
    call reinit_power_nvme_identity
    test rax, rax
    jnz .changed
    mov byte [rel np_active], 1
    cmp r12d, DP_FENCE
    je .fence
    cmp r13, [rel np_token]
    je .same_token
    ; Cancelled before FENCE: still require fresh namespace and useful read.
    cmp r12d, DP_VERIFY
    jne .changed
    mov [rel np_token], r13
    mov dword [rel np_stage], 0
    mov byte [rel np_baseline], 0
.same_token:
    cmp r12d, DP_STOP
    je .stop
    cmp r12d, DP_RESTORE
    je .restore
    cmp r12d, DP_VERIFY
    je .verify
    jmp .changed
.fence:
    mov [rel np_token], r13
    mov dword [rel np_stage], 0
    mov byte [rel np_baseline], 0
    mov edx, DP_ACK_FENCED
    jmp .ok
.stop:
    mov eax, [rel np_stage]
    cmp eax, 0
    je .drain
    cmp eax, 1
    je .baseline_done
    cmp eax, 2
    je .flush_done
    jmp .failed
.drain:
    cmp byte [rel nvme_admin_pending], 0
    jne .drain_admin
    cmp byte [rel nvme_io_pending], 0
    jne .drain_io
    mov eax, 1
    call reinit_power_nvme_command
    test rax, rax
    jnz .failed
    mov dword [rel np_stage], 1
    jmp .pending
.drain_admin:
    xor edi, edi
    call reinit_power_nvme_complete
    jmp .completion_edge
.drain_io:
    mov edi, 1
    call reinit_power_nvme_complete
.completion_edge:
    test rax, rax
    jz .pending
    jmp .pending_or_failed
.baseline_done:
    mov edi, 1
    call reinit_power_nvme_complete
    test rax, rax
    jnz .pending_or_failed
    mov rsi, [rel nvme_bounce]
    lea rdi, [rel np_before]
    mov edx, [rel nvme_sector_size]
    call memcpy
    mov eax, 2
    call reinit_power_nvme_command
    test rax, rax
    jnz .failed
    mov dword [rel np_stage], 2
    jmp .pending
.flush_done:
    mov edi, 1
    call reinit_power_nvme_complete
    test rax, rax
    jnz .pending_or_failed
    cmp byte [rel nvme_admin_pending], 0
    jne .failed
    cmp byte [rel nvme_io_pending], 0
    jne .failed
    call reinit_power_nvme_queues
    test rax, rax
    jnz .failed
    ; Freeze both SQ tails, CQ heads/phases and observed SQ heads. No CC write.
    lea rsi, [rel nvme_asq_tail]
    lea rdi, [rel np_frozen]
    mov edx, 10
    call memcpy
    mov eax, [rel nvme_io_sqhd]
    mov [rel np_frozen+10], eax
    mov byte [rel np_baseline], 1
    mov dword [rel np_stage], 0
    mov edx, DP_ACK_FENCED|DP_ACK_DRAINED|DP_ACK_DMA_STOPPED|DP_ACK_FLUSHED
    jmp .ok
.restore:
    cmp byte [rel np_baseline], 1
    jne .failed
    lea rdi, [rel nvme_asq_tail]
    lea rsi, [rel np_frozen]
    mov edx, 10
    call memcmp
    test eax, eax
    jnz .failed
    mov eax, [rel nvme_io_sqhd]
    cmp eax, [rel np_frozen+10]
    jne .failed
    mov dword [rel np_stage], 0
    mov edx, DP_ACK_FENCED
    jmp .ok
.verify:
    mov eax, [rel np_stage]
    cmp eax, 0
    je .verify_start
    cmp eax, 1
    je .identified
    cmp eax, 2
    je .read_done
    jmp .failed
.verify_start:
    cmp byte [rel nvme_admin_pending], 0
    jne .failed
    cmp byte [rel nvme_io_pending], 0
    jne .failed
    mov eax, 3
    call reinit_power_nvme_command
    test rax, rax
    jnz .failed
    mov dword [rel np_stage], 1
    jmp .pending
.identified:
    xor edi, edi
    call reinit_power_nvme_complete
    test rax, rax
    jnz .pending_or_failed
    call reinit_power_nvme_identity
    test rax, rax
    jnz .changed
    mov eax, 1
    call reinit_power_nvme_command
    test rax, rax
    jnz .failed
    mov dword [rel np_stage], 2
    jmp .pending
.read_done:
    mov edi, 1
    call reinit_power_nvme_complete
    test rax, rax
    jnz .pending_or_failed
    cmp byte [rel np_baseline], 1
    jne .ready
    mov rdi, [rel nvme_bounce]
    lea rsi, [rel np_before]
    mov edx, [rel nvme_sector_size]
    call memcmp
    test eax, eax
    jnz .failed
.ready:
    mov dword [rel np_stage], 0
    mov edx, DP_ACK_FENCED|DP_ACK_READY
    jmp .ok
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
    jmp .out
.ok:
    xor eax, eax
.out:
    mov byte [rel np_permit], 0
    mov byte [rel np_active], 0
    push rax
    push rdx
    call reinit_power_nvme_identity
    test rax, rax
    pop rdx
    pop rcx
    jz .post_ok
    mov rax, DP_CHANGED
    xor edx, edx
    jmp .post_out
.post_ok:
    mov rax, rcx
.post_out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

%macro WDATA_svc_reinit_power_nvme 0
align 8
np_context: dq 0
np_declaration: times dp_driver_size db 0
np_token: dq 0
np_stage: dd 0
np_pci_id: dd 0
np_baseline: db 0
np_permit: db 0
np_active: db 0
np_frozen: times 14 db 0
np_expected: times NVME_SQ_ESZ db 0
np_pin_nvme_bar0: times 8 db 0
np_pin_nvme_cap: times 8 db 0
np_pin_nvme_stride: times 4 db 0
np_pin_nvme_claim_legacy: times 1 db 0
np_pin_nvme_busno: times 12 db 0
np_pin_nvme_vmd_child: times 1 db 0
np_pin_nvme_vmd_cfg: times 8 db 0
np_pin_nvme_sector_size: times 4 db 0
np_pin_nvme_physical_size: times 4 db 0
np_pin_nvme_identify_fields: times 28 db 0
np_pin_nvme_lba_max: times 8 db 0
np_pin_nvme_asq: times 48 db 0
np_pin_nvme_ops: times blk_ops_size db 0
np_pin_nvme_devs: times 40 db 0
np_pin_nvme_info: times blk_info_size db 0
np_pin_nvme_model: times 48 db 0
np_pin_nvme_serial: times 24 db 0
np_namespace: times 192 db 0
np_before: times 4096 db 0
%endmacro
WDATA_DEFER WDATA_svc_reinit_power_nvme
