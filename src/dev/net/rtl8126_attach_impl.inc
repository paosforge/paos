; R16 independent protocol engine. Pinned BSD register facts in spec and data.
; Every RMW is observed once, not retried until it appears to match. Optional
; readiness timeouts are recorded and processing continues. Only CMD.RESET
; failure prevents DMA; existing PCI identity/MAC/range/ownership guards remain.
; Tables: 16-byte {kind, register, preserved-bit mask, set bits}; kind0 ends.
; Data-port writes (kind7) observe the transport latch, NOT the auto-increment
; data register. Reading A438/B87E between writes would corrupt the stream.

; EDI=kind, ESI=register, EDX=status, EAX=observed. Preserve all registers.
r26_record:
    push rbx
    push rcx
    push r8
    lea rbx, [rel r26_attach_trace]
    mov ecx, [rbx+8]
    cmp ecx, R26A_CAPACITY
    jae .overflow
    lea r8, [rbx+rcx*8+R26A_HEADER]
    mov [r8], dil
    mov [r8+1], dl
    mov [r8+2], si
    mov [r8+4], eax
    inc dword [rbx+8]
    jmp .out
.overflow:
    inc dword [rbx+12]
.out:
    pop r8
    pop rcx
    pop rbx
    ret

r26_trace_init:
    push rdi
    push rcx
    mov rax, [rel r26_attach_trace+40]
    inc rax
    push rax
    lea rdi, [rel r26_attach_trace]
    mov ecx, R26A_SIZE/8
    xor eax, eax
    cld
    rep stosq
    pop rax
    mov [rel r26_attach_trace+40], rax
    mov dword [rel r26_attach_trace], R26A_MAGIC
    mov word [rel r26_attach_trace+4], R26A_VERSION
    mov word [rel r26_attach_trace+6], R26A_SIZE
    pop rcx
    pop rdi
    ret

; RAM-only public snapshot. Header counters are sampled independently, not
; claimed as one hardware transaction; no MMIO/PCI/network/firmware call.
r26_attach_snapshot_impl:
    cmp esi, R26A_SIZE
    jb .bad
    test rdi, rdi
    jz .bad
    cmp dword [rel r26_attach_trace], R26A_MAGIC
    jne .bad
    push rsi
    push rcx
    mov rax, [rel e5000b_rx_frames]
    mov [rel r26_attach_trace+64], rax
    mov rax, [rel e5000b_tx_frames]
    mov [rel r26_attach_trace+72], rax
    mov rax, [rel e5000b_tx_timeouts]
    mov [rel r26_attach_trace+80], rax
    mov rax, [rel e5000b_tx_drops]
    mov [rel r26_attach_trace+88], rax
    mov rax, [rel e5000b_rx_drops]
    mov [rel r26_attach_trace+96], rax
    mov rax, [rel e5000b_owner_mismatches]
    mov [rel r26_attach_trace+104], rax
    mov rax, [rel e5000b_rx_du_acks]
    mov [rel r26_attach_trace+112], rax
    mov rax, [rel e5000b_recover_successes]
    mov [rel r26_attach_trace+120], rax
    lea rsi, [rel r26_attach_trace]
    mov ecx, R26A_SIZE/8
    cld
    rep movsq
    mov eax, R26A_SIZE
    pop rcx
    pop rsi
    ret
.bad:
    mov eax, -1
    ret

; CSI dword transport: ESI register / EDX value; read EAX or -1.
r26_csi_read:
    push rbx
    and esi, 0xfff
    mov edx, esi
    or edx, 0xf000
    mov esi, 0x68
    call e5b_wr
    mov ebx, 20000
.poll:
    mov edi, 1
    call tsc_delay_us
    mov esi, 0x68
    call e5b_rd
    test eax, 0x80000000
    jnz .done
    dec ebx
    jnz .poll
    mov rax, -1
    jmp .out
.done:
    mov edi, 20
    call tsc_delay_us
    mov esi, 0x64
    call e5b_rd
.out:
    pop rbx
    ret
r26_csi_write:
    push rbx
    push rsi
    mov esi, 0x64
    call e5b_wr
    pop rdx
    and edx, 0xfff
    or edx, 0x8000f000
    mov esi, 0x68
    call e5b_wr
    mov ebx, 20000
.poll:
    mov edi, 1
    call tsc_delay_us
    mov esi, 0x68
    call e5b_rd
    test eax, 0x80000000
    jz .done
    dec ebx
    jnz .poll
    mov rax, -1
    jmp .out
.done:
    mov edi, 20
    call tsc_delay_us
    xor eax, eax
.out:
    pop rbx
    ret

; RDI=table, callee-saved registers preserved. No optional-error early return.
r26_run_table:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
.next:
    mov r14d, [r12]
    test r14d, r14d
    jz .out
    mov ebx, [r12+4]
    mov r13d, [r12+8]
    mov ebp, [r12+12]
    xor r15d, r15d
    cmp r14d, 5
    je .delay
    cmp r14d, 6
    je .patch
    cmp r14d, 12
    je .twi
    ; Read before RMW only; mask-zero direct and kind7 stream writes skip it.
    cmp r14d, 7
    je .stream
    test r13d, r13d
    jz .write
    mov esi, ebx
    cmp r14d, 1
    je .mmread
    cmp r14d, 2
    je .macread
    cmp r14d, 3
    je .phyread
    call r26_csi_read
    cmp rax, -1
    je .read_timeout
    jmp .have
.mmread:
    call e5b_rd
    jmp .have
.macread:
    call e5b_mac_read
    jmp .have
.phyread:
    call e5b_phy_read
    test eax, eax
    js .read_timeout
.have:
    and eax, r13d
    or ebp, eax
    jmp .write
.read_timeout:
    ; A failed RMW read must not turn into an all-ones write. Record it and
    ; continue to the next independent register, never manufacture its value.
    mov r15d, 2
    jmp .record
.stream:
    mov r15d, 4
.write:
    mov esi, ebx
    mov edx, ebp
    cmp r14d, 1
    je .mmwrite
    cmp r14d, 2
    je .macwrite
    cmp r14d, 4
    je .csiwrite
    call e5b_phy_write
    test eax, eax
    jnz .timeout
    cmp r14d, 7
    je .stream_latch
    cmp ebx, 0xa438
    je .stream_latch
    cmp ebx, 0xb87e
    je .stream_latch
    mov esi, ebx
    call e5b_phy_read
    test eax, eax
    js .timeout
    jmp .compare
.mmwrite:
    call e5b_wr
    mov esi, ebx
    call e5b_rd
    jmp .compare
.macwrite:
    call e5b_mac_write
    mov esi, ebx
    call e5b_mac_read
    jmp .compare
.csiwrite:
    call r26_csi_write
    test eax, eax
    jnz .timeout
    mov esi, ebx
    call r26_csi_read
    cmp rax, -1
    je .timeout
.compare:
    cmp eax, ebp
    je .record
    mov r15d, 1
    jmp .record
.stream_latch:
    mov r15d, 4
.latch:
    mov esi, 0xb8
    call e5b_rd
    jmp .record
.timeout:
    mov eax, -1
    mov r15d, 2
    jmp .record
.delay:
    mov edi, ebp
    call tsc_delay_us
    mov eax, ebp
    jmp .record
.twi:
    call r26_twi_wait
    mov r15d, edx
    jmp .record
.patch:
    mov edi, ebp
    call r26_patch_phy
    mov r15d, edx
.record:
    mov edi, r14d
    mov esi, ebx
    mov edx, r15d
    call r26_record
    add r12, 16
    jmp .next
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; PHY MCU patch request and bounded acknowledgement; EDI=on -> EDX=status,
; EAX=last B800 observation. Timeout is recorded, not an attach abort.
r26_patch_phy:
    push rbx
    push r12
    mov r12d, edi
    mov esi, 0xb820
    call e5b_phy_read
    test eax, eax
    js .bad
    and eax, 0xffef
    test r12d, r12d
    jz .write
    or eax, 0x10
.write:
    mov edx, eax
    mov esi, 0xb820
    call e5b_phy_write
    test eax, eax
    jnz .bad
    mov ebx, 1000
.poll:
    mov esi, 0xb800
    call e5b_phy_read
    test eax, eax
    js .bad
    mov edx, eax
    and edx, 0x40
    test r12d, r12d
    jz .clear
    cmp edx, 0x40
    je .ok
    jmp .wait
.clear:
    test edx, edx
    jz .ok
.wait:
    mov edi, 100
    push rax                     ; retain last B800 sample if the wait expires
    call tsc_delay_us
    pop rax
    dec ebx
    jnz .poll
.bad:
    mov edx, 2
    jmp .out
.ok:
    xor edx, edx
.out:
    pop r12
    pop rbx
    ret

r26_twi_wait:
    push rbx
    mov ebx, 10
.poll:
    mov edi, 100
    call tsc_delay_us
    mov esi, 0xd0
    call e5b_rd
    test eax, 0x02000000
    jnz .ok
    dec ebx
    jnz .poll
    mov edx, 2
    jmp .out
.ok:
    xor edx, edx
.out:
    pop rbx
    ret

; Two bounded chip resets, in BSD chipinit order. No optional handoff readback
; may abort the sequence; mandatory command reset remains fatal at either reset.
e5000b_full_reset:
    push rbx
    call r26_trace_init
    mov byte [rel e5000b_drain_expired], 0
    mov byte [rel e5000b_bmcr_valid], 0
    mov word [rel e5000b_bmcr_before], 0
    mov word [rel e5000b_bmcr_after], 0
    mov word [rel e5000b_phy_state], 0
    call r26_dump_registers
    mov esi, 0x40
    call e5b_rd
    and eax, 0x7cf00000
    mov [rel r26_attach_trace+20], eax
    mov byte [rel r26_revision], 1
    cmp eax, 0x64a00000
    jne .revision
    mov byte [rel r26_revision], 2
.revision:
    mov esi, 0xa400
    call e5b_phy_read
    test eax, eax
    js .realwow
    mov [rel e5000b_bmcr_before], ax
    or byte [rel e5000b_bmcr_valid], 1
.realwow:
    mov byte [rel e5000b_reset_phase], 1
    lea rdi, [rel r26_realwow]
    call r26_run_table
    call r26_reset_drain
    test eax, eax
    jnz .fatal
    lea rdi, [rel r26_exit_oob]
    call r26_run_table
    call r26_ups_exit
    ; PLL and PHY power up precede hw_init. BMCR is explicitly AUTOEN.
    or byte [rel e5000b_bmcr_valid], 0x80
    lea rdi, [rel r26_power_up]
    call r26_run_table
    mov edi, 3
    call r26_wait_phy_state
    lea rdi, [rel r26_hw_init]
    call r26_run_table
    call r26_load_mac_ucode
    lea rdi, [rel r26_hw_init_end]
    call r26_run_table
    call r26_reset_drain
    test eax, eax
    jnz .fatal
    call r26_phy_config
    call r26_factory_station
    mov byte [rel e5000b_reset_phase], 24
    mov dword [rel r26_attach_trace+36], 24
    xor eax, eax
    pop rbx
    ret
.fatal:
    ; A first CMD reset can fail before the power-up attempt. Keep those raw
    ; readings in R26A, but do not claim a legacy NAR wake was attempted.
    test byte [rel e5000b_bmcr_valid], 0x80
    jnz .fatal_observed
    mov byte [rel e5000b_bmcr_valid], 0
    mov word [rel e5000b_bmcr_before], 0
    mov word [rel e5000b_bmcr_after], 0
    mov word [rel e5000b_phy_state], 0
.fatal_observed:
    mov dword [rel r26_attach_trace+16], 1
    mov rax, -1
    pop rbx
    ret

; BSD optional FIFO/queue drains; CMD write clears STOPREQ and stale enables.
r26_reset_drain:
    push rbx
    lea rdi, [rel r26_drain_start]
    call r26_run_table
    mov ebx, 3000
.fifo:
    mov edi, 50
    call tsc_delay_us
    mov esi, 0xd0
    call e5b_rd
    and eax, 0x30000000
    cmp eax, 0x30000000
    je .fifo_record
    dec ebx
    jnz .fifo
    or byte [rel e5000b_drain_expired], 1
.fifo_record:
    mov edi, 1
    mov esi, 0xd0
    xor edx, edx
    test ebx, ebx
    jnz .fifo_log
    mov edx, 2
.fifo_log:
    call r26_record
    mov ebx, 3000
.queue:
    mov edi, 50
    call tsc_delay_us
    mov esi, 0xe0
    call e5b_rd
    and eax, 0x01030000
    cmp eax, 0x01030000
    je .queue_record
    dec ebx
    jnz .queue
    or byte [rel e5000b_drain_expired], 2
.queue_record:
    mov edi, 1
    mov esi, 0xe0
    xor edx, edx
    test ebx, ebx
    jnz .queue_log
    mov edx, 2
.queue_log:
    call r26_record
    mov byte [rel e5000b_reset_phase], 4
    call e5000b_soft_reset
    push rax
    mov esi, 0x34
    call e5b_rd
    mov edi, 10
    mov esi, 0x37
    xor edx, edx
    cmp qword [rsp], 0
    jz .reset_log
    mov edx, 2
.reset_log:
    call r26_record
    pop rax
    pop rbx
    ret

; EDI=expected PHY A420 low3; 100 x 1ms, bounded transport per read.
r26_wait_phy_state:
    push rbx
    push r12
    mov r12d, edi
    mov ebx, 100
.poll:
    mov esi, 0xa420
    call e5b_phy_read
    test eax, eax
    js .bad
    mov edx, eax
    and edx, 7
    cmp edx, r12d
    je .ok
    mov edi, 1000
    push rax                     ; delay returns RDTSC, not the A420 sample
    call tsc_delay_us
    pop rax
    dec ebx
    jnz .poll
.bad:
    mov edx, 2
    jmp .record
.ok:
    xor edx, edx
.record:
    mov edi, 3
    mov esi, 0xa420
    ; The latest unavailable read must erase any earlier cached word/validity.
    mov word [rel e5000b_phy_state], 0
    and byte [rel e5000b_bmcr_valid], 0xfb
    test eax, eax
    js .state_unavailable
    mov [rel e5000b_phy_state], ax
    or byte [rel e5000b_bmcr_valid], 4
.state_unavailable:
    call r26_record
    pop r12
    pop rbx
    ret
r26_ups_exit:
    mov esi, 0xd42c
    call e5b_mac_read
    mov edi, 2
    mov esi, 0xd42c
    xor edx, edx
    call r26_record
    test eax, 0x100
    jz .out
    mov edi, 2
    call r26_wait_phy_state
    lea rdi, [rel r26_ups_clear]
    call r26_run_table
.out:
    ret

; Always install the pinned revision's MCU data, even when another OS left a
; matching version tag. The batch records words checked and mismatches; it
; does not fill PHG with thousands of firmware words.
r26_load_mac_ucode:
    push rbx
    push r12
    push r13
    lea r12, [rel r26_mac_ucode_1]
    lea r13, [rel r26_mac_ucode_1_end]
    cmp byte [rel r26_revision], 2
    jne .begin
    lea r12, [rel r26_mac_ucode_2]
    lea r13, [rel r26_mac_ucode_2_end]
.begin:
    xor ebx, ebx
.loop:
    cmp r12, r13
    jae .finish
    ; MAC_R26_2 changes from RAM page0 to1 after 256 entries.
    cmp ebx, 256
    jne .write
    cmp byte [rel r26_revision], 2
    jne .write
    lea rdi, [rel r26_mac_page1]
    call r26_run_table
.write:
    movzx esi, word [r12]
    movzx edx, word [r12+2]
    call e5b_mac_write
    movzx esi, word [r12]
    call e5b_mac_read
    cmp ax, [r12+2]
    je .next
    inc dword [rel r26_attach_trace+48]
    cmp dword [rel r26_attach_trace+60], 0
    jne .next
    mov [rel r26_attach_trace+56], eax
    movzx eax, word [r12]
    mov [rel r26_attach_trace+60], eax
.next:
    inc ebx
    add r12, 4
    jmp .loop
.finish:
    mov [rel r26_attach_trace+24], ebx
    mov edi, 8
    xor esi, esi
    mov eax, ebx
    xor edx, edx
    cmp dword [rel r26_attach_trace+48], 0
    je .record
    mov edx, 1
.record:
    call r26_record
    lea rdi, [rel r26_mac_enable_1]
    cmp byte [rel r26_revision], 2
    jne .enable
    lea rdi, [rel r26_mac_enable_2]
.enable:
    call r26_run_table
    ; Version words are data, written to page2 in the BSD endian/order.
    lea rdi, [rel r26_mac_page2]
    call r26_run_table
    sub r13, 16
    xor ebx, ebx
.version:
    mov esi, 0xf9f8
    add esi, ebx
    movzx edx, word [r13+2]
    call e5b_mac_write
    mov esi, 0xf9f8
    add esi, ebx
    call e5b_mac_read
    xor edx, edx
    cmp ax, [r13+2]
    je .version_record
    mov edx, 1
.version_record:
    mov edi, 2
    mov esi, 0xf9f8
    add esi, ebx
    call r26_record
    add r13, 4
    add ebx, 2
    cmp ebx, 8
    jb .version
    lea rdi, [rel r26_mac_page0]
    call r26_run_table
    pop r13
    pop r12
    pop rbx
    ret

r26_load_phy_ucode:
    push rbx
    push r12
    push r13
    mov edi, 1
    call r26_patch_phy
    mov edi, 6
    mov esi, 0xb820
    call r26_record
    lea r12, [rel r26_phy_ucode_1]
    lea r13, [rel r26_phy_ucode_1_end]
    cmp byte [rel r26_revision], 2
    jne .begin
    lea r12, [rel r26_phy_ucode_2]
    lea r13, [rel r26_phy_ucode_2_end]
.begin:
    xor ebx, ebx
    test edx, edx
    jnz .failed
.loop:
    cmp r12, r13
    jae .finish
    ; R26_1 documented patch boundary at word6989.
    cmp ebx, 6989
    jne .write
    xor edi, edi
    call r26_patch_phy
    mov edi, 6
    mov esi, 0xb820
    call r26_record
    test edx, edx
    jnz .failed
    mov edi, 1
    call r26_patch_phy
    mov edi, 6
    mov esi, 0xb820
    call r26_record
    test edx, edx
    jnz .failed
.write:
    movzx esi, word [r12]
    movzx edx, word [r12+2]
    call e5b_phy_write
    test eax, eax
    jnz .failed
    inc ebx
    add r12, 4
    jmp .loop
.failed:
    inc dword [rel r26_attach_trace+32]
    ; Transport is unusable: rest of this one data stream cannot be sent
    ; coherently. Record partial word count and continue independent steps.
.finish:
    mov [rel r26_attach_trace+28], ebx
    mov edi, 9
    xor esi, esi
    mov eax, ebx
    mov edx, 4
    cmp r12, r13
    jae .record
    mov edx, 2
.record:
    call r26_record
    xor edi, edi
    call r26_patch_phy
    mov edi, 6
    mov esi, 0xb820
    call r26_record
    ; Only publish the data version if the whole stream completed.
    cmp r12, r13
    jb .out
    lea rdi, [rel r26_phy_version_1]
    cmp byte [rel r26_revision], 2
    jne .version
    lea rdi, [rel r26_phy_version_2]
.version:
    call r26_run_table
.out:
    pop r13
    pop r12
    pop rbx
    ret

r26_phy_reset_wait:
    push rbx
    mov ebx, 2500
.poll:
    mov esi, 0xa400
    call e5b_phy_read
    test eax, eax
    js .bad
    test eax, 0x8000
    jz .ok
    mov edi, 1000
    push rax                     ; expiry must record the actual BMCR sample
    call tsc_delay_us
    pop rax
    dec ebx
    jnz .poll
.bad:
    inc dword [rel r26_attach_trace+52]
    mov edx, 2
    jmp .record
.ok:
    xor edx, edx
.record:
    mov edi, 11
    mov esi, 0xa400
    call r26_record
    pop rbx
    ret
r26_phy_config:
    lea rdi, [rel r26_phy_reset]
    call r26_run_table
    call r26_phy_reset_wait
    call r26_load_phy_ucode
    lea rdi, [rel r26_phy_tuning_1]
    cmp byte [rel r26_revision], 2
    jne .tune
    lea rdi, [rel r26_phy_tuning_2]
.tune:
    call r26_run_table
    lea rdi, [rel r26_eee_off]
    call r26_run_table
    ret
r26_mac_config:
    lea rdi, [rel r26_mac_init]
    call r26_run_table
    lea rdi, [rel r26_eee_off]
    call r26_run_table
    ret
r26_media_config:
    lea rdi, [rel r26_media]
    call r26_run_table
    call r26_phy_reset_wait
    mov esi, 0xa400
    call e5b_phy_read
    test eax, eax
    js .out
    mov [rel e5000b_bmcr_after], ax
    or byte [rel e5000b_bmcr_valid], 2
    test ax, 0x0800
    jnz .out
    test ax, 0x1000
    jz .out
    movzx edx, byte [rel e5000b_bmcr_valid]
    and edx, 0x87
    cmp edx, 0x87                     ; attempted and all promised readings
    jne .out
    movzx edx, word [rel e5000b_phy_state]
    and edx, 7
    cmp edx, 3                        ; the observed PHY awake state
    jne .out
    or byte [rel e5000b_bmcr_valid], 0x40
.out:
    ret

r26_factory_station:
    push rbx
    push r12
    mov esi, 0x19e0
    call e5b_rd
    mov ebx, eax
    mov esi, 0x19e4
    call e5b_rd
    movzx r12d, ax
    mov esi, 0x50
    mov edx, 0xc0
    call e5b_or
    mov esi, 0
    mov edx, ebx
    call e5b_wr
    mov esi, 4
    call e5b_rd
    and eax, 0xffff0000
    or eax, r12d
    mov edx, eax
    mov esi, 4
    call e5b_wr
    mov esi, 0x50
    mov edx, 0xc0
    call e5b_andn
    ; Live MAC validation and recovery identity equality still govern registration.
    mov esi, 0
    call e5b_rd
    mov edi, 1                        ; HAL reads clobber volatile argument regs
    mov esi, 0
    xor edx, edx
    call r26_record
    mov esi, 4
    call e5b_rd
    mov edi, 1
    mov esi, 4
    xor edx, edx
    call r26_record
    pop r12
    pop rbx
    ret

; Read-only register bench before initialization and after arm. Does not read
; auto-increment PHY data windows or destructive tally-DMA command registers.
r26_dump_registers:
    push rbx
    push r12
    lea r12, [rel r26_dump_list]
.loop:
    mov edi, [r12]
    test edi, edi
    jz .out
    mov ebx, [r12+4]
    mov esi, ebx
    cmp edi, 1
    je .mmio
    cmp edi, 2
    je .mac
    call e5b_phy_read
    jmp .record
.mac:
    call e5b_mac_read
    jmp .record
.mmio:
    call e5b_rd
.record:
    mov edi, [r12]
    mov esi, ebx
    xor edx, edx
    cmp edi, 3
    jne .save
    test eax, eax
    jns .save
    mov edx, 2
.save:
    call r26_record
    add r12, 8
    jmp .loop
.out:
    pop r12
    pop rbx
    ret

align 8
r26_attach_trace: times R26A_SIZE db 0
r26_revision: db 0
align 4
r26_realwow:
    dd 0x2, 0xc0bc, 0x0, 0xff
    dd 0, 0, 0, 0
r26_drain_start:
    dd 1, 0x38, 0, 0
    dd 0x1, 0x44, 0xffffffc0, 0x0
    dd 0x1, 0xf0, 0xffffffff, 0x80000
    dd 0x1, 0x34, 0xffffffff, 0x80000000
    dd 0x5, 0x0, 0x0, 0xc8
    dd 0, 0, 0, 0
r26_exit_oob:
    dd 0x1, 0xd0, 0x7fffffff, 0x0
    dd 0x2, 0xe8de, 0xbfff, 0x0
    dd 0xc, 0xd2, 0x0, 0x0
    dd 0x2, 0xc0aa, 0x0, 0x7d0
    dd 0x2, 0xc0a6, 0x0, 0x1b5
    dd 0x2, 0xc01e, 0x0, 0x5555
    dd 0xc, 0xd2, 0x0, 0x0
    dd 0, 0, 0, 0
r26_ups_clear:
    dd 0x2, 0xd42c, 0xfeff, 0x0
    dd 0x3, 0xa466, 0xfffe, 0x0
    dd 0x3, 0xa468, 0xfff5, 0x0
    dd 0, 0, 0, 0
r26_power_up:
    dd 0x1, 0x6c, 0xffffffff, 0xc0000000
    dd 0x3, 0xa400, 0x0, 0x1000
    dd 0, 0, 0, 0
r26_hw_init:
    dd 0x1, 0x50, 0xffffffff, 0xc0
    dd 0x1, 0x34, 0xfffffff7, 0x0
    dd 0x1, 0x54, 0xfffeffff, 0x0
    dd 0x1, 0x50, 0xffffff3f, 0x0
    dd 0x1, 0xf0, 0xffff7fff, 0x0
    dd 0x2, 0xd40a, 0xffef, 0x0
    dd 0x1, 0x50, 0xffffffff, 0xc0
    dd 0x1, 0x34, 0xfffffff7, 0x0
    dd 0x1, 0x54, 0xfffeffff, 0x0
    dd 0x1, 0x50, 0xffffff3f, 0x0
    dd 0x2, 0xfc48, 0x0, 0x0
    dd 0x2, 0xfc28, 0x0, 0x0
    dd 0x2, 0xfc2a, 0x0, 0x0
    dd 0x2, 0xfc2c, 0x0, 0x0
    dd 0x2, 0xfc2e, 0x0, 0x0
    dd 0x2, 0xfc30, 0x0, 0x0
    dd 0x2, 0xfc32, 0x0, 0x0
    dd 0x2, 0xfc34, 0x0, 0x0
    dd 0x2, 0xfc36, 0x0, 0x0
    dd 0x2, 0xfc38, 0x0, 0x0
    dd 0x2, 0xfc3a, 0x0, 0x0
    dd 0x2, 0xfc3c, 0x0, 0x0
    dd 0x2, 0xfc3e, 0x0, 0x0
    dd 0x2, 0xfc40, 0x0, 0x0
    dd 0x2, 0xfc42, 0x0, 0x0
    dd 0x2, 0xfc44, 0x0, 0x0
    dd 0x2, 0xfc46, 0x0, 0x0
    dd 0x5, 0x0, 0x0, 0xbb8
    dd 0x2, 0xfc26, 0x0, 0x0
    dd 0x2, 0xe446, 0xfffc, 0x0
    dd 0, 0, 0, 0
r26_hw_init_end:
    dd 0x4, 0x108, 0xffffffff, 0x100000
    dd 0x1, 0x38, 0x0, 0x0
    dd 0x1, 0x58, 0x0, 0x0
    dd 0x1, 0x5c, 0x0, 0x0
    dd 0x1, 0x8c, 0x0, 0x0
    dd 0x1, 0xf4, 0x0, 0x0
    dd 0, 0, 0, 0
r26_mac_enable_1:
    dd 0x2, 0xfc26, 0x0, 0x8000
    dd 0x2, 0xfc2c, 0x0, 0x2360
    dd 0x2, 0xfc2e, 0x0, 0x14a4
    dd 0x2, 0xfc30, 0x0, 0x415e
    dd 0x2, 0xfc32, 0x0, 0x41e4
    dd 0x2, 0xfc34, 0x0, 0x4280
    dd 0x2, 0xfc36, 0x0, 0x234a
    dd 0x2, 0xfc48, 0x0, 0xfc
    dd 0, 0, 0, 0
r26_phy_version_1:
    dd 0x3, 0xa436, 0x0, 0x801e
    dd 0x7, 0xa438, 0x0, 0x33
    dd 0, 0, 0, 0
r26_mac_enable_2:
    dd 0x2, 0xfc26, 0x0, 0x8000
    dd 0x2, 0xfc2c, 0x0, 0x14a4
    dd 0x2, 0xfc2e, 0x0, 0x4176
    dd 0x2, 0xfc30, 0x0, 0x41fc
    dd 0x2, 0xfc32, 0x0, 0x4298
    dd 0x2, 0xfc3a, 0x0, 0x234a
    dd 0x2, 0xfc48, 0x0, 0x23c
    dd 0, 0, 0, 0
r26_phy_version_2:
    dd 0x3, 0xa436, 0x0, 0x801e
    dd 0x7, 0xa438, 0x0, 0x60
    dd 0, 0, 0, 0
r26_mac_page0:
    dd 0x2, 0xe446, 0xfffc, 0x0
    dd 0, 0, 0, 0
r26_mac_page1:
    dd 0x2, 0xe446, 0xfffc, 0x1
    dd 0, 0, 0, 0
r26_mac_page2:
    dd 0x2, 0xe446, 0xfffc, 0x2
    dd 0, 0, 0, 0
r26_phy_reset:
    dd 0x3, 0xa408, 0xfe1f, 0x0
    dd 0x3, 0xa412, 0xfcff, 0x0
    dd 0x3, 0xa5d4, 0xfe7f, 0x0
    dd 0x3, 0xa400, 0x0, 0x9200
    dd 0, 0, 0, 0
r26_eee_off:
    dd 0x3, 0xa5b4, 0x7fff, 0x0
    dd 0x2, 0xe040, 0xfffc, 0x0
    dd 0x3, 0xa5d0, 0xfff9, 0x0
    dd 0x3, 0xa6d4, 0xfffc, 0x0
    dd 0x3, 0xa6d8, 0xffef, 0x0
    dd 0x3, 0xa428, 0xff7f, 0x0
    dd 0x3, 0xa4a2, 0xfdff, 0x0
    dd 0x2, 0xe052, 0xfffe, 0x0
    dd 0x3, 0xa442, 0xcfff, 0x0
    dd 0x3, 0xa430, 0x7fff, 0x0
    dd 0, 0, 0, 0
r26_mac_init:
    dd 0x1, 0xf0, 0xffff7fff, 0x0
    dd 0x1, 0x50, 0xffffffff, 0xc0
    dd 0x1, 0x34, 0xfffffff7, 0x0
    dd 0x1, 0x54, 0xfffeffff, 0x0
    dd 0x1, 0x6048, 0xffff0000, 0x60a
    dd 0x4, 0x70c, 0xc0ffffff, 0x27000000
    dd 0x4, 0x890, 0xfffffffe, 0x0
    dd 0x1, 0x4500, 0xffffff00, 0x0
    dd 0x1, 0x4800, 0xffffffe3, 0x0
    dd 0x1, 0x50, 0xffefffff, 0x0
    dd 0x2, 0xc140, 0x0, 0xffff
    dd 0x2, 0xc142, 0x0, 0xffff
    dd 0x2, 0xeb58, 0xffff, 0x1
    dd 0x1, 0xd8, 0xfffffffd, 0x0
    dd 0x2, 0xe614, 0xf8ff, 0x300
    dd 0x2, 0xe63e, 0xf3ff, 0x0
    dd 0x2, 0xe63e, 0xffcf, 0x20
    dd 0x2, 0xc0b4, 0xfffe, 0x0
    dd 0x2, 0xc0b4, 0xffff, 0x1
    dd 0x2, 0xc0b4, 0xffff, 0xc
    dd 0x2, 0xeb6a, 0xff00, 0x33
    dd 0x2, 0xeb50, 0xfc1f, 0x40
    dd 0x2, 0xe056, 0xff0f, 0x0
    dd 0x1, 0x54, 0xffffff, 0x10000000
    dd 0x2, 0xe040, 0xefff, 0x0
    dd 0x2, 0xea1c, 0xfffc, 0x1
    dd 0x2, 0xe0c0, 0x0, 0x4000
    dd 0x2, 0xe052, 0xffff, 0x60
    dd 0x2, 0xe052, 0xff77, 0x0
    dd 0x2, 0xd430, 0xf000, 0x45f
    dd 0x1, 0xd0, 0xffffffff, 0xc0
    dd 0x2, 0xe080, 0xfffd, 0x0
    dd 0x2, 0xea1c, 0xfcfb, 0x0
    dd 0x2, 0xeb54, 0xffff, 0x1
    dd 0x5, 0x0, 0x0, 0x1
    dd 0x2, 0xeb54, 0xfffe, 0x0
    dd 0x1, 0x1880, 0xffffffcf, 0x0
    dd 0x1, 0x34, 0xfffffffe, 0x0
    dd 0x1, 0x58, 0x0, 0x0
    dd 0x1, 0x5c, 0x0, 0x0
    dd 0x1, 0x8c, 0x0, 0x0
    dd 0x1, 0xf4, 0x0, 0x0
    dd 0x1, 0xa00, 0x0, 0x0
    dd 0x1, 0xa04, 0x0, 0x0
    dd 0x1, 0xa08, 0x0, 0x0
    dd 0x1, 0xa0c, 0x0, 0x0
    dd 0x1, 0xa10, 0x0, 0x0
    dd 0x1, 0xa14, 0x0, 0x0
    dd 0x1, 0xa18, 0x0, 0x0
    dd 0x1, 0xa1c, 0x0, 0x0
    dd 0x1, 0xa20, 0x0, 0x0
    dd 0x1, 0xa24, 0x0, 0x0
    dd 0x1, 0xa28, 0x0, 0x0
    dd 0x1, 0xa2c, 0x0, 0x0
    dd 0x1, 0xa30, 0x0, 0x0
    dd 0x1, 0xa34, 0x0, 0x0
    dd 0x1, 0xa38, 0x0, 0x0
    dd 0x1, 0xa3c, 0x0, 0x0
    dd 0x1, 0xa40, 0x0, 0x0
    dd 0x1, 0xa44, 0x0, 0x0
    dd 0x1, 0xa48, 0x0, 0x0
    dd 0x1, 0xa4c, 0x0, 0x0
    dd 0x1, 0xa50, 0x0, 0x0
    dd 0x1, 0xa54, 0x0, 0x0
    dd 0x1, 0xa58, 0x0, 0x0
    dd 0x1, 0xa5c, 0x0, 0x0
    dd 0x1, 0xa60, 0x0, 0x0
    dd 0x1, 0xa64, 0x0, 0x0
    dd 0x1, 0xa68, 0x0, 0x0
    dd 0x1, 0xa6c, 0x0, 0x0
    dd 0x1, 0xa70, 0x0, 0x0
    dd 0x1, 0xa74, 0x0, 0x0
    dd 0x1, 0xa78, 0x0, 0x0
    dd 0x1, 0xa7c, 0x0, 0x0
    dd 0x1, 0x34, 0xffffffe9, 0x0
    dd 0x1, 0x78, 0xffff, 0x0
    dd 0x2, 0xc0ac, 0xffff, 0x1f80
    dd 0x2, 0xe098, 0x0, 0xc302
    dd 0x2, 0xe032, 0xfffc, 0x0
    dd 0x4, 0x98, 0xffff00ff, 0x0
    dd 0x2, 0xe092, 0xff00, 0x0
    dd 0x1, 0x8, 0x0, 0x0
    dd 0x1, 0xc, 0x0, 0x0
    dd 0x1, 0xe0, 0xffffffff, 0x20
    dd 0x1, 0x50, 0xffffffff, 0xc0
    dd 0x1, 0x34, 0xfffffff7, 0x0
    dd 0x1, 0x54, 0xfffeffff, 0x0
    dd 0, 0, 0, 0
r26_media:
    dd 0x3, 0xa428, 0xfdff, 0x0
    dd 0x3, 0xa5ea, 0xfff8, 0x0
    dd 0x3, 0xa408, 0x0, 0xde1
    dd 0x3, 0xa412, 0x0, 0x300
    dd 0x3, 0xa5d4, 0xfe7f, 0x180
    dd 0x3, 0xa400, 0x0, 0x9200
    dd 0, 0, 0, 0
r26_dump_list:
    dd 1, 0x0
    dd 1, 0x4
    dd 1, 0x19e0
    dd 1, 0x19e4
    dd 1, 0x34
    dd 1, 0x38
    dd 1, 0x3c
    dd 1, 0x40
    dd 1, 0x44
    dd 1, 0x50
    dd 1, 0x54
    dd 1, 0x6c
    dd 1, 0xd0
    dd 1, 0xd8
    dd 1, 0xe0
    dd 1, 0xe4
    dd 1, 0xe8
    dd 1, 0xf0
    dd 1, 0x4500
    dd 1, 0x4800
    dd 1, 0x6048
    dd 2, 0xc0bc
    dd 2, 0xd42c
    dd 2, 0xd40a
    dd 2, 0xe8de
    dd 2, 0xe040
    dd 2, 0xe052
    dd 2, 0xe080
    dd 2, 0xea1c
    dd 2, 0xeb58
    dd 2, 0xe614
    dd 2, 0xe63e
    dd 3, 0xa400
    dd 3, 0xa420
    dd 3, 0xa5d0
    dd 3, 0xa5d4
    dd 3, 0xa6d4
    dd 3, 0xa6d8
    dd 3, 0xa428
    dd 3, 0xa4a2
    dd 3, 0xa442
    dd 3, 0xa430
    dd 0, 0
