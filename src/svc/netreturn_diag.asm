;; MODULE svc/netreturn_diag
;; LAYER 5
;; EXPORTS netreturn_init_capture, netreturn_boot_publish, netreturn_poll_enter, netreturn_poll_exit
;; IMPORTS boot/boot_v2_health, boot/nvram_access, dev/net/rtl8126, svc/command_udp, core/build_id
;; CAPS
;; OWNER rc-resource-claude
;; CONTEXT: bsp_only
; Opt-in lab image only: -DRCQ_NET_RETURN_DIAG=1. Three best-effort writes to
; ONE owned variable, never BootReady/health/boot journal. Missing/failed writes
; are missing evidence. No retries, NIC writes, RX/ISR calls or promotion effect.
; PND1 v1/512 bytes: identity 0..127, init NIC 128..255, returned-poll NIC
; 256..383, existing progress snapshot 384..479, reserved 480..507, CRC32 508.
%ifndef RCQ_NET_RETURN_DIAG
%define RCQ_NET_RETURN_DIAG 0
%endif
%if RCQ_NET_RETURN_DIAG != 0 && RCQ_NET_RETURN_DIAG != 1
%error "RCQ_NET_RETURN_DIAG must be 0 or 1"
%endif
%if RCQ_NET_RETURN_DIAG
NR_SIZE equ 512
NR_CRC equ 508
NR_NIC_SIZE equ 128

%macro NR_SAVE 0
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8                         ; SysV call alignment
%endmacro
%macro NR_RESTORE 0
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    ret
%endmacro

; Only a verified normal Manager attempt on the actual RTL8126 can produce
; this diagnostic. Refusal does not change any existing boot-health state.
netreturn_eligible:
    cmp byte [rel pbm_manager_launch], 1
    jne .no
    cmp byte [rel pbm_safe_runtime_active], 0
    jne .no
    test byte [rel pbm_flags], PBM_HF_MUTABLE_ATTEMPT
    jz .no
    cmp byte [rel pbm_profile], PBM_PROFILE_NORMAL
    jne .no
    movzx eax, byte [rel pbm_entry]
    cmp eax, PBM_ENTRY_PAOS_A
    je .entry
    cmp eax, PBM_ENTRY_PAOS_B
    jne .no
.entry:
    cmp qword [rel pbm_manager_sequence], 0
    je .no
    cmp qword [rel pbm_attempt_nonce], 0
    je .no
    cmp qword [rel pbm_state_generation], 0
    je .no
    cmp byte [rel paos_build_state], BID_ST_MATCH
    jne .no
    cmp dword [rel e5000b_matches], 1
    jne .no
    cmp dword [rel e5000b_devid], 0x5000
    jne .no
    ; Driver encoding is bus<<16 | device<<8 | function, not packed BDF16.
    cmp qword [rel e5000b_bdf], 0xffffff
    ja .no
    test dword [rel e5000b_bdf], 0xe0f8 ; device<=31, function<=7
    jnz .no
    xor eax, eax
    xor edx, edx
    xor ecx, ecx
    lea r8, [rel pbm_payload_sha]
    lea r9, [rel paos_build_measured]
.digest:
    or al, [r8 + rcx]
    or dl, [r9 + rcx]
    inc ecx
    cmp ecx, 32
    jb .digest
    test al, al
    jz .no
    test dl, dl
    jz .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; RDI=private 128-byte destination. Fixed read-only software/MMIO sample,
; sequential rather than atomic. Flags say what was sampled, never ready.
; No address, function pointer, packet, auth key or descriptor DMA address export.
netreturn_nic_snapshot:
    push rbx
    push r12
    push r13
    mov r12, rdi
    xor eax, eax
    mov ecx, NR_NIC_SIZE / 8
    rep stosq
    mov rax, [rel e5000b_bdf]
    mov [r12 + 8], rax
    mov rax, [rel e5000b_slot]
    mov [r12 + 16], rax
    mov eax, [rel e5000b_rx_cursor]
    mov [r12 + 24], eax
    mov eax, [rel e5000b_tx_head]
    mov [r12 + 28], eax
    mov eax, [rel e5000b_mac]
    mov [r12 + 32], eax
    mov ax, [rel e5000b_mac + 4]
    mov [r12 + 36], ax
%macro NR_FLAG 2
    cmp byte [rel %1], 1
    jne %%unset
    or qword [r12], 1 << %2
%%unset:
%endmacro
    NR_FLAG e5000b_registered, 0
    NR_FLAG e5000b_hw_ok, 1
    NR_FLAG e5000b_rings_ok, 2
    NR_FLAG e5000b_mac_ok, 3
    NR_FLAG e5000b_iso_ok, 4
    NR_FLAG e5000b_link_up, 5
%unmacro NR_FLAG 2
    mov rax, [rel e5000b_region]
    test rax, rax
    jz .counters
    cmp rax, [rel e5000b_bar]
    jne .counters
    test al, 3
    jnz .counters
    mov rdx, [rel e5000b_region + 8]
    cmp rdx, 0xf4
    jb .counters
    add rax, rdx
    jc .counters
    xor r13d, r13d
.mmio:
    lea rbx, [rel nr_mmio_offsets]
    mov esi, [rbx + r13*4]
    call e5b_rd                         ; HAL-gated dword reads only
    mov [r12 + r13*4 + 40], eax
    inc r13d
    cmp r13d, 5
    jb .mmio
    or qword [r12], 1 << 8
.counters:
%assign nr_off 64
%macro NR_COUNTER 1
    mov rax, [rel %1]
    mov [r12 + nr_off], rax
%assign nr_off nr_off+8
%endmacro
    NR_COUNTER e5000b_rx_frames
    NR_COUNTER e5000b_tx_frames
    NR_COUNTER e5000b_rx_drops
    NR_COUNTER e5000b_tx_drops
    NR_COUNTER e5000b_tx_timeouts
    NR_COUNTER e5000b_owner_mismatches
%unmacro NR_COUNTER 1
    cmp dword [rel e5000b_rx_cursor], E5B_NUM_RX
    jae .tx
    mov rdi, [rel e5000b_rx_ring]
    mov esi, E5B_NUM_RX * 32
    call e5000b_dma_range_ok
    test eax, eax
    jz .tx
    mov eax, [rel e5000b_rx_cursor]
    shl eax, 5
    add rax, [rel e5000b_rx_ring]
    mov edx, [rax + 28]
    mov [r12 + 112], edx
    mov edx, [rax + 24]
    mov [r12 + 116], edx
    or qword [r12], 1 << 9
.tx:
    cmp dword [rel e5000b_tx_head], E5B_NUM_TX
    jae .out
    mov rdi, [rel e5000b_tx_ring]
    mov esi, E5B_NUM_TX * 32
    call e5000b_dma_range_ok
    test eax, eax
    jz .out
    mov eax, [rel e5000b_tx_head]
    shl eax, 5
    add rax, [rel e5000b_tx_ring]
    mov edx, [rax + 28]
    mov [r12 + 120], edx
    or qword [r12], 1 << 10
.out:
    pop r13
    pop r12
    pop rbx
    ret

netreturn_init_capture:
    NR_SAVE
    cmp byte [rel nr_initialized], 0
    jne .out
    mov byte [rel nr_initialized], 1       ; no re-arm, including failed init
    call netreturn_eligible
    test eax, eax
    jz .out
    lea rdi, [rel nr_record]
    xor eax, eax
    mov ecx, NR_SIZE / 8
    rep stosq
    mov dword [rel nr_record], 'PND1'
    mov word [rel nr_record + 4], 1
    mov word [rel nr_record + 6], NR_SIZE
    mov dword [rel nr_record + 12], 1
    mov rax, [rel pbm_manager_sequence]
    mov [rel nr_record + 16], rax
    mov rax, [rel pbm_attempt_nonce]
    mov [rel nr_record + 24], rax
    mov rax, [rel pbm_state_generation]
    mov [rel nr_record + 32], rax
    lea rsi, [rel pbm_payload_sha]
    lea rdi, [rel nr_record + 40]
    mov ecx, 4
    rep movsq
    lea rsi, [rel paos_build_measured]
    lea rdi, [rel nr_record + 72]
    mov ecx, 4
    rep movsq
    lea rdi, [rel nr_record + 128]
    call netreturn_nic_snapshot
    mov byte [rel nr_ready], 1
.out:
    NR_RESTORE

; Revalidate every publication against captured attempt/build/BDF/slot. Never
; attach an earlier snapshot to a later identity, even within one boot.
netreturn_context_matches:
    sub rsp, 8
    call netreturn_eligible
    add rsp, 8
    test eax, eax
    jz .no
    mov rax, [rel pbm_manager_sequence]
    cmp rax, [rel nr_record + 16]
    jne .no
    mov rax, [rel pbm_attempt_nonce]
    cmp rax, [rel nr_record + 24]
    jne .no
    mov rax, [rel pbm_state_generation]
    cmp rax, [rel nr_record + 32]
    jne .no
    mov rax, [rel e5000b_bdf]
    cmp rax, [rel nr_record + 136]
    jne .no
    mov rax, [rel e5000b_slot]
    cmp rax, [rel nr_record + 144]
    jne .no
    lea rsi, [rel pbm_payload_sha]
    lea rdi, [rel nr_record + 40]
    mov ecx, 4
    repe cmpsq
    jne .no
    lea rsi, [rel paos_build_measured]
    lea rdi, [rel nr_record + 72]
    mov ecx, 4
    repe cmpsq
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; EDI=phase 1..3. Caller has advanced its private phase BEFORE attempting IO:
; success, storage refusal and firmware error all consume exactly one attempt.
netreturn_publish:
    push rbx
    push r12
    push r13
    mov r13d, edi
    call netreturn_context_matches
    test eax, eax
    jz .disable
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .disable
    mov r12, [rel runtime_services]
    test r12, r12
    jz .disable
    cmp qword [r12 + 0x58], 0
    je .disable
    mov [rel nr_record + 8], r13d
    lea rdi, [rel nr_record + 384]
    call command_udp_progress_snapshot
    lea rdi, [rel nr_record]
    mov esi, NR_CRC
    call pbm_crc32
    mov [rel nr_record + NR_CRC], eax
    lea rdi, [rel pbm_health_var_guid]
    lea rsi, [rel nr_var_name]
    xor edx, edx                       ; existing implicit PaOS NVRAM policy
    lea rcx, [rel nr_caller]
    call storage_access_nvram_require
    test rax, rax
    jnz .disable
    lea rcx, [rel nr_var_name]
    lea rdx, [rel pbm_health_var_guid]
    mov r8d, PBM_EFI_HEALTH_ATTRS
    mov r9d, NR_SIZE
    sub rsp, 48                        ; aligned MS-ABI shadow + fifth argument
    lea rbx, [rel nr_record]
    mov [rsp + 32], rbx
    call [r12 + 0x58]
    add rsp, 48
    test rax, rax
    jz .out
.disable:
    mov byte [rel nr_ready], 0           ; fail best-effort; never retry
.out:
    pop r13
    pop r12
    pop rbx
    ret

netreturn_boot_publish:
    NR_SAVE
    cmp byte [rel nr_ready], 1
    jne .out
    cmp byte [rel nr_phase], 0
    jne .out
    mov byte [rel nr_phase], 1
    mov edi, 1
    call netreturn_publish
.out:
    NR_RESTORE

; Called at the ACTUAL command_udp_poll entry, before its first owner call.
netreturn_poll_enter:
    NR_SAVE
    cmp byte [rel nr_ready], 1
    jne .out
    cmp byte [rel nr_phase], 1
    jne .out
    mov byte [rel nr_phase], 2
    mov qword [rel nr_record + 104], 1
    mov edi, 2
    call netreturn_publish
.out:
    NR_RESTORE

; Header calls ONLY after the real command_udp_poll returned. A loop-end HLT
; marker is not a substitute. First returned sample only, never periodic IO.
netreturn_poll_exit:
    NR_SAVE
    cmp byte [rel nr_ready], 1
    jne .out
    cmp byte [rel nr_phase], 2
    jne .out
    call netreturn_context_matches
    test eax, eax
    jz .disable
    mov byte [rel nr_phase], 3
    mov qword [rel nr_record + 112], 1
    lea rdi, [rel nr_record + 256]
    call netreturn_nic_snapshot
    or dword [rel nr_record + 12], 2
    mov edi, 3
    call netreturn_publish
    jmp .out
.disable:
    mov byte [rel nr_ready], 0
.out:
    NR_RESTORE

nr_mmio_offsets: dd 0x34, 0x40, 0x44, 0x6c, 0xf0
nr_var_name: dw 'P','a','O','S','N','e','t','D','i','a','g',0
nr_caller: db 'netreturn-diag',0
%macro WDATA_svc_netreturn 0
alignb 8
nr_record: resb NR_SIZE
nr_initialized: resb 1
nr_ready: resb 1
nr_phase: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_svc_netreturn
%endif
