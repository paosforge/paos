%include "core/abi/build_profile.inc"
; Public Terminal's single hvc0 attachment. All entry points run on the
; cooperative BSP, without yielding. No guest address or queue is retained.
; Attach/read/write: RDI=nonzero window-owner, ESI=exact consumed START.
; read/write additionally RDX=owned bytes, ECX=1..256 capacity/length.
; attach/write -> 1 accepted, 0 refused; read -> bytes, -1 detached/overflow.
; A missing prompt, a transport acceptance or a shell-ready bit is not proof.
HV_TERMINAL_CAP equ 8192
%ifdef HV_VCON_TX_MAX
%if HV_VCON_TX_MAX > HV_TERMINAL_CAP
%error "Terminal backpressure requires every valid TX chain to fit its ring"
%endif
%endif

; ESI=requested generation. No side effects; preserves all but EAX.
hv_terminal_current:
    test esi, esi
    jz .bad
    cmp esi, [rel hv_linux_start_gen]
    jne .bad
    cmp esi, [rel hv_linux_start_consumed]
    jne .bad
    cmp byte [rel hv_linux_running], 1
    jne .bad
    cmp byte [rel hv_linux_stop_req], 0
    jne .bad
    cmp byte [rel hv_linux_run_req], 0
    jne .bad
    cmp byte [rel hv_vcon_ready], 1
    jne .bad
    cmp word [rel hv_vcon_q_ready], 0x0101
    jne .bad
    test dword [rel vm_profile_live_devices], VP_DEV_CONSOLE
    jz .bad
    test dword [rel vm_profile_live_devices], VP_DEV_PADCHAN | VP_DEV_PINCHAN | VP_DEV_WARMCHAN
    jnz .bad
    cmp byte [rel hvp_bound], 0
    jne .bad
    cmp byte [rel hvw_bound], 0
    jne .bad
    cmp byte [rel padc_bound], 0
    jne .bad
    cmp byte [rel dc_active], 0
    jne .bad
%if !PAOS_PUBLIC_BUILD
    cmp byte [rel browser_selected], 0
    jne .bad
%endif
    cmp byte [rel cdp_bound], 0
    jne .bad
    cmp byte [rel gws_bound], 0
    jne .bad
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp byte [rel hv_vcon_pmr_bound], 0
    jne .bad
%endif
%endif
    ; The existing driver's bootstrap also writes shell lines. It must finish
    ; before the user takes this console; no early user/startup interleaving.
    cmp byte [rel vtd_network_mode], 0
    je .yes
    cmp byte [rel vtd_domain_bridge_ready], 1
    jne .bad
.yes:
    mov eax, 1
    ret
.bad:
    xor eax, eax
    ret

hv_terminal_attach:
    test rdi, rdi
    jz .bad
    call hv_terminal_current
    test eax, eax
    jz .bad
    cmp qword [rel hv_terminal_owner], 0
    je .bind
    push rsi
    mov esi, [rel hv_terminal_generation]
    call hv_terminal_current
    pop rsi
    test eax, eax
    jnz .bad                           ; one live owner, even the same caller
.bind:
    call hv_terminal_reset
    mov [rel hv_terminal_generation], esi
    mov [rel hv_terminal_owner], rdi    ; publish after the new empty ring
    mov eax, 1
    ret
.bad:
    xor eax, eax
    ret

hv_terminal_status:
hv_terminal_matches:
    test rdi, rdi
    jz .bad
    cmp rdi, [rel hv_terminal_owner]
    jne .bad
    cmp esi, [rel hv_terminal_generation]
    jne .bad
    cmp dword [rel hv_terminal_overflow], 0
    jne .bad
    jmp hv_terminal_current
.bad:
    xor eax, eax
    ret

; ECX=complete validated TX chain length (<=HV_VCON_TX_MAX). Preserve all
; except EAX/flags. No reservation is retained: BSP cannot yield between this
; admission and the complete capture. Unattached/private consumers stay free.
hv_terminal_tx_room:
    push rsi
    cmp qword [rel hv_terminal_owner], 0
    je .unattached
    mov esi, [rel hv_terminal_generation]
    call hv_terminal_current
    test eax, eax
    jz .unattached
    mov eax, HV_TERMINAL_CAP
    cmp eax, [rel hv_terminal_count]
    jb .full
    sub eax, [rel hv_terminal_count]
    cmp eax, ecx
    setae al
    movzx eax, al
    pop rsi
    ret
.full:
    xor eax, eax
    pop rsi
    ret
.unattached:
    mov eax, 1
    pop rsi
    ret

; RDI/ESI=attached owner/START. GUI stopped-vCPU turn, no yield. The producer
; may have stopped notifying while its head was blocked; revalidate everything
; in the existing bounded TX engine instead of saving any guest addresses.
hv_terminal_poll:
    call hv_terminal_matches
    test eax, eax
    jz .out
    call hv_vcon_serve_tx                    ; stopped vCPU, bounded validated retry
.out:
    ret

hv_terminal_write:
    call hv_terminal_matches
    test eax, eax
    jz .bad
    test ecx, ecx
    jz .bad
    cmp ecx, 256
    ja .bad
    test rdx, rdx
    jz .bad
    mov rdi, rdx
    mov esi, ecx
    ; The existing full-chain validator and power fence own publication.
    ; No copied queue or delayed key can survive a lock, close or STOP.
    jmp hv_vcon_rx_bytes.terminal_owned
.bad:
    xor eax, eax
    ret

; RDI=attached owner, ESI=exact consumed START, EDX=cols, ECX=rows.
; Cooperative BSP/stopped guest: publish the pair before ConfigGeneration.
; The latest pair coalesces in the device page, with no queue or guest pointer.
hv_terminal_resize:
    HV_POWER_WORK hv_terminal_resize, 0, hv_guest_power_io_admit
    call hv_terminal_matches
    test eax, eax
    jz .bad
    test edx, edx
    jz .bad
    cmp edx, 0xFFFF
    ja .bad
    test ecx, ecx
    jz .bad
    cmp ecx, 0xFFFF
    ja .bad
    mov rax, [rel hv_linux_region]
    test rax, rax
    jz .bad
    mov r8d, ecx
    shl r8d, 16
    or r8d, edx
    cmp r8d, [rax + HV_VCON_PAGE + 0x100]
    je .accepted
    mov [rax + HV_VCON_PAGE + 0x100], dx
    mov [rax + HV_VCON_PAGE + 0x102], cx
    inc dword [rax + HV_VCON_PAGE + 0xFC]
    ; A driver declining SIZE gets neither a config IRQ nor a false ACK.
    ; hv_terminal_matches already earned readiness for this exact START.
    test dword [rel hv_vcon_drvfeat], 1
    jz .accepted
    or dword [rel hv_vcon_isr], 2
    mov edx, [rel hv_vcon_isr]
    mov [rax + HV_VCON_PAGE + 0x60], edx
    mov byte [rel hv_vcon_irq_pend], 1
.accepted:
    mov eax, 1
    ret
.bad:
    xor eax, eax
    ret

hv_terminal_read:
    call hv_terminal_matches
    test eax, eax
    jz .bad
    test ecx, ecx
    jz .bad
    cmp ecx, 256
    ja .bad
    test rdx, rdx
    jz .bad
    mov eax, [rel hv_terminal_count]
    cmp eax, ecx
    cmova eax, ecx
    push rax
    mov ecx, eax
    mov r8d, [rel hv_terminal_head]
    lea r9, [rel hv_terminal_ring]
.copy:
    test ecx, ecx
    jz .done
    mov al, [r9 + r8]
    mov [rdx], al
    inc rdx
    inc r8d
    and r8d, HV_TERMINAL_CAP - 1
    dec ecx
    jmp .copy
.done:
    mov [rel hv_terminal_head], r8d
    pop rax
    sub [rel hv_terminal_count], eax
    ret
.bad:
    mov eax, -1
    ret

hv_terminal_detach:
    cmp rdi, [rel hv_terminal_owner]
    jne .out
    cmp esi, [rel hv_terminal_generation]
    jne .out
    jmp hv_terminal_reset
.out:
    ret

hv_terminal_reset:
    mov qword [rel hv_terminal_owner], 0
    mov dword [rel hv_terminal_generation], 0
    mov dword [rel hv_terminal_head], 0
    mov dword [rel hv_terminal_count], 0
    mov dword [rel hv_terminal_overflow], 0
    ; No old attachment geometry survives detach, restart or a fresh attach.
    mov rax, [rel hv_linux_region]
    test rax, rax
    jz .done
    mov dword [rax + HV_VCON_PAGE + 0x100], 0
    mov dword [rax + HV_VCON_PAGE + 0xFC], 0
.done:
    ret

; AL=actual hvc0 TX byte; preserve every register and flags for VM owner.
; Called only after existing descriptor validation, never from RAW/fixtures.
hv_terminal_byte:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    cmp qword [rel hv_terminal_owner], 0
    je .out
    mov esi, [rel hv_terminal_generation]
    call hv_terminal_current
    test eax, eax
    jz .revoke
    cmp dword [rel hv_terminal_overflow], 0
    jne .out
    cmp dword [rel hv_terminal_count], HV_TERMINAL_CAP
    jae .overflow
    mov ecx, [rel hv_terminal_head]
    add ecx, [rel hv_terminal_count]
    and ecx, HV_TERMINAL_CAP - 1
    lea rdx, [rel hv_terminal_ring]
    mov al, [rsp + 24]                  ; original byte, preceding three saved registers
    mov [rdx + rcx], al
    inc dword [rel hv_terminal_count]
    jmp .out
.overflow:
    mov dword [rel hv_terminal_overflow], 1 ; no silent loss or partial VT stream
    jmp .out
.revoke:
    call hv_terminal_reset
.out:
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_hv_terminal_console 0
alignb 8
hv_terminal_owner: resq 1
hv_terminal_generation: resd 1
hv_terminal_head: resd 1
hv_terminal_count: resd 1
hv_terminal_overflow: resd 1
hv_terminal_ring: resb HV_TERMINAL_CAP
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_terminal_console
