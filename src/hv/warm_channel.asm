;; MODULE hv/warm_channel
;; LAYER 5
;; EXPORTS hvcw_begin, hvcw_pump, hvcw_receive, hvcw_uart_byte, hvcw_revoke, hvcw_retired, hvcw_last_load_start, hvcw_last_load_gen, hvcw_last_load_serial, hvcw_last_load_pid
;; IMPORTS hv/vmx, hv/warm_lifecycle, hv/vm_profile, hv/hv_ops, core/time
;; CAPS
;; OWNER saga:hv
; Native owner of the expendable guest's private PWR1 console. Serialized at
; stopped-vCPU BSP boundaries. No wait, scheduling, allocation or guest pointer
; survives a call. A guest reply is never authority for physical RAM release.
; Generic line/binary ingress and foreign console owners cannot enter this mode.

HVCW_MAGIC equ 0x31525750
HVCW_BYTES equ 64
HVCW_CAP equ 384 * 1024 * 1024
HVCW_MIN_RAM equ 512 * 1024 * 1024
HVCW_TIMEOUT_US equ 20000000
HVCW_FRAGMENT_US equ 1000000
HVCW_WAIT_READY equ 1
HVCW_BOOT_PENDING equ 2
HVCW_WAIT_HELLO equ 3
HVCW_GRANT_PENDING equ 4
HVCW_WAIT_GRANT equ 5
HVCW_ACTIVE equ 6
HVCW_STOPPING equ 7
HVCW_FAULT equ 8

; After Resource Begin and bound publication, before any guest instruction.
; EAX=0 prepared / -1 rejected (caller still owes physical retirement).
hvcw_begin:
    push rdi
    push rcx
    lea  rdi, [rel hvcw_state]
    mov  ecx, hvcw_state_end - hvcw_state
    xor  eax, eax
    cld
    rep  stosb
    mov  rax, [rel hvw_gen]
    mov  [rel hvcw_gen], rax
    mov  rax, [rel hvw_token]
    mov  [rel hvcw_token], rax
    mov  rax, [rel hvw_serial]
    mov  [rel hvcw_serial], rax
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel hvcw_start], eax
    mov  rax, [rel vm_profile_active]
    mov  [rel hvcw_profile], rax
    mov  rax, [rel hv_ops_active]
    mov  [rel hvcw_backend], rax
    call time_monotonic_now_us
    test rax, rax
    jz   .bad
    mov  [rel hvcw_last_us], rax
    add  rax, HVCW_TIMEOUT_US
    jc   .bad
    mov  [rel hvcw_deadline], rax
    mov  byte [rel hvcw_phase], HVCW_WAIT_READY
    xor  eax, eax
    pop  rcx
    pop  rdi
    ret
.bad:
    mov  byte [rel hvcw_phase], HVCW_FAULT
    mov  eax, -1
    pop  rcx
    pop  rdi
    ret

; Every admission/receive/send must still own this exact physical allocation
; and the current accepted START/profile, with no external console readers.
hvcw_current:
    xor  eax, eax
    cmp  byte [rel hvw_bound], 1
    jne  .out
    cmp  byte [rel hv_linux_running], 1
    jne  .out
    cmp  dword [rel vm_profile_dev_mask], VP_DEV_WARMDOMAIN
    jne  .out
    cmp  dword [rel vm_profile_live_devices], VP_DEV_WARMDOMAIN
    jne  .out
    mov  edx, [rel hvcw_start]
    test edx, edx
    jz   .out
    cmp  edx, [rel hv_linux_start_consumed]
    jne  .out
    cmp  edx, [rel hv_linux_start_gen]
    jne  .out
    cmp  edx, [rel vm_profile_gen]
    jne  .out
    mov  rdx, [rel hvcw_profile]
    test rdx, rdx
    jz   .out
    cmp  rdx, [rel vm_profile_active]
    jne  .out
    mov  rdx, [rel hvcw_backend]
    test rdx, rdx
    jz   .out
    cmp  rdx, [rel hv_ops_active]
    jne  .out
    mov  rdx, [rel hvcw_gen]
    cmp  rdx, [rel hvw_gen]
    jne  .out
    cmp  rdx, [rel hv_linux_mb_gen]
    jne  .out
    mov  rdx, [rel hvcw_token]
    test rdx, rdx
    jz   .out
    cmp  rdx, [rel hvw_token]
    jne  .out
    cmp  rdx, [rel hv_linux_mb_token]
    jne  .out
    mov  rdx, [rel hvcw_serial]
    test rdx, rdx
    jz   .out
    cmp  rdx, [rel hvw_serial]
    jne  .out
    jmp  hvw_readers_idle
.out:
    ret

; One actual UART byte in AL, all registers preserved. Only a complete line
; WARM_PROXY_READY LF counts; substring/prefix/overlong/CR garbage cannot ready
; the channel. The image sets hvc0 raw/no-echo before printing this marker.
hvcw_uart_byte:
    cmp  byte [rel hvcw_phase], HVCW_WAIT_READY
    jne  .out
    push rax
    push rcx
    push rdx
    mov  ecx, [rel hvcw_line_size]
    cmp  al, 10
    je   .line
    cmp  ecx, hvcw_ready_len
    jae  .overflow
    lea  rdx, [rel hvcw_line]
    mov  [rdx + rcx], al
    inc  ecx
    mov  [rel hvcw_line_size], ecx
    jmp  .done
.overflow:
    mov  dword [rel hvcw_line_size], hvcw_ready_len + 1
    jmp  .done
.line:
    cmp  ecx, hvcw_ready_len
    jne  .reset
    xor  ecx, ecx
.compare:
    lea  rdx, [rel hvcw_line]
    mov  al, [rdx + rcx]
    lea  rdx, [rel hvcw_ready_text]
    cmp  al, [rdx + rcx]
    jne  .reset
    inc  ecx
    cmp  ecx, hvcw_ready_len
    jb   .compare
    mov  byte [rel hvcw_phase], HVCW_BOOT_PENDING
.reset:
    mov  dword [rel hvcw_line_size], 0
.done:
    pop  rdx
    pop  rcx
    pop  rax
.out:
    ret

; Fresh native frame; token/cap/seq are zero only for bootstrap. RDI points to
; owned native storage, never to guest RAM. Callers fill the operation fields.
hvcw_frame:
    lea  rdi, [rel hvcw_tx]
    mov  ecx, HVCW_BYTES / 8
    xor  eax, eax
    cld
    rep  stosq
    mov  dword [rel hvcw_tx], HVCW_MAGIC
    mov  word [rel hvcw_tx + 4], 1
    mov  qword [rel hvcw_tx + 16], MB_OWNER_HV_LINUX
    mov  rax, [rel hvcw_gen]
    mov  [rel hvcw_tx + 24], rax
    ret

; At most one 64B whole-or-nothing queue transfer. The generic entry refuses
; WARMCHAN; only this native owner calls its private label after exact binding.
hvcw_send:
    call hvcw_current
    test eax, eax
    jz   .out
    lea  rdi, [rel hvcw_tx]
    mov  esi, HVCW_BYTES
    jmp  hv_vcon_rx_bytes.private_warm
.out:
    ret

; Clean exit service opportunity. Never renews a deadline because a guest is
; busy, spinning, fragmenting output or withholding its ready/HELLO/LOAD reply.
hvcw_pump:
    cmp  byte [rel hvw_bound], 1
    jne  .out
    cmp  byte [rel hvcw_phase], HVCW_STOPPING
    jae  .out
    call hvcw_current
    test eax, eax
    jz   hvcw_fail
    call hvw_policy
    test eax, eax
    jz   hvcw_fail
    call time_monotonic_now_us
    test rax, rax
    jz   hvcw_fail
    cmp  rax, [rel hvcw_last_us]
    jb   hvcw_fail
    mov  [rel hvcw_last_us], rax
    cmp  byte [rel hvcw_phase], HVCW_ACTIVE
    je   .fragment
    cmp  rax, [rel hvcw_deadline]
    jae  hvcw_fail
.fragment:
    cmp  dword [rel hvcw_rx_size], 0
    je   .phase
    cmp  rax, [rel hvcw_fragment_deadline]
    jae  hvcw_fail
.phase:
    cmp  byte [rel hvcw_phase], HVCW_BOOT_PENDING
    je   .bootstrap
    cmp  byte [rel hvcw_phase], HVCW_GRANT_PENDING
    jne  .out
    ; Unloaded HELLO was validated. Recheck policy immediately before each
    ; attempted GRANT; no stored eligibility or guest flags supply authority.
    cmp  qword [rel hv_linux_ram_bytes], HVCW_MIN_RAM
    jb   hvcw_fail
    cmp  byte [rel hvw_resource_open], 1
    jne  hvcw_fail
    call hvcw_frame
    mov  word [rel hvcw_tx + 6], 1
    mov  qword [rel hvcw_tx + 8], 1
    mov  rax, [rel hvcw_token]
    mov  [rel hvcw_tx + 32], rax
    mov  qword [rel hvcw_tx + 40], HVCW_CAP
    mov  qword [rel hvcw_tx + 48], 3
    call hvcw_send
    test eax, eax
    jz   .out
    mov  byte [rel hvcw_phase], HVCW_WAIT_GRANT
    mov  qword [rel hvcw_seq], 1
    jmp  .published
.bootstrap:
    call hvcw_frame
    call hvcw_send
    test eax, eax
    jz   .out
    mov  byte [rel hvcw_phase], HVCW_WAIT_HELLO
.published:
    ; The queue transaction cannot yield. Only after its complete success is
    ; a response expected. Policy loss subsequently invalidates before REVOKE.
    mov  rax, [rel hvcw_last_us]
    add  rax, HVCW_TIMEOUT_US
    jc   hvcw_fail
    mov  [rel hvcw_deadline], rax
.out:
    ret

; Called AFTER local grant invalidation by hvw_revoke, before STOP publication.
; A best-effort REVOKE never waits for a guest to run/reap/reply and never
; changes the physical retirement fence. If GRANT was queued, sequence2 is
; next even before its reply; bootstrap-only sessions require no model revoke.
hvcw_revoke:
    cmp  byte [rel hvcw_phase], HVCW_STOPPING
    jae  .out
    movzx eax, byte [rel hvcw_phase]
    mov  byte [rel hvcw_phase], HVCW_STOPPING
    cmp  eax, HVCW_WAIT_GRANT
    jb   .out
    call hvcw_frame
    mov  word [rel hvcw_tx + 6], 2
    mov  qword [rel hvcw_tx + 8], 2
    mov  rax, [rel hvcw_token]
    mov  [rel hvcw_tx + 32], rax
    mov  qword [rel hvcw_tx + 48], 4      ; owning guest off, not a guest claim
    jmp  hvcw_send
.out:
    ret
hvcw_fail:
    mov  byte [rel hvw_granted], 0
    call hvw_revoke                       ; invalidates before any transport
    mov  byte [rel hvcw_phase], HVCW_FAULT
    ret

; ECX bytes in the already-complete private hv_vcon_txbuf snapshot. Preserve
; every register: queue retirement follows this call. Fragment/coalesce as a
; byte stream, not a one-descriptor record assumption. One retained64B record.
hvcw_receive:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov  ebx, ecx
    lea  rsi, [rel hv_vcon_txbuf]
    call hvcw_current
    test eax, eax
    jz   .bad
    cmp  byte [rel hvcw_phase], HVCW_STOPPING
    jae  .out
    call time_monotonic_now_us
    test rax, rax
    jz   .bad
    cmp  rax, [rel hvcw_last_us]
    jb   .bad
    mov  [rel hvcw_last_us], rax
    cmp  byte [rel hvcw_phase], HVCW_ACTIVE
    je   .check_fragment
    cmp  rax, [rel hvcw_deadline]
    jae  .bad
.check_fragment:
    cmp  dword [rel hvcw_rx_size], 0
    je   .copy
    cmp  rax, [rel hvcw_fragment_deadline]
    jae  .bad
.copy:
    test ebx, ebx
    jz   .out
    cmp  dword [rel hvcw_rx_size], 0
    jne  .byte
    call time_monotonic_now_us
    add  rax, HVCW_FRAGMENT_US
    jc   .bad
    mov  [rel hvcw_fragment_deadline], rax
.byte:
    mov  edx, [rel hvcw_rx_size]
    lea  rdi, [rel hvcw_rx]
    mov  al, [rsi]
    inc  rsi
    mov  [rdi + rdx], al
    inc  edx
    dec  ebx
    mov  [rel hvcw_rx_size], edx
    cmp  edx, HVCW_BYTES
    jb   .copy
    mov  dword [rel hvcw_rx_size], 0
    push rsi
    call hvcw_reply
    pop  rsi
    test eax, eax
    jz   .bad
    jmp  .copy
.bad:
    call hvcw_fail
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

; EAX=1 exact unloaded HELLO or successful LOAD reply;0 hostile/refused/stale.
; A validated LOAD reply records model readiness only, never freed RAM.
hvcw_reply:
    xor  eax, eax
    cmp  dword [rel hvcw_rx], HVCW_MAGIC
    jne  .out
    cmp  word [rel hvcw_rx + 4], 1
    jne  .out
    cmp  qword [rel hvcw_rx + 16], MB_OWNER_HV_LINUX
    jne  .out
    mov  rdx, [rel hvcw_gen]
    cmp  rdx, [rel hvcw_rx + 24]
    jne  .out
    cmp  qword [rel hvcw_rx + 48], 0
    jne  .out
    cmp  byte [rel hvcw_phase], HVCW_WAIT_HELLO
    jne  .grant
    cmp  word [rel hvcw_rx + 6], 0x8000
    jne  .out
    cmp  qword [rel hvcw_rx + 8], 0
    jne  .out
    cmp  qword [rel hvcw_rx + 32], 0
    jne  .out
    cmp  qword [rel hvcw_rx + 40], 0
    jne  .out
    cmp  qword [rel hvcw_rx + 56], 0
    jne  .out
    mov  byte [rel hvcw_phase], HVCW_GRANT_PENDING
    mov  eax, 1
    ret
.grant:
    cmp  byte [rel hvcw_phase], HVCW_WAIT_GRANT
    jne  .out
    cmp  word [rel hvcw_rx + 6], 0x8001
    jne  .out
    cmp  qword [rel hvcw_rx + 8], 1
    jne  .out
    mov  rdx, [rel hvcw_token]
    cmp  rdx, [rel hvcw_rx + 32]
    jne  .out
    cmp  qword [rel hvcw_rx + 40], HVCW_CAP
    jne  .out
    cmp  qword [rel hvcw_rx + 56], 0
    je   .out                            ; real worker PID required, not authority
    call hvw_policy                      ; policy may have changed during LOAD
    test eax, eax
    jz   .out
    ; Retained observation only, outside the erased private transport record.
    ; All reply identity, status, current-owner and current policy checks precede it.
    mov  eax, [rel hvcw_start]
    mov  [rel hvcw_last_load_start], eax
    mov  rax, [rel hvcw_gen]
    mov  [rel hvcw_last_load_gen], rax
    mov  rax, [rel hvcw_rx + 56]
    mov  [rel hvcw_last_load_pid], rax
    mov  rax, [rel hvcw_serial]
    mov  [rel hvcw_last_load_serial], rax
    mov  byte [rel hvw_granted], 1         ; only now advertise model readiness
    mov  byte [rel hvcw_phase], HVCW_ACTIVE
    mov  eax, 1
.out:
    ret

; Called only after actual successful physical release. Keep lifecycle's
; serial high-water; erase the retired channel's native record bytes/state.
hvcw_retired:
    lea  rdi, [rel hvcw_state]
    mov  ecx, hvcw_state_end - hvcw_state
    xor  eax, eax
    cld
    rep  stosb
    ret

hvcw_ready_text: db 'WARM_PROXY_READY'
hvcw_ready_len equ $ - hvcw_ready_text
%include "core/abi/wdata.inc"
%macro WDATA_hv_warm_channel 0
alignb 8
hvcw_state:
hvcw_gen: resq 1
hvcw_token: resq 1
hvcw_serial: resq 1
hvcw_seq: resq 1
hvcw_last_us: resq 1
hvcw_deadline: resq 1
hvcw_fragment_deadline: resq 1
hvcw_profile: resq 1
hvcw_backend: resq 1
hvcw_start: resd 1
hvcw_rx_size: resd 1
hvcw_line_size: resd 1
hvcw_phase: resb 1
hvcw_line: resb hvcw_ready_len
alignb 8
hvcw_tx: resb HVCW_BYTES
hvcw_rx: resb HVCW_BYTES
hvcw_state_end:
; No token, owner credential, pointer, model data or transcript is retained.
alignb 8
hvcw_last_load_gen: resq 1
hvcw_last_load_serial: resq 1
hvcw_last_load_pid: resq 1
hvcw_last_load_start: resd 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_warm_channel
