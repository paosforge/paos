; Lab-only Beelink/Lenovo and private-Q AUTH2/AUTHLOGIN observation.
; Never an authority source.
; 48-byte PAOSLG01 record, or72-byte PAOSLG02 at stages20/21/60, on UDP9997 ->9998.
; The extension measures only live host CR0, IA32_MTRR_DEF_TYPE and a heartbeat count.
; No request bytes, credential values/lengths, keys, callback addresses or
; authentication outcomes are serialized. A stage means reached, not passed.
; No firmware/disk write, RX, dispatch, timer wait, retry or reply credit.
; The ordinary driver TX is called once; failure is ignored. At most 64
; submissions per boot. The original request/response storage is untouched.
%if PAOS_PUBLIC_BUILD = 0
%if PAOS_PUBLICITY_LAB_PROFILE = 1
command_udp_login_trace:
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
    mov rbp, rsp
    and rsp, -16
    sub rsp, 256
    movdqu [rsp+0], xmm0
    movdqu [rsp+16], xmm1
    movdqu [rsp+32], xmm2
    movdqu [rsp+48], xmm3
    movdqu [rsp+64], xmm4
    movdqu [rsp+80], xmm5
    movdqu [rsp+96], xmm6
    movdqu [rsp+112], xmm7
    movdqu [rsp+128], xmm8
    movdqu [rsp+144], xmm9
    movdqu [rsp+160], xmm10
    movdqu [rsp+176], xmm11
    movdqu [rsp+192], xmm12
    movdqu [rsp+208], xmm13
    movdqu [rsp+224], xmm14
    movdqu [rsp+240], xmm15
    cld
    test eax, eax
    jz .retire
    cmp eax, 1
    jne .event
    mov byte [rel login_wire_active], 0
    cmp byte [rel control_reply_active], 1
    jne .out
    cmp byte [rel control_reply_sending], 0
    jne .out
    cmp rsi, 10
    jb .out
    cmp word [rdi+8], 0x204e        ; final N + space, exact AUTHLOGIN verb
    jne .out
    mov rax, 0x49474f4c48545541     ; AUTHLOGI, no argument read or copy
    cmp [rdi], rax
    jne .out
    mov eax, [rel udp_our_mac]
    cmp eax, [rel udp_expected_mac_beelink]
    jne .lenovo
    mov ax, [rel udp_our_mac+4]
    cmp ax, [rel udp_expected_mac_beelink+4]
    je .machine
.lenovo:
    mov eax, [rel udp_our_mac]
    cmp eax, [rel udp_expected_mac_lenovo]
    jne .private_q
    mov ax, [rel udp_our_mac+4]
    cmp ax, [rel udp_expected_mac_lenovo+4]
    je .machine
.private_q:
    cmp dword [rel udp_our_mac], 0x12005452
    jne .out
    cmp word [rel udp_our_mac+4], 0x5634
    jne .out
.machine:
    mov rdi, [rel udp_ingress_handle]
    test rdi, rdi
    jz .out
    mov rsi, [rdi+dev.ops]
    test rsi, rsi
    jz .out
    mov [rel login_wire_handle], rdi
    mov [rel login_wire_ops], rsi
    call netdev_power_member       ; bounded registry check, no driver operation
    test rax, rax
    jz .out
    mov [rel login_wire_epoch_ptr], rax
    mov [rel login_wire_generation], rdx
    mov rax, [rel login_wire_ops]
    mov rax, [rax+netdev_ops.tx]
    test rax, rax
    jz .out
    mov [rel login_wire_tx], rax
    lea rbx, [rel login_wire_frame]
    ; Entire frame is this fixed public record; no transport body is reused.
    mov eax, [rel udp_reply_mac]
    mov [rbx], eax
    mov ax, [rel udp_reply_mac+4]
    mov [rbx+4], ax
    mov eax, [rel udp_our_mac]
    mov [rbx+6], eax
    mov ax, [rel udp_our_mac+4]
    mov [rbx+10], ax
    mov word [rbx+12], 0x0008
    mov dword [rbx+14], 0x4c000045  ; IPv4 total length 76
    mov dword [rbx+18], 0
    mov dword [rbx+22], 0x00001140  ; TTL64, UDP, checksum initially zero
    mov eax, [rel udp_reply_srcip]
    mov [rbx+26], eax
    mov eax, [rel udp_reply_ip]
    mov [rbx+30], eax
    lea rdi, [rbx+14]
    mov esi, 20
    call net_cksum16
    mov [rbx+24], ah
    mov [rbx+25], al
    mov dword [rbx+34], 0x0e270d27  ; UDP9997 ->9998, never the owner reply port
    mov dword [rbx+38], 0x00003800  ; length56, checksum0 valid for IPv4
    mov rax, 0x3130474c534f4150     ; PAOSLG01
    mov [rbx+42], rax
    mov dword [rbx+50], 0          ; stage u16, sequence u16
    mov eax, [rel boot_nonce]
    mov [rbx+54], eax
    mov rax, [rel boot_tsc_start]
    mov [rbx+58], rax
    mov rax, [rel control_reply_nonce]
    mov [rbx+66], rax
    mov rax, [rel control_reply_nonce+8]
    mov [rbx+74], rax
    mov byte [rel login_wire_active], 1
.event:
    cmp byte [rel login_wire_active], 1
    jne .out
    cmp word [rbp+112], 60
    jne .regular_budget
    cmp dword [rel login_wire_budget], 32 ; reserve room for post-KDF boundaries
    jae .out
.regular_budget:
    cmp dword [rel login_wire_budget], 64
    jae .retire
    cmp byte [rel control_reply_sending], 0
    jne .retire
    mov rdi, [rel login_wire_handle]
    cmp rdi, [rel udp_ingress_handle]
    jne .retire
    mov rsi, [rel login_wire_ops]
    call netdev_power_member
    test rax, rax
    jz .retire
    cmp rax, [rel login_wire_epoch_ptr]
    jne .retire
    cmp rdx, [rel login_wire_generation]
    jne .retire
    ; Nonce equality also prevents a callback from an unrelated request.
    mov rax, [rel control_reply_nonce]
    cmp rax, [rel login_wire_frame+66]
    jne .retire
    mov rax, [rel control_reply_nonce+8]
    cmp rax, [rel login_wire_frame+74]
    jne .retire
    inc dword [rel login_wire_budget] ; charge the submission, even when TX fails
    inc word [rel login_wire_frame+52]
    mov ax, [rbp+112]               ; original EAX stage, below fourteen pushes
    mov [rel login_wire_frame+50], ax
    call boot_ms_now
    mov [rel login_wire_frame+82], rax
    mov r12d, 90
    mov word [rel login_wire_frame+16], 0x4c00 ; total76, legacy48-byte payload
    mov word [rel login_wire_frame+38], 0x3800 ; UDP56
    mov byte [rel login_wire_frame+49], '1'
    movzx eax, word [rel login_wire_frame+50]
    cmp eax, 20
    je .cache_observation
    cmp eax, 21
    je .cache_observation
    cmp eax, 60
    jne .checksum
.cache_observation:
    cmp eax, 20
    jne .keep_heartbeat
    mov qword [rel login_wire_heartbeat], 0
.keep_heartbeat:
    cmp eax, 60
    jne .sample_cache
    inc qword [rel login_wire_heartbeat]
.sample_cache:
    mov rax, [rel login_wire_heartbeat]
    mov [rel login_wire_frame+106], rax
    mov rax, cr0                   ; live host, not saved guest/host VMCS state
    mov [rel login_wire_frame+90], rax
    mov qword [rel login_wire_frame+98], -1 ; unsupported MTRR is unknown
    mov eax, 1
    cpuid
    test edx, 1 << 12
    jz .extended
    mov ecx, 0x2FF                 ; IA32_MTRR_DEF_TYPE, public cache policy
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [rel login_wire_frame+98], rax
.extended:
    mov r12d, 114
    mov word [rel login_wire_frame+16], 0x6400 ; total100
    mov word [rel login_wire_frame+38], 0x5000 ; UDP80
    mov byte [rel login_wire_frame+49], '2'
.checksum:
    mov word [rel login_wire_frame+24], 0
    lea rdi, [rel login_wire_frame+14]
    mov esi, 20
    call net_cksum16
    mov [rel login_wire_frame+24], ah
    mov [rel login_wire_frame+25], al
    mov rdi, [rel login_wire_handle]
    lea rsi, [rel login_wire_frame]
    mov edx, r12d
    call [rel login_wire_tx]         ; exactly one existing driver TX, never a retry
    jmp .out
.retire:
    mov byte [rel login_wire_active], 0
.out:
    movdqu xmm0, [rsp+0]
    movdqu xmm1, [rsp+16]
    movdqu xmm2, [rsp+32]
    movdqu xmm3, [rsp+48]
    movdqu xmm4, [rsp+64]
    movdqu xmm5, [rsp+80]
    movdqu xmm6, [rsp+96]
    movdqu xmm7, [rsp+112]
    movdqu xmm8, [rsp+128]
    movdqu xmm9, [rsp+144]
    movdqu xmm10, [rsp+160]
    movdqu xmm11, [rsp+176]
    movdqu xmm12, [rsp+192]
    movdqu xmm13, [rsp+208]
    movdqu xmm14, [rsp+224]
    movdqu xmm15, [rsp+240]
    mov rsp, rbp
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

; Only public route/boot/challenge scalars and the fixed public frame.
%macro WDATA_login_stage_wire 0
alignb 16
login_wire_frame: resb 114
login_wire_active: resb 1
alignb 8
login_wire_handle: resq 1
login_wire_ops: resq 1
login_wire_tx: resq 1
login_wire_epoch_ptr: resq 1
login_wire_generation: resq 1
login_wire_heartbeat: resq 1
login_wire_budget: resd 1
%endmacro
WDATA_BSS_DEFER WDATA_login_stage_wire
%endif
%endif
