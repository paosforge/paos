;; MODULE net/carrier_drill
;; LAYER 4
;; EXPORTS netdev_carrier_drill_prepare, netdev_carrier_drill_set, netdev_carrier_drill_link, netdev_carrier_drill_finish, netdev_carrier_drill_observe, carrier_drill_prepare, carrier_drill_set, carrier_drill_link, carrier_drill_finish, carrier_drill_observation
;; IMPORTS net/netdev, dev/net/rtl8125, dev/net/rtl8168, dev/net/rtl8126, dev/net/e1000e
;; CAPS
;; OWNER saga:net
;; CONTEXT: bsp_only
; Real PHY outage primitive for an owner-authorized, autonomous BSP consumer.
; This is NOT a command, timer, TCP producer or runtime PASS. Caller consumes
; owner intent, binds selected NIC+epoch, selects the exact TCP state, restores
; on every exit (including timeout), and records independent TCP/wire evidence.
; Never wait for another host packet to restore the PHY whose carrier is down.
;
; prepare(RDI handle, RSI generation) -> original BMCR / full -1. No PHY write.
; set(same, EDX=1 down / 0 restore) -> 0 after ACK AND persistent-bit readback.
; link(same) -> 0 down / 1 up / -1 unknown from a fresh physical status read.
; finish(same) -> 0 only untouched prepare or verified restore + physical up.
; observation(same, RDX=64-byte trusted output) -> valid, phase, request,
; write result, readback, actual raw link status, sequence, final result.
; Observation is passive, including after finish. Unknown/foreign yields zeros.
;
; One active context, one down per prepare, at most three restore attempts.
; Failed/ambiguous writes retain restoration debt. New preparation is allowed
; only after finish; thus SYN-SENT and ESTABLISHED can have distinct outages.
; Normal PHY down does not retire a netdev. If membership/epoch changes, never
; restore into a replacement device; retain debt and report failure to caller.
; All GPR callee-saved registers are preserved. Caller-saved may be clobbered.

; Consumer-facing dispatch: caller supplies the exact selected handle only.
; RAX=current nonzero nonsaturated generation, RDX=original BMCR, or RAX=-1.
; set/link/finish/observe keep that returned generation; no caller ops guesses.
netdev_carrier_drill_prepare:
    push r12
    mov r12, rdi
    mov rdi, r12
    lea rsi, [rel rtl8125_ops]
    call netdev_power_member
    test rax, rax
    jnz .found
    mov rdi, r12
    lea rsi, [rel rtl8168_ops]
    call netdev_power_member
    test rax, rax
    jnz .found
    mov rdi, r12
    lea rsi, [rel e5000b_ops]
    call netdev_power_member
    test rax, rax
    jnz .found
    mov rdi, r12
    lea rsi, [rel e1000e_ops]
    call netdev_power_member
    test rax, rax
    jnz .found
    mov rax, -1
    pop r12
    ret
.found:
    mov rdi, r12
    mov rsi, rdx
    call carrier_drill_prepare
    cmp rax, -1
    je .out
    mov rdx, rax
    mov rax, [rel cd_epoch]
.out:
    pop r12
    ret
netdev_carrier_drill_set:
    jmp carrier_drill_set
netdev_carrier_drill_link:
    jmp carrier_drill_link
netdev_carrier_drill_finish:
    jmp carrier_drill_finish
netdev_carrier_drill_observe:
    jmp carrier_drill_observation

carrier_drill_prepare:
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    cmp qword [rel cd_busy], 0
    jne .bad
    test r13, r13
    jz .bad
    cmp r13, -1
    je .bad
    mov qword [rel cd_obs], 0       ; failed new prepare must expose no prior valid record
    mov [rel cd_handle], r12
    mov [rel cd_epoch], r13
    mov rdi, r12
    lea rsi, [rel rtl8125_ops]
    call netdev_power_member
    test rax, rax
    jnz .family0
    mov rdi, r12
    lea rsi, [rel rtl8168_ops]
    call netdev_power_member
    test rax, rax
    jnz .family1
    mov rdi, r12
    lea rsi, [rel e5000b_ops]
    call netdev_power_member
    test rax, rax
    jnz .family2
    mov rdi, r12
    lea rsi, [rel e1000e_ops]
    call netdev_power_member
    test rax, rax
    jnz .family3
    jmp .bad
.family0:
    lea rcx, [rel rtl8125_ops]
    mov qword [rel cd_family], 0
    jmp .member
.family1:
    lea rcx, [rel rtl8168_ops]
    mov qword [rel cd_family], 1
    jmp .member
.family2:
    lea rcx, [rel e5000b_ops]
    mov qword [rel cd_family], 2
    jmp .member
.family3:
    lea rcx, [rel e1000e_ops]
    mov qword [rel cd_family], 3
    jmp .member
.member:
    cmp rdx, r13
    jne .bad
    mov [rel cd_ops], rcx
    mov [rel cd_epoch_ptr], rax
    call cd_ready
    cmp rax, 1
    jne .bad
    call cd_validate
    test rax, rax
    jnz .bad
    call cd_link
    cmp rax, 1
    jne .bad
    mov [rel cd_obs + 40], rdx
    call cd_validate
    test rax, rax
    jnz .bad
    call cd_read
    cmp rax, 0xffff
    jae .bad
    test eax, 0xcc00                 ; reset, loopback, isolate or already powered down
    jnz .bad
    mov [rel cd_original], rax
    mov qword [rel cd_busy], 1
    mov qword [rel cd_restores], 0
    mov qword [rel cd_obs], 1
    mov qword [rel cd_obs + 8], 1
    mov [rel cd_obs + 16], rax
    mov qword [rel cd_obs + 24], -2
    mov [rel cd_obs + 32], rax
    mov qword [rel cd_obs + 56], 0
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r13
    pop r12
    ret

carrier_drill_set:
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    mov r14d, edx
    cmp r14d, 1
    ja .bad
    call cd_validate
    test rax, rax
    jnz .bad
    cmp r14d, 0
    je .restore
    cmp qword [rel cd_busy], 1
    jne .bad
    mov qword [rel cd_busy], 2       ; debt BEFORE possibly ambiguous write
    mov r14, [rel cd_original]
    or r14d, 0x0800
    jmp .write
.restore:
    cmp qword [rel cd_busy], 2
    jne .bad
    cmp qword [rel cd_restores], 3
    jae .bad
    inc qword [rel cd_restores]
    mov r14, [rel cd_original]
    test r14d, 0x1000
    jz .write
    or r14d, 0x0200                 ; restart only original autoneg policy
.write:
    mov [rel cd_obs + 16], r14
    mov qword [rel cd_obs + 8], 2
    mov qword [rel cd_obs + 24], -2
    mov qword [rel cd_obs + 32], -1 ; clear old success before any access
    mov qword [rel cd_obs + 56], -1
    add qword [rel cd_obs + 48], 1
    sbb qword [rel cd_obs + 48], 0  ; saturating sequence
    call cd_validate
    test rax, rax
    jnz .bad
    call cd_ready
    cmp rax, 1
    jne .bad
    call cd_validate
    test rax, rax
    jnz .bad
    mov esi, r14d
    call cd_write
    mov [rel cd_obs + 24], rax
    ; Even a failed ACK may have changed PHY. Always retain a fresh readback.
    call cd_validate
    test rax, rax
    jnz .bad
    call cd_read
    mov [rel cd_obs + 32], rax
    cmp qword [rel cd_obs + 24], 0
    jne .bad
    cmp rax, 0xffff
    jae .bad
    xor eax, r14d
    test eax, 0xfdff               ; all persistent bits; AN restart self-clears
    jnz .bad
    test r14d, 0x0800
    jnz .ok
    mov qword [rel cd_busy], 3     ; verified register restore, carrier unproven
    mov qword [rel cd_obs + 8], 3
.ok:
    mov qword [rel cd_obs + 56], 0
    xor eax, eax
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r14
    pop r13
    pop r12
    ret

carrier_drill_link:
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    cmp qword [rel cd_busy], 0
    je .bad
    call cd_validate
    test rax, rax
    jnz .bad
    call cd_link
    mov [rel cd_obs + 40], rdx
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r13
    pop r12
    ret

carrier_drill_finish:
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    call cd_validate
    test rax, rax
    jnz .bad
    cmp qword [rel cd_busy], 1
    je .done                       ; prepared but no write occurred
    cmp qword [rel cd_busy], 3
    jne .bad
    call cd_link
    mov [rel cd_obs + 40], rdx
    cmp rax, 1
    jne .bad
.done:
    mov qword [rel cd_busy], 0
    mov qword [rel cd_obs + 8], 4
    xor eax, eax
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r13
    pop r12
    ret

carrier_drill_observation:
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    test r14, r14
    jz .out
    call cd_validate
    cmp qword [rel cd_obs], 1
    je .valid_checked
    mov rax, -1
.valid_checked:
    xor ecx, ecx
.copy:
    xor edx, edx
    test rax, rax
    jnz .store
    lea r8, [rel cd_obs]
    mov rdx, [r8 + rcx*8]
.store:
    mov [r14 + rcx*8], rdx
    inc ecx
    cmp ecx, 8
    jb .copy
.out:
    pop r14
    pop r13
    pop r12
    ret

; R12/R13 exact caller identity. Registry membership before handle dereference.
cd_validate:
    cmp r12, [rel cd_handle]
    jne .bad
    cmp r13, [rel cd_epoch]
    jne .bad
    mov rdi, r12
    mov rsi, [rel cd_ops]
    call netdev_power_member
    test rax, rax
    jz .bad
    cmp rax, [rel cd_epoch_ptr]
    jne .bad
    cmp rdx, r13
    jne .bad
    cmp [rax], r13
    jne .bad
    xor eax, eax
    ret
.bad:
    mov rax, -1
    ret

cd_ready:
    mov rdi, [rel cd_handle]
    cmp qword [rel cd_family], 0
    je rtl8125_carrier_ready
    cmp qword [rel cd_family], 1
    je rtl8168_carrier_ready
    cmp qword [rel cd_family], 2
    je rtl8126_carrier_ready
    cmp qword [rel cd_family], 3
    je e1000e_carrier_ready
    mov rax, -1
    mov rdx, -1
    ret

cd_read:
    mov rdi, [rel cd_handle]
    cmp qword [rel cd_family], 0
    je rtl8125_carrier_read
    cmp qword [rel cd_family], 1
    je rtl8168_carrier_read
    cmp qword [rel cd_family], 2
    je rtl8126_carrier_read
    cmp qword [rel cd_family], 3
    je e1000e_carrier_read
    mov rax, -1
    mov rdx, -1
    ret

cd_write:
    mov rdi, [rel cd_handle]
    cmp qword [rel cd_family], 0
    je rtl8125_carrier_write
    cmp qword [rel cd_family], 1
    je rtl8168_carrier_write
    cmp qword [rel cd_family], 2
    je rtl8126_carrier_write
    cmp qword [rel cd_family], 3
    je e1000e_carrier_write
    mov rax, -1
    mov rdx, -1
    ret

cd_link:
    mov rdi, [rel cd_handle]
    cmp qword [rel cd_family], 0
    je rtl8125_carrier_link
    cmp qword [rel cd_family], 1
    je rtl8168_carrier_link
    cmp qword [rel cd_family], 2
    je rtl8126_carrier_link
    cmp qword [rel cd_family], 3
    je e1000e_carrier_link
    mov rax, -1
    mov rdx, -1
    ret

%macro WDATA_net_carrier_drill_0 0
align 8
cd_busy:       dq 0
cd_handle:     dq 0
cd_ops:        dq 0
cd_epoch:      dq 0
cd_epoch_ptr:  dq 0
cd_family:     dq 0
cd_original:   dq 0
cd_restores:   dq 0
cd_obs:        times 8 dq 0
%endmacro
WDATA_DEFER WDATA_net_carrier_drill_0

; Keep the selectable external lab204 driver usable. It has no checked PHY
; primitive in this unit, so capability is honestly absent, never aliased to
; clean-driver hardware/state or a logical disconnect.
%ifdef PAOS_LAB_RTL8126_204
%if PAOS_LAB_RTL8126_204
rtl8126_carrier_ready:
    xor eax, eax
    ret
rtl8126_carrier_read:
rtl8126_carrier_write:
    mov rax, -1
    ret
rtl8126_carrier_link:
    mov rdx, -1
    mov rax, -1
    ret
%endif
%endif
