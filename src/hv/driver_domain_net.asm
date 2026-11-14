;; MODULE hv/driver_domain_net
;; LAYER 5
;; EXPORTS nd_transport_alive, nd_ready_generation, nd_console_byte, nd_build_ready
;; IMPORTS hv/driver_domain, hv/guestnet, dev/net/virtio_domain, hv/nic_assignment
;; CAPS extension
;; OWNER saga:hv
;; CONTEXT: bsp_only
; This bridge record is a guest observation, never an Internet/Terminal verdict.
; It may enable DORA only with exact native custody, actual queues and live DMA.
; Unbind actual frame queues before the loader releases guest RAM. This does
; not offer another device release or STOP; terminal owner already retired it.
nd_transport_retire:
    cmp byte [rel domain_capstone_nd],1
    jne .out
    jmp virtio_domain_capstone_stop
.out:
    ret

nd_transport_alive:
    mov eax,[rel nd_state]
    cmp eax,1
    je .yes
    cmp eax,2
    je .yes
    xor eax,eax
    ret
.yes:
    mov eax,1
    ret

nd_ready_generation:
    cmp dword [rel nd_operational],1
    jne .bad
    sub rsp,8
    call nd_current
    add rsp,8
    test eax,eax
    jz .bad
    mov eax,[rel nd_generation]
    ret
.bad:
    xor eax,eax
    ret

; Called only for original counted virtio-console TX bytes, never UART/input.
; Fixed exact line; a partial line cannot survive a START or a console reset.
nd_console_byte:
    push rbx
    push r12
    push r13
    mov r12d,eax
    cmp dword [rel nd_state],2
    jne .out
    cmp dword [rel nd_operational],0
    jne .out
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel nd_generation]
    jne .reset
    mov rax,[rel hv_vcon_epoch]
    cmp rax,[rel nd_console_epoch]
    je .epoch
    mov [rel nd_console_epoch],rax
    mov dword [rel nd_ready_pos],0
    mov byte [rel nd_ready_line],0
.epoch:
    cmp r12b,10
    je .newline
    cmp byte [rel nd_ready_line],1
    jne .out
    mov ebx,[rel nd_ready_pos]
    cmp ebx,64
    jae .drop
    cmp r12b,13
    je .cr
    cmp byte [rel nd_ready_cr],0
    jne .drop
    lea rax,[rel nd_ready_text]
    cmp r12b,[rax+rbx]
    jne .drop
    inc dword [rel nd_ready_pos]
    jmp .out
.cr:
    cmp byte [rel nd_ready_cr],0
    jne .drop
    lea rax,[rel nd_ready_text]
    cmp byte [rax+rbx],0
    jne .drop
    mov byte [rel nd_ready_cr],1
    jmp .out
.newline:
    cmp byte [rel nd_ready_line],1
    jne .line
    mov ebx,[rel nd_ready_pos]
    cmp ebx,64
    jae .line
    lea rax,[rel nd_ready_text]
    cmp byte [rax+rbx],0
    jne .line
    call nd_current
    test eax,eax
    jz .line
    cmp byte [rel hv_linux_kboot],1
    jne .line
    cmp byte [rel hv_vcon_q_ready],1
    jne .line
    cmp word [rel guestnet_q_ready],0x0101
    jne .line
    cmp byte [rel guestnet_driver_ok],1
    jne .line
%ifdef PAOS_DRIVER_DOMAIN_EVERYBOOT
    ; A ready line needs the complete length/hash-verified census. Signature
    ; and DATA persistence remain separate observations, never inferred here.
    mov eax,[rel nd_learn_state]
    cmp eax,2
    jb .line
    cmp eax,5
    je .line
    cmp eax,6
    ja .line
%endif
    ; Actual NIC leaf validates enforcement/generation/BDF; record raw proof.
    lea rdi,[rel nd_live_receipt]
    call nic_assignment_receipt
    cmp eax,1
    jne .line
    cmp qword [rel nd_live_receipt],1
    jne .line
    mov rax,[rel nd_generation]
    cmp rax,[rel nd_live_receipt+8]
    jne .line
    mov eax,[rel nd_bdf]
    cmp rax,[rel nd_live_receipt+16]
    jne .line
    call nd_clock
    test eax,eax
    jz .line
    mov rax,[rel nd_clock_ms]
    mov [rel nd_bridge_ms],rax
    mov dword [rel nd_operational],1
.line:
    mov byte [rel nd_ready_line],1
    mov byte [rel nd_ready_cr],0
    mov dword [rel nd_ready_pos],0
    jmp .out
.drop:
    mov byte [rel nd_ready_line],0
.reset:
    mov dword [rel nd_ready_pos],0
.out:
    mov eax,r12d
    pop r13
    pop r12
    pop rbx
    ret

nd_build_ready:
%ifdef PAOS_DRIVER_DOMAIN_EVERYBOOT
    sub rsp,8
    call nd_learn_reset
    add rsp,8
%endif
    lea rdi,[rel nd_ready_text]
    lea rsi,[rel nd_ready_prefix]
    mov ecx,nd_ready_prefix_end-nd_ready_prefix
    cld
    rep movsb
    lea rsi,[rel nd_nonce]
    mov ecx,16
    rep movsb
    mov al,' '
    stosb
    mov rax,[rel nd_generation]
    mov r8d,10
    xor ecx,ecx
.decimal:
    xor edx,edx
    div r8
    add dl,'0'
    push rdx
    inc ecx
    test rax,rax
    jnz .decimal
.digits:
    pop rax
    stosb
    loop .digits
    mov byte [rdi],0
    mov dword [rel nd_ready_pos],0
    mov byte [rel nd_ready_line],0
    mov byte [rel nd_ready_cr],0
    mov rax,[rel hv_vcon_epoch]
    mov [rel nd_console_epoch],rax
    ret
nd_ready_prefix: db 'PAOS_ND_READY '
nd_ready_prefix_end:
%include "core/abi/wdata.inc"
%macro WDATA_hv_driver_domain_net 0
align 16
nd_operational: dd 0
nd_ready_pos: dd 0
nd_ready_line: db 0
nd_ready_cr: db 0
align 8
nd_bridge_ms: dq 0
nd_console_epoch: dq 0
nd_ready_text: times 64 db 0
nd_live_receipt: times 64 db 0
%endmacro
WDATA_DEFER WDATA_hv_driver_domain_net
