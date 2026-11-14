;; MODULE hv/input_domain_command
;; LAYER 5
;; EXPORTS pinj_command, pinj_backend_stopped, pinj_gui_take_hook
;; IMPORTS hv/vmx, hv/input_owner, hv/input_domain_bridge, hv/input_domain_consumer, boot/gop
;; CAPS extension
;; OWNER saga:input
; Explicit GUESTVM PIN1 caller at the existing cooperative stopped-vCPU command
; boundary. No yield, guest entry, automatic poll or device discovery. SHOW is an explicit
; optional typed GUI drain; TAKE retains its original record-only behavior.
; Same registry owner authorization as GUESTVM. BIND does not admit a profile,
; assign a controller or prove that evdev descriptors name physical hardware.

; RDI=text after PIN1. BIND gen epoch session | KEY/PTR/PUMP/TAKE/STOP/SHOW gen.
; Canonical positive u64 identities; all syntax parsed before side effects.
; Output contains at most one complete PDC1/DOMN record, never HUMAN authority.
pinj_command:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,1024                         ; args24 + record320 + hex641, disjoint
    mov rbx,rdi
    call hv_out_reset
    mov rdi,rbx
    call hv_skip_spaces
    mov rbx,rax
    xor r13d,r13d
    lea r14,[rel pinj_verbs]
.verb:
    mov rdi,rbx
    movsxd rsi,dword [r14]
    lea rdx,[rel pinj_verbs]
    add rsi,rdx
    call hv_tok_is
    test al,al
    jnz .matched
    add r14,8
    inc r13d
    cmp r13d,7
    jb .verb
    jmp .invalid
.matched:
    mov eax,[r14+4]
    add rbx,rax
    mov r14d,1
    test r13d,r13d
    jnz .parse
    mov r14d,3
.parse:
    xor r15d,r15d
.number:
    mov rdi,rbx
    call pinj_u64
    jc .invalid
    mov [rsp+r15*8],rax
    mov rbx,rdi
    inc r15d
    cmp r15d,r14d
    jb .number
    mov rdi,rbx
    call hv_skip_spaces
    cmp byte [rax],0
    jne .invalid
    mov rdi,[rsp]                         ; exact caller START, not a guessed latest
    test r13d,r13d
    jz .bind
    cmp r13d,3
    je .pump
    cmp r13d,4
    je .take
    cmp r13d,5
    je .stop
    cmp r13d,6
    je .show
    mov edx,r13d                          ; KEY1 / PTR2
    mov esi,1
    call pinb_request
    test eax,eax
    jnz .render
    mov rdi,[rsp]
    call hv_pin_pump                      ; exactly one service opportunity
    jmp .render                           ; 0 pressure /64 sent /negative refusal
.bind:
    ; Validate native dimensions and empty consumer BEFORE acquiring an owner.
    cmp dword [rel pinc_state],0
    jne .busy
    mov ecx,[rel fb_width]
    mov r8d,[rel fb_height]
    test ecx,ecx
    jz .invalid
    test r8d,r8d
    jz .invalid
    cmp ecx,32768
    ja .invalid
    cmp r8d,32768
    ja .invalid
    mov rsi,[rsp+8]
    mov rdx,[rsp+16]
    call hv_pin_bind                      ; actual profile/START/epoch/queues
    test eax,eax
    jnz .render
    mov rdi,[rsp]
    mov rsi,[rsp+8]
    mov rdx,[rsp+16]
    mov ecx,[rel fb_width]
    mov r8d,[rel fb_height]
    call pinc_bind
    test eax,eax
    jz .render
    mov r12d,eax
    mov rdi,[rsp]
    call hv_pin_stop                      ; partial bind retains CPU/RAM custody
    mov eax,r12d
    jmp .render
.pump:
    call hv_pin_pump                      ; never allocates another sequence
    jmp .render
.take:
    lea rsi,[rsp+32]
    mov edx,320
    call pinb_poll                        ; only checked native DOMAIN drain
    jmp .render
.show:
    mov rax,[rel pinj_gui_take_hook]
    test rax,rax
    jz .unavailable
    lea rsi,[rsp+32]
    mov edx,320
    call rax                             ; L6 owns admission, poll and GUI effects
    jmp .render
.unavailable:
    mov eax,-95
    jmp .render
.stop:
    call hv_pin_stop                      ; request actual CPU stop, not peer ACK
    jmp .render
.busy:
    mov eax,-16
    jmp .render
.invalid:
    mov eax,-22
.render:
    mov r12d,eax
    lea rdi,[rel pinj_status]
    call hv_out_str
    test r12d,r12d
    jns .positive
    lea rdi,[rel pinj_minus]
    call hv_out_str
    mov eax,r12d
    neg eax
    jmp .decimal
.positive:
    mov eax,r12d
.decimal:
    call hv_out_dec
    cmp r13d,4
    je .record
    cmp r13d,6
    jne .out
.record:
    cmp r12d,320
    jne .out
    ; Complete snapshot only. Hex preserves every identity/deadline/event byte.
    lea rsi,[rsp+32]
    lea rdi,[rsp+352]
    lea r8,[rel pinj_hex]
    mov ecx,320
.hex:
    movzx eax,byte [rsi]
    mov edx,eax
    shr eax,4
    mov al,[r8+rax]
    mov [rdi],al
    and edx,15
    mov al,[r8+rdx]
    mov [rdi+1],al
    inc rsi
    add rdi,2
    dec ecx
    jnz .hex
    mov byte [rdi],0
    lea rdi,[rel pinj_record]
    call hv_out_str
    lea rdi,[rsp+352]
    call hv_out_str
.out:
    mov eax,r12d
    add rsp,1024
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI native NUL-terminated command text -> RAX value, RDI delimiter, CF failure.
; At most20 digits, no leading zero, sign, wrap, tab or attached suffix.
pinj_u64:
.spaces:
    cmp byte [rdi],' '
    jne .start
    inc rdi
    jmp .spaces
.start:
    cmp byte [rdi],'1'
    jb .bad
    cmp byte [rdi],'9'
    ja .bad
    xor eax,eax
    xor r9d,r9d
    mov r10d,10
.digit:
    movzx ecx,byte [rdi]
    sub ecx,'0'
    cmp ecx,9
    ja .end
    inc r9d
    cmp r9d,20
    ja .bad
    mul r10
    test rdx,rdx
    jnz .bad
    add rax,rcx
    jc .bad
    inc rdi
    jmp .digit
.end:
    cmp byte [rdi],0
    je .ok
    cmp byte [rdi],' '
    jne .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

; Called only from the actual loader/backend terminal path AFTER hv_pin_retire.
; Failed/unknown CPU-off or a retained owner cannot erase DOMAIN held state.
pinj_backend_stopped:
    cmp byte [rel hvp_bound],0
    jne .out
    cmp byte [rel hv_linux_running],0
    jne .out
    cmp byte [rel hv_linux_vmx_live],0
    jne .out
    cmp byte [rel hv_guest_power_fenced],0
    jne .out
    mov edi,[rel hv_linux_start_consumed]
    cmp edi,[rel hv_linux_start_gen]
    jne .out
    jmp pinc_retire                        ; no-op refusal when no consumer exists
.out:
    ret

align 8
pinj_verbs:
    dd pinj_bind-pinj_verbs,4,pinj_key-pinj_verbs,3,pinj_ptr-pinj_verbs,3
    dd pinj_pump-pinj_verbs,4,pinj_take-pinj_verbs,4,pinj_stop-pinj_verbs,4
    dd pinj_show-pinj_verbs,4
pinj_bind: db 'BIND',0
pinj_key: db 'KEY',0
pinj_ptr: db 'PTR',0
pinj_pump: db 'PUMP',0
pinj_take: db 'TAKE',0
pinj_stop: db 'STOP',0
pinj_show: db 'SHOW',0
pinj_status: db ' PIN1 status=',0
pinj_minus: db '-',0
pinj_record: db ' record=',0
pinj_hex: db '0123456789abcdef',0

%include "core/abi/wdata.inc"
%macro WDATA_hv_input_domain_command 0
alignb 8
pinj_gui_take_hook: resq 1                ; native L6 registration only
%endmacro
WDATA_BSS_DEFER WDATA_hv_input_domain_command
