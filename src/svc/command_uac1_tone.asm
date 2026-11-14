;; MODULE svc/command_uac1_tone
;; LAYER 5
;; EXPORTS command_uac1_tone_init, uac1_tone_start, uac1_tone_tick, uac1_tone_status
;; IMPORTS svc/command, usb/enum, dev/usb/uac1_activate, dev/usb/xhci, core/cadence, core/time
;; CAPS
;; OWNER rc-codex-av
; Explicit owner diagnostic, never a boot action or selected sound backend.
; U64 packed selection: index8 | interface8<<8 | alternate8<<16 (OUT only).
; Exactly256 1ms PCM16 stereo48k packets, same fixed1kHz square-wave cycle.
; One retained diagnostic lifetime; uncertain activation/transport is never
; retried, reset, cancelled or made reusable here. Existing retirement owns it.
UAT_PHASE equ 0                  ; 0idle/1preparing/2active/3drained/4failed
UAT_ERROR equ 4
UAT_SENT equ 8
UAT_DONE equ 12
UAT_TICKS equ 16
UAT_ADDR equ 20
UAT_HC equ 24
UAT_DEADLINE equ 32
UAT_SLOT equ 40
UAT_GENERATION equ 48
UAT_CAPACITY equ 52
UAT_ACT equ 64                   ; existing192B activation receipt
UAT_COMPLETION equ 256           ; existing16B completion receipt
UAT_PACKETS equ 272              ; eight{pointer64,length64}
UAT_PCM equ 400                  ; one immutable192B packet, copied on enqueue
UAT_LAST_NOW equ 592             ; append-only private monotonic observation

command_uac1_tone_init:
    sub rsp,8
    lea rdi,[rel uac1_tone_verb]
    lea rsi,[rel uac1_tone_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,1
    call command_register_verb
    lea rdi,[rel uac1_stat_verb]
    lea rsi,[rel uac1_stat_handler]
    xor edx,edx
    mov ecx,ARGT_U64
    xor r8d,r8d
    xor r9d,r9d
    call command_register_verb
    add rsp,8
    ret
uac1_tone_handler:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    call cmd_handler_prologue
    cmp qword [r12+REQ_PRINCIPAL],CMD_PRINCIPAL_OWNER
    jne .bad
    mov rdi,[r12+REQ_ARG]
    call uac1_tone_start
    test rax,rax
    jnz .bad
    mov qword [r13+RSP_CODE],CMDE_OK
    mov qword [r13+RSP_ACCEPTED],1
    jmp .record
.bad:
    mov qword [r13+RSP_CODE],CMDE_BADARG
    mov qword [r13+RSP_ACCEPTED],0
    lea rax,[rel uac1_tone_hint]
    mov [r13+RSP_HINT],rax
.record:
    call uac1_tone_status
    mov [r13+RSP_VAL],rax
    pop r13
    pop r12
    pop rbx
    ret
uac1_stat_handler:
    push rbx
    mov rbx,rsi
    call cmd_handler_prologue
    call uac1_tone_status
    mov [rbx+RSP_VAL],rax
    mov qword [rbx+RSP_CODE],CMDE_OK
    pop rbx
    ret
; Read-only packed facts: phase8,error8,sent16,completed16,activation stage16.
uac1_tone_status:
    movzx eax,word [rel uac1_tone_state+UAT_ACT+128]
    shl rax,16
    mov ax,[rel uac1_tone_state+UAT_DONE]
    shl rax,16
    mov ax,[rel uac1_tone_state+UAT_SENT]
    shl rax,8
    mov al,[rel uac1_tone_state+UAT_ERROR]
    shl rax,8
    mov al,[rel uac1_tone_state+UAT_PHASE]
    ret

uac1_tone_start:                 ; RDI packed selection, EAX0/-1
    push rbx
    push rbp
    push r12
    mov rbx,rdi
    cmp rbx,0xffffff
    ja .bad
    test ebx,0xff0000
    jz .bad
    cmp dword [rel uac1_tone_state+UAT_PHASE],0
    jne .bad
    cmp qword [rel tsc_khz],0
    je .bad
    movzx r12d,bl
    call usb_dev_count
    cmp r12,rax
    jae .bad
    mov rdi,r12
    call usb_dev_is_null
    test eax,eax
    jnz .bad
    mov rdi,r12
    call usb_dev_addr
    cmp rax,1
    jb .bad
    cmp rax,255
    ja .bad
    mov r12d,eax
    movzx edi,bl
    call usb_dev_hc
    test rax,rax
    jz .bad
    mov rbp,rax
    mov rdi,rax
    call xhci_hc_generation
    cmp eax,-1
    je .bad
    mov [rel uac1_tone_state+UAT_GENERATION],eax
    mov [rel uac1_tone_state+UAT_HC],rbp
    mov [rel uac1_tone_state+UAT_ADDR],r12d
    mov qword [rel uac1_tone_state+UAT_SLOT],-1
    mov dword [rel uac1_tone_state+UAT_PHASE],1
    lea rdi,[rel uac1_tone_cadence]
    mov esi,1
    mov edx,1000
    mov rcx,[rel tsc_khz]
    lea r8,[rel uac1_tone_tick]
    call cadence_register_named
    cmp eax,-1
    je .cadence_fail
    mov [rel uac1_tone_state+UAT_SLOT],rax
    mov rdi,rbp
    mov esi,r12d
    mov edx,ebx
    shr edx,8
    mov ecx,48000
    mov r8d,2
    lea r9,[rel uac1_tone_state+UAT_ACT]
    call uac1_fs_activate
    test eax,eax
    jnz .activation_fail
    ; The actual helper admitted PCM16 stereo48k, OUT interval1. Capacity uses
    ; actual MPS, so a192B packet also works with larger advertised extents.
    mov ecx,[rel uac1_tone_state+UAT_ACT+16]
    cmp ecx,192
    jb .activation_fail
    cmp ecx,1023
    ja .activation_fail
    mov eax,1792
    xor edx,edx
    div ecx
    cmp eax,8
    jbe .capacity
    mov eax,8
.capacity:
    mov [rel uac1_tone_state+UAT_CAPACITY],eax
    lea rdi,[rel uac1_tone_state+UAT_PCM]
    mov ecx,24
    mov eax,0x10001000
    rep stosd
    mov ecx,24
    mov eax,0xf000f000
    rep stosd
    lea rdi,[rel uac1_tone_state+UAT_PACKETS]
    lea rax,[rel uac1_tone_state+UAT_PCM]
    mov ecx,8
.packets:
    mov [rdi],rax
    mov qword [rdi+8],192
    add rdi,16
    loop .packets
    call time_monotonic_now_us
    mov [rel uac1_tone_state+UAT_LAST_NOW],rax
    add rax,5000000
    jc .deadline_fail
    mov [rel uac1_tone_state+UAT_DEADLINE],rax
    mov edi,[rel uac1_tone_state+UAT_CAPACITY]
    call uac1_tone_queue
    test eax,eax
    jnz .queue_fail
    mov dword [rel uac1_tone_state+UAT_PHASE],2
    xor eax,eax
    jmp .out
.cadence_fail: mov eax,3
    jmp .fail
.activation_fail: mov eax,4
    jmp .fail
.deadline_fail: mov eax,5
    jmp .fail
.queue_fail:
    cmp eax,5
    je .fail
    cmp eax,9
    je .fail
    mov eax,7
.fail:
    call uac1_tone_fail
    jmp .out
.bad: mov rax,-1
.out:
    pop r12
    pop rbp
    pop rbx
    ret

uac1_tone_owner:
    mov rdi,[rel uac1_tone_state+UAT_HC]
    mov esi,[rel uac1_tone_state+UAT_ADDR]
    mov edx,[rel uac1_tone_state+UAT_ACT+12]
    ret
uac1_tone_queue:                 ; EDI count; commit only inside original lease
    push rbx
    push r12
    sub rsp,8
    mov ebx,edi
    call uac1_tone_reply_guard
    test eax,eax
    jnz .out
    call uac1_tone_owner
    lea rcx,[rel uac1_tone_state+UAT_PACKETS]
    mov r8d,ebx
    call xhci_iso_fs_stream_queue
    mov r12,rax
    call uac1_tone_reply_guard
    test eax,eax
    jnz .out
    test r12,r12
    jnz .transport
    add [rel uac1_tone_state+UAT_SENT],ebx
    xor eax,eax
    jmp .out
.transport:
    mov rax,-1
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; Fresh actual incarnation and monotonic time around every owned I/O reply.
; EAX0=valid,5=expired/rewound,9=incarnation lost. Never renew the budget,
; credit a stale reply, retry an uncertain call, or discard pending DMA.
uac1_tone_reply_guard:
    sub rsp,8
    mov rdi,[rel uac1_tone_state+UAT_HC]
    call xhci_hc_generation
    cmp eax,[rel uac1_tone_state+UAT_GENERATION]
    jne .generation
    call time_monotonic_now_us
    cmp rax,[rel uac1_tone_state+UAT_LAST_NOW]
    jb .time
    cmp rax,[rel uac1_tone_state+UAT_DEADLINE]
    jae .time
    mov [rel uac1_tone_state+UAT_LAST_NOW],rax
    xor eax,eax
    jmp .out
.time: mov eax,5
    jmp .out
.generation: mov eax,9
.out:
    add rsp,8
    ret

uac1_tone_tick:
    push rbx
    push rbp
    push r12
    cmp dword [rel uac1_tone_state+UAT_PHASE],2
    jne .out
    inc dword [rel uac1_tone_state+UAT_TICKS]
    cmp dword [rel uac1_tone_state+UAT_TICKS],5000
    ja .timeout
    call uac1_tone_reply_guard
    test eax,eax
    jnz .fail
    mov ebx,8                       ; finite work per canonical cadence turn
.consume:
    call uac1_tone_reply_guard
    test eax,eax
    jnz .fail
    call uac1_tone_owner
    xor ecx,ecx                     ; OUT does not copy a caller buffer
    mov r8d,192
    lea r9,[rel uac1_tone_state+UAT_COMPLETION]
    call xhci_iso_fs_stream_poll
    mov r12,rax
    call uac1_tone_reply_guard
    test eax,eax
    jnz .fail
    mov rax,r12
    cmp rax,-2
    je .out
    cmp rax,192
    jne .completion
    inc dword [rel uac1_tone_state+UAT_DONE]
    cmp dword [rel uac1_tone_state+UAT_DONE],256
    je .drained
    cmp dword [rel uac1_tone_state+UAT_SENT],256
    jae .next
    mov edi,1
    call uac1_tone_queue
    test eax,eax
    jnz .queue
.next:
    dec ebx
    jnz .consume
    jmp .out
.drained:
    call uac1_tone_reply_guard
    test eax,eax
    jnz .fail
    call uac1_tone_owner
    call xhci_iso_fs_stream_close
    mov r12,rax
    call uac1_tone_reply_guard
    test eax,eax
    jnz .fail
    test r12,r12
    jnz .close
    mov dword [rel uac1_tone_state+UAT_PHASE],3
    call uac1_tone_unschedule
    jmp .out
.timeout: mov eax,5
    jmp .fail
.completion: mov eax,6
    jmp .fail
.queue:
    cmp eax,5
    je .fail
    cmp eax,9
    je .fail
    mov eax,7
    jmp .fail
.close: mov eax,8
    jmp .fail
.generation: mov eax,9
.fail:
    call uac1_tone_fail
.out:
    pop r12
    pop rbp
    pop rbx
    ret

uac1_tone_fail:                  ; exact failure remains; no transport close
    mov [rel uac1_tone_state+UAT_ERROR],eax
    mov dword [rel uac1_tone_state+UAT_PHASE],4
    sub rsp,8
    call uac1_tone_unschedule
    add rsp,8
    mov rax,-1
    ret
uac1_tone_unschedule:
    mov edi,[rel uac1_tone_state+UAT_SLOT]
    cmp edi,-1
    je .out
    mov qword [rel uac1_tone_state+UAT_SLOT],-1
    jmp cadence_unregister
.out: ret

align 8
uac1_tone_state: times UAT_LAST_NOW+8 db 0
uac1_tone_storage_end:
uac1_tone_verb: db 'UAC1_TONE',0
uac1_stat_verb: db 'UAC1_STAT',0
uac1_tone_cadence: db 'uac1-tone',0
uac1_tone_hint: db 'UAC1 tone refused; UAC1_STAT reports phase/error/counts/stage',0
