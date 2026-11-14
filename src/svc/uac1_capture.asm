;; MODULE svc/uac1_capture
;; LAYER 5
;; EXPORTS uac1_capture_start, uac1_capture_start_mono, uac1_capture_channels, uac1_capture_tick, uac1_capture_status, uac1_capture_bytes, uac1_capture_read
;; IMPORTS usb/enum, dev/usb/uac1_activate, dev/usb/xhci, core/cadence, core/time
;; CAPS
;; OWNER rc-codex-av
; Explicit serialized owner diagnostic, not a boot action or registered backend.
; Selection index8|interface8<<8|alternate8<<16. Fixed48k stereoS16 IN; explicit mono entry uses96B intervals.
; Exactly256 bounded service intervals; short/zero packets retain only actual
; complete frames, never zero padding. Whole completed capture is immutable.
; One retained lifetime; unknown activation/transport is never retried/reset.
; No cancellation or reusable ownership: canonical controller retirement owns
; pending DMA on failure. No capture presentation clock or physical proof.
UAC_PHASE equ 0                  ; 0idle/1preparing/2active/3drained/4failed
UAC_ERROR equ 4
UAC_SENT equ 8
UAC_DONE equ 12
UAC_TICKS equ 16
UAC_ADDR equ 20
UAC_HC equ 24
UAC_DEADLINE equ 32
UAC_SLOT equ 40
UAC_GENERATION equ 48
UAC_CAPACITY equ 52
UAC_ACT equ 64                   ; existing192B activation receipt
UAC_COMPLETION equ 256           ; existing16B completion receipt
UAC_PACKETS equ 272              ; eight{pointer64,length64}
UAC_PACKET equ 400               ; private192B accepted completion
UAC_BYTES equ 592                 ; actual complete-frame bytes
UAC_CHANNELS equ 596              ; frozen1mono/2stereo profile
UAC_PACKET_BYTES equ 600          ;96mono/192stereo per1ms
UAC_FRAME_MASK equ 604            ;1mono/3stereo complete-frame alignment
UAC_PCM equ 608                   ; immutable whole capture,49152B maximum
UAC_LAST_NOW equ UAC_PCM+49152    ; monotonic bracket, no replacement budget

; Read-only packed facts: phase8,error8,sent16,completed16,activation stage16.
uac1_capture_status:
    movzx eax,word [rel uac1_capture_state+UAC_ACT+128]
    shl rax,16
    mov ax,[rel uac1_capture_state+UAC_DONE]
    shl rax,16
    mov ax,[rel uac1_capture_state+UAC_SENT]
    shl rax,8
    mov al,[rel uac1_capture_state+UAC_ERROR]
    shl rax,8
    mov al,[rel uac1_capture_state+UAC_PHASE]
    ret

uac1_capture_start:                 ; stereo; RDI selection, EAX0/-1
    mov edx,2
    jmp uac1_capture_start_profile
uac1_capture_start_mono:            ; mono; same selection and lifetime
    mov edx,1
uac1_capture_start_profile:
    push rbx
    push rbp
    push r12
    mov rbx,rdi
    cmp rbx,0xffffff
    ja .bad
    test ebx,0xff0000
    jz .bad
    cmp dword [rel uac1_capture_state+UAC_PHASE],0
    jne .bad
    cmp qword [rel tsc_khz],0
    je .bad
    shl rdx,32
    or rbx,rdx                     ; retain profile across external calls
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
    mov rcx,rbx
    shr rcx,32
    mov [rel uac1_capture_state+UAC_CHANNELS],ecx
    lea edx,[rcx+rcx-1]
    mov [rel uac1_capture_state+UAC_FRAME_MASK],edx
    imul ecx,96
    mov [rel uac1_capture_state+UAC_PACKET_BYTES],ecx
    mov [rel uac1_capture_state+UAC_GENERATION],eax
    mov [rel uac1_capture_state+UAC_HC],rbp
    mov [rel uac1_capture_state+UAC_ADDR],r12d
    mov qword [rel uac1_capture_state+UAC_SLOT],-1
    mov dword [rel uac1_capture_state+UAC_PHASE],1
    lea rdi,[rel uac1_capture_cadence]
    mov esi,1
    mov edx,1000
    mov rcx,[rel tsc_khz]
    lea r8,[rel uac1_capture_tick]
    call cadence_register_named
    cmp eax,-1
    je .cadence_fail
    mov [rel uac1_capture_state+UAC_SLOT],rax
    mov rdi,rbp
    mov esi,r12d
    mov edx,ebx
    shr edx,8
    or edx,0x10000                  ; actual function selector IN
    mov ecx,48000
    mov r8d,[rel uac1_capture_state+UAC_CHANNELS]
    lea r9,[rel uac1_capture_state+UAC_ACT]
    call uac1_fs_activate
    test eax,eax
    jnz .activation_fail
    ; Actual helper admitted selected PCM16 channel profile48k, IN interval1.
    ; Capacity uses actual MPS; requests use exact profile payload.
    mov ecx,[rel uac1_capture_state+UAC_ACT+16]
    cmp ecx,[rel uac1_capture_state+UAC_PACKET_BYTES]
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
    mov [rel uac1_capture_state+UAC_CAPACITY],eax
    lea rdi,[rel uac1_capture_state+UAC_PACKETS]
    xor eax,eax                    ; IN packet pointers are ignored
    mov ecx,8
    mov edx,[rel uac1_capture_state+UAC_PACKET_BYTES]
.packets:
    mov [rdi],rax
    mov [rdi+8],rdx
    add rdi,16
    loop .packets
    call time_monotonic_now_us
    mov [rel uac1_capture_state+UAC_LAST_NOW],rax
    add rax,5000000
    jc .deadline_fail
    mov [rel uac1_capture_state+UAC_DEADLINE],rax
    mov edi,[rel uac1_capture_state+UAC_CAPACITY]
    call uac1_capture_queue
    test eax,eax
    jnz .queue_fail
    mov dword [rel uac1_capture_state+UAC_PHASE],2
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
    call uac1_capture_fail
    jmp .out
.bad: mov rax,-1
.out:
    pop r12
    pop rbp
    pop rbx
    ret

uac1_capture_owner:
    mov rdi,[rel uac1_capture_state+UAC_HC]
    mov esi,[rel uac1_capture_state+UAC_ADDR]
    mov edx,[rel uac1_capture_state+UAC_ACT+12]
    ret
uac1_capture_queue:                 ; EDI count; commit only inside original lease
    push rbx
    push r12
    sub rsp,8
    mov ebx,edi
    call uac1_capture_reply_guard
    test eax,eax
    jnz .out
    call uac1_capture_owner
    lea rcx,[rel uac1_capture_state+UAC_PACKETS]
    mov r8d,ebx
    call xhci_iso_fs_stream_queue
    mov r12,rax
    call uac1_capture_reply_guard
    test eax,eax
    jnz .out                       ; accepted/unknown DMA remains retained
    test r12,r12
    jnz .transport
    add [rel uac1_capture_state+UAC_SENT],ebx
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
; EAX0=valid,5=expired/rewound,9=incarnation lost. Does not renew the budget,
; credit PCM, retry an uncertain call, close live work, or discard owned DMA.
uac1_capture_reply_guard:
    sub rsp,8
    mov rdi,[rel uac1_capture_state+UAC_HC]
    call xhci_hc_generation
    cmp eax,[rel uac1_capture_state+UAC_GENERATION]
    jne .generation
    call time_monotonic_now_us
    cmp rax,[rel uac1_capture_state+UAC_LAST_NOW]
    jb .time
    cmp rax,[rel uac1_capture_state+UAC_DEADLINE]
    jae .time
    mov [rel uac1_capture_state+UAC_LAST_NOW],rax
    xor eax,eax
    jmp .out
.time: mov eax,5
    jmp .out
.generation: mov eax,9
.out:
    add rsp,8
    ret

uac1_capture_tick:
    push rbx
    push rbp
    push r12
    cmp dword [rel uac1_capture_state+UAC_PHASE],2
    jne .out
    inc dword [rel uac1_capture_state+UAC_TICKS]
    cmp dword [rel uac1_capture_state+UAC_TICKS],5000
    ja .timeout
    call uac1_capture_reply_guard
    test eax,eax
    jnz .fail
    mov ebx,8                       ; finite work per canonical cadence turn
.consume:
    call uac1_capture_reply_guard
    test eax,eax
    jnz .fail
    call uac1_capture_owner
    lea rcx,[rel uac1_capture_state+UAC_PACKET]
    mov r8d,[rel uac1_capture_state+UAC_PACKET_BYTES]
    lea r9,[rel uac1_capture_state+UAC_COMPLETION]
    call xhci_iso_fs_stream_poll
    mov r12,rax
    call uac1_capture_reply_guard
    test eax,eax
    jnz .fail
    mov rax,r12
    cmp rax,-2
    je .out
    mov ecx,[rel uac1_capture_state+UAC_PACKET_BYTES]
    cmp rax,rcx
    ja .completion                  ; includes negative errors
    test eax,[rel uac1_capture_state+UAC_FRAME_MASK]
    jnz .completion                 ; complete selected S16 frames only
    mov r12d,eax
    mov ecx,[rel uac1_capture_state+UAC_BYTES]
    lea edx,[rcx+rax]
    cmp edx,49152
    ja .completion
    lea rdi,[rel uac1_capture_state+UAC_PCM]
    add rdi,rcx
    lea rsi,[rel uac1_capture_state+UAC_PACKET]
    mov ecx,r12d
    cld
    rep movsb
    add [rel uac1_capture_state+UAC_BYTES],r12d
    inc dword [rel uac1_capture_state+UAC_DONE]
    cmp dword [rel uac1_capture_state+UAC_DONE],256
    je .drained
    cmp dword [rel uac1_capture_state+UAC_SENT],256
    jae .next
    mov edi,1
    call uac1_capture_queue
    test eax,eax
    jnz .queue
.next:
    dec ebx
    jnz .consume
    jmp .out
.drained:
    call uac1_capture_reply_guard
    test eax,eax
    jnz .fail
    call uac1_capture_owner
    call xhci_iso_fs_stream_close
    mov r12,rax
    call uac1_capture_reply_guard
    test eax,eax
    jnz .fail
    test r12,r12
    jnz .close
    mov dword [rel uac1_capture_state+UAC_PHASE],3
    call uac1_capture_unschedule
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
    call uac1_capture_fail
.out:
    pop r12
    pop rbp
    pop rbx
    ret

uac1_capture_fail:                  ; exact failure remains; no transport close
    mov [rel uac1_capture_state+UAC_ERROR],eax
    mov dword [rel uac1_capture_state+UAC_PHASE],4
    sub rsp,8
    call uac1_capture_unschedule
    add rsp,8
    mov rax,-1
    ret
uac1_capture_unschedule:
    mov edi,[rel uac1_capture_state+UAC_SLOT]
    cmp edi,-1
    je .out
    mov qword [rel uac1_capture_state+UAC_SLOT],-1
    jmp cadence_unregister
.out: ret

; Complete capture only. EAX1/2 channels; rate48000/PCM16 are fixed.
uac1_capture_channels:
    cmp dword [rel uac1_capture_state+UAC_PHASE],3
    jne .bad
    mov eax,[rel uac1_capture_state+UAC_CHANNELS]
    ret
.bad: mov rax,-1
    ret

; Complete capture only. RAX=actual PCM bytes, -1 until successful drain.
uac1_capture_bytes:
    cmp dword [rel uac1_capture_state+UAC_PHASE],3
    jne .bad
    mov eax,[rel uac1_capture_state+UAC_BYTES]
    ret
.bad: mov rax,-1
    ret

; RDI=byte offset, RSI=trusted mapped output, RDX=positive byte length.
; Exact complete-frame ranges only; refusal never touches the output. No DMA
; clock or continuity claim, and no read access to partial/failed captures.
uac1_capture_read:
    cmp dword [rel uac1_capture_state+UAC_PHASE],3
    jne .bad
    test rdx,rdx
    jz .bad
    mov rax,rdi
    or rax,rdx
    test eax,[rel uac1_capture_state+UAC_FRAME_MASK]
    jnz .bad
    mov rax,rdi
    add rax,rdx
    jc .bad
    mov ecx,[rel uac1_capture_state+UAC_BYTES]
    cmp rax,rcx
    ja .bad
    test rsi,rsi
    jz .bad
    mov rax,rsi
    add rax,rdx
    jc .bad
    mov rcx,rax
    dec rcx
    shr rcx,47
    jnz .bad
    lea rcx,[rel uac1_capture_storage_end]
    cmp rsi,rcx
    jae .copy
    lea rcx,[rel uac1_capture_state]
    cmp rax,rcx
    ja .bad
.copy:
    mov r8,rdi
    mov rdi,rsi
    lea rsi,[rel uac1_capture_state+UAC_PCM]
    add rsi,r8
    mov rax,rdx
    mov rcx,rdx
    cld
    rep movsb
    ret
.bad: mov rax,-1
    ret

align 8
uac1_capture_state: times 49760 db 0
    times 8 db 0                    ; UAC_LAST_NOW
uac1_capture_storage_end:
uac1_capture_cadence: db 'uac1-capture',0
