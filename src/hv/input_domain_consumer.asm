;; MODULE hv/input_domain_consumer
;; LAYER 5
;; EXPORTS pinc_bind, pinc_poll, pinc_retire
;; IMPORTS hv/input_domain
;; CAPS extension
;; OWNER saga:input
; Native PIN1 consumer. Serialized by the SAME stopped-vCPU owner as pind_*.
; No guest span is read here: pind_take supplies the complete private snapshot.
; Separate held keys and pixel pointer state; never physical input queues,
; HUMAN presence, credentials, shortcuts, submit, or a request principal.
; Output PDC1 records have fixed DOMN provenance, not a KO_* / WM origin value.
; They are data for a native sink which MUST preserve this authority boundary.
; No automatic activation or GUI action sink. A record is not physical proof.
;
; Current -> prospective -> complete record -> caller copy -> current commit.
; No partial report/state publication. Refusal leaves caller bytes untouched.
; A semantic fault cancels PRIVATE held state and poisons this client binding;
; it is not an ordinary key/button release or a successful device/VM stop.

PINC_SIZE equ 320
PINC_LIVE equ 1
PINC_FAULT equ 2
PINC_STOPPED equ 3

; gen, epoch, session, width, height. Exact fresh idle PIN1 binding, sequence0.
; Dimensions native-owned 1..32768, held state all-up. Does not bind transport.
pinc_bind:
    cmp dword [rel pinc_state],0
    jne .busy
    test rdi,rdi
    jz .invalid
    cmp rdi,[rel pind_gen]
    jne .stale
    cmp rsi,[rel pind_epoch]
    jne .stale
    cmp rdx,[rel pind_session]
    jne .stale
    cmp dword [rel pind_state],PIND_IDLE
    jne .busy
    cmp qword [rel pind_sequence],0
    jne .stale
    test ecx,ecx
    jz .invalid
    cmp rcx,32768
    ja .invalid
    test r8d,r8d
    jz .invalid
    cmp r8,32768
    ja .invalid
    mov [rel pinc_gen],rdi
    mov [rel pinc_epoch],rsi
    mov [rel pinc_session],rdx
    mov [rel pinc_width],ecx
    mov [rel pinc_height],r8d
    mov dword [rel pinc_state],PINC_LIVE
    ; Storage is zero at boot or scrubbed by exact retirement.
    mov dword [rel pinc_current+48],2 ; position UNOBSERVED until pointer DATA
    xor eax,eax
    ret
.busy: mov eax,-16
    ret
.invalid: mov eax,-22
    ret
.stale: mov eax,-116
    ret

; gen, now_ms, stable native output, capacity>=320 ->320 complete /0 no ready
; /negative refusal. Invalid output is retryable without consuming PIN1 READY.
; One call consumes at most one response; quiet is a distinct typed record.
pinc_poll:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    cmp rdi,[rel pinc_gen]
    jne .stale
    cmp dword [rel pinc_state],0
    je .stale
    cmp dword [rel pinc_state],PINC_FAULT
    je .fault_return
    test rdx,rdx
    jz .invalid
    cmp rcx,PINC_SIZE
    jb .invalid
    mov rax,rdx
    add rax,PINC_SIZE
    jc .invalid
    lea r8,[rel pinc_storage_end]
    cmp rdx,r8
    jae .check_client_span
    lea r8,[rel pinc_storage]
    cmp rax,r8
    ja .invalid
.check_client_span:
    lea r8,[rel pind_storage_end]
    cmp rdx,r8
    jae .span_ok
    lea r8,[rel pind_storage]
    cmp rax,r8
    ja .invalid
.span_ok:
    cmp rdi,[rel pind_gen]
    jne .client_lost
    mov rax,[rel pinc_epoch]
    cmp rax,[rel pind_epoch]
    jne .client_lost
    mov rax,[rel pinc_session]
    cmp rax,[rel pind_session]
    jne .client_lost
    cmp rsi,[rel pinc_now]
    jb .bad_clock
    mov [rel pinc_now],rsi
    ; A second request before delivery would lose key transitions. Refuse it.
    mov rax,[rel pinc_sequence]
    cmp dword [rel pinc_state],PINC_STOPPED
    je .stopped
    cmp rax,65536
    jae .exhausted
    inc rax
    cmp [rel pind_sequence],rax
    ja .bad
    call pind_check                  ; includes original absolute READY deadline
    test eax,eax
    jnz .client_error
    cmp dword [rel pind_state],PIND_STOPPED
    je .bad
    cmp dword [rel pind_state],PIND_IDLE
    jne .check_ready
    mov rax,[rel pinc_sequence]
    cmp [rel pind_sequence],rax
    jne .bad
    jmp .none
.check_ready:
    cmp dword [rel pind_state],PIND_READY
    jne .none
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rel pinc_wire]
    mov ecx,256
    call pind_take
    test eax,eax
    jle .client_error
    mov ebx,eax
    lea r15,[rel pinc_wire]
    mov rax,[rel pinc_sequence]
    inc rax
    cmp [r15+24],rax
    jne .bad
    mov rax,[rel pinc_epoch]
    cmp [r15+8],rax
    jne .bad
    mov rax,[rel pinc_session]
    cmp [r15+16],rax
    jne .bad
    ; Wire grammar was checked by PIN1. Bound its use again at this boundary.
    mov eax,[r15+36]
    cmp eax,24
    ja .bad
    lea eax,[rax*8+64]
    cmp eax,ebx
    jne .bad
    pushfq
    cld
    lea rsi,[rel pinc_current]
    lea rdi,[rel pinc_next]
    mov ecx,64
    rep movsb
    lea rdi,[rel pinc_report]
    mov ecx,PINC_SIZE
    xor eax,eax
    rep stosb
    popfq
    mov qword [rel pinc_delta],0
    mov dword [rel pinc_motion],0
    mov dword [rel pinc_next+44],0 ; wheel is this packet, never replayed
    mov dword [rel pinc_report],'PDC1'
    mov word [rel pinc_report+4],1
    mov word [rel pinc_report+6],1 ; DATA
    mov [rel pinc_report+8],r12
    mov rax,[rel pinc_epoch]
    mov [rel pinc_report+16],rax
    mov rax,[rel pinc_session]
    mov [rel pinc_report+24],rax
    mov rax,[r15+24]
    mov [rel pinc_report+32],rax
    mov rax,[r15+32]              ; source,count
    mov [rel pinc_report+40],rax
    mov dword [rel pinc_report+48],'DOMN' ; fixed UNTRUSTED DOMAIN DATA
    mov rax,[rel pind_deadline]
    mov [rel pinc_report+56],rax  ; exact original request budget for native sink
    sub rax,r13
    mov [rel pinc_report+52],eax  ; remaining 1..2000ms, never renewed by consume
    cmp word [r15+6],0x8002
    je .stop
    cmp word [r15+6],0x8001
    jne .bad
    cmp dword [r15+32],1
    jb .bad
    cmp dword [r15+32],2
    ja .bad
    cmp dword [r15+40],-11
    je .quiet
    cmp dword [r15+40],0
    jne .bad
    mov ebx,[r15+36]
    test ebx,ebx
    jz .bad
    dec ebx                       ; exclude final SYN (validated upstream)
    lea r10,[r15+64]
    lea r11,[rel pinc_next]
.event:
    test ebx,ebx
    jz .events_done
    movzx eax,word [r10]
    movzx ecx,word [r10+2]
    mov edx,[r10+4]
    cmp dword [r15+32],1
    jne .pointer
    cmp eax,1
    jne .bad
    cmp ecx,1
    jb .bad
    cmp ecx,255
    ja .bad
    mov esi,ecx
    and esi,7
    shr ecx,3
    mov eax,1
    push rcx
    mov ecx,esi
    shl eax,cl
    pop rcx
    movzx esi,byte [r11+rcx]
    test esi,eax
    jz .key_up
    test edx,edx
    jz .release
    cmp edx,2                     ; repeat only a held key
    jne .bad
    jmp .next
.key_up:
    cmp edx,1                     ; press only an all-up key
    jne .bad
    or [r11+rcx],al
    jmp .next
.release:
    not eax
    and [r11+rcx],al
    jmp .next
.pointer:
    cmp eax,1
    je .button
    cmp eax,2
    je .relative
    cmp eax,3
    jne .bad
    ; Normalized ABS coordinates to this native consumer's dimensions.
    cmp edx,32767
    ja .bad
    cmp ecx,1
    ja .bad
    mov eax,edx
    mov esi,[rel pinc_width]
    test ecx,ecx
    jz .absolute_dim
    mov esi,[rel pinc_height]
.absolute_dim:
    dec esi
    imul rax,rsi
    mov esi,32767
    xor edx,edx
    div rsi
    mov [r11+rcx*4+32],eax
    mov dword [r11+48],1
    jmp .next
.relative:
    cmp edx,-32767
    jl .bad
    cmp edx,32767
    jg .bad
    cmp ecx,8
    je .wheel
    cmp ecx,1
    ja .bad
    lea rsi,[rel pinc_delta]
    add [rsi+rcx*4],edx ; full SYN transaction, then one clamp
    mov dword [rel pinc_motion],1
    mov dword [r11+48],0
    jmp .next
.wheel:
    add [r11+44],edx
    jmp .next
.button:
    sub ecx,272
    cmp ecx,2
    ja .bad
    cmp edx,1
    ja .bad
    mov eax,1
    shl eax,cl
    test [r11+40],eax
    jz .button_up
    test edx,edx
    jnz .bad
    not eax
    and [r11+40],eax
    jmp .next
.button_up:
    cmp edx,1
    jne .bad
    or [r11+40],eax
.next:
    add r10,8
    dec ebx
    jmp .event
.events_done:
    cmp qword [r10],0
    jne .bad
    cmp dword [rel pinc_motion],0
    je .sources
    xor ecx,ecx
.clamp_axis:
    lea rsi,[rel pinc_delta]
    mov eax,[r11+rcx*4+32]
    add eax,[rsi+rcx*4]
    test eax,eax
    jns .clamp_high
    xor eax,eax
.clamp_high:
    mov esi,[rel pinc_width]
    test ecx,ecx
    jz .relative_dim
    mov esi,[rel pinc_height]
.relative_dim:
    dec esi
    cmp eax,esi
    cmovg eax,esi
    mov [r11+rcx*4+32],eax
    inc ecx
    cmp ecx,2
    jb .clamp_axis
.sources:
    cmp dword [r15+36],1
    je .publish                   ; SYN alone is not observed key/pointer activity
    mov ecx,[r15+32]
    dec ecx
    mov eax,1
    shl eax,cl
    or [r11+56],eax                ; sources with actual non-SYN events
    jmp .publish
.quiet:
    cmp dword [r15+36],0
    jne .bad
    mov word [rel pinc_report+6],2 ; QUIET != detached / attached / physical
    jmp .publish
.stop:
    cmp dword [r15+32],0
    jne .bad
    cmp dword [r15+36],0
    jne .bad
    cmp dword [r15+40],0
    jne .bad
    mov word [rel pinc_report+6],3 ; CANCEL, never a normal release action
    pushfq
    cld
    lea rdi,[rel pinc_next]
    mov ecx,64
    xor eax,eax
    rep stosb
    popfq
    mov dword [rel pinc_next+48],2
.publish:
    pushfq
    cld
    lea rsi,[r15+64]
    lea rdi,[rel pinc_report+64]
    mov ecx,[r15+36]
    shl ecx,3
    rep movsb
    lea rsi,[rel pinc_next]
    lea rdi,[rel pinc_report+256]
    mov ecx,64
    rep movsb
    lea rsi,[rel pinc_report]
    mov rdi,r14
    mov ecx,PINC_SIZE
    rep movsb                     ; only complete trusted-native record
    lea rsi,[rel pinc_next]
    lea rdi,[rel pinc_current]
    mov ecx,64
    rep movsb
    popfq
    mov rax,[r15+24]
    mov [rel pinc_sequence],rax
    cmp word [rel pinc_report+6],3
    jne .delivered
    mov dword [rel pinc_state],PINC_STOPPED
.delivered:
    ; No retained wire / caller event payload to replay after success.
    pushfq
    cld
    lea rdi,[rel pinc_next]
    mov ecx,pinc_storage_end-pinc_next
    xor eax,eax
    rep stosb
    popfq
    mov eax,PINC_SIZE
    jmp .out
.stopped:
    cmp [rel pind_sequence],rax
    jne .bad
    cmp dword [rel pind_state],PIND_STOPPED
    jne .bad
.none: xor eax,eax
    jmp .out
.exhausted:
    cmp [rel pind_sequence],rax
    jne .bad
    cmp dword [rel pind_state],PIND_IDLE
    jne .bad
    jmp .none
.invalid: mov eax,-22
    jmp .out
.stale: mov eax,-116
    jmp .out
.bad_clock: mov eax,-5
    jmp .poison
.bad: mov eax,-71
    jmp .poison
.client_lost: mov eax,-116
    jmp .cancel                   ; never poison a replacement client's owner
.client_error:
    test eax,eax
    jnz .cancel
    jmp .bad
.poison:
    mov rdi,r12
    call pind_poison
.cancel:
    mov dword [rel pinc_state],PINC_FAULT
    push rax
    pushfq
    cld
    lea rdi,[rel pinc_current]
    mov ecx,pinc_storage_end-pinc_current
    xor eax,eax
    rep stosb
    popfq
    pop rax
    jmp .out
.fault_return: mov eax,-5
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Exact consumer gen; only AFTER actual owner called pind_retire on VM stop.
; This cancels local data, not physical keys or ordinary release callbacks.
pinc_retire:
    cmp rdi,[rel pinc_gen]
    jne .stale
    cmp dword [rel pinc_state],0
    je .stale
    cmp dword [rel pind_state],0
    jne .busy
    pushfq
    cld
    lea rdi,[rel pinc_storage]
    mov ecx,pinc_storage_end-pinc_storage
    xor eax,eax
    rep stosb
    popfq
    ret
.stale: mov eax,-116
    ret
.busy: mov eax,-16
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_input_domain_consumer 0
alignb 8
pinc_storage:
pinc_gen: resq 1
pinc_epoch: resq 1
pinc_session: resq 1
pinc_sequence: resq 1
pinc_now: resq 1
pinc_width: resd 1
pinc_height: resd 1
pinc_state: resd 1
alignb 8
pinc_current: resb 64
pinc_next: resb 64
pinc_delta: resd 2
pinc_motion: resd 1
pinc_wire: resb 256
pinc_report: resb PINC_SIZE
pinc_storage_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_input_domain_consumer
