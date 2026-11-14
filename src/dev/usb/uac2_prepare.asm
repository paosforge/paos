;; MODULE dev/usb/uac2_prepare
;; LAYER 3
;; EXPORTS uac2_fs_prepare, uac2_fs_unprepare
;; IMPORTS boot/native_driver_gate, dev/usb/uac2_function, dev/usb/uac2_clock, dev/usb/xhci
;; CAPS
;; OWNER rc-codex-av
%include "boot/native_driver_gate.inc"
; Native EP0 preparation only, NOT an ISO transport or a sound backend.
; RDI mapped aligned512B context, RSI exact nonzero owner token. EAX0/-1.
; Context ABI and ownership/retirement contract: docs/uac2_fs_preparation.md.
; One exclusive USB owner, immutable inputs, original absolute us deadline.
; No retry/rollback after a failed transaction; failed context is terminal.
uac2_fs_prepare:
    NATIVE_DRIVER_REFUSE 7
    xor r10d,r10d
    jmp uac2_prepare_entry
uac2_fs_unprepare:
    mov r10d,1
uac2_prepare_entry:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,4928                  ; private clock entries/ratios above4608
    cld
    mov rbp,rsp
    mov [rbp+4536],r10
    mov r12,rdi
    mov r15,rsi
    ; Stable mapped native spans are a caller precondition, not a page probe.
    test rdi,rdi
    jz .invalid
    test dil,7
    jnz .invalid
    lea rax,[rdi+511]
    cmp rax,rdi
    jb .invalid
    shr rax,47
    jnz .invalid
    cmp dword [rdi],512
    jne .invalid
    cmp dword [rdi+4],1
    jne .invalid
    test rsi,rsi
    jz .invalid
    cmp rsi,[rdi+48]
    jne .invalid
    mov r13,[rdi+8]
    test r13,r13
    jz .invalid
    lea rax,[r13+dev_size-1]
    cmp rax,r13
    jb .invalid
    shr rax,47
    jnz .invalid
    lea rax,[r13+dev_size]
    cmp r12,rax
    jae .hc_disjoint
    lea rax,[r12+512]
    cmp r13,rax
    jb .invalid
.hc_disjoint:
    mov r11,[r13+dev.ops]
    test r11,r11
    jz .invalid
    lea rax,[r11+usbhc_ops_size-1]
    cmp rax,r11
    jb .invalid
    shr rax,47
    jnz .invalid
    lea rax,[r11+usbhc_ops_size]
    cmp r12,rax
    jae .ops_disjoint
    lea rax,[r12+512]
    cmp r11,rax
    jb .invalid
.ops_disjoint:
    mov r14,[r11+usbhc_ops.control]
    mov rax,[r11+usbhc_ops.topology]
    test r14,r14
    jz .invalid
    test rax,rax
    jz .invalid
    mov [rbp+4584],rax
    mov rbx,[r12+16]
    cmp rbx,1
    jb .invalid
    cmp rbx,255
    ja .invalid
    mov rax,[r12+24]
    cmp rax,0x1ffff                ; FS IN/OUT only; HS/reserved bits refuse
    ja .invalid
    test eax,0xff00
    jz .invalid
    cmp qword [r12+32],8000
    jb .invalid
    cmp qword [r12+32],192000
    ja .invalid
    cmp qword [r12+40],1
    jb .invalid
    cmp qword [r12+40],2
    ja .invalid
    mov rax,[r12+56]
    shr rax,32
    jnz .invalid
    cmp dword [r12+56],-1
    je .invalid
    cmp qword [r12+64],0
    je .invalid
    mov rax,[r12+72]
    test rax,rax
    jz .invalid
    shr rax,47
    jnz .invalid
    mov rax,[r12+80]
    test rax,rax
    jz .invalid
    shr rax,47
    jnz .invalid
    cmp qword [rbp+4536],0
    jne .claim_stop
    xor eax,eax
    mov edx,1
    lock cmpxchg [r12+88],edx       ; FRESH -> BUSY; reentry never mutates
    jne .invalid
    lea rdi,[r12+92]
    xor eax,eax
    mov ecx,420
    rep stosb
    mov [r12+112],r14
    mov rax,[rbp+4584]
    mov [r12+120],rax
    mov qword [rbp+4544],1         ; capture topology once, compare thereafter
    mov dword [r12+92],1
    call .guard
    test eax,eax
    jnz .failed
    ; Fetch exact complete configuration index0 using the accepted transport.
    mov dword [r12+92],2
    mov qword [rbp+4496],0
    mov word [rbp+4496],0x0680
    mov word [rbp+4498],0x0200
    mov word [rbp+4502],9
    lea rcx,[rbp]
    xor r10d,r10d
    call .wire
    test eax,eax
    jnz .failed
    cmp word [rbp],0x0209
    jne .failed
    movzx eax,word [rbp+2]
    cmp eax,9
    jb .failed
    cmp eax,4096
    ja .failed
    mov [rbp+4528],rax
    mov [rbp+4502],ax
    mov dword [r12+92],3
    lea rcx,[rbp]
    xor r10d,r10d
    call .wire
    test eax,eax
    jnz .failed
    mov dword [r12+92],4
    lea rdi,[rbp]
    mov rsi,[rbp+4528]
    mov rdx,[r12+24]
    mov rcx,[r12+32]
    mov r8,[r12+40]
    lea r9,[r12+144]
    call uac2_pcm16_function_parse
    test eax,eax
    jnz .failed
    ; Pure observation of the accepted AC/selected AS standard interfaces.
    ; Retain outside the unchanged224B candidate before config scratch reuse.
    mov eax,[r12+144+196]
    mov eax,[rbp+rax-9+5]
    bswap eax
    shr eax,8
    mov [r12+408],eax
    mov eax,[r12+144+200]
    mov eax,[rbp+rax+5]
    bswap eax
    shr eax,8
    mov [r12+412],eax
    call .clock_path              ; direct root or supported readonly clock links
    test eax,eax
    jne .failed
    mov eax,[r12+144+196]          ; AC config offset + root AC-relative offset
    add eax,[r12+144+112]
    mov rdx,[rbp+rax]
    mov [r12+368],rdx             ; accepted exact8B Clock Source descriptor
    ; Preserve a matching live configuration. Never steal a different one.
    mov dword [r12+92],5
    mov qword [rbp+4496],0
    mov word [rbp+4496],0x0880
    mov word [rbp+4502],1
    lea rcx,[rbp+4512]
    xor r10d,r10d
    call .wire
    test eax,eax
    jnz .failed
    movzx eax,byte [rbp+4512]
    cmp eax,[r12+144+164]
    je .configured
    test eax,eax
    jnz .failed
    mov dword [r12+92],6
    mov word [rbp+4496],0x0900
    mov eax,[r12+144+164]
    mov [rbp+4498],ax
    mov word [rbp+4502],0
    lea rcx,[rbp+4512]
    mov r10d,1
    call .wire
    test eax,eax
    jnz .failed
    mov dword [r12+92],7
    mov qword [rbp+4496],0
    mov word [rbp+4496],0x0880
    mov word [rbp+4502],1
    lea rcx,[rbp+4512]
    xor r10d,r10d
    call .wire
    test eax,eax
    jnz .failed
    movzx eax,byte [rbp+4512]
    cmp eax,[r12+144+164]
    jne .failed
.configured:
    mov dword [r12+92],8
    call .get_interface
    test eax,eax
    jnz .failed
    cmp byte [rbp+4512],0
    jne .failed
    mov dword [rbp+4888],0       ; initial path admission, derive root frequency
    call .path_controls
    test eax,eax
    jnz .failed
    ; RANGE count then exact bounded full response, never inferred from parser.
    mov dword [r12+92],9
    xor ecx,ecx
    xor r8d,r8d
    call .clock_request
    test eax,eax
    jnz .failed
    lea rcx,[rbp+4096]
    xor r10d,r10d
    call .wire
    test eax,eax
    jnz .failed
    movzx r8d,word [rbp+4096]
    mov ecx,1
    call .clock_request
    test eax,eax
    jnz .failed
    mov dword [r12+92],10
    lea rcx,[rbp+4096]
    xor r10d,r10d
    call .wire
    test eax,eax
    jnz .failed
    lea rdi,[rbp+4096]
    movzx esi,word [rbp+4502]
    mov rdx,[rbp+4880]
    xor ecx,ecx
    xor r8d,r8d
    lea r9,[r12+376]
    call uac2_frequency_select
    test eax,eax
    jnz .failed
    mov dword [r12+92],11
    call .get_frequency
    test eax,eax
    jnz .failed
    mov eax,[rbp+4512]
    cmp eax,[rbp+4880]
    je .frequency_confirmed
    ; Accepted request builder refuses SET for a read-only frequency control.
    mov ecx,4
    mov r8,[rbp+4880]
    call .clock_request
    test eax,eax
    jnz .failed
    mov dword [r12+92],12
    lea rcx,[rbp+4504]             ; builder's four-byte LE payload
    mov r10d,2
    call .wire
    test eax,eax
    jnz .failed
    mov dword [r12+92],13
    call .get_frequency
    test eax,eax
    jnz .failed
    mov eax,[rbp+4512]
    cmp eax,[rbp+4880]
    jne .failed
.frequency_confirmed:
    test byte [r12+368+5],4
    jz .valid_clock
    mov dword [r12+92],14
    mov ecx,3
    xor r8d,r8d
    call .clock_request
    test eax,eax
    jnz .failed
    lea rcx,[rbp+4512]
    xor r10d,r10d
    call .wire
    test eax,eax
    jnz .failed
    cmp byte [rbp+4512],1
    jne .failed
.valid_clock:
    mov dword [r12+92],15
    mov eax,[r12+144+176]
    mov r10d,4
    call .set_interface
    test eax,eax
    jnz .failed
    call .get_interface
    test eax,eax
    jnz .failed
    movzx eax,byte [rbp+4512]
    cmp eax,[r12+144+176]
    jne .failed
    mov dword [rbp+4888],1       ; active-alt ratio must still match observed clock
    call .path_controls
    test eax,eax
    jnz .failed
    mov dword [r12+88],2           ; PREPARED != PCM running/healthy
    xor eax,eax
    jmp .out
.claim_stop:
    mov eax,2
    mov edx,1
    lock cmpxchg [r12+88],edx
    jne .invalid
    mov qword [rbp+4544],0
    mov dword [r12+92],16
    cmp r14,[r12+112]
    jne .failed
    mov rax,[rbp+4584]
    cmp rax,[r12+120]
    jne .failed
    ; Owner callback must confirm actual ISO stop before allowing this EP0 stop.
    ; A changed live alt belongs to retirement; do not overwrite another owner.
    call .get_interface
    test eax,eax
    jnz .failed
    movzx eax,byte [rbp+4512]
    cmp eax,[r12+144+176]
    jne .failed
    mov dword [r12+92],17
    xor eax,eax
    mov r10d,8
    call .set_interface
    test eax,eax
    jnz .failed
    mov dword [r12+92],18
    call .get_interface
    test eax,eax
    jnz .failed
    cmp byte [rbp+4512],0
    jne .failed
    mov dword [r12+88],3           ; verified alt0, no transfer/DMA reclamation claim
    xor eax,eax
    jmp .out
.failed:
    mov dword [r12+88],4           ; terminal: no retry, inverse or uncertain stop
.invalid:
    mov eax,-1
.out:
    add rsp,4928
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

.clock_path:
    ; Complete parser audited namespace and path: retain at most31 clock links.
    ; Each private8B entry: ID,type,numerator:u16,denominator:u16,reserved:u16.
    mov dword [rbp+4864],0
    mov rax,[r12+32]
    mov [rbp+4880],rax            ; root rate initially equals original PCM rate
    mov ecx,[r12+144+108]
    cmp ecx,1
    jb .path_bad
    cmp ecx,32
    ja .path_bad
    cmp dword [r12+144+124],0
    jne .path_links
    cmp ecx,1
    jne .path_bad
    xor eax,eax
    ret
.path_links:
    cmp dword [r12+144+124],3
    ja .path_bad
    dec ecx
    jz .path_bad
    mov [rbp+4864],ecx
    xor r10d,r10d
.path_next:
    movzx ecx,byte [r12+144+128+r10]
    mov r8d,[r12+144+196]
    add r8,rbp
    mov r9d,[r12+144+208]
    add r9,r8
.path_seek:
    cmp r8,r9
    jae .path_bad
    movzx eax,byte [r8]
    cmp eax,4
    jb .path_bad
    lea rdx,[r8+rax]
    cmp rdx,r9
    ja .path_bad
    cmp byte [r8+3],cl
    je .path_found
    mov r8,rdx
    jmp .path_seek
.path_found:
    cmp word [r8+1],0x0b24
    jne .path_multiplier
    cmp eax,8
    jne .path_bad
    cmp byte [r8+4],1
    jne .path_bad
    test byte [r8+6],1
    jz .path_bad
    movzx eax,byte [r12+144+129+r10]
    cmp [r8+5],al
    jne .path_bad
    jmp .path_save
.path_multiplier:
    cmp word [r8+1],0x0c24
    jne .path_bad
    cmp eax,7
    jne .path_bad
    cmp byte [r8+5],5             ; exact read-only numerator AND denominator
    jne .path_bad
    movzx eax,byte [r12+144+129+r10]
    cmp [r8+4],al
    jne .path_bad
.path_save:
    mov qword [rbp+4608+r10*8],0
    mov [rbp+4608+r10*8],cl
    mov al,[r8+2]
    mov [rbp+4609+r10*8],al
    inc r10d
    cmp r10d,[rbp+4864]
    jb .path_next
    xor eax,eax
    ret
.path_bad:
    mov eax,-1
    ret

.path_controls:
    sub rsp,8
    mov dword [rbp+4872],0
.controls_next:
    mov eax,[rbp+4872]
    cmp eax,[rbp+4864]
    jae .controls_done
    cmp byte [rbp+4609+rax*8],12
    je .controls_multiplier
    cmp dword [rbp+4888],0        ; unary selector stays exactly the accepted query
    jne .controls_advance
    mov dword [r12+92],19
    mov ecx,1
    mov edx,1
    call .path_request
    test eax,eax
    jnz .controls_bad
    cmp byte [rbp+4512],1
    jne .controls_bad
    jmp .controls_advance
.controls_multiplier:
    mov dword [r12+92],20
    cmp dword [rbp+4888],0
    je .numerator_request
    mov dword [r12+92],22
.numerator_request:
    mov ecx,1
    mov edx,2                    ; Layout2, unsigned16 little-endian
    call .path_request
    test eax,eax
    jnz .controls_bad
    movzx ecx,word [rbp+4512]
    test ecx,ecx
    jz .controls_bad
    mov eax,[rbp+4872]
    cmp dword [rbp+4888],0
    jne .numerator_compare
    mov [rbp+4610+rax*8],cx
    jmp .denominator_stage
.numerator_compare:
    cmp [rbp+4610+rax*8],cx
    jne .controls_bad
.denominator_stage:
    mov dword [r12+92],21
    cmp dword [rbp+4888],0
    je .denominator_request
    mov dword [r12+92],23
.denominator_request:
    mov ecx,2
    mov edx,2
    call .path_request
    test eax,eax
    jnz .controls_bad
    movzx ecx,word [rbp+4512]
    test ecx,ecx
    jz .controls_bad
    mov eax,[rbp+4872]
    cmp dword [rbp+4888],0
    jne .denominator_compare
    mov [rbp+4612+rax*8],cx
    ; Clock out = in*P/Q, so requested input clock = current requested*Q/P.
    ; Each internal clock must be integral and within the supported8k..192k.
    movzx r8d,word [rbp+4610+rax*8]
    mov rax,[rbp+4880]
    mul rcx                     ; <=192000*65535; full-width overflow checked
    test rdx,rdx
    jnz .controls_bad
    div r8                      ; P already nonzero; no truncation accepted
    test rdx,rdx
    jnz .controls_bad
    cmp rax,8000
    jb .controls_bad
    cmp rax,192000
    ja .controls_bad
    mov [rbp+4880],rax
    jmp .controls_advance
.denominator_compare:
    cmp [rbp+4612+rax*8],cx
    jne .controls_bad
.controls_advance:
    inc dword [rbp+4872]
    jmp .controls_next
.controls_done:
    xor eax,eax
    jmp .controls_out
.controls_bad:
    mov eax,-1
.controls_out:
    add rsp,8
    ret

.path_request:                    ; ECX control, EDX layout length; read-only
    sub rsp,8
    mov qword [rbp+4496],0
    mov word [rbp+4496],0x01a1
    shl ecx,8
    mov [rbp+4498],cx
    mov eax,[rbp+4872]
    movzx eax,byte [rbp+4608+rax*8]
    shl eax,8
    or eax,[r12+144+168]
    mov [rbp+4500],ax
    mov [rbp+4502],dx
    lea rcx,[rbp+4512]
    xor r10d,r10d                ; no selector/multiplier SET requests
    call .wire
    add rsp,8
    ret

.clock_request:                    ; ECX operation, R8 operand; build actual setup
    sub rsp,8
    lea rdi,[r12+368]
    mov esi,8
    mov edx,[r12+144+168]
    lea r9,[rbp+4496]
    call uac2_clock_request
    add rsp,8
    ret
.get_frequency:
    sub rsp,8
    mov ecx,2
    xor r8d,r8d
    call .clock_request
    test eax,eax
    jnz .frequency_out
    lea rcx,[rbp+4512]
    xor r10d,r10d
    call .wire
.frequency_out:
    add rsp,8
    ret
.get_interface:
    mov qword [rbp+4496],0
    mov word [rbp+4496],0x0a81
    mov eax,[r12+144+172]
    mov [rbp+4500],ax
    mov word [rbp+4502],1
    lea rcx,[rbp+4512]
    xor r10d,r10d
    jmp .wire
.set_interface:                    ; EAX alt, R10D attempted mutation bit
    mov qword [rbp+4496],0
    mov word [rbp+4496],0x0b01
    mov [rbp+4498],ax
    mov eax,[r12+144+172]
    mov [rbp+4500],ax
    lea rcx,[rbp+4512]
    jmp .wire
.wire:
    sub rsp,8
    mov [rbp+4552],rcx
    mov [rbp+4560],r10d
    movzx eax,word [rbp+4502]
    mov [rbp+4568],rax
    call .guard
    test eax,eax
    jnz .wire_out
    mov eax,[rbp+4560]
    or [r12+96],eax                ; attempted, including unknown completion
    mov dword [r12+100],1
    mov rdi,r13
    lea rsi,[rbp+4496]
    mov rdx,rbx
    mov rcx,[rbp+4552]
    mov r8,[rbp+4568]
    call r14                      ; same native HC EP0 transport as UAC1
    cmp rax,[rbp+4568]
    jne .wire_unknown
    mov dword [r12+100],0          ; exact ACK, even if later identity/time fails
    call .guard                   ; fresh time AFTER actual synchronous I/O
    jmp .wire_out
.wire_unknown:
    mov eax,-1
.wire_out:
    add rsp,8
    ret
.guard:
    sub rsp,40                    ; private topology16, aligned callback stack
    call .time
    test eax,eax
    jnz .guard_out
    mov rdi,r15
    mov rsi,r13
    mov rdx,rbx
    mov rcx,[r12+56]
    call [r12+80]                 ; trusted exclusive function/device lease
    test rax,rax
    jnz .guard_no
    mov rdi,r13
    call xhci_hc_generation
    cmp eax,[r12+56]
    jne .guard_no
    mov rdi,r13
    mov rsi,rbx
    mov rdx,rsp
    call [r12+120]
    test rax,rax
    jnz .guard_no
    cmp byte [rsp+usb_topo.speed],USB_SPEED_FULL
    jne .guard_no
    mov rax,[rsp]
    mov rdx,[rsp+8]
    cmp qword [rbp+4544],0
    je .compare_topology
    mov [r12+128],rax
    mov [r12+136],rdx
    mov qword [rbp+4544],0
    jmp .guard_time
.compare_topology:
    cmp rax,[r12+128]
    jne .guard_no
    cmp rdx,[r12+136]
    jne .guard_no
.guard_time:
    call .time                    ; callbacks consume the same original budget
    jmp .guard_out
.guard_no:
    mov eax,-1
.guard_out:
    add rsp,40
    ret
.time:
    sub rsp,8
    call [r12+72]                 ; trusted monotonic microseconds, no host fiction
    cmp rax,[r12+104]
    jb .time_no
    cmp rax,[r12+64]
    jae .time_no
    mov rdx,[r12+64]
    sub rdx,rax
    cmp rdx,10000000              ; bounded admission, never renew on stop
    ja .time_no
    mov [r12+104],rax
    xor eax,eax
    jmp .time_out
.time_no:
    mov eax,-1
.time_out:
    add rsp,8
    ret
