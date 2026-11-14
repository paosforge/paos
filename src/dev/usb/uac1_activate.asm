;; MODULE dev/usb/uac1_activate
;; LAYER 3
;; EXPORTS uac1_fs_activate, uac1_fs_activate_deadline
;; IMPORTS boot/native_driver_gate, dev/usb/uac1_function, dev/usb/xhci, core/time
;; CAPS
;; OWNER rc-codex-av
%include "boot/native_driver_gate.inc"
; Explicit, serialized USB-class caller owns the addressed device/interface.
; RDI native xHCI dev*, RSI neutral address1..255, RDX function selector,
; RCX sample rate, R8 channels, R9 mapped writable192B receipt. EAX0/-1.
; Receipt: candidate128B; u32 attempted stage/mutation mask/success/address;
; u64 HC; u32 generation/reserved; topology16B; remaining16B reserved.
; No global registration, retries, rollback or implicit ownership transfer.
; A mutation bit means attempted (possibly unknown), never verified completion.
; Failed receipt remains for caller's ordinary device retirement/recovery.
uac1_fs_activate:
    NATIVE_DRIVER_REFUSE 7
    xor r10d,r10d
    xor r11d,r11d
    xor eax,eax                     ; compatible direct caller: no clock policy
    jmp uac1_fs_activate_common
; Same six arguments, plus SysV stack arguments7=original absolute us deadline,
; 8=expected native generation (full-width u32, excluding unavailable -1).
; Bounded native owner retains serialization/custody. No budget renewal or
; retry/cleanup follows an unknown or late reply. Legacy entry is unchanged.
uac1_fs_activate_deadline:
    NATIVE_DRIVER_REFUSE 7
    mov r10,[rsp+8]
    mov r11,[rsp+16]
    mov eax,1
uac1_fs_activate_common:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,4360                    ; config4096 + private parser/topology/guards
    mov rbp,rsp                     ; aligned calls, <6KiB including parser
    mov r12,rdi
    mov r13,rsi
    mov r14,r9
    mov [rbp+4280],rdx
    mov [rbp+4288],rcx
    mov [rbp+4296],r8
    mov [rbp+4328],r10              ; immutable original deadline
    mov [rbp+4312],r11              ; immutable expected generation
    mov [rbp+4344],eax              ; bounded entry, separate from deadline0
    mov qword [rbp+4336],0          ; last checked native monotonic us
    ; Invalid scalars/receipt/handle spans do not touch caller memory or EP0.
    cmp rsi,1
    jb .invalid
    cmp rsi,255
    ja .invalid
    cmp rdx,0x1ffff
    ja .invalid
    test edx,0xff00
    jz .invalid
    cmp rcx,8000
    jb .invalid
    cmp rcx,192000
    ja .invalid
    cmp r8,1
    jb .invalid
    cmp r8,2
    ja .invalid
    test r9,r9
    jz .invalid
    lea rax,[r9+191]
    cmp rax,r9
    jb .invalid
    shr rax,47
    jnz .invalid
    test rdi,rdi
    jz .invalid
    lea rax,[rdi+dev_size-1]
    cmp rax,rdi
    jb .invalid
    shr rax,47
    jnz .invalid
    ; Never let receipt initialization overwrite the HC or its vtable.
    lea rax,[rdi+dev_size]
    cmp r9,rax
    jae .handle_disjoint
    lea rax,[r9+192]
    cmp rdi,rax
    jb .invalid
.handle_disjoint:
    mov rbx,[rdi+dev.ops]
    test rbx,rbx
    jz .invalid
    lea rax,[rbx+usbhc_ops_size-1]
    cmp rax,rbx
    jb .invalid
    shr rax,47
    jnz .invalid
    lea rax,[rbx+usbhc_ops_size]
    cmp r9,rax
    jae .ops_disjoint
    lea rax,[r9+192]
    cmp rbx,rax
    jb .invalid
.ops_disjoint:
    mov r15,[rbx+usbhc_ops.control]
    test r15,r15
    jz .invalid
    mov rax,[rbx+usbhc_ops.topology]
    test rax,rax
    jz .invalid
    mov [rbp+4320],rax
    cmp dword [rbp+4344],0
    je .admitted
    cmp qword [rbp+4328],0
    je .invalid
    mov rax,[rbp+4312]
    shr rax,32
    jnz .invalid
    cmp dword [rbp+4312],-1
    je .invalid
    call .clock
    jc .invalid
    mov rax,[rbp+4328]
    sub rax,[rbp+4336]
    cmp rax,10000000                ; bounded admitted remaining time, no renewal
    ja .invalid
.admitted:
    mov rdi,r14
    xor eax,eax
    mov ecx,24
    cld
    rep stosq
    mov [r14+140],r13d
    mov [r14+144],r12
    mov dword [r14+128],1
    mov rdi,r12
    call xhci_hc_generation
    cmp eax,-1
    je .no
    mov [r14+152],eax
    call .guard
    jc .no
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rbp+4224]
    call [rbp+4320]
    test rax,rax
    jnz .no
    call .guard
    jc .no
    cmp byte [rbp+4224+usb_topo.speed],USB_SPEED_FULL
    jne .no
    ; Header then exact bounded complete config, index zero only.
    mov dword [r14+128],2
    mov qword [rbp+4256],0
    mov word [rbp+4256],0x0680
    mov word [rbp+4258],0x0200
    mov word [rbp+4262],9
    lea rcx,[rbp]
    call .control
    cmp rax,9
    jne .no
    cmp word [rbp],0x0209
    jne .no
    movzx eax,word [rbp+2]
    cmp eax,9
    jb .no
    cmp eax,4096
    ja .no
    mov [rbp+4304],rax
    mov [rbp+4262],ax
    mov dword [r14+128],3
    lea rcx,[rbp]
    call .control
    cmp rax,[rbp+4304]
    jne .no
    mov dword [r14+128],4
    lea rdi,[rbp]
    mov rsi,[rbp+4304]
    mov rdx,[rbp+4280]
    mov rcx,[rbp+4288]
    mov r8,[rbp+4296]
    lea r9,[rbp+4096]
    call uac1_fs_function_parse
    test eax,eax
    jnz .no
    ; No sampling control: only one discrete rate proves current frequency.
    test dword [rbp+4096+44],1
    jnz .rate_supported
    mov eax,[rbp+4096+80]             ; complete config-relative AS start
    cmp byte [rbp+rax+23],1
    jne .no
.rate_supported:
    lea rsi,[rbp+4096]
    mov rdi,r14
    mov ecx,16
    rep movsq
    ; Preserve an already-active matching config, including composite HID.
    mov dword [r14+128],5
    mov qword [rbp+4256],0
    mov word [rbp+4256],0x0880        ; GET_CONFIGURATION
    mov word [rbp+4262],1
    lea rcx,[rbp+4264]
    call .control
    cmp rax,1
    jne .no
    movzx eax,byte [rbp+4264]
    cmp eax,[r14+64]
    je .configured
    test eax,eax
    jnz .no                          ; never reset a different live config
    mov dword [r14+128],6
    mov qword [rbp+4256],0
    mov word [rbp+4256],0x0900        ; SET_CONFIGURATION (only from zero)
    mov eax,[r14+64]
    mov [rbp+4258],ax
    xor ecx,ecx
    call .control
    test rax,rax
    jnz .no
    mov dword [r14+128],7
    mov qword [rbp+4256],0
    mov word [rbp+4256],0x0880
    mov word [rbp+4262],1
    lea rcx,[rbp+4264]
    call .control
    cmp rax,1
    jne .no
    movzx eax,byte [rbp+4264]
    cmp eax,[r14+64]
    jne .no
.configured:
    mov dword [r14+128],8
    mov qword [rbp+4256],0
    mov word [rbp+4256],0x0a81        ; GET_INTERFACE, selected AS only
    mov eax,[r14]
    mov [rbp+4260],ax
    mov word [rbp+4262],1
    lea rcx,[rbp+4264]
    call .control
    cmp rax,1
    jne .no
    cmp byte [rbp+4264],0
    jne .no                          ; no rebinding an active/unknown owner
    mov dword [r14+128],9
    mov qword [rbp+4256],0
    mov word [rbp+4256],0x0b01        ; SET_INTERFACE
    mov eax,[r14+4]
    mov [rbp+4258],ax
    mov eax,[r14]
    mov [rbp+4260],ax
    xor ecx,ecx
    call .control
    test rax,rax
    jnz .no
    mov dword [r14+128],10
    mov word [rbp+4256],0x0a81
    mov word [rbp+4258],0
    mov word [rbp+4262],1
    lea rcx,[rbp+4264]
    call .control
    cmp rax,1
    jne .no
    movzx eax,byte [rbp+4264]
    cmp eax,[r14+4]
    jne .no
    test dword [r14+44],1
    jz .recheck
    mov dword [r14+128],11
    mov qword [rbp+4256],0
    mov word [rbp+4256],0x0122        ; class endpoint SET_CUR SAMPLING_FREQ
    mov word [rbp+4258],0x0100
    mov eax,[r14+12]
    mov [rbp+4260],ax
    mov word [rbp+4262],3
    mov eax,[r14+24]
    mov [rbp+4264],eax
    lea rcx,[rbp+4264]
    call .control
    cmp rax,3                        ; shared HC OUT ABI returns data bytes
    jne .no
    mov dword [r14+128],12
    mov word [rbp+4256],0x81a2        ; class endpoint GET_CUR
    mov qword [rbp+4264],0
    lea rcx,[rbp+4264]
    call .control
    cmp rax,3
    jne .no
    mov eax,[rbp+4264]
    and eax,0x00ffffff
    cmp eax,[r14+24]
    jne .no
.recheck:
    mov dword [r14+128],13
    call .guard
    jc .no
    mov rdi,r12
    call xhci_hc_generation
    cmp eax,[r14+152]
    jne .no
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rbp+4240]
    call [rbp+4320]
    test rax,rax
    jnz .no
    call .guard
    jc .no
    lea rsi,[rbp+4224]
    lea rdi,[rbp+4240]
    mov ecx,2
    repe cmpsq
    jne .no
    lea rsi,[rbp+4240]
    lea rdi,[r14+160]
    mov ecx,2
    rep movsq
    mov dword [r14+128],14
    call .guard
    jc .no
    or dword [r14+132],8
    mov eax,[r14+80]
    add eax,[r14+52]                 ; AS start + endpoint relative offset
    lea rdx,[rbp+rax]
    mov rdi,r12
    mov rsi,r13
    call xhci_iso_fs_configure
    test rax,rax
    jnz .no
    call .guard
    jc .no
    mov dword [r14+128],15
    mov dword [r14+136],1
    xor eax,eax
    jmp .out
.no:
.invalid:
    mov eax,-1
.out:
    add rsp,4360
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.control:
    sub rsp,8
    mov [rbp+4352],rcx
    call .guard
    jc .control_bad
    ; Only submission sets attempted mutation bits; a pre-call refusal does not.
    mov eax,[r14+128]
    cmp eax,6
    jne .not_config
    or dword [r14+132],1
.not_config:
    cmp eax,9
    jne .not_alt
    or dword [r14+132],2
.not_alt:
    cmp eax,11
    jne .not_rate
    or dword [r14+132],4
.not_rate:
    mov rdi,r12
    lea rsi,[rbp+4256]
    mov rdx,r13
    movzx r8d,word [rbp+4262]
    mov rcx,[rbp+4352]
    call r15
    mov [rbp+4352],rax
    call .guard
    jc .control_bad
    mov rax,[rbp+4352]
    add rsp,8
    ret
.control_bad:
    mov rax,-1
    add rsp,8
    ret
.guard:
    cmp dword [rbp+4344],0
    je .guard_ok
    sub rsp,8
    mov rdi,r12
    call xhci_hc_generation
    cmp eax,[rbp+4312]
    jne .guard_bad
    call .clock
    jc .guard_bad
    ; Clock sampling can cross a controller incarnation. Refuse before the
    ; next native callback or publishing a successful activation receipt.
    mov rdi,r12
    call xhci_hc_generation
    cmp eax,[rbp+4312]
    jne .guard_bad
    add rsp,8
.guard_ok:
    clc
    ret
.guard_bad:
    add rsp,8
    stc
    ret
.clock:
    sub rsp,8
    call time_monotonic_now_us
    cmp rax,[rbp+4336]
    jb .clock_bad
    cmp rax,[rbp+4328]
    jae .clock_bad
    mov [rbp+4336],rax
    add rsp,8
    clc
    ret
.clock_bad:
    add rsp,8
    stc
    ret
