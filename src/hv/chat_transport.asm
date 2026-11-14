;; MODULE hv/chat_transport
;; LAYER 5
;; PURPOSE Bounded app-only PCHAT byte delivery and untrusted result quarantine.
;; EXPORTS chat_vm_offer, chat_vm_status, chat_vm_cancel, chat_vm_result_copy, chat_vm_retire, chat_vm_pio
;; IMPORTS hv/app_vm, hv/app_vm_boot, hv/guest_request, core/time, core/smp, sec/session, core/lib/sha256
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Codex / rc-vm-claude. No guest send verb, grant, privacy bit or provider.
; SEC spends its exact human Send capsule BEFORE offer; native APIs accept
; trusted mapped pointers only. Successful transport is not answer publication.
CH_FRAME_MAX equ 45288
CH_RESULT_MAX equ 96+65536+8192
CH_BUDGET_US equ 130000000

; RDI native descriptor64: version1, invocation, original instance, frame ptr,
; frame bytes, original binding48 ptr, original app128 ptr, reserved0 ->1/0.
; Captures only one request; invocation floor survives all retire/clear paths.
chat_vm_offer:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    cmp byte [rel ch_busy],0
    jne .bad
    call ch_guard
    test eax,eax
    jz .bad
    cmp qword [rel ch_state],0
    jne .bad
    mov rdi,rbx
    mov esi,64
    call ch_disjoint
    test eax,eax
    jz .bad
    cmp qword [rbx],1
    jne .bad
    cmp qword [rbx+56],0
    jne .bad
    mov r12,[rbx+8]
    test r12,r12
    jz .bad
    cmp r12,-1
    je .bad
    cmp r12,[rel ch_floor]
    jbe .bad
    mov r13,[rbx+32]
    cmp r13,65
    jb .bad
    cmp r13,CH_FRAME_MAX
    ja .bad
    mov rdi,[rbx+24]
    mov rsi,r13
    call ch_disjoint
    test eax,eax
    jz .bad
    mov rdi,[rbx+40]
    mov esi,48
    call ch_disjoint
    test eax,eax
    jz .bad
    mov rdi,[rbx+48]
    mov esi,128
    call ch_disjoint
    test eax,eax
    jz .bad
    mov byte [rel ch_busy],1
    mov [rel ch_invocation],r12
    mov rax,[rbx+16]
    mov [rel ch_instance],rax
    mov [rel ch_frame_bytes],r13
    mov rsi,[rbx+40]
    lea rdi,[rel ch_binding]
    mov ecx,6
    cld
    rep movsq
    mov rsi,[rbx+48]
    lea rdi,[rel ch_app]
    mov ecx,16
    rep movsq
    mov rsi,[rbx+24]
    lea rdi,[rel ch_frame]
    mov rcx,r13
    rep movsb
    mov rax,0x0031305441484350    ; PCHAT01\0
    cmp [rel ch_frame],rax
    jne .clear_bad
    cmp dword [rel ch_frame+8],1
    jne .clear_bad                   ; no cloud delivery or fallback
    cmp qword [rel ch_frame+40],1
    jne .clear_bad
    cmp r12,[rel ch_frame+16]
    jne .clear_bad
    cmp qword [rel ch_frame+48],0
    jne .clear_bad
    cmp qword [rel ch_frame+56],0
    jne .clear_bad
    mov eax,[rel ch_frame+12]
    dec eax
    cmp eax,255
    ja .clear_bad
    mov rax,[rel ch_frame+24]
    test rax,rax
    jz .clear_bad
    cmp rax,4096
    ja .clear_bad
    mov rdx,[rel ch_frame+32]
    test rdx,rdx
    jz .shape
    cmp rdx,168
    jb .clear_bad
    cmp rdx,41128
    ja .clear_bad
.shape:
    add rax,rdx
    add rax,64                      ; operands already bounded, no wrap
    cmp rax,r13
    jne .clear_bad
    call ch_current
    test eax,eax
    jz .clear_bad
    lea rdi,[rel ch_hash]
    lea rsi,[rel ch_frame]
    mov rdx,r13
    call sha256_hash
    test rax,rax
    jnz .clear_bad
    call ch_current
    test eax,eax
    jz .clear_bad
    call time_monotonic_now_us
    add rax,CH_BUDGET_US
    jc .clear_bad
    mov [rel ch_deadline],rax
    mov [rel ch_floor],r12           ; burn before first possible delivery
    mov qword [rel ch_state],1
    mov byte [rel ch_busy],0
    mov eax,1
    jmp .out
.clear_bad:
    call chat_vm_retire
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

ch_guard:
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Original full native proofs; never refresh/rebind/borrow current identity.
ch_current:
    push rbx
    call ch_guard
    test eax,eax
    jz .bad
    call app_vm_boot_current
    cmp eax,1
    jne .bad
    mov rdi,[rel ch_instance]
    call app_vm_status
    cmp eax,4                       ; actual RUNNING, not READY/driver
    jne .bad
    mov rdi,[rel ch_binding+16]
    mov esi,[rel ch_binding+24]
    lea rdx,[rel ch_check_binding]
    mov ecx,48
    call guest_request_binding_copy
    cmp eax,1
    jne .bad
    lea rdi,[rel ch_binding]
    lea rsi,[rel ch_check_binding]
    mov ecx,6
    cld
    repe cmpsq
    jne .bad
    mov rdi,[rel ch_instance]
    lea rsi,[rel ch_check_app]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .bad
    lea rdi,[rel ch_app]
    lea rsi,[rel ch_check_app]
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Trusted mapped pointer RDI,size RSI ->1/0; no alias of any portal state.
ch_disjoint:
    test rdi,rdi
    jz .bad
    test rsi,rsi
    jz .bad
    mov rax,rdi
    add rax,rsi
    jc .bad
    lea rdx,[rel ch_floor]
    cmp rax,rdx
    jbe .ok
    lea rdx,[rel ch_end]
    cmp rdi,rdx
    jb .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Native original invocation ->state0/1offered/2delivered/3cancel/4quarantine,
; -1 unavailable. No state or receipt authorizes display/action/send.
chat_vm_status:
    push rbx
    mov rbx,rdi
    call ch_guard
    test eax,eax
    jz .bad
    cmp rbx,[rel ch_invocation]
    jne .bad
    cmp qword [rel ch_state],0
    je .bad
    call ch_current
    test eax,eax
    jz .retire
    call ch_expiry
    mov rax,[rel ch_state]
    pop rbx
    ret
.retire:
    call chat_vm_retire
.bad:
    mov rax,-1
    pop rbx
    ret

; Local native cancel only. Never reopen/refund the SEC capsule or old frame.
chat_vm_cancel:
    push rbx
    mov rbx,rdi
    call ch_guard
    test eax,eax
    jz .bad
    cmp rbx,[rel ch_invocation]
    jne .bad
    cmp qword [rel ch_state],0
    je .bad
    call ch_cancel
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret
ch_expiry:
    call time_monotonic_now_us
    cmp rax,[rel ch_deadline]
    jb .out
    call ch_cancel
.out:
    ret
ch_cancel:
    mov qword [rel ch_state],3
    mov qword [rel ch_frame_bytes],0
    mov qword [rel ch_cursor],0
    mov qword [rel ch_result_bytes],0
    mov qword [rel ch_received],0
    lea rdi,[rel ch_frame]
    xor eax,eax
    mov ecx,CH_FRAME_MAX+CH_RESULT_MAX
    cld
    rep stosb
    ret

; Copy raw quarantine only, NEVER an answer/publication permit. SEC/INPUT must
; validate actual receipts and original human capsule before using text.
; RDI invocation,RSI offset,RDX trusted mapped out,RCX bytes ->0/-1.
chat_vm_result_copy:
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    call ch_guard
    test eax,eax
    jz .bad
    cmp byte [rel ch_busy],0
    jne .bad
    cmp rbx,[rel ch_invocation]
    jne .bad
    cmp qword [rel ch_state],4
    jne .bad
    mov rdi,r13
    mov rsi,r14
    call ch_disjoint
    test eax,eax
    jz .bad
    mov rax,r12
    add rax,r14
    jc .bad
    cmp rax,[rel ch_result_bytes]
    ja .bad
    call ch_current
    test eax,eax
    jz .retire_bad
    call time_monotonic_now_us
    cmp rax,[rel ch_deadline]
    jae .retire_bad
    mov byte [rel ch_busy],1
    lea rsi,[rel ch_result]
    add rsi,r12
    mov rdi,r13
    mov rcx,r14
    cld
    rep movsb
    call ch_current
    test eax,eax
    jz .zero_bad
    call time_monotonic_now_us
    cmp rax,[rel ch_deadline]
    jae .zero_bad
    mov byte [rel ch_busy],0
    xor eax,eax
    jmp .out
.zero_bad:
    mov rdi,r13
    mov rcx,r14
    xor eax,eax
    cld
    rep stosb
.retire_bad:
    call chat_vm_retire
.bad:
    mov eax,-1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Actual normalized PIO qualification EDI/guest EAX ESI ->claimed EAX/IN EDX.
; 5070 IN32 frame length / OUT32 response length or commit1/cancelACK2/fail3;
; 5074 IN8 request / OUT8 result; 5078 IN32 state. No seeks or guest pointers.
chat_vm_pio:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12d,esi
    mov r13d,edi
    shr r13d,16
    cmp r13d,0x5070
    je .ours
    cmp r13d,0x5074
    je .ours
    cmp r13d,0x5078
    jne .unrelated
.ours:
    call ch_guard
    test eax,eax
    jz .refuse
    cmp byte [rel ch_busy],0
    jne .refuse
    cmp byte [rel avm_exit_open],1
    jne .refuse
    call app_vm_exit_endpoint
    test rax,rax
    jz .retire
    cmp qword [rel ch_state],0
    je .idle
    cmp rax,[rel ch_binding+16]
    jne .retire
    cmp edx,[rel ch_binding+24]
    jne .retire
    call ch_current
    test eax,eax
    jz .retire
    call ch_expiry
.idle:
    mov eax,ebx
    and eax,0xffff
    and eax,~0x40
    cmp r13d,0x5074
    je .byte
    cmp eax,11
    je .input
    cmp eax,3
    jne .retire
    cmp r13d,0x5070
    jne .retire
    cmp qword [rel ch_state],3
    je .cancelled
    cmp qword [rel ch_state],2
    jne .refuse
    cmp r12d,1
    je .commit
    cmp qword [rel ch_result_bytes],0
    jne .retire
    cmp r12d,96
    jb .retire
    cmp r12d,CH_RESULT_MAX
    ja .retire
    mov [rel ch_result_bytes],r12
    jmp .zero
.cancelled:
    cmp r12d,2
    je .retire_zero                ; guest asserts actual adapter reaped
    cmp r12d,3
    jne .refuse
    mov byte [rel avm_dispatch_fault],1 ; existing VM retirement on failed reap
    jmp .retire_zero
.input:
    cmp r13d,0x5078
    je .state
    xor edx,edx
    cmp qword [rel ch_state],1
    jne .claimed
    mov edx,[rel ch_frame_bytes]
    jmp .claimed
.state:
    mov edx,[rel ch_state]
    jmp .claimed
.byte:
    cmp eax,8
    je .read
    test eax,eax
    jnz .retire
    cmp qword [rel ch_state],2
    jne .refuse
    mov rax,[rel ch_received]
    cmp rax,[rel ch_result_bytes]
    jae .retire
    lea rdx,[rel ch_result]
    mov [rdx+rax],r12b
    inc qword [rel ch_received]
    jmp .zero
.read:
    cmp qword [rel ch_state],1
    jne .refuse
    mov rax,[rel ch_cursor]
    cmp rax,[rel ch_frame_bytes]
    jae .retire
    lea rdx,[rel ch_frame]
    movzx edx,byte [rdx+rax]
    inc qword [rel ch_cursor]
    inc rax
    cmp rax,[rel ch_frame_bytes]
    jne .claimed
    mov qword [rel ch_state],2      ; exact frame/EOF handed off only once
    lea rdi,[rel ch_frame]
    mov ecx,CH_FRAME_MAX
    xor eax,eax
    cld
    rep stosb                      ; retain only original hash and identity
    jmp .claimed
.commit:
    mov rax,[rel ch_result_bytes]
    cmp rax,96
    jb .retire
    cmp rax,[rel ch_received]
    jne .retire
    mov rax,0x0000313053524350        ; PCRS01\0\0
    cmp [rel ch_result],rax
    jne .retire
    mov rax,[rel ch_invocation]
    cmp rax,[rel ch_result+8]
    jne .retire
    cmp dword [rel ch_result+16],1
    jne .retire
    cmp dword [rel ch_result+20],255
    ja .retire
    mov rax,[rel ch_result+24]
    cmp rax,65536
    ja .retire
    mov rdx,[rel ch_result+32]
    cmp rdx,8192
    ja .retire
    add rax,rdx
    add rax,96
    cmp rax,[rel ch_result_bytes]
    jne .retire
    cmp qword [rel ch_result+72],1    ; untrusted bridge complete annotation
    ja .retire
    cmp qword [rel ch_result+80],0
    jne .retire
    cmp qword [rel ch_result+88],0
    jne .retire
    lea rdi,[rel ch_result+40]
    lea rsi,[rel ch_hash]
    mov ecx,32
    cld
    repe cmpsb
    jne .retire
    mov qword [rel ch_state],4      ; quarantine, no UI effect/grant/verb
.zero:
    xor edx,edx
.claimed:
    mov eax,1
    jmp .out
.retire_zero:
    call chat_vm_retire
    jmp .zero
.retire:
    cmp qword [rel ch_state],0
    je .erase
    mov byte [rel avm_dispatch_fault],1 ; protocol/identity loss cannot leave an old child
.erase:
    call chat_vm_retire
.refuse:
    mov edx,-1
    jmp .claimed
.unrelated:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Existing guest_request transport retirement invokes this leaf. Preserve all
; registers/flags, clear bytes and identity; never reset the invocation floor.
chat_vm_retire:
    pushfq
    push rax
    push rcx
    push rdi
    lea rdi,[rel ch_begin]
    mov ecx,ch_end-ch_begin
    xor eax,eax
    cld
    rep stosb
    pop rdi
    pop rcx
    pop rax
    popfq
    ret

%include "core/abi/wdata.inc"
%macro WDATA_chat_transport 0
alignb 8
ch_floor: resq 1
ch_begin:
ch_state: resq 1
ch_busy: resb 1
alignb 8
ch_invocation: resq 1
ch_instance: resq 1
ch_deadline: resq 1
ch_frame_bytes: resq 1
ch_cursor: resq 1
ch_result_bytes: resq 1
ch_received: resq 1
ch_binding: resb 48
ch_app: resb 128
ch_check_binding: resb 48
ch_check_app: resb 128
ch_hash: resb 32
ch_frame: resb CH_FRAME_MAX
ch_result: resb CH_RESULT_MAX
ch_end:
%endmacro
WDATA_BSS_DEFER WDATA_chat_transport
