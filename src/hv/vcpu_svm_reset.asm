;; MODULE hv/vcpu_svm_reset
;; LAYER 5
;; EXPORTS vcpu_svm_reset_at, vcpu_svm_sipi_at
;; IMPORTS
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Owned virtual INIT/SIPI images, no entry.
; IF0/DF0, both cores root, all executors closed, no live VMRUN on this VMCB.
; Caller owns/serializes context, 4K VMCB, 120B GPR image, 16B startup record.
; Startup record: qword activity (0 active,1 HLT,3 wait-SIPI), qword generation.
; Native host addresses are trusted/mapped outside NPT. No globals/privilege.
; This helper does not reset separate xstate/LAPIC/deferred records or grant GO.
%include "hv/vcpu_svm.inc"

; RDI lifetime context, RSI GPR image, RDX startup record -> EAX1/0.
; A completed refusal changes no byte. Generation never wraps. All controls
; stay exact except dirty/flush, interrupt request/shadow, stale exit/decode.
; Guest PAT stays at the frozen profile value across virtual INIT, as on VMX.
vcpu_svm_reset_at:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    test r12, r12
    jz .bad
    test r13, r13
    jz .bad
    test r14, r14
    jz .bad
    cmp qword [r12 + VSP_LIVE], 1
    ja .bad
    cmp qword [r12 + VSP_ACTIVE], 0
    jne .bad
    cmp qword [r12 + VSP_FAULT], 0
    jne .bad
    mov r15, [r12 + VSP_VMCB]
    test r15, r15
    jz .bad
    test r15d, 4095
    jnz .bad
    cmp qword [r14 + 8], -1
    je .bad
    mov rax, [r14]
    cmp rax, 3
    ja .bad
    cmp rax, 2                        ; no invented software activity
    je .bad
    ; Pairwise nonoverlap of all four complete ranges, including overflow.
    mov r8, r12
    mov r9d, VSP_SIZE
    mov r10, r13
    mov r11d, 120
    call vsy_disjoint
    test eax, eax
    jz .bad
    mov r10, r14
    mov r11d, 16
    call vsy_disjoint
    test eax, eax
    jz .bad
    mov r10, r15
    mov r11d, 4096
    call vsy_disjoint
    test eax, eax
    jz .bad
    mov r8, r13
    mov r9d, 120
    mov r10, r14
    mov r11d, 16
    call vsy_disjoint
    test eax, eax
    jz .bad
    mov r10, r15
    mov r11d, 4096
    call vsy_disjoint
    test eax, eax
    jz .bad
    mov r8, r14
    mov r9d, 16
    call vsy_disjoint
    test eax, eax
    jz .bad
    ; All refusals precede the first write. No copy of old guest save bytes.
    mov rbx, [r15 + 0x668]            ; PAT belongs to the profile, not INIT
    lea rdi, [r15 + 0x400]
    xor eax, eax
    mov ecx, 0x400 / 8
    cld
    rep stosq
    mov rdi, r13
    mov ecx, 15
    rep stosq
    ; Six data/code segment images. Real mode, 64 KiB limits, zero bases.
    lea rdi, [r15 + 0x400]
    mov ecx, 6
.seg:
    mov word [rdi + 2], 0x92
    mov dword [rdi + 4], 0xFFFF
    add rdi, 16
    loop .seg
    mov word [r15 + 0x412], 0x9A     ; CS executable/readable, real mode
    mov dword [r15 + 0x464], 0xFFFF ; GDTR
    mov word [r15 + 0x472], 0x82     ; LDTR, present LDT
    mov dword [r15 + 0x474], 0xFFFF
    mov dword [r15 + 0x484], 0xFFFF ; IDTR
    mov word [r15 + 0x492], 0x83     ; TR, present busy16-bit TSS
    mov dword [r15 + 0x494], 0xFFFF
    mov qword [r15 + 0x4D0], 1 << 12 ; SVM's hardware SVME, guest policy hides it
    mov qword [r15 + 0x558], 0x60000010
    mov qword [r15 + 0x560], 0x400
    mov dword [r15 + 0x568], 0xFFFF0FF0
    mov qword [r15 + 0x570], 2
    mov [r15 + 0x668], rbx
    mov byte [r15 + 0x05C], 1        ; global ASID flush on the next VMRUN
    mov qword [r15 + 0x060], 1 << 24 ; keep virtual masking, cancel requests
    mov qword [r15 + 0x068], 0
    mov qword [r15 + 0x070], 0
    mov qword [r15 + 0x078], 0
    mov qword [r15 + 0x080], 0
    mov qword [r15 + 0x088], 0
    mov qword [r15 + 0x0A8], 0
    mov dword [r15 + 0x0C0], 0       ; every field must reload
    mov qword [r15 + 0x0C8], 0
    mov qword [r15 + 0x0D0], 0       ; decode-assist length and bytes
    mov qword [r15 + 0x0D8], 0
    inc qword [r14 + 8]
    mov qword [r14], 3               ; publish wait-SIPI only after complete reset
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI lifetime context, RSI startup record, EDX vector0..255 -> EAX1/0.
; This is only the virtual SIPI transition; no physical IPI or guest entry.
vcpu_svm_sipi_at:
    test rdi, rdi
    jz .bad
    test rsi, rsi
    jz .bad
    cmp edx, 255
    ja .bad
    cmp qword [rdi + VSP_LIVE], 1
    ja .bad
    cmp qword [rdi + VSP_ACTIVE], 0
    jne .bad
    cmp qword [rdi + VSP_FAULT], 0
    jne .bad
    cmp qword [rsi], 3
    jne .bad
    cmp qword [rsi + 8], 0
    je .bad                          ; no SIPI before any owned reset
    mov rax, [rdi + VSP_VMCB]
    test rax, rax
    jz .bad
    test eax, 4095
    jnz .bad
    ; Leaf range checks use only scratch GPRs; preserve input context/record.
    mov r8, rdi
    mov r9d, VSP_SIZE
    mov r10, rsi
    mov r11d, 16
    push rax
    push rdx
    sub rsp, 8
    call vsy_disjoint
    test eax, eax
    jz .bad_stack
    mov r10, [rsp + 16]
    mov r11d, 4096
    call vsy_disjoint
    test eax, eax
    jz .bad_stack
    mov r8, rsi
    mov r9d, 16
    call vsy_disjoint
    test eax, eax
    jz .bad_stack
    add rsp, 8
    pop rdx
    pop rax
    mov ecx, edx
    shl ecx, 8
    mov [rax + 0x410], cx
    shl edx, 12
    mov [rax + 0x418], rdx
    mov qword [rax + 0x578], 0
    mov qword [rax + 0x068], 0
    mov dword [rax + 0x0C0], 0
    mov qword [rsi], 0               ; activity LAST, exact startup generation
    mov eax, 1
    ret
.bad_stack:
    add rsp, 24
.bad:
    xor eax, eax
    ret

; R8 start/R9 size, R10 start/R11 size; only RAX/RCX/flags changed. EAX1/0.
vsy_disjoint:
    mov rax, r8
    add rax, r9
    jc .bad
    mov rcx, r10
    add rcx, r11
    jc .bad
    cmp rax, r10
    jbe .ok
    cmp rcx, r8
    jbe .ok
.bad:
    xor eax, eax
    ret
.ok:
    mov eax, 1
    ret
