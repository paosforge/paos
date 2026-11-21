;; MODULE hv/tools_vm_seed
;; LAYER 5
;; EXPORTS tools_vm_seed
;; IMPORTS hv/tools_vm_memory, core/csprng
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Claude / rc-vm-claude. Tools D4c (T6, SEC 121319 E1-E3): the boot
; entropy for a tools load is one Linux setup_data SETUP_RNG_SEED record whose
; 64 bytes come from the native CSPRNG, drawn fresh by this call.
; - E1: one draw per record, written only after the T1 scrub completed, into
;   a still-zero 80-byte span of this load's own RAM (tools_vm_gpa against the
;   original START/token). Nothing is kept, so no seed survives a restart or
;   replacement. Linking the record into boot_params.setup_data, and the chain
;   check, belong to the image stage that owns boot_params; this leaf returns
;   the GPA to link.
; - E2: a CSPRNG refusal (pool not ready, unhealthy, reseed limit) returns 0.
;   csprng_generate zeroes its output on refusal and no header is written, so
;   no record exists, zero-filled or otherwise. The image-stage caller retires
;   the load through the one retire path; there is no fallback source.
; - E3: there is no native staging copy. The CSPRNG writes straight into the
;   guest span, and this module keeps no storage, logs and publishes nothing.
; Stopped-loader leaf like tools_vm_initrd: no boot completion or state change.
%include "hv/tools_vm.inc"

TVM_SEED_BYTES equ 64
TVM_SEED_RECORD equ 16 + TVM_SEED_BYTES   ; setup_data: next, type, len, data
TVM_SETUP_RNG_SEED equ 9

; Original RDI=START, RSI=token, RDX=own 8-aligned GPA ->RAX=GPA /0. A refusal
; leaves the span unchanged except where a refused draw zeroes its 64 bytes,
; which were already zero.
tools_vm_seed:
    cmp qword [rel tvm_state],TVM_LOADING
    jne .bad
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    mov rbx,rdx
    call tvm_memory_stopped
    test eax,eax
    jz .refuse
    mov rax,[rel tvm_capacity]
    cmp rax,[rel tvm_clear_offset]       ; T1 scrub complete
    jne .refuse
    test rbx,rbx                         ; 0 ends a setup_data chain
    jz .refuse
    test rbx,7
    jnz .refuse
    mov rdi,r12
    mov rsi,r13
    mov rdx,rbx
    mov ecx,TVM_SEED_RECORD
    call tools_vm_gpa
    test rax,rax
    jz .refuse
    mov r12,rax
    xor edx,edx
    xor ecx,ecx
.zero:
    or rdx,[r12+rcx*8]
    inc ecx
    cmp ecx,TVM_SEED_RECORD/8
    jb .zero
    test rdx,rdx                         ; never over loaded or earlier bytes
    jnz .refuse
    lea rdi,[r12+16]
    mov esi,TVM_SEED_BYTES
    call csprng_generate
    test eax,eax
    jnz .refuse                          ; data zeroed by csprng, no header
    mov dword [r12+8],TVM_SETUP_RNG_SEED
    mov dword [r12+12],TVM_SEED_BYTES
    mov rax,rbx
    jmp .out
.refuse:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    xor eax,eax
    ret
