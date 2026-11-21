;; MODULE hv/tools_vm_memory
;; LAYER 5
;; EXPORTS tools_vm_memory_acquire, tools_vm_memory_clear, tools_vm_memory_load, tools_vm_memory_scrub, tools_vm_memory_release, tools_vm_slat_build, tools_vm_gpa
;; IMPORTS core/memory_budget
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Internal, serialized, nonyielding RAM service.
; No owner/session admission, CPU entry, runtime or Terminal caller exists in
; this slice. Later lifecycle callers must first establish local authority.
; Unlike the app's implicit current singleton calls, EVERY operation carries
; the original START/token. No context pointer or guest argument selects state.
%include "hv/tools_vm.inc"

; RDI native selected RAM (0=2GiB, or exact2/3GiB), RSI fresh uint32 START.
; ->1 acquired /0 unchanged. No eviction, START reuse/wrap or boot reservation.
tools_vm_memory_acquire:
    cmp qword [rel tvm_state],TVM_EMPTY
    jne .bad
    cmp qword [rel tvm_token],0
    jne .bad
    test rsi,rsi
    jz .bad
    mov eax,esi
    cmp rax,rsi
    jne .bad
    cmp rsi,[rel tvm_start]
    jbe .bad
    test rdi,rdi
    jnz .choice
    mov edi,TVM_RAM_DEFAULT
.choice:
    mov eax,TVM_RAM_DEFAULT
    cmp rdi,rax
    je .acquire
    mov eax,TVM_RAM_LARGE
    cmp rdi,rax
    jne .bad
.acquire:
    push rbx
    push r12
    sub rsp,8
    mov rbx,rdi
    mov r12,rsi
    mov r9,rdi
    lea rcx,[rdi+TVM_CONTROL]
    mov edi,TVM_OWNER
    mov edx,MB_KIND_GUEST
    mov r8d,TVM_CONTROL
    call mb_acquire
    test eax,eax
    jnz .out
    mov [rel tvm_token],rdx
    mov [rel tvm_base],r8
    mov [rel tvm_capacity],r9
    lea rax,[r8+TVM_CONTROL]
    mov [rel tvm_ram],rax
    mov [rel tvm_ram_bytes],rbx
    mov [rel tvm_start],r12
    mov qword [rel tvm_clear_offset],0
    mov qword [rel tvm_root],0
    mov qword [rel tvm_cpu_live],0
    mov qword [rel tvm_roots_retired],1
    mov qword [rel tvm_state],TVM_PREPARING
    mov eax,1
    jmp .return
.out:
    xor eax,eax
.return:
    add rsp,8
    pop r12
    pop rbx
    ret
.bad:
    xor eax,eax
    ret

; Internal exact capsule AND allocator join. RDI START, RSI token ->1/0.
; Broker read uses native stack storage, never guest/shared scratch. It cannot
; yield; these serialized callers may use the returned geometry immediately.
tvm_memory_current:
    test rdi,rdi
    jz .bad
    cmp rdi,[rel tvm_start]
    jne .bad
    test rsi,rsi
    jz .bad
    cmp rsi,[rel tvm_token]
    jne .bad
    sub rsp,72
    mov rdx,rsi
    mov rsi,rdi
    mov edi,TVM_OWNER
    mov rcx,rsp
    mov r8d,MB_ALLOCATION_BYTES
    call mb_allocation_read
    test eax,eax
    jnz .refused
    cmp qword [rsp+MB_REC_KIND],MB_KIND_GUEST
    jne .refused
    mov rax,[rel tvm_base]
    test eax,TVM_CONTROL-1
    jnz .refused
    cmp rax,[rsp+MB_REC_BASE]
    jne .refused
    add rax,TVM_CONTROL
    jc .refused
    cmp rax,[rel tvm_ram]
    jne .refused
    mov rax,[rel tvm_ram_bytes]
    cmp rax,[rsp+MB_REC_RESIDENT]
    jne .refused
    mov edx,TVM_RAM_DEFAULT
    cmp rax,rdx
    je .geometry
    mov edx,TVM_RAM_LARGE
    cmp rax,rdx
    jne .refused
.geometry:
    add rax,TVM_CONTROL
    cmp rax,[rel tvm_capacity]
    jne .refused
    cmp rax,[rsp+MB_REC_BYTES]
    jne .refused
    add rax,[rel tvm_base]
    jc .refused
    mov eax,1
    add rsp,72
    ret
.refused:
    add rsp,72
.bad:
    xor eax,eax
    ret

; RDI START, RSI token. All memory writers require actual CPU/root retirement.
tvm_memory_stopped:
    cmp qword [rel tvm_cpu_live],0
    jne .bad
    cmp qword [rel tvm_roots_retired],1
    jne .bad
    jmp tvm_memory_current
.bad:
    xor eax,eax
    ret

; Original START/token ->1 complete /2 more /0 refusal. <=1MiB, no callbacks.
tools_vm_memory_clear:
    mov rax,[rel tvm_state]
    cmp rax,TVM_PREPARING
    je .state
    cmp rax,TVM_SCRUBBING
    jne .bad
.state:
    sub rsp,8
    call tvm_memory_stopped
    add rsp,8
    test eax,eax
    jz .bad
    mov rdx,[rel tvm_clear_offset]
    mov rcx,[rel tvm_capacity]
    cmp rdx,rcx
    ja .bad
    je .done
    sub rcx,rdx
    cmp rcx,TVM_CLEAR_SLICE
    jbe .slice
    mov ecx,TVM_CLEAR_SLICE
.slice:
    mov rdi,[rel tvm_base]
    add rdi,rdx
    add rdx,rcx
    shr rcx,3
    xor eax,eax
    cld
    rep stosq
    mov [rel tvm_clear_offset],rdx
    cmp rdx,[rel tvm_capacity]
    jne .more
.done:
    mov eax,1
    ret
.more:
    mov eax,2
    ret
.bad:
    xor eax,eax
    ret

; Loading is impossible until every control/RAM byte was initially cleared.
tools_vm_memory_load:
    cmp qword [rel tvm_state],TVM_PREPARING
    jne .bad
    sub rsp,8
    call tvm_memory_stopped
    add rsp,8
    test eax,eax
    jz .bad
    mov rax,[rel tvm_capacity]
    cmp rax,[rel tvm_clear_offset]
    jne .bad
    mov qword [rel tvm_state],TVM_LOADING
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; CPU lifecycle has to retire CPU/roots first; this function cannot do so.
; Repeated original scrub does not reset progress. Refusals change no state.
tools_vm_memory_scrub:
    cmp qword [rel tvm_state],TVM_EMPTY
    je .bad
    sub rsp,8
    call tvm_memory_stopped
    add rsp,8
    test eax,eax
    jz .bad
    cmp qword [rel tvm_state],TVM_SCRUBBING
    je .done
    mov qword [rel tvm_clear_offset],0
    mov qword [rel tvm_root],0
    mov qword [rel tvm_state],TVM_SCRUBBING
.done:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

tools_vm_memory_release:
    cmp qword [rel tvm_state],TVM_SCRUBBING
    jne .bad
    sub rsp,8
    call tvm_memory_stopped
    add rsp,8
    test eax,eax
    jz .bad
    mov rax,[rel tvm_capacity]
    cmp rax,[rel tvm_clear_offset]
    jne .bad
    sub rsp,8
    mov edi,TVM_OWNER
    mov rsi,[rel tvm_start]
    mov rdx,[rel tvm_token]
    call mb_release
    add rsp,8
    test eax,eax
    jnz .bad
    ; Retain START forever: later acquisitions must use a greater uint32.
    lea rdi,[rel tvm_token]
    mov ecx,(tvm_memory_end-tvm_token)/8
    xor eax,eax
    cld
    rep stosq
    mov qword [rel tvm_roots_retired],1
    mov qword [rel tvm_state],TVM_EMPTY
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI START, RSI token, EDX1 EPT/2 NPT. ->root/0. No live-root rebuild.
tools_vm_slat_build:
    cmp qword [rel tvm_state],TVM_LOADING
    jne .bad
    push rbx
    mov ebx,edx
    call tvm_memory_stopped
    test eax,eax
    jz .out
    cmp ebx,1
    je .intel
    cmp ebx,2
    jne .out
    mov r9d,0x87
    jmp .build
.intel:
    mov r9d,0xb7
.build:
    mov r10,[rel tvm_base]
    xor eax,eax
    lea rdi,[r10+TVM_ROOT]
    mov ecx,0x2000/8
    cld
    rep stosq
    lea rdi,[r10+TVM_PD]
    mov ecx,TVM_PD_COUNT*4096/8
    rep stosq
    lea rax,[r10+TVM_PDPT+7]
    mov [r10+TVM_ROOT],rax
    mov rcx,[rel tvm_ram_bytes]
    shr rcx,30
    lea rdi,[r10+TVM_PDPT]
    lea rdx,[r10+TVM_PD+7]
.directory:
    mov rax,rdx
    stosq
    add rdx,4096
    loop .directory
    mov rdx,[rel tvm_ram]
    mov rcx,[rel tvm_ram_bytes]
    shr rcx,21
    lea rdi,[r10+TVM_PD]
.leaf:
    mov rax,rdx
    or rax,r9
    stosq
    add rdx,TVM_CONTROL
    loop .leaf
    lea rax,[r10+TVM_ROOT]
    cmp ebx,1
    jne .root
    or rax,0x1e
.root:
    mov [rel tvm_root],rax
    pop rbx
    ret
.out:
    pop rbx
.bad:
    xor eax,eax
    ret

; RDI START, RSI token, RDX GPA, RCX length ->own RAM HVA/0.
; No conversion of a guest address until original allocation custody is joined.
tools_vm_gpa:
    cmp qword [rel tvm_state],TVM_LOADING
    jb .refused
    cmp qword [rel tvm_state],4       ; READY/RUNNING; no pre-clear/retired IO
    ja .refused
    push rbx
    push r12
    sub rsp,8
    mov rbx,rdx
    mov r12,rcx
    call tvm_memory_current
    test eax,eax
    jz .bad
    test r12,r12
    jz .bad
    mov rax,rbx
    add rax,r12
    jc .bad
    cmp rax,[rel tvm_ram_bytes]
    ja .bad
    mov rax,[rel tvm_ram]
    add rax,rbx
    jc .bad
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret
.refused:
    xor eax,eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_tools_vm_memory 0
align 8
tvm_state: dq TVM_EMPTY
tvm_start: dq 0
tvm_token: dq 0
tvm_base: dq 0
tvm_ram: dq 0
tvm_ram_bytes: dq 0
tvm_capacity: dq 0
tvm_clear_offset: dq 0
tvm_root: dq 0
tvm_cpu_live: dq 0
tvm_roots_retired: dq 1
tvm_memory_end:
; Snapshot disjointness loads this span with ECX. Reject empty, reversed
; or truncated layouts at WDATA expansion, after both labels are defined.
times (((tvm_memory_end-tvm_state) <= 0) || ((tvm_memory_end-tvm_state) > 0xffffffff)) * -1 db 0
%endmacro
WDATA_DEFER WDATA_hv_tools_vm_memory
