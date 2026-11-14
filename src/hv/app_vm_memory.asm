;; MODULE hv/app_vm_memory
;; LAYER 5
;; EXPORTS app_vm_memory_acquire, app_vm_memory_clear, app_vm_memory_release, app_vm_slat_build, app_vm_gpa, avm_state, avm_start, avm_base, avm_ram, avm_ram_bytes, avm_capacity, avm_token, avm_clear_offset, avm_root, avm_cpu_live, avm_roots_retired
;; IMPORTS core/memory_budget
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. One app VM owns a separate broker record.
; No driver geometry/device/START state is read or written. Caller is native,
; serializes this object and holds the app lifecycle across each bounded call.
; This module neither publishes a principal nor enters a guest.
%include "hv/app_vm.inc"

; ESI=exact current app START, RDI=RAM bytes. ->1 acquired /0 refused.
; The allocator is the physical nonoverlap authority, including driver RAM.
; PREPARING is private lifecycle state, not an authority supplied by an app.
app_vm_memory_acquire:
    cmp qword [rel avm_state],AVM_PREPARING
    jne .bad
    cmp qword [rel avm_token],0
    jne .bad
    test esi,esi
    jz .bad
    cmp esi,[rel avm_start]
    jne .bad
    cmp rdi,AVM_RAM_MIN
    jb .bad
    cmp rdi,AVM_RAM_MAX
    ja .bad
    test edi,AVM_CONTROL-1
    jnz .bad
    push rbx
    mov rbx,rdi
    mov r9,rdi
    lea rcx,[rdi+AVM_CONTROL]
    mov edi,AVM_OWNER
    mov edx,MB_KIND_GUEST
    mov r8d,AVM_CONTROL
    call mb_acquire
    test eax,eax
    jnz .refused
    mov [rel avm_token],rdx
    mov [rel avm_base],r8
    mov [rel avm_capacity],r9
    lea rax,[r8+AVM_CONTROL]
    mov [rel avm_ram],rax
    mov [rel avm_ram_bytes],rbx
    mov qword [rel avm_clear_offset],0
    mov qword [rel avm_root],0
    mov qword [rel avm_cpu_live],0
    mov qword [rel avm_roots_retired],1
    mov eax,1
    pop rbx
    ret
.refused:
    pop rbx
.bad:
    xor eax,eax
    ret

; Clear <=1MiB per turn, no callback/yield. ->1 complete,2 more,0 refused.
; PREPARING clears before load. SCRUBBING clears after actual CPU/root retire.
; No state transition is hidden in the memory service.
app_vm_memory_clear:
    mov rax,[rel avm_state]
    cmp rax,AVM_PREPARING
    je .state_ok
    cmp rax,AVM_SCRUBBING
    jne .bad
.state_ok:
    cmp qword [rel avm_token],0
    je .bad
    cmp qword [rel avm_cpu_live],0
    jne .bad
    cmp qword [rel avm_roots_retired],1
    jne .bad
    mov rdx,[rel avm_clear_offset]
    mov rcx,[rel avm_capacity]
    cmp rdx,rcx
    ja .bad
    je .done
    sub rcx,rdx
    cmp rcx,AVM_CLEAR_SLICE
    jbe .slice
    mov ecx,AVM_CLEAR_SLICE
.slice:
    mov rdi,[rel avm_base]
    add rdi,rdx
    jc .bad
    add rdx,rcx
    mov [rel avm_clear_offset],rdx
    shr rcx,3
    xor eax,eax
    cld
    rep stosq
    cmp rdx,[rel avm_capacity]
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

; No free while CPU/SLAT/control users remain. Caller sets SCRUBBING only
; after actual backend retirement, then completes clear before this call.
; A busy/stale broker release retains the entire exact ownership record.
app_vm_memory_release:
    cmp qword [rel avm_state],AVM_SCRUBBING
    jne .bad
    cmp qword [rel avm_token],0
    je .bad
    cmp qword [rel avm_cpu_live],0
    jne .bad
    cmp qword [rel avm_roots_retired],1
    jne .bad
    mov rax,[rel avm_capacity]
    test rax,rax
    jz .bad
    cmp rax,[rel avm_clear_offset]
    jne .bad
    sub rsp,8
    mov edi,AVM_OWNER
    mov esi,[rel avm_start]
    mov rdx,[rel avm_token]
    call mb_release
    add rsp,8
    test eax,eax
    jnz .bad
    mov qword [rel avm_token],0
    mov qword [rel avm_base],0
    mov qword [rel avm_capacity],0
    mov qword [rel avm_ram],0
    mov qword [rel avm_ram_bytes],0
    mov qword [rel avm_root],0
    mov qword [rel avm_clear_offset],0
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; EDI1 Intel EPT /2 AMD NPT. Map ONLY own RAM, no native/MMIO/device pages.
; Own control pages, host vectors, script proof and driver RAM stay outside.
; Must finish initial scrub before first table write. ->root or0.
app_vm_slat_build:
    cmp qword [rel avm_state],AVM_LOADING
    jne .bad
    cmp qword [rel avm_token],0
    je .bad
    cmp qword [rel avm_cpu_live],0
    jne .bad
    cmp qword [rel avm_roots_retired],1
    jne .bad
    mov rax,[rel avm_capacity]
    cmp rax,[rel avm_clear_offset]
    jne .bad
    cmp edi,1
    je .intel
    cmp edi,2
    jne .bad
    mov r8d,7
    mov r9d,0x87                    ; NPT P|RW|US|PS
    jmp .build
.intel:
    mov r8d,7
    mov r9d,0xB7                    ; EPT R|W|X|WB|PS
.build:
    mov r10,[rel avm_base]
    lea rdi,[r10+AVM_ROOT]
    xor eax,eax
    mov ecx,0x3000/8
    cld
    rep stosq
    lea rax,[r10+AVM_PDPT]
    or rax,r8
    mov [r10+AVM_ROOT],rax
    lea rax,[r10+AVM_PD]
    or rax,r8
    mov [r10+AVM_PDPT],rax
    mov rdx,[rel avm_ram]
    mov rcx,[rel avm_ram_bytes]
    shr rcx,21
    lea rdi,[r10+AVM_PD]
.leaf:
    mov rax,rdx
    or rax,r9
    stosq
    add rdx,AVM_CONTROL
    loop .leaf
    lea rax,[r10+AVM_ROOT]
    cmp r9d,0xB7
    jne .root
    or rax,0x1E                    ; WB, four levels, A/D disabled
.root:
    mov [rel avm_root],rax
    ret
.bad:
    xor eax,eax
    ret

; RDI=GPA, RSI=length. Native decoder only; ->own HVA or0.
; Zero-length and wrapping/partially outside accesses are refused.
app_vm_gpa:
    cmp qword [rel avm_token],0
    je .bad
    test rsi,rsi
    jz .bad
    mov rax,rdi
    add rax,rsi
    jc .bad
    cmp rax,[rel avm_ram_bytes]
    ja .bad
    mov rax,[rel avm_ram]
    add rax,rdi
    jc .bad
    ret
.bad:
    xor eax,eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_app_vm_memory 0
align 8
avm_state: dq AVM_EMPTY
avm_start: dq 0
avm_base: dq 0
avm_ram: dq 0
avm_ram_bytes: dq 0
avm_capacity: dq 0
avm_token: dq 0
avm_clear_offset: dq 0
avm_root: dq 0
avm_cpu_live: dq 0
avm_roots_retired: dq 1
%endmacro
WDATA_DEFER WDATA_hv_app_vm_memory
