;; MODULE hv/app_vm_boot
;; LAYER 5
;; EXPORTS app_vm_boot_begin, app_vm_boot_tick, app_vm_boot_current, avm_runtime_gen, avm_boot_phase, avm_kernel_bytes, avm_initrd_gpa
;; IMPORTS hv/app_runtime, hv/app_vm_memory, hv/app_vm_payload, hv/isolated_vm_boot_tables, hv/isolated_vm_initrd, core/lib/sha256
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Actual signed-runtime descriptor and bounded file reads, independently hashed
; AFTER copying into this VM's own memory. No driver-profile/global mutation.
%include "hv/app_vm.inc"
%include "hv/isolated_vm_boot_tables.asm"
%include "hv/isolated_vm_initrd.asm"

; LOADING, private RAM scrubbed. ->1 initialized/0 rejected. No guest identity.
app_vm_boot_begin:
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
    push rbx
    mov rbx,[rel avm_base]
    lea rdi,[rbx+AVM_RUNTIME_DESC]
    mov esi,128
    call app_runtime_descriptor
    cmp eax,1
    jne .pop_bad
    cmp qword [rbx+AVM_RUNTIME_DESC],1
    jne .pop_bad
    mov rax,[rbx+AVM_RUNTIME_DESC+8]
    test rax,rax
    jz .pop_bad
    cmp rax,-1
    je .pop_bad
    mov [rel avm_runtime_gen],rax
    ; Bounds before any read or pointer arithmetic. Kernel file max64MiB;
    ; initrd must fit own RAM, nonzero. The actual producer selects both.
    mov rax,[rbx+AVM_RUNTIME_DESC+16]
    cmp rax,4096
    jb .pop_bad
    cmp rax,0x4000000
    ja .pop_bad
    mov rax,[rbx+AVM_RUNTIME_DESC+24]
    test rax,rax
    jz .pop_bad
    cmp rax,[rel avm_ram_bytes]
    jae .pop_bad
    mov ecx,4
    lea rdi,[rbx+AVM_RUNTIME_DESC+96]
.reserved:
    cmp qword [rdi],0
    jne .pop_bad
    add rdi,8
    loop .reserved
    mov qword [rel avm_boot_offset],0
    mov qword [rel avm_boot_phase],1
    mov eax,1
    pop rbx
    ret
.pop_bad:
    mov qword [rel avm_boot_phase],0
    mov qword [rel avm_runtime_gen],0
    pop rbx
.bad:
    xor eax,eax
    ret

; Exact selected runtime remains current. Read-only, no guest execution.
app_vm_boot_current:
    cmp qword [rel avm_runtime_gen],0
    je .bad
    cmp qword [rel avm_token],0
    je .bad
    push rbx
    mov rbx,[rel avm_base]
    lea rdi,[rbx+AVM_RUNTIME_CHECK]
    mov esi,128
    call app_runtime_descriptor
    cmp eax,1
    jne .pop_bad
    lea rdi,[rbx+AVM_RUNTIME_DESC]
    lea rsi,[rbx+AVM_RUNTIME_CHECK]
    mov ecx,16
    cld
    repe cmpsq
    jne .pop_bad
    mov eax,1
    pop rbx
    ret
.pop_bad:
    pop rbx
.bad:
    xor eax,eax
    ret

; ->2 more/1 complete/0 rejected. At most one <=1MiB file read per call.
; Failure poisons this load, caller retires and scrubs; no partial reuse.
app_vm_boot_tick:
    cmp qword [rel avm_state],AVM_LOADING
    jne .bad
    cmp qword [rel avm_cpu_live],0
    jne .bad
    cmp qword [rel avm_roots_retired],1
    jne .bad
    cmp qword [rel avm_token],0
    je .bad
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov rbx,[rel avm_base]
    call app_vm_payload_current
    cmp eax,1
    jne .failed
    call app_vm_boot_current
    cmp eax,1
    jne .failed
    mov rax,[rel avm_boot_phase]
    cmp eax,1
    je .header
    cmp eax,2
    je .kernel
    cmp eax,3
    je .initrd
    cmp eax,4
    je .finish
    jmp .failed
.header:
    mov r8,[rbx+AVM_RUNTIME_DESC+16]
    cmp r8,32768
    jbe .header_count
    mov r8d,32768
.header_count:
    mov rdi,[rel avm_runtime_gen]
    mov esi,1
    xor edx,edx
    lea rcx,[rbx+AVM_BOOT_HEADER]
    call app_runtime_read
    cmp eax,1
    jne .failed
    lea r12,[rbx+AVM_BOOT_HEADER]
    cmp word [r12+0x1fe],0xaa55
    jne .failed
    cmp dword [r12+0x202],0x53726448 ; HdrS
    jne .failed
    cmp word [r12+0x206],0x020c
    jb .failed
    ; Setup header ends at 0x202+byte[0x201] (boot protocol). It must cover
    ; init_size (0x260..0x263), the last field this loader reads, and stay
    ; below the zero page's edd/e820 area at 0x290. Shipped kernels: 0x26c.
    movzx eax,byte [r12+0x201]
    cmp eax,0x264-0x202
    jb .failed
    cmp eax,0x290-0x202
    ja .failed
    ; Actual selected recipe may be fixed at16MiB. A fixed kernel must
    ; prefer exactly that load address; no blind relocation. code32_start
    ; (0x214) is the loader's field: a stock bzImage holds 0x100000 there
    ; whatever PHYSICAL_START is, entry here is the 64-bit one at
    ; AVM_KERNEL+0x200, and .finish writes 0x214 itself (VM, desktop 118753).
    cmp byte [r12+0x234],1
    ja .failed
    je .alignment
    cmp qword [r12+0x258],AVM_KERNEL
    jne .failed
.alignment:
    mov eax,[r12+0x230]
    test eax,eax
    jz .failed
    lea edx,[rax-1]
    test eax,edx
    jnz .failed
    test edx,AVM_KERNEL
    jnz .failed
    test byte [r12+0x236],1          ; 64-bit entry supported
    jz .failed
    movzx eax,byte [r12+0x1f1]
    test eax,eax
    jnz .setup_count
    mov eax,4
.setup_count:
    inc eax
    shl eax,9
    cmp eax,32768
    ja .failed
    cmp rax,[rbx+AVM_RUNTIME_DESC+16]
    jae .failed
    mov [rel avm_setup_bytes],rax
    mov r13,[rbx+AVM_RUNTIME_DESC+16]
    sub r13,rax
    mov [rel avm_kernel_bytes],r13
    mov r14d,[r12+0x260]             ; real decompression/init working size
    cmp r14,r13
    jb .failed
    test r14,r14
    jz .failed
    ; Highest page below both own RAM and the actual inclusive kernel ceiling;
    ; disjoint from the real startup workspace, not just compressed file bytes.
    mov rdi,[rel avm_ram_bytes]
    mov rsi,[rbx+AVM_RUNTIME_DESC+24]
    mov rdx,r14
    mov ecx,[r12+0x22c]
    call isolated_vm_initrd
    test rax,rax
    jz .failed
    mov [rel avm_initrd_gpa],rax
    ; This VM's boot_params (never driver RAM) is a zeroed page carrying only
    ; the kernel's own setup header, 0x1f1 .. 0x202+byte[0x201]. The rest of
    ; the file's first 4 KiB is boot-sector code and filler: a stock bzImage
    ; holds 0xffffffff at ext_cmd_line_ptr (0xc8), which sent the 6.6
    ; decompressor to 0xffffffff_00020000 (#PF->#DF; track B be886f79d).
    mov rdi,[rel avm_ram]
    add rdi,AVM_BP
    mov rdx,rdi
    xor eax,eax
    mov ecx,4096/8
    cld
    rep stosq
    lea rdi,[rdx+0x1f1]
    lea rsi,[r12+0x1f1]
    movzx ecx,byte [r12+0x201]
    add ecx,0x202-0x1f1
    rep movsb
    lea rdi,[rbx+AVM_HASH_CTX]
    call sha256_stream_init
    lea rdi,[rbx+AVM_HASH_CTX]
    lea rsi,[rbx+AVM_BOOT_HEADER]
    mov rdx,[rel avm_setup_bytes]
    call sha256_stream_update
    test eax,eax
    jnz .failed
    mov qword [rel avm_boot_offset],0
    mov qword [rel avm_boot_phase],2
    jmp .more
.kernel:
    mov r12,[rel avm_boot_offset]
    mov r13,[rel avm_kernel_bytes]
    sub r13,r12
    jc .failed
    jz .kernel_done
    cmp r13,AVM_CLEAR_SLICE
    jbe .kernel_count
    mov r13d,AVM_CLEAR_SLICE
.kernel_count:
    lea rdi,[r12+AVM_KERNEL]
    mov rsi,r13
    call app_vm_gpa
    test rax,rax
    jz .failed
    mov r14,rax
    mov rdi,[rel avm_runtime_gen]
    mov esi,1
    mov rdx,r12
    add rdx,[rel avm_setup_bytes]
    mov rcx,r14
    mov r8,r13
    call app_runtime_read
    cmp eax,1
    jne .failed
    lea rdi,[rbx+AVM_HASH_CTX]
    mov rsi,r14
    mov rdx,r13
    call sha256_stream_update
    test eax,eax
    jnz .failed
    add r12,r13
    mov [rel avm_boot_offset],r12
    jmp .more
.kernel_done:
    lea rdi,[rbx+AVM_HASH_CTX]
    lea rsi,[rbx+AVM_HASH_OUT]
    call sha256_stream_final
    test eax,eax
    jnz .failed
    lea rdi,[rbx+AVM_HASH_OUT]
    lea rsi,[rbx+AVM_RUNTIME_DESC+32]
    mov ecx,4
    cld
    repe cmpsq
    jne .failed
    lea rdi,[rbx+AVM_HASH_CTX]
    call sha256_stream_init
    mov qword [rel avm_boot_offset],0
    mov qword [rel avm_boot_phase],3
    jmp .more
.initrd:
    mov r12,[rel avm_boot_offset]
    mov r13,[rbx+AVM_RUNTIME_DESC+24]
    sub r13,r12
    jc .failed
    jz .initrd_done
    cmp r13,AVM_CLEAR_SLICE
    jbe .initrd_count
    mov r13d,AVM_CLEAR_SLICE
.initrd_count:
    mov rdi,[rel avm_initrd_gpa]
    add rdi,r12
    jc .failed
    mov rsi,r13
    call app_vm_gpa
    test rax,rax
    jz .failed
    mov r14,rax
    mov rdi,[rel avm_runtime_gen]
    mov esi,2
    mov rdx,r12
    mov rcx,r14
    mov r8,r13
    call app_runtime_read
    cmp eax,1
    jne .failed
    lea rdi,[rbx+AVM_HASH_CTX]
    mov rsi,r14
    mov rdx,r13
    call sha256_stream_update
    test eax,eax
    jnz .failed
    add r12,r13
    mov [rel avm_boot_offset],r12
    jmp .more
.initrd_done:
    lea rdi,[rbx+AVM_HASH_CTX]
    lea rsi,[rbx+AVM_HASH_OUT]
    call sha256_stream_final
    test eax,eax
    jnz .failed
    lea rdi,[rbx+AVM_HASH_OUT]
    lea rsi,[rbx+AVM_RUNTIME_DESC+64]
    mov ecx,4
    cld
    repe cmpsq
    jne .failed
    mov qword [rel avm_boot_phase],4
    jmp .more
.finish:
    ; Recheck actual selected generation and signed app before CPU preparation.
    call app_vm_boot_current
    cmp eax,1
    jne .failed
    call app_vm_payload_current
    cmp eax,1
    jne .failed
    mov r12,[rel avm_ram]
    lea rdi,[r12+AVM_CMD]
    lea rsi,[rel avm_boot_cmd]
    mov ecx,avm_boot_cmd_end-avm_boot_cmd
    cld
    rep movsb
    lea rdi,[r12+AVM_BP]
    mov byte [rdi+0x210],0xff
    or byte [rdi+0x211],0x80
    mov dword [rdi+0x214],AVM_KERNEL
    mov rax,[rel avm_initrd_gpa]
    mov [rdi+0x218],eax
    mov rax,[rbx+AVM_RUNTIME_DESC+24]
    mov [rdi+0x21c],eax
    mov dword [rdi+0x228],AVM_CMD
    mov byte [rdi+0x1e8],2
    mov qword [rdi+0x2d0],0
    mov qword [rdi+0x2d8],0xa0000
    mov dword [rdi+0x2e0],1
    mov qword [rdi+0x2e4],0x100000
    mov rax,[rel avm_ram_bytes]
    sub rax,0x100000
    mov [rdi+0x2ec],rax
    mov dword [rdi+0x2f4],1
    ; Private guest long-mode tables and GDT/TSS, all guest physical offsets.
    mov rdi,r12
    mov rsi,[rel avm_ram_bytes]
    call isolated_vm_boot_tables
    test eax,eax
    jz .failed
    mov rax,0x00af9b000000ffff
    mov [r12+0x508],rax
    mov rax,0x00cf93000000ffff
    mov [r12+0x510],rax
    mov rax,0x00008b0006000067
    mov [r12+0x518],rax
    mov qword [r12+0x520],0
    mov word [r12+0x600+0x66],104
    mov qword [rel avm_boot_phase],5
    mov eax,1
    jmp .out
.more:
    mov eax,2
    jmp .out
.failed:
    mov qword [rel avm_boot_phase],0
    mov qword [rel avm_runtime_gen],0
    xor eax,eax
.out:
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    xor eax,eax
    ret

avm_boot_cmd: db "console=ttyS0,115200 quiet loglevel=0 noapic nolapic hpet=disable clocksource=tsc tsc=reliable rdinit=/init rootfstype=ramfs panic=-1",0
avm_boot_cmd_end:
%include "core/abi/wdata.inc"
%macro WDATA_hv_app_vm_boot 0
align 8
avm_runtime_gen: dq 0
avm_boot_phase: dq 0
avm_boot_offset: dq 0
avm_setup_bytes: dq 0
avm_kernel_bytes: dq 0
avm_initrd_gpa: dq 0
%endmacro
WDATA_DEFER WDATA_hv_app_vm_boot
