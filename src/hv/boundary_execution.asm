;; MODULE hv/boundary_execution
;; LAYER 5
;; EXPORTS hv_boundary_exec_enter, hv_boundary_exec_vmx, hv_boundary_exec_svm, hv_boundary_exec_render
;; IMPORTS hv/boundary, hv/vmx, hv/vm_profile, core/smp
;; CAPS
;; OWNER saga:hv
; X4 actual paired executor observations. Telemetry has no authority and never
; changes admission, mitigation execution, custody or fail-stop behavior.
; Per dense CPU: private frame/token + entry plan/receipt; separate seqlocked
; completed record. Only real hardware landing sites call completion. VMfail,
; canceled entries, VM-entry-failure exits and SVM INVALID never publish.
; RDI=retained HVB frame. Completion EDX=path (1 HLT,2 Linux,3 AP,4 appVM),
; SVM RCX=actual VMCB EXITCODE. All caller registers/flags survive.
; Public448: version,present,logical,fullAPIC,count,backend,path,reason (8Q),
; entry CBO96, entry receipt96, exit CBO96, exit receipt96. Tokens redacted.
; Last completion per CPU is an observation, not a full path/SMT efficacy census.
BEX_SEQ equ 208
BEX_PUBLIC equ 216
BEX_BYTES equ 448
BEX_SLOT equ 672
%macro BEX_SAVE 0
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
%endmacro
%macro BEX_RESTORE 0
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret
%endmacro

hv_boundary_exec_enter:
    BEX_SAVE
    mov r8,rdi
    call smp_current_logical
    cmp eax,SMP_CPU_CAPACITY
    jae .out
    imul eax,BEX_SLOT
    lea r9,[rel bex_slots]
    add r9,rax
    mov qword [r9],0
    cmp qword [r8+HVB_ACTIVE],1
    jne .out
    cmp qword [r8+HVB_RECEIPT],0
    jne .out
    cmp qword [r8+HVB_RECEIPT+56],2
    jne .out
    mov rax,[r8+HVB_RECEIPT+40]
    test rax,rax
    jz .out
    mov [r9+8],rax
    lea rdi,[r9+16]
    lea rsi,[r8+HVB_POLICY]
    mov ecx,12
    cld
    rep movsq
    lea rsi,[r8+HVB_RECEIPT]
    mov ecx,12
    rep movsq
    mov [r9],r8                     ; pending private frame published last
.out:
    BEX_RESTORE

hv_boundary_exec_vmx:
    BEX_SAVE
    mov r8,rdi
    mov r10d,edx
    mov edi,0x4402
    vmread rax,rdi
    jc bex_done
    jz bex_done
    bt eax,31                       ; VM-entry failure via HOST_RIP != execution
    jc bex_done
    mov rcx,rax
    mov esi,1
    jmp bex_complete

hv_boundary_exec_svm:
    BEX_SAVE
    mov r8,rdi
    mov r10d,edx
    cmp rcx,-1                      ; architected INVALID VMRUN
    je bex_done
    cmp rcx,0x403                   ; reject reserved/invalid sentinel exitcodes
    ja bex_done
    mov esi,2
bex_complete:
    mov r11,rcx                     ; actual architectural exit reason
    mov rdx,rsi                     ; backend
    push rdx
    call smp_current_logical
    pop rdx
    cmp eax,SMP_CPU_CAPACITY
    jae bex_done
    mov ecx,eax
    imul eax,BEX_SLOT
    lea r9,[rel bex_slots]
    add r9,rax
    cmp [r9],r8
    jne bex_done
    mov qword [r9],0                ; consume once, even on malformed closure
    cmp qword [r8+HVB_ACTIVE],0
    jne bex_done
    cmp qword [r8+HVB_FRONTIER],0
    jne bex_done
    cmp qword [r8+HVB_RECEIPT],0
    jne bex_done
    cmp qword [r8+HVB_RECEIPT+56],3
    jne bex_done
    mov rax,[r9+8]
    cmp rax,[r8+HVB_RECEIPT+40]
    jne bex_done
    mov rax,[r9+112+48]
    cmp rax,[r8+HVB_RECEIPT+48]
    jne bex_done
    inc qword [r9+BEX_SEQ]          ; single CPU writer, odd while copying
    mov qword [r9+BEX_PUBLIC],1
    mov qword [r9+BEX_PUBLIC+8],1
    mov [r9+BEX_PUBLIC+16],rcx
    mov [r9+BEX_PUBLIC+24],rax
    inc qword [r9+BEX_PUBLIC+32]
    mov [r9+BEX_PUBLIC+40],rdx
    mov [r9+BEX_PUBLIC+48],r10
    mov [r9+BEX_PUBLIC+56],r11
    lea rdi,[r9+BEX_PUBLIC+64]
    lea rsi,[r9+16]
    mov ecx,24
    cld
    rep movsq
    lea rsi,[r8+HVB_POLICY]
    mov ecx,12
    rep movsq
    lea rsi,[r8+HVB_RECEIPT]
    mov ecx,12
    rep movsq
    mov qword [r9+BEX_PUBLIC+160+40],0
    mov qword [r9+BEX_PUBLIC+352+40],0
    inc qword [r9+BEX_SEQ]          ; even publication, x86 store ordering
bex_done:
    BEX_RESTORE

; EDI=canonical dense CPU0..31 selected by command parser. BSP-only renderer.
; Bounded retries: concurrent AP write yields present0, never a torn receipt.
hv_boundary_exec_render:
    push rbx
    push r12
    push r13
    mov r12d,edi
    lea rbx,[rel bex_snapshot]
    mov rdi,rbx
    xor eax,eax
    mov ecx,BEX_BYTES/8
    cld
    rep stosq
    cmp r12d,SMP_CPU_CAPACITY
    jae .empty
    imul eax,r12d,BEX_SLOT
    lea r8,[rel bex_slots]
    add r8,rax
    mov r13d,3
.retry:
    mov r10,[r8+BEX_SEQ]
    test r10b,1
    jnz .again
    mov rdi,rbx
    lea rsi,[r8+BEX_PUBLIC]
    mov ecx,BEX_BYTES/8
    rep movsq
    lfence
    cmp r10,[r8+BEX_SEQ]
    je .copied
.again:
    dec r13d
    jnz .retry
    mov rdi,rbx
    xor eax,eax
    mov ecx,BEX_BYTES/8
    rep stosq
.empty:
.copied:
    mov qword [rbx],1
    mov [rbx+16],r12
    call hv_out_reset
    lea rdi,[rel str_bex]
    call hv_out_str
    mov eax,r12d
    call hv_out_dec
    lea rdi,[rel str_bex_data]
    call hv_out_str
    mov rdi,rbx
    mov esi,BEX_BYTES
    call vp_out_hex
    lea rdi,[rel str_bex_end]
    call hv_out_str
    pop r13
    pop r12
    pop rbx
    ret
str_bex: db ' BOUND_EXEC v=1 cpu=',0
str_bex_data: db ' data=',0
str_bex_end: db ' end=1',0
%macro WDATA_hv_boundary_execution_bss 0
alignb 64
bex_slots: resb BEX_SLOT*SMP_CPU_CAPACITY
bex_snapshot: resb BEX_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_hv_boundary_execution_bss
