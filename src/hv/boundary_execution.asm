;; MODULE hv/boundary_execution
;; LAYER 5
;; EXPORTS hv_boundary_exec_copy, hv_boundary_exec_enter, hv_boundary_exec_vmx, hv_boundary_exec_svm, hv_boundary_exec_render, hv_boundary_cost_stamp, hv_boundary_cost_render
;; IMPORTS hv/capability_observation, hv/context_execution, hv/boundary, hv/vmx, hv/vm_profile, core/smp, svc/boot_clock
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
    mov rdi,r8
    call capability_case_enter       ; passive exact checked entry input
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
    ; Cost metadata shares this exact completed receipt and publication epoch.
    ; Missing/incomplete timing must not suppress the existing X4 observation.
    mov rax, [r9+BEX_PUBLIC+16]
    imul eax,72
    lea rsi,[rel bcost_slots]
    add rsi,rax
    lea rdi,[rsi+40]
    xor eax,eax
    mov ecx,4
    rep stosq
    cmp [rsi],r8
    jne .cost_done
    lea rdi,[rsi+40]
    add rsi,8
    mov ecx,4
    rep movsq
.cost_done:
    inc qword [r9+BEX_SEQ]          ; even publication, x86 store ordering
    mov rdi,r8
    lea rsi,[r9+BEX_PUBLIC]
    call capability_case_complete    ; preserves registers/flags and X5 callback
    lea rdi,[r9+BEX_PUBLIC]
    call context_domain_complete     ; telemetry-only exact driver context join
bex_done:
    BEX_RESTORE

; EDI=dense CPU, RSI=mapped448B destination. EAX1 copied,0 absent/busy.
; Three attempts; a failed copy is wholly zero. No output/private token/dispatch.
hv_boundary_exec_copy:
    push rbx
    push r12
    push r13
    mov rbx,rsi
    mov r12d,edi
    mov rdi,rbx
    xor eax,eax
    mov ecx,56
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
    mov ecx,56
    rep movsq
    lfence
    cmp r10,[r8+BEX_SEQ]
    jne .again
    cmp qword [rbx+8],1
    jne .clear
    mov eax,1
    jmp .out
.again:
    dec r13d
    jnz .retry
.clear:
    mov rdi,rbx
    xor eax,eax
    mov ecx,56
    rep stosq
.empty:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

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

; RDI=retained frame, ESI=entry0/exit1, EDX=start0/end1. Calling CPU is
; pinned by the existing guard/custody, IF0. Preserve every volatile register
; and RFLAGS, notably the executor return RAX. No timing result is authority.
; Serialized elapsed context-call spans include args, timestamp/helper overhead;
; never guest run time, a pure instruction latency, or mitigation-off delta.
hv_boundary_cost_stamp:
    BEX_SAVE
    mov r8,rdi
    mov r10d,esi
    mov r11d,edx
    cmp r10d,1
    ja .out
    cmp r11d,1
    ja .out
    call smp_current_logical
    cmp eax,SMP_CPU_CAPACITY
    jae .out
    imul eax,72
    lea r9,[rel bcost_slots]
    add r9,rax
    test r10d,r10d
    jnz .bound
    test r11d,r11d
    jnz .bound
    mov [r9],r8
    mov qword [r9+8],0
    mov qword [r9+16],0
    mov qword [r9+24],0
    mov qword [r9+32],0
.bound:
    cmp [r9],r8
    jne .out
    lea ecx,[r11d+r10d*2]
    lfence
    rdtsc
    lfence
    shl rdx,32
    or rax,rdx
    mov [r9+rcx*8+8],rax
.out:
    BEX_RESTORE

; Separate read-only BOUNDCOST page: X4 BOUNDEXEC v1 wire is unchanged.
; Fixed32Q: completed BEX header8, matching context-call spans4, checked
; BOOTCLOCK projection20. Snapshot origin is EFI entry, NEVER external G0.
; Projection indexes: status,origin,khz,source,reason,now,begin,ebs,ready,ack,
; pixel,input,udp,ssh,preload0,preload1,preloadDone,bsp0,bsp1,bspDone.
hv_boundary_cost_render:
    push rbx
    push r12
    push r13
    mov r12d,edi
    lea rbx,[rel bcost_snapshot]
    mov rdi,rbx
    xor eax,eax
    mov ecx,32
    cld
    rep stosq
    cmp r12d,SMP_CPU_CAPACITY
    jae .clock
    imul eax,r12d,BEX_SLOT
    lea r8,[rel bex_slots]
    add r8,rax
    imul eax,r12d,72
    lea r9,[rel bcost_slots+40]
    add r9,rax
    mov r13d,3
.retry:
    mov r10,[r8+BEX_SEQ]
    test r10b,1
    jnz .again
    mov rdi,rbx
    lea rsi,[r8+BEX_PUBLIC]
    mov ecx,8
    rep movsq
    mov rsi,r9
    mov ecx,4
    rep movsq
    lfence
    cmp r10,[r8+BEX_SEQ]
    je .clock
.again:
    dec r13d
    jnz .retry
    mov rdi,rbx
    xor eax,eax
    mov ecx,12
    rep stosq
.clock:
    mov qword [rbx],1
    mov [rbx+16],r12
    lea rdi,[rel bcost_clock]
    call boot_clock_snapshot
    ; Reuse checked native BOOTCLOCK v7 facts, not a second clock reader.
%macro BCC_COPY 2
    mov rax,[rel bcost_clock+%2]
    mov [rbx+96+%1*8],rax
%endmacro
    BCC_COPY 0,416
    BCC_COPY 1,0
    BCC_COPY 2,8
    BCC_COPY 3,16
    BCC_COPY 4,24
    BCC_COPY 5,408
    BCC_COPY 6,424
    BCC_COPY 7,56
    BCC_COPY 8,64
    BCC_COPY 9,72
    BCC_COPY 10,80
    BCC_COPY 11,104
    BCC_COPY 12,112
    BCC_COPY 13,120
    BCC_COPY 14,360
    BCC_COPY 15,368
    BCC_COPY 16,392
    BCC_COPY 17,376
    BCC_COPY 18,384
    BCC_COPY 19,400
%unmacro BCC_COPY 2
    call hv_out_reset
    lea rdi,[rel str_bcost]
    call hv_out_str
    mov eax,r12d
    call hv_out_dec
    lea rdi,[rel str_bex_data]
    call hv_out_str
    mov rdi,rbx
    mov esi,256
    call vp_out_hex
    lea rdi,[rel str_bex_end]
    call hv_out_str
    pop r13
    pop r12
    pop rbx
    ret
str_bcost: db ' BOUND_COST v=1 cpu=',0

%macro WDATA_hv_boundary_execution_bss 0
alignb 64
bex_slots: resb BEX_SLOT*SMP_CPU_CAPACITY
bex_snapshot: resb BEX_BYTES
bcost_slots: resb 72*SMP_CPU_CAPACITY
bcost_snapshot: resb 256
bcost_clock: resb 432
%endmacro
WDATA_BSS_DEFER WDATA_hv_boundary_execution_bss
