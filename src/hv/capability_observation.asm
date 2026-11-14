;; MODULE hv/capability_observation
;; LAYER 5
;; EXPORTS capability_case_enter, capability_case_complete, capability_case_render
;; IMPORTS hv/boundary, hv/boundary_execution, hv/vmx, hv/vm_profile, core/smp
;; CAPS
;; OWNER saga:security
; Passive X9: copy the actual checked inputs of a completed BEX pair.
; No sample, classification override, mitigation write, launch or admission.
; Same CPU/IF0 writer and bounded seqlock reader as existing BEX telemetry.
; Private frame/token never leave this module. Raw checked input contains
; full APIC ownership, not a runtime custody token. Only full versions6/7.
; Public1040 = BEX header64, original context64, entry232, exit232, BEX448.
; Three pages360/232/448 share the completed count; a changing epoch is U.
CC_SEQ equ 312
CC_PUBLIC equ 320
CC_BYTES equ 1040
CC_SLOT equ 1408
%macro CC_SAVE 0
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
%macro CC_RESTORE 0
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
; RDI=actual retained HVB frame. Called only after BEX accepted its entry.
capability_case_enter:
    CC_SAVE
    cld
    mov r8,rdi
    call smp_current_logical
    cmp eax,SMP_CPU_CAPACITY
    jae .out
    imul eax,CC_SLOT
    lea r9,[rel cc_slots]
    add r9,rax
    mov qword [r9],0
    call cc_input
    test rsi,rsi
    jz .out
    lea rdi,[r9+16]
    mov ecx,29
    xor eax,eax
    rep stosq
    lea rdi,[r9+16]
    mov ecx,r10d
    shr ecx,3
    rep movsq
    mov eax,[rel hv_linux_start_gen]
    mov [r9+248],rax
    mov eax,[rel hv_linux_start_consumed]
    mov [r9+256],rax
    mov eax,[rel hv_linux_load_gen]
    mov [r9+264],rax
    mov eax,[rel vm_profile_gen]
    mov [r9+272],rax
    movzx eax,byte [rel hv_launch_mode]
    mov [r9+280],rax
    mov eax,[r8+HVB_CUSTODY_KIND]
    mov [r9+288],rax
    mov eax,[r8+HVB_CORE_STATE]
    mov [r9+296],rax
    mov [r9+304],r10
    mov rax,[r8+HVB_RECEIPT+40]
    mov [r9+8],rax
    mov [r9],r8
.out:
    CC_RESTORE
; RDI=exact frame, RSI=just completed/redacted BEX448, before X5 callback.
capability_case_complete:
    CC_SAVE
    cld
    mov r8,rdi
    mov r11,rsi
    mov rax,[r11+16]
    cmp rax,SMP_CPU_CAPACITY
    jae .out
    imul eax,CC_SLOT
    lea r9,[rel cc_slots]
    add r9,rax
    cmp [r9],r8
    jne .out
    mov qword [r9],0
    mov rax,[r8+HVB_RECEIPT+40]
    cmp [r9+8],rax
    jne .out
    call cc_input
    cmp r10,[r9+304]
    jne .out
    test rsi,rsi
    jz .out
    inc qword [r9+CC_SEQ]
    ; Save exit input before RSI is reused. Zero AMD's unused32 bytes.
    lea rdi,[r9+CC_PUBLIC+360]
    mov ecx,29
    xor eax,eax
    rep stosq
    lea rdi,[r9+CC_PUBLIC+360]
    mov ecx,r10d
    shr ecx,3
    rep movsq
    lea rdi,[r9+CC_PUBLIC]
    mov rsi,r11
    mov ecx,8
    rep movsq
    lea rsi,[r9+248]
    mov ecx,8
    rep movsq
    lea rsi,[r9+16]
    mov ecx,29
    rep movsq
    lea rdi,[r9+CC_PUBLIC+592]
    mov rsi,r11
    mov ecx,56
    rep movsq
    inc qword [r9+CC_SEQ]
.out:
    CC_RESTORE
; Existing checked sample only. RSI pointer or0, R10 size. No re-sampling.
cc_input:
    xor esi,esi
    xor r10d,r10d
    cmp qword [r8+HVB_SAMPLE_RC],0
    jne .out
    cmp qword [r8+HVB_STAGE],4
    jne .out
    cmp dword [r8+HVB_SVM],2
    jne .amd
    cmp qword [r8+HVB_INTEL+192],6
    jne .out
    lea rsi,[r8+HVB_INTEL]
    mov r10d,232
    ret
.amd:
    cmp dword [r8+HVB_SVM],1
    jne .out
    cmp qword [r8+HVB_AMD+160],7
    jne .out
    lea rsi,[r8+HVB_AMD]
    mov r10d,200
.out:
    ret
; EDI=dense CPU0..31, ESI=page0..2. Existing BSP command reader only.
capability_case_render:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12d,edi
    mov r13d,esi
    lea rbx,[rel cc_snapshot]
    cld
    mov rdi,rbx
    xor eax,eax
    mov ecx,CC_BYTES/8
    rep stosq
    cmp r12d,SMP_CPU_CAPACITY
    jae .empty
    cmp r13d,2
    ja .empty
    imul eax,r12d,CC_SLOT
    lea r8,[rel cc_slots]
    add r8,rax
    mov r14d,3
.retry:
    mov r10,[r8+CC_SEQ]
    test r10b,1
    jnz .again
    mov rdi,rbx
    lea rsi,[r8+CC_PUBLIC]
    mov ecx,CC_BYTES/8
    rep movsq
    lfence
    cmp r10,[r8+CC_SEQ]
    je .copied
.again:
    dec r14d
    jnz .retry
    mov rdi,rbx
    xor eax,eax
    mov ecx,CC_BYTES/8
    rep stosq
.empty:
.copied:
    mov qword [rbx],1
    mov [rbx+16],r12
    call hv_out_reset
    lea rdi,[rel cc_prefix]
    call hv_out_str
    mov eax,r12d
    call hv_out_dec
    lea rdi,[rel cc_page]
    call hv_out_str
    mov eax,r13d
    call hv_out_dec
    lea rdi,[rel cc_epoch]
    call hv_out_str
    mov rax,[rbx+32]
    call cc_out_u64
    lea rdi,[rel cc_data]
    call hv_out_str
    mov rdi,rbx
    mov esi,360
    test r13d,r13d
    jz .hex
    lea rdi,[rbx+360]
    mov esi,232
    cmp r13d,1
    je .hex
    lea rdi,[rbx+592]
    mov esi,448
.hex:
    call vp_out_hex
    lea rdi,[rel capcase_wire_end]
    call hv_out_str
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
; RAX=full-width completed count. hv_out_dec accepts only a dword.
cc_out_u64:
    sub rsp,40
    lea rcx,[rsp+31]
    mov byte [rcx],0
    mov r9d,10
.digit:
    xor edx,edx
    div r9
    add dl,'0'
    dec rcx
    mov [rcx],dl
    test rax,rax
    jnz .digit
    mov rdi,rcx
    call hv_out_str
    add rsp,40
    ret
cc_prefix: db ' CAP_CASE v=1 cpu=',0
cc_page: db ' page=',0
cc_epoch: db ' epoch=',0
cc_data: db ' data=',0
capcase_wire_end: db ' end=1',0
%macro WDATA_hv_capability_observation_bss 0
alignb 64
cc_slots: resb CC_SLOT*SMP_CPU_CAPACITY
cc_snapshot: resb CC_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_hv_capability_observation_bss
