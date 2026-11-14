; Common C3 CPU-owned selectors. Only retained RAM and unprivileged CPUID;
; no probe, MSR/MMIO/port access, callback, selection or owner state change.
; Separate scope keeps the original 1024-byte COMPAT record limit intact.
hw_r_bindcpu:
    push rbx
    push r12
    push r13
    sub rsp,96
    mov rdi,rsp
    xor eax,eax
    mov ecx,24
    cld
    rep stosd
    movzx eax,byte [rel tsc_calibration_source]
    mov [rsp],eax
    mov rax,[rel tsc_khz]
    mov [rsp+4],rax
    movzx eax,byte [rel smp_lapic_mode]
    mov [rsp+12],eax
    movzx eax,byte [rel gov_hwp_present]
    mov [rsp+16],eax
    movzx eax,byte [rel gov_cppc_present]
    mov [rsp+20],eax
    movzx eax,byte [rel gov_policy_fw_seen]
    mov [rsp+24],eax
    movzx eax,byte [rel therm_source]
    mov [rsp+28],eax
    mov eax,[rel idle_depth_state]
    mov [rsp+32],eax
    xor eax,eax
    cpuid
    mov [rsp+64],eax
    mov edi,1
    cmp ebx,0x756e6547
    jne .amd
    cmp edx,0x49656e69
    jne .amd
    cmp ecx,0x6c65746e
    je .vendor
.amd:
    mov edi,2
    cmp ebx,0x68747541
    jne .unknown
    cmp edx,0x69746e65
    jne .unknown
    cmp ecx,0x444d4163
    je .vendor
.unknown:
    xor edi,edi
.vendor:
    mov [rsp+36],edi
    mov eax,1
    xor ecx,ecx
    cpuid
    mov [rsp+44],edx
    mov [rsp+48],ecx
    mov edx,eax
    shr edx,8
    and edx,15
    cmp edx,15
    jne .family
    shr eax,20
    and eax,255
    add edx,eax
.family:
    mov [rsp+40],edx
    cmp dword [rsp+64],6
    jb .extended
    mov eax,6
    xor ecx,ecx
    cpuid
    mov [rsp+52],eax
.extended:
    mov eax,0x80000000
    cpuid
    mov [rsp+68],eax
    cmp eax,0x80000007
    jb .ratio
    mov eax,0x80000007
    xor ecx,ecx
    cpuid
    mov [rsp+60],edx
    cmp dword [rsp+68],0x80000008
    jb .ratio
    mov eax,0x80000008
    xor ecx,ecx
    cpuid
    mov [rsp+56],ebx
.ratio:
    cmp dword [rsp+64],0x15
    jb .render
    mov eax,0x15
    xor ecx,ecx
    cpuid
    mov [rsp+72],eax
    mov [rsp+76],ebx
    mov [rsp+80],ecx
.render:
    lea rdi,[rel hwc_core_scope]
    call hw_puts
    xor r12d,r12d
.next:
    mov edi,[rsp+r12*4]
    call hw_put_dec
    inc r12d
    cmp r12d,21
    jae .done
    lea rdi,[rel str_hw_comma]
    call hw_puts
    jmp .next
.done:
    add rsp,96
    pop r13
    pop r12
    pop rbx
    ret
hwc_core_scope: db " scope=core-v1 core=",0
