; C3 common retained selectors. Called with hw_lock held; no device/firmware
; operations, allocation, ownership change or transfer. Forward symbol refs
; only: private structs stay behind their module's read-only snapshot ABI.
%macro HWC_DEC 2
    lea rdi,[rel %%key]
    call hw_puts
    mov edi,%2
    call hw_put_dec
    jmp %%end
%%key: db " ",%1,"=",0
%%end:
%endmacro
%macro HWC_BYTE 2
    movzx ebx,byte [rel %2]
    HWC_DEC %1,ebx
%endmacro
%macro HWC_BOOLPTR 2
    xor ebx,ebx
    cmp qword [rel %2],0
    setne bl
    HWC_DEC %1,ebx
%endmacro

hw_r_bindsys:
    push rbx
    sub rsp,32
    lea rdi,[rel hwc_sys_scope]
    call hw_puts
    mov rax,[rel hv_ops_active]
    xor ebx,ebx
    test rax,rax
    jz .hv
    mov ebx,3                      ; an unknown actual selector is visible
    lea rdx,[rel hv_ops_vmx]
    cmp rax,rdx
    jne .svm
    mov ebx,1
    jmp .hv
.svm:
    lea rdx,[rel hv_ops_svm]
    cmp rax,rdx
    jne .hv
    mov ebx,2
.hv:
    HWC_DEC "hv",ebx
    mov rdi,rsp
    call idle_probe_cpu_ident
    mov ebx,ecx
    shr ebx,5
    and ebx,1
    HWC_DEC "vmx",ebx
    mov ebx,[rsp+4]
    HWC_DEC "cpu",ebx
    mov eax,0x80000000
    cpuid
    xor r8d,r8d
    cmp eax,0x80000001
    jb .svm_bit
    mov eax,0x80000001
    cpuid
    mov r8d,ecx
    shr r8d,2
    and r8d,1
.svm_bit:
    mov ebx,r8d
    HWC_DEC "svm",ebx
    HWC_BYTE "vtd",vtd_ready
    mov ebx,[rel vtd_dmar_snap_len]
    HWC_DEC "dmar",ebx
    HWC_BYTE "amdvi",amdvi_owned
    HWC_BOOLPTR "ivhd",amdvi_ivhd
    call hw_iommu_render
    HWC_BYTE "ps2kbd",ps2_kbd_armed
    HWC_BYTE "ps2ctl",ps2_census_controller
    HWC_BYTE "ps2mouse",ps2_mouse_armed
    HWC_BYTE "ps2ack",ps2_mouse_acked
    HWC_BYTE "ec",ecp_active
    call ecp_census_match
    mov ebx,eax
    HWC_DEC "ecmatch",ebx
    xor ebx,ebx
    cmp qword [rel gop_proto],0
    setne bl
    HWC_DEC "gop",ebx
    mov ebx,[rel fb_width]
    HWC_DEC "width",ebx
    mov ebx,[rel fb_height]
    HWC_DEC "height",ebx
    mov ebx,[rel gop_selected_pci_nodes]
    HWC_DEC "gop_pci",ebx
    mov ebx,[rel gop_census_path_state]
    HWC_DEC "gop_path_state",ebx
    mov ebx,[rel gop_census_root_hid]
    HWC_DEC "gop_root_hid",ebx
    mov ebx,[rel gop_census_root_uid]
    HWC_DEC "gop_root_uid",ebx
    mov ebx,[rel gop_census_path_n]
    HWC_DEC "gop_path_n",ebx
    mov dword [rsp+24],0
.path:
    mov eax,[rsp+24]
    cmp eax,[rel gop_census_path_n]
    jae .path_done
    cmp eax,16
    jae .path_done
    lea rdx,[rel gop_census_path]
    movzx ebx,byte [rdx+rax]
    HWC_DEC "gop_path",ebx
    inc dword [rsp+24]
    jmp .path
.path_done:
    mov ebx,[rel gop_census_pci+0]
    HWC_DEC "gop_pci_state",ebx
    mov ebx,[rel gop_census_pci+4]
    HWC_DEC "gop_segment",ebx
    mov ebx,[rel gop_census_pci+8]
    HWC_DEC "gop_bdf",ebx
    mov ebx,[rel gop_census_pci+12]
    HWC_DEC "gop_id",ebx
    mov ebx,[rel gop_census_pci+16]
    HWC_DEC "gop_class",ebx
    mov ebx,[rel gop_census_pci+20]
    HWC_DEC "gop_revision",ebx
    lea rdi,[rel hwc_sys_missing]
    call hw_puts
    add rsp,32
    pop rbx
    ret
hwc_sys_scope: db " scope=retained-v1",0
hwc_sys_missing: db " audio=unobserved",0

hw_r_bindvmd:
    push rbx
    push r12
    push r13
    sub rsp,32
    lea rdi,[rel hwc_vmd_scope]
    call hw_puts
    mov ebx,[rel vmd_root_bus]
    shl ebx,8
    mov eax,[rel vmd_root_dev]
    shl eax,3
    or ebx,eax
    or ebx,[rel vmd_root_fn]
    HWC_DEC "root",ebx
    movzx r12d,byte [rel vmd_child_count]
    HWC_DEC "n",r12d
    xor r13d,r13d
.next:
    cmp r13d,r12d
    jae .done
    cmp r13d,8
    jae .done                     ; invalid count stays explicit n > rows
    mov edi,r13d
    mov rsi,rsp
    call vmd_child_identity_snapshot
    test eax,eax
    jz .advance                   ; n mismatch exposes absent/corrupt record
    lea rdi,[rel hwc_child]
    call hw_puts
    mov edi,r13d
    call hw_put_dec
    lea rdi,[rel str_hw_comma]
    call hw_puts
    mov edi,[rsp+20]               ; domain-relative BDF, never ordinary PCI BDF
    call hw_put_dec
    lea rdi,[rel str_hw_comma]
    call hw_puts
    mov edi,[rsp+25]               ; unaligned cached actual vendor/device
    call hw_put_dec
    lea rdi,[rel str_hw_comma]
    call hw_puts
    mov edi,[rsp+16]
    call hw_put_dec
    lea rdi,[rel str_hw_comma]
    call hw_puts
    movzx edi,byte [rsp+29]
    call hw_put_dec
    xor ebx,ebx
    cmp byte [rel ahci_vmd_child],1
    jne .ahci
    mov rax,[rsp+8]
    cmp rax,[rel ahci_bar5]
    sete bl
.ahci:
    lea rdi,[rel str_hw_comma]
    call hw_puts
    mov edi,ebx
    call hw_put_dec
    xor ebx,ebx
    cmp byte [rel nvme_vmd_child],1
    jne .nvme
    mov rax,[rsp]
    cmp rax,[rel nvme_vmd_cfg]
    sete bl
.nvme:
    lea rdi,[rel str_hw_comma]
    call hw_puts
    mov edi,ebx
    call hw_put_dec
.advance:
    inc r13d
    jmp .next
.done:
    add rsp,32
    pop r13
    pop r12
    pop rbx
    ret
hwc_vmd_scope: db " scope=vmd-child-v1",0
hwc_child: db " child=",0

%include "svc/hw_iommu_census.inc"
