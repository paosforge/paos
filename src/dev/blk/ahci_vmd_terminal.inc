; Original selected VMD route for the existing terminal HBA leaf. No root
; writes, reset, rebind, inventory or Flush. Cached provenance is RAM only;
; fresh native policy/root config precedes child ECAM, then exact child config
; precedes each existing HBA effect. EAX/CF status never comes from report bytes.
%include "core/abi/vmd_selected_root.inc"

ahci_vmd_terminal_reset:
    lea rdi,[rel ahci_vmd_terminal_observations]
    mov ecx,480/8
    xor eax,eax
    rep stosq
    ret

ahci_vmd_terminal_prepare:
    lea rdi,[rel ahci_vmd_terminal_observations]
    mov dword [rdi],1
    mov dword [rdi+8],3                  ; actual API returns unavailable until attempted
    mov dword [rdi+12],3
    mov dword [rdi+16],1
    mov dword [rdi+160],1
    mov dword [rdi+164],1
    mov dword [rdi+168],3
    mov dword [rdi+172],128
    mov dword [rdi+320],1
    mov dword [rdi+324],2
    mov dword [rdi+152],1                ; explicit VMD route, never legacy BDF
    lea rdi,[rel ahci_vmd_terminal_observations+192]
    call ahci_vmd_owner_snapshot
    mov [rel ahci_vmd_terminal_observations+12],eax
    mov [rel ahci_vmd_terminal_observations+168],eax
    or dword [rel ahci_vmd_terminal_observations+16],2
    lea rdi,[rel ahci_vmd_terminal_observations+32]
    call vmd_selected_root_snapshot
    mov [rel ahci_vmd_terminal_observations+8],eax
    or dword [rel ahci_vmd_terminal_observations+16],4
    cmp eax,1
    jne .bad
    cmp dword [rel ahci_vmd_terminal_observations+12],1
    jne .bad
    push rbp
    push r12
    lea rbp,[rel ahci_vmd_terminal_observations+32]
    lea r12,[rel ahci_vmd_terminal_observations+192]
    cmp dword [rbp+VSR_SCHEMA],1
    jne .pop_bad
    cmp dword [rbp+VSR_FLAGS],1
    jne .pop_bad
    cmp dword [rbp+VSR_RESERVED],0
    jne .pop_bad
    cmp dword [r12+VSO_SCHEMA],1
    jne .pop_bad
    cmp dword [r12+VSO_FLAGS],1
    jne .pop_bad
    mov rax,[rbp+VSR_DOMAIN]
    test rax,rax
    jz .pop_bad
    cmp rax,[r12+VSO_DOMAIN]
    jne .pop_bad
    cmp qword [r12+VSO_ATTACH],0
    je .pop_bad
%macro AV_JOIN 3
    mov %1,[rbp+%2]
    cmp %1,[r12+%3]
    jne .pop_bad
%endmacro
    AV_JOIN eax,VSR_BUS,VSO_ROOT_BUS
    AV_JOIN eax,VSR_DEV,VSO_ROOT_DEV
    AV_JOIN eax,VSR_FN,VSO_ROOT_FN
    AV_JOIN rax,VSR_CFGBAR,VSO_ROOTBAR
    AV_JOIN rax,VSR_ECAM,VSO_ECAM
    AV_JOIN rax,VSR_WINDOW_GB,VSO_WINDOW_GB
%unmacro AV_JOIN 3
    cmp dword [rbp+VSR_BUS],255
    ja .pop_bad
    cmp dword [rbp+VSR_DEV],31
    ja .pop_bad
    cmp dword [rbp+VSR_FN],7
    ja .pop_bad
    mov eax,[rbp+VSR_PCI_ID]
    cmp ax,0x8086
    jne .pop_bad
    mov eax,[rbp+VSR_CLASSREV]
    shr eax,8
    cmp eax,0x010400
    jne .pop_bad
    cmp dword [r12+VSO_CLASS],0x010601
    jne .pop_bad
    cmp dword [r12+VSO_REVISION],255
    ja .pop_bad
    cmp dword [r12+VSO_VMCAP],-1
    je .pop_bad
    cmp dword [r12+VSO_VMCONFIG],-1
    je .pop_bad
    cmp dword [r12+VSO_MAPPED],1
    jne .pop_bad
    cmp dword [r12+VSO_ROOT_COUNT],0
    je .pop_bad
    cmp dword [r12+VSO_INDEX],8
    jae .pop_bad
    mov eax,[r12+VSO_PCI_ID]
    test ax,ax
    jz .pop_bad
    cmp ax,0xffff
    je .pop_bad
    mov [r13+136],eax                    ; original actual selected child ID
    mov rax,[r12+VSO_BAR]
    cmp rax,[r13+64]
    jne .pop_bad
    mov eax,[r12+VSO_CHILD_BDF]
    mov [rel ahci_vmd_terminal_observations+336],eax
    test eax,~0xff1f07
    jnz .pop_bad
    mov ecx,eax
    shr ecx,16
    mov edx,[r12+VSO_BUSES]
    test edx,edx
    jz .pop_bad
    cmp edx,32
    ja .pop_bad
    cmp ecx,edx
    jae .pop_bad
    shl rcx,20
    mov esi,eax
    shr esi,8
    and esi,31
    shl rsi,15
    add rcx,rsi
    and eax,7
    shl rax,12
    add rcx,rax
    mov rax,[rbp+VSR_ECAM]
    cmp rax,[rbp+VSR_CFGBAR]
    jne .pop_bad
    cmp rax,0x1000
    jb .pop_bad
    test eax,0xfffff
    jnz .pop_bad
    mov [rel ahci_vmd_terminal_observations+128],rax
    shl rdx,20
    mov [rel ahci_vmd_terminal_observations+136],rdx
    add rdx,rax
    jc .pop_bad
    mov rsi,0x800000000000               ; existing lower canonical identity route
    cmp rdx,rsi
    ja .pop_bad
    mov rsi,0x400000000                 ; original low16GiB mapping
    cmp rdx,rsi
    jbe .reachable
    mov rsi,[rbp+VSR_WINDOW_GB]
    test rsi,rsi
    jz .pop_bad
    cmp rsi,0x1ffff
    ja .pop_bad
    shl rsi,30
    cmp rax,rsi
    jb .pop_bad
    mov rdi,0x80000000                   ; original two-GiB window, whole extent
    add rsi,rdi
    cmp rdx,rsi
    ja .pop_bad
.reachable:
    add rcx,rax
    jc .pop_bad
    cmp rcx,[r12+VSO_CFG]
    jne .pop_bad
    mov [rel ahci_vmd_terminal_observations+384],rcx
    mov qword [rel ahci_vmd_terminal_observations+392],0x1000
    add rcx,0x1000
    jc .pop_bad
    cmp rcx,rdx
    ja .pop_bad
    or dword [rel ahci_vmd_terminal_observations+16],24
    pop r12
    pop rbp
    clc
    ret
.pop_bad:
    pop r12
    pop rbp
.bad:
    stc
    ret

; Refresh independent same-lifetime API returns and compare their entire raw
; records to the per-call originals. Keep originals even when a new lifetime
; is now available. The mismatch stage remains independently observable.
ahci_vmd_terminal_current:
    lea rdi,[rel ahci_vmd_terminal_child_now]
    call ahci_vmd_owner_snapshot
    mov [rel ahci_vmd_terminal_observations+12],eax
    mov [rel ahci_vmd_terminal_observations+168],eax
    cmp eax,1
    jne .bad
    lea rsi,[rel ahci_vmd_terminal_child_now]
    lea rdi,[rel ahci_vmd_terminal_observations+192]
    mov ecx,16
    repe cmpsq
    jne .bad
    lea rdi,[rel ahci_vmd_terminal_root_now]
    call vmd_selected_root_snapshot
    mov [rel ahci_vmd_terminal_observations+8],eax
    cmp eax,1
    jne .bad
    lea rsi,[rel ahci_vmd_terminal_root_now]
    lea rdi,[rel ahci_vmd_terminal_observations+32]
    mov ecx,8
    repe cmpsq
    jne .bad
    clc
    ret
.bad:
    stc
    ret

; Fresh supported original selected root, read-only PCI. No ECAM touched until
; this entire check passes. Unknown-domain policy uses the original RSI=-1;
; an ECAM-relative child is never a segment0 policy candidate.
ahci_vmd_terminal_root_admit:
    push rbp
    lea rbp,[rel ahci_vmd_terminal_observations+32]
    inc dword [rel ahci_vmd_terminal_observations+24]
    mov dword [rel ahci_vmd_terminal_observations+28],0
    and dword [rel ahci_vmd_terminal_observations+16],~32
    mov dword [rel ahci_vmd_terminal_observations+124],1
    cmp qword [rel ahci_power_gate],0
    jne .bad
    cmp qword [rel ahci_power_command_gate],0
    jne .bad
    call ahci_vmd_terminal_current
    jc .bad
    mov edi,5
    mov rsi,-1
    call native_driver_gate
    jc .bad
%macro AV_ROOT_READ 3
    mov dword [rel ahci_vmd_terminal_observations+124],%3
    mov ecx,%1
    call .cfg
    mov [rel ahci_vmd_terminal_observations+%2],eax
    bts dword [rel ahci_vmd_terminal_observations+28],%3-2
%endmacro
    AV_ROOT_READ 0,96,2
    cmp eax,[rbp+VSR_PCI_ID]
    jne .bad
    AV_ROOT_READ 8,100,3
    cmp eax,[rbp+VSR_CLASSREV]
    jne .bad
    AV_ROOT_READ 0x10,104,4
    test al,1
    jnz .bad
    mov edx,eax
    and edx,6
    cmp edx,0
    je .bar32
    cmp edx,4
    jne .bad
    AV_ROOT_READ 0x14,108,5
    mov edx,eax
    shl rdx,32
    jmp .bar
.bar32:
    xor edx,edx
    mov dword [rel ahci_vmd_terminal_observations+108],0
.bar:
    mov eax,[rel ahci_vmd_terminal_observations+104]
    and eax,0xfffffff0
    or rax,rdx
    cmp rax,[rbp+VSR_CFGBAR]
    jne .bad
    AV_ROOT_READ 4,112,6
    cmp eax,-1
    je .bad
    test eax,2
    jz .bad
    AV_ROOT_READ 0x40,116,7
    cmp eax,[rel ahci_vmd_terminal_observations+192+VSO_VMCAP]
    jne .bad
    AV_ROOT_READ 0x44,120,8
    cmp eax,[rel ahci_vmd_terminal_observations+192+VSO_VMCONFIG]
    jne .bad
    mov dword [rel ahci_vmd_terminal_observations+124],0
    or dword [rel ahci_vmd_terminal_observations+16],32
    pop rbp
    clc
    ret
.cfg:
    mov edi,[rbp+VSR_BUS]
    mov esi,[rbp+VSR_DEV]
    mov edx,[rbp+VSR_FN]
    jmp pci_cfg_read32
.bad:
    pop rbp
    stc
    ret
%unmacro AV_ROOT_READ 3

ahci_vmd_terminal_admit:
    call ahci_vmd_terminal_hardware_admit
    jc .bad
    cmp dword [rel ahci_boh_terminal_observations],2
    jne .bad                            ; no initial transfer observation is not ownership
    jmp ahci_boh_terminal_admit
.bad:
    stc
    ret

; The same accepted fresh root/child checks also qualify the original initial
; ownership transfer, before any HBA access. No firmware check recurses here.
ahci_vmd_terminal_hardware_admit:
    call ahci_vmd_terminal_root_admit
    jc .bad
    inc dword [rel ahci_vmd_terminal_observations+376]
    mov dword [rel ahci_vmd_terminal_observations+332],0
    and dword [rel ahci_vmd_terminal_observations+16],~64
%macro AV_CHILD_READ 3
    mov ecx,%1
    call ahci_vmd_terminal_child_read
    jc .bad
    mov [rel ahci_vmd_terminal_observations+%2],eax
    mov [r13+%3],eax
%endmacro
    AV_CHILD_READ 0,340,140
    or dword [rel ahci_vmd_terminal_observations+332],1
    cmp eax,[r13+136]
    jne .bad
    AV_CHILD_READ 8,344,144
    or dword [rel ahci_vmd_terminal_observations+332],2
    mov edx,[rel ahci_vmd_terminal_observations+192+VSO_CLASS]
    shl edx,8
    or edx,[rel ahci_vmd_terminal_observations+192+VSO_REVISION]
    cmp eax,edx
    jne .bad
    AV_CHILD_READ 0x24,348,148
    or dword [rel ahci_vmd_terminal_observations+332],4
    test eax,15
    jnz .bad
    cmp rax,rbx
    jne .bad
    AV_CHILD_READ 4,352,152
    or dword [rel ahci_vmd_terminal_observations+332],8
    cmp eax,-1
    je .bad
    test eax,2
    jz .bad
    or dword [rel ahci_vmd_terminal_observations+16],64
    clc
    ret
.bad:
    stc
    ret
%unmacro AV_CHILD_READ 3

; ECX child register; exact original function-local 4KiB extent, with explicit
; local bounds even when the HAL bring-up bypass is active.
ahci_vmd_terminal_child_read:
    cmp ecx,0xffc
    ja .bad
    test ecx,3
    jnz .bad
    lea rdi,[rel ahci_vmd_terminal_observations+384]
    mov esi,ecx
    jmp hal_mmio_read32
.bad:
    mov eax,-1
    stc
    ret

; Original caller post-read: fresh root/lifetime/policy before child access.
ahci_vmd_terminal_cfg_read:
    push rcx
    call ahci_vmd_terminal_root_admit
    pop rcx
    jc .bad
    push rcx
    call ahci_vmd_terminal_child_read
    pop rcx
    jc .bad
    cmp ecx,4
    jne .identity
    mov [rel ahci_vmd_terminal_observations+360],eax
    or dword [rel ahci_vmd_terminal_observations+368],1
    or dword [rel ahci_vmd_terminal_observations+16],256
    ret
.identity:
    test ecx,ecx
    jnz .done
    mov [rel ahci_vmd_terminal_observations+364],eax
    or dword [rel ahci_vmd_terminal_observations+368],2
.done:
    ret
.bad:
    mov eax,-1
    stc
    ret

; EDX requested low16 Command. HAL accepted write16 never replays Status.
; Existing immediate .admit already qualified current root+child before effect.
ahci_vmd_terminal_command:
    mov [rel ahci_vmd_terminal_observations+356],edx
    mov dword [rel ahci_vmd_terminal_observations+144],16
    mov esi,4
    lea rdi,[rel ahci_vmd_terminal_observations+384]
    call hal_mmio_write16
    jc .bad
    or dword [rel ahci_vmd_terminal_observations+16],128
    mov dword [rel ahci_vmd_terminal_observations+372],1
    clc
    ret
.bad:
    stc
    ret
align 8
ahci_vmd_terminal_observations: times 480 db 0
ahci_vmd_terminal_child_now: times 128 db 0
ahci_vmd_terminal_root_now: times 64 db 0
