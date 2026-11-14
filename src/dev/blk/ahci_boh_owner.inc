; Original selected legacy initial BIOS/OS ownership transfer, before GHC/ports.
; No DMA/command/Flush/reset, no forced BIOS/BB clear. BSP initial attach only.
; Raw original capture and passive same-terminal copy are separate160B records.
ABOH_US equ 2025000
ABOH_POLLS equ 2026
ahci_boh_owner_acquire:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    cld
    lea r12,[rel ahci_boh_observations]
    mov rdi,r12
    mov ecx,160/8
.zero:
    cmp qword [rdi],0
    jne .replay
    add rdi,8
    loop .zero
    mov dword [r12],1
    mov dword [r12+4],4
    mov dword [r12+8],-1
    mov dword [r12+12],-1
    mov dword [r12+20],1
    mov dword [r12+92],1
    mov rax,[rel ahci_boh_attempt]
    cmp rax,-1
    je .fail
    inc rax
    mov [rel ahci_boh_attempt],rax
    mov [r12+24],rax
    mov rbx,[rel ahci_bar5]
    mov [r12+32],rbx
    mov qword [r12+40],0x100
    mov eax,[rel ahci_busno]
    shl eax,8
    mov edx,[rel ahci_devno]
    shl edx,3
    or eax,edx
    or eax,[rel ahci_fn]
    mov [r12+48],eax
    mov eax,[rel ahci_terminal_selected_id]
    mov [r12+52],eax
    or dword [r12+16],1
    cmp byte [rel ahci_vmd_child],1
    jne .legacy_selected
    call ahci_vmd_boh_begin              ; original root/child capture, before ownership MMIO
    jc .fail
.legacy_selected:
    cmp qword [rel tsc_khz],0
    je .initial
    call time_monotonic_now_us
    mov [r12+96],rax
    mov [r12+112],rax
    add rax,ABOH_US
    jc .fail
    mov [r12+104],rax
    or dword [r12+16],64
.initial:
    call .sample
    jc .fail
    test dword [r12+60],1
    jz .not_required
    mov edx,eax
    and edx,0x13
    cmp edx,2
    je .owned
    ; Ownership already requested is observed, never rewritten or invented.
    test eax,2
    jnz .wait
    test dword [r12+16],64
    jz .fail
    mov dword [r12+92],2
    call .sample                         ; fresh policy/PCI/CAP2/BOHC before request
    jc .fail
    test eax,2
    jnz .wait
    mov ebp,eax
    call time_monotonic_now_us            ; request window starts at actual OOS intent
    cmp rax,[r12+112]
    jb .fail
    mov [r12+96],rax
    mov [r12+112],rax
    add rax,ABOH_US
    jc .fail
    mov [r12+104],rax
    mov eax,ebp
    and eax,~8                           ; OOC is W1C: do not acknowledge it
    or eax,2                             ; set OOS, retain observed BOS/BB/SOOE
    mov [r12+76],eax
    mov dword [r12+80],1                  ; intent BEFORE actual HAL write
    mov dword [r12+20],2
    or dword [r12+16],16
    mov edx,eax
    lea rdi,[r12+32]
    mov esi,0x28
    call hal_mmio_write32
    jc .fail
.wait:
    mov dword [r12+92],3
    cmp dword [r12+84],ABOH_POLLS
    jae .fail
    inc dword [r12+84]                    ; actual wait poll attempts, excluding admissions
    call .sample
    jc .fail
    mov edx,eax
    and edx,0x13
    cmp edx,2
    je .owned
    test dword [r12+16],64
    jz .fail
    test dword [r12+16],128
    jnz .delay
    mov rax,[r12+112]
    sub rax,[r12+96]
    cmp rax,25000
    jae .fail                           ; no observed BB: refuse rather than force takeover
.delay:
    cmp dword [r12+88],2025
    jae .fail
    inc dword [r12+88]
    mov edi,1000
    call tsc_delay_us
    jmp .wait
.not_required:
    mov dword [r12+20],6
    xor eax,eax
    jmp .complete
.owned:
    mov dword [r12+20],3
    mov eax,1
.complete:
    mov dword [r12+92],4
    mov [r12+12],eax
    jmp .out
.replay:
    cmp dword [r12+136],-1
    je .replayed
    inc dword [r12+136]
.replayed:
    mov dword [r12+20],4
    mov eax,-2
    mov [r12+12],eax
    jmp .out
.fail:
    mov dword [r12+20],5
    mov eax,-1
    cmp dword [r12+80],0
    je .failed
    mov dword [r12+20],4
    mov eax,-2
.failed:
    mov [r12+12],eax
    jmp .out
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret
.sample:
    sub rsp,8
    call ahci_boh_initial_admit
    jc .bad
    test dword [r12+16],64
    jz .cap2
    call time_monotonic_now_us
    cmp rax,[r12+112]
    jb .bad                             ; monotonic last value, not just start
    mov [r12+112],rax
    cmp rax,[r12+104]
    jae .bad
.cap2:
    lea rdi,[r12+32]
    mov esi,0x24
    call hal_mmio_read32
    jc .bad
    mov [r12+64],eax
    test dword [r12+16],4
    jnz .same_cap2
    mov [r12+60],eax
    or dword [r12+16],4
.same_cap2:
    cmp eax,-1
    je .bad
    cmp eax,[r12+60]
    jne .bad
    test eax,1
    jz .sample_ok
    lea rdi,[r12+32]
    mov esi,0x28
    call hal_mmio_read32
    jc .bad
    mov [r12+72],eax
    test dword [r12+16],8
    jnz .bohc_seen
    mov [r12+68],eax
    or dword [r12+16],8
.bohc_seen:
    cmp dword [r12+80],0
    je .known
    or dword [r12+16],32
.known:
    test eax,~0x1f
    jnz .bad
    test eax,0x10
    jz .sample_ok
    test dword [r12+16],128
    jnz .sample_ok
    test dword [r12+16],64
    jz .sample_ok
    mov rdx,[r12+112]
    mov [r12+120],rdx
    or dword [r12+16],128
.sample_ok:
    add rsp,8
    clc
    ret
.bad:
    add rsp,8
    stc
    ret

; Fresh exact original selected legacy admission BEFORE each ownership MMIO phase.
; R12 actual retained original record, RBX original selected BAR.
ahci_boh_initial_admit:
    cmp dword [r12],2
    je ahci_vmd_boh_initial_admit
    sub rsp,8
    cmp byte [rel ahci_claim_legacy],1
    jne .bad
    cmp byte [rel ahci_vmd_child],0
    jne .bad
    cmp qword [rel ahci_power_gate],0
    jne .bad
    cmp qword [rel ahci_power_command_gate],0
    jne .bad
    cmp [rel ahci_bar5],rbx
    jne .bad
    cmp rbx,0x1000
    jb .bad
    test ebx,15
    jnz .bad
    lea rax,[rbx+0x100]
    mov rdx,0x100000000
    cmp rax,rdx
    ja .bad
    cmp dword [rel ahci_busno],255
    ja .bad
    cmp dword [rel ahci_devno],31
    ja .bad
    cmp dword [rel ahci_fn],7
    ja .bad
    mov esi,[rel ahci_busno]
    shl esi,8
    mov eax,[rel ahci_devno]
    shl eax,3
    or esi,eax
    or esi,[rel ahci_fn]
    cmp esi,[r12+48]
    jne .bad
    mov edi,5
    call native_driver_gate
    jc .bad
    xor ecx,ecx
    call .cfg
    cmp eax,-1
    je .bad
    test ax,ax
    jz .bad
    cmp ax,0xffff
    je .bad
    cmp eax,[r12+52]
    jne .bad
    cmp eax,[rel ahci_terminal_selected_id]
    jne .bad
    mov ecx,8
    call .cfg
    mov edx,eax
    shr edx,8
    cmp edx,0x010601
    jne .bad
    test dword [r12+16],2
    jz .first_class
    cmp eax,[r12+56]
    jne .bad
.first_class:
    mov [r12+56],eax
    mov ecx,0x24
    call .cfg
    test eax,15
    jnz .bad
    cmp rax,rbx
    jne .bad
    mov ecx,4
    call .cfg
    mov [r12+132],eax
    cmp eax,-1
    je .bad
    test eax,2
    jz .bad
    test dword [r12+16],2
    jnz .admitted
    mov [r12+128],eax
.admitted:
    or dword [r12+16],2
    add rsp,8
    clc
    ret
.cfg:
    mov edi,[rel ahci_busno]
    mov esi,[rel ahci_devno]
    mov edx,[rel ahci_fn]
    jmp pci_cfg_read32
.bad:
    add rsp,8
    stc
    ret

; RAM only: prepare original same-call passive report before any inactive return.
; EAX0/CF0 eligible or old no-attempt, -1/-2/CF1 actual refusal/uncertainty.
ahci_boh_terminal_prepare:
    push rbx
    push r12
    cld
    lea r12,[rel ahci_boh_terminal_observations]
    mov rdi,r12
    lea rsi,[rel ahci_boh_observations]
    mov ecx,160/8
    rep movsq
    cmp dword [r12],0
    jne .seen
    mov rdi,r12
    mov ecx,160/8
.zero:
    cmp qword [rdi],0
    jne .refused
    add rdi,8
    loop .zero
    xor eax,eax
    jmp .ok
.seen:
    call ahci_boh_snapshot_binding
    jc .refused
    cmp dword [r12+136],0
    jne .refused
    cmp dword [r12+20],6
    je .not_required
    cmp dword [r12+20],3
    jne .refused
    cmp dword [r12+12],1
    jne .refused
    test dword [r12+60],1
    jz .refused
    test dword [r12+16],8
    jz .refused
    mov eax,[r12+72]
    test eax,~0x1f
    jnz .refused
    and eax,0x13
    cmp eax,2
    jne .refused
    jmp .qualified
.not_required:
    cmp dword [r12+12],0
    jne .refused
    test dword [r12+60],1
    jnz .refused
    cmp dword [r12+80],0
    jne .refused
.qualified:
    mov dword [r12+156],-1               ; current terminal guard not yet observed
    xor eax,eax
.ok:
    clc
    pop r12
    pop rbx
    ret
.refused:
    mov eax,-1
    cmp dword [r12+80],0
    jne .uncertain
    cmp dword [r12+20],2
    je .uncertain
    cmp dword [r12+20],4
    jne .bad
.uncertain:
    mov eax,-2
.bad:
    stc
    pop r12
    pop rbx
    ret

; Bound original snapshot, never cached identity alone as device/I/O ownership.
ahci_boh_snapshot_binding:
    cmp dword [r12],2
    je ahci_vmd_boh_snapshot_binding
    cmp dword [r12],1
    jne .bad
    cmp dword [r12+4],4
    jne .bad
    cmp dword [r12+8],-1
    jne .bad
    mov eax,[r12+16]
    and eax,7
    cmp eax,7
    jne .bad
    mov rax,[r12+24]
    test rax,rax
    jz .bad
    cmp rax,[rel ahci_boh_attempt]
    jne .bad
    cmp qword [r12+40],0x100
    jne .bad
    cmp byte [rel ahci_claim_legacy],1
    jne .bad
    cmp byte [rel ahci_vmd_child],0
    jne .bad
    mov rax,[rel ahci_bar5]
    cmp rax,[r12+32]
    jne .bad
    mov eax,[rel ahci_terminal_selected_id]
    cmp eax,[r12+52]
    jne .bad
    mov eax,[rel ahci_busno]
    shl eax,8
    mov edx,[rel ahci_devno]
    shl edx,3
    or eax,edx
    or eax,[rel ahci_fn]
    cmp eax,[r12+48]
    jne .bad
    mov eax,[r12+60]
    cmp eax,-1
    je .bad
    cmp eax,[r12+64]
    jne .bad
    cmp dword [r12+80],1
    ja .bad
    cmp dword [r12+84],ABOH_POLLS
    ja .bad
    cmp dword [r12+88],2025
    ja .bad
    clc
    ret
.bad:
    stc
    ret

; Called only after original fresh terminal policy/PCI/MSE admission, before
; every native terminal effect. Current values are captured by the actual guard.
ahci_boh_terminal_admit:
    push r12
    lea r12,[rel ahci_boh_terminal_observations]
    cmp dword [r12],0
    je .ok
    mov dword [r12+156],-1
    cmp dword [r12+140],-1
    je .bad
    inc dword [r12+140]
    call ahci_boh_snapshot_binding
    jc .bad
    mov rax,[r13+64]
    cmp rax,[r12+32]
    jne .bad
    mov eax,[r13+136]
    cmp eax,[r12+52]
    jne .bad
    mov eax,[r13+144]
    cmp eax,[r12+56]
    jne .bad
    or dword [r12+152],1
    lea rdi,[r12+32]
    mov esi,0x24
    call hal_mmio_read32
    jc .bad
    mov [r12+144],eax
    or dword [r12+152],2
    cmp eax,[r12+60]
    jne .bad
    test eax,1
    jz .ready
    lea rdi,[r12+32]
    mov esi,0x28
    call hal_mmio_read32
    jc .bad
    mov [r12+148],eax
    or dword [r12+152],4
    test eax,~0x1f
    jnz .bad
    and eax,0x13
    cmp eax,2
    jne .bad
.ready:
    mov dword [r12+156],0
.ok:
    clc
    pop r12
    ret
.bad:
    stc
    pop r12
    ret

%include "core/abi/wdata.inc"
%macro WDATA_dev_blk_ahci_boh_owner 0
align 8
ahci_boh_attempt: dq 0
ahci_boh_observations: times 160 db 0
ahci_boh_terminal_observations: times 160 db 0
%endmacro
WDATA_DEFER WDATA_dev_blk_ahci_boh_owner
