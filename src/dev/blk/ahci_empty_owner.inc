; Initial post-EBS native acquisition of implemented empty legacy AHCI ports.
; Private acquire is called ONLY by ahci_blk_create's original DET0 scan. It
; takes an idle receive engine into native custody by closure + real allocation
; + full64 install/readback, never by adopting or dereferencing old pointers.
; No disk/command/ST/Flush or disk-write authority is created. BSP-only.
AEO_BYTES equ 192
AEO_PORTS equ 32
AEO_POLLS equ 200
AEO_US equ 200000
; F4 (ROOT 121225, SEC 121230 S-1..S-6): firmware-latched PxIS on an idle empty port.
; One shared DHRS-only mask (BOOT's ATAPI A2b uses the same equ); any other bit refuses.
AEO_IS_STALE equ 0x1
; ahci_empty_owner_is_table: u64 claimed ABAR, u32 packed BDF, u32 latched-port bitmap,
; then 32 x {u32 original PxIS at first admission, u32 cleared mask (W1C intent)}.
AEO_IS_ABAR equ 0
AEO_IS_BDF equ 8
AEO_IS_LATCHED equ 12
AEO_IS_ENTRIES equ 16
AEO_IS_BYTES equ AEO_IS_ENTRIES+AEO_PORTS*8
; get(RDI=full-width physical port) -> RAX=record, EDX=state, CF0;
; invalid -> RAX=0 EDX=0 CF1. Other registers unchanged. No hardware/effects.
ahci_empty_owner_get:
    cmp rdi,AEO_PORTS
    jae .bad
    imul eax,edi,AEO_BYTES
    lea rdx,[rel ahci_empty_owner_table]
    add rax,rdx
    mov edx,[rax+4]
    clc
    ret
.bad:
    xor eax,eax
    xor edx,edx
    stc
    ret

; is_get(RDI=full-width physical port) -> RAX=&{u32 original PxIS, u32 cleared mask},
; EDX=1 latched this boot/0 not yet, CF0; invalid -> RAX=EDX=0, CF1. Read-only RAM query;
; other registers unchanged. The table header carries the one claimed HBA identity.
ahci_empty_owner_is_get:
    cmp rdi,AEO_PORTS
    jae .bad
    lea rax,[rel ahci_empty_owner_is_table]
    push rcx
    mov ecx,edi
    mov edx,[rax+AEO_IS_LATCHED]
    shr edx,cl
    and edx,1
    pop rcx
    lea rax,[rax+AEO_IS_ENTRIES+rdi*8]
    clc
    ret
.bad:
    xor eax,eax
    xor edx,edx
    stc
    ret

; acquire(EDI=physical port) -> EAX1 native owned,0 outside legacy scope,
; -1 refused before effects/allocation,-2 partial/unknown/already attempted.
; Preserves RBX/RBP/R12..R15. Never resets retained rows or frees allocations.
ahci_empty_owner_acquire:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    cld
    cmp byte [rel ahci_vmd_child],0
    jne .outside
    cmp edi,AEO_PORTS
    jae .invalid
    mov r13d,edi
    imul eax,edi,AEO_BYTES
    lea r12,[rel ahci_empty_owner_table]
    add r12,rax
    cmp dword [r12],0
    jne .replay
    mov dword [r12],1
    mov dword [r12+4],1                  ; captured/ineligible until final publish
    mov [r12+8],edi
    mov rax,[rel ahci_empty_owner_generation]
    mov [r12+16],rax
    mov rbx,[rel ahci_bar5]
    mov [r12+24],rbx
    mov eax,[rel ahci_busno]
    shl eax,8
    mov edx,[rel ahci_devno]
    shl edx,3
    or eax,edx
    or eax,[rel ahci_fn]
    mov [r12+32],eax
    mov eax,[rel ahci_terminal_selected_id]
    mov [r12+36],eax
    mov eax,[rel ahci_cap]
    mov [r12+44],eax
    mov eax,[rel ahci_pi]
    mov [r12+48],eax
    mov eax,r13d
    shl eax,7
    lea r14,[rbx+rax+0x100]
    mov [r12+176],r14
    mov qword [r12+184],128               ; HAL region exactly one physical port
    mov dword [r12+148],1                ; admission/time unavailable
    cmp qword [rel tsc_khz],0
    je .fail
    call time_monotonic_now_us
    mov [r12+168],rax
    add rax,AEO_US
    jc .fail
    mov [r12+160],rax
    call .fresh
    jc .fail
    mov eax,[r12+108]
    mov [r12+104],eax                    ; original CMD, never overwritten
    ; Retain raw original full64 registers only; never follow their addresses.
    xor esi,esi
    call .read64
    jc .fail
    mov [r12+88],rax
    mov esi,8
    call .read64
    jc .fail
    mov [r12+96],rax
    or dword [r12+12],1
    mov dword [r12+148],2                ; engine closure
    ; F4: exactly one W1C of the latched stale status, before any engine effect.
    lea rdx,[rel ahci_empty_owner_is_table]
    mov eax,[rdx+AEO_IS_ENTRIES+r13*8]
    test eax,eax
    jz .status_clear
    call .fresh                          ; S-3: still the latched original, no superset
    jc .fail
    lea rdx,[rel ahci_empty_owner_is_table]
    mov eax,[rdx+AEO_IS_ENTRIES+r13*8]
    cmp eax,[r12+132]
    jne .fail
    mov [rdx+AEO_IS_ENTRIES+r13*8+4],eax ; intent latched first; stale admission now OFF
    mov edx,eax                         ; the observed bits only, never all-ones
    mov esi,0x10
    call .write
    jc .fail
    ; S-4: both paths below begin with .fresh, now with the stale admission off, so
    ; PxIS must read 0 before the next effect (a re-raised DHRS refuses as partial).
.status_clear:
    test dword [r12+108],0x10
    jz .close_wait
    call .fresh
    jc .fail
    mov edx,[r12+108]
    and edx,~0x10                       ; only FRE; ST/CR/queues already idle
    mov esi,0x18
    call .write
    jc .fail
.close_wait:
    call .fresh
    jc .fail
    test dword [r12+108],0x10
    jnz .fail
    test dword [r12+108],0x4000
    jz .closed
    call .delay
    jc .fail
    jmp .close_wait
.closed:
    mov dword [r12+148],3                ; native allocation
    mov dword [r12+4],2                  ; allocator intent: zero may follow uncertain map effects
    mov edi,4096
    call dma_alloc
    mov [r12+56],rax                    ; retain actual allocator return even invalid
    mov [r12+64],rax                    ; current one-value CPU/physical/IOVA ABI
    test rax,rax
    jz .fail
    test eax,4095
    jnz .fail
    mov rdx,rax
    add rdx,4096
    jc .fail
    test dword [r12+44],AHCI_CAP_S64A
    jnz .width_ok
    mov rdx,rax
    shr rdx,32
    test rdx,rdx
    jnz .fail
.width_ok:
    add rax,0x400
    mov [r12+72],rax
    mov [r12+80],rax
    mov rdi,[r12+56]                    ; only freshly allocated CPU bytes
    xor eax,eax
    mov ecx,4096/8
    rep stosq
    or dword [r12+12],2
    mov dword [r12+148],4                ; install while FRE/FR/ST/CR all closed
    xor ebp,ebp
.install:
    call .fresh
    jc .fail
    test dword [r12+108],0xc011
    jnz .fail
    mov rax,[r12+64]
    test ebp,8
    jz .cl
    mov rax,[r12+80]
.cl:
    test ebp,4
    jz .low
    shr rax,32
.low:
    mov edx,eax
    mov esi,ebp
    call .write
    jc .fail
    add ebp,4
    cmp ebp,16
    jb .install
    call .pointers
    jc .fail
    or dword [r12+12],4
    mov dword [r12+148],5                ; native receive-only activation
    call .fresh
    jc .fail
    test dword [r12+108],0xc011
    jnz .fail
    mov edx,[r12+108]
    or edx,0x10
    mov esi,0x18
    call .write
    jc .fail
.start_wait:
    call .fresh
    jc .fail
    test dword [r12+108],0x10
    jz .fail
    test dword [r12+108],0x4000
    jnz .owned
    call .delay
    jc .fail
    jmp .start_wait
.owned:
    or dword [r12+12],8
    mov dword [r12+148],0
    mfence
    mov dword [r12+4],3                 ; publish only actual complete ownership
    mov eax,1
    jmp .out
.fail:
    mov eax,-1
    cmp dword [r12+4],2
    je .partial
    cmp dword [r12+144],0
    jne .partial
    cmp qword [r12+56],0
    jne .partial
    mov dword [r12+4],5                 ; refusal before effects/allocation
    jmp .out
.partial:
    mov dword [r12+4],4                 ; sticky uncertain; no restore/retry/free
.replay:
    mov eax,-2
    jmp .out
.outside:
    xor eax,eax
    jmp .out
.invalid:
    mov eax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Every effect is immediately preceded by .fresh: original identity/policy,
; bound architectural extent, deadline and current link/queue/IRQ/engine state.
.fresh:
    call .admit
    jc .bad
    call time_monotonic_now_us
    cmp rax,[r12+168]
    jb .bad
    cmp rax,[r12+160]
    jae .bad
%macro AEO_READ 2
    mov esi,%1
    call .read
    jc .bad
    mov [r12+%2],eax
%endmacro
    AEO_READ 0x18,108
    AEO_READ 0x28,112
    AEO_READ 0x24,116
    AEO_READ 0x38,120
    AEO_READ 0x34,124
    AEO_READ 0x14,128
    AEO_READ 0x10,132
    AEO_READ 0x40,136
    AEO_READ 0x20,140
%unmacro AEO_READ 2
    call .stale_latch
    jc .bad
    mov eax,[r12+112]
    and eax,15
    jnz .bad
    cmp dword [r12+120],0
    jne .bad
    cmp dword [r12+124],0
    jne .bad
    cmp dword [r12+128],0
    jne .bad
    call .stale_check
    jc .bad
    cmp dword [r12+136],0
    jne .bad
    test dword [r12+140],0x89
    jnz .bad
    mov eax,[r12+108]
    ; No command engine/override/ICC; preserve lower idle implementation bits.
    test eax,0xffff8009
    jnz .bad
    test dword [r12+12],4
    jnz .pointers
    clc
    ret
; First fresh read of a port this boot: bind the one claimed HBA identity and keep the
; raw firmware PxIS once (S-5). Re-entry never reaches here (row already attempted).
.stale_latch:
    lea rdx,[rel ahci_empty_owner_is_table]
    cmp dword [rdx+AEO_IS_LATCHED],0
    jne .stale_identity
    mov [rdx+AEO_IS_ABAR],rbx
    mov eax,[r12+32]
    mov [rdx+AEO_IS_BDF],eax
.stale_identity:
    cmp [rdx+AEO_IS_ABAR],rbx
    jne .bad
    mov eax,[r12+32]
    cmp eax,[rdx+AEO_IS_BDF]
    jne .bad
    bt dword [rdx+AEO_IS_LATCHED],r13d
    jc .stale_kept
    mov eax,[r12+132]
    mov [rdx+AEO_IS_ENTRIES+r13*8],eax
    bts dword [rdx+AEO_IS_LATCHED],r13d
.stale_kept:
    clc
    ret
; PxIS is 0, or (before the one W1C) exactly the latched original and DHRS only.
; IE==0 and DET==0 are already required by the caller's same fresh read (S-2).
.stale_check:
    mov eax,[r12+132]
    test eax,eax
    jz .stale_ok
    lea rdx,[rel ahci_empty_owner_is_table]
    cmp dword [rdx+AEO_IS_ENTRIES+r13*8+4],0
    jne .bad
    cmp eax,[rdx+AEO_IS_ENTRIES+r13*8]
    jne .bad
    test eax,~AEO_IS_STALE
    jnz .bad
.stale_ok:
    clc
    ret
.admit:
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
    cmp esi,[r12+32]
    jne .bad
    mov edi,5
    call native_driver_gate
    jc .bad
    xor ecx,ecx
    call .cfg
    cmp eax,[r12+36]
    jne .bad
    cmp eax,[rel ahci_terminal_selected_id]
    jne .bad
    test ax,ax
    jz .bad
    cmp ax,0xffff
    je .bad
    mov ecx,8
    call .cfg
    mov edx,eax
    shr edx,8
    cmp edx,0x010601
    jne .bad
    cmp dword [r12+40],0
    je .first_class
    cmp eax,[r12+40]
    jne .bad
.first_class:
    mov [r12+40],eax
    mov ecx,0x24
    call .cfg
    test eax,15
    jnz .bad
    cmp rax,rbx
    jne .bad
    mov ecx,4
    call .cfg
    cmp eax,-1
    je .bad
    mov [r12+52],eax
    and eax,6
    cmp eax,6
    jne .bad
    ; PCI identity and memory admission established before these HBA reads.
    lea rax,[rbx+0x1100]
    mov rdx,0x100000000
    cmp rax,rdx
    ja .bad
    mov eax,[rbx]
    cmp eax,[r12+44]
    jne .bad
    cmp eax,-1
    je .bad
    mov ecx,eax
    and ecx,31
    cmp r13d,ecx
    ja .bad
    mov eax,[rbx+12]
    cmp eax,[r12+48]
    jne .bad
    bt eax,r13d
    jnc .bad
    inc ecx
    cmp ecx,32
    je .pi_ok
    mov edx,-1
    shl edx,cl
    test eax,edx
    jnz .bad
.pi_ok:
    mov eax,[rbx+4]
    and eax,~2
    cmp eax,0x80000000
    jne .bad
    ; AHCI1.3.1 10.6: optional SMI firmware ownership is separate from EBS.
    ; BOOT owns active handoff. Never take a BIOS-owned/busy receive engine.
    mov eax,[rbx+0x24]                  ; CAP2, architectural HBA register
    test dword [r12+12],1
    jz .first_cap2
    cmp eax,[r12+156]
    jne .bad
.first_cap2:
    mov [r12+156],eax
    cmp eax,-1
    je .bad
    test eax,1                          ; CAP2.BOH absent: normal initial OS takeover
    jz .handoff_ok
    mov eax,[rbx+0x28]                  ; BOHC: require OOS, no BOS or BB
    and eax,0x13
    cmp eax,2
    jne .bad
.handoff_ok:
    clc
    ret
.cfg:
    mov edi,[rel ahci_busno]
    mov esi,[rel ahci_devno]
    mov edx,[rel ahci_fn]
    jmp pci_cfg_read32
.read:
    lea rdi,[r12+176]
    jmp hal_mmio_read32
.read64:
    push rbp
    push rsi
    call .read
    jc .read64_bad
    mov ebp,eax
    mov rsi,[rsp]
    add esi,4
    call .read
    jc .read64_bad
    shl rax,32
    or rax,rbp
    pop rsi
    pop rbp
    clc
    ret
.read64_bad:
    pop rsi
    pop rbp
    stc
    ret
.pointers:
    xor esi,esi
    call .read64
    jc .bad
    cmp rax,[r12+64]
    jne .bad
    mov esi,8
    call .read64
    jc .bad
    cmp rax,[r12+80]
    jne .bad
    clc
    ret
.write:
    ; Intent precedes call: even an unknown/rejected HAL acknowledgement is
    ; conservatively partial. Caller has just freshly qualified this effect.
    mov dword [r12+4],2
    inc dword [r12+144]
    lea rdi,[r12+176]
    jmp hal_mmio_write32
.delay:
    inc dword [r12+152]
    cmp dword [r12+152],AEO_POLLS
    jae .bad
    mov edi,1000
    call tsc_delay_us
    clc
    ret
.bad:
    stc
    ret
%include "core/abi/wdata.inc"
%macro WDATA_dev_blk_ahci_empty_owner 0
align 8
ahci_empty_owner_generation: dq 1         ; boot-local, never reset by attach
ahci_empty_owner_table: times AEO_PORTS*AEO_BYTES db 0
ahci_empty_owner_is_table: times AEO_IS_BYTES db 0   ; F4 stale-status record, written once
%endmacro
WDATA_DEFER WDATA_dev_blk_ahci_empty_owner
