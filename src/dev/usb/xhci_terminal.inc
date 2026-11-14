; Original terminal-only controller ownership effect. No participant/context is
; fabricated. The BSP caller owns IF0 and the original USBMSD terminal fence.
; See XHCI_TERMINAL_STOP.md. All records are outside the swapped owner images.
XT_BYTES equ 160
XT_MAX equ XHCI_INST_MAX + XHCI_CAND_MAX + 1
XT_TOTAL equ (XT_MAX + 1) * XT_BYTES

; EAX0 original inactive /1 observed stopped /-1 no-effect refusal /-2 uncertain.
; Preserve native callee registers and flags (including IF/DF). No reset, image
; switch, event consumption, resource release or original owner-state mutation.
xhci_terminal_quiesce:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    cld
    lea r13,[rel xhci_terminal_observations]
    mov rdi,r13
    mov ecx,XT_TOTAL/8
    xor eax,eax
    rep stosq
    lea rdi,[rel xhci_terminal_firmware_observations]
    mov ecx,XT_TOTAL/8
    rep stosq
    mov dword [r13],1
    mov dword [r13+12],-1
    mov eax,[rel xhci_inst_n]
    mov [r13+20],eax
    mov eax,[rel xhci_inst_cur]
    mov [r13+24],eax
    xor eax,eax
    cmp qword [rel reinit_power_xhci_context],0
    setne al
    mov [r13+36],eax
    or dword [r13+16],1
    cmp dword [rel xhci_terminal_latched],0
    jne .replay
    test eax,eax
    jnz .refused
    cmp dword [r13+20],XHCI_INST_MAX
    ja .refused
    cmp dword [r13+20],0
    jne .registered_header
    cmp dword [r13+24],0
    jne .refused
    jmp .work_guards
.registered_header:
    mov eax,[r13+24]
    cmp eax,[r13+20]
    jae .refused
.work_guards:
    call xhci_power_command_guard
    test eax,eax
    jnz .refused
    call xhci_power_iso_guard
    test eax,eax
    jnz .refused
    or dword [r13+16],2
    xor r14d,r14d
.images:
    lea rbp,[rel xhci_inst_r1]
    cmp r14d,[r13+24]
    je .image
    imul eax,r14d,XHCI_INST_BYTES
    lea rbp,[rel xhci_inst_save]
    add rbp,rax
.image:
    cmp dword [r13+20],0
    jne .registered_image
    ; n0 is not absence. Observe every original pre-registration allocation
    ; and stage in actual LIVE before deciding that this image is inactive.
    xor edx,edx
%assign XT_RAM_BIT 0
%macro XT_PARTIAL 1
    cmp qword [rbp+%1-xhci_inst_r1],0
    je %%zero
    bts edx,XT_RAM_BIT
%%zero:
%assign XT_RAM_BIT XT_RAM_BIT+1
%endmacro
    XT_PARTIAL xhci_region
    XT_PARTIAL xhci_region+8
    XT_PARTIAL xhci_dcbaa
    XT_PARTIAL xhci_cmd_ring
    XT_PARTIAL xhci_evt_ring
    XT_PARTIAL xhci_erst
    XT_PARTIAL xhci_out_ctx
    XT_PARTIAL xhci_in_ctx_base
    XT_PARTIAL xhci_ep0_base
    XT_PARTIAL xhci_scr_arr_base
    XT_PARTIAL xhci_dma_set
    XT_PARTIAL xhci_scratch_pages
    XT_PARTIAL xhci_xfer_dma
%unmacro XT_PARTIAL 1
    cmp dword [rbp+xhci_generation-xhci_inst_r1],0
    je .partial_stage
    or edx,1<<13
.partial_stage:
    cmp dword [rbp+xhci_init_phase-xhci_inst_r1],0
    je .partial_observed
    or edx,1<<14
.partial_observed:
    mov [r13+40],edx                 ; original partial presence bits, observed
    or dword [r13+16],4
    test edx,edx
    jz .retained
    mov edi,2
    jmp .add_image
.registered_image:
    mov edi,1
.add_image:
    mov esi,r14d
    call .new_record
    jc .refused
    mov eax,[rbp+xhci_generation-xhci_inst_r1]
    mov [r12+36],eax
    cmp dword [r12+4],1
    jne .image_fields
    test eax,eax
    jz .refused
.image_fields:
    mov eax,[rbp+xhci_bus-xhci_inst_r1]
    mov [r12+44],eax
    mov eax,[rbp+xhci_dev-xhci_inst_r1]
    mov [r12+48],eax
    mov eax,[rbp+xhci_fn-xhci_inst_r1]
    mov [r12+52],eax
    mov rax,[rbp+xhci_region-xhci_inst_r1]
    mov [r12+64],rax
    mov rax,[rbp+xhci_region+8-xhci_inst_r1]
    mov [r12+72],rax
    mov eax,[rbp+xhci_op-xhci_inst_r1]
    mov [r12+80],eax
    mov eax,[rbp+xhci_rt-xhci_inst_r1]
    mov [r12+84],eax
    ; Original candidate identity joins this actual software/DMA owner; cached
    ; candidate identity alone never authorizes MMIO or a successful result.
    mov ecx,[rel xhci_cand_n]
    cmp ecx,XHCI_CAND_MAX
    ja .refused
    xor ebx,ebx
    lea r15,[rel xhci_cand]
.candidate:
    cmp ebx,ecx
    jae .refused
    mov eax,[r12+44]
    cmp eax,[r15+XC_BUS]
    jne .next_candidate
    mov eax,[r12+48]
    cmp eax,[r15+XC_DEV]
    jne .next_candidate
    mov eax,[r12+52]
    cmp eax,[r15+XC_FN]
    jne .next_candidate
    mov [r12+40],ebx
    mov eax,[r15+XC_VENDEV]
    mov [r12+56],eax
    jmp .image_next
.next_candidate:
    inc ebx
    add r15,XHCI_CAND_SZ
    jmp .candidate
.image_next:
    inc r14d
    cmp r14d,[r13+20]
    jb .images
.retained:
    xor edi,edi
    call xhci_discard_owner_at
    mov [r13+28],edx
    mov [r13+32],ecx
    test ecx,ecx
    jnz .refused
    cmp edx,XHCI_CAND_MAX
    ja .refused
    xor r14d,r14d
.retained_loop:
    cmp r14d,[r13+28]
    jae .preflight
    mov edi,r14d
    call xhci_discard_owner_at
    test ecx,ecx
    jnz .refused
    cmp edx,[r13+28]
    jne .refused
    test rax,rax
    jz .refused
    mov rbp,rax
    mov edi,3
    mov esi,r14d
    call .new_record
    jc .refused
    mov eax,[rbp+4]
    mov [r12+40],eax
    cmp eax,[rel xhci_cand_n]
    jae .refused
    cmp eax,XHCI_CAND_MAX
    jae .refused
    mov eax,[rbp+8]
    mov [r12+44],eax
    mov eax,[rbp+12]
    mov [r12+48],eax
    mov eax,[rbp+16]
    mov [r12+52],eax
    mov eax,[rbp+20]
    mov [r12+56],eax
    mov eax,[rbp+24]
    mov [r12+36],eax
    mov rax,[rbp+32]
    mov [r12+64],rax
    mov rax,[rbp+40]
    mov [r12+72],rax
    ; Historical outcomes are deliberately not inspected as current authority.
    inc r14d
    jmp .retained_loop
.preflight:
    or dword [r13+16],8
    mov ebx,1
.preflight_loop:
    cmp ebx,[r13+8]
    ja .effects
    imul eax,ebx,XT_BYTES
    lea r12,[r13+rax]
    call .admit                       ; all original owners before ANY mutation
    jc .refused
    ; Equal original BDF+region owners share ONE current hardware effect.
    ; Retained generations/allocations remain owned and separately exported.
    mov r14d,1
.alias_loop:
    cmp r14d,ebx
    jae .preflight_next
    imul eax,r14d,XT_BYTES
    lea r15,[r13+rax]
    mov eax,[r12+44]
    cmp eax,[r15+44]
    jne .alias_next
    mov rax,[r12+48]
    cmp rax,[r15+48]
    jne .alias_next
    cmp dword [r12+4],1
    jne .alias_region
    cmp dword [r15+4],1
    je .refused                       ; duplicate registered native ownership
.alias_region:
    mov rax,[r12+64]
    cmp rax,[r15+64]
    jne .refused
    mov rax,[r12+72]
    cmp rax,[r15+72]
    jne .refused
    mov [r12+156],r14d                ; original record1..13, never zero authority
    jmp .preflight_next
.alias_next:
    inc r14d
    jmp .alias_loop
.preflight_next:
    inc ebx
    jmp .preflight_loop
.effects:
    or dword [r13+16],16
    cmp dword [r13+8],0
    je .inactive
    mov ebx,1
.effect_loop:
    imul eax,ebx,XT_BYTES
    lea r12,[r13+rax]
    mov eax,[r12+156]
    test eax,eax
    jnz .alias_effect
    call .admit                       ; immediate fresh admission, not cached success
    jc .refused
    call .stop
    jc .refused
    jmp .effect_next
.alias_effect:
    imul eax,eax,XT_BYTES
    lea rsi,[r13+rax]
    cmp dword [rsi+12],1
    jne .refused
    ; Copy only this same-call fresh hardware observations/results. Original
    ; source kind/index/generation/BDF/region and explicit alias stay separate.
    mov eax,[rsi+16]
    or eax,1<<20
    mov [r12+16],eax
    add rsi,88
    lea rdi,[r12+88]
    mov ecx,17
    rep movsd
    mov dword [r12+12],1
.effect_next:
    inc ebx
    cmp ebx,[r13+8]
    jbe .effect_loop
    mov eax,1
    jmp .publish
.inactive:
    xor eax,eax                       ; no original owned state, not PCI absence
    jmp .publish
.refused:
    mov eax,-1
    cmp dword [r13+156],0
    je .publish
.replay:
    mov eax,-2                        ; never replay a completed/uncertain effect
.publish:
    mov [r13+12],eax
    add rsp,24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

.new_record:                          ; EDI kind, ESI original source index
    mov eax,[r13+8]
    cmp eax,XT_MAX
    jae .new_bad
    inc eax
    mov [r13+8],eax
    imul eax,eax,XT_BYTES
    lea r12,[r13+rax]
    mov dword [r12],1
    mov [r12+4],edi
    mov [r12+8],esi
    mov dword [r12+12],3              ; unattempted, never zero-filled success
    mov dword [r12+16],1
    mov eax,[r13+20]
    mov [r12+20],eax
    mov eax,[r13+24]
    mov [r12+24],eax
    mov dword [r12+140],3
    mov dword [r12+144],3
    mov dword [r12+148],3
    mov dword [r12+152],3
    clc
    ret
.new_bad:
    stc
    ret

.pci_read:
    mov edi,[r12+44]
    mov esi,[r12+48]
    mov edx,[r12+52]
    jmp pci_cfg_read32
.identity:
    cmp dword [r12+44],255
    ja .bad
    cmp dword [r12+48],31
    ja .bad
    cmp dword [r12+52],7
    ja .bad
    xor ecx,ecx
    call .pci_read
    cmp ax,0xffff
    je .bad
    test ax,ax
    jz .bad
    cmp eax,[r12+56]
    jne .bad
    mov ecx,8
    call .pci_read
    mov [r12+60],eax
    shr eax,8
    cmp eax,0x0c0330
    jne .bad
    or dword [r12+16],2
    clc
    ret
.admit:
    call .identity
    jc .bad
    mov ecx,4
    call .pci_read
    cmp eax,-1
    je .bad
    test eax,2
    jz .bad                           ; never enable decode to manufacture admission
    mov [r12+88],eax
    or dword [r12+16],4
    mov ecx,0x10
    call .pci_read
    mov edx,eax
    and eax,15
    cmp eax,4                         ; original native mapped64 memory BAR
    jne .bad
    ; Keep low BAR across the actual PCI call in a preserved native register.
    push rbx
    mov ebx,edx
    mov ecx,0x14
    call .pci_read
    shl rax,32
    and ebx,~15
    or rax,rbx
    pop rbx
    cmp rax,[r12+64]
    jne .bad
    test rax,rax
    jz .bad
    test rax,0xfff
    jnz .bad
    mov rdx,[r12+72]
    cmp rdx,0x40
    jb .bad
    cmp rdx,0x40000
    ja .bad
    add rax,rdx
    jc .bad
    mov rdi,[r12+64]
    mov rax,0x400000000
    cmp rdi,rax
    jb .mapped                         ; original bring-up identity-map rule below16GiB
    call paging_xhci_bar_mapped         ; same original high-BAR mapping admission
    test eax,eax
    jz .bad
.mapped:
    or dword [r12+16],8
    xor esi,esi
    call .read
    jc .bad
    and eax,255
    cmp eax,0x20
    jb .bad
    cmp eax,0xfc
    ja .bad
    test eax,3
    jnz .bad
    cmp dword [r12+80],0
    je .op_known
    cmp eax,[r12+80]
    jne .bad
.op_known:
    mov [r12+80],eax
    mov esi,0x18                       ; exact current runtime aperture for masking
    call .read
    jc .bad
    test eax,31
    jnz .bad
    test eax,eax
    jz .bad
    cmp dword [r12+84],0
    je .rt_known
    cmp eax,[r12+84]
    jne .bad
.rt_known:
    mov [r12+84],eax
    mov esi,[r12+80]
    add rsi,0x20                      ; full CRCR aperture bounded; only low CRR is observed
    cmp rsi,[r12+72]
    ja .bad
    mov esi,eax
    add rsi,XHCI_IMAN+4
    cmp rsi,[r12+72]
    ja .bad
    mov esi,[r12+80]
    call .read
    jc .bad
    test eax,2                         ; do not interfere with an actual reset
    jnz .bad
    mov [r12+100],eax
    mov esi,[r12+84]
    add rsi,XHCI_IMAN
    call .read
    jc .bad
    mov [r12+116],eax
    or dword [r12+16],16
    ; Same actual owner-qualified region, after native PCI/BAR/aperture
    ; admission. Current firmware custody vetoes the original stop.
    jmp .firmware_guard

.firmware_guard:
    push rbx
    push rbp
    push r14
    lea rax,[rel xhci_terminal_observations]
    mov rbp,r12
    sub rbp,rax
    lea rax,[rel xhci_terminal_firmware_observations]
    add rbp,rax
    mov r11d,[rbp+84]
    inc r11d
    mov rdi,rbp
    mov ecx,XT_BYTES/8
    xor eax,eax
    rep stosq
    mov dword [rbp],2
    mov dword [rbp+4],4
    mov rax,r12
    sub rax,r13
    xor edx,edx
    mov ecx,XT_BYTES
    div ecx
    mov [rbp+8],eax
    mov dword [rbp+12],-1
    mov dword [rbp+16],1
    mov eax,[r12+4]
    mov [rbp+20],eax
    mov eax,[r12+8]
    mov [rbp+24],eax
    mov eax,[r12+36]
    mov [rbp+28],eax
    mov eax,[r12+44]
    mov [rbp+32],eax
    mov eax,[r12+48]
    mov [rbp+36],eax
    mov eax,[r12+52]
    mov [rbp+40],eax
    mov eax,[r12+40]
    mov [rbp+44],eax
    mov rax,[r12+64]
    mov [rbp+48],rax
    mov rax,[r12+72]
    mov [rbp+56],rax
    mov [rbp+84],r11d
    mov esi,XHCI_HCCPARAMS1
    call .read
    mov [rbp+64],eax                  ; returned value, availability is explicit
    jc .firmware_bad
    or dword [rbp+16],2
    shr eax,16
    shl eax,2
    mov [rbp+68],eax
    mov ebx,eax
    test ebx,ebx
    jz .firmware_none
    mov r14d,50                      ; original native finite chain bound
.firmware_walk:
    cmp ebx,0x20
    jb .firmware_bad
    mov [rbp+72],ebx
    inc dword [rbp+80]
    and dword [rbp+16],~4             ; availability refers to the last raw header
    mov esi,ebx
    call .read
    mov [rbp+76],eax
    jc .firmware_bad
    or dword [rbp+16],4
    mov ecx,eax
    and ecx,255
    jz .firmware_bad                 ; reserved capability0 is not an end marker
    cmp ecx,1
    je .firmware_found
    shr eax,8
    and eax,255
    test eax,eax
    jz .firmware_none
    shl eax,2
    add ebx,eax
    dec r14d
    jnz .firmware_walk
    jmp .firmware_bad
.firmware_found:
    or dword [rbp+16],8
    lea rdx,[rbx+8]
    cmp rdx,[r12+72]
    ja .firmware_bad
    test eax,1<<16
    jnz .firmware_bad
    test eax,1<<24
    jz .firmware_bad
    or dword [rbp+16],32
    jmp .firmware_ready
.firmware_none:
    or dword [rbp+16],64
.firmware_ready:
    or dword [rbp+16],128
    mov dword [rbp+12],0
    pop r14
    pop rbp
    pop rbx
    clc
    ret
.firmware_bad:
    pop r14
    pop rbp
    pop rbx
    stc
    ret
.read:                                ; actual owner-qualified private region
    lea rdi,[r12+64]
    mov rax,rsi
    add rax,4
    jc .bad
    cmp rax,[r12+72]
    ja .bad
    call hal_mmio_read32
    jc .bad
    cmp eax,-1
    je .bad
    clc
    ret
.write:
    lea rdi,[r12+64]
    mov rax,rsi
    add rax,4
    jc .bad
    cmp rax,[r12+72]
    ja .bad
    call hal_mmio_write32
    jc .bad
    mov dword [r13+156],1             ; actual accepted effect; never UI resumption
    mov dword [rel xhci_terminal_latched],1
    clc
    ret
.bad:
    stc
    ret

.stop:
    or dword [r12+16],32
    mov eax,[r12+116]
    and eax,~3                        ; IE off, write0 to IP RW1C (preserve pending)
    mov [r12+120],eax
    mov edx,eax
    mov esi,[r12+84]
    add rsi,XHCI_IMAN
    call .write
    jc .stop_bad
    or dword [r12+16],64
    mov eax,[r12+100]
    and eax,~(XHCI_USBCMD_RS|XHCI_USBCMD_INTE)
    mov [r12+104],eax
    mov edx,eax
    mov esi,[r12+80]
    call .write
    jc .bus_master
    or dword [r12+16],128
    mov ebp,200
.poll:
    inc dword [r12+136]
    mov esi,[r12+80]
    add rsi,XHCI_USBSTS
    call .read
    jc .bus_master
    mov [r12+112],eax
    or dword [r12+16],256
    test eax,0x1004                   ; host error is unavailable, never successful HCH
    jnz .bus_master
    mov dword [r12+140],2
    test eax,XHCI_USBSTS_HCH
    jz .read_crr
    mov dword [r12+140],0
.read_crr:
    mov esi,[r12+80]
    add rsi,0x18
    call .read
    jc .bus_master
    mov [r12+128],eax
    or dword [r12+16],512
    mov dword [r12+148],2
    test eax,8
    jnz .poll_again
    mov dword [r12+148],0
    cmp dword [r12+140],0
    je .halted
.poll_again:
    mov edi,1000
    call tsc_delay_us
    dec ebp
    jnz .poll
    jmp .bus_master
.halted:
    mov esi,[r12+80]
    call .read
    jc .bus_master
    mov [r12+108],eax
    or dword [r12+16],1024
    test eax,XHCI_USBCMD_RS|XHCI_USBCMD_INTE|2
    jnz .bus_master
    mov esi,[r12+84]
    add rsi,XHCI_IMAN
    call .read
    jc .bus_master
    mov [r12+124],eax
    or dword [r12+16],2048
    mov dword [r12+144],2
    test eax,2
    jnz .bus_master
    mov dword [r12+144],0
.bus_master:
    ; Independent current PCI containment even after a halt timeout/unavailable.
    ; Never derive completion from a request or from historical discard bits.
    call .identity
    jc .stop_bad
    mov ecx,4
    call .pci_read
    cmp eax,-1
    je .stop_bad
    and eax,0xffff & ~4
    or eax,0x400                      ; Command only, no Status RW1C acknowledgements
    mov [r12+92],eax
    mov r8d,eax
    mov edi,[r12+44]
    mov esi,[r12+48]
    mov edx,[r12+52]
    mov ecx,4
    mov dword [r13+156],1             ; issued PCI write has no completion return
    mov dword [rel xhci_terminal_latched],1
    call pci_cfg_write32
    or dword [r12+16],4096
    mov ecx,4
    call .pci_read
    mov [r12+96],eax
    cmp eax,-1
    je .stop_bad
    or dword [r12+16],8192
    call .identity
    jc .stop_bad
    or dword [r12+16],16384
    mov dword [r12+152],2
    test dword [r12+96],4
    jnz .stop_bad
    test dword [r12+96],0x400
    jz .stop_bad
    mov dword [r12+152],0
    cmp dword [r12+140],0
    jne .stop_bad
    cmp dword [r12+144],0
    jne .stop_bad
    cmp dword [r12+148],0
    jne .stop_bad
    mov dword [r12+12],1
    clc
    ret
.stop_bad:
    mov dword [r12+12],-1
    cmp dword [r13+156],0
    je .bad
    mov dword [r12+12],-2
    stc
    ret

align 8
xhci_terminal_latched: dd 0
align 8
xhci_terminal_observations: times XT_TOTAL db 0
xhci_terminal_firmware_observations: times XT_TOTAL db 0
