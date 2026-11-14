;; MODULE dev/blk/usb_msd_owned
;; LAYER 3
;; EXPORTS usb_msd_owned_record, usb_msd_owned_query, usb_msd_owned_prepare, usb_msd_owned_reprobe
;; IMPORTS dev/blk/usb_msd, usb/enum, fs/blockdev, dev/usb/xhci
;; CAPS
;; OWNER saga:storage
; Internal original class owner ABI, no command/signing/power implementation.
; Caller first retires old VFS handles. Prepare consumes the incarnation once,
; records actual cached root provenance, then makes the original block member
; dead/unregistered BEFORE offering INPUT's one root power cycle.
; Capture enumeration provenance at the ORIGINAL class binding, before BOT
; traffic. A later HC reset or cache rewrite cannot become old-incarnation proof.
; EDI=original enumerated index. Does not change normal bind admission.
usb_msd_owned_record:
    push rbx
    push r12
    mov ebx,edi
    mov dword [rel msd_bound_hc_generation],0
    mov rdi,[rel msd_hc]
    call xhci_hc_generation
    test eax,eax
    jz .out
    mov r12d,eax
    mov edi,ebx
    call usb_dev_topo_ptr
    test rax,rax
    jz .out
    mov rdx,[rax]
    mov [rel msd_bound_topology],rdx
    mov rdx,[rax+8]
    mov [rel msd_bound_topology+8],rdx
    mov edi,ebx
    call usb_dev_desc_ptr
    test rax,rax
    jz .out
    cmp byte [rax],18
    jne .out
    cmp byte [rax+1],1
    jne .out
    mov rdx,[rax]
    mov [rel msd_bound_descriptor],rdx
    mov rdx,[rax+8]
    mov [rel msd_bound_descriptor+8],rdx
    mov dx,[rax+16]
    mov [rel msd_bound_descriptor+16],dx
    mov [rel msd_bound_hc_generation],r12d
.out:
    pop r12
    pop rbx
    ret

; RDI=exact current MSD dev, RSI=retained media generation, RDX=96B output.
; Output: version/size/phase/reserved u32; oldgen/hc u64; root/hcgen u32;
; topology16; deviceDescriptor18/pad6; lbaMax u64; blockBytes/reserved u32.
; Query has identical validation and 96-byte output, phase0. No IO or consume.
usb_msd_owned_query:
    xor eax,eax
    jmp msd_owned_observe
usb_msd_owned_prepare:
    mov eax,1
msd_owned_observe:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov [rsp],eax
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    test rdx,rdx
    jz .fail
    cmp dword [rel msd_owned_snapshot+8],0
    je .phase_ok
    cmp dword [rel msd_owned_snapshot+8],3
    jne .fail
    cmp r13,[rel msd_owned_snapshot+16]
    jbe .fail
.phase_ok:
    lea rax,[rel msd_dev]
    cmp rdi,rax
    jne .fail
    test rsi,rsi
    jz .fail
    cmp byte [rel msd_bound],1
    jne .fail
    cmp byte [rel msd_dead],0
    jne .fail
    cmp dword [rax+dev.health],HEALTH_OK
    jne .fail
    xor ebx,ebx
.member:
    mov rdi,rbx
    mov esi,BLKCAP_READ
    xor edx,edx
    call blk_iter_after
    test rax,rax
    jz .fail
    mov rbx,rax
    cmp rax,r12
    jne .member
    lea rdx,[rel msd_info]
    cmp [rax+dev.info],rdx
    jne .fail
    cmp [rdx+blk_info.media_generation],r13
    jne .fail
    mov rdi,[rel msd_hc]
    call xhci_hc_generation
    test eax,eax
    jz .fail
    cmp eax,[rel msd_bound_hc_generation]
    jne .fail
    mov r15d,eax
    mov rax,[rel msd_hc]
    mov rdx,[rax+dev.ops]
    cmp rdx,[rel msd_hcops]
    jne .fail
    call usb_dev_count
    cmp eax,USB_MAX_DEV
    ja .fail
    mov ebp,eax
    xor ebx,ebx
    xor r12d,r12d                  ; exact inventory index+1, reject duplicates
.find:
    cmp ebx,ebp
    jae .found
    mov edi,ebx
    call usb_dev_is_null
    test eax,eax
    jnz .next
    mov edi,ebx
    call usb_dev_hc
    cmp rax,[rel msd_hc]
    jne .next
    mov edi,ebx
    call usb_dev_addr
    cmp al,[rel msd_port]
    jne .next
    test eax,eax
    jz .fail
    cmp eax,255
    ja .fail
    test r12d,r12d
    jnz .fail
    lea r12d,[ebx+1]
.next:
    inc ebx
    jmp .find
.found:
    test r12d,r12d
    jz .fail
    lea edi,[r12d-1]
    call usb_dev_topo_ptr
    mov rbx,rax
    call msd_owned_topology
    test eax,eax
    jz .fail
    lea edi,[r12d-1]
    call usb_dev_desc_ptr
    test rax,rax
    jz .fail
    cmp byte [rax],18
    jne .fail
    cmp byte [rax+1],1
    jne .fail
    mov rdx,[rax]
    cmp rdx,[rel msd_bound_descriptor]
    jne .fail
    mov rdx,[rax+8]
    cmp rdx,[rel msd_bound_descriptor+8]
    jne .fail
    mov dx,[rax+16]
    cmp dx,[rel msd_bound_descriptor+16]
    jne .fail
    mov rdx,[rbx]
    cmp rdx,[rel msd_bound_topology]
    jne .fail
    mov rdx,[rbx+8]
    cmp rdx,[rel msd_bound_topology+8]
    jne .fail
    mov r12,rax
    mov rdi,r14
    xor eax,eax
    mov ecx,12
    rep stosq
    mov dword [r14],1
    mov dword [r14+4],96
    mov [r14+16],r13
    mov rax,[rel msd_hc]
    mov [r14+24],rax
    movzx eax,byte [rel msd_port]
    mov [r14+32],eax
    mov [r14+36],r15d
    mov rax,[rbx]
    mov [r14+40],rax
    mov rax,[rbx+8]
    mov [r14+48],rax
    mov rax,[r12]
    mov [r14+56],rax
    mov rax,[r12+8]
    mov [r14+64],rax
    mov ax,[r12+16]
    mov [r14+72],ax
    mov rax,[rel msd_lba_max]
    mov [r14+80],rax
    mov eax,[rel msd_block_size]
    cmp eax,512
    jne .fail
    mov [r14+88],eax
    cmp dword [rsp],0
    je .observed
    lea rdi,[rel msd_owned_snapshot]
    mov rsi,r14
    mov ecx,12
    rep movsq
    ; No reopening or reset after this boundary, including uncertain power.
    mov dword [r14+8],1
    mov dword [rel msd_owned_snapshot+8],1
    mov byte [rel msd_dead],1
    mov byte [rel msd_bound],0
    mov dword [rel msd_dev+dev.health],HEALTH_DEAD
    lea rdi,[rel msd_dev]
    call blk_deregister
.observed:
    xor eax,eax
    jmp .out
.fail:
    mov rax,-1
.out:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RBX=actual 16B topology; current exact root only, no hubs/TT/route.
msd_owned_topology:
    xor eax,eax
    test rbx,rbx
    jz .out
    cmp byte [rbx+usb_topo.slot],0
    je .out
    movzx edx,byte [rel msd_port]
    cmp [rbx+usb_topo.root],dl
    jne .out
    cmp byte [rbx+usb_topo.speed],1
    jb .out
    cmp byte [rbx+usb_topo.speed],4
    ja .out
    cmp byte [rbx+usb_topo.depth],0
    jne .out
    cmp dword [rbx+usb_topo.parent_slot],0
    jne .out
    cmp dword [rbx+usb_topo.route],0
    jne .out
    cmp word [rbx+usb_topo.hub_ports],0
    jne .out
    mov eax,1
.out:
    ret

; RDI=original INPUT80B receipt, RAX=fresh registered media generation / 0.
; One offer after prepare. Bad/missing/uncertain evidence consumes it too.
; Original caller owns power; this helper neither repeats retirement nor cycles.
usb_msd_owned_reprobe:
    push rbx
    push r12
    push r13
    mov r12,rdi
    cmp dword [rel msd_owned_snapshot+8],1
    jne .fail
    mov dword [rel msd_owned_snapshot+8],2
    test rdi,rdi
    jz .fail
    cmp byte [rel msd_bound],0
    jne .fail
    cmp byte [rel msd_dead],1
    jne .fail
    cmp dword [rdi],1
    jne .fail
    cmp dword [rdi+4],80
    jne .fail
    cmp dword [rdi+8],0
    jne .fail
    cmp dword [rdi+12],63
    jne .fail
    cmp dword [rdi+72],0
    jne .fail
    cmp dword [rdi+76],0
    jne .fail
    mov rax,[rdi+16]
    cmp rax,[rel msd_owned_snapshot+24]
    jne .fail
    mov eax,[rdi+24]
    cmp eax,[rel msd_owned_snapshot+32]
    jne .fail
    mov eax,[rdi+28]
    cmp eax,[rel msd_owned_snapshot+36]
    jne .fail
    mov rax,[rdi+32]
    cmp rax,[rel msd_owned_snapshot+40]
    jne .fail
    mov rax,[rdi+40]
    cmp rax,[rel msd_owned_snapshot+48]
    jne .fail
    ; Raw observations must agree with the flags, not summary booleans alone.
    mov eax,[rdi+48]
    and eax,0x201
    cmp eax,0x201                  ; initial PP+CCS
    jne .fail
    test dword [rdi+52],0x201       ; actual off PP0/CCS0
    jnz .fail
    mov eax,[rdi+56]
    and eax,0x201
    cmp eax,0x201                  ; actual restored PP1/CCS1
    jne .fail
    test dword [rdi+60],8          ; HCC PPC
    jz .fail
    cmp dword [rdi+64],1
    jb .fail
    cmp dword [rdi+64],100
    ja .fail
    cmp dword [rdi+68],1
    jb .fail
    cmp dword [rdi+68],100
    ja .fail
    mov rdi,[rel msd_owned_snapshot+24]
    cmp rdi,[rel msd_hc]
    jne .fail
    mov rax,[rdi+dev.ops]
    cmp rax,[rel msd_hcops]
    jne .fail
    call xhci_hc_generation
    cmp eax,[rel msd_owned_snapshot+36]
    jne .fail
    mov rdi,[rel msd_owned_snapshot+24]
    mov esi,[rel msd_owned_snapshot+32]
    call usb_dev_refresh_root
    test eax,eax
    jz .fail
    lea ebx,[eax-1]
    mov r13d,ebx
    mov edi,ebx
    call usb_dev_hc
    cmp rax,[rel msd_owned_snapshot+24]
    jne .fail
    mov edi,ebx
    call usb_dev_addr
    cmp eax,[rel msd_owned_snapshot+32]
    jne .fail
    mov edi,ebx
    call usb_dev_desc_ptr
    test rax,rax
    jz .fail
    mov rdx,[rax]
    cmp rdx,[rel msd_owned_snapshot+56]
    jne .fail
    mov rdx,[rax+8]
    cmp rdx,[rel msd_owned_snapshot+64]
    jne .fail
    mov dx,[rax+16]
    cmp dx,[rel msd_owned_snapshot+72]
    jne .fail
    mov edi,ebx
    call usb_dev_topo_ptr
    mov rbx,rax
    call msd_owned_topology
    test eax,eax
    jz .fail
    ; Fresh same root topology after reenumeration; slot may be different.
    ; Consume fresh class descriptors through the original maintained BOT code.
    mov byte [rel msd_dead],0
    call msd_get_config
    test eax,eax
    jz .dead
    mov edi,eax
    call msd_walk_config
    test eax,eax
    jz .dead
    call msd_set_configuration
    test rax,rax
    js .dead
    lea rdx,[rel msd_in_ep_desc]
    call msd_configure_ep
    test rax,rax
    jnz .dead
    lea rdx,[rel msd_out_ep_desc]
    call msd_configure_ep
    test rax,rax
    jnz .dead
    call msd_inquiry
    test eax,eax
    jnz .dead
    call msd_tur_ready
    test eax,eax
    jnz .dead
    call msd_read_capacity
    test eax,eax
    jnz .dead
    mov rax,[rel msd_lba_max]
    cmp rax,[rel msd_owned_snapshot+80]
    jne .dead
    cmp dword [rel msd_block_size],512
    jne .dead
    mov rdi,[rel msd_hc]
    call xhci_hc_generation
    cmp eax,[rel msd_owned_snapshot+36]
    jne .dead
    mov rax,[rel msd_hc]
    mov rax,[rax+dev.ops]
    cmp rax,[rel msd_hcops]
    jne .dead
    call msd_register
    cmp rax,REG_OK
    jne .dead
    mov rax,[rel msd_info+blk_info.media_generation]
    cmp rax,[rel msd_owned_snapshot+16]
    jbe .deregister
    mov edi,r13d
    call usb_msd_owned_record
    mov eax,[rel msd_bound_hc_generation]
    cmp eax,[rel msd_owned_snapshot+36]
    jne .deregister
    mov rax,[rel msd_info+blk_info.media_generation]
    mov byte [rel msd_bound],1
    mov byte [rel msd_state],MSD_ST_BOUND
    mov dword [rel msd_owned_snapshot+8],3
    jmp .out
.deregister:
    lea rdi,[rel msd_dev]
    call blk_deregister
.dead:
    mov byte [rel msd_dead],1
    mov dword [rel msd_dev+dev.health],HEALTH_DEAD
.fail:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_dev_blk_usb_msd_owned 0
alignb 8
msd_owned_snapshot: resb 96
msd_bound_hc_generation: resd 1
msd_bound_topology: resb 16
msd_bound_descriptor: resb 18
%endmacro
WDATA_BSS_DEFER WDATA_BSS_dev_blk_usb_msd_owned
