;; MODULE hv/pci_census_observation
;; LAYER 5
;; EXPORTS pcc_register_verbs
;; IMPORTS hv/a1_pci_census, hv/driver_domain_command, hv/vmx, svc/command, core/time, boot/header, hv/hp_tcr_observe, bus/pci_bdf, boot/paging
;; CAPS extension
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; Ordinary read-only command. Capture actual eight-function config census once;
; expose ordered frozen pages independent of domain START, claims or assignment.
; Original boot120s cutoff, <=100ms producer budget, >=1ms return reserve.
pcc_register_verbs:
    push rbx
    lea rdi,[rel pcc_verb]
    lea rsi,[rel nd_command_pcc]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    xor r9d,r9d
    call command_register_verb
    lea rdi,[rel pcc_hp_verb]
    lea rsi,[rel nd_command_pcchp]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    xor r9d,r9d
    call command_register_verb
    pop rbx
    ret

; PCICENS hhhh probe16 sequence page0..8. All raw partial refusal bytes
; are retained. No reset, device config/MMIO, mapping or ownership writes.
; Explicit paired observation; PCICENS itself remains config-only.
nd_command_pcchp:
    mov r10d,1
    jmp pcc_command_common
nd_command_pcc:
    xor r10d,r10d
pcc_command_common:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov [rel pcc_arg_mode],r10d
    call cmd_handler_prologue
    mov r12,rsi
    mov rbx,[rdi+REQ_ARG]
    call hv_out_reset
    test rbx,rbx
    jz .syntax
    xor ecx,ecx
.bound:
    cmp byte [rbx+rcx],0
    je .parse
    inc ecx
    cmp ecx,64
    jb .bound
    jmp .syntax
.parse:
    mov rdi,rbx
    lea rsi,[rel pcc_arg_bdf]
    mov edx,5
    call nd_token
    test rax,rax
    jz .syntax
    mov rdi,rax
    lea rsi,[rel pcc_arg_probe]
    mov edx,17
    call nd_token
    test rax,rax
    jz .syntax
    mov rdi,rax
    lea rsi,[rel pcc_arg_seq]
    mov edx,11
    call nd_token
    test rax,rax
    jz .syntax
    mov rdi,rax
    lea rsi,[rel pcc_arg_page]
    mov edx,2
    call nd_token
    test rax,rax
    jz .syntax
    cmp byte [rax],0
    jne .syntax
    lea rdi,[rel pcc_arg_bdf]
    mov esi,16
    mov edx,4
    call nd_number
    jc .syntax
    cmp ecx,4
    jne .syntax
    mov r13d,eax
    test al,7
    jnz .syntax
    lea rdi,[rel pcc_arg_probe]
    call pcc_probe_valid
    test rax,rax
    jz .syntax
    mov [rel pcc_probe_value],rax
    lea rdi,[rel pcc_arg_seq]
    mov esi,10
    mov edx,10
    call nd_number
    jc .syntax
    mov r14d,eax
    movzx ebx,byte [rel pcc_arg_page]
    sub ebx,'0'
    mov eax,8
    add eax,[rel pcc_arg_mode]
    cmp ebx,eax
    ja .syntax
    test r14d,r14d
    jnz .cached
    test ebx,ebx
    jnz .syntax
    mov dword [rel pcc_valid],0
    cmp dword [rel pcc_sequence],0xffffffff
    je .cache_error
    inc dword [rel pcc_sequence]
    mov [rel pcc_bdf],r13d
    mov eax,[rel pcc_arg_mode]
    mov [rel pcc_mode],eax
    mov dword [rel pcc_hp_valid],0
    lea rdi,[rel pcc_probe]
    lea rsi,[rel pcc_arg_probe]
    mov ecx,17
    cld
    rep movsb
    ; Calibrated time and an original boot timestamp are mandatory. All
    ; arithmetic is bounded/checked before the producer can touch PCI.
    mov rax,[rel tsc_khz]
    cmp rax,100000
    jb .budget_error
    cmp rax,10000000
    ja .budget_error
    mov [rel pcc_request+40],rax
    mov [rel pcc_request+48],rax
    imul rax,120000
    mov rcx,[rel boot_tsc_start]
    test rcx,rcx
    jz .budget_error
    add rax,rcx
    jc .budget_error
    mov [rel pcc_boot_deadline],rax
    call tsc_now
    cmp rax,[rel boot_tsc_start]
    jb .budget_error
    mov rcx,[rel pcc_boot_deadline]
    cmp rax,rcx
    jae .budget_error
    mov rdx,[rel pcc_request+40]
    imul rdx,100
    add rdx,rax
    jc .budget_error
    cmp rdx,rcx
    cmova rdx,rcx
    mov [rel pcc_request+32],rdx
    mov dword [rel pcc_request],'A1CQ'
    mov dword [rel pcc_request+4],(64<<16)|1
    mov [rel pcc_request+8],r13d
    mov dword [rel pcc_request+12],0
    mov rax,[rel pcc_probe_value]
    mov [rel pcc_request+16],rax
    mov eax,[rel pcc_sequence]
    mov [rel pcc_request+24],rax
    mov qword [rel pcc_request+56],0
    lea rdi,[rel pcc_request]
    lea rsi,[rel pcc_cache]
    mov edx,2176
    call a1_pci_census
    cmp eax,2
    je .native_result
    test eax,eax
    jnz .cache_error
.native_result:
    cmp dword [rel pcc_cache],'A1CS'
    jne .cache_error
    cmp dword [rel pcc_cache+4],(2176<<16)|1
    jne .cache_error
    cmp eax,[rel pcc_cache+8]
    jne .cache_error
    cmp r13d,[rel pcc_cache+16]
    jne .cache_error
    mov rcx,[rel pcc_probe_value]
    cmp rcx,[rel pcc_cache+32]
    jne .cache_error
    mov ecx,[rel pcc_sequence]
    cmp rcx,[rel pcc_cache+40]
    jne .cache_error
    mov [rel pcc_status],eax
    mov rax,[rel pcc_cache+56]
    mov [rel pcc_last_tsc],rax
    cmp dword [rel pcc_mode],1
    jne .captured
    ; Actual TCR leaf is immediate, before any page/network offer. It uses
    ; this original producer result, probe, sequence and absolute deadline.
    call pcc_hp_capture
.captured:
    mov dword [rel pcc_next_page],1
    mov dword [rel pcc_valid],1
    jmp .emit
.cached:
    test ebx,ebx
    jz .cache_error
    cmp dword [rel pcc_valid],1
    jne .cache_error
    cmp r14d,[rel pcc_sequence]
    jne .cache_error
    mov eax,[rel pcc_arg_mode]
    cmp eax,[rel pcc_mode]
    jne .cache_error
    cmp r13d,[rel pcc_bdf]
    jne .cache_error
.identity:
    cmp ebx,[rel pcc_next_page]
    jne .cache_error
    lea rdi,[rel pcc_arg_probe]
    lea rsi,[rel pcc_probe]
    mov ecx,17
    cld
    repe cmpsb
    jne .cache_error
    inc dword [rel pcc_next_page]
.emit:
    call tsc_now
    cmp rax,[rel pcc_last_tsc]
    jb .cache_error
    cmp rax,[rel pcc_boot_deadline]
    jae .budget_error
    mov [rel pcc_last_tsc],rax
    cmp ebx,9
    jne .census_prefix
    cmp dword [rel pcc_hp_valid],1
    jne .cache_error
    lea rdi,[rel pcc_hp_ok]
    jmp .prefix
.census_prefix:
    lea rdi,[rel pcc_ok]
.prefix:
    call hv_out_str
    lea rdi,[rel pcc_probe]
    call hv_out_str
    mov edi,[rel pcc_bdf]
    call nd_info_number
    mov edi,[rel pcc_sequence]
    call nd_info_number
    mov edi,[rel pcc_status]
    cmp ebx,9
    jne .status
    mov edi,[rel pcc_hp_cache+8]
.status:
    call nd_info_number
    mov edi,ebx
    call nd_info_number
    mov r14d,256
    cmp ebx,8
    jb .length
    mov r14d,128
.length:
    mov edi,r14d
    call nd_info_number
    lea rdi,[rel pcc_space]
    call hv_out_str
    lea r13,[rel pcc_hp_cache]
    cmp ebx,9
    je .payload
    shl ebx,8
    lea r13,[rel pcc_cache]
    add r13,rbx
.payload:
    add r14,r13
.hex:
    lea rdx,[rel pcc_hex]
    movzx eax,byte [r13]
    shr eax,4
    mov al,[rdx+rax]
    call hv_out_putc
    lea rdx,[rel pcc_hex]
    movzx eax,byte [r13]
    and eax,15
    mov al,[rdx+rax]
    call hv_out_putc
    inc r13
    cmp r13,r14
    jb .hex
    jmp .ready
.syntax:
    lea rdi,[rel pcc_syntax]
    call hv_out_str
    jmp .ready
.budget_error:
    mov dword [rel pcc_valid],0
    lea rdi,[rel pcc_budget]
    call hv_out_str
    jmp .ready
.cache_error:
    lea rdi,[rel pcc_stale]
    call hv_out_str
.ready:
    mov byte [rel hv_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Private native composition. The span describes only the genuine existing
; whole-leaf non-RAM firmware admission + existing UC identity mapping, not a
; sized BAR aperture. Walk every overlap; no mapping or device write is made.
; Its revision is this map observation's original local capture sequence.
pcc_hp_capture:
    push rbx
    mov dword [rel pcc_hp_valid],0
    mov dword [rel pcc_hp_map_refusal],0
    lea rdi,[rel pcc_hp_request]
    xor eax,eax
    mov ecx,(96+64+128)/8
    cld
    rep stosq
    mov dword [rel pcc_hp_request],'A1HQ'
    mov dword [rel pcc_hp_request+4],(96<<16)|1
    mov eax,[rel pcc_bdf]
    mov [rel pcc_hp_request+8],eax
    mov [rel pcc_hp_map+48],eax
    mov rax,[rel pcc_request+16]
    mov [rel pcc_hp_request+16],rax
    mov [rel pcc_hp_map+8],rax
    mov rax,[rel pcc_request+24]
    mov [rel pcc_hp_request+24],rax
    mov [rel pcc_hp_request+88],rax
    mov [rel pcc_hp_map+16],rax
    mov [rel pcc_hp_map+24],rax
    mov rax,[rel pcc_request+32]
    mov [rel pcc_hp_request+32],rax
    mov rax,[rel pcc_request+40]
    mov [rel pcc_hp_request+40],rax
    mov rax,[rel pcc_request+48]
    mov [rel pcc_hp_request+48],rax
    lea rax,[rel pcc_cache]
    mov [rel pcc_hp_request+56],rax
    mov dword [rel pcc_hp_request+64],2176
    lea rax,[rel pcc_hp_map]
    mov [rel pcc_hp_request+72],rax
    mov dword [rel pcc_hp_request+80],64
    mov dword [rel pcc_hp_map],'A1HM'
    mov dword [rel pcc_hp_map+4],(64<<16)|1
    mov dword [rel pcc_hp_map+52],2
    mov dword [rel pcc_hp_map+56],1
    ; Other identities/incomplete census pass to the actual leaf for their
    ; honest reason, without deriving a device mapping or reading MMIO here.
    cmp qword [rel pcc_cache+8],0
    jne .leaf
    cmp dword [rel pcc_cache+128],0x816810ec
    jne .leaf
    cmp dword [rel pcc_cache+136],0x0200000e
    jne .leaf
    cmp dword [rel pcc_cache+172],0x8617103c
    jne .leaf
    mov eax,[rel pcc_cache+128+0x18]
    test al,1
    jnz .map_type
    mov edx,eax
    and edx,6
    xor ebx,ebx
    cmp edx,4
    je .wide
    test edx,edx
    jnz .map_type
    jmp .bar
.wide:
    mov ebx,[rel pcc_cache+128+0x1c]
    shl rbx,32
.bar:
    and eax,~15
    or rbx,rax
    test rbx,rbx
    jz .map_zero
    mov rax,rbx
    shr rax,34
    jnz .map_limit
    mov eax,ebx
    and eax,0x1fffff
    cmp eax,0x1fffbc              ; entire TCR dword in same existing leaf
    ja .map_tail
    mov rdi,rbx
    and rdi,-0x200000
    call pci_mmio_nonram_chunk
    test eax,eax
    jz .map_resource
    mov rdi,rbx
    and rdi,-0x200000
    call paging_pd_entry_ptr
    test rax,rax
    jz .map_missing
    mov rax,[rax]
    mov edx,eax
    and edx,0x109b
    cmp edx,0x9b
    jne .map_flags
    mov rdx,0x000fffffffe00000
    and rax,rdx
    mov rcx,rbx
    and rcx,-0x200000
    cmp rax,rcx
    jne .map_identity
    mov [rel pcc_hp_map+32],rbx
    mov eax,ebx
    and eax,0x1fffff
    mov edx,0x200000
    sub edx,eax
    mov [rel pcc_hp_map+40],rdx
    jmp .leaf
; Same guards and exit path as before; retain only the first producer refusal.
; These codes describe map prerequisites, never admission/reset authority.
.map_type:
    mov dword [rel pcc_hp_map_refusal],1
    jmp .leaf
.map_zero:
    mov dword [rel pcc_hp_map_refusal],2
    jmp .leaf
.map_limit:
    mov dword [rel pcc_hp_map_refusal],3
    jmp .leaf
.map_tail:
    mov dword [rel pcc_hp_map_refusal],4
    jmp .leaf
.map_resource:
    mov dword [rel pcc_hp_map_refusal],5
    jmp .leaf
.map_missing:
    mov dword [rel pcc_hp_map_refusal],6
    jmp .leaf
.map_flags:
    mov dword [rel pcc_hp_map_refusal],7
    jmp .leaf
.map_identity:
    mov dword [rel pcc_hp_map_refusal],8
.leaf:
    lea rdi,[rel pcc_hp_request]
    lea rsi,[rel pcc_hp_cache]
    mov edx,128
    call hp_tcr_observe
    cmp eax,2
    je .result
    test eax,eax
    jnz .done
.result:
    cmp dword [rel pcc_hp_cache],'A1HT'
    jne .done
    cmp dword [rel pcc_hp_cache+4],(128<<16)|1
    jne .done
    cmp eax,[rel pcc_hp_cache+8]
    jne .done
    mov eax,[rel pcc_bdf]
    cmp eax,[rel pcc_hp_cache+16]
    jne .done
    mov rax,[rel pcc_request+16]
    cmp rax,[rel pcc_hp_cache+24]
    jne .done
    mov rax,[rel pcc_request+24]
    cmp rax,[rel pcc_hp_cache+32]
    jne .done
    cmp rax,[rel pcc_hp_cache+40]
    jne .done
    mov rax,[rel pcc_hp_cache+56]
    cmp rax,[rel pcc_last_tsc]
    jbe .valid
    mov [rel pcc_last_tsc],rax
.valid:
    ; Private AMD leaf remains A1HT v1. Upgrade only this validated export;
    ; v2 assigns formerly reserved124 to the caller's map-refusal stage.
    ; Census/identity/budget/TCR failures must never borrow an earlier stage.
    mov dword [rel pcc_hp_cache+4],(128<<16)|2
    cmp dword [rel pcc_hp_cache+8],2
    jne .mark_valid
    cmp dword [rel pcc_hp_cache+12],6
    jne .mark_valid
    mov eax,[rel pcc_hp_map_refusal]
    mov [rel pcc_hp_cache+124],eax
.mark_valid:
    mov dword [rel pcc_hp_valid],1
.done:
    pop rbx
    ret

; Fixed-width lower-case hex token -> numeric original probe64.
pcc_probe_valid:
    xor ecx,ecx
    xor r8d,r8d
.loop:
    movzx eax,byte [rdi+rcx]
    sub eax,'0'
    cmp eax,9
    jbe .digit
    sub eax,'a'-'0'
    cmp eax,5
    ja .bad
    add eax,10
.digit:
    shl r8,4
    or r8,rax
    inc ecx
    cmp ecx,16
    jb .loop
    cmp byte [rdi+16],0
    jne .bad
    mov rax,r8
    ret
.bad:
    xor eax,eax
    ret

pcc_verb: db 'PCICENS',0
pcc_hp_verb: db 'PCIHPT',0
pcc_hp_ok: db 'PHT1 ',0
pcc_ok: db 'PCC1 ',0
pcc_syntax: db 'PCCERR1 1',0
pcc_stale: db 'PCCERR1 2',0
pcc_budget: db 'PCCERR1 3',0
pcc_space: db ' ',0
pcc_hex: db '0123456789abcdef'
%include "core/abi/wdata.inc"
%macro WDATA_hv_pci_census_observation 0
align 8
pcc_sequence: dq 0
pcc_boot_deadline: dq 0
pcc_last_tsc: dq 0
pcc_probe_value: dq 0
pcc_mode: dd 0
pcc_arg_mode: dd 0
pcc_hp_valid: dd 0
pcc_hp_map_refusal: dd 0
pcc_valid: dd 0
pcc_bdf: dd 0
pcc_status: dd 0
pcc_next_page: dd 0
pcc_probe: times 17 db 0
pcc_arg_bdf: times 5 db 0
pcc_arg_probe: times 17 db 0
pcc_arg_seq: times 11 db 0
pcc_arg_page: times 2 db 0
align 16
pcc_request: times 64 db 0
pcc_cache: times 2176 db 0
align 16
pcc_hp_request: times 96 db 0
pcc_hp_map: times 64 db 0
pcc_hp_cache: times 128 db 0
%endmacro
WDATA_DEFER WDATA_hv_pci_census_observation
