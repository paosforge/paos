; USBMAP <16 lowercase hex nonce> <1..16 retained USB enumeration slot>.
; Owner-only actual standard GET_DESCRIPTOR plus the owned high-page operation.
; No reset, rescan, topology changes, configuration or physical-address input.
; Wire: fourteen LE qwords +18 descriptor bytes, hex, under USB_OUT_CAP.
cmd_verb_usbmap:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    sub  rsp, 144
    mov  rbx, rsi
    mov  r12, [rdi + REQ_ARG]
    call usb_out_reset
    cmp  byte [rel command_auth_remote_active], 1
    jne  .owner
    call command_auth_owner_request
    test eax, eax
    jz   .refused
.owner:
    mov  rdi, r12
    call hp_usb_mapping_parse
    test eax, eax
    jz   .refused
    mov  rdi, rdx                    ; parsed nonzero nonce
    mov  esi, eax                    ; parsed selector
    mov  rdx, rsp
    call hp_usb_mapping_observe
    call usb_out_reset               ; transfer diagnostics may stage other output
    lea  rdi, [rel str_usbmap_head]
    call usb_out_str
    xor  r13d, r13d
.hex:
    movzx edi, byte [rsp + r13]
    call usb_out_hex2
    inc  r13d
    cmp  r13d, 130
    jb   .hex
    lea  rdi, [rel str_usbmap_end]
    call usb_out_str
    mov  qword [rbx + RSP_CODE], CMDE_OK
    mov  qword [rbx + RSP_ACCEPTED], 1
    jmp  .out
.refused:
    lea  rdi, [rel str_usbmap_refused]
    call usb_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
.out:
    mov  byte [rel usb_out_ready], 1
    mov  rax, [rbx + RSP_CODE]
    add  rsp, 144
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bounded canonical grammar; EAX=selector1..16 or0; RDX=nonzero nonce.
hp_usb_mapping_parse:
    xor  eax, eax
    xor  edx, edx
    test rdi, rdi
    jz   .bad
    xor  ecx, ecx
.digit:
    movzx r8d, byte [rdi + rcx]
    sub  r8d, '0'
    cmp  r8d, 9
    jbe  .hex
    sub  r8d, 'a' - '0'
    cmp  r8d, 5
    ja   .bad
    add  r8d, 10
.hex:
    shl  rdx, 4
    or   rdx, r8
    inc  ecx
    cmp  ecx, 16
    jb   .digit
    test rdx, rdx
    jz   .bad
    cmp  byte [rdi + 16], ' '
    jne  .bad
    movzx eax, byte [rdi + 17]
    sub  eax, '1'
    cmp  eax, 8
    ja   .bad
    inc  eax
    cmp  byte [rdi + 18], 0
    je   .out
    cmp  eax, 1
    jne  .bad
    movzx eax, byte [rdi + 18]
    sub  eax, '0'
    cmp  eax, 6
    ja   .bad
    add  eax, 10
    cmp  byte [rdi + 19], 0
    je   .out
.bad:
    xor  eax, eax
.out:
    ret

; RDI nonce, ESI selector, RDX record130*. Both peers always attempted.
; Status usb:0 actual exact transfer,1 prerequisite absent,2 transfer error,
; 3 descriptor changed,4 controller identity/generation/slot changed.
hp_usb_mapping_observe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 80
    mov  rbx, rdx
    mov  r12, rdi
    mov  r13d, esi
    mov  rdi, rbx
    xor  eax, eax
    mov  ecx, 130
    rep stosb
    mov  [rbx], r12
    mov  [rbx + 8], r13
    mov  qword [rbx + 16], 1
    mov  rdi, r12
    call hp_mapping_probe
    mov  [rbx + 24], rax
    mov  [rbx + 88], rdx
    mov  [rbx + 96], rcx
    mov  rax, [rel inv_top_of_ram]
    mov  [rbx + 104], rax
    call acpi_ownership_snapshot         ; fresh read, no ownership side effect
    mov  [rbx + 80], rax
.usb:
    lea  edi, [r13 - 1]
    call usb_dev_is_null
    test eax, eax
    jnz  .out
    lea  edi, [r13 - 1]
    call usb_dev_hc
    test rax, rax
    jz   .out
    mov  r14, rax
    cmp  dword [r14 + dev.class], CLASS_USBHC
    jne  .out
    cmp  dword [r14 + dev.health], HEALTH_OK
    jne  .out
    lea  edi, [r13 - 1]
    call usb_dev_addr
    test eax, eax
    jz   .out
    mov  r15d, eax
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rbx + 32]
    call xhci_preservation_snapshot
    test eax, eax
    jnz  .out
    lea  edi, [r13 - 1]
    call usb_dev_desc_ptr
    test rax, rax
    jz   .out
    mov  rsi, rax
    lea  rdi, [rbx + 112]
    mov  ecx, 18
    rep  movsb
    mov  rax, [r14 + dev.ops]
    test rax, rax
    jz   .out
    mov  rax, [rax + usbhc_ops.control]
    test rax, rax
    jz   .out
    mov  rdi, r14
    lea  rsi, [rel hp_usb_mapping_setup]
    mov  edx, r15d
    lea  rcx, [rel hp_usb_mapping_fresh] ; permanent aligned DMA buffer
    mov  r8d, 18
    ; Retained storage survives a timed-out transfer; never DMA into a stack.
    call rax
    mov  qword [rbx + 16], 2
    cmp  rax, 18
    jne  .out
    mov  qword [rbx + 16], 3
    cmp  word [rel hp_usb_mapping_fresh], 0x0112
    jne  .out
    lea  rsi, [rel hp_usb_mapping_fresh]
    lea  rdi, [rbx + 112]
    mov  ecx, 18
    repe cmpsb
    jne  .out
    mov  qword [rbx + 16], 4
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rsp + 24]
    call xhci_preservation_snapshot
    test eax, eax
    jnz  .out
    lea  rsi, [rsp + 24]
    lea  rdi, [rbx + 32]
    mov  ecx, 6                      ; instance,BDF,generation,port,slot,BAR
    repe cmpsq
    jne  .out
    mov  qword [rbx + 16], 0
.out:
    add  rsp, 80
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

hp_usb_mapping_register:
    lea  rdi, [rel str_verb_usbmap]
    lea  rsi, [rel cmd_verb_usbmap]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1                      ; existing owner mutation admission
    jmp  command_register_verb
str_verb_usbmap: db 'USBMAP',0
str_usbmap_head: db 'USBMAP v=1 data=',0
str_usbmap_end: db ' end=1',0
str_usbmap_refused: db 'USBMAP REFUSED owner_or_arguments',0
hp_usb_mapping_setup: db 0x80,6,0,1,0,0,18,0

%macro WDATA_svc_hp_usb_mapping 0
align 64
hp_usb_mapping_fresh: times 64 db 0
%endmacro
WDATA_DEFER WDATA_svc_hp_usb_mapping
