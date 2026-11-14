%macro PU_TEXT 1
    lea rdi,[rel %1]
    mov rsi,rbp
    call fmt_str
    add rbp,rax
%endmacro
%macro PU_HEX 0
    mov rsi,rbp
    mov edx,16
    call fmt_hex
    add rbp,rax
%endmacro
; Passive original USB terminal return. RDI=144B snapshot, ESI=actual EAX.
; Busy2 has NO per-call snapshot and may belong to another active terminal;
; do not dereference or serialize the shared sample in that case. No pointers
; appear in the record. This is source/device evidence, never physical proof.
command_power_return_usb:
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
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp,rsp
    sub rsp,1040
    and rsp,-16
    mov [rsp+1024],rbp
    cmp byte [rel pr_linux],1
    jne .out
    cmp byte [rel pr_kind],2
    jne .out
    cmp byte [rel pr_state],PR_COMMITTED
    jne .out
    cmp byte [rel sd_state],SD_EXECUTING
    jne .out
    mov r12,rdi
    mov r13d,esi
    xor r14d,r14d
    cmp esi,2
    je .sample_ready
    cmp esi,5
    ja .sample_ready
    cmp dword [rdi],1
    jne .sample_ready
    cmp dword [rdi+4],144
    jne .sample_ready
    cmp [rdi+8],esi
    jne .sample_ready
    mov r14d,1
.sample_ready:
    mov rbp,rsp
    PU_TEXT pu_trace
    PU_TEXT pr_nonce
    PU_TEXT pr_s_build
    PU_TEXT paos_build_hex
    PU_TEXT pr_s_boot_id
    PU_TEXT pr_s_hex
    mov rdi,[rel boot_tsc_start]
    PU_HEX
    PU_TEXT pr_s_boot_nonce
    PU_TEXT pr_s_hex
    mov edi,[rel boot_nonce]
    PU_HEX
    PU_TEXT pr_s_seq
    PU_TEXT pr_s_hex
    mov rdi,[rel pr_next_sequence]
    PU_HEX
    PU_TEXT pr_s_kind
    PU_TEXT pr_s_hex
    movzx edi,byte [rel pr_kind]
    PU_HEX
    PU_TEXT pu_result
    PU_TEXT pr_s_hex
    mov edi,r13d
    PU_HEX
    PU_TEXT pu_sample
    PU_TEXT pr_s_hex
    mov edi,r14d
    PU_HEX
    test r14d,r14d
    jz .sample_done
    PU_TEXT pu_fence
    PU_TEXT pr_s_hex
    mov edi,[r12+12]
    PU_HEX
    PU_TEXT pu_media_gen
    PU_TEXT pr_s_hex
    mov rdi,[r12+24]
    PU_HEX
    PU_TEXT pu_hc_gen
    PU_TEXT pr_s_hex
    mov edi,[r12+40]
    PU_HEX
    PU_TEXT pu_port
    PU_TEXT pr_s_hex
    mov edi,[r12+44]
    PU_HEX
    PU_TEXT pu_owner_version
    PU_TEXT pr_s_hex
    mov edi,[r12+48]
    PU_HEX
    PU_TEXT pu_owner_size
    PU_TEXT pr_s_hex
    mov edi,[r12+52]
    PU_HEX
    PU_TEXT pu_owner_phase
    PU_TEXT pr_s_hex
    mov edi,[r12+56]
    PU_HEX
    PU_TEXT pu_owner_root
    PU_TEXT pr_s_hex
    mov edi,[r12+80]
    PU_HEX
    PU_TEXT pu_owner_hc_gen
    PU_TEXT pr_s_hex
    mov edi,[r12+84]
    PU_HEX
    PU_TEXT pu_lba_max
    PU_TEXT pr_s_hex
    mov rdi,[r12+128]
    PU_HEX
    PU_TEXT pu_block_bytes
    PU_TEXT pr_s_hex
    mov edi,[r12+136]
    PU_HEX
.sample_done:
    PU_TEXT pr_s_ms
    PU_TEXT pr_s_hex
    call boot_ms_now
    mov rdi,rax
    PU_HEX
    PU_TEXT pr_s_until
    PU_TEXT pr_s_hex
    mov rdi,[rel pr_deadline]
    PU_HEX
    PU_TEXT sd_s_crlf
    mov rdi,rsp
    call serial_string
    call serial_drain_poll
.out:
    mov rsp,[rsp+1024]
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
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

pu_trace: db '[PAOS64] POWERUSB1 nonce=',0
pu_result: db ' result=',0
pu_sample: db ' sample=',0
pu_fence: db ' fence=',0
pu_media_gen: db ' media_gen=',0
pu_hc_gen: db ' hc_gen=',0
pu_port: db ' port=',0
pu_owner_version: db ' owner_version=',0
pu_owner_size: db ' owner_size=',0
pu_owner_phase: db ' owner_phase=',0
pu_owner_root: db ' owner_root=',0
pu_owner_hc_gen: db ' owner_hc_gen=',0
pu_lba_max: db ' lba_max=',0
pu_block_bytes: db ' block_bytes=',0

%unmacro PU_TEXT 1
%unmacro PU_HEX 0
