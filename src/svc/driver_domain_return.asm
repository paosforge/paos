;; MODULE svc/driver_domain_return
;; LAYER 5
;; EXPORTS driver_domain_return_prepare, driver_return_saved
;; IMPORTS hv/driver_domain_return, boot/header, boot/beacon, boot/boot_v2_handoff, boot/boot_v2_health, boot/nvram_access, core/build_id
;; CAPS
;; OWNER rc-boot-claude
;; CONTEXT: bsp_only
; Original post-ACK, pre-CLI boundary. VM owns exact STOP, terminal retirement
; and original deadlines. EAX0/1/2 safe for reset, >=3 refuses before wipe/TEoff.
; One attempt per boot. Never reuse a cached observation after a new START.
driver_domain_return_prepare:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    push r13
    push r14
    mov r13d,3
    cmp byte [rel driver_return_once],0
    jne .out
    mov byte [rel driver_return_once],1
    pushfq
    pop rax
    test eax,0x200                 ; never yield with interrupts excluded
    jz .out
    call nd_return_prepare
    cmp eax,4
    ja .out
    mov r13d,eax
    lea rbx,[rel driver_return_bytes]
    mov rdi,rbx
    xor eax,eax
    mov ecx,256/8
    cld
    rep stosq
    mov rdi,rbx
    lea rsi,[rel nd_return_record]
    mov ecx,128/8
    rep movsq
    mov rax,0x0000314e5452444e
    cmp [rbx],rax
    jne .invalid
    cmp dword [rbx+8],1
    jne .invalid
    cmp dword [rbx+12],128
    jne .invalid
    cmp [rbx+44],r13d
    jne .invalid
    cmp dword [rbx+92],0
    jne .invalid
    ; Missing diagnostic evidence does not change independent reset safety.
    cmp byte [rel pbm_manager_launch],1
    jne .out
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .out
    test byte [rel pbm_flags],PBM_HF_MUTABLE_ATTEMPT
    jz .out
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne .out
    cmp byte [rel paos_build_state],BID_ST_MATCH
    jne .out
    mov r12,[rel runtime_services]
    test r12,r12
    jz .out
    mov rax,[rel boot_tsc_start]
    mov [rbx+128],rax
    mov eax,[rel boot_nonce]
    mov [rbx+136],eax
    mov rax,[rel pbm_manager_sequence]
    mov [rbx+144],rax
    mov rax,[rel pbm_attempt_nonce]
    mov [rbx+152],rax
    mov rax,[rel pbm_state_generation]
    mov [rbx+160],rax
    lea rdi,[rbx+168]
    lea rsi,[rel paos_build_measured]
    mov ecx,4
    rep movsq
    lea rsi,[rel pbm_payload_sha]
    mov ecx,4
    rep movsq
    mov al,[rel pbm_entry]
    mov [rbx+232],al
    mov byte [rbx+234],BID_ST_MATCH
    mov rdi,rbx
    mov esi,252
    call pbm_crc32
    mov [rbx+252],eax
    mov rdi,rbx
    call driver_return_wire_ok
    test eax,eax
    jz .out
    call driver_return_read
    mov rdx,0x800000000000000E
    cmp rax,rdx                    ; only confirmed NOT_FOUND is missing
    je .gate
    test rax,rax
    jnz .unknown
    cmp dword [rel driver_return_attrs],7
    jne .unknown
    cmp qword [rel driver_return_size],256
    jne .unknown
    lea rdi,[rel driver_return_verify]
    call driver_return_wire_ok
    test eax,eax
    jz .unknown                    ; preserve unknown existing diagnostic bytes
.gate:
    lea rdi,[rel driver_return_guid]
    lea rsi,[rel driver_return_name]
    xor edx,edx
    lea rcx,[rel driver_return_tag]
    call storage_access_nvram_require
    test rax,rax
    jnz .out
    lea rcx,[rel driver_return_name]
    lea rdx,[rel driver_return_guid]
    mov r8d,7
    mov r9d,256
    sub rsp,48                    ; aligned UEFI home space + fifth argument
    mov [rsp+32],rbx
    call [r12+0x58]
    add rsp,48
    test rax,rax
    jnz .unknown
    call driver_return_read
    test rax,rax
    jnz .unknown
    cmp dword [rel driver_return_attrs],7
    jne .unknown
    cmp qword [rel driver_return_size],256
    jne .unknown
    lea rdi,[rel driver_return_verify]
    mov rsi,rbx
    mov ecx,256/8
    cld
    repe cmpsq
    jne .unknown
    mov byte [rel driver_return_saved],1
.unknown:
    ; No erase, alternate variable, retry or second STOP after uncertainty.
.out:
    mov eax,r13d
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret
.invalid:
    mov r13d,3
    jmp .out

; RDI=256B. Pure schema/CRC/full-identity validation before replacing a record.
; This diagnostic does not confer authority or certify actual OS return.
driver_return_wire_ok:
    push rbx
    mov rbx,rdi
    mov rax,0x0000314e5452444e
    cmp [rbx],rax
    jne .bad
    cmp dword [rbx+8],1
    jne .bad
    cmp dword [rbx+12],128
    jne .bad
    cmp dword [rbx+44],4
    ja .bad
    cmp dword [rbx+92],0
    jne .bad
    cmp qword [rbx+128],0
    je .bad
    cmp dword [rbx+140],0
    jne .bad
    cmp qword [rbx+144],0
    je .bad
    cmp qword [rbx+152],0
    je .bad
    cmp qword [rbx+160],0
    je .bad
    mov rax,[rbx+168]
    or rax,[rbx+176]
    or rax,[rbx+184]
    or rax,[rbx+192]
    jz .bad
    mov rax,[rbx+200]
    or rax,[rbx+208]
    or rax,[rbx+216]
    or rax,[rbx+224]
    jz .bad
    cmp byte [rbx+232],1
    jb .bad
    cmp byte [rbx+232],2
    ja .bad
    cmp word [rbx+233],0x0100
    jne .bad
    lea rdi,[rbx+235]
    mov ecx,17
    xor eax,eax
    cld
    repe scasb
    jne .bad
    mov rdi,rbx
    mov esi,252
    call pbm_crc32
    cmp eax,[rbx+252]
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

driver_return_read:
    mov qword [rel driver_return_size],256
    mov dword [rel driver_return_attrs],0
    lea rcx,[rel driver_return_name]
    lea rdx,[rel driver_return_guid]
    lea r8,[rel driver_return_attrs]
    lea r9,[rel driver_return_size]
    sub rsp,40
    lea rax,[rel driver_return_verify]
    mov [rsp+32],rax
    call [r12+0x48]
    add rsp,40
    ret

driver_return_guid: dd 0x7a965d12
    dw 0xc839,0x4a77
    db 0xb1,0xe2,0x90,0x6e,0xf7,0x24,0x43,0x8c
align 2
driver_return_name: dw 'P','a','O','S','D','r','i','v','e','r','D','o','m','a','i','n','R','e','t','u','r','n',0
driver_return_tag: db 'driver-domain-return',0
%include "core/abi/wdata.inc"
%macro WDATA_svc_driver_domain_return 0
driver_return_once: db 0
driver_return_saved: db 0
align 8
driver_return_size: dq 0
driver_return_attrs: dd 0
align 8
driver_return_bytes: times 256 db 0
driver_return_verify: times 256 db 0
%endmacro
WDATA_DEFER WDATA_svc_driver_domain_return
