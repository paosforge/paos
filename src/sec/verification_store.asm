;; MODULE sec/verification_store
;; LAYER 5
;; EXPORTS vfy_store_load, vfy_store_commit
;; IMPORTS boot/header, boot/boot_v2_handoff, boot/nvram_access, fs/storage_access
;; CAPS
;; OWNER rc-sec-claude
;; CONTEXT: bsp_only  (one trusted native service transaction; no yield/AP/IRQ)
; Fixed existing row192 in PaOSVerifyIssued1, PaOS data GUID, attrs NV|BS|RT=7.
; Unlinked adapter; no host EFI action, provisioning, delete, fallback or reseed.
; load(RDI=out192) ->0 or -11. Full-size/attrs read required; failure zeros out.
; commit(RDI=expected192, RSI=burned192) ->0 / -11 storage / -12 stale / -1 bad.
; Mapped stable disjoint pointers only. Caller authenticates/binds both rows and
; owns exclusive access. Adapter permits only LIVE->BURNED with immutable
; bytes8..111 identical and verifier/reserved cleared. It re-reads and compares
; ALL expected bytes before SetVariable, then requires successful SetVariable
; and exact192B/attrs/full-byte readback. It never restores old bytes on failure.
; UEFI's synchronous nonvolatile update is the persistence boundary. Normal
; power loss yields old (no candidate evaluated), new (replay refused), or an
; invalid/torn row (MAC refusal). Firmware that lies about durable completion
; and malicious whole-NVRAM rollback need stronger platform anchoring; this
; adapter does not establish it or authorize login. Native/runtime/metal proof
; is still required. No RT-variable schema migration or automatic creation.
; Scratch erased. No static writable state. DF clear on return, nonvols saved.

vfy_store_load:
    cld
    push rbx
    push r12
    sub rsp,72
    mov rbx,rdi
    test rbx,rbx
    jz .bad_null
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .bad
    mov r12,[rel runtime_services]
    test r12,r12
    jz .bad
    mov qword [rsp+56],192
    mov dword [rsp+48],0
    lea rcx,[rel vs_name]
    lea rdx,[rel storage_access_nvram_paos_data_guid]
    lea r8,[rsp+48]
    lea r9,[rsp+56]
    mov [rsp+32],rbx
    call [r12+0x48]
    test rax,rax
    jnz .bad
    cmp qword [rsp+56],192
    jne .bad
    cmp dword [rsp+48],7
    jne .bad
    xor eax,eax
    jmp .out
.bad:
    mov rdi,rbx
    xor eax,eax
    mov ecx,24
    rep stosq
.bad_null:
    mov eax,-11
.out:
    ; Firmware metadata only, no secrets in this frame.
    add rsp,72
    pop r12
    pop rbx
    ret

vfy_store_commit:
    cld
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp,256                    ; aligned shadow40 + readback192 + metadata
    mov r12,rdi
    mov r13,rsi
    test r12,r12
    jz .invalid
    test r13,r13
    jz .invalid
    cmp dword [r12],0x31524956
    jne .invalid
    cmp dword [r13],0x31524956
    jne .invalid
    cmp dword [r12+4],0x00010001
    jne .invalid
    cmp dword [r13+4],0x00020001
    jne .invalid
    xor r8d,r8d
    mov ecx,13                     ; immutable sequence/request/bindings/time
.identity:
    mov rax,[r12+rcx*8]
    xor rax,[r13+rcx*8]
    or r8,rax
    dec ecx
    jnz .identity
    mov ecx,6
.zero:
    or r8,[r13+rcx*8+104]          ; verifier32 and reserved16
    dec ecx
    jnz .zero
    test r8,r8
    jnz .invalid
    lea rdi,[rsp+48]
    call vfy_store_load
    test eax,eax
    jnz .out
    xor r8d,r8d
    mov ecx,24
.expected:
    mov rax,[rsp+rcx*8+40]
    xor rax,[r12+rcx*8-8]
    or r8,rax
    dec ecx
    jnz .expected
    test r8,r8
    jnz .stale
    call storage_access_request_intent
    mov edx,eax
    lea rdi,[rel storage_access_nvram_paos_data_guid]
    lea rsi,[rel vs_name]
    lea rcx,[rel vs_tag]
    call storage_access_nvram_require
    test rax,rax
    jnz .storage
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .storage
    mov rbx,[rel runtime_services]
    test rbx,rbx
    jz .storage
    lea rcx,[rel vs_name]
    lea rdx,[rel storage_access_nvram_paos_data_guid]
    mov r8d,7
    mov r9d,192
    mov [rsp+32],r13
    call [rbx+0x58]
    test rax,rax
    jnz .storage
    lea rdi,[rsp+48]
    call vfy_store_load
    test eax,eax
    jnz .out
    xor r8d,r8d
    mov ecx,24
.readback:
    mov rax,[rsp+rcx*8+40]
    xor rax,[r13+rcx*8-8]
    or r8,rax
    dec ecx
    jnz .readback
    test r8,r8
    jnz .storage
    xor eax,eax
    jmp .out
.invalid:
    mov eax,-1
    jmp .out
.stale:
    mov eax,-12
    jmp .out
.storage:
    mov eax,-11
.out:
    mov r14d,eax
    xor eax,eax
    mov rdi,rsp
    mov ecx,32
    rep stosq
    mov eax,r14d
    add rsp,256
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

vs_name: dw 'P','a','O','S','V','e','r','i','f','y','I','s','s','u','e','d','1',0
vs_tag: db 'verification_issued',0
