;; MODULE core/maintenance_sources
;; LAYER 1
;; CONTEXT: bsp_only
;; EXPORTS maintenance_crash_import, maintenance_crash_prepare, maintenance_crash_identity_prepare
;; IMPORTS core/maintenance_record, core/lib/sha256, boot/boot_v2_handoff, boot/boot_v2_health, boot/header
;; CAPS
;; OWNER rc-vm-claude
; Read exact prior fatal sources. PBCI full identities must embed the independently
; read PBCR exactly; absence alone permits the legacy truncated diagnostic.
; No current-image identity lookup or source repair; no raw addresses in events.
%include "core/abi/maintenance.inc"

; RDI=exact32B PBCR, RSI=distinct128B output. EAX1 only on strict known schema.
; Output always cleared first; no pointer/free text/timing/nonce gets copied.
maintenance_crash_prepare:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    mov rbx,rdi
    mov r12,rsi
    mov rdi,rsi
    xor eax,eax
    mov ecx,ME_RECORD_BYTES/8
    rep stosq
    cmp dword [rbx],0x52434250           ; PBCR
    jne .bad
    cmp word [rbx+4],1
    jne .bad
    cmp word [rbx+6],32
    jne .bad
    mov rdi,rbx
    mov esi,28
    call pbm_crc32
    cmp eax,[rbx+28]
    jne .bad
    cmp byte [rbx+8],31                 ; vector
    ja .bad
    test byte [rbx+11],0xf8             ; only defined flags
    jnz .bad
    cmp byte [rbx+9],255
    jne .phase
    cmp byte [rbx+10],0
    jne .bad
    jmp .offset
.phase:
    cmp byte [rbx+9],8
    ja .bad
    cmp byte [rbx+10],2
    ja .bad
.offset:
    test byte [rbx+11],1
    jnz .relative
    cmp dword [rbx+16],-1
    jne .bad
    jmp .build
.relative:
    cmp dword [rbx+16],-1
    je .bad
.build:
    test byte [rbx+11],2
    jnz .identity
    cmp dword [rbx+20],0
    jne .bad
.identity:
    mov dword [r12+ME_SOURCE],3
    mov word [r12+ME_COMPONENT],3
    mov al,[rbx+9]
    mov [r12+ME_PHASE],al
    mov byte [r12+ME_GATE],255
    movzx eax,byte [rbx+8]
    or eax,0xc0000000                   ; typed CPU vector, not a raw address
    mov [r12+ME_ERROR],eax
    test byte [rbx+11],2
    jz .digest
    mov eax,[rbx+20]
    test eax,eax                        ; zero prefix cannot earn identity
    jz .digest
    mov dword [r12+ME_IDENTITY],2
    mov [r12+ME_BUILD],eax
.digest:
    lea rdi,[r12+ME_SOURCE_DIGEST]
    mov rsi,rbx
    mov edx,32
    call sha256_hash
    test rax,rax
    jnz .bad
    mov eax,1
    jmp .done
.bad:
    mov rdi,r12
    xor eax,eax
    mov ecx,ME_RECORD_BYTES/8
    rep stosq
.done:
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

; RDI=PBCI128, RSI=distinct128B output, RDX=independent validated PBCR32.
; Full fatal identity is diagnostic provenance, not successful health or signature.
maintenance_crash_identity_prepare:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    lea rdi,[rbx+8]
    call maintenance_crash_prepare
    test eax,eax
    jz .bad
    cmp dword [rbx],0x49434250
    jne .bad
    cmp dword [rbx+4],0x00800001
    jne .bad
    lea rdi,[rbx+8]
    mov rsi,r13
    mov ecx,4
    repe cmpsq
    jne .bad
    mov al,[rbx+19]                     ; embedded PBCR flags
    and al,6
    cmp al,6
    jne .bad
    movzx eax,byte [rbx+104]
    dec eax
    cmp eax,2
    ja .bad
    cmp byte [rbx+105],3
    jne .bad
    cmp word [rbx+106],0
    jne .bad
    cmp dword [rbx+108],0
    jne .bad
    cmp dword [rbx+120],0
    jne .bad
    mov eax,[rbx+112]
    cmp eax,[rbx+32]
    jne .bad
    mov eax,[rbx+40]
    cmp eax,[rbx+28]
    jne .bad
    lea rsi,[rbx+40]
    mov rax,[rsi]
    or rax,[rsi+8]
    or rax,[rsi+16]
    or rax,[rsi+24]
    jz .bad
    lea rsi,[rbx+72]
    mov rax,[rsi]
    or rax,[rsi+8]
    or rax,[rsi+16]
    or rax,[rsi+24]
    jz .bad
    mov rdi,rbx
    mov esi,124
    call pbm_crc32
    test eax,eax
    jz .bad
    cmp eax,[rbx+124]
    jne .bad
    mov dword [r12+ME_IDENTITY],1
    lea rdi,[r12+ME_BUILD]
    lea rsi,[rbx+72]                    ; captured Manager-expected file SHA
    mov ecx,4
    rep movsq
    lea rdi,[r12+ME_SOURCE_DIGEST]
    mov rsi,rbx
    mov edx,128
    call sha256_hash
    test rax,rax
    jnz .bad
    mov eax,1
    jmp .out
.bad:
    mov rdi,r12
    xor eax,eax
    mov ecx,ME_RECORD_BYTES/8
    rep stosq
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

; One read/offer at live handoff per boot; no inferred crash and no retry after
; any unavailable/unknown response. EAX append status or2unavailable/4invalid.
maintenance_crash_import:
    cmp byte [rel maintenance_crash_attempted],0
    jne .unavailable
    mov byte [rel maintenance_crash_attempted],1
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    mov ebx,2
    cmp byte [rel pbm_manager_launch],1
    jne .done
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .done
    mov r12,[rel runtime_services]
    test r12,r12
    jz .done
    mov qword [rel maintenance_crash_size],32
    mov dword [rel maintenance_crash_attrs],0
    lea rcx,[rel maintenance_crash_name]
    lea rdx,[rel maintenance_crash_guid]
    lea r8,[rel maintenance_crash_attrs]
    lea r9,[rel maintenance_crash_size]
    sub rsp,48
    lea rax,[rel maintenance_crash_raw]
    mov [rsp+32],rax
    call [r12+0x48]
    add rsp,48
    test rax,rax
    jnz .done
    mov ebx,4
    cmp qword [rel maintenance_crash_size],32
    jne .done
    cmp dword [rel maintenance_crash_attrs],7
    jne .done
    lea rdi,[rel maintenance_crash_raw]
    lea rsi,[rel maintenance_crash_candidate]
    call maintenance_crash_prepare
    test eax,eax
    jz .done
    ; Only NOT_FOUND permits the legacy prefix-only fallback. Known malformed,
    ; unknown, inaccessible or torn full source cannot silently become legacy.
    mov qword [rel maintenance_crash_size],128
    mov dword [rel maintenance_crash_attrs],0
    lea rcx,[rel maintenance_crash_identity_name]
    lea rdx,[rel maintenance_crash_guid]
    lea r8,[rel maintenance_crash_attrs]
    lea r9,[rel maintenance_crash_size]
    sub rsp,48
    lea rax,[rel maintenance_crash_identity_raw]
    mov [rsp+32],rax
    call [r12+0x48]
    add rsp,48
    mov rdx,0x800000000000000e
    cmp rax,rdx
    je .append
    mov ebx,2
    test rax,rax
    jnz .done
    mov ebx,4
    cmp qword [rel maintenance_crash_size],128
    jne .done
    cmp dword [rel maintenance_crash_attrs],7
    jne .done
    lea rdi,[rel maintenance_crash_identity_raw]
    lea rsi,[rel maintenance_crash_candidate]
    lea rdx,[rel maintenance_crash_raw]
    call maintenance_crash_identity_prepare
    test eax,eax
    jz .done
.append:
    lea rdi,[rel maintenance_crash_candidate]
    call maintenance_event_append
    mov ebx,eax
.done:
    mov eax,ebx
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret
.unavailable:
    mov eax,2
    ret

maintenance_crash_guid: db 0x12,0x5d,0x96,0x7a,0x39,0xc8,0x77,0x4a,0xb1,0xe2,0x90,0x6e,0xf7,0x24,0x43,0x8c
align 2,db 0
maintenance_crash_identity_name: dw 'P','a','O','S','C','r','a','s','h','I','d','e','n','t','i','t','y','R','e','c','o','r','d',0
align 2,db 0
maintenance_crash_name: dw 'P','a','O','S','C','r','a','s','h','R','e','c','o','r','d',0
%include "core/abi/wdata.inc"
%macro WDATA_maintenance_sources 0
maintenance_crash_attempted: db 0
align 8
maintenance_crash_size: dq 0
maintenance_crash_attrs: dd 0
maintenance_crash_raw: times 32 db 0
maintenance_crash_identity_raw: times 128 db 0
maintenance_crash_candidate: times ME_RECORD_BYTES db 0
%endmacro
WDATA_DEFER WDATA_maintenance_sources
