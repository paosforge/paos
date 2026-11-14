;; MODULE gui/app_store_install
;; LAYER 6
;; PURPOSE Fixed physical install writer for the authenticated bounded app aggregate.
;; EXPORTS app_store_install
;; IMPORTS gui/app_install, gui/app_remove, svc/app_store, svc/app_execution_state, svc/command, sec/app_store_seal, sec/app_store_intent, sec/session, fs/app_store_data, core/lib/sha256, core/smp
;; OWNER saga:app_store
;; CONTEXT: bsp_only
%include "fs/app_store_layout.inc"
; Callback ABI RDI original physical intent,RSI old candidate hint,RDX length.
; The hint is never authority or copied. Real fixed GUI accessors recheck that
; intent and copy the currently verified sharing candidate into private storage.
; Result1 durable catalog commit,0 refused/preeffect failure,2 uncertain.
; No automatic retry and no grants, launch, key enrollment or filesystem paths.
app_store_install:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rdx
    call smp_current_logical
    test eax,eax
    jnz .refused
    cmp byte [rel ais_busy],0
    jne .refused
    mov byte [rel ais_busy],1
    test r12,r12
    jz .fail
    test r13,r13
    jz .fail
    cmp r13,65536
    ja .fail
    cmp byte [rel cmd_in_dispatch],0
    jne .fail
    cmp dword [rel cmd_dispatch_depth],0
    jne .fail
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .fail
    cmp rdx,-1
    je .fail
    mov [rel ais_epoch],rdx
    mov [rel ais_intent],r12
    call app_remove_store_busy
    test eax,eax
    jnz .fail
    mov rdi,r12
    lea rsi,[rel ais_descriptor]
    mov edx,704
    call app_install_store_descriptor
    cmp eax,1
    jne .fail
    cmp qword [rel ais_descriptor],1
    jne .fail
    cmp r13,[rel ais_descriptor+16]
    jne .fail
    mov rax,[rel ais_epoch]
    cmp rax,[rel ais_descriptor+24]
    jne .fail
    cmp qword [rel ais_descriptor+88],1
    ja .fail
    mov rdi,r12
    lea rsi,[rel ais_candidate]
    mov rdx,r13
    call app_install_store_copy
    cmp eax,1
    jne .fail
    lea rdi,[rel ais_digest]
    lea rsi,[rel ais_candidate]
    mov rdx,r13
    call sha256_hash
    lea rdi,[rel ais_digest]
    lea rsi,[rel ais_descriptor+32]
    mov ecx,32
    cld
    repe cmpsb
    jne .fail
    ; Fixed accessors return the fully verified BASHAPP2 candidate. Preserve
    ; its actual unsigned/signed class and descriptor agreement. Catalog presence
    ; never supplies execution approval or an author key.
    mov rax,[rel ais_descriptor+88]
    lea eax,[rax*2+1]                  ; unsigned0 -> flags1, signed1 -> flags3
    cmp dword [rel ais_candidate+40],eax
    jne .fail
    mov rax,'BASHAPP2'
    cmp [rel ais_candidate+64],rax
    jne .fail
    ; Derive only from the fixed original physical card intent. Neither the
    ; candidate hint nor caller metadata can manufacture this choice.
    mov rdi,r12
    call app_install_store_execution_policy
    cmp rax,ASL_EXEC_OWNER_UNSIGNED
    ja .fail
    mov [rel ais_exec_policy],rax
    test rax,rax
    jz .policy_ready
    cmp dword [rel ais_candidate+40],1
    jne .fail
.policy_ready:
    lea rdi,[rel ais_image]
    mov esi,ASL_MAX
    lea rdx,[rel ais_token]
    lea rcx,[rel ais_length]
    call app_store_snapshot
    cmp eax,1
    je .catalog
    cmp eax,2
    jne .fail
    ; Absence is not initialized empty. Only this still-current physical
    ; install may create a catalog, after a second fresh fixed DATA absence.
    lea rdi,[rel ais_token]
    call app_store_data_bind
    cmp eax,1
    jne .fail
    lea rdi,[rel ais_token]
    lea rsi,[rel ais_image]
    mov edx,ASL_MAX
    call app_store_data_read
    cmp rax,-4
    jne .fail
    lea rdi,[rel ais_image]
    mov ecx,ASL_PAYLOAD/8
    xor eax,eax
    rep stosq
    mov rax,'PAOSAPS1'
    mov [rel ais_image],rax
    mov dword [rel ais_image+ASL_VERSION],1
    mov dword [rel ais_image+12],ASL_HEADER
    mov qword [rel ais_image+ASL_GENERATION],1
    mov dword [rel ais_image+28],ASL_SLOT_BYTES
    mov qword [rel ais_image+ASL_TOTAL],ASL_PAYLOAD
    mov qword [rel ais_image+ASL_NEXT_ID],1
    mov qword [rel ais_length],ASL_PAYLOAD
.catalog:
    cmp qword [rel ais_image+ASL_GENERATION],-1
    je .fail
    cmp qword [rel ais_image+ASL_NEXT_ID],-1
    je .fail
    cmp dword [rel ais_image+ASL_COUNT],ASL_SLOTS
    jae .fail
    mov rax,[rel ais_length]
    add rax,r13
    jc .fail
    cmp rax,ASL_MAX
    ja .fail
    ; Scan all slots before changing a byte: no interrupted removal or implicit
    ; replacement/upgrades. Exact duplicate ID is refused even if bytes differ.
    lea rbx,[rel ais_image+ASL_HEADER]
    mov ebp,ASL_SLOTS
.scan:
    cmp dword [rbx+ASL_STATE],ASL_REMOVING
    je .fail
    cmp dword [rbx+ASL_STATE],0
    je .next
    lea rdi,[rbx+ASL_BUNDLE_ID]
    lea rsi,[rel ais_descriptor+192+16]
    mov ecx,64
    repe cmpsb
    je .fail
.next:
    add rbx,ASL_SLOT_BYTES
    dec ebp
    jnz .scan
    ; Compact metadata only. Payloads already follow occupied slot order;
    ; preserving that order leaves every unrelated byte/ID/offset unchanged.
    lea rbx,[rel ais_image+ASL_HEADER]
    mov r14,rbx
    mov ebp,ASL_SLOTS
.compact:
    cmp dword [rbx+ASL_STATE],0
    je .compact_next
    mov rsi,rbx
    mov rdi,r14
    mov ecx,ASL_SLOT_BYTES/8
    rep movsq
    add r14,ASL_SLOT_BYTES
.compact_next:
    add rbx,ASL_SLOT_BYTES
    dec ebp
    jnz .compact
    mov rdi,r14
    lea rcx,[rel ais_image+ASL_PAYLOAD]
    sub rcx,rdi
    xor eax,eax
    rep stosb
    mov dword [r14+ASL_STATE],ASL_LIVE
    mov dword [r14+ASL_PROFILE],2
    mov rax,[rel ais_image+ASL_NEXT_ID]
    mov [r14+ASL_ID],rax
    inc qword [rel ais_image+ASL_NEXT_ID]
    lea rdi,[r14+ASL_DIGEST]
    lea rsi,[rel ais_descriptor+32]
    mov ecx,4
    rep movsq
    lea rdi,[r14+ASL_BUNDLE_ID]
    lea rsi,[rel ais_descriptor+192+16]
    mov ecx,8
    rep movsq
    ; Catalog display64: verified printable name1..95, truncate at60 and append
    ; '...' if longer63. Trim spaces at the truncation boundary, never the name.
    lea rsi,[rel ais_descriptor+192+256]
    xor ebp,ebp
.name_length:
    cmp byte [rsi+rbp],0
    je .name_ready
    inc ebp
    cmp ebp,96
    jb .name_length
    jmp .fail
.name_ready:
    test ebp,ebp
    jz .fail
    lea rdi,[r14+ASL_DISPLAY]
    cmp ebp,63
    jbe .short_name
    mov ebp,60
.trim:
    cmp byte [rsi+rbp-1],' '
    jne .long_copy
    dec ebp
    jnz .trim
    jmp .fail
.long_copy:
    mov ecx,ebp
    rep movsb
    mov dword [rdi],0x002e2e2e
    jmp .payload
.short_name:
    mov ecx,ebp
    rep movsb
.payload:
    mov rax,[rel ais_length]
    mov [r14+ASL_OFFSET],rax
    mov [r14+ASL_LENGTH],r13
    lea rdi,[rel ais_image]
    add rdi,rax
    lea rsi,[rel ais_candidate]
    mov rcx,r13
    rep movsb
    add rax,r13
    mov [rel ais_length],rax
    mov [rel ais_image+ASL_TOTAL],rax
    inc dword [rel ais_image+ASL_COUNT]
    inc qword [rel ais_image+ASL_GENERATION]
    cmp qword [rel ais_exec_policy],ASL_EXEC_OWNER_UNSIGNED
    jne .seal
    mov dword [rel ais_image+ASL_VERSION],2
    mov qword [r14+ASL_EXEC_POLICY],ASL_EXEC_OWNER_UNSIGNED
    mov rcx,[rel ais_image+ASL_GENERATION]
    mov [r14+ASL_EXEC_GENERATION],rcx
.seal:
    lea rdi,[rel ais_image]
    mov rsi,rax
    call app_store_seal_sign
    cmp eax,1
    jne .fail
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .fail
    cmp rdx,[rel ais_epoch]
    jne .fail
    call app_remove_store_busy
    test eax,eax
    jnz .fail
    call app_execution_invalidate    ; before the original writer can have any effect
    lea rdi,[rel ais_token]
    lea rsi,[rel ais_image]
    mov rdx,[rel ais_length]
    mov rcx,[rel ais_intent]
    mov r8d,1
    call app_store_intent_write
    cmp rax,-3
    jne .write_known
    call app_execution_uncertain     ; preserves actual -3; no retry or execution grant
.write_known:
    test rax,rax
    jz .committed
    mov r12d,2
    cmp rax,-3
    je .return
.fail:
    xor r12d,r12d
    jmp .return
.committed:
    mov r12d,1
.return:
    ; A completed callback keeps no candidate bytes, binding or intent cache.
    lea rdi,[rel ais_scratch]
    mov ecx,ais_scratch_end-ais_scratch
    xor eax,eax
    cld
    rep stosb
    mov byte [rel ais_busy],0
    mov eax,r12d
    jmp .out
.refused:
    xor eax,eax
.out:
    cld
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_app_store_install 0
alignb 8
ais_busy: resb 1
alignb 8
ais_scratch:
ais_exec_policy: resq 1
ais_epoch: resq 1
ais_intent: resq 1
ais_length: resq 1
ais_token: resb 112
ais_descriptor: resb 704
ais_digest: resb 32
ais_candidate: resb 65536
ais_image: resb ASL_MAX
ais_scratch_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_app_store_install
