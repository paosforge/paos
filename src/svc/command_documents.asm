;; MODULE svc/command_documents
;; LAYER 5
;; EXPORTS terminal_documents_provider_init, terminal_documents_plan, terminal_documents_validate, terminal_documents_execute, terminal_documents_prepare_scope, terminal_documents_saved_scope, terminal_documents_retire, verb_id_doclist, verb_id_docread, verb_id_docnew
;; IMPORTS svc/command, sec/terminal_policy, sec/terminal_command, sec/session, fs/public_documents, fs/public_documents_read, svc/terminal_scoped_read, fs/terminal_list, core/lib/mem, core/lib/sha256, core/smp
;; OWNER rc-fs-claude
;; CONTEXT: bsp_only
%include "fs/public_documents.inc"
%include "fs/terminal_scoped_read.inc"
%include "fs/terminal_list.inc"
; Native six-callback provider. No guest pointer, selector, path privilege,
; OWNER substitution, generic internal capability or synthetic input.
; Public Documents are a distinct bounded native-created namespace; all other
; DATA and picked/foreign roots remain unclassified and refused.
terminal_documents_provider_init:       ; -> native table48 /0, no auto grant
    push rbx
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp byte [rel pdc_busy],0
    jne .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    call terminal_documents_retire
    ; Rebase owned registry metadata before its first dereference.
    lea rax,[rel pdc_name_list]
    mov [rel pdc_registry+0],rax
    lea rax,[rel pdc_doclist]
    mov [rel pdc_registry+8],rax
    lea rax,[rel verb_id_doclist]
    mov [rel pdc_registry+16],rax
    mov qword [rel pdc_registry+24],0
    lea rax,[rel pdc_name_read]
    mov [rel pdc_registry+32],rax
    lea rax,[rel pdc_docread]
    mov [rel pdc_registry+40],rax
    lea rax,[rel verb_id_docread]
    mov [rel pdc_registry+48],rax
    mov qword [rel pdc_registry+56],0
    lea rax,[rel pdc_name_new]
    mov [rel pdc_registry+64],rax
    lea rax,[rel pdc_docnew]
    mov [rel pdc_registry+72],rax
    lea rax,[rel verb_id_docnew]
    mov [rel pdc_registry+80],rax
    mov qword [rel pdc_registry+88],1
    cmp byte [rel pdc_registered],1
    je .configure
    ; Register once. On partial capacity failure retain owned IDs and retry
    ; only missing registrations; never duplicate or evict another verb.
    lea rbx,[rel pdc_registry]
    mov ecx,3
.register:
    push rcx
    mov rax,[rbx+16]
    cmp qword [rax],-1
    jne .next
    mov rdi,[rbx]
    mov rsi,[rbx+8]
    xor edx,edx
    mov ecx,2                       ; ARGT_TEXT
    xor r8d,r8d
    mov r9,[rbx+24]
    call command_register_verb
    cmp eax,-1
    je .full
    mov rdx,[rbx+16]
    mov [rdx],rax
.next:
    pop rcx
    add rbx,32
    loop .register
    mov byte [rel pdc_registered],1
.configure:
    call public_documents_read_init
    test rax,rax
    jz .bad
    mov rdi,rax
    call terminal_fs_configure
    cmp eax,1
    jne .bad
    ; Publish only relocated native callback addresses after configuration.
    lea rax,[rel terminal_documents_plan]
    mov [rel pdc_ops+0],rax
    lea rax,[rel terminal_documents_validate]
    mov [rel pdc_ops+8],rax
    lea rax,[rel terminal_documents_execute]
    mov [rel pdc_ops+16],rax
    lea rax,[rel terminal_documents_prepare_scope]
    mov [rel pdc_ops+24],rax
    lea rax,[rel terminal_documents_saved_scope]
    mov [rel pdc_ops+32],rax
    lea rax,[rel terminal_documents_retire]
    mov [rel pdc_ops+40],rax
    lea rax,[rel pdc_ops]
    pop rbx
    ret
.full:
    pop rcx
.bad:
    xor eax,eax
    pop rbx
    ret

; Native registry metadata is insufficient: exact owned ID, canonical name,
; actual final handler and argument/destructiveness contract must still match.
pdc_registry_current:
    push rbx
    push r12
    mov r12,[rel pdc_kind]
    cmp r12,2
    ja .bad
    shl r12,5
    lea rbx,[rel pdc_registry]
    add rbx,r12
    mov rax,[rbx+16]
    mov r12,[rax]
    call command_verb_count
    cmp r12,rax
    jae .bad
    imul r12,48
    lea rax,[rel verb_table]
    add r12,rax
    mov rax,[rbx]
    cmp [r12],rax
    jne .bad
    mov rax,[rbx+8]
    cmp [r12+8],rax
    jne .bad
    cmp qword [r12+16],0
    jne .bad
    cmp qword [r12+24],2
    jne .bad
    cmp qword [r12+32],0
    jne .bad
    mov rax,[rbx+24]
    cmp [r12+40],rax
    jne .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Parse exact stable canonical command text. No quote/shell expansion/import.
; DOCLIST | DOCREAD <UTF8-leaf> <u64-offset> <1..65536-count>
; DOCNEW <UTF8-leaf> <hex0..384-bytes-or-dash-for-empty>.
pdc_parse:
    push rbx
    push rbp
    push r12
    push r13
    mov r12,rdi
    lea rbx,[rel pdc_registry]
    xor ebp,ebp
.name:
    mov rdi,[rbx]
    lea rsi,[rel pdc_text]
    xor ecx,ecx
.match:
    mov al,[rdi+rcx]
    test al,al
    jz .end
    cmp al,[rsi+rcx]
    jne .next
    inc ecx
    jmp .match
.next:
    inc ebp
    add rbx,32
    cmp ebp,3
    jb .name
    jmp .bad
.end:
    mov [rel pdc_kind],rbp
    lea r13,[rsi+rcx]
    test ebp,ebp
    jnz .args
    cmp byte [r13],0
    jne .bad
    mov [rel pdc_arg],r13
    mov eax,1
    jmp .out
.args:
    cmp byte [r13],' '
    jne .bad
    inc r13
    mov [rel pdc_arg],r13
    xor ecx,ecx
.leaf:
    mov al,[r13+rcx]
    cmp al,' '
    je .leaf_end
    test al,al
    jz .bad
    cmp ecx,63
    jae .bad
    inc ecx
    jmp .leaf
.leaf_end:
    mov [rel pdc_name_len],rcx
    lea rbp,[r13+rcx+1]
    mov rdi,r13
    mov rsi,rcx
    call public_documents_name_check
    cmp eax,1
    jne .bad
    lea rdi,[rel pdc_name]
    mov rsi,r13
    mov rcx,[rel pdc_name_len]
    cld
    rep movsb
    cmp qword [rel pdc_kind],2
    je .new
    mov rsi,rbp
    call pdc_decimal
    cmp edx,1
    jne .bad
    cmp byte [rsi],' '
    jne .bad
    mov [rel pdc_offset],rax
    inc rsi
    call pdc_decimal
    cmp edx,1
    jne .bad
    cmp byte [rsi],0
    jne .bad
    test rax,rax
    jz .bad
    cmp rax,65536
    ja .bad
    mov [rel pdc_count],rax
    mov eax,1
    jmp .out
.new:
    cmp byte [rbp],'-'
    jne .hex
    cmp byte [rbp+1],0
    jne .bad
    mov eax,1
    jmp .out
.hex:
    lea r12,[rel pdc_payload]
    xor ebx,ebx
.hex_loop:
    movzx eax,byte [rbp]
    test eax,eax
    jz .hex_end
    cmp ebx,PUD_PAYLOAD
    jae .bad
    call pdc_nibble
    cmp eax,15
    ja .bad
    shl eax,4
    mov r13d,eax
    movzx eax,byte [rbp+1]
    call pdc_nibble
    cmp eax,15
    ja .bad
    or eax,r13d
    mov [r12+rbx],al
    inc ebx
    add rbp,2
    jmp .hex_loop
.hex_end:
    test ebx,ebx
    jz .bad
    mov [rel pdc_payload_len],rbx
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
pdc_nibble:
    sub eax,'0'
    cmp eax,9
    jbe .out
    add eax,'0'
    or eax,32
    sub eax,'a'
    cmp eax,5
    ja .bad
    add eax,10
.out:
    ret
.bad:
    mov eax,-1
    ret
pdc_decimal:                        ; RSI digits -> RAX value,EDX1/0,RSI end
    xor r8d,r8d
    xor ecx,ecx
.loop:
    movzx eax,byte [rsi]
    sub eax,'0'
    cmp eax,9
    ja .end
    mov rdx,0x1999999999999999
    cmp r8,rdx
    ja .bad
    jne .mul
    cmp eax,5
    ja .bad
.mul:
    imul r8,r8,10
    add r8,rax
    inc rsi
    inc ecx
    jmp .loop
.end:
    test ecx,ecx
    jz .bad
    mov rax,r8
    mov edx,1
    ret
.bad:
    xor edx,edx
    ret

terminal_documents_plan:             ; frame1088, desc256 ->1/0
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    cmp byte [rel pdc_busy],0
    jne .deny
    mov byte [rel pdc_busy],1
    call terminal_documents_retire
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel pdc_registered],1
    jne .bad
    cmp dword [r12+4],1
    jne .bad
    mov ebx,[r12+28]
    test ebx,ebx
    jz .bad
    cmp ebx,1023
    ja .bad
    cmp byte [r12+rbx+64],0
    jne .bad
    ; A hidden NUL cannot let grammar and SEC's full text hash disagree.
    xor ecx,ecx
.no_nul:
    cmp byte [r12+rcx+64],0
    je .bad
    inc ecx
    cmp ecx,ebx
    jb .no_nul
    lea rdi,[rel pdc_text]
    lea rsi,[r12+64]
    mov ecx,ebx
    cld
    rep movsb
    mov [rel pdc_text_len],rbx
    call pdc_parse
    cmp eax,1
    jne .bad
    call pdc_registry_current
    cmp eax,1
    jne .bad
    lea rdi,[rel pdc_text_hash]
    lea rsi,[rel pdc_text]
    mov rdx,rbx
    call sha256_hash
    test eax,eax
    jnz .bad
    lea rdi,[rel pdc_record]
    lea rsi,[rel pdc_scope]
    lea rdx,[rel pdc_token]
    call public_documents_load
    cmp eax,1
    jne .bad
    lea rdi,[rel pdc_before]
    lea rsi,[rel pdc_record]
    call public_documents_digest
    test eax,eax
    jnz .bad
    mov qword [rel pdc_op],20
    mov qword [rel pdc_target],1
    mov rax,[rel pdc_record+PUD_OWNER]
    mov [rel pdc_generation],rax
    cmp qword [rel pdc_kind],0
    je .freeze
    cmp qword [rel pdc_kind],2
    je .construct
    ; Existing file resolved by canonical exact leaf; record shape excludes
    ; duplicate names and aliases. Freeze its real ID/generation and bounds.
    lea rbx,[rel pdc_record+PUD_HEADER]
    mov r12d,PUD_ROWS
.find:
    cmp byte [rbx],0
    je .bad
    mov rdx,[rel pdc_name_len]
    cmp byte [rbx+rdx],0
    jne .next
    mov rdi,rbx
    lea rsi,[rel pdc_name]
    call memcmp
    test eax,eax
    jz .found
.next:
    add rbx,PUD_ROW
    dec r12d
    jnz .find
    jmp .bad
.found:
    mov rax,[rbx+PUD_R_ID]
    inc rax
    jz .bad
    mov [rel pdc_target],rax
    mov rax,[rbx+PUD_R_GEN]
    mov [rel pdc_generation],rax
    mov rax,[rel pdc_offset]
    cmp rax,[rbx+PUD_R_SIZE]
    ja .bad
    jmp .freeze
.construct:
    lea rdi,[rel pdc_record]
    lea rsi,[rel pdc_name]
    mov rdx,[rel pdc_name_len]
    lea rcx,[rel pdc_payload]
    mov r8,[rel pdc_payload_len]
    call public_documents_build
    cmp rax,-1
    je .bad
    mov [rel pdc_new_id],rax
    inc rax
    jz .bad
    mov [rel pdc_target],rax
    mov qword [rel pdc_generation],1
    mov qword [rel pdc_op],36
    lea rdi,[rel pdc_after]
    lea rsi,[rel pdc_record]
    call public_documents_digest
    test eax,eax
    jnz .bad
.freeze:
    mov rax,[rel pdc_op]
    mov [r13+56],rax
    mov qword [r13+64],PUD_SCOPE_ID
    mov rax,[rel pdc_target]
    mov [r13+72],rax
    mov rax,[rel pdc_generation]
    mov [r13+80],rax
    mov qword [r13+88],0
    lea rdi,[r13+136]
    lea rsi,[rel pdc_scope]
    mov ecx,8
    rep movsq
    mov byte [rel pdc_active],1
    mov byte [rel pdc_busy],0
    mov eax,1
    jmp .out
.bad:
    call terminal_documents_retire
    mov byte [rel pdc_busy],0
.deny:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Every check, final copyout and PAGE word reaches this frozen validator.
; Mutation has a strict before proof, exact synchronous constructor proof,
; and authenticated created-result proof. There is no allow-on-spent flag.
terminal_documents_validate:         ; desc256 ->1/0
    push rbx
    push r12
    mov rbx,rdi
    cmp byte [rel pdc_active],1
    jne .bad
    test rbx,rbx
    jz .bad
    cmp qword [rbx],1
    jne .bad
    mov rax,[rel pdc_op]
    cmp [rbx+56],rax
    jne .bad
    cmp qword [rbx+64],PUD_SCOPE_ID
    jne .bad
    mov rax,[rel pdc_target]
    cmp [rbx+72],rax
    jne .bad
    mov rax,[rel pdc_generation]
    cmp [rbx+80],rax
    jne .bad
    cmp qword [rbx+88],0
    jne .bad
    mov rax,[rel pdc_text_len]
    cmp [rbx+96],rax
    jne .bad
    lea rdi,[rbx+104]
    lea rsi,[rel pdc_text_hash]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[rbx+136]
    lea rsi,[rel pdc_scope]
    mov edx,64
    call memcmp
    test eax,eax
    jnz .bad
    call pdc_registry_current
    cmp eax,1
    jne .bad
    cmp byte [rel pdc_commit],2
    je .bad
    cmp qword [rel pdc_kind],2
    jne .reload
    mov rdi,[rel pdc_original_request]
    call public_documents_transaction_active
    test eax,eax
    jz .reload
    cmp eax,1
    jne .bad
    mov rdi,[rel pdc_original_request]
    lea rsi,[rel pdc_scope]
    lea rdx,[rel pdc_after]
    mov rcx,[rel pdc_new_id]
    call public_documents_transaction_current
    cmp eax,1
    jne .bad
    jmp .ok
.reload:
    lea rdi,[rel pdc_verify_record]
    lea rsi,[rel pdc_verify_scope]
    lea rdx,[rel pdc_verify_token]
    call public_documents_load
    cmp eax,1
    jne .bad
    lea rdi,[rel pdc_verify_scope]
    lea rsi,[rel pdc_scope]
    mov edx,64
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[rel pdc_verify_digest]
    lea rsi,[rel pdc_verify_record]
    call public_documents_digest
    test eax,eax
    jnz .bad
    lea rsi,[rel pdc_before]
    cmp byte [rel pdc_commit],1
    jne .compare
    lea rsi,[rel pdc_after]
.compare:
    lea rdi,[rel pdc_verify_digest]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
.ok:
    cmp byte [rel pdc_active],1
    jne .bad
    mov r12d,1
    jmp .wipe
.bad:
    xor r12d,r12d
.wipe:
    lea rdi,[rel pdc_verify_record]
    xor eax,eax
    mov ecx,(pdc_verify_end-pdc_verify_record)/8
    cld
    rep stosq
    mov eax,r12d
    pop r12
    pop rbx
    ret

; Execute through the actual shared registry, original TERM request AUTH11.
terminal_documents_execute:          ; desc,out65536,frame,capacity ->CMDE,EDXlen
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    cmp ecx,65536
    jb .deny
    cmp byte [rel pdc_busy],0
    jne .deny
    cmp byte [rel pdc_executed],0
    jne .deny
    call terminal_documents_validate
    cmp eax,1
    jne .deny
    mov byte [rel pdc_busy],1
    mov byte [rel pdc_executed],1
    lea rdi,[rel pdc_desc]
    mov rsi,rbx
    mov ecx,256/8
    cld
    rep movsq
    lea rdi,[rel pdc_request]
    xor eax,eax
    mov ecx,(56+48)/8
    rep stosq
    mov rax,[rel pdc_kind]
    shl rax,5
    lea rdx,[rel pdc_registry]
    mov rax,[rdx+rax+16]
    mov rax,[rax]
    mov [rel pdc_request],rax
    mov rax,[rel pdc_arg]
    mov [rel pdc_request+32],rax
    mov byte [rel pdc_executing],1
    mov rdi,rbx
    lea rsi,[rel pdc_request]
    lea rdx,[rel pdc_response]
    call terminal_policy_command_dispatch
    mov byte [rel pdc_executing],0
    test eax,eax
    jnz .failed
    mov rdi,rbx
    call terminal_documents_validate
    cmp eax,1
    jne .failed
    mov rdi,rbx
    call terminal_policy_copyout
    cmp eax,1
    jne .failed
    cmp byte [rel pdc_active],1
    jne .failed
    mov r13,[rel pdc_output_len]
    cmp r13,65536
    ja .failed
    mov rdi,r12
    lea rsi,[rel pdc_output]
    mov rcx,r13
    cld
    rep movsb
    xor ebx,ebx
    jmp .wipe
.failed:
    mov ebx,6
    xor r13d,r13d
.wipe:
    lea rdi,[rel pdc_output]
    xor eax,eax
    mov ecx,65536/8
    rep stosq
    mov byte [rel pdc_busy],0
    mov eax,ebx
    mov rdx,r13
    jmp .out
.deny:
    mov eax,6
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Actual final handlers have no ambient-owner fast path. Only the exact
; original SEC-minted request may delegate these Documents operations.
pdc_doclist:
    xor edx,edx
    jmp pdc_handler
pdc_docread:
    mov edx,1
    jmp pdc_handler
pdc_docnew:
    mov edx,2
pdc_handler:                         ; CMDREQ56, CMDRSP48
    call cmd_handler_prologue
    push rbx
    push rbp
    push r12
    push r13
    sub rsp,8
    mov r12,rdi
    mov r13,rsi
    mov ebp,edx
    mov ebx,6
    test r13,r13
    jz .out
    mov rdi,r13
    xor eax,eax
    mov ecx,6
    cld
    rep stosq
    mov qword [r13],6
    cmp byte [rel pdc_executing],1
    jne .out
    cmp byte [rel pdc_busy],1
    jne .out
    cmp rbp,[rel pdc_kind]
    jne .out
    test r12,r12
    jz .out
    mov rax,[rel pdc_request]
    cmp [r12],rax
    jne .out
    mov rax,[rel pdc_arg]
    cmp [r12+32],rax
    jne .out
    cmp qword [r12+24],0
    jne .out
    mov [rel pdc_original_request],r12
    mov rdi,r12
    call terminal_policy_command_copyout
    cmp eax,1
    jne .out
    cmp ebp,2
    je .create
    cmp ebp,1
    je .read
    ; Enumerate only rows from the freshly authenticated frozen aggregate.
    lea rdi,[rel pdc_record]
    lea rsi,[rel pdc_scratch_scope]
    lea rdx,[rel pdc_scratch_token]
    call public_documents_load
    cmp eax,1
    jne .out
    lea rbx,[rel pdc_record+PUD_HEADER]
    lea rbp,[rel pdc_list_rows]
    xor r12d,r12d
.list_loop:
    cmp r12d,PUD_ROWS
    jae .pack
    cmp byte [rbx],0
    je .pack
    mov rdi,rbp
    xor eax,eax
    mov ecx,TFL_NATIVE_BYTES/8
    rep stosq
    mov rdi,rbp
    mov rsi,rbx
    mov ecx,PUD_NAME/8
    rep movsq
    mov rax,[rbx+PUD_R_SIZE]
    mov [rbp+TFL_N_SIZE],rax
    mov qword [rbp+TFL_N_CLASS],1
    mov rax,[rbx+PUD_R_ID]
    inc rax
    mov [rbp+TFL_N_TARGET],rax
    mov rax,[rbx+PUD_R_GEN]
    mov [rbp+TFL_N_GEN],rax
    inc r12d
    add rbx,PUD_ROW
    add rbp,TFL_NATIVE_BYTES
    jmp .list_loop
.pack:
    lea rdi,[rel pdc_list_rows]
    mov rsi,r12
    xor edx,edx
    lea rcx,[rel pdc_output]
    mov r8d,65536
    call terminal_fs_list_pack
    cmp rax,-1
    je .refuse
    mov [rel pdc_output_len],rax
    jmp .final
.read:
    lea rdi,[rel pdc_desc]
    lea rsi,[rel pdc_name]
    mov edx,[rel pdc_name_len]
    mov rcx,[rel pdc_offset]
    mov r8,[rel pdc_count]
    lea r9,[rel pdc_output]
    call terminal_fs_read
    cmp rax,-1
    je .refuse
    mov [rel pdc_output_len],rax
    jmp .final
.create:
    mov rdi,r12
    lea rsi,[rel pdc_name]
    mov rdx,[rel pdc_name_len]
    lea rcx,[rel pdc_payload]
    mov r8,[rel pdc_payload_len]
    call public_documents_create
    test rax,rax
    jnz .create_failed
    mov byte [rel pdc_commit],1
    lea rdi,[rel pdc_output]
    mov qword [rdi],1
    mov rax,[rel pdc_new_id]
    mov [rdi+8],rax
    mov qword [rdi+16],1
    mov rax,[rel pdc_payload_len]
    mov [rdi+24],rax
    mov qword [rel pdc_output_len],32
.final:
    lea rdi,[rel pdc_desc]
    call terminal_documents_validate
    cmp eax,1
    jne .refuse
    mov rdi,[rel pdc_original_request]
    call terminal_policy_command_copyout
    cmp eax,1
    jne .refuse
    mov qword [r13],0
    mov rax,[rel pdc_output_len]
    mov [r13+24],rax
    xor ebx,ebx
    jmp .out
.create_failed:
    mov [r13+32],rax                ; -3 means uncertain; never auto-retry
    mov byte [rel pdc_commit],2
.refuse:
    mov ebx,6
.out:
    mov eax,ebx
    add rsp,8
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Native physical owner selection of the sole Documents root: op20, slot0,
; generation0 sentinel (fixed namespace, not a reused widget/drive slot).
terminal_documents_prepare_scope:    ; op,slot,fullgen,out128 ->1/0
    push rbx
    push r12
    mov rbx,rcx
    cmp edi,20
    jne .bad
    test rsi,rsi
    jnz .bad
    test rdx,rdx
    jnz .bad
    cmp byte [rel pdc_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    call session_shell_local_authority
    cmp rax,1
    jne .bad
    mov r12,rdx
    call smp_current_logical
    test eax,eax
    jnz .bad
    test rbx,rbx
    jz .bad
    lea rdi,[rel pdc_verify_record]
    lea rsi,[rel pdc_verify_scope]
    lea rdx,[rel pdc_verify_token]
    call public_documents_load
    cmp eax,1
    jne .bad
    call session_shell_local_authority
    cmp rax,1
    jne .bad
    cmp rdx,r12
    jne .bad
    lea rdi,[rel pdc_scope_candidate]
    xor eax,eax
    mov ecx,128/8
    cld
    rep stosq
    mov qword [rel pdc_scope_candidate],1
    mov qword [rel pdc_scope_candidate+8],20
    mov qword [rel pdc_scope_candidate+16],PUD_SCOPE_ID
    mov qword [rel pdc_scope_candidate+24],1
    mov rax,[rel pdc_verify_record+PUD_OWNER]
    mov [rel pdc_scope_candidate+32],rax
    lea rdi,[rel pdc_scope_candidate+48]
    lea rsi,[rel pdc_verify_scope]
    mov ecx,64/8
    rep movsq
    mov rdi,rbx
    lea rsi,[rel pdc_scope_candidate]
    mov ecx,128/8
    rep movsq
    mov ebx,1
    jmp .wipe
.bad:
    xor ebx,ebx
.wipe:
    call pdc_scope_wipe
    mov eax,ebx
    pop r12
    pop rbx
    ret
terminal_documents_saved_scope:      ; scope128 ->1/0, actual current root proof
    push rbx
    sub rsp,128
    mov rbx,rdi
    ; Same authenticated root check without accepting an arbitrary path or
    ; restoring a PID. Restore caller already supplies fresh local owner bind.
    mov edi,20
    xor esi,esi
    xor edx,edx
    mov rcx,rsp
    call terminal_documents_prepare_scope
    cmp eax,1
    jne .bad
    mov rdi,rsp
    mov rsi,rbx
    mov edx,128
    call memcmp
    test eax,eax
    jnz .bad
    mov ebx,1
    jmp .wipe
.bad:
    xor ebx,ebx
.wipe:
    mov rdi,rsp
    xor eax,eax
    mov ecx,128/8
    rep stosq
    mov eax,ebx
    add rsp,128
    pop rbx
    ret
pdc_scope_wipe:
    push rax
    lea rdi,[rel pdc_verify_record]
    xor eax,eax
    mov ecx,(pdc_verify_end-pdc_verify_record)/8
    cld
    rep stosq
    lea rdi,[rel pdc_scope_candidate]
    mov ecx,128/8
    rep stosq
    pop rax
    ret

; STOP/revoke/endpoint/session retirement wipes operands, output and all IO
; identities; original in-flight stack owns its lock until it unwinds.
terminal_documents_retire:
    pushfq
    push rax
    push rcx
    push rdi
    call terminal_fs_retire
    call public_documents_read_retire
    call public_documents_retire
    mov byte [rel pdc_active],0
    mov byte [rel pdc_executing],0
    lea rdi,[rel pdc_private]
    xor eax,eax
    mov ecx,(pdc_private_end-pdc_private)/8
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    popfq
    ret
%macro WDATA_command_documents 0
align 8
pdc_ops: times 6 dq 0
pdc_registry: times 12 dq 0
verb_id_doclist: dq -1
verb_id_docread: dq -1
verb_id_docnew: dq -1
pdc_name_list: db 'DOCLIST',0
pdc_name_read: db 'DOCREAD',0
pdc_name_new: db 'DOCNEW',0
pdc_registered: db 0
pdc_busy: db 0
pdc_active: db 0
pdc_executing: db 0
align 8
pdc_private:
pdc_kind: dq 0
pdc_op: dq 0
pdc_target: dq 0
pdc_generation: dq 0
pdc_new_id: dq 0
pdc_arg: dq 0
pdc_original_request: dq 0
pdc_name_len: dq 0
pdc_payload_len: dq 0
pdc_offset: dq 0
pdc_count: dq 0
pdc_text_len: dq 0
pdc_output_len: dq 0
pdc_commit: db 0
pdc_executed: db 0
    times 6 db 0
pdc_name: times 64 db 0
pdc_payload: times 384 db 0
pdc_text: times 1024 db 0
pdc_text_hash: times 32 db 0
pdc_before: times 32 db 0
pdc_after: times 32 db 0
pdc_scope: times 64 db 0
pdc_token: times 112 db 0
pdc_record: times PUD_BYTES db 0
pdc_desc: times 256 db 0
pdc_request: times 56 db 0
pdc_response: times 48 db 0
pdc_scratch_scope: times 64 db 0
pdc_scratch_token: times 112 db 0
pdc_list_rows: times PUD_ROWS*TFL_NATIVE_BYTES db 0
pdc_verify_record: times PUD_BYTES db 0
pdc_verify_scope: times 64 db 0
pdc_verify_token: times 112 db 0
pdc_verify_digest: times 32 db 0
pdc_verify_end:
pdc_scope_candidate: times 128 db 0
pdc_output: times 65536 db 0
pdc_private_end:
%endmacro
WDATA_DEFER WDATA_command_documents
