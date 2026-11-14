;; MODULE fs/public_documents
;; LAYER 4
;; EXPORTS public_documents_transaction_active, public_documents_digest, public_documents_build, public_documents_transaction_current, public_documents_name_check, public_documents_record_check, public_documents_current, public_documents_load, public_documents_create, public_documents_write_check, public_documents_sign_authorized, public_documents_retire
;; IMPORTS fs/data_config_authority, fs/data_config_provider, fs/vol_owner_data, fs/terminal_read, sec/public_documents_seal, sec/terminal_command, core/smp, core/lib/mem, core/lib/sha256
;; OWNER rc-fs-claude
;; CONTEXT: bsp_only
%include "fs/public_documents.inc"
; The logical Documents root is a NEW native namespace, not a relabeling of
; DATA/config, a granted arbitrary path, or an imported FAT directory. Only the
; explicit native creator below can authenticate rows. The aggregate itself
; remains a private implementation record; read/list project ordinary rows.

; One canonical, case-sensitive UTF-8 leaf, 1..63 bytes. No aliases, hierarchy,
; traversal, hidden tail or filesystem indirection in this bounded namespace.
public_documents_name_check:
    push rbx
    push r12
    sub rsp,8
    mov rbx,rdi
    mov r12,rsi
    test rsi,rsi
    jz .bad
    cmp rsi,PUD_NAME-1
    ja .bad
    test rdi,rdi
    jz .bad
    xor edx,edx
    call terminal_fs_path_check
    test eax,eax
    jnz .bad
    xor ecx,ecx
.scan:
    cmp byte [rbx+rcx],'/'
    je .bad
    ; The first command grammar is whitespace-delimited. Reject space rather
    ; than publishing a document the maintained native command cannot name.
    cmp byte [rbx+rcx],' '
    je .bad
    inc rcx
    cmp rcx,r12
    jb .scan
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; Exact native4224 record shape and content hashes, independent of MAC/open.
; Zero padding and increasing IDs exclude aliases, stale retained bytes and
; ambiguous slots. Input is immutable; empty/unknown format cannot confer class.
public_documents_record_check:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,40
    mov r12,rdi
    test r12,r12
    jz .bad
    mov rax,PUD_MAGIC
    cmp [r12],rax
    jne .bad
    cmp qword [r12+8],1
    jne .bad
    cmp qword [r12+PUD_OWNER],0
    je .bad
    mov r15,[r12+PUD_NEXT]
    test r15,r15
    jz .bad
    cmp r15,-1
    je .bad
    mov rax,[r12+PUD_KEY]
    or rax,[r12+PUD_KEY+8]
    or rax,[r12+PUD_KEY+16]
    or rax,[r12+PUD_KEY+24]
    jz .bad
    mov rax,[r12+PUD_KEY+32]
    or rax,[r12+PUD_KEY+40]
    or rax,[r12+PUD_KEY+48]
    or rax,[r12+PUD_KEY+56]
    jz .bad
    lea r13,[r12+PUD_HEADER]
    xor ebx,ebx                         ; previous native document ID
    xor ebp,ebp                         ; row index; nonempty rows precede zero rows
    xor r14d,r14d                       ; empty suffix seen
.row:
    mov rax,[r13+PUD_R_ID]
    test rax,rax
    jz .empty
    test r14d,r14d
    jnz .bad
    cmp rax,rbx
    jbe .bad
    cmp rax,r15
    jae .bad
    mov rbx,rax
    cmp qword [r13+PUD_R_GEN],1
    jne .bad
    cmp qword [r13+PUD_R_SIZE],PUD_PAYLOAD
    ja .bad
    cmp qword [r13+88],0
    jne .bad
    xor ecx,ecx
.name:
    cmp byte [r13+rcx],0
    je .name_end
    inc ecx
    cmp ecx,PUD_NAME
    jb .name
    jmp .bad
.name_end:
    mov rdi,r13
    mov esi,ecx
    mov [rsp+32],rcx
    call public_documents_name_check
    cmp eax,1
    jne .bad
    mov rcx,[rsp+32]
.name_pad:
    cmp byte [r13+rcx],0
    jne .bad
    inc ecx
    cmp ecx,PUD_NAME
    jb .name_pad
    ; Every name is unique by native exact bytes, including case. No FAT LFN
    ; or short spelling is resolved to this logical object by the provider.
    lea r14,[r12+PUD_HEADER]
.unique:
    cmp r14,r13
    jae .data
    mov rdi,r13
    mov rsi,r14
    mov edx,PUD_NAME
    call memcmp
    test rax,rax
    jz .bad
    add r14,PUD_ROW
    jmp .unique
.data:
    xor r14d,r14d
    mov rcx,[r13+PUD_R_SIZE]
.data_pad:
    cmp rcx,PUD_PAYLOAD
    jae .hash
    cmp byte [r13+PUD_R_DATA+rcx],0
    jne .bad
    inc ecx
    jmp .data_pad
.hash:
    mov rdi,rsp
    lea rsi,[r13+PUD_R_DATA]
    mov rdx,[r13+PUD_R_SIZE]
    call sha256_hash
    test rax,rax
    jnz .bad
    mov rdi,rsp
    lea rsi,[r13+PUD_R_HASH]
    mov edx,32
    call memcmp
    test rax,rax
    jnz .bad
    jmp .next
.empty:
    mov r14d,1
    xor ecx,ecx
.zero:
    cmp qword [r13+rcx],0
    jne .bad
    add ecx,8
    cmp ecx,PUD_ROW
    jb .zero
.next:
    add r13,PUD_ROW
    inc ebp
    cmp ebp,PUD_ROWS
    jb .row
    mov ebx,1
    jmp .wipe
.bad:
    xor ebx,ebx
.wipe:
    mov rdi,rsp
    xor eax,eax
    mov ecx,5
    cld
    rep stosq
    mov eax,ebx
    add rsp,40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Internal metadata/root identity recheck. The sealed role is sampled again;
; full accepted GPT/header/table/BPB and actual generation are checked by the
; existing provider. No rebinding, cached class, or positive path-prefix proof.
; RDI token112, RSI expected root64 ->1/0, no output.
public_documents_current:
    push rbx
    push r12
    push r13
    sub rsp,128
    mov r12,rdi
    mov r13,rsi
    call data_config_current
    test rax,rax
    jnz .bad
    mov rdi,rsp
    call vol_owner_data_identity
    test eax,eax
    jnz .bad
    lea rdi,[rsp+64]
    mov rsi,rsp
    call public_documents_root_key
    cmp eax,1
    jne .bad
    lea rdi,[rsp+64]
    mov rsi,r13
    mov edx,64
    call memcmp
    test rax,rax
    jnz .bad
    mov rdi,r12
    call data_config_current
    test rax,rax
    jnz .bad
    mov ebx,1
    jmp .wipe
.bad:
    xor ebx,ebx
.wipe:
    mov rdi,rsp
    xor eax,eax
    mov ecx,16
    cld
    rep stosq
    mov eax,ebx
    add rsp,128
    pop r13
    pop r12
    pop rbx
    ret

; Semantic aggregate digest: MAC bytes excluded, every other byte included.
; Native immutable record and mapped out32. Used to freeze exact constructor
; before spending, and to prove that exact result after durable publication.
public_documents_digest:                 ; RDI out32, RSI record4224 ->0/-1
    push r12
    sub rsp,PUD_BYTES
    mov r12,rdi
    mov rdi,rsp
    mov ecx,PUD_BYTES/8
    cld
    rep movsq
    lea rdi,[rsp+PUD_MAC]
    xor eax,eax
    mov ecx,4
    rep stosq
    mov rdi,r12
    mov rsi,rsp
    mov edx,PUD_BYTES
    call sha256_hash
    mov r12,rax
    mov rdi,rsp
    xor eax,eax
    mov ecx,PUD_BYTES/8
    rep stosq
    mov rax,r12
    add rsp,PUD_BYTES
    pop r12
    ret

; Bounded native constructor. record4224,name span,length,payload,length ->
; new ID/-1. Stage one complete zero-padded row before changing the record.
; No IO, signature, principal, public class or click comes from this helper.
public_documents_build:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,PUD_ROW+8
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    mov rbp,r8
    cmp rbp,PUD_PAYLOAD
    ja .bad
    test rbp,rbp
    jz .name
    test r15,r15
    jz .bad
.name:
    mov rdi,r13
    mov rsi,r14
    call public_documents_name_check
    cmp eax,1
    jne .bad
    mov rdi,r12
    call public_documents_record_check
    cmp eax,1
    jne .bad
    mov rbx,[r12+PUD_NEXT]
    cmp rbx,-2
    jae .bad
    lea r9,[r12+PUD_HEADER]
    mov r10d,PUD_ROWS
.slot:
    cmp qword [r9+PUD_R_ID],0
    je .build
    mov rdi,r9
    mov rsi,r13
    mov rdx,r14
    call memcmp
    test rax,rax
    jnz .next
    cmp byte [r9+r14],0
    je .bad
.next:
    add r9,PUD_ROW
    dec r10d
    jnz .slot
    jmp .bad
.build:
    mov [rsp+PUD_ROW],r9
    mov rdi,rsp
    xor eax,eax
    mov ecx,PUD_ROW/8
    rep stosq
    mov [rsp+PUD_R_ID],rbx
    mov qword [rsp+PUD_R_GEN],1
    mov [rsp+PUD_R_SIZE],rbp
    mov rdi,rsp
    mov rsi,r13
    mov rcx,r14
    rep movsb
    lea rdi,[rsp+PUD_R_DATA]
    mov rsi,r15
    mov rcx,rbp
    rep movsb
    lea rdi,[rsp+PUD_R_HASH]
    lea rsi,[rsp+PUD_R_DATA]
    mov rdx,rbp
    call sha256_hash
    test rax,rax
    jnz .bad
    mov rdi,[rsp+PUD_ROW]
    mov rsi,rsp
    mov ecx,PUD_ROW/8
    rep movsq
    inc qword [r12+PUD_NEXT]
    jmp .wipe
.bad:
    mov rbx,-1
.wipe:
    mov rdi,rsp
    xor eax,eax
    mov ecx,(PUD_ROW+8)/8
    rep stosq
    mov rax,rbx
    add rsp,PUD_ROW+8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Exact active constructor proof, used ONLY while its synchronous DATA journal
; is in flight. It cannot authorize a different operation or serve as a
; post-effect tombstone. Outside this frame the provider must reopen and prove
; the exact authenticated created record again, including PAGE copyout checks.
; RDI original req, RSI root64, RDX expected semantic digest32, RCX new doc ID.
public_documents_transaction_active:    ; exact request ->1 active /0 idle /-1 other
    cmp byte [rel pud_create_busy],0
    je .idle
    cmp byte [rel pud_create_phase],1
    jb .other
    cmp byte [rel pud_create_phase],2
    ja .other
    cmp rdi,[rel pud_create_request]
    jne .other
    mov eax,1
    ret
.idle:
    xor eax,eax
    ret
.other:
    mov eax,-1
    ret

public_documents_transaction_current:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,32
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    cmp byte [rel pud_create_busy],1
    jne .bad
    cmp byte [rel pud_create_phase],1
    jb .bad
    cmp byte [rel pud_create_phase],2
    ja .bad
    cmp r12,[rel pud_create_request]
    jne .bad
    mov rax,[rel pud_create_image+PUD_NEXT]
    dec rax
    cmp rax,r15
    jne .bad
    lea rdi,[rel pud_create_scope]
    mov rsi,r13
    mov edx,64
    call memcmp
    test rax,rax
    jnz .bad
    lea rdi,[rel pud_create_token]
    mov rsi,r13
    call public_documents_current
    cmp eax,1
    jne .bad
    mov rdi,rsp
    lea rsi,[rel pud_create_image]
    call public_documents_digest
    test rax,rax
    jnz .bad
    mov rdi,rsp
    mov rsi,r14
    mov edx,32
    call memcmp
    test rax,rax
    jnz .bad
    cmp r12,[rel pud_create_request]
    jne .bad
    cmp byte [rel pud_create_phase],1
    jb .bad
    cmp byte [rel pud_create_phase],2
    ja .bad
    mov ebx,1
    jmp .wipe
.bad:
    xor ebx,ebx
.wipe:
    mov rdi,rsp
    xor eax,eax
    mov ecx,4
    cld
    rep stosq
    mov eax,ebx
    add rsp,32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; load(out record4224, out root64, out token112)->1/0. Native mapped private
; outputs only, disjoint from this module. Every failure leaves them untouched.
; Confirmed absence creates an empty *logical* native namespace in memory;
; it does not write or classify any preexisting disk content. A malformed,
; foreign-owner, unsigned, unreadable or wrong-root record is never empty.
public_documents_load:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    call smp_current_logical
    test eax,eax
    jnz .bad
    test r12,r12
    jz .bad
    test r13,r13
    jz .bad
    test r14,r14
    jz .bad
    cmp byte [rel pud_load_busy],0
    jne .bad
    mov byte [rel pud_load_busy],1
    mov byte [rel pud_load_active],1
    lea rdi,[rel pud_load_token]
    call data_config_acquire_provisioned
    test rax,rax
    jnz .fail
    lea rdi,[rel pud_load_volume]
    call vol_owner_data_identity
    test eax,eax
    jnz .fail
    lea rdi,[rel pud_load_scope]
    lea rsi,[rel pud_load_volume]
    call public_documents_root_key
    cmp eax,1
    jne .fail
    lea rdi,[rel pud_load_token]
    lea rsi,[rel pud_store_name]
    lea rdx,[rel pud_load_image]
    mov ecx,PUD_BYTES
    call data_config_read
    cmp rax,-4                          ; native confirmed complete absence only
    je .empty
    cmp rax,PUD_BYTES
    jne .fail
    lea rdi,[rel pud_load_image]
    mov esi,PUD_BYTES
    call public_documents_seal_open
    cmp eax,1
    jne .fail
    lea rdi,[rel pud_load_image+PUD_KEY]
    lea rsi,[rel pud_load_scope]
    mov edx,64
    call memcmp
    test rax,rax
    jnz .fail
    jmp .current
.empty:
    lea rdi,[rel pud_load_image]
    xor eax,eax
    mov ecx,PUD_BYTES/8
    cld
    rep stosq
    mov rax,PUD_MAGIC
    mov [rel pud_load_image],rax
    mov qword [rel pud_load_image+8],1
    mov rax,[rel public_documents_owner_generation]
    mov [rel pud_load_image+PUD_OWNER],rax
    mov qword [rel pud_load_image+PUD_NEXT],1
    lea rdi,[rel pud_load_image+PUD_KEY]
    lea rsi,[rel pud_load_scope]
    mov ecx,8
    rep movsq
.current:
    lea rdi,[rel pud_load_token]
    lea rsi,[rel pud_load_scope]
    call public_documents_current
    cmp eax,1
    jne .fail
    cmp byte [rel pud_load_active],1
    jne .fail
    mov rdi,r12
    lea rsi,[rel pud_load_image]
    mov ecx,PUD_BYTES/8
    rep movsq
    mov rdi,r13
    lea rsi,[rel pud_load_scope]
    mov ecx,8
    rep movsq
    mov rdi,r14
    lea rsi,[rel pud_load_token]
    mov ecx,14
    rep movsq
    mov ebx,1
    jmp .wipe
.fail:
    xor ebx,ebx
.wipe:
    lea rdi,[rel pud_load_private]
    xor eax,eax
    mov ecx,pud_load_end-pud_load_private
    rep stosb
    mov byte [rel pud_load_active],0
    mov byte [rel pud_load_busy],0
    mov eax,ebx
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; create(original native CMDREQ56, name span, length, explicit payload,
;        payload length0..384)->0 durable /-1 refused /-2 busy /-3 uncertain.
; Only the real shared-registry handler calls this. No path, mount, callback,
; key, credential, import-source or claimed principal is accepted as authority.
public_documents_create:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    mov rbp,r8
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp rbp,PUD_PAYLOAD
    ja .bad
    test rbp,rbp
    jz .name
    test r15,r15
    jz .bad
.name:
    mov rdi,r13
    mov rsi,r14
    call public_documents_name_check
    cmp eax,1
    jne .bad
    cmp byte [rel pud_create_busy],0
    jne .busy
    mov rdi,r12
    call terminal_policy_command_copyout
    cmp eax,1
    jne .bad
    mov byte [rel pud_create_busy],1
    mov byte [rel pud_create_phase],1
    mov [rel pud_create_request],r12
    lea rdi,[rel pud_create_name]
    mov rsi,r13
    mov rcx,r14
    cld
    rep movsb
    lea rdi,[rel pud_create_payload]
    mov rsi,r15
    mov rcx,rbp
    rep movsb
    lea rdi,[rel pud_create_image]
    lea rsi,[rel pud_create_scope]
    lea rdx,[rel pud_create_token]
    call public_documents_load
    cmp eax,1
    jne .fail
    cmp byte [rel pud_create_phase],1
    jne .fail
    lea rdi,[rel pud_create_image]
    lea rsi,[rel pud_create_name]
    mov rdx,r14
    lea rcx,[rel pud_create_payload]
    mov r8,rbp
    call public_documents_build
    cmp rax,-1
    je .fail
    lea rdi,[rel pud_create_image]
    mov esi,PUD_BYTES
    call public_documents_seal_sign
    cmp eax,1
    jne .fail
    call public_documents_sign_authorized
    cmp eax,1
    jne .fail
    ; One semantic mutation, frozen exact name/payload/root. The existing
    ; journal publishes an immutable private snapshot and checks the ORIGINAL
    ; request plus volume/role before every physical write/flush thereafter.
    mov rdi,r12
    call terminal_policy_command_effect
    cmp eax,1
    jne .fail
    cmp byte [rel pud_create_phase],1
    jne .fail
    mov byte [rel pud_create_phase],2
    lea rdi,[rel pud_create_token]
    lea rsi,[rel pud_store_name]
    lea rdx,[rel pud_create_image]
    mov ecx,PUD_BYTES
    mov r8,r12
    mov r9,r12
    call data_config_write_documents
    mov rbx,rax
    test rax,rax
    jnz .wipe
    cmp byte [rel pud_create_phase],2
    jne .uncertain
    mov rdi,r12
    call terminal_policy_command_copyout
    cmp eax,1
    jne .uncertain
    xor ebx,ebx
    jmp .wipe
.uncertain:
    mov rbx,-3
    jmp .wipe
.fail:
    mov rbx,-1
.wipe:
    lea rdi,[rel pud_create_private]
    xor eax,eax
    mov ecx,pud_create_end-pud_create_private
    rep stosb
    mov byte [rel pud_create_phase],0
    mov byte [rel pud_create_busy],0
    mov rax,rbx
    jmp .out
.busy:
    mov rax,-2
    jmp .out
.bad:
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

; Sign check does not spend the click; no unsigned content gains a class.
public_documents_sign_authorized:
    cmp byte [rel pud_create_busy],1
    jne .bad
    cmp byte [rel pud_create_phase],1
    jne .bad
    mov rdi,[rel pud_create_request]
    jmp terminal_policy_command_copyout
.bad:
    xor eax,eax
    ret

; Fixed DATA mode4 checker ->0/-1. It never manufactures OWNER authority.
; Repeated at every physical effect, including the journal's cleanup writes.
public_documents_write_check:           ; R8/R9 exact original CMDREQ pointer
    push r8
    push r9
    sub rsp,8
    cmp byte [rel pud_create_busy],1
    jne .bad
    cmp byte [rel pud_create_phase],2
    jne .bad
    mov rdi,[rel pud_create_request]
    test rdi,rdi
    jz .bad
    cmp rdi,r8
    jne .bad
    cmp rdi,r9
    jne .bad
    call terminal_policy_command_copyout
    cmp eax,1
    jne .bad
    xor eax,eax
    jmp .out
.bad:
    mov rax,-1
.out:
    add rsp,8
    pop r9
    pop r8
    ret

; Preserving synchronous cancel. Original frames retain their reentry locks;
; resumed IO cannot return success or release bytes after revoke/STOP/lock.
public_documents_retire:
    pushfq
    push rax
    push rcx
    push rdi
    mov byte [rel pud_load_active],0
    mov byte [rel pud_create_phase],0
    lea rdi,[rel pud_load_private]
    xor eax,eax
    mov ecx,pud_load_end-pud_load_private
    cld
    rep stosb
    lea rdi,[rel pud_create_private]
    mov ecx,pud_create_end-pud_create_private
    rep stosb
    pop rdi
    pop rcx
    pop rax
    popfq
    ret

pud_store_name: db 'PAOSDOCSBIN'
%macro WDATA_BSS_public_documents 0
alignb 8
pud_load_busy: resb 1
pud_load_active: resb 1
pud_create_busy: resb 1
pud_create_phase: resb 1
alignb 8
pud_load_private:
pud_load_image: resb PUD_BYTES
pud_load_volume: resb 64
pud_load_scope: resb 64
pud_load_token: resb 112
pud_load_end:
alignb 8
pud_create_private:
pud_create_request: resq 1
pud_create_name: resb PUD_NAME
pud_create_payload: resb PUD_PAYLOAD
pud_create_image: resb PUD_BYTES
pud_create_scope: resb 64
pud_create_token: resb 112
pud_create_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_public_documents
