;; MODULE sec/terminal_providers
;; LAYER 6
;; PURPOSE Independent native GUI/FS provider slots and isolated final planning.
;; EXPORTS terminal_policy_provider_register
;; IMPORTS sec/terminal_policy, sec/terminal_native
;; OWNER saga:terminal_policy
;; CONTEXT: bsp_only
; register(RDI kind1 GUI /2 FS,RSI table6 or0)->1/0, native idle only.
; All six callbacks are required. Copy before invalidation so even replacing
; a slot with its own table cannot observe a partially retired registration.
; Reconfiguration fences all old grants/results/clicks; replay floors survive.
terminal_policy_provider_register:
    push rbx
    push r12
    sub rsp,48
    mov rbx,rdi
    mov r12,rsi
    call tp_native_idle
    test eax,eax
    jz .bad
    cmp byte [rel tpp_planning],0
    jne .bad
    cmp rbx,1
    jb .bad
    cmp rbx,2
    ja .bad
    mov rdi,rsp
    xor eax,eax
    mov ecx,6
    rep stosq
    test r12,r12
    jz .install
    mov rsi,r12
    mov rdi,rsp
    mov ecx,6
.copy:
    lodsq
    test rax,rax
    jz .bad
    stosq
    loop .copy
.install:
    ; Keep the six-qword native pointer ABI. An org0 data initializer stores
    ; image offsets, so materialize actual mapped callbacks only after all
    ; original idle/planning/kind/completeness guards have passed.
    lea rax,[rel tpp_plan]
    mov [rel tpp_ops],rax
    lea rax,[rel tpp_validate]
    mov [rel tpp_ops+8],rax
    lea rax,[rel tpp_execute]
    mov [rel tpp_ops+16],rax
    lea rax,[rel tpp_prepare]
    mov [rel tpp_ops+24],rax
    lea rax,[rel tpp_restore_validate]
    mov [rel tpp_ops+32],rax
    lea rax,[rel tpp_retire]
    mov [rel tpp_ops+40],rax
    lea rdi,[rel tpp_ops]
    call terminal_policy_native_configure
    cmp eax,1
    jne .bad
    dec rbx
    imul rbx,48
    lea rdi,[rel tpp_slots]
    add rdi,rbx
    mov rsi,rsp
    mov ecx,6
    rep movsq
    mov r12d,1
    jmp .wipe
.bad:
    xor r12d,r12d
.wipe:
    mov rdi,rsp
    xor eax,eax
    mov ecx,6
    rep stosq
    mov eax,r12d
    add rsp,48
    pop r12
    pop rbx
    ret

; Closed ownership: RAX actual final op -> EAX kind1/2 or0. No fallthrough
; to settings/install/public-value authority until a real owner adapter exists.
tpp_kind:
    cmp rax,TP_DESKTOP
    jb .none
    cmp rax,TP_UI_READ
    jbe .gui
    cmp rax,TP_DATA_READ
    je .fs
    cmp rax,TP_FOLDER_READ
    je .fs
    cmp rax,TP_FILL
    jb .none
    cmp rax,TP_CLOSE
    jbe .gui
    cmp rax,TP_STORAGE_WRITE
    je .fs
.none:
    xor eax,eax
    ret
.gui:
    mov eax,1
    ret
.fs:
    mov eax,2
    ret

; Plan is a non-effecting bounded native proof. Try GUI then FS using fresh
; private copies of BOTH records; refused writes never reach the next owner.
; A successful planner claiming the other domain rejects the whole invocation.
; Actual effect/copyout helpers accept only the owned active descriptor, so
; this scratch record cannot mint a command ticket or spend a click.
tpp_plan:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    xor r14d,r14d
    xor r15d,r15d
    cmp byte [rel tpp_planning],0
    jne .out
    mov byte [rel tpp_planning],1
.next:
    imul rbx,r14,48
    lea rax,[rel tpp_slots]
    add rbx,rax
    cmp qword [rbx],0
    je .advance
    lea rdi,[rel tpp_request]
    mov rsi,r12
    mov ecx,TP_WIRE_BYTES/8
    rep movsq
    lea rdi,[rel tpp_desc]
    mov rsi,r13
    mov ecx,TP_DESC_BYTES/8
    rep movsq
    lea rdi,[rel tpp_request]
    lea rsi,[rel tpp_desc]
    call [rbx]
    cmp eax,1
    jne .refused
    mov rax,[rel tpp_desc+TP_D_OP]
    call tpp_kind
    lea rcx,[r14+1]
    cmp rax,rcx
    jne .wrong_owner
    mov rdi,r12
    lea rsi,[rel tpp_request]
    mov ecx,TP_WIRE_BYTES/8
    rep movsq
    mov rdi,r13
    lea rsi,[rel tpp_desc]
    mov ecx,TP_DESC_BYTES/8
    rep movsq
    mov r15d,1
    jmp .wipe
.refused:
    call [rbx+40]                   ; cancel only this owner's staging
.advance:
    inc r14d
    cmp r14d,2
    jb .next
    jmp .wipe
.wrong_owner:
    call [rbx+40]
.wipe:
    call tpp_wipe
    mov byte [rel tpp_planning],0
.out:
    mov eax,r15d
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Route the immutable descriptor by actual operation for every proof/effect.
; Preserve input registers (execute uses RSI/RDX/RCX), return slot in RAX.
tpp_desc_slot:
    mov rax,[rdi+TP_D_OP]
    jmp tpp_slot
tpp_scope_slot:
    mov rax,[rdi+TP_S_OP]
    cmp rax,TP_DESKTOP
    jb .bad
    cmp rax,TP_FOLDER_READ
    ja .bad
    jmp tpp_slot
.bad:
    xor eax,eax
    ret
tpp_slot:
    call tpp_kind
    test eax,eax
    jz .out
    dec eax
    imul eax,48
    lea r10,[rel tpp_slots]
    add rax,r10
.out:
    ret

tpp_validate:
    call tpp_desc_slot
    test rax,rax
    jz tpp_false
    cmp qword [rax+8],0
    je tpp_false
    jmp [rax+8]
tpp_execute:
    call tpp_desc_slot
    test rax,rax
    jz .deny
    cmp qword [rax+16],0
    je .deny
    jmp [rax+16]
.deny:
    mov eax,CMDE_AUTHDENY
    xor edx,edx
    ret
tpp_prepare:
    mov rax,rdi
    cmp rax,TP_DESKTOP
    jb tpp_false
    cmp rax,TP_FOLDER_READ
    ja tpp_false
    call tpp_slot
    test rax,rax
    jz tpp_false
    cmp qword [rax+24],0
    je tpp_false
    jmp [rax+24]
tpp_restore_validate:
    call tpp_scope_slot
    test rax,rax
    jz tpp_false
    cmp qword [rax+32],0
    je tpp_false
    jmp [rax+32]
tpp_false:
    xor eax,eax
    ret

; Provider retire callbacks are preserving/nonrecursive by contract. Our outer
; wrapper preserves all volatile registers/flags even for a noisy native leaf.
tpp_retire:
    TP_SAVE_VOL
    cmp qword [rel tpp_slots+40],0
    je .fs
    call [rel tpp_slots+40]
.fs:
    cmp qword [rel tpp_slots+48+40],0
    je .wipe
    call [rel tpp_slots+48+40]
.wipe:
    call tpp_wipe
    TP_RESTORE_VOL
    ret
tpp_wipe:
    lea rdi,[rel tpp_request]
    xor eax,eax
    mov ecx,(TP_WIRE_BYTES+TP_DESC_BYTES)/8
    rep stosq
    ret

%macro WDATA_terminal_providers 0
align 8
tpp_slots: times 12 dq 0
tpp_ops: times 6 dq 0
tpp_planning: db 0
align 8
tpp_request: times TP_WIRE_BYTES db 0
tpp_desc: times TP_DESC_BYTES db 0
%endmacro
WDATA_DEFER WDATA_terminal_providers
