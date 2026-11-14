;; MODULE hv/app_vm_payload
;; LAYER 5
;; EXPORTS app_vm_payload_load, app_vm_payload_current, app_vm_payload_hash, app_vm_payload_retire, avm_payload_valid, avm_handle, avm_payload_bytes, avm_session, avm_owner
;; IMPORTS hv/app_vm_memory, svc/app_script, core/lib/sha256, sec/session
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; The signed bundle is copied into native control RAM excluded from EPT/NPT.
; There is no caller-provided digest, guest pointer, executable native payload,
; callback verifier or alternate unsigned path. No principal is published here.
%include "hv/app_vm.inc"

; RDI=current app_script handle ->1/0. Private LOADING lifecycle only.
; Snapshot, exact copy, hash actual copied bytes, then recheck whole snapshot.
; A failed copy/verification never leaves a valid payload marker.
app_vm_payload_load:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov byte [rel avm_payload_valid],0
    cmp qword [rel avm_state],AVM_LOADING
    jne .bad
    cmp qword [rel avm_token],0
    je .bad
    cmp qword [rel avm_cpu_live],0
    jne .bad
    cmp qword [rel avm_roots_retired],1
    jne .bad
    mov rax,[rel avm_clear_offset]
    cmp rax,[rel avm_capacity]
    jne .bad
    test r12,r12
    jz .bad
    call session_shell_local_authority
    test rax,rax
    jz .bad
    mov [rel avm_owner],rax
    mov r13,[rel session_authority_epoch]
    test r13,r13
    jz .bad
    cmp r13,-1
    je .bad
    mov [rel avm_session],r13
    mov [rel avm_handle],r12
    mov rbx,[rel avm_base]
    mov rdi,r12
    lea rsi,[rbx+AVM_DESCRIPTOR]
    mov edx,AVM_DESCRIPTOR_BYTES
    call app_script_descriptor
    cmp eax,1
    jne .bad
    cmp qword [rbx+AVM_DESCRIPTOR],1
    jne .bad
    cmp [rbx+AVM_DESCRIPTOR+8],r12
    jne .bad
    mov rcx,[rbx+AVM_DESCRIPTOR+16]
    cmp rcx,656
    jb .bad
    cmp rcx,AVM_PAYLOAD_MAX
    ja .bad
    cmp qword [rbx+AVM_DESCRIPTOR+368],1
    jne .bad
    cmp qword [rbx+AVM_DESCRIPTOR+376],0
    jne .bad
    mov [rel avm_payload_bytes],rcx
    mov rdi,r12
    xor esi,esi
    lea rdx,[rbx+AVM_PAYLOAD]
    call app_script_copy
    cmp eax,1
    jne .bad
    ; Hash the private image, not source, claimed metadata or driver RAM.
    call app_vm_payload_hash
    test eax,eax
    jz .bad
    mov byte [rel avm_payload_valid],1
    call app_vm_payload_current
    test eax,eax
    jz .bad
    mov eax,1
    jmp .out
.bad:
    call app_vm_payload_retire
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Rehash exact immutable copy. Also called at activation, BEFORE guest entry.
; The lifecycle serializes this service; no yielding or guest execution here.
app_vm_payload_hash:
    push rbx
    mov rbx,[rel avm_base]
    cmp qword [rel avm_token],0
    je .bad
    mov rdx,[rel avm_payload_bytes]
    cmp rdx,656
    jb .bad
    cmp rdx,AVM_PAYLOAD_MAX
    ja .bad
    lea rdi,[rbx+AVM_DIGEST]
    lea rsi,[rbx+AVM_PAYLOAD]
    call sha256_hash
    test rax,rax
    jnz .bad
    lea rsi,[rbx+AVM_DIGEST]
    lea rdi,[rbx+AVM_DESCRIPTOR+32]
    mov ecx,32
    cld
    repe cmpsb
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Current verifier object AND exact session/owner must remain live. Replacing
; a signed bundle with even identical bytes changes its native handle. Native
; callers must retire the app on refusal, before any next effect or guest turn.
app_vm_payload_current:
    push rbx
    cmp byte [rel avm_payload_valid],1
    jne .bad
    cmp qword [rel avm_token],0
    je .bad
    ; Native read-only currentness also runs inside actual GUES admission.
    ; Public load/copy above still requires local OWNER authority.
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    cmp qword [rel session_key_handle],0
    je .bad
    mov rax,[rel session_bound_pid]
    test rax,rax
    jz .bad
    cmp rax,[rel avm_owner]
    jne .bad
    mov rax,[rel session_authority]
    cmp rax,[rel session_authority_epoch]
    jne .bad
    mov rax,[rel avm_session]
    test rax,rax
    jz .bad
    cmp rax,[rel session_authority_epoch]
    jne .bad
    mov rbx,[rel avm_base]
    mov rdi,[rel avm_handle]
    lea rsi,[rbx+AVM_DESC_CHECK]
    mov edx,AVM_DESCRIPTOR_BYTES
    call app_script_native_descriptor
    cmp eax,1
    jne .bad
    lea rdi,[rbx+AVM_DESCRIPTOR]
    lea rsi,[rbx+AVM_DESC_CHECK]
    mov ecx,AVM_DESCRIPTOR_BYTES/8
    cld
    repe cmpsq
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Invalidates before the lifecycle's CPU retirement or bounded full scrub.
; A RUNNING VM can never regain this marker except through a fresh prepare.
app_vm_payload_retire:
    mov byte [rel avm_payload_valid],0
    mov qword [rel avm_handle],0
    mov qword [rel avm_payload_bytes],0
    mov qword [rel avm_session],0
    mov qword [rel avm_owner],0
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_app_vm_payload 0
align 8
avm_handle: dq 0
avm_payload_bytes: dq 0
avm_session: dq 0
avm_owner: dq 0
avm_payload_valid: db 0
%endmacro
WDATA_DEFER WDATA_hv_app_vm_payload
