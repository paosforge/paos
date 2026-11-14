;; MODULE gui/app_installed
;; LAYER 6
;; PURPOSE Local owner launch projection from an actual authenticated installed row.
;; EXPORTS app_installed_declare, app_installed_tick
;; IMPORTS svc/app_store, svc/app_script, svc/app_package, svc/app_analysis, sec/app_install_grants, gui/app_launcher, gui/app_launch_flow, svc/command, sec/session, core/smp, core/heap, core/time, core/lib/sha256
;; OWNER saga:app_store
;; CONTEXT: bsp_only
%include "fs/app_store_layout.inc"
; APPRUN <nonreused entry ID>. Merely queues a native catalog lookup; no remote,
; agent or script source can publish a launcher. The existing launcher owns all
; later physical launch policy, real VM lifetime, START and binding validation.
app_installed_declare:
    lea rdi,[rel air_verb]
    lea rsi,[rel cmd_verb_apprun]
    mov rdx,CMD_AUTH_CAP_EXTENSION
    mov ecx,ARGT_U64
    xor r8d,r8d
    mov r9d,1
    jmp command_register_verb
cmd_verb_apprun:
    call cmd_handler_prologue
    push rbx
    push r12
    mov rbx,rdi
    mov r12,rsi
    mov qword [r12+RSP_CODE],CMDE_AUTHDENY
    mov qword [r12+RSP_VAL],0
    cmp byte [rel cmd_in_dispatch],1
    jne .out
    cmp qword [rbx+REQ_SOURCE],CMD_SOURCE_CONSOLE
    jne .out
    cmp qword [rbx+REQ_PRINCIPAL],PRIN_OWNER
    jne .out
    call smp_current_logical
    test eax,eax
    jnz .out
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .out
    test rdx,rdx
    jz .out
    cmp rdx,-1
    je .out
    cmp byte [rel air_pending],0
    jne .out
    mov rax,[rbx+REQ_ARG]
    test rax,rax
    jz .out
    cmp rax,-1
    je .out
    mov [rel air_id],rax
    mov [rel air_epoch],rdx
    cmp qword [rel tsc_khz],0
    je .out
    call time_monotonic_now_us
    test rax,rax
    jz .out
    add rax,30000000
    jc .out
    mov [rel air_deadline],rax
    mov byte [rel air_pending],1
    mov qword [r12+RSP_CODE],CMDE_OK
    mov qword [r12+RSP_VAL],1
.out:
    pop r12
    pop rbx
    ret
app_installed_tick:
    cmp byte [rel air_pending],1
    jne .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp dword [rel cmd_dispatch_depth],0
    jne .out
    call smp_current_logical
    test eax,eax
    jnz .out
    mov byte [rel air_pending],0
    push rbx
    push r12
    push r13
    call air_owner
    test eax,eax
    jz .done
    call app_launch_flow_available
    cmp eax,1
    jne .done
    cmp qword [rel air_image],0
    jne .allocated
    mov edi,ASL_MAX
    call kmalloc
    test rax,rax
    jz .done
    mov [rel air_image],rax
.allocated:
    mov rdi,[rel air_image]
    mov esi,ASL_MAX
    lea rdx,[rel air_token]
    lea rcx,[rel air_length]
    call app_store_snapshot
    cmp eax,1
    jne .done
    mov rbx,[rel air_image]
    lea r12,[rbx+ASL_HEADER]
    mov r13d,ASL_SLOTS
    ; Any interrupted removal denies the catalog, just like its maintained list.
.denials:
    cmp dword [r12+ASL_STATE],ASL_REMOVING
    je .done
    add r12,ASL_SLOT_BYTES
    dec r13d
    jnz .denials
    lea r12,[rbx+ASL_HEADER]
    mov r13d,ASL_SLOTS
.find:
    cmp dword [r12+ASL_STATE],ASL_LIVE
    jne .next
    mov rax,[rel air_id]
    cmp [r12+ASL_ID],rax
    je .found
.next:
    add r12,ASL_SLOT_BYTES
    dec r13d
    jnz .find
    jmp .done
.found:
    cmp dword [r12+ASL_PROFILE],2
    jne .done
    mov rsi,[r12+ASL_LENGTH]
    cmp rsi,65536
    ja .done
    cmp rsi,769
    jb .done
    mov rdi,[r12+ASL_OFFSET]
    cmp rdi,ASL_PAYLOAD
    jb .done
    mov rax,rdi
    add rax,rsi
    jc .done
    cmp rax,[rel air_length]
    ja .done
    add rdi,rbx
    mov [rel air_bytes],rdi
    mov [rel air_bytes_n],rsi
    ; The complete exact-byte digest is independently checked again here.
    lea rdi,[rel air_digest]
    mov rsi,[rel air_bytes]
    mov rdx,[rel air_bytes_n]
    call sha256_hash
    lea rdi,[rel air_digest]
    lea rsi,[r12+ASL_DIGEST]
    mov ecx,4
    cld
    repe cmpsq
    jne .done
    mov rdi,[rel air_bytes]
    mov rsi,[rel air_bytes_n]
    call app_package_stage
    test rax,rax
    jz .done
    mov [rel air_package],rax
    mov rdi,rax
    call app_analysis_build
    cmp eax,1
    jne .done
    mov rdi,[rel air_package]
    lea rsi,[rel air_analysis]
    mov edx,192
    call app_analysis_descriptor
    cmp eax,1
    jne .done
    call air_owner
    test eax,eax
    jz .done
    mov rdi,[rel air_package]
    mov esi,2
    mov rdx,[rel air_epoch]
    lea rcx,[rel air_analysis]
    call app_install_grants_restore  ; same digest/profile/requests/analyzer versions
    ; No remembered consent means the normal launch panel still asks the owner.
    call app_launcher_clear
    cmp eax,1
    jne .done
    ; Only canonical unsigned sharing selects native installed-owner staging.
    ; The package was fully parsed above; no failed signed result falls back.
    mov rdi,[rel air_bytes]
    cmp dword [rdi+40],1
    jne .signed_stage
    mov rdi,[rel air_id]
    call app_script_stage_installed
    jmp .staged
.signed_stage:
    mov rsi,[rel air_bytes_n]
    call app_script_stage            ; original strict signature/current APPKEY
.staged:
    test rax,rax
    jz .done
    mov r12,rax
    ; The fixed stage owns a second fresh authenticated lookup. It must still
    ; be the exact bytes already analyzed and used for remembered permissions.
    mov rdi,r12
    lea rsi,[rel air_script]
    mov edx,384
    call app_script_descriptor
    cmp eax,1
    jne .retire
    mov rax,[rel air_bytes_n]
    cmp [rel air_script+16],rax
    jne .retire
    lea rdi,[rel air_digest]
    lea rsi,[rel air_script+32]
    mov ecx,4
    cld
    repe cmpsq
    jne .retire
    call air_owner
    test eax,eax
    jz .retire
    mov rdi,r12
    call app_launcher_publish
    cmp eax,1
    je .done
.retire:
    call app_script_retire
.done:
    mov rdi,[rel air_image]
    test rdi,rdi
    jz .pop
    xor eax,eax
    mov ecx,ASL_MAX/8
    cld
    rep stosq
.pop:
    pop r13
    pop r12
    pop rbx
.out:
    ret
air_owner:
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    test rdx,rdx
    jz .bad
    cmp rdx,-1
    je .bad
    cmp rdx,[rel air_epoch]
    jne .bad
    cmp qword [rel tsc_khz],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel air_deadline]
    jae .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret
air_verb: db 'APPRUN',0
%macro WDATA_BSS_app_installed 0
alignb 8
air_id: resq 1
air_epoch: resq 1
air_deadline: resq 1
air_image: resq 1
air_length: resq 1
air_bytes: resq 1
air_bytes_n: resq 1
air_package: resq 1
air_pending: resb 1
alignb 8
air_token: resb 112
air_digest: resb 32
air_analysis: resb 192
air_script: resb 384
%endmacro
WDATA_BSS_DEFER WDATA_BSS_app_installed
