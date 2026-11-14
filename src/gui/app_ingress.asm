;; MODULE gui/app_ingress
;; LAYER 6
;; PURPOSE Bounded native owner console ingress for signed script bundles.
;; EXPORTS app_ingress_declare, app_ingress_tick, cmd_verb_appscript
;; IMPORTS gui/app_launch_flow, gui/app_launcher, svc/app_script, svc/command, svc/command_auth, sec/session, fs/vfs, core/heap, core/time, core/smp
;; OWNER saga:app_ingress
;; CONTEXT: bsp_only
; APPSCRIPT /selected/volume/path | STATUS. Only the original registry handler
; queues a native copy. No guest/remote setter, execution, policy or trust grant.
AI_MAX equ 65536
AI_PATH_MAX equ 255
AI_BOUND_US equ 30000000
AI_IDLE equ 0
AI_QUEUED equ 1
AI_PUBLISHED equ 2
AI_REFUSED equ 3

app_ingress_declare:
    lea rdi,[rel ai_verb]
    lea rsi,[rel cmd_verb_appscript]
    mov rdx,CMD_AUTH_CAP_EXTENSION
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    mov r9d,1
    jmp command_register_verb

; RDI original typed request, RSI original response. Queued != published/run.
cmd_verb_appscript:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    mov qword [r13+RSP_CODE],CMDE_AUTHDENY
    mov qword [r13+RSP_VAL],0
    cmp byte [rel cmd_in_dispatch],1
    jne .out
    cmp qword [r12+REQ_SOURCE],CMD_SOURCE_CONSOLE
    jne .out
    cmp qword [r12+REQ_PRINCIPAL],PRIN_OWNER
    jne .out
    call smp_current_logical
    test eax,eax
    jnz .out
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .out
    mov rbx,[r12+REQ_ARG]
    test rbx,rbx
    jz .badarg
    cmp byte [rbx],'/'
    je .path
    lea rsi,[rel ai_status_word]
    xor ecx,ecx
.status_word:
    mov al,[rsi+rcx]
    cmp al,[rbx+rcx]
    jne .badarg
    inc ecx
    test al,al
    jnz .status_word                   ; stops at first mismatch/NUL, at most7
    mov eax,[rel ai_status]
    mov [r13+RSP_VAL],rax
    mov qword [r13+RSP_CODE],CMDE_OK
    jmp .out
.path:
    cmp byte [rbx],'/'
    jne .badarg
    cmp byte [rbx+1],0
    je .badarg
    xor ecx,ecx
.length:
    movzx eax,byte [rbx+rcx]
    test al,al
    jz .bounded
    cmp ecx,AI_PATH_MAX
    jae .badarg
    cmp al,' '
    jb .badarg
    cmp al,'~'
    ja .badarg
    inc ecx
    jmp .length
.bounded:
    cmp byte [rel ai_pending],0
    jne .badarg
    mov [rel ai_length],ecx
    call app_launch_flow_available
    cmp eax,1
    jne .badarg
    cmp dword [rel vfs_disk_handle],-1
    je .badarg
    cmp qword [rel tsc_khz],0
    je .badarg
    call time_monotonic_now_us
    test rax,rax
    jz .badarg
    add rax,AI_BOUND_US
    jc .badarg
    mov [rel ai_deadline],rax
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .out
    mov [rel ai_epoch],rdx
    mov rax,[rel session_key_handle]
    mov [rel ai_key],rax
    mov eax,[rel vfs_disk_handle]
    mov [rel ai_mount],eax
    mov ecx,[rel ai_length]
    inc ecx
    lea rdi,[rel ai_path]
    mov rsi,rbx
    cld
    rep movsb                         ; never retain the request's pointer
    mov dword [rel ai_status],AI_QUEUED
    mov byte [rel ai_pending],1
    mov qword [r13+RSP_CODE],CMDE_OK
    mov qword [r13+RSP_VAL],AI_QUEUED
    jmp .out
.badarg:
    mov qword [r13+RSP_CODE],CMDE_BADARG
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Read-only exact admission lifetime; no ambient OWNER projection.
ai_current:
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    cmp rdx,[rel ai_epoch]
    jne .bad
    mov rax,[rel session_key_handle]
    cmp rax,[rel ai_key]
    jne .bad
    mov eax,[rel vfs_disk_handle]
    cmp eax,[rel ai_mount]
    jne .bad
    cmp qword [rel tsc_khz],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel ai_deadline]
    jae .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; One bounded local read/verify/publication at idle. This does not prepare a VM.
app_ingress_tick:
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp byte [rel ai_pending],1
    jne .out
    call smp_current_logical
    test eax,eax
    jnz .out
    mov byte [rel ai_pending],0         ; consume before I/O or callbacks
    mov dword [rel ai_status],AI_REFUSED
    call ai_current
    cmp eax,1
    jne .done
    call app_launch_flow_available
    cmp eax,1
    jne .done
    ; Original native launcher refuses clear while its form storage is live.
    call app_launcher_clear
    cmp eax,1
    jne .done
    cmp qword [rel ai_bytes],0
    jne .allocated
    mov edi,AI_MAX
    call kmalloc
    test rax,rax
    jz .done
    mov [rel ai_bytes],rax
.allocated:
    mov edi,[rel ai_mount]
    lea rsi,[rel ai_path]
    mov edx,[rel ai_length]
    lea rcx,[rel ai_stat]
    call vfs_stat_path
    test rax,rax
    jnz .done
    mov rax,[rel ai_stat+fs_stat.size]
    cmp rax,656                        ; real v2 container's minimum shape
    jb .done
    cmp rax,AI_MAX
    ja .done
    mov [rel ai_size],rax
    mov edi,[rel ai_mount]
    lea rsi,[rel ai_path]
    mov edx,[rel ai_length]
    xor ecx,ecx
    mov r8,[rel ai_bytes]
    mov r9,rax
    call vfs_read_at_path
    cmp rax,[rel ai_size]
    jne .done                          ; short/failed read never reaches verifier
    call ai_current
    cmp eax,1
    jne .done
    mov rdi,[rel ai_bytes]
    mov rsi,[rel ai_size]
    call app_script_stage              ; actual immutable private copy + RSA/APPKEY
    test rax,rax
    jz .done
    mov [rel ai_handle],rax
    call ai_current
    cmp eax,1
    jne .retire
    call app_launch_flow_available
    cmp eax,1
    jne .retire
    mov rdi,[rel ai_handle]
    call app_launcher_publish          ; real form lint + exact descriptor checks
    cmp eax,1
    jne .retire
    mov dword [rel ai_status],AI_PUBLISHED
    jmp .done
.retire:
    call app_script_retire             ; only this newly staged native snapshot
.done:
    lea rdi,[rel ai_path]
    xor eax,eax
    mov ecx,256/8
    cld
    rep stosq
    mov rdi,[rel ai_bytes]
    test rdi,rdi
    jz .out
    mov ecx,AI_MAX/8
    rep stosq                         ; reused input storage never retains payload
.out:
    ret

; Keep constants in the native image's single section; writable state is
; deferred below to the original page-isolated WDATA regions.
ai_verb: db 'APPSCRIPT',0
ai_status_word: db 'STATUS',0
%include "core/abi/wdata.inc"
%macro WDATA_app_ingress 0
align 8
ai_bytes: dq 0
ai_size: dq 0
ai_handle: dq 0
ai_epoch: dq 0
ai_key: dq 0
ai_deadline: dq 0
ai_status: dd AI_IDLE
ai_length: dd 0
ai_mount: dd -1
ai_pending: db 0
%endmacro
WDATA_DEFER WDATA_app_ingress
%macro WDATA_app_ingress_bss 0
align 8
ai_path: resb 256
ai_stat: resb fs_stat_size
%endmacro
WDATA_BSS_DEFER WDATA_app_ingress_bss
