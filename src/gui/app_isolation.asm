;; MODULE gui/app_isolation
;; LAYER 6
;; PURPOSE Local deny-only signed APP VM admission and frozen OWNER observation.
;; EXPORTS app_isolation_declare, app_isolation_tick, udp_app_isolation_take
;; IMPORTS hv/app_vm, hv/app_vm_memory, gui/app_launch_flow, svc/app_script, svc/command, svc/command_udp, sec/session, fs/vfs, core/heap, core/time, core/smp, core/lib/str
;; OWNER saga:app_isolation
;; CONTEXT: bsp_only
; APPISO <16 lowercase hex nonce> /selected/signed/script queues ONE local OWNER
; refusal attempt. No remote/injected/guest queue or authority projection. Native
; idle retains exact current session/key/mount and a30s admission lifetime.
; APPISOOBS <same nonce> <word0..31> is OWNER-only, frozen, read-only evidence.
; No trust installation, form, guest entry, device/root changes or disk writes.
%include "hv/app_vm.inc"
AIP_WORDS equ 32
AIP_MAX equ 65536
app_isolation_declare:
    lea rdi,[rel aip_verb]
    lea rsi,[rel cmd_verb_appiso]
    mov rdx,CMD_AUTH_CAP_EXTENSION
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    mov r9d,1
    call command_register_verb
    lea rdi,[rel aip_obsverb]
    lea rsi,[rel cmd_verb_appisoobs]
    mov rdx,CMD_AUTH_CAP_EXTENSION
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    mov r9d,1
    jmp command_register_verb

; RSI nonce followed by space; no unbounded strlen or trailing acceptance.
aip_nonce_valid:
    xor ecx,ecx
.next:
    mov al,[rsi+rcx]
    cmp al,'0'
    jb .bad
    cmp al,'9'
    jbe .ok
    cmp al,'a'
    jb .bad
    cmp al,'f'
    ja .bad
.ok:
    inc ecx
    cmp ecx,16
    jb .next
    cmp byte [rsi+16],' '
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

cmd_verb_appiso:
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
    cmp byte [rel aip_pending],0
    jne .out
    cmp qword [rel aip_sequence],0
    jne .out
    mov rbx,[r12+REQ_ARG]
    test rbx,rbx
    jz .out
    mov rsi,rbx
    call aip_nonce_valid
    cmp eax,1
    jne .out
    ; A spent attempt stays frozen for the whole boot, even for a new nonce.
    cmp byte [rbx+17],'/'
    jne .out
    xor ecx,ecx
.length:
    mov al,[rbx+rcx+17]
    test al,al
    jz .length_ok
    cmp ecx,255
    jae .out
    cmp al,33
    jb .out
    cmp al,126
    ja .out
    inc ecx
    jmp .length
.length_ok:
    cmp ecx,2
    jb .out
    mov [rel aip_length],ecx
    cmp dword [rel vfs_disk_handle],-1
    je .out
    cmp qword [rel tsc_khz],0
    je .out
    call time_monotonic_now_us
    test rax,rax
    jz .out
    add rax,30000000
    jc .out
    mov [rel aip_deadline],rax
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .out
    test rdx,rdx
    jz .out
    cmp rdx,-1
    je .out
    mov [rel aip_epoch],rdx
    mov rax,[rel session_key_handle]
    mov [rel aip_key],rax
    mov eax,[rel vfs_disk_handle]
    mov [rel aip_mount],eax
    mov rax,[rbx]
    mov [rel aip_nonce],rax
    mov rax,[rbx+8]
    mov [rel aip_nonce+8],rax
    lea rsi,[rbx+17]
    lea rdi,[rel aip_path]
    mov ecx,[rel aip_length]
    inc ecx
    cld
    rep movsb
    mov byte [rel aip_ready],0
    mov byte [rel aip_pending],1
    mov qword [r13+RSP_CODE],CMDE_OK
.out:
    pop r13
    pop r12
    pop rbx
    ret

aip_current:
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    cmp rdx,[rel aip_epoch]
    jne .bad
    mov rax,[rel session_key_handle]
    cmp rax,[rel aip_key]
    jne .bad
    mov eax,[rel vfs_disk_handle]
    cmp eax,[rel aip_mount]
    jne .bad
    cmp qword [rel tsc_khz],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel aip_deadline]
    jae .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Native state only, no caller-authored values. RDI exact64-byte native output.
aip_vm_state:
    lea rsi,[rel avm_state]
    mov rax,[rsi]
    stosq
    mov rax,[rel avm_instance]
    stosq
    mov eax,[rel avm_start]
    stosq
    mov rax,[rel avm_token]
    stosq
    mov rax,[rel avm_base]
    stosq
    mov rax,[rel avm_root]
    stosq
    mov rax,[rel avm_cpu_live]
    stosq
    mov rax,[rel avm_roots_retired]
    stosq
    ret

app_isolation_tick:
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp byte [rel aip_pending],1
    jne .out
    call smp_current_logical
    test eax,eax
    jnz .out
    mov byte [rel aip_pending],0       ; spend before any I/O, never retry
    lea rdi,[rel aip_result]
    xor eax,eax
    mov ecx,AIP_WORDS
    cld
    rep stosq
    inc qword [rel aip_sequence]
    mov qword [rel aip_result],1
    mov rax,[rel aip_sequence]
    mov [rel aip_result+8],rax
    mov rax,[rel aip_epoch]
    mov [rel aip_result+7*8],rax
    call aip_current
    cmp eax,1
    jne .done
    call app_launch_flow_available
    cmp eax,1
    jne .done
    cmp qword [rel avm_state],AVM_EMPTY
    jne .done
    ; Never replace a foreign/current staged script. Existing retired-slot
    ; observation checks full private storage, not just an invented empty flag.
    lea rdi,[rel aip_result+8*8]       ; zero digest until verified descriptor
    lea rsi,[rel aip_cache]
    call app_script_observe
    cmp qword [rel aip_cache+88],1
    jne .done
    cmp qword [rel aip_bytes],0
    jne .allocated
    mov edi,AIP_MAX
    call kmalloc
    test rax,rax
    jz .done
    mov [rel aip_bytes],rax
.allocated:
    mov edi,[rel aip_mount]
    lea rsi,[rel aip_path]
    mov edx,[rel aip_length]
    lea rcx,[rel aip_stat]
    call vfs_stat_path
    test rax,rax
    jnz .done
    mov rax,[rel aip_stat+fs_stat.size]
    cmp rax,656
    jb .done
    cmp rax,AIP_MAX
    ja .done
    mov [rel aip_result+5*8],rax
    mov edi,[rel aip_mount]
    lea rsi,[rel aip_path]
    mov edx,[rel aip_length]
    xor ecx,ecx
    mov r8,[rel aip_bytes]
    mov r9,rax
    call vfs_read_at_path
    cmp rax,[rel aip_result+5*8]
    jne .done
    call aip_current
    cmp eax,1
    jne .done
    mov rdi,[rel aip_bytes]
    mov rsi,[rel aip_result+5*8]
    call app_script_stage            ; real strict RSA/trust + private snapshot
    test rax,rax
    jz .done
    mov [rel aip_result+6*8],rax
    mov rdi,rax
    lea rsi,[rel aip_descriptor]
    mov edx,384
    call app_script_descriptor
    cmp eax,1
    jne .retire
    lea rsi,[rel aip_descriptor+32]
    lea rdi,[rel aip_result+8*8]
    mov ecx,6                       ; exact whole SHA32 and signer key16
    rep movsq
    call aip_current
    cmp eax,1
    jne .retire
    mov qword [rel aip_result+2*8],1
    lea rdi,[rel aip_result+14*8]
    call aip_vm_state
    mov rdi,[rel aip_result+6*8]
    xor esi,esi
    call app_vm_prepare_without_isolation ; same actual VM admission, deny-only
    mov [rel aip_result+3*8],rax
    mov [rel aip_result+4*8],rdx
    lea rdi,[rel aip_result+22*8]
    call aip_vm_state
.retire:
    call app_script_retire           ; only the exact newly staged own snapshot
    lea rdi,[rel aip_result+8*8]
    lea rsi,[rel aip_cache]
    call app_script_observe
    mov rax,[rel aip_cache+88]
    mov [rel aip_result+30*8],rax
.done:
    call time_monotonic_now_us
    mov [rel aip_result+31*8],rax
    mov byte [rel aip_ready],1
    lea rdi,[rel aip_path]
    xor eax,eax
    mov ecx,256/8
    rep stosq
    mov rdi,[rel aip_bytes]
    test rdi,rdi
    jz .out
    mov ecx,AIP_MAX/8
    rep stosq
.out:
    ret

cmd_verb_appisoobs:
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
    cmp qword [r12+REQ_PRINCIPAL],PRIN_OWNER
    jne .out
    call smp_current_logical
    test eax,eax
    jnz .out
    call session_shell_require_unlocked
    test eax,eax
    jnz .out
    cmp qword [rel session_bound_pid],PRIN_OWNER
    jne .out
    cmp byte [rel aip_ready],1
    jne .out
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel aip_epoch]
    jne .out
    cmp rax,[rel session_authority]
    jne .out
    mov rax,[rel session_key_handle]
    cmp rax,[rel aip_key]
    jne .out
    mov rbx,[r12+REQ_ARG]
    test rbx,rbx
    jz .out
    mov rsi,rbx
    call aip_nonce_valid
    cmp eax,1
    jne .out
    mov rax,[rbx]
    cmp rax,[rel aip_nonce]
    jne .out
    mov rax,[rbx+8]
    cmp rax,[rel aip_nonce+8]
    jne .out
    movzx eax,byte [rbx+17]
    sub eax,'0'
    cmp eax,9
    ja .out
    cmp byte [rbx+18],0
    je .index
    imul eax,10
    movzx edx,byte [rbx+18]
    sub edx,'0'
    cmp edx,9
    ja .out
    add eax,edx
    cmp byte [rbx+19],0
    jne .out
.index:
    cmp eax,AIP_WORDS
    jae .out
    lea rdx,[rel aip_result]
    mov rax,[rdx+rax*8]
    mov [r13+RSP_VAL],rax
    mov qword [r13+RSP_CODE],CMDE_OK
.out:
    pop r13
    pop r12
    pop rbx
    ret

udp_app_isolation_take:
    lea rdi,[rel udp_line]
    lea rsi,[rel aip_obsverb]
    call strcmp
    test eax,eax
    jnz .no
    cmp qword [rel udp_rsp+RSP_CODE],CMDE_OK
    jne .no
    lea rdi,[rel aip_value]
    call udp_put_str
    mov rdi,[rel udp_rsp+RSP_VAL]
    call udp_put_dec
    call udp_put_uptime
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

aip_verb: db 'APPISO',0
aip_obsverb: db 'APPISOOBS',0
aip_value: db ' AISO=',0
%include "core/abi/wdata.inc"
%macro WDATA_app_isolation 0
align 8
aip_bytes: dq 0
aip_sequence: dq 0
aip_epoch: dq 0
aip_key: dq 0
aip_deadline: dq 0
aip_length: dd 0
aip_mount: dd -1
aip_pending: db 0
aip_ready: db 0
%endmacro
WDATA_DEFER WDATA_app_isolation
%macro WDATA_BSS_app_isolation 0
alignb 8
aip_nonce: resb 16
aip_path: resb 256
aip_stat: resb fs_stat_size
aip_descriptor: resb 384
aip_cache: resb 96
aip_result: resq AIP_WORDS
%endmacro
WDATA_BSS_DEFER WDATA_BSS_app_isolation
