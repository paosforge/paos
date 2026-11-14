;; MODULE gui/app_store_observe
;; LAYER 6
;; PURPOSE Bounded owner-only readback of the real installed-store lifecycle.
;; EXPORTS app_store_observe_declare, app_store_observe_tick, udp_app_store_observe_take
;; IMPORTS svc/command, svc/command_udp, svc/app_store, sec/session, sec/app_install_grants, svc/app_script, gui/app_launcher, gui/app_launch_flow, gui/app_widget, gui/form_events, sec/app_binding, hv/app_network, hv/app_runtime_observer, core/smp, core/heap, core/lib/sha256
;; OWNER saga:app_store
;; CONTEXT: bsp_only
%include "fs/app_store_layout.inc"
; No writer, approval, staging, removal or VM callback. Command dispatch queues
; one digest; native idle reads the maintained APIs at depth zero. The result
; (199 words, runtime profile221) freezes one epoch and nonreused sequence.
%ifdef APP_RUNTIME_OBSERVER_ABI_V1
ASO_WORDS equ 221                    ; additive original guest BEGIN receipt
%else
ASO_WORDS equ 199
%endif
ASO_BYTES equ ASO_WORDS*8

app_store_observe_declare:
    lea rdi,[rel aso_verb]
    lea rsi,[rel cmd_verb_appstoreobs]
    mov rdx,CMD_AUTH_CAP_EXTENSION
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    mov r9d,1
    jmp command_register_verb

; C<64 lower-case hex digest> -> capture sequence, R<16 hex token> -> word.
; token=(sequence<<8)|word0..198. Failed/pending/other-epoch reads never expose
; previous data. The remote sender still passes ordinary signed OWNER dispatch.
cmd_verb_appstoreobs:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    cld
    mov r12,rdi
    mov r13,rsi
    mov qword [r13+RSP_CODE],CMDE_AUTHDENY
    mov qword [r13+RSP_VAL],0
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],1
    jne .out
    cmp qword [r12+REQ_PRINCIPAL],PRIN_OWNER
    jne .out
    ; Read-only remote OWNER observations use the ordinary remote/session gate;
    ; local_authority deliberately refuses every remote frame and is only used
    ; when the queued capture runs at native idle below.
    call session_shell_require_unlocked
    test eax,eax
    jnz .out
    cmp qword [rel session_bound_pid],PRIN_OWNER
    jne .out
    mov rdx,[rel session_authority_epoch]
    test rdx,rdx
    jz .out
    cmp rdx,-1
    je .out
    cmp rdx,[rel session_authority]
    jne .out
    mov rbx,[r12+REQ_ARG]
    test rbx,rbx
    jz .bad
    cmp byte [rbx],'C'
    jne .read
    cmp byte [rel aso_pending],0
    jne .bad
    mov rax,[rel aso_sequence]
    shr rax,55
    jnz .bad
    ; Validate the whole request before replacing any frozen observation.
    lea rsi,[rbx+1]
    mov ecx,64
.validate:
    lodsb
    call aso_nibble
    jc .bad
    loop .validate
    cmp byte [rsi],0
    jne .bad
    mov [rel aso_epoch],rdx
    lea rsi,[rbx+1]
    lea rdi,[rel aso_target]
    mov ecx,32
.digest:
    lodsb
    call aso_nibble
    shl al,4
    mov ah,al
    lodsb
    call aso_nibble
    or al,ah
    stosb
    loop .digest
    inc qword [rel aso_sequence]
    mov byte [rel aso_ready],0
    mov byte [rel aso_pending],1
    mov rax,[rel aso_sequence]
    jmp .ok
.read:
%ifdef APP_RUNTIME_OBSERVER_ABI_V1
    cmp byte [rbx],'L'
    je .long_read
%endif
    cmp byte [rbx],'R'
    jne .bad
    cmp rdx,[rel aso_epoch]
    jne .out
    cmp byte [rel aso_ready],1
    jne .bad
    lea rsi,[rbx+1]
    xor r8d,r8d
    mov ecx,16
.token:
    lodsb
    call aso_nibble
    jc .bad
    shl r8,4
    movzx eax,al
    or r8,rax
    loop .token
    cmp byte [rsi],0
    jne .bad
    movzx eax,r8b
    cmp eax,ASO_WORDS
    jae .bad
    shr r8,8
    cmp r8,[rel aso_sequence]
    jne .bad
    lea rdx,[rel aso_result]
    mov rax,[rdx+rax*8]
%ifdef APP_RUNTIME_OBSERVER_ABI_V1
    jmp .ok
.long_read:
    ; Same original OWNER/epoch/pending guards as R; independent low10 token.
    cmp rdx,[rel aso_epoch]
    jne .out
    cmp byte [rel aso_ready],1
    jne .bad
    lea rsi,[rbx+1]
    xor r8d,r8d
    mov ecx,16
.long_token:
    lodsb
    call aso_nibble
    jc .bad
    shl r8,4
    movzx eax,al
    or r8,rax
    loop .long_token
    cmp byte [rsi],0
    jne .bad
    mov eax,r8d
    and eax,1023
    cmp eax,848
    jae .bad
    shr r8,10
    ; A sixteen-hex token cannot encode sequence >=2**54. Full comparison
    ; refuses those captures without changing the original C/R55 contract.
    cmp r8,[rel aso_sequence]
    jne .bad
    lea rdx,[rel aso_long_result]
    mov rax,[rdx+rax*8]
    jmp .ok
%endif
.ok:
    mov [r13+RSP_VAL],rax
    mov qword [r13+RSP_CODE],CMDE_OK
    jmp .out
.bad:
    mov qword [r13+RSP_CODE],CMDE_BADARG
.out:
    pop r13
    pop r12
    pop rbx
    ret

; AL lower-case hex -> nibble, CF bad. Preserves all other registers incl AH.
aso_nibble:
    cmp al,'0'
    jb .bad
    cmp al,'9'
    jbe .number
    cmp al,'a'
    jb .bad
    cmp al,'f'
    ja .bad
    sub al,'a'-10
    clc
    ret
.number:
    sub al,'0'
    clc
    ret
.bad:
    stc
    ret

app_store_observe_tick:
    cmp byte [rel aso_pending],1
    jne .out
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp dword [rel cmd_dispatch_depth],0
    jne .out
    mov byte [rel aso_pending],0
    mov byte [rel aso_ready],0
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .out
    cmp rdx,[rel aso_epoch]
    jne .out
    push rbx
    push r12
    push r13
    lea rdi,[rel aso_result]
    xor eax,eax
    mov ecx,ASO_WORDS
    cld
    rep stosq
    mov qword [rel aso_result],1
    mov rax,[rel aso_sequence]
    mov [rel aso_result+8],rax
    mov rax,[rel aso_epoch]
    mov [rel aso_result+16],rax
    lea rdi,[rel aso_result+11*8]
    lea rsi,[rel aso_target]
    mov ecx,4
    rep movsq
    cmp qword [rel aso_image],0
    jne .image
    mov edi,ASL_MAX
    call kmalloc
    test rax,rax
    jz .finish
    mov [rel aso_image],rax
.image:
    mov rdi,[rel aso_image]
    mov esi,ASL_MAX
    lea rdx,[rel aso_token]
    lea rcx,[rel aso_length]
    call app_store_snapshot
    mov [rel aso_result+3*8],rax
    cmp eax,1
    jne .leaves
    mov rbx,[rel aso_image]
    mov rax,[rbx+ASL_GENERATION]
    mov [rel aso_result+4*8],rax
    mov rax,[rbx+ASL_COUNT]
    mov [rel aso_result+5*8],rax
    mov rax,[rbx+ASL_NEXT_ID]
    mov [rel aso_result+6*8],rax
    mov rax,[rbx+ASL_TOTAL]
    mov [rel aso_result+7*8],rax
    lea rdi,[rel aso_result+15*8]
    mov rsi,rbx
    mov rdx,[rel aso_length]
    call sha256_hash
    lea rdi,[rel aso_result+19*8]
    lea rsi,[rel aso_token+56]
    mov edx,56
    call sha256_hash
    lea r12,[rbx+ASL_HEADER]
    mov r13d,ASL_SLOTS
.scan:
    cmp dword [r12+ASL_STATE],0
    je .next
    lea rdi,[r12+ASL_DIGEST]
    lea rsi,[rel aso_target]
    mov ecx,4
    repe cmpsq
    jne .next
    mov rax,[r12+ASL_ID]
    mov [rel aso_result+8*8],rax
    mov eax,[r12+ASL_PROFILE]
    mov [rel aso_result+9*8],rax
    mov eax,[r12+ASL_STATE]
    mov [rel aso_result+10*8],rax
    mov rax,[r12+ASL_LENGTH]
    mov [rel aso_result+49*8],rax
.next:
    add r12,ASL_SLOT_BYTES
    dec r13d
    jnz .scan
    xor edi,edi
    lea rsi,[rel aso_row]
    mov edx,256
    xor ecx,ecx
    call app_store_list
    mov [rel aso_result+23*8],rax
    mov [rel aso_result+24*8],rdx
    cmp eax,1
    jne .leaves
    lea rdi,[rel aso_result+25*8]
    lea rsi,[rel aso_row]
    mov edx,256
    call sha256_hash
.leaves:
    lea rdi,[rel aso_target]
    lea rsi,[rel aso_result+29*8]
    call app_install_grants_observe
    lea rdi,[rel aso_target]
    lea rsi,[rel aso_result+34*8]
    call app_script_observe
    lea rdi,[rel aso_target]
    lea rsi,[rel aso_result+46*8]
    call app_launcher_observe
    lea rdi,[rel aso_result+50*8]
    mov esi,80
    call app_launch_flow_observe
    ; Additive v1 trailing observations. The original first60 words keep ABI.
    lea rdi,[rel aso_result+60*8]
    call app_binding_observe
    lea rdi,[rel aso_result+69*8]
    lea rsi,[rel aso_target]
    mov ecx,4
    repe cmpsq
    je .useful
    lea rdi,[rel aso_result+60*8]
    xor eax,eax
    mov ecx,15
    rep stosq
.useful:
    lea rdi,[rel aso_target]
    lea rsi,[rel aso_result+75*8]
    call app_widget_observe
    lea rdi,[rel aso_target]
    lea rsi,[rel aso_result+97*8]
    call form_events_observe
%ifdef APP_RUNTIME_OBSERVER_ABI_V1
    lea rdi,[rel aso_target]
    lea rsi,[rel aso_result+199*8]
    call form_events_observe_begin
%endif
    ; Original first119 remain byte-for-byte ABI; two separate policy slots.
    lea rdi,[rel aso_target]
    lea rsi,[rel aso_result+119*8]
    call app_binding_policy_observe
    ; Additive public network witness. Never expose the last admitted app's
    ; record for another requested digest. An absent record means unavailable,
    ; not evidence that a refused operation caused no DNS or TCP effects.
    lea rdi,[rel aso_result+175*8]
    mov esi,192
    call app_network_observe
    cmp eax,1
    jne .network_absent
    lea rdi,[rel aso_result+175*8+128]
    lea rsi,[rel aso_target]
    mov ecx,4
    cld
    repe cmpsq
    je .finish
.network_absent:
    lea rdi,[rel aso_result+175*8]
    xor eax,eax
    mov ecx,24
    rep stosq
.finish:
%ifdef APP_RUNTIME_OBSERVER_ABI_V1
    call aso_long_capture
%endif
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .release
    cmp rdx,[rel aso_epoch]
    jne .release
    mov byte [rel aso_ready],1
.release:
    mov rdi,[rel aso_image]
    test rdi,rdi
    jz .pop
    xor eax,eax
    mov ecx,ASL_MAX/8
    rep stosq
.pop:
    pop r13
    pop r12
    pop rbx
.out:
    ret

%ifdef APP_RUNTIME_OBSERVER_ABI_V1
; Profile-only fixed L848, one original idle capture, no read-side callbacks.
; Header16 + original native816 + accepted launcher8 + matching flow8.
aso_long_capture:
    sub rsp,8
    lea rdi,[rel aso_long_result]
    xor eax,eax
    mov ecx,848
    cld
    rep stosq
    mov qword [rel aso_long_result],1
    mov rax,[rel aso_sequence]
    mov [rel aso_long_result+8],rax
    mov rax,[rel aso_epoch]
    mov [rel aso_long_result+16],rax
    mov qword [rel aso_long_result+24],848
    lea rdi,[rel aso_long_result+64]
    lea rsi,[rel aso_target]
    mov ecx,4
    rep movsq
    lea rdi,[rel aso_long_result+16*8]
    mov esi,6528
    call app_runtime_observe
    cmp eax,1
    jne .native_absent
    cmp qword [rel aso_long_result+16*8],1
    jne .native_absent
    cmp qword [rel aso_long_result+17*8],6528
    jne .native_absent
    mov qword [rel aso_long_result+4*8],1
    cmp qword [rel aso_long_result+19*8],1
    jne .clicks                 ; native empty/U header remains explicit
    ; Original snapshot digest is native64+64, not a guest body assertion.
    lea rdi,[rel aso_long_result+32*8]
    lea rsi,[rel aso_target]
    mov ecx,4
    cld
    repe cmpsq
    jne .native_absent
    jmp .clicks
.native_absent:
    mov qword [rel aso_long_result+4*8],0
    lea rdi,[rel aso_long_result+16*8]
    xor eax,eax
    mov ecx,816
    cld
    rep stosq
.clicks:
    ; Existing target-specific launcher record is from this same original C.
    cmp qword [rel aso_result+46*8],1
    jne .done
    lea rdi,[rel aso_long_result+832*8]
    mov esi,64
    call app_launcher_click_observe
    cmp eax,1
    jne .launcher_absent
    cmp qword [rel aso_long_result+832*8],1
    jne .launcher_absent
    cmp qword [rel aso_long_result+833*8],0
    je .launcher_absent
    mov qword [rel aso_long_result+5*8],1
    lea rdi,[rel aso_long_result+840*8]
    mov esi,64
    call app_launch_flow_click_observe
    cmp eax,1
    jne .flow_absent
    cmp qword [rel aso_long_result+840*8],1
    jne .flow_absent
    mov rax,[rel aso_long_result+841*8]
    cmp rax,[rel aso_long_result+833*8]
    jne .flow_absent
    mov rax,[rel aso_long_result+842*8]
    test rax,rax
    jz .flow_absent
    cmp rax,[rel aso_long_result+834*8]
    jne .flow_absent
    mov qword [rel aso_long_result+6*8],1
    jmp .done
.launcher_absent:
    lea rdi,[rel aso_long_result+832*8]
    xor eax,eax
    mov ecx,16
    cld
    rep stosq
    jmp .done
.flow_absent:
    lea rdi,[rel aso_long_result+840*8]
    xor eax,eax
    mov ecx,8
    cld
    rep stosq
.done:
    add rsp,8
    ret
%endif

; Called only in the normal post-dispatch reply projection. A typed refused
; response never prints ASOBS. Neither the command nor this printer is public.
udp_app_store_observe_take:
    push rbx
    lea rdi,[rel udp_line]
    lea rsi,[rel aso_verb]
    call strcmp
    test eax,eax
    jnz .no
    cmp qword [rel udp_rsp+RSP_CODE],CMDE_OK
    jne .no
    lea rdi,[rel aso_value]
    call udp_put_str
    mov rdi,[rel udp_rsp+RSP_VAL]
    call udp_put_dec
    call udp_put_uptime
    mov eax,1
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

aso_verb: db 'APPSTOREOBS',0
aso_value: db ' ASOBS=',0
%macro WDATA_BSS_app_store_observe 0
alignb 8
aso_sequence: resq 1
aso_epoch: resq 1
aso_image: resq 1
aso_length: resq 1
aso_pending: resb 1
aso_ready: resb 1
alignb 8
aso_target: resb 32
aso_result: resb ASO_BYTES
%ifdef APP_RUNTIME_OBSERVER_ABI_V1
aso_long_result: resq 848
%endif
aso_token: resb 112
aso_row: resb 256
%endmacro
WDATA_BSS_DEFER WDATA_BSS_app_store_observe
