;; MODULE cognition/hook_edges_cognition
;; LAYER 6
;; EXPORTS hook_cognition_edges_declare, hook_modelkat_plan, hook_modelkat_post, hook_ai_intent_plan, hook_ai_intent_post
;; IMPORTS cognition/gpt2_engine, cognition/ai_intent_controller, svc/command, svc/command_hook
;; CAPS
;; OWNER saga:cognition
; Read-only latched GPT2 diagnostics and masked native AI intent status.
; Registry dispatch retains the caller's native authority; INTENT additionally
; checks the native owner ticket and live compute cap. No model load/inference.
; BSP serialized like the native shared stage. Copy one complete validated reply,
; then wipe all384 producer bytes/cursor/ready/pending, including refusal paths.
HCM_REPLY_MAX equ 384
hook_cognition_edges_declare:
    push rbx
    lea rbx,[rel hook_edge_modelkat]
    lea  rax, [rel str_hcm_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hcm_kind]
    mov  [rbx + HE_KIND], rax
    lea rax,[rel str_hcm_schema]
    mov [rbx+HE_SCHEMA],rax
    lea rax,[rel hook_modelkat_plan]
    mov [rbx+HE_PLAN],rax
    lea rax,[rel hook_modelkat_post]
    mov [rbx+HE_POST],rax
    mov qword [rbx+HE_OBUF],0
    mov qword [rbx+HE_OREADY],0
    mov qword [rbx+HE_WITNESS],0 ; whole validated reply, including route/hash
    mov rdi,rbx
    call command_hook_edge_register
    lea rbx,[rel hook_edge_ai_intent]
    lea  rax, [rel str_hai_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hcm_kind]
    mov  [rbx + HE_KIND], rax
    lea rax,[rel str_hai_schema]
    mov [rbx+HE_SCHEMA],rax
    lea rax,[rel hook_ai_intent_plan]
    mov [rbx+HE_PLAN],rax
    lea rax,[rel hook_ai_intent_post]
    mov [rbx+HE_POST],rax
    mov qword [rbx+HE_OBUF],0
    mov qword [rbx+HE_OREADY],0
    mov qword [rbx+HE_WITNESS],0
    mov rdi,rbx
    call command_hook_edge_register
    pop rbx
    ret

; GET/OBSERVE only; the common dispatcher retains the original caller envelope.
hook_ai_intent_plan:
    call hai_retire
    cmp edi,HOP_GET
    jne .na
    cmp byte [rsi],0
    jne .bad
    cmp byte [rdx],0
    jne .bad
    call command_hook_arg_reset
    lea rdi,[rel str_hai_arg]
    call command_hook_arg_str
    mov byte [rel hai_pending],1
    lea rax,[rel str_hai_verb]
    xor edx,edx
    ret
.na:
    xor eax,eax
    mov edx,HOOK_PLAN_NA
    ret
.bad:
    xor eax,eax
    mov edx,HOOK_PLAN_BADARG
    ret

hook_ai_intent_post:
    push rbx
    push r12
    push r13
    mov rbx,rcx
    cmp qword [rbx+RSP_CODE],CMDE_OK
    jne .refused
    cmp qword [rbx+RSP_ACCEPTED],1
    jne .bad
    cmp byte [rel hai_pending],1
    jne .bad
    cmp byte [rel cog_out_ready],1
    jne .bad
    lea r12,[rel cog_out_buf]
    xor ecx,ecx
.length:
    cmp ecx,128
    jae .bad
    cmp byte [r12+rcx],0
    je .bounded
    inc ecx
    jmp .length
.bounded:
    lea rax,[r12+rcx]
    cmp rax,[rel cog_out_cur]
    jne .bad
    mov rdi,r12
    lea rsi,[rel str_hai_reply]
    call hcm_literal
    test eax,eax
    jz .bad
    call hcm_u64
    test eax,eax
    jz .bad
    cmp rdx,7
    ja .bad
    cmp rdx,[rbx+RSP_VAL]
    jne .bad
    lea rsi,[rel str_hai_reason]
    call hcm_literal
    test eax,eax
    jz .bad
    call hcm_u64
    test eax,eax
    jz .bad
    cmp rdx,5
    ja .bad
    lea rsi,[rel str_hai_have]
    call hcm_literal
    test eax,eax
    jz .bad
    call hcm_u64
    test eax,eax
    jz .bad
    cmp rdx,1
    ja .bad
    lea rsi,[rel str_hai_seq]
    call hcm_literal
    test eax,eax
    jz .bad
    call hcm_u64
    test eax,eax
    jz .bad
    mov eax,0xffffffff
    cmp rdx,rax
    ja .bad
    lea rsi,[rel str_hai_none]
    call hcm_literal
    test eax,eax
    jz .bad
    cmp byte [rdi],0
    jne .bad
    sub rdi,r12
    mov r13,rdi
    call command_hook_out_reset
    mov rsi,r13
    mov rdi,r12
    call command_hook_out_strn
    call hai_retire
    mov eax,1
    jmp .out
.bad:
    mov qword [rbx+RSP_CODE],CMDE_BADARG
.refused:
    call command_hook_out_reset
    lea rdi,[rel str_hai_refused]
    call command_hook_out_str
    mov qword [rbx+RSP_ACCEPTED],0
    mov qword [rbx+RSP_VAL],0
    call hai_retire
    mov eax,1
.out:
    pop r13
    pop r12
    pop rbx
    ret
hai_retire:
    mov byte [rel hai_pending],0
    jmp hcm_retire
hook_modelkat_plan:
    call hcm_retire
    cmp edi,HOP_GET
    jne .na
    cmp byte [rsi],0
    jne .bad
    cmp byte [rdx],0
    jne .bad
    lea rdi,[rel str_hcm_verb]
    call command_lookup
    cmp rax,-1
    je .unregistered
    mov byte [rel hcm_pending],1
.unregistered:
    lea rax,[rel str_hcm_verb]
    xor edx,edx
    ret
.na:
    xor eax,eax
    mov edx,HOOK_PLAN_NA
    ret
.bad:
    xor eax,eax
    mov edx,HOOK_PLAN_BADARG
    ret
hook_modelkat_post:
    push rbx
    push r12
    mov rbx,rcx
    cmp qword [rbx+RSP_CODE],CMDE_OK
    jne .refused
    cmp byte [rel hcm_pending],1
    jne .bad
    cmp byte [rel cog_out_ready],1
    jne .bad
    lea rdi,[rel cog_out_buf]
    xor ecx,ecx
.length:
    cmp ecx,HCM_REPLY_MAX
    jae .bad
    cmp byte [rdi+rcx],0
    je .bounded
    inc ecx
    jmp .length
.bounded:
    lea rax,[rdi+rcx]
    cmp rax,[rel cog_out_cur]
    jne .bad
    mov r12,rdi
    call hcm_record
    test eax,eax
    jz .bad
    cmp rdx,[rbx+RSP_VAL] ; bind native scalar argmax, not merely plausible text
    jne .bad
    sub rdi,r12
    push rdi
    call command_hook_out_reset
    pop rsi
    mov rdi,r12
    call command_hook_out_strn
    call hcm_retire
    mov eax,1
    jmp .out
.bad:
    call command_hook_out_reset
    lea rdi,[rel str_hcm_bad]
    call command_hook_out_str
    mov qword [rbx+RSP_CODE],CMDE_BADARG
    mov qword [rbx+RSP_ACCEPTED],0
    mov qword [rbx+RSP_VAL],0
    lea rax,[rel str_hcm_bad]
    mov [rbx+RSP_HINT],rax
    call hcm_retire
    mov eax,1
    jmp .out
.refused:
    call hcm_retire
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret
hcm_retire:
    push rax
    push rcx
    push rdi
    mov byte [rel hcm_pending],0
    mov byte [rel cog_out_ready],0
    mov qword [rel cog_out_cur],0
    lea rdi,[rel cog_out_buf]
    xor eax,eax
    mov ecx,HCM_REPLY_MAX/8
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    ret

; A prior bounded NUL check makes each byte/string read contained. No producer
; pointers other than the owned fixed stage are followed. EAX=valid,RDX=argmax.
hcm_record:
    push rbx
    push r12
    lea rsi,[rel str_hcm_argmax]
    call hcm_literal
    test eax,eax
    jz .no
    call hcm_u64
    test eax,eax
    jz .no
    mov ebx,0xffffffff
    cmp rdx,rbx
    ja .no
    mov r12,rdx
    lea rsi,[rel str_hcm_ref]
    call hcm_literal
    test eax,eax
    jz .no
    call hcm_u64
    test eax,eax
    jz .no
    cmp rdx,1
    ja .no
    lea rsi,[rel str_hcm_disk]
    call hcm_literal
    test eax,eax
    jz .no
    call hcm_u64
    test eax,eax
    jz .no
    cmp rdx,1
    ja .no
    mov rbx,rdx
    lea rsi,[rel str_hcm_size]
    call hcm_literal
    test eax,eax
    jz .no
    call hcm_u64
    test eax,eax
    jz .no
    lea rsi,[rel str_hcm_sha]
    call hcm_literal
    test eax,eax
    jz .no
    cmp byte [rdi],'n'
    jne .hash
    lea rsi,[rel str_hcm_none]
    jmp .sha
.hash:
    lea rsi,[rel str_cog_sha_value] ; exact native configured digest text
.sha:
    call hcm_literal
    test eax,eax
    jz .no
    test ebx,ebx
    jz .loader
    ; Both retained-file routes report disk=1. Match their exact native text.
    push rdi
    lea rsi,[rel str_hcm_via_boot]
    call hcm_literal
    pop rdi
    test eax,eax
    jz .disk_via
    lea rsi,[rel str_hcm_via_boot]
    jmp .via
.disk_via:
    lea rsi,[rel str_hcm_via_disk]
    jmp .via
.loader:
%if COG_MODEL_ENABLED = 0
    lea rsi,[rel str_hcm_via_disabled]
%else
    lea rsi,[rel str_hcm_via_loader]
%endif
.via:
    call hcm_literal
    test eax,eax
    jz .no
    cmp byte [rdi],0
    jne .no
    mov rdx,r12
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret
hcm_literal:
    mov al,[rsi]
    test al,al
    jz .yes
    cmp al,[rdi]
    jne .no
    inc rsi
    inc rdi
    jmp hcm_literal
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
; Canonical unsigned decimal, bounded to20 digits, overflow checked before use.
hcm_u64:
    xor edx,edx
    xor ecx,ecx
.loop:
    movzx eax,byte [rdi]
    sub eax,'0'
    cmp eax,9
    ja .end
    cmp ecx,20
    jae .no
    test ecx,ecx
    jnz .acc
    cmp eax,0
    jne .acc
    movzx r8d,byte [rdi+1]
    sub r8d,'0'
    cmp r8d,9
    jbe .no
.acc:
    mov r8,1844674407370955161
    cmp rdx,r8
    ja .no
    jne .add
    cmp eax,5
    ja .no
.add:
    lea rdx,[rdx+rdx*4]
    lea rdx,[rax+rdx*2]
    inc ecx
    inc rdi
    jmp .loop
.end:
    test ecx,ecx
    jz .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
str_hcm_name: db "modelkat",0
str_hcm_kind: db "service",0
str_hcm_verb: db "MODELKAT",0
str_hcm_schema: db "v=1 inst=none get=MODELKAT{argmax:u32,ref:capital_france,expect:262,present:bool,disk:bool,size:u64,sha256:configured|none,via:disabled|qemu_loader|fat32_disk/blk_ops|boot_data} observe=whole-native-reply scope=cached-GPT2-boot-diagnostic authority=native no-inference-load-or-classifier-quality-claim list=na set=na input=na cancel=na",0
str_hcm_bad: db " hook err=modelkat_reply_incomplete",0
str_hcm_argmax: db " argmax=",0
str_hcm_ref: db " ref=capital_france expect=262 present=",0
str_hcm_disk: db " disk=",0
str_hcm_size: db " size=",0
str_hcm_sha: db " sha256=",0
str_hcm_none: db "none",0
str_hcm_via_boot: db " via=boot_data",0
str_hcm_via_disk: db " via=fat32_disk/blk_ops",0
str_hcm_via_disabled: db " via=disabled",0
str_hcm_via_loader: db " via=qemu_loader",0
align 8
hook_edge_modelkat: times HE_SZ db 0
hcm_pending: db 0
str_hai_name: db "ai_intent",0
str_hai_verb: db "MODELRUN",0
str_hai_arg: db "INTENT",0
str_hai_schema: db "v=1 inst=none get=MODELRUN_INTENT{bits:u3,reason:0..5,have_seq:bool,seq:u32,action:none} observe=whole-masked-native-snapshot authority=native-owner-compute scope=request-only,no-pop,no-raw-event,no-timestamp,no-mic list=na set=na input=na cancel=na",0
str_hai_reply: db " ai_intent v=1 bits=",0
str_hai_reason: db " reason=",0
str_hai_have: db " have_seq=",0
str_hai_seq: db " seq=",0
str_hai_none: db " action=none",0
str_hai_refused: db " ai_intent refused=native_or_reply action=none",0
align 8
hook_edge_ai_intent: times HE_SZ db 0
hai_pending: db 0
