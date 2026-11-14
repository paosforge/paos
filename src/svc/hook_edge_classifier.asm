;; MODULE svc/hook_edge_classifier
;; LAYER 5
;; EXPORTS hook_classifier_edge_declare, hook_classifier_plan, hook_classifier_post
;; IMPORTS svc/command_hook, svc/command, cognition/gpt2_engine
;; CAPS
;; OWNER saga:command
; Typed projection only. Native MODELRUN CLASSIFY owns authentication, compute
; capability, generation, session/volume lifetime and bounded retirement.
; classifier:<positive u64 generation>: SET <text>, INPUT <u64 step ordinal>,
; GET/OBSERVE (result), CANCEL. No new verb, policy, principal or scheduler.
; The common hook's 224-byte native argument bound further limits typed text.
%include "core/abi/wdata.inc"

hook_classifier_edge_declare:
    push rbx
    lea rbx,[rel hook_edge_classifier]
    lea  rax, [rel hcl_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel hcl_kind]
    mov  [rbx + HE_KIND], rax
    lea rax,[rel hcl_schema]
    mov [rbx+HE_SCHEMA],rax
    lea rax,[rel hook_classifier_plan]
    mov [rbx+HE_PLAN],rax
    lea rax,[rel hook_classifier_post]
    mov [rbx+HE_POST],rax
    mov qword [rbx+HE_OBUF],0
    mov qword [rbx+HE_OREADY],0
    mov qword [rbx+HE_WITNESS],0
    mov rdi,rbx
    call command_hook_edge_register
    pop rbx
    ret

hook_classifier_plan:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12,rsi
    mov r13,rdx
    call hcl_retire
    cmp ebx,HOP_GET
    je .read
    cmp ebx,HOP_CANCEL
    je .read
    cmp ebx,HOP_SET
    je .instance
    cmp ebx,HOP_INPUT
    je .instance
    xor eax,eax
    mov edx,HOOK_PLAN_NA
    jmp .out
.read:
    cmp byte [r13],0
    jne .bad
.instance:
    mov rdi,r12
    call hcl_u64
    jc .bad
    test rax,rax
    jz .bad
    call command_hook_arg_reset
    lea rdi,[rel hcl_begin]
    cmp ebx,HOP_SET
    je .prefix
    lea rdi,[rel hcl_step]
    cmp ebx,HOP_INPUT
    je .prefix
    lea rdi,[rel hcl_result]
    cmp ebx,HOP_GET
    je .prefix
    lea rdi,[rel hcl_cancel]
.prefix:
    call command_hook_arg_str
    mov rdi,r12
    call command_hook_arg_str
    cmp ebx,HOP_SET
    je .payload
    cmp ebx,HOP_INPUT
    jne .planned
    mov rdi,r13
    call hcl_u64
    jc .bad
.payload:
    lea rdi,[rel hcl_space]
    call command_hook_arg_str
    mov rdi,r13
    call command_hook_arg_str
.planned:
    mov [rel hcl_pending],ebx
    lea rax,[rel hcl_verb]
    xor edx,edx
    jmp .out
.bad:
    xor eax,eax
    mov edx,HOOK_PLAN_BADARG
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Exact canonical decimal, at most 20 digits, full u64, no trailing token.
hcl_u64:
    xor eax,eax
    xor ecx,ecx
    cmp byte [rdi],'0'
    jne .next
    cmp byte [rdi+1],0
    jne .bad
.next:
    movzx edx,byte [rdi]
    test edx,edx
    jz .end
    sub edx,'0'
    cmp edx,9
    ja .bad
    inc ecx
    cmp ecx,20
    ja .bad
    mov r8,1844674407370955161
    cmp rax,r8
    ja .bad
    jne .add
    cmp edx,5
    ja .bad
.add:
    imul rax,10
    add rax,rdx
    inc rdi
    jmp .next
.end:
    test ecx,ecx
    jz .bad
    clc
    ret
.bad:
    stc
    ret

; Only a current, complete native advisory/status response may become a witness.
; Only finite uncalibrated score/runnerup/margin bit patterns accompany advice.
; No model text, label, ownership binding or pointer is projected.
hook_classifier_post:
    push rbx
    push r12
    mov rbx,rcx
    cmp qword [rbx+RSP_CODE],CMDE_OK
    jne .refused
    cmp qword [rbx+RSP_ACCEPTED],1
    jne .bad
    cmp edi,[rel hcl_pending]
    jne .bad
    cmp byte [rel cog_out_ready],1
    jne .bad
    lea r12,[rel cog_out_buf]
    xor ecx,ecx
.length:
    cmp ecx,384
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
    call hcl_record
    test eax,eax
    jz .bad
    sub rdi,r12
    push rdi
    call command_hook_out_reset
    pop rsi
    mov rdi,r12
    call command_hook_out_strn
    mov qword [rbx+RSP_VAL],0
    call hcl_retire
    mov eax,1
    jmp .out
.bad:
    call command_hook_out_reset
    lea rdi,[rel hcl_bad_reply]
    call command_hook_out_str
    mov qword [rbx+RSP_CODE],CMDE_BADARG
    mov qword [rbx+RSP_ACCEPTED],0
    mov qword [rbx+RSP_VAL],0
    call hcl_retire
    mov eax,1
    jmp .out
.refused:
    ; UDP's generic envelope does not expose RSP_CODE. Retiring the native
    ; stage without a replacement hid errors behind "HOOK OK". Project only
    ; fixed public reasons from a complete current stage, never arbitrary text.
    lea r12,[rel hcl_reason_native]
    cmp edi,[rel hcl_pending]
    jne .refusal_stage
    cmp byte [rel cog_out_ready],1
    jne .refusal_stage
    call hcl_refusal_reason
    test rax,rax
    jz .refusal_stage
    mov r12,rax
.refusal_stage:
    call command_hook_out_reset
    lea rdi,[rel hcl_refusal_prefix]
    call command_hook_out_str
    mov rdi,r12
    call command_hook_out_str
    lea rdi,[rel hcl_code]
    call command_hook_out_str
    mov rdi,[rbx+RSP_CODE]
    call command_hook_out_dec
    lea rdi,[rel hcl_none]
    call command_hook_out_str
    mov qword [rbx+RSP_ACCEPTED],0
    mov qword [rbx+RSP_VAL],0
    call hcl_retire
    mov eax,1
.out:
    pop r12
    pop rbx
    ret

; Fixed literals bound every read well inside the 384-byte native stage.
; Return only a constant reason, and only for its matching native error code.
hcl_refusal_reason:
    cmp qword [rbx+RSP_CODE],CMDE_AUTHDENY
    je .owner
    cmp qword [rbx+RSP_CODE],CMDE_BADARG
    jne .no
    lea rdi,[rel cog_out_buf]
    lea rsi,[rel hcl_refused_admission]
    call hcl_literal
    jz .arguments
    lea rax,[rel hcl_reason_admission]
    jmp .end
.arguments:
    lea rdi,[rel cog_out_buf]
    lea rsi,[rel hcl_refused_arguments]
    call hcl_literal
    jz .no
    lea rax,[rel hcl_reason_arguments]
    jmp .end
.owner:
    lea rdi,[rel cog_out_buf]
    lea rsi,[rel hcl_refused_owner]
    call hcl_literal
    jz .no
    lea rax,[rel hcl_reason_owner]
.end:
    cmp byte [rdi],0
    jne .no
    cmp rdi,[rel cog_out_cur]
    jne .no
    ret
.no:
    xor eax,eax
    ret

hcl_record:
    cmp dword [rel hcl_pending],HOP_GET
    jne .status
    lea rsi,[rel hcl_advice]
    call hcl_literal
    jz .no
    call hcl_number
    jc .no
    mov r8,0xffffffff
    cmp rax,r8
    ja .no
    lea rsi,[rel hcl_advisory]
    call hcl_literal
    jz .no
    lea rsi,[rel hcl_score]
    call hcl_literal
    jz .no
    call hcl_f32_bits
    jc .no
    lea rsi,[rel hcl_second]
    call hcl_literal
    jz .no
    call hcl_f32_bits
    jc .no
    lea rsi,[rel hcl_margin]
    call hcl_literal
    jz .no
    call hcl_f32_bits
    jc .no
    ; Margin is nonnegative; preserve IEEE negative zero exactly.
    mov r8d,eax
    and r8d,0x7fffffff
    jz .margin_ok
    test eax,0x80000000
    jnz .no
.margin_ok:
    lea rsi,[rel hcl_uncalibrated]
    call hcl_literal
    jz .no
.status:
    lea rsi,[rel hcl_status]
    call hcl_literal
    jz .no
    call hcl_number
    jc .no
    cmp rax,3
    ja .no
    ; Text status and native scalar must describe this same accepted reply.
    cmp rax,[rbx+RSP_VAL]
    jne .no
    cmp dword [rel hcl_pending],HOP_GET
    jne .ordinal
    cmp rax,1
    ja .no
.ordinal:
    lea rsi,[rel hcl_ordinal]
    call hcl_literal
    jz .no
    call hcl_number
    jc .no
    lea rsi,[rel hcl_none]
    call hcl_literal
    jz .no
    cmp byte [rdi],0
    jne .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
; Canonical unsigned decimal of one finite IEEE binary32 bit pattern.
; Check upper bits before exponent/sign; formatting does not touch FP state.
hcl_f32_bits:
    call hcl_number
    jc .bad
    mov r8,0xffffffff
    cmp rax,r8
    ja .bad
    mov r8d,eax
    and r8d,0x7fffffff
    cmp r8d,0x7f800000
    jae .bad
    clc
    ret
.bad:
    stc
    ret
hcl_literal:
    mov al,[rsi]
    test al,al
    jz .yes
    cmp al,[rdi]
    jne .no
    inc rsi
    inc rdi
    jmp hcl_literal
.yes:
    mov eax,1
    test eax,eax
    ret
.no:
    xor eax,eax
    ret
; Decimal token terminated by the fixed following literal's leading space.
hcl_number:
    mov r9,rdi
.scan:
    cmp byte [rdi],' '
    je .end
    cmp byte [rdi],0
    je .bad
    sub rdi,r9
    cmp rdi,20
    jae .bad
    add rdi,r9
    inc rdi
    jmp .scan
.end:
    mov r10,rdi
    mov byte [rdi],0
    mov rdi,r9
    call hcl_u64
    mov byte [r10],' '
    mov rdi,r10
    ret
.bad:
    stc
    ret
hcl_retire:
    push rax
    push rcx
    push rdi
    mov dword [rel hcl_pending],0
    mov byte [rel cog_out_ready],0
    mov qword [rel cog_out_cur],0
    lea rdi,[rel cog_out_buf]
    xor eax,eax
    mov ecx,384/8
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    ret
hcl_name: db "classifier",0
hcl_kind: db "service",0
hcl_schema: db "kind=service identity=classifier:<positive-u64-generation> get=RESULT observe=RESULT set=<text> input=<u64-ordinal> cancel=CANCEL native=MODELRUN_CLASSIFY begin=monotonic-generation bounds=native-argument-223-bytes result=advice-index-status-ordinal score=uncalibrated-f32-bits calibration=none action=none authority=native-owner-compute-lifetime production=manifest-admitted-only",0
hcl_verb: db "MODELRUN",0
hcl_begin: db "CLASSIFY BEGIN ",0
hcl_step: db "CLASSIFY STEP ",0
hcl_result: db "CLASSIFY RESULT ",0
hcl_cancel: db "CLASSIFY CANCEL ",0
hcl_space: db " ",0
hcl_advice: db " classifier advice_index=",0
hcl_advisory: db " advisory=1",0
hcl_score: db " score_f32_bits=",0
hcl_second: db " second_f32_bits=",0
hcl_margin: db " margin_f32_bits=",0
hcl_uncalibrated: db " calibrated=0",0
hcl_status: db " classifier status=",0
hcl_ordinal: db " ordinal=",0
hcl_none: db " action=none",0
hcl_refusal_prefix: db " classifier refused=",0
hcl_code: db " code=",0
hcl_reason_native: db "native",0
hcl_reason_admission: db "admission",0
hcl_reason_arguments: db "arguments_or_state",0
hcl_reason_owner: db "owner_or_lifetime",0
hcl_refused_admission: db " classifier refused=admission action=none",0
hcl_refused_arguments: db " classifier refused=arguments_or_state action=none",0
hcl_refused_owner: db " classifier refused=owner_or_lifetime action=none",0
hcl_bad_reply: db " hook err=classifier_reply_incomplete",0
%macro WDATA_svc_hook_edge_classifier_0 0
align 8,db 0
hook_edge_classifier: times HE_SZ db 0
hcl_pending: dd 0
%endmacro
WDATA_DEFER WDATA_svc_hook_edge_classifier_0
