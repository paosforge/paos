;; MODULE gui/img/hook_edge_image
;; LAYER 6
;; EXPORTS hook_image_edge_declare, hook_image_plan, hook_image_post
;; IMPORTS gui/img/img_core, svc/command, svc/command_hook
;; CAPS
;; OWNER saga:gui_image_pipeline
; Typed built-in image catalog, not arbitrary file access. Common dispatch
; retains native authority. No direct handler call. Explicit decode is a
; synchronous diagnostic whose whole-reply witness includes time and heap.
; BSP command serialization owns the stage, retired before/after every use.
HIE_NATIVE_MAX equ 1180
HIE_NAME_MAX equ 63

hook_image_edge_declare:
    push rbx
    lea rbx,[rel hook_edge_image]
    lea  rax, [rel hie_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel hie_kind]
    mov  [rbx + HE_KIND], rax
    lea rax,[rel hie_schema]
    mov [rbx+HE_SCHEMA],rax
    lea rax,[rel hook_image_plan]
    mov [rbx+HE_PLAN],rax
    lea rax,[rel hook_image_post]
    mov [rbx+HE_POST],rax
    mov qword [rbx+HE_OBUF],0
    mov qword [rbx+HE_OREADY],0
    mov qword [rbx+HE_WITNESS],0
    mov rdi,rbx
    call command_hook_edge_register
    pop rbx
    ret

hook_image_plan:
    push rdi
    push rsi
    push rdx
    call hie_retire
    pop rdx
    pop rsi
    pop rdi
    cmp edi,HOP_LIST
    je .list
    cmp edi,HOP_GET
    jne .na
    cmp byte [rsi],0
    je .bad
    xor ecx,ecx
.name:
    mov al,[rsi+rcx]
    test al,al
    jz .name_ok
    cmp ecx,HIE_NAME_MAX
    jae .bad
    cmp al,'a'
    jb .upper
    cmp al,'z'
    jbe .next
.upper:
    cmp al,'A'
    jb .digit
    cmp al,'Z'
    jbe .next
.digit:
    cmp al,'0'
    jb .punct
    cmp al,'9'
    jbe .next
.punct:
    cmp al,'_'
    je .next
    cmp al,'-'
    je .next
    cmp al,'.'
    jne .bad
.next:
    inc ecx
    jmp .name
.name_ok:
    mov r8,rsi
    mov r9d,2
    lea r10,[rel hie_info]
    cmp byte [rdx],0
    je .argument
    mov rdi,rdx
    lea rsi,[rel hie_decode]
    call command_hook_word_eq
    test eax,eax
    jz .bad
    mov r9d,3
    lea r10,[rel hie_dec]
    jmp .argument
.list:
    cmp byte [rdx],0
    jne .bad
    lea r8,[rel hie_first]
    cmp byte [rsi],0
    je .list_ok
    cmp byte [rsi+1],0
    jne .bad
    cmp byte [rsi],'1'
    jb .bad
    cmp byte [rsi],'3'
    ja .bad
    mov r8,rsi
.list_ok:
    mov r9d,1
    lea r10,[rel hie_list]
.argument:
    push r9
    push r10
    mov rdi,r8
    call command_hook_arg_str
    mov rdi,[rsp]
    call command_lookup
    pop r10
    pop r9
    cmp rax,-1
    je .return_verb
    mov [rel hie_pending],r9b
.return_verb:
    mov rax,r10
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

hook_image_post:
    push rbx
    push r12
    mov rbx,rcx
    call command_hook_out_reset          ; gate refusals must not expose old text
    cmp qword [rbx+RSP_CODE],CMDE_OK
    je .publication
    ; A native BADARG may publish its normal missing-name diagnosis; gate
    ; refusals have no fresh stage and retain their original code/hint.
    cmp qword [rbx+RSP_CODE],CMDE_BADARG
    jne .retire
    cmp byte [rel img_out_ready],1
    jne .retire
.publication:
    movzx eax,byte [rel hie_pending]
    dec eax
    cmp eax,2
    ja .bad
    cmp byte [rel img_out_ready],1
    jne .bad
    lea rax,[rel command_hook_arg]
    cmp [rbx+RSP_VAL],rax                ; native argument-binding contract
    jne .bad
    lea r12,[rel img_out_buf]
    xor ecx,ecx
.length:
    cmp ecx,HOOK_OUT_MAX
    jae .bad                            ; refuse rather than truncate
    mov al,[r12+rcx]
    test al,al
    jz .bounded
    cmp al,32
    jb .bad
    cmp al,126
    ja .bad
    inc ecx
    jmp .length
.bounded:
    test ecx,ecx
    jz .bad
    lea rax,[r12+rcx]
    cmp rax,[rel img_out_cur]
    jne .bad
    push rcx
    call command_hook_out_reset
    pop rsi
    mov rdi,r12
    call command_hook_out_strn
    jmp .retire
.bad:
    mov qword [rbx+RSP_CODE],CMDE_BADARG
    lea rax,[rel hie_error]
    mov [rbx+RSP_HINT],rax
    call command_hook_out_reset
    lea rdi,[rel hie_error]
    call command_hook_out_str
.retire:
    call hie_retire
    mov eax,1
    pop r12
    pop rbx
    ret

hie_retire:
    cld
    lea rdi,[rel img_out_buf]
    mov ecx,HIE_NATIVE_MAX
    xor eax,eax
    rep stosb
    mov qword [rel img_out_cur],0
    mov byte [rel img_out_ready],0
    mov byte [rel hie_pending],0
    ret

align 8
hook_edge_image: times HE_SZ db 0
hie_pending: db 0
hie_name: db "image",0
hie_kind: db "service",0
hie_list: db "IMGLIST",0
hie_info: db "IMGINFO",0
hie_dec: db "IMGDEC",0
hie_decode: db "DECODE",0
hie_first: db "1",0
hie_error: db " hook err=image_reply_incomplete",0
hie_schema: db "v=1 scope=builtin-catalog-only list=image[:page1..3]:IMGLIST{page,n,name,fmt,bytes} get=image:<name1..63>[decode]:IMGINFO|IMGDEC name=case-sensitive[A-Za-z0-9_.-] info={imginfo,reason?,name?,fmt?,w?,h?,bpp?} decode={imgdec,reason?,name?,fmt?,w?,h?,rgba_crc32?,ms?,heap_delta,heap_now} authority=native observe=whole-reply(decode-includes-ms-and-heap) decode=synchronous-diagnostic-no-pixels-or-files set=na input=na cancel=na",0
