;; MODULE svc/hook_edge_partition
;; LAYER 5
;; EXPORTS hook_partition_edge_declare, hook_partition_plan, hook_partition_post
;; IMPORTS svc/command_fs, svc/command_hook, svc/command, svc/hook_edges_svc
;; CAPS
;; OWNER saga:command
; Selected mounted volume only. Native PARTLS owns device-union resolution and
; formatting; no mount choice/probe/backend I/O is added here. BSP serialized.
; Native fs_finish returns the request-argument pointer even for textual ERR:
; bind that exact scalar before copying, clear the ephemeral pointer afterwards,
; and promote canonical ERR to typed refusal so OBSERVE cannot witness failure.
HPI_REPLY_MAX equ 1408
hook_partition_edge_declare:
    push rbx
    lea rbx,[rel hook_edge_partition]
    lea  rax, [rel str_hpi_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hpi_kind]
    mov  [rbx + HE_KIND], rax
    lea rax,[rel str_hpi_schema]
    mov [rbx+HE_SCHEMA],rax
    lea rax,[rel hook_partition_plan]
    mov [rbx+HE_PLAN],rax
    lea rax,[rel hook_partition_post]
    mov [rbx+HE_POST],rax
    mov qword [rbx+HE_OBUF],0
    mov qword [rbx+HE_OREADY],0
    lea rax,[rel str_hpi_witness]
    mov [rbx+HE_WITNESS],rax
    mov rdi,rbx
    call command_hook_edge_register
    pop rbx
    ret
hook_partition_plan:
    call hpi_retire
    cmp edi,HOP_GET
    jne .na
    cmp byte [rsi],0
    jne .bad
    cmp byte [rdx],0
    jne .bad
    lea rdi,[rel str_hpi_verb]
    call command_lookup
    cmp rax,-1
    je .unregistered
    xor edi,edi
    call hse_arg_nonce
    mov byte [rel hpi_pending],1
.unregistered:
    lea rax,[rel str_hpi_verb]
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
hook_partition_post:
    push rbx
    push r12
    push r13
    mov rbx,rcx
    cmp qword [rbx+RSP_CODE],CMDE_OK
    jne .refused
    cmp byte [rel hpi_pending],1
    jne .bad
    cmp byte [rel fs_out_ready],1
    jne .bad
    cmp byte [rel fs_out_truncated],0
    jne .bad
    lea rax,[rel command_hook_arg]
    cmp [rbx+RSP_VAL],rax
    jne .bad
    lea r12,[rel fs_out_buf]
    xor r13d,r13d
.length:
    cmp r13d,HPI_REPLY_MAX
    jae .bad
    cmp byte [r12+r13],0
    je .bounded
    inc r13d
    jmp .length
.bounded:
    cmp r13d,HOOK_OUT_MAX
    jae .bad
    lea rax,[r12+r13]
    cmp rax,[rel fs_out_cur]
    jne .bad
    mov rdi,r12
    lea rsi,[rel str_hpi_native_error]
    call hpi_literal
    test eax,eax
    jz .record
    cmp byte [rdi],0
    jne .bad
    call hpi_copy
    mov qword [rbx+RSP_CODE],CMDE_BADARG
    mov qword [rbx+RSP_ACCEPTED],0
    lea rax,[rel str_hpi_native_error]
    mov [rbx+RSP_HINT],rax
    jmp .done
.record:
    mov rdi,r12
    call hpi_record
    test eax,eax
    jz .bad
    call hpi_copy
.done:
    mov qword [rbx+RSP_VAL],0 ; never publish the ephemeral native argument address
    call hpi_retire
    mov eax,1
    jmp .out
.bad:
    call command_hook_out_reset
    lea rdi,[rel str_hpi_bad]
    call command_hook_out_str
    mov qword [rbx+RSP_CODE],CMDE_BADARG
    mov qword [rbx+RSP_ACCEPTED],0
    mov qword [rbx+RSP_VAL],0
    lea rax,[rel str_hpi_bad]
    mov [rbx+RSP_HINT],rax
    jmp .done
.refused:
    call hpi_retire
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret
hpi_copy:
    call command_hook_out_reset
    mov rdi,r12
    mov rsi,r13
    jmp command_hook_out_strn
hpi_retire:
    push rax
    push rcx
    push rdi
    mov byte [rel hpi_pending],0
    mov byte [rel fs_out_ready],0
    mov byte [rel fs_out_truncated],0
    mov qword [rel fs_out_cur],0
    lea rdi,[rel fs_out_buf]
    xor eax,eax
    mov ecx,HPI_REPLY_MAX
    cld
    rep stosb
    pop rdi
    pop rcx
    pop rax
    ret

; Complete ordered canonical grammar after a bounded NUL/cursor check. Device
; names follow the native sanitized1..63 [A-Za-z0-9_.-] token.
; P repeats that exact name, with selected-volume index0 (not a disk census).
hpi_record:
    push rbx
    push r12
    push r13
    lea rsi,[rel str_hpi_head]
    call hpi_literal
    test eax,eax
    jz .no
    lea rsi,[rel command_hook_arg]
    call hpi_literal
    test eax,eax
    jz .no
    lea rsi,[rel str_hpi_dev]
    call hpi_literal
    test eax,eax
    jz .no
    mov r12,rdi
    xor r13d,r13d
.name:
    movzx eax,byte [rdi]
    cmp eax,':'
    je .name_end
    cmp eax,'0'
    jb .punctuation
    cmp eax,'9'
    jbe .name_character
    cmp eax,'A'
    jb .punctuation
    cmp eax,'Z'
    jbe .name_character
    cmp eax,'a'
    jb .punctuation
    cmp eax,'z'
    jbe .name_character
.punctuation:
    cmp eax,'_'
    je .name_character
    cmp eax,'-'
    je .name_character
    cmp eax,'.'
    jne .no
.name_character:
    cmp r13d,63
    jae .no
    inc r13d
    inc rdi
    jmp .name
.name_end:
    test r13d,r13d
    jz .no
    inc rdi
    mov rbx,rdi
    mov rdi,rbx
    lea rsi,[rel str_hpi_gpt]
    call hpi_literal
    test eax,eax
    jnz .scheme
    mov rdi,rbx
    lea rsi,[rel str_hpi_mbr]
    call hpi_literal
    test eax,eax
    jnz .scheme
    mov rdi,rbx
    lea rsi,[rel str_hpi_super]
    call hpi_literal
    test eax,eax
    jnz .scheme
    mov rdi,rbx
    lea rsi,[rel str_hpi_unknown_colon]
    call hpi_literal
    test eax,eax
    jnz .scheme
    jmp .no
.scheme:
    cmp byte [rdi],'u'
    jne .count_number
    lea rsi,[rel str_hpi_unknown]
    call hpi_literal
    test eax,eax
    jz .no
    jmp .part
.count_number:
    call hpi_u64
    test eax,eax
    jz .no
    mov eax,0xfffffffe
    cmp rdx,rax
    ja .no
.part:
    lea rsi,[rel str_hpi_part]
    call hpi_literal
    test eax,eax
    jz .no
    xor ecx,ecx
.repeat_name:
    cmp rcx,r13
    jae .repeat_end
    mov al,[r12+rcx]
    cmp al,[rdi+rcx]
    jne .no
    inc ecx
    jmp .repeat_name
.repeat_end:
    add rdi,r13
    lea rsi,[rel str_hpi_index]
    call hpi_literal
    test eax,eax
    jz .no
    cmp byte [rdi],'u'
    jne .extent_number
    lea rsi,[rel str_hpi_unknown_colon]
    call hpi_literal
    test eax,eax
    jz .no
    lea rsi,[rel str_hpi_unknown]
    call hpi_literal
    test eax,eax
    jz .no
    jmp .type
.extent_number:
    call hpi_u64
    test eax,eax
    jz .no
    cmp rdx,-1
    je .no
    mov r12,rdx
    lea rsi,[rel str_hpi_colon]
    call hpi_literal
    test eax,eax
    jz .no
    call hpi_u64
    test eax,eax
    jz .no
    test rdx,rdx
    jz .no
    add rdx,r12
    jc .no
.type:
    lea rsi,[rel str_hpi_colon]
    call hpi_literal
    test eax,eax
    jz .no
    mov rbx,rdi
    mov rdi,rbx
    lea rsi,[rel str_hpi_ntfs]
    call hpi_literal
    test eax,eax
    jnz .type_end
    mov rdi,rbx
    lea rsi,[rel str_hpi_linux]
    call hpi_literal
    test eax,eax
    jnz .type_end
    mov rdi,rbx
    lea rsi,[rel str_hpi_fat]
    call hpi_literal
    test eax,eax
    jnz .type_end
    mov rdi,rbx
    lea rsi,[rel str_hpi_exfat]
    call hpi_literal
    test eax,eax
    jnz .type_end
    mov rdi,rbx
    lea rsi,[rel str_hpi_unknown]
    call hpi_literal
    test eax,eax
    jnz .type_end
    jmp .no
.type_end:
    cmp byte [rdi],0
    jne .no
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret
hpi_literal:
    mov al,[rsi]
    test al,al
    jz .yes
    cmp al,[rdi]
    jne .no
    inc rsi
    inc rdi
    jmp hpi_literal
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
; Canonical unsigned decimal, bounded to20 digits, overflow checked before use.
hpi_u64:
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
str_hpi_name: db "partition",0
str_hpi_kind: db "storage",0
str_hpi_verb: db "PARTLS",0
str_hpi_schema: db "v=1 inst=none get=PARTLS{DEV{name:token1..63|unavailable,scheme:gpt|mbr|superfloppy|unavailable,count:u32-except-max|unavailable},P{name:same,index:0,start:u64|unavailable,sectors:u64-nonzero|unavailable,type:07|83|fat32|exfat|unavailable}} observe=DEV,P nonce=excluded scope=selected-volume-only scalar=native-argument-bound-then-zero authority=native list=na set=na input=na cancel=na",0
str_hpi_witness: db " DEV=",0," P=",0,0
str_hpi_bad: db " hook err=partition_reply_incomplete",0
str_hpi_native_error: db "PARTLS ERR no_partition_inventory",0
str_hpi_head: db "PARTLS NONCE=",0
str_hpi_dev: db " DEV=",0
str_hpi_gpt: db "gpt:",0
str_hpi_mbr: db "mbr:",0
str_hpi_super: db "superfloppy:",0
str_hpi_unknown_colon: db "unavailable:",0
str_hpi_unknown: db "unavailable",0
str_hpi_part: db " P=",0
str_hpi_index: db ":0:",0
str_hpi_colon: db ":",0
str_hpi_ntfs: db "07",0
str_hpi_linux: db "83",0
str_hpi_fat: db "fat32",0
str_hpi_exfat: db "exfat",0
align 8
hook_edge_partition: times HE_SZ db 0
hpi_pending: db 0
