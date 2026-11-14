;; MODULE svc/hook_edge_ntfsstate
;; LAYER 5
;; EXPORTS hook_ntfsstate_edge_declare, hook_ntfsstate_plan, hook_ntfsstate_post
;; IMPORTS svc/command_fs, svc/command_hook, svc/command, svc/hook_edges_svc
;; CAPS
;; OWNER saga:command

; Read-only native FSNTFSSTATE: selected NTFS context facts, not mount selection.
; The accepted native producer owns registry/context/geometry/generation checks.
; Bind its request-argument scalar and fresh nonce before copying the complete
; canonical V1 record; retire shared staging on every path. BSP serialized.
HNS_REPLY_MAX equ 1408
hook_ntfsstate_edge_declare:
    push rbx
    lea rbx,[rel hook_edge_ntfsstate]
    lea  rax, [rel str_hns_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hns_kind]
    mov  [rbx + HE_KIND], rax
    lea rax,[rel str_hns_schema]
    mov [rbx+HE_SCHEMA],rax
    lea rax,[rel hook_ntfsstate_plan]
    mov [rbx+HE_PLAN],rax
    lea rax,[rel hook_ntfsstate_post]
    mov [rbx+HE_POST],rax
    mov qword [rbx+HE_OBUF],0
    mov qword [rbx+HE_OREADY],0
    lea rax,[rel str_hns_witness]
    mov [rbx+HE_WITNESS],rax
    mov rdi,rbx
    call command_hook_edge_register
    pop rbx
    ret
hook_ntfsstate_plan:
    call hns_retire
    cmp edi,HOP_GET
    jne .na
    cmp byte [rsi],0
    jne .bad
    cmp byte [rdx],0
    jne .bad
    lea rdi,[rel str_hns_verb]
    call command_lookup
    cmp rax,-1
    je .unregistered
    xor edi,edi
    call hse_arg_nonce
    mov byte [rel hns_pending],1
.unregistered:
    lea rax,[rel str_hns_verb]
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
hook_ntfsstate_post:
    push rbx
    push r12
    push r13
    mov rbx,rcx
    cmp qword [rbx+RSP_CODE],CMDE_OK
    jne .refused
    cmp byte [rel hns_pending],1
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
    cmp r13d,HNS_REPLY_MAX
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
    call hns_record
    test eax,eax
    jz .bad
    call hns_copy
.done:
    mov qword [rbx+RSP_VAL],0 ; never publish the ephemeral native argument address
    call hns_retire
    mov eax,1
    jmp .out
.bad:
    call command_hook_out_reset
    lea rdi,[rel str_hns_bad]
    call command_hook_out_str
    mov qword [rbx+RSP_CODE],CMDE_BADARG
    mov qword [rbx+RSP_ACCEPTED],0
    mov qword [rbx+RSP_VAL],0
    lea rax,[rel str_hns_bad]
    mov [rbx+RSP_HINT],rax
    jmp .done
.refused:
    mov qword [rbx+RSP_VAL],0
    call hns_retire
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret
hns_copy:
    call command_hook_out_reset
    mov rdi,r12
    mov rsi,r13
    jmp command_hook_out_strn
hns_retire:
    push rax
    push rcx
    push rdi
    mov byte [rel hns_pending],0
    mov byte [rel fs_out_ready],0
    mov byte [rel fs_out_truncated],0
    mov qword [rel fs_out_cur],0
    lea rdi,[rel fs_out_buf]
    xor eax,eax
    mov ecx,HNS_REPLY_MAX
    cld
    rep stosb
    pop rdi
    pop rcx
    pop rax
    ret

; Exact ordered grammar. Noncurrent states must have all facts unavailable.
; Current names follow native ASCII token1..63 (including colon). Numeric
; fields retain full u64 widths and the native inclusive-last-LBA invariant.
hns_record:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea rsi,[rel str_hns_head]
    call hns_literal
    test eax,eax
    jz .no
    lea rsi,[rel command_hook_arg]
    call hns_literal
    test eax,eax
    jz .no
    lea rsi,[rel str_hns_state]
    call hns_literal
    test eax,eax
    jz .no
    mov rbx,rdi
    xor r12d,r12d
    lea rsi,[rel str_hns_current]
    call hns_literal
    test eax,eax
    jz .closed
    inc r12d
    jmp .state
.closed:
    mov rdi,rbx
    lea rsi,[rel str_hns_closed]
    call hns_literal
    test eax,eax
    jnz .state
    mov rdi,rbx
    lea rsi,[rel str_hns_stale]
    call hns_literal
    test eax,eax
    jnz .state
    mov rdi,rbx
    lea rsi,[rel str_hns_unknown]
    call hns_literal
    test eax,eax
    jz .no
.state:
    lea rsi,[rel str_hns_dev]
    call hns_literal
    test eax,eax
    jz .no
    test r12d,r12d
    jnz .name_start
    lea rsi,[rel str_hns_unknown]
    call hns_literal
    test eax,eax
    jz .no
    jmp .fields_start
.name_start:
    xor ecx,ecx
.name:
    movzx eax,byte [rdi]
    cmp eax,' '
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
    je .name_character
    cmp eax,':'
    jne .no
.name_character:
    cmp ecx,63
    jae .no
    inc ecx
    inc rdi
    jmp .name
.name_end:
    test ecx,ecx
    jz .no
.fields_start:
    xor r13d,r13d
.fields:
    lea rsi,[rel hns_fields]
    movsxd rax,dword [rsi+r13*4]
    add rsi,rax
    call hns_literal
    test eax,eax
    jz .no
    test r12d,r12d
    jnz .number
    lea rsi,[rel str_hns_unknown]
    call hns_literal
    test eax,eax
    jz .no
    jmp .next
.number:
    call hns_u64
    test eax,eax
    jz .no
    test r13d,r13d
    jnz .start
    mov eax,0xfffffffe                 ; native mount handle excludes -1
    cmp rdx,rax
    ja .no
    jmp .next
.start:
    cmp r13d,1
    jne .sectors
    mov r14,rdx
    jmp .next
.sectors:
    cmp r13d,2
    jne .last
    test rdx,rdx
    jz .no
    dec rdx                           ; native extent uses inclusive last LBA
    add rdx,r14
    jc .no
    mov r15,rdx
    jmp .next
.last:
    cmp r13d,3
    jne .sector_bytes
    cmp rdx,r15
    jb .no
    jmp .next
.sector_bytes:
    cmp r13d,4
    jne .logical_bytes
    cmp rdx,512                       ; native CURRENT geometry is 512-byte
    jne .no
    jmp .next
.logical_bytes:
    cmp r13d,5
    jne .generation
    test rdx,rdx
    jz .next
    cmp rdx,512                       ; zero means unspecified, preserve it
    jne .no
    jmp .next
.generation:
    test rdx,rdx                      ; native media/binding epochs nonzero
    jz .no
.next:
    inc r13d
    cmp r13d,8
    jb .fields
    cmp byte [rdi],0
    jne .no
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
hns_literal:
    mov al,[rsi]
    test al,al
    jz .yes
    cmp al,[rdi]
    jne .no
    inc rsi
    inc rdi
    jmp hns_literal
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
; Canonical unsigned decimal, bounded to20 digits, overflow checked before use.
hns_u64:
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
str_hns_name: db "ntfsstate",0
str_hns_kind: db "storage",0
str_hns_verb: db "FSNTFSSTATE",0
str_hns_schema: db "v=1 inst=none get=FSNTFSSTATE{V:1,STATE:current|closed|stale|unavailable,DEV:token1..63,MOUNT:u32-except-max,START:u64,SECTORS:u64-nonzero,LBA_MAX:u64-inclusive,SECTOR_BYTES:512,LOGICAL_BYTES:0|512,MEDIA_GEN:u64-nonzero,BINDING_GEN:u64-nonzero} noncurrent=all-facts-unavailable observe=STATE,DEV,MOUNT,START,SECTORS,LBA_MAX,SECTOR_BYTES,LOGICAL_BYTES,MEDIA_GEN,BINDING_GEN nonce=excluded scope=saved-NTFS-selection-only scalar=native-argument-bound-then-zero authority=native no-media-I/O list=na set=na input=na cancel=na",0
str_hns_witness: db " STATE=",0," DEV=",0," MOUNT=",0," START=",0," SECTORS=",0," LBA_MAX=",0," SECTOR_BYTES=",0," LOGICAL_BYTES=",0," MEDIA_GEN=",0," BINDING_GEN=",0,0
str_hns_bad: db " hook err=ntfsstate_reply_incomplete",0
str_hns_head: db "FSNTFSSTATE V=1 NONCE=",0
str_hns_state: db " STATE=",0
str_hns_current: db "current",0
str_hns_closed: db "closed",0
str_hns_stale: db "stale",0
str_hns_unknown: db "unavailable",0
str_hns_dev: db " DEV=",0
str_hns_field0: db " MOUNT=",0
str_hns_field1: db " START=",0
str_hns_field2: db " SECTORS=",0
str_hns_field3: db " LBA_MAX=",0
str_hns_field4: db " SECTOR_BYTES=",0
str_hns_field5: db " LOGICAL_BYTES=",0
str_hns_field6: db " MEDIA_GEN=",0
str_hns_field7: db " BINDING_GEN=",0
align 4
hns_fields:
    dd str_hns_field0 - hns_fields
    dd str_hns_field1 - hns_fields
    dd str_hns_field2 - hns_fields
    dd str_hns_field3 - hns_fields
    dd str_hns_field4 - hns_fields
    dd str_hns_field5 - hns_fields
    dd str_hns_field6 - hns_fields
    dd str_hns_field7 - hns_fields
align 8
hook_edge_ntfsstate: times HE_SZ db 0
hns_pending: db 0
