;; MODULE hv/filesystem_queue
;; LAYER 5
;; EXPORTS fsq_prepare, fsq_finish
;; IMPORTS hv/vmx
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Private bounded split queue snapshot shared by the two F11 devices. No
; indirect/event-index features. The sole resident vCPU is stopped throughout
; prepare, caller service and finish. All spans, including unused capacity,
; must be disjoint from all three metadata spans and every other chain span.
; Resource callbacks operate on private bounce storage, never on these HVAs.
FSQ_MAX equ 8
struc FSQ
 .desc: resq 1
 .avail: resq 1
 .used: resq 1
 .num: resd 1
 .ready: resd 1
 .last: resw 1
 .published: resw 1
 .padding: resd 1
endstruc
struc FSQ_WORK
 .meta: resq 6                      ; HVA,length x3
 .table: resb FSQ_MAX*16
 .span: resq FSQ_MAX*2              ; HVA,length in chain order
 .flags: resw FSQ_MAX
 .head: resd 1
 .count: resd 1
 .total: resd 1
 .seen: resd 1
 .queue: resq 1
 .snapshot: resb FSQ_size
endstruc

; RDI=private FSQ, RSI=private FSQ_WORK ->1 chain/0 empty/-1 malformed.
; Output is unusable unless 1 returned. Does not mutate guest or queue state.
fsq_prepare:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov rbx,rdi
    mov rbp,rsi
    mov rdi,rbp
    mov ecx,FSQ_WORK_size
    xor eax,eax
    cld
    rep stosb
    mov [rbp+FSQ_WORK.queue],rbx
    lea rdi,[rbp+FSQ_WORK.snapshot]
    mov rsi,rbx
    mov ecx,FSQ_size
    rep movsb
    cmp dword [rbx+FSQ.ready],1
    jne .empty
    mov r12d,[rbx+FSQ.num]
    test r12d,r12d
    jz .bad
    cmp r12d,FSQ_MAX
    ja .bad
    lea eax,[r12d-1]
    test eax,r12d
    jnz .bad
    test qword [rbx+FSQ.desc],15
    jnz .bad
    test qword [rbx+FSQ.avail],1
    jnz .bad
    test qword [rbx+FSQ.used],3
    jnz .bad
    xor r13d,r13d
.meta:
    mov rdi,[rbx+r13*8]
    mov esi,r12d
    cmp r13d,0
    jne .not_desc
    shl esi,4
    jmp .map
.not_desc:
    cmp r13d,1
    jne .used
    lea esi,[rsi*2+6]
    jmp .map
.used:
    lea esi,[rsi*8+6]
.map:
    mov r14,rsi
    call hv_linux_gpa2hva
    test rax,rax
    jz .bad
    mov r15d,r13d
    shl r15d,4
    mov [rbp+FSQ_WORK.meta+r15],rax
    mov [rbp+FSQ_WORK.meta+r15+8],r14
    ; Metadata may not alias even when the descriptor chain is empty.
    xor edx,edx
.prior_meta:
    cmp edx,r15d
    jae .next_meta
    mov rcx,[rbp+FSQ_WORK.meta+rdx]
    mov rdi,rcx
    add rdi,[rbp+FSQ_WORK.meta+rdx+8]
    cmp rax,rdi
    jae .meta_disjoint
    lea rsi,[rax+r14]
    cmp rcx,rsi
    jb .bad
.meta_disjoint:
    add edx,16
    jmp .prior_meta
.next_meta:
    inc r13d
    cmp r13d,3
    jb .meta
    mov rax,[rbp+FSQ_WORK.meta+32]
    mov dx,[rbx+FSQ.published]
    cmp dx,[rax+2]
    jne .bad
    mov rax,[rbp+FSQ_WORK.meta+16]
    test word [rax],~1              ; only NO_INTERRUPT
    jnz .bad
    movzx ecx,word [rax+2]
    sub cx,[rbx+FSQ.last]
    jz .empty
    cmp cx,r12w
    ja .bad
    movzx ecx,word [rbx+FSQ.last]
    lea edx,[r12d-1]
    and ecx,edx
    movzx r13d,word [rax+rcx*2+4]
    cmp r13d,r12d
    jae .bad
    mov [rbp+FSQ_WORK.head],r13d
    lea rdi,[rbp+FSQ_WORK.table]
    mov rsi,[rbp+FSQ_WORK.meta]
    mov ecx,r12d
    shl ecx,4
    rep movsb                       ; whole table before any backend callback
.chain:
    cmp r13d,r12d
    jae .bad
    bts [rbp+FSQ_WORK.seen],r13d
    jc .bad
    mov r14d,[rbp+FSQ_WORK.count]
    cmp r14d,FSQ_MAX
    jae .bad
    mov eax,r13d
    shl eax,4
    lea r15,[rbp+FSQ_WORK.table+rax]
    movzx edx,word [r15+12]
    test edx,~3                     ; direct NEXT/WRITE only
    jnz .bad
    mov [rbp+FSQ_WORK.flags+r14*2],dx
    mov rdi,[r15]
    mov esi,[r15+8]
    test esi,esi
    jz .bad
    cmp esi,65536                  ; bounded unused tail capacity too
    ja .bad
    call hv_linux_gpa2hva
    test rax,rax
    jz .bad
    mov ecx,[r15+8]
    mov rdi,rax
    lea rsi,[rax+rcx]
    xor edx,edx
.alias_meta:
    cmp edx,48
    jae .alias_data_start
    mov r8,[rbp+FSQ_WORK.meta+rdx]
    mov r9,r8
    add r9,[rbp+FSQ_WORK.meta+rdx+8]
    cmp rdi,r9
    jae .meta_ok
    cmp r8,rsi
    jb .bad
.meta_ok:
    add edx,16
    jmp .alias_meta
.alias_data_start:
    xor edx,edx
    mov r10d,r14d
    shl r10d,4
.alias_data:
    cmp edx,r10d
    jae .span_ok
    mov r8,[rbp+FSQ_WORK.span+rdx]
    mov r9,r8
    add r9,[rbp+FSQ_WORK.span+rdx+8]
    cmp rdi,r9
    jae .data_ok
    cmp r8,rsi
    jb .bad
.data_ok:
    add edx,16
    jmp .alias_data
.span_ok:
    mov [rbp+FSQ_WORK.span+r10],rax
    mov [rbp+FSQ_WORK.span+r10+8],rcx
    add [rbp+FSQ_WORK.total],ecx
    jc .bad
    inc dword [rbp+FSQ_WORK.count]
    test word [r15+12],1
    jz .ok
    movzx r13d,word [r15+14]
    jmp .chain
.ok:
    mov eax,1
    jmp .out
.empty:
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI=private WORK, ESI=actual bytes written ->0 published/-1 stale.
; Caller revalidates START/device/attachment after any callback BEFORE writing
; data and calling this. No callbacks from payload publication to used.idx.
fsq_finish:
    push rbx
    mov rbx,rdi
    mov r10d,esi
    mov rdi,[rbx+FSQ_WORK.queue]
    lea rsi,[rbx+FSQ_WORK.snapshot]
    mov ecx,FSQ_size/8
    cld
    repe cmpsq
    jne .bad
    mov rdx,[rbx+FSQ_WORK.queue]
    mov rdi,[rbx+FSQ_WORK.meta+32]
    mov ax,[rdx+FSQ.published]
    cmp ax,[rdi+2]
    jne .bad
    mov ecx,[rdx+FSQ.num]
    dec ecx
    movzx eax,ax
    and eax,ecx
    mov ecx,[rbx+FSQ_WORK.head]
    mov [rdi+rax*8+4],ecx
    mov [rdi+rax*8+8],r10d
    inc word [rdx+FSQ.last]
    inc word [rdx+FSQ.published]
    mov ax,[rdx+FSQ.published]
    mov [rdi+2],ax                  ; publish index last
    xor eax,eax
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret
