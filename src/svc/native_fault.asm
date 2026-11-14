;; MODULE svc/native_fault
;; LAYER 5
;; EXPORTS native_fault_control, native_fault_snapshot
;; IMPORTS core/native_app
;; CAPS
;; OWNER saga:rc_t2_4_native_fault
; Fixed trusted module, not arbitrary ring0 isolation or a core recovery route.
; The entry only computes in its own arena with IF unchanged and no host calls.
; A failed entry stays STUCK until this explicit bounded owner restart control.
; Snapshot22Q: status/kind/slot/gen/restart_gen/lease/first_rc/cause/state/
; entered/reentry_rc/reentry_count/restart_rc/stale_rc/zeroed/healthy_rc/
; healthy_count/value/unregister_rc/live_before/live_after/first_cycles.
; status0 earned,1 context/capacity refusal,2 unavailable fence,3 contradiction.
native_fault_control:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,16
    mov qword [rsp],0                 ; exact owned registration only
    mov r15,rdi
    lea rbx,[rel native_fault_snapshot]
    mov rdi,rbx
    mov ecx,22
    xor eax,eax
    cld
    rep stosq
    mov qword [rbx],1
    mov [rbx+8],r15
    mov qword [rbx+16],-1
    cmp r15,1
    ja .out
    xor edi,edi                       ; public query includes context gate
    call native_app_query
    test rax,rax
    js .out
    call native_fault_live_count
    mov [rbx+152],rax
    mov [rbx+160],rax
    lea rdi,[rel native_fault_entry]
    mov esi,20
    call native_app_register_with_lease
    test rax,rax
    js .out
    mov r12,rax
    mov r13,rdx
    mov qword [rsp],1
    mov [rbx+16],rax
    mov [rbx+24],rdx
    mov qword [rbx+40],20
    mov qword [rbx],3
    mov edi,r12d
    call native_app_query
    cmp rax,NAPP_READY
    jne .cleanup
    cmp rdx,r13
    jne .cleanup
    mov r14,r8
    mov [r14+8],r15
    mov edi,r12d
    mov rsi,r13
    call native_app_dispatch
    mov [rbx+48],rax
    cmp rax,-4
    je .unavailable
    cmp rax,1
    jne .cleanup
    mov edi,r12d
    call native_app_query
    mov [rbx+56],r10
    mov [rbx+64],rax
    mov [rbx+168],r9
    cmp rax,NAPP_STUCK
    jne .cleanup
    cmp rdx,r13
    jne .cleanup
    cmp r8,r14
    jne .cleanup
    test r9,r9
    jz .cleanup
    mov rax,r15
    inc rax
    neg rax
    cmp r10,rax
    jne .cleanup
    mov rax,[r14+16]
    mov [rbx+72],rax
    cmp rax,1
    jne .cleanup
    mov edi,r12d
    mov rsi,r13
    call native_app_dispatch             ; STUCK must never execute again
    mov [rbx+80],rax
    cmp rax,1
    jne .cleanup
    mov rax,[r14+16]
    mov [rbx+88],rax
    cmp rax,1
    jne .cleanup
    mov edi,r12d
    mov rsi,r13
    call native_app_restart
    mov [rbx+96],rax
    test rax,rax
    jnz .cleanup
    mov [rbx+32],rdx
    mov rsi,r13                        ; stale handle control, no dispatch
    mov r13,rdx                        ; only new known owned generation
    cmp r13,[rbx+24]
    jbe .cleanup
    mov edi,r12d
    call native_app_dispatch
    mov [rbx+104],rax
    cmp rax,-2
    jne .cleanup
    mov edi,r12d
    call native_app_query
    cmp rax,NAPP_READY
    jne .cleanup
    cmp rdx,r13
    jne .cleanup
    cmp r8,r14
    jne .cleanup
    xor eax,eax
    xor ecx,ecx
.zero_check:
    or rax,[r14+rcx*8]
    inc ecx
    cmp ecx,4096/8
    jb .zero_check
    test rax,rax
    jnz .cleanup
    mov qword [rbx+112],1
    mov qword [r14],1                  ; trusted owner selects useful computation
    mov edi,r12d
    mov rsi,r13
    call native_app_dispatch
    mov [rbx+120],rax
    test rax,rax
    jnz .cleanup
    mov rax,[r14+16]
    mov [rbx+128],rax
    cmp rax,1
    jne .cleanup
    mov rax,[r14+24]
    mov [rbx+136],rax
    cmp rax,2080                       ; actual sum1..64, not a latched marker
    jne .cleanup
    mov edi,r12d
    call native_app_query
    cmp rax,NAPP_READY
    jne .cleanup
    cmp rdx,r13
    jne .cleanup
    test r10,r10
    jnz .cleanup
    mov qword [rbx],0
    jmp .cleanup
.unavailable:
    mov qword [rbx],2
.cleanup:
    cmp qword [rsp],1
    jne .out
    mov edi,r12d
    mov rsi,r13
    call native_app_unregister          ; one known handle, never retry/guess
    mov [rbx+144],rax
    test rax,rax
    jnz .bad
    call native_fault_live_count
    mov [rbx+160],rax
    cmp rax,[rbx+152]
    jne .bad
    jmp .out
.bad:
    mov qword [rbx],3
.out:
    mov rax,[rbx]
    add rsp,16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Read-only aggregate; foreign entries, generations and arenas are never reset.
native_fault_live_count:
    push rbx
    push r12
    sub rsp,8
    xor ebx,ebx
    xor r12d,r12d
.loop:
    mov edi,ebx
    call native_app_query              ; public read-only slot/state query
    cmp rax,NAPP_RUNNING
    ja .bad
    test rax,rax
    jz .next
    inc r12d
.next:
    inc ebx
    cmp ebx,NAPP_MAX
    jb .loop
    mov rax,r12
    jmp .out
.bad:
    mov rax,-1
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

native_fault_entry:
    inc qword [rdi+16]
    cmp qword [rdi],1
    je .useful
    cmp qword [rdi+8],0
    jne .spin
    ud2                                ; actual recoverable module #UD
.spin:
    pause
    jmp .spin                          ; actual watchdog nonreturn, IF unchanged
.useful:
    xor eax,eax
    mov ecx,64
.sum:
    add rax,rcx
    loop .sum
    mov [rdi+24],rax
    ret

%macro WDATA_native_fault 0
align 8
native_fault_snapshot: times 22 dq 0
%endmacro
WDATA_DEFER WDATA_native_fault
