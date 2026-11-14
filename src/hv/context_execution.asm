;; MODULE hv/context_execution
;; LAYER 5
;; EXPORTS context_domain_complete, context_ansi_enter, context_ansi_exit, context_vt_enter, context_vt_exit, context_execution_render, cex_copy
;; IMPORTS hv/vmx, hv/driver_domain, hv/vm_profile, core/smp
;; CAPS
;; OWNER saga:hv
; X5 observations only. Never selects, weakens or performs a mitigation.
; Driver rows require a completed real Linux hardware pair AND the current
; native START/profile join. Retain independently of later unrelated guests.
; Parser counters observe actual native feed call/return, not security efficacy.
; Portable VT code stays unmodified. No pointer, payload or private token emitted.
CEX_ID_BYTES equ 384
CEX_PAIR_BYTES equ 448
CEX_PARSER_BYTES equ 192
CEX_DOMAIN_SLOT equ 840             ; sequence8 + identity384 + BEX448
CEX_PARSER_SLOT equ 104             ; sequence8 + observation96
%macro CEX_SAVE 0
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
%endmacro
%macro CEX_RESTORE 0
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    ret
%endmacro

; RDI=completed redacted BEX448 (after its even publication). Called only by
; the successful hardware-pair recorder. All caller GPRs/flags preserved.
context_domain_complete:
    CEX_SAVE
    mov r12,rdi
    cmp qword [r12],1
    jne .out
    cmp qword [r12+8],1
    jne .out
    cmp qword [r12+48],2             ; actual Linux landing, not HLT/AP/appVM
    jne .out
    mov r13,[r12+16]
    cmp r13,SMP_CPU_CAPACITY
    jae .out
    ; Driver START owns the shared Linux loader/profile until retirement.
    mov eax,[rel nd_state]
    cmp eax,1
    je .state_ok
    cmp eax,2
    jne .out
.state_ok:
    mov r14,[rel nd_generation]
    test r14,r14
    jz .out
    mov eax,[rel hv_linux_start_gen]
    cmp rax,r14
    jne .out
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,r14
    jne .out
    mov eax,[rel vm_profile_gen]
    cmp rax,r14
    jne .out
    mov r15,[rel nd_profile]
    test r15,r15
    jz .out
    cmp r15,[rel vm_profile_active]
    jne .out
    imul ebx,r13d,CEX_DOMAIN_SLOT
    lea rax,[rel cex_domain_slots]
    add rbx,rax
    inc qword [rbx]                  ; odd, one pinned CPU writer
    lea rdi,[rbx+8]
    xor eax,eax
    mov ecx,CEX_ID_BYTES/8
    cld
    rep stosq
    mov qword [rbx+8],1
    mov qword [rbx+16],1
    mov [rbx+24],r13
    mov rax,[r12+24]
    mov [rbx+32],rax                 ; full actual receipt APIC
    mov rax,[r12+32]
    mov [rbx+40],rax                 ; exact BEX completion sequence
    mov [rbx+48],r14                 ; native domain START
    mov [rbx+56],r14                 ; consumed Linux START
    mov [rbx+64],r14                 ; native profile generation
    mov eax,[rel nd_devices]
    mov [rbx+72],rax
    mov eax,[rel nd_bdf]
    mov [rbx+80],rax
    lea rdi,[rbx+88]
    lea rsi,[rel nd_nonce]
    mov ecx,16
    rep movsb
    mov rsi,r15
    mov ecx,35                      ; native immutable profile280, no pointer
    rep movsq
    lea rdi,[rbx+8+CEX_ID_BYTES]
    mov rsi,r12
    mov ecx,CEX_PAIR_BYTES/8
    rep movsq
    inc qword [rbx]                  ; even publication
.out:
    CEX_RESTORE

context_ansi_enter:                  ; original RSI=bounded input length
    CEX_SAVE
    mov r11,rsi
    xor r10d,r10d
    jmp cex_parser_enter
context_vt_enter:                    ; original EDX=bounded input length
    CEX_SAVE
    mov r11d,edx
    mov r10d,1
cex_parser_enter:
    call smp_current_logical
    cmp eax,SMP_CPU_CAPACITY
    jae .out
    mov r12d,eax
    shl eax,1
    add eax,r10d
    imul ebx,eax,CEX_PARSER_SLOT
    lea rax,[rel cex_parser_slots]
    add rbx,rax
    call smp_lapic_read_id
    mov r13d,eax
    call cex_parser_lock
    jnz .out
    mov qword [rbx+8],1
    mov qword [rbx+16],1
    mov [rbx+24],r12
    mov [rbx+32],r13
    lea eax,[r10+1]
    mov [rbx+40],rax
    inc qword [rbx+48]              ; invocation ordinal, no data/pointer
    mov [rbx+64],r11
    cmp qword [rbx+96],0
    je .not_nested
    or qword [rbx+88],2             ; reentrancy is visible, never efficacy
.not_nested:
    inc qword [rbx+96]
    inc qword [rbx]
.out:
    CEX_RESTORE
context_ansi_exit:
    CEX_SAVE
    xor r10d,r10d
    jmp cex_parser_exit
context_vt_exit:
    CEX_SAVE
    mov r10d,1
cex_parser_exit:
    call smp_current_logical
    cmp eax,SMP_CPU_CAPACITY
    jae .out
    shl eax,1
    add eax,r10d
    imul ebx,eax,CEX_PARSER_SLOT
    lea rax,[rel cex_parser_slots]
    add rbx,rax
    call cex_parser_lock
    jnz .out
    cmp qword [rbx+96],0
    je .unpaired
    inc qword [rbx+56]
    dec qword [rbx+96]
    cmp qword [rbx+96],0
    jne .published
    inc qword [rbx+72]
    jmp .published
.unpaired:
    cmp qword [rbx+16],0
    je .published                  ; dropped entry is absence, not a forged row
    or qword [rbx+88],1
.published:
    inc qword [rbx]
.out:
    CEX_RESTORE

; Nonblocking writer acquisition. A timer-preempted observation never allows a
; second writer to make its sequence even. Contention drops telemetry only.
cex_parser_lock:
    mov rax,[rbx]
    test al,1
    jnz .out
    lea rdx,[rax+1]
    lock cmpxchg [rbx],rdx
    jnz .out
    xor eax,eax
.out:
    ret

; Bounded seqlock copy: RSI=sequence+data,RDI=out,ECX=qwords.
; Concurrent writer after three attempts gives zeros, not a torn positive.
cex_copy:
    mov r8,rdi
    mov r9,rsi
    mov r10d,ecx
    mov r11d,3
.retry:
    mov rax,[r9]
    test al,1
    jnz .again
    lea rsi,[r9+8]
    mov rdi,r8
    mov ecx,r10d
    cld
    rep movsq
    lfence
    cmp rax,[r9]
    je .out
.again:
    dec r11d
    jnz .retry
    mov rdi,r8
    xor eax,eax
    mov ecx,r10d
    rep stosq
.out:
    ret

; EDI=page0..5: page%2 dense CPU, page/2 identity/pair/parsers.
; Each complete native output <1024 incl source census word (parser pages).
context_execution_render:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12d,edi
    mov r13d,edi
    and r13d,1
    shr edi,1
    mov r14d,edi
    ; Identity page seals the matching receipt for the subsequent pair page.
    ; BSP command serialization owns these two reader caches; live VM execution
    ; never pauses and cannot relabel an older identity with a newer receipt.
    imul eax,r13d,CEX_ID_BYTES+CEX_PAIR_BYTES
    lea rbx,[rel cex_read_cache]
    add rbx,rax
    cmp r14d,1
    je .pair_page
    cmp r14d,2
    je .parser_page
    imul eax,r13d,CEX_DOMAIN_SLOT
    lea rsi,[rel cex_domain_slots]
    add rsi,rax
    mov rdi,rbx
    mov ecx,(CEX_ID_BYTES+CEX_PAIR_BYTES)/8
    call cex_copy
    mov r15d,CEX_ID_BYTES
    jmp .wire
.pair_page:
    add rbx,CEX_ID_BYTES
    mov r15d,CEX_PAIR_BYTES
    jmp .wire
.parser_page:
    lea rbx,[rel cex_snapshot]
    imul eax,r13d,2*CEX_PARSER_SLOT
    lea rsi,[rel cex_parser_slots]
    add rsi,rax
    mov rdi,rbx
    mov ecx,12
    call cex_copy
    imul eax,r13d,2*CEX_PARSER_SLOT
    lea rsi,[rel cex_parser_slots+CEX_PARSER_SLOT]
    add rsi,rax
    lea rdi,[rbx+96]
    mov ecx,12
    call cex_copy
    mov r15d,CEX_PARSER_BYTES
.wire:
    call hv_out_reset
    lea rdi,[rel str_cex]
    call hv_out_str
    mov eax,r12d
    call hv_out_dec
    lea rdi,[rel str_cex_data]
    call hv_out_str
    mov rdi,rbx
    mov esi,r15d
    call vp_out_hex
    cmp r14d,2
    jne .end
    lea rdi,[rel str_cex_census]
    call hv_out_str
.end:
    lea rdi,[rel str_cex_end]
    call hv_out_str
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
str_cex: db ' CTX_EXEC v=1 page=',0
str_cex_data: db ' data=',0
str_cex_end: db ' end=1',0
; Hash pins the reviewed decision list, not execution efficacy.
str_cex_census: db ' census=4e9ad1534e4020f56878a800f2656d2c4a61ff17e7a89e0ebcabeb6d9bcaf429',0
%macro WDATA_hv_context_execution_bss 0
alignb 64
cex_domain_slots: resb CEX_DOMAIN_SLOT*SMP_CPU_CAPACITY
cex_parser_slots: resb 2*CEX_PARSER_SLOT*SMP_CPU_CAPACITY
cex_read_cache: resb 2*(CEX_ID_BYTES+CEX_PAIR_BYTES)
cex_snapshot: resb CEX_PARSER_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_hv_context_execution_bss
