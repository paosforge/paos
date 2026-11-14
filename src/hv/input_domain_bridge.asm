;; MODULE hv/input_domain_bridge
;; LAYER 5
;; EXPORTS pinb_request, pinb_poll, pinb_check
;; IMPORTS hv/input_owner, hv/input_domain, hv/input_domain_consumer, core/time
;; CAPS extension
;; OWNER saga:input
; Checked PIN1 -> native DOMAIN composition. Inactive, no GUI/HUMAN producer.
; Every entry shares the VM owner's serialized stopped-vCPU no-yield boundary.
; After hv_pin_bind, pinc_bind must succeed BEFORE the first request. Use this
; bridge as the ONLY request/response consumer, hv_pin_pump for queue service.
; No guest entry, transport, polling loop, extra deadline, or physical authority.

; Native admission helper: exact VM + consumer binding check. Stale callers never stop an owner.
pinb_check:
    push rbx
    mov rbx,rdi
    call hv_pin_check
    test eax,eax
    jnz .out
    cmp rbx,[rel pinc_gen]
    jne .stale
    cmp dword [rel pinc_state],PINC_FAULT
    je .fault
    cmp dword [rel pinc_state],PINC_LIVE
    jne .busy
    mov rax,[rel pind_epoch]
    cmp rax,[rel pinc_epoch]
    jne .stale
    mov rax,[rel pind_session]
    cmp rax,[rel pinc_session]
    jne .stale
    xor eax,eax
    jmp .out
.fault:
    mov rdi,rbx
    call hv_pin_stop              ; retain exact owner until actual CPU-off
    mov eax,-5
    jmp .out
.stale: mov eax,-116
    jmp .out
.busy: mov eax,-16
.out:
    pop rbx
    ret

; RDI=gen, ESI=op(1 POLL /2 protocol STOP), EDX=source(1 KEY/2 PTR/0 STOP).
; A complete QUIET or CANCEL is a response too. Never skip a consumer drain.
; An outstanding or stolen reply cannot cause a new request/sequence/send here.
pinb_request:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12d,esi
    mov r13d,edx
    call pinb_check
    test eax,eax
    jnz .out
    mov rax,[rel pinc_sequence]
    cmp rax,[rel pind_sequence]
    jne .busy
    mov rdi,rbx
    mov esi,r12d
    mov edx,r13d
    call hv_pin_request
    jmp .out
.busy: mov eax,-16
.out:
    pop r13
    pop r12
    pop rbx
    ret

; RDI=gen, RSI=stable disjoint native output, RDX=capacity(u64).
; ->320 complete PDC1 /0 no complete reply /negative refusal. No caller time.
; Invalid output cannot consume READY or overwrite VM owner custody. Client and
; consumer storage exclusion and exact original deadline stay in pinc_poll.
pinb_poll:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    test rsi,rsi
    jz .invalid
    cmp rdx,PINC_SIZE
    jb .invalid
    mov rax,rsi
    add rax,PINC_SIZE
    jc .invalid
    lea rcx,[rel hvp_storage_end]
    cmp rsi,rcx
    jae .span_ok
    lea rcx,[rel hvp_storage]
    cmp rax,rcx
    ja .invalid
.span_ok:
    call time_monotonic_now_us
    xor edx,edx
    mov ecx,1000
    div rcx
    mov r14,rax
    mov rdi,rbx
    call pinb_check               ; same stopped-vCPU boundary, no yield
    test eax,eax
    jnz .out
    mov rdi,rbx
    mov rsi,r14
    mov rdx,r12
    mov rcx,r13
    call pinc_poll               ; alternative to hv_pin_take, not both
    mov r15d,eax
    cmp dword [rel pinc_state],PINC_FAULT
    je .fault
    cmp dword [rel pind_state],PIND_FAULT
    jne .out
.fault:
    mov rdi,rbx
    call hv_pin_stop              ; no retry, no protocol-STOP retirement
    mov eax,r15d
    jmp .out
.invalid: mov eax,-22
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
