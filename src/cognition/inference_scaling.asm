;; MODULE cognition/inference_scaling
;; LAYER 6
;; EXPORTS cog_matmul, cog_scale_command, cog_scale_measuring
;; IMPORTS core/smp, core/time, core/lib/sha256, cognition/gpt2_engine, svc/command
;; CAPS
;; OWNER saga:cognition
;; CONTEXT: bsp_only (orchestration; arithmetic tiles run on the scheduler's CPUs)
; MODELRUN SCALE single|parallel <16 lowercase hex nonce>
; MODELRUN SCALE CPU <dense cpu> <same nonce> (immutable completed counters)
; Same admitted model, fixed reference prompt, all 50257 final logits hashed.
; No model/readiness/policy/authority changes. One BSP request owns the persistent
; activations; only disjoint projection columns execute concurrently. A late AP
; pins the entire working set until the maintained lane reports retirement.

; Same ABI as simd_matmul; this engine's M5 projections are vector @ matrix.
cog_matmul:
    cmp ecx, 1
    jne .bad
    sub rsp, 40
    mov [rsp], rdx                       ; C
    mov [rsp + 8], rdi                   ; A
    mov [rsp + 16], rsi                  ; B
    mov [rsp + 24], r8                   ; N (callers write R8D)
    mov [rsp + 32], r9                   ; K
    mov edi, [rel cog_compute_parallel]
    mov rsi, rsp
    call smp_matmul
    lea rsp, [rsp + 40]                  ; retain the join's CF
    ret
.bad:
    stc
    ret

; Match an immutable prefix including its final space. No read beyond the first
; mismatching/NUL byte. RDI=text, RSI=prefix -> RAX=remaining text or 0.
cog_scale_prefix:
    xor ecx, ecx
.loop:
    mov al, [rsi + rcx]
    test al, al
    jz .yes
    cmp al, [rdi + rcx]
    jne .no
    inc ecx
    jmp .loop
.yes:
    lea rax, [rdi + rcx]
    ret
.no:
    xor eax, eax
    ret

; RSI points to exactly 16 lowercase hex digits followed by NUL -> EAX 1/0.
cog_scale_nonce_valid:
    xor ecx, ecx
.loop:
    mov al, [rsi + rcx]
    cmp al, '0'
    jb .no
    cmp al, '9'
    jbe .next
    cmp al, 'a'
    jb .no
    cmp al, 'f'
    ja .no
.next:
    inc ecx
    cmp ecx, 16
    jb .loop
    cmp byte [rsi + 16], 0
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

cog_scale_command:
    call cmd_handler_prologue
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r13, rsi                        ; response
    mov r14, rdx                        ; text after SCALE
    call cog_out_reset
    mov rdi, r14
    lea rsi, [rel cog_scale_cpu_prefix]
    call cog_scale_prefix
    test rax, rax
    jnz .cpu
    mov rdi, r14
    lea rsi, [rel cog_scale_single_prefix]
    call cog_scale_prefix
    xor r12d, r12d
    test rax, rax
    jnz .run
    mov rdi, r14
    lea rsi, [rel cog_scale_parallel_prefix]
    call cog_scale_prefix
    mov r12d, 1
    test rax, rax
    jz .refused
.run:
    mov r14, rax
    mov rsi, rax
    call cog_scale_nonce_valid
    test eax, eax
    jz .refused
    ; Check before touching tokens, result buffers, counters or activations.
    call smp_par_for_retired
    test eax, eax
    jz .retiring
    cmp byte [rel cog_model_present], 1
    jne .unavailable
    mov byte [rel cog_scale_complete], 0
    mov rsi, r14
    lea rdi, [rel cog_scale_nonce]
    mov ecx, 17
    cld
    rep movsb
    mov [rel cog_scale_mode], r12d
    xor ebx, ebx
.before:
    lea rax, [rel cpu_pf_matmul_units]
    mov rdx, [rax + rbx*8]
    lea rax, [rel cog_scale_units]
    mov [rax + rbx*8], rdx
    lea rax, [rel cpu_pf_busy_tsc]
    mov rdx, [rax + rbx*8]
    lea rax, [rel cog_scale_ticks]
    mov [rax + rbx*8], rdx
    inc ebx
    cmp ebx, MAXCORE
    jb .before
    call time_monotonic_now_us
    mov r15, rax
    mov [rel cog_compute_parallel], r12d
    mov byte [rel cog_scale_measuring], 1
    call cog_run_forward
    mov ebp, eax
    mov byte [rel cog_scale_measuring], 0
    mov dword [rel cog_compute_parallel], 1
    call time_monotonic_now_us
    cmp rax, r15
    jb .failed
    sub rax, r15
    mov [rel cog_scale_elapsed], rax
    cmp ebp, COG_REF_ARGMAX
    jne .failed                         ; timeout never hashes or publishes buffers
    xor ebx, ebx
    xor r12d, r12d
.after:
    lea rax, [rel cpu_pf_matmul_units]
    mov rdx, [rax + rbx*8]
    lea rax, [rel cog_scale_units]
    sub rdx, [rax + rbx*8]
    jc .failed
    mov [rax + rbx*8], rdx
    add r12, rdx
    jc .failed
    lea rax, [rel cpu_pf_busy_tsc]
    mov rdx, [rax + rbx*8]
    lea rax, [rel cog_scale_ticks]
    sub rdx, [rax + rbx*8]
    jc .failed
    mov [rax + rbx*8], rdx
    inc ebx
    cmp ebx, MAXCORE
    jb .after
    ; Five prompt positions, six layers, four real projection shapes each.
    cmp r12, 5*6*(768*2304 + 768*768 + 768*3072 + 3072*768)
    jne .failed
    mov [rel cog_scale_total], r12
    lea rdi, [rel cog_scale_digest]
    mov rsi, [rel m5_logits]
    mov edx, 50257*4
    call sha256_hash
    test rax, rax
    jnz .failed
    xor ecx, ecx
.hex:
    lea rdx, [rel cog_scale_digest]
    movzx eax, byte [rdx + rcx]
    mov edi, eax
    shr edi, 4
    and eax, 15
    lea rdx, [rel cog_scale_hex_digits]
    mov dil, [rdx + rdi]
    mov al, [rdx + rax]
    lea rdx, [rel cog_scale_digest_hex]
    mov [rdx + rcx*2], dil
    mov [rdx + rcx*2 + 1], al
    inc ecx
    cmp ecx, 32
    jb .hex
    mov byte [rel cog_scale_complete], 1
    lea rdi, [rel cog_scale_header]
    call cog_put_str
    lea rdi, [rel cog_scale_nonce]
    call cog_put_str
    lea rdi, [rel cog_scale_mode_field]
    call cog_put_str
    lea rdi, [rel cog_scale_single_name]
    cmp dword [rel cog_scale_mode], 0
    je .mode
    lea rdi, [rel cog_scale_parallel_name]
.mode:
    call cog_put_str
    lea rdi, [rel cog_scale_complete_field]
    call cog_put_str
    mov edi, COG_REF_ARGMAX
    call cog_put_dec
    lea rdi, [rel cog_scale_units_field]
    call cog_put_str
    mov rdi, [rel cog_scale_total]
    call cog_put_dec
    lea rdi, [rel cog_scale_elapsed_field]
    call cog_put_str
    mov rdi, [rel cog_scale_elapsed]
    call cog_put_dec
    lea rdi, [rel cog_scale_digest_field]
    call cog_put_str
    lea rdi, [rel cog_scale_digest_hex]
    call cog_put_str
    lea rdi, [rel cog_scale_cpus_field]
    call cog_put_str
    mov edi, MAXCORE
    call cog_put_dec
    jmp .ready
.cpu:
    xor ebx, ebx
    xor ecx, ecx
.digits:
    movzx edx, byte [rax]
    sub edx, '0'
    cmp edx, 9
    ja .end_digits
    imul ebx, 10
    add ebx, edx
    inc rax
    inc ecx
    cmp ecx, 2
    jbe .digits
    jmp .refused
.end_digits:
    test ecx, ecx
    jz .refused
    cmp byte [rax], ' '
    jne .refused
    cmp ebx, MAXCORE
    jae .refused
    lea r14, [rax + 1]
    mov rsi, r14
    call cog_scale_nonce_valid
    test eax, eax
    jz .refused
    cmp byte [rel cog_scale_complete], 1
    jne .stale
    xor ecx, ecx
.same_nonce:
    lea rdx, [rel cog_scale_nonce]
    mov al, [r14 + rcx]
    cmp al, [rdx + rcx]
    jne .stale
    inc ecx
    cmp ecx, 16
    jb .same_nonce
    lea rdi, [rel cog_scale_cpu_header]
    call cog_put_str
    mov rdi, r14
    call cog_put_str
    lea rdi, [rel cog_scale_cpu_field]
    call cog_put_str
    mov edi, ebx
    call cog_put_dec
    lea rdi, [rel cog_scale_units_field]
    call cog_put_str
    lea rax, [rel cog_scale_units]
    mov rdi, [rax + rbx*8]
    call cog_put_dec
    lea rdi, [rel cog_scale_ticks_field]
    call cog_put_str
    lea rax, [rel cog_scale_ticks]
    mov rdi, [rax + rbx*8]
    call cog_put_dec
    jmp .ready
.refused:
    lea rdi, [rel cog_scale_refused]
    jmp .status
.unavailable:
    mov byte [rel cog_scale_complete], 0
    lea rdi, [rel cog_scale_unavailable]
    jmp .status
.retiring:
    mov byte [rel cog_scale_complete], 0
    lea rdi, [rel cog_scale_retiring]
    jmp .status
.failed:
    mov byte [rel cog_scale_complete], 0
    lea rdi, [rel cog_scale_failed]
    jmp .status
.stale:
    lea rdi, [rel cog_scale_stale]
.status:
    call cog_put_str
.ready:
    ; COMPLETE logical replies are one ASCII line. Delimit our staged record
    ; from UDP's following earned markers without adding an interior newline.
    lea rdi, [rel cog_scale_record_end]
    call cog_put_str
    mov byte [rel cog_out_ready], 1
    mov qword [r13 + RSP_CODE], CMDE_OK
    mov qword [r13 + RSP_VAL], 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_cognition_inference_scaling 0
align 8
cog_compute_parallel: dd 1
cog_scale_mode: dd 0
cog_scale_complete: db 0
cog_scale_measuring: db 0
cog_scale_nonce: times 17 db 0
align 8
cog_scale_elapsed: dq 0
cog_scale_total: dq 0
cog_scale_units: times MAXCORE dq 0
cog_scale_ticks: times MAXCORE dq 0
cog_scale_digest: times 32 db 0
cog_scale_digest_hex: times 65 db 0
%endmacro
WDATA_DEFER WDATA_cognition_inference_scaling

cog_scale_hex_digits: db '0123456789abcdef'
cog_scale_record_end: db ' MODEL_SCALE_END',0
cog_scale_cpu_prefix: db 'CPU ',0
cog_scale_single_prefix: db 'single ',0
cog_scale_parallel_prefix: db 'parallel ',0
cog_scale_single_name: db 'single',0
cog_scale_parallel_name: db 'parallel',0
cog_scale_header: db ' MODEL_SCALE rev=1 nonce=',0
cog_scale_cpu_header: db ' MODEL_SCALE_CPU rev=1 nonce=',0
cog_scale_mode_field: db ' mode=',0
cog_scale_complete_field: db ' state=complete token=',0
cog_scale_units_field: db ' units=',0
cog_scale_elapsed_field: db ' elapsed_us=',0
cog_scale_digest_field: db ' sha256=',0
cog_scale_cpus_field: db ' cpus=',0
cog_scale_cpu_field: db ' cpu=',0
cog_scale_ticks_field: db ' ticks=',0
cog_scale_refused: db ' MODEL_SCALE state=refused',0
cog_scale_unavailable: db ' MODEL_SCALE state=unavailable',0
cog_scale_retiring: db ' MODEL_SCALE state=retiring',0
cog_scale_failed: db ' MODEL_SCALE state=failed',0
cog_scale_stale: db ' MODEL_SCALE state=stale',0
