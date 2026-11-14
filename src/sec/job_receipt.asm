;; MODULE sec/job_receipt
;; LAYER 5
;; EXPORTS cmd_verb_keygen, job_receipt_selftest, job_receipt_declare, cmd_verb_jobrun, cmd_verb_jobpub, job_m_identity, job_m_receipt, job_m_pubkey, job_out_ready, job_out_buf
;; IMPORTS core/build_id, boot/header, core/sched, core/time, core/capability, core/lock, core/lib/fmt, core/lib/mem, core/lib/str, sec/principal, sec/node_identity, svc/command, boot/serial
;; CAPS
;; OWNER saga:sec
;; LOCK: job_receipt_lock PROTECTS job_live, job_kat, job_body_buf, job_signature, job_out_buf, job_work_mem
; ============================================================================
; Contract 1055 — the portable JOB + identity-signed metering receipt seam.
;
; JOBRUN never invokes compute directly.  It fills the canonical sched_job
; descriptor with {owner identity, owner grant, cap scope, declared resources,
; result channel, nonce, entry, meter hook} and submits it through job_submit.
; The scheduler rechecks the current principal registry plus caller ceiling
; and active caller scope before proving cap_scope >=
; required_cap, narrows cap_current_mask, executes via its replaceable dispatch
; hook (local at scale 1), measures TSC edges, and invokes our meter hook.
;
; The exact canonical body signed by the active node Ed25519 identity is:
;   v=1,job_id=N,owner=N,cap_scope=NAME,cpu_us=N,mem=N,energy_est=N,nonce=TOKEN
; TOKEN is 1..95 printable ASCII bytes (0x21..0x7e), except comma and equals.
; The descriptor extent is authoritative; no NUL terminator is required there.
; It contains no spaces so UDP exposes it unambiguously as BODY=<body> followed
; by SIG=<128 hex>.  JOBPUB publishes the matching 32-byte public key.
; ============================================================================

JOB_SCOPE_MAX        equ 24
JOB_NONCE_MAX        equ 96               ; fits SJOB_NONCE_COPY_BYTES custody
JOB_BODY_MAX         equ 512 ; bounded by sched_job.receipt_storage
JOB_OUT_MAX          equ 512
JOB_ENERGY_NJ_PER_US equ 15000             ; v1 estimate: 15 W, explicitly estimated
JOB_DECL_CPU_US      equ 1000
JOB_DECL_MEM         equ 4096
JOB_DECL_ENERGY      equ (JOB_DECL_CPU_US * JOB_ENERGY_NJ_PER_US)

; ---------------------------------------------------------------------------
; Receipt construction and metering hook
; ---------------------------------------------------------------------------
job_body_reset:
    lea  rax, [rel job_body_buf]
    mov  [rel job_body_cur], rax
    mov  byte [rel job_body_buf], 0
    mov  byte [rel job_body_error], 0
    ret

; Exact extent validation, shared by live admission and the signing boundary.
; RDI=bytes, RSI=len. Never inspect a terminator outside the declared extent.
job_nonce_validate:
    test rdi, rdi
    jz   .fail
    test rsi, rsi
    jz   .fail
    cmp  rsi, JOB_NONCE_MAX - 1
    ja   .fail
    mov  rax, rdi
    add  rax, rsi
    jc   .fail                            ; reject wrapping extent before read
    xor  ecx, ecx
.byte:
    movzx eax, byte [rdi + rcx]
    cmp  al, 0x21
    jb   .fail
    cmp  al, 0x7e
    ja   .fail
    cmp  al, ','
    je   .fail
    cmp  al, '='
    je   .fail
    inc  rcx
    cmp  rcx, rsi
    jb   .byte
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

; RDI=source, RSI=extent, RDX=&cursor, RCX=buffer, R8=capacity.
; Preflight the entire append including its NUL before the first write.
job_buffer_append:
    mov  r9, [rdx]
    cmp  r9, rcx
    jb   .fail
    sub  r9, rcx
    cmp  r9, r8
    jae  .fail
    sub  r8, r9
    dec  r8
    cmp  rsi, r8
    ja   .fail
    mov  r9, [rdx]
    xor  r10d, r10d
.copy:
    cmp  r10, rsi
    jae  .done
    mov  al, [rdi + r10]
    mov  [r9 + r10], al
    inc  r10
    jmp  .copy
.done:
    add  r9, rsi
    mov  byte [r9], 0
    mov  [rdx], r9
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

job_body_put_bytes:                         ; RDI=bytes, RSI=extent
    cmp  byte [rel job_body_error], 0
    jne  .fail
    lea  rdx, [rel job_body_cur]
    lea  rcx, [rel job_body_buf]
    mov  r8d, JOB_BODY_MAX
    sub  rsp, 8
    call job_buffer_append
    add  rsp, 8
    test eax, eax
    jz   .out
.fail:
    mov  byte [rel job_body_error], 1
    mov  eax, -1
.out:
    ret

job_body_put_str:                           ; RDI=internal bounded cstr
    xor  esi, esi
.scan:
    cmp  rsi, JOB_BODY_MAX
    jae  .fail
    cmp  byte [rdi + rsi], 0
    je   job_body_put_bytes
    inc  rsi
    jmp  .scan
.fail:
    mov  byte [rel job_body_error], 1
    mov  eax, -1
    ret

job_body_put_dec:                           ; RDI=u64; 20 digits + NUL
    sub  rsp, 8
    lea  rsi, [rel job_dec_buf]
    call fmt_dec
    lea  rdi, [rel job_dec_buf]
    mov  rsi, rax
    call job_body_put_bytes
    add  rsp, 8
    ret

; Retire all artifact authority, including a signature from an earlier JOB.
; RDI=descriptor; preserves the descriptor and all callee-saved registers.
job_artifact_clear:
    mov  qword [rdi + sched_job.receipt_len], 0
    mov  qword [rdi + sched_job.receipt_body], 0
    mov  qword [rdi + sched_job.signature], 0
    mov  byte [rel job_out_ready], 0
    mov  byte [rel job_out_buf], 0
    lea  rax, [rel job_out_buf]
    mov  [rel job_out_cur], rax
    mov  byte [rel job_out_error], 0
    mov  byte [rel job_body_buf], 0
    lea  rax, [rel job_body_buf]
    mov  [rel job_body_cur], rax
    mov  byte [rel job_body_error], 0
    xor  eax, eax
    lea  rdx, [rel job_signature]
    mov  ecx, 8
.wipe:
    mov  [rdx], rax
    add  rdx, 8
    dec  ecx
    jnz  .wipe
    mov  byte [rdi + sched_job.receipt_storage], 0
    lea  rdx, [rdi + sched_job.signature_storage]
    mov  ecx, 8
.wipe_owned:
    dec  ecx
    mov  [rdx + rcx*8], rax
    jnz  .wipe_owned
    ret

; job_receipt_meter(RDI=sched_job*) -> RAX=0/-1.  Called only by job_submit.
job_receipt_meter:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    call job_artifact_clear
    mov  rdi, [r12 + sched_job.nonce_ptr]
    mov  rsi, [r12 + sched_job.nonce_len]
    call job_nonce_validate
    test eax, eax
    jnz  .fail
    ; Scope text comes from the supported capability identity, not a pointer.
    mov  rax, [r12 + sched_job.cap_scope]
    cmp  rax, PMCAP_COMPUTE
    je   .scope_valid
    cmp  rax, PMCAP_BLOCK_WRITE
    jne  .fail
.scope_valid:

    ; cpu_us = (end_tsc - start_tsc) * 1000 / tsc_khz.  Bare metal has a
    ; calibrated invariant TSC; an uncalibrated environment degrades honestly
    ; to zero usage rather than inventing a duration.
    mov  rax, [r12 + sched_job.tsc_end]
    sub  rax, [r12 + sched_job.tsc_start]
    jc   .fail                         ; regressed TSC cannot be charged
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jz   .cpu_zero
    mov  rbx, 1000
    mul  rbx
    cmp  rdx, rcx                       ; DIV needs high half < divisor
    jae  .fail
    div  rcx
    jmp  .cpu_set
.cpu_zero:
    xor  eax, eax
.cpu_set:
    mov  r13, rax                       ; publish metrics only after both fit
    mov  rbx, JOB_ENERGY_NJ_PER_US
    mul  rbx
    test rdx, rdx
    jnz  .fail                         ; estimated energy must fit u64
    mov  [r12 + sched_job.cpu_us], r13
    mov  [r12 + sched_job.energy_est], rax

    call job_body_reset
    lea  rdi, [rel str_job_body_v]
    call job_body_put_str
    mov  rdi, [r12 + sched_job.id]
    call job_body_put_dec
    lea  rdi, [rel str_job_body_owner]
    call job_body_put_str
    mov  rdi, [r12 + sched_job.owner]
    call job_body_put_dec
    lea  rdi, [rel str_job_body_scope]
    call job_body_put_str
    lea  rdi, [rel str_cap_compute]
    cmp  qword [r12 + sched_job.cap_scope], PMCAP_COMPUTE
    je   .scope_text
    lea  rdi, [rel str_cap_block_write]
.scope_text:
    call job_body_put_str
    lea  rdi, [rel str_job_body_cpu]
    call job_body_put_str
    mov  rdi, [r12 + sched_job.cpu_us]
    call job_body_put_dec
    lea  rdi, [rel str_job_body_mem]
    call job_body_put_str
    mov  rdi, [r12 + sched_job.mem_used]
    call job_body_put_dec
    lea  rdi, [rel str_job_body_energy]
    call job_body_put_str
    mov  rdi, [r12 + sched_job.energy_est]
    call job_body_put_dec
    lea  rdi, [rel str_job_body_nonce]
    call job_body_put_str
    mov  rdi, [r12 + sched_job.nonce_ptr]
    mov  rsi, [r12 + sched_job.nonce_len]
    call job_body_put_bytes
    cmp  byte [rel job_body_error], 0
    jne  .fail

    mov  r13, [rel job_body_cur]
    lea  rax, [rel job_body_buf]
    sub  r13, rax
    cmp  r13, JOB_BODY_MAX - 1
    jae  .fail
    ; Freeze the bounded body in descriptor-owned storage before entering the
    ; signer. Its callback may submit another JOB using the shared formatter.
    lea  rdi, [r12 + sched_job.receipt_storage]
    lea  rsi, [rel job_body_buf]
    xor  ecx, ecx
.freeze_body:
    mov  al, [rsi + rcx]
    mov  [rdi + rcx], al
    inc  rcx
    cmp  rcx, r13
    jbe  .freeze_body                     ; include the existing bounded NUL
    ; Real detached Ed25519 signature through the authenticated node identity.
    lea  rdi, [r12 + sched_job.receipt_storage]
    mov  rsi, r13
    lea  rdx, [r12 + sched_job.signature_storage]
    mov  ecx, 64
    call node_identity_sign_active
    test eax, eax
    jnz  .fail
    lea  rax, [r12 + sched_job.receipt_storage]
    mov  [r12 + sched_job.receipt_body], rax
    mov  [r12 + sched_job.receipt_len], r13
    lea  rax, [r12 + sched_job.signature_storage]
    mov  [r12 + sched_job.signature], rax

    xor  eax, eax
    jmp  .out
.fail:
    mov  rdi, r12
    call job_artifact_clear
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bounded local workload.  The caller nonce seeds real arithmetic, then the JOB
; touches every byte of its fixed 4-KiB work buffer before reporting mem_used.
job_receipt_compute:
    mov  r8, [rdi + sched_job.nonce_ptr]
    mov  rcx, [rdi + sched_job.nonce_len]
    mov  rax, 0xcbf29ce484222325
    mov  r9, 0x100000001b3
    xor  edx, edx
.nonce:
    cmp  rdx, rcx
    jae  .mix_start
    movzx r10d, byte [r8 + rdx]
    xor  rax, r10
    imul rax, r9
    inc  rdx
    jmp  .nonce
.mix_start:
    lea  r11, [rel job_work_mem]
    xor  edx, edx
.touch:
    mov  [r11 + rdx], al
    xor  rax, rdx
    rol  rax, 7
    imul rax, r9
    inc  edx
    cmp  edx, JOB_DECL_MEM
    jb   .touch
    mov  ecx, 4096
.mix:
    xor  rax, rcx
    rol  rax, 7
    imul rax, r9
    dec  ecx
    jnz  .mix
    mov  qword [rdi + sched_job.mem_used], JOB_DECL_MEM
    ret

; ---------------------------------------------------------------------------
; JOB preparation and result channels
; ---------------------------------------------------------------------------
; job_prepare(RDI=job, RSI=scope_name, RDX=scope_bit, RCX=nonce,
;             R8=nonce_len, R9=result_channel) -> initialized descriptor.
job_prepare:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push r9
    sub  rsp, 8                            ; keep SysV call sites 16-byte aligned
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8
    lea  rdi, [rel principal_capabilities]
    call job_bind_owner_lookup             ; L5 supplies the real locked registry
    test eax, eax
    jnz  .binding_failed
    mov  rdi, r12
    xor  esi, esi
    mov  edx, sched_job_size
    call memset
    add  rsp, 8
    pop  r9
    mov  [r12 + sched_job.result_channel], r9
    call principal_current
    mov  [r12 + sched_job.owner], rax
    mov  rdi, rax
    call principal_capabilities
    mov  [r12 + sched_job.owner_caps], rax
    mov  [r12 + sched_job.cap_scope], r14
    mov  qword [r12 + sched_job.required_cap], PMCAP_COMPUTE
    mov  [r12 + sched_job.scope_name], r13
    mov  qword [r12 + sched_job.decl_cpu_us], JOB_DECL_CPU_US
    mov  qword [r12 + sched_job.decl_mem], JOB_DECL_MEM
    mov  qword [r12 + sched_job.decl_energy], JOB_DECL_ENERGY
    mov  [r12 + sched_job.nonce_ptr], r15
    mov  [r12 + sched_job.nonce_len], rbx
    lea  rax, [rel job_receipt_compute]
    mov  [r12 + sched_job.entry], rax
    lea  rax, [rel job_receipt_meter]
    mov  [r12 + sched_job.meter_hook], rax
    jmp  .out
.binding_failed:
    mov  rdi, r12
    xor  esi, esi
    mov  edx, sched_job_size
    call memset
    add  rsp, 8
    pop  r9
    mov  eax, -1                           ; existing submit rejects the empty job
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

job_receipt_test_deliver:
    inc  byte [rel job_test_delivered]
    xor  eax, eax
    ret

job_out_reset:
    lea  rax, [rel job_out_buf]
    mov  [rel job_out_cur], rax
    mov  byte [rel job_out_buf], 0
    mov  byte [rel job_out_ready], 0
    mov  byte [rel job_out_error], 0
    ret

job_out_put_bytes:                          ; RDI=bytes, RSI=extent
    cmp  byte [rel job_out_error], 0
    jne  .fail
    lea  rdx, [rel job_out_cur]
    lea  rcx, [rel job_out_buf]
    mov  r8d, JOB_OUT_MAX
    sub  rsp, 8
    call job_buffer_append
    add  rsp, 8
    test eax, eax
    jz   .out
.fail:
    mov  byte [rel job_out_error], 1
    mov  eax, -1
.out:
    ret

job_out_put_str:                            ; RDI=internal bounded cstr
    xor  esi, esi
.scan:
    cmp  rsi, JOB_OUT_MAX
    jae  .fail
    cmp  byte [rdi + rsi], 0
    je   job_out_put_bytes
    inc  rsi
    jmp  .scan
.fail:
    mov  byte [rel job_out_error], 1
    mov  eax, -1
    ret

job_out_put_hexbytes:                       ; RDI=bytes, RSI=len
    cmp  byte [rel job_out_error], 0
    jne  .fail
    cmp  rsi, (JOB_OUT_MAX - 1) / 2
    ja   .fail
    lea  rax, [rel job_out_buf]
    mov  r9, [rel job_out_cur]
    cmp  r9, rax
    jb   .fail
    sub  r9, rax
    cmp  r9, JOB_OUT_MAX
    jae  .fail
    mov  r8d, JOB_OUT_MAX - 1
    sub  r8, r9
    lea  rdx, [rsi + rsi]
    cmp  rdx, r8
    ja   .fail
    mov  r9, [rel job_out_cur]
    xor  ecx, ecx
.byte:
    cmp  rcx, rsi
    jae  .done
    movzx eax, byte [rdi + rcx]
    mov  edx, eax
    shr  eax, 4
    and  edx, 15
    lea  r8, [rel job_hex]
    mov  al, [r8 + rax]
    mov  [r9], al
    mov  al, [r8 + rdx]
    mov  [r9 + 1], al
    add  r9, 2
    inc  rcx
    jmp  .byte
.done:
    mov  byte [r9], 0
    mov  [rel job_out_cur], r9
    xor  eax, eax
    ret
.fail:
    mov  byte [rel job_out_error], 1
    mov  eax, -1
    ret

; Live result channel: stage the exact signed artifact for the UDP projection.
job_receipt_wire_deliver:
    push r12
    mov  r12, rdi
    call job_out_reset
    lea  rax, [r12 + sched_job.receipt_storage]
    cmp  [r12 + sched_job.receipt_body], rax
    jne  .fail
    lea  rax, [r12 + sched_job.signature_storage]
    cmp  [r12 + sched_job.signature], rax
    jne  .fail
    cmp  qword [r12 + sched_job.receipt_len], 0
    je   .fail
    cmp  qword [r12 + sched_job.receipt_len], JOB_BODY_MAX - 1
    jae  .fail
    lea  rdi, [rel str_job_body_prefix]
    call job_out_put_str
    mov  rdi, [r12 + sched_job.receipt_body]
    mov  rsi, [r12 + sched_job.receipt_len]
    call job_out_put_bytes
    lea  rdi, [rel str_job_sig_prefix]
    call job_out_put_str
    mov  rdi, [r12 + sched_job.signature]
    mov  esi, 64
    call job_out_put_hexbytes
    cmp  byte [rel job_out_error], 0
    jne  .fail
    mov  byte [rel job_out_ready], 1
    xor  eax, eax
    pop  r12
    ret
.fail:
    mov  rdi, r12
    call job_artifact_clear
    mov  eax, -1
    pop  r12
    ret

; ---------------------------------------------------------------------------
; Registry declaration + handlers
; ---------------------------------------------------------------------------
; Named scale-1 lock sites retain the one shared spinlock implementation while
; making the protected receipt workspace machine-auditable.
job_receipt_lock_acquire:
    lea  rdi, [rel job_receipt_lock]
    jmp  spin_acquire

job_receipt_lock_release:
    lea  rdi, [rel job_receipt_lock]
    jmp  spin_release

job_receipt_declare:
    lea  rdi, [rel str_verb_jobpub]
    lea  rsi, [rel cmd_verb_jobpub]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    cmp  eax, -1
    je   .fail
    mov  [rel job_verb_pub], eax
    lea  rdi, [rel str_verb_jobrun]
    lea  rsi, [rel cmd_verb_jobrun]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    cmp  eax, -1
    je   .fail
    mov  [rel job_verb_run], eax
    lea  rdi, [rel str_verb_keygen]
    lea  rsi, [rel cmd_verb_keygen]
    xor  edx, edx                    ; ordinary nonpublic mutation classifier
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    cmp  eax, -1
    je   .fail
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

; C2 fresh operation; all private work is in the existing node key service.
; Message is domain16/build32/bootLE64/challenge32/generationLE64, never supplied
; wholesale by a caller. Existing job lock owns public formatting and generation.
cmd_verb_keygen:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    call job_receipt_lock_acquire
    lea rdi, [rel job_out_buf]
    xor esi, esi
    mov edx, JOB_OUT_MAX
    call memset
    call job_out_reset
    lea rdi, [rel c2_proof]
    xor esi, esi
    mov edx, 96
    call memset
    mov qword [r12+RSP_CODE], CMDE_BADARG
    cmp byte [rel paos_build_state], 1  ; stamped measurement matches
    jne .binding
    cmp qword [rel boot_tsc_start], 0
    je .binding
    cmp qword [rel c2_generation], -1
    je .binding
    mov rdi, [rbx+REQ_ARG]
    test rdi, rdi
    jz .args
    xor ecx, ecx
.decode:
    mov al, [rdi+rcx]
    call c2_nibble
    test eax, eax
    js .args
    mov r8d, eax
    shl r8d, 4
    inc ecx
    mov al, [rdi+rcx]
    call c2_nibble
    test eax, eax
    js .args
    or eax, r8d
    mov edx, ecx
    shr edx, 1
    lea rsi, [rel c2_message+56]
    mov [rsi+rdx], al
    inc ecx
    cmp ecx, 64
    jb .decode
    cmp byte [rdi+64], 0
    jne .args
    lea rdi, [rel c2_message]
    lea rsi, [rel c2_domain]
    mov edx, 16
    call memcpy
    lea rdi, [rel c2_message+16]
    lea rsi, [rel paos_build_measured]
    mov edx, 32
    call memcpy
    mov rax, [rel boot_tsc_start]
    mov [rel c2_message+48], rax
    mov rax, [rel c2_generation]
    inc rax
    mov [rel c2_message+88], rax
    lea rdi, [rel c2_message]
    mov esi, 96
    lea rdx, [rel c2_proof]
    call node_identity_generate_proof
    test eax, eax
    jnz .service
    lea rdi, [rel c2_proof]
    lea rsi, [rel c2_previous_public]
    mov edx, 32
    call memcmp
    test eax, eax
    jz .service
    ; Refuse a changed candidate/boot rather than format a misleading receipt.
    mov rax, [rel boot_tsc_start]
    cmp rax, [rel c2_message+48]
    jne .binding
    cmp byte [rel paos_build_state], 1
    jne .binding
    lea rdi, [rel c2_message+16]
    lea rsi, [rel paos_build_measured]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .binding
    mov rax, [rel c2_message+88]
    mov [rel c2_generation], rax
    lea rdi, [rel c2_previous_public]
    lea rsi, [rel c2_proof]
    mov edx, 32
    call memcpy
    lea rdi, [rel c2_prefix]
    call job_out_put_str
    lea rdi, [rel c2_message+16]
    mov esi, 32
    call job_out_put_hexbytes
    lea rdi, [rel c2_boot]
    call job_out_put_str
    mov rdi, [rel c2_message+48]
    call c2_put_dec
    lea rdi, [rel c2_gen]
    call job_out_put_str
    mov rdi, [rel c2_message+88]
    call c2_put_dec
    lea rdi, [rel c2_challenge]
    call job_out_put_str
    lea rdi, [rel c2_message+56]
    mov esi, 32
    call job_out_put_hexbytes
    lea rdi, [rel c2_pub]
    call job_out_put_str
    lea rdi, [rel c2_proof+0]
    mov esi, 32
    call job_out_put_hexbytes
    lea rdi, [rel c2_sig]
    call job_out_put_str
    lea rdi, [rel c2_proof+32]
    mov esi, 64
    call job_out_put_hexbytes
    lea rdi, [rel c2_ok]
    call job_out_put_str
    cmp byte [rel job_out_error], 0
    jne .service
    mov qword [r12+RSP_CODE], CMDE_OK
    jmp .ready
.args:
    lea r13, [rel c2_args]
    jmp .refuse
.binding:
    lea r13, [rel c2_binding]
    jmp .refuse
.service:
    lea r13, [rel c2_service]
.refuse:
    call job_out_reset
    mov rdi, r13
    call job_out_put_str
.ready:
    mov byte [rel job_out_ready], 1
    call job_receipt_lock_release
    pop r13
    pop r12
    pop rbx
    ret

c2_nibble:                          ; AL lowercase hex -> EAX0..15/-1
    cmp al, '0'
    jb .bad
    cmp al, '9'
    jbe .digit
    cmp al, 'a'
    jb .bad
    cmp al, 'f'
    ja .bad
    sub al, 'a'-10
    movzx eax, al
    ret
.digit:
    sub al, '0'
    movzx eax, al
    ret
.bad:
    mov eax, -1
    ret

c2_put_dec:
    sub rsp, 8
    lea rsi, [rel job_dec_buf]
    call fmt_dec
    lea rdi, [rel job_dec_buf]
    mov rsi, rax
    call job_out_put_bytes
    add rsp, 8
    ret

cmd_verb_jobpub:
    call cmd_handler_prologue
    push r13
    mov  r13, rsi
    call job_receipt_lock_acquire
    call job_out_reset
    lea  rdi, [rel job_public]
    mov  esi, 32
    call node_identity_public
    test eax, eax
    jnz  .unavailable
    lea  rdi, [rel str_job_pub_prefix]
    call job_out_put_str
    lea  rdi, [rel job_public]
    mov  esi, 32
    call job_out_put_hexbytes
    lea  rdi, [rel str_job_pub_alg]
    call job_out_put_str
    mov  byte [rel job_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    lea  rax, [rel job_public]
    mov  [r13 + RSP_VAL], rax
    jmp  .unlock
.unavailable:
    lea  rdi, [rel str_job_identity_err]
    call job_out_put_str
    mov  byte [rel job_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.unlock:
    call job_receipt_lock_release
    pop  r13
    ret

; Copy one bounded arg token. RDI=src, RSI=dst, EDX=capacity;
; RAX=len or -1, RDI=first delimiter on success.
job_copy_token:
    dec  edx
    xor  ecx, ecx
.loop:
    movzx eax, byte [rdi]
    test al, al
    jz   .done
    cmp  al, ' '
    je   .done
    cmp  al, 0x21
    jb   .long
    cmp  al, 0x7e
    ja   .long
    cmp  al, ','
    je   .long
    cmp  al, '='
    je   .long
    cmp  ecx, edx
    jae  .long
    mov  [rsi + rcx], al
    inc  ecx
    inc  rdi
    jmp  .loop
.done:
    mov  byte [rsi + rcx], 0
    mov  eax, ecx
    ret
.long:
    mov  byte [rsi + rcx], 0
    mov  rax, -1
    ret

job_skip_spaces:
    cmp  byte [rdi], ' '
    jne  .done
    inc  rdi
    jmp  job_skip_spaces
.done:
    ret

cmd_verb_jobrun:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                           ; req
    mov  r13, rsi                           ; rsp
    call job_receipt_lock_acquire
    lea  rdi, [rel job_live]
    call job_artifact_clear

    mov  rdi, [r12 + REQ_ARG]
    lea  rsi, [rel job_live_scope]
    mov  edx, JOB_SCOPE_MAX
    call job_copy_token
    cmp  rax, 0
    jle  .badarg
    call job_skip_spaces
    lea  rsi, [rel job_live_nonce]
    mov  edx, JOB_NONCE_MAX
    call job_copy_token
    cmp  rax, 0
    jle  .badarg
    mov  r15, rax                           ; nonce length
    call job_skip_spaces
    cmp  byte [rdi], 0
    jne  .badarg

    ; Parse the declared scope.  The fixed local workload requires
    ; PMCAP_COMPUTE; CAP_BLOCK_WRITE therefore exercises the negative barrier:
    ; scope lacks required compute -> SJOB_ERR_CAP, no meter hook/receipt.
    xor  r14d, r14d
    lea  rdi, [rel job_live_scope]
    lea  rsi, [rel str_cap_compute]
    call strcmp
    test rax, rax
    jnz  .try_block
    mov  r14, PMCAP_COMPUTE
    jmp  .scope_ready
.try_block:
    lea  rdi, [rel job_live_scope]
    lea  rsi, [rel str_cap_block_write]
    call strcmp
    test rax, rax
    jnz  .scope_ready                       ; unknown => scope 0 => fail closed
    mov  r14, PMCAP_BLOCK_WRITE
.scope_ready:
    lea  rdi, [rel job_live]
    lea  rsi, [rel job_live_scope]
    mov  rdx, r14
    lea  rcx, [rel job_live_nonce]
    mov  r8, r15
    lea  r9, [rel job_receipt_wire_deliver]
    call job_prepare
    lea  rdi, [rel job_live]
    call job_submit
    cmp  eax, SJOB_ERR_CAP
    je   .capdeny
    test eax, eax
    jnz  .failed
    cmp  byte [rel job_out_ready], 1
    jne  .failed
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_ACCEPTED], 1
    mov  rax, [rel job_live + sched_job.id]
    mov  [r13 + RSP_JOBID], rax
    mov  [r13 + RSP_VAL], rax
    jmp  .unlock
.capdeny:
    call job_out_reset
    lea  rdi, [rel str_job_cap_err]
    call job_out_put_str
    mov  byte [rel job_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_CAPDENY
    jmp  .unlock
.badarg:
    call job_out_reset
    lea  rdi, [rel str_job_arg_err]
    call job_out_put_str
    mov  byte [rel job_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .unlock
.failed:
    call job_out_reset
    lea  rdi, [rel str_job_run_err]
    call job_out_put_str
    mov  byte [rel job_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    ; The raw ARGT_TEXT is echoed by the generic UDP response shell.  Once the
    ; parsed request has failed specifically because no runtime signer exists,
    ; consume that scratch text so the refusal cannot masquerade as a nonce-
    ; bearing receipt.  Parsed scope/nonce copies above remain lock-owned.
    mov  rax, [r12 + REQ_ARG]
    mov  byte [rax], 0
.unlock:
    call job_receipt_lock_release
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Boot KAT: real submit/sign/verify, body tamper rejection, cap-scope denial,
; and dead-result-channel reaping.  The signed receipt is fixture-scoped: the
; node-identity consumer harness owns the active key and clears it on return.
; ---------------------------------------------------------------------------
job_receipt_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call job_receipt_lock_acquire
    mov  byte [rel job_m_identity], 0
    mov  byte [rel job_m_receipt], 0
    mov  byte [rel job_m_pubkey], 0
    mov  byte [rel job_test_delivered], 0

    call job_receipt_declare
    test eax, eax
    jnz  .fail
    lea  rdi, [rel job_public]
    mov  esi, 32
    call node_identity_public
    test eax, eax
    jnz  .fail

    ; Positive: one owner/compute JOB goes through job_submit and its result
    ; channel; the detached signature verifies over the exact canonical body.
    lea  rdi, [rel job_kat]
    lea  rsi, [rel str_cap_compute]
    mov  edx, PMCAP_COMPUTE
    lea  rcx, [rel str_job_kat_nonce]
    mov  r8d, str_job_kat_nonce.len
    lea  r9, [rel job_receipt_test_deliver]
    call job_prepare
    lea  rdi, [rel job_kat]
    call job_submit
    test eax, eax
    jnz  .fail
    cmp  dword [rel job_kat + sched_job.state], SJOB_ST_DONE
    jne  .fail
    cmp  byte [rel job_test_delivered], 1
    jne  .fail
    cmp  qword [rel job_kat + sched_job.owner], PRIN_OWNER
    jne  .fail
    cmp  qword [rel job_kat + sched_job.cap_scope], PMCAP_COMPUTE
    jne  .fail
    cmp  qword [rel job_kat + sched_job.mem_used], JOB_DECL_MEM
    jne  .fail
    mov  rdi, [rel job_kat + sched_job.receipt_body]
    mov  rsi, [rel job_kat + sched_job.receipt_len]
    mov  rdx, [rel job_kat + sched_job.signature]
    mov  ecx, 64
    call node_identity_verify
    test eax, eax
    jnz  .fail

    ; Tamper one byte of the signed BODY; verification must fail, then restore.
    mov  rbx, [rel job_kat + sched_job.receipt_body]
    xor  byte [rbx + 4], 1
    mov  rdi, rbx
    mov  rsi, [rel job_kat + sched_job.receipt_len]
    mov  rdx, [rel job_kat + sched_job.signature]
    mov  ecx, 64
    call node_identity_verify
    mov  r14, rax
    xor  byte [rbx + 4], 1
    test r14, r14
    jz   .fail

    ; Negative: block-write-only scope cannot run a compute-required entry.
    lea  rdi, [rel job_kat_negative]
    lea  rsi, [rel str_cap_block_write]
    mov  edx, PMCAP_BLOCK_WRITE
    lea  rcx, [rel str_job_kat_nonce]
    mov  r8d, str_job_kat_nonce.len
    lea  r9, [rel job_receipt_test_deliver]
    call job_prepare
    lea  rdi, [rel job_kat_negative]
    call job_submit
    cmp  eax, SJOB_ERR_CAP
    jne  .fail
    cmp  qword [rel job_kat_negative + sched_job.receipt_len], 0
    jne  .fail
    cmp  dword [rel job_kat_negative + sched_job.state], SJOB_ST_REJECTED
    jne  .fail

    ; Degrade: a dead result channel is reaped after signing, never waited on.
    lea  rdi, [rel job_kat_dead]
    lea  rsi, [rel str_cap_compute]
    mov  edx, PMCAP_COMPUTE
    lea  rcx, [rel str_job_kat_nonce]
    mov  r8d, str_job_kat_nonce.len
    xor  r9d, r9d
    call job_prepare
    lea  rdi, [rel job_kat_dead]
    call job_submit
    test eax, eax
    jnz  .fail
    cmp  dword [rel job_kat_dead + sched_job.state], SJOB_ST_DONE
    jne  .fail
    cmp  dword [rel job_kat_dead + sched_job.reaped], 1
    jne  .fail
    cmp  qword [rel job_kat_dead + sched_job.receipt_len], 0
    je   .fail

    mov  byte [rel job_m_identity], 1
    ; job_m_receipt/job_m_pubkey are legacy BOOTLOG projections.  Keep both
    ; retired: this callback proves only a fixture KAT, not a live identity.
    call job_receipt_lock_release
    lea  rdi, [rel str_job_m_identity]
    call serial_string
    lea  rdi, [rel str_job_m_receipt]
    call serial_string
    xor  eax, eax
    jmp  .out
.fail:
    call job_receipt_lock_release
    lea  rdi, [rel str_job_m_fail]
    call serial_string
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Data
; ---------------------------------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_sec_job_receipt_0 0
align 8
job_receipt_lock: db 0
align 8
job_body_cur:     dq 0
job_out_cur:      dq 0
job_body_error:   db 0
job_out_error:    db 0
job_dec_buf:      times 21 db 0
align 8
job_verb_pub:     dd -1
job_verb_run:     dd -1
times 32 db 0                  ; job_m_identity..job_work_mem moved to WDATA_sec_job_receipt_0_bss1: keeps the labels below at their offset mod 64

align 8
c2_generation: dq 0
c2_previous_public: times 32 db 0
c2_message: times 96 db 0
c2_proof: times 96 db 0
c2_domain: db 'PAOS-C2-KEY-v1',0,0
str_verb_keygen: db 'KEYGEN',0
c2_prefix: db 'C2KEY v=1 source=csprng health=ready build=',0
c2_boot: db ' boot=',0
c2_gen: db ' generation=',0
c2_challenge: db ' challenge=',0
c2_pub: db ' pub=',0
c2_sig: db ' sig=',0
c2_ok: db ' verify=1 tamper=1 wiped=1 installed=0',0
c2_args: db 'C2KEY REFUSED reason=args',0
c2_binding: db 'C2KEY REFUSED reason=binding',0
c2_service: db 'C2KEY REFUSED reason=key_service',0

job_hex: db "0123456789abcdef"

str_verb_jobrun: db "JOBRUN",0
str_verb_jobpub: db "JOBPUB",0
str_cap_compute: db "CAP_COMPUTE",0
str_cap_block_write: db "CAP_BLOCK_WRITE",0

str_job_body_v:      db "v=1,job_id=",0
str_job_body_owner:  db ",owner=",0
str_job_body_scope:  db ",cap_scope=",0
str_job_body_cpu:    db ",cpu_us=",0
str_job_body_mem:    db ",mem=",0
str_job_body_energy: db ",energy_est=",0
str_job_body_nonce:  db ",nonce=",0
str_job_body_prefix: db "BODY=",0
str_job_sig_prefix:  db " SIG=",0
str_job_pub_prefix:  db "PUB=",0
str_job_pub_alg:     db " ALG=ed25519",0
str_job_cap_err:     db "ERR cap_scope_violation",0
str_job_arg_err:     db "ERR JOBRUN expected='CAP_COMPUTE <nonce>'",0
str_job_run_err:     db "ERR job_receipt_unavailable",0
str_job_identity_err: db "ERR node_identity_unavailable",0

str_job_kat_nonce: db "BOOT-JOB-KAT"
.len equ $ - str_job_kat_nonce
db 0
%endmacro
WDATA_DEFER WDATA_sec_job_receipt_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_sec_job_receipt_0_bss1 0
resb 32                 ; keeps job_m_identity at its WDATA offset mod 64
job_m_identity:   resb 1
job_m_receipt:    resb 1
job_m_pubkey:     resb 1
job_out_ready:    resb 1
job_test_delivered: resb 1
alignb 8
job_live:         resb sched_job_size
job_kat:          resb sched_job_size
job_kat_negative: resb sched_job_size
job_kat_dead:     resb sched_job_size
job_body_buf:     resb JOB_BODY_MAX
job_signature:    resb 64
job_public:       resb 32
job_out_buf:      resb JOB_OUT_MAX
job_live_scope:   resb JOB_SCOPE_MAX
job_live_nonce:   resb JOB_NONCE_MAX
job_work_mem:     resb JOB_DECL_MEM
%endmacro
WDATA_BSS_DEFER WDATA_sec_job_receipt_0_bss1

str_job_m_identity: db "[PAOS64] P2 job: submit carries owner identity and cap scope [job.identity]",13,10,0
str_job_m_receipt:  db "[PAOS64] P2 job: signed-receipt KAT under fixture identity PASS (runtime identity absent) [job.receipt.kat]",13,10,0
str_job_m_fail:     db "[PAOS64] P2 job: portable signed-receipt KAT FAIL (markers withheld)",13,10,0
