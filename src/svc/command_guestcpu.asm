;; MODULE svc/command_guestcpu
;; LAYER 5
;; EXPORTS guestcpu_register_verb, command_guestcpu_public_observation
;; IMPORTS core/lib/mem, core/lib/str, core/smp, core/time, svc/command, svc/command_aihook, svc/command_cons, svc/command_smp, hv/hv_ops, hv/vmx
;; CAPS
;; OWNER saga:smp_daily_driver_completion
; Task 1330h0: a read-only registry projection over the existing single vCPU.
; It never starts/stops a guest or changes placement. UDP and the in-process AI
; path dispatch the same handler and consume the same bounded rendered row.

GUESTCPU_MAX_VCPUS      equ MAXCORE
GUESTCPU_HOST_NONE      equ 0xFFFFFFFF
GUESTCPU_FIX_MAX        equ 0
GUESTCPU_FIX_CONFIGURED equ 4
GUESTCPU_FIX_ONLINE     equ 8
GUESTCPU_FIX_STATE      equ 12
GUESTCPU_FIX_HOST       equ 16
GUESTCPU_FIX_BEFORE     equ 24
GUESTCPU_FIX_AFTER      equ 32
GUESTCPU_ST_STOPPED     equ 0
GUESTCPU_ST_RUNNING     equ 1
GUESTCPU_ST_DEGRADED    equ 2

; Exact public-read extension. Other names retain the existing console/SMP
; fail-closed matcher, and the live row must remain cap=0/destr=0.
command_guestcpu_public_observation:
    xor  eax, eax
    cmp  dword [rdi], 'GUES'
    jne  command_public_observation_mux
    cmp  dword [rdi + 4], 'TCPU'
    jne  command_public_observation_mux
    cmp  byte [rdi + 8], 0
    jne  command_public_observation_mux
    call command_lookup
    cmp  eax, -1
    je   .no
    imul rax, VERB_ENT_SZ
    lea  rdx, [rel verb_table]
    cmp  qword [rdx + rax + VERB_CAP], 0
    jne  .no
    cmp  qword [rdx + rax + VERB_DESTR], 0
    jne  .no
    mov  eax, 1
.no:
    ret

guestcpu_register_verb:
    lea  rdi, [rel str_verb_guestcpu]
    lea  rsi, [rel cmd_verb_guestcpu]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    test eax, eax
    js   .out
    mov  [rel verb_id_guestcpu], eax
    call guestcpu_selftest
.out:
    ret

; GUESTCPU <16-hex nonce> SCHEMA|SUMMARY|CPU 0
cmd_verb_guestcpu:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    call smpobs_arg_bounded
    jc   .badarg
    mov  rdi, [r12 + REQ_ARG]
    call smpobs_parse_nonce
    jc   .badarg
    mov  r12, rax
    cmp  byte [rdx], ' '
    jne  .badarg
    lea  rbx, [rdx + 1]
    cmp  dword [rbx], 'SCHE'
    jne  .check_summary
    cmp  word [rbx + 4], 'MA'
    jne  .badarg
    cmp  byte [rbx + 6], 0
    jne  .badarg
    call guestcpu_render_schema
    jmp  .ok
.check_summary:
    cmp  dword [rbx], 'SUMM'
    jne  .check_cpu
    cmp  dword [rbx + 4], 'ARY'
    jne  .badarg
    cmp  byte [rbx + 7], 0
    jne  .badarg
    call guestcpu_render_summary
    jmp  .ok
.check_cpu:
    cmp  dword [rbx], 'CPU '
    jne  .badarg
    cmp  byte [rbx + 4], '0'
    jne  .badarg
    cmp  byte [rbx + 5], 0
    jne  .badarg
    call guestcpu_render_cpu0
.ok:
    lea  rax, [rel smpobs_out_buf]
    mov  [r13 + RSP_VAL], rax
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  byte [rel smpobs_out_ready], 1
    jmp  .out
.badarg:
    call smpobs_out_reset
    lea  rdi, [rel str_guestcpu_badarg]
    call smpobs_put_str
    lea  rax, [rel smpobs_out_buf]
    mov  [r13 + RSP_VAL], rax
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    mov  byte [rel smpobs_out_ready], 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

guestcpu_begin:
    push rdi
    call smpobs_out_reset
    lea  rdi, [rel str_guestcpu_nonce]
    call smpobs_put_str
    pop  rdi
    jmp  smpobs_put_hex16

guestcpu_render_schema:
    mov  rdi, r12
    call guestcpu_begin
    lea  rdi, [rel str_guestcpu_schema]
    jmp  smpobs_put_str

guestcpu_render_summary:
    mov  rdi, r12
    call guestcpu_begin
    lea  rdi, [rel str_guestcpu_max]
    call smpobs_put_str
    mov  edi, GUESTCPU_MAX_VCPUS
    call smpobs_put_dec
    lea  rdi, [rel str_guestcpu_configured]
    call smpobs_put_str
    lea  rdi, [rel str_guestcpu_online]
    call smpobs_put_str
    call guestcpu_state
    mov  edi, edx
    call smpobs_put_dec
    lea  rdi, [rel str_guestcpu_generation]
    call smpobs_put_str
    mov  edi, [rel hv_linux_start_gen]
    call smpobs_put_dec
    lea  rdi, [rel str_guestcpu_state]
    call smpobs_put_str
    call guestcpu_state
    mov  rdi, rax
    call smpobs_put_str
    lea  rdi, [rel str_guestcpu_backend]
    call smpobs_put_str
    call guestcpu_backend
    mov  rdi, rax
    call smpobs_put_str
    lea  rdi, [rel str_guestcpu_projection]
    jmp  smpobs_put_str

guestcpu_render_cpu0:
    mov  rdi, r12
    call guestcpu_begin
    lea  rdi, [rel str_guestcpu_cpu0]
    call smpobs_put_str
    call guestcpu_state
    mov  rdi, rax
    call smpobs_put_str
    lea  rdi, [rel str_guestcpu_host]
    call smpobs_put_str
    call guestcpu_state
    test edx, edx
    jz   .host_none
    call smp_current_logical
    cmp  eax, MAXCORE
    jae  .host_none
    mov  edi, eax
    call smpobs_put_dec
    jmp  .run
.host_none:
    lea  rdi, [rel str_guestcpu_none]
    call smpobs_put_str
.run:
    lea  rdi, [rel str_guestcpu_run_ns]
    call smpobs_put_str
    call guestcpu_live_run_ticks
    mov  rdi, rax
    call guestcpu_ticks_to_ns
    mov  rdi, rax
    call smpobs_put_dec
    lea  rdi, [rel str_guestcpu_exits]
    call smpobs_put_str
    mov  rdi, [rel hv_ops_perf_vm_exits]
    call smpobs_put_dec
    lea  rdi, [rel str_guestcpu_interrupts]
    call smpobs_put_str
    mov  rdi, [rel hv_guestcpu_interrupts]
    call smpobs_put_dec
    lea  rdi, [rel str_guestcpu_halt_wakes]
    call smpobs_put_str
    mov  rdi, [rel hv_guestcpu_halt_wakes]
    call smpobs_put_dec
    lea  rdi, [rel str_guestcpu_progress]
    call smpobs_put_str
    call guestcpu_last_progress_ms
    mov  rdi, rax
    call smpobs_put_dec
    lea  rdi, [rel str_guestcpu_faults]
    call smpobs_put_str
    mov  rdi, [rel hv_guestcpu_faults]
    jmp  smpobs_put_dec

; RAX=backend text; EDX=0 unavailable, 1 usable VMX, 2 declared SVM stub.
guestcpu_backend:
    mov  rax, [rel hv_ops_active]
    lea  rcx, [rel hv_ops_vmx]
    cmp  rax, rcx
    jne  .svm
    cmp  byte [rel hv_vmx_present], 1
    jne  .unavailable
    cmp  byte [rel hv_vmxon_ok], 1
    jne  .unavailable
    cmp  byte [rel hv_ept_built], 1
    jne  .unavailable
    lea  rax, [rel str_guestcpu_vmx]
    mov  edx, 1
    ret
.svm:
    lea  rcx, [rel hv_ops_svm]
    cmp  rax, rcx
    jne  .unavailable
    lea  rax, [rel str_guestcpu_svm]
    mov  edx, 2
    ret
.unavailable:
    lea  rax, [rel str_guestcpu_unavailable]
    xor  edx, edx
    ret

; RAX=state text; EDX=online. Offline states never expose placement.
guestcpu_state:
    call guestcpu_backend
    cmp  edx, 1
    jne  .degraded
    cmp  byte [rel hv_linux_panicked], 1
    je   .degraded
    cmp  byte [rel hv_linux_load_err], 0
    jne  .degraded
    cmp  byte [rel hv_linux_running], 1
    je   .resident
    cmp  byte [rel hv_linux_start_active], 1
    je   .runnable
    lea  rax, [rel str_guestcpu_stopped]
    xor  edx, edx
    ret
.resident:
    cmp  dword [rel hv_exit_reason], 12
    je   .halted
    lea  rax, [rel str_guestcpu_running]
    mov  edx, 1
    ret
.halted:
    lea  rax, [rel str_guestcpu_halted]
    mov  edx, 1
    ret
.runnable:
    lea  rax, [rel str_guestcpu_runnable]
    mov  edx, 1
    ret
.degraded:
    lea  rax, [rel str_guestcpu_degraded]
    xor  edx, edx
    ret

guestcpu_live_run_ticks:
    mov  r8, [rel hv_guestcpu_run_tsc_accum]
    cmp  byte [rel hv_linux_running], 1
    jne  .done
    mov  rcx, [rel hv_linux_run_start_tsc]
    test rcx, rcx
    jz   .done
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, rcx
    jb   .done
    sub  rax, rcx
    add  r8, rax
.done:
    mov  rax, r8
    ret

; RDI=calibrated TSC ticks -> RAX=nanoseconds, avoiding ticks*1e6 overflow.
guestcpu_ticks_to_ns:
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jz   .zero
    mov  rax, rdi
    xor  edx, edx
    div  rcx
    mov  r8, rax
    mov  rax, rdx
    imul rax, rax, 1000000
    xor  edx, edx
    div  rcx
    imul r8, r8, 1000000
    add  rax, r8
    ret
.zero:
    xor  eax, eax
    ret

; Monotonic timestamp of the latest completed VM-exit, in calibrated TSC ms.
guestcpu_last_progress_ms:
    mov  rax, [rel hv_guestcpu_last_progress_tsc]
    test rax, rax
    jz   .zero
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jz   .zero
    xor  edx, edx
    div  rcx
    ret
.zero:
    xor  eax, eax
    ret

; Pure hostile-fixture validator: reject counter regression, placement on an
; offline state, and anything other than the one-vCPU baseline.
guestcpu_fixture_validate:
    mov  eax, [rdi + GUESTCPU_FIX_MAX]
    cmp  eax, 2
    jb   .bad
    cmp  eax, 256
    ja   .bad
    cmp  dword [rdi + GUESTCPU_FIX_CONFIGURED], 1
    jne  .bad
    mov  eax, [rdi + GUESTCPU_FIX_ONLINE]
    cmp  eax, 1
    ja   .bad
    movzx ecx, byte [rdi + GUESTCPU_FIX_STATE]
    cmp  ecx, GUESTCPU_ST_DEGRADED
    ja   .bad
    mov  rax, [rdi + GUESTCPU_FIX_AFTER]
    cmp  rax, [rdi + GUESTCPU_FIX_BEFORE]
    jb   .bad
    cmp  ecx, GUESTCPU_ST_RUNNING
    je   .running
    cmp  dword [rdi + GUESTCPU_FIX_ONLINE], 0
    jne  .bad
    cmp  dword [rdi + GUESTCPU_FIX_HOST], GUESTCPU_HOST_NONE
    jne  .bad
    mov  eax, 1
    ret
.running:
    cmp  dword [rdi + GUESTCPU_FIX_ONLINE], 1
    jne  .bad
    cmp  dword [rdi + GUESTCPU_FIX_HOST], GUESTCPU_HOST_NONE
    je   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

guestcpu_selftest:
    lea  rdi, [rel guestcpu_fix_stopped]
    call guestcpu_fixture_validate
    test eax, eax
    jz   .fail
    lea  rdi, [rel guestcpu_fix_running]
    call guestcpu_fixture_validate
    test eax, eax
    jz   .fail
    lea  rdi, [rel guestcpu_fix_degraded]
    call guestcpu_fixture_validate
    test eax, eax
    jz   .fail
    lea  rdi, [rel guestcpu_fix_bad_place]
    call guestcpu_fixture_validate
    test eax, eax
    jnz  .fail
    lea  rdi, [rel guestcpu_fix_bad_counter]
    call guestcpu_fixture_validate
    test eax, eax
    jnz  .fail
    mov  eax, [rel verb_id_guestcpu]
    mov  [rel guestcpu_kat_req + REQ_VERB], rax
    mov  qword [rel guestcpu_kat_req + REQ_CAP], 0
    mov  qword [rel guestcpu_kat_req + REQ_IDEM], 0
    mov  qword [rel guestcpu_kat_req + REQ_SEL], 0
    lea  rax, [rel str_guestcpu_kat_schema]
    mov  [rel guestcpu_kat_req + REQ_ARG], rax
    lea  rdi, [rel guestcpu_kat_req]
    lea  rsi, [rel guestcpu_kat_rsp]
    call command_dispatch
    cmp  qword [rel guestcpu_kat_rsp + RSP_CODE], CMDE_OK
    jne  .fail
    lea  rdi, [rel smpobs_out_buf]
    lea  rsi, [rel str_guestcpu_kat_schema_expected]
    call strcmp
    test eax, eax
    jnz  .fail
    lea  rdi, [rel smpobs_out_buf]
    call strlen
    inc  rax
    mov  rdx, rax
    lea  rdi, [rel guestcpu_kat_registry]
    lea  rsi, [rel smpobs_out_buf]
    call memcpy
    mov  edi, [rel verb_id_guestcpu]
    lea  rsi, [rel str_guestcpu_kat_schema]
    call command_aihook_submit
    cmp  rdx, CMDE_OK
    jne  .fail
    lea  rcx, [rel smpobs_out_buf]
    cmp  rax, rcx
    jne  .fail
    lea  rdi, [rel guestcpu_kat_registry]
    lea  rsi, [rel smpobs_out_buf]
    call strcmp
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_guestcpu_schema_ok]
    call serial_string
    lea  rdi, [rel str_guestcpu_aihook_ok]
    call serial_string
.fail:
    mov  byte [rel smpobs_out_ready], 0
    ret

align 8
verb_id_guestcpu: dd 0
align 8
guestcpu_kat_req: times REQ_SZ db 0
guestcpu_kat_rsp: times RSP_SZ db 0
guestcpu_kat_registry: times 192 db 0

align 8
guestcpu_fix_stopped:
    dd 32, 1, 0
    db GUESTCPU_ST_STOPPED, 0, 0, 0
    dd GUESTCPU_HOST_NONE, 0
    dq 7, 7
guestcpu_fix_running:
    dd 32, 1, 1
    db GUESTCPU_ST_RUNNING, 0, 0, 0
    dd 3, 0
    dq 7, 8
guestcpu_fix_degraded:
    dd 32, 1, 0
    db GUESTCPU_ST_DEGRADED, 0, 0, 0
    dd GUESTCPU_HOST_NONE, 0
    dq 7, 8
guestcpu_fix_bad_place:
    dd 32, 1, 0
    db GUESTCPU_ST_STOPPED, 0, 0, 0
    dd 0, 0
    dq 7, 8
guestcpu_fix_bad_counter:
    dd 32, 1, 1
    db GUESTCPU_ST_RUNNING, 0, 0, 0
    dd 3, 0
    dq 8, 7

str_verb_guestcpu: db "GUESTCPU", 0
str_guestcpu_nonce: db "nonce=", 0
str_guestcpu_schema: db " schema=paos.guest-vcpu.v1 selectors=SCHEMA,SUMMARY,CPU effect=read ai_projection=registry", 0
str_guestcpu_max: db " max_vcpus=", 0
str_guestcpu_configured: db " configured=1", 0
str_guestcpu_online: db " online=", 0
str_guestcpu_generation: db " generation=", 0
str_guestcpu_state: db " state=", 0
str_guestcpu_backend: db " backend=", 0
str_guestcpu_projection: db " ai_projection=registry", 0
str_guestcpu_cpu0: db " vcpu=0 state=", 0
str_guestcpu_host: db " host_logical=", 0
str_guestcpu_run_ns: db " run_ns=", 0
str_guestcpu_exits: db " exits=", 0
str_guestcpu_interrupts: db " interrupts=", 0
str_guestcpu_halt_wakes: db " halt_wakes=", 0
str_guestcpu_progress: db " last_progress_ms=", 0
str_guestcpu_faults: db " faults=", 0
str_guestcpu_stopped: db "stopped", 0
str_guestcpu_runnable: db "runnable", 0
str_guestcpu_running: db "running", 0
str_guestcpu_halted: db "halted", 0
str_guestcpu_degraded: db "degraded", 0
str_guestcpu_vmx: db "vmx", 0
str_guestcpu_svm: db "svm", 0
str_guestcpu_unavailable: db "unavailable", 0
str_guestcpu_none: db "none", 0
str_guestcpu_badarg: db "error=badarg expected=GUESTCPU_<nonce>_SCHEMA|SUMMARY|CPU_0", 0
str_guestcpu_kat_schema: db "0123456789abcdef SCHEMA", 0
str_guestcpu_kat_schema_expected: db "nonce=0123456789abcdef schema=paos.guest-vcpu.v1 selectors=SCHEMA,SUMMARY,CPU effect=read ai_projection=registry", 0
str_guestcpu_schema_ok: db "[PAOS64] guest vCPU: bounded state/counter schema KAT PASS [guest.vcpu.schema.ok]", 13, 10, 0
str_guestcpu_aihook_ok: db "[PAOS64] guest vCPU: registry and in-process AI-hook fields identical [guest.vcpu.aihook.parity.ok]", 13, 10, 0
