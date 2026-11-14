;; MODULE svc/command_cons
;; LAYER 5
;; EXPORTS command_public_observation_mux, cons_local_begin, cons_local_finish, cons_secret_verb, cons_line_class, cons_redact_line, cons_declare, cons_bind_grid, cons_bind_render, cons_finalize, cons_window_bind_default, cons_window_unbind, cons_keyboard_begin, cons_keyboard_finish, cons_job_complete, cons_session_count, cmd_verb_consgrid, grid_out_reset, grid_out_str, grid_out_char, grid_out_dec, grid_out_buf, grid_out_ready, grid_out_cur
;; IMPORTS boot/serial, core/lib/fmt, core/lib/str, core/time, svc/command, svc/command_udp, svc/command_auth, svc/command_smp
;; CAPS
;; OWNER saga:verb_console
; Contract 2150 supplied the registry surface. Contract 2153 turns five of the
; declarations into bounded, named session nouns. The transcript is deliberately
; only a view cache: command_dispatch/audit remains the flight recorder authority.

%include "core/abi/wdata.inc"

%macro CONS_REGISTER 4
    lea  rdi, [rel %1]
    lea  rsi, [rel %2]
    mov  rdx, %3
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, %4
    call command_register_verb
    or   ebx, eax
%endmacro

CONS_SESSION_MAX equ 4
CONS_NAME_MAX    equ 31
CONS_REC_CAP     equ 24
CONS_BYTE_BUDGET equ 8192
CONS_LINE_MAX    equ 96
CONS_REPLY_MAX   equ 256
CONS_PAGE_RECS   equ 2

CONS_ORIGIN_KBD    equ 1
CONS_ORIGIN_UDP    equ 2
CONS_ORIGIN_ATTACH equ 3
CONS_ORIGIN_JOB    equ 4
CONS_CLASS_SAFE    equ 0             ; SEC-transcript-user-data-verbs classes
CONS_CLASS_USER    equ 1
CONS_CLASS_SECRET  equ 2
CONS_CLASS_VERB_MAX equ 32
CONS_KEEP_QCUT     equ 0x80          ; user-data line: the last kept target ends at '?'
CONS_KEEP_LINE_ALL equ 0x7F          ; user-data line: every token is a target
CONS_ENV_UNSIGNED  equ 0
CONS_ENV_OWNER     equ 1
CONS_ENV_LOCAL     equ 2

; Per-session metadata. floor is the oldest readable sequence; tail is the
; newest assigned sequence. Empty sessions therefore expose floor=tail+1.
CS_ACTIVE equ 0
CS_NAME   equ 8
CS_FLOOR  equ 40
CS_TAIL   equ 48
CS_HEAD   equ 56
CS_COUNT  equ 60
CS_USED   equ 64
CS_BOUND  equ 68
CS_SIZE   equ 80

; Fixed-width transcript records keep allocation and eviction deterministic.
CR_SEQ       equ 0
CR_TS        equ 8
CR_IDEM      equ 16
CR_ENV       equ 24
CR_ORIGIN    equ 32
CR_LINE_LEN  equ 36
CR_REPLY_LEN equ 40
CR_COST      equ 44
CR_CODE      equ 48
CR_JOBID     equ 56
CR_LINE      equ 64
CR_REPLY     equ (CR_LINE + CONS_LINE_MAX)
CR_SIZE      equ (CR_REPLY + CONS_REPLY_MAX)
CR_RESERVED  equ (64 + CONS_LINE_MAX + CONS_REPLY_MAX)

; A job association is projection state, not a second scheduler. It remembers
; only where the command model should append its eventual completion record.
CJ_ACTIVE  equ 0
CJ_SESSION equ 4
CJ_ENV     equ 8
CJ_JOBID   equ 16
CJ_LINE    equ 24
CJ_SIZE    equ (CJ_LINE + CONS_LINE_MAX)

; Exact public T0 extension used by the command model's central dispatch gate.
; Anything outside these six byte-exact names delegates to the pre-existing SMP
; observation matcher; unknown/new names therefore remain owner-signed.  A name
; match is still insufficient: the live registry row must remain cap=0/destr=0,
; so a later rung can replace a body and raise its metadata without re-registering
; or accidentally retaining this rung's public exemption.
; SEC-P1: the six names are a LAB-only exemption. The owner session records
; every locally typed verb line plus its reply and CONSGRID dumps the console's
; screen cells, so in the shipped floor they need an owner envelope like
; WINTREE/FSREAD (gated by S4). Shipped bytes delegate straight to the SMP matcher.
command_public_observation_mux:
    xor  eax, eax
%if PAOS_PUBLICITY_LAB_PROFILE == 0
    jmp  command_smp_public_observation
%else
    cmp  dword [rdi], 'CONS'
    jne  command_smp_public_observation
    cmp  dword [rdi + 4], 'GRID'
    jne  .skeleton
    cmp  byte [rdi + 8], 0
    je   .yes
    jmp  command_smp_public_observation
.skeleton:
    cmp  dword [rdi + 4], '_LIS'
    jne  .new
    cmp  byte [rdi + 8], 'T'
    jne  command_smp_public_observation
    cmp  byte [rdi + 9], 0
    je   .yes
    jmp  command_smp_public_observation
.new:
    cmp  dword [rdi + 4], '_NEW'
    jne  .submit
    cmp  byte [rdi + 8], 0
    je   .yes
    jmp  command_smp_public_observation
.submit:
    cmp  dword [rdi + 4], '_SUB'
    jne  .read
    cmp  word [rdi + 8], 'MI'
    jne  command_smp_public_observation
    cmp  byte [rdi + 10], 'T'
    jne  command_smp_public_observation
    cmp  byte [rdi + 11], 0
    je   .yes
    jmp  command_smp_public_observation
.read:
    cmp  dword [rdi + 4], '_REA'
    jne  .close
    cmp  byte [rdi + 8], 'D'
    jne  command_smp_public_observation
    cmp  byte [rdi + 9], 0
    je   .yes
    jmp  command_smp_public_observation
.close:
    cmp  dword [rdi + 4], '_CLO'
    jne  command_smp_public_observation
    cmp  word [rdi + 8], 'SE'
    jne  command_smp_public_observation
    cmp  byte [rdi + 10], 0
    jne  command_smp_public_observation
.yes:
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
%endif

cons_declare:
    push rbx
    xor  ebx, ebx
    CONS_REGISTER str_verb_consgrid,    cmd_verb_consgrid,    0, 0
    CONS_REGISTER str_verb_cons_list,   cmd_verb_cons_list,   0, 0
    CONS_REGISTER str_verb_cons_new,    cmd_verb_cons_new,    0, 1
    CONS_REGISTER str_verb_cons_submit, cmd_verb_cons_submit, 0, 0
    CONS_REGISTER str_verb_cons_read,   cmd_verb_cons_read,   0, 0
    CONS_REGISTER str_verb_cons_close,  cmd_verb_cons_close,  0, 1
    test ebx, ebx
    js   .fail
    mov  byte [rel cons_registered], 1
    call cons_sessions_init
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_cons_fail]
    call serial_string
    pop  rbx
    ret

; cons_bind_grid(RDI=dump_for_window callback, RSI=KAT-byte pointer).
; The GUI layer calls down once its grid exists.
; Runtime addresses avoid baked dq symbol RVAs and keep svc/ independent of L6.
cons_bind_grid:
    mov  [rel cons_grid_dump_cb], rdi
    mov  [rel cons_grid_kat_ptr], rsi
    ret

; The GUI binds the one renderer as a callback instead of letting L5 reach up
; into widget code. callback(line, reply, reply_len, origin, result_code).
cons_bind_render:
    mov  [rel cons_render_cb], rdi
    ret

; Contract 2153 session-noun state initializer. A conventional owner session
; exists independently of the window; closing/reopening the form only changes
; CS_BOUND and cannot erase these bytes.
cons_sessions_init:
    lea  rdi, [rel cons_sessions]
    xor  eax, eax
    mov  ecx, CONS_SESSION_MAX * CS_SIZE
    cld
    rep  stosb
    lea  rdi, [rel cons_records]
    mov  ecx, CONS_SESSION_MAX * CONS_REC_CAP * CR_SIZE
    rep  stosb
    lea  rdi, [rel cons_job_tracks]
    mov  ecx, JOB_MAX * CJ_SIZE
    rep  stosb
    mov  dword [rel cons_bound_session], -1
    mov  qword [rel cons_inner_exec_count], 0
    mov  qword [rel cons_pending_kbd_rec], 0
    mov  qword [rel cons_job_accept_count], 0
    mov  qword [rel cons_job_completion_count], 0
    lea  rdi, [rel str_cons_owner]
    call cons_session_create
    mov  [rel cons_default_session], eax
    ret

cons_finalize:
    cmp  byte [rel cons_registered], 1
    jne  .fail
    mov  rax, [rel cons_grid_dump_cb]
    test rax, rax
    jz   .fail
    mov  rax, [rel cons_grid_kat_ptr]
    test rax, rax
    jz   .fail
    cmp  byte [rax], 1
    jne  .fail
    lea  rdi, [rel cons_job_complete]
    call command_job_bind_completion
    call cons_rung3_selftest
    test eax, eax
    jnz  .fail
    call cons_rung4_selftest
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_cons_marker]
    call serial_string
    lea  rdi, [rel str_cons_job_marker]
    call serial_string
    ret
.fail:
    lea  rdi, [rel str_cons_fail]
    call serial_string
    ret

; Boot KAT exercises the real handlers through command_dispatch, then clears
; its private transcript so the first user read starts from a clean noun.
cons_rung3_selftest:
    push rbx
    push r12
    push r13
    mov  eax, CONS_SESSION_MAX
    cmp  eax, 4
    jne  .fail
    mov  eax, CONS_BYTE_BUDGET
    cmp  eax, CR_RESERVED * CONS_REC_CAP
    jae  .fail                            ; byte budget must independently bind
    lea  rdi, [rel str_cons_owner]
    call cons_session_find
    cmp  eax, -1
    je   .fail
    lea  rdi, [rel str_cons_kat_name]
    call cons_session_create
    jc   .fail
    cmp  edx, 1
    jne  .fail
    mov  qword [rel cons_kat_req + REQ_CAP], -1
    mov  qword [rel cons_kat_req + REQ_IDEM], 0
    mov  qword [rel cons_kat_req + REQ_SEL], 0
    mov  qword [rel cons_kat_req + REQ_SOURCE], CMD_SOURCE_INTERNAL
    mov  qword [rel cons_kat_req + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    lea  rdi, [rel str_verb_cons_list]
    call command_lookup
    cmp  eax, -1
    je   .fail
    mov  [rel cons_kat_req + REQ_VERB], rax
    lea  rax, [rel str_cons_empty]
    mov  [rel cons_kat_req + REQ_ARG], rax
    call grid_out_reset
    lea  rdi, [rel cons_kat_req]
    lea  rsi, [rel cons_kat_rsp]
    call command_dispatch
    test eax, eax
    jnz  .fail
    call cons_session_count
    cmp  eax, 2
    jne  .fail
    lea  rdi, [rel str_verb_cons_close]
    call command_lookup
    cmp  eax, -1
    je   .fail
    mov  [rel cons_kat_req + REQ_VERB], rax
    lea  rax, [rel str_cons_kat_name]
    mov  [rel cons_kat_req + REQ_ARG], rax
    call grid_out_reset
    lea  rdi, [rel cons_kat_req]
    lea  rsi, [rel cons_kat_rsp]
    call command_dispatch
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_cons_kat_name]
    call cons_session_find
    cmp  eax, -1
    jne  .fail
    lea  rdi, [rel str_verb_cons_submit]
    call command_lookup
    cmp  eax, -1
    je   .fail
    mov  [rel cons_kat_req + REQ_VERB], rax
    lea  rax, [rel str_cons_kat_submit]
    mov  [rel cons_kat_req + REQ_ARG], rax
    mov  r12, [rel cons_inner_exec_count]
    call grid_out_reset
    lea  rdi, [rel cons_kat_req]
    lea  rsi, [rel cons_kat_rsp]
    call command_dispatch
    test eax, eax
    jnz  .fail
    mov  r13, [rel cons_kat_rsp + RSP_VAL]
    lea  rdi, [rel cons_kat_req]
    lea  rsi, [rel cons_kat_rsp]
    call command_dispatch
    test eax, eax
    jnz  .fail
    cmp  [rel cons_kat_rsp + RSP_VAL], r13
    jne  .fail
    inc  r12
    cmp  [rel cons_inner_exec_count], r12
    jne  .fail
    ; Two more records make the first page full with a real continuation.
    mov  ecx, 2
.seed:
    push rcx
    mov  edi, [rel cons_default_session]
    lea  rsi, [rel str_cons_kat_line]
    mov  edx, CONS_ORIGIN_ATTACH
    xor  ecx, ecx
    mov  r8, CONS_ENV_LOCAL
    call cons_record_begin
    test rax, rax
    jz   .seed_fail
    mov  rdi, rax
    lea  rsi, [rel str_cons_kat_reply]
    mov  edx, str_cons_kat_reply.len
    xor  ecx, ecx
    call cons_record_finish
    pop  rcx
    loop .seed
    lea  rdi, [rel str_verb_cons_read]
    call command_lookup
    cmp  eax, -1
    je   .fail
    mov  [rel cons_kat_req + REQ_VERB], rax
    lea  rax, [rel str_cons_kat_read]
    mov  [rel cons_kat_req + REQ_ARG], rax
    call grid_out_reset
    lea  rdi, [rel cons_kat_req]
    lea  rsi, [rel cons_kat_rsp]
    call command_dispatch
    test eax, eax
    jnz  .fail
    cmp  dword [rel cons_last_read_emitted], CONS_PAGE_RECS
    jne  .fail
    cmp  dword [rel cons_last_read_more], 1
    jne  .fail
    cmp  qword [rel cons_last_read_next], 3
    jne  .fail
    lea  rdi, [rel str_cons_session_marker]
    call serial_string
    lea  rdi, [rel str_cons_idem_marker]
    call serial_string
    lea  rdi, [rel str_cons_read_marker]
    call serial_string
    call cons_sessions_init
    call grid_out_reset
    xor  eax, eax
    jmp  .out
.seed_fail:
    pop  rcx
.fail:
    call cons_sessions_init
    call grid_out_reset
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Rung-4 KAT: the shipped slow verb produces an accepted record, an unrelated
; PING runs next, STATUS observes RUNNING, and the job callback appends record 4.
cons_rung4_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cons_sessions_init
    mov  r12d, [rel cons_default_session]
    mov  qword [rel cons_kat_req + REQ_CAP], -1
    mov  qword [rel cons_kat_req + REQ_IDEM], 0
    mov  qword [rel cons_kat_req + REQ_SEL], 0
    mov  qword [rel cons_kat_req + REQ_SOURCE], CMD_SOURCE_INTERNAL
    mov  qword [rel cons_kat_req + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER

    lea  rdi, [rel str_verb_slow]
    call command_lookup
    cmp  eax, -1
    je   .fail
    mov  [rel cons_kat_req + REQ_VERB], rax
    mov  qword [rel cons_kat_req + REQ_ARG], 0
    lea  rdi, [rel cons_kat_req]
    lea  rsi, [rel cons_kat_rsp]
    call command_dispatch
    cmp  qword [rel cons_kat_rsp + RSP_ACCEPTED], 1
    jne  .fail
    mov  r14, [rel cons_kat_rsp + RSP_JOBID]
    test r14, r14
    jz   .fail
    mov  edi, r12d
    lea  rsi, [rel str_cons_kat_slow]
    mov  edx, CONS_ORIGIN_ATTACH
    xor  ecx, ecx
    mov  r8, CONS_ENV_LOCAL
    call cons_record_begin
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  rdi, rbx
    lea  rsi, [rel str_cons_kat_slow_reply]
    mov  edx, str_cons_kat_slow_reply.len
    xor  ecx, ecx
    call cons_record_finish
    mov  rdi, rbx
    mov  esi, r12d
    mov  rdx, r14
    mov  rcx, CONS_ENV_LOCAL
    call cons_job_accept
    jc   .fail
    cmp  dword [rbx + CR_REPLY], ' acc'
    jne  .fail

    lea  rdi, [rel str_verb_ping]
    call command_lookup
    cmp  eax, -1
    je   .fail
    mov  [rel cons_kat_req + REQ_VERB], rax
    mov  qword [rel cons_kat_req + REQ_ARG], 2154
    lea  rdi, [rel cons_kat_req]
    lea  rsi, [rel cons_kat_rsp]
    call command_dispatch
    cmp  qword [rel cons_kat_rsp + RSP_VAL], 2154
    jne  .fail
    mov  edi, r12d
    lea  rsi, [rel str_cons_kat_ping]
    mov  edx, CONS_ORIGIN_ATTACH
    xor  ecx, ecx
    mov  r8, CONS_ENV_LOCAL
    call cons_record_begin
    test rax, rax
    jz   .fail
    mov  rdi, rax
    lea  rsi, [rel str_cons_kat_ping_reply]
    mov  edx, str_cons_kat_ping_reply.len
    xor  ecx, ecx
    call cons_record_finish

    mov  eax, [rel verb_id_status]
    mov  [rel cons_kat_req + REQ_VERB], rax
    mov  [rel cons_kat_req + REQ_ARG], r14
    lea  rdi, [rel cons_kat_req]
    lea  rsi, [rel cons_kat_rsp]
    call command_dispatch
    cmp  qword [rel cons_kat_rsp + RSP_CODE], CMDE_OK
    jne  .fail
    cmp  qword [rel cons_kat_rsp + RSP_VAL], JOB_ST_RUN
    jne  .fail
    mov  edi, r12d
    lea  rsi, [rel str_cons_kat_status]
    mov  edx, CONS_ORIGIN_ATTACH
    xor  ecx, ecx
    mov  r8, CONS_ENV_LOCAL
    call cons_record_begin
    test rax, rax
    jz   .fail
    mov  rdi, rax
    lea  rsi, [rel str_cons_kat_status_reply]
    mov  edx, str_cons_kat_status_reply.len
    xor  ecx, ecx
    call cons_record_finish

    mov  r13d, SLOWJOB_STEPS
.pump:
    mov  rdi, r14
    call command_job_pump
    dec  r13d
    jnz  .pump
    cmp  qword [rel cons_job_accept_count], 1
    jne  .fail
    cmp  qword [rel cons_job_completion_count], 1
    jne  .fail
    mov  edi, r12d
    call cons_session_ptr
    cmp  dword [rax + CS_COUNT], 4
    jne  .fail
    cmp  qword [rax + CS_TAIL], 4
    jne  .fail
    mov  edi, r12d
    xor  esi, esi
    call cons_record_ptr
    cmp  qword [rax + CR_SEQ], 1
    jne  .fail
    cmp  [rax + CR_JOBID], r14
    jne  .fail
    mov  edi, r12d
    mov  esi, 1
    call cons_record_ptr
    cmp  qword [rax + CR_SEQ], 2
    jne  .fail
    mov  edi, r12d
    mov  esi, 2
    call cons_record_ptr
    cmp  qword [rax + CR_SEQ], 3
    jne  .fail
    mov  edi, r12d
    mov  esi, 3
    call cons_record_ptr
    mov  r15, rax
    cmp  qword [r15 + CR_SEQ], 4
    jne  .fail
    cmp  dword [r15 + CR_ORIGIN], CONS_ORIGIN_JOB
    jne  .fail
    cmp  [r15 + CR_JOBID], r14
    jne  .fail
    cmp  qword [r15 + CR_CODE], CMDE_OK
    jne  .fail
    cmp  dword [r15 + CR_REPLY], ' com'
    jne  .fail
    lea  rdi, [r15 + CR_LINE]
    lea  rsi, [rel str_cons_kat_slow]
    call strcmp
    test eax, eax
    jnz  .fail
    call cons_sessions_init
    xor  eax, eax
    jmp  .out
.fail:
    call cons_sessions_init
    mov  eax, 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Bounded session table and transcript ring.
; ---------------------------------------------------------------------------

cons_session_ptr:                         ; EDI=id -> RAX=CS*
    imul rdi, rdi, CS_SIZE
    lea  rax, [rel cons_sessions]
    add  rax, rdi
    ret

cons_record_ptr:                          ; EDI=session, ESI=physical slot -> RAX=CR*
    imul rdi, rdi, CONS_REC_CAP * CR_SIZE
    imul rsi, rsi, CR_SIZE
    lea  rax, [rel cons_records]
    add  rax, rdi
    add  rax, rsi
    ret

; Strict noun token: 1..31 printable non-space bytes. EAX=len, CF on invalid.
cons_name_len:
    xor  eax, eax
.next:
    movzx ecx, byte [rdi + rax]
    test cl, cl
    jz   .done
    cmp  cl, 0x21
    jb   .bad
    cmp  cl, 0x7e
    ja   .bad
    inc  eax
    cmp  eax, CONS_NAME_MAX
    jbe  .next
.bad:
    stc
    ret
.done:
    test eax, eax
    jz   .bad
    clc
    ret

cons_session_find:                        ; RDI=name -> EAX=id or -1
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
.scan:
    cmp  ebx, CONS_SESSION_MAX
    jae  .miss
    mov  edi, ebx
    call cons_session_ptr
    cmp  byte [rax + CS_ACTIVE], 1
    jne  .next
    lea  rdi, [rax + CS_NAME]
    mov  rsi, r12
    call strcmp
    test eax, eax
    jz   .hit
.next:
    inc  ebx
    jmp  .scan
.hit:
    mov  eax, ebx
    jmp  .out
.miss:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; RDI=name -> EAX=id, EDX=created(0/1), CF on invalid/full.
cons_session_create:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    call cons_name_len
    jc   .bad
    mov  r13d, eax
    mov  rdi, r12
    call cons_session_find
    cmp  eax, -1
    je   .find_free
    xor  edx, edx
    clc
    jmp  .out
.find_free:
    xor  ebx, ebx
.free_scan:
    cmp  ebx, CONS_SESSION_MAX
    jae  .bad
    mov  edi, ebx
    call cons_session_ptr
    cmp  byte [rax + CS_ACTIVE], 0
    je   .claim
    inc  ebx
    jmp  .free_scan
.claim:
    mov  r10, rax
    mov  rdi, r10
    xor  eax, eax
    mov  ecx, CS_SIZE
    cld
    rep  stosb
    mov  edi, ebx
    xor  esi, esi
    call cons_record_ptr
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, CONS_REC_CAP * CR_SIZE
    rep  stosb
    mov  edi, ebx
    call cons_session_ptr
    mov  r10, rax
    mov  byte [r10 + CS_ACTIVE], 1
    lea  rdi, [r10 + CS_NAME]
    mov  rsi, r12
    mov  ecx, r13d
    inc  ecx
    rep  movsb
    mov  qword [r10 + CS_FLOOR], 1
    mov  qword [r10 + CS_TAIL], 0
    mov  dword [r10 + CS_BOUND], -1
    mov  eax, ebx
    mov  edx, 1
    clc
    jmp  .out
.bad:
    mov  eax, -1
    xor  edx, edx
    stc
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

cons_session_count:
    xor  eax, eax
    xor  ecx, ecx
.loop:
    cmp  ecx, CONS_SESSION_MAX
    jae  .done
    mov  edx, ecx
    imul edx, CS_SIZE
    lea  r8, [rel cons_sessions]
    cmp  byte [r8 + rdx + CS_ACTIVE], 1
    jne  .next
    inc  eax
.next:
    inc  ecx
    jmp  .loop
.done:
    ret

; Copy a token without mutating the command buffer. RDI=input, RSI=dst,
; EDX=dst bytes. RAX=first byte after following spaces, ECX=len, CF on error.
cons_token_copy:
    xor  ecx, ecx
    test edx, edx
    jz   .bad
.cp:
    mov  al, [rdi + rcx]
    test al, al
    jz   .end
    cmp  al, ' '
    je   .end
    mov  r8d, ecx
    inc  r8d
    cmp  r8d, edx
    jae  .bad
    mov  [rsi + rcx], al
    inc  ecx
    jmp  .cp
.end:
    test ecx, ecx
    jz   .bad
    mov  byte [rsi + rcx], 0
    lea  rax, [rdi + rcx]
.spaces:
    cmp  byte [rax], ' '
    jne  .ok
    inc  rax
    jmp  .spaces
.ok:
    clc
    ret
.bad:
    stc
    ret

; RDI=src RSI=dst EDX=capacity. EAX=len, CF if it does not fit.
cons_cstr_copy:
    xor  eax, eax
.loop:
    cmp  eax, edx
    jae  .bad
    mov  cl, [rdi + rax]
    mov  [rsi + rax], cl
    test cl, cl
    jz   .ok
    inc  eax
    jmp  .loop
.bad:
    stc
    ret
.ok:
    clc
    ret

; Stable nonzero FNV-1a key used only inside a named session.
cons_hash_key:
    mov  rax, 0xcbf29ce484222325
.byte:
    movzx ecx, byte [rdi]
    test cl, cl
    jz   .done
    xor  rax, rcx
    mov  rdx, 0x100000001b3
    imul rax, rdx
    inc  rdi
    jmp  .byte
.done:
    test rax, rax
    jnz  .ret
    inc  rax
.ret:
    ret

; RDI=session id, RSI=line, EDX=origin, RCX=idem, R8=env -> RAX=record,
; RDX=assigned seq. Eviction happens before allocation and advances floor.
cons_record_begin:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13, rsi
    mov  ebp, edx
    mov  r14, rcx
    mov  r15, r8
    xor  eax, eax
.line_len:
    cmp  eax, CONS_LINE_MAX - 1
    jae  .fail
    cmp  byte [r13 + rax], 0
    je   .len_ok
    inc  eax
    jmp  .line_len
.len_ok:
    mov  [rel cons_record_line_len_tmp], eax
    mov  edi, r12d
    call cons_session_ptr
    mov  rbx, rax
    cmp  byte [rbx + CS_ACTIVE], 1
    jne  .fail
.make_room:
    cmp  dword [rbx + CS_COUNT], CONS_REC_CAP
    jae  .evict
    mov  eax, [rbx + CS_USED]
    add  eax, CR_RESERVED
    cmp  eax, CONS_BYTE_BUDGET
    jbe  .room
.evict:
    cmp  dword [rbx + CS_COUNT], 0
    je   .fail
    mov  edi, r12d
    mov  esi, [rbx + CS_HEAD]
    call cons_record_ptr
    mov  ecx, [rax + CR_COST]
    cmp  ecx, [rbx + CS_USED]
    ja   .used_zero
    sub  [rbx + CS_USED], ecx
    jmp  .floor
.used_zero:
    mov  dword [rbx + CS_USED], 0
.floor:
    mov  rdx, [rax + CR_SEQ]
    inc  rdx
    mov  [rbx + CS_FLOOR], rdx
    mov  eax, [rbx + CS_HEAD]
    inc  eax
    cmp  eax, CONS_REC_CAP
    jb   .head_ok
    xor  eax, eax
.head_ok:
    mov  [rbx + CS_HEAD], eax
    dec  dword [rbx + CS_COUNT]
    jmp  .make_room
.room:
    mov  esi, [rbx + CS_HEAD]
    add  esi, [rbx + CS_COUNT]
    cmp  esi, CONS_REC_CAP
    jb   .slot_ok
    sub  esi, CONS_REC_CAP
.slot_ok:
    mov  edi, r12d
    call cons_record_ptr
    mov  r10, rax
    mov  [rel cons_record_ptr_tmp], rax
    mov  rdi, r10
    xor  eax, eax
    mov  ecx, CR_SIZE
    rep  stosb
    inc  qword [rbx + CS_TAIL]
    mov  rdx, [rbx + CS_TAIL]
    cmp  dword [rbx + CS_COUNT], 0
    jne  .have_floor
    mov  [rbx + CS_FLOOR], rdx
.have_floor:
    mov  r10, [rel cons_record_ptr_tmp]
    mov  [r10 + CR_SEQ], rdx
    call tsc_now
    mov  r10, [rel cons_record_ptr_tmp]
    mov  [r10 + CR_TS], rax
    mov  [r10 + CR_IDEM], r14
    mov  [r10 + CR_ENV], r15
    mov  [r10 + CR_ORIGIN], ebp
    mov  dword [r10 + CR_COST], CR_RESERVED
    mov  rdi, r13                       ; every writer's line is classified here
    lea  rsi, [r10 + CR_LINE]
    mov  edx, CONS_LINE_MAX
    xor  ecx, ecx
    call cons_redact_line
    mov  r10, [rel cons_record_ptr_tmp]
    mov  [r10 + CR_LINE_LEN], eax
    inc  dword [rbx + CS_COUNT]
    add  dword [rbx + CS_USED], CR_RESERVED
    mov  rax, r10
    mov  rdx, [r10 + CR_SEQ]
    jmp  .out
.fail:
    xor  eax, eax
    xor  edx, edx
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=record, RSI=reply, EDX=len, RCX=result code. The reply follows the class
; of the record's own (already classified) line: cons_redact_reply.
cons_record_finish:
    push rdi
    push rsi
    push rdx
    push rcx
    push r9
    push r10
    push r11
    mov  [rdi + CR_CODE], rcx
    cmp  edx, CONS_REPLY_MAX - 1
    jbe  .len_ok
    mov  edx, CONS_REPLY_MAX - 1
.len_ok:
    lea  rcx, [rdi + CR_REPLY]
    mov  r8d, CONS_REPLY_MAX
    lea  rdi, [rdi + CR_LINE]
    call cons_redact_reply
    mov  rdi, [rsp + 48]
    mov  [rdi + CR_REPLY_LEN], eax
    pop  r11
    pop  r10
    pop  r9
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret

; Append bounded presentation fields to an already-finished record. These
; helpers extend the existing transcript reply; they never create a side log.
cons_record_append_str:                  ; RDI=record, RSI=cstr
    mov  ecx, [rdi + CR_REPLY_LEN]
    lea  r8, [rdi + CR_REPLY]
.copy:
    cmp  ecx, CONS_REPLY_MAX - 1
    jae  .done
    mov  al, [rsi]
    test al, al
    jz   .done
    mov  [r8 + rcx], al
    inc  ecx
    inc  rsi
    jmp  .copy
.done:
    mov  [rdi + CR_REPLY_LEN], ecx
    mov  byte [r8 + rcx], 0
    ret

cons_record_append_dec:                  ; RDI=record, RSI=value
    push rbx
    mov  rbx, rdi
    mov  rdi, rsi
    lea  rsi, [rel cons_job_num_buf]
    call fmt_dec
    mov  rdi, rbx
    lea  rsi, [rel cons_job_num_buf]
    call cons_record_append_str
    pop  rbx
    ret

; RDI=accepted record, ESI=session, RDX=job_id, RCX=envelope class.
; The record is extended in place once, then a bounded association remembers
; only enough information to append the eventual completion to this session.
cons_job_accept:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    mov  r15, rcx
    test r14, r14
    jz   .fail
    mov  [r12 + CR_JOBID], r14
    ; Accepted is a compact semantic envelope. The generic transport reply can
    ; already fill CR_REPLY, so replace it before adding the required job id.
    mov  dword [r12 + CR_REPLY_LEN], 0
    mov  byte [r12 + CR_REPLY], 0
    lea  rsi, [rel str_cons_job_accepted]
    call cons_record_append_str
    mov  rdi, r12
    mov  rsi, r14
    call cons_record_append_dec
    mov  rdi, r12
    lea  rsi, [rel str_cons_job_est]
    call cons_record_append_str
    mov  rdi, r12
    mov  rsi, SLOWJOB_EST_SEC
    call cons_record_append_dec
    xor  ebx, ebx
.scan:
    cmp  ebx, JOB_MAX
    jae  .fail
    mov  eax, ebx
    imul rax, CJ_SIZE
    lea  r10, [rel cons_job_tracks]
    add  r10, rax
    cmp  byte [r10 + CJ_ACTIVE], 0
    je   .claim
    inc  ebx
    jmp  .scan
.claim:
    mov  [r10 + CJ_SESSION], r13d
    mov  [r10 + CJ_ENV], r15
    mov  [r10 + CJ_JOBID], r14
    lea  rdi, [r10 + CJ_LINE]
    lea  rsi, [r12 + CR_LINE]
    mov  ecx, CONS_LINE_MAX
    cld
    rep  movsb
    mov  byte [r10 + CJ_ACTIVE], 1
    inc  qword [rel cons_job_accept_count]
    clc
    jmp  .out
.fail:
    stc
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; command-model completion callback: append a NEW origin=job record. The
; accepted record is immutable, and a bound window is rendered in-process.
cons_job_complete:                       ; RDI=job_id, RSI=state, RDX=result
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rdi
    mov  r14, rsi
    mov  r15, rdx
    xor  ebx, ebx
.scan:
    cmp  ebx, JOB_MAX
    jae  .out
    mov  eax, ebx
    imul rax, CJ_SIZE
    lea  r12, [rel cons_job_tracks]
    add  r12, rax
    cmp  byte [r12 + CJ_ACTIVE], 1
    jne  .next
    cmp  [r12 + CJ_JOBID], r13
    je   .found
.next:
    inc  ebx
    jmp  .scan
.found:
    mov  edi, [r12 + CJ_SESSION]
    lea  rsi, [r12 + CJ_LINE]
    mov  edx, CONS_ORIGIN_JOB
    xor  ecx, ecx
    mov  r8, [r12 + CJ_ENV]
    call cons_record_begin
    test rax, rax
    jz   .release
    mov  rbx, rax
    mov  [rbx + CR_JOBID], r13
    mov  qword [rbx + CR_CODE], CMDE_OK
    mov  rdi, rbx
    lea  rsi, [rel str_cons_job_completion]
    call cons_record_append_str
    mov  rdi, rbx
    mov  rsi, r13
    call cons_record_append_dec
    mov  rdi, rbx
    lea  rsi, [rel str_cons_job_status_done]
    call cons_record_append_str
    mov  rdi, rbx
    mov  rsi, r14
    call cons_record_append_dec
    mov  rdi, rbx
    lea  rsi, [rel str_cons_job_final_env]
    call cons_record_append_str
    mov  rdi, rbx
    mov  rsi, CMDE_OK
    call cons_record_append_dec
    mov  rdi, rbx
    lea  rsi, [rel str_cons_job_result]
    call cons_record_append_str
    mov  rdi, rbx
    mov  rsi, r15
    call cons_record_append_dec
    mov  edi, [r12 + CJ_SESSION]
    call cons_session_ptr
    cmp  byte [rax + CS_ACTIVE], 1
    jne  .count
    cmp  dword [rax + CS_BOUND], -1
    je   .count
    mov  rax, [rel cons_render_cb]
    test rax, rax
    jz   .count
    lea  rdi, [rbx + CR_LINE]
    lea  rsi, [rbx + CR_REPLY]
    mov  edx, [rbx + CR_REPLY_LEN]
    mov  ecx, CONS_ORIGIN_JOB
    mov  r8, [rbx + CR_CODE]
    call rax
.count:
    inc  qword [rel cons_job_completion_count]
.release:
    mov  byte [r12 + CJ_ACTIVE], 0
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

cons_record_find_idem:                   ; EDI=session, RSI=hash -> RAX=record/0
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
    call cons_session_ptr
    mov  rbx, rax
    xor  ecx, ecx
.scan:
    cmp  ecx, [rbx + CS_COUNT]
    jae  .miss
    mov  esi, [rbx + CS_HEAD]
    add  esi, ecx
    cmp  esi, CONS_REC_CAP
    jb   .idx_ok
    sub  esi, CONS_REC_CAP
.idx_ok:
    mov  edi, r12d
    push rcx
    call cons_record_ptr
    pop  rcx
    cmp  [rax + CR_IDEM], r13
    je   .out
    inc  ecx
    jmp  .scan
.miss:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

cons_stage_bad:
    call grid_out_reset
    call grid_out_str
    mov  byte [rel grid_out_ready], 1
    ret

cmd_verb_cons_list:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  r12, rsi
    mov  rax, [rdi + REQ_ARG]
    test rax, rax
    jz   .bad
    cmp  byte [rax], 0
    jne  .bad
    call grid_out_reset
    lea  rdi, [rel str_cons_list_head]
    call grid_out_str
    call cons_session_count
    mov  rdi, rax
    call grid_out_dec
    xor  ebx, ebx
.loop:
    cmp  ebx, CONS_SESSION_MAX
    jae  .ready
    mov  edi, ebx
    call cons_session_ptr
    cmp  byte [rax + CS_ACTIVE], 1
    jne  .next
    push rax
    lea  rdi, [rel str_cons_list_row]
    call grid_out_str
    pop  rax
    push rax
    lea  rdi, [rax + CS_NAME]
    call grid_out_str
    lea  rdi, [rel str_cons_list_seq]
    call grid_out_str
    pop  rax
    push rax
    mov  rdi, [rax + CS_TAIL]
    call grid_out_dec
    lea  rdi, [rel str_cons_list_floor]
    call grid_out_str
    pop  rax
    push rax
    mov  rdi, [rax + CS_FLOOR]
    call grid_out_dec
    lea  rdi, [rel str_cons_list_bound]
    call grid_out_str
    pop  rax
    mov  edi, [rax + CS_BOUND]
    cmp  edi, -1
    je   .none
    call grid_out_dec
    jmp  .bound_done
.none:
    lea  rdi, [rel str_cons_none]
    call grid_out_str
.bound_done:
    lea  rdi, [rel str_cons_records]
    call grid_out_str
    mov  edi, ebx
    call cons_session_ptr
    push rax
    mov  edi, [rax + CS_COUNT]
    call grid_out_dec
    lea  rdi, [rel str_cons_bytes]
    call grid_out_str
    pop  rax
    mov  edi, [rax + CS_USED]
    call grid_out_dec
    lea  rdi, [rel str_cons_budget]
    call grid_out_str
.next:
    inc  ebx
    jmp  .loop
.ready:
    mov  byte [rel grid_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    call cons_session_count
    mov  [r12 + RSP_VAL], rax
    jmp  .out
.bad:
    lea  rdi, [rel str_cons_list_bad]
    call cons_stage_bad
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
.out:
    pop  r12
    pop  rbx
    ret

cmd_verb_cons_new:
    call cmd_handler_prologue
    push r12
    push r13
    mov  r12, rsi
    mov  r13, [rdi + REQ_ARG]
    mov  rdi, r13
    call cons_session_create
    jc   .bad
    push rax
    push rdx
    call grid_out_reset
    lea  rdi, [rel str_cons_new_ok]
    call grid_out_str
    mov  rdi, r13
    call grid_out_str
    lea  rdi, [rel str_cons_created]
    call grid_out_str
    pop  rdi
    call grid_out_dec
    lea  rdi, [rel str_cons_id]
    call grid_out_str
    pop  rdi
    mov  [r12 + RSP_VAL], rdi
    call grid_out_dec
    mov  byte [rel grid_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  qword [r12 + RSP_ACCEPTED], 1
    jmp  .out
.bad:
    lea  rdi, [rel str_cons_new_bad]
    call cons_stage_bad
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
.out:
    pop  r13
    pop  r12
    ret

cmd_verb_cons_close:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, [rdi + REQ_ARG]
    mov  rdi, r13
    call cons_session_find
    cmp  eax, -1
    je   .bad
    mov  ebx, eax
    mov  edi, ebx
    call cons_session_ptr
    cmp  dword [rax + CS_BOUND], -1
    je   .destroy
    mov  rdx, rax
    mov  rax, [rel cons_render_cb]
    test rax, rax
    jz   .destroy
    push rdx
    lea  rdi, [rel str_cons_terminal_closed]
    lea  rsi, [rdx + CS_NAME]
    xor  edx, edx
.name_len:
    cmp  byte [rsi + rdx], 0
    je   .notice
    inc  edx
    jmp  .name_len
.notice:
    mov  ecx, CONS_ORIGIN_ATTACH
    xor  r8d, r8d
    call rax
    pop  rdx
    mov  rax, rdx
.destroy:
    mov  byte [rax + CS_ACTIVE], 0
    mov  dword [rax + CS_BOUND], -1
    cmp  ebx, [rel cons_bound_session]
    jne  .reply
    mov  dword [rel cons_bound_session], -1
.reply:
    call grid_out_reset
    lea  rdi, [rel str_cons_close_ok]
    call grid_out_str
    mov  rdi, r13
    call grid_out_str
    mov  byte [rel grid_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  qword [r12 + RSP_ACCEPTED], 1
    mov  [r12 + RSP_VAL], rbx
    jmp  .out
.bad:
    lea  rdi, [rel str_cons_close_bad]
    call cons_stage_bad
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

cons_parse_u64_full:                    ; RDI=decimal/NUL -> RAX, CF on malformed
    xor  eax, eax
    xor  ecx, ecx
.digit:
    movzx edx, byte [rdi]
    test dl, dl
    jz   .done
    cmp  dl, '0'
    jb   .bad
    cmp  dl, '9'
    ja   .bad
    sub  edx, '0'
    imul rax, rax, 10
    jo   .bad
    add  rax, rdx
    jc   .bad
    inc  rdi
    inc  ecx
    jmp  .digit
.done:
    ; Empty is the registry's established numeric default (STATUS -> liveness).
    clc
    ret
.bad:
    stc
    ret

; RDI=record, ESI=duplicate. Emits the cached inner result and current execution
; count; a duplicate path never reaches command_dispatch.
cons_stage_submit_record:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, esi
    call grid_out_reset
    lea  rdi, [rel str_cons_submit_ok]
    call grid_out_str
    lea  rdi, [rel cons_submit_name]
    call grid_out_str
    lea  rdi, [rel str_cons_idem]
    call grid_out_str
    mov  rdi, [rbx + CR_IDEM]
    call grid_out_dec
    lea  rdi, [rel str_cons_seq]
    call grid_out_str
    mov  rdi, [rbx + CR_SEQ]
    call grid_out_dec
    lea  rdi, [rel str_cons_duplicate]
    call grid_out_str
    mov  edi, r12d
    call grid_out_dec
    lea  rdi, [rel str_cons_exec_count]
    call grid_out_str
    mov  rdi, [rel cons_inner_exec_count]
    call grid_out_dec
    lea  rdi, [rel str_cons_inner]
    call grid_out_str
    lea  rdi, [rbx + CR_REPLY]
    call grid_out_str
    mov  byte [rel grid_out_ready], 1
    pop  r12
    pop  rbx
    ret

; Idempotency suppresses execution, never authorization.  A retry is classified
; from the cached ORIGINAL verb (not attacker-controlled retry text), then runs
; the same live metadata/AUTH1 gate as dispatch without invoking its handler.
; RDI=outer request, ESI=inner verb id, RDX=outer response -> EAX=CMDE_*.
cons_authorize_cached_submit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  ebx, esi
    mov  r13, rdx
    mov  edi, ebx
    call command_verb_name
    mov  r14, rax
    cmp  qword [r12 + REQ_SOURCE], CMD_SOURCE_CONSOLE
    jne  .remote
    cmp  qword [r12 + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne  .authdeny
    jmp  .legacy_cap
.remote:
    cmp  byte [rel command_auth_remote_active], 1
    jne  .legacy_cap
    mov  edi, ebx
    call command_verb_cap
    mov  r15, rax
    mov  edi, ebx
    call command_verb_destr
    mov  rdx, rax
    mov  rdi, r14
    mov  rsi, r15
    call command_auth_required_cap
    test rax, rax
    jz   .allowed
    mov  rdi, rax
    mov  rsi, r14
    call command_auth_gate
    test eax, eax
    jz   .allowed
.authdeny:
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    mov  edi, ebx
    call command_verb_cap
    mov  [r13 + RSP_EXPECTED], rax
    lea  rax, [rel command_auth_out_buf]
    mov  [r13 + RSP_HINT], rax
    mov  eax, CMDE_AUTHDENY
    jmp  .out
.legacy_cap:
    mov  edi, ebx
    call command_verb_cap
    cmp  [r12 + REQ_CAP], rax
    jae  .allowed
    mov  qword [r13 + RSP_CODE], CMDE_CAPDENY
    mov  [r13 + RSP_EXPECTED], rax
    mov  eax, CMDE_CAPDENY
    jmp  .out
.allowed:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

cmd_verb_cons_submit:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                       ; outer request (holds AUTH1 principal/source)
    mov  r13, rsi                       ; outer response
    mov  rdi, [r12 + REQ_ARG]
    lea  rsi, [rel cons_submit_name]
    mov  edx, CONS_NAME_MAX + 1
    call cons_token_copy
    jc   .bad_arg
    mov  rdi, rax
    lea  rsi, [rel cons_submit_key]
    mov  edx, 64
    call cons_token_copy
    jc   .bad_arg
    mov  r14, rax                       ; complete inner verb line
    cmp  byte [r14], 0
    je   .bad_arg
    mov  rdi, r14
    lea  rsi, [rel cons_submit_line]
    mov  edx, CONS_LINE_MAX
    call cons_cstr_copy
    jc   .bad_arg
    mov  rdi, r14
    lea  rsi, [rel cons_inner_line]
    mov  edx, CONS_LINE_MAX
    call cons_cstr_copy
    jc   .bad_arg

    lea  rdi, [rel cons_submit_name]
    call cons_session_find
    cmp  eax, -1
    je   .bad_session
    mov  r15d, eax
    lea  rdi, [rel cons_submit_key]
    call cons_hash_key
    mov  rbx, rax
    mov  [r12 + REQ_IDEM], rax           ; reuse the canonical envelope field
    mov  edi, r15d
    mov  rsi, rbx
    call cons_record_find_idem
    mov  [rel cons_duplicate_record_tmp], rax
    test rax, rax
    jz   .split_inner
    ; A duplicate key returns the original record even if retry text differs.
    ; Classify the cached line so public-looking replacement text cannot expose
    ; a privileged cached result without the privileged verb's own AUTH1 gate.
    lea  rdi, [rax + CR_LINE]
    lea  rsi, [rel cons_inner_line]
    mov  edx, CONS_LINE_MAX
    call cons_cstr_copy
    jc   .bad_inner

    ; Split the private copy. The transcript retains cons_submit_line unchanged.
.split_inner:
    lea  r14, [rel cons_inner_line]
    mov  rax, r14
.find_space:
    cmp  byte [rax], 0
    je   .no_arg
    cmp  byte [rax], ' '
    je   .have_arg
    inc  rax
    jmp  .find_space
.have_arg:
    mov  byte [rax], 0
    inc  rax
.skip_arg_space:
    cmp  byte [rax], ' '
    jne  .arg_ready
    inc  rax
    jmp  .skip_arg_space
.no_arg:
.arg_ready:
    mov  [rel cons_inner_arg_ptr], rax
    mov  rdi, r14
    call command_lookup
    cmp  eax, -1
    je   .bad_inner
    mov  [rel cons_inner_verb_id], eax
    cmp  qword [rel cons_duplicate_record_tmp], 0
    je   .new_submission
    mov  rdi, r12
    mov  esi, eax
    mov  rdx, r13
    call cons_authorize_cached_submit
    test eax, eax
    jnz  .out
    mov  rbx, [rel cons_duplicate_record_tmp]
    jmp  .duplicate

.new_submission:
    lea  rdi, [rel cons_inner_req]
    mov  [rdi + REQ_VERB], rax
    mov  rax, [r12 + REQ_CAP]
    mov  [rdi + REQ_CAP], rax
    mov  [rdi + REQ_IDEM], rbx
    mov  qword [rdi + REQ_SEL], 0
    mov  rax, [r12 + REQ_SOURCE]
    mov  [rdi + REQ_SOURCE], rax
    mov  rax, [r12 + REQ_PRINCIPAL]
    mov  [rdi + REQ_PRINCIPAL], rax
    mov  edi, [rel cons_inner_verb_id]
    call command_verb_argt
    cmp  eax, ARGT_TEXT
    je   .text_arg
    cmp  eax, ARGT_NONE
    je   .zero_arg
    mov  rdi, [rel cons_inner_arg_ptr]
    call cons_parse_u64_full
    jc   .bad_inner
    jmp  .set_arg
.zero_arg:
    xor  eax, eax
.set_arg:
    mov  [rel cons_inner_req + REQ_ARG], rax
    jmp  .dispatch
.text_arg:
    mov  rax, [rel cons_inner_arg_ptr]
    mov  [rel cons_inner_req + REQ_ARG], rax
.dispatch:
    lea  rdi, [rel cons_inner_req]
    lea  rsi, [rel cons_inner_rsp]
    call command_dispatch                 ; same registry, same live AUTH1 ticket
    mov  r14, [rel cons_inner_rsp + RSP_CODE]
    cmp  r14, CMDE_AUTHDENY
    je   .auth_refused                    ; refusal is not transcript material
    inc  qword [rel cons_inner_exec_count]

    lea  rdi, [rel cons_inner_line]
    mov  rsi, [rel cons_inner_arg_ptr]
    lea  rdx, [rel cons_inner_rsp]
    call command_udp_capture_reply
    mov  [rel cons_inner_reply_ptr], rax
    mov  [rel cons_inner_reply_len], edx
    mov  r8, CONS_ENV_UNSIGNED
    cmp  qword [r12 + REQ_SOURCE], CMD_SOURCE_CONSOLE
    jne  .remote_env
    mov  r8, CONS_ENV_LOCAL
    jmp  .record
.remote_env:
    cmp  qword [r12 + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne  .record
    mov  r8, CONS_ENV_OWNER
.record:
    mov  [rel cons_inner_env_tmp], r8
    mov  edi, r15d
    lea  rsi, [rel cons_submit_line]
    mov  edx, CONS_ORIGIN_UDP
    mov  rcx, rbx
    call cons_record_begin
    test rax, rax
    jz   .full
    mov  rbx, rax                       ; record
    mov  rdi, rbx
    mov  rsi, [rel cons_inner_reply_ptr]
    mov  edx, [rel cons_inner_reply_len]
    mov  rcx, r14
    call cons_record_finish

    ; Only an INNER accepted envelope grows the transcript into a job pair.
    ; CONS_SUBMIT's own acceptance bit is transport/session bookkeeping and is
    ; deliberately irrelevant here, so fast verbs remain single-record.
    cmp  qword [rel cons_inner_rsp + RSP_ACCEPTED], 1
    jne  .status_shape
    mov  rdx, [rel cons_inner_rsp + RSP_JOBID]
    test rdx, rdx
    jz   .status_shape
    mov  rdi, rbx
    mov  esi, r15d
    mov  rcx, [rel cons_inner_env_tmp]
    call cons_job_accept
    jc   .full
.status_shape:
    mov  eax, [rel cons_inner_verb_id]
    cmp  eax, [rel verb_id_status]
    jne  .render
    cmp  qword [rel cons_inner_req + REQ_ARG], 0
    je   .render
    mov  dword [rbx + CR_REPLY_LEN], 0
    mov  byte [rbx + CR_REPLY], 0
    test r14, r14
    jz   .status_ok
    mov  rdi, rbx
    lea  rsi, [rel str_cons_job_error]
    call cons_record_append_str
    mov  rdi, rbx
    mov  rsi, r14
    call cons_record_append_dec
    mov  rdi, rbx
    lea  rsi, [rel str_cons_job_hint]
    call cons_record_append_str
    mov  rsi, [rel cons_inner_rsp + RSP_HINT]
    test rsi, rsi
    jz   .render
    mov  rdi, rbx
    call cons_record_append_str
    jmp  .render
.status_ok:
    mov  rdi, rbx
    lea  rsi, [rel str_cons_job_state]
    call cons_record_append_str
    mov  rax, [rel cons_inner_rsp + RSP_VAL]
    cmp  rax, JOB_ST_RUN
    jne  .status_done
    mov  rdi, rbx
    lea  rsi, [rel str_cons_job_running]
    call cons_record_append_str
    jmp  .render
.status_done:
    cmp  rax, JOB_ST_DONE
    jne  .status_numeric
    mov  rdi, rbx
    lea  rsi, [rel str_cons_job_done]
    call cons_record_append_str
    jmp  .render
.status_numeric:
    mov  rdi, rbx
    mov  rsi, rax
    call cons_record_append_dec

    ; A remote submission becomes pixels only when this session is bound.
.render:
    mov  edi, r15d
    call cons_session_ptr
    cmp  dword [rax + CS_BOUND], -1
    je   .stage_new
    mov  rax, [rel cons_render_cb]
    test rax, rax
    jz   .stage_new
    lea  rdi, [rbx + CR_LINE]
    lea  rsi, [rbx + CR_REPLY]
    mov  edx, [rbx + CR_REPLY_LEN]
    mov  ecx, [rbx + CR_ORIGIN]
    mov  r8, [rbx + CR_CODE]
    call rax
.stage_new:
    mov  rdi, rbx
    xor  esi, esi
    call cons_stage_submit_record
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_ACCEPTED], 1
    mov  rax, [rbx + CR_SEQ]
    mov  [r13 + RSP_VAL], rax
    jmp  .out
.duplicate:
    mov  rdi, rbx
    mov  esi, 1
    call cons_stage_submit_record
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_ACCEPTED], 1
    mov  rax, [rbx + CR_SEQ]
    mov  [r13 + RSP_VAL], rax
    jmp  .out
.auth_refused:
    ; Preserve the inner gate's actionable envelope; command_auth_out_buf is
    ; already staged and the outer UDP projection will send it verbatim.
    lea  rsi, [rel cons_inner_rsp]
    mov  rdi, r13
    mov  ecx, RSP_SZ / 8
    rep  movsq
    jmp  .out
.bad_session:
    lea  rdi, [rel str_cons_submit_bad_session]
    jmp  .bad
.bad_inner:
    lea  rdi, [rel str_cons_submit_bad_inner]
    jmp  .bad
.full:
    lea  rdi, [rel str_cons_submit_full]
    jmp  .bad
.bad_arg:
    lea  rdi, [rel str_cons_submit_bad_arg]
.bad:
    call cons_stage_bad
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

cons_out_origin:                         ; EDI=origin
    cmp  edi, CONS_ORIGIN_KBD
    je   .kbd
    cmp  edi, CONS_ORIGIN_UDP
    je   .udp
    cmp  edi, CONS_ORIGIN_JOB
    je   .job
    lea  rdi, [rel str_cons_origin_attach]
    jmp  grid_out_str
.kbd:
    lea  rdi, [rel str_cons_origin_kbd]
    jmp  grid_out_str
.udp:
    lea  rdi, [rel str_cons_origin_udp]
    jmp  grid_out_str
.job:
    lea  rdi, [rel str_cons_origin_job]
    jmp  grid_out_str

cmd_verb_cons_read:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  rdi, [rdi + REQ_ARG]
    lea  rsi, [rel cons_read_name]
    mov  edx, CONS_NAME_MAX + 1
    call cons_token_copy
    jc   .bad_arg
    cmp  dword [rax], 'from'
    jne  .bad_arg
    cmp  byte [rax + 4], '='
    jne  .bad_arg
    lea  rdi, [rax + 5]
    call cons_parse_u64_full
    jc   .bad_arg
    mov  r14, rax                       ; requested sequence
    lea  rdi, [rel cons_read_name]
    call cons_session_find
    cmp  eax, -1
    je   .bad_session
    mov  r15d, eax
    mov  edi, r15d
    call cons_session_ptr
    mov  rbx, rax
    mov  rax, [rbx + CS_FLOOR]
    cmp  r14, rax
    jae  .from_ok
    mov  r14, rax                       ; honest clamp from below floor
.from_ok:
    xor  r13d, r13d                     ; available records
    mov  rax, [rbx + CS_TAIL]
    cmp  rax, r14
    jb   .counts
    sub  rax, r14
    inc  rax
    mov  r13d, eax
.counts:
    mov  eax, r13d
    cmp  eax, CONS_PAGE_RECS
    jbe  .emit_count_ok
    mov  eax, CONS_PAGE_RECS
.emit_count_ok:
    mov  [rel cons_last_read_emitted], eax
    mov  dword [rel cons_last_read_more], 0
    mov  qword [rel cons_last_read_next], 0
    cmp  r13d, eax
    jbe  .header
    mov  dword [rel cons_last_read_more], 1
    mov  rcx, r14
    add  rcx, rax
    mov  [rel cons_last_read_next], rcx
.header:
    call grid_out_reset
    lea  rdi, [rel str_cons_read_head]
    call grid_out_str
    lea  rdi, [rel cons_read_name]
    call grid_out_str
    lea  rdi, [rel str_cons_list_floor]
    call grid_out_str
    mov  rdi, [rbx + CS_FLOOR]
    call grid_out_dec
    lea  rdi, [rel str_cons_list_seq]
    call grid_out_str
    mov  rdi, [rbx + CS_TAIL]
    call grid_out_dec
    lea  rdi, [rel str_cons_from]
    call grid_out_str
    mov  rdi, r14
    call grid_out_dec
    lea  rdi, [rel str_cons_next]
    call grid_out_str
    mov  rdi, [rel cons_last_read_next]
    call grid_out_dec
    lea  rdi, [rel str_cons_more]
    call grid_out_str
    mov  edi, [rel cons_last_read_more]
    call grid_out_dec
    xor  r13d, r13d
.emit:
    cmp  r13d, [rel cons_last_read_emitted]
    jae  .ready
    mov  rax, r14
    add  rax, r13
    sub  rax, [rbx + CS_FLOOR]
    add  eax, [rbx + CS_HEAD]
    cmp  eax, CONS_REC_CAP
    jb   .idx_ok
    sub  eax, CONS_REC_CAP
.idx_ok:
    mov  edi, r15d
    mov  esi, eax
    call cons_record_ptr
    mov  [rel cons_read_record_tmp], rax
    lea  rdi, [rel str_cons_read_row]
    call grid_out_str
    mov  rax, [rel cons_read_record_tmp]
    mov  rdi, [rax + CR_SEQ]
    call grid_out_dec
    lea  rdi, [rel str_cons_origin]
    call grid_out_str
    mov  rax, [rel cons_read_record_tmp]
    mov  edi, [rax + CR_ORIGIN]
    call cons_out_origin
    lea  rdi, [rel str_cons_job_id]
    call grid_out_str
    mov  rax, [rel cons_read_record_tmp]
    mov  rdi, [rax + CR_JOBID]
    call grid_out_dec
    lea  rdi, [rel str_cons_env]
    call grid_out_str
    mov  rax, [rel cons_read_record_tmp]
    mov  rdi, [rax + CR_ENV]
    call grid_out_dec
    lea  rdi, [rel str_cons_final_status]
    call grid_out_str
    mov  rax, [rel cons_read_record_tmp]
    mov  rdi, [rax + CR_CODE]
    call grid_out_dec
    lea  rdi, [rel str_cons_ts]
    call grid_out_str
    mov  rax, [rel cons_read_record_tmp]
    mov  rdi, [rax + CR_TS]
    call grid_out_dec
    lea  rdi, [rel str_cons_line]
    call grid_out_str
    mov  rax, [rel cons_read_record_tmp]
    lea  rdi, [rax + CR_LINE]
    call grid_out_str
    lea  rdi, [rel str_cons_reply]
    call grid_out_str
    mov  rax, [rel cons_read_record_tmp]
    mov  edi, [rax + CR_REPLY_LEN]
    call grid_out_dec
    lea  rdi, [rel str_cons_reply_data]
    call grid_out_str
    mov  rax, [rel cons_read_record_tmp]
    lea  rdi, [rax + CR_REPLY]
    call grid_out_str
    inc  r13d
    jmp  .emit
.ready:
    mov  byte [rel grid_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  rax, [rel cons_last_read_next]
    mov  [r12 + RSP_VAL], rax
    jmp  .out
.bad_session:
    lea  rdi, [rel str_cons_read_bad_session]
    jmp  .bad
.bad_arg:
    lea  rdi, [rel str_cons_read_bad_arg]
.bad:
    call cons_stage_bad
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; GUI binding: close/reopen changes only CS_BOUND. Replay walks the retained
; ring and calls the one L6 renderer; it owns no second glyph engine.
; ---------------------------------------------------------------------------
cons_window_unbind:                       ; EDI=window
    push rbx
    mov  ebx, edi
    xor  ecx, ecx
.scan:
    cmp  ecx, CONS_SESSION_MAX
    jae  .done
    mov  edi, ecx
    call cons_session_ptr
    cmp  byte [rax + CS_ACTIVE], 1
    jne  .next
    cmp  [rax + CS_BOUND], ebx
    jne  .next
    mov  dword [rax + CS_BOUND], -1
.next:
    inc  ecx
    jmp  .scan
.done:
    mov  dword [rel cons_bound_session], -1
    pop  rbx
    ret

cons_window_bind_default:                 ; EDI=window -> EAX=session id/-1, EDX=count
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  edi, r12d
    call cons_window_unbind
    lea  rdi, [rel str_cons_owner]
    call cons_session_find
    cmp  eax, -1
    jne  .found
    lea  rdi, [rel str_cons_owner]
    call cons_session_create
    jc   .bad
.found:
    mov  r13d, eax
    mov  [rel cons_bound_session], eax
    mov  edi, eax
    call cons_session_ptr
    mov  rbx, rax
    mov  [rbx + CS_BOUND], r12d
    mov  rax, [rel cons_render_cb]
    test rax, rax
    jz   .ret_ok
    xor  r12d, r12d
.replay:
    cmp  r12d, [rbx + CS_COUNT]
    jae  .ret_ok
    mov  esi, [rbx + CS_HEAD]
    add  esi, r12d
    cmp  esi, CONS_REC_CAP
    jb   .idx_ok
    sub  esi, CONS_REC_CAP
.idx_ok:
    mov  edi, r13d
    call cons_record_ptr
    mov  r10, rax
    mov  rax, [rel cons_render_cb]
    lea  rdi, [r10 + CR_LINE]
    lea  rsi, [r10 + CR_REPLY]
    mov  edx, [r10 + CR_REPLY_LEN]
    mov  ecx, [r10 + CR_ORIGIN]
    mov  r8, [r10 + CR_CODE]
    call rax
    inc  r12d
    jmp  .replay
.ret_ok:
    mov  edx, [rbx + CS_COUNT]
    mov  eax, r13d
    jmp  .out
.bad:
    mov  eax, -1
    xor  edx, edx
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

cons_keyboard_begin:                      ; RDI=line -> RAX=seq/0
    push r12
    mov  r12, rdi
    mov  edi, [rel cons_bound_session]
    cmp  edi, 0
    jl   .bad
    mov  rsi, r12
    mov  edx, CONS_ORIGIN_KBD
    xor  ecx, ecx
    mov  r8, CONS_ENV_LOCAL
    call cons_record_begin
    mov  [rel cons_pending_kbd_rec], rax
    mov  edi, [rel cons_bound_session]
    mov  [rel cons_pending_kbd_session], edi
    mov  rax, rdx
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    ret

; RDI=reply RSI=len RDX=result code RCX=job_id R8=accepted.
cons_keyboard_finish:
    push r12
    push r13
    push r14
    mov  r12, [rel cons_pending_kbd_rec]
    mov  r13, rcx
    mov  r14, r8
    test r12, r12
    jz   .out
    mov  rcx, rdx
    mov  edx, esi
    mov  rsi, rdi
    mov  rdi, r12
    call cons_record_finish
    inc  qword [rel cons_inner_exec_count]
    cmp  r14, 1
    jne  .clear
    test r13, r13
    jz   .clear
    mov  rdi, r12
    mov  esi, [rel cons_pending_kbd_session]
    mov  rdx, r13
    mov  rcx, CONS_ENV_LOCAL
    call cons_job_accept
.clear:
    mov  qword [rel cons_pending_kbd_rec], 0
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; RCQ-22 Terminal transcript parity: a Terminal window records its native
; command lines into its OWN named session (found or created on first use) with
; the Console keyboard line's record shape: origin kbd, env local, the same
; sequence numbers, ring/byte bounds, job completion and CONS_READ authority.
; CS_BOUND stays -1, so no Console renderer ever runs for these sessions, and
; the Console's bound-session keyboard path above is untouched.
; cons_local_begin(RDI=session name, RSI=line) -> RAX=record/0, EDX=session/-1
;   (EDX=-1: no session - not declared yet, an invalid name or a full table).
cons_local_begin:
    push rbx
    push r12
    mov  r12, rsi
    cmp  byte [rel cons_registered], 1
    jne  .none
    call cons_session_create             ; finds an existing name first
    jc   .none
    mov  ebx, eax
    mov  edi, eax
    mov  rsi, r12
    mov  edx, CONS_ORIGIN_KBD
    xor  ecx, ecx
    mov  r8, CONS_ENV_LOCAL
    call cons_record_begin               ; RAX=0 for an over-long line
    mov  edx, ebx
    jmp  .out
.none:
    xor  eax, eax
    mov  edx, -1
.out:
    pop  r12
    pop  rbx
    ret

; cons_local_finish(RDI=record/0, RSI=reply, EDX=len, RCX=result code,
;   R8=accepted job id/0, R9D=session): the reply, then (for an accepted job)
;   the same completion association a Console keyboard line gets.
cons_local_finish:
    test rdi, rdi
    jz   .out
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, r8
    mov  r14d, r9d
    call cons_record_finish
    inc  qword [rel cons_inner_exec_count]  ; as cons_keyboard_finish counts a typed line
    test r13, r13
    jz   .done
    mov  rdi, r12
    mov  esi, r14d
    mov  rdx, r13
    mov  rcx, CONS_ENV_LOCAL
    call cons_job_accept
.done:
    pop  r14
    pop  r13
    pop  r12
.out:
    ret

; RCQ-22 (srcreview 2026-10-08 10:09): a transcript keeps only the verb of a
; line whose argument or reply can carry a secret. The list is the UDP audit's
; credential verbs plus str_cons_secret_verbs:
;   - secret store: DSECPUT argument, DSECGET/DSECGETAS plaintext reply,
;     DSECUNWRAP credential;
;   - KV values: DBPUT/DBPUTKILL argument, DBGET reply;
;   - principal tokens and KDF input/output: PRINWRITE, PRINREAD, PRINKDF;
;   - keystrokes or pasted text that may be a password: GUESTKEY, KBINJ, KBDBUF
;     (the raw keyboard ring), TERMFEED, CLIPSET/CLIPGET, CDPBRIDGE;
;   - fresh CSPRNG bytes: RANDOM;
;   - replays of other lines: AUDIT (UDP command lines), CONS_READ, CONSGRID,
;     CONS_SUBMIT (an inner command line);
;   - HOOK (RCQ-15): its arguments are an inner native argument (TERMFEED keys,
;     WIDGETSET text).
; Several are conservative pending an rc-sec ruling. test_rc_terminal_alias_host.py
; derives every registered verb from source and requires each one to be in this
; list or in its reviewed transcript-safe list.
; cons_secret_verb(RDI=canonical upper-case verb) -> EAX 1 secret / 0.
cons_secret_verb:
    push rbx
    mov  rbx, rdi
    call udp_net_is_credential_verb
    test eax, eax
    jnz  .out
    lea  rsi, [rel str_cons_secret_verbs]
.scan:
    cmp  byte [rsi], 0
    je   .no
    mov  rdi, rbx
    push rsi
    call strcmp
    pop  rsi
    test eax, eax
    jz   .yes
.skip:
    inc  rsi
    cmp  byte [rsi - 1], 0
    jne  .skip
    jmp  .scan
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  rbx
    ret

; SEC-transcript-user-data-verbs: one transcript classifier for every writer.
; cons_verb_class(RDI=canonical verb) -> EAX=class, RDX=the user-data row's two
; keep bytes (line targets, reply head tokens) or 0. SECRET: the argument or the
; reply can carry a secret (cons_secret_verb). USER_DATA: the argument or the
; reply carries file/sector/typed/fetched content (str_cons_user_data_verbs).
; Uncertain -> payload: a verb on neither list that is not registered is SECRET
; with EDX=1, and the recorder names it "<unknown>": its bytes are the caller's
; (a password typed alone, or 'AUTHLOGIN<TAB><pw>'), never a verb name.
cons_verb_class:
    push rbx
    mov  rbx, rdi
    cmp  byte [rbx], 0
    je   .safe
    call cons_secret_verb
    test eax, eax
    jnz  .secret
    lea  rsi, [rel str_cons_user_data_verbs]
.scan:
    cmp  byte [rsi], 0
    je   .registered
    mov  rdi, rbx
    push rsi
    call strcmp
    pop  rsi
    mov  ecx, eax
.skip:
    inc  rsi
    cmp  byte [rsi - 1], 0
    jne  .skip
    test ecx, ecx
    jz   .user
    add  rsi, 2                         ; the row's keep bytes
    jmp  .scan
.user:
    mov  rdx, rsi
    mov  eax, CONS_CLASS_USER
    jmp  .out
.registered:
    mov  rdi, rbx
    call command_lookup
    cmp  rax, -1
    je   .unknown
.safe:
    xor  eax, eax
    xor  edx, edx
    jmp  .out
.secret:
    mov  eax, CONS_CLASS_SECRET
    xor  edx, edx
    jmp  .out
.unknown:
    mov  eax, CONS_CLASS_SECRET
    mov  edx, 1
.out:
    pop  rbx
    ret

; cons_line_class(RDI=line) -> EAX=class, RDX=keep bytes/0, RSI=arguments.
; The verb is the first space-delimited token after leading spaces, split as
; the Console and CONS_SUBMIT split it (exact case). A verb longer than
; CONS_CLASS_VERB_MAX - 1 is SECRET and unknown (EDX=1).
cons_line_class:
    push rbx
    mov  rbx, rdi
.lead:
    cmp  byte [rbx], ' '
    jne  .verb
    inc  rbx
    jmp  .lead
.verb:
    cmp  byte [rbx], '/'
    jne  .token
    inc  rbx                              ; Console presentation prefix
    jmp  .lead
.token:
    lea  rdi, [rel cons_class_verb]
    xor  ecx, ecx
.copy:
    mov  al, [rbx + rcx]
    test al, al
    jz   .end
    cmp  al, ' '
    je   .end
    cmp  ecx, CONS_CLASS_VERB_MAX - 1
    jae  .long
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .copy
.long:
    mov  byte [rdi + rcx], 0
.long_skip:
    mov  al, [rbx + rcx]
    test al, al
    jz   .long_args
    cmp  al, ' '
    je   .long_args
    inc  ecx
    jmp  .long_skip
.long_args:
    add  rbx, rcx
    call .skip_spaces
    mov  eax, CONS_CLASS_SECRET
    mov  edx, 1
    jmp  .out
.end:
    mov  byte [rdi + rcx], 0
    add  rbx, rcx
    call .skip_spaces
    lea  rdi, [rel cons_class_verb]
    call cons_verb_class
.out:
    mov  rsi, rbx
    pop  rbx
    ret
.skip_spaces:
    cmp  byte [rbx], ' '
    jne  .skipped
    inc  rbx
    jmp  .skip_spaces
.skipped:
    ret

; cons_redact_line(RDI=line, RSI=dst, EDX=dst capacity incl. NUL, RCX=canonical
; verb or 0) -> EAX=length written, ECX=class. SAFE: the line verbatim.
; SECRET: "<VERB> <redacted>", or "<unknown> <redacted>" when the first token is
; no registered verb. USER_DATA: "<VERB>", the row's leading target tokens
; (CONS_KEEP_QCUT: the last one is a URL, kept as scheme://host[:port] only; a
; control byte ends the targets), then " <redacted N bytes>" for the N bytes
; not kept. A canonical verb (the UDP audit) classifies
; and names the row instead of the line's own first token. Output is bounded:
; a cut drops the tail, never moves payload forward.
cons_redact_line:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r15, rdi
    mov  r12, rsi
    xor  r13d, r13d
    lea  r14d, [rdx - 1]
    mov  rbx, rcx
    mov  dword [rel cons_redact_drop], 0
    call cons_line_class
    mov  ebp, eax
    mov  [rel cons_redact_row], rdx
    mov  [rel cons_redact_args], rsi
    lea  rax, [rel cons_class_verb]
    mov  [rel cons_redact_verb], rax
    test rbx, rbx
    jz   .classed
    mov  [rel cons_redact_verb], rbx
    mov  rdi, rbx
    call cons_verb_class
    mov  ebp, eax
    mov  [rel cons_redact_row], rdx
.classed:
    cmp  ebp, CONS_CLASS_SAFE
    jne  .verb
    mov  rsi, r15
    call cons_redact_put_str
    jmp  .done
.verb:
    mov  rsi, [rel cons_redact_verb]
    cmp  ebp, CONS_CLASS_SECRET
    jne  .named
    cmp  qword [rel cons_redact_row], 1
    jne  .named
    lea  rsi, [rel str_cons_unknown]    ; srcreview R1: never the caller's token
.named:
    call cons_redact_put_str
    cmp  ebp, CONS_CLASS_SECRET
    jne  .user
    lea  rsi, [rel str_cons_redacted]
    call cons_redact_put_str
    jmp  .done
.user:
    mov  rdx, [rel cons_redact_row]
    movzx ebx, byte [rdx]
    mov  r9d, ebx
    and  ebx, ~CONS_KEEP_QCUT & 0xFF    ; target count
    and  r9d, CONS_KEEP_QCUT
    mov  rsi, [rel cons_redact_args]
.target:
    test ebx, ebx
    jz   .tail
    cmp  byte [rsi], 0
    je   .tail
    mov  al, ' '
    call cons_redact_put
    cmp  ebx, 1
    jne  .target_byte
    test r9d, r9d
    jz   .target_byte
    call cons_redact_url                ; srcreview R2: scheme://host[:port] only
    mov  [rel cons_redact_drop], edx
    jmp  .tail
.target_byte:
    mov  al, [rsi]
    test al, al
    jz   .tail
    cmp  al, ' '
    je   .target_end
    jb   .tail                          ; a tab or control byte: the rest is payload
.target_put:
    call cons_redact_put
    inc  rsi
    jmp  .target_byte
.target_end:
    inc  rsi
    cmp  byte [rsi], ' '
    je   .target_end
    dec  ebx
    jmp  .target
.tail:
    mov  rdi, rsi
    xor  ecx, ecx
.tail_len:
    cmp  byte [rdi + rcx], 0
    je   .tail_have
    inc  ecx
    jmp  .tail_len
.tail_have:
    add  ecx, [rel cons_redact_drop]
    test ecx, ecx
    jz   .done
    mov  ebx, ecx
    lea  rsi, [rel str_cons_redacted_n]
    call cons_redact_put_str
    mov  eax, ebx
    call cons_redact_put_dec
    lea  rsi, [rel str_cons_redacted_bytes]
    call cons_redact_put_str
.done:
    mov  byte [r12 + r13], 0
    mov  eax, r13d
    mov  ecx, ebp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; cons_redact_url(RSI=URL token) puts "scheme://" (when the token has one) and
; the authority's host[:port] through cons_redact_put -> RSI at the first byte
; after the authority ('/', '?', '#', or the token's end), EDX=the userinfo
; bytes dropped (user:password@). Path, query and fragment stay payload.
cons_redact_url:
    push rbx
    push rbp
    mov  rbx, rsi
    xor  ecx, ecx
.scheme:
    mov  al, [rbx + rcx]
    cmp  al, ' '
    jbe  .no_scheme
    cmp  al, ':'
    je   .colon
    cmp  al, '/'
    je   .no_scheme
    cmp  al, '?'
    je   .no_scheme
    cmp  al, '#'
    je   .no_scheme
    cmp  al, '@'
    je   .no_scheme
    inc  ecx
    jmp  .scheme
.colon:
    cmp  byte [rbx + rcx + 1], '/'
    jne  .no_scheme
    cmp  byte [rbx + rcx + 2], '/'
    jne  .no_scheme
    add  ecx, 3
    jmp  .authority
.no_scheme:
    xor  ecx, ecx
.authority:
    xor  edx, edx
.put_scheme:
    cmp  edx, ecx
    jae  .scan
    mov  al, [rbx + rdx]
    call cons_redact_put
    inc  edx
    jmp  .put_scheme
.scan:
    mov  ebp, ecx                       ; host start: after the last '@'
.scan_byte:
    mov  al, [rbx + rdx]
    cmp  al, ' '
    jbe  .end
    cmp  al, '/'
    je   .end
    cmp  al, '?'
    je   .end
    cmp  al, '#'
    je   .end
    cmp  al, '@'
    jne  .scan_next
    lea  ebp, [rdx + 1]
.scan_next:
    inc  edx
    jmp  .scan_byte
.end:
    push rdx
    mov  eax, ebp
    sub  eax, ecx
    push rax                            ; userinfo bytes dropped
    mov  ecx, ebp
.put_host:
    cmp  ecx, [rsp + 8]
    jae  .put_done
    mov  al, [rbx + rcx]
    call cons_redact_put
    inc  ecx
    jmp  .put_host
.put_done:
    pop  rdx
    pop  rax
    lea  rsi, [rbx + rax]
    pop  rbp
    pop  rbx
    ret

; cons_redact_reply(RDI=recorded line, RSI=reply, EDX=length, RCX=dst,
; R8D=dst capacity incl. NUL) -> EAX=length written. The reply follows its
; line's class: SECRET -> "<redacted>"; USER_DATA keeps its leading spaces and
; the row's head tokens and replaces the rest with "<redacted N bytes>"; SAFE is
; copied. Any byte <= ' ' separates
; tokens, so a multi-line reply never extends the head.
cons_redact_reply:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r15, rsi
    mov  ebp, edx
    mov  r12, rcx
    xor  r13d, r13d
    lea  r14d, [r8 - 1]
    call cons_line_class
    cmp  eax, CONS_CLASS_SECRET
    je   .secret
    cmp  eax, CONS_CLASS_USER
    jne  .all
    movzx ebx, byte [rdx + 1]           ; head tokens
    xor  ecx, ecx                       ; reply cursor
.lead:
    cmp  ecx, ebp
    jae  .done
    cmp  byte [r15 + rcx], ' '
    ja   .head
    mov  al, [r15 + rcx]
    call cons_redact_put
    inc  ecx
    jmp  .lead
.head:
    test ebx, ebx
    jz   .payload
.head_token:
    cmp  ecx, ebp
    jae  .done
    mov  al, [r15 + rcx]
    cmp  al, ' '
    jbe  .head_gap
    call cons_redact_put
    inc  ecx
    jmp  .head_token
.head_gap:
    mov  edx, ecx                       ; the separator run before the next token
.gap_scan:
    cmp  edx, ebp
    jae  .done
    cmp  byte [r15 + rdx], ' '
    ja   .gap_end
    inc  edx
    jmp  .gap_scan
.gap_end:
    dec  ebx
    jz   .payload_at_gap
.gap_copy:
    mov  al, [r15 + rcx]
    call cons_redact_put
    inc  ecx
    cmp  ecx, edx
    jb   .gap_copy
    jmp  .head_token
.payload_at_gap:
    mov  ecx, edx
.payload:
    mov  ebx, ebp
    sub  ebx, ecx                       ; N payload bytes
    test r13d, r13d
    jz   .marker
    cmp  byte [r12 + r13 - 1], ' '
    jbe  .marker                        ; the kept separator already spaces it
    mov  al, ' '
    call cons_redact_put
.marker:
    lea  rsi, [rel str_cons_redacted_n + 1]
    call cons_redact_put_str
    mov  eax, ebx
    call cons_redact_put_dec
    lea  rsi, [rel str_cons_redacted_bytes]
    call cons_redact_put_str
    jmp  .done
.secret:
    lea  rsi, [rel str_cons_redacted + 1]
    call cons_redact_put_str
    jmp  .done
.all:
    xor  ecx, ecx
.all_byte:
    cmp  ecx, ebp
    jae  .done
    mov  al, [r15 + rcx]
    call cons_redact_put
    inc  ecx
    jmp  .all_byte
.done:
    mov  byte [r12 + r13], 0
    mov  eax, r13d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Bounded writers shared by cons_redact_line/reply, over the caller's R12 (dst),
; R13D (length) and R14D (capacity - 1): a full buffer drops the byte.
cons_redact_put:                        ; AL
    cmp  r13d, r14d
    jae  .full
    mov  [r12 + r13], al
    inc  r13d
.full:
    ret
cons_redact_put_str:                    ; RSI=cstr (advanced)
    mov  al, [rsi]
    test al, al
    jz   .end
    call cons_redact_put
    inc  rsi
    jmp  cons_redact_put_str
.end:
    ret
cons_redact_put_dec:                    ; EAX; clobbers RDX, R8, keeps RCX
    push rcx
    sub  rsp, 16
    xor  ecx, ecx
    mov  r8d, 10
.div:
    xor  edx, edx
    div  r8d
    add  dl, '0'
    mov  [rsp + rcx], dl
    inc  ecx
    test eax, eax
    jnz  .div
.out:
    dec  ecx
    mov  al, [rsp + rcx]
    call cons_redact_put
    test ecx, ecx
    jnz  .out
    add  rsp, 16
    pop  rcx
    ret

; Parse one unsigned decimal token. RDI=input at first digit; returns EAX and
; RDI at space/NUL, CF=1 on malformed/overflow. Kept in L5 so the command
; projection never reaches upward into window_mgmt for tokenization.
cons_parse_u32:
    xor  eax, eax
    xor  ecx, ecx
.digit:
    movzx edx, byte [rdi]
    cmp  dl, '0'
    jb   .end
    cmp  dl, '9'
    ja   .end
    sub  edx, '0'
    imul eax, eax, 10
    jo   .bad
    add  eax, edx
    jc   .bad
    inc  rdi
    inc  ecx
    jmp  .digit
.end:
    test ecx, ecx
    jz   .bad
    clc
    ret
.bad:
    stc
    ret

; CONSGRID <win> [page]. The L6 callback finds the owning widget and dumps
; materialized cells. Pagination remains row-atomic under the UDP clamp.
cmd_verb_consgrid:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  r13, rsi
    mov  r14, [rdi + REQ_ARG]
    mov  rdi, r14
    call cons_parse_u32
    jc   .bad_arg
    mov  r12d, eax                    ; owner window
    mov  r14, rdi
    mov  ebx, 1                       ; default page
    cmp  byte [r14], 0
    je   .find
    cmp  byte [r14], ' '
    jne  .bad_arg
.skip_space:
    inc  r14
    cmp  byte [r14], ' '
    je   .skip_space
    mov  rdi, r14
    call cons_parse_u32
    jc   .bad_arg
    mov  ebx, eax
    cmp  byte [rdi], 0
    jne  .bad_arg
.find:
    mov  rax, [rel cons_grid_dump_cb]
    test rax, rax
    jz   .bad_window
    mov  edi, r12d
    mov  esi, ebx
    call rax
    cmp  eax, 1
    je   .bad_window
    test eax, eax
    jnz  .bad_page
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], r12
    jmp  .out
.bad_arg:
    lea  rdi, [rel str_consgrid_bad_arg]
    jmp  .error
.bad_window:
    lea  rdi, [rel str_consgrid_bad_window]
    jmp  .error
.bad_page:
    lea  rdi, [rel str_consgrid_bad_page]
.error:
    call grid_out_reset
    call grid_out_str
    mov  byte [rel grid_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    mov  qword [r13 + RSP_EXPECTED], 0    ; a number slot: CONSGRID has no expected scalar (the hint names the form)
    lea  rax, [rel str_consgrid_hint]
    mov  [r13 + RSP_HINT], rax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

str_verb_consgrid:    db "CONSGRID",0
str_verb_cons_list:   db "CONS_LIST",0
str_verb_cons_new:    db "CONS_NEW",0
str_verb_cons_submit: db "CONS_SUBMIT",0
str_verb_cons_read:   db "CONS_READ",0
str_verb_cons_close:  db "CONS_CLOSE",0
str_cons_empty:       db 0
; RCQ-15: HOOK is secret: it carries native keystrokes and field text (TERMFEED keys, WIDGETSET values).
; The host transcript tests parse this table statically: keep its db lines contiguous, with no comments
; between or after them.
str_cons_secret_verbs:
    db "DSECPUT",0,"DSECGET",0,"DSECGETAS",0,"DSECUNWRAP",0
    db "DBGET",0,"DBPUT",0,"DBPUTKILL",0
    db "PRINKDF",0,"PRINWRITE",0,"PRINREAD",0
    db "GUESTKEY",0,"KBINJ",0,"KBDBUF",0,"TERMFEED",0,"CLIPSET",0,"CLIPGET",0,"CDPBRIDGE",0
    db "RANDOM",0,"AUDIT",0,"CONS_READ",0,"CONSGRID",0,"CONS_SUBMIT",0
    db "OWNERSTAT",0,"FSOWNSTAT",0
    db "MODELRUN",0                     ; classifier text is private caller data
    db "HOOK",0,0
; User-data verbs: "VERB",0,<line target tokens kept>,<reply head tokens kept>.
; Everything after the kept tokens is "<redacted N bytes>" in the transcript and
; the UDP audit row. Every writer records the canonical reply envelope
; (command_udp_capture_reply), whose generic shape is "PAOS VERSION=<v> <VERB>
; OK|REFUSED ARG=<raw arg> ...": a head of 4 keeps the status and never ARG=;
; a head of 4+k on an exclusive reply may show at most the k target tokens the
; line keeps. Per-verb grammar/reply evidence: sec-evidence
; SEC-TRANSCRIPT_USER_DATA_VERBS.md. The census pins this table.
str_cons_user_data_verbs:
    db "DPOWER",0,0,4                   ; custody token in/out; keep status, never token or ARG=
    db "HDALOOP",0,0,4                  ; HL1 opcode/phase/error; READ's captured PCM is payload
    db "HPPERSISTTEST",0,0,4            ; generic reply can echo arbitrary refused arguments
    db "BLKREAD",0,2,4                  ; <backend> <lba>; reply hex= sector (GEN: keep "PAOS VERSION= VERB OK")
    db "BLKWRITE",0,2,4                 ; <backend> <lba> <hex1024>; GEN echoes the hex as ARG=
    db "CHAT_GETTEXT",0,0,4             ; reply Q=<typed> A=<answer>
    db "CHAT_SENDTEXT",0,0,4            ; <text...>
    db "APPSTOREOBS",0,0,0              ; extended L reply relays unvalidated guest record bytes
    db "DOCREAD",0,1,0                  ; <leaf> <offset> <count>; reply byte zero can be file content
    db "DOCNEW",0,1,0                   ; <leaf> <hex payload>; reply may be raw/binary or generic echo
    db "FSNEW",0,1,5                    ; <path> <hex> <nonce>; EXCL "FSNEW NONCE= OK SIZE="
    db "FSREAD",0,CONS_KEEP_LINE_ALL,4  ; <path...> <off> <len> <nonce>; reply SHA256= DATA= are content
    db "FSWRITE",0,1,5                  ; <path> <hex> <nonce> | <name> <off> <hex> <nonce>
    db "HTTPBODY",0,0,0                 ; the reply is the fetched body
    db "HTTPGET",0,1|CONS_KEEP_QCUT,4   ; <url>, query is payload; reply body= (stale on failure)
    db "WEBSTRUCT",0,1,3                ; HEX <hex>; WEB "webstruct=ok used= records=" then records
    db "WIDGETGET",0,2,4                ; <id> <field>; reply <field>=<value>
    db "WIDGETLIST",0,0,4               ; reply val=<value> per widget
    db "WIDGETSET",0,2,4                ; <id> <field> <value...>; GEN echoes the value as ARG=
    db "UAC1_CREAD",0,0,4               ; <offset|count>; reply DATA= captured PCM
    db "UAC1_IREAD",0,0,4               ; <offset|count>; reply DATA= captured PCM
    db "UAC2_IREAD",0,0,4               ; <offset|count>; reply DATA= captured PCM
    db 0
str_cons_redacted:        db " <redacted>",0
str_cons_redacted_n:      db " <redacted ",0
str_cons_redacted_bytes:  db " bytes>",0
str_cons_unknown:         db "<unknown>",0      ; an unregistered first token (srcreview R1)
str_cons_owner:       db "owner",0
str_cons_kat_name:    db "kat",0
str_cons_kat_submit:  db "owner kat-idem PING 2153",0
str_cons_kat_line:    db "PING 2153",0
str_cons_kat_reply:   db "kat=ok"
.len equ $ - str_cons_kat_reply
                       db 0
str_cons_kat_read:    db "owner from=1",0
str_cons_kat_slow:    db "SLOWJOB kat-2154",0
str_cons_kat_slow_reply: db " SLOWJOB OK"
.len equ $ - str_cons_kat_slow_reply
                       db 0
str_cons_kat_ping:    db "PING 2154",0
str_cons_kat_ping_reply: db " PING OK nonce=2154"
.len equ $ - str_cons_kat_ping_reply
                       db 0
str_cons_kat_status:  db "STATUS job",0
str_cons_kat_status_reply: db " STATUS OK state=running"
.len equ $ - str_cons_kat_status_reply
                       db 0

str_cons_list_head:   db " CONS_LIST n=",0
str_cons_list_row:    db " CONS name=",0
str_cons_list_seq:    db " seq=",0
str_cons_list_floor:  db " floor=",0
str_cons_list_bound:  db " bound=",0
str_cons_records:     db " records=",0
str_cons_bytes:       db " bytes=",0
str_cons_budget:      db "/8192",0
str_cons_none:        db "none",0
str_cons_list_bad:    db " CONS_LIST=ERR expected=no_args",0
str_cons_new_ok:      db " CONS_NEW name=",0
str_cons_created:     db " created=",0
str_cons_id:          db " id=",0
str_cons_new_bad:     db " CONS_NEW=ERR expected=name hint=name_1_to_31_no_spaces_or_table_full",0
str_cons_close_ok:    db " CONS_CLOSE name=",0
str_cons_close_bad:   db " CONS_CLOSE=ERR expected=existing_name",0
str_cons_terminal_closed: db "[session closed]",0
str_cons_submit_ok:   db " CONS_SUBMIT name=",0
str_cons_idem:        db " idem=",0
str_cons_seq:         db " seq=",0
str_cons_duplicate:   db " duplicate=",0
str_cons_exec_count:  db " exec_count=",0
str_cons_inner:       db " inner=",0
str_cons_submit_bad_arg: db " CONS_SUBMIT=ERR expected=name_idem_key_line",0
str_cons_submit_bad_session: db " CONS_SUBMIT=ERR unknown_session hint=CONS_NEW",0
str_cons_submit_bad_inner: db " CONS_SUBMIT=ERR unknown_or_malformed_inner_verb",0
str_cons_submit_full: db " CONS_SUBMIT=ERR transcript_budget",0
str_cons_read_head:   db " CONS_READ name=",0
str_cons_from:        db " from=",0
str_cons_next:        db " next=",0
str_cons_more:        db " more=",0
str_cons_read_row:    db " REC seq=",0
str_cons_origin:      db " origin=",0
str_cons_origin_kbd:  db "kbd",0
str_cons_origin_udp:  db "udp",0
str_cons_origin_attach: db "attach",0
str_cons_origin_job:  db "job",0
str_cons_job_id:      db " job_id=",0
str_cons_env:         db " envelope_status=",0
str_cons_final_status: db " final_status=",0
str_cons_ts:          db " ts=",0
str_cons_line:        db " line=",0
str_cons_reply:       db " reply_bytes=",0
str_cons_reply_data:  db " reply=",0
str_cons_read_bad_arg: db " CONS_READ=ERR expected=name_from_seq",0
str_cons_read_bad_session: db " CONS_READ=ERR unknown_session hint=CONS_LIST",0
str_consgrid_bad_arg: db " CONSGRID=ERR bad_arg",0
str_consgrid_bad_window: db " CONSGRID=ERR no_console_grid_for_window",0
str_consgrid_bad_page: db " CONSGRID=ERR bad_page",0
str_consgrid_hint:     db "read WINTREE for the console_grid owner and continuation page",0
str_cons_marker: db "[PAOS64] verb-console rung 0: CONS_* skeleton verbs registered honest-unsupported with CATALOG metadata [cons.skeleton.registered]",13,10,0
str_cons_session_marker: db "[PAOS64] verb-console rung 3: durable session table live (create/list/close, window-decoupled) [cons.session.noun]",13,10,0
str_cons_idem_marker: db "[PAOS64] verb-console rung 3: CONS_SUBMIT idempotency selftest (same key -> one execution) [cons.submit.idempotent]",13,10,0
str_cons_read_marker: db "[PAOS64] verb-console rung 3: CONS_READ from-seq paging selftest under the datagram clamp [cons.read.paged]",13,10,0
str_cons_job_marker: db "[PAOS64] verb-console rung 4: job accepted/completion records selftest (slow-verb fixture, interleaved command) [cons.job.records]",13,10,0
str_cons_fail:   db "[PAOS64] verb-console rung 3: session noun selftest/registry FAILED",13,10,0
str_cons_job_accepted: db " accepted job=",0
str_cons_job_est:      db " est=",0
str_cons_job_completion: db " completion job=",0
str_cons_job_status_done: db " status=done state=",0
str_cons_job_final_env: db " envelope_status=",0
str_cons_job_result:   db " result=",0
str_cons_job_state:    db " state=",0
str_cons_job_running:  db "running",0
str_cons_job_done:     db "done",0
str_cons_job_error:    db " ERR code=",0
str_cons_job_hint:     db " hint=",0
cons_registered: db 0
align 8
cons_grid_dump_cb:      dq 0
cons_grid_kat_ptr:      dq 0
cons_render_cb:         dq 0
cons_record_ptr_tmp:    dq 0
cons_read_record_tmp:   dq 0
cons_pending_kbd_rec:   dq 0
cons_inner_env_tmp:     dq 0
cons_inner_reply_ptr:   dq 0
cons_inner_arg_ptr:     dq 0
cons_duplicate_record_tmp: dq 0
cons_inner_exec_count:  dq 0
cons_job_accept_count:  dq 0
cons_job_completion_count: dq 0
cons_last_read_next:    dq 0
cons_inner_verb_id:     dd -1
cons_default_session:   dd -1
cons_bound_session:     dd -1
cons_pending_kbd_session: dd -1
cons_record_line_len_tmp: dd 0
cons_inner_reply_len:   dd 0
cons_last_read_emitted: dd 0
cons_last_read_more:    dd 0
align 8
cons_inner_req:         times REQ_SZ db 0
cons_inner_rsp:         times RSP_SZ db 0
cons_kat_req:           times REQ_SZ db 0
cons_kat_rsp:           times RSP_SZ db 0
cons_submit_name:       times (CONS_NAME_MAX + 1) db 0
cons_read_name:         times (CONS_NAME_MAX + 1) db 0
cons_submit_key:        times 64 db 0
cons_submit_line:       times CONS_LINE_MAX db 0
cons_inner_line:        times CONS_LINE_MAX db 0
cons_job_num_buf:       times 24 db 0
cons_class_verb:        times CONS_CLASS_VERB_MAX db 0
align 8
cons_redact_row:        dq 0
cons_redact_args:       dq 0
cons_redact_verb:       dq 0
cons_redact_drop:       dd 0             ; URL userinfo bytes a USER_DATA line dropped
align 8
; Transcript projection tables retain their exact strides and zero initial state.
%macro WDATA_cons_tables 0
cons_sessions:          resb (CONS_SESSION_MAX * CS_SIZE)
cons_records:           resb (CONS_SESSION_MAX * CONS_REC_CAP * CR_SIZE)
cons_job_tracks:        resb (JOB_MAX * CJ_SIZE)
%endmacro
WDATA_BSS_DEFER WDATA_cons_tables
align 8
grid_out_cur:           dq 0
grid_out_buf:           times 1450 db 0
grid_out_ready:         db 0

grid_out_reset:
    lea  rax, [rel grid_out_buf]
    mov  [rel grid_out_cur], rax
    mov  byte [rax], 0
    mov  byte [rel grid_out_ready], 0
    ret
grid_out_str:
    mov  rsi, [rel grid_out_cur]
    lea  rdx, [rel grid_out_buf + 1450 - 1]
.cp:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel grid_out_cur], rsi
    ret
grid_out_char:
    mov  rsi, [rel grid_out_cur]
    lea  rax, [rel grid_out_buf + 1450 - 2]
    cmp  rsi, rax
    jae  .ret
    mov  [rsi], dil
    inc  rsi
    mov  byte [rsi], 0
    mov  [rel grid_out_cur], rsi
.ret:
    ret
grid_out_dec:
    mov  rsi, [rel grid_out_cur]
    lea  rax, [rel grid_out_buf + 1450 - 24]
    cmp  rsi, rax
    jae  .ret
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  byte [rsi], 0
    mov  [rel grid_out_cur], rsi
.ret:
    ret

%undef CONS_REGISTER
