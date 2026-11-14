;; MODULE svc/command_owner_stat
;; LAYER 5
;; EXPORTS owner_stat_declare, cmd_verb_ownerstat, ownerstat_buf
;; IMPORTS svc/command, sec/owner_store, core/lib/fmt
;; CAPS
;; OWNER saga:sec
; ============================================================================
; svc/command_owner_stat.asm — OWNERSTAT, the owner store's state after EBS
; (owner identity S1b-2; srcreview S1b F2 / DC3).
;
; sec/owner_store decides the store before ExitBootServices and keeps only
; scalars afterwards (DC4: no record, stage or key buffer survives). Before
; this verb they reached only the pre-EBS serial line, so a suppressed stage
; (DC3: an unchanged generation) was invisible to a remote owner.
;
;   OWNERSTAT  ->  owner_store state=<s> gen=<g> summary=<k> stage=<d>
;                  slot=<n> planted=<bits>
;
; Decimal values: state OWS_* (0 not run, 1 loaded, 2 unowned, 3 corrupt,
; 4 failed), the committed generation (0 = none), the committed record's
; non-secret change kind, this boot's stage decision OWS_STG_*, the committed
; slot (255 = none), and ows_planted (bits 0/1 a foreign variable seen under
; slot 0/1; bits 4/5 it could not be deleted: stuck; bit 6 a stage the
; firmware would not delete; bit 7 its name was rotated away, gen + 1). Stage
; 6 = no stage name this boot (no Y or no valid base): nothing was read. No
; GUID, key, verifier, fleet byte or stage name is read here.
;
; WHO MAY. Registered cap=0, destructive=0, ARGT_NONE. Which owner state a box
; is in is owner-private (it tells whether a password or key is enrolled), so
; this file refuses any principal but OWNER with AUTHDENY, as FSOWNSTAT does.
; ============================================================================

OWNERSTAT_CAP   equ 128

owner_stat_declare:
    lea  rdi, [rel str_ownerstat_verb]
    lea  rsi, [rel cmd_verb_ownerstat]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9                          ; read-only
    call command_register_verb
    ret

; cmd_verb_ownerstat(RDI=request, RSI=response)
cmd_verb_ownerstat:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  rbx, rsi
    mov  qword [rbx + RSP_VAL], -1
    mov  qword [rbx + RSP_EXPECTED], 0
    cmp  qword [rdi + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne  .notowner
    lea  r12, [rel ownerstat_buf]
    lea  rdi, [rel str_ownerstat_state]
    movzx r13d, byte [rel ows_state]
    call .field
    lea  rdi, [rel str_ownerstat_gen]
    mov  r13, [rel ows_generation]
    call .field
    lea  rdi, [rel str_ownerstat_summary]
    mov  r13d, [rel ows_summary]
    call .field
    lea  rdi, [rel str_ownerstat_stage]
    movzx r13d, byte [rel ows_stage]
    call .field
    lea  rdi, [rel str_ownerstat_slot]
    movzx r13d, byte [rel ows_selected]
    call .field
    lea  rdi, [rel str_ownerstat_planted]
    movzx r13d, byte [rel ows_planted]
    call .field
    movzx eax, byte [rel ows_state]
    mov  [rbx + RSP_VAL], rax
    mov  qword [rbx + RSP_CODE], CMDE_OK
    lea  rax, [rel ownerstat_buf]
    mov  [rbx + RSP_HINT], rax
    xor  eax, eax
    jmp  .out
.notowner:
    mov  qword [rbx + RSP_CODE], CMDE_AUTHDENY
    lea  rax, [rel str_ownerstat_notowner]
    mov  [rbx + RSP_HINT], rax
    mov  eax, CMDE_AUTHDENY
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
; append the label [RDI] and R13 in decimal at R12; R12 advances to the NUL.
; The labels are fixed and the values are a byte, a dword or a qword, so the
; six fields fit OWNERSTAT_CAP (longest line 97 bytes with NUL). The call
; pushed 8 bytes: realign before calling out.
.field:
    sub  rsp, 8
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    mov  rdi, r13
    mov  rsi, r12
    call fmt_dec
    add  r12, rax
    add  rsp, 8
    ret

str_ownerstat_verb:     db "OWNERSTAT", 0
str_ownerstat_state:    db "owner_store state=", 0
str_ownerstat_gen:      db " gen=", 0
str_ownerstat_summary:  db " summary=", 0
str_ownerstat_stage:    db " stage=", 0
str_ownerstat_slot:     db " slot=", 0
str_ownerstat_planted:  db " planted=", 0
str_ownerstat_notowner: db "REFUSED owner principal only", 0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
%macro WDATA_svc_command_owner_stat 0
ownerstat_buf:  times OWNERSTAT_CAP db 0
%endmacro
WDATA_DEFER WDATA_svc_command_owner_stat
