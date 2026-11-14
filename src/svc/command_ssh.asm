;; MODULE svc/command_ssh
;; LAYER 5
;; EXPORTS command_ssh_init, command_guestcpu_public_observation, ssh_cmd_out_buf, ssh_cmd_out_ready, SSH_CMD_OUT_CAP
;; IMPORTS net/tcp, svc/command, svc/command_guestcpu, svc/ssh, svc/ssh_auth, svc/ssh_channel, svc/command_audit, core/lib/mem, core/lib/fmt
;; CAPS
;; OWNER saga:ssh_server
; Public read-only TOFU projection. The handler is reachable only through the
; one command registry; UDP merely emits this staged semantic line.

command_guestcpu_public_observation:
    xor  eax, eax
    cmp  dword [rdi], 'SSHH'
    je   .hostkey
    ; 2142: SSHKEYLIST (fingerprints only) and SSHSTAT are public T0 reads.
    cmp  dword [rdi], 'SSHK'
    jne  .not_keylist
    cmp  dword [rdi + 4], 'EYLI'
    jne  .not_keylist
    cmp  word [rdi + 8], 'ST'
    jne  .not_keylist
    cmp  byte [rdi + 10], 0
    je   .metadata
.not_keylist:
    cmp  dword [rdi], 'SSHS'
    jne  .not_sshstat
    cmp  word [rdi + 4], 'TA'
    jne  .not_sshstat
    cmp  byte [rdi + 6], 'T'
    jne  .not_sshstat
    cmp  byte [rdi + 7], 0
    je   .metadata
.not_sshstat:
    cmp  dword [rdi], 'SSHK'
    jne  .base
    cmp  dword [rdi + 4], 'EXST'
    jne  .base
    cmp  word [rdi + 8], 'AT'
    jne  .base
    cmp  byte [rdi + 10], 0
    jne  .base
    jmp  .metadata
.hostkey:
    cmp  dword [rdi + 4], 'OSTK'
    jne  .base
    cmp  word [rdi + 8], 'EY'
    jne  .base
    cmp  byte [rdi + 10], 0
    jne  .base
.metadata:
    ; Match is still insufficient: public status is earned from the live
    ; cap=0/destr=0 registry metadata, exactly like the existing chain.
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
.base:
    jmp  command_guestcpu_public_observation_base

command_ssh_init:
    push rbx
    lea  rdi, [rel str_verb_sshhostkey]
    lea  rsi, [rel cmd_verb_sshhostkey]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8d, r8d
    xor  r9d, r9d
    call command_register_verb
    test eax, eax
    js   .out
    lea  rdi, [rel str_verb_sshkexstat]
    lea  rsi, [rel cmd_verb_sshkexstat]
    xor  edx, edx
    mov  ecx, ARGT_U64
    xor  r8d, r8d
    xor  r9d, r9d
    call command_register_verb
    test eax, eax
    js   .out
    ; 2142: owner-signed enrollment (destructive => AUTH1 MUTATE scope) and
    ; the two public reads of the login surface.
    lea  rdi, [rel str_verb_sshkeyadd]
    lea  rsi, [rel cmd_verb_sshkeyadd]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1
    call command_register_verb
    test eax, eax
    js   .out
    lea  rdi, [rel str_verb_sshkeydel]
    lea  rsi, [rel cmd_verb_sshkeydel]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1
    call command_register_verb
    test eax, eax
    js   .out
    lea  rdi, [rel str_verb_sshkeylist]
    lea  rsi, [rel cmd_verb_sshkeylist]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8d, r8d
    xor  r9d, r9d
    call command_register_verb
    test eax, eax
    js   .out
    lea  rdi, [rel str_verb_sshstat]
    lea  rsi, [rel cmd_verb_sshstat]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8d, r8d
    xor  r9d, r9d
    call command_register_verb
    test eax, eax
    js   .out
    ; Owner-only wire-record evidence; no generic public-read grant.
    lea  rdi, [rel str_verb_sshrecord]
    lea  rsi, [rel cmd_verb_sshrecord]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    xor  r9d, r9d
    call command_register_verb
    test eax, eax
    js   .out
%ifdef PAOS_PUBLICITY_LAB_PROFILE
%if PAOS_PUBLICITY_LAB_PROFILE
    ; Explicit owner opt-in only; no generic public read/arming authority.
    lea  rdi, [rel str_verb_sshpretrace]
    lea  rsi, [rel cmd_verb_sshpretrace]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1                         ; existing consumed AUTH1 MUTATE scope
    call command_register_verb
    test eax, eax
    js   .out
%endif
%endif
    ; Password-only authority observation: owner carrier, scoped inner request.
    lea  rdi, [rel str_verb_authpwkey]
    lea  rsi, [rel cmd_verb_authpwkey]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1
    call command_register_verb
    test eax, eax
    js   .out
    call ssh_keystore_init
    ; The persistence/transport marker set includes this public projection, so
    ; it can only be earned after the registry accepted the exact T0 row.
    ; SEC-GD1b: these KATs drive the REAL audited SSH paths (a valid-key OWNER
    ; login, refused keys, exec). Bracket them so boot starts with a truthful
    ; Guardian spine: no owner login that never happened.
    call audit_sec_save
    call ssh_transport_selftest
    call ssh_auth_selftest                    ; 2142 publickey/principal/audit KATs
    call ssh_channel_selftest                 ; 2143 session/exec/capability KATs
    call audit_sec_restore
    ; Owner-bound read of actual outgoing identity/pins; never public T0.
    lea  rdi, [rel str_verb_sshpresence]
    lea  rsi, [rel cmd_verb_sshpresence]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1
    call command_register_verb
    test eax, eax
    js   .out
    lea  rdi, [rel str_verb_sshcliprofile]
    lea  rsi, [rel cmd_verb_sshcliprofile]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1
    call command_register_verb
    test eax, eax
    js   .out
%ifdef PAOS_PUBLICITY_LAB_PROFILE
%if PAOS_PUBLICITY_LAB_PROFILE
    ; Lab only; registry still consumes existing AUTH1 MUTATE authority.
    lea  rdi, [rel str_verb_sshprofilefault]
    lea  rsi, [rel cmd_verb_sshprofilefault]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1
    call command_register_verb
    test eax, eax
    js   .out
%endif
%endif
    ; Explicit outgoing server trust, same consumed OWNER AUTH1 MUTATE gate.
    lea  rdi, [rel str_verb_sshkhtrust]
    lea  rsi, [rel cmd_verb_sshkhtrust]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1
    call command_register_verb
    test eax, eax
    js   .out
    ; Deliberate endpoint old/new action; never public or automatic trust.
    lea  rdi, [rel str_verb_sshkhreplace]
    lea  rsi, [rel cmd_verb_sshkhreplace]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1
    call command_register_verb
    test eax, eax
    js   .out
    ; RCQ-07b: the owner's known_hosts clear (owner-signed, destructive). Last,
    ; and contained: a full registry loses only this row, never the SSH server.
    lea  rdi, [rel str_verb_sshkhclear]
    lea  rsi, [rel cmd_verb_sshkhclear]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8d, r8d
    mov  r9d, 1
    call command_register_verb
.out:
    pop  rbx
    ret

; RDI=bytes, ESI=len, RDX=dst -> RAX=end. Lowercase hex matches the host
; witness oracle and keeps the bounded reply unambiguous.
ssh_cmd_hex_bytes:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, rdx
    xor  ecx, ecx
.loop:
    cmp  ecx, r12d
    jae  .done
    movzx eax, byte [rbx + rcx]
    mov  edx, eax
    shr  eax, 4
    and  edx, 15
    lea  r8, [rel ssh_cmd_hex_digits]
    mov  al, [r8 + rax]
    mov  [r13], al
    mov  dl, [r8 + rdx]
    mov  [r13 + 1], dl
    add  r13, 2
    inc  ecx
    jmp  .loop
.done:
    mov  rax, r13
    pop  r13
    pop  r12
    pop  rbx
    ret

cmd_verb_sshkexstat:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  rbx, rsi
    mov  r12, [rdi + REQ_ARG]
    cmp  byte [rel ssh_kex_witness_ready], 1
    jne  .unavailable
    cmp  r12, SSH_KEX_WITNESS_N
    jae  .bad_selector
    lea  r13, [rel ssh_cmd_out_buf]
    mov  rdi, r13
    lea  rsi, [rel str_sshkexstat_prefix]
    mov  edx, str_sshkexstat_prefix.len
    call memcpy
    add  r13, str_sshkexstat_prefix.len
    mov  al, r12b
    add  al, '0'
    mov  [r13], al
    inc  r13
    lea  rdi, [r13]
    lea  rsi, [rel str_sshkexstat_len]
    mov  edx, str_sshkexstat_len.len
    call memcpy
    add  r13, str_sshkexstat_len.len
    lea  rax, [rel ssh_kex_witness_len]
    mov  edi, [rax + r12*4]
    mov  rsi, r13
    call fmt_dec
    add  r13, rax
    lea  rdi, [r13]
    lea  rsi, [rel str_sshkexstat_data]
    mov  edx, str_sshkexstat_data.len
    call memcpy
    add  r13, str_sshkexstat_data.len
    mov  eax, r12d
    shl  eax, 5
    lea  rdi, [rel ssh_kex_witness_data]
    add  rdi, rax
    mov  esi, 32
    mov  rdx, r13
    call ssh_cmd_hex_bytes
    mov  byte [rax], 0
    mov  byte [rel ssh_cmd_out_ready], 1
    mov  qword [rbx + RSP_ACCEPTED], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    jmp  .out
.bad_selector:
    lea  rdi, [rel ssh_cmd_out_buf]
    lea  rsi, [rel str_sshkexstat_bad]
    mov  edx, str_sshkexstat_bad.len
    call memcpy
    mov  byte [rel ssh_cmd_out_buf + str_sshkexstat_bad.len], 0
    jmp  .reject
.unavailable:
    lea  rdi, [rel ssh_cmd_out_buf]
    lea  rsi, [rel str_sshkexstat_unavailable]
    mov  edx, str_sshkexstat_unavailable.len
    call memcpy
    mov  byte [rel ssh_cmd_out_buf + str_sshkexstat_unavailable.len], 0
.reject:
    mov  byte [rel ssh_cmd_out_ready], 1
    mov  qword [rbx + RSP_ACCEPTED], 0
    mov  qword [rbx + RSP_CODE], CMDE_BADJOB
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

cmd_verb_sshhostkey:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rsi
    cmp  byte [rel ssh_hostkey_ready], 1
    jne  .unavailable
    lea  rdi, [rel ssh_cmd_out_buf]
    lea  rsi, [rel str_sshhostkey_prefix]
    mov  edx, str_sshhostkey_prefix.len
    call memcpy
    lea  rdi, [rel ssh_cmd_out_buf + str_sshhostkey_prefix.len]
    lea  rsi, [rel ssh_host_fingerprint]
    mov  edx, [rel ssh_host_fingerprint_len]
    call memcpy
    mov  eax, str_sshhostkey_prefix.len
    add  eax, [rel ssh_host_fingerprint_len]
    lea  rdi, [rel ssh_cmd_out_buf]
    add  rdi, rax
    mov  byte [rdi], 0
    mov  byte [rel ssh_cmd_out_ready], 1
    mov  qword [rbx + RSP_ACCEPTED], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    pop  rbx
    ret
.unavailable:
    lea  rdi, [rel ssh_cmd_out_buf]
    lea  rsi, [rel str_sshhostkey_unavailable]
    mov  edx, str_sshhostkey_unavailable.len
    call memcpy
    mov  byte [rel ssh_cmd_out_buf + str_sshhostkey_unavailable.len], 0
    mov  byte [rel ssh_cmd_out_ready], 1
    mov  qword [rbx + RSP_ACCEPTED], 0
    mov  qword [rbx + RSP_CODE], CMDE_BADJOB
    pop  rbx
    ret

SSH_CMD_OUT_CAP equ 768
ssh_cmd_out_ready: db 0
ssh_cmd_out_buf: times SSH_CMD_OUT_CAP db 0
str_verb_sshhostkey: db "SSHHOSTKEY",0
str_verb_sshkeyadd: db "SSHKEYADD",0
str_verb_sshkeydel: db "SSHKEYDEL",0
str_verb_sshkhtrust: db "SSHKHTRUST",0
str_verb_sshkhclear: db "SSHKHCLEAR",0
str_verb_sshkeylist: db "SSHKEYLIST",0
str_verb_sshstat: db "SSHSTAT",0
str_verb_sshrecord: db "SSHRECORD",0
str_verb_sshkexstat: db "SSHKEXSTAT",0
str_sshhostkey_prefix: db "SSHHOSTKEY type=ssh-ed25519 fingerprint=SHA256:"
.len equ $ - str_sshhostkey_prefix
str_sshhostkey_unavailable: db "ERR SSHHOSTKEY unavailable"
.len equ $ - str_sshhostkey_unavailable
str_sshkexstat_prefix: db "SSHKEXSTAT i="
.len equ $ - str_sshkexstat_prefix
str_sshkexstat_len: db " len="
.len equ $ - str_sshkexstat_len
str_sshkexstat_data: db " data="
.len equ $ - str_sshkexstat_data
str_sshkexstat_bad: db "ERR SSHKEXSTAT selector expected=0..9"
.len equ $ - str_sshkexstat_bad
str_sshkexstat_unavailable: db "ERR SSHKEXSTAT unavailable"
.len equ $ - str_sshkexstat_unavailable
ssh_cmd_hex_digits: db "0123456789abcdef"

str_verb_authpwkey: db "AUTHPWKEY",0

str_verb_sshcliprofile: db "SSHCLIPROFILE",0

str_verb_sshpresence: db "SSHPRESENCE",0
%include "svc/ssh_presence_command.inc"
str_verb_sshkhreplace: db "SSHKHREPLACE",0

%ifdef PAOS_PUBLICITY_LAB_PROFILE
%if PAOS_PUBLICITY_LAB_PROFILE
str_verb_sshprofilefault: db "SSHPROFILEFAULT",0
%endif
%endif

%ifdef PAOS_PUBLICITY_LAB_PROFILE
%if PAOS_PUBLICITY_LAB_PROFILE
str_verb_sshpretrace: db "SSHPRETRACE",0
%include "svc/ssh_preauth_trace_command.inc"
%endif
%endif
