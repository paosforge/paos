;; MODULE svc/ssh_auth
;; LAYER 5
;; EXPORTS cmd_verb_sshprofilefault, cmd_verb_sshkhreplace, cmd_verb_sshkhtrust, cmd_verb_authpwkey, ssh_userauth_packet, ssh_keystore_init, ssh_keystore_find, ssh_keystore_commit_stage, ssh_auth_command_caps, ssh_auth_selftest, ssh_auth_audit_exec, ssh_key_fingerprint, ssh_txt_reset, ssh_txt_put_str, ssh_txt_put_dec, ssh_txt_put_hex16, ssh_txt_put_bytes, cmd_verb_sshkeyadd, cmd_verb_sshkeydel, cmd_verb_sshkhclear, cmd_verb_sshkeylist, cmd_verb_sshstat, ssh_auth_ok_count, ssh_auth_fail_count, ssh_exec_count, ssh_exec_refused, cmd_verb_sshrecord, ssh_keys_nvram_writes, cmd_verb_sshcliprofile
;; IMPORTS svc/ssh, sec/principal, sec/session, svc/command, svc/command_auth, svc/command_audit, core/lib/mem, core/lib/sha256, core/lib/ed25519, core/lib/fmt, boot/header, boot/boot_v2_handoff, boot/serial, fs/storage_access, boot/nvram_access, svc/ssh_client
;; CAPS
;; OWNER saga:ssh_server
; ============================================================================
; SSH rung 2 (Task2142): RFC 4252 publickey user authentication.
;
;   * Method `publickey`, algorithm `ssh-ed25519` only (v1 is keys-only).
;   * The two-step flow: an unsigned query earns SSH_MSG_USERAUTH_PK_OK only
;     for an enrolled key and NEVER binds anything; only the signed request is
;     verified, over the RFC 4252 section 7 blob that starts with THIS
;     connection's session id (a signature from another session is a replay).
;   * Verification runs through the one Task2501 seam,
;     authenticate_bind(AUTH_BIND_ED25519): the seam checks enrollment AND the
;     signature and selects the output principal. SSH binds that principal to
;     the CONNECTION (ctx SSH_C_PID); it never writes the global local-session
;     principal and never unlocks the local desktop.
;   * Enrolled-key store: four ssh-ed25519 public keys, each with a capability
;     restriction mask, in the dedicated UEFI variable PaOSSshKeys (CRC-bound,
;     exact readback, runtime-mapped only; the same contract as
;     PaOSPrincipalCred). Never a raw-sector write. A hypervisor boot without
;     runtime services keeps a RAM-only store, like the other identity records.
;     Enrollment is an OWNER-SIGNED AUTH1 verb (SSHKEYADD/SSHKEYDEL; each
;     mutation is exactly one SetVariable); SSHKEYLIST is a public read.
;   * Every attempt (accepted and refused) is recorded in the command audit
;     ring with the key fingerprint; identical consecutive refusals coalesce
;     into one record with a repeat count. Consecutive failures trigger a
;     bounded global backoff (5 s doubling to 60 s). Attempts during a backoff
;     never extend it, so a flood cannot lock the owner out indefinitely, and
;     no path here blocks: UDP STATUS keeps answering throughout.
; ============================================================================

SSH_AUTH_CONN_MAX       equ 6                  ; failures before this connection closes
SSH_AUTH_LOCK_AFTER     equ 5                  ; consecutive failures before backoff
SSH_AUTH_BACKOFF_MS     equ 5000
SSH_AUTH_BACKOFF_MAX_MS equ 60000
SSH_UA_SIGNED_CAP       equ 1024               ; ED25519_MAX_MESSAGE
SSH_KEY_BLOB_LEN        equ 51                 ; string "ssh-ed25519" || string pub32
SSH_SIG_BLOB_WIRE_LEN   equ 83                 ; string "ssh-ed25519" || string sig64

SSH_AR_OK         equ 0
SSH_AR_UNENROLLED equ 1
SSH_AR_BADSIG     equ 2
SSH_AR_USER       equ 3
SSH_AR_SERVICE    equ 4
SSH_AR_METHOD     equ 5
SSH_AR_ALG        equ 6
SSH_AR_LOCKOUT    equ 7

; --- enrolled-key store record (UEFI variable PaOSSshKeys) ---
SSHK_MAX          equ 4
SSHK_ENT_PUB      equ 0
SSHK_ENT_CAPS     equ 32
SSHK_ENT_FLAGS    equ 40
SSHK_ENT_SIZE     equ 48
SSHK_REC_MAGIC    equ 0x4b535350              ; "PSSK"
SSHK_REC_VERSION  equ 1
SSHK_REC_SIZE     equ 224
SSHK_REC_COUNT    equ 8
SSHK_REC_ENTRIES  equ 16
SSHK_REC_CRC      equ 220
SSHK_ST_UNAVAILABLE equ 0                     ; metal without runtime services: no store
SSHK_ST_RAM       equ 1                       ; hypervisor fixture: volatile store
SSHK_ST_NVRAM     equ 2
SSHK_ST_POISONED  equ 3                       ; malformed/unreadable/uncertain durable write
SSHK_EFI_NOT_FOUND equ 0x800000000000000E
SSHK_CAPS_ALL     equ -1

%if (SSHK_REC_ENTRIES + SSHK_MAX * SSHK_ENT_SIZE) > SSHK_REC_CRC
    %error "ssh key store record overflow"
%endif

; ---------------------------------------------------------------------------
; Small bounded text builder shared by the SSH verbs / audit lines.
; ---------------------------------------------------------------------------
; ssh_txt_reset(RDI=buffer, ESI=capacity incl. NUL)
%include "svc/ssh_profile_fault_command.inc"

ssh_txt_reset:
    mov  [rel ssh_txt_cur], rdi
    lea  rax, [rdi + rsi - 1]
    mov  [rel ssh_txt_end], rax
    mov  byte [rdi], 0
    ret

; ssh_txt_put_bytes(RDI=src, ESI=len) — bounded, always NUL-terminated.
ssh_txt_put_bytes:
    mov  rdx, [rel ssh_txt_cur]
    mov  rcx, [rel ssh_txt_end]
.loop:
    test esi, esi
    jz   .done
    cmp  rdx, rcx
    jae  .done
    mov  al, [rdi]
    mov  [rdx], al
    inc  rdi
    inc  rdx
    dec  esi
    jmp  .loop
.done:
    mov  byte [rdx], 0
    mov  [rel ssh_txt_cur], rdx
    ret

; ssh_txt_put_str(RDI=cstr)
ssh_txt_put_str:
    mov  rdx, [rel ssh_txt_cur]
    mov  rcx, [rel ssh_txt_end]
.loop:
    mov  al, [rdi]
    test al, al
    jz   .done
    cmp  rdx, rcx
    jae  .done
    mov  [rdx], al
    inc  rdi
    inc  rdx
    jmp  .loop
.done:
    mov  byte [rdx], 0
    mov  [rel ssh_txt_cur], rdx
    ret

; ssh_txt_put_dec(RDI=value)
ssh_txt_put_dec:
    lea  rsi, [rel ssh_txt_num]
    call fmt_dec
    lea  rdi, [rel ssh_txt_num]
    jmp  ssh_txt_put_str

; ssh_txt_put_hex16(RDI=value) — exactly sixteen lowercase digits.
ssh_txt_put_hex16:
    lea  rsi, [rel ssh_txt_num]
    mov  edx, 16
    call fmt_hex
    lea  rdi, [rel ssh_txt_num]
    jmp  ssh_txt_put_str

; ---------------------------------------------------------------------------
; Base64 (RFC 4648 standard alphabet).
; ---------------------------------------------------------------------------
; ssh_b64_encode(RDI=src, ESI=len, RDX=dst, ECX=1 pad / 0 no pad) -> EAX=len.
ssh_b64_encode:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, rdx
    mov  r14d, ecx
    lea  r8, [rel ssh_b64]
    mov  r9, r13
.triplet:
    cmp  r12d, 3
    jb   .tail
    movzx eax, byte [rbx]
    shl  eax, 16
    movzx ecx, byte [rbx + 1]
    shl  ecx, 8
    or   eax, ecx
    movzx ecx, byte [rbx + 2]
    or   eax, ecx
    mov  ecx, eax
    shr  ecx, 18
    and  ecx, 63
    mov  cl, [r8 + rcx]
    mov  [r9], cl
    mov  ecx, eax
    shr  ecx, 12
    and  ecx, 63
    mov  cl, [r8 + rcx]
    mov  [r9 + 1], cl
    mov  ecx, eax
    shr  ecx, 6
    and  ecx, 63
    mov  cl, [r8 + rcx]
    mov  [r9 + 2], cl
    and  eax, 63
    mov  al, [r8 + rax]
    mov  [r9 + 3], al
    add  rbx, 3
    add  r9, 4
    sub  r12d, 3
    jmp  .triplet
.tail:
    test r12d, r12d
    jz   .done
    movzx eax, byte [rbx]
    shl  eax, 16
    cmp  r12d, 2
    jb   .one
    movzx ecx, byte [rbx + 1]
    shl  ecx, 8
    or   eax, ecx
.one:
    mov  ecx, eax
    shr  ecx, 18
    and  ecx, 63
    mov  cl, [r8 + rcx]
    mov  [r9], cl
    mov  ecx, eax
    shr  ecx, 12
    and  ecx, 63
    mov  cl, [r8 + rcx]
    mov  [r9 + 1], cl
    add  r9, 2
    cmp  r12d, 2
    jb   .pad_two
    mov  ecx, eax
    shr  ecx, 6
    and  ecx, 63
    mov  cl, [r8 + rcx]
    mov  [r9], cl
    inc  r9
    test r14d, r14d
    jz   .done
    mov  byte [r9], '='
    inc  r9
    jmp  .done
.pad_two:
    test r14d, r14d
    jz   .done
    mov  word [r9], '=='
    add  r9, 2
.done:
    mov  byte [r9], 0
    mov  rax, r9
    sub  rax, r13
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_b64_value(AL=char) -> EAX 0..63, or -1.
ssh_b64_value:
    cmp  al, 'A'
    jb   .digit
    cmp  al, 'Z'
    ja   .lower
    movzx eax, al
    sub  eax, 'A'
    ret
.lower:
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'z'
    ja   .bad
    movzx eax, al
    sub  eax, 'a' - 26
    ret
.digit:
    cmp  al, '+'
    je   .plus
    cmp  al, '/'
    je   .slash
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    ja   .bad
    movzx eax, al
    add  eax, 52 - '0'
    ret
.plus:
    mov  eax, 62
    ret
.slash:
    mov  eax, 63
    ret
.bad:
    mov  eax, -1
    ret

; ssh_b64_decode(RDI=src, ESI=len, RDX=dst, ECX=cap) -> EAX=bytes or -1.
; Accepts canonical padded or unpadded input; any other byte is malformed.
ssh_b64_decode:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, rdx
    mov  r14d, ecx
    ; strip up to two trailing '='
    test r12d, r12d
    jz   .bad
    cmp  byte [rbx + r12 - 1], '='
    jne  .unpadded
    dec  r12d
    test r12d, r12d
    jz   .bad
    cmp  byte [rbx + r12 - 1], '='
    jne  .unpadded
    dec  r12d
.unpadded:
    mov  eax, r12d
    and  eax, 3
    cmp  eax, 1
    je   .bad
    xor  r15d, r15d                    ; out length
    xor  r8d, r8d                      ; accumulator
    xor  r9d, r9d                      ; bits held
    xor  r10d, r10d                    ; index
.loop:
    cmp  r10d, r12d
    jae  .done
    mov  al, [rbx + r10]
    call ssh_b64_value
    test eax, eax
    js   .bad
    shl  r8d, 6
    or   r8d, eax
    add  r9d, 6
    inc  r10d
    cmp  r9d, 8
    jb   .loop
    sub  r9d, 8
    cmp  r15d, r14d
    jae  .bad
    mov  eax, r8d
    mov  ecx, r9d
    shr  eax, cl
    mov  [r13 + r15], al
    inc  r15d
    mov  eax, 1
    shl  eax, cl
    dec  eax
    and  r8d, eax
    jmp  .loop
.done:
    mov  eax, r15d
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_bytes_eq(RDI=data, ESI=len, RDX=literal, ECX=literal len) -> EAX 1/0.
ssh_bytes_eq:
    cmp  esi, ecx
    jne  .no
    test ecx, ecx
    jz   .yes
.loop:
    mov  al, [rdi]
    cmp  al, [rdx]
    jne  .no
    inc  rdi
    inc  rdx
    dec  ecx
    jnz  .loop
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ssh_key_blob_build(RDI=pub32) -> RAX=ssh_key_blob_scratch (51 bytes).
ssh_key_blob_build:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel ssh_key_blob_scratch]
    lea  rsi, [rel ssh_user_key_prefix]
    mov  edx, SSH_KEY_BLOB_LEN - 32
    call memcpy
    lea  rdi, [rel ssh_key_blob_scratch + SSH_KEY_BLOB_LEN - 32]
    mov  rsi, rbx
    mov  edx, 32
    call memcpy
    lea  rax, [rel ssh_key_blob_scratch]
    pop  rbx
    ret

; ssh_key_fingerprint(RDI=pub32, RSI=dst >=44 bytes) -> EAX=43.
; Identical to OpenSSH's SHA256:<base64-no-pad> display of the key blob.
ssh_key_fingerprint:
    push rbx
    mov  rbx, rsi
    call ssh_key_blob_build
    lea  rdi, [rel ssh_key_digest]
    mov  rsi, rax
    mov  edx, SSH_KEY_BLOB_LEN
    call sha256_hash
    lea  rdi, [rel ssh_key_digest]
    mov  esi, 32
    mov  rdx, rbx
    xor  ecx, ecx
    call ssh_b64_encode
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Enrolled-key store.
; ---------------------------------------------------------------------------
; ssh_keystore_init — boot load / explicit validated reload. Absent = empty store.
; A malformed/unreadable variable POISONS the store (all SSH auth refused,
; enrollment refused); it is never silently replaced.
ssh_keystore_init:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    lea  rdi, [rel ssh_keys_record]
    xor  esi, esi
    mov  edx, SSHK_REC_SIZE
    call memset
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .unmapped
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .poison
    cmp  qword [r12 + 0x48], 0
    je   .poison
    mov  qword [rel ssh_keys_var_size], SSHK_REC_SIZE
    mov  dword [rel ssh_keys_var_attrs], 0
    lea  rcx, [rel ssh_keys_var_name]
    lea  rdx, [rel ssh_keys_var_guid]
    lea  r8, [rel ssh_keys_var_attrs]
    lea  r9, [rel ssh_keys_var_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel ssh_keys_stage]
    mov  [rsp + 32], rbx
    call [r12 + 0x48]                   ; EFI_RUNTIME_SERVICES.GetVariable
    mov  rsp, r13
    test rax, rax
    jz   .validate
    mov  rdx, SSHK_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .poison
    mov  byte [rel ssh_keys_state], SSHK_ST_NVRAM
    jmp  .ok
.validate:
    cmp  dword [rel ssh_keys_var_attrs], AUTH_EFI_ATTRS
    jne  .poison
    cmp  qword [rel ssh_keys_var_size], SSHK_REC_SIZE
    jne  .poison
    lea  rdi, [rel ssh_keys_stage]
    call ssh_keystore_record_valid
    test eax, eax
    jz   .poison
    lea  rdi, [rel ssh_keys_record]
    lea  rsi, [rel ssh_keys_stage]
    mov  edx, SSHK_REC_SIZE
    call memcpy
    mov  byte [rel ssh_keys_state], SSHK_ST_NVRAM
    jmp  .ok
.unmapped:
    ; Uncertain durable authority cannot recover through a RAM-only fallback.
    cmp  byte [rel ssh_keys_state], SSHK_ST_POISONED
    je   .poison
    mov  eax, 1
    cpuid
    bt   ecx, 31
    jnc  .unavailable
    mov  byte [rel ssh_keys_state], SSHK_ST_RAM
    jmp  .ok
.unavailable:
    mov  byte [rel ssh_keys_state], SSHK_ST_UNAVAILABLE
    jmp  .ok
.poison:
    mov  byte [rel ssh_keys_state], SSHK_ST_POISONED
    lea  rdi, [rel ssh_keys_record]
    xor  esi, esi
    mov  edx, SSHK_REC_SIZE
    call memset
.ok:
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_keystore_record_valid(RDI=record) -> EAX 1/0 (magic/version/size/CRC,
; flags in {0,1}, count equals the number of valid slots).
ssh_keystore_record_valid:
    push rbx
    push r12
    mov  rbx, rdi
    cmp  dword [rbx], SSHK_REC_MAGIC
    jne  .no
    cmp  word [rbx + 4], SSHK_REC_VERSION
    jne  .no
    cmp  word [rbx + 6], SSHK_REC_SIZE
    jne  .no
    mov  rdi, rbx
    mov  esi, SSHK_REC_CRC
    call pbm_crc32
    cmp  eax, [rbx + SSHK_REC_CRC]
    jne  .no
    xor  r12d, r12d
    xor  ecx, ecx
.slot:
    cmp  ecx, SSHK_MAX
    jae  .count
    imul eax, ecx, SSHK_ENT_SIZE
    mov  edx, [rbx + SSHK_REC_ENTRIES + rax + SSHK_ENT_FLAGS]
    cmp  edx, 1
    ja   .no
    add  r12d, edx
    inc  ecx
    jmp  .slot
.count:
    cmp  [rbx + SSHK_REC_COUNT], r12d
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; ssh_keystore_find(RDI=pub32) -> EAX slot or -1, RDX=capability mask.
; Preserves RBX/RBP/R12-R15. Only available RAM/NVRAM stores match keys.
ssh_keystore_find:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    cmp  byte [rel ssh_keys_state], SSHK_ST_RAM
    je   .available
    cmp  byte [rel ssh_keys_state], SSHK_ST_NVRAM
    jne  .none
.available:
    xor  ebx, ebx
.loop:
    cmp  ebx, SSHK_MAX
    jae  .none
    imul eax, ebx, SSHK_ENT_SIZE
    lea  r13, [rel ssh_keys_record + SSHK_REC_ENTRIES]
    add  r13, rax
    cmp  dword [r13 + SSHK_ENT_FLAGS], 1
    jne  .next
    mov  rdi, r13
    mov  rsi, r12
    mov  edx, 32
    call memcmp
    test eax, eax
    jz   .found
.next:
    inc  ebx
    jmp  .loop
.found:
    mov  eax, ebx
    mov  rdx, [r13 + SSHK_ENT_CAPS]
    jmp  .out
.none:
    mov  eax, -1
    xor  edx, edx
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_auth_command_caps(RDI=ctx) -> EAX 0/-1, RDX=current key ceiling.
; Each NEW command rechecks exact authenticated key identity, never slot/display
; fingerprint. The idle-loop consumer serializes store commits and admission.
; The unchanged command_auth_authorize intersects the resulting key ceiling
; with the bound principal's CURRENT registry grant. Keep the -1 unrestricted
; key marker intact: explicit owner unlock/storage intent depend on it.
; This admits a command snapshot; it does not cancel an in-flight handler.
ssh_auth_command_caps:
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rdi
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_CONNECTION
    jne  .bad
    cmp  byte [rbx + SSH_C_AUTH_BOUND], 1
    jne  .bad
    cmp  byte [rel ssh_keys_state], SSHK_ST_RAM
    je   .lookup
    cmp  byte [rel ssh_keys_state], SSHK_ST_NVRAM
    jne  .bad
.lookup:
    lea  rdi, [rbx + SSH_C_AUTH_PUB]
    call ssh_keystore_find
    cmp  eax, -1
    je   .bad
    mov  r12, rdx
    and  r12, [rbx + SSH_C_CAPMASK]       ; original ceiling never grows
    mov  rdi, [rbx + SSH_C_PID]
    test rdi, rdi
    jz   .bad
    cmp  rdi, PRIN_ADVISOR
    je   .bad
    call principal_capabilities
    test rax, rax                       ; missing/authority-free principal refuses
    jz   .bad
    mov  rdx, r12
    xor  eax, eax
    jmp  .out
.bad:
    xor  edx, edx
    mov  eax, -1
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; ssh_keystore_commit_stage -> EAX 0 committed / -1 refused. Seals the staged
; record (header, count, CRC), performs ONE SetVariable plus exact readback,
; and only then replaces the live table. Once SetVariable may run, authority
; is poisoned until exact readback succeeds or explicit validated reload.
; Pre-write refusals retain authority; no rollback/retry. RAM mode stays RAM.
ssh_keystore_commit_stage:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    cmp  byte [rel ssh_keys_state], SSHK_ST_RAM
    je   .available
    cmp  byte [rel ssh_keys_state], SSHK_ST_NVRAM
    jne  .bad
.available:
    mov  dword [rel ssh_keys_stage], SSHK_REC_MAGIC
    mov  word [rel ssh_keys_stage + 4], SSHK_REC_VERSION
    mov  word [rel ssh_keys_stage + 6], SSHK_REC_SIZE
    xor  edx, edx
    xor  ecx, ecx
.count:
    cmp  ecx, SSHK_MAX
    jae  .counted
    imul eax, ecx, SSHK_ENT_SIZE
    lea  rbx, [rel ssh_keys_stage + SSHK_REC_ENTRIES]
    add  edx, [rbx + rax + SSHK_ENT_FLAGS]
    inc  ecx
    jmp  .count
.counted:
    mov  [rel ssh_keys_stage + SSHK_REC_COUNT], edx
    mov  dword [rel ssh_keys_stage + 12], 0
    lea  rdi, [rel ssh_keys_stage]
    mov  esi, SSHK_REC_CRC
    call pbm_crc32
    mov  [rel ssh_keys_stage + SSHK_REC_CRC], eax
    lea  rdi, [rel ssh_keys_stage]
    call ssh_keystore_record_valid
    test eax, eax
    jz   .bad                           ; malformed stage is a no-write refusal
    cmp  byte [rel ssh_keys_state], SSHK_ST_RAM
    je   .commit
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .bad
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    cmp  qword [r12 + 0x48], 0
    je   .bad
    cmp  qword [r12 + 0x58], 0
    je   .bad
    call storage_access_request_intent      ; storage canon: PaOS-namespace NVRAM = NORMAL (ADMIN 06:22)
    mov  edx, eax
    lea  rdi, [rel ssh_keys_var_guid]
    lea  rsi, [rel ssh_keys_var_name]
    lea  rcx, [rel str_ssh_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    ; Firmware may mutate even when it returns an error.
    mov  byte [rel ssh_keys_state], SSHK_ST_POISONED ; possible write revokes authority
    lea  rcx, [rel ssh_keys_var_name]
    lea  rdx, [rel ssh_keys_var_guid]
    mov  r8d, AUTH_EFI_ATTRS
    mov  r9d, SSHK_REC_SIZE
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel ssh_keys_stage]
    mov  [rsp + 32], rbx
    call [r12 + 0x58]                   ; EFI_RUNTIME_SERVICES.SetVariable
    mov  rsp, r13
    test rax, rax
    jnz  .bad
    mov  qword [rel ssh_keys_var_size], SSHK_REC_SIZE
    mov  dword [rel ssh_keys_var_attrs], 0
    lea  rcx, [rel ssh_keys_var_name]
    lea  rdx, [rel ssh_keys_var_guid]
    lea  r8, [rel ssh_keys_var_attrs]
    lea  r9, [rel ssh_keys_var_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel ssh_keys_verify]
    mov  [rsp + 32], rbx
    call [r12 + 0x48]                   ; exact readback
    mov  rsp, r13
    test rax, rax
    jnz  .bad
    cmp  dword [rel ssh_keys_var_attrs], AUTH_EFI_ATTRS
    jne  .bad
    cmp  qword [rel ssh_keys_var_size], SSHK_REC_SIZE
    jne  .bad
    lea  rdi, [rel ssh_keys_stage]
    lea  rsi, [rel ssh_keys_verify]
    mov  edx, SSHK_REC_SIZE
    call memcmp
    test eax, eax
    jnz  .bad
    inc  qword [rel ssh_keys_nvram_writes]
.commit:
    lea  rdi, [rel ssh_keys_record]
    lea  rsi, [rel ssh_keys_stage]
    mov  edx, SSHK_REC_SIZE
    call memcpy
    cmp  byte [rel ssh_keys_state], SSHK_ST_RAM
    je   .ok
    mov  byte [rel ssh_keys_state], SSHK_ST_NVRAM ; publish authority after bytes
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

ssh_keystore_state_name:
    movzx eax, byte [rel ssh_keys_state]
    shl  eax, 4
    lea  rdx, [rel ssh_keys_state_names]
    add  rax, rdx
    ret

ssh_keystore_count:
    mov  eax, [rel ssh_keys_record + SSHK_REC_COUNT]
    ret

; ---------------------------------------------------------------------------
; Audit: every attempt, accepted or refused. Identical consecutive refusals
; (same reason + key fingerprint, no other audit record in between) rewrite
; the newest record with a repeat count instead of flooding the ring.
; ---------------------------------------------------------------------------
; ssh_auth_audit(EDI=SSH_AR_*, RSI=ctx or 0, RDX=pid)
ssh_auth_audit:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    cmp  byte [rel ssh_selftest_mode], 1
    jne  .live
    cmp  byte [rel ssh_auth_kat_audit], 1
    jne  .out
.live:
    lea  rdi, [rel ssh_audit_line]
    mov  esi, SSH_AUDIT_LINE_CAP
    call ssh_txt_reset
    test ebx, ebx
    jnz  .refused
    lea  rdi, [rel str_ssh_audit_ok]
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_txt_put_dec
    jmp  .fp
.refused:
    lea  rdi, [rel str_ssh_audit_refused]
    call ssh_txt_put_str
    mov  eax, ebx
    shl  eax, 4
    lea  rdi, [rel ssh_auth_reason_names]
    add  rdi, rax
    call ssh_txt_put_str
.fp:
    lea  rdi, [rel str_ssh_audit_fp]
    call ssh_txt_put_str
    test r12, r12
    jz   .no_fp
    cmp  byte [r12 + SSH_C_FP], 0
    je   .no_fp
    lea  rdi, [r12 + SSH_C_FP]
    mov  esi, 16
    call ssh_txt_put_bytes
    jmp  .fp_done
.no_fp:
    lea  rdi, [rel str_ssh_audit_nofp]
    call ssh_txt_put_str
.fp_done:
    test ebx, ebx
    jnz  .refusal_key
    mov  rdi, r12
    lea  rsi, [rel ssh_audit_line]
    call ssh_presence_prepare
    jmp  .log_new
.refusal_key:
    ; key = reason + first 16 fingerprint chars (the line itself, pre-count)
    cmp  byte [rel ssh_audit_rep_valid], 1
    jne  .log_new
    mov  rax, [rel audit_seq]
    cmp  rax, [rel ssh_audit_rep_seq]
    jne  .log_new
    lea  rdi, [rel ssh_audit_line]
    lea  rsi, [rel ssh_audit_rep_key]
    call strcmp
    test eax, eax
    jnz  .log_new
    cmp  qword [rel ssh_audit_rep_count], -1
    je   .repeat_capped
    inc  qword [rel ssh_audit_rep_count]
.repeat_capped:
    lea  rdi, [rel str_ssh_audit_repeat]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_audit_rep_count]
    call ssh_txt_put_dec
    lea  rdi, [rel ssh_audit_line]
    call audit_replace_newest
    jmp  .out
.log_new:
    mov  byte [rel ssh_audit_rep_valid], 0
    ; Network-access gate rule 3: the row carries src=ssh svc=ssh, the bound
    ; principal (ok) or none (refused), verb=userauth and the result/reason.
    lea  rdi, [rel ssh_audit_line]
    mov  esi, AUDIT_NET_META(AUDIT_NSRC_SSH, AUDIT_NSVC_SSH, AUDIT_NRES_ADMIT) | AUDIT_NET_FRESH
    mov  rdx, r13
    xor  ecx, ecx
    test ebx, ebx
    jz   .meta
    mov  esi, AUDIT_NET_META(AUDIT_NSRC_SSH, AUDIT_NSVC_SSH, AUDIT_NRES_REFUSED)
    xor  edx, edx
    mov  eax, ebx
    shl  eax, 4
    lea  rcx, [rel ssh_auth_reason_names]
    add  rcx, rax
.meta:
    lea  r8, [rel str_ssh_audit_userauth]
    call audit_log_net
    test ebx, ebx
    jnz  .refusal_receipt
    mov  rdi, r12
    mov  esi, eax
    call ssh_presence_audited           ; existing single successful attempt only
    jmp  .out
.refusal_receipt:
    test eax, eax
    jz   .out                              ; folded into an older row: nothing to re-arm
    lea  rdi, [rel ssh_audit_rep_key]
    lea  rsi, [rel ssh_audit_line]
    mov  edx, SSH_AUDIT_LINE_CAP
    call memcpy
    mov  rax, [rel audit_seq]
    mov  [rel ssh_audit_rep_seq], rax
    mov  qword [rel ssh_audit_rep_count], 1
    mov  byte [rel ssh_audit_rep_valid], 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_auth_audit_exec(RDI=verb cstr, RSI=pid, RDX=exit status, ECX=arg bytes,
;   R8=gate refusal reason cstr or 0, R9D=AUDIT_NRES_* of the network gate)
; One receipt per SSH exec (accepted or refused). Argument bytes are counted,
; never copied: an exec line can carry secrets the ring must not retain. The
; row's structured verb is the canonical name (net_audit_verb_name).
ssh_auth_audit_exec:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14d, ecx
    mov  r15, r8
    mov  [rel ssh_audit_exec_res], r9d
    cmp  byte [rel ssh_selftest_mode], 1
    je   .out
    lea  rdi, [rel ssh_audit_line]
    mov  esi, SSH_AUDIT_LINE_CAP
    call ssh_txt_reset
    lea  rdi, [rel str_ssh_audit_exec]
    call ssh_txt_put_str
    mov  rdi, r12
    call ssh_txt_put_dec
    lea  rdi, [rel str_ssh_audit_rc]
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_txt_put_dec
    lea  rdi, [rel str_ssh_audit_argb]
    call ssh_txt_put_str
    mov  edi, r14d
    call ssh_txt_put_dec
    lea  rdi, [rel str_ssh_audit_verb]
    call ssh_txt_put_str
    mov  rdi, rbx
    call ssh_txt_put_str
    mov  byte [rel ssh_audit_rep_valid], 0
    mov  rdi, rbx
    call net_audit_verb_name
    mov  r8, rax
    lea  rdi, [rel ssh_audit_line]
    mov  esi, [rel ssh_audit_exec_res]
    cmp  esi, AUDIT_NRES_ADMIT
    ja   .res_refused
    mov  esi, AUDIT_NET_META(AUDIT_NSRC_SSH, AUDIT_NSVC_SSH, AUDIT_NRES_ADMIT) | AUDIT_NET_FRESH
    jmp  .res_ok                           ; exec on a signature-bound connection: fresh
.res_refused:
    shl  esi, 16
    or   esi, AUDIT_NSRC_SSH | (AUDIT_NSVC_SSH << 8)
.res_ok:
    mov  rdx, r12
    mov  rcx, r15
    call audit_log_net
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; RFC 4252 USERAUTH_REQUEST.
; ssh_userauth_packet(RDI=ctx, RSI=payload, EDX=len) -> EAX 0 reply queued /
; -1 close. The payload lives in ctx PLAIN, which sealing a reply overwrites,
; so every input field is consumed before the first ssh_queue_gcm.
; ---------------------------------------------------------------------------
ssh_userauth_packet:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rsi
    add  r13, rdx                        ; payload end
    test edx, edx
    jz   .fatal
    cmp  byte [r12], SSH_MSG_USERAUTH_REQUEST
    jne  .ignored                        ; RFC 4253 11: unrelated messages are ignored
    lea  rdi, [r12 + 1]
    mov  rsi, r13
    call ssh_string_read
    cmp  rax, -1
    je   .fatal
    mov  [rel ssh_ua_user], rax
    mov  [rel ssh_ua_user_len], edx
    mov  rdi, r8
    mov  rsi, r13
    call ssh_string_read
    cmp  rax, -1
    je   .fatal
    mov  [rel ssh_ua_service], rax
    mov  [rel ssh_ua_service_len], edx
    mov  rdi, r8
    mov  rsi, r13
    call ssh_string_read
    cmp  rax, -1
    je   .fatal
    mov  r14, r8                         ; cursor after method
    mov  byte [rbx + SSH_C_FP], 0
    mov  rdi, rax
    mov  esi, edx
    lea  rdx, [rel str_ssh_method_none]
    mov  ecx, 4
    push rdi
    push rsi
    call ssh_bytes_eq
    pop  rsi
    pop  rdi
    test eax, eax
    jnz  .methods
    lea  rdx, [rel str_ssh_method_publickey]
    mov  ecx, 9
    call ssh_bytes_eq
    test eax, eax
    jz   .bad_method
    ; boolean has_signature, algorithm name, key blob
    cmp  r14, r13
    jae  .fatal
    movzx eax, byte [r14]
    mov  [rel ssh_ua_has_sig], al
    lea  rdi, [r14 + 1]
    mov  rsi, r13
    call ssh_string_read
    cmp  rax, -1
    je   .fatal
    mov  [rel ssh_ua_alg], rax
    mov  [rel ssh_ua_alg_len], edx
    mov  rdi, r8
    mov  rsi, r13
    call ssh_string_read
    cmp  rax, -1
    je   .fatal
    mov  [rel ssh_ua_blob], rax
    mov  r15, r8                          ; end of the signed prefix
    cmp  edx, SSH_KEY_BLOB_LEN
    jne  .bad_alg
    mov  rdi, [rel ssh_ua_alg]
    mov  esi, [rel ssh_ua_alg_len]
    lea  rdx, [rel ssh_alg_host]
    mov  ecx, ssh_alg_host.len
    call ssh_bytes_eq
    test eax, eax
    jz   .bad_alg
    mov  rdi, [rel ssh_ua_blob]
    mov  esi, SSH_KEY_BLOB_LEN - 32
    lea  rdx, [rel ssh_user_key_prefix]
    mov  ecx, SSH_KEY_BLOB_LEN - 32
    call ssh_bytes_eq
    test eax, eax
    jz   .bad_alg
    ; Fingerprint of the offered key (audit + SSHSTAT), before any decision.
    mov  rdi, [rel ssh_ua_blob]
    add  rdi, SSH_KEY_BLOB_LEN - 32
    lea  rsi, [rbx + SSH_C_FP]
    call ssh_key_fingerprint
    mov  rdi, [rel ssh_ua_user]
    mov  esi, [rel ssh_ua_user_len]
    lea  rdx, [rel str_ssh_login_user]
    mov  ecx, 4
    call ssh_bytes_eq
    test eax, eax
    jz   .bad_user
    mov  rdi, [rel ssh_ua_service]
    mov  esi, [rel ssh_ua_service_len]
    lea  rdx, [rel str_ssh_service_connection]
    mov  ecx, 14
    call ssh_bytes_eq
    test eax, eax
    jz   .bad_service
    ; Bounded global backoff: while active, even an enrolled key is refused.
    call ssh_auth_backoff_remaining
    test rax, rax
    jnz  .lockout
    mov  rdi, [rel ssh_ua_blob]
    add  rdi, SSH_KEY_BLOB_LEN - 32
    call ssh_keystore_find
    cmp  eax, -1
    je   .unenrolled
    mov  [rel ssh_ua_key_slot], eax
    mov  [rel ssh_ua_key_caps], rdx
    cmp  byte [rel ssh_ua_has_sig], 0
    jne  .signed
    ; Query only: say the key is acceptable, bind NOTHING (RFC 4252 7).
    lea  rdi, [rel ssh_ua_reply]
    mov  byte [rdi], SSH_MSG_USERAUTH_PK_OK
    lea  rdi, [rel ssh_ua_reply + 1]
    mov  esi, ssh_alg_host.len
    call ssh_be32_store
    lea  rdi, [rel ssh_ua_reply + 5]
    lea  rsi, [rel ssh_alg_host]
    mov  edx, ssh_alg_host.len
    call memcpy
    lea  rdi, [rel ssh_ua_reply + 5 + ssh_alg_host.len]
    mov  esi, SSH_KEY_BLOB_LEN
    call ssh_be32_store
    lea  rdi, [rel ssh_ua_reply + 9 + ssh_alg_host.len]
    mov  rsi, [rel ssh_ua_blob]
    mov  edx, SSH_KEY_BLOB_LEN
    call memcpy
    mov  rdi, rbx
    lea  rsi, [rel ssh_ua_reply]
    mov  edx, 9 + ssh_alg_host.len + SSH_KEY_BLOB_LEN
    call ssh_queue_gcm
    jmp  .queued
.signed:
    mov  rdi, r15
    mov  rsi, r13
    call ssh_string_read
    cmp  rax, -1
    je   .fatal
    cmp  r8, r13
    jne  .fatal                           ; nothing may trail the signature
    cmp  edx, SSH_SIG_BLOB_WIRE_LEN
    jne  .badsig
    mov  r14, rax                         ; signature blob
    mov  rdi, r14
    mov  esi, SSH_SIG_BLOB_WIRE_LEN - 64
    lea  rdx, [rel ssh_user_sig_prefix]
    mov  ecx, SSH_SIG_BLOB_WIRE_LEN - 64
    call ssh_bytes_eq
    test eax, eax
    jz   .badsig
    ; RFC 4252 7 signed data: string session_id || the request through the key blob.
    mov  rcx, r15
    sub  rcx, r12
    lea  rax, [rcx + 36]
    cmp  rax, SSH_UA_SIGNED_CAP
    ja   .badsig
    mov  [rel ssh_ua_proof + AUTH_ED25519_PROOF_MSG_LEN], rax
    push rcx
    lea  rdi, [rel ssh_ua_signed]
    mov  esi, 32
    call ssh_be32_store
    lea  rdi, [rel ssh_ua_signed + 4]
    lea  rsi, [rbx + SSH_C_SESSION_ID]
    mov  edx, 32
    call memcpy
    pop  rdx
    lea  rdi, [rel ssh_ua_signed + 36]
    mov  rsi, r12
    call memcpy
    mov  rax, [rel ssh_ua_blob]
    add  rax, SSH_KEY_BLOB_LEN - 32
    mov  [rel ssh_ua_proof + AUTH_ED25519_PROOF_PUB], rax
    lea  rax, [rel ssh_ua_signed]
    mov  [rel ssh_ua_proof + AUTH_ED25519_PROOF_MSG], rax
    lea  rax, [r14 + SSH_SIG_BLOB_WIRE_LEN - 64]
    mov  [rel ssh_ua_proof + AUTH_ED25519_PROOF_SIG], rax
    lea  rdi, [rel ssh_ua_auth_ctx]
    xor  esi, esi
    mov  edx, AUTH_CTX_SIZE
    call memset
    lea  rax, [rel ssh_ua_proof]
    mov  [rel ssh_ua_auth_ctx + AUTH_CTX_CREDENTIAL], rax
    mov  qword [rel ssh_ua_auth_ctx + AUTH_CTX_CRED_LEN], AUTH_ED25519_PROOF_SIZE
    mov  edi, AUTH_BIND_ED25519
    lea  rsi, [rel ssh_ua_auth_ctx]
    call authenticate_bind               ; the one Task2501 seam; output-only pid
    test rax, rax
    jz   .badsig
    ; Bound: this CONNECTION now runs as the verifier-selected principal.
    mov  r14, rax
    mov  [rbx + SSH_C_PID], rax
    ; Capture the actual verified key bytes only after the output-only bind
    ; succeeds. An unsigned offer/display fingerprint carries no authority.
    lea  rdi, [rbx + SSH_C_AUTH_PUB]
    mov  rsi, [rel ssh_ua_proof + AUTH_ED25519_PROOF_PUB]
    mov  edx, 32
    call memcpy
    mov  byte [rbx + SSH_C_AUTH_BOUND], 1
    mov  rax, r14
    mov  rdx, [rel ssh_ua_key_caps]
    mov  [rbx + SSH_C_CAPMASK], rdx
    mov  edx, [rel ssh_ua_key_slot]
    mov  [rbx + SSH_C_KEY_INDEX], dl
    mov  byte [rbx + SSH_C_STATE], SSH_STATE_CONNECTION
    mov  qword [rel ssh_auth_streak], 0
    mov  qword [rel ssh_auth_backoff_left], 0
    mov  qword [rel ssh_auth_backoff_last], 0
    cmp  qword [rel ssh_auth_ok_count], -1
    je   .ok_capped
    inc  qword [rel ssh_auth_ok_count]
.ok_capped:
    mov  [rel ssh_auth_last_pid], rax
    xor  edi, edi
    mov  rsi, rbx
    mov  rdx, rax
    call ssh_auth_audit
    mov  byte [rel ssh_onebyte_reply], SSH_MSG_USERAUTH_SUCCESS
    mov  rdi, rbx
    lea  rsi, [rel ssh_onebyte_reply]
    mov  edx, 1
    call ssh_queue_gcm
    jmp  .queued
.methods:
    ; "none" lists the methods; it is neither an attempt nor a failure.
    mov  rdi, rbx
    lea  rsi, [rel ssh_userauth_failure]
    mov  edx, SSH_USERAUTH_FAILURE_LEN
    call ssh_queue_gcm
    jmp  .queued
.bad_method:
    mov  edi, SSH_AR_METHOD
    jmp  .refuse
.bad_alg:
    mov  edi, SSH_AR_ALG
    jmp  .refuse
.bad_user:
    mov  edi, SSH_AR_USER
    jmp  .refuse
.bad_service:
    mov  edi, SSH_AR_SERVICE
    jmp  .refuse
.unenrolled:
    mov  edi, SSH_AR_UNENROLLED
    jmp  .refuse
.badsig:
    mov  edi, SSH_AR_BADSIG
    jmp  .refuse
.lockout:
    mov  edi, SSH_AR_LOCKOUT
.refuse:
    mov  r14d, edi
    cmp  byte [rbx + SSH_C_AUTH_FAILS], 255
    je   .conn_capped
    inc  byte [rbx + SSH_C_AUTH_FAILS]
.conn_capped:
    cmp  qword [rel ssh_auth_fail_count], -1
    je   .fail_capped
    inc  qword [rel ssh_auth_fail_count]
.fail_capped:
    cmp  r14d, SSH_AR_LOCKOUT
    je   .refuse_audit                    ; attempts during backoff never extend it
    ; Earlier parser/method/user refusals also cannot extend an active wait.
    call ssh_auth_backoff_remaining
    test rax, rax
    jnz  .refuse_audit
    cmp  qword [rel ssh_auth_streak], -1
    je   .streak_capped
    inc  qword [rel ssh_auth_streak]
.streak_capped:
    mov  rcx, [rel ssh_auth_streak]
    cmp  rcx, SSH_AUTH_LOCK_AFTER
    jb   .refuse_audit
    sub  rcx, SSH_AUTH_LOCK_AFTER
    cmp  rcx, 4
    jbe  .shift_ok
    mov  ecx, 4
.shift_ok:
    mov  eax, SSH_AUTH_BACKOFF_MS
    shl  rax, cl
    cmp  rax, SSH_AUTH_BACKOFF_MAX_MS
    jbe  .backoff_ok
    mov  eax, SSH_AUTH_BACKOFF_MAX_MS
.backoff_ok:
    mov  [rel ssh_auth_backoff_ms], rax
    mov  [rel ssh_auth_backoff_left], rax
    call boot_ms_now
    mov  [rel ssh_auth_backoff_last], rax
    cmp  qword [rel ssh_auth_lockouts], -1
    je   .refuse_audit
    inc  qword [rel ssh_auth_lockouts]
.refuse_audit:
    mov  edi, r14d
    mov  rsi, rbx
    xor  edx, edx
    call ssh_auth_audit
    mov  rdi, rbx
    lea  rsi, [rel ssh_userauth_failure]
    mov  edx, SSH_USERAUTH_FAILURE_LEN
    call ssh_queue_gcm
    test eax, eax
    jnz  .fatal
    cmp  byte [rbx + SSH_C_AUTH_FAILS], SSH_AUTH_CONN_MAX
    jae  .fatal                           ; this connection spent its attempts
    xor  eax, eax
    jmp  .out
.queued:
    test eax, eax
    jnz  .fatal
.ignored:
    xor  eax, eax
    jmp  .out
.fatal:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssh_auth_backoff_remaining() -> RAX=remaining milliseconds (0..60000).
; Boot-clock custody, shared by USERAUTH and its read-only status projection.
; No absolute deadline/addition: a near-u64 sample cannot wrap into admission.
; Zero means unavailable: invalidate the baseline, credit nothing. The first
; recovery sample and each backwards/reset sample only rebase; repeated samples
; credit nothing. Thereafter a forward difference consumes at most the bounded
; remaining duration. No polling, policy/counter/audit mutation or wall clock.
; Clobbers only RAX,RCX,RDX (same as boot_ms_now); BSP SSH command ownership.
ssh_auth_backoff_remaining:
    cmp  qword [rel ssh_auth_backoff_left], 0
    je   .empty
    call boot_ms_now
    mov  rdx, [rel ssh_auth_backoff_last]
    mov  [rel ssh_auth_backoff_last], rax
    test rax, rax
    jz   .remaining
    test rdx, rdx
    jz   .remaining
    cmp  rax, rdx
    jbe  .remaining
    sub  rax, rdx
    cmp  rax, [rel ssh_auth_backoff_left]
    jae  .expired
    sub  [rel ssh_auth_backoff_left], rax
.remaining:
    mov  rax, [rel ssh_auth_backoff_left]
    ret
.expired:
    mov  qword [rel ssh_auth_backoff_last], 0
    mov  qword [rel ssh_auth_backoff_left], 0
.empty:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; Registry verbs (projections through the ONE command registry).
; ---------------------------------------------------------------------------
; Enrollment authority: an owner-signed AUTH1 envelope that the command_auth
; gate has already verified and consumed. An SSH-authenticated request never
; enrolls or removes keys (a stolen key must not be able to mint another).
ssh_keyverb_owner_signed:
    cmp  qword [rdi + REQ_SOURCE], CMD_SOURCE_SSH
    je   .no
    cmp  byte [rel command_auth_remote_active], 1
    jne  .no
    mov  rax, [rel command_auth_remote_ticket]
    test rax, rax
    jz   .no
    cmp  byte [rax + AUTH_T_STATE], AUTH_TS_CONSUMED
    jne  .no
    cmp  qword [rax + AUTH_T_PRINCIPAL], PRIN_OWNER
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

ssh_keyverb_out_begin:
    lea  rdi, [rel ssh_cmd_out_buf]
    mov  esi, SSH_CMD_OUT_CAP
    jmp  ssh_txt_reset

ssh_keyverb_finish_ok:
    mov  byte [rel ssh_cmd_out_ready], 1
    mov  qword [rdi + RSP_ACCEPTED], 1
    mov  qword [rdi + RSP_CODE], CMDE_OK
    ret

ssh_keyverb_finish_err:
    mov  byte [rel ssh_cmd_out_ready], 1
    mov  qword [rdi + RSP_ACCEPTED], 0
    mov  qword [rdi + RSP_CODE], CMDE_BADARG
    ret

; skip spaces: RDI=ptr -> RAX=first non-space
ssh_keyverb_skip:
    mov  rax, rdi
.loop:
    cmp  byte [rax], ' '
    jne  .done
    inc  rax
    jmp  .loop
.done:
    ret

; token length: RDI=ptr -> EAX bytes before space/NUL
ssh_keyverb_toklen:
    xor  eax, eax
.loop:
    mov  cl, [rdi + rax]
    test cl, cl
    jz   .done
    cmp  cl, ' '
    je   .done
    inc  eax
    jmp  .loop
.done:
    ret

; SSHKEYADD [ssh-ed25519 ]<base64 key blob> [caps=<16hex>] [comment]
cmd_verb_sshkeyadd:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15, rsi
    mov  r14, rdi
    mov  r12, [rdi + REQ_ARG]
    call ssh_keyverb_out_begin
    call principal_owner_change_ready
    test eax, eax
    jz .pending_owner
    mov  rdi, r14
    call ssh_keyverb_owner_signed
    test eax, eax
    jz   .need_auth1
    test r12, r12
    jz   .grammar
    mov  rdi, r12
    call ssh_keyverb_skip
    mov  r12, rax
    mov  rdi, r12
    call ssh_keyverb_toklen
    cmp  eax, ssh_alg_host.len
    jne  .blob
    mov  rdi, r12
    mov  esi, eax
    lea  rdx, [rel ssh_alg_host]
    mov  ecx, ssh_alg_host.len
    call ssh_bytes_eq
    test eax, eax
    jz   .blob
    lea  rdi, [r12 + ssh_alg_host.len]
    call ssh_keyverb_skip
    mov  r12, rax
.blob:
    mov  rdi, r12
    call ssh_keyverb_toklen
    test eax, eax
    jz   .grammar
    cmp  eax, 96
    ja   .grammar
    mov  r13d, eax
    mov  rdi, r12
    mov  esi, r13d
    lea  rdx, [rel ssh_keyverb_blob]
    mov  ecx, 64
    call ssh_b64_decode
    cmp  eax, SSH_KEY_BLOB_LEN
    jne  .grammar
    lea  rdi, [rel ssh_keyverb_blob]
    mov  esi, SSH_KEY_BLOB_LEN - 32
    lea  rdx, [rel ssh_user_key_prefix]
    mov  ecx, SSH_KEY_BLOB_LEN - 32
    call ssh_bytes_eq
    test eax, eax
    jz   .grammar
    ; optional caps=<16hex> restriction (default: everything the principal holds)
    mov  rax, SSHK_CAPS_ALL
    mov  [rel ssh_keyverb_caps], rax
    lea  rdi, [r12 + r13]
    call ssh_keyverb_skip
    mov  r12, rax
    cmp  dword [r12], 'caps'
    jne  .caps_done
    cmp  byte [r12 + 4], '='
    jne  .caps_done
    lea  rdi, [r12 + 5]
    call command_auth_parse_hex64
    jc   .grammar
    mov  [rel ssh_keyverb_caps], rax
.caps_done:
    cmp  byte [rel ssh_keys_state], SSHK_ST_POISONED
    je   .store_bad
    cmp  byte [rel ssh_keys_state], SSHK_ST_UNAVAILABLE
    je   .store_bad
    lea  rdi, [rel ssh_keyverb_blob + SSH_KEY_BLOB_LEN - 32]
    call ssh_keystore_find
    cmp  eax, -1
    jne  .exists
    ; first free slot
    xor  ebx, ebx
.free:
    cmp  ebx, SSHK_MAX
    jae  .full
    imul eax, ebx, SSHK_ENT_SIZE
    lea  rcx, [rel ssh_keys_record + SSHK_REC_ENTRIES]
    cmp  dword [rcx + rax + SSHK_ENT_FLAGS], 0
    je   .slot
    inc  ebx
    jmp  .free
.slot:
    lea  rdi, [rel ssh_keys_stage]
    lea  rsi, [rel ssh_keys_record]
    mov  edx, SSHK_REC_SIZE
    call memcpy
    imul eax, ebx, SSHK_ENT_SIZE
    lea  r13, [rel ssh_keys_stage + SSHK_REC_ENTRIES]
    add  r13, rax
    mov  rdi, r13
    lea  rsi, [rel ssh_keyverb_blob + SSH_KEY_BLOB_LEN - 32]
    mov  edx, 32
    call memcpy
    mov  rax, [rel ssh_keyverb_caps]
    mov  [r13 + SSHK_ENT_CAPS], rax
    mov  dword [r13 + SSHK_ENT_FLAGS], 1
    mov  dword [r13 + SSHK_ENT_FLAGS + 4], 0
    call ssh_keystore_commit_stage
    test eax, eax
    jnz  .persist_failed
    lea  rdi, [rel str_sshkeyadd_ok]
    call ssh_txt_put_str
    jmp  .describe
.exists:
    mov  ebx, eax
    lea  rdi, [rel str_sshkeyadd_exists]
    call ssh_txt_put_str
.describe:
    mov  edi, ebx
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshkey_fp]
    call ssh_txt_put_str
    lea  rdi, [rel ssh_keyverb_blob + SSH_KEY_BLOB_LEN - 32]
    lea  rsi, [rel ssh_keyverb_fp]
    call ssh_key_fingerprint
    lea  rdi, [rel ssh_keyverb_fp]
    call ssh_txt_put_str
    lea  rdi, [rel str_sshkey_caps]
    call ssh_txt_put_str
    imul eax, ebx, SSHK_ENT_SIZE
    lea  rcx, [rel ssh_keys_record + SSHK_REC_ENTRIES]
    mov  rdi, [rcx + rax + SSHK_ENT_CAPS]
    call ssh_txt_put_hex16
    call ssh_keyverb_put_store
    mov  rdi, r15
    call ssh_keyverb_finish_ok
    jmp  .out
.pending_owner:
    lea rdi, [rel str_sshkey_pending_owner]
    call ssh_txt_put_str
    jmp .err
.need_auth1:
    lea  rdi, [rel str_sshkeyadd_need_auth1]
    call ssh_txt_put_str
    jmp  .err
.grammar:
    lea  rdi, [rel str_sshkeyadd_grammar]
    call ssh_txt_put_str
    jmp  .err
.full:
    lea  rdi, [rel str_sshkeyadd_full]
    call ssh_txt_put_str
    jmp  .err
.store_bad:
.persist_failed:
    lea  rdi, [rel str_sshkeyadd_persist]
    call ssh_txt_put_str
    call ssh_keyverb_put_store
.err:
    mov  rdi, r15
    call ssh_keyverb_finish_err
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

ssh_keyverb_put_store:
    lea  rdi, [rel str_sshkey_keys]
    call ssh_txt_put_str
    call ssh_keystore_count
    mov  edi, eax
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshkey_store]
    call ssh_txt_put_str
    call ssh_keystore_state_name
    mov  rdi, rax
    jmp  ssh_txt_put_str

; SSHKEYDEL <slot>
cmd_verb_sshkeydel:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  r12, rdi
    call ssh_keyverb_out_begin
    call principal_owner_change_ready
    test eax, eax
    jz .pending_owner
    mov  rdi, r12
    call ssh_keyverb_owner_signed
    test eax, eax
    jz   .need_auth1
    mov  rdi, [r12 + REQ_ARG]
    test rdi, rdi
    jz   .grammar
    call ssh_keyverb_skip
    movzx ebx, byte [rax]
    sub  ebx, '0'
    cmp  ebx, SSHK_MAX
    jae  .grammar
    cmp  byte [rax + 1], 0
    je   .slot_ok
    cmp  byte [rax + 1], ' '
    jne  .grammar
.slot_ok:
    imul eax, ebx, SSHK_ENT_SIZE
    lea  rcx, [rel ssh_keys_record + SSHK_REC_ENTRIES]
    cmp  dword [rcx + rax + SSHK_ENT_FLAGS], 1
    jne  .empty
    lea  rdi, [rel ssh_keys_stage]
    lea  rsi, [rel ssh_keys_record]
    mov  edx, SSHK_REC_SIZE
    call memcpy
    imul eax, ebx, SSHK_ENT_SIZE
    lea  rdi, [rel ssh_keys_stage + SSHK_REC_ENTRIES]
    add  rdi, rax
    xor  esi, esi
    mov  edx, SSHK_ENT_SIZE
    call memset
    call ssh_keystore_commit_stage
    test eax, eax
    jnz  .persist_failed
    lea  rdi, [rel str_sshkeydel_ok]
    call ssh_txt_put_str
    mov  edi, ebx
    call ssh_txt_put_dec
    call ssh_keyverb_put_store
    mov  rdi, r13
    call ssh_keyverb_finish_ok
    jmp  .out
.pending_owner:
    lea rdi, [rel str_sshkey_pending_owner]
    call ssh_txt_put_str
    jmp .err
.need_auth1:
    lea  rdi, [rel str_sshkeydel_need_auth1]
    call ssh_txt_put_str
    jmp  .err
.grammar:
    lea  rdi, [rel str_sshkeydel_grammar]
    call ssh_txt_put_str
    jmp  .err
.empty:
    lea  rdi, [rel str_sshkeydel_empty]
    call ssh_txt_put_str
    jmp  .err
.persist_failed:
    lea  rdi, [rel str_sshkeyadd_persist]
    call ssh_txt_put_str
    call ssh_keyverb_put_store
.err:
    mov  rdi, r13
    call ssh_keyverb_finish_err
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
%include "svc/ssh_profile_command.inc"
; ---------------------------------------------------------------------------

%include "svc/ssh_trust_replace_command.inc"

; SSHKHTRUST <IPv4>:<port> <64 lower-case SHA256 hex digits>.
; Explicit owner provision, never a trust prompt automatically answered by the
; peer. AUTH1 owner MUTATE gate precedes parsing and any native store operation.
; No replacement/clear, EFI write, signing, credential send or connection start.
cmd_verb_sshkhtrust:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    sub  rsp, 48                       ; public IPv4/port/digest only
    call ssh_keyverb_out_begin
    mov  rdi, r12
    call ssh_keyverb_owner_signed
    test eax, eax
    jz   .owner
    mov  rdi, [r12 + REQ_ARG]
    mov  rsi, rsp
    call ssh_khtrust_parse
    test eax, eax
    jnz  .grammar
    mov  edi, [rsp]
    mov  esi, [rsp + 4]
    lea  rdx, [rsp + 8]
    call ssh_cli_trust_host
    test eax, eax
    js   .refused
    lea  rdi, [rel str_sshkhtrust_ok]
    test eax, eax
    jz   .accepted
    lea  rdi, [rel str_sshkhtrust_same]
.accepted:
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_ok
    jmp  .out
.owner:
    lea  rdi, [rel str_sshkhtrust_owner]
    jmp  .err
.grammar:
    lea  rdi, [rel str_sshkhtrust_usage]
    jmp  .err
.refused:
    lea  rdi, [rel str_sshkhtrust_unavailable]
    cmp  eax, -2
    je   .full
    cmp  eax, -3
    jne  .err
    lea  rdi, [rel str_sshkhtrust_conflict]
    jmp  .err
.full:
    lea  rdi, [rel str_sshkhtrust_full]
.err:
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_err
.out:
    ; No secret bytes, but do not retain another request's public parse buffer.
    mov  rdi, rsp
    xor  esi, esi
    mov  edx, 48
    call memset
    add  rsp, 48
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=NUL argument, RSI=40B output IPv4(memory order),port(u32),digest32.
; Exact finite grammar, <=3 digits/octet, <=5/port, no trailing whitespace.
; Output is private to the handler's stack; no partial parse can reach a store.
ssh_khtrust_parse:
    test rdi, rdi
    jz   .bad
    mov  r8, rsi
    xor  r9d, r9d
.octet:
    xor  eax, eax
    xor  r10d, r10d
.digit:
    movzx edx, byte [rdi]
    sub  edx, '0'
    cmp  edx, 9
    ja   .octet_end
    inc  r10d
    cmp  r10d, 3
    ja   .bad
    imul eax, eax, 10
    add  eax, edx
    cmp  eax, 255
    ja   .bad
    inc  rdi
    jmp  .digit
.octet_end:
    test r10d, r10d
    jz   .bad
    mov  [r8 + r9], al
    inc  r9d
    cmp  r9d, 4
    je   .port
    cmp  byte [rdi], '.'
    jne  .bad
    inc  rdi
    jmp  .octet
.port:
    cmp  byte [rdi], ':'
    jne  .bad
    cmp  dword [r8], 0
    je   .bad
    inc  rdi
    xor  eax, eax
    xor  r10d, r10d
.port_digit:
    movzx edx, byte [rdi]
    sub  edx, '0'
    cmp  edx, 9
    ja   .port_end
    inc  r10d
    cmp  r10d, 5
    ja   .bad
    imul eax, eax, 10
    add  eax, edx
    cmp  eax, 65535
    ja   .bad
    inc  rdi
    jmp  .port_digit
.port_end:
    test eax, eax
    jz   .bad
    cmp  byte [rdi], ' '
    jne  .bad
    mov  [r8 + 4], eax
    inc  rdi
    xor  ecx, ecx
.hex:
    movzx eax, byte [rdi + rcx]
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .number
    sub  eax, 'a'
    cmp  eax, 5
    ja   .bad
    add  eax, 10
    jmp  .nibble
.number:
    sub  eax, '0'
.nibble:
    mov  r9d, ecx
    shr  r9d, 1
    test cl, 1
    jnz  .low
    shl  eax, 4
    mov  [r8 + r9 + 8], al
    jmp  .next
.low:
    or   [r8 + r9 + 8], al
.next:
    inc  ecx
    cmp  ecx, 64
    jb   .hex
    cmp  byte [rdi + 64], 0
    jne  .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; SSHKHCLEAR (RCQ-07b): the owner's explicit clear of the SSH CLIENT's
; known_hosts (PaOSSshKnownHosts, svc/ssh_client). Every saved and in-boot
; host-key pin is forgotten: the only way out of a damaged or unauthentic store,
; and how a legitimately rotated server key is accepted again. Owner-signed
; AUTH1 only, never over SSH (the same authority as SSHKEYDEL).
cmd_verb_sshkhclear:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  r12, rdi
    call ssh_keyverb_out_begin
    mov  rdi, r12
    call ssh_keyverb_owner_signed
    test eax, eax
    jz   .need_auth1
    call ssh_cli_known_hosts_clear
    test rax, rax
    jnz  .failed
    lea  rdi, [rel str_sshkhclear_ok]
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_ok
    jmp  .out
.need_auth1:
    lea  rdi, [rel str_sshkhclear_need_auth1]
    call ssh_txt_put_str
    jmp  .err
.failed:
    cmp  rax, -2
    je   .uncertain
    lea  rdi, [rel str_sshkhclear_failed]
    call ssh_txt_put_str
    jmp  .err
.uncertain:
    lea  rdi, [rel str_sshkhclear_uncertain]
    call ssh_txt_put_str
.err:
    mov  rdi, r13
    call ssh_keyverb_finish_err
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; SSHKEYLIST — public read: fingerprints + capability masks, never key bytes.
cmd_verb_sshkeylist:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    call ssh_keyverb_out_begin
    lea  rdi, [rel str_sshkeylist_hdr]
    call ssh_txt_put_str
    call ssh_keystore_count
    mov  edi, eax
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshkey_store]
    call ssh_txt_put_str
    call ssh_keystore_state_name
    mov  rdi, rax
    call ssh_txt_put_str
    xor  ebx, ebx
.slot:
    cmp  ebx, SSHK_MAX
    jae  .done
    imul eax, ebx, SSHK_ENT_SIZE
    lea  r12, [rel ssh_keys_record + SSHK_REC_ENTRIES]
    add  r12, rax
    cmp  dword [r12 + SSHK_ENT_FLAGS], 1
    jne  .next
    lea  rdi, [rel str_sshkeylist_k]
    call ssh_txt_put_str
    mov  edi, ebx
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshkeylist_eq]
    call ssh_txt_put_str
    mov  rdi, r12
    lea  rsi, [rel ssh_keyverb_fp]
    call ssh_key_fingerprint
    lea  rdi, [rel ssh_keyverb_fp]
    call ssh_txt_put_str
    lea  rdi, [rel str_sshkey_caps]
    call ssh_txt_put_str
    mov  rdi, [r12 + SSHK_ENT_CAPS]
    call ssh_txt_put_hex16
.next:
    inc  ebx
    jmp  .slot
.done:
    mov  rdi, r13
    call ssh_keyverb_finish_ok
    pop  r13
    pop  r12
    pop  rbx
    ret

; SSHSTAT — public read of the SSH login surface plus THIS request's own
; source/principal (an SSH exec reports source=ssh and its bound pid).
cmd_verb_sshstat:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  r12, rdi
    call ssh_keyverb_out_begin
    lea  rdi, [rel str_sshstat_source]
    call ssh_txt_put_str
    mov  rax, [r12 + REQ_SOURCE]
    cmp  rax, CMD_SOURCE_SSH
    jbe  .src_ok
    mov  eax, 6
.src_ok:
    shl  eax, 4
    lea  rdi, [rel ssh_source_names]
    add  rdi, rax
    call ssh_txt_put_str
    lea  rdi, [rel str_sshstat_principal]
    call ssh_txt_put_str
    mov  rdi, [r12 + REQ_PRINCIPAL]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshstat_ok]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_auth_ok_count]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshstat_fail]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_auth_fail_count]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshstat_streak]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_auth_streak]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshstat_lockouts]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_auth_lockouts]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshstat_lockout_ms]
    call ssh_txt_put_str
    call ssh_auth_backoff_remaining
    mov  rdi, rax
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshstat_exec]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_exec_count]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshstat_exec_refused]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_exec_refused]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshstat_nvram_writes]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_keys_nvram_writes]
    call ssh_txt_put_dec
    call ssh_keyverb_put_store
    mov  rdi, r13
    call ssh_keyverb_finish_ok
    pop  r13
    pop  r12
    pop  rbx
    ret

; SSHRECORD <16 lowercase hex nonce>: authenticated owner carrier only.
; Observes the actual cached AEAD failure, never starts capture or touches a
; live context, TCP, crypto, auth state, retirement, counters or deadlines.
cmd_verb_sshrecord:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    call ssh_keyverb_out_begin
    mov  rdi, r12
    call ssh_keyverb_owner_signed
    test eax, eax
    jz   .bad
    mov  rbx, [r12 + REQ_ARG]
    test rbx, rbx
    jz   .bad
    xor  ecx, ecx
.nonce:
    movzx eax, byte [rbx + rcx]
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .next
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
.next:
    inc  ecx
    cmp  ecx, 16
    jb   .nonce
    cmp  byte [rbx + 16], 0
    jne  .bad
    lea  rdi, [rel str_sshrecord_prefix]
    call ssh_txt_put_str
    mov  rdi, rbx
    mov  esi, 16
    call ssh_txt_put_bytes
    lea  rdi, [rel str_sshrecord_event]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_event]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_ready]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_ready]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_connection]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_connection]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_previous_bytes]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_previous_bytes]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_previous_ordinal]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_previous_ordinal]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_rejected_bytes]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_rejected_bytes]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_rejected_ordinal]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_rejected_ordinal]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_state]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_state]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_principal]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_principal]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_bound]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_bound]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_exec]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_exec]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_auth_ok]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_auth_ok]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_nvram_writes]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_nvram_writes]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_local_ip]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_local_ip]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_remote_ip]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_remote_ip]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_local_port]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_local_port]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_remote_port]
    call ssh_txt_put_str
    mov  rdi, [rel ssh_record_remote_port]
    call ssh_txt_put_hex16
    lea  rdi, [rel str_sshrecord_previous]
    call ssh_txt_put_str
    lea  rbx, [rel ssh_record_previous]
    mov  r12d, 4
.previous:
    mov  rdi, [rbx]
    bswap rdi
    call ssh_txt_put_hex16
    add  rbx, 8
    dec  r12d
    jnz  .previous
    lea  rdi, [rel str_sshrecord_rejected]
    call ssh_txt_put_str
    lea  rbx, [rel ssh_record_rejected]
    mov  r12d, 4
.rejected:
    mov  rdi, [rbx]
    bswap rdi
    call ssh_txt_put_hex16
    add  rbx, 8
    dec  r12d
    jnz  .rejected
    mov  rdi, r13
    call ssh_keyverb_finish_ok
    jmp  .out
.bad:
    lea  rdi, [rel str_sshrecord_refused]
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_err
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Boot KATs: publickey verify against the enrolled-key store, principal
; binding (connection-scoped, output-only), audit + lockout/backoff.
; Uses the RFC 8032 section 7.1 test-1 key as the enrolled user key, a fixed
; session id, and drives the SAME ssh_userauth_packet parser the wire uses.
; The live store/counters are saved and restored around the fixture.
; ---------------------------------------------------------------------------
ssh_auth_selftest:
    push rbx
    push r12
    push r13
    push r14
    mov  byte [rel ssh_selftest_mode], 1
    ; save live state
    lea  rdi, [rel ssh_keys_kat_saved]
    lea  rsi, [rel ssh_keys_record]
    mov  edx, SSHK_REC_SIZE
    call memcpy
    movzx eax, byte [rel ssh_keys_state]
    mov  [rel ssh_keys_kat_saved_state], al
    call principal_current
    mov  r14, rax                          ; the local-session principal must not move
    ; enroll the KAT key in RAM only (caps = everything)
    lea  rdi, [rel ssh_keys_record]
    xor  esi, esi
    mov  edx, SSHK_REC_SIZE
    call memset
    mov  byte [rel ssh_keys_state], SSHK_ST_RAM
    lea  rdi, [rel ssh_keys_record + SSHK_REC_ENTRIES]
    lea  rsi, [rel ssh_transport_kat_host_public]
    mov  edx, 32
    call memcpy
    mov  qword [rel ssh_keys_record + SSHK_REC_ENTRIES + SSHK_ENT_CAPS], SSHK_CAPS_ALL
    mov  dword [rel ssh_keys_record + SSHK_REC_ENTRIES + SSHK_ENT_FLAGS], 1
    mov  dword [rel ssh_keys_record + SSHK_REC_COUNT], 1
    ; signed request payload built once; signature over session id 0x11..
    call ssh_auth_kat_build
    test eax, eax
    jnz  .fail

    ; (1) signed request on a ctx whose session id matches -> bound OWNER.
    call ssh_auth_kat_ctx
    mov  rbx, rax
    mov  rdi, rbx
    lea  rsi, [rel ssh_auth_kat_payload]
    mov  edx, [rel ssh_auth_kat_payload_len]
    call ssh_userauth_packet
    test eax, eax
    jnz  .fail
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_CONNECTION
    jne  .fail
    cmp  qword [rbx + SSH_C_PID], PRIN_OWNER
    jne  .fail
    cmp  dword [rbx + SSH_C_OUTQ_LEN], 36     ; exactly one sealed 1-byte SUCCESS
    jne  .fail
    ; (2) the same signature replayed into another session is refused.
    call ssh_auth_kat_ctx
    mov  rbx, rax
    mov  byte [rbx + SSH_C_SESSION_ID], 0x12
    mov  rdi, rbx
    lea  rsi, [rel ssh_auth_kat_payload]
    mov  edx, [rel ssh_auth_kat_payload_len]
    call ssh_userauth_packet
    test eax, eax
    jnz  .fail
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_USERAUTH
    jne  .fail
    cmp  qword [rbx + SSH_C_PID], 0
    jne  .fail
    ; (3) the unsigned query for the enrolled key earns PK_OK but binds nothing.
    call ssh_auth_kat_ctx
    mov  rbx, rax
    mov  rax, [rel ssh_auth_kat_hassig_ptr]
    mov  byte [rax], 0
    mov  rdi, rbx
    lea  rsi, [rel ssh_auth_kat_payload]
    mov  edx, [rel ssh_auth_kat_query_len]
    call ssh_userauth_packet
    mov  rcx, [rel ssh_auth_kat_hassig_ptr]
    mov  byte [rcx], 1
    test eax, eax
    jnz  .fail
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_USERAUTH
    jne  .fail
    cmp  qword [rbx + SSH_C_PID], 0
    jne  .fail
    cmp  dword [rbx + SSH_C_OUTQ_LEN], 0
    je   .fail
    ; (4) an unenrolled key (store emptied) is refused, signature or not.
    mov  dword [rel ssh_keys_record + SSHK_REC_ENTRIES + SSHK_ENT_FLAGS], 0
    call ssh_auth_kat_ctx
    mov  rbx, rax
    mov  rdi, rbx
    lea  rsi, [rel ssh_auth_kat_payload]
    mov  edx, [rel ssh_auth_kat_payload_len]
    call ssh_userauth_packet
    mov  dword [rel ssh_keys_record + SSHK_REC_ENTRIES + SSHK_ENT_FLAGS], 1
    test eax, eax
    jnz  .fail
    cmp  qword [rbx + SSH_C_PID], 0
    jne  .fail
    ; the local-session principal never moved through any of this
    call principal_current
    cmp  rax, r14
    jne  .fail
    lea  rdi, [rel str_ssh_auth_publickey_marker]
    call serial_string
    lea  rdi, [rel str_ssh_auth_principal_marker]
    call serial_string

    ; (5) audit + lockout: consecutive failures arm a bounded backoff that
    ; refuses even the valid signature; refusals coalesce in the audit ring.
    mov  byte [rel ssh_auth_kat_audit], 1
    mov  qword [rel ssh_auth_streak], 0
    mov  qword [rel ssh_auth_backoff_left], 0
    mov  rax, [rel audit_seq]
    mov  r13, rax
    mov  r12d, SSH_AUTH_LOCK_AFTER
.hammer:
    call ssh_auth_kat_ctx
    mov  rbx, rax
    mov  byte [rbx + SSH_C_SESSION_ID], 0x12
    mov  rdi, rbx
    lea  rsi, [rel ssh_auth_kat_payload]
    mov  edx, [rel ssh_auth_kat_payload_len]
    call ssh_userauth_packet
    dec  r12d
    jnz  .hammer
    ; five identical refusals -> ONE new audit record carrying x5
    mov  rax, [rel audit_seq]
    sub  rax, r13
    cmp  rax, 1
    jne  .fail_audit
    lea  rdi, [rel ssh_audit_line]
    lea  rsi, [rel str_ssh_kat_audit_expect]
    call strcmp
    test eax, eax
    jnz  .fail_audit
    cmp  qword [rel ssh_auth_backoff_left], 0
    je   .fail_audit
    call ssh_auth_kat_ctx
    mov  rbx, rax
    mov  rdi, rbx
    lea  rsi, [rel ssh_auth_kat_payload]
    mov  edx, [rel ssh_auth_kat_payload_len]
    call ssh_userauth_packet
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_USERAUTH
    jne  .fail_audit                          ; lockout must hold the valid key too
    ; backoff over -> the valid key binds again and clears the streak
    mov  qword [rel ssh_auth_backoff_left], 0
    call ssh_auth_kat_ctx
    mov  rbx, rax
    mov  rdi, rbx
    lea  rsi, [rel ssh_auth_kat_payload]
    mov  edx, [rel ssh_auth_kat_payload_len]
    call ssh_userauth_packet
    cmp  byte [rbx + SSH_C_STATE], SSH_STATE_CONNECTION
    jne  .fail_audit
    cmp  qword [rel ssh_auth_streak], 0
    jne  .fail_audit
    lea  rdi, [rel str_ssh_auth_audit_marker]
    call serial_string
    xor  eax, eax
    jmp  .restore
.fail_audit:
.fail:
    lea  rdi, [rel str_ssh_auth_kat_fail]
    call serial_string
    mov  eax, -1
.restore:
    push rax
    mov  byte [rel ssh_auth_kat_audit], 0
    mov  byte [rel ssh_audit_rep_valid], 0
    lea  rdi, [rel ssh_keys_record]
    lea  rsi, [rel ssh_keys_kat_saved]
    mov  edx, SSHK_REC_SIZE
    call memcpy
    movzx eax, byte [rel ssh_keys_kat_saved_state]
    mov  [rel ssh_keys_state], al
    mov  qword [rel ssh_auth_streak], 0
    mov  qword [rel ssh_auth_backoff_left], 0
    mov  qword [rel ssh_auth_backoff_last], 0
    mov  qword [rel ssh_auth_backoff_ms], 0
    mov  qword [rel ssh_auth_ok_count], 0
    mov  qword [rel ssh_auth_fail_count], 0
    mov  qword [rel ssh_auth_lockouts], 0
    mov  qword [rel ssh_auth_last_pid], 0
    call ssh_contexts_base
    mov  rdi, rax
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE
    call memset
    mov  byte [rel ssh_selftest_mode], 0
    pop  rax
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Fresh KAT context in slot 0: USERAUTH state, session id = 32 x 0x11.
ssh_auth_kat_ctx:
    call ssh_contexts_base
    mov  rdi, rax
    xor  esi, esi
    mov  edx, SSH_CTX_SIZE
    call memset
    call ssh_contexts_base
    mov  byte [rax + SSH_C_STATE], SSH_STATE_USERAUTH
    lea  rdi, [rax + SSH_C_SESSION_ID]
    mov  esi, 0x11
    mov  edx, 32
    call memset
    call ssh_contexts_base
    ret

; Build the fixture USERAUTH_REQUEST (user paos, ssh-connection, publickey,
; TRUE, ssh-ed25519, KAT key blob, signature over the session-bound blob).
ssh_auth_kat_build:
    push rbx
    push r12
    lea  rbx, [rel ssh_auth_kat_payload]
    mov  r12, rbx
    mov  byte [rbx], SSH_MSG_USERAUTH_REQUEST
    inc  rbx
    mov  rdi, rbx
    lea  rsi, [rel str_ssh_login_user]
    mov  edx, 4
    call ssh_auth_kat_put_string
    mov  rbx, rax
    mov  rdi, rbx
    lea  rsi, [rel str_ssh_service_connection]
    mov  edx, 14
    call ssh_auth_kat_put_string
    mov  rbx, rax
    mov  rdi, rbx
    lea  rsi, [rel str_ssh_method_publickey]
    mov  edx, 9
    call ssh_auth_kat_put_string
    mov  rbx, rax
    mov  [rel ssh_auth_kat_hassig_ptr], rbx
    mov  byte [rbx], 1
    inc  rbx
    mov  rdi, rbx
    lea  rsi, [rel ssh_alg_host]
    mov  edx, ssh_alg_host.len
    call ssh_auth_kat_put_string
    mov  rbx, rax
    lea  rdi, [rel ssh_transport_kat_host_public]
    call ssh_key_blob_build
    mov  rdi, rbx
    mov  rsi, rax
    mov  edx, SSH_KEY_BLOB_LEN
    call ssh_auth_kat_put_string
    mov  rbx, rax
    mov  rax, rbx
    sub  rax, r12
    mov  [rel ssh_auth_kat_query_len], eax
    ; signed data = string(session id 0x11 x32) || payload prefix
    lea  rdi, [rel ssh_ua_signed]
    mov  esi, 32
    call ssh_be32_store
    lea  rdi, [rel ssh_ua_signed + 4]
    mov  esi, 0x11
    mov  edx, 32
    call memset
    lea  rdi, [rel ssh_ua_signed + 36]
    mov  rsi, r12
    mov  edx, [rel ssh_auth_kat_query_len]
    call memcpy
    lea  rdi, [rel ssh_transport_kat_host_seed]
    mov  esi, 32
    lea  rdx, [rel ssh_ua_signed]
    mov  ecx, [rel ssh_auth_kat_query_len]
    add  ecx, 36
    lea  r8, [rel ssh_auth_kat_sig]
    mov  r9d, 64
    call ed25519_sign
    test eax, eax
    jnz  .bad
    ; string( string "ssh-ed25519" || string sig64 )
    mov  rdi, rbx
    mov  esi, SSH_SIG_BLOB_WIRE_LEN
    call ssh_be32_store
    lea  rdi, [rbx + 4]
    lea  rsi, [rel ssh_user_sig_prefix]
    mov  edx, SSH_SIG_BLOB_WIRE_LEN - 64
    call memcpy
    lea  rdi, [rbx + 4 + SSH_SIG_BLOB_WIRE_LEN - 64]
    lea  rsi, [rel ssh_auth_kat_sig]
    mov  edx, 64
    call memcpy
    add  rbx, 4 + SSH_SIG_BLOB_WIRE_LEN
    mov  rax, rbx
    sub  rax, r12
    mov  [rel ssh_auth_kat_payload_len], eax
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; RDI=dst, RSI=src, EDX=len -> RAX=dst after string(len||bytes)
ssh_auth_kat_put_string:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    mov  esi, edx
    call ssh_be32_store
    lea  rdi, [rbx + 4]
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    lea  rax, [rbx + 4]
    add  rax, r13
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---- data -------------------------------------------------------------------
SSH_AUDIT_LINE_CAP equ 72                        ; == command_audit AUDIT_TXT
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_ssh_auth_0 0
align 8
ssh_txt_cur:          dq 0
ssh_txt_end:          dq 0
ssh_txt_num:          times 24 db 0
ssh_auth_ok_count:    dq 0
ssh_auth_fail_count:  dq 0
ssh_auth_streak:      dq 0
ssh_auth_lockouts:    dq 0
ssh_auth_backoff_ms:  dq 0
ssh_auth_backoff_left: dq 0           ; bounded remaining duration, never a deadline
ssh_auth_backoff_last: dq 0           ; 0 = unknown clock baseline
ssh_auth_last_pid:    dq 0
ssh_exec_count:       dq 0
ssh_exec_refused:     dq 0
ssh_keys_nvram_writes: dq 0
ssh_audit_rep_seq:    dq 0
ssh_audit_rep_count:  dq 0
ssh_ua_user:          dq 0
ssh_ua_service:       dq 0
ssh_ua_alg:           dq 0
ssh_ua_blob:          dq 0
ssh_ua_key_caps:      dq 0
ssh_keyverb_caps:     dq 0
ssh_keys_var_size:    dq SSHK_REC_SIZE
ssh_auth_kat_hassig_ptr: dq 0
ssh_ua_user_len:      dd 0
ssh_ua_service_len:   dd 0
ssh_ua_alg_len:       dd 0
ssh_ua_key_slot:      dd 0
ssh_keys_var_attrs:   dd 0
ssh_auth_kat_payload_len: dd 0
ssh_auth_kat_query_len: dd 0
ssh_ua_has_sig:       db 0
ssh_audit_rep_valid:  db 0
ssh_auth_kat_audit:   db 0
ssh_keys_state:       db SSHK_ST_UNAVAILABLE
ssh_keys_kat_saved_state: db 0
ssh_onebyte_reply:    db 0
align 8
ssh_ua_proof:         times AUTH_ED25519_PROOF_SIZE db 0
ssh_ua_auth_ctx:      times AUTH_CTX_SIZE db 0
ssh_ua_signed:        times SSH_UA_SIGNED_CAP db 0
ssh_ua_reply:         times 96 db 0
ssh_key_blob_scratch: times 64 db 0
ssh_key_digest:       times 32 db 0
ssh_keyverb_blob:     times 72 db 0
ssh_keyverb_fp:       times 48 db 0
ssh_audit_line:       times SSH_AUDIT_LINE_CAP db 0
ssh_audit_exec_res:   dd 0
ssh_audit_rep_key:    times SSH_AUDIT_LINE_CAP db 0
ssh_auth_kat_payload: times 320 db 0
ssh_auth_kat_sig:     times 64 db 0
align 8
ssh_keys_record:      times SSHK_REC_SIZE db 0
ssh_keys_stage:       times SSHK_REC_SIZE db 0
ssh_keys_verify:      times SSHK_REC_SIZE db 0
ssh_keys_kat_saved:   times SSHK_REC_SIZE db 0

; 7268a9b4-3f8a-45a0-9f8d-1b73e9ac2142 (PaOSPrincipalCred family, Task2142)
ssh_keys_var_guid:
    dd 0x7268a9b4
    dw 0x3f8a,0x45a0
    db 0x9f,0x8d,0x1b,0x73,0xe9,0xac,0x21,0x42
ssh_keys_var_name:
    dw 'P','a','O','S','S','s','h','K','e','y','s',0
%endmacro
WDATA_DEFER WDATA_svc_ssh_auth_0

; Fixed 16-byte stride name tables (no link-time pointer tables: this image
; is relocated at load, so only RIP-relative LEAs are valid addresses).
%macro SSH_NAME16 1
    %%s: db %1, 0
    times 16 - ($ - %%s) db 0
%endmacro
ssh_keys_state_names:
    SSH_NAME16 "unavailable"
    SSH_NAME16 "ram"
    SSH_NAME16 "nvram"
    SSH_NAME16 "poisoned"
ssh_auth_reason_names:
    SSH_NAME16 "ok"
    SSH_NAME16 "unenrolled"
    SSH_NAME16 "bad_signature"
    SSH_NAME16 "user"
    SSH_NAME16 "service"
    SSH_NAME16 "method"
    SSH_NAME16 "algorithm"
    SSH_NAME16 "lockout"
ssh_source_names:
    SSH_NAME16 "internal"
    SSH_NAME16 "udp"
    SSH_NAME16 "serial"
    SSH_NAME16 "aihook"
    SSH_NAME16 "console"
    SSH_NAME16 "ssh"
    SSH_NAME16 "other"

; string "ssh-ed25519" || uint32 32  (user key blob prefix)
ssh_user_key_prefix:
    dd 0x0b000000
    db "ssh-ed25519"
    dd 0x20000000
; string "ssh-ed25519" || uint32 64  (signature blob prefix)
ssh_user_sig_prefix:
    dd 0x0b000000
    db "ssh-ed25519"
    dd 0x40000000

str_ssh_method_none:        db "none"
str_ssh_method_publickey:   db "publickey"
str_ssh_login_user:         db "paos",0
str_ssh_service_connection: db "ssh-connection"
str_ssh_audit_ok:        db "SSH auth=ok pid=",0
str_ssh_audit_refused:   db "SSH auth=refused reason=",0
str_ssh_audit_fp:        db " fp=SHA256:",0
str_ssh_audit_nofp:      db "-",0
str_ssh_audit_repeat:    db " x",0
str_ssh_audit_exec:      db "SSH exec pid=",0
str_ssh_audit_userauth:  db "userauth",0
str_ssh_audit_rc:        db " rc=",0
str_ssh_audit_argb:      db " argb=",0
str_ssh_audit_verb:      db " ",0
str_ssh_kat_audit_expect: db "SSH auth=refused reason=bad_signature fp=SHA256:bbXpuKG6zhzdmnxq x5",0
str_sshkey_pending_owner: db "Available after PaOS next starts",0
str_sshkeyadd_ok:        db "SSHKEYADD ok slot=",0
str_sshkeyadd_exists:    db "SSHKEYADD exists slot=",0
str_sshkey_fp:           db " fingerprint=SHA256:",0
str_sshkey_caps:         db " caps=",0
str_sshkey_keys:         db " keys=",0
str_sshkey_store:        db " store=",0
str_sshkeyadd_need_auth1: db "ERR SSHKEYADD refused=owner_signed_auth1_required hint='AUTH1-sign SSHKEYADD; SSH sessions cannot enroll keys'",0
str_sshkeyadd_grammar:   db "ERR SSHKEYADD expected='[ssh-ed25519] <base64-ed25519-key-blob> [caps=<16hex>]'",0
str_sshkeyadd_full:      db "ERR SSHKEYADD full max=4 hint=SSHKEYDEL",0
str_sshkeyadd_persist:   db "ERR SSH key store commit unverified; inspect store state",0
str_sshkeydel_ok:        db "SSHKEYDEL ok slot=",0
str_sshkeydel_need_auth1: db "ERR SSHKEYDEL refused=owner_signed_auth1_required",0
str_sshkeydel_grammar:   db "ERR SSHKEYDEL expected='<slot 0..3>'",0
str_sshkeydel_empty:     db "ERR SSHKEYDEL slot_empty hint=SSHKEYLIST",0
str_sshkhtrust_ok: db "SSHKHTRUST ok trusted=boot_only durable=not_yet_authenticated (saved only after successful peer authentication; refusal to save remains explicit)",0
str_sshkhtrust_same: db "SSHKHTRUST ok pin=already_exact persistence=unchanged (no write issued)",0
str_sshkhtrust_owner: db "ERR SSHKHTRUST owner_signed_auth1_required",0
str_sshkhtrust_usage: db "ERR SSHKHTRUST usage=<IPv4>:<port> <64lowerhexSHA256>",0
str_sshkhtrust_unavailable: db "ERR SSHKHTRUST trust_unavailable (no pin changed; owner must repair damaged or uncertain store)",0
str_sshkhtrust_full: db "ERR SSHKHTRUST table_full (no pin evicted)",0
str_sshkhtrust_conflict: db "ERR SSHKHTRUST conflict (existing pin retained; deliberate owner SSHKHCLEAR forgets ALL pins and requires reenrollment)",0
str_sshkhclear_ok:       db "SSHKHCLEAR ok known_hosts=cleared (all server pins removed; client identity retained; independently verify each server fingerprint and reprovision with SSHKHTRUST before reconnecting)",0
str_sshkhclear_need_auth1: db "ERR SSHKHCLEAR refused=owner_signed_auth1_required",0
str_sshkhclear_failed:   db "ERR SSHKHCLEAR no_mutation_issued (trust unchanged)",0
str_sshkhclear_uncertain: db "ERR SSHKHCLEAR commit_uncertain (new host trust refused; owner may clear again)",0
str_sshkeylist_hdr:      db "SSHKEYLIST keys=",0
str_sshkeylist_k:        db " k",0
str_sshkeylist_eq:       db "=SHA256:",0
str_sshrecord_prefix: db "SSHRECORD=1 nonce=",0
str_sshrecord_refused: db "ERR SSHRECORD owner_or_args",0
str_sshrecord_event: db " event=",0
str_sshrecord_ready: db " ready=",0
str_sshrecord_connection: db " connection=",0
str_sshrecord_previous_bytes: db " previous_bytes=",0
str_sshrecord_previous_ordinal: db " previous_ordinal=",0
str_sshrecord_rejected_bytes: db " rejected_bytes=",0
str_sshrecord_rejected_ordinal: db " rejected_ordinal=",0
str_sshrecord_state: db " state=",0
str_sshrecord_principal: db " principal=",0
str_sshrecord_bound: db " bound=",0
str_sshrecord_exec: db " exec=",0
str_sshrecord_auth_ok: db " auth_ok=",0
str_sshrecord_nvram_writes: db " nvram_writes=",0
str_sshrecord_local_ip: db " local_ip=",0
str_sshrecord_remote_ip: db " remote_ip=",0
str_sshrecord_local_port: db " local_port=",0
str_sshrecord_remote_port: db " remote_port=",0
str_sshrecord_previous: db " previous=",0
str_sshrecord_rejected: db " rejected=",0
str_sshstat_source:      db "SSHSTAT source=",0
str_sshstat_principal:   db " principal=",0
str_sshstat_ok:          db " auth_ok=",0
str_sshstat_fail:        db " auth_fail=",0
str_sshstat_streak:      db " streak=",0
str_sshstat_lockouts:    db " lockouts=",0
str_sshstat_lockout_ms:  db " lockout_ms=",0
str_sshstat_exec:        db " exec=",0
str_sshstat_exec_refused: db " exec_refused=",0
str_sshstat_nvram_writes: db " key_nvram_writes=",0
str_ssh_auth_publickey_marker: db "[PAOS64] SSH rung 2: ssh-ed25519 publickey verify against the enrolled-key store selftest [ssh.auth.publickey]",13,10,0
str_ssh_auth_principal_marker: db "[PAOS64] SSH rung 2: authenticated connection bound to a PaOS principal (owner v1) [ssh.auth.principal]",13,10,0
str_ssh_auth_audit_marker: db "[PAOS64] SSH rung 2: auth attempts logged to the audit ring + lockout/backoff selftest [ssh.auth.audit]",13,10,0
str_ssh_auth_kat_fail:   db "[PAOS64] SSH rung 2: userauth selftest FAIL [ssh.auth.fail]",13,10,0
str_ssh_nvg_tag: db "ssh_keystore", 0

; AUTHPWKEY <32 lowercase hex nonce> <SSHKEYADD public argument>
; The signed carrier only permits this observation. The inner *actual*
; SSHKEYADD handler receives the genuine password-bound local OWNER principal
; with no remote signature ticket. It cannot borrow the carrier's authority.
; No password, DATA handle, private key or verifier is rendered. BSP command
; dispatch is serialized; this frame has no scheduler/network/yield call.
; Signed-service, boot fixture and PUSH sessions are explicitly unavailable.
cmd_verb_authpwkey:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    call ssh_keyverb_out_begin
    mov  rdi, r12
    call ssh_keyverb_owner_signed
    test eax, eax
    jz   .unavailable
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .unavailable
    cmp  qword [rel session_bound_pid], PRIN_OWNER
    jne  .unavailable
    cmp  byte [rel session_unlock_method], SESSION_METHOD_AUTHLOGIN
    je   .password
    cmp  byte [rel session_unlock_method], SESSION_METHOD_LOCAL
    jne  .unavailable
.password:
    cmp  byte [rel prin_boot_fixture_active], 0
    jne  .unavailable
    mov  edi, PRIN_OWNER
    call principal_credential
    test rax, rax
    jz   .unavailable
    cmp  edx, PRIN_CREDENTIAL_LEN
    jne  .unavailable
    cmp  rax, [rel session_key_handle]
    jne  .unavailable
    mov  rbx, [r12 + REQ_ARG]
    test rbx, rbx
    jz   .unavailable
    xor  ecx, ecx
.nonce:
    movzx eax, byte [rbx + rcx]
    cmp  al, '0'
    jb   .unavailable
    cmp  al, '9'
    jbe  .digit
    cmp  al, 'a'
    jb   .unavailable
    cmp  al, 'f'
    ja   .unavailable
.digit:
    inc  ecx
    cmp  ecx, 32
    jb   .nonce
    cmp  byte [rbx + 32], ' '
    jne  .unavailable
    ; Fixed public fixture only: 68 base64 bytes + zero capability mask.
    ; Stop at any NUL rather than reading through a short argument.
    xor  ecx, ecx
.public:
    movzx eax, byte [rbx + rcx + 33]
    cmp  al, '+'
    je   .public_ok
    cmp  al, '/'
    je   .public_ok
    cmp  al, '0'
    jb   .unavailable
    cmp  al, '9'
    jbe  .public_ok
    cmp  al, 'A'
    jb   .unavailable
    cmp  al, 'Z'
    jbe  .public_ok
    cmp  al, 'a'
    jb   .unavailable
    cmp  al, 'z'
    ja   .unavailable
.public_ok:
    inc  ecx
    cmp  ecx, 68
    jb   .public
    xor  ecx, ecx
    lea  rdx, [rel ssh_pwkey_zero_caps]
.mask:
    mov  al, [rdx + rcx]
    cmp  al, [rbx + rcx + 101]
    jne  .unavailable
    inc  ecx
    test al, al
    jnz  .mask
    lea  rdi, [rel ssh_pwkey_argument]
    lea  rsi, [rbx + 33]
    mov  edx, 90
    call sha256_hash
    test eax, eax
    jnz  .unavailable
    ; Full protected record snapshots, not just public row count. This also
    ; detects an incorrectly admitted add even if the handler reports refusal.
    lea  rdi, [rel ssh_pwkey_before]
    lea  rsi, [rel ssh_keys_record]
    mov  edx, SSHK_REC_SIZE
    call sha256_hash
    test eax, eax
    jnz  .unavailable
    mov  r14, [rel command_auth_remote_ticket]
    movzx r15d, byte [rel command_auth_remote_active]
    ; Keep authenticated principal=OWNER; remove ONLY signed-key authority.
    ; Keep remote_active so subordinate code cannot gain local/internal bypass.
    mov  qword [rel command_auth_remote_ticket], 0
    lea  rax, [rbx + 33]
    mov  [r12 + REQ_ARG], rax
    mov  rdi, r12
    mov  rsi, r13
    call cmd_verb_sshkeyadd
    mov  [r12 + REQ_ARG], rbx
    mov  [rel command_auth_remote_ticket], r14
    mov  [rel command_auth_remote_active], r15b
    mov  r14, [r13 + RSP_ACCEPTED]
    ; Earn the refusal reason from the actual handler buffer, not from the
    ; expected path or an arbitrary parser/store error that also returns 0.
    lea  rdi, [rel ssh_cmd_out_buf]
    lea  rsi, [rel str_sshkeyadd_need_auth1]
    xor  ecx, ecx
.reason:
    mov  al, [rsi + rcx]
    cmp  al, [rdi + rcx]
    jne  .other_reason
    inc  ecx
    test al, al
    jnz  .reason
    mov  byte [rel ssh_pwkey_denied], 1
    jmp  .reason_done
.other_reason:
    mov  byte [rel ssh_pwkey_denied], 0
.reason_done:
    lea  rdi, [rel ssh_pwkey_after]
    lea  rsi, [rel ssh_keys_record]
    mov  edx, SSHK_REC_SIZE
    call sha256_hash
    test eax, eax
    jnz  .unavailable
    call ssh_keyverb_out_begin
    lea  rdi, [rel ssh_pwkey_result]
    call ssh_txt_put_str
    ; exact caller challenge, no NUL write into the request buffer
    mov  rdi, rbx
    mov  esi, 32
    call ssh_txt_put_bytes
    lea  rdi, [rel ssh_pwkey_argument_text]
    call ssh_txt_put_str
    lea  rdi, [rel ssh_pwkey_argument]
    call ssh_pwkey_digest
    lea  rdi, [rel ssh_pwkey_accepted]
    call ssh_txt_put_str
    mov  rdi, r14
    call ssh_txt_put_dec
    lea  rdi, [rel ssh_pwkey_denied_text]
    call ssh_txt_put_str
    movzx edi, byte [rel ssh_pwkey_denied]
    call ssh_txt_put_dec
    lea  rdi, [rel ssh_pwkey_before_text]
    call ssh_txt_put_str
    lea  rdi, [rel ssh_pwkey_before]
    call ssh_pwkey_digest
    lea  rdi, [rel ssh_pwkey_after_text]
    call ssh_txt_put_str
    lea  rdi, [rel ssh_pwkey_after]
    call ssh_pwkey_digest
    mov  rdi, r13
    call ssh_keyverb_finish_ok
    jmp  .out
.unavailable:
    call ssh_keyverb_out_begin
    lea  rdi, [rel ssh_pwkey_unavailable]
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_err
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=public record digest. Hex, with no private credential material.
ssh_pwkey_digest:
    push rbx
    push r12
    mov  rbx, rdi
    xor  r12d, r12d
.loop:
    movzx edi, byte [rbx + r12]
    lea  rsi, [rel ssh_txt_num]
    mov  edx, 2
    call fmt_hex
    lea  rdi, [rel ssh_txt_num]
    mov  esi, 2
    call ssh_txt_put_bytes
    inc  r12d
    cmp  r12d, 32
    jb   .loop
    pop  r12
    pop  rbx
    ret

ssh_pwkey_result: db "AUTHPWKEY OBSERVED method=password pid=1 operation=SSHKEYADD nonce=",0
ssh_pwkey_accepted: db " accepted=",0
ssh_pwkey_before_text: db " before=",0
ssh_pwkey_after_text: db " after=",0
ssh_pwkey_unavailable: db "AUTHPWKEY UNOBSERVED password_session_unavailable",0
align 8
ssh_pwkey_before: times 32 db 0
ssh_pwkey_after: times 32 db 0

ssh_pwkey_denied_text: db " owner_key_required=",0
ssh_pwkey_denied: db 0

ssh_pwkey_zero_caps: db " caps=0000000000000000",0
ssh_pwkey_argument_text: db " argument_sha256=",0
align 8
ssh_pwkey_argument: times 32 db 0
