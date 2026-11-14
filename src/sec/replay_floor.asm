;; MODULE sec/replay_floor
;; LAYER 5
;; EXPORTS replay_floor_preebs, replay_floor_stage_reseed, rpf_state, rpf_err, rpf_flags, rpf_b, rpf_f, rpf_seal, rpf_tsc, rpf_epoch
;; IMPORTS boot/header, boot/serial, boot/nvram_access, boot/boot_v2_handoff, core/lib/hmac_sha256, sec/principal, sec/system_secret, sec/owner_store, svc/command_auth
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only
; ============================================================================
; sec/replay_floor.asm — SEC-replay-record-mac S1: the signed-request replay
; floor in a boot-services-only variable (design 0c8bed8c §3/§9, root ACCEPT
; 00:22:33, rc-boot placement 00:58:34, root 01:01:52).
;
; PaOSCommandAuthReplay (NV|BS|RT) is writable by any runtime OS, so deleting,
; lowering or rolling it back reopened captured owner-signed envelopes.
; PaOSReplayFloor is NV|BS (0x3): after ExitBootServices the firmware hides it
; and refuses runtime writes, so only pre-EBS code can change it.
;
; replay_floor_preebs (boot/header, AFTER owner_store_preebs, BEFORE EBS):
;   1. reads F (exactly ours: attrs NV|BS, 64 B, magic, version, size, CRC;
;      anything else under the name is DELETED and treated as absent), the RT
;      replay record R_rt and the principal record's PASSWORD floor pw_rt;
;   2. B = max(F, R_rt, pw_rt). With F valid the two RT inputs are clamped to
;      F + 2^32 (§9.2): a runtime OS that writes 2^64-1 there would otherwise
;      saturate the NV|BS floor for good;
;   3. F absent on an estate whose owner record says replay_floor_seeded
;      (ows_floor_seeded, §9.4), or whose owner store is CORRUPT/FAILED, or
;      with a seed input above RPF_SEED_CEIL = 2^48 (§9.8), is a LOSS: F is rewritten in state LOST with
;      value B and a TSC epoch, and every boot reports LOST until an owner
;      reseed (§9.5). Absent on an unseeded estate: first use / migration;
;   4. otherwise writes F' = min(2^64-1, B + 2^24) state HELD, byte-exact
;      read-back, then mirrors F' into the RT record (pre-EBS, §9.1) so older
;      A/B images see the higher floor, also read back;
;   5. reports one marker line with the step's TSC delta (rc-boot (e)).
;   A LOST floor stays LOST until the console OWNER stages AUTHFLOOR RESEED
;   (replay_floor_stage_reseed): PaOSReplayFloorReseed (NV|BS|RT) binds the
;   loss epoch, the owner generation and the LOST value under HMAC-SHA256 keyed
;   by HKDF(Y, "PaOS/replay/reseed/v1"). The next pre-EBS step honours exactly
;   that stage and deletes any stage it reads (§9.5).
; command_auth_replay_load then takes H = B and, when HELD, R = F' sealed:
; no runtime SetVariable on the signed path. rpf_seal = F' bounds command and
; PASSWORD sequences for the whole boot whenever F' was committed (§9.3).
;
; Residual (§6): pre-EBS code (a UEFI shell, a db-trusted loader, an NVRAM
; clear, SPI) can still rewrite F lower; deleting it on a seeded estate is
; detected. Same class as PaOSSystemSecret and the owner store. Rollback
; (srcreview R1): an older pre-floor image checks only the RT record and
; ignores a LOST F; there is no boot-side minimum-version gate (design §9.9a).
; ============================================================================

RPF_NONE          equ 0                 ; not run: no runtime services
RPF_HELD          equ 1                 ; F' and the RT mirror committed and read back
RPF_MIRROR_FAILED equ 2                 ; F' committed; the RT mirror did not verify
RPF_FAILED        equ 3                 ; F' not committed: signed remote refused this boot
RPF_LOST          equ 4                 ; seeded estate without its floor: refused until reseed

RPF_E_NONE        equ 0
RPF_E_READ        equ 1                 ; F's GetVariable failed (not NOT_FOUND)
RPF_E_DELETE      equ 2                 ; a foreign variable under F's name would not delete
RPF_E_GATE        equ 3                 ; storage gate refused F
RPF_E_SET         equ 4                 ; SetVariable(F) failed
RPF_E_GET         equ 5                 ; read-back GetVariable(F) failed
RPF_E_COMPARE     equ 6                 ; read-back attrs/size/bytes differ
RPF_E_LOST        equ 7                 ; seeded estate, F absent or LOST
RPF_E_SATURATED   equ 8                 ; B is already 2^64-1: no window left
RPF_E_SEED_CEIL   equ 9                 ; LOST because a seed input was above RPF_SEED_CEIL

RPF_FL_RT_CLAMPED equ 1                 ; R_rt above F + 2^32 was clamped
RPF_FL_PW_CLAMPED equ 2                 ; pw_rt above F + 2^32 was clamped
RPF_FL_REPLACED   equ 4                 ; a foreign variable under F's name was deleted
RPF_FL_SEEDED     equ 8                 ; F was absent: first use / migration this boot
RPF_FL_RT_INVALID equ 16                ; an RT record was present but not valid (ignored)
RPF_FL_OVER_CEIL  equ 32                ; F absent and a seed input was above RPF_SEED_CEIL
RPF_FL_RESEEDED   equ 64                ; a LOST floor was reseeded by a valid owner stage

RPF_ATTRS         equ 0x00000003        ; NV | BOOTSERVICE_ACCESS, never RUNTIME_ACCESS
RPF_MAGIC         equ 0x31465250        ; "PRF1"
RPF_VERSION       equ 1
RPF_SIZE          equ 64
RPF_OFF_MAGIC     equ 0
RPF_OFF_VERSION   equ 4
RPF_OFF_SIZE      equ 6
RPF_OFF_STATE     equ 8                 ; u8 RPF_REC_HELD / RPF_REC_LOST, 9..15 zero
RPF_OFF_FLOOR     equ 16                ; u64 F
RPF_OFF_BOOTS     equ 24                ; u64 boots that committed F (diagnostic)
RPF_OFF_EPOCH     equ 32                ; u64 TSC at the loss (0 while HELD)
RPF_OFF_CRC       equ 60                ; CRC32 (pbm_crc32) over [0, 60); 40..59 zero
RPF_REC_HELD      equ 1
RPF_REC_LOST      equ 2
RPF_WINDOW        equ 0x1000000         ; 2^24 sequences per boot
RPF_CLAMP         equ 0x100000000       ; 2^32: the most one boot may raise B from RT inputs
RPF_SEED_CEIL     equ 0x1000000000000   ; 2^48: the highest seed input without an F (16.7 M boots of 2^24)
RPF_EFI_NOT_FOUND        equ 0x800000000000000E
RPF_EFI_BUFFER_TOO_SMALL equ 0x8000000000000005
RPF_RT_GETVAR     equ 0x48
RPF_PRIN_MAX      equ 208               ; PRIN_RECORD_SIZE (v2/v3); v1 is 128
RPF_STG_ATTRS     equ 0x00000007        ; NV | BS | RT: the runtime can only write RT variables
RPF_STG_MAGIC     equ 0x31525250        ; "PRR1"
RPF_STG_SIZE      equ 64
RPF_STG_OFF_EPOCH equ 8                 ; u64 the LOST record's epoch
RPF_STG_OFF_GEN   equ 16                ; u64 the owner generation (ows_generation)
RPF_STG_OFF_FLOOR equ 24                ; u64 the LOST value it reseeds from
RPF_STG_OFF_MAC   equ 32                ; HMAC-SHA256(HKDF(Y, info), [0, 32))

; replay_floor_preebs — PRE-EBS only. No return value: the outcome is rpf_state
;   / rpf_err / rpf_flags / rpf_b / rpf_f / rpf_seal. Preserves the callee-saved
;   registers.
replay_floor_preebs:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and  rsp, -16
    sub  rsp, 48
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel rpf_tsc], rax
    mov  byte [rel rpf_state], RPF_NONE
    mov  byte [rel rpf_err], RPF_E_NONE
    mov  byte [rel rpf_key_ready], 0
    mov  qword [rel rpf_epoch], 0
    mov  byte [rel rpf_flags], 0
    mov  qword [rel rpf_b], 0
    mov  qword [rel rpf_f], 0
    mov  qword [rel rpf_seal], -1        ; no floor committed: no extra bound
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .report
    call rpf_read_rt                     ; RAX = R_rt (0 when absent/invalid)
    mov  r14, rax
    call rpf_read_password               ; RAX = pw_rt (0 when absent/invalid)
    mov  r15, rax
    ; ---- F ----
    xor  r13d, r13d                      ; r13 = F, valid only when ebx = 1
    xor  ebx, ebx
    mov  qword [rel rpf_io_size], RPF_SIZE
    mov  dword [rel rpf_io_attrs], 0
    lea  rcx, [rel rpf_name]
    lea  rdx, [rel command_auth_replay_guid]
    lea  r8, [rel rpf_io_attrs]
    lea  r9, [rel rpf_io_size]
    lea  rax, [rel rpf_blob]
    mov  [rsp + 32], rax
    call [r12 + RPF_RT_GETVAR]
    test rax, rax
    jz   .f_found
    mov  rdx, RPF_EFI_NOT_FOUND
    cmp  rax, rdx
    je   .f_absent
    mov  rdx, RPF_EFI_BUFFER_TOO_SMALL
    cmp  rax, rdx
    je   .f_replace                     ; oversized: not ours
    mov  byte [rel rpf_err], RPF_E_READ
    jmp  .failed                        ; a device error decides nothing
.f_found:
    cmp  dword [rel rpf_io_attrs], RPF_ATTRS
    jne  .f_replace                     ; RT-visible (or otherwise foreign): never trusted
    cmp  qword [rel rpf_io_size], RPF_SIZE
    jne  .f_replace
    lea  rdi, [rel rpf_blob]
    call rpf_blob_valid
    test eax, eax
    jz   .f_replace
    mov  r13, [rel rpf_blob + RPF_OFF_FLOOR]
    mov  ebx, 1
    ; clamp both RT inputs to F + 2^32 (saturating)
    mov  rax, r13
    mov  rdx, RPF_CLAMP
    add  rax, rdx
    jnc  .cap_ok
    mov  rax, -1
.cap_ok:
    cmp  r14, rax
    jbe  .rt_ok
    mov  r14, rax
    or   byte [rel rpf_flags], RPF_FL_RT_CLAMPED
.rt_ok:
    cmp  r15, rax
    jbe  .pw_ok
    mov  r15, rax
    or   byte [rel rpf_flags], RPF_FL_PW_CLAMPED
.pw_ok:
    jmp  .compute
.f_replace:
    or   byte [rel rpf_flags], RPF_FL_REPLACED
    call rpf_delete
    test eax, eax
    jz   .f_absent
    mov  byte [rel rpf_err], RPF_E_DELETE
    jmp  .failed
.f_absent:
    or   byte [rel rpf_flags], RPF_FL_SEEDED
    ; Without F there is nothing to clamp to (root 01:13:39 (A)). A seed input
    ; above RPF_SEED_CEIL is tampering, not history: it is dropped, never
    ; folded, and the estate raises the loss alarm instead of seeding F near
    ; 2^64-1 (a signed-remote DoS only a reseed would undo).
    mov  rax, RPF_SEED_CEIL
    cmp  r14, rax
    jbe  .seed_rt_ok
    xor  r14d, r14d
    or   byte [rel rpf_flags], RPF_FL_OVER_CEIL
.seed_rt_ok:
    cmp  r15, rax
    jbe  .compute
    xor  r15d, r15d
    or   byte [rel rpf_flags], RPF_FL_OVER_CEIL
.compute:
    ; B = max(F, R_rt', pw_rt')
    mov  rax, r13
    cmp  r14, rax
    jbe  .b1
    mov  rax, r14
.b1:
    cmp  r15, rax
    jbe  .b2
    mov  rax, r15
.b2:
    mov  [rel rpf_b], rax
    test ebx, ebx
    jz   .absent_policy
    cmp  byte [rel rpf_blob + RPF_OFF_STATE], RPF_REC_LOST
    jne  .commit
    ; a LOST floor stays LOST until an owner reseed of exactly this loss (§9.5)
    mov  [rel rpf_f], r13
    mov  rax, [rel rpf_blob + RPF_OFF_EPOCH]
    mov  [rel rpf_epoch], rax
    call rpf_reseed_check                ; EAX 1: a valid stage (read stages are deleted either way)
    test eax, eax
    jz   .lost
    or   byte [rel rpf_flags], RPF_FL_RESEEDED
    jmp  .commit
.absent_policy:
    ; seeded estate without its floor: record the loss, never re-seed silently.
    ; A corrupt or failed owner store is never mapped to "unseeded" either, and
    ; a seed input above the ceiling is never seeded.
    test byte [rel rpf_flags], RPF_FL_OVER_CEIL
    jnz  .loss
    cmp  byte [rel ows_floor_seeded], 1
    je   .loss
    cmp  byte [rel ows_state], OWS_CORRUPT
    je   .loss
    cmp  byte [rel ows_state], OWS_FAILED
    jne  .commit
.loss:
    and  byte [rel rpf_flags], ~RPF_FL_SEEDED
    mov  rax, [rel rpf_b]
    mov  [rel rpf_f], rax
    mov  rcx, [rel rpf_tsc]              ; the loss epoch: this boot's start TSC
    mov  [rel rpf_epoch], rcx
    mov  edi, RPF_REC_LOST
    mov  rsi, rax
    xor  edx, edx                        ; a new LOST record restarts the boot count
    call rpf_build
    call rpf_write_verify                ; best effort: this boot is refused either way
.lost:
    ; the console OWNER may stage a reseed this boot: derive its key while Y is
    ; still the BS-only copy (pre-EBS); no Y this boot -> AUTHFLOOR refuses
    lea  rdi, [rel rpf_reseed_info]
    mov  esi, rpf_reseed_info.len
    lea  rdx, [rel rpf_reseed_key]
    call system_secret_hkdf
    mov  [rel rpf_key_ready], al
    mov  byte [rel rpf_state], RPF_LOST
    mov  byte [rel rpf_err], RPF_E_LOST
    test byte [rel rpf_flags], RPF_FL_OVER_CEIL
    jz   .report
    mov  byte [rel rpf_err], RPF_E_SEED_CEIL
    jmp  .report
.commit:
    mov  rsi, [rel rpf_b]
    cmp  rsi, -1
    jne  .window
    mov  byte [rel rpf_err], RPF_E_SATURATED
    jmp  .failed
.window:
    mov  rax, RPF_WINDOW
    add  rsi, rax
    jnc  .fprime
    mov  rsi, -1
.fprime:
    mov  [rel rpf_f], rsi
    xor  edx, edx
    test ebx, ebx
    jz   .boots
    mov  rdx, [rel rpf_blob + RPF_OFF_BOOTS]
.boots:
    add  rdx, 1
    sbb  rdx, 0                          ; saturating count
    mov  edi, RPF_REC_HELD
    xor  ecx, ecx
    call rpf_build
    call rpf_write_verify
    test eax, eax
    jnz  .failed                         ; rpf_err holds the step
    mov  rax, [rel rpf_f]
    mov  [rel rpf_seal], rax
    ; ---- RT mirror: never lower it (an RT record above F' stays as it is) ----
    mov  byte [rel rpf_state], RPF_HELD
    cmp  [rel rpf_rt_raw], rax
    jae  .report
    mov  rdi, rax
    call rpf_mirror
    test eax, eax
    jz   .report
    mov  byte [rel rpf_state], RPF_MIRROR_FAILED
    jmp  .report
.failed:
    mov  byte [rel rpf_state], RPF_FAILED
    mov  qword [rel rpf_seal], -1
.report:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel rpf_tsc]
    mov  [rel rpf_tsc], rax
    lea  rdi, [rel str_rpf_state]
    call serial_string
    movzx edi, byte [rel rpf_state]
    call serial_hex64
    lea  rdi, [rel str_rpf_err]
    call serial_string
    movzx edi, byte [rel rpf_err]
    call serial_hex64
    lea  rdi, [rel str_rpf_b]
    call serial_string
    mov  rdi, [rel rpf_b]
    call serial_hex64
    lea  rdi, [rel str_rpf_f]
    call serial_string
    mov  rdi, [rel rpf_f]
    call serial_hex64
    lea  rdi, [rel str_rpf_flags]
    call serial_string
    movzx edi, byte [rel rpf_flags]
    call serial_hex64
    lea  rdi, [rel str_rpf_tsc]
    call serial_string
    mov  rdi, [rel rpf_tsc]
    call serial_hex64
    lea  rdi, [rel str_rpf_marker]
    call serial_string
    lea  rsp, [rbp - 40]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; rpf_build(EDI = record state, RSI = floor, RDX = boots, RCX = epoch) — fills
;   rpf_blob with an exact record and its CRC.
rpf_build:
    push rbx
    push rdi
    push rsi
    push rdx
    push rcx
    cld
    lea  rdi, [rel rpf_blob]
    xor  eax, eax
    mov  ecx, RPF_SIZE
    rep  stosb
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rax
    mov  dword [rel rpf_blob + RPF_OFF_MAGIC], RPF_MAGIC
    mov  word [rel rpf_blob + RPF_OFF_VERSION], RPF_VERSION
    mov  word [rel rpf_blob + RPF_OFF_SIZE], RPF_SIZE
    mov  [rel rpf_blob + RPF_OFF_STATE], al
    mov  [rel rpf_blob + RPF_OFF_FLOOR], rsi
    mov  [rel rpf_blob + RPF_OFF_BOOTS], rdx
    mov  [rel rpf_blob + RPF_OFF_EPOCH], rcx
    lea  rdi, [rel rpf_blob]
    mov  esi, RPF_OFF_CRC
    call pbm_crc32
    mov  [rel rpf_blob + RPF_OFF_CRC], eax
    pop  rbx
    ret

; rpf_blob_valid(RDI = 64-byte copy) -> EAX 1 when magic, version, size, a
;   known state, zero padding and the CRC are exactly ours.
rpf_blob_valid:
    push rbx
    mov  rbx, rdi
    xor  eax, eax
    cmp  dword [rbx + RPF_OFF_MAGIC], RPF_MAGIC
    jne  .out
    cmp  word [rbx + RPF_OFF_VERSION], RPF_VERSION
    jne  .out
    cmp  word [rbx + RPF_OFF_SIZE], RPF_SIZE
    jne  .out
    movzx ecx, byte [rbx + RPF_OFF_STATE]
    cmp  ecx, RPF_REC_HELD
    je   .state_ok
    cmp  ecx, RPF_REC_LOST
    jne  .out
.state_ok:
    mov  rcx, [rbx + RPF_OFF_STATE]
    shr  rcx, 8                         ; bytes 9..15
    or   rcx, [rbx + 40]
    or   rcx, [rbx + 48]
    mov  edx, [rbx + 56]                ; 56..59 (a 32-bit OR would drop rcx's high half)
    or   rcx, rdx
    test rcx, rcx
    jnz  .out
    mov  esi, RPF_OFF_CRC
    call pbm_crc32
    cmp  eax, [rbx + RPF_OFF_CRC]
    sete al
    movzx eax, al
.out:
    pop  rbx
    ret

; rpf_write_verify -> EAX 0 when rpf_blob is stored as PaOSReplayFloor (NV|BS)
;   and reads back byte-exact with exactly those attributes; else -1 and
;   rpf_err holds the failing step.
rpf_write_verify:
    push rbp
    mov  rbp, rsp
    push r12
    and  rsp, -16
    sub  rsp, 48
    mov  r12, [rel runtime_services]
    mov  byte [rel rpf_err], RPF_E_GATE
    lea  rdi, [rel command_auth_replay_guid]
    lea  rsi, [rel rpf_name]
    xor  edx, edx                       ; SA_INTENT_IMPLICIT: PaOS-namespace -> NORMAL
    lea  rcx, [rel str_rpf_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    mov  byte [rel rpf_err], RPF_E_SET
    lea  rcx, [rel rpf_name]
    lea  rdx, [rel command_auth_replay_guid]
    mov  r8d, RPF_ATTRS
    mov  r9d, RPF_SIZE
    lea  rax, [rel rpf_blob]
    mov  [rsp + 32], rax
    call [r12 + 0x58]                   ; SetVariable (literal: test_nvram_setvariable_sites scans it)
    test rax, rax
    jnz  .bad
    mov  byte [rel rpf_err], RPF_E_GET
    mov  qword [rel rpf_io_size], RPF_SIZE
    mov  dword [rel rpf_io_attrs], 0
    lea  rcx, [rel rpf_name]
    lea  rdx, [rel command_auth_replay_guid]
    lea  r8, [rel rpf_io_attrs]
    lea  r9, [rel rpf_io_size]
    lea  rax, [rel rpf_verify]
    mov  [rsp + 32], rax
    call [r12 + RPF_RT_GETVAR]
    test rax, rax
    jnz  .bad
    mov  byte [rel rpf_err], RPF_E_COMPARE
    cmp  dword [rel rpf_io_attrs], RPF_ATTRS
    jne  .bad
    cmp  qword [rel rpf_io_size], RPF_SIZE
    jne  .bad
    lea  rsi, [rel rpf_blob]
    lea  rdi, [rel rpf_verify]
    mov  ecx, RPF_SIZE
    cld
    repe cmpsb
    jne  .bad
    mov  byte [rel rpf_err], RPF_E_NONE
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    lea  rsp, [rbp - 8]
    pop  r12
    pop  rbp
    ret

; rpf_delete -> EAX 0 when nothing is left under PaOSReplayFloor (DataSize 0
;   deletes whatever attributes it had; pre-EBS that includes an RT-visible one).
rpf_delete:
    push rbp
    mov  rbp, rsp
    push r12
    and  rsp, -16
    sub  rsp, 48
    mov  r12, [rel runtime_services]
    lea  rdi, [rel command_auth_replay_guid]
    lea  rsi, [rel rpf_name]
    xor  edx, edx
    lea  rcx, [rel str_rpf_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    lea  rcx, [rel rpf_name]
    lea  rdx, [rel command_auth_replay_guid]
    xor  r8d, r8d
    xor  r9d, r9d
    mov  qword [rsp + 32], 0
    call [r12 + 0x58]                   ; SetVariable (literal: test_nvram_setvariable_sites scans it)
    test rax, rax
    jz   .ok
    mov  rdx, RPF_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .bad
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    lea  rsp, [rbp - 8]
    pop  r12
    pop  rbp
    ret

; rpf_read_rt -> RAX = the RT replay record's sequence when it is exactly a
;   record command_auth_replay_load accepts (attrs NV|BS|RT, 64 B, magic,
;   version, size, this command lineage's replay domain, CRC, seq != 0); else 0. Never fails
;   the floor: the RT record is an input, not an authority. rpf_rt_raw keeps the
;   value for the mirror's never-lower rule.
; Pair mode retains the original primary's domain across signer replacement;
; neither the selected signer nor a changing pair digest starts another floor.
rpf_read_rt:
    push rbp
    mov  rbp, rsp
    push r12
    and  rsp, -16
    sub  rsp, 48
    mov  qword [rel rpf_rt_raw], 0
    mov  r12, [rel runtime_services]
    mov  qword [rel rpf_io_size], AUTH_REPLAY_SIZE
    mov  dword [rel rpf_io_attrs], 0
    lea  rcx, [rel command_auth_replay_name]
    lea  rdx, [rel command_auth_replay_guid]
    lea  r8, [rel rpf_io_attrs]
    lea  r9, [rel rpf_io_size]
    lea  rax, [rel rpf_rt_buf]
    mov  [rsp + 32], rax
    call [r12 + RPF_RT_GETVAR]
    test rax, rax
    jz   .check
    mov  rdx, RPF_EFI_NOT_FOUND
    cmp  rax, rdx
    je   .zero
    jmp  .invalid
.check:
    cmp  dword [rel rpf_io_attrs], AUTH_EFI_ATTRS
    jne  .invalid
    cmp  qword [rel rpf_io_size], AUTH_REPLAY_SIZE
    jne  .invalid
    cmp  dword [rel rpf_rt_buf + AUTH_REPLAY_MAGIC_OFF], AUTH_REPLAY_MAGIC
    jne  .invalid
    cmp  word [rel rpf_rt_buf + AUTH_REPLAY_VERSION_OFF], AUTH_REPLAY_VERSION
    jne  .invalid
    cmp  word [rel rpf_rt_buf + AUTH_REPLAY_SIZE_OFF], AUTH_REPLAY_SIZE
    jne  .invalid
%ifdef BOOT_V2_COMMAND_PAIR_ABI
    lea  rsi, [rel boot_v2_command_replay_domain_id]
%else
    lea  rsi, [rel command_auth_owner_key_id]
%endif
    lea  rdi, [rel rpf_rt_buf + AUTH_REPLAY_KEY_ID_OFF]
    mov  ecx, 32
    cld
    repe cmpsb
    jne  .invalid
    lea  rdi, [rel rpf_rt_buf]
    mov  esi, AUTH_REPLAY_CRC32_OFF
    call pbm_crc32
    cmp  eax, [rel rpf_rt_buf + AUTH_REPLAY_CRC32_OFF]
    jne  .invalid
    mov  rax, [rel rpf_rt_buf + AUTH_REPLAY_SEQ_OFF]
    test rax, rax
    jz   .invalid
    mov  [rel rpf_rt_raw], rax
    jmp  .out
.invalid:
    or   byte [rel rpf_flags], RPF_FL_RT_INVALID
.zero:
    xor  eax, eax
.out:
    lea  rsp, [rbp - 8]
    pop  r12
    pop  rbp
    ret

; rpf_read_password -> RAX = the principal record's PASSWORD floor
;   (PRIN_REC_LAST_SEQ) when PaOSPrincipalCred is NV|BS|RT with a v1 (128 B) or
;   v2/v3 (208 B) shape, magic, matching size field and CRC; else 0. The buffer
;   can hold Y (v1/v2): it is zeroed before return (reset_wipe covers a fault).
;   A looser check than principal's can only raise B, and only within the clamp.
rpf_read_password:
    push rbp
    mov  rbp, rsp
    push r12
    push rbx
    and  rsp, -16
    sub  rsp, 48
    xor  ebx, ebx
    mov  r12, [rel runtime_services]
    mov  qword [rel rpf_io_size], RPF_PRIN_MAX
    mov  dword [rel rpf_io_attrs], 0
    lea  rcx, [rel prin_record_name]
    lea  rdx, [rel prin_record_guid]
    lea  r8, [rel rpf_io_attrs]
    lea  r9, [rel rpf_io_size]
    lea  rax, [rel rpf_prin_buf]
    mov  [rsp + 32], rax
    call [r12 + RPF_RT_GETVAR]
    test rax, rax
    jnz  .wipe
    cmp  dword [rel rpf_io_attrs], AUTH_EFI_ATTRS
    jne  .wipe
    cmp  dword [rel rpf_prin_buf + PRIN_REC_MAGIC], PRIN_RECORD_MAGIC
    jne  .wipe
    movzx esi, word [rel rpf_prin_buf + PRIN_REC_SIZE]
    cmp  rsi, [rel rpf_io_size]
    jne  .wipe
    movzx eax, word [rel rpf_prin_buf + PRIN_REC_VERSION]
    cmp  esi, PRIN_V1_SIZE
    je   .v1
    cmp  esi, PRIN_RECORD_SIZE
    jne  .wipe
    cmp  eax, 2
    jb   .wipe
    cmp  eax, 3
    ja   .wipe
    jmp  .crc
.v1:
    cmp  eax, 1
    je   .crc
    cmp  eax, 3
    jne  .wipe
.crc:
    sub  esi, 4
    push rsi
    push rsi
    lea  rdi, [rel rpf_prin_buf]
    call pbm_crc32
    pop  rsi
    pop  rsi
    lea  rdx, [rel rpf_prin_buf]
    cmp  eax, [rdx + rsi]
    jne  .wipe
    mov  rbx, [rel rpf_prin_buf + PRIN_REC_LAST_SEQ]
.wipe:
    cld
    lea  rdi, [rel rpf_prin_buf]
    xor  eax, eax
    mov  ecx, RPF_PRIN_MAX
    rep  stosb
    mov  rax, rbx
    lea  rsp, [rbp - 16]
    pop  rbx
    pop  r12
    pop  rbp
    ret

; rpf_mirror(RDI = F') -> EAX 0 when PaOSCommandAuthReplay holds F' (the same
;   record command_auth_replay_persist writes: the stable replay domain, time 0, flags
;   1) and reads back byte-exact with attributes NV|BS|RT; else -1.
rpf_mirror:
    push rbp
    mov  rbp, rsp
    push r12
    push rbx
    and  rsp, -16
    sub  rsp, 48
    mov  rbx, rdi
    mov  r12, [rel runtime_services]
    cld
    lea  rdi, [rel rpf_rt_buf]
    xor  eax, eax
    mov  ecx, AUTH_REPLAY_SIZE
    rep  stosb
    mov  dword [rel rpf_rt_buf + AUTH_REPLAY_MAGIC_OFF], AUTH_REPLAY_MAGIC
    mov  word [rel rpf_rt_buf + AUTH_REPLAY_VERSION_OFF], AUTH_REPLAY_VERSION
    mov  word [rel rpf_rt_buf + AUTH_REPLAY_SIZE_OFF], AUTH_REPLAY_SIZE
%ifdef BOOT_V2_COMMAND_PAIR_ABI
    lea  rsi, [rel boot_v2_command_replay_domain_id]
%else
    lea  rsi, [rel command_auth_owner_key_id]
%endif
    lea  rdi, [rel rpf_rt_buf + AUTH_REPLAY_KEY_ID_OFF]
    mov  ecx, 32
    rep  movsb
    mov  [rel rpf_rt_buf + AUTH_REPLAY_SEQ_OFF], rbx
    mov  dword [rel rpf_rt_buf + AUTH_REPLAY_FLAGS_OFF], 1
    lea  rdi, [rel rpf_rt_buf]
    mov  esi, AUTH_REPLAY_CRC32_OFF
    call pbm_crc32
    mov  [rel rpf_rt_buf + AUTH_REPLAY_CRC32_OFF], eax
    lea  rdi, [rel command_auth_replay_guid]
    lea  rsi, [rel command_auth_replay_name]
    xor  edx, edx
    lea  rcx, [rel str_rpf_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    lea  rcx, [rel command_auth_replay_name]
    lea  rdx, [rel command_auth_replay_guid]
    mov  r8d, AUTH_EFI_ATTRS
    mov  r9d, AUTH_REPLAY_SIZE
    lea  rax, [rel rpf_rt_buf]
    mov  [rsp + 32], rax
    call [r12 + 0x58]                   ; SetVariable (literal: test_nvram_setvariable_sites scans it)
    test rax, rax
    jnz  .bad
    mov  qword [rel rpf_io_size], AUTH_REPLAY_SIZE
    mov  dword [rel rpf_io_attrs], 0
    lea  rcx, [rel command_auth_replay_name]
    lea  rdx, [rel command_auth_replay_guid]
    lea  r8, [rel rpf_io_attrs]
    lea  r9, [rel rpf_io_size]
    lea  rax, [rel rpf_verify]
    mov  [rsp + 32], rax
    call [r12 + RPF_RT_GETVAR]
    test rax, rax
    jnz  .bad
    cmp  dword [rel rpf_io_attrs], AUTH_EFI_ATTRS
    jne  .bad
    cmp  qword [rel rpf_io_size], AUTH_REPLAY_SIZE
    jne  .bad
    lea  rsi, [rel rpf_rt_buf]
    lea  rdi, [rel rpf_verify]
    mov  ecx, AUTH_REPLAY_SIZE
    cld
    repe cmpsb
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    lea  rsp, [rbp - 16]
    pop  rbx
    pop  r12
    pop  rbp
    ret

; rpf_reseed_check — PRE-EBS. EAX 1 when PaOSReplayFloorReseed is exactly an
;   owner reseed of this LOST floor: NV|BS|RT, 64 B, magic, version, size, the
;   LOST record's epoch, this boot's owner generation, the LOST value, and the
;   HMAC under HKDF(Y, info). Any stage read is deleted (honoured or not); the
;   derived key and MAC are zeroed before return.
rpf_reseed_check:
    push rbp
    mov  rbp, rsp
    push r12
    push rbx
    and  rsp, -16
    sub  rsp, 48
    xor  ebx, ebx
    mov  r12, [rel runtime_services]
    mov  qword [rel rpf_io_size], RPF_STG_SIZE
    mov  dword [rel rpf_io_attrs], 0
    lea  rcx, [rel rpf_stage_name]
    lea  rdx, [rel command_auth_replay_guid]
    lea  r8, [rel rpf_io_attrs]
    lea  r9, [rel rpf_io_size]
    lea  rax, [rel rpf_stage_buf]
    mov  [rsp + 32], rax
    call [r12 + RPF_RT_GETVAR]
    test rax, rax
    jz   .present
    mov  rdx, RPF_EFI_NOT_FOUND
    cmp  rax, rdx
    je   .out                            ; no stage
    jmp  .delete                         ; oversized or unreadable: never a stage
.present:
    cmp  dword [rel rpf_io_attrs], RPF_STG_ATTRS
    jne  .delete
    cmp  qword [rel rpf_io_size], RPF_STG_SIZE
    jne  .delete
    cmp  dword [rel rpf_stage_buf + RPF_OFF_MAGIC], RPF_STG_MAGIC
    jne  .delete
    cmp  word [rel rpf_stage_buf + RPF_OFF_VERSION], RPF_VERSION
    jne  .delete
    cmp  word [rel rpf_stage_buf + RPF_OFF_SIZE], RPF_STG_SIZE
    jne  .delete
    mov  rax, [rel rpf_epoch]
    cmp  [rel rpf_stage_buf + RPF_STG_OFF_EPOCH], rax
    jne  .delete                         ; a stage captured at an earlier loss
    mov  rax, [rel ows_generation]
    cmp  [rel rpf_stage_buf + RPF_STG_OFF_GEN], rax
    jne  .delete
    mov  rax, [rel rpf_f]
    cmp  [rel rpf_stage_buf + RPF_STG_OFF_FLOOR], rax
    jne  .delete
    lea  rdi, [rel rpf_reseed_info]
    mov  esi, rpf_reseed_info.len
    lea  rdx, [rel rpf_reseed_key]
    call system_secret_hkdf
    test eax, eax
    jz   .delete                         ; no Y this boot: nothing can be verified
    lea  rdi, [rel rpf_stage_mac]
    lea  rsi, [rel rpf_reseed_key]
    mov  edx, 32
    lea  rcx, [rel rpf_stage_buf]
    mov  r8d, RPF_STG_OFF_MAC
    call hmac_sha256
    test rax, rax
    jnz  .delete
    xor  eax, eax                        ; constant-time compare
    xor  ecx, ecx
    lea  rsi, [rel rpf_stage_mac]
    lea  r8, [rel rpf_stage_buf + RPF_STG_OFF_MAC]
.cmp:
    mov  dl, [rsi + rcx]
    xor  dl, [r8 + rcx]
    or   al, dl
    inc  ecx
    cmp  ecx, 32
    jb   .cmp
    test al, al
    jnz  .delete
    mov  ebx, 1
.delete:
    call rpf_stage_delete
.out:
    cld
    xor  eax, eax
    lea  rdi, [rel rpf_reseed_key]
    mov  ecx, 32
    rep  stosb
    lea  rdi, [rel rpf_stage_mac]
    mov  ecx, 32
    rep  stosb
    mov  eax, ebx
    lea  rsp, [rbp - 16]
    pop  rbx
    pop  r12
    pop  rbp
    ret

; rpf_stage_delete -> EAX 0 when nothing is left under PaOSReplayFloorReseed.
rpf_stage_delete:
    push rbp
    mov  rbp, rsp
    push r12
    and  rsp, -16
    sub  rsp, 48
    mov  r12, [rel runtime_services]
    lea  rdi, [rel command_auth_replay_guid]
    lea  rsi, [rel rpf_stage_name]
    xor  edx, edx
    lea  rcx, [rel str_rpf_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    lea  rcx, [rel rpf_stage_name]
    lea  rdx, [rel command_auth_replay_guid]
    xor  r8d, r8d
    xor  r9d, r9d
    mov  qword [rsp + 32], 0
    call [r12 + 0x58]                   ; SetVariable (literal: test_nvram_setvariable_sites scans it)
    test rax, rax
    jz   .ok
    mov  rdx, RPF_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .bad
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    lea  rsp, [rbp - 8]
    pop  r12
    pop  rbp
    ret

; replay_floor_stage_reseed — RUNTIME (AUTHFLOOR RESEED, console OWNER only;
;   command_auth checks the ingress). EAX 0 when PaOSReplayFloorReseed holds the
;   HMAC-bound reseed of this boot's LOST floor and reads back byte-exact with
;   NV|BS|RT; -1 when the floor is not LOST, no key was derived pre-EBS (no Y),
;   firmware runtime code is not mapped, or a firmware step failed.
replay_floor_stage_reseed:
    push rbp
    mov  rbp, rsp
    push r12
    push rbx
    and  rsp, -16
    sub  rsp, 48
    mov  ebx, -1
    cmp  byte [rel rpf_state], RPF_LOST
    jne  .out
    cmp  byte [rel rpf_key_ready], 1
    jne  .out
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .out
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .out
    cld
    lea  rdi, [rel rpf_stage_buf]
    xor  eax, eax
    mov  ecx, RPF_STG_SIZE
    rep  stosb
    mov  dword [rel rpf_stage_buf + RPF_OFF_MAGIC], RPF_STG_MAGIC
    mov  word [rel rpf_stage_buf + RPF_OFF_VERSION], RPF_VERSION
    mov  word [rel rpf_stage_buf + RPF_OFF_SIZE], RPF_STG_SIZE
    mov  rax, [rel rpf_epoch]
    mov  [rel rpf_stage_buf + RPF_STG_OFF_EPOCH], rax
    mov  rax, [rel ows_generation]
    mov  [rel rpf_stage_buf + RPF_STG_OFF_GEN], rax
    mov  rax, [rel rpf_f]
    mov  [rel rpf_stage_buf + RPF_STG_OFF_FLOOR], rax
    lea  rdi, [rel rpf_stage_buf + RPF_STG_OFF_MAC]
    lea  rsi, [rel rpf_reseed_key]
    mov  edx, 32
    lea  rcx, [rel rpf_stage_buf]
    mov  r8d, RPF_STG_OFF_MAC
    call hmac_sha256
    test rax, rax
    jnz  .out
    lea  rdi, [rel command_auth_replay_guid]
    lea  rsi, [rel rpf_stage_name]
    xor  edx, edx
    lea  rcx, [rel str_rpf_reseed_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .out
    lea  rcx, [rel rpf_stage_name]
    lea  rdx, [rel command_auth_replay_guid]
    mov  r8d, RPF_STG_ATTRS
    mov  r9d, RPF_STG_SIZE
    lea  rax, [rel rpf_stage_buf]
    mov  [rsp + 32], rax
    call [r12 + 0x58]                   ; SetVariable (literal: test_nvram_setvariable_sites scans it)
    test rax, rax
    jnz  .out
    mov  qword [rel rpf_io_size], RPF_STG_SIZE
    mov  dword [rel rpf_io_attrs], 0
    lea  rcx, [rel rpf_stage_name]
    lea  rdx, [rel command_auth_replay_guid]
    lea  r8, [rel rpf_io_attrs]
    lea  r9, [rel rpf_io_size]
    lea  rax, [rel rpf_verify]
    mov  [rsp + 32], rax
    call [r12 + RPF_RT_GETVAR]
    test rax, rax
    jnz  .out
    cmp  dword [rel rpf_io_attrs], RPF_STG_ATTRS
    jne  .out
    cmp  qword [rel rpf_io_size], RPF_STG_SIZE
    jne  .out
    lea  rsi, [rel rpf_stage_buf]
    lea  rdi, [rel rpf_verify]
    mov  ecx, RPF_STG_SIZE
    cld
    repe cmpsb
    jne  .out
    xor  ebx, ebx
.out:
    mov  eax, ebx
    lea  rsp, [rbp - 16]
    pop  rbx
    pop  r12
    pop  rbp
    ret

%include "core/abi/wdata.inc" ; WDATA_BSS_DEFER; standalone assemblies expand blocks in place
; Zero-initialised state with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER):
; replay_floor_preebs sets every field at entry, and every runtime consumer keys
; on rpf_state (RPF_NONE = 0 = not run), so the zero image value is never trusted.
%macro WDATA_BSS_sec_replay_floor 0
alignb 8
rpf_b:            resq 1                ; B: this boot's floor (H at runtime)
rpf_f:            resq 1                ; F' committed (HELD/MIRROR_FAILED) or the LOST value
rpf_seal:         resq 1                ; the highest sequence any path may admit (HELD/MIRROR_FAILED)
rpf_tsc:          resq 1                ; the step's TSC delta (start TSC while running)
rpf_epoch:        resq 1                ; the LOST record's epoch (0 unless LOST)
rpf_rt_raw:       resq 1                ; the valid R_rt before clamping (the mirror never lowers it)
rpf_io_size:      resq 1
rpf_io_attrs:     resd 1
rpf_state:        resb 1
rpf_err:          resb 1
rpf_flags:        resb 1
rpf_key_ready:    resb 1                ; rpf_reseed_key holds HKDF(Y, info) for AUTHFLOOR this boot
alignb 16
rpf_reseed_key:   resb 32               ; HKDF(Y, "PaOS/replay/reseed/v1") while LOST (reset_wipe covers it)
rpf_stage_mac:    resb 32               ; the recomputed stage MAC (pre-EBS, then zeroed)
rpf_stage_buf:    resb RPF_STG_SIZE
rpf_blob:         resb RPF_SIZE
rpf_verify:       resb RPF_SIZE
rpf_rt_buf:       resb AUTH_REPLAY_SIZE
rpf_prin_buf:     resb RPF_PRIN_MAX         ; the principal record (can hold Y) for one read
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_replay_floor
align 2, db 0                           ; CHAR16 variable names (char16_align_check)
rpf_name:
    dw 'P','a','O','S','R','e','p','l','a','y','F','l','o','o','r',0
rpf_stage_name:
    dw 'P','a','O','S','R','e','p','l','a','y','F','l','o','o','r','R','e','s','e','e','d',0
rpf_reseed_info:  db "PaOS/replay/reseed/v1"
.len equ $ - rpf_reseed_info
str_rpf_nvg_tag:  db "replay_floor_preebs",0
str_rpf_reseed_tag: db "replay_floor_reseed",0
str_rpf_state:    db "[PAOS64] replay floor: state=",0
str_rpf_err:      db " err=",0
str_rpf_b:        db " B=",0
str_rpf_f:        db " F=",0
str_rpf_flags:    db " flags=",0
str_rpf_tsc:      db " tsc=",0
str_rpf_marker:   db " [sec.replay_floor.preebs]",13,10,0
