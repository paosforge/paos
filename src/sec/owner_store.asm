;; MODULE sec/owner_store
;; LAYER 5
;; EXPORTS owner_store_preebs, owner_enrolled_modulus, owner_password_take, owner_password_discard, ows_state, ows_stage, ows_selected, ows_generation, ows_summary, ows_planted, ows_floor_seeded, ows_local, ows_zbound, ows_stage_name, owner_stage_prepare, owner_stage_pending, owner_stage_commit, owner_writer_discard, owner_writer_read, owner_writer_write, owner_writer_delete, ows_wr_ready, ows_wr_stage, ows_wr_target_hash, ows_wr_pending_hash, ows_committed_hash, ows_wr_io, ows_wr_size, ows_wr_attrs
;; IMPORTS boot/header, boot/serial, boot/nvram_access, boot/boot_v2_handoff, sec/principal, sec/owner_stage_key, sec/owner_record, core/lib/sha256, core/lib/hmac_sha256, core/lib/mem, core/reset_wipe, fs/storage_access
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only
; ============================================================================
; sec/owner_store.asm — owner identity S1b-1: the per-install PaOSOwner store,
; read and committed before ExitBootServices (design note §3.2; srcreview
; DC3/DC5; root D5 07:43).
;
; PaOSOwner0 / PaOSOwner1 are two NV|BS slots (512 B, sec/owner_record): after
; EBS the firmware hides them and refuses runtime writes, so a runtime OS can
; neither read, replace, revert nor delete the committed owner. A change made
; after EBS is staged (NV|BS|RT, 608 B) with the body of the next record, base
; generation + 1, SHA-256 of the base record, and an HMAC keyed by
; HKDF-SHA256(Z, info "PaOS/owner/stage-z/v1"). The stage's NAME is
; "PaOSOwnerStage" + 32 lowercase hex of HKDF-SHA256(Z, info
; "PaOS/owner/stage-name-z/v1" || gen_le64)[0..16), gen = the committed, verified
; record's generation (0 = proven absence); root A5 16:57:58 / 17:49:33. Z is
; the owner stage key (sec/owner_stage_key, S1b-2c-0, root 11:25:44): born
; pre-EBS, NV|BS only, never derived from Y, which a runtime OS may have read
; while it sat in the RT record. A runtime OS cannot compute the name or the
; MAC without Z, and only that name is ever read. A stage MACed or named under
; the old Y labels can never verify here (srcreview Z3).
;
; Strict Z4 / F1 correction (design9dbc265e, original review1485b8c6):
;   - fixed authenticated NV|BS PaOSOwnerMigration journal is read FIRST;
;   - v1->v2 preserves original base+stage before canonicalization, verifies
;     journal, then writes nonempty INVALID tombstones B->A BEFORE targets A->B;
;   - verified stage cleanup and journal absence precede APPLIED/handoff;
;   - uncertain progress locks this pass; authenticated recovery runs before
;     ordinary selection, including missing stage/ordinary records;
;   - legacy valid v1/v2 without J is preserved/LOCKED, never silently repaired.
; Real capacity, native bytes/pre-EBS TSC and metal qualification remain owed.
;
; owner_store_preebs (boot/header, after system_secret_preebs, BEFORE EBS):
;   1. reads both slots. Anything under a slot name that is not exactly NV|BS
;      (an RT-visible variable a runtime OS planted, or an oversized one we
;      never write) is DELETED and counted in ows_planted, never trusted. One
;      the firmware will not delete (an authenticated 0x27 variable a runtime
;      OS created; srcreview S1b F1) is still never trusted: the slot is
;      ABSENT for selection, flagged "stuck" (ows_planted bit 4 + slot) and
;      never written, so a plant cannot fail the store every boot;
;   2. owner_record_select: the valid slot with the higher generation. Both
;      genuinely absent = UNOWNED. No valid slot, or an equal-generation
;      divergence = CORRUPT: fail closed, never mapped to absence;
;   2b. LOADED at generation g: a stage under name(g - 1) is stale by
;      construction. One a cut left between an applied commit and its delete
;      still carries the committed record (verifier) RT-visible (F4), so it is
;      deleted when it has exactly the stage attributes; anything else there
;      (an authenticated plant a rotation moved away from) is left alone.
;      Never decided, never trusted, never flagged;
;   3. without Z, or without a validated base (CORRUPT, FAILED), no stage
;      name exists: nothing is read, decided or written (UNNAMED). Otherwise
;      the stage under this generation's name is verified against the
;      selected record (or proven absence) with owner_stage_validate.
;      Invalid, stale or foreign: deleted. Valid:
;      owner_change_needs_confirmation decides. An authority-ADDING change
;      (owner KEY add/replace, FLEET accept) needs a typed firmware ConIn
;      confirmation, which this build does not have: the stage is refused and
;      deleted, the record is unchanged (root D5 (1)/(5)). Anything else is
;      applied to the INACTIVE slot (slot 0 when unowned, slot 1 if slot 0 is
;      stuck; a stuck target fails the apply and keeps the stage), read back byte-exact, and only then is the
;      stage deleted (DC5: a cut before the read-back leaves the active slot
;      and the stage, which re-applies next boot; a cut after it leaves a stage
;      whose base generation is no longer current, which is refused);
;   3a. a stage the firmware will not delete (bit 6) under this generation's
;      name would block every change. LOADED, the committed record is
;      re-committed unchanged at generation + 1 to the inactive slot (read
;      back): the name moves (bit 7), once per pass. Nothing is rotated when
;      UNOWNED (no record to bump) or when an applied change already moved it;
;   3b. keeps both slot names taken (srcreview S1b F1 N1): when the store is
;      LOADED and the other slot name is genuinely empty this boot (nothing
;      read there, nothing stuck), the committed record is copied into it
;      (NV|BS, read back). An identical equal-generation pair selects slot 0,
;      and the next change overwrites the inactive copy, so a runtime OS never
;      again finds an empty owner name to plant an undeletable variable in.
;      A committed OWR_VERSION_Z record also overwrites a v1 record in the
;      other slot, so an image before Z reads CORRUPT, never the older record;
;   4. reports state, slot, generation and the non-secret summary every boot
;      on the pre-EBS serial line (DC3: a suppressed stage shows as an
;      unchanged generation; S1b-2 exposes them after EBS), and leaves
;      ows_stage_name = the name for the final committed generation (empty
;      when none can be derived: the post-EBS writer then stages nothing).
; Every buffer that held a record, a stage or the stage key is zeroed before
; return (DC4). c2a retains a sanitized public base (password/FLEET zero),
; its integrity digest and the current-generation derived stage MAC key only
; on a ready boot (accepted DC4 deviation D1-D4). Raw Z never survives this
; pass. The password hand-off exception is
; the S1b-2c password hand-off (srcreview S1b-2 D4): when the committed record
; carries OWR_LOCAL, its iterations, salt and verifier (OWS_PW_LEN bytes) are
; copied out for sec/principal, which takes them once (owner_password_take) or
; discards them (owner_password_discard) in principal_credentials_init, on
; every path, as system_secret_take/discard do for Y. Only a LOADED store
; fills it; reset_wipe covers a fault before that.
; APP keeps only the selected validated OWR_KEY public modulus, converted to
; the verifier's little-endian form. No private key, enrollment or AUTH change.
; Missing/uncertain authority has no public-key handoff or publisher fallback.
;
; Residuals: pre-EBS code (a UEFI shell, any db-trusted loader) and an SPI
; dump read the slots, as for Y. A runtime OS can delete a pending stage
; (suppression, DC3) and re-plant the copy it captured later: while no newer
; generation has been committed, that stage still binds the current record
; and APPLIES, so the owner's own change lands late, never a forged one. The
; generation/prev-hash binding refuses a re-planted stage only once a newer
; generation exists (srcreview S1b F2). Once a record is committed both names
; are taken (3b), so an undeletable plant under a slot name is possible only
; before the first commit (UNOWNED) or after something outside the OS cleared
; a name: there it blocks first setup or owner changes (reported as stuck,
; ows_planted bits 4/5) until firmware setup clears it. A plant of the stage
; name the firmware will not delete is flagged too (bit 6) and rotated away
; (3a); before the first commit it blocks first setup, as a stuck slot does.
; A plant under any other name (the fixed pre-A5 name, an old generation's,
; a guess) is never read. Z compromise (pre-EBS code, SPI) breaks the name as
; it breaks the MAC.
; From the boot after a rotation the plant sits at name(g - 1), which 2b
; leaves alone unless it is exactly NV|BS|RT, so OWNERSTAT reads gen+1,
; stage=0, planted=0: gen+1 is not proof that a change applied (srcreview
; S1b-2b L1). The owner confirms a change by signing in with the new
; credential.
; No plant can replace, hide or revert the committed record.
; ============================================================================

OWS_NONE          equ 0                 ; not run: no runtime services
OWS_PW_ITER       equ 0                 ; the password hand-off: u32 iterations,
OWS_PW_SALT       equ 4                 ; 16-byte salt,
OWS_PW_VERIFIER   equ 20                ; 32-byte verifier
OWS_PW_LEN        equ 52
OWS_LOADED        equ 1                 ; a valid record is selected
OWS_UNOWNED       equ 2                 ; both slots genuinely absent
OWS_CORRUPT       equ 3                 ; no valid slot / divergent tie: fail closed
OWS_FAILED        equ 4                 ; a firmware error: decide nothing
OWS_PLANTED_STUCK_SLOTS equ 0x30         ; ows_planted bits 4+5: both slot names undeletable (blocks first setup)
OWS_PLANTED_STUCK_STAGE equ 0x40         ; ows_planted bit 6: the stage name undeletable (blocks first setup)
%if OWR_SALT + 16 != OWR_VERIFIER || OWS_PW_SALT + 16 != OWS_PW_VERIFIER || OWS_PW_VERIFIER + 32 != OWS_PW_LEN
    %error "S1b-2c hand-off copies salt+verifier as one run"
%endif
%ifdef PRIN_OWS_MIRROR
%if PRIN_OWS_LOADED != OWS_LOADED || PRIN_OWS_UNOWNED != OWS_UNOWNED || PRIN_OWS_CORRUPT != OWS_CORRUPT || PRIN_OWS_FAILED != OWS_FAILED || PRIN_OWNER_PW_LEN != OWS_PW_LEN
    %error "sec/principal mirrors owner_store states and the hand-off size"
%endif
%if PRIN_OWS_STUCK_SLOTS != OWS_PLANTED_STUCK_SLOTS || PRIN_OWS_STUCK_STAGE != OWS_PLANTED_STUCK_STAGE
    %error "sec/principal mirrors the ows_planted stuck bits"
%endif
%endif

OWS_STG_NONE      equ 0                 ; no stage
OWS_STG_APPLIED   equ 1                 ; committed/read back; migration additionally completes both slots and verifies journal absence
OWS_STG_REFUSED   equ 2                 ; invalid, stale or foreign: deleted, record unchanged
OWS_STG_CONFIRM   equ 3                 ; authority-adding: needs firmware confirm (not in this build), deleted
OWS_STG_KEPT      equ 4                 ; named, but the stage key could not be derived this boot: left untouched
OWS_STG_FAILED    equ 5                 ; a firmware error while applying: stage kept for the next boot
OWS_STG_UNNAMED   equ 6                 ; no Z or no validated base this boot: no name, nothing read

OWS_REC_ATTRS     equ 0x00000003        ; NV | BOOTSERVICE_ACCESS
OWS_REC_SIZE      equ 512
OWS_STAGE_SIZE    equ 608
OWS_STAGE_BODY    equ 64
OWS_EFI_NOT_FOUND        equ 0x800000000000000E
OWS_EFI_BUFFER_TOO_SMALL equ 0x8000000000000005
OWS_EFI_APPEND_WRITE     equ 0x40               ; EFI_VARIABLE_APPEND_WRITE
OWS_RT_GETVAR     equ 0x48
OWS_RT_QUERYVAR   equ 0x80             ; offsetof(EFI_RUNTIME_SERVICES, QueryVariableInfo)

%if OWS_STAGE_BODY + OWS_REC_SIZE + 32 != OWS_STAGE_SIZE
    %error owner_store_stage_layout_mismatch
%endif

; owner_store_preebs — PRE-EBS only. No return value: the outcome is ows_state
;   and ows_stage. Preserves the callee-saved registers.
owner_store_preebs:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    and  rsp, -16
    sub  rsp, 48
    call ows_writer_reset
    mov  byte [rel ows_state], OWS_NONE
    mov  byte [rel ows_floor_seeded], 0
    mov  byte [rel ows_local], 0
    mov  byte [rel ows_zbound], 0
    call owner_password_discard         ; S1b-2c: only a record committed in this pass hands a verifier on
    mov  byte [rel ows_stage], OWS_STG_NONE
    mov  byte [rel ows_selected], 0xFF
    mov  byte [rel ows_planted], 0
    mov  qword [rel ows_generation], 0
    mov  dword [rel ows_summary], 0
    mov  word [rel ows_stage_name], 0
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .wipe
    mov  byte [rel ows_j_raw], 0
    ; Authenticated migration recovery precedes all ordinary authority,
    ; stage cleanup/selection and handoff. No raw-read foreign deletion.
    call ows_j_entry
    test eax, eax
    js   .transaction_failed
    jnz  .journal_done
    ; ---- 1. both slots ----
    xor  edi, edi
    call ows_read_slot
    test eax, eax
    jnz  .failed
    mov  edi, 1
    call ows_read_slot
    test eax, eax
    jnz  .failed
    call ows_legacy_mixed
    test eax, eax
    jnz  .transaction_failed
    ; ---- 2. select ----
    mov  rdi, [rel ows_slot_ptr]
    mov  rsi, [rel ows_slot_size]
    mov  edx, [rel ows_slot_attrs]
    mov  rcx, [rel ows_slot_ptr + 8]
    mov  r8, [rel ows_slot_size + 8]
    mov  r9d, [rel ows_slot_attrs + 4]
    call owner_record_select
    cmp  eax, -1
    je   .unowned
    cmp  eax, 1
    ja   .corrupt                       ; -2 (or anything not 0/1): never absence
    mov  [rel ows_selected], al
    mov  byte [rel ows_state], OWS_LOADED
    call ows_publish_selected
    jmp  .stage
.unowned:
    mov  byte [rel ows_state], OWS_UNOWNED
    jmp  .stage
.corrupt:
    mov  byte [rel ows_state], OWS_CORRUPT
    ; ---- 3. a pending stage ----
.stage:
    call ows_clean_previous
    call ows_stage_decide
    call ows_mirror
    call ows_name_current               ; the name the post-EBS writer stages under
    jmp  .wipe
.journal_done:
    call ows_name_current
    jmp  .wipe
.transaction_failed:
    call ows_j_lock
    jmp  .wipe
.failed:
    mov  byte [rel ows_state], OWS_FAILED
    mov  byte [rel ows_selected], 0xFF
.wipe:
    call ows_writer_capture             ; sanitized public base + derived MAC only; before transient scrub/Z discard
    call ows_owner_key_capture          ; public verification bytes only, independent of writer readiness
    call ows_wipe_buffers
.report:
    call owner_stage_key_discard        ; c2a retains only the derived current-generation stage MAC, never raw Z
    lea  rdi, [rel str_ows_state]
    call serial_string
    movzx edi, byte [rel ows_state]
    call serial_hex64
    lea  rdi, [rel str_ows_slot]
    call serial_string
    movzx edi, byte [rel ows_selected]
    call serial_hex64
    lea  rdi, [rel str_ows_gen]
    call serial_string
    mov  rdi, [rel ows_generation]
    call serial_hex64
    lea  rdi, [rel str_ows_summary]
    call serial_string
    mov  edi, [rel ows_summary]
    call serial_hex64
    lea  rdi, [rel str_ows_stage]
    call serial_string
    movzx edi, byte [rel ows_stage]
    call serial_hex64
    lea  rdi, [rel str_ows_planted]
    call serial_string
    movzx edi, byte [rel ows_planted]
    call serial_hex64
    lea  rdi, [rel str_ows_marker]
    call serial_string
    lea  rsp, [rbp - 32]
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ows_read_slot(EDI = 0/1) -> EAX 0 when the slot's (pointer, size, attrs)
;   triple is set, -1 on a firmware error. Absent = (NULL, 0, 0). A variable
;   under the name that is not exactly NV|BS, or is larger than a record, was
;   not written by this module: it is deleted and the slot is absent (still
;   absent, flagged stuck, when the firmware refuses the delete).
ows_read_slot:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    and  rsp, -16
    sub  rsp, 48
    mov  ebx, edi
    mov  r12, [rel runtime_services]
    lea  r10, [rel ows_slot_ptr]
    mov  qword [r10 + rbx*8], 0
    lea  r10, [rel ows_slot_size]
    mov  qword [r10 + rbx*8], 0
    lea  r10, [rel ows_slot_attrs]
    mov  dword [r10 + rbx*4], 0
    mov  qword [rel ows_io_size], OWS_REC_SIZE
    mov  dword [rel ows_io_attrs], 0
    lea  rcx, [rel ows_name0]
    test ebx, ebx
    jz   .named
    lea  rcx, [rel ows_name1]
.named:
    lea  rdx, [rel prin_record_guid]
    lea  r8, [rel ows_io_attrs]
    lea  r9, [rel ows_io_size]
    mov  rax, rbx
    shl  rax, 9                         ; * OWS_REC_SIZE
    lea  r10, [rel ows_slot_buf]
    add  rax, r10
    mov  [rsp + 32], rax
    call [r12 + OWS_RT_GETVAR]
    test rax, rax
    jz   .found
    mov  rdx, OWS_EFI_NOT_FOUND
    cmp  rax, rdx
    je   .ok                            ; genuinely absent
    mov  rdx, OWS_EFI_BUFFER_TOO_SMALL
    cmp  rax, rdx
    je   .foreign                       ; never ours: we write exactly 512 B
    jmp  .bad                           ; a device error decides nothing
.found:
    cmp  dword [rel ows_io_attrs], OWS_REC_ATTRS
    jne  .foreign                       ; RT-visible (or other): planted, never trusted
    mov  rax, rbx
    shl  rax, 9
    lea  r10, [rel ows_slot_buf]
    add  rax, r10
    lea  r10, [rel ows_slot_ptr]
    mov  [r10 + rbx*8], rax
    mov  rax, [rel ows_io_size]
    lea  r10, [rel ows_slot_size]
    mov  [r10 + rbx*8], rax             ; a short NV|BS copy is ours but torn: validate refuses it
    lea  r10, [rel ows_slot_attrs]
    mov  dword [r10 + rbx*4], OWS_REC_ATTRS
    jmp  .ok
.foreign:
    cmp  byte [rel ows_j_raw], 1
    je   .bad                           ; recovery preserves foreign/oversized estate
    mov  eax, 1
    mov  ecx, ebx
    shl  eax, cl
    or   [rel ows_planted], al
    lea  rdi, [rel ows_name0]
    test ebx, ebx
    jz   .delete
    lea  rdi, [rel ows_name1]
.delete:
    mov  esi, [rel ows_io_attrs]        ; 0 when GetVariable reported none (oversized)
    call ows_delete
    test eax, eax
    jz   .ok
    mov  eax, 0x10                      ; undeletable: stays absent and untrusted, flagged stuck
    mov  ecx, ebx
    shl  eax, cl
    or   [rel ows_planted], al
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    lea  rsp, [rbp - 16]
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ows_publish_selected — ows_generation / ows_summary from the selected slot.
ows_publish_selected:
    movzx eax, byte [rel ows_selected]
    lea  rdx, [rel ows_slot_ptr]
    mov  rax, [rdx + rax*8]
    mov  rdx, [rax + OWR_GEN]
    mov  [rel ows_generation], rdx
    mov  edx, [rax + OWR_SUMMARY]
    mov  [rel ows_summary], edx
    ; replay_floor_preebs reads this after the buffers are wiped (DC4)
    test dword [rax + OWR_FLAGS], OWR_FLOOR_SEEDED
    setnz byte [rel ows_floor_seeded]
    jmp  ows_handoff_capture

; ows_handoff_capture(RAX = the committed record) — S1b-2c: ows_local and the
;   password hand-off follow the committed record (a later applied stage
;   replaces what the selected slot set). Clobbers RCX/RSI/RDI.
ows_handoff_capture:
    call owner_password_discard
    cmp  word [rax + 4], OWR_VERSION_Z  ; S1b-2c-0: only a Z-bound record can be STORE authority
    sete byte [rel ows_zbound]
    test dword [rax + OWR_FLAGS], OWR_LOCAL
    setnz byte [rel ows_local]
    jz   .out
    cld
    mov  ecx, [rax + OWR_ITERATIONS]
    mov  [rel ows_pw_handoff + OWS_PW_ITER], ecx
    lea  rsi, [rax + OWR_SALT]          ; OWR_SALT and OWR_VERIFIER are contiguous (324 + 16 = 340)
    lea  rdi, [rel ows_pw_handoff + OWS_PW_SALT]
    mov  ecx, OWS_PW_LEN - OWS_PW_SALT
    rep  movsb
    mov  byte [rel ows_pw_ready], 1
.out:
    ret

; owner_password_take(RDI = OWS_PW_LEN-byte destination) -> EAX 1 when the
;   committed record carries OWR_LOCAL and this boot still holds its hand-off
;   (copied, then zeroed: at most once), else 0 with the destination untouched.
owner_password_take:
    xor  eax, eax
    cmp  byte [rel ows_pw_ready], 1
    jne  .out
    push rdi
    cld
    lea  rsi, [rel ows_pw_handoff]
    mov  ecx, OWS_PW_LEN
    rep  movsb
    pop  rdi
    call owner_password_discard
    mov  eax, 1
.out:
    ret

; owner_password_discard — zeroes the hand-off whether or not it was taken.
;   Preserves every register but flags.
owner_password_discard:
    push rdi
    push rcx
    push rax
    cld
    lea  rdi, [rel ows_pw_handoff]
    xor  eax, eax
    mov  ecx, OWS_PW_LEN
    rep  stosb
    mov  byte [rel ows_pw_ready], 0
    pop  rax
    pop  rcx
    pop  rdi
    ret

; ows_stage_decide — step 3. Sets ows_stage; on an applied stage also
;   ows_state/ows_selected/ows_generation/ows_summary.
ows_stage_decide:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    and  rsp, -16
    sub  rsp, 48
    mov  r12, [rel runtime_services]
    ; Only a validated base or proven absence anchors a stage, and only with
    ; Z is there a name: otherwise nothing is read and any stage is untouched.
    call ows_name_current
    test eax, eax
    jz   .unnamed
    mov  qword [rel ows_io_size], OWS_STAGE_SIZE
    mov  dword [rel ows_io_attrs], 0
    lea  rcx, [rel ows_stage_name]
    lea  rdx, [rel prin_record_guid]
    lea  r8, [rel ows_io_attrs]
    lea  r9, [rel ows_io_size]
    lea  rax, [rel ows_stage_buf]
    mov  [rsp + 32], rax
    call [r12 + OWS_RT_GETVAR]
    mov  edx, [rel ows_io_attrs]
    mov  [rel ows_stage_attrs], edx     ; the commit read-back reuses ows_io_attrs
    test rax, rax
    jz   .present
    mov  rdx, OWS_EFI_NOT_FOUND
    cmp  rax, rdx
    je   .none
    mov  rdx, OWS_EFI_BUFFER_TOO_SMALL
    cmp  rax, rdx
    je   .refuse                        ; oversized: never a stage
    mov  byte [rel ows_stage], OWS_STG_FAILED
    jmp  .out
.none:
    mov  byte [rel ows_stage], OWS_STG_NONE
    jmp  .out
.unnamed:
    mov  byte [rel ows_stage], OWS_STG_UNNAMED
    jmp  .out
.present:
    lea  rdi, [rel ows_stage_info]
    mov  esi, ows_stage_info.len
    lea  rdx, [rel ows_stage_key]
    call owner_stage_key_hkdf
    test eax, eax
    jz   .kept                          ; no Z this boot: cannot judge, keep it
    xor  r13d, r13d                     ; base pointer (NULL = proven absence)
    xor  r14d, r14d                     ; base size
    cmp  byte [rel ows_state], OWS_LOADED
    jne  .validate
    movzx eax, byte [rel ows_selected]
    lea  rdx, [rel ows_slot_ptr]
    mov  r13, [rdx + rax*8]
    mov  r14d, OWS_REC_SIZE
.validate:
    lea  rdi, [rel ows_stage_buf]
    mov  rsi, [rel ows_io_size]
    mov  edx, [rel ows_io_attrs]
    mov  rcx, r13
    mov  r8, r14
    lea  r9, [rel ows_stage_key]
    call owner_stage_validate
    mov  ebx, eax
    call ows_wipe_stage_key
    test ebx, ebx
    jnz  .refuse
    mov  rdi, r13
    lea  rsi, [rel ows_stage_buf + OWS_STAGE_BODY]
    call owner_change_needs_confirmation
    test eax, eax
    jz   .apply
    cmp  eax, 1
    jne  .refuse
    mov  byte [rel ows_stage], OWS_STG_CONFIRM
    jmp  .delete
.apply:
    ; the inactive slot: the other one when loaded; slot 0 when unowned, slot 1
    ; if slot 0 is stuck. A stuck target is never written (srcreview S1b F1).
    xor  ebx, ebx
    cmp  byte [rel ows_state], OWS_LOADED
    jne  .unowned_target
    movzx ebx, byte [rel ows_selected]
    xor  ebx, 1
    jmp  .target
.unowned_target:
    test byte [rel ows_planted], 0x10
    jz   .target
    mov  ebx, 1
.target:
    mov  eax, 0x10
    mov  ecx, ebx
    shl  eax, cl
    test [rel ows_planted], al
    jnz  .apply_failed
.write:
    ; Preserve the ORIGINAL authenticated stage before version/CRC changes.
    cld
    lea  rsi, [rel ows_stage_buf]
    lea  rdi, [rel ows_j_buf + 704]
    mov  ecx, OWS_STAGE_SIZE
    rep  movsb
    mov  rdi, r13                       ; the base (NULL = proven absence)
    call ows_stage_version              ; Z4: the result's version is decided here, never by the body
    test r13, r13
    jz   .ordinary_commit
    cmp  word [r13 + 4], OWR_VERSION
    jne  .ordinary_commit
    cmp  word [rel ows_stage_buf + OWS_STAGE_BODY + 4], OWR_VERSION_Z
    jne  .ordinary_commit
    call ows_j_create                    ; validated v1 -> canonical v2 only
    test eax, eax
    jz   .out
    call ows_j_lock
    jmp  .out
.ordinary_commit:
    mov  edi, ebx
    lea  rsi, [rel ows_stage_buf + OWS_STAGE_BODY]
    call ows_commit_slot
    test eax, eax
    jnz  .apply_failed
    lea  rax, [rel ows_stage_buf + OWS_STAGE_BODY]
    lea  rdx, [rel ows_slot_ptr]
    mov  [rdx + rbx*8], rax             ; the committed record, for ows_mirror
    mov  [rel ows_selected], bl
    mov  byte [rel ows_state], OWS_LOADED
    mov  rax, [rel ows_stage_buf + OWS_STAGE_BODY + OWR_GEN]
    mov  [rel ows_generation], rax
    mov  eax, [rel ows_stage_buf + OWS_STAGE_BODY + OWR_SUMMARY]
    mov  [rel ows_summary], eax
    test dword [rel ows_stage_buf + OWS_STAGE_BODY + OWR_FLAGS], OWR_FLOOR_SEEDED
    setnz byte [rel ows_floor_seeded]
    lea  rax, [rel ows_stage_buf + OWS_STAGE_BODY]
    call ows_handoff_capture
    mov  byte [rel ows_stage], OWS_STG_APPLIED
    jmp  .delete
.apply_failed:
    mov  byte [rel ows_stage], OWS_STG_FAILED  ; the stage stays: the next boot re-applies it
    jmp  .out
.kept:
    mov  byte [rel ows_stage], OWS_STG_KEPT
    jmp  .out
.refuse:
    mov  byte [rel ows_stage], OWS_STG_REFUSED
.delete:
    lea  rdi, [rel ows_stage_name]
    mov  esi, [rel ows_stage_attrs]
    call ows_delete
    test eax, eax
    jz   .out
    or   byte [rel ows_planted], 0x40   ; stuck stage (srcreview N2): blocks every change under this name
    cmp  byte [rel ows_stage], OWS_STG_APPLIED
    je   .out                           ; the applied generation already moved the name
    call ows_rotate
.out:
    lea  rsp, [rbp - 32]
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ows_stage_version(RDI = base record, NULL for proven absence) — srcreview Z4
;   with root's OWR_VERSION bump (11:25:44): sets the staged body's version and
;   CRC before the commit. OWR_VERSION_Z (2) says "the LOCAL verifier, if any,
;   was set by a Z-verified stage": the result has no LOCAL, or it is a first
;   setup, or the base had no LOCAL, or the base is already v2, or the stage
;   changed the ITERATIONS/SALT/VERIFIER block. Otherwise (a v1 base whose LOCAL
;   block the stage kept) the result stays v1, so a non-LOCAL change never
;   promotes a pre-Z verifier. The body's own version is ignored. A rotation
;   (3a) and the slot copy (3b) copy the record and keep its version.
ows_stage_version:
    push rbx
    lea  rbx, [rel ows_stage_buf + OWS_STAGE_BODY]
    mov  word [rbx + 4], OWR_VERSION_Z
    test dword [rbx + OWR_FLAGS], OWR_LOCAL
    jz   .crc
    test rdi, rdi
    jz   .crc
    test dword [rdi + OWR_FLAGS], OWR_LOCAL
    jz   .crc
    cmp  word [rdi + 4], OWR_VERSION_Z
    je   .crc
    lea  rsi, [rdi + OWR_ITERATIONS]
    lea  rdi, [rbx + OWR_ITERATIONS]
    mov  ecx, OWR_PW_BLOCK_LEN
    cld
    repe cmpsb
    jne  .crc
    mov  word [rbx + 4], OWR_VERSION
.crc:
    mov  rdi, rbx
    mov  esi, OWR_CRC
    call pbm_crc32
    mov  [rbx + OWR_CRC], eax
    pop  rbx
    ret

; ows_name_current -> EAX 1 and ows_stage_name = the stage name for
;   ows_generation (step 3), when the store is LOADED or UNOWNED and this boot
;   holds Z. EAX 0 and an empty name otherwise. gen is only ever the committed,
;   verified record's (ows_publish_selected, an applied or rotated commit), or
;   0 for proven absence: never a stage's or any RT-visible variable's.
;   Clobbers RAX, RCX, RDX, RSI, RDI, R8-R11.
ows_name_current:
    xor  eax, eax
    mov  word [rel ows_stage_name], 0
    cmp  byte [rel ows_state], OWS_LOADED
    je   .derive
    cmp  byte [rel ows_state], OWS_UNOWNED
    jne  .out
.derive:
    mov  rdi, [rel ows_generation]
    jmp  ows_name_gen
.out:
    ret

; ows_name_gen(RDI = generation) -> EAX 1 and ows_stage_name for it, or EAX 0
;   and an empty name when this boot holds no Z. Same clobbers.
ows_name_gen:
    push rbx
    mov  rbx, rdi
    mov  word [rel ows_stage_name], 0
    cld
    lea  rsi, [rel ows_name_label]
    lea  rdi, [rel ows_name_info]
    mov  ecx, ows_name_label.len
    rep  movsb
    mov  [rdi], rbx
    xor  ebx, ebx
    lea  rdi, [rel ows_name_info]
    mov  esi, ows_name_label.len + 8
    lea  rdx, [rel ows_stage_key]
    call owner_stage_key_hkdf
    test eax, eax
    jz   .wipe                          ; no Z: no name
    lea  rsi, [rel ows_stage_prefix]
    lea  rdi, [rel ows_stage_name]
    mov  ecx, ows_stage_prefix.len
    rep  movsb
    lea  rsi, [rel ows_stage_key]
    lea  r8, [rel ows_hex]
    mov  ecx, 16
.hex:
    movzx eax, byte [rsi]
    mov  edx, eax
    shr  eax, 4
    and  edx, 15
    movzx eax, byte [r8 + rax]
    movzx edx, byte [r8 + rdx]
    mov  [rdi], ax
    mov  [rdi + 2], dx
    add  rdi, 4
    inc  rsi
    dec  ecx
    jnz  .hex
    mov  word [rdi], 0
    mov  ebx, 1
.wipe:
    call ows_wipe_stage_key
    mov  eax, ebx
    pop  rbx
    ret

; ows_clean_previous — step 2b. LOADED at generation g >= 1 (gen 0 has no
;   predecessor): GetVariable(name(g - 1)); exactly NV|BS|RT is deleted (its
;   result not judged), anything else and every error is left alone.
ows_clean_previous:
    cmp  byte [rel ows_state], OWS_LOADED
    jne  .out
    push rbx
    push r12
    sub  rsp, 40
    mov  r12, [rel runtime_services]
    mov  rdi, [rel ows_generation]
    dec  rdi
    call ows_name_gen
    test eax, eax
    jz   .done
    mov  qword [rel ows_io_size], OWS_STAGE_SIZE
    mov  dword [rel ows_io_attrs], 0
    lea  rcx, [rel ows_stage_name]
    lea  rdx, [rel prin_record_guid]
    lea  r8, [rel ows_io_attrs]
    lea  r9, [rel ows_io_size]
    lea  rax, [rel ows_stage_buf]
    mov  [rsp + 32], rax
    call [r12 + OWS_RT_GETVAR]
    test rax, rax
    jnz  .done
    cmp  dword [rel ows_io_attrs], OWS_ATTRS
    jne  .done                          ; not a stage we wrote: an authenticated plant stays
    lea  rdi, [rel ows_stage_name]
    mov  esi, OWS_ATTRS
    call ows_delete
.done:
    add  rsp, 40
    pop  r12
    pop  rbx
.out:
    ret

; ows_rotate — step 3a (root A5 16:57:58 (b)/(e)). Called once per pass, only
;   after a stuck delete of a stage that was NOT applied. LOADED: copies the
;   committed record to the stage buffer's body, sets generation + 1 and the
;   CRC, and commits it to the inactive slot (never a stuck one) with the usual
;   read-back. On success the copy is the committed record (bit 7). A refused
;   or uncertain commit leaves the generation, so the name never names
;   different content. The record's credentials and summary are unchanged.
ows_rotate:
    cmp  byte [rel ows_state], OWS_LOADED
    jne  .out
    push rbx
    push r12
    sub  rsp, 8
    movzx ebx, byte [rel ows_selected]
    lea  rdx, [rel ows_slot_ptr]
    mov  rsi, [rdx + rbx*8]             ; the committed record
    xor  ebx, 1                         ; the inactive slot
    mov  eax, 0x10
    mov  ecx, ebx
    shl  eax, cl
    test [rel ows_planted], al
    jnz  .done                          ; stuck: never written
    mov  r12, [rsi + OWR_GEN]
    add  r12, 1
    jz   .done                          ; a generation never wraps
    cld
    lea  rdi, [rel ows_stage_buf + OWS_STAGE_BODY]
    mov  ecx, OWS_REC_SIZE
    rep  movsb
    mov  [rel ows_stage_buf + OWS_STAGE_BODY + OWR_GEN], r12
    lea  rdi, [rel ows_stage_buf + OWS_STAGE_BODY]
    mov  esi, OWR_CRC
    call pbm_crc32
    mov  [rel ows_stage_buf + OWS_STAGE_BODY + OWR_CRC], eax
    mov  edi, ebx
    lea  rsi, [rel ows_stage_buf + OWS_STAGE_BODY]
    call ows_commit_slot
    test eax, eax
    jnz  .done
    mov  [rel ows_selected], bl         ; (the other slot keeps the old record: ows_mirror has nothing to do)
    mov  [rel ows_generation], r12
    or   byte [rel ows_planted], 0x80   ; the stage name rotated this boot
.done:
    add  rsp, 8
    pop  r12
    pop  rbx
.out:
    ret

; ows_commit_slot(EDI = 0/1, RSI = 512-byte record) -> EAX 0 when the record is
;   stored under that slot as NV|BS and reads back byte-exact with exactly
;   those attributes.
ows_commit_slot:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    and  rsp, -16
    sub  rsp, 48
    mov  r13, rsi
    mov  r12, [rel runtime_services]
    lea  rbx, [rel ows_name0]
    test edi, edi
    jz   .named
    lea  rbx, [rel ows_name1]
.named:
    lea  rdi, [rel prin_record_guid]
    mov  rsi, rbx
    xor  edx, edx                       ; SA_INTENT_IMPLICIT: PaOS-namespace -> NORMAL
    lea  rcx, [rel str_ows_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    mov  rcx, rbx
    lea  rdx, [rel prin_record_guid]
    mov  r8d, OWS_REC_ATTRS
    mov  r9d, OWS_REC_SIZE
    mov  [rsp + 32], r13
    call [r12 + 0x58]                   ; SetVariable (literal: test_nvram_setvariable_sites scans it)
    test rax, rax
    jnz  .bad
    mov  qword [rel ows_io_size], OWS_REC_SIZE
    mov  dword [rel ows_io_attrs], 0
    mov  rcx, rbx
    lea  rdx, [rel prin_record_guid]
    lea  r8, [rel ows_io_attrs]
    lea  r9, [rel ows_io_size]
    lea  rax, [rel ows_verify_buf]
    mov  [rsp + 32], rax
    call [r12 + OWS_RT_GETVAR]
    test rax, rax
    jnz  .bad
    cmp  dword [rel ows_io_attrs], OWS_REC_ATTRS
    jne  .bad
    cmp  qword [rel ows_io_size], OWS_REC_SIZE
    jne  .bad
    mov  rsi, r13
    lea  rdi, [rel ows_verify_buf]
    mov  ecx, OWS_REC_SIZE
    cld
    repe cmpsb
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    lea  rsp, [rbp - 24]
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ows_mirror — availability copy into genuine absence only. Rollback safety
; is provided by the authenticated journal barrier, never best-effort copying.
; Legacy mixed valid v1/v2 is locked before selection, not silently repaired.
ows_mirror:
    cmp  byte [rel ows_state], OWS_LOADED
    jne  .out
    movzx eax, byte [rel ows_selected]
    lea  rdx, [rel ows_slot_ptr]
    mov  rsi, [rdx + rax*8]             ; the committed record (a slot buffer, or the applied stage body)
    test rsi, rsi
    jz   .out
    mov  edi, eax
    xor  edi, 1
    mov  rcx, [rdx + rdi*8]
    test rcx, rcx
    jz   .take
    jmp  .out                           ; existing bounded bytes are preserved
.take:
    mov  eax, 0x10
    mov  ecx, edi
    shl  eax, cl
    test [rel ows_planted], al
    jnz  .out                           ; stuck: never written
    sub  rsp, 8
    call ows_commit_slot
    add  rsp, 8
.out:
    ret

; ows_delete(RDI = UCS-2 name, ESI = the attributes GetVariable reported, 0 if
;   none) -> EAX 0 when nothing is left under that name. DataSize 0 with
;   Attributes 0 deletes whatever attributes it had; pre-EBS that includes an
;   RT-visible one. Firmware that refuses a delete whose attributes differ
;   (srcreview S1b N4) gets one retry with the reported attributes. An
;   authenticated variable refuses both: it stays, and the caller flags it.
ows_delete:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    and  rsp, -16
    sub  rsp, 48
    mov  rbx, rdi
    mov  r13d, esi
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    lea  rdi, [rel prin_record_guid]
    mov  rsi, rbx
    xor  edx, edx
    lea  rcx, [rel str_ows_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    xor  r8d, r8d                       ; first: Attributes 0
.set:
    mov  rcx, rbx
    lea  rdx, [rel prin_record_guid]
    xor  r9d, r9d
    mov  qword [rsp + 32], 0
    call [r12 + 0x58]                   ; SetVariable (literal: test_nvram_setvariable_sites scans it)
    test rax, rax
    jz   .ok
    mov  rdx, OWS_EFI_NOT_FOUND
    cmp  rax, rdx
    je   .ok
    mov  r8d, r13d                      ; once more with the reported attributes,
    and  r8d, ~OWS_EFI_APPEND_WRITE     ;   minus APPEND_WRITE: with size 0 it is a no-op success (srcreview A1)
    xor  r13d, r13d
    test r8d, r8d
    jnz  .set
    jmp  .bad
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    lea  rsp, [rbp - 24]
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; F1 strict Z4, independently accepted design 9dbc265e / review1485b8c6.
; PRE-EBS ONLY. Each uncertainty stops this pass; no APPLIED until J absence.
OWS_J_SIZE equ 1344
OWS_J_MAC equ 1312
OWS_J_BASE equ 192
OWS_J_STAGE equ 704
OWS_J_CAPACITY equ 3392

; Clear every authority field on an uncertain prepared migration.
ows_j_lock:
    mov byte [rel ows_state], OWS_FAILED
    mov byte [rel ows_stage], OWS_STG_FAILED
    mov byte [rel ows_selected], 0xFF
    mov qword [rel ows_generation], 0
    mov dword [rel ows_summary], 0
    mov byte [rel ows_floor_seeded], 0
    mov byte [rel ows_local], 0
    mov byte [rel ows_zbound], 0
    mov word [rel ows_stage_name], 0
    jmp owner_password_discard

; Reject legacy mixed VALID versions before exposing authority or cleanup.
ows_legacy_mixed:
    push rbx
    push r12
    sub rsp, 8
    xor ebx, ebx
    xor r12d, r12d
.next:
    lea rax, [rel ows_slot_ptr]
    mov rdi, [rax + rbx*8]
    lea rax, [rel ows_slot_size]
    mov rsi, [rax + rbx*8]
    lea rax, [rel ows_slot_attrs]
    mov edx, [rax + rbx*4]
    call owner_record_validate
    test eax, eax
    jnz .advance
    lea rax, [rel ows_slot_ptr]
    mov rax, [rax + rbx*8]
    movzx ecx, word [rax + 4]
    bts r12d, ecx
.advance:
    inc ebx
    cmp ebx, 2
    jb .next
    xor eax, eax
    cmp r12d, 6
    sete al
    add rsp, 8
    pop r12
    pop rbx
    ret

; Read J into ows_j_buf, BEFORE ordinary reads. 0 absent, 1 completed, -1
; failure. A foreign/oversized/torn J is preserved and fails closed.
ows_j_entry:
    push rbp
    mov rbp, rsp
    push r12
    and rsp, -16
    sub rsp, 48
    mov r12, [rel runtime_services]
    mov qword [rel ows_io_size], OWS_J_SIZE
    mov dword [rel ows_io_attrs], 0
    lea rcx, [rel ows_j_name]
    lea rdx, [rel prin_record_guid]
    lea r8, [rel ows_io_attrs]
    lea r9, [rel ows_io_size]
    lea rax, [rel ows_j_buf]
    mov [rsp + 32], rax
    call [r12 + OWS_RT_GETVAR]
    mov rdx, OWS_EFI_NOT_FOUND
    cmp rax, rdx
    je .absent
    test rax, rax
    jnz .bad
    cmp qword [rel ows_io_size], OWS_J_SIZE
    jne .bad
    cmp dword [rel ows_io_attrs], OWS_REC_ATTRS
    jne .bad
    call ows_j_validate
    test eax, eax
    jnz .bad
    mov byte [rel ows_j_raw], 1
    xor edi, edi
    call ows_read_slot
    test eax, eax
    jnz .bad
    mov edi, 1
    call ows_read_slot
    test eax, eax
    jnz .bad
    call ows_j_classify
    test eax, eax
    jnz .bad
    call ows_j_run
    test eax, eax
    jnz .bad
    mov eax, 1
    jmp .out
.absent:
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    lea rsp, [rbp - 8]
    pop r12
    pop rbp
    ret

; RDI/RSI point to 32 bytes, EAX zero iff equal. Never early-exit on bytes.
ows_j_digest_diff:
    xor eax, eax
    xor ecx, ecx
.loop:
    movzx edx, byte [rdi + rcx]
    xor dl, [rsi + rcx]
    or eax, edx
    inc ecx
    cmp ecx, 32
    jb .loop
    ret

; Domain separated MAC over exact [0,1312). EAX 0/-1. Key never stored in J.
ows_j_mac:
    sub rsp, 8
    lea rdi, [rel ows_j_info]
    mov esi, ows_j_info.len
    lea rdx, [rel ows_j_key]
    call owner_stage_key_hkdf
    test eax, eax
    jz .bad
    lea rdi, [rel ows_j_digest]
    lea rsi, [rel ows_j_key]
    mov edx, 32
    lea rcx, [rel ows_j_buf]
    mov r8d, OWS_J_MAC
    call hmac_sha256
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 8
    ret

; J MAC first, then exact header/base/stage/policy/canonical target binding.
; Original stage is NEVER authenticated after its version has been changed.
ows_j_validate:
    push rbx
    push r12
    sub rsp, 8
    call ows_j_mac
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_j_digest]
    lea rsi, [rel ows_j_buf + OWS_J_MAC]
    call ows_j_digest_diff
    test eax, eax
    jnz .bad
    lea r12, [rel ows_j_buf]
    mov rax, 0x00314c4e4a574f50       ; "POWJNL1\0"
    cmp [r12], rax
    jne .bad
    cmp dword [r12 + 8], 1
    jne .bad
    cmp dword [r12 + 12], OWS_J_SIZE
    jne .bad
    cmp dword [r12 + 32], 1
    ja .bad
    cmp dword [r12 + 36], 0
    jne .bad
    cmp qword [r12 + 184], 0
    jne .bad
    lea rdi, [r12 + OWS_J_BASE]
    mov esi, OWS_REC_SIZE
    mov edx, OWS_REC_ATTRS
    call owner_record_validate
    test eax, eax
    jnz .bad
    cmp word [r12 + OWS_J_BASE + 4], OWR_VERSION
    jne .bad
    mov rax, [r12 + OWS_J_BASE + OWR_GEN]
    cmp rax, [r12 + 16]
    jne .bad
    add rax, 1
    jc .bad
    cmp rax, [r12 + 24]
    jne .bad
    lea rdi, [rel ows_j_digest]
    lea rsi, [r12 + OWS_J_BASE]
    mov edx, OWS_REC_SIZE
    call sha256_hash
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_j_digest]
    lea rsi, [r12 + 40]
    call ows_j_digest_diff
    test eax, eax
    jnz .bad
    ; Original selected slot MUST bind to exactly this embedded base.
    mov ebx, [r12 + 32]
    cmp dword [r12 + 168 + rbx*4], OWS_REC_SIZE
    jne .bad
    cmp dword [r12 + 176 + rbx*4], OWS_REC_ATTRS
    jne .bad
    shl ebx, 5
    lea rsi, [r12 + 104 + rbx]
    lea rdi, [rel ows_j_digest]
    call ows_j_digest_diff
    test eax, eax
    jnz .bad
    xor ebx, ebx
.meta:
    mov edx, [r12 + 168 + rbx*4]
    cmp edx, OWS_REC_SIZE
    ja .bad
    test edx, edx
    jz .empty
    cmp dword [r12 + 176 + rbx*4], OWS_REC_ATTRS
    jne .bad
    jmp .next
.empty:
    cmp dword [r12 + 176 + rbx*4], 0
    jne .bad
    lea rdi, [rel ows_j_digest]
    lea rsi, [r12 + OWS_J_BASE]       ; nonNULL for SHA256(empty)
    xor edx, edx
    call sha256_hash
    test eax, eax
    jnz .bad
    mov eax, ebx
    shl eax, 5
    lea rsi, [r12 + 104 + rax]
    lea rdi, [rel ows_j_digest]
    call ows_j_digest_diff
    test eax, eax
    jnz .bad
.next:
    inc ebx
    cmp ebx, 2
    jb .meta
    lea rdi, [rel ows_stage_info]
    mov esi, ows_stage_info.len
    lea rdx, [rel ows_stage_key]
    call owner_stage_key_hkdf
    test eax, eax
    jz .bad
    lea rdi, [r12 + OWS_J_STAGE]
    mov esi, OWS_STAGE_SIZE
    mov edx, OWS_ATTRS
    lea rcx, [r12 + OWS_J_BASE]
    mov r8d, OWS_REC_SIZE
    lea r9, [rel ows_stage_key]
    call owner_stage_validate
    mov ebx, eax
    call ows_wipe_stage_key
    test ebx, ebx
    jnz .bad
    lea rdi, [r12 + OWS_J_BASE]
    lea rsi, [r12 + OWS_J_STAGE + OWS_STAGE_BODY]
    call owner_change_needs_confirmation
    test eax, eax
    jnz .bad
    cld
    lea rsi, [r12 + OWS_J_STAGE]
    lea rdi, [rel ows_stage_buf]
    mov ecx, OWS_STAGE_SIZE
    rep movsb
    lea rdi, [r12 + OWS_J_BASE]
    call ows_stage_version
    cmp word [rel ows_stage_buf + OWS_STAGE_BODY + 4], OWR_VERSION_Z
    jne .bad
    cld
    lea rsi, [rel ows_stage_buf + OWS_STAGE_BODY]
    lea rdi, [rel ows_j_target]
    mov ecx, OWS_REC_SIZE
    rep movsb
    lea rdi, [rel ows_j_digest]
    lea rsi, [rel ows_j_target]
    mov edx, OWS_REC_SIZE
    call sha256_hash
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_j_digest]
    lea rsi, [r12 + 72]
    call ows_j_digest_diff
    test eax, eax
    jnz .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret

; Admit only exact target, exact validated original v1, or bounded invalid /
; absent NV|BS. A valid foreign/newer record and target+v1 are conflicts.
ows_j_classify:
    push rbx
    push r12
    sub rsp, 8
    mov byte [rel ows_j_targets], 0
    mov byte [rel ows_j_v1], 0
    xor ebx, ebx
.next:
    lea rax, [rel ows_slot_ptr]
    mov r12, [rax + rbx*8]
    test r12, r12
    jz .advance
    lea rax, [rel ows_slot_size]
    cmp qword [rax + rbx*8], OWS_REC_SIZE
    jne .advance                       ; raw read already bounded/attrs3
    mov rsi, r12
    lea rdi, [rel ows_j_target]
    mov ecx, OWS_REC_SIZE
    cld
    repe cmpsb
    jne .not_target
    mov eax, 1
    mov ecx, ebx
    shl eax, cl
    or [rel ows_j_targets], al
    jmp .advance
.not_target:
    mov rdi, r12
    mov esi, OWS_REC_SIZE
    mov edx, OWS_REC_ATTRS
    call owner_record_validate
    test eax, eax
    jnz .advance                       ; torn/invalid; valid J is sole recovery authority
    cmp word [r12 + 4], OWR_VERSION
    jne .bad
    lea rdi, [rel ows_j_digest]
    mov rsi, r12
    mov edx, OWS_REC_SIZE
    call sha256_hash
    test eax, eax
    jnz .bad
    lea r12, [rel ows_j_buf]
    cmp dword [r12 + 168 + rbx*4], OWS_REC_SIZE
    jne .bad
    cmp dword [r12 + 176 + rbx*4], OWS_REC_ATTRS
    jne .bad
    mov eax, ebx
    shl eax, 5
    lea rsi, [r12 + 104 + rax]
    lea rdi, [rel ows_j_digest]
    call ows_j_digest_diff
    test eax, eax
    jnz .bad
    mov eax, 1
    mov ecx, ebx
    shl eax, cl
    or [rel ows_j_v1], al
.advance:
    inc ebx
    cmp ebx, 2
    jb .next
    cmp byte [rel ows_j_targets], 0
    je .ok
    cmp byte [rel ows_j_v1], 0
    jne .bad                           ; impossible ordered progress: don't silently repair
.ok:
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret

; Build J from existing exact snapshots and the saved ORIGINAL stage.
; Called with R13=validated base; no source authority is published until P8.
ows_j_create:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    and rsp, -16
    sub rsp, 48
    test byte [rel ows_planted], 0x33
    jnz .bad                           ; no foreign/stuck slot participates
    mov r12, [rel runtime_services]
    cmp dword [r12 + 12], OWS_RT_QUERYVAR + 8  ; EFI_TABLE_HEADER.HeaderSize
    jb .bad
    cmp qword [r12 + OWS_RT_QUERYVAR], 0
    je .bad
    mov ecx, OWS_REC_ATTRS
    lea rdx, [rel ows_j_max_storage]
    lea r8, [rel ows_j_remaining]
    lea r9, [rel ows_j_max_size]
    call [r12 + OWS_RT_QUERYVAR]
    test rax, rax
    jnz .bad
    cmp qword [rel ows_j_max_size], OWS_J_SIZE
    jb .bad
    cmp qword [rel ows_j_remaining], OWS_J_CAPACITY
    jb .bad
    ; Preserve [704,1312) saved at entry to .write; zero only the header/base.
    cld
    xor eax, eax
    lea rdi, [rel ows_j_buf]
    mov ecx, OWS_J_STAGE
    rep stosb
    lea r12, [rel ows_j_buf]
    mov rax, 0x00314c4e4a574f50
    mov [r12], rax
    mov dword [r12 + 8], 1
    mov dword [r12 + 12], OWS_J_SIZE
    mov rax, [r13 + OWR_GEN]
    mov [r12 + 16], rax
    add rax, 1
    jc .bad
    mov [r12 + 24], rax
    movzx eax, byte [rel ows_selected]
    mov [r12 + 32], eax
    cld
    mov rsi, r13
    lea rdi, [r12 + OWS_J_BASE]
    mov ecx, OWS_REC_SIZE
    rep movsb
    lea rdi, [r12 + 40]
    mov rsi, r13
    mov edx, OWS_REC_SIZE
    call sha256_hash
    test eax, eax
    jnz .bad
    cld
    lea rsi, [rel ows_stage_buf + OWS_STAGE_BODY]
    lea rdi, [rel ows_j_target]
    mov ecx, OWS_REC_SIZE
    rep movsb
    lea rdi, [r12 + 72]
    lea rsi, [rel ows_j_target]
    mov edx, OWS_REC_SIZE
    call sha256_hash
    test eax, eax
    jnz .bad
    xor ebx, ebx
.snapshot:
    lea rax, [rel ows_slot_size]
    mov rdx, [rax + rbx*8]
    mov [r12 + 168 + rbx*4], edx
    lea rax, [rel ows_slot_attrs]
    mov eax, [rax + rbx*4]
    mov [r12 + 176 + rbx*4], eax
    mov eax, ebx
    shl eax, 5
    lea rdi, [r12 + 104 + rax]
    lea rax, [rel ows_slot_ptr]
    mov rsi, [rax + rbx*8]
    test rsi, rsi
    jnz .hash
    lea rsi, [r12 + OWS_J_BASE]        ; SHA256(empty)
.hash:
    call sha256_hash
    test eax, eax
    jnz .bad
    inc ebx
    cmp ebx, 2
    jb .snapshot
    call ows_j_mac
    test eax, eax
    jnz .bad
    cld
    lea rsi, [rel ows_j_digest]
    lea rdi, [r12 + OWS_J_MAC]
    mov ecx, 32
    rep movsb
    ; Common validator checks creation and recovery with identical rules.
    call ows_j_validate
    test eax, eax
    jnz .bad
    call ows_j_classify
    test eax, eax
    jnz .bad
    call ows_j_write                   ; P1 exact write/readback BEFORE ordinary changes
    test eax, eax
    jnz .bad
    call ows_j_run
    jmp .out
.bad:
    mov eax, -1
.out:
    lea rsp, [rbp - 16]
    pop r12
    pop rbx
    pop rbp
    ret

; P1 writes J through the storage gate and verifies every byte and attrs.
ows_j_write:
    push rbp
    mov rbp, rsp
    push r12
    and rsp, -16
    sub rsp, 48
    mov r12, [rel runtime_services]
    lea rdi, [rel prin_record_guid]
    lea rsi, [rel ows_j_name]
    xor edx, edx
    lea rcx, [rel str_ows_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz .bad
    lea rcx, [rel ows_j_name]
    lea rdx, [rel prin_record_guid]
    mov r8d, OWS_REC_ATTRS
    mov r9d, OWS_J_SIZE
    lea rax, [rel ows_j_buf]
    mov [rsp + 32], rax
    call [r12 + 0x58]
    test rax, rax
    jnz .bad
    mov qword [rel ows_io_size], OWS_J_SIZE
    mov dword [rel ows_io_attrs], 0
    lea rcx, [rel ows_j_name]
    lea rdx, [rel prin_record_guid]
    lea r8, [rel ows_io_attrs]
    lea r9, [rel ows_io_size]
    lea rax, [rel ows_j_verify]
    mov [rsp + 32], rax
    call [r12 + OWS_RT_GETVAR]
    test rax, rax
    jnz .bad
    cmp qword [rel ows_io_size], OWS_J_SIZE
    jne .bad
    cmp dword [rel ows_io_attrs], OWS_REC_ATTRS
    jne .bad
    cld
    lea rsi, [rel ows_j_buf]
    lea rdi, [rel ows_j_verify]
    mov ecx, OWS_J_SIZE
    repe cmpsb
    jne .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    lea rsp, [rbp - 8]
    pop r12
    pop rbp
    ret

; P2-P8. Classify the entire estate before entry. Idempotently preserve any
; already-exact target; otherwise B then A tombstones, re-read the barrier,
; A then B targets. Never delete ordinary slot names.
ows_j_run:
    push rbx
    push r12
    sub rsp, 8
    mov ebx, [rel ows_j_buf + 32]     ; A original selected
    lea r12, [rel ows_j_verify]       ; independent of commit_slot readback
    cld
    xor eax, eax
    mov rdi, r12
    mov ecx, OWS_REC_SIZE
    rep stosb
    mov dword [r12], OWR_MAGIC
    mov word [r12 + 4], 65535
    mov word [r12 + 6], OWS_REC_SIZE
    cmp byte [rel ows_j_targets], 0
    jne .targets
    mov edi, ebx
    xor edi, 1
    mov rsi, r12
    call ows_j_tombstone
    test eax, eax
    jnz .bad
    mov edi, ebx
    mov rsi, r12
    call ows_j_tombstone
    test eax, eax
    jnz .bad
    ; Fresh side-effect-free reads verify both exact tombstones BEFORE v2.
    mov byte [rel ows_j_raw], 1
    xor edi, edi
    call ows_read_slot
    test eax, eax
    jnz .bad
    mov edi, 1
    call ows_read_slot
    test eax, eax
    jnz .bad
    xor edi, edi
    call ows_j_is_tombstone
    test eax, eax
    jnz .bad
    mov edi, 1
    call ows_j_is_tombstone
    test eax, eax
    jnz .bad
.targets:
    mov eax, 1
    mov ecx, ebx
    shl eax, cl
    test [rel ows_j_targets], al
    jnz .target_b
    mov edi, ebx
    lea rsi, [rel ows_j_target]
    call ows_commit_slot
    test eax, eax
    jnz .bad
.target_b:
    xor ebx, 1
    mov eax, 1
    mov ecx, ebx
    shl eax, cl
    test [rel ows_j_targets], al
    jnz .cleanup
    mov edi, ebx
    lea rsi, [rel ows_j_target]
    call ows_commit_slot
    test eax, eax
    jnz .bad
.cleanup:
    call ows_j_cleanup_stage
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_j_name]
    mov esi, OWS_REC_ATTRS
    call ows_j_delete_once
    test eax, eax
    jnz .bad                           ; D-N1: may have removed J, still LOCK current pass
    ; P8: no earlier handoff/APPLIED/generation/summary publication.
    lea rax, [rel ows_j_target]
    mov [rel ows_slot_ptr], rax
    mov [rel ows_slot_ptr + 8], rax
    mov [rel ows_selected], bl          ; compatibility: other original slot
    mov byte [rel ows_state], OWS_LOADED
    call ows_publish_selected
    mov byte [rel ows_stage], OWS_STG_APPLIED
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret

; EDI=slot -> 0 iff exact nonempty invalid tombstone. No firmware side effect.
ows_j_is_tombstone:
    mov eax, edi
    lea rdx, [rel ows_slot_size]
    cmp qword [rdx + rax*8], OWS_REC_SIZE
    jne .bad
    lea rdx, [rel ows_slot_attrs]
    cmp dword [rdx + rax*4], OWS_REC_ATTRS
    jne .bad
    lea rdx, [rel ows_slot_ptr]
    mov rsi, [rdx + rax*8]
    test rsi, rsi
    jz .bad
    lea rdi, [rel ows_j_verify]
    mov ecx, OWS_REC_SIZE
    cld
    repe cmpsb
    jne .bad
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; Skip already-exact tombstone; commit readback is separate ows_verify_buf.
ows_j_tombstone:
    push rbx
    mov ebx, edi
    call ows_j_is_tombstone
    test eax, eax
    jz .out
    mov edi, ebx
    lea rsi, [rel ows_j_verify]
    call ows_commit_slot
.out:
    pop rbx
    ret

; P6: exact original S only. Missing is fine; foreign/replaced is preserved
; with diagnostic, never treated as an instruction. Read/delete errors STOP.
ows_j_cleanup_stage:
    push rbp
    mov rbp, rsp
    push r12
    and rsp, -16
    sub rsp, 48
    mov r12, [rel runtime_services]
    mov rdi, [rel ows_j_buf + 16]
    call ows_name_gen
    test eax, eax
    jz .bad
    mov qword [rel ows_io_size], OWS_STAGE_SIZE
    mov dword [rel ows_io_attrs], 0
    lea rcx, [rel ows_stage_name]
    lea rdx, [rel prin_record_guid]
    lea r8, [rel ows_io_attrs]
    lea r9, [rel ows_io_size]
    lea rax, [rel ows_j_verify]
    mov [rsp + 32], rax
    call [r12 + OWS_RT_GETVAR]
    mov rdx, OWS_EFI_NOT_FOUND
    cmp rax, rdx
    je .ok
    mov rdx, OWS_EFI_BUFFER_TOO_SMALL
    cmp rax, rdx
    je .foreign
    test rax, rax
    jnz .bad
    cmp dword [rel ows_io_attrs], OWS_ATTRS
    jne .foreign
    cmp qword [rel ows_io_size], OWS_STAGE_SIZE
    jne .foreign
    lea rsi, [rel ows_j_verify]
    lea rdi, [rel ows_j_buf + OWS_J_STAGE]
    mov ecx, OWS_STAGE_SIZE
    cld
    repe cmpsb
    jne .foreign
    lea rdi, [rel ows_stage_name]
    mov esi, OWS_ATTRS
    call ows_j_delete_once
    jmp .out
.foreign:
    or byte [rel ows_planted], 0x40
.ok:
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    lea rsp, [rbp - 8]
    pop r12
    pop rbp
    ret

; RDI=name ESI=canonical attrs. EXACTLY ONE SetVariable attempt plus verified
; NOT_FOUND. Any returned EFI error stops even if deletion actually happened;
; next boot J present resumes, genuine J absence classifies ordinary v2.
ows_j_delete_once:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    and rsp, -16
    sub rsp, 48
    mov rbx, rdi
    mov r13d, esi
    mov r12, [rel runtime_services]
    lea rdi, [rel prin_record_guid]
    mov rsi, rbx
    xor edx, edx
    lea rcx, [rel str_ows_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz .bad
    mov rcx, rbx
    lea rdx, [rel prin_record_guid]
    mov r8d, r13d
    xor r9d, r9d
    mov qword [rsp + 32], 0
    call [r12 + 0x58]
    test rax, rax
    jnz .bad
    mov qword [rel ows_io_size], OWS_J_SIZE
    mov dword [rel ows_io_attrs], 0
    mov rcx, rbx
    lea rdx, [rel prin_record_guid]
    lea r8, [rel ows_io_attrs]
    lea r9, [rel ows_io_size]
    lea rax, [rel ows_j_verify]
    mov [rsp + 32], rax
    call [r12 + OWS_RT_GETVAR]
    mov rdx, OWS_EFI_NOT_FOUND
    cmp rax, rdx
    jne .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    lea rsp, [rbp - 24]
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; Public-only APP verification handoff. The final selected record has passed
; owner_record_select/commit validation. Never expose a pending stage, a
; corrupt/ambiguous store or the compiled publisher key. Clear on every pass.
ows_owner_key_capture:
    mov  byte [rel ows_owner_key_ready], 0
    lea  rdi, [rel ows_owner_modulus]
    xor  eax, eax
    mov  ecx, 256
    cld
    rep  stosb
    cmp  byte [rel ows_state], OWS_LOADED
    jne  .out
    movzx eax, byte [rel ows_selected]
    cmp  eax, 1
    ja   .out
    lea  rdx, [rel ows_slot_ptr]
    mov  rsi, [rdx + rax*8]
    test rsi, rsi
    jz   .out
    test dword [rsi + OWR_FLAGS], OWR_KEY
    jz   .out
    lea  rsi, [rsi + OWR_MODULUS + 255]
    lea  rdi, [rel ows_owner_modulus]
    mov  ecx, 256
.reverse:
    mov  al, [rsi]
    mov  [rdi], al
    dec  rsi
    inc  rdi
    dec  ecx
    jnz  .reverse
    mov  byte [rel ows_owner_key_ready], 1
.out:
    ret

; owner_enrolled_modulus() -> RAX public RSA2048 little-endian bytes or NULL.
; No firmware I/O or mutation. Reset and uncertain boots retire this authority.
owner_enrolled_modulus:
    xor  eax, eax
    cmp  byte [rel reset_wipe_done], 0
    jne  .out
    cmp  byte [rel ows_state], OWS_LOADED
    jne  .out
    cmp  byte [rel ows_owner_key_ready], 1
    jne  .out
    lea  rax, [rel ows_owner_modulus]
.out:
    ret

; ows_wipe_stage_key — the derived stage key lives only across one validate.
ows_wipe_stage_key:
    push rdi
    push rcx
    push rax
    cld
    lea  rdi, [rel ows_stage_key]
    xor  eax, eax
    mov  ecx, 32
    rep  stosb
    pop  rax
    pop  rcx
    pop  rdi
    ret

; ows_wipe_buffers — DC4: no record, stage or read-back survives the pass.
ows_wipe_buffers:
    cld
    xor  eax, eax
    lea  rdi, [rel ows_slot_buf]
    mov  ecx, 2 * OWS_REC_SIZE
    rep  stosb
    lea  rdi, [rel ows_stage_buf]
    mov  ecx, OWS_STAGE_SIZE
    rep  stosb
    lea  rdi, [rel ows_verify_buf]
    mov  ecx, OWS_REC_SIZE
    rep  stosb
    mov  qword [rel ows_slot_ptr], 0
    mov  qword [rel ows_slot_ptr + 8], 0
    lea  rdi, [rel ows_j_buf]
    mov  ecx, OWS_J_SIZE
    rep  stosb
    lea  rdi, [rel ows_j_verify]
    mov  ecx, OWS_J_SIZE
    rep  stosb
    lea  rdi, [rel ows_j_target]
    mov  ecx, OWS_REC_SIZE
    rep  stosb
    lea  rdi, [rel ows_j_key]
    mov  ecx, 32
    rep  stosb
    lea  rdi, [rel ows_j_digest]
    mov  ecx, 32
    rep  stosb
    jmp  ows_wipe_stage_key

%include "core/abi/wdata.inc" ; WDATA_BSS_DEFER; standalone assemblies expand blocks in place
; Zero-initialised state with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER):
; owner_store_preebs sets every field at entry, so the zero image value is never read.
; c2a post-EBS writer, owned by sec/owner_store. Credential lock serializes
; all runtime calls. No caller gains authority by building/storing a stage.
; Raw Z is discarded pre-EBS; only the current stage MAC is retained.
ows_writer_reset:
    sub rsp, 8
    mov byte [rel ows_wr_ready], 0
    lea rdi, [rel ows_wr_base]
    xor esi, esi
    mov edx, 512 + 32 * 4
    call memset
    add rsp, 8
    jmp owner_writer_discard

ows_writer_capture:
    push rbx
    xor ebx, ebx
    cmp byte [rel ows_state], OWS_LOADED
    jne .unowned
    movzx eax, byte [rel ows_selected]
    cmp eax, 1
    ja .out
    lea rdx, [rel ows_slot_ptr]
    mov rbx, [rdx + rax*8]
    test rbx, rbx
    jz .out
    lea rdi, [rel ows_committed_hash]
    mov rsi, rbx
    mov edx, 512
    call sha256_hash
    test eax, eax
    jnz .out
    lea rdi, [rel ows_wr_base_hash]
    lea rsi, [rel ows_committed_hash]
    mov edx, 32
    call memcpy
    lea rdi, [rel ows_wr_base]
    mov rsi, rbx
    mov edx, 512
    call memcpy
    lea rdi, [rel ows_wr_base + OWR_ITERATIONS]
    xor esi, esi
    mov edx, OWR_PW_BLOCK_LEN
    call memset
    lea rdi, [rel ows_wr_base + OWR_FLEET_BLOCK]
    xor esi, esi
    mov edx, OWR_CRC - OWR_FLEET_BLOCK
    call memset
    test dword [rbx + OWR_FLAGS], OWR_FLEET
    jnz .out                             ; FLEET never reaches a ready writer
    jmp .guard
.unowned:
    cmp byte [rel ows_state], OWS_UNOWNED
    jne .out
    mov dword [rel ows_wr_base], OWR_MAGIC
    mov word [rel ows_wr_base + 4], OWR_VERSION_Z
    mov word [rel ows_wr_base + 6], OWR_SIZE
    lea rdi, [rel ows_wr_base_hash]
    lea rsi, [rel ows_wr_absent]
    mov edx, ows_wr_absent.len
    call sha256_hash
    test eax, eax
    jnz .out
.guard:
    test byte [rel ows_planted], 0x70
    jnz .out
    cmp byte [rel ows_stage], OWS_STG_KEPT
    je .out
    cmp byte [rel ows_stage], OWS_STG_FAILED
    je .out
    cmp word [rel ows_stage_name], 0
    je .out
    cmp qword [rel ows_generation], -1
    je .out
    lea rdi, [rel ows_wr_zero_hash]
    lea rsi, [rel ows_wr_base]
    mov edx, 512
    call sha256_hash
    test eax, eax
    jnz .out
    lea rdi, [rel ows_stage_info]
    mov esi, ows_stage_info.len
    lea rdx, [rel ows_wr_mac_key]
    call owner_stage_key_hkdf
    test eax, eax
    jz .out
    mov byte [rel ows_wr_ready], 1
.out:
    cmp byte [rel ows_wr_ready], 1
    je .return
    lea rdi, [rel ows_wr_mac_key]
    xor esi, esi
    mov edx, 32
    call memset
.return:
    pop rbx
    ret

; Common ready/runtime/wipe guard, rechecked at the actual mutation sites.
ows_writer_guard:
    cmp byte [rel ows_wr_ready], 1
    jne .bad
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .bad
    cmp byte [rel reset_wipe_done], 0
    jne .bad
    cmp qword [rel runtime_services], 0
    je .bad
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; RDI=pw52 ->0 prepared/-1. No firmware writes. Caller always discards scratch.
owner_stage_prepare:
    push rbx
    mov rbx, rdi
    call owner_writer_discard
    call ows_writer_guard
    test eax, eax
    jnz .bad
    test rbx, rbx
    jz .bad
    lea rdi, [rel ows_wr_digest]
    lea rsi, [rel ows_wr_base]
    mov edx, 512
    call sha256_hash
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_wr_digest]
    lea rsi, [rel ows_wr_zero_hash]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_wr_stage + OWS_BODY]
    lea rsi, [rel ows_wr_base]
    mov edx, 512
    call memcpy
    lea rdi, [rel ows_wr_stage + OWS_BODY + OWR_ITERATIONS]
    mov rsi, rbx
    mov edx, 52
    call memcpy
    mov rax, [rel ows_generation]
    mov [rel ows_wr_stage + OWS_BASE_GEN], rax
    add rax, 1
    jc .bad
    mov [rel ows_wr_stage + OWS_NEW_GEN], rax
    mov [rel ows_wr_stage + OWS_BODY + OWR_GEN], rax
    mov word [rel ows_wr_stage + OWS_BODY + 4], OWR_VERSION_Z
    or dword [rel ows_wr_stage + OWS_BODY + OWR_FLAGS], OWR_LOCAL
    mov dword [rel ows_wr_stage + OWS_BODY + OWR_SUMMARY], OWS_KIND_LOCAL
    lea rdi, [rel ows_wr_stage + OWS_BODY]
    mov esi, OWR_CRC
    call pbm_crc32
    mov [rel ows_wr_stage + OWS_BODY + OWR_CRC], eax
    lea rdi, [rel ows_wr_stage + OWS_BODY]
    mov esi, OWR_SIZE
    mov edx, OWR_ATTRS
    call owner_record_validate
    test eax, eax
    jnz .bad
    mov dword [rel ows_wr_stage], OWS_MAGIC
    mov word [rel ows_wr_stage + 4], OWS_VERSION
    mov word [rel ows_wr_stage + 6], OWS_SIZE
    mov dword [rel ows_wr_stage + OWS_KIND], OWS_KIND_LOCAL
    lea rdi, [rel ows_wr_stage + OWS_PREV_HASH]
    lea rsi, [rel ows_wr_base_hash]
    mov edx, 32
    call memcpy
    lea rdi, [rel ows_wr_stage]
    call ows_writer_mac
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_wr_stage + OWS_MAC]
    lea rsi, [rel ows_wr_digest]
    mov edx, 32
    call memcpy
    lea rdi, [rel ows_wr_target_hash]
    lea rsi, [rel ows_wr_stage + OWS_BODY]
    mov edx, 512
    call sha256_hash
    pop rbx
    ret
.bad:
    call owner_writer_discard
    mov eax, -1
    pop rbx
    ret

; RDI=stage608 -> MAC into digest, immediate per-call key wipe on every exit.
ows_writer_mac:
    push rbx
    mov rbx, rdi
    lea rdi, [rel ows_wr_call_key]
    lea rsi, [rel ows_wr_mac_key]
    mov edx, 32
    call memcpy
    lea rdi, [rel ows_wr_digest]
    lea rsi, [rel ows_wr_call_key]
    mov edx, 32
    mov rcx, rbx
    mov r8d, OWS_MAC
    call hmac_sha256
    mov ebx, eax
    lea rdi, [rel ows_wr_call_key]
    xor esi, esi
    mov edx, 32
    call memset
    mov eax, ebx
    pop rbx
    ret

; ->0 genuinely absent,1 exact current LOCAL stage (pending_hash filled),-1
; malformed/foreign/uncertain. The public sanitized base is protected by D2;
; real pre-EBS D1 is still the apply guard. No variable is overwritten here.
owner_stage_pending:
    push rbx
    call ows_writer_guard
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_stage_name]
    lea rsi, [rel ows_wr_io]
    mov edx, OWS_SIZE
    call owner_writer_read
    cmp eax, 1
    je .absent
    test eax, eax
    jnz .bad
    cmp qword [rel ows_wr_size], OWS_SIZE
    jne .bad
    cmp dword [rel ows_wr_attrs], OWS_ATTRS
    jne .bad
    cmp dword [rel ows_wr_io], OWS_MAGIC
    jne .bad
    cmp dword [rel ows_wr_io + 4], (OWS_SIZE << 16) | OWS_VERSION
    jne .bad
    cmp dword [rel ows_wr_io + OWS_KIND], OWS_KIND_LOCAL
    jne .bad
    cmp dword [rel ows_wr_io + 60], 0
    jne .bad
    mov rax, [rel ows_generation]
    cmp [rel ows_wr_io + OWS_BASE_GEN], rax
    jne .bad
    add rax, 1
    jc .bad
    cmp [rel ows_wr_io + OWS_NEW_GEN], rax
    jne .bad
    cmp [rel ows_wr_io + OWS_BODY + OWR_GEN], rax
    jne .bad
    cmp dword [rel ows_wr_io + OWS_BODY + OWR_SUMMARY], OWS_KIND_LOCAL
    jne .bad
    cmp word [rel ows_wr_io + OWS_BODY + 4], OWR_VERSION_Z
    jne .bad
    lea rdi, [rel ows_wr_io + OWS_PREV_HASH]
    lea rsi, [rel ows_wr_base_hash]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_wr_io + OWS_BODY]
    mov esi, OWR_SIZE
    mov edx, OWR_ATTRS
    call owner_record_validate
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_wr_io]
    call ows_writer_mac
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_wr_digest]
    lea rsi, [rel ows_wr_io + OWS_MAC]
    call ows_j_digest_diff
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_wr_pending_hash]
    lea rsi, [rel ows_wr_io + OWS_BODY]
    mov edx, 512
    call sha256_hash
    test eax, eax
    jnz .bad
    mov eax, 1
    jmp .out
.absent:
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    pop rbx
    ret

owner_stage_commit:
    sub rsp, 8
    call ows_writer_guard
    add rsp, 8
    test eax, eax
    jnz .bad
    lea rdi, [rel ows_stage_name]
    lea rsi, [rel ows_wr_stage]
    mov edx, OWS_SIZE
    jmp owner_writer_write
.bad:
    mov eax, -1
    ret

; Runtime bounded I/O, common Win64 frame and storage-access gate.
; READ: RDI=name,RSI=buffer,RDX=capacity ->0 present,1 NOT_FOUND,-1 error.
owner_writer_read:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    and rsp, -16
    sub rsp, 48
    mov rbx, rdi
    mov r13, rsi
    mov [rel ows_wr_size], rdx
    mov dword [rel ows_wr_attrs], 0
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .bad
    cmp byte [rel reset_wipe_done], 0
    jne .bad
    mov r12, [rel runtime_services]
    test r12, r12
    jz .bad
    mov rcx, rbx
    lea rdx, [rel prin_record_guid]
    lea r8, [rel ows_wr_attrs]
    lea r9, [rel ows_wr_size]
    mov [rsp + 32], r13
    call [r12 + OWS_RT_GETVAR]
    test rax, rax
    jz .out
    mov rdx, OWS_EFI_NOT_FOUND
    cmp rax, rdx
    jne .bad
    mov eax, 1
    jmp .out
.bad:
    mov eax, -1
.out:
    lea rsp, [rbp - 24]
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; WRITE RDI=name,RSI=body,RDX=size<=608 (0 deletes) ->0 exact readback/-1.
owner_writer_write:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    and rsp, -16
    sub rsp, 48
    mov rbx, rdi
    mov r13, rsi
    mov r14, rdx
    cmp r14, OWS_SIZE
    ja .bad
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .bad
    cmp byte [rel reset_wipe_done], 0
    jne .bad
    mov r12, [rel runtime_services]
    test r12, r12
    jz .bad
    call storage_access_request_intent
    mov edx, eax
    lea rdi, [rel prin_record_guid]
    mov rsi, rbx
    lea rcx, [rel ows_wr_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz .bad
    cmp byte [rel reset_wipe_done], 0
    jne .bad
    mov rcx, rbx
    lea rdx, [rel prin_record_guid]
    mov r8d, 7
    mov r9, r14
    mov [rsp + 32], r13
    call [r12 + 0x58]
    test rax, rax
    jnz .bad
    mov rdi, rbx
    lea rsi, [rel ows_wr_io]
    mov edx, OWS_SIZE
    call owner_writer_read
    test r14, r14
    jz .deleted
    test eax, eax
    jnz .bad
    cmp [rel ows_wr_size], r14
    jne .bad
    cmp dword [rel ows_wr_attrs], 7
    jne .bad
    lea rdi, [rel ows_wr_io]
    mov rsi, r13
    mov rdx, r14
    call memcmp
    test eax, eax
    jnz .bad
    xor eax, eax
    jmp .out
.deleted:
    cmp eax, 1
    jne .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    lea rsp, [rbp - 32]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

owner_writer_delete:
    xor esi, esi
    xor edx, edx
    jmp owner_writer_write

owner_writer_discard:
    lea rdi, [rel ows_wr_stage]
    xor esi, esi
    mov edx, 608 * 2 + 32 * 4
    jmp memset

%macro WDATA_BSS_sec_owner_writer 0
alignb 16
ows_wr_base:         resb 512             ; SENSITIVE, sanitized public fields only
ows_wr_base_hash:    resb 32              ; exact committed base lineage (nonsecret)
ows_wr_zero_hash:    resb 32              ; D2 sanitized-base integrity check
ows_committed_hash:  resb 32              ; W1 promotion anchor even when writer refused
ows_wr_mac_key:      resb 32              ; KEY_MATERIAL, retained only when ready
ows_wr_stage:        resb 608             ; KEY_MATERIAL, per-request next body/MAC
ows_wr_io:           resb 608             ; KEY_MATERIAL, bounded stage/wrap I/O
ows_wr_target_hash:  resb 32
ows_wr_pending_hash: resb 32
ows_wr_digest:       resb 32
ows_wr_call_key:     resb 32              ; per-call MAC copy, always immediately scrubbed
ows_wr_size:         resq 1
ows_wr_attrs:        resd 1
ows_wr_ready:        resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_owner_writer
ows_wr_absent: db "PaOS/owner/absent/v1"
.len equ $ - ows_wr_absent
ows_wr_tag: db "owner_stage_writer",0


%macro WDATA_BSS_sec_owner_store 0
alignb 8
ows_generation:   resq 1                ; the committed generation this boot (0 = none)
ows_io_size:      resq 1
ows_j_max_storage: resq 1
ows_j_remaining: resq 1
ows_j_max_size:   resq 1
ows_slot_ptr:     resq 2                ; owner_record_select triples (pointer, size, attrs)
ows_slot_size:    resq 2
ows_slot_attrs:   resd 2
ows_io_attrs:     resd 1
ows_stage_attrs:  resd 1                ; the stage's reported attributes, for its delete retry
ows_summary:      resd 1                ; the committed record's non-secret change kind
ows_state:        resb 1
ows_stage:        resb 1
ows_selected:     resb 1                ; the committed slot (0xFF = none)
ows_planted:      resb 1                ; bit 0/1: a foreign variable under slot 0/1 was seen (deleted unless stuck);
                                        ; bit 4/5: it could not be deleted (stuck: absent, never written);
                                        ; bit 6: a stage the firmware would not delete (stuck stage);
                                        ; bit 7: that stage's name was rotated away this boot (gen + 1)
ows_floor_seeded: resb 1                ; the committed record carries OWR_FLOOR_SEEDED (sec/replay_floor)
ows_local:        resb 1                ; the committed record carries OWR_LOCAL (S1b-2c; kept after EBS)
ows_zbound:       resb 1                ; it is OWR_VERSION_Z: its LOCAL block came from a Z-verified stage (kept after EBS)
ows_j_raw:        resb 1                ; preserve unclassified recovery estate
ows_j_targets:    resb 1                ; bitset of exact authenticated targets
ows_j_v1:         resb 1                ; bitset of validated original v1 records
ows_pw_ready:     resb 1                ; ows_pw_handoff holds the committed record's password fields
ows_owner_key_ready: resb 1            ; current validated KEY public handoff, never an enrollment path
alignb 16
ows_owner_modulus: resb 256            ; PUBLIC: selected enrolled RSA modulus, little-endian; no custody material
ows_pw_handoff:   resb OWS_PW_LEN       ; S1b-2c: iterations, salt, verifier until principal takes them
ows_slot_buf:     resb 2 * OWS_REC_SIZE ; both slots (verifier, key, fleet block while in use)
ows_stage_buf:    resb OWS_STAGE_SIZE   ; the pending stage while in use
ows_verify_buf:   resb OWS_REC_SIZE     ; the commit read-back
ows_j_buf:        resb OWS_J_SIZE       ; KEY_MATERIAL: authenticated oldbase/originalstage
ows_j_verify:     resb OWS_J_SIZE       ; KEY_MATERIAL: journal/cleanup readback, then tombstone
ows_j_target:     resb OWS_REC_SIZE     ; KEY_MATERIAL: canonical new owner
ows_j_key:        resb 32               ; KEY_MATERIAL: domain-separated HKDF(Z)
ows_j_digest:     resb 32               ; KEY_MATERIAL: SHA/MAC scratch
ows_stage_key:    resb 32               ; HKDF(Z) for one validate or one name, then zeroed
ows_name_info:    resb 32               ; "PaOS/owner/stage-name/v1" || gen_le64
ows_stage_name:   resw 47               ; CHAR16 "PaOSOwnerStage" + 32 hex + NUL (empty = none)
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_owner_store
align 2, db 0                           ; CHAR16 variable names (char16_align_check)
ows_j_name:
    dw 'P','a','O','S','O','w','n','e','r','M','i','g','r','a','t','i','o','n',0
ows_name0:
    dw 'P','a','O','S','O','w','n','e','r','0',0
ows_name1:
    dw 'P','a','O','S','O','w','n','e','r','1',0
ows_stage_prefix:
    dw 'P','a','O','S','O','w','n','e','r','S','t','a','g','e'
.len equ $ - ows_stage_prefix
ows_stage_info:   db "PaOS/owner/stage-z/v1"
.len equ $ - ows_stage_info
ows_name_label:   db "PaOS/owner/stage-name-z/v1"
.len equ $ - ows_name_label
ows_hex:          db "0123456789abcdef"
str_ows_nvg_tag:  db "owner_store_preebs",0
str_ows_state:    db "[PAOS64] owner store: state=",0
str_ows_slot:     db " slot=",0
str_ows_gen:      db " gen=",0
str_ows_summary:  db " summary=",0
str_ows_stage:    db " stage=",0
str_ows_planted:  db " planted=",0
str_ows_marker:   db " [sec.owner.preebs]",13,10,0

ows_j_info: db "PaOS/owner/migrate-journal/v1",0
    dw 'P','a','O','S','O','w','n','e','r','M','i','g','r','a','t','i','o','n',0
    db 0xb4,0xa9,0x68,0x72,0x8a,0x3f,0xa0,0x45,0x9f,0x8d,0x1b,0x73,0xe9,0xac,0x25,0x01
.len equ $ - ows_j_info
