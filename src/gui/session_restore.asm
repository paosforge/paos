;; MODULE gui/session_restore
;; LAYER 6
;; EXPORTS sess_recovery_console_title, session_ram_checkpoint_build, session_ram_checkpoint_export, session_ram_checkpoint_install, session_declare, session_restore, session_clear_fresh_windows, session_persist_selftest
;; IMPORTS gui/console_app, boot/serial, fs/blockdev, fs/storage_access, dev/blk/ahci, gui/chat_app, gui/window_mgmt, sec/principal, sec/session, svc/command
;; CAPS
;; OWNER saga:gui
; ============================================================================
; gui/session_restore.asm — C-1105 desktop_session_restore: Win11-style session
; persistence. The desktop REMEMBERS the last-opened user windows (title, x, y,
; w, h, state, z-order) in a compact manifest on the persistent block device, and
; RESTORES them after a reboot. Built on the C17 wm_* window TABLE (chat_app) + the
; 1064 WM verbs + the PROVEN 1107 cross-reboot persist path (raw-sector write to a
; reserved GPT-gap scratch LBA, temp-then-swap safe-write).
;
; WHY A RAW-SECTOR MANIFEST (ports 1107, not fat32_writefile): the 1107 hotpatch-
; persist already proves a bare-metal cross-reboot write->readback->replay using
; blk_write to a GPT-gap scratch sector (0x700/0x708). A session manifest is the same
; shape (a small fixed record read back at boot), so we reuse that proven seam UNCHANGED.
;
; WHICH DISK — ahci0 (Samsung 870), NOT nvme0: the two GPT-gap scratch LBAs 0x700/0x708
; are the ONLY sectors empirically proven reliably WRITABLE on this box's disks (the
; 1027b/1028 allowlist; the Intel nvme errors writes to un-preconditioned gap sectors
; like 0x710 — measured 0/15, while 0x700/0x708 are 24/24). hotpatch-persist owns
; nvme0's 0x700/0x708, so session takes the SAME two verified LBAs on the OTHER physical
; disk — ahci0 (the Samsung 870, which carries recovery Ubuntu; writes confined to its
; own verified GPT gap). Separate disk => zero collision with hotpatch. ahci0 writes to
; 0x700/0x708 measured 12/12 reliable on bare metal.
;
; SAFE-WRITE (temp-then-swap, the 1107 / 9374c2 defense): the new manifest is written
; to the TMP sector, read back, and required byte-equal BEFORE it is committed to the
; PRIMARY sector. A torn/failed write leaves the last-good PRIMARY manifest intact —
; a reboot mid-write can at worst drop the newest change, never destroy the session
; and never touch the bootable keep (only the two gap sectors are ever written).
;
; SELF-VALIDATING MANIFEST: magic "SESSMAN1" + present flag + window count + a byte
; checksum over the entries. Boot re-verifies magic+count+checksum before restoring —
; a torn write fails validation and the desktop starts empty (marker manifest.absent),
; never a crash or half-restore.
;
; THE un-fakeable grade is bare-metal (probe_desktop_session_restore.sh): open a
; window whose TITLE carries a RANDOM NONCE at RANDOM geometry, SESSSAVE, REBOOT (the
; uptime resets), and the restored WINLIST must contain the SAME nonce-titled window
; at the SAME x/y — a latch cannot know the nonce or geometry across a reboot; only
; real persistence can. session_persist_selftest gives the QEMU BUILD gate on the
; write+readback+re-parse code paths (throwaway nvme namespace); on the real disk the
; write is deferred to SESSSAVE + the supervised boot restore (same discipline as 1107).
;
; Verbs (registered through the ONE 1077 registry): WINOPEN (key=value: app title= x=
; y= w= h=), WINLIST (title+geometry per window — the probe's restore grade), WINCLOSE
; <title> (close by title), SESSSAVE (explicit flush), SESSINFO (n=<count> saved=<flag>).
; ============================================================================

; --- manifest sector layout (single 512B sector) ---------------------------
SESS_OFF_MAGIC   equ 0        ; 8 bytes  "SESSMAN1"
SESS_OFF_PRESENT equ 8        ; dd  1 = a session is present, 0 = none/cleared
SESS_OFF_COUNT   equ 12       ; dd  number of window entries (1..SESS_MAXWIN)
SESS_OFF_SUM     equ 16       ; dd  byte checksum over the entries region (torn-write guard)
SESS_OFF_PRINCIPAL equ 20     ; dd  bound owner (lab builds also admit SYSTEM)
SESS_OFF_ENTRIES equ 24       ; entries[] start here
SESS_ENTRY       equ 64       ; per-window record size
SESS_E_STATE     equ 0        ; dd  WM_VISIBLE / WM_MIN
SESS_E_X         equ 4        ; dd
SESS_E_Y         equ 8        ; dd
SESS_E_W         equ 12       ; dd
SESS_E_H         equ 16       ; dd
SESS_E_TITLE     equ 20       ; 40 bytes (matches WMX_TITLE_MAX), NUL-padded
SESS_MAXWIN      equ 5        ; ON-DISK record cap, independent of WM_MAX (G9 option a, ADMIN 2026-10-02): the record
                              ; is byte-unchanged; the walk below persists the FIRST 5 eligible slots in ascending
                              ; slot order (skip CHAT_SLOT; FRESH visible/minimized only); more open windows are not saved
SESS_SECTOR      equ 512
SESS_OWNED_SIZE  equ SESS_OFF_ENTRIES + SESS_MAXWIN * SESS_ENTRY ; bytes 0..343
; EQU symbols are assembler-time values, not preprocessor macros. A nonzero
; difference makes TIMES negative and fails the actual product assembly.
times -((SESS_OWNED_SIZE - DCB_RECORD_OFF) * (SESS_OWNED_SIZE - DCB_RECORD_OFF)) db 0

SESS_LBA_PRIMARY equ PERSIST_GAP_LBA_PRIMARY ; committed manifest  (ahci0 GPT-gap, 1028-verified writable)
SESS_LBA_TMP     equ PERSIST_GAP_LBA_TMP     ; temp-then-swap slot  (ahci0 GPT-gap, 1028-verified writable)
SESS_PERSIST_RETRY equ 6      ; bounded retries: a cold ahci port errors the first op, warms on retry

; ---------------------------------------------------------------------------
; low-level helpers
; ---------------------------------------------------------------------------

; sess_dev -> RAX = persistent block dev* ("ahci0" = the Samsung 870) or 0. Binds the
;   REAL disk BY NAME (blk_select would pick the volatile RAMBLK; nvme0's gap sectors
;   are hotpatch's). clobbers RAX,RCX,RDX,R8,R9.
sess_dev:
    lea  rdi, [rel str_sess_disk]
    mov  esi, 5
    call blk_find
    ret

; sess_storage_gate(RDI=first lba, RSI=count) -> RAX 0 permitted / -1 refused.
; Session save is an IMPLICIT (background/automatic) write: it may only touch
; storage PaOS provably owns (or QEMU test scratch). A raw GPT-gap write on a
; real disk is SENSITIVE (PETER 21:25) and is refused fail-closed — never
; redirected elsewhere. ROB-03: on the Dell/Lenovo ahci0 is the Windows disk.
sess_storage_gate:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    call sess_dev
    test rax, rax
    jz   .no
    mov  rdi, rax
    mov  rsi, r12
    mov  rdx, r13
    mov  ecx, SA_INTENT_IMPLICIT
    lea  r8, [rel str_sess_sa_caller]
    call storage_access_require
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    ret

; sess_write(RDI=lba, RSI=buf) -> RAX 0 ok / -1 err. The session owns only
; bytes 0..343; preserve contract-1054's authenticated tail at 344..511.
sess_write:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  rbx, rsi
    call persist_gap_lock_acquire
    call sess_dev
    test rax, rax
    jz   .err_locked
    mov  r13, rax
    mov  rdi, r13
    mov  rsi, r12
    mov  edx, 1
    lea  rcx, [rel sess_preserve]
    call blk_read
    test rax, rax
    jnz  .err_locked
    lea  rdi, [rel sess_preserve]
    mov  rsi, rbx
    mov  ecx, SESS_OWNED_SIZE
    cld
    rep  movsb
    mov  rdi, r13
    mov  rsi, r12
    mov  rdx, 1
    lea  rcx, [rel sess_preserve]
    call blk_write
    test rax, rax
    jnz  .err_locked
    mov  rdi, r13
    call blk_flush
    test rax, rax
    jnz  .err_locked
    xor  r13d, r13d
    jmp  .unlock
.err_locked:
    mov  r13, -1
.unlock:
    call persist_gap_lock_release
    mov  rax, r13
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; sess_read(RDI=lba, RSI=buf) -> RAX 0 ok / -1 err (1 sector).
sess_read:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  rbx, rsi
    call persist_gap_lock_acquire
    call sess_dev
    test rax, rax
    jz   .err_locked
    mov  rdi, rax
    mov  rsi, r12
    mov  rdx, 1
    mov  rcx, rbx
    call blk_read
    test rax, rax
    jnz  .err_locked
    xor  r13d, r13d
    jmp  .unlock
.err_locked:
    mov  r13, -1
.unlock:
    call persist_gap_lock_release
    mov  rax, r13
    pop  r13
    pop  r12
    pop  rbx
    ret

; sess_memeq(RDI=a, RSI=b, ECX=len) -> RAX 1 equal / 0 not. clobbers RAX,RCX,RDI,RSI,DL.
sess_memeq:
.l:
    test ecx, ecx
    jz   .eq
    mov  al, [rdi]
    mov  dl, [rsi]
    cmp  al, dl
    jne  .ne
    inc  rdi
    inc  rsi
    dec  ecx
    jmp  .l
.eq:
    mov  rax, 1
    ret
.ne:
    xor  eax, eax
    ret

; sess_checksum(RDI=ptr, ECX=nbytes) -> EAX = sum of bytes. clobbers EAX,ECX,EDX,RDI.
sess_checksum:
    xor  eax, eax
.l:
    test ecx, ecx
    jz   .d
    movzx edx, byte [rdi]
    add  eax, edx
    inc  rdi
    dec  ecx
    jmp  .l
.d:
    ret

; sess_streq_tok(RDI=title cstr, RSI=arg) -> RAX 1 if title == arg's first token
;   (arg token ends at space/NUL; title ends at NUL). clobbers RAX,RCX,RDI,RSI.
sess_streq_tok:
.l:
    mov  al, [rdi]                      ; title char
    mov  cl, [rsi]                      ; arg char
    test cl, cl
    jz   .argend
    cmp  cl, ' '
    je   .argend
    test al, al
    jz   .no                            ; title ended but arg continues
    cmp  al, cl
    jne  .no
    inc  rdi
    inc  rsi
    jmp  .l
.argend:
    test al, al                         ; arg token ended -> title must also end
    jz   .yes
.no:
    xor  eax, eax
    ret
.yes:
    mov  rax, 1
    ret

; ---------------------------------------------------------------------------
; session_manifest_valid(RSI=buf) -> RAX = count (1..SESS_MAXWIN) if the sector is a
;   valid session manifest (magic + present + count-sane + checksum), else 0.
; ---------------------------------------------------------------------------
session_manifest_valid:
    push rbx
    push r8
    mov  rbx, rsi
    cmp  dword [rbx + SESS_OFF_PRESENT], 1
    jne  .no
    mov  rdi, rbx
    lea  rsi, [rel str_sess_magic]
    mov  ecx, 8
    call sess_memeq
    cmp  rax, 1
    jne  .no
    mov  r8d, [rbx + SESS_OFF_COUNT]
    cmp  r8d, 1
    jb   .no
    cmp  r8d, SESS_MAXWIN
    ja   .no
    cmp  dword [rbx + SESS_OFF_PRINCIPAL], PRIN_OWNER
    je   .identity_ok
%if PAOS_PUBLICITY_LAB_PROFILE
    cmp  dword [rbx + SESS_OFF_PRINCIPAL], PRIN_SYSTEM
    je   .identity_ok
%endif
    jmp  .no
.identity_ok:
    mov  eax, r8d
    imul eax, SESS_ENTRY
    mov  ecx, eax
    lea  rdi, [rbx + SESS_OFF_ENTRIES]
    call sess_checksum
    cmp  eax, [rbx + SESS_OFF_SUM]
    jne  .no
    mov  eax, r8d
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r8
    pop  rbx
    ret

; session_manifest_build -> RAX 0 when sess_manifest holds a fresh, checksummed manifest of
;   the live USER windows (any count), -1 when the identity is refused (nothing usable
;   built). No storage is touched. RCQ-27 M1-3 C1: shared by the durable save
;   (session_persist) and the M1 checkpoint (session_ram_checkpoint_build), so SLEEP
;   no longer depends on the legacy session-sector write.
session_manifest_build:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; zero the build buffer (cld: DF may be set by a prior handler; rep stosb MUST
    ;   run forward or it corrupts memory before the buffer — the SESSSAVE-cold bug)
    lea  rdi, [rel sess_manifest]
    xor  eax, eax
    mov  ecx, SESS_OWNED_SIZE
    cld
    rep  stosb
    ; magic
    mov  rax, [rel str_sess_magic]
    mov  [rel sess_manifest + SESS_OFF_MAGIC], rax
    ; A durable workspace is identity-bound data. Refuse writes while locked
    ; or under the machine SYSTEM principal rather than producing an orphaned
    ; document that a later user session could inherit.
    call principal_current
    cmp  rax, PRIN_OWNER
    je   .identity_accepted
%if PAOS_PUBLICITY_LAB_PROFILE
    cmp  rax, PRIN_SYSTEM
    je   .identity_accepted
%endif
    jmp  .identity_refused
.identity_accepted:
    mov  [rel sess_manifest + SESS_OFF_PRINCIPAL], eax
    ; walk user slots
    xor  r13d, r13d                     ; count
    lea  r15, [rel sess_manifest + SESS_OFF_ENTRIES]
    xor  r12d, r12d
.slot:
    cmp  r12d, WM_MAX
    jae  .slotdone
    cmp  r13d, SESS_MAXWIN
    jae  .slotdone
    cmp  r12d, CHAT_SLOT
    je   .slotnext
    lea  rax, [rel wm_restore_class]
    cmp  byte [rax + r12], WM_RESTORE_FRESH
    jne  .slotnext
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .take
    cmp  eax, WM_MIN
    je   .take
    jmp  .slotnext
.take:
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    mov  [r15 + SESS_E_STATE], eax
    lea  rax, [rel wm_x]
    mov  eax, [rax + r12*4]
    mov  [r15 + SESS_E_X], eax
    lea  rax, [rel wm_y]
    mov  eax, [rax + r12*4]
    mov  [r15 + SESS_E_Y], eax
    lea  rax, [rel wm_w]
    mov  eax, [rax + r12*4]
    mov  [r15 + SESS_E_W], eax
    lea  rax, [rel wm_h]
    mov  eax, [rax + r12*4]
    mov  [r15 + SESS_E_H], eax
    ; title cstr -> entry title (<=39, NUL-padded; buffer already zeroed)
    lea  rax, [rel wm_title]
    mov  rsi, [rax + r12*8]
    test rsi, rsi
    jz   .titdone
    lea  rdi, [r15 + SESS_E_TITLE]
    mov  ecx, WMX_TITLE_MAX - 1
.titcp:
    test ecx, ecx
    jz   .titdone
    mov  al, [rsi]
    test al, al
    jz   .titdone
    mov  [rdi], al
    inc  rdi
    inc  rsi
    dec  ecx
    jmp  .titcp
.titdone:
    add  r15, SESS_ENTRY
    inc  r13d
.slotnext:
    inc  r12d
    jmp  .slot
.slotdone:
    mov  dword [rel sess_manifest + SESS_OFF_PRESENT], 1
    mov  [rel sess_manifest + SESS_OFF_COUNT], r13d
    mov  eax, r13d
    imul eax, SESS_ENTRY
    mov  ecx, eax
    lea  rdi, [rel sess_manifest + SESS_OFF_ENTRIES]
    call sess_checksum
    mov  [rel sess_manifest + SESS_OFF_SUM], eax
    xor  eax, eax
    jmp  .out
.identity_refused:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; session_persist -> RAX 0 ok / -1 err. Build a manifest from the live USER windows
;   (restore_class=fresh and VISIBLE/MIN) and write it temp-then-swap. Demo
;   windows are class=always and therefore never duplicated by session replay.
; ---------------------------------------------------------------------------
session_persist:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call session_manifest_build
    test rax, rax
    jnz  .identity_refused
    mov  r13d, [rel sess_manifest + SESS_OFF_COUNT]
    ; --- temp-then-swap: TMP write -> readback byte-equal -> PRIMARY commit ---
    ;   RETRIED: a COLD ahci port (no recent op to settle it — the SESSSAVE/WINCLOSE
    ;   path, vs WINOPEN which draws first) errors the first op; the ops themselves warm
    ;   the port so a retry succeeds (BLK verbs never see this — each is a separate cmd
    ;   with a network round-trip between). Bounded; content-safe (idempotent same-LBA
    ;   writes, PRIMARY only committed after a verified TMP round-trip).
    ; storage-access gate (ROB-03): refuse before any sector is touched. The built
    ;   manifest stays in sess_manifest so the lock path can keep its RAM checkpoint.
    mov  rdi, SESS_LBA_PRIMARY
    mov  esi, SESS_LBA_TMP - SESS_LBA_PRIMARY + 1
    call sess_storage_gate
    test rax, rax
    jnz  .storage_refused
    mov  r14d, SESS_PERSIST_RETRY
.attempt:
    mov  rdi, SESS_LBA_TMP
    lea  rsi, [rel sess_manifest]
    call sess_write
    test rax, rax
    jnz  .retry
    mov  rdi, SESS_LBA_TMP
    lea  rsi, [rel sess_scratch]
    call sess_read
    test rax, rax
    jnz  .retry
    lea  rdi, [rel sess_manifest]
    lea  rsi, [rel sess_scratch]
    mov  ecx, SESS_OWNED_SIZE
    call sess_memeq
    cmp  rax, 1
    jne  .retry
    mov  rdi, SESS_LBA_PRIMARY
    lea  rsi, [rel sess_manifest]
    call sess_write
    test rax, rax
    jnz  .retry
    mov  [rel sess_saved_count], r13d
    mov  dword [rel sess_saved_flag], 1
    xor  eax, eax
    jmp  .out
.retry:
    dec  r14d
    jnz  .attempt
    mov  rax, -1
    jmp  .out
.identity_refused:
    mov  rax, -1
    jmp  .out
.storage_refused:
    mov  rax, -2                        ; storage access not permitted (fail-closed, nothing written)
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Session-shell workspace ops. GUI owns the document/window bytes and registers
; these callbacks downward into sec/session; security never imports layer 6.
; ---------------------------------------------------------------------------
session_workspace_gui_commit:
    call session_persist
    test rax, rax
    jz   .ram
    cmp  rax, -2                        ; durable write refused by the storage gate: keep the
    je   .ram                           ;   in-RAM checkpoint so lock/unlock still restores windows
    lea  rsi, [rel sess_manifest]       ; -1: a failed write still leaves the built manifest
    call session_manifest_valid         ;   (M1-3 C1); an identity refusal leaves it zeroed,
    test eax, eax                       ;   so it is never installed
    jz   .bad
.ram:
    lea  rdi, [rel session_ram_checkpoint]
    lea  rsi, [rel sess_manifest]
    mov  edx, SESS_SECTOR
    call memcpy
    mov  byte [rel session_ram_checkpoint_valid], 1
    xor  eax, eax
    ret
.bad:
    mov  byte [rel session_ram_checkpoint_valid], 0
    mov  eax, -1
    ret

; session_ram_checkpoint_build -> EAX 0 when the live windows now form the in-RAM
;   checkpoint (a valid manifest: the owner, 1..SESS_MAXWIN windows), else -1 and the
;   in-RAM checkpoint is unchanged. Never touches storage: a missing or failing
;   session disk no longer empties SLEEP (RCQ-27 M1-3 C1, rc-qemu 14:52).
session_ram_checkpoint_build:
    call session_manifest_build
    test rax, rax
    jnz  .bad                           ; identity refused: never install a partial build
    lea  rsi, [rel sess_manifest]
    call session_manifest_valid
    test eax, eax
    jz   .bad                           ; no windows (or not a valid manifest)
    lea  rdi, [rel session_ram_checkpoint]
    lea  rsi, [rel sess_manifest]
    mov  edx, SESS_SECTOR
    call memcpy
    mov  byte [rel session_ram_checkpoint_valid], 1
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; RCQ-27 POWER-06 M1-3: the M1 checkpoint carries exactly this module's manifest.
; session_ram_checkpoint_export(RDI = 512-byte out) -> EAX 0 when the in-RAM
;   checkpoint (refreshed by the workspace commit) is a valid manifest, copied out;
;   else -1 and nothing is copied (no windows, no owner, a stale checkpoint).
session_ram_checkpoint_export:
    push rbx
    mov  rbx, rdi
    mov  eax, -1
    cmp  byte [rel session_ram_checkpoint_valid], 1
    jne  .out
    lea  rsi, [rel session_ram_checkpoint]
    call session_manifest_valid
    test eax, eax
    mov  eax, -1
    jz   .out
    mov  rdi, rbx
    lea  rsi, [rel session_ram_checkpoint]
    mov  edx, SESS_SECTOR
    call memcpy
    lea  rdi, [rbx + SESS_OWNED_SIZE]       ; srcreview NIT: never carry the on-disk tail (344..511)
    xor  esi, esi
    mov  edx, SESS_SECTOR - SESS_OWNED_SIZE
    call memset
    xor  eax, eax
.out:
    pop  rbx
    ret

; session_ram_checkpoint_install(RSI = 512-byte manifest from a verified M1
;   checkpoint) -> EAX 0 when it is a valid manifest, now the in-RAM checkpoint the
;   next workspace restore applies (session_workspace_gui_restore re-validates it
;   and requires its principal to be the signed-in one); else -1, nothing changed.
session_ram_checkpoint_install:
    push rbx
    mov  rbx, rsi
    call session_manifest_valid
    test eax, eax
    mov  eax, -1
    jz   .out
    lea  rdi, [rel session_ram_checkpoint]
    mov  rsi, rbx
    mov  edx, SESS_SECTOR
    call memcpy
    mov  byte [rel session_ram_checkpoint_valid], 1
    xor  eax, eax
.out:
    pop  rbx
    ret

session_workspace_gui_discard:
    mov  byte [rel session_ram_checkpoint_valid], 0
    mov  byte [rel session_restore_ram_offer], 0
    lea  rdi, [rel session_ram_checkpoint]
    xor  esi, esi
    mov  edx, SESS_SECTOR
    call memset
    ret

; Observe/cache the durable document while the login gate is locked. This is
; deliberately not session_restore: no WM slot, focus, or framebuffer state may
; be changed before authentication. The absent path retains the established
; QEMU boot diagnostic; a valid document becomes only an optional RAM fast path.
session_workspace_gui_observe_locked:
    push r14
    mov  r14d, SESS_PERSIST_RETRY
.reread:
    mov  rdi, SESS_LBA_PRIMARY
    lea  rsi, [rel sess_scratch]
    call sess_read
    test rax, rax
    jz   .validate
    dec  r14d
    jnz  .reread
    jmp  .absent
.validate:
    lea  rsi, [rel sess_scratch]
    call session_manifest_valid
    test eax, eax
    jz   .absent
    lea  rdi, [rel session_ram_checkpoint]
    lea  rsi, [rel sess_scratch]
    mov  edx, SESS_SECTOR
    call memcpy
    mov  byte [rel session_ram_checkpoint_valid], 1
    xor  eax, eax
    pop  r14
    ret
.absent:
    call session_workspace_gui_discard
    lea  rdi, [rel str_sess_absent]
    call serial_string
    xor  eax, eax
    pop  r14
    ret

session_workspace_gui_restore:
    cmp  byte [rel session_ram_checkpoint_valid], 1
    jne  .fallback
    lea  rsi, [rel session_ram_checkpoint]
    call session_manifest_valid
    test eax, eax
    jz   .discard
    mov  byte [rel session_restore_ram_offer], 1
    call session_restore
    test eax, eax
    jnz  .restore_failed
    call principal_current
    mov  rdx, rax
    mov  eax, 1                         ; RAM checkpoint fast path
    ret
.discard:
    call session_workspace_gui_discard
.fallback:
    mov  byte [rel session_restore_ram_offer], 0
    call session_restore
    test eax, eax
    jnz  .restore_failed
    call principal_current
    mov  rdx, rax
    mov  eax, 2                         ; durable document safe fallback
    ret
.restore_failed:
    xor  edx, edx
    mov  eax, -1
    ret

; Pure document KAT for login.session.gate. It uses the exact SESSMAN1 parser,
; carries geometry/title content, and never touches disk or live windows.
session_workspace_gui_kat:
    lea  rdi, [rel session_ram_checkpoint]
    xor  esi, esi
    mov  edx, SESS_SECTOR
    call memset
    mov  rax, [rel str_sess_magic]
    mov  [rel session_ram_checkpoint + SESS_OFF_MAGIC], rax
    mov  dword [rel session_ram_checkpoint + SESS_OFF_PRESENT], 1
    mov  dword [rel session_ram_checkpoint + SESS_OFF_COUNT], 1
    mov  dword [rel session_ram_checkpoint + SESS_OFF_PRINCIPAL], PRIN_OWNER
    mov  dword [rel session_ram_checkpoint + SESS_OFF_ENTRIES + SESS_E_STATE], WM_VISIBLE
    mov  dword [rel session_ram_checkpoint + SESS_OFF_ENTRIES + SESS_E_X], 37
    mov  dword [rel session_ram_checkpoint + SESS_OFF_ENTRIES + SESS_E_Y], 53
    mov  dword [rel session_ram_checkpoint + SESS_OFF_ENTRIES + SESS_E_W], 211
    mov  dword [rel session_ram_checkpoint + SESS_OFF_ENTRIES + SESS_E_H], 127
    mov  rax, [rel str_session_kat_title]
    mov  [rel session_ram_checkpoint + SESS_OFF_ENTRIES + SESS_E_TITLE], rax
    lea  rdi, [rel session_ram_checkpoint + SESS_OFF_ENTRIES]
    mov  ecx, SESS_ENTRY
    call sess_checksum
    mov  [rel session_ram_checkpoint + SESS_OFF_SUM], eax
    lea  rsi, [rel session_ram_checkpoint]
    call session_manifest_valid
    cmp  eax, 1
    jne  .bad
%if WM_RESTORE_ALWAYS != 0 || WM_RESTORE_FRESH != 1 || WM_RESTORE_NEVER != 2
    %error "session restore_class slot-19 vocabulary drift"
%endif
    mov  byte [rel session_ram_checkpoint_valid], 1
    xor  eax, eax
    ret
.bad:
    call session_workspace_gui_discard
    mov  eax, -1
    ret

%if PAOS_PUBLICITY_LAB_PROFILE
; RDI=nonce title. Persist a real window, discard RAM, restore from the durable
; document, prove its title/class, then remove it and recommit prior workspace.
session_workspace_gui_probe:
    push rbx
    push r12
    mov  r12, rdi
    mov  esi, 41
    mov  edx, 67
    mov  ecx, 303
    mov  r8d, 181
    mov  r9d, WM_RESTORE_FRESH
    call wmx_open_window
    cmp  eax, -1
    je   .bad
    call session_workspace_gui_commit
    test eax, eax
    jnz  .bad
    call session_workspace_gui_discard
    call session_restore
    xor  ebx, ebx
.find:
    cmp  ebx, WM_MAX
    jae  .bad
    lea  rax, [rel wm_state]
    mov  eax, [rax + rbx*4]
    cmp  eax, WM_VISIBLE
    je   .compare
    cmp  eax, WM_MIN
    jne  .next
.compare:
    lea  rax, [rel wm_title]
    mov  rdi, [rax + rbx*8]
    test rdi, rdi
    jz   .next
    mov  rsi, r12
    call strcmp
    test eax, eax
    jz   .found
.next:
    inc  ebx
    jmp  .find
.found:
    lea  rax, [rel wm_restore_class]
    cmp  byte [rax + rbx], WM_RESTORE_FRESH
    jne  .bad
    lea  rax, [rel wm_state]
    mov  dword [rax + rbx*4], WM_CLOSED
    mov  edi, ebx
    call wmx_owner_clear                ; F2: closed slots carry no owner
    call wm_erase_slot
    call wmx_draw_all
    call session_workspace_gui_commit
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret
%endif

; ---------------------------------------------------------------------------
; Retire only document-owned FRESH windows before reconstitution. ALWAYS demo
; windows and the reserved chat slot stay outside the workspace document.
session_clear_fresh_windows:
    xor  edi, edi                       ; no manifest: every fresh window goes
; sess_clear_fresh_unlisted(EDI = entry count of the manifest in sess_scratch): close the
;   fresh windows, except a live one whose title the manifest names. RCQ-27 M1 R2 (rc-qemu
;   17:34 F2): clearing it first defeated the 2026-09-08 replay guard, so the unlock fast
;   path closed the live Console and replayed a bare copy (no tabstrip, no input field).
sess_clear_fresh_unlisted:
    push r12
    push r13
    mov  r13d, edi
    xor  r12d, r12d
.loop:
    cmp  r12d, WM_MAX
    jae  .done
    cmp  r12d, CHAT_SLOT
    je   .next
    lea  rax, [rel wm_restore_class]
    cmp  byte [rax + r12], WM_RESTORE_FRESH
    jne  .next
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .live
    cmp  eax, WM_MIN
    jne  .next
.live:
    mov  edi, r12d
    mov  esi, r13d
    call sess_slot_listed
    test eax, eax
    jnz  .next                          ; the replay below skips it (title live)
    lea  rax, [rel wm_state]
    mov  dword [rax + r12*4], WM_CLOSED
    mov  edi, r12d
    call wmx_owner_clear                ; F2: closed slots carry no owner
    call wm_erase_slot
.next:
    inc  r12d
    jmp  .loop
.done:
    pop  r13
    pop  r12
    ret

; sess_slot_listed(EDI = slot, ESI = entry count) -> EAX 1 when the slot's live title
;   equals an entry title of the manifest in sess_scratch, else 0. clobbers: RCX, RDX, R8, R9
sess_slot_listed:
    lea  rax, [rel wm_title]
    mov  r8, [rax + rdi*8]              ; live title ptr (0 = none)
    test r8, r8
    jz   .no
    xor  ecx, ecx
.entry:
    cmp  ecx, esi
    jae  .no
    imul edx, ecx, SESS_ENTRY
    lea  rax, [rel sess_scratch + SESS_OFF_ENTRIES + SESS_E_TITLE]
    add  rdx, rax
    mov  r9, r8
.cmp:
    mov  al, [rdx]
    cmp  al, [r9]
    jne  .next_entry
    test al, al
    jz   .yes
    inc  rdx
    inc  r9
    jmp  .cmp
.next_entry:
    inc  ecx
    jmp  .entry
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; session_restore — boot restore: read the PRIMARY manifest, re-open each window at
;   its stored geometry/title into a free slot (z-order = slot order, focus = last).
;   Valid manifest -> [desktop.session.restored]; absent/torn -> desktop starts empty
;   + [desktop.session.manifest.absent] (never a crash or half-restore). Runs after
;   the desktop init (fb + wm_* table ready). On QEMU the throwaway namespace holds no
;   session -> absent path; the QEMU marker gate is session_persist_selftest.
; ---------------------------------------------------------------------------
session_restore:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; A valid RAM checkpoint is an optional one-shot fast path. Doubt is
    ; discarded by sec/session before this function selects the disk fallback.
    cmp  byte [rel session_restore_ram_offer], 1
    jne  .reread_begin
    mov  byte [rel session_restore_ram_offer], 0
    lea  rdi, [rel sess_scratch]
    lea  rsi, [rel session_ram_checkpoint]
    mov  edx, SESS_SECTOR
    call memcpy
    jmp  .readok
.reread_begin:
    ; read the PRIMARY manifest (retry a cold ahci port so a settle-error isn't
    ;   mistaken for "no session")
    mov  r14d, SESS_PERSIST_RETRY
.reread:
    mov  rdi, SESS_LBA_PRIMARY
    lea  rsi, [rel sess_scratch]
    call sess_read
    test rax, rax
    jz   .readok
    dec  r14d
    jnz  .reread
    jmp  .absent
.readok:
    lea  rsi, [rel sess_scratch]
    call session_manifest_valid
    test rax, rax
    jz   .absent
    mov  r13d, eax                      ; count
    call principal_current
    mov  edx, [rel sess_scratch + SESS_OFF_PRINCIPAL]
    cmp  rax, rdx
    jne  .absent                        ; never restore another principal's tree
    mov  edi, r13d
    call sess_clear_fresh_unlisted      ; a live window the manifest names stays (M1 R2)
    xor  r12d, r12d                     ; i
    mov  r14d, -1                       ; last restored slot (-1 = nothing restored yet)
    mov  dword [rel sess_restore_skipped], 0
.rloop:
    cmp  r12d, r13d
    jae  .rdone
    mov  eax, r12d
    imul eax, SESS_ENTRY
    add  eax, SESS_OFF_ENTRIES
    lea  rbx, [rel sess_scratch]
    add  rbx, rax                       ; entry ptr
    ; Legacy manifests predate the hidden recovery Console. They carry only
    ; titles, not app identities: suppress its exact reserved historical titles,
    ; never a prefix or arbitrary window. New Console forms are class=always.
    lea  rdi, [rbx + SESS_E_TITLE]
    call sess_recovery_console_title
    test eax, eax
    jnz  .rskip
    ; --- 2026-09-08: never replay a window an app already opened this boot
    ;     (console_app_init / the ANSI app run before session_restore). A bare
    ;     copy on top of the real window has no widgets: nothing can take the
    ;     keyboard and body clicks hit nothing. ---
    lea  rdi, [rbx + SESS_E_TITLE]
    call sess_title_live
    test eax, eax
    jz   .rfresh
.rskip:
    inc  dword [rel sess_restore_skipped]
    inc  r12d
    jmp  .rloop
.rfresh:
    call wmx_find_free_slot
    cmp  eax, 0
    jl   .rdone                         ; no free slot -> stop (best-effort)
    mov  r15d, eax                      ; slot
    mov  eax, [rbx + SESS_E_X]
    lea  rcx, [rel wm_x]
    mov  [rcx + r15*4], eax
    mov  eax, [rbx + SESS_E_Y]
    lea  rcx, [rel wm_y]
    mov  [rcx + r15*4], eax
    mov  eax, [rbx + SESS_E_W]
    lea  rcx, [rel wm_w]
    mov  [rcx + r15*4], eax
    mov  eax, [rbx + SESS_E_H]
    lea  rcx, [rel wm_h]
    mov  [rcx + r15*4], eax
    ; title -> wmx_titles[slot*WMX_TITLE_MAX]; wm_title[slot] = that (runtime lea)
    mov  eax, r15d
    imul eax, WMX_TITLE_MAX
    lea  rdi, [rel wmx_titles]
    add  rdi, rax
    lea  rcx, [rel wm_title]
    mov  [rcx + r15*8], rdi
    lea  rsi, [rbx + SESS_E_TITLE]
    mov  ecx, WMX_TITLE_MAX - 1
.rtit:
    test ecx, ecx
    jz   .rtitend
    mov  al, [rsi]
    test al, al
    jz   .rtitend
    mov  [rdi], al
    inc  rdi
    inc  rsi
    dec  ecx
    jmp  .rtit
.rtitend:
    mov  byte [rdi], 0
    ; state last (so the slot is only "live" once fully populated)
    mov  eax, [rbx + SESS_E_STATE]
    lea  rcx, [rel wm_state]
    mov  [rcx + r15*4], eax
    mov  edi, r15d
    call wmx_owner_clear                ; F2: a restored window is the owner's own
    lea  rcx, [rel wm_restore_class]
    mov  byte [rcx + r15], WM_RESTORE_FRESH
    lea  rcx, [rel wm_attn]
    mov  byte [rcx + r15], 0
    mov  r14d, r15d
    inc  r12d
    jmp  .rloop
.rdone:
    cmp  dword [rel sess_restore_skipped], 0
    je   .rdone_nofocus_msg
    lea  rdi, [rel str_sess_skipped]
    call serial_string                  ; plain line, no marker token
.rdone_nofocus_msg:
    cmp  r14d, WM_MAX
    jae  .rdone_draw                    ; nothing restored: keep the focus the apps set
    mov  [rel wm_focus], r14d           ; focus the last-restored (topmost)
.rdone_draw:
    call wmx_draw_all
    lea  rdi, [rel str_sess_restored]
    call serial_string                  ; [desktop.session.restored]
    call sess_focus_keyboard_owner      ; the restored desktop always has a keyboard owner
    xor  eax, eax
    jmp  .out
.absent:
    lea  rdi, [rel str_sess_absent]
    call serial_string                  ; [desktop.session.manifest.absent]
    call sess_focus_keyboard_owner
    mov  eax, -1
.out:
    push rax
    push rdx
    call console_observe_unlock
    pop rdx
    pop rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI = validated manifest title; EAX = 1 only for an exact reserved recovery
; Console title. The old manifest schema cannot recover an app/widget tree.
; Do not recreate a visible bare Console on boot or unlock. A live explicitly
; opened recovery window is preserved by sess_clear_fresh_unlisted above.
; Clobbers RAX, RCX, RDX, RSI; RDI is preserved for the live-title guard.
sess_recovery_console_title:
    lea  rsi, [rel str_sess_recovery_console]
    mov  rdx, rdi
    mov  ecx, 2
.compare:
    mov  al, [rsi]
    cmp  al, [rdx]
    jne  .next
    test al, al
    jz   .yes
    inc  rsi
    inc  rdx
    jmp  .compare
.next:
    dec  ecx
    jz   .no
    lea  rsi, [rel str_sess_recovery_console_old]
    mov  rdx, rdi
    jmp  .compare
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; session_persist_selftest — QEMU BUILD gate for the two required markers. Exercises
;   the FULL write+readback+re-parse path against the throwaway nvme namespace with a
;   RANDOM-nonce geometry (content grade, not a latch): pack a 1-window manifest, write
;   it, read it back byte-equal -> [desktop.session.persist]; then re-VALIDATE + parse
;   the read-back copy and require the SAME random x/y survived -> [desktop.session.
;   restored]. Gated to QEMU (real disk write deferred to SESSSAVE + supervised boot
;   restore; the un-fakeable grade is the bare-metal cross-reboot UDP probe).
; ---------------------------------------------------------------------------
; sess_focus_keyboard_owner — if the focused window has no focused widget, raise
; the topmost VISIBLE window that has one (wgt_focus_by_win[slot] != -1), scanning
; from the highest slot down so a later-created window wins. No-op otherwise.
sess_focus_keyboard_owner:
    push rbx
    mov  eax, [rel wm_focus]
    cmp  eax, WM_MAX
    jae  .fk_scan
    lea  rcx, [rel wgt_focus_by_win]
    cmp  dword [rcx + rax*4], -1
    je   .fk_scan
    ; 0.0.52 re-cut invariant guard: "the focused window owns the keyboard" only when the
    ; global keyboard widget is a LIVE widget of that window. A stale wgt_focus_id (a closed
    ; window's retired widget, -1, or another window's widget) is no owner.
    mov  ebx, eax
    mov  ecx, [rel wgt_focus_id]
    cmp  ecx, [rel wgt_count]
    jae  .fk_scan                       ; -1 (unsigned) or past the table
    mov  edi, ecx
    call wgt_slot_ptr                   ; clobbers RAX, R10
    cmp  dword [rax + WGI_TYPE], 0
    je   .fk_scan                       ; retired
    cmp  [rax + WGI_WIN], ebx
    jne  .fk_scan
    ; 0.0.53 (travels with WK-B7B): a CONJUNCTION, never a replacement. B7b reuses interior ids, so a
    ; stale wgt_focus_id can name a live widget of the SAME slot's new form; the owner must also BE the
    ; window's recorded keyboard widget.
    lea  rdx, [rel wgt_focus_by_win]
    cmp  ecx, [rdx + rbx*4]
    je   .fk_owned                      ; the focused window really owns the keyboard
.fk_scan:
    mov  ebx, -1                        ; best slot: the topmost (highest z stamp) visible window with a focused widget
    xor  edx, edx
    xor  ecx, ecx
.fk_next:
    cmp  ecx, WM_MAX
    jae  .fk_pick
    lea  rax, [rel wm_state]
    cmp  dword [rax + rcx*4], WM_VISIBLE
    jne  .fk_skip
    lea  rax, [rel wgt_focus_by_win]
    cmp  dword [rax + rcx*4], -1
    je   .fk_skip
    lea  rax, [rel wm_zstamp]
    mov  eax, [rax + rcx*4]
    cmp  ebx, -1
    je   .fk_take
    cmp  eax, edx
    jb   .fk_skip
.fk_take:
    mov  edx, eax
    mov  ebx, ecx
.fk_skip:
    inc  ecx
    jmp  .fk_next
.fk_pick:
    cmp  ebx, -1
    je   .fk_out
    mov  edi, ebx
    call wmx_raise_slot                 ; focus + z-order + repaint
.fk_owned:
    lea  rdi, [rel str_sess_kbd_owner]  ; the post-condition holds (verified or established)
    call serial_string
.fk_out:
    pop  rbx
    ret

; sess_title_live(RDI=title cstr) -> EAX 1 if a VISIBLE or MIN window already carries
; exactly this title (NUL-terminated compare), else 0. clobbers RAX,RCX,RDX,RSI,RDI,R8.
sess_title_live:
    push rbx
    mov  r8, rdi                        ; wanted title
    xor  ebx, ebx
.st_slot:
    cmp  ebx, WM_MAX
    jae  .st_no
    lea  rcx, [rel wm_state]
    mov  eax, [rcx + rbx*4]
    cmp  eax, WM_VISIBLE
    je   .st_check
    cmp  eax, WM_MIN
    jne  .st_next
.st_check:
    lea  rcx, [rel wm_title]
    mov  rsi, [rcx + rbx*8]             ; live title ptr (0 = none)
    test rsi, rsi
    jz   .st_next
    mov  rdi, r8
.st_cmp:
    mov  al, [rdi]
    mov  dl, [rsi]
    cmp  al, dl
    jne  .st_next
    test al, al
    jz   .st_yes
    inc  rdi
    inc  rsi
    jmp  .st_cmp
.st_next:
    inc  ebx
    jmp  .st_slot
.st_yes:
    mov  eax, 1
    pop  rbx
    ret
.st_no:
    xor  eax, eax
    pop  rbx
    ret

session_persist_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call sess_dev
    test rax, rax
    jz   .skip                          ; no persistent backend
    call ahci_model_is_qemu
    test rax, rax
    jz   .metal                         ; real disk: defer to SESSSAVE + boot restore
    ; --- random nonce geometry (content token the read-back must carry) ---
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rcx, 0x1105E5B0C0FFEE05
    xor  rax, rcx
    mov  r14, rax
    mov  r12d, r14d
    and  r12d, 0x1FF
    add  r12d, 32                       ; X = (nonce & 0x1FF) + 32
    mov  r13, r14
    shr  r13, 16
    and  r13d, 0xFF
    add  r13d, 32                       ; Y = ((nonce>>16) & 0xFF) + 32
    ; --- pack a 1-window manifest ---
    lea  rdi, [rel sess_manifest]
    xor  eax, eax
    mov  ecx, SESS_OWNED_SIZE
    cld
    rep  stosb
    mov  rax, [rel str_sess_magic]
    mov  [rel sess_manifest + SESS_OFF_MAGIC], rax
    mov  dword [rel sess_manifest + SESS_OFF_PRESENT], 1
    mov  dword [rel sess_manifest + SESS_OFF_COUNT], 1
    mov  dword [rel sess_manifest + SESS_OFF_PRINCIPAL], PRIN_OWNER
    lea  rbx, [rel sess_manifest + SESS_OFF_ENTRIES]
    mov  dword [rbx + SESS_E_STATE], WM_VISIBLE
    mov  [rbx + SESS_E_X], r12d
    mov  [rbx + SESS_E_Y], r13d
    mov  dword [rbx + SESS_E_W], 300
    mov  dword [rbx + SESS_E_H], 200
    mov  rax, [rel str_sess_selftitle]
    mov  [rbx + SESS_E_TITLE], rax      ; "SESSKAT\0" (8 bytes incl NUL)
    lea  rdi, [rel sess_manifest + SESS_OFF_ENTRIES]
    mov  ecx, SESS_ENTRY
    call sess_checksum
    mov  [rel sess_manifest + SESS_OFF_SUM], eax
    ; --- selftest LBA: last valid data sector (QEMU vvfat rejects low/reserved) ---
    mov  r15, [rel ahci_lba_max]
    test r15, r15
    jz   .lba_lo
    dec  r15
    jmp  .lba_set
.lba_lo:
    mov  r15, 8
.lba_set:
    ; --- GPT guard (desktop bring-up 2026-09-07): on a GPT disk the last 33 sectors hold
    ;     the BACKUP GPT (header at lba_max, entry array just below). lba_max-1 is INSIDE
    ;     that array -> never write the selftest manifest there. Read the last sector and
    ;     skip (honest marker) when it carries the "EFI PART" signature. ---
    mov  rdi, [rel ahci_lba_max]
    lea  rsi, [rel sess_scratch]
    call sess_read
    test rax, rax
    jnz  .gpt_checked                   ; unreadable tail: fall through to the old path
    mov  rax, 0x5452415020494645        ; "EFI PART"
    cmp  [rel sess_scratch], rax
    je   .gpt_backup
.gpt_checked:
    mov  rdi, r15
    mov  esi, 1
    call sess_storage_gate              ; implicit self-test write: QEMU test scratch only
    test rax, rax
    jnz  .storage_skip
    ; --- WRITE -> READBACK -> byte-equal (persist) ---
    mov  rdi, r15
    lea  rsi, [rel sess_manifest]
    call sess_write
    test rax, rax
    jnz  .done
    mov  rdi, r15
    lea  rsi, [rel sess_scratch]
    call sess_read
    test rax, rax
    jnz  .done
    lea  rdi, [rel sess_manifest]
    lea  rsi, [rel sess_scratch]
    mov  ecx, SESS_OWNED_SIZE
    call sess_memeq
    cmp  rax, 1
    jne  .done
    lea  rdi, [rel str_sess_persist]
    call serial_string                  ; [desktop.session.persist]
    ; --- re-VALIDATE + parse the READ-BACK copy; require the random geom survived ---
    lea  rsi, [rel sess_scratch]
    call session_manifest_valid
    cmp  rax, 1
    jne  .done
    lea  rbx, [rel sess_scratch + SESS_OFF_ENTRIES]
    cmp  dword [rbx + SESS_E_X], r12d
    jne  .done
    cmp  dword [rbx + SESS_E_Y], r13d
    jne  .done
    lea  rdi, [rel str_sess_restored]
    call serial_string                  ; [desktop.session.restored]
    jmp  .done
.metal:
    lea  rdi, [rel str_sess_metal]
    call serial_string
    jmp  .done
.storage_skip:
    lea  rdi, [rel str_sess_sa_skip]
    call serial_string                  ; [desktop.session.persist.skipped.storage_access]
    jmp  .done
.gpt_backup:
    lea  rdi, [rel str_sess_gpt_skip]
    call serial_string                  ; [desktop.session.persist.skipped.gpt_backup]
    jmp  .done
.skip:
    lea  rdi, [rel str_sess_skip]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; UDP verbs (replies staged into the shared chat_out_buf, framed by command_udp).
; ---------------------------------------------------------------------------

; VERB: WINOPEN <app> title=<T> x=<X> y=<Y> [w=<W>] [h=<H>] — open a titled window in
;   a free slot (key=value args, any order; a leading positional app token is ignored).
;   Auto-persists the session (Win11 behavior; best-effort — no-op if no disk).
cmd_verb_winopen:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  r13, rsi
    mov  r14, [rdi + REQ_ARG]
    call session_shell_require_unlocked
    test eax, eax
    jnz  .locked
    call wmx_find_free_slot
    cmp  eax, 0
    jl   .full
    mov  r12d, eax                      ; slot
    ; geometry defaults
    lea  rcx, [rel wm_x]
    mov  dword [rcx + r12*4], 100
    lea  rcx, [rel wm_y]
    mov  dword [rcx + r12*4], 100
    lea  rcx, [rel wm_w]
    mov  dword [rcx + r12*4], 300
    lea  rcx, [rel wm_h]
    mov  dword [rcx + r12*4], 200
    ; default title -> empty string in the slot buffer
    mov  eax, r12d
    imul eax, WMX_TITLE_MAX
    lea  rbx, [rel wmx_titles]
    add  rbx, rax
    mov  byte [rbx], 0
    lea  rcx, [rel wm_title]
    mov  [rcx + r12*8], rbx
    mov  rdi, r14                       ; arg cursor
.scan:
    mov  al, [rdi]
    test al, al
    jz   .scandone
    cmp  al, ' '
    jne  .tok
    inc  rdi
    jmp  .scan
.tok:
    ; single-char geom key?  X= form
    cmp  byte [rdi + 1], '='
    jne  .maybe_title
    mov  al, [rdi]
    cmp  al, 'x'
    je   .kx
    cmp  al, 'y'
    je   .ky
    cmp  al, 'w'
    je   .kw
    cmp  al, 'h'
    je   .kh
    jmp  .skiptok
.kx:
    add  rdi, 2
    call chat_parse_u32
    lea  rcx, [rel wm_x]
    mov  [rcx + r12*4], eax
    jmp  .scan
.ky:
    add  rdi, 2
    call chat_parse_u32
    lea  rcx, [rel wm_y]
    mov  [rcx + r12*4], eax
    jmp  .scan
.kw:
    add  rdi, 2
    call chat_parse_u32
    lea  rcx, [rel wm_w]
    mov  [rcx + r12*4], eax
    jmp  .scan
.kh:
    add  rdi, 2
    call chat_parse_u32
    lea  rcx, [rel wm_h]
    mov  [rcx + r12*4], eax
    jmp  .scan
.maybe_title:
    ; "title=" ?
    lea  rsi, [rel str_key_title]
    mov  rbx, rdi                       ; save token start
    mov  ecx, 6
.tmatch:
    mov  al, [rsi]
    test al, al
    jz   .istitle
    mov  dl, [rdi]
    cmp  al, dl
    jne  .nottitle
    inc  rdi
    inc  rsi
    jmp  .tmatch
.istitle:
    ; rdi now past "title=" -> store token as the slot title
    mov  esi, r12d
    call wmx_store_title                ; copies title, sets wm_title[slot], advances rdi
    jmp  .scan
.nottitle:
    mov  rdi, rbx                       ; restore, treat as an ignored token (app name)
.skiptok:
    mov  al, [rdi]
    test al, al
    jz   .scandone
    cmp  al, ' '
    je   .scan
    inc  rdi
    jmp  .skiptok
.scandone:
    lea  rcx, [rel wm_state]
    mov  dword [rcx + r12*4], WM_VISIBLE
    mov  edi, r12d
    call wmx_owner_open                 ; F2: WINOPEN -> the requester's principal
    call wmx_frame_may_focus            ; F2b-2: only an OWNER request takes the keyboard
    test eax, eax
    jnz  .opened_unfocused
    mov  [rel wm_focus], r12d
.opened_unfocused:
    call wmx_draw_all
    call session_persist                ; best-effort auto-save (Win11 behavior)
    call chat_out_reset
    lea  rdi, [rel str_wo_ok]           ; " winopen=ok idx="
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    jmp  .stage
.full:
    call chat_out_reset
    lea  rdi, [rel str_wo_full]         ; " winopen=ERR no_free_slot"
    call chat_put_str
    mov  qword [r13 + RSP_CODE], CMDE_BUSY  ; G-11: a refusal is never OK; the text is unchanged
    jmp  .staged
.locked:
    call chat_out_reset
    lea  rdi, [rel str_sess_gate_locked]
    call chat_put_str
.stage:
    mov  qword [r13 + RSP_CODE], CMDE_OK
.staged:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_VAL], 0
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; VERB: WINLIST — one "WIN[i] title=T state=S x=X y=Y w=W h=H" line per live window.
;   The probe's restore grade: greps the nonce title + its x=/y= on the SAME line.
cmd_verb_winlist:
    call cmd_handler_prologue
    push r12
    push r13
    mov  r13, rsi
    call session_shell_require_unlocked
    test eax, eax
    jnz  .locked
    call chat_out_reset
    xor  r12d, r12d
.loop:
    cmp  r12d, WM_MAX
    jae  .done
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .emit
    cmp  eax, WM_MIN
    je   .emit
    jmp  .next
.emit:
    lea  rdi, [rel str_wl_win]          ; "\nWIN["
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    lea  rdi, [rel str_wl_title]        ; "] title="
    call chat_put_str
    lea  rax, [rel wm_title]
    mov  rdi, [rax + r12*8]
    test rdi, rdi
    jz   .st
    call chat_put_str
.st:
    lea  rdi, [rel str_wl_state]        ; " state="
    call chat_put_str
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_MIN
    je   .st_min
    lea  rdi, [rel str_wl_vis]
    jmp  .st_put
.st_min:
    lea  rdi, [rel str_wl_min]
.st_put:
    call chat_put_str
    lea  rdi, [rel str_wl_x]            ; " x="
    call chat_put_str
    lea  rax, [rel wm_x]
    mov  edi, [rax + r12*4]
    call chat_put_dec
    lea  rdi, [rel str_wl_y]            ; " y="
    call chat_put_str
    lea  rax, [rel wm_y]
    mov  edi, [rax + r12*4]
    call chat_put_dec
    lea  rdi, [rel str_wl_w]            ; " w="
    call chat_put_str
    lea  rax, [rel wm_w]
    mov  edi, [rax + r12*4]
    call chat_put_dec
    lea  rdi, [rel str_wl_h]            ; " h="
    call chat_put_str
    lea  rax, [rel wm_h]
    mov  edi, [rax + r12*4]
    call chat_put_dec
.next:
    inc  r12d
    jmp  .loop
.done:
    jmp  .stage
.locked:
    call chat_out_reset
    lea  rdi, [rel str_sess_gate_locked]
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    pop  r13
    pop  r12
    ret

; VERB: WINCLOSE <title> — close the live window whose title matches (slot -> CLOSED),
;   then auto-persist so the next restore drops it. SEC-winmove (C) (root 14:51:31):
;   the match only considers slots the request's principal may act on (never chrome,
;   the owner any other, anyone else only its own), so a title it may not close reads
;   as not_found and is never revealed by a denial.
cmd_verb_winclose:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  r13, rsi
    mov  rbx, rdi                       ; the request
    mov  r14, [rdi + REQ_ARG]
    call session_shell_require_unlocked
    test eax, eax
    jnz  .locked
.sk:
    cmp  byte [r14], ' '
    jne  .find
    inc  r14
    jmp  .sk
.find:
    xor  r12d, r12d
.floop:
    cmp  r12d, WM_MAX
    jae  .notfound
    lea  rax, [rel wm_state]
    mov  eax, [rax + r12*4]
    cmp  eax, WM_VISIBLE
    je   .cmp
    cmp  eax, WM_MIN
    je   .cmp
    jmp  .fnext
.cmp:
    mov  rdi, rbx
    mov  esi, r12d
    call wmx_req_may_act                ; a slot it may not act on never matches
    test eax, eax
    jnz  .fnext
    lea  rax, [rel wm_title]
    mov  rdi, [rax + r12*8]
    test rdi, rdi
    jz   .fnext
    mov  rsi, r14
    call sess_streq_tok
    cmp  rax, 1
    je   .hit
.fnext:
    inc  r12d
    jmp  .floop
.hit:
    mov  edi, r12d
    call wmx_close_slot                 ; F2b-W2: the shared close (owner clear, widget retire, and the
                                        ; frame-gated focus hand-off: wm_focus never names a closed slot)
    call session_persist
    call chat_out_reset
    lea  rdi, [rel str_wc_ok]           ; " winclose=ok idx="
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    jmp  .stage
.notfound:
    call chat_out_reset
    lea  rdi, [rel str_wc_bad]          ; " winclose=ERR not_found"
    call chat_put_str
    ; G-11: no such title among the windows this principal may act on. Another principal's
    ; window reads as absent, so both cases share BADSEL and the code leaks nothing more.
    mov  qword [r13 + RSP_CODE], CMDE_BADSEL
    jmp  .staged
.locked:
    call chat_out_reset
    lea  rdi, [rel str_sess_gate_locked]
    call chat_put_str
.stage:
    mov  qword [r13 + RSP_CODE], CMDE_OK
.staged:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_VAL], 0
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RC-task-manager (spec 21.2.7 items 2-3): the window side of Task Manager. Native
; modules run under the core/native_app watchdog and their binding is WM metadata
; (window_mgmt wm_native_*). Both verbs serve unlocked sessions only and, like
; WINCLOSE, consider only windows the request's principal may act on: another
; principal's window reads as absent, never as a denial.
;
; VERB: APPSTAT — one line per native-bound window: APP[idx] state=<s> gen=<bound
;   generation> cycles=<last measured dispatch, core/native_app; 0 unless ready/stuck>.
;   ready = the bound module is live; stuck = the WM latch is set, which is the only
;   state APPRESTART accepts ("Restart this app"); gone = the record is free or its
;   generation moved on; unavailable = the ABI refused the query (context). Read-only.
cmd_verb_appstat:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsi
    mov  rbx, rdi                       ; the request
    call session_shell_require_unlocked
    test eax, eax
    jnz  .locked
    call chat_out_reset
    lea  rdi, [rel str_as_head]         ; " appstat=v1 leaked="
    call chat_put_str
    mov  edi, [rel wmx_native_leaked]
    call chat_put_dec
    xor  r12d, r12d
.loop:
    cmp  r12d, WM_MAX
    jae  .stage
    lea  rax, [rel wm_native_slot]
    cmp  dword [rax + r12*4], -1
    je   .next
    mov  rdi, rbx
    mov  esi, r12d
    call wmx_req_may_act                ; a window it may not act on is not listed
    test eax, eax
    jnz  .next
    lea  rdi, [rel str_as_app]          ; "\nAPP["
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    lea  rax, [rel wm_native_gen]
    mov  r14, [rax + r12*8]             ; the bound generation
    xor  r15d, r15d                     ; cycles shown only for the bound, live module
    lea  rax, [rel wm_native_slot]
    mov  edi, [rax + r12*4]
    call native_app_query               ; RAX state, RDX live generation, R9 last cycles
    lea  rdi, [rel str_as_unavail]      ; "] state=unavailable"
    test rax, rax
    js   .put_state
    lea  rdi, [rel str_as_gone]         ; "] state=gone"
    jz   .put_state                     ; a free record
    cmp  rdx, r14
    jne  .put_state                     ; the bound generation is no longer live
    mov  r15, r9
    lea  rdi, [rel str_as_ready]        ; "] state=ready"
    lea  rax, [rel wm_native_stuck]
    cmp  byte [rax + r12], 1
    jne  .put_state
    lea  rdi, [rel str_as_stuck]        ; "] state=stuck"
.put_state:
    call chat_put_str
    lea  rdi, [rel str_as_gen]          ; " gen="
    call chat_put_str
    mov  rdi, r14
    call chat_put_dec
    lea  rdi, [rel str_as_cycles]       ; " cycles="
    call chat_put_str
    mov  rdi, r15
    call chat_put_dec
.next:
    inc  r12d
    jmp  .loop
.locked:
    call chat_out_reset
    lea  rdi, [rel str_sess_gate_locked]
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; VERB: APPRESTART <idx> <gen> — "Restart this app" for a stuck native window: the
;   watchdog zeroes the module's arena and advances its generation; the window, its
;   title, geometry, z-order, owner and saved state stay (wmx_native_restart). <gen>
;   is the generation APPSTAT showed, so a stale offer is refused. The request's
;   principal is the one wmx_native_restart checks (srcreview 53367 F1).
cmd_verb_apprestart:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  r13, rsi
    mov  rbx, rdi                       ; the request
    call session_shell_require_unlocked
    test eax, eax
    jnz  .locked
    mov  rdi, [rbx + REQ_ARG]
    call sr_parse_u64                   ; window index
    test edx, edx
    jz   .args
    cmp  rax, WM_MAX
    jae  .args
    mov  r12, rax
    call sr_parse_u64                   ; generation
    test edx, edx
    jz   .args
.tail:
    cmp  byte [rdi], ' '
    jne  .tail_end
    inc  rdi
    jmp  .tail
.tail_end:
    cmp  byte [rdi], 0
    jne  .args                          ; nothing but spaces may follow the generation
    mov  r14, rax
    lea  rax, [rel wm_native_slot]
    cmp  dword [rax + r12*4], -1
    je   .absent
    mov  rdi, rbx
    mov  esi, r12d
    call wmx_req_may_act
    test eax, eax
    jnz  .absent
    lea  rax, [rel wm_native_gen]
    cmp  [rax + r12*8], r14
    jne  .stale
    lea  rax, [rel wm_native_stuck]
    cmp  byte [rax + r12], 1
    jne  .not_stuck
    mov  rdi, rbx
    call session_shell_request_principal
    mov  rsi, rax
    mov  edi, r12d
    call wmx_native_restart             ; checks this principal again, then the ABI's generation
    test eax, eax
    jnz  .refused
    call chat_out_reset
    lea  rdi, [rel str_ar_ok]           ; " apprestart=ok idx="
    call chat_put_str
    mov  edi, r12d
    call chat_put_dec
    lea  rdi, [rel str_as_gen]          ; " gen="
    call chat_put_str
    lea  rax, [rel wm_native_gen]
    mov  rdi, [rax + r12*8]
    call chat_put_dec
    jmp  .stage
.args:
    lea  rdi, [rel str_ar_args]         ; " apprestart=ERR args"
    jmp  .err
.absent:
    lea  rdi, [rel str_ar_absent]       ; " apprestart=ERR not_found"
    jmp  .err
.stale:
    lea  rdi, [rel str_ar_stale]        ; " apprestart=ERR stale"
    jmp  .err
.not_stuck:
    lea  rdi, [rel str_ar_running]      ; " apprestart=ERR not_stuck"
    jmp  .err
.refused:
    lea  rdi, [rel str_ar_refused]      ; " apprestart=ERR refused"
.err:
    push rdi
    call chat_out_reset
    pop  rdi
    call chat_put_str
    jmp  .stage
.locked:
    call chat_out_reset
    lea  rdi, [rel str_sess_gate_locked]
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; sr_parse_u64(RDI=text) -> RAX value, EDX digit count (0 = no number or more than
; 19 digits), RDI just past the number. Leading spaces are skipped. Clobbers RCX.
sr_parse_u64:
    cmp  byte [rdi], ' '
    jne  .digits
    inc  rdi
    jmp  sr_parse_u64
.digits:
    xor  eax, eax
    xor  edx, edx
.next:
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .done
    cmp  edx, 19
    jae  .long
    imul rax, rax, 10
    add  rax, rcx
    inc  edx
    inc  rdi
    jmp  .next
.long:
    xor  edx, edx
.done:
    ret

; VERB: SESSSAVE — explicit flush of the current session to durable storage.
cmd_verb_sesssave:
    call cmd_handler_prologue
    push r13
    mov  r13, rsi
    call session_shell_require_unlocked
    test eax, eax
    jnz  .locked
    call wmx_draw_all                   ; settle: the compositor's memory traffic flushes the
                                        ;   CPU store buffer so the ahci DMA reads a coherent
                                        ;   command table (WINOPEN/WINCLOSE persist works BECAUSE
                                        ;   they repaint first; a cold SESSSAVE otherwise errors)
    call session_persist
    push rax                            ; chat_out_reset returns its buffer in RAX
    call chat_out_reset
    pop  rax                            ; branch on session_persist, not the reset helper
    test rax, rax
    jnz  .err
    lea  rdi, [rel str_ss_ok]           ; " sesssave=ok saved n="
    call chat_put_str
    mov  edi, [rel sess_saved_count]
    call chat_put_dec
    jmp  .stage
.err:
    cmp  rax, -2
    jne  .werr
    lea  rdi, [rel str_ss_refused]      ; " sesssave=ERR storage_not_permitted"
    call chat_put_str
    jmp  .stage
.werr:
    lea  rdi, [rel str_ss_err]          ; " sesssave=ERR write_failed"
    call chat_put_str
    jmp  .stage
.locked:
    call chat_out_reset
    lea  rdi, [rel str_sess_gate_locked]
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    pop  r13
    ret

; VERB: SESSINFO — report the saved manifest state ("n=<count> saved=<0|1>").
cmd_verb_sessinfo:
    call cmd_handler_prologue
    push r13
    mov  r13, rsi
    call session_shell_require_unlocked
    test eax, eax
    jnz  .locked
    call chat_out_reset
    lea  rdi, [rel str_si_pre]          ; " SESSINFO n="
    call chat_put_str
    mov  edi, [rel sess_saved_count]
    call chat_put_dec
    lea  rdi, [rel str_si_saved]        ; " saved="
    call chat_put_str
    mov  edi, [rel sess_saved_flag]
    call chat_put_dec
    jmp  .stage
.locked:
    call chat_out_reset
    lea  rdi, [rel str_sess_gate_locked]
    call chat_put_str
.stage:
    mov  byte [rel chat_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    pop  r13
    ret

; ---------------------------------------------------------------------------
; session_declare — register the 5 session/window verbs through the ONE registry.
; ---------------------------------------------------------------------------
session_declare:
    lea  rdi, [rel session_workspace_gui_commit]
    lea  rsi, [rel session_workspace_gui_restore]
    lea  rdx, [rel session_workspace_gui_discard]
    lea  rcx, [rel session_workspace_gui_kat]
%if PAOS_PUBLICITY_LAB_PROFILE
    lea  r8, [rel session_workspace_gui_probe]
%else
    xor  r8d, r8d
%endif
    lea  r9, [rel session_workspace_gui_observe_locked]
    call session_shell_register_workspace_ops
    lea  rdi, [rel str_verb_winopen]
    lea  rsi, [rel cmd_verb_winopen]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_winlist]
    lea  rsi, [rel cmd_verb_winlist]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_winclose]
    lea  rsi, [rel cmd_verb_winclose]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_appstat]
    lea  rsi, [rel cmd_verb_appstat]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                         ; read-only
    call command_register_verb
    lea  rdi, [rel str_verb_apprestart]
    lea  rsi, [rel cmd_verb_apprestart]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                          ; restarts a module: AUTH1-gated like WINCLOSE
    call command_register_verb
    lea  rdi, [rel str_verb_sesssave]
    lea  rsi, [rel cmd_verb_sesssave]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1                         ; writes the durable workspace document
    call command_register_verb
    lea  rdi, [rel str_verb_sessinfo]
    lea  rsi, [rel cmd_verb_sessinfo]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ret

; ---------------------------------------------------------------------------
; data
; ---------------------------------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_session_restore_0 0
str_sess_magic:     db "SESSMAN1"                    ; 8 bytes, no terminator
str_sess_disk:      db "ahci0", 0                    ; Samsung 870 — separate disk from hotpatch's nvme0
str_sess_selftitle: db "SESSKAT", 0                  ; 8 bytes incl NUL (qword-loadable)
str_session_kat_title: db "SSKAT3375",0

str_key_title:      db "title=", 0

; verb names
str_verb_winopen:   db "WINOPEN", 0
str_verb_winlist:   db "WINLIST", 0
str_verb_winclose:  db "WINCLOSE", 0
str_verb_sesssave:  db "SESSSAVE", 0
str_verb_sessinfo:  db "SESSINFO", 0

; staged-reply fragments
str_wo_ok:      db " winopen=ok idx=", 0
str_wo_full:    db " winopen=ERR no_free_slot", 0
str_wc_ok:      db " winclose=ok idx=", 0
str_wc_bad:     db " winclose=ERR not_found", 0
str_ss_ok:      db " sesssave=ok saved n=", 0
str_ss_err:     db " sesssave=ERR write_failed", 0
str_ss_refused: db " sesssave=ERR storage_not_permitted", 0
str_sess_sa_caller: db "session_save", 0
str_sess_sa_skip:  db "[PAOS64] L6 gui: session persist selftest SKIPPED: storage access not permitted [desktop.session.persist.skipped.storage_access]", 13, 10, 0
str_si_pre:     db " SESSINFO n=", 0
str_si_saved:   db " saved=", 0
str_sess_gate_locked: db " session=locked", 0

; WINLIST line fragments
str_wl_win:     db 10, "WIN[", 0
str_wl_title:   db "] title=", 0
str_wl_state:   db " state=", 0
str_wl_vis:     db "visible", 0
str_wl_min:     db "min", 0
str_wl_x:       db " x=", 0
str_wl_y:       db " y=", 0
str_wl_w:       db " w=", 0
str_wl_h:       db " h=", 0

; boot markers (serial; regression_tests.txt registers the bracket tokens)
str_sess_persist:   db "[PAOS64] L6 gui: session manifest write->readback byte-equal PASS [desktop.session.persist]", 13, 10, 0
str_sess_restored:  db "[PAOS64] L6 gui: session manifest re-parsed + windows restored (geometry carried) [desktop.session.restored]", 13, 10, 0
str_sess_absent:    db "[PAOS64] L6 gui: no valid session manifest at boot -> desktop starts empty [desktop.session.manifest.absent]", 13, 10, 0
str_sess_metal:     db "[PAOS64] L6 gui: session persist read-ready; write deferred to SESSSAVE + supervised boot restore (bare metal)", 13, 10, 0
str_sess_gpt_skip:  db "[PAOS64] L6 gui: session persist selftest SKIPPED: ahci0 tail sector carries a backup GPT header (desktop-safe) [desktop.session.persist.skipped.gpt_backup]", 13, 10, 0
str_sess_skip:      db "[PAOS64] L6 gui: no persistent block device -> session restore skipped", 13, 10, 0

; saved-state (updated by session_persist; read by SESSINFO)
str_sess_dbg:       db "[PAOS64] SESSDBG persist fail step=0x", 0
str_sess_dbg_nl:    db 13, 10, 0

align 4
sess_saved_count:   dd 0
sess_restore_skipped: dd 0              ; live or explicit-recovery entries omitted from replay
sess_saved_flag:    dd 0
sess_dbg_step:      dd 0
session_ram_checkpoint_valid: db 0
session_restore_ram_offer:    db 0

; manifest working buffers (RW, in-image)
align 8
sess_manifest:      times SESS_SECTOR db 0
str_sess_kbd_owner: db "[PAOS64] L6 gui: keyboard owner after session replay = the topmost window with a focused widget", 13, 10, 0
str_sess_skipped:   db "[PAOS64] L6 gui: session replay skipped window(s) already live or reserved for explicit recovery (no duplicate shells)", 13, 10, 0
; sess_scratch..session_ram_checkpoint moved to WDATA_gui_session_restore_0_bss1 (zero-fill tail)
%endmacro
WDATA_DEFER WDATA_gui_session_restore_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_gui_session_restore_0_bss1 0
resb 4                 ; keeps sess_scratch at its WDATA offset mod 64
sess_scratch:       resb SESS_SECTOR
sess_preserve:      resb SESS_SECTOR
session_ram_checkpoint: resb SESS_SECTOR
%endmacro
WDATA_BSS_DEFER WDATA_gui_session_restore_0_bss1
; RC-task-manager verbs (APPSTAT/APPRESTART): their own block, so the pinned block above keeps its base layout.
%macro WDATA_gui_session_restore_1 0
str_verb_appstat:   db "APPSTAT", 0
str_verb_apprestart: db "APPRESTART", 0
str_as_head:    db " appstat=v1 leaked=", 0
str_as_app:     db 10, "APP[", 0
str_as_ready:   db "] state=ready", 0
str_as_stuck:   db "] state=stuck", 0
str_as_gone:    db "] state=gone", 0
str_as_unavail: db "] state=unavailable", 0
str_as_gen:     db " gen=", 0
str_as_cycles:  db " cycles=", 0
str_ar_ok:      db " apprestart=ok idx=", 0
str_ar_args:    db " apprestart=ERR args", 0
str_ar_absent:  db " apprestart=ERR not_found", 0
str_ar_stale:   db " apprestart=ERR stale", 0
str_ar_running: db " apprestart=ERR not_stuck", 0
str_ar_refused: db " apprestart=ERR refused", 0
%endmacro
WDATA_DEFER WDATA_gui_session_restore_1

; Exact legacy recovery titles; no change to the saved manifest layout.
%macro WDATA_gui_session_restore_2 0
str_sess_recovery_console: db "PaOS_Console", 0
str_sess_recovery_console_old: db "PaOS Console", 0
%endmacro
WDATA_DEFER WDATA_gui_session_restore_2
