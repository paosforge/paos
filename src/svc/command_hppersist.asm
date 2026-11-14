;; MODULE svc/command_hppersist
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS hotpatch_persist_replay, hotpatch_persist_selftest, hp_persist_commit, hp_persist_clear_store, hp_persist_test_declare
;; IMPORTS boot/serial, core/lib/ed25519, svc/hotpatch, fs/blockdev, fs/storage_access, dev/blk/nvme, dev/blk/ahci, svc/command, svc/command_auth, svc/command_udp
;; CAPS
;; OWNER saga:hotpatch
; ============================================================================
; svc/command_hppersist.asm — hot-patch PERSISTENCE (1107): make a live patch STICK
; across a reboot. The 1018/1106 patcher is RAM-only — a committed detour vanishes on
; reset, so a task the loop "implemented" via hot-patch is gone and box/ESP/git diverge.
; This folds the ACTIVE patch into a small manifest written to a RESERVED GPT-gap scratch
; sector on the persistent block device, and RE-APPLIES it at boot.
;
; WHY A MANIFEST, NOT PE-SURGERY: re-applying a recorded {symbol, body} at boot reuses
; the PROVEN 1106 machinery (hp_resolve_symbol -> lea address (G1-safe), hotpatch_arena_init,
; hotpatch_write_detour) unchanged. Folding bytes into the on-disk PE image would need a
; second, unproven relocation path. The manifest is the smaller, safer seam.
;
; SAFE-WRITE (temp-then-swap, the 9374c2 / fat32_writefile defense — a failed write can
; NEVER corrupt the good keep): write the new manifest to the TMP sector, read it back and
; require byte-equality, and ONLY THEN commit it to the PRIMARY sector. A torn/failed TMP
; write leaves PRIMARY (the last-good manifest) intact. And crucially we ONLY ever touch the
; two GPT-gap scratch LBAs (0x700/0x708, the 1027b allowlist, VERIFIED clear of ESP/Windows/
; recovery on the real disk) — the bootable keep is structurally never written here, so even
; a power-loss mid-write can at worst drop the patch, never brick the box.
;
; AUTHENTICATED MANIFEST: HPMANIF2 reserves the final 64 bytes for an Ed25519
; signature over a canonical copy of the complete sector. CRC remains an
; integrity check, never executable authority. PaOS has no enrolled owner
; persistence key/signer, so release commit/replay is disabled. A QEMU-only
; fixture proves valid signed replay and invalid-signature refusal.
; ============================================================================

; --- manifest sector layout (single persisted patch; 512B sector) -----------
HPM_MAGIC_OFF   equ 0        ; 8 bytes  "HPMANIF2"
HPM_PRESENT     equ 8        ; dd  1 = one patch present, 0 = none/cleared
HPM_BODYLEN     equ 12       ; dd  patch body length (bytes)
HPM_BODYCRC     equ 16       ; dd  zlib/IEEE CRC32 of the body (integrity + host contract)
HPM_SYMLEN      equ 20       ; dd  symbol-name length (<=23)
HPM_SYM         equ 24       ; 24 bytes  target symbol name (NUL-padded)
HPM_GRADELEN    equ 48       ; dd  rendered STATUS-hook grade length
HPM_GRADECRC    equ 52       ; dd  CRC32 of the rendered grade bytes
HPM_BODY        equ 64       ; body bytes start here
HPM_GRADE       equ 320      ; expected rendered bytes (after max-size body)
HPM_SIGNATURE   equ 448      ; detached Ed25519 signature (64 bytes)
HPM_SIGLEN      equ 64
HPM_SECTOR      equ 512      ; canonical transcript: full sector, signature zeroed
HPM_BODYMAX     equ 256      ; body cap (64 fits + margin; keeps one sector)
HPM_GRADEMAX    equ 128      ; enough for either existing STATUS-path slot

HPM_LBA_PRIMARY equ PERSIST_GAP_LBA_PRIMARY ; committed manifest  (1027b allowlist LBA0, GPT-gap verified)
HPM_LBA_TMP     equ PERSIST_GAP_LBA_TMP     ; temp-then-swap slot  (1027b allowlist LBA1, GPT-gap verified)
HPM_LBA_TEST_A  equ 8        ; fallback only inside the QEMU-device-gated fixture
HP_REC_STATE_SIZE equ hp_rec_state_end - hp_rec_active

; HPPERSISTTEST <exact-device-name> <first-decimal-lba> <count-decimal> TEST
; One foreground transaction, at most 16 nominated sectors. The signed fixture
; uses only the first one. It never creates production executable persistence.
HPT_ARG_MAX equ 96
HPT_NAME_MAX equ 31
HPT_EXTENT_MAX equ 16

hp_persist_test_declare:
%if PAOS_PUBLIC_BUILD
    ret
%else
    lea  rdi, [rel str_hpt_verb]
    lea  rsi, [rel cmd_verb_hppersisttest]
    mov  rdx, CMD_AUTH_CAP_HOTPATCH
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1
    jmp  command_register_verb

%endif

%if !PAOS_PUBLIC_BUILD
; Strict decimal token: RSI=current cursor, ECX=bytes remaining through NUL.
; -> RAX=value, advances RSI/ECX past one separating space; CF=1 on malformed
; or overflowing input. Unlike the old block parser, never accepts a prefix.
hp_test_decimal:
    xor  eax, eax
    xor  r8d, r8d
.digit:
    test ecx, ecx
    jz   .bad
    movzx edx, byte [rsi]
    cmp  dl, ' '
    je   .end
    sub  edx, '0'
    cmp  edx, 9
    ja   .bad
    mov  r9d, edx
    mov  r10d, 10
    mul  r10
    test rdx, rdx
    jnz  .bad
    add  rax, r9
    jc   .bad
    inc  r8d
    inc  rsi
    dec  ecx
    jmp  .digit
.end:
    test r8d, r8d
    jz   .bad
    inc  rsi
    dec  ecx
    clc
    ret
.bad:
    stc
    ret

; Called only by a registry handler. Refusal before taking the busy byte never
; clears another frame's context/grant. Depth-1 and the busy guard reject nested
; reentry, including during gate reads or fixture callbacks.
cmd_verb_hppersisttest:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rsi                       ; typed response
    mov  r12, rdi                       ; request
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_VAL], 0
    cmp  byte [rel cmd_in_dispatch], 1
    jne  .out
    cmp  dword [rel cmd_dispatch_depth], 1
    jne  .out
    cmp  byte [rel hp_test_busy], 0
    jne  .out
    ; The signed fixture reuses the upload arena. A live or unconfirmed patch
    ; owns those bytes until successful REVERT; refuse before owning any state.
    cmp  byte [rel hp_rec_active], 0
    jne  .out
    call storage_access_request_owner
    cmp  eax, 1
    jne  .auth
    mov  byte [rel hp_test_busy], 1
    mov  rsi, [r12 + REQ_ARG]
    test rsi, rsi
    jz   .cleanup
    ; Bound the entire grammar before copying a name or resolving a device.
    xor  ecx, ecx
.length:
    cmp  ecx, HPT_ARG_MAX
    jae  .cleanup
    cmp  byte [rsi + rcx], 0
    je   .length_ok
    inc  ecx
    jmp  .length
.length_ok:
    inc  ecx                           ; include the terminator in cursor budget
    lea  rdi, [rel hp_test_name]
    xor  edx, edx
.name:
    mov  al, [rsi]
    cmp  al, ' '
    je   .name_end
    cmp  al, 0x21
    jb   .cleanup
    cmp  al, 0x7e
    ja   .cleanup
    cmp  edx, HPT_NAME_MAX
    jae  .cleanup
    mov  [rdi + rdx], al
    inc  edx
    inc  rsi
    dec  ecx
    jmp  .name
.name_end:
    test edx, edx
    jz   .cleanup
    mov  byte [rdi + rdx], 0
    mov  [rel hp_test_name_len], edx
    inc  rsi
    dec  ecx
    call hp_test_decimal
    jc   .cleanup
    mov  r13, rax                       ; first sector
    call hp_test_decimal
    jc   .cleanup
    test rax, rax
    jz   .cleanup
    cmp  rax, HPT_EXTENT_MAX
    ja   .cleanup
    mov  r14, rax                       ; count
    cmp  ecx, 5
    jne  .cleanup
    cmp  dword [rsi], 'TEST'
    jne  .cleanup
    cmp  byte [rsi + 4], 0
    jne  .cleanup
    mov  rax, r13
    add  rax, r14
    jc   .cleanup                       ; exclusive extent must not wrap
    lea  rdi, [rel hp_test_name]
    mov  esi, [rel hp_test_name_len]
    call blk_find_named
    test rax, rax
    jz   .cleanup
    mov  r15, rax
    ; The first supported disposable backend is the existing singleton NVMe
    ; device. Tie its model helper to that exact handle, never a global model
    ; attached to an unrelated selected AHCI device.
    lea  rdx, [rel nvme_devs]
    cmp  r15, rdx
    jne  .cleanup
    lea  rdx, [rel nvme_ops]
    cmp  [r15 + dev.ops], rdx
    jne  .cleanup
    cmp  dword [r15 + dev.class], CLASS_BLOCK
    jne  .cleanup
    cmp  dword [r15 + dev.health], HEALTH_OK
    jne  .cleanup
    test dword [r15 + dev.flags], BLKF_RO | BLKF_REMOVABLE
    jnz  .cleanup
    mov  rdx, [r15 + dev.info]
    test rdx, rdx
    jz   .cleanup
    cmp  dword [rdx + blk_info.logical_sector_bytes], 512
    jne  .cleanup
    test dword [rdx + blk_info.flags], BLKF_RO | BLKF_REMOVABLE
    jnz  .cleanup
    cmp  byte [rdx + blk_info.removable], 0
    jne  .cleanup
    mov  rax, [rdx + blk_info.capabilities]
    and  eax, BLKCAP_ALL_IO
    cmp  eax, BLKCAP_ALL_IO
    jne  .cleanup
    mov  rax, r13
    add  rax, r14
    dec  rax
    cmp  rax, [rdx + blk_info.lba_max]
    ja   .cleanup
    mov  rax, [rdx + blk_info.media_generation]
    test rax, rax
    jz   .cleanup
    mov  [rel hp_test_generation], rax
    mov  [rel hp_test_device], r15
    mov  [rel hp_test_first], r13
    mov  [rel hp_test_count], r14
    call nvme_model_is_qemu
    cmp  eax, 1
    jne  .cleanup
    mov  rdi, r15
    mov  rsi, r13
    mov  rdx, r14
    call storage_access_classify
    cmp  eax, SA_CLASS_TEST_SCRATCH
    jne  .cleanup                       ; even SPECIAL may not nominate a GPT/foreign range
    mov  byte [rel hp_test_active], 1
    call hp_test_resolve                 ; gate read may have invalidated the medium
    test rax, rax
    jz   .cleanup
    call hotpatch_persist_selftest
    test eax, eax
    jnz  .cleanup
    mov  qword [rbx + RSP_CODE], CMDE_OK
    mov  qword [rbx + RSP_VAL], 1
.cleanup:
    call storage_access_grants_clear     ; this depth-1 synchronous action owns its grants
    lea  rdi, [rel hp_test_context]
    xor  esi, esi
    mov  edx, hp_test_context_end - hp_test_context
    call memset
    jmp  .out
.auth:
    mov  qword [rbx + RSP_CODE], CMDE_AUTHDENY
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%endif

; Resolve only the live transaction, with no probing or fallback. Lookup checks
; registry membership before dereferencing the saved pointer's info.
hp_test_resolve:
    cmp  byte [rel hp_test_active], 1
    jne  .none
    cmp  dword [rel cmd_dispatch_depth], 1
    jne  .none
    lea  rdi, [rel hp_test_name]
    mov  esi, [rel hp_test_name_len]
    call blk_find_named
    test rax, rax
    jz   .none
    cmp  rax, [rel hp_test_device]
    jne  .none
    lea  rdx, [rel nvme_ops]
    cmp  [rax + dev.ops], rdx
    jne  .none
    cmp  dword [rax + dev.class], CLASS_BLOCK
    jne  .none
    test dword [rax + dev.flags], BLKF_RO | BLKF_REMOVABLE
    jnz  .none
    mov  rdx, [rax + dev.info]
    test rdx, rdx
    jz   .none
    mov  rcx, [rdx + blk_info.media_generation]
    cmp  rcx, [rel hp_test_generation]
    jne  .none
    cmp  dword [rdx + blk_info.logical_sector_bytes], 512
    jne  .none
    test dword [rdx + blk_info.flags], BLKF_RO | BLKF_REMOVABLE
    jnz  .none
    cmp  byte [rdx + blk_info.removable], 0
    jne  .none
    mov  rcx, [rdx + blk_info.capabilities]
    and  ecx, BLKCAP_ALL_IO
    cmp  ecx, BLKCAP_ALL_IO
    jne  .none
    mov  rcx, [rel hp_test_first]
    add  rcx, [rel hp_test_count]
    jc   .none
    dec  rcx
    cmp  rcx, [rdx + blk_info.lba_max]
    ja   .none
    ret
.none:
    xor  eax, eax
    ret

hp_sector_device:                      ; RDI=lba -> RAX=selected device / 0
    cmp  byte [rel hp_test_busy], 0
    je   hp_persist_dev
    push rbx
    mov  rbx, rdi
    call hp_test_resolve
    test rax, rax
    jz   .out
    sub  rbx, [rel hp_test_first]
    jb   .none
    cmp  rbx, [rel hp_test_count]
    jb   .out
.none:
    xor  eax, eax
.out:
    pop  rbx
    ret

; This fixture's model helper belongs to one NVMe instance. Never use that
; global model to bless another selected backend.
hp_fixture_qemu:
    lea  rdx, [rel nvme_devs]
    cmp  rax, rdx
    jne  .none
    jmp  nvme_model_is_qemu
.none:
    xor  eax, eax
    ret

; -> RAX=fixture sector, or -1 unavailable. Runtime stores nominate their own
; first sector. Legacy fixture geometry comes from that same selected device.
hp_fixture_sector:
    call hp_persist_dev
    test rax, rax
    jz   .none
    cmp  byte [rel hp_test_active], 1
    jne  .legacy
    mov  rax, [rel hp_test_first]
    ret
.legacy:
    mov  rdx, [rax + dev.info]
    test rdx, rdx
    jz   .none
    mov  rax, [rdx + blk_info.lba_max]
    test rax, rax
    jz   .fallback
    dec  rax
    ret
.fallback:
    mov  eax, HPM_LBA_TEST_A
    ret
.none:
    mov  rax, -1
    ret

; ---------------------------------------------------------------------------
; hp_persist_dev -> RAX = the descriptor-owned healthy SYSTEM disk or 0.
; The original Lenovo used NVMe; the replacement target's ESP is on AHCI while a
; second AHCI disk holds DATA. Resolve that system disk by the exact IDENTIFY
; model+serial generated from primary_target.json, never by HBA port order. Keep
; exact-name healthy NVMe as the QEMU/older-target fallback. blk_select would
; choose volatile RAMBLK and the command-layer prefix walker accepts degraded
; devices, so neither is a persistence authority. clobbers caller-saved.
; ---------------------------------------------------------------------------
hp_persist_dev:
    cmp  byte [rel hp_test_busy], 0
    jne  hp_test_resolve
%ifndef COG_MODEL_ENABLED
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
%error "public build requires explicit COG_MODEL_ENABLED"
%endif
%endif
%define COG_MODEL_ENABLED 1
%endif
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0 && COG_MODEL_ENABLED != 0
%error "public build requires COG_MODEL_ENABLED=0"
%endif
%endif
%if COG_MODEL_ENABLED = 0
    ; No descriptor-owned persistence disk exists in this optional profile.
    ; Refuse selection entirely, including the historical nvme0 fallback.
    xor eax, eax
    ret
%else
    lea  rdi, [rel hp_system_disk_model]
    lea  rsi, [rel hp_system_disk_serial]
    call ahci_find_identity
    test rax, rax
    jnz  .found
    lea  rdi, [rel str_nvme_name]           ; "nvme0"
    mov  esi, 5
    call blk_find_named
.found:
    ret
%endif

; hp_sector_write(RDI=lba, RSI=srcbuf) -> RAX 0 ok / -1 err. If a live
; transaction selected a nonzero hp_persist_stage, advance it before FLUSH so
; the authenticated reply distinguishes the write from the durability barrier.
hp_sector_write:
    push rbx
    push r12
    push r13
    mov  r12, rdi                           ; lba
    mov  rbx, rsi                           ; buf
    call hp_sector_device
    test rax, rax
    jz   .err
    mov  r13, rax                          ; pin same device for grant/write/flush
    mov  rdi, rax
    mov  rsi, r12
    mov  edx, 1
    lea  r8, [rel str_hp_sa_caller]
    call storage_access_require_request
    test rax, rax
    jnz  .err
    mov  rdi, r12
    call hp_sector_device
    test rax, rax
    jz   .err
    cmp  rax, r13
    jne  .err
    cmp  byte [rel hp_test_busy], 0
    je   .write
    mov  rdi, r13
    mov  rsi, r12
    mov  edx, 1
    call storage_access_classify
    cmp  eax, SA_CLASS_TEST_SCRATCH
    jne  .err
    mov  rdi, r12
    call hp_sector_device
    cmp  rax, r13
    jne  .err
.write:
    mov  rdi, rax
    mov  rsi, r12
    mov  rdx, 1
    mov  rcx, rbx
    call blk_write
    test rax, rax
    jnz  .err
    cmp  byte [rel hp_persist_stage], 0
    je   .flush
    inc  byte [rel hp_persist_stage]
.flush:
    mov  rdi, r12
    call hp_sector_device
    test rax, rax
    jz   .err
    cmp  rax, r13
    jne  .err
    mov  rdi, rax
    call blk_flush
    test rax, rax
    jnz  .err
    xor  eax, eax
    jmp  .out
.err:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; hp_sector_read(RDI=lba, RSI=dstbuf) -> RAX 0 ok / -1 err (reads 1 sector).
hp_sector_read:
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
    call hp_sector_device
    test rax, rax
    jz   .err
    mov  rdi, rax
    mov  rsi, r12
    mov  rdx, 1
    mov  rcx, rbx
    call blk_read
    test rax, rax
    jnz  .err
    xor  eax, eax
    jmp  .out
.err:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; hp_memeq(RDI=a, RSI=b, ECX=len) -> RAX 1 equal / 0 not. clobbers RAX,RCX,RDI,RSI.
hp_memeq:
.l:
    test ecx, ecx
    jz   .eq
    mov  al, [rdi]
    cmp  al, [rsi]
    jne  .ne
    inc  rdi
    inc  rsi
    dec  ecx
    jmp  .l
.eq:
    mov  eax, 1
    ret
.ne:
    xor  eax, eax
    ret

; hp_capture_status_grade(RDI=existing STATUS-path target, RSI=dst) -> EAX=len | 0.
; The only HP_ELIG_SINGLE_FN slots are reply-builder hooks whose ABI is
; RBX=reply base and R15D=cursor. Invoking the live detour here measures the
; patched behavior after it was armed; a manifest latch cannot manufacture the
; per-delivery bytes written by the uploaded body.
hp_capture_status_grade:
    push rbx
    push r12
    push r15
    mov  r12, rdi
    mov  rbx, rsi
    xor  r15d, r15d
    call r12
    mov  eax, r15d
    test eax, eax
    jz   .bad
    cmp  eax, HPM_GRADEMAX
    ja   .bad
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r12
    pop  rbx
    ret

; hp_persist_verify_grade(RDI=live target, RSI=valid manifest) -> RAX 1 match / 0.
; Re-invokes the replayed body and compares the exact rendered bytes captured
; before persistence. This is the content gate behind replay.ok.
hp_persist_verify_grade:
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
    lea  rsi, [rel hp_grade_verify]
    mov  rdi, r12
    call hp_capture_status_grade
    cmp  eax, [rbx + HPM_GRADELEN]
    jne  .no
    mov  ecx, eax
    lea  rdi, [rel hp_grade_verify]
    lea  rsi, [rbx + HPM_GRADE]
    call hp_memeq
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; hp_mani_pack(RDI=symname cstr, RSI=body ptr, EDX=bodylen) — build a manifest sector
;   into hp_mani_buf. Recomputes body CRC authoritatively. clobbers caller-saved.
;   Assumes bodylen <= HPM_BODYMAX (caller-checked).
; ---------------------------------------------------------------------------
hp_mani_pack:
    push rbx
    push r12
    push r13
    mov  r12, rdi                           ; sym
    mov  r13, rsi                           ; body
    mov  ebx, edx                           ; len
    lea  rdi, [rel hp_mani_buf]             ; zero the whole sector
    mov  ecx, HPM_SECTOR
    xor  al, al
    cld
    rep  stosb
    lea  rdi, [rel hp_mani_buf]             ; magic (exactly 8 bytes)
    lea  rsi, [rel str_hpm_magic]
    mov  ecx, 8
    rep  movsb
    mov  dword [rel hp_mani_buf + HPM_PRESENT], 1
    mov  [rel hp_mani_buf + HPM_BODYLEN], ebx
    mov  rdi, r13                           ; body CRC
    mov  esi, ebx
    call hotpatch_crc32
    mov  [rel hp_mani_buf + HPM_BODYCRC], eax
    mov  rsi, r12                           ; symbol name (<=23 + NUL)
    lea  rdi, [rel hp_mani_buf + HPM_SYM]
    xor  ecx, ecx
.symcp:
    mov  al, [rsi + rcx]
    mov  [rdi + rcx], al
    test al, al
    jz   .symdone
    inc  ecx
    cmp  ecx, 23
    jb   .symcp
.symdone:
    mov  [rel hp_mani_buf + HPM_SYMLEN], ecx
    mov  rsi, r13                           ; body bytes
    lea  rdi, [rel hp_mani_buf + HPM_BODY]
    mov  ecx, ebx
    rep  movsb
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; hp_persist_build -> RAX 1 packed / 0 no active record / 2 content ungradeable.
; Reads the COMMIT-time snapshot in hp_rec_* and invokes the active STATUS-path
; detour to persist its exact rendered bytes beside the body.
; ---------------------------------------------------------------------------
hp_persist_build:
    cmp  byte [rel hp_rec_active], 1
    jne  .none
    mov  edx, [rel hp_rec_bodylen]
    test edx, edx
    jz   .none
    cmp  edx, HPM_BODYMAX
    ja   .none
    lea  rdi, [rel hp_rec_symname]
    mov  rsi, [rel hp_rec_slot]             ; body bytes live in the arena slot
    call hp_mani_pack
    mov  rdi, [rel hp_rec_target]
    lea  rax, [rel general_probe_field]
    cmp  rdi, rax
    je   .capture
    lea  rax, [rel status_hotpatch_hook]
    cmp  rdi, rax
    jne  .ungradeable                        ; never invoke a future non-STATUS ABI
.capture:
    lea  rsi, [rel hp_mani_buf + HPM_GRADE]
    call hp_capture_status_grade
    test eax, eax
    jz   .ungradeable
    mov  [rel hp_mani_buf + HPM_GRADELEN], eax
    mov  esi, eax
    lea  rdi, [rel hp_mani_buf + HPM_GRADE]
    call hotpatch_crc32
    mov  [rel hp_mani_buf + HPM_GRADECRC], eax
    mov  eax, 1
    ret
.ungradeable:
    mov  eax, 2
    ret
.none:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; hp_persist_valid(RSI=manifest buf) -> RAX 1 valid / 0. Magic + present + body-len
;   range + sym-len range + CRC(body)==body_crc (a torn write fails CRC -> ignored).
;   clobbers RAX,RCX,RDX,RDI.
; ---------------------------------------------------------------------------
hp_persist_valid:
    mov  rdi, rsi                           ; magic compare (8 bytes)
    lea  rdx, [rel str_hpm_magic]
    mov  ecx, 8
.mchk:
    mov  al, [rdi]
    cmp  al, [rdx]
    jne  .no
    inc  rdi
    inc  rdx
    dec  ecx
    jnz  .mchk
    cmp  dword [rsi + HPM_PRESENT], 1
    jne  .no
    mov  ecx, [rsi + HPM_BODYLEN]
    test ecx, ecx
    jz   .no
    cmp  ecx, HPM_BODYMAX
    ja   .no
    cmp  dword [rsi + HPM_SYMLEN], 23
    ja   .no
    mov  ecx, [rsi + HPM_GRADELEN]
    test ecx, ecx
    jz   .no
    cmp  ecx, HPM_GRADEMAX
    ja   .no
    push rsi                                ; CRC over the rendered behavior token
    lea  rdi, [rsi + HPM_GRADE]
    mov  esi, ecx
    call hotpatch_crc32
    pop  rsi
    cmp  eax, [rsi + HPM_GRADECRC]
    jne  .no
    mov  ecx, [rsi + HPM_BODYLEN]
    push rsi                                ; CRC over the body
    lea  rdi, [rsi + HPM_BODY]
    mov  esi, ecx
    call hotpatch_crc32
    pop  rsi
    cmp  eax, [rsi + HPM_BODYCRC]
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hp_persist_signature_valid(RDI=owner public32, RSI=manifest) -> EAX 1/0.
; Authentication covers every manifest byte after canonicalizing only the
; detached-signature field to zero. Structural/CRC validity is never authority.
hp_persist_signature_valid:
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
    test r12, r12
    jz   .no
    mov  rsi, rbx
    call hp_persist_valid
    test eax, eax
    jz   .no
    lea  rdi, [rel hp_mani_auth]
    mov  rsi, rbx
    mov  edx, HPM_SECTOR
    call memcpy
    lea  rdi, [rel hp_mani_auth + HPM_SIGNATURE]
    xor  esi, esi
    mov  edx, HPM_SIGLEN
    call memset
    mov  rdi, r12
    mov  esi, 32
    lea  rdx, [rel hp_mani_auth]
    mov  ecx, HPM_SECTOR
    lea  r8, [rbx + HPM_SIGNATURE]
    mov  r9d, HPM_SIGLEN
    call ed25519_verify
    test eax, eax
    setz al
    movzx eax, al
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; hp_persist_apply(RDI=owner public32, RSI=manifest) -> RAX 1 applied / 0.
; Signature verification is repeated inside this mutating primitive and occurs
; before symbol resolution, arena copy, saved-byte updates, or detour writes.
; ---------------------------------------------------------------------------
hp_persist_apply:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15, rdi                           ; executable authority
    mov  rbx, rsi                           ; manifest
    mov  rdi, r15
    mov  rsi, rbx
    call hp_persist_signature_valid
    test eax, eax
    jz   .no
    lea  rdi, [rbx + HPM_SYM]
    call hp_resolve_symbol                  ; RAX = symtab entry / 0
    test rax, rax
    jz   .no
    mov  r12, rax
    cmp  dword [r12 + HP_SYM_ELIG], HP_ELIG_SINGLE_FN
    jne  .no                                ; boot-path/etc -> never arm
    mov  r13, [r12 + HP_SYM_ADDR]           ; runtime target VA (lea-filled by symtab_init)
    test r13, r13
    jz   .no
    call hp_upload_arena_init               ; RAX = guarded executable arena slot
    mov  r14, rax
    test r14, r14
    jz   .no
    mov  ecx, [rbx + HPM_BODYLEN]           ; copy body -> slot
    mov  rsi, rbx
    add  rsi, HPM_BODY
    mov  rdi, r14
    cld
    rep  movsb
    mov  rdi, r14                           ; defensive re-CRC of the in-slot body
    mov  esi, [rbx + HPM_BODYLEN]
    call hotpatch_crc32
    cmp  eax, [rbx + HPM_BODYCRC]
    jne  .no
    mov  rdi, r14
    call hp_upload_canaries_intact
    test eax, eax
    jz   .no
    mov  ecx, [r13]                         ; save target's 5 entry bytes
    mov  [rel hp_rec_saved], ecx
    mov  cl, [r13 + 4]
    mov  [rel hp_rec_saved + 4], cl
    mov  rdi, r13                           ; arm the detour
    mov  rsi, r14
    call hotpatch_write_detour              ; RAX 1 armed / 0 refused (range)
    test rax, rax
    jz   .no
    mov  rdi, r13                           ; invoke the replayed STATUS-path body
    mov  rsi, rbx                           ; and require byte-exact pre-reboot content
    call hp_persist_verify_grade
    test rax, rax
    jnz  .graded
    mov  rdi, r13                           ; content mismatch -> undo before returning
    lea  rsi, [rel hp_rec_saved]
    call hotpatch_restore_bytes
    jmp  .no
.graded:
    mov  [rel hp_rec_target], r13           ; rebuild the active record
    mov  [rel hp_rec_slot], r14
    mov  byte [rel hp_rec_active], 1
    mov  ecx, [rbx + HPM_BODYLEN]
    mov  [rel hp_rec_bodylen], ecx
    mov  ecx, [rbx + HPM_BODYCRC]
    mov  [rel hp_rec_bodycrc], ecx
    lea  rsi, [rbx + HPM_SYM]               ; keep the symbol for a re-PERSIST
    lea  rdi, [rel hp_rec_symname]
    call hp_copy_symname
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; hp_persist_commit -> 0 no active patch / 6 release-disabled. No owner
; Ed25519 key or signer is enrolled, so release code cannot create executable
; persistence and never reaches the raw-sector helpers above.
; ---------------------------------------------------------------------------
hp_persist_commit:
    mov  byte [rel hp_persist_stage], 0
    cmp  byte [rel hp_rec_active], 1
    jne  .none
    mov  eax, 6
    ret
.none:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; hp_persist_clear_store -> 3 release-disabled. Release creates and replays no
; executable manifests, so this public command performs no raw-sector mutation.
; ---------------------------------------------------------------------------
hp_persist_clear_store:
    mov  byte [rel hp_persist_stage], 0
    mov  eax, 3
    ret

; ---------------------------------------------------------------------------
; hotpatch_persist_replay — release-disabled BOOT hook. There is no enrolled
; owner Ed25519 key, so release boot does not read, copy, or detour persisted
; executable data. The signed path exists only in the QEMU fixture.
; ---------------------------------------------------------------------------
hotpatch_persist_replay:
    ; Release replay is disabled: no owner Ed25519 key, disk read, copy, or detour.
    ret

; ---------------------------------------------------------------------------
; hotpatch_persist_selftest — QEMU-only signed persistence fixture. It drives
; the real DATA hostile matrix, signs the complete manifest, round-trips it
; through a disposable QEMU namespace, proves a CRC-valid/signature-invalid
; twin cannot change code/record/guards, then applies, content-grades, and
; restores the valid signed read-back twin. The exact QEMU-device gate precedes
; all fixture block I/O; release/metal performs none.
; ---------------------------------------------------------------------------
hotpatch_persist_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15d, 1                         ; skipped unless the signed fixture succeeds

    call hp_persist_dev
    test rax, rax
    jz   .skip
    call hp_fixture_qemu                    ; selected device, before fixture block I/O
    test rax, rax
    jz   .metal

    call hp_upload_bounds_selftest
    test eax, eax
    jz   .bounds_ok
    mov  edi, eax
    push rdi
    lea  rdi, [rel str_hpp_bounds_mask]
    call serial_string
    pop  rdi
    call serial_hex64
    call serial_newline
    lea  rdi, [rel str_hpp_fail_bounds]
    jmp  .fail_early
.bounds_ok:

    ; PIC STATUS body: render a per-boot eight-byte nonce.
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rcx, 0x3021E5B0C0FFEE11
    xor  rax, rcx
    mov  r14, rax
    lea  rdi, [rel hp_security_body]
    mov  byte [rdi + 0], 0x48
    mov  byte [rdi + 1], 0xB8
    mov  [rdi + 2], r14
    mov  byte [rdi + 10], 0x4A
    mov  byte [rdi + 11], 0x89
    mov  byte [rdi + 12], 0x04
    mov  byte [rdi + 13], 0x3B
    mov  byte [rdi + 14], 0x41
    mov  byte [rdi + 15], 0x83
    mov  byte [rdi + 16], 0xC7
    mov  byte [rdi + 17], 0x08
    mov  byte [rdi + 18], 0xC3

    lea  rdi, [rel str_hps_gpf_name]
    lea  rsi, [rel hp_security_body]
    mov  edx, 19
    call hp_mani_pack
    mov  dword [rel hp_mani_buf + HPM_GRADELEN], 8
    mov  [rel hp_mani_buf + HPM_GRADE], r14
    lea  rdi, [rel hp_mani_buf + HPM_GRADE]
    mov  esi, 8
    call hotpatch_crc32
    mov  [rel hp_mani_buf + HPM_GRADECRC], eax

    ; Sign the canonical full-sector transcript while signature bytes are zero.
    lea  rdi, [rel hp_mani_auth]
    lea  rsi, [rel hp_mani_buf]
    mov  edx, HPM_SECTOR
    call memcpy
    lea  rdi, [rel hp_security_seed]
    mov  esi, 32
    lea  rdx, [rel hp_mani_auth]
    mov  ecx, HPM_SECTOR
    lea  r8, [rel hp_mani_buf + HPM_SIGNATURE]
    mov  r9d, HPM_SIGLEN
    call ed25519_sign
    test eax, eax
    jnz  .fail_sign

    ; Use the same disposable last-LBA fixture as the existing NVMe selftest.
    call hp_fixture_sector
    cmp  rax, -1
    je   .fail_store
    mov  r12, rax
    mov  rdi, r12
    lea  rsi, [rel hp_mani_buf]
    call hp_sector_write
    test eax, eax
    jnz  .fail_store
    mov  rdi, r12
    lea  rsi, [rel hp_mani_verify]
    call hp_sector_read
    test eax, eax
    jnz  .fail_store
    lea  rdi, [rel hp_mani_buf]
    lea  rsi, [rel hp_mani_verify]
    mov  ecx, HPM_SECTOR
    call hp_memeq
    cmp  eax, 1
    jne  .fail_store
    lea  rdi, [rel str_hpp_esp_write]
    call serial_string

    lea  rsi, [rel hp_mani_verify]
    call hp_persist_valid
    cmp  eax, 1
    jne  .fail_structure

    ; Snapshot all state the invalid-signature path is forbidden to alter.
    lea  rdx, [rel general_probe_field]
    mov  rax, [rdx]
    mov  [rel hp_security_code_snapshot], rax
    lea  rdi, [rel hp_security_rec_snapshot]
    lea  rsi, [rel hp_rec_active]
    mov  edx, HP_REC_STATE_SIZE
    call memcpy
    call hp_upload_arena_init
    mov  r13, rax
    test r13, r13
    jz   .fail_arena

    xor  byte [rel hp_mani_verify + HPM_SIGNATURE + 7], 0x80
    lea  rsi, [rel hp_mani_verify]
    call hp_persist_valid                    ; remains structurally and CRC valid
    cmp  eax, 1
    jne  .fail_invalid_structure
    lea  rdi, [rel hp_security_public]
    lea  rsi, [rel hp_mani_verify]
    call hp_persist_apply
    xor  byte [rel hp_mani_verify + HPM_SIGNATURE + 7], 0x80
    test eax, eax
    jnz  .fail_invalid_accept
    lea  rdx, [rel general_probe_field]
    mov  rax, [rdx]
    cmp  rax, [rel hp_security_code_snapshot]
    jne  .fail_invalid_code
    lea  rdi, [rel hp_security_rec_snapshot]
    lea  rsi, [rel hp_rec_active]
    mov  ecx, HP_REC_STATE_SIZE
    call hp_memeq
    cmp  eax, 1
    jne  .fail_invalid_record
    mov  rdi, r13
    call hp_upload_canaries_intact
    cmp  eax, 1
    jne  .fail_invalid_guard

    ; The byte-identical valid signed twin must copy, detour, and render nonce.
    lea  rdi, [rel hp_security_public]
    lea  rsi, [rel hp_mani_verify]
    call hp_persist_apply
    cmp  eax, 1
    jne  .fail_valid_apply
    cmp  byte [rel hp_rec_active], 1
    jne  .fail_valid_record
    mov  rdi, [rel hp_rec_slot]
    call hp_upload_canaries_intact
    cmp  eax, 1
    jne  .fail_valid_guard
    lea  rdi, [rel general_probe_field]
    lea  rsi, [rel hp_mani_verify]
    call hp_persist_verify_grade
    cmp  eax, 1
    jne  .fail_valid_grade

    mov  rdi, [rel hp_rec_target]
    lea  rsi, [rel hp_rec_saved]
    call hotpatch_restore_bytes
    lea  rdi, [rel hp_rec_active]
    lea  rsi, [rel hp_security_rec_snapshot]
    mov  edx, HP_REC_STATE_SIZE
    call memcpy
    lea  rdx, [rel general_probe_field]
    mov  rax, [rdx]
    cmp  rax, [rel hp_security_code_snapshot]
    jne  .fail_restore
    lea  rdi, [rel str_hpp_survive]
    call serial_string
    lea  rdi, [rel str_hpp_replay_ok]
    call serial_string
    lea  rdi, [rel str_hpp_security_pass]
    call serial_string
    xor  r15d, r15d
    jmp  .done

.fail_sign:
    lea  rdi, [rel str_hpp_fail_sign]
    jmp  .fail_early
.fail_store:
    lea  rdi, [rel str_hpp_fail_store]
    jmp  .fail_early
.fail_structure:
    lea  rdi, [rel str_hpp_fail_structure]
.fail_early:
    mov  r15d, -1
    call serial_string
    lea  rdi, [rel str_hpp_security_fail]
    call serial_string
    jmp  .done
.fail_arena:
    lea  rdi, [rel str_hpp_fail_arena]
    jmp  .fail_mutating
.fail_invalid_structure:
    xor  byte [rel hp_mani_verify + HPM_SIGNATURE + 7], 0x80
    lea  rdi, [rel str_hpp_fail_invalid_structure]
    jmp  .fail_mutating
.fail_invalid_accept:
    lea  rdi, [rel str_hpp_fail_invalid_accept]
    jmp  .fail_mutating
.fail_invalid_code:
    lea  rdi, [rel str_hpp_fail_invalid_code]
    jmp  .fail_mutating
.fail_invalid_record:
    lea  rdi, [rel str_hpp_fail_invalid_record]
    jmp  .fail_mutating
.fail_invalid_guard:
    lea  rdi, [rel str_hpp_fail_invalid_guard]
    jmp  .fail_mutating
.fail_valid_apply:
    lea  rdi, [rel str_hpp_fail_valid_apply]
    jmp  .fail_mutating
.fail_valid_record:
    lea  rdi, [rel str_hpp_fail_valid_record]
    jmp  .fail_mutating
.fail_valid_guard:
    lea  rdi, [rel str_hpp_fail_valid_guard]
    jmp  .fail_mutating
.fail_valid_grade:
    lea  rdi, [rel str_hpp_fail_valid_grade]
    jmp  .fail_mutating
.fail_restore:
    lea  rdi, [rel str_hpp_fail_restore]
.fail_mutating:
    mov  r15d, -1
    mov  r12, rdi
    cmp  byte [rel hp_rec_active], 1
    jne  .restore_record
    mov  rdi, [rel hp_rec_target]
    lea  rsi, [rel hp_rec_saved]
    call hotpatch_restore_bytes
.restore_record:
    lea  rdi, [rel hp_rec_active]
    lea  rsi, [rel hp_security_rec_snapshot]
    mov  edx, HP_REC_STATE_SIZE
    call memcpy
    mov  rdi, r12
    call serial_string
    lea  rdi, [rel str_hpp_security_fail]
    call serial_string
    jmp  .done
.metal:
    lea  rdi, [rel str_hpp_metal]
    call serial_string
    jmp  .done
.skip:
    lea  rdi, [rel str_hpp_skip]
    call serial_string
.done:
    mov  eax, r15d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Old CRC-only block fixture retained as non-assembled archaeology.
%if 0
; ---------------------------------------------------------------------------
; hotpatch_persist_selftest — QEMU BUILD gate for the two required markers. Exercises
;   the FULL write+replay path against the throwaway nvme namespace:
;     * [hotpatch.persist.esp_write]      — a packed manifest written to nvme reads
;       back byte-equal (the ESP-write path works).
;     * [hotpatch.persist.survives_reboot]— that read-back manifest validates + re-applies
;       to a live slot and CONTENT-GRADES (general_probe_field renders the random nonce),
;       then reverts clean — proving what the disk holds re-applies (survives-reboot proxy).
;   Gated to QEMU (nvme model contains "QEMU"): on the REAL disk a boot-time write to a
;   scratch sector is not done unsupervised — the un-fakeable cross-reboot grade is the
;   bare-metal UDP probe. No persistent dev -> honest skip.
; ---------------------------------------------------------------------------
hotpatch_persist_selftest_crc_only_legacy:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  r15, r15                           ; failure count
    call hp_persist_dev
    test rax, rax
    jz   .skip                              ; no persistent backend at all
    call nvme_model_is_qemu
    test rax, rax
    jz   .metal                             ; real disk: defer the write to the UDP probe

    ; --- build a PIC STATUS-hook body for general_probe_field (slot 0):
    ;     mov rax,<nonce>; mov [rbx+r15],rax; add r15d,8; ret. The random
    ;     eight-byte rendered value is captured in the manifest and must be
    ;     reproduced by the replayed detour. ---
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rcx, 0x1107E5B0C0FFEE11
    xor  rax, rcx
    mov  r14, rax                           ; R14 = random nonce (graded token)
    lea  rdi, [rel hp_scratch]
    mov  byte [rdi + 0], 0x48
    mov  byte [rdi + 1], 0xB8
    mov  [rdi + 2], r14
    mov  byte [rdi + 10], 0x4A
    mov  byte [rdi + 11], 0x89
    mov  byte [rdi + 12], 0x04
    mov  byte [rdi + 13], 0x3B
    mov  byte [rdi + 14], 0x41
    mov  byte [rdi + 15], 0x83
    mov  byte [rdi + 16], 0xC7
    mov  byte [rdi + 17], 0x08
    mov  byte [rdi + 18], 0xC3

    ; --- pack a manifest {sym="general_probe_field", body(19), grade=<nonce>} ---
    lea  rdi, [rel str_hps_gpf_name]        ; "general_probe_field" (hotpatch.asm)
    lea  rsi, [rel hp_scratch]
    mov  edx, 19
    call hp_mani_pack
    mov  dword [rel hp_mani_buf + HPM_GRADELEN], 8
    mov  [rel hp_mani_buf + HPM_GRADE], r14
    lea  rdi, [rel hp_mani_buf + HPM_GRADE]
    mov  esi, 8
    call hotpatch_crc32
    mov  [rel hp_mani_buf + HPM_GRADECRC], eax

    ; --- selftest write LBA: a HIGH in-namespace data sector. QEMU's vvfat-backed
    ;     nvme namespace REJECTS writes to low/reserved sectors (FS metadata region)
    ;     but accepts data-region writes (this is exactly what nvme's own rw.verified
    ;     uses). Clamp to the last valid LBA; fall back to a small LBA only if lba_max
    ;     is unknown. The real ESP-persist sectors (0x700/0x708) are used on bare metal
    ;     only, where the disk is huge and those live in the verified GPT gap. ---
    mov  r12, [rel nvme_lba_max]
    test r12, r12
    jz   .lba_lo
    dec  r12                                ; last valid LBA (writable data sector)
    jmp  .lba_set
.lba_lo:
    mov  r12, HPM_LBA_TEST_A
.lba_set:

    ; --- WRITE -> READBACK -> byte-equal (esp_write) ---
    mov  rdi, r12
    lea  rsi, [rel hp_mani_buf]
    call hp_sector_write
    test rax, rax
    setnz al
    movzx eax, al
    add  r15, rax
    mov  rdi, r12
    lea  rsi, [rel hp_mani_verify]
    call hp_sector_read
    test rax, rax
    setnz al
    movzx eax, al
    add  r15, rax
    lea  rdi, [rel hp_mani_buf]
    lea  rsi, [rel hp_mani_verify]
    mov  ecx, HPM_SECTOR
    call hp_memeq                           ; RAX 1 equal
    cmp  rax, 1
    setne al
    movzx eax, al
    add  r15, rax
    test r15, r15
    jnz  .replay                            ; write path failed -> no esp_write marker
    lea  rdi, [rel str_hpp_esp_write]
    call serial_string                      ; [hotpatch.persist.esp_write]

.replay:
    ; --- validate + re-apply the READ-BACK copy, content-grade, revert ---
    lea  rsi, [rel hp_mani_verify]
    call hp_persist_valid
    cmp  rax, 1
    setne al
    movzx eax, al
    add  r15, rax
    lea  rsi, [rel hp_mani_verify]
    call hp_persist_apply
    cmp  rax, 1
    setne al
    movzx eax, al
    add  r15, rax
    cmp  byte [rel hp_rec_active], 1
    jne  .grade_missing
    lea  rdi, [rel general_probe_field]
    lea  rsi, [rel hp_mani_verify]
    call hp_persist_verify_grade            ; replayed hook must render exact nonce bytes
    cmp  rax, 1
    setne al
    movzx eax, al
    add  r15, rax
    jmp  .revert
.grade_missing:
    inc  r15
.revert:
    ; revert the test detour -> clean slate (arena free for boot replay / live UDP)
    cmp  byte [rel hp_rec_active], 1
    jne  .reverted
    mov  rdi, [rel hp_rec_target]
    lea  rsi, [rel hp_rec_saved]
    call hotpatch_restore_bytes
    mov  byte [rel hp_rec_active], 0
.reverted:
    test r15, r15
    jnz  .done
    lea  rdi, [rel str_hpp_survive]
    call serial_string                      ; [hotpatch.persist.survives_reboot]
    lea  rdi, [rel str_hpp_replay_ok]
    call serial_string                      ; QEMU content-grade for task1113 marker
    jmp  .done
.metal:
    lea  rdi, [rel str_hpp_metal]
    call serial_string                      ; read-ready; write deferred to UDP probe
    jmp  .done
.skip:
    lea  rdi, [rel str_hpp_skip]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
%endif

; --- svc/command_hppersist data (RW, in-image) ------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_command_hppersist_0 0
%if !PAOS_PUBLIC_BUILD
str_hpt_verb:       db "HPPERSISTTEST", 0
%endif
str_hpm_magic:      db "HPMANIF2"                                  ; 8 bytes, no terminator
str_hpp_replayed:   db "[PAOS64] L5 svc: hotpatch persisted patch re-applied at boot from ESP scratch [hotpatch.persist.replayed]", 13, 10, 0
str_hpp_replay_ok:  db "[PAOS64] hotpatch persisted patch replayed and content verified [hotpatch.persist.replay.ok]", 13, 10, 0
str_hpp_esp_write:  db "[PAOS64] L5 svc: hotpatch signed manifest QEMU write->readback byte-equal PASS [hotpatch.persist.esp_write]", 13, 10, 0
str_hpp_survive:    db "[PAOS64] L5 svc: hotpatch persisted manifest re-applies + content-grades post-store (survives-reboot proxy) [hotpatch.persist.survives_reboot]", 13, 10, 0
str_hpp_metal:      db "[PAOS64] L5 svc: hotpatch executable replay release-disabled (no owner Ed25519 key) [hotpatch.persist.release.disabled]", 13, 10, 0
str_hpp_skip:       db "[PAOS64] L5 svc: hotpatch ESP-persist selftest skipped (no persistent block dev)", 13, 10, 0
str_hpp_bounds_mask: db "[PAOS64] M6 security: hotpatch bounds fixture FAIL mask=", 0
str_hpp_security_pass: db "[PAOS64] M6 security: hotpatch bounds and authenticated replay PASS [security.hotpatch.bounded_signed_replay]", 13, 10, 0
str_hpp_security_fail: db "[PAOS64] M6 security: hotpatch bounds/authenticated replay fixture FAIL (marker withheld)", 13, 10, 0
str_hpp_fail_bounds: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=bounds_matrix", 13, 10, 0
str_hpp_fail_sign: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=manifest_sign", 13, 10, 0
str_hpp_fail_store: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=manifest_qemu_roundtrip", 13, 10, 0
str_hpp_fail_structure: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=manifest_structure", 13, 10, 0
str_hpp_fail_arena: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=guarded_arena", 13, 10, 0
str_hpp_fail_invalid_structure: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=invalid_signature_crc_twin", 13, 10, 0
str_hpp_fail_invalid_accept: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=invalid_signature_accepted", 13, 10, 0
str_hpp_fail_invalid_code: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=invalid_signature_code_mutated", 13, 10, 0
str_hpp_fail_invalid_record: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=invalid_signature_record_mutated", 13, 10, 0
str_hpp_fail_invalid_guard: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=invalid_signature_guard_mutated", 13, 10, 0
str_hpp_fail_valid_apply: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=valid_signature_apply", 13, 10, 0
str_hpp_fail_valid_record: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=valid_signature_record", 13, 10, 0
str_hpp_fail_valid_guard: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=valid_signature_guard", 13, 10, 0
str_hpp_fail_valid_grade: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=valid_signature_grade", 13, 10, 0
str_hpp_fail_restore: db "[PAOS64] M6 security: hotpatch fixture FAIL stage=restore_exact", 13, 10, 0
%if COG_MODEL_ENABLED = 1
hp_system_disk_model:  db COG_SYSTEM_MODEL_BYTES, 0  ; generated exact boot-disk IDENTIFY model
hp_system_disk_serial: db COG_SYSTEM_SERIAL_BYTES, 0 ; generated exact boot-disk IDENTIFY serial
%endif

align 8
times 41 db 0                  ; hp_mani_buf..hp_persist_stage moved to WDATA_svc_command_hppersist_0_bss1: keeps the labels below at their offset mod 64

; RFC 8032 case-1 identity, confined to the QEMU-only signed fixture.
hp_security_seed:
    db 0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4
    db 0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
hp_security_public:
    db 0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a
    db 0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
str_hp_sa_caller: db "HOTPATCH_PERSIST", 0
%endmacro
WDATA_DEFER WDATA_svc_command_hppersist_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_svc_command_hppersist_0_bss1 0
resb 40                 ; keeps hp_mani_buf at its WDATA offset mod 64
alignb 8
hp_mani_buf:        resb HPM_SECTOR                  ; manifest staging (pack/clear)
hp_mani_verify:     resb HPM_SECTOR                  ; readback verify + selftest re-apply source
hp_mani_store:      resb HPM_SECTOR                  ; boot-replay read target
hp_mani_auth:       resb HPM_SECTOR                  ; canonical signature transcript
hp_grade_verify:    resb HPM_GRADEMAX                 ; replay/selftest rendered-content scratch
hp_security_body:   resb 32                           ; signed-fixture PIC body
hp_security_code_snapshot: resq 1                     ; invalid-signature exactness
hp_security_rec_snapshot: resb HP_REC_STATE_SIZE
hp_persist_stage:   resb 1                            ; live failure witness; 0 = idle/success
alignb 8
hp_test_context:
hp_test_device:     resq 1
hp_test_generation: resq 1
hp_test_first:      resq 1
hp_test_count:      resq 1
hp_test_name_len:   resd 1
hp_test_active:     resb 1
hp_test_busy:       resb 1
hp_test_name:       resb HPT_NAME_MAX + 1
hp_test_context_end:
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_hppersist_0_bss1
