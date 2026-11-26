;; MODULE svc/command_blk
;; LAYER 5
;; EXPORTS command_blk_init, cmd_verb_blkinfo, cmd_verb_blkread, cmd_verb_blkwrite, cmd_verb_blkflush, blk_out_buf, blk_out_ready, blk_out_cur
;; IMPORTS boot/serial, core/lib/fmt, core/lib/str, svc/command, fs/blockdev, fs/storage_access, dev/blk/nvme, dev/blk/ahci
;; CAPS
;; OWNER saga:storage
; ============================================================================
; svc/command_blk.asm — the GENERIC block-scratch UDP verb surface (1027b): a THIN
; PROJECTION of the fs/blockdev class DISPATCH into the ONE command registry
; (svc/command.asm, 1077). It owns NO storage logic — every sector moves through
; blk_read/blk_write/blk_flush against a backend selected BY NAME from the same
; registry blk_register populated (no class-core edit; the §9.4 additive seam,
; modeled on svc/command_reinit.asm).
;
;   BLKINFO  <backend>                  -> BLK INFO dev=<name> MODEL=<id-model> LBA=<ss> lba_max=<n>
;   BLKREAD  <backend> <lba>            -> BLKDATA lba=0x<lba> hex=<1024 hex chars>
;   BLKWRITE <backend> <lba> <hex1024>  -> BLK WRITE ok  (gated: reserved-LBA allowlist ONLY;
;                                          a disk behind Intel VMD -> BLK ERR vmd_raid_member)
;   BLKFLUSH <backend>                  -> BLK FLUSH ok
;
; WRITE GATE (SECURITY.md §4, driver_classes.inc blk_ops.write note): the upper
; half enforces a compile-time reserved-LBA allowlist BEFORE the vtable is reached.
; The two allowed LBAs live in the GPT alignment gap (LBA 34..2047: after the
; partition-entry array at LBA 2..33, before the first partition at LBA 2048 —
; VERIFIED against the live disk's GPT via BLKREAD before the first supervised
; write; see gauntlet_v2/probes/probe_drv_nvme_backend.sh). Everything else —
; ESP, MSR, Windows C:, recovery, backup GPT — is structurally unreachable
; through this verb, whatever the caller sends.
;
; Reply staging: the handler formats ONE line into blk_out_buf; command_udp frames
; it in the lean data envelope (VERSION, verb, OK/REFUSED, bounded ARG echo, then
; this line; RCQ-19) because the BLKREAD body is 1024 hex chars and the common base
; block (~550 B by 0.0.65) plus data would truncate the sector mid-hex.
; ============================================================================

BLK_ALLOW_LBA0   equ PERSIST_GAP_LBA_PRIMARY ; scratch sector   (GPT gap, see header note)
BLK_ALLOW_LBA1   equ PERSIST_GAP_LBA_TMP     ; negative-integrity sibling (same gap)

; ---------------------------------------------------------------------------
; command_blk_init — register the 4 BLK* verbs through the SAME
;   command_register_verb (no registry-core edit), then derive the earned
;   BOOTLOG marker flags from the REAL post-boot blockdev/nvme state (the same
;   state that gated the serial markers — no latch: an absent controller can
;   never raise blk_m_id). Runs after blk_selftest + reinit_declare (registry
;   + blockdev both up). clobbers: caller-saved.
; ---------------------------------------------------------------------------
command_blk_init:
    push rbx
    lea  rdi, [rel str_verb_blkinfo]
    lea  rsi, [rel cmd_verb_blkinfo]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                          ; read-only
    call command_register_verb
    lea rdi, [rel str_verb_blkid]
    lea rsi, [rel cmd_verb_blkid]
    xor edx, edx
    mov ecx, ARGT_TEXT
    xor r8, r8
    xor r9, r9                          ; protected cached read, no device IO
    call command_register_verb
    lea  rdi,[rel str_verb_blkpolicy]
    lea  rsi,[rel cmd_verb_blkpolicy]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8,r8
    xor r9,r9                        ; protected read-only, no grant or write
    call command_register_verb
    lea  rdi, [rel str_verb_blkread]
    lea  rsi, [rel cmd_verb_blkread]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                          ; read-only
    call command_register_verb
    lea  rdi, [rel str_verb_blkwrite]
    lea  rsi, [rel cmd_verb_blkwrite]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                           ; destructive (writes a sector)
    call command_register_verb
    lea  rdi, [rel str_verb_blkflush]
    lea  rsi, [rel cmd_verb_blkflush]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                           ; destructive (commits cached writes)
    call command_register_verb
    ; 1117a: BLK_RW <backend> — supervised metal write+readback round-trip. A single
    ;   verb writes a per-run rdtsc nonce to the reserved-LBA scratch (0x700 gap),
    ;   flushes, reads it back, and content-grades the readback -> match=0|1. The
    ;   real controller round-trip that un-tags blk.*.rw from qemu-only.
    lea  rdi, [rel str_verb_blkrw]
    lea  rsi, [rel cmd_verb_blkrw]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                           ; destructive (writes the scratch sector)
    call command_register_verb

    lea rdi,[rel str_verb_blkgeomfile]
    lea rsi,[rel cmd_verb_blkgeomfile]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8,r8
    mov r9,1
    call command_register_verb
    lea rdi,[rel str_verb_blkgeom]
    lea rsi,[rel cmd_verb_blkgeom]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8,r8
    mov r9,1                           ; bounded explicit scratch write
    call command_register_verb

    ; --- earned BOOTLOG marker flags (mirror the serial markers' conditions) ---
    lea  rdi, [rel str_nvme_name]        ; "nvme0" registered?
    mov  esi, 5
    call blk_find
    test rax, rax
    jz   .no_reg
    mov  byte [rel blk_m_reg], 1
.no_reg:
    lea  rdi, [rel str_nullblk_name]     ; "nullblk" registered (seam-2nd)?
    mov  esi, 7
    call blk_find
    test rax, rax
    jz   .no_null
    mov  byte [rel blk_m_null], 1
.no_null:
    cmp  byte [rel nvme_present], 1
    jne  .absent
    cmp  byte [rel nvme_model], 0        ; a real IDENTIFY filled the model
    je   .flags_done
    mov  byte [rel blk_m_id], 1
    jmp  .flags_done
.absent:
    mov  byte [rel blk_m_skip], 1        ; honest skip token (probe's clean-SKIP path)
.flags_done:
    ; --- 1028 ahci earned flags (mirror the ahci serial markers' conditions) --
    lea  rdi, [rel str_ahci_name]        ; "ahci0" registered?
    mov  esi, 5
    call blk_find
    test rax, rax
    jz   .no_areg
    mov  byte [rel blk_m_areg], 1
.no_areg:
    cmp  byte [rel ahci_present], 1
    jne  .a_absent
    cmp  byte [rel ahci_model], 0        ; a real IDENTIFY filled the model
    je   .a_done
    mov  byte [rel blk_m_aid], 1
    jmp  .a_done
.a_absent:
    mov  byte [rel blk_m_askip], 1       ; honest skip token (probe's clean-SKIP path)
.a_done:
    lea  rdi, [rel str_blk_verbs_reg]
    call serial_string                   ; [blk.verbs.registered]
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; blk_find(RDI=name ptr, ESI=name len) -> RAX = dev* or 0. Walks the class
;   registry matching the caller token as a PREFIX of dev.name ("nvme" matches
;   "nvme0"; "nullblk" matches "nullblk"). Read-only walk — the core is not
;   edited to support this (the intrusive list IS the published seam shape).
;   clobbers: RAX,RCX,RDX,R8,R9
; ---------------------------------------------------------------------------
blk_find:
    test esi, esi
    jz   .none
    mov  rax, [rel blk_registry_head]
.walk:
    test rax, rax
    jz   .none
    mov  rdx, [rax + dev.name]
    test rdx, rdx
    jz   .next
    xor  ecx, ecx
.cmp:
    cmp  ecx, esi
    jae  .hit                            ; all caller chars matched -> prefix hit
    movzx r8d, byte [rdi + rcx]
    movzx r9d, byte [rdx + rcx]
    cmp  r8d, r9d
    jne  .next
    inc  ecx
    jmp  .cmp
.next:
    mov  rax, [rax + dev.next]
    jmp  .walk
.hit:
    ret
.none:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; blk_tokenize(RDI=arg cstr) — split the raw ARGT_TEXT token on single/multi
;   spaces into up to 3 (ptr,len) pairs WITHOUT modifying the line (the raw arg
;   is echoed verbatim later; a NUL-split would truncate the echo). Token 2 runs
;   to end-of-line (the 1024-char hex body has no spaces). clobbers: RAX,RCX,RDX
; ---------------------------------------------------------------------------
blk_tokenize:
    xor  ecx, ecx                        ; token index
    lea  rdx, [rel blk_tok_ptr]
    mov  qword [rdx], 0
    mov  qword [rdx + 8], 0
    mov  qword [rdx + 16], 0
    lea  rax, [rel blk_tok_len]
    mov  dword [rax], 0
    mov  dword [rax + 4], 0
    mov  dword [rax + 8], 0
    test rdi, rdi
    jz   .done
.skip_sp:
    cmp  byte [rdi], ' '
    jne  .tok_start
    inc  rdi
    jmp  .skip_sp
.tok_start:
    cmp  byte [rdi], 0
    je   .done
    cmp  ecx, 3
    jae  .done
    mov  [rdx + rcx*8], rdi              ; token start
.tok_scan:
    movzx eax, byte [rdi]
    test al, al
    jz   .tok_end
    cmp  al, ' '
    je   .tok_end
    inc  rdi
    jmp  .tok_scan
.tok_end:
    mov  rax, rdi
    sub  rax, [rdx + rcx*8]              ; len
    push rdx
    lea  rdx, [rel blk_tok_len]
    mov  [rdx + rcx*4], eax
    pop  rdx
    inc  ecx
    jmp  .skip_sp
.done:
    ret

; blk_parse_u64(RDI=ptr, ESI=len) -> RAX = value. Accepts 0x-prefixed hex or
;   plain decimal. Out-of-alphabet chars terminate the parse. clobbers RAX,RCX,RDX,R8
blk_parse_u64:
    xor  eax, eax
    test esi, esi
    jz   .done
    cmp  esi, 2
    jb   .dec
    cmp  word [rdi], '0x'
    jne  .dec
    add  rdi, 2
    sub  esi, 2
.hex:
    test esi, esi
    jz   .done
    movzx ecx, byte [rdi]
    call blk_nibble
    cmp  edx, 16
    jae  .done
    shl  rax, 4
    or   rax, rdx
    inc  rdi
    dec  esi
    jmp  .hex
.dec:
    test esi, esi
    jz   .done
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .done
    imul rax, rax, 10
    add  rax, rcx
    inc  rdi
    dec  esi
    jmp  .dec
.done:
    ret

; blk_nibble(ECX=ascii) -> EDX = 0..15, or 16+ if not hex. clobbers EDX
blk_nibble:
    mov  edx, ecx
    sub  edx, '0'
    cmp  edx, 9
    jbe  .ok
    mov  edx, ecx
    or   edx, 0x20                       ; tolower
    sub  edx, 'a'
    cmp  edx, 5
    ja   .bad
    add  edx, 10
.ok:
    ret
.bad:
    mov  edx, 16
    ret

; ---- staged-reply cursor helpers (the command_reinit pattern) ---------------
; blk_out_reset — start a fresh staged line. clobbers RAX
blk_out_reset:
    lea  rax, [rel blk_out_buf]
    mov  [rel blk_out_cur], rax
    mov  byte [rax], 0
    ret

; blk_out_str(RDI=cstr) — append, keep NUL-terminated. clobbers RAX,RSI,RDI
blk_out_str:
    mov  rsi, [rel blk_out_cur]
.cp:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel blk_out_cur], rsi
    ret

; blk_out_dec(RDI=value) — append unsigned decimal via canonical fmt_dec. clobbers caller-saved
blk_out_dec:
    mov  rsi, [rel blk_out_cur]
    push rsi
    call fmt_dec                         ; RDI=value, RSI=dst -> RAX=digits (NUL-terminates)
    pop  rsi
    add  rsi, rax
    mov  [rel blk_out_cur], rsi
    ret

; blk_out_hex(RDI=value) — append lowercase hex (no 0x) via canonical fmt_hex. clobbers caller-saved
blk_out_hex:
    mov  rsi, [rel blk_out_cur]
    push rsi
    call fmt_hex                         ; NUL-terminates
    pop  rdi
.adv:
    cmp  byte [rdi], 0
    je   .done
    inc  rdi
    jmp  .adv
.done:
    mov  [rel blk_out_cur], rdi
    ret

; blk_out_sector_hex — append blk_data_buf (512 bytes) as 1024 lowercase hex
;   chars at the staged cursor. Deterministic size; blk_out_buf is sized for it.
;   clobbers RAX,RCX,RDX,RSI,RDI
blk_out_sector_hex:
    push rbx
    lea  rbx, [rel blk_hexdigits]        ; RIP-relative base (an absolute disp bakes the RVA)
    mov  rdi, [rel blk_out_cur]
    lea  rsi, [rel blk_data_buf]
    xor  ecx, ecx
.byte:
    cmp  ecx, 512
    jae  .done
    movzx eax, byte [rsi + rcx]
    mov  edx, eax
    shr  edx, 4
    mov  dl, [rbx + rdx]
    mov  [rdi], dl
    mov  edx, eax
    and  edx, 0x0F
    mov  dl, [rbx + rdx]
    mov  [rdi + 1], dl
    add  rdi, 2
    inc  ecx
    jmp  .byte
.done:
    mov  byte [rdi], 0
    mov  [rel blk_out_cur], rdi
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; blk_arg_common — shared handler front half: RDI=req -> tokenize the arg,
;   resolve tok0 to a backend. Returns RAX=dev* (0 = fail, staged error line
;   already written + ready). clobbers caller-saved.
; ---------------------------------------------------------------------------
blk_arg_common:
    mov  rdi, [rdi + REQ_ARG]
    call blk_tokenize
    call blk_out_reset
    mov  rdi, [rel blk_tok_ptr]
    mov  esi, [rel blk_tok_len]
    call blk_find
    test rax, rax
    jz   .nodev
    ret
.nodev:
    lea  rdi, [rel str_blk_e_nodev]
    call blk_out_str
    mov  byte [rel blk_out_ready], 1
    xor  eax, eax
    ret

; ===========================================================================
; THE VERB HANDLERS — dispatched THROUGH the ONE command_dispatch (RDI=req,
; RSI=resp; RSP_CODE pre-defaulted to OK by the dispatcher).
; ===========================================================================

; BLKINFO <backend> — identify plausibility: real model + sector size + capacity.
cmd_verb_blkinfo:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  r12, -1                         ; AHCI logical slot, or non-AHCI
    call blk_arg_common
    test rax, rax
    jz   .out
    mov  rbx, rax
    lea  rdi, [rel str_blk_info_pre]     ; " BLK INFO dev="
    call blk_out_str
    mov  rdi, [rbx + dev.name]
    call blk_out_str
    lea  rdi, [rel str_blk_info_model]   ; " MODEL="
    call blk_out_str
    ; nvme/ahci report their REAL IDENTIFY model (spaces -> '_' so the token
    ; greps as one word); other backends report their name (no id-page to quote).
    lea  rax, [rel nvme_devs]
    cmp  rbx, rax
    jne  .try_ahci
    cmp  byte [rel nvme_model], 0
    je   .model_name
    lea  rsi, [rel nvme_model]
    jmp  .model_sanitize
.try_ahci:
    lea  rax, [rel ahci_devs]
    xor  ecx, ecx
.ahci_slot:
    cmp  ecx, AHCI_MAX_DISKS
    jae  .model_name
    cmp  rbx, rax
    je   .ahci_hit
    add  rax, dev_size
    inc  ecx
    jmp  .ahci_slot
.ahci_hit:
    mov  r12d, ecx
    imul eax, ecx, 41
    lea  rsi, [rel ahci_models]
    add  rsi, rax
    cmp  byte [rsi], 0
    je   .model_name
.model_sanitize:
    lea  rdi, [rel blk_model_scratch]
    xor  ecx, ecx
.msan:
    cmp  ecx, 47
    jae  .msdone
    mov  al, [rsi + rcx]
    test al, al
    jz   .msdone
    cmp  al, ' '
    jne  .mskeep
    mov  al, '_'
.mskeep:
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .msan
.msdone:
    mov  byte [rdi + rcx], 0
    lea  rdi, [rel blk_model_scratch]
    call blk_out_str
    jmp  .serial
.model_name:
    mov  rdi, [rbx + dev.name]
    call blk_out_str
.serial:
    cmp  r12, -1
    je   .lba
    imul eax, r12d, 21
    lea  rsi, [rel ahci_serials]
    add  rsi, rax
    cmp  byte [rsi], 0
    je   .lba
    lea  rdi, [rel str_blk_info_serial]
    call blk_out_str
    imul eax, r12d, 21
    lea  rdi, [rel ahci_serials]
    add  rdi, rax
    call blk_out_str
.lba:
    lea  rdi, [rel str_blk_info_lba]     ; " LBA="
    call blk_out_str
    mov  rax, [rbx + dev.info]
    mov  edi, [rax + blk_info.sector_size]
    call blk_out_dec
    lea  rdi, [rel str_blk_info_max]     ; " lba_max="
    call blk_out_str
    mov  rax, [rbx + dev.info]
    mov  rdi, [rax + blk_info.lba_max]
    call blk_out_dec
    ; --- nvme live-controller diag (read-only): CSTS/CC straight off BAR0 + the
    ;     PCI command word, so a dead-at-runtime controller is visible in one
    ;     BLKINFO instead of a bare read_failed (instrument-before-theorize). ---
    lea  rax, [rel nvme_devs]
    cmp  rbx, rax
    jne  .no_diag
    cmp  byte [rel nvme_present], 1
    jne  .no_diag
    lea  rdi, [rel str_blk_i_csts]       ; " csts=0x"
    call blk_out_str
    mov  rax, [rel nvme_bar0]
    mov  edi, [rax + 0x1C]
    call blk_out_hex
    lea  rdi, [rel str_blk_i_cc]         ; " cc=0x"
    call blk_out_str
    mov  rax, [rel nvme_bar0]
    mov  edi, [rax + 0x14]
    call blk_out_hex
    lea  rdi, [rel str_blk_i_pcicmd]     ; " pcicmd=0x"
    call blk_out_str
    mov  edi, [rel nvme_busno]
    mov  esi, [rel nvme_devno]
    mov  edx, [rel nvme_fn]
    mov  ecx, 0x04
    call pci_cfg_read32
    movzx edi, ax
    call blk_out_hex
    lea  rdi, [rel str_blk_i_bar]        ; " bar=0x"
    call blk_out_str
    mov  rdi, [rel nvme_bar0]
    call blk_out_hex
.no_diag:
    mov  rdi,rbx
    call blk_out_geometry
    lea  rax, [rel msd_dev]
    cmp  rbx, rax
    jne  .not_stick
    lea  rdi, [rel str_blk_info_no_cache] ; flush answered 'no cache': nothing proven durable
    call blk_out_str
    mov  edi, [rel msd_flush_no_cache]
    call blk_out_dec
.not_stick:
    mov  byte [rel blk_out_ready], 1
.out:
    pop  r12
    pop  rbx
    ret

; BLKREAD <backend> <lba> — one 512B sector through the class dispatch, hex out.
cmd_verb_blkread:
    call cmd_handler_prologue
    push rbx
    push r12
    call blk_arg_common
    test rax, rax
    jz   .out
    mov  rbx, rax
    mov  rdi, [rel blk_tok_ptr + 8]
    mov  esi, [rel blk_tok_len + 4]
    call blk_parse_u64
    mov  r12, rax                        ; lba
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, 1
    lea  rcx, [rel blk_data_buf]
    call blk_read                        ; the ONE class dispatch
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_blk_data_pre]     ; " BLKDATA lba=0x"
    call blk_out_str
    mov  rdi, r12
    call blk_out_hex
    lea  rdi, [rel str_blk_data_hex]     ; " hex="
    call blk_out_str
    call blk_out_sector_hex
    mov  byte [rel blk_out_ready], 1
    jmp  .out
.fail:
    lea  rdi, [rel str_blk_e_read]
    call blk_out_str
    lea  rdi, [rel str_blk_e_st]         ; " st=0x" — nvme last CQ status (0xffff=timeout)
    call blk_out_str
    movzx edi, word [rel nvme_last_st]
    call blk_out_hex
    mov  byte [rel blk_out_ready], 1
.out:
    pop  r12
    pop  rbx
    ret

; BLKWRITE <backend> <lba> <hex1024> — allowlist-gated single-sector write.
cmd_verb_blkwrite:
    call cmd_handler_prologue
    push rbx
    push r12
    call blk_arg_common
    test rax, rax
    jz   .out
    mov  rbx, rax
    mov  rdi, [rel blk_tok_ptr + 8]
    mov  esi, [rel blk_tok_len + 4]
    call blk_parse_u64
    mov  r12, rax                        ; lba
    ; --- THE WRITE GATE: reserved-LBA allowlist, checked BEFORE any decode ---
    cmp  r12, BLK_ALLOW_LBA0
    je   .allowed
    cmp  r12, BLK_ALLOW_LBA1
    je   .allowed
    lea  rdi, [rel str_blk_e_lba]        ; " BLK ERR lba_not_allowed lba=0x"
    call blk_out_str
    mov  rdi, r12
    call blk_out_hex
    mov  byte [rel blk_out_ready], 1
    jmp  .out
.allowed:
    ; --- decode: token 2 must be EXACTLY 1024 hex chars -> 512 bytes ---------
    cmp  dword [rel blk_tok_len + 8], 1024
    jne  .badhex
    mov  rsi, [rel blk_tok_ptr + 16]
    lea  rdi, [rel blk_data_buf]
    xor  r8d, r8d                        ; byte index
.dec2:
    cmp  r8d, 512
    jae  .decoded
    movzx ecx, byte [rsi]
    call blk_nibble
    cmp  edx, 16
    jae  .badhex
    mov  eax, edx
    shl  eax, 4
    movzx ecx, byte [rsi + 1]
    call blk_nibble
    cmp  edx, 16
    jae  .badhex
    or   eax, edx
    mov  [rdi + r8], al
    add  rsi, 2
    inc  r8d
    jmp  .dec2
.decoded:
    ; SEC-S6-lba-dup: 0x700/0x708 are shared persistence sectors (fs/blockdev
    ; reservation); a raw owner write serializes with their RMW owners and bumps
    ; persist_gap_epoch. Held from the gate to the flush, released on every exit.
    call persist_gap_lock_acquire
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, 1
    lea  r8, [rel str_blkwrite_sa_caller]
    call storage_access_require_request  ; storage canon: sensitive only with owner-signed authority
    test rax, rax
    jnz  .wfail
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, 1
    lea  rcx, [rel blk_data_buf]
    call blk_write                       ; the ONE class dispatch (gate already passed)
    test rax, rax
    jnz  .wfail
    ; An ACKed write must survive a reset: DRAM-less NVMe (Beelink Maxio) keeps
    ; it in a volatile cache until an NVM Flush (BLK_RW already flushes).
    mov  rdi, rbx
    call blk_flush
    test rax, rax
    jnz  .wfail
    call persist_gap_lock_release
    lea  rdi, [rel str_blk_w_ok]         ; " BLK WRITE ok lba=0x"
    call blk_out_str
    mov  rdi, r12
    call blk_out_hex
    mov  byte [rel blk_out_ready], 1
    jmp  .out
.badhex:
    lea  rdi, [rel str_blk_e_hex]        ; " BLK ERR badhex len="
    call blk_out_str
    mov  edi, [rel blk_tok_len + 8]
    call blk_out_dec
    mov  byte [rel blk_out_ready], 1
    jmp  .out
.wfail:
    call persist_gap_lock_release        ; every .wfail follows the acquire at .decoded
    mov  rdi, rbx
    call storage_access_vmd_member       ; name the data-safety refusal (root 75030)
    lea  rdi, [rel str_blk_e_write]
    test eax, eax
    jz   .wfail_reply
    lea  rdi, [rel str_blk_e_vmd]        ; " BLK ERR vmd_raid_member"
.wfail_reply:
    call blk_out_str
    mov  byte [rel blk_out_ready], 1
.out:
    pop  r12
    pop  rbx
    ret

; BLKFLUSH <backend> — real flush through the dispatch (NAND-commit the write).
cmd_verb_blkflush:
    call cmd_handler_prologue
    push rbx
    call blk_arg_common
    test rax, rax
    jz   .out
    mov  rdi, rax
    call blk_flush
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_blk_f_ok]
    call blk_out_str
    mov  byte [rel blk_out_ready], 1
    jmp  .out
.fail:
    lea  rdi, [rel str_blk_e_flush]
    call blk_out_str
    mov  byte [rel blk_out_ready], 1
.out:
    pop  rbx
    ret

; BLK_RW <backend> — the SUPERVISED metal write+readback round-trip (1117a). Unlike
;   the boot selftest (read-only on real hardware, per ahci_self_exercise's SAFETY
;   GATE), this is the operator-triggered write path the original design reserved for
;   the BLKWRITE 0x700/0x708 allowlist. It writes a fresh per-run rdtsc nonce into the
;   0x700 scratch sector (structurally the ONLY LBA this reaches — same gate the
;   allowlist enforces), flushes, reads the sector straight back into a SEPARATE
;   buffer, and content-grades: match=1 iff the readback carries the exact nonce at
;   both the head and tail guard offsets. A latch replying a static value fails the
;   per-run nonce; a broken controller fails the readback compare. On match the
;   hw-only marker fires (blk.ahci.rw.baremetal / blk.nvme.rw.baremetal).
cmd_verb_blkrw:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    call blk_arg_common                  ; tokenize + resolve tok0 -> RAX=dev* (stages err if none)
    test rax, rax
    jz   .out
    mov  rbx, rax                        ; dev*

    ; --- fresh per-run nonce (rdtsc: un-fakeable, differs every call) ---------
    rdtsc                                ; EDX:EAX
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax                        ; r12 = nonce

    ; --- build the 512B block: deterministic base + nonce at head & tail ------
    lea  rdi, [rel blk_data_buf]
    call blk_fill_pattern_b              ; 512B deterministic pattern
    lea  rdi, [rel blk_data_buf]
    mov  [rdi], r12                      ; nonce @ offset 0
    mov  [rdi + 504], r12                ; nonce @ tail guard (catches partial writes)

    ; --- SEC-S6-lba-dup: the shared persistence sector, under its lock ---------
    ; Held from the gate through write, flush and readback; released at .stage
    ; and .fail. The nonce stays in the sector (S5 quiesce proof re-reads it).
    call persist_gap_lock_acquire
    ; --- storage-access gate (explicit owner authority for a sensitive target) ---
    mov  rdi, rbx
    mov  rsi, BLK_ALLOW_LBA0
    mov  edx, 1
    lea  r8, [rel str_blkrw_sa_caller]
    call storage_access_require_request
    test rax, rax
    jnz  .fail
    ; --- write -> flush -> readback through the ONE class dispatch ------------
    mov  rdi, rbx
    mov  rsi, BLK_ALLOW_LBA0             ; 0x700 — the reserved scratch gap sector
    mov  rdx, 1
    lea  rcx, [rel blk_data_buf]
    call blk_write
    test rax, rax
    jnz  .fail
    mov  rdi, rbx
    call blk_flush
    test rax, rax
    jnz  .fail
    mov  rdi, rbx
    mov  rsi, BLK_ALLOW_LBA0
    mov  rdx, 1
    lea  rcx, [rel blkrw_rb_buf]         ; SEPARATE buffer — no aliasing the written one
    call blk_read
    test rax, rax
    jnz  .fail

    ; --- content-grade: readback must carry the nonce at head AND tail --------
    xor  r13d, r13d                      ; match flag = 0
    mov  rax, [rel blkrw_rb_buf]
    cmp  rax, r12
    jne  .stage
    mov  rax, [rel blkrw_rb_buf + 504]
    cmp  rax, r12
    jne  .stage
    mov  r13d, 1                         ; match=1
.stage:
    call persist_gap_lock_release
    lea  rdi, [rel str_blk_rw_pre]       ; " BLK_RW dev="
    call blk_out_str
    mov  rdi, [rbx + dev.name]
    call blk_out_str
    lea  rdi, [rel str_blk_rw_wrote]     ; " wrote=0x"
    call blk_out_str
    mov  rdi, r12
    call blk_out_hex
    lea  rdi, [rel str_blk_rw_read]      ; " read=0x"
    call blk_out_str
    mov  rdi, [rel blkrw_rb_buf]         ; the readback head nonce (verbatim)
    call blk_out_hex
    lea  rdi, [rel str_blk_rw_match]     ; " match="
    call blk_out_str
    mov  rdi, r13
    call blk_out_dec
    mov  byte [rel blk_out_ready], 1
    ; --- on match, fire the hw-only baremetal marker for the resolved backend --
    test r13d, r13d
    jz   .out
    lea  rax, [rel ahci_dev]
    cmp  rbx, rax
    jne  .try_nvme_marker
    lea  rdi, [rel str_blk_rw_m_ahci]
    call serial_string                   ; [blk.ahci.rw.baremetal]
    jmp  .out
.try_nvme_marker:
    lea  rax, [rel nvme_devs]
    cmp  rbx, rax
    jne  .out
    lea  rdi, [rel str_blk_rw_m_nvme]
    call serial_string                   ; [blk.nvme.rw.baremetal]
    jmp  .out
.fail:
    call persist_gap_lock_release        ; every .fail follows the acquire above
    lea  rdi, [rel str_blk_rw_err]       ; " BLK_RW ERR io_failed st=0x"
    call blk_out_str
    movzx edi, word [rel nvme_last_st]
    call blk_out_hex
    mov  byte [rel blk_out_ready], 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---- svc/command_blk data (in-image writable; migrates to BSS under W^X) -----
blk_out_ready:     db 0
blk_m_reg:         db 0                  ; BOOTLOG " blk.nvme.registered"
blk_m_id:          db 0                  ; BOOTLOG " blk.nvme.identify.ok"
blk_m_null:        db 0                  ; BOOTLOG " blk.nullblk.registered"
blk_m_skip:        db 0                  ; BOOTLOG " blk.nvme: skipped (no disk)"
blk_m_areg:        db 0                  ; BOOTLOG " blk.ahci.registered"
blk_m_aid:         db 0                  ; BOOTLOG " blk.ahci.identify.ok"
blk_m_askip:       db 0                  ; BOOTLOG " blk.ahci: skipped (no disk)"
blk_out_cur:       dq 0
blk_tok_ptr:       times 3 dq 0
blk_tok_len:       times 3 dd 0
blk_data_buf:      times 512 db 0
blkrw_rb_buf:      times 512 db 0       ; BLK_RW readback (separate from the written buf)
blk_model_scratch: times 48 db 0
blk_out_buf:       times 1152 db 0       ; " BLKDATA lba=0x<16> hex=" + 1024 + slack
blk_hexdigits:     db "0123456789abcdef"

str_verb_blkinfo:  db "BLKINFO", 0
str_verb_blkread:  db "BLKREAD", 0
str_verb_blkwrite: db "BLKWRITE", 0
str_verb_blkflush: db "BLKFLUSH", 0
str_verb_blkrw:    db "BLK_RW", 0

str_blk_verbs_reg: db "[PAOS64] L5 svc: BLK verbs registered (BLKINFO/BLKREAD/BLKWRITE/BLKFLUSH) [blk.verbs.registered]", 13, 10, 0

str_blk_info_pre:   db " BLK INFO dev=", 0
str_blk_info_model: db " MODEL=", 0
str_blk_info_serial: db " SERIAL=", 0
str_blk_info_lba:   db " LBA=", 0
str_blk_info_max:   db " lba_max=", 0
str_blk_info_no_cache: db " MSD_NO_CACHE=", 0
str_blk_data_pre:   db " BLKDATA lba=0x", 0
str_blk_data_hex:   db " hex=", 0
str_blk_w_ok:       db " BLK WRITE ok lba=0x", 0
str_blk_f_ok:       db " BLK FLUSH ok", 0
str_blk_e_nodev:    db " BLK ERR no_backend", 0
str_blk_e_read:     db " BLK ERR read_failed", 0
str_blk_e_write:    db " BLK ERR write_failed", 0
str_blk_e_vmd:      db " BLK ERR vmd_raid_member", 0
str_blk_e_flush:    db " BLK ERR flush_failed", 0
str_blk_e_lba:      db " BLK ERR lba_not_allowed lba=0x", 0
str_blk_e_hex:      db " BLK ERR badhex len=", 0
str_blk_e_st:       db " st=0x", 0
str_blk_i_csts:     db " csts=0x", 0
str_blk_i_cc:       db " cc=0x", 0
str_blk_i_pcicmd:   db " pcicmd=0x", 0
str_blk_i_bar:      db " bar=0x", 0
str_blk_rw_pre:     db " BLK_RW dev=", 0
str_blk_rw_wrote:   db " wrote=0x", 0
str_blk_rw_read:    db " read=0x", 0
str_blk_rw_match:   db " match=", 0
str_blk_rw_err:     db " BLK_RW ERR io_failed st=0x", 0
str_blk_rw_m_ahci:  db "[PAOS64] L5 svc: BLK_RW metal round-trip PASS (per-run nonce write->flush->readback match) [blk.ahci.rw.baremetal]", 13, 10, 0
str_blk_rw_m_nvme:  db "[PAOS64] L5 svc: BLK_RW metal round-trip PASS (per-run nonce write->flush->readback match) [blk.nvme.rw.baremetal]", 13, 10, 0
str_blkwrite_sa_caller: db "BLKWRITE", 0
str_blkrw_sa_caller: db "BLK_RW", 0

%include "svc/command_blk_geometry.asm"

str_verb_blkpolicy: db "BLKPOLICY",0
%include "svc/command_blk_policy.asm"

%include "svc/command_blk_probe.asm"
%include "svc/command_blk_identify.asm"
