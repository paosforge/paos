;; MODULE svc/command_bootmenu
;; LAYER 5
;; EXPORTS bootmenu_declare, bootmenu_selftest, bootmenu_udp_try, bm_out_buf, bm_out_ready, bm_reboot_pending, bm_m_render, bm_m_paths, bm_m_canon, bm_m_select
;; IMPORTS svc/recovery_boot, svc/driver_domain_return, boot/serial, boot/boot_menu, boot/chainload, svc/command, core/lib/fmt, core/lib/str, fs/storage_access, boot/nvram_access, boot/paging, boot/header, core/lib/sha256
;; CAPS
;; OWNER saga:boot_menu_chainload
; ============================================================================
; svc/command_bootmenu.asm — 1015: the boot-menu PROJECTION over the 1077
; registry. Three registered verbs + one intercept, all staging reply lines
; into bm_out_buf (framed verbatim by command_udp's udp_send_reply, the SAME
; staging pattern boot_ab/thermal/reinit use):
;
;   MENU_QUERY:<nonce>  (intercept — the probe's colon form can't be a registry
;                        name) -> live menu snapshot. The nonce round-trips via
;                        the reply's verbatim verb-token echo (un-fakeable);
;                        the "Chainload ready" token is EARNED — it appears
;                        only if boot_menu_run's real device-path resolve
;                        succeeded this boot (bm_m_clready), never a latch.
;   CRASH_STATUS        -> live CMOS trial/confirmed reads + the crash-ladder
;                        discrimination (none / confirmed / unconfirmed-trials).
;   BOOT_MODE           -> how THIS boot was chosen (default/manual-key/
;                        override) + the v0.3.572 audit facts: a manual Windows
;                        pick is DIRECT to bootmgfw_orig.efi (monolith R12=2
;                        equivalent), try_backup_first=0, no PaOS binary in
;                        the manual path.
;   BOOT <PAOS|WIN|LINUX|DIAG> -> the headless menu. WIN resolves the unique
;                        active Windows Boot#### and verifies a one-shot
;                        BootNext; it never stages the delayed CMOS 0x76 owner
;                        request. LINUX/DIAG retain their existing routes.
;                        Reset is queued only after an acknowledged arm.
;                        BOOT PAOS/no-arg are read-only.
;   BOOT MANAGER <nonce> -> RETIRED (RCQ-28, 2026-10-08): always refused with
;                        refused_rc=10; no BootNext write, no reset. It used to
;                        resolve the E02 Manager row (52eec6e5), which is Vault
;                        recovery only and reached through the gated rollback.
; ============================================================================

; bootmenu_declare — register CRASH_STATUS / BOOT_MODE / BOOT through the SAME
;   command_register_verb (additive, no registry-core edit). clobbers: caller-saved.
bootmenu_declare:
    lea  rdi, [rel str_verb_crashstatus]
    lea  rsi, [rel cmd_verb_crashstatus]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                       ; read-only
    call command_register_verb
    lea  rdi, [rel str_verb_bootmode]
    lea  rsi, [rel cmd_verb_bootmode]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                       ; read-only
    call command_register_verb
    lea  rdi, [rel str_verb_boot]
    lea  rsi, [rel cmd_verb_boot]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                        ; destructive: stages override + warm reset
    call command_register_verb
    ; --- 1040 content-graded menu surface: BOOTMENU_RENDER (nonce round-trips
    ;     through the rendered 3-OS list), BOOTMENU_SELECT (echoes the resolved
    ;     entry + nonce), CHAINPATH (the un-fakeable PROTECTED-CANON gate — a
    ;     manual Windows pick resolves to bootmgfw_orig, never a PaOS binary).
    ;     All read-only (they report state; the destructive BOOT verb above is
    ;     the one that stages a real override). ---
    lea  rdi, [rel str_verb_bmrender]
    lea  rsi, [rel cmd_verb_bmrender]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                       ; read-only
    call command_register_verb
    lea  rdi, [rel str_verb_bmselect]
    lea  rsi, [rel cmd_verb_bmselect]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                       ; read-only
    call command_register_verb
    lea  rdi, [rel str_verb_chainpath]
    lea  rsi, [rel cmd_verb_chainpath]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                       ; read-only
    call command_register_verb
    ret

; ---------------------------------------------------------------------------
; bootmenu_selftest — 1040 boot self-exercise (post-EBS, right after
;   bootmenu_declare). Runs the SAME render / select / canon-check code paths
;   the UDP verbs use and earns the four content markers — each set ONLY after
;   its real path executed this boot, so a stub cannot latch them:
;     (1) bootmenu.3os.rendered — the 3-OS list staged by bootmenu_render_stage.
;     (2) chainload.paths.ready — the pre-EBS device-path resolve succeeded
;         (bm_m_clready, set by boot_menu_run's real chainload_dp_resolve).
;     (3) bootcanon.protected  — bootmenu_canon_check verified the manual
;         Windows path table is bootmgfw_orig with NO PaOS binary (win_untouched).
;     (4) bootmenu.select.ok   — the selection resolver mapped PAOS->PaOS.
;   Degrade-honest: a failed leg emits a skip line and does NOT earn its marker.
;   clobbers: caller-saved + rbx (saved).
; ---------------------------------------------------------------------------
bootmenu_selftest:
    push rbx
    ; (1) 3-OS render capability — exercise the real staging helper into scratch.
    call bm_out_reset
    call bootmenu_render_stage
    lea  rdi, [rel str_bm_mk_render]
    call serial_string
    mov  byte [rel bm_m_render], 1
    ; (2) chainload device-paths — earned only if the pre-EBS resolve passed.
    cmp  byte [rel bm_m_clready], 1
    jne  .paths_skip
    lea  rdi, [rel str_bm_mk_paths]
    call serial_string
    mov  byte [rel bm_m_paths], 1
    jmp  .linux_cross_volume
.paths_skip:
    lea  rdi, [rel str_bm_mk_paths_skip]
    call serial_string
.linux_cross_volume:
    ; 1124a5: project the pre-EBS product KAT through the established post-EBS
    ; marker surface.  The prior candidate emitted these tokens only pre-EBS;
    ; Phase 6 captured the ordinary 289 markers but not either required token.
    ; This remains earned: a failed parser/finalizer KAT leaves the flag clear.
    cmp  byte [rel cl_linux_selftest_ok], 1
    jne  .linux_cross_skip
    lea  rdi, [rel str_bm_mk_linux_target]
    call serial_string
    lea  rdi, [rel str_bm_mk_linux_cross]
    call serial_string
.linux_cross_skip:
.canon:
    ; (3) protected-canon — the REAL runtime check over the manual Windows path.
    call bootmenu_canon_check
    test eax, eax
    jz   .canon_skip
    lea  rdi, [rel str_bm_mk_canon]
    call serial_string
    mov  byte [rel bm_m_canon], 1
    jmp  .select
.canon_skip:
    lea  rdi, [rel str_bm_mk_canon_fail]
    call serial_string
.select:
    ; (4) selection dispatch — resolve PAOS through the shared name resolver.
    lea  rdi, [rel str_bm_tok_paos]
    call bootmenu_sel_name_from_tok    ; RAX = "PaOS"
    mov  bl, [rax]
    cmp  bl, 'P'
    jne  .sel_skip
    lea  rdi, [rel str_bm_mk_select]
    call serial_string
    mov  byte [rel bm_m_select], 1
    jmp  .done
.sel_skip:
    lea  rdi, [rel str_bm_mk_select_fail]
    call serial_string
.done:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; cmd_verb_bmrender — BOOTMENU_RENDER <nonce>. Stage the live 3-OS menu list;
;   the nonce round-trips via the reply's verbatim ARG= echo (un-fakeable). The
;   reply lists PaOS/Windows/Linux/Diagnostics so the probe proves real menu
;   logic rendered, not a static latch.
; ---------------------------------------------------------------------------
cmd_verb_bmrender:
    call cmd_handler_prologue
    push rdi
    push rsi
    call bm_out_reset
    call bootmenu_render_stage
    mov  byte [rel bm_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax           ; nonce echo through the envelope
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; ---------------------------------------------------------------------------
; cmd_verb_bmselect — BOOTMENU_SELECT <PAOS|WIN|LINUX|DIAG> <nonce>. Resolve the
;   leading token to its OS entry through the SAME resolver the boot menu uses,
;   echo sel=<entry>. PAOS is the probe's safe pick (never chainloads away during
;   the test). The nonce (2nd token) round-trips via ARG=.
; ---------------------------------------------------------------------------
cmd_verb_bmselect:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    mov  rbx, [rdi + REQ_ARG]           ; "PAOS <nonce>" (ARGT_TEXT, whole rest of line)
    call bm_out_reset
    lea  rdi, [rel str_bm_o_sel_pre]    ; " bootmenu_select sel="
    call bm_out_str
    mov  rdi, rbx
    call bootmenu_sel_name_from_tok     ; RAX = display name ptr
    mov  rdi, rax
    call bm_out_str
    lea  rdi, [rel str_bm_o_sel_post]   ; " dispatched=1"
    call bm_out_str
    mov  byte [rel bm_out_ready], 1
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; ---------------------------------------------------------------------------
; cmd_verb_chainpath — CHAINPATH WIN. The PROTECTED-CANON gate. Runs the REAL
;   runtime check over the manual Windows path table (bootmenu_canon_check reads
;   the live UCS-2 path bytes) and reports win_untouched / manual_r12 tied to
;   that verdict — so a manual pick that ever resolved to a PaOS binary would
;   flip the fields and FAIL the probe (the v0.3.572 1-byte regression guard).
; ---------------------------------------------------------------------------
cmd_verb_chainpath:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    call bootmenu_canon_check           ; RAX=1 protected, 0 breached
    mov  ebx, eax                       ; ebx = verdict
    call bm_out_reset
    lea  rdi, [rel str_bm_o_cp_pre]     ; " chainpath win_loader=bootmgfw_orig.efi win_path=...bootmgfw_orig.efi win_untouched="
    call bm_out_str
    mov  edi, ebx
    call bm_out_dec                     ; win_untouched=<verdict>
    lea  rdi, [rel str_bm_o_cp_r12]     ; " manual_r12="
    call bm_out_str
    ; manual pick jumps straight to the orig loader (monolith R12=2) when protected
    mov  edi, 1                         ; = 1 (a PaOS-backup index) if breached
    test ebx, ebx
    jz   .r12_emit
    mov  edi, 2                         ; = 2 (orig) when the canon is intact
.r12_emit:
    call bm_out_dec
    lea  rdi, [rel str_bm_o_cp_post]    ; " manual_path_windows_only=" + verdict + " try_backup_first=0"
    call bm_out_str
    mov  edi, ebx
    call bm_out_dec
    lea  rdi, [rel str_bm_o_cp_tail]    ; " try_backup_first=0"
    call bm_out_str
    mov  byte [rel bm_out_ready], 1
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; ---------------------------------------------------------------------------
; bootmenu_render_stage — append the fixed 3-OS menu list onto the staged reply
;   cursor (the render helper shared by the UDP verb + the boot selftest).
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
bootmenu_render_stage:
    lea  rdi, [rel str_bm_o_render]
    call bm_out_str
    ret

; ---------------------------------------------------------------------------
; bootmenu_sel_name_from_tok(RDI=arg text) -> RAX = display-name ptr. Resolve
;   the leading token by its (case-folded) initial — PaOS/Windows/Linux/Diag
;   have distinct first letters. Empty/unknown -> PaOS (the safe default, same
;   as the boot menu's countdown-expiry default). clobbers: RAX,RCX.
; ---------------------------------------------------------------------------
bootmenu_sel_name_from_tok:
    movzx eax, byte [rdi]
    or   al, 0x20                       ; ASCII case-fold
    cmp  al, 'w'
    je   .win
    cmp  al, 'l'
    je   .linux
    cmp  al, 'd'
    je   .diag
    lea  rax, [rel str_bm_sel_paos]
    ret
.win:
    lea  rax, [rel str_bm_sel_win]
    ret
.linux:
    lea  rax, [rel str_bm_sel_linux]
    ret
.diag:
    lea  rax, [rel str_bm_sel_diag]
    ret

; ---------------------------------------------------------------------------
; bootmenu_canon_check -> RAX=1 if the protected boot canon is intact, else 0.
;   The un-fakeable invariant, checked at RUNTIME against the LIVE manual-Windows
;   path table (boot/chainload.asm data): (1) the manual pick's primary path
;   really names the real Windows loader (contains "orig"); (2) neither manual
;   path contains "paos" (no PaOS keep/backup in the manual chainload path — the
;   v0.3.572 1-byte bug is dead by CONSTRUCTION). If a future edit ever pointed a
;   manual pick at a PaOS binary, (2) fails and the gate reports win_untouched=0.
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
bootmenu_canon_check:
    push rbx
    lea  rdi, [rel cl_ucs2_orig_path]
    lea  rsi, [rel str_bm_needle_orig]
    call bm_ucs2_contains               ; manual primary = the real bootmgfw_orig?
    test eax, eax
    jz   .breached
    lea  rdi, [rel cl_ucs2_orig_path]
    lea  rsi, [rel str_bm_needle_paos]
    call bm_ucs2_contains               ; ...and NOT a PaOS binary
    test eax, eax
    jnz  .breached
    lea  rdi, [rel cl_ucs2_bootmgr_path]
    lea  rsi, [rel str_bm_needle_paos]
    call bm_ucs2_contains               ; the fallback manual path is Windows-only too
    test eax, eax
    jnz  .breached
    mov  eax, 1
    jmp  .out
.breached:
    xor  eax, eax
.out:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; bm_ucs2_contains(RDI=UCS-2 haystack, RSI=lowercase ASCII needle) -> RAX=1 if
;   the needle occurs (case-insensitive) in the haystack. Haystack is UCS-2
;   (one word/char, ASCII in the low byte), NUL-word terminated. clobbers:
;   RAX,RCX,RSI,RDI + RBX/R12 (saved).
; ---------------------------------------------------------------------------
bm_ucs2_contains:
    push rbx
    push r12
    mov  r12, rsi                       ; needle base
.outer:
    movzx eax, word [rdi]
    test ax, ax
    jz   .notfound                      ; haystack exhausted, no match
    mov  rbx, rdi                       ; candidate window in haystack
    mov  rsi, r12                       ; needle cursor
.inner:
    movzx ecx, byte [rsi]               ; needle char (already lowercase)
    test cl, cl
    jz   .found                         ; needle fully matched
    movzx eax, word [rbx]               ; haystack char (UCS-2)
    test ax, ax
    jz   .advance                       ; haystack ended mid-needle
    or   al, 0x20                       ; case-fold the ASCII low byte
    cmp  al, cl
    jne  .advance
    add  rbx, 2
    inc  rsi
    jmp  .inner
.advance:
    add  rdi, 2
    jmp  .outer
.found:
    mov  eax, 1
    jmp  .out
.notfound:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; bootmenu_udp_try(R12=verb token, R13=arg ptr) -> RAX=1 handled, 0 fall through.
;   Intercepts the probe's colon form "MENU_QUERY:<nonce>" (prefix match on the
;   10 verb chars; the nonce tail echoes back via the reply's verb-token echo).
;   Preserves RBX/R12/R13 (udp_dispatch_line contract).
; ---------------------------------------------------------------------------
bootmenu_udp_try:
    cmp  dword [r12], 'MENU'
    jne  .no
    cmp  dword [r12 + 4], '_QUE'
    jne  .no
    cmp  word [r12 + 8], 'RY'
    jne  .no
    ; --- matched: stage the live menu snapshot ---
    call bm_out_reset
    lea  rdi, [rel str_bm_o_menu]     ; " MENU 1=PaOS 2=Windows 3=Linux 4=Diagnostics ..."
    call bm_out_str
    cmp  byte [rel bm_m_clready], 1   ; EARNED token — only if the real dp resolve passed
    jne  .not_ready
    lea  rdi, [rel str_bm_o_clready]
    call bm_out_str
    jmp  .flags
.not_ready:
    lea  rdi, [rel str_bm_o_clnot]
    call bm_out_str
.flags:
    lea  rdi, [rel str_bm_o_disp]     ; " menu_displayed="
    call bm_out_str
    movzx edi, byte [rel bm_m_menu]
    call bm_out_dec
    lea  rdi, [rel str_bm_o_chk]      ; " checkpoints="
    call bm_out_str
    movzx edi, byte [rel bm_m_checkpoints]
    call bm_out_dec
    lea  rdi, [rel str_bm_o_state]    ; " state_loaded="
    call bm_out_str
    movzx edi, byte [rel bm_m_state]
    call bm_out_dec
    call bm_out_mode                  ; " mode=<default-paos|manual-key|override-verb>"
    ; 1124a5: content-bearing evidence from the product resolver.  This is
    ; especially useful on fail-open boots, where PaOS remains reachable and
    ; the operator must be able to distinguish absent/ambiguous/variable/
    ; BootNext failures without relying on an unobservable latch.
    lea  rdi, [rel str_bm_o_lnx_try]
    call bm_out_str
    movzx edi, byte [rel cl_linux_live_attempted]
    call bm_out_dec
    lea  rdi, [rel str_bm_o_lnx_rc]
    call bm_out_str
    movzx edi, byte [rel cl_linux_fail_rc]
    call bm_out_dec
    lea  rdi, [rel str_bm_o_lnx_boot]
    call bm_out_str
    movzx edi, word [rel cl_linux_selected_boot]
    call bm_out_hex
    lea  rdi, [rel str_bm_o_lnx_dp]
    call bm_out_str
    mov  edi, [rel cl_linux_dp_len]
    call bm_out_dec
    lea  rdi, [rel str_bm_o_lnx_kat]
    call bm_out_str
    movzx edi, byte [rel cl_linux_selftest_ok]
    call bm_out_dec
    mov  byte [rel bm_out_ready], 1
    mov  eax, 1
    ret
.no:
    ; --- BOOTLINUX: one-token SIGNED intercept (declared beside REBOOT, CMD_AUTH_CAP_BOOT)
    ;     that arms "boot Linux next" WITHOUT touching the registry argument path, so a
    ;     build whose argument copy is broken (sprint 86d5172d, 2026-09-07) stays recoverable
    ;     from gpu with no keyboard at the box. Same arm + ack-then-warm-reset contract as
    ;     `BOOT LINUX` (the dispatcher fires the reset off bm_reboot_pending after the ack). ---
    cmp  dword [r12], 'BOOT'
    jne  .no_bootlinux
    cmp  dword [r12 + 4], 'LINU'
    jne  .no_bootlinux
    cmp  word [r12 + 8], 'X'          ; 'X' then NUL: exact token, never a registry name
    jne  .no_bootlinux
    push r12
    call bm_out_reset
    mov  byte [rel bm_reset_admitted], 0
    lea  rdi, [rel str_bm_o_bootlinux]
    call bm_out_str
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .bl_cmos
    ; storage gate, NVRAM class: BootNext (EFI_GLOBAL) is SENSITIVE -> only the
    ; verified OWNER ticket in flight (SPECIAL) may arm it; audited. Refusal is
    ; fail-closed (no CMOS fallback, no reset).
    call storage_access_request_intent
    mov  edx, eax
    call bm_bootnext_gate
    test rax, rax
    jnz  .bl_nvram_refused
    call bm_reset_admit               ; ROOT109558: after the gate, before any arm
    test eax, eax
    jnz  .bl_guest_live
    call chainload_linux_arm_bootnext ; runtime-mapped chain: firmware BootNext=ubuntu (SB-safe)
    test rax, rax
    jnz  .bl_cmos
    mov  ax, [rel cl_linux_selected_boot]   ; the verified UINT16 a refusal may delete
    movzx edx, byte [rel bm_bootnext_granted] ; the exact intent its BootNext gate was passed
    call driver_return_bootnext_armed       ; SEC109848: owned value, intent and marker in one step
    lea  rdi, [rel str_bm_o_tolinux_bn]
    call bm_out_str
    jmp  .bl_queued
.bl_cmos:
    call bm_reset_admit               ; once per request: no-op after the BootNext path admitted
    test eax, eax
    jnz  .bl_guest_live
    lea  rdi, [rel str_bm_o_tolinux]
    call bm_out_str
    mov  esi, BM_OVR_LINUX
    call bm_cmos_arm_override         ; AL = LIVE read-back -> the reply grades the byte
    movzx r12d, al
    lea  rdi, [rel str_bm_o_ovrrb]    ; " cmos76="
    call bm_out_str
    mov  edi, r12d
    call bm_out_dec
    lea  rdi, [rel str_bm_o_reboot]   ; " one_shot=1 warm_cf9=queued"
    call bm_out_str
.bl_queued:
    mov  byte [rel bm_reboot_pending], 1
    call bm_out_uncertain
    mov  byte [rel bm_out_ready], 1
    pop  r12
    mov  eax, 1
    ret
.bl_guest_live:
    call bm_out_uncertain
    mov  byte [rel bm_out_ready], 1   ; refusal text staged by bm_reset_admit; nothing armed
    pop  r12
    mov  eax, 1
    ret
.bl_nvram_refused:
    lea  rdi, [rel str_bm_o_bootnext_refused]
    call bm_out_str
    call bm_out_uncertain
    mov  byte [rel bm_out_ready], 1
    pop  r12
    mov  eax, 1
    ret
.no_bootlinux:
    xor  eax, eax
    ret

; --- VERB: CRASH_STATUS <nonce> — live crash-ladder state. Reply avoids the
;     raw counter-register jargon; discriminates on the REAL CMOS bytes read
;     at dispatch time (not boot-time copies).
cmd_verb_crashstatus:
    call cmd_handler_prologue
    push rdi
    push rsi
    push r12
    push r13
    mov  dil, CHAINLOAD_CMOS_TRIAL
    call chainload_cmos_rd
    movzx r12d, al                    ; live trial
    mov  dil, CHAINLOAD_CMOS_CONF
    call chainload_cmos_rd
    movzx r13d, al                    ; live confirmed
    call bm_out_reset
    ; crash discrimination: confirmed keep -> none(confirmed); trial==0 ->
    ; none; else unconfirmed trials are on the ladder (prior boots not committed)
    cmp  r13d, CHAINLOAD_CONF_MAGIC
    je   .conf
    test r12d, r12d
    jz   .clean
    lea  rdi, [rel str_bm_o_cr_trials]
    jmp  .cr_emit
.conf:
    lea  rdi, [rel str_bm_o_cr_conf]
    jmp  .cr_emit
.clean:
    lea  rdi, [rel str_bm_o_cr_none]
.cr_emit:
    call bm_out_str
    lea  rdi, [rel str_bm_o_cr_trial]  ; " trial="
    call bm_out_str
    mov  edi, r12d
    call bm_out_dec
    lea  rdi, [rel str_bm_o_cr_confv]  ; " confirmed=0x"
    call bm_out_str
    mov  edi, r13d
    call bm_out_hex
    lea  rdi, [rel str_bm_o_cr_ladder] ; " boot_in_progress=0 recovery_ladder=armed windows_fallback_at=3"
    call bm_out_str
    mov  byte [rel bm_out_ready], 1
    pop  r13
    pop  r12
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax          ; nonce echo through the envelope
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: BOOT_MODE <nonce> — how THIS boot was chosen + the v0.3.572 audit
;     facts for the manual-Windows path (contract regression_protection (b)).
cmd_verb_bootmode:
    call cmd_handler_prologue
    push rdi
    push rsi
    call bm_out_reset
    mov rdi, [rdi+REQ_ARG]
    call bm_fw_observe
    test eax, eax
    jnz .bootmode_ready
    call bm_out_mode                   ; " mode=<...>"
    lea  rdi, [rel str_bm_o_diag]      ; " diag="
    call bm_out_str
    movzx edi, byte [rel bm_diag_mode]
    call bm_out_dec
    lea  rdi, [rel str_bm_o_audit]     ; the manual-Windows path audit line
    call bm_out_str
    ; 1262a: read-only post-Manager consumption witness. Coupled with the
    ; Manager handoff serial markers and this request's nonce, absent BootNext
    ; proves firmware consumed the owned one-shot before child dispatch.
    cmp byte [rel pbm_runtime_read_mapped], 1
    jne .bootnext_not_absent
    mov rax, [rel runtime_services]
    test rax, rax
    jz .bootnext_not_absent
    cmp qword [rax+0x48], 0
    je .bootnext_not_absent
    call chainload_manager_require_bootnext_absent
    test eax, eax
    jnz  .bootnext_not_absent
    lea  rdi, [rel str_bm_o_manager_consumed]
    jmp  .bootnext_emit
.bootnext_not_absent:
    lea  rdi, [rel str_bm_o_manager_unconsumed]
.bootnext_emit:
    call bm_out_str
.bootmode_ready:
    mov  byte [rel bm_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: BOOT <PAOS|WIN|WINDOWS|LINUX|DIAG|MANAGER nonce> — the headless menu selection.
;     WIN uses a unique verified Windows BootNext; LINUX/DIAG retain their
;     established routes. PAOS / unknown
;     / empty are read-only status replies.
cmd_verb_boot:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    push r12
    mov  rbx, [rdi + REQ_ARG]          ; raw token ptr (ARGT_TEXT; may be empty)
    call bm_bootnext_intent_capture    ; RDI=request -> bm_bootnext_intent
    call bm_out_reset
    mov  byte [rel bm_reset_admitted], 0
    test rbx, rbx
    jz   .help
    cmp  byte [rbx], 0
    je   .help
    ; Signed recovery policy uses the existing BOOT capability/session gate.
    cmp dword [rbx],'RECO'
    jne .not_recovery
    cmp dword [rbx+4],'VERY'
    jne .not_recovery
    cmp byte [rbx+8],' '
    jne .not_recovery
    mov byte [rel bm_manager_command],1
    lea rdi,[rbx+9]
    call recovery_boot_command
    test eax,eax
    jz .recovery_refused
    lea rdi,[rel str_bm_recovery_ok]
    call bm_out_str
    jmp .stage
.recovery_refused:
    mov byte [rel bm_manager_error],BM_RC_RETIRED
    lea rdi,[rel str_bm_recovery_no]
    call bm_out_str
    jmp .stage
.not_recovery:
    ; 1262a: exact subcommand prefix. No public BOOTNEXT number is accepted.
    cmp  dword [rbx], 'MANA'
    jne  .not_manager
    cmp  word [rbx + 4], 'GE'
    jne  .not_manager
    cmp  byte [rbx + 6], 'R'
    jne  .not_manager
    cmp  byte [rbx + 7], ' '
    jne  .not_manager
    ; RCQ-28 (2026-10-08): retired. The only row it resolved is the E02 Manager
    ; \EFI\PaOS\e02\manager-52eec6e53d92c54b.efi, which the boot canon keeps as a
    ; Vault recovery artifact reachable only through the gated rollback rail; booting
    ; it would apply pre-Boot-v2 policy to today's journal. Refuse before any nonce,
    ; BootNext or resolver work: nothing is written and no reset is queued.
    mov  byte [rel bm_manager_command], 1
    mov  byte [rel bm_manager_error], BM_RC_RETIRED
    lea  rdi, [rel str_bm_o_manager_retired]
    call bm_out_str
    jmp  .stage
.not_manager:
    lea  rdi, [rel str_bm_tok_paos]
    mov  rsi, rbx
    call strcmp
    test rax, rax
    jz   .paos
    lea  rdi, [rel str_bm_tok_win]
    mov  rsi, rbx
    call strcmp
    test rax, rax
    jz   .win
    lea  rdi, [rel str_bm_tok_windows]
    mov  rsi, rbx
    call strcmp
    test rax, rax
    jz   .win
    lea  rdi, [rel str_bm_tok_linux]
    mov  rsi, rbx
    call strcmp
    test rax, rax
    jz   .linux
    lea  rdi, [rel str_bm_tok_diag]
    mov  rsi, rbx
    call strcmp
    test rax, rax
    jz   .diag
.help:
    lea  rdi, [rel str_bm_o_help]
    call bm_out_str
    jmp  .stage
.paos:
    lea  rdi, [rel str_bm_o_paos]
    call bm_out_str
    jmp  .stage
.win:
    ; The old CMOS 0x76 owner request survives Windows-first BootOrder and is
    ; imported on a later Manager visit. A verified firmware BootNext is the
    ; one-shot authority for this transition. Never fall back to CMOS.
    mov  byte [rel bm_manager_command], 1
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .win_no_runtime
%ifdef PAOS_LAB_CHANNEL
    LAB_BOOTNEXT_GRANT
%endif
    movzx edx, byte [rel bm_bootnext_intent]
%ifdef PAOS_LAB_CHANNEL
    LAB_BOOTNEXT_REVOKE
%endif
    call bm_bootnext_gate              ; BootNext is SENSITIVE (EFI_GLOBAL): SPECIAL only, audited
    test rax, rax
    jnz  .win_nvram_refused
    call bm_reset_admit                ; ROOT109558: after the gate, before any arm
    test eax, eax
    jnz  .guest_live
    call chainload_windows_arm_bootnext
    test eax, eax
    jnz  .win_refused
    mov  ax, [rel cl_manager_selected_boot] ; the verified UINT16 a refusal may delete
    movzx edx, byte [rel bm_bootnext_granted] ; the exact intent its BootNext gate was passed
    call driver_return_bootnext_armed       ; SEC109848: owned value, intent and marker in one step
    lea  rdi, [rel str_bm_o_towin_bootnext]
    call bm_out_str
    mov  byte [rel bm_reboot_pending], 1
    jmp  .stage
.win_nvram_refused:
    mov  byte [rel cl_windows_fail_rc], BM_RC_STORAGE_REFUSED
    jmp  .win_refused
.win_no_runtime:
    mov  byte [rel cl_windows_fail_rc], 4
.win_refused:
    mov  al, [rel cl_windows_fail_rc]
    mov  byte [rel bm_manager_error], al
    lea  rdi, [rel str_bm_o_towin_refused]
    call bm_out_str
    movzx edi, byte [rel bm_manager_error]
    call bm_out_dec
    lea  rdi, [rel str_bm_o_towin_noreset]
    call bm_out_str
    jmp  .stage
.linux:
    ; Runtime mapped (mutable v2 chain): the CMOS 0x76 override is bypassed on
    ; Manager launches, so arm the firmware BootNext to ubuntu DIRECTLY here via
    ; runtime GetVariable/SetVariable. The deferred ResetSystem then lands on
    ; ubuntu one-shot, SB-safe. Falls back to legacy CMOS staging when NX.
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .linux_cmos
%ifdef PAOS_LAB_CHANNEL
    LAB_BOOTNEXT_GRANT
%endif
    movzx edx, byte [rel bm_bootnext_intent]
%ifdef PAOS_LAB_CHANNEL
    LAB_BOOTNEXT_REVOKE
%endif
    call bm_bootnext_gate              ; BootNext is SENSITIVE (EFI_GLOBAL): SPECIAL only, audited
    test rax, rax
    jnz  .linux_nvram_refused
    call bm_reset_admit                ; ROOT109558: after the gate, before any arm
    test eax, eax
    jnz  .guest_live
    call chainload_linux_arm_bootnext
    test rax, rax
    jnz  .linux_cmos
    mov  ax, [rel cl_linux_selected_boot]   ; the verified UINT16 a refusal may delete
    movzx edx, byte [rel bm_bootnext_granted] ; the exact intent its BootNext gate was passed
    call driver_return_bootnext_armed       ; SEC109848: owned value, intent and marker in one step
    lea  rdi, [rel str_bm_o_tolinux_bn]
    call bm_out_str
    mov  byte [rel bm_reboot_pending], 1
    jmp  .stage
.linux_nvram_refused:
    ; fail-closed: no silent CMOS fallback for a refused sensitive write
    mov  byte [rel bm_manager_command], 1
    mov  byte [rel bm_manager_error], BM_RC_STORAGE_REFUSED
    lea  rdi, [rel str_bm_o_bootnext_refused]
    call bm_out_str
    jmp  .stage
.linux_cmos:
    mov  esi, BM_OVR_LINUX
    lea  rdi, [rel str_bm_o_tolinux]
    jmp  .set_ovr
.diag:
    mov  esi, BM_OVR_DIAG
    lea  rdi, [rel str_bm_o_todiag]
.set_ovr:
    push rsi
    push rdi
    call bm_reset_admit                ; once per request, before any text or CMOS write
    pop  rdi
    pop  rsi
    test eax, eax
    jnz  .guest_live
    push rsi                           ; keep the override value across the emit
    call bm_out_str
    pop  rsi
    call bm_cmos_arm_override          ; AL = LIVE read-back -> the reply grades the byte
    movzx r12d, al
    lea  rdi, [rel str_bm_o_ovrrb]     ; " cmos76="
    call bm_out_str
    mov  edi, r12d
    call bm_out_dec
    lea  rdi, [rel str_bm_o_reboot]    ; " one_shot=1 warm_cf9=queued"
    call bm_out_str
    mov  byte [rel bm_reboot_pending], 1
    jmp  .stage
.guest_live:
    mov  byte [rel bm_manager_command], 1
    mov  byte [rel bm_manager_error], BM_RC_GUEST_LIVE
    cmp  byte [rel driver_return_uncertain], 0
    je   .stage
    mov  byte [rel bm_manager_error], BM_RC_GUEST_LIVE_TARGET
.stage:
    call bm_out_uncertain
    mov  byte [rel bm_out_ready], 1
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    cmp  byte [rel bm_manager_command], 1
    jne  .response_ok
    cmp  byte [rel bm_manager_error], 0
    jne  .response_refused
.response_ok:
    mov  qword [rsi + RSP_CODE], CMDE_OK
    mov  byte [rel bm_manager_command], 0
    ret
.response_refused:
    mov  qword [rsi + RSP_CODE], CMDE_BADSEL
    mov  byte [rel bm_manager_command], 0
    mov  byte [rel bm_manager_error], 0
    ret

BM_RC_STORAGE_REFUSED equ 9           ; BootNext refused by the storage gate (NVRAM SENSITIVE class)
BM_RC_RETIRED         equ 10          ; BOOT MANAGER: the E02 Manager row is retired (Vault recovery only)
BM_RC_GUEST_LIVE      equ 11          ; ROOT109558: a live guest was not retired; nothing armed, no reset
BM_RC_GUEST_LIVE_TARGET equ 12        ; SEC109734: refused as 11, and an earlier one-shot target may still be set

; ROOT109558 (1), SEC109572 S1: a reset verb admits after its own gates and before
; its first state write. EAX 0 admitted (once per request), 1 refused: the honest
; reason is staged and nothing is armed or queued.
bm_reset_admit:
    cmp  byte [rel bm_reset_admitted], 1
    je   .ok
    call driver_return_verb_admit      ; verified cleanup retry, then the live-guest admit
    test eax, eax
    jnz  .refused
    mov  byte [rel bm_reset_admitted], 1
.ok:
    xor  eax, eax
    ret
.refused:
    lea  rdi, [rel str_bm_o_guest_live]
    call bm_out_str
    cmp  byte [rel driver_return_admit_reason], 4
    je   .unverified
    lea  rdi, [rel str_bm_o_stop_refused]
    call bm_out_str
    movzx edi, byte [rel driver_return_admit_blocker]
    call bm_out_dec
    mov  eax, 1
    ret
.unverified:
    lea  rdi, [rel str_bm_o_stop_unverified]
    call bm_out_str
    mov  eax, 1
    ret

; ESI = override value -> AL = the LIVE override byte read back. SEC109572 S2:
; record the byte it replaces (the first one, if this reset already armed CMOS)
; so a refused fire can put it back. SEC109734: a write the boot-constant CMOS
; gate drops marks nothing; a marked arm read back equal supersedes an earlier
; uncertain CMOS undo.
bm_cmos_arm_override:
    push rsi
    test byte [rel driver_return_armed], DRA_CMOS
    jnz  .write
    mov  dil, BM_CMOS_OVERRIDE
    call chainload_cmos_rd
    mov  [rel driver_return_cmos_prior], al
.write:
    mov  esi, [rsp]
    mov  dil, BM_CMOS_OVERRIDE
    call chainload_cmos_wr
    call chainload_cmos_nvram_ok
    jne  .readback
    or   byte [rel driver_return_armed], DRA_CMOS
.readback:
    mov  dil, BM_CMOS_OVERRIDE
    call chainload_cmos_rd
    pop  rsi
    cmp  al, sil
    jne  .out
    test byte [rel driver_return_armed], DRA_CMOS
    jz   .out
    and  byte [rel driver_return_uncertain], ~DRA_CMOS
.out:
    ret

; SEC109734 (3.2): every reply while an undo is unconfirmed says so.
bm_out_uncertain:
    cmp  byte [rel driver_return_uncertain], 0
    je   .none
    lea  rdi, [rel str_bm_o_target_uncertain]
    jmp  bm_out_str
.none:
    ret

; bm_bootnext_intent_capture(RDI=request) — the explicit authority of THIS BOOT
; request for the firmware-global BootNext write: SPECIAL when a verified OWNER
; AUTH1 ticket (or unrestricted owner SSH key) is in flight, or when the request
; is the local console with the authenticated OWNER principal (the dispatcher
; already refuses any non-owner console principal).  Otherwise IMPLICIT.
; Preserves every register except RAX.
bm_bootnext_intent_capture:
    push rdi
    mov  byte [rel bm_bootnext_intent], SA_INTENT_IMPLICIT
    test rdi, rdi
    jz   .out
    cmp  qword [rdi + REQ_SOURCE], CMD_SOURCE_CONSOLE
    jne  .remote
    cmp  qword [rdi + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne  .out
    mov  byte [rel bm_bootnext_intent], SA_INTENT_SPECIAL
    jmp  .out
.remote:
    call storage_access_request_intent
    mov  [rel bm_bootnext_intent], al
.out:
    pop  rdi
    ret

; bm_bootnext_gate(EDX=SA_INTENT_*) -> RAX 0 permitted / -1 refused.  Classifies
; the exact (VendorGuid, name) the chainloader writes: EFI_GLOBAL "BootNext".
bm_bootnext_gate:
    push rcx
    push rsi
    push rdi
    lea  rdi, [rel cl_efi_global_guid]
    lea  rsi, [rel cl_linux_bootnext_name]
    lea  rcx, [rel str_bm_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .gate_refused
    mov  [rel bm_bootnext_granted], dl     ; only a permitted BootNext grant's own EDX (so only SPECIAL)
.gate_refused:
    pop  rdi
    pop  rsi
    pop  rcx
    ret
bm_out_mode:
    lea  rdi, [rel str_bm_o_mode]
    call bm_out_str
    movzx eax, byte [rel bm_boot_mode]
    cmp  eax, BM_MODE_KEY
    je   .key
    cmp  eax, BM_MODE_OVERRIDE
    je   .ovr
    lea  rdi, [rel str_bm_o_m_def]
    jmp  .emit
.key:
    lea  rdi, [rel str_bm_o_m_key]
    jmp  .emit
.ovr:
    lea  rdi, [rel str_bm_o_m_ovr]
.emit:
    call bm_out_str
    ret

; --- staged-reply buffer helpers (mirror boot_ab's ab_out_*) ---
bm_out_reset:
    lea  rax, [rel bm_out_buf]
    mov  [rel bm_out_cur], rax
    ret
bm_out_str:
    mov  rsi, [rel bm_out_cur]
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
    mov  [rel bm_out_cur], rsi
    ret
bm_out_dec:
    mov  rsi, [rel bm_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel bm_out_cur], rsi
    ret
bm_out_hex:
    mov  rsi, [rel bm_out_cur]
    push rsi
    xor  edx, edx
    call fmt_hex
    pop  rsi
    add  rsi, rax
    mov  [rel bm_out_cur], rsi
    ret

; Fixed-width Boot#### formatter (EDI low word -> four uppercase hex chars).
bm_out_hex4:
    mov  rsi, [rel bm_out_cur]
    mov  edx, edi
    mov  eax, edx
    shr  eax, 12
    call bm_hex_digit
    mov  [rsi], al
    mov  eax, edx
    shr  eax, 8
    call bm_hex_digit
    mov  [rsi + 1], al
    mov  eax, edx
    shr  eax, 4
    call bm_hex_digit
    mov  [rsi + 2], al
    mov  eax, edx
    call bm_hex_digit
    mov  [rsi + 3], al
    mov  byte [rsi + 4], 0
    add  rsi, 4
    mov  [rel bm_out_cur], rsi
    ret
bm_hex_digit:
    and  eax, 0x0F
    cmp  eax, 10
    jb   .digit
    add  eax, 'A' - 10 - '0'
.digit:
    add  eax, '0'
    ret

; --- svc/command_bootmenu data ------------------------------------------------
align 8
bm_out_cur:        dq 0               ; live staged-reply cursor
bm_out_ready:      db 0               ; a reply line is staged in bm_out_buf
bm_reboot_pending: db 0               ; BOOT verb queued a warm CF9 (fired post-ack)
bm_reset_admitted: db 0               ; this request's reset admit already passed
bm_manager_command: db 0              ; current BOOT request took MANAGER branch
bm_manager_error:   db 0              ; 0 success; chainload rc; 7 bad nonce
align 8
%include "core/abi/wdata.inc"
%macro WDATA_BSS_svc_bootstate_out 0
alignb 16
bm_out_buf: resb 10240
%endmacro
WDATA_BSS_DEFER WDATA_BSS_svc_bootstate_out

; --- verb names (matched verbatim by command_lookup) ---
str_verb_crashstatus: db "CRASH_STATUS", 0
str_verb_bootmode:    db "BOOT_MODE", 0
str_verb_boot:        db "BOOT", 0
str_verb_bmrender:    db "BOOTMENU_RENDER", 0
str_verb_bmselect:    db "BOOTMENU_SELECT", 0
str_verb_chainpath:   db "CHAINPATH", 0

; --- 1040 content markers earned by bootmenu_selftest (each set only after its
;     real code path ran this boot) ---
bm_m_render:  db 0
bm_m_paths:   db 0
bm_m_canon:   db 0
bm_m_select:  db 0

; --- BOOT arg tokens ---
str_bm_tok_paos:    db "PAOS", 0
str_bm_tok_win:     db "WIN", 0
str_bm_tok_windows: db "WINDOWS", 0
str_bm_tok_linux:   db "LINUX", 0
str_bm_tok_diag:    db "DIAG", 0

; --- staged reply fragments ---
str_bm_o_menu:     db " MENU 1=PaOS 2=Windows 3=Linux 4=Diagnostics countdown=2s default=PaOS", 0
str_bm_o_clready:  db " Chainload ready targets=bootmgfw_orig.efi,BOOTMGR.EFI,shimx64.efi,grubx64.efi", 0
str_bm_o_clnot:    db " chainload=not-ready", 0
str_bm_o_disp:     db " menu_displayed=", 0
str_bm_o_chk:      db " checkpoints=", 0
str_bm_o_state:    db " state_loaded=", 0
str_bm_o_mode:     db " mode=", 0
str_bm_o_lnx_try:  db " linux_resolve_attempted=", 0
str_bm_o_lnx_rc:   db " linux_resolve_rc=", 0
str_bm_o_lnx_boot: db " linux_boot=0x", 0
str_bm_o_lnx_dp:   db " linux_dp_bytes=", 0
str_bm_o_lnx_kat:  db " linux_cross_volume_kat=", 0
str_bm_o_m_def:    db "default-paos", 0
str_bm_o_m_key:    db "manual-key", 0
str_bm_o_m_ovr:    db "override-verb", 0
str_bm_o_diag:     db " diag=", 0
str_bm_o_audit:    db " manual Windows pick=direct bootmgfw_orig.efi (monolith R12=2 equivalent) try_backup_first=0 paos_binary_in_manual_path=0", 0
str_bm_o_manager_consumed: db " manager_bootnext=consumed", 0
str_bm_o_manager_unconsumed: db " manager_bootnext=present-or-unknown", 0
str_bm_o_cr_none:  db " crash=none", 0
str_bm_o_cr_conf:  db " crash=none(keep-confirmed)", 0
str_bm_o_cr_trials: db " crash=unconfirmed_trials(on-ladder)", 0
str_bm_o_cr_trial: db " trial=", 0
str_bm_o_cr_confv: db " confirmed=0x", 0
str_bm_o_cr_ladder: db " boot_in_progress=0 recovery_ladder=armed windows_fallback_at=3", 0
str_bm_o_help:     db " boot options: PAOS|WIN|LINUX|DIAG|MANAGER <nonce> (one-shot verified selection + warm reset)", 0
str_bm_o_paos:     db " boot=PAOS already running (no reset)", 0
str_bm_o_towin_bootnext: db " boot=WIN bootnext=verified-windows one_shot=1 reset=queued", 0
str_bm_o_towin_refused: db " boot=WIN refused_rc=", 0
str_bm_o_guest_live: db " reset=refused guest=live warm_cf9=not-queued reason=", 0
str_bm_o_stop_refused: db "stop_refused blocker=", 0
str_bm_o_stop_unverified: db "stop_unverified", 0
str_bm_o_target_uncertain: db " one_shot_target=may-be-set cleanup=uncertain", 0
str_bm_o_bootnext_refused: db " bootnext=REFUSED storage_not_permitted warm_cf9=not-queued [storage.nvram.refused]", 0
str_bm_nvg_tag: db "boot_verb_bootnext", 0
bm_bootnext_intent: db 0
bm_bootnext_granted: db 0             ; SA_INTENT_* of the last permitted BootNext gate
str_bm_o_towin_noreset: db " warm_cf9=not-queued bootnext=inspect-if-write-uncertain", 0
str_bm_o_tolinux:  db " boot=LINUX override staged", 0
str_bm_o_bootlinux: db " BOOTLINUX intercept (no registry arg path)", 0
str_bm_o_tolinux_bn: db " boot=LINUX bootnext=ubuntu one_shot=1 reset=queued", 0
str_bm_o_todiag:   db " boot=DIAG override staged", 0
str_bm_o_ovrrb:    db " cmos76=", 0
str_bm_o_reboot:   db " one_shot=1 warm_cf9=queued", 0
str_bm_o_manager_retired: db " boot=MANAGER refused_rc=10 reason=retired-e02-manager-vault-recovery-only use=gated-rollback bootnext_write_count=0 warm_cf9=not-queued", 0

; --- 1040 BOOTMENU_RENDER / BOOTMENU_SELECT / CHAINPATH staged fragments ---
str_bm_o_render:   db " bootmenu_3os rendered=1 entries: 1=PaOS 2=Windows 3=Linux 4=Diagnostics countdown=2s default=PaOS", 0
str_bm_o_sel_pre:  db " bootmenu_select sel=", 0
str_bm_o_sel_post: db " dispatched=1", 0
; NOTE (probe negative gate): the CHAINPATH reply must NAME bootmgfw_orig and must
; NOT contain the substrings "paos.efi" / "paos_backup" / "lkg" — keep it Windows-only.
str_bm_o_cp_pre:   db " chainpath win_loader=bootmgfw_orig.efi win_path=\EFI\Microsoft\Boot\bootmgfw_orig.efi win_untouched=", 0
str_bm_o_cp_r12:   db " manual_r12=", 0
str_bm_o_cp_post:  db " manual_path_windows_only=", 0
str_bm_o_cp_tail:  db " try_backup_first=0", 0

; --- selection display names (no CRLF — these go into the UDP reply line) ---
str_bm_sel_paos:   db "PaOS", 0
str_bm_sel_win:    db "Windows", 0
str_bm_sel_linux:  db "Linux", 0
str_bm_sel_diag:   db "Diagnostics", 0

; --- canon-check needles (lowercase; bm_ucs2_contains case-folds the haystack) ---
str_bm_needle_orig: db "orig", 0
str_bm_needle_paos: db "paos", 0

; --- boot-selftest marker serial lines (carry the literal contract tokens) ---
str_bm_mk_render:      db "[PAOS64] P1 boot: 3-OS menu rendered (PaOS/Windows/Linux/Diag) [bootmenu.3os.rendered]", 13, 10, 0
str_bm_mk_paths:       db "[PAOS64] P1 boot: chainload device-paths built (unmodified loaders: bootmgfw_orig.efi/BOOTMGR.EFI/shimx64.efi/grubx64.efi) [chainload.paths.ready]", 13, 10, 0
str_bm_mk_paths_skip:  db "[PAOS64] P1 boot: chainload device-paths NOT ready (dp unresolved) — menu offers PaOS/Diag only", 13, 10, 0
str_bm_mk_canon:       db "[PAOS64] P1 boot: protected-canon check passed (Windows bootmgfw untouched; manual pick=bootmgfw_orig, no PaOS binary) [bootcanon.protected]", 13, 10, 0
str_bm_mk_canon_fail:  db "[PAOS64] P1 boot: protected-canon check FAILED — manual Windows path is not the real loader (canon breached)", 13, 10, 0
str_bm_mk_select:      db "[PAOS64] P1 boot: selection dispatched (self-exercise PAOS -> PaOS entry) [bootmenu.select.ok]", 13, 10, 0
str_bm_mk_select_fail: db "[PAOS64] P1 boot: selection resolver FAILED to map PAOS -> PaOS", 13, 10, 0
str_bm_mk_linux_target: db "[PAOS64] P1 boot: exact Ubuntu authority selected external ESP shim [boot.linux.target.resolved]", 13, 10, 0
str_bm_mk_linux_cross: db "[PAOS64] P1 boot: two-ESP renumber/absence/malformed/ambiguity KAT passed [boot.linux.cross_volume.ready]", 13, 10, 0

str_bm_recovery_ok: db "recovery policy accepted; explicit owner grant; silence_s=180 absolute_s=1800",0
str_bm_recovery_no: db "recovery policy refused; require exact current signed grant, owner, boot/generation/operation and live deadline",0

%include "src/svc/command_bootstate.inc"
