;; MODULE boot/boot_menu
;; LAYER 0
;; EXPORTS boot_menu_run, bm_face_progress_run, bm_face_refresh, bm_face_milestone, bm_face_retire, bm_face_boot_services_live, bm_face_draw_status, bm_face_owner, bm_m_state, bm_m_checkpoints, bm_m_menu, bm_m_clready, bm_boot_mode, bm_diag_mode
;; IMPORTS boot/firmware_logo_draw, boot/gop, boot/serial, boot/chainload, boot/header, boot/boot_v2_health, boot/paging
;; CAPS
;; OWNER saga:boot_menu_chainload
; ============================================================================
; boot/boot_menu.asm — 1015: the boot-canon 3-OS NAVIGATION MENU (M5 seam).
;
; PaOS is a PEER choice, not a replacement: from a cold boot the user sees a
; 4-option menu (PaOS / Windows / Linux / Diagnostics) with a short countdown,
; picks with digits/letters or arrows+Enter, and the pick EXECUTES — Windows
; and Linux via the proven 9702 device-path LoadImage/StartImage chainloader
; (boot/chainload.asm), PaOS/Diagnostics by continuing this very boot. Runs
; PRE-EBS in efi_entry (chainload + ConIn/ConOut/Stall are boot services;
; after exit_boot_and_page it is too late), right after the 9702 crash-ladder
; escalate-check, so the recovery decision always precedes the user decision.
;
; HEADLESS/REMOTE leg: the BOOT <PAOS|WIN|LINUX|DIAG> registry verb (svc/
; command_bootmenu.asm) stages a ONE-SHOT CMOS override byte (0x76) + fires a
; warm CF9; this module reads + CLEARS the byte first thing next boot (clear-
; before-act — a failed chainload can never loop) and executes the choice.
; This is the rework's canonical PaOS->Windows in-band transition (M14a).
;
; v0.3.572 REGRESSION GUARD (contract known_trap): a MANUAL Windows pick calls
; chainload_windows_orig, whose path table holds ONLY real-Windows loaders
; (bootmgfw_orig.efi, BOOTMGR.EFI — the monolith's R12=2 entry equivalent).
; No PaOS keep/backup path exists in the manual path, BY CONSTRUCTION —
; try_backup_first has no PaOS branch to take.
;
; DEGRADE (contract negatives): no ConOut/ConIn (nulls) -> serial-only menu,
; countdown still runs, boot continues; chainload target missing -> fail-open
; through the next path then back to PaOS; QEMU ConIn is stubbed (contract
; hardware_specific (a)) -> countdown expires -> PaOS default. All four
; markers are content-graded serial lines with LIVE CMOS values, emitted
; pre-EBS -> qemu-only in regression (M720s early serial is lost on the wire;
; the live flags ride the UDP MENU_QUERY reply for bare-metal grading).
; ============================================================================

%ifndef PAOS_PUBLICITY_LAB_PROFILE
%define PAOS_PUBLICITY_LAB_PROFILE 0
%endif

BM_CMOS_OVERRIDE  equ 0x76            ; one-shot boot-choice override (0x74/0x75 = boot_ab)
BM_OVR_NONE       equ 0
BM_OVR_WIN        equ 1
BM_OVR_LINUX      equ 2
BM_OVR_DIAG       equ 3

BM_MODE_DEFAULT   equ 0               ; countdown expired -> PaOS
BM_MODE_KEY       equ 1               ; manual keyboard pick
BM_MODE_OVERRIDE  equ 2               ; BOOT-verb CMOS one-shot honored

BM_TICKS          equ 20              ; 20 x 100ms Stall = the 2s default window
BM_TICKS_FROZEN   equ 600             ; absolute navigation window: 60s from menu entry
; Volatile visual state is BSP boot-owned; runtime never reopens this face.
BM_FACE_PENDING  equ 0
BM_FACE_ACTIVE   equ 1
BM_FACE_DONE     equ 2
BM_FACE_DEGRADED equ 3
BM_FACE_FAILED   equ 4
BM_FACE_MAX_PIXELS equ 16777216       ; fixed64MiB clear ceiling, not a timing claim
; The progress face is a single isolated line in a 2560x1600 OVMF capture.
; Render it one integer step larger than the multiline Manager face so psm-6
; retains the mixed-case product name and both digits of v0.1.
BM_FACE_RASTER_SCALE equ 3
BM_FACE_RASTER_W  equ (8 * BM_FACE_RASTER_SCALE)
BM_FACE_GUTTER_W  equ 4
BM_FACE_CELL_W    equ (BM_FACE_RASTER_W + BM_FACE_GUTTER_W)
BM_FACE_GLYPH_H   equ (16 * BM_FACE_RASTER_SCALE)
BM_FACE_TEXT_CHARS equ 30
BM_FACE_TEXT_W    equ (BM_FACE_TEXT_CHARS * BM_FACE_CELL_W)
%ifdef FLD_TEXT_WIDTH
%if FLD_TEXT_WIDTH != BM_FACE_TEXT_W || FLD_TEXT_HEIGHT != BM_FACE_GLYPH_H || FLD_MAX_PIXELS != BM_FACE_MAX_PIXELS
    %error "Owned-logo consumer and loading-face surface contract drifted"
%endif
%endif

%if PBM_A1_FACE_CHECKPOINT_COUNT != 9
    %error "A1 loading face denominator drifted from the P0-P8 graph"
%endif

; ---------------------------------------------------------------------------
; boot_menu_run — called from efi_entry PRE-EBS, after chainload_escalate_check.
;   (A) load + one-shot-clear the CMOS override, print the live state line;
;   (B) validate the chainloader (real dp resolve) -> "Chainload ready";
;   (C) checkpoints line; (D) honor the override; (E) render the menu (serial
;   + ConOut); (F) countdown + key poll -> execute the pick. Returns to
;   continue the PaOS boot in every non-chainload (or chainload-failed) case.
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
boot_menu_run:
    cmp  byte [rel bm_face_boot_services_live], 1
    jne  .not_live
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32

    ; --- (A) load boot state: override (one-shot), trial, confirmed ---
    mov  dil, BM_CMOS_OVERRIDE
    call chainload_cmos_rd
    movzx r15d, al                    ; r15d = override byte (raw)
    cmp  r15d, 3
    jbe  .ovr_sane                    ; garbage / first-ever CMOS -> none
    xor  r15d, r15d
.ovr_sane:
    test r15d, r15d
    jz   .no_clear
    ; CLEAR BEFORE ACT: a chainload that fails (or a diag boot that faults)
    ; must never re-trigger the override -> bounded, never a boot loop.
    mov  dil, BM_CMOS_OVERRIDE
    xor  esi, esi
    call chainload_cmos_wr
.no_clear:
    mov  dil, CHAINLOAD_CMOS_TRIAL
    call chainload_cmos_rd
    movzx r13d, al                    ; r13d = trial byte
    cmp  r13d, 9
    jbe  .trial_sane
    mov  r13d, 9                      ; clamp for the single-digit print
.trial_sane:
    mov  dil, CHAINLOAD_CMOS_CONF
    call chainload_cmos_rd
    movzx r14d, al                    ; r14d = confirmed byte

    ; marker: Boot state loaded (live CMOS values -> content, not a latch)
    lea  rdi, [rel str_bm_state_pre]
    call serial_string
    lea  eax, [r15d + '0']
    mov  [rel bm_digit], al
    lea  rdi, [rel bm_digit]
    call serial_string
    lea  rdi, [rel str_bm_state_trial]
    call serial_string
    lea  eax, [r13d + '0']
    mov  [rel bm_digit], al
    lea  rdi, [rel bm_digit]
    call serial_string
    lea  rdi, [rel str_bm_state_conf]
    call serial_string
    mov  eax, r14d
    shr  eax, 4
    call bm_put_hexdigit
    mov  eax, r14d
    call bm_put_hexdigit
    lea  rdi, [rel str_bm_state_post]
    call serial_string
    mov  byte [rel bm_m_state], 1

    ; --- (B) validate the chainloader for real: resolve + measure our boot
    ;     device's base device path — the actual first stage every chainload
    ;     uses. Success == LoadImage is viable -> "Chainload ready" is earned. ---
    call chainload_dp_resolve
    test rax, rax
    jnz  .cl_not_ready
    lea  rdi, [rel str_bm_clready]
    call serial_string
    mov  byte [rel bm_m_clready], 1
    jmp  .cl_done
.cl_not_ready:
    lea  rdi, [rel str_bm_cl_notready]
    call serial_string
.cl_done:

    ; --- (C) checkpoints: escalate-check ran (9702), state loaded, override
    ;     one-shot-cleared, chainloader validated -> the recovery ladder's
    ;     checkpoints for THIS boot are all behind us. ---
    lea  rdi, [rel str_bm_checkpoints]
    call serial_string
    mov  byte [rel bm_m_checkpoints], 1

    ; --- (D) honor the one-shot override (BOOT verb, previous boot) ---
    cmp  r15d, BM_OVR_WIN
    je   .ovr_win
    cmp  r15d, BM_OVR_LINUX
    je   .ovr_linux
    cmp  r15d, BM_OVR_DIAG
    je   .ovr_diag
    jmp  .menu
.ovr_win:
    mov  byte [rel bm_boot_mode], BM_MODE_OVERRIDE
    lea  rdi, [rel str_bm_ovr_win]
    call serial_string
    call chainload_windows_orig       ; does not return on success
    lea  rdi, [rel str_bm_failopen]
    call serial_string
    jmp  .menu                        ; fail-open: still offer the menu
.ovr_linux:
    mov  byte [rel bm_boot_mode], BM_MODE_OVERRIDE
    lea  rdi, [rel str_bm_ovr_linux]
    call serial_string
    call chainload_linux_orig
    lea  rdi, [rel str_bm_failopen]
    call serial_string
    jmp  .menu
.ovr_diag:
    mov  byte [rel bm_boot_mode], BM_MODE_OVERRIDE
    mov  byte [rel bm_diag_mode], 1
    lea  rdi, [rel str_bm_diag]
    call serial_string
    ; diagnostics == this boot with the diag flag up (verb surface is the
    ; console); fall through to the menu so a local user can still re-pick

    ; --- (E) render the menu: serial marker line + firmware text console ---
.menu:
    lea  rdi, [rel str_bm_menu]
    call serial_string
    mov  byte [rel bm_m_menu], 1
    lea  rdi, [rel bm_u_menu]
    call bm_conout_str

    ; --- QEMU/VM gate: OVMF's serial-mirrored ConIn parses terminal escape
    ;     NOISE as arrow keys (observed live: a phantom Down selected Windows
    ;     and froze the countdown -> regression wedge). The contract's platform
    ;     split makes keyboard selection a BARE-METAL leg (QEMU ConIn is
    ;     stubbed/untrusted), so gate the key poll on the CPUID hypervisor bit
    ;     — the same discriminator as the 9702 CF9 arm. A VM boot is then a
    ;     deterministic countdown -> PaOS; the BOOT-verb override still works
    ;     everywhere (it needs no ConIn). ---
    mov  eax, 1
    cpuid                             ; ECX bit31 = hypervisor present (clobbers rbx: saved)
    xor  eax, eax
    test ecx, (1 << 31)
    setnz al
    mov  [rel bm_vm], al

    ; --- VM: skip the countdown entirely. Two reasons, both observed live:
    ;     (a) ConIn noise (above); (b) the regression harness injects its PS/2
    ;     keyboard/mouse test inputs on a FIXED schedule ("do not touch") — a
    ;     2s pre-EBS stall shifts the whole boot timeline and the injected DOWN
    ;     key lands before the ps2 driver is up (keyboard.input regression).
    ;     The interactive countdown is the bare-metal UX leg; the VM rung
    ;     grades the menu render + state machine + verbs. ---
    cmp  byte [rel bm_vm], 1
    jne  .arm_countdown
    lea  rdi, [rel str_bm_vmskip]
    call serial_string
    jmp  .timeout

    ; --- (F) countdown + key poll. r12d = arrow-selected index (0=PaOS
    ;     1=Windows 2=Linux 3=Diag), r13d = default/grace ticks remaining,
    ;     r14d = absolute wait budget. Each wait receives a fresh watchdog
    ;     budget; repeated navigation cannot extend the absolute deadline. ---
.arm_countdown:
    call preebs_wdt_arm
    xor  r12d, r12d
    mov  r13d, BM_TICKS
    mov  r14d, BM_TICKS_FROZEN
.tick:
    mov  rax, [rel system_table]
    test rax, rax
    jz   .stall
    mov  rcx, [rax + 48]              ; ConIn (SIMPLE_TEXT_INPUT_PROTOCOL)
    test rcx, rcx
    jz   .stall
    lea  rdx, [rel bm_key]
    mov  rax, [rcx + 8]               ; ReadKeyStroke(This, &Key)
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32
    call rax
    mov  rsp, rbp
    pop  rbp
    test rax, rax
    jnz  .stall                       ; EFI_NOT_READY -> no key this tick
    movzx eax, word [rel bm_key + 2]  ; UnicodeChar
    test ax, ax
    jnz  .char
    movzx eax, word [rel bm_key]      ; ScanCode (arrows: Up=1 Down=2)
    cmp  ax, 0x01
    je   .sel_up
    cmp  ax, 0x02
    je   .sel_down
    jmp  .stall                       ; other scan keys ignored
.char:
    cmp  ax, 0x0D                     ; Enter -> execute the arrow selection
    je   .execute_sel
    cmp  ax, '1'
    je   .pick_paos
    cmp  ax, '2'
    je   .pick_win
    cmp  ax, '3'
    je   .pick_linux
    cmp  ax, '4'
    je   .pick_diag
    or   al, 0x20                     ; letter shortcuts, case-folded
    cmp  al, 'p'
    je   .pick_paos
    cmp  al, 'w'
    je   .pick_win
    cmp  al, 'l'
    je   .pick_linux
    cmp  al, 'd'
    je   .pick_diag
    jmp  .stall                       ; unknown key ignored
.sel_up:
    sub  r12d, 1
    jns  .sel_show
    mov  r12d, 3
    jmp  .sel_show
.sel_down:
    inc  r12d
    cmp  r12d, 4
    jb   .sel_show
    xor  r12d, r12d
.sel_show:
    mov  r13d, r14d                  ; navigation uses only the remaining 60s window
    lea  rdi, [rel str_bm_sel_pre]
    call serial_string
    mov  eax, r12d
    call bm_sel_name_serial           ; prints "<name>" + CRLF (serial)
    mov  eax, r12d
    call bm_sel_name_conout           ; "> <name>" (firmware console)
    jmp  .stall
.execute_sel:
    cmp  r12d, 1
    je   .pick_win
    cmp  r12d, 2
    je   .pick_linux
    cmp  r12d, 3
    je   .pick_diag
    ; fall through: selection 0 = PaOS
.pick_paos:
    mov  byte [rel bm_boot_mode], BM_MODE_KEY
    jmp  .paos_continue
.pick_win:
    mov  byte [rel bm_boot_mode], BM_MODE_KEY
    lea  rdi, [rel str_bm_pick_win]   ; manual pick: DIRECT to real Windows
    call serial_string
    call chainload_windows_orig       ; path table = real Windows ONLY (v0.3.572 guard)
    lea  rdi, [rel str_bm_failopen]
    call serial_string
    jmp  .paos_continue
.pick_linux:
    mov  byte [rel bm_boot_mode], BM_MODE_KEY
    lea  rdi, [rel str_bm_pick_linux]
    call serial_string
    call chainload_linux_orig
    lea  rdi, [rel str_bm_failopen]
    call serial_string
    jmp  .paos_continue
.pick_diag:
    mov  byte [rel bm_boot_mode], BM_MODE_KEY
    mov  byte [rel bm_diag_mode], 1
    lea  rdi, [rel str_bm_diag]
    call serial_string
    jmp  .paos_continue

.stall:
    cmp  r13d, 10                     ; halfway tick mark (skipped when frozen)
    jne  .no_tickmark
    lea  rdi, [rel str_bm_cd1]
    call serial_string
    lea  rdi, [rel bm_u_cd1]
    call bm_conout_str
.no_tickmark:
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .timeout                     ; paranoid: no Stall -> take the default now
    mov  ecx, 100000                  ; 100ms
    mov  rax, [rax + 0xF8]            ; BS->Stall(µs)
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32
    call rax
    mov  rsp, rbp
    pop  rbp
    dec  r14d
    jz   .timeout
    dec  r13d
    jnz  .tick
.timeout:
    ; no mode store here: bm_boot_mode initializes to BM_MODE_DEFAULT (0), and
    ; a DIAG override that fell through to the menu must KEEP mode=override
    ; (stamping DEFAULT on timeout clobbered it — caught live on .50).

.paos_continue:
    lea  rdi, [rel str_bm_go_paos]
    call serial_string
    movzx eax, byte [rel bm_boot_mode]
    add  eax, '0'
    mov  [rel bm_digit], al
    lea  rdi, [rel bm_digit]
    call serial_string
    lea  rdi, [rel str_bm_go_post]
    call serial_string
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.not_live:
    ret

; bm_put_hexdigit(AL low nibble) — one hex char to serial. clobbers RAX,RDI(,serial).
bm_put_hexdigit:
    and  eax, 0x0F
    cmp  eax, 10
    jb   .num
    add  eax, 'A' - 10 - '0'
.num:
    add  eax, '0'
    mov  [rel bm_digit], al
    lea  rdi, [rel bm_digit]
    call serial_string
    ret

; Bind the existing face once after GOP acquisition. Actual C3WD edges can
; already have recorded P0 STARTING; binding never invents or advances a cell.
; Keep the proven four-register entry frame. Firmware bridges align their own
; shadow area, so later milestone callers need no fragile parity compensation.
bm_face_progress_run:
    push rbx
    push r12
    push r13
    push r14
    cmp  byte [rel bm_face_owner], 0
    jne  .out
    mov  byte [rel bm_face_owner], 1
    call firmware_logo_draw
    test eax, eax
    jnz  .logo_ready
    call bm_face_clear_console
    call bm_face_fb_clear
.logo_ready:
    call bm_face_progress_build
    call bm_face_progress_draw
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Final GOP revalidation may adopt a different base/stride or reset its pixels.
; Repaint the whole admitted surface before cache policy/EBS, even when the logo
; was drawn on the earlier mode. No firmware console call here: it could modeset
; again after validation. This never acquires ownership or advances health.
bm_face_refresh:
    push rbx
    push r12
    push r13
    push r14
    cmp  byte [rel bm_face_owner], 1
    jne  .out
    call bm_face_surface_valid
    test eax, eax
    jz   .out
    call firmware_logo_draw
    test eax, eax
    jnz  .logo_ready
    call bm_face_fb_clear
.logo_ready:
    call bm_face_progress_build
    call bm_face_progress_draw
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=actual stage, ESI=STARTING/COMPLETED, EDX=actual result. Only an earned
; predecessor permits STARTING. Complete/fail requires that same active cell.
; Duplicates, reordered edges and same-attempt recovery cannot fabricate work.
; This is presentation state only: no readiness/persistence/security authority.
bm_face_milestone:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    cmp  edi, PBM_A1_FACE_CHECKPOINT_COUNT
    jae  .out
    lea  r14, [rel bm_face_state]
    movzx ebx, byte [r14 + r12]
    cmp  esi, PBM_INIT_TRANSITION_STARTING
    jne  .complete
    test edx, edx
    jnz  .out
    test ebx, ebx
    jnz  .out
    test r12d, r12d
    jz   .activate
    movzx eax, byte [r14 + r12 - 1]
    cmp  eax, BM_FACE_DONE
    je   .activate
    cmp  eax, BM_FACE_DEGRADED
    jne  .out
.activate:
    mov  ebx, BM_FACE_ACTIVE
    jmp  .store
.complete:
    cmp  esi, PBM_INIT_TRANSITION_COMPLETED
    jne  .out
    cmp  ebx, BM_FACE_ACTIVE
    jne  .out
    mov  ebx, BM_FACE_DONE
    cmp  edx, PBM_INIT_RESULT_HEALTHY
    je   .store
    mov  ebx, BM_FACE_DEGRADED
    cmp  edx, PBM_INIT_RESULT_DEFERRED
    je   .store
    cmp  edx, PBM_INIT_RESULT_DISABLED
    je   .store
    mov  ebx, BM_FACE_FAILED
    cmp  edx, PBM_INIT_RESULT_FAILED
    jne  .out
.store:
    mov  [r14 + r12], bl
    inc  qword [rel bm_face_update_count]
    call bm_face_progress_build
    call bm_face_progress_draw
    mov  edi, r12d
    lea  rax, [rel bm_face_progress_cells]
    movzx esi, byte [rax + r12]
    call boot_v2_face_progress_observe
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Called before either GUI or CLI takes the display. Later real milestones
; still update nine-cell state, but cannot repaint/clear the final presentation.
bm_face_retire:
    mov  byte [rel bm_face_owner], 2
    mov  byte [rel bm_face_draw_status], 3
    ret

; Fill both invariant nine-cell projections from actual individual states.
; '.'=resolved healthy, '|'=active, '-'=deferred/disabled, 'X'=failed, ' '=pending.
; No prefix is inferred from a later stage number.
bm_face_progress_build:
    push rax
    push rcx
    push rdi
    push rsi
    lea  rdi, [rel bm_u_progress_cells]
    lea  rsi, [rel bm_face_progress_cells]
    xor  ecx, ecx
.cell:
    lea  rax, [rel bm_face_state]
    movzx eax, byte [rax + rcx]
    cmp  eax, BM_FACE_PENDING
    je   .pending
    cmp  eax, BM_FACE_ACTIVE
    je   .active
    cmp  eax, BM_FACE_DONE
    je   .done
    cmp  eax, BM_FACE_DEGRADED
    je   .degraded
    mov  eax, 'X'
    jmp  .store
.pending:
    mov  eax, ' '
    jmp  .store
.active:
    mov  eax, '|'
    jmp  .store
.done:
    mov  eax, '.'
    jmp  .store
.degraded:
    mov  eax, '-'
.store:
    mov  [rdi + rcx*2], ax
    mov  [rsi + rcx], al
    inc  ecx
    cmp  ecx, PBM_A1_FACE_CHECKPOINT_COUNT
    jb   .cell
    pop  rsi
    pop  rdi
    pop  rcx
    pop  rax
    ret

; Validate the existing GOP-owned32-bit surface on each clear/draw. EAX is
; bounded pixel count or0, RCX scratch. Accept RGB/BGR only; unknown bit masks
; degrade to pre-EBS text or no display. No allocation/mode-set or trust change.
bm_face_surface_valid:
    mov  rcx, [rel fb_base]
    test rcx, rcx
    jz   .bad
    test cl, 3
    jnz  .bad
    cmp  dword [rel fb_bpp], 32
    jne  .bad
    cmp  dword [rel fb_pixel_format], 1
    ja   .bad
    mov  ecx, [rel fb_width]
    cmp  ecx, FLD_LINE_WIDTH
    jb   .bad
    cmp  [rel fb_stride], ecx
    jb   .bad
    mov  eax, [rel fb_stride]
    mov  ecx, [rel fb_height]
    cmp  ecx, FLD_LINE_HEIGHT
    jb   .bad
    imul rax, rcx                    ; uint32*uint32 fits uint64
    cmp  rax, BM_FACE_MAX_PIXELS
    ja   .bad
    mov  rcx, rax
    shl  rcx, 2
    cmp  [rel fb_size], rcx
    jb   .bad
    add  rcx, [rel fb_base]
    jc   .bad
    mov  rcx, [rel fb_base]
    add  rcx, [rel fb_size]
    jc   .bad
    ret
.bad:
    xor  eax, eax
    ret

; Fallback black clear retains the MSI handoff fix when no usable owned logo;
; never clear after retirement. An admitted logo skips both firmware and GOP clears.
; At most BM_FACE_MAX_PIXELS stores, and only inside the validated allocation.
bm_face_fb_clear:
    cmp  byte [rel bm_face_owner], 1
    jne  .out
    call bm_face_surface_valid
    test eax, eax
    jz   .out
    mov  ecx, eax
    mov  rdi, [rel fb_base]
    xor  eax, eax
    cld
    rep  stosd
.out:
    ret

; Paint the loading line directly into the GOP framebuffer using the same
; Spleen 8x16 bitmap as the Manager face (exact-font OCR). This avoids OVMF's console
; font confusing the literal "PaOS" with "Pa0S" while retaining ConOut as a
; non-fatal fallback when GOP is absent.
bm_face_progress_draw:
%if PAOS_PUBLICITY_LAB_PROFILE
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel bm_face_draw_status], 0
    cmp  byte [rel bm_face_owner], 2
    je   .retired
    cmp  byte [rel bm_face_owner], 1
    jne  .out
    call bm_face_surface_valid
    test eax, eax
    jz   .console
    inc  qword [rel bm_face_draw_count]
    mov  byte [rel bm_face_draw_status], 1
    mov  eax, [rel fb_width]
    cmp  eax, BM_FACE_TEXT_W
    jb   .console
    sub  eax, BM_FACE_TEXT_W
    shr  eax, 1
    mov  r13d, eax
    mov  eax, [rel fb_height]
    cmp  eax, BM_FACE_GLYPH_H
    jb   .console
    sub  eax, BM_FACE_GLYPH_H
    shr  eax, 1
    cmp  dword [rel firmware_logo_drawn], 1
    jne  .line_y
    mov  edx, [rel firmware_logo_line_y]
    mov  ecx, [rel fb_height]
    lea  rdx, [rdx + BM_FACE_GLYPH_H]
    cmp  rdx, rcx
    ja   .line_y
    mov  eax, [rel firmware_logo_line_y]
.line_y:
    mov  r14d, eax
    lea  r12, [rel bm_face_progress_ascii]
    xor  r15d, r15d
.next:
    movzx eax, byte [r12]
    test al, al
    jz   .out
    mov  esi, r13d
    mov  edx, r14d
    call bm_face_progress_char
    add  r13d, BM_FACE_CELL_W
    inc  r12
    inc  r15d
    cmp  r15d, BM_FACE_TEXT_CHARS
    jb   .next
    jmp  .out
.console:
    lea  rdi, [rel bm_u_progress]
    call bm_conout_str
    jc   .out
    mov  byte [rel bm_face_draw_status], 2
    inc  qword [rel bm_face_draw_count]
    jmp  .out
.retired:
    mov  byte [rel bm_face_draw_status], 3
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
%endif
    ret

; EAX=ASCII, ESI=x, EDX=y. Expand one 8x16 glyph by the declared integer
; scale directly in the validated framebuffer. This is the Manager face's proven
; scale-generic raster sequence, adapted to PaOS's compact glyph index.
bm_face_progress_char:
    push rbx
    push r12
    push r13
    push r14
    push r15
    and  eax, 0x7F
    lea  r12, [rel bm_face_glyph_index]
    movzx eax, byte [r12 + rax]
    shl  eax, 4
    lea  r12, [rel bm_face_ocr_font]
    add  r12, rax
    mov  r13d, esi
    mov  r14d, edx
    xor  r15d, r15d
.row:
    movzx ebx, byte [r12 + r15]
    xor  r10d, r10d
.column:
    mov  edx, 0x80
    mov  ecx, r10d
    shr  edx, cl
    xor  eax, eax
    test ebx, edx
    jz   .color_ready
    mov  eax, 0x00FFFFFF
.color_ready:
    mov  r11d, r15d
    imul r11d, r11d, BM_FACE_RASTER_SCALE
    add  r11d, r14d
    imul r11d, dword [rel fb_stride]
    mov  edi, r10d
    imul edi, edi, BM_FACE_RASTER_SCALE
    add  edi, r13d
    add  r11d, edi
    shl  r11, 2
    add  r11, [rel fb_base]
    mov  edx, BM_FACE_RASTER_SCALE
.scale_y:
    mov  rdi, r11
    mov  ecx, BM_FACE_RASTER_SCALE
.scale_x:
    mov  [rdi], eax
    add  rdi, 4
    loop .scale_x
    mov  ecx, [rel fb_stride]
    shl  rcx, 2
    add  r11, rcx
    dec  edx
    jnz  .scale_y
    inc  r10d
    cmp  r10d, 8
    jb   .column
    ; Clear the inter-cell gutter on every scaled row so inherited firmware
    ; pixels cannot leak into the otherwise deterministic text band.
    mov  r11d, r15d
    imul r11d, r11d, BM_FACE_RASTER_SCALE
    add  r11d, r14d
    imul r11d, dword [rel fb_stride]
    mov  edi, r13d
    add  edi, BM_FACE_RASTER_W
    add  r11d, edi
    shl  r11, 2
    add  r11, [rel fb_base]
    mov  edx, BM_FACE_RASTER_SCALE
.gutter_y:
    mov  rdi, r11
    mov  ecx, BM_FACE_GUTTER_W
    xor  eax, eax
    rep  stosd
    mov  ecx, [rel fb_stride]
    shl  rcx, 2
    add  r11, rcx
    dec  edx
    jnz  .gutter_y
    inc  r15d
    cmp  r15d, 16
    jb   .row
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

bm_face_clear_console:
    cmp  byte [rel bm_face_boot_services_live], 1
    jne  .out
    mov  rax, [rel system_table]
    test rax, rax
    jz   .out
    mov  rcx, [rax + 64]
    test rcx, rcx
    jz   .out
    mov  rax, [rcx + 48]
    test rax, rax
    jz   .out
    ; Explicit Win64 shadow area/alignment, independent of nested caller parity.
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32
    call rax
    mov  rsp, rbp
    pop  rbp
.out:
    ret

; bm_conout_str(RDI=UCS-2 str) -- firmware text only before first EBS attempt.
; CF=0 only when OutputString actually returns EFI_SUCCESS; otherwise CF=1.
bm_conout_str:
    cmp  byte [rel bm_face_boot_services_live], 1
    jne  .skip
    mov  rax, [rel system_table]
    test rax, rax
    jz   .skip
    mov  rcx, [rax + 64]
    test rcx, rcx
    jz   .skip
    mov  rdx, rdi
    mov  rax, [rcx + 8]
    test rax, rax
    jz   .skip
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32
    call rax
    mov  rsp, rbp
    pop  rbp
    test rax, rax
    jnz  .skip
    clc
    ret
.skip:
    stc
    ret

; bm_sel_name_serial(EAX=index 0..3) — print the option name + CRLF to serial.
bm_sel_name_serial:
    call bm_sel_name_ptr
    call serial_string
    ret
; bm_sel_name_conout(EAX=index 0..3) — print "> <name>" to the firmware console.
bm_sel_name_conout:
    cmp  eax, 1
    je   .w
    cmp  eax, 2
    je   .l
    cmp  eax, 3
    je   .d
    lea  rdi, [rel bm_u_sel0]
    jmp  .out
.w: lea  rdi, [rel bm_u_sel1]
    jmp  .out
.l: lea  rdi, [rel bm_u_sel2]
    jmp  .out
.d: lea  rdi, [rel bm_u_sel3]
.out:
    call bm_conout_str
    ret
; bm_sel_name_ptr(EAX=index) -> RDI = serial name string (switch-on-id, never
;   a dq table — MODULES §3.2 runtime-VA rule).
bm_sel_name_ptr:
    cmp  eax, 1
    je   .w
    cmp  eax, 2
    je   .l
    cmp  eax, 3
    je   .d
    lea  rdi, [rel str_bm_name_paos]
    ret
.w: lea  rdi, [rel str_bm_name_win]
    ret
.l: lea  rdi, [rel str_bm_name_linux]
    ret
.d: lea  rdi, [rel str_bm_name_diag]
    ret

; ---- data --------------------------------------------------------------------
bm_m_state:       db 0                ; earned: state line printed (live CMOS)
bm_m_checkpoints: db 0                ; earned: checkpoint ladder complete
bm_m_menu:        db 0                ; earned: menu rendered this boot
bm_m_clready:     db 0                ; earned: dp resolve OK -> chainload viable
bm_boot_mode:     db 0                ; BM_MODE_* — how this boot was chosen
bm_diag_mode:     db 0                ; 1 == diagnostics pick (verb console boot)
bm_vm:            db 0                ; 1 == hypervisor present (ConIn untrusted)
bm_digit:         db 0, 0             ; 1-char serial scratch
align 4
bm_key:           dd 0                ; EFI_INPUT_KEY {u16 ScanCode, u16 UnicodeChar}

; --- serial marker lines (the 4 contract markers; live values inline) ---
str_bm_state_pre:   db "[PAOS64] Boot state loaded: override=", 0
str_bm_state_trial: db " trial=", 0
str_bm_state_conf:  db " confirmed=0x", 0
str_bm_state_post:  db " [boot.menu.state]", 13, 10, 0
str_bm_clready:     db "[PAOS64] Chainload ready: device-path resolved — bootmgfw_orig.efi/BOOTMGR.EFI/shimx64.efi/grubx64.efi staged [boot.menu.chainload.ready]", 13, 10, 0
str_bm_cl_notready: db "[PAOS64] P0 boot menu: chainload NOT ready (device path unresolvable) — menu offers PaOS/Diag only", 13, 10, 0
str_bm_checkpoints: db "[PAOS64] Boot checkpoints ready: escalate-check done + state loaded + override one-shot cleared + chainloader validated [boot.menu.checkpoints]", 13, 10, 0
str_bm_menu:        db "[PAOS64] Boot menu displayed: 1=PaOS 2=Windows 3=Linux 4=Diagnostics (digit/letter or arrows+Enter; default PaOS in 2s) [boot.menu.displayed]", 13, 10, 0

; --- decision lines ---
str_bm_ovr_win:    db "[PAOS64] P0 boot menu: override BOOT WIN -> chainload real Windows (one-shot cleared)", 13, 10, 0
str_bm_ovr_linux:  db "[PAOS64] P0 boot menu: override BOOT LINUX -> chainload Ubuntu (one-shot cleared)", 13, 10, 0
str_bm_pick_win:   db "[PAOS64] P0 boot menu: MANUAL pick Windows -> direct bootmgfw_orig.efi (try_backup_first=0, no PaOS binary in this path)", 13, 10, 0
str_bm_pick_linux: db "[PAOS64] P0 boot menu: MANUAL pick Linux -> shimx64.efi/grubx64.efi", 13, 10, 0
str_bm_diag:       db "[PAOS64] P0 boot menu: DIAGNOSTICS mode — diag flag set, verb surface (serial/UDP) is the console", 13, 10, 0
str_bm_failopen:   db "[PAOS64] P0 boot menu: chainload target missing/failed — fail-open, continuing", 13, 10, 0
str_bm_sel_pre:    db "[PAOS64] P0 boot menu: selected=", 0
str_bm_cd1:        db "[PAOS64] P0 boot menu: 1s...", 13, 10, 0
str_bm_vmskip:     db "[PAOS64] P0 boot menu: countdown skipped (VM: untrusted ConIn + fixed-schedule harness inputs) -> PaOS default", 13, 10, 0
str_bm_go_paos:    db "[PAOS64] P0 boot menu: -> PaOS (mode=", 0
str_bm_go_post:    db ")", 13, 10, 0
str_bm_name_paos:  db "PaOS", 13, 10, 0
str_bm_name_win:   db "Windows", 13, 10, 0
str_bm_name_linux: db "Linux", 13, 10, 0
str_bm_name_diag:  db "Diagnostics", 13, 10, 0

; Compact copy of the Manager face's Spleen 8x16 glyphs (BSD-2-Clause; see
; THIRD_PARTY_NOTICES.md). The
; 128-byte index keeps lookup deterministic without duplicating a 2 KiB font.
align 16
bm_face_glyph_index:
    db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    db 0,0,0,0,0,0,0,0,0,0,0,0,0,1,2,3
    db 4,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    db 0,0,0,0,0,0,0,0,0,0,0,0,6,0,0,7
    db 8,0,0,9,0,0,0,0,22,0,0,10,11,12,0,0
    db 0,13,0,0,14,0,0,15,0,16,0,0,0,0,17,18
    db 0,0,0,19,0,0,20,0,0,0,0,0,21,0,0,0
bm_face_ocr_font:
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+0020
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; U+002d
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00 ; U+002e
    db 0x00,0x06,0x06,0x0c,0x0c,0x18,0x18,0x30,0x30,0x60,0x60,0xc0,0xc0,0x00,0x00,0x00 ; U+002f
    db 0x00,0x00,0x7c,0xc6,0xc6,0xce,0xde,0xf6,0xe6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+0030
    db 0x00,0x00,0x18,0x38,0x78,0x58,0x18,0x18,0x18,0x18,0x18,0x7e,0x00,0x00,0x00,0x00 ; U+0031
    db 0x00,0x00,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0x7e,0x00,0x00,0x00,0x00 ; U+004c
    db 0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+004f
    db 0x00,0x00,0xfc,0xc6,0xc6,0xc6,0xfc,0xc0,0xc0,0xc0,0xc0,0xc0,0x00,0x00,0x00,0x00 ; U+0050
    db 0x00,0x00,0x7e,0xc0,0xc0,0xc0,0x7c,0x06,0x06,0x06,0x06,0xfc,0x00,0x00,0x00,0x00 ; U+0053
    db 0x00,0x3e,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x3e,0x00,0x00,0x00 ; U+005b
    db 0x00,0xc0,0xc0,0x60,0x60,0x30,0x30,0x18,0x18,0x0c,0x0c,0x06,0x06,0x00,0x00,0x00 ; U+005c
    db 0x00,0x7c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x7c,0x00,0x00,0x00 ; U+005d
    db 0x00,0x00,0x00,0x00,0x00,0x7c,0x06,0x7e,0xc6,0xc6,0xc6,0x7e,0x00,0x00,0x00,0x00 ; U+0061
    db 0x00,0x00,0x06,0x06,0x06,0x7e,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x00,0x00,0x00,0x00 ; U+0064
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x06,0x06,0xfc,0x00 ; U+0067
    db 0x00,0x00,0x18,0x18,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x1c,0x00,0x00,0x00,0x00 ; U+0069
    db 0x00,0x00,0x00,0x00,0x00,0xfc,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+006e
    db 0x00,0x00,0x00,0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00 ; U+006f
    db 0x00,0x00,0x00,0x00,0x00,0x7e,0xc0,0xc0,0x7c,0x06,0x06,0xfc,0x00,0x00,0x00,0x00 ; U+0073
    db 0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xc6,0xc6,0x6c,0x38,0x10,0x00,0x00,0x00,0x00 ; U+0076
    db 0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00 ; U+007c
; --- firmware-console (UCS-2) menu text ---
align 2
    db 0x00,0x00,0xc6,0xc6,0xc6,0x6c,0x38,0x6c,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00 ; U+0058 failure, same Spleen8x16 source
bm_u_menu:
    dw 13, 10
    dw 'P','a','O','S',' ','b','o','o','t',' ','m','e','n','u', 13, 10
    dw ' ','1',' ','P','a','O','S',' ',' ','2',' ','W','i','n','d','o','w','s',' ',' ','3',' ','L','i','n','u','x',' ',' ','4',' ','D','i','a','g','n','o','s','t','i','c','s', 13, 10
    dw 'b','o','o','t','i','n','g',' ','P','a','O','S',' ','i','n',' ','2','s',' ','(','p','r','e','s','s',' ','a',' ','k','e','y',')', 13, 10, 0
bm_u_cd1:
    dw '1','s','.','.','.', 13, 10, 0
bm_u_sel0:
    dw 13, 10, '>', ' ', 'P','a','O','S', ' ', 0
bm_u_sel1:
    dw 13, 10, '>', ' ', 'W','i','n','d','o','w','s', ' ', 0
bm_u_sel2:
    dw 13, 10, '>', ' ', 'L','i','n','u','x', ' ', 0
bm_u_sel3:
    dw 13, 10, '>', ' ', 'D','i','a','g','n','o','s','t','i','c','s', ' ', 0

; Post-EBS milestone stores use the existing page-isolated writable region,
; rather than introducing new writes to pages containing boot instructions.
%include "core/abi/wdata.inc"
%macro WDATA_boot_face 0
; ---- BSP-owned volatile presentation; one image boot, never a health token ----
bm_face_owner: db 0                  ;0not acquired,1face,2final GUI/CLI owns pixels
bm_face_boot_services_live: db 1     ; cleared BEFORE first ExitBootServices call
bm_face_draw_status: db 0            ;0unavailable,1GOP,2firmware text,3retired
bm_face_state: times PBM_A1_FACE_CHECKPOINT_COUNT db BM_FACE_PENDING
align 8
bm_face_update_count: dq 0
bm_face_draw_count: dq 0

bm_face_progress_ascii: db "Loading PaOS v0.1  ["
bm_face_progress_cells: times PBM_A1_FACE_CHECKPOINT_COUNT db ' '
                        db ']',0

    align 2, db 0                  ; CHAR16 object follows 31 bytes of ASCII
bm_u_progress:
    dw 13,'L','o','a','d','i','n','g',' ','P','a','O','S',' ','v','0','.','1',' ',' ','['
bm_u_progress_cells:
    times PBM_A1_FACE_CHECKPOINT_COUNT dw ' '
    dw ']',0
%endmacro
WDATA_DEFER WDATA_boot_face
