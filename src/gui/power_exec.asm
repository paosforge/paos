;; MODULE gui/power_exec
;; LAYER 6
;; EXPORTS power_recovery_controller, power_lab_return, power_execute, power_question_text, power_warm_reset, acpi_sleep_s5, power_s5_bind, power_s5_request, power_s5_step, power_s5_cancel, power_s5_status, power_button_ownership, power_button_ownership_abort, power_button_ownership_live
;; IMPORTS svc/driver_domain_return, svc/recovery_boot, svc/recovery_controller, svc/lab_return, hv/guest_power, svc/reinit_power_e1000e, bus/acpi_hp_s5, bus/acpi, svc/command, svc/command_udp, svc/command_bootmenu, core/diag, dev/blk/ahci, dev/blk/nvme, boot/boot_v2_health, boot/serial, sec/principal, svc/command_software_stop, core/reset_wipe, svc/reinit_power, svc/reinit_power_ram, sec/session, core/time, hv/vtd
;; CAPS io
;; OWNER saga:msi_start_programs_settings
; ============================================================================
; gui/power_exec.asm — leave PaOS on purpose, after the owner confirmed it
; (hub packet 0009; the MSI spoke's power_menu core without its trial handshake).
;
; Peter 2026-09-30: PaOS had no way to leave, so he pressed RESET. The
; Terminal's `windows`, `reboot` and `shutdown` (each asking y/N first) and,
; from packet 0010, Start > Power reach this module:
;   POWER_WINDOWS   the hub's own Return-to-Windows request, `BOOT WIN`,
;                   dispatched as the console owner (svc/command_bootmenu: the
;                   storage-access gate, then the firmware BootNext to the
;                   Windows Boot Manager). Only if it was accepted does the warm
;                   reset below follow; a refusal resets nothing.
;   POWER_RESTART   the hub's warm reset, the same sequence command_udp's REBOOT
;                   runs: diag ring flush, NVMe quiesce, firmware ResetSystem(warm)
;                   when it is proven usable, else CF9.
;   POWER_SHUTDOWN  ACPI S5 (soft off) through the FADT PM1 control blocks and
;                   the DSDT's \_S5 sleep type, else firmware
;                   ResetSystem(shutdown) when usable. If neither takes, PaOS
;                   stays up and says so unless terminal NIC fencing has begun
;                   (then a returned sleep stays fenced and halts). Power is removed only after
;                   power_storage_quiesce: every disk PaOS owns is flushed (AHCI)
;                   or flushed and shut down (NVMe), else nothing powers off.
; power_execute returns only when nothing happened: RAX = the reason text.
; ============================================================================
%include "core/abi/driver_power.inc"
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place

POWER_WINDOWS       equ 1
POWER_RESTART       equ 2
POWER_SHUTDOWN      equ 3
POWER_S5_SPUN       equ 4               ; acpi_sleep_s5: PM1 written (quiesced), still running
POWER_S5_UNQUIESCED equ 5               ; acpi_sleep_s5: a disk was not quiesced, no PM1 write
POWER_S5_MODE_REFUSED equ 6             ; storage quiesced; mode refused/restored, no PM1 write
POWER_S5_HP_REFUSED equ 7               ; HP fixed preparation pin/resource mismatch
POWER_S5_NIC_REFUSED equ 8              ; storage complete; NIC refused before any effect
POWER_S5_GUEST_REFUSED equ 9            ; live/incomplete guest ownership; no teardown proof

;; power_question_text(EDI = kind) -> RAX the y/N question (the Terminal's)
power_question_text:
    lea  rax, [rel power_q_windows]
    cmp  edi, POWER_WINDOWS
    je   .out
    lea  rax, [rel power_q_shutdown]
    cmp  edi, POWER_SHUTDOWN
    je   .out
    lea  rax, [rel power_q_restart]
.out:
    ret

;; power_execute(EDI = kind): the owner confirmed. Returns only on failure,
;; RAX = a one-line reason (nothing was reset).
power_execute:
    push rbx
    mov  ebx, edi
    lea  rax, [rel power_r_unknown]
    cmp  ebx, POWER_WINDOWS
    jb   .out
    cmp  ebx, POWER_SHUTDOWN
    ja   .out
    ; SEC-owner-key-in-push-record (P1): the owner key a password sign-in left
    ; for later PUSH unlocks does not outlive this boot, including a warm reset
    ; or the M1 checkpoint-and-off path (pwr_m1_sleep_exec lands here).
    ; Opt-in local confirmed flow only. Unbound, locked automatic policy and
    ; authenticated remote/operator rails retain their existing legacy path.
    cmp ebx, POWER_SHUTDOWN
    jne .legacy
    call hv_guest_power_s5_inactive
    test eax, eax
    lea rax, [rel power_r_guest_active]
    jnz .out                            ; before key wipe or managed FENCE
    cmp qword [rel ps5_plan], 0
    je .legacy
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .legacy
    call power_s5_request
    cmp rax, DP_PENDING
    lea rax, [rel ps5_refused_text]
    jne .out
    lea rax, [rel ps5_pending_text]
    jmp .out
.legacy:
    ; Warm returns retain keys until domain quiescence and canonical reset wipe.
    lea  rdi, [rel power_confirmed_text]
    call serial_string
    call software_stop_stability_exit_hook ; G9: settle the strong health ack before any power action
    lea  rdi, [rel power_k_windows]
    cmp  ebx, POWER_WINDOWS
    je   .kind
    lea  rdi, [rel power_k_restart]
    cmp  ebx, POWER_RESTART
    je   .kind
    lea  rdi, [rel power_k_shutdown]
.kind:
    call serial_string
    cmp  ebx, POWER_WINDOWS
    je   .windows
    cmp  ebx, POWER_SHUTDOWN
    je   .shutdown
    call power_warm_reset               ; does not return
    lea  rax, [rel power_r_reset]
    jmp  .out
.windows:
    call power_boot_win                 ; -> EAX 0 accepted
    test eax, eax
    jnz  .windows_refused
    call power_warm_reset
    lea  rax, [rel power_r_reset]
    jmp  .out
.windows_refused:
    lea  rdi, [rel power_windows_refused_text]
    call serial_string
    lea  rax, [rel power_r_windows]
    jmp  .out
.shutdown:
    call principal_wipe_owner_boot_key
    call acpi_sleep_s5                  ; returns only if S5 did not take: EAX why
    cmp  eax, POWER_S5_UNQUIESCED
    je   .unquiesced                    ; a disk is not quiesced: remove no power
    cmp  byte [rel pbm_runtime_reset_usable], 1
    jne  .shutdown_failed
    mov  edi, eax
    call power_shutdown_fallback
    test eax, eax
    jnz  .unquiesced
.shutdown_failed:
    call power_nvme_offline             ; EAX 1 = the NVMe is offline now
    test eax, eax
    lea  rax, [rel power_r_shutdown]    ; (lea keeps the flags)
    jz   .out
    lea  rax, [rel power_r_shutdown_offline]
    jmp  .out
.unquiesced:
    call power_nvme_offline
    test eax, eax
    lea  rax, [rel power_r_unquiesced]
    jz   .out
    lea  rax, [rel power_r_unquiesced_offline]
.out:
    pop  rbx
    ret

;; power_boot_win -> EAX 0 when the hub's `BOOT WIN` armed the return (its
;; staged reply is consumed and logged), else nonzero.
power_boot_win:
    push rbx
    lea  rdi, [rel power_verb_boot]
    call command_lookup
    cmp  eax, -1
    je   .refused
    mov  [rel power_req + REQ_VERB], rax
    mov  qword [rel power_req + REQ_CAP], -1
    mov  qword [rel power_req + REQ_IDEM], 0
    mov  qword [rel power_req + REQ_SEL], 0
    lea  rax, [rel power_arg_win]
    mov  [rel power_req + REQ_ARG], rax
    mov  qword [rel power_req + REQ_SOURCE], CMD_SOURCE_CONSOLE
    lea  rdi, [rel power_req]
    call session_shell_prepare_local_request
    mov  byte [rel bm_reboot_pending], 0
    lea  rdi, [rel power_req]
    lea  rsi, [rel power_rsp]
    call command_dispatch
    lea  rdi, [rel power_verb_boot]
    lea  rsi, [rel power_arg_win]
    lea  rdx, [rel power_rsp]
    call command_udp_capture_reply      ; RAX text, EDX length: consume + log it
    mov  rdi, rax
    call serial_string
    call serial_newline
    cmp  qword [rel power_rsp + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel bm_reboot_pending], 1
    jne  .refused
    mov  byte [rel bm_reboot_pending], 0 ; this module fires the reset itself
    xor  eax, eax
    jmp  .out
.refused:
    mov  byte [rel bm_reboot_pending], 0
    mov  eax, 1
.out:
    pop  rbx
    ret

;; power_lab_return: depth-zero lab timer expiry. Existing Windows default and
;; consumed one-shot boot entry are operator prerequisites; write no BootNext,
;; boot order, CMOS, slot or health state. Quiesce every owned disk before reset.
;; If quiesce refuses, restore IF and return without wiping keys or resetting.
;; The timer already consumed this attempt, so a refusal cannot create a loop.
power_lab_return:
    call driver_domain_return_prepare
    cmp eax,3
    jae .domain_refused
    pushfq
    cli
    mov edi, 1                          ; no timely owner contact; not a NIC diagnosis
    call lab_return_report
    call power_storage_quiesce
    test eax, eax
    jnz .refused
    mov edi, 3                          ; intent only; reset/return remain unobserved
    call lab_return_report
    call power_warm_reset.prepared       ; same guarded observation, no second STOP
.out:
    popfq
    ret
.refused:
    mov edi, 2                          ; quiesce refused, no reset attempted
    call lab_return_report
    jmp .out
.domain_refused:
    ret

;; power_warm_reset: the hub's warm reset (command_udp REBOOT's sequence).
;; Unsafe retirement returns before key wipe/CLI; after preparation, a reset
;; that returns halts after the key wipe (SEC-pre-reset-wipe-hook).
power_warm_reset:
    call driver_domain_return_prepare
    cmp eax,3
    jae .domain_refused
.prepared:                              ; only the already-guarded lab timer enters here
    lea  rdi, [rel power_reset_text]
    call serial_string
    call serial_drain_poll
    pushfq
    cli
    call diag_persist_flush             ; seal the persistent ring first
    call nvme_quiesce_for_reset         ; DRAM-less drives lose cached writes at CF9
    call reset_wipe_all                 ; no key material survives into the next boot's DRAM
    call vtd_reset_te_off               ; DMA remapping off before firmware/next OS (root 74762, SEC F1)
    cmp  byte [rel pbm_runtime_reset_usable], 1
    jne  .cf9
    mov  ecx, 1                         ; EfiResetWarm
    call power_reset_system
.cf9:
    mov  al, 0x06
    mov  dx, 0x0cf9
    out  dx, al
    jmp  reset_wipe_halt                ; the keys are gone: never resume
.domain_refused:
    ret

; Owner-grant R5 only, called at BSP depth zero after an irreversible one-time
; policy claim. Existing quiesce/key wipe and ResetSystem paths are retained.
; Pre-reset refusal leaves keys intact and never resets or retries. No timer reaches S5.
power_recovery_controller:
    call driver_domain_return_prepare
    cmp eax,3
    jae .domain_refused
    pushfq
    cli
    call recovery_boot_effect_begin
    test eax,eax
    jz .refused
    cmp byte [rel pbm_runtime_reset_usable],1
    jne .refused
    call power_storage_quiesce
    test eax,eax
    jnz .refused
    call recovery_boot_quiesced
    test eax,eax
    jz .refused
    call recovery_boot_expiry
    test eax,eax
    jz .refused
    call recovery_boot_effect_budget
    test eax,eax
    jz .refused
    ; BootNext/request were exactly read back. The canonical helper wipes
    ; all reset-sensitive keys immediately before ResetSystem. Returned reset
    ; is terminal; do not resume with wiped keys or issue another reset.
    mov ecx,1
    call power_reset_system
    call recovery_boot_failure         ; returned reset is recorded uncertain before terminal halt
    jmp reset_wipe_halt
.refused:
    call recovery_boot_failure
    popfq
    ret
.domain_refused:
    call recovery_boot_failure
    ret

;; power_nvme_offline -> EAX 1 when the NVMe this driver brought up is now
;; offline (CC.SHN written by a quiesce, or poisoned earlier), else 0. The
;; refusal/failure text is chosen from this live state, never from a guess.
power_nvme_offline:
    xor  eax, eax
    cmp  byte [rel nvme_present], 1
    jne  .out
    cmp  byte [rel nvme_io_poisoned], 0
    setne al
.out:
    ret

;; power_shutdown_fallback(EDI = why acpi_sleep_s5 returned): firmware
;; ResetSystem(shutdown) under the S5 storage rule. POWER_S5_SPUN already
;; quiesced before its PM1 writes; MODE_REFUSED also quiesced before its mode
;; attempt; HP_REFUSED/NIC_REFUSED completed storage before their preflight.
;; Every other reason needs storage quiesce here first.
;; -> EAX 1 when power_storage_quiesce refused (nothing was
;; powered off, keys intact); never returns once ResetSystem was called (the
;; key wipe ran: a firmware that returns ends in reset_wipe_halt).
power_shutdown_fallback:
    pushfq
    cli
    push rdi                            ; census may clobber caller-saved reason
    call hv_guest_power_s5_inactive
    pop rdi
    test eax, eax
    jnz .out                            ; even an already-flushed reason must refuse
    cmp  edi, POWER_S5_SPUN
    je   .reset
    cmp  edi, POWER_S5_MODE_REFUSED
    je   .reset
    cmp  edi, POWER_S5_HP_REFUSED
    je   .reset
    cmp  edi, POWER_S5_NIC_REFUSED
    je   .reset
    call power_storage_quiesce
    test eax, eax
    jnz  .out
.reset:
    call power_s5_commit_key             ; managed firmware path has the same storage rule
    mov  ecx, 2                         ; EfiResetShutdown
    call power_reset_system
    jmp  reset_wipe_halt                ; firmware returned, the keys are gone: stop
.out:
    popfq
    ret

;; power_storage_quiesce (IF clear) -> EAX 0 when every disk PaOS owns is
;; quiesced, 1 when one is not (the caller then removes no power). Order: the
;; diag ring to DRAM; one FLUSH CACHE EXT per live AHCI port (state-preserving,
;; so a refusal there skips the NVMe and leaves it usable, nvme=4); then the
;; NVMe Flush + normal shutdown, complete only at CSTS.SHST=10b (a timeout refuses; a
;; controller this driver does not own or that is not enabled has nothing to
;; quiesce). Reports one line and drains it: the caller's next I/O may remove
;; power.
power_storage_quiesce:
    push rbx
    call hv_guest_power_s5_inactive
    test eax, eax
    jnz .guest_refused                   ; no disk shutdown while guest work is live
    call diag_persist_flush
    call ahci_flush_for_reset           ; EAX flushed, EDX failed
    mov  [rel power_q_ahci_ok], eax
    mov  [rel power_q_ahci_failed], edx
    mov  dword [rel power_q_nvme], 4    ; 4 = not attempted
    mov  ebx, 1
    test edx, edx
    jnz  .report                        ; refused: the NVMe stays up and usable
    call nvme_quiesce_for_reset         ; EAX 0 shut down / 1 not enabled / 2 timeout / 3 not owned
    mov  [rel power_q_nvme], eax
    xor  ebx, ebx
    cmp  eax, 2
    sete bl
.report:
    lea  rdi, [rel power_q_text]
    call serial_string
    mov  edi, [rel power_q_ahci_ok]
    call serial_hex64
    lea  rdi, [rel power_q_failed_text]
    call serial_string
    mov  edi, [rel power_q_ahci_failed]
    call serial_hex64
    lea  rdi, [rel power_q_nvme_text]
    call serial_string
    mov  edi, [rel power_q_nvme]
    call serial_hex64
    lea  rdi, [rel power_q_ok_text]
    test ebx, ebx
    jz   .line
    lea  rdi, [rel power_q_refused_text]
.line:
    call serial_string
    call serial_drain_poll
    mov  eax, ebx
.guest_refused:
    pop  rbx
    ret

;; power_reset_system(ECX = EFI_RESET_TYPE): firmware ResetSystem, exactly as
;; command_udp calls it (aligned stack, 32-byte home space). Runs the key wipe
;; first; if the firmware returns, the caller must not resume (reset_wipe_halt).
power_reset_system:
    call reset_wipe_all                 ; every ResetSystem (warm or shutdown) wipes first
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .out
    xor  edx, edx
    xor  r8d, r8d
    xor  r9d, r9d
    mov  r11, rsp
    and  rsp, -16
    sub  rsp, 48
    mov  [rsp + 40], r11
    call [rax + 0x68]                   ; EFI_RUNTIME_SERVICES.ResetSystem
    mov  rsp, [rsp + 40]
.out:
    ret

;; acpi_sleep_s5() -> returns only when S5 did not take (EAX reason: 1 no
;; FADT, 2 no PM1a control block, 3 no \_S5 package, 4 still running).
;; SLP_TYPa/b come from the DSDT's `Name(_S5, Package(){a, b, ...})`.
ACPI_FADT_DSDT      equ 40
ACPI_FADT_PM1A_CNT  equ 64
ACPI_FADT_PM1B_CNT  equ 68
ACPI_FADT_X_DSDT    equ 140
ACPI_FADT_X_PM1A    equ 172                 ; GAS: space, width, offset, access, address
ACPI_PM1_SLP_MASK   equ 0x3c00              ; SLP_TYP (12:10) and SLP_EN (13)
ACPI_PM1_SLP_EN     equ 0x2000
ACPI_PM1_WAK_STS    equ 0x8000              ; PM1 status: write one to clear
; BEGIN PURE FADT PM1 -- host tests assemble these exact instructions.
; RDI=FADT, RSI=available mapped bytes -> EAX=PM1a | PM1b<<16, or -1.
; No mapping/checksum inference: firmware caller supplies acpi_validate_sdt's
; qualified extent; host caller supplies genuinely backed immutable bytes.
; Require complete header/declared extent and PM1_CNT_LEN >=2. This existing
; 16-bit sequence supports System I/O, width16, offset0, access0 (unspecified)
; or2 (word). Nonzero extended GAS takes precedence; absent/zero falls back
; independently to legacy. Malformed present GAS never falls back. PM1a must
; exist; PM1b may be absent, but malformed present PM1b refuses both ports.
; Whole decoded block must fit 16-bit port space; do not truncate any address.
power_fadt_pm1_decode:
    test rdi, rdi
    jz   .refuse
    mov  rax, rdi
    add  rax, rsi
    jc   .refuse                     ; caller pointer + available span
    cmp  rsi, ACPI_HDR_LEN
    jb   .refuse
    cmp  dword [rdi], 'FACP'
    jne  .refuse
    mov  r8d, [rdi + 4]
    cmp  r8d, 90                     ; includes PM1_CNT_LEN at89
    jb   .refuse
    cmp  r8d, AF_MAX_TABLE
    ja   .refuse
    cmp  r8, rsi
    ja   .refuse                     ; full declared table within available bytes
    cmp  byte [rdi + 89], 2
    jb   .refuse
    mov  eax, [rdi + ACPI_FADT_PM1A_CNT]
    mov  edx, ACPI_FADT_X_PM1A
    call .select
    cmp  rax, -1
    je   .refuse
    test eax, eax
    jz   .refuse                     ; mandatory PM1a
    mov  r11d, eax
    mov  eax, [rdi + ACPI_FADT_PM1B_CNT]
    mov  edx, ACPI_FADT_X_PM1A + 12
    call .select
    cmp  rax, -1
    je   .refuse
    shl  eax, 16
    or   eax, r11d
    ret
.select:
    ; EAX=legacy address, EDX=GAS offset. A partial GAS is not absence.
    cmp  r8d, edx
    jbe  .port
    lea  ecx, [rdx + 12]
    cmp  r8d, ecx
    jb   .invalid
    mov  rcx, [rdi + rdx + 4]         ; full 64-bit GAS address
    test rcx, rcx
    jz   .port                       ; zero address: legacy fallback
    mov  rax, rcx
    cmp  byte [rdi + rdx], 1
    jne  .invalid                    ; System I/O only
    cmp  byte [rdi + rdx + 1], 16
    jne  .invalid
    cmp  byte [rdi + rdx + 2], 0
    jne  .invalid
    cmp  byte [rdi + rdx + 3], 0
    je   .port
    cmp  byte [rdi + rdx + 3], 2
    jne  .invalid
.port:
    test rax, rax
    jz   .selected                   ; optional absence, caller checks PM1a
    cmp  rax, 0xfffe
    ja   .invalid                    ; including upper32 and second byte
    movzx ecx, byte [rdi + 89]
    dec  ecx
    add  rcx, rax
    cmp  rcx, 0xffff
    ja   .invalid                    ; complete PM1_CNT_LEN port extent
.selected:
    ret
.invalid:
    mov  rax, -1
    ret
.refuse:
    mov  eax, -1
    ret
; END PURE FADT PM1

; FADT PM1 status blocks for the existing 16-bit legacy sleep sequence.
; RDI/RSI as power_fadt_pm1_decode -> EAX=STS_a | STS_b<<16, or -1.
; PM1_EVT_LEN=4 describes a 16-bit status + 16-bit enable pair. Decode the
; entire block before I/O; do not derive a status address from a control port.
power_fadt_pm1_status_decode:
    call power_fadt_pm1_decode       ; same qualified header/extent contract
    cmp  eax, -1
    je   .refuse
    mov  r9d, eax                   ; validated control ports for alias refusal
    movzx r10d, byte [rdi + 89]
    add  r10d, 2                    ; overlap test: control length + status length - 2
    cmp  byte [rdi + 88], 4
    jne  .refuse                    ; larger status registers need another rail
    mov  r8d, [rdi + 4]
    mov  eax, [rdi + 56]
    mov  edx, 148                    ; X_PM1a_EVT_BLK
    call .select
    cmp  rax, -1
    je   .refuse
    test eax, eax
    jz   .refuse
    mov  r11d, eax
    mov  eax, [rdi + 60]
    mov  edx, 160                    ; X_PM1b_EVT_BLK
    call .select
    cmp  rax, -1
    je   .refuse
    test eax, eax
    jz   .no_b
    mov  ecx, eax
    sub  ecx, r11d
    add  ecx, 3
    cmp  ecx, 6
    jbe  .refuse                    ; event blocks must not overlap
    jmp  .pack
.no_b:
    test r9d, 0xffff0000
    jnz  .refuse                    ; a PM1b control requires its status block
.pack:
    shl  eax, 16
    or   eax, r11d
    ret
.select:
    cmp  r8d, edx
    jbe  .port
    lea  ecx, [rdx + 12]
    cmp  r8d, ecx
    jb   .invalid
    mov  rcx, [rdi + rdx + 4]
    test rcx, rcx
    jz   .port
    mov  rax, rcx
    cmp  byte [rdi + rdx], 1
    jne  .invalid
    cmp  byte [rdi + rdx + 1], 32
    jne  .invalid
    cmp  byte [rdi + rdx + 2], 0
    jne  .invalid
    mov  cl, [rdi + rdx + 3]
    test cl, cl
    jz   .port
    cmp  cl, 2
    je   .port
    cmp  cl, 3
    jne  .invalid
.port:
    test rax, rax
    jz   .selected                  ; absent PM1b is allowed
    cmp  rax, 0xfffc                 ; full four-byte I/O block, no truncation
    ja   .invalid
    movzx ecx, r9w
    call .no_control_alias
    jc   .invalid
    mov  ecx, r9d
    shr  ecx, 16
    test ecx, ecx
    jz   .selected
    call .no_control_alias
    jc   .invalid
.selected:
    ret
.no_control_alias:
    mov  edx, eax
    sub  edx, ecx
    add  edx, 3
    cmp  r10d, edx                   ; CF=0 means blocks overlap
    cmc                             ; return CF=1 on overlap
    ret
.invalid:
    mov  rax, -1
    ret
.refuse:
    mov  eax, -1
    ret

; Qualified FADT mode command: EAX=SMI port | ENABLE<<16 | DISABLE<<24,
; zero means the platform has no legacy/ACPI transition; -1 refuses. These
; commands are used only when actual SCI_EN is clear at the final S5 boundary.
; Reuse both complete PM1 decoders, then exclude every decoded block from
; the byte SMI command address. No vendor port or command is synthesized.
power_fadt_mode_decode:
    call power_fadt_pm1_status_decode
    cmp eax, -1
    je .refuse
    cmp dword [rdi + 4], 116
    jb .refuse
    test dword [rdi + 112], 0x100000 ; HW_REDUCED has no legacy-mode protocol
    jnz .refuse
    mov r10d, eax                   ; status ports; R9D still holds control ports
    mov r8d, [rdi + 48]             ; SMI_CMD (32-bit FADT address)
    test r8d, r8d
    jz .none                       ; ACPI-only platform: no SMI required
    cmp r8d, 0xffff
    ja .refuse
    movzx eax, byte [rdi + 52]
    test eax, eax
    jz .refuse
    movzx edx, byte [rdi + 53]
    test edx, edx
    jz .refuse                     ; a returned transition must be reversible
    cmp eax, edx
    je .refuse
    movzx ecx, r9w
    call .control_alias
    jc .refuse
    shr r9d, 16
    mov ecx, r9d
    call .control_alias
    jc .refuse
    movzx ecx, r10w
    call .event_alias
    jc .refuse
    shr r10d, 16
    mov ecx, r10d
    call .event_alias
    jc .refuse
    shl edx, 24
    shl eax, 16
    or eax, edx
    or eax, r8d
    ret
.control_alias:
    test ecx, ecx
    jz .clear
    mov r11d, r8d
    sub r11d, ecx
    movzx ecx, byte [rdi + 89]
    cmp r11d, ecx
    ret                            ; CF=1 within the complete control block
.event_alias:
    test ecx, ecx
    jz .clear
    mov r11d, r8d
    sub r11d, ecx
    cmp r11d, 4
    ret
.clear:
    clc
    ret
.none:
    xor eax, eax
    ret
.refuse:
    mov eax, -1
    ret

; One 8-bit firmware command, then <=1000 actual SCI_EN reads spaced by
; bounded 1ms delays. EDI=qualified packed mode command, ESI=PM1a control,
; EDX=desired SCI_EN (1 enable / 0 restore legacy). No IRQ policy change here.
; EAX=0 observed desired mode, -1 timeout. Callee-saved state stays intact.
power_s5_mode_set:
    push rbx
    push r12
    push r13
    push r14
    mov r12d, edi
    mov r13d, esi
    mov r14d, edx
%ifdef PAOS_LAB_HP_SMICMD_TRACE
    POWER_LAB_SMICMD_ENTER          ; HP244 lab: caller + TSC before the command
%endif
    mov eax, r12d
    shr eax, 16
    test r14d, r14d
    jnz .command
    shr eax, 8
.command:
    mov edx, r12d
    out dx, al
    mov ebx, 1000
.poll:
    mov edx, r13d
    in ax, dx
    and eax, 1
    cmp eax, r14d
    je .observed
    mov edi, 1000
    call tsc_delay_us
    dec ebx
    jnz .poll
    mov eax, -1
    jmp .out
.observed:
    xor eax, eax
.out:
%ifdef PAOS_LAB_HP_SMICMD_TRACE
    POWER_LAB_SMICMD_EXIT           ; HP244 lab: one SMICMD line per command
%endif
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Working-state fixed-button ownership, separate from terminal S5. State:
; 0 untried,1 initializing,2 live polled owner,3 admission refused,
; 4 enable/arming failed and unwound,5 live mode lost,6 route refused/lost,
; 7 cleanup uncertain (SCI route contained; never report success).
; Only the BSP calls this: once at boot before any xHCI handoff
; (xhci_acpi_mode_early), then from its existing local event service. It adds no
; user action, shutdown authority or remote verb. SCI_BOOT is not used as evidence of mode.
power_button_ownership:
    push rbx
    push r12
    push r13
    pushfq
    cli
    sub rsp, 8
    cmp byte [rel power_button_ownership_state], 2
    je .live
    cmp byte [rel power_button_ownership_state], 0
    jne .bad
    mov byte [rel power_button_ownership_state], 1
    mov edi, 'FACP'
    call acpi_find_table
    test rax, rax
    jz .admission
    mov rbx, rax
    mov rdi, rax
    mov esi, 'FACP'
    call acpi_validate_sdt
    cmp eax, AF_VALID
    jne .admission
    mov r12d, ecx
    mov rdi, rbx
    mov esi, r12d
    call acpi_fixed_button_decode
    cmp rax, -2
    je .admission
    mov rdi, rbx
    mov esi, r12d
    call power_fadt_pm1_decode
    cmp eax, -1
    je .admission
    mov [rel power_button_ownership_pm1], eax
    mov rdi, rbx
    mov esi, r12d
    call power_fadt_mode_decode
    cmp eax, -1
    je .admission
    mov [rel power_button_ownership_command], eax
    movzx edi, word [rel power_button_ownership_pm1]
    call acpi_fixed_button_read16
    and eax, 1
    mov [rel power_button_ownership_live], al
    test eax, eax
    jnz .route
    ; ACPI-only firmware must already expose SCI_EN=1. Never fabricate a port
    ; or force SCI_EN in PM1_CNT. A real delay calibration bounds the command.
    cmp dword [rel power_button_ownership_command], 0
    je .admission
    cmp qword [rel tsc_khz], 0
    je .admission
.route:
    movzx edi, word [rbx+46]
    call acpi_sci_prepare
    test eax, eax
    jnz .routing
    call acpi_sci_hold
    test eax, eax
    jnz .routing
    ; Fresh mode read after route qualification/masking, immediately before the
    ; optional firmware command. Do not act on the earlier admission sample.
    movzx edi, word [rel power_button_ownership_pm1]
    call acpi_fixed_button_read16
    and eax, 1
    mov [rel power_button_ownership_live], al
    test eax, eax
    jnz .owned
    cmp dword [rel power_button_ownership_command], 0
    je .release_admission
    cmp qword [rel tsc_khz], 0
    je .release_admission
    mov byte [rel power_button_ownership_changed], 1
    mov edi, [rel power_button_ownership_command]
    movzx esi, word [rel power_button_ownership_pm1]
    mov edx, 1
    call power_s5_mode_set
    test eax, eax
    jnz .transition_failed
.owned:
    mov byte [rel power_button_ownership_state], 2
.live:
    movzx edi, word [rel power_button_ownership_pm1]
    call acpi_fixed_button_read16
    and eax, 1
    mov [rel power_button_ownership_live], al
    test eax, eax
    jz .lost
    call acpi_sci_check
    test eax, eax
    jnz .route_lost
    xor eax, eax
    jmp .out
.transition_failed:
    mov edi, 4
    jmp .retire
.lost:
    mov edi, 5
    jmp .retire
.route_lost:
    mov edi, 6
.retire:
    call power_button_ownership_abort
    jmp .bad
.release_admission:
    call acpi_sci_release
    test eax, eax
    jnz .unknown
.admission:
    mov byte [rel power_button_ownership_state], 3
    jmp .bad
.routing:
    cmp eax, -2
    je .unknown
    mov byte [rel power_button_ownership_state], 6
    jmp .bad
.unknown:
    mov byte [rel power_button_ownership_state], 7
    mov byte [rel power_button_ownership_live], 255
    call acpi_sci_contain
.bad:
    mov eax, -1
.out:
    add rsp, 8
    popfq
    pop r13
    pop r12
    pop rbx
    ret

; EDI=reason4/5/6. Stop event ownership first; clear only enables we introduced.
; Our boot ACPI_ENABLE is never undone in that boot (root 72372): a DISABLE is a
; runtime SMI_CMD write back to legacy mode, the transition whose firmware
; handler halted the HP chipset xHCI (HP244). While SCI_EN=1, or after an
; ENABLE that timed out and may still complete, ACPI mode stays, the SCI route
; stays masked (state 7) and one acpi_kept line names the reason. Failed/unknown
; cleanup keeps the route masked. A lost live mode never causes an automatic
; second ACPI_ENABLE or repeats a press.
power_button_ownership_abort:
    push rbx
    pushfq
    cli
    sub rsp, 8
    mov ebx, edi
    call acpi_fixed_button_disarm
    test eax, eax
    jnz .unknown
    cmp byte [rel power_button_ownership_changed], 1
    jne .release
    movzx edi, word [rel power_button_ownership_pm1]
    call acpi_fixed_button_read16
    and eax, 1
    mov [rel power_button_ownership_live], al
    test eax, eax
    jnz .keep_acpi
    cmp ebx, 4
    jne .release
    ; ENABLE timed out: firmware may still be completing it. Never release
    ; based on a stale zero, and never answer it with DISABLE.
.keep_acpi:
    lea rdi, [rel power_acpi_kept_text]
    call serial_string
    mov edi, ebx
    call serial_hex64
    call serial_newline
    jmp .unknown
.release:
    call acpi_sci_release
    test eax, eax
    jnz .unknown
    mov byte [rel power_button_ownership_changed], 0
    mov [rel power_button_ownership_state], bl
    jmp .out
.unknown:
    mov byte [rel power_button_ownership_live], 255
    mov byte [rel power_button_ownership_state], 7
    call acpi_sci_contain
.out:
    mov eax, -1
    add rsp, 8
    popfq
    pop rbx
    ret

%macro WDATA_gui_button_ownership 0
align 4
power_button_ownership_command: dd 0
power_button_ownership_live: db 255
power_button_ownership_changed: db 0
%endmacro
WDATA_DEFER WDATA_gui_button_ownership
; END BUTTON OWNERSHIP

acpi_sleep_s5:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16                    ; status, mode commands, mode/NIC-effect flags
    mov dword [rsp + 8], 0
    mov dword [rsp + 12], 0
    call hv_guest_power_s5_inactive
    test eax, eax
    mov r15d, POWER_S5_GUEST_REFUSED
    jnz .fail
    lea  rdi, [rel power_s5_try_text]
    call serial_string
    mov  edi, 'FACP'
    call acpi_find_table
    mov  r15d, 1
    test rax, rax
    jz   .fail
    mov  rbx, rax
    ; acpi_find_table establishes uniqueness/mapping/checksum, not an available
    ; byte count in ECX. Revalidate to obtain the qualified complete FADT span.
    mov  rdi, rbx
    mov  esi, 'FACP'
    call acpi_validate_sdt
    cmp  eax, AF_VALID
    jne  .no_pm1
    mov  r14d, ecx
    mov  rdi, rbx
    mov  esi, ecx
    call power_fadt_pm1_decode
    cmp  eax, -1
    je   .no_pm1
    movzx r12d, ax
    shr  eax, 16
    mov  r13d, eax
    mov  rdi, rbx
    mov  esi, r14d
    call power_fadt_pm1_status_decode
    cmp  eax, -1
    je   .no_pm1
    mov  [rsp], eax
    test r13d, r13d
    jz   .dsdt
    test eax, 0xffff0000
    jz   .no_pm1                    ; both control blocks require status blocks
.dsdt:
    mov rdi, rbx
    mov esi, r14d
    call power_fadt_mode_decode
    mov [rsp + 4], eax              ; malformed mode data is relevant only if SCI_EN=0
    xor  eax, eax
    cmp  r14d, ACPI_FADT_X_DSDT + 8
    jb   .dsdt32
    mov  rax, [rbx + ACPI_FADT_X_DSDT]
.dsdt32:
    test rax, rax
    jnz  .have_dsdt
    mov  eax, [rbx + ACPI_FADT_DSDT]
.have_dsdt:
    mov  r15d, 3
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  rdi, rbx
    mov  esi, 'DSDT'
    call acpi_validate_sdt
    cmp  eax, AF_VALID
    jne  .fail
    ; The checksum/length-validated DSDT has at most AF_MAX_DSDT bytes.
    ; Extraction is DSDT-only, pure and complete before any power I/O.
    lea  rdi, [rbx + ACPI_HDR_LEN]
    mov  esi, ecx
    sub  esi, ACPI_HDR_LEN
    call power_s5_parse_dsdt
    cmp  eax, -1
    je   .fail
    mov  r15d, eax
    and  r15d, 7                       ; SLP_TYPa, already range-validated
    shr  eax, 8
    mov  r14d, eax                     ; SLP_TYPb, never synthesized
.enter:
    ; Read-only trace distinguishes table/ACPI-mode selection from a returned
    ; sleep write or an off-draw measurement on the next carrying metal run.
    lea  rdi, [rel power_s5_registers_text]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    lea  rdi, [rel power_s5_status_port_text]
    call serial_string
    movzx edi, word [rsp]
    call serial_hex64
    lea  rdi, [rel power_s5_control_text]
    call serial_string
    mov  edx, r12d
    in   ax, dx
    movzx edi, ax
    call serial_hex64
    lea  rdi, [rel power_s5_wake_text]
    call serial_string
    movzx edx, word [rsp]
    in   ax, dx
    movzx edi, ax
    call serial_hex64
    lea  rdi, [rel power_s5_types_text]
    call serial_string
    mov  edi, r14d
    shl  edi, 8
    or   edi, r15d
    call serial_hex64
    call serial_newline
    call power_s5_nic_trace                 ; read-only, before CLI/storage/sleep
    lea  rdi, [rel power_s5_enter_text]
    call serial_string
    call serial_drain_poll
    pushfq                              ; the caller's IF, restored exactly below
    cli
    call power_storage_quiesce          ; completed (not just issued) before any PM1 write
    test eax, eax
    jnz  .unquiesced
    ; Firmware can hand us legacy mode (observed on HP179). SCI_EN is a
    ; firmware acknowledgement, never a bit for the OS to force in PM1_CNT.
    ; Only this terminal, storage-complete S5 path requests the mode switch.
    mov edx, r12d
    in ax, dx
    test ax, 1
    jnz .mode_ready                    ; preserve already-ACPI machines exactly
    mov edi, [rsp + 12]                ; pushfq above the local frame
    cmp edi, -1
    je .mode_refused
    test edi, edi
    jz .mode_ready                     ; FADT SMI_CMD=0: ACPI-only platform
    mov dword [rsp + 16], 1            ; set BEFORE command, even on uncertain ACK
    mov esi, r12d
    mov edx, 1
    call power_s5_mode_set
    test eax, eax
    jnz .mode_failed
    lea rdi, [rel power_s5_mode_enabled_text]
    call serial_string
    mov edx, r12d
    in ax, dx
    movzx edi, ax
    call serial_hex64
    call serial_newline
    call serial_drain_poll
.mode_ready:
    mov rdi, rbx                        ; still the admitted DSDT pointer
    movzx esi, word [rsp + 8]           ; decoded PM1a event port, below flags
    mov edx, r12d                      ; decoded PM1a control port
    call acpi_hp_s5_prepare             ; zero=other platform,1=prepared,-1=refuse
    test eax, eax
    js .hp_refused
    cmp eax, 1
    jne .hp_prepared
    lea rdi, [rel power_hp_pts_complete_text]
    call serial_string
    call serial_drain_poll
.hp_prepared:
    ; The irreversible native NIC leaf is last: storage and platform-specific
    ; preparation have both completed. It is distinct from retained-plan stop.
    sub rsp,8                         ; flags above locals skew call alignment
    call power_s5_nic_stop
    add rsp,8
    cmp eax,-2
    je .nic_terminal_failed
    test eax,eax
    js .nic_refused
    mov [rsp+20],eax                   ; 0 skipped /1 terminal D3 (flags above locals)
    call power_s5_commit_key             ; managed only: storage complete before key wipe
    wbinvd
    ; ACPI legacy sleep starts by clearing WAK_STS (W1C). Preserve every
    ; other fixed-event status and every enable bit. A latched prior wake
    ; must not be carried into this S5 transition.
    movzx edx, word [rsp + 8]            ; pushfq is above our decoded ports
    mov  ax, ACPI_PM1_WAK_STS
    out  dx, ax
    movzx edx, word [rsp + 10]
    test edx, edx
    jz   .wake_cleared
    out  dx, ax
.wake_cleared:
    ; SLP_TYP first, then SLP_EN, PM1a before PM1b (as ACPICA does)
    mov  edx, r12d
    in   ax, dx
    and  ax, ~ACPI_PM1_SLP_MASK & 0xffff
    mov  ecx, r15d
    and  ecx, 7
    shl  ecx, 10
    or   ax, cx
    mov  r8w, ax
    out  dx, ax
    test r13d, r13d
    jz   .en_a
    mov  edx, r13d
    in   ax, dx
    and  ax, ~ACPI_PM1_SLP_MASK & 0xffff
    mov  ecx, r14d
    and  ecx, 7
    shl  ecx, 10
    or   ax, cx
    mov  r9w, ax
    out  dx, ax
.en_a:
    mov  edx, r12d
    mov  ax, r8w
    or   ax, ACPI_PM1_SLP_EN
    out  dx, ax
    test r13d, r13d
    jz   .wait
    mov  edx, r13d
    mov  ax, r9w
    or   ax, ACPI_PM1_SLP_EN
    out  dx, ax
.wait:
    mov  ecx, 50000000                  ; the platform powers off within this spin
.spin:
    pause
    dec  ecx
    jnz  .spin
    call .restore_mode                  ; no new SCI mode escapes to the live caller
    cmp dword [rsp+20],0
    je .returned_without_nic
    ; D3 exit requires a full device reinitialization. Never restore IF and
    ; return to the UI/poll loop pretending this terminal device is live.
    cmp byte [rel pbm_runtime_reset_usable],1
    jne .nic_terminal_failed
    mov edi,POWER_S5_SPUN
    sub rsp,8
    call power_shutdown_fallback        ; already-quiesced firmware shutdown, else halt
    add rsp,8
.nic_terminal_failed:
    sub rsp,8
    call reset_wipe_all
    call reset_wipe_halt
.returned_without_nic:
    popfq                               ; still running: restore IF exactly, never force it on
    mov  r15d, 4
    jmp  .fail
.hp_refused:
    call .restore_mode
    lea rdi, [rel power_hp_pts_refused_text]
    call serial_string
    popfq
    mov r15d, POWER_S5_HP_REFUSED        ; normal firmware fallback, keys retained
    jmp .fail
.nic_refused:
    call .restore_mode
    popfq
    mov r15d,POWER_S5_NIC_REFUSED       ; no NIC effect; ordinary firmware fallback
    jmp .fail
.mode_failed:
    call .restore_mode                  ; cancel even an unacknowledged enable command
.mode_refused:
    lea rdi, [rel power_s5_mode_refused_text]
    call serial_string
    popfq
    mov r15d, POWER_S5_MODE_REFUSED      ; existing firmware fallback; storage already complete
    jmp .fail
.restore_mode:
    ; Nested call adds one return address above flags and the 16-byte locals.
    cmp dword [rsp + 24], 0
    je .mode_restored
    mov edi, [rsp + 20]
    mov esi, r12d
    xor edx, edx
    call power_s5_mode_set
    test eax, eax
    jz .mode_restored
    ; Cannot resume an IRQ-enabled caller with unknown firmware event routing.
    ; Storage is already quiesced: erase keys and stop with IF still clear.
    lea rdi, [rel power_s5_mode_unrestored_text]
    call serial_string
    call serial_drain_poll
    call reset_wipe_all
    call reset_wipe_halt
.mode_restored:
    ret
.unquiesced:
    popfq
    mov  r15d, POWER_S5_UNQUIESCED
    jmp  .fail
.no_pm1:
    mov  r15d, 2
.fail:
    lea  rdi, [rel power_s5_failed_text]
    call serial_string
    mov  eax, r15d
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
; Bounded terminal diagnostic only. A sample failure never gates shutdown;
; no class/power adapter registration, driver stop or PCI power-state write.
; Fields after v1 are result/bus/devfn/id/cmdsts/pmoff/pmcap/pmcsr/reads/gen.
power_s5_nic_trace:
    push rbx
    sub rsp, 64
    mov rdi, rsp
    call reinit_power_e1000e_snapshot
    lea rdi, [rel power_s5_nic_text]
    call serial_string
    xor ebx, ebx
.field:
    mov edi, [rsp+4+rbx*4]
    call serial_hex64
    lea rdi, [rel power_s5_nic_sep]
    call serial_string
    inc ebx
    cmp ebx, 9
    jb .field
    mov rdi, [rsp+40]
    call serial_hex64
    call serial_newline
    add rsp, 64
    pop rbx
    ret

; Called with IF clear after storage/platform preparation. The production leaf
; provides the result plus exact PCI readbacks, not a claim of electrical off.
power_s5_nic_stop:
    push rbx
    sub rsp,32
    mov rdi,rsp
    call reinit_power_e1000e_s5
    lea rdi,[rel power_s5_nic_stop_text]
    call serial_string
    xor ebx,ebx
.field:
    mov edi,[rsp+rbx*4]
    call serial_hex64
    lea rdi,[rel power_s5_nic_sep]
    call serial_string
    inc ebx
    cmp ebx,6
    jb .field
    call serial_newline
    call serial_drain_poll
    mov eax,[rsp]
    add rsp,32
    pop rbx
    ret

; BEGIN PURE S5 PARSER -- the host fixture assembles this production region.
; power_s5_parse_dsdt(RDI=DSDT body, RSI=body byte count) -> EAX:
;   SLP_TYPa | (SLP_TYPb << 8), or UINT32_MAX on refusal.
; The caller validates the complete DSDT checksum/header/mapping first. This
; helper independently enforces the remaining 256-KiB-DSDT byte budget and
; bounds every read. No AML namespace, evaluation, allocation or I/O occurs.
; Approved grammar: NameOp [RootChar] _S5_ PackageOp PkgLength NumElements
; followed by exactly NumElements constants from Zero/One/BytePrefix+byte.
; PkgLength includes its own 1-4 bytes; reserved lead bits must be zero.
; Both sleep types must be explicit and fit their 3-bit fields. Other declared
; elements may contain byte values but must have the same approved encoding.
; A recognized name with a missing/unsupported value, malformed package,
; zero matches or multiple exact names refuses.
; Coverage is deliberately DSDT-only. Callee-saved registers are preserved.
power_s5_parse_dsdt:
    push rbx
    push r12
    push r13
    push r14
    push r15
    test rdi, rdi
    jz   .refuse
    test rsi, rsi
    jz   .refuse
    cmp  rsi, AF_MAX_DSDT - ACPI_HDR_LEN
    ja   .refuse
    mov  r14, rdi
    add  r14, rsi
    jc   .refuse
    mov  rbx, rdi
    mov  r12d, -1                     ; no accepted package yet
.scan:
    cmp  rbx, r14
    jae  .done
    cmp  byte [rbx], 0x08             ; NameOp, not an arbitrary _S5 substring
    jne  .next
    lea  rsi, [rbx + 1]
    cmp  rsi, r14
    jae  .next
    cmp  byte [rsi], 0x5c             ; optional RootChar
    jne  .name
    inc  rsi
.name:
    mov  rax, r14
    sub  rax, rsi
    cmp  rax, 4                      ; recognize the complete name first
    jb   .next
    cmp  dword [rsi], '_S5_'
    jne  .next
    cmp  r12d, -1
    jne  .refuse                     ; another exact name is ambiguous
    cmp  rax, 5                      ; no value byte after a recognized name
    jb   .refuse
    cmp  byte [rsi + 4], 0x12
    jne  .refuse                     ; never ignore an unsupported _S5 value
    lea  r13, [rsi + 5]              ; PkgLength begins here
    cmp  r13, r14
    jae  .refuse
    movzx eax, byte [r13]
    mov  r9d, eax
    shr  r9d, 6                      ; number of following length bytes
    lea  rsi, [r13 + 1]
    test r9d, r9d
    jnz  .long_length
    mov  r8d, eax
    and  r8d, 0x3f
    jmp  .length_ready
.long_length:
    test al, 0x30                    ; reserved for a multi-byte length
    jnz  .refuse
    mov  r8d, eax
    and  r8d, 0x0f
    mov  rax, r14
    sub  rax, rsi                    ; compare remaining bytes without overflow
    cmp  rax, r9
    jb   .refuse
    mov  ecx, 4
.length_byte:
    movzx edx, byte [rsi]
    shl  edx, cl
    or   r8d, edx
    inc  rsi
    add  ecx, 8
    dec  r9d
    jnz  .length_byte
.length_ready:
    mov  r15, r13
    add  r15, r8
    jc   .refuse
    cmp  r15, r14
    ja   .refuse
    cmp  rsi, r15                    ; length must include NumElements
    jae  .refuse
    movzx r10d, byte [rsi]
    inc  rsi
    cmp  r10d, 2
    jb   .refuse
    call .element
    cmp  eax, 7                      ; also refuses UINT32_MAX
    ja   .refuse
    mov  r11d, eax
    call .element
    cmp  eax, 7
    ja   .refuse
    shl  eax, 8
    or   r11d, eax
    sub  r10d, 2
.remaining:
    test r10d, r10d
    jz   .package_end
    call .element
    cmp  eax, -1
    je   .refuse
    dec  r10d
    jmp  .remaining
.package_end:
    cmp  rsi, r15                    ; no undeclared/truncated elements
    jne  .refuse
    mov  r12d, r11d
.next:
    inc  rbx                        ; scan the entire declared byte budget
    jmp  .scan
.done:
    mov  eax, r12d
    jmp  .out
.refuse:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.element:
    cmp  rsi, r15
    jae  .bad_element
    movzx eax, byte [rsi]
    inc  rsi
    cmp  eax, 1                      ; ZeroOp or OneOp
    jbe  .element_out
    cmp  eax, 0x0a                   ; the only sanctioned integer prefix
    jne  .bad_element
    cmp  rsi, r15
    jae  .bad_element
    movzx eax, byte [rsi]
    inc  rsi
.element_out:
    ret
.bad_element:
    mov  eax, -1
    ret
; END PURE S5 PARSER

power_confirmed_text:    db "[PAOS64] power.confirmed",0
power_k_windows:         db " kind=windows",13,10,0
power_k_restart:         db " kind=restart",13,10,0
power_k_shutdown:        db " kind=shutdown",13,10,0
power_reset_text:        db "[PAOS64] power.reset.warm",13,10,0
power_windows_refused_text: db "[PAOS64] power.windows.refused (BOOT WIN did not arm; nothing was reset)",13,10,0
power_s5_nic_text: db "[PAOS64] power.s5.nic_pci v1 result/bus/devfn/id/cmdsts/pmoff/pmcap/pmcsr/reads/gen=",0
power_s5_nic_sep: db "/",0
power_s5_nic_stop_text: db "[PAOS64] power.s5.nic_stop v1 result/stage/pm_before/pm_after/cmd_after/polls=",0
power_s5_try_text:       db "[PAOS64] power.s5.try",13,10,0
power_s5_registers_text: db "[PAOS64] power.s5.registers cnt=",0
power_s5_status_port_text: db " sts=",0
power_s5_control_text:   db " control_before=",0
power_s5_wake_text:      db " status_before=",0
power_s5_types_text:     db " types=",0
power_s5_mode_enabled_text: db "[PAOS64] power.s5.acpi_mode enabled control_after=",0
power_s5_mode_refused_text: db "[PAOS64] power.s5.acpi_mode refused",13,10,0
power_s5_mode_unrestored_text: db "[PAOS64] power.s5.acpi_mode restore_failed stopping",13,10,0
power_acpi_kept_text:    db "[PAOS64] power.button.acpi_kept route_masked state=7 reason=",0
power_s5_enter_text:     db "[PAOS64] power.s5.enter",13,10,0
power_hp_pts_complete_text: db "[PAOS64] HP fixed S5 preparation complete",13,10,0
power_hp_pts_refused_text: db "[PAOS64] HP fixed S5 preparation refused",13,10,0
power_s5_failed_text:    db "[PAOS64] power.s5.failed coverage=dsdt-only",13,10,0
power_q_windows:         db "Return to Windows now? [y/N] ",0
power_q_restart:         db "Restart PaOS now? [y/N] ",0
power_q_shutdown:        db "Shut down (power off) now? [y/N] ",0
power_r_windows:         db "Return to Windows refused: no Windows boot entry could be armed (nothing was reset)",13,10,0
power_r_unquiesced:      db "Shut down refused: a disk could not be flushed, so power was left on (try again)",13,10,0
power_r_unquiesced_offline: db "Shut down refused: the NVMe disk did not finish shutting down; power was left on and that disk is offline until restart (Shut down again to power off)",13,10,0
power_r_shutdown_offline: db "Shut down failed: neither ACPI S5 nor the firmware powered off; the disks were flushed and the NVMe disk is offline until restart",13,10,0
power_q_text:            db "[PAOS64] power.storage.quiesce ahci_flushed=",0
power_q_failed_text:     db " ahci_failed=",0
power_q_nvme_text:       db " nvme=",0
power_q_ok_text:         db " ok",13,10,0
power_q_refused_text:    db " REFUSED",13,10,0
power_r_guest_active:    db "Shut down refused: guest work or an assigned device is still active; actual stop and teardown are required",13,10,0
power_r_shutdown:        db "Shut down failed: neither ACPI S5 nor the firmware powered off (nothing was reset)",13,10,0
power_r_reset:           db "Restart failed: the reset did not take",13,10,0
power_r_unknown:         db "unknown power request",13,10,0
power_verb_boot:         db "BOOT",0
power_arg_win:           db "WIN",0

%macro WDATA_gui_power_exec_0 0
alignb 8
power_req:               resb REQ_SZ
power_rsp:               resb RSP_SZ
power_q_ahci_ok:         resd 1
power_q_ahci_failed:     resd 1
power_q_nvme:            resd 1
%endmacro
WDATA_BSS_DEFER WDATA_gui_power_exec_0

; Opt-in S5 transaction over the accepted driver_power v1 plan. This owns no
; driver registry/ABI. Native-button observation still only opens confirmation.
PS5_WAIT equ 1
PS5_RECOVER equ 2
PS5_COMMIT equ 3
PS5_TERMINAL equ 4
PS5_DEGRADED equ 5
PS5_AUTH equ -11
PS5_REQUIRED equ 127                    ; six native classes + explicit guest
%macro PS5_ENTER 0
    cld
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
%endmacro
%macro PS5_EXIT 0
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    cld
    ret
%endmacro
; Private try-only guard, never spins over a callback or irreversible commit.
power_s5_enter:
    mov al, 1
    xchg al, [rel ps5_busy]
    test al, al
    jnz .busy
    xor eax, eax
    ret
.busy:
    mov rax, DP_BUSY
    ret

; Trusted kernel owner: RDI=pinned plan, ESI=explicit required mask, EDX=ms.
; All seven class owners must declare readiness/absence. No RAM-only system
; success: storage must explicitly own IRQ/DMA/flush and not be the reference.
power_s5_bind:
    PS5_ENTER
    mov r12, rdi
    mov r13d, esi
    mov r14d, edx
    call power_s5_enter
    test rax, rax
    jnz .out
    mov rbp, DP_UNSUPPORTED
    cmp qword [rel ps5_plan], 0
    jne .done
    test r12, r12
    jz .done
    cmp dword [r12+dp_context.version], DP_VERSION
    jne .done
    cmp dword [r12+dp_context.state], DP_RUNNING
    jne .done
    cmp byte [r12+dp_context.busy], 0
    jne .done
    cmp dword [r12+dp_context.count], DP_LIMIT
    ja .done
    cmp r13d, PS5_REQUIRED
    jne .done
    mov eax, [r12+dp_context.members]
    and eax, r13d
    cmp eax, r13d
    jne .done
    test r14d, r14d
    jz .done
    cmp r14d, DP_MAX_MS
    ja .done
    xor ecx, ecx
.find_storage:
    cmp ecx, [r12+dp_context.count]
    jae .done
    mov eax, ecx
    shl rax, 6
    lea rbx, [r12+rax+dp_context.slots+dp_slot.driver]
    inc ecx
    cmp dword [rbx+dp_driver.kind], DP_STORAGE
    jne .find_storage
    mov eax, [rbx+dp_driver.capabilities]
    and eax, 7
    cmp eax, 7
    jne .done
    lea rax, [rel reinit_power_ram_callback]
    cmp [rbx+dp_driver.callback], rax
    je .done
    mov [rel ps5_plan], r12
    mov [rel ps5_required], r13d
    mov [rel ps5_timeout], r14d
    xor ebp, ebp
.done:
    mov rax, rbp
    mov byte [rel ps5_busy], 0
.out:
    PS5_EXIT

; Existing confirmed local-owner caller only; no new command/native bypass.
; Confirmation remains the established human-origin y/N flow. This repeats its
; local session authority gate and pins full64 token/epoch through the commit.
power_s5_request:
    PS5_ENTER
    call power_s5_enter
    test rax, rax
    jnz .out
    mov rbp, DP_UNSUPPORTED
    mov rbx, [rel ps5_plan]
    test rbx, rbx
    jz .done
    mov rbp, DP_BUSY
    cmp byte [rel ps5_attempted], 0
    jne .done
    cmp dword [rel ps5_state], PS5_WAIT
    je .done
    cmp dword [rel ps5_state], PS5_RECOVER
    je .done
    call session_shell_local_authority
    mov rbp, PS5_AUTH
    cmp rax, PRIN_OWNER
    jne .done
    test rdx, rdx
    jz .done
    mov r12, rdx
    mov r13, [rel session_authority_epoch]
    call boot_ms_now
    mov rbp, DP_CLOCK
    test rax, rax
    jz .done                            ; uncalibrated clock cannot bound a request
    mov rdi, rbx
    mov esi, DP_POWER_QUIESCE
    mov edx, [rel ps5_required]
    mov ecx, [rel ps5_timeout]
    call reinit_power_begin
    mov rbp, rax
    cmp rax, DP_PENDING
    jne .done
    mov [rel ps5_owner_token], r12
    mov [rel ps5_owner_epoch], r13
    mov rax, [rbx+dp_context.token]
    mov [rel ps5_plan_token], rax
    mov dword [rel ps5_error], 0
    mov dword [rel ps5_state], PS5_WAIT
.done:
    mov rax, rbp
    mov byte [rel ps5_busy], 0
.out:
    PS5_EXIT

power_s5_owner_valid:
    sub rsp, 8
    call session_shell_local_authority
    add rsp, 8
    cmp rax, PRIN_OWNER
    jne .bad
    cmp rdx, [rel ps5_owner_token]
    jne .bad
    mov rax, [rel session_authority_epoch]
    cmp rax, [rel ps5_owner_epoch]
    jne .bad
    xor eax, eax
    ret
.bad:
    mov rax, PS5_AUTH
    ret

; RBX=plan, EBP=reason. Use only the existing coordinator's cancel/recovery or
; actual paused-plan resume. No hardware rollback is claimed after commit.
power_s5_abort:
    sub rsp, 8
    mov [rel ps5_error], ebp
    cmp dword [rbx+dp_context.state], DP_PAUSED
    je .resume
    mov rdi, rbx
    call reinit_power_cancel
    jmp .result
.resume:
    mov rdi, rbx
    mov esi, DP_RECOVERY_MS
    call reinit_power_resume
.result:
    cmp rax, DP_PENDING
    jne .degraded
    mov dword [rel ps5_state], PS5_RECOVER
    add rsp, 8
    ret
.degraded:
    mov dword [rel ps5_state], PS5_DEGRADED
    add rsp, 8
    ret

power_s5_cancel:
    PS5_ENTER
    call power_s5_enter
    test rax, rax
    jnz .out
    mov rax, DP_INVALID
    cmp dword [rel ps5_state], PS5_WAIT
    jne .done
    mov rbx, [rel ps5_plan]
    mov rbp, DP_CANCELLED
    call power_s5_abort
    cmp dword [rel ps5_state], PS5_RECOVER
    jne .error
    mov rax, DP_PENDING
    jmp .done
.error:
    movsxd rax, dword [rel ps5_error]
.done:
    mov byte [rel ps5_busy], 0
.out:
    PS5_EXIT

; Resident idle-loop projection. One parent step/callback per invocation. Final
; canonical S5 commit is latched before any irreversible operation and never
; retried, including a return with storage already offline or an uncertain stop.
power_s5_step:
    PS5_ENTER
    call power_s5_enter
    test rax, rax
    jnz .out
    mov rax, DP_UNSUPPORTED
    mov rbx, [rel ps5_plan]
    test rbx, rbx
    jz .done
    mov eax, [rel ps5_state]
    cmp eax, PS5_WAIT
    je .identity
    cmp eax, PS5_RECOVER
    je .identity
    movsxd rax, dword [rel ps5_error]
    jmp .done
.identity:
    mov rax, [rbx+dp_context.token]
    cmp rax, [rel ps5_plan_token]
    jne .changed
    cmp dword [rel ps5_state], PS5_RECOVER
    je .drive
    call power_s5_owner_valid
    test rax, rax
    jnz .auth
.drive:
    mov rdi, rbx
    call reinit_power_step
    cmp rax, DP_PENDING
    je .pending
    cmp dword [rbx+dp_context.state], DP_DEGRADED
    je .parent_degraded
    cmp dword [rbx+dp_context.state], DP_RUNNING
    je .recovered
    cmp dword [rbx+dp_context.state], DP_PAUSED
    jne .changed
    cmp dword [rel ps5_state], PS5_WAIT
    jne .changed
    ; The final boundary independently samples time and authority. The parent
    ; cannot authorize a commit at/after its exclusive deadline or on stale login.
    call boot_ms_now
    cmp rax, [rbx+dp_context.clock_last]
    jb .clock
    cmp rax, [rbx+dp_context.deadline]
    jae .timeout
    call power_s5_owner_valid
    test rax, rax
    jnz .auth
    mov byte [rel ps5_attempted], 1
    mov dword [rel ps5_state], PS5_COMMIT
    mov byte [rel ps5_committing], 1
    mov byte [rel ps5_wipe_done], 0
    call power_s5_managed_commit
    ; Canonical poweroff returning does not prove hardware rollback/readiness.
    mov byte [rel ps5_committing], 0
    call power_nvme_offline
    mov [rel ps5_offline], al
    mov dword [rel ps5_state], PS5_DEGRADED
    mov dword [rel ps5_error], DP_FAILED
    mov rax, DP_FAILED
    jmp .done
.auth:
    mov rbp, PS5_AUTH
    jmp .abort
.clock:
    mov rbp, DP_CLOCK
    jmp .abort
.timeout:
    mov rbp, DP_TIMEOUT
.abort:
    call power_s5_abort
    cmp dword [rel ps5_state], PS5_RECOVER
    jne .saved_error
.pending:
    mov rax, DP_PENDING
    jmp .done
.changed:
    mov dword [rel ps5_error], DP_CHANGED
    mov dword [rel ps5_state], PS5_DEGRADED
    jmp .saved_error
.parent_degraded:
    mov dword [rel ps5_state], PS5_DEGRADED
    cmp dword [rel ps5_error], 0
    jne .saved_error
    mov eax, [rbx+dp_context.error]
    mov [rel ps5_error], eax
    jmp .saved_error
.recovered:
    mov dword [rel ps5_state], PS5_TERMINAL
    cmp dword [rel ps5_error], 0
    jne .saved_error
    mov eax, [rbx+dp_context.error]
    mov [rel ps5_error], eax
.saved_error:
    movsxd rax, dword [rel ps5_error]
.done:
    mov byte [rel ps5_busy], 0
.out:
    PS5_EXIT

; Shared canonical seams, no new firmware/PM1 algorithm. A returned commit stays
; fenced/degraded; ResetSystem returning still ends at reset_wipe_halt as before.
power_s5_managed_commit:
    sub rsp, 8
    call software_stop_stability_exit_hook ; retain the canonical strong-health settlement
    call acpi_sleep_s5
    cmp eax, POWER_S5_UNQUIESCED
    je .out
    cmp byte [rel pbm_runtime_reset_usable], 1
    jne .out
    mov edi, eax
    call power_shutdown_fallback
.out:
    add rsp, 8
    ret

; Called only AFTER the existing canonical storage helper returned complete.
; Legacy callers have already wiped at power_execute and remain unchanged.
power_s5_commit_key:
    cmp byte [rel ps5_committing], 1
    jne .out
    cmp byte [rel ps5_wipe_done], 0
    jne .out
    mov byte [rel ps5_wipe_done], 1
    sub rsp, 8
    call principal_wipe_owner_boot_key
    add rsp, 8
.out:
    ret

; EAX=state (0unbound/idle), EDX=signed error, RCX=full64 plan token,
; R8D=commit attempted, R9D=actual canonical NVMe offline observation.
power_s5_status:
    cld
    mov eax, [rel ps5_state]
    mov edx, [rel ps5_error]
    mov rcx, [rel ps5_plan_token]
    movzx r8d, byte [rel ps5_attempted]
    movzx r9d, byte [rel ps5_offline]
    ret

%macro WDATA_gui_managed_s5 0
align 8
ps5_plan: dq 0
ps5_plan_token: dq 0
ps5_owner_token: dq 0
ps5_owner_epoch: dq 0
ps5_required: dd 0
ps5_timeout: dd 0
ps5_state: dd 0
ps5_error: dd 0
ps5_busy: db 0
ps5_attempted: db 0
ps5_committing: db 0
ps5_wipe_done: db 0                  ; boolean completion latch; contains no key bytes
ps5_offline: db 0
ps5_pending_text: db "Shut down requested; waiting for owned drivers to stop.", 0
ps5_refused_text: db "Managed shut down refused or already active; inspect driver ownership.", 0
%endmacro
WDATA_DEFER WDATA_gui_managed_s5
