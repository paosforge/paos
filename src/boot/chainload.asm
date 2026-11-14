;; MODULE boot/chainload
;; LAYER 0
;; EXPORTS chainload_cmos_nvram_ok, chainload_escalate_check, chainload_m_check, chainload_windows_orig, chainload_linux_orig, chainload_manager_require_bootnext_absent, chainload_linux_volume_resolve, chainload_dp_resolve, chainload_try_path, chainload_cmos_rd, chainload_cmos_wr, cl_linux_live_attempted, cl_linux_fail_rc, cl_linux_selected_boot, cl_linux_dp_len, cl_linux_selftest_ok, cl_manager_fail_rc, cl_manager_selected_boot, chainload_linux_arm_bootnext, chainload_windows_arm_bootnext
;; IMPORTS boot/serial, boot/header, boot/boot_v2_handoff
;; CAPS
;; OWNER saga:boot
; ============================================================================
; boot/chainload.asm — 9702: the ACT-ON-FALLBACK half of the A/B boot canon.
;
; core/boot_canon (1073) proved the trial/good state machine; svc/boot_ab (1014)
; put the counter in real CMOS (0x74 trial / 0x75 confirmed) — but NOTHING acted
; on FALLBACK: a keep that fault-reboots every boot would climb the counter and
; then just... keep booting (with the armed CF9 of 9702, an infinite reboot
; loop). THIS module closes the ladder: at efi_entry, BEFORE ExitBootServices
; (LoadImage/StartImage are boot services — after exit_boot_and_page it is too
; late), read the CMOS trial/confirmed bytes; an UNCONFIRMED keep with >=
; CHAINLOAD_MAX_TRIALS recorded trials chainloads bootmgfw_orig.efi (Windows).
; The trial byte is reset to 0 first, so the NEXT PaOS boot gets a fresh trial
; ladder (self-healing: a still-broken keep takes another N fault-reboots and
; lands back in Windows — bounded, never an infinite loop, never a dark box).
;
; PORT (M16): the device-path LoadImage/StartImage sequence, GUIDs, UCS-2 paths
; and stack discipline are ported from the monolith's chainload_windows
; (../paos/paos.asm:139628 — boots Windows on THIS Lenovo today). Deliberate
; deltas, earned: (a) only the two REAL-Windows paths (bootmgfw_orig.efi, then
; the Lenovo-layout BOOTMGR.EFI) — the monolith's backup/lkg/bootmgfw entries
; are PaOS keeps, wrong for an escalation whose goal is "get OFF the broken
; keep"; (b) fail-OPEN: if both paths fail to load, print and continue booting
; PaOS (a reachable trial keep beats a hung firmware shell).
;
; CMOS access is a module-local 2-liner (NMI-bit index write + data read), same
; register order as the monolith cmos_read; svc/boot_ab's cmos_ab_rd is layer 5
; and cannot be imported from layer 0.
; ============================================================================

CHAINLOAD_CMOS_IDX   equ 0x70
CHAINLOAD_CMOS_DATA  equ 0x71
CHAINLOAD_CMOS_TRIAL equ 0x74         ; = boot_ab CMOS_AB_TRIAL
CHAINLOAD_CMOS_CONF  equ 0x75         ; = boot_ab CMOS_AB_CONFIRMED
CHAINLOAD_CONF_MAGIC equ 0xC0         ; = boot_ab AB_CONFIRMED_MAGIC
CHAINLOAD_MAX_TRIALS equ 3            ; = boot_ab AB_MAX_TRIALS

; 1124a5: bounded live BootOrder / EFI_LOAD_OPTION geometry. These preserve
; Classic's proven 64-entry BootOrder bound while retaining the COMPLETE
; firmware device path used by the selected option. No Boot####, disk, or
; partition identity is compiled into PaOS.
CL_LINUX_BOOTORDER_MAX equ 128
CL_LINUX_LOADOPT_MAX   equ 768
CL_LINUX_DP_MAX        equ 512
CL_LINUX_PATH_BYTES    equ 48         ; 23 UCS-2 chars + NUL
CL_LINUX_FILE_NODE_LEN equ (4 + CL_LINUX_PATH_BYTES)
CL_WINDOWS_DESC_BYTES  equ 42         ; L"Windows Boot Manager" + NUL
CL_WINDOWS_PATH_BYTES  equ 66         ; L"\EFI\Microsoft\Boot\bootmgfw.efi" + NUL
CL_WINDOWS_FILE_NODE_LEN equ (4 + CL_WINDOWS_PATH_BYTES)

; RCQ-28 (2026-10-08): the 1262a resolver for the retained E02 'PaOS Boot Manager'
; row (chainload_manager_once and its enumeration/match helpers) is removed. That row
; is the Vault recovery artifact 52eec6e5, reached only through the gated rollback
; rail; BOOT MANAGER refuses (refused_rc=10). The BootNext-absent check, the verified
; BootNext write and cl_manager_* state below serve the WIN/LINUX one-shot paths.
CL_EFI_NOT_FOUND         equ 0x800000000000000E

; HP CMOS allowlist (Q8): legacy CMOS NVRAM I/O (0x70/0x71) is limited to
; GenuineIntel, i.e. the Lenovo/Dell/Beelink/MSI fleet whose CMOS canon is
; metal-proven. On AMD (HP EliteDesk 705 G5: PaOS CMOS writes are the leading
; explanation of BIOS error 005 / factory-default resets) and any other vendor
; PaOS performs NO CMOS port I/O: reads return 0 (the fresh-CMOS view: no trial,
; not confirmed, no override) and writes are dropped. Volatile-only on those CPUs.
; A live Try boot (RCQ-29 pbm_try_media) gets the same volatile view on every CPU, so
; booting a Try USB never changes the machine's CMOS.
; chainload_cmos_nvram_ok -> ZF=1 iff CMOS NVRAM I/O is permitted. Preserves all GPRs.
chainload_cmos_nvram_ok:
    cmp  byte [rel pbm_try_media], 1
    je   .try_media
    cmp  byte [rel chainload_cmos_vendor], 0
    jne  .known
    push rax
    push rbx
    push rcx
    push rdx
    xor  eax, eax
    cpuid
    mov  al, 2                        ; 2 = not GenuineIntel -> no CMOS NVRAM I/O
    cmp  ebx, 0x756E6547              ; "Genu"
    jne  .store
    cmp  edx, 0x49656E69              ; "ineI"
    jne  .store
    cmp  ecx, 0x6C65746E              ; "ntel"
    jne  .store
    mov  al, 1                        ; 1 = GenuineIntel -> legacy CMOS canon unchanged
.store:
    mov  [rel chainload_cmos_vendor], al
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
.known:
    cmp  byte [rel chainload_cmos_vendor], 1
    ret
.try_media:
    cmp  byte [rel pbm_try_media], 0  ; 1 != 0 -> ZF=0: no CMOS port I/O
    ret

; chainload_cmos_rd(DIL=index) -> AL. clobbers RAX,RDX.
chainload_cmos_rd:
    call chainload_cmos_nvram_ok
    jne  .volatile
    mov  al, dil
    or   al, 0x80                     ; keep NMI disabled during the access
    mov  dx, CHAINLOAD_CMOS_IDX
    out  dx, al
    mov  dx, CHAINLOAD_CMOS_DATA
    in   al, dx
    ret
.volatile:
    xor  eax, eax
    ret

; chainload_cmos_wr(DIL=index, SIL=value). clobbers RAX,RDX.
chainload_cmos_wr:
    call chainload_cmos_nvram_ok
    jne  .dropped
    mov  al, dil
    or   al, 0x80
    mov  dx, CHAINLOAD_CMOS_IDX
    out  dx, al
    mov  al, sil
    mov  dx, CHAINLOAD_CMOS_DATA
    out  dx, al
.dropped:
    ret

; ---------------------------------------------------------------------------
; chainload_escalate_check — called from efi_entry PRE-EBS (boot services must
;   still be alive). Reads the live CMOS trial/confirmed bytes, prints the
;   decision (content-graded: live values, fires every boot -> regression
;   marker boot.chainload.check), and on FALLBACK resets the trial counter and
;   chainloads Windows. Returns (continues PaOS boot) in every non-escalate or
;   escalate-failed case. clobbers: caller-saved.
; ---------------------------------------------------------------------------
chainload_escalate_check:
    push rbx
    push r12

    mov  dil, CHAINLOAD_CMOS_CONF
    call chainload_cmos_rd
    movzx r12d, al                    ; r12b = confirmed byte
    mov  dil, CHAINLOAD_CMOS_TRIAL
    call chainload_cmos_rd
    movzx ebx, al                     ; ebx = trial byte
    cmp  ebx, CHAINLOAD_MAX_TRIALS + 2
    jbe  .trial_sane                  ; garbage / first-ever CMOS -> treat as 0 (boot_ab parity)
    xor  ebx, ebx
.trial_sane:

    ; --- print the live decision line (the every-boot content grade) ---
    lea  rdi, [rel str_cl_chk_pre]    ; "...escalate-check: trial="
    call serial_string
    lea  eax, [ebx + '0']             ; trial is 0..5 post-sanitise — single digit
    mov  [rel cl_digit], al
    lea  rdi, [rel cl_digit]
    call serial_string
    lea  rdi, [rel str_cl_chk_conf]   ; " confirmed=0x"
    call serial_string
    mov  eax, r12d
    shr  eax, 4
    call cl_put_hexdigit
    mov  eax, r12d
    call cl_put_hexdigit

    ; --- the decision. ORDER MATTERS (1273/P56, fixed 2026-08-07): the trial cap
    ;     is tested FIRST. Previously `confirmed == 0xC0` short-circuited to
    ;     .continue before the cap was ever examined, so a keep that had proved
    ;     itself ONCE could never escalate again no matter how many times it
    ;     subsequently failed — it could only recover if something else happened
    ;     to clear the magic. A keep that has burned its whole trial budget is
    ;     failing NOW; what it managed on some earlier boot does not matter. ---
%ifdef PAOS_ESCALATE_FORCE
    ; 1273/P56 NEGATIVE-TEST FIXTURE (build-gated, never in a release): force the
    ; exhausted-budget branch so the escalation LADDER ORDER can be graded without
    ; having to run a real keep into the ground first.
    jmp  .escalate
%endif
    cmp  ebx, CHAINLOAD_MAX_TRIALS
    jae  .escalate                    ; budget exhausted -> escalate, magic or not
    jmp  .continue                    ; under the cap -> keep booting this keep
    ;
    ; NOTE on the retired confirmed==0xC0 test. It is deliberately gone rather
    ; than reordered: once the cap is authoritative the magic adds nothing here.
    ; boot_ab_commit resets the trial byte to 0, so a genuinely confirmed keep
    ; is always under the cap and continues exactly as before -- the ONLY
    ; behaviour that changes is the case this fix exists for, a keep sitting at
    ; or past its budget that used to be waved through forever. The magic keeps
    ; its real job in svc/boot_ab (the trial/good state machine); it is simply
    ; not evidence about THIS boot.

.escalate:
    ; --- FALLBACK ladder. Rung 1 is the VERIFIED VAULT BASELINE — a known-good
    ;     PaOS. Handing the owner's machine to a different operating system is a
    ;     LAST resort, not the first thing we try: the whole point of the A/B
    ;     design is that PaOS recovers to PaOS. Windows stays as the final rung
    ;     so the machine is never left unbootable (invariant I1). ---
    lea  rdi, [rel str_cl_escalate]
    call serial_string
    xor  esi, esi                     ; reset trial -> next PaOS boot is a fresh ladder
    mov  dil, CHAINLOAD_CMOS_TRIAL
    call chainload_cmos_wr
    call chainload_vault_baseline     ; does not return on success
    ; rung 2: the Vault copy is missing/unloadable — fall through to Windows.
    lea  rdi, [rel str_cl_vault_miss]
    call serial_string
    call chainload_windows_orig       ; does not return on success
    ; fail-open: Windows loader missing/unloadable — keep booting PaOS
    lea  rdi, [rel str_cl_failopen]
    call serial_string
    jmp  .done
.continue:
    lea  rdi, [rel str_cl_continue]   ; " -> continue [boot.chainload.check]"
    call serial_string
    mov  byte [rel chainload_m_check], 1
.done:
    pop  r12
    pop  rbx
    ret

; cl_put_hexdigit(AL low nibble) — one hex char to serial. clobbers RAX,RDI(,serial).
cl_put_hexdigit:
    and  eax, 0x0F
    cmp  eax, 10
    jb   .num
    add  eax, 'A' - 10 - '0'
.num:
    add  eax, '0'
    mov  [rel cl_digit], al
    lea  rdi, [rel cl_digit]
    call serial_string
    ret

; ---------------------------------------------------------------------------
; chainload_windows_orig — device-path LoadImage + StartImage of the REAL
;   Windows loader. Ported from monolith chainload_windows (paos.asm:139631):
;   HandleProtocol(LoadedImage) -> our DeviceHandle -> HandleProtocol(DevicePath)
;   -> measure -> composite [base dp][FilePath node][END] -> LoadImage(BootPolicy
;   =TRUE) -> StartImage. Tries bootmgfw_orig.efi then BOOTMGR.EFI. Returns only
;   if every path failed. clobbers: caller-saved + rbx/r12/r13/r14 (saved).
; ---------------------------------------------------------------------------
chainload_windows_orig:
    push rbx
    push r12
    push r13                          ; UCS-2 path ptr
    push r14                          ; UCS-2 path byte length
    sub  rsp, 32                      ; shadow (4 pushes + call -> RSP ≡ 0 mod 16)

    call chainload_dp_resolve         ; base device path -> cl_device_dp/_len
    test rax, rax
    jnz  .fail

    lea  r13, [rel cl_ucs2_orig_path]
    mov  r14d, (cl_ucs2_orig_path_end - cl_ucs2_orig_path)
    lea  rdi, [rel str_cl_try_orig]
    call chainload_try_path           ; returns only if this path failed
    lea  r13, [rel cl_ucs2_bootmgr_path]
    mov  r14d, (cl_ucs2_bootmgr_path_end - cl_ucs2_bootmgr_path)
    lea  rdi, [rel str_cl_try_bootmgr]
    call chainload_try_path
.fail:
    add  rsp, 32
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; chainload_vault_baseline — 1273/P56: boot the signed, never-written Vault
;   baseline (the A/B design's known-good PaOS). Same LoadImage/StartImage
;   idiom as chainload_windows_orig; returns only if the path failed to load,
;   so the caller can fall through to its next rung.
;
;   The Vault is immutable by invariant I4, which is exactly what makes it the
;   right escalation target: it is the one PaOS image on the ESP that a bad
;   update cannot have corrupted.
; ---------------------------------------------------------------------------
chainload_vault_baseline:
    push rbx
    push r12
    push r13                          ; UCS-2 path ptr
    push r14                          ; UCS-2 path byte length
    sub  rsp, 32                      ; shadow (4 pushes + call -> RSP = 0 mod 16)

    call chainload_dp_resolve         ; base device path -> cl_device_dp/_len
    test rax, rax
    jnz  .fail

    lea  r13, [rel cl_ucs2_vault_path]
    mov  r14d, (cl_ucs2_vault_path_end - cl_ucs2_vault_path)
    lea  rdi, [rel str_cl_try_vault]
    call chainload_try_path           ; returns only if this path failed
.fail:
    add  rsp, 32
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Require EFI_NOT_FOUND for BootNext.  A present value, BUFFER_TOO_SMALL, or
; any other runtime-service error is foreign/unknown authority and is left
; byte-for-byte untouched.
chainload_manager_require_bootnext_absent:
    push rbx
    sub  rsp, 32
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .variable_fail
    mov  qword [rel cl_manager_var_size], 2
    lea  rcx, [rel cl_linux_bootnext_name]
    lea  rdx, [rel cl_efi_global_guid]
    lea  r8,  [rel cl_manager_var_attrs]
    lea  r9,  [rel cl_manager_var_size]
    sub  rsp, 48
    lea  rbx, [rel cl_manager_bootnext_readback]
    mov  [rsp + 32], rbx
    mov  rax, [rel runtime_services]
    call [rax + 0x48]                 ; GetVariable(BootNext)
    add  rsp, 48
    mov  rdx, CL_EFI_NOT_FOUND
    cmp  rax, rdx
    je   .absent
    mov  byte [rel cl_manager_fail_rc], 4
    mov  eax, 1
    jmp  .out
.variable_fail:
    mov  byte [rel cl_manager_fail_rc], 1
    mov  eax, 1
    jmp  .out
.absent:
    xor  eax, eax
.out:
    add  rsp, 32
    pop  rbx
    ret

; A failed/mismatched readback is not deleted here: after the sole write, an
; observed different value is foreign concurrent authority and must remain
; untouched. The outer transaction's next live audit reconciles an unreadable
; outcome without guessing ownership.
chainload_manager_set_bootnext_verified:
    push rbx
    sub  rsp, 32
    cmp  byte [rel pbm_try_media], 1  ; live Try media: BootNext is persistent NV, refuse
    je   .fail
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .fail
    lea  rcx, [rel cl_linux_bootnext_name]
    lea  rdx, [rel cl_efi_global_guid]
    mov  r8d, 0x07                   ; NV | BOOTSERVICE | RUNTIME
    mov  r9d, 2
    sub  rsp, 48
    lea  rbx, [rel cl_manager_selected_boot]
    mov  [rsp + 32], rbx
    mov  rax, [rel runtime_services]
    call [rax + 0x58]                 ; the sole owned SetVariable
    add  rsp, 48
    test rax, rax
    jnz  .fail

    mov  qword [rel cl_manager_var_size], 2
    mov  word [rel cl_manager_bootnext_readback], 0xFFFF
    lea  rcx, [rel cl_linux_bootnext_name]
    lea  rdx, [rel cl_efi_global_guid]
    lea  r8,  [rel cl_manager_var_attrs]
    lea  r9,  [rel cl_manager_var_size]
    sub  rsp, 48
    lea  rbx, [rel cl_manager_bootnext_readback]
    mov  [rsp + 32], rbx
    mov  rax, [rel runtime_services]
    call [rax + 0x48]
    add  rsp, 48
    test rax, rax
    jnz  .fail
    cmp  qword [rel cl_manager_var_size], 2
    jne  .fail
    movzx eax, word [rel cl_manager_bootnext_readback]
    cmp  ax, [rel cl_manager_selected_boot]
    jne  .fail
    mov  byte [rel cl_manager_bootnext_armed], 1
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, 1
.out:
    add  rsp, 32
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; chainload_linux_orig — 1015/1124a5 external-Linux leg.
;
; The old implementation appended an Ubuntu filename to PaOS's NVMe device
; path, which can never reach the SATA ESP. The first 1124a5 candidate instead
; passed a short-form cross-volume path to LoadImage; real Lenovo firmware
; returned to PaOS. Use the mechanism already proven by Classic on this exact
; machine: resolve the live Ubuntu Boot#### option, retain and validate its
; complete device path, arm that DYNAMIC option as BootNext, verify read-back,
; and warm-reset so firmware's own Boot Manager consumes the option. The menu
; already cleared CMOS 0x76 before entering here, so Linux remains one-shot and
; its ordinary reboot returns to direct PaOS. Missing, malformed, ambiguous,
; unwriteable, or unverified authority fails open without changing BootOrder.
; ---------------------------------------------------------------------------
chainload_linux_orig:
    push rbx
    sub  rsp, 32

    call chainload_linux_volume_resolve
    test rax, rax
    jnz  .resolve_fail
    call chainload_linux_emit_resolution
    call chainload_linux_set_bootnext_verified
    test rax, rax
    jnz  .bootnext_fail
    lea  rdi, [rel str_cl_linux_bootnext_ok]
    call serial_string
    call chainload_linux_reset_warm   ; does not return when either reset works
    mov  byte [rel cl_linux_fail_rc], 5
    lea  rdi, [rel str_cl_linux_reset_fail]
    call serial_string
    jmp  .fail
.resolve_fail:
    cmp  byte [rel cl_linux_fail_rc], 3
    je   .ambiguous
    cmp  byte [rel cl_linux_fail_rc], 6
    je   .malformed
    cmp  byte [rel cl_linux_fail_rc], 1
    je   .variable_fail
    lea  rdi, [rel str_cl_linux_absent]
    call serial_string
    jmp  .fail
.ambiguous:
    lea  rdi, [rel str_cl_linux_ambiguous]
    call serial_string
    jmp  .fail
.malformed:
    lea  rdi, [rel str_cl_linux_malformed]
    call serial_string
    jmp  .fail
.variable_fail:
    lea  rdi, [rel str_cl_linux_varfail]
    call serial_string
    jmp  .fail
.bootnext_fail:
    mov  byte [rel cl_linux_fail_rc], 4
    lea  rdi, [rel str_cl_linux_bootnext_fail]
    call serial_string
.fail:
    add  rsp, 32
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; chainload_linux_volume_resolve — bounded dynamic Boot#### resolver.
;
; Every candidate must be ACTIVE, have the exact case-insensitive vendor label
; "ubuntu", contain one valid HardDrive media node followed by one exact final
; FilePath node for \EFI\ubuntu\{shimx64,grubx64}.efi, and end in END_ENTIRE.
; The COMPLETE FilePathList is retained. Multiple entries of either kind are
; ambiguous. A normal shim+grub pair is allowed only when both carry the exact
; same HardDrive node; shim is then selected, preserving the established signed
; path preference. RAX=0 success, nonzero fail-open. Callee-saved preserved.
; ---------------------------------------------------------------------------
chainload_linux_volume_resolve:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32

    call chainload_linux_candidates_reset
    mov  byte [rel cl_linux_live_attempted], 1
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .variable_fail

    mov  qword [rel cl_linux_var_size], CL_LINUX_BOOTORDER_MAX
    lea  rcx, [rel cl_linux_bootorder_name]
    lea  rdx, [rel cl_efi_global_guid]
    lea  r8,  [rel cl_linux_var_attrs]
    lea  r9,  [rel cl_linux_var_size]
    sub  rsp, 48
    lea  rbx, [rel cl_linux_bootorder_buf]
    mov  [rsp + 32], rbx
    mov  rax, [rel runtime_services]
    call [rax + 0x48]                 ; EFI_RUNTIME_SERVICES.GetVariable
    add  rsp, 48
    test rax, rax
    jnz  .variable_fail

    mov  r12, [rel cl_linux_var_size]
    test r12, r12
    jz   .no_match
    cmp  r12, CL_LINUX_BOOTORDER_MAX
    ja   .variable_fail
    test r12b, 1                     ; UINT16 array must be even-sized
    jnz  .variable_fail
    shr  r12, 1
    xor  r13d, r13d
.entry_loop:
    cmp  r13, r12
    jae  .finish
    lea  rax, [rel cl_linux_bootorder_buf]
    mov  rcx, r13
    add  rcx, rcx
    add  rax, rcx
    movzx r14d, word [rax]

    ; Build L"BootXXXX" from the live option number (M13: never remembered).
    lea  rbx, [rel cl_linux_boot_name + 8]
    mov  eax, r14d
    shr  eax, 12
    call cl_linux_hex_ucs2
    mov  [rbx], ax
    mov  eax, r14d
    shr  eax, 8
    call cl_linux_hex_ucs2
    mov  [rbx + 2], ax
    mov  eax, r14d
    shr  eax, 4
    call cl_linux_hex_ucs2
    mov  [rbx + 4], ax
    mov  eax, r14d
    call cl_linux_hex_ucs2
    mov  [rbx + 6], ax

    mov  qword [rel cl_linux_var_size], CL_LINUX_LOADOPT_MAX
    lea  rcx, [rel cl_linux_boot_name]
    lea  rdx, [rel cl_efi_global_guid]
    lea  r8,  [rel cl_linux_var_attrs]
    lea  r9,  [rel cl_linux_var_size]
    sub  rsp, 48
    lea  rbx, [rel cl_linux_loadopt_buf]
    mov  [rsp + 32], rbx
    mov  rax, [rel runtime_services]
    call [rax + 0x48]
    add  rsp, 48
    test rax, rax
    ; A listed option that cannot be read (including BUFFER_TOO_SMALL) is
    ; unknown authority, not permission to choose a different volume. Refuse
    ; the transition instead of silently hiding a malformed/oversized peer.
    jnz  .variable_fail
    mov  rsi, [rel cl_linux_var_size]
    lea  rdi, [rel cl_linux_loadopt_buf]
    mov  edx, r14d
    call chainload_linux_consider_loadopt
.next_entry:
    inc  r13
    jmp  .entry_loop
.finish:
    call chainload_linux_candidates_finish
    jmp  .out
.no_match:
    mov  byte [rel cl_linux_fail_rc], 2
    mov  eax, 1
    jmp  .out
.variable_fail:
    mov  byte [rel cl_linux_fail_rc], 1
    mov  eax, 1
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; AL=nibble -> AX=uppercase UCS-2 hex character.
cl_linux_hex_ucs2:
    and  eax, 0x0F
    cmp  al, 10
    jb   .digit
    add  al, 'A' - 10
    movzx eax, al
    ret
.digit:
    add  al, '0'
    movzx eax, al
    ret

chainload_linux_candidates_reset:
    mov  byte [rel cl_linux_shim_count], 0
    mov  byte [rel cl_linux_grub_count], 0
    mov  byte [rel cl_linux_invalid_count], 0
    mov  byte [rel cl_linux_fail_rc], 0
    mov  byte [rel cl_linux_selected_kind], 0
    mov  word [rel cl_linux_selected_boot], 0
    mov  dword [rel cl_linux_dp_len], 0
    mov  byte [rel cl_linux_bootnext_armed], 0
    ret

; RDI=EFI_LOAD_OPTION, RSI=returned bytes, EDX=live Boot####.
; EAX=0 reject/ignore, 1 shim, 2 grub. The first candidate of each kind is
; copied whole; later candidates increment the count so finalize must refuse.
chainload_linux_consider_loadopt:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  r12, rdi                    ; blob base
    mov  r13, rdi
    add  r13, rsi                    ; blob end
    mov  ebx, edx                    ; dynamic Boot####
    xor  eax, eax

    cmp  byte [rel cl_linux_target_mode], 1
    je   .windows_description
    cmp  rsi, 20                    ; header + exact L"ubuntu" + NUL
    jb   .ignore
    test dword [r12], 1             ; LOAD_OPTION_ACTIVE
    jz   .ignore
    movzx eax, word [r12 + 6]
    or   al, 0x20
    cmp  ax, 'u'
    jne  .ignore
    movzx eax, word [r12 + 8]
    or   al, 0x20
    cmp  ax, 'b'
    jne  .ignore
    movzx eax, word [r12 + 10]
    or   al, 0x20
    cmp  ax, 'u'
    jne  .ignore
    movzx eax, word [r12 + 12]
    or   al, 0x20
    cmp  ax, 'n'
    jne  .ignore
    movzx eax, word [r12 + 14]
    or   al, 0x20
    cmp  ax, 't'
    jne  .ignore
    movzx eax, word [r12 + 16]
    or   al, 0x20
    cmp  ax, 'u'
    jne  .ignore
    cmp  word [r12 + 18], 0
    jne  .ignore
    lea  r14, [r12 + 20]
    jmp  .description_ready
.windows_description:
    cmp  rsi, 6 + CL_WINDOWS_DESC_BYTES
    jb   .ignore
    test dword [r12], 1
    jz   .ignore
    lea  rdi, [r12 + 6]
    lea  rsi, [rel cl_ucs2_windows_description]
    mov  ecx, CL_WINDOWS_DESC_BYTES / 2
    cld
    repe cmpsw
    jne  .ignore
    lea  r14, [r12 + 6 + CL_WINDOWS_DESC_BYTES]
.description_ready:
    movzx ecx, word [r12 + 4]       ; FilePathListLength
    test ecx, ecx
    jz   .reject
    cmp  ecx, CL_LINUX_DP_MAX
    ja   .reject
    mov  r15, r14
    add  r15, rcx
    cmp  r15, r13
    ja   .reject

    xor  r8d, r8d                   ; HardDrive offset + 1
    xor  r9d, r9d                   ; exact path kind
    mov  rdi, r14
.node_loop:
    lea  rax, [rdi + 4]
    cmp  rax, r15
    ja   .reject
    movzx ecx, word [rdi + 2]
    cmp  ecx, 4
    jb   .reject
    mov  rax, rdi
    add  rax, rcx
    cmp  rax, r15
    ja   .reject
    movzx edx, byte [rdi]
    cmp  dl, 0x7F
    je   .end_node
    test r9d, r9d
    jnz  .reject                     ; filename must be final non-END node
    cmp  dl, 0x04
    jne  .next_node
    cmp  byte [rdi + 1], 0x01
    je   .harddrive_node
    cmp  byte [rdi + 1], 0x04
    je   .filepath_node
    jmp  .next_node
.harddrive_node:
    cmp  ecx, 42                    ; UEFI HARDDRIVE_DEVICE_PATH
    jne  .reject
    test r8d, r8d
    jnz  .reject
    cmp  byte [rel cl_linux_target_mode], 1
    jne  .hd_offset
    cmp  dword [rdi + 4], 0         ; nonzero partition number
    je   .reject
    cmp  byte [rdi + 40], 2         ; GPT partition signature
    jne  .reject
    cmp  byte [rdi + 41], 2         ; GUID signature type
    jne  .reject
.hd_offset:
    mov  r8, rdi
    sub  r8, r14
    inc  r8d
    jmp  .next_node
.filepath_node:
    test r8d, r8d
    jz   .reject
    cmp  byte [rel cl_linux_target_mode], 1
    je   .windows_filepath
    cmp  ecx, CL_LINUX_FILE_NODE_LEN
    jne  .reject
    mov  r11, rdi
    lea  rdi, [rdi + 4]
    call cl_linux_exact_path_kind
    mov  rdi, r11
    test eax, eax
    jz   .reject
    mov  r9d, eax
    jmp  .next_node
.windows_filepath:
    cmp  ecx, CL_WINDOWS_FILE_NODE_LEN
    jne  .reject
    mov  r11, rdi
    lea  rdi, [rdi + 4]
    call cl_windows_exact_path
    mov  rdi, r11
    test eax, eax
    jz   .reject
    mov  r9d, 1                     ; reuse the unique selected-path slot
.next_node:
    movzx ecx, word [rdi + 2]
    add  rdi, rcx
    jmp  .node_loop
.end_node:
    cmp  byte [rdi + 1], 0xFF
    jne  .reject
    cmp  ecx, 4
    jne  .reject
    add  rdi, 4
    cmp  rdi, r15
    jne  .reject
    test r8d, r8d
    jz   .reject
    test r9d, r9d
    jz   .reject

    mov  ecx, r15d
    sub  ecx, r14d
    cmp  r9d, 1
    je   .capture_shim
    inc  byte [rel cl_linux_grub_count]
    cmp  byte [rel cl_linux_grub_count], 1
    jne  .accepted
    mov  [rel cl_linux_grub_len], ecx
    mov  eax, r8d
    dec  eax
    mov  [rel cl_linux_grub_hd_off], eax
    mov  [rel cl_linux_grub_boot], bx
    mov  rsi, r14
    lea  rdi, [rel cl_linux_grub_dp]
    cld                              ; pre-EBS DF is not an authority
    rep  movsb
    jmp  .accepted
.capture_shim:
    inc  byte [rel cl_linux_shim_count]
    cmp  byte [rel cl_linux_shim_count], 1
    jne  .accepted
    mov  [rel cl_linux_shim_len], ecx
    mov  eax, r8d
    dec  eax
    mov  [rel cl_linux_shim_hd_off], eax
    mov  [rel cl_linux_shim_boot], bx
    mov  rsi, r14
    lea  rdi, [rel cl_linux_shim_dp]
    cld
    rep  movsb
.accepted:
    mov  eax, r9d
    jmp  .out
.reject:
    ; Once an active option has asserted the exact OS vendor authority,
    ; malformed/unknown device-path data must poison the whole selection. It
    ; cannot be silently skipped in favor of a more convenient peer.
    inc  byte [rel cl_linux_invalid_count]
.ignore:
    xor  eax, eax
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI -> exact 48-byte UCS-2 payload. EAX=1 shim, 2 grub, 0 no match.
cl_linux_exact_path_kind:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    mov  r8, rdi
    lea  rsi, [rel cl_ucs2_shim_path]
    mov  ecx, CL_LINUX_PATH_BYTES / 2
.shim_loop:
    movzx eax, word [rdi]
    movzx edx, word [rsi]
    cmp  ax, 'A'
    jb   .shim_a_folded
    cmp  ax, 'Z'
    ja   .shim_a_folded
    add  ax, 0x20
.shim_a_folded:
    cmp  dx, 'A'
    jb   .shim_b_folded
    cmp  dx, 'Z'
    ja   .shim_b_folded
    add  dx, 0x20
.shim_b_folded:
    cmp  ax, dx
    jne  .try_grub
    add  rdi, 2
    add  rsi, 2
    dec  ecx
    jnz  .shim_loop
    mov  eax, 1
    jmp  .done
.try_grub:
    mov  rdi, r8
    lea  rsi, [rel cl_ucs2_grub_path]
    mov  ecx, CL_LINUX_PATH_BYTES / 2
.grub_loop:
    movzx eax, word [rdi]
    movzx edx, word [rsi]
    cmp  ax, 'A'
    jb   .grub_a_folded
    cmp  ax, 'Z'
    ja   .grub_a_folded
    add  ax, 0x20
.grub_a_folded:
    cmp  dx, 'A'
    jb   .grub_b_folded
    cmp  dx, 'Z'
    ja   .grub_b_folded
    add  dx, 0x20
.grub_b_folded:
    cmp  ax, dx
    jne  .no
    add  rdi, 2
    add  rsi, 2
    dec  ecx
    jnz  .grub_loop
    mov  eax, 2
    jmp  .done
.no:
    xor  eax, eax
.done:
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; RDI -> exact Windows-owned FilePath payload, including UCS-2 NUL.
; The same bounded BootOrder/Boot#### parser owns identity and ambiguity for both
; Linux and Windows; this comparison never accepts a PaOS slot as Windows.
cl_windows_exact_path:
    push rcx
    push rdx
    push rsi
    push rdi
    lea  rsi, [rel cl_ucs2_windows_path]
    mov  ecx, CL_WINDOWS_PATH_BYTES / 2
.loop:
    movzx eax, word [rdi]
    movzx edx, word [rsi]
    cmp  ax, 'A'
    jb   .a_folded
    cmp  ax, 'Z'
    ja   .a_folded
    add  ax, 0x20
.a_folded:
    cmp  dx, 'A'
    jb   .b_folded
    cmp  dx, 'Z'
    ja   .b_folded
    add  dx, 0x20
.b_folded:
    cmp  ax, dx
    jne  .no
    add  rdi, 2
    add  rsi, 2
    dec  ecx
    jnz  .loop
    mov  eax, 1
    jmp  .done
.no:
    xor  eax, eax
.done:
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    ret

; Refuse duplicates, bind a shim+grub pair to one exact HD node, prefer shim,
; and copy the complete selected FilePathList to a stable buffer.
chainload_linux_candidates_finish:
    cmp  byte [rel cl_linux_invalid_count], 0
    jne  .malformed
    cmp  byte [rel cl_linux_shim_count], 1
    ja   .ambiguous
    cmp  byte [rel cl_linux_grub_count], 1
    ja   .ambiguous
    cmp  byte [rel cl_linux_shim_count], 1
    jne  .grub_only
    cmp  byte [rel cl_linux_grub_count], 1
    jne  .source_shim
    lea  rsi, [rel cl_linux_shim_dp]
    mov  eax, [rel cl_linux_shim_hd_off]
    add  rsi, rax
    lea  rdi, [rel cl_linux_grub_dp]
    mov  eax, [rel cl_linux_grub_hd_off]
    add  rdi, rax
    mov  ecx, 42
    cld
    repe cmpsb
    jne  .ambiguous
.source_shim:
    lea  rsi, [rel cl_linux_shim_dp]
    mov  ecx, [rel cl_linux_shim_len]
    movzx r11d, word [rel cl_linux_shim_boot]
    mov  byte [rel cl_linux_selected_kind], 1
    jmp  .select
.grub_only:
    cmp  byte [rel cl_linux_grub_count], 1
    jne  .missing
    lea  rsi, [rel cl_linux_grub_dp]
    mov  ecx, [rel cl_linux_grub_len]
    movzx r11d, word [rel cl_linux_grub_boot]
    mov  byte [rel cl_linux_selected_kind], 2
.select:
    mov  [rel cl_linux_dp_len], ecx
    mov  [rel cl_linux_selected_boot], r11w
    lea  rdi, [rel cl_linux_selected_dp]
    cld
    rep  movsb
    mov  byte [rel cl_linux_fail_rc], 0
    xor  eax, eax
    ret
.ambiguous:
    mov  byte [rel cl_linux_fail_rc], 3
    mov  eax, 1
    ret
.malformed:
    mov  byte [rel cl_linux_fail_rc], 6
    mov  eax, 1
    ret
.missing:
    mov  byte [rel cl_linux_fail_rc], 2
    mov  eax, 1
    ret

; Port of Classic's proven SetVariable(BootNext), strengthened with immediate
; GetVariable read-back. BootOrder is never touched. On mismatch, delete the
; one-shot so fail-open cannot leave a surprising future transition armed.
chainload_linux_set_bootnext_verified:
    push rbx
    sub  rsp, 32
    cmp  byte [rel pbm_try_media], 1  ; live Try media: BootNext is persistent NV, refuse
    je   .fail
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .fail
    lea  rcx, [rel cl_linux_bootnext_name]
    lea  rdx, [rel cl_efi_global_guid]
    mov  r8d, 0x07                   ; NV | BOOTSERVICE | RUNTIME
    mov  r9d, 2
    sub  rsp, 48
    lea  rbx, [rel cl_linux_selected_boot]
    mov  [rsp + 32], rbx
    mov  rax, [rel runtime_services]
    call [rax + 0x58]                ; SetVariable
    add  rsp, 48
    test rax, rax
    jnz  .fail

    mov  qword [rel cl_linux_var_size], 2
    mov  word [rel cl_linux_bootnext_readback], 0xFFFF
    lea  rcx, [rel cl_linux_bootnext_name]
    lea  rdx, [rel cl_efi_global_guid]
    lea  r8,  [rel cl_linux_var_attrs]
    lea  r9,  [rel cl_linux_var_size]
    sub  rsp, 48
    lea  rbx, [rel cl_linux_bootnext_readback]
    mov  [rsp + 32], rbx
    mov  rax, [rel runtime_services]
    call [rax + 0x48]                ; GetVariable
    add  rsp, 48
    test rax, rax
    jnz  .clear_fail
    cmp  qword [rel cl_linux_var_size], 2
    jne  .clear_fail
    movzx eax, word [rel cl_linux_bootnext_readback]
    cmp  ax, [rel cl_linux_selected_boot]
    jne  .clear_fail
    mov  byte [rel cl_linux_bootnext_armed], 1
    xor  eax, eax
    jmp  .out
.clear_fail:
    call chainload_linux_clear_bootnext
.fail:
    mov  eax, 1
.out:
    add  rsp, 32
    pop  rbx
    ret

; chainload_linux_arm_bootnext — resolve ubuntu + set BootNext, NO reset. For the
;   post-EBS BOOT LINUX verb on the mutable v2 chain (runtime mapped): arm the
;   firmware one-shot so the deferred warm reset lands on ubuntu, bypassing the
;   Manager's A/B pending-attempt state. RAX=0 armed, nonzero fail-open.
chainload_linux_arm_bootnext:
    push rbx
    sub  rsp, 32
    call chainload_linux_volume_resolve
    test rax, rax
    jnz  .fail
    call chainload_linux_set_bootnext_verified   ; RAX=0 ok
    jmp  .out
.fail:
    mov  eax, 1
.out:
    add  rsp, 32
    pop  rbx
    ret

; One target-neutral Windows BootNext. The same bounded BootOrder/Boot####
; parser used by Linux selects exactly one active Windows-owned bootmgfw path;
; no machine GUID, Boot#### number or loader bytes are compiled into PaOS.
; A present/unknown BootNext refuses before writing. The Manager's generic
; setter writes once and verifies exact UINT16 readback without deleting a
; foreign/uncertain value on failure. No legacy CMOS 0x76 request is staged.
chainload_windows_arm_bootnext:
    push rbx
    sub  rsp, 32
    mov  byte [rel cl_windows_fail_rc], 0
    call chainload_manager_require_bootnext_absent
    test eax, eax
    jnz  .foreign
    mov  byte [rel cl_linux_target_mode], 1
    call chainload_linux_volume_resolve
    mov  byte [rel cl_linux_target_mode], 0
    test eax, eax
    jnz  .resolve
    mov  ax, [rel cl_linux_selected_boot]
    mov  [rel cl_manager_selected_boot], ax
    call chainload_manager_set_bootnext_verified
    test eax, eax
    jnz  .uncertain
    xor  eax, eax
    jmp  .out
.foreign:
    mov  byte [rel cl_windows_fail_rc], 1
    jmp  .fail
.resolve:
    mov  byte [rel cl_windows_fail_rc], 2
    jmp  .fail
.uncertain:
    mov  byte [rel cl_windows_fail_rc], 3
.fail:
    mov  eax, 1
.out:
    add  rsp, 32
    pop  rbx
    ret

chainload_linux_clear_bootnext:
    push rbx
    sub  rsp, 32
    cmp  byte [rel pbm_try_media], 1  ; live Try media: no NV delete either
    je   .out
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .out
    lea  rcx, [rel cl_linux_bootnext_name]
    lea  rdx, [rel cl_efi_global_guid]
    xor  r8d, r8d
    xor  r9d, r9d
    sub  rsp, 48
    mov  qword [rsp + 32], 0
    mov  rax, [rel runtime_services]
    call [rax + 0x58]
    add  rsp, 48
.out:
    mov  byte [rel cl_linux_bootnext_armed], 0
    add  rsp, 32
    pop  rbx
    ret

; Prefer UEFI ResetSystem(EfiResetWarm); the already-proven CF9 warm reset is
; the bounded in-band fallback. If both return, disarm BootNext and fail open.
chainload_linux_reset_warm:
    push rbx
    sub  rsp, 32
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .cf9
    mov  ecx, 1                     ; EfiResetWarm
    xor  edx, edx                   ; EFI_SUCCESS
    xor  r8d, r8d
    xor  r9d, r9d
    call [rax + 0x68]               ; ResetSystem; success never returns
.cf9:
    mov  al, 0x06
    mov  dx, 0x0CF9
    out  dx, al
    mov  ecx, 0x100000              ; allow posted reset to take effect
.wait_reset:
    pause
    dec  ecx
    jnz  .wait_reset
    call chainload_linux_clear_bootnext
    mov  eax, 1
    add  rsp, 32
    pop  rbx
    ret

; Deterministic two-ESP KAT over the SAME live parser/finalizer. The PaOS ESP
; is ignored, the renumbered SATA shim wins over its same-volume grub peer,
; malformed/absent data is rejected, and a duplicate volume is ambiguous.
chainload_linux_fixture_kat:
    push rbx
    sub  rsp, 32
    call chainload_linux_candidates_reset
    lea  rdi, [rel cl_linux_fixture_paos]
    mov  esi, cl_linux_fixture_paos.end - cl_linux_fixture_paos
    mov  edx, 0xA001
    call chainload_linux_consider_loadopt
    test eax, eax
    jnz  .fail
    lea  rdi, [rel cl_linux_fixture_sata_grub]
    mov  esi, cl_linux_fixture_sata_grub.end - cl_linux_fixture_sata_grub
    mov  edx, 0xD010
    call chainload_linux_consider_loadopt
    cmp  eax, 2
    jne  .fail
    lea  rdi, [rel cl_linux_fixture_sata]
    mov  esi, cl_linux_fixture_sata.end - cl_linux_fixture_sata
    mov  edx, 0xB011
    call chainload_linux_consider_loadopt
    cmp  eax, 1
    jne  .fail
    call chainload_linux_candidates_finish
    test eax, eax
    jnz  .fail
    cmp  word [rel cl_linux_selected_boot], 0xB011
    jne  .fail
    cmp  byte [rel cl_linux_selected_kind], 1
    jne  .fail
    cmp  dword [rel cl_linux_selected_dp + 24], 0xB2B2B2B2
    jne  .fail
    cmp  dword [rel cl_linux_dp_len], 98
    jne  .fail

    ; Shim absent: preserve the established direct-grub fallback policy.
    call chainload_linux_candidates_reset
    lea  rdi, [rel cl_linux_fixture_sata_grub]
    mov  esi, cl_linux_fixture_sata_grub.end - cl_linux_fixture_sata_grub
    mov  edx, 0xD010
    call chainload_linux_consider_loadopt
    call chainload_linux_candidates_finish
    test eax, eax
    jnz  .fail
    cmp  word [rel cl_linux_selected_boot], 0xD010
    jne  .fail
    cmp  byte [rel cl_linux_selected_kind], 2
    jne  .fail

    call chainload_linux_candidates_reset
    lea  rdi, [rel cl_linux_fixture_malformed]
    mov  esi, cl_linux_fixture_malformed.end - cl_linux_fixture_malformed
    mov  edx, 0xBADC
    call chainload_linux_consider_loadopt
    test eax, eax
    jnz  .fail
    call chainload_linux_candidates_finish
    test eax, eax
    jz   .fail
    cmp  byte [rel cl_linux_fail_rc], 6
    jne  .fail

    call chainload_linux_candidates_reset
    lea  rdi, [rel cl_linux_fixture_sata]
    mov  esi, cl_linux_fixture_sata.end - cl_linux_fixture_sata
    mov  edx, 0xB011
    call chainload_linux_consider_loadopt
    lea  rdi, [rel cl_linux_fixture_sata2]
    mov  esi, cl_linux_fixture_sata2.end - cl_linux_fixture_sata2
    mov  edx, 0xC012
    call chainload_linux_consider_loadopt
    call chainload_linux_candidates_finish
    test eax, eax
    jz   .fail
    cmp  byte [rel cl_linux_fail_rc], 3
    jne  .fail

    call chainload_linux_candidates_reset
    call chainload_linux_candidates_finish
    test eax, eax
    jz   .fail
    cmp  byte [rel cl_linux_fail_rc], 2
    jne  .fail
    call chainload_linux_candidates_reset
    xor  eax, eax
    jmp  .out
.fail:
    call chainload_linux_candidates_reset
    mov  eax, 1
.out:
    add  rsp, 32
    pop  rbx
    ret

chainload_linux_resolver_selftest:
    push rbx
    sub  rsp, 32
    mov  byte [rel cl_linux_selftest_ok], 0
    call chainload_linux_fixture_kat
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_cl_linux_target_kat]
    call serial_string
    lea  rdi, [rel str_cl_linux_cross_kat]
    call serial_string
    mov  byte [rel cl_linux_selftest_ok], 1
    jmp  .out
.fail:
    lea  rdi, [rel str_cl_linux_kat_fail]
    call serial_string
.out:
    add  rsp, 32
    pop  rbx
    ret

chainload_linux_emit_resolution:
    push rbx
    sub  rsp, 32
    lea  rdi, [rel str_cl_linux_live_pre]
    call serial_string
    movzx ebx, word [rel cl_linux_selected_boot]
    mov  eax, ebx
    shr  eax, 12
    call cl_put_hexdigit
    mov  eax, ebx
    shr  eax, 8
    call cl_put_hexdigit
    mov  eax, ebx
    shr  eax, 4
    call cl_put_hexdigit
    mov  eax, ebx
    call cl_put_hexdigit
    lea  rdi, [rel str_cl_linux_live_len]
    call serial_string
    mov  ebx, [rel cl_linux_dp_len]
    mov  eax, ebx
    shr  eax, 12
    call cl_put_hexdigit
    mov  eax, ebx
    shr  eax, 8
    call cl_put_hexdigit
    mov  eax, ebx
    shr  eax, 4
    call cl_put_hexdigit
    mov  eax, ebx
    call cl_put_hexdigit
    lea  rdi, [rel str_cl_linux_live_post]
    call serial_string
    add  rsp, 32
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Bounded pre-EBS fallback only. UEFI 2.10 §§7.2.3,10.3.1: an End Instance
; (7f/01/4) continues the path; only End Entire (7f/ff/4) completes it.
; Other node types are opaque. Each instance receives the FilePath append.
;
; The native fallback owns a 64-KiB base snapshot. Its actual extent bounds
; both the accepted base and composite, and implies <= capacity/4 nodes. This
; is an implementation capacity, not a UEFI limit. Oversized maps/paths refuse
; without changing BootOrder/BootNext, CMOS, secure boot or recovery policy.
; GetMemoryMap is read-only; its private snapshot never supplies an EBS key.
; ---------------------------------------------------------------------------
CL_DP_CAPACITY equ (cl_dp_base_end - cl_dp_base)
CL_DP_MAP_CAPACITY equ (cl_dp_map_end - cl_dp_map)

; Fresh bounded memory-map admission. A failed call retires the previous map.
; Firmware tables themselves are trusted EFI entry authority. Firmware-returned
; object pointers are not dereferenced until covered by this validated map.
chainload_dp_read_map:
    push rbx
    push rsi
    push rdi
    sub  rsp, 48
    mov  qword [rel cl_dp_map_count], 0
    mov  qword [rel cl_dp_map_size], CL_DP_MAP_CAPACITY
    mov  qword [rel cl_dp_map_stride], 0
    mov  dword [rel cl_dp_map_version], 0
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .fail
    cmp  qword [rax + 0x38], 0
    je   .fail
    lea  rcx, [rel cl_dp_map_size]
    lea  rdx, [rel cl_dp_map]
    lea  r8, [rel cl_dp_map_key]
    lea  r9, [rel cl_dp_map_stride]
    lea  rax, [rel cl_dp_map_version]
    mov  [rsp + 32], rax
    mov  rax, [rel boot_services]
    call [rax + 0x38]                 ; GetMemoryMap; no allocation/retry loop
    test rax, rax
    jnz  .fail
    cmp  dword [rel cl_dp_map_version], 1
    jne  .fail
    mov  rax, [rel cl_dp_map_size]
    test rax, rax
    jz   .fail
    cmp  rax, CL_DP_MAP_CAPACITY
    ja   .fail
    mov  rbx, [rel cl_dp_map_stride]
    cmp  rbx, 40                      ; complete EFI_MEMORY_DESCRIPTOR v1 prefix
    jb   .fail
    xor  edx, edx
    div  rbx
    test rdx, rdx
    jnz  .fail
    test rax, rax
    jz   .fail
    mov  r11, rax
    lea  rsi, [rel cl_dp_map]
    xor  edi, edi
.desc:
    mov  r8, [rsi + 8]                ; PhysicalStart
    test r8, 4095
    jnz  .fail
    mov  r9, [rsi + 24]               ; NumberOfPages (full width)
    test r9, r9
    jz   .fail
    mov  rax, r9
    shr  rax, 52
    jnz  .fail
    shl  r9, 12
    add  r9, r8
    jc   .fail
    ; No ambiguous overlapping ranges, including reserved/MMIO descriptors.
    lea  rdx, [rel cl_dp_map]
    mov  rcx, rdi
.overlap:
    test rcx, rcx
    jz   .next
    mov  rax, [rdx + 24]
    shl  rax, 12
    add  rax, [rdx + 8]               ; earlier descriptor already validated
    cmp  r8, rax
    jae  .disjoint
    cmp  [rdx + 8], r9
    jb   .fail
.disjoint:
    add  rdx, rbx
    dec  rcx
    jmp  .overlap
.next:
    add  rsi, rbx
    inc  rdi
    cmp  rdi, r11
    jb   .desc
    mov  [rel cl_dp_map_count], r11    ; publish only after complete admission
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, 1
.out:
    add  rsp, 48
    pop  rdi
    pop  rsi
    pop  rbx
    ret

; RCX=address, RDX=nonzero extent. Full interval must be covered by ordinary
; pre-EBS RAM (Loader/Boot/Runtime code/data or conventional memory). Adjacent
; descriptors may cover it; holes, reserved/MMIO/unusable and RP refuse.
; R8D=0 read, 1 write (also refuse RO). No memory at RCX is read here.
; Low canonical identity addresses are the supported pre-virtual-map seam;
; never truncate a firmware pointer to 32 bits. Preserves all nonvolatile GPRs.
chainload_dp_range:
    test rcx, rcx
    jz   .fail
    test rdx, rdx
    jz   .fail
    add  rdx, rcx
    jc   .fail
    mov  rax, rdx
    dec  rax
    shr  rax, 47
    jnz  .fail
    mov  eax, 0x2000                 ; refuse possibly read-protected memory
    test r8d, r8d
    jz   .mask
    or   eax, 0x20000                ; write needs non-RO RAM too
.mask:
    mov  r8d, eax
.cover:
    mov  r9, [rel cl_dp_map_count]
    lea  r10, [rel cl_dp_map]
.scan:
    test r9, r9
    jz   .fail
    cmp  dword [r10], 1
    jb   .next
    cmp  dword [r10], 7
    ja   .next
    test [r10 + 32], r8
    jnz  .next
    cmp  rcx, [r10 + 8]
    jb   .next
    mov  r11, [r10 + 24]
    shl  r11, 12
    add  r11, [r10 + 8]
    cmp  rcx, r11
    jae  .next
    cmp  rdx, r11
    jbe  .ok
    mov  rcx, r11                    ; advance to adjacent covered RAM
    jmp  .cover
.next:
    add  r10, [rel cl_dp_map_stride]
    dec  r9
    jmp  .scan
.ok:
    xor  eax, eax
    ret
.fail:
    mov  eax, 1
    ret

; RAX..RDX destination versus RCX..R8 protected interval (half-open).
chainload_dp_disjoint:
    cmp  rax, r8
    jae  .ok
    cmp  rdx, rcx
    jbe  .ok
    mov  eax, 1
    ret
.ok:
    xor  eax, eax
    ret

; RSI=untrusted source, RDX=maximum complete extent (<= actual snapshot).
; Validate each header BEFORE reading it and each whole node BEFORE copying.
; RAX=status, EDX=complete bytes including End Entire, ECX=instance count.
; On failure no published base/length is installed; private scratch may change.
chainload_dp_capture:
    push rbx
    push rbp
    push r12
    push r14
    push r15
    sub  rsp, 48
    mov  r12, rsi
    mov  rbp, rdx
    xor  r15d, r15d
    xor  ebx, ebx
    mov  r14d, CL_DP_CAPACITY / 4     ; finite complete-header node budget
.node:
    test r14d, r14d
    jz   .fail
    dec  r14d
    mov  rax, r15
    add  rax, 4
    jc   .fail
    cmp  rax, rbp
    ja   .fail
    mov  rcx, r12
    mov  edx, 4
    xor  r8d, r8d
    call chainload_dp_range
    test rax, rax
    jnz  .fail
    movzx eax, word [r12 + 2]
    cmp  eax, 4
    jb   .fail
    mov  rdx, rax
    add  rax, r15
    jc   .fail
    cmp  rax, rbp
    ja   .fail
    mov  [rsp + 32], edx             ; cache the checked extent, never reread it
    mov  rcx, r12
    xor  r8d, r8d
    call chainload_dp_range
    test rax, rax
    jnz  .fail
    lea  rdi, [rel cl_dp_base]
    add  rdi, r15
    mov  rsi, r12
    mov  ecx, [rsp + 32]
    mov  edx, ecx
    add  r12, rdx                    ; range check already proved no wrap
    add  r15, rdx
    cld
    rep  movsb
    sub  rdi, rdx                    ; inspect the now-owned complete node
    cmp  [rdi + 2], dx               ; refuse an inconsistent copied header
    jne  .fail
    cmp  byte [rdi], 0x7f
    jne  .node
    cmp  edx, 4
    jne  .fail
    inc  ebx
    cmp  byte [rdi + 1], 1
    je   .node
    cmp  byte [rdi + 1], 0xff
    jne  .fail
    mov  edx, r15d
    mov  ecx, ebx
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, 1
.out:
    add  rsp, 48
    pop  r15
    pop  r14
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Resolve protocol pointers into a bounded OWNED base snapshot. Publication is
; retired before any attempt, including HandleProtocol/status/geometry failure.
chainload_dp_resolve:
    push rbp
    mov  rbp, rsp
    push rbx
    and  rsp, -16                    ; tolerate both native caller stack parities
    sub  rsp, 32
    mov  qword [rel cl_device_dp], 0
    mov  dword [rel cl_device_dp_len], 0
    mov  dword [rel cl_dp_instances], 0
    mov  qword [rel cl_loaded_image], 0
    mov  qword [rel cl_dp_protocol], 0
    cmp  byte [rel cl_linux_selftest_done], 1
    je   .linux_kat_done
    mov  byte [rel cl_linux_selftest_done], 1
    call chainload_linux_resolver_selftest
.linux_kat_done:
    call chainload_dp_read_map
    test rax, rax
    jnz  .fail
    mov  rax, [rel boot_services]
    cmp  qword [rax + 0x98], 0
    je   .fail
    mov  rcx, [rel image_handle]
    lea  rdx, [rel cl_loaded_image_guid]
    lea  r8, [rel cl_loaded_image]
    call [rax + 0x98]                 ; HandleProtocol(LoadedImage)
    test rax, rax
    jnz  .fail
    mov  rcx, [rel cl_loaded_image]
    mov  edx, 32                      ; includes DeviceHandle at offset 24
    xor  r8d, r8d
    call chainload_dp_range
    test rax, rax
    jnz  .fail
    mov  rax, [rel cl_loaded_image]
    mov  rcx, [rax + 24]
    test rcx, rcx
    jz   .fail
    mov  rax, [rel boot_services]
    lea  rdx, [rel cl_device_path_guid]
    lea  r8, [rel cl_dp_protocol]      ; never publish an unchecked firmware ptr
    call [rax + 0x98]
    test rax, rax
    jnz  .fail
    mov  rsi, [rel cl_dp_protocol]
    mov  edx, CL_DP_CAPACITY
    call chainload_dp_capture
    test rax, rax
    jnz  .fail
    lea  rax, [rel cl_dp_base]
    mov  [rel cl_device_dp], rax
    sub  edx, 4                       ; compatibility: excludes final End Entire
    mov  [rel cl_device_dp_len], edx
    mov  [rel cl_dp_instances], ecx
    xor  eax, eax
    jmp  .out
.fail:
    mov  qword [rel cl_loaded_image], 0
    mov  qword [rel cl_dp_protocol], 0
    mov  eax, 1
.out:
    lea  rsp, [rbp - 8]
    pop  rbx
    pop  rbp
    ret

; R13=UCS-2 NUL-terminated path, R14=FULL-WIDTH byte extent including NUL.
; Refusal precedes allocation and trap restoration. Revalidate saved state and
; append extent; composite length = full base + instances * (4 + path bytes).
; Every returned firmware call leaves the existing fallback caller free to try
; its next path. StartImage remains subject to firmware Secure Boot enforcement.
chainload_try_path:
    push rbx
    push rbp
    push r12
    push r15
    mov  r15, rsp
    and  rsp, -16                    ; firmware ABI belongs to this boundary
    sub  rsp, 48
    mov  [rsp + 32], rdi             ; preserve the caller's path banner
    mov  qword [rel cl_dp_buf], 0
    mov  qword [rel cl_image], 0
    mov  dword [rel cl_dp_size], 0
    lea  rax, [rel cl_dp_base]
    cmp  [rel cl_device_dp], rax
    jne  .refuse
    mov  ebp, [rel cl_device_dp_len]
    cmp  ebp, CL_DP_CAPACITY - 4
    ja   .refuse
    add  ebp, 4
    mov  r12d, [rel cl_dp_instances]
    test r12d, r12d
    jz   .refuse
    ; EFI FilePath node length is a UINT16; valid UCS-2 byte extents are even.
    cmp  r14, 2
    jb   .refuse
    cmp  r14, 65530
    ja   .refuse
    test r14b, 1
    jnz  .refuse
    mov  rax, r14
    add  rax, 4
    mul  r12                         ; full-width append product
    test rdx, rdx
    jnz  .refuse
    add  rax, rbp
    jc   .refuse
    cmp  rax, CL_DP_CAPACITY
    ja   .refuse
    mov  [rel cl_dp_size], eax
    call chainload_dp_read_map
    test rax, rax
    jnz  .refuse
    mov  rax, [rel boot_services]
    cmp  qword [rax + 0x40], 0
    je   .refuse
    cmp  qword [rax + 0x48], 0
    je   .refuse
    cmp  qword [rax + 0xc8], 0
    je   .refuse
    cmp  qword [rax + 0xd0], 0
    je   .refuse
    lea  rsi, [rel cl_dp_base]
    mov  rdx, rbp
    call chainload_dp_capture
    test rax, rax
    jnz  .refuse
    cmp  edx, ebp
    jne  .refuse
    cmp  ecx, r12d
    jne  .refuse
    mov  rcx, r13
    mov  rdx, r14
    xor  r8d, r8d
    call chainload_dp_range
    test rax, rax
    jnz  .refuse
    mov  rsi, r13
    mov  rcx, r14
    shr  rcx, 1
.string:
    dec  rcx
    jz   .nul
    cmp  word [rsi], 0                ; one complete string, no hidden suffix
    je   .refuse
    add  rsi, 2
    jmp  .string
.nul:
    cmp  word [rsi], 0
    jne  .refuse
    mov  rax, [rel boot_services]
    mov  ecx, 2                      ; EfiLoaderData
    mov  edx, [rel cl_dp_size]
    lea  r8, [rel cl_dp_buf]
    call [rax + 0x40]                 ; AllocatePool only after source admission
    test rax, rax
    jnz  .alloc_fail                  ; failed OUT parameter is undefined
    mov  rcx, [rel cl_dp_buf]
    mov  edx, [rel cl_dp_size]
    mov  r8d, 1
    call chainload_dp_range
    test rax, rax
    jnz  .pool_invalid                ; don't FreePool an invalid firmware ptr
    ; Allocation must not alias inputs or private admission state. The pool
    ; contract supplies ownership/size; checked RAM coverage supplies the
    ; address seam. Never consume an in-place overwrite as a validated path.
    mov  rax, [rel cl_dp_buf]
    mov  edx, [rel cl_dp_size]
    add  rdx, rax
    lea  rcx, [rel cl_dp_base]
    lea  r8, [rel cl_dp_base_end]
    call chainload_dp_disjoint
    test rax, rax
    jnz  .pool_invalid
    mov  rax, [rel cl_dp_buf]
    lea  rcx, [rel cl_loaded_image]
    lea  r8, [rel cl_dp_base_end]       ; includes private control/map/base scratch
    call chainload_dp_disjoint
    test rax, rax
    jnz  .pool_invalid
    mov  rax, [rel cl_dp_buf]
    mov  rcx, r13
    lea  r8, [r13 + r14]
    call chainload_dp_disjoint
    test rax, rax
    jnz  .pool_invalid
    mov  rdi, [rel cl_dp_buf]
    lea  rbx, [rel cl_dp_base]
    lea  r12, [rbx + rbp]
.compose:
    cmp  byte [rbx], 0x7f
    jne  .copy
    mov  byte [rdi], 4
    mov  byte [rdi + 1], 4
    lea  eax, [r14 + 4]
    mov  [rdi + 2], ax
    add  rdi, 4
    mov  rsi, r13
    mov  rcx, r14
    cld
    rep  movsb
.copy:
    movzx ecx, word [rbx + 2]
    mov  rsi, rbx
    add  rbx, rcx
    cld
    rep  movsb
    cmp  rbx, r12
    jb   .compose
    mov  rax, [rel cl_dp_buf]
    mov  edx, [rel cl_dp_size]
    add  rax, rdx
    cmp  rdi, rax                     ; actual cursor must equal admitted extent
    jne  .out_free
    ; Restore firmware fault gates only for a fully admitted composite. This
    ; retains the 1273a fix: foreign loaders never run under PaOS early traps.
    call early_trap_uninstall
    mov  rdi, [rsp + 32]
    call serial_string
    mov  rax, [rel boot_services]
    mov  ecx, 1                      ; BootPolicy=TRUE (existing policy)
    mov  rdx, [rel image_handle]
    mov  r8, [rel cl_dp_buf]
    xor  r9, r9
    sub  rsp, 48
    mov  qword [rsp + 32], 0
    lea  rbx, [rel cl_image]
    mov  [rsp + 40], rbx
    call [rax + 0xc8]                 ; LoadImage verifies per firmware policy
    add  rsp, 48
    test rax, rax
    jnz  .out_free
    cmp  qword [rel cl_image], 0
    je   .out_free
    lea  rdi, [rel str_cl_loaded]
    call serial_string
    mov  rax, [rel boot_services]
    mov  rcx, [rel cl_image]
    xor  edx, edx
    xor  r8d, r8d
    call [rax + 0xd0]                 ; StartImage; a real OS never returns
.out_free:
    mov  rcx, [rel cl_dp_buf]
    mov  rax, [rel boot_services]
    call [rax + 0x48]
.alloc_fail:
    mov  qword [rel cl_dp_buf], 0
    mov  qword [rel cl_image], 0
    mov  dword [rel cl_dp_size], 0
    mov  eax, 1
    jmp  .out
.pool_invalid:
    mov  qword [rel cl_dp_buf], 0
.refuse:
    mov  qword [rel cl_device_dp], 0
    mov  dword [rel cl_device_dp_len], 0
    mov  dword [rel cl_dp_instances], 0
    mov  dword [rel cl_dp_size], 0
    mov  eax, 1
.out:
    mov  rsp, r15
    pop  r15
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ---- data --------------------------------------------------------------------
chainload_m_check:  db 0              ; earned: escalate-check ran this boot (BOOTLOG)
cl_digit:           db 0, 0           ; 1-char serial_string scratch
align 8
cl_loaded_image:    dq 0
cl_device_dp:       dq 0
cl_dp_instances:    dd 0
cl_device_dp_len:   dd 0
cl_dp_size:         dd 0
cl_dp_buf:          dq 0
cl_image:           dq 0
cl_dp_protocol:     dq 0
cl_dp_map_count:    dq 0
cl_dp_map_size:     dq 0
cl_dp_map_stride:   dq 0
cl_dp_map_key:      dq 0
cl_dp_map_version:  dd 0
align 8
cl_dp_map:          times 65536 db 0
cl_dp_map_end:
cl_dp_base:         times 65536 db 0
cl_dp_base_end:

; 1124a5 live resolver state. Static data never embeds a symbol pointer.
align 8
cl_linux_var_attrs:       dq 0
cl_linux_var_size:        dq 0
cl_linux_dp_len:          dd 0
cl_linux_shim_len:        dd 0
cl_linux_shim_hd_off:     dd 0
cl_linux_grub_len:        dd 0
cl_linux_grub_hd_off:     dd 0
cl_linux_shim_boot:       dw 0
cl_linux_grub_boot:       dw 0
cl_linux_selected_boot:   dw 0
cl_linux_bootnext_readback: dw 0
cl_linux_shim_count:      db 0
cl_linux_grub_count:      db 0
cl_linux_invalid_count:   db 0
cl_linux_selected_kind:   db 0       ; 1=shim, 2=grub
cl_linux_target_mode:     db 0       ; 0=ubuntu, 1=Windows Boot Manager
cl_windows_fail_rc:       db 0       ; 1=foreign BootNext, 2=route, 3=write/readback uncertain
cl_linux_fail_rc:         db 0       ; 0 ok, 1 vars, 2 absent, 3 ambiguous, 4 BootNext, 5 reset, 6 malformed
cl_linux_selftest_done:   db 0
cl_linux_selftest_ok:     db 0
cl_linux_live_attempted:  db 0
cl_linux_bootnext_armed:  db 0
chainload_cmos_vendor:    db 0       ; 0 unknown, 1 GenuineIntel (CMOS I/O), 2 other (none)
align 8

cl_manager_var_size:         dq 0
cl_manager_var_attrs:        dq 0
cl_manager_selected_boot:    dw 0
cl_manager_bootnext_readback: dw 0
cl_manager_fail_rc:          db 0       ; 0 ok, 1 vars, 2 absent, 3 ambiguous, 4 foreign BootNext, 5 write/readback, 6 malformed
cl_manager_bootnext_armed:   db 0
align 8

cl_efi_global_guid:
    dd 0x8BE4DF61
    dw 0x93CA, 0x11D2
    db 0xAA,0x0D,0x00,0xE0,0x98,0x03,0x2B,0x8C
cl_linux_bootorder_name:
    dw 'B','o','o','t','O','r','d','e','r',0
cl_linux_boot_name:
    dw 'B','o','o','t',0,0,0,0,0
cl_linux_bootnext_name:
    dw 'B','o','o','t','N','e','x','t',0
align 8
cl_linux_bootorder_buf: times CL_LINUX_BOOTORDER_MAX db 0
cl_linux_loadopt_buf:   times CL_LINUX_LOADOPT_MAX db 0
cl_linux_shim_dp:       times CL_LINUX_DP_MAX db 0
cl_linux_grub_dp:       times CL_LINUX_DP_MAX db 0
cl_linux_selected_dp:   times CL_LINUX_DP_MAX db 0

; EFI_LOADED_IMAGE_PROTOCOL_GUID {5B1B31A1-9562-11D2-8E3F-00A0C969723B} (monolith)
align 8
cl_loaded_image_guid:
    dd 0x5B1B31A1
    dw 0x9562, 0x11D2
    db 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B
; EFI_DEVICE_PATH_PROTOCOL_GUID {09576E91-6D3F-11D2-8E39-00A0C969723B} (monolith)
cl_device_path_guid:
    dd 0x09576E91
    dw 0x6D3F, 0x11D2
    db 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B

cl_ucs2_orig_path:
    dw '\','E','F','I','\','M','i','c','r','o','s','o','f','t','\','B','o','o','t','\','b','o','o','t','m','g','f','w','_','o','r','i','g','.','e','f','i', 0
cl_ucs2_orig_path_end:
cl_ucs2_vault_path:
    dw '\','E','F','I','\','P','a','O','S','\','v','a','u','l','t','\'
    dw 'b','a','s','e','l','i','n','e','-','p','a','o','s','.','e','f','i', 0
cl_ucs2_vault_path_end:
cl_ucs2_bootmgr_path:
    dw '\','E','F','I','\','M','i','c','r','o','s','o','f','t','\','B','o','o','t','\','B','O','O','T','M','G','R','.','E','F','I', 0
cl_ucs2_bootmgr_path_end:
; 1015 Linux leg (SATA Ubuntu): shim (Secure Boot chain) first, then grub direct
cl_ucs2_shim_path:
    dw '\','E','F','I','\','u','b','u','n','t','u','\','s','h','i','m','x','6','4','.','e','f','i', 0
cl_ucs2_grub_path:
    dw '\','E','F','I','\','u','b','u','n','t','u','\','g','r','u','b','x','6','4','.','e','f','i', 0
cl_ucs2_windows_description:
    dw 'W','i','n','d','o','w','s',' ','B','o','o','t',' ','M','a','n','a','g','e','r',0
cl_ucs2_windows_path:
    dw '\','E','F','I','\','M','i','c','r','o','s','o','f','t','\','B','o','o','t','\','b','o','o','t','m','g','f','w','.','e','f','i',0
cl_linux_fixture_paos:
    dd 1
    dw 98
    dw 'P','a','O','S',0
    db 0x04,0x01
    dw 42
    dd 1
    dq 0x800,0x100000
    dd 0xA1A1A1A1,0xA1A1A1A1,0xA1A1A1A1,0xA1A1A1A1
    db 0x02,0x02
    db 0x04,0x04
    dw CL_LINUX_FILE_NODE_LEN
    dw '\','E','F','I','\','u','b','u','n','t','u','\','s','h','i','m','x','6','4','.','e','f','i',0
    db 0x7F,0xFF
    dw 4
.end:

cl_linux_fixture_sata:
    dd 1
    dw 98
    dw 'u','b','u','n','t','u',0
    db 0x04,0x01
    dw 42
    dd 1
    dq 0x800,0x219800
    dd 0xB2B2B2B2,0xB2B2B2B2,0xB2B2B2B2,0xB2B2B2B2
    db 0x02,0x02
    db 0x04,0x04
    dw CL_LINUX_FILE_NODE_LEN
    dw '\','E','F','I','\','u','b','u','n','t','u','\','s','h','i','m','x','6','4','.','e','f','i',0
    db 0x7F,0xFF
    dw 4
.end:

cl_linux_fixture_sata_grub:
    dd 1
    dw 98
    dw 'u','b','u','n','t','u',0
    db 0x04,0x01
    dw 42
    dd 1
    dq 0x800,0x219800
    dd 0xB2B2B2B2,0xB2B2B2B2,0xB2B2B2B2,0xB2B2B2B2
    db 0x02,0x02
    db 0x04,0x04
    dw CL_LINUX_FILE_NODE_LEN
    dw '\','E','F','I','\','u','b','u','n','t','u','\','g','r','u','b','x','6','4','.','e','f','i',0
    db 0x7F,0xFF
    dw 4
.end:

cl_linux_fixture_sata2:
    dd 1
    dw 98
    dw 'u','b','u','n','t','u',0
    db 0x04,0x01
    dw 42
    dd 1
    dq 0x800,0x319800
    dd 0xC3C3C3C3,0xC3C3C3C3,0xC3C3C3C3,0xC3C3C3C3
    db 0x02,0x02
    db 0x04,0x04
    dw CL_LINUX_FILE_NODE_LEN
    dw '\','E','F','I','\','u','b','u','n','t','u','\','s','h','i','m','x','6','4','.','e','f','i',0
    db 0x7F,0xFF
    dw 4
.end:

cl_linux_fixture_malformed:
    dd 1
    dw 7
    dw 'u','b','u','n','t','u',0
    db 0x04,0x04
    dw 3
    times 3 db 0
.end:

str_cl_chk_pre:   db "[PAOS64] P0 boot-canon escalate-check: trial=", 0
str_cl_chk_conf:  db " confirmed=0x", 0
str_cl_continue:  db " -> continue [boot.chainload.check]", 13, 10, 0
str_cl_escalate:  db " -> FALLBACK: unconfirmed keep exhausted its trials — trial reset + escalate to the verified Vault baseline, Windows as last rung [boot.chainload.escalate]", 13, 10, 0
str_cl_failopen:  db "[PAOS64] P0 boot-canon escalate: ALL Windows paths failed to load — fail-open, continuing PaOS boot", 13, 10, 0
str_cl_try_vault: db "[PAOS64] P0 chainload: trying the verified Vault baseline (EFI\PaOS\vault\baseline-paos.efi)...", 13, 10, 0
str_cl_vault_miss: db "[PAOS64] P0 boot-canon escalate: Vault baseline unloadable — falling through to the Windows loader [boot.escalate.vault_miss]", 13, 10, 0
str_cl_try_orig:  db "[PAOS64] P0 chainload: trying bootmgfw_orig.efi...", 13, 10, 0
str_cl_try_bootmgr: db "[PAOS64] P0 chainload: trying BOOTMGR.EFI...", 13, 10, 0
str_cl_try_shim:  db "[PAOS64] P0 chainload: trying \EFI\ubuntu\shimx64.efi...", 13, 10, 0
str_cl_try_grub:  db "[PAOS64] P0 chainload: trying \EFI\ubuntu\grubx64.efi...", 13, 10, 0
str_cl_linux_absent: db "[PAOS64] P0 Linux transition: no exact active ubuntu shim/grub option; fail-open to PaOS", 13, 10, 0
str_cl_linux_ambiguous: db "[PAOS64] P0 Linux transition: ambiguous Ubuntu options/volumes refused; fail-open to PaOS", 13, 10, 0
str_cl_linux_malformed: db "[PAOS64] P0 Linux transition: malformed active Ubuntu authority refused; fail-open to PaOS", 13, 10, 0
str_cl_linux_varfail: db "[PAOS64] P0 Linux transition: BootOrder/Boot#### GetVariable failed; fail-open to PaOS", 13, 10, 0
str_cl_linux_bootnext_fail: db "[PAOS64] P0 Linux transition: BootNext write/read-back failed and was disarmed; fail-open to PaOS", 13, 10, 0
str_cl_linux_reset_fail: db "[PAOS64] P0 Linux transition: warm ResetSystem+CF9 returned; BootNext disarmed; fail-open to PaOS", 13, 10, 0
str_cl_linux_bootnext_ok: db "[PAOS64] P0 Linux transition: dynamic BootNext verified; firmware handoff queued", 13, 10, 0
str_cl_linux_target_kat: db "[PAOS64] exact live-option parser selected external ESP shim [boot.linux.target.resolved]", 13, 10, 0
str_cl_linux_cross_kat: db "[PAOS64] two-ESP renumber/absence/malformed/ambiguity KAT passed [boot.linux.cross_volume.ready]", 13, 10, 0
str_cl_linux_kat_fail: db "[PAOS64] boot Linux cross-volume product KAT FAILED", 13, 10, 0
str_cl_linux_live_pre: db "[PAOS64] P0 Linux transition: selected Boot####=0x", 0
str_cl_linux_live_len: db " complete_device_path_bytes=0x", 0
str_cl_linux_live_post: db " policy=shim-first authority=firmware-BootNext", 13, 10, 0
str_cl_loaded:    db "[PAOS64] P0 chainload: LoadImage OK -> StartImage", 13, 10, 0
