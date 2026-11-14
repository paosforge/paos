;; MODULE dev/power/ec_power
;; LAYER 3
;; EXPORTS ecp_census_match, ecp_forecast_update, ecp_forecast_snapshot, ecp_forecast_project, ecp_lid_button_snapshot, ecp_lid_confirm_begin, ecp_lid_confirm_cancel, ecp_init_cooperative, ecp_sample_begin, ecp_sample_step, ecp_sample_cancel, ecp_sample_recover, ecp_sample_state, ecp_bat_sample_ms, ecp_freshness, ecp_init, ecp_refresh, ecp_pm1_poll, ecp_lid_poll, ecp_lid_read_now, ecp_bl_set_pct, ecp_bl_lid_blank, ecp_bl_lid_restore, ecp_bl_lid_dark, ecp_status_format, ecp_lid, ecp_lid_events, ecp_q_other, ecp_bl_ok, ecp_bl_duty, ecp_bl_max, ecp_bl_min, ecp_bl_base, ecp_active, ecp_ac, ecp_bat_present, ecp_bat_state, ecp_bat_pct, ecp_bat_rate, ecp_bat_rem, ecp_bat_full, ecp_bat_design, ecp_bat_mv, ecp_bat_dmv, ecp_bat_warn, ecp_warn_events, ecp_pwrbtn_presses, ecp_ec_timeouts, ecp_ec_garbage, ecp_pm1_sts_port, ecp_sci_en, ecp_ec_writes, ecp_data_port, ecp_cmd_port
;; IMPORTS boot/smbios, bus/acpi, bus/pci, bus/hal, core/time, boot/serial
;; CAPS io
;; OWNER saga:rc_power
; ============================================================================
; dev/power/ec_power.asm — laptop embedded-controller battery/AC and the ACPI
; fixed-feature power button, without an AML interpreter (RCQ-27 slice 1).
;
; Everything is keyed by an SMBIOS-matched platform descriptor (ecp_desc_table).
; A machine with no row does no port I/O at all and emits nothing: ecp_init
; compares two SMBIOS strings and returns. The only row today is the Dell
; Latitude 5490 (rc-target4 DELL_LAPTOP_BACKEND_MAP.md a6f699ac, DSDT 382c156f;
; the same values are the "ec" quirk of gauntlet_v2/config/machine_quirks.json
; dell-latitude-5490-SERIAL, and a host test pins the two together).
;
; EC transport (ACPI 6.x sec. 12.2/12.3; DSDT ECDV _CRS data 0x930, cmd/status
; 0x934; no _GLK, no ECDT): RD_EC 0x80 = wait IBF=0, cmd, wait IBF=0, address,
; wait OBF=1, data. Desktop battery and lid work shares a cooperative engine:
; one phase, at most two byte IOs per idle call, no busy delays. Each wait has
; 64 polls; the whole sample has a 1024-call / 2000ms bound. Legacy explicit
; synchronous refresh uses ECP_WAIT_ITERS polls, 1 us apart. A stale OBF byte is
; drained (bounded) before a command so it can never be read as a result.
; The only EC write that exists is the battery select the DSDT's _BST/_BIF do
; first (ECG6/ECG9: ECWB(0x03, 1)); the descriptor is refused unless its select
; is exactly that, and no other write path is assembled.
;
; Battery/AC (DSDT): AC._PSR = EC[6] bit0; BAT0._STA = EC[6] bit1; _BST = ECG6(1):
; select, EC[0x10] state, words 0x12 rate / 0x16 remaining / 0x14 mV, with
; ECG6's rate rules keyed on ECG2 = EC[0] bit0; _BIF = ECG9(1): words 0x20 design
; / 0x1E last full / 0x22 design mV. Words are two RD_EC reads, low byte first
; (ECR2). Any timeout or implausible value is "unknown" (0xFF / -1), never a
; fabricated 0 % or 100 %.
;
; Lid (RCQ-27 slice 2; DSDT _Q66 -> NEVT): the EC raises SCI_EVT (status bit 5);
; the one query is 0x66, whose handler reads the event word (ECG1 = EC word 0x07)
; and, on bit 0x0004, the lid (ECG3 = EC[0] bit 0x10; _LID 1 = open). Without SCI
; wiring the tick polls: SCI_EVT -> QR_EC 0x84 (bounded, read-type command) ->
; 0x66 -> event word -> lid re-read; plus a 1 s safety re-read. A change is
; reported only after two consecutive equal reads (bounce suppression). NEVT's
; write to PCH memory 0xFDAE05B8 is firmware bookkeeping and is NOT replicated.
;
; Backlight (slice 2): the Intel PCH PWM on the iGPU (Intel graphics PRM Vol 2c,
; BLC_PWM_PCH_CTL1 / BLC_PWM_PCH_CTL2; the Dell's values read on the device):
; CTL1 0xC8250 (bit31 enable, bit29 polarity), CTL2 0xC8254 (max = bits 31:16,
; duty = 15:0). Only on the descriptor's GPU (bdf + vendor:device, class 03, memory
; decode on, BAR0 below 4 GiB like every other PaOS MMIO driver), only with the
; PWM enabled by firmware, normal polarity and a sane max; a set is a
; read-modify-write of the duty field alone, clamped to [min, max] with
; min = max(1, max * bl_min_255 / 255) (the descriptor's floor) - never 0, never
; a black panel - and read back.
; Every PWM access runs on the one idle-loop context (power_events_tick and the
; BACKLIGHT verb's dispatch frame run in turn, never concurrently); that is the
; only serialization, and a new caller from another context must add a lock.
; Lid (root 16:43:12): a debounced lid close saves the duty and writes duty 0 (max
; and CTL1 untouched, so the PWM stays enabled and validated); the open writes the
; saved duty back, exactly (not raised to the BACKLIGHT floor: it is the level the
; panel had). The lid is the only writer of duty 0, so it owns the recovery
; (srcreview H1): only a verified restore ends the dark state, and while the PWM
; does not validate the lid poll retries the restore while the lid is open. While
; the lid holds the panel dark a BACKLIGHT set is refused, so nothing but the lid
; lights a panel the lid darkened. Duty 0 is a 0 % duty cycle in
; the CTL2 duty field (Intel graphics PRM Vol 2c, BLC_PWM_PCH_CTL2); whether the
; panel is fully dark at 0 % is the Dell metal row's observation. The CTL1 enable
; bit is never cleared here.
;
; Power button: FADT Flags.PWR_BUTTON=0 selects the fixed-feature button
; (PM1x_STS.PWRBTN_STS bit 8). The PM1a event block comes from the FADT
; (X_PM1a_EVT_BLK, else PM1a_EVT_BLK). Polled, never interrupt-armed; cleared by
; writing 1 to bit 8 alone (write-1-to-clear), never writing back other bits.
; ============================================================================

ECP_WAIT_ITERS     equ 2000                ; per IBF/OBF wait, 1 us apart
ECP_DRAIN_MAX      equ 8                   ; stale OBF bytes discarded per command
ECP_ST_OBF         equ 0x01
ECP_ST_IBF         equ 0x02
ECP_RD_EC          equ 0x80
ECP_WR_EC          equ 0x81
ECP_ONLY_WRITE_REG equ 0x03                ; the DSDT's battery select (ECWB(0x03, Arg0))
ECP_ONLY_WRITE_VAL equ 0x01                ; BAT0 (_BST/_BIF call ECG6/ECG9 with One)
; Fresh only for age < 20 s: twice the normal 10 s cadence allows bounded
; jitter/one delayed refresh, never an unbounded critical/healthy cache.
ECP_MAX_AGE_MS     equ 20000
ECP_F_NEVER        equ 0
ECP_F_VALID        equ 1
ECP_F_ABSENT       equ 2
ECP_F_FAILED       equ 3
ECP_F_EXPIRED      equ 4
ECP_F_CLOCK        equ 5
ECP_UNKNOWN8       equ 0xFF
ECP_PWRBTN_STS     equ 0x0100              ; PM1_STS bit 8
ECP_FADT_PM1A_EVT  equ 56
ECP_FADT_PM1A_CNT  equ 64
ECP_FADT_EVT_LEN   equ 88
ECP_FADT_FLAGS     equ 112
ECP_FADT_X_PM1A_EVT equ 148
ECP_FADT_PWR_BUTTON equ (1 << 4)           ; 1 = control-method power button

struc ecp_desc
    .vendor:     resb 16                   ; SMBIOS type 1 manufacturer, exact
    .product:    resb 24                   ; SMBIOS type 1 product name, exact
    .data_port:  resw 1
    .cmd_port:   resw 1
    .sel_reg:    resb 1                    ; battery select write (must be 0x03 <- 1)
    .sel_val:    resb 1
    .acbat_reg:  resb 1                    ; AC bit0 / battery-present bit1
    .flag_reg:   resb 1                    ; ECG2 (rate sign rule): bit0
    .state_reg:  resb 1                    ; _BST state
    .rate_w:     resb 1
    .rem_w:      resb 1
    .mv_w:       resb 1
    .design_w:   resb 1
    .full_w:     resb 1
    .dmv_w:      resb 1
    .pwrbtn:     resb 1                    ; 1 = poll the FADT fixed-feature button
    .lid_reg:    resb 1                    ; slice 2: lid byte (ECG3)
    .lid_mask:   resb 1                    ;          set = open
    .evt_query:  resb 1                    ;          the _Qxx value carrying lid events
    .evt_word:   resb 1                    ;          NEVT event word (ECG1)
    .evt_lid:    resb 1                    ;          lid-change bit in its low byte
    .bl_min_255: resb 1                    ;          backlight floor in 1/255 of max (0 = no backlight)
    .gpu_dev:    resb 1                    ;          iGPU bus 0 device
    .gpu_fn:     resb 1                    ;          iGPU function
    .gpu_vendev: resd 1                    ;          vendor | device << 16
endstruc

; --- port I/O (the host test supplies these) ------------------------------------
%ifndef ECP_HOST_IO
; ecp_io_in8(EDI=port) -> EAX. clobbers RDX.
ecp_io_in8:
    mov  edx, edi
    xor  eax, eax
    in   al, dx
    ret
; ecp_io_out8(EDI=port, ESI=value). clobbers RAX, RDX.
ecp_io_out8:
    mov  edx, edi
    mov  eax, esi
    out  dx, al
    ret
; ecp_io_in16(EDI=port) -> EAX. clobbers RDX.
ecp_io_in16:
    mov  edx, edi
    xor  eax, eax
    in   ax, dx
    ret
; ecp_io_out16(EDI=port, ESI=value). clobbers RAX, RDX.
ecp_io_out16:
    mov  edx, edi
    mov  eax, esi
    out  dx, ax
    ret
%endif

; --- EC transport -------------------------------------------------------------
; ecp_wait(ESI=mask, EDX=want) -> CF=1 after ECP_WAIT_ITERS polls. clobbers
;   RAX, RCX, RDX, RDI, R8, R9.
ecp_wait:
    mov  r8d, esi
    mov  r9d, edx
    mov  ecx, ECP_WAIT_ITERS
.poll:
    push rcx
    movzx edi, word [rel ecp_cmd_port]
    call ecp_io_in8
    pop  rcx
    and  eax, r8d
    cmp  eax, r9d
    je   .ok
    push rcx
    mov  edi, 1
    call tsc_delay_us
    pop  rcx
    dec  ecx
    jnz  .poll
    inc  dword [rel ecp_ec_timeouts]
    stc
    ret
.ok:
    clc
    ret

; ecp_drain -> CF. Discard <=8 bytes, then require an observed empty OBF.
; The ninth status read verifies the limit; it never consumes a ninth byte.
ecp_drain:
    push rbx
    mov  ebx, ECP_DRAIN_MAX
.l:
    movzx edi, word [rel ecp_cmd_port]
    call ecp_io_in8
    test eax, ECP_ST_OBF
    jz   .clean
    test ebx, ebx
    jz   .full
    movzx edi, word [rel ecp_data_port]
    call ecp_io_in8
    inc  dword [rel ecp_ec_garbage]
    dec  ebx
    jmp  .l
.full:
    inc  dword [rel ecp_ec_timeouts]
    pop  rbx
    stc
    ret
.clean:
    pop  rbx
    clc
    ret

; ecp_send(EDI=port, ESI=byte) after IBF=0 -> CF. clobbers caller-saved.
ecp_send:
    push rdi
    push rsi
    mov  esi, ECP_ST_IBF
    xor  edx, edx
    call ecp_wait
    pop  rsi
    pop  rdi
    jc   .out
    call ecp_io_out8
    clc
.out:
    ret

; Synchronous callers share custody with the cooperative engine. Kind 4 is a
; captured single operation, always discarded during retirement. No reset or new
; command is used to recover an uncertain handshake. Address/ports/descriptor
; survive timeout and reinit; explicit recover/step retires only its tail.
; ecp_sync(ESI=address, EDX=0 read / FF sole select / FE query) -> byte, CF.
ecp_sync:
    cmp  byte [rel ecp_sample_state], 0
    je   .available
    stc
    ret
.available:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, esi
    mov  r12d, edx
    call ecp_drain
    jc   .out
    mov  [rel ecp_sync_address], bl
    mov  [rel ecp_sync_op], r12b
    mov  rax, [rel ecp_desc_ptr]
    mov  [rel ecp_sample_desc], rax
    mov  ax, [rel ecp_data_port]
    mov  [rel ecp_sample_data_port], ax
    mov  ax, [rel ecp_cmd_port]
    mov  [rel ecp_sample_cmd_port], ax
    mov  byte [rel ecp_sample_kind], 4
    mov  byte [rel ecp_sample_op], 0
    mov  byte [rel ecp_sample_phase], 1
    mov  byte [rel ecp_sample_polls], 0
    mov  byte [rel ecp_sample_retries], 0
    mov  byte [rel ecp_sample_discard], 1
    mov  dword [rel ecp_sample_cleanup], 0
    mov  byte [rel ecp_sample_state], 1
    movzx edi, word [rel ecp_cmd_port]
    mov  esi, ECP_RD_EC
    cmp  r12d, 0xFF
    jne  .query_check
    mov  esi, ECP_WR_EC
.query_check:
    cmp  r12d, 0xFE
    jne  .command
    mov  esi, ECP_QR_EC
.command:
    ; Final admission observes both buffers on the same status read. OBF that
    ; arrives while waiting for IBF cannot be consumed as this command's result.
    push rsi
    mov  esi, ECP_ST_IBF | ECP_ST_OBF
    xor  edx, edx
    call ecp_wait
    pop  rsi
    jc   .failed
    movzx edi, word [rel ecp_cmd_port]
    call ecp_io_out8
    mov  byte [rel ecp_sample_phase], 2
    cmp  r12d, 0xFE
    je   .response
    movzx edi, word [rel ecp_data_port]
    mov  esi, ebx
    call ecp_send
    jc   .failed
.response:
    mov  byte [rel ecp_sample_phase], 3
    cmp  r12d, 0xFF
    je   .value
    mov  esi, ECP_ST_OBF
    mov  edx, ECP_ST_OBF
    call ecp_wait
    jc   .failed
    movzx edi, word [rel ecp_data_port]
    call ecp_io_in8
    and  eax, 0xFF
    jmp  .success
.value:
    movzx edi, word [rel ecp_data_port]
    mov  esi, ECP_ONLY_WRITE_VAL
    call ecp_send
    jc   .failed
    mov  byte [rel ecp_sample_phase], 4
    inc  dword [rel ecp_ec_writes]
    mov  esi, ECP_ST_IBF
    xor  edx, edx
    call ecp_wait
    jc   .failed
.success:
    mov  byte [rel ecp_sample_state], 0
    clc
    jmp  .out
.failed:
    cmp  byte [rel ecp_sample_phase], 1
    je   .safe
    mov  byte [rel ecp_sample_state], 2
    stc
    jmp  .out
.safe:
    mov  byte [rel ecp_sample_state], 0
    stc
.out:
    lea  rsp, [rsp + 8]                    ; preserve CF
    pop  r12
    pop  rbx
    ret

; ecp_read(ESI=EC address) -> EAX byte, CF on transport refusal/timeout.
ecp_read:
    xor  edx, edx
    jmp  ecp_sync

; ecp_read_word(ESI=EC address) -> EAX = [addr] | [addr+1] << 8 (DSDT ECR2), CF.
ecp_read_word:
    push rbx
    push r12
    mov  ebx, esi
    call ecp_read
    jc   .out
    mov  r12d, eax
    lea  esi, [rbx + 1]
    call ecp_read
    jc   .out
    shl  eax, 8
    or   eax, r12d
    clc
.out:
    pop  r12
    pop  rbx
    ret

; ecp_select_battery -> CF. The one EC write: WR_EC ECP_ONLY_WRITE_REG <- VAL.
;   No register or value comes from a caller or the descriptor.
ecp_select_battery:
    mov  esi, ECP_ONLY_WRITE_REG
    mov  edx, 0xFF
    jmp  ecp_sync

; --- descriptor match ---------------------------------------------------------
; ecp_streq(RDI=a, RSI=b, ECX=max) -> ZF=1 only when both strings end (NUL) at
;   the same place within max bytes; running out of the field is "not equal".
ecp_streq:
.l:
    mov  al, [rdi]
    cmp  al, [rsi]
    jne  .ne
    test al, al
    jz   .eq
    inc  rdi
    inc  rsi
    dec  ecx
    jnz  .l
    jmp  .ne
.eq:
    xor  eax, eax
    ret
.ne:
    or   eax, 1
    ret

; C3 read-only selected descriptor vs actual SMBIOS match and retained ports.
; EAX=0 unavailable,1 match,2 observed contradiction. No EC operation.
ecp_census_match:
    push rbx
    cmp byte [rel ecp_active],1
    jne .unknown
    mov rbx,[rel ecp_desc_ptr]
    test rbx,rbx
    jz .unknown
    call ecp_match
    cmp rax,rbx
    jne .conflict
    mov ax,[rbx+ecp_desc.data_port]
    cmp ax,[rel ecp_data_port]
    jne .conflict
    mov ax,[rbx+ecp_desc.cmd_port]
    cmp ax,[rel ecp_cmd_port]
    jne .conflict
    mov eax,1
    jmp .done
.conflict:
    mov eax,2
    jmp .done
.unknown:
    xor eax,eax
.done:
    pop rbx
    ret

; ecp_match -> RAX = descriptor or 0. No I/O.
ecp_match:
    push rbx
    lea  rbx, [rel ecp_desc_table]
.row:
    lea  rax, [rel ecp_desc_table_end]
    cmp  rbx, rax
    jae  .none
    cmp  dword [rel smbios_identity_state], SMB_ST_OK
    jne  .none
    lea  rdi, [rel smbios_sys_vendor]
    lea  rsi, [rbx + ecp_desc.vendor]
    mov  ecx, 16
    call ecp_streq
    jne  .next
    lea  rdi, [rel smbios_sys_product]
    lea  rsi, [rbx + ecp_desc.product]
    mov  ecx, 24
    call ecp_streq
    jne  .next
    ; the one permitted EC write, or the row is refused outright
    cmp  byte [rbx + ecp_desc.sel_reg], ECP_ONLY_WRITE_REG
    jne  .next
    cmp  byte [rbx + ecp_desc.sel_val], ECP_ONLY_WRITE_VAL
    jne  .next
    mov  rax, rbx
    pop  rbx
    ret
.next:
    add  rbx, ecp_desc_size
    jmp  .row
.none:
    xor  eax, eax
    pop  rbx
    ret

; --- FADT PM1a event block ----------------------------------------------------
; ecp_fadt_pm1(RDI=FADT, ESI=validated length) -> EAX = PM1a_STS port (0 = none),
;   EDX = PM1a_CNT legacy port (0 = none), ECX = 1 when the button is fixed
;   feature. Pure. A present extended block must be System I/O and in range.
ecp_fadt_pm1:
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
    cmp  esi, ECP_FADT_FLAGS + 4
    jb   .out
    cmp  dword [rdi], 'FACP'
    jne  .out
    test dword [rdi + ECP_FADT_FLAGS], ECP_FADT_PWR_BUTTON
    setz cl
    mov  edx, [rdi + ECP_FADT_PM1A_CNT]
    cmp  edx, 0xFFFF
    jbe  .cnt_ok
    xor  edx, edx
.cnt_ok:
    movzx r8d, byte [rdi + ECP_FADT_EVT_LEN]
    cmp  r8d, 4
    jb   .none
    test r8d, 1
    jnz  .none
    mov  eax, [rdi + ECP_FADT_PM1A_EVT]       ; legacy
    cmp  esi, ECP_FADT_X_PM1A_EVT + 12
    jb   .range
    mov  r9, [rdi + ECP_FADT_X_PM1A_EVT + 4]
    test r9, r9
    jz   .range                               ; absent extended block: legacy
    cmp  byte [rdi + ECP_FADT_X_PM1A_EVT], 1  ; System I/O only
    jne  .none
    mov  rax, r9
.range:
    test rax, rax
    jz   .none
    lea  r9, [rax + r8 - 1]
    cmp  r9, 0xFFFF
    ja   .none
    ret
.none:
    xor  eax, eax
.out:
    ret

; --- init / refresh / poll ----------------------------------------------------
; ecp_init — match; on a row: FADT PM1, stale PWRBTN cleared (no event), first
;   refresh, one [power.ec] line. Without a row: nothing (no I/O, no output).
; The resident GUI selects this entry; legacy explicit synchronous callers keep
; ecp_init/refresh. Lid baseline and battery work queue on the desktop entry;
; PM1/PWM initialization retains the existing finite register operations.
ecp_init_cooperative:
    mov  byte [rel ecp_init_async], 1
    sub  rsp, 8
    call ecp_init
    add  rsp, 8
    mov  byte [rel ecp_init_async], 0
    ret
ecp_init:
    cld
    cmp  byte [rel ecp_sample_state], 0
    je   .available
    sub  rsp, 8
    call ecp_sample_cancel                 ; cannot retarget a live/uncertain handshake
    add  rsp, 8
    ret
.available:
    sub rsp, 8
    call ecp_sample_cancel                  ; reset queued requests without touching EC
    add rsp, 8
    mov byte [rel ecp_sample_kind], 0
    push rbx
    push r12
    mov  byte [rel ecp_active], 0
    call ecp_match
    test rax, rax
    jz   .out
    mov  rbx, rax
    mov  [rel ecp_desc_ptr], rax
    mov  ax, [rbx + ecp_desc.data_port]
    mov  [rel ecp_data_port], ax
    mov  ax, [rbx + ecp_desc.cmd_port]
    mov  [rel ecp_cmd_port], ax
    mov  byte [rel ecp_active], 1
    mov  dword [rel ecp_pm1_sts_port], 0
    mov  byte [rel ecp_sci_en], ECP_UNKNOWN8
    cmp  byte [rbx + ecp_desc.pwrbtn], 1
    jne  .refresh
    mov  edi, 'FACP'
    call acpi_find_table
    test rax, rax
    jz   .refresh
    mov  r12, rax
    mov  rdi, rax
    mov  esi, 'FACP'
    call acpi_validate_sdt
    cmp  eax, AF_VALID
    jne  .refresh
    mov  rdi, r12
    mov  esi, ecx
    call ecp_fadt_pm1
    test ecx, ecx
    jz   .refresh                             ; control-method button: not this path
    mov  [rel ecp_pm1_sts_port], eax
    test eax, eax
    jz   .refresh
    test edx, edx
    jz   .stale
    mov  edi, edx
    call ecp_io_in16
    and  eax, 1                               ; PM1_CNT.SCI_EN (diagnostic only)
    mov  [rel ecp_sci_en], al
.stale:
    mov  edi, [rel ecp_pm1_sts_port]
    call ecp_io_in16
    test eax, ECP_PWRBTN_STS
    jz   .refresh
    mov  edi, [rel ecp_pm1_sts_port]           ; the power-on press: clear, no event
    mov  esi, ECP_PWRBTN_STS
    call ecp_io_out16
    mov  byte [rel ecp_pwrbtn_stale], 1
.refresh:
    cmp  byte [rel ecp_init_async], 1
    je   .async
    call ecp_refresh
    call ecp_lid_init
    call ecp_bl_init
    jmp  .report
.async:
    call ecp_lid_init_cooperative           ; queue baseline; no synchronous lid IO
    call ecp_bl_init
    call ecp_sample_begin                   ; no battery IO on this entry
.report:
    lea  rdi, [rel ecp_s_init]
    call serial_string
    lea  rdi, [rbx + ecp_desc.product]
    call serial_string
    lea  rdi, [rel ecp_s_ports]
    call serial_string
    movzx edi, word [rel ecp_data_port]
    call serial_hex64
    lea  rdi, [rel ecp_s_cmd]
    call serial_string
    movzx edi, word [rel ecp_cmd_port]
    call serial_hex64
    lea  rdi, [rel ecp_s_pm1]
    call serial_string
    mov  edi, [rel ecp_pm1_sts_port]
    call serial_hex64
    lea  rdi, [rel ecp_s_sci]
    call serial_string
    movzx edi, byte [rel ecp_sci_en]
    call serial_hex64
    lea  rdi, [rel ecp_s_line]
    call serial_string
    lea  rdi, [rel ecp_line]
    mov  esi, ECP_LINE_MAX
    call ecp_status_format
    lea  rdi, [rel ecp_line]
    call serial_string
    lea  rdi, [rel ecp_s_tail]
    call serial_string
.out:
    pop  r12
    pop  rbx
    ret

; ecp_refresh — one AC/battery snapshot. Each failed or implausible field is
;   unknown; a failed group never leaves an old value standing.
ecp_refresh:
    cld
    cmp  byte [rel ecp_sample_state], 0
    je   .available
    stc                                   ; busy: preserve last completed sample, no handshake
    ret
.available:
    push rbx
    push r12
    push r13
    cmp  byte [rel ecp_active], 1
    jne  .out
    ; Fence the previous snapshot before any EC access. Last successful sample
    ; timestamps survive ordinary failure for diagnostic age, never data reuse.
    call boot_ms_now
    mov  [rel ecp_attempt_ms], rax
    mov  byte [rel ecp_attempt_clock], 1
    test rax, rax
    jz   .bad_clock
    cmp  rax, [rel ecp_last_clock_ms]
    jb   .bad_clock
    mov  [rel ecp_last_clock_ms], rax
    jmp  .start
.bad_clock:
    mov  byte [rel ecp_attempt_clock], 0
.start:
    mov  byte [rel ecp_ac_fresh], ECP_F_FAILED
    mov  byte [rel ecp_bat_fresh], ECP_F_FAILED
    mov  rbx, [rel ecp_desc_ptr]
    mov  byte [rel ecp_ac], ECP_UNKNOWN8
    mov  byte [rel ecp_bat_present], ECP_UNKNOWN8
    call ecp_battery_unknown
    movzx esi, byte [rbx + ecp_desc.acbat_reg]
    call ecp_read
    jc   .finish
    mov  ecx, eax
    and  ecx, 1
    mov  [rel ecp_ac], cl
    shr  eax, 1
    and  eax, 1
    mov  [rel ecp_bat_present], al
    mov  byte [rel ecp_ac_fresh], ECP_F_VALID
    mov  byte [rel ecp_bat_fresh], ECP_F_ABSENT
    test eax, eax
    jz   .finish
    mov  byte [rel ecp_bat_fresh], ECP_F_FAILED
    ; From here a timeout anywhere voids the whole battery snapshot (.void).
    movzx esi, byte [rbx + ecp_desc.flag_reg]
    call ecp_read
    jc   .void
    and  eax, 1
    mov  r13d, eax                            ; ECG2
    call ecp_select_battery
    jc   .void
    movzx esi, byte [rbx + ecp_desc.state_reg]
    call ecp_read
    jc   .void
    and  eax, 7
    mov  byte [rel ecp_bat_state], ECP_UNKNOWN8
    cmp  eax, 3
    je   .state_done                          ; charging and discharging: implausible
    and  eax, 3
    mov  [rel ecp_bat_state], al              ; 0 idle, 1 discharging, 2 charging
.state_done:
    movzx esi, byte [rbx + ecp_desc.rate_w]
    call ecp_read_word
    jc   .void
    ; ECG6: 0 -> 1; on ECG2: bit15 -> unknown else as is; off: bit15 -> -x, else unknown
    test eax, eax
    jnz  .rate_nz
    mov  eax, 1
    jmp  .rate_set
.rate_nz:
    test r13d, r13d
    jz   .rate_off
    test eax, 0x8000
    jnz  .rate_unknown
    jmp  .rate_set
.rate_off:
    test eax, 0x8000
    jz   .rate_unknown
    neg  eax
    and  eax, 0xFFFF
    jmp  .rate_set
.rate_unknown:
    mov  eax, -1
.rate_set:
    mov  [rel ecp_bat_rate], eax
    movzx esi, byte [rbx + ecp_desc.rem_w]
    call ecp_read_word
    jc   .void
    mov  [rel ecp_bat_rem], eax
    movzx esi, byte [rbx + ecp_desc.mv_w]
    call ecp_read_word
    jc   .void
    mov  [rel ecp_bat_mv], eax
    call ecp_select_battery                   ; ECG9 selects again before _BIF
    jc   .void
    movzx esi, byte [rbx + ecp_desc.design_w]
    call ecp_read_word
    jc   .void
    mov  [rel ecp_bat_design], eax
    movzx esi, byte [rbx + ecp_desc.full_w]
    call ecp_read_word
    jc   .void
    mov  [rel ecp_bat_full], eax
    movzx esi, byte [rbx + ecp_desc.dmv_w]
    call ecp_read_word
    jc   .void
    mov  [rel ecp_bat_dmv], eax
    call ecp_plausible
    cmp  byte [rel ecp_bat_pct], ECP_UNKNOWN8
    je   .finish
    cmp  byte [rel ecp_bat_state], ECP_UNKNOWN8
    je   .finish
    mov  byte [rel ecp_bat_fresh], ECP_F_VALID
    jmp  .finish
.void:
    call ecp_battery_unknown
.finish:
    ; Qualify both ends of the bounded transport. Age begins at the attempt,
    ; so even a slow read cannot mint a younger or future-dated sample.
    call boot_ms_now
    test rax, rax
    jz   .clock_failed
    cmp  byte [rel ecp_attempt_clock], 1
    jne  .clock_failed
    cmp  rax, [rel ecp_attempt_ms]
    jb   .clock_failed
    cmp  rax, [rel ecp_last_clock_ms]
    jb   .clock_failed
    mov  [rel ecp_last_clock_ms], rax
    mov  rax, [rel ecp_attempt_ms]
    cmp  byte [rel ecp_ac_fresh], ECP_F_VALID
    jne  .bat_time
    mov  [rel ecp_ac_sample_ms], rax
.bat_time:
    cmp  byte [rel ecp_bat_fresh], ECP_F_ABSENT
    ja   .out
    mov  [rel ecp_bat_sample_ms], rax
    jmp  .out
.clock_failed:
    call ecp_clock_unknown
.out:
    call ecp_battery_warn_update
    pop  r13
    pop  r12
    pop  rbx
    ret

; Cooperative EC sample, BSP idle-loop only; no callbacks/IRQs or delay loops.
; begin: no IO. step: ONE phase, <=1 status poll + <=1 byte read/write (2 IO).
; 64 polls per wait, 1024 service calls / 2000 ms per transaction. Cancellation
; retires only the current captured operation, <=128 further service calls. An
; unfinished command retains blocked custody; only explicit recover retries its
; exact captured phase, never a new command (one recovery attempt per sample).
; No reset/abort firmware command.
ECP_SAMPLE_PENDING equ 1
ECP_SAMPLE_DONE equ 2
ECP_SAMPLE_FAILED equ -1
ECP_SAMPLE_BLOCKED equ -2
ECP_SAMPLE_POLL_LIMIT equ 64
ECP_SAMPLE_STEP_LIMIT equ 1024
ECP_SAMPLE_CLEAN_LIMIT equ 128
ECP_SAMPLE_MAX_MS equ 2000

ecp_sample_begin:
    cld
    cmp  byte [rel ecp_sample_state], 2
    je   .blocked
    cmp  byte [rel ecp_sample_state], 1
    jne  .idle
    cmp  byte [rel ecp_sample_kind], 0
    je   .pending
    mov  byte [rel ecp_battery_due], 1      ; lid custody must not lose battery cadence
.pending:
    mov  eax, ECP_SAMPLE_PENDING
    ret
.blocked:
    mov  eax, ECP_SAMPLE_BLOCKED
    ret
.idle:
    mov  byte [rel ecp_sample_kind], 0
    mov  byte [rel ecp_battery_due], 0
    jmp  ecp_sample_capture

; Common capture for BAT(0), lid poll(1), raw confirmation(2), initial baseline(3).
ecp_sample_capture:
    cmp  byte [rel ecp_active], 1
    jne  .failed
    sub  rsp, 8
    call boot_ms_now
    cmp byte [rel ecp_sample_kind], 0
    jne .clock_check
    mov  [rel ecp_attempt_ms], rax
.clock_check:
    test rax, rax
    jz   .clock
    cmp  rax, [rel ecp_last_clock_ms]
    jb   .clock
    mov  [rel ecp_last_clock_ms], rax
    mov  [rel ecp_sample_started_ms], rax
    mov  [rel ecp_sample_last_ms], rax
    mov  rax, [rel ecp_desc_ptr]
    mov  [rel ecp_sample_desc], rax
    mov  ax, [rel ecp_data_port]
    mov  [rel ecp_sample_data_port], ax
    mov  ax, [rel ecp_cmd_port]
    mov  [rel ecp_sample_cmd_port], ax
    mov  dword [rel ecp_sample_steps], 0
    mov  dword [rel ecp_sample_cleanup], 0
    mov  byte [rel ecp_sample_op], 0
    mov  byte [rel ecp_lid_has_read], 0
    cmp  byte [rel ecp_sample_kind], 2
    jb   .op_set
    mov  byte [rel ecp_sample_op], 3        ; confirmation/baseline is just RD lid
.op_set:
    mov  rax, [rel ecp_lid_confirm_id]
    mov  [rel ecp_sample_lid_id], rax
    mov  byte [rel ecp_sample_phase], 0
    mov  byte [rel ecp_sample_polls], 0
    mov  byte [rel ecp_sample_drained], 0
    mov  byte [rel ecp_sample_discard], 0
    mov  byte [rel ecp_sample_clock_bad], 0
    mov  byte [rel ecp_sample_ac_done], 0
    mov  byte [rel ecp_sample_retries], 0
    mov  byte [rel ecp_sample_state], 1
    add  rsp, 8
.pending:
    mov  eax, ECP_SAMPLE_PENDING
    ret
.clock:
    mov  [rel ecp_last_clock_ms], rax
    call ecp_clock_unknown
    add  rsp, 8
.failed:
    cmp byte [rel ecp_sample_kind], 2
    jne .failed_out
    mov byte [rel ecp_lid_confirm_state], 3
.failed_out:
    mov  eax, ECP_SAMPLE_FAILED
    ret

; Cancel/pause/stop does not drop a partially sent command. step must service
; its retirement on this same rail; no further register operation is started.
ecp_sample_cancel:
    cld
    mov byte [rel ecp_battery_due], 0
    mov byte [rel ecp_lid_due], 0
    mov byte [rel ecp_lid_init_due], 0
    mov byte [rel ecp_lid_confirm_queued], 0
    cmp byte [rel ecp_lid_confirm_state], 0
    je .queues_cleared
    mov byte [rel ecp_lid_confirm_state], 3
.queues_cleared:
    xor  eax, eax
    cmp  byte [rel ecp_sample_state], 0
    je   .out
    mov  byte [rel ecp_sample_discard], 1
    cmp  byte [rel ecp_sample_state], 2
    je   .blocked
    mov  eax, ECP_SAMPLE_PENDING
.out:
    ret
.blocked:
    mov  eax, ECP_SAMPLE_BLOCKED
    ret

; Explicit retry of retained custody after a transient EC stall. Never clears
; a handshake by assumption. Context must still match; step enforces it too.
ecp_sample_recover:
    cld
    cmp  byte [rel ecp_sample_state], 2
    jne  ecp_sample_cancel
    cmp  byte [rel ecp_sample_retries], 1
    jae  .blocked
    inc  byte [rel ecp_sample_retries]
    mov  byte [rel ecp_sample_discard], 1
    mov  byte [rel ecp_sample_polls], 0
    mov  dword [rel ecp_sample_cleanup], 0
    mov  byte [rel ecp_sample_state], 1
    mov  eax, ECP_SAMPLE_PENDING
    ret
.blocked:
    mov  eax, ECP_SAMPLE_BLOCKED
    ret

ecp_sample_step:
    cld
    push rbx
    push r12
    sub  rsp, 8
    xor  eax, eax
    cmp  byte [rel ecp_sample_state], 0
    jne  .live
    call ecp_service_begin                 ; queued intent; zero IO
    cmp  byte [rel ecp_sample_state], 1
    jne  .out
.live:
    cmp  byte [rel ecp_sample_state], 2
    je   .blocked_out
    ; Captured identity/ports cannot be replaced while custody is live.
    cmp  byte [rel ecp_active], 1
    jne  .context_changed
    mov  rax, [rel ecp_desc_ptr]
    cmp  rax, [rel ecp_sample_desc]
    jne  .context_changed
    mov  ax, [rel ecp_data_port]
    cmp  ax, [rel ecp_sample_data_port]
    jne  .context_changed
    mov  ax, [rel ecp_cmd_port]
    cmp  ax, [rel ecp_sample_cmd_port]
    jne  .context_changed
    cmp  byte [rel ecp_sample_discard], 1
    je   .cleanup
    call boot_ms_now
    test rax, rax
    jz   .clock
    cmp  rax, [rel ecp_sample_last_ms]
    jb   .clock
    cmp  rax, [rel ecp_last_clock_ms]
    jb   .clock
    mov  [rel ecp_sample_last_ms], rax
    mov  [rel ecp_last_clock_ms], rax
    sub  rax, [rel ecp_sample_started_ms]
    jc   .clock
    cmp  rax, ECP_SAMPLE_MAX_MS
    jae  .retire
    inc  dword [rel ecp_sample_steps]
    cmp  dword [rel ecp_sample_steps], ECP_SAMPLE_STEP_LIMIT
    ja   .retire
    jmp  .phase
.clock:
    mov  [rel ecp_last_clock_ms], rax
    mov  byte [rel ecp_sample_clock_bad], 1
    call ecp_clock_unknown
.retire:
    mov  byte [rel ecp_sample_discard], 1
.cleanup:
    inc  dword [rel ecp_sample_cleanup]
    cmp  dword [rel ecp_sample_cleanup], ECP_SAMPLE_CLEAN_LIMIT
    jae  .quarantine
.phase:
    xor  ebx, ebx
    cmp  byte [rel ecp_sample_kind], 4
    jne  .table_op
    movzx r12d, byte [rel ecp_sync_op]
    jmp  .dispatch                         ; captured synchronous tail only
.table_op:
    movzx ebx, byte [rel ecp_sample_op]
    cmp  byte [rel ecp_sample_kind], 0
    je   .battery_ops
    cmp  ebx, 4
    jae  .quarantine
    lea  r12, [rel ecp_lid_ops]
    jmp  .ops_ready
.battery_ops:
    cmp  ebx, 17
    jae  .quarantine
    lea  r12, [rel ecp_sample_ops]
.ops_ready:
    movzx eax, byte [r12 + rbx*2]
    mov  r12d, eax                         ; FF select, otherwise descriptor offset
    cmp  byte [rel ecp_sample_discard], 1
    jne  .dispatch
    cmp  byte [rel ecp_sample_phase], 1
    jbe  .failure                          ; no command sent: already safely retired
.dispatch:
    movzx eax, byte [rel ecp_sample_phase]
    cmp  eax, 0
    je   .drain
    cmp  eax, 1
    je   .command
    cmp  eax, 2
    je   .address
    cmp  eax, 3
    je   .response
    cmp  eax, 4
    je   .consumed
    jmp  .quarantine
.drain:
    movzx edi, word [rel ecp_sample_cmd_port]
    call ecp_io_in8
    test eax, ECP_ST_OBF
    jz   .next_phase
    movzx edi, word [rel ecp_sample_data_port]
    call ecp_io_in8
    inc  dword [rel ecp_ec_garbage]
    inc  byte [rel ecp_sample_drained]
    cmp  byte [rel ecp_sample_drained], ECP_DRAIN_MAX
    jae  .timeout_safe
    jmp  .pending
.command:
    movzx edi, word [rel ecp_sample_cmd_port]
    call ecp_io_in8
    test eax, ECP_ST_IBF
    jnz  .wait
    movzx edi, word [rel ecp_sample_cmd_port]
    cmp  r12d, 0xFE
    jne  .read_command
    test eax, ECP_ST_SCI_EVT
    jz   .no_query
    mov  esi, ECP_QR_EC
    call ecp_io_out8
    mov  byte [rel ecp_sample_phase], 3     ; QR has no address byte
    mov  byte [rel ecp_sample_polls], 0
    jmp  .pending
.no_query:
    mov  byte [rel ecp_sample_raw], 0
    jmp  .advance
.read_command:
    mov  esi, ECP_RD_EC
    cmp  r12d, 0xFF
    jne  .send_command
    mov  esi, ECP_WR_EC
.send_command:
    call ecp_io_out8
    jmp  .next_phase
.address:
    movzx edi, word [rel ecp_sample_cmd_port]
    call ecp_io_in8
    test eax, ECP_ST_IBF
    jnz  .wait
    mov  esi, ECP_ONLY_WRITE_REG
    cmp  r12d, 0xFF
    je   .send_address
    cmp  byte [rel ecp_sample_kind], 4
    jne  .descriptor_address
    movzx esi, byte [rel ecp_sync_address]
    jmp  .send_address
.descriptor_address:
    mov  rax, [rel ecp_sample_desc]
    movzx esi, byte [rax + r12]
    lea  rax, [rel ecp_sample_ops]
    cmp  byte [rel ecp_sample_kind], 0
    je   .address_table
    lea  rax, [rel ecp_lid_ops]
.address_table:
    movzx ecx, byte [rax + rbx*2 + 1]
    add  esi, ecx                         ; exact low-byte then high-byte ECR2
.send_address:
    movzx edi, word [rel ecp_sample_data_port]
    call ecp_io_out8
    jmp  .next_phase
.response:
    movzx edi, word [rel ecp_sample_cmd_port]
    call ecp_io_in8
    cmp  r12d, 0xFF
    je   .value
    test eax, ECP_ST_OBF
    jz   .wait
    movzx edi, word [rel ecp_sample_data_port]
    call ecp_io_in8
    lea  rdx, [rel ecp_sample_raw]
    mov  [rdx + rbx], al
    cmp  byte [rel ecp_sample_kind], 0
    je   .battery_response
    cmp  ebx, 3
    jne  .advance
    mov  byte [rel ecp_lid_has_read], 1
    jmp  .complete
.battery_response:
    test ebx, ebx
    jnz  .advance
    mov  byte [rel ecp_sample_ac_done], 1
    test al, 2
    jz   .complete                         ; qualified absent group
    jmp  .advance
.value:
    test eax, ECP_ST_IBF
    jnz  .wait
    movzx edi, word [rel ecp_sample_data_port]
    mov  esi, ECP_ONLY_WRITE_VAL
    call ecp_io_out8
    inc  dword [rel ecp_ec_writes]          ; attempted write even if consume wait later fails
    jmp  .next_phase
.consumed:
    cmp  r12d, 0xFF
    jne  .quarantine
    movzx edi, word [rel ecp_sample_cmd_port]
    call ecp_io_in8
    test eax, ECP_ST_IBF
    jnz  .wait
.advance:
    cmp  byte [rel ecp_sample_discard], 1
    je   .failure
    cmp  byte [rel ecp_sample_kind], 0
    je   .battery_advance
    call ecp_lid_advance
    cmp  eax, ECP_SAMPLE_DONE
    je   .complete
    jmp  .reset_phase
.battery_advance:
    inc  byte [rel ecp_sample_op]
    cmp  byte [rel ecp_sample_op], 17
    jae  .complete
.reset_phase:
    mov  byte [rel ecp_sample_phase], 0
    mov  byte [rel ecp_sample_drained], 0
    mov  byte [rel ecp_sample_polls], 0
    jmp  .pending
.next_phase:
    inc  byte [rel ecp_sample_phase]
    mov  byte [rel ecp_sample_polls], 0
.pending:
    mov  eax, ECP_SAMPLE_PENDING
    jmp  .out
.wait:
    inc  byte [rel ecp_sample_polls]
    cmp  byte [rel ecp_sample_polls], ECP_SAMPLE_POLL_LIMIT
    jb   .pending
    inc  dword [rel ecp_ec_timeouts]
    cmp  byte [rel ecp_sample_phase], 1
    je   .failure                          ; no command sent, custody safe to release
    jmp  .quarantine
.timeout_safe:
    inc  dword [rel ecp_ec_timeouts]
.failure:
    mov  byte [rel ecp_sample_state], 0
    call ecp_sample_failed
    mov  eax, ECP_SAMPLE_FAILED
    jmp  .out
.context_changed:
    mov  byte [rel ecp_sample_ac_done], 0
.quarantine:
    mov  byte [rel ecp_sample_state], 2
    mov  byte [rel ecp_sample_discard], 1
    call ecp_sample_failed
.blocked_out:
    mov  eax, ECP_SAMPLE_BLOCKED
    jmp  .out
.complete:
    cmp  byte [rel ecp_sample_discard], 1
    je   .failure
    mov  byte [rel ecp_sample_state], 0
    call ecp_sample_publish
    mov  eax, ECP_SAMPLE_DONE
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; Terminal publication only, with no EC IO. BSP serialization makes these
; software groups coherent to status/policy observers; not a hardware latch.
ecp_sample_ac_publish:
    movzx eax, byte [rel ecp_sample_raw]
    mov  ecx, eax
    and  ecx, 1
    mov  [rel ecp_ac], cl
    shr  eax, 1
    and  eax, 1
    mov  [rel ecp_bat_present], al
    mov  byte [rel ecp_ac_fresh], ECP_F_VALID
    mov  rax, [rel ecp_sample_started_ms]
    mov  [rel ecp_ac_sample_ms], rax
    ret

ecp_sample_failed:
    cmp byte [rel ecp_sample_kind], 4
    jne .publish_failure
    ret                                    ; sync caller already owns refusal effects
.publish_failure:
    cmp byte [rel ecp_sample_kind], 0
    jne ecp_lid_failed
    sub  rsp, 8
    cmp  byte [rel ecp_sample_clock_bad], 1
    je   .clock
    mov  byte [rel ecp_ac_fresh], ECP_F_FAILED
    mov  byte [rel ecp_bat_fresh], ECP_F_FAILED
    mov  byte [rel ecp_ac], ECP_UNKNOWN8
    mov  byte [rel ecp_bat_present], ECP_UNKNOWN8
    call ecp_battery_unknown
    cmp  byte [rel ecp_sample_ac_done], 1
    jne  .warn
    call ecp_sample_ac_publish              ; independently completed AC/presence group
.warn:
    call ecp_battery_warn_update
    add  rsp, 8
    ret
.clock:
    call ecp_clock_unknown
    add  rsp, 8
    ret

ecp_sample_publish:
    cmp byte [rel ecp_sample_kind], 0
    jne ecp_lid_publish
    sub  rsp, 8
    call ecp_sample_ac_publish
    call ecp_battery_unknown
    mov  byte [rel ecp_bat_fresh], ECP_F_ABSENT
    cmp  byte [rel ecp_bat_present], 0
    je   .bat_time
    mov  byte [rel ecp_bat_fresh], ECP_F_FAILED
    movzx eax, byte [rel ecp_sample_raw + 3]
    and  eax, 7
    cmp  eax, 3
    je   .state_done
    and  eax, 3
    mov  [rel ecp_bat_state], al
.state_done:
    movzx eax, word [rel ecp_sample_raw + 4]
    test eax, eax
    jnz  .rate_nz
    mov  eax, 1
    jmp  .rate_set
.rate_nz:
    test byte [rel ecp_sample_raw + 1], 1
    jz   .rate_off
    test eax, 0x8000
    jnz  .rate_unknown
    jmp  .rate_set
.rate_off:
    test eax, 0x8000
    jz   .rate_unknown
    neg  eax
    and  eax, 0xFFFF
    jmp  .rate_set
.rate_unknown:
    mov  eax, -1
.rate_set:
    mov  [rel ecp_bat_rate], eax
    movzx eax, word [rel ecp_sample_raw + 6]
    mov  [rel ecp_bat_rem], eax
    movzx eax, word [rel ecp_sample_raw + 8]
    mov  [rel ecp_bat_mv], eax
    movzx eax, word [rel ecp_sample_raw + 11]
    mov  [rel ecp_bat_design], eax
    movzx eax, word [rel ecp_sample_raw + 13]
    mov  [rel ecp_bat_full], eax
    movzx eax, word [rel ecp_sample_raw + 15]
    mov  [rel ecp_bat_dmv], eax
    call ecp_plausible
    cmp  byte [rel ecp_bat_pct], ECP_UNKNOWN8
    je   .warn
    cmp  byte [rel ecp_bat_state], ECP_UNKNOWN8
    je   .warn
    mov  byte [rel ecp_bat_fresh], ECP_F_VALID
.bat_time:
    mov  rax, [rel ecp_sample_started_ms]
    mov  [rel ecp_bat_sample_ms], rax
.warn:
    call ecp_battery_warn_update
    add  rsp, 8
    ret

; ecp_freshness() -- BSP/idle-loop serialization, like ecp_refresh. No EC IO.
; Revalidate before every status/policy consumer. Expiry and clock loss are
; sticky until a new qualified refresh. Age/attempt/sample values are full64.
ecp_freshness:
    cld
    push rbx
    call boot_ms_now
    mov  qword [rel ecp_ac_age_ms], -1
    mov  qword [rel ecp_bat_age_ms], -1
    mov  qword [rel ecp_lid_age_ms], -1
    test rax, rax
    jz   .clock
    cmp  rax, [rel ecp_last_clock_ms]
    jb   .clock
    mov  [rel ecp_last_clock_ms], rax
    mov  rbx, rax
    mov  rcx, [rel ecp_ac_sample_ms]
    test rcx, rcx
    jz   .battery
    sub  rax, rcx
    jc   .clock
    mov  [rel ecp_ac_age_ms], rax
    cmp  byte [rel ecp_ac_fresh], ECP_F_VALID
    jne  .battery
    cmp  rax, ECP_MAX_AGE_MS
    jb   .battery
    mov  byte [rel ecp_ac_fresh], ECP_F_EXPIRED
    mov  byte [rel ecp_ac], ECP_UNKNOWN8
    mov  byte [rel ecp_bat_present], ECP_UNKNOWN8
.battery:
    mov  rax, rbx
    mov  rcx, [rel ecp_bat_sample_ms]
    test rcx, rcx
    jz   .lid
    sub  rax, rcx
    jc   .clock
    mov  [rel ecp_bat_age_ms], rax
    cmp  byte [rel ecp_bat_fresh], ECP_F_ABSENT
    ja   .lid
    cmp  rax, ECP_MAX_AGE_MS
    jb   .lid
    mov  byte [rel ecp_bat_fresh], ECP_F_EXPIRED
    call ecp_battery_unknown
.lid:
    ; Diagnostics only: retain the saved value and existing lid action policy.
    ; Saved, debounced lid state has its own observation age. Never substitute
    ; battery refresh or a successful event query for an actual stable lid read.
    mov  rax, rbx
    mov  rcx, [rel ecp_lid_sample_ms]
    test rcx, rcx
    jz   .warn
    cmp  rax, rcx
    jb   .clock
    sub  rax, rcx
    mov  [rel ecp_lid_age_ms], rax
    cmp  byte [rel ecp_lid_fresh], ECP_F_VALID
    jne  .warn
    cmp  rax, ECP_MAX_AGE_MS
    jb   .warn
    mov  byte [rel ecp_lid_fresh], ECP_F_EXPIRED
.warn:
    cmp  byte [rel ecp_ac_fresh], ECP_F_VALID
    jne  .unknown
    cmp  byte [rel ecp_ac], 1
    je   .out
    cmp  byte [rel ecp_bat_fresh], ECP_F_ABSENT
    jbe  .out
.unknown:
    mov  byte [rel ecp_bat_warn], ECP_UNKNOWN8
.out:
    pop  rbx
    ret
.clock:
    ; A later good clock alone cannot resurrect the old sample. A new refresh
    ; may recover in the new epoch, but only by reading both groups again.
    mov  [rel ecp_last_clock_ms], rax
    call ecp_clock_unknown
    jmp  .out

ecp_clock_unknown:
    mov byte [rel ecp_lid_confirm_queued], 0
    cmp byte [rel ecp_lid_confirm_state], 0
    je .sample
    mov byte [rel ecp_lid_confirm_state], 3  ; queued/completed raw result cannot cross epochs
.sample:
    cmp  byte [rel ecp_sample_state], 0
    je   .groups
    mov  byte [rel ecp_sample_clock_bad], 1
    mov  byte [rel ecp_sample_discard], 1    ; any observer's clock loss retires this attempt
.groups:
    cmp  byte [rel ecp_ac_fresh], ECP_F_NEVER
    je   .bat
    mov  byte [rel ecp_ac_fresh], ECP_F_CLOCK
.bat:
    cmp  byte [rel ecp_bat_fresh], ECP_F_NEVER
    je   .void
    mov  byte [rel ecp_bat_fresh], ECP_F_CLOCK
.void:
    cmp  byte [rel ecp_lid_fresh], ECP_F_NEVER
    je   .lid_void
    mov  byte [rel ecp_lid_fresh], ECP_F_CLOCK
.lid_void:
    mov  qword [rel ecp_lid_sample_ms], 0
    mov  qword [rel ecp_lid_age_ms], -1
    mov  qword [rel ecp_ac_sample_ms], 0
    mov  qword [rel ecp_bat_sample_ms], 0
    mov  qword [rel ecp_ac_age_ms], -1
    mov  qword [rel ecp_bat_age_ms], -1
    mov  byte [rel ecp_ac], ECP_UNKNOWN8
    mov  byte [rel ecp_bat_present], ECP_UNKNOWN8
    mov  byte [rel ecp_bat_warn], ECP_UNKNOWN8
    jmp  ecp_battery_unknown

; --- RCQ-27 POWER-04: low / critical charge warnings ------------------------------
; Declared policy (RC spec 6.4.2 POWER-04; thresholds bound here, before freeze):
;   on battery (AC=0) with a known percentage:
;     <= ECP_WARN_LOW (15 %)  -> low,      cleared only at >= ECP_WARN_LOW_CLEAR (20 %)
;     <= ECP_WARN_CRIT (7 %)  -> critical, eased to low only at >= ECP_WARN_CRIT_CLEAR (10 %)
;   AC connected, or no battery -> none; AC or percentage unknown -> unknown.
; Evaluated after every refresh (10 s cadence); a change to none/low/critical is
; logged once ([power.battery.warn]); unknown is never logged as a warning and
; never invents a level. No automatic power action here: what PaOS does at
; critical charge is user power policy, decided with the lid/button policy.
ECP_WARN_NONE        equ 0
ECP_WARN_LOW         equ 15
ECP_WARN_LOW_CLEAR   equ 20
ECP_WARN_CRIT        equ 7
ECP_WARN_CRIT_CLEAR  equ 10
ECP_WL_NONE          equ 0
ECP_WL_LOW           equ 1
ECP_WL_CRITICAL      equ 2

ecp_battery_warn_update:
    sub  rsp, 8
    call ecp_forecast_update
    add  rsp, 8
    cmp  byte [rel ecp_active], 1
    jne  .out
    cmp  byte [rel ecp_ac_fresh], ECP_F_VALID
    jne  .unknown
    movzx ecx, byte [rel ecp_bat_warn]        ; previous level (ECP_UNKNOWN8 = unknown)
    movzx eax, byte [rel ecp_ac]
    cmp  eax, 1
    je   .none                                ; on AC: nothing to warn about
    cmp  eax, ECP_UNKNOWN8
    je   .unknown
    cmp  byte [rel ecp_bat_fresh], ECP_F_ABSENT
    je   .none
    cmp  byte [rel ecp_bat_fresh], ECP_F_VALID
    jne  .unknown
    movzx eax, byte [rel ecp_bat_pct]
    cmp  eax, ECP_UNKNOWN8
    je   .unknown
    xor  edx, edx                             ; base = previous, unknown counts as none
    cmp  ecx, ECP_UNKNOWN8
    je   .eval
    mov  edx, ecx
.eval:
    cmp  eax, ECP_WARN_CRIT
    jbe  .crit
    cmp  edx, ECP_WL_CRITICAL
    jne  .not_crit_held
    cmp  eax, ECP_WARN_CRIT_CLEAR
    jb   .crit                                ; hysteresis: stay critical below 10 %
.not_crit_held:
    cmp  eax, ECP_WARN_LOW
    jbe  .low
    test edx, edx
    jz   .none
    cmp  eax, ECP_WARN_LOW_CLEAR
    jb   .low                                 ; hysteresis: stay low below 20 %
.none:
    mov  edx, ECP_WL_NONE
    jmp  .set
.low:
    mov  edx, ECP_WL_LOW
    jmp  .set
.crit:
    mov  edx, ECP_WL_CRITICAL
.set:
    mov  [rel ecp_bat_warn], dl
    cmp  edx, ecx
    je   .out
    cmp  ecx, ECP_UNKNOWN8
    jne  .log
    test edx, edx
    jz   .out                                 ; unknown -> none: the first reading, not an event
.log:
    inc  dword [rel ecp_warn_events]
    jmp  ecp_battery_warn_log
.unknown:
    mov  byte [rel ecp_bat_warn], ECP_UNKNOWN8
.out:
    ret

; ecp_battery_warn_log — "[PAOS64] power: battery warning <level> pct=<n> [power.battery.warn]"
ecp_battery_warn_log:
    push rbx
    push r12
    push r13
    lea  rbx, [rel ecp_warn_line]
    lea  r12, [rel ecp_warn_line + 95]
    lea  rsi, [rel ecp_s_warn]
    call ecp_fmt_str
    call ecp_warn_name                        ; RSI = "none" / "low" / "critical"
    call ecp_fmt_str
    lea  rsi, [rel ecp_k_warn_pct]
    call ecp_fmt_str
    movzx eax, byte [rel ecp_bat_pct]
    call ecp_fmt_u8
    lea  rsi, [rel ecp_s_warn_tail]
    call ecp_fmt_str
    mov  byte [rbx], 0
    lea  rdi, [rel ecp_warn_line]
    call serial_string
    pop  r13
    pop  r12
    pop  rbx
    ret

; ecp_warn_name -> RSI = the current level's name. clobbers: EAX.
ecp_warn_name:
    movzx eax, byte [rel ecp_bat_warn]
    lea  rsi, [rel ecp_v_unknown]
    cmp  eax, ECP_WL_CRITICAL
    ja   .out
    lea  rsi, [rel ecp_v_none]
    test eax, eax
    jz   .out
    lea  rsi, [rel ecp_v_low]
    cmp  eax, ECP_WL_LOW
    je   .out
    lea  rsi, [rel ecp_v_critical]
.out:
    ret

ecp_battery_unknown:
    mov  byte [rel ecp_bat_state], ECP_UNKNOWN8
    mov  byte [rel ecp_bat_pct], ECP_UNKNOWN8
    mov  eax, -1
    mov  [rel ecp_bat_rate], eax
    mov  [rel ecp_bat_rem], eax
    mov  [rel ecp_bat_full], eax
    mov  [rel ecp_bat_design], eax
    mov  [rel ecp_bat_mv], eax
    mov  [rel ecp_bat_dmv], eax
    ret

; ecp_plausible — 0xFFFF words are unknown; percent only from a sane pair
;   (0 < full, remaining <= full), never clamped into 0 or 100.
ecp_plausible:
    lea  rdx, [rel ecp_bat_rem]
    mov  ecx, 6
.w:
    cmp  dword [rdx], 0xFFFF
    jne  .w_ok
    mov  dword [rdx], -1
.w_ok:
    add  rdx, 4
    dec  ecx
    jnz  .w
    cmp  dword [rel ecp_bat_design], 0
    jne  .design_ok
    mov  dword [rel ecp_bat_design], -1
.design_ok:
    mov  byte [rel ecp_bat_pct], ECP_UNKNOWN8
    mov  ecx, [rel ecp_bat_full]
    cmp  ecx, -1
    je   .out
    test ecx, ecx
    jz   .zero_full
    mov  eax, [rel ecp_bat_rem]
    cmp  eax, -1
    je   .out
    cmp  eax, ecx
    ja   .out                                 ; above last full: no invented 100 %
    imul eax, eax, 100
    xor  edx, edx
    div  ecx
    mov  [rel ecp_bat_pct], al
    ret
.zero_full:
    mov  dword [rel ecp_bat_full], -1
.out:
    ret

; ecp_pm1_poll -> EAX 1 when a press was latched (and cleared), else 0.
;   Writes PWRBTN_STS alone (W1C); no other PM1 status bit is ever written as 1.
ecp_pm1_poll:
    xor  eax, eax
    cmp  byte [rel ecp_active], 1
    jne  .out
    mov  edi, [rel ecp_pm1_sts_port]
    test edi, edi
    jz   .out
    call ecp_io_in16
    test eax, ECP_PWRBTN_STS
    jz   .none
    mov  edi, [rel ecp_pm1_sts_port]
    mov  esi, ECP_PWRBTN_STS
    call ecp_io_out16
    inc  dword [rel ecp_pwrbtn_presses]
    mov  eax, 1
    ret
.none:
    xor  eax, eax
.out:
    ret

; --- lid (slice 2) ------------------------------------------------------------------
ECP_ST_SCI_EVT   equ 0x20
ECP_QR_EC        equ 0x84
ECP_LID_SAFETY   equ 10                    ; re-read the lid every 10th poll (~1 s at 100 ms)

; ecp_query -> EAX = query value (0 = none pending), CF=1 on a transport timeout.
ecp_query:
    cmp  byte [rel ecp_sample_state], 0
    je   .available
    stc
    ret
.available:
    movzx edi, word [rel ecp_cmd_port]
    call ecp_io_in8
    test eax, ECP_ST_SCI_EVT
    jz   .none
    xor  esi, esi
    mov  edx, 0xFE
    jmp  ecp_sync
.none:
    xor  eax, eax
    clc
.out:
    ret

; ecp_lid_read -> EAX 1 open / 0 closed, CF=1 on timeout.
ecp_lid_read:
    mov  rdx, [rel ecp_desc_ptr]
    movzx esi, byte [rdx + ecp_desc.lid_reg]
    call ecp_read
    jc   .out
    mov  rdx, [rel ecp_desc_ptr]
    movzx ecx, byte [rdx + ecp_desc.lid_mask]
    and  eax, ecx
    setnz al
    movzx eax, al
    clc
.out:
    ret

; Confirmation is an explicit one-shot request. No EC IO in these APIs.
; begin -> nonzero full64 request token, 0 if unavailable/busy/time invalid.
; read_now(RDI=token) -> 256 pending, 0 closed, 1 open, FF failed/stale/mismatch.
; Only a matching completed raw read, age <2000ms from request, can return closed.
ecp_lid_confirm_begin:
    cld
    cmp byte [rel ecp_active], 1
    jne .failed
    cmp byte [rel ecp_lid_ok], 1
    jne .failed
    cmp byte [rel ecp_lid_confirm_state], 1
    je .failed
    cmp byte [rel ecp_sample_state], 2
    je .failed
    sub rsp, 8
    call boot_ms_now
    test rax, rax
    jz .clock
    cmp rax, [rel ecp_last_clock_ms]
    jb .clock
    mov [rel ecp_last_clock_ms], rax
    mov [rel ecp_lid_confirm_ms], rax
    add rsp, 8
    mov rax, [rel ecp_lid_confirm_seq]
    cmp rax, -1
    je .failed                           ; never wrap/reuse a request token
    inc rax
    mov [rel ecp_lid_confirm_seq], rax
    mov [rel ecp_lid_confirm_id], rax
    mov byte [rel ecp_lid_confirm_value], ECP_UNKNOWN8
    mov byte [rel ecp_lid_confirm_state], 1
    mov byte [rel ecp_lid_confirm_queued], 1
    ret
.clock:
    mov [rel ecp_last_clock_ms], rax
    call ecp_clock_unknown
    add rsp, 8
.failed:
    xor eax, eax
    ret

ecp_lid_confirm_cancel:
    cld
    test rdi, rdi
    jz .out
    cmp rdi, [rel ecp_lid_confirm_id]
    jne .out
    mov byte [rel ecp_lid_confirm_queued], 0
    mov byte [rel ecp_lid_confirm_state], 0
    cmp byte [rel ecp_sample_kind], 2
    jne .out
    cmp rdi, [rel ecp_sample_lid_id]
    jne .out
    cmp byte [rel ecp_sample_state], 0
    je .out
    mov byte [rel ecp_sample_discard], 1    ; finish only the captured handshake
.out:
    xor eax, eax
    ret

ecp_lid_read_now:
    cld
    push rbx
    mov rbx, rdi
    test rbx, rbx
    jz .unknown
    cmp rbx, [rel ecp_lid_confirm_id]
    jne .unknown
    cmp byte [rel ecp_active], 1
    jne .expired
    cmp byte [rel ecp_lid_ok], 1
    jne .expired
    cmp byte [rel ecp_lid_confirm_state], 1
    jb .unknown
    cmp byte [rel ecp_lid_confirm_state], 2
    ja .unknown
    call boot_ms_now
    test rax, rax
    jz .clock
    cmp rax, [rel ecp_last_clock_ms]
    jb .clock
    mov [rel ecp_last_clock_ms], rax
    mov rdx, rax
    sub rax, [rel ecp_lid_confirm_ms]
    jnc .age
    mov rax, rdx
    jmp .clock
.age:
    cmp rax, ECP_SAMPLE_MAX_MS
    jae .expired
    cmp byte [rel ecp_lid_confirm_state], 1
    je .pending
    movzx eax, byte [rel ecp_lid_confirm_value]
    mov byte [rel ecp_lid_confirm_state], 0 ; consume once, never a cached fresh answer
    jmp .out
.pending:
    mov eax, 256
    jmp .out
.clock:
    mov [rel ecp_last_clock_ms], rax
    call ecp_clock_unknown
    jmp .unknown
.expired:
    mov rdi, rbx
    call ecp_lid_confirm_cancel
.unknown:
    mov eax, ECP_UNKNOWN8
.out:
    pop rbx
    ret

; ecp_lid_init — first stable state (unknown on timeout); no event.
ecp_lid_init:
    mov  qword [rel ecp_lid_sample_ms], 0
    mov  qword [rel ecp_lid_age_ms], -1
    mov  byte [rel ecp_lid_fresh], ECP_F_NEVER
    mov  byte [rel ecp_lid], ECP_UNKNOWN8
    mov  byte [rel ecp_lid_ok], 0
    mov  rdx, [rel ecp_desc_ptr]
    cmp  byte [rdx + ecp_desc.evt_query], 0
    je   .out
    mov  byte [rel ecp_lid_ok], 1
    call ecp_lid_read
    jc   .out
    mov  [rel ecp_lid], al
    mov  [rel ecp_lid_cand], al
.out:
    ret

; Poll queues one coalesced demand and consumes previously completed changes.
; No EC IO here. power_events_tick services the shared rail once per idle tick.
; Return 2 establishes an asynchronous boot baseline, without a close event.
ecp_lid_poll:
    cld
    cmp byte [rel ecp_active], 1
    jne .none
    cmp byte [rel ecp_lid_ok], 1
    jne .none
    mov byte [rel ecp_lid_due], 1
    jmp ecp_lid_take_result
.none:
    xor eax, eax
    ret

ecp_lid_take_result:
    xor eax, eax
    cmp byte [rel ecp_lid_baseline_ready], 0
    je .change
    mov byte [rel ecp_lid_baseline_ready], 0
    mov eax, 2
    ret
.change:
    cmp byte [rel ecp_lid_change_ready], 0
    je .out
    mov byte [rel ecp_lid_change_ready], 0
    mov eax, 1
.out:
    ret

ecp_lid_init_cooperative:
    mov qword [rel ecp_lid_sample_ms], 0
    mov qword [rel ecp_lid_age_ms], -1
    mov byte [rel ecp_lid_fresh], ECP_F_NEVER
    mov byte [rel ecp_lid], ECP_UNKNOWN8
    mov byte [rel ecp_lid_cand], ECP_UNKNOWN8
    mov byte [rel ecp_lid_cand_n], 0
    mov byte [rel ecp_lid_pending], 0
    mov byte [rel ecp_lid_change_ready], 0
    mov byte [rel ecp_lid_baseline_ready], 0
    mov byte [rel ecp_lid_ok], 0
    mov rdx, [rel ecp_desc_ptr]
    cmp byte [rdx + ecp_desc.evt_query], 0
    je .out
    mov byte [rel ecp_lid_ok], 1
    mov byte [rel ecp_lid_init_due], 1
.out:
    ret

; Choose intent only at an idle handshake boundary; no EC IO. A battery cadence
; that arrived during lid work is retained. Raw confirmation is bounded by its
; request time as well as the common transport deadline.
ecp_service_begin:
    cmp byte [rel ecp_lid_confirm_queued], 1
    je .confirm
    cmp byte [rel ecp_battery_due], 1
    je ecp_sample_begin
    cmp byte [rel ecp_lid_init_due], 1
    je .baseline
    cmp byte [rel ecp_lid_due], 1
    jne .idle
    mov byte [rel ecp_lid_due], 0
    cmp byte [rel ecp_active], 1
    jne .idle
    cmp byte [rel ecp_lid_ok], 1
    jne .idle
    inc dword [rel ecp_lid_polls]
    mov byte [rel ecp_sample_kind], 1
    jmp ecp_sample_capture
.confirm:
    mov byte [rel ecp_lid_confirm_queued], 0
    cmp byte [rel ecp_lid_confirm_state], 1
    jne .idle
    mov byte [rel ecp_sample_kind], 2
    jmp ecp_sample_capture
.baseline:
    mov byte [rel ecp_lid_init_due], 0
    mov byte [rel ecp_sample_kind], 3
    jmp ecp_sample_capture
.idle:
    xor eax, eax
    ret

; Called after completed QR/event bytes; returns pending with next op selected,
; or DONE without a lid read when neither event/debounce nor safety needs one.
ecp_lid_advance:
    mov rdx, [rel ecp_sample_desc]
    cmp ebx, 0
    jne .event_word
    mov al, [rel ecp_sample_raw]
    test al, al
    jz .reread_check
    cmp al, [rdx + ecp_desc.evt_query]
    jne .other
    mov byte [rel ecp_sample_op], 1
    jmp .pending
.other:
    inc dword [rel ecp_q_other]
    jmp .reread_check
.event_word:
    cmp ebx, 1
    jne .event_done
    mov byte [rel ecp_sample_op], 2
    jmp .pending
.event_done:
    mov al, [rel ecp_sample_raw + 1]
    test al, [rdx + ecp_desc.evt_lid]
    jz .reread_check
    inc dword [rel ecp_lid_events]
    mov byte [rel ecp_lid_pending], 2
.reread_check:
    cmp byte [rel ecp_lid_pending], 0
    jne .reread
    mov eax, [rel ecp_lid_polls]
    xor edx, edx
    mov ecx, ECP_LID_SAFETY
    div ecx
    test edx, edx
    jnz .done
.reread:
    mov byte [rel ecp_sample_op], 3
.pending:
    mov eax, ECP_SAMPLE_PENDING
    ret
.done:
    mov eax, ECP_SAMPLE_DONE
    ret

ecp_lid_failed:
    cmp byte [rel ecp_sample_clock_bad], 1
    je ecp_clock_unknown
    cmp byte [rel ecp_sample_kind], 2
    jne .saved
    mov rax, [rel ecp_sample_lid_id]
    cmp rax, [rel ecp_lid_confirm_id]
    jne .out
    mov byte [rel ecp_lid_confirm_state], 3
.out:
    ret
.saved:
    mov byte [rel ecp_lid_fresh], ECP_F_FAILED
    ret

ecp_lid_publish:
    cmp byte [rel ecp_lid_has_read], 1
    jne .out
    mov rdx, [rel ecp_sample_desc]
    mov al, [rel ecp_sample_raw + 3]
    test al, [rdx + ecp_desc.lid_mask]
    setnz al
    cmp byte [rel ecp_sample_kind], 2
    je .confirmation
    cmp byte [rel ecp_sample_kind], 3
    je .baseline
    cmp al, [rel ecp_lid]
    jne .differs
    mov [rel ecp_lid_cand], al
    mov byte [rel ecp_lid_cand_n], 0
    mov byte [rel ecp_lid_pending], 0
    jmp .validated
.differs:
    cmp al, [rel ecp_lid_cand]
    je .again
    mov [rel ecp_lid_cand], al
    mov byte [rel ecp_lid_cand_n], 1
    mov byte [rel ecp_lid_pending], 2
    ret
.again:
    inc byte [rel ecp_lid_cand_n]
    cmp byte [rel ecp_lid_cand_n], 2
    jb .out
    mov [rel ecp_lid], al
    mov byte [rel ecp_lid_cand_n], 0
    mov byte [rel ecp_lid_pending], 0
    mov byte [rel ecp_lid_change_ready], 1
    jmp .validated
.out:
    ret
.baseline:
    mov [rel ecp_lid], al
    mov [rel ecp_lid_cand], al
    mov byte [rel ecp_lid_cand_n], 0
    mov byte [rel ecp_lid_pending], 0
    mov byte [rel ecp_lid_baseline_ready], 1
.validated:
    ; The shared rail already checked clock/descriptor/transport through its
    ; terminal boundary. Start time is conservative; raw policy confirmations
    ; and the first differing debounce candidate cannot renew this sample.
    mov rax, [rel ecp_sample_started_ms]
    mov [rel ecp_lid_sample_ms], rax
    mov byte [rel ecp_lid_fresh], ECP_F_VALID
    ret
.confirmation:
    mov rdx, [rel ecp_sample_lid_id]
    cmp rdx, [rel ecp_lid_confirm_id]
    jne .out
    cmp byte [rel ecp_lid_confirm_state], 1
    jne .out
    mov [rel ecp_lid_confirm_value], al
    mov byte [rel ecp_lid_confirm_state], 2
    ret

; --- PCH backlight (slice 2) ---------------------------------------------------------
ECP_BL_CTL1      equ 0xC8250
ECP_BL_CTL2      equ 0xC8254
ECP_BL_ENABLE    equ 0x80000000
ECP_BL_POLARITY  equ 0x20000000
ECP_BL_APERTURE  equ 0x200000              ; GTTMMADR register half (2 MiB)
ECP_BL_MAX_MIN   equ 16                    ; a PWM max below this is not a real panel PWM
ECP_BL_LID_TRIES equ 3                     ; restore writes a validated PWM gets before the lid gives up

; ecp_bl_rd(ESI=offset) -> EAX. ecp_bl_wr(ESI=offset, EDX=value).
ecp_bl_rd:
    lea  rdi, [rel ecp_bl_region]
    jmp  hal_mmio_read32
ecp_bl_wr:
    lea  rdi, [rel ecp_bl_region]
    jmp  hal_mmio_write32

; ecp_bl_init — identify the descriptor's GPU and the firmware-enabled PWM.
;   Reads only (PCI config + two registers); never changes the PWM.
ecp_bl_init:
    push rbx
    push r12
    mov  byte [rel ecp_bl_ok], 0
    mov  rbx, [rel ecp_desc_ptr]
    cmp  byte [rbx + ecp_desc.bl_min_255], 0
    je   .out
    xor  edi, edi
    movzx esi, byte [rbx + ecp_desc.gpu_dev]
    movzx edx, byte [rbx + ecp_desc.gpu_fn]
    xor  ecx, ecx
    call pci_cfg_read32
    lea  r12, [rel ecp_s_bl_nogpu]
    cmp  eax, [rbx + ecp_desc.gpu_vendev]
    jne  .refuse
    xor  edi, edi
    movzx esi, byte [rbx + ecp_desc.gpu_dev]
    movzx edx, byte [rbx + ecp_desc.gpu_fn]
    mov  ecx, 0x08
    call pci_cfg_read32
    shr  eax, 24
    cmp  eax, 0x03                            ; display controller
    jne  .refuse
    xor  edi, edi
    movzx esi, byte [rbx + ecp_desc.gpu_dev]
    movzx edx, byte [rbx + ecp_desc.gpu_fn]
    mov  ecx, 0x04
    call pci_cfg_read32
    lea  r12, [rel ecp_s_bl_nodecode]
    test eax, 0x02                            ; memory decode left on by firmware
    jz   .refuse
    xor  edi, edi
    movzx esi, byte [rbx + ecp_desc.gpu_dev]
    movzx edx, byte [rbx + ecp_desc.gpu_fn]
    mov  ecx, 0x10
    call pci_cfg_read32
    lea  r12, [rel ecp_s_bl_bar]
    test eax, 1
    jnz  .refuse                              ; I/O BAR
    mov  [rel ecp_bl_base], eax
    and  dword [rel ecp_bl_base], 0xFFFFFFF0
    and  eax, 0x06
    cmp  eax, 0x04
    jne  .bar32
    xor  edi, edi
    movzx esi, byte [rbx + ecp_desc.gpu_dev]
    movzx edx, byte [rbx + ecp_desc.gpu_fn]
    mov  ecx, 0x14
    call pci_cfg_read32
    mov  [rel ecp_bl_base + 4], eax
.bar32:
    mov  rax, [rel ecp_bl_base]
    test rax, rax
    jz   .refuse
    lea  rcx, [rax + ECP_BL_APERTURE]
    mov  rdx, 0x100000000
    cmp  rcx, rdx
    ja   .refuse                              ; only below 4 GiB (firmware MTRR-UC hole)
    mov  [rel ecp_bl_region], rax
    mov  qword [rel ecp_bl_region + 8], ECP_BL_APERTURE
    call ecp_bl_read_state
    lea  r12, [rel ecp_s_bl_state]
    test eax, eax
    jz   .refuse
    mov  eax, [rel ecp_bl_max]                ; min = max(1, ceil(max * floor / 255))
    movzx ecx, byte [rbx + ecp_desc.bl_min_255]
    imul eax, ecx
    add  eax, 254
    xor  edx, edx
    mov  ecx, 255
    div  ecx
    test eax, eax
    jnz  .min_ok
    mov  eax, 1
.min_ok:
    mov  [rel ecp_bl_min], eax
    mov  byte [rel ecp_bl_ok], 1
    lea  r12, [rel ecp_s_bl_ready]
.refuse:
    lea  rdi, [rel ecp_s_bl_head]
    call serial_string
    mov  rdi, r12
    call serial_string
    lea  rdi, [rel ecp_s_bl_base]
    call serial_string
    mov  rdi, [rel ecp_bl_base]
    call serial_hex64
    lea  rdi, [rel ecp_s_bl_ctl]
    call serial_string
    mov  edi, [rel ecp_bl_ctl1]
    call serial_hex64
    lea  rdi, [rel ecp_s_bl_ctl2]
    call serial_string
    mov  edi, [rel ecp_bl_ctl2]
    call serial_hex64
    lea  rdi, [rel ecp_s_bl_tail]
    call serial_string
.out:
    pop  r12
    pop  rbx
    ret

; ecp_bl_read_state -> EAX 1 when the PWM is usable: enabled, normal polarity,
;   max >= ECP_BL_MAX_MIN, duty <= max. ctl1/ctl2 are kept raw for the log line;
;   max/duty are cached only once validated. An unusable PWM clears ecp_bl_ok for
;   the rest of the boot (fail closed: BACKLIGHT refuses, the BL_* fields read
;   unknown), so no caller ever divides by or scales with an unvalidated max.
ecp_bl_read_state:
    mov  esi, ECP_BL_CTL1
    call ecp_bl_rd
    mov  [rel ecp_bl_ctl1], eax
    mov  esi, ECP_BL_CTL2
    call ecp_bl_rd
    mov  [rel ecp_bl_ctl2], eax
    mov  ecx, eax
    shr  ecx, 16                              ; max
    and  eax, 0xFFFF                          ; duty
    mov  edx, [rel ecp_bl_ctl1]
    test edx, ECP_BL_ENABLE
    jz   .no
    test edx, ECP_BL_POLARITY
    jnz  .no
    cmp  ecx, ECP_BL_MAX_MIN
    jb   .no
    cmp  eax, ecx
    ja   .no
    mov  [rel ecp_bl_max], ecx
    mov  [rel ecp_bl_duty], eax
    mov  eax, 1
    ret
.no:
    mov  byte [rel ecp_bl_ok], 0
    xor  eax, eax
    ret

; ecp_bl_set_pct(EDI = 0..100) -> EAX 0 set (and read back) / -1 refused.
;   duty = clamp(max * pct / 100, min, max); never 0.
ecp_bl_set_pct:
    push rbx
    mov  ebx, edi
    cmp  byte [rel ecp_active], 1
    jne  .refuse
    cmp  byte [rel ecp_bl_lid_dark], 0
    jne  .refuse                              ; the lid holds the panel dark until it opens
    cmp  byte [rel ecp_bl_ok], 1
    jne  .refuse
    cmp  ebx, 100
    ja   .refuse
    call ecp_bl_read_state                    ; firmware may have changed it since init
    test eax, eax
    jz   .refuse
    mov  eax, [rel ecp_bl_max]
    imul eax, ebx
    xor  edx, edx
    mov  ecx, 100
    div  ecx
    cmp  eax, [rel ecp_bl_min]
    jae  .not_low
    mov  eax, [rel ecp_bl_min]
.not_low:
    cmp  eax, [rel ecp_bl_max]
    jbe  .not_high
    mov  eax, [rel ecp_bl_max]
.not_high:
    test eax, eax
    jz   .refuse                              ; belt and braces: never a zero duty
    mov  ebx, eax
    mov  edx, [rel ecp_bl_ctl2]
    and  edx, 0xFFFF0000                      ; keep max: write the duty field only
    or   edx, ebx
    mov  esi, ECP_BL_CTL2
    call ecp_bl_wr
    inc  dword [rel ecp_bl_writes]
    call ecp_bl_read_state
    test eax, eax
    jz   .refuse                              ; the PWM went unusable under the write
    cmp  [rel ecp_bl_duty], ebx
    jne  .refuse
    xor  eax, eax
    pop  rbx
    ret
.refuse:
    mov  eax, -1
    pop  rbx
    ret

; ecp_bl_lid_blank -> EAX 0 dark (now, or already) / -1 refused.
;   Saves the validated duty, then writes duty 0 with the max bits kept. The dark
;   flag is set with the write, before the read-back, so the open always restores.
ecp_bl_lid_blank:
    cmp  byte [rel ecp_bl_lid_dark], 0
    jne  .ok
    cmp  byte [rel ecp_active], 1
    jne  .refuse
    cmp  byte [rel ecp_bl_ok], 1
    jne  .refuse
    call ecp_bl_read_state
    test eax, eax
    jz   .refuse
    mov  eax, [rel ecp_bl_duty]
    mov  [rel ecp_bl_lid_saved], eax
    mov  byte [rel ecp_bl_lid_tries], 0
    mov  edx, [rel ecp_bl_ctl2]
    and  edx, 0xFFFF0000                      ; keep max; duty 0
    mov  esi, ECP_BL_CTL2
    call ecp_bl_wr
    inc  dword [rel ecp_bl_writes]
    mov  byte [rel ecp_bl_lid_dark], 1
    call ecp_bl_read_state
    test eax, eax
    jz   .refuse
    cmp  dword [rel ecp_bl_duty], 0
    jne  .refuse
.ok:
    xor  eax, eax
    ret
.refuse:
    mov  eax, -1
    ret

; ecp_bl_lid_restore -> EAX 0 restored / 1 not dark (nothing to do) / -1 not yet
;   (still dark: the caller retries) / -2 given up (no longer dark).
;   Validates the PWM itself (ecp_bl_read_state, whatever ecp_bl_ok says: the PWM
;   may have been unusable for a moment while closed), then writes the saved duty
;   back, clamped to the current max, and reads it back. Only a verified restore
;   clears the dark flag. A PWM that does not validate gets no write and stays
;   dark until a later retry finds it valid. A validated PWM that does not keep the
;   written duty gets ECP_BL_LID_TRIES writes in all; then the flag clears and the
;   panel is left to firmware. ecp_bl_ok stays as ecp_bl_read_state left it, so a
;   PWM that was unusable once still refuses BACKLIGHT for the rest of the boot.
ecp_bl_lid_restore:
    push rbx
    mov  eax, 1
    cmp  byte [rel ecp_bl_lid_dark], 0
    je   .out
    cmp  byte [rel ecp_active], 1
    jne  .not_yet
    call ecp_bl_read_state
    test eax, eax
    jz   .not_yet                             ; not valid now: write nothing, retry later
    mov  ebx, [rel ecp_bl_lid_saved]
    cmp  ebx, [rel ecp_bl_max]
    jbe  .in_range
    mov  ebx, [rel ecp_bl_max]                ; firmware lowered max while closed
.in_range:
    mov  edx, [rel ecp_bl_ctl2]
    and  edx, 0xFFFF0000
    or   edx, ebx
    mov  esi, ECP_BL_CTL2
    call ecp_bl_wr
    inc  dword [rel ecp_bl_writes]
    inc  byte [rel ecp_bl_lid_tries]
    call ecp_bl_read_state
    test eax, eax
    jz   .unverified
    cmp  ebx, [rel ecp_bl_duty]
    jne  .unverified
    mov  byte [rel ecp_bl_lid_dark], 0
    xor  eax, eax
.out:
    pop  rbx
    ret
.unverified:
    cmp  byte [rel ecp_bl_lid_tries], ECP_BL_LID_TRIES
    jb   .not_yet
    mov  byte [rel ecp_bl_lid_dark], 0        ; give up: the panel is left to firmware
    mov  eax, -2
    pop  rbx
    ret
.not_yet:
    mov  eax, -1
    pop  rbx
    ret

; --- STATUS projection ------------------------------------------------------------
; Forecast model: BSP serialized, published EC data only; never performs IO.
; Read docs/power/battery_forecast.md for units, uncertainty and owner boundary.
; update clobbers caller-saved, preserves SysV callee-saved. No authority implied.
ecp_forecast_update:
    cld
    push rbx
    call ecp_freshness
    mov qword [rel ecp_fc_health], -1
    cmp byte [rel ecp_active], 1
    jne .invalid
    cmp byte [rel ecp_bat_fresh], ECP_F_VALID
    jne .invalid
    cmp byte [rel ecp_bat_present], 1
    jne .invalid
    mov eax, [rel ecp_bat_full]
    test eax, eax
    jz .invalid
    cmp eax, 65534
    ja .invalid
    mov ecx, [rel ecp_bat_design]
    test ecx, ecx
    jz .health_done
    cmp ecx, 65534
    ja .health_done
    imul rax, rax, 100
    xor edx, edx
    div rcx
    mov [rel ecp_fc_health], rax
.health_done:
    cmp byte [rel ecp_ac_fresh], ECP_F_VALID
    jne .invalid
    cmp byte [rel ecp_ac], 0
    jne .invalid
    cmp byte [rel ecp_bat_state], 1
    jne .invalid
    mov eax, [rel ecp_bat_rem]
    cmp eax, [rel ecp_bat_full]
    ja .invalid
    ; The descriptor maps a zero raw rate to1; it is not a measured drain.
    mov ebx, [rel ecp_bat_rate]
    cmp ebx, 2
    jb .invalid
    cmp ebx, 32768
    ja .invalid
    mov r8, [rel ecp_bat_sample_ms]
    test r8, r8
    jz .invalid
    mov rax, r8
    sub rax, [rel ecp_fc_sample]
    jc .reset
    cmp rax, ECP_MAX_AGE_MS
    jae .reset
    mov eax, [rel ecp_bat_full]
    cmp eax, [rel ecp_fc_full]
    jne .reset
    mov eax, [rel ecp_bat_design]
    cmp eax, [rel ecp_fc_design]
    jne .reset
    cmp r8, [rel ecp_fc_sample]
    je .calculate
    jmp .append
.reset:
    mov dword [rel ecp_fc_count], 0
    mov dword [rel ecp_fc_index], 0
.append:
    mov eax, [rel ecp_bat_full]
    mov [rel ecp_fc_full], eax
    mov eax, [rel ecp_bat_design]
    mov [rel ecp_fc_design], eax
    mov [rel ecp_fc_sample], r8
    mov ecx, [rel ecp_fc_count]
    test ecx, ecx
    jz .first
    mov eax, [rel ecp_fc_mean]
    lea eax, [eax+eax*2]
    lea eax, [eax+ebx+2]
    shr eax, 2
    jmp .mean
.first:
    mov eax, ebx
.mean:
    mov [rel ecp_fc_mean], eax
    mov eax, [rel ecp_fc_index]
    lea rdx, [rel ecp_fc_rates]
    mov [rdx+rax*4], ebx
    inc eax
    and eax, 7
    mov [rel ecp_fc_index], eax
    cmp ecx, 8
    jae .calculate
    inc dword [rel ecp_fc_count]
.calculate:
    mov qword [rel ecp_fc_low_s], -1
    mov qword [rel ecp_fc_high_s], -1
    cmp dword [rel ecp_fc_count], 3
    jb .out
    mov eax, [rel ecp_fc_mean]
    xor edx, edx
    mov ecx, 5
    add eax, 4
    div ecx                              ; ceil(mean/5), minimum20% margin
    mov r9d, [rel ecp_fc_mean]
    mov r10d, r9d
    sub r9d, eax
    jnz .margin
    mov r9d, 1
.margin:
    add r10d, eax
    xor ecx, ecx
    lea rdx, [rel ecp_fc_rates]
.band:
    mov eax, [rdx+rcx*4]
    cmp eax, r9d
    cmovb r9d, eax
    cmp eax, r10d
    cmova r10d, eax
    inc ecx
    cmp ecx, [rel ecp_fc_count]
    jb .band
    mov [rel ecp_fc_low_ma], r9d
    mov [rel ecp_fc_high_ma], r10d
    mov eax, [rel ecp_bat_rem]
    imul rax, rax, 3600
    mov r8, rax
    xor edx, edx
    div r10
    mov [rel ecp_fc_low_s], rax
    mov rax, r8
    lea rax, [rax+r9-1]
    xor edx, edx
    div r9
    mov [rel ecp_fc_high_s], rax
.out:
    pop rbx
    ret
.invalid:
    mov qword [rel ecp_fc_sample], 0
    mov qword [rel ecp_fc_low_s], -1
    mov qword [rel ecp_fc_high_s], -1
    mov dword [rel ecp_fc_count], 0
    mov dword [rel ecp_fc_index], 0
    mov dword [rel ecp_fc_mean], 0
    jmp .out

; snapshot(RDI=trusted caller RAM, RSI>=64)->64 or0 (short: no writes).
; Eight qwords: valid, sample_ms, low_s, high_s, health_pct, count, mean_mA,
; reserved0. Unknown seconds/health=-1; valid only after3 qualified samples.
; This is a trusted in-kernel API; caller must enforce live owner UI/telemetry.
ecp_forecast_snapshot:
    cld
    cmp rsi, 64
    jb .short
    push rbx
    mov rbx, rdi
    call ecp_forecast_update
    xor eax, eax
    cmp dword [rel ecp_fc_count], 3
    setae al
    mov [rbx], rax
    mov rax, [rel ecp_fc_sample]
    mov [rbx+8], rax
    mov rax, [rel ecp_fc_low_s]
    mov [rbx+16], rax
    mov rax, [rel ecp_fc_high_s]
    mov [rbx+24], rax
    mov rax, [rel ecp_fc_health]
    mov [rbx+32], rax
    mov eax, [rel ecp_fc_count]
    mov [rbx+40], rax
    mov eax, [rel ecp_fc_mean]
    mov [rbx+48], rax
    mov qword [rbx+56], 0
    mov eax, 64
    pop rbx
    ret
.short:
    xor eax, eax
    ret

; project(RDI=measured post-job baseline mA2..32768, RSI=remaining s1..604800,
; RDX=current sample_ms)->RAX low_s/RDX high_s, both-1 if unavailable.
; Trusted caller owns baseline provenance and job duration; no public entry.
; Phase1 uses observed current drain band, phase2 baseline +/-20%. No guessed
; idle power or synthetic "measured" bit. Refuse stale sample binding.
ecp_forecast_project:
    cld
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    call ecp_forecast_update
    cmp dword [rel ecp_fc_count], 3
    jb .unknown
    cmp r13, [rel ecp_fc_sample]
    jne .unknown
    cmp rbx, 2
    jb .unknown
    cmp rbx, 32768
    ja .unknown
    test r12, r12
    jz .unknown
    cmp r12, 604800
    ja .unknown
    mov rax, rbx
    add rax, 4
    xor edx, edx
    mov ecx, 5
    div rcx
    mov r9, rbx
    sub r9, rax
    jnz .base_low
    mov r9d, 1
.base_low:
    add rbx, rax                          ; baseline high
    mov eax, [rel ecp_bat_rem]
    imul r8, rax, 3600                    ; capacity in mA seconds
    mov ecx, [rel ecp_fc_high_ma]
    mov rax, rcx
    imul rax, r12
    cmp rax, r8
    jae .runs_out_low
    mov rax, r8
    mov edx, [rel ecp_fc_high_ma]
    imul rdx, r12
    sub rax, rdx
    xor edx, edx
    div rbx
    add rax, r12
    jmp .low_done
.runs_out_low:
    mov rax, r8
    xor edx, edx
    div rcx
.low_done:
    mov r10, rax
    mov ecx, [rel ecp_fc_low_ma]
    mov rax, rcx
    imul rax, r12
    cmp rax, r8
    jae .runs_out_high
    mov rax, r8
    mov edx, [rel ecp_fc_low_ma]
    imul rdx, r12
    sub rax, rdx
    lea rax, [rax+r9-1]
    xor edx, edx
    div r9
    add rax, r12
    jmp .high_done
.runs_out_high:
    lea rax, [r8+rcx-1]
    xor edx, edx
    div rcx
.high_done:
    mov rdx, rax
    mov rax, r10
    jmp .out
.unknown:
    mov rax, -1
    mov rdx, rax
.out:
    pop r13
    pop r12
    pop rbx
    ret

align 8
ecp_fc_sample: dq 0
ecp_fc_low_s: dq -1
ecp_fc_high_s: dq -1
ecp_fc_health: dq -1
ecp_fc_count: dd 0
ecp_fc_index: dd 0
ecp_fc_mean: dd 0
ecp_fc_full: dd 0
ecp_fc_design: dd 0
ecp_fc_low_ma: dd 0
ecp_fc_high_ma: dd 0
ecp_fc_rates: times 8 dd 0

; ecp_status_format(RDI=buffer, ESI=capacity) -> RAX length (NUL written).
;   " AC=1 BAT=1 BAT_PCT=100 BAT_STATE=idle BAT_REM=59455 BAT_FULL=59455
;    BAT_DESIGN=… BAT_DESIGN_MV=7600 BAT_MV=8292 BAT_RATE=1 BAT_UNIT=mAh PWRBTN=0"; unknown fields say
;   "unknown". Capacities/rate are the EC's _BIF power unit 1: mAh / mA (mV for
;   voltage); BAT_PCT is the unit-free remaining/last-full ratio, rounded down.
;   BAT_DESIGN_MV is the cached ECG9/_BIF nominal voltage, not the changing
;   _BST terminal voltage BAT_MV. It permits a caller to compare mAh with an
;   OS's nominal mWh presentation (mAh * design_mV / 1000). No _BIX support or
;   measured energy/rate is implied. Zero/unknown design voltage stays unknown.
; ecp_lid_button_snapshot(RDI caller-owned RAM, RSI capacity, EDX kind=1 lid/2 button)
; -> RAX=64 or 0, no writes on short/foreign selector. Eight qwords: tag,
; kind, backend, support, saved lid (0/1/255), u32 native counter, reserved*2.
; Passive BSP-serialized software publication only. No IO, sampling, freshness
; mutation, clock, or consumption of pending lid/button results. This snapshot
; carries no observation timestamps: consumers MUST report unknown age. A latched
; software counter neither proves physical state nor records a resulting action.
ecp_lid_button_snapshot:
    cmp  rsi, 64
    jb   .bad
    cmp  edx, 1
    je   .size_ok
    cmp  edx, 2
    jne  .bad
.size_ok:
    mov  edx, edx                         ; EDX is the API selector width
    mov  qword [rdi], 0x31424c
    mov  [rdi + 8], rdx
    movzx eax, byte [rel ecp_active]
    mov  [rdi + 16], rax
    mov  qword [rdi + 24], 0
    mov  qword [rdi + 32], 255
    mov  qword [rdi + 40], 0
    mov  qword [rdi + 48], 0
    mov  qword [rdi + 56], 0
    cmp  eax, 1
    jne  .done
    cmp  edx, 1
    jne  .button
    movzx eax, byte [rel ecp_lid_ok]
    mov  [rdi + 24], rax
    cmp  eax, 1
    jne  .done
    movzx eax, byte [rel ecp_lid]
    mov  [rdi + 32], rax
    mov  eax, [rel ecp_lid_events]
    mov  [rdi + 40], rax
    jmp  .done
.button:
    cmp  word [rel ecp_pm1_sts_port], 0
    je   .done
    mov  qword [rdi + 24], 1
    mov  eax, [rel ecp_pwrbtn_presses]
    mov  [rdi + 40], rax
.done:
    mov  eax, 64
    ret
.bad:
    xor  eax, eax
    ret

ecp_status_format:
    cld
    test esi, esi
    jz   .empty
    push rbx
    push r12
    push r13
    mov  r13, rdi
    mov  rbx, rdi
    lea  r12, [rdi + rsi - 1]                ; last byte stays for the NUL
    call ecp_freshness
    lea  rsi, [rel ecp_k_ac]
    call ecp_fmt_str
    movzx eax, byte [rel ecp_ac]
    call ecp_fmt_u8
    lea  rsi, [rel ecp_k_bat]
    call ecp_fmt_str
    movzx eax, byte [rel ecp_bat_present]
    call ecp_fmt_u8
    lea  rsi, [rel ecp_k_pct]
    call ecp_fmt_str
    movzx eax, byte [rel ecp_bat_pct]
    call ecp_fmt_u8
    lea  rsi, [rel ecp_k_state]
    call ecp_fmt_str
    movzx eax, byte [rel ecp_bat_state]
    lea  rsi, [rel ecp_v_unknown]
    cmp  eax, 2
    ja   .state
    lea  rsi, [rel ecp_v_idle]
    test eax, eax
    jz   .state
    lea  rsi, [rel ecp_v_discharging]
    cmp  eax, 1
    je   .state
    lea  rsi, [rel ecp_v_charging]
.state:
    call ecp_fmt_str
    lea  rsi, [rel ecp_k_rem]
    call ecp_fmt_str
    mov  eax, [rel ecp_bat_rem]
    call ecp_fmt_u32
    lea  rsi, [rel ecp_k_full]
    call ecp_fmt_str
    mov  eax, [rel ecp_bat_full]
    call ecp_fmt_u32
    lea  rsi, [rel ecp_k_design]
    call ecp_fmt_str
    mov  eax, [rel ecp_bat_design]
    call ecp_fmt_u32
    lea  rsi, [rel ecp_k_design_mv]
    call ecp_fmt_str
    mov  eax, [rel ecp_bat_dmv]
    test eax, eax
    jnz  .design_mv
    mov  eax, -1
.design_mv:
    call ecp_fmt_u32
    lea  rsi, [rel ecp_k_mv]
    call ecp_fmt_str
    mov  eax, [rel ecp_bat_mv]
    call ecp_fmt_u32
    lea  rsi, [rel ecp_k_rate]
    call ecp_fmt_str
    mov  eax, [rel ecp_bat_rate]
    call ecp_fmt_u32
    lea  rsi, [rel ecp_k_unit]
    call ecp_fmt_str
    lea  rsi, [rel ecp_k_warn]
    call ecp_fmt_str
    call ecp_warn_name
    call ecp_fmt_str
    lea  rsi, [rel ecp_k_lid]
    call ecp_fmt_str
    movzx eax, byte [rel ecp_lid]
    lea  rsi, [rel ecp_v_unknown]
    cmp  eax, 1
    ja   .lid
    lea  rsi, [rel ecp_v_open]
    je   .lid
    lea  rsi, [rel ecp_v_closed]
.lid:
    call ecp_fmt_str
    lea  rsi, [rel ecp_k_lid_fresh]
    call ecp_fmt_str
    movzx eax, byte [rel ecp_lid_fresh]
    call ecp_fmt_fresh
    lea  rsi, [rel ecp_k_lid_age]
    call ecp_fmt_str
    mov  rax, [rel ecp_lid_age_ms]
    call ecp_fmt_u64
    lea  rsi, [rel ecp_k_bl_duty]
    call ecp_fmt_str
    mov  eax, -1
    cmp  byte [rel ecp_bl_ok], 1
    jne  .bl_duty
    mov  eax, [rel ecp_bl_duty]
.bl_duty:
    call ecp_fmt_u32
    lea  rsi, [rel ecp_k_bl_max]
    call ecp_fmt_str
    mov  eax, -1
    cmp  byte [rel ecp_bl_ok], 1
    jne  .bl_max
    mov  eax, [rel ecp_bl_max]
.bl_max:
    call ecp_fmt_u32
    lea  rsi, [rel ecp_k_bl_pct]
    call ecp_fmt_str
    mov  eax, -1
    cmp  byte [rel ecp_bl_ok], 1
    jne  .bl_pct
    cmp  dword [rel ecp_bl_max], 0
    je   .bl_pct                              ; never a #DE in STATUS, whatever the cache holds
    mov  eax, [rel ecp_bl_duty]
    imul eax, eax, 100
    xor  edx, edx
    div  dword [rel ecp_bl_max]
.bl_pct:
    call ecp_fmt_u32
    lea  rsi, [rel ecp_k_pwrbtn]
    call ecp_fmt_str
    mov  eax, [rel ecp_pwrbtn_presses]
    call ecp_fmt_dec
    lea  rsi, [rel ecp_k_sample]
    call ecp_fmt_str
    movzx eax, byte [rel ecp_sample_state]
    cmp  eax, 2
    jbe  .sample_name
    mov  eax, 2
.sample_name:
    shl  eax, 3
    lea  rsi, [rel ecp_sample_names]
    add  rsi, rax
    call ecp_fmt_str
    lea  rsi, [rel ecp_k_ac_fresh]
    call ecp_fmt_str
    movzx eax, byte [rel ecp_ac_fresh]
    call ecp_fmt_fresh
    lea  rsi, [rel ecp_k_ac_age]
    call ecp_fmt_str
    mov  rax, [rel ecp_ac_age_ms]
    call ecp_fmt_u64
    lea  rsi, [rel ecp_k_bat_fresh]
    call ecp_fmt_str
    movzx eax, byte [rel ecp_bat_fresh]
    call ecp_fmt_fresh
    lea  rsi, [rel ecp_k_bat_age]
    call ecp_fmt_str
    mov  rax, [rel ecp_bat_age_ms]
    call ecp_fmt_u64
    lea  rsi, [rel ecp_k_ac_attempt]
    call ecp_fmt_str
    mov  rax, [rel ecp_attempt_ms]
    call ecp_fmt_u64_number
    lea  rsi, [rel ecp_k_bat_attempt]
    call ecp_fmt_str
    mov  rax, [rel ecp_attempt_ms]
    call ecp_fmt_u64_number
    mov  byte [rbx], 0
    mov  rax, rbx
    sub  rax, r13
    pop  r13
    pop  r12
    pop  rbx
    ret
.empty:
    xor  eax, eax
    ret

; helpers: RBX = cursor, R12 = last usable byte. clobber RAX, RCX, RDX, RSI.
ecp_fmt_str:
.l:
    mov  al, [rsi]
    test al, al
    jz   .out
    cmp  rbx, r12
    jae  .out
    mov  [rbx], al
    inc  rbx
    inc  rsi
    jmp  .l
.out:
    ret
ecp_fmt_u8:                                  ; EAX, 0xFF = unknown
    cmp  eax, ECP_UNKNOWN8
    jne  ecp_fmt_dec
    lea  rsi, [rel ecp_v_unknown]
    jmp  ecp_fmt_str
ecp_fmt_u32:                                 ; EAX, -1 = unknown
    cmp  eax, -1
    jne  ecp_fmt_dec
    lea  rsi, [rel ecp_v_unknown]
    jmp  ecp_fmt_str
ecp_fmt_fresh:                               ; EAX enum, fixed-size string slots
    cmp  eax, ECP_F_CLOCK
    jbe  .known
    mov  eax, ECP_F_CLOCK
.known:
    shl  eax, 3
    lea  rsi, [rel ecp_fresh_names]
    add  rsi, rax
    jmp  ecp_fmt_str
ecp_fmt_u64:                                 ; RAX unsigned, -1 = unknown
    cmp  rax, -1
    jne  ecp_fmt_u64_number
    lea  rsi, [rel ecp_v_unknown]
    jmp  ecp_fmt_str
ecp_fmt_u64_number:                          ; timestamps have no reserved numeric value
    sub  rsp, 24
    lea  rsi, [rsp + 23]
    mov  byte [rsi], 0
    mov  ecx, 10
.d:
    xor  edx, edx
    div  rcx
    add  dl, '0'
    dec  rsi
    mov  [rsi], dl
    test rax, rax
    jnz  .d
    call ecp_fmt_str
    add  rsp, 24
    ret
ecp_fmt_dec:                                 ; EAX unsigned
    sub  rsp, 16
    lea  rsi, [rsp + 15]
    mov  byte [rsi], 0
    mov  ecx, 10
.d:
    xor  edx, edx
    div  ecx
    add  dl, '0'
    dec  rsi
    mov  [rsi], dl
    test eax, eax
    jnz  .d
    call ecp_fmt_str
    add  rsp, 16
    ret

; --- platform descriptors (one row per machine; host test pins them) -----------
align 8
ecp_desc_table:
    ; Dell Latitude 5490 (serial redacted, BIOS 1.41.0): DSDT 382c156f, map a6f699ac
    db "Dell Inc.", 0
    times 16 - 10 db 0
    db "Latitude 5490", 0
    times 24 - 14 db 0
    dw 0x0930, 0x0934                         ; ECDV _CRS data, cmd/status
    db ECP_ONLY_WRITE_REG, ECP_ONLY_WRITE_VAL ; ECWB(0x03, One)
    db 0x06                                   ; AC bit0 (_PSR), BAT0 present bit1 (_STA)
    db 0x00                                   ; ECG2 = EC[0] bit0 (ECG6 rate rule)
    db 0x10                                   ; _BST state
    db 0x12, 0x16, 0x14                       ; rate, remaining, mV
    db 0x20, 0x1E, 0x22                       ; design, last full, design mV
    db 1                                      ; FADT fixed-feature power button
    db 0x00, 0x10                             ; lid = EC[0] bit4 (ECG3; set = open)
    db 0x66, 0x07, 0x04                       ; _Q66 -> NEVT: event word 0x07, lid bit 0x0004
    db 10                                     ; backlight floor 10/255 of max (never 0)
    db 0x02, 0x00                             ; iGPU 00:02.0
    dd 0x59178086                             ; Intel UHD 620 (KBL-R)
ecp_desc_table_end:
%if (ecp_desc_table_end - ecp_desc_table) % ecp_desc_size
  %error "ecp_desc_table row size drifted from struc ecp_desc"
%endif

ECP_LINE_MAX equ 512
align 8
ecp_desc_ptr:       dq 0
ecp_pm1_sts_port:   dd 0
ecp_bat_rate:       dd -1
ecp_bat_rem:        dd -1                     ; ecp_plausible walks 6 dwords: rem, full, design, mv, dmv, spare
ecp_bat_full:       dd -1
ecp_bat_design:     dd -1
ecp_bat_mv:         dd -1
ecp_bat_dmv:        dd -1
ecp_bat_spare:      dd -1
ecp_pwrbtn_presses: dd 0
ecp_ec_timeouts:    dd 0
ecp_ec_garbage:     dd 0
ecp_ec_writes:      dd 0
ecp_data_port:      dw 0
ecp_cmd_port:       dw 0
ecp_active:         db 0
ecp_ac:             db ECP_UNKNOWN8
ecp_bat_present:    db ECP_UNKNOWN8
ecp_bat_state:      db ECP_UNKNOWN8
ecp_bat_pct:        db ECP_UNKNOWN8
ecp_bat_warn:       db ECP_UNKNOWN8           ; RCQ-27 POWER-04: 0 none, 1 low, 2 critical, unknown
align 4
ecp_warn_events:    dd 0
ecp_warn_line:      times 96 db 0
ecp_sci_en:         db ECP_UNKNOWN8
ecp_pwrbtn_stale:   db 0
ecp_line:           times ECP_LINE_MAX db 0
align 8
ecp_bl_region:      dq 0, 0                   ; HAL region { bar_base, bar_size }
ecp_bl_base:        dq 0
ecp_bl_ctl1:        dd 0
ecp_bl_ctl2:        dd 0
ecp_bl_max:         dd 0
ecp_bl_duty:        dd 0
ecp_bl_min:         dd 0
ecp_bl_writes:      dd 0
ecp_bl_lid_saved:   dd 0                      ; the duty before the lid closed
ecp_lid_events:     dd 0
ecp_lid_polls:      dd 0
ecp_q_other:        dd 0
ecp_bl_ok:          db 0
ecp_bl_lid_dark:    db 0                      ; 1 while the lid holds the panel at duty 0
ecp_bl_lid_tries:   db 0                      ; restore writes since the last blank
ecp_lid:            db ECP_UNKNOWN8           ; 1 open, 0 closed
ecp_lid_ok:         db 0
ecp_lid_cand:       db ECP_UNKNOWN8
ecp_lid_cand_n:     db 0
ecp_lid_pending:    db 0
ecp_s_bl_head:   db "[PAOS64] power: backlight ", 0
ecp_s_bl_ready:  db "PCH PWM ready", 0
ecp_s_bl_nogpu:  db "refused: descriptor iGPU not found", 0
ecp_s_bl_nodecode: db "refused: memory decode off", 0
ecp_s_bl_bar:    db "refused: BAR not a 32-bit-reachable memory BAR", 0
ecp_s_bl_state:  db "refused: PWM not enabled / inverted / no max", 0
ecp_s_bl_base:   db " gttmmadr=", 0
ecp_s_bl_ctl:    db " ctl1=", 0
ecp_s_bl_ctl2:   db " ctl2=", 0
ecp_s_bl_tail:   db " [power.backlight]", 13, 10, 0
ecp_k_lid:     db " LID=", 0
ecp_k_warn:    db " BAT_WARN=", 0
ecp_k_warn_pct: db " pct=", 0
ecp_s_warn:    db "[PAOS64] power: battery warning ", 0
ecp_s_warn_tail: db " [power.battery.warn]", 13, 10, 0
ecp_v_none:    db "none", 0
ecp_v_low:     db "low", 0
ecp_v_critical: db "critical", 0
ecp_k_bl_duty: db " BL_DUTY=", 0
ecp_k_bl_max:  db " BL_MAX=", 0
ecp_k_bl_pct:  db " BL_PCT=", 0
ecp_v_open:    db "open", 0
ecp_v_closed:  db "closed", 0
ecp_s_init:   db "[PAOS64] power: EC backend ", 0
ecp_s_ports:  db " data=", 0
ecp_s_cmd:    db " cmd=", 0
ecp_s_pm1:    db " pm1a_sts=", 0
ecp_s_sci:    db " sci_en=", 0
ecp_s_line:   db " ->", 0
ecp_s_tail:   db " [power.ec]", 13, 10, 0
ecp_k_ac:     db " AC=", 0
ecp_k_bat:    db " BAT=", 0
ecp_k_pct:    db " BAT_PCT=", 0
ecp_k_state:  db " BAT_STATE=", 0
ecp_k_rem:    db " BAT_REM=", 0
ecp_k_full:   db " BAT_FULL=", 0
ecp_k_design: db " BAT_DESIGN=", 0
ecp_k_design_mv: db " BAT_DESIGN_MV=", 0
ecp_k_mv:     db " BAT_MV=", 0
ecp_k_rate:   db " BAT_RATE=", 0
ecp_k_unit:   db " BAT_UNIT=mAh", 0          ; ECG9: _BIF power unit 1 (mA/mAh, mV)
ecp_k_pwrbtn: db " PWRBTN=", 0
ecp_v_unknown: db "unknown", 0
ecp_v_idle:   db "idle", 0
ecp_v_discharging: db "discharging", 0
ecp_v_charging: db "charging", 0

; Independent group validity. Never/clock-loss ages use -1; ordinary failures
; retain last successful timestamps for diagnostics, never the failed values.
align 8
ecp_attempt_ms: dq 0
ecp_last_clock_ms: dq 0
ecp_ac_sample_ms: dq 0
ecp_bat_sample_ms: dq 0
ecp_lid_sample_ms: dq 0
ecp_lid_age_ms: dq -1
ecp_ac_age_ms: dq -1
ecp_bat_age_ms: dq -1
ecp_attempt_clock: db 0
ecp_ac_fresh: db ECP_F_NEVER
ecp_bat_fresh: db ECP_F_NEVER
ecp_lid_fresh: db ECP_F_NEVER
ecp_fresh_names:
    db "never",0,0,0
    db "valid",0,0,0
    db "absent",0,0
    db "failed",0,0
    db "expired",0
    db "clock",0,0,0
ecp_k_ac_fresh: db " AC_FRESH=",0
ecp_k_ac_age: db " AC_AGE_MS=",0
ecp_k_bat_fresh: db " BAT_FRESH=",0
ecp_k_bat_age: db " BAT_AGE_MS=",0
ecp_k_lid_fresh: db " LID_FRESH=",0
ecp_k_lid_age: db " LID_AGE_MS=",0
ecp_k_ac_attempt: db " AC_ATTEMPT_MS=",0
ecp_k_bat_attempt: db " BAT_ATTEMPT_MS=",0

; Cooperative sampler: private raw bytes; published only at terminal boundary.
align 8
ecp_sample_desc: dq 0
ecp_sample_last_ms: dq 0
ecp_sample_started_ms: dq 0
ecp_sample_data_port: dw 0
ecp_sample_cmd_port: dw 0
ecp_sample_steps: dd 0
ecp_sample_cleanup: dd 0
ecp_sync_address: db 0                  ; captured synchronous RD address
ecp_sync_op: db 0                       ; 0 RD, FF sole select, FE query
ecp_sample_state: db 0                     ; 0 idle, 1 pending, 2 blocked/uncertain custody
ecp_sample_op: db 0
ecp_sample_phase: db 0                    ; drain, command, address, response/value, write-consumed
ecp_sample_polls: db 0
ecp_sample_drained: db 0
ecp_sample_discard: db 0
ecp_sample_clock_bad: db 0
ecp_sample_ac_done: db 0
ecp_sample_retries: db 0                  ; one bounded retained-handshake recovery
ecp_init_async: db 0
ecp_sample_raw: times 17 db 0
; {captured descriptor byte offset, high-byte delta}; FF means select BAT0.
ecp_sample_ops:
    db ecp_desc.acbat_reg,0, ecp_desc.flag_reg,0, 0xFF,0, ecp_desc.state_reg,0
    db ecp_desc.rate_w,0, ecp_desc.rate_w,1, ecp_desc.rem_w,0, ecp_desc.rem_w,1
    db ecp_desc.mv_w,0, ecp_desc.mv_w,1, 0xFF,0
    db ecp_desc.design_w,0, ecp_desc.design_w,1, ecp_desc.full_w,0, ecp_desc.full_w,1
    db ecp_desc.dmv_w,0, ecp_desc.dmv_w,1
ecp_sample_names: db "idle",0,0,0,0, "pending",0, "blocked",0
ecp_k_sample: db " EC_SAMPLE=",0

; Shared cooperative EC rail: intent queues never own a hardware handshake.
align 8
ecp_lid_confirm_seq: dq 0
ecp_lid_confirm_id: dq 0
ecp_lid_confirm_ms: dq 0
ecp_sample_lid_id: dq 0
ecp_sample_kind: db 0                   ; BAT, poll, raw confirmation, baseline, sync tail
ecp_battery_due: db 0
ecp_lid_due: db 0
ecp_lid_init_due: db 0
ecp_lid_change_ready: db 0
ecp_lid_baseline_ready: db 0
ecp_lid_has_read: db 0
ecp_lid_confirm_queued: db 0
ecp_lid_confirm_state: db 0             ; 0 none,1 pending,2 complete,3 failed
ecp_lid_confirm_value: db ECP_UNKNOWN8
ecp_lid_ops: db 0xFE,0, ecp_desc.evt_word,0, ecp_desc.evt_word,1, ecp_desc.lid_reg,0
