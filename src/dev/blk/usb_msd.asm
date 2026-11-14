;; MODULE dev/blk/usb_msd
;; LAYER 3
;; EXPORTS usb_msd_power_quiesce, usb_msd_power_release, usb_msd_power_snapshot, msd_census_model, msd_last_sense, msd_tur_attempts, usb_msd_init, usb_msd_dev, msd_bound, msd_state, msd_port, msd_lba_max, msd_block_size, msd_cmds, msd_cmd_fail, msd_cmd_refused, msd_write_refused, msd_flush_no_cache, msd_dead, msd_owned_skips
;; IMPORTS boot/native_driver_gate, boot/native_driver_preload, usb/enum, fs/blockdev, dev/usb/xhci, dev/usb/hid, dev/net/ax88179, dev/net/ax88179b, dev/net/cdc_ecm, boot/serial, core/time
;; CAPS dma
;; OWNER saga:storage
; ============================================================================
; dev/blk/usb_msd.asm — USB mass-storage Bulk-Only Transport block backend
; (Try/Install K rung W3; ported from the MSI spoke's src/dev/blk/usb_msd.asm,
; Task3486). Write and flush: Peter 87106, removable FAT32/exFAT is read/write.
;
; WHAT IT IS: a pure class consumer of the enumeration seam (usb/enum) and the
; xHCI endpoint seam (usbhc_ops.control / .configure_ep / .bulk_in /
; .bulk_out). It runs from the enumeration adapter (usb_hid_enum_selftest),
; right after enumeration and BEFORE usb_hid_init: in QEMU, every synchronous
; EP0 control transfer times out once usb_hid_init has run (no completion
; event, on every slot; the unpatched cdc_ecm probe hits it too), while bulk
; endpoints keep working. It walks the enumerated device table for the FIRST
; device that
;   * no other driver owns (usb_hid_port_owned / ax88179_port_owned /
;     cdc_ecm_port_owned, defensive: they bind later in today's order), and
;   * is a PURE mass-storage device: every interface of its configuration is
;     class 08 / subclass 06 (SCSI transparent) / protocol 50 (BOT), so a
;     composite device or any interface another class driver would claim
;     (HID, CDC, vendor) leaves the whole device to its owner;
; with a bulk IN and a bulk OUT endpoint on that interface. It then:
;   SET_CONFIGURATION, configures the two bulk pipes, INQUIRY, TEST UNIT
;   READY (bounded retries), READ CAPACITY(10), bounded read-only write-protection
;   header -> registers "usbmsd0" with actual WP flags.
; The MSI spoke's root-8 claim becomes this class bind.
;
; COMMANDS:
;   * msd_cmd issues only INQUIRY (12h), TEST UNIT READY (00h), REQUEST SENSE
;     (03h), the initial exact MODE SENSE(6) header (1Ah), READ CAPACITY(10)
;     (25h), READ(10) (28h), WRITE(10) (2Ah) and
;     SYNCHRONIZE CACHE(10) (35h); any other opcode is refused before a CBW
;     leaves. WRITE(10) is the only data-OUT stage and must move exactly the
;     length its CDB names; SYNCHRONIZE CACHE carries no data.
;   * REQUEST SENSE (0005b) during bind follows only a TEST UNIT READY that
;     reported CHECK CONDITION. UNIT ATTENTION (key 6) or NOT READY / becoming
;     ready (2/04/01) is retried, at most MSD_TUR_RETRIES TURs within
;     MSD_TUR_BUDGET_US; every other sense fails closed (no reset of any kind).
;   * The block upper half and storage_access still gate every write: a stick
;     classifies SENSITIVE, and implicit writers never reach this backend.
;
; FAULT RULE: fail closed. A CBW that does not leave, a data or CSW stage that
; fails or comes up short, a CSW with a bad signature/tag/status, or a write CSW
; that reports residue marks the device dead; every later I/O returns -1. Nothing
; is replayed: a failed write may already have reached the media. No controller
; reset, no port reset, no BOT reset, no CLEAR_FEATURE.
; A command the device fails with CSW status 1 returns -1 and reads its sense
; (msd_classify_failure): after bind, a UNIT ATTENTION or no medium means the
; media or its cache are no longer the ones this boot saw, so the device goes
; dead; DATA PROTECT or unreadable sense turns it read-only; anything else
; leaves it alive.
;
; Registered at PRIO_DOMAIN: a USB stick never outranks a native boot disk.
; ============================================================================

MSD_CFGBUF_SZ        equ 256
MSD_MAX_XFER         equ 2048            ; XHCI_INTR_REPORT_BYTES: one bulk transfer
MSD_SECTORS_PER_CMD  equ 4               ; 4 * 512 = MSD_MAX_XFER
MSD_TUR_RETRIES      equ 5               ; 0005b: <= 5 TEST UNIT READY attempts ...
MSD_TUR_BUDGET_US    equ 2000000         ; ... within <= 2 s in total
MSD_TUR_DELAY_US     equ 300000
MSD_SENSE_LEN        equ 18
MSD_SK_NOT_READY     equ 0x02
MSD_SK_UNIT_ATTN     equ 0x06
MSD_ASC_NOT_READY    equ 0x04
MSD_ASCQ_BECOMING    equ 0x01
MSD_SK_ILLEGAL       equ 0x05
MSD_SK_DATA_PROTECT  equ 0x07
MSD_ASC_INVALID_OP   equ 0x20
MSD_ASC_NO_MEDIUM    equ 0x3A
MSD_CSW_ATTEMPTS     equ 6
MSD_CSW_ATTEMPTS_WRITE equ 100           ; 30 s at the HC's 300 ms: flash may program this long
MSD_CBW_SIG          equ 0x43425355      ; 'USBC'
MSD_CSW_SIG          equ 0x53425355      ; 'USBS'
MSD_IF_CLASS_MSC     equ 0x08
MSD_IF_SUB_SCSI      equ 0x06
MSD_IF_PROTO_BOT     equ 0x50
MSD_DT_INTERFACE     equ 0x04
MSD_DT_ENDPOINT      equ 0x05
MSD_OP_TUR           equ 0x00
MSD_OP_REQ_SENSE     equ 0x03
MSD_OP_INQUIRY       equ 0x12
MSD_OP_MODE_SENSE6   equ 0x1A
MSD_OP_READ_CAP10    equ 0x25
MSD_OP_READ10        equ 0x28
MSD_OP_WRITE10       equ 0x2A
MSD_OP_SYNC10        equ 0x35
; msd_state: where the bind stopped (reported in the serial line)
MSD_ST_NONE          equ 0
MSD_ST_CONFIG        equ 1
MSD_ST_SETCFG        equ 2
MSD_ST_EP            equ 3
MSD_ST_INQUIRY       equ 4
MSD_ST_TUR           equ 5
MSD_ST_CAPACITY      equ 6
MSD_ST_REGISTER      equ 7
MSD_ST_BOUND         equ 8
MSD_ST_PROTECTION    equ 9

; usb_msd_init — bind at most one unowned BOT device; never wedges boot.
usb_msd_init:
%ifdef PAOS_LAB_USB_MSD_DUMP
    ; The optional upper-half read is a separate ordinary request after bind.
    ; Keep it outside the bind's admission, so blk_read can enter normally.
    xor eax,eax
    mov r10d,1
    lock cmpxchg [rel msd_io_gate],r10d
    jne .busy
    sub rsp,8
    call usb_msd_init_active
    mov dword [rel msd_io_gate],0
    cmp byte [rel msd_bound],1
    jne .out
    call msd_lab_dump
.out:
    add rsp,8
    ret
.busy:
    mov rax,-1
    ret
%else
    lea rax,[rel usb_msd_init_active]
    jmp msd_io_enter
%endif
usb_msd_init_active:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov dword [rel msd_bind_result],0 ; unknown until actual scan completes
    mov  dword [rel msd_inquiry_bytes], 0
    mov  byte [rel msd_bound], 0
    mov  byte [rel msd_dead], 0
    mov  byte [rel msd_wp], 0          ; no write-protection reply yet
    mov  byte [rel msd_state], MSD_ST_NONE
    call usb_dev_count
    mov  r15d, eax
    cmp eax,USB_MAX_DEV
    ja .scan_unavailable
    xor  ebx, ebx
.device:
    cmp  ebx, r15d
    jae  .none
    cmp  ebx, USB_MAX_DEV
    jae  .none
    mov  edi, ebx
    call usb_dev_is_null
    test eax, eax
    jnz  .next
    mov  edi, ebx
    call usb_dev_hc
    test rax, rax
    jz   .next
    mov  r12, rax
    mov  edi, ebx
    call usb_dev_addr
    test eax, eax
    jz   .next
    mov  r13d, eax
    ; Policy precedes even the first config request or ownership record.
    mov edi, ebx
    call usb_msd_policy_admit
    test eax, eax
    jnz .next
    ; never take a device another hub driver already owns
    mov  rdi, r12
    mov  esi, r13d
    call usb_hid_port_owned
    test eax, eax
    jnz  .owned
    mov  rdi, r12
    mov  esi, r13d
    call ax88179_port_owned
    test eax, eax
    jnz  .owned
    call ax88179b_port_owned
    test eax, eax
    jnz  .owned
    mov  rdi, r12
    mov  esi, r13d
    call cdc_ecm_port_owned
    test eax, eax
    jnz  .owned
    mov  [rel msd_hc], r12
    mov  rax, [r12 + dev.ops]
    mov  [rel msd_hcops], rax
    mov  [rel msd_port], r13b
    mov  edi, ebx
    call usb_msd_owned_record
    mov  byte [rel msd_state], MSD_ST_CONFIG
    call msd_get_config
    test eax, eax
    jz   .next                          ; read-only probe failed: try the next device
    mov  edi, eax
    call msd_walk_config
    test eax, eax
    jz   .next                          ; not a BOT stick
    ; --- this device is the candidate: bind it or fail closed ---
    mov  byte [rel msd_state], MSD_ST_SETCFG
    call msd_set_configuration
    test rax, rax
    js   .fail
    mov  byte [rel msd_state], MSD_ST_EP
    lea  rdx, [rel msd_in_ep_desc]
    call msd_configure_ep
    test rax, rax
    jnz  .fail
    lea  rdx, [rel msd_out_ep_desc]
    call msd_configure_ep
    test rax, rax
    jnz  .fail
    mov  byte [rel msd_state], MSD_ST_INQUIRY
    call msd_inquiry_active
    test eax, eax
    jnz  .fail
    mov  byte [rel msd_state], MSD_ST_TUR
    call msd_tur_ready_active
    test eax, eax
    jnz  .fail
.capacity:
    mov  byte [rel msd_state], MSD_ST_CAPACITY
    call msd_read_capacity_active
    test eax, eax
    jnz  .fail
    mov  byte [rel msd_state], MSD_ST_PROTECTION
    call msd_write_protection_active
    test eax, eax
    jnz  .fail
    mov  byte [rel msd_state], MSD_ST_REGISTER
    call msd_register
    cmp  rax, REG_OK
    jne  .fail
    mov  byte [rel msd_state], MSD_ST_BOUND
    mov  byte [rel msd_bound], 1
    mov dword [rel msd_bind_result],2
    lea  rdi, [rel str_msd_bound]
    call serial_string
    movzx edi, byte [rel msd_port]
    call serial_hex64
    lea  rdi, [rel str_msd_lba]
    call serial_string
    mov  rdi, [rel msd_lba_max]
    call serial_hex64
    lea  rdi, [rel str_msd_tur]
    call serial_string
    mov  edi, [rel msd_tur_attempts]
    call serial_hex64
    lea  rdi, [rel str_msd_sense]
    call serial_string
    mov  edi, [rel msd_last_sense]
    call serial_hex64
    lea  rdi, [rel str_msd_bound_tail]
    call serial_string
    jmp  .out
.scan_unavailable:
    mov dword [rel msd_bind_result],3
    jmp .out
.owned:
    inc  dword [rel msd_owned_skips]
.next:
    inc  ebx
    jmp  .device
.none:
    mov dword [rel msd_bind_result],1 ; completed actual class scan, no owned MSD
    lea  rdi, [rel str_msd_absent]
    call serial_string
    jmp  .out
.fail:
    mov dword [rel msd_bind_result],3
    mov  byte [rel msd_dead], 1
    lea  rdi, [rel str_msd_failed]
    call serial_string
    movzx edi, byte [rel msd_state]
    call serial_hex64
    lea  rdi, [rel str_msd_tur]
    call serial_string
    mov  edi, [rel msd_tur_attempts]
    call serial_hex64
    lea  rdi, [rel str_msd_sense]
    call serial_string
    mov  edi, [rel msd_last_sense]
    call serial_hex64
    lea  rdi, [rel str_msd_failed_tail]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; usb_msd_policy_admit(EDI=enumeration index) -> EAX 0/-1.
; R12=the exact HC from that row, preserved by the caller.
; Normal/network_guest retain existing probe order. boot_only requires exact
; registered HC BDF AND exact boot USB port chain; upstream hubs do not qualify.
; RAM-only admission, no instance switch, MMIO, control transfer or claim.
usb_msd_policy_admit:
    push rbx
    mov ebx, edi
    cmp qword [rel native_driver_selected_policy], 0
    je .ordinary
    cmp qword [rel native_driver_selected_policy], 2
    je .ordinary
    mov rdi, r12                       ; exact HC returned for this enum row
    call xhci_storage_bdf
    mov rsi, rax
    mov edi, 5
    call native_driver_gate
    jc .deny
    mov edi, ebx
    call usb_dev_boot_path_exact
    cmp eax, 1
    jne .deny
    xor eax, eax
    pop rbx
    ret
.ordinary:
    mov edi, 5
    mov rsi, -1
    call native_driver_gate
    jc .deny
    xor eax, eax
    pop rbx
    ret
.deny:
    mov eax, -1
    pop rbx
    ret

; usb_msd_dev() -> RAX = the registered dev* (0 when nothing is bound)
usb_msd_dev:
    xor  eax, eax
    cmp  byte [rel msd_bound], 1
    jne  .out
    lea  rax, [rel msd_dev]
.out:
    ret

; ---------------------------------------------------------------------------
; control plane (read-only probes + SET_CONFIGURATION of the bound candidate)
; ---------------------------------------------------------------------------
msd_control:
    mov  rdi, [rel msd_hc]
    movzx edx, byte [rel msd_port]
    mov  rax, [rel msd_hcops]
    jmp  [rax + usbhc_ops.control]

; msd_get_config() -> EAX = total configuration bytes read into msd_cfgbuf (0 = fail)
msd_get_config:
    push rbx
    lea  rdi, [rel msd_setup]
    mov  byte [rdi + usb_setup.bmRequestType], 0x80
    mov  byte [rdi + usb_setup.bRequest], 6           ; GET_DESCRIPTOR
    mov  word [rdi + usb_setup.wValue], 0x0200        ; CONFIGURATION, index 0
    mov  word [rdi + usb_setup.wIndex], 0
    mov  word [rdi + usb_setup.wLength], 9
    mov  rsi, rdi
    lea  rcx, [rel msd_cfgbuf]
    mov  r8d, MSD_CFGBUF_SZ
    call msd_control
    cmp  rax, 9
    jne  .fail
    lea  rbx, [rel msd_cfgbuf]
    cmp  byte [rbx + 1], 2
    jne  .fail
    movzx eax, word [rbx + 2]                          ; wTotalLength
    cmp  eax, 9
    jb   .fail
    cmp  eax, MSD_CFGBUF_SZ
    ja   .fail
    mov  ebx, eax
    lea  rdi, [rel msd_setup]
    mov  [rdi + usb_setup.wLength], ax
    mov  rsi, rdi
    lea  rcx, [rel msd_cfgbuf]
    mov  r8d, MSD_CFGBUF_SZ
    call msd_control
    cmp  eax, ebx
    jne  .fail
    mov  eax, ebx
    pop  rbx
    ret
.fail:
    xor  eax, eax
    pop  rbx
    ret

; msd_walk_config(EDI = config length) -> EAX 1 when one BOT interface (08/06/50,
;   alternate 0) with a bulk IN and a bulk OUT endpoint was found; fills
;   msd_config / msd_iface / msd_in_ep / msd_out_ep and the two endpoint copies.
msd_walk_config:
    push rbx
    push r14
    mov  byte [rel msd_in_valid], 0
    mov  byte [rel msd_out_valid], 0
    mov  byte [rel msd_in_bot], 0
    mov  byte [rel msd_foreign_if], 0
    lea  rbx, [rel msd_cfgbuf]
    mov  al, [rbx + 5]                 ; bConfigurationValue
    mov  [rel msd_config], al
    mov  r14d, edi
    lea  r14, [rbx + r14]
.wl:
    cmp  rbx, r14
    jae  .done
    movzx eax, byte [rbx]              ; bLength
    test eax, eax
    jz   .done
    lea  rdx, [rbx + rax]
    cmp  rdx, r14
    ja   .done                         ; a descriptor may not cross the blob
    cmp  byte [rbx + 1], MSD_DT_INTERFACE
    jne  .not_if
    mov  byte [rel msd_in_bot], 0
    cmp  eax, 9
    jb   .foreign
    cmp  byte [rbx + 5], MSD_IF_CLASS_MSC
    jne  .foreign                      ; any non-BOT interface: not a pure MSC device
    cmp  byte [rbx + 6], MSD_IF_SUB_SCSI
    jne  .foreign
    cmp  byte [rbx + 7], MSD_IF_PROTO_BOT
    jne  .foreign
    cmp  byte [rbx + 3], 0             ; alternate setting 0 only
    jne  .next
    cmp  byte [rel msd_in_valid], 1    ; a complete pair already found: stop looking
    jne  .if_take
    cmp  byte [rel msd_out_valid], 1
    je   .next
.if_take:
    mov  al, [rbx + 2]
    mov  [rel msd_iface], al
    mov  byte [rel msd_in_bot], 1
    mov  byte [rel msd_in_valid], 0    ; endpoints belong to THIS interface
    mov  byte [rel msd_out_valid], 0
    jmp  .next
.not_if:
    cmp  byte [rbx + 1], MSD_DT_ENDPOINT
    jne  .next
    cmp  byte [rel msd_in_bot], 1
    jne  .next
    cmp  eax, 7
    jb   .next
    movzx edx, byte [rbx + 3]          ; bmAttributes
    and  edx, USB_EP_XFER_MASK
    cmp  edx, USB_EP_XFER_BULK
    jne  .next
    movzx eax, byte [rbx + 2]          ; bEndpointAddress
    test al, USB_EP_DIR_IN
    jz   .out_ep
    cmp  byte [rel msd_in_valid], 1
    je   .next
    mov  [rel msd_in_ep], al
    mov  byte [rel msd_in_valid], 1
    lea  rdi, [rel msd_in_ep_desc]
    call msd_copy_ep
    jmp  .next
.out_ep:
    cmp  byte [rel msd_out_valid], 1
    je   .next
    mov  [rel msd_out_ep], al
    mov  byte [rel msd_out_valid], 1
    lea  rdi, [rel msd_out_ep_desc]
    call msd_copy_ep
    jmp  .next
.foreign:
    mov  byte [rel msd_foreign_if], 1
.next:
    movzx eax, byte [rbx]
    add  rbx, rax
    jmp  .wl
.done:
    xor  eax, eax
    cmp  byte [rel msd_foreign_if], 0
    jne  .ret                          ; composite / other-class device: never ours
    cmp  byte [rel msd_in_valid], 1
    jne  .ret
    cmp  byte [rel msd_out_valid], 1
    jne  .ret
    mov  eax, 1
.ret:
    pop  r14
    pop  rbx
    ret

; msd_copy_ep(RDI = 7-byte destination): copy the endpoint descriptor at RBX.
msd_copy_ep:
    mov  eax, [rbx]
    mov  [rdi], eax
    mov  ax, [rbx + 4]
    mov  [rdi + 4], ax
    mov  al, [rbx + 6]
    mov  [rdi + 6], al
    ret

; msd_set_configuration() -> RAX = control status (>= 0 accepted)
msd_set_configuration:
    lea  rdi, [rel msd_setup]
    mov  byte [rdi + usb_setup.bmRequestType], 0x00
    mov  byte [rdi + usb_setup.bRequest], 9           ; SET_CONFIGURATION
    movzx eax, byte [rel msd_config]
    mov  [rdi + usb_setup.wValue], ax
    mov  word [rdi + usb_setup.wIndex], 0
    mov  word [rdi + usb_setup.wLength], 0
    mov  rsi, rdi
    xor  ecx, ecx
    xor  r8d, r8d
    jmp  msd_control

; msd_configure_ep(RDX = usb_endpoint_desc*) -> RAX 0/-1 through the HC seam
msd_configure_ep:
    mov  rdi, [rel msd_hc]
    movzx esi, byte [rel msd_port]
    mov  rax, [rel msd_hcops]
    jmp  [rax + usbhc_ops.configure_ep]

; One nonblocking admission word: 0 idle, 1 complete ordinary request (or the
; final release publication),
; 2 terminal fence. RAX=internal request body. All arguments and caller IF are
; retained. A busy caller cannot touch shared CDB/CBW/CSW or change ownership.
msd_io_enter:
    mov r11,rax
    xor eax,eax
    mov r10d,1
    lock cmpxchg [rel msd_io_gate],r10d
    jne .busy
    sub rsp,8
    call r11
    add rsp,8
    mov dword [rel msd_io_gate],0
    ret
.busy:
    mov rax,-1
    ret

; ---------------------------------------------------------------------------
; Bulk-Only Transport
; ---------------------------------------------------------------------------
; msd_bulk(EDI=endpoint address, RSI=buf, EDX=len, ECX=dir 1 IN / 0 OUT) -> RAX len / -1
msd_bulk:
    mov  eax, ecx
    mov  r8d, edx
    mov  rcx, rsi
    mov  edx, edi
    movzx esi, byte [rel msd_port]
    mov  rdi, [rel msd_hc]
    mov  r9, [rel msd_hcops]
    test eax, eax
    jz   .out
    jmp  [r9 + usbhc_ops.bulk_in]
.out:
    jmp  [r9 + usbhc_ops.bulk_out]

; msd_cmd(RDI=cdb, ESI=cdb length, EDX=data length, RCX=data buffer)
;   -> EAX 0 = CSW status 0, 1 = CSW status "failed", -1 = refused/transport/phase.
;   Only the opcodes in the header may leave. The opcode sets the data direction:
;   WRITE(10) is OUT, every other data stage is IN (msd_last_data_len = bytes moved).
;   Any transport or phase failure marks the device dead (no reset of any kind).
msd_cmd:
    lea rax,[rel msd_cmd_active]
    jmp msd_io_enter
msd_cmd_active:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15, rcx
    xor  ebp, ebp                      ; 0 no media change, 1 WRITE(10), 2 SYNCHRONIZE CACHE
    mov  dword [rel msd_last_data_len], 0
    cmp  byte [rel msd_dead], 1
    je   .refused
    movzx eax, byte [r12]
    cmp  al, MSD_OP_TUR
    je   .op_ok
    cmp  al, MSD_OP_REQ_SENSE
    je   .op_ok
    cmp  al, MSD_OP_INQUIRY
    je   .op_ok
    cmp  al, MSD_OP_MODE_SENSE6
    je   .mode_sense
    cmp  al, MSD_OP_READ_CAP10
    je   .op_ok
    cmp  al, MSD_OP_READ10
    je   .op_ok
    test dword [rel msd_dev + dev.flags], BLKF_RO
    jnz  .refused
    cmp  al, MSD_OP_SYNC10
    jne  .not_sync
    test r14d, r14d
    jnz  .refused
    mov  ebp, 2
    jmp  .op_ok
.not_sync:
    cmp  al, MSD_OP_WRITE10
    jne  .refused                      ; the allowlist
    movzx eax, word [r12 + 7]          ; blocks, big-endian
    xchg al, ah
    shl  eax, 9
    test eax, eax
    jz   .refused
    cmp  eax, r14d                     ; the CBW and the CDB name one length
    jne  .refused
    mov  ebp, 1
    jmp  .op_ok
.mode_sense:
    ; Only the pre-registration read-only header probe, never MODE SELECT.
    cmp  byte [rel msd_bound], 0
    jne  .refused
    cmp  r13d, 6
    jne  .refused
    cmp  r14d, 4
    jne  .refused
    cmp  dword [r12], 0x003F081A       ; opcode, DBD, current/all pages, subpage0
    jne  .refused
    cmp  word [r12 + 4], 4            ; allocation4, control0
    jne  .refused
.op_ok:
    cmp  r13d, 16
    ja   .refused
    cmp  r14d, MSD_MAX_XFER
    ja   .refused
    inc  qword [rel msd_cmds]
    ; --- CBW (31 bytes) ---
    lea  rdi, [rel msd_cbw]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    mov  [rdi + 16], rax
    mov  [rdi + 24], rax
    mov  dword [rdi], MSD_CBW_SIG
    inc  dword [rel msd_tag]
    mov  eax, [rel msd_tag]
    mov  [rdi + 4], eax
    mov  [rdi + 8], r14d               ; dCBWDataTransferLength
    xor  eax, eax
    test r14d, r14d
    jz   .flags
    cmp  ebp, 1
    je   .flags                        ; data-OUT
    mov  al, 0x80                      ; data-IN
.flags:
    mov  [rdi + 12], al
    mov  byte [rdi + 13], 0            ; LUN 0
    mov  [rdi + 14], r13b
    xor  ecx, ecx
.cdb:
    cmp  ecx, r13d
    jae  .cbw_send
    mov  al, [r12 + rcx]
    mov  [rdi + rcx + 15], al
    inc  ecx
    jmp  .cdb
.cbw_send:
    movzx edi, byte [rel msd_out_ep]
    lea  rsi, [rel msd_cbw]
    mov  edx, 31
    xor  ecx, ecx
    call msd_bulk
    cmp  rax, 31
    jne  .transport
    ; --- data stage ---
    test r14d, r14d
    jz   .csw
    cmp  ebp, 1
    jne  .data_in
    movzx edi, byte [rel msd_out_ep]
    mov  rsi, r15
    mov  edx, r14d
    xor  ecx, ecx
    call msd_bulk
    cmp  rax, r14
    jne  .transport                    ; a stalled, failed or short write: fail closed
    mov  [rel msd_last_data_len], r14d
    jmp  .csw
.data_in:
    movzx edi, byte [rel msd_in_ep]
    mov  rsi, r15
    mov  edx, r14d
    mov  ecx, 1
    call msd_bulk
    test rax, rax
    js   .transport                    ; a stalled/failed data stage: fail closed
    mov  [rel msd_last_data_len], eax
.csw:
    ; --- CSW (13 bytes), bounded polls ---
    mov  ebx, MSD_CSW_ATTEMPTS
    test ebp, ebp
    jz   .csw_try
    mov  ebx, MSD_CSW_ATTEMPTS_WRITE
.csw_try:
    movzx edi, byte [rel msd_in_ep]
    lea  rsi, [rel msd_csw]
    mov  edx, 13
    mov  ecx, 1
    call msd_bulk
    cmp  rax, 13
    je   .csw_have
    dec  ebx
    jnz  .csw_try
    jmp  .transport
.csw_have:
    lea  rsi, [rel msd_csw]
    cmp  dword [rsi], MSD_CSW_SIG
    jne  .transport
    mov  eax, [rsi + 4]
    cmp  eax, [rel msd_tag]
    jne  .transport
    movzx eax, byte [rsi + 12]
    mov  [rel msd_last_csw_status], eax
    test eax, eax
    jnz  .csw_status
    cmp  ebp, 1
    jne  .out
    cmp  dword [rsi + 8], 0            ; dCSWDataResidue: all of it, or it did not happen
    je   .out
    jmp  .transport
.csw_status:
    cmp  eax, 1
    jne  .transport                    ; 2 = phase error
    inc  qword [rel msd_cmd_fail]
    jmp  .out
.transport:
    inc  qword [rel msd_cmd_fail]
    mov  byte [rel msd_dead], 1
    ; The terminal BOT state must also exclude this backend from class selection.
    ; A SCSI status-1 command failure and caller refusals do not take this edge.
    mov  dword [rel msd_dev + dev.health], HEALTH_DEAD
    mov  eax, -1
    jmp  .out
.refused:
    inc  dword [rel msd_cmd_refused]
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; msd_inquiry() -> EAX 0 when a direct-access device answered
msd_inquiry:
    lea rax,[rel msd_inquiry_active]
    jmp msd_io_enter
msd_inquiry_active:
    mov  dword [rel msd_inquiry_bytes], 0
    lea  rdi, [rel msd_cdb]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    mov  byte [rdi], MSD_OP_INQUIRY
    mov  byte [rdi + 4], 36
    mov  esi, 6
    mov  edx, 36
    lea  rcx, [rel msd_inq]
    call msd_cmd_active
    test eax, eax
    jnz  .fail
    cmp  dword [rel msd_last_data_len], 5
    jb   .fail
    movzx eax, byte [rel msd_inq]
    and  eax, 0x1F
    test eax, eax                      ; peripheral device type 0 = direct access
    jnz  .fail
    mov  eax, [rel msd_last_data_len]
    mov  [rel msd_inquiry_bytes], eax
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

; msd_test_unit_ready() -> EAX 0 ready, 1 not ready yet, -1 transport (dead).
;   A CHECK CONDITION (1) is classified by msd_tur_ready through REQUEST SENSE.
msd_test_unit_ready:
    lea rax,[rel msd_test_unit_ready_active]
    jmp msd_io_enter
msd_test_unit_ready_active:
    lea  rdi, [rel msd_cdb]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    mov  byte [rdi], MSD_OP_TUR
    mov  esi, 6
    xor  edx, edx
    xor  ecx, ecx
    jmp  msd_cmd_active

; msd_request_sense() -> EAX 0 with msd_last_sense = key<<16 | ASC<<8 | ASCQ from
;   fixed-format sense data (response code 70h/71h), else -1. 18 bytes data-in.
msd_request_sense:
    lea rax,[rel msd_request_sense_active]
    jmp msd_io_enter
msd_request_sense_active:
    lea  rdi, [rel msd_cdb]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    mov  byte [rdi], MSD_OP_REQ_SENSE
    mov  byte [rdi + 4], MSD_SENSE_LEN
    mov  esi, 6
    mov  edx, MSD_SENSE_LEN
    lea  rcx, [rel msd_sense]
    call msd_cmd_active
    test eax, eax
    jnz  .fail
    cmp  dword [rel msd_last_data_len], 14
    jb   .fail
    movzx eax, byte [rel msd_sense]
    and  eax, 0x7F
    cmp  eax, 0x70
    je   .fixed
    cmp  eax, 0x71
    jne  .fail
.fixed:
    movzx eax, byte [rel msd_sense + 2]
    and  eax, 0x0F                     ; sense key
    shl  eax, 16
    movzx ecx, byte [rel msd_sense + 12]   ; ASC
    shl  ecx, 8
    or   eax, ecx
    movzx ecx, byte [rel msd_sense + 13]   ; ASCQ
    or   eax, ecx
    mov  [rel msd_last_sense], eax
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

; msd_tur_ready() -> EAX 0 once TEST UNIT READY passes, else -1 (fail closed).
;   CHECK CONDITION -> REQUEST SENSE; retried only for UNIT ATTENTION (any) or
;   NOT READY / becoming ready (2/04/01), <= MSD_TUR_RETRIES TURs and
;   <= MSD_TUR_BUDGET_US in total. Never a reset.
msd_tur_ready:
    lea rax,[rel msd_tur_ready_active]
    jmp msd_io_enter
msd_tur_ready_active:
    push rbx
    push r12
    mov  dword [rel msd_tur_attempts], 0
    mov  dword [rel msd_last_sense], 0
    call time_monotonic_now_us
    mov  r12, rax                      ; start
.try:
    inc  dword [rel msd_tur_attempts]
    call msd_test_unit_ready_active
    test eax, eax
    jz   .ready
    js   .fail                         ; transport: already marked dead
    call msd_request_sense_active
    test eax, eax
    jnz  .fail
    mov  eax, [rel msd_last_sense]
    mov  ecx, eax
    shr  ecx, 16
    cmp  ecx, MSD_SK_UNIT_ATTN
    je   .retryable
    cmp  eax, (MSD_SK_NOT_READY << 16) | (MSD_ASC_NOT_READY << 8) | MSD_ASCQ_BECOMING
    jne  .fail                         ; any other sense: fail closed
.retryable:
    cmp  dword [rel msd_tur_attempts], MSD_TUR_RETRIES
    jae  .fail
    call time_monotonic_now_us
    sub  rax, r12
    add  rax, MSD_TUR_DELAY_US
    cmp  rax, MSD_TUR_BUDGET_US
    ja   .fail                         ; the next attempt would overrun 2 s
    mov  edi, MSD_TUR_DELAY_US
    call tsc_delay_us
    jmp  .try
.ready:
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; msd_read_capacity() -> EAX 0 when READ CAPACITY(10) reported 512-byte blocks;
;   fills msd_lba_max / msd_block_size.
msd_read_capacity:
    lea rax,[rel msd_read_capacity_active]
    jmp msd_io_enter
msd_read_capacity_active:
    lea  rdi, [rel msd_cdb]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    mov  byte [rdi], MSD_OP_READ_CAP10
    mov  esi, 10
    mov  edx, 8
    lea  rcx, [rel msd_cap]
    call msd_cmd_active
    test eax, eax
    jnz  .fail
    cmp  dword [rel msd_last_data_len], 8
    jne  .fail
    mov  eax, [rel msd_cap]
    bswap eax
    mov  [rel msd_lba_max], rax
    mov  eax, [rel msd_cap + 4]
    bswap eax
    mov  [rel msd_block_size], eax
    cmp  eax, 512
    jne  .fail
    xor  eax, eax
    ret
.fail:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; blk_ops backend
; ---------------------------------------------------------------------------
; One initial read-only WP header, after capacity and before registration.
; WP: 0 unsupported/unknown (prior compatibility), 1 actual RW, 2 actual RO.
; Only explicit unsupported-command sense keeps prior compatibility. A short,
; malformed, residual or otherwise uncertain reply refuses bind. No reset/retry.
msd_write_protection_active:
    lea  rdi, [rel msd_cdb]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    mov  dword [rdi], 0x003F081A
    mov  byte [rdi + 4], 4
    mov  dword [rel msd_mode_header], 0
    mov  esi, 6
    mov  edx, 4
    lea  rcx, [rel msd_mode_header]
    call msd_cmd_active
    test eax, eax
    jnz  .command_failed
    cmp  dword [rel msd_last_data_len], 4
    jne  .fail
    cmp  dword [rel msd_csw + 8], 0
    jne  .fail
    cmp  byte [rel msd_mode_header], 3
    jb   .fail
    cmp  byte [rel msd_mode_header + 3], 0 ; DBD suppressed descriptors
    jne  .fail
    mov  al, [rel msd_mode_header + 2]
    shr  al, 7
    inc  al
    mov  [rel msd_wp], al
    xor  eax, eax
    ret
.command_failed:
    cmp  byte [rel msd_dead], 0
    jne  .fail
    cmp  dword [rel msd_last_csw_status], 1
    jne  .fail
    call msd_request_sense_active
    test eax, eax
    jnz  .fail
    cmp  dword [rel msd_csw + 8], 0
    jne  .fail
    cmp  byte [rel msd_sense + 7], 6  ; declared extent must include ASC/ASCQ
    jb   .fail
    cmp  dword [rel msd_last_sense], (MSD_SK_ILLEGAL << 16) | (MSD_ASC_INVALID_OP << 8)
    je   .unsupported
    cmp  dword [rel msd_last_sense], (MSD_SK_ILLEGAL << 16) | (0x24 << 8)
    jne  .fail
.unsupported:
    xor  eax, eax                     ; not a claim that WP is clear
    ret
.fail:
    mov  eax, -1
    ret

msd_register:
    push rbx
    lea  rbx, [rel msd_ops]
    lea  rax, [rel msd_op_identify]
    mov  [rbx + blk_ops.identify], rax
    lea  rax, [rel msd_op_read]
    mov  [rbx + blk_ops.read], rax
    lea  rax, [rel msd_op_write]
    mov  [rbx + blk_ops.write], rax
    lea  rax, [rel msd_op_flush]
    mov  [rbx + blk_ops.flush], rax
    lea  rbx, [rel msd_info]
    lea  rax, [rel str_msd_name]
    mov  [rbx + blk_info.name], rax
    mov  dword [rbx + blk_info.sector_size], 512
    mov  rax, [rel msd_lba_max]
    mov  [rbx + blk_info.lba_max], rax
    mov  byte  [rbx + blk_info.dma_mask], 64
    mov  byte  [rbx + blk_info.removable], 1
    mov  dword [rbx + blk_info.flags], BLKF_REMOVABLE
    cmp  byte [rel msd_wp], 2
    jne  .info_flags
    or   dword [rbx + blk_info.flags], BLKF_RO
.info_flags:
    mov  dword [rbx + blk_info.unit], 0
    mov  dword [rbx + blk_info.logical_sector_bytes], 512
    mov  dword [rbx + blk_info.physical_sector_bytes], 512
    mov  dword [rbx + blk_info.physical_alignment_bytes], 0
    mov  dword [rbx + blk_info.max_transfer_sectors], 128
    mov  qword [rbx + blk_info.capabilities], BLKCAP_READ | BLKCAP_WRITE | BLKCAP_FLUSH
    mov  qword [rbx + blk_info.media_generation], 1
    lea  rbx, [rel msd_dev]
    lea  rax, [rel msd_ops]
    mov  [rbx + dev.ops], rax
    lea  rax, [rel msd_info]
    mov  [rbx + dev.info], rax
    mov  qword [rbx + dev.priv], 0
    mov  dword [rbx + dev.prio], PRIO_DOMAIN       ; never outranks a native boot disk
    mov  dword [rbx + dev.health], HEALTH_OK
    mov  dword [rbx + dev.class], CLASS_BLOCK
    mov  dword [rbx + dev.flags], 0
    cmp  byte [rel msd_wp], 2
    jne  .dev_flags
    or   dword [rbx + dev.flags], BLKF_RO
.dev_flags:
    lea  rax, [rel str_msd_name]
    mov  [rbx + dev.name], rax
    mov  rdi, rbx
    call blk_register
    cmp rax,REG_OK
    jne .out
    mov rdx,[rel msd_info+blk_info.media_generation]
    mov [rel msd_registered_generation],rdx
.out:
    pop  rbx
    ret

msd_op_identify:
    xor  eax, eax
    ret

; read(self, RSI=lba, RDX=count, RCX=buf) -> RAX 0/-1, READ(10) in 4-sector commands
msd_op_read:
    lea rax,[rel msd_op_read_active]
    jmp msd_io_enter
msd_op_read_active:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    cmp  byte [rel msd_bound], 1
    jne  .fail
.loop:
    test r13, r13
    jz   .ok
    mov  ebx, MSD_SECTORS_PER_CMD
    cmp  r13, rbx
    jae  .n_ok
    mov  ebx, r13d
.n_ok:
    mov  rax, r12
    add  rax, rbx
    dec  rax
    shr  rax, 32
    jnz  .fail                         ; READ(10) addresses 32-bit LBAs only
    lea  rdi, [rel msd_cdb]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    mov  byte [rdi], MSD_OP_READ10
    mov  eax, r12d
    bswap eax
    mov  [rdi + 2], eax                ; LBA, big-endian
    mov  eax, ebx
    xchg al, ah
    mov  [rdi + 7], ax                 ; transfer length, big-endian
    mov  esi, 10
    mov  edx, ebx
    shl  edx, 9
    mov  rcx, r14
    call msd_cmd_active
    test eax, eax
    jz   .moved
    cmp  eax, 1
    jne  .fail
    call msd_classify_failure
    jmp  .fail
.moved:
    mov  eax, ebx
    shl  eax, 9
    cmp  [rel msd_last_data_len], eax
    jne  .fail
    add  r12, rbx
    sub  r13, rbx
    add  r14, rax
    jmp  .loop
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; msd_classify_failure() after a CSW status 1: reads sense and narrows what may
;   still reach this device. Clobbers caller-saved.
msd_classify_failure:
    mov  dword [rel msd_last_sense], 0
    call msd_request_sense_active
    test eax, eax
    jnz  .read_only                    ; unknown state: no more writes on a guess
    mov  eax, [rel msd_last_sense]
    mov  ecx, eax
    shr  ecx, 16
    cmp  ecx, MSD_SK_UNIT_ATTN
    je   .terminal
    cmp  ecx, MSD_SK_DATA_PROTECT
    je   .read_only
    shr  eax, 8
    cmp  eax, (MSD_SK_NOT_READY << 8) | MSD_ASC_NO_MEDIUM
    jne  .out
.terminal:
    mov  byte [rel msd_dead], 1
    mov  dword [rel msd_dev + dev.health], HEALTH_DEAD
    ret
.read_only:
    or   dword [rel msd_info + blk_info.flags], BLKF_RO
    or   dword [rel msd_dev + dev.flags], BLKF_RO
.out:
    ret

; write(self, RSI=lba, RDX=count, RCX=buf) -> RAX 0/-1, WRITE(10) in 4-sector commands.
;   The whole range is checked before the first CBW. Any failure ends the request;
;   earlier chunks may already be on the media and the caller is told -1.
msd_op_write:
    lea rax,[rel msd_op_write_active]
    jmp msd_io_enter
msd_op_write_active:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    cmp  byte [rel msd_bound], 1
    jne  .refused
    test dword [rel msd_dev + dev.flags], BLKF_RO
    jnz  .refused
    test r13, r13
    jz   .ok
    mov  rax, r12
    add  rax, r13
    jc   .refused
    dec  rax
    cmp  rax, [rel msd_lba_max]
    ja   .refused
    shr  rax, 32
    jnz  .refused                      ; WRITE(10) addresses 32-bit LBAs only
.loop:
    test r13, r13
    jz   .ok
    mov  ebx, MSD_SECTORS_PER_CMD
    cmp  r13, rbx
    jae  .n_ok
    mov  ebx, r13d
.n_ok:
    lea  rdi, [rel msd_cdb]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    mov  byte [rdi], MSD_OP_WRITE10
    mov  eax, r12d
    bswap eax
    mov  [rdi + 2], eax                ; LBA, big-endian
    mov  eax, ebx
    xchg al, ah
    mov  [rdi + 7], ax                 ; transfer length, big-endian
    mov  esi, 10
    mov  edx, ebx
    shl  edx, 9
    mov  rcx, r14
    call msd_cmd_active
    test eax, eax
    jz   .moved
    cmp  eax, 1
    jne  .fail
    call msd_classify_failure
    jmp  .fail
.moved:
    mov  eax, ebx
    shl  eax, 9
    add  r12, rbx
    sub  r13, rbx
    add  r14, rax
    jmp  .loop
.ok:
    xor  eax, eax
    jmp  .out
.refused:
    inc  dword [rel msd_write_refused]
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; flush(self) -> RAX 0/-1, SYNCHRONIZE CACHE(10) over the whole device. A stick that
;   answers ILLEGAL REQUEST / invalid opcode has no such command: success, counted in
;   msd_flush_no_cache, since nothing more can be asked of it. Every other failure is -1.
msd_op_flush:
    lea rax,[rel msd_op_flush_active]
    jmp msd_io_enter
msd_op_flush_active:
    cmp  byte [rel msd_bound], 1
    jne  .fail
    lea  rdi, [rel msd_cdb]
    xor  eax, eax
    mov  [rdi], rax
    mov  [rdi + 8], rax
    mov  byte [rdi], MSD_OP_SYNC10
    mov  esi, 10
    xor  edx, edx
    xor  ecx, ecx
    sub  rsp, 8
    call msd_cmd_active
    add  rsp, 8
    test eax, eax
    jz   .out
    cmp  eax, 1
    jne  .fail
    sub  rsp, 8
    call msd_classify_failure
    add  rsp, 8
    mov  eax, [rel msd_last_sense]
    shr  eax, 8
    cmp  eax, (MSD_SK_ILLEGAL << 8) | MSD_ASC_INVALID_OP
    jne  .fail
    inc  dword [rel msd_flush_no_cache]
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret
.out:
    xor  eax, eax
    ret


; Terminal MSD quiescence, called with interrupts in the original caller state.
; EAX: 0 real SYNC completion, 1 completed scan/no owned MSD, 2 active work,
; 3 unavailable/foreign/stale incarnation, 4 dead/failed, 5 unsupported SYNC.
; Successful 0/1 retain gate2 until terminal execution or caller's explicit abort.
; No waiting/replay/reset/reprobe/unregister/owner change. Failed normal BOT may
; already have affected the media; its existing dead/RO effects are preserved.
; 144B snapshot: version,size,result,fence u32; dev/mediaGeneration/HC u64;
; original HCgeneration/port u32; original validated 96B owner query at +48.
usb_msd_power_quiesce:
    push rbx
    push r12
    push r13
    sub rsp,96
    xor eax,eax
    mov edx,2
    lock cmpxchg [rel msd_io_gate],edx
    jne .busy
    lea r12,[rel usb_msd_power_snapshot]
    mov rdi,r12
    xor eax,eax
    mov ecx,18
    rep stosq
    mov dword [r12],1
    mov dword [r12+4],144
    mov dword [r12+8],3
    mov dword [r12+12],2
    call blk_registered_count          ; invalid/cyclic registry is unavailable
    test eax,eax
    js .unavailable
    mov r13d,eax
    cmp byte [rel msd_bound],1
    jne .unbound
    lea rax,[rel msd_dev]
    mov [r12+16],rax
    mov rax,[rel msd_registered_generation]
    mov [r12+24],rax
    mov rax,[rel msd_hc]
    mov [r12+32],rax
    mov eax,[rel msd_bound_hc_generation]
    mov [r12+40],eax
    movzx eax,byte [rel msd_port]
    mov [r12+44],eax
    cmp byte [rel msd_dead],0
    jne .failed
    cmp dword [rel msd_dev+dev.health],HEALTH_OK
    jne .failed
    lea rax,[rel msd_ops]
    cmp [rel msd_dev+dev.ops],rax
    jne .unavailable
    mov rsi,[r12+24]
    test rsi,rsi
    jz .unavailable
    lea rdi,[rel msd_dev]
    lea rdx,[r12+48]
    call usb_msd_owned_query
    test rax,rax
    jnz .unavailable
    mov ebx,[rel msd_flush_no_cache]
    call msd_op_flush_active           ; original opcode, permissions and wire path
    test rax,rax
    jnz .failed
    cmp ebx,[rel msd_flush_no_cache]
    jne .unsupported                  ; legacy flush's unsupported success != completed
    cmp dword [rel msd_last_csw_status],0
    jne .failed
    cmp dword [rel msd_csw+8],0        ; zero data SYNC cannot leave residue
    jne .failed
    ; Actual completion must still name the same original device incarnation.
    lea rax,[rel msd_ops]
    cmp [rel msd_dev+dev.ops],rax
    jne .unavailable
    lea rdi,[rel msd_dev]
    mov rsi,[r12+24]
    mov rdx,rsp
    call usb_msd_owned_query
    test rax,rax
    jnz .unavailable
    lea rsi,[r12+48]
    mov rdi,rsp
    mov ecx,12
    repe cmpsq
    jne .unavailable
    xor eax,eax
    jmp .retained
.unbound:
    cmp byte [rel msd_bound],0
    jne .unavailable
    cmp byte [rel msd_dead],0
    jne .unavailable
    cmp dword [rel msd_bind_result],1
    jne .unavailable
    ; A completed absent scan cannot conceal an old registered MSD member.
    xor ebx,ebx
.absent_member:
    mov rdi,rbx
    xor esi,esi
    xor edx,edx
    call blk_iter_all_after
    test rax,rax
    jz .absent
    test r13d,r13d
    jz .unavailable
    dec r13d
    lea rdx,[rel msd_dev]
    cmp rax,rdx
    je .unavailable
    mov rbx,rax
    jmp .absent_member
.absent:
    mov eax,1
    jmp .retained
.unsupported:
    mov eax,5
    jmp .release
.failed:
    mov eax,4
    jmp .release
.unavailable:
    mov eax,3
.release:
    mov dword [r12+12],0
    mov [r12+8],eax
    mov dword [rel msd_io_gate],0       ; open admission only after sample publication
    jmp .out
.retained:
    mov [r12+8],eax
    jmp .out
.busy:
    ; No snapshot write while another terminal owns it; return2 is decisive.
    mov eax,2
.out:
    add rsp,96
    pop r13
    pop r12
    pop rbx
    ret

; Only the original serialized terminal caller uses this on a returned abort.
; Release exactly gate2; never unlock another ordinary in-flight BOT request.
usb_msd_power_release:
    mov eax,2
    mov edx,1                         ; hold admission through snapshot publication
    lock cmpxchg [rel msd_io_gate],edx
    jne .out
    mov dword [rel usb_msd_power_snapshot+12],0
    mov dword [rel msd_io_gate],0
.out:
    ret

%ifdef PAOS_LAB_USB_MSD_DUMP
; QEMU-lab only, never a shipped build: read LBA 0-7 through the block upper half
; (blk_read on the registered device) and print the 4096 bytes as hex lines, so a
; harness can compare them with the stick's marker.
msd_lab_dump:
    push rbx
    push r12
    lea  rdi, [rel msd_dev]
    xor  esi, esi
    mov  edx, 8
    lea  rcx, [rel msd_lab_buf]
    call blk_read
    test rax, rax
    jnz  .fail
    xor  ebx, ebx                      ; byte offset
.line:
    cmp  ebx, 4096
    jae  .done
    lea  rdi, [rel msd_lab_line]
    lea  rsi, [rel str_msd_lab_hex]
.pfx:
    mov  al, [rsi]
    test al, al
    jz   .hex
    mov  [rdi], al
    inc  rsi
    inc  rdi
    jmp  .pfx
.hex:
    xor  r12d, r12d
.byte:
    cmp  r12d, 32
    jae  .eol
    lea  rsi, [rel msd_lab_buf]
    add  rsi, rbx
    movzx eax, byte [rsi + r12]
    mov  ecx, eax
    shr  ecx, 4
    lea  rdx, [rel msd_hex_digits]
    mov  cl, [rdx + rcx]
    mov  [rdi], cl
    and  eax, 0x0F
    mov  al, [rdx + rax]
    mov  [rdi + 1], al
    add  rdi, 2
    inc  r12d
    jmp  .byte
.eol:
    mov  byte [rdi], 13
    mov  byte [rdi + 1], 10
    mov  byte [rdi + 2], 0
    lea  rdi, [rel msd_lab_line]
    call serial_string
    add  ebx, 32
    jmp  .line
.done:
    lea  rdi, [rel str_msd_lab_done]
    call serial_string
    jmp  .out
.fail:
    lea  rdi, [rel str_msd_lab_fail]
    call serial_string
.out:
    pop  r12
    pop  rbx
    ret
%endif

; --- data ---------------------------------------------------------------------
align 8
msd_io_gate:     dd 0
msd_bind_result: dd 0
msd_registered_generation: dq 0
usb_msd_power_snapshot: times 144 db 0
msd_dev:         times dev_size db 0
msd_ops:         times blk_ops_size db 0
msd_info:        times blk_info_size db 0
msd_hc:          dq 0
msd_hcops:       dq 0
msd_lba_max:     dq 0
msd_cmds:        dq 0
msd_cmd_fail:    dq 0
msd_block_size:  dd 0
msd_tag:         dd 0
msd_last_data_len: dd 0
msd_last_csw_status: dd 0
msd_cmd_refused: dd 0
msd_write_refused: dd 0
msd_flush_no_cache: dd 0
msd_owned_skips: dd 0
msd_last_sense:  dd 0                    ; key<<16 | ASC<<8 | ASCQ of the last REQUEST SENSE
msd_tur_attempts: dd 0
msd_port:        db 0
msd_config:      db 0
msd_iface:       db 0
msd_in_ep:       db 0
msd_out_ep:      db 0
msd_in_valid:    db 0
msd_out_valid:   db 0
msd_in_bot:      db 0
msd_foreign_if:  db 0
msd_bound:       db 0
msd_dead:        db 0
msd_state:       db 0
align 8
msd_setup:       times 8 db 0
msd_in_ep_desc:  times 8 db 0
msd_out_ep_desc: times 8 db 0
msd_wp:          db 0
msd_mode_header: times 4 db 0
msd_cdb:         times 16 db 0
msd_cbw:         times 32 db 0
msd_csw:         times 16 db 0
msd_cap:         times 8 db 0
msd_sense:       times 20 db 0
msd_inq:         times 40 db 0
msd_cfgbuf:      times MSD_CFGBUF_SZ db 0
str_msd_name:    db "usbmsd0", 0
str_msd_bound:   db "[PAOS64] usb_msd: usbmsd0 bound read/write (BOT; INQUIRY/TUR/REQUEST SENSE/READ CAPACITY/READ(10)/WRITE(10)/SYNC only) port=", 0
str_msd_lba:     db " lba_max=", 0
str_msd_tur:     db " tur=", 0
str_msd_sense:   db " sense=", 0
str_msd_bound_tail: db " [usb.msd.bound.rw]", 13, 10, 0
str_msd_absent:  db "[PAOS64] usb_msd: no unowned pure MSC-BOT device [usb.msd.absent]", 13, 10, 0
str_msd_failed:  db "[PAOS64] usb_msd: bind failed closed at stage=", 0
str_msd_failed_tail: db " (no reset issued) [usb.msd.failed]", 13, 10, 0
%ifdef PAOS_LAB_USB_MSD_DUMP
msd_hex_digits:  db "0123456789abcdef"
str_msd_lab_hex: db "[PAOS64] lab.usb_msd.hex ", 0
str_msd_lab_done: db "[PAOS64] lab.usb_msd.dump done bytes=4096", 13, 10, 0
str_msd_lab_fail: db "[PAOS64] lab.usb_msd.dump READ FAILED", 13, 10, 0
msd_lab_line:    times 96 db 0
align 16
msd_lab_buf:     times 4096 db 0
%endif

; Read-only boot INQUIRY identity. No callback/transfer or inferred filename.
; RDI=exact device -> RAX=28 raw vendor/product/revision bytes or 0.
msd_census_model:
    xor eax,eax
    lea rcx,[rel msd_dev]
    cmp rdi,rcx
    jne .out
    cmp dword [rel msd_inquiry_bytes],36
    jb .out
    lea rax,[rel msd_inq+8]
.out:
    ret
align 4
msd_inquiry_bytes: dd 0

%include "dev/blk/usb_msd_owned.asm"
