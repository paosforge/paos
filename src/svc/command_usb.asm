;; MODULE svc/command_usb
;; LAYER 5
;; EXPORTS command_usb_register, cmd_verb_usblist, cmd_verb_usbdesc, cmd_verb_usbports, usb_out_buf, usb_out_ready, usb_out_cur, usb_out_kind, usb_out_slot, cmd_verb_usbmap, hp_usb_mapping_register, hp_usb_mapping_observe, hp_usb_mapping_parse
;; IMPORTS boot/serial, core/lib/fmt, core/lib/str, usb/enum, dev/usb/xhci, dev/usb/hid, svc/command, svc/command_auth, boot/paging, bus/acpi
;; CAPS
;; OWNER saga:usb
; ============================================================================
; svc/command_usb.asm — THE USB observability PROJECTION over the enum seam
; (contract 1031, COMMANDS.md §1 single vocabulary). USBLIST/USBDESC are the
; GENERIC USB query verbs (§7d: NOT a bespoke probe-only interface — they print the
; enum seam's own state), so the probe content-grades the PRINTED descriptor bytes.
;
;   USBLIST        -> one line per enumerated device:
;                     "SLOT=<n> VID:PID=<vid>:<pid> CLASS=<cc>"  (n is 1-based)
;   USBDESC <slot> -> the 18-byte DEVICE DESCRIPTOR as 36 lowercase hex chars
;                     (bLength .. bNumConfigurations), or " none" for an empty slot
;                     (the negative-integrity gate: a fabricated descriptor fails).
;
; Both replies stage into usb_out_buf, framed verbatim by command_udp.asm exactly
; like rt_out_buf/sched_out_buf. Data (usb_out_*) is defined here and referenced by
; command_udp's staged-reply block.
; ============================================================================

USB_OUT_CAP      equ 512
; USBLIST is row-atomic and bounded (HUB0 grew the device table to 16 rows; ~12 rows
; would overflow USB_OUT_CAP). Worst-case row: "SLOT=" + 10-digit slot + " VID:PID=" +
; 4 + ":" + 4 + " CLASS=" + 2 + " PORT=" + 3 (byte) + CRLF = 53. Truncation line:
; "USBLIST truncated shown=" + 10 digits + " total=" + 10 digits = 51 (+ NUL).
USB_ROW_MAX      equ 53
USB_TRUNC_MAX    equ 51

; ---------------------------------------------------------------------------
; staged-reply helpers (usb_out_buf). clobbers documented per helper.
; ---------------------------------------------------------------------------
usb_out_reset:
    mov byte [rel usb_out_ready], 0
    mov byte [rel usb_out_kind], 0
    mov dword [rel usb_out_slot], 0
    lea  rax, [rel usb_out_buf]
    mov  [rel usb_out_cur], rax
    mov  byte [rel usb_out_buf], 0
    ret

; usb_out_str(RDI = cstr) — append NUL-terminated string. clobbers RAX,RSI.
usb_out_str:
    mov  rsi, [rel usb_out_cur]
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
    mov  [rel usb_out_cur], rsi
    ret

; usb_out_dec(RDI = value) — append decimal. clobbers RAX,RSI.
usb_out_dec:
    mov  rsi, [rel usb_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel usb_out_cur], rsi
    ret

; usb_out_hex2(EDI = byte) — append exactly 2 lowercase hex chars. clobbers RAX,RSI,RDX.
usb_out_hex2:
    and  edi, 0xFF
    mov  rsi, [rel usb_out_cur]
    push rsi
    mov  edx, 2                      ; min 2 digits -> "00".."ff"
    call fmt_hex
    pop  rsi
    add  rsi, rax
    mov  [rel usb_out_cur], rsi
    ret

; usb_out_hex4(EDI = word, little-endian pair already assembled) — 4 hex chars.
usb_out_hex4:
    and  edi, 0xFFFF
    mov  rsi, [rel usb_out_cur]
    push rsi
    mov  edx, 4
    call fmt_hex
    pop  rsi
    add  rsi, rax
    mov  [rel usb_out_cur], rsi
    ret

; usb_out_hex8(EDI = dword) — exactly 8 hex chars. clobbers RAX,RSI,RDX.
usb_out_hex8:
    mov  eax, edi
    mov  rdi, rax                    ; zero-extend to 64
    mov  rsi, [rel usb_out_cur]
    push rsi
    mov  edx, 8
    call fmt_hex
    pop  rsi
    add  rsi, rax
    mov  [rel usb_out_cur], rsi
    ret

; ---------------------------------------------------------------------------
; VERB: USBLIST (RDI=req, RSI=resp) — list every enumerated device. clobbers: c-s.
; ---------------------------------------------------------------------------
cmd_verb_usblist:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi                    ; resp
    call usb_out_reset
    call usb_dev_count
    mov  r12d, eax                   ; device count
    test r12d, r12d
    jz   .empty
    xor  ebx, ebx                    ; index
.loop:
    cmp  ebx, r12d
    jae  .done
    ; emit a row only if it fits whole, keeping room for the truncation line unless
    ; this is the last row; otherwise end with "USBLIST truncated shown=<n> total=<m>".
    mov  rax, [rel usb_out_cur]
    lea  rcx, [rel usb_out_buf]
    sub  rax, rcx                    ; bytes used
    add  rax, USB_ROW_MAX + 1        ; + this row + NUL
    lea  ecx, [ebx + 1]
    cmp  ecx, r12d
    jae  .fit
    add  rax, USB_TRUNC_MAX          ; more rows follow: reserve the truncation line
.fit:
    cmp  rax, USB_OUT_CAP
    ja   .truncate
    lea  rdi, [rel str_usb_slot]     ; "SLOT="
    call usb_out_str
    lea  edi, [ebx + 1]              ; 1-based slot number
    call usb_out_dec
    lea  rdi, [rel str_usb_vidpid]   ; " VID:PID="
    call usb_out_str
    ; descriptor -> vid (bytes 8..9 LE), pid (10..11 LE), class (byte 4)
    mov  edi, ebx
    call usb_dev_desc_ptr            ; RAX = ptr or 0
    test rax, rax
    jz   .next
    mov  r8, rax
    movzx edi, byte [r8 + 9]
    shl  edi, 8
    movzx eax, byte [r8 + 8]
    or   edi, eax                    ; vid
    call usb_out_hex4
    lea  rdi, [rel str_usb_colon]    ; ":"
    call usb_out_str
    mov  edi, ebx
    call usb_dev_desc_ptr
    mov  r8, rax
    movzx edi, byte [r8 + 11]
    shl  edi, 8
    movzx eax, byte [r8 + 10]
    or   edi, eax                    ; pid
    call usb_out_hex4
    lea  rdi, [rel str_usb_class]    ; " CLASS="
    call usb_out_str
    mov  edi, ebx
    call usb_dev_desc_ptr
    mov  r8, rax
    movzx edi, byte [r8 + 4]         ; bDeviceClass
    call usb_out_hex2
    lea  rdi, [rel str_usb_port]     ; " PORT="
    call usb_out_str
    mov  edi, ebx
    call usb_dev_addr                ; root-hub port the device was found on
    mov  edi, eax
    call usb_out_dec
    lea  rdi, [rel str_usb_nl]       ; newline
    call usb_out_str
.next:
    inc  ebx
    jmp  .loop
.truncate:
    lea  rdi, [rel str_usb_trunc]    ; "USBLIST truncated shown="
    call usb_out_str
    mov  edi, ebx                    ; rows emitted
    call usb_out_dec
    lea  rdi, [rel str_usb_total]    ; " total="
    call usb_out_str
    mov  edi, r12d
    call usb_out_dec
    jmp  .done
.empty:
    lea  rdi, [rel str_usb_nodev]    ; "USBLIST none"
    call usb_out_str
.done:
    mov byte [rel usb_out_kind], 1      ; current USBLIST publication
    mov  byte [rel usb_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; VERB: USBDESC (RDI=req, RSI=resp) — ARGT_TEXT arg = "<slot>". Print the 18-byte
;   device descriptor as 36 hex chars, or " none" for an empty/out-of-range slot.
;   Also USBDESC hid <state1..4>: cached public HID binding, separate kind4.
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
cmd_verb_usbdesc:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi                    ; resp
    mov  r12, [rdi + REQ_ARG]        ; -> "<slot>" or canonical "hid <state>"
    mov  rdi, r12
    call usb_desc_hid
    test eax, eax
    jnz  .hid_done
    call usb_out_reset
    lea  rdi, [rel str_usb_desc_pre] ; "USBDESC slot="
    call usb_out_str
    ; Canonical uint32 slot, consumed in full before any registry lookup.
    ; No leading-zero aliases, signed/prefix forms, suffixes or wrapped values.
    ; Invalid input keeps the existing slot0/none response and retires any prior slot selection.
    ; The pre-multiply bound inspects at most11 input bytes even without a terminator;
    ; valid but absent slots still echo their exact original numeric selector.
    xor  ebx, ebx                    ; slot accumulator
    test r12, r12
    jz   .parsed
    cmp  byte [r12], '0'
    jne  .parse
    cmp  byte [r12 + 1], 0
    jne  .bad_slot
    jmp  .parsed
.parse:
    movzx eax, byte [r12]
    test eax, eax
    jz   .parsed
    sub  eax, '0'
    cmp  eax, 9
    ja   .bad_slot
    cmp  ebx, 429496729
    ja   .bad_slot
    jb   .digit
    cmp  eax, 5
    ja   .bad_slot
.digit:
    imul ebx, ebx, 10
    add  ebx, eax
    inc  r12
    jmp  .parse
.bad_slot:
    xor  ebx, ebx
.parsed:
    mov  edi, ebx
    call usb_out_dec                 ; echo the requested slot
    ; index = slot - 1; validate + fetch descriptor
    test ebx, ebx
    jz   .none                       ; slot 0 invalid
    lea  edi, [ebx - 1]
    call usb_dev_desc_ptr            ; RAX = ptr or 0 (out of range -> 0)
    test rax, rax
    jz   .none
    mov  r8, rax                     ; SAVE desc ptr FIRST — usb_out_str clobbers AL of rax
    lea  rdi, [rel str_usb_desc_bytes]  ; " bytes="
    call usb_out_str
    ; emit 18 bytes as 36 hex chars
    xor  ecx, ecx
.emit:
    cmp  ecx, 18
    jae  .desc_done
    push rcx
    push r8
    movzx edi, byte [r8 + rcx]
    call usb_out_hex2
    pop  r8
    pop  rcx
    inc  ecx
    jmp  .emit
.desc_done:
    jmp  .staged
.none:
    lea  rdi, [rel str_usb_none]     ; " none"
    call usb_out_str
.staged:
    mov byte [rel usb_out_kind], 2      ; current USBDESC publication
    mov [rel usb_out_slot], ebx         ; exact native parsed selector
    mov  byte [rel usb_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    pop  r13
    pop  r12
    pop  rbx
    ret

; Cached HID reply has its own provenance kind; numeric USBDESC/HOOK stays kind2.
.hid_done:
    mov  qword [r13 + RSP_CODE], CMDE_OK
    pop  r13
    pop  r12
    pop  rbx
    ret

; USBDESC hid <state1..4> observes a HID binding ordinal, NOT USBLIST slot.
; One exact canonical selector, one cached16-byte record, maximum160 reply bytes.
; Invalid syntax follows the unchanged numeric USBDESC path. No device I/O.
usb_desc_hid:
    test rdi, rdi
    jz   .miss
    cmp  byte [rdi], 'h'
    jne  .miss
    cmp  byte [rdi + 1], 'i'
    jne  .miss
    cmp  byte [rdi + 2], 'd'
    jne  .miss
    cmp  byte [rdi + 3], ' '
    jne  .miss
    movzx eax, byte [rdi + 4]
    sub  eax, '1'
    cmp  eax, 3
    ja   .miss
    cmp  byte [rdi + 5], 0
    jne  .miss
    push rbx
    push r12
    push r13
    sub  rsp, 16
    lea  r12d, [eax + 1]
    call usb_out_reset
    lea  rdi, [rel str_usb_hid_state]
    call usb_out_str
    mov  edi, r12d
    call usb_out_dec
    mov  edi, r12d
    mov  rsi, rsp
    call usb_hid_binding_snapshot
    test eax, eax
    jz   .none
    xor  ebx, ebx
    lea  r13, [rel usb_hid_field_names]
.fields:
    movsxd rax, dword [r13 + rbx*4]
    lea  rdi, [r13 + rax]
    call usb_out_str
    movzx edi, byte [rsp + rbx]
    call usb_out_dec
    inc  ebx
    cmp  ebx, 8
    jb   .fields
    lea  rdi, [rel str_usb_hid_generation]
    call usb_out_str
    mov  edi, [rsp + 8]
    call usb_out_dec
    lea  rdi, [rel str_usb_hid_sequence]
    call usb_out_str
    mov  edi, [rsp + 12]
    call usb_out_dec
    jmp  .done
.none:
    lea  rdi, [rel str_usb_none]
    call usb_out_str
.done:
    mov  byte [rel usb_out_kind], 4
    mov  [rel usb_out_slot], r12d
    mov  byte [rel usb_out_ready], 1
    add  rsp, 16
    pop  r13
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.miss:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; VERB: USBPORTS (RDI=req, RSI=resp) — diagnostic: dump the xHCI root-hub port count
;   + each live PORTSC dword (connect/enable/speed/reset). clobbers: caller-saved.
; ---------------------------------------------------------------------------
cmd_verb_usbports:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi                    ; resp
    call usb_out_reset
    lea  rdi, [rel str_usb_ports_pre]  ; "USBPORTS maxports="
    call usb_out_str
    call xhci_get_maxports
    mov  r12d, eax                   ; maxports
    mov  edi, eax
    call usb_out_dec
    call usb_out_init_receipt        ; saved original selection; never reads hardware
    mov  ebx, 1
.loop:
    cmp  ebx, r12d
    ja   .done
    cmp  ebx, 24                     ; existing port cap; omissions are explicit
    ja   .ports_more
    ; Whole port rows plus the worst fixed hub refusal/count/more tails and
    ; portsmore must fit after the initialization receipt. Never split a row.
    mov  rax, [rel usb_out_cur]
    lea  rcx, [rel usb_out_buf]
    sub  rax, rcx
    cmp  rax, USB_OUT_CAP - 15 - USB_PORT_TAIL_MAX
    ja   .ports_more
    lea  rdi, [rel str_usb_port_p]   ; " p"
    call usb_out_str
    mov  edi, ebx
    call usb_out_dec
    lea  rdi, [rel str_usb_port_eq]  ; "=0x"
    call usb_out_str
    mov  edi, ebx
    call xhci_read_portsc            ; EAX = raw PORTSC
    mov  edi, eax
    call usb_out_hex8                ; full 32-bit: CCS/PED/PR/speed + CSC/PRC change bits
    inc  ebx
    jmp  .loop
.ports_more:
    lea  rdi, [rel str_usb_ports_more]
    call usb_out_str
    mov  edi, r12d
    sub  edi, ebx
    inc  edi
    call usb_out_dec
.done:
    ; RCQ-09: every hub configured or refused this boot (usb_hub_record), so a
    ; serial-less target localizes a missing hub child in one read:
    ; " hubfail=<count> i<xHCI instance> s<parent slot> p<hub port> st<stage> cc<code>"
    ; (the last hub-child address refusal, xhci_hub_child_last; absent when none),
    ; " hubs=<seen>" then " hub<i>=VVVV:PPPP c<controller> p<root> d<depth> s<speed>
    ; r<reason> n<ports> x<hub_ctx> pw<powered> cn<connected> em<empty> di<disabled>
    ; fa<failed> en<enumerated> lp<last port not enumerated> ls<its outcome>", bounded
    ; by USB_OUT_CAP; " more=<k>" names the hubs not shown (not kept, or would not fit).
    call xhci_hub_child_last
    cmp  dword [rax], 0
    je   .no_hubfail
    mov  rbx, rax
    lea  rdi, [rel str_usb_hubfail]
    call usb_out_str
    mov  edi, [rbx]
    call usb_out_dec
    xor  ecx, ecx
.hubfail_field:
    cmp  ecx, 4
    jae  .hubfail_cc
    push rcx
    lea  rax, [rel usb_hubfail_names]
    movsxd rdi, dword [rax + rcx*4]
    add  rdi, rax
    call usb_out_str
    mov  rcx, [rsp]
    movzx edi, byte [rbx + 4 + rcx]
    call usb_out_dec
    pop  rcx
    inc  ecx
    jmp  .hubfail_field
.hubfail_cc:
    lea  rdi, [rel str_usb_hf_cc]
    call usb_out_str
    mov  edi, [rbx + 8]
    call usb_out_dec
.no_hubfail:
    lea  rdi, [rel str_usb_hubs]
    call usb_out_str
    xor  edi, edi
    call usb_hub_record
    mov  r12d, edx
    mov  edi, edx
    call usb_out_dec
    xor  ebx, ebx
.hub:
    cmp  ebx, r12d
    jae  .hubs_end
    mov  rax, [rel usb_out_cur]
    lea  rcx, [rel usb_out_buf]
    sub  rax, rcx
    cmp  rax, USB_OUT_CAP - USB_HUB_ITEM_MAX
    ja   .hubs_more
    mov  edi, ebx
    call usb_hub_record
    test rax, rax
    jz   .hubs_more                  ; seen but not kept
    push rbx
    mov  rbx, rax
    lea  rdi, [rel str_usb_hub_i]    ; " hub"
    call usb_out_str
    mov  edi, [rsp]
    call usb_out_dec
    lea  rdi, [rel str_usb_hub_eq]   ; "="
    call usb_out_str
    movzx edi, word [rbx]
    call usb_out_hex4
    lea  rdi, [rel str_usb_hub_colon]
    call usb_out_str
    movzx edi, word [rbx + 2]
    call usb_out_hex4
    xor  ecx, ecx
.field:
    cmp  ecx, USB_HUB_FIELDS
    jae  .field_done
    push rcx
    lea  rax, [rel usb_hub_field_names]
    movsxd rdi, dword [rax + rcx*4]
    add  rdi, rax
    call usb_out_str
    mov  rcx, [rsp]
    lea  rax, [rel usb_hub_field_offs]
    movzx eax, byte [rax + rcx]
    movzx edi, byte [rbx + rax]
    call usb_out_dec
    pop  rcx
    inc  ecx
    jmp  .field
.field_done:
    pop  rbx
    inc  ebx
    jmp  .hub
.hubs_end:
    cmp  ebx, r12d
    jae  .hubs_done
.hubs_more:
    lea  rdi, [rel str_usb_hub_more] ; " more="
    call usb_out_str
    mov  edi, r12d
    sub  edi, ebx
    call usb_out_dec
.hubs_done:
    mov byte [rel usb_out_kind], 3      ; existing USBPORTS diagnostic publication
    mov  byte [rel usb_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    pop  r13
    pop  r12
    pop  rbx
    ret

; Original selected initialization context. Fixed <=74 bytes when present,
; <=10 when absent. All numbers use existing bounded native formatters. This
; receipt describes the initial selection even if backend0 is a later fallback.
usb_out_init_receipt:
    push rbx
    call xhci_get_init_receipt
    mov  rbx, rax
    cmp  dword [rbx], 0
    je   .none
    lea  rdi, [rel str_usb_init]
    call usb_out_str
    mov  edi, [rbx + 4]
    call usb_out_hex2
    lea  rdi, [rel str_usb_colon]
    call usb_out_str
    mov  edi, [rbx + 8]
    call usb_out_hex2
    lea  rdi, [rel str_usb_init_dot]
    call usb_out_str
    mov  edi, [rbx + 12]
    call usb_out_hex2
    lea  rdi, [rel str_usb_init_id]
    call usb_out_str
    mov  edi, [rbx + 16]
    call usb_out_hex4
    lea  rdi, [rel str_usb_colon]
    call usb_out_str
    mov  edi, [rbx + 16]
    shr  edi, 16
    call usb_out_hex4
    lea  rdi, [rel str_usb_init_h2]
    call usb_out_str
    mov  edi, [rbx + 20]
    call usb_out_hex8
    lea  rdi, [rel str_usb_init_hv]
    call usb_out_str
    mov  edi, [rbx + 24]
    and  edi, 1
    call usb_out_dec
    lea  rdi, [rel str_usb_init_phase]
    call usb_out_str
    mov  edi, [rbx + 28]
    call usb_out_hex2
    lea  rdi, [rel str_usb_init_rc]
    call usb_out_str
    mov  edi, [rbx + 32]
    call usb_out_hex8
    lea  rdi, [rel str_usb_init_reg]
    call usb_out_str
    mov  edi, [rbx + 36]
    call usb_out_hex8
    pop  rbx
    ret
.none:
    lea  rdi, [rel str_usb_init_none]
    call usb_out_str
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; command_usb_register — register USBLIST/USBDESC in the verb registry. Called from
;   boot/header AFTER command_registry_init + usb_enum_selftest. clobbers: c-s.
; ---------------------------------------------------------------------------
command_usb_register:
    call hp_usb_mapping_register
    lea  rdi, [rel str_verb_usblist]
    lea  rsi, [rel cmd_verb_usblist]
    xor  edx, edx                    ; cap 0 (v1 allow-all)
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_usbdesc]
    lea  rsi, [rel cmd_verb_usbdesc]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_usbports]
    lea  rsi, [rel cmd_verb_usbports]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ret

; ---- module data ----------------------------------------------------------
align 8
usb_out_kind:    db 0                ; 0=none,1=list,2=descriptor,3=ports,4=HID binding; correlation only
align 4
usb_out_slot:    dd 0                ; actual USBDESC parsed slot, otherwise 0
usb_out_ready:   db 0                ; 1 = usb_out_buf holds a staged reply line
align 8
usb_out_cur:     dq 0
usb_out_buf:     times USB_OUT_CAP db 0

; At most8 byte fields and2 u32 fields: <=160 bytes including selector/NUL.
str_usb_hid_state: db "USBHID state=", 0
str_usb_hid_active: db " active=", 0
str_usb_hid_kind: db " kind=", 0
str_usb_hid_port: db " port=", 0
str_usb_hid_if: db " if=", 0
str_usb_hid_ep: db " ep=", 0
str_usb_hid_slot: db " slot=", 0
str_usb_hid_protocol: db " protocol=", 0
str_usb_hid_wire: db " wire=", 0
str_usb_hid_generation: db " generation=", 0
str_usb_hid_sequence: db " sequence=", 0
align 4
usb_hid_field_names:
    dd str_usb_hid_active - usb_hid_field_names, str_usb_hid_kind - usb_hid_field_names
    dd str_usb_hid_port - usb_hid_field_names, str_usb_hid_if - usb_hid_field_names
    dd str_usb_hid_ep - usb_hid_field_names, str_usb_hid_slot - usb_hid_field_names
    dd str_usb_hid_protocol - usb_hid_field_names, str_usb_hid_wire - usb_hid_field_names

str_verb_usblist:  db "USBLIST", 0
str_verb_usbdesc:  db "USBDESC", 0
str_verb_usbports: db "USBPORTS", 0
str_usb_ports_pre: db "USBPORTS maxports=", 0
; Original root-port cap24 retained, but initialization adds <=74 bytes.
; Every port row reserves 110 bytes for portsmore (<=21), hubfail (<=56),
; hubs count (<=16), hub more (<=16), and NUL. Hub records use their existing
; 120-byte whole-record reservation. Thus neither optional tail can overrun.
USB_PORT_TAIL_MAX equ 110
str_usb_ports_more: db " portsmore=", 0
str_usb_init:       db " init=", 0
str_usb_init_none:  db " init=none", 0
str_usb_init_dot:   db ".", 0
str_usb_init_id:    db " id=", 0
str_usb_init_h2:    db " h2=", 0
str_usb_init_hv:    db " hv=", 0
str_usb_init_phase: db " ph=", 0
str_usb_init_rc:    db " rc=", 0
str_usb_init_reg:   db " rg=", 0
USB_HUB_ITEM_MAX  equ 120
USB_HUB_FIELDS    equ 15
str_usb_hubs:      db " hubs=", 0
str_usb_hubfail:   db " hubfail=", 0
str_usb_hf_i:      db " i", 0
str_usb_hf_st:     db " st", 0
str_usb_hf_cc:     db " cc", 0
str_usb_hf_lp:     db " lp", 0
str_usb_hf_ls:     db " ls", 0
str_usb_hub_i:     db " hub", 0
str_usb_hub_eq:    db "=", 0
str_usb_hub_colon: db ":", 0
str_usb_hub_more:  db " more=", 0
str_usb_hf_c:      db " c", 0
str_usb_hf_p:      db " p", 0
str_usb_hf_d:      db " d", 0
str_usb_hf_s:      db " s", 0
str_usb_hf_r:      db " r", 0
str_usb_hf_n:      db " n", 0
str_usb_hf_x:      db " x", 0
str_usb_hf_pw:     db " pw", 0
str_usb_hf_cn:     db " cn", 0
str_usb_hf_em:     db " em", 0
str_usb_hf_di:     db " di", 0
str_usb_hf_fa:     db " fa", 0
str_usb_hf_en:     db " en", 0
usb_hub_field_offs: db 16, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18
; rel32 from each table (org 0 image: no absolute pointers)
align 4
usb_hub_field_names:
    dd str_usb_hf_c - usb_hub_field_names, str_usb_hf_p - usb_hub_field_names
    dd str_usb_hf_d - usb_hub_field_names, str_usb_hf_s - usb_hub_field_names
    dd str_usb_hf_r - usb_hub_field_names, str_usb_hf_n - usb_hub_field_names
    dd str_usb_hf_x - usb_hub_field_names, str_usb_hf_pw - usb_hub_field_names
    dd str_usb_hf_cn - usb_hub_field_names, str_usb_hf_em - usb_hub_field_names
    dd str_usb_hf_di - usb_hub_field_names, str_usb_hf_fa - usb_hub_field_names
    dd str_usb_hf_en - usb_hub_field_names, str_usb_hf_lp - usb_hub_field_names
    dd str_usb_hf_ls - usb_hub_field_names
usb_hubfail_names:
    dd str_usb_hf_i - usb_hubfail_names, str_usb_hf_s - usb_hubfail_names
    dd str_usb_hf_p - usb_hubfail_names, str_usb_hf_st - usb_hubfail_names
str_usb_port_p:    db " p", 0
str_usb_port_eq:   db "=0x", 0

str_usb_slot:      db "SLOT=", 0
str_usb_vidpid:    db " VID:PID=", 0
str_usb_colon:     db ":", 0
str_usb_class:     db " CLASS=", 0
str_usb_port:      db " PORT=", 0
str_usb_nl:        db 13, 10, 0
str_usb_nodev:     db "USBLIST none", 0
str_usb_trunc:     db "USBLIST truncated shown=", 0
str_usb_total:     db " total=", 0
str_usb_desc_pre:  db "USBDESC slot=", 0
str_usb_desc_bytes: db " bytes=", 0
str_usb_none:      db " none", 0

%include "svc/hp_usb_mapping.inc"
