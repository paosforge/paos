;; MODULE hv/nd_isolation
;; LAYER 5
;; EXPORTS ndiso_group_snapshot, ndiso_group_capture, nd_group_refusal_page, ndiso_capture, ndiso_render, ndiso_valid, ndiso_text_rows, nd_iso_page, nd_iso_scope_page, ndiso_short_text
;; IMPORTS hv/pci_assign, hv/amdvi, hv/amdvi_hda, hv/vtd, bus/pci_bdf, net/netdev, dev/net/ax88179, dev/net/ax88179b, dev/net/cdc_ecm, dev/net/cdc_ncm, svc/command_netcheck, boot/header
;; CAPS
;; OWNER saga:device_assignment_portability
;; CONTEXT: bsp_only
; NDISO1 (ROOT110035; AMD PLAN f2cccad6, SEC109995/110011/110040, VM110041,
; FS110037/110048, AMD110044, VM110051, SEC110052, INPUT110053): the driver-domain isolation-refusal record and the ONE
; producer of the user's text about it. Evidence and words only: nothing here
; is an admission input, nothing reads it to grant, retry or relax, and no
; surface offers an override. The ISO_* refusal and nd_boot_error 5 stay as the
; classifier decided them.
;
; nd_iso_page, 32 bytes, written once per boot by ndiso_capture:
;   +0 u8 valid (0/1; all other bytes zero while 0)  +1 u8 ISO_* reason 1..9
;   +2 u8 acs_state: 0 none (no port), 1 ABSENT, 2 NOT_ENABLED, 3 UNOBSERVED,
;        4 PROVEN (the top port passes the gate's own ACS test)
;   +3 u8 backend: 0 none, 1 VT-d, 2 AMD-Vi
;   +4 u16 target BDF   +6 u16 top chain port BDF (0xFFFF none)
;   +8 u16 member BDF: the peer where devassign_classify's group walk stops
;        (0xFFFF none)  +10 u8 member kind DA_K_* (0xFF none)  +11 u8 member flags DA_F_*
;   +12 u16 group category mask (every DMA/protected member except the target)
;   +14 u16 the PROTECTED subset of that mask (VT-d lifelines; never set on AMD)
;   +16 u64 boot_ms at capture   +24 u32 target vendor|device<<16   +28 zero
; Categories (bit): 0 storage (class 01), 1 USB (0c03), 2 network (02),
;   3 display (03), 4 audio/multimedia (04), 5 other.
; The page only names facts from the host's own snapshot: no DMI/model, no
; device-supplied string, no guest byte.

%include "hv/pcia_grp.inc"

NDISO_PAGE_BYTES   equ 32
NDISO_ROW_GLYPHS   equ 58              ; FS110048: Connection listview, (480-12)/8
NDISO_ROWS         equ 7               ; FS110048: (156-30)/18 visible rows
NDISO_TEXT_MAX     equ NDISO_ROWS * NDISO_ROW_GLYPHS + NDISO_ROWS - 1 ; 412: line 1 + LF + line 2, no NUL
NDISO_SCRATCH      equ 512             ; compose buffer (> any uncollapsed text)
NDISO_LINK_DOWN    equ 0               ; NETCHECK NC_LINK_DOWN (pinned by a HOST row)
NDISO_LINK_UP      equ 1               ; NETCHECK NC_LINK_UP
NDISO_NONE16       equ 0xFFFF
NDISO_ACS_NONE     equ 0
NDISO_ACS_ABSENT   equ 1
NDISO_ACS_NOT_ENABLED equ 2
NDISO_ACS_UNOBSERVED  equ 3
NDISO_ACS_PROVEN   equ 4
NDISO_CAT_OTHER    equ 5
NDISO_CATS         equ 6
NDISO_W3_MAX       equ 8                ; W3 ND_ACS_DEPTH: entries in nd_acs_record

; GRF1 v1 is the separate whole-group refusal observation. It never extends
; NDISO1 or the boot NICS selector namespace. Written only from original A's
; result path: +0 magic, +4 u16 version, +6 u16 length32, +8 reason1..15,
; +9 native backend, +10 selected BDF, +12 zero, +16 consumed START, +24 zero.
; Success/invalid input clears it; it is never an admission or retry input.
; EDI selected BDF, ESI original A result, RDX actual consumed START. Preserve
; EAX (the original result) and all SysV callee-saved registers. BSP/IF0.
ndiso_group_capture:
    lea r9, [rel nd_group_refusal_page]
    mov qword [r9], 0
    mov qword [r9+8], 0
    mov qword [r9+16], 0
    mov qword [r9+24], 0
    cmp edi, 65535
    ja .out
    cmp esi, 1
    jb .out
    cmp esi, 15
    ja .out
    test rdx, rdx
    jz .out
    mov r10, rdx
    shr r10, 32
    jnz .out
    xor r8d, r8d
    cmp byte [rel amdvi_owned], 1
    je .amd
    cmp byte [rel vtd_enabled], 1
    jne .backend
    mov r8d, 1
    jmp .backend
.amd:
    cmp byte [rel vtd_enabled], 0
    jne .out
    mov r8d, 2
.backend:
    mov word [r9+4], 1
    mov word [r9+6], 32
    mov [r9+8], sil
    mov [r9+9], r8b
    mov [r9+10], di
    mov [r9+16], rdx
    mov dword [r9], 0x31465247       ; GRF1 published last
.out: ret

; NDS1 v9 passive group pages, called only by the native snapshot owner.
; RDI expected consumed START, ESI selected BDF, RDX private32 refusal output,
; RCX private176 receipt output. Both fixed buffers are zeroed on no match.
; No PCI/config access, scan, reset, admission, lifecycle or claim mutation.
ndiso_group_snapshot:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov ebx, esi
    mov r13, rdx
    mov r14, rcx
    mov rdi, r13
    xor eax, eax
    mov ecx, 4
    cld
    rep stosq
    mov rdi, r14
    mov ecx, 22
    rep stosq
    test r12, r12
    jz .out
    mov rax, r12
    shr rax, 32
    jnz .out
    cmp ebx, 65535
    ja .out
    lea rsi, [rel nd_group_refusal_page]
    cmp dword [rsi], 0x31465247
    jne .receipt
    cmp [rsi+16], r12
    jne .receipt
    cmp [rsi+10], bx
    jne .receipt
    mov rdi, r13
    mov ecx, 4
    rep movsq
.receipt:
    mov rdi, r14
    mov esi, 176
    call pcia_grp_receipt
    cmp eax, 176
    jne .out
    cmp [r14+8+PG_GEN], r12
    jne .clear_receipt
    movzx eax, byte [r14+8+PG_SEL]
    shl eax, 4
    cmp [r14+8+PG_MEMBERS+rax+PGM_BDF], bx
    je .out
.clear_receipt:
    mov rdi, r14
    xor eax, eax
    mov ecx, 22
    rep stosq
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ndiso_capture(EDI=target BDF, ESI=nic_select_snapshot result, RDX=W3's
; nd_acs_record of this boot) — once per boot, only for ISO_* 1..9 (never
; NICS_* 10..14 or 0). Called by nd_boot_start right after nic_select_snapshot,
; before any other group gate, so pcia_iso_record and the W3 record are this
; target's (count u32, then per port bdf u16, type u8, status u8, before u32,
; after u32, zero u32). Read-only on hardware: one conf1 read of
; the target's ID dword and of each member's class dword. Preserves RBX, RBP,
; R12-R15.
ndiso_capture:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    cmp  byte [rel nd_iso_page], 0
    jne  .out                            ; once: never rewritten this boot
    cmp  esi, 1
    jb   .out
    cmp  esi, 9
    ja   .out
    cmp  edi, 0xFFFF
    ja   .out
    mov  r12d, edi                       ; target
    mov  r13d, esi                       ; reason
    mov  [rsp], rdx                      ; W3 record (may be 0)
    lea  rbx, [rel nd_iso_page]
    xor  eax, eax
    mov  [rbx], rax
    mov  [rbx + 8], rax
    mov  [rbx + 16], rax
    mov  [rbx + 24], rax
    mov  [rbx + 1], r13b
    mov  [rbx + 4], r12w
    mov  word [rbx + 6], NDISO_NONE16
    mov  word [rbx + 8], NDISO_NONE16
    mov  byte [rbx + 10], 0xFF
    xor  eax, eax
    cmp  byte [rel vtd_enabled], 1
    jne  .amd
    mov  eax, 1
.amd:
    cmp  byte [rel amdvi_owned], 1
    jne  .backend
    mov  eax, 2
.backend:
    mov  [rbx + 3], al
    mov  edi, r12d
    xor  esi, esi
    call pci_bdf_read
    mov  [rbx + 24], eax
    ; Group facts exist only for the two group verdicts.
    cmp  r13d, ISO_PROTECTED
    jb   .stamp
    cmp  r13d, ISO_SHARED_DMA
    ja   .stamp
    mov  edi, r12d
    call pcia_group_record_peek
    test rax, rax
    jz   .stamp
    mov  r14, rax                        ; completed fact record
    lea  r15, [r14 + 16]                 ; device records
    movzx ebp, byte [r14 + 3]            ; n_dev
    ; --- member: devassign_classify's own .grp order, first unsafe peer ---
    movzx r8d, byte [r15 + 7]            ; target group
    movzx r9d, word [r15 + 0]            ; target segment
    mov  ecx, 1
.m_scan:
    cmp  ecx, ebp
    jae  .m_done
    lea  r10, [r15 + rcx*8]
    movzx eax, byte [r10 + 7]
    cmp  eax, r8d
    jne  .m_next
    movzx eax, word [r10 + 0]
    cmp  eax, r9d
    jne  .m_done                         ; ISO_SEGMENT would stop there: no member
    movzx eax, byte [r10 + 6]
    test al, DA_F_PROTECTED
    jnz  .m_found
    test al, DA_F_DMA
    jnz  .m_found                        ; a DMA endpoint or a DMA bridge
.m_next:
    inc  ecx
    jmp  .m_scan
.m_found:
    movzx eax, byte [r10 + 2]
    shl  eax, 8
    mov  al, [r10 + 3]
    mov  [rbx + 8], ax
    mov  al, [r10 + 5]
    mov  [rbx + 10], al
    mov  al, [r10 + 6]
    mov  [rbx + 11], al
.m_done:
    ; --- categories over every member of the target's group ---
    mov  r13d, 1                         ; record index (the reason is on the page)
.c_scan:
    cmp  r13d, ebp
    jae  .c_done
    lea  r10, [r15 + r13*8]
    movzx eax, byte [r10 + 7]
    cmp  al, [r15 + 7]
    jne  .c_next
    test byte [r10 + 6], DA_F_DMA | DA_F_PROTECTED
    jz   .c_next                         ; a topology-only bridge is no member
    movzx edi, byte [r10 + 2]
    shl  edi, 8
    mov  dil, [r10 + 3]
    mov  esi, 8
    call pci_bdf_read
    call ndiso_category                  ; EAX class dword -> ECX bit
    mov  edx, 1
    shl  edx, cl
    or   [rbx + 12], dx
    lea  r10, [r15 + r13*8]
    test byte [r10 + 6], DA_F_PROTECTED
    jz   .c_next
    or   [rbx + 14], dx
.c_next:
    inc  r13d
    jmp  .c_scan
.c_done:
    ; --- port: the chain's top bridge (parent DA_ROOT); none on a root bus ---
    movzx eax, byte [r15 + 4]            ; target's parent
    cmp  al, DA_ROOT
    je   .stamp
    xor  edx, edx
.p_up:
    cmp  eax, ebp
    jae  .stamp                          ; malformed: no port
    inc  edx
    cmp  edx, ebp
    ja   .stamp
    lea  r10, [r15 + rax*8]
    movzx ecx, byte [r10 + 4]
    cmp  cl, DA_ROOT
    je   .p_top
    mov  eax, ecx
    jmp  .p_up
.p_top:
    movzx eax, byte [r10 + 2]
    shl  eax, 8
    mov  al, [r10 + 3]
    mov  [rbx + 6], ax
    mov  byte [rbx + 2], NDISO_ACS_UNOBSERVED
    cmp  byte [rbx + 3], 2
    jne  .stamp                          ; VT-d never reads ACS: UNOBSERVED
    ; AMD-Vi: W3's record of this boot's chain, read just before this gate.
    mov  r10, [rsp]
    test r10, r10
    jz   .stamp
    mov  ecx, [r10]
    cmp  ecx, NDISO_W3_MAX                ; W3 ND_ACS_DEPTH
    ja   .stamp
    add  r10, 4
.a_scan:
    test ecx, ecx
    jz   .stamp                          ; no entry: UNOBSERVED
    cmp  [r10], ax
    je   .a_found
    add  r10, 16
    dec  ecx
    jmp  .a_scan
.a_found:
    movzx ecx, byte [r10 + 3]            ; W3 status
    mov  byte [rbx + 2], NDISO_ACS_ABSENT
    cmp  ecx, 1
    je   .stamp
    mov  byte [rbx + 2], NDISO_ACS_NOT_ENABLED
    cmp  ecx, 10                         ; Capability lacks a required bit
    je   .stamp
    mov  byte [rbx + 2], NDISO_ACS_UNOBSERVED
    test ecx, ecx
    jnz  .stamp
    mov  eax, [r10 + 8]                  ; after (0 unless resampled)
    test eax, eax
    jnz  .a_test
    mov  eax, [r10 + 4]                  ; before: already enabled, no store
.a_test:
    mov  edx, eax
    and  eax, PCIA_ACS_REQUIRED
    cmp  eax, PCIA_ACS_REQUIRED
    mov  byte [rbx + 2], NDISO_ACS_NOT_ENABLED
    jne  .stamp
    shr  edx, 16
    and  edx, PCIA_ACS_REQUIRED | PCIA_ACS_DT
    cmp  edx, PCIA_ACS_REQUIRED          ; the gate's own test: all four on, DT off
    jne  .stamp
    mov  byte [rbx + 2], NDISO_ACS_PROVEN
.stamp:
    ; Capture alongside the first boot refusal only. The parsed IVRS tables
    ; are immutable, so this is the same predicate over the original facts.
    cmp r13d, ISO_RMRR
    jne .scope_done
    cmp byte [rbx+3], 2
    jne .scope_done
    mov edi, r12d
    lea rsi, [rel nd_iso_scope_page]
    call amdvi_scope_snapshot
.scope_done:
    call boot_ms_now
    mov  [rbx + 16], rax
    mov  byte [rbx], 1                   ; valid last
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EAX = config dword 0x08 -> ECX = category bit. Clobbers EAX, EDX.
ndiso_category:
    mov  edx, eax
    shr  edx, 24                         ; base class
    mov  ecx, 0
    cmp  edx, 0x01
    je   .done
    mov  ecx, 2
    cmp  edx, 0x02
    je   .done
    mov  ecx, 3
    cmp  edx, 0x03
    je   .done
    mov  ecx, 4
    cmp  edx, 0x04
    je   .done
    mov  ecx, NDISO_CAT_OTHER
    cmp  edx, 0x0C
    jne  .done
    shr  eax, 16
    cmp  al, 0x03                        ; serial bus / USB
    jne  .done
    mov  ecx, 1
.done:
    ret

; ndiso_valid -> EAX 1 when this boot's isolation refusal has a record, else 0.
ndiso_valid:
    movzx eax, byte [rel nd_iso_page]
    ret

; ndiso_render(RDI=buf, ESI=cap) -> EAX = bytes written (line 1, LF, line 2;
; no NUL counted, none written), 0 = no message (no valid record: ELIGIBLE or a
; failure that is not an isolation refusal), -1 = cap too small or no fitting
; text (nothing is ever truncated; the caller shows ndiso_short_text and keeps
; the refusal outcome). The text has no comma (FS110048: the listview ends a
; row at ','), and wrapped by ndiso_text_rows it fills at most NDISO_ROWS rows
; of NDISO_ROW_GLYPHS with line 2 present (SEC110052): when the full category
; list would not fit, it collapses to "<first>; other devices". Line 2 reads
; the same egress facts NETCHECK reports (INPUT110053): netdev_select_peek,
; netcheck_selected_link and the registry; no counter, no driver IO. The one
; text producer for every surface.
%if netdev_minfo_size > 48
%error "ndiso_render: its frame holds one netdev_minfo in 48 bytes"
%endif
ndiso_render:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 72                         ; [0,48) netdev_minfo, 48 buf, 56 cap, 64 collapse
    xor  eax, eax
    cmp  byte [rel nd_iso_page], 1
    jne  .ret
    test rdi, rdi
    jz   .small
    mov  [rsp + 48], rdi
    mov  [rsp + 56], esi
    mov  dword [rsp + 64], 0
.compose:
    lea  r12, [rel nd_iso_text]
    mov  r13d, NDISO_SCRATCH
    xor  r14d, r14d                      ; length
    xor  r15d, r15d                      ; overflow flag
    lea  rbx, [rel nd_iso_page]
    ; ---- line 1 (SEC110052 forms a/b/c) ----
    lea  rsi, [rel ndiso_s_card]
    call ndiso_put
    mov  eax, [rbx + 24]
    and  eax, 0xFFFF
    mov  ecx, 4
    call ndiso_put_hex
    mov  al, ':'
    call ndiso_put_char
    mov  eax, [rbx + 24]
    shr  eax, 16
    mov  ecx, 4
    call ndiso_put_hex
    lea  rsi, [rel ndiso_s_at]
    call ndiso_put
    movzx eax, word [rbx + 4]
    call ndiso_put_bdf
    movzx eax, byte [rbx + 1]
    cmp  eax, ISO_PROTECTED
    jb   .plain
    cmp  eax, ISO_SHARED_DMA
    ja   .plain
    cmp  word [rbx + 12], 0
    je   .plain                          ; no group facts: no group claim
    lea  rsi, [rel ndiso_s_shares]
    call ndiso_put
    mov  edi, [rsp + 64]
    call ndiso_put_list
    mov  al, '.'
    call ndiso_put_char
    cmp  word [rbx + 6], NDISO_NONE16
    je   .final
    movzx eax, byte [rbx + 2]
    cmp  eax, NDISO_ACS_ABSENT
    jb   .final
    cmp  eax, NDISO_ACS_UNOBSERVED
    ja   .final                          ; PROVEN: no port sentence (form b)
    lea  rsi, [rel ndiso_s_port]
    call ndiso_put
    movzx eax, word [rbx + 6]
    call ndiso_put_bdf
    lea  rsi, [rel ndiso_s_close]
    call ndiso_put
    movzx eax, byte [rbx + 2]
    lea  rcx, [rel ndiso_acs_words]
    movsxd rsi, dword [rcx + rax*4 - 4]
    add  rsi, rcx
    call ndiso_put
    mov  al, '.'
    call ndiso_put_char
    jmp  .final
.plain:
    lea  rsi, [rel ndiso_s_plain]        ; form c
    call ndiso_put
.final:
    lea  rsi, [rel ndiso_s_final]
    call ndiso_put
    mov  al, 10
    call ndiso_put_char
    ; ---- line 2: the adapter that holds egress (INPUT110053 table) ----
    call netdev_select_peek
    mov  rbp, rax
    test rax, rax
    jz   .walk
    test dword [rbp + dev.flags], NETDEV_F_ABSENT
    jnz  .walk
    call ndiso_is_usb
    mov  ebx, eax
    mov  rdi, rbp
    call netcheck_selected_link
    test ebx, ebx
    jz   .native
    lea  rsi, [rel ndiso_s_using_usb]
    cmp  eax, NDISO_LINK_UP
    je   .usb_using
    lea  rsi, [rel ndiso_s_no_link]
    cmp  eax, NDISO_LINK_DOWN
    je   .usb_found
    lea  rsi, [rel ndiso_s_not_in_use]   ; not the stack's NIC, or never sampled
.usb_found:
    push rsi
    push rsi
    lea  rsi, [rel ndiso_s_usb_found]
    call ndiso_put
    mov  rdi, rbp
    call ndiso_put_name
    pop  rsi
    pop  rsi
    call ndiso_put
    jmp  .measure
.usb_using:
    call ndiso_put
    mov  rdi, rbp
    call ndiso_put_name
    lea  rsi, [rel ndiso_s_own_driver]
    call ndiso_put
    jmp  .measure
.native:
    cmp  eax, NDISO_LINK_UP
    jne  .walk                           ; a native card is named only while it carries traffic
    cmp  dword [rbp + dev.prio], PRIO_DOMAIN
    jbe  .walk                           ; a share-back relay or loopback carries no LAN
    lea  rsi, [rel ndiso_s_using_card]
    call ndiso_put
    mov  rdi, rbp
    call ndiso_put_name
    lea  rsi, [rel ndiso_s_card_tail]
    call ndiso_put
    jmp  .measure
.walk:
    ; A registered USB adapter that does not hold egress: found, never "using".
    xor  ebx, ebx
.slot:
    cmp  ebx, NETDEV_MAX_SLOTS
    jae  .none
    mov  edi, ebx
    mov  rsi, rsp
    call netdev_member_brief
    inc  ebx
    test rax, rax
    jnz  .slot
    test dword [rsp + netdev_minfo.flags], NETDEV_F_ABSENT
    jnz  .slot
    mov  rax, [rsp + netdev_minfo.handle]
    call ndiso_is_usb
    test eax, eax
    jz   .slot
    mov  rbp, [rsp + netdev_minfo.handle]
    lea  rsi, [rel ndiso_s_not_in_use]
    jmp  .usb_found
.none:
    lea  rsi, [rel ndiso_s_no_network]
    call ndiso_put
.measure:
    test r15d, r15d
    jnz  .too_long
    cmp  r14d, NDISO_TEXT_MAX
    ja   .too_long
    mov  rdi, r12
    mov  esi, r14d
    call ndiso_text_rows
    cmp  eax, NDISO_ROWS
    jbe  .copy
.too_long:
    cmp  dword [rsp + 64], 0
    jne  .small                          ; collapsed and still too long: the short form
    mov  dword [rsp + 64], 1
    jmp  .compose
.copy:
    cmp  r14d, [rsp + 56]
    ja   .small
    mov  rdi, [rsp + 48]
    xor  ecx, ecx
.byte:
    cmp  ecx, r14d
    jae  .done
    mov  al, [r12 + rcx]
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .byte
.done:
    mov  eax, r14d
    jmp  .ret
.small:
    mov  eax, -1
.ret:
    add  rsp, 72
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ndiso_text_rows(RDI=text, ESI=len) -> EAX = rows the text fills when each
; LF-separated line is wrapped greedily at single spaces into rows of at most
; NDISO_ROW_GLYPHS glyphs: a word joins the open row when row + 1 + word fits,
; else opens a row; a word longer than a row takes ceil(word / glyphs) rows; a
; line starts a new row. The rule FS's Connection rows use (FS110048). Clobbers
; RAX, RCX, RDX, R8-R11.
ndiso_text_rows:
    xor  eax, eax                        ; rows
    xor  r8d, r8d                        ; open row length (0 = none)
    xor  ecx, ecx
.word:
    xor  edx, edx
.wlen:
    lea  r9d, [rcx + rdx]
    cmp  r9d, esi
    jae  .place
    mov  r10b, [rdi + r9]
    cmp  r10b, ' '
    je   .place
    cmp  r10b, 10
    je   .place
    inc  edx
    jmp  .wlen
.place:
    test edx, edx
    jz   .sep
    test r8d, r8d
    jz   .open
    lea  r11d, [r8 + rdx + 1]
    cmp  r11d, NDISO_ROW_GLYPHS
    ja   .open
    mov  r8d, r11d
    jmp  .sep
.open:
    mov  r11d, edx
.split:
    inc  eax
    cmp  r11d, NDISO_ROW_GLYPHS
    jbe  .last
    sub  r11d, NDISO_ROW_GLYPHS
    jmp  .split
.last:
    mov  r8d, r11d
.sep:
    add  ecx, edx
    cmp  ecx, esi
    jae  .out
    cmp  byte [rdi + rcx], 10
    jne  .space
    xor  r8d, r8d
.space:
    inc  ecx
    jmp  .word
.out:
    ret

; The render's appenders share its registers: R12 buf, R13D cap, R14D length,
; R15D overflow. Past the cap nothing more is written and the overflow flag
; is set. Clobber RAX, RCX, RDX, RSI as noted.
; ndiso_put(RSI = NUL-terminated text). Clobbers RAX, RSI.
ndiso_put:
.next:
    mov  al, [rsi]
    test al, al
    jz   .ret
    call ndiso_put_char
    inc  rsi
    jmp  .next
.ret:
    ret

; ndiso_put_char(AL).
ndiso_put_char:
    cmp  r14d, r13d
    jae  .over
    mov  [r12 + r14], al
    inc  r14d
    ret
.over:
    mov  r15d, 1
    ret

; ndiso_put_hex(EAX = value, ECX = digits), lower-case. Clobbers RAX, RCX, RDX.
ndiso_put_hex:
    mov  edx, eax
.digit:
    test ecx, ecx
    jz   .ret
    dec  ecx
    mov  eax, edx
    shl  ecx, 2
    shr  eax, cl
    shr  ecx, 2
    and  eax, 15
    push rdx
    push rcx
    lea  rdx, [rel ndiso_hex]
    mov  al, [rdx + rax]
    call ndiso_put_char
    pop  rcx
    pop  rdx
    jmp  .digit
.ret:
    ret

; ndiso_put_bdf(EAX = packed BDF) -> "bb:dd.f". Clobbers RAX, RCX, RDX.
ndiso_put_bdf:
    push rbx
    mov  ebx, eax
    shr  eax, 8
    mov  ecx, 2
    call ndiso_put_hex
    mov  al, ':'
    call ndiso_put_char
    mov  eax, ebx
    shr  eax, 3
    and  eax, 31
    mov  ecx, 2
    call ndiso_put_hex
    mov  al, '.'
    call ndiso_put_char
    mov  eax, ebx
    and  eax, 7
    mov  ecx, 1
    call ndiso_put_hex
    pop  rbx
    ret

; ndiso_put_list(EDI = collapse): the page's categories in fixed order, joined
; by "; " (never a comma). A PROTECTED storage member (VT-d) reads "the boot
; disk controller"; every other name is the plain class string (SEC110052).
; Collapsed: "<first>; other devices". Reads nd_iso_page +12/+14. Clobbers
; RAX, RCX, RSI.
ndiso_put_list:
    push rbx
    push rbp
    push rdi                             ; [rsp] = collapse
    movzx ebx, word [rel nd_iso_page + 12]
    and  ebx, (1 << NDISO_CATS) - 1
    xor  ebp, ebp                        ; category index
.cat:
    cmp  ebp, NDISO_CATS
    jae  .ret
    bt   ebx, ebp
    jnc  .next
    btr  ebx, ebp
    test ebp, ebp
    jnz  .plain                          ; only storage has a protected name
    test byte [rel nd_iso_page + 14], 1
    jz   .plain
    lea  rsi, [rel ndiso_s_pcat_storage]
    jmp  .put
.plain:
    lea  rcx, [rel ndiso_cat_words]
    movsxd rsi, dword [rcx + rbp*4]
    add  rsi, rcx
.put:
    call ndiso_put
    test ebx, ebx
    jz   .ret                            ; that was the last one
    lea  rsi, [rel ndiso_s_semi]
    call ndiso_put
    cmp  dword [rsp], 0
    je   .next
    lea  rsi, [rel ndiso_s_cat_other]    ; collapsed: the rest as one phrase
    call ndiso_put
    jmp  .ret
.next:
    inc  ebp
    jmp  .cat
.ret:
    pop  rdi
    pop  rbp
    pop  rbx
    ret

; ndiso_put_name(RDI = member handle): dev.name (set by every NIC backend),
; else its netdev_info.name, else "network". PaOS's own registry strings only.
ndiso_put_name:
    mov  rsi, [rdi + dev.name]
    test rsi, rsi
    jnz  .put
    mov  rsi, [rdi + dev.info]
    test rsi, rsi
    jz   .fallback
    mov  rsi, [rsi + netdev_info.name]
    test rsi, rsi
    jnz  .put
.fallback:
    lea  rsi, [rel ndiso_s_network]
.put:
    jmp  ndiso_put

; ndiso_is_usb(RAX = member handle) -> EAX 1 when its dev.ops is a native USB
; Ethernet backend's: the USB prefix of W4a's netdev_ops_no_requester (pinned
; equal by a HOST row), never NETF_USB. Clobbers RAX, RCX.
ndiso_is_usb:
    mov  rax, [rax + dev.ops]
    lea  rcx, [rel ax_ops]
    cmp  rax, rcx
    je   .yes
    lea  rcx, [rel axb_ops]
    cmp  rax, rcx
    je   .yes
    lea  rcx, [rel cdc_ecm_ops]
    cmp  rax, rcx
    je   .yes
    lea  rcx, [rel cdc_ncm_ops]
    cmp  rax, rcx
    je   .yes
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

align 4
ndiso_acs_words:                         ; acs_state 1..3, rel32 from this label
    dd ndiso_s_acs_absent - ndiso_acs_words
    dd ndiso_s_acs_not_enabled - ndiso_acs_words
    dd ndiso_s_acs_unobserved - ndiso_acs_words
ndiso_cat_words:                         ; category bit 0..5, rel32 from this label
    dd ndiso_s_cat_storage - ndiso_cat_words, ndiso_s_cat_usb - ndiso_cat_words
    dd ndiso_s_cat_net - ndiso_cat_words, ndiso_s_cat_display - ndiso_cat_words
    dd ndiso_s_cat_audio - ndiso_cat_words, ndiso_s_cat_other - ndiso_cat_words
ndiso_hex: db '0123456789abcdef'
; SEC110040: shown verbatim by the GUI on the isolation-refusal outcome (38 bytes).
ndiso_short_text: db "Card can't be isolated: see list below", 0
ndiso_s_card: db 'Network card ', 0
ndiso_s_at: db ' at ', 0
ndiso_s_shares: db " can't be isolated: it shares an isolation group with: ", 0
ndiso_s_plain: db " can't be isolated.", 0
ndiso_s_port: db ' The PCIe root port above it (', 0
ndiso_s_close: db ') ', 0
ndiso_s_acs_absent: db 'has no ACS', 0
ndiso_s_acs_not_enabled: db 'has no proven ACS isolation', 0
ndiso_s_acs_unobserved: db 'could not be checked for ACS', 0
ndiso_s_final: db ' PaOS will not give it to the network domain.', 0
ndiso_s_semi: db '; ', 0
ndiso_s_cat_storage: db 'a storage controller', 0
ndiso_s_cat_usb: db 'a USB controller', 0
ndiso_s_cat_net: db 'another network card', 0
ndiso_s_cat_display: db 'a display controller', 0
ndiso_s_cat_audio: db 'an audio device', 0
ndiso_s_cat_other: db 'other devices', 0
ndiso_s_pcat_storage: db 'the boot disk controller', 0
ndiso_s_using_card: db 'Network is using the ', 0
ndiso_s_card_tail: db " network card with PaOS's own driver.", 0
ndiso_s_using_usb: db 'Network is using the USB adapter ', 0
ndiso_s_own_driver: db " with PaOS's own driver.", 0
ndiso_s_usb_found: db 'USB adapter ', 0
ndiso_s_no_link: db ' found; no cable link yet.', 0
ndiso_s_not_in_use: db ' found; not in use yet.', 0
ndiso_s_network: db 'network', 0
%ifndef PAOS_NATIVE_DRIVER_DEFAULT
%define PAOS_NATIVE_DRIVER_DEFAULT 0
%endif
%if PAOS_NATIVE_DRIVER_DEFAULT
; boot_only denies native USB Ethernet (class 6) by design: no USB offer.
ndiso_s_no_network: db 'No network.', 0
%else
ndiso_s_no_network: db 'No network. Connect a supported USB Ethernet adapter and restart (see release notes).', 0
%endif
%include "core/abi/wdata.inc"
%macro WDATA_hv_nd_isolation 0
align 8
nd_iso_page: times NDISO_PAGE_BYTES db 0
nd_iso_scope_page: times 48 db 0       ; NAS1 retained with the first boot refusal
nd_group_refusal_page: times 32 db 0
%endmacro
WDATA_DEFER WDATA_hv_nd_isolation
%macro WDATA_BSS_hv_nd_isolation_text 0
alignb 8
nd_iso_text: resb NDISO_SCRATCH            ; ndiso_render's compose buffer (BSP-local)
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_nd_isolation_text
