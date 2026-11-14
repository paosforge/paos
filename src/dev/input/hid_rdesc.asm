;; MODULE dev/input/hid_rdesc
;; LAYER 3
;; EXPORTS hid_rdesc_parse, hid_rdesc_parse_touchpad
;; IMPORTS
;; CAPS
;; OWNER saga:input_system
; ============================================================================
; dev/input/hid_rdesc.asm — TP2 `hid_report_descriptor_parser` (hub/touchpad
; lane, 2026-10-01). Pure, bounded, allocation-free HID report-descriptor
; parser shared by USB HID (report protocol) and HID-over-I2C. Written from
; the USB-IF "Device Class Definition for HID 1.11" (§6.2.2 short items:
; prefix = tag[7:4] type[3:2] size[1:0], sizes 0/1/2/4; main/global/local
; semantics, Push/Pop, locals cleared after every main item) and the HID
; Usage Tables (Generic Desktop 0x01, Keyboard 0x07, Button 0x09,
; Digitizers 0x0D). No third-party parser code.
;
; hid_rdesc_parse(rdi=descriptor, esi=length, rdx=layout[128]) -> eax status
; The first top-level Application collection of a supported kind is selected:
;   GD Mouse (0x00010002) -> 1, Digitizer Touch Pad (0x000D0005) -> 2,
;   GD Keyboard (0x00010006) -> 3.
; Input fields of that collection's (first) report ID are located by bit
; offset (excluding the report-ID byte). Touch pads: each Logical collection
; with usage Finger (0x000D0022) is one contact slot (max 5).
; Fail closed: on any error the layout is all zero.
;
; Layout (128 bytes):
;   +0  dd kind            +4  db report_id   +5 db buttons   +6 dw button_off
;   +8  dw x_off  +10 db x_size  +11 db x_rel   +12 dw y_off  +14 db y_size  +15 db y_rel
;   +16 dd x_lmin +20 dd x_lmax  +24 dd y_lmin  +28 dd y_lmax
;   +32 dw wheel_off  +34 db wheel_size  +35 db fingers
;   +36 dw cc_off     +38 db cc_size     +39 db kbd_array_count
;   +40 dw report_bits +42 dw kbd_mod_off +44 dw kbd_array_off +46 db kbd_array_size
;   +48 finger[5] x 16: +0 dw tip_off +2 dw id_off +4 db id_size +5 db have
;                      (b0 tip b1 id b2 x b3 y) +6 dw x_off +8 db x_size
;                      +9 db y_size +10 dw y_off
;   +124 dd present (b0 x/y b1 wheel b2 kbd_mod b3 kbd_array b4 contact_count
;                    b5 buttons)
; ============================================================================

HRD_OK              equ 0
HRD_ERR_TRUNCATED   equ 1
HRD_ERR_LONG_ITEM   equ 2
HRD_ERR_UNBALANCED  equ 3
HRD_ERR_DEPTH       equ 4
HRD_ERR_PUSH        equ 5
HRD_ERR_OVERSIZE    equ 6
HRD_ERR_USAGES      equ 7
HRD_ERR_IDS         equ 8
HRD_ERR_BAD_ID      equ 9
HRD_ERR_NO_APP      equ 10
HRD_ERR_BAD_ARGS    equ 11
HRD_ERR_RESERVED    equ 12

HRD_MAX_LEN         equ 4096
HRD_MAX_DEPTH       equ 8
HRD_MAX_PUSH        equ 4
HRD_MAX_USAGES      equ 16
HRD_MAX_IDS         equ 16
HRD_MAX_FINGERS     equ 5
HRD_MAX_REPORT_BITS equ 4096

L_KIND      equ 0
L_RID       equ 4
L_BUTTONS   equ 5
L_BTN_OFF   equ 6
L_X_OFF     equ 8
L_X_SIZE    equ 10
L_X_REL     equ 11
L_Y_OFF     equ 12
L_Y_SIZE    equ 14
L_Y_REL     equ 15
L_X_LMIN    equ 16
L_X_LMAX    equ 20
L_Y_LMIN    equ 24
L_Y_LMAX    equ 28
L_WHEEL_OFF equ 32
L_WHEEL_SZ  equ 34
L_FINGERS   equ 35
L_CC_OFF    equ 36
L_CC_SIZE   equ 38
L_KA_COUNT  equ 39
L_BITS      equ 40
L_KMOD_OFF  equ 42
L_KA_OFF    equ 44
L_KA_SIZE   equ 46
L_FINGER    equ 48
LF_TIP_OFF  equ 0
LF_ID_OFF   equ 2
LF_ID_SIZE  equ 4
LF_HAVE     equ 5
LF_X_OFF    equ 6
LF_X_SIZE   equ 8
LF_Y_SIZE   equ 9
LF_Y_OFF    equ 10
L_PRESENT   equ 124

P_XY        equ 0x01
P_WHEEL     equ 0x02
P_KMOD      equ 0x04
P_KARRAY    equ 0x08
P_CC        equ 0x10
P_BUTTONS   equ 0x20

; parser frame (r15)
G_PAGE      equ 0
G_LMIN      equ 4
G_LMAX      equ 8
G_RSIZE     equ 12
G_RCOUNT    equ 16
G_RID       equ 20
G_BYTES     equ 32
F_PUSH      equ 32                  ; HRD_MAX_PUSH x G_BYTES
F_PUSHN     equ 160
F_USAGES    equ 168                 ; HRD_MAX_USAGES dd
F_NUSAGES   equ 232
F_SHORTM    equ 236                 ; bit i: usage i was a 1/2-byte (page-less) usage
F_UMIN      equ 240
F_UMAX      equ 244
F_RANGE     equ 248                 ; b0 min b1 max b2 min short b3 max short
F_DEPTH     equ 252
F_APPD      equ 256                 ; depth of the open selected application (0 = none)
F_FINGD     equ 260                 ; depth of the open finger collection (0 = none)
F_FINGI     equ 264                 ; finger slot index (-1 = none yet)
F_SELRID    equ 268                 ; selected report id (-1 = unset)
F_IDS       equ 272                 ; HRD_MAX_IDS dd: b31 used, b23:16 id, b15:0 input bits
F_NIDS      equ 336
F_I         equ 340
F_BASE      equ 344
F_FLAGS     equ 348
F_ENTRY     equ 352                 ; dq pointer to the current id entry
F_PROOF     equ 360                 ; optional strict USB proof[64], normal parser unchanged
F_SIZE      equ 368

; Strict USB entry: same layout[128] ABI, R8=caller-owned proof[64].
; Proof: variable-bit mask[32], five ID maxima dd, contact-count maximum dd.
; Finite absolute, parallel contact reports only. No ignored input authority.
hid_rdesc_parse_touchpad:
    test r8, r8
    jnz  hid_rdesc_parse.entry
    mov  eax, HRD_ERR_BAD_ARGS
    ret

hid_rdesc_parse:
    xor  r8d, r8d
.entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, F_SIZE
    mov  r15, rsp
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    mov  eax, HRD_ERR_BAD_ARGS
    test r14, r14
    jz   .out_raw
    cld
    mov  rdi, r14
    xor  eax, eax
    mov  ecx, 16
    rep  stosq
    mov  rdi, r15
    mov  ecx, F_SIZE / 8
    rep  stosq
    mov  [r15 + F_PROOF], r8
    test r8, r8
    jz   .frame_ready
    mov  rdi, r8
    mov  ecx, 8
    rep  stosq
.frame_ready:
    mov  dword [r15 + F_FINGI], -1
    mov  dword [r15 + F_SELRID], -1
    mov  eax, HRD_ERR_BAD_ARGS
    test r12, r12
    jz   .fail
    test r13d, r13d
    jz   .fail
    cmp  r13d, HRD_MAX_LEN
    ja   .fail
    add  r13, r12                   ; r13 = end

.item:
    cmp  r12, r13
    jae  .end
    movzx ebx, byte [r12]
    inc  r12
    mov  eax, HRD_ERR_LONG_ITEM
    cmp  ebx, 0xFE
    je   .fail
    mov  ecx, ebx
    and  ecx, 3
    cmp  ecx, 3
    jne  .nbytes
    mov  ecx, 4
.nbytes:
    mov  rax, r13
    sub  rax, r12
    cmp  rax, rcx
    jb   .err_trunc
    xor  edx, edx                   ; edx = unsigned data
    xor  r8d, r8d                   ; r8d = sign-extended data
    cmp  ecx, 1
    je   .d1
    cmp  ecx, 2
    je   .d2
    cmp  ecx, 4
    je   .d4
    jmp  .have
.d1:
    movzx edx, byte [r12]
    movsx r8d, byte [r12]
    jmp  .adv
.d2:
    movzx edx, word [r12]
    movsx r8d, word [r12]
    jmp  .adv
.d4:
    mov  edx, [r12]
    mov  r8d, edx
.adv:
    add  r12, rcx
.have:
    mov  r9d, ecx                   ; data bytes
    mov  eax, ebx
    shr  eax, 2
    and  eax, 3
    mov  r10d, ebx
    shr  r10d, 4                    ; tag
    test eax, eax
    jz   .main
    cmp  eax, 1
    je   .global
    cmp  eax, 2
    je   .local
    jmp  .err_reserved

; ---- global items ----
.global:
    cmp  r10d, 0
    jne  .g1
    mov  [r15 + G_PAGE], edx
    jmp  .item
.g1:
    cmp  r10d, 1
    jne  .g2
    mov  [r15 + G_LMIN], r8d
    jmp  .item
.g2:
    cmp  r10d, 2
    jne  .g7
    mov  eax, r8d
    cmp  dword [r15 + G_LMIN], 0
    jl   .lmax_store
    test r8d, r8d
    jns  .lmax_store
    cmp  r9d, 4
    je   .lmax_store
    mov  eax, edx                   ; non-negative minimum: a short maximum is unsigned
.lmax_store:
    mov  [r15 + G_LMAX], eax
    jmp  .item
.g7:
    cmp  r10d, 6
    jbe  .item                      ; physical min/max, unit exponent, unit: not used
    cmp  r10d, 7
    jne  .g8
    mov  [r15 + G_RSIZE], edx
    jmp  .item
.g8:
    cmp  r10d, 8
    jne  .g9
    mov  eax, HRD_ERR_BAD_ID
    test edx, edx
    jz   .fail
    cmp  edx, 255
    ja   .fail
    mov  [r15 + G_RID], edx
    jmp  .item
.g9:
    cmp  r10d, 9
    jne  .g10
    mov  [r15 + G_RCOUNT], edx
    jmp  .item
.g10:
    cmp  r10d, 10
    jne  .g11
    mov  eax, [r15 + F_PUSHN]
    cmp  eax, HRD_MAX_PUSH
    jae  .err_push
    imul eax, eax, G_BYTES
    lea  rdi, [r15 + F_PUSH + rax]
    mov  rsi, r15
    mov  ecx, G_BYTES / 8
    rep  movsq
    inc  dword [r15 + F_PUSHN]
    jmp  .item
.g11:
    cmp  r10d, 11
    jne  .err_reserved
    mov  eax, [r15 + F_PUSHN]
    test eax, eax
    jz   .err_push
    dec  eax
    mov  [r15 + F_PUSHN], eax
    imul eax, eax, G_BYTES
    lea  rsi, [r15 + F_PUSH + rax]
    mov  rdi, r15
    mov  ecx, G_BYTES / 8
    rep  movsq
    jmp  .item

; ---- local items ----
.local:
    cmp  r10d, 0
    jne  .l1
    mov  eax, [r15 + F_NUSAGES]
    cmp  eax, HRD_MAX_USAGES
    jae  .err_usages
    mov  [r15 + F_USAGES + rax*4], edx
    cmp  r9d, 4
    je   .l0_full
    bts  dword [r15 + F_SHORTM], eax
.l0_full:
    inc  dword [r15 + F_NUSAGES]
    jmp  .item
.l1:
    cmp  r10d, 1
    jne  .l2
    mov  [r15 + F_UMIN], edx
    or   dword [r15 + F_RANGE], 1
    cmp  r9d, 4
    je   .item
    or   dword [r15 + F_RANGE], 4
    jmp  .item
.l2:
    cmp  r10d, 2
    jne  .l3
    mov  [r15 + F_UMAX], edx
    or   dword [r15 + F_RANGE], 2
    cmp  r9d, 4
    je   .item
    or   dword [r15 + F_RANGE], 8
    jmp  .item
.l3:
    cmp  qword [r15 + F_PROOF], 0
    je   .local_unused
    cmp  r10d, 10
    je   .err_reserved             ; delimiter alternatives are outside USB profile
.local_unused:
    cmp  r10d, 10
    jbe  .item                      ; designators, strings, delimiter: accepted, unused
    jmp  .err_reserved

; ---- main items ----
.main:
    cmp  r10d, 8
    je   .input
    cmp  r10d, 9
    je   .main_done                 ; Output
    cmp  r10d, 11
    je   .main_done                 ; Feature
    cmp  r10d, 10
    je   .collection
    cmp  r10d, 12
    je   .end_collection
    jmp  .err_reserved

.collection:
    mov  eax, [r15 + F_DEPTH]
    cmp  eax, HRD_MAX_DEPTH
    jae  .err_depth
    inc  eax
    mov  [r15 + F_DEPTH], eax
    mov  [r15 + F_FLAGS], edx       ; collection type
    xor  ecx, ecx
    call .resolve
    mov  ecx, [r15 + F_DEPTH]
    cmp  qword [r15 + F_PROOF], 0
    je   .collection_mode
    call .touchpad_collection
    jc   .err_reserved
.collection_mode:
    cmp  ecx, 1
    jne  .coll_inner
    cmp  byte [r15 + F_FLAGS], 1    ; Application
    jne  .main_done
    cmp  dword [r14 + L_KIND], 0
    jne  .main_done
    mov  edx, 1
    cmp  eax, 0x00010002
    je   .select
    mov  edx, 2
    cmp  eax, 0x000D0005
    je   .select
    mov  edx, 3
    cmp  eax, 0x00010006
    je   .select
    jmp  .main_done
.select:
    mov  [r14 + L_KIND], edx
    mov  dword [r15 + F_APPD], 1
    jmp  .main_done
.coll_inner:
    cmp  dword [r15 + F_APPD], 0
    je   .main_done
    cmp  dword [r14 + L_KIND], 2
    jne  .main_done
    cmp  byte [r15 + F_FLAGS], 2    ; Logical
    jne  .main_done
    cmp  eax, 0x000D0022            ; Finger
    jne  .main_done
    inc  dword [r15 + F_FINGI]
    mov  [r15 + F_FINGD], ecx
    jmp  .main_done

.end_collection:
    mov  eax, [r15 + F_DEPTH]
    test eax, eax
    jz   .err_unbal
    cmp  eax, [r15 + F_FINGD]
    jne  .ec_app
    mov  dword [r15 + F_FINGD], 0
.ec_app:
    cmp  eax, [r15 + F_APPD]
    jne  .ec_dec
    mov  dword [r15 + F_APPD], 0
.ec_dec:
    dec  dword [r15 + F_DEPTH]
    jmp  .main_done

.input:
    mov  [r15 + F_FLAGS], edx
    cmp  qword [r15 + F_PROOF], 0
    je   .input_mode
    call .touchpad_input
    jc   .err_reserved
.input_mode:
    mov  eax, HRD_ERR_OVERSIZE
    cmp  dword [r15 + G_RSIZE], 32
    ja   .fail
    cmp  dword [r15 + G_RCOUNT], 255
    ja   .fail
    call .id_entry                  ; rax = entry pointer, or CF=1 table full
    jc   .err_ids
    mov  [r15 + F_ENTRY], rax
    movzx ecx, word [rax]
    mov  [r15 + F_BASE], ecx
    mov  eax, [r15 + G_RSIZE]
    imul eax, [r15 + G_RCOUNT]
    add  eax, ecx
    cmp  eax, HRD_MAX_REPORT_BITS
    ja   .err_oversize
    mov  rdx, [r15 + F_ENTRY]
    mov  [rdx], ax                  ; account the bits before field assignment
    cmp  dword [r15 + F_APPD], 0
    je   .main_done
    mov  eax, [r15 + G_RID]
    cmp  dword [r15 + F_SELRID], -1
    jne  .sel_known
    mov  [r15 + F_SELRID], eax
.sel_known:
    cmp  eax, [r15 + F_SELRID]
    jne  .main_done
    test dword [r15 + F_FLAGS], 1   ; Constant: padding only
    jnz  .main_done
    test dword [r15 + F_FLAGS], 2   ; Variable?
    jnz  .vars
    cmp  dword [r14 + L_KIND], 3
    jne  .main_done
    test dword [r14 + L_PRESENT], P_KARRAY
    jnz  .main_done
    mov  eax, [r15 + F_BASE]
    mov  [r14 + L_KA_OFF], ax
    mov  eax, [r15 + G_RCOUNT]
    mov  [r14 + L_KA_COUNT], al
    mov  eax, [r15 + G_RSIZE]
    mov  [r14 + L_KA_SIZE], al
    or   dword [r14 + L_PRESENT], P_KARRAY
    jmp  .main_done
.vars:
    mov  dword [r15 + F_I], 0
.var_loop:
    mov  ecx, [r15 + F_I]
    cmp  ecx, [r15 + G_RCOUNT]
    jae  .main_done
    call .resolve
    mov  ecx, [r15 + F_I]
    imul ecx, [r15 + G_RSIZE]
    add  ecx, [r15 + F_BASE]        ; ecx = bit offset of this field
    cmp  qword [r15 + F_PROOF], 0
    je   .field_mode
    push rax
    push rcx
    call .touchpad_field
    pop  rcx
    pop  rax
    jc   .err_reserved
.field_mode:
    call .assign
    inc  dword [r15 + F_I]
    jmp  .var_loop

.main_done:                         ; locals end with every main item
    xor  eax, eax
    mov  [r15 + F_NUSAGES], eax
    mov  [r15 + F_SHORTM], eax
    mov  [r15 + F_RANGE], eax
    jmp  .item

.end:
    mov  eax, HRD_ERR_UNBALANCED
    cmp  dword [r15 + F_DEPTH], 0
    jne  .fail
    mov  eax, HRD_ERR_NO_APP
    cmp  dword [r14 + L_KIND], 0
    je   .fail
    mov  eax, [r15 + F_SELRID]
    cmp  eax, -1
    jne  .rid_ok
    xor  eax, eax
.rid_ok:
    mov  [r14 + L_RID], al
    mov  [r15 + G_RID], eax
    call .id_entry
    jc   .err_ids
    movzx ecx, word [rax]
    mov  [r14 + L_BITS], cx
    mov  eax, [r15 + F_FINGI]
    inc  eax                        ; -1 -> 0
    cmp  eax, HRD_MAX_FINGERS
    jbe  .fingers
    mov  eax, HRD_MAX_FINGERS
.fingers:
    mov  [r14 + L_FINGERS], al
    cmp  qword [r15 + F_PROOF], 0
    je   .profile_done
    call .touchpad_end
    jc   .err_reserved
.profile_done:
    xor  eax, eax
    jmp  .out

.err_trunc:
    mov  eax, HRD_ERR_TRUNCATED
    jmp  .fail
.err_reserved:
    mov  eax, HRD_ERR_RESERVED
    jmp  .fail
.err_push:
    mov  eax, HRD_ERR_PUSH
    jmp  .fail
.err_usages:
    mov  eax, HRD_ERR_USAGES
    jmp  .fail
.err_depth:
    mov  eax, HRD_ERR_DEPTH
    jmp  .fail
.err_unbal:
    mov  eax, HRD_ERR_UNBALANCED
    jmp  .fail
.err_ids:
    mov  eax, HRD_ERR_IDS
    jmp  .fail
.err_oversize:
    mov  eax, HRD_ERR_OVERSIZE
.fail:
    mov  ebx, eax                   ; fail closed: the layout reads all zero
    mov  rdi, r14
    xor  eax, eax
    mov  ecx, 16
    rep  stosq
    mov  eax, ebx
.out:
.out_raw:
    add  rsp, F_SIZE
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; .resolve(ecx = field index) -> eax = 32-bit usage (page:id), 0 = none.
; Clobbers ecx, edx, esi.
.resolve:
    mov  esi, [r15 + F_NUSAGES]
    test esi, esi
    jz   .res_range
    cmp  ecx, esi
    jb   .res_idx
    lea  ecx, [esi - 1]             ; the last usage repeats for the remaining fields
.res_idx:
    mov  eax, [r15 + F_USAGES + rcx*4]
    bt   dword [r15 + F_SHORTM], ecx
    jnc  .res_ret
    movzx eax, ax
    mov  edx, [r15 + G_PAGE]
    shl  edx, 16
    or   eax, edx
.res_ret:
    ret
.res_range:
    test dword [r15 + F_RANGE], 1
    jz   .res_none
    mov  eax, [r15 + F_UMIN]
    test dword [r15 + F_RANGE], 4
    jz   .res_min_full
    movzx eax, ax
    mov  edx, [r15 + G_PAGE]
    shl  edx, 16
    or   eax, edx
.res_min_full:
    add  eax, ecx
    test dword [r15 + F_RANGE], 2
    jz   .res_ret
    mov  edx, [r15 + F_UMAX]
    test dword [r15 + F_RANGE], 8
    jz   .res_max_full
    movzx edx, dx
    mov  esi, [r15 + G_PAGE]
    shl  esi, 16
    or   edx, esi
.res_max_full:
    cmp  eax, edx
    jbe  .res_ret
.res_none:
    xor  eax, eax
    ret

; .id_entry -> rax = pointer to the id-table entry for G_RID (created on first
; use), CF=1 when the table is full. Clobbers ecx, edx, esi.
.id_entry:
    mov  edx, [r15 + G_RID]
    shl  edx, 16
    or   edx, 0x80000000
    xor  ecx, ecx
.id_scan:
    cmp  ecx, [r15 + F_NIDS]
    jae  .id_new
    mov  esi, [r15 + F_IDS + rcx*4]
    and  esi, 0xFFFF0000
    cmp  esi, edx
    je   .id_found
    inc  ecx
    jmp  .id_scan
.id_new:
    cmp  ecx, HRD_MAX_IDS
    jae  .id_full
    mov  [r15 + F_IDS + rcx*4], edx
    inc  dword [r15 + F_NIDS]
.id_found:
    lea  rax, [r15 + F_IDS + rcx*4]
    clc
    ret
.id_full:
    stc
    ret

; .assign(eax = usage, ecx = bit offset) for one Variable input field.
; Clobbers eax, edx, esi, edi.
.assign:
    mov  edi, [r15 + G_RSIZE]
    mov  edx, [r15 + F_FLAGS]
    shr  edx, 2
    and  edx, 1                     ; Relative
    cmp  eax, 0x00010030
    je   .as_x
    cmp  eax, 0x00010031
    je   .as_y
    cmp  eax, 0x00010038
    je   .as_wheel
    cmp  eax, 0x000D0042
    je   .as_tip
    cmp  eax, 0x000D0051
    je   .as_cid
    cmp  eax, 0x000D0054
    je   .as_cc
    mov  esi, eax
    shr  esi, 16
    cmp  esi, 0x0009
    je   .as_button
    cmp  esi, 0x0007
    je   .as_key
    ret
.as_x:
    call .finger_slot               ; rsi = slot or 0
    test rsi, rsi
    jz   .as_x_top
    mov  [rsi + LF_X_OFF], cx
    mov  [rsi + LF_X_SIZE], dil
    or   byte [rsi + LF_HAVE], 4
    cmp  dword [r15 + F_FINGI], 0
    jne  .as_ret
    mov  eax, [r15 + G_LMIN]
    mov  [r14 + L_X_LMIN], eax
    mov  eax, [r15 + G_LMAX]
    mov  [r14 + L_X_LMAX], eax
    ret
.as_x_top:
    cmp  dword [r14 + L_KIND], 2
    je   .as_ret
    cmp  byte [r14 + L_X_SIZE], 0
    jne  .as_ret
    mov  [r14 + L_X_OFF], cx
    mov  [r14 + L_X_SIZE], dil
    mov  [r14 + L_X_REL], dl
    mov  eax, [r15 + G_LMIN]
    mov  [r14 + L_X_LMIN], eax
    mov  eax, [r15 + G_LMAX]
    mov  [r14 + L_X_LMAX], eax
    jmp  .as_xy_present
.as_y:
    call .finger_slot
    test rsi, rsi
    jz   .as_y_top
    mov  [rsi + LF_Y_OFF], cx
    mov  [rsi + LF_Y_SIZE], dil
    or   byte [rsi + LF_HAVE], 8
    cmp  dword [r15 + F_FINGI], 0
    jne  .as_ret
    mov  eax, [r15 + G_LMIN]
    mov  [r14 + L_Y_LMIN], eax
    mov  eax, [r15 + G_LMAX]
    mov  [r14 + L_Y_LMAX], eax
    ret
.as_y_top:
    cmp  dword [r14 + L_KIND], 2
    je   .as_ret
    cmp  byte [r14 + L_Y_SIZE], 0
    jne  .as_ret
    mov  [r14 + L_Y_OFF], cx
    mov  [r14 + L_Y_SIZE], dil
    mov  [r14 + L_Y_REL], dl
    mov  eax, [r15 + G_LMIN]
    mov  [r14 + L_Y_LMIN], eax
    mov  eax, [r15 + G_LMAX]
    mov  [r14 + L_Y_LMAX], eax
.as_xy_present:
    cmp  byte [r14 + L_X_SIZE], 0
    je   .as_ret
    cmp  byte [r14 + L_Y_SIZE], 0
    je   .as_ret
    or   dword [r14 + L_PRESENT], P_XY
    ret
.as_wheel:
    test dword [r14 + L_PRESENT], P_WHEEL
    jnz  .as_ret
    mov  [r14 + L_WHEEL_OFF], cx
    mov  [r14 + L_WHEEL_SZ], dil
    or   dword [r14 + L_PRESENT], P_WHEEL
    ret
.as_tip:
    call .finger_slot
    test rsi, rsi
    jz   .as_ret
    test byte [rsi + LF_HAVE], 1
    jnz  .as_ret
    mov  [rsi + LF_TIP_OFF], cx
    or   byte [rsi + LF_HAVE], 1
    ret
.as_cid:
    call .finger_slot
    test rsi, rsi
    jz   .as_ret
    mov  [rsi + LF_ID_OFF], cx
    mov  [rsi + LF_ID_SIZE], dil
    or   byte [rsi + LF_HAVE], 2
    ret
.as_cc:
    cmp  dword [r14 + L_KIND], 2
    jne  .as_ret
    test dword [r14 + L_PRESENT], P_CC
    jnz  .as_ret
    mov  [r14 + L_CC_OFF], cx
    mov  [r14 + L_CC_SIZE], dil
    or   dword [r14 + L_PRESENT], P_CC
    ret
.as_button:
    mov  esi, [r14 + L_KIND]
    cmp  esi, 3
    je   .as_ret
    test dword [r14 + L_PRESENT], P_BUTTONS
    jnz  .as_more_buttons
    mov  [r14 + L_BTN_OFF], cx
    or   dword [r14 + L_PRESENT], P_BUTTONS
.as_more_buttons:
    cmp  byte [r14 + L_BUTTONS], 255
    je   .as_ret
    inc  byte [r14 + L_BUTTONS]
    ret
.as_key:
    cmp  dword [r14 + L_KIND], 3
    jne  .as_ret
    and  eax, 0xFFFF
    cmp  eax, 0xE0
    jb   .as_ret
    cmp  eax, 0xE7
    ja   .as_ret
    test dword [r14 + L_PRESENT], P_KMOD
    jnz  .as_ret
    mov  [r14 + L_KMOD_OFF], cx
    or   dword [r14 + L_PRESENT], P_KMOD
.as_ret:
    ret

; .finger_slot -> rsi = layout finger slot of the open finger collection, or 0
.finger_slot:
    xor  esi, esi
    cmp  dword [r15 + F_FINGD], 0
    je   .fs_ret
    mov  eax, [r15 + F_FINGI]
    cmp  eax, HRD_MAX_FINGERS
    jae  .fs_ret
    shl  eax, 4
    lea  rsi, [r14 + L_FINGER + rax]
.fs_ret:
    ret

; Strict entry helpers. Normal hid_rdesc_parse does not enter these paths.
.touchpad_collection:
    cmp  ecx, 1
    jne  .tc_finger
    cmp  dword [r14 + L_KIND], 0
    jne  .tp_bad
    cmp  eax, 0x000D0005
    jne  .tp_bad
    cmp  dword [r15 + F_FLAGS], 1
    jne  .tp_bad
    clc
    ret
.tc_finger:
    cmp  ecx, 2
    jne  .tp_bad
    cmp  dword [r15 + F_FINGD], 0
    jne  .tp_bad
    cmp  dword [r15 + F_FINGI], HRD_MAX_FINGERS - 1
    jge  .tp_bad
    cmp  eax, 0x000D0022
    jne  .tp_bad
    cmp  dword [r15 + F_FLAGS], 2
    jne  .tp_bad
    clc
    ret
.touchpad_input:
    cmp  dword [r15 + F_APPD], 1
    jne  .tp_bad
    mov  eax, [r15 + G_RID]
    cmp  dword [r15 + F_SELRID], -1
    je   .ti_id
    cmp  eax, [r15 + F_SELRID]
    jne  .tp_bad                    ; no silently ignored second Input ID
.ti_id:
    cmp  dword [r15 + G_RSIZE], 1
    jb   .tp_bad
    cmp  dword [r15 + G_RSIZE], 16
    ja   .tp_bad
    cmp  dword [r15 + G_RCOUNT], 1
    jb   .tp_bad
    cmp  dword [r15 + G_RCOUNT], 16
    ja   .tp_bad
    mov  eax, [r15 + F_FLAGS]
    and  eax, ~2
    cmp  eax, 1
    je   .tp_good                   ; absolute Constant, array/variable padding
    cmp  dword [r15 + F_FLAGS], 2
    jne  .tp_bad                    ; no relative/null/buffered/array data
    cmp  dword [r15 + G_LMIN], 0
    jl   .tp_bad
    mov  eax, [r15 + G_LMAX]
    cmp  eax, [r15 + G_LMIN]
    jle  .tp_bad
    mov  ecx, [r15 + G_RSIZE]
    mov  edx, 1
    shl  edx, cl
    dec  edx
    cmp  eax, edx
    ja   .tp_bad
    jmp  .tp_good
.touchpad_field:
    mov  r8, [r15 + F_PROOF]
    mov  r9d, eax                   ; usage
    mov  r10d, ecx                  ; bit offset
    mov  edx, [r15 + G_RSIZE]
    add  edx, ecx
    cmp  edx, 248
    ja   .tp_bad
.tf_mask:
    bts  dword [r8], ecx
    jc   .tp_bad
    inc  ecx
    cmp  ecx, edx
    jb   .tf_mask
    mov  ecx, r10d
    call .finger_slot
    cmp  r9d, 0x000D0054
    je   .tf_count
    mov  eax, r9d
    shr  eax, 16
    cmp  eax, 9
    je   .tf_button
    test rsi, rsi
    jz   .tp_bad
    cmp  r9d, 0x00010030
    je   .tf_x
    cmp  r9d, 0x00010031
    je   .tf_y
    cmp  r9d, 0x000D0051
    je   .tf_id
    cmp  r9d, 0x000D0042
    je   .tf_tip
    cmp  r9d, 0x000D0047
    jne  .tp_bad
    jmp  .tf_binary                 ; optional Confidence, no gesture semantics
.tf_tip:
    test byte [rsi + LF_HAVE], 1
    jnz  .tp_bad
.tf_binary:
    cmp  dword [r15 + G_RSIZE], 1
    jne  .tp_bad
    cmp  dword [r15 + G_LMIN], 0
    jne  .tp_bad
    cmp  dword [r15 + G_LMAX], 1
    jne  .tp_bad
    jmp  .tp_good
.tf_id:
    test byte [rsi + LF_HAVE], 2
    jnz  .tp_bad
    cmp  dword [r15 + G_RSIZE], 8
    ja   .tp_bad
    cmp  dword [r15 + G_LMIN], 0
    jne  .tp_bad
    mov  eax, [r15 + F_FINGI]
    mov  edx, [r15 + G_LMAX]
    mov  [r8 + 32 + rax*4], edx
    jmp  .tp_good
.tf_x:
    mov  edx, 4
    lea  rdi, [r14 + L_X_LMIN]
    jmp  .tf_axis
.tf_y:
    mov  edx, 8
    lea  rdi, [r14 + L_Y_LMIN]
.tf_axis:
    test [rsi + LF_HAVE], dl
    jnz  .tp_bad
    cmp  dword [r15 + F_FINGI], 0
    je   .tp_good
    mov  eax, [r15 + G_LMIN]
    cmp  eax, [rdi]
    jne  .tp_bad
    mov  eax, [r15 + G_LMAX]
    cmp  eax, [rdi + 4]
    jne  .tp_bad
    jmp  .tp_good
.tf_count:
    test rsi, rsi
    jnz  .tp_bad
    test dword [r14 + L_PRESENT], P_CC
    jnz  .tp_bad
    cmp  dword [r15 + G_RSIZE], 8
    ja   .tp_bad
    cmp  dword [r15 + G_LMIN], 0
    jne  .tp_bad
    mov  eax, [r15 + G_LMAX]
    cmp  eax, 5
    ja   .tp_bad
    mov  [r8 + 52], eax
    jmp  .tp_good
.tf_button:
    test rsi, rsi
    jnz  .tp_bad
    movzx eax, byte [r14 + L_BUTTONS]
    inc  eax
    cmp  eax, 3
    ja   .tp_bad
    movzx edx, r9w
    cmp  eax, edx
    jne  .tp_bad
    test dword [r14 + L_PRESENT], P_BUTTONS
    jz   .tf_binary
    movzx eax, word [r14 + L_BTN_OFF]
    movzx edx, byte [r14 + L_BUTTONS]
    add  eax, edx
    cmp  eax, r10d
    jne  .tp_bad
    jmp  .tf_binary
.touchpad_end:
    cmp  dword [r14 + L_KIND], 2
    jne  .tp_bad
    test dword [r14 + L_PRESENT], P_CC
    jz   .tp_bad
    movzx ecx, byte [r14 + L_FINGERS]
    test ecx, ecx
    jz   .tp_bad
    movzx eax, word [r14 + L_BITS]
    test eax, eax
    jz   .tp_bad
    cmp  eax, 248
    ja   .tp_bad
    lea  rsi, [r14 + L_FINGER]
.te_slot:
    cmp  byte [rsi + LF_HAVE], 15
    jne  .tp_bad
    add  rsi, 16
    loop .te_slot
.tp_good:
    clc
    ret
.tp_bad:
    stc
    ret
