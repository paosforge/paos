;; MODULE gui/ime_dict_absent
;; LAYER 6
;; EXPORTS ime_dict_bind, ime_dict_lookup, ime_dict_candidate, ime_dict_bound
;; IMPORTS boot/serial
;; CAPS
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
;
; RCQ-38 I3b-1 (root 15:25 Q1(b)): this image carries no dictionary. gui/ime_dict.asm (I1) reads its shards through
; gui/res_pack, whose reader is not linked yet (rc-boot R2, rc-fs G1b), so I1 is not linked either. This file stands
; in for the three entry points I2 (gui/ime_core) calls, with I1's own codes:
;   ime_dict_bind      accepts locale 1 (ja) and 2 (zh-Hans) with one serial marker: the method runs with no dictionary
;   ime_dict_lookup    IME_E_UNBOUND, so I2 shows UNAVAILABLE on Space and the kana stays editable
;   ime_dict_candidate IME_E_UNBOUND (never reached: I2 has no candidate list without a lookup)
; Any other locale is IME_E_LOCALE, as in I1. No arena, no heap, no I/O but the marker. The dictionary slice replaces
; this file with I1 + res_pack in paos.asm.
;
; One dictionary (root 16:01:48 (2)(b)): this file defines IME_DICT_LINKED and refuses to assemble when it is already
; defined; gui/ime_route refuses to assemble without it; I1 linked beside this file redefines its three entry points,
; which the assembler refuses too. The dictionary slice defines IME_DICT_LINKED beside I1's include.
; Absent is observable (root 16:01:48 (2)(a)): ime_dict_bound is 0, read by every IME state surface.

%ifdef IME_DICT_LINKED
%fatal "two IME dictionaries linked: gui/ime_dict_absent and another"
%endif
%define IME_DICT_LINKED 1

IMD_E_LOCALE        equ 1               ; = ime_dict's IME_E_LOCALE (census-pinned)
IMD_E_UNBOUND       equ 12              ; = ime_dict's IME_E_UNBOUND (census-pinned)

; ime_dict_bind(EDI locale) -> EAX 0 / IMD_E_LOCALE. Clobbers caller-saved.
ime_dict_bind:
    lea  eax, [rdi - 1]
    cmp  eax, 1
    ja   .locale
    cmp  byte [rel imd_marked], 0
    jne  .ok
    mov  byte [rel imd_marked], 1
    sub  rsp, 8
    lea  rdi, [rel str_imd_absent]
    call serial_string
    add  rsp, 8
.ok:
    xor  eax, eax
    ret
.locale:
    mov  eax, IMD_E_LOCALE
    ret

; ime_dict_lookup(EDI locale, RSI key, EDX bytes) / ime_dict_candidate(EDI locale, ESI row, RDX out) -> EAX
; IMD_E_UNBOUND (IMD_E_LOCALE for another locale), ECX/EDX 0. Nothing is written.
ime_dict_lookup:
ime_dict_candidate:
    xor  ecx, ecx
    xor  edx, edx
    lea  eax, [rdi - 1]
    cmp  eax, 1
    mov  eax, IMD_E_UNBOUND
    jbe  .out
    mov  eax, IMD_E_LOCALE
.out:
    ret

ime_dict_bound:      db 0                ; 0: no dictionary in this image (the mode surfaces show it absent)
str_imd_absent:      db "[ime.dict] absent: no dictionary in this image (kana only; Space shows UNAVAILABLE)", 13, 10, 0

%macro WDATA_gui_ime_dict_absent 0
imd_marked:          resb 1              ; the absent marker was printed
%endmacro
WDATA_BSS_DEFER WDATA_gui_ime_dict_absent
