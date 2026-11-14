;; MODULE core/unicode_edit
;; LAYER 1
;; EXPORTS ue_utf8_cstr_prefix, ue_utf8_decode, ue_utf8_encode, ue_utf8_validate, ue_grapheme_next, ue_grapheme_prev, ue_cell_width
;; IMPORTS
;; CAPS
;; OWNER rc-codex-relops
;; CONTEXT: any
; RCQ-38: include-free immutable Unicode 15.1 edit primitives. SysV AMD64.
; No allocation, globals, callbacks or I/O; caller owns stable bounded buffers.
; Explicit lengths permit U+0000. Max input length 1 MiB. See UNICODE_EDIT.md.

ue_code_start:
; RDI bytes, RSI length, RDX offset, RCX writable {u32 scalar,u32 bytes}.
; EAX 1 decoded, 0 end, -1 invalid; output untouched unless EAX=1.
ue_utf8_decode:
    test rcx, rcx
    jz ue_bad
    push rbx
    mov rbx, rcx
    call ue_read
    cmp eax, -2
    je .end
    cmp eax, -1
    je .out
    mov [rbx], eax
    mov [rbx+4], ecx
    mov eax, 1
    jmp .out
.end:
    xor eax, eax
.out:
    pop rbx
    ret
ue_bad:
    mov eax, -1
    ret

; Internal decoder -> EAX scalar / -1 invalid / -2 end; ECX encoded bytes.
; Keeps RDI/RSI/RDX and all nonvolatile registers. Clobbers R8-R11.
ue_read:
    cmp rsi, 1048576
    ja ue_bad
    mov rax, rdi
    add rax, rsi
    jc ue_bad
    test rsi, rsi
    jz .span_ok
    test rdi, rdi
    jz ue_bad
.span_ok:
    cmp rdx, rsi
    ja ue_bad
    je .end
    test rdi, rdi
    jz ue_bad
    movzx eax, byte [rdi+rdx]
    mov ecx, 1
    cmp eax, 0x80
    jb .done
    cmp eax, 0xc2
    jb ue_bad
    mov r8d, 0x80
    mov ecx, 2
    cmp eax, 0xe0
    jb .two
    mov r8d, 0x800
    mov ecx, 3
    cmp eax, 0xf0
    jb .three
    cmp eax, 0xf4
    ja ue_bad
    mov r8d, 0x10000
    mov ecx, 4
    and eax, 7
    jmp .length
.three:
    and eax, 15
    jmp .length
.two:
    and eax, 31
.length:
    mov r9, rsi
    sub r9, rdx
    cmp r9, rcx
    jb ue_bad
    mov r10d, 1
.loop:
    lea r11, [rdi+rdx]
    movzx r9d, byte [r11+r10]
    sub r9d, 0x80
    cmp r9d, 63
    ja ue_bad
    shl eax, 6
    or eax, r9d
    inc r10d
    cmp r10d, ecx
    jb .loop
    cmp eax, r8d
    jb ue_bad
    cmp eax, 0x10ffff
    ja ue_bad
    mov r9d, eax
    and r9d, 0xfffff800
    cmp r9d, 0xd800
    je ue_bad
.done:
    ret
.end:
    mov eax, -2
    ret

; RDI=cstr, RSI=output, RDX=output bytes excluding NUL. Caller owns readable
; input through its NUL or capacity+1 bytes and output capacity+1 bytes. Exact
; in-place copying is supported. No read past an encountered NUL, no lookahead
; beyond capacity, no partial or noncanonical scalar. Does not normalize names.
; -> RAX copied bytes, EDX 0 complete / 1 clipped or malformed. A malformed
; suffix is never repaired into an actionable name: consumers retain EDX.
ue_utf8_cstr_prefix:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16                     ; native decoder output
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    xor  r15d, r15d
.next:
    movzx eax, byte [r12 + r15]      ; only capacity+1st byte tests completion
    test al, al
    jz   .complete
    cmp  r15, r14
    jae  .clipped
    mov  ebx, 1
    cmp  al, 0x80
    jb   .decode
    cmp  al, 0xc2
    jb   .clipped
    mov  ebx, 2
    cmp  al, 0xe0
    jb   .span
    mov  ebx, 3
    cmp  al, 0xf0
    jb   .span
    cmp  al, 0xf4
    ja   .clipped
    mov  ebx, 4
.span:
    mov  rax, r14
    sub  rax, r15
    cmp  rax, rbx
    jb   .clipped                    ; don't inspect a scalar outside the bound
    mov  ecx, 1
.nul:
    lea  rax, [r12 + r15]
    cmp  byte [rax + rcx], 0
    je   .clipped                    ; decoder must not read beyond a short cstr
    inc  ecx
    cmp  ecx, ebx
    jb   .nul
.decode:
    lea  rdi, [r12 + r15]
    mov  esi, ebx
    xor  edx, edx
    mov  rcx, rsp
    call ue_utf8_decode              ; canonical scalar, including surrogate/overlong checks
    cmp  eax, 1
    jne  .clipped
    xor  ecx, ecx
.copy:
    lea  rdi, [r12 + r15]
    mov  al, [rdi + rcx]
    lea  rsi, [r13 + r15]
    mov  [rsi + rcx], al
    inc  ecx
    cmp  ecx, ebx
    jb   .copy
    add  r15, rbx
    jmp  .next
.complete:
    xor  edx, edx
    jmp  .out
.clipped:
    mov  edx, 1
.out:
    mov  byte [r13 + r15], 0
    mov  rax, r15
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI scalar, RSI destination, RDX capacity -> EAX bytes / -1.
; Invalid scalar/short capacity/pointer overflow fails without any write.
ue_utf8_encode:
    cmp edi, 0x10ffff
    ja ue_bad
    mov eax, edi
    and eax, 0xfffff800
    cmp eax, 0xd800
    je ue_bad
    test rsi, rsi
    jz ue_bad
    mov rax, rsi
    add rax, rdx
    jc ue_bad
    mov ecx, 1
    cmp edi, 0x80
    jb .size
    inc ecx
    cmp edi, 0x800
    jb .size
    inc ecx
    cmp edi, 0x10000
    jb .size
    inc ecx
.size:
    cmp rdx, rcx
    jb ue_bad
    mov eax, edi
    mov r8d, ecx
    cmp ecx, 1
    je .first
.tail:
    dec ecx
    mov edx, eax
    and dl, 63
    or dl, 0x80
    mov [rsi+rcx], dl
    shr eax, 6
    cmp ecx, 1
    ja .tail
    mov edx, 0xf0
    cmp r8d, 4
    je .prefix
    mov edx, 0xe0
    cmp r8d, 3
    je .prefix
    mov edx, 0xc0
.prefix:
    or eax, edx
.first:
    mov [rsi], al
    mov eax, r8d
    ret

; RDI bytes, RSI length -> EAX 1 valid / 0 invalid. Empty null span is valid.
ue_utf8_validate:
    xor edx, edx
.loop:
    call ue_read
    cmp eax, -2
    je .yes
    cmp eax, -1
    je .no
    add rdx, rcx
    jmp .loop
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; EDI scalar -> EAX 0/1/2 cells, -1 invalid scalar. Mn/Me/Cf override W/F.
ue_cell_width:
    cmp edi, 0x10ffff
    ja ue_bad
    mov eax, edi
    and eax, 0xfffff800
    cmp eax, 0xd800
    je ue_bad
    call ue_property
    shr eax, 5
    and eax, 3
    ret

; Internal property lookup. EDI scalar -> EAX packed flags; preserves nonvolatiles.
ue_property:
    lea r8, [rel ue_properties]
    xor edx, edx
    mov ecx, UE_PROP_COUNT
.search:
    lea eax, [edx+ecx]
    shr eax, 1
    mov r9d, [r8+rax*4]
    shr r9d, 9
    cmp edi, r9d
    jb .left
    lea edx, [eax+1]
    jmp .more
.left:
    mov ecx, eax
.more:
    cmp edx, ecx
    jb .search
    mov eax, [r8+rdx*4-4]
    and eax, 511
    ; Hangul syllables AC00..D7A3: LV at each multiple of 28, LVT otherwise.
    lea r9d, [rdi-0xac00]
    cmp r9d, 11171
    ja .done
    mov r10d, eax
    mov eax, r9d
    xor edx, edx
    mov ecx, 28
    div ecx
    mov eax, r10d
    and eax, ~15
    or eax, 12
    test edx, edx
    jz .done
    inc eax
.done:
    ret

; RDI immutable valid-or-untrusted UTF8, RSI length, RDX EGC-boundary offset.
; RAX neighboring boundary / -1 invalid UTF8, non-boundary or invalid span.
; Endpoints saturate (prev(0)=0,next(len)=len). Full span checked each call.
ue_grapheme_next:
    mov ecx, 1
    jmp ue_scan
ue_grapheme_prev:
    xor ecx, ecx
ue_scan:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48
    mov [rsp], ecx                       ; direction
    mov qword [rsp+8], -1                ; result
    mov dword [rsp+16], 0                ; requested offset is a boundary
    mov qword [rsp+20], 0                ; previous GCB, RI count
    mov qword [rsp+28], 0                ; EP and InCB histories
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
    xor r15d, r15d
    cmp r13, r12
    ja .bad
    call .mark                          ; start boundary
.loop:
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r14
    call ue_read
    cmp eax, -1
    je .bad
    cmp eax, -2
    je .end
    mov [rsp+40], ecx
    mov edi, eax
    call ue_property
    mov [rsp+36], eax
    mov edx, eax
    and edx, 15                         ; current GCB
    test r14, r14
    jz .update
    mov ecx, [rsp+20]                   ; previous GCB
    cmp ecx, 1                         ; GB3 CR x LF
    jne .control
    cmp edx, 2
    je .update
.control:
    test ecx, ecx
    jz .before_control
    cmp ecx, 3                         ; GB4 break after Control/CR/LF
    jbe .break
.before_control:
    cmp edx, 1                         ; GB5 break before Control/CR/LF
    jb .hangul
    cmp edx, 3
    jbe .break
.hangul:
    cmp ecx, 9                         ; GB6 L x (L,V,LV,LVT)
    jne .gb7
    cmp edx, 9
    je .update
    cmp edx, 10
    je .update
    cmp edx, 12
    jae .update
.gb7:
    cmp ecx, 12                        ; GB7 (LV,V) x (V,T)
    je .vt
    cmp ecx, 10
    jne .gb8
.vt:
    cmp edx, 10
    je .update
    cmp edx, 11
    je .update
.gb8:
    cmp ecx, 13                        ; GB8 (LVT,T) x T
    je .t
    cmp ecx, 11
    jne .gb9
.t:
    cmp edx, 11
    je .update
.gb9:
    cmp edx, 4                         ; GB9 x Extend/ZWJ
    je .update
    cmp edx, 5
    je .update
    cmp edx, 8                         ; GB9a x SpacingMark
    je .update
    cmp ecx, 7                         ; GB9b Prepend x
    je .update
    mov ecx, eax
    shr ecx, 7                         ; GB9c consonant/linker history
    cmp ecx, 1
    jne .gb11
    cmp dword [rsp+32], 2
    je .update
.gb11:
    test eax, 16                       ; GB11 EP Extend* ZWJ x EP
    jz .ri
    cmp dword [rsp+28], 2
    je .update
.ri:
    cmp edx, 6                         ; GB12/13 odd preceding RI run
    jne .break
    test dword [rsp+24], 1
    jnz .update
.break:
    call .mark
.update:
    mov eax, [rsp+36]
    mov edx, eax
    and edx, 15
    mov [rsp+20], edx
    cmp edx, 6
    jne .ri_reset
    inc dword [rsp+24]
    jmp .ep
.ri_reset:
    mov dword [rsp+24], 0
.ep:
    test eax, 16
    jnz .ep_one
    cmp dword [rsp+28], 1
    jne .ep_zero
    cmp edx, 4
    je .incb
    cmp edx, 5
    jne .ep_zero
    mov dword [rsp+28], 2
    jmp .incb
.ep_one:
    mov dword [rsp+28], 1
    jmp .incb
.ep_zero:
    mov dword [rsp+28], 0
.incb:
    shr eax, 7
    cmp eax, 1
    je .incb_one
    cmp eax, 2
    je .advance
    cmp eax, 3
    jne .incb_zero
    cmp dword [rsp+32], 0
    je .advance
    mov dword [rsp+32], 2
    jmp .advance
.incb_one:
    mov dword [rsp+32], 1
    jmp .advance
.incb_zero:
    mov dword [rsp+32], 0
.advance:
    mov ecx, [rsp+40]
    add r14, rcx
    jmp .loop
.end:
    call .mark
    cmp dword [rsp+16], 1
    jne .bad
    mov rax, [rsp+8]
    cmp r13, r12
    jne .out
    cmp dword [rsp], 1
    jne .out
    mov rax, r12
    jmp .out
.bad:
    mov rax, -1
.out:
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.mark:
    ; CALL adds 8 to local offsets. Last boundary is R15.
    cmp r14, r13
    jne .maybe_next
    mov dword [rsp+24], 1
    cmp dword [rsp+8], 0
    jne .marked
    mov [rsp+16], r15
    jmp .marked
.maybe_next:
    cmp r15, r13
    jne .marked
    cmp dword [rsp+8], 1
    jne .marked
    mov [rsp+16], r14
.marked:
    mov r15, r14
    ret
ue_code_end:
; BEGIN GENERATED UNICODE 15.1 DATA
ue_properties:
    dd 0x00000023, 0x00001422, 0x00001623, 0x00001a21, 0x00001c23, 0x00004020, 0x0000fe23, 0x00014020
    dd 0x00015230, 0x00015420, 0x00015a03, 0x00015c30, 0x00015e20, 0x00060104, 0x00069e04, 0x0006a104
    dd 0x0006e020, 0x00090704, 0x00091004, 0x00091420, 0x000b2304, 0x000b7c20, 0x000b7f04, 0x000b8020
    dd 0x000b8304, 0x000b8620, 0x000b8904, 0x000b8c20, 0x000b8f04, 0x000b9020, 0x000c0007, 0x000c0c20
    dd 0x000c2104, 0x000c3620, 0x000c3803, 0x000c3a20, 0x000c9704, 0x000cc020, 0x000ce104, 0x000ce220
    dd 0x000dad04, 0x000dba07, 0x000dbc20, 0x000dbf04, 0x000dca20, 0x000dcf04, 0x000dd220, 0x000dd504
    dd 0x000ddc20, 0x000e1e07, 0x000e2020, 0x000e2304, 0x000e2420, 0x000e6104, 0x000e9620, 0x000f4c04
    dd 0x000f6220, 0x000fd704, 0x000fe820, 0x000ffb04, 0x000ffc20, 0x00102d04, 0x00103420, 0x00103704
    dd 0x00104820, 0x00104b04, 0x00105020, 0x00105304, 0x00105c20, 0x0010b304, 0x0010b820, 0x00112007
    dd 0x00112420, 0x00113104, 0x00114020, 0x00119504, 0x0011c407, 0x0011c704, 0x00120004, 0x00120628
    dd 0x00120820, 0x00122aa0, 0x00127404, 0x00127628, 0x00127904, 0x00127a20, 0x00127c28, 0x00128204
    dd 0x00129228, 0x00129b84, 0x00129c28, 0x0012a020, 0x0012a304, 0x0012aa04, 0x0012b0a0, 0x0012c020
    dd 0x0012c404, 0x0012c820, 0x0012f0a0, 0x00130020, 0x00130204, 0x00130428, 0x00130820, 0x00132aa0
    dd 0x00135220, 0x001354a0, 0x00136220, 0x001364a0, 0x00136620, 0x00136ca0, 0x00137420, 0x00137904
    dd 0x00137a20, 0x00137c24, 0x00137e28, 0x00138204, 0x00138a20, 0x00138e28, 0x00139220, 0x00139628
    dd 0x00139b84, 0x00139c20, 0x0013ae24, 0x0013b020, 0x0013b8a0, 0x0013bc20, 0x0013bea0, 0x0013c020
    dd 0x0013c404, 0x0013c820, 0x0013e0a0, 0x0013e420, 0x0013fd04, 0x0013fe20, 0x00140204, 0x00140628
    dd 0x00140820, 0x00147904, 0x00147a20, 0x00147c28, 0x00148204, 0x00148620, 0x00148e04, 0x00149220
    dd 0x00149604, 0x00149c20, 0x0014a204, 0x0014a420, 0x0014e004, 0x0014e420, 0x0014ea04, 0x0014ec20
    dd 0x00150204, 0x00150628, 0x00150820, 0x00152aa0, 0x00155220, 0x001554a0, 0x00156220, 0x001564a0
    dd 0x00156820, 0x00156aa0, 0x00157420, 0x00157904, 0x00157a20, 0x00157c28, 0x00158204, 0x00158c20
    dd 0x00158e04, 0x00159228, 0x00159420, 0x00159628, 0x00159b84, 0x00159c20, 0x0015c404, 0x0015c820
    dd 0x0015f2a0, 0x0015f404, 0x00160020, 0x00160204, 0x00160428, 0x00160820, 0x00162aa0, 0x00165220
    dd 0x001654a0, 0x00166220, 0x001664a0, 0x00166820, 0x00166aa0, 0x00167420, 0x00167904, 0x00167a20
    dd 0x00167c24, 0x00167e04, 0x00168028, 0x00168204, 0x00168a20, 0x00168e28, 0x00169220, 0x00169628
    dd 0x00169b84, 0x00169c20, 0x0016aa04, 0x0016ae24, 0x0016b020, 0x0016b8a0, 0x0016bc20, 0x0016bea0
    dd 0x0016c020, 0x0016c404, 0x0016c820, 0x0016e2a0, 0x0016e420, 0x00170404, 0x00170620, 0x00177c24
    dd 0x00177e28, 0x00178004, 0x00178228, 0x00178620, 0x00178c28, 0x00179220, 0x00179428, 0x00179a04
    dd 0x00179c20, 0x0017ae24, 0x0017b020, 0x00180004, 0x00180228, 0x00180804, 0x00180a20, 0x00182aa0
    dd 0x00185220, 0x001854a0, 0x00187420, 0x00187904, 0x00187a20, 0x00187c04, 0x00188228, 0x00188a20
    dd 0x00188c04, 0x00189220, 0x00189404, 0x00189b84, 0x00189c20, 0x0018ab04, 0x0018ae20, 0x0018b0a0
    dd 0x0018b620, 0x0018c404, 0x0018c820, 0x00190204, 0x00190428, 0x00190820, 0x00197904, 0x00197a20
    dd 0x00197c28, 0x00197e04, 0x00198028, 0x00198424, 0x00198628, 0x00198a20, 0x00198c04, 0x00198e28
    dd 0x00199220, 0x00199428, 0x00199804, 0x00199c20, 0x0019aa24, 0x0019ae20, 0x0019c404, 0x0019c820
    dd 0x0019e628, 0x0019e820, 0x001a0004, 0x001a0428, 0x001a0820, 0x001a2aa0, 0x001a7704, 0x001a7a20
    dd 0x001a7c24, 0x001a7e28, 0x001a8204, 0x001a8a20, 0x001a8c28, 0x001a9220, 0x001a9428, 0x001a9b84
    dd 0x001a9c27, 0x001a9e20, 0x001aae24, 0x001ab020, 0x001ac404, 0x001ac820, 0x001b0204, 0x001b0428
    dd 0x001b0820, 0x001b9404, 0x001b9620, 0x001b9e24, 0x001ba028, 0x001ba404, 0x001baa20, 0x001bac04
    dd 0x001bae20, 0x001bb028, 0x001bbe24, 0x001bc020, 0x001be428, 0x001be820, 0x001c6204, 0x001c6420
    dd 0x001c6628, 0x001c6804, 0x001c7104, 0x001c7620, 0x001c8e04, 0x001c9104, 0x001c9804, 0x001c9e20
    dd 0x001d6204, 0x001d6420, 0x001d6628, 0x001d6804, 0x001d7104, 0x001d7604, 0x001d7a20, 0x001d9104
    dd 0x001d9804, 0x001d9e20, 0x001e3104, 0x001e3420, 0x001e6b04, 0x001e6c20, 0x001e6f04, 0x001e7020
    dd 0x001e7304, 0x001e7420, 0x001e7c28, 0x001e8020, 0x001ee304, 0x001ee604, 0x001ee904, 0x001eea04
    dd 0x001ef504, 0x001efc04, 0x001efe28, 0x001f0104, 0x001f0204, 0x001f0504, 0x001f0a20, 0x001f0d04
    dd 0x001f1020, 0x001f1a04, 0x001f3020, 0x001f3204, 0x001f7a20, 0x001f8d04, 0x001f8e20, 0x00205a04
    dd 0x00206228, 0x00206404, 0x00206f04, 0x00207020, 0x00207304, 0x00207628, 0x00207a04, 0x00207e20
    dd 0x0020ac28, 0x0020b004, 0x0020b420, 0x0020bc04, 0x0020c220, 0x0020e204, 0x0020ea20, 0x00210404
    dd 0x00210620, 0x00210828, 0x00210a04, 0x00210e20, 0x00211b04, 0x00211c20, 0x00213a04, 0x00213c20
    dd 0x00220049, 0x0022c02a, 0x0023502b, 0x00240020, 0x0026bb04, 0x0026c020, 0x002e2404, 0x002e2904
    dd 0x002e2a28, 0x002e2c20, 0x002e6404, 0x002e6828, 0x002e6a20, 0x002ea404, 0x002ea820, 0x002ee404
    dd 0x002ee820, 0x002f6804, 0x002f6c28, 0x002f6e04, 0x002f7c28, 0x002f8c04, 0x002f8e28, 0x002f9204
    dd 0x002fa504, 0x002fa604, 0x002fa820, 0x002fbb04, 0x002fbc20, 0x00301604, 0x00301c03, 0x00301e04
    dd 0x00302020, 0x00310a04, 0x00310e20, 0x00315304, 0x00315420, 0x00324004, 0x00324628, 0x00324e04
    dd 0x00325228, 0x00325820, 0x00326028, 0x00326404, 0x00326628, 0x00327304, 0x00327820, 0x00342f04
    dd 0x00343228, 0x00343604, 0x00343820, 0x0034aa28, 0x0034ac04, 0x0034ae28, 0x0034b004, 0x0034be20
    dd 0x0034c104, 0x0034c220, 0x0034c404, 0x0034c620, 0x0034ca04, 0x0034da28, 0x0034e604, 0x0034eb04
    dd 0x0034fa20, 0x0034ff04, 0x00350020, 0x00356104, 0x00357c04, 0x00357f04, 0x00359e20, 0x00360004
    dd 0x00360828, 0x00360a20, 0x00366904, 0x00366a24, 0x00366c04, 0x00367628, 0x00367804, 0x00367a28
    dd 0x00368404, 0x00368628, 0x00368a20, 0x0036d704, 0x0036e820, 0x00370004, 0x00370428, 0x00370620
    dd 0x00374228, 0x00374404, 0x00374c28, 0x00375004, 0x00375428, 0x00375704, 0x00375804, 0x00375c20
    dd 0x0037cd04, 0x0037ce28, 0x0037d004, 0x0037d428, 0x0037da04, 0x0037dc28, 0x0037de04, 0x0037e428
    dd 0x0037e820, 0x00384828, 0x00385804, 0x00386828, 0x00386c04, 0x00386f04, 0x00387020, 0x0039a104
    dd 0x0039a620, 0x0039a904, 0x0039c228, 0x0039c504, 0x0039d220, 0x0039db04, 0x0039dc20, 0x0039e904
    dd 0x0039ea20, 0x0039ee28, 0x0039f104, 0x0039f420, 0x003b8104, 0x003c0020, 0x00401603, 0x00401804
    dd 0x00401b05, 0x00401c03, 0x00402020, 0x00405023, 0x00405403, 0x00405e20, 0x00407830, 0x00407a20
    dd 0x00409230, 0x00409420, 0x0040c003, 0x0040ca23, 0x0040cc03, 0x0040e020, 0x0041a104, 0x0041ba04
    dd 0x0041c304, 0x0041c404, 0x0041cb04, 0x0041e220, 0x00424430, 0x00424620, 0x00427230, 0x00427420
    dd 0x00432830, 0x00433420, 0x00435230, 0x00435620, 0x00463450, 0x00463820, 0x00465030, 0x00465240
    dd 0x00465620, 0x00471030, 0x00471220, 0x00479e30, 0x0047a020, 0x0047d250, 0x0047da30, 0x0047e050
    dd 0x0047e230, 0x0047e650, 0x0047e820, 0x0047f030, 0x0047f620, 0x00498430, 0x00498620, 0x004b5430
    dd 0x004b5820, 0x004b6c30, 0x004b6e20, 0x004b8030, 0x004b8220, 0x004bf630, 0x004bfa50, 0x004bfe20
    dd 0x004c0030, 0x004c0c20, 0x004c0e30, 0x004c2620, 0x004c2850, 0x004c2c30, 0x004c9050, 0x004ca830
    dd 0x004cfe50, 0x004d0030, 0x004d0c20, 0x004d2030, 0x004d2650, 0x004d2830, 0x004d4250, 0x004d4430
    dd 0x004d5450, 0x004d5830, 0x004d7a50, 0x004d7e30, 0x004d8850, 0x004d8c30, 0x004d9c50, 0x004d9e30
    dd 0x004da850, 0x004daa30, 0x004dd450, 0x004dd630, 0x004de450, 0x004de830, 0x004dea50, 0x004dec30
    dd 0x004df450, 0x004df630, 0x004dfa50, 0x004dfc30, 0x004e0a50, 0x004e0c20, 0x004e1030, 0x004e1450
    dd 0x004e1830, 0x004e2620, 0x004e2830, 0x004e2a20, 0x004e2c30, 0x004e2e20, 0x004e3a30, 0x004e3c20
    dd 0x004e4230, 0x004e4420, 0x004e5050, 0x004e5220, 0x004e6630, 0x004e6a20, 0x004e8830, 0x004e8a20
    dd 0x004e8e30, 0x004e9020, 0x004e9850, 0x004e9a20, 0x004e9c50, 0x004e9e20, 0x004ea650, 0x004eac20
    dd 0x004eae50, 0x004eb020, 0x004ec630, 0x004ed020, 0x004f2a50, 0x004f3020, 0x004f4230, 0x004f4420
    dd 0x004f6050, 0x004f6220, 0x004f7e50, 0x004f8020, 0x00526830, 0x00526c20, 0x00560a30, 0x00561020
    dd 0x00563650, 0x00563a20, 0x0056a050, 0x0056a220, 0x0056aa50, 0x0056ac20, 0x0059df04, 0x0059e420
    dd 0x005aff04, 0x005b0020, 0x005bc104, 0x005c0020, 0x005d0040, 0x005d3420, 0x005d3640, 0x005de820
    dd 0x005e0040, 0x005fac20, 0x005fe040, 0x00605504, 0x00605d44, 0x00606050, 0x00606240, 0x00607a50
    dd 0x00607c40, 0x00607e20, 0x00608240, 0x00612e20, 0x00613304, 0x00613640, 0x00620020, 0x00620a40
    dd 0x00626020, 0x00626240, 0x00631e20, 0x00632040, 0x0063c820, 0x0063de40, 0x00643e20, 0x00644040
    dd 0x00649020, 0x0064a040, 0x00652e50, 0x00653040, 0x00653250, 0x00653440, 0x009b8020, 0x009c0040
    dd 0x01491a20, 0x01492040, 0x01498e20, 0x014cdf04, 0x014ce004, 0x014ce620, 0x014ce904, 0x014cfc20
    dd 0x014d3d04, 0x014d4020, 0x014de104, 0x014de420, 0x01500404, 0x01500620, 0x01500c04, 0x01500e20
    dd 0x01501604, 0x01501820, 0x01504628, 0x01504a04, 0x01504e28, 0x01505020, 0x01505904, 0x01505a20
    dd 0x01510028, 0x01510420, 0x01516828, 0x01518804, 0x01518c20, 0x0151c104, 0x0151e420, 0x0151fe04
    dd 0x01520020, 0x01524c04, 0x01525704, 0x01525c20, 0x01528e04, 0x0152a428, 0x0152a820, 0x0152c049
    dd 0x0152fa20, 0x01530004, 0x01530628, 0x01530820, 0x01536704, 0x01536828, 0x01536c04, 0x01537428
    dd 0x01537804, 0x01537c28, 0x01538220, 0x0153ca04, 0x0153cc20, 0x01545204, 0x01545e28, 0x01546204
    dd 0x01546628, 0x01546a04, 0x01546e20, 0x01548604, 0x01548820, 0x01549804, 0x01549a28, 0x01549c20
    dd 0x0154f804, 0x0154fa20, 0x01556104, 0x01556220, 0x01556504, 0x01556a20, 0x01556f04, 0x01557220
    dd 0x01557d04, 0x01558020, 0x01558304, 0x01558420, 0x0155d628, 0x0155d804, 0x0155dc28, 0x0155e020
    dd 0x0155ea28, 0x0155ed04, 0x0155ee20, 0x0157c628, 0x0157ca04, 0x0157cc28, 0x0157d004, 0x0157d228
    dd 0x0157d620, 0x0157d828, 0x0157db04, 0x0157dc20, 0x01580040, 0x01af4820, 0x01af602a, 0x01af8e20
    dd 0x01af962b, 0x01aff820, 0x01f20040, 0x01f60020, 0x01f63d04, 0x01f63e20, 0x01fc0004, 0x01fc2040
    dd 0x01fc3420, 0x01fc4104, 0x01fc6040, 0x01fca620, 0x01fca840, 0x01fcce20, 0x01fcd040, 0x01fcd820
    dd 0x01fdfe03, 0x01fe0020, 0x01fe0240, 0x01fec220, 0x01ff3c24, 0x01ff4020, 0x01ffc040, 0x01ffce20
    dd 0x01ffe023, 0x01fff203, 0x01fff820, 0x0203fb04, 0x0203fc20, 0x0205c104, 0x0205c220, 0x0206ed04
    dd 0x0206f620, 0x02140204, 0x02140820, 0x02140a04, 0x02140e20, 0x02141804, 0x02141b04, 0x02141c04
    dd 0x02141f04, 0x02142020, 0x02147104, 0x02147620, 0x02147f04, 0x02148020, 0x0215cb04, 0x0215ce20
    dd 0x021a4904, 0x021a5020, 0x021d5704, 0x021d5a20, 0x021dfb04, 0x021e0020, 0x021e8d04, 0x021ea220
    dd 0x021f0504, 0x021f0c20, 0x02200028, 0x02200204, 0x02200428, 0x02200620, 0x02207004, 0x02208e20
    dd 0x0220e104, 0x0220e220, 0x0220e604, 0x0220ea20, 0x0220ff04, 0x02210004, 0x02210428, 0x02210620
    dd 0x02216028, 0x02216604, 0x02216e28, 0x02217204, 0x02217504, 0x02217620, 0x02217a07, 0x02217c20
    dd 0x02218404, 0x02218620, 0x02219a07, 0x02219c20, 0x02220104, 0x02220620, 0x02224e04, 0x02225828
    dd 0x02225a04, 0x02226704, 0x02226a20, 0x02228a28, 0x02228e20, 0x0222e704, 0x0222e820, 0x02230004
    dd 0x02230428, 0x02230620, 0x02236628, 0x02236c04, 0x02237e28, 0x02238220, 0x02238427, 0x02238820
    dd 0x02239204, 0x02239504, 0x02239604, 0x02239a20, 0x02239c28, 0x02239e04, 0x0223a020, 0x02245828
    dd 0x02245e04, 0x02246428, 0x02246804, 0x02246a28, 0x02246d04, 0x02246e04, 0x02247020, 0x02247c04
    dd 0x02247e20, 0x02248204, 0x02248420, 0x0225be04, 0x0225c028, 0x0225c604, 0x0225d304, 0x0225d620
    dd 0x02260004, 0x02260428, 0x02260820, 0x02267704, 0x02267a20, 0x02267c24, 0x02267e28, 0x02268004
    dd 0x02268228, 0x02268a20, 0x02268e28, 0x02269220, 0x02269628, 0x02269c20, 0x0226ae24, 0x0226b020
    dd 0x0226c428, 0x0226c820, 0x0226cd04, 0x0226da20, 0x0226e104, 0x0226ea20, 0x02286a28, 0x02287004
    dd 0x02288028, 0x02288404, 0x02288a28, 0x02288d04, 0x02288e20, 0x0228bd04, 0x0228be20, 0x02296024
    dd 0x02296228, 0x02296604, 0x02297228, 0x02297404, 0x02297628, 0x02297a24, 0x02297c28, 0x02297e04
    dd 0x02298228, 0x02298404, 0x02298704, 0x02298820, 0x022b5e24, 0x022b6028, 0x022b6404, 0x022b6c20
    dd 0x022b7028, 0x022b7804, 0x022b7c28, 0x022b7e04, 0x022b8104, 0x022b8220, 0x022bb804, 0x022bbc20
    dd 0x022c6028, 0x022c6604, 0x022c7628, 0x022c7a04, 0x022c7c28, 0x022c7e04, 0x022c8220, 0x022d5604
    dd 0x022d5828, 0x022d5a04, 0x022d5c28, 0x022d6004, 0x022d6c28, 0x022d6f04, 0x022d7020, 0x022e3a04
    dd 0x022e4020, 0x022e4404, 0x022e4c28, 0x022e4e04, 0x022e5704, 0x022e5820, 0x02305828, 0x02305e04
    dd 0x02307028, 0x02307204, 0x02307504, 0x02307620, 0x02326024, 0x02326228, 0x02326c20, 0x02326e28
    dd 0x02327220, 0x02327604, 0x02327a28, 0x02327d04, 0x02327e27, 0x02328028, 0x02328227, 0x02328428
    dd 0x02328704, 0x02328820, 0x0233a228, 0x0233a804, 0x0233b020, 0x0233b404, 0x0233b828, 0x0233c004
    dd 0x0233c220, 0x0233c828, 0x0233ca20, 0x02340204, 0x02341620, 0x02346604, 0x02346904, 0x02346a04
    dd 0x02347228, 0x02347427, 0x02347604, 0x02347e20, 0x02348f04, 0x02349020, 0x0234a204, 0x0234ae28
    dd 0x0234b204, 0x0234b820, 0x02350827, 0x02351404, 0x02352e28, 0x02353004, 0x02353304, 0x02353420
    dd 0x02385e28, 0x02386004, 0x02386e20, 0x02387004, 0x02387c28, 0x02387e04, 0x02388020, 0x02392404
    dd 0x02395020, 0x02395228, 0x02395404, 0x02396228, 0x02396404, 0x02396828, 0x02396a04, 0x02396e20
    dd 0x023a6204, 0x023a6e20, 0x023a7404, 0x023a7620, 0x023a7804, 0x023a7c20, 0x023a7e04, 0x023a8504
    dd 0x023a8604, 0x023a8904, 0x023a8c27, 0x023a8e04, 0x023a9020, 0x023b1428, 0x023b1e20, 0x023b2004
    dd 0x023b2420, 0x023b2628, 0x023b2a04, 0x023b2c28, 0x023b2f04, 0x023b3020, 0x023de604, 0x023dea28
    dd 0x023dee20, 0x023e0004, 0x023e0427, 0x023e0628, 0x023e0820, 0x023e6828, 0x023e6c04, 0x023e7620
    dd 0x023e7c28, 0x023e8004, 0x023e8228, 0x023e8504, 0x023e8620, 0x02686003, 0x02688004, 0x02688220
    dd 0x02688e04, 0x0268ac20, 0x02d5e104, 0x02d5ea20, 0x02d66104, 0x02d66e20, 0x02de9e04, 0x02dea020
    dd 0x02dea228, 0x02df1020, 0x02df1e04, 0x02df2620, 0x02dfc040, 0x02dfc804, 0x02dfca20, 0x02dfe048
    dd 0x02dfe420, 0x02e00040, 0x030ff020, 0x03100040, 0x0319ac20, 0x031a0040, 0x031a1220, 0x035fe040
    dd 0x035fe820, 0x035fea40, 0x035ff820, 0x035ffa40, 0x035ffe20, 0x03600040, 0x03624620, 0x03626440
    dd 0x03626620, 0x0362a040, 0x0362a620, 0x0362aa40, 0x0362ac20, 0x0362c840, 0x0362d020, 0x0362e040
    dd 0x0365f820, 0x03793a04, 0x03793d04, 0x03793e20, 0x03794003, 0x03794820, 0x039e0004, 0x039e5c20
    dd 0x039e6004, 0x039e8e20, 0x03a2cb24, 0x03a2cc28, 0x03a2cf04, 0x03a2d420, 0x03a2da28, 0x03a2dd24
    dd 0x03a2e603, 0x03a2f704, 0x03a30620, 0x03a30b04, 0x03a31820, 0x03a35504, 0x03a35c20, 0x03a48504
    dd 0x03a48a20, 0x03b40004, 0x03b46e20, 0x03b47604, 0x03b4da20, 0x03b4ea04, 0x03b4ec20, 0x03b50804
    dd 0x03b50a20, 0x03b53604, 0x03b54020, 0x03b54204, 0x03b56020, 0x03c00104, 0x03c00e20, 0x03c01104
    dd 0x03c03220, 0x03c03704, 0x03c04420, 0x03c04704, 0x03c04a20, 0x03c04d04, 0x03c05620, 0x03c11f04
    dd 0x03c12020, 0x03c26104, 0x03c26e20, 0x03c55d04, 0x03c55e20, 0x03c5d904, 0x03c5e020, 0x03c9d904
    dd 0x03c9e020, 0x03d1a104, 0x03d1ae20, 0x03d28904, 0x03d29620, 0x03e00030, 0x03e00850, 0x03e00a30
    dd 0x03e19e50, 0x03e1a030, 0x03e20020, 0x03e21a30, 0x03e22020, 0x03e25e30, 0x03e26020, 0x03e2d830
    dd 0x03e2e420, 0x03e2fc30, 0x03e30020, 0x03e31c50, 0x03e31e20, 0x03e32250, 0x03e33620, 0x03e35a30
    dd 0x03e3cc26, 0x03e40040, 0x03e40250, 0x03e40630, 0x03e42040, 0x03e43450, 0x03e43640, 0x03e45e50
    dd 0x03e46040, 0x03e46450, 0x03e47640, 0x03e47830, 0x03e48040, 0x03e49230, 0x03e4a050, 0x03e4a430
    dd 0x03e4c050, 0x03e4cc30, 0x03e60050, 0x03e64230, 0x03e65a50, 0x03e66c30, 0x03e66e50, 0x03e6fa30
    dd 0x03e6fc50, 0x03e72830, 0x03e74050, 0x03e79630, 0x03e79e50, 0x03e7a830, 0x03e7c050, 0x03e7e230
    dd 0x03e7e850, 0x03e7ea30, 0x03e7f050, 0x03e7f644, 0x03e80050, 0x03e87e30, 0x03e88050, 0x03e88230
    dd 0x03e88450, 0x03e9fa30, 0x03e9fe50, 0x03ea7c20, 0x03ea8c30, 0x03ea9650, 0x03ea9e30, 0x03eaa050
    dd 0x03ead030, 0x03eaf450, 0x03eaf630, 0x03eb2a50, 0x03eb2e30, 0x03eb4850, 0x03eb4a30, 0x03ebf650
    dd 0x03eca020, 0x03ed0050, 0x03ed8c30, 0x03ed9850, 0x03ed9a30, 0x03eda050, 0x03eda630, 0x03edaa50
    dd 0x03edb030, 0x03edb850, 0x03edc030, 0x03edd650, 0x03edda30, 0x03ede850, 0x03edfa30, 0x03ee0020
    dd 0x03eee830, 0x03ef0020, 0x03efaa30, 0x03efc050, 0x03efd830, 0x03efe050, 0x03efe230, 0x03f00020
    dd 0x03f01830, 0x03f02020, 0x03f09030, 0x03f0a020, 0x03f0b430, 0x03f0c020, 0x03f11030, 0x03f12020
    dd 0x03f15c30, 0x03f20020, 0x03f21850, 0x03f27620, 0x03f27850, 0x03f28c20, 0x03f28e50, 0x03f40030
    dd 0x03f4e050, 0x03f4fa30, 0x03f50050, 0x03f51230, 0x03f52050, 0x03f57c30, 0x03f57e50, 0x03f58c30
    dd 0x03f59c50, 0x03f5b830, 0x03f5c050, 0x03f5d230, 0x03f5e050, 0x03f5f230, 0x03f60020, 0x03f80030
    dd 0x03fffc20, 0x04000040, 0x05fffc20, 0x06000040, 0x07fffc20, 0x1c000023, 0x1c000203, 0x1c000423
    dd 0x1c004004, 0x1c010023, 0x1c020004, 0x1c03e023, 0x1c200020, 0x22000000
ue_properties_end:
UE_PROP_COUNT equ 1349
; END GENERATED UNICODE 15.1 DATA
