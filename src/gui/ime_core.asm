;; MODULE gui/ime_core
;; LAYER 6
;; EXPORTS ime_romaji_step, ime_py_lookup, ime_py_segment, ime_set_method, ime_cancel, ime_key, ime_preedit, ime_commit_take, ime_cand_info, ime_cand_get, ime_conv_info
;; IMPORTS gui/ime_dict, core/lib/mem, boot/serial
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
;
; RCQ-38 I2, the IME core (DESIGN_RCQ38_TEXT_ENTRY B, PLAN_I2_IME_CORE.md). Host-only and UNWIRED: not in
; paos.asm, no caller, build-gated behind INPUT_TEXT_CONSUMERS_BUILT like I1.
;
; It reads relops' compiled conversion tables ime_ja_table / ime_zh_table (gauntlet_v2/docs/ime/TABLES.md, the v1
; consumer ABI frozen at dc4558a06) through their header fields only: offsets, never pointers. They are reviewed
; compiled-in DATA, so there is no runtime validator (TABLES.md); each output index is still bounded at use.
;
; I2a: the romaji step (ja) and the pinyin syllable lookup and segmentation (zh), each exactly the TABLES.md
; contract, reproduced against relops' 884 golden vectors.
; I2b: the pre-edit state machine and conversion over I1 (ime_dict_lookup / ime_dict_candidate).
;
; ORIGIN (rc-sec 10:37:44): the IME composes ONLY KO_HUMAN keys. Any other key returns PASS with the whole IME state
; untouched, so an injector never appends to, edits, converts, picks for, commits or cancels a hand pre-edit, and a
; commit is always all-hand. ime_cancel (the wiring calls it on a focus, lock, session or layout change) DISCARDS
; the pre-edit and never commits it. Secret fields and the lock screen never reach ime_key (a wiring row).
;
; CAPS (srcreview C1, 17:49:26 / 18:00:22): ja holds kana + pending romaji bytes <= IME_KANA_MAX (42) after every
; key's run, checked on the run's OUTPUT and undone byte for byte when over. No table row emits more scalars than
; it consumes, so the flush at Space also stays <= 42 kana = 126 B, inside I1's 128 B key. The rule is strict at
; the edge, as accepted: a key whose pending prefix would reach 43 is refused even when its syllable would fit
; (41 kana + 'ts': 'tsu' -> つ = 42 is not typable). zh holds 64 typed bytes.

IT_ROW_SIZE         equ 14              ; TABLES.md header fields (u16)
IT_COUNT            equ 16
IT_ROWS             equ 18
IT_POOL             equ 20
IT_POOL_COUNT       equ 22

IME_RJ_REFUSED      equ 0               ; ime_romaji_step states
IME_RJ_EMIT         equ 1
IME_RJ_PREFIX       equ 2
IME_RJ_NONE         equ 3
IME_RJ_PENDING_MAX  equ 4               ; TABLES.md: the pending buffer is 1..4 ASCII bytes

IME_PY_ACCEPT       equ 1               ; ime_py_segment states
IME_PY_PENDING      equ 2
IME_PY_REFUSED      equ 3
IME_PY_MAX          equ 64              ; normalized pinyin bytes: the zh pre-edit cap
IME_PY_SYL_MAX      equ 6               ; the longest source syllable (zhuang)

IME_M_OFF           equ 0               ; methods = I1's locales
IME_M_JA            equ 1
IME_M_ZH            equ 2
IME_S_IDLE          equ 0               ; states
IME_S_COMPOSING     equ 1
IME_S_CONVERTING    equ 2
IME_F_NO_CANDIDATES equ 1               ; flags (visible, cleared by the next edit)
IME_F_UNAVAILABLE   equ 2
IME_A_CONSUMED      equ 1               ; ime_key actions; without CONSUMED the caller delivers the key itself
IME_A_PREEDIT       equ 2
IME_A_COMMIT        equ 4               ; ime_commit_take holds text until the next ime_key
IME_A_CANDS         equ 8
IME_K_BACKSPACE     equ 0x110001        ; non-scalar keys (scalars are < 0x110000; Space is scalar 32)
IME_K_ENTER         equ 0x110002
IME_K_ESCAPE        equ 0x110003
IME_K_UP            equ 0x110004
IME_K_DOWN          equ 0x110005
IME_K_LEFT          equ 0x110006
IME_K_RIGHT         equ 0x110007
IME_K_PGUP          equ 0x110008
IME_K_PGDN          equ 0x110009
IME_K_F7            equ 0x11000A        ; ja: commit the run as katakana
IME_ORIGIN_HUMAN    equ 0               ; = KO_HUMAN (dev/input/ps2.asm; census-pinned)
IME_DICT_KEY_REFUSED equ 13             ; = ime_dict's IME_E_KEY (census-pinned): too long, no candidates
IME_DICT_E_RANGE    equ 9               ; = ime_dict's IME_E_ROW: no such candidate
IME_DICT_E_MATCHES  equ 14              ; = ime_dict's IME_E_MATCHES (census-pinned): over 512 rows, no list
IME_KANA_MAX        equ 42              ; typing cap: kana + pending bytes <= 42, so <= 42 kana = 126 B (I1's 128 B
                                        ; key bound) even after the flush: no table row emits more than it consumes
IME_UNDO_SLOTS      equ 12              ; the kana slots one typed key's run can write (4 steps x 3), restored on refusal
IME_KANA_CAP        equ 64              ; storage: the cap + one step's 3 + a flush's 12, rounded
IME_PAGE            equ 9               ; candidates per page (digits 1-9)
IME_VIEW_CAP        equ IME_KANA_CAP * 3 + IME_RJ_PENDING_MAX
IME_COMMIT_CAP      equ 384             ; a 256 B surface + a 64 B zh remainder, or 64 kana x 3

section .text

; it_lb(R8 table, EDI key) -> EAX the first row whose u32 key is >= EDI (keys strictly increase). Clobbers ECX,
; EDX, R9-R11.
it_lb:
    movzx r9d, word [r8 + IT_ROWS]
    add  r9, r8
    movzx r10d, word [r8 + IT_ROW_SIZE]
    xor  eax, eax
    movzx ecx, word [r8 + IT_COUNT]
.bisect:
    cmp  eax, ecx
    jae  .out
    lea  edx, [rax + rcx]
    shr  edx, 1
    mov  r11d, edx
    imul r11d, r10d
    cmp  [r9 + r11], edi
    jae  .upper
    lea  eax, [rdx + 1]
    jmp  .bisect
.upper:
    mov  ecx, edx
    jmp  .bisect
.out:
    ret

; it_row(R8 table, EAX index) -> R9 the row's address; CF set when the index is past the last row. Clobbers R10.
it_row:
    movzx r10d, word [r8 + IT_COUNT]
    cmp  eax, r10d
    jae  .past
    movzx r9d, word [r8 + IT_ROWS]
    add  r9, r8
    movzx r10d, word [r8 + IT_ROW_SIZE]
    imul r10d, eax
    add  r9, r10
    clc
    ret
.past:
    stc
    ret

; ime_romaji_step(RDI pending, ESI len 1..4, EDX flush, RCX out u32[3]) -> EAX state, EDX consumed, ECX outputs.
; TABLES.md: unless flushing, a whole pending buffer that is a PROPER prefix of a key is PREFIX (consumed 0, no
; output), even when it is itself a key (n, ww). Otherwise the longest key that prefixes the buffer EMITs its
; output and its recorded consumed length (keylen - carrylen, so a carry stays pending). No key: NONE, consumed 1,
; the first byte passed through. A length outside 1..4 or a byte outside 1..127: REFUSED, nothing consumed.
ime_romaji_step:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15, rcx
    lea  eax, [rsi - 1]
    cmp  eax, IME_RJ_PENDING_MAX - 1
    ja   .refuse
    xor  ebx, ebx                       ; the packed key: four 7-bit groups, most significant first
    xor  ecx, ecx
.pack:
    shl  ebx, 7
    cmp  ecx, r13d
    jae  .pad
    movzx eax, byte [r12 + rcx]
    lea  edx, [rax - 1]
    cmp  edx, 126
    ja   .refuse
    or   ebx, eax
.pad:
    inc  ecx
    cmp  ecx, 4
    jb   .pack
    lea  r8, [rel ime_ja_table]
    test r14d, r14d
    jnz  .longest
    lea  edi, [rbx + 1]                 ; the first key after the buffer's own spelling
    call it_lb
    call it_row
    jc   .longest
    mov  ecx, r13d
    call rj_mask
    and  eax, [r9]
    cmp  eax, ebx
    je   .prefix
.longest:

.try:                                   ; r13d: the length tried, longest first
    mov  ecx, r13d
    call rj_mask
    and  eax, ebx
    mov  edi, eax
    mov  r14d, eax
    call it_lb
    call it_row
    jc   .shorter
    cmp  [r9], r14d
    je   .emit
.shorter:
    dec  r13d
    jnz  .try
    movzx eax, byte [r12]
    mov  [r15], eax
    mov  eax, IME_RJ_NONE
    mov  edx, 1
    mov  ecx, 1
    jmp  .out
.emit:
    xor  ecx, ecx
.scalar:
    movzx eax, byte [r9 + 4 + rcx]      ; 1-based pool index; 0 ends the output
    test eax, eax
    jz   .emitted
    movzx edx, word [r8 + IT_POOL_COUNT]
    cmp  eax, edx
    ja   .refuse
    movzx edx, word [r8 + IT_POOL]
    lea  rdx, [r8 + rdx]
    movzx eax, word [rdx + rax*2 - 2]
    mov  [r15 + rcx*4], eax
    inc  ecx
    cmp  ecx, 3
    jb   .scalar
.emitted:
    test ecx, ecx
    jz   .refuse
    movzx edx, byte [r9 + 7]
    mov  eax, IME_RJ_EMIT
    jmp  .out
.prefix:
    mov  eax, IME_RJ_PREFIX
    xor  edx, edx
    xor  ecx, ecx
    jmp  .out
.refuse:
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; rj_mask(ECX groups 1..4) -> EAX the mask of the first ECX 7-bit groups of a packed ja key. Clobbers ECX.
rj_mask:
    neg  ecx
    add  ecx, 4
    imul ecx, ecx, 7
    mov  eax, 1
    shl  eax, cl
    neg  eax
    and  eax, 0x0FFFFFFF
    ret

; py_mask(ECX letters 1..6) -> EAX the mask of the first ECX 5-bit groups of a packed zh key. Clobbers ECX.
py_mask:
    neg  ecx
    add  ecx, IME_PY_SYL_MAX
    imul ecx, ecx, 5
    mov  eax, 1
    shl  eax, cl
    neg  eax
    and  eax, 0x3FFFFFFF
    ret

; py_pack(RSI letters, ECX n) -> EAX the packed key (a=1..z=26, six 5-bit groups, most significant first); CF set
; when n is 0 or over 6 or a byte is not a..z. Clobbers EDX, R8D.
py_pack:
    lea  eax, [rcx - 1]
    cmp  eax, IME_PY_SYL_MAX - 1
    ja   .bad
    xor  eax, eax
    xor  r8d, r8d
.group:
    shl  eax, 5
    cmp  r8d, ecx
    jae  .pad
    movzx edx, byte [rsi + r8]
    sub  edx, 'a'
    cmp  edx, 25
    ja   .bad
    inc  edx
    or   eax, edx
.pad:
    inc  r8d
    cmp  r8d, IME_PY_SYL_MAX
    jb   .group
    clc
    ret
.bad:
    stc
    ret

; py_spell(RSI letters, ECX n) -> EAX the source row id of that spelling, or -1. The spellings are the source
; syllables plus the two TABLES.md aliases nve -> nue and lve -> lue (no table rows). Preserves RSI, RBX, RBP,
; R12-R15.
py_spell:
    push rsi
    sub  rsp, 16
    cmp  ecx, 3
    jne  .plain
    cmp  word [rsi + 1], 'v' | ('e' << 8)
    jne  .plain
    mov  byte [rsp + 1], 'u'
    mov  byte [rsp + 2], 'e'
    mov  al, [rsi]
    mov  [rsp], al
    cmp  al, 'n'
    je   .alias
    cmp  al, 'l'
    jne  .plain
.alias:
    mov  rsi, rsp
.plain:
    call py_pack
    jc   .none
    mov  edi, eax
    mov  [rsp + 8], eax
    lea  r8, [rel ime_zh_table]
    call it_lb
    mov  esi, eax
    call it_row
    jc   .none
    mov  eax, [rsp + 8]
    cmp  [r9], eax
    jne  .none
    mov  eax, esi
    jmp  .out
.none:
    mov  eax, -1
.out:
    add  rsp, 16
    pop  rsi
    ret

; py_is_prefix(RSI letters, ECX n) -> EAX 1 when the text is a PROPER prefix of a spelling (a source syllable or
; an alias), else 0. Preserves RSI, RBX, RBP, R12-R15.
py_is_prefix:
    push rsi
    push rbx
    sub  rsp, 8
    mov  ebx, ecx
    lea  eax, [rcx - 1]
    cmp  eax, 1
    ja   .table                         ; nv / lv: proper prefixes of the aliases only
    mov  al, [rsi]
    cmp  al, 'n'
    je   .alias
    cmp  al, 'l'
    jne  .table
.alias:
    cmp  ebx, 1
    je   .yes
    cmp  byte [rsi + 1], 'v'
    je   .yes
.table:
    cmp  ebx, IME_PY_SYL_MAX
    jae  .no
    mov  ecx, ebx
    call py_pack
    jc   .no
    mov  [rsp], eax
    lea  edi, [rax + 1]
    lea  r8, [rel ime_zh_table]
    call it_lb
    call it_row
    jc   .no
    mov  ecx, ebx
    call py_mask
    and  eax, [r9]
    cmp  eax, [rsp]
    jne  .no
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  rbx
    pop  rsi
    ret

; py_norm(RSI src, ECX len, RDI dst, EDX cap) -> EAX the normalized length, or -1 past cap. TABLES.md spelling
; normalization only: U+00FC (UTF-8 C3 BC) and "u:" become v; every other byte is copied.
py_norm:
    xor  eax, eax                       ; written
    xor  r8d, r8d                       ; read
.next:
    cmp  r8d, ecx
    jae  .done
    movzx r9d, byte [rsi + r8]
    lea  r10d, [r8 + 1]
    cmp  r10d, ecx
    jae  .copy
    movzx r11d, byte [rsi + r10]
    cmp  r9d, 0xC3
    jne  .colon
    cmp  r11d, 0xBC
    je   .v
.colon:
    cmp  r9d, 'u'
    jne  .copy
    cmp  r11d, ':'
    jne  .copy
.v:
    mov  r9d, 'v'
    inc  r8d
.copy:
    cmp  eax, edx
    jae  .over
    mov  [rdi + rax], r9b
    inc  eax
    inc  r8d
    jmp  .next
.over:
    mov  eax, -1
.done:
    ret

; ime_py_lookup(RDI text, ESI len) -> EAX bit 0 = a spelling (syllable or alias), bit 1 = a proper prefix of one;
; EDX the source row id of the spelling, or -1. The text is normalized first; anything else than a..z is neither.
ime_py_lookup:
    push rbx
    push r12
    sub  rsp, 24
    mov  rbx, rsp
    mov  ecx, esi
    mov  rsi, rdi
    mov  rdi, rbx
    mov  edx, IME_PY_SYL_MAX + 1
    call py_norm
    mov  r12d, -1
    xor  edx, edx                       ; the flags
    cmp  eax, IME_PY_SYL_MAX
    ja   .out                           ; past cap or longer than any spelling: neither
    test eax, eax
    jz   .out
    mov  [rsp + 16], eax
    mov  rsi, rbx
    mov  ecx, eax
    call py_spell
    xor  edx, edx
    cmp  eax, -1
    je   .prefix
    mov  r12d, eax
    mov  edx, 1
.prefix:
    mov  [rsp + 20], edx
    mov  rsi, rbx
    mov  ecx, [rsp + 16]
    call py_is_prefix
    mov  edx, [rsp + 20]
    shl  eax, 1
    or   edx, eax
.out:
    mov  eax, edx
    mov  edx, r12d
    add  rsp, 24
    pop  r12
    pop  rbx
    ret

; ime_py_segment(RDI text, ESI len, EDX final) -> EAX ACCEPT|PENDING|REFUSED, ECX tokens, EDX the pending
; remainder's length. TABLES.md: apostrophes force boundaries; each run takes the greedy longest spelling; at a
; dead end the MOST RECENT token of the run is shortened ONCE to its next shorter spelling, then greedy again; a
; second dead end, or no shorter choice, refuses the whole input (no candidates). While typing (final 0) a remainder
; of the LAST run that is a proper prefix stays PENDING before any retry and spends none. Tokens: ime_py_ids (row
; ids; an alias gives its source row) and ime_py_bnd (half-open, in the normalized text ime_py_norm, apostrophes
; counted). ime_py_back counts the retries, also on a refusal. Input over IME_PY_MAX bytes refuses.
ime_py_segment:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24
    mov  r14d, edx
    mov  dword [rel ime_py_n], 0
    mov  dword [rel ime_py_back], 0
    mov  ecx, esi
    mov  rsi, rdi
    lea  rdi, [rel ime_py_norm]
    mov  edx, IME_PY_MAX
    call py_norm
    mov  [rel ime_py_len], eax
    cmp  eax, -1
    je   .refused
    test eax, eax
    jz   .refused
    lea  r12, [rel ime_py_norm]
    mov  r13d, eax
    ; [a-z]+('[a-z]+)*
    xor  ecx, ecx
    mov  edx, 1                         ; 1: the previous byte was an apostrophe (or the start)
.shape:
    movzx eax, byte [r12 + rcx]
    cmp  al, "'"
    jne  .letter
    test edx, edx
    jnz  .refused
    mov  edx, 1
    jmp  .shaped
.letter:
    sub  eax, 'a'
    cmp  eax, 25
    ja   .refused
    xor  edx, edx
.shaped:
    inc  ecx
    cmp  ecx, r13d
    jb   .shape
    test edx, edx
    jnz  .refused
    xor  ebp, ebp                       ; the run's start
.run:
    mov  r15d, ebp                      ; the run's end
.run_end:
    cmp  r15d, r13d
    jae  .run_found
    cmp  byte [r12 + r15], "'"
    je   .run_found
    inc  r15d
    jmp  .run_end
.run_found:
    mov  eax, [rel ime_py_n]
    mov  [rsp], eax                     ; the run's first token
    mov  dword [rsp + 4], 0             ; its retry is not spent
    mov  ebx, ebp                       ; pos
.step:
    cmp  ebx, r15d
    jae  .run_done
    test r14d, r14d
    jnz  .greedy
    cmp  r15d, r13d
    jne  .greedy
    lea  rsi, [r12 + rbx]
    mov  ecx, r15d
    sub  ecx, ebx
    call py_is_prefix
    test eax, eax
    jnz  .pending
.greedy:
    mov  ecx, r15d
    sub  ecx, ebx
    cmp  ecx, IME_PY_SYL_MAX
    jbe  .longest
    mov  ecx, IME_PY_SYL_MAX
.longest:
    mov  [rsp + 8], ecx
    lea  rsi, [r12 + rbx]
    call py_spell
    cmp  eax, -1
    jne  .take
    mov  ecx, [rsp + 8]
    dec  ecx
    jnz  .longest
    ; a dead end
    cmp  dword [rsp + 4], 0
    jne  .refused
    mov  ecx, [rel ime_py_n]
    cmp  ecx, [rsp]
    je   .refused
    dec  ecx
    mov  [rel ime_py_n], ecx
    lea  rdx, [rel ime_py_bnd]
    movzx ebx, word [rdx + rcx*4]       ; the popped token's start
    movzx ecx, word [rdx + rcx*4 + 2]
    sub  ecx, ebx
.shorter:
    dec  ecx
    jz   .refused
    mov  [rsp + 8], ecx
    lea  rsi, [r12 + rbx]
    call py_spell
    mov  ecx, [rsp + 8]
    cmp  eax, -1
    je   .shorter
    mov  dword [rsp + 4], 1
    inc  dword [rel ime_py_back]
.take:
    mov  ecx, [rel ime_py_n]
    lea  rdx, [rel ime_py_ids]
    mov  [rdx + rcx*2], ax
    lea  rdx, [rel ime_py_bnd]
    mov  [rdx + rcx*4], bx
    add  ebx, [rsp + 8]
    mov  [rdx + rcx*4 + 2], bx
    inc  ecx
    mov  [rel ime_py_n], ecx
    jmp  .step
.run_done:
    lea  ebp, [r15 + 1]
    cmp  r15d, r13d
    jb   .run
    mov  eax, IME_PY_ACCEPT
    xor  edx, edx
    jmp  .out
.pending:
    mov  eax, IME_PY_PENDING
    mov  edx, r15d
    sub  edx, ebx
    jmp  .out
.refused:
    mov  dword [rel ime_py_n], 0
    mov  eax, IME_PY_REFUSED
    xor  edx, edx
.out:
    mov  ecx, [rel ime_py_n]
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------------------------------------- I2b
; py_id_text(EDI source row id, RSI dst) -> EAX letters: the canonical spelling of a zh table row. Clobbers ECX,
; EDX, R8, R9.
py_id_text:
    lea  r8, [rel ime_zh_table]
    mov  eax, edi
    call it_row
    mov  edx, [r9]
    xor  eax, eax
    mov  ecx, 25
.group:
    mov  r8d, edx
    shr  r8d, cl
    and  r8d, 31
    jz   .out
    add  r8d, 'a' - 1
    mov  [rsi + rax], r8b
    inc  eax
    sub  ecx, 5
    jns  .group
.out:
    ret

; ik_utf8(EDI scalar < 0x10000, RSI dst) -> EAX bytes written (1..3).
ik_utf8:
    cmp  edi, 0x80
    jae  .two
    mov  [rsi], dil
    mov  eax, 1
    ret
.two:
    cmp  edi, 0x800
    jae  .three
    mov  eax, edi
    shr  eax, 6
    or   al, 0xC0
    mov  [rsi], al
    mov  eax, edi
    and  al, 0x3F
    or   al, 0x80
    mov  [rsi + 1], al
    mov  eax, 2
    ret
.three:
    mov  eax, edi
    shr  eax, 12
    or   al, 0xE0
    mov  [rsi], al
    mov  eax, edi
    shr  eax, 6
    and  al, 0x3F
    or   al, 0x80
    mov  [rsi + 1], al
    mov  eax, edi
    and  al, 0x3F
    or   al, 0x80
    mov  [rsi + 2], al
    mov  eax, 3
    ret

; ik_view() -> EAX bytes: the pre-edit as UTF-8 in ime_view (ja: the kana, then the pending romaji; zh: the text
; as typed).
ik_view:
    push rbx
    push r12
    sub  rsp, 8
    xor  ebx, ebx
    cmp  byte [rel ime_method], IME_M_JA
    jne  .zh
    xor  r12d, r12d
.kana:
    cmp  r12d, [rel ime_kana_n]
    jae  .pending
    lea  rax, [rel ime_kana]
    mov  edi, [rax + r12*4]
    lea  rsi, [rel ime_view]
    add  rsi, rbx
    call ik_utf8
    add  ebx, eax
    inc  r12d
    jmp  .kana
.pending:
    lea  rdi, [rel ime_view]
    add  rdi, rbx
    lea  rsi, [rel ime_rj]
    mov  edx, [rel ime_rj_n]
    add  ebx, edx
    call memcpy
    jmp  .out
.zh:
    lea  rdi, [rel ime_view]
    lea  rsi, [rel ime_zh]
    mov  edx, [rel ime_zh_n]
    mov  ebx, edx
    call memcpy
.out:
    mov  eax, ebx
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; ik_run(EDX flush): run the ja romaji steps over the pending buffer into the kana, until PREFIX (typing) or until
; the buffer is empty (flush). A carry stays pending.
ik_run:
    push rbx
    push r12
    push r13
    sub  rsp, 16                        ; the step's 3 output scalars
    mov  ebx, edx
.step:
    mov  esi, [rel ime_rj_n]
    test esi, esi
    jz   .out
    lea  rdi, [rel ime_rj]
    mov  edx, ebx
    mov  rcx, rsp
    call ime_romaji_step
    cmp  eax, IME_RJ_PREFIX
    je   .out
    test eax, eax
    jz   .drop                          ; refused: only bytes of the table alphabet are ever pending
    mov  r12d, edx                      ; consumed
    mov  r13d, ecx
    xor  ecx, ecx
.copy:
    cmp  ecx, r13d
    jae  .shift
    mov  edx, [rel ime_kana_n]
    cmp  edx, IME_KANA_CAP
    jae  .shift
    mov  eax, [rsp + rcx*4]
    lea  r8, [rel ime_kana]
    mov  [r8 + rdx*4], eax
    inc  edx
    mov  [rel ime_kana_n], edx
    inc  ecx
    jmp  .copy
.shift:
    lea  r8, [rel ime_rj]
    mov  ecx, [rel ime_rj_n]
    sub  ecx, r12d
    mov  [rel ime_rj_n], ecx
    xor  edx, edx
.move:
    cmp  edx, ecx
    jae  .clear
    lea  eax, [rdx + r12]
    mov  al, [r8 + rax]
    mov  [r8 + rdx], al
    inc  edx
    jmp  .move
.clear:
    cmp  edx, IME_RJ_PENDING_MAX
    jae  .step
    mov  byte [r8 + rdx], 0
    inc  edx
    jmp  .clear
.drop:
    mov  dword [rel ime_rj_n], 0
.out:
    add  rsp, 16
    pop  r13
    pop  r12
    pop  rbx
    ret

; ik_alpha(EDI key) -> EAX 1 when the key belongs to the active method's alphabet: ja the TABLES.md key bytes
; (a-z and ' , - . / [ ] ~); zh a-z, and an apostrophe once a pre-edit exists.
ik_alpha:
    xor  eax, eax
    cmp  edi, 127
    ja   .out
    lea  ecx, [rdi - 'a']
    cmp  ecx, 25
    jbe  .yes
    cmp  byte [rel ime_method], IME_M_JA
    jne  .zh
    lea  rcx, [rel ime_ja_marks]
.mark:
    movzx edx, byte [rcx]
    test edx, edx
    jz   .out
    cmp  edx, edi
    je   .yes
    inc  rcx
    jmp  .mark
.zh:
    cmp  edi, "'"
    jne  .out
    cmp  byte [rel ime_state], IME_S_IDLE
    je   .out
.yes:
    mov  eax, 1
.out:
    ret

; ik_type(EDI key of the alphabet) -> EAX actions: append it to the pre-edit. Over the cap (ja: the kana plus the
; pending romaji after the key's run over IME_KANA_MAX, checked on the run's OUTPUT and undone byte for byte; zh: 64
; bytes) or a zh apostrophe that would start the text or follow another: refused and counted, nothing changes.
ik_type:
    push rbx
    sub  rsp, 16 + IME_UNDO_SLOTS * 4   ; the undo: kana_n, rj_n, rj, then the kana slots from kana_n on
    mov  ebx, edi
    cmp  byte [rel ime_method], IME_M_JA
    jne  .zh
    mov  ecx, [rel ime_rj_n]
    cmp  ecx, IME_RJ_PENDING_MAX        ; never: a typing run leaves at most a 3-byte PREFIX pending
    jae  .refuse
    mov  eax, [rel ime_kana_n]
    cmp  eax, IME_KANA_MAX
    jae  .refuse
    mov  [rsp], eax
    mov  [rsp + 4], ecx
    mov  edx, [rel ime_rj]
    mov  [rsp + 8], edx
    lea  rdi, [rsp + 16]
    lea  rsi, [rel ime_kana]
    lea  rsi, [rsi + rax*4]             ; kana_n < 42: the 12 slots stay inside IME_KANA_CAP
    mov  edx, IME_UNDO_SLOTS * 4
    call memcpy
    mov  ecx, [rel ime_rj_n]
    lea  rdx, [rel ime_rj]
    mov  [rdx + rcx], bl
    inc  ecx
    mov  [rel ime_rj_n], ecx
    xor  edx, edx
    call ik_run
    mov  eax, [rel ime_kana_n]
    add  eax, [rel ime_rj_n]
    cmp  eax, IME_KANA_MAX
    jbe  .typed
    mov  eax, [rsp]                     ; over: undo the run
    mov  [rel ime_kana_n], eax
    mov  ecx, [rsp + 4]
    mov  [rel ime_rj_n], ecx
    mov  ecx, [rsp + 8]
    mov  [rel ime_rj], ecx
    lea  rdi, [rel ime_kana]
    lea  rdi, [rdi + rax*4]
    lea  rsi, [rsp + 16]
    mov  edx, IME_UNDO_SLOTS * 4
    call memcpy
    jmp  .refuse
.zh:
    mov  ecx, [rel ime_zh_n]
    cmp  ecx, IME_PY_MAX
    jae  .refuse
    lea  rdx, [rel ime_zh]
    cmp  ebx, "'"
    jne  .put
    test ecx, ecx
    jz   .refuse
    cmp  byte [rdx + rcx - 1], "'"
    je   .refuse
.put:
    mov  [rdx + rcx], bl
    inc  ecx
    mov  [rel ime_zh_n], ecx
.typed:
    mov  byte [rel ime_state], IME_S_COMPOSING
    mov  byte [rel ime_flags], 0
    mov  eax, IME_A_CONSUMED | IME_A_PREEDIT
    jmp  .out
.refuse:
    inc  dword [rel ime_refused]
    mov  eax, IME_A_CONSUMED
.out:
    add  rsp, 16 + IME_UNDO_SLOTS * 4
    pop  rbx
    ret

; ik_clear() empties the pre-edit and the conversion (state IDLE); the commit buffer stays.
ik_clear:
    sub  rsp, 8
    lea  rdi, [rel ime_st_begin]
    xor  esi, esi
    mov  edx, ime_st_end - ime_st_begin
    call memset
    add  rsp, 8
    ret

; ik_commit_preedit(EDI katakana) -> EAX actions: commit the pre-edit as it stands (ja: the kana after a flush, as
; katakana when asked: +0x60 on U+3041..U+3096 only; zh: the text as typed), then clear it.
ik_commit_preedit:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, edi
    cmp  byte [rel ime_method], IME_M_JA
    jne  .zh
    mov  edx, 1
    call ik_run
    xor  r12d, r12d
.kana:
    cmp  r12d, [rel ime_kana_n]
    jae  .done
    lea  rax, [rel ime_kana]
    mov  edi, [rax + r12*4]
    test ebx, ebx
    jz   .put
    lea  eax, [rdi - 0x3041]
    cmp  eax, 0x3096 - 0x3041
    ja   .put
    add  edi, 0x60
.put:
    mov  eax, [rel ime_commit_n]
    lea  rsi, [rel ime_commit]
    add  rsi, rax
    call ik_utf8
    add  [rel ime_commit_n], eax
    inc  r12d
    jmp  .kana
.zh:
    call ik_commit_rest
.done:
    call ik_clear
    mov  eax, IME_A_CONSUMED | IME_A_PREEDIT | IME_A_COMMIT
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; ik_commit_rest() appends the zh text as typed to the commit buffer.
ik_commit_rest:
    sub  rsp, 8
    lea  rdi, [rel ime_commit]
    mov  eax, [rel ime_commit_n]
    add  rdi, rax
    lea  rsi, [rel ime_zh]
    mov  edx, [rel ime_zh_n]
    add  [rel ime_commit_n], edx
    call memcpy
    add  rsp, 8
    ret

; ik_backspace() -> EAX actions: ja removes the last pending romaji byte, else the last kana SCALAR; zh the last
; byte. An empty pre-edit returns to IDLE.
ik_backspace:
    cmp  byte [rel ime_method], IME_M_JA
    jne  .zh
    mov  ecx, [rel ime_rj_n]
    test ecx, ecx
    jz   .kana
    dec  ecx
    mov  [rel ime_rj_n], ecx
    lea  rdx, [rel ime_rj]
    mov  byte [rdx + rcx], 0
    jmp  .left
.kana:
    mov  ecx, [rel ime_kana_n]
    test ecx, ecx
    jz   .left
    dec  ecx
    mov  [rel ime_kana_n], ecx
    lea  rdx, [rel ime_kana]
    mov  dword [rdx + rcx*4], 0
.left:
    mov  eax, [rel ime_kana_n]
    or   eax, [rel ime_rj_n]
    jmp  .state
.zh:
    mov  ecx, [rel ime_zh_n]
    test ecx, ecx
    jz   .zh_left
    dec  ecx
    mov  [rel ime_zh_n], ecx
    lea  rdx, [rel ime_zh]
    mov  byte [rdx + rcx], 0
.zh_left:
    mov  eax, [rel ime_zh_n]
.state:
    mov  byte [rel ime_flags], 0
    test eax, eax
    jnz  .out
    mov  byte [rel ime_state], IME_S_IDLE
.out:
    mov  eax, IME_A_CONSUMED | IME_A_PREEDIT
    ret

; ik_convert() -> EAX actions. ja: flush, then ONE segment, the whole kana run. zh: segment the text (final); the
; key is the CANONICAL syllables joined by single spaces (the PDCT1 row form), tried for the longest leading run of
; k = n..1 syllables that has candidates; ime_conv_end marks the text it covers. Candidates: CONVERTING, selection 0.
; None (or a refused segmentation, an over-long key or a run over I1's 512 rows, where zh tries the next shorter run):
; NO_CANDIDATES. I1 unavailable: UNAVAILABLE, never a list.
ik_convert:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    cmp  byte [rel ime_method], IME_M_JA
    jne  .zh
    mov  edx, 1
    call ik_run
    call ik_view
    mov  edx, eax
    mov  edi, IME_M_JA
    lea  rsi, [rel ime_view]
    call ime_dict_lookup
    jmp  .result
.zh:
    lea  rdi, [rel ime_zh]
    mov  esi, [rel ime_zh_n]
    mov  edx, 1
    call ime_py_segment
    cmp  eax, IME_PY_ACCEPT
    jne  .none
    mov  r13d, ecx                      ; k
.try:
    test r13d, r13d
    jz   .none
    xor  r12d, r12d                     ; key bytes
    xor  r14d, r14d                     ; token
.token:
    cmp  r14d, r13d
    jae  .lookup
    lea  rsi, [rel ime_view]
    test r14d, r14d
    jz   .first
    mov  byte [rsi + r12], ' '
    inc  r12d
.first:
    add  rsi, r12
    lea  rax, [rel ime_py_ids]
    movzx edi, word [rax + r14*2]
    call py_id_text
    add  r12d, eax
    inc  r14d
    jmp  .token
.lookup:
    mov  edi, IME_M_ZH
    lea  rsi, [rel ime_view]
    mov  edx, r12d
    call ime_dict_lookup
    cmp  eax, IME_DICT_E_MATCHES        ; too many rows for this run: try the next shorter one
    je   .next_run
    test eax, eax
    jnz  .result
    test ecx, ecx
    jnz  .covered
.next_run:
    dec  r13d
    jmp  .try
.covered:
    lea  rax, [rel ime_py_bnd]
    movzx edx, word [rax + r13*4 - 2]   ; the end of token k-1
    mov  [rel ime_conv_end], edx
    xor  eax, eax
.result:
    test eax, eax
    jnz  .error
    test ecx, ecx
    jz   .none
    mov  [rel ime_cands], ecx
    mov  dword [rel ime_sel], 0
    mov  byte [rel ime_state], IME_S_CONVERTING
    mov  byte [rel ime_flags], 0
    mov  eax, IME_A_CONSUMED | IME_A_PREEDIT | IME_A_CANDS
    jmp  .out
.error:
    cmp  eax, IME_DICT_KEY_REFUSED
    je   .none
    cmp  eax, IME_DICT_E_MATCHES        ; ja: the one run has over 512 rows: no list, I1 is fine
    je   .none
    mov  byte [rel ime_flags], IME_F_UNAVAILABLE
    jmp  .stay
.none:
    mov  byte [rel ime_flags], IME_F_NO_CANDIDATES
.stay:
    mov  eax, IME_A_CONSUMED | IME_A_PREEDIT
.out:
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ik_pick(EDI candidate) -> EAX actions: commit its surface. ja: the whole run is gone (IDLE). zh: the text after
; ime_conv_end (leading apostrophes dropped) stays as the pre-edit. If I1 cannot read it: UNAVAILABLE, back to
; COMPOSING with the pre-edit unchanged, nothing committed.
ik_pick:
    sub  rsp, 8
    mov  esi, edi
    movzx edi, byte [rel ime_method]
    lea  rdx, [rel ime_commit]          ; empty: every ime_key starts with no commit
    call ime_dict_candidate
    test eax, eax
    jnz  .fail
    mov  [rel ime_commit_n], edx
    cmp  byte [rel ime_method], IME_M_ZH
    je   .rest
    call ik_clear
    jmp  .done
.rest:
    mov  ecx, [rel ime_conv_end]
    lea  r8, [rel ime_zh]
.strip:
    cmp  ecx, [rel ime_zh_n]
    jae  .move
    cmp  byte [r8 + rcx], "'"
    jne  .move
    inc  ecx
    jmp  .strip
.move:
    mov  edx, [rel ime_zh_n]
    sub  edx, ecx
    xor  eax, eax
.byte:
    cmp  eax, IME_PY_MAX
    jae  .moved
    xor  r9d, r9d
    cmp  eax, edx
    jae  .put
    lea  r10d, [rax + rcx]
    movzx r9d, byte [r8 + r10]
.put:
    mov  [r8 + rax], r9b
    inc  eax
    jmp  .byte
.moved:
    mov  [rel ime_zh_n], edx
    mov  dword [rel ime_cands], 0
    mov  dword [rel ime_sel], 0
    mov  dword [rel ime_conv_end], 0
    mov  byte [rel ime_flags], 0
    mov  byte [rel ime_state], IME_S_COMPOSING
    test edx, edx
    jnz  .done
    mov  byte [rel ime_state], IME_S_IDLE
.done:
    mov  eax, IME_A_CONSUMED | IME_A_COMMIT | IME_A_PREEDIT | IME_A_CANDS
    add  rsp, 8
    ret
.fail:
    mov  dword [rel ime_commit_n], 0
    call ik_back
    mov  byte [rel ime_flags], IME_F_UNAVAILABLE
    add  rsp, 8
    ret

; ik_back() -> EAX actions: leave the candidate list, back to COMPOSING with the pre-edit unchanged.
ik_back:
    mov  dword [rel ime_cands], 0
    mov  dword [rel ime_sel], 0
    mov  dword [rel ime_conv_end], 0
    mov  byte [rel ime_state], IME_S_COMPOSING
    mov  eax, IME_A_CONSUMED | IME_A_PREEDIT | IME_A_CANDS
    ret

; ime_set_method(EDI 0 off | 1 ja | 2 zh-Hans) -> EAX status (I1's). The pre-edit is discarded first. A method binds
; its dictionary through I1; a refusal leaves the IME OFF (keys PASS: Latin typing stays live) with a marker.
ime_set_method:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, edi
    call ime_cancel
    mov  byte [rel ime_method], IME_M_OFF
    xor  eax, eax
    test ebx, ebx
    jz   .out
    mov  eax, 1                         ; = ime_dict's IME_E_LOCALE
    cmp  ebx, IME_M_ZH
    ja   .refused
    mov  edi, ebx
    call ime_dict_bind
    test eax, eax
    jnz  .refused
    mov  [rel ime_method], bl
    jmp  .out
.refused:
    mov  r12d, eax
    lea  rdi, [rel str_ime_method]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_ime_core_status]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    lea  rdi, [rel str_ime_core_eol]
    call serial_string
    mov  eax, r12d
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; ime_cancel(): DISCARD the pre-edit, the candidate list, any untaken commit and the last zh segmentation (rc-sec
; 10:37:44: a focus, lock, session or layout change never commits). The method stays.
ime_cancel:
    sub  rsp, 8
    call ik_clear
    lea  rdi, [rel ime_commit]
    xor  esi, esi
    mov  edx, IME_COMMIT_CAP
    call memset
    mov  dword [rel ime_commit_n], 0
    lea  rdi, [rel ime_py_len]          ; and the last zh segmentation (srcreview INFO 17:49:26)
    xor  esi, esi
    mov  edx, ime_py_norm + IME_PY_MAX - ime_py_len
    call memset
    add  rsp, 8
    ret

; ime_key(EDI key, ESI origin) -> EAX actions (PLAN_I2 4). A key whose origin is not KO_HUMAN, or any key while the
; method is OFF: PASS (0), the state untouched. Otherwise the commit buffer is emptied and the key is handled by
; state; without IME_A_CONSUMED the caller delivers the key after taking any commit.
ime_key:
    push rbx
    push r12
    push r15
    mov  r12d, edi
    xor  r15d, r15d
    cmp  esi, IME_ORIGIN_HUMAN
    jne  .out
    movzx ebx, byte [rel ime_method]
    test ebx, ebx
    jz   .out
    mov  dword [rel ime_commit_n], 0
    movzx eax, byte [rel ime_state]
    cmp  eax, IME_S_CONVERTING
    je   .converting
    cmp  eax, IME_S_COMPOSING
    je   .composing
    mov  edi, r12d
    call ik_alpha
    test eax, eax
    jz   .out
.type:
    mov  edi, r12d
    call ik_type
    or   r15d, eax
    jmp  .out
.composing:
    cmp  r12d, IME_K_BACKSPACE
    jne  .not_bs
    call ik_backspace
    jmp  .set
.not_bs:
    cmp  r12d, IME_K_ENTER
    jne  .not_enter
    xor  edi, edi
    call ik_commit_preedit
    jmp  .set
.not_enter:
    cmp  r12d, IME_K_ESCAPE
    jne  .not_esc
    call ik_clear
    mov  eax, IME_A_CONSUMED | IME_A_PREEDIT
    jmp  .set
.not_esc:
    cmp  r12d, ' '
    jne  .not_space
    call ik_convert
    jmp  .set
.not_space:
    cmp  r12d, IME_K_F7
    jne  .compose_key
    cmp  ebx, IME_M_JA
    jne  .compose_key
    mov  edi, 1
    call ik_commit_preedit
    jmp  .set
.compose_key:
    mov  edi, r12d
    call ik_alpha
    test eax, eax
    jnz  .type
    xor  edi, edi                       ; any other key: commit the pre-edit as is, then the key goes on
    call ik_commit_preedit
    and  eax, ~IME_A_CONSUMED
    jmp  .set
.converting:
    cmp  r12d, ' '
    je   .next
    cmp  r12d, IME_K_DOWN
    je   .next
    cmp  r12d, IME_K_UP
    je   .prev
    cmp  r12d, IME_K_PGDN
    je   .page_down
    cmp  r12d, IME_K_PGUP
    je   .page_up
    cmp  r12d, IME_K_ENTER
    je   .pick_sel
    cmp  r12d, IME_K_ESCAPE
    je   .back
    cmp  r12d, IME_K_BACKSPACE
    je   .back
    cmp  r12d, IME_K_LEFT
    je   .noop
    cmp  r12d, IME_K_RIGHT
    je   .noop
    cmp  r12d, IME_K_F7
    je   .noop
    lea  eax, [r12 - '0']
    cmp  eax, 9
    ja   .conv_key
    test eax, eax
    jz   .noop
    dec  eax
    mov  ecx, eax
    mov  eax, [rel ime_sel]
    xor  edx, edx
    mov  r8d, IME_PAGE
    div  r8d
    imul eax, eax, IME_PAGE
    add  eax, ecx
    cmp  eax, [rel ime_cands]
    jae  .noop
    mov  edi, eax
    call ik_pick
    jmp  .set
.conv_key:
    mov  edi, r12d
    call ik_alpha
    mov  ebx, eax
    mov  edi, [rel ime_sel]
    call ik_pick
    mov  r15d, eax
    test eax, IME_A_COMMIT
    jz   .out                           ; unreadable: the key is spent with the UNAVAILABLE flag
    test ebx, ebx
    jnz  .type                          ; a letter after a pick starts (or extends) the next pre-edit
    call ik_commit_rest                 ; any other key: the zh remainder is committed as typed, then the key
    call ik_clear                       ; goes on
    and  r15d, ~IME_A_CONSUMED
    jmp  .out
.pick_sel:
    mov  edi, [rel ime_sel]
    call ik_pick
    jmp  .set
.back:
    call ik_back
    jmp  .set
.noop:
    mov  eax, IME_A_CONSUMED
    jmp  .set
.next:
    mov  eax, [rel ime_sel]
    inc  eax
    cmp  eax, [rel ime_cands]
    jb   .select
    xor  eax, eax
    jmp  .select
.prev:
    mov  eax, [rel ime_sel]
    test eax, eax
    jnz  .prev_one
    mov  eax, [rel ime_cands]
.prev_one:
    dec  eax
    jmp  .select
.page_down:
    mov  eax, [rel ime_sel]
    xor  edx, edx
    mov  ecx, IME_PAGE
    div  ecx
    inc  eax
    imul eax, eax, IME_PAGE
    cmp  eax, [rel ime_cands]
    jb   .select
    xor  eax, eax
    jmp  .select
.page_up:
    mov  eax, [rel ime_sel]
    xor  edx, edx
    mov  ecx, IME_PAGE
    div  ecx
    test eax, eax
    jnz  .page_prev
    mov  eax, [rel ime_cands]
    dec  eax
    xor  edx, edx
    div  ecx
    inc  eax
.page_prev:
    dec  eax
    imul eax, eax, IME_PAGE
.select:
    mov  [rel ime_sel], eax
    mov  eax, IME_A_CONSUMED | IME_A_CANDS
.set:
    mov  r15d, eax
.out:
    mov  eax, r15d
    pop  r15
    pop  r12
    pop  rbx
    ret

; ime_preedit(RDI out, ESI cap) -> EAX bytes (-1 when cap is short, nothing written), EDX the caret (its end),
; ECX state | flags << 8 | method << 16.
ime_preedit:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    call ik_view
    mov  ebx, eax
    cmp  eax, r13d
    ja   .short
    mov  rdi, r12
    lea  rsi, [rel ime_view]
    mov  edx, ebx
    call memcpy
    mov  eax, ebx
    jmp  .out
.short:
    mov  eax, -1
.out:
    mov  edx, ebx
    movzx ecx, byte [rel ime_method]
    shl  ecx, 8
    mov  cl, [rel ime_flags]
    shl  ecx, 8
    mov  cl, [rel ime_state]
    pop  r13
    pop  r12
    pop  rbx
    ret

; ime_commit_take(RDI out, ESI cap) -> EAX bytes (-1 when cap is short: nothing taken). Empties the buffer.
ime_commit_take:
    push rbx
    mov  ebx, [rel ime_commit_n]
    cmp  ebx, esi
    ja   .short
    lea  rsi, [rel ime_commit]
    mov  edx, ebx
    call memcpy
    lea  rdi, [rel ime_commit]
    xor  esi, esi
    mov  edx, IME_COMMIT_CAP
    call memset
    mov  dword [rel ime_commit_n], 0
    mov  eax, ebx
    pop  rbx
    ret
.short:
    mov  eax, -1
    pop  rbx
    ret

; ime_cand_info() -> EAX candidates (0 unless CONVERTING), EDX the selection.
ime_cand_info:
    mov  eax, [rel ime_cands]
    mov  edx, [rel ime_sel]
    ret

; ime_cand_get(EDI i, RSI out 256 B) -> EAX status, EDX the surface's bytes: candidate i of the current list.
ime_cand_get:
    sub  rsp, 8
    cmp  edi, [rel ime_cands]
    jae  .range
    mov  rdx, rsi
    mov  esi, edi
    movzx edi, byte [rel ime_method]
    call ime_dict_candidate
    add  rsp, 8
    ret
.range:
    mov  eax, IME_DICT_E_RANGE
    xor  edx, edx
    add  rsp, 8
    ret

; ime_conv_info() -> EAX the pre-edit bytes, from its start, that the current conversion covers (0 unless CONVERTING;
; ja: the whole kana run, zh: ime_conv_end), ECX state | flags << 8 | method << 16 as ime_preedit. RCQ-38 I3: it
; only reads, so the view and the mode indicator never touch the IME state (not even the ime_view scratch).
ime_conv_info:
    movzx ecx, byte [rel ime_method]
    shl  ecx, 8
    mov  cl, [rel ime_flags]
    shl  ecx, 8
    mov  cl, [rel ime_state]
    xor  eax, eax
    cmp  byte [rel ime_state], IME_S_CONVERTING
    jne  .out
    cmp  byte [rel ime_method], IME_M_JA
    jne  .zh
    xor  edx, edx
    lea  r8, [rel ime_kana]
.kana:                                  ; the UTF-8 length ik_utf8 gives each scalar
    cmp  edx, [rel ime_kana_n]
    jae  .out
    mov  r9d, [r8 + rdx*4]
    inc  eax
    cmp  r9d, 0x80
    jb   .next
    inc  eax
    cmp  r9d, 0x800
    jb   .next
    inc  eax
.next:
    inc  edx
    jmp  .kana
.zh:
    mov  eax, [rel ime_conv_end]
.out:
    ret

ime_ja_marks:        db "',-./[]~", 0   ; the ja alphabet beyond a-z (TABLES.md key bytes; census-pinned)
str_ime_method:      db "[ime.core] method refused locale=", 0
str_ime_core_status: db " status=", 0
str_ime_core_eol:    db 13, 10, 0

%macro WDATA_gui_ime_core 0
alignb 8
ime_st_begin:                           ; ---- the pre-edit and conversion (ik_clear zeroes it all)
ime_state:           resb 1
ime_flags:           resb 1
alignb 4
ime_kana:            resd IME_KANA_CAP  ; ja: the converted kana scalars
ime_kana_n:          resd 1
ime_rj:              resb IME_RJ_PENDING_MAX ; ja: the pending romaji
ime_rj_n:            resd 1
ime_zh:              resb IME_PY_MAX     ; zh: the text as typed
ime_zh_n:            resd 1
ime_cands:           resd 1
ime_sel:             resd 1
ime_conv_end:        resd 1             ; zh: the bytes of ime_zh the conversion covers
ime_view:            resb IME_VIEW_CAP   ; the pre-edit as UTF-8, and the conversion key
ime_st_end:
ime_commit:          resb IME_COMMIT_CAP
ime_commit_n:        resd 1
ime_refused:         resd 1             ; keys refused at a cap
ime_method:          resb 1             ; 0 off, 1 ja, 2 zh-Hans
ime_py_len:          resd 1
ime_py_n:            resd 1
ime_py_back:         resd 1
ime_py_ids:          resw IME_PY_MAX     ; the last segmentation's tokens: source row ids
ime_py_bnd:          resw IME_PY_MAX * 2 ; their half-open boundaries in ime_py_norm
ime_py_norm:         resb IME_PY_MAX     ; its normalized text
%endmacro
WDATA_BSS_DEFER WDATA_gui_ime_core
