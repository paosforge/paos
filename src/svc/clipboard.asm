;; MODULE svc/clipboard
;; LAYER 5
;; EXPORTS clipboard_init, clipboard_bind_textfield, clipboard_audit_line, clipboard_out_buf, clipboard_out_ready
;; IMPORTS boot/serial, core/lock, core/lib/fmt, core/lib/str, svc/command, svc/command_auth
;; CAPS clipboard.read(slot20), clipboard.write(signed)
;; OWNER saga:clipboard_service
;; LOCK: clipboard_lock PROTECTS clipboard_entry
; ============================================================================
; Task3373 — one nonvisual, typed clipboard service.
;
; Entry v1 reserves every format-changing field now: media type, inline bytes or
; a slot-14 handle, provenance, generation, and a bounded history index.  The
; history ring itself is deliberately absent until its own rung.  CLIPSET never
; echoes or audits content; CLIPINFO never emits content or the handle value.
;
; Wire grammar (bounded, synchronous):
;   CLIPSET <media> inline <bytes...> [provenance=<token>]
;   CLIPSET text/plain textfield <id> [provenance=<token>]
;   CLIPSET <media> handle slot14:<positive-decimal> [provenance=<token>]
;   CLIPGET <media> [textfield <id>]
;   CLIPINFO
; Explicit textfield modes reuse WIDGETGET/WIDGETSET's value functions.  They
; do not observe selection/caret state and never run automatically.
; ============================================================================

CLIP_KIND_EMPTY      equ 0
CLIP_KIND_INLINE     equ 1
CLIP_KIND_HANDLE14   equ 2
CLIP_MEDIA_MAX       equ 63
CLIP_INLINE_MAX      equ 768
CLIP_PROVENANCE_MAX  equ 127
CLIP_ARG_MAX         equ 1024
CLIP_PARSE_PAD       equ 16             ; lookahead guard for token recognizers
CLIP_OUT_MAX         equ 1152
CLIP_HISTORY_MAX     equ 16
CLIP_HISTORY_NONE    equ 0xFFFFFFFF
CLIP_WIDGET_ID_MAX       equ 31
CLIP_TEXTFIELD_VALUE_MAX equ 39

; Fixed v1 entry header; the reserved history field keeps later ring adoption
; additive.  Buffers follow as bounded inline fields.
CLIP_E_KIND          equ 0              ; db CLIP_KIND_*
CLIP_E_PRESENT       equ 1              ; db
CLIP_E_FLAGS         equ 2              ; dw reserved
CLIP_E_INLINE_LEN    equ 4              ; dd
CLIP_E_PROV_LEN      equ 8              ; dd
CLIP_E_HISTORY       equ 12             ; dd, CLIP_HISTORY_NONE in v1
CLIP_E_GENERATION    equ 16             ; dq
CLIP_E_HANDLE14      equ 24             ; dq
CLIP_E_MEDIA         equ 32             ; 64-byte cstr
CLIP_E_INLINE        equ 96             ; 769-byte cstr
CLIP_E_PROVENANCE    equ 865            ; 128-byte cstr
CLIP_E_SIZE          equ 993

%if CLIP_E_INLINE + CLIP_INLINE_MAX + 1 != CLIP_E_PROVENANCE
    %error "clipboard inline envelope drift"
%endif
%if CLIP_E_PROVENANCE + CLIP_PROVENANCE_MAX + 1 != CLIP_E_SIZE
    %error "clipboard provenance envelope drift"
%endif

clipboard_lock_acquire:
    lea  rdi, [rel clipboard_lock]
    jmp  spin_acquire

clipboard_lock_release:
    lea  rdi, [rel clipboard_lock]
    jmp  spin_release

; Copy RSI into the bounded parser arena. EAX=0 or -1; always NUL-safe.
clipboard_arg_copy:
    lea  rdi, [rel clipboard_parse_buf]
    xor  ecx, ecx
.copy:
    cmp  ecx, CLIP_ARG_MAX
    jae  .at_cap
    mov  al, [rsi + rcx]
    test al, al
    jz   .done
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .copy
.at_cap:
    mov  byte [rdi + CLIP_ARG_MAX], 0
    cmp  byte [rsi + CLIP_ARG_MAX], 0
    jne  .bad
.done:
    mov  byte [rdi + rcx], 0
    ; The provenance matcher uses bounded fixed-width comparisons.  Keep a
    ; zero guard after every copied request, including an exact-cap request,
    ; so those comparisons can never inspect beyond the parser arena.
    mov  qword [rdi + rcx + 1], 0
    mov  qword [rdi + rcx + 9], 0
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; Peek only at the first token.  This runs before the full argument copy so a
; SECRET media request cannot leave its value in service scratch. EAX=0 normal,
; 1 exact SECRET type, -1 malformed/oversize.
clipboard_peek_media:
    lea  rdx, [rel clipboard_media_peek]
    xor  ecx, ecx
.scan:
    mov  al, [rdi + rcx]
    test al, al
    jz   .end
    cmp  al, ' '
    je   .end
    cmp  ecx, CLIP_MEDIA_MAX
    jae  .bad
    mov  [rdx + rcx], al
    inc  ecx
    jmp  .scan
.end:
    test ecx, ecx
    jz   .bad
    mov  byte [rdx + rcx], 0
    lea  rdi, [rel clipboard_media_peek]
    lea  rsi, [rel str_clip_media_secret]
    call strcmp
    test eax, eax
    jnz  .normal
    mov  eax, 1
    ret
.normal:
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

clipboard_skip_space:                   ; RDI -> RAX
    mov  rax, rdi
.loop:
    cmp  byte [rax], ' '
    jne  .done
    inc  rax
    jmp  .loop
.done:
    ret

; NUL-split one token. RDI=token, RAX=first non-space after it.
clipboard_split_token:
    mov  rax, rdi
.scan:
    mov  cl, [rax]
    test cl, cl
    jz   .done
    cmp  cl, ' '
    je   .split
    inc  rax
    jmp  .scan
.split:
    mov  byte [rax], 0
    inc  rax
.spaces:
    cmp  byte [rax], ' '
    jne  .done
    inc  rax
    jmp  .spaces
.done:
    ret

; Split an optional trailing " provenance=<token>" from a data tail.  RAX=0
; absent or pointer to the provenance value.  Empty/spaced provenance is left
; for the bounded validator to refuse.
clipboard_split_provenance:
    mov  rax, rdi
.next:
    cmp  byte [rax], 0
    je   .none
    cmp  byte [rax], ' '
    jne  .advance
    cmp  dword [rax + 1], 'prov'
    jne  .advance
    cmp  dword [rax + 5], 'enan'
    jne  .advance
    cmp  word [rax + 9], 'ce'
    jne  .advance
    cmp  byte [rax + 11], '='
    jne  .advance
    mov  byte [rax], 0
    lea  rax, [rax + 12]
    ret
.advance:
    inc  rax
    jmp  .next
.none:
    xor  eax, eax
    ret

; RDI=cstr, ESI=max accepted bytes -> EAX=len or -1.
clipboard_bounded_len:
    xor  eax, eax
.loop:
    cmp  eax, esi
    jae  .at_max
    cmp  byte [rdi + rax], 0
    je   .done
    inc  eax
    jmp  .loop
.at_max:
    cmp  byte [rdi + rax], 0
    jne  .bad
.done:
    ret
.bad:
    mov  eax, -1
    ret

; Exact known public media vocabulary. SECRET is handled before this function.
clipboard_media_allowed:
    push rbx
    mov  rbx, rdi
    lea  rsi, [rel str_clip_media_text]
    call strcmp
    test eax, eax
    jz   .yes
    mov  rdi, rbx
    lea  rsi, [rel str_clip_media_octets]
    call strcmp
    test eax, eax
    jz   .yes
    mov  rdi, rbx
    lea  rsi, [rel str_clip_media_png]
    call strcmp
    test eax, eax
    jz   .yes
    mov  rdi, rbx
    lea  rsi, [rel str_clip_media_jpeg]
    call strcmp
    test eax, eax
    jz   .yes
    xor  eax, eax
    pop  rbx
    ret
.yes:
    mov  eax, 1
    pop  rbx
    ret

; Strict positive decimal, full-token consumption. RDI=cstr -> RAX, EDX=0/1.
; Widget ids are zero-based.  Preserve the positive-only parser for slot-14
; handles while admitting the one canonical zero spelling at widget call sites.
clipboard_parse_widget_id:
    cmp  byte [rdi], '0'
    jne  clipboard_parse_positive
    cmp  byte [rdi + 1], 0
    jne  clipboard_parse_positive
    xor  eax, eax
    xor  edx, edx
    ret

clipboard_parse_positive:
    xor  eax, eax
    xor  ecx, ecx
.digit:
    movzx r8d, byte [rdi + rcx]
    test r8b, r8b
    jz   .end
    sub  r8d, '0'
    cmp  r8d, 9
    ja   .bad
    mov  r9, 0x1999999999999999
    cmp  rax, r9
    ja   .bad
    jb   .accumulate
    cmp  r8d, 5                         ; UINT64_MAX's final decimal digit
    ja   .bad
.accumulate:
    imul rax, rax, 10
    add  rax, r8
    inc  ecx
    jmp  .digit
.end:
    test ecx, ecx
    jz   .bad
    test rax, rax
    jz   .bad
    xor  edx, edx
    ret
.bad:
    xor  eax, eax
    mov  edx, 1
    ret

; Validate "slot14:<positive-decimal>".
clipboard_parse_handle14:
    cmp  dword [rdi], 'slot'
    jne  .bad
    cmp  word [rdi + 4], '14'
    jne  .bad
    cmp  byte [rdi + 6], ':'
    jne  .bad
    add  rdi, 7
    jmp  clipboard_parse_positive
.bad:
    xor  eax, eax
    mov  edx, 1
    ret

; Commit only after the caller has validated every field. Arguments:
; RDI=media, ESI=kind, RDX=inline ptr, ECX=inline len, R8=handle, R9=provenance.
clipboard_commit_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    mov  r15d, ecx
    mov  rbx, r8
    mov  rbp, r9
    mov  rdi, r12
    mov  esi, CLIP_MEDIA_MAX
    call clipboard_bounded_len
    test eax, eax
    js   .bad
    mov  [rel clipboard_commit_media_len], eax
    mov  dword [rel clipboard_commit_prov_len], 0
    test rbp, rbp
    jz   .validated
    mov  rdi, rbp
    mov  esi, CLIP_PROVENANCE_MAX
    call clipboard_bounded_len
    test eax, eax
    js   .bad
    test eax, eax
    jz   .bad
    mov  [rel clipboard_commit_prov_len], eax
.validated:
    cmp  r13d, CLIP_KIND_INLINE
    jne  .handle
    cmp  r15d, CLIP_INLINE_MAX
    ja   .bad
    test r14, r14
    jz   .bad
    jmp  .lock
.handle:
    cmp  r13d, CLIP_KIND_HANDLE14
    jne  .bad
    test rbx, rbx
    jz   .bad
    xor  r15d, r15d
.lock:
    call clipboard_lock_acquire
    lea  rdi, [rel clipboard_entry]
    xor  eax, eax
    mov  ecx, CLIP_E_SIZE
    cld
    rep  stosb
    mov  byte [rel clipboard_entry + CLIP_E_KIND], r13b
    mov  byte [rel clipboard_entry + CLIP_E_PRESENT], 1
    mov  [rel clipboard_entry + CLIP_E_INLINE_LEN], r15d
    mov  dword [rel clipboard_entry + CLIP_E_HISTORY], CLIP_HISTORY_NONE
    mov  [rel clipboard_entry + CLIP_E_HANDLE14], rbx
    mov  eax, [rel clipboard_commit_media_len]
    lea  rdi, [rel clipboard_entry + CLIP_E_MEDIA]
    mov  rsi, r12
    mov  ecx, eax
    rep  movsb
    mov  byte [rdi], 0
    test r15d, r15d
    jz   .copy_prov
    lea  rdi, [rel clipboard_entry + CLIP_E_INLINE]
    mov  rsi, r14
    mov  ecx, r15d
    rep  movsb
    mov  byte [rdi], 0
.copy_prov:
    mov  eax, [rel clipboard_commit_prov_len]
    mov  [rel clipboard_entry + CLIP_E_PROV_LEN], eax
    test eax, eax
    jz   .generation
    lea  rdi, [rel clipboard_entry + CLIP_E_PROVENANCE]
    mov  rsi, rbp
    mov  ecx, eax
    rep  movsb
    mov  byte [rdi], 0
.generation:
    inc  qword [rel clipboard_generation]
    mov  rax, [rel clipboard_generation]
    mov  [rel clipboard_entry + CLIP_E_GENERATION], rax
    call clipboard_lock_release
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

clipboard_clear_entry:
    call clipboard_lock_acquire
    lea  rdi, [rel clipboard_entry]
    xor  eax, eax
    mov  ecx, CLIP_E_SIZE
    cld
    rep  stosb
    mov  dword [rel clipboard_entry + CLIP_E_HISTORY], CLIP_HISTORY_NONE
    call clipboard_lock_release
    ret

; ---- bounded reply builder -------------------------------------------------
clipboard_out_reset:
    lea  rax, [rel clipboard_out_buf]
    mov  [rel clipboard_out_cur], rax
    mov  byte [rax], 0
    ret

clipboard_out_puts:                     ; RDI=cstr
    mov  rsi, [rel clipboard_out_cur]
    lea  rdx, [rel clipboard_out_buf + CLIP_OUT_MAX]
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    lea  rcx, [rsi + 1]
    cmp  rcx, rdx
    jae  .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel clipboard_out_cur], rsi
    ret

clipboard_out_putdec:                   ; RDI=u64
    mov  rsi, [rel clipboard_out_cur]
    lea  rax, [rsi + 24]
    lea  rdx, [rel clipboard_out_buf + CLIP_OUT_MAX]
    cmp  rax, rdx
    jae  .done
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel clipboard_out_cur], rsi
.done:
    ret

clipboard_out_kind:
    cmp  al, CLIP_KIND_INLINE
    jne  .handle
    lea  rdi, [rel str_clip_kind_inline]
    jmp  clipboard_out_puts
.handle:
    lea  rdi, [rel str_clip_kind_handle]
    jmp  clipboard_out_puts

; RDI=prefix. Emits metadata only while holding the entry lock.
clipboard_stage_metadata:
    push r12
    mov  r12, rdi
    call clipboard_out_reset
    mov  rdi, r12
    call clipboard_out_puts
    call clipboard_lock_acquire
    cmp  byte [rel clipboard_entry + CLIP_E_PRESENT], 1
    jne  .empty
    lea  rdi, [rel str_clip_media_key]
    call clipboard_out_puts
    lea  rdi, [rel clipboard_entry + CLIP_E_MEDIA]
    call clipboard_out_puts
    lea  rdi, [rel str_clip_kind_key]
    call clipboard_out_puts
    mov  al, [rel clipboard_entry + CLIP_E_KIND]
    call clipboard_out_kind
    lea  rdi, [rel str_clip_bytes_key]
    call clipboard_out_puts
    mov  edi, [rel clipboard_entry + CLIP_E_INLINE_LEN]
    call clipboard_out_putdec
    lea  rdi, [rel str_clip_prov_key]
    call clipboard_out_puts
    cmp  dword [rel clipboard_entry + CLIP_E_PROV_LEN], 0
    je   .no_prov
    lea  rdi, [rel clipboard_entry + CLIP_E_PROVENANCE]
    call clipboard_out_puts
    jmp  .history
.no_prov:
    lea  rdi, [rel str_clip_none]
    call clipboard_out_puts
.history:
    lea  rdi, [rel str_clip_history_key]
    call clipboard_out_puts
    mov  edi, CLIP_HISTORY_MAX
    call clipboard_out_putdec
    lea  rdi, [rel str_clip_generation_key]
    call clipboard_out_puts
    mov  rdi, [rel clipboard_entry + CLIP_E_GENERATION]
    call clipboard_out_putdec
    jmp  .unlock
.empty:
    lea  rdi, [rel str_clip_empty_metadata]
    call clipboard_out_puts
.unlock:
    call clipboard_lock_release
    mov  byte [rel clipboard_out_ready], 1
    pop  r12
    ret

; RDI=requested media. Emits the capability-scoped content/handle.
clipboard_stage_get:
    push rbx
    mov  rbx, rdi
    call clipboard_out_reset
    call clipboard_lock_acquire
    cmp  byte [rel clipboard_entry + CLIP_E_PRESENT], 1
    jne  .empty
    lea  rdi, [rel clipboard_entry + CLIP_E_MEDIA]
    mov  rsi, rbx
    call strcmp
    test eax, eax
    jnz  .mismatch
    lea  rdi, [rel str_clip_get_ok]
    call clipboard_out_puts
    lea  rdi, [rel str_clip_media_key]
    call clipboard_out_puts
    lea  rdi, [rel clipboard_entry + CLIP_E_MEDIA]
    call clipboard_out_puts
    lea  rdi, [rel str_clip_kind_key]
    call clipboard_out_puts
    mov  al, [rel clipboard_entry + CLIP_E_KIND]
    call clipboard_out_kind
    lea  rdi, [rel str_clip_bytes_key]
    call clipboard_out_puts
    mov  edi, [rel clipboard_entry + CLIP_E_INLINE_LEN]
    call clipboard_out_putdec
    cmp  byte [rel clipboard_entry + CLIP_E_KIND], CLIP_KIND_INLINE
    jne  .emit_handle
    lea  rdi, [rel str_clip_data_key]
    call clipboard_out_puts
    lea  rdi, [rel clipboard_entry + CLIP_E_INLINE]
    call clipboard_out_puts
    jmp  .common
.emit_handle:
    lea  rdi, [rel str_clip_handle_key]
    call clipboard_out_puts
    mov  rdi, [rel clipboard_entry + CLIP_E_HANDLE14]
    call clipboard_out_putdec
.common:
    lea  rdi, [rel str_clip_prov_key]
    call clipboard_out_puts
    cmp  dword [rel clipboard_entry + CLIP_E_PROV_LEN], 0
    je   .no_prov
    lea  rdi, [rel clipboard_entry + CLIP_E_PROVENANCE]
    call clipboard_out_puts
    jmp  .gen
.no_prov:
    lea  rdi, [rel str_clip_none]
    call clipboard_out_puts
.gen:
    lea  rdi, [rel str_clip_generation_key]
    call clipboard_out_puts
    mov  rdi, [rel clipboard_entry + CLIP_E_GENERATION]
    call clipboard_out_putdec
    xor  eax, eax
    jmp  .unlock
.empty:
    lea  rdi, [rel str_clip_ref_empty]
    call clipboard_out_puts
    mov  eax, -1
    jmp  .unlock
.mismatch:
    lea  rdi, [rel str_clip_ref_media]
    call clipboard_out_puts
    mov  eax, -1
.unlock:
    push rax
    call clipboard_lock_release
    mov  byte [rel clipboard_out_ready], 1
    pop  rax
    pop  rbx
    ret

clipboard_stage_refusal:                ; RDI=complete safe refusal string
    call clipboard_out_reset
    call clipboard_out_puts
    mov  byte [rel clipboard_out_ready], 1
    ret

; ---- registry handlers ----------------------------------------------------
cmd_verb_clipset:
    call cmd_handler_prologue
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r14, rsi                       ; response
    mov  r12, [rdi + REQ_ARG]
    test r12, r12
    jz   .bad_args
    mov  rdi, r12
    call clipboard_peek_media
    cmp  eax, 1
    je   .secret
    test eax, eax
    js   .bad_media
    mov  rsi, r12
    call clipboard_arg_copy
    test eax, eax
    jnz  .oversize
    lea  r12, [rel clipboard_parse_buf] ; media
    mov  rdi, r12
    call clipboard_split_token
    mov  r13, rax                       ; kind
    cmp  byte [r13], 0
    je   .bad_args
    mov  rdi, r13
    call clipboard_split_token
    mov  r15, rax                       ; payload tail
    cmp  byte [r15], 0
    je   .bad_args
    mov  rdi, r15
    call clipboard_split_provenance
    mov  rbp, rax                       ; optional provenance
    mov  rdi, r12
    call clipboard_media_allowed
    test eax, eax
    jz   .bad_media
    lea  rdi, [rel str_clip_kind_inline]
    mov  rsi, r13
    call strcmp
    test eax, eax
    jz   .inline
    lea  rdi, [rel str_clip_kind_handle]
    mov  rsi, r13
    call strcmp
    test eax, eax
    jz   .handle
    lea  rdi, [rel str_clip_kind_textfield]
    mov  rsi, r13
    call strcmp
    test eax, eax
    jz   .textfield
    jmp  .bad_kind
.inline:
    mov  rdi, r15
    mov  esi, CLIP_INLINE_MAX
    call clipboard_bounded_len
    test eax, eax
    js   .oversize
    mov  ecx, eax
    mov  rdi, r12
    mov  esi, CLIP_KIND_INLINE
    mov  rdx, r15
    xor  r8d, r8d
    mov  r9, rbp
    call clipboard_commit_entry
    test eax, eax
    jnz  .bad_args
    jmp  .stored
.handle:
    mov  rdi, r15
    call clipboard_parse_handle14
    test edx, edx
    jnz  .bad_handle
    mov  r8, rax
    mov  rdi, r12
    mov  esi, CLIP_KIND_HANDLE14
    xor  edx, edx
    xor  ecx, ecx
    mov  r9, rbp
    call clipboard_commit_entry
    test eax, eax
    jnz  .bad_handle
    jmp  .stored
.textfield:
    lea  rdi, [rel str_clip_media_text]
    mov  rsi, r12
    call strcmp
    test eax, eax
    jnz  .bad_media
    mov  rdi, r15
    call clipboard_parse_widget_id
    test edx, edx
    jnz  .bad_widget
    cmp  rax, CLIP_WIDGET_ID_MAX
    ja   .bad_widget
    mov  edi, eax
    mov  rax, [rel clipboard_widget_get]
    test rax, rax
    jz   .bad_widget
    call rax
    test edx, edx
    jnz  .bad_widget
    mov  rdx, rax
    mov  rdi, r12
    mov  esi, CLIP_KIND_INLINE
    mov  r9, rbp
    xor  r8d, r8d
    call clipboard_commit_entry
    test eax, eax
    jnz  .bad_widget
.stored:
    lea  rdi, [rel str_clip_set_ok]
    call clipboard_stage_metadata
    mov  qword [r14 + RSP_CODE], CMDE_OK
    jmp  .out
.secret:
    lea  rdi, [rel str_clip_ref_secret_set]
    jmp  .refuse
.bad_media:
    lea  rdi, [rel str_clip_ref_bad_media_set]
    jmp  .refuse
.bad_kind:
    lea  rdi, [rel str_clip_ref_bad_kind]
    jmp  .refuse
.bad_handle:
    lea  rdi, [rel str_clip_ref_bad_handle]
    jmp  .refuse
.bad_widget:
    lea  rdi, [rel str_clip_ref_bad_widget]
    jmp  .refuse
.oversize:
    lea  rdi, [rel str_clip_ref_oversize]
    jmp  .refuse
.bad_args:
    lea  rdi, [rel str_clip_ref_bad_args_set]
.refuse:
    call clipboard_stage_refusal
    mov  qword [r14 + RSP_CODE], CMDE_BADARG
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

cmd_verb_clipget:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14, rsi
    mov  r12, [rdi + REQ_ARG]
    test r12, r12
    jz   .bad_args
    mov  rdi, r12
    call clipboard_peek_media
    cmp  eax, 1
    je   .secret
    test eax, eax
    js   .bad_media
    mov  rsi, r12
    call clipboard_arg_copy
    test eax, eax
    jnz  .bad_args
    lea  r12, [rel clipboard_parse_buf]
    mov  rdi, r12
    call clipboard_split_token
    mov  r13, rax                       ; optional target mode
    mov  rdi, r12
    call clipboard_media_allowed
    test eax, eax
    jz   .bad_media
    cmp  byte [r13], 0
    jne  .target
    mov  rdi, r12
    call clipboard_stage_get
    test eax, eax
    jnz  .semantic_refusal
    mov  qword [r14 + RSP_CODE], CMDE_OK
    jmp  .out
.target:
    mov  rdi, r13
    call clipboard_split_token
    mov  r15, rax
    lea  rdi, [rel str_clip_kind_textfield]
    mov  rsi, r13
    call strcmp
    test eax, eax
    jnz  .bad_args
    mov  rdi, r15
    call clipboard_parse_widget_id
    test edx, edx
    jnz  .bad_widget
    cmp  rax, CLIP_WIDGET_ID_MAX
    ja   .bad_widget
    mov  ebx, eax
    ; Snapshot only an inline text/plain entry before invoking the GUI setter.
    call clipboard_lock_acquire
    cmp  byte [rel clipboard_entry + CLIP_E_PRESENT], 1
    jne  .unlock_empty
    cmp  byte [rel clipboard_entry + CLIP_E_KIND], CLIP_KIND_INLINE
    jne  .unlock_kind
    lea  rdi, [rel clipboard_entry + CLIP_E_MEDIA]
    lea  rsi, [rel str_clip_media_text]
    call strcmp
    test eax, eax
    jnz  .unlock_media
    lea  rdi, [rel clipboard_entry + CLIP_E_MEDIA]
    mov  rsi, r12
    call strcmp
    test eax, eax
    jnz  .unlock_media
    mov  r13d, [rel clipboard_entry + CLIP_E_INLINE_LEN]
    cmp  r13d, CLIP_TEXTFIELD_VALUE_MAX
    ja   .unlock_widget
    lea  rsi, [rel clipboard_entry + CLIP_E_INLINE]
    lea  rdi, [rel clipboard_widget_tmp]
    mov  ecx, r13d
    cld
    rep  movsb
    mov  byte [rdi], 0
    call clipboard_lock_release
    mov  edi, ebx
    lea  rsi, [rel clipboard_widget_tmp]
    mov  edx, r13d
    mov  rax, [rel clipboard_widget_set]
    test rax, rax
    jz   .bad_widget
    call rax
    test eax, eax
    jnz  .bad_widget
    lea  rdi, [rel str_clip_get_widget_ok]
    call clipboard_stage_metadata
    mov  qword [r14 + RSP_CODE], CMDE_OK
    jmp  .out
.unlock_empty:
    lea  r15, [rel str_clip_ref_empty]
    jmp  .unlock_refuse
.unlock_kind:
    lea  r15, [rel str_clip_ref_kind]
    jmp  .unlock_refuse
.unlock_media:
    lea  r15, [rel str_clip_ref_media]
    jmp  .unlock_refuse
.unlock_widget:
    lea  r15, [rel str_clip_ref_bad_widget]
.unlock_refuse:
    call clipboard_lock_release
    mov  rdi, r15
    jmp  .refuse
.secret:
    lea  rdi, [rel str_clip_ref_secret_get]
    jmp  .refuse
.bad_media:
    lea  rdi, [rel str_clip_ref_bad_media_get]
    jmp  .refuse
.bad_widget:
    lea  rdi, [rel str_clip_ref_bad_widget]
    jmp  .refuse
.bad_args:
    lea  rdi, [rel str_clip_ref_bad_args_get]
.refuse:
    call clipboard_stage_refusal
.semantic_refusal:
    mov  qword [r14 + RSP_CODE], CMDE_BADARG
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

cmd_verb_clipinfo:
    call cmd_handler_prologue
    push r14
    mov  r14, rsi
    mov  rax, [rdi + REQ_ARG]
    test rax, rax
    jz   .ok
    cmp  byte [rax], 0
    jne  .bad
.ok:
    lea  rdi, [rel str_clip_info]
    call clipboard_stage_metadata
    mov  qword [r14 + RSP_CODE], CMDE_OK
    pop  r14
    ret
.bad:
    lea  rdi, [rel str_clip_ref_bad_args_info]
    call clipboard_stage_refusal
    mov  qword [r14 + RSP_CODE], CMDE_BADARG
    pop  r14
    ret

; Raw accepted CLIPSET commands would otherwise be copied verbatim into AUDIT.
; Return a fixed action receipt instead; no clipboard value reaches logs.
clipboard_audit_line:
    mov  rax, rdi
    cmp  dword [rdi], 'CLIP'
    jne  .out
    cmp  dword [rdi + 4], 'SET '
    jne  .out
    lea  rax, [rel str_clip_audit_set]
.out:
    ret

; L6 binds its exact stock-textfield value callbacks after the widget vtable is
; live.  The service retains no GUI symbols and no secret-capable generic hook.
clipboard_bind_textfield:                ; RDI=get, RSI=set
    mov  [rel clipboard_widget_get], rdi
    mov  [rel clipboard_widget_set], rsi
    ret

; ---- boot KAT + declaration -----------------------------------------------
clipboard_kat_dispatch:                 ; EDI=verb id, RSI=arg, RDX=cap
    lea  rax, [rel clipboard_kat_req]
    mov  [rax + REQ_VERB], rdi
    mov  [rax + REQ_CAP], rdx
    mov  qword [rax + REQ_IDEM], 0
    mov  qword [rax + REQ_SEL], 0
    mov  [rax + REQ_ARG], rsi
    mov  rdi, rax
    lea  rsi, [rel clipboard_kat_rsp]
    call command_dispatch
    ret

clipboard_selftest:
    push rbx
    mov  byte [rel clipboard_widget_saved_valid], 0
    mov  rax, [rel clipboard_widget_get]
    test rax, rax
    jz   .fail
    mov  rax, [rel clipboard_widget_set]
    test rax, rax
    jz   .fail
    ; Preserve the pre-KAT field bytes so every later exit can restore them.
    mov  edi, 1
    call [rel clipboard_widget_get]
    test edx, edx
    jnz  .fail
    mov  [rel clipboard_widget_saved_len], ecx
    lea  rdi, [rel clipboard_widget_saved]
    mov  rsi, rax
    cld
    rep  movsb
    mov  byte [rdi], 0
    mov  byte [rel clipboard_widget_saved_valid], 1
    ; Registry metadata proves CLIPGET is slot-20, not public T0.
    mov  edi, [rel clipboard_verb_get]
    call command_verb_cap
    cmp  rax, CMD_AUTH_CAP_CLIPBOARD_READ
    jne  .fail
    lea  rdi, [rel str_verb_clipset]
    xor  esi, esi
    mov  edx, 1
    call command_auth_required_cap
    ; Slot 48 does not fit cmp r64,imm32.  Materialize the exact capability
    ; before comparing so NASM cannot truncate the self-test oracle.
    mov  rdx, CMD_AUTH_CAP_MUTATE
    cmp  rax, rdx
    jne  .fail
    lea  rdi, [rel str_verb_clipinfo]
    xor  esi, esi
    xor  edx, edx
    call command_auth_required_cap
    test rax, rax
    jnz  .fail
    ; Positive inline/provenance path through the one registry dispatch.
    mov  edi, [rel clipboard_verb_set]
    lea  rsi, [rel str_clip_kat_set]
    xor  edx, edx
    call clipboard_kat_dispatch
    test eax, eax
    jnz  .fail
    lea  rdi, [rel clipboard_entry + CLIP_E_INLINE]
    lea  rsi, [rel str_clip_kat_value]
    call strcmp
    test eax, eax
    jnz  .fail
    lea  rdi, [rel clipboard_entry + CLIP_E_PROVENANCE]
    lea  rsi, [rel str_clip_kat_prov]
    call strcmp
    test eax, eax
    jnz  .fail
    mov  rbx, [rel clipboard_generation]
    ; SECRET refusal runs through the handler and cannot advance state.
    mov  edi, [rel clipboard_verb_set]
    lea  rsi, [rel str_clip_kat_secret]
    xor  edx, edx
    call clipboard_kat_dispatch
    cmp  rax, CMDE_BADARG
    jne  .fail
    cmp  [rel clipboard_generation], rbx
    jne  .fail
    lea  rdi, [rel clipboard_entry + CLIP_E_INLINE]
    lea  rsi, [rel str_clip_kat_value]
    call strcmp
    test eax, eax
    jnz  .fail
    ; Handle grammar and slot-14 discriminator are structural, not a magic id.
    mov  edi, [rel clipboard_verb_set]
    lea  rsi, [rel str_clip_kat_handle]
    xor  edx, edx
    call clipboard_kat_dispatch
    test eax, eax
    jnz  .fail
    cmp  byte [rel clipboard_entry + CLIP_E_KIND], CLIP_KIND_HANDLE14
    jne  .fail
    cmp  qword [rel clipboard_entry + CLIP_E_HANDLE14], 14
    jne  .fail
    ; Explicit textfield bridge calls the same value functions as WIDGETGET/SET.
    mov  edi, 1
    lea  rsi, [rel str_clip_kat_widget]
    mov  edx, str_clip_kat_widget.len
    call [rel clipboard_widget_set]
    test eax, eax
    jnz  .fail_restore
    mov  edi, 1
    call [rel clipboard_widget_get]
    test edx, edx
    jnz  .fail_restore
    mov  rdi, rax
    lea  rsi, [rel str_clip_kat_widget]
    call strcmp
    test eax, eax
    jnz  .fail_restore
    xor  ebx, ebx
    jmp  .restore
.fail_restore:
    mov  ebx, 1
.restore:
    cmp  byte [rel clipboard_widget_saved_valid], 1
    jne  .restored
    mov  edi, 1
    lea  rsi, [rel clipboard_widget_saved]
    mov  edx, [rel clipboard_widget_saved_len]
    call [rel clipboard_widget_set]
    test eax, eax
    jz   .restored
    mov  ebx, 1
.restored:
    call clipboard_clear_entry
    mov  qword [rel clipboard_generation], 0  ; KAT state is not user history
    mov  byte [rel clipboard_out_ready], 0
    test ebx, ebx
    jnz  .return
    lea  rdi, [rel str_clip_marker]
    call serial_string
    mov  byte [rel clipboard_m_typed], 1
.return:
    mov  eax, ebx
    pop  rbx
    ret
.fail:
    mov  ebx, 1
    jmp  .restore

clipboard_init:
    mov  byte [rel clipboard_lock], 0
    mov  byte [rel clipboard_out_ready], 0
    mov  byte [rel clipboard_m_typed], 0
    mov  qword [rel clipboard_generation], 0
    call clipboard_clear_entry
    push rbx
    xor  ebx, ebx
    lea  rdi, [rel str_verb_clipset]
    lea  rsi, [rel cmd_verb_clipset]
    xor  edx, edx                       ; destructive cap=0 -> signed generic mutation
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    mov  [rel clipboard_verb_set], eax
    or   ebx, eax
    lea  rdi, [rel str_verb_clipget]
    lea  rsi, [rel cmd_verb_clipget]
    mov  rdx, CMD_AUTH_CAP_CLIPBOARD_READ
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                          ; optional explicit paste mutates a textfield
    call command_register_verb
    mov  [rel clipboard_verb_get], eax
    or   ebx, eax
    lea  rdi, [rel str_verb_clipinfo]
    lea  rsi, [rel cmd_verb_clipinfo]
    xor  edx, edx                       ; bounded metadata-only public T0
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    mov  [rel clipboard_verb_info], eax
    or   ebx, eax
    test ebx, ebx
    js   .fail
    pop  rbx
    call clipboard_selftest
    ret
.fail:
    pop  rbx
    mov  eax, -1
    ret

; ---- data -----------------------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_clipboard_0 0
align 8
clipboard_generation:       dq 0
clipboard_out_cur:          dq 0
clipboard_widget_get:       dq 0
clipboard_widget_set:       dq 0
clipboard_commit_media_len: dd 0
clipboard_commit_prov_len:  dd 0
clipboard_verb_set:         dd -1
clipboard_verb_get:         dd -1
clipboard_verb_info:        dd -1
times 51 db 0                  ; clipboard_lock..clipboard_out_buf moved to WDATA_svc_clipboard_0_bss1: keeps the labels below at their offset mod 64

; Registry names.
str_verb_clipset:  db "CLIPSET",0
str_verb_clipget:  db "CLIPGET",0
str_verb_clipinfo: db "CLIPINFO",0

; Typed vocabulary.
str_clip_media_text:     db "text/plain",0
str_clip_media_octets:   db "application/octet-stream",0
str_clip_media_png:      db "image/png",0
str_clip_media_jpeg:     db "image/jpeg",0
str_clip_media_secret:   db "application/x-paos-secret",0
str_clip_kind_inline:    db "inline",0
str_clip_kind_handle:    db "handle",0
str_clip_kind_textfield: db "textfield",0

; Safe responses: no CLIPSET string includes caller content.
str_clip_set_ok:            db "CLIPSET OK",0
str_clip_get_ok:            db "CLIPGET OK",0
str_clip_get_widget_ok:     db "CLIPGET OK target=textfield",0
str_clip_info:              db "CLIPINFO",0
str_clip_media_key:         db " media_type=",0
str_clip_kind_key:          db " kind=",0
str_clip_bytes_key:         db " bytes=",0
str_clip_data_key:          db " data=",0
str_clip_handle_key:        db " handle=slot14:",0
str_clip_prov_key:          db " provenance=",0
str_clip_history_key:       db " history_reserved=",0
str_clip_generation_key:    db " generation=",0
str_clip_none:              db "none",0
str_clip_empty_metadata:    db " media_type=none kind=empty bytes=0 provenance=none history_reserved=16 generation=0",0
str_clip_ref_secret_set:    db "CLIPSET SECRET REFUSED reason=secret_media mutation=0",0
str_clip_ref_bad_media_set: db "CLIPSET REFUSED reason=unknown_media mutation=0",0
str_clip_ref_bad_kind:      db "CLIPSET REFUSED reason=unknown_kind mutation=0",0
str_clip_ref_bad_handle:    db "CLIPSET REFUSED reason=invalid_slot14_handle mutation=0",0
str_clip_ref_bad_widget:    db "CLIP REFUSED reason=invalid_or_secret_textfield mutation=0",0
str_clip_ref_oversize:      db "CLIPSET REFUSED reason=oversize_inline mutation=0",0
str_clip_ref_bad_args_set:  db "CLIPSET REFUSED reason=bad_args mutation=0",0
str_clip_ref_secret_get:    db "CLIPGET SECRET REFUSED reason=secret_media mutation=0",0
str_clip_ref_bad_media_get: db "CLIPGET REFUSED reason=unknown_media mutation=0",0
str_clip_ref_bad_args_get:  db "CLIPGET REFUSED reason=bad_args mutation=0",0
str_clip_ref_empty:         db "CLIPGET REFUSED reason=empty mutation=0",0
str_clip_ref_media:         db "CLIPGET REFUSED reason=media_mismatch mutation=0",0
str_clip_ref_kind:          db "CLIPGET REFUSED reason=handle_not_text mutation=0",0
str_clip_ref_bad_args_info: db "CLIPINFO REFUSED reason=bad_args mutation=0",0
str_clip_audit_set:         db "CLIPSET [content-redacted]",0

; KAT values are fixed non-secrets and are cleared before the service goes live.
str_clip_kat_value:   db "clip-kat-value",0
str_clip_kat_prov:    db "kat",0
str_clip_kat_set:     db "text/plain inline clip-kat-value provenance=kat",0
str_clip_kat_secret:  db "application/x-paos-secret inline must-not-store",0
str_clip_kat_handle:  db "image/png handle slot14:14 provenance=kat",0
; Exact 32-byte value guards the token_hex(16) widget boundary that escaped
; the earlier short KAT while the metal verifier correctly stayed red.
str_clip_kat_widget:  db "clip-widget-kat-0123456789abcdef",0
.len equ $ - str_clip_kat_widget - 1
%endmacro
WDATA_DEFER WDATA_svc_clipboard_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_svc_clipboard_0_bss1 0
resb 52                 ; keeps clipboard_lock at its WDATA offset mod 64
clipboard_lock:             resb 1
clipboard_out_ready:        resb 1
clipboard_m_typed:          resb 1
alignb 8
clipboard_entry:       resb CLIP_E_SIZE
clipboard_media_peek:  resb (CLIP_MEDIA_MAX + 1)
clipboard_parse_buf:   resb (CLIP_ARG_MAX + 1 + CLIP_PARSE_PAD)
clipboard_widget_tmp:  resb (CLIP_TEXTFIELD_VALUE_MAX + 1)
clipboard_widget_saved: resb (CLIP_TEXTFIELD_VALUE_MAX + 1)
clipboard_widget_saved_len: resd 1
clipboard_widget_saved_valid: resb 1
clipboard_kat_req:     resb REQ_SZ
clipboard_kat_rsp:     resb RSP_SZ
clipboard_out_buf:     resb CLIP_OUT_MAX
%endmacro
WDATA_BSS_DEFER WDATA_svc_clipboard_0_bss1
str_clip_marker: db "[PAOS64] clipboard: typed envelope/auth/secret exclusion KAT PASS [svc.clipboard.typed]",13,10,0
