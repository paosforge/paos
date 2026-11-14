;; MODULE svc/history
;; LAYER 5
;; EXPORTS history_append, history_query, history_ai_ticket_issue, history_reopen_resolve, history_on_lock, history_cfg_load, history_declare, history_set_window_check, hist_cfg_key, hist_key
;; IMPORTS core/heap, core/csprng, core/time, core/lib/mem, core/lib/str, core/lib/sha256, core/lib/hmac_sha256, core/lib/hkdf_sha256, core/lib/aes256_gcm, security/sensitive_classifier, sec/principal, sec/session, svc/command, svc/command_auth, svc/command_audit, boot/nvram_access, boot/serial
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only
; ============================================================================
; svc/history — the owner's activity history, H1 core (RC-history-and-rewind,
; spec v0.60 21.2.10; design HISTORY_STORE_DESIGN 991c30e4, wire ABI r2 + r3).
;
; Native only. There is no verb that reads it, no export of the ring, the key or
; a record: history_query returns bounded rows, and only to the owner's own UI or
; to an AI question the owner asked (single-use ticket). H1 keeps the records in
; RAM (lost at restart; the persisted slice is H2), each sealed with AES-256-GCM
; under H = HKDF(owner key, store_id, "PaOS/history/v1"). H exists only while the
; owner session is unlocked: history_on_lock (session_shell_lock_core) zeroes it,
; and a changed session epoch re-derives it. Records stay sealed across a lock.
;
; history_append refuses, in this order, before any byte of the event is copied:
;   OFF / PAUSED (owner switch), LOCKED (session locked or no owner key),
;   BAD (null pointers), NOT_PRODUCER (producer id is not the record's category),
;   EXCLUDED: the request is not the owner's own (r3 §3), the window is stale,
;   chrome, another principal's or no-history (r3 §1), the focus widget is a
;   secret field or not in that window; CATEGORY_OFF; then the r2 schema (BAD),
;   unowned files and non-http(s) URLs (EXCLUDED). A label that classifies as a
;   secret, card or SSN is blanked and the record marked F_REDACTED. WEB records
;   keep only scheme://host/path: userinfo, query and fragment are never stored.
;
; Settings (HISTCFG, owner only; "on" only from the owner's own console) are
; saved in PaOSHistCfg, a MACed record in the PaOS data/config namespace, the
; gui/kbd_prefs pattern with its own HKDF domain. Off by default.
; ============================================================================

HIST_OK           equ 0
HIST_OFF          equ 1
HIST_PAUSED       equ 2
HIST_LOCKED       equ 3
HIST_EXCLUDED     equ 4
HIST_BAD          equ 5
HIST_FULL         equ 6
HIST_CATEGORY_OFF equ 7
HIST_RATE         equ 8
HIST_DENIED       equ 9
HIST_NOT_PRODUCER equ 10
HIST_NCODES       equ 11

; record v1 (128 B, r2 §1)
HR_VER    equ 0
HR_CAT    equ 1
HR_ACT    equ 2
HR_FLAGS  equ 3
HR_TWALL  equ 4
HR_TMONO  equ 12
HR_APP    equ 20
HR_KIND   equ 24
HR_RSV    equ 25
HR_OREF   equ 28
HR_LABEL  equ 60
HR_REOPEN equ 108
HR_AUX    equ 124
HR_SIZE   equ 128
HR_LABEL_MAX equ 48
HF_KEEP_QUERY equ 0x01
HF_REDACTED   equ 0x80

HC_DOCUMENTS equ 1
HC_WEB       equ 2
HC_APPS      equ 3
HC_AI        equ 4
HC_SETTINGS  equ 5
HC_SYSTEM    equ 6
HC_ALL_MASK  equ 0x3F
HK_FILE      equ 1
HK_WEB       equ 2

; ctx16 (r2 §4, r3 §1)
HX_WINDOW equ 0                         ; slot | window generation << 8 (wmx_window_id), 0 = none
HX_WIDGET equ 4                         ; widget id + 1, 0 = none
HX_REQ    equ 8                         ; the live dispatch request, 0 = native-internal work

; ring: seq u64 (also the AAD), ciphertext 128, tag 16
HIST_CAP       equ 1024                 ; power of two
HE_SEQ         equ 0
HE_CT          equ 8
HE_TAG         equ 136
HE_SIZE        equ 152
HIST_URL_MAX   equ 2048

; query (r2 §7)
HQ_VER     equ 0
HQ_FLAGS   equ 1
HQ_CATS    equ 2
HQ_RSV     equ 3
HQ_MAXROWS equ 4
HQ_FROM    equ 8
HQ_TO      equ 16
HQ_APP     equ 24
HQ_TEXTLEN equ 28
HQ_TEXT    equ 32
HQ_TEXT_MAX equ 32
HQC_REQUESTER equ 0
HQC_RSV       equ 4
HQC_TICKET    equ 8
HQC_RSV2      equ 24
HQR_OWNER_UI    equ 1
HQR_AI_QUESTION equ 2
HQ_ROWS_MAX  equ 50
HQ_ROW_SIZE  equ 80
HQ_OUT_MIN   equ 16 + HQ_ROWS_MAX * HQ_ROW_SIZE   ; 4016
HQ_RATE_MAX  equ 60                     ; queries per minute, every requester together
HIST_TICKET_MS   equ 120000
HIST_TICKET_USES equ 3

; settings record PaOSHistCfg (64 B)
HCF_MAGIC     equ 'PHSC'
HCF_REC_SIZE  equ 64
HCF_EFI_ATTRS equ 7
HCF_NOT_FOUND equ 0x800000000000000e
HCF_BUFFER_TOO_SMALL equ 0x8000000000000005
HCF_ST_UNLOADED equ 0
HCF_ST_RAMONLY  equ 1
HCF_ST_NOKEY    equ 2
HCF_ST_NVRAM    equ 3
HCF_ST_POISONED equ 4
HCF_RETENTION_DEFAULT equ 90
HCF_RETENTION_MAX     equ 365

; ---------------------------------------------------------------------------
; history_append(RDI = record128, ESI = producer_id, RDX = ctx16, RCX = url,
;   R8D = url_len) -> EAX = HIST_*. Native producers only (r2 §4). Preserves
;   RBX, RBP, R12-R15.
; ---------------------------------------------------------------------------
history_append:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    mov  r15, rcx
    mov  ebx, r8d
    cmp  byte [rel hist_enabled], 1
    jne  .off
    cmp  byte [rel hist_paused], 0
    jne  .paused
    call hist_key_ensure                ; refuses while the session is locked
    test eax, eax
    jnz  .locked
    test r12, r12
    jz   .bad
    test r14, r14
    jz   .bad
    ; the producer table is the identity on 1..6: each producer owns one category
    movzx eax, byte [r12 + HR_CAT]
    cmp  eax, r13d
    jne  .not_producer
    dec  eax
    cmp  eax, HC_SYSTEM
    jae  .not_producer
    mov  rdi, [r14 + HX_REQ]
    call hist_request_owner
    test eax, eax
    jz   .excluded
    mov  edi, [r14 + HX_WINDOW]
    movzx esi, byte [r12 + HR_CAT]
    mov  edx, [r14 + HX_WIDGET]
    call hist_window_ok
    test eax, eax
    jnz  .excluded
    movzx ecx, byte [r12 + HR_CAT]
    dec  ecx
    movzx eax, byte [rel hist_cat_mask]
    bt   eax, ecx
    jnc  .category_off
    mov  rdi, r12
    mov  rsi, r15
    mov  edx, ebx
    call hist_schema_ok                 ; -> EAX HIST_OK / HIST_BAD / HIST_EXCLUDED
    test eax, eax
    jnz  .code
    mov  rdi, [rel hist_ring]
    test rdi, rdi
    jnz  .ring
    mov  edi, HIST_CAP * HE_SIZE
    call kmalloc
    test rax, rax
    jz   .full
    mov  [rel hist_ring], rax
    mov  rdi, rax
    xor  esi, esi
    mov  edx, HIST_CAP * HE_SIZE
    call memset                         ; kmalloc does not zero
.ring:
    ; copy, then let the store fill what it owns
    lea  rdi, [rel hist_stage]
    mov  rsi, r12
    mov  edx, HR_SIZE
    call memcpy
    cmp  byte [rel hist_stage + HR_KIND], HK_WEB
    jne  .label
    mov  rdi, r15
    mov  esi, ebx
    call hist_web_fill                  ; -> EAX HIST_OK / BAD / EXCLUDED
    test eax, eax
    jnz  .wipe_code
.label:
    and  byte [rel hist_stage + HR_FLAGS], ~HF_KEEP_QUERY   ; the RC keep-list is empty
    call hist_label_redact
    call time_wall_utc_now_s            ; NTP provenance only, else 0 ("time unknown")
    imul rax, rax, 1000
    mov  [rel hist_stage + HR_TWALL], rax
    call time_monotonic_now_us
    xor  edx, edx
    mov  ecx, 1000
    div  rcx
    mov  [rel hist_stage + HR_TMONO], rax
    call hist_seal_stage
    test eax, eax
    jnz  .wipe_full
    xor  eax, eax
    jmp  .wipe_code
.wipe_full:
    mov  eax, HIST_FULL
.wipe_code:
    push rax
    lea  rdi, [rel hist_stage]
    xor  esi, esi
    mov  edx, HR_SIZE
    call memset
    pop  rax
    jmp  .code
.off:
    mov  eax, HIST_OFF
    jmp  .code
.paused:
    mov  eax, HIST_PAUSED
    jmp  .code
.locked:
    mov  eax, HIST_LOCKED
    jmp  .code
.bad:
    mov  eax, HIST_BAD
    jmp  .code
.not_producer:
    mov  eax, HIST_NOT_PRODUCER
    jmp  .code
.excluded:
    mov  eax, HIST_EXCLUDED
    jmp  .code
.category_off:
    mov  eax, HIST_CATEGORY_OFF
    jmp  .code
.full:
    mov  eax, HIST_FULL
.code:
    mov  [rsp], eax
    lea  rcx, [rel hist_counts]
    add  qword [rcx + rax*8], 1
    cmp  eax, HIST_EXCLUDED
    je   .audit
    cmp  eax, HIST_BAD
    je   .audit
    cmp  eax, HIST_NOT_PRODUCER
    jne  .out
.audit:
    ; a refusal names no verified principal: it folds into the public counters
    mov  edi, eax
    shl  edi, 16
    or   edi, AUDIT_SEC_C_HISTORY | (AUDIT_SEC_V_REFUSED << 8) | (AUDIT_SEC_R_HISTORY_APPEND << 16)
    xor  esi, esi
    mov  edx, r13d
    call audit_sec_event
.out:
    mov  eax, [rsp]
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; hist_request_owner(RDI = req or 0) -> EAX 1 = the event is the owner's own
; (r3 §3). With a request: it is the one being dispatched (its source and
; principal equal the dispatcher's copies), its principal is OWNER, and the
; owner's authority is proven for its source (console: the bound local owner;
; UDP/serial/AI hook/SSH: that request's own AUTH1 owner ticket or owner SSH
; key). Without one: native work outside any dispatch, unlocked, owner bound.
; Injected input and every other source refuse. Clobbers caller-saved.
hist_request_owner:
    cmp  byte [rel session_injected_input], 0
    jne  .no
    test rdi, rdi
    jz   .native
    cmp  byte [rel cmd_in_dispatch], 1
    jne  .no
    mov  rax, [rdi + REQ_SOURCE]
    cmp  rax, [rel cmd_dispatch_last_source]
    jne  .no
    mov  rcx, [rdi + REQ_PRINCIPAL]
    cmp  rcx, [rel cmd_dispatch_last_principal]
    jne  .no
    cmp  rcx, CMD_PRINCIPAL_OWNER
    jne  .no
    cmp  rax, CMD_SOURCE_CONSOLE
    je   .console
    cmp  rax, CMD_SOURCE_UDP
    je   .remote
    cmp  rax, CMD_SOURCE_SERIAL
    je   .remote
    cmp  rax, CMD_SOURCE_AIHOOK
    je   .remote
    cmp  rax, CMD_SOURCE_SSH
    jne  .no
.remote:
    call command_auth_owner_request     ; 1 own AUTH1 owner ticket, 2 owner SSH key
    test eax, eax
    jz   .no
    jmp  .yes
.console:
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .no
    jmp  .yes
.native:
    ; inside a dispatch the producer must name the request it serves
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .no
    cmp  byte [rel command_auth_remote_active], 0
    jne  .no
    cmp  qword [rel session_bound_pid], PRIN_OWNER
    jne  .no
    cmp  qword [rel prin_active_pid], PRIN_OWNER
    jne  .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hist_window_ok(EDI = window_id, ESI = category, EDX = widget id + 1 or 0)
; -> EAX 0 ok, -1 = EXCLUDED. No window is accepted for DOCUMENTS, SETTINGS and
; SYSTEM only, and then with no widget. A named window and its focus widget are
; judged by the window registry's own check (gui/window_mgmt wmx_history_target:
; current generation, shown or minimized, the owner's, not marked no-history; a
; widget that is live, in that window and not a secret field), registered once
; through history_set_window_check. Until it is registered every named window
; refuses. Clobbers caller-saved.
hist_window_ok:
    test edi, edi
    jnz  .window
    test edx, edx
    jnz  .no                            ; a widget needs its window
    cmp  esi, HC_DOCUMENTS
    je   .yes
    cmp  esi, HC_SETTINGS
    je   .yes
    cmp  esi, HC_SYSTEM
    jne  .no
.yes:
    xor  eax, eax
    ret
.window:
    mov  rax, [rel hist_window_check]
    test rax, rax
    jz   .no
    mov  esi, edx
    call rax                            ; EDI window id, ESI widget id + 1 -> EAX slot or -1
    test eax, eax
    js   .no
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; history_set_window_check(RDI = fn) -> EAX 0 / -1. The window registry
; (gui/window_mgmt, wmx_declare) names its check once at boot; a second
; registration or a null pointer is refused and changes nothing.
history_set_window_check:
    test rdi, rdi
    jz   .no
    cmp  qword [rel hist_window_check], 0
    jne  .no
    mov  [rel hist_window_check], rdi
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; hist_schema_ok(RDI = record, RSI = url, EDX = url_len) -> EAX HIST_OK,
; HIST_BAD (r2 §1-3, §5, §6 input rules) or HIST_EXCLUDED (an unowned volume's
; file). Nothing is repaired. Clobbers caller-saved.
hist_schema_ok:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    cmp  byte [rbx + HR_VER], 1
    jne  .bad
    ; category / kind / action: one rule row must admit all three
    movzx eax, byte [rbx + HR_CAT]
    movzx edx, byte [rbx + HR_KIND]
    movzx ecx, byte [rbx + HR_ACT]
    cmp  ecx, 31
    ja   .bad
    lea  rsi, [rel hist_rules]
    mov  edi, HIST_RULES
.rule:
    cmp  [rsi], al
    jne  .next_rule
    cmp  [rsi + 1], dl
    jne  .next_rule
    mov  r8d, [rsi + 4]
    bt   r8d, ecx
    jc   .rule_ok
.next_rule:
    add  rsi, 8
    dec  edi
    jnz  .rule
    jmp  .bad
.rule_ok:
    ; producer flags: only F_KEEP_QUERY, and only on WEB
    movzx ecx, byte [rbx + HR_FLAGS]
    test ecx, ~HF_KEEP_QUERY & 0xFF
    jnz  .bad
    test ecx, ecx
    jz   .flags_ok
    cmp  edx, HK_WEB
    jne  .bad
.flags_ok:
    cmp  qword [rbx + HR_TWALL], 0       ; the store stamps both times
    jne  .bad
    cmp  qword [rbx + HR_TMONO], 0
    jne  .bad
    cmp  byte [rbx + HR_RSV], 0
    jne  .bad
    cmp  word [rbx + HR_RSV + 1], 0
    jne  .bad
    cmp  dword [rbx + HR_AUX], 0
    jne  .bad
    cmp  eax, HC_APPS
    jne  .app_ok
    cmp  dword [rbx + HR_APP], 0
    je   .bad
.app_ok:
    ; object_ref: every byte past the kind's fields is zero
    lea  rsi, [rel hist_oref_used]
    movzx ecx, byte [rsi + rdx]
.oref_zero:
    cmp  ecx, 32
    jae  .oref_done
    cmp  byte [rbx + HR_OREF + rcx], 0
    jne  .bad
    inc  ecx
    jmp  .oref_zero
.oref_done:
    cmp  edx, HK_WEB
    je   .web
    test r12, r12                       ; only WEB carries a URL
    jnz  .bad
    test r13d, r13d
    jnz  .bad
    lea  rdi, [rbx + HR_LABEL]
    mov  esi, HR_LABEL_MAX
    call hist_text_ok
    test eax, eax
    js   .bad
    movzx edx, byte [rbx + HR_KIND]
    cmp  edx, HK_FILE
    jne  .ok
    cmp  qword [rbx + HR_OREF], 0       ; vol_id 0: not a PaOS-owned volume
    je   .excluded
    jmp  .ok
.web:
    ; the store fills the label and the reference; the producer's are zero
    xor  ecx, ecx
.web_label:
    cmp  byte [rbx + HR_LABEL + rcx], 0
    jne  .bad
    inc  ecx
    cmp  ecx, HR_LABEL_MAX
    jb   .web_label
    test r12, r12
    jz   .bad
    test r13d, r13d
    jz   .bad
    cmp  r13d, HIST_URL_MAX
    ja   .bad
.ok:
    xor  eax, eax
    jmp  .out
.excluded:
    mov  eax, HIST_EXCLUDED
    jmp  .out
.bad:
    mov  eax, HIST_BAD
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; hist_text_ok(RDI = text, ESI = field size) -> EAX = length up to the first
; NUL, or -1. Strict UTF-8 (no overlong, surrogate or > U+10FFFF), no C0/C1
; control or DEL, no U+2028/2029, no bidi control (U+200E/200F, 202A-202E,
; 2066-2069); a sequence never crosses the field end; after the first NUL every
; byte is zero. Clobbers RAX, RCX, RDX, R8, R9.
hist_text_ok:
    xor  ecx, ecx
.next:
    cmp  ecx, esi
    jae  .len
    movzx eax, byte [rdi + rcx]
    test eax, eax
    jz   .tail
    cmp  eax, 0x80
    jae  .multi
    cmp  eax, 0x20
    jb   .bad
    cmp  eax, 0x7F
    je   .bad
    inc  ecx
    jmp  .next
.multi:
    cmp  eax, 0xC2
    jb   .bad
    cmp  eax, 0xE0
    jb   .two
    cmp  eax, 0xF0
    jb   .three
    cmp  eax, 0xF4
    ja   .bad
    ; four bytes: F0 needs 90..BF, F4 needs 80..8F
    lea  edx, [ecx + 4]
    cmp  edx, esi
    ja   .bad
    movzx r8d, byte [rdi + rcx + 1]
    cmp  eax, 0xF0
    jne  .f4
    cmp  r8d, 0x90
    jb   .bad
.f4:
    cmp  eax, 0xF4
    jne  .four_cont
    cmp  r8d, 0x8F
    ja   .bad
.four_cont:
    lea  r9d, [ecx + 1]
.four_loop:
    movzx r8d, byte [rdi + r9]
    and  r8d, 0xC0
    cmp  r8d, 0x80
    jne  .bad
    inc  r9d
    cmp  r9d, edx                       ; edx = ecx + 4
    jb   .four_loop
    add  ecx, 4
    jmp  .next
.two:
    lea  edx, [ecx + 2]
    cmp  edx, esi
    ja   .bad
    movzx r8d, byte [rdi + rcx + 1]
    mov  r9d, r8d
    and  r9d, 0xC0
    cmp  r9d, 0x80
    jne  .bad
    cmp  eax, 0xC2                      ; C2 80..9F: the C1 controls
    jne  .two_ok
    cmp  r8d, 0xA0
    jb   .bad
.two_ok:
    add  ecx, 2
    jmp  .next
.three:
    lea  edx, [ecx + 3]
    cmp  edx, esi
    ja   .bad
    movzx r8d, byte [rdi + rcx + 1]
    movzx r9d, byte [rdi + rcx + 2]
    mov  edx, r8d
    and  edx, 0xC0
    cmp  edx, 0x80
    jne  .bad
    mov  edx, r9d
    and  edx, 0xC0
    cmp  edx, 0x80
    jne  .bad
    cmp  eax, 0xE0                      ; overlong
    jne  .not_e0
    cmp  r8d, 0xA0
    jb   .bad
.not_e0:
    cmp  eax, 0xED                      ; surrogates
    jne  .not_ed
    cmp  r8d, 0xA0
    jae  .bad
.not_ed:
    cmp  eax, 0xE2
    jne  .three_ok
    cmp  r8d, 0x80                      ; U+2000..203F
    jne  .e2_81
    cmp  r9d, 0x8E                      ; U+200E, U+200F
    je   .bad
    cmp  r9d, 0x8F
    je   .bad
    cmp  r9d, 0xA8                      ; U+2028..202E
    jb   .three_ok
    cmp  r9d, 0xAE
    jbe  .bad
    jmp  .three_ok
.e2_81:
    cmp  r8d, 0x81                      ; U+2066..2069
    jne  .three_ok
    cmp  r9d, 0xA6
    jb   .three_ok
    cmp  r9d, 0xA9
    jbe  .bad
.three_ok:
    add  ecx, 3
    jmp  .next
.tail:
    mov  eax, ecx
.zero:
    cmp  ecx, esi
    jae  .out
    cmp  byte [rdi + rcx], 0
    jne  .bad
    inc  ecx
    jmp  .zero
.len:
    mov  eax, ecx
.out:
    ret
.bad:
    mov  eax, -1
    ret

; hist_web_fill(RDI = url, ESI = len 1..2048) -> EAX HIST_OK, HIST_BAD or
; HIST_EXCLUDED; fills hist_stage's label and object_ref (r2 §6). Only
; printable ASCII; only http and https; the userinfo, query and fragment are
; dropped (the RC keep-list is empty), the scheme and host lower-cased. The
; label is host + path (first 48 bytes), the reference SHA-256 of
; "scheme://host/path". The URL is never kept: the scratch is zeroed on every
; exit. Clobbers caller-saved.
hist_web_fill:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12d, esi
    xor  ecx, ecx
.ascii:
    movzx eax, byte [rbx + rcx]
    cmp  eax, 0x21
    jb   .bad
    cmp  eax, 0x7E
    ja   .bad
    inc  ecx
    cmp  ecx, r12d
    jb   .ascii
    ; scheme
    lea  r14, [rel hist_url_buf]
    xor  r13d, r13d                     ; output length
    mov  r15d, 7                        ; "http://"
    lea  rsi, [rel str_hist_https]
    cmp  r12d, 8
    jb   .try_http
    mov  edx, 8
    call .prefix
    jnc  .https
.try_http:
    lea  rsi, [rel str_hist_http]
    mov  edx, 7
    cmp  r12d, 7
    jb   .excluded
    call .prefix
    jc   .excluded
    jmp  .scheme_out
.https:
    mov  r15d, 8
.scheme_out:
    ; rsi = canonical lower-case scheme text, r15d its length
    xor  ecx, ecx
.copy_scheme:
    mov  al, [rsi + rcx]
    mov  [r14 + rcx], al
    inc  ecx
    cmp  ecx, r15d
    jb   .copy_scheme
    mov  r13d, r15d
    ; authority: [r15, end of authority)
    mov  ecx, r15d
.auth_end:
    cmp  ecx, r12d
    jae  .auth_found
    movzx eax, byte [rbx + rcx]
    cmp  al, '/'
    je   .auth_found
    cmp  al, '?'
    je   .auth_found
    cmp  al, '#'
    je   .auth_found
    inc  ecx
    jmp  .auth_end
.auth_found:
    mov  r8d, ecx                       ; end of authority
    mov  r9d, r15d                      ; host start: after the last '@'
    mov  ecx, r15d
.at:
    cmp  ecx, r8d
    jae  .host
    cmp  byte [rbx + rcx], '@'
    jne  .at_next
    lea  r9d, [ecx + 1]
.at_next:
    inc  ecx
    jmp  .at
.host:
    cmp  r9d, r8d
    jae  .bad                           ; empty host
    mov  r10d, r13d                     ; label starts at the host
    mov  ecx, r9d
.copy_host:
    cmp  ecx, r8d
    jae  .path
    movzx eax, byte [rbx + rcx]
    cmp  al, 'A'
    jb   .host_byte
    cmp  al, 'Z'
    ja   .host_byte
    or   al, 0x20
.host_byte:
    mov  [r14 + r13], al
    inc  r13d
    inc  ecx
    jmp  .copy_host
.path:
    cmp  ecx, r12d
    jae  .built
    movzx eax, byte [rbx + rcx]
    cmp  al, '?'
    je   .built
    cmp  al, '#'
    je   .built
    mov  [r14 + r13], al
    inc  r13d
    inc  ecx
    jmp  .path
.built:
    ; label = host + path, first 48 bytes (ASCII: every byte is a boundary)
    lea  rdi, [rel hist_stage + HR_LABEL]
    lea  rsi, [r14 + r10]
    mov  edx, r13d
    sub  edx, r10d
    cmp  edx, HR_LABEL_MAX
    jbe  .label_len
    mov  edx, HR_LABEL_MAX
.label_len:
    call memcpy
    lea  rdi, [rel hist_stage + HR_OREF]
    mov  rsi, r14
    mov  edx, r13d
    call sha256_hash
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.excluded:
    mov  eax, HIST_EXCLUDED
    jmp  .out
.bad:
    mov  eax, HIST_BAD
.out:
    push rax
    lea  rdi, [rel hist_url_buf]
    xor  esi, esi
    mov  edx, HIST_URL_MAX
    call memset
    pop  rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
; .prefix: CF=0 when the URL starts with the lower-case text RSI (EDX bytes),
; ASCII case-folded. Clobbers RAX, RCX.
.prefix:
    xor  ecx, ecx
.prefix_byte:
    movzx eax, byte [rbx + rcx]
    cmp  al, 'A'
    jb   .prefix_cmp
    cmp  al, 'Z'
    ja   .prefix_cmp
    or   al, 0x20
.prefix_cmp:
    cmp  al, [rsi + rcx]
    jne  .prefix_no
    inc  ecx
    cmp  ecx, edx
    jb   .prefix_byte
    clc
    ret
.prefix_no:
    stc
    ret

; hist_label_redact: run the store's own classifier over hist_stage's label; a
; secret, card number or SSN (or a classifier that cannot finish) blanks the
; label and sets F_REDACTED. The event itself is kept. Clobbers caller-saved.
hist_label_redact:
    lea  rdi, [rel hist_stage + HR_LABEL]
    xor  esi, esi
.len:
    cmp  esi, HR_LABEL_MAX
    jae  .classify
    cmp  byte [rdi + rsi], 0
    je   .classify
    inc  esi
    jmp  .len
.classify:
    test esi, esi
    jz   .out
    lea  rdx, [rel hist_spans]
    mov  ecx, HIST_SPANS
    xor  r8d, r8d
    xor  r9d, r9d
    call sensitive_classify
    test eax, eax
    jnz  .redact                        ; bounds/malformed/too many: fail closed
    lea  rsi, [rel hist_spans]
.span:
    test ecx, ecx
    jz   .out
    movzx eax, word [rsi + 8]
    cmp  eax, SC_SECRET
    je   .redact
    cmp  eax, SC_CARD
    je   .redact
    cmp  eax, SC_SSN
    je   .redact
    add  rsi, SC_SPAN_SIZE
    dec  ecx
    jmp  .span
.redact:
    lea  rdi, [rel hist_stage + HR_LABEL]
    xor  esi, esi
    mov  edx, HR_LABEL_MAX
    call memset
    or   byte [rel hist_stage + HR_FLAGS], HF_REDACTED
.out:
    lea  rdi, [rel hist_spans]
    xor  esi, esi
    mov  edx, HIST_SPANS * SC_SPAN_SIZE
    jmp  memset

; hist_seal_stage -> EAX 0 / -1: seal hist_stage into the next ring entry
; under H. The 96-bit nonce is the entry's sequence number (never reused under
; one H: the sequence only grows, and a cleared store rotates store_id) and
; the sequence is the AAD, so an entry cannot be moved to another slot.
hist_seal_stage:
    mov  rax, [rel hist_seq]
    inc  rax
    jz   .no                            ; 2^64 records: never wrap a nonce
    mov  [rel hist_seq], rax
    mov  rdx, rax
    and  edx, HIST_CAP - 1
    imul rdx, rdx, HE_SIZE
    add  rdx, [rel hist_ring]
    mov  [rdx + HE_SEQ], rax
    mov  rdi, rdx
    lea  rsi, [rel hist_stage]
    lea  rcx, [rdx + HE_CT]
    lea  r8, [rdx + HE_TAG]
    mov  r9, rax
    jmp  hist_aead_seal
.no:
    mov  eax, -1
    ret

; hist_aead_seal / hist_aead_open(RDI = entry (its seq is the AAD), RSI = in,
; RCX = out, R8 = tag, R9 = seq) -> EAX aes256_gcm status.
hist_aead_seal:
    call hist_aead_prep
    lea  rdi, [rel hist_aead]
    jmp  aes256_gcm_seal
hist_aead_open:
    call hist_aead_prep
    lea  rdi, [rel hist_aead]
    jmp  aes256_gcm_open
hist_aead_prep:
    mov  [rel hist_nonce], r9
    mov  dword [rel hist_nonce + 8], 'HIS1'
    lea  rax, [rel hist_key]
    mov  [rel hist_aead + AEAD_KEY], rax
    lea  rax, [rel hist_nonce]
    mov  [rel hist_aead + AEAD_NONCE], rax
    mov  [rel hist_aead + AEAD_AAD], rdi
    mov  qword [rel hist_aead + AEAD_AAD_LEN], 8
    mov  [rel hist_aead + AEAD_INPUT], rsi
    mov  qword [rel hist_aead + AEAD_INPUT_LEN], HR_SIZE
    mov  [rel hist_aead + AEAD_OUTPUT], rcx
    mov  [rel hist_aead + AEAD_TAG], r8
    ret

; hist_key_ensure -> EAX 0 = H is ready for this unlocked owner session, -1.
; H is derived from the owner key principal_credential hands out only while the
; owner is signed in; a changed session epoch (a lock this module missed)
; discards it first.
hist_key_ensure:
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .no
    cmp  byte [rel hist_key_ready], 1
    jne  .derive
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel hist_key_epoch]
    je   .ok
.derive:
    call hist_key_wipe
    cmp  byte [rel hist_store_id_ready], 1
    je   .have_id
    lea  rdi, [rel hist_store_id]
    mov  esi, 16
    call csprng_generate
    test eax, eax
    jnz  .no
    mov  byte [rel hist_store_id_ready], 1
.have_id:
    mov  edi, PRIN_OWNER
    call principal_credential
    test rax, rax
    jz   .no
    cmp  edx, 32
    jne  .no
    mov  rdi, rax
    mov  esi, 32
    lea  rdx, [rel hist_store_id]
    mov  ecx, 16
    lea  r8, [rel hist_key_info]
    mov  r9d, hist_key_info.len
    sub  rsp, 24
    lea  rax, [rel hist_key]
    mov  [rsp], rax
    mov  qword [rsp + 8], 32
    call hkdf_sha256_derive
    add  rsp, 24
    test eax, eax
    jnz  .no
    mov  rax, [rel session_authority_epoch]
    mov  [rel hist_key_epoch], rax
    mov  al, [rel prin_data_wrap_ready]
    mov  [rel hist_key_kind], al        ; 1 = the stable DATA key, 0 = the KEK (RAM only: fine)
    mov  byte [rel hist_key_ready], 1
.ok:
    xor  eax, eax
    ret
.no:
    call hist_key_wipe
    mov  eax, -1
    ret

; hist_key_wipe: H, the AI ticket and the plaintext stage are gone. Clobbers
; RAX, RCX, RDX, RSI, RDI.
hist_key_wipe:
    mov  byte [rel hist_key_ready], 0
    lea  rdi, [rel hist_key]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  byte [rel hist_ticket_valid], 0
    lea  rdi, [rel hist_ai_ticket]
    xor  esi, esi
    mov  edx, 16
    call memset
    lea  rdi, [rel hist_stage]
    xor  esi, esi
    mov  edx, HR_SIZE
    jmp  memset

; history_on_lock — session_shell_lock_core, right after principal_clear_bound:
; no byte of H, of the AI ticket or of a plaintext record survives a lock.
; Preserves every register.
history_on_lock:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    call hist_key_wipe
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; hist_owner_local -> EAX 1 when the owner's own local UI asks: no dispatch, no
; remote frame, no injected input, and the bound local session is the owner.
hist_owner_local:
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .no
    cmp  byte [rel command_auth_remote_active], 0
    jne  .no
    cmp  byte [rel session_injected_input], 0
    jne  .no
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hist_now_ms -> RAX = boot milliseconds (0 = uncalibrated). Clobbers RCX,
; RDX, R8.
hist_now_ms:
    call time_monotonic_now_us
    xor  edx, edx
    mov  ecx, 1000
    div  rcx
    ret

; ---------------------------------------------------------------------------
; history_ai_ticket_issue(RDI = out16) -> EAX 0 / -1. The native AI key path,
; when the owner asks a question at the machine: one ticket, 120 s, at most 3
; queries, gone at lock. A new ticket replaces the old one.
; ---------------------------------------------------------------------------
history_ai_ticket_issue:
    push rbx
    mov  rbx, rdi
    test rdi, rdi
    jz   .no
    cmp  byte [rel hist_enabled], 1
    jne  .no
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .no
    call hist_owner_local
    test eax, eax
    jz   .no
    call hist_now_ms
    test rax, rax
    jz   .no                            ; no clock, no expiry: no ticket
    add  rax, HIST_TICKET_MS
    mov  [rel hist_ticket_expiry], rax
    mov  byte [rel hist_ticket_valid], 0
    lea  rdi, [rel hist_ai_ticket]
    mov  esi, 16
    call csprng_generate
    test eax, eax
    jnz  .no
    mov  rax, [rel session_authority_epoch]
    mov  [rel hist_ticket_epoch], rax
    mov  byte [rel hist_ticket_uses], 0
    mov  byte [rel hist_ticket_valid], 1
    mov  rdi, rbx
    lea  rsi, [rel hist_ai_ticket]
    mov  edx, 16
    call memcpy
    xor  eax, eax
    pop  rbx
    ret
.no:
    mov  eax, -1
    pop  rbx
    ret

; hist_ticket_take(RDI = ticket16) -> EAX 1 = a live ticket of this session,
; one use consumed; 0 = DENIED. The comparison runs over all 16 bytes.
hist_ticket_take:
    cmp  byte [rel hist_ticket_valid], 1
    jne  .no
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel hist_ticket_epoch]
    jne  .no
    cmp  byte [rel hist_ticket_uses], HIST_TICKET_USES
    jae  .no
    push rdi
    call hist_now_ms
    pop  rdi
    test rax, rax
    jz   .no
    cmp  rax, [rel hist_ticket_expiry]
    jae  .no
    lea  rsi, [rel hist_ai_ticket]
    mov  rax, [rdi]
    xor  rax, [rsi]
    mov  rcx, [rdi + 8]
    xor  rcx, [rsi + 8]
    or   rax, rcx
    jnz  .no
    inc  byte [rel hist_ticket_uses]
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; history_query(RDI = query64, RSI = qctx32, RDX = out, ECX = out_cap >= 4016)
;   -> EAX = status (r2 §7), also in the out header when out is usable. Every
;   call, refused or not, writes one AUDIT_SEC_C_HISTORY Guardian event.
;   Preserves RBX, RBP, R12-R15.
; ---------------------------------------------------------------------------
history_query:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  dword [rsp + 8], 0             ; rows
    mov  dword [rsp + 12], 0            ; requester
    test rdx, rdx
    jz   .bad_noout
    cmp  ecx, HQ_OUT_MIN
    jb   .bad_noout
    mov  rdi, rdx
    xor  esi, esi
    mov  edx, HQ_OUT_MIN
    call memset
    test r12, r12
    jz   .bad
    test r13, r13
    jz   .bad
    mov  eax, [r13 + HQC_REQUESTER]
    mov  [rsp + 12], eax
    cmp  byte [rel hist_enabled], 1
    jne  .off
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .locked
    call hist_query_valid
    test eax, eax
    jz   .bad
    ; rate: every requester together, before any credential is looked at
    call hist_now_ms
    mov  rcx, rax
    sub  rcx, [rel hist_rate_start]
    cmp  rcx, 60000
    jb   .window
    mov  [rel hist_rate_start], rax
    mov  dword [rel hist_rate_count], 0
.window:
    cmp  dword [rel hist_rate_count], HQ_RATE_MAX
    jae  .rate
    inc  dword [rel hist_rate_count]
    cmp  dword [r13 + HQC_REQUESTER], HQR_OWNER_UI
    je   .owner_ui
    cmp  qword [rel session_bound_pid], PRIN_OWNER
    jne  .denied
    lea  rdi, [r13 + HQC_TICKET]
    call hist_ticket_take
    test eax, eax
    jz   .denied
    jmp  .admitted
.owner_ui:
    call hist_owner_local
    test eax, eax
    jz   .denied
.admitted:
    call hist_key_ensure
    test eax, eax
    jnz  .locked
    call hist_scan
    mov  [rsp + 8], eax
    xor  eax, eax
    jmp  .done
.bad_noout:
    xor  r14d, r14d
.bad:
    mov  eax, HIST_BAD
    jmp  .done
.off:
    mov  eax, HIST_OFF
    jmp  .done
.locked:
    mov  eax, HIST_LOCKED
    jmp  .done
.rate:
    mov  eax, HIST_RATE
    jmp  .done
.denied:
    mov  eax, HIST_DENIED
.done:
    mov  [rsp], eax
    ; Guardian: allowed with the verified requester, else unverified (folded)
    mov  edi, eax
    shl  edi, 16
    or   edi, AUDIT_SEC_C_HISTORY | (AUDIT_SEC_R_HISTORY_QUERY << 16)
    xor  esi, esi
    mov  edx, [rsp + 12]
    test eax, eax
    jnz  .refused
    or   edi, AUDIT_SEC_V_ALLOWED << 8
    mov  esi, PRIN_OWNER
    cmp  dword [rsp + 12], HQR_OWNER_UI
    je   .who
    mov  esi, PRIN_ADVISOR
.who:
    mov  edx, [rsp + 8]                 ; rows
    jmp  .audit
.refused:
    cmp  eax, HIST_DENIED
    je   .policy
    cmp  eax, HIST_RATE
    je   .policy
    or   edi, AUDIT_SEC_V_INFO << 8
    jmp  .audit
.policy:
    or   edi, AUDIT_SEC_V_REFUSED << 8
.audit:
    call audit_sec_event
    test r14, r14
    jz   .out
    mov  eax, [rsp]
    mov  byte [r14], 1
    mov  [r14 + 1], al
    mov  eax, [rsp + 8]
    mov  [r14 + 2], ax
    mov  byte [r14 + 5], 1              ; no_cloud: no PaOS-drawn cloud confirmation exists in RC
    mov  rax, [rel audit_sec_seq]
    mov  [r14 + 8], rax
.out:
    lea  rdi, [rel hist_stage]
    xor  esi, esi
    mov  edx, HR_SIZE
    call memset
    mov  eax, [rsp]
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; hist_query_valid -> EAX 1 when query64 (R12) and qctx32 (R13) are exactly
; well formed (r2 §7). Clobbers caller-saved.
hist_query_valid:
    cmp  byte [r12 + HQ_VER], 1
    jne  .no
    cmp  byte [r12 + HQ_FLAGS], 0
    jne  .no
    movzx eax, byte [r12 + HQ_CATS]
    test eax, eax
    jz   .no
    test eax, ~HC_ALL_MASK & 0xFF
    jnz  .no
    cmp  byte [r12 + HQ_RSV], 0
    jne  .no
    mov  eax, [r12 + HQ_MAXROWS]
    test eax, eax
    jz   .no
    cmp  eax, HQ_ROWS_MAX
    ja   .no
    mov  rax, [r12 + HQ_FROM]
    mov  rcx, [r12 + HQ_TO]
    test rax, rax
    jz   .times_ok
    test rcx, rcx
    jz   .times_ok
    cmp  rax, rcx
    ja   .no
.times_ok:
    mov  eax, [r12 + HQ_TEXTLEN]
    cmp  eax, HQ_TEXT_MAX
    ja   .no
    push rax
    lea  rdi, [r12 + HQ_TEXT]
    mov  esi, HQ_TEXT_MAX
    call hist_text_ok
    pop  rcx
    cmp  eax, ecx                       ; no NUL inside, nothing after
    jne  .no
    cmp  dword [r13 + HQC_RSV], 0
    jne  .no
    cmp  qword [r13 + HQC_RSV2], 0
    jne  .no
    mov  eax, [r13 + HQC_REQUESTER]
    cmp  eax, HQR_AI_QUESTION
    je   .yes
    cmp  eax, HQR_OWNER_UI
    jne  .no
    mov  rax, [r13 + HQC_TICKET]        ; the owner's UI carries no ticket
    or   rax, [r13 + HQC_TICKET + 8]
    jnz  .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hist_scan -> EAX rows written to R14 + 16; newest first; sets the truncated
; byte when a further match exists. Each entry is authenticated before it is
; read; one that does not open (another key) is skipped and counted.
hist_scan:
    push rbx
    push rbp
    push r15
    xor  ebp, ebp                       ; rows
    mov  rbx, [rel hist_seq]            ; candidate seq
    mov  rax, [rel hist_ring]
    test rax, rax
    jz   .done
.next:
    cmp  rbx, [rel hist_first_seq]
    jb   .done
    test rbx, rbx
    jz   .done
    mov  rax, [rel hist_seq]
    sub  rax, rbx
    cmp  rax, HIST_CAP
    jae  .done                          ; overwritten
    mov  rdi, rbx
    and  edi, HIST_CAP - 1
    imul rdi, rdi, HE_SIZE
    add  rdi, [rel hist_ring]
    cmp  [rdi + HE_SEQ], rbx
    jne  .skip
    lea  rsi, [rdi + HE_CT]
    lea  rcx, [rel hist_stage]
    lea  r8, [rdi + HE_TAG]
    mov  r9, rbx
    call hist_aead_open
    test eax, eax
    jnz  .unreadable
    call hist_match
    test eax, eax
    jz   .skip
    cmp  ebp, [r12 + HQ_MAXROWS]
    jae  .truncated
    mov  r15d, ebp
    imul r15, r15, HQ_ROW_SIZE
    lea  r15, [r14 + 16 + r15]
    mov  rax, [rel hist_stage + HR_TWALL]
    mov  [r15], rax
    mov  al, [rel hist_stage + HR_CAT]
    mov  [r15 + 8], al
    mov  al, [rel hist_stage + HR_ACT]
    mov  [r15 + 9], al
    mov  al, [rel hist_stage + HR_FLAGS]
    mov  [r15 + 10], al
    mov  eax, [rel hist_stage + HR_APP]
    mov  [r15 + 12], eax
    lea  rdi, [r15 + 16]
    lea  rsi, [rel hist_stage + HR_LABEL]
    mov  edx, HR_LABEL_MAX
    call memcpy
    mov  rdi, rbx
    call hist_handle
    test eax, eax
    jnz  .skip_row
    lea  rdi, [r15 + 64]
    lea  rsi, [rel hist_mac]
    mov  edx, 16
    call memcpy
.skip_row:
    inc  ebp
    jmp  .skip
.unreadable:
    add  qword [rel hist_unreadable], 1
.skip:
    dec  rbx
    jmp  .next
.truncated:
    mov  byte [r14 + 4], 1
.done:
    lea  rdi, [rel hist_mac]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  eax, ebp
    pop  r15
    pop  rbp
    pop  rbx
    ret

; hist_match -> EAX 1 when hist_stage passes the query in R12: its category is
; in the mask, its app matches, its time is in range (a record with an unknown
; time matches only an open range) and the text is a case-folded ASCII
; substring of the label.
hist_match:
    movzx ecx, byte [rel hist_stage + HR_CAT]
    dec  ecx
    movzx eax, byte [r12 + HQ_CATS]
    bt   eax, ecx
    jnc  .no
    mov  eax, [r12 + HQ_APP]
    test eax, eax
    jz   .app_ok
    cmp  eax, [rel hist_stage + HR_APP]
    jne  .no
.app_ok:
    mov  rax, [rel hist_stage + HR_TWALL]
    mov  rcx, [r12 + HQ_FROM]
    test rcx, rcx
    jz   .from_ok
    cmp  rax, rcx                       ; an unknown time (0) is below every bound
    jb   .no
.from_ok:
    mov  rcx, [r12 + HQ_TO]
    test rcx, rcx
    jz   .to_ok
    test rax, rax
    jz   .no
    cmp  rax, rcx
    ja   .no
.to_ok:
    mov  r9d, [r12 + HQ_TEXTLEN]
    test r9d, r9d
    jz   .yes
    xor  r8d, r8d                       ; start in the label
    lea  r10, [rel hist_stage + HR_LABEL]
.start:
    lea  eax, [r8d + r9d]
    cmp  eax, HR_LABEL_MAX
    ja   .no
    xor  ecx, ecx
.cmp:
    lea  eax, [r8d + ecx]
    movzx edx, byte [r10 + rax]
    test edx, edx
    jz   .no                            ; the label ended first
    cmp  dl, 'A'
    jb   .lab
    cmp  dl, 'Z'
    ja   .lab
    or   dl, 0x20
.lab:
    movzx eax, byte [r12 + HQ_TEXT + rcx]
    cmp  al, 'A'
    jb   .txt
    cmp  al, 'Z'
    ja   .txt
    or   al, 0x20
.txt:
    cmp  al, dl
    jne  .advance
    inc  ecx
    cmp  ecx, r9d
    jb   .cmp
.yes:
    mov  eax, 1
    ret
.advance:
    inc  r8d
    jmp  .start
.no:
    xor  eax, eax
    ret

; hist_handle(RDI = seq) -> EAX 0 / -1; hist_mac = HMAC-SHA256(H, "PaOSHH1" 0,
; seq, session epoch): its first 16 bytes are the row's opaque handle, valid
; only for this unlocked session (H and the epoch both change at lock).
hist_handle:
    mov  [rel hist_handle_in + 8], rdi
    mov  rax, [rel session_authority_epoch]
    mov  [rel hist_handle_in + 16], rax
    mov  rax, 'PaOSHH1'
    mov  [rel hist_handle_in], rax
    lea  rdi, [rel hist_mac]
    lea  rsi, [rel hist_key]
    mov  edx, 32
    lea  rcx, [rel hist_handle_in]
    mov  r8d, 24
    jmp  hmac_sha256

; ---------------------------------------------------------------------------
; history_reopen_resolve(RDI = handle16, RSI = out_reopen16) -> EAX = the
; record's category (1..6) with its producer's reopen_ref in out, or -1. Only
; the owner's own local UI, unlocked; one Guardian event per call.
; ---------------------------------------------------------------------------
history_reopen_resolve:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub  rsp, 16
    mov  r12, rdi
    mov  r13, rsi
    mov  dword [rsp], -1
    test rdi, rdi
    jz   .done
    test rsi, rsi
    jz   .done
    cmp  byte [rel hist_enabled], 1
    jne  .done
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .done
    call hist_owner_local
    test eax, eax
    jz   .done
    call hist_key_ensure
    test eax, eax
    jnz  .done
    mov  rax, [rel hist_ring]
    test rax, rax
    jz   .done
    mov  rbx, [rel hist_seq]
.next:
    cmp  rbx, [rel hist_first_seq]
    jb   .done
    test rbx, rbx
    jz   .done
    mov  rax, [rel hist_seq]
    sub  rax, rbx
    cmp  rax, HIST_CAP
    jae  .done
    mov  rdi, rbx
    call hist_handle
    test eax, eax
    jnz  .skip
    mov  rax, [rel hist_mac]
    xor  rax, [r12]
    mov  rcx, [rel hist_mac + 8]
    xor  rcx, [r12 + 8]
    or   rax, rcx
    jnz  .skip
    mov  rdi, rbx
    and  edi, HIST_CAP - 1
    imul rdi, rdi, HE_SIZE
    add  rdi, [rel hist_ring]
    cmp  [rdi + HE_SEQ], rbx
    jne  .done
    lea  rsi, [rdi + HE_CT]
    lea  rcx, [rel hist_stage]
    lea  r8, [rdi + HE_TAG]
    mov  r9, rbx
    call hist_aead_open
    test eax, eax
    jnz  .done
    mov  rdi, r13
    lea  rsi, [rel hist_stage + HR_REOPEN]
    mov  edx, 16
    call memcpy
    movzx eax, byte [rel hist_stage + HR_CAT]
    mov  [rsp], eax
    jmp  .done
.skip:
    dec  rbx
    jmp  .next
.done:
    mov  edi, AUDIT_SEC_C_HISTORY | (AUDIT_SEC_R_HISTORY_REOPEN << 16)
    xor  esi, esi
    xor  edx, edx
    cmp  dword [rsp], 0
    jl   .refused
    or   edi, AUDIT_SEC_V_ALLOWED << 8
    mov  esi, PRIN_OWNER
    mov  edx, [rsp]
    jmp  .audit
.refused:
    or   edi, AUDIT_SEC_V_REFUSED << 8
.audit:
    call audit_sec_event
    lea  rdi, [rel hist_stage]
    xor  esi, esi
    mov  edx, HR_SIZE
    call memset
    lea  rdi, [rel hist_mac]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  eax, [rsp]
    add  rsp, 16
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; history_declare — register HISTCFG (owner only; settings, persisted).
; ---------------------------------------------------------------------------
history_declare:
    lea  rdi, [rel str_verb_histcfg]
    lea  rsi, [rel cmd_verb_histcfg]
    mov  rdx, CMD_AUTH_CAP_MUTATE           ; never public
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1                             ; changes and deletes owner data
    jmp  command_register_verb

; VERB: HISTCFG [on|off|pause|resume|clear|cats=N|retention=N]
;   Owner only: the console's bound local owner, or the request's own AUTH1
;   owner ticket / owner SSH key. "on" only at the owner's own console (the
;   first-enable acknowledgement; root 15:47:54 / design §5). Reply
;   "HISTCFG enabled=<0|1> paused=<0|1> cats=<mask> retention=<days>
;   records=<n> store=<nvram|ram|failed>". A change is saved (PaOSHistCfg).
cmd_verb_histcfg:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    mov  r13, rsi
    mov  rbx, [rdi + REQ_ARG]
    xor  r14d, r14d                     ; 1 = the request came from the console
    cmp  qword [rdi + REQ_SOURCE], CMD_SOURCE_CONSOLE
    jne  .remote
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .deny
    mov  r14d, 1
    jmp  .owner
.remote:
    call command_auth_owner_request     ; 1 own AUTH1 owner ticket, 2 owner SSH key
    test eax, eax
    jz   .deny
.owner:
    mov  r12d, 2                        ; store: 2 = nothing to save
    test rbx, rbx
    jz   .report
.ws:
    cmp  byte [rbx], ' '
    jne  .word
    inc  rbx
    jmp  .ws
.word:
    cmp  byte [rbx], 0
    je   .report
    mov  rdi, rbx
    lea  rsi, [rel str_hcf_on]
    call strcmp
    test eax, eax
    jz   .on
    mov  rdi, rbx
    lea  rsi, [rel str_hcf_off]
    call strcmp
    test eax, eax
    jz   .off
    mov  rdi, rbx
    lea  rsi, [rel str_hcf_pause]
    call strcmp
    test eax, eax
    jz   .pause
    mov  rdi, rbx
    lea  rsi, [rel str_hcf_resume]
    call strcmp
    test eax, eax
    jz   .resume
    mov  rdi, rbx
    lea  rsi, [rel str_hcf_clear]
    call strcmp
    test eax, eax
    jz   .clear
    mov  rdi, rbx
    lea  rsi, [rel str_hcf_cats]
    mov  ecx, 5
    call hist_word_value
    cmp  eax, -2
    je   .not_cats
    cmp  eax, HC_ALL_MASK
    ja   .bad
    mov  [rel hist_cat_mask], al
    jmp  .save
.not_cats:
    mov  rdi, rbx
    lea  rsi, [rel str_hcf_retention]
    mov  ecx, 10
    call hist_word_value
    cmp  eax, 1
    jl   .bad
    cmp  eax, HCF_RETENTION_MAX
    ja   .bad
    mov  [rel hist_retention], ax
    jmp  .save
.on:
    test r14d, r14d
    jz   .deny                          ; turning it on needs the owner at the machine
    mov  byte [rel hist_ack], 1
    mov  byte [rel hist_enabled], 1
    jmp  .save
.off:
    mov  byte [rel hist_enabled], 0
    jmp  .save
.pause:
    mov  byte [rel hist_paused], 1
    jmp  .save
.resume:
    mov  byte [rel hist_paused], 0
    jmp  .save
.clear:
    call hist_clear_all
    mov  r12d, 2
    jmp  .report
.save:
    call hist_cfg_persist
    mov  r12d, eax
.report:
    call session_out_reset
    lea  rdi, [rel str_hcf_enabled]
    call session_out_str
    movzx edi, byte [rel hist_enabled]
    call session_out_dec
    lea  rdi, [rel str_hcf_paused]
    call session_out_str
    movzx edi, byte [rel hist_paused]
    call session_out_dec
    lea  rdi, [rel str_hcf_cats_out]
    call session_out_str
    movzx edi, byte [rel hist_cat_mask]
    call session_out_dec
    lea  rdi, [rel str_hcf_retention_out]
    call session_out_str
    movzx edi, word [rel hist_retention]
    call session_out_dec
    lea  rdi, [rel str_hcf_records]
    call session_out_str
    call hist_record_count
    mov  rdi, rax
    call session_out_dec
    lea  rdi, [rel str_hcf_store]
    call session_out_str
    lea  rdi, [rel str_hcf_store_failed]
    cmp  r12d, -1
    je   .store
    lea  rdi, [rel str_hcf_store_ram]
    cmp  r12d, 1
    je   .store
    cmp  byte [rel hist_cfg_state], HCF_ST_NVRAM
    je   .nvram
    cmp  byte [rel hist_cfg_state], HCF_ST_POISONED
    jne  .store
.nvram:
    lea  rdi, [rel str_hcf_store_nvram]
.store:
    call session_out_str
    mov  qword [r13 + RSP_CODE], CMDE_OK
    jmp  .ready
.deny:
    call session_out_reset
    lea  rdi, [rel str_hcf_owner_only]
    call session_out_str
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    jmp  .ready
.bad:
    call session_out_reset
    lea  rdi, [rel str_hcf_bad]
    call session_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.ready:
    mov  byte [rel session_out_ready], 1
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; hist_word_value(RDI = word, RSI = "key=" text, ECX = its length) -> EAX = the
; decimal value after it (1..3 digits, nothing after), -1 = malformed, -2 =
; another word. Clobbers caller-saved.
hist_word_value:
    xor  edx, edx
.key:
    mov  al, [rdi + rdx]
    cmp  al, [rsi + rdx]
    jne  .other
    inc  edx
    cmp  edx, ecx
    jb   .key
    add  rdi, rcx
    xor  eax, eax
    xor  ecx, ecx
.digit:
    movzx edx, byte [rdi + rcx]
    test edx, edx
    jz   .end
    sub  edx, '0'
    cmp  edx, 9
    ja   .bad
    imul eax, eax, 10
    add  eax, edx
    inc  ecx
    cmp  ecx, 3
    ja   .bad
    jmp  .digit
.end:
    test ecx, ecx
    jz   .bad
    ret
.bad:
    mov  eax, -1
    ret
.other:
    mov  eax, -2
    ret

; hist_record_count -> RAX = records held (newest HIST_CAP since the last clear).
hist_record_count:
    mov  rax, [rel hist_seq]
    mov  rcx, [rel hist_first_seq]
    cmp  rax, rcx
    jb   .none
    sub  rax, rcx
    inc  rax
    cmp  rax, HIST_CAP
    jbe  .out
    mov  eax, HIST_CAP
.out:
    ret
.none:
    xor  eax, eax
    ret

; hist_clear_all: every record goes, the ring is zeroed and store_id rotates,
; so H changes and nothing sealed before can open again. One Guardian line with
; the count, never content.
hist_clear_all:
    push rbx
    call hist_record_count
    mov  rbx, rax
    mov  rdi, [rel hist_ring]
    test rdi, rdi
    jz   .ids
    xor  esi, esi
    mov  edx, HIST_CAP * HE_SIZE
    call memset
.ids:
    mov  rax, [rel hist_seq]
    inc  rax
    mov  [rel hist_first_seq], rax
    mov  byte [rel hist_store_id_ready], 0
    lea  rdi, [rel hist_store_id]
    xor  esi, esi
    mov  edx, 16
    call memset
    call hist_key_wipe
    mov  edi, AUDIT_SEC_C_HISTORY | (AUDIT_SEC_V_INFO << 8) | (AUDIT_SEC_R_HISTORY_CLEAR << 16)
    mov  esi, PRIN_OWNER
    mov  rdx, rbx
    call audit_sec_event
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Settings record (gui/kbd_prefs pattern, own record, name and HKDF domain).
; Record64: 'PHSC', version 1 u16, bytes 64 u16, generation u32 (nonzero),
; enabled u8@12, category mask u8@13 (bits 0..5), paused u8@14, ack u8@15
; (enabled needs it), retention days u16@16 (1..365), zero @18..31, HMAC32@32.
; ---------------------------------------------------------------------------

; history_cfg_load — once, at boot after the machine secret exists. A valid
; record replaces the defaults (off); absent keeps them; anything else keeps
; them, is never trusted, and the owner's next change replaces it.
history_cfg_load:
    cmp  byte [rel hist_cfg_state], HCF_ST_UNLOADED
    jne  .out
    mov  byte [rel hist_cfg_state], HCF_ST_RAMONLY
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .unavailable
    mov  byte [rel hist_cfg_state], HCF_ST_NOKEY
    call hist_cfg_derive
    test eax, eax
    jnz  .unavailable
    call hist_cfg_getvar
    cmp  eax, 1
    je   .absent
    cmp  eax, -2
    je   .read_error
    test eax, eax
    jnz  .poison
    lea  rdi, [rel hist_cfg_stage]
    call hist_cfg_valid
    test eax, eax
    jz   .poison
    mov  eax, [rel hist_cfg_stage + 8]
    mov  [rel hist_cfg_gen], eax
    mov  al, [rel hist_cfg_stage + 12]
    mov  [rel hist_enabled], al
    mov  al, [rel hist_cfg_stage + 13]
    mov  [rel hist_cat_mask], al
    mov  al, [rel hist_cfg_stage + 14]
    mov  [rel hist_paused], al
    mov  al, [rel hist_cfg_stage + 15]
    mov  [rel hist_ack], al
    mov  ax, [rel hist_cfg_stage + 16]
    mov  [rel hist_retention], ax
    call hist_cfg_mark_saved
    mov  byte [rel hist_cfg_state], HCF_ST_NVRAM
    lea  rdi, [rel str_hcf_loaded]
    jmp  serial_string
.absent:
    call hist_cfg_mark_saved            ; the shipped defaults need no write
    mov  byte [rel hist_cfg_state], HCF_ST_NVRAM
    ret
.read_error:
    mov  byte [rel hist_cfg_state], HCF_ST_POISONED
    lea  rdi, [rel str_hcf_read_error]
    jmp  serial_string
.unavailable:
    lea  rdi, [rel str_hcf_unavailable]
    jmp  serial_string
.poison:
    mov  byte [rel hist_cfg_state], HCF_ST_POISONED
    lea  rdi, [rel str_hcf_poisoned]
    jmp  serial_string
.out:
    ret

; hist_cfg_mark_saved: the values in force are what storage holds.
hist_cfg_mark_saved:
    mov  al, [rel hist_enabled]
    mov  [rel hist_cfg_saved + 0], al
    mov  al, [rel hist_cat_mask]
    mov  [rel hist_cfg_saved + 1], al
    mov  al, [rel hist_paused]
    mov  [rel hist_cfg_saved + 2], al
    mov  al, [rel hist_ack]
    mov  [rel hist_cfg_saved + 3], al
    mov  ax, [rel hist_retention]
    mov  [rel hist_cfg_saved + 4], ax
    mov  byte [rel hist_cfg_saved_valid], 1
    ret

; hist_cfg_persist -> EAX 0 saved or unchanged, 1 RAM only this boot, -1 the
; save or its readback failed (the values still apply this boot).
hist_cfg_persist:
    cmp  byte [rel hist_cfg_state], HCF_ST_NVRAM
    je   .live
    cmp  byte [rel hist_cfg_state], HCF_ST_POISONED
    jne  .ram
.live:
    cmp  byte [rel hist_cfg_saved_valid], 1
    jne  .build
    mov  al, [rel hist_enabled]
    cmp  al, [rel hist_cfg_saved + 0]
    jne  .build
    mov  al, [rel hist_cat_mask]
    cmp  al, [rel hist_cfg_saved + 1]
    jne  .build
    mov  al, [rel hist_paused]
    cmp  al, [rel hist_cfg_saved + 2]
    jne  .build
    mov  al, [rel hist_ack]
    cmp  al, [rel hist_cfg_saved + 3]
    jne  .build
    mov  ax, [rel hist_retention]
    cmp  ax, [rel hist_cfg_saved + 4]
    je   .unchanged
.build:
    cmp  dword [rel hist_cfg_gen], 0xffffffff
    je   .failed                        ; refuse a generation wrap before any write
    lea  rdi, [rel hist_cfg_stage]
    xor  esi, esi
    mov  edx, HCF_REC_SIZE
    call memset
    mov  dword [rel hist_cfg_stage], HCF_MAGIC
    mov  word [rel hist_cfg_stage + 4], 1
    mov  word [rel hist_cfg_stage + 6], HCF_REC_SIZE
    mov  eax, [rel hist_cfg_gen]
    inc  eax
    mov  [rel hist_cfg_stage + 8], eax
    mov  al, [rel hist_enabled]
    mov  [rel hist_cfg_stage + 12], al
    mov  al, [rel hist_cat_mask]
    mov  [rel hist_cfg_stage + 13], al
    mov  al, [rel hist_paused]
    mov  [rel hist_cfg_stage + 14], al
    mov  al, [rel hist_ack]
    mov  [rel hist_cfg_stage + 15], al
    mov  ax, [rel hist_retention]
    mov  [rel hist_cfg_stage + 16], ax
    lea  rdi, [rel hist_cfg_stage]
    call hist_cfg_valid_fields
    test eax, eax
    jz   .failed
    lea  rdi, [rel hist_cfg_stage]
    call hist_cfg_mac
    test eax, eax
    jnz  .failed
    lea  rdi, [rel hist_cfg_stage + 32]
    lea  rsi, [rel hist_cfg_mac_out]
    mov  edx, 32
    call memcpy
    call hist_cfg_setvar
    test eax, eax
    jnz  .failed
    mov  eax, [rel hist_cfg_stage + 8]
    mov  [rel hist_cfg_gen], eax
    call hist_cfg_mark_saved
    mov  byte [rel hist_cfg_state], HCF_ST_NVRAM
.unchanged:
    xor  eax, eax
    ret
.ram:
    mov  eax, 1
    ret
.failed:
    lea  rdi, [rel str_hcf_save_failed]
    call serial_string
    mov  eax, -1
    ret

; The gui/kbd_prefs machine-secret HKDF pattern, own domain label.
hist_cfg_derive:
    push rbx
    call principal_current
    mov  rbx, rax
    test rax, rax
    jz   .enter
    cmp  rax, PRIN_OWNER
    jne  .unbound
.enter:
    call principal_enter_system
    call principal_system_auth_credential
    test rax, rax
    jz   .bad
    cmp  edx, 32
    jne  .bad
    mov  rdi, rax
    mov  esi, 32
    xor  edx, edx
    xor  ecx, ecx
    lea  r8, [rel hist_cfg_info]
    mov  r9d, hist_cfg_info.len
    sub  rsp, 16
    lea  rax, [rel hist_cfg_key]
    mov  [rsp], rax
    mov  qword [rsp + 8], 32
    call hkdf_sha256_derive
    add  rsp, 16
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .restore
.bad:
    lea  rdi, [rel hist_cfg_key]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  eax, -1
.restore:
    sub  rsp, 16
    mov  [rsp], rax
    cmp  rbx, PRIN_OWNER
    je   .owner
    call principal_clear_bound
    jmp  .restored
.owner:
    call principal_leave_system
.restored:
    mov  rax, [rsp]
    add  rsp, 16
    pop  rbx
    ret
.unbound:
    mov  eax, -1
    pop  rbx
    ret

; RDI record -> hist_cfg_mac_out = HMAC(key, record[0:32]).
hist_cfg_mac:
    mov  rcx, rdi
    lea  rdi, [rel hist_cfg_mac_out]
    lea  rsi, [rel hist_cfg_key]
    mov  edx, 32
    mov  r8d, 32
    jmp  hmac_sha256

; Fixed fields: enabled and paused and ack are 0/1, enabled needs ack, the mask
; holds six categories, retention is 1..365, the tail is zero.
hist_cfg_valid_fields:
    cmp  dword [rdi], HCF_MAGIC
    jne  .no
    cmp  word [rdi + 4], 1
    jne  .no
    cmp  word [rdi + 6], HCF_REC_SIZE
    jne  .no
    cmp  dword [rdi + 8], 0
    je   .no
    cmp  byte [rdi + 12], 1
    ja   .no
    cmp  byte [rdi + 13], HC_ALL_MASK
    ja   .no
    cmp  byte [rdi + 14], 1
    ja   .no
    cmp  byte [rdi + 15], 1
    ja   .no
    cmp  byte [rdi + 12], 1
    jne  .acked
    cmp  byte [rdi + 15], 1
    jne  .no
.acked:
    movzx eax, word [rdi + 16]
    test eax, eax
    jz   .no
    cmp  eax, HCF_RETENTION_MAX
    ja   .no
    mov  ecx, 18
.reserved:
    cmp  byte [rdi + rcx], 0
    jne  .no
    inc  ecx
    cmp  ecx, 32
    jb   .reserved
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

hist_cfg_valid:
    push rbx
    mov  rbx, rdi
    call hist_cfg_valid_fields
    test eax, eax
    jz   .out
    mov  rdi, rbx
    call hist_cfg_mac
    test eax, eax
    jnz  .mac_failed
    lea  rsi, [rel hist_cfg_mac_out]
    xor  eax, eax
    xor  ecx, ecx
.cmp:
    mov  dl, [rbx + rcx + 32]
    xor  dl, [rsi + rcx]
    or   al, dl
    inc  ecx
    cmp  ecx, 32
    jb   .cmp
    test al, al
    setz al
    movzx eax, al
    jmp  .out
.mac_failed:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Exact NV|BS|RT and 64-byte GetVariable -> 0 read, 1 absent, -1 wrong
; attributes/size (an oversized record included), -2 no runtime services or
; another firmware read error.
hist_cfg_getvar:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .read_error
    mov  qword [rel hist_cfg_size], HCF_REC_SIZE
    mov  dword [rel hist_cfg_attrs], 0
    lea  rcx, [rel hist_cfg_var_name]
    lea  rdx, [rel hist_cfg_var_guid]
    lea  r8, [rel hist_cfg_attrs]
    lea  r9, [rel hist_cfg_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rax, [rel hist_cfg_stage]
    mov  [rsp + 32], rax
    call [r12 + 0x48]
    mov  rsp, r13
    test rax, rax
    jz   .read
    mov  rdx, HCF_NOT_FOUND
    cmp  rax, rdx
    je   .absent
    mov  rdx, HCF_BUFFER_TOO_SMALL
    cmp  rax, rdx
    je   .bad
    jmp  .read_error
.absent:
    mov  eax, 1
    jmp  .out
.read_error:
    mov  eax, -2
    jmp  .out
.read:
    cmp  dword [rel hist_cfg_attrs], HCF_EFI_ATTRS
    jne  .bad
    cmp  qword [rel hist_cfg_size], HCF_REC_SIZE
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Canonical storage gate before SetVariable, then exact attributes/length/bytes
; readback. Nothing saved is advanced until every check passes.
hist_cfg_setvar:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .bad
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    call storage_access_request_intent
    mov  edx, eax
    lea  rdi, [rel hist_cfg_var_guid]
    lea  rsi, [rel hist_cfg_var_name]
    lea  rcx, [rel str_hcf_gate_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    lea  rcx, [rel hist_cfg_var_name]
    lea  rdx, [rel hist_cfg_var_guid]
    mov  r8d, HCF_EFI_ATTRS
    mov  r9d, HCF_REC_SIZE
    and  rsp, -16
    sub  rsp, 48
    lea  rax, [rel hist_cfg_stage]
    mov  [rsp + 32], rax
    call [r12 + 0x58]
    mov  rsp, r13
    test rax, rax
    jnz  .bad
    mov  qword [rel hist_cfg_size], HCF_REC_SIZE
    mov  dword [rel hist_cfg_attrs], 0
    lea  rcx, [rel hist_cfg_var_name]
    lea  rdx, [rel hist_cfg_var_guid]
    lea  r8, [rel hist_cfg_attrs]
    lea  r9, [rel hist_cfg_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rax, [rel hist_cfg_verify]
    mov  [rsp + 32], rax
    call [r12 + 0x48]
    mov  rsp, r13
    test rax, rax
    jnz  .bad
    cmp  dword [rel hist_cfg_attrs], HCF_EFI_ATTRS
    jne  .bad
    cmp  qword [rel hist_cfg_size], HCF_REC_SIZE
    jne  .bad
    lea  rdi, [rel hist_cfg_stage]
    lea  rsi, [rel hist_cfg_verify]
    mov  edx, HCF_REC_SIZE
    call memcmp
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    mov  rsp, r13
    pop  r13
    pop  r12
    pop  rbx
    ret

; category / kind / allowed-action mask (r2 §2), 8 bytes per row, no pointers
HIST_RULES equ 7
align 4
hist_rules:
    db HC_DOCUMENTS, 1, 0, 0
    dd (1<<1)|(1<<2)|(1<<3)|(1<<4)|(1<<5)|(1<<6)|(1<<7)|(1<<11)
    db HC_WEB, 2, 0, 0
    dd (1<<8)|(1<<4)
    db HC_APPS, 3, 0, 0
    dd (1<<12)|(1<<13)
    db HC_AI, 4, 0, 0
    dd (1<<9)
    db HC_SETTINGS, 5, 0, 0
    dd (1<<10)|(1<<11)
    db HC_SYSTEM, 6, 0, 0
    dd (1<<15)|(1<<16)
    db HC_SYSTEM, 7, 0, 0
    dd (1<<14)
; object_ref bytes each kind uses (r2 §3); every later byte must be zero
hist_oref_used: db 32, 32, 0, 0, 24, 16, 6, 16
hist_key_info: db 'PaOS/history/v1'
.len equ $ - hist_key_info
hist_cfg_info: db 'PaOS/svc/history_cfg/v1'
.len equ $ - hist_cfg_info
str_hist_http:  db 'http://'
str_hist_https: db 'https://'
str_verb_histcfg: db "HISTCFG", 0
str_hcf_on:     db "on", 0
str_hcf_off:    db "off", 0
str_hcf_pause:  db "pause", 0
str_hcf_resume: db "resume", 0
str_hcf_clear:  db "clear", 0
str_hcf_cats:   db "cats="
str_hcf_retention: db "retention="
str_hcf_enabled: db "HISTCFG enabled=", 0
str_hcf_paused: db " paused=", 0
str_hcf_cats_out: db " cats=", 0
str_hcf_retention_out: db " retention=", 0
str_hcf_records: db " records=", 0
str_hcf_store:  db " store=", 0
str_hcf_store_nvram: db "nvram", 0
str_hcf_store_ram: db "ram", 0
str_hcf_store_failed: db "failed", 0
str_hcf_owner_only: db "HISTCFG owner only (on: at the owner's console)", 0
str_hcf_bad:    db "HISTCFG usage: on|off|pause|resume|clear|cats=0..63|retention=1..365", 0
str_hcf_gate_tag: db 'hist_cfg_setvar', 0
str_hcf_loaded: db '[PAOS64] history settings restored [sec.history.cfg.loaded]', 13, 10, 0
str_hcf_read_error: db '[PAOS64] history settings unreadable; history off this boot [sec.history.cfg.read_error]', 13, 10, 0
str_hcf_unavailable: db '[PAOS64] history settings store unavailable; history off, RAM only [sec.history.cfg.unavailable]', 13, 10, 0
str_hcf_poisoned: db '[PAOS64] history settings malformed or unauthentic; history off [sec.history.cfg.poisoned]', 13, 10, 0
str_hcf_save_failed: db '[PAOS64] history settings apply this boot; save/readback failed [sec.history.cfg.save_failed]', 13, 10, 0
align 8
; PaOS data/config vendor GUID (nvg_paos_guids #3), as gui/clock_prefs
hist_cfg_var_guid:
    dd 0x5a6ec129
    dw 0x2554, 0x494c
    db 0x99,0xbd,0xb0,0x39,0x60,0xdf,0x47,0x04
hist_cfg_var_name: dw 'P','a','O','S','H','i','s','t','C','f','g',0

HIST_SPANS equ 8

%include "core/abi/wdata.inc"
%macro WDATA_svc_history 0
align 8, db 0
; KEY_MATERIAL: H, the record key; reset_wipe_all wipes all 32 bytes.
hist_key: times 32 db 0
; KEY_MATERIAL: the settings record MAC key (HKDF of the machine secret).
hist_cfg_key: times 32 db 0
; KEY_MATERIAL: the live AI question ticket.
hist_ai_ticket: times 16 db 0
hist_store_id: times 16 db 0
hist_stage: times HR_SIZE db 0          ; one plaintext record, zeroed after each use
hist_url_buf: times HIST_URL_MAX db 0   ; the stripped URL, zeroed after each use
hist_mac: times 32 db 0
hist_handle_in: times 24 db 0
hist_spans: times HIST_SPANS * 16 db 0
hist_aead: times 64 db 0
hist_nonce: times 16 db 0
hist_ring: dq 0
hist_window_check:  dq 0                 ; gui/window_mgmt wmx_history_target, set once at boot
hist_seq: dq 0                          ; the last sequence sealed
hist_first_seq: dq 1                    ; the oldest sequence still held (moves at clear)
hist_key_epoch: dq 0
hist_ticket_expiry: dq 0
hist_ticket_epoch: dq 0
hist_rate_start: dq 0
hist_unreadable: dq 0
hist_counts: times HIST_NCODES dq 0
hist_rate_count: dd 0
hist_cfg_gen: dd 0
hist_cfg_size: dq 0
hist_cfg_attrs: dd 0
hist_retention: dw HCF_RETENTION_DEFAULT
hist_enabled: db 0
hist_paused: db 0
hist_cat_mask: db HC_ALL_MASK
hist_ack: db 0
hist_key_ready: db 0
hist_key_kind: db 0
hist_store_id_ready: db 0
hist_ticket_valid: db 0
hist_ticket_uses: db 0
hist_cfg_state: db HCF_ST_UNLOADED
hist_cfg_saved_valid: db 0
align 8, db 0
hist_cfg_saved: times 8 db 0
hist_cfg_mac_out: times 32 db 0
hist_cfg_stage: times HCF_REC_SIZE db 0
hist_cfg_verify: times HCF_REC_SIZE db 0
%endmacro
WDATA_DEFER WDATA_svc_history
