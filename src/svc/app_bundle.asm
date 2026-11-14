;; MODULE svc/app_bundle
;; LAYER 5
;; EXPORTS app_bundle_declare, app_bundle_verify, app_bundle_run, app_bundle_inspect, app_trust_find, app_trust_add, app_trust_del, app_key_id, cmd_verb_app, cmd_verb_appkey, app_out_buf, app_out_ready
;; IMPORTS core/lib/str, core/lib/sha256, bootmgr/rsa2048_verify, svc/command, svc/command_auth, sec/owner_store, fs/vfs, core/heap
;; CAPS
;; OWNER saga:command
; ============================================================================
; svc/app_bundle.asm -- RCQ-31: the NATIVE CONSUMER of the public PaOS app
; bundle v1 (root 18:45: one signed, architecture-neutral bundle of a manifest
; plus recipes that call registered typed verbs; NO CPU code). The bound seam
; (container bytes, load order, grammar, markers) is NATIVE_BUNDLE_V1_SEAM.md
; (rc-resource 18:53); APP_COMPATIBILITY.md and the schema mirror it.
;
;   APP LOAD <path>     read the file from the selected FS volume, verify, and
;                       make it the ONE resident bundle (only on success)
;   APP RUN <entry>     run one declared entry recipe
;   APP INSPECT <entry> <page1..4>  read up to four exact stored calls, no dispatch
;   APP UNLOAD | STATUS
;   APPKEY ADD <512 hex, big-endian modulus> | DEL <32 hex key id> | LIST
;
; Container (little-endian): a 64-byte header (magic PAOSAPP1, container v1,
; offsets/lengths of manifest, recipes and opaque assets, contiguous, flags
; and reserved 0, a 16-byte key id = SHA-256 of the signer's big-endian
; modulus), then the sections, then a 256-byte RSA-2048 PKCS#1 v1.5 SHA-256
; signature over every byte before it (the existing strict verifier, e=65537).
;
; VERIFY BEFORE PARSE: header bounds and the container version are the only
; bytes read before the signature verifies. The manifest (whose line 1 must be
; sdk=1) and the recipes are parsed only from signed bytes.
;
; TRUST (Policy 8): the validated per-install enrolled owner's public key is
; trusted when present (sec/owner_store); there is no compiled signer fallback.
; The owner may add up to APP_KEYS_MAX more (APPKEY, which needs the
; owner-only SOVEREIGN_CONTROL scope). Slice 1 keeps added keys in RAM.
;
; APPS NEVER GRANT AUTHORITY. Each step must match a row of the APP VERB TABLE
; whose capability the manifest declares (else [app.verb.unlisted] or
; [app.cap.denied], and nothing is dispatched), and then runs through the ONE
; command_dispatch with the invoking request's source, principal, capability
; and idempotency key copied unchanged (HOOK's delegation model). The native
; gate decides as if the invoker had typed the verb; an app is never looser.
;
; WIRING: all profiles include and declare the same consumer. F2 source binding
; uses the final committed OWR_KEY public modulus, not a pending stage,
; publisher or compiled lab signer. APP and APPKEY remain protected verbs;
; availability in a public image grants no unauthenticated access. A remote
; APP spends its single-use
; exact-capability ticket on the outer dispatch, so a nested non-public step
; refuses there; the fix for that is a separate RUN verb, never a public APP.
;
; MEMORY: the stage and resident bundle buffers (2 x APP_FILE_MAX) are one
; heap block taken on the first APP LOAD, not image bytes (the Dell ESP
; image cap). No block refuses the load as why=mem; RUN and STATUS touch the
; buffers only after a load has committed, so they never see a null pointer.
; ============================================================================

APP_FILE_MAX     equ 16384
APP_HDR          equ 64
APP_SIG          equ 256
APP_MAN_MAX      equ 2048
APP_REC_MAX      equ 8192
APP_LINE_MAX     equ 160
APP_RECIPES_MAX  equ 4
APP_STEPS_MAX    equ 16
APP_STEP_TOTAL   equ 64
APP_ENTRY_MAX    equ 4
APP_KEYS_MAX     equ 8
APP_OUT_MAX      equ 4096
APP_PATH_MAX     equ 255

; container header
APPH_MAGIC  equ 0
APPH_CVER   equ 8
APPH_HSIZE  equ 10
APPH_TOTAL  equ 12
APPH_MOFF   equ 16
APPH_MLEN   equ 20
APPH_ROFF   equ 24
APPH_RLEN   equ 28
APPH_AOFF   equ 32
APPH_ALEN   equ 36
APPH_FLAGS  equ 40
APPH_RSVD   equ 44
APPH_KEYID  equ 48

; parsed bundle (offsets into its buffer, so a verified stage copies as is)
APPM_CAPS   equ 0
APPM_ID_OFF equ 8
APPM_ID_LEN equ 12
APPM_VER_OFF equ 16
APPM_VER_LEN equ 20
APPM_NENT   equ 24
APPM_ENT    equ 28                ; APP_ENTRY_MAX x (off dd, len dd)
APPM_NREC   equ 60
APPM_REC    equ 64                ; APP_RECIPES_MAX x APPR_SZ
APPM_NSTEP  equ 128
APPM_STEP   equ 132               ; APP_STEP_TOTAL x (off dd, len dd)
APPM_KEYID  equ 644
APPM_TOTAL  equ 660
APPM_SZ     equ 664

APPR_NOFF   equ 0
APPR_NLEN   equ 4
APPR_FIRST  equ 8
APPR_COUNT  equ 12
APPR_SZ     equ 16

; trusted key slot
APPK_USED   equ 0
APPK_ID     equ 8
APPK_MOD    equ 24
APPK_SZ     equ 280

; APP VERB TABLE row
APPT_VERB   equ 0
APPT_ARGS   equ 8
APPT_CAP    equ 16
APPT_STABLE equ 24
APPT_SZ     equ 32

; load verdicts
APP_OK              equ 0
APP_MALFORMED       equ 1
APP_UNSUP_CONTAINER equ 2
APP_UNTRUSTED       equ 3
APP_BADSIG          equ 4
APP_UNSUP_SDK       equ 5
APP_BAD_MANIFEST    equ 6
APP_BAD_RECIPE      equ 7

; malformed reasons (index into app_why_names)
APP_WHY_SIZE      equ 1
APP_WHY_MAGIC     equ 2
APP_WHY_HDRSIZE   equ 3
APP_WHY_TOTAL     equ 4
APP_WHY_MANIFEST  equ 5
APP_WHY_RECIPES   equ 6
APP_WHY_ASSETS    equ 7
APP_WHY_FLAGS     equ 8
APP_WHY_RESERVED  equ 9
APP_WHY_READ      equ 10
APP_WHY_MEM       equ 11

; run verdicts
APP_RUN_OK       equ 0
APP_RUN_NONE     equ 1
APP_RUN_NOENTRY  equ 2
APP_RUN_UNLISTED equ 3
APP_RUN_DENIED   equ 4
APP_RUN_FAILED   equ 5
APP_RUN_BUSY     equ 6
APP_INSPECT_PAGE equ 7
APP_RUN_INVALID  equ 8

; capability names (bit = 1 << index into app_cap_names)
APP_CAP_NET_READ equ 1
APP_CAP_SYS_READ equ 2
APP_CAP_FS_READ  equ 4
APP_CAP_GUI_READ equ 8
APP_CAP_GUI_WRITE equ 16

; manifest keys seen
APP_MK_ID   equ 1
APP_MK_VER  equ 2
APP_MK_CAPS equ 4
APP_MK_ENTRY equ 8
APP_NAME_MAX equ 32

; app_bundle_declare -- register APP (owner EXTENSION scope) and APPKEY (owner-only
;   SOVEREIGN_CONTROL: adding a signing key is a trust grant the AI operator never holds).
app_bundle_declare:
    lea  rdi, [rel str_verb_app]
    lea  rsi, [rel cmd_verb_app]
    mov  rdx, CMD_AUTH_CAP_EXTENSION
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1
    call command_register_verb
    lea  rdi, [rel str_verb_appkey]
    lea  rsi, [rel cmd_verb_appkey]
    mov  rdx, CMD_AUTH_CAP_SOVEREIGN_CONTROL
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1
    jmp  command_register_verb

; ---------------------------------------------------------------------------
; Trust list
; ---------------------------------------------------------------------------

; app_key_id(RDI = 256-byte little-endian modulus, RSI = out16): the first 16 bytes
;   of SHA-256 over the big-endian modulus (what a signer's tool sees).
app_key_id:
    push r12
    push r13
    sub  rsp, 8
    mov  r12, rdi
    mov  r13, rsi
    lea  rdx, [rel app_be_tmp]
    xor  ecx, ecx
.rev:
    mov  eax, 255
    sub  eax, ecx
    mov  al, [r12 + rax]
    mov  [rdx + rcx], al
    inc  ecx
    cmp  ecx, 256
    jb   .rev
    lea  rdi, [rel app_digest]
    lea  rsi, [rel app_be_tmp]
    mov  edx, 256
    call sha256_hash
    mov  rax, [rel app_digest]
    mov  [r13], rax
    mov  rax, [rel app_digest + 8]
    mov  [r13 + 8], rax
    add  rsp, 8
    pop  r13
    pop  r12
    ret

; app_id_eq16(RDI, RSI) -> EAX 1 when the two 16-byte ids are equal. Uses RAX only.
app_id_eq16:
    mov  rax, [rdi]
    cmp  rax, [rsi]
    jne  .no
    mov  rax, [rdi + 8]
    cmp  rax, [rsi + 8]
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

app_owner_id_ready:
    push rbx
    call owner_enrolled_modulus
    mov  rbx, rax
    test rax, rax
    jz   .absent
    mov  rdi, rax
    lea  rsi, [rel app_owner_id]
    call app_key_id
    mov  byte [rel app_owner_ready], 1
.out:
    mov  rax, rbx
    pop  rbx
    ret
.absent:
    mov  byte [rel app_owner_ready], 0
    mov  qword [rel app_owner_id], 0
    mov  qword [rel app_owner_id + 8], 0
    jmp  .out

; app_trust_find(RDI = key id16) -> RAX = the trusted little-endian modulus, or 0.
app_trust_find:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    call app_owner_id_ready
    mov  rbx, rax
    test rax, rax
    jz   .added
    lea  rdi, [rel app_owner_id]
    mov  rsi, r12
    call app_id_eq16
    test eax, eax
    jz   .added
    mov  rax, rbx
    jmp  .out
.added:
    xor  ebx, ebx
.slot:
    cmp  ebx, APP_KEYS_MAX
    jae  .none
    imul rdx, rbx, APPK_SZ
    lea  rax, [rel app_keys]
    add  rdx, rax
    cmp  byte [rdx + APPK_USED], 1
    jne  .next
    lea  rdi, [rdx + APPK_ID]
    mov  rsi, r12
    call app_id_eq16
    test eax, eax
    jz   .next
    lea  rax, [rdx + APPK_MOD]
    jmp  .out
.next:
    inc  ebx
    jmp  .slot
.none:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; app_trust_add(RDI = 256-byte little-endian modulus) -> EAX = slot, -1 full,
;   -2 already trusted (the owner key included), -3 not a 2048-bit modulus or even
;   (RCQ-31 F4: an RSA modulus is odd; an even one would burn a slot that never verifies).
;   app_tmp_id holds the key id for -2 and success.
app_trust_add:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    mov  eax, -3
    test byte [r12 + 255], 0x80
    jz   .out
    test byte [r12], 1
    jz   .out
    lea  rsi, [rel app_tmp_id]
    call app_key_id
    lea  rdi, [rel app_tmp_id]
    call app_trust_find
    test rax, rax
    mov  eax, -2
    jnz  .out
    xor  ebx, ebx
.slot:
    cmp  ebx, APP_KEYS_MAX
    jae  .full
    imul rdx, rbx, APPK_SZ
    lea  rax, [rel app_keys]
    add  rdx, rax
    cmp  byte [rdx + APPK_USED], 0
    je   .put
    inc  ebx
    jmp  .slot
.put:
    mov  byte [rdx + APPK_USED], 1
    mov  rax, [rel app_tmp_id]
    mov  [rdx + APPK_ID], rax
    mov  rax, [rel app_tmp_id + 8]
    mov  [rdx + APPK_ID + 8], rax
    lea  rdi, [rdx + APPK_MOD]
    mov  rsi, r12
    mov  ecx, 256
    rep  movsb
    mov  eax, ebx
    jmp  .out
.full:
    mov  eax, -1
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; app_trust_del(RDI = key id16) -> EAX 0 removed, -1 unknown, -2 the owner key (never removed).
app_trust_del:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    call app_owner_id_ready
    test rax, rax
    jz   .added
    lea  rdi, [rel app_owner_id]
    mov  rsi, r12
    call app_id_eq16
    test eax, eax
    mov  eax, -2
    jnz  .out
.added:
    xor  ebx, ebx
.slot:
    cmp  ebx, APP_KEYS_MAX
    jae  .none
    imul rdx, rbx, APPK_SZ
    lea  rax, [rel app_keys]
    add  rdx, rax
    cmp  byte [rdx + APPK_USED], 1
    jne  .next
    lea  rdi, [rdx + APPK_ID]
    mov  rsi, r12
    call app_id_eq16
    test eax, eax
    jz   .next
    mov  rdi, rdx
    xor  eax, eax
    mov  ecx, APPK_SZ
    rep  stosb
    xor  eax, eax
    jmp  .out
.next:
    inc  ebx
    jmp  .slot
.none:
    mov  eax, -1
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Verify + parse
; ---------------------------------------------------------------------------

; app_bundle_verify(RDI = buffer, ESI = length) -> EAX = APP_* verdict. Fills
;   app_stage_meta (offsets into the buffer); app_why / app_why_line say why.
app_bundle_verify:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  [rel app_v_buf], r12
    mov  dword [rel app_why], 0
    mov  dword [rel app_why_line], 0
    lea  rdi, [rel app_stage_meta]
    xor  eax, eax
    mov  ecx, APPM_SZ
    rep  stosb
    mov  ecx, APP_WHY_SIZE
    cmp  r13d, APP_FILE_MAX
    ja   .malformed
    cmp  r13d, APP_HDR + APP_SIG + 2
    jb   .malformed
    mov  ecx, APP_WHY_MAGIC
    mov  rax, 'PAOSAPP1'
    cmp  [r12 + APPH_MAGIC], rax
    jne  .malformed
    cmp  word [r12 + APPH_CVER], 1
    jne  .unsup_container
    mov  ecx, APP_WHY_HDRSIZE
    cmp  word [r12 + APPH_HSIZE], APP_HDR
    jne  .malformed
    mov  ecx, APP_WHY_TOTAL
    cmp  [r12 + APPH_TOTAL], r13d
    jne  .malformed
    mov  ecx, APP_WHY_MANIFEST
    cmp  dword [r12 + APPH_MOFF], APP_HDR
    jne  .malformed
    mov  eax, [r12 + APPH_MLEN]
    test eax, eax
    jz   .malformed
    cmp  eax, APP_MAN_MAX
    ja   .malformed
    add  eax, APP_HDR                     ; manifest end
    mov  ecx, APP_WHY_RECIPES
    cmp  [r12 + APPH_ROFF], eax
    jne  .malformed
    mov  edx, [r12 + APPH_RLEN]
    test edx, edx
    jz   .malformed
    cmp  edx, APP_REC_MAX
    ja   .malformed
    add  eax, edx                         ; recipes end
    mov  ecx, APP_WHY_ASSETS
    cmp  [r12 + APPH_AOFF], eax
    jne  .malformed
    mov  edx, [r12 + APPH_ALEN]
    cmp  edx, APP_FILE_MAX
    ja   .malformed                       ; bounded before the sum: no 32-bit wrap
    add  eax, edx                         ; signature offset
    lea  edx, [eax + APP_SIG]
    cmp  edx, r13d
    jne  .malformed
    mov  r14d, eax                        ; signed length
    mov  ecx, APP_WHY_FLAGS
    cmp  dword [r12 + APPH_FLAGS], 0
    jne  .malformed
    mov  ecx, APP_WHY_RESERVED
    cmp  dword [r12 + APPH_RSVD], 0
    jne  .malformed
    ; trust, then the signature: nothing below reads an unsigned byte
    lea  rdi, [r12 + APPH_KEYID]
    call app_trust_find
    test rax, rax
    jz   .untrusted
    mov  rcx, rax
    lea  rdi, [r12 + r14]
    mov  rsi, r12
    mov  edx, r14d
    call rsa2048_verify_sha256
    test eax, eax
    jnz  .badsig
    mov  rax, [r12 + APPH_KEYID]
    mov  [rel app_stage_meta + APPM_KEYID], rax
    mov  rax, [r12 + APPH_KEYID + 8]
    mov  [rel app_stage_meta + APPM_KEYID + 8], rax
    mov  [rel app_stage_meta + APPM_TOTAL], r13d
    call app_parse_manifest
    test eax, eax
    jnz  .out
    call app_parse_recipes
    test eax, eax
    jnz  .out
    call app_check_entries
    jmp  .out
.malformed:
    mov  [rel app_why], ecx
    mov  eax, APP_MALFORMED
    jmp  .out
.unsup_container:
    mov  eax, APP_UNSUP_CONTAINER
    jmp  .out
.untrusted:
    mov  eax, APP_UNTRUSTED
    jmp  .out
.badsig:
    mov  eax, APP_BADSIG
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; app_next_line -> EAX = offset of the next line in [app_lp, app_lend), EDX = its
;   length without the LF; EAX = -1 at the region end. Counts app_lineno. app_nolf = 1
;   when the line ran to the region end without its LF (every line must end in LF).
app_next_line:
    mov  byte [rel app_nolf], 0
    mov  eax, [rel app_lp]
    cmp  eax, [rel app_lend]
    jae  .eof
    mov  rsi, [rel app_v_buf]
    mov  ecx, eax
.scan:
    cmp  ecx, [rel app_lend]
    jae  .last
    ; Retain the logical-region check; independently clip the byte address to
    ; the native LOAD allocation. A constant bound avoids a second memory-bound
    ; dependency. See gauntlet_v2/docs/app_bundle_byte_bounds.md (G1 subset).
    mov  edx, APP_FILE_MAX - 1
    cmp  ecx, edx
    cmovb edx, ecx
    cmp  byte [rsi + rdx], 10
    je   .lf
    inc  ecx
    jmp  .scan
.lf:
    mov  edx, ecx
    sub  edx, eax
    inc  ecx
    mov  [rel app_lp], ecx
    inc  dword [rel app_lineno]
    ret
.last:
    mov  edx, ecx                         ; a line without its LF: the caller refuses it
    sub  edx, eax
    mov  [rel app_lp], ecx
    inc  dword [rel app_lineno]
    mov  byte [rel app_nolf], 1
    ret
.eof:
    mov  eax, -1
    ret

; app_printable(RDI = bundle span ptr, ESI = len) -> EAX 1 when every byte is 0x20..0x7e
app_printable:
    mov  r11, [rel app_v_buf]             ; bundle-only: live LOAD allocation base
    xor  ecx, ecx
.byte:
    cmp  ecx, esi
    jae  .yes
    ; Translate the span pointer back to a full-width allocation offset before
    ; clipping. The logical cursor/length continue to decide grammar acceptance.
    mov  rdx, rdi
    sub  rdx, r11
    add  rdx, rcx
    mov  eax, APP_FILE_MAX - 1
    cmp  rdx, rax
    cmova rdx, rax
    movzx eax, byte [r11 + rdx]
    cmp  al, 0x20
    jb   .no
    cmp  al, 0x7e
    ja   .no
    inc  ecx
    jmp  .byte
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; app_has_prefix(RDI = ptr, ESI = len, RDX = cstr) -> EAX 1 when the span starts with
;   the cstr; ECX = the cstr's length then.
app_has_prefix:
    xor  ecx, ecx
.ch:
    movzx eax, byte [rdx + rcx]
    test al, al
    jz   .yes
    cmp  ecx, esi
    jae  .no
    cmp  al, [rdi + rcx]
    jne  .no
    inc  ecx
    jmp  .ch
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; app_tok_eq(RDI = ptr, ESI = len, RDX = cstr) -> EAX 1 when the span equals the cstr
app_tok_eq:
    call app_has_prefix
    test eax, eax
    jz   .out
    xor  eax, eax
    cmp  ecx, esi
    sete al
.out:
    ret

; app_name_ok(RDI = ptr, ESI = len) -> EAX 1 for a recipe/entry name [a-z][a-z0-9_-]{0,31}
app_name_ok:
    test esi, esi
    jz   .no
    cmp  esi, APP_NAME_MAX
    ja   .no
    movzx eax, byte [rdi]
    cmp  al, 'a'
    jb   .no
    cmp  al, 'z'
    ja   .no
    mov  edx, 1
    jmp  app_charset_ok
.no:
    xor  eax, eax
    ret

; app_charset_ok(RDI = ptr, ESI = len, EDX = 0 id [a-z0-9.-] / 1 name [a-z0-9_-]) -> EAX 1/0
app_charset_ok:
    xor  ecx, ecx
.ch:
    cmp  ecx, esi
    jae  .yes
    movzx eax, byte [rdi + rcx]
    cmp  al, 'a'
    jb   .not_lower
    cmp  al, 'z'
    jbe  .next
.not_lower:
    cmp  al, '0'
    jb   .punct
    cmp  al, '9'
    jbe  .next
.punct:
    test edx, edx
    jnz  .name
    cmp  al, '.'
    je   .next
    cmp  al, '-'
    je   .next
    jmp  .no
.name:
    cmp  al, '_'
    je   .next
    cmp  al, '-'
    jne  .no
.next:
    inc  ecx
    jmp  .ch
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Explicit bundle-origin helpers. The shared raw helpers above also consume
; command buffers and retain their original byte-address/caller contract.
; Stage consumers use app_v_buf; RUN/INSPECT use the distinct app_res_ptr.
; R8/R9/R11 are scratch; logical spans and the cstr caller contract are unchanged.
; Only the bundle-side byte read is clipped. See app_bundle_helper_origins.md.
%macro APP_BOUNDED_PREFIX 2
%1:
    mov  r11, [rel %2]
    xor  ecx, ecx
.ch:
    movzx eax, byte [rdx + rcx]
    test al, al
    jz   .yes
    cmp  ecx, esi
    jae  .no
    mov  r8, rdi
    sub  r8, r11
    add  r8, rcx
    mov  r9d, APP_FILE_MAX - 1
    cmp  r8, r9
    cmova r8, r9
    cmp  al, [r11 + r8]
    jne  .no
    inc  ecx
    jmp  .ch
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret
%endmacro
APP_BOUNDED_PREFIX app_stage_has_prefix, app_v_buf
APP_BOUNDED_PREFIX app_res_has_prefix, app_res_ptr
%unmacro APP_BOUNDED_PREFIX 2

%macro APP_BOUNDED_TOKEN 2
%1:
    call %2
    test eax, eax
    jz   .out
    xor  eax, eax
    cmp  ecx, esi
    sete al
.out:
    ret
%endmacro
APP_BOUNDED_TOKEN app_stage_tok_eq, app_stage_has_prefix
APP_BOUNDED_TOKEN app_res_tok_eq, app_res_has_prefix
%unmacro APP_BOUNDED_TOKEN 2

app_stage_name_ok:
    mov  r11, [rel app_v_buf]
    test esi, esi
    jz   .no
    cmp  esi, APP_NAME_MAX
    ja   .no
    mov  r8, rdi
    sub  r8, r11
    mov  r9d, APP_FILE_MAX - 1
    cmp  r8, r9
    cmova r8, r9
    movzx eax, byte [r11 + r8]
    cmp  al, 'a'
    jb   .no
    cmp  al, 'z'
    ja   .no
    mov  edx, 1
    jmp  app_stage_charset_ok
.no:
    xor  eax, eax
    ret

app_stage_charset_ok:
    mov  r11, [rel app_v_buf]
    xor  ecx, ecx
.ch:
    cmp  ecx, esi
    jae  .yes
    mov  r8, rdi
    sub  r8, r11
    add  r8, rcx
    mov  r9d, APP_FILE_MAX - 1
    cmp  r8, r9
    cmova r8, r9
    movzx eax, byte [r11 + r8]
    cmp  al, 'a'
    jb   .not_lower
    cmp  al, 'z'
    jbe  .next
.not_lower:
    cmp  al, '0'
    jb   .punct
    cmp  al, '9'
    jbe  .next
.punct:
    test edx, edx
    jnz  .name
    cmp  al, '.'
    je   .next
    cmp  al, '-'
    je   .next
    jmp  .no
.name:
    cmp  al, '_'
    je   .next
    cmp  al, '-'
    jne  .no
.next:
    inc  ecx
    jmp  .ch
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; app_version_ok(RDI = bundle span ptr, ESI = len) -> EAX 1 for N.N.N, each 1..5 digits <= 65535
app_version_ok:
    mov  r11, [rel app_v_buf]             ; bundle-only: live LOAD allocation base
    xor  ecx, ecx
    xor  r8d, r8d                         ; components done
.comp:
    xor  r9d, r9d                         ; value
    xor  r10d, r10d                       ; digits
.dig:
    cmp  ecx, esi
    jae  .end_comp
    ; Translate the span pointer back to a full-width allocation offset before
    ; clipping. The logical cursor/length continue to decide grammar acceptance.
    mov  rdx, rdi
    sub  rdx, r11
    add  rdx, rcx
    mov  eax, APP_FILE_MAX - 1
    cmp  rdx, rax
    cmova rdx, rax
    movzx eax, byte [r11 + rdx]
    cmp  al, '.'
    je   .end_comp
    sub  eax, '0'
    cmp  eax, 9
    ja   .no
    imul r9d, r9d, 10
    add  r9d, eax
    inc  r10d
    cmp  r10d, 5
    ja   .no
    inc  ecx
    jmp  .dig
.end_comp:
    test r10d, r10d
    jz   .no
    cmp  r9d, 65535
    ja   .no
    inc  r8d
    cmp  ecx, esi
    jae  .last
    cmp  r8d, 3
    jae  .no
    inc  ecx                              ; past the dot
    jmp  .comp
.last:
    cmp  r8d, 3
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; app_span_eq(EDI = off1, ESI = len1, EDX = off2, ECX = len2) -> EAX 1 when the two
;   spans of app_v_buf are equal
app_span_eq:
    cmp  esi, ecx
    jne  .no
    mov  r8, [rel app_v_buf]
    xor  r9d, r9d
.ch:
    cmp  r9d, esi
    jae  .yes
    lea  r10d, [rdi + r9]
    mov  r11d, APP_FILE_MAX - 1
    cmp  r10d, r11d
    cmova r10d, r11d
    movzx eax, byte [r8 + r10]
    lea  r11d, [rdx + r9]
    mov  r10d, APP_FILE_MAX - 1
    cmp  r11d, r10d
    cmova r11d, r10d
    cmp  al, [r8 + r11]
    jne  .no
    inc  r9d
    jmp  .ch
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; app_cap_lookup(RDI = ptr, ESI = len) -> RAX = the capability bit, or 0
app_cap_lookup:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    xor  ebx, ebx
.name:
    lea  rax, [rel app_cap_names]
    mov  rdx, [rax + rbx*8]               ; rel delta from the table (org-0 image)
    test rdx, rdx
    jz   .none
    add  rdx, rax
    mov  rdi, r12
    mov  esi, r13d
    call app_stage_tok_eq
    test eax, eax
    jnz  .hit
    inc  ebx
    jmp  .name
.hit:
    mov  ecx, ebx
    mov  eax, 1
    shl  rax, cl
    jmp  .out
.none:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; app_parse_manifest -> EAX = 0, APP_UNSUP_SDK or APP_BAD_MANIFEST (app_why_line).
app_parse_manifest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, [rel app_v_buf]
    mov  dword [rel app_lp], APP_HDR
    mov  eax, [r12 + APPH_MLEN]
    add  eax, APP_HDR
    mov  [rel app_lend], eax
    mov  dword [rel app_lineno], 0
    xor  ebx, ebx                         ; keys seen
    call app_next_line
    cmp  eax, -1
    je   .unsup
    cmp  byte [rel app_nolf], 0
    jne  .unsup
    cmp  edx, 5
    jne  .unsup
    ; One clipped five-byte span covers both SDK literal reads. Logical line
    ; checks above still decide acceptance; clipping confines the addresses.
    mov  r10d, APP_FILE_MAX - 5
    cmp  eax, r10d
    cmovb r10d, eax
    cmp  dword [r12 + r10], 'sdk='
    jne  .unsup
    cmp  byte [r12 + r10 + 4], '1'
    jne  .unsup
.line:
    call app_next_line
    cmp  eax, -1
    je   .end
    mov  r13d, eax
    mov  r14d, edx
    cmp  byte [rel app_nolf], 0
    jne  .bad
    lea  rdi, [r12 + r13]
    mov  esi, r14d
    call app_printable
    test eax, eax
    jz   .bad
    lea  rdi, [r12 + r13]
    mov  esi, r14d
    lea  rdx, [rel str_app_k_id]
    call app_stage_has_prefix
    test eax, eax
    jnz  .id
    lea  rdi, [r12 + r13]
    mov  esi, r14d
    lea  rdx, [rel str_app_k_version]
    call app_stage_has_prefix
    test eax, eax
    jnz  .version
    lea  rdi, [r12 + r13]
    mov  esi, r14d
    lea  rdx, [rel str_app_k_caps]
    call app_stage_has_prefix
    test eax, eax
    jnz  .caps
    lea  rdi, [r12 + r13]
    mov  esi, r14d
    lea  rdx, [rel str_app_k_entry]
    call app_stage_has_prefix
    test eax, eax
    jnz  .entry
    jmp  .bad
.id:
    test ebx, APP_MK_ID
    jnz  .bad
    or   ebx, APP_MK_ID
    lea  eax, [r13 + 3]
    lea  edx, [r14 - 3]
    cmp  edx, 3
    jb   .bad
    cmp  edx, 63
    ja   .bad
    mov  [rel app_stage_meta + APPM_ID_OFF], eax
    mov  [rel app_stage_meta + APPM_ID_LEN], edx
    lea  rdi, [r12 + rax]
    mov  esi, edx
    xor  edx, edx
    call app_stage_charset_ok
    test eax, eax
    jz   .bad
    jmp  .line
.version:
    test ebx, APP_MK_VER
    jnz  .bad
    or   ebx, APP_MK_VER
    lea  eax, [r13 + 8]
    lea  edx, [r14 - 8]
    mov  [rel app_stage_meta + APPM_VER_OFF], eax
    mov  [rel app_stage_meta + APPM_VER_LEN], edx
    lea  rdi, [r12 + rax]
    mov  esi, edx
    call app_version_ok
    test eax, eax
    jz   .bad
    jmp  .line
.caps:
    test ebx, APP_MK_CAPS
    jnz  .bad
    or   ebx, APP_MK_CAPS
    lea  r15d, [r13 + 5]                  ; token start
    lea  eax, [r13 + r14]
    mov  [rel app_cap_end], eax
    cmp  r15d, eax
    je   .line                            ; caps= with no names: none declared
.cap_tok:
    mov  ecx, r15d
.cap_scan:
    cmp  ecx, [rel app_cap_end]
    jae  .cap_have
    mov  r10d, APP_FILE_MAX - 1
    cmp  ecx, r10d
    cmovb r10d, ecx
    cmp  byte [r12 + r10], ','
    je   .cap_have
    inc  ecx
    jmp  .cap_scan
.cap_have:
    mov  [rel app_cap_next], ecx
    mov  esi, ecx
    sub  esi, r15d
    jz   .bad                             ; empty name
    lea  rdi, [r12 + r15]
    call app_cap_lookup
    test rax, rax
    jz   .bad                             ; not a contract capability
    test [rel app_stage_meta + APPM_CAPS], rax
    jnz  .bad                             ; duplicate
    or   [rel app_stage_meta + APPM_CAPS], rax
    mov  ecx, [rel app_cap_next]
    cmp  ecx, [rel app_cap_end]
    jae  .line
    lea  r15d, [rcx + 1]
    cmp  r15d, [rel app_cap_end]
    jae  .bad                             ; trailing comma
    jmp  .cap_tok
.entry:
    test ebx, APP_MK_ENTRY
    jnz  .bad
    or   ebx, APP_MK_ENTRY
    lea  r15d, [r13 + 6]                  ; name start
    lea  eax, [r13 + r14]
    mov  [rel app_cap_end], eax
    cmp  r15d, eax
    je   .bad                             ; at least one entry
.ent_tok:
    mov  ecx, r15d
.ent_scan:
    cmp  ecx, [rel app_cap_end]
    jae  .ent_have
    mov  r10d, APP_FILE_MAX - 1
    cmp  ecx, r10d
    cmovb r10d, ecx
    cmp  byte [r12 + r10], ','
    je   .ent_have
    inc  ecx
    jmp  .ent_scan
.ent_have:
    mov  [rel app_cap_next], ecx
    mov  edx, ecx
    sub  edx, r15d
    mov  [rel app_tmp_off], r15d
    mov  [rel app_tmp_len], edx
    lea  rdi, [r12 + r15]
    mov  esi, edx
    call app_stage_name_ok
    test eax, eax
    jz   .bad
    cmp  dword [rel app_stage_meta + APPM_NENT], APP_ENTRY_MAX
    jae  .bad
    xor  r15d, r15d
.ent_dup:
    cmp  r15d, [rel app_stage_meta + APPM_NENT]
    jae  .ent_add
    lea  r8, [rel app_stage_meta + APPM_ENT]
    mov  edi, [rel app_tmp_off]
    mov  esi, [rel app_tmp_len]
    mov  edx, [r8 + r15*8]
    mov  ecx, [r8 + r15*8 + 4]
    call app_span_eq
    test eax, eax
    jnz  .bad
    inc  r15d
    jmp  .ent_dup
.ent_add:
    mov  eax, [rel app_stage_meta + APPM_NENT]
    lea  r8, [rel app_stage_meta + APPM_ENT]
    mov  ecx, [rel app_tmp_off]
    mov  [r8 + rax*8], ecx
    mov  ecx, [rel app_tmp_len]
    mov  [r8 + rax*8 + 4], ecx
    inc  dword [rel app_stage_meta + APPM_NENT]
    mov  ecx, [rel app_cap_next]
    cmp  ecx, [rel app_cap_end]
    jae  .line
    lea  r15d, [rcx + 1]
    cmp  r15d, [rel app_cap_end]
    jae  .bad                             ; trailing comma
    jmp  .ent_tok
.end:
    cmp  ebx, APP_MK_ID | APP_MK_VER | APP_MK_CAPS | APP_MK_ENTRY
    jne  .bad_end
    xor  eax, eax
    jmp  .out
.bad_end:
    mov  dword [rel app_lineno], 0
.bad:
    mov  eax, [rel app_lineno]
    mov  [rel app_why_line], eax
    mov  eax, APP_BAD_MANIFEST
    jmp  .out
.unsup:
    mov  eax, APP_UNSUP_SDK
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; app_parse_recipes -> EAX = 0 or APP_BAD_RECIPE (app_why_line).
app_parse_recipes:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, [rel app_v_buf]
    mov  eax, [r12 + APPH_ROFF]
    mov  [rel app_lp], eax
    add  eax, [r12 + APPH_RLEN]
    mov  [rel app_lend], eax
    mov  dword [rel app_lineno], 0
    mov  ebx, -1                          ; current recipe; -1 = between recipes
.line:
    call app_next_line
    cmp  eax, -1
    je   .end
    mov  r13d, eax
    mov  r14d, edx
    cmp  byte [rel app_nolf], 0
    jne  .bad
    cmp  r14d, APP_LINE_MAX
    ja   .bad
    lea  rdi, [r12 + r13]
    mov  esi, r14d
    call app_printable
    test eax, eax
    jz   .bad
    cmp  ebx, -1
    jne  .inside
    lea  rdi, [r12 + r13]
    mov  esi, r14d
    lea  rdx, [rel str_app_k_recipe]
    call app_stage_has_prefix
    test eax, eax
    jz   .bad
    cmp  dword [rel app_stage_meta + APPM_NREC], APP_RECIPES_MAX
    jae  .bad
    lea  ecx, [r13 + 7]
    lea  edx, [r14 - 7]
    mov  [rel app_tmp_off], ecx
    mov  [rel app_tmp_len], edx
    lea  rdi, [r12 + rcx]
    mov  esi, edx
    call app_stage_name_ok
    test eax, eax
    jz   .bad
    xor  r15d, r15d
.dup:
    cmp  r15d, [rel app_stage_meta + APPM_NREC]
    jae  .add
    mov  eax, r15d
    shl  eax, 4
    lea  r8, [rel app_stage_meta + APPM_REC]
    mov  edi, [rel app_tmp_off]
    mov  esi, [rel app_tmp_len]
    mov  edx, [r8 + rax + APPR_NOFF]
    mov  ecx, [r8 + rax + APPR_NLEN]
    call app_span_eq
    test eax, eax
    jnz  .bad
    inc  r15d
    jmp  .dup
.add:
    mov  ebx, [rel app_stage_meta + APPM_NREC]
    mov  eax, ebx
    shl  eax, 4
    lea  r8, [rel app_stage_meta + APPM_REC]
    mov  ecx, [rel app_tmp_off]
    mov  [r8 + rax + APPR_NOFF], ecx
    mov  ecx, [rel app_tmp_len]
    mov  [r8 + rax + APPR_NLEN], ecx
    mov  ecx, [rel app_stage_meta + APPM_NSTEP]
    mov  [r8 + rax + APPR_FIRST], ecx
    mov  dword [r8 + rax + APPR_COUNT], 0
    inc  dword [rel app_stage_meta + APPM_NREC]
    jmp  .line
.inside:
    mov  eax, ebx
    shl  eax, 4
    lea  r15, [rel app_stage_meta + APPM_REC]
    add  r15, rax                         ; the open recipe
    cmp  r14d, 3
    jne  .step
    mov  r10d, APP_FILE_MAX - 3
    cmp  r13d, r10d
    cmovb r10d, r13d
    cmp  word [r12 + r10], 'en'
    jne  .step
    cmp  byte [r12 + r10 + 2], 'd'
    jne  .step
    cmp  dword [r15 + APPR_COUNT], 0
    je   .bad                             ; a recipe has at least one step
    mov  ebx, -1
    jmp  .line
.step:
    lea  rdi, [r12 + r13]
    mov  esi, r14d
    lea  rdx, [rel str_app_k_step]
    call app_stage_has_prefix
    test eax, eax
    jz   .bad
    cmp  r14d, 5
    jbe  .bad
    lea  r10d, [r13 + 5]
    mov  r11d, APP_FILE_MAX - 1
    cmp  r10d, r11d
    cmova r10d, r11d
    cmp  byte [r12 + r10], ' '
    je   .bad                             ; the verb starts right after "step "
    ; contract v1 (SDK parity, slice 2): the verb is [A-Z][A-Z0-9_]{0,63}, then the
    ; line ends or a space starts the argument text
    lea  ecx, [r14 - 5]
    xor  edx, edx
.sv_ch:
    cmp  edx, ecx
    jae  .sv_ok
    lea  r10d, [r13 + rdx + 5]
    mov  r11d, APP_FILE_MAX - 1
    cmp  r10d, r11d
    cmova r10d, r11d
    movzx eax, byte [r12 + r10]
    cmp  al, ' '
    je   .sv_ok
    cmp  al, 'A'
    jb   .sv_tail
    cmp  al, 'Z'
    jbe  .sv_next
.sv_tail:
    test edx, edx
    jz   .bad                             ; the first verb byte is A-Z
    cmp  al, '_'
    je   .sv_next
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    ja   .bad
.sv_next:
    inc  edx
    cmp  edx, 64
    ja   .bad
    jmp  .sv_ch
.sv_ok:
    cmp  dword [r15 + APPR_COUNT], APP_STEPS_MAX
    jae  .bad
    mov  eax, [rel app_stage_meta + APPM_NSTEP]
    cmp  eax, APP_STEP_TOTAL
    jae  .bad
    lea  r8, [rel app_stage_meta + APPM_STEP]
    lea  ecx, [r13 + 5]
    mov  [r8 + rax*8], ecx
    lea  ecx, [r14 - 5]
    mov  [r8 + rax*8 + 4], ecx
    inc  dword [rel app_stage_meta + APPM_NSTEP]
    inc  dword [r15 + APPR_COUNT]
    jmp  .line
.end:
    cmp  ebx, -1
    jne  .bad                             ; a recipe left open
    cmp  dword [rel app_stage_meta + APPM_NREC], 0
    je   .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, [rel app_lineno]
    mov  [rel app_why_line], eax
    mov  eax, APP_BAD_RECIPE
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; app_check_entries -> EAX = 0, or APP_BAD_MANIFEST (line 0) when an entry names no recipe.
app_check_entries:
    push rbx
    push r12
    push r13
    xor  ebx, ebx
.ent:
    cmp  ebx, [rel app_stage_meta + APPM_NENT]
    jae  .ok
    xor  r12d, r12d
.rec:
    cmp  r12d, [rel app_stage_meta + APPM_NREC]
    jae  .bad
    lea  r8, [rel app_stage_meta + APPM_ENT]
    mov  edi, [r8 + rbx*8]
    mov  esi, [r8 + rbx*8 + 4]
    mov  eax, r12d
    shl  eax, 4
    lea  r8, [rel app_stage_meta + APPM_REC]
    mov  edx, [r8 + rax + APPR_NOFF]
    mov  ecx, [r8 + rax + APPR_NLEN]
    call app_span_eq
    test eax, eax
    jnz  .next
    inc  r12d
    jmp  .rec
.next:
    inc  ebx
    jmp  .ent
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  dword [rel app_why_line], 0
    mov  eax, APP_BAD_MANIFEST
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Run
; ---------------------------------------------------------------------------

; app_cstr_eq(RDI, RDX) -> EAX 1 when the two cstrs are equal
app_cstr_eq:
    xor  ecx, ecx
.ch:
    mov  al, [rdi + rcx]
    cmp  al, [rdx + rcx]
    jne  .no
    test al, al
    jz   .yes
    inc  ecx
    jmp  .ch
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; app_match_row -> RAX = the APP VERB TABLE row for (app_line verb, app_r_args), or 0.
;   RCQ-31 F1: the verb AND the whole argument text must equal the row exactly (case
;   as written; an empty row means no argument). There is no prefix or boundary
;   match, so 'HOOK LIST fs:/' or 'STATUS 5' matches no row and is refused before
;   any dispatch. Named pattern rows below accept only bounded typed tokens,
;   literal separators and terminal NUL; never a general HOOK prefix.
app_match_row:
    push rbx
    lea  rbx, [rel app_verb_table]
.row:
    mov  rdx, [rbx + APPT_VERB]           ; rel delta from app_verb_table; 0 ends it
    test rdx, rdx
    jz   .none
    lea  rax, [rel app_verb_table]
    add  rdx, rax
    lea  rdi, [rel app_line]
    call app_cstr_eq
    test eax, eax
    jz   .next
    mov  rdi, [rel app_r_args]
    mov  rdx, [rbx + APPT_ARGS]
    lea  rax, [rel app_verb_table]
    add  rdx, rax
    lea  rax, [rel app_verb_audio_playback]
    cmp  rbx, rax
    je   .audio
    lea  rax, [rel app_verb_gui_patterns]
    cmp  rbx, rax
    jb   .exact
    lea  rax, [rel app_verb_gui_end]
    cmp  rbx, rax
    jb   .gui
.exact:
    call app_cstr_eq
    jmp  .matched
.audio:
    call app_audio_playback_args
    jmp  .matched
.gui:
    call app_gui_args
.matched:
    test eax, eax
    jnz  .hit
.next:
    add  rbx, APPT_SZ
    jmp  .row
.hit:
    mov  rax, rbx
    pop  rbx
    ret
.none:
    xor  eax, eax
    pop  rbx
    ret

; The audio family: RDI=args, RDX=literal prefix.
app_audio_playback_args:
.prefix:
    mov  al, [rdx]
    test al, al
    jz   .nonce
    cmp  al, [rdi]
    jne  .no
    inc  rdx
    inc  rdi
    jmp  .prefix
.nonce:
    mov  ecx, 16
.digit:
    mov  al, [rdi]
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .advance
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
.advance:
    inc  rdi
    dec  ecx
    jnz  .digit
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; RDI=args, RDX=trusted template. Only the named rows use this grammar.
; Tokens: 1=u31, 2=cursor0..128, 3=form identifier1..31,
; 4=page1..u32, 5=offset0..1280, 6=length1..384, 7=final read field.
; All numbers are canonical decimal. Instance existence, field/type support,
; page/range semantics, native authorization and results belong to HOOK/native.
; No input rewriting, clamping, new commands or authority is performed here.
app_gui_args:
    push rbx
    push r12
    mov  r12, rdx
.token:
    movzx ebx, byte [r12]
    test ebx, ebx
    jz   .end
    cmp  ebx, 7
    je   .field
    cmp  ebx, 3
    je   .identifier
    cmp  ebx, 6
    jbe  .number
    cmp  bl, [rdi]
    jne  .no
    inc  rdi
    jmp  .next
.number:
    xor  r11d, r11d
    mov  r10d, 0x7fffffff
    cmp  ebx, 1
    je   .decimal
    mov  r10d, 128
    cmp  ebx, 2
    je   .decimal
    mov  r10d, 0xffffffff
    mov  r11d, 1
    cmp  ebx, 4
    je   .decimal
    mov  r10d, 1280
    xor  r11d, r11d
    cmp  ebx, 5
    je   .decimal
    mov  r10d, 384
    mov  r11d, 1
.decimal:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .no
    cmp  byte [rdi], '0'
    jne  .digits
    movzx ecx, byte [rdi + 1]
    sub  ecx, '0'
    cmp  ecx, 9
    jbe  .no
.digits:
    xor  eax, eax
.digit:
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .number_end
    imul rax, rax, 10
    add  rax, rcx
    cmp  rax, r10
    ja   .no
    inc  rdi
    jmp  .digit
.number_end:
    cmp  rax, r11
    jb   .no
    jmp  .next
.identifier:
    mov  al, [rdi]
    cmp  al, 'a'
    jb   .no
    cmp  al, 'z'
    ja   .no
    xor  ecx, ecx
.id_char:
    mov  al, [rdi]
    cmp  al, 'a'
    jb   .id_other
    cmp  al, 'z'
    jbe  .id_advance
.id_other:
    cmp  al, '_'
    je   .id_advance
    cmp  al, '0'
    jb   .id_end
    cmp  al, '9'
    ja   .id_end
.id_advance:
    inc  ecx
    cmp  ecx, 31
    ja   .no
    inc  rdi
    jmp  .id_char
.id_end:
    jmp  .next
.field:
    lea  r8, [rel app_gui_fields]
.field_row:
    mov  rdx, [r8]
    test rdx, rdx
    jz   .no
    lea  rax, [rel app_gui_fields]
    add  rdx, rax
    call app_cstr_eq
    test eax, eax
    jnz  .yes
    add  r8, 8
    jmp  .field_row
.next:
    inc  r12
    jmp  .token
.end:
    cmp  byte [rdi], 0
    jne  .no
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; app_parse_u64(RDI = cstr) -> RAX = value, EDX = 1 (empty = 0), or EDX = 0
app_parse_u64:
    xor  eax, eax
    xor  ecx, ecx
.dig:
    movzx r8d, byte [rdi + rcx]
    test r8d, r8d
    jz   .yes
    sub  r8d, '0'
    cmp  r8d, 9
    ja   .no
    cmp  ecx, 18
    jae  .no
    imul rax, rax, 10
    add  rax, r8
    inc  ecx
    jmp  .dig
.yes:
    mov  edx, 1
    ret
.no:
    xor  edx, edx
    ret

; app_copy_res_step(EDI = resident offset, ESI = length) -> EAX = 1/0.
; Parsed "step " lines have 1..APP_LINE_MAX-5 bytes. Recheck that saved span
; before touching app_line. Clip every consumed source/destination address to
; its constant allocation bound as well; metadata/table and base lifetime are
; separate contracts. No command parsing or authority decision lives here.
app_copy_res_step:
    xor  eax, eax
    test esi, esi
    jz   .ret
    cmp  esi, APP_LINE_MAX - 5
    ja   .ret
    mov  r9d, edi
    mov  edx, esi
    add  rdx, r9                        ; full-width sum, never wraps at u32
    cmp  rdx, APP_FILE_MAX
    ja   .ret
    mov  r8, [rel app_res_ptr]
    lea  rdi, [rel app_line]
    xor  ecx, ecx
.copy:
    cmp  ecx, esi
    jae  .done
    mov  r10, r9
    mov  r11d, APP_FILE_MAX - 1
    cmp  r10, r11
    cmova r10, r11
    mov  al, [r8 + r10]
    mov  rdx, rcx
    mov  r11d, APP_LINE_MAX - 6
    cmp  rdx, r11
    cmova rdx, r11
    mov  [rdi + rdx], al
    inc  r9
    inc  rcx
    jmp  .copy
.done:
    mov  edx, APP_LINE_MAX - 5
    cmp  rcx, rdx
    cmova rcx, rdx
    mov  byte [rdi + rcx], 0
    mov  eax, 1
.ret:
    ret

; app_res_meta_ok() -> EAX=1 iff fixed resident tables and recipe spans fit.
; LOAD owns metadata publication and BSP serialization owns its lifetime. These
; defensive checks do not grant authority or admit a bundle. Even a bypassed
; branch leaves each indexed table operand dependent on its constant capacity.
; Clobbers only caller-saved registers; reads metadata, writes nothing.
app_res_meta_ok:
    xor  eax, eax
    cmp  dword [rel app_res_meta + APPM_NENT], APP_ENTRY_MAX
    ja   .ret
    mov  r9d, [rel app_res_meta + APPM_NREC]
    cmp  r9d, APP_RECIPES_MAX
    ja   .ret
    mov  r10d, [rel app_res_meta + APPM_NSTEP]
    cmp  r10d, APP_STEP_TOTAL
    ja   .ret
    xor  r11d, r11d
.recipe:
    cmp  r11d, r9d
    jae  .ok
    mov  ecx, r11d
    mov  edx, APP_RECIPES_MAX - 1
    cmp  ecx, edx
    cmova ecx, edx
    shl  ecx, 4
    lea  r8, [rel app_res_meta + APPM_REC]
    add  r8, rcx
    mov  edx, [r8 + APPR_COUNT]
    cmp  edx, APP_STEPS_MAX
    ja   .ret
    mov  ecx, [r8 + APPR_FIRST]
    add  rcx, rdx                       ; full-width sum, including corrupt dd values
    cmp  rcx, r10
    ja   .ret
    inc  r11d
    jmp  .recipe
.ok:
    mov  eax, 1
.ret:
    ret

; app_bundle_run(RDI = invoking request, RSI = entry cstr) -> EAX = APP_RUN_*.
;   app_r_step = the step reached (1-based) or, on success, the step count.
app_bundle_run:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  [rel app_r_req], rdi
    mov  [rel app_r_entry], rsi
    mov  dword [rel app_r_step], 0
    mov  qword [rel app_r_code], 0
    mov  eax, APP_RUN_BUSY
    cmp  byte [rel app_busy], 0
    jne  .ret_idle
    mov  eax, APP_RUN_NONE
    cmp  byte [rel app_res_loaded], 1
    jne  .ret_idle
    mov  byte [rel app_busy], 1
    call app_res_meta_ok
    test eax, eax
    jz   .badmeta
    mov  r12, [rel app_res_ptr]
    xor  ebx, ebx
.ent:
    cmp  ebx, [rel app_res_meta + APPM_NENT]
    jae  .noentry
    mov  eax, ebx
    mov  edx, APP_ENTRY_MAX - 1
    cmp  eax, edx
    cmova eax, edx
    lea  r8, [rel app_res_meta + APPM_ENT]
    mov  esi, [r8 + rax*8 + 4]
    mov  eax, [r8 + rax*8]
    lea  rdi, [r12 + rax]
    mov  rdx, [rel app_r_entry]
    call app_res_tok_eq
    test eax, eax
    jnz  .ent_ok
    inc  ebx
    jmp  .ent
.ent_ok:
    xor  ebx, ebx
.rec:
    cmp  ebx, [rel app_res_meta + APPM_NREC]
    jae  .noentry
    mov  eax, ebx
    mov  edx, APP_RECIPES_MAX - 1
    cmp  eax, edx
    cmova eax, edx
    shl  eax, 4
    lea  r13, [rel app_res_meta + APPM_REC]
    add  r13, rax
    mov  eax, [r13 + APPR_NOFF]
    mov  esi, [r13 + APPR_NLEN]
    lea  rdi, [r12 + rax]
    mov  rdx, [rel app_r_entry]
    call app_res_tok_eq
    test eax, eax
    jnz  .rec_ok
    inc  ebx
    jmp  .rec
.rec_ok:
    xor  r14d, r14d                       ; step index (R12-R14 survive command_dispatch)
.step:
    cmp  r14d, [r13 + APPR_COUNT]
    jae  .ok
    mov  eax, [r13 + APPR_FIRST]
    add  rax, r14
    mov  edx, APP_STEP_TOTAL - 1
    cmp  rax, rdx
    cmova rax, rdx
    lea  r8, [rel app_res_meta + APPM_STEP]
    mov  edi, [r8 + rax*8]
    mov  esi, [r8 + rax*8 + 4]
    call app_copy_res_step
    test eax, eax
    jz   .badarg
    lea  rdi, [rel app_line]
.split:
    mov  al, [rdi]
    test al, al
    jz   .noargs
    cmp  al, ' '
    je   .args
    inc  rdi
    jmp  .split
.args:
    mov  byte [rdi], 0
    inc  rdi
.noargs:
    mov  [rel app_r_args], rdi
    call app_match_row
    test rax, rax
    jz   .unlisted
    mov  [rel app_r_row], rax
    mov  rcx, [rax + APPT_CAP]
    test [rel app_res_meta + APPM_CAPS], rcx
    jz   .denied
    lea  rdi, [rel app_line]
    call command_lookup
    cmp  eax, -1
    je   .noverb
    mov  eax, eax
    mov  [rel app_r_verb], rax
    mov  rdi, rax
    call command_verb_argt
    cmp  eax, ARGT_TEXT
    je   .arg_text
    cmp  eax, ARGT_U64
    je   .arg_u64
    mov  rcx, [rel app_r_args]
    cmp  byte [rcx], 0
    jne  .badarg                          ; ARGT_NONE takes no argument
    xor  eax, eax
    jmp  .arg_set
.arg_text:
    mov  rax, [rel app_r_args]
    jmp  .arg_set
.arg_u64:
    mov  rdi, [rel app_r_args]
    call app_parse_u64
    test edx, edx
    jz   .badarg
.arg_set:
    mov  [rel app_req + REQ_ARG], rax
    mov  rax, [rel app_r_verb]
    mov  [rel app_req + REQ_VERB], rax
    mov  rcx, [rel app_r_req]
    mov  rax, [rcx + REQ_CAP]
    mov  [rel app_req + REQ_CAP], rax
    mov  rax, [rcx + REQ_IDEM]
    mov  [rel app_req + REQ_IDEM], rax
    mov  qword [rel app_req + REQ_SEL], 0
    mov  rax, [rcx + REQ_SOURCE]
    mov  [rel app_req + REQ_SOURCE], rax
    mov  rax, [rcx + REQ_PRINCIPAL]
    mov  [rel app_req + REQ_PRINCIPAL], rax
    inc  qword [rel app_dispatches]
    lea  rdi, [rel app_req]
    lea  rsi, [rel app_rsp]
    call command_dispatch                 ; THE one entry: the native gate decides
    mov  rax, [rel app_rsp + RSP_CODE]
    mov  [rel app_r_code], rax
    lea  rdi, [rel str_app_o_step]
    call app_out_str
    lea  edi, [r14 + 1]
    call app_out_dec
    lea  rdi, [rel str_app_o_verb]
    call app_out_str
    lea  rdi, [rel app_line]
    call app_out_str
    lea  rdi, [rel str_app_o_code]
    call app_out_str
    mov  rdi, [rel app_r_code]
    call app_out_dec
    lea  rdi, [rel str_app_o_val]
    call app_out_str
    mov  rdi, [rel app_rsp + RSP_VAL]
    call app_out_dec
    lea  rdi, [rel str_app_nl]
    call app_out_str
    cmp  qword [rel app_r_code], CMDE_OK
    jne  .step_failed
    inc  r14d
    jmp  .step
.ok:
    mov  [rel app_r_step], r14d
    mov  eax, APP_RUN_OK
    jmp  .ret
.noverb:
    mov  qword [rel app_r_code], CMDE_NOVERB
    jmp  .step_failed
.badarg:
    mov  qword [rel app_r_code], CMDE_BADARG
.step_failed:
    inc  r14d
    mov  [rel app_r_step], r14d
    mov  eax, APP_RUN_FAILED
    jmp  .ret
.unlisted:
    inc  r14d
    mov  [rel app_r_step], r14d
    mov  eax, APP_RUN_UNLISTED
    jmp  .ret
.denied:
    inc  r14d
    mov  [rel app_r_step], r14d
    inc  qword [rel app_denied]
    mov  eax, APP_RUN_DENIED
    jmp  .ret
.badmeta:
    mov  qword [rel app_r_code], CMDE_BADARG
    mov  eax, APP_RUN_INVALID
    jmp  .ret
.noentry:
    mov  eax, APP_RUN_NOENTRY
.ret:
    mov  byte [rel app_busy], 0
.ret_idle:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; app_bundle_inspect(RDI = validated entry cstr, ESI = page1..4) -> APP_RUN_*
; or APP_INSPECT_PAGE. Caller resets reply staging. Trusted resident metadata
; comes only from verified LOAD. This reads it without changing run/load/trust
; state, issuing a command, or treating declared capabilities as granted ones.
; Existing BSP serialization owns lifetime; busy refuses before buffer access.
; Four steps/page bounds the largest native v1 reply below1024 bytes: each
; parsed step <=155 bytes, id<=63, version<=17, entry<=32, key32, caps<=25.
app_bundle_inspect:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  r12, rdi                       ; immutable request entry
    mov  r13d, esi                      ; page
    mov  eax, APP_RUN_BUSY
    cmp  byte [rel app_busy], 0
    jne  .out
    mov  eax, APP_RUN_NONE
    cmp  byte [rel app_res_loaded], 1
    jne  .out
    mov  eax, APP_INSPECT_PAGE
    cmp  r13d, 1
    jb   .out
    cmp  r13d, 4
    ja   .out
    call app_res_meta_ok
    test eax, eax
    jz   .badmeta
    mov  r14, [rel app_res_ptr]
    xor  ebx, ebx
.entry:
    cmp  ebx, [rel app_res_meta + APPM_NENT]
    jae  .unknown
    mov  eax, ebx
    mov  edx, APP_ENTRY_MAX - 1
    cmp  eax, edx
    cmova eax, edx
    lea  r8, [rel app_res_meta + APPM_ENT]
    mov  esi, [r8 + rax*8 + 4]
    mov  eax, [r8 + rax*8]
    lea  rdi, [r14 + rax]
    mov  rdx, r12
    call app_res_tok_eq
    test eax, eax
    jnz  .entry_ok
    inc  ebx
    jmp  .entry
.entry_ok:
    xor  ebx, ebx
.recipe:
    cmp  ebx, [rel app_res_meta + APPM_NREC]
    jae  .unknown
    mov  eax, ebx
    mov  edx, APP_RECIPES_MAX - 1
    cmp  eax, edx
    cmova eax, edx
    shl  eax, 4
    lea  r15, [rel app_res_meta + APPM_REC]
    add  r15, rax
    mov  eax, [r15 + APPR_NOFF]
    mov  esi, [r15 + APPR_NLEN]
    lea  rdi, [r14 + rax]
    mov  rdx, r12
    call app_res_tok_eq
    test eax, eax
    jnz  .found
    inc  ebx
    jmp  .recipe
.found:
    mov  eax, [r15 + APPR_COUNT]
    add  eax, 3
    shr  eax, 2
    mov  [rsp], rax                     ; page count
    cmp  r13d, eax
    ja   .page
    lea  ebx, [r13d - 1]
    shl  ebx, 2
    mov  [rsp + 8], rbx                 ; first, zero-based
    lea  eax, [rbx + 4]
    cmp  eax, [r15 + APPR_COUNT]
    jbe  .end_set
    mov  eax, [r15 + APPR_COUNT]
.end_set:
    mov  [rsp + 16], rax                ; exclusive end / last one-based
    lea  rdi, [rel str_app_m_inspect]
    call app_out_str
    call app_out_ident
    lea  rdi, [rel str_app_o_caps]
    call app_out_str
    mov  rdi, [rel app_res_meta + APPM_CAPS]
    call app_out_caps
    lea  rdi, [rel str_app_o_recipe]
    call app_out_str
    mov  rdi, r12
    call app_out_str
    lea  rdi, [rel str_app_o_steps]
    call app_out_str
    mov  edi, [r15 + APPR_COUNT]
    call app_out_dec
    lea  rdi, [rel str_app_o_page]
    call app_out_str
    mov  rdi, r13
    call app_out_dec
    lea  rdi, [rel str_app_o_pages]
    call app_out_str
    mov  rdi, [rsp]
    call app_out_dec
    lea  rdi, [rel str_app_o_first]
    call app_out_str
    lea  rdi, [rbx + 1]
    call app_out_dec
    lea  rdi, [rel str_app_o_last]
    call app_out_str
    mov  rdi, [rsp + 16]
    call app_out_dec
    lea  rdi, [rel str_app_nl]
    call app_out_str
.step:
    lea  rdi, [rel str_app_o_step]
    call app_out_str
    lea  rdi, [rbx + 1]
    call app_out_dec
    lea  rdi, [rel str_app_o_call]
    call app_out_str
    mov  eax, [r15 + APPR_FIRST]
    add  rax, rbx
    mov  edx, APP_STEP_TOTAL - 1
    cmp  rax, rdx
    cmova rax, rdx
    lea  r8, [rel app_res_meta + APPM_STEP]
    mov  edi, [r8 + rax*8]
    mov  esi, [r8 + rax*8 + 4]
    call app_out_res_span
    lea  rdi, [rel str_app_nl]
    call app_out_str
    inc  ebx
    cmp  rbx, [rsp + 16]
    jb   .step
    xor  eax, eax
    jmp  .out
.badmeta:
    mov  eax, APP_RUN_INVALID
    jmp  .out
.unknown:
    mov  eax, APP_RUN_NOENTRY
    jmp  .out
.page:
    mov  eax, APP_INSPECT_PAGE
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Reply staging (app_out_buf, NUL-terminated, bounded; truncation is marked)
; ---------------------------------------------------------------------------

app_out_reset:
    mov  dword [rel app_out_len], 0
    mov  byte [rel app_out_buf], 0
    mov  byte [rel app_out_trunc], 0
    ret

; app_out_mem(RDI = ptr, ESI = len)
app_out_mem:
    mov  ecx, [rel app_out_len]
    lea  rdx, [rel app_out_buf]
.ch:
    test esi, esi
    jz   .done
    cmp  ecx, APP_OUT_MAX - 1
    jae  .full
    mov  al, [rdi]
    mov  [rdx + rcx], al
    inc  rdi
    inc  ecx
    dec  esi
    jmp  .ch
.full:
    mov  byte [rel app_out_trunc], 1
.done:
    mov  [rel app_out_len], ecx
    mov  byte [rdx + rcx], 0
    ret

; app_out_str(RDI = cstr)
app_out_str:
    xor  esi, esi
.len:
    cmp  byte [rdi + rsi], 0
    je   app_out_mem
    inc  esi
    jmp  .len

; app_out_dec(RDI = unsigned value)
app_out_dec:
    sub  rsp, 40
    lea  r8, [rsp + 32]
    mov  r9, r8
    mov  rax, rdi
    mov  ecx, 10
.dig:
    xor  edx, edx
    div  rcx
    add  dl, '0'
    dec  r9
    mov  [r9], dl
    test rax, rax
    jnz  .dig
    mov  rdi, r9
    mov  rsi, r8
    sub  rsi, r9
    call app_out_mem
    add  rsp, 40
    ret

; app_out_hex(RDI = ptr, ESI = byte count): lowercase hex
app_out_hex:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    xor  ebx, ebx
.byte:
    cmp  ebx, r13d
    jae  .done
    lea  rcx, [rel app_hexdig]
    movzx eax, byte [r12 + rbx]
    shr  eax, 4
    mov  al, [rcx + rax]
    mov  [rel app_hex2], al
    movzx eax, byte [r12 + rbx]
    and  eax, 15
    mov  al, [rcx + rax]
    mov  [rel app_hex2 + 1], al
    lea  rdi, [rel app_hex2]
    mov  esi, 2
    call app_out_mem
    inc  ebx
    jmp  .byte
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; app_out_caps(RDI = capability mask): comma-separated names ("-" for none)
app_out_caps:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    xor  ebx, ebx
    xor  r13d, r13d                       ; names written
    test r12, r12
    jnz  .name
    lea  rdi, [rel str_app_dash]
    call app_out_str
    jmp  .done
.name:
    lea  rax, [rel app_cap_names]
    mov  rdx, [rax + rbx*8]               ; rel delta; 0 ends the table
    test rdx, rdx
    jz   .done
    bt   r12, rbx
    jnc  .next
    test r13d, r13d
    jz   .first
    lea  rdi, [rel str_app_comma]
    call app_out_str
.first:
    lea  rax, [rel app_cap_names]
    mov  rdi, [rax + rbx*8]
    add  rdi, rax                         ; rel delta -> address
    call app_out_str
    inc  r13d
.next:
    inc  ebx
    jmp  .name
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; app_out_res_span(EDI = off, ESI = len) from the resident bundle
app_out_res_span:
    mov  r8, [rel app_res_ptr]
    mov  r9d, edi                       ; unsigned metadata offset; full-width cursor
    mov  ecx, [rel app_out_len]
    lea  rdx, [rel app_out_buf]
.ch:
    test esi, esi
    jz   .done
    cmp  ecx, APP_OUT_MAX - 1
    jae  .full
    ; Clip each resident source byte independently of the metadata and output
    ; bounds. Generic app_out_mem also serves non-bundle buffers; keep it raw.
    mov  r10, r9
    mov  r11d, APP_FILE_MAX - 1
    cmp  r10, r11
    cmova r10, r11
    mov  al, [r8 + r10]
    mov  [rdx + rcx], al
    inc  r9
    inc  ecx
    dec  esi
    jmp  .ch
.full:
    mov  byte [rel app_out_trunc], 1
.done:
    mov  [rel app_out_len], ecx
    mov  byte [rdx + rcx], 0
    ret

; app_out_ident: " id=<id> version=<v> key=<hex16>" of the resident bundle
app_out_ident:
    lea  rdi, [rel str_app_o_id]
    call app_out_str
    mov  edi, [rel app_res_meta + APPM_ID_OFF]
    mov  esi, [rel app_res_meta + APPM_ID_LEN]
    call app_out_res_span
    lea  rdi, [rel str_app_o_version]
    call app_out_str
    mov  edi, [rel app_res_meta + APPM_VER_OFF]
    mov  esi, [rel app_res_meta + APPM_VER_LEN]
    call app_out_res_span
    lea  rdi, [rel str_app_o_key]
    call app_out_str
    lea  rdi, [rel app_res_meta + APPM_KEYID]
    mov  esi, 16
    jmp  app_out_hex

; app_out_refusal(EDI = APP_* load verdict): the stable refusal marker
app_out_refusal:
    push rbx
    mov  ebx, edi
    cmp  ebx, APP_UNSUP_CONTAINER
    je   .container
    cmp  ebx, APP_UNSUP_SDK
    je   .sdk
    cmp  ebx, APP_UNTRUSTED
    je   .untrusted
    cmp  ebx, APP_BADSIG
    je   .badsig
    cmp  ebx, APP_BAD_MANIFEST
    je   .manifest
    cmp  ebx, APP_BAD_RECIPE
    je   .recipe
    lea  rdi, [rel str_app_m_malformed]
    call app_out_str
    mov  eax, [rel app_why]
    cmp  eax, APP_WHY_MEM
    jbe  .why_ok
    xor  eax, eax
.why_ok:
    lea  rcx, [rel app_why_names]
    mov  rdi, [rcx + rax*8]
    add  rdi, rcx                         ; rel delta -> address
    call app_out_str
    jmp  .out
.container:
    lea  rdi, [rel str_app_m_unsup_container]
    call app_out_str
    mov  rdi, [rel app_stage_ptr]
    movzx edi, word [rdi + APPH_CVER]
    call app_out_dec
    jmp  .out
.sdk:
    lea  rdi, [rel str_app_m_unsup_sdk]
    call app_out_str
    jmp  .out
.untrusted:
    lea  rdi, [rel str_app_m_untrusted]
    jmp  .key
.badsig:
    lea  rdi, [rel str_app_m_badsig]
.key:
    call app_out_str
    mov  rdi, [rel app_stage_ptr]
    add  rdi, APPH_KEYID
    mov  esi, 16
    call app_out_hex
    jmp  .out
.manifest:
    lea  rdi, [rel str_app_m_manifest]
    jmp  .line
.recipe:
    lea  rdi, [rel str_app_m_recipe]
.line:
    call app_out_str
    mov  edi, [rel app_why_line]
    call app_out_dec
.out:
    pop  rbx
    ret

; app_hexbyte(RDI = two hex digits) -> EAX = 0..255, or -1
app_hexbyte:
    movzx eax, byte [rdi]
    call app_hexnib
    test eax, eax
    js   .out
    mov  edx, eax
    movzx eax, byte [rdi + 1]
    call app_hexnib
    test eax, eax
    js   .out
    shl  edx, 4
    or   eax, edx
.out:
    ret

app_hexnib:
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .digit
    or   al, 0x20
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
    sub  eax, 'a' - 10
    ret
.digit:
    sub  eax, '0'
    ret
.no:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; VERB: APP (RDI = req, RSI = rsp). VERIFY/LOAD <path> | RUN <entry> | UNLOAD | STATUS
; ---------------------------------------------------------------------------
cmd_verb_app:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    call app_out_reset
    mov  byte [rel app_verify_only], 0
    mov  r14, [r12 + REQ_ARG]
    test r14, r14
    jz   .usage
    mov  rdi, r14
    call strlen                           ; the request text is NUL-bounded by its ingress
    mov  r15d, eax
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rel str_app_s_load]
    call app_has_prefix
    test eax, eax
    jnz  .load
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rel str_app_s_verify]
    call app_has_prefix
    test eax, eax
    jnz  .verify
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rel str_app_s_run]
    call app_has_prefix
    test eax, eax
    jnz  .run
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rel str_app_s_inspect]
    call app_has_prefix
    test eax, eax
    jnz  .inspect
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rel str_app_s_unload]
    call app_tok_eq
    test eax, eax
    jnz  .unload
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rel str_app_s_status]
    call app_tok_eq
    test eax, eax
    jnz  .status
.usage:
    lea  rdi, [rel str_app_m_usage]
    call app_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .done

.load:
    lea  rbx, [r14 + 5]
    mov  ecx, r15d
    sub  ecx, 5
    jmp  .path
.verify:
    ; Same EXTENSION admission, file bounds, trust anchors, strict RSA and
    ; parser as LOAD. Only stage scratch is touched; never publish or dispatch.
    cmp  byte [rel app_busy], 0
    jne  .verify_busy
    mov  byte [rel app_verify_only], 1
    lea  rbx, [r14 + 7]
    mov  ecx, r15d
    sub  ecx, 7
.path:
    test ecx, ecx
    jz   .usage
    cmp  ecx, APP_PATH_MAX
    ja   .usage
    mov  [rel app_path_len], ecx
    cmp  qword [rel app_stage_ptr], 0     ; first LOAD: one block for stage + resident
    jne  .have_bufs
    mov  edi, 2 * (APP_FILE_MAX + 16)
    call kmalloc                          ; clobbers rax, rdx, rdi
    test rax, rax
    jz   .no_mem
    lea  rdx, [rax + APP_FILE_MAX + 16]
    mov  [rel app_res_ptr], rdx
    mov  [rel app_stage_ptr], rax
.have_bufs:
    mov  edi, [rel vfs_disk_handle]
    cmp  edi, -1
    je   .read_fail
    mov  rsi, rbx
    mov  edx, [rel app_path_len]
    lea  rcx, [rel app_stat]
    call vfs_stat_path
    test rax, rax
    jnz  .read_fail
    mov  rax, [rel app_stat + fs_stat.size]
    cmp  rax, APP_FILE_MAX
    ja   .too_big
    mov  [rel app_file_len], eax
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, rbx
    mov  edx, [rel app_path_len]
    xor  ecx, ecx
    mov  r8, [rel app_stage_ptr]
    mov  r9d, [rel app_file_len]
    call vfs_read_at_path
    mov  ecx, [rel app_file_len]
    cmp  rax, rcx
    jne  .read_fail
    cmp  byte [rel app_verify_only], 0
    je   .verify_file
    ; Attest exactly the bounded bytes read, including a bad signature. Never
    ; attach a digest to a failed/short read or an oversized file.
    lea  rdi, [rel app_digest]
    mov  rsi, [rel app_stage_ptr]
    mov  edx, [rel app_file_len]
    call sha256_hash
    lea  rdi, [rel str_app_m_verify]
    call app_out_str
    lea  rdi, [rel app_digest]
    mov  esi, 32
    call app_out_hex
    lea  rdi, [rel str_app_o_bytes]
    call app_out_str
    mov  edi, [rel app_file_len]
    call app_out_dec
    lea  rdi, [rel str_app_nl]
    call app_out_str
.verify_file:
    mov  rdi, [rel app_stage_ptr]
    mov  esi, [rel app_file_len]
    call app_bundle_verify
    test eax, eax
    jnz  .load_refused
    cmp  byte [rel app_verify_only], 0
    jne  .verified
    ; commit: the verified stage becomes the one resident bundle
    mov  rdi, [rel app_res_ptr]
    mov  rsi, [rel app_stage_ptr]
    mov  ecx, [rel app_stage_meta + APPM_TOTAL]
    rep  movsb
    lea  rdi, [rel app_res_meta]
    lea  rsi, [rel app_stage_meta]
    mov  ecx, APPM_SZ
    rep  movsb
    mov  byte [rel app_res_loaded], 1
    inc  qword [rel app_loads]
    lea  rdi, [rel str_app_m_loaded]
    call app_out_str
    call app_out_ident
    lea  rdi, [rel str_app_o_recipes]
    call app_out_str
    mov  edi, [rel app_res_meta + APPM_NREC]
    call app_out_dec
    lea  rdi, [rel str_app_o_caps]
    call app_out_str
    mov  rdi, [rel app_res_meta + APPM_CAPS]
    call app_out_caps
    jmp  .done
.verified:
    lea  rdi, [rel str_app_m_verified]
    call app_out_str
    lea  rdi, [rel app_stage_meta + APPM_KEYID]
    mov  esi, 16
    call app_out_hex
    jmp  .done
.verify_busy:
    lea  rdi, [rel str_app_m_busy]
    call app_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .done
.read_fail:
    mov  dword [rel app_why], APP_WHY_READ
    mov  eax, APP_MALFORMED
    jmp  .load_refused
.no_mem:
    mov  dword [rel app_why], APP_WHY_MEM
    mov  eax, APP_MALFORMED
    jmp  .load_refused
.too_big:
    mov  dword [rel app_why], APP_WHY_SIZE
    mov  eax, APP_MALFORMED
.load_refused:
    mov  ebx, eax
    cmp  byte [rel app_verify_only], 0
    jne  .refusal_reply
    lea  rcx, [rel app_refused]
    inc  qword [rcx + rbx*8]
.refusal_reply:
    mov  edi, ebx
    call app_out_refusal
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .done

.inspect:
    lea  rbx, [r14 + 8]
    xor  esi, esi
.inspect_name:
    cmp  esi, APP_NAME_MAX
    ja   .usage
    cmp  byte [rbx + rsi], ' '
    je   .inspect_page
    cmp  byte [rbx + rsi], 0
    je   .usage
    inc  esi
    jmp  .inspect_name
.inspect_page:
    mov  r15d, esi
    mov  rdi, rbx
    call app_name_ok
    test eax, eax
    jz   .usage
    movzx esi, byte [rbx + r15 + 1]
    sub  esi, '0'
    cmp  esi, 1
    jb   .usage
    cmp  esi, 4
    ja   .usage
    cmp  byte [rbx + r15 + 2], 0
    jne  .usage
    ; Private bounded name, so INSPECT never changes RUN's shared app_line
    ; scratch, even when app_busy refuses it. Wipe before releasing the frame.
    sub  rsp, 40
    mov  r8d, esi
    mov  ecx, r15d
    mov  rdi, rsp
    mov  rsi, rbx
    rep  movsb
    mov  byte [rdi], 0
    mov  esi, r8d
    mov  rdi, rsp
    call app_bundle_inspect
    mov  r8d, eax
    mov  rdi, rsp
    xor  eax, eax
    mov  ecx, 5
    rep  stosq
    add  rsp, 40
    mov  eax, r8d
    cmp  eax, APP_RUN_OK
    je   .done
    cmp  eax, APP_RUN_NONE
    je   .run_none
    cmp  eax, APP_RUN_NOENTRY
    je   .inspect_unknown
    cmp  eax, APP_RUN_INVALID
    je   .run_invalid
    cmp  eax, APP_INSPECT_PAGE
    je   .inspect_badpage
    jmp  .run_busy
.inspect_unknown:
    lea  rdi, [rel str_app_m_noentry]
    call app_out_str
    mov  rdi, rbx
    mov  esi, r15d
    call app_out_mem
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .done
.inspect_badpage:
    lea  rdi, [rel str_app_m_inspect_page]
    call app_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .done

.run:
    cmp  r15d, 4
    jbe  .usage
    mov  rdi, r12
    lea  rsi, [r14 + 4]
    call app_bundle_run
    mov  ebx, eax
    cmp  ebx, APP_RUN_OK
    je   .run_ok
    cmp  ebx, APP_RUN_NONE
    je   .run_none
    cmp  ebx, APP_RUN_NOENTRY
    je   .run_noentry
    cmp  ebx, APP_RUN_UNLISTED
    je   .run_unlisted
    cmp  ebx, APP_RUN_DENIED
    je   .run_denied
    cmp  ebx, APP_RUN_FAILED
    je   .run_failed
    cmp  ebx, APP_RUN_INVALID
    je   .run_invalid
.run_busy:
    lea  rdi, [rel str_app_m_busy]
    call app_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .done
.run_invalid:
    lea  rdi, [rel str_app_m_invalid]
    call app_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .done
.run_ok:
    lea  rdi, [rel str_app_m_run_ok]
    call app_out_str
    call app_out_ident
    lea  rdi, [rel str_app_o_recipe]
    call app_out_str
    lea  rdi, [r14 + 4]
    call app_out_str
    lea  rdi, [rel str_app_o_steps]
    call app_out_str
    mov  edi, [rel app_r_step]
    call app_out_dec
    jmp  .done
.run_none:
    lea  rdi, [rel str_app_m_none]
    call app_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADSEL
    jmp  .done
.run_noentry:
    lea  rdi, [rel str_app_m_noentry]
    call app_out_str
    lea  rdi, [r14 + 4]
    call app_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .done
.run_unlisted:
    lea  rdi, [rel str_app_m_unlisted]
    call app_out_str
    call .step_verb
    mov  qword [r13 + RSP_CODE], CMDE_CAPDENY
    jmp  .done
.run_denied:
    lea  rdi, [rel str_app_m_denied]
    call app_out_str
    call .step_verb
    lea  rdi, [rel str_app_o_cap]
    call app_out_str
    mov  rax, [rel app_r_row]
    mov  rdi, [rax + APPT_CAP]
    call app_out_caps
    mov  qword [r13 + RSP_CODE], CMDE_CAPDENY
    jmp  .done
.run_failed:
    lea  rdi, [rel str_app_m_failed]
    call app_out_str
    lea  rdi, [r14 + 4]
    call app_out_str
    lea  rdi, [rel str_app_o_step_kv]
    call app_out_str
    mov  edi, [rel app_r_step]
    call app_out_dec
    lea  rdi, [rel str_app_o_code]
    call app_out_str
    mov  rdi, [rel app_r_code]
    call app_out_dec
    mov  rax, [rel app_r_code]
    mov  [r13 + RSP_CODE], rax
    jmp  .done
.step_verb:                               ; " step=<n> verb=<V>"
    lea  rdi, [rel str_app_o_step_kv]
    call app_out_str
    mov  edi, [rel app_r_step]
    call app_out_dec
    lea  rdi, [rel str_app_o_verb]
    call app_out_str
    lea  rdi, [rel app_line]
    jmp  app_out_str

.unload:
    mov  byte [rel app_res_loaded], 0
    lea  rdi, [rel str_app_m_unloaded]
    call app_out_str
    jmp  .done

.status:
    lea  rdi, [rel str_app_m_status]
    call app_out_str
    movzx edi, byte [rel app_res_loaded]
    call app_out_dec
    cmp  byte [rel app_res_loaded], 1
    jne  .status_counts
    call app_out_ident
    lea  rdi, [rel str_app_o_caps]
    call app_out_str
    mov  rdi, [rel app_res_meta + APPM_CAPS]
    call app_out_caps
.status_counts:
    lea  rdi, [rel str_app_o_loads]
    call app_out_str
    mov  rdi, [rel app_loads]
    call app_out_dec
    lea  rdi, [rel str_app_o_refused]
    call app_out_str
    xor  eax, eax
    xor  ecx, ecx
    lea  rdx, [rel app_refused]
.sum:
    add  rax, [rdx + rcx*8]
    inc  ecx
    cmp  ecx, 8
    jb   .sum
    mov  rdi, rax
    call app_out_dec
    lea  rdi, [rel str_app_o_denied]
    call app_out_str
    mov  rdi, [rel app_denied]
    call app_out_dec
    lea  rdi, [rel str_app_o_dispatches]
    call app_out_str
    mov  rdi, [rel app_dispatches]
    call app_out_dec

.done:
    mov  byte [rel app_out_ready], 1
    mov  rax, [r13 + RSP_CODE]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; VERB: APPKEY (RDI = req, RSI = rsp). ADD <512 hex> | DEL <32 hex> | LIST
; ---------------------------------------------------------------------------
cmd_verb_appkey:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    call app_out_reset
    mov  r14, [r12 + REQ_ARG]
    test r14, r14
    jz   .usage
    mov  rdi, r14
    call strlen                           ; the request text is NUL-bounded by its ingress
    mov  r15d, eax
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rel str_app_s_add]
    call app_has_prefix
    test eax, eax
    jnz  .add
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rel str_app_s_del]
    call app_has_prefix
    test eax, eax
    jnz  .del
    mov  rdi, r14
    mov  esi, r15d
    lea  rdx, [rel str_app_s_list]
    call app_tok_eq
    test eax, eax
    jnz  .list
.usage:
    lea  rdi, [rel str_app_m_key_usage]
    call app_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .done

.add:
    cmp  r15d, 4 + 512
    jne  .usage
    xor  ebx, ebx                         ; big-endian byte index
.add_hex:
    lea  rdi, [r14 + 4 + rbx*2]
    call app_hexbyte
    test eax, eax
    js   .usage
    mov  ecx, 255
    sub  ecx, ebx
    lea  rdx, [rel app_tmp_mod]
    mov  [rdx + rcx], al                  ; stored little-endian
    inc  ebx
    cmp  ebx, 256
    jb   .add_hex
    lea  rdi, [rel app_tmp_mod]
    call app_trust_add
    test eax, eax
    jns  .added
    cmp  eax, -1
    je   .full
    cmp  eax, -2
    je   .dup
    lea  rdi, [rel str_app_m_key_bad]
    call app_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .done
.added:
    lea  rdi, [rel str_app_m_key_added]
    jmp  .with_id
.full:
    lea  rdi, [rel str_app_m_key_full]
    call app_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .done
.dup:
    lea  rdi, [rel str_app_m_key_dup]
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.with_id:
    call app_out_str
    lea  rdi, [rel app_tmp_id]
    mov  esi, 16
    call app_out_hex
    jmp  .done

.del:
    cmp  r15d, 4 + 32
    jne  .usage
    xor  ebx, ebx
.del_hex:
    lea  rdi, [r14 + 4 + rbx*2]
    call app_hexbyte
    test eax, eax
    js   .usage
    lea  rdx, [rel app_tmp_id]
    mov  [rdx + rbx], al
    inc  ebx
    cmp  ebx, 16
    jb   .del_hex
    lea  rdi, [rel app_tmp_id]
    call app_trust_del
    test eax, eax
    jz   .deleted
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    lea  rdi, [rel str_app_m_key_unknown]
    cmp  eax, -1
    je   .with_id
    lea  rdi, [rel str_app_m_key_owner]
    jmp  .with_id
.deleted:
    lea  rdi, [rel str_app_m_key_deleted]
    jmp  .with_id

.list:
    call app_owner_id_ready
    lea  rdi, [rel str_app_m_keys]
    call app_out_str
    cmp  byte [rel app_owner_ready], 1
    jne  .list_no_owner
    lea  rdi, [rel app_owner_id]
    mov  esi, 16
    call app_out_hex
    jmp  .list_added
.list_no_owner:
    lea  rdi, [rel str_app_dash]
    call app_out_str
.list_added:
    xor  ebx, ebx
.list_slot:
    cmp  ebx, APP_KEYS_MAX
    jae  .done
    imul rax, rbx, APPK_SZ
    lea  r15, [rel app_keys]
    add  r15, rax
    cmp  byte [r15 + APPK_USED], 1
    jne  .list_next
    lea  rdi, [rel str_app_o_key]
    call app_out_str
    lea  rdi, [r15 + APPK_ID]
    mov  esi, 16
    call app_out_hex
.list_next:
    inc  ebx
    jmp  .list_slot

.done:
    mov  byte [rel app_out_ready], 1
    mov  rax, [r13 + RSP_CODE]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Tables, strings and state
; ---------------------------------------------------------------------------
align 8
; APP VERB TABLE, contract v1 (rc-resource 19:46:40, bound with rc-codex-relops' SDK).
; Each row is exact text except named bounded audio/GUI patterns. Manifest
; permission is checked by the loader only and grants no PaOS authority
; (the native verb's own gate still runs).
; Additive: a new row (for example another HOOK DESCRIBE <edge>) never changes an
; existing row's meaning.
app_verb_table:
    dq str_verb_hook_app - app_verb_table, str_app_a_get_net - app_verb_table, APP_CAP_NET_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_a_list - app_verb_table, APP_CAP_SYS_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_a_describe_net - app_verb_table, APP_CAP_SYS_READ, 1
    dq str_verb_status_app - app_verb_table, str_app_empty - app_verb_table, APP_CAP_SYS_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_a_get_fs - app_verb_table, APP_CAP_FS_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_a_describe_fs - app_verb_table, APP_CAP_SYS_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_a_describe_audio - app_verb_table, APP_CAP_SYS_READ, 1
app_verb_audio_playback:
    dq str_verb_hook_app - app_verb_table, str_app_a_audio_playback - app_verb_table, APP_CAP_SYS_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_a_get_forms - app_verb_table, APP_CAP_SYS_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_a_describe_forms - app_verb_table, APP_CAP_SYS_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_a_describe_form - app_verb_table, APP_CAP_SYS_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_a_describe_widget - app_verb_table, APP_CAP_SYS_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_a_catalog - app_verb_table, APP_CAP_SYS_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_a_widgets - app_verb_table, APP_CAP_GUI_READ, 1
app_verb_gui_patterns:
    dq str_verb_hook_app - app_verb_table, str_app_p_catalog - app_verb_table, APP_CAP_SYS_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_p_widgets - app_verb_table, APP_CAP_GUI_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_p_widget_get - app_verb_table, APP_CAP_GUI_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_p_widget_observe - app_verb_table, APP_CAP_GUI_READ, 1
    dq str_verb_hook_app - app_verb_table, str_app_p_widget_set - app_verb_table, APP_CAP_GUI_WRITE, 1
    dq str_verb_hook_app - app_verb_table, str_app_p_form - app_verb_table, APP_CAP_SYS_READ, 1
app_verb_gui_end:
    dq 0, 0, 0, 0
app_cap_names:
    dq str_app_cap_net_read - app_cap_names
    dq str_app_cap_sys_read - app_cap_names
    dq str_app_cap_fs_read - app_cap_names
    dq str_app_cap_gui_read - app_cap_names
    dq str_app_cap_gui_write - app_cap_names
    dq 0
app_gui_fields:
    dq str_app_g_role - app_gui_fields, str_app_g_label - app_gui_fields
    dq str_app_g_intent - app_gui_fields, str_app_g_seq - app_gui_fields
    dq str_app_g_value - app_gui_fields, str_app_g_min - app_gui_fields
    dq str_app_g_max - app_gui_fields, str_app_g_step - app_gui_fields
    dq str_app_g_sel - app_gui_fields, 0
app_why_names:
    dq str_app_dash - app_why_names
    dq str_app_why_size - app_why_names
    dq str_app_why_magic - app_why_names
    dq str_app_why_hdrsize - app_why_names
    dq str_app_why_total - app_why_names
    dq str_app_why_manifest - app_why_names
    dq str_app_why_recipes - app_why_names
    dq str_app_why_assets - app_why_names
    dq str_app_why_flags - app_why_names
    dq str_app_why_reserved - app_why_names
    dq str_app_why_read - app_why_names
    dq str_app_why_mem - app_why_names

str_verb_app:          db "APP", 0
str_verb_appkey:       db "APPKEY", 0
str_verb_hook_app:     db "HOOK", 0
str_verb_status_app:   db "STATUS", 0
str_app_a_describe_audio: db "DESCRIBE audio", 0
str_app_a_audio_playback: db "GET audio playback ", 0
str_app_a_get_fs:      db "GET fs", 0
str_app_a_describe_fs: db "DESCRIBE fs", 0
str_app_a_get_net:     db "GET net", 0
str_app_a_list:        db "LIST", 0
str_app_a_describe_net: db "DESCRIBE net", 0
str_app_a_get_forms: db "GET forms", 0
str_app_a_describe_forms: db "DESCRIBE forms", 0
str_app_a_describe_form: db "DESCRIBE form", 0
str_app_a_describe_widget: db "DESCRIBE widget", 0
str_app_a_catalog: db "CATALOG", 0
str_app_a_widgets: db "LIST widget", 0
str_app_p_catalog: db "CATALOG ", 2, 0
str_app_p_widgets: db "LIST widget ", 1, 0
str_app_p_widget_get: db "GET widget:", 1, " ", 7, 0
str_app_p_widget_observe: db "OBSERVE widget:", 1, " ", 7, 0
str_app_p_widget_set: db "SET widget:", 1, " value ", 1, 0
str_app_p_form: db "GET form:", 3, " page ", 4, " read ", 5, " ", 6, 0
str_app_g_role: db "role", 0
str_app_g_label: db "label", 0
str_app_g_intent: db "intent", 0
str_app_g_seq: db "intent_seq", 0
str_app_g_value: db "value", 0
str_app_g_min: db "min", 0
str_app_g_max: db "max", 0
str_app_g_step: db "step", 0
str_app_g_sel: db "sel", 0
str_app_empty:         db 0
str_app_cap_net_read:  db "net.read", 0
str_app_cap_sys_read:  db "sys.read", 0
str_app_cap_fs_read:   db "fs.read", 0
str_app_cap_gui_read:  db "gui.read", 0
str_app_cap_gui_write: db "gui.write", 0
str_app_k_id:          db "id=", 0
str_app_k_version:     db "version=", 0
str_app_k_caps:        db "caps=", 0
str_app_k_entry:       db "entry=", 0
str_app_k_recipe:      db "recipe ", 0
str_app_k_step:        db "step ", 0
str_app_s_load:        db "LOAD ", 0
str_app_s_verify:      db "VERIFY ", 0
str_app_s_run:         db "RUN ", 0
str_app_s_unload:      db "UNLOAD", 0
str_app_s_status:      db "STATUS", 0
str_app_s_inspect:     db "INSPECT ", 0
str_app_s_add:         db "ADD ", 0
str_app_s_del:         db "DEL ", 0
str_app_s_list:        db "LIST", 0
str_app_why_size:      db "size", 0
str_app_why_magic:     db "magic", 0
str_app_why_hdrsize:   db "header_size", 0
str_app_why_total:     db "total_size", 0
str_app_why_manifest:  db "manifest_range", 0
str_app_why_recipes:   db "recipes_range", 0
str_app_why_assets:    db "assets_range", 0
str_app_why_flags:     db "flags", 0
str_app_why_reserved:  db "reserved", 0
str_app_why_read:      db "read", 0
str_app_why_mem:       db "mem", 0
str_app_m_usage:       db "[app.usage] APP LOAD <path> | VERIFY <path> | RUN <entry> | INSPECT <entry> <page1..4> | UNLOAD | STATUS", 0
str_app_m_key_usage:   db "[app.usage] APPKEY ADD <512 hex modulus> | DEL <32 hex key id> | LIST", 0
str_app_m_malformed:   db "[app.bundle.malformed] why=", 0
str_app_m_manifest:    db "[app.bundle.malformed] why=manifest line=", 0
str_app_m_recipe:      db "[app.bundle.malformed] why=recipe line=", 0
str_app_m_unsup_container: db "[app.contract.unsupported] layer=container v=", 0
str_app_m_unsup_sdk:   db "[app.contract.unsupported] layer=sdk", 0
str_app_m_untrusted:   db "[app.sig.untrusted] key=", 0
str_app_m_badsig:      db "[app.sig.bad] key=", 0
str_app_m_loaded:      db "[app.loaded]", 0
str_app_m_verify:      db "[app.verify] sha256=", 0
str_app_m_verified:    db "[app.verified] key=", 0
str_app_o_bytes:       db " bytes=", 0
str_app_m_unloaded:    db "[app.unloaded]", 0
str_app_m_status:      db "[app.status] loaded=", 0
str_app_m_inspect:     db "[app.inspect]", 0
str_app_m_inspect_page: db "[app.inspect.page] outside recipe pages", 0
str_app_m_run_ok:      db "[app.run.ok]", 0
str_app_m_none:        db "[app.none] no bundle is loaded", 0
str_app_m_noentry:     db "[app.entry.unknown] entry=", 0
str_app_m_unlisted:    db "[app.verb.unlisted]", 0
str_app_m_denied:      db "[app.cap.denied]", 0
str_app_m_failed:      db "[app.step.failed] recipe=", 0
str_app_m_busy:        db "[app.busy]", 0
str_app_m_invalid:     db "[app.invalid] resident bundle invalid; unload and reload", 0
str_app_m_key_added:   db "[app.key.added] key=", 0
str_app_m_key_dup:     db "[app.key.duplicate] key=", 0
str_app_m_key_full:    db "[app.key.full]", 0
str_app_m_key_bad:     db "[app.key.bad] why=not_rsa2048", 0
str_app_m_key_unknown: db "[app.key.unknown] key=", 0
str_app_m_key_owner:   db "[app.key.owner] the owner key is never removed key=", 0
str_app_m_key_deleted: db "[app.key.deleted] key=", 0
str_app_m_keys:        db "[app.keys] owner=", 0
str_app_o_id:          db " id=", 0
str_app_o_version:     db " version=", 0
str_app_o_key:         db " key=", 0
str_app_o_recipes:     db " recipes=", 0
str_app_o_recipe:      db " recipe=", 0
str_app_o_page:        db " page=", 0
str_app_o_pages:       db " pages=", 0
str_app_o_first:       db " first=", 0
str_app_o_last:        db " last=", 0
str_app_o_call:        db " call=", 0
str_app_o_caps:        db " caps=", 0
str_app_o_cap:         db " cap=", 0
str_app_o_steps:       db " steps=", 0
str_app_o_step:        db "step=", 0
str_app_o_step_kv:     db " step=", 0
str_app_o_verb:        db " verb=", 0
str_app_o_code:        db " code=", 0
str_app_o_val:         db " val=", 0
str_app_o_loads:       db " loads=", 0
str_app_o_refused:     db " refused=", 0
str_app_o_denied:      db " denied=", 0
str_app_o_dispatches:  db " dispatches=", 0
str_app_dash:          db "-", 0
str_app_comma:         db ",", 0
str_app_nl:            db 10, 0
app_hexdig:            db "0123456789abcdef"

align 8
app_v_buf:        dq 0
app_r_req:        dq 0
app_r_entry:      dq 0
app_r_args:       dq 0
app_r_row:        dq 0
app_r_verb:       dq 0
app_r_code:       dq 0
app_loads:        dq 0
app_denied:       dq 0
app_dispatches:   dq 0
app_refused:      times 8 dq 0
app_req:          times 8 dq 0            ; REQ_SZ (56) rounded up
app_rsp:          times 6 dq 0            ; RSP_SZ
app_stat:         times 2 dq 0            ; fs_stat
app_tmp_id:       times 16 db 0
app_owner_id:     times 16 db 0
app_digest:       times 32 db 0
app_why:          dd 0
app_why_line:     dd 0
app_lp:           dd 0
app_lend:         dd 0
app_lineno:       dd 0
app_cap_end:      dd 0
app_cap_next:     dd 0
app_tmp_off:      dd 0
app_tmp_len:      dd 0
app_path_len:     dd 0
app_file_len:     dd 0
app_r_step:       dd 0
app_out_len:      dd 0
app_hex2:         dw 0
app_owner_ready:  db 0
app_res_loaded:   db 0
app_busy:         db 0
app_verify_only:  db 0
app_out_ready:    db 0
app_out_trunc:    db 0
app_nolf:         db 0
align 8
app_stage_ptr:    dq 0                   ; heap, APP_FILE_MAX + 16 each (first LOAD)
app_res_ptr:      dq 0
app_stage_meta:   times APPM_SZ db 0
app_res_meta:     times APPM_SZ db 0
app_keys:         times APP_KEYS_MAX * APPK_SZ db 0
app_be_tmp:       times 256 db 0
app_tmp_mod:      times 256 db 0
app_line:         times APP_LINE_MAX + 8 db 0
app_out_buf:      times APP_OUT_MAX db 0
