;; MODULE gui/command_res
;; LAYER 6
;; EXPORTS gres_declare, gres_out_buf, gres_out_ready, gres_out_cur
;; IMPORTS svc/command, core/lib/fmt, core/lib/sha256, boot/gop, boot/boot_v2_handoff, boot/serial, gui/window, gui/chat_app
;; CAPS
;; OWNER saga:gui
; ============================================================================
; gui/command_res.asm — resolution/autodetect PROJECTION over the ONE 1077
; registry: RESINFO / RESMODES / GOP / EDID.
;
; The DETECTION lives in boot/gop.asm (gop_autodetect, pre-EBS — QueryMode/
; SetMode/EDID are boot services); this module only FRAMES the captured facts
; on the wire so the bare-metal probe can content-grade them:
;   RESINFO  -> " RESINFO native=<W>x<H> active=<W>x<H> src=edid|gop dpi=<N> modes=<N>"
;               native  = the detected monitor-native mode (EDID preferred, else
;                         the max GOP mode — never a hardcode)
;               active  = the LIVE render surface (fb_width/fb_height re-read per
;                         call, not a boot-time copy: active==native is earned)
;               src     = where native came from (edid|gop; none = no detect ran)
;   RESMODES -> " RESMODES n=<N> cur=<W>x<H> <W>x<H> <W>x<H> ..." — the box's own
;               enumerated GOP inventory (boot-time capture: QueryMode dies at
;               ExitBootServices), the probe's source of truth that native is
;               the MAX supported mode, not a fallback.
;   EDID <nonce> -> the exact validated 128/256-byte pre-EBS firmware record,
;               with count/checksum/SHA-256 facts and complete lowercase hex.
;
; Replies stage into gres_out_buf and take command_udp's LEAN path (same
; clamp-safety pattern as BLK/widget: emitted before the marker blocks so a
; 64-mode list can never truncate mid-token).
; ============================================================================

GRES_OUT_MAX equ 1024

; ---------------------------------------------------------------------------
; gres_declare — register RESINFO + RESMODES + GOP + EDID through the SAME
;   command_register_verb (additive, no registry-core edit). clobbers: caller-saved.
; ---------------------------------------------------------------------------
gres_declare:
    push rbx
    push r12
    push r13
    xor  ebx, ebx
    lea  rdi, [rel str_verb_resinfo]
    lea  rsi, [rel cmd_verb_resinfo]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                        ; read-only
    call command_register_verb
    or   ebx, eax
    lea  rdi, [rel str_verb_resmodes]
    lea  rsi, [rel cmd_verb_resmodes]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                        ; read-only
    call command_register_verb
    or   ebx, eax
    lea  rdi, [rel str_verb_gop]
    lea  rsi, [rel cmd_verb_gop]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                        ; read-only
    call command_register_verb
    mov  r12d, eax
    or   ebx, eax
    lea  rdi, [rel str_verb_edid]
    lea  rsi, [rel cmd_verb_edid]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                        ; read-only
    call command_register_verb
    mov  r13d, eax
    or   ebx, eax
    lea  rdi, [rel str_verb_resset]
    lea  rsi, [rel cmd_verb_resset]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                         ; DESTRUCTIVE: reprograms live scanout
    call command_register_verb
    or   ebx, eax
    lea  rdi, [rel str_verb_displays]
    lea  rsi, [rel cmd_verb_displays]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                        ; read-only
    call command_register_verb
    or   ebx, eax
    lea  rdi, [rel str_verb_gophealth]  ; 1249 P53 self-detection oracle (public read)
    lea  rsi, [rel cmd_verb_gophealth]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                        ; read-only
    call command_register_verb
    or   ebx, eax
    test ebx, ebx
    js   .fail
    mov  edi, r13d
    call gres_edid_selftest
    call gres_edid_oracle_kat          ; Task3474 DH2: guest EDID oracle digest KAT
    mov  edi, r12d
    call gres_gop_selftest
    pop  r13
    pop  r12
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_gres_regfail]
    call serial_string
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- bounded out-buffer helpers (same shape as widget's wgt_out_*) ---
gres_out_reset:
    lea  rax, [rel gres_out_buf]
    mov  [rel gres_out_cur], rax
    ret
gres_out_str:
    mov  rsi, [rel gres_out_cur]
    lea  rdx, [rel gres_out_buf + GRES_OUT_MAX - 1]
.cp:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel gres_out_cur], rsi
    ret
gres_out_dec:
    mov  rsi, [rel gres_out_cur]
    lea  rax, [rel gres_out_buf + GRES_OUT_MAX - 24]
    cmp  rsi, rax
    jae  .skip                         ; <24 bytes headroom: clamp (fmt_dec needs room)
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel gres_out_cur], rsi
.skip:
    ret

; gres_out_hex64(RDI=value) -- append exactly sixteen lowercase hex digits.
gres_out_hex64:
    mov  rsi, [rel gres_out_cur]
    lea  rax, [rel gres_out_buf + GRES_OUT_MAX - 17]
    cmp  rsi, rax
    ja   .skip
    push rsi
    mov  edx, 16
    call fmt_hex
    pop  rsi
    add  rsi, rax
    mov  [rel gres_out_cur], rsi
.skip:
    ret

; gop_nonce_valid(RDI=cstr) -> EAX=1 only for 1..64 [A-Za-z0-9._:-] bytes.
; The bounded grammar prevents an argument from injecting another GOP field.
gop_nonce_valid:
    test rdi, rdi
    jz   .bad
    xor  ecx, ecx
.next:
    movzx eax, byte [rdi + rcx]
    test al, al
    jz   .end
    cmp  ecx, 64
    jae  .bad
    cmp  al, '0'
    jb   .punct
    cmp  al, '9'
    jbe  .accept
    cmp  al, 'A'
    jb   .punct
    cmp  al, 'Z'
    jbe  .accept
    cmp  al, 'a'
    jb   .punct
    cmp  al, 'z'
    jbe  .accept
.punct:
    cmp  al, '.'
    je   .accept
    cmp  al, '_'
    je   .accept
    cmp  al, ':'
    je   .accept
    cmp  al, '-'
    jne  .bad
.accept:
    inc  ecx
    jmp  .next
.end:
    test ecx, ecx
    jz   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; gres_out_raw_bytes(RDI=bytes, ESI=count) — append exactly two lowercase hex
; digits per byte. Returns EAX=1 when the complete value fit, else 0 without
; writing a partial byte.
gres_out_raw_bytes:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    mov  rbx, [rel gres_out_cur]
.next:
    test r13d, r13d
    jz   .ok
    lea  rax, [rel gres_out_buf + GRES_OUT_MAX - 1]
    lea  rcx, [rbx + 2]
    cmp  rcx, rax
    ja   .full
    movzx edi, byte [r12]
    mov  rsi, rbx
    mov  edx, 2
    call fmt_hex
    add  rbx, rax
    inc  r12
    dec  r13d
    jmp  .next
.ok:
    mov  byte [rbx], 0
    mov  [rel gres_out_cur], rbx
    mov  eax, 1
    jmp  .out
.full:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; VERB: EDID <nonce> — project the exact validated pre-EBS record. Fixed order:
;   EDID nonce=<token> present=<0|1> bytes=<0|128|256> blocks=<0|1|2>
;        checksum=<none|ok> sha256=<-|64 lowercase hex> data=<-|complete hex>
; The 256-byte maximum stays below GRES_OUT_MAX and the UDP payload ceiling.
; ---------------------------------------------------------------------------
cmd_verb_edid:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, [rdi + REQ_ARG]
    mov  r14, rsi
    mov  rdi, r12
    call gop_nonce_valid
    test eax, eax
    jz   .bad_nonce

    movzx eax, byte [rel gop_edid_present]
    test eax, eax
    jz   .absent
    cmp  eax, 1
    jne  .bad_record
    mov  ebx, [rel gop_edid_bytes]
    cmp  ebx, 128
    je   .size_ok
    cmp  ebx, 256
    jne  .bad_record
.size_ok:
    movzx eax, byte [rel gop_edid_blocks]
    mov  edx, ebx
    shr  edx, 7
    cmp  eax, edx
    jne  .bad_record
    cmp  byte [rel gop_edid_checksum_ok], 1
    jne  .bad_record
    lea  r13, [rel gop_edid_raw]
    xor  r15d, r15d
.block:
    xor  edx, edx
    mov  ecx, 128
.sum:
    add  dl, [r13 + r15]
    inc  r15d
    loop .sum
    test dl, dl
    jnz  .bad_record
    cmp  r15d, ebx
    jb   .block
    movzx eax, byte [r13 + 126]
    inc  eax
    movzx edx, byte [rel gop_edid_blocks]
    cmp  eax, edx
    jne  .bad_record
    lea  rdi, [rel gres_edid_digest]
    mov  rsi, r13
    mov  edx, ebx
    call sha256_hash
    test rax, rax
    jnz  .bad_record

    call gres_out_reset
    lea  rdi, [rel str_gres_edid_nonce]
    call gres_out_str
    mov  rdi, r12
    call gres_out_str
    lea  rdi, [rel str_gres_edid_present]
    call gres_out_str
    mov  edi, 1
    call gres_out_dec
    lea  rdi, [rel str_gres_edid_bytes]
    call gres_out_str
    mov  edi, ebx
    call gres_out_dec
    lea  rdi, [rel str_gres_edid_blocks]
    call gres_out_str
    movzx edi, byte [rel gop_edid_blocks]
    call gres_out_dec
    lea  rdi, [rel str_gres_edid_checksum]
    call gres_out_str
    lea  rdi, [rel str_gres_edid_ok]
    call gres_out_str
    lea  rdi, [rel str_gres_edid_sha]
    call gres_out_str
    lea  rdi, [rel gres_edid_digest]
    mov  esi, 32
    call gres_out_raw_bytes
    test eax, eax
    jz   .bad_record
    lea  rdi, [rel str_gres_edid_data]
    call gres_out_str
    mov  rdi, r13
    mov  esi, ebx
    call gres_out_raw_bytes
    test eax, eax
    jz   .bad_record
    jmp  .success

.absent:
    ; An invalid flag is publishable only with fully cleared metadata/storage.
    cmp  dword [rel gop_edid_bytes], 0
    jne  .bad_record
    cmp  byte [rel gop_edid_blocks], 0
    jne  .bad_record
    cmp  byte [rel gop_edid_checksum_ok], 0
    jne  .bad_record
    lea  r13, [rel gop_edid_raw]
    xor  eax, eax
.zero_scan:
    cmp  qword [r13 + rax], 0
    jne  .bad_record
    add  eax, 8
    cmp  eax, 256
    jb   .zero_scan
    call gres_out_reset
    lea  rdi, [rel str_gres_edid_nonce]
    call gres_out_str
    mov  rdi, r12
    call gres_out_str
    lea  rdi, [rel str_gres_edid_absent]
    call gres_out_str
.success:
    mov  byte [rel gres_out_ready], 1
    mov  [r14 + RSP_VAL], r12
    mov  qword [r14 + RSP_CODE], CMDE_OK
    jmp  .done
.bad_nonce:
    call gres_out_reset
    lea  rdi, [rel str_gres_edid_bad_nonce]
    call gres_out_str
    mov  byte [rel gres_out_ready], 1
    mov  qword [r14 + RSP_CODE], CMDE_BADARG
    jmp  .done
.bad_record:
    call gres_out_reset
    lea  rdi, [rel str_gres_edid_bad_record]
    call gres_out_str
    mov  byte [rel gres_out_ready], 1
    mov  qword [r14 + RSP_CODE], CMDE_BADSEL
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Construct deterministic host-reproducible valid 128/256-byte fixtures in
; gres_out_buf. The 256-byte case adds a minimal 02/03 extension.
gres_edid_make_fixture:
    lea  rdi, [rel gres_out_buf]
    xor  eax, eax
    mov  ecx, 32
    rep  stosq
    mov  rax, 0x00ffffffffffff00
    mov  [rel gres_out_buf], rax
    cmp  esi, 256
    je   .two
    mov  byte [rel gres_out_buf + 126], 0
    mov  byte [rel gres_out_buf + 127], 6
    lea  rax, [rel gres_out_buf]
    ret
.two:
    mov  byte [rel gres_out_buf + 126], 1
    mov  byte [rel gres_out_buf + 127], 5
    mov  byte [rel gres_out_buf + 128], 2
    mov  byte [rel gres_out_buf + 129], 3
    mov  byte [rel gres_out_buf + 255], 0xfb
    lea  rax, [rel gres_out_buf]
    ret

gres_edid_record_matches:
    push rbx
    mov  ebx, esi
    cmp  byte [rel gop_edid_present], 1
    jne  .no
    cmp  [rel gop_edid_bytes], ebx
    jne  .no
    mov  eax, ebx
    shr  eax, 7
    movzx edx, byte [rel gop_edid_blocks]
    cmp  eax, edx
    jne  .no
    cmp  byte [rel gop_edid_checksum_ok], 1
    jne  .no
    mov  rcx, rbx
    lea  rsi, [rel gop_edid_raw]
    repe cmpsb
    jne  .no
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; Negative vectors must erase metadata and every byte, not merely clear present.
gres_edid_record_zero:
    cmp  byte [rel gop_edid_present], 0
    jne  .no
    cmp  dword [rel gop_edid_bytes], 0
    jne  .no
    cmp  byte [rel gop_edid_blocks], 0
    jne  .no
    cmp  byte [rel gop_edid_checksum_ok], 0
    jne  .no
    lea  rdi, [rel gop_edid_raw]
    mov  ecx, 32
.scan:
    cmp  qword [rdi], 0
    jne  .no
    add  rdi, 8
    loop .scan
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

gres_edid_emit_kat_line:
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    lea  rdi, [rel gres_edid_digest]
    lea  rsi, [rel gop_edid_raw]
    mov  edx, r13d
    call sha256_hash
    test rax, rax
    jnz  .fail
    call gres_out_reset
    mov  rdi, r12
    call gres_out_str
    lea  rdi, [rel gres_edid_digest]
    mov  esi, 32
    call gres_out_raw_bytes
    test eax, eax
    jz   .fail
    lea  rdi, [rel str_gres_edid_data]
    call gres_out_str
    lea  rdi, [rel gop_edid_raw]
    mov  esi, r13d
    call gres_out_raw_bytes
    test eax, eax
    jz   .fail
    lea  rdi, [rel gres_out_buf]
    call serial_string
    lea  rdi, [rel str_gres_nl]
    call serial_string
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    ret

; Valid fixtures, invalid vectors, and maximum reply all exercise the same
; validation/publication helper and registered EDID handler used in production.
gres_edid_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 384
    mov  r14, rsp
    mov  r15d, edi
    lea  rsi, [rel gop_edid_raw]
    mov  rdi, r14
    mov  ecx, 32
    rep  movsq
    mov  eax, [rel gop_edid_bytes]
    mov  [r14 + 256], eax
    mov  al, [rel gop_edid_blocks]
    mov  [r14 + 260], al
    mov  al, [rel gop_edid_checksum_ok]
    mov  [r14 + 261], al
    mov  al, [rel gop_edid_present]
    mov  [r14 + 262], al
    mov  r13d, 1
    cmp  r15d, -1
    je   .fail

    ; The KAT must not sanitize a broken live record before the runtime oracle
    ; sees it. Validate the saved state before mutating the shared publisher.
    cmp  byte [r14 + 262], 1
    jne  .saved_absent
    mov  eax, [r14 + 256]
    cmp  eax, 128
    je   .saved_present_size_ok
    cmp  eax, 256
    jne  .fail
.saved_present_size_ok:
    shr  eax, 7
    movzx edx, byte [r14 + 260]
    cmp  eax, edx
    jne  .fail
    cmp  byte [r14 + 261], 1
    jne  .fail
    jmp  .saved_state_ok
.saved_absent:
    cmp  byte [r14 + 262], 0
    jne  .fail
    cmp  dword [r14 + 256], 0
    jne  .fail
    cmp  byte [r14 + 260], 0
    jne  .fail
    cmp  byte [r14 + 261], 0
    jne  .fail
    mov  rdi, r14
    mov  ecx, 32
.saved_zero_scan:
    cmp  qword [rdi], 0
    jne  .fail
    add  rdi, 8
    loop .saved_zero_scan
.saved_state_ok:

    mov  esi, 128
    call gres_edid_make_fixture
    mov  r12, rax
    mov  rdi, rax
    mov  esi, 128
    call gop_edid_validate_publish
    cmp  eax, 1
    jne  .fail
    mov  rdi, r12
    mov  esi, 128
    call gres_edid_record_matches
    cmp  eax, 1
    jne  .fail
    lea  rdi, [rel str_edid_kat_128]
    mov  esi, 128
    call gres_edid_emit_kat_line
    cmp  eax, 1
    jne  .fail

    mov  esi, 256
    call gres_edid_make_fixture
    mov  r12, rax
    mov  rdi, rax
    mov  esi, 256
    call gop_edid_validate_publish
    cmp  eax, 1
    jne  .fail
    mov  rdi, r12
    mov  esi, 256
    call gres_edid_record_matches
    cmp  eax, 1
    jne  .fail
    lea  rdi, [rel str_edid_kat_256]
    mov  esi, 256
    call gres_edid_emit_kat_line
    cmp  eax, 1
    jne  .fail

    ; Exercise the maximum record through the registered read-only verb. The
    ; registry entry itself (the one paos.asm wraps in the session gate): this
    ; is a boot KAT of the verb, and the gate refuses every non-public name
    ; while the session is locked, the release boot's state. A zeroed request
    ; is CMD_SOURCE_INTERNAL / CMD_PRINCIPAL_NONE.
%if REQ_SZ > 64
%error "the EDID KAT's request no longer fits before its response"
%endif
%if 336 + RSP_SZ > 384
%error "the EDID KAT's response no longer fits in its frame"
%endif
%if CMD_SOURCE_INTERNAL != 0 || CMD_PRINCIPAL_NONE != 0
%error "the EDID KAT's zeroed request is no longer CMD_SOURCE_INTERNAL / CMD_PRINCIPAL_NONE"
%endif
    lea  rdi, [r14 + 272]
    xor  eax, eax
    mov  ecx, 12
    rep  stosq
    mov  eax, r15d
    mov  [r14 + 272 + REQ_VERB], rax
    lea  rax, [rel str_edid_kat_nonce]
    mov  [r14 + 272 + REQ_ARG], rax
    lea  rdi, [r14 + 272]
    lea  rsi, [r14 + 336]
    call command_dispatch_registry
    cmp  qword [r14 + 336 + RSP_CODE], CMDE_OK
    jne  .fail
    lea  rax, [rel str_edid_kat_nonce]
    cmp  [r14 + 336 + RSP_VAL], rax
    jne  .fail
    cmp  byte [rel gres_out_ready], 1
    jne  .fail
    lea  rax, [rel gres_out_buf]
    mov  rdx, [rel gres_out_cur]
    sub  rdx, rax
    cmp  edx, 651
    jne  .fail
    lea  rdi, [rel str_edid_kat_reply_prefix]
    lea  rsi, [rel gres_out_buf]
.prefix:
    mov  al, [rdi]
    test al, al
    jz   .negative_truncated
    cmp  al, [rsi]
    jne  .fail
    inc  rdi
    inc  rsi
    jmp  .prefix

.negative_truncated:
    mov  byte [rel gres_out_ready], 0
    mov  esi, 128
    call gres_edid_make_fixture
    mov  rdi, rax
    mov  esi, 127
    call gop_edid_validate_publish
    test eax, eax
    jnz  .fail
    call gres_edid_record_zero
    cmp  eax, 1
    jne  .fail

    mov  esi, 256
    call gres_edid_make_fixture
    mov  rdi, rax
    mov  esi, 128
    call gop_edid_validate_publish
    test eax, eax
    jnz  .fail
    call gres_edid_record_zero
    cmp  eax, 1
    jne  .fail

    mov  esi, 256
    call gres_edid_make_fixture
    inc  byte [rel gres_out_buf + 255]
    mov  rdi, rax
    mov  esi, 256
    call gop_edid_validate_publish
    test eax, eax
    jnz  .fail
    call gres_edid_record_zero
    cmp  eax, 1
    jne  .fail
    lea  rdi, [rel str_edid_kat_negatives]
    call serial_string
    jmp  .restore

.fail:
    xor  r13d, r13d
.restore:
    cmp  byte [r14 + 262], 1
    je   .restore_present
    cmp  byte [r14 + 262], 0
    jne  .restore_bad
    call gop_edid_clear
    jmp  .report
.restore_present:
    mov  rdi, r14
    mov  esi, [r14 + 256]
    call gop_edid_validate_publish
    cmp  eax, 1
    je   .report
.restore_bad:
    xor  r13d, r13d
    call gop_edid_clear
.report:
    mov  byte [rel gres_out_ready], 0
    test r13d, r13d
    jz   .report_fail
    lea  rdi, [rel str_edid_kat_pass]
    call serial_string
    jmp  .done
.report_fail:
    lea  rdi, [rel str_edid_kat_fail]
    call serial_string
.done:
    add  rsp, 384
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; VERB: GOP <nonce> -- read the retained pre-EBS firmware record from the live
; globals on every call. This is retrospective evidence available after NIC
; bind, never a claim that UDP witnessed P0-P7 in real time.
;
; Exact staged grammar:
;   GOP nonce=<token> base=0x<16hex> w=<u32> h=<u32> stride=<u32>
;       pixfmt=<0..2> bpp=32 fbsize=<u64> src=uefi-pre-ebs-retrospective
; ---------------------------------------------------------------------------
cmd_verb_gop:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  r12, [rdi + REQ_ARG]
    mov  r14, rsi
    mov  rdi, r12
    call gop_nonce_valid
    test eax, eax
    jz   .bad_nonce

    ; Refuse absent, non-linear, or internally impossible retained records.
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .bad_record
    call .mode
    test ebx, ebx
    jz   .bad_record
    test eax, eax
    jz   .bad_record
    cmp  ecx, ebx
    jb   .bad_record
    mov  eax, [rel fb_pixel_format]
    cmp  eax, 2
    ja   .bad_record
    cmp  dword [rel fb_bpp], 32
    jne  .bad_record
    mov  r13, [rel fb_size]
    test r13, r13
    jz   .bad_record
    call .mode
    mov  edx, eax
    mov  eax, ecx                     ; minimum bytes = stride * height * 4
    imul rax, rdx
    mov  rdx, rax
    shr  rdx, 62                      ; multiplying by four must remain uint64
    jnz  .bad_record
    shl  rax, 2
    cmp  r13, rax
    jb   .bad_record

    call gres_out_reset
    lea  rdi, [rel str_gres_gop_nonce]
    call gres_out_str
    mov  rdi, r12                     ; verbatim, after the bounded validation
    call gres_out_str
    lea  rdi, [rel str_gres_gop_base]
    call gres_out_str
    mov  rdi, [rel fb_scanout_base]   ; the GOP base even while the back buffer is attached
    test rdi, rdi
    jnz  .gres_base_known
    mov  rdi, [rel fb_base]
.gres_base_known:
    call gres_out_hex64
    lea  rdi, [rel str_gres_gop_w]
    call gres_out_str
    call .mode
    mov  edi, ebx
    call gres_out_dec
    lea  rdi, [rel str_gres_gop_h]
    call gres_out_str
    call .mode
    mov  edi, eax
    call gres_out_dec
    lea  rdi, [rel str_gres_gop_stride]
    call gres_out_str
    call .mode
    mov  edi, ecx
    call gres_out_dec
    lea  rdi, [rel str_gres_gop_pixfmt]
    call gres_out_str
    mov  edi, [rel fb_pixel_format]
    call gres_out_dec
    lea  rdi, [rel str_gres_gop_bpp]
    call gres_out_str
    mov  edi, [rel fb_bpp]
    call gres_out_dec
    lea  rdi, [rel str_gres_gop_fbsize]
    call gres_out_str
    mov  rdi, [rel fb_size]
    call gres_out_dec
    lea  rdi, [rel str_gres_gop_source]
    call gres_out_str
    mov  byte [rel gres_out_ready], 1
    mov  [r14 + RSP_VAL], r12
    mov  qword [r14 + RSP_CODE], CMDE_OK
    jmp  .done
.bad_nonce:
    call gres_out_reset
    lea  rdi, [rel str_gres_gop_bad_nonce]
    call gres_out_str
    mov  byte [rel gres_out_ready], 1
    mov  qword [r14 + RSP_CODE], CMDE_BADARG
    jmp  .done
.bad_record:
    call gres_out_reset
    lea  rdi, [rel str_gres_gop_bad_record]
    call gres_out_str
    mov  byte [rel gres_out_ready], 1
    mov  qword [r14 + RSP_CODE], CMDE_BADSEL
.done:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
; EBX=width, EAX=height, ECX=stride of the retained scanout mode; while the GUI composes
; 2x (RCQ-16 fb_scale=2) fb_* is the logical surface and the record is fb_out_*
.mode:
    mov  ebx, [rel fb_width]
    mov  eax, [rel fb_height]
    mov  ecx, [rel fb_stride]
    cmp  byte [rel fb_scale], 2
    jne  .mode_out
    mov  ebx, [rel fb_out_width]
    mov  eax, [rel fb_out_height]
    mov  ecx, [rel fb_out_stride]
.mode_out:
    ret

; ---------------------------------------------------------------------------
; VERB: GOPHEALTH — 1249 P53 self-detection oracle (public read, no argument).
;   Frames the boot-time facts boot/gop measured (rung 1 SetMode-always, rung 2
;   Blt calibration, rung 3 pre-EBS revalidation, P52 register fact) plus the
;   EFFECTIVE framebuffer memory type read from the live PTE + IA32_PAT.
; ---------------------------------------------------------------------------
cmd_verb_gophealth:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rdi
    mov  r12, rsi
    call gres_out_reset
    lea  rdi, [rel str_gh_pre]
    call gres_out_str
    xor  ebx, ebx                                   ; self_detected: both measurements produced a verdict
    mov  eax, [rel gop_calib_status]
    cmp  eax, 1
    jb   .sd_done
    cmp  eax, 2
    ja   .sd_done
    mov  eax, [rel gop_reval_status]
    cmp  eax, 1
    jb   .sd_done
    cmp  eax, 3
    je   .sd_done
    mov  ebx, 1
.sd_done:
    mov  edi, ebx
    call gres_out_dec
    lea  rdi, [rel str_gh_fresh]
    call gres_out_str
    xor  edi, edi
    mov  eax, [rel gop_reval_status]
    cmp  eax, 1
    jb   .fr_done
    cmp  eax, 3
    je   .fr_done
    mov  edi, 1
.fr_done:
    call gres_out_dec
    lea  rdi, [rel str_gh_calib]
    call gres_out_str
    mov  eax, [rel gop_calib_status]
    lea  rdi, [rel str_gh_not_run]
    cmp  eax, 1
    jne  .c2
    lea  rdi, [rel str_gh_pass]
.c2:
    cmp  eax, 2
    jne  .c3
    lea  rdi, [rel str_gh_corrected]
.c3:
    cmp  eax, 3
    jne  .c4
    lea  rdi, [rel str_gh_refused]
.c4:
    call gres_out_str
    lea  rdi, [rel str_gh_state]
    call gres_out_str
    mov  eax, [rel gop_health_state]
    lea  rdi, [rel str_gh_st_unknown]
    cmp  eax, 1
    jne  .s2
    lea  rdi, [rel str_gh_st_coherent]
.s2:
    cmp  eax, 2
    jne  .s3
    lea  rdi, [rel str_gh_st_meta]
.s3:
    cmp  eax, 3
    jne  .s4
    lea  rdi, [rel str_gh_st_calib]
.s4:
    cmp  eax, 4
    jne  .s5
    lea  rdi, [rel str_gh_st_reg]
.s5:
    cmp  eax, 5
    jne  .s6
    lea  rdi, [rel str_gh_st_regna]
.s6:
    call gres_out_str
    lea  rdi, [rel str_gh_pitch_meta]
    call gres_out_str
    mov  edi, [rel gop_calib_meta_pitch]
    call gres_out_dec
    lea  rdi, [rel str_gh_pitch_meas]
    call gres_out_str
    mov  edi, [rel gop_calib_pitch]
    call gres_out_dec
    lea  rdi, [rel str_gh_fmt_meta]
    call gres_out_str
    mov  edi, [rel fb_pixel_format]
    call gres_out_dec
    lea  rdi, [rel str_gh_fmt_meas]
    call gres_out_str
    mov  edi, [rel gop_calib_format]
    call gres_out_dec
    lea  rdi, [rel str_gh_reason]
    call gres_out_str
    mov  edi, [rel gop_calib_reason]
    call gres_out_dec
    lea  rdi, [rel str_gh_changes]
    call gres_out_str
    mov  edi, [rel gop_reval_changes]
    call gres_out_dec
    lea  rdi, [rel str_gh_setmode]
    call gres_out_str
    mov  edi, [rel gop_setmode_forced]
    call gres_out_dec
    lea  rdi, [rel str_gh_remodeset]
    call gres_out_str
    mov  edi, [rel gop_reval_remodeset]
    call gres_out_dec
    lea  rdi, [rel str_gh_setcalls]
    call gres_out_str
    mov  edi, [rel gop_setmode_attempts]
    call gres_out_dec
    lea  rdi, [rel str_gh_hp_live]
    call gres_out_str
    mov  edi, [rel gop_hp_live_consumed]
    call gres_out_dec
    lea  rdi, [rel str_gh_register]
    call gres_out_str
    mov  eax, [rel gop_reg_status]
    lea  rdi, [rel str_gh_reg_na]
    cmp  eax, 1
    jne  .r2
    lea  rdi, [rel str_gh_reg_match]
.r2:
    cmp  eax, 2
    jne  .r3
    lea  rdi, [rel str_gh_reg_mismatch]
.r3:
    call gres_out_str
    lea  rdi, [rel str_gh_reg_stride]
    call gres_out_str
    mov  edi, [rel gop_reg_stride64]
    call gres_out_dec
    lea  rdi, [rel str_gh_reg_size]
    call gres_out_str
    mov  edi, [rel gop_reg_size]
    call gres_out_hex64
    lea  rdi, [rel str_gh_reg_srcsz]
    call gres_out_str
    mov  edi, [rel gop_reg_srcsz]
    call gres_out_hex64
    lea  rdi, [rel str_gh_repairs]
    call gres_out_str
    mov  edi, [rel gop_disp_repairs]
    call gres_out_dec
    lea  rdi, [rel str_gh_memtype]
    call gres_out_str
    mov  rax, [rel fb_scanout_base]                 ; 2026-09-08: probe the GOP scanout, not the RAM buffer
    test rax, rax
    jz   .probe_live
    push qword [rel fb_base]
    mov  [rel fb_base], rax
    call gop_fb_memtype_probe                       ; effective type from the live PTE + IA32_PAT
    pop  qword [rel fb_base]
    jmp  .probe_done
.probe_live:
    call gop_fb_memtype_probe                       ; effective type from the live PTE + IA32_PAT
.probe_done:
    lea  rdi, [rel str_gh_mt_unknown]
    cmp  eax, 0
    jne  .m1
    lea  rdi, [rel str_gh_mt_uc]
.m1:
    cmp  eax, 1
    jne  .m4
    lea  rdi, [rel str_gh_mt_wc]
.m4:
    cmp  eax, 4
    jne  .m5
    lea  rdi, [rel str_gh_mt_wt]
.m5:
    cmp  eax, 5
    jne  .m6
    lea  rdi, [rel str_gh_mt_wp]
.m6:
    cmp  eax, 6
    jne  .m7
    lea  rdi, [rel str_gh_mt_wb]
.m7:
    cmp  eax, 7
    jne  .mff
    lea  rdi, [rel str_gh_mt_ucm]
.mff:
    cmp  eax, 0xFF
    jne  .mfe
    lea  rdi, [rel str_gh_mt_unmapped]
.mfe:
    cmp  eax, 0xFE
    jne  .m_out
    lea  rdi, [rel str_gh_mt_nopat]
.m_out:
    call gres_out_str
    lea  rdi, [rel str_gh_range]
    call gres_out_str
    lea  rdi, [rel str_gh_range_none]
    cmp  dword [rel gop_fb_range_exact], 1
    jne  .rg
    lea  rdi, [rel str_gh_range_exact]
.rg:
    call gres_out_str
    lea  rdi, [rel str_gh_p2m]
    call gres_out_str
    mov  edi, [rel gop_fb_pages_2m]
    call gres_out_dec
    lea  rdi, [rel str_gh_p4k]
    call gres_out_str
    mov  edi, [rel gop_fb_pages_4k]
    call gres_out_dec
    lea  rdi, [rel str_gh_locate_initial]
    call gres_out_str
    mov  rdi, [rel gop_locate_initial_status]
    call gres_out_hex64
    lea  rdi, [rel str_gh_connect_attempts]
    call gres_out_str
    mov  edi, [rel gop_connect_attempts]
    call gres_out_dec
    lea  rdi, [rel str_gh_connect_successes]
    call gres_out_str
    mov  edi, [rel gop_connect_successes]
    call gres_out_dec
    lea  rdi, [rel str_gh_connect_status]
    call gres_out_str
    mov  rdi, [rel gop_connect_last_status]
    call gres_out_hex64
    lea  rdi, [rel str_gh_locate_retry]
    call gres_out_str
    mov  rdi, [rel gop_locate_retry_status]
    call gres_out_hex64
    ; PCI discovery facts are scalars; state meanings are in boot/gop.asm.
    lea  rdi, [rel str_gh_pci_discovery]
    call gres_out_str
    mov  edi, [rel gop_pci_discovery]
    call gres_out_dec
    lea  rdi, [rel str_gh_pci_locate]
    call gres_out_str
    mov  rdi, [rel gop_pci_locate_status]
    call gres_out_hex64
    lea  rdi, [rel str_gh_pci_handles]
    call gres_out_str
    mov  rdi, [rel gop_pci_handles]
    call gres_out_dec
    lea  rdi, [rel str_gh_pci_scanned]
    call gres_out_str
    mov  edi, [rel gop_pci_scanned]
    call gres_out_dec
    lea  rdi, [rel str_gh_pci_proto_fail]
    call gres_out_str
    mov  edi, [rel gop_pci_protocol_failures]
    call gres_out_dec
    lea  rdi, [rel str_gh_pci_proto_null]
    call gres_out_str
    mov  edi, [rel gop_pci_protocol_nulls]
    call gres_out_dec
    lea  rdi, [rel str_gh_pci_proto_error]
    call gres_out_str
    mov  rdi, [rel gop_pci_protocol_error]
    call gres_out_hex64
    lea  rdi, [rel str_gh_pci_read_fail]
    call gres_out_str
    mov  edi, [rel gop_pci_read_failures]
    call gres_out_dec
    lea  rdi, [rel str_gh_pci_read_error]
    call gres_out_str
    mov  rdi, [rel gop_pci_read_error]
    call gres_out_hex64
    lea  rdi, [rel str_gh_pci_non_display]
    call gres_out_str
    mov  edi, [rel gop_pci_non_display]
    call gres_out_dec
    lea  rdi, [rel str_gh_manager_locate]
    call gres_out_str
    cmp  byte [rel pbm_manager_gop_valid], 1
    jne  .manager_unknown
    mov  rdi, [rel pbm_manager_gop_status]
    call gres_out_hex64
    jmp  .manager_done
.manager_unknown:
    lea  rdi, [rel str_gh_manager_unknown]
    call gres_out_str
.manager_done:
    mov  byte [rel gres_out_ready], 1
    mov  rax, [r13 + REQ_ARG]
    mov  [r12 + RSP_VAL], rax
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r13
    pop  r12
    pop  rbx
    ret

; gres_gop_selftest(EDI=registered GOP slot) -- QEMU/metal-common in-process
; content KAT. It dispatches through the one registry and requires the
; staged reply to carry the unknown-at-handler static challenge verbatim before
; the fixed base field. The live bare-metal probe supplies the fresh-random half.
; Task3474 DH2: guest EDID oracle KAT. Builds a synthetic EDID (native 1920x1080,
; physical 520x290 mm, a CTA-861 extension carrying an HDR Static Metadata block),
; then decodes native geometry, physical mm, computed DPI, CTA presence and HDR
; capability over the raw bytes — the same digest schema the shipped guest parser
; emits (edid_parser.c). Plausibility bounds match the guest (mm 10..3000, DPI
; 20..1000): zero/implausible mm -> physical_trust=0 (resolution-fallback). Also
; proves a corrupted block is rejected. Emits [gui.hires.edid.oracle.kat] on pass.
gres_edid_oracle_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  rbx, [rel edid_oracle_scratch]
    mov  rdi, rbx
    xor  eax, eax
    mov  ecx, 32
    rep  stosq                          ; zero 256 bytes
    mov  byte [rbx+0], 0x00              ; EDID header magic 00 FF FF FF FF FF FF 00
    mov  byte [rbx+1], 0xFF
    mov  byte [rbx+2], 0xFF
    mov  byte [rbx+3], 0xFF
    mov  byte [rbx+4], 0xFF
    mov  byte [rbx+5], 0xFF
    mov  byte [rbx+6], 0xFF
    mov  byte [rbx+7], 0x00
    mov  byte [rbx+54], 0x01            ; DTD @54: nonzero pixel clock = timing descriptor
    mov  byte [rbx+55], 0x01
    mov  byte [rbx+56], 0x80            ; hactive 1920 = 0x780: low 0x80, hi nibble 7
    mov  byte [rbx+58], 0x70
    mov  byte [rbx+59], 0x38            ; vactive 1080 = 0x438: low 0x38, hi nibble 4
    mov  byte [rbx+61], 0x40
    mov  byte [rbx+66], 0x08            ; width_mm 520 = 0x208: dtd[12]=0x08, dtd[14] hi nibble 2
    mov  byte [rbx+67], 0x22            ; height_mm 290 = 0x122: dtd[13]=0x22, dtd[14] lo nibble 1
    mov  byte [rbx+68], 0x21
    mov  byte [rbx+126], 1             ; one extension block
    call edid_oracle_fix_checksum_base
    mov  byte [rbx+128], 0x02          ; CTA-861 extension tag
    mov  byte [rbx+129], 0x03          ; revision 3
    mov  byte [rbx+130], 12            ; DTD offset within block (data blocks occupy [4,12))
    mov  byte [rbx+131], 0x00
    mov  byte [rbx+132], 0xE3          ; data block: tag 7 (extended), length 3
    mov  byte [rbx+133], 0x06          ; extended tag 6 = HDR Static Metadata
    mov  byte [rbx+134], 0x02          ; supported EOTF (bit1 = SMPTE ST 2084 / PQ)
    mov  byte [rbx+135], 0x00
    call edid_oracle_fix_checksum_cta
    ; decode + assert the digest
    lea  rdi, [rel edid_oracle_scratch]
    call edid_oracle_decode
    cmp  dword [rel edid_oracle_nw], 1920
    jne  .fail
    cmp  dword [rel edid_oracle_nh], 1080
    jne  .fail
    cmp  dword [rel edid_oracle_mmw], 520
    jne  .fail
    cmp  dword [rel edid_oracle_mmh], 290
    jne  .fail
    cmp  dword [rel edid_oracle_dpix], 94
    jne  .fail
    cmp  dword [rel edid_oracle_dpiy], 95
    jne  .fail
    cmp  byte [rel edid_oracle_cta], 1
    jne  .fail
    cmp  byte [rel edid_oracle_hdr], 1
    jne  .fail
    cmp  byte [rel edid_oracle_trust], 1
    jne  .fail
    ; corrupt-digest control: flip a byte -> the block checksum must now fail
    xor  byte [rbx+10], 0xFF
    call edid_oracle_checksum_ok_base
    test eax, eax
    jnz  .fail                          ; a corrupt block must be rejected, not accepted
    xor  byte [rbx+10], 0xFF            ; restore
    ; zero-mm control: physical size 0 -> resolution-fallback (physical_trust=0)
    mov  byte [rbx+66], 0x00
    mov  byte [rbx+67], 0x00
    mov  byte [rbx+68], 0x00
    lea  rdi, [rel edid_oracle_scratch]
    call edid_oracle_decode
    cmp  byte [rel edid_oracle_trust], 0
    jne  .fail
    lea  rdi, [rel str_hires_edid_oracle_kat]
    call serial_string
.fail:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; edid_oracle_decode(RDI=edid buffer) -> fills edid_oracle_* result vars. Mirrors
; the guest parser's byte decode: native/mm from the base DTD, DPI = round(px*254/
; (mm*10)) gated by plausibility, CTA presence, and an HDR Static Metadata scan.
edid_oracle_decode:
    push rbx
    push r12
    mov  rbx, rdi
    movzx eax, byte [rbx+56]            ; native_w
    movzx ecx, byte [rbx+58]
    and  ecx, 0xF0
    shl  ecx, 4
    or   eax, ecx
    mov  [rel edid_oracle_nw], eax
    movzx eax, byte [rbx+59]            ; native_h
    movzx ecx, byte [rbx+61]
    and  ecx, 0xF0
    shl  ecx, 4
    or   eax, ecx
    mov  [rel edid_oracle_nh], eax
    movzx eax, byte [rbx+66]            ; width_mm
    movzx ecx, byte [rbx+68]
    and  ecx, 0xF0
    shl  ecx, 4
    or   eax, ecx
    mov  [rel edid_oracle_mmw], eax
    movzx eax, byte [rbx+67]            ; height_mm
    movzx ecx, byte [rbx+68]
    and  ecx, 0x0F
    shl  ecx, 8
    or   eax, ecx
    mov  [rel edid_oracle_mmh], eax
    mov  byte  [rel edid_oracle_trust], 0
    mov  dword [rel edid_oracle_dpix], 0
    mov  dword [rel edid_oracle_dpiy], 0
    mov  eax, [rel edid_oracle_mmw]     ; plausibility: 10..3000 mm each axis
    cmp  eax, 10
    jb   .cta
    cmp  eax, 3000
    ja   .cta
    mov  eax, [rel edid_oracle_mmh]
    cmp  eax, 10
    jb   .cta
    cmp  eax, 3000
    ja   .cta
    mov  eax, [rel edid_oracle_nw]      ; dpix = (nw*254 + mmw*5)/(mmw*10)
    imul eax, 254
    mov  ecx, [rel edid_oracle_mmw]
    imul ecx, 5
    add  eax, ecx
    mov  ecx, [rel edid_oracle_mmw]
    imul ecx, 10
    xor  edx, edx
    div  ecx
    mov  [rel edid_oracle_dpix], eax
    mov  eax, [rel edid_oracle_nh]      ; dpiy = (nh*254 + mmh*5)/(mmh*10)
    imul eax, 254
    mov  ecx, [rel edid_oracle_mmh]
    imul ecx, 5
    add  eax, ecx
    mov  ecx, [rel edid_oracle_mmh]
    imul ecx, 10
    xor  edx, edx
    div  ecx
    mov  [rel edid_oracle_dpiy], eax
    mov  eax, [rel edid_oracle_dpix]    ; DPI plausibility 20..1000
    cmp  eax, 20
    jb   .cta
    cmp  eax, 1000
    ja   .cta
    mov  eax, [rel edid_oracle_dpiy]
    cmp  eax, 20
    jb   .cta
    cmp  eax, 1000
    ja   .cta
    mov  byte [rel edid_oracle_trust], 1
.cta:
    mov  byte [rel edid_oracle_cta], 0
    mov  byte [rel edid_oracle_hdr], 0
    cmp  byte [rbx+126], 1              ; >= one extension
    jb   .done
    cmp  byte [rbx+128], 0x02           ; first extension is CTA-861
    jne  .done
    mov  byte [rel edid_oracle_cta], 1
    movzx ecx, byte [rbx+130]           ; DTD offset within the CTA block = data-block end
    cmp  ecx, 4
    jbe  .done
    mov  r12d, 4                        ; data blocks start at CTA offset 4
.hdr_scan:
    cmp  r12d, ecx
    jae  .done
    lea  rax, [rbx+128]
    movzx edx, byte [rax+r12]           ; data-block header = (tag<<5)|len
    mov  esi, edx
    and  esi, 0xE0
    cmp  esi, 0xE0                       ; tag 7 (extended)?
    jne  .hdr_next
    movzx esi, byte [rax+r12+1]          ; extended tag
    cmp  esi, 6                          ; 6 = HDR Static Metadata
    jne  .hdr_next
    mov  byte [rel edid_oracle_hdr], 1
    jmp  .done
.hdr_next:
    and  edx, 0x1F                       ; payload length
    add  edx, 1                          ; + the header byte
    add  r12d, edx
    jmp  .hdr_scan
.done:
    pop  r12
    pop  rbx
    ret

; edid_oracle_fix_checksum_base — set [RBX+127] so bytes 0..127 sum to 0 mod 256.
edid_oracle_fix_checksum_base:
    push rcx
    xor  eax, eax
    xor  ecx, ecx
.s:
    add  al, [rbx+rcx]
    inc  ecx
    cmp  ecx, 127
    jb   .s
    neg  al
    mov  [rbx+127], al
    pop  rcx
    ret

; edid_oracle_fix_checksum_cta — set [RBX+255] so bytes 128..255 sum to 0 mod 256.
edid_oracle_fix_checksum_cta:
    push rcx
    xor  eax, eax
    mov  ecx, 128
.s:
    add  al, [rbx+rcx]
    inc  ecx
    cmp  ecx, 255
    jb   .s
    neg  al
    mov  [rbx+255], al
    pop  rcx
    ret

; edid_oracle_checksum_ok_base(RBX=buf) -> EAX 1 iff bytes 0..127 sum to 0 mod 256.
edid_oracle_checksum_ok_base:
    push rcx
    xor  edx, edx
    xor  ecx, ecx
.s:
    add  dl, [rbx+rcx]
    inc  ecx
    cmp  ecx, 128
    jb   .s
    xor  eax, eax
    test dl, dl
    jnz  .out
    mov  eax, 1
.out:
    pop  rcx
    ret

GRES_GOP_FRAME equ REQ_SZ + RSP_SZ   ; stack-local REQ, then RSP (no overlap)
%if (GRES_GOP_FRAME % 16) != 8
%error "gres_gop_selftest's frame must leave its calls 16-byte aligned"
%endif
gres_gop_selftest:
    sub  rsp, GRES_GOP_FRAME
    mov  eax, edi
    cmp  eax, -1
    je   .fail
    mov  [rsp + REQ_VERB], rax
    mov  qword [rsp + REQ_CAP], 0
    mov  qword [rsp + REQ_IDEM], 0
    mov  qword [rsp + REQ_SEL], 0
    lea  rax, [rel str_gop_kat_nonce]
    mov  [rsp + REQ_ARG], rax
    mov  qword [rsp + REQ_SOURCE], CMD_SOURCE_INTERNAL
    mov  qword [rsp + REQ_PRINCIPAL], CMD_PRINCIPAL_NONE
    lea  rdi, [rsp]
    lea  rsi, [rsp + REQ_SZ]
    call command_dispatch_registry      ; the verb itself, as gres_edid_selftest
    cmp  qword [rsp + REQ_SZ + RSP_CODE], CMDE_OK
    jne  .fail
    lea  rax, [rel str_gop_kat_nonce]
    cmp  [rsp + REQ_SZ + RSP_VAL], rax
    jne  .fail
    cmp  byte [rel gres_out_ready], 1
    jne  .fail
    lea  rdi, [rel str_gop_kat_prefix]
    lea  rsi, [rel gres_out_buf]
.compare:
    mov  al, [rdi]
    test al, al
    jz   .pass
    cmp  al, [rsi]
    jne  .fail
    inc  rdi
    inc  rsi
    jmp  .compare
.pass:
    lea  rdi, [rel str_gop_kat_pass]
    call serial_string
    mov  byte [rel gres_out_ready], 0
    add  rsp, GRES_GOP_FRAME
    ret
.fail:
    lea  rdi, [rel str_gop_kat_fail]
    call serial_string
    mov  byte [rel gres_out_ready], 0
    add  rsp, GRES_GOP_FRAME
    ret

; gres_out_wh(EDI=w, ESI=h) — append "<w>x<h>". clobbers caller-saved.
gres_out_wh:
    push rbx
    mov  ebx, esi
    call gres_out_dec
    lea  rdi, [rel str_gres_x]
    call gres_out_str
    mov  edi, ebx
    call gres_out_dec
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; VERB: RESINFO — the detection verdict, content-gradeable. active is read LIVE
;   from fb_width/fb_height (the actual render surface), never from a copy.
; ---------------------------------------------------------------------------
cmd_verb_resinfo:
    call cmd_handler_prologue
    push rdi
    push rsi
    call gres_out_reset
    lea  rdi, [rel str_gres_ri]        ; " RESINFO native="
    call gres_out_str
    mov  edi, [rel res_native_w]
    mov  esi, [rel res_native_h]
    call gres_out_wh
    lea  rdi, [rel str_gres_act]       ; " active="
    call gres_out_str
    mov  edi, [rel fb_width]
    mov  esi, [rel fb_height]
    call gres_out_wh
    lea  rdi, [rel str_gres_src]       ; " src="
    call gres_out_str
    cmp  byte [rel res_src], 1
    je   .edid
    cmp  byte [rel res_src], 2
    je   .gop
    lea  rdi, [rel str_gres_none]
    jmp  .srcout
.edid:
    lea  rdi, [rel str_gres_edid]
    jmp  .srcout
.gop:
    lea  rdi, [rel str_gres_gop]
.srcout:
    call gres_out_str
    lea  rdi, [rel str_gres_dpi]       ; " dpi="
    call gres_out_str
    movzx edi, byte [rel res_dpi]
    call gres_out_dec
    lea  rdi, [rel str_gres_modes]     ; " modes="
    call gres_out_str
    mov  edi, [rel gop_mode_count]
    call gres_out_dec
    mov  byte [rel gres_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; ---------------------------------------------------------------------------
; VERB: RESMODES — dump the boot-time GOP mode inventory (the probe cross-checks
;   native == max of THIS list, proving detection rather than a hardcode).
; ---------------------------------------------------------------------------
cmd_verb_resmodes:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    push r12
    call gres_out_reset
    lea  rdi, [rel str_gres_rm]        ; " RESMODES n="
    call gres_out_str
    mov  edi, [rel gop_mode_count]
    call gres_out_dec
    lea  rdi, [rel str_gres_cur]       ; " cur="
    call gres_out_str
    mov  edi, [rel fb_width]
    mov  esi, [rel fb_height]
    call gres_out_wh
    xor  r12d, r12d
.mloop:
    cmp  r12d, [rel gop_mode_count]
    jae  .done
    lea  rdi, [rel str_gres_sp]
    call gres_out_str
    lea  rbx, [rel gop_mode_list]
    mov  eax, r12d
    mov  edi, [rbx + rax*8]            ; width
    mov  esi, [rbx + rax*8 + 4]        ; height
    call gres_out_wh
    inc  r12d
    jmp  .mloop
.done:
    mov  byte [rel gres_out_ready], 1
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret


; ---------------------------------------------------------------------------
; res_parse_wh(RDI = "<W>x<H>") -> EAX = width, EDX = height; EAX = 0 on any
;   malformed input. Bounded at 5 digits per field, requires the 'x' separator
;   and a clean NUL terminator -- a partial parse is an error, never a guess.
;   clobbers: rax, rcx, rdx, rsi, rdi
; ---------------------------------------------------------------------------
res_parse_wh:
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
.w:
    movzx esi, byte [rdi]
    cmp  sil, '0'
    jb   .wdone
    cmp  sil, '9'
    ja   .wdone
    cmp  ecx, 5
    jae  .bad
    imul eax, eax, 10
    sub  esi, '0'
    add  eax, esi
    inc  rdi
    inc  ecx
    jmp  .w
.wdone:
    test ecx, ecx
    jz   .bad
    movzx esi, byte [rdi]
    cmp  sil, 'x'
    je   .sep
    cmp  sil, 'X'
    jne  .bad
.sep:
    inc  rdi
    xor  ecx, ecx
.h:
    movzx esi, byte [rdi]
    cmp  sil, '0'
    jb   .hdone
    cmp  sil, '9'
    ja   .hdone
    cmp  ecx, 5
    jae  .bad
    imul edx, edx, 10
    sub  esi, '0'
    add  edx, esi
    inc  rdi
    inc  ecx
    jmp  .h
.hdone:
    test ecx, ecx
    jz   .bad
    cmp  byte [rdi], 0
    jne  .bad
    test eax, eax
    jz   .bad
    test edx, edx
    jz   .bad
    ret
.bad:
    xor  eax, eax
    xor  edx, edx
    ret

; ---------------------------------------------------------------------------
; res_mode_ok(EDI = w, ESI = h) -> EAX = 1 when (w,h) is in the box's OWN
;   boot-time GOP inventory, else 0. The verb refuses anything not enumerated,
;   so no caller can program an invented geometry into the display engine.
;   clobbers: rax, rbx, r12 (restored)
; ---------------------------------------------------------------------------
res_mode_ok:
    push rbx
    push r12
    xor  r12d, r12d
.l:
    cmp  r12d, [rel gop_mode_count]
    jae  .no
    lea  rbx, [rel gop_mode_list]
    mov  eax, r12d
    cmp  edi, [rbx + rax*8]
    jne  .nx
    cmp  esi, [rbx + rax*8 + 4]
    je   .yes
.nx:
    inc  r12d
    jmp  .l
.yes:
    mov  eax, 1
    pop  r12
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; VERB: RESSET <W>x<H> — reprogram the LIVE render geometry, then re-assert the
;   scanout plane from it. This is the write counterpart to RESINFO/RESMODES.
;
;   Guards, in order (any failure leaves the display untouched):
;     1. the argument must parse exactly as <W>x<H>
;     2. (W,H) must appear in the box's own enumerated GOP inventory
;     3. W/H must fit inside the framebuffer the firmware actually allocated at
;        boot (tracked lazily in res_boot_*), so a smaller boot mode can never
;        be told to scan out a larger surface and walk off the end of it
;
;   The reply carries the geometry read back OUT OF THE DISPLAY ENGINE
;   (gop_plane_geom), not PaOS's own globals: "ok=1" alone would be an
;   unearned ack, and this whole defect class hides behind those.
;
;   Recovery: this verb never touches the network path, so an unreadable mode
;   is always undone by sending RESSET with a working geometry.
; ---------------------------------------------------------------------------
cmd_verb_resset:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14, rdi                       ; request
    mov  r15, rsi                       ; response
    ; lazily latch the boot-time surface the firmware allocated
    cmp  byte [rel fb_scale], 2
    je   .have_boot                     ; scaled: fb_* is the logical surface; every request refuses below
    cmp  dword [rel res_boot_stride], 0
    jne  .have_boot
    mov  eax, [rel fb_stride]
    mov  [rel res_boot_stride], eax
    mov  eax, [rel fb_height]
    mov  [rel res_boot_height], eax
.have_boot:
    mov  rdi, [r14 + REQ_ARG]
    test rdi, rdi
    jz   .bad_parse
    call res_parse_wh
    mov  r12d, eax                      ; w
    mov  r13d, edx                      ; h
    call gres_out_reset
    lea  rdi, [rel str_gres_rs]
    call gres_out_str
    test r12d, r12d
    jz   .bad_parse2
    ; RCQ-16 VQ-01: the 2x logical desktop is fixed from the first attach; a mode change
    ; would re-plan the plane, shadow and pointer under a scaled GUI. Change nothing.
    cmp  byte [rel fb_scale], 2
    je   .scaled
    mov  edi, r12d
    mov  esi, r13d
    call res_mode_ok
    test eax, eax
    jz   .unlisted
    cmp  r12d, [rel res_boot_stride]
    ja   .toobig
    cmp  r13d, [rel res_boot_height]
    ja   .toobig
    ; REFUSE when we have no verified control of the scanout plane. Without a
    ; register map, gop_plane_dump skips -- so applying the new geometry would
    ; move PaOS's drawing while the plane kept fetching the OLD stride, which
    ; is precisely the wrapped/tiled screen this whole effort exists to remove.
    ; Better to change nothing and say why.
    cmp  dword [rel gop_disp_tier], 0
    je   .noplane
    ; --- apply: globals first, then re-assert the plane from them
    mov  [rel fb_width],  r12d
    mov  [rel fb_height], r13d
    mov  [rel fb_stride], r12d
    call gop_plane_dump                 ; the geometry-repair path itself
    ; Repaint through the SAME compositor the boot path uses. gop_fill was
    ; wrong here: it is the boot-time "prove PaOS drew pixels" test pattern
    ; (blue=y&0xFF, green=x&0xFF), so it left a 256px debug gradient as the
    ; desktop wallpaper and wm_repaint_all only redraws WINDOWS -- the
    ; backdrop, swatches and taskbar were never restored. The compositor
    ; reads fb_width/fb_height live, so it re-lays the whole desktop at the
    ; new geometry. It paints the compositor FLOOR (backdrop, swatches,
    ; taskbar, clock, placeholder window rects) but not the app content, so
    ; wm_repaint_all follows to redraw the real Monitor/Netmon/Chat windows
    ; with their text. Floor first, apps second: the apps overpaint.
    call gui_compositor_selftest
    call wm_repaint_all                 ; ...then the real app windows on top
    lea  rdi, [rel str_gres_ok1]
    call gres_out_str
    jmp  .report
.bad_parse:
    call gres_out_reset
    lea  rdi, [rel str_gres_rs]
    call gres_out_str
.bad_parse2:
    lea  rdi, [rel str_gres_eparse]
    call gres_out_str
    jmp  .report
.unlisted:
    lea  rdi, [rel str_gres_eunlist]
    call gres_out_str
    jmp  .report
.toobig:
    lea  rdi, [rel str_gres_ebig]
    call gres_out_str
    jmp  .report
.noplane:
    lea  rdi, [rel str_gres_enoplane]
    call gres_out_str
    jmp  .report
.scaled:
    lea  rdi, [rel str_gres_escaled]
    call gres_out_str
.report:
    ; cur= is re-read live; hw_* is read out of the display engine
    lea  rdi, [rel str_gres_cur]
    call gres_out_str
    mov  edi, [rel fb_width]
    mov  esi, [rel fb_height]
    call gres_out_wh
    call gop_plane_geom                 ; EAX = stride raw, EDX = size raw
    cmp  eax, 0xFFFFFFFF
    je   .nohw
    mov  r12d, eax
    mov  r13d, edx
    lea  rdi, [rel str_gres_hwstr]      ; " hw_stride_px="
    call gres_out_str
    mov  edi, r12d
    shl  edi, 4                         ; raw*64 bytes -> /4 bytes-per-pixel = raw*16
    call gres_out_dec
    lea  rdi, [rel str_gres_hwsz]       ; " hw_size="
    call gres_out_str
    mov  eax, r13d
    and  eax, 0xFFFF
    inc  eax
    mov  edi, eax                       ; width  = (raw & 0xFFFF) + 1
    mov  eax, r13d
    shr  eax, 16
    inc  eax
    mov  esi, eax                       ; height = (raw >> 16) + 1
    call gres_out_wh
    jmp  .fin
.nohw:
    lea  rdi, [rel str_gres_hwno]
    call gres_out_str
.fin:
    lea  rdi, [rel str_gres_tier]
    call gres_out_str
    mov  edi, [rel gop_disp_tier]
    call gres_out_dec
    lea  rdi, [rel str_gres_rep]
    call gres_out_str
    mov  edi, [rel gop_disp_repairs]
    call gres_out_dec
    mov  byte [rel gres_out_ready], 1
    mov  rax, [r14 + REQ_ARG]
    mov  [r15 + RSP_VAL], rax
    mov  qword [r15 + RSP_CODE], CMDE_OK
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret


; ---------------------------------------------------------------------------
; VERB: DISPLAYS — enumerate what the display engine actually HAS, by reading
;   every pipe rather than assuming the boot output is the only one.
;
;   This is the multi-output foundation, deliberately landed before there is a
;   second monitor to drive. PaOS today keeps ONE set of framebuffer globals,
;   so every drawing site reaches straight for "the" screen; bolting a second
;   output on later would mean touching all of them. Enumeration first means
;   the additional output arrives as data, not as a rewrite.
;
;   Reports, per pipe: whether its primary plane is ENABLED (PLANE_CTL bit 31)
;   and the pipe's source size. Entirely read-only -- nothing here programs an
;   output. With one monitor attached the honest answer is exactly one enabled
;   pipe, and that is what makes this testable NOW instead of on faith.
; ---------------------------------------------------------------------------
cmd_verb_displays:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14, rdi
    mov  r15, rsi
    call gres_out_reset
    lea  rdi, [rel str_gres_dsp]
    call gres_out_str
    lea  rdi, [rel str_gres_tier]
    call gres_out_str
    mov  edi, [rel gop_disp_tier]
    call gres_out_dec
    lea  rdi, [rel str_gres_outs]       ; " outputs="
    call gres_out_str
    mov  edi, [rel gop_output_count]
    call gres_out_dec
    lea  rdi, [rel str_gres_slash]
    call gres_out_str
    mov  edi, GOP_OUTPUTS_MAX
    call gres_out_dec
    lea  rdi, [rel str_gres_ddim]       ; " ddi_enabled=0x"
    call gres_out_str
    call gop_ddi_mask
    mov  edi, eax
    call gres_out_dec
    xor  r12d, r12d                     ; pipe index
.ploop:
    cmp  r12d, 3
    jae  .pdone
    lea  rdi, [rel str_gres_pipe]       ; " pipe"
    call gres_out_str
    lea  rax, [rel str_gres_pipeltr]
    add  rax, r12
    mov  rdi, rax
    call gres_out_str1                  ; the pipe letter, A/B/C
    mov  edi, r12d
    call gop_pipe_probe                 ; EAX = PLANE_CTL, EDX = PIPE_SRCSZ
    cmp  eax, 0xFFFFFFFF
    je   .pnone
    mov  r13d, edx
    test eax, eax
    js   .pon                           ; bit31 set -> plane enabled
    lea  rdi, [rel str_gres_poff]
    call gres_out_str
    jmp  .pnext
.pon:
    lea  rdi, [rel str_gres_pon]
    call gres_out_str
    mov  eax, r13d
    shr  eax, 16
    inc  eax
    mov  edi, eax                       ; PIPE_SRCSZ = (w-1)<<16 | (h-1)
    mov  eax, r13d
    and  eax, 0xFFFF
    inc  eax
    mov  esi, eax
    call gres_out_wh
    lea  rdi, [rel str_gres_ddisel]     ; ",ddi="
    call gres_out_str
    mov  edi, [rel gop_last_ddisel]
    call gres_out_dec
    jmp  .pnext
.pnone:
    lea  rdi, [rel str_gres_pna]
    call gres_out_str
.pnext:
    inc  r12d
    jmp  .ploop
.pdone:
    mov  byte [rel gres_out_ready], 1
    mov  rax, [r14 + REQ_ARG]
    mov  [r15 + RSP_VAL], rax
    mov  qword [r15 + RSP_CODE], CMDE_OK
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; gres_out_str1(RDI) — append exactly one character (the pipe letter table is
;   a flat string, so the generic NUL-terminated append would run past it).
gres_out_str1:
    mov  rsi, [rel gres_out_cur]
    lea  rdx, [rel gres_out_buf + GRES_OUT_MAX - 1]
    cmp  rsi, rdx
    jae  .skip
    mov  al, [rdi]
    mov  [rsi], al
    inc  rsi
    mov  byte [rsi], 0
    mov  [rel gres_out_cur], rsi
.skip:
    ret

; --- gui/command_res data ----------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_command_res_0 0
align 8
times 48 db 0                  ; gres_out_cur..gres_edid_digest moved to WDATA_gui_command_res_0_bss1: keeps the labels below at their offset mod 64

str_gres_outs:     db " outputs=", 0
str_gres_slash:    db "/", 0
str_gres_ddim:     db " ddi_enabled=", 0
str_gres_ddisel:   db ",ddi=", 0
str_verb_displays: db "DISPLAYS", 0
str_gres_dsp:      db " DISPLAYS", 0
str_gres_tier:     db " map_tier=", 0
str_gres_rep:      db " regs_repaired=", 0
str_gres_pipe:     db " pipe", 0
str_gres_pipeltr:  db "ABC", 0
str_gres_pon:      db "=on:", 0
str_gres_poff:     db "=off", 0
str_gres_pna:      db "=unmapped", 0
str_gres_escaled:  db " ok=0 err=scaled_desktop", 0
str_gres_enoplane: db " ok=0 err=no_verified_plane_control", 0
str_verb_resset:   db "RESSET", 0
str_gres_rs:       db " RESSET", 0
str_gres_ok1:      db " ok=1", 0
str_gres_eparse:   db " ok=0 err=parse want=<W>x<H>", 0
str_gres_eunlist:  db " ok=0 err=not_in_gop_inventory", 0
str_gres_ebig:     db " ok=0 err=exceeds_boot_surface", 0
str_gres_hwstr:    db " hw_stride_px=", 0
str_gres_hwsz:     db " hw_size=", 0
str_gres_hwno:     db " hw=unavailable", 0
align 8
res_boot_stride:   dd 0
res_boot_height:   dd 0
str_verb_resinfo:  db "RESINFO", 0
str_verb_resmodes: db "RESMODES", 0
str_verb_gop:      db "GOP", 0
str_verb_gophealth: db "GOPHEALTH", 0
str_gh_pre:        db " GOPHEALTH gop.scanout.self_detected=", 0
str_gh_fresh:      db " mode_record_fresh=", 0
str_gh_calib:      db " calibration=", 0
str_gh_not_run:    db "not_run", 0
str_gh_pass:       db "pass", 0
str_gh_corrected:  db "corrected", 0
str_gh_refused:    db "refused", 0
str_gh_state:      db " state=", 0
str_gh_st_unknown: db "unknown", 0
str_gh_st_coherent: db "coherent", 0
str_gh_st_meta:    db "metadata_mismatch", 0
str_gh_st_calib:   db "calibration_refused", 0
str_gh_st_reg:     db "register_mismatch", 0
str_gh_st_regna:   db "register_unavailable", 0
str_gh_pitch_meta: db " pitch_meta=", 0
str_gh_pitch_meas: db " pitch_measured=", 0
str_gh_fmt_meta:   db " format_meta=", 0
str_gh_fmt_meas:   db " format_measured=", 0
str_gh_reason:     db " reason=", 0
str_gh_changes:    db " record_changes=", 0
str_gh_setmode:    db " setmode_forced=", 0
str_gh_remodeset:  db " remodeset=", 0
str_gh_setcalls:   db " setmode_calls=", 0
str_gh_hp_live:    db " hp_live_consumed=", 0
str_gh_register:   db " register=", 0
str_gh_reg_na:     db "unavailable", 0
str_gh_reg_match:  db "match", 0
str_gh_reg_mismatch: db "mismatch", 0
str_gh_reg_stride: db " reg_stride64=", 0
str_gh_reg_size:   db " reg_size=0x", 0
str_gh_reg_srcsz:  db " reg_srcsz=0x", 0
str_gh_repairs:    db " repairs=", 0
str_gh_memtype:    db " fb_memtype=", 0
str_gh_mt_unknown: db "unknown", 0
str_gh_mt_uc:      db "UC", 0
str_gh_mt_wc:      db "WC", 0
str_gh_mt_wt:      db "WT", 0
str_gh_mt_wp:      db "WP", 0
str_gh_mt_wb:      db "WB", 0
str_gh_mt_ucm:     db "UC-", 0
str_gh_mt_unmapped: db "unmapped", 0
str_gh_mt_nopat:   db "no_pat", 0
str_gh_range:      db " fb_range=", 0
str_gh_range_none: db "none", 0
str_gh_range_exact: db "exact", 0
str_gh_p2m:        db " pages_2m=", 0
str_gh_p4k:        db " pages_4k=", 0
str_gh_locate_initial: db " locate_initial=0x", 0
str_gh_connect_attempts: db " connect_attempts=", 0
str_gh_connect_successes: db " connect_successes=", 0
str_gh_connect_status: db " connect_last_status=0x", 0
str_gh_locate_retry: db " locate_retry=0x", 0
str_gh_pci_discovery: db " pci_discovery=", 0
str_gh_pci_locate: db " pci_locate=0x", 0
str_gh_pci_handles: db " pci_handles=", 0
str_gh_pci_scanned: db " pci_scanned=", 0
str_gh_pci_proto_fail: db " pci_proto_fail=", 0
str_gh_pci_proto_null: db " pci_proto_null=", 0
str_gh_pci_proto_error: db " pci_proto_error=0x", 0
str_gh_pci_read_fail: db " pci_read_fail=", 0
str_gh_pci_read_error: db " pci_read_error=0x", 0
str_gh_pci_non_display: db " pci_non_display=", 0
str_gh_manager_locate: db " manager_locate=", 0
str_gh_manager_unknown: db "unknown", 0
str_verb_edid:     db "EDID", 0
str_gres_edid_nonce:    db " EDID nonce=", 0
str_gres_edid_present:  db " present=", 0
str_gres_edid_bytes:    db " bytes=", 0
str_gres_edid_blocks:   db " blocks=", 0
str_gres_edid_checksum: db " checksum=", 0
str_gres_edid_ok:       db "ok", 0
str_gres_edid_sha:      db " sha256=", 0
str_gres_edid_data:     db " data=", 0
str_gres_edid_absent:   db " present=0 bytes=0 blocks=0 checksum=none sha256=- data=-", 0
str_gres_edid_bad_nonce:  db " EDID ERR malformed_nonce", 0
str_gres_edid_bad_record: db " EDID ERR incoherent_record", 0
str_gres_nl:            db 13, 10, 0
str_edid_kat_nonce: db "edid-kat", 0
str_edid_kat_reply_prefix: db " EDID nonce=edid-kat present=1 bytes=256 blocks=2 checksum=ok sha256=", 0
str_edid_kat_128: db "[PAOS64] display: raw EDID KAT case=valid128 bytes=128 blocks=1 checksum=ok sha256=", 0
str_edid_kat_256: db "[PAOS64] display: raw EDID KAT case=valid256 bytes=256 blocks=2 checksum=ok sha256=", 0
str_edid_kat_negatives: db "[PAOS64] display: raw EDID KAT negatives=truncated,extension-count,checksum clear=1", 13, 10, 0
str_hires_edid_oracle_kat: db "[PAOS64] hires EDID: guest oracle digest KAT PASS [gui.hires.edid.oracle.kat]", 13, 10, 0
align 8
edid_oracle_scratch: times 256 db 0     ; Task3474: synthetic EDID for the oracle KAT
edid_oracle_nw:    dd 0
edid_oracle_nh:    dd 0
edid_oracle_mmw:   dd 0
edid_oracle_mmh:   dd 0
edid_oracle_dpix:  dd 0
edid_oracle_dpiy:  dd 0
edid_oracle_cta:   db 0
edid_oracle_hdr:   db 0
edid_oracle_trust: db 0                  ; 1=physical DPI trusted, 0=resolution-fallback
str_edid_kat_pass: db "[PAOS64] display: raw EDID retention/checksum/clear KAT PASS [display.edid.raw.kat]", 13, 10, 0
str_edid_kat_fail: db "[PAOS64] display: raw EDID retention/checksum/clear KAT FAIL", 13, 10, 0
str_gres_gop_nonce:  db " GOP nonce=", 0
str_gres_gop_base:   db " base=0x", 0
str_gres_gop_w:      db " w=", 0
str_gres_gop_h:      db " h=", 0
str_gres_gop_stride: db " stride=", 0
str_gres_gop_pixfmt: db " pixfmt=", 0
str_gres_gop_bpp:    db " bpp=", 0
str_gres_gop_fbsize: db " fbsize=", 0
str_gres_gop_source: db " src=uefi-pre-ebs-retrospective", 0
str_gres_gop_bad_nonce:  db " GOP ERR malformed_nonce", 0
str_gres_gop_bad_record: db " GOP ERR unavailable_or_incoherent_record", 0
str_gop_kat_nonce:  db "gop-qemu-kat", 0
str_gop_kat_prefix: db " GOP nonce=gop-qemu-kat base=0x", 0
str_gop_kat_pass: db "[PAOS64] L6 gui: GOP mode record registry/lean grammar KAT PASS [gop.mode.record.kat]", 13, 10, 0
str_gop_kat_fail: db "[PAOS64] L6 gui: GOP mode record registry/lean grammar KAT FAIL", 13, 10, 0
str_gres_ri:    db " RESINFO native=", 0
str_gres_act:   db " active=", 0
str_gres_src:   db " src=", 0
str_gres_edid:  db "edid", 0
str_gres_gop:   db "gop", 0
str_gres_none:  db "none", 0
str_gres_dpi:   db " dpi=", 0
str_gres_modes: db " modes=", 0
str_gres_rm:    db " RESMODES n=", 0
str_gres_cur:   db " cur=", 0
str_gres_x:     db "x", 0
str_gres_sp:    db " ", 0
str_gres_regfail: db "[PAOS64] M6 GUI: RESINFO/RESMODES/GOP/EDID verb registration FAILED", 13, 10, 0
%endmacro
WDATA_DEFER WDATA_gui_command_res_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_gui_command_res_0_bss1 0
alignb 8
gres_out_cur:   resq 1
gres_out_ready: resb 1                 ; 1 = gres_out_buf holds a staged reply (LEAN path)
alignb 8
gres_out_buf:   resb GRES_OUT_MAX
gres_edid_digest: resb 32
%endmacro
WDATA_BSS_DEFER WDATA_gui_command_res_0_bss1
