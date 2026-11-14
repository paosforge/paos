;; MODULE gui/img/img_photo_file_digest
;; LAYER 6
;; EXPORTS img_photo_file_digest
;; IMPORTS core/lib/sha256
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only  (caller serializes ALL shared SHA256 users; no AP/IRQ/reentry)
;
; Actual creator: rc-ai-claude on OpenAI Codex.
; img_photo_file_digest(RDI=immutable mapped LE request48) -> EAX0/RDX64,
; or EAX2/RDX0 refusal. Request: src:u64@0,length:u64@8,dst:u64@16,
; capacity:u64@24,reserved:u64@32=0,reserved:u64@40=0.
; Source length1..33554432 (32MiB), destination capacity64..67108864 (64MiB).
; Full spans must not wrap; destination excludes source and request48. Readonly
; request/source alias is allowed. Caller maps and stabilizes every admitted
; span for the entire synchronous call, and owns access/lifetime policy.
;
; Output64: magic8="PAOSFILE",LEu32version1@8,LEu32algorithm1(SHA256)@12,
; LEu64sourceLength@16,standard SHA256(raw original bytes)32@24,reserved8zero@56.
; All bytes matter, including metadata/container/padding/trailing bytes; there
; is no decoding, format sniffing or pixel/perceptual comparison. File identity
; is distinct from img_rgba_digest. Length+SHA equality is candidate evidence,
; never skip/import/delete/access authority. No filesystem/IO/retained pointers.
;
; Validate all request fields/full spans before reading any source byte. All
; SHA work precedes publication: refusal changes no caller bytes; success
; writes exactly64B and leaves capacity slack/source/request unchanged.
; No allocation/free or wrapper globals/decoder-state mutation. Initialized
; and wiped176B private frame holds SHA context112 and candidate64. Shared
; SHA module compression scratch remains nonzeroized; serialize ALL SHA users.
; Full64 RBX/RBP/R12-R15, flags/DF and FP controls preserved. O(length).

%if S256_CTX_SZ > 112
    %error "img_photo_file_digest private frame must fit SHA256 context"
%endif

img_photo_file_digest:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 176
    mov  rbp, rsp
    cld
    mov  r11, rdi
    mov  rdi, rbp
    xor  eax, eax
    mov  ecx, 22
    rep  stosq
    test r11, r11
    jz   .bad
    mov  r10, r11
    add  r10, 48
    jc   .bad
    mov  rbx, [r11]
    mov  r12, [r11 + 8]
    mov  r15, [r11 + 16]
    mov  r9, [r11 + 24]
    cmp  qword [r11 + 32], 0
    jne  .bad
    cmp  qword [r11 + 40], 0
    jne  .bad
    test rbx, rbx
    jz   .bad
    test r15, r15
    jz   .bad
    test r12, r12
    jz   .bad
    cmp  r12, 33554432
    ja   .bad
    cmp  r9, 64
    jb   .bad
    cmp  r9, 67108864
    ja   .bad
    mov  r8, rbx
    add  r8, r12
    jc   .bad
    add  r9, r15
    jc   .bad
    cmp  rbx, r9
    jae  .source_clear
    cmp  r15, r8
    jb   .bad
.source_clear:
    cmp  r11, r9
    jae  .request_clear
    cmp  r15, r10
    jb   .bad
.request_clear:
    mov  rax, 'PAOSFILE'
    mov  [rbp + 112], rax
    mov  rax, 0x0000000100000001
    mov  [rbp + 120], rax
    mov  [rbp + 128], r12
    mov  rdi, rbp
    call sha256_stream_init
    test rax, rax
    jnz  .bad
    mov  rdi, rbp
    mov  rsi, rbx
    mov  rdx, r12
    call sha256_stream_update
    test rax, rax
    jnz  .bad
    mov  rdi, rbp
    lea  rsi, [rbp + 136]
    call sha256_stream_final
    test rax, rax
    jnz  .bad
    mov  rdi, r15
    lea  rsi, [rbp + 112]
    mov  ecx, 8
    rep  movsq
    xor  eax, eax
    mov  edx, 64
    jmp  .return
.bad:
    mov  eax, 2
    xor  edx, edx
.return:
    mov  r8d, eax
    mov  r9, rdx
    mov  rdi, rbp
    xor  eax, eax
    mov  ecx, 22
    rep  stosq
    mov  eax, r8d
    mov  rdx, r9
    add  rsp, 176
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
