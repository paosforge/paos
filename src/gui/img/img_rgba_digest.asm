;; MODULE gui/img/img_rgba_digest
;; LAYER 6
;; EXPORTS img_rgba_digest
;; IMPORTS core/lib/sha256
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only  (shared SHA256 compression workspace; caller serializes all SHA users)
;
; Actual creator: rc-ai-claude running on OpenAI Codex.
; img_rgba_digest(RDI=immutable LE request48) -> EAX0/RDX64, or EAX2/RDX0.
; Request: src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,w:u32@32,h:u32@36,
; stride:u64@40. Stable mapped top-down straight RGBA8888, dimensions1..4096,
; area<=4194304, stride>=w*4, (h-1)*stride+w*4<=len (checked unsigned math).
; Full src/dst spans must be nonwrapping and disjoint; dst/request48 disjoint.
; Readonly source/request alias is allowed. Source padding is never hashed.
;
; Output64 LE: version:u32@0=1,algorithm:u32@4=1(SHA256),w:u32@8,h:u32@12,
; pixel_bytes:u64@16=w*h*4,reserved:u64@24=0,digest:32bytes@32.
; Digest = SHA256("PaOS.RGBA.v1" + four NUL bytes + LEu32(w)+LEu32(h)
;                  + row0[w*4] + row1[w*4] + ...).
; Dimensions are part of identity; stride/padding/metadata are not. All RGBA
; bytes, including hidden RGB under alpha0, matter. Caller bakes orientation
; using the shared decoder before hashing. This is exact decoded-pixel identity,
; not perceptual/visually-equivalent duplicate detection or original file hash.
; SHA equality is a candidate match, not permission to delete/skip a file.
;
; Every request/span/geometry check and all SHA work precede publication of
; exactly64B; failure writes no caller bytes, success leaves slack untouched.
; No allocation/free/IO/retained pointers or globals of this wrapper. The real
; SHA module has shared compression scratch: BSP-only, serialized with ALL SHA
; users (no AP/IRQ/reentrant calls). Context/header/candidate stay in initialized
; and wiped224B frame. Shared SHA scratch is not zeroized by this operation.
; Full64 nonvolatiles and caller flags/DF/FP controls preserved. O(w*h), <=16MiB
; pixel bytes+24B header; maximum416B below caller return with current SHA code.

%if S256_CTX_SZ > 112
    %error "img_rgba_digest private frame must fit the SHA256 context"
%endif

img_rgba_digest:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 224
    mov  rbp, rsp
    cld
    mov  r11, rdi
    mov  rdi, rbp
    xor  eax, eax
    mov  ecx, 28
    rep  stosq
    test r11, r11
    jz   .bad
    mov  r10, r11
    add  r10, 48
    jc   .bad
    mov  rbx, [r11]
    mov  r8, [r11 + 8]
    mov  r15, [r11 + 16]
    mov  r9, [r11 + 24]
    mov  r12d, [r11 + 32]
    mov  r13d, [r11 + 36]
    mov  r14, [r11 + 40]
    test rbx, rbx
    jz   .bad
    test r15, r15
    jz   .bad
    cmp  r9, 64
    jb   .bad
    test r12d, r12d
    jz   .bad
    test r13d, r13d
    jz   .bad
    cmp  r12d, 4096
    ja   .bad
    cmp  r13d, 4096
    ja   .bad
    mov  [rbp + 128], r12d
    mov  [rbp + 132], r13d
    mov  rax, r12
    imul rax, r13
    cmp  rax, 4194304
    ja   .bad
    shl  rax, 2
    mov  [rbp + 160], rax
    shl  r12, 2
    cmp  r14, r12
    jb   .bad
    mov  rax, r13
    dec  rax
    mul  r14
    test rdx, rdx
    jnz  .bad
    add  rax, r12
    jc   .bad
    cmp  rax, r8
    ja   .bad
    add  r8, rbx
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
    mov  rax, 'PaOS.RGB'
    mov  [rbp + 112], rax
    mov  dword [rbp + 120], 'A.v1'    ; four NULs at124..127 from initialization
    mov  rax, 0x0000000100000001
    mov  [rbp + 144], rax
    mov  rax, [rbp + 128]
    mov  [rbp + 152], rax
    mov  rdi, rbp
    call sha256_stream_init
    test rax, rax
    jnz  .bad
    mov  rdi, rbp
    lea  rsi, [rbp + 112]
    mov  edx, 24
    call sha256_stream_update
    test rax, rax
    jnz  .bad
.row:
    mov  rdi, rbp
    mov  rsi, rbx
    mov  rdx, r12
    call sha256_stream_update
    test rax, rax
    jnz  .bad
    dec  r13d
    jz   .final
    add  rbx, r14                    ; only step to rows proven in full source
    jmp  .row
.final:
    mov  rdi, rbp
    lea  rsi, [rbp + 176]
    call sha256_stream_final
    test rax, rax
    jnz  .bad
    mov  rdi, r15
    lea  rsi, [rbp + 144]
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
    mov  ecx, 28
    rep  stosq
    mov  eax, r8d
    mov  rdx, r9
    add  rsp, 224
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
