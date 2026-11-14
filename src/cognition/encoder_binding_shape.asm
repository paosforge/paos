;; MODULE cognition/encoder_binding_shape
;; LAYER 6
;; EXPORTS cog_encoder_digest_bound_rank_shape_f32_advisory
;; IMPORTS core/lib/sha256, cog_encoder_packed_rank_shape_f32_advisory
;; CAPS
;; OWNER saga:cognition
;; CONTEXT: bsp_only  (canonical SHA256 has unlocked module-static scratch)
; Optional five-artifact digest-bound prepared exact-shape classifier advice.
; SysV RDI=text, RSI=result20, RDX=config288, RCX=prepared2096. Config first128
; match packed_rank_shape exactly; tail160 are trusted SHA256 pins in order
; PVT/PEM/PMW/BLP/prototypes. Same accepted preparation record, no new format.
; Arena EXACTLY A(L)+6816+4count; L2..512, count2..256, every ordered12 layer.
; A(L)=align4(9L)+15360L+max(6144L+144L^2,20352L). No fixed-workspace gap.
; Full64 sizes/ends/nonoverlap and prepared header/identity checked before any
; hash or caller write. Whole result/arena protect each other and text, all five
; complete artifacts, original config288 (including pins), prepared2096. Immutable
; inputs may alias. Whole config and shape header snapshotted; accepted child
; retokenizes/compares actual used IDs before encoder writes. Never cached trust.
; Canonical unchanged SHA256 hashes full artifact bytes including every tail;
; all five32-byte pins must match before child inference/descriptors write.
; Caller supplies TRUSTED pins bound to admitted model/prototypes/labels/policy,
; and stable immutable admitted mapped inputs/config/preparation for whole call.
; Attacker-selected matching pins do not establish admission. No loader, trust
; store, allocation, global scratch, authority, calibration or quality change.
; BSP-only serialized context, never AP/IRQ, as canonical SHA256 requires.
; EAX0choose/1abstain/2invalid. Preflight/hash/digest refusal leaves entire caller
; result/arena unchanged. Downstream refusal preserves result; accepted child may
; retain scratch. No stale advice consumed; successful abstention preserved.
; Caller DF restored after canonical hash REP; full MXCSR/x87/nonvolatile GPR/RSP
; preserved. Ownstack<480bytes; nestedshape<6608. All old APIs remain byte-exact.

cog_encoder_digest_bound_rank_shape_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 408
    pushfq
    pop  qword [rsp+320]
    mov  r12, rdi
    mov  r13, rsi
    mov  rbp, rdx
    mov  [rsp+336], rcx          ; original prepared2096
    test r12, r12
    jz   .invalid
    test r13, r13
    jz   .invalid
    test r13b, 3
    jnz  .invalid
    test rbp, rbp
    jz   .invalid
    test bpl, 7
    jnz  .invalid
    mov  rax, rbp
    add  rax, 288
    jc   .invalid
    mov  [rsp+328], rbp
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbp+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 36
    jb   .snapshot
    cmp  qword [rsp], 4096
    ja   .invalid
    cmp  qword [rsp+16], 20
    jb   .invalid
    cmp  qword [rsp+16], 8388608
    ja   .invalid
    cmp  qword [rsp+32], 47671320
    jne  .invalid
    cmp  qword [rsp+48], 21234832
    jne  .invalid
    cmp  qword [rsp+64], 243376
    jne  .invalid
    cmp  qword [rsp+72], 20
    jne  .invalid
    mov  ebx, [rsp+112]
    cmp  ebx, 2
    jb   .invalid
    cmp  ebx, 256
    ja   .invalid
    cmp  dword [rsp+116], 384
    jne  .invalid
    imul rax, rbx, 1536
    cmp  [rsp+104], rax
    jne  .invalid
    mov  eax, [rsp+120]
    and  eax, 0x7fffffff
    cmp  eax, 0x7f800000
    jae  .invalid
    mov  eax, [rsp+124]
    and  eax, 0x7fffffff
    cmp  eax, 0x7f800000
    jae  .invalid
    test eax, eax
    jz   .margin_valid
    test dword [rsp+124], 0x80000000
    jnz  .invalid
.margin_valid:
    cmp  qword [rsp+8], 0
    je   .invalid
    mov  ecx, 24
.pack_pointers:
    mov  rdi, [rsp+rcx]
    test rdi, rdi
    jz   .invalid
    test dil, 3
    jnz  .invalid
    add  ecx, 16
    cmp  ecx, 72
    jb   .pack_pointers
    mov  r14, [rsp+96]
    test r14, r14
    jz   .invalid
    test r14b, 3
    jnz  .invalid
    mov  r15, [rsp+80]
    test r15, r15
    jz   .invalid
    test r15b, 7
    jnz  .invalid
    mov  rax, [rsp+336]
    test rax, rax
    jz   .invalid
    test al, 7
    jnz  .invalid
    mov  rdx, rax
    add  rdx, 2096
    jc   .invalid
    xor  ecx, ecx
.shape_snapshot:
    mov  rdx, [rax+rcx*8]
    mov  [rsp+344+rcx*8], rdx
    inc  ecx
    cmp  ecx, 6
    jb   .shape_snapshot
    mov  eax, [rsp+344]
    cmp  eax, 2
    jb   .invalid
    cmp  eax, 512
    ja   .invalid
    cmp  dword [rsp+348], 0
    jne  .invalid
    call .size                    ; bounded full64 arithmetic, never record trust
    cmp  [rsp+352], rax
    jne  .invalid
    lea  rax, [rax+rbx*4+6816]
    cmp  [rsp+88], rax            ; exact whole classifier arena, full64
    jne  .invalid
    mov  rax, [rsp+360]
    cmp  rax, r12
    jne  .invalid
    mov  rax, [rsp+368]
    cmp  rax, [rsp]
    jne  .invalid
    mov  rax, [rsp+376]
    cmp  rax, [rsp+8]
    jne  .invalid
    mov  rax, [rsp+384]
    cmp  rax, [rsp+16]
    jne  .invalid
    mov  r9, rsp
    mov  r10, r13
    mov  r11, r13
    add  r11, 20
    jc   .invalid
    call .check_sources
    jnz  .invalid
    mov  rdi, r15
    mov  rsi, [rsp+88]
    call .range_ok
    jnz  .invalid
    mov  r10, r15
    mov  r11, r15
    add  r11, [rsp+88]
    jc   .invalid
    call .check_sources           ;whole arena protects pins and every artifact
    jnz  .invalid
    cld                           ;canonical streaming SHA requires forward REP
    xor  ebx, ebx
.hash_artifact:
    mov  eax, ebx
    shl  eax, 4
    add  eax, 8
    cmp  ebx, 4
    jne  .hash_slot
    mov  eax, 96                  ;prototype slot follows packed workspace fields
.hash_slot:
    mov  rsi, [rsp+rax]
    mov  rdx, [rsp+rax+8]
    lea  rdi, [rsp+288]
    call sha256_hash
    test rax, rax
    jnz  .invalid                 ;hash failure never consumes stale digest
    mov  eax, ebx
    shl  eax, 5
    lea  rdx, [rsp+rax+128]
    xor  r8d, r8d
    xor  ecx, ecx
.digest_words:
    mov  rax, [rsp+rcx*8+288]
    xor  rax, [rdx+rcx*8]
    or   r8, rax
    inc  ecx
    cmp  ecx, 4
    jb   .digest_words
    test r8, r8
    jnz  .invalid                 ;all32 digestbytes, no prefix match
    inc  ebx
    cmp  ebx, 5
    jb   .hash_artifact
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, rsp
    mov  rcx, [rsp+336]
    call cog_encoder_packed_rank_shape_f32_advisory
    jmp  .restore_df
.invalid:
    mov  eax, 2
.restore_df:
    test qword [rsp+320], 0x400
    jz   .df_clear
    std
    jmp  .out
.df_clear:
    cld
.out:
    add  rsp, 408
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
.check_sources:
    mov  rdi, r12
    mov  rsi, [r9]
    test rsi, rsi
    jz   .empty_text
    call .range_ok
    jnz  .sources_bad
.empty_text:
    mov  ecx, 8
.packs:
    mov  rdi, [r9+rcx]
    mov  rsi, [r9+rcx+8]
    call .range_ok
    jnz  .sources_bad
    add  ecx, 16
    cmp  ecx, 72
    jb   .packs
    mov  rdi, r14
    mov  rsi, [r9+104]
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+328]
    mov  esi, 288
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+336]
    mov  esi, 2096               ; protect whole prepared capacity
    call .range_ok
    jnz  .sources_bad
    xor  eax, eax
    ret
.sources_bad:
    or   eax, 1
    ret
.range_ok:
    mov  rax, rdi
    add  rax, rsi
    jc   .range_bad
    cmp  rax, r10
    jbe  .range_good
    cmp  rdi, r11
    jae  .range_good
.range_bad:
    or   eax, 1
    ret
.range_good:
    xor  eax, eax
    ret

.size:
    mov  r10d, eax
    imul r10, 1536
    mov  edx, eax
    imul rdx, rdx
    imul rdx, 144
    lea  rdx, [rdx+r10*4]
    mov  r11d, eax
    imul r11, 20352
    cmp  rdx, r11
    cmovb rdx, r11
    imul r11, r10, 10
    add  rdx, r11
    lea  ecx, [eax+eax*8]
    add  rcx, 3
    and  rcx, -4
    lea  rax, [rdx+rcx]
    ret
