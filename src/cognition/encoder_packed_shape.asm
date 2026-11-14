;; MODULE cognition/encoder_packed_shape
;; LAYER 6
;; EXPORTS cog_encoder_packed_rank_shape_f32_advisory
;; IMPORTS cog_encoder_pack_models_advisory, cog_encoder_ascii_cls_shape_f32_advisory, cog_encoder_score_f32_advisory
;; CAPS
;; OWNER saga:cognition
; Optional prepared ASCII -> PMW1/BLP1 descriptors -> exact shape encoder ->
; normalized prototype advice. All old fixed/shape/cooperative/digest APIs exact.
; SysV RDI=text,RSI=result20,RDX=config128,RCX=prepared2096. Configuration is
; exactly existing packed_rank128 EXCEPT workbytes=A(L)+6816+4*count. Preparation
; is the accepted shape_prepare record (header48 plus capacity512 token IDs).
; Caller prepares using admitted immutable text/PVT before allocating scratch.
; L2..512,count2..256,width384; text0..4096,PVT20..8MiB,PEM47671320,
; PMW21234832,BLP243376,prototypebytes=count1536,resultbytes20. Originalconfig
; and record8-aligned; work8-aligned, output/prototypes/packs4-aligned, nonnull.
; Exact full64 length/end/alias checks protect whole arena/result against each
; other and whole text/PVT/PEM/PMW/BLP/prototypes/config128/prepared2096 before
; descriptor writes. Immutable sources may alias; no mapping rights inferred.
;
; Arena: CLS1536,12model descriptors3744,accepted encoder A(L),score1536+4count.
; A(L)=align4(9L)+10N+max(4N+144L^2,20352L),N=1536L. Empty/count2=78268;
; max/count256=48771232. Score scratch follows ACTUAL shape, no worstcase gap.
; Bounds/identity/header snapshot select exact size, never model admission. The
; accepted shape child privately re-tokenizes and compares count/used IDs before
; encoder writes, and executes every ordered12 layer on the actual guarded/shared
; QKV path. Stable authenticated immutable mappings across this synchronous call
; remain CALLER responsibility, including original preparation/config. No loader,
; new format/global scratch/allocator/cached digest/trust/authority/quality grant.
; Existing digest-bound path remains intact; caller-supplied packs alone do not
; establish trust. Thresholds/prototype labels remain uncalibrated caller policy.
;
; EAX0choose/1abstain/2invalid. Metadata/header/ownership/builder refusal leaves
; entire arena/result unchanged. Token/content/numeric failure after builder may
; retain descriptors/stages; final result stays unchanged, no failed CLS feeds
; scoring. Scorer refusal retains encoder scratch but never publishes stale advice.
; Only successful scorer publishes result, including valid abstain. Complete caller
; MXCSR/x87/DF/nonvolatile GPR/RSP preserved. Ownstack392bytes; nestedshape<6048,
; builder<672,scorer<584. No native runtime/latency/model quality claim.

cog_encoder_packed_rank_shape_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 344
    mov  r12, rdi
    mov  r13, rsi
    mov  rbp, rdx
    mov  [rsp+256], rcx          ; original prepared record
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
    add  rax, 128
    jc   .invalid
    mov  [rsp+248], rbp
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbp+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 16
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
    mov  rax, [rsp+256]
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
    mov  [rsp+264+rcx*8], rdx
    inc  ecx
    cmp  ecx, 6
    jb   .shape_snapshot
    mov  eax, [rsp+264]
    cmp  eax, 2
    jb   .invalid
    cmp  eax, 512
    ja   .invalid
    cmp  dword [rsp+268], 0
    jne  .invalid
    call .size                    ; bounded full64 arithmetic, never record trust
    cmp  [rsp+272], rax
    jne  .invalid
    mov  [rsp+312], rax           ; accepted exact shape arena A(L)
    lea  rax, [rax+rbx*4+6816]
    cmp  [rsp+88], rax            ; exact whole classifier arena, full64
    jne  .invalid
    mov  rax, [rsp+280]
    cmp  rax, r12
    jne  .invalid
    mov  rax, [rsp+288]
    cmp  rax, [rsp]
    jne  .invalid
    mov  rax, [rsp+296]
    cmp  rax, [rsp+8]
    jne  .invalid
    mov  rax, [rsp+304]
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
    call .check_sources           ; whole arena protects every later source
    jnz  .invalid
    mov  qword [rsp+128], 21234832
    mov  qword [rsp+136], 243376
    mov  qword [rsp+144], 3744
    mov  qword [rsp+152], 0
    mov  rdi, [rsp+40]
    mov  rsi, [rsp+56]
    lea  rdx, [r15+1536]
    lea  rcx, [rsp+128]
    call cog_encoder_pack_models_advisory
    test eax, eax
    jnz  .invalid                 ; failed descriptors never reach encoder
    mov  rax, 0x0000000c00000200  ; maximum512, all12 admitted layers
    mov  [rsp+128], rax
    mov  rax, [rsp]
    mov  [rsp+136], rax
    mov  rax, [rsp+8]
    mov  [rsp+144], rax
    mov  rax, [rsp+16]
    mov  [rsp+152], rax
    mov  qword [rsp+160], 1536
    mov  rax, [rsp+24]
    mov  [rsp+168], rax
    mov  rax, [rsp+32]
    mov  [rsp+176], rax
    mov  rax, [rsp+56]
    add  rax, 16
    mov  [rsp+184], rax
    mov  qword [rsp+192], 1536
    add  rax, 1536
    mov  [rsp+200], rax           ; exact embedding beta from admitted BLP
    mov  qword [rsp+208], 1536
    lea  rax, [r15+1536]
    mov  [rsp+216], rax
    mov  qword [rsp+224], 3744
    lea  rax, [r15+5280]
    mov  [rsp+232], rax
    mov  rax, [rsp+312]
    mov  [rsp+240], rax
    mov  rdi, r12
    mov  rsi, r15
    lea  rdx, [rsp+128]
    mov  rcx, [rsp+256]
    call cog_encoder_ascii_cls_shape_f32_advisory
    test eax, eax
    jnz  .invalid                 ; failed shape/graph never reaches scorer
    mov  rax, [rsp+112]
    mov  [rsp+128], rax
    mov  rax, [rsp+120]
    mov  [rsp+136], rax
    mov  qword [rsp+144], 1536
    mov  rax, [rsp+104]
    mov  [rsp+152], rax
    mov  qword [rsp+160], 20
    mov  rax, [rsp+312]
    lea  rax, [r15+rax+5280]
    mov  [rsp+168], rax
    lea  rax, [rbx*4+1536]
    mov  [rsp+176], rax
    mov  qword [rsp+184], 0
    mov  rdi, r15
    mov  rsi, r14
    mov  rdx, r13
    lea  rcx, [rsp+128]
    call cog_encoder_score_f32_advisory
    jmp  .out
.invalid:
    mov  eax, 2
.out:
    add  rsp, 344
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
    mov  rdi, [r9+248]
    mov  esi, 128
    call .range_ok
    jnz  .sources_bad
    mov  rdi, [r9+256]
    mov  esi, 2096               ; protect entire prepared capacity
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
