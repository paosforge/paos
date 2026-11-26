;; MODULE hv/vcpu_ap_frozen
;; LAYER 5
;; EXPORTS vcpu_ap_frozen_check, vcpu_ap_frozen_shadow, vafs_valid
;; IMPORTS hv/vcpu_ap_hash
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Checked helpers; AP cycle wiring remains separate.
; C4 frozen-blob hash checker. Caller freezes and validates
; mapped, owned metadata/ranges outside guest EPT before publishing START.
; RDI immutable manifest: epoch(u64), count(u64), count*48-byte records:
; address(u64), length(u64), SHA256(32B). RSI exact current custody epoch.
; 1..24 blobs, each 1..4096B, at most96KiB hash input, private stack scratch.
; No mutation/publication. Return1 if complete and equal,0 means do not enter.
; A matching digest never authorizes writes: separate writer gates cover all
; EPT/SLAT descendants and every table/template mutation while the gang is open.
;
; T1-5 S7 per-exit cost: the BSP (vst_epoch_prepare, twice) and the AP
; (vcpu_ap_run) recheck the whole manifest on every vCPU0 exit. A private
; shadow keeps the same guarantee without SHA-256 on that path. At seal,
; vcpu_ap_frozen_shadow copies every blob into root-only storage outside any
; guest EPT/NPT, hashes the COPY and requires each sealed digest. A later
; check takes the fast path only when the count and every record's address,
; length and digest equal the shadow's, and every live byte
; equals the verified shadow byte; then SHA-256(live) = sealed digest = the
; current manifest digest, exactly what the hash path proves. Any miss falls
; through to the unchanged full hash, which alone decides refusal. As with a
; rewritten manifest digest today, only a writer that also rewrites the
; private shadow identically is not caught. The fast path writes nothing.
vcpu_ap_frozen_check:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 40
    mov  r12, rdi
    test rsi, rsi
    jz   .bad
    cmp  [r12], rsi
    jne  .bad
    mov  r14, [r12 + 8]
    test r14, r14
    jz   .bad
    cmp  r14, 24
    ja   .bad
    ; PRECONDITION: no seal runs concurrently with any check. vafs_valid is
    ; read once, with no seqlock. Both seals (vst_seal, vsm_seal) are BSP-only
    ; and need vca_ready == 0 (vcpu_start_seal.asm:27, vcpu_svm_prepare.asm:383);
    ; the AP checks only while vca_ready != 0 (vcpu_ap.asm:262, vcpu_ap_run.asm:71)
    ; and the BSP checks only from its own exit path after START. Both closes
    ; clear vafs_valid with vca_ready. A future reseal while the gang is open
    ; must add a generation re-read after the compare.
    cmp  qword [rel vafs_valid], 1
    jne  .hash
    cmp  [rel vafs_count], r14          ; never an index entry the seal did not write
    jne  .hash
    xor  ebx, ebx
.fast:
    imul r13, rbx, 48
    lea  rdi, [rel vafs_index]
    add  rdi, r13
    lea  r13, [r12 + r13 + 16]
    xor  ecx, ecx
.fast_meta:                             ; address, length, 32B digest
    mov  rax, [r13 + rcx*8]
    cmp  rax, [rdi + rcx*8]
    jne  .hash
    inc  ecx
    cmp  ecx, 6
    jb   .fast_meta
    mov  rsi, [r13]
    mov  rdx, [r13 + 8]                 ; 1..4096, bound when the shadow was sealed
    mov  rdi, rbx
    shl  rdi, 12
    lea  rax, [rel vafs_bytes]
    add  rdi, rax
    xor  ecx, ecx
.fast_qword:
    lea  rax, [rcx + 8]
    cmp  rax, rdx
    ja   .fast_byte
    mov  rax, [rsi + rcx]
    cmp  rax, [rdi + rcx]
    jne  .hash
    add  rcx, 8
    jmp  .fast_qword
.fast_byte:
    cmp  rcx, rdx
    jae  .fast_next
    mov  al, [rsi + rcx]
    cmp  al, [rdi + rcx]
    jne  .hash
    inc  rcx
    jmp  .fast_byte
.fast_next:
    inc  ebx
    cmp  rbx, r14
    jb   .fast
    mov  eax, 1
    jmp  .out
.hash:
    xor  ebx, ebx
.record:
    imul r13, rbx, 48
    lea  r13, [r12 + r13 + 16]
    mov  rsi, [r13]
    test rsi, rsi
    jz   .bad
    mov  rdx, [r13 + 8]
    test rdx, rdx
    jz   .bad
    cmp  rdx, 4096
    ja   .bad
    mov  rax, rsi
    add  rax, rdx
    jc   .bad
    mov  rdi, rsp
    call vcpu_ap_sha256_hash
    test rax, rax
    jnz  .bad
    xor  edx, edx
    xor  ecx, ecx
.digest:
    mov  rax, [rsp + rcx*8]
    xor  rax, [r13 + rcx*8 + 16]
    or   rdx, rax
    inc  ecx
    cmp  ecx, 4
    jb   .digest
    test rdx, rdx
    jnz  .bad
    inc  ebx
    cmp  rbx, r14
    jb   .record
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    add  rsp, 40
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vcpu_ap_frozen_shadow(RDI manifest, RSI its sealed epoch) -> EAX1 /0.
; Seal-time only (BSP, READY0, no GO, no AP check running). Invalidates first,
; copies each validated blob, hashes the private copy against the sealed
; digest and publishes the shadow LAST. 0 leaves it invalid: every later
; check then takes the full hash path, never a weaker one.
vcpu_ap_frozen_shadow:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 40
    mov  qword [rel vafs_valid], 0
    mov  r12, rdi
    test rsi, rsi
    jz   .bad
    cmp  [r12], rsi
    jne  .bad
    mov  r14, [r12 + 8]
    test r14, r14
    jz   .bad
    cmp  r14, 24
    ja   .bad
    xor  ebx, ebx
.record:
    imul r13, rbx, 48
    lea  r13, [r12 + r13 + 16]
    mov  rsi, [r13]
    test rsi, rsi
    jz   .bad
    mov  rdx, [r13 + 8]
    test rdx, rdx
    jz   .bad
    cmp  rdx, 4096
    ja   .bad
    mov  rax, rsi
    add  rax, rdx
    jc   .bad
    imul rdi, rbx, 48
    lea  rax, [rel vafs_index]
    add  rdi, rax
    xor  ecx, ecx
.meta:
    mov  rax, [r13 + rcx*8]
    mov  [rdi + rcx*8], rax
    inc  ecx
    cmp  ecx, 6
    jb   .meta
    mov  rdi, rbx
    shl  rdi, 12
    lea  rax, [rel vafs_bytes]
    add  rdi, rax
    mov  rcx, rdx
    cld
    rep  movsb
    mov  rsi, rbx
    shl  rsi, 12
    lea  rax, [rel vafs_bytes]
    add  rsi, rax
    mov  rdx, [r13 + 8]
    mov  rdi, rsp
    call vcpu_ap_sha256_hash            ; the COPY, never the live blob
    test rax, rax
    jnz  .bad
    xor  edx, edx
    xor  ecx, ecx
.digest:
    mov  rax, [rsp + rcx*8]
    xor  rax, [r13 + rcx*8 + 16]
    or   rdx, rax
    inc  ecx
    cmp  ecx, 4
    jb   .digest
    test rdx, rdx
    jnz  .bad
    inc  ebx
    cmp  rbx, r14
    jb   .record
    mov  [rel vafs_count], r14
    mov  qword [rel vafs_valid], 1       ; last
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    add  rsp, 40
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Root-only, outside every guest EPT/NPT leaf (the seals admit only guest RAM).
; paos.asm includes core/abi/wdata.inc before every module.
%macro WDATA_BSS_hv_vcpu_ap_frozen 0
alignb 4096
vafs_bytes: resb 24 * 4096
vafs_index: resb 24 * 48
vafs_valid: resq 1
vafs_count: resq 1
%endmacro
%ifdef PAOS_WDATA_REGION
WDATA_BSS_DEFER WDATA_BSS_hv_vcpu_ap_frozen
%else
section .bss                            ; standalone host assembly: writable zeros
WDATA_BSS_hv_vcpu_ap_frozen
section .text
%endif
