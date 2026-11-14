;; MODULE hv/vcpu_ap_frozen
;; LAYER 5
;; EXPORTS vcpu_ap_frozen_check
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
