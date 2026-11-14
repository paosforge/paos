;; MODULE hv/vcpu_ap_xstate
;; LAYER 5
;; EXPORTS vcpu_ap_xstate_save, vcpu_ap_xstate_guest, vcpu_ap_xstate_host, vcpu_ap_xcr0_valid
;; IMPORTS
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. AP-local standard XSAVE, never BSP globals.
; Context8q: host buffer,guest buffer,capacity,frozen allowed guest XCR0,
; current guest XCR0,own host XCR0,host-saved flag,own supported mask.
; Caller proves nonoverlapping mapped64-aligned buffers/context outside EPT,
; zeroed standard headers and guest FCW037F/MXCSR1F80 at START. IF0,live guard.
; This backend requires own XSAVE+OSXSAVE and own host x87+SSE enabled;
; unsupported APs refuse without modifying native state. No feature enabling.
; All routines preserve callee-save GPRs. Faults remain guarded/nonresuming.
%include "hv/vcpu_ap_xstate.inc"

; RSI candidate,RDX supported ->EAX1 legal /0 invalid. Same architectural
; dependencies as the ordinary BSP checker; private AP leaf, no global reason.
vcpu_ap_xcr0_valid:
    xor  eax, eax
    mov  rcx, rdx
    not  rcx
    test rsi, rcx
    jnz  .out
    test esi, 1
    jz   .out
    mov  ecx, esi
    and  ecx, 6
    cmp  ecx, 4
    je   .out
    mov  ecx, esi
    and  ecx, 0xE0
    jz   .mpx
    cmp  ecx, 0xE0
    jne  .out
    test esi, 4
    jz   .out
.mpx:
    mov  ecx, esi
    and  ecx, 0x18
    jz   .amx
    cmp  ecx, 0x18
    jne  .out
.amx:
    mov  ecx, esi
    and  ecx, 0x60000
    jz   .ok
    cmp  ecx, 0x60000
    jne  .out
.ok:
    mov  eax, 1
.out:
    ret

; Capture this AP's live host XCR0 and vectors once per attempted boundary
; pair, before any guest restore. Returns1 or0; refusal writes no context/data.
vcpu_ap_xstate_save:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    cmp  qword [r12 + VAX_SAVED], 0
    jne  .bad
    mov  rax, [r12 + VAX_HOST]
    mov  rdx, [r12 + VAX_GUEST]
    test rax, rax
    jz   .bad
    test rdx, rdx
    jz   .bad
    cmp  rax, rdx
    je   .bad
    or   rax, rdx
    test eax, 63
    jnz  .bad
    cmp  qword [r12 + VAX_CAPACITY], 576
    jb   .bad
    mov  eax, 1
    cpuid
    and  ecx, (1 << 26) | (1 << 27)
    cmp  ecx, (1 << 26) | (1 << 27)
    jne  .bad
    mov  rax, cr0
    test eax, (1 << 2) | (1 << 3)         ; EM/TS would make XSAVE fault
    jnz  .bad
    mov  rax, cr4
    test eax, 1 << 18
    jz   .bad
    xor  ecx, ecx
    xgetbv
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax                       ; own live host, never BSP snapshot
    and  eax, 3
    cmp  eax, 3                         ; preserve every usable legacy vector
    jne  .bad
    mov  eax, 0xD
    xor  ecx, ecx
    cpuid
    shl  rdx, 32
    or   rax, rdx
    mov  r14, rax
    cmp  ebx, 576
    jb   .bad
    cmp  ecx, ebx
    jb   .bad
    cmp  rcx, [r12 + VAX_CAPACITY]        ; all standard user components fit
    ja   .bad
    mov  rsi, r13
    mov  rdx, r14
    call vcpu_ap_xcr0_valid
    cmp  eax, 1
    jne  .bad
    mov  r15, [r12 + VAX_ALLOWED]
    bt   r15, 9                         ; PKRU is hidden and never guest-owned
    jc   .bad
    mov  rsi, r15
    mov  rdx, r13                       ; guest set must fit THIS host's XCR0
    call vcpu_ap_xcr0_valid
    cmp  eax, 1
    jne  .bad
    mov  rsi, [r12 + VAX_VALUE]
    mov  rdx, r15
    call vcpu_ap_xcr0_valid
    cmp  eax, 1
    jne  .bad
    ; Validate the standard guest header before a later XRSTOR. These mapped
    ; private bytes are AP/BSP-owned, never supplied directly by the guest.
    mov  rdi, [r12 + VAX_GUEST]
    mov  rax, r13
    not  rax
    test [rdi + 512], rax
    jnz  .bad
    xor  ecx, ecx
.header:
    cmp  qword [rdi + rcx*8 + 520], 0    ; XCOMP_BV and six reserved qwords
    jne  .bad
    inc  ecx
    cmp  ecx, 7
    jb   .header
    ; Clear host header first: XSAVE does not promise to write reserved bytes.
    ; Caller owns the full host buffer, which is disposable until SAVED=1.
    mov  rdi, [r12 + VAX_HOST]
    mov  qword [rdi + 512], 0
    mov  qword [rdi + 520], 0
    mov  qword [rdi + 528], 0
    mov  qword [rdi + 536], 0
    mov  qword [rdi + 544], 0
    mov  qword [rdi + 552], 0
    mov  qword [rdi + 560], 0
    mov  qword [rdi + 568], 0
    mov  rax, r13
    mov  rdx, rax
    shr  rdx, 32
    xsave64 [rdi]
    mov  [r12 + VAX_HOST_VALUE], r13
    mov  [r12 + VAX_SUPPORTED], r14
    mov  qword [r12 + VAX_SAVED], 1
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Last helper before FINAL. Caller has freshly checked saved/current masks;
; hardware guest XSETBV always exits and BSP updates VALUE only while both root.
vcpu_ap_xstate_guest:
    mov  r8, rdi
    mov  eax, [r8 + VAX_HOST_VALUE]
    mov  edx, [r8 + VAX_HOST_VALUE + 4]
    fxrstor64 [rel vax_init]             ; SSE remains usable with XCR0.SSE=0
    mov  rdi, [r8 + VAX_GUEST]
    xrstor64 [rdi]                      ; also initializes every disabled part
    mov  eax, [r8 + VAX_VALUE]
    mov  edx, [r8 + VAX_VALUE + 4]
    xor  ecx, ecx
    xsetbv
    ret

; After this attempt's executor exit, exact host vectors and XCR0. RDI ctx;
; caller has already executed VAX_LAND or never restored guest state. No #GP
; recovery: the park guard owns any unexpected instruction fault.
vcpu_ap_xstate_host:
    mov  r8, rdi
    mov  eax, [r8 + VAX_HOST_VALUE]
    mov  edx, [r8 + VAX_HOST_VALUE + 4]
    xor  ecx, ecx
    xsetbv
    mov  rdi, [r8 + VAX_HOST]
    xrstor64 [rdi]
    mov  qword [r8 + VAX_SAVED], 0
    ret

align 64
vax_init:
    dw 0x037F
    times 22 db 0
    dd 0x1F80
    times 576 - 28 db 0
