;; MODULE hv/slat_mmio
;; LAYER 5
;; EXPORTS hv_slat_map_mmio
;; IMPORTS hv/hv_ops, hv/vcpu_ap_run, hv/vcpu_bsp
;; CAPS
;; OWNER saga:hv
; RCQ-50 S2: map one assigned BAR range of any size into the guest SLAT.
;
; The legacy VT-d path maps at most 16 MiB of a BAR in 4 KiB pages
; (VTD_BAR_MAP_MAX_BYTES; 16 table pages). A GPU's register BAR (16 MiB) and
; its VRAM aperture (tens of GiB) need large leaves: each step here takes the
; largest leaf that the GPA, the HPA and the remaining length all allow, 1 GiB
; (only when the caller says the backend supports it), 2 MiB, else 4 KiB.
; Leaves are the backend's MMIO_4K bits (EPT: R|W, UC, !X; NPT: UC, NX) plus
; PS for a large leaf. Tables come from the caller's bounded pool only.
;
; Fail closed: a refusal returns before or at the first slot it cannot use and
; never overwrites a present entry; an identical leaf is accepted (re-map). A
; slot holding a table where a large leaf would go is descended with smaller
; leaves, so a BAR may share a PD with the device register pages. A refused
; call can leave the leaves it wrote before the refusal: the caller refuses its
; START, and every START rebuilds the SLAT from cleared control pages.
;
; Pool descriptor (caller memory, HSM_BYTES):
HSM_BASE        equ 0           ; u64 first table page (4 KiB aligned, identity HVA == HPA)
HSM_PAGES       equ 8           ; u32 pages in the pool
HSM_USED        equ 12          ; u32 pages taken so far (in/out)
HSM_FLAGS       equ 16          ; u32 HSM_F_*
HSM_LEAVES_4K   equ 20          ; u32 out: leaves written by this call, by size
HSM_LEAVES_2M   equ 24
HSM_LEAVES_1G   equ 28
HSM_BYTES       equ 32
HSM_F_1G        equ 1           ; 1 GiB leaves (EPT cap bit 17 / NPT CPUID 1 GiB pages)

HV_SLAT_MMIO_OK       equ 0
HV_SLAT_MMIO_INVALID  equ 1     ; zero/unaligned length or address, wrap, GPA beyond 4-level, HPA beyond 2^52, > MAX
HV_SLAT_MMIO_POOL     equ 2     ; the caller's table pool is exhausted
HV_SLAT_MMIO_CONFLICT equ 3     ; a present entry differs (RAM, another BAR, a leaf where a table goes)
HV_SLAT_MMIO_MAX      equ 0x1000000000      ; 64 GiB per call bounds the walk
HV_SLAT_MMIO_GPA_END  equ 0x1000000000000   ; 4-level SLAT: 256 TiB
HV_SLAT_MMIO_HPA_END  equ 0x10000000000000  ; architectural 52-bit ceiling, NOT the CPU's MAXPHYADDR: a caller
                                            ; bounds a BAR HPA by CPUID 0x80000008 EAX[7:0] itself (RCQ-50 N1)
HV_SLAT_MMIO_ADDR     equ 0x000FFFFFFFFFF000

; hv_slat_map_mmio(RDI=SLAT root (PML4), RSI=GPA, RDX=HPA, RCX=bytes, R8=pool
; descriptor) -> EAX=HV_SLAT_MMIO_*. Clears the descriptor's leaf counters on
; entry and counts what it writes. Preserves RBX, RBP, R12-R15.
hv_slat_map_mmio:
    ; S7: table lifetime is frozen until both vCPUs are retired.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24                            ; [rsp] table bits, [rsp+8] 4 KiB leaf bits
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    mov  r15, r8
    xor  eax, eax
    mov  [r15 + HSM_LEAVES_4K], eax
    mov  [r15 + HSM_LEAVES_2M], eax
    mov  [r15 + HSM_LEAVES_1G], eax
    mov  eax, HV_SLAT_MMIO_INVALID
    test rbx, rbx
    jz   .out
    test r14, r14
    jz   .out
    mov  rcx, r12
    or   rcx, r13
    or   rcx, r14
    or   rcx, rbx
    test ecx, 0xFFF
    jnz  .out
    mov  rcx, HV_SLAT_MMIO_MAX
    cmp  r14, rcx
    ja   .out
    mov  rcx, r12
    add  rcx, r14
    jc   .out
    mov  rdx, HV_SLAT_MMIO_GPA_END
    cmp  rcx, rdx
    ja   .out
    mov  rcx, r13
    add  rcx, r14
    jc   .out
    mov  rdx, HV_SLAT_MMIO_HPA_END
    cmp  rcx, rdx
    ja   .out
    mov  edi, HV_SLAT_TABLE
    call hv_slat_bits
    mov  [rsp], rax
    mov  edi, HV_SLAT_MMIO_4K
    call hv_slat_bits
    mov  [rsp + 8], rax
    mov  r9, HV_SLAT_MMIO_ADDR
.chunk:
    mov  rax, r12
    or   rax, r13
    mov  ebp, 12
    test eax, 0x1FFFFF
    jnz  .walk
    cmp  r14, 0x200000
    jb   .walk
    mov  ebp, 21
    test dword [r15 + HSM_FLAGS], HSM_F_1G
    jz   .walk
    test eax, 0x3FFFFFFF
    jnz  .walk
    cmp  r14, 0x40000000
    jb   .walk
    mov  ebp, 30
.walk:
    mov  rsi, rbx                           ; current table
    mov  ecx, 39                            ; its index shift
.level:
    mov  rax, r12
    shr  rax, cl
    and  eax, 0x1FF
    lea  rdi, [rsi + rax*8]                 ; the slot
    cmp  ecx, ebp
    je   .leaf
    mov  rax, [rdi]
    test al, 7
    jnz  .have_table
    test rax, rax
    jnz  .conflict                          ; not present, but not empty either
    call .take
    test rax, rax
    jz   .pool
    mov  rdx, rax
    or   rdx, [rsp]
    mov  [rdi], rdx
    mov  rsi, rax
    jmp  .down
.have_table:
    test al, 0x80
    jnz  .conflict                          ; a leaf where this range needs a table
    mov  rsi, rax
    and  rsi, r9
.down:
    sub  ecx, 9
    jmp  .level
.leaf:
    mov  rdx, r13
    and  rdx, r9
    or   rdx, [rsp + 8]
    cmp  ecx, 12
    je   .leaf_bits
    or   rdx, 0x80                          ; PS: a 2 MiB or 1 GiB leaf
.leaf_bits:
    mov  rax, [rdi]
    test rax, rax
    jz   .write
    cmp  rax, rdx
    je   .advance                           ; the identical leaf is already there
    test al, 7
    jz   .conflict
    test al, 0x80
    jnz  .conflict
    cmp  ecx, 12
    je   .conflict
    sub  ebp, 9                             ; a table lives here: smaller leaves under it
    jmp  .walk
.write:
    mov  [rdi], rdx
    lea  rax, [r15 + HSM_LEAVES_4K]
    cmp  ecx, 12
    je   .count
    lea  rax, [r15 + HSM_LEAVES_2M]
    cmp  ecx, 21
    je   .count
    lea  rax, [r15 + HSM_LEAVES_1G]
.count:
    inc  dword [rax]
.advance:
    mov  eax, 1
    shl  rax, cl
    add  r12, rax
    add  r13, rax
    sub  r14, rax
    jnz  .chunk
    mfence
    mov  eax, HV_SLAT_MMIO_OK
    jmp  .out
.pool:
    mov  eax, HV_SLAT_MMIO_POOL
    jmp  .out
.conflict:
    mov  eax, HV_SLAT_MMIO_CONFLICT
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; .take -> RAX = one zeroed pool page, or 0 when the pool is exhausted.
; Clobbers RAX, RDX only (the walk keeps RCX, RSI, RDI, R9 live).
.take:
    mov  eax, [r15 + HSM_USED]
    cmp  eax, [r15 + HSM_PAGES]
    jae  .take_none
    inc  dword [r15 + HSM_USED]
    shl  rax, 12
    add  rax, [r15 + HSM_BASE]
    xor  edx, edx
.take_zero:
    mov  qword [rax + rdx*8], 0
    inc  edx
    cmp  edx, 512
    jb   .take_zero
    ret
.take_none:
    xor  eax, eax
    ret
