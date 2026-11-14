;; MODULE hv/vcpu_cpuid
;; LAYER 5
;; EXPORTS vcpuid_same, vcpuid_capture, vcpuid_build, vcpuid_query, vcb_cpuid_table, vcpuid_capture_at, vcpuid_build_at
;; IMPORTS hv/vcpu_ap_run
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Intel SDM vol2 CPUID table3-8.
; Fixed-key raw samples belong to each CPU. START intersects both samples
; before publication and freezes the result with its manifest. The query
; executes no CPUID/XGETBV, reads no mutable host feature mask and writes no
; table. START/AP sampling handshake and READY publication remain separate.
%include "hv/vcpu_cpuid.inc"

; RDI=owned/mapped VCP_BYTES sample, READY0. Capture THIS CPU, no allocator.
; Input keys above this CPU's actual basic/extended maximum return zero.
; Destination must be private to the executing CPU, never shared hv scratch.
; EAX1/0; all callee-save preserved. No sample writes while READY is nonzero.
vcpuid_capture:
    cmp  qword [rel vca_ready], 0
    jne  .refuse
    jmp vcpuid_capture_at
.refuse:
    xor eax,eax
    ret

; Explicit independent native object. Caller owns/serializes its private raw
; buffer and may not modify another VM's published table. No S7 state access.
vcpuid_capture_at:
    test rdi, rdi
    jz   .refuse
    test rdi, 15
    jnz  .refuse
    mov  rax, rdi
    add  rax, VCP_BYTES
    jc   .refuse
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    xor  eax, eax
    xor  ecx, ecx
    cpuid
    mov  r14d, eax
    mov  eax, 0x80000000
    xor  ecx, ecx
    cpuid
    mov  r15d, eax
    xor  r13d, r13d
.next:
    lea  r8, [rel vcp_keys]
    mov  eax, [r8 + r13*8]
    mov  ecx, [r8 + r13*8 + 4]
    test eax, eax
    js   .extended
    cmp  eax, r14d
    jbe  .native
    jmp  .zero
.extended:
    cmp  eax, r15d
    jbe  .native
.zero:
    xor  eax, eax
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
    jmp  .store
.native:
    cpuid
.store:
    mov  [r12], eax
    mov  [r12 + 4], ebx
    mov  [r12 + 8], ecx
    mov  [r12 + 12], edx
    add  r12, 16
    inc  r13d
    cmp  r13d, VCP_COUNT
    jb   .next
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.refuse:
    xor  eax, eax
    ret

; RDI=frozen sample. Compare this CPU without rewriting READY inputs.
vcpuid_same:
    test rdi, rdi
    jz   .refuse
    test rdi, 15
    jnz  .refuse
    mov  rax, rdi
    add  rax, VCP_BYTES
    jc   .refuse
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    xor  eax, eax
    xor  ecx, ecx
    cpuid
    mov  r14d, eax
    mov  eax, 0x80000000
    xor  ecx, ecx
    cpuid
    mov  r15d, eax
    xor  r13d, r13d
.next:
    lea  r8, [rel vcp_keys]
    mov  eax, [r8 + r13*8]
    mov  ecx, [r8 + r13*8 + 4]
    test eax, eax
    js   .extended
    cmp  eax, r14d
    jbe  .native
    jmp  .zero
.extended:
    cmp  eax, r15d
    jbe  .native
.zero:
    xor  eax, eax
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
    jmp  .store
.native:
    cpuid
.store:
    cmp  [r12], eax
    jne  .changed
    cmp  [r12 + 4], ebx
    jne  .changed
    cmp  [r12 + 8], ecx
    jne  .changed
    cmp  [r12 + 12], edx
    jne  .changed
    add  r12, 16
    inc  r13d
    cmp  r13d, VCP_COUNT
    jb   .next
    mov  eax, 1
    jmp  .out
.changed:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.refuse:
    xor  eax, eax
    ret

; RDI=owned output, RSI=BSP sample, RDX=AP sample, RCX=scheduler allowed mask.
; Three aligned mapped nonoverlapping buffers; input samples may alias each
; other. No output bytes change on refusal. RAX=final allowed XCR0 mask or0.
; Require common Intel XSAVE, CLFLUSH line size and physical address format.
; For every retained vector component, ordered nonoverlapping size/offset agree;
; incompatible CPU layouts refuse rather than reinterpreting an XSAVE image.
vcpuid_build:
    cmp  qword [rel vca_ready], 0
    jne  .refuse
    jmp vcpuid_build_at
.refuse:
    xor eax,eax
    ret

; Same checked explicit-buffer model builder, independent lifecycle. The
; original wrapper still refuses writes to the maintained live S7 object.
vcpuid_build_at:
    test rdi, rdi
    jz   .refuse
    test rsi, rsi
    jz   .refuse
    test rdx, rdx
    jz   .refuse
    mov  rax, rdi
    or   rax, rsi
    or   rax, rdx
    test rax, 15
    jnz  .refuse
    mov  r8, rdi
    add  r8, VCP_BYTES
    jc   .refuse
    mov  r9, rsi
    add  r9, VCP_BYTES
    jc   .refuse
    cmp  rdi, r9
    jae  .ap_range
    cmp  rsi, r8
    jb   .refuse
.ap_range:
    mov  r9, rdx
    add  r9, VCP_BYTES
    jc   .refuse
    cmp  rdi, r9
    jae  .ranges_ok
    cmp  rdx, r8
    jb   .refuse
.ranges_ok:
    cmp  dword [rsi], 0xD
    jb   .refuse
    cmp  dword [rdx], 0xD
    jb   .refuse
    ; Both samples must have the same complete supported native vendor.
    mov rax, [rsi + 4]
    cmp rax, [rdx + 4]
    jne .refuse
    mov eax, [rsi + 12]
    cmp eax, [rdx + 12]
    jne .refuse
    cmp dword [rsi + 4], 'Auth'
    je .amd_vendor
    cmp dword [rsi + 4], 'Genu'
    jne .refuse
    cmp dword [rsi + 8], 'ntel'
    jne .refuse
    cmp dword [rsi + 12], 'ineI'
    jne .refuse
    jmp .vendor_ok
.amd_vendor:
    cmp dword [rsi + 8], 'cAMD'
    jne .refuse
    cmp dword [rsi + 12], 'enti'
    jne .refuse
.vendor_ok:
    cmp  dword [rsi + VCP_EXT], 0x80000008
    jb   .refuse
    cmp  dword [rdx + VCP_EXT], 0x80000008
    jb   .refuse
    mov  eax, [rsi + 16 + 8]
    and  eax, [rdx + 16 + 8]
    and  eax, (1 << 26) | (1 << 27)
    cmp  eax, (1 << 26) | (1 << 27)
    jne  .refuse
    mov  eax, [rsi + 16 + 4]
    xor  eax, [rdx + 16 + 4]
    test eax, 0xFF00
    jnz  .refuse
    mov  r8d, [rsi + VCP_D]
    and  r8d, [rdx + VCP_D]
    and  r8, rcx
    and  r8d, VCP_VECTOR
    mov  eax, r8d
    and  eax, 3
    cmp  eax, 3
    jne  .refuse
    test r8d, 4
    jz   .drop512
    mov  eax, r8d
    and  eax, 0xE0
    cmp  eax, 0xE0
    je   .layout
.drop512:
    and  r8d, ~0xE0
.layout:
    mov  r9d, 2
    mov  r10d, 576
.component:
    bt   r8, r9
    jnc  .advance
    mov  r11, r9
    shl  r11, 4
    mov  eax, [rsi + r11 + VCP_D]
    test eax, eax
    jz   .refuse
    cmp  eax, [rdx + r11 + VCP_D]
    jne  .refuse
    mov  ecx, [rsi + r11 + VCP_D + 4]
    cmp  ecx, r10d
    jb   .refuse
    cmp  ecx, [rdx + r11 + VCP_D + 4]
    jne  .refuse
    add  eax, ecx
    jc   .refuse
    cmp  eax, 65536
    ja   .refuse
    cmp  eax, r10d
    cmova r10d, eax
    mov  ecx, [rsi + r11 + VCP_D + 8]
    or   ecx, [rdx + r11 + VCP_D + 8]
    test ecx, 1
    jnz  .refuse
    mov  ecx, [rsi + r11 + VCP_D + 12]
    or   ecx, [rdx + r11 + VCP_D + 12]
    jnz  .refuse
.advance:
    inc  r9d
    cmp  r9d, 8
    jb   .component
    ; Physical width may differ: advertise the common minimum, linear48.
    movzx eax, byte [rsi + 76*16]
    movzx ecx, byte [rdx + 76*16]
    cmp  eax, 36
    jb   .refuse
    cmp  eax, 52
    ja   .refuse
    cmp  ecx, 36
    jb   .refuse
    cmp  ecx, 52
    ja   .refuse
    cmp  eax, ecx
    cmova eax, ecx
    cmp  byte [rsi + 76*16 + 1], 48
    jb   .refuse
    cmp  byte [rdx + 76*16 + 1], 48
    jb   .refuse
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, r8
    mov  ebx, eax
    ; All validation precedes the first output write.
    mov  ecx, VCP_BYTES / 8
    xor  eax, eax
    cld
    rep  stosq
    mov  dword [r12], 0x1F
    mov rax, [r13 + 4]
    mov [r12 + 4], rax
    mov eax, [r13 + 12]
    mov [r12 + 12], eax
    mov  eax, [r13 + 16]
    mov  [r12 + 16], eax
    mov  eax, [r13 + 16 + 4]
    and  eax, 0xFF00
    or   eax, 2 << 16
    mov  [r12 + 16 + 4], eax
    mov  eax, [r13 + 16 + 8]
    and  eax, [r14 + 16 + 8]
    ; No MONITOR/VMX/SMX/EIST/TM2/DCA/xTPR/PDCM or MSR perf/debug facilities.
    and  eax, ~((1<<2)|(1<<3)|(1<<4)|(1<<5)|(1<<6)|(1<<7)|(1<<8)|(1<<11)|(1<<14)|(1<<15)|(1<<18))
    or   eax, (1<<21)|(1<<24)|(1<<31)
    test r15d, 4
    jnz  .leaf1_vector
    and  eax, ~((1<<12)|(1<<28)|(1<<29))
.leaf1_vector:
    mov  [r12 + 16 + 8], eax
    mov  eax, [r13 + 16 + 12]
    and  eax, [r14 + 16 + 12]
    and  eax, ~((1<<7)|(1<<12)|(1<<14)|(1<<21)|(1<<22)|(1<<29)|(1<<31))
    or   eax, (1<<9)|(1<<28)
    mov  [r12 + 16 + 12], eax
    mov  eax, [r13 + 32 + 4]
    and  eax, [r14 + 32 + 4]
    and  eax, ~((1<<1)|(1<<2)|(1<<4)|(1<<11)|(1<<12)|(1<<14)|(1<<15)|(1<<25))
    test r15d, 4
    jnz  .leaf7_512
    and  eax, ~(1<<5)
.leaf7_512:
    mov  ecx, r15d
    and  ecx, 0xE0
    cmp  ecx, 0xE0
    je   .leaf7_b
    and  eax, ~((1<<16)|(1<<17)|(1<<21)|(1<<26)|(1<<27)|(1<<28)|(1<<30)|(1<<31))
.leaf7_b:
    mov  [r12 + 32 + 4], eax
    mov  eax, [r13 + 32 + 8]
    and  eax, [r14 + 32 + 8]
    and  eax, ~((1<<3)|(1<<4)|(1<<5)|(1<<7)|(1<<13)|(1<<16)|(0x1F<<17)|(1<<23)|(1<<24)|(1<<29)|(1<<30)|(1<<31))
    test r15d, 4
    jnz  .leaf7_c512
    and  eax, ~((1<<9)|(1<<10))
.leaf7_c512:
    cmp  ecx, 0xE0
    je   .leaf7_c
    and  eax, ~((1<<1)|(1<<6)|(1<<11)|(1<<12)|(1<<14))
.leaf7_c:
    mov  [r12 + 32 + 8], eax
    mov  eax, [r13 + 32 + 12]
    and  eax, [r14 + 32 + 12]
    and  eax, ~((1<<5)|(1<<9)|(1<<11)|(1<<13)|(1<<15)|(1<<16)|(1<<18)|(1<<19)|(1<<20)|(1<<22)|(1<<24)|(1<<25)|(0x3F<<26))
    cmp  ecx, 0xE0
    je   .leaf7_d
    and  eax, ~((1<<2)|(1<<3)|(1<<8)|(1<<23))
.leaf7_d:
    mov  [r12 + 32 + 12], eax
    mov  [r12 + VCP_D], r15d
    mov  [r12 + VCP_D + 4], r10d
    mov  [r12 + VCP_D + 8], r10d
    mov  eax, [r13 + VCP_D + 16]
    and  eax, [r14 + VCP_D + 16]
    and  eax, 1                            ; XSAVEOPT only; no compact/XSS/XFD
    mov  [r12 + VCP_D + 16], eax
    mov  ecx, 2
.copy_component:
    bt   r15, rcx
    jnc  .copy_next
    mov  rax, rcx
    shl  rax, 4
    mov  rdx, [r13 + rax + VCP_D]
    mov  [r12 + rax + VCP_D], rdx           ; size and standard offset only
.copy_next:
    inc  ecx
    cmp  ecx, 8
    jb   .copy_component
    ; Timing leaves are optional; publish only exactly equal native tuples.
    mov  ecx, 67
.timing:
    mov  rax, rcx
    shl  rax, 4
    mov  rdx, [r13 + rax]
    cmp  rdx, [r14 + rax]
    jne  .timing_next
    mov  rsi, [r13 + rax + 8]
    cmp  rsi, [r14 + rax + 8]
    jne  .timing_next
    mov  [r12 + rax], rdx
    mov  [r12 + rax + 8], rsi
.timing_next:
    inc  ecx
    cmp  ecx, 69
    jb   .timing
    mov  dword [r12 + VCP_EXT], 0x80000008
    mov  eax, [r13 + 70*16 + 8]
    and  eax, [r14 + 70*16 + 8]
    and  eax, (1<<0)|(1<<5)|(1<<8)           ; LAHF/LZCNT/PREFETCHW
    mov  [r12 + 70*16 + 8], eax
    mov  eax, [r13 + 70*16 + 12]
    and  eax, [r14 + 70*16 + 12]
    and  eax, (1<<11)|(1<<20)|(1<<26)|(1<<27)|(1<<29)
    mov  [r12 + 70*16 + 12], eax
    mov  eax, [r13 + 75*16 + 12]
    and  eax, [r14 + 75*16 + 12]
    and  eax, 1<<8                         ; invariant TSC only
    mov  [r12 + 75*16 + 12], eax
    or   ebx, 48<<8
    mov  [r12 + 76*16], ebx
    ; Private AMD execution implements only the small CR4 model. Hide the
    ; corresponding native extensions rather than faulting Linux after it
    ; enables an advertised PCID/SMEP/SMAP/UMIP facility. Intel stays exact.
    cmp dword [r12 + 4], 'Auth'
    jne .amd_feature_done
    and dword [r12 + 16 + 8], ~(1<<17) ; PCID
    and dword [r12 + 32 + 4], ~((1<<7)|(1<<10)|(1<<20)) ; SMEP/INVPCID/SMAP
    and dword [r12 + 32 + 8], ~(1<<2) ; UMIP
.amd_feature_done:
    ; Intel reserves 80000008 ECX. Topology lives only in leaves B/1F.
    cmp dword [r12 + 4], 'Auth'
    jne .topology_done
    mov dword [r12 + 76*16 + 8], 0x1001 ; AMD NC=1, core-id width1
.topology_done:
    mov  rax, r15
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.refuse:
    xor  eax, eax
    ret

; EDI leaf, ESI subleaf, RDX selected guest XCR0, RCX actual selected CR4,
; R8D virtual ID0/1, R9 frozen table. Returns EAX/EBX/ECX/EDX (CPUID ABI).
; Caller owns table/generation validation; no table writes or native query.
vcpuid_query:
    push rbp
    push r12
    push r13
    push r14
    mov  r12, rdx
    mov  r13, rcx
    mov  r14d, r8d
    mov  rbp, r9
    cmp  edi, 0xB
    je   .topology
    cmp  edi, 0x1F
    je   .topology
    lea  r8, [rel vcp_keys]
    xor  ecx, ecx
.find:
    cmp  edi, [r8 + rcx*8]
    jne  .next
    cmp  esi, [r8 + rcx*8 + 4]
    je   .found
.next:
    inc  ecx
    cmp  ecx, VCP_COUNT
    jb   .find
.zero:
    xor  eax, eax
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
    jmp  .out
.found:
    shl  ecx, 4
    mov  eax, [rbp + rcx]
    mov  ebx, [rbp + rcx + 4]
    mov  edx, [rbp + rcx + 12]
    mov  ecx, [rbp + rcx + 8]
    cmp  edi, 1
    je   .leaf1
    cmp  edi, 0xD
    jne  .out
    test esi, esi
    jnz  .out
    and  r12d, eax
    xor  ebx, ebx
    test r12d, r12d
    jz   .out
    mov  ebx, 576
    mov  r8d, 2
.size:
    bt   r12, r8
    jnc  .size_next
    mov  r9, r8
    shl  r9, 4
    mov  r10d, [rbp + r9 + VCP_D]
    add  r10d, [rbp + r9 + VCP_D + 4]
    cmp  ebx, r10d
    cmovb ebx, r10d
.size_next:
    inc  r8d
    cmp  r8d, 8
    jb   .size
    jmp  .out
.leaf1:
    and  ebx, 0xFFFFFF
    mov  r8d, r14d
    shl  r8d, 24
    or   ebx, r8d
    and  ecx, ~(1<<27)
    test r13d, 1<<18
    jz   .out
    or   ecx, 1<<27
    jmp  .out
.topology:
    xor  eax, eax
    xor  ebx, ebx
    mov  ecx, esi
    and  ecx, 0xFF
    mov  edx, r14d
    cmp  esi, 0
    jne  .core
    mov  ebx, 1
    or   ecx, 1<<8
    jmp  .out
.core:
    cmp  esi, 1
    jne  .out
    mov  eax, 1
    mov  ebx, 2
    or   ecx, 2<<8
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

align 8
vcp_keys:
    dd 0,0, 1,0, 7,0
%assign vcp_i 0
%rep 64
    dd 0xD,vcp_i
%assign vcp_i vcp_i+1
%endrep
    dd 0x15,0, 0x16,0, 0x80000000,0, 0x80000001,0
    dd 0x80000002,0, 0x80000003,0, 0x80000004,0
    dd 0x80000006,0, 0x80000007,0, 0x80000008,0
%macro WDATA_hv_vcpu_cpuid 0
alignb 16
vcb_cpuid_table: resb VCP_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_hv_vcpu_cpuid
