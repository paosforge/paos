;; MODULE sec/cpu_microcode_boot
;; LAYER 2
;; EXPORTS cpu_microcode_boot_bsp, mcb_pack_buf, mcb_pack_len, mcb_state, ucode_pack_slice, cpu_microcode_boot_line, cpu_microcode_boot_tsc, mcb_line
;; IMPORTS sec/cpu_microcode, sec/cpu_security, core/lib/fmt, boot/serial
;; CAPS
;; OWNER saga:security
; RCQ-42 raw compatibility entry; normal boot uses cpu_microcode_boot_bsp_checked.
; Original slice 2b-1b BOOT placement
; (rc-boot 02:49:41): header .normal_profile after boot_ab_early, the TCO
; deadman and fault_warmreset_arm, so a load that wedges the CPU still charges
; this boot's trial and climbs the CMOS ladder; before ST_LIB and any consumer
; of CPUID-derived caps. Safe, Manager and Rescue never reach it.
;
; The pack is mcb_pack_buf/mcb_pack_len: the pre-EBS read (sec/ucode_preload)
; sets them only for bytes whose SHA-256 equals the digest compiled into this
; image; otherwise the length is 0 and the result is MCB_NOPACK with nothing
; selected or written. The vendor verifies its own signature in the CPU; PaOS
; only ever hands it bytes the image signature covers.
;
; One fleet pack serves Intel and AMD (slice 2b-3, envelope frozen with relops
; 2026-10-17 06:0x): a "PAOSUCD1" envelope of unmodified upstream vendor
; streams, one bounded slice per vendor. Only the slice for the BSP's sampled
; vendor reaches the selector. A malformed envelope refuses the whole pack
; (MCB_E_ENVELOPE); no slice for this vendor is MCB_NOSLICE. Either way no MSR
; is read or written.
;
; Result (MCB_RESULT, signed): MC_APPLIED 0, MC_NONE 1 (nothing newer),
; MCB_NOPACK 2, MCB_NOSLICE 3, MCB_E_ENVELOPE -20, else the select or apply
; MC_E_* refusal. MCB_RECORD keeps the
; selector/apply record (REV = selected revision, AFTER = revision read back),
; MCB_SAMPLE the BSP sample taken before the load. Raw TSC at entry and exit
; for the boot budget. One short serial line; nothing persists.

MCB_NOPACK      equ 2
MCB_NOSLICE     equ 3                   ; well-formed pack, no slice for this CPU vendor
MCB_E_ENVELOPE  equ -20                 ; the admitted pack's envelope breaks a rule

; PAOSUCD1 envelope (little endian): 32-byte header, then COUNT 16-byte slice
; entries. Rules: file_len = the pack length (< 1 MiB); version 1; header_len
; 32; count 1..2; reserved fields 0; vendor 1 Intel or 2 AMD, each at most
; once; offsets 16-byte aligned, ascending, after the table, not overlapping;
; length > 0 and the slice inside the pack; every other byte (padding between
; and after slices) is 0.
UCD_MAGIC       equ 'PAOSUCD1'
UCD_VERSION     equ 8                   ; dd 1
UCD_HEADER_LEN  equ 12                  ; dd 32
UCD_COUNT       equ 16                  ; dd 1..2
UCD_FILE_LEN    equ 20                  ; dd
UCD_RESERVED    equ 24                  ; dq 0
UCD_HEADER      equ 32
UCD_E_VENDOR    equ 0                   ; entry: dd 1 Intel / 2 AMD (cpu_security CSS_VENDOR)
UCD_E_OFFSET    equ 4
UCD_E_LENGTH    equ 8
UCD_E_RESERVED  equ 12
UCD_ENTRY       equ 16
UCD_MAX_SLICES  equ 2
UCD_MAX         equ 0x100000

MCB_DONE        equ 0                   ; dd 1 once the BSP call ran
MCB_RESULT      equ 4                   ; dd signed result (above)
MCB_PID         equ 8                   ; dd Intel platform id passed to select
MCB_TSC_START   equ 16                  ; dq raw TSC at entry
MCB_TSC_END     equ 24                  ; dq raw TSC after the line is staged
MCB_RECORD      equ 32                  ; MCS_SIZE (40) select/apply record
MCB_SAMPLE      equ 72                  ; CSS_SIZE (112) BSP sample
MCB_SIZE        equ 184
MCB_LINE_MAX    equ 96

; cpu_microcode_boot_bsp: once, on the BSP, interrupts off. -> RAX = result.
; Keeps RBX, RBP, R12-R15.
cpu_microcode_boot_bsp:
    push rbx
    push r12
    push r13
    lea  rbx, [rel mcb_state]
    call cpu_microcode_boot_tsc
    mov  [rbx + MCB_TSC_START], rax
    lea  rdi, [rbx + MCB_SAMPLE]
    mov  esi, CSS_SIZE
    call cpu_security_sample
    mov  dword [rbx + MCB_RESULT], MCB_NOPACK
    mov  r12, [rel mcb_pack_buf]
    mov  r13, [rel mcb_pack_len]
    test r12, r12
    jz   .report
    test r13, r13
    jz   .report
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, [rbx + MCB_SAMPLE + CSS_VENDOR]
    call ucode_pack_slice               ; this vendor's slice of the PAOSUCD1 pack
    mov  [rbx + MCB_RESULT], eax
    test eax, eax
    jnz  .report                        ; no slice or a malformed envelope: nothing read or written
    mov  r12, rdi
    mov  r13, rsi
    xor  ecx, ecx                       ; platform id: Intel bare metal only
    cmp  dword [rbx + MCB_SAMPLE + CSS_VENDOR], 1
    jne  .select
    cmp  dword [rbx + MCB_SAMPLE + CSS_HV], 0
    jne  .select                        ; select refuses a guest; read no MSR there
    mov  ecx, 0x17                      ; IA32_PLATFORM_ID
    call cpu_security_rdmsr
    mov  ecx, edx
    shr  ecx, 50 - 32
    and  ecx, 7
.select:
    mov  [rbx + MCB_PID], ecx
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbx + MCB_SAMPLE]
    lea  r8, [rbx + MCB_RECORD]
    call cpu_microcode_select
    mov  [rbx + MCB_RESULT], eax
    cmp  eax, MC_SELECTED
    jne  .report                        ; MC_NONE or a refusal: nothing written
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbx + MCB_SAMPLE]
    lea  r8, [rbx + MCB_RECORD]
    call cpu_microcode_apply
    mov  [rbx + MCB_RESULT], eax
.report:
    mov  dword [rbx + MCB_DONE], 1
    call cpu_microcode_boot_line
    call cpu_microcode_boot_tsc
    mov  [rbx + MCB_TSC_END], rax
    lea  rdi, [rel mcb_line]
    call serial_string
    movsxd rax, dword [rbx + MCB_RESULT]
    pop  r13
    pop  r12
    pop  rbx
    ret

; ucode_pack_slice(RDI=pack, RSI=length, EDX=CPU vendor) -> EAX 0 with
; RDI = that vendor's slice and RSI = its length; else EAX MCB_NOSLICE (the
; envelope is well-formed, no slice for this vendor) or MCB_E_ENVELOPE (any
; rule above broken: the whole pack is refused). Pure. Keeps RBX, RBP, R12-R15.
ucode_pack_slice:
    push rbx
    push r12
    mov  r8, rdi                        ; pack
    mov  r9, rsi                        ; length
    mov  r10d, edx                      ; the CPU's vendor
    xor  ebx, ebx                       ; vendors seen (bit 1 Intel, bit 2 AMD)
    xor  r12d, r12d                     ; the CPU vendor's entry, 0 = none
    mov  eax, MCB_E_ENVELOPE
    cmp  r9, UCD_HEADER + UCD_ENTRY
    jb   .out
    cmp  r9, UCD_MAX
    jae  .out
    mov  rcx, UCD_MAGIC
    cmp  [r8], rcx
    jne  .out
    cmp  dword [r8 + UCD_VERSION], 1
    jne  .out
    cmp  dword [r8 + UCD_HEADER_LEN], UCD_HEADER
    jne  .out
    mov  ecx, [r8 + UCD_FILE_LEN]
    cmp  rcx, r9
    jne  .out
    cmp  qword [r8 + UCD_RESERVED], 0
    jne  .out
    mov  r11d, [r8 + UCD_COUNT]
    lea  ecx, [r11 - 1]
    cmp  ecx, UCD_MAX_SLICES - 1
    ja   .out                           ; count 1..2
    lea  rdx, [r8 + UCD_HEADER]         ; the first entry
    mov  ecx, r11d
    shl  ecx, 4
    add  ecx, UCD_HEADER                ; cursor: the first byte after the table
    cmp  rcx, r9
    ja   .out
.entry:
    cmp  dword [rdx + UCD_E_RESERVED], 0
    jne  .out
    mov  esi, [rdx + UCD_E_VENDOR]
    lea  edi, [rsi - 1]
    cmp  edi, 1
    ja   .out                           ; vendor 1 or 2
    bts  ebx, esi
    jc   .out                           ; each vendor once
    mov  edi, [rdx + UCD_E_OFFSET]
    test edi, 15
    jnz  .out
    cmp  rdi, rcx
    jb   .out                           ; ascending, after the table, no overlap
    mov  esi, [rdx + UCD_E_LENGTH]
    test esi, esi
    jz   .out
    add  rsi, rdi                       ; the slice end (64-bit: no wrap)
    cmp  rsi, r9
    ja   .out
.pad:                                   ; [cursor, offset) is zero padding
    cmp  rcx, rdi
    jae  .padded
    cmp  byte [r8 + rcx], 0
    jne  .out
    inc  rcx
    jmp  .pad
.padded:
    mov  rcx, rsi                       ; cursor = the slice end
    cmp  [rdx + UCD_E_VENDOR], r10d
    jne  .next
    mov  r12, rdx
.next:
    add  rdx, UCD_ENTRY
    dec  r11d
    jnz  .entry
.tail:                                  ; nothing but zero after the last slice
    cmp  rcx, r9
    jae  .checked
    cmp  byte [r8 + rcx], 0
    jne  .out
    inc  rcx
    jmp  .tail
.checked:
    mov  eax, MCB_NOSLICE
    test r12, r12
    jz   .out
    mov  edi, [r12 + UCD_E_OFFSET]
    mov  esi, [r12 + UCD_E_LENGTH]
    add  rdi, r8
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; "[PAOS64] microcode fw=<hex|none> result=<signed> new=<hex> after=<hex>"
; into mcb_line (bounded: four fields of at most 11 bytes after a fixed head).
; RBX = mcb_state. Clobbers caller-saved and R12.
cpu_microcode_boot_line:
    lea  r12, [rel mcb_line]
    lea  rdi, [rel str_mcb_head]
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    cmp  dword [rbx + MCB_SAMPLE + CSS_REV_VALID], 0
    jne  .fw
    lea  rdi, [rel str_mcb_none]
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    jmp  .result
.fw:
    mov  edi, [rbx + MCB_SAMPLE + CSS_REV]
    mov  rsi, r12
    xor  edx, edx
    call fmt_hex
    add  r12, rax
.result:
    lea  rdi, [rel str_mcb_result]
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    movsxd rdi, dword [rbx + MCB_RESULT]
    test rdi, rdi
    jns  .unsigned
    mov  byte [r12], '-'
    inc  r12
    neg  rdi
.unsigned:
    mov  rsi, r12
    call fmt_dec
    add  r12, rax
    lea  rdi, [rel str_mcb_new]
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    mov  edi, [rbx + MCB_RECORD + MCS_REV]
    mov  rsi, r12
    xor  edx, edx
    call fmt_hex
    add  r12, rax
    lea  rdi, [rel str_mcb_after]
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    mov  edi, [rbx + MCB_RECORD + MCS_AFTER]
    mov  rsi, r12
    xor  edx, edx
    call fmt_hex
    add  r12, rax
    mov  word [r12], 0x0a0d
    mov  byte [r12 + 2], 0
    ret

; Hardware adapter: tests replace only this body.
cpu_microcode_boot_tsc:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    ret

str_mcb_head:   db "[PAOS64] microcode fw=", 0
str_mcb_none:   db "none", 0
str_mcb_result: db " result=", 0
str_mcb_new:    db " new=", 0
str_mcb_after:  db " after=", 0

%macro WDATA_cpu_microcode_boot 0
alignb 16
mcb_pack_buf:   resq 1                  ; admitted pack (2b-2), 0 = none
mcb_pack_len:   resq 1
mcb_state:      resb MCB_SIZE
mcb_line:       resb MCB_LINE_MAX
%endmacro
WDATA_BSS_DEFER WDATA_cpu_microcode_boot
