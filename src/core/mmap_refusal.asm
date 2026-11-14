;; MODULE core/mmap_refusal
;; LAYER 1
;; EXPORTS mmap_refusal_selftest
;; IMPORTS boot/serial, boot/paging
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/mmap_refusal.asm — T1-4.8: the final-map validator refuses unsupported layouts (VM, 2026-10-25)
;
; Runs the boot path's own mmap_final_validate (boot/paging.asm), unchanged, over fixed malformed
; descriptor sets in a private 64 KiB buffer and requires each case's exact verdict and admit
; reason: an empty or oversized map (2), an unsupported descriptor size/version or a trailing
; partial descriptor (3), an unaligned, empty, oversized or wrapping span on any row (4), overlapping
; physical records (5) and an overflowing conventional sum (6). Two admitted layouts (firmware order
; unsorted, exact adjacency, strides 48 and 64) bound it from the other side.
;
; The validator reads only its five pending-map inputs (owned buffer, capacity, pending size,
; descriptor size, descriptor version). They are swapped to the private buffer for the run and
; restored with the admit reason and interval count afterwards; the published map (mmap_buffer/
; mmap_size/mmap_desc_size) is never read or written. A held interval claim fails the KAT
; before anything is swapped. The case bytes must come back unchanged (firmware order and
; bytes are preserved). One PASS or FAILED line; the boot continues either way.

MRK_CASE_BYTES   equ 128                  ; 32 B header + 3 rows of 32 B
MRK_ROWS         equ 3
MRK_CHECK_BYTES  equ 768                  ; 3 rows at the widest stride written (256)

; header: dd desc_size, desc_ver, pending_size, row_stride, want_rax, want_reason; dq pad
%macro MRK_CASE 6
    dd %1, %2, %3, %4, %5, %6
    dq 0
%endmacro
; row: dd type, pad; dq phys, virt, pages
%macro MRK_ROW 4
    dd %1, 0
    dq %2, %3, %4
%endmacro
%macro MRK_NONE 0
    MRK_ROW 0, 0, 0, 0
%endmacro

mrk_cases:
    ; 1 admitted: firmware order unsorted, conventional ending exactly where loader data starts
    MRK_CASE 48, 1, 144, 48, 0, 0
    MRK_ROW 2, 0x200000, 0, 16
    MRK_ROW 7, 0x100000, 0, 256
    MRK_ROW 3, 0x300000, 0x300000, 1
    ; 2 admitted at stride 64 (padding between descriptors)
    MRK_CASE 64, 1, 192, 64, 0, 0
    MRK_ROW 7, 0x400000, 0, 4
    MRK_ROW 1, 0x100000, 0, 1
    MRK_ROW 4, 0x101000, 0, 2
    ; 3-4 reason 2: empty map, map larger than the owned buffer
    MRK_CASE 48, 1, 0, 48, 1, 2
    MRK_ROW 2, 0x100000, 0, 1
    MRK_NONE
    MRK_NONE
    MRK_CASE 48, 1, 65536 + 48, 48, 1, 2
    MRK_ROW 2, 0x100000, 0, 1
    MRK_NONE
    MRK_NONE
    ; 5-9 reason 3: stride 32, 264, 44; version 2; trailing partial descriptor
    MRK_CASE 32, 1, 96, 48, 1, 3
    MRK_ROW 2, 0x100000, 0, 1
    MRK_NONE
    MRK_NONE
    MRK_CASE 264, 1, 264, 48, 1, 3
    MRK_ROW 2, 0x100000, 0, 1
    MRK_NONE
    MRK_NONE
    MRK_CASE 44, 1, 88, 48, 1, 3
    MRK_ROW 2, 0x100000, 0, 1
    MRK_NONE
    MRK_NONE
    MRK_CASE 48, 2, 48, 48, 1, 3
    MRK_ROW 2, 0x100000, 0, 1
    MRK_NONE
    MRK_NONE
    MRK_CASE 48, 1, 100, 48, 1, 3
    MRK_ROW 2, 0x100000, 0, 1
    MRK_ROW 2, 0x200000, 0, 1
    MRK_NONE
    ; 10-15 reason 4: unaligned physical, unaligned virtual, zero pages, 2^52 pages,
    ; physical end wrapping 2^64, virtual end wrapping 2^64
    MRK_CASE 48, 1, 48, 48, 1, 4
    MRK_ROW 2, 0x100800, 0, 1
    MRK_NONE
    MRK_NONE
    MRK_CASE 48, 1, 48, 48, 1, 4
    MRK_ROW 2, 0x100000, 0x10, 1
    MRK_NONE
    MRK_NONE
    MRK_CASE 48, 1, 48, 48, 1, 4
    MRK_ROW 2, 0x100000, 0, 0
    MRK_NONE
    MRK_NONE
    MRK_CASE 48, 1, 48, 48, 1, 4
    MRK_ROW 7, 0, 0, 0x10000000000000
    MRK_NONE
    MRK_NONE
    MRK_CASE 48, 1, 48, 48, 1, 4
    MRK_ROW 2, 0xFFFFFFFFFFFFF000, 0, 2
    MRK_NONE
    MRK_NONE
    MRK_CASE 48, 1, 48, 48, 1, 4
    MRK_ROW 2, 0x100000, 0xFFFFFFFFFFFFE000, 3
    MRK_NONE
    MRK_NONE
    ; 16 reason 4 on the last row after two admissible ones (every row is checked)
    MRK_CASE 48, 1, 144, 48, 1, 4
    MRK_ROW 7, 0x100000, 0, 16
    MRK_ROW 2, 0x200000, 0, 16
    MRK_ROW 2, 0x300000, 0, 0
    ; 17 reason 5: loader records overlapping by one page, unsorted
    MRK_CASE 48, 1, 96, 48, 1, 5
    MRK_ROW 2, 0x10F000, 0, 1
    MRK_ROW 1, 0x100000, 0, 16
    MRK_NONE
    ; 18 reason 6: conventional bytes overflow 2^64 before the overlap is reached
    MRK_CASE 48, 1, 96, 48, 1, 6
    MRK_ROW 7, 0, 0, 0xFFFFFFFFFFFFF
    MRK_ROW 7, 0, 0, 0xFFFFFFFFFFFFF
    MRK_NONE
mrk_cases_end:
MRK_CASES equ (mrk_cases_end - mrk_cases) / MRK_CASE_BYTES
MRK_ADMITTED equ 2

; Saved validator inputs and results (restored after the run).
MRK_SAVE_OWNED   equ 0
MRK_SAVE_CAP     equ 8
MRK_SAVE_SIZE    equ 16
MRK_SAVE_DSIZE   equ 24
MRK_SAVE_DVER    equ 32
MRK_SAVE_COUNT   equ 40
MRK_SAVE_REASON  equ 48
MRK_FAIL_RAX     equ 56
MRK_SAVE_BYTES   equ 64

; mmap_refusal_selftest — EAX 0 PASS, else the 1-based failing case (0xFF: claim held).
mmap_refusal_selftest:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, MRK_SAVE_BYTES + 8
    xor  ebx, ebx                         ; failing case, 0 = none
    cmp  qword [rel mmap_interval_busy], 0
    je   .claim_free
    mov  ebx, 0xFF
    mov  qword [rsp + MRK_FAIL_RAX], -1
    mov  dword [rsp + MRK_SAVE_REASON], -1
    jmp  .report
.claim_free:
    mov  rax, [rel mmap_owned_buffer]
    mov  [rsp + MRK_SAVE_OWNED], rax
    mov  rax, [rel mmap_capacity]
    mov  [rsp + MRK_SAVE_CAP], rax
    mov  rax, [rel mmap_pending_size]
    mov  [rsp + MRK_SAVE_SIZE], rax
    mov  rax, [rel mmap_pending_desc_size]
    mov  [rsp + MRK_SAVE_DSIZE], rax
    mov  rax, [rel mmap_pending_desc_ver]
    mov  [rsp + MRK_SAVE_DVER], rax
    mov  rax, [rel mmap_interval_count]
    mov  [rsp + MRK_SAVE_COUNT], rax
    mov  eax, [rel mmap_admit_reason]
    mov  [rsp + MRK_SAVE_REASON], eax
    lea  rax, [rel mrk_buffer]
    mov  [rel mmap_owned_buffer], rax
    mov  qword [rel mmap_capacity], MMAP_BUFFER_BYTES
    lea  r12, [rel mrk_cases]
    xor  r13d, r13d                       ; case index
.case:
    cmp  r13d, MRK_CASES
    jae  .restore
    ; Zero the rows' span, then place each row at the case's stride.
    lea  rdi, [rel mrk_buffer]
    xor  eax, eax
    mov  ecx, MRK_CHECK_BYTES / 8
.zero:
    mov  [rdi], rax
    add  rdi, 8
    dec  ecx
    jnz  .zero
    lea  rdi, [rel mrk_buffer]
    lea  rsi, [r12 + 32]
    mov  r14d, MRK_ROWS
.row:
    mov  eax, [rsi]
    mov  [rdi], eax
    mov  rax, [rsi + 8]
    mov  [rdi + 8], rax
    mov  rax, [rsi + 16]
    mov  [rdi + 16], rax
    mov  rax, [rsi + 24]
    mov  [rdi + 24], rax
    mov  eax, [r12 + 12]                  ; row stride
    add  rdi, rax
    add  rsi, 32
    dec  r14d
    jnz  .row
    call mrk_checksum
    mov  r15, rax
    mov  eax, [r12]
    mov  [rel mmap_pending_desc_size], rax
    mov  eax, [r12 + 4]
    mov  [rel mmap_pending_desc_ver], rax
    mov  eax, [r12 + 8]
    mov  [rel mmap_pending_size], rax
    mov  dword [rel mmap_admit_reason], -1
    call mmap_final_validate
    mov  [rsp + MRK_FAIL_RAX], rax
    lea  ebx, [r13 + 1]
    mov  ecx, [r12 + 16]
    cmp  rax, rcx
    jne  .restore
    mov  eax, [rel mmap_admit_reason]
    cmp  eax, [r12 + 20]
    jne  .restore
    cmp  qword [rel mmap_interval_busy], 0
    jne  .restore                         ; the claim is released on every path
    call mrk_checksum
    cmp  rax, r15
    jne  .restore                         ; the validator never writes the map bytes
    xor  ebx, ebx
    add  r12, MRK_CASE_BYTES
    inc  r13d
    jmp  .case
.restore:
    mov  eax, [rel mmap_admit_reason]
    mov  r14d, eax                        ; failing case's reason, for the line
    mov  rax, [rsp + MRK_SAVE_OWNED]
    mov  [rel mmap_owned_buffer], rax
    mov  rax, [rsp + MRK_SAVE_CAP]
    mov  [rel mmap_capacity], rax
    mov  rax, [rsp + MRK_SAVE_SIZE]
    mov  [rel mmap_pending_size], rax
    mov  rax, [rsp + MRK_SAVE_DSIZE]
    mov  [rel mmap_pending_desc_size], rax
    mov  rax, [rsp + MRK_SAVE_DVER]
    mov  [rel mmap_pending_desc_ver], rax
    mov  rax, [rsp + MRK_SAVE_COUNT]
    mov  [rel mmap_interval_count], rax
    mov  eax, [rsp + MRK_SAVE_REASON]
    mov  [rel mmap_admit_reason], eax
    mov  [rsp + MRK_SAVE_REASON], r14d
.report:
    test ebx, ebx
    jnz  .fail
    lea  rdi, [rel str_mrk_pass_pfx]
    call serial_string
    mov  edi, MRK_CASES
    call serial_hex64
    lea  rdi, [rel str_mrk_refused]
    call serial_string
    mov  edi, MRK_CASES - MRK_ADMITTED
    call serial_hex64
    lea  rdi, [rel str_mrk_pass]
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_mrk_fail_pfx]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_mrk_rax]
    call serial_string
    mov  rdi, [rsp + MRK_FAIL_RAX]
    call serial_hex64
    lea  rdi, [rel str_mrk_reason]
    call serial_string
    mov  edi, [rsp + MRK_SAVE_REASON]
    call serial_hex64
    lea  rdi, [rel str_mrk_fail]
    call serial_string
.done:
    mov  eax, ebx
    add  rsp, MRK_SAVE_BYTES + 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RAX = rotate-xor digest of the rows' span of mrk_buffer. Clobbers RCX, RDX.
mrk_checksum:
    lea  rdx, [rel mrk_buffer]
    xor  eax, eax
    mov  ecx, MRK_CHECK_BYTES / 8
.next:
    rol  rax, 7
    xor  rax, [rdx]
    add  rdx, 8
    dec  ecx
    jnz  .next
    ret

; --- core/mmap_refusal data (read-only strings) ---
str_mrk_pass_pfx: db "[PAOS64] M7 memmap: refusal KAT cases=", 0
str_mrk_refused:  db " refused=", 0
str_mrk_pass:     db " PASS [memmap.refusal.ok]", 13, 10, 0
str_mrk_fail_pfx: db "[PAOS64] M7 memmap: refusal KAT FAILED case=", 0
str_mrk_rax:      db " rax=", 0
str_mrk_reason:   db " reason=", 0
str_mrk_fail:     db " [memmap.refusal.fail]", 13, 10, 0

%include "core/abi/wdata.inc"
; Private validator input: never published, never handed to firmware.
%macro WDATA_core_mmap_refusal 0
alignb 16
mrk_buffer: resb MMAP_BUFFER_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_core_mmap_refusal
