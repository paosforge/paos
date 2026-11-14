;; MODULE bus/acpi_hp_s5
;; LAYER 2
;; EXPORTS acpi_hp_s5_prepare
;; IMPORTS bus/acpi, bus/acpi_table_spans, core/lib/sha256
;; CAPS io
;; OWNER saga:power
;; CONTEXT: bsp_only
; HP 705 G5 / 8617 fixed _PTS(5) transaction, desktop-root 2026-10-17 12:08.
; No AML decoding, namespace or execution. The complete retained eleven-table
; multiset must match SHA-256 pins below, including the SSDT containing APTS.
; Derivation: PTS_TABLES.json and resource HP_FADT_FIELD_ADDENDUM.json; ordered
; actual ACPICA accesses: target hp-pts-host-io-trace-20261017/RESULT.json.
; Firmware spans/map remain immutable/owned throughout this terminal BSP path.
; Caller: validated DSDT RDI, decoded PM1a event port ESI, control port EDX.
; IF must be clear, storage quiesced and existing owner authorization retained.
; EAX=0 unrelated platform (no accesses),1 complete fixed sequence,-1 refused.
; Revalidate all spans, PM ports, FACS and memory BEFORE any preparation write.
; Honor HPCF's GlobalLock: busy acquisition refuses without changing its word.
; FACS lock protocol: ACPI6.6 5.2.10.1,
; https://uefi.org/specs/ACPI/6.6/05_ACPI_Software_Programming_Model.html#global-lock
; All sequence accesses are byte-sized, with the two PEWS reads kept distinct.
; This is preparation, not evidence of physical S5. No rollback is promised
; after the first write. Normal return has completed all preparation accesses.
%include "bus/acpi_table_spans.inc"

HP_S5_LOCAL equ 488             ; sources296 + SHA ctx112 + digest32 + locals48
HP_S5_CTX equ 296
HP_S5_DIGEST equ 408
HP_S5_EVENT equ 440
HP_S5_CONTROL equ 444
HP_S5_SEEN equ 456
HP_S5_DSDT equ 464

acpi_hp_s5_prepare:
    ; Caller has already validated this entire DSDT. Unrelated firmware keeps
    ; the existing generic S5 path, without collecting its AML or touching I/O.
    cmp dword [rdi+10], 'HPQO'
    jne .unrelated
    cmp word [rdi+14], 'EM'
    jne .unrelated
    cmp dword [rdi+16], '8617'
    jne .unrelated
    cmp dword [rdi+20], '    '
    jne .unrelated
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, HP_S5_LOCAL
    mov [rsp+HP_S5_DSDT], rdi
    mov [rsp+HP_S5_EVENT], esi
    mov [rsp+HP_S5_CONTROL], edx
    mov qword [rsp+HP_S5_SEEN], 0
    mov rdi, rsp
    call acpi_table_spans_collect
    cmp eax, AF_VALID
    jne .refuse
    cmp ecx, 11
    jne .refuse
    mov rax, [rsp+acpi_table_spans.spans]
    cmp rax, [rsp+HP_S5_DSDT]
    jne .refuse
    xor r12d, r12d
.hash_table:
    mov r13, r12
    shl r13, 4
    mov r14, [rsp+r13+acpi_table_spans.spans]
    mov r15, [rsp+r13+acpi_table_spans.spans+8]
    sub r15, r14
    lea rdi, [rsp+HP_S5_CTX]
    call sha256_stream_init
    lea rdi, [rsp+HP_S5_CTX]
    mov rsi, r14
    mov rdx, r15
    call sha256_stream_update
    test eax, eax
    jnz .refuse
    lea rdi, [rsp+HP_S5_CTX]
    lea rsi, [rsp+HP_S5_DIGEST]
    call sha256_stream_final
    test eax, eax
    jnz .refuse
    xor ebp, ebp
    lea rbx, [rel hp_s5_pins]
.find_pin:
    cmp r15d, [rbx]
    jne .next_pin
    lea rsi, [rsp+HP_S5_DIGEST]
    lea rdi, [rbx+4]
    mov ecx, 32
    repe cmpsb
    jne .next_pin
    bts qword [rsp+HP_S5_SEEN], rbp
    jc .refuse                     ; duplicates never replace a missing table
    test r12d, r12d
    jnz .matched
    test ebp, ebp                  ; the DSDT pin must be source index0
    jnz .refuse
.matched:
    inc r12d
    cmp r12d, 11
    jb .hash_table
    cmp qword [rsp+HP_S5_SEEN], 0x7ff
    jne .refuse
    jmp .ports
.next_pin:
    inc ebp
    add rbx, 36
    cmp ebp, 11
    jb .find_pin
    jmp .refuse
.ports:
    ; This unique FADT was re-admitted by the collector. Require the complete
    ; extended fields; legacy and extended nonzero addresses must agree with
    ; the existing S5 decoders used by this same call. No saved 0x400 is used.
    mov rbx, [rsp+acpi_table_spans.fadt_start]
    mov rax, [rsp+acpi_table_spans.fadt_end]
    sub rax, rbx
    cmp eax, 196
    jb .refuse
    cmp byte [rbx+88], 4
    jne .refuse
    cmp byte [rbx+89], 2
    jne .refuse
    mov ebp, [rsp+HP_S5_EVENT]
    cmp ebp, 0x100
    jb .refuse
    cmp ebp, 0xfffc
    ja .refuse
    test ebp, 3
    jnz .refuse
    cmp ebp, 0x24c                   ; no overlap with the pinned debug ports
    je .refuse
    mov eax, [rbx+56]
    test eax, eax
    jz .event_gas
    cmp eax, ebp
    jne .refuse
.event_gas:
    mov rax, [rbx+152]
    test rax, rax
    jz .event_legacy
    cmp rax, rbp
    jne .refuse
    cmp word [rbx+148], 0x2001       ; SystemIO,32 bits
    jne .refuse
    cmp byte [rbx+150], 0
    jne .refuse
    mov al, [rbx+151]
    test al, al
    jz .control
    cmp al, 2
    je .control
    cmp al, 3
    jne .refuse
    jmp .control
.event_legacy:
    cmp [rbx+56], ebp
    jne .refuse
.control:
    mov r13d, [rsp+HP_S5_CONTROL]
    cmp r13d, 0x100
    jb .refuse
    cmp r13d, 0xfffe
    ja .refuse
    test r13d, 1
    jnz .refuse
    cmp r13d, 0x24e
    je .refuse
    mov eax, r13d
    sub eax, ebp
    add eax, 1
    cmp eax, 4
    jbe .refuse
    mov eax, [rbx+64]
    test eax, eax
    jz .control_gas
    cmp eax, r13d
    jne .refuse
.control_gas:
    mov rax, [rbx+176]
    test rax, rax
    jz .control_legacy
    cmp rax, r13
    jne .refuse
    cmp word [rbx+172], 0x1001
    jne .refuse
    cmp byte [rbx+174], 0
    jne .refuse
    mov al, [rbx+175]
    test al, al
    jz .facs
    cmp al, 2
    jne .refuse
    jmp .facs
.control_legacy:
    cmp [rbx+64], r13d
    jne .refuse
.facs:
    mov r12, [rbx+132]              ; FADT X_FIRMWARE_CTRL, then legacy FACS
    test r12, r12
    jnz .facs_header
    mov r12d, [rbx+36]
.facs_header:
    test r12, 63
    jnz .refuse
    mov rdi, r12
    mov esi, 64
    xor edx, edx
    call acpi_range
    jc .refuse
    cmp dword [r12], 'FACS'
    jne .refuse
    mov esi, [r12+4]
    cmp esi, 64
    jb .refuse
    cmp esi, 4096
    ja .refuse
    mov rdi, r12
    xor edx, edx
    call acpi_hp_s5_nvs
    jc .refuse
    mov edi, 0x481e5000             ; pinned HPCF SystemMemory region, length0x5c
    mov esi, 0x5c
    xor edx, edx
    call acpi_hp_s5_nvs              ; live firmware NVS descriptor required
    jc .refuse
    mov edi, 0xfed80000             ; pinned ERMM SystemMemory device resource
    mov esi, 0x1000
    mov edx, 1
    call acpi_range                 ; identity-map extent; reject RAM aliases
    jc .refuse
    ; GlobalLock word: preserve reserved bits. Never set Pending on refusal.
    ; Only acquire a completely free lock; a concurrent winner is a refusal.
    mov eax, [r12+16]
    test al, 3
    jnz .refuse
    mov ecx, eax
    or ecx, 2
    lock cmpxchg [r12+16], ecx
    jne .refuse
    ; Exactly the _PTS(5) byte-access order recovered in the host trace.
    ; Hold the GlobalLock only for HPCF, as its Field LockRule requires.
    mov edi, 0x481e503c
    mov byte [rdi], 5
    ; OSPM GlobalLock release: an SMI waiter may have set Pending while owned.
    ; Clear both low bits atomically and signal GBL_RLS only when requested.
    mov eax, [r12+16]
.release:
    mov ecx, eax
    and ecx, ~3
    lock cmpxchg [r12+16], ecx
    jne .release
    test al, 1
    jz .global_released
    mov edx, r13d
    in ax, dx
    or ax, 4
    out dx, ax
.global_released:
    mov dx, 0x24e
    mov al, 5
    out dx, al
    inc dx
    mov al, 0x54
    out dx, al
    mov dx, 0x80
    mov al, 5
    out dx, al
    mov edi, 0xfed80288
    mov al, [rdi]
    or al, 2
    mov [rdi], al
    mov edi, 0xfed802b0
    mov al, [rdi]
    and al, 0xf3
    or al, 4
    mov [rdi], al
    mov edx, ebp
    inc edx
    in al, dx
    and al, 0x40
    mov cl, al
    in al, dx
    and al, 0xbf
    or al, cl
    out dx, al
    mov dx, 0x80
    mov al, 0x55
    out dx, al
    mov dx, 0x72
    mov al, 0xf1
    out dx, al
    inc dx
    mov al, 0x55
    out dx, al
.complete:
    mov eax, 1
    jmp .out
.refuse:
    mov eax, -1
.out:
    add rsp, HP_S5_LOCAL
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.unrelated:
    xor eax, eax
    ret

; Require retained ACPI NVS for writable firmware state. acpi_range validates
; map shape, arithmetic and complete coverage first. Recheck every intersecting
; descriptor, so an overlapping conventional-RAM entry cannot be hidden by an
; earlier NVS cover. No mapping is manufactured or memory-map type changed.
acpi_hp_s5_nvs:
    xor edx, edx
    call acpi_range
    jc .bad
    lea r10, [rdi+rsi]
    mov r8, [rel mmap_buffer]
    mov r9, r8
    add r9, [rel mmap_size]
    xor r11d, r11d
.next:
    cmp r8, r9
    jae .done
    test qword [r8+8], 4095
    jnz .bad
    mov rax, [r8+24]
    mov rdx, rax
    shr rdx, 52
    jnz .bad
    shl rax, 12
    add rax, [r8+8]
    jc .bad
    cmp rdi, rax
    jae .skip
    cmp r10, [r8+8]
    jbe .skip
    cmp dword [r8], 10              ; EfiACPIMemoryNVS, not reclaimable RAM
    jne .bad
    cmp rdi, [r8+8]
    jb .bad
    cmp r10, rax
    ja .bad
    mov r11d, 1
.skip:
    add r8, [rel mmap_desc_size]
    jmp .next
.done:
    test r11d, r11d
    jz .bad
    clc
    ret
.bad:
    stc
    ret

align 4
hp_s5_pins:
    dd 59675 ; registry-value-000.bin
    db 0x6f,0x63,0x7c,0x7b,0x7e,0x32,0x6c,0x41,0x48,0x7a,0x90,0xe8,0x4d,0x9c,0xdb,0x0d,0x59,0xea,0x1a,0x73,0x44,0xe9,0xe6,0x3d,0xd4,0x86,0xf0,0x1f,0xb5,0xdc,0x7d,0x6d
    dd 21529 ; registry-value-004.bin
    db 0xd8,0x72,0x28,0xe0,0xd7,0x44,0xdf,0xc1,0x58,0x63,0xf3,0x62,0x20,0x39,0x1d,0x9e,0x0c,0xa0,0xf4,0x6a,0x80,0x18,0xd4,0xf0,0x26,0x85,0xe0,0xc5,0x09,0xc8,0xac,0xba
    dd 991 ; registry-value-005.bin
    db 0x50,0xd2,0xd6,0x57,0x13,0xd6,0xae,0x83,0x38,0x0a,0x17,0xcb,0x2b,0xec,0xe9,0xd6,0x04,0xed,0xcb,0x85,0xaa,0x1e,0xb7,0xde,0x8b,0x62,0x03,0xef,0x69,0x00,0x12,0x29
    dd 979 ; registry-value-006.bin
    db 0xbe,0x7c,0x49,0xff,0x1d,0xff,0x45,0xe9,0x0a,0x54,0xfc,0xd4,0xa9,0xc7,0x3e,0x9d,0xdf,0x8f,0x8f,0x36,0x2b,0x6d,0x7c,0x73,0xe8,0x8d,0x7e,0xb5,0xad,0xa5,0x0b,0x72
    dd 43 ; registry-value-007.bin
    db 0x13,0x65,0x72,0xef,0xc3,0xf2,0x4d,0xb2,0x6c,0x44,0x7d,0x1b,0x25,0xfa,0x4e,0x72,0x17,0xf6,0x56,0x67,0x39,0xad,0xbc,0xab,0xc9,0xbd,0x5c,0x71,0x43,0x83,0xd0,0x38
    dd 50 ; registry-value-008.bin
    db 0x91,0x75,0x90,0x37,0x50,0xbc,0x76,0x43,0xde,0x9d,0x98,0xf0,0x56,0xe8,0x1c,0xa7,0x50,0x50,0x9c,0x97,0x08,0x73,0x38,0x72,0x5b,0xa8,0xee,0x5c,0x05,0xfb,0x5c,0xfa
    dd 105 ; registry-value-009.bin
    db 0x20,0x1a,0x03,0x23,0x84,0x94,0xf4,0xd4,0x9d,0x1e,0xc8,0x5a,0xd6,0x3e,0x35,0x8a,0x13,0x85,0xc5,0x6b,0xea,0x49,0xf2,0x94,0xee,0x08,0xde,0x84,0x83,0x40,0x9b,0x8e
    dd 7875 ; registry-value-010.bin
    db 0xe1,0x40,0x09,0x7b,0x5d,0xff,0x83,0xc6,0x6d,0xef,0xf9,0xf0,0x36,0x28,0xcd,0x2a,0x71,0x24,0x83,0x20,0x2a,0x43,0xb2,0xf6,0xc9,0x6c,0xbf,0x87,0x34,0xcd,0x40,0xf0
    dd 191 ; registry-value-011.bin
    db 0x22,0x58,0xb9,0x66,0x2b,0xfe,0xe2,0xb7,0xc5,0x15,0xe7,0x61,0x2c,0x9d,0x69,0x4d,0x03,0x61,0x22,0xe6,0x36,0x0c,0x13,0xc1,0xf4,0x1c,0x60,0x2f,0xa2,0xe1,0x43,0xbb
    dd 4508 ; registry-value-012.bin
    db 0x8d,0x5d,0xb2,0x41,0x7e,0xb5,0xaa,0xa4,0x51,0x1f,0x32,0x5c,0x00,0xa8,0xfc,0x0f,0x64,0xc8,0x59,0xa8,0x1d,0x82,0x2b,0x62,0x8a,0xe0,0xab,0x99,0x02,0x41,0xb9,0x02
    dd 298 ; registry-value-013.bin
    db 0xc4,0x15,0x76,0xbb,0x77,0x59,0xa8,0xf6,0xed,0x15,0x64,0x28,0xc6,0xc4,0xe4,0x9f,0xe5,0x84,0x20,0xb7,0x31,0xec,0x3b,0x0d,0xef,0xd6,0xc4,0xce,0x76,0x94,0xe0,0x5d
