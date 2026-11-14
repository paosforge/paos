;; MODULE core/memmap
;; LAYER 1
;; EXPORTS memmap_total, memmap_total_bytes, memmap_selftest, memmap_inventory
;; IMPORTS boot/serial, boot/paging
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/memmap.asm — own the UEFI memory map; sum usable (conventional) RAM.
;
; boot/paging.asm already AllocatePool's a buffer and calls GetMemoryMap right
; before ExitBootServices (mmap_buffer / mmap_size / mmap_desc_size live in its
; data). That buffer is EfiLoaderData, so it SURVIVES EBS — PaOS owns it. paging
; used the map only for the EBS key and otherwise discarded it; here we walk it.
;
; Each EFI_MEMORY_DESCRIPTOR (stride = mmap_desc_size, NOT sizeof — the firmware
; may pad it, so we step by the runtime stride, never a hardcoded width):
;   Type           u32 @0   (7 = EfiConventionalMemory = free usable RAM)
;   PhysicalStart  u64 @8
;   VirtualStart   u64 @16
;   NumberOfPages  u64 @24   (4 KiB pages)
;   Attribute      u64 @32
; Total usable RAM = Σ NumberOfPages(type 7) × 4096. This is the input the later
; dma_alloc hole-avoidance + heap sizing build on (MEMORY_MAP §1).
; ============================================================================

EFI_CONVENTIONAL_MEMORY equ 7

; memmap_inventory(RDI=out[24]) — observe the already published EBS map.
; +0 state:u32 (0 absent, 1 valid, 2 invalid), +4 descriptor count:u32,
; +8 conventional bytes:u64, +16 loader/boot-service bytes:u64 (types1..4).
; These are saved firmware type totals, NOT current allocator free/admission.
; No firmware calls, allocation, map mutation or memmap_total_bytes writes.
; paging owns discovery/admission/overlap checks; these are defensive bounded
; geometry and arithmetic checks only. Invalid output carries no partial totals.
; Preserves callee-saved registers. Clobbers RAX,RCX,RDX,RSI,R8-R11.
memmap_inventory:
    mov  qword [rdi], 0
    mov  qword [rdi + 8], 0
    mov  qword [rdi + 16], 0
    mov  rsi, [rel mmap_buffer]
    test rsi, rsi
    jz   .out
    mov  dword [rdi], 2
    mov  r8, [rel mmap_desc_size]
    cmp  r8, 40
    jb   .out
    cmp  r8, 256
    ja   .out
    test r8, 7
    jnz  .out
    mov  r9, [rel mmap_size]
    test r9, r9
    jz   .out
    cmp  r9, 65536                         ; existing paging map-buffer capacity
    ja   .out
    mov  rax, rsi
    add  rax, r9
    jc   .out
    mov  rax, r9
    xor  edx, edx
    div  r8
    test rdx, rdx
    jnz  .out
    mov  [rdi + 4], eax
    xor  r10d, r10d                        ; conventional bytes
    xor  r11d, r11d                        ; loader/boot-service bytes
.loop:
    mov  rax, [rsi + 24]
    test rax, rax
    jz   .invalid
    mov  rdx, rax
    shr  rdx, 52
    jnz  .invalid
    shl  rax, 12
    mov  rdx, [rsi + 8]
    test rdx, 4095
    jnz  .invalid
    add  rdx, rax
    jc   .invalid
    mov  ecx, [rsi]
    cmp  ecx, EFI_CONVENTIONAL_MEMORY
    je   .conventional
    cmp  ecx, 1
    jb   .next
    cmp  ecx, 4
    ja   .next
    add  r11, rax
    jc   .invalid
    jmp  .next
.conventional:
    add  r10, rax
    jc   .invalid
.next:
    add  rsi, r8
    sub  r9, r8
    jnz  .loop
    mov  [rdi + 8], r10
    mov  [rdi + 16], r11
    mov  dword [rdi], 1
    ret
.invalid:
    mov  dword [rdi + 4], 0
.out:
    ret

; memmap_total — walk the saved map, sum type-7 page counts, return RAX = bytes
;   (pages × 4096). Also caches the result in memmap_total_bytes. Clobbers RAX.
memmap_total:
    push rbx
    push rcx
    push rsi
    mov  rsi, [rel mmap_buffer]          ; map base (persists post-EBS)
    mov  rcx, [rel mmap_size]            ; total bytes of the map
    mov  rbx, [rel mmap_desc_size]       ; per-descriptor stride
    xor  eax, eax                        ; page accumulator
    test rsi, rsi
    jz   .done
    test rbx, rbx
    jz   .done                           ; no stride -> nothing safe to walk
.loop:
    cmp  rcx, rbx                         ; less than one full descriptor left?
    jb   .done
    cmp  dword [rsi], EFI_CONVENTIONAL_MEMORY
    jne  .next
    add  rax, [rsi + 24]                 ; += NumberOfPages
.next:
    add  rsi, rbx                         ; advance by the runtime stride
    sub  rcx, rbx
    jmp  .loop
.done:
    shl  rax, 12                         ; pages × 4096
    mov  [rel memmap_total_bytes], rax
    pop  rsi
    pop  rcx
    pop  rbx
    ret

; memmap_selftest — sum conventional RAM, emit the marker + total bytes.
memmap_selftest:
    call memmap_total
    test rax, rax
    jz   .fail                            ; zero usable RAM => map walk is wrong
    lea  rdi, [rel str_memmap_ok]
    call serial_string
    mov  rdi, rax
    call serial_hex64
    lea  rdi, [rel str_memmap_nl]
    call serial_string
    ret
.fail:
    lea  rdi, [rel str_memmap_fail]
    call serial_string
    ret

; --- core/memmap data (in-image; the image page is RW+X under paging) ---
memmap_total_bytes: dq 0
str_memmap_ok:   db "[PAOS64] M1 memmap: conventional RAM total=", 0
str_memmap_nl:   db 13, 10, 0
str_memmap_fail: db "[PAOS64] M1 memmap: FAILED (empty/unwalkable map)", 13, 10, 0
