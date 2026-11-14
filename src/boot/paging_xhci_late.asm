;; MODULE boot/paging_xhci_late
;; LAYER 0
;; EXPORTS
;; IMPORTS boot/paging
;; CAPS
;; OWNER saga:boot
; Emit the paging-owned xHCI high-MMIO helpers only after gop_mode_list.
; Definitions and authority remain in boot/paging.asm; this include preserves
; the known-safe early GOP data address without machine-specific binaries.
PAGING_XHCI_HIGH_MAP
PAGING_XHCI_BAR_CHECK

; This wrapper preserves the old pre-GOP map routine byte-for-byte. Its caller
; is still one near CALL, so the layout-sensitive gop_mode_list cannot move.
; The separate ResetSystem permission is examined only after the full mutable
; runtime map succeeded. Real Lenovo SHA583 still instruction-fetch-faulted at
; the firmware pointer despite descriptor/PDE checks. Keep deferred BOOT resets
; on the already-proven CF9 path until an independently executable firmware
; return can be demonstrated; other runtime services retain their mapping.
map_pbm_runtime_code_and_reset_guard:
    call map_pbm_runtime_code
    mov  byte [rel pbm_runtime_reset_usable], 0
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .out
    push r12
    push r13
    push r14
    mov  rax, [rel runtime_services]
    test rax, rax
    jz   .done
    mov  r10, [rax + 0x68]
    test r10, r10
    jz   .done
    mov  rsi, [rel mmap_buffer]
    mov  r12, [rel mmap_size]
    mov  r13, [rel mmap_desc_size]
    test rsi, rsi
    jz   .done
    cmp  r13, 40
    jb   .done
    cmp  r13, 256
    ja   .done
    mov  r14, rsi
    add  r14, r12
    jc   .done
.descriptor:
    cmp  rsi, r14
    jae  .done
    mov  rax, rsi
    add  rax, r13
    jc   .done
    cmp  rax, r14
    ja   .done
    bt   qword [rsi + 32], 63         ; EFI_MEMORY_RUNTIME
    jnc  .next
    cmp  dword [rsi], 5               ; EfiRuntimeServicesCode
    jne  .next
    mov  rax, [rsi + 24]              ; NumberOfPages
    test rax, rax
    jz   .done
    shr  rax, 52
    jnz  .done
    mov  rax, [rsi + 24]
    shl  rax, 12
    add  rax, [rsi + 8]               ; exclusive byte end
    jc   .done
    cmp  rax, [rel ident_bytes]
    ja   .done
    cmp  r10, [rsi + 8]
    jb   .next
    cmp  r10, rax
    jae  .next
    mov  rdi, r10
    call paging_pd_entry_ptr
    test rax, rax
    jz   .done
    bt   qword [rax], 63
    jc   .done
    mov  byte [rel pbm_runtime_reset_usable], 0
    jmp  .done
.next:
    add  rsi, r13
    jmp  .descriptor
.done:
    pop  r14
    pop  r13
    pop  r12
.out:
    ret

; RCQ-36 private boot observations are never mutated after CR3 installation.
PAGING_HDA_DATA
