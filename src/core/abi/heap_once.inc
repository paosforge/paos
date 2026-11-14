; ============================================================================
; core/abi/heap_once.inc — ONE-TIME ZEROED KERNEL-HEAP BUFFERS (image diet).
; A header: emits no bytes where it is included; HEAP_ONCE_ACCESSOR emits code.
;
; WHY: a `times N db 0` buffer costs N bytes of the ESP payload (the image is one
; flat -f bin PE with no virtual-size-only BSS). The Dell ESP holds the payload
; plus a temp copy (FINDING_20260930_DELL_ESP_SPACE.md), so large zero-initialised
; buffers are moved to one zeroed kernel-heap allocation each (the v0.0.44
; ssh_contexts_base pattern, svc/ssh.asm).
;
; HOW: the module keeps an 8-byte image pointer (normally inside its WDATA block)
; and emits an accessor:
;
;     HEAP_ONCE_ACCESSOR my_buf_base, my_buf_ptr, MY_BUF_BYTES, str_my_buf_fail
;
;   my_buf_base -> RAX = the zeroed buffer, or 0 when the heap refused (heap not
;   yet up — kmalloc refuses cleanly before PH_HEAP_INIT — or exhausted; the fail
;   string is printed once per refused call). Preserves EVERY register except RAX
;   (flags are clobbered). The first successful call allocates + zeroes; the
;   pointer is published with LOCK CMPXCHG, so two racing first callers agree on
;   one buffer (the loser's block is a bounded, one-time leak on a bump heap).
;
; The kernel heap is 16 MiB below 4 GiB, identity-mapped, 16-byte aligned
; (boot/paging.asm + core/heap.asm). It holds no code, so heap buffers are never
; TCG self-modifying-code slow-path writers. Do NOT use this for buffers that
; need page alignment, a fixed position relative to code (hot-patch arena, SMP
; trampoline, PMOD export table) or any use before PH_HEAP_INIT.
; ============================================================================
%ifndef PAOS_HEAP_ONCE_INC
%define PAOS_HEAP_ONCE_INC 1

; HEAP_ONCE_ACCESSOR name, ptr_symbol, size_bytes, fail_string_symbol
%macro HEAP_ONCE_ACCESSOR 4
%1:
    mov  rax, [rel %2]
    test rax, rax
    jnz  %%have
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    sub  rsp, 8                             ; 16-align the kmalloc/memset calls
    mov  edi, %3
    call kmalloc
    test rax, rax
    jz   %%fail
    mov  r8, rax
    mov  rdi, rax
    xor  esi, esi
    mov  edx, %3
    call memset
    mov  rdx, r8
    xor  eax, eax
    lock cmpxchg [rel %2], rdx              ; publish iff still unset
    jne  %%done                             ; lost a first-use race: RAX = winner's
    mov  rax, rdx
    jmp  %%done
%%fail:
    lea  rdi, [rel %4]
    call serial_string
    xor  eax, eax
%%done:
    add  rsp, 8
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
%%have:
    ret
%endmacro

%endif
