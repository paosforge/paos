;; MODULE core/lib/fixed
;; LAYER 1
;; EXPORTS q32_from_us, q32_to_us, q32_to_ms_signed, be64_load, be64_store
;; IMPORTS
;; CAPS
;; OWNER saga:net
; Canonical unsigned Q32.32 and big-endian u64 helpers.  SNTP is their first
; caller; keeping the arithmetic here prevents protocol modules from growing
; private fixed-point or byte-order implementations.

; q32_from_us(RDI=microseconds, range < 2^32 seconds) -> RAX=Q32.32.
q32_from_us:
    mov  rax, rdi
    xor  edx, edx
    mov  rcx, 1000000
    div  rcx                         ; RAX=seconds, RDX=fractional microseconds
    shl  rax, 32
    mov  r8, rax
    mov  rax, rdx
    shl  rax, 32
    xor  edx, edx
    div  rcx
    or   rax, r8
    ret

; q32_to_us(RDI=unsigned Q32.32) -> RAX=microseconds.
q32_to_us:
    mov  eax, edi                    ; fraction
    mov  rcx, 1000000
    mul  rcx
    shr  rax, 32                     ; fractional microseconds
    mov  r8, rax
    mov  rax, rdi
    shr  rax, 32
    imul rax, rax, 1000000
    add  rax, r8
    ret

; q32_to_ms_signed(RDI=signed Q32.32) -> RAX=signed whole milliseconds.
q32_to_ms_signed:
    mov  r8, rdi
    test rdi, rdi
    jns  .magnitude
    neg  rdi
.magnitude:
    mov  rax, rdi
    mov  rcx, 1000
    mul  rcx
    shrd rax, rdx, 32
    test r8, r8
    jns  .done
    neg  rax
.done:
    ret

; be64_load(RDI=8 readable bytes) -> RAX. NULL degrades to zero.
be64_load:
    test rdi, rdi
    jz   .zero
    xor  eax, eax
    xor  ecx, ecx
    mov  edx, 8
.load:
    shl  rax, 8
    mov  cl, [rdi]
    or   rax, rcx
    inc  rdi
    dec  edx
    jnz  .load
    ret
.zero:
    xor  eax, eax
    ret

; be64_store(RDI=8 writable bytes, RSI=value). NULL writes nothing.
be64_store:
    test rdi, rdi
    jz   .store_done
    mov  ecx, 8
.store:
    rol  rsi, 8
    mov  [rdi], sil
    inc  rdi
    dec  ecx
    jnz  .store
.store_done:
    ret
