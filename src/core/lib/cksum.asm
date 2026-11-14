;; MODULE core/lib/cksum
;; LAYER 1
;; EXPORTS net_cksum16, net_cksum16_kat
;; IMPORTS boot/serial
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/lib/cksum.asm — the ONE canonical 16-bit one's-complement checksum
; (RFC 1071). G1: checksum math is COMMON to IPv4/UDP/TCP/ICMP, so it lives here
; in core/lib and is called by net/* — NOT copied per-protocol (contract 1042
; known_trap). The IPv4/UDP checksum is the same algorithm; only the byte span
; (and, for UDP, a prepended pseudo-header) differ, and those are the caller's
; job. This routine treats the buffer as a sequence of big-endian (network-order)
; 16-bit words, sums them into a 32-bit accumulator, folds the carries, and
; returns the one's complement — exactly the value that goes on the wire.
; ============================================================================

; net_cksum16(RDI=ptr, RSI=len_bytes) -> AX = RFC1071 checksum (network-order value)
;   SMALLEST/SIMPLEST variant (tournament 1408, hot_path): the one's-complement sum
;   is endian-agnostic — summing the buffer as NATIVE (little-endian) 16-bit words
;   and byte-swapping the folded result ONCE at the end yields exactly the same
;   network-order checksum as swapping every word in the loop (BSD in_cksum trick).
;   That drops the per-word `xchg` from the hot loop (fewer ops, no data change) and
;   a trailing odd byte simply adds as the LOW half of a native word — after the one
;   final swap it lands in the high half, per RFC1071. A 64-bit accumulator can't
;   overflow across any real buffer, so no mid-loop carry fold is needed.
;   Re-running over a buffer whose checksum field already holds the correct value
;   yields 0x0000 (the receiver's validity test) — proven by net_cksum16_kat.
;   in: RDI=ptr, RSI=len   out: RAX=checksum (0..0xFFFF)   clobbers: RAX,RCX,RDX,RDI
net_cksum16:
    xor  eax, eax                        ; 64-bit sum accumulator (rax)
    mov  rcx, rsi                         ; remaining byte count
.word_loop:
    cmp  rcx, 2
    jb   .tail
    movzx edx, word [rdi]                 ; native (little-endian) 16-bit word
    add  rax, rdx
    add  rdi, 2
    sub  rcx, 2
    jmp  .word_loop
.tail:
    test rcx, rcx
    jz   .fold
    movzx edx, byte [rdi]                 ; final odd byte -> LOW half of a native word
    add  rax, rdx
.fold:
    mov  rdx, rax
    shr  rdx, 16
    and  eax, 0xFFFF
    add  eax, edx                         ; fold high bits into low 16
    mov  edx, eax
    shr  edx, 16
    add  eax, edx                         ; second fold (carry from the first add)
    not  eax
    and  eax, 0xFFFF
    xchg al, ah                           ; native sum -> network-order value (one swap)
    ret

; net_cksum16_kat — boot KAT (tournament 1408 correctness GATE). Runs three RFC1071
;   reference vectors and emits [tourn.net_cksum16.kat] ONLY on all-pass; a variant
;   whose output diverges by even one bit fails a compare and the marker never fires.
;   One shared buffer serves all three: data(8) -> classic 0x220d; data+cksum(10) ->
;   receiver re-sum 0x0000; first 3 bytes -> odd-tail 0x0dfe.
;   clobbers: caller-saved (called at boot, PH_KAT)
net_cksum16_kat:
    lea  rdi, [rel nc_kat_v1]             ; RFC1071 classic 8-byte vector
    mov  esi, 8
    call net_cksum16
    cmp  eax, 0x220d
    jne  .fail
    lea  rdi, [rel nc_kat_v1]             ; data + its checksum re-sums to 0 (wire test)
    mov  esi, 10
    call net_cksum16
    test eax, eax
    jnz  .fail
    lea  rdi, [rel nc_kat_v1]             ; odd trailing byte (3-byte span) -> 0x0dfe
    mov  esi, 3
    call net_cksum16
    cmp  eax, 0x0dfe
    jne  .fail
    lea  rdi, [rel str_nc_kat_ok]
    call serial_string
    ret
.fail:
    lea  rdi, [rel str_nc_kat_fail]
    call serial_string
    ret

nc_kat_v1:       db 0x00,0x01,0xf2,0x03,0xf4,0xf5,0xf6,0xf7, 0x22,0x0d
str_nc_kat_ok:   db "[PAOS64] P1 core/lib: net_cksum16 KAT PASS (RFC1071 0x220d + receiver re-sum 0x0000 + odd-tail 0x0dfe) [tourn.net_cksum16.kat]", 13, 10, 0
str_nc_kat_fail: db "[PAOS64] P1 core/lib: net_cksum16 KAT FAIL [tourn.net_cksum16.kat.fail]", 13, 10, 0
