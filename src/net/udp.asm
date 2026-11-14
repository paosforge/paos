;; MODULE net/udp
;; LAYER 4
;; EXPORTS udp4_send, udp4_payload_view, udp4_arp_request
;; IMPORTS core/lib/mem, core/lib/cksum, lib/safe_buffer, net/netdev, net/arp_cache
;; CAPS
;; OWNER saga:net
; Shared bounded Ethernet/IPv4/UDP framing seam.  Callers provide storage and
; route values; this module owns the one header/checksum/length implementation.

struc udp4_tx
  .frame:       resq 1
  .capacity:    resd 1
  .src_ip:      resd 1
  .dst_ip:      resd 1
  .src_port:    resw 1
  .dst_port:    resw 1
  .src_mac:     resq 1
  .dst_mac:     resq 1
  .payload:     resq 1
  .payload_len: resd 1
endstruc

struc udp4_view
  .src_ip:      resd 1
  .dst_ip:      resd 1
  .src_port:    resw 1
  .dst_port:    resw 1
  .pad:         resd 1
  .payload:     resq 1
  .payload_len: resd 1
endstruc

UDP4_ETH_HLEN equ 14
UDP4_MAX_PAY  equ 1472

; udp4_send(RDI=udp4_tx descriptor) -> RAX=0 sent / -1 rejected or TX failed.
; UDP checksum zero is the IPv4 "not computed" value; IPv4 checksum is real.
udp4_send:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    test rbx, rbx
    jz   .reject
    mov  r12, [rbx + udp4_tx.frame]
    mov  r13, [rbx + udp4_tx.src_mac]
    mov  r14, [rbx + udp4_tx.dst_mac]
    test r12, r12
    jz   .reject
    test r13, r13
    jz   .reject
    test r14, r14
    jz   .reject
    mov  ecx, [rbx + udp4_tx.payload_len]
    cmp  ecx, UDP4_MAX_PAY
    ja   .reject
    test ecx, ecx
    jz   .reject
    cmp  qword [rbx + udp4_tx.payload], 0
    je   .reject
    cmp  dword [rbx + udp4_tx.capacity], 60
    jb   .reject
    mov  edi, ecx
    mov  esi, 42
    call safe_checked_add
    test edx, edx
    jnz  .reject
    mov  ecx, [rbx + udp4_tx.capacity]
    cmp  rax, rcx
    ja   .reject
    cmp  dword [rbx + udp4_tx.src_ip], 0
    je   .reject
    cmp  dword [rbx + udp4_tx.dst_ip], 0
    je   .reject

    mov  eax, [r14]
    mov  [r12], eax
    mov  ax, [r14 + 4]
    mov  [r12 + 4], ax
    mov  eax, [r13]
    mov  [r12 + 6], eax
    mov  ax, [r13 + 4]
    mov  [r12 + 10], ax
    mov  word [r12 + 12], 0x0008       ; Ethernet IPv4, wire 08 00

    lea  rdi, [r12 + 14]
    mov  byte [rdi], 0x45
    mov  byte [rdi + 1], 0
    mov  eax, [rbx + udp4_tx.payload_len]
    add  eax, 28
    mov  [rdi + 2], ah
    mov  [rdi + 3], al
    mov  dword [rdi + 4], 0            ; id=0, unfragmented
    mov  byte [rdi + 8], 64
    mov  byte [rdi + 9], 17
    mov  word [rdi + 10], 0
    mov  eax, [rbx + udp4_tx.src_ip]
    mov  [rdi + 12], eax
    mov  eax, [rbx + udp4_tx.dst_ip]
    mov  [rdi + 16], eax
    mov  esi, 20
    call net_cksum16
    rol  ax, 8                         ; store checksum in network byte order
    mov  [r12 + 24], ax

    lea  rdi, [r12 + 34]
    movzx eax, word [rbx + udp4_tx.src_port]
    mov  [rdi], ah
    mov  [rdi + 1], al
    movzx eax, word [rbx + udp4_tx.dst_port]
    mov  [rdi + 2], ah
    mov  [rdi + 3], al
    mov  eax, [rbx + udp4_tx.payload_len]
    add  eax, 8
    mov  [rdi + 4], ah
    mov  [rdi + 5], al
    mov  word [rdi + 6], 0
    lea  rdi, [r12 + 42]
    mov  rsi, [rbx + udp4_tx.payload]
    mov  edx, [rbx + udp4_tx.payload_len]
    call memcpy

    mov  edx, [rbx + udp4_tx.payload_len]
    add  edx, 42
    cmp  edx, 60
    jae  .send
    lea  rdi, [r12 + rdx]
    mov  ecx, 60
    sub  ecx, edx
    xor  eax, eax
    rep  stosb
    mov  edx, 60
.send:
    mov  rsi, r12
    call netdev_tx
    jmp  .out
.reject:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; udp4_payload_view(RDI=frame, RSI=available bytes, RDX=udp4_view) -> 0/-1.
; Output is committed only after every Ethernet/IP/UDP length check succeeds
; and the checksums verify: the IPv4 header checksum always (RFC 1122
; 3.2.1.2), the UDP checksum over pseudo-header + segment whenever it is
; non-zero (RFC 768, RFC 1122 4.1.3.4; zero means "not computed" on IPv4).
udp4_payload_view:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    test rbx, rbx
    jz   .view_reject
    test r13, r13
    jz   .view_reject
    mov  rdi, rbx
    mov  rsi, r12
    xor  edx, edx
    mov  ecx, 14 + 20
    call safe_span_validate
    test eax, eax
    jnz  .view_reject
    cmp  word [rbx + 12], 0x0008
    jne  .view_reject
    lea  r8, [rbx + 14]
    movzx eax, byte [r8]
    mov  ecx, eax
    shr  ecx, 4
    cmp  ecx, 4
    jne  .view_reject
    and  eax, 0x0f
    shl  eax, 2
    cmp  eax, 20
    jb   .view_reject
    mov  r9d, eax                       ; IHL
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, 14
    lea  ecx, [r9d + 8]
    call safe_span_validate
    test eax, eax
    jnz  .view_reject
    cmp  byte [r8 + 9], 17
    jne  .view_reject
    mov  al, [r8 + 6]
    and  al, 0xbf                       ; allow DF only; reject MF/reserved/offset
    jnz  .view_reject
    cmp  byte [r8 + 7], 0
    jne  .view_reject
    movzx eax, byte [r8 + 2]
    shl  eax, 8
    mov  al, [r8 + 3]
    mov  r10d, eax                      ; IPv4 total length
    lea  ecx, [r9d + 8]
    cmp  r10d, ecx
    jb   .view_reject
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, 14
    mov  ecx, r10d
    call safe_span_validate
    test eax, eax
    jnz  .view_reject
    lea  r11, [r8 + r9]                 ; UDP header
    movzx eax, byte [r11 + 4]
    shl  eax, 8
    mov  al, [r11 + 5]
    cmp  eax, 8
    jb   .view_reject
    mov  ecx, r10d
    sub  ecx, r9d
    cmp  eax, ecx
    ja   .view_reject

    ; net_cksum16 clobbers RAX,RCX,RDX,RDI only: R8-R11 frame views survive.
    push rax                            ; UDP length (header + data)
    mov  rdi, r8
    mov  esi, r9d
    call net_cksum16                    ; a valid header re-sums to 0
    test eax, eax
    jnz  .cksum_bad                   ; bad IPv4 header
    cmp  word [r11 + 6], 0
    je   .cksum_ok
    sub  rsp, 16                        ; pseudo-header: src, dst, 0, 17, UDP length
    mov  ecx, [r8 + 12]
    mov  [rsp], ecx
    mov  ecx, [r8 + 16]
    mov  [rsp + 4], ecx
    mov  word [rsp + 8], 0x1100         ; zero byte, protocol 17
    mov  cx, [r11 + 4]                  ; UDP length as it is on the wire
    mov  [rsp + 10], cx
    mov  rdi, rsp
    mov  esi, 12
    call net_cksum16
    not  eax
    and  eax, 0xFFFF
    mov  [rsp + 12], eax                ; pseudo-header partial sum
    mov  rdi, r11
    mov  esi, [rsp + 16]                ; the saved UDP length
    call net_cksum16
    not  eax
    and  eax, 0xFFFF
    add  eax, [rsp + 12]                ; one's-complement add of the two partial sums
    mov  ecx, eax
    shr  ecx, 16
    and  eax, 0xFFFF
    add  eax, ecx
    add  rsp, 16
    cmp  eax, 0xFFFF                    ; a valid datagram sums to all ones
    jne  .cksum_bad
.cksum_ok:
    pop  rax
    sub  eax, 8

    mov  ecx, [r8 + 12]
    mov  [r13 + udp4_view.src_ip], ecx
    mov  ecx, [r8 + 16]
    mov  [r13 + udp4_view.dst_ip], ecx
    movzx ecx, byte [r11]
    shl  ecx, 8
    mov  cl, [r11 + 1]
    mov  [r13 + udp4_view.src_port], cx
    movzx ecx, byte [r11 + 2]
    shl  ecx, 8
    mov  cl, [r11 + 3]
    mov  [r13 + udp4_view.dst_port], cx
    lea  rcx, [r11 + 8]
    mov  [r13 + udp4_view.payload], rcx
    mov  [r13 + udp4_view.payload_len], eax
    xor  eax, eax
    jmp  .view_out
.cksum_bad:
    pop  rax
.view_reject:
    mov  rax, -1
.view_out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; udp4_arp_request(RDI=src MAC, ESI=src IP, EDX=target IP,
;                  RCX=frame scratch, R8D=capacity) -> 0/-1.
udp4_arp_request:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, edx
    test rbx, rbx
    jz   .arp_reject
    test rcx, rcx
    jz   .arp_reject
    cmp  r8d, 60
    jb   .arp_reject
    test r12d, r12d
    jz   .arp_reject
    test r13d, r13d
    jz   .arp_reject
    push rcx
    push r8
    mov  edi, r13d
    call arp_pending_note                ; SEC-S7a: only this target's reply is solicited
    pop  r8
    pop  rcx
    mov  r9, rcx
    mov  dword [r9], 0xffffffff
    mov  word [r9 + 4], 0xffff
    mov  eax, [rbx]
    mov  [r9 + 6], eax
    mov  ax, [rbx + 4]
    mov  [r9 + 10], ax
    mov  word [r9 + 12], 0x0608
    lea  rdi, [r9 + 14]
    mov  word [rdi], 0x0100
    mov  word [rdi + 2], 0x0008
    mov  byte [rdi + 4], 6
    mov  byte [rdi + 5], 4
    mov  word [rdi + 6], 0x0100
    mov  eax, [rbx]
    mov  [rdi + 8], eax
    mov  ax, [rbx + 4]
    mov  [rdi + 12], ax
    mov  [rdi + 14], r12d
    mov  qword [rdi + 18], 0
    mov  [rdi + 24], r13d
    lea  rdi, [r9 + 42]
    xor  eax, eax
    mov  ecx, 18
    rep  stosb
    mov  rsi, r9
    mov  edx, 60
    call netdev_tx
    jmp  .arp_out
.arp_reject:
    mov  rax, -1
.arp_out:
    pop  r13
    pop  r12
    pop  rbx
    ret
