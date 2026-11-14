;; MODULE hv/domain_channel
;; LAYER 5
;; EXPORTS dc_reset, dc_submit, dc_cancel, dc_receive, dc_make_frame, dc_expire
;; IMPORTS core/time
;; CAPS
;; OWNER saga:web_browser
; 2717 audit: 1013b's dev/net/virtio_domain rings hold Ethernet, not typed
; control. Its local control uses hv/vmx's console split queues (the same
; machinery used by 2716). CDP1 adds a record type to those queues, not a ring,
; device, socket, or host-address grant. Queue 0 carries requests, 1 replies.
;
; Little endian, 64-byte header + 1..192 bytes:
;  0 magic CDP1; 4 channel u16=2717; 6 version u16=1; 8 generation u64;
; 16 request ID u64; 24 total u32; 28 offset u32; 32 fragment length u32;
; 36 last u32 (0/1); 40 host absolute TSC deadline u64; 48 reserved[16]=0.
; The deadline is opaque to the guest; the host enforces it on every fragment.
; Transport treats payload as bytes; only the diagnostic guest parses JSON.
;
; v1: one outstanding request, 1024 bytes/direction, 64 IDs per generation.
; Completed/cancelled/failed IDs remain tombstones until reset. Exhausting the
; ledger returns backpressure; it never evicts an ID and permits replay.
; Call at an owned stopped-vCPU boundary; no helper yields or retains borrowed
; pointers. Receive consumes a private snapshot produced by the ring walker.
; Errors: 1 syntax/frame, 2 generation, 3 oversize, 4 order/truncated,
; 5 unsolicited, 6 deadline, 7 backpressure, 8 duplicate, 9 cancelled,
; 10 unavailable, 11 guest/transport, 12 EPT revoke, 13 inactive, 14 not found.

DC_HEADER equ 64
DC_CHUNK equ 192
DC_FRAME equ DC_HEADER + DC_CHUNK
DC_MAX equ 1024
DC_IDS equ 64

; Reset cancels all work and scrubs private bytes. Never wrap generation.
dc_reset:
    cmp qword [rel dc_generation], -1
    je .exhausted
    inc qword [rel dc_generation]
.scrub:
    lea rdi, [rel dc_private]
    xor eax, eax
    mov ecx, dc_private_end - dc_private
    rep stosb
    ret
.exhausted:
    ; Preserve the final identity, but cancellation and erasure still happen.
    ; Pending bytes must not remain eligible for make_frame/receive after STOP.
    mov byte [rel dc_exhausted], 1
    jmp .scrub

; RDI=owned bytes, ESI=length, RDX=id, RCX=deadline, R8=generation.
; Returns EAX=error. Rejections preserve a still-live pending request. Expired
; work is reaped first, even when the caller has not separately polled it.
dc_submit:
    push rdx
    push rcx
    call dc_expire
    pop rcx
    pop rdx
    mov eax, 13
    cmp byte [rel dc_active], 1
    jne .out
    mov eax, 2
    cmp r8, [rel dc_generation]
    jne .out
    mov eax, 1
    test rdi, rdi
    jz .out
    test rdx, rdx
    jz .out
    test esi, esi
    jz .out
    mov eax, 3
    cmp esi, DC_MAX
    ja .out
    push rdx
    push rcx
    rdtsc
    shl rdx, 32
    or rax, rdx
    pop rcx
    pop rdx
    cmp rax, rcx
    mov eax, 6
    jae .out
    lea r9, [rel dc_ids]
    xor r10d, r10d
.id:
    cmp r10d, [rel dc_id_count]
    jae .capacity
    mov eax, 8
    cmp rdx, [r9 + r10*8]
    je .out
    inc r10d
    jmp .id
.capacity:
    mov eax, 7
    cmp byte [rel dc_pending], 0
    jne .out
    cmp r10d, DC_IDS
    jae .out
    mov [r9 + r10*8], rdx
    inc dword [rel dc_id_count]
    mov [rel dc_id], rdx
    mov [rel dc_deadline], rcx
    mov [rel dc_length], esi
    mov ecx, esi
    mov rsi, rdi
    lea rdi, [rel dc_request]
    rep movsb
    lea rdi, [rel dc_reply]
    xor eax, eax
    mov ecx, DC_MAX
    rep stosb
    mov dword [rel dc_tx_offset], 0
    mov dword [rel dc_rx_offset], 0
    mov dword [rel dc_reply_length], 0
    mov dword [rel dc_error], 0
    mov byte [rel dc_delivered], 0
    mov byte [rel dc_pending], 1
    xor eax, eax
.out:
    ret

; RDI=exact ID, RSI=generation. A cancelled tombstone cannot deliver late data.
dc_cancel:
    mov eax, 2
    cmp rsi, [rel dc_generation]
    jne .out
    mov eax, 14
    cmp byte [rel dc_pending], 1
    jne .out
    cmp rdi, [rel dc_id]
    jne .out
    mov byte [rel dc_pending], 0
    mov dword [rel dc_error], 9
    mov dword [rel dc_rx_offset], 0
    mov dword [rel dc_reply_length], 0
    inc qword [rel dc_cancelled]
    xor eax, eax
.out:
    ret

; Deadline enforcement occurs even if no guest response ever arrives.
dc_expire:
    cmp byte [rel dc_pending], 1
    jne .out
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, [rel dc_deadline]
    jb .out
    mov byte [rel dc_pending], 0
    mov dword [rel dc_error], 6
    mov dword [rel dc_rx_offset], 0
    mov dword [rel dc_reply_length], 0
.out:
    ret

; Build next request fragment in dc_wire. EAX=wire length, 0 if no work.
; Caller advances dc_tx_offset ONLY after the existing RX ring accepts bytes.
dc_make_frame:
    call dc_expire
    xor eax, eax
    cmp byte [rel dc_pending], 1
    jne .out
    mov edx, [rel dc_tx_offset]
    cmp edx, [rel dc_length]
    jae .out
    lea rdi, [rel dc_wire]
    mov ecx, DC_FRAME / 8
    rep stosq
    lea rdi, [rel dc_wire]
    mov dword [rdi], 'CDP1'
    mov dword [rdi + 4], 0x00010A9D
    mov rax, [rel dc_generation]
    mov [rdi + 8], rax
    mov rax, [rel dc_id]
    mov [rdi + 16], rax
    mov eax, [rel dc_length]
    mov [rdi + 24], eax
    mov [rdi + 28], edx
    sub eax, edx
    cmp eax, DC_CHUNK
    jbe .last
    mov eax, DC_CHUNK
    jmp .payload
.last:
    mov dword [rdi + 36], 1
.payload:
    mov [rdi + 32], eax
    mov rcx, [rel dc_deadline]
    mov [rdi + 40], rcx
    mov ecx, eax
    lea rsi, [rel dc_request]
    add rsi, rdx
    add rdi, DC_HEADER
    rep movsb
    add eax, DC_HEADER
.out:
    ret

; RDI=private frame snapshot, ESI=actual bytes. EAX=error or 0.
; Validate every header field and all widened lengths BEFORE any payload copy.
; No partial response is observable. Invalid streams terminate the request.
dc_receive:
    push rbx
    push r12
    mov rbx, rdi
    mov r12d, esi
    call dc_expire
    mov eax, 1
    test rbx, rbx
    jz .bad
    cmp r12d, DC_HEADER
    jb .bad
    cmp r12d, DC_FRAME
    ja .bad
    cmp dword [rbx], 'CDP1'
    jne .bad
    cmp dword [rbx + 4], 0x00010A9D
    jne .bad
    mov rdx, [rbx + 48]
    or rdx, [rbx + 56]
    jnz .bad
    mov eax, 2
    mov rdx, [rbx + 8]
    cmp rdx, [rel dc_generation]
    jne .bad
    mov eax, 5
    mov rdx, [rbx + 16]
    cmp rdx, [rel dc_id]
    jne .bad
    cmp byte [rel dc_pending], 1
    je .pending
    mov eax, [rel dc_error]
    test eax, eax
    jnz .bad
    mov eax, 8
    jmp .bad
.pending:
    mov eax, 5
    mov edx, [rel dc_tx_offset]
    cmp edx, [rel dc_length]
    jne .bad
    mov eax, 6
    mov rdx, [rbx + 40]
    cmp rdx, [rel dc_deadline]
    jne .bad
    mov eax, 3
    mov edx, [rbx + 24]
    test edx, edx
    jz .bad
    cmp edx, DC_MAX
    ja .bad
    mov eax, 4
    cmp dword [rel dc_rx_offset], 0
    je .first
    cmp edx, [rel dc_reply_length]
    jne .bad
.first:
    mov ecx, [rbx + 32]
    test ecx, ecx
    jz .bad
    cmp ecx, DC_CHUNK
    ja .bad
    lea r8d, [rcx + DC_HEADER]
    cmp r8d, r12d
    jne .bad
    mov r8d, [rbx + 28]
    cmp r8d, [rel dc_rx_offset]
    je .offset
    mov eax, 8
    jb .bad
    mov eax, 4
    jmp .bad
.offset:
    add r8, rcx                         ; widened before comparing/copying
    cmp r8, rdx
    ja .bad
    xor r9d, r9d
    cmp r8, rdx
    sete r9b
    cmp [rbx + 36], r9d
    jne .bad
    ; R10-H1: complete every nested bounds/order/final-bit check before
    ; guest-controlled RCX or the admitted reply offset reaches the copy.
    ; The earlier transport acquire predates these nested field checks.
    lfence
    mov [rel dc_reply_length], edx
    lea rdi, [rel dc_reply]
    mov eax, [rel dc_rx_offset]
    add rdi, rax
    lea rsi, [rbx + DC_HEADER]
    rep movsb
    mov [rel dc_rx_offset], r8d
    inc qword [rel dc_rx_frames]
    test r9d, r9d
    jz .ok
    mov byte [rel dc_pending], 0
    mov byte [rel dc_delivered], 1
    inc qword [rel dc_deliveries]
.ok:
    xor eax, eax
    jmp .out
.bad:
    mov [rel dc_error], eax
    mov byte [rel dc_pending], 0
    ; A duplicate after a completed response is refused, not a second delivery.
    ; The diagnostic probe checks delivery-count deltas independently.
    inc qword [rel dc_refusals]
.out:
    pop r12
    pop rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_hv_domain_channel_0 0
align 8
dc_generation: dq 0
dc_exhausted: db 0
align 8
dc_private:
dc_id: dq 0
dc_deadline: dq 0
dc_deliveries: dq 0
dc_refusals: dq 0
dc_cancelled: dq 0
dc_rx_frames: dq 0
dc_tx_frames: dq 0
dc_length: dd 0
dc_reply_length: dd 0
dc_tx_offset: dd 0
dc_rx_offset: dd 0
dc_id_count: dd 0
dc_error: dd 0
dc_active: db 0
dc_pending: db 0
dc_delivered: db 0
align 8
dc_ids: times DC_IDS dq 0
dc_request: times DC_MAX db 0
dc_reply: times DC_MAX db 0
dc_wire: times DC_FRAME db 0
dc_private_end:
%endmacro
WDATA_DEFER WDATA_hv_domain_channel_0
