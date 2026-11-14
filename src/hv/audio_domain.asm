;; MODULE hv/audio_domain
;; LAYER 5
;; EXPORTS padn_bind, padn_request, padn_pump, padn_receive, padn_take, padn_retire, padn_context, padn_failure_event
;; IMPORTS
;; CAPS extension
;; OWNER saga:audio
; Native PAD1 PCM client. No enumeration, assignment, console acquisition,
; guest launch or snd_register side effects. The VM owner binds this client
; only after acquiring a private binary channel for the exact stopped-vCPU
; START generation. That owner serializes every entry and retires the binding
; after stopping the domain; retirement here does NOT stop a VM or revoke DMA.
;
; All buffers are native-owned. Receive takes the console walker's completed
; private snapshot, never guest memory. Times are the caller's monotonic boot
; milliseconds. Each request has one absolute 2000ms deadline across all
; chunks/backpressure; partial responses never escape to callers. An uncertain
; send, hostile response or deadline fault disables transmission until exact
; retirement. Accepted frame counts are NOT device position or audible proof.

PADN_HEADER equ 64
PADN_MAX equ 4160
PADN_IDLE equ 1
PADN_TX equ 2
PADN_RX equ 3
PADN_READY equ 4
PADN_FAULT equ 5
PADN_STOPPED equ 6

; RDI=monotonically increasing START generation, RSI=nonzero launch epoch,
; RDX=nonzero session, RCX=trusted send callback(bytes,len)->1/0/negative.
; Callback must use the already-owned channel; 0 means definitely unaccepted.
; Any result other than 0/1 is uncertain. No automatic transport retry.
padn_bind:
    cmp dword [rel padn_state], 0
    jne .busy
    test rdi, rdi
    jz .invalid
    test rsi, rsi
    jz .invalid
    test rdx, rdx
    jz .invalid
    test rcx, rcx
    jz .invalid
    cmp rdi, [rel padn_last_generation]
    jbe .stale
    cmp rsi, [rel padn_last_epoch]
    jbe .stale
    mov [rel padn_generation], rdi
    mov [rel padn_last_generation], rdi
    mov [rel padn_epoch], rsi
    mov [rel padn_last_epoch], rsi
    mov [rel padn_session], rdx
    mov [rel padn_send], rcx
    mov dword [rel padn_state], PADN_IDLE
    xor eax, eax
    ret
.busy: mov eax, -16
    ret
.invalid: mov eax, -22
    ret
.stale: mov eax, -116
    ret

; Internal common identity/clock/deadline check. RDI=generation, RSI=now_ms.
; Preserves request argument registers. Poisoning scrubs PCM and leaves the
; generation bound, so failed I/O cannot silently authorize a fresh domain.
padn_check:
    cmp rdi, [rel padn_generation]
    jne .stale
    cmp dword [rel padn_state], 0
    je .stale
    cmp dword [rel padn_state], PADN_FAULT
    je .fault
    cmp rsi, [rel padn_now]
    jb .clock
    mov [rel padn_now], rsi
    cmp dword [rel padn_state], PADN_TX
    je .deadline
    cmp dword [rel padn_state], PADN_RX
    jne .ok
.deadline:
    cmp rsi, [rel padn_deadline]
    jae .timeout
.ok: xor eax, eax
    ret
.clock: mov eax, -5
    jmp padn_poison
.timeout: mov eax, -110
    jmp padn_poison
.stale: mov eax, -116
    ret
.fault: mov eax, -5
    ret

padn_poison:
    ; Native owner serializes PADN entries. Publish one aligned, sanitized
    ; count/reason pair, not identity/PCM/callback data. It survives retirement.
    ; Saturation is terminal: no wrap or changed reason under the same count.
    ; Preserve original return registers/flags and all existing scrub behavior.
    pushfq
    push rcx
    push rdx
    cmp dword [rel padn_state], PADN_FAULT
    je .recorded
    mov rdx, [rel padn_failure_event]
    shr rdx, 32
    cmp edx, 0xFFFFFFFF
    je .recorded
    inc edx
    shl rdx, 32
    mov ecx, 3                       ; IO/uncertainty or reversed monotonic clock
    cmp eax, -110
    jne .protocol
    mov ecx, 1                       ; absolute request deadline expired
    jmp .publish
.protocol:
    cmp eax, -71
    jne .publish
    mov ecx, 2                       ; malformed/hostile PAD1 reply
.publish:
    or rdx, rcx
    mov [rel padn_failure_event], rdx
.recorded:
    pop rdx
    pop rcx
    popfq
    mov dword [rel padn_state], PADN_FAULT
    mov [rel padn_error], eax
    push rdi
    push rcx
    push rax
    pushfq
    cld
    lea rdi, [rel padn_tx]
    mov ecx, PADN_MAX * 2
    xor eax, eax
    rep stosb
    popfq
    pop rax
    pop rcx
    pop rdi
    ret

; RDI=generation, ESI=op1..6, EDX=frames, RCX=native PCM or0,
; R8D=OPEN directions1..3 or0, R9=now_ms. Returns0 queued or negative errno.
; PLAY snapshots the entire request; later retries may submit only the known
; unaccepted suffix after taking a valid partial/EAGAIN reply.
padn_request:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov ebx, esi
    mov r12d, edx
    mov r13, rcx
    mov r14d, r8d
    mov r15, r9
    mov rsi, r9
    call padn_check
    test eax, eax
    jnz .out
    cmp dword [rel padn_state], PADN_STOPPED
    je .pipe
    cmp dword [rel padn_state], PADN_IDLE
    jne .busy
    cmp ebx, 1
    jb .invalid
    cmp ebx, 6
    ja .invalid
    cmp r15, -2001
    ja .invalid
    cmp dword [rel padn_remote_fault], 0
    je .geometry
    cmp ebx, 5
    jae .geometry
    mov eax, -5
    jmp .out
.geometry:
    cmp ebx, 1
    je .open
    test r14d, r14d
    jnz .invalid
    cmp ebx, 2
    je .play
    cmp ebx, 3
    je .capture
    test r12d, r12d
    jnz .invalid
    test r13, r13
    jnz .invalid
    cmp ebx, 6
    je .queue
    cmp dword [rel padn_directions], 0
    je .pipe
    cmp ebx, 5
    je .queue
    test dword [rel padn_directions], 1
    jz .pipe
    jmp .queue
.open:
    cmp dword [rel padn_opened], 0
    jne .pipe
    test r12d, r12d
    jnz .invalid
    test r13, r13
    jnz .invalid
    test r14d, r14d
    jz .invalid
    cmp r14d, 3
    ja .invalid
    jmp .queue
.play:
    test dword [rel padn_directions], 1
    jz .pipe
    cmp dword [rel padn_draining], 0
    jne .pipe
    test r13, r13
    jz .invalid
    jmp .frames
.capture:
    test dword [rel padn_directions], 2
    jz .pipe
    test r13, r13
    jnz .invalid
.frames:
    test r12d, r12d
    jz .invalid
    cmp r12d, 1024
    ja .invalid
.queue:
    cmp qword [rel padn_sequence], 65536
    jae .pipe
    inc qword [rel padn_sequence]
    lea rax, [r15 + 2000]
    mov [rel padn_deadline], rax
    pushfq
    cld
    lea rdi, [rel padn_tx]
    mov ecx, PADN_MAX * 2
    xor eax, eax
    rep stosb
    mov dword [rel padn_tx], 'PAD1'
    mov word [rel padn_tx + 4], 1
    mov [rel padn_tx + 6], bx
    mov rax, [rel padn_epoch]
    mov [rel padn_tx + 8], rax
    mov rax, [rel padn_session]
    mov [rel padn_tx + 16], rax
    mov rax, [rel padn_sequence]
    mov [rel padn_tx + 24], rax
    mov dword [rel padn_tx + 32], 48000
    mov dword [rel padn_tx + 36], 0x00010002
    mov [rel padn_tx + 40], r12d
    mov [rel padn_tx + 52], r14d
    mov dword [rel padn_tx_length], PADN_HEADER
    cmp ebx, 2
    jne .control
    lea ecx, [r12 * 4]
    mov [rel padn_tx + 44], ecx
    add [rel padn_tx_length], ecx
    mov rsi, r13
    lea rdi, [rel padn_tx + PADN_HEADER]
    rep movsb
.control:
    popfq
    cmp ebx, 1
    jne .drain
    mov dword [rel padn_opened], 1
.drain:
    cmp ebx, 4
    jne .queued
    mov dword [rel padn_draining], 1
.queued:
    mov dword [rel padn_tx_offset], 0
    mov dword [rel padn_rx_length], 0
    mov dword [rel padn_state], PADN_TX
    xor eax, eax
    jmp .out
.invalid: mov eax, -22
    jmp .out
.busy: mov eax, -16
    jmp .out
.pipe: mov eax, -32
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI=generation, RSI=now_ms. Pump ONE <=256B request chunk. Returns number
; definitely delivered,0 pressure/no TX, or negative. Caller yields/resumes VM
; through its normal owner flow; this function never runs or spins a vCPU.
padn_pump:
    push rbx
    push r12
    push r13
    call padn_check
    test eax, eax
    jnz .out
    xor eax, eax
    cmp dword [rel padn_state], PADN_TX
    jne .out
    mov r12, rdi
    mov r13, [rel padn_sequence]
    mov ebx, [rel padn_tx_length]
    mov eax, [rel padn_tx_offset]
    sub ebx, eax
    mov ecx, 256
    cmp ebx, ecx
    cmova ebx, ecx
    lea rdi, [rel padn_tx]
    add rdi, rax
    mov esi, ebx
    call [rel padn_send]
    cmp r12, [rel padn_generation]
    jne .stale
    cmp dword [rel padn_state], PADN_TX
    jne .stale
    cmp r13, [rel padn_sequence]
    jne .stale
    test eax, eax
    jz .out
    cmp eax, 1
    jne .uncertain
    add [rel padn_tx_offset], ebx
    mov eax, [rel padn_tx_offset]
    cmp eax, [rel padn_tx_length]
    jne .delivered
    mov dword [rel padn_state], PADN_RX
.delivered: mov eax, ebx
    jmp .out
.uncertain: mov eax, -5
    call padn_poison
    jmp .out
.stale: mov eax, -116
.out:
    pop r13
    pop r12
    pop rbx
    ret

; RDI=generation, RSI=now_ms, RDX=completed private console snapshot,
; ECX=1..4096 bytes. Returns0 assembling,1 complete, negative poisoned/refused.
padn_receive:
    call padn_check
    test eax, eax
    jnz .out
    cmp dword [rel padn_state], PADN_RX
    jne .bad
    test rdx, rdx
    jz .bad
    test ecx, ecx
    jz .bad
    cmp ecx, 4096
    ja .bad
    mov eax, [rel padn_rx_length]
    add eax, ecx
    cmp eax, PADN_MAX
    ja .bad
    pushfq
    push rsi
    push rdi
    cld
    mov esi, [rel padn_rx_length]
    lea rdi, [rel padn_rx]
    add rdi, rsi
    mov rsi, rdx
    rep movsb
    pop rdi
    pop rsi
    popfq
    mov [rel padn_rx_length], eax
    cmp eax, PADN_HEADER
    jb .partial
    call padn_validate
    test eax, eax
    js .bad
    cmp eax, [rel padn_rx_length]
    jb .bad
    ja .partial
    mov dword [rel padn_state], PADN_READY
    mov eax, 1
    ret
.partial: xor eax, eax
.out: ret
.bad: mov eax, -71
    jmp padn_poison

; Returns expected wire length after independently validating the complete
; header; negative means hostile. No guest-controlled length feeds a copy.
padn_validate:
    cmp dword [rel padn_rx], 'PAD1'
    jne .bad
    cmp word [rel padn_rx + 4], 1
    jne .bad
    mov ax, [rel padn_tx + 6]
    or ax, 0x8000
    cmp ax, [rel padn_rx + 6]
    jne .bad
    mov rax, [rel padn_tx + 8]
    cmp rax, [rel padn_rx + 8]
    jne .bad
    mov rax, [rel padn_tx + 16]
    cmp rax, [rel padn_rx + 16]
    jne .bad
    mov rax, [rel padn_tx + 24]
    cmp rax, [rel padn_rx + 24]
    jne .bad
    cmp dword [rel padn_rx + 32], 48000
    jne .bad
    cmp dword [rel padn_rx + 36], 0x00010002
    jne .bad
    cmp qword [rel padn_rx + 56], 0
    jne .bad
    cmp dword [rel padn_rx + 48], 4095
    ja .bad
    mov eax, [rel padn_rx + 40]
    cmp eax, [rel padn_tx + 40]
    ja .bad
    cmp dword [rel padn_rx + 48], 0
    je .flags
    test eax, eax
    jnz .bad
.flags:
    mov edx, [rel padn_rx + 52]
    cmp word [rel padn_tx + 6], 6
    je .status_flags
    test edx, edx
    jnz .bad
    jmp .payload
.status_flags:
    cmp edx, [rel padn_directions]
    jne .bad
.payload:
    cmp word [rel padn_tx + 6], 3
    jne .no_pcm
    shl eax, 2
    jmp .size
.no_pcm:
    xor eax, eax
.size:
    cmp eax, [rel padn_rx + 44]
    jne .bad
    add eax, PADN_HEADER
    ret
.bad: mov eax, -71
    ret

; RDI=generation, RSI=now_ms, RDX=caller-owned >=4160B output.
; Returns exactly one validated complete response length,0 not ready,negative.
; Copies nothing on refusal. There is no partially published capture buffer.
padn_take:
    call padn_check
    test eax, eax
    jnz .out
    xor eax, eax
    cmp dword [rel padn_state], PADN_READY
    jne .out
    test rdx, rdx
    jz .invalid
    cmp dword [rel padn_rx + 48], 0
    je .success
    cmp dword [rel padn_rx + 48], 11
    je .release
    mov dword [rel padn_remote_fault], 1
    jmp .release
.success:
    movzx ecx, word [rel padn_tx + 6]
    cmp ecx, 1
    jne .progress
    mov eax, [rel padn_tx + 52]
    mov [rel padn_directions], eax
.progress:
    mov eax, [rel padn_rx + 40]
    cmp ecx, 2
    jne .capture
    add [rel padn_accepted], rax
.capture:
    cmp ecx, 3
    jne .release
    add [rel padn_captured], rax
.release:
    mov dword [rel padn_state], PADN_IDLE
    cmp word [rel padn_tx + 6], 5
    jne .copy
    mov dword [rel padn_state], PADN_STOPPED
    mov dword [rel padn_directions], 0
.copy:
    pushfq
    push rsi
    push rdi
    cld
    mov rdi, rdx
    lea rsi, [rel padn_rx]
    mov ecx, [rel padn_rx_length]
    mov edx, ecx
    rep movsb
    lea rdi, [rel padn_tx]
    mov ecx, PADN_MAX * 2
    xor eax, eax
    rep stosb
    pop rdi
    pop rsi
    popfq
    mov eax, edx
.out: ret
.invalid: mov eax, -22
    ret

; RDI=generation, RSI=now_ms, RDX=private writable32B snapshot.
; Validates identity/deadline before publishing metadata. No PCM or callback
; pointer escapes. The trusted native caller owns a disjoint output span.
padn_context:
    sub rsp,8
    call padn_check
    add rsp,8
    test eax,eax
    jnz .out
    test rdx,rdx
    jz .invalid
    mov rax,[rel padn_epoch]
    mov [rdx],rax
    mov rax,[rel padn_session]
    mov [rdx+8],rax
    mov eax,[rel padn_state]
    mov [rdx+16],eax
    mov eax,[rel padn_directions]
    mov [rdx+20],eax
    mov eax,[rel padn_remote_fault]
    mov [rdx+24],eax
    mov eax,[rel padn_draining]
    mov [rdx+28],eax
    xor eax,eax
.out: ret
.invalid: mov eax,-22
    ret

; RDI=exact bound generation, called only after VM stop/channel retirement.
; Erase PCM, callback, counters and identity; retain anti-reuse high watermarks.
padn_retire:
    cmp rdi, [rel padn_generation]
    jne .stale
    cmp dword [rel padn_state], 0
    je .stale
    pushfq
    push rdi
    cld
    lea rdi, [rel padn_private]
    mov ecx, padn_storage_end - padn_private
    xor eax, eax
    rep stosb
    pop rdi
    popfq
    ret
.stale: mov eax, -116
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_audio_domain 0
alignb 8
padn_storage:
padn_last_generation: resq 1
padn_last_epoch: resq 1
; High32 saturated terminal-transition count, low32 normalized reason1..3.
; Native owner serialized; one aligned x86 store publishes a coherent pair.
padn_failure_event: resq 1
padn_private:
padn_generation: resq 1
padn_epoch: resq 1
padn_session: resq 1
padn_send: resq 1
padn_now: resq 1
padn_sequence: resq 1
padn_deadline: resq 1
padn_accepted: resq 1
padn_captured: resq 1
padn_state: resd 1
padn_error: resd 1
padn_remote_fault: resd 1
padn_opened: resd 1
padn_directions: resd 1
padn_draining: resd 1
padn_tx_length: resd 1
padn_tx_offset: resd 1
padn_rx_length: resd 1
alignb 8
padn_tx: resb PADN_MAX
padn_rx: resb PADN_MAX
padn_storage_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_audio_domain
