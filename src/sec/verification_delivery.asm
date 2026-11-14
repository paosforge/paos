;; MODULE sec/verification_delivery
;; LAYER 2
;; EXPORTS vfy_delivery_reset, vfy_delivery_route_set, vfy_delivery_publish, vfy_delivery_attach, vfy_delivery_take, vfy_delivery_still_valid, vfy_delivery_poll_cancel, vfy_delivery_cancel, vfy_delivery_result, vfy_delivery_inspect, vfy_delivery_retire
;; IMPORTS core/time
;; CAPS
;; OWNER saga:security
;; CONTEXT: bsp_only  (serialized trusted-native calls; no AP, IRQ, yielding callback or concurrent worker)
; VFD1 native delivery lifecycle, design r2. Unlinked preparation seam: this
; module delivers no authentication, code issuance/checking, rate policy or
; durable anti-rollback guarantee. The issuer must bind owner/machine/purpose,
; commit issuance/rates/burn durably, and supply globally unique random IDs.
; All pointers are bounded, valid, disjoint native buffers, NOT guest pointers.
; Only trusted issuer/enrollment code may publish/cancel/route_set/retire/reset.
; The eventual bridge exposes only the five worker calls, disconnects the old
; worker before attach, and serializes operations through the BSP. No reset or
; routing entry is an owner-authorization check by itself.
;
; Worker ABI: attach()->generation 1..UINT32_MAX-1 (0 exhausted); take(out,cap)->256/0/-1;
; still_valid(id16,connector,generation)->1/0; poll_cancel(out16)->1/0;
; result(id16,0 sent|1 failed|2 down)->1 accepted/0 ignored. An attach or result
; never grants authority. Take transfers plaintext once and wipes our copy.
; No implicit retry/eviction; unknown sends are never queued again.
;
; Producer ABI: publish(frame256,size=256)->0/-1 (<=300s TTL); route_set(id32,
; generation32,channel32=1..3|0 revoke)->0/-1. Generations strictly advance on
; any change; identical tuples are idempotent. Eight route rows never evict.
; cancel(id16)->1 known/0 absent, queues one cancel on first invalidation.
; retire(id16)->1/0 requires trusted expiry AND cancel drained, then wipes row.
; The caller consumes inspect/audit metadata before retiring; no auto-retire.
; reset() wipes all state; a worker must attach again. Boot/reset wiring open.
;
; inspect(id16,out64,cap>=64)->0/-1. Short/null output untouched, otherwise
; zeroed on absence. Metadata LE: id16,expiry64,connector32,generation32,
; channel32,state32,flags32,worker32,result32,reason32,duplicates32,reserved32.
; States: 0free 1queued 2dispatched 3done 4unknown 5cancelled.
; Flags: 1cancel_pending 2result_seen 4late
;        8sent_receipt_observed_at_or_after_expiry.
; Reasons: 0none 1burn/cancel 2expired 3route_changed 4clock 5worker_exhausted.
; First reason/result kept, duplicate results saturate. A known late result
; does not erase an earlier unknown or cancellation. Bit8 means a successful
; sent receipt was processed at/after expiry under source-qualified UTC.
; Actual send time is unknown: result carries only ID and outcome, no send
; timestamp. An on-time send with a delayed receipt also sets bit8; neither
; flag nor receipt supplies a send-time witness or recalls a message.
;
; Time dependency gives source-qualified UTC, not cryptographically
; authenticated network time. Missing, >INT64_MAX or backward UTC cancels all
; live rows, never revives one. The per-boot high-water mark is NOT durable.
; Product integration must supply the service's trusted-clock/rollback policy.

VFD_N           equ 8
VFD_SIZE        equ 320
VFD_ID          equ 256
VFD_EXP         equ 272
VFD_CID         equ 280
VFD_GEN         equ 284
VFD_CHANNEL     equ 288
VFD_STATE       equ 292
VFD_FLAGS       equ 296
VFD_WORKER      equ 300
VFD_RESULT      equ 304
VFD_REASON      equ 308
VFD_DUPLICATES  equ 312
VFD_QUEUED      equ 1
VFD_DISPATCHED  equ 2
VFD_DONE        equ 3
VFD_UNKNOWN     equ 4
VFD_CANCELLED   equ 5

%macro VFD_ENTER 0
    push rbx
    push r12
    push r13
    push r14
    push r15
    cld
%endmacro
%macro VFD_LEAVE 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
%endmacro

vfy_delivery_reset:
    cld
    lea rdi, [rel vfd_entries]
    mov ecx, (VFD_N*VFD_SIZE + VFD_N*16 + 16)/8
    xor eax, eax
    rep stosq
    ret

; Internal find-by-id, RAX=row or zero. Clobbers R8..R10, RCX, RDX.
vfd_find:
    test rdi, rdi
    jz .missing
    mov r9, [rdi]
    mov r10, [rdi+8]
    lea rax, [rel vfd_entries]
    mov ecx, VFD_N
.loop:
    cmp dword [rax+VFD_STATE], 0
    je .next
    cmp [rax+VFD_ID], r9
    jne .next
    cmp [rax+VFD_ID+8], r10
    je .out
.next:
    add rax, VFD_SIZE
    dec ecx
    jnz .loop
.missing:
    xor eax, eax
.out:
    ret

; Internal authoritative route find, EDI=id -> RAX=row or zero.
vfd_route_find:
    lea rax, [rel vfd_routes]
    mov ecx, VFD_N
.loop:
    cmp [rax], edi
    je .out
    add rax, 16
    dec ecx
    jnz .loop
    xor eax, eax
.out:
    ret

; Internal cancel RDI=row ESI=reason; first reason only, one cancel notification.
; Terminal delivery state remains truthful; all plaintext is erased.
vfd_cancel_entry:
    cmp dword [rdi+VFD_REASON], 0
    jne .out
    mov [rdi+VFD_REASON], esi
    or dword [rdi+VFD_FLAGS], 1
    cmp dword [rdi+VFD_STATE], VFD_UNKNOWN
    jae .wipe
    cmp dword [rdi+VFD_STATE], VFD_DONE
    je .wipe
    mov dword [rdi+VFD_STATE], VFD_CANCELLED
.wipe:
    xor eax, eax
    mov ecx, 32
    rep stosq
.out:
    ret

; Internal snapshot and sweep; RAX=qualified nondecreasing UTC, or zero.
; Every worker call checks fresh time. Bad time permanently invalidates rows.
vfd_tick:
    push rbx
    push r12
    push r13
    call time_wall_utc_now_s
    mov r12, rax
    test rax, rax
    jle .bad_clock
    cmp rax, [rel vfd_clock_floor]
    jb .bad_clock
    mov [rel vfd_clock_floor], rax
    xor r13d, r13d
    jmp .sweep
.bad_clock:
    xor r12d, r12d
    mov r13d, 4
.sweep:
    lea rbx, [rel vfd_entries]
.loop:
    cmp dword [rbx+VFD_STATE], 0
    je .next
    mov esi, r13d
    test esi, esi
    jnz .cancel
    cmp r12, [rbx+VFD_EXP]
    jb .next
    mov esi, 2
.cancel:
    mov rdi, rbx
    call vfd_cancel_entry
.next:
    add rbx, VFD_SIZE
    lea rax, [rel vfd_entries+VFD_N*VFD_SIZE]
    cmp rbx, rax
    jb .loop
    mov rax, r12
    pop r13
    pop r12
    pop rbx
    ret

vfy_delivery_route_set:
    VFD_ENTER
    mov r12d, edi
    mov r13d, esi
    mov r14d, edx
    test r12d, r12d
    jz .bad
    test r13d, r13d
    jz .bad
    cmp r14d, 3
    ja .bad
    call vfd_route_find
    test rax, rax
    jz .new
    cmp r13d, [rax+4]
    jb .bad
    ja .store
    cmp r14d, [rax+8]
    jne .bad
    xor eax, eax
    jmp .out
.new:
    lea rax, [rel vfd_routes]
    mov ecx, VFD_N
.find_free:
    cmp dword [rax], 0
    je .store
    add rax, 16
    dec ecx
    jnz .find_free
    jmp .bad
.store:
    mov [rax], r12d
    mov [rax+4], r13d
    mov [rax+8], r14d
    ; Any advance invalidates every prior request on this connector, including
    ; queued rows. No implicit migration to a new destination/generation.
    lea rbx, [rel vfd_entries]
    mov r15d, VFD_N
.invalidate:
    cmp dword [rbx+VFD_STATE], 0
    je .next
    cmp [rbx+VFD_CID], r12d
    jne .next
    mov rdi, rbx
    mov esi, 3
    call vfd_cancel_entry
.next:
    add rbx, VFD_SIZE
    dec r15d
    jnz .invalidate
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    VFD_LEAVE

vfy_delivery_publish:
    VFD_ENTER
    mov r12, rdi
    cmp rsi, 256
    jne .bad
    test r12, r12
    jz .bad
    cmp dword [rel vfd_worker_generation], -1
    je .bad
    call vfd_tick
    test rax, rax
    jz .bad
    mov r13, rax
    cmp dword [r12], 0x31444656       ; VFD1
    jne .bad
    cmp word [r12+4], 1
    jne .bad
    movzx eax, byte [r12+6]
    dec eax
    cmp eax, 2
    ja .bad
    movzx eax, byte [r12+7]
    dec eax
    cmp eax, 3
    ja .bad
    mov rax, [r12+8]
    or rax, [r12+16]
    jz .bad
    mov rax, [r12+24]
    test rax, rax
    js .bad
    sub rax, r13
    jbe .bad
    cmp rax, 300
    ja .bad
    cmp word [r12+42], 0
    jne .bad
    movzx ecx, word [r12+40]
    dec ecx
    cmp ecx, 199
    ja .bad
    inc ecx
    lea rsi, [r12+44]
.text:
    movzx eax, byte [rsi]
    cmp eax, 0x20
    jb .bad
    cmp eax, 0x7e
    ja .bad
    inc rsi
    dec ecx
    jnz .text
    lea rdx, [r12+256]
.padding:
    cmp byte [rsi], 0
    jne .bad
    inc rsi
    cmp rsi, rdx
    jb .padding
    mov edi, [r12+32]
    test edi, edi
    jz .bad
    call vfd_route_find
    test rax, rax
    jz .bad
    mov edx, [r12+36]
    cmp edx, [rax+4]
    jne .bad
    movzx edx, byte [r12+6]
    cmp edx, [rax+8]
    jne .bad
    lea rdi, [r12+8]
    call vfd_find
    test rax, rax
    jnz .bad
    lea rbx, [rel vfd_entries]
    mov ecx, VFD_N
.free:
    cmp dword [rbx+VFD_STATE], 0
    je .store
    add rbx, VFD_SIZE
    dec ecx
    jnz .free
    jmp .bad
.store:
    mov rdi, rbx
    mov rsi, r12
    mov ecx, 32
    rep movsq
    mov rax, [r12+8]
    mov [rbx+VFD_ID], rax
    mov rax, [r12+16]
    mov [rbx+VFD_ID+8], rax
    mov rax, [r12+24]
    mov [rbx+VFD_EXP], rax
    mov rax, [r12+32]
    mov [rbx+VFD_CID], rax
    movzx eax, byte [r12+6]
    mov [rbx+VFD_CHANNEL], eax
    mov dword [rbx+VFD_RESULT], -1
    mov dword [rbx+VFD_STATE], VFD_QUEUED
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    VFD_LEAVE

vfy_delivery_attach:
    VFD_ENTER
    call vfd_tick
    cmp dword [rel vfd_worker_generation], -2
    jae .exhausted
    inc dword [rel vfd_worker_generation]
    lea rbx, [rel vfd_entries]
    mov r12d, VFD_N
.loop:
    cmp dword [rbx+VFD_STATE], VFD_DISPATCHED
    jne .next
    mov dword [rbx+VFD_STATE], VFD_UNKNOWN
.next:
    add rbx, VFD_SIZE
    dec r12d
    jnz .loop
    mov eax, [rel vfd_worker_generation]
    jmp .out
.exhausted:
    mov dword [rel vfd_worker_generation], -1 ; permanent exhausted sentinel
    lea rbx, [rel vfd_entries]
    mov r12d, VFD_N
.cancel:
    cmp dword [rbx+VFD_STATE], 0
    je .advance
    mov rdi, rbx
    mov esi, 5
    call vfd_cancel_entry
.advance:
    add rbx, VFD_SIZE
    dec r12d
    jnz .cancel
    xor eax, eax
.out:
    VFD_LEAVE

vfy_delivery_take:
    VFD_ENTER
    mov r12, rdi
    test rdi, rdi
    jz .bad
    cmp rsi, 256
    jb .bad
    cmp dword [rel vfd_worker_generation], 0
    je .bad
    cmp dword [rel vfd_worker_generation], -1
    je .bad
    call vfd_tick
    test rax, rax
    jz .empty
    lea rbx, [rel vfd_entries]
    mov r13d, VFD_N
.find:
    cmp dword [rbx+VFD_STATE], VFD_QUEUED
    je .take
    add rbx, VFD_SIZE
    dec r13d
    jnz .find
.empty:
    xor eax, eax
    jmp .out
.take:
    mov rdi, r12
    mov rsi, rbx
    mov ecx, 32
    rep movsq
    mov rdi, rbx
    mov ecx, 32
    xor eax, eax
    rep stosq
    mov dword [rbx+VFD_STATE], VFD_DISPATCHED
    mov eax, [rel vfd_worker_generation]
    mov [rbx+VFD_WORKER], eax
    mov eax, 256
    jmp .out
.bad:
    mov eax, -1
.out:
    VFD_LEAVE

vfy_delivery_still_valid:
    VFD_ENTER
    mov r12, rdi
    mov r13d, esi
    mov r14d, edx
    call vfd_tick
    test rax, rax
    jz .no
    mov rdi, r12
    call vfd_find
    test rax, rax
    jz .no
    mov rbx, rax
    cmp dword [rbx+VFD_STATE], VFD_DISPATCHED
    jne .no
    cmp dword [rbx+VFD_REASON], 0
    jne .no
    cmp [rbx+VFD_CID], r13d
    jne .no
    cmp [rbx+VFD_GEN], r14d
    jne .no
    mov eax, [rel vfd_worker_generation]
    cmp eax, [rbx+VFD_WORKER]
    jne .no
    mov edi, r13d
    call vfd_route_find
    test rax, rax
    jz .no
    cmp [rax+4], r14d
    jne .no
    mov edx, [rbx+VFD_CHANNEL]
    cmp [rax+8], edx
    jne .no
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    VFD_LEAVE

vfy_delivery_poll_cancel:
    VFD_ENTER
    mov r12, rdi
    test rdi, rdi
    jz .empty
    call vfd_tick
    lea rbx, [rel vfd_entries]
    mov ecx, VFD_N
.loop:
    test dword [rbx+VFD_FLAGS], 1
    jnz .copy
    add rbx, VFD_SIZE
    dec ecx
    jnz .loop
.empty:
    xor eax, eax
    jmp .out
.copy:
    mov rax, [rbx+VFD_ID]
    mov [r12], rax
    mov rax, [rbx+VFD_ID+8]
    mov [r12+8], rax
    and dword [rbx+VFD_FLAGS], ~1
    mov eax, 1
.out:
    VFD_LEAVE

vfy_delivery_cancel:
    VFD_ENTER
    call vfd_find
    test rax, rax
    jz .out
    mov rdi, rax
    mov esi, 1
    call vfd_cancel_entry
    mov eax, 1
.out:
    VFD_LEAVE

vfy_delivery_result:
    VFD_ENTER
    mov r12, rdi
    mov r13d, esi
    cmp r13d, 2
    ja .ignore
    call vfd_tick
    mov r14, rax
    mov rdi, r12
    call vfd_find
    test rax, rax
    jz .ignore
    mov rbx, rax
    cmp dword [rbx+VFD_WORKER], 0
    je .ignore                      ; a queued/cancelled-before-take ID is not a receipt
    test dword [rbx+VFD_FLAGS], 2
    jnz .duplicate
    or dword [rbx+VFD_FLAGS], 2
    mov [rbx+VFD_RESULT], r13d
    cmp dword [rbx+VFD_REASON], 0
    jne .late
    cmp dword [rbx+VFD_STATE], VFD_UNKNOWN
    je .late
    mov eax, [rel vfd_worker_generation]
    cmp [rbx+VFD_WORKER], eax
    jne .late
    mov dword [rbx+VFD_STATE], VFD_DONE
    jmp .expiry
.late:
    or dword [rbx+VFD_FLAGS], 4
.expiry:
    test r13d, r13d
    jnz .accepted
    test r14, r14
    jz .accepted
    cmp r14, [rbx+VFD_EXP]
    jb .accepted
    or dword [rbx+VFD_FLAGS], 8       ; receipt observed after expiry; send time unknown
.accepted:
    mov eax, 1
    jmp .out
.duplicate:
    cmp dword [rbx+VFD_DUPLICATES], -1
    je .ignore
    inc dword [rbx+VFD_DUPLICATES]
.ignore:
    xor eax, eax
.out:
    VFD_LEAVE

vfy_delivery_inspect:
    VFD_ENTER
    mov r12, rdi
    mov r13, rsi
    cmp rdx, 64
    jb .bad
    test r13, r13
    jz .bad
    mov rdi, r13
    xor eax, eax
    mov ecx, 8
    rep stosq
    call vfd_tick
    mov rdi, r12
    call vfd_find
    test rax, rax
    jz .bad
    lea rsi, [rax+VFD_ID]
    mov rdi, r13
    mov ecx, 8
    rep movsq
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    VFD_LEAVE

vfy_delivery_retire:
    VFD_ENTER
    mov r12, rdi
    call vfd_tick
    test rax, rax
    jz .no
    mov r13, rax
    mov rdi, r12
    call vfd_find
    test rax, rax
    jz .no
    cmp r13, [rax+VFD_EXP]
    jb .no
    test dword [rax+VFD_FLAGS], 1
    jnz .no
    mov rdi, rax
    xor eax, eax
    mov ecx, VFD_SIZE/8
    rep stosq
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    VFD_LEAVE

align 16
vfd_entries: times VFD_N*VFD_SIZE db 0
vfd_routes: times VFD_N*16 db 0
vfd_clock_floor: dq 0
vfd_worker_generation: dd 0
vfd_reserved: dd 0
