;; MODULE core/memory_budget
;; LAYER 1
;; EXPORTS mb_allocation_read, mb_pressure_poll, mb_guest_warm_begin, mb_guest_warm_retire, mb_guest_warm_end, mb_guest_warm_zero, mb_snapshot_zero, mb_snapshot_copy, mb_guest_control_copy, mb_guest_capture_begin, mb_guest_capture_end, mb_acquire, mb_acquire_bounded, mb_release, mb_cache_report, mb_cache_invalidate, mb_snapshot
;; IMPORTS boot/paging
;; CAPS
;; OWNER saga:core
;; LOCK: mb_lock PROTECTS mb_table, mb_next_token, mb_pressure_bytes, mb_pressure_align
; One shared physical span owner for cooperating post-EBS consumers. Only the
; successfully published, immutable final map is authority: boot/paging already
; validated descriptor nonoverlap before publishing it. EFI-allocated heaps,
; image and DMA storage are outside type7. This is not a reclaiming heap.
;
; All public calls preserve RBX/RBP/R12-R15. Volatile registers and flags may
; change. A short try-lock refuses busy; no callbacks, spinning or guest waits.
; No boot KAT or runtime caller is added here. Consumers must replace ALL their
; independent type7 scans with this ABI before shared ownership is established.
;
; A release is the caller's assertion that execution, translations, DMA and
; other users have quiesced. Snapshot storage must be scrubbed first. The next
; owner must initialize its storage before exposing it. Cache reports neither
; free physical RAM nor prove cache-free capture; callers own that protocol.
%include "core/abi/memory_budget.inc"

; Internal lock helper, preserving all argument registers except RAX/R10.
mb_try_lock:
    xor eax, eax
    mov r10d, 1
    lock cmpxchg [rel mb_lock], r10d
    jnz .busy
    xor eax, eax
    ret
.busy:
    mov eax, MB_E_BUSY
    ret

; Internal structural guard on the already-admitted map. R8=managed type7
; bytes in [4096,16GiB). Descriptors may be unordered. No map writes. The
; published map's nonoverlap is guaranteed by mmap_final_validate, not inferred
; from this sum. Bound matches the canonical 65536-byte final-map buffer.
mb_map:
    push rbx
    push r12
    push r13
    xor r8d, r8d
    mov rsi, [rel mmap_buffer]
    cmp rsi, 4096
    jb .bad
    mov rcx, [rel mmap_size]
    test rcx, rcx
    jz .bad
    cmp rcx, 65536
    ja .bad
    mov r12, rsi
    add r12, rcx
    jc .bad
    mov r13, MB_LIMIT
    cmp r12, r13
    ja .bad
    mov rbx, [rel mmap_desc_size]
    cmp rbx, 40
    jb .bad
    cmp rbx, 256
    ja .bad
    test bl, 7
    jnz .bad
    mov rax, rcx
    xor edx, edx
    div rbx
    test rdx, rdx
    jnz .bad
.row:
    mov r9, [rsi + 8]
    test r9d, 4095
    jnz .bad
    mov r10, [rsi + 24]
    test r10, r10
    jz .bad
    mov rax, r10
    shr rax, 52
    jnz .bad
    shl r10, 12
    add r10, r9
    jc .bad
    cmp dword [rsi], 7
    jne .next
    cmp r9, 4096
    jae .floor
    mov r9d, 4096
.floor:
    cmp r10, r13
    jbe .ceiling
    mov r10, r13
.ceiling:
    cmp r9, r10
    jae .next
    sub r10, r9
    add r8, r10
    jc .bad
    cmp r8, r13
    ja .bad
.next:
    add rsi, rbx
    cmp rsi, r12
    jb .row
    xor eax, eax
    jmp .out
.bad:
    xor r8d, r8d
    mov eax, MB_E_MAP
.out:
    pop r13
    pop r12
    pop rbx
    ret

; mb_acquire(RDI=owner,RSI=nonzero uint32 generation,RDX=kind,RCX=bytes,
;            R8=power-of-two alignment>=4096,R9=resident guest RAM subset)
; -> EAX=status, RDX=unique token,R8=base,R9=page-rounded bytes.
; Failure zeros token/base/bytes. One active owner+kind record is allowed,
; including across generations: a forgotten release cannot silently leak a
; previous guest and start another generation. Different owners share a table.
; Same arguments/results as mb_acquire, plus R10=trusted caller's byte ceiling
; for ALL live records of this owner, across kinds and generations. Charge the
; page-rounded request under mb_lock with admission/publication. A quota miss
; leaves ownership, token sequence and global physical-pressure demand intact.
; This bounds this request; callers must consistently use their policy ceiling.
; It does not configure system-wide policy or reclaim other consumers' storage.
mb_acquire_bounded:
    test r10, r10
    jz .bad_limit
    mov rax, MB_LIMIT
    cmp r10, rax
    jbe mb_acquire_common
.bad_limit:
    mov eax, MB_E_INPUT
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    ret

; Retained trusted-kernel entry, with no caller byte ceiling.
mb_acquire:
    xor r10d, r10d
mb_acquire_common:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov [rsp + 40], r9
    mov [rsp + 56], r10
    mov qword [rsp + 64], 0
    mov eax, MB_E_INPUT
    test rdi, rdi
    jz .out
    test rsi, rsi
    jz .out
    mov r10, rsi
    shr r10, 32
    jnz .out
    cmp rdx, MB_KIND_SPEED_RESERVE
    je .policy
    cmp rdx, MB_KIND_OPTIONAL_WORK
    je .optional
    cmp rdx, MB_KIND_OPTIONAL_STAGED
    je .optional
    cmp edx, MB_KIND_GUEST
    je .guest
    cmp rdx, MB_KIND_SNAPSHOT
    jne .out
    test r9, r9
    jnz .out
    jmp .size
.optional:
    cmp rdi, MB_OWNER_OPTIONAL_CPU
    jne .policy
    cmp qword [rsp + 56], 0            ; mb_acquire deliberately clears the ceiling
    je .policy
    test r9, r9
    jnz .out
    jmp .size
.guest:
    cmp rdx, MB_KIND_GUEST
    jne .out
    test r9, r9
    jz .out
    cmp r9, rcx
    ja .out
.size:
    test rcx, rcx
    jz .out
    add rcx, 4095
    jc .out
    and rcx, -4096
    mov r10, MB_LIMIT
    cmp rcx, r10
    ja .out
    mov [rsp + 24], rcx
    cmp r8, 4096
    jb .out
    cmp r8, r10
    ja .out
    lea r10, [r8 - 1]
    test r8, r10
    jnz .out
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_map
    test eax, eax
    jnz .unlock
    mov qword [rsp + 48], 0
    lea r11, [rel mb_table]
    mov ecx, MB_RECORDS
.slot:
    cmp qword [r11 + MB_REC_TOKEN], 0
    je .free
    mov rax, [rsp]
    cmp [r11 + MB_REC_OWNER], rax
    jne .slot_next
    mov rax, [r11 + MB_REC_BYTES]
    add [rsp + 64], rax
    mov rax, [rsp + 16]
    cmp [r11 + MB_REC_KIND], rax
    jne .slot_next
    mov eax, MB_E_DUPLICATE
    jmp .unlock
.free:
    cmp qword [rsp + 48], 0
    jne .slot_next
    mov [rsp + 48], r11
.slot_next:
    add r11, MB_REC_SIZE
    dec ecx
    jnz .slot
    mov eax, MB_E_FULL
    cmp qword [rsp + 48], 0
    je .unlock
    mov eax, MB_E_TOKEN
    cmp qword [rel mb_next_token], -1
    je .unlock
    mov rax, [rsp + 56]
    test rax, rax
    jz .fit
    sub rax, [rsp + 64]
    jc .quota
    cmp [rsp + 24], rax
    ja .quota
.fit:
    mov rdi, [rsp + 24]
    mov rsi, [rsp + 32]
    call mb_fit
    test eax, eax
    jz .found
    ; Only an otherwise-valid physical-capacity miss is pressure. Publish
    ; conservative geometry while holding the same short ownership lock;
    ; never invoke the consumer or wait for retirement on this path.
    mov rax, [rsp + 24]
    cmp rax, [rel mb_pressure_bytes]
    jbe .pressure_align
    mov [rel mb_pressure_bytes], rax
.pressure_align:
    mov rax, [rsp + 32]
    cmp rax, [rel mb_pressure_align]
    jbe .pressure_done
    mov [rel mb_pressure_align], rax
.pressure_done:
    mov eax, MB_E_CAPACITY
    jmp .unlock
.quota:
    mov eax, MB_E_QUOTA
    jmp .unlock
.found:
    ; A successful retry satisfying the entire conservative demand is actual
    ; recovery too. Do not require a second free copy of its now-owned span.
    cmp r15, [rel mb_pressure_bytes]
    jb .publish
    mov rax, [rsp + 32]
    cmp rax, [rel mb_pressure_align]
    jb .publish
    mov qword [rel mb_pressure_bytes], 0
    mov qword [rel mb_pressure_align], 0
.publish:
    mov r11, [rsp + 48]
    mov rax, [rsp]
    mov [r11 + MB_REC_OWNER], rax
    mov rax, [rsp + 8]
    mov [r11 + MB_REC_GEN], rax
    mov rax, [rsp + 16]
    mov [r11 + MB_REC_KIND], rax
    mov [r11 + MB_REC_BASE], r12
    mov [r11 + MB_REC_BYTES], r15
    mov rax, [rsp + 40]
    mov [r11 + MB_REC_RESIDENT], rax
    mov qword [r11 + MB_REC_CACHE], 0
    mov qword [r11 + MB_REC_DIRTY], 0
    mov qword [r11 + MB_REC_SERIAL], 0
    mov qword [r11 + MB_REC_KNOWN], 0
    mov qword [r11 + MB_REC_PENDING], 0
    mov qword [r11 + MB_REC_WARM_SERIAL], 0
    mov qword [r11 + MB_REC_WARM_STATE], 0
    mov qword [r11 + MB_REC_CAPTURE], 0
    mov qword [r11 + MB_REC_CAPTURE_SERIAL], 0
    inc qword [rel mb_next_token]
    mov rdx, [rel mb_next_token]
    mov [r11 + MB_REC_TOKEN], rdx
    mov r8, r12
    mov r9, r15
    xor eax, eax
.unlock:
    mov dword [rel mb_lock], 0
    jmp .out
.policy:
    ; The real warm worker uses guest kind1 RAM, never a second kind3 span.
    ; Native physical reserve has no configured reclaimable consumer. The
    ; existing BOOT gate alone cannot grant physical ownership.
    mov eax, MB_E_POLICY
.out:
    test eax, eax
    jz .return
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
.return:
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Internal non-mutating first fit. Lock held and mb_map already validated.
; RDI=rounded bytes, RSI=alignment; EAX=status, R12=base on success.
; Clobbers volatile registers and RBX/RBP/R12-R15. Every collision advances
; past a live span; map and table have the same fixed bounds as mb_acquire.
mb_fit:
    mov r15, rdi
    mov r9, rsi
    mov rbx, [rel mmap_buffer]
    mov rbp, [rel mmap_size]
    mov r14, [rel mmap_desc_size]
.descriptor:
    cmp dword [rbx], 7
    jne .next
    mov r12, [rbx + 8]
    mov r13, [rbx + 24]
    shl r13, 12
    add r13, r12
    mov r10, MB_LIMIT
    cmp r13, r10
    jbe .end
    mov r13, r10
.end:
    cmp r12, 4096
    jae .align
    mov r12d, 4096
.align:
    mov r10, r9
    lea rax, [r10 - 1]
    add r12, rax
    jc .next
    neg r10
    and r12, r10
.try:
    mov rdx, r12
    add rdx, r15
    jc .next
    cmp rdx, r13
    ja .next
    lea r11, [rel mb_table]
    mov ecx, MB_RECORDS
.collision:
    cmp qword [r11 + MB_REC_TOKEN], 0
    je .collision_next
    cmp rdx, [r11 + MB_REC_BASE]
    jbe .collision_next
    mov r10, [r11 + MB_REC_BASE]
    add r10, [r11 + MB_REC_BYTES]
    cmp r12, r10
    jae .collision_next
    mov r12, r10
    jmp .align                       ; restart against every span after advance
.collision_next:
    add r11, MB_REC_SIZE
    dec ecx
    jnz .collision
    xor eax, eax
    ret
.next:
    add rbx, r14
    sub rbp, r14
    jnz .descriptor
    mov eax, MB_E_CAPACITY
    ret

; BSP/stopped-vCPU service readout for native warm retirement. No arguments.
; EAX=MB_OK, EDX=current physical-pressure level (0/1). On busy/map error,
; EAX!=0 and EDX=1: conservatively assert pressure, never infer a clear.
; Only a true capacity miss sets demand. A later poll clears it only if the
; maximum pending rounded size AND alignment fit the live physical table.
; An actual allocation satisfying that geometry also clears demand. A smaller
; allocation, cache report, STOP reply, warm End or failed release cannot.
; A poll never allocates, releases or calls VM.
; The consumer applies LEVEL CHANGES at its serialized service boundary; do
; not repeatedly call hvw_pressure(0), which restarts the warm idle interval.
mb_pressure_poll:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov edx, 1
    call mb_try_lock
    test eax, eax
    jnz .out
    cmp qword [rel mb_pressure_bytes], 0
    je .clear
    call mb_map
    test eax, eax
    jnz .unknown
    mov rdi, [rel mb_pressure_bytes]
    mov rsi, [rel mb_pressure_align]
    call mb_fit
    test eax, eax
    jz .clear
    xor eax, eax
    mov edx, 1
    jmp .unlock
.clear:
    mov qword [rel mb_pressure_bytes], 0
    mov qword [rel mb_pressure_align], 0
    xor eax, eax
    xor edx, edx
    jmp .unlock
.unknown:
    mov edx, 1
.unlock:
    mov dword [rel mb_lock], 0
.out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Internal exact-key lookup, lock held. RDI owner,RSI generation,RDX token.
; R11=record on success; never accepts a cached address as an ownership key.
mb_find:
    test rdx, rdx
    jz .bad
    lea r11, [rel mb_table]
    mov r10d, MB_RECORDS
.row:
    cmp [r11 + MB_REC_TOKEN], rdx
    jne .next
    cmp [r11 + MB_REC_OWNER], rdi
    jne .bad
    cmp [r11 + MB_REC_GEN], rsi
    jne .bad
    xor eax, eax
    ret
.next:
    add r11, MB_REC_SIZE
    dec r10d
    jnz .row
.bad:
    mov eax, MB_E_STALE
    ret

; RDI=owner, RSI=generation, RDX=token, RCX=trusted native output,
; R8=MB_ALLOCATION_BYTES. Copy only the allocation geometry, under its lock.
; No map scan, lifetime operation or storage access; refusal leaves output
; untouched. A caller must still join its own execution/START observations.
mb_allocation_read:
    push rbx
    mov rbx, rcx
    mov eax, MB_E_INPUT
    test rbx, rbx
    jz .out
    cmp r8, MB_ALLOCATION_BYTES
    jne .out
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_find
    test eax, eax
    jnz .unlock
    mov rsi, r11
    mov rdi, rbx
    mov ecx, MB_ALLOCATION_BYTES / 8
    cld
    rep movsq
    xor eax, eax
.unlock:
    mov dword [rel mb_lock], 0
.out:
    pop rbx
    ret

; Exact-key release after caller quiescence. Token counter is never reset.
mb_release:
    sub rsp, 8
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_find
    test eax, eax
    jnz .unlock
    mov eax, MB_E_STATE
    cmp qword [r11 + MB_REC_WARM_STATE], 0
    jne .unlock
    cmp qword [r11 + MB_REC_CAPTURE], 0
    jne .unlock
    xor eax, eax
    mov ecx, MB_REC_SIZE / 8
.clear:
    mov qword [r11], 0
    add r11, 8
    dec ecx
    jnz .clear
.unlock:
    mov dword [rel mb_lock], 0
.out:
    add rsp, 8
    ret

; Open one fresh cache-report request: exact key plus RCX=request serial.
; Serial is caller-owned, nonzero and strictly increasing for this token.
mb_cache_invalidate:
    sub rsp, 8
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_find
    test eax, eax
    jnz .unlock
    mov eax, MB_E_STATE
    cmp qword [r11 + MB_REC_WARM_STATE], MB_WARM_RETIRING
    je .unlock
    cmp qword [r11 + MB_REC_CAPTURE], 0
    jne .unlock
    mov eax, MB_E_REPORT
    cmp qword [r11 + MB_REC_KIND], MB_KIND_GUEST
    jne .unlock
    cmp rcx, [r11 + MB_REC_SERIAL]
    jbe .unlock
    mov [r11 + MB_REC_SERIAL], rcx
    mov qword [r11 + MB_REC_KNOWN], 0
    mov qword [r11 + MB_REC_PENDING], 1
    xor eax, eax
.unlock:
    mov dword [rel mb_lock], 0
.out:
    add rsp, 8
    ret

; Consume one pending report: exact key,RCX=request serial,R8=cache,R9=dirty.
; VM validates actual channel/generation and converts bounded guest units first.
; Unknown and pending are explicit; telemetry never changes physical ownership.
mb_cache_report:
    sub rsp, 8
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_find
    test eax, eax
    jnz .unlock
    mov eax, MB_E_STATE
    cmp qword [r11 + MB_REC_WARM_STATE], MB_WARM_RETIRING
    je .unlock
    cmp qword [r11 + MB_REC_CAPTURE], 0
    jne .unlock
    mov eax, MB_E_REPORT
    cmp qword [r11 + MB_REC_PENDING], 1
    jne .unlock
    cmp rcx, [r11 + MB_REC_SERIAL]
    jne .unlock
    cmp r8, [r11 + MB_REC_RESIDENT]
    ja .unlock
    cmp r9, r8
    ja .unlock
    mov [r11 + MB_REC_CACHE], r8
    mov [r11 + MB_REC_DIRTY], r9
    mov qword [r11 + MB_REC_KNOWN], 1
    mov qword [r11 + MB_REC_PENDING], 0
    xor eax, eax
.unlock:
    mov dword [rel mb_lock], 0
.out:
    add rsp, 8
    ret

; Guest warm lifecycle: exact physical key in RDI/RSI/RDX, nonzero monotonic
; request serial in RCX. These are trusted kernel calls, never guest authority.
; VM must check the real BOOT idle gate and grant generation BEFORE begin and
; publish the grant only after success. Begin/retire/capture linearize on the
; same short lock as allocation/release. No callback, waiting or guest work is
; performed under the lock. RSS and cache stay subsets of resident kind1 RAM.
;
; Begin admits one warm lifetime. Retire fences LOAD/RUN and late cache replies;
; it does NOT return physical credit. End requires the VM's actual execution,
; reader and DMA quiescence plus unmapping/scrubbing/exclusion of warm/model/cache
; pages. A process exit or DROP reply alone cannot authorize End. Only a later
; exact mb_release, after all other VM users stop, returns the physical span.
; Serial high-water marks survive End; old grants cannot restart the lifetime.
mb_guest_warm_begin:
    sub rsp, 8
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_find
    test eax, eax
    jnz .unlock
    mov eax, MB_E_STATE
    cmp qword [r11 + MB_REC_KIND], MB_KIND_GUEST
    jne .unlock
    cmp qword [r11 + MB_REC_WARM_STATE], 0
    jne .unlock
    cmp qword [r11 + MB_REC_CAPTURE], 0
    jne .unlock
    cmp rcx, [r11 + MB_REC_WARM_SERIAL]
    jbe .unlock
    mov [r11 + MB_REC_WARM_SERIAL], rcx
    mov qword [r11 + MB_REC_WARM_STATE], MB_WARM_ACTIVE
    call mb_cache_forget
    xor eax, eax
.unlock:
    mov dword [rel mb_lock], 0
.out:
    add rsp, 8
    ret

mb_guest_warm_retire:
    sub rsp, 8
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_find
    test eax, eax
    jnz .unlock
    mov eax, MB_E_STATE
    test rcx, rcx
    jz .unlock
    cmp rcx, [r11 + MB_REC_WARM_SERIAL]
    jne .unlock
    cmp qword [r11 + MB_REC_WARM_STATE], MB_WARM_ACTIVE
    je .retire
    cmp qword [r11 + MB_REC_WARM_STATE], MB_WARM_RETIRING
    jne .unlock
    xor eax, eax                           ; same revoke is idempotent
    jmp .unlock
.retire:
    mov qword [r11 + MB_REC_WARM_STATE], MB_WARM_RETIRING
    call mb_cache_forget
    xor eax, eax
.unlock:
    mov dword [rel mb_lock], 0
.out:
    add rsp, 8
    ret

; Clear only a live exact warm allocation, under the allocation/release lock.
; RDI/RSI/RDX = owner/generation/token, RCX = nonzero warm serial.
; R8 = trusted native pointer to four qwords: expected base, expected capacity,
; offset, length. No guest pointer is admitted here. Actual record geometry is
; authoritative; cached geometry must match it exactly. Writes are bounded to
; MB_WARM_ZERO_MAX and require ACTIVE/RETIRING, with capture excluded. Length0
; validates only the complete extent (offset=capacity), including End/release
; retry after state0. It neither certifies prior writes nor replaces quiescence.
; No returned raw pointer, callbacks, waits or nested allocator calls while held.
mb_guest_warm_zero:
    push rbx
    mov rbx, r8
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_find
    test eax, eax
    jnz .unlock
    mov eax, MB_E_STATE
    cmp qword [r11 + MB_REC_KIND], MB_KIND_GUEST
    jne .unlock
    test rcx, rcx
    jz .unlock
    cmp rcx, [r11 + MB_REC_WARM_SERIAL]
    jne .unlock
    cmp qword [r11 + MB_REC_CAPTURE], 0
    jne .unlock
    cmp qword [r11 + MB_REC_WARM_STATE], MB_WARM_RETIRING
    ja .unlock
    mov eax, MB_E_INPUT
    test rbx, rbx
    jz .unlock
    mov r8, [r11 + MB_REC_BASE]
    mov r9, [r11 + MB_REC_BYTES]
    cmp r8, [rbx]
    jne .unlock
    cmp r9, [rbx + 8]
    jne .unlock
    cmp r8, 4096
    jb .unlock
    test r8, 4095
    jnz .unlock
    test r9, r9
    jz .unlock
    test r9, 4095
    jnz .unlock
    mov r10, r8
    add r10, r9
    jc .unlock
    mov rdx, MB_LIMIT
    cmp r10, rdx
    ja .unlock
    mov r10, [rbx + 16]
    mov rdx, [rbx + 24]
    cmp rdx, MB_WARM_ZERO_MAX
    ja .unlock
    add r10, rdx
    jc .unlock
    cmp r10, r9
    ja .unlock
    test rdx, rdx
    jnz .write
    cmp r10, r9                            ; only complete-span final validation
    jne .unlock
    xor eax, eax
    jmp .unlock
.write:
    mov eax, MB_E_STATE
    cmp qword [r11 + MB_REC_WARM_STATE], MB_WARM_ACTIVE
    jb .unlock
    mov rdi, r8
    add rdi, [rbx + 16]                    ; actual record base, checked offset
    mov rcx, rdx
    xor eax, eax
    cld
    rep stosb
    mfence                                ; publish completion before unlock
.unlock:
    mov dword [rel mb_lock], 0
.out:
    pop rbx
    ret

; Snapshot DISCARD clear, after the native caller excludes capture/resume.
; RDI/RSI/RDX=owner/generation/token, RCX=trusted four-qword descriptor:
; expected base, capacity, offset, length. Exact live snapshot ownership and
; geometry are checked under the same lock as release, before any write.
; At most 1 MiB per call; no callbacks, yields or returned raw pointers.
; Length0 accepts only offset=capacity for final validation before release.
; This does not prove prior clearing or replace the caller's reader custody.
mb_snapshot_zero:
    push rbx
    mov rbx, rcx
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_find
    test eax, eax
    jnz .unlock
    mov eax, MB_E_STATE
    cmp rdi, MB_OWNER_GUESTSNAP
    jne .unlock
    cmp qword [r11 + MB_REC_KIND], MB_KIND_SNAPSHOT
    jne .unlock
    cmp qword [r11 + MB_REC_WARM_STATE], 0
    jne .unlock
    cmp qword [r11 + MB_REC_CAPTURE], 0
    jne .unlock
    mov eax, MB_E_INPUT
    test rbx, rbx
    jz .unlock
    mov r8, [r11 + MB_REC_BASE]
    mov r9, [r11 + MB_REC_BYTES]
    cmp r8, [rbx]
    jne .unlock
    cmp r9, [rbx + 8]
    jne .unlock
    cmp r8, 4096
    jb .unlock
    test r8, 4095
    jnz .unlock
    test r9, r9
    jz .unlock
    test r9, 4095
    jnz .unlock
    mov r10, r8
    add r10, r9
    jc .unlock
    mov rdx, MB_LIMIT
    cmp r10, rdx
    ja .unlock
    mov r10, [rbx + 16]
    mov rdx, [rbx + 24]
    cmp rdx, MB_SNAPSHOT_ZERO_MAX
    ja .unlock
    add r10, rdx
    jc .unlock
    cmp r10, r9
    ja .unlock
    test rdx, rdx
    jnz .write
    cmp r10, r9
    jne .unlock
    xor eax, eax
    jmp .unlock
.write:
    mov rdi, r8
    add rdi, [rbx + 16]
    mov rcx, rdx
    xor eax, eax
    cld
    rep stosb
    mfence
.unlock:
    mov dword [rel mb_lock], 0
.out:
    pop rbx
    ret

; RDI=trusted MB_COPY_SIZE descriptor; EAX=status. Join both exact live keys,
; kinds and cached geometry under the same lock as release and the real copy.
; Native caller retains stopped-vCPU/reader custody across chunks, without
; yielding. A successful check alone is never returned as pointer authority.
; Length0 validates only offset=RAM_BYTES, including final completion/retry.
mb_snapshot_copy:
    push rbx
    push r12
    mov rbx, rdi
    mov eax, MB_E_INPUT
    test rbx, rbx
    jz .out
    call mb_try_lock
    test eax, eax
    jnz .out
    mov edi, MB_OWNER_HV_LINUX
    mov rsi, [rbx + MB_COPY_GUEST_GEN]
    mov rdx, [rbx + MB_COPY_GUEST_TOKEN]
    call mb_find
    test eax, eax
    jnz .unlock
    mov r12, r11
    mov edi, MB_OWNER_GUESTSNAP
    mov rsi, [rbx + MB_COPY_SNAP_GEN]
    mov rdx, [rbx + MB_COPY_SNAP_TOKEN]
    call mb_find
    test eax, eax
    jnz .unlock
    mov eax, MB_E_STATE
    cmp qword [r12 + MB_REC_KIND], MB_KIND_GUEST
    jne .unlock
    cmp qword [r11 + MB_REC_KIND], MB_KIND_SNAPSHOT
    jne .unlock
    cmp qword [r12 + MB_REC_WARM_STATE], 0
    jne .unlock
    cmp qword [r11 + MB_REC_WARM_STATE], 0
    jne .unlock
    cmp qword [r11 + MB_REC_CAPTURE], 0
    jne .unlock
    cmp qword [rbx + MB_COPY_DIRECTION], 0
    jne .restore
    cmp qword [r12 + MB_REC_CAPTURE], 1
    jne .unlock
    mov rcx, [rbx + MB_COPY_SERIAL]
    test rcx, rcx
    jz .unlock
    cmp rcx, [r12 + MB_REC_CAPTURE_SERIAL]
    jne .unlock
    jmp .geometry
.restore:
    cmp qword [rbx + MB_COPY_DIRECTION], 1
    jne .unlock
    cmp qword [r12 + MB_REC_CAPTURE], 0
    jne .unlock
    cmp qword [rbx + MB_COPY_SERIAL], 0
    jne .unlock
.geometry:
    mov eax, MB_E_INPUT
    mov r8, [r12 + MB_REC_BASE]
    cmp r8, [rbx + MB_COPY_GUEST_BASE]
    jne .unlock
    mov rcx, [r12 + MB_REC_BYTES]
    cmp rcx, [rbx + MB_COPY_GUEST_CAPACITY]
    jne .unlock
    test rcx, rcx
    jz .unlock
    mov r9, r8
    add r9, rcx
    jc .unlock
    mov rcx, MB_LIMIT
    cmp r9, rcx
    ja .unlock
    mov rsi, [rbx + MB_COPY_GUEST_RAM]
    cmp rsi, r8
    jb .unlock
    mov rcx, [rbx + MB_COPY_RAM_BYTES]
    test rcx, rcx
    jz .unlock
    cmp rcx, [r12 + MB_REC_RESIDENT]
    jne .unlock
    mov rdx, rsi
    add rdx, rcx
    jc .unlock
    cmp rdx, r9
    ja .unlock
    mov rdi, [r11 + MB_REC_BASE]
    cmp rdi, [rbx + MB_COPY_SNAP_BASE]
    jne .unlock
    mov r10, [r11 + MB_REC_BYTES]
    cmp r10, [rbx + MB_COPY_SNAP_CAPACITY]
    jne .unlock
    cmp rcx, r10
    ja .unlock
    add r10, rdi
    jc .unlock
    mov rdx, MB_LIMIT
    cmp r10, rdx
    ja .unlock
    ; Physical owners must remain disjoint; never alias a snapshot into the
    ; guest control/RAM/framebuffer record, even on a corrupt cached receipt.
    cmp rdi, r9
    jae .extent
    cmp r10, r8
    ja .unlock
.extent:
    mov r8, [rbx + MB_COPY_OFFSET]
    mov r9, [rbx + MB_COPY_LENGTH]
    cmp r9, MB_SNAPSHOT_COPY_MAX
    ja .unlock
    mov r10, r8
    add r10, r9
    jc .unlock
    cmp r10, rcx
    ja .unlock
    test r9, r9
    jnz .copy
    cmp r10, rcx
    jne .unlock
    xor eax, eax
    jmp .unlock
.copy:
    add rsi, r8
    add rdi, r8
    cmp qword [rbx + MB_COPY_DIRECTION], 0
    je .write
    xchg rsi, rdi
.write:
    mov rcx, r9
    cld
    rep movsb
    mfence
    xor eax, eax
.unlock:
    mov dword [rel mb_lock], 0
.out:
    pop r12
    pop rbx
    ret

; RDI=trusted MB_CONTROL_SIZE descriptor, EAX=status. The native caller owns
; HOST (a static snapshot page), the selected offset and stopped-vCPU custody.
; Never lend an unchecked guest pointer: read/write one whole control page
; while the exact live allocation and capture/warm exclusion remain locked.
mb_guest_control_copy:
    push rbx
    mov rbx, rdi
    mov eax, MB_E_INPUT
    test rbx, rbx
    jz .out
    call mb_try_lock
    test eax, eax
    jnz .out
    mov edi, MB_OWNER_HV_LINUX
    mov rsi, [rbx + MB_CONTROL_GEN]
    mov rdx, [rbx + MB_CONTROL_TOKEN]
    call mb_find
    test eax, eax
    jnz .unlock
    mov eax, MB_E_STATE
    cmp qword [r11 + MB_REC_KIND], MB_KIND_GUEST
    jne .unlock
    cmp qword [r11 + MB_REC_WARM_STATE], 0
    jne .unlock
    cmp qword [rbx + MB_CONTROL_DIRECTION], 0
    jne .restore
    cmp qword [r11 + MB_REC_CAPTURE], 1
    jne .unlock
    mov rcx, [rbx + MB_CONTROL_SERIAL]
    test rcx, rcx
    jz .unlock
    cmp rcx, [r11 + MB_REC_CAPTURE_SERIAL]
    jne .unlock
    jmp .geometry
.restore:
    cmp qword [rbx + MB_CONTROL_DIRECTION], 1
    jne .unlock
    cmp qword [r11 + MB_REC_CAPTURE], 0
    jne .unlock
    cmp qword [rbx + MB_CONTROL_SERIAL], 0
    jne .unlock
.geometry:
    mov eax, MB_E_INPUT
    mov r8, [r11 + MB_REC_BASE]
    cmp r8, [rbx + MB_CONTROL_BASE]
    jne .unlock
    mov rcx, [r11 + MB_REC_BYTES]
    cmp rcx, [rbx + MB_CONTROL_CAPACITY]
    jne .unlock
    test rcx, rcx
    jz .unlock
    mov r9, r8
    add r9, rcx
    jc .unlock
    mov rdx, MB_LIMIT
    cmp r9, rdx
    ja .unlock
    mov r10, [rbx + MB_CONTROL_RAM]
    cmp r10, r8
    jbe .unlock
    mov rcx, [rbx + MB_CONTROL_RAM_BYTES]
    test rcx, rcx
    jz .unlock
    cmp rcx, [r11 + MB_REC_RESIDENT]
    jne .unlock
    mov rdx, r10
    add rdx, rcx
    jc .unlock
    cmp rdx, r9
    ja .unlock
    mov rsi, [rbx + MB_CONTROL_OFFSET]
    test rsi, MB_CONTROL_PAGE_BYTES - 1
    jnz .unlock
    add rsi, r8
    jc .unlock
    mov rdx, rsi
    add rdx, MB_CONTROL_PAGE_BYTES
    jc .unlock
    cmp rdx, r10                         ; entirely inside the control prefix
    ja .unlock
    mov rdi, [rbx + MB_CONTROL_HOST]
    test rdi, rdi
    jz .unlock
    mov rdx, rdi
    add rdx, MB_CONTROL_PAGE_BYTES
    jc .unlock
    ; A corrupt native descriptor must never alias its host page into guest
    ; control/RAM/framebuffer storage. Native HOST provenance is caller-owned.
    cmp rdi, r9
    jae .copy
    cmp rdx, r8
    ja .unlock
.copy:
    cmp qword [rbx + MB_CONTROL_DIRECTION], 0
    je .write
    xchg rsi, rdi
.write:
    mov ecx, MB_CONTROL_PAGE_BYTES
    cld
    rep movsb
    mfence
    xor eax, eax
.unlock:
    mov dword [rel mb_lock], 0
.out:
    pop rbx
    ret

mb_guest_warm_end:
    sub rsp, 8
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_find
    test eax, eax
    jnz .unlock
    mov eax, MB_E_STATE
    test rcx, rcx
    jz .unlock
    cmp rcx, [r11 + MB_REC_WARM_SERIAL]
    jne .unlock
    cmp qword [r11 + MB_REC_WARM_STATE], MB_WARM_RETIRING
    jne .unlock
    mov qword [r11 + MB_REC_WARM_STATE], 0
    xor eax, eax
.unlock:
    mov dword [rel mb_lock], 0
.out:
    add rsp, 8
    ret

; Hold exclusion across the entire real guest RAM copy, not merely a precheck.
; Warm begin and physical release refuse while held. Capture refuses a live or
; retiring warm lifetime, so the caller retries after real VM retirement. These
; calls do not promise to drop unrelated Linux cache; the warm End contract is
; the trusted exclusion seam for this consumer. Capture serials are independent
; of warm/report serials and are never reused within an allocation token.
mb_guest_capture_begin:
    sub rsp, 8
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_find
    test eax, eax
    jnz .unlock
    mov eax, MB_E_STATE
    cmp qword [r11 + MB_REC_KIND], MB_KIND_GUEST
    jne .unlock
    cmp qword [r11 + MB_REC_WARM_STATE], 0
    jne .unlock
    cmp qword [r11 + MB_REC_CAPTURE], 0
    jne .unlock
    cmp rcx, [r11 + MB_REC_CAPTURE_SERIAL]
    jbe .unlock
    mov [r11 + MB_REC_CAPTURE_SERIAL], rcx
    mov qword [r11 + MB_REC_CAPTURE], 1
    call mb_cache_forget
    xor eax, eax
.unlock:
    mov dword [rel mb_lock], 0
.out:
    add rsp, 8
    ret

mb_guest_capture_end:
    sub rsp, 8
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_find
    test eax, eax
    jnz .unlock
    mov eax, MB_E_STATE
    test rcx, rcx
    jz .unlock
    cmp rcx, [r11 + MB_REC_CAPTURE_SERIAL]
    jne .unlock
    cmp qword [r11 + MB_REC_CAPTURE], 1
    jne .unlock
    mov qword [r11 + MB_REC_CAPTURE], 0
    xor eax, eax
.unlock:
    mov dword [rel mb_lock], 0
.out:
    add rsp, 8
    ret

; Internal, record lock held. Preserve report serial high-water mark so a late
; reply cannot become fresh after retirement, a new warm grant or capture.
mb_cache_forget:
    mov qword [r11 + MB_REC_CACHE], 0
    mov qword [r11 + MB_REC_DIRTY], 0
    mov qword [r11 + MB_REC_KNOWN], 0
    mov qword [r11 + MB_REC_PENDING], 0
    ret

; mb_snapshot(RDI=trusted kernel buffer,MB_SUM_SIZE bytes)->EAX=status.
; On refusal output is untouched. Managed/unclaimed refers ONLY to this type7
; physical allocator, not whole-system free heap. Reported cache is a subset of
; guest resident RAM, as of the last confirmed reply; never add it to claimed.
mb_snapshot:
    push rbx
    push r12
    sub rsp, MB_SUM_SIZE
    mov rbx, rdi
    mov eax, MB_E_INPUT
    test rbx, rbx
    jz .out
    call mb_try_lock
    test eax, eax
    jnz .out
    call mb_map
    test eax, eax
    jnz .unlock
    mov rdi, rsp
    xor eax, eax
    mov ecx, MB_SUM_SIZE / 8
    cld
    rep stosq
    mov qword [rsp + MB_SUM_SCHEMA], 1
    mov [rsp + MB_SUM_MANAGED], r8
    lea r11, [rel mb_table]
    mov r12d, MB_RECORDS
.row:
    cmp qword [r11 + MB_REC_TOKEN], 0
    je .next
    inc qword [rsp + MB_SUM_RECORDS]
    mov rax, [r11 + MB_REC_BYTES]
    add [rsp + MB_SUM_CLAIMED], rax
    jc .bad
    cmp qword [r11 + MB_REC_KIND], MB_KIND_SNAPSHOT
    je .snap
    cmp qword [r11 + MB_REC_KIND], MB_KIND_GUEST
    jne .next                         ; optional CPU storage has no guest/cache subset
    mov rax, [r11 + MB_REC_RESIDENT]
    add [rsp + MB_SUM_GUEST_RAM], rax
    jc .bad
    cmp qword [r11 + MB_REC_KNOWN], 1
    jne .unknown
    inc qword [rsp + MB_SUM_CACHE_KNOWN]
    mov rax, [r11 + MB_REC_CACHE]
    add [rsp + MB_SUM_REPORTED_CACHE], rax
    jc .bad
    jmp .pending
.unknown:
    inc qword [rsp + MB_SUM_CACHE_UNKNOWN]
.pending:
    cmp qword [r11 + MB_REC_PENDING], 1
    jne .next
    inc qword [rsp + MB_SUM_PENDING]
    jmp .next
.snap:
    add [rsp + MB_SUM_SNAPSHOT], rax
    jc .bad
.next:
    add r11, MB_REC_SIZE
    dec r12d
    jnz .row
    mov rax, [rsp + MB_SUM_MANAGED]
    sub rax, [rsp + MB_SUM_CLAIMED]
    jc .bad
    mov [rsp + MB_SUM_UNCLAIMED], rax
    mov rsi, rsp
    mov rdi, rbx
    mov ecx, MB_SUM_SIZE / 8
    rep movsq
    xor eax, eax
    jmp .unlock
.bad:
    mov eax, MB_E_STATE
.unlock:
    mov dword [rel mb_lock], 0
.out:
    add rsp, MB_SUM_SIZE
    pop r12
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_core_memory_budget 0
mb_lock: dd 0
    align 8, db 0
mb_next_token: dq 0
mb_pressure_bytes: dq 0
mb_pressure_align: dq 0
mb_table: times MB_REC_SIZE * MB_RECORDS db 0
%endmacro
WDATA_DEFER WDATA_core_memory_budget
