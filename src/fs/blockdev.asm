;; MODULE fs/blockdev
;; LAYER 4
;; EXPORTS blk_write_dispatches, blk_write_dispatch_wrapped, blk_registered_at, blk_storage_identity, blk_members_snapshot, blk_census_snapshot_v2, blk_census_snapshot, blk_init, blk_register, blk_deregister, blk_select, blk_find_named, blk_iter_after, blk_iter_all_after, blk_find_prefix_after, blk_validate_range, blk_read, blk_write, blk_write_owned, blk_flush, blk_flush_failures, blk_identify, blk_reinit, blk_selftest, blk_registered_count, persist_gap_lock_acquire, persist_gap_lock_release
;; IMPORTS dev/blk/ahci, dev/blk/nvme, dev/blk/usb_msd, dev/blk/ramblk, dev/blk/nullblk, boot/serial, core/heap, core/lock, dev/blk/vmd, fs/storage_access, dev/usb/xhci, fs/guest_volume
;; CAPS
;; OWNER saga:storage
;; CONTEXT: bsp_only  (RCQ-21 SA2a: blk_write_owned admission must not race the backend dispatch)
;; LOCK: persist_gap_lock PROTECTS persist_gap_epoch, PERSIST_GAP_LBA_PRIMARY, PERSIST_GAP_LBA_TMP
;; LOCK: blk_registry_lock PROTECTS blk_registry_head, blk_media_generation_next
; ============================================================================
; fs/blockdev.asm — the L4 BLOCK-device class core (C7/1007). The storage analog
; of net/netdev.asm: the shared blk_ops seam (identify/read/write/flush), the
; N-ary backend REGISTRY (ordered by .prio), highest-priority-HEALTHY SELECTION,
; a backend-agnostic DISPATCH (the same code routes to ramblk today and to
; nvme/ahci the moment their bus layer is wired — NO core edit to add a backend:
; that invariance IS the seam test), and the REINIT CONTRACT (RESILIENCE.md §2/3:
; idempotent re-runnable init via identify(), quiesce via flush(), and — the part
; that matters — VERIFY-AFTER via a post-reinit liveness read, so "reinit done"
; means the device actually works again, not that init merely returned).
;
; The class ships a FAKE backend (dev/blk/ramblk.asm) that is BOTH the QEMU-no-
; hardware regression target AND the reference implementation of blk_ops
; (DRIVER_MODEL §7). blk_selftest below is content-graded: it drives real
; write/read round-trips through the DISPATCH and prints FNV-1a sector checksums
; a stub cannot fake (known-answer table lives in the probe).
;
; The L3-backend -> blk_register upward call is the ONE sanctioned upward edge
; (DRIVER_MODEL §5); modlint whitelists it for dev/blk/ backends.
; ============================================================================

BLK_REGISTRY_LIMIT equ 64

; Read-only lifetime observation; never reset by a request. Overflow is sticky.
%macro WDATA_BSS_fs_blockdev_refusal 0
alignb 8
blk_write_dispatches: resq 1
blk_write_dispatch_wrapped: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_blockdev_refusal

blk_members_snapshot:
    jmp blk_members_snapshot_impl

%include "fs/block_members.inc"

; Read-only U7-ENUM registry snapshot. Count ALL registered devices, including
; degraded backends, rather than silently substituting the healthy selection.
; EAX=count (0..BLK_REGISTRY_LIMIT), or -1 for corrupt/overfull registry state.
blk_registered_count:
    sub  rsp, 8
    call blk_registry_lock_acquire
    mov  rdx, [rel blk_registry_head]
    xor  ecx, ecx
.next:
    test rdx, rdx
    jz   .done
    cmp  ecx, BLK_REGISTRY_LIMIT
    jae  .bad
    cmp  dword [rdx + dev.class], CLASS_BLOCK
    jne  .bad
    cmp  qword [rdx + dev.ops], 0
    je   .bad
    cmp  qword [rdx + dev.info], 0
    je   .bad
    inc  ecx
    mov  rdx, [rdx + dev.next]
    jmp  .next
.bad:
    mov  ecx, -1
.done:
    mov  [rsp], ecx
    call blk_registry_lock_release
    mov  eax, [rsp]
    add  rsp, 8
    ret

; Named wrappers keep the registry/identity lock mechanically auditable.  The
; registry links and generation allocator are protected here; registered
; blk_info geometry/generation is immutable, with the KAT's fault injections
; using these same wrappers around each temporary mutation.
blk_registry_lock_acquire:
    lea  rdi, [rel blk_registry_lock]
    jmp  spin_acquire

blk_registry_lock_release:
    lea  rdi, [rel blk_registry_lock]
    jmp  spin_release

; ---- blk_init — reset the registry (idempotent) ----------------------------
blk_init:
    call blk_registry_lock_acquire
    mov  qword [rel blk_registry_head], 0
    call blk_registry_lock_release
    ; Scale-1 exercise for the shared persistent-sector composition lock.
    call persist_gap_lock_acquire
    call persist_gap_lock_release
    ret

; ---- blk_register(RDI=dev*) -> RAX REG_OK/REG_REJECT -------------------------
; Validates the uniform header, then inserts into the intrusive .next list
; ordered by .prio DESCENDING (head = highest priority). Selection walks from
; the head and takes the first HEALTHY node, so priority ordering + health is
; the whole native->degraded->domain fallback (DRIVER_MODEL §6).
blk_register:
    call guest_volume_registry_allowed
    test rax,rax
    jnz .reject
    cmp  qword [rdi + dev.ops], 0
    je   .reject
    cmp  qword [rdi + dev.info], 0
    je   .reject
    cmp  dword [rdi + dev.class], CLASS_BLOCK
    jne  .reject
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rdi
    mov  r12d, [rbx + dev.prio]             ; my priority
    call blk_registry_lock_acquire
    ; Admission must inspect the entire list before choosing an insertion
    ; point. A higher-priority candidate must not bypass the capacity bound,
    ; a duplicate later in the list, or a cycle. Reject before changing links
    ; or consuming a medium generation.
    mov  rax, [rel blk_registry_head]
    xor  r9d, r9d
.admit:
    test rax, rax
    jz   .find_slot
    cmp  rax, rbx                           ; one handle may occur only once
    je   .reject_locked
    inc  r9d
    cmp  r9d, BLK_REGISTRY_LIMIT
    jae  .reject_locked                     ; corrupt/cyclic list stays bounded
    mov  rax, [rax + dev.next]
    jmp  .admit
.find_slot:
    lea  rsi, [rel blk_registry_head]       ; rsi = &(prev->next); start at the head slot
.scan:
    mov  rax, [rsi]                         ; current node
    test rax, rax
    jz   .insert                            ; end of list -> append here
    mov  ecx, [rax + dev.prio]
    cmp  ecx, r12d
    jl   .insert                            ; current prio < mine -> insert BEFORE current
    lea  rsi, [rax + dev.next]              ; advance
    jmp  .scan
.insert:
    ; Registration is the medium/backend-generation boundary.  Assign a fresh
    ; class-owned identity before the info block becomes visible; reinit never
    ; comes through this path, so it preserves the token.  Exhaustion fails
    ; closed instead of wrapping to an identity a stale handle may remember.
    mov  rdx, [rbx + dev.info]
    cmp  qword [rel blk_media_generation_next], -1
    je   .reject_locked
    inc  qword [rel blk_media_generation_next]
    mov  rax, [rel blk_media_generation_next]
    mov  [rdx + blk_info.media_generation], rax
    mov  rax, [rsi]                         ; old successor
    mov  [rbx + dev.next], rax              ; my.next = old successor
    mov  [rsi], rbx                         ; prev->next = me
    call blk_registry_lock_release
    mov  eax, REG_OK
    add  rsp, 8
    pop  r12
    pop  rbx
    ret
.reject_locked:
    call blk_registry_lock_release
    mov  eax, REG_REJECT
    add  rsp, 8
    pop  r12
    pop  rbx
    ret
.reject:
    mov  eax, REG_REJECT
    ret

; ---- blk_deregister(RDI=dev*) — unlink (called by the degrade ladder) --------
blk_deregister:
    push rbx
    mov  rbx, rdi
    call blk_registry_lock_acquire
    lea  rsi, [rel blk_registry_head]
    xor  ecx, ecx
.scan:
    mov  rax, [rsi]
    test rax, rax
    jz   .done                              ; not found
    cmp  rax, rbx
    je   .unlink
    inc  ecx
    cmp  ecx, BLK_REGISTRY_LIMIT
    jae  .done
    lea  rsi, [rax + dev.next]
    jmp  .scan
.unlink:
    mov  rax, [rbx + dev.next]
    mov  [rsi], rax
    mov  qword [rbx + dev.next], 0
.done:
    call blk_registry_lock_release
    pop  rbx
    ret

; ---- blk_select() -> RAX = highest-prio HEALTHY dev* (or 0) ------------------
blk_select:
    mov  rax, [rel blk_registry_head]
.loop:
    test rax, rax
    jz   .none
    cmp  dword [rax + dev.health], HEALTH_OK
    je   .found
    mov  rax, [rax + dev.next]
    jmp  .loop
.none:
    xor  eax, eax
.found:
    ret

; blk_find_named(RDI=name,ESI=len) -> RAX=healthy dev* / 0.
; The filesystem receives an explicit device handle; it never imports ahci/nvme.
blk_find_named:
    test esi, esi
    jz   .none
    mov  rax, [rel blk_registry_head]
.walk:
    test rax, rax
    jz   .none
    cmp  dword [rax + dev.health], HEALTH_OK
    jne  .next
    mov  rdx, [rax + dev.name]
    test rdx, rdx
    jz   .next
    xor  ecx, ecx
.cmp:
    cmp  ecx, esi
    jae  .term
    mov  r8b, [rdi + rcx]
    cmp  r8b, [rdx + rcx]
    jne  .next
    inc  ecx
    jmp  .cmp
.term:
    cmp  byte [rdx + rcx], 0
    je   .found
.next:
    mov  rax, [rax + dev.next]
    jmp  .walk
.none:
    xor  eax, eax
.found:
    ret

; blk_iter_after(RDI=previous dev* or 0, RSI=required BLKCAP_* mask,
;                EDX=excluded BLKF_* mask) -> RAX=next healthy match / 0.
; The previous handle is resolved by a bounded walk from the registry head; it
; is never dereferenced directly, so a stale/unregistered handle cannot escape
; the registry or manufacture a successor.  No device name or unit participates.
; Internal ownership census also sees degraded aliases, so a later recovery
; cannot resurrect a native mount that predates guest writes.
blk_iter_all_after:
    mov eax,1
    jmp blk_iter_after.entry
blk_iter_after:
    xor eax,eax
.entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov r15d,eax
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    call blk_registry_lock_acquire
    mov  rbx, [rel blk_registry_head]
    xor  ebp, ebp
    test r12, r12
    jz   .scan_match
.find_previous:
    test rbx, rbx
    jz   .none
    cmp  rbx, r12
    je   .after_previous
    mov  rbx, [rbx + dev.next]
    inc  ebp
    cmp  ebp, BLK_REGISTRY_LIMIT
    jb   .find_previous
    jmp  .none
.after_previous:
    mov  rbx, [rbx + dev.next]
    inc  ebp
.scan_match:
    test rbx, rbx
    jz   .none
    cmp  ebp, BLK_REGISTRY_LIMIT
    jae  .none
    test r15d,r15d
    jnz .info
    cmp  dword [rbx + dev.health], HEALTH_OK
    jne  .next
.info:
    mov  rax, [rbx + dev.info]
    test rax, rax
    jz   .next
    mov  rcx, [rax + blk_info.capabilities]
    and  rcx, r13
    cmp  rcx, r13
    jne  .next
    mov  ecx, [rax + blk_info.flags]
    and  ecx, r14d
    jz   .found
.next:
    mov  rbx, [rbx + dev.next]
    inc  ebp
    jmp  .scan_match
.found:
    call blk_registry_lock_release
    mov  rax, rbx
    jmp  .out
.none:
    call blk_registry_lock_release
    xor  eax, eax
.out:
    add rsp,8
    pop r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; blk_find_prefix_after(RDI=prefix, ESI=len, RDX=previous dev* or 0)
;   -> RAX=next healthy prefix-matching dev* / 0.  This is the bounded registry
; iterator used by already-shipped callers.  Compatibility only: new discovery
; uses blk_iter_after and capability/flag policy, never a controller prefix.
blk_find_prefix_after:
    test esi, esi
    jz   .none
    test rdx, rdx
    jz   .head
    mov  rax, [rdx + dev.next]
    jmp  .walk
.head:
    mov  rax, [rel blk_registry_head]
.walk:
    test rax, rax
    jz   .none
    cmp  dword [rax + dev.health], HEALTH_OK
    jne  .next
    mov  r8, [rax + dev.name]
    test r8, r8
    jz   .next
    xor  ecx, ecx
.cmp:
    cmp  ecx, esi
    jae  .found
    mov  r9b, [rdi + rcx]
    cmp  r9b, [r8 + rcx]
    jne  .next
    inc  ecx
    jmp  .cmp
.next:
    mov  rax, [rax + dev.next]
    jmp  .walk
.none:
    xor  eax, eax
.found:
    ret

; ---- backend-agnostic DISPATCH (the seam — identical for every backend) ------
; blk_validate_range(RDI=dev,RSI=lba,RDX=count) -> RAX=0 or BLK_ERR_*.
; On success RDX is restored to count and R8 is the checked byte count.
; New-capability backends must declare complete truthful geometry.  A zero
; capability mask denotes a shipped pre-2912 backend: its old sector_size and
; lba_max remain range-checked, while max/physical/cap policy waits for that
; controller's own just-in-time geometry rung.
blk_validate_range:
    test rdi, rdi
    jz   .bad_geometry
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .unhealthy
    mov  r10, [rdi + dev.info]
    test r10, r10
    jz   .bad_geometry
    test rdx, rdx
    jz   .zero_count
    mov  r9, rdx                            ; preserve count across MUL
    mov  r11, [r10 + blk_info.capabilities]
    mov  r8d, [r10 + blk_info.logical_sector_bytes]
    test r11, r11
    jnz  .new_geometry
    mov  r8d, [r10 + blk_info.sector_size] ; strict compatibility geometry
    test r8d, r8d
    jz   .bad_geometry
    mov  eax, r8d
    dec  eax
    test eax, r8d
    jnz  .bad_geometry
    jmp  .byte_count
.new_geometry:
    cmp  r8d, 512
    jb   .bad_geometry
    mov  eax, r8d
    dec  eax
    test eax, r8d
    jnz  .bad_geometry                     ; logical bytes must be a power of two
    cmp  r8d, [r10 + blk_info.sector_size]
    jne  .bad_geometry                     ; legacy and truthful logical views agree
    mov  ecx, [r10 + blk_info.physical_sector_bytes]
    cmp  ecx, r8d
    jb   .bad_geometry
    mov  eax, ecx
    dec  eax
    test eax, ecx
    jnz  .bad_geometry
    xor  edx, edx
    mov  eax, ecx
    div  r8d
    test edx, edx
    jnz  .bad_geometry
    mov  ecx, [r10 + blk_info.physical_alignment_bytes]
    cmp  ecx, [r10 + blk_info.physical_sector_bytes]
    jae  .bad_geometry
    xor  edx, edx
    mov  eax, ecx
    div  r8d
    test edx, edx
    jnz  .bad_geometry
    cmp  dword [r10 + blk_info.max_transfer_sectors], 0
    je   .bad_geometry
.byte_count:
    mov  rax, r9
    mul  r8                                ; RDX:RAX=count*logical
    test rdx, rdx
    jnz  .byte_overflow
    mov  r8, rax                           ; checked byte count result
    test r11, r11
    jz   .lba_end
    mov  eax, [r10 + blk_info.max_transfer_sectors]
    cmp  r9, rax
    ja   .above_max
.lba_end:
    mov  rax, r9
    dec  rax
    add  rax, rsi
    jc   .lba_overflow
    cmp  rax, [r10 + blk_info.lba_max]
    ja   .end_of_device
    mov  rdx, r9                           ; restore dispatch count
    xor  eax, eax
    ret
.zero_count:
    mov  eax, BLK_ERR_ZERO_COUNT
    ret
.lba_overflow:
    mov  eax, BLK_ERR_LBA_OVERFLOW
    ret
.end_of_device:
    mov  eax, BLK_ERR_END_OF_DEVICE
    ret
.byte_overflow:
    mov  eax, BLK_ERR_BYTE_OVERFLOW
    ret
.bad_geometry:
    mov  eax, BLK_ERR_INVALID_GEOMETRY
    ret
.above_max:
    mov  eax, BLK_ERR_MAX_TRANSFER
    ret
.unhealthy:
    mov  eax, BLK_ERR_UNHEALTHY
    ret

; blk_read/write(RDI=dev, RSI=lba, RDX=count, RCX=buf) -> RAX 0/BLK_ERR_*
; blk_flush/identify(RDI=dev) -> RAX 0/-1
; Every range refusal and the structural RO/capability gates precede vtable entry.
; Exclusive guest transfer has no ambient bypass, even for SPECIAL/owned ops.
blk_guest_refused:
    mov eax,BLK_ERR_WRITE_GATE
    ret

blk_identify:
    call guest_volume_native_allowed
    test rax,rax
    jnz blk_guest_refused
    mov  rax, [rdi + dev.ops]
    jmp  [rax + blk_ops.identify]
blk_read:
    call guest_volume_native_allowed
    test rax,rax
    jnz blk_guest_refused
    push rcx                                ; validator may use RCX; backend ABI needs buf intact
    call blk_validate_range
    pop  rcx
    test rax, rax
    jnz  .done
    mov  r8, [rdi + dev.info]
    mov  r9, [r8 + blk_info.capabilities]
    test r9, r9
    jz   .dispatch                         ; pre-2912 compatibility backend
    test r9, BLKCAP_READ
    jz   .capability
.dispatch:
    mov  rax, [rdi + dev.ops]
    jmp  [rax + blk_ops.read]
.capability:
    mov  eax, BLK_ERR_CAPABILITY
.done:
    ret

; blk_write_owned(RDI=dev, RSI=lba, RDX=count, RCX=buf, R8=owned op handle)
;   -> RAX 0/BLK_ERR_* (RCQ-21 SA2a; rc-sec rulings 07:21:38, 08:45:23). The
;   ONLY entry that presents an owned filesystem operation. It runs the same
;   validated body as blk_write, and its write is admitted ONLY by
;   storage_access_owned_admitted: a missing, stale or forged handle is
;   refused, never retried against an ordinary grant. The handle travels in
;   this call's own stack frame (no module global), so a nested or later
;   generic blk_write can neither see, inherit nor launder it.
blk_write_owned:
    test r8, r8
    jz   .refused
    push r8                                 ; [rsp + 8] in the body: the presented op
    push 0                                  ; pad: the body runs at blk_write's alignment
    jmp  blk_write.body
.refused:
    mov  eax, BLK_ERR_WRITE_GATE
    ret

blk_write:
    push 0                                  ; generic entry: no owned op presented
    push 0
.body:
    call guest_volume_native_allowed
    test rax,rax
    jnz .ro
    test rdi, rdi
    jz   .invalid
    mov  r8, [rdi + dev.info]
    test r8, r8
    jz   .invalid
    test dword [r8 + blk_info.flags], BLKF_RO
    jnz  .ro
    test dword [rdi + dev.flags], BLKF_RO
    jnz  .ro
    push rcx                                ; preserve caller buffer across geometry arithmetic
    call blk_validate_range
    pop  rcx
    test rax, rax
    jnz  .done
    mov  r8, [rdi + dev.info]
    mov  r9, [r8 + blk_info.capabilities]
    test r9, r9
    jz   .dispatch
    test r9, BLKCAP_WRITE
    jz   .capability
.dispatch:
    ; SEC-S6 / Task 3025: the storage gate is structural. A write is dispatched
    ; only inside a grant the gate gave for this device (storage_access_write_
    ; admitted preserves RDI/RSI/RDX/RCX), never on a caller's word alone.
    ; RCQ-21 SA2a: a presented owned op is admitted ONLY by the owned check
    ; (full live identity re-probe), the generic entry ONLY by the legacy grants;
    ; each admission is followed directly by its own dispatch.
    mov  r8, [rsp + 8]
    add  rsp, 16                            ; frame consumed: R8 is this call's presented op
    test r8, r8
    jnz  .owned
    call storage_access_write_admitted
    test rax, rax
    jnz  .write_gate
    lock inc qword [rel blk_write_dispatches] ; F6: actual admitted backend offer
    jnz .counted_generic
    mov byte [rel blk_write_dispatch_wrapped],1
.counted_generic:
    mov  rax, [rdi + dev.ops]
    jmp  [rax + blk_ops.write]
.owned:
    call storage_access_owned_admitted      ; preserves RDI/RSI/RDX/RCX; no fallback
    test rax, rax
    jnz  .write_gate
    lock inc qword [rel blk_write_dispatches] ; F6: actual admitted backend offer
    jnz .counted_owned
    mov byte [rel blk_write_dispatch_wrapped],1
.counted_owned:
    mov  rax, [rdi + dev.ops]
    jmp  [rax + blk_ops.write]
.write_gate:
    mov  eax, BLK_ERR_WRITE_GATE
    ret
.invalid:                                   ; exits below still hold the 16-byte frame
    mov  eax, BLK_ERR_INVALID_GEOMETRY
    jmp  .done
.ro:
    mov  eax, BLK_ERR_WRITE_GATE
    jmp  .done
.capability:
    mov  eax, BLK_ERR_CAPABILITY
.done:
    add  rsp, 16
    ret
blk_flush:
    call guest_volume_native_allowed
    test rax,rax
    jnz .guest_refused
    test rdi, rdi
    jz   .invalid
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .unhealthy
    mov  r8, [rdi + dev.info]
    test r8, r8
    jz   .invalid
    mov  r9, [r8 + blk_info.capabilities]
    test r9, r9
    jz   .dispatch                          ; 0 = a legacy (pre-2912) mask: its flush op runs
    test r9, BLKCAP_FLUSH
    jz   .unsupported
.dispatch:
    sub  rsp, 8
    mov  rax, [rdi + dev.ops]
    call [rax + blk_ops.flush]
    add  rsp, 8
    test rax, rax
    jnz  .failed
    ret
.invalid:
    mov  eax, BLK_ERR_INVALID_GEOMETRY
    jmp  .failed
.unhealthy:
    mov  eax, BLK_ERR_UNHEALTHY
    jmp  .failed
.unsupported:                               ; declared, without FLUSH: nothing can be made durable
    mov  eax, BLK_ERR_FLUSH_UNSUPPORTED
    jmp .failed
.guest_refused:
    mov eax,BLK_ERR_WRITE_GATE
.failed:
    ; RCQ-20 S1S2 return-1 (srcreview A-F1): every refused or failed flush is
    ; counted, so a copy job that saw one reports DURABLE=uncertain even when a
    ; caller's retry later succeeded (a re-flush does not make the earlier data
    ; durable). Monotonic, any device: conservative, never a false "1".
    inc  qword [rel blk_flush_failures]
    ret

; ---- blk_reinit(RDI=dev) -> RAX 0 live / stable BLK_ERR_* refusal -----------
; The reinit contract (RESILIENCE §2/3): quiesce -> idempotent re-init -> VERIFY.
; "Done" is proven by a post-reinit liveness READ of a known sector returning 0,
; NOT by init exiting. A backend whose identify() clears a wedged flag becomes
; readable again here; one that stays wedged fails the verify and reports dead.
blk_reinit:
    call guest_volume_native_allowed
    test rax,rax
    jnz blk_guest_refused
    push rbx
    sub  rsp, 64
    mov  rbx, rdi                           ; preserve dev across ops calls
    mov  rax, [rbx + dev.info]
    test rax, rax
    jz   .changed
    mov  [rsp + 0], rax
    mov  rdx, [rax + blk_info.lba_max]
    mov  [rsp + 8], rdx
    mov  rdx, [rax + blk_info.capabilities]
    mov  [rsp + 16], rdx
    mov  rdx, [rax + blk_info.media_generation]
    mov  [rsp + 24], rdx
    mov  edx, [rax + blk_info.logical_sector_bytes]
    mov  [rsp + 32], edx
    mov  edx, [rax + blk_info.physical_sector_bytes]
    mov  [rsp + 36], edx
    mov  edx, [rax + blk_info.physical_alignment_bytes]
    mov  [rsp + 40], edx
    mov  edx, [rax + blk_info.max_transfer_sectors]
    mov  [rsp + 44], edx
    mov  edx, [rax + blk_info.sector_size]
    mov  [rsp + 48], edx
    mov  edx, [rax + blk_info.flags]
    mov  [rsp + 52], edx
    mov  edx, [rax + blk_info.unit]
    mov  [rsp + 56], edx
    ; quiesce (best-effort; a wedged device may -1 here — that's fine)
    mov  rdi, rbx
    call blk_flush
    ; idempotent re-init (identify doubles as the re-runnable init that un-wedges)
    mov  rdi, rbx
    call blk_identify
    test rax, rax
    jnz  .dead
    ; Reinit may reset queues but must not silently replace the medium or alter
    ; declared geometry/capabilities.  A backend media-change path deregisters
    ; and re-registers, establishing a fresh class-owned generation instead.
    mov  rax, [rbx + dev.info]
    cmp  rax, [rsp + 0]
    jne  .changed
    mov  rdx, [rax + blk_info.lba_max]
    cmp  rdx, [rsp + 8]
    jne  .changed
    mov  rdx, [rax + blk_info.capabilities]
    cmp  rdx, [rsp + 16]
    jne  .changed
    mov  rdx, [rax + blk_info.media_generation]
    cmp  rdx, [rsp + 24]
    jne  .changed
    mov  edx, [rax + blk_info.logical_sector_bytes]
    cmp  edx, [rsp + 32]
    jne  .changed
    mov  edx, [rax + blk_info.physical_sector_bytes]
    cmp  edx, [rsp + 36]
    jne  .changed
    mov  edx, [rax + blk_info.physical_alignment_bytes]
    cmp  edx, [rsp + 40]
    jne  .changed
    mov  edx, [rax + blk_info.max_transfer_sectors]
    cmp  edx, [rsp + 44]
    jne  .changed
    mov  edx, [rax + blk_info.sector_size]
    cmp  edx, [rsp + 48]
    jne  .changed
    mov  edx, [rax + blk_info.flags]
    cmp  edx, [rsp + 52]
    jne  .changed
    mov  edx, [rax + blk_info.unit]
    cmp  edx, [rsp + 56]
    jne  .changed
    ; verify-AFTER through the SAME centralized validator + dispatch.
    mov  rdi, rbx
    mov  rsi, 3
    mov  rdx, 1
    lea  rcx, [rel blk_scratch]
    call blk_read
    test rax, rax
    jnz  .dead
    xor  eax, eax
    add  rsp, 64
    pop  rbx
    ret
.changed:
    mov  eax, BLK_ERR_INVALID_GEOMETRY
    add  rsp, 64
    pop  rbx
    ret
.dead:
    mov  eax, BLK_ERR_BACKEND
    add  rsp, 64
    pop  rbx
    ret

; ---- blk_cksum(RDI=buf, RSI=len) -> RAX = FNV-1a 64 -------------------------
; The content-grade primitive: a stub that prints the marker without moving real
; bytes cannot produce the known-answer checksum the probe validates.
;   clobbers RAX,RCX,RDX,R8,R9
blk_cksum:
    mov  rax, 0xCBF29CE484222325            ; FNV offset basis
    mov  r9,  0x100000001B3                 ; FNV prime
    xor  rcx, rcx
.next:
    cmp  rcx, rsi
    jae  .done
    movzx r8, byte [rdi + rcx]
    xor  rax, r8
    mul  r9                                 ; rdx:rax = rax*prime; low 64 (rax) = mod 2^64
    inc  rcx
    jmp  .next
.done:
    ret

; ============================================================================
; blk_selftest — the content-graded boot acceptance (called from boot/header).
; Emits the eight legacy markers plus the geometry/range receipt. Everything
; routes through the class DISPATCH, so
; the read/write/flush selftests ALSO prove the seam (the selected backend is
; reached by backend-agnostic code) and the degraded nvme/ahci registrations
; prove degrade-never-crash + N-ary priority selection.
; ============================================================================
blk_selftest:
    push rbx
    call blk_init

    ; --- bring up the class core + the fake (reference) backend -------------
    lea  rdi, [rel str_blk_seam_init]
    call serial_string                      ; marker 1: blockdev.class.seam.init

    call ramblk_create                      ; registers a RAM backend (pre-filled pattern A)
    lea  rdi, [rel str_blk_ramblk_reg]
    call serial_string                      ; marker 2: blockdev.ramblk.registered

    ; --- register the two production backends' vtables (seam members) -------
    ; Both now do REAL bring-up (nvme 1027, ahci 1028) but register at
    ; PRIO_DOMAIN, so ramblk stays selected as the safe boot scratch default;
    ; an absent controller/disk self-marks HEALTH_DEGRADED — degrade, never crash.
    call vmd_domain_create                  ; Intel VMD domain first: publishes AHCI/NVMe children hidden from the legacy bus
    call nvme_blk_create
    lea  rdi, [rel str_blk_nvme_reg]
    call serial_string                      ; marker 3: blockdev.nvme.registered
    call ahci_blk_create
    lea  rdi, [rel str_blk_ahci_reg]
    call serial_string                      ; marker 4: blockdev.ahci.registered

    ; --- 1027: NVMe backend boot acceptance (real controller if present) -----
    ; nvme_blk_create (above) now does real PCI detect + controller bring-up +
    ; IDENTIFY. nvme_self_exercise emits the 1027 markers: blk.nvme.registered,
    ; blk.nvme.identify.ok, and — QEMU only — blk.nvme.rw.verified (write->flush->
    ; readback content-grade against the emulated nvme namespace); on the real disk
    ; it does a read-only content-grade (the write round-trip is a supervised step).
    ; Then nullblk registers behind the SAME blk_ops (blk.nullblk.registered),
    ; proving the class core below is UNEDITED to accept another backend (§9.4).
    call nvme_self_exercise
    ; --- 1028: AHCI backend boot acceptance (real HBA + disk if present) -----
    ; ahci_blk_create (above) now does real PCI detect + HBA port bring-up +
    ; IDENTIFY. ahci_self_exercise emits the 1028 markers: blk.ahci.registered,
    ; blk.ahci.identify.ok and blk.ahci.read.verified. A destructive round-trip
    ; additionally needs an explicitly owned scratch extent; none is minted
    ; today, so the boot test emits a write SKIP independently of model name.
    call ahci_self_exercise
    call nullblk_create

    ; --- select the healthy backend (ramblk; nvme/ahci are degraded) --------
    call blk_select
    mov  rbx, rax                           ; rbx = selected dev* (survives all ops calls)
    test rbx, rbx
    jz   .no_backend

    ; --- READ selftest: read pre-filled sector 3, checksum it --------------
    mov  rdi, rbx
    mov  rsi, 3
    mov  rdx, 1
    lea  rcx, [rel blk_scratch]
    call blk_read
    lea  rdi, [rel blk_scratch]
    mov  rsi, 512
    call blk_cksum                          ; RAX = FNV of sector 3
    lea  rdi, [rel str_blk_read_pre]
    call serial_string
    mov  rdi, rax
    call serial_hex64                       ; prints 0x<16 hex>
    lea  rdi, [rel str_blk_read_post]
    call serial_string                      ; marker 5: blockdev.read.selftest

    ; --- WRITE selftest: write pattern B to sector 5, read it back --------
    ; storage-access gate: a boot self-test is implicit -> RAM/test scratch only. The selected device is the
    ;   RAM reference backend by construction (ramblk_wedge below); if it ever were a real disk, skip honestly.
    mov  rdi, rbx
    mov  rsi, 5
    mov  edx, 1
    mov  ecx, SA_INTENT_IMPLICIT
    lea  r8, [rel str_blk_selftest_sa_caller]
    call storage_access_require
    test rax, rax
    jnz  .reinit
    lea  rdi, [rel blk_scratch]
    call blk_fill_pattern_b                 ; blk_scratch <- pattern B (512 bytes)
    mov  rdi, rbx
    mov  rsi, 5
    mov  rdx, 1
    lea  rcx, [rel blk_scratch]
    call blk_write
    ; read it back into a distinct buffer and checksum -> must equal FNV(B)
    mov  rdi, rbx
    mov  rsi, 5
    mov  rdx, 1
    lea  rcx, [rel blk_scratch2]
    call blk_read
    lea  rdi, [rel blk_scratch2]
    mov  rsi, 512
    call blk_cksum
    lea  rdi, [rel str_blk_write_pre]
    call serial_string
    mov  rdi, rax
    call serial_hex64
    lea  rdi, [rel str_blk_write_post]
    call serial_string                      ; marker 6: blockdev.write.selftest

    ; --- FLUSH selftest: flush must actually fire (return 0) --------------
    mov  rdi, rbx
    call blk_flush
    test rax, rax
    jnz  .flush_fail
    lea  rdi, [rel str_blk_flush_ok]
    call serial_string                      ; marker 7: blockdev.flush.selftest
    jmp  .reinit

.flush_fail:
    lea  rdi, [rel str_blk_flush_bad]
    call serial_string
    jmp  .reinit

    ; --- REINIT cycle: wedge -> read must fail -> reinit -> liveness read --
.reinit:
    mov  rdi, rbx
    call ramblk_wedge                       ; simulate a hung ring on the fake backend
    ; a read on the wedged device must now fail (proves the wedge is real)
    mov  rdi, rbx
    mov  rsi, 3
    mov  rdx, 1
    lea  rcx, [rel blk_scratch]
    call blk_read
    test rax, rax
    jz   .reinit_bad                        ; read SUCCEEDED while wedged -> not a real wedge
    ; now reinit + verify-after (liveness)
    mov  rdi, rbx
    call blk_reinit
    test rax, rax
    jnz  .reinit_bad
    lea  rdi, [rel str_blk_reinit_ok]
    call serial_string                      ; marker 8: blockdev.reinit.verify (+ liveness=ok)
    call blk_geometry_range_selftest
    call storage_inventory_kat                ; Task3470: NVMe inventory parser content KAT
    jmp  .done

.reinit_bad:
    lea  rdi, [rel str_blk_reinit_bad]
    call serial_string
    jmp  .done

.no_backend:
    lea  rdi, [rel str_blk_nobackend]
    call serial_string
.done:
    pop  rbx
    ret

; blk_fill_pattern_b(RDI=buf) — 512 bytes: byte(O) = (O*13 + 0x27) & 0xFF.
; (Pattern A, the pre-filled read pattern, lives in ramblk_create.)
blk_fill_pattern_b:
    xor  rcx, rcx                           ; O
.next:
    cmp  rcx, 512
    jae  .done
    mov  rax, rcx
    imul rax, rax, 13
    add  rax, 0x27
    mov  [rdi + rcx], al
    inc  rcx
    jmp  .next
.done:
    ret

; Fill a caller-owned KAT buffer with a deterministic nonzero pattern.
; RDI=buffer, RSI=bytes, EDX=seed.
blk_geom_fill:
    xor  r8, r8
.next:
    cmp  r8, rsi
    jae  .done
    mov  rax, r8
    imul rax, rax, 29
    mov  r9, r8
    shr  r9, 8
    imul r9, r9, 17
    add  rax, r9
    add  eax, edx
    mov  [rdi + r8], al
    inc  r8
    jmp  .next
.done:
    ret

; Exactly sixteen lowercase hexadecimal digits, with no diagnostic 0x prefix.
; The external receipt grammar uses this for runtime tokens and checksums.
blk_serial_hex16:
    push rax
    push rbx
    push rcx
    mov  rbx, rdi
    mov  ecx, 16
.nibble:
    rol  rbx, 4
    mov  al, bl
    and  al, 0x0f
    cmp  al, 10
    jb   .decimal
    add  al, 'a' - 10
    jmp  .emit
.decimal:
    add  al, '0'
.emit:
    movzx edi, al
    call serial_char
    dec  ecx
    jnz  .nibble
    pop  rcx
    pop  rbx
    pop  rax
    ret

; blk_geom_census() -> RAX = the number of healthy BLKCAP_ALL_IO, non-RO
; registrations, or -1 unless each ramblk witness is among them exactly once,
; no handle repeats its predecessor, and the walk stays within the registry
; limit.  The witnesses are identified by their dev identity, never by name.
blk_geom_census:
    push rbx
    push rbp
    push r12
    push r13
    sub  rsp, 8
    xor  ebx, ebx                         ; the previous match
    xor  ebp, ebp                         ; matches
    xor  r12d, r12d                       ; 512e witness hits
    xor  r13d, r13d                       ; 4Kn witness hits
.next:
    mov  rdi, rbx
    mov  esi, BLKCAP_ALL_IO
    mov  edx, BLKF_RO
    call blk_iter_after
    test rax, rax
    jz   .walked
    cmp  rax, rbx
    je   .bad
    mov  rbx, rax
    inc  ebp
    cmp  ebp, BLK_REGISTRY_LIMIT
    ja   .bad
    lea  rcx, [rel ramblk_dev]
    cmp  rax, rcx
    jne  .not_512
    inc  r12d
.not_512:
    lea  rcx, [rel ramblk_4kn_dev]
    cmp  rax, rcx
    jne  .next
    inc  r13d
    jmp  .next
.walked:
    cmp  r12d, 1
    jne  .bad
    cmp  r13d, 1
    jne  .bad
    mov  eax, ebp
    jmp  .out
.bad:
    mov  rax, -1
.out:
    add  rsp, 8
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Two controller-neutral reference media grade the additive ABI and ordinary
; class dispatch.  A receipt is emitted only after every content/state check.
blk_geometry_range_selftest:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8

    call ramblk_create_4kn
    cmp  eax, REG_OK
    jne  .fail
    mov  rdi, 32768
    call kmalloc
    test rax, rax
    jz   .fail
    mov  [rel blk_geom_scratch], rax

    ; Capability/flag policy discovers each ramblk witness exactly once.  A real
    ; AHCI disk or NVMe namespace declares BLKCAP_ALL_IO too (RCQ-05) and may
    ; match; it is counted, never addressed: every I/O below names a witness.
    call blk_geom_census
    cmp  rax, 2
    jl   .fail
    mov  [rsp], eax                       ; the match count the post-reinit census must repeat
    lea  rbx, [rel ramblk_dev]
    lea  r12, [rel ramblk_4kn_dev]

    ; Each witness must declare the geometry of its variant.
    mov  r13, [rbx + dev.info]
    mov  r14, [r12 + dev.info]
    cmp  dword [r13 + blk_info.logical_sector_bytes], 512
    jne  .fail
    cmp  dword [r14 + blk_info.logical_sector_bytes], 4096
    jne  .fail
    cmp  dword [r13 + blk_info.physical_sector_bytes], 4096
    jne  .fail
    cmp  dword [r14 + blk_info.physical_sector_bytes], 4096
    jne  .fail
    cmp  dword [r13 + blk_info.physical_alignment_bytes], 0
    jne  .fail
    cmp  dword [r14 + blk_info.physical_alignment_bytes], 0
    jne  .fail
    cmp  dword [r13 + blk_info.max_transfer_sectors], RAMBLK_MAX_XFER
    jne  .fail
    cmp  dword [r14 + blk_info.max_transfer_sectors], RAMBLK_MAX_XFER
    jne  .fail
    mov  rax, [r13 + blk_info.capabilities]
    and  rax, BLKCAP_ALL_IO
    cmp  rax, BLKCAP_ALL_IO
    jne  .fail
    mov  rax, [r14 + blk_info.capabilities]
    and  rax, BLKCAP_ALL_IO
    cmp  rax, BLKCAP_ALL_IO
    jne  .fail
    mov  rax, [r13 + blk_info.media_generation]
    test rax, rax
    jz   .fail
    mov  [rel blk_geom_gen512], rax
    mov  rdx, [r14 + blk_info.media_generation]
    test rdx, rdx
    jz   .fail
    cmp  rax, rdx
    je   .fail
    mov  [rel blk_geom_gen4kn], rdx

    ; Valid one-sector read/write through ordinary class dispatch on each ABI.
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 512
    mov  edx, 0x31
    call blk_geom_fill
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 512
    call blk_cksum
    mov  r15, rax
    mov  rdi, rbx                           ; storage-access gate: LBA 1 is a GPT header on a real disk
    mov  esi, 1
    mov  edx, 1
    mov  ecx, SA_INTENT_IMPLICIT
    lea  r8, [rel str_blk_geom_sa_caller]
    call storage_access_require
    test rax, rax
    jnz  .fail
    mov  rdi, rbx
    mov  esi, 1
    mov  edx, 1
    mov  rcx, [rel blk_geom_scratch]
    call blk_write
    test rax, rax
    jnz  .fail
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 512
    mov  edx, 0x91
    call blk_geom_fill
    mov  rdi, rbx
    mov  esi, 1
    mov  edx, 1
    mov  rcx, [rel blk_geom_scratch]
    call blk_read
    test rax, rax
    jnz  .fail
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 512
    call blk_cksum
    cmp  rax, r15
    jne  .fail

    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 4096
    mov  edx, 0x42
    call blk_geom_fill
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 4096
    call blk_cksum
    mov  r15, rax
    mov  rdi, r12                           ; storage-access gate (4Kn witness, same rule)
    mov  esi, 1
    mov  edx, 1
    mov  ecx, SA_INTENT_IMPLICIT
    lea  r8, [rel str_blk_geom_sa_caller]
    call storage_access_require
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  esi, 1
    mov  edx, 1
    mov  rcx, [rel blk_geom_scratch]
    call blk_write
    test rax, rax
    jnz  .fail
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 4096
    mov  edx, 0x92
    call blk_geom_fill
    mov  rdi, r12
    mov  esi, 1
    mov  edx, 1
    mov  rcx, [rel blk_geom_scratch]
    call blk_read
    test rax, rax
    jnz  .fail
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 4096
    call blk_cksum
    cmp  rax, r15
    jne  .fail
    mov  rdi, rbx
    call blk_flush
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call blk_flush
    test rax, rax
    jnz  .fail

    ; Reinit preserves every declared field and verifies liveness via validator.
    mov  rdi, rbx
    call blk_reinit
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call blk_reinit
    test rax, rax
    jnz  .fail
    cmp  qword [r13 + blk_info.media_generation], 0
    je   .fail
    mov  rax, [r13 + blk_info.media_generation]
    cmp  rax, [rel blk_geom_gen512]
    jne  .fail
    mov  rax, [r14 + blk_info.media_generation]
    cmp  rax, [rel blk_geom_gen4kn]
    jne  .fail

    ; Reset operation counters, then exact eight-sector write/read on both.
    mov  rdi, rbx
    call blk_identify
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call blk_identify
    test rax, rax
    jnz  .fail

    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 4096
    mov  edx, 0x53
    call blk_geom_fill
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 4096
    call blk_cksum
    test rax, rax
    jz   .fail
    mov  [rel blk_geom_cksum512], rax
    mov  rdi, rbx                           ; SEC-S6: gate exactly the range written (blk_write admits only that)
    mov  esi, 8
    mov  edx, 8
    mov  ecx, SA_INTENT_IMPLICIT
    lea  r8, [rel str_blk_geom_sa_caller]
    call storage_access_require
    test rax, rax
    jnz  .fail
    mov  rdi, rbx
    mov  esi, 8
    mov  edx, 8
    mov  rcx, [rel blk_geom_scratch]
    call blk_write
    test rax, rax
    jnz  .fail
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 4096
    mov  edx, 0x13
    call blk_geom_fill
    mov  rdi, rbx
    mov  esi, 8
    mov  edx, 8
    mov  rcx, [rel blk_geom_scratch]
    call blk_read
    test rax, rax
    jnz  .fail
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 4096
    call blk_cksum
    cmp  rax, [rel blk_geom_cksum512]
    jne  .fail

    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 32768
    mov  edx, 0xC1
    call blk_geom_fill
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 32768
    call blk_cksum
    test rax, rax
    jz   .fail
    cmp  rax, [rel blk_geom_cksum512]
    je   .fail
    mov  [rel blk_geom_cksum4kn], rax
    mov  rdi, r12                           ; SEC-S6: gate exactly the range written
    mov  esi, 4
    mov  edx, 8
    mov  ecx, SA_INTENT_IMPLICIT
    lea  r8, [rel str_blk_geom_sa_caller]
    call storage_access_require
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  esi, 4
    mov  edx, 8
    mov  rcx, [rel blk_geom_scratch]
    call blk_write
    test rax, rax
    jnz  .fail
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 32768
    mov  edx, 0x14
    call blk_geom_fill
    mov  rdi, r12
    mov  esi, 4
    mov  edx, 8
    mov  rcx, [rel blk_geom_scratch]
    call blk_read
    test rax, rax
    jnz  .fail
    mov  rdi, [rel blk_geom_scratch]
    mov  esi, 32768
    call blk_cksum
    cmp  rax, [rel blk_geom_cksum4kn]
    jne  .fail

    mov  rax, [rbx + dev.priv]
    cmp  qword [rax + ramblk_priv.ring_ctr], 2
    jne  .fail
    mov  rdx, [r12 + dev.priv]
    cmp  qword [rdx + ramblk_priv.ring_ctr], 2
    jne  .fail
    mov  qword [rel blk_geom_backend_calls], 4

    ; Snapshot the two complete images before hostile requests.
    mov  rax, [rbx + dev.priv]
    mov  rdi, [rax + ramblk_priv.buf]
    mov  esi, RAMBLK_512_NSEC * RAMBLK_512_SECSZ
    call blk_cksum
    mov  [rel blk_geom_img512], rax
    mov  rax, [r12 + dev.priv]
    mov  rdi, [rax + ramblk_priv.buf]
    mov  esi, RAMBLK_4KN_NSEC * RAMBLK_4KN_SECSZ
    call blk_cksum
    mov  [rel blk_geom_img4kn], rax

    ; Every hostile class refuses before the backend counter can advance.
    mov  rdi, rbx
    xor  esi, esi
    xor  edx, edx
    mov  rcx, [rel blk_geom_scratch]
    call blk_read
    cmp  eax, BLK_ERR_ZERO_COUNT
    jne  .fail
    mov  rdi, rbx
    mov  rsi, -1
    mov  edx, 2
    mov  rcx, [rel blk_geom_scratch]
    call blk_read
    cmp  eax, BLK_ERR_LBA_OVERFLOW
    jne  .fail
    mov  rdi, rbx
    mov  rsi, [r13 + blk_info.lba_max]
    mov  edx, 2
    mov  rcx, [rel blk_geom_scratch]
    call blk_read
    cmp  eax, BLK_ERR_END_OF_DEVICE
    jne  .fail
    mov  rdi, rbx
    xor  esi, esi
    mov  rdx, 0x0080000000000000
    mov  rcx, [rel blk_geom_scratch]
    call blk_read
    cmp  eax, BLK_ERR_BYTE_OVERFLOW
    jne  .fail
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, RAMBLK_MAX_XFER + 1
    mov  rcx, [rel blk_geom_scratch]
    call blk_read
    cmp  eax, BLK_ERR_MAX_TRANSFER
    jne  .fail

    ; Geometry/flag test mutations use the same declared registry lock.
    call blk_registry_lock_acquire
    mov  dword [r13 + blk_info.physical_sector_bytes], 513
    call blk_registry_lock_release
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, 1
    mov  rcx, [rel blk_geom_scratch]
    call blk_read
    mov  ebp, eax
    call blk_registry_lock_acquire
    mov  dword [r13 + blk_info.physical_sector_bytes], 4096
    call blk_registry_lock_release
    cmp  ebp, BLK_ERR_INVALID_GEOMETRY
    jne  .fail

    call blk_registry_lock_acquire
    or   dword [r13 + blk_info.flags], BLKF_RO
    call blk_registry_lock_release
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, 1
    mov  rcx, [rel blk_geom_scratch]
    call blk_write
    mov  ebp, eax
    call blk_registry_lock_acquire
    and  dword [r13 + blk_info.flags], ~BLKF_RO
    call blk_registry_lock_release
    cmp  ebp, BLK_ERR_WRITE_GATE
    jne  .fail

    mov  rax, [rbx + dev.priv]
    cmp  qword [rax + ramblk_priv.ring_ctr], 2
    jne  .fail
    mov  rdx, [r12 + dev.priv]
    cmp  qword [rdx + ramblk_priv.ring_ctr], 2
    jne  .fail
    mov  rdi, [rax + ramblk_priv.buf]
    mov  esi, RAMBLK_512_NSEC * RAMBLK_512_SECSZ
    call blk_cksum
    cmp  rax, [rel blk_geom_img512]
    jne  .fail
    mov  rax, [r12 + dev.priv]
    mov  rdi, [rax + ramblk_priv.buf]
    mov  esi, RAMBLK_4KN_NSEC * RAMBLK_4KN_SECSZ
    call blk_cksum
    cmp  rax, [rel blk_geom_img4kn]
    jne  .fail

    ; One final reinit proves the same identities/geometries remain live.
    mov  rdi, rbx
    call blk_reinit
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call blk_reinit
    test rax, rax
    jnz  .fail
    mov  rax, [r13 + blk_info.media_generation]
    cmp  rax, [rel blk_geom_gen512]
    jne  .fail
    mov  rax, [r14 + blk_info.media_generation]
    cmp  rax, [rel blk_geom_gen4kn]
    jne  .fail

    ; Reinit cannot duplicate, drop or repeat a handle in the iterator's result.
    call blk_geom_census
    cmp  eax, [rsp]
    jne  .fail

    rdtsc
    shl  rdx, 32
    or   rax, rdx
    xor  rax, [rel blk_geom_gen512]
    xor  rax, [rel blk_geom_gen4kn]
    or   rax, 1
    mov  [rel blk_geom_token], rax
    lea  rdi, [rel str_blk_geom_receipt_a]
    call serial_string
    mov  rdi, [rel blk_geom_token]
    call blk_serial_hex16
    lea  rdi, [rel str_blk_geom_receipt_b]
    call serial_string
    mov  rdi, [rel blk_geom_cksum512]
    call blk_serial_hex16
    lea  rdi, [rel str_blk_geom_receipt_c]
    call serial_string
    mov  rdi, [rel blk_geom_cksum4kn]
    call blk_serial_hex16
    lea  rdi, [rel str_blk_geom_receipt_d]
    call serial_string
    lea  rdi, [rel str_blk_geom_ok]
    call serial_string
    jmp  .out
.fail:
    lea  rdi, [rel str_blk_geom_fail]
    call serial_string
.out:
    ; No test device outlives the KAT, pass or fail: a readable 4Kn peer left registered
    ; makes every exact-GUID guest-source scan fail closed (G1b rc-sec b1). Not found = no-op.
    lea  rdi, [rel ramblk_4kn_dev]
    call blk_deregister
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ---- THE persist-gap reservation (SEC-S6-lba-dup) -------------------------
; The ONE definition of the two GPT-alignment-gap sectors PaOS writes for
; persistence. Every module names these (its own equ is an alias of them); a
; literal 0x700/0x708 sector equ anywhere else fails gauntlet_v2/tools/
; persist_gap_lint.py (make lint). Every RUNTIME writer holds persist_gap_lock;
; the AHCI boot self-exercise requires a proven owned extent in addition to
; storage access. These aliases reserve no disk layout: 0x700 can be FAT data.
; No owned raw scratch extent is minted today, so boot testing stays read-only.
;   owner                          device           bytes     writes
;   gui/session_restore            ahci0            0..343    manifest (RMW)
;   fs/data_crypto_store (+safe_write) metal: NVRAM; 344..511 legacy gap tail; raw
;                                  QEMU: gap         sector    write in QEMU only
;   svc/command_hppersist          (aliases kept; its fixture writes LBA 8, not the gap)
;   svc/command_blk BLKWRITE/BLK_RW any backend      0..511    owner-signed raw
;   dev/blk/ahci self-exercise     owned extent only 0..511   skipped (no owned extent)
PERSIST_GAP_LBA_PRIMARY equ 0x700
PERSIST_GAP_LBA_TMP     equ 0x708

; The session-manifest prefix and encrypted-DATA tail intentionally occupy
; disjoint byte ranges of the same two empirically proven AHCI gap sectors.
; Both read/modify/write owners serialize through this L4 lock.
persist_gap_lock_acquire:
    lea  rdi, [rel persist_gap_lock]
    call spin_acquire
    inc  qword [rel persist_gap_epoch]
    ret

persist_gap_lock_release:
    lea  rdi, [rel persist_gap_lock]
    jmp  spin_release

; ---- fs/blockdev data (in-image writable; migrates to BSS under full W^X) ----
; T0-1.C3 pure selected registry census. RSI=24-byte caller buffer:
; +0 one-based selected ordinal (0 none), +4 exact ops family,
; +8 actual health, +12 priority, +16 all member count, +20 flags
; (1 invalid/clipped list, 2 busy). No pointer/name/MAC or device callback.
; Nonblocking acquisition; no registration, selection mutation or device IO.
%include "core/abi/registry_instance_census.inc"
; RSI=64B v2 internal snapshot. Same selection/lock as legacy24B entry.
blk_census_snapshot_v2:
    mov eax,1
    jmp blk_census_snapshot.with_instance
blk_census_snapshot:
    xor eax,eax
.with_instance:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov r14d,eax
    mov r12,rsi
    mov qword [r12],0
    mov qword [r12+8],0
    mov qword [r12+16],0
    test r14d,r14d
    jz .legacy
    mov qword [r12+24],0
    mov qword [r12+32],0
    mov qword [r12+40],0
    mov qword [r12+48],0
    mov qword [r12+56],0
.legacy:
    xor r13d,r13d
    lea rdi,[rel blk_registry_lock]
    call spin_try_acquire
    test eax,eax
    jz .busy
    mov rbx,[rel blk_registry_head]
    xor r13d,r13d
.walk:
    test rbx,rbx
    jz .selected
    cmp dword [r12+16],BLK_REGISTRY_LIMIT
    jae .bad
    inc dword [r12+16]
    cmp dword [rbx+dev.class],CLASS_BLOCK
    jne .bad
    cmp qword [rbx+dev.ops],0
    je .bad
    test r13,r13
    jnz .next
    cmp dword [rbx+dev.health],HEALTH_OK
    jne .next
    mov r13,rbx                         ; exact blk_select first healthy policy
    mov eax,[r12+16]
    mov [r12],eax
.next:
    mov rbx,[rbx+dev.next]
    jmp .walk
.selected:
    test r13,r13
    jz .unlock
    mov eax,[r13+dev.health]
    mov [r12+8],eax
    mov eax,[r13+dev.prio]
    mov [r12+12],eax
    mov rdx,[r13+dev.ops]
    mov dword [r12+4],255
    lea rax,[rel ahci_ops]
    cmp rdx,rax
    jne .family_1
    mov dword [r12+4],1
    jmp .unlock
.family_1:
    lea rax,[rel nvme_ops]
    cmp rdx,rax
    jne .family_2
    mov dword [r12+4],2
    jmp .unlock
.family_2:
    lea rax,[rel msd_ops]
    cmp rdx,rax
    jne .family_3
    mov dword [r12+4],3
    jmp .unlock
.family_3:
    lea rax,[rel ramblk_ops]
    cmp rdx,rax
    jne .family_4
    mov dword [r12+4],4
    jmp .unlock
.family_4:
    lea rax,[rel nullblk_ops]
    cmp rdx,rax
    jne .family_5
    mov dword [r12+4],5
    jmp .unlock
.family_5:
    jmp .unlock
.bad:
    or dword [r12+20],1
.unlock:
    test r14d,r14d
    jz .release
    cmp dword [r12+20],0
    jne .release
    test r13,r13
    jz .release
    BLK_CENSUS_INSTANCE
.release:
    lea rdi,[rel blk_registry_lock]
    call spin_release
    jmp .done
.busy:
    mov dword [r12+20],2
.done:
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_fs_blockdev_0 0
align 8
times 48 db 0                  ; persist_gap_lock..blk_geom_token moved to WDATA_fs_blockdev_0_bss1: keeps the labels below at their offset mod 64

str_blk_seam_init:  db "[PAOS64] P3 blk: class core initialized [blockdev.class.seam.init]", 13, 10, 0
str_blk_ramblk_reg: db "[PAOS64] P3 blk: ramblk reference backend registered (seam-2nd) [blockdev.ramblk.registered]", 13, 10, 0
str_blk_nvme_reg:   db "[PAOS64] P3 blk: NVMe backend registered (degraded: no bus layer in keep) [blockdev.nvme.registered]", 13, 10, 0
str_blk_ahci_reg:   db "[PAOS64] P3 blk: AHCI backend registered (seam member) [blockdev.ahci.registered]", 13, 10, 0
str_blk_read_pre:   db "[PAOS64] P3 blk: read sector selftest PASS cksum=", 0
str_blk_read_post:  db " [blockdev.read.selftest]", 13, 10, 0
str_blk_write_pre:  db "[PAOS64] P3 blk: write round-trip selftest PASS cksum=", 0
str_blk_write_post: db " [blockdev.write.selftest]", 13, 10, 0
str_blk_flush_ok:   db "[PAOS64] P3 blk: flush selftest PASS [blockdev.flush.selftest]", 13, 10, 0
str_blk_flush_bad:  db "[PAOS64] P3 blk: flush selftest FAIL", 13, 10, 0
str_blk_reinit_ok:  db "[PAOS64] P3 blk: reinit wedge->reinit->verify PASS liveness=ok [blockdev.reinit.verify]", 13, 10, 0
str_blk_reinit_bad: db "[PAOS64] P3 blk: reinit selftest FAIL", 13, 10, 0
str_blk_nobackend:  db "[PAOS64] P3 blk: FAIL no healthy backend selected", 13, 10, 0
str_blk_geom_receipt_a: db "BLKGEOM token=", 0
str_blk_geom_receipt_b: db " variants=512e,4kn logical=512,4096 physical=4096,4096 max=8,8 bytes=4096,32768 checksum=", 0
str_blk_geom_receipt_c: db ",", 0
str_blk_geom_receipt_d: db " zero=refused lba_overflow=refused end=refused byte_overflow=refused above_max=refused invalid_geometry=refused write_gate=unchanged images_unchanged=1 reinit_geometry=stable backend_calls=4 iterator=generic iter_devices=2 iter_unique=2 identity_generation=stable prefix_policy=absent capabilities=read,write,flush", 13, 10, 0
str_blk_geom_ok: db "[PAOS64] blk: geometry and bounded range dispatch content KAT PASS [blk.geometry.range.kat]", 13, 10, 0
str_blk_geom_fail: db "[PAOS64] blk: geometry/range content KAT FAIL", 13, 10, 0
str_blk_selftest_sa_caller: db "blk_selftest", 0
str_blk_geom_sa_caller: db "blk_geometry_selftest", 0
%endmacro
WDATA_DEFER WDATA_fs_blockdev_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_fs_blockdev_0_bss1 0
alignb 8
persist_gap_lock:   resb 1
alignb 8
persist_gap_epoch:  resq 1
alignb 8
blk_registry_lock:  resb 1
alignb 8
blk_registry_head:  resq 1
blk_media_generation_next: resq 1
blk_scratch:        resb 4096
blk_scratch2:       resb 512
blk_geom_scratch:       resq 1
blk_geom_gen512:        resq 1
blk_geom_gen4kn:        resq 1
blk_geom_cksum512:      resq 1
blk_geom_cksum4kn:      resq 1
blk_geom_img512:        resq 1
blk_geom_img4kn:        resq 1
blk_geom_backend_calls: resq 1
blk_geom_token:         resq 1
%endmacro
WDATA_BSS_DEFER WDATA_fs_blockdev_0_bss1
; RCQ-20 S1S2 return-1: refused/failed blk_flush count since boot (zero-fill tail).
%macro WDATA_BSS_fs_blockdev_flush 0
alignb 8
blk_flush_failures: resq 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_blockdev_flush

; Read-only full registry ordinal (one-based), including degraded/dead members.
; Try-lock never waits, no caller handle/name dereferenced, bounded to 16/64.
; RDI=ordinal -> RAX=current static registered device or 0 (unavailable).
blk_registered_at:
    push rbx
    push r12
    mov r12d,edi
    dec edi
    cmp edi,16
    jae .none
    lea rdi,[rel blk_registry_lock]
    call spin_try_acquire
    test eax,eax
    jz .none
    mov rbx,[rel blk_registry_head]
.walk:
    test rbx,rbx
    jz .release
    cmp dword [rbx+dev.class],CLASS_BLOCK
    jne .invalid
    cmp qword [rbx+dev.ops],0
    je .invalid
    cmp qword [rbx+dev.info],0
    je .invalid
    dec r12d
    jz .release
    mov rbx,[rbx+dev.next]
    jmp .walk
.invalid:
    xor ebx,ebx
.release:
    lea rdi,[rel blk_registry_lock]
    call spin_release
    mov rax,rbx
    jmp .out
.none:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Read-only cached controller/media identity for an already registered handle.
; RSI ->96 caller bytes, cleared every time. u32 family,vmd,controller_kind,
; c0,c1,c2,unit,model_n; raw model[48] at32. Kind1 PCI B/D/F; kind2 USB
; exact xHCI instance+address; kind3 synthetic. No I/O or controller switching.
; Geometry is independently read from this exact dev.info by the projection.
%include "core/abi/vmd_selected_owner.inc"

blk_storage_identity:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov rdi,rsi
    xor eax,eax
    mov ecx,12
    cld
    rep stosq
    test rbx,rbx
    jz .out
    mov rdx,[rbx+dev.ops]
    lea rax,[rel ahci_ops]
    cmp rdx,rax
    jne .nvme
    lea rax,[rel ahci_devs]
    xor r13d,r13d
.ahci:
    cmp r13d,AHCI_MAX_DISKS
    jae .out
    cmp rax,rbx
    je .ahci_found
    add rax,dev_size
    inc r13d
    jmp .ahci
.ahci_found:
    mov dword [r12],1
    movzx eax,byte [rel ahci_vmd_child]
    mov [r12+4],eax
    test eax,eax
    jnz .ahci_vmd
    mov dword [r12+8],1
    mov eax,[rel ahci_busno]
    mov [r12+12],eax
    mov eax,[rel ahci_devno]
    mov [r12+16],eax
    mov eax,[rel ahci_fn]
    mov [r12+20],eax
    jmp .ahci_unit
.ahci_vmd:
    ; The legacy PCI scan cells do not describe a VMD child. Project the
    ; original selected child's ECAM-relative BDF from its live RAM lifetime.
    ; Missing/stale provenance leaves controller_kind unknown, not PCI 0:0.0.
    sub rsp,VSO_BYTES
    mov rdi,rsp
    call ahci_vmd_owner_snapshot
    cmp eax,1
    jne .ahci_vmd_done
    mov eax,[rsp+VSO_CHILD_BDF]
    mov edx,eax
    shr edx,16
    mov [r12+12],edx
    mov edx,eax
    shr edx,8
    and edx,31
    mov [r12+16],edx
    and eax,7
    mov [r12+20],eax
    mov dword [r12+8],1
.ahci_vmd_done:
    add rsp,VSO_BYTES
.ahci_unit:
    lea rax,[rel ahci_port]
    mov eax,[rax+r13*4]
    mov [r12+24],eax
    imul eax,r13d,41
    lea rsi,[rel ahci_models]
    add rsi,rax
    mov ecx,40
    jmp .model
.nvme:
    lea rax,[rel nvme_devs]
    cmp rbx,rax
    jne .usb
    lea rax,[rel nvme_ops]
    cmp rdx,rax
    jne .out
    mov dword [r12],2
    movzx eax,byte [rel nvme_vmd_child]
    mov [r12+4],eax
    mov dword [r12+8],1
    mov eax,[rel nvme_busno]
    mov [r12+12],eax
    mov eax,[rel nvme_devno]
    mov [r12+16],eax
    mov eax,[rel nvme_fn]
    mov [r12+20],eax
    mov rax,[rbx+dev.info]
    mov eax,[rax+blk_info.unit]
    mov [r12+24],eax
    lea rsi,[rel nvme_model]
    mov ecx,40
    jmp .model
.usb:
    lea rax,[rel msd_ops]
    cmp rdx,rax
    jne .ram
    mov dword [r12],3
    mov rdi,[rel msd_hc]
    test rdi,rdi
    jz .out
    call xhci_hc_instance
    test eax,eax
    js .out
    mov dword [r12+8],2
    mov [r12+12],eax
    movzx eax,byte [rel msd_port]
    mov [r12+24],eax
    mov rdi,rbx
    call msd_census_model
    test rax,rax
    jz .out
    mov rsi,rax
    mov ecx,28
    jmp .model
.ram:
    lea rax,[rel ramblk_ops]
    cmp rdx,rax
    jne .null
    mov dword [r12],4
    jmp .synthetic
.null:
    lea rax,[rel nullblk_ops]
    cmp rdx,rax
    jne .out
    mov dword [r12],5
.synthetic:
    mov dword [r12+8],3
    mov rax,[rbx+dev.info]
    mov eax,[rax+blk_info.unit]
    mov [r12+24],eax
    mov rsi,[rbx+dev.name]
    mov ecx,31
.model:
    test rsi,rsi
    jz .out
    xor edx,edx
.copy:
    mov al,[rsi+rdx]
    test al,al
    jz .trim
    mov [r12+rdx+32],al
    inc edx
    cmp edx,ecx
    jb .copy
.trim:
    test edx,edx
    jz .length
    cmp byte [r12+rdx+31],' '
    jne .length
    dec edx
    jmp .trim
.length:
    mov [r12+28],edx
.out:
    pop r13
    pop r12
    pop rbx
    ret
