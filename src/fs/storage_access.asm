;; MODULE fs/storage_access
;; LAYER 4
;; EXPORTS storage_access_decision, storage_access_binding_busy, storage_access_classify, storage_access_vmd_member, storage_access_require, storage_access_require_request, storage_access_permitted_request, storage_access_set_request_intent, storage_access_request_intent, storage_access_request_owner_swap, storage_access_request_owner, storage_access_write_admitted, storage_access_writer_grant, storage_access_writer_revoke, storage_access_grants_clear, storage_access_job_grant, storage_access_job_grant_carried, storage_access_job_require, storage_access_job_step_end, storage_access_job_revoke, storage_access_owned_op_begin, storage_access_owned_op_end, storage_access_owned_admitted, storage_access_owned_latched
;; IMPORTS fs/blockdev, fs/vol_owner, core/smp, dev/blk/ahci, dev/blk/nvme, dev/blk/ramblk, dev/blk/nullblk, boot/serial, boot/boot_v2_handoff
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only  (RCQ-21 SA2a: the owned-op slot and S6 tables are unlocked module state)
; ============================================================================
; fs/storage_access — the ONE storage-access permission gate (PETER RULING
; 2026-09-29 21:25; SPRINT ADMIN 21:23/21:24 ROB-03 data-safety directive).
;
; Canon: PaOS may write any connected disk, but SENSITIVE writes need explicit
; special permission, and NO background/implicit feature may perform one.
; Sensitive = another OS's partition, raw sectors / unallocated GPT gaps,
; partition tables, the ESP and boot areas, whole-disk operations. Every write
; path asks this gate first; a refusal is fail-closed with a marker, never a
; silent fallback to another location.
;
; Classification is read from the LIVE disk at call time (never from a cached
; model name or a remembered layout):
;   SA_CLASS_PAOS_OWNED   range lies inside storage PaOS provably owns. HOOK:
;                         a PaOS partition-type GUID / Vault is not minted yet
;                         (planner + Guardian saga), so nothing is classified
;                         owned today — documented default, not an invented one.
;   SA_CLASS_TEST_SCRATCH RAM/null backends (by ops vtable), or a QEMU-model disk
;                         (IDENTIFY model contains "QEMU") WITHOUT a GPT: the
;                         harness's throwaway vvfat/raw scratch media. A QEMU disk
;                         that DOES carry a GPT is treated as a real layout
;                         (ROB-03: Dell-shaped Windows GPT on ahci0).
;   SA_CLASS_SENSITIVE    everything else: any raw write to a GPT disk (gap,
;                         tables, ESP, foreign partitions), and every non-QEMU
;                         disk without a proven PaOS-owned range.
;   SA_CLASS_UNKNOWN      unreadable/invalid device or range -> always refused.
;
; Before any class: a disk behind Intel VMD (storage_access_vmd_member) is never
; written, whatever the intent. Its HBA may serve an Intel RST RAID array whose
; metadata PaOS does not parse, so a raw write can corrupt the array (root 75030,
; product data safety; NVMe behind VMD root 75379). require refuses it with its
; own marker; ahci_op_write / nvme_op_write refuse it again for every grant kind.
; Reads stay allowed.
;
; Intents: SA_INTENT_IMPLICIT (background/automatic: session save, self-tests)
; may write only OWNED or TEST_SCRATCH. SA_INTENT_SPECIAL means the caller holds
; explicit special permission (Stage B: owner-signed sensitive verbs, audited);
; it additionally admits SENSITIVE. The account hierarchy that may grant or
; restrict special permission is an open planner/Guardian design question.
;
; UEFI variables are the NVRAM class of this same gate (PETER 2026-09-30 06:22):
; boot/nvram_access.asm storage_access_nvram_require - PaOS-namespace variables
; NORMAL, firmware-global / Secure Boot / shim / foreign variables SENSITIVE
; (SPECIAL intent only, audited). It sits at L0 so the L0 Boot-v2 health
; publisher can call it downward; every PaOS SetVariable site routes through it.
; ============================================================================

SA_CLASS_UNKNOWN      equ 0
SA_CLASS_PAOS_OWNED   equ 1
SA_CLASS_TEST_SCRATCH equ 2
SA_CLASS_SENSITIVE    equ 3
SA_INTENT_IMPLICIT    equ 0
SA_INTENT_SPECIAL     equ 1
SA_SECTOR_MAX         equ 4096
SA_GPT_SIGNATURE      equ 0x5452415020494645    ; "EFI PART"
SA_GRANT_SLOTS        equ 4                     ; power of two: latest grant per device
SA_GRANT_SZ           equ 24                    ; dev, lba, count
SA_JOB_SLOTS          equ 2                     ; live job windows; a full table refuses (never evicts)
SA_JOB_SZ             equ 32                    ; tag, dev, lba, count
SA_OWNED_SEQ_LIMIT    equ 0x00FFFFFFFFFFFFFF    ; owned-op handles never wrap: begin latches refusal here

; ---- SEC-S6 / audit Task 3025: the gate is STRUCTURAL inside blk_write ------
; Every permit this gate gives (require / require_request / permitted_request)
; records a GRANT {dev, lba, count}, the latest per device. blk_write admits a
; write only inside a live grant on the same device, so a writer that never
; asked, or writes outside what it asked for, is refused by the class core
; itself (BLK_ERR_WRITE_GATE), not by convention. Grants are cleared at every
; request boundary (storage_access_set_request_intent: remote begin/end). Local
; GUI/terminal commands and background ticks are not boundaries, so a grant from
; one of those lives until the next remote request or until it is replaced. FAT32, which decides
; under its own policy (fd_mutation_authorized, partition-bounded), holds a
; WRITER grant only around its own write (storage_access_writer_grant/revoke).

; sa_grant_record(RDI=dev, RSI=lba, RDX=count). clobbers: R8-R10.
sa_grant_record:
    lea  r8, [rel sa_grants]
    xor  r9d, r9d
.find:
    cmp  r9d, SA_GRANT_SLOTS
    jae  .new
    imul r10, r9, SA_GRANT_SZ
    cmp  [r8 + r10], rdi
    je   .put
    inc  r9d
    jmp  .find
.new:
    mov  r9d, [rel sa_grant_next]
    inc  dword [rel sa_grant_next]
    and  r9d, SA_GRANT_SLOTS - 1
    imul r10, r9, SA_GRANT_SZ
.put:
    mov  [r8 + r10], rdi
    mov  [r8 + r10 + 8], rsi
    mov  [r8 + r10 + 16], rdx
    ret

; storage_access_grants_clear — drop every request grant (not the writer grant).
;   clobbers: R8, R9.
storage_access_grants_clear:
    lea  r8, [rel sa_grants]
    xor  r9d, r9d
.zero:
    mov  qword [r8 + r9*8], 0
    inc  r9d
    cmp  r9d, SA_GRANT_SLOTS * SA_GRANT_SZ / 8
    jb   .zero
    ret

; storage_access_binding_busy -> EAX 1 while a writer/owned op or retained
; asynchronous job window is active. Pure BSP state read; no authority changes.
storage_access_binding_busy:
    cmp  qword [rel sa_writer_dev], 0
    jne  .busy
    cmp  qword [rel sa_owned_handle], 0
    jne  .busy
    lea  rdx, [rel sa_jobs]
    xor  ecx, ecx
.next:
    cmp  qword [rdx + rcx], 0
    jne  .busy
    add  ecx, SA_JOB_SZ
    cmp  ecx, SA_JOB_SLOTS * SA_JOB_SZ
    jb   .next
    xor  eax, eax
    ret
.busy:
    mov  eax, 1
    ret

; storage_access_writer_grant(RDI=dev, RSI=lba, RDX=count) / _writer_revoke —
;   an own-policy writer's window for the duration of ONE write. Preserves all
;   registers.
storage_access_writer_grant:
    mov  [rel sa_writer_dev], rdi
    mov  [rel sa_writer_lba], rsi
    mov  [rel sa_writer_count], rdx
    ret
storage_access_writer_revoke:
    mov  qword [rel sa_writer_dev], 0
    ret

; ---- Job windows (rc-fs RCQ-20 copy job) ------------------------------------
; A background job (an ext4 FSCOPY) steps from the idle tick, outside any
; request, so its per-transaction gate would see IMPLICIT intent and refuse a
; SENSITIVE volume. storage_access_job_grant takes a JOB WINDOW while the
; owner's request is still in flight (FSCOPY BEGIN): it is permitted only where
; storage_access_require_request permits under the CURRENT intent, and audited
; the same way. The window survives request boundaries. It admits nothing by
; itself: each step presents its tag to storage_access_job_require, which
; checks the range against the window and records the ordinary request grant
; for exactly that range, so only a caller holding the tag inherits it.
; storage_access_job_step_end(tag) drops that grant when the step returns (a
; cadence tick is not a request boundary, so nothing else would), keeping the
; window. storage_access_job_revoke ends the window (DONE / CANCELLED / FAILED
; / disarm) and drops the same leftover grant.

; sa_job_free_slot -> RAX byte offset of a free job slot / -1 none. clobbers R9.
sa_job_free_slot:
    lea  r9, [rel sa_jobs]
    xor  eax, eax
.scan:
    cmp  qword [r9 + rax], 0
    je   .ret
    add  eax, SA_JOB_SZ
    cmp  eax, SA_JOB_SLOTS * SA_JOB_SZ
    jb   .scan
    mov  rax, -1
.ret:
    ret

; sa_job_find(RCX=tag) -> RAX byte offset of the live window / -1. clobbers R9.
sa_job_find:
    lea  r9, [rel sa_jobs]
    test rcx, rcx
    jz   .none                               ; tag 0 marks a free slot, never a job
    xor  eax, eax
.scan:
    cmp  [r9 + rax], rcx
    je   .ret
    add  eax, SA_JOB_SZ
    cmp  eax, SA_JOB_SLOTS * SA_JOB_SZ
    jb   .scan
.none:
    mov  rax, -1
.ret:
    ret

; storage_access_job_grant(RDI=dev, RSI=lba, RDX=count, R8=caller tag cstr)
;   -> RAX job tag (> 0) / -1 refused (gate refusal marker, a zero/wrapping
;   range, or no free slot).
storage_access_job_grant:
    movzx ecx, byte [rel sa_request_intent]   ; the CURRENT request's intent decides
.carried:                                    ; storage_access_job_grant_carried joins here with its own ECX
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14d, ecx                           ; the deciding intent: callee-saved until the gate (rev 3 (i))
    test rdx, rdx
    jz   .no
    mov  rax, rsi
    add  rax, rdx
    jc   .no
    call sa_job_free_slot                    ; refuse before the gate audits a grant
    test rax, rax
    js   .no
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, r13
    mov  ecx, r14d
    call storage_access_require              ; that intent decides (R8 = caller)
    test rax, rax
    jnz  .no
    call sa_job_free_slot
    test rax, rax
    js   .no
    inc  qword [rel sa_job_seq]             ; 64-bit: never reissues a tag
    jnz  .seq
    inc  qword [rel sa_job_seq]             ; 0 marks a free slot, never a tag
.seq:
    mov  rdx, [rel sa_job_seq]
    mov  [r9 + rax], rdx
    mov  [r9 + rax + 8], rbx
    mov  [r9 + rax + 16], r12
    mov  [r9 + rax + 24], r13
    mov  rax, rdx
    jmp  .out
.no:
    mov  rax, -1
.out:
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; storage_access_job_grant_carried(RDI=dev, RSI=lba, RDX=count, ECX=SA_INTENT_*, R8=caller tag cstr) -> as
;   storage_access_job_grant, decided under the intent a queued ext4 copy carried from its owner's console
;   request (RCQ-20 S5c; rc-sec rev 3 6454fc74). ONE caller, ext_w_job_open_carried (storage_grant_lint). It
;   never reads or writes the request's intent or owner bit; the body above is the one copy both share.
storage_access_job_grant_carried:
    jmp  storage_access_job_grant.carried

; storage_access_job_require(RDI=dev, RSI=lba, RDX=count, RCX=job tag) -> RAX 0 /
;   -1 (counted). [lba, lba+count) on dev must lie inside the live window `tag`;
;   then the range is recorded as a request grant (blk_write's admission).
;   Preserves RDI, RSI, RDX, RCX; clobbers RAX, R8-R11.
storage_access_job_require:
    test rdx, rdx
    jz   .no
    mov  r11, rsi
    add  r11, rdx                            ; the step's end (exclusive)
    jc   .no
    call sa_job_find
    test rax, rax
    js   .no
    cmp  rdi, [r9 + rax + 8]
    jne  .no
    mov  r10, [r9 + rax + 16]
    cmp  rsi, r10
    jb   .no
    add  r10, [r9 + rax + 24]
    cmp  r11, r10
    ja   .no
    inc  qword [rel sa_job_admits]
    call sa_grant_record                     ; exactly this range, latest for the device
    xor  eax, eax
    ret
.no:
    inc  qword [rel sa_job_refusals]
    mov  rax, -1
    ret

; sa_job_drop_grant(R8=job slot) - zero a request grant on the job's device that
;   lies inside the window. clobbers RCX, R9-R11.
sa_job_drop_grant:
    mov  r11, [r8 + 16]
    add  r11, [r8 + 24]                      ; window end
    lea  r9, [rel sa_grants]
    xor  r10d, r10d
.grant:
    mov  rcx, [r8 + 8]
    cmp  [r9 + r10], rcx
    jne  .next
    mov  rcx, [r9 + r10 + 8]
    cmp  rcx, [r8 + 16]
    jb   .next
    add  rcx, [r9 + r10 + 16]
    jc   .next
    cmp  rcx, r11
    ja   .next
    mov  qword [r9 + r10], 0                 ; the job's leftover grant on that device
.next:
    add  r10d, SA_GRANT_SZ
    cmp  r10d, SA_GRANT_SLOTS * SA_GRANT_SZ
    jb   .grant
    ret

; storage_access_job_step_end(RDI=job tag) -> RAX 0 / -1 no such live window.
;   Called after EVERY copy step: drops the step's request grant, keeps the
;   window. clobbers RAX, RCX, R8-R11.
storage_access_job_step_end:
    mov  rcx, rdi
    call sa_job_find
    test rax, rax
    js   .out
    lea  r8, [r9 + rax]
    call sa_job_drop_grant
    xor  eax, eax
.out:
    ret

; storage_access_job_revoke(RDI=job tag) -> RAX 0 / -1 no such live window. A
;   request grant on the job's device that lies inside the window goes with it,
;   and so does any live owned filesystem operation (fail-closed: its later
;   writes are refused). clobbers RAX, RCX, R8-R11.
storage_access_job_revoke:
    mov  qword [rel sa_owned_handle], 0     ; RCQ-21 SA2a: a job's end/cancel ends any owned op too
    mov  rcx, rdi
    call sa_job_find
    test rax, rax
    js   .out
    lea  r8, [r9 + rax]
    call sa_job_drop_grant
    xor  eax, eax
    mov  [r8], rax
    mov  [r8 + 8], rax
    mov  [r8 + 16], rax
    mov  [r8 + 24], rax
.out:
    ret

; storage_access_write_admitted(RDI=dev, RSI=lba, RDX=count) -> RAX 0 admitted /
;   -1 refused (counted in sa_unadmitted_writes). [lba, lba+count) must lie inside
;   the writer grant or a request grant on the SAME device. Preserves RDI, RSI,
;   RDX, RCX; clobbers RAX, R8-R11.
storage_access_write_admitted:
    test rdx, rdx
    jz   .no                                 ; a zero-sector write is never admitted
    call sa_try_write_refused                ; RCQ-29 live Try: no grant reaches a real disk
    test rax, rax
    jnz  .no
    mov  r11, rsi
    add  r11, rdx                            ; end (exclusive)
    jc   .no
    cmp  rdi, [rel sa_writer_dev]
    jne  .table
    mov  r8, [rel sa_writer_lba]
    cmp  rsi, r8
    jb   .table
    add  r8, [rel sa_writer_count]
    jc   .table
    cmp  r11, r8
    jbe  .yes
.table:
    lea  r8, [rel sa_grants]
    xor  r9d, r9d
.loop:
    cmp  r9d, SA_GRANT_SLOTS
    jae  .no
    imul r10, r9, SA_GRANT_SZ
    cmp  rdi, [r8 + r10]
    jne  .next
    mov  rax, [r8 + r10 + 8]
    cmp  rsi, rax
    jb   .next
    add  rax, [r8 + r10 + 16]
    jc   .next
    cmp  r11, rax
    jbe  .yes
.next:
    inc  r9d
    jmp  .loop
.no:
    inc  qword [rel sa_unadmitted_writes]
    mov  rax, -1
    ret
.yes:
    xor  eax, eax
    ret

; sa_try_write_refused(RDI=dev) -> RAX 0 / -1 refused. RCQ-29 live Try: booted from
;   a live Try USB, only the RAM and null backends, which never persist, may take a
;   (still admitted) write. Every other device (internal SATA/NVMe, the USB itself)
;   is refused whatever grant or owned op exists, counted in sa_try_refused_writes
;   and reported once. Both admissions call it first: storage_access_write_admitted
;   (generic blk_write) and storage_access_owned_admitted (blk_write_owned).
;   Outside Try, RAX 0. Preserves RDI, RSI, RDX, RCX, R8; clobbers RAX, R9-R11.
sa_try_write_refused:
    xor  eax, eax
    cmp  byte [rel pbm_try_media], 1
    jne  .out
    mov  r9, [rdi + dev.ops]
    lea  r10, [rel ramblk_ops]
    cmp  r9, r10
    je   .out
    lea  r10, [rel nullblk_ops]
    cmp  r9, r10
    je   .out
    inc  qword [rel sa_try_refused_writes]
    cmp  byte [rel sa_try_refusal_reported], 0
    jne  .refused
    mov  byte [rel sa_try_refusal_reported], 1
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    lea  rdi, [rel str_sa_try_refused]
    call serial_string
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
.refused:
    mov  rax, -1
.out:
    ret

; ---- RCQ-21 SA2a: owned filesystem operations ---------------------------------
; (rc-sec rulings 07:21:38 and 08:45:23; rc-fs SA2 note 6c1abb17.) A volume the
; owner adopted (fs/vol_owner) becomes write authority ONLY inside an owned
; filesystem operation, and ONLY for writes presented through blk_write_owned.
; This is a distinct kind: it records no S6 grant, storage_access_write_admitted
; never reads it, and a generic blk_write on the same device and range gains
; nothing while it is live (raw / BLK* / SPECIAL / scratch stay as they were).
;
;   storage_access_owned_op_begin(dev, first, count, vol_owner token) -> handle
;     One live op at a time (a nested begin is refused and never replaces the
;     live one). The whole [first, first+count) must pass vol_owner_live_check
;     now. Handles are a monotonic sequence and never reused; at
;     SA_OWNED_SEQ_LIMIT begin latches refusal for the rest of the boot.
;   storage_access_owned_op_end(handle): clears the op only when the handle is
;     the live one, so a stale end can never clear a later op. Every request
;     boundary (storage_access_set_request_intent) and every job end or cancel
;     (storage_access_job_revoke) clears it as well.
;   storage_access_owned_admitted(dev, lba, n, handle): per write, immediately
;     before blk_write's backend dispatch: the live handle, the op's device,
;     overflow-safe containment in the op window, then vol_owner_live_check
;     (a full re-probe of the partition table and filesystem identity and
;     eligibility, SEC ae3d2900) for exactly this range.
;
; Serialization: BSP only, enforced at run time (sa_owned_on_bsp) and by
; bsp_only_context_lint (fs/storage_access, fs/blockdev and fs/vol_owner are
; declared bsp_only: no AP entry or IDT gate reaches them). The path re-probe -> backend entry
; has no yield, scheduler or callback seam: vol_owner's reads are blk_read into
; AHCI/NVMe busy polls (tsc_delay_us is a pause spin) or the xHCI bulk drain,
; which only records completion state; no lock is held across any IO.

; sa_owned_on_bsp -> ZF set when this CPU is the BSP. clobbers RAX, RCX, RDX, RSI.
sa_owned_on_bsp:
    call smp_lapic_read_id
    cmp  eax, [rel smp_bsp_apic]
    ret

; storage_access_owned_op_begin(RDI=dev, RSI=first, RDX=count, RCX=token)
;   -> RAX op handle (nonzero) / 0 refused.
storage_access_owned_op_begin:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    call sa_owned_on_bsp
    jne  .no
    cmp  byte [rel sa_owned_latched], 0
    jne  .no
    cmp  qword [rel sa_owned_handle], 0
    jne  .no                                 ; one op at a time; the live one is kept
    test rbx, rbx
    jz   .no
    test r13, r13
    jz   .no
    mov  rax, r12
    add  rax, r13
    jc   .no
    mov  rax, [rel sa_owned_seq]
    mov  rcx, SA_OWNED_SEQ_LIMIT
    cmp  rax, rcx
    jae  .latch
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, r14
    call vol_owner_live_check
    test eax, eax
    jnz  .no
    mov  rax, [rel sa_owned_seq]
    inc  rax
    mov  [rel sa_owned_seq], rax
    mov  [rel sa_owned_dev], rbx
    mov  [rel sa_owned_first], r12
    mov  [rel sa_owned_count], r13
    mov  [rel sa_owned_token], r14
    mov  [rel sa_owned_handle], rax
    inc  qword [rel sa_owned_begins]
    jmp  .out
.latch:
    mov  byte [rel sa_owned_latched], 1
.no:
    inc  qword [rel sa_owned_refusals]
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; storage_access_owned_op_end(RDI=handle) — preserves every register.
storage_access_owned_op_end:
    test rdi, rdi
    jz   .out
    cmp  rdi, [rel sa_owned_handle]
    jne  .out                                ; stale or foreign: never clears a later op
    mov  qword [rel sa_owned_handle], 0
    mov  qword [rel sa_owned_token], 0
.out:
    ret

; storage_access_owned_admitted(RDI=dev, RSI=lba, RDX=count, R8=handle)
;   -> RAX 0 admitted / -1. Preserves RDI, RSI, RDX, RCX; clobbers R8-R11.
storage_access_owned_admitted:
    call sa_try_write_refused                ; RCQ-29 live Try: an owned op is no exception
    test rax, rax
    jnz  .try_refused
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    mov  rbx, r8
    call sa_owned_on_bsp
    jne  .no
    test rbx, rbx
    jz   .no
    cmp  rbx, [rel sa_owned_handle]
    jne  .no
    mov  rdi, [rsp + 32]
    mov  rsi, [rsp + 24]
    mov  rdx, [rsp + 16]
    cmp  rdi, [rel sa_owned_dev]
    jne  .no
    test rdx, rdx
    jz   .no
    mov  rax, rsi                            ; rel = lba - first < count, n <= count - rel
    sub  rax, [rel sa_owned_first]
    jb   .no
    mov  rcx, [rel sa_owned_count]
    cmp  rax, rcx
    jae  .no
    sub  rcx, rax
    cmp  rdx, rcx
    ja   .no
    mov  rcx, [rel sa_owned_token]
    call vol_owner_live_check
    test eax, eax
    jnz  .no
    cmp  rbx, [rel sa_owned_handle]          ; L3: still the live op after the re-probe
    jne  .no
    inc  qword [rel sa_owned_admits]
    xor  eax, eax
    jmp  .out
.no:
    inc  qword [rel sa_owned_refusals]
    mov  rax, -1
.out:
    pop  rbx
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret
.try_refused:
    inc  qword [rel sa_owned_refusals]
    ret                                     ; RAX -1 from sa_try_write_refused

; sa_dev_is_qemu(RDI=dev) -> RAX 1 if the device's backend reports a QEMU model.
sa_dev_is_qemu:
    mov  rax, [rdi + dev.name]
    test rax, rax
    jz   .no
    cmp  byte [rax], 'a'                    ; ahci*
    je   .ahci
    cmp  byte [rax], 'n'                    ; nvme* (RAM/null backends handled by the caller)
    jne  .no
    cmp  byte [rax + 1], 'v'
    jne  .no
    jmp  nvme_model_is_qemu
.ahci:
    jmp  ahci_model_is_qemu
.no:
    xor  eax, eax
    ret

; storage_access_classify(RDI=dev, RSI=lba, RDX=count) -> RAX SA_CLASS_*.
; Reads LBA 1 of the live device. Clobbers caller-saved registers.
storage_access_classify:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    test rbx, rbx
    jz   .unknown
    test r13, r13
    jz   .unknown
    mov  rax, [rbx + dev.ops]               ; backend identity by vtable, never by diagnostic name
    lea  rcx, [rel ramblk_ops]              ; RAM reference backend — never persistent
    cmp  rax, rcx
    je   .scratch
    lea  rcx, [rel nullblk_ops]             ; null backend — discards
    cmp  rax, rcx
    je   .scratch
    mov  rax, [rbx + dev.name]
    test rax, rax
    jz   .unknown
    mov  rax, [rbx + dev.info]              ; the probe reads ONE logical sector: it must fit sa_sector
    test rax, rax
    jz   .unknown
    mov  ecx, [rax + blk_info.logical_sector_bytes]
    test ecx, ecx
    jnz  .lsb
    mov  ecx, [rax + blk_info.sector_size]
.lsb:
    cmp  ecx, SA_SECTOR_MAX
    ja   .unknown
    mov  rdi, rbx
    mov  rsi, 1                             ; primary GPT header lives at LBA 1
    mov  rdx, 1
    lea  rcx, [rel sa_sector]
    call blk_read
    test rax, rax
    jnz  .unknown
    mov  rax, SA_GPT_SIGNATURE
    cmp  [rel sa_sector], rax
    je   .sensitive                         ; GPT disk: every raw write is sensitive (owned-partition hook: none minted)
    mov  rdi, rbx
    call sa_dev_is_qemu
    test rax, rax
    jz   .sensitive                         ; non-QEMU disk without a proven PaOS range
.scratch:
    mov  eax, SA_CLASS_TEST_SCRATCH
    jmp  .out
.sensitive:
    mov  eax, SA_CLASS_SENSITIVE
    jmp  .out
.unknown:
    mov  eax, SA_CLASS_UNKNOWN
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Request-scoped intent (Stage B). The authenticated transport sets SPECIAL only while a request that
; carries a VERIFIED OWNER AUTH1 ticket is in flight (svc/command_auth remote_begin/remote_end); every
; other context — boot, the network poll loop, timers, unsigned verbs — runs IMPLICIT. Never derived from
; the global current principal (which is shared with the local session).
storage_access_set_request_intent:          ; EDI = SA_INTENT_*  (clobbers R8, R9)
    mov  [rel sa_request_intent], dil
    mov  qword [rel sa_owned_handle], 0     ; RCQ-21 SA2a: and every owned filesystem operation
    jmp  storage_access_grants_clear        ; a request boundary ends every request grant

storage_access_request_intent:              ; -> EAX = current SA_INTENT_*
    movzx eax, byte [rel sa_request_intent]
    ret

; Request-scoped OWNER bit (RCQ-21 SA2b, rc-sec S1). 1 only while a request from the verified OWNER principal is
; in flight: a console OWNER, a verified owner AUTH ticket, or an owner SSH key. It is never 1 for SYSTEM, ADVISOR,
; the AI hook or an injected line. The command layer sets it per dispatch frame and restores the outer frame's bit
; on return; the owned-volume writers read it (ext4_write: arm, and every request-driven transaction). It grants no
; access by itself: an owned write still needs a live owned op (storage_access_owned_admitted).
storage_access_request_owner_swap:          ; EDI = 0/1 -> EAX = the previous bit; clobbers RDI only
    movzx eax, byte [rel sa_request_owner]
    and  edi, 1
    mov  [rel sa_request_owner], dil
    ret

storage_access_request_owner:               ; -> EAX = 0/1
    movzx eax, byte [rel sa_request_owner]
    ret

; storage_access_owned_latched -> EAX 1 once the owned-op handle space is exhausted (no owned op begins again
;   this boot) / 0. Read-only; RCQ-20 S5c: a carried BEGIN refuses on it (rc-sec rev 3 C3 (h)).
storage_access_owned_latched:
    movzx eax, byte [rel sa_owned_latched]
    ret

; storage_access_require_request(RDI=dev, RSI=lba, RDX=count, R8=caller tag) -> RAX 0 / -1 (marker on refusal)
storage_access_require_request:
    movzx ecx, byte [rel sa_request_intent]
    jmp  storage_access_require

; storage_access_permitted_request(RDI=dev, RSI=lba, RDX=count) -> RAX 0 permitted / -1 refused. NO marker:
; for idempotent background retry loops that must decide once, not log every tick.
storage_access_permitted_request:
    mov  [rel sa_req_dev], rdi
    mov  [rel sa_req_lba], rsi
    mov  [rel sa_req_count], rdx
    movzx ecx,byte [rel sa_request_intent]
    call storage_access_decision
    test rax,rax
    jz .yes
.no:
    mov  rax, -1
    ret
.yes:
    mov  rdi, [rel sa_req_dev]
    mov  rsi, [rel sa_req_lba]
    mov  rdx, [rel sa_req_count]
    call sa_grant_record                     ; the decision is the write's admission
    xor  eax, eax
    ret

; storage_access_require(RDI=dev, RSI=lba, RDX=count, RCX=SA_INTENT_*, R8=caller tag cstr)
;   -> RAX 0 permitted / -1 refused (serial marker names class, intent, caller, device, lba).
storage_access_require:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rcx
    mov  r14, r8
    mov  [rel sa_req_count], rdx
    call storage_access_decision
    mov r15d,r9d
    cmp r10d,1                         ; VMD is refused before any live read
    je .vmd
    test rax,rax
    jz .ok
.refuse:
    lea  rdi, [rel str_sa_refused]
    call serial_string
    mov  rdi, r15
    call serial_hex64
    lea  rdi, [rel str_sa_intent]
    call serial_string
    mov  rdi, r13
    call serial_hex64
    lea  rdi, [rel str_sa_caller]
    call serial_string
    mov  rdi, r14
    test rdi, rdi
    jnz  .tag
    lea  rdi, [rel str_sa_unknown]
.tag:
    call serial_string
    lea  rdi, [rel str_sa_dev]
    call serial_string
    mov  rdi, [rbx + dev.name]
    test rdi, rdi
    jnz  .name
    lea  rdi, [rel str_sa_unknown]
.name:
    call serial_string
    lea  rdi, [rel str_sa_lba]
    call serial_string
    mov  rdi, r12
    call serial_hex64
    lea  rdi, [rel str_sa_marker]
    call serial_string
    mov  rax, -1
    jmp  .out
.vmd:
    lea  rdi, [rel str_sa_vmd_refused]
    call serial_string
    mov  rdi, r14
    test rdi, rdi
    jnz  .vtag
    lea  rdi, [rel str_sa_unknown]
.vtag:
    call serial_string
    lea  rdi, [rel str_sa_dev]
    call serial_string
    mov  rdi, [rbx + dev.name]
    test rdi, rdi
    jnz  .vname
    lea  rdi, [rel str_sa_unknown]
.vname:
    call serial_string
    lea  rdi, [rel str_sa_lba]
    call serial_string
    mov  rdi, r12
    call serial_hex64
    lea  rdi, [rel str_sa_vmd_marker]
    call serial_string
    mov  rax, -1
    jmp  .out
.ok:
    cmp  r15d, SA_CLASS_SENSITIVE
    jne  .ok_plain
    ; audit: every SENSITIVE write that explicit owner authority admits is logged (PETER 21:25)
    lea  rdi, [rel str_sa_special]
    call serial_string
    mov  rdi, r14
    test rdi, rdi
    jnz  .atag
    lea  rdi, [rel str_sa_unknown]
.atag:
    call serial_string
    lea  rdi, [rel str_sa_dev]
    call serial_string
    mov  rdi, [rbx + dev.name]
    test rdi, rdi
    jnz  .aname
    lea  rdi, [rel str_sa_unknown]
.aname:
    call serial_string
    lea  rdi, [rel str_sa_lba]
    call serial_string
    mov  rdi, r12
    call serial_hex64
    lea  rdi, [rel str_sa_special_marker]
    call serial_string
    inc  qword [rel sa_special_grants]
.ok_plain:
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, [rel sa_req_count]
    call sa_grant_record                     ; SEC-S6: this permit admits exactly this range in blk_write
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; storage_access_vmd_member(RDI=dev) -> EAX 1 when dev is an AHCI disk whose HBA, or
;   an NVMe namespace whose controller, came from the Intel VMD child domain
;   (ahci_vmd_child / nvme_vmd_child), else 0. Backend identity by vtable, never
;   by name. Clobbers EAX, RCX only.
storage_access_vmd_member:
    xor  eax, eax
    test rdi, rdi
    jz   .out
    lea  rcx, [rel ahci_ops]
    cmp  [rdi + dev.ops], rcx
    jne  .nvme
    cmp  byte [rel ahci_vmd_child], 0
    setne al
    ret
.nvme:
    lea  rcx, [rel nvme_ops]
    cmp  [rdi + dev.ops], rcx
    jne  .out
    cmp  byte [rel nvme_vmd_child], 0
    setne al
.out:
    ret

str_sa_vmd_refused: db "[PAOS64] storage: write REFUSED: Intel VMD/RST RAID member (RST metadata not parsed) caller=", 0
str_sa_vmd_marker:  db " [storage.access.vmd-raid-refused]", 13, 10, 0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_fs_storage_access_0 0
str_sa_refused: db "[PAOS64] storage: access REFUSED (fail-closed) class=", 0
str_sa_intent:  db " intent=", 0
str_sa_caller:  db " caller=", 0
str_sa_dev:     db " dev=", 0
str_sa_lba:     db " lba=", 0
str_sa_marker:  db " [storage.access.refused]", 13, 10, 0
str_sa_unknown: db "?", 0
str_sa_special: db "[PAOS64] storage: SENSITIVE write GRANTED by explicit owner authority (audited) caller=", 0
str_sa_special_marker: db " [storage.access.special]", 13, 10, 0
str_sa_try_refused: db "[PAOS64] storage: live Try boot; persistent block write refused (first of any; RAM/null only) [storage.try.write-refused]", 13, 10, 0
; sa_request_intent..sa_sector moved to WDATA_fs_storage_access_0_bss1 (zero-fill tail)
%endmacro
WDATA_DEFER WDATA_fs_storage_access_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_fs_storage_access_0_bss1 0
resb 38                 ; keeps sa_request_intent at its WDATA offset mod 64
sa_request_intent: resb 1
sa_request_owner: resb 1                    ; RCQ-21 SA2b: the in-flight request is the verified OWNER
alignb 8
sa_special_grants: resq 1
sa_unadmitted_writes: resq 1                ; blk_write refusals: no grant covered the range
sa_req_dev:     resq 1
sa_req_lba:     resq 1
sa_req_count:   resq 1
sa_writer_dev:  resq 1
sa_writer_lba:  resq 1
sa_writer_count: resq 1
sa_grant_next:  resd 1
alignb 8
sa_grants:      resb SA_GRANT_SLOTS * SA_GRANT_SZ
sa_job_seq:     resq 1                      ; last job tag issued (tags start at 1)
sa_job_admits:  resq 1                      ; job_require: ranges admitted inside a window
sa_job_refusals: resq 1                     ; job_require: unknown tag, other device or outside
sa_jobs:        resb SA_JOB_SLOTS * SA_JOB_SZ
sa_owned_handle: resq 1                     ; RCQ-21 SA2a: the live owned op (0 = none)
sa_owned_seq:   resq 1                      ; last handle issued (never reused)
sa_owned_dev:   resq 1
sa_owned_first: resq 1
sa_owned_count: resq 1
sa_owned_token: resq 1
sa_owned_begins: resq 1
sa_owned_admits: resq 1
sa_owned_refusals: resq 1
sa_owned_latched: resb 1                    ; handle space exhausted: no owned op for this boot
sa_try_refusal_reported: resb 1             ; RCQ-29: the one Try refusal line was printed
alignb 8
sa_try_refused_writes: resq 1               ; RCQ-29: persistent-device writes refused in a Try boot
alignb 16
sa_sector:      resb SA_SECTOR_MAX           ; one logical sector (512e or 4Kn)
%endmacro
WDATA_BSS_DEFER WDATA_fs_storage_access_0_bss1

%include "fs/storage_access_decision.asm"
