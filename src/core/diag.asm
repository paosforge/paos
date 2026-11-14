;; MODULE core/diag
;; LAYER 1
;; EXPORTS diag_init, diag_phase_enter, diag_phase_exit, diag_boot_phase_record, diag_ring_append, diag_ring_fault, diag_ring_mca, diag_mark_boot_healthy, diag_persist_flush, diag_report_prev, diag_prev_fault_at, diag_prev_record_at, diag_live_record_copy, diag_selftest, diag_prev_health_faults, diag_prev_health_valid, diag_crash_slot_fatal, diag_crash_record_project, diag_crash_record_status, diag_crash_record, diag_ring_dropped, diag_prev_crash_slot
;; IMPORTS core/crash_identity, boot/serial, boot/paging, core/idt, core/log, core/lib/mem, core/lib/str, core/build_id, boot/boot_v2_handoff, boot/boot_v2_health, boot/nvram_access, boot/header
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/diag.asm — the DEBUG-INFO foundation: a PERSISTENT diag ring + fault dump.
;
; This is the PLAN resilience dividend (RESILIENCE.md) made concrete at the very
; bottom of the stack: a fixed 64 KiB RAM region (reserved by boot/paging.asm at
; DIAG_RING_BASE, MEMORY_MAP §1) that SURVIVES A WARM REBOOT, into which the boot
; path writes a breadcrumb per phase (enter/exit) and the IDT common handler
; writes a full register dump (vector/errcode/RIP/CR2) on every fault. Because the
; region is at a fixed address and is never cleared, the NEXT boot reads the
; PREVIOUS boot's ring back and reports it (diag_report_prev) — so a crash that
; would otherwise vanish in a triple-fault reboot leaves forensic state that P2
; surfaces. "Extra debug info = faster loop": the loop sees WHERE it died, not just
; THAT it died.
;
; DISTILLED, not ported: the old tree had a BOOT.LOG breadcrumb buffer (flushed to
; a file) + a watchdog-state byte, but no fixed persistent ring. This unifies the
; breadcrumb + the crash dump into one fixed-address ring with a magic'd header,
; the improvement MEMORY_MAP §1 calls for.
;
; The ordinary one-boot QEMU regression remains a structural write/readback smoke
; test. Task1265's behavior fixture additionally keeps one QEMU process alive,
; sends the in-band warm REBOOT, and compares second-boot DIAGRING with serial.
; A cold QEMU start still honestly reports "fresh (no previous ring)".
;
; Ring layout (geometry constants in core/abi/diag.inc, shared with boot/paging):
;   header  DIAG_HDR_SIZE bytes: magic, boot#, head, seq, fault#, last-fault dump
;   records DIAG_NREC * DIAG_REC_SIZE: fixed-stride ring, head wraps at DIAG_REC_AREA
; ============================================================================

; Adaptive logging needs to distinguish faults from an incomplete boot from the
; deliberate exception KATs in a boot that reached P7.  Preserve the public,
; cumulative DIAG_H_FAULTS counter and use the first reserved header qword as a
; successful-P7 baseline.  Old v3 rings have zero here because fresh format
; clears the complete 192-byte header.
DIAG_H_HEALTH_FAULT_BASE equ 160
; RCQ-41: first fatal fault of a boot, 24 bytes in the unused header tail.
; Written only by diag_crash_slot_fatal on the real .panic path; projected by
; the next Manager-launched boot into the PaOSCrashRecord EFI variable.
DIAG_H_CRASH     equ 168
DIAG_CR_VEC      equ 0                      ; db exception vector
DIAG_CR_STAGE    equ 1                      ; db PBIC stage P0..P8, 0xFF unknown
DIAG_CR_TRANS    equ 2                      ; db PBIC transition 0..2
DIAG_CR_FLAGS    equ 3                      ; db DIAG_CRF_*
DIAG_CR_ERR      equ 4                      ; dd low error code
DIAG_CR_RIP      equ 8                      ; dd RIP - image base, 0xFFFFFFFF outside
DIAG_CR_BUILD    equ 12                     ; dd measured build id prefix, 0 unknown
DIAG_CR_BOOT     equ 16                     ; dd low ring boot counter of the crash
DIAG_CR_CHECK    equ 20                     ; dd DIAG_CR_MAGIC ^ the five dwords above
DIAG_CR_BYTES    equ 24
DIAG_CR_MAGIC    equ 0x31524350             ; 'PCR1'
DIAG_CRF_RIP_IMAGE equ 0x01
DIAG_CRF_BUILD   equ 0x02
DIAG_CRF_MANAGER equ 0x04
DIAG_CRF_ALL     equ 0x07
%if DIAG_H_CRASH < DIAG_H_HEALTH_FAULT_BASE + 8 || DIAG_H_CRASH + DIAG_CR_BYTES > DIAG_HDR_SIZE
%error "crash slot must sit in the free header tail"
%endif
; PaOSCrashRecord wire: 32 bytes, CRC32 over [0,28).
DIAG_CREC_MAGIC  equ 0x52434250             ; 'PBCR'
DIAG_CREC_BYTES  equ 32
DIAG_CREC_SLOT   equ 8                      ; slot bytes [0,20) copied here
DIAG_CREC_CRC    equ 28
DIAG_CREC_ATTRS  equ 7                      ; NV|BS|RT, as PaOSInitCheckpoint

; diag_init — bind the reserved ring, detect a warm-reboot survivor, arm logging.
;   Reads boot/paging's diag_ring_base (0 if reservation failed => diag disables
;   itself, never faults). A self-consistent v3 ring snapshots the PREVIOUS
;   summary for serial/DIAGRING. Missing magic is cold/no-prior; present but
;   invalid geometry is MALFORMED and is reformatted without trusting its bytes.
;   in: -   out: -   clobbers: RAX,RCX,RDX,RSI,RDI (RBX saved)
diag_init:
    push rbx
    mov qword [rel diag_prev_crash_slot], 0
    mov qword [rel diag_prev_crash_slot + 8], 0
    mov qword [rel diag_prev_crash_slot + 16], 0
    mov  byte [rel diag_prev_health_valid], 0
    mov  qword [rel diag_prev_health_faults], 0
    mov  rbx, [rel diag_ring_base]       ; fixed region reserved by boot/paging
    test rbx, rbx
    jz   .noring
    mov  [rel diag_ptr], rbx
    mov  rax, DIAG_MAGIC
    cmp  [rbx + DIAG_H_MAGIC], rax
    je   .validate
    mov  rax, DIAG_MAGIC_INV
    cmp  [rbx + DIAG_H_MAGIC_INV], rax
    jne  .fresh_none                       ; neither v3 witness: no retained PaOS ring
    mov  byte [rel diag_prev_valid], DIAG_PREV_BAD_MAGIC
    jmp  .fresh                            ; inverse survived primary-magic damage
.validate:
    mov  rdi, rbx
    call diag_header_validate
    cmp  eax, DIAG_PREV_VALID
    je   .snapshot
    mov  [rel diag_prev_valid], al         ; bounded first-failed-invariant code
    jmp  .fresh
.snapshot:
    ; --- previous ring present (warm-reboot survivor) — snapshot for P2 report ---
    mov  rax, [rbx + DIAG_H_BOOT]
    mov  [rel diag_prev_boot], rax
    mov  rax, [rbx + DIAG_H_SEQ]
    mov  [rel diag_prev_seq], rax
    mov  rax, [rbx + DIAG_H_FAULTS]
    mov  [rel diag_prev_faults], rax
    mov  rcx, [rbx + DIAG_H_HEALTH_FAULT_BASE]
    cmp  rcx, rax                         ; corrupt/ambiguous baseline fails open
    ja   .health_snapshot_bad
    sub  rax, rcx
    mov  [rel diag_prev_health_faults], rax
    mov  byte [rel diag_prev_health_valid], 1
    jmp  .health_snapshot_done
.health_snapshot_bad:
    mov  byte [rel diag_prev_health_valid], 0
.health_snapshot_done:
    mov  rax, [rbx + DIAG_H_LVEC]
    mov  [rel diag_prev_fvec], rax
    mov  rax, [rbx + DIAG_H_LRIP]
    mov  [rel diag_prev_frip], rax
    mov  rax, [rbx + DIAG_H_LCR2]
    mov  [rel diag_prev_fcr2], rax
    ; Root88483: snapshot the first-fatal header slot before current-boot
    ; logging. Projection does not consume it; later faults may overwrite the
    ; live header, so DIAGRING must read this boot-local prior copy instead.
    mov  rax, [rbx + DIAG_H_CRASH]
    mov  [rel diag_prev_crash_slot], rax
    mov  rax, [rbx + DIAG_H_CRASH + 8]
    mov  [rel diag_prev_crash_slot + 8], rax
    mov  rax, [rbx + DIAG_H_CRASH + 16]
    mov  [rel diag_prev_crash_slot + 16], rax
    mov  byte [rel diag_prev_valid], DIAG_PREV_VALID
    inc  qword [rbx + DIAG_H_BOOT]        ; count this boot (persistence proof)
    clflush [rbx + 64]                    ; preserve valid-empty boot identity too
    mfence
    jmp  .ready
.fresh_none:
    mov  byte [rel diag_prev_valid], DIAG_PREV_NONE
.fresh:
    mov  rdi, rbx                          ; zero the whole region (fresh cold boot)
    xor  esi, esi
    mov  edx, DIAG_RING_SIZE
    call memset
    mov  rax, DIAG_MAGIC
    mov  [rbx + DIAG_H_MAGIC], rax
    mov  qword [rbx + DIAG_H_BOOT], 1      ; head/seq/faults left 0 by memset
    mov  dword [rbx + DIAG_H_VERSION], DIAG_VERSION
    mov  dword [rbx + DIAG_H_HDR_BYTES], DIAG_HDR_SIZE
    mov  dword [rbx + DIAG_H_REC_BYTES], DIAG_REC_SIZE
    mov  dword [rbx + DIAG_H_REC_COUNT], DIAG_NREC
    mov  dword [rbx + DIAG_H_RING_BYTES], DIAG_RING_SIZE
    mov  rax, DIAG_MAGIC_INV
    mov  [rbx + DIAG_H_MAGIC_INV], rax
    ; Publish the format witnesses before any record can advertise itself.
    ; This also makes a just-reformatted empty ring survive an external reset.
    clflush [rbx + 64]
    clflush [rbx + 128]
    mfence
.ready:
    mov  rax, [rbx + DIAG_H_SEQ]
    mov  [rel diag_live_first], rax       ; never expose a previous boot record
    mov  rax, [rbx + DIAG_H_BOOT]
    mov  [rel diag_live_boot], rax
    mov  byte [rel diag_ready], 1
    lea  rdi, [rel str_diag_init]
    call serial_string
    pop  rbx
    ret
.noring:
    mov  byte [rel diag_ready], 0
    lea  rdi, [rel str_diag_noring]
    call serial_string
    pop  rbx
    ret

; diag_header_validate(RDI=ring base) -> EAX=DIAG_PREV_VALID or the bounded
; DIAG_PREV_BAD_* code for the first rejected invariant.  This is the single
; decoder gate before serial or UDP may trust prior state.  No writes.
; Preserves nonvolatiles.
diag_header_validate:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  rax, DIAG_MAGIC_INV
    cmp  [rbx + DIAG_H_MAGIC_INV], rax
    jne  .bad_inverse
    cmp  dword [rbx + DIAG_H_VERSION], DIAG_VERSION
    jne  .bad_version
    cmp  dword [rbx + DIAG_H_HDR_BYTES], DIAG_HDR_SIZE
    jne  .bad_header_bytes
    cmp  dword [rbx + DIAG_H_REC_BYTES], DIAG_REC_SIZE
    jne  .bad_record_bytes
    cmp  dword [rbx + DIAG_H_REC_COUNT], DIAG_NREC
    jne  .bad_record_count
    cmp  dword [rbx + DIAG_H_RING_BYTES], DIAG_RING_SIZE
    jne  .bad_ring_bytes
    cmp  qword [rbx + DIAG_H_BOOT], 0
    je   .bad_boot
    mov  r12, [rbx + DIAG_H_HEAD]
    cmp  r12, DIAG_REC_AREA
    jae  .bad_head_range
    test r12, DIAG_REC_SIZE - 1
    jnz  .bad_head_align
    mov  r14, [rbx + DIAG_H_SEQ]
    mov  rax, [rbx + DIAG_H_FAULTS]
    cmp  rax, r14                         ; cannot have more faults than records
    ja   .bad_fault_count
    mov  rax, r14                         ; exact next-slot relation
    xor  edx, edx
    mov  rcx, DIAG_NREC
    div  rcx                              ; RDX = seq modulo record count
    imul rdx, rdx, DIAG_REC_SIZE
    cmp  r12, rdx
    jne  .bad_head_seq
    mov  r13, r14                         ; retained records = min(seq, NREC)
    cmp  r13, DIAG_NREC
    jbe  .scan
    mov  r13, DIAG_NREC
.scan:
    test r13, r13
    jz   .good
    test r12, r12
    jnz  .back
    mov  r12, DIAG_REC_AREA
.back:
    sub  r12, DIAG_REC_SIZE
    dec  r14
    lea  r15, [rbx + DIAG_HDR_SIZE]
    add  r15, r12
    cmp  [r15 + DIAG_R_SEQ], r14
    jne  .bad_record_seq
    mov  eax, [r15 + DIAG_R_KIND]
    cmp  eax, DIAG_K_ENTER
    jb   .bad_record_kind
    cmp  eax, DIAG_K_MAX
    ja   .bad_record_kind
    cmp  eax, DIAG_K_EXIT
    ja   .next                            ; each registered non-phase owner defines its u32 arg
    cmp  dword [r15 + DIAG_R_ARG], DIAG_NPHASES
    jb   .next
    cmp  dword [r15 + DIAG_R_ARG], DIAG_ARG_UNATTRIBUTED
    jne  .bad_phase_arg
    cmp  eax, DIAG_K_EXIT                 ; only a boot-wait EXIT row carries it
    jne  .bad_phase_arg
.next:
    dec  r13
    jmp  .scan
.good:
    mov  eax, DIAG_PREV_VALID
    jmp  .out
.bad_inverse:
    mov  eax, DIAG_PREV_BAD_INVERSE
    jmp  .out
.bad_version:
    mov  eax, DIAG_PREV_BAD_VERSION
    jmp  .out
.bad_header_bytes:
    mov  eax, DIAG_PREV_BAD_HEADER_BYTES
    jmp  .out
.bad_record_bytes:
    mov  eax, DIAG_PREV_BAD_RECORD_BYTES
    jmp  .out
.bad_record_count:
    mov  eax, DIAG_PREV_BAD_RECORD_COUNT
    jmp  .out
.bad_ring_bytes:
    mov  eax, DIAG_PREV_BAD_RING_BYTES
    jmp  .out
.bad_boot:
    mov  eax, DIAG_PREV_BAD_BOOT
    jmp  .out
.bad_head_range:
    mov  eax, DIAG_PREV_BAD_HEAD_RANGE
    jmp  .out
.bad_head_align:
    mov  eax, DIAG_PREV_BAD_HEAD_ALIGN
    jmp  .out
.bad_fault_count:
    mov  eax, DIAG_PREV_BAD_FAULT_COUNT
    jmp  .out
.bad_head_seq:
    mov  eax, DIAG_PREV_BAD_HEAD_SEQ
    jmp  .out
.bad_record_seq:
    mov  eax, DIAG_PREV_BAD_RECORD_SEQ
    jmp  .out
.bad_record_kind:
    mov  eax, DIAG_PREV_BAD_RECORD_KIND
    jmp  .out
.bad_phase_arg:
    mov  eax, DIAG_PREV_BAD_PHASE_ARG
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; diag_ring_append(EDI=kind, ESI=arg, RDX=a, RCX=b, R8=c, R9=tagptr|0).
; Registered diagnostic producers supply their closed taxonomy and scalar fields.
;   Write one fixed-stride record at head, advance head (wrapping) + seq.
;   EAX=1 committed, 0 unavailable/busy. One atomic try-claim: never spin/wait
;   when another CPU or a fault-interrupted writer owns it. Busy attempts touch
;   no retained bytes and increment boot-local diag_ring_dropped (u64 modulo).
;   Fault records and their header summary share this same claim. The separate
;   first-fatal crash slot does not take it. Clobbers volatiles; saves nonvolatiles.
diag_ring_append:
    cmp  byte [rel diag_ready], 0
    je   .skip
    xor  eax, eax
    mov  r10d, 1
    lock cmpxchg [rel diag_ring_busy], r10
    jne  .busy
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    push rdx
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rbp, rax
    pop  rdx
    mov  r12d, edi                         ; kind
    mov  r13d, esi                         ; arg
    mov  r14, r9                           ; tag ptr (0 => none)
    mov  rbx, [rel diag_ptr]
    mov  r11, [rbx + DIAG_H_HEAD]          ; head byte-offset within the record area
    lea  r15, [rbx + DIAG_HDR_SIZE]
    add  r15, r11                          ; r15 = record address
    mov  [r15 + DIAG_R_KIND], r12d
    mov  [r15 + DIAG_R_ARG], r13d
    mov  rax, [rbx + DIAG_H_SEQ]
    mov  [r15 + DIAG_R_SEQ], rax
    mov  [r15 + DIAG_R_A], rdx
    mov  [r15 + DIAG_R_B], rcx
    mov  [r15 + DIAG_R_C], r8
    ; Every committed tag is NUL-padded, including a reused slot whose new
    ; name is shorter. strcpy_s terminates but does not clear the old tail.
    lea  rdi, [r15 + DIAG_R_TAG]
    xor  esi, esi
    mov  edx, 24
    call memset
    test r14, r14
    jz   .advance
    lea  rdi, [r15 + DIAG_R_TAG]           ; bounded copy of the name (always NUL-terms)
    mov  rsi, r14
    mov  edx, 24
    call strcpy_s
.advance:
    ; Commit the complete record before publishing a sequence/head that names
    ; it.  The Manager may reset PaOS without traversing command_udp's CF9 path;
    ; record-first publication prevents a mixed generation on real silicon.
    clflush [r15]
    mfence
    ; Only a committed fault contributes to faults_total/last-fault. A nested
    ; refused fault must not make faults_total exceed the record sequence or
    ; replace the successful owner's tuple. All summary fields share one line.
    cmp  r12d, DIAG_K_FAULT
    jne  .count_record
    inc  qword [rbx + DIAG_H_FAULTS]
    mov  eax, [r15 + DIAG_R_ARG]
    mov  [rbx + DIAG_H_LVEC], rax
    mov  rax, [r15 + DIAG_R_A]
    mov  [rbx + DIAG_H_LRIP], rax
    mov  rax, [r15 + DIAG_R_B]
    mov  [rbx + DIAG_H_LCR2], rax
.count_record:
    inc  qword [rbx + DIAG_H_SEQ]
    mov  r11, [rbx + DIAG_H_HEAD]          ; reload (calls above are pure re: r11)
    add  r11, DIAG_REC_SIZE
    cmp  r11, DIAG_REC_AREA
    jb   .store
    xor  r11, r11                          ; wrap
.store:
    mov  [rbx + DIAG_H_HEAD], r11
    clflush [rbx + 64]                    ; retained summary cache line
    mfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, rbp
    add  [rel log_cost_ring_tsc], rax
    mov  qword [rel diag_ring_busy], 0     ; release after complete publication (TSO)
    mov  eax, 1
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.busy:
    lock inc qword [rel diag_ring_dropped]
.skip:
    xor  eax, eax
    ret

; diag_name_of(RDI=phase id) -> RAX = ptr to its NUL-terminated name.
;   Runtime lea into the name table (NEVER a dq <symbol> — the load-VA hazard).
;   clobbers: RAX,RCX
diag_name_of:
    cmp  rdi, DIAG_NPHASES
    jae  .unk
    mov  rax, rdi
    shl  rax, 4                            ; * DIAG_PH_STRIDE (16)
    lea  rcx, [rel diag_phase_names]
    add  rax, rcx
    ret
.unk:
    lea  rax, [rel diag_name_unk]
    ret

; diag_phase_log(EDI=id, ESI=kind) — internal: append a phase breadcrumb record.
diag_phase_log:
    push rdi                               ; id
    push rsi                               ; kind
    call diag_name_of                      ; RDI=id -> RAX=name ptr
    mov  r9, rax
    pop  rax                               ; kind
    pop  rsi                               ; id -> arg
    mov  edi, eax                          ; kind -> R_KIND
    xor  edx, edx
    xor  ecx, ecx
    xor  r8d, r8d
    call diag_ring_append
    ret

; diag_phase_enter(EDI=phase id) — breadcrumb: entering a boot phase.
diag_phase_enter:
    mov  esi, DIAG_K_ENTER
    jmp  diag_phase_log

; diag_phase_exit(EDI=phase id) — breadcrumb: leaving a boot phase.
diag_phase_exit:
    mov  esi, DIAG_K_EXIT
    call diag_phase_log
    ; The durable ring row above is unconditional. A phase boundary no longer
    ; drains the UART FIFO: boot work never waits for the wire (root
    ; RC-boot-audit-fixes 2026-10-17); the IRQ tick and idle drain it, and
    ; terminal paths call serial_fault_flush.
    ret

; diag_boot_phase_record(EDI=P0..P8, ESI=PBM_INIT_TRANSITION_*, RDX=TSC)
; Record each C3 checkpoint edge in the retained diagnostic ring. R_A carries
; the edge's original timestamp so the pre-diag P0/P1 edges can be replayed
; after diag_init without moving their measured boundary.
diag_boot_phase_record:
    cmp  edi, PBM_INIT_STAGE_P8
    ja   .done
    mov  r10d, edi
    cmp  esi, PBM_INIT_TRANSITION_STARTING
    je   .enter
    cmp  esi, PBM_INIT_TRANSITION_COMPLETED
    jne  .done
    mov  edi, DIAG_K_EXIT
    jmp  .append
.enter:
    mov  edi, DIAG_K_ENTER
.append:
    mov  esi, r10d
    lea  r9, [rel diag_boot_phase_names]
    mov  eax, r10d
    shl  eax, 2
    add  r9, rax
    xor  ecx, ecx
    xor  r8d, r8d
    call diag_ring_append
.done:
    ret

; diag_persist_flush — commit the retained ring to DRAM before a warm-reset
;   boundary.  CF9 resets the CPU caches; without an explicit writeback, real
;   silicon can retain a mixture of old DRAM and dirty cache lines even though
;   QEMU's reset model preserves every write.  Flush only this fixed 64 KiB
;   region (never global WBINVD: active device DMA makes that needlessly risky).
;   No-op when the reservation is unavailable. clobbers: RCX,RDI.
diag_persist_flush:
    cmp  byte [rel diag_ready], 0
    je   .done
    mov  rdi, [rel diag_ptr]
    mov  ecx, DIAG_RING_SIZE / 64
.line:
    clflush [rdi]
    add  rdi, 64
    dec  ecx
    jnz  .line
    mfence                                  ; every dirty ring line reached DRAM
.done:
    ret

; diag_ring_fault(RDI=vector, RSI=errcode, RDX=RIP, RCX=CR2) — record a fault dump.
;   Called from core/idt's isr_common on BOTH the trapped-recover path and the
;   panic path (so a real crash leaves forensics for the next boot BEFORE it
;   halts). Updates the header's last-fault fields + appends a fault record, then
;   commits the complete retained window before a panic can fire CF9.
;   EAX=1 committed, 0 unavailable/busy. No full-window flush after refusal.
;   Preserves the caller's stack frame (RBX saved).
; Fatal #MC last-chance snapshot, not an MCA initializer/recovery assessment.
; Qualified Intel: architectural globals and bank STATUS. AuthenticAMD with
; CPUID ScalableMca: globals and SMCA bank STATUS, separately tagged. Other
; qualified AMD: globals only with scan count0; no unqualified bank probing.
; No CTL/ADDR/MISC, WRMSR, CR4 write, clear, allocation, wait or serial lock.
; Unknown vendors are explicitly unqualified. Missing ring => no extra
; hardware work. The caller writes the ordinary final fault and flushes all.
; At most 32 banks, with raw CAP retained so truncation is visible; invalid VAL
; banks are read but not published. No per-bank error severity interpretation.
; Unqualified tag C: 1=vendor, 2=missing CPUID leaf/MSR/MCE/MCA feature.
diag_ring_mca:
    cmp  byte [rel diag_ready], 0
    je   .skip
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  eax, eax
    cpuid
    cmp  ebx, 0x756e6547               ; GenuineIntel
    jne  .check_amd
    cmp  edx, 0x49656e69
    jne  .vendor
    cmp  ecx, 0x6c65746e
    jne  .vendor
    xor  r15d, r15d                  ; Intel bank snapshot
    jmp  .qualify
.check_amd:
    cmp  ebx, 0x68747541               ; AuthenticAMD, all three words
    jne  .vendor
    cmp  edx, 0x69746e65
    jne  .vendor
    cmp  ecx, 0x444d4163
    jne  .vendor
    mov  r15d, 1                      ; AMD globals fallback unless SMCA qualifies
.qualify:
    cmp  eax, 1
    jb   .features
    mov  eax, 1
    cpuid
    and  edx, 0x40a0                  ; MSR(5), MCE(7), MCA(14), all required
    cmp  edx, 0x40a0
    jne  .features
    test r15d, r15d
    jz   .layout_ready                 ; Intel uses no AMD extended leaves
    mov  eax, 0x80000000
    cpuid
    cmp  eax, 0x80000007
    jb   .layout_ready                 ; retain AMD architectural globals
    mov  eax, 0x80000007
    cpuid
    test ebx, 1 << 3                   ; ScalableMca, no family/model guess
    jz   .layout_ready
    mov  r15d, 2                       ; qualified AMD SMCA STATUS layout
.layout_ready:
    mov  ebx, r15d                    ; layout survives CPUID and ring append
    mov  ecx, 0x179                   ; architectural MCG_CAP, CPUID.MCA
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax
    movzx r14d, al                    ; COUNT is only the low byte
    cmp  r14d, 32
    jbe  .bounded
    mov  r14d, 32
.bounded:
    cmp  ebx, 1
    jne  .read_global
    xor  r14d, r14d                   ; AMD bank layout/access not qualified
.read_global:
    mov  ecx, 0x17a                   ; IA32_MCG_STATUS
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax
    mov  edi, DIAG_K_MCA
    mov  esi, 0xffffffff
    mov  rdx, r12
    mov  rcx, r13
    mov  r8d, r14d
    lea  r9, [rel .global_tag]
    test ebx, ebx
    jz   .append_global
    lea  r9, [rel .amd_global_tag]
    cmp  ebx, 2
    jne  .append_global
    lea  r9, [rel .smca_global_tag]
.append_global:
    call diag_ring_append
    xor  r15d, r15d
.bank:
    cmp  r15d, r14d
    jae  .done
    lea  ecx, [r15d * 4 + 0x401]      ; IA32_MCi_STATUS, no other bank MSRs
    cmp  ebx, 2
    jne  .read_bank
    mov  ecx, r15d
    shl  ecx, 4
    add  ecx, 0xc0002001               ; AMD MCA_STATUS, 16-MSR bank stride
.read_bank:
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    bt   rax, 63                      ; VAL, not any low-word error/UC bit
    jnc  .next
    mov  edi, DIAG_K_MCA
    mov  esi, r15d
    mov  rdx, rax
    mov  rcx, r13
    mov  r8, r12
    lea  r9, [rel .bank_tag]
    cmp  ebx, 2
    jne  .append_bank
    lea  r9, [rel .smca_bank_tag]
.append_bank:
    call diag_ring_append
.next:
    inc  r15d
    jmp  .bank
.vendor:
    mov  r8d, 1
    jmp  .unqualified
.features:
    mov  r8d, 2
.unqualified:
    mov  edi, DIAG_K_MCA
    mov  esi, 0xffffffff
    xor  edx, edx
    xor  ecx, ecx
    lea  r9, [rel .unsupported_tag]
    call diag_ring_append
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.skip:
    ret
.global_tag:      db "mca-global", 0
.amd_global_tag:  db "mca-amd-global", 0
.bank_tag:        db "mca-bank", 0
.smca_global_tag: db "smca-global", 0
.smca_bank_tag:   db "smca-bank", 0
.unsupported_tag: db "mca-unqualified", 0
; ---- end fatal MCA capture ----

diag_ring_fault:
    cmp  byte [rel diag_ready], 0
    je   .skip
    push rbx
    mov  r8, rsi                           ; c = error code
    mov  esi, edi                          ; arg = vector
    mov  edi, DIAG_K_FAULT                 ; kind (rdx=RIP=a, rcx=CR2=b already set)
    lea  r9, [rel diag_tag_fault]
    call diag_ring_append
    test eax, eax
    jz   .uncommitted
    call diag_persist_flush                 ; crash evidence must survive real CF9
    mov  eax, 1
.uncommitted:
    pop  rbx
    ret
.skip:
    xor  eax, eax
    ret

; diag_crash_slot_fatal(RDI=vector, RSI=error code, RDX=faulting RIP)
;   RCQ-41. Called from idt .panic only after every self-test escape, so a
;   contained/KAT fault never reaches it. Fault context: no calls, no locks, no
;   firmware. The first fatal fault of this boot claims the slot (XCHG is
;   locked); a nested fault or another CPU's later fault changes nothing.
;   Sanitized: image-relative RIP only, no CR2, registers or absolute address.
;   clobbers: RAX,RCX,R8,R9,R10,R11
diag_crash_slot_fatal:
    cmp  byte [rel diag_ready], 0
    je   .out
    mov  al, 1
    xchg al, [rel diag_crash_claimed]
    test al, al
    jnz  .out
    mov  r8, [rel diag_ptr]
    add  r8, DIAG_H_CRASH
    mov  dword [r8 + DIAG_CR_CHECK], 0       ; an older retained slot is now void
    xor  ecx, ecx
    mov  r9, rdx
    sub  r9, [rel pbm_image_base]
    jb   .rip_outside
    cmp  r9, [rel pbm_image_size]
    jae  .rip_outside
    mov  rax, r9
    shr  rax, 32                            ; offset must fit the dd field
    jnz  .rip_outside
    or   ecx, DIAG_CRF_RIP_IMAGE
    jmp  .rip_done
.rip_outside:
    mov  r9d, 0xFFFFFFFF
.rip_done:
    mov  [r8 + DIAG_CR_RIP], r9d
    mov  [r8 + DIAG_CR_VEC], dil
    mov  [r8 + DIAG_CR_ERR], esi
    mov  word [r8 + DIAG_CR_STAGE], 0x00FF   ; stage unknown, no transition
    cmp  byte [rel pbm_init_checkpoint_loaded], 1
    jne  .stage_done
    mov  al, [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF]
    mov  [r8 + DIAG_CR_STAGE], al
    mov  al, [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF]
    mov  [r8 + DIAG_CR_TRANS], al
.stage_done:
    xor  eax, eax
    cmp  byte [rel paos_build_state], BID_ST_UNMEASURED
    je   .build_done                        ; measured identity, stamped or not
    mov  eax, [rel paos_build_measured]
    or   ecx, DIAG_CRF_BUILD
.build_done:
    mov  [r8 + DIAG_CR_BUILD], eax
    cmp  byte [rel pbm_manager_launch], 1
    jne  .flags_done
    or   ecx, DIAG_CRF_MANAGER
.flags_done:
    mov  [r8 + DIAG_CR_FLAGS], cl
    mov  rax, [r8 - DIAG_H_CRASH + DIAG_H_BOOT]
    mov  [r8 + DIAG_CR_BOOT], eax
    call diag_crash_slot_check               ; EAX = check of the stored dwords
    mov  [r8 + DIAG_CR_CHECK], eax           ; published last (TSO store order)
    clflush [r8]
    clflush [r8 + DIAG_CR_BYTES - 1]
    mfence
    push rdi
    push rsi
    mov rdi,r8
    mov rsi,[r8-DIAG_H_CRASH+DIAG_H_BOOT]
    call crash_identity_capture ; same first-fatal claimant; no firmware
    pop rsi
    pop rdi
.out:
    ret

; R8 = slot -> EAX = DIAG_CR_MAGIC ^ dwords 0..4. Leaf, clobbers EAX only.
diag_crash_slot_check:
    mov  eax, DIAG_CR_MAGIC
    xor  eax, [r8]
    xor  eax, [r8 + 4]
    xor  eax, [r8 + 8]
    xor  eax, [r8 + 12]
    xor  eax, [r8 + 16]
    ret

; diag_crash_record_project — RCQ-41, task context after diag_init.
;   A retained (warm-reset survivor) ring whose crash slot is intact becomes the
;   32-byte PaOSCrashRecord, written only by a Manager-launched mutable attempt
;   whose runtime services are mapped. An identical stored record is not
;   rewritten. One SetVariable at most, exact read-back, no retry or erase; an
;   unknown existing value is preserved. Diagnostic only: never policy, health
;   or authority. diag_crash_record_status: 0 none, 1 saved, 2 refused or
;   unavailable, 3 uncertain write, 4 already stored.
diag_crash_record_project:
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    push rbx
    push r12
    mov  byte [rel diag_crash_record_status], 0
    cmp  byte [rel diag_ready], 0
    je   .out
    cmp  byte [rel diag_prev_valid], DIAG_PREV_VALID
    jne  .out
    mov  r8, [rel diag_ptr]
    add  r8, DIAG_H_CRASH
    mov  ebx, [r8 + DIAG_CR_CHECK]
    test ebx, ebx
    jz   .out
    call diag_crash_slot_check
    cmp  eax, ebx
    jne  .out
    cmp  byte [r8 + DIAG_CR_VEC], 31
    ja   .out
    test byte [r8 + DIAG_CR_FLAGS], ~DIAG_CRF_ALL & 0xFF
    jnz  .out
    movzx eax, byte [r8 + DIAG_CR_STAGE]
    cmp  eax, 0xFF
    je   .stage_unknown
    cmp  eax, PBM_INIT_STAGE_P8
    ja   .out
    cmp  byte [r8 + DIAG_CR_TRANS], PBM_INIT_TRANSITION_COMPLETED
    ja   .out
    jmp  .stage_ok
.stage_unknown:
    cmp  byte [r8 + DIAG_CR_TRANS], 0
    jne  .out
.stage_ok:
    lea  rdi, [rel diag_crash_record]
    mov  dword [rdi], DIAG_CREC_MAGIC
    mov  word [rdi + 4], 1
    mov  word [rdi + 6], DIAG_CREC_BYTES
    lea  rsi, [r8]
    lea  rdi, [rdi + DIAG_CREC_SLOT]
    mov  ecx, DIAG_CR_CHECK
    rep  movsb
    lea  rdi, [rel diag_crash_record]
    mov  esi, DIAG_CREC_CRC
    call pbm_crc32
    mov  [rel diag_crash_record + DIAG_CREC_CRC], eax
    mov  byte [rel diag_crash_record_status], 2
    cmp  byte [rel pbm_manager_launch], 1
    jne  .report
    test byte [rel pbm_flags], PBM_HF_MUTABLE_ATTEMPT
    jz   .report
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .report
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .report
    call diag_crash_record_read
    mov  rbx, 0x800000000000000E             ; EFI_NOT_FOUND: first record
    cmp  rax, rbx
    je   .write
    test rax, rax
    jnz  .report
    cmp  dword [rel diag_crash_attrs], DIAG_CREC_ATTRS
    jne  .report
    cmp  qword [rel diag_crash_size], DIAG_CREC_BYTES
    jne  .report
    lea  rdi, [rel diag_crash_verify]
    call diag_crash_record_wire_ok
    test eax, eax
    jz   .report                            ; unknown existing value: preserve
    lea  rsi, [rel diag_crash_record]
    lea  rdi, [rel diag_crash_verify]
    mov  ecx, DIAG_CREC_BYTES / 8
    repe cmpsq
    jne  .write
    mov  byte [rel diag_crash_record_status], 4
    jmp  .report
.write:
    lea  rdi, [rel diag_crash_guid]
    lea  rsi, [rel diag_crash_name]
    xor  edx, edx
    lea  rcx, [rel str_diag_crash_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .report
    mov  byte [rel diag_crash_record_status], 3
    lea  rcx, [rel diag_crash_name]
    lea  rdx, [rel diag_crash_guid]
    mov  r8d, DIAG_CREC_ATTRS
    mov  r9d, DIAG_CREC_BYTES
    sub  rsp, 48
    lea  rax, [rel diag_crash_record]
    mov  [rsp + 32], rax
    call [r12 + 0x58]                       ; EFI_RUNTIME_SERVICES.SetVariable
    add  rsp, 48
    test rax, rax
    jnz  .report
    call diag_crash_record_read
    test rax, rax
    jnz  .report
    cmp  dword [rel diag_crash_attrs], DIAG_CREC_ATTRS
    jne  .report
    cmp  qword [rel diag_crash_size], DIAG_CREC_BYTES
    jne  .report
    lea  rsi, [rel diag_crash_record]
    lea  rdi, [rel diag_crash_verify]
    mov  ecx, DIAG_CREC_BYTES / 8
    repe cmpsq
    jne  .report
    mov  byte [rel diag_crash_record_status], 1
.report:
    lea  rdi, [rel str_diag_crash_status]
    call serial_string
    movzx edi, byte [rel diag_crash_record_status]
    call serial_hex64
    lea  rdi, [rel str_diag_crash_vec]
    call serial_string
    movzx edi, byte [rel diag_crash_record + DIAG_CREC_SLOT + DIAG_CR_VEC]
    call serial_hex64
    lea  rdi, [rel str_diag_crash_rip]
    call serial_string
    mov  edi, [rel diag_crash_record + DIAG_CREC_SLOT + DIAG_CR_RIP]
    call serial_hex64
    lea  rdi, [rel str_diag_crash_end]
    call serial_string
.out:
    pop  r12
    pop  rbx
    mov  rsp, rbp
    pop  rbp
    ret

; R12 = runtime table. Exact owned name/GUID, bounded read into the verify
; buffer, no mutation. RAX = EFI status.
diag_crash_record_read:
    mov  qword [rel diag_crash_size], DIAG_CREC_BYTES
    mov  dword [rel diag_crash_attrs], 0
    lea  rcx, [rel diag_crash_name]
    lea  rdx, [rel diag_crash_guid]
    lea  r8, [rel diag_crash_attrs]
    lea  r9, [rel diag_crash_size]
    sub  rsp, 40
    lea  rax, [rel diag_crash_verify]
    mov  [rsp + 32], rax
    call [r12 + 0x48]                       ; EFI_RUNTIME_SERVICES.GetVariable
    add  rsp, 40
    ret

; RDI = 32 bytes -> EAX 1 for a well-formed PaOSCrashRecord v1, else 0.
diag_crash_record_wire_ok:
    push rbx
    mov  rbx, rdi
    xor  eax, eax
    cmp  dword [rbx], DIAG_CREC_MAGIC
    jne  .out
    cmp  word [rbx + 4], 1
    jne  .out
    cmp  word [rbx + 6], DIAG_CREC_BYTES
    jne  .out
    mov  esi, DIAG_CREC_CRC
    call pbm_crc32
    cmp  eax, [rbx + DIAG_CREC_CRC]
    mov  eax, 0
    jne  .out
    inc  eax
.out:
    pop  rbx
    ret

; P7 health boundary for adaptive verbosity.  Records, sequence numbers, and the
; public cumulative faults_total are never removed.  Instead retain the current
; cumulative count as the successful-P7 baseline.  The next boot selects from
; faults_total-baseline: deliberate boot KAT exceptions remain forensic records,
; while any post-P7/runtime fault makes that delta nonzero and forces VERBOSE.
diag_mark_boot_healthy:
    cmp  byte [rel diag_ready], 0
    je   .done
    mov  rax, [rel diag_ptr]
    mov  rcx, [rax + DIAG_H_FAULTS]
    mov  [rax + DIAG_H_HEALTH_FAULT_BASE], rcx
    clflush [rax + 128]
    mfence
.done:
    ret

; diag_report_prev — P2 observability: read back + report the PREVIOUS boot's ring.
;   On a warm-reboot survivor: boot#, seq, fault count, and the last fault dump.
;   On a fresh cold boot (QEMU): "none". Does NOT gate — the marker is diag_selftest.
;   clobbers: RAX,RCX,RDX,RSI,RDI
diag_report_prev:
    ; current boot's live ring stats first — makes the phase breadcrumbs (which go
    ; to the ring, not serial) observable: seq counts every enter/exit + fault.
    cmp  byte [rel diag_ready], 0
    je   .skip
    mov  r8, [rel diag_ptr]
    lea  rdi, [rel str_cur_pfx]
    call serial_string
    mov  rdi, [r8 + DIAG_H_BOOT]
    call serial_hex64
    lea  rdi, [rel str_cur_seq]
    call serial_string
    mov  r8, [rel diag_ptr]
    mov  rdi, [r8 + DIAG_H_SEQ]
    call serial_hex64
    lea  rdi, [rel str_cur_faults]
    call serial_string
    mov  r8, [rel diag_ptr]
    mov  rdi, [r8 + DIAG_H_FAULTS]
    call serial_hex64
    lea  rdi, [rel str_diag_nl]
    call serial_string
.skip:
    lea  rdi, [rel str_prev_pfx]
    call serial_string
    cmp  byte [rel diag_prev_valid], DIAG_PREV_VALID
    jne  .not_valid
    lea  rdi, [rel str_prev_boot]
    call serial_string
    mov  rdi, [rel diag_prev_boot]
    call serial_hex64
    lea  rdi, [rel str_prev_seq]
    call serial_string
    mov  rdi, [rel diag_prev_seq]
    call serial_hex64
    lea  rdi, [rel str_prev_faults]
    call serial_string
    mov  rdi, [rel diag_prev_faults]
    call serial_hex64
    lea  rdi, [rel str_prev_lvec]
    call serial_string
    mov  rdi, [rel diag_prev_fvec]
    call serial_hex64
    lea  rdi, [rel str_prev_lrip]
    call serial_string
    mov  rdi, [rel diag_prev_frip]
    call serial_hex64
    lea  rdi, [rel str_diag_nl]
    call serial_string
    jmp  .preserved
.not_valid:
    cmp  byte [rel diag_prev_valid], DIAG_PREV_BAD_MIN
    jb   .fresh
    lea  rdi, [rel str_prev_malformed]
    call serial_string
    jmp  .preserved
.fresh:
    lea  rdi, [rel str_prev_none]
    call serial_string
.preserved:
    ; The previous-boot ring READBACK PATH is exercised on every boot (a survivor
    ; is reported above; a fresh cold boot reports "none"). Task1265 grades the
    ; same values after a QEMU warm reset and through the nonce-bound UDP verb.
    lea  rdi, [rel str_diag_ring_preserved] ; ring-readback gate marker (diag.ring.preserved)
    call serial_string
    ret

; diag_prev_fault_at(RDI=zero-based newest-fault ordinal) -> RAX=record ptr or 0.
; Walks backward from the validated prior sequence boundary and never consults
; current header head/seq.  Thus current-boot appends cannot be mistaken for
; prior evidence.  If a wrapped current boot eventually overwrites an old slot,
; the exact sequence check makes that record unavailable rather than mislabelled.
diag_prev_fault_at:
    cmp  byte [rel diag_prev_valid], DIAG_PREV_VALID
    jne  .miss
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15, rdi                         ; requested fault ordinal
    mov  r14, [rel diag_prev_seq]
    test r14, r14
    jz   .miss_saved
    mov  r13, r14
    cmp  r13, DIAG_NREC
    jbe  .have_count
    mov  r13, DIAG_NREC
.have_count:
    mov  rax, r14
    xor  edx, edx
    mov  rcx, DIAG_NREC
    div  rcx
    imul r12, rdx, DIAG_REC_SIZE          ; saved prior head, derived from seq
    mov  rbx, [rel diag_ptr]
.scan:
    test r13, r13
    jz   .miss_saved
    test r12, r12
    jnz  .back
    mov  r12, DIAG_REC_AREA
.back:
    sub  r12, DIAG_REC_SIZE
    dec  r14
    lea  rax, [rbx + DIAG_HDR_SIZE]
    add  rax, r12
    cmp  [rax + DIAG_R_SEQ], r14
    jne  .miss_saved                       ; overwritten or torn: refuse the tail
    cmp  dword [rax + DIAG_R_KIND], DIAG_K_FAULT
    jne  .next
    test r15, r15
    jz   .found
    dec  r15
.next:
    dec  r13
    jmp  .scan
.found:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.miss_saved:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.miss:
    xor  eax, eax
    ret

; diag_live_record_copy(RDI=sequence or UINT64_MAX for head, RSI=private96B,
; RDX=capacity) -> EAX 0 copied, 1 unavailable, 2 busy, 3 bad request,
; 4 stale/future, 5 other record kind/tag, 6 malformed header/sequence.
; Output: boot/seq_total/first_retained/drops (four QWORDs), then raw64B record
; or zero64B for a head request. One nonblocking shared writer try-claim gives
; an O(1) stable copy; no returned pointer, scan, retry or diagnostic append.
; Only current hardware-poll records may cross this owner-facing read seam.
; Every refusal leaves destination and ring untouched, and busy keeps its owner.
diag_live_record_copy:
    test rsi,rsi
    jz .bad_request
    cmp rdx,96
    jb .bad_request
    mov rax,rsi
    add rax,95
    jc .bad_request
    cmp byte [rel diag_ready],0
    je .unavailable
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,96
    mov r12,rsi
    mov r13,rdi
    xor eax,eax
    mov edx,1
    lock cmpxchg [rel diag_ring_busy],rdx
    jne .busy
    mov rbx,[rel diag_ptr]
    test rbx,rbx
    jz .missing
    mov rax,rbx
    add rax,DIAG_RING_SIZE
    jc .malformed
    cmp r12,rax
    jae .header
    lea rax,[r12+95]
    cmp rax,rbx
    jae .overlap
.header:
    mov rax,DIAG_MAGIC
    cmp [rbx+DIAG_H_MAGIC],rax
    jne .malformed
    mov rax,DIAG_MAGIC_INV
    cmp [rbx+DIAG_H_MAGIC_INV],rax
    jne .malformed
    cmp dword [rbx+DIAG_H_VERSION],DIAG_VERSION
    jne .malformed
    cmp dword [rbx+DIAG_H_HDR_BYTES],DIAG_HDR_SIZE
    jne .malformed
    cmp dword [rbx+DIAG_H_REC_BYTES],DIAG_REC_SIZE
    jne .malformed
    cmp dword [rbx+DIAG_H_REC_COUNT],DIAG_NREC
    jne .malformed
    cmp dword [rbx+DIAG_H_RING_BYTES],DIAG_RING_SIZE
    jne .malformed
    cmp qword [rbx+DIAG_H_BOOT],0
    je .malformed
    mov rax,[rbx+DIAG_H_BOOT]
    cmp rax,[rel diag_live_boot]
    jne .malformed
    mov r14,[rbx+DIAG_H_SEQ]
    cmp r14,[rel diag_live_first]
    jb .malformed
    cmp r14,-1
    je .malformed                       ; exhausted sequence is not a fresh window
    mov rax,r14
    xor edx,edx
    mov ecx,DIAG_NREC
    div rcx
    shl rdx,6
    cmp [rbx+DIAG_H_HEAD],rdx
    jne .malformed
    mov r15,r14
    sub r15,DIAG_NREC
    jnc .first
    xor r15d,r15d
.first:
    cmp r15,[rel diag_live_first]
    jae .boot_first
    mov r15,[rel diag_live_first]
.boot_first:
    mov rdi,rsp
    xor eax,eax
    mov ecx,12
    rep stosq
    mov rax,[rbx+DIAG_H_BOOT]
    mov [rsp],rax
    mov [rsp+8],r14
    mov [rsp+16],r15
    mov rax,[rel diag_ring_dropped]
    mov [rsp+24],rax
    cmp r13,-1
    je .copy
    cmp r13,r15
    jb .stale
    cmp r13,r14
    jae .stale
    mov rax,r13
    xor edx,edx
    mov ecx,DIAG_NREC
    div rcx
    shl rdx,6
    lea r15,[rbx+rdx+DIAG_HDR_SIZE]
    cmp [r15+DIAG_R_SEQ],r13
    jne .malformed
    lea rdi,[r15+DIAG_R_TAG]
    cmp dword [r15+DIAG_R_KIND],DIAG_K_AER
    je .aer
    cmp dword [r15+DIAG_R_KIND],DIAG_K_MCA
    jne .filtered
    lea rsi,[rel .tag_mca]
    mov ecx,14
    call .tag_equal
    test eax,eax
    jnz .record
    lea rsi,[rel .tag_smca]
    mov ecx,15
    call .tag_equal
    test eax,eax
    jnz .record
    lea rsi,[rel .tag_boot_mca]
    mov ecx,9
    call .tag_equal
    test eax,eax
    jnz .record
    lea rsi,[rel .tag_boot_smca]
    mov ecx,10
    call .tag_equal
    test eax,eax
    jz .filtered
    jmp .record
.aer:
    lea rsi,[rel .tag_aer]
    mov ecx,9
    call .tag_equal
    test eax,eax
    jnz .record
    lea rsi,[rel .tag_aer_v2]
    mov ecx,12
    call .tag_equal
    test eax,eax
    jnz .record
    lea rsi,[rel .tag_aer_boot_root]
    mov ecx,14
    call .tag_equal
    test eax,eax
    jz .filtered
.record:
    mov rsi,r15
    lea rdi,[rsp+32]
    mov ecx,8
    rep movsq
.copy:
    mov rsi,rsp
    mov rdi,r12
    mov ecx,12
    rep movsq
    xor eax,eax
    jmp .release
.overlap:
    mov eax,3
    jmp .release
.missing:
    mov eax,1
    jmp .release
.stale:
    mov eax,4
    jmp .release
.filtered:
    mov eax,5
    jmp .release
.malformed:
    mov eax,6
.release:
    mov qword [rel diag_ring_busy],0
    jmp .done
.busy:
    mov eax,2
.done:
    add rsp,96
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.bad_request:
    mov eax,3
    ret
.unavailable:
    mov eax,1
    ret
.tag_equal:
    xor r8d,r8d
.tag_byte:
    mov al,[rdi+r8]
    cmp al,[rsi+r8]
    jne .tag_no
    inc r8d
    cmp r8d,ecx
    jb .tag_byte
    mov eax,1
    ret
.tag_no:
    xor eax,eax
    ret
.tag_boot_mca: db 'mca-boot',0
.tag_boot_smca: db 'smca-boot',0
.tag_mca: db 'mca-corrected',0
.tag_smca: db 'smca-corrected',0
.tag_aer: db 'aer-poll',0
.tag_aer_v2: db 'aer-poll-v2',0
.tag_aer_boot_root: db 'aer-boot-root',0
; ---- end current hardware-record copy ----

; diag_prev_record_at(RDI=registered kind, RSI=newest matching ordinal)
; -> RAX=prior record pointer or 0. Read-only bounded lookup; no current header
; fields are authority. Same single-writer limitation as diag_prev_fault_at.
; A broken sequence anywhere in the traversed tail refuses rather than skipping
; a torn/overwritten slot and falsely calling an older match the newest.
diag_prev_record_at:
    cmp  rdi, DIAG_K_ENTER
    jb   .miss
    cmp  rdi, DIAG_K_MAX
    ja   .miss
    cmp  rsi, DIAG_NREC
    jae  .miss
    cmp  byte [rel diag_prev_valid], DIAG_PREV_VALID
    jne  .miss
    cmp  qword [rel diag_ptr], 0
    je   .miss
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  ebp, edi
    mov  r15, rsi
    mov  r14, [rel diag_prev_seq]
    test r14, r14
    jz   .miss_saved
    mov  r13, r14
    cmp  r13, DIAG_NREC
    jbe  .have_count
    mov  r13, DIAG_NREC
.have_count:
    mov  rax, r14
    xor  edx, edx
    mov  rcx, DIAG_NREC
    div  rcx
    imul r12, rdx, DIAG_REC_SIZE
    mov  rbx, [rel diag_ptr]
.scan:
    test r13, r13
    jz   .miss_saved
    test r12, r12
    jnz  .back
    mov  r12, DIAG_REC_AREA
.back:
    sub  r12, DIAG_REC_SIZE
    dec  r14
    lea  rax, [rbx + DIAG_HDR_SIZE]
    add  rax, r12
    cmp  [rax + DIAG_R_SEQ], r14
    jne  .miss_saved
    cmp  [rax + DIAG_R_KIND], ebp
    jne  .next
    test r15, r15
    jz   .found
    dec  r15
.next:
    dec  r13
    jmp  .scan
.miss_saved:
    xor  eax, eax
.found:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
.miss:
    xor  eax, eax
    ret
; ---- end registered prior-record lookup ----

; diag_selftest — THE acceptance test. Arm + force a TRAPPED #GP (a non-canonical
;   read), prove the IDT handler wrote a full register dump to the ring, read that
;   record BACK from the ring, report it, and emit the gate marker. (#PF is already
;   exercised by wx_selftest; this covers the #GP dump + the ring readback path.)
;   The fault is "trapped": diag_fault_expect arms core/idt to record+resume at
;   .recover instead of panicking — a diagnosed fault, not a fatal one.
;   clobbers: volatiles (RBX,R12 saved)
diag_selftest:
    push rbx
    push r12
    cmp  byte [rel diag_ready], 0
    je   .fail
    mov  rbx, [rel diag_ptr]               ; snapshot fault count before the fault
    mov  rax, [rbx + DIAG_H_FAULTS]
    mov  [rel diag_pretest_faults], rax
    lea  rax, [rel .recover]               ; arm the trapped-fault recovery point
    mov  [rel diag_fault_recover_rip], rax
    mov  byte [rel diag_fault_expect], 1
    mov  rax, 0x8000000000000000           ; non-canonical linear address
    mov  rax, [rax]                        ; #GP(0) -> isr_common records + resumes
    mov  byte [rel diag_fault_expect], 0   ; reached only if NO fault fired -> broken
    jmp  .fail
.recover:
    mov  byte [rel diag_fault_expect], 0
    ; 1) the fault count must have advanced (a fault record was written)
    mov  rbx, [rel diag_ptr]
    mov  rax, [rbx + DIAG_H_FAULTS]
    cmp  rax, [rel diag_pretest_faults]
    jbe  .fail
    ; 2) read the LAST record back: must be a #GP fault record with a captured RIP
    mov  r11, [rbx + DIAG_H_HEAD]
    test r11, r11
    jnz  .have_head
    mov  r11, DIAG_REC_AREA                 ; head wrapped to 0 => last slot is the top
.have_head:
    sub  r11, DIAG_REC_SIZE
    lea  r12, [rbx + DIAG_HDR_SIZE]
    add  r12, r11                           ; r12 = last record (read back from the ring)
    cmp  dword [r12 + DIAG_R_KIND], DIAG_K_FAULT
    jne  .fail
    cmp  dword [r12 + DIAG_R_ARG], 13       ; #GP vector
    jne  .fail
    cmp  qword [r12 + DIAG_R_A], 0          ; RIP captured?
    je   .fail
    ; 3) report the dump straight from the ring record we just read back
    lea  rdi, [rel str_dump_pfx]
    call serial_string
    mov  edi, [r12 + DIAG_R_ARG]            ; vector
    call serial_hex64
    lea  rdi, [rel str_dump_err]
    call serial_string
    mov  rdi, [r12 + DIAG_R_C]              ; error code
    call serial_hex64
    lea  rdi, [rel str_dump_rip]
    call serial_string
    mov  rdi, [r12 + DIAG_R_A]              ; faulting RIP
    call serial_hex64
    lea  rdi, [rel str_dump_cr2]
    call serial_string
    mov  rdi, [r12 + DIAG_R_B]              ; CR2
    call serial_hex64
    lea  rdi, [rel str_dump_suffix]
    call serial_string
    lea  rdi, [rel str_fault_dump_captured] ; fault-dump gate marker (fault.dump.captured)
    call serial_string
    lea  rdi, [rel str_diag_pass]           ; the gate marker
    call serial_string
    pop  r12
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_diag_fail]
    call serial_string
    pop  r12
    pop  rbx
    ret

; --- core/diag data (in-image RW+X pre-BSS, MEMORY_MAP §3.1). The RING ITSELF is
;     NOT here — it lives at the fixed reserved DIAG_RING_BASE; these are only the
;     module's own scratch/snapshot vars + strings. ---
diag_ready:          db 0                   ; 1 once the ring is bound + stamped
diag_prev_valid:     db DIAG_PREV_NONE      ; NONE, VALID, or bounded BAD_* reason code
align 8, db 0
diag_ring_busy:      dq 0                   ; boot-local, never retained across boots
diag_ring_dropped:   dq 0                   ; contended attempts only; not disabled calls
diag_ptr:            dq 0                   ; bound ring base (== diag_ring_base)
diag_live_first:     dq 0                   ; boot-local sequence floor
diag_live_boot:      dq 0                   ; boot identity captured at bind
diag_prev_boot:      dq 0                   ; snapshot of the previous ring's summary
diag_prev_seq:       dq 0
diag_prev_faults:    dq 0
diag_prev_health_faults: dq 0              ; prior faults after its last successful P7
diag_prev_health_valid: db 0               ; baseline <= cumulative faults_total
diag_prev_fvec:      dq 0
diag_prev_frip:      dq 0
diag_prev_fcr2:      dq 0
diag_pretest_faults: dq 0                   ; fault count before the selftest's forced #GP
diag_prev_crash_slot: times DIAG_CR_BYTES db 0 ; prior header bytes, never live fault state
diag_crash_claimed:  db 0                   ; RCQ-41: 1 once this boot's first fatal fault owns the slot
diag_crash_record_status: db 0              ; RCQ-41 projection result (see diag_crash_record_project)
align 8, db 0
diag_crash_size:     dq 0
diag_crash_attrs:    dd 0
align 8, db 0
diag_crash_record:   times DIAG_CREC_BYTES db 0
diag_crash_verify:   times DIAG_CREC_BYTES db 0
; 7a965d12-c839-4a77-b1e2-906ef724438c: the PaOSInitCheckpoint namespace
; (boot/nvram_access row 7), so the existing NVRAM storage gate applies.
diag_crash_guid:
    dd 0x7A965D12
    dw 0xC839, 0x4A77
    db 0xB1,0xE2,0x90,0x6E,0xF7,0x24,0x43,0x8C
diag_crash_name:     dw 'P','a','O','S','C','r','a','s','h','R','e','c','o','r','d',0

diag_name_unk:  db "?", 0
diag_tag_fault: db "fault", 0

; Phase-name table — DIAG_PH_STRIDE-byte slots, SAME ORDER as the PH_* ids in
; core/abi/diag.inc. Indexed by a runtime lea in diag_name_of (a table, not a
; hardcoded switch — TESTING §5 seam: a new phase is one PH_* + one PHN row).
%macro PHN 1
%%s: db %1, 0
     times DIAG_PH_STRIDE - ($ - %%s) db 0
%endmacro
diag_phase_names:
    PHN "idt"          ; 0  PH_IDT_ST
    PHN "wx"           ; 1  PH_WX_ST
    PHN "lib"          ; 2  PH_LIB
    PHN "logfmt"       ; 3  PH_LOGFMT
    PHN "kat"          ; 4  PH_KAT
    PHN "heap_init"    ; 5  PH_HEAP_INIT
    PHN "heap"         ; 6  PH_HEAP_ST
    PHN "memmap"       ; 7  PH_MEMMAP
    PHN "time"         ; 8  PH_TIME
    PHN "timer_init"   ; 9  PH_TIMER_INIT
    PHN "timer"        ; 10 PH_TIMER_ST
    PHN "sched"        ; 11 PH_SCHED
    PHN "preempt"      ; 12 PH_PREEMPT
    PHN "dma"          ; 13 PH_DMA
    PHN "diag"         ; 14 PH_DIAG
    PHN "hotpatch"     ; 15 PH_HOTPATCH

; Fixed-width runtime-addressed tags for retained C3 P0..P8 edge records.
diag_boot_phase_names:
    db "P0",0,0, "P1",0,0, "P2",0,0, "P3",0,0, "P4",0,0
    db "P5",0,0, "P6",0,0, "P7",0,0, "P8",0,0

str_diag_init:   db "[PAOS64] P2 diag: persistent ring up (fixed region bound)", 13, 10, 0
str_diag_crash_tag:    db "diag-crash-record", 0
str_diag_crash_status: db "[boot.v2.crash-record] status=", 0
str_diag_crash_vec:    db " vector=", 0
str_diag_crash_rip:    db " image_offset=", 0
str_diag_crash_end:    db " authority=diagnostic_only", 13, 10, 0
str_diag_noring: db "[PAOS64] P2 diag: ring UNAVAILABLE (reservation failed) — disabled", 13, 10, 0
str_cur_pfx:     db "[PAOS64] P2 diag: cur-ring boot=", 0
str_cur_seq:     db " seq=", 0
str_cur_faults:  db " faults=", 0
str_prev_pfx:    db "[PAOS64] P2 diag: prev-ring ", 0
str_prev_none:   db "none (fresh cold boot; persistence is warm-reboot/bare-metal)", 13, 10, 0
str_prev_malformed: db "malformed (version/geometry/count/record refused; live ring reformatted)", 13, 10, 0
str_prev_boot:   db "boot=", 0
str_prev_seq:    db " seq=", 0
str_prev_faults: db " faults=", 0
str_prev_lvec:   db " lastfault v=", 0
str_prev_lrip:   db " rip=", 0
str_dump_pfx:    db "[PAOS64] P2 diag: trapped #GP dump v=", 0
str_dump_err:    db " err=", 0
str_dump_rip:    db " rip=", 0
str_dump_cr2:    db " cr2=", 0
str_dump_suffix: db " (ring readback OK)", 13, 10, 0
str_diag_pass:   db "[PAOS64] P2 diag: ring+faultdump PASS", 13, 10, 0
str_diag_fail:   db "[PAOS64] P2 diag: ring+faultdump FAIL", 13, 10, 0
str_fault_dump_captured:  db "[PAOS64] P2 fault: register dump captured [fault.dump.captured]", 13, 10, 0
str_diag_ring_preserved:  db "[PAOS64] P2 diag: ring write->readback OK [diag.ring.preserved]", 13, 10, 0
str_diag_nl:          db 13, 10, 0
