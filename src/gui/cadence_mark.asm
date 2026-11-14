;; MODULE gui/cadence_mark
;; LAYER 6
;; EXPORTS cadence_mark, cadence_batch_begin, cadence_batch_end, cadence_mark_declare, cadence_flicker_registry_init, flicker_analyze, flicker_beat_fixture_arm, flicker_stall_fixture_arm, flicker_crc_fixture_arm, flicker_crc_fixture_clear, cadence_batch_depth, flk_crc_calibrate, flk_crc_calibrated
;; IMPORTS boot/serial, boot/gop, core/time, core/cadence, core/lib/crc32, svc/command, svc/command_scap, gui/taskbar, gui/command_gui, gui/window, dev/input/ps2
;; CAPS
;; OWNER saga:gui_screen_capture
; ============================================================================
; DESKTOP §2.5.1 damage/cadence flight recorder (contract 2131).
;
; This is the ONE paint-event ring.  The hot writer seams test
; cadence_mark_level before setting up a call, so Tier 0 costs one load/branch.
; Tier 1 records DRAW/PRESENT edges only; analysis remains in the read verbs.
;
; The contract fixes a 32-byte record and a 16 KiB ring.  Its prose field list
; says pad[7], but the semantic fields consume 26 bytes, so the realizable
; 32-byte packed layout has six trailing pad bytes:
;   00 tsc:u64, 08 region:u16, 10 event:u8, 11 seq:u16,
;   13 x:u16, 15 y:u16, 17 w:u16, 19 h:u16,
;   21 crc32:u32, 25 flags:u8, 26 pad:u8[6].
; The unaligned word/dword fields are deliberate and safe on x86-64.  Rung 2132
; owns crc32/flags; this rung writes both as zero.
; ============================================================================

CADE_PRESENT          equ 1
CADE_CLEAR            equ 2
CADE_DRAW             equ 3
CADE_INPUT            equ 4
CADE_SAMPLE           equ 5           ; on-demand measurement, never a paint claim

CADR_REGION_TASKBAR   equ 0xFFFD
CADR_REGION_CURSOR    equ 0xFFFE
CADR_REGION_PRESENT   equ 0xFFFF
CADR_REGION_FLICKER   equ 0xFFFC
CADR_REGION_FLK_BEAT  equ 0xFFFB
CADR_REGION_FLK_CRC   equ 0xFFFA
CADR_REGION_TASKBAR_BTN equ 0xFFF9        ; per-window taskbar buttons (Task 2135: one TASKBAR row per tick)

CADR_MAX              equ 512
CADR_REC_SIZE         equ 32
; CRC/flags/epoch evidence expands each row; eight rows keep one page inside
; the canonical 1472-byte F1 datagram without truncating any record.
CADR_PAGE_RECORDS     equ 8

CADR_TSC              equ 0
CADR_REGION           equ 8
CADR_EVENT            equ 10
CADR_SEQ              equ 11
CADR_X                equ 13
CADR_Y                equ 15
CADR_W                equ 17
CADR_H                equ 19
CADR_CRC32            equ 21
CADR_FLAGS            equ 25
CADR_PAD               equ 26

CADR_FLAG_CRC_VALID   equ 0x01
CADR_FLAG_CRC_SAMPLED equ 0x02
CADR_FLAG_FIXTURE     equ 0x80

FLK_CRC_FULL_BYTES    equ 65536
FLK_CRC_SAMPLE_ROWS   equ 8
FLK_CRC_BUDGET_US     equ 2000
FLK_CRC_CAL_SAMPLES   equ 9
FLK_FIXTURE_MS        equ 500
FLK_CRC_FIX_X         equ 8
FLK_CRC_FIX_Y         equ 64
FLK_CRC_FIX_W         equ 256
FLK_CRC_FIX_H         equ 65           ; 66,560 bytes: forces the sampled path

FLKR_ID               equ 0
FLKR_VERDICT          equ 2
FLKR_SAMPLED          equ 3
FLKR_X                equ 4
FLKR_Y                equ 6
FLKR_W                equ 8
FLKR_H                equ 10
FLKR_EVENTS           equ 12
FLKR_SIZE             equ 16
FLKR_MAX              equ 16

FLKV_OK               equ 0
FLKV_BEAT             equ 1
FLKV_STALL            equ 2

; Inline at a framebuffer writer's entry.  Call setup happens only on Tier 1;
; Tier 0 accounts the skipped record without entering cadence_mark.
%macro CADENCE_DRAW_CURRENT 4
    cmp  byte [rel cadence_mark_level], 0
    jne  %%enabled
    inc  dword [rel cadence_dropped]
    jmp  %%done
%%enabled:
    push rax
    push rdi
    push rsi
    push rdx
    push rcx
    movzx edi, word [rel cadence_region_current]
    mov  esi, CADE_DRAW
    mov  edx, %1
    mov  eax, %2
    shl  eax, 16
    or   edx, eax
    mov  ecx, %3
    mov  eax, %4
    shl  eax, 16
    or   ecx, eax
    call cadence_mark
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    pop  rax
%%done:
%endmacro

; Batch edges obey the same Tier-0 rule: no helper call setup when disabled.
; The skipped PRESENT edge is charged at END; BEGIN is only bookkeeping.
%macro CADENCE_BATCH_BEGIN 0
    cmp  byte [rel cadence_mark_level], 0
    jne  %%enabled
    inc  byte [rel cadence_batch_depth]
    jmp  %%done
%%enabled:
    call cadence_batch_begin
%%done:
%endmacro

%macro CADENCE_BATCH_END 0
    cmp  byte [rel cadence_mark_level], 0
    jne  %%enabled
    cmp  byte [rel cadence_batch_depth], 0
    je   %%done
    dec  byte [rel cadence_batch_depth]
    jnz  %%done
    inc  dword [rel cadence_dropped]
    call fb_present_flush              ; 2026-09-08: outermost batch closed -> ONE present
    jmp  %%done
%%enabled:
    call cadence_batch_end
%%done:
%endmacro

; cadence_mark(rdi=region:u16, rsi=event:u8, rdx=x|y<<16, rcx=w|h<<16)
; Preserve every input and scratch register so instrumentation cannot perturb
; the painter.  SPSC today: the BSP paint context is the sole producer.
cadence_mark:
    push rax
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi                     ; region/event/geometry survive CRC work
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, ecx

    ; Writer hooks run immediately before their paint.  Finalizing the previous
    ; record here therefore reads it after that previous painter returned, while
    ; still in the same single-threaded paint context.  The following PRESENT
    ; edge normally closes the last DRAW in a batch; an on-demand read closes
    ; the final pending edge before analysis.
    call cadence_crc_finalize_pending

    mov  r8d, [rel cadence_head]
    shl  r8d, 5                        ; * CADR_REC_SIZE
    lea  r9, [rel cadence_ring]
    add  r9, r8
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [r9 + CADR_TSC], rax
    mov  [rel cadence_last_tsc], rax
    mov  [r9 + CADR_REGION], r12w
    mov  [r9 + CADR_EVENT], r13b
    mov  ax, [rel cadence_seq]
    mov  [r9 + CADR_SEQ], ax
    inc  word [rel cadence_seq]

    mov  eax, r14d
    mov  [r9 + CADR_X], ax
    shr  eax, 16
    mov  [r9 + CADR_Y], ax
    mov  eax, r15d
    mov  [r9 + CADR_W], ax
    shr  eax, 16
    mov  [r9 + CADR_H], ax
    mov  dword [r9 + CADR_CRC32], 0
    mov  byte [r9 + CADR_FLAGS], 0
    mov  dword [r9 + CADR_PAD], 0
    mov  word [r9 + CADR_PAD + 4], 0
    mov  [rel cadence_pending_ptr], r9

    mov  eax, [rel cadence_count]
    cmp  eax, CADR_MAX
    jae  .overwrite
    inc  dword [rel cadence_count]
    jmp  .counted
.overwrite:
    inc  dword [rel cadence_wrapped]
.counted:
    inc  dword [rel cadence_records_total]
    mov  eax, [rel cadence_head]
    inc  eax
    and  eax, CADR_MAX - 1
    mov  [rel cadence_head], eax

    ; A DRAW inside an open batch contributes to its exact bounding union.
    cmp  r13b, CADE_DRAW
    jne  .done
    cmp  byte [rel cadence_batch_depth], 0
    je   .done
    mov  eax, r14d
    and  eax, 0xFFFF                   ; x
    mov  edx, r14d
    shr  edx, 16                       ; y
    mov  ecx, r15d
    and  ecx, 0xFFFF                   ; w
    mov  r8d, r15d
    shr  r8d, 16                       ; h
    add  ecx, eax                      ; x2 (exclusive)
    add  r8d, edx                      ; y2 (exclusive)
    cmp  byte [rel cadence_batch_valid], 0
    jne  .union_existing
    mov  [rel cadence_batch_x], eax
    mov  [rel cadence_batch_y], edx
    mov  [rel cadence_batch_x2], ecx
    mov  [rel cadence_batch_y2], r8d
    mov  byte [rel cadence_batch_valid], 1
    jmp  .done
.union_existing:
    cmp  eax, [rel cadence_batch_x]
    jae  .x_min_ok
    mov  [rel cadence_batch_x], eax
.x_min_ok:
    cmp  edx, [rel cadence_batch_y]
    jae  .y_min_ok
    mov  [rel cadence_batch_y], edx
.y_min_ok:
    cmp  ecx, [rel cadence_batch_x2]
    jbe  .x_max_ok
    mov  [rel cadence_batch_x2], ecx
.x_max_ok:
    cmp  r8d, [rel cadence_batch_y2]
    jbe  .done
    mov  [rel cadence_batch_y2], r8d
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    pop  rax
    ret

; Finalize the previous record from the settled framebuffer.  Full rects repack
; every row; larger rects deterministically repack y,y+8,y+16... until the
; 64 KiB payload cap.  Thus every record makes exactly one bounded call to the
; canonical CRC and the calibrated 64 KiB cost is an honest hot-path ceiling.
cadence_crc_finalize_pending:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    ; A metal calibration over budget leaves Tier 1 safely unarmed.  TCG is
    ; still permitted to exercise the exact path (its translated wall cost is
    ; not a display-performance claim); the raw measured cost remains visible.
    cmp  byte [rel flk_crc_calibrated], 1
    jne  .out
    mov  rbx, [rel cadence_pending_ptr]
    test rbx, rbx
    jz   .out
    mov  qword [rel cadence_pending_ptr], 0
    movzx eax, byte [rbx + CADR_EVENT]
    cmp  eax, CADE_DRAW
    je   .event_eligible
    cmp  eax, CADE_PRESENT
    je   .event_eligible
    cmp  eax, CADE_SAMPLE
    jne  .out
.event_eligible:
    mfence                             ; 1249: WC framebuffer — drain combining buffers before the CRC row copy
    mov  rbp, [rel fb_perf_scratch]
    test rbp, rbp
    jz   .out
    mov  rax, [rel fb_base]
    test rax, rax
    je   .out
    cmp  rax, rbp
    je   .out                          ; PERF redirects fb here; never self-repack

    movzx eax, word [rbx + CADR_W]
    test eax, eax
    jz   .out
    mov  r12d, eax
    shl  r12d, 2                       ; packed bytes per selected row
    cmp  r12d, FLK_CRC_FULL_BYTES
    ja   .out                          ; one row cannot fit the measured cap
    movzx eax, word [rbx + CADR_H]
    test eax, eax
    jz   .out
    mov  r13d, 1
    movzx ecx, word [rbx + CADR_W]
    movzx edx, word [rbx + CADR_H]
    imul rcx, rdx
    shl  rcx, 2
    cmp  rcx, FLK_CRC_FULL_BYTES
    jbe  .step_ready
    mov  r13d, FLK_CRC_SAMPLE_ROWS
.step_ready:
    ; SCREEN2 must be able to pull the same exact rect: reject, do not clip.
    movzx eax, word [rbx + CADR_X]
    movzx ecx, word [rbx + CADR_W]
    add  ecx, eax
    cmp  ecx, [rel fb_width]
    ja   .out
    movzx eax, word [rbx + CADR_Y]
    movzx ecx, word [rbx + CADR_H]
    add  ecx, eax
    cmp  ecx, [rel fb_height]
    ja   .out

    xor  r14d, r14d                    ; bytes packed (never above the cap)
    xor  r15d, r15d                    ; rect-relative row
.row:
    movzx eax, word [rbx + CADR_H]
    cmp  r15d, eax
    jae  .rows_done
    mov  eax, r14d
    add  eax, r12d
    cmp  eax, FLK_CRC_FULL_BYTES
    jbe  .copy_row
    jmp  .rows_done                    ; deterministic first selected rows only
.copy_row:
    movzx eax, word [rbx + CADR_Y]
    add  eax, r15d
    imul eax, [rel fb_stride]
    movzx ecx, word [rbx + CADR_X]
    add  eax, ecx
    mov  rsi, [rel fb_base]
    lea  rsi, [rsi + rax*4]
    lea  rdi, [rbp + r14]
    mov  ecx, r12d
    cld
    rep  movsb
    add  r14d, r12d
    add  r15d, r13d
    jmp  .row
.rows_done:
    test r14d, r14d
    jz   .out
    mov  rdi, rbp
    mov  esi, r14d
    call hotpatch_crc32
    mov  [rbx + CADR_CRC32], eax
    mov  al, CADR_FLAG_CRC_VALID
    cmp  r13d, 1
    je   .flags
    or   al, CADR_FLAG_CRC_SAMPLED
.flags:
    mov  [rbx + CADR_FLAGS], al
    mov  eax, [rel scap_geom_epoch]
    mov  [rbx + CADR_PAD], eax          ; same-geometry cross-check token
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Median of nine fenced measurements of the canonical CRC over one buffer.
flk_crc_measure_med:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13d, esi
    xor  r14d, r14d
.sample:
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rbx, rax
    mov  rdi, r12
    mov  esi, r13d
    call hotpatch_crc32
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, rbx
    lea  rcx, [rel flk_crc_cal_samples]
    mov  [rcx + r14*4], eax
    inc  r14d
    cmp  r14d, FLK_CRC_CAL_SAMPLES
    jb   .sample
    mov  r14d, 1
.isort:
    cmp  r14d, FLK_CRC_CAL_SAMPLES
    jae  .sorted
    lea  rcx, [rel flk_crc_cal_samples]
    mov  eax, [rcx + r14*4]
    mov  ebx, r14d
.shift:
    test ebx, ebx
    jz   .place
    lea  edx, [ebx - 1]
    mov  r13d, [rcx + rdx*4]
    cmp  r13d, eax
    jbe  .place
    mov  [rcx + rbx*4], r13d
    dec  ebx
    jmp  .shift
.place:
    mov  [rcx + rbx*4], eax
    inc  r14d
    jmp  .isort
.sorted:
    mov  eax, [rcx + (FLK_CRC_CAL_SAMPLES/2)*4]
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Boot calibration is earned from the already-allocated off-screen benchmark
; scratch.  Both 1 KiB and the actual 64 KiB cap are measured; no estimate is
; substituted when TSC calibration or scratch is unavailable.
flk_crc_calibrate:
    push rbx
    mov  rbx, [rel fb_perf_scratch]
    test rbx, rbx
    jz   .fail
    mov  rdi, rbx
    mov  esi, 1024
    call flk_crc_measure_med
    mov  [rel flk_crc_cycles_1k], eax
    mov  rdi, rbx
    mov  esi, FLK_CRC_FULL_BYTES
    call flk_crc_measure_med
    mov  [rel flk_crc_cycles_64k], eax
    test eax, eax
    jz   .fail
    mov  ecx, FLK_CRC_FULL_BYTES
    dec  ecx
    add  rax, rcx
    xor  edx, edx
    mov  ecx, FLK_CRC_FULL_BYTES
    div  rcx
    mov  [rel flk_crc_cycles_per_byte], eax
    mov  eax, [rel flk_crc_cycles_64k]
    imul rax, rax, 1000
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jz   .fail
    lea  rax, [rax + rcx - 1]
    xor  edx, edx
    div  rcx
    mov  [rel flk_crc_cost_us_64k], eax
    test eax, eax
    jz   .fail
    cmp  eax, FLK_CRC_BUDGET_US
    jbe  .armed
    ; The contract's 2 ms budget grades the Lenovo hot path.  QEMU/TCG must
    ; nevertheless boot the same instrument so its both-target marker and
    ; functional regressions remain live; CPUID.HYPERVISOR makes that exception
    ; explicit while preserving the measured (possibly >2 ms) CADSTAT value.
    mov  eax, 1
    cpuid
    test ecx, 0x80000000
    jz   .fail
.armed:
    mov  byte [rel flk_crc_calibrated], 1
    lea  rdi, [rel str_flk_crc_armed]
    call serial_string
    pop  rbx
    ret
.fail:
    mov  byte [rel flk_crc_calibrated], 0
    lea  rdi, [rel str_flk_crc_fail]
    call serial_string
    pop  rbx
    ret

; Called after form_cadence_live_init, because that shipped initializer resets
; the one core table.  The returned slot is the only registry state consumed by
; FLICKER; no parallel registry or structural extension is introduced.
cadence_flicker_registry_init:
    push rbx
    mov  rbx, [rel tsc_khz]
    imul rbx, rbx, FLK_FIXTURE_MS
    test rbx, rbx
    jnz  .period
    mov  rbx, 500000
.period:
    lea  rdi, [rel str_flk_cad_id]
    mov  esi, 1                        ; on_demand
    xor  edx, edx                      ; declared_hz=0 spells on-demand honestly
    mov  rcx, rbx                      ; retained declared interval for STALLFIX
    xor  r8d, r8d
    call cadence_register_named
    cmp  eax, -1
    je   .fail
    mov  [rel flk_cad_slot], eax
    mov  ecx, eax
    imul rcx, rcx, CAD_ENT_SZ
    lea  rdx, [rel cad_table]
    add  rdx, rcx
    mov  qword [rdx + CAD_RATE], -1    ; cadence_poll must not drive on-demand work
    mov  qword [rdx + CAD_DEADLINE], -1
    pop  rbx
    ret
.fail:
    mov  dword [rel flk_cad_slot], -1
    pop  rbx
    ret

; Deterministic A/B/A/B classifier fixture.  These records are explicitly
; flagged as synthetic samples: they exercise only the on-demand analyzer and
; never pretend that a paint occurred or alter framebuffer pixels.
flicker_beat_fixture_arm:
    push rbx
    push r14
    cmp  byte [rel flk_crc_calibrated], 1
    jne  .out
    call cadence_crc_finalize_pending
    xor  r14d, r14d
.edge:
    mov  edi, CADR_REGION_FLK_BEAT
    mov  esi, CADE_SAMPLE
    mov  edx, 0x00020002              ; x=2,y=2
    mov  ecx, 0x00010001              ; w=1,h=1
    call cadence_mark
    mov  rbx, [rel cadence_pending_ptr]
    test rbx, rbx
    jz   .out
    mov  qword [rel cadence_pending_ptr], 0
    mov  eax, 0xA17E5EED
    test r14b, 1
    jz   .store
    mov  eax, 0xB26F6FFE
.store:
    mov  [rbx + CADR_CRC32], eax
    mov  byte [rbx + CADR_FLAGS], CADR_FLAG_CRC_VALID | CADR_FLAG_FIXTURE
    mov  eax, [rel scap_geom_epoch]
    mov  [rbx + CADR_PAD], eax
    inc  r14d
    cmp  r14d, 4
    jb   .edge
.out:
    pop  r14
    pop  rbx
    ret

; Deterministic synthetic stall: register one settled 1x1 sample and then feed
; it no more.  Analysis compares elapsed time with the consumer entry's actual
; CAD_PERIOD, never a duplicated clock constant.
flicker_stall_fixture_arm:
    push rdi
    push rsi
    push rdx
    push rcx
    call cadence_crc_finalize_pending
    mov  edi, CADR_REGION_FLICKER
    mov  esi, CADE_SAMPLE
    xor  edx, edx
    mov  ecx, 0x00010001
    call cadence_mark
    call cadence_crc_finalize_pending
    mov  rax, [rel cadence_last_tsc]
    mov  [rel flk_fixture_tsc], rax
    mov  byte [rel flk_fixture_armed], 1
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret

; Deterministic sampled-path acceptance measurement.  Snapshot one already-
; rendered >64 KiB rectangle through the same capped CRC path; no painter is
; called and no framebuffer byte is changed.  SCREEN2 can therefore pull the
; settled pixels immediately and independently recompute the sampled CRC.
flicker_crc_fixture_arm:
    cmp  byte [rel flk_crc_calibrated], 1
    jne  .out
    cmp  dword [rel fb_width], FLK_CRC_FIX_X + FLK_CRC_FIX_W
    jb   .out
    cmp  dword [rel fb_height], FLK_CRC_FIX_Y + FLK_CRC_FIX_H
    jb   .out
    call cadence_crc_finalize_pending
    mov  edi, CADR_REGION_FLK_CRC
    mov  esi, CADE_SAMPLE
    mov  edx, (FLK_CRC_FIX_Y << 16) | FLK_CRC_FIX_X
    mov  ecx, (FLK_CRC_FIX_H << 16) | FLK_CRC_FIX_W
    call cadence_mark
    call cadence_crc_finalize_pending
.out:
    ret

; Retained additive verb surface from the earlier reversible-paint fixture.
; Measurement-only CRCFIX has nothing to restore.
flicker_crc_fixture_clear:
    ret

; EAX=newest-relative offset -> RAX=record pointer in the snapshotted ring.
flk_ring_at_offset:
    mov  edx, [rel flk_snap_head]
    dec  edx
    sub  edx, eax
    and  edx, CADR_MAX - 1
    shl  edx, 5
    lea  rax, [rel cadence_ring]
    add  rax, rdx
    ret

; DI=region -> RAX=compact result row, adding one if capacity remains.
flk_region_find_or_add:
    xor  ecx, ecx
    lea  rax, [rel flk_regions]
.find:
    cmp  ecx, [rel flk_region_count]
    jae  .add
    cmp  [rax + FLKR_ID], di
    je   .done
    add  rax, FLKR_SIZE
    inc  ecx
    jmp  .find
.add:
    cmp  ecx, FLKR_MAX
    jae  .none
    mov  [rax + FLKR_ID], di
    mov  byte [rax + FLKR_VERDICT], FLKV_OK
    mov  byte [rax + FLKR_SAMPLED], 0
    mov  qword [rax + FLKR_X], 0
    mov  dword [rax + FLKR_EVENTS], 0
    inc  dword [rel flk_region_count]
.done:
    ret
.none:
    xor  eax, eax
    ret

; EAX=start offset, RDI=reference record -> next older valid record with the
; exact same region AND rect, or EAX=-1.  This exact pair prevents composition
; of two different rects in one region from masquerading as a beat.
flk_find_older_same:
    push rbx
    push r12
    mov  ebx, eax
    mov  r12, rdi
.scan:
    cmp  ebx, [rel flk_snap_count]
    jae  .none
    mov  eax, ebx
    call flk_ring_at_offset
    test byte [rax + CADR_FLAGS], CADR_FLAG_CRC_VALID
    jz   .next
    movzx edx, byte [rax + CADR_EVENT]
    cmp  edx, CADE_DRAW
    je   .eligible
    cmp  edx, CADE_PRESENT
    je   .eligible
    test byte [rax + CADR_FLAGS], CADR_FLAG_FIXTURE
    jz   .next
.eligible:
    mov  rdx, [rel flk_snap_cutoff]
    cmp  [rax + CADR_TSC], rdx
    jb   .none
    mov  dx, [r12 + CADR_REGION]
    cmp  [rax + CADR_REGION], dx
    jne  .next
    mov  dx, [r12 + CADR_X]
    cmp  [rax + CADR_X], dx
    jne  .next
    mov  dx, [r12 + CADR_Y]
    cmp  [rax + CADR_Y], dx
    jne  .next
    mov  dx, [r12 + CADR_W]
    cmp  [rax + CADR_W], dx
    jne  .next
    mov  dx, [r12 + CADR_H]
    cmp  [rax + CADR_H], dx
    jne  .next
    mov  eax, ebx
    jmp  .out
.next:
    inc  ebx
    jmp  .scan
.none:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; Host-driven bounded analysis.  Nothing below runs from the paint hot path.
; The 2-second time horizon makes a stopped A/B fight clear after settling while
; the resident-record cap remains CADR_MAX.
flicker_analyze:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    call cadence_crc_finalize_pending
    mov  eax, [rel cadence_count]
    mov  [rel flk_snap_count], eax
    mov  eax, [rel cadence_head]
    mov  [rel flk_snap_head], eax
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel flk_analysis_tsc], rax
    mov  rcx, [rel tsc_khz]
    imul rcx, rcx, 2000
    cmp  rax, rcx
    jb   .zero_cutoff
    sub  rax, rcx
    jmp  .cutoff
.zero_cutoff:
    xor  eax, eax
.cutoff:
    mov  [rel flk_snap_cutoff], rax

    lea  rdi, [rel flk_regions]
    mov  ecx, FLKR_MAX * FLKR_SIZE
    xor  eax, eax
    cld
    rep  stosb
    lea  rdi, [rel flk_beat_members]
    mov  ecx, CADR_MAX
    rep  stosb
    mov  dword [rel flk_region_count], 0
    mov  dword [rel flk_analyzed_count], 0
    mov  dword [rel flk_beat_count], 0
    mov  dword [rel flk_stall_count], 0

    ; Pass 1: bounded resident records -> unique region rows + event counts.
    xor  r12d, r12d
.collect:
    cmp  r12d, [rel flk_snap_count]
    jae  .beat_scan_start
    mov  eax, r12d
    call flk_ring_at_offset
    mov  r13, rax
    test byte [r13 + CADR_FLAGS], CADR_FLAG_CRC_VALID
    jz   .collect_next
    mov  rax, [r13 + CADR_TSC]
    cmp  rax, [rel flk_snap_cutoff]
    jb   .beat_scan_start
    movzx edi, byte [r13 + CADR_EVENT]
    cmp  edi, CADE_DRAW
    je   .collect_event
    cmp  edi, CADE_PRESENT
    je   .collect_event
    test byte [r13 + CADR_FLAGS], CADR_FLAG_FIXTURE
    jz   .collect_next
.collect_event:
    inc  dword [rel flk_analyzed_count]
    movzx edi, word [r13 + CADR_REGION]
    call flk_region_find_or_add
    test rax, rax
    jz   .collect_next
    cmp  dword [rax + FLKR_EVENTS], 0
    jne  .event_count
    mov  dx, [r13 + CADR_X]
    mov  [rax + FLKR_X], dx
    mov  dx, [r13 + CADR_Y]
    mov  [rax + FLKR_Y], dx
    mov  dx, [r13 + CADR_W]
    mov  [rax + FLKR_W], dx
    mov  dx, [r13 + CADR_H]
    mov  [rax + FLKR_H], dx
    mov  dl, [r13 + CADR_FLAGS]
    and  dl, CADR_FLAG_CRC_SAMPLED
    setnz dl
    mov  [rax + FLKR_SAMPLED], dl
.event_count:
    inc  dword [rax + FLKR_EVENTS]
.collect_next:
    inc  r12d
    jmp  .collect

    ; Pass 2: every record asks for its next three exact-group predecessors.
    ; D,C,B,A is a beat iff D==B, C==A, and D!=C.  Member bytes prevent
    ; overlapping quartets from inflating maxscore.
.beat_scan_start:
    xor  r12d, r12d
.beat_scan:
    cmp  r12d, [rel flk_snap_count]
    jae  .score_members
    mov  eax, r12d
    call flk_ring_at_offset
    mov  r13, rax
    test byte [r13 + CADR_FLAGS], CADR_FLAG_CRC_VALID
    jz   .beat_next
    movzx eax, byte [r13 + CADR_EVENT]
    cmp  eax, CADE_DRAW
    je   .beat_event
    cmp  eax, CADE_PRESENT
    je   .beat_event
    test byte [r13 + CADR_FLAGS], CADR_FLAG_FIXTURE
    jz   .beat_next
.beat_event:
    mov  rax, [r13 + CADR_TSC]
    cmp  rax, [rel flk_snap_cutoff]
    jb   .score_members
    mov  ebx, [r13 + CADR_CRC32]
    lea  eax, [r12d + 1]
    mov  rdi, r13
    call flk_find_older_same
    cmp  eax, -1
    je   .beat_next
    mov  [rel flk_q_j], eax
    call flk_ring_at_offset
    mov  r14d, [rax + CADR_CRC32]
    cmp  r14d, ebx
    je   .beat_next                    ; A and B must be distinct
    mov  eax, [rel flk_q_j]
    inc  eax
    mov  rdi, r13
    call flk_find_older_same
    cmp  eax, -1
    je   .beat_next
    mov  [rel flk_q_k], eax
    call flk_ring_at_offset
    cmp  [rax + CADR_CRC32], ebx
    jne  .beat_next
    mov  eax, [rel flk_q_k]
    inc  eax
    mov  rdi, r13
    call flk_find_older_same
    cmp  eax, -1
    je   .beat_next
    mov  [rel flk_q_l], eax
    call flk_ring_at_offset
    cmp  [rax + CADR_CRC32], r14d
    jne  .beat_next
    lea  rax, [rel flk_beat_members]
    mov  byte [rax + r12], 1
    mov  ecx, [rel flk_q_j]
    mov  byte [rax + rcx], 1
    mov  ecx, [rel flk_q_k]
    mov  byte [rax + rcx], 1
    mov  ecx, [rel flk_q_l]
    mov  byte [rax + rcx], 1
    movzx edi, word [r13 + CADR_REGION]
    call flk_region_find_or_add
    test rax, rax
    jz   .beat_next
    mov  byte [rax + FLKR_VERDICT], FLKV_BEAT
    mov  dx, [r13 + CADR_X]
    mov  [rax + FLKR_X], dx
    mov  dx, [r13 + CADR_Y]
    mov  [rax + FLKR_Y], dx
    mov  dx, [r13 + CADR_W]
    mov  [rax + FLKR_W], dx
    mov  dx, [r13 + CADR_H]
    mov  [rax + FLKR_H], dx
.beat_next:
    inc  r12d
    jmp  .beat_scan

.score_members:
    xor  r12d, r12d
    xor  r13d, r13d
    lea  rbx, [rel flk_beat_members]
.member:
    cmp  r12d, [rel flk_snap_count]
    jae  .stall_check
    cmp  byte [rbx + r12], 0
    je   .member_next
    inc  r13d
.member_next:
    inc  r12d
    jmp  .member

.stall_check:
    ; Live stall oracle: taskbar.clock and taskbar.attention are registry-owned
    ; cadences and both paint CADR_REGION_TASKBAR.  Derive the strictest of
    ; their declared intervals from the ONE table, then compare it with the
    ; newest settled taskbar edge.  No clock period is duplicated here.
    xor  r14d, r14d                    ; minimum taskbar CAD_PERIOD (0=none)
    xor  r12d, r12d
.stall_cadence_scan:
    cmp  r12d, [rel cad_count]
    jae  .stall_find_taskbar
    mov  eax, r12d
    imul rax, rax, CAD_ENT_SZ
    lea  rbx, [rel cad_table]
    add  rbx, rax
    mov  rsi, [rbx + CAD_ID]
    test rsi, rsi
    jz   .stall_cadence_next
    cmp  dword [rsi], 'task'
    jne  .stall_cadence_next
    cmp  dword [rsi + 4], 'bar.'
    jne  .stall_cadence_next
    mov  rax, [rbx + CAD_PERIOD]
    test rax, rax
    jz   .stall_cadence_next
    test r14, r14
    jz   .stall_take_period
    cmp  rax, r14
    jae  .stall_cadence_next
.stall_take_period:
    mov  r14, rax
.stall_cadence_next:
    inc  r12d
    jmp  .stall_cadence_scan
.stall_find_taskbar:
    test r14, r14
    jz   .stall_fixture
    cmp  byte [rel dpms_blanked], 1    ; RCQ-27 L3: a blanked screen skips the attention
    je   .stall_fixture                ; repaint by design, which is not a stall
    xor  r12d, r12d
.stall_taskbar_scan:
    cmp  r12d, [rel flk_snap_count]
    jae  .stall_fixture
    mov  eax, r12d
    call flk_ring_at_offset
    mov  rbx, rax
    test byte [rbx + CADR_FLAGS], CADR_FLAG_CRC_VALID
    jz   .stall_taskbar_next
    mov  rax, [rbx + CADR_TSC]
    cmp  rax, [rel flk_snap_cutoff]
    jb   .stall_fixture
    cmp  word [rbx + CADR_REGION], CADR_REGION_TASKBAR
    jne  .stall_taskbar_next
    movzx eax, byte [rbx + CADR_EVENT]
    cmp  eax, CADE_DRAW
    je   .stall_taskbar_age
    cmp  eax, CADE_PRESENT
    jne  .stall_taskbar_next
.stall_taskbar_age:
    mov  rax, r14
    shl  rax, 1
    mov  rcx, [rel flk_analysis_tsc]
    sub  rcx, [rbx + CADR_TSC]
    cmp  rcx, rax
    jbe  .stall_fixture
    mov  edi, CADR_REGION_TASKBAR
    call flk_region_find_or_add
    test rax, rax
    jz   .stall_fixture
    mov  byte [rax + FLKR_VERDICT], FLKV_STALL
    jmp  .stall_fixture
.stall_taskbar_next:
    inc  r12d
    jmp  .stall_taskbar_scan

.stall_fixture:
    cmp  byte [rel flk_fixture_armed], 1
    jne  .count_verdicts
    mov  eax, [rel flk_cad_slot]
    cmp  eax, -1
    je   .count_verdicts
    imul rax, rax, CAD_ENT_SZ
    lea  rbp, [rel cad_table]
    add  rbp, rax
    mov  rax, [rbp + CAD_PERIOD]
    shl  rax, 1
    mov  rcx, [rel flk_analysis_tsc]
    sub  rcx, [rel flk_fixture_tsc]
    cmp  rcx, rax
    jbe  .count_verdicts
    mov  edi, CADR_REGION_FLICKER
    call flk_region_find_or_add
    test rax, rax
    jz   .count_verdicts
    mov  byte [rax + FLKR_VERDICT], FLKV_STALL
    mov  word [rax + FLKR_X], 0
    mov  word [rax + FLKR_Y], 0
    mov  word [rax + FLKR_W], 1
    mov  word [rax + FLKR_H], 1

.count_verdicts:
    xor  r12d, r12d
    lea  rbx, [rel flk_regions]
.verdict:
    cmp  r12d, [rel flk_region_count]
    jae  .maxscore
    cmp  byte [rbx + FLKR_VERDICT], FLKV_BEAT
    jne  .not_beat
    inc  dword [rel flk_beat_count]
    jmp  .verdict_next
.not_beat:
    cmp  byte [rbx + FLKR_VERDICT], FLKV_STALL
    jne  .verdict_next
    inc  dword [rel flk_stall_count]
.verdict_next:
    add  rbx, FLKR_SIZE
    inc  r12d
    jmp  .verdict

.maxscore:
    xor  eax, eax
    cmp  dword [rel flk_analyzed_count], 0
    je   .score_ready
    mov  eax, r13d
    imul eax, eax, 1000
    xor  edx, edx
    div  dword [rel flk_analyzed_count]
    cmp  eax, 999                       ; gui_out_frac3's fixed 0.NNN grammar
    jbe  .score_ready
    mov  eax, 999
.score_ready:
    mov  [rel flicker_maxscore], eax

    ; Project the current analysis into the one registry consumer entry.
    mov  eax, [rel flk_cad_slot]
    cmp  eax, -1
    je   .out
    imul rax, rax, CAD_ENT_SZ
    lea  rbx, [rel cad_table]
    add  rbx, rax
    inc  qword [rbx + CAD_FIRES]
    mov  rax, [rbx + CAD_FIRES]
    mov  [rbx + CAD_MEAS_HZ], rax       ; on-demand measured_rate=analysis count
    mov  eax, [rel flk_stall_count]
    mov  [rbx + CAD_MISSED], rax
    mov  ecx, [rel flk_beat_count]
    add  ecx, eax
    xor  eax, eax
    test ecx, ecx
    setnz al
    mov  [rbx + CAD_VITAL], rax
    call time_monotonic_now_us
    xor  edx, edx
    mov  ecx, 1000
    div  rcx
    mov  [rbx + CAD_AUDIT], rax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Layer-3 cursor writer callback.  ps2.asm owns only the optional downward
; callback seam; the ONE ring and record primitive remain here at Layer 6.
cadence_mark_cursor:
    mov  edi, CADR_REGION_CURSOR
    mov  esi, CADE_DRAW
    mov  edx, r8d
    mov  eax, r9d
    shl  eax, 16
    or   edx, eax
    mov  ecx, r10d
    mov  eax, r11d
    shl  eax, 16
    or   ecx, eax
    call cadence_mark
    ret

; Nestable batch boundary.  Only the outer exit emits PRESENT, so a WINMOVE's
; old-footprint erase and nested whole-desktop repaint share one honest edge.
cadence_batch_begin:
    cmp  byte [rel cadence_batch_depth], 0
    jne  .nested
    mov  byte [rel cadence_batch_valid], 0
.nested:
    inc  byte [rel cadence_batch_depth]
    ret

cadence_batch_end:
    push rax
    push rdi
    push rsi
    push rdx
    push rcx
    cmp  byte [rel cadence_batch_depth], 0
    je   .out
    dec  byte [rel cadence_batch_depth]
    jnz  .out
    call fb_present_flush               ; 2026-09-08: outermost batch closed -> ONE present
    cmp  byte [rel cadence_mark_level], 0
    jne  .enabled
    inc  dword [rel cadence_dropped]    ; the skipped PRESENT edge
    mov  byte [rel cadence_batch_valid], 0
    jmp  .out
.enabled:
    cmp  byte [rel cadence_batch_valid], 0
    je   .out
    mov  edx, [rel cadence_batch_x]
    mov  eax, [rel cadence_batch_y]
    shl  eax, 16
    or   edx, eax
    mov  ecx, [rel cadence_batch_x2]
    sub  ecx, [rel cadence_batch_x]
    mov  eax, [rel cadence_batch_y2]
    sub  eax, [rel cadence_batch_y]
    shl  eax, 16
    or   ecx, eax
    mov  edi, CADR_REGION_PRESENT
    mov  esi, CADE_PRESENT
    call cadence_mark
    mov  byte [rel cadence_batch_valid], 0
.out:
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    pop  rax
    ret

; Register the two read-only Tier-0 verbs, bind the lower-layer cursor callback,
; and arm the earned boot marker.
cadence_mark_declare:
    push rbx
    xor  ebx, ebx
    lea  rdi, [rel str_verb_cadmark]
    lea  rsi, [rel cmd_verb_cadmark]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    or   ebx, eax
    lea  rdi, [rel str_verb_cadstat]
    lea  rsi, [rel cmd_verb_cadstat]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    or   ebx, eax
    xor  edi, edi
    cmp  byte [rel cadence_mark_level], 0
    je   .bind_cursor
    lea  rdi, [rel cadence_mark_cursor]
.bind_cursor:
    lea  rsi, [rel cadence_dropped]
    call ps2_cursor_set_damage_hook
    test ebx, ebx
    js   .ret
    cmp  byte [rel cadence_mark_level], 0
    je   .ret
    mov  byte [rel cadence_armed], 1
    lea  rdi, [rel str_cadence_armed]
    call serial_string
    call flk_crc_calibrate
.ret:
    pop  rbx
    ret

; CADSTAT -> live counters.  `records` is total accepted records; count is
; intentionally not substituted, so overflow accounting remains auditable.
cmd_verb_cadstat:
    call cmd_handler_prologue
    push rdi
    push rsi
    push r12
    mov  r12, rsi
    call f1_out_reset
    lea  rdi, [rel str_cadstat_head]
    call f1_put_str
    movzx edi, byte [rel cadence_mark_level]
    call f1_put_dec
    lea  rdi, [rel str_cadstat_records]
    call f1_put_str
    mov  edi, [rel cadence_records_total]
    call f1_put_dec
    lea  rdi, [rel str_cadstat_dropped]
    call f1_put_str
    mov  edi, [rel cadence_dropped]
    call f1_put_dec
    lea  rdi, [rel str_cadstat_wrapped]
    call f1_put_str
    mov  edi, [rel cadence_wrapped]
    call f1_put_dec
    lea  rdi, [rel str_cadstat_crc_cost]
    call f1_put_str
    mov  edi, [rel flk_crc_cost_us_64k]
    call f1_put_dec
    lea  rdi, [rel str_cadstat_last]
    call f1_put_str
    mov  rdi, [rel cadence_last_tsc]
    call cadr_put_hex16
    mov  byte [rel f1_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  qword [r12 + RSP_VAL], 0
    pop  r12
    pop  rsi
    pop  rdi
    ret

; CADMARK [page] -> newest-first, ring-index paged snapshot.  Page identity is
; derived from the snapshotted head/count, never from wrapping seq.
cmd_verb_cadmark:
    call cmd_handler_prologue
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r15, rsi                       ; response
    mov  rdi, [rdi + REQ_ARG]
    call gui_parse_u32
    mov  r12d, eax                      ; requested zero-based page
    mov  r13d, [rel cadence_count]      ; stable resident-count snapshot
    mov  r14d, [rel cadence_head]       ; stable next-write snapshot

    mov  eax, r13d
    add  eax, CADR_PAGE_RECORDS - 1
    xor  edx, edx
    mov  ecx, CADR_PAGE_RECORDS
    div  ecx
    mov  ebx, eax                       ; page count
    test ebx, ebx
    jnz  .pages_ready
    mov  ebx, 1
.pages_ready:
    mov  eax, r12d
    imul eax, CADR_PAGE_RECORDS
    xor  ebp, ebp                       ; records shown on this page
    cmp  eax, r13d
    jae  .shown_ready
    mov  ebp, r13d
    sub  ebp, eax
    cmp  ebp, CADR_PAGE_RECORDS
    jbe  .shown_ready
    mov  ebp, CADR_PAGE_RECORDS
.shown_ready:
    call f1_out_reset
    lea  rdi, [rel str_cadmark_page]
    call f1_put_str
    mov  edi, r12d
    call f1_put_dec
    lea  rdi, [rel str_cadr_slash]
    call f1_put_str
    mov  edi, ebx
    call f1_put_dec
    lea  rdi, [rel str_cadmark_n]
    call f1_put_str
    mov  edi, ebp
    call f1_put_dec

    xor  ebx, ebx                       ; row within page
.row:
    cmp  ebx, ebp
    jae  .staged
    mov  eax, r12d
    imul eax, CADR_PAGE_RECORDS
    add  eax, ebx                       ; newest-relative offset
    mov  edx, r14d
    dec  edx
    sub  edx, eax
    and  edx, CADR_MAX - 1
    shl  edx, 5
    lea  rax, [rel cadence_ring]
    add  rax, rdx
    push rax                            ; fixed pointer: never baked in static data

    lea  rdi, [rel str_cadmark_tsc]
    call f1_put_str
    mov  rax, [rsp]
    mov  rdi, [rax + CADR_TSC]
    call cadr_put_hex16
    lea  rdi, [rel str_cadmark_region]
    call f1_put_str
    mov  rax, [rsp]
    movzx edi, word [rax + CADR_REGION]
    call f1_put_dec
    lea  rdi, [rel str_cadmark_event]
    call f1_put_str
    mov  rax, [rsp]
    movzx edi, byte [rax + CADR_EVENT]
    call f1_put_dec
    lea  rdi, [rel str_cadmark_rect]
    call f1_put_str
    mov  rax, [rsp]
    movzx edi, word [rax + CADR_X]
    call f1_put_dec
    lea  rdi, [rel str_cadr_comma]
    call f1_put_str
    mov  rax, [rsp]
    movzx edi, word [rax + CADR_Y]
    call f1_put_dec
    lea  rdi, [rel str_cadr_comma]
    call f1_put_str
    mov  rax, [rsp]
    movzx edi, word [rax + CADR_W]
    call f1_put_dec
    lea  rdi, [rel str_cadr_comma]
    call f1_put_str
    mov  rax, [rsp]
    movzx edi, word [rax + CADR_H]
    call f1_put_dec
    lea  rdi, [rel str_cadmark_seq]
    call f1_put_str
    mov  rax, [rsp]
    movzx edi, word [rax + CADR_SEQ]
    call f1_put_dec
    mov  rax, [rsp]
    test byte [rax + CADR_FLAGS], CADR_FLAG_CRC_VALID
    jz   .row_done
    lea  rdi, [rel str_cadmark_crc]
    call f1_put_str
    mov  rax, [rsp]
    mov  edi, [rax + CADR_CRC32]
    call cadr_put_hex8
    lea  rdi, [rel str_cadmark_flags]
    call f1_put_str
    mov  rax, [rsp]
    movzx edi, byte [rax + CADR_FLAGS]
    call f1_put_dec
    lea  rdi, [rel str_cadmark_valid]
    call f1_put_str
    mov  edi, 1
    call f1_put_dec
    lea  rdi, [rel str_cadmark_sampled]
    call f1_put_str
    mov  rax, [rsp]
    movzx edi, byte [rax + CADR_FLAGS]
    shr  edi, 1
    and  edi, 1
    call f1_put_dec
    lea  rdi, [rel str_cadmark_epoch]
    call f1_put_str
    mov  rax, [rsp]
    mov  edi, [rax + CADR_PAD]
    call f1_put_dec
.row_done:
    add  rsp, 8
    inc  ebx
    jmp  .row
.staged:
    mov  rax, [rel f1_out_cur]
    mov  byte [rax], 0
    mov  byte [rel f1_out_ready], 1
    mov  qword [r15 + RSP_CODE], CMDE_OK
    mov  qword [r15 + RSP_VAL], 0
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Fixed-width TSC formatter over F1's already-bounded full-datagram buffer.
cadr_put_hex16:
    push rbx
    push r12
    push r13
    mov  r13, rdi
    mov  rsi, [rel f1_out_cur]
    lea  rax, [rel f1_out_buf + 1455]   ; 16 chars + final NUL must fit
    cmp  rsi, rax
    ja   .out
    mov  r12d, 60
.nibble:
    mov  rax, r13
    mov  ecx, r12d
    shr  rax, cl
    and  eax, 15
    lea  rbx, [rel str_cadr_hex]
    mov  al, [rbx + rax]
    mov  [rsi], al
    inc  rsi
    sub  r12d, 4
    jns  .nibble
    mov  byte [rsi], 0
    mov  [rel f1_out_cur], rsi
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Fixed-width lowercase CRC field (eight hex digits, including leading zeroes).
cadr_put_hex8:
    push rbx
    push r12
    push r13
    mov  r13d, edi
    mov  rsi, [rel f1_out_cur]
    lea  rax, [rel f1_out_buf + 1463]
    cmp  rsi, rax
    ja   .out
    mov  r12d, 28
.nibble:
    mov  eax, r13d
    mov  ecx, r12d
    shr  eax, cl
    and  eax, 15
    lea  rbx, [rel str_cadr_hex]
    mov  al, [rbx + rax]
    mov  [rsi], al
    inc  rsi
    sub  r12d, 4
    jns  .nibble
    mov  byte [rsi], 0
    mov  [rel f1_out_cur], rsi
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---- state -----------------------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_cadence_mark_0 0
align 8
cadence_last_tsc:      dq 0
cadence_pending_ptr:   dq 0
cadence_head:          dd 0
cadence_count:         dd 0
cadence_records_total: dd 0
cadence_dropped:       dd 0
cadence_wrapped:       dd 0
cadence_seq:           dw 0
cadence_region_current: dw CADR_REGION_TASKBAR
cadence_mark_level:    db 1
cadence_armed:         db 0
cadence_batch_depth:   db 0
cadence_batch_valid:   db 0
align 4
cadence_batch_x:       dd 0
cadence_batch_y:       dd 0
cadence_batch_x2:      dd 0
cadence_batch_y2:      dd 0

; Contract 2132 CRC calibration/work state.  The 64 KiB payload scratch is the
; already-owned heap buffer fb_perf_scratch; image growth stays well below the
; contract's 8 KiB delta.
align 8
flk_analysis_tsc:      dq 0
flk_snap_cutoff:       dq 0
flk_fixture_tsc:       dq 0
flk_crc_cycles_1k:     dd 0
flk_crc_cycles_64k:    dd 0
flk_crc_cycles_per_byte: dd 0
flk_crc_cost_us_64k:   dd 0
flk_crc_calibrated:    db 0
flk_fixture_armed:     db 0
align 4
flk_cad_slot:          dd -1
times 16 db 0                  ; flk_snap_count..cadence_ring moved to WDATA_gui_cadence_mark_0_bss1: keeps the labels below at their offset mod 64

str_verb_cadmark:      db "CADMARK",0
str_verb_cadstat:      db "CADSTAT",0
str_cadstat_head:      db " cadstat=ok level=",0
str_cadstat_records:   db " records=",0
str_cadstat_dropped:   db " dropped=",0
str_cadstat_wrapped:   db " wrapped=",0
str_cadstat_crc_cost:  db " crc_cost_us_64k=",0
str_cadstat_last:      db " last_tsc=",0
str_cadmark_page:      db " CADMARK page=",0
str_cadr_slash:        db "/",0
str_cadmark_n:         db " n=",0
str_cadmark_tsc:       db " | tsc=",0
str_cadmark_region:    db " r=",0
str_cadmark_event:     db " e=",0
str_cadmark_rect:      db " rect=",0
str_cadr_comma:        db ",",0
str_cadmark_seq:       db " seq=",0
str_cadmark_crc:       db " crc=",0
str_cadmark_flags:     db " flags=",0
str_cadmark_valid:     db " crc_valid=",0
str_cadmark_sampled:   db " crc_sampled=",0
str_cadmark_epoch:     db " epoch=",0
str_cadr_hex:          db "0123456789abcdef"
str_cadence_armed:     db "[PAOS64] M6 gui: damage ring armed (512 rec, 4 writer families + cursor, tier1) [gui.damage.ring]",13,10,0
str_flk_crc_armed:     db "[PAOS64] M6 gui: flicker CRC vitals armed (crc-per-rect, cap 64K/8row, cost measured) [gui.flicker.crc]",13,10,0
str_flk_crc_fail:      db "[PAOS64] M6 gui: flicker CRC calibration FAILED or exceeds 2000us (marker withheld)",13,10,0
str_flk_cad_id:        db "flicker.crc",0
%endmacro
WDATA_DEFER WDATA_gui_cadence_mark_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_gui_cadence_mark_0_bss1 0
resb 48                 ; keeps flk_snap_count at its WDATA offset mod 64
flk_snap_count:        resd 1
flk_snap_head:         resd 1
flk_region_count:      resd 1
flk_analyzed_count:    resd 1
flk_beat_count:        resd 1
flk_stall_count:       resd 1
flk_q_j:               resd 1
flk_q_k:               resd 1
flk_q_l:               resd 1
flk_crc_cal_samples:   resd FLK_CRC_CAL_SAMPLES
flk_regions:           resb FLKR_MAX * FLKR_SIZE
flk_beat_members:      resb CADR_MAX
alignb 32
cadence_ring:          resb CADR_MAX * CADR_REC_SIZE
%endmacro
WDATA_BSS_DEFER WDATA_gui_cadence_mark_0_bss1
