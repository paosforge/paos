;; MODULE snd/core
;; LAYER 4
;; EXPORTS snd_census_snapshot, snd_init, snd_register, snd_deregister, snd_select, snd_selftest
;; IMPORTS dev/snd/hda_backend, boot/serial, core/lock, dev/snd/nullsnd
;; CAPS
;; OWNER saga:audio
;; LOCK: snd_registry_lock PROTECTS snd_registry_head
; ============================================================================
; snd/core.asm — the sounddev CLASS CORE (DRIVER_MODEL §5): the registry, the
; selection rule, and the ABI-v2 stream contract that chip backends port
; against. Mirrors fs/blockdev.asm: one intrusive prio-DESC registry, one
; selection rule (highest-prio HEALTH_OK backend, or none), one runtime-built
; vtable discipline. Backends register UPWARD via snd_register (the sanctioned
; L3->L4 edge); the core dispatches through .ops. There is exactly ONE core,
; ONE selection rule, ONE registry — no second snd variant (Task3201).
;
; The nullsnd fake backend is BOTH the QEMU-no-hardware regression target and
; the reference vtable implementation; snd_selftest drives it through the full
; ABI-v2 lifecycle and emits the content KAT the probe grades.
; ============================================================================

SND_REGISTRY_LIMIT   equ 16

snd_registry_lock_acquire:
    lea  rdi, [rel snd_registry_lock]
    jmp  spin_acquire

snd_registry_lock_release:
    lea  rdi, [rel snd_registry_lock]
    jmp  spin_release

; snd_init — reset the registry (idempotent).
snd_init:
    call snd_registry_lock_acquire
    mov  qword [rel snd_registry_head], 0
    call snd_registry_lock_release
    ret

; snd_register(RDI=dev) -> RAX REG_OK/REG_REJECT. Validates the uniform header
; (ops/info non-null, class == CLASS_SOUND) BEFORE locking, then does an
; bounded whole-list capacity/duplicate check, then intrusive prio-DESC insert.
snd_register:
    push rbx
    push r12
    mov  r12, rdi
    mov  rax, [r12 + dev.ops]
    test rax, rax
    jz   .reject
    mov  rax, [r12 + dev.info]
    test rax, rax
    jz   .reject
    cmp  dword [r12 + dev.class], CLASS_SOUND
    jne  .reject
    call snd_registry_lock_acquire
    ; Admission must inspect the whole list before choosing an insertion
    ; point. A high-priority candidate can otherwise skip both the capacity
    ; bound and an existing copy of its handle farther down the list.
    mov  rax, [rel snd_registry_head]
    xor  ecx, ecx
.admission_walk:
    test rax, rax
    jz   .admission_end
    cmp  ecx, SND_REGISTRY_LIMIT
    jae  .reject_locked
    cmp  rax, r12
    je   .reject_locked
    inc  ecx
    mov  rax, [rax + dev.next]
    jmp  .admission_walk
.admission_end:
    cmp  ecx, SND_REGISTRY_LIMIT
    jae  .reject_locked
    lea  rsi, [rel snd_registry_head]   ; rsi = &prev->next (starts at head slot)
    mov  ebx, [r12 + dev.prio]          ; my prio
    xor  ecx, ecx                       ; bounded walk counter
.walk:
    mov  rax, [rsi]
    test rax, rax
    jz   .insert
    cmp  rax, r12
    je   .reject_locked                 ; same handle registered twice
    cmp  ecx, SND_REGISTRY_LIMIT
    jae  .reject_locked
    mov  edx, [rax + dev.prio]
    cmp  edx, ebx
    jl   .insert                        ; insert before first strictly-lower prio -> DESC
    lea  rsi, [rax + dev.next]
    inc  ecx
    jmp  .walk
.insert:
    mov  rax, [rsi]                     ; successor
    mov  [r12 + dev.next], rax
    mov  [rsi], r12
    call snd_registry_lock_release
    xor  eax, eax                       ; REG_OK
    pop  r12
    pop  rbx
    ret
.reject_locked:
    call snd_registry_lock_release
.reject:
    mov  eax, REG_REJECT
    pop  r12
    pop  rbx
    ret

; snd_deregister(RDI=dev) -> RAX 0/-1. Bounded find-and-unlink; zeroes dev.next.
snd_deregister:
    push r12
    mov  r12, rdi
    call snd_registry_lock_acquire
    lea  rsi, [rel snd_registry_head]
    xor  ecx, ecx
.walk:
    mov  rax, [rsi]
    test rax, rax
    jz   .miss
    cmp  ecx, SND_REGISTRY_LIMIT
    jae  .miss
    cmp  rax, r12
    je   .unlink
    lea  rsi, [rax + dev.next]
    inc  ecx
    jmp  .walk
.unlink:
    mov  rax, [r12 + dev.next]
    mov  [rsi], rax
    mov  qword [r12 + dev.next], 0
    call snd_registry_lock_release
    xor  eax, eax
    pop  r12
    ret
.miss:
    call snd_registry_lock_release
    mov  eax, -1
    pop  r12
    ret

; snd_select() -> RAX = highest-prio HEALTH_OK backend, or 0. The list is
; prio-DESC, so the first healthy node is the selection.
snd_select:
    mov  rax, [rel snd_registry_head]
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

; snd_kat_zero_params — clear the KAT stream-params scratch before each open.
snd_kat_zero_params:
    lea  rdi, [rel snd_kat_params]
    mov  ecx, snd_stream_params_size
.z:
    test ecx, ecx
    jz   .d
    mov  byte [rdi], 0
    inc  rdi
    dec  ecx
    jmp  .z
.d:
    ret

; snd_selftest — ABI-v2 content KAT over the nullsnd reference backend. Registers
; nullsnd (PRIO_DOMAIN) + a lower-prio fixture, proves prio-DESC selection, the
; unsupported-format reject, a timestamped interactive stereo playback stream
; (opaque nonzero handle), exact frame accounting, status/xrun/state, volume,
; stale-handle rejection, recover, reopen-resets-position, and dead-select=none.
; Every SNDKAT line and the final marker are emitted only after the real op
; return is asserted, so a marker cannot appear without the behaviour.
snd_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15

    call snd_init
    call nullsnd_create
    cmp  eax, REG_OK
    jne  .done
    call nullsnd_create_fixture
    cmp  eax, REG_OK
    jne  .done

    ; --- selection: must return the prio-10 primary, not the prio-5 fixture --
    call snd_select
    test rax, rax
    jz   .done
    lea  rcx, [rel nullsnd_dev]
    cmp  rax, rcx
    jne  .done
    mov  rbx, rax                       ; rbx = selected dev (nullsnd)
    lea  rdi, [rel snd_kat_l2]
    call serial_string
    lea  rdi, [rel snd_kat_l3]
    call serial_string

    ; --- unsupported format -> open() returns -1 --------------------------
    call snd_kat_zero_params
    mov  dword [rel snd_kat_params + snd_stream_params.format], SNDFMT_S24LE
    mov  dword [rel snd_kat_params + snd_stream_params.channels], 2
    mov  rdi, rbx
    mov  rax, [rbx + dev.ops]
    lea  rsi, [rel snd_kat_params]
    lea  rdx, [rel snd_kat_handle]
    call [rax + snd_ops.open]
    test rax, rax
    jns  .done                          ; must be negative
    lea  rdi, [rel snd_kat_l4]
    call serial_string

    ; --- open a valid interactive stereo playback stream ------------------
    call snd_kat_zero_params
    mov  dword [rel snd_kat_params + snd_stream_params.rate], 48000
    mov  dword [rel snd_kat_params + snd_stream_params.format], SNDFMT_S16LE
    mov  dword [rel snd_kat_params + snd_stream_params.channels], 2
    mov  dword [rel snd_kat_params + snd_stream_params.direction], SND_DIR_PLAY
    mov  dword [rel snd_kat_params + snd_stream_params.latency_class], SND_LATENCY_INTERACTIVE
    mov  dword [rel snd_kat_params + snd_stream_params.timestamp_base], SND_TSBASE_TSC
    mov  qword [rel snd_kat_params + snd_stream_params.session_group], 21301
    mov  qword [rel snd_kat_handle], 0
    mov  rdi, rbx
    mov  rax, [rbx + dev.ops]
    lea  rsi, [rel snd_kat_params]
    lea  rdx, [rel snd_kat_handle]
    call [rax + snd_ops.open]
    test rax, rax
    jnz  .done                          ; open must succeed (0)
    mov  r13, [rel snd_kat_handle]
    test r13, r13
    jz   .done                          ; handle must be nonzero

    lea  rdi, [rel snd_kat_l1a]
    call serial_string
    mov  rdi, r13
    call serial_decimal
    lea  rdi, [rel snd_kat_nl]
    call serial_string

    lea  rdi, [rel snd_kat_l5a]
    call serial_string
    mov  edi, 48000
    call serial_decimal
    lea  rdi, [rel snd_kat_l5b]
    call serial_string
    mov  rdi, [rel snd_kat_params + snd_stream_params.session_group]
    call serial_decimal
    lea  rdi, [rel snd_kat_nl]
    call serial_string

    ; --- submit 4096 bytes -> accepts all; position -> frames -------------
    mov  rdi, rbx
    mov  rax, [rbx + dev.ops]
    mov  rsi, r13
    lea  rdx, [rel snd_kat_pcm]
    mov  rcx, 4096
    call [rax + snd_ops.submit]
    cmp  rax, 4096
    jne  .done
    mov  r14, rax                       ; bytes accepted

    mov  rdi, rbx
    mov  rax, [rbx + dev.ops]
    mov  rsi, r13
    call [rax + snd_ops.position]
    test rax, rax
    js   .done
    mov  r15, rax                       ; frames

    ; assert frames * 4 == bytes (frame_bytes truly 4 for S16LE stereo)
    mov  rax, r15
    shl  rax, 2
    cmp  rax, r14
    jne  .done

    lea  rdi, [rel snd_kat_l6a]
    call serial_string
    mov  rdi, r14
    call serial_decimal
    lea  rdi, [rel snd_kat_l6b]
    call serial_string
    mov  edi, 4                         ; frame_bytes (proven above)
    call serial_decimal
    lea  rdi, [rel snd_kat_l6c]
    call serial_string
    mov  rdi, r15
    call serial_decimal
    lea  rdi, [rel snd_kat_nl]
    call serial_string

    ; --- status: timestamp_frames == frames, xruns=0, state=running -------
    mov  rdi, rbx
    mov  rax, [rbx + dev.ops]
    mov  rsi, r13
    lea  rdx, [rel snd_kat_status]
    call [rax + snd_ops.status]
    test rax, rax
    jnz  .done
    cmp  dword [rel snd_kat_status + snd_status.state], SND_STATE_RUNNING
    jne  .done
    cmp  dword [rel snd_kat_status + snd_status.xruns], 0
    jne  .done
    mov  rax, [rel snd_kat_status + snd_status.timestamp]
    cmp  rax, r15
    jne  .done
    lea  rdi, [rel snd_kat_l7a]
    call serial_string
    mov  rdi, [rel snd_kat_status + snd_status.timestamp]
    call serial_decimal
    lea  rdi, [rel snd_kat_l7b]
    call serial_string

    ; --- set_volume=0, stale_handle=-1, recover=0, reopen_position=0 ------
    mov  rdi, rbx
    mov  rax, [rbx + dev.ops]
    mov  rsi, r13
    mov  rdx, 0x4000
    call [rax + snd_ops.set_volume]
    test rax, rax
    jnz  .done

    mov  rdi, rbx
    mov  rax, [rbx + dev.ops]
    mov  rsi, r13
    call [rax + snd_ops.close]
    test rax, rax
    jnz  .done

    ; submit on the now-closed handle -> -1 (stale rejection)
    mov  rdi, rbx
    mov  rax, [rbx + dev.ops]
    mov  rsi, r13
    lea  rdx, [rel snd_kat_pcm]
    mov  rcx, 64
    call [rax + snd_ops.submit]
    cmp  rax, -1
    jne  .done

    mov  rdi, rbx
    mov  rax, [rbx + dev.ops]
    call [rax + snd_ops.recover]
    test rax, rax
    jnz  .done

    ; reopen -> fresh handle, position resets to 0
    call snd_kat_zero_params
    mov  dword [rel snd_kat_params + snd_stream_params.rate], 48000
    mov  dword [rel snd_kat_params + snd_stream_params.format], SNDFMT_S16LE
    mov  dword [rel snd_kat_params + snd_stream_params.channels], 2
    mov  dword [rel snd_kat_params + snd_stream_params.direction], SND_DIR_PLAY
    mov  dword [rel snd_kat_params + snd_stream_params.latency_class], SND_LATENCY_INTERACTIVE
    mov  dword [rel snd_kat_params + snd_stream_params.timestamp_base], SND_TSBASE_TSC
    mov  qword [rel snd_kat_params + snd_stream_params.session_group], 21301
    mov  qword [rel snd_kat_handle], 0
    mov  rdi, rbx
    mov  rax, [rbx + dev.ops]
    lea  rsi, [rel snd_kat_params]
    lea  rdx, [rel snd_kat_handle]
    call [rax + snd_ops.open]
    test rax, rax
    jnz  .done
    mov  r13, [rel snd_kat_handle]
    mov  rdi, rbx
    mov  rax, [rbx + dev.ops]
    mov  rsi, r13
    call [rax + snd_ops.position]
    test rax, rax
    jnz  .done                          ; reopened position must be exactly 0
    lea  rdi, [rel snd_kat_l8]
    call serial_string

    ; --- force every registered node HEALTH_DEAD -> select() returns none -
    mov  rax, [rel snd_registry_head]
.deadloop:
    test rax, rax
    jz   .deaddone
    mov  dword [rax + dev.health], HEALTH_DEAD
    mov  rax, [rax + dev.next]
    jmp  .deadloop
.deaddone:
    call snd_select
    test rax, rax
    jnz  .done                          ; must be none
    lea  rdi, [rel snd_kat_l9]
    call serial_string

    ; --- this KAT exercises nullsnd; it does not inventory audio devices -----
    lea  rdi, [rel snd_kat_scope]
    call serial_string
    lea  rdi, [rel str_snd_kat_pass]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; C3 RSI=trusted16B out: selected id(0none/1fake/2HDA/3unknown),
; member count, flags(1invalid-list/2busy/4missing-identity), actual PCI ID.
; Bounded, nonblocking and memory-only. No backend ops/admission callbacks.
snd_census_snapshot:
 push rbx
 push r12
 push r13
 mov r12,rsi
 mov qword [r12],0
 mov qword [r12+8],0
 lea rdi,[rel snd_registry_lock]
 call spin_try_acquire
 test eax,eax
 jz .busy
 xor r13d,r13d
 mov rbx,[rel snd_registry_head]
.walk:
 test rbx,rbx
 jz .selected
 cmp dword [r12+4],SND_REGISTRY_LIMIT
 jae .bad_list
 inc dword [r12+4]
 test r13,r13
 jnz .next
 cmp dword [rbx+dev.health],HEALTH_OK
 jne .next
 mov r13,rbx
.next:
 mov rbx,[rbx+dev.next]
 jmp .walk
.bad_list:
 or dword [r12+8],1
.selected:
 test r13,r13
 jz .unlock
 mov dword [r12],1
 lea rax,[rel nullsnd_dev]
 cmp r13,rax
 je .unlock
 lea rax,[rel nullsnd_fx_dev]
 cmp r13,rax
 je .unlock
 mov dword [r12],3
 mov rdi,r13
 call hda_backend_census_identity
 test edx,edx
 jz .unlock
 mov dword [r12],2
 mov [r12+12],eax
 test eax,eax
 jnz .unlock
 or dword [r12+8],4
.unlock:
 call snd_registry_lock_release
 jmp .done
.busy:
 or dword [r12+8],2
.done:
 pop r13
 pop r12
 pop rbx
 ret

; --- snd/core state (in-image writable) --------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_snd_core_0 0
align 8
times 16 db 0                  ; snd_registry_lock..snd_kat_pcm moved to WDATA_snd_core_0_bss1: keeps the labels below at their offset mod 64

snd_kat_l1a:     db "SNDKAT token=snd1 abi=2 handle=", 0
snd_kat_l2:      db "SNDKAT token=snd1 vtable=runtime prio_order=desc", 13, 10, 0
snd_kat_l3:      db "SNDKAT token=snd1 selected=nullsnd health=HEALTH_OK", 13, 10, 0
snd_kat_l4:      db "SNDKAT token=snd1 unsupported_format=-1", 13, 10, 0
snd_kat_l5a:     db "SNDKAT token=snd1 rate=", 0
snd_kat_l5b:     db " format=s16le channels=2 direction=playback timestamp_base=tsc latency_class=interactive session_group=", 0
snd_kat_l6a:     db "SNDKAT token=snd1 bytes=", 0
snd_kat_l6b:     db " frame_bytes=", 0
snd_kat_l6c:     db " position_frames=", 0
snd_kat_l7a:     db "SNDKAT token=snd1 timestamp_frames=", 0
snd_kat_l7b:     db " xruns=0 state=running", 13, 10, 0
snd_kat_l8:      db "SNDKAT token=snd1 set_volume=0 stale_handle=-1 recover=0 reopen_position=0", 13, 10, 0
snd_kat_l9:      db "SNDKAT token=snd1 sole_dead_select=none", 13, 10, 0
snd_kat_scope: db "SNDKAT fixture_scope=core_nullsnd device_inventory=not_probed", 13, 10, 0
snd_kat_nl:      db 13, 10, 0
str_snd_kat_pass: db "[PAOS64] snd: core/nullsnd ABI v2 accounting/recovery KAT PASS [snd.core.nullsnd.kat]", 13, 10, 0
%endmacro
WDATA_DEFER WDATA_snd_core_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_snd_core_0_bss1 0
alignb 8
snd_registry_lock:  resb 1
alignb 8
snd_registry_head:  resq 1
snd_kat_params:     resb snd_stream_params_size
snd_kat_status:     resb snd_status_size
snd_kat_handle:     resq 1
snd_kat_pcm:        resb 4096
%endmacro
WDATA_BSS_DEFER WDATA_snd_core_0_bss1
