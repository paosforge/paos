;; MODULE hv/warm_lifecycle
;; LAYER 5
;; EXPORTS hvw_readers_idle, hvw_idle_tick, hvw_policy, hvw_prepare, hvw_revoke, hvw_pressure, hvw_release_step, hvw_released, hvw_before_vmxoff, hvw_bound, hvw_status_verb, hvw_render_stat
;; IMPORTS hv/warm_channel, hv/vmx, hv/hv_ops, hv/vm_profile, core/memory_budget, core/time, sec/session, dev/input/ps2, svc/reserve_gate, hv/vcpu_ap_run, hv/vcpu_bsp
;; CAPS
;; OWNER saga:hv
; Expendable warm-only guest. No foreground app/driver guest may enter this
; lifecycle. WARMCHAN is exactly TIMER|CONSOLE|WARMCHAN, CLI, one vCPU.
; This component owns physical retirement, not a guest process-exit assertion.
; No model grant is sent here: the private PWR1 consumer must additionally
; validate its unloaded HELLO and current policy before publishing GRANT.
;
; All calls are serialized at stopped-vCPU/BSP service boundaries, never IRQ,
; entered without the memory-budget lock. Only the bounded allocator clear
; holds that lock internally, with no callbacks. No function yields or waits.
; Retirement clears at most 1 MiB per resident-task turn, keeping the full
; physical token reserved until the complete control/RAM/framebuffer extent is
; scrubbed. The owning task yields between turns. There is no partial credit.
;
; Intel first: only VMX with a verified INVEPT before VMXOFF can enter. AMD
; admission is closed until a complete ASID/NPT retirement path is implemented.

HVW_SCRUB_QUANTUM equ MB_WARM_ZERO_MAX
HVW_IDLE_US equ 10000000

; Normal BSP idle boundary, after input/session and boot settle observation.
; Observe BOOT eligibility even while locked: the boot gate is independent of
; local-session authority. Then sample the unlocked idle interval before any
; START can publish start_active. Neither call allocates, launches or grants.
; A bound warm guest already samples policy at its stopped-vCPU host boundary.
hvw_idle_tick:
    call reserve_gate_admit
    cmp  byte [rel hvw_bound], 0
    jne  .out
    call hvw_policy
.out:
    ret

; EAX=1 only with boot eligibility AND a fresh continuous local unlocked idle
; interval. Sticky reserve_gate_open alone never authorizes work. Session
; credentials below are trusted kernel state, never caller/guest input. A
; changed principal, key, presence count, zero/regressed clock or pressure
; restarts the interval. No command-auth/refusal state is mutated.
hvw_policy:
    push rbx
    call hvw_pressure_sample
    call time_monotonic_now_us
    mov  rbx, rax
    test rax, rax
    jz   .reset
    cmp  byte [rel hvw_under_pressure], 0
    jne  .reset
    cmp  byte [rel session_locked], SESSION_UNLOCKED
    jne  .reset
    mov  rax, [rel session_bound_pid]
    test rax, rax
    jz   .reset
    cmp  rax, [rel hvw_principal]
    jne  .reset
    mov  rax, [rel session_key_handle]
    test rax, rax
    jz   .reset
    cmp  rax, [rel hvw_session_key]
    jne  .reset
    mov  rax, [rel ps2_human_input_events]
    cmp  rax, [rel hvw_presence]
    jne  .reset
    cmp  rbx, [rel hvw_last_us]
    jb   .reset
    cmp  qword [rel hvw_quiet_us], 0
    je   .reset
    mov  [rel hvw_last_us], rbx
    sub  rbx, [rel hvw_quiet_us]
    cmp  rbx, HVW_IDLE_US
    jb   .no
    call reserve_gate_admit                ; clobbers token/serial argument registers
    pop  rbx
    ret
.reset:
    mov  [rel hvw_last_us], rbx
    mov  [rel hvw_quiet_us], rbx
    mov  rax, [rel session_bound_pid]
    mov  [rel hvw_principal], rax
    mov  rax, [rel session_key_handle]
    mov  [rel hvw_session_key], rax
    mov  rax, [rel ps2_human_input_events]
    mov  [rel hvw_presence], rax
.no:
    xor  eax, eax
    pop  rbx
    ret

; After actual allocation, before loader touches the span. Ordinary profiles
; are unchanged. Snapshot resume and external readers/DMA are never warm.
; EAX=0 admitted/no warm profile, nonzero refuses intact. Begin owns the same
; kind1 token; cache/RSS are subsets, never a second native kind3 allocation.
hvw_prepare:
    test dword [rel vm_profile_dev_mask], VP_DEV_WARMCHAN
    jz   .ordinary
    mov  eax, MB_E_STATE
    cmp  byte [rel hvw_bound], 0
    jne  .out
    lea  rax, [rel hv_ops_vmx]
    cmp  rax, [rel hv_ops_active]
    jne  .bad
    cmp  byte [rel gsn_resume_live], 0
    jne  .bad
    call hv_linux_span_pinned
    test eax, eax
    jnz  .bad
    call hvw_readers_idle
    test eax, eax
    jz   .bad
    call hvw_policy
    test eax, eax
    jz   .bad
    mov  rax, [rel hvw_serial_high]
    inc  rax
    jz   .bad
    mov  [rel hvw_serial_high], rax          ; even a refused attempt cannot reuse a serial
    mov  edi, MB_OWNER_HV_LINUX
    mov  rsi, [rel hv_linux_mb_gen]          ; actual physical generation, not START/PID
    mov  rdx, [rel hv_linux_mb_token]
    mov  rcx, rax                           ; reconstruct after BOOT gate clobbers
    call mb_guest_warm_begin
    test eax, eax
    jnz  .out
    mov  rax, [rel hv_linux_mb_gen]
    mov  [rel hvw_gen], rax
    mov  rax, [rel hv_linux_mb_token]
    mov  [rel hvw_token], rax
    mov  rax, [rel hvw_serial_high]
    mov  [rel hvw_serial], rax
    mov  qword [rel hvw_scrubbed], 0
    mov  byte [rel hvw_granted], 0
    mov  byte [rel hvw_stopped], 0
    mov  byte [rel hvw_resource_open], 1
    mov  byte [rel hvw_slat_retired], 1       ; no VMXON/guest execution yet
    mov  byte [rel hvw_bound], 1             ; publish ownership last
    call hvcw_begin
    test eax, eax
    jnz  .bad
.ordinary:
    xor  eax, eax
.out:
    ret
.bad:
    mov  eax, MB_E_STATE
    ret

; Read the real allocator only outside its lock, at this stopped-vCPU service
; boundary. Busy/unknown is pressure; repeated levels never restart quiet time.
hvw_pressure_sample:
    call mb_pressure_poll
    mov  edi, 1
    test eax, eax
    jnz  .level
    test edx, edx
    setnz dil
.level:
    cmp  dil, [rel hvw_under_pressure]
    jne  hvw_pressure
    ret

; RDI=1 pressure, 0 current producer reports pressure cleared. Native-only;
; the allocator/service producer supplies reality. Never accepts a guest bit.
; Revocation is asynchronous: no LOAD/RUN/reply or child reap is awaited.
hvw_pressure:
    test rdi, rdi
    setnz byte [rel hvw_under_pressure]
    mov  qword [rel hvw_quiet_us], 0
    jnz  hvw_revoke
    ret

; Invalidate local grant BEFORE the resource/transport fence and ask only this
; expendable guest to stop. The private bridge may send a best-effort REVOKE;
; its reply never grants physical release. Busy resource lock is retried later.
hvw_revoke:
    mov  byte [rel hvw_granted], 0
    cmp  byte [rel hvw_bound], 1
    jne  .out
    call hvcw_revoke                       ; local grant was invalidated first
    mov  byte [rel hv_linux_stop_req], 1
    cmp  byte [rel hvw_resource_open], 1
    jne  .out
    jmp  hvw_retire_key
.out:
    ret
hvw_retire_key:
    mov  edi, MB_OWNER_HV_LINUX
    mov  rsi, [rel hvw_gen]
    mov  rdx, [rel hvw_token]
    mov  rcx, [rel hvw_serial]
    jmp  mb_guest_warm_retire

; Called while still in VMX root, after dynamic readers revoke and before
; VMXOFF. Remove all top-level SLAT entries, then verify real INVEPT. A failed
; flush quarantines the physical token; neither stop nor a guest ACK repairs it.
hvw_before_vmxoff:
    ; S7: table lifetime is frozen until both vCPUs are retired.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    cmp  byte [rel hvw_bound], 1
    jne  .out
    mov  byte [rel hvw_slat_retired], 0
    mov  edi, 0x2000                       ; PML4 shared by Linux EPT/NPT builder
    mov  esi, 0x1000
    call hvw_zero_span
    test eax, eax
    jnz  .out                              ; no write/INVEPT on stale ownership
    call hv_vmx_slat_flush
    cmp  eax, 1
    jne  .out
    mov  byte [rel hvw_slat_retired], 1
.out:
    ret

; RDI offset, RSI length. Validate both cached caller keys, then join exact
; base/capacity to the live allocator record and clear while its lock is held.
; Descriptor lives on the trusted native stack; no pointer escapes the call.
hvw_zero_span:
    ; Includes whole-control scrubs; never alter frozen S7 tables.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    sub  rsp, 40
    mov  [rsp + 16], rdi
    mov  [rsp + 24], rsi
    mov  eax, MB_E_STALE
    mov  rdx, [rel hvw_token]
    test rdx, rdx
    jz   .out
    cmp  rdx, [rel hv_linux_mb_token]
    jne  .out
    mov  rsi, [rel hvw_gen]
    test rsi, rsi
    jz   .out
    cmp  rsi, [rel hv_linux_mb_gen]
    jne  .out
    mov  rax, [rel hv_linux_region]
    mov  [rsp], rax
    mov  rax, [rel hv_linux_region_capacity]
    mov  [rsp + 8], rax
    mov  edi, MB_OWNER_HV_LINUX
    mov  rcx, [rel hvw_serial]
    mov  r8, rsp
    call mb_guest_warm_zero
.out:
    add  rsp, 40
    ret

; Shared ordinary/warm release census: EAX=1 only with every native reader
; detached. Device DMA pins are checked
; independently by hv_linux_span_pinned. Called before any scrub and every turn.
hvw_readers_idle:
    xor  eax, eax
    cmp  byte [rel cdp_bound], 0
    jne  .out
    cmp  byte [rel gws_bound], 0
    jne  .out
    cmp  byte [rel padc_bound], 0
    jne  .out
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .out
%endif
%endif
    mov  eax, 1
.out:
    ret

; Warm branch of hv_linux_release_mem. A bound token is never passed through
; the ordinary release path. Retain every key/address on refusal. Each call
; writes at most one owned quantum; no callbacks or scheduling within a scrub.
hvw_release_step:
    mov  byte [rel hvw_granted], 0
    mov  eax, MB_E_STALE
    mov  rdx, [rel hvw_token]
    test rdx, rdx
    jz   .out
    cmp  rdx, [rel hv_linux_mb_token]
    jne  .out
    mov  rsi, [rel hvw_gen]
    cmp  rsi, [rel hv_linux_mb_gen]
    jne  .out
    mov  eax, MB_E_BUSY
    cmp  byte [rel hvw_stopped], 1
    jne  .out
    cmp  byte [rel hv_linux_running], 0
    jne  .out
    cmp  byte [rel hv_linux_vmx_live], 0
    jne  .out
    cmp  qword [rel hv_svm_cur_vmcb], 0
    jne  .out
    cmp  byte [rel hv_linux_run_req], 0
    jne  .out
    cmp  byte [rel hv_guest_power_fenced], 0
    jne  .out
    cmp  byte [rel hv_linux_release_deferred], 0
    jne  .out
    cmp  byte [rel hvw_slat_retired], 1
    jne  .out
    call hv_linux_span_pinned
    test eax, eax
    jnz  .busy
    call hvw_readers_idle
    test eax, eax
    jz   .busy
    cmp  byte [rel hvw_resource_open], 1
    jne  .scrub
    call hvw_retire_key                    ; cache late replies fenced before writes
    test eax, eax
    jnz  .out
.scrub:
    mov  rcx, [rel hv_linux_region_capacity]
    test rcx, rcx
    jz   .busy
    mov  rdi, [rel hv_linux_region]
    test rdi, rdi
    jz   .busy
    mov  rax, rdi
    add  rax, rcx
    jc   .busy
    mov  rdx, [rel hvw_scrubbed]
    cmp  rdx, rcx
    ja   .busy
    je   .end
    ; Retire native descriptor caches before the first byte is scrubbed.
    test rdx, rdx
    jnz  .chunk
    call hv_vcon_state_zero
    call guestnet_state_zero
    mov  qword [rel hv_linux_eptp], 0
    mov  rcx, [rel hv_linux_region_capacity]
    mov  rdi, [rel hv_linux_region]
    xor  edx, edx
.chunk:
    sub  rcx, rdx
    cmp  rcx, HVW_SCRUB_QUANTUM
    jbe  .extent
    mov  ecx, HVW_SCRUB_QUANTUM
.extent:
    push rcx
    mov  rdi, rdx
    mov  rsi, rcx
    call hvw_zero_span                    ; complete control + RAM + framebuffer
    pop  rcx
    test eax, eax
    jnz  .out
    add  [rel hvw_scrubbed], rcx            ; publish only after the real write
    mov  rax, [rel hvw_scrubbed]
    cmp  rax, [rel hv_linux_region_capacity]
    jne  .busy
.end:
    mov  rdi, [rel hvw_scrubbed]
    xor  esi, esi
    call hvw_zero_span                    ; exact full extent, also on release retry
    test eax, eax
    jnz  .out
    cmp  byte [rel hvw_resource_open], 1
    jne  .release
    mov  edi, MB_OWNER_HV_LINUX
    mov  rsi, [rel hvw_gen]
    mov  rdx, [rel hvw_token]
    mov  rcx, [rel hvw_serial]
    call mb_guest_warm_end                 ; actual stop + unmap + complete scrub only
    test eax, eax
    jnz  .out
    mov  byte [rel hvw_resource_open], 0    ; retry release without double End
.release:
    mov  edi, MB_OWNER_HV_LINUX
    mov  rsi, [rel hvw_gen]
    mov  rdx, [rel hvw_token]
    call mb_release
    test eax, eax
    jnz  .out
    ; Publish a retained receipt only after successful real allocator release.
    ; Capacity/key still name the just-scrubbed span; no new allocation can
    ; enter while bound is set. Serial publishes the completed observation last.
    mov  rax, [rel hvw_gen]
    mov  [rel hvw_last_release_gen], rax
    mov  rax, [rel hv_linux_region_capacity]
    mov  [rel hvw_last_release_bytes], rax
    mov  eax, [rel hvcw_start]
    mov  [rel hvw_last_release_start], eax
    mov  rax, [rel hvw_serial]
    mov  [rel hvw_last_release_serial], rax
    mov  qword [rel hv_linux_region_resident], 0
    mov  qword [rel hv_linux_region], 0
    mov  qword [rel hv_linux_region_capacity], 0
    mov  qword [rel hv_linux_ram], 0
    mov  qword [rel hv_linux_mb_token], 0
    mov  qword [rel hv_linux_mb_gen], 0
    jmp  hvw_released
.busy:
    mov  eax, MB_E_BUSY
.out:
    ret
hvw_released:
    call hvcw_retired
    mov  qword [rel hvw_gen], 0
    mov  qword [rel hvw_token], 0
    mov  qword [rel hvw_serial], 0
    mov  qword [rel hvw_scrubbed], 0
    mov  byte [rel hvw_bound], 0            ; new allocation/START admitted only now
    xor  eax, eax
    ret

; Owner-gated by the existing GUESTVM dispatcher authorization. Cooperative BSP
; observation only: no policy call, pump, scheduler yield, MMIO, or VMCS read.
; Reject extra arguments; reading cannot launch, grant, revoke or release.
hvw_status_verb:
    call hv_skip_spaces
    cmp  byte [rax], 0
    je   hvw_render_stat
    call hv_out_reset
    lea  rdi, [rel str_hvw_status_args]
    jmp  hv_out_str

; Separate bounded 1024-byte reply; maximum-width unsigned values fit whole.
; Receipts are historical observations, never authority or current liveness.
hvw_render_stat:
    call hv_out_reset
    lea  rdi, [rel str_hvw_status_head]
    call hv_out_str
    lea  rdi, [rel str_hvw_status_start]
    call hv_out_str
    mov  eax, [rel hv_linux_start_gen]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_consumed]
    call hv_out_str
    mov  eax, [rel hv_linux_start_consumed]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_bound]
    call hv_out_str
    movzx eax, byte [rel hvw_bound]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_phase]
    call hv_out_str
    movzx eax, byte [rel hvcw_phase]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_granted]
    call hv_out_str
    movzx eax, byte [rel hvw_granted]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_stopped]
    call hv_out_str
    movzx eax, byte [rel hvw_stopped]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_slat_retired]
    call hv_out_str
    movzx eax, byte [rel hvw_slat_retired]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_resource_open]
    call hv_out_str
    movzx eax, byte [rel hvw_resource_open]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_pressure]
    call hv_out_str
    movzx eax, byte [rel hvw_under_pressure]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_running]
    call hv_out_str
    movzx eax, byte [rel hv_linux_running]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_vmx_live]
    call hv_out_str
    movzx eax, byte [rel hv_linux_vmx_live]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_queued]
    call hv_out_str
    movzx eax, byte [rel hv_linux_run_req]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_starting]
    call hv_out_str
    movzx eax, byte [rel hv_linux_start_active]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_load_err]
    call hv_out_str
    movzx eax, byte [rel hv_linux_load_err]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_live_bytes]
    call hv_out_str
    mov  rax, [rel hv_linux_region_capacity]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_scrubbed]
    call hv_out_str
    mov  rax, [rel hvw_scrubbed]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_load_start]
    call hv_out_str
    mov  eax, [rel hvcw_last_load_start]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_load_gen]
    call hv_out_str
    mov  rax, [rel hvcw_last_load_gen]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_load_serial]
    call hv_out_str
    mov  rax, [rel hvcw_last_load_serial]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_load_pid]
    call hv_out_str
    mov  rax, [rel hvcw_last_load_pid]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_release_start]
    call hv_out_str
    mov  eax, [rel hvw_last_release_start]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_release_gen]
    call hv_out_str
    mov  rax, [rel hvw_last_release_gen]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_release_serial]
    call hv_out_str
    mov  rax, [rel hvw_last_release_serial]
    call hvw_out_u64
    lea  rdi, [rel str_hvw_status_release_bytes]
    call hv_out_str
    mov  rax, [rel hvw_last_release_bytes]
    call hvw_out_u64
    ret

; Unlike hv_out_dec's u32 ABI, physical generations/bytes/PIDs are u64.
; A stack-local decimal buffer avoids truncated receipts and persistent text.
hvw_out_u64:
    push rbx
    sub  rsp, 32
    lea  rcx, [rsp + 23]
    mov  byte [rcx], 0
    mov  ebx, 10
.loop:
    xor  edx, edx
    div  rbx
    add  dl, '0'
    dec  rcx
    mov  [rcx], dl
    test rax, rax
    jnz  .loop
    mov  rdi, rcx
    call hv_out_str
    add  rsp, 32
    pop  rbx
    ret

str_hvw_status_head: db " GUESTVM WARMSTAT rev=1", 0
str_hvw_status_args: db " GUESTVM WARMSTAT error=args", 0
str_hvw_status_start: db " start=", 0
str_hvw_status_consumed: db " consumed=", 0
str_hvw_status_bound: db " bound=", 0
str_hvw_status_phase: db " phase=", 0
str_hvw_status_granted: db " granted=", 0
str_hvw_status_stopped: db " stopped=", 0
str_hvw_status_slat_retired: db " slat_retired=", 0
str_hvw_status_resource_open: db " resource_open=", 0
str_hvw_status_pressure: db " pressure=", 0
str_hvw_status_running: db " running=", 0
str_hvw_status_vmx_live: db " vmx_live=", 0
str_hvw_status_queued: db " queued=", 0
str_hvw_status_starting: db " starting=", 0
str_hvw_status_load_err: db " load_err=", 0
str_hvw_status_live_bytes: db " live_bytes=", 0
str_hvw_status_scrubbed: db " scrubbed=", 0
str_hvw_status_load_start: db " load_start=", 0
str_hvw_status_load_gen: db " load_gen=", 0
str_hvw_status_load_serial: db " load_serial=", 0
str_hvw_status_load_pid: db " load_pid=", 0
str_hvw_status_release_start: db " release_start=", 0
str_hvw_status_release_gen: db " release_gen=", 0
str_hvw_status_release_serial: db " release_serial=", 0
str_hvw_status_release_bytes: db " release_bytes=", 0

%include "core/abi/wdata.inc"
%macro WDATA_hv_warm_lifecycle 0
alignb 8
hvw_serial_high: resq 1
hvw_serial: resq 1
hvw_gen: resq 1
hvw_token: resq 1
hvw_scrubbed: resq 1
hvw_presence: resq 1
hvw_principal: resq 1
hvw_session_key: resq 1
hvw_quiet_us: resq 1
hvw_last_us: resq 1
hvw_last_release_gen: resq 1
hvw_last_release_serial: resq 1
hvw_last_release_bytes: resq 1
hvw_last_release_start: resd 1
hvw_bound: resb 1
hvw_stopped: resb 1
hvw_granted: resb 1
hvw_resource_open: resb 1
hvw_slat_retired: resb 1
hvw_under_pressure: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_warm_lifecycle
