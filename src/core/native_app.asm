;; MODULE core/native_app
;; LAYER 1
;; EXPORTS native_app_register, native_app_register_with_lease, native_app_dispatch, native_app_restart, native_app_unregister, native_app_query
;; IMPORTS boot/pmod_loader, core/smp, core/time
;; CAPS
;; OWNER saga:core
;
; Restartable native module ABI, BSP desktop-dispatch context ONLY (IF=1,
; outside IRQ). Not an arbitrary kernel callback killer. An entry may touch its
; arena and compute, but must not mask interrupts, call host services, retain
; authority or hold shared locks. The WM commits successful results and keeps
; window/document restore metadata outside the arena. Core faults remain core
; faults; this ring-0 fence is honest-mistake containment, not a security domain.
;
; Module entry: RDI=owned zero-initialized 4096-byte arena, RSI=4096. No caps.
; Non-returning entry is cut off at an absolute registration-time deadline (+delivery and
; <=one calibrated periodic tick). STUCK never re-enters without explicit restart.
; Handles are (slot,generation); a slot is not itself authority. Trusted WM must
; check the current session before accepting a restart request from a user.
%define NATIVE_APP_WATCHDOG_API 1
NAPP_MAX equ 8
NAPP_ARENA_SIZE equ 4096
NAPP_REC_SIZE equ 64
NAPP_ENTRY equ 0
NAPP_GEN equ 8
NAPP_STATE equ 16
NAPP_ELAPSED equ 24
NAPP_LEASE equ 32
NAPP_CAUSE equ 40
NAPP_DEFAULT_MS equ 20
NAPP_MAX_MS equ 100
NAPP_FREE equ 0
NAPP_READY equ 1
NAPP_STUCK equ 2
NAPP_RUNNING equ 3

; Gate preserves ABI inputs. No AP or IRQ may borrow BSP/global PMOD state.
native_app_gate:
    pushfq
    pop  rax
    test eax, 1 << 9
    jz   .busy
    push rdi
    push rsi
    push rdx
    call smp_current_logical
    pop  rdx
    pop  rsi
    pop  rdi
    test eax, eax
    jnz  .busy
    cmp  byte [rel cpu_irq_depth], 0
    jne  .busy
    cmp  byte [rel native_app_busy], 0
    jne  .busy
    cmp  byte [rel pmod_call_active], 0
    jne  .busy
    xor  eax, eax
    ret
.busy:
    mov  rax, -3
    ret

; register(RDI=immutable trusted entry) -> RAX=slot, RDX=generation, or -1/-3.
; Fixed owned arenas avoid caller aliasing and cross-app reset of shared data.
native_app_register:
    mov  esi, NAPP_DEFAULT_MS
    jmp  native_app_register_with_lease

; Trusted registration only: RSI=lease milliseconds, 1..100. No runtime setter.
native_app_register_with_lease:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
    call native_app_gate
    test rax, rax
    jnz  .out
    test rbx, rbx
    jz   .bad
    test r12, r12
    jz   .bad
    cmp  r12, NAPP_MAX_MS
    ja   .bad
    xor  eax, eax
    lea  r8, [rel native_app_records]
.find:
    cmp  qword [r8 + NAPP_STATE], NAPP_FREE
    jne  .next
    mov  rdx, [r8 + NAPP_GEN]
    inc  rdx
    jz   .next                         ; never wrap an old handle back to life
    mov  [r8 + NAPP_GEN], rdx
    mov  [r8 + NAPP_ENTRY], rbx
    mov  qword [r8 + NAPP_ELAPSED], 0
    mov  [r8 + NAPP_LEASE], r12
    mov  qword [r8 + NAPP_CAUSE], 0
    mov  qword [r8 + NAPP_STATE], NAPP_READY
    ; Free arenas are cleared on unregister; static initial arenas are zero.
    jmp  .out
.next:
    add  r8, NAPP_REC_SIZE
    inc  eax
    cmp  eax, NAPP_MAX
    jb   .find
.bad:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; resolve(EDI=slot, RSI=generation) -> R8=record or RAX=-1 invalid/-2 stale.
native_app_resolve:
    cmp  edi, NAPP_MAX
    jae  .bad
    mov  eax, edi
    shl  eax, 6
    lea  r8, [rel native_app_records]
    add  r8, rax
    cmp  qword [r8 + NAPP_STATE], NAPP_FREE
    je   .bad
    cmp  rsi, [r8 + NAPP_GEN]
    jne  .stale
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret
.stale:
    mov  rax, -2
    ret

; dispatch(EDI=slot, RSI=generation) -> 0 completed, 1 STUCK, -1 invalid,
; -2 stale, -3 busy/context, -4 unavailable. Query exposes elapsed TSC cycles.
native_app_dispatch:
    push rbx
    push r12
    push r13
    call native_app_gate
    test rax, rax
    jnz  .out
    call native_app_resolve
    test rax, rax
    jnz  .out
    mov  r12, r8
    mov  eax, 1
    cmp  qword [r12 + NAPP_STATE], NAPP_STUCK
    je   .out
    ; Periodic fallback is bounded by the measured BSP reload, never the
    ; startup's nominal count. Deadline-capable CPUs do not need that fallback.
    cmp  byte [rel pmod_watchdog_deadline_mode], 1
    je   .lease_ready
    cmp  byte [rel smp_bsp_tick_calibrated], 1
    jne  .unavailable
.lease_ready:
    mov  byte [rel native_app_busy], 1
    mov  qword [r12 + NAPP_STATE], NAPP_RUNNING
    mov  eax, edi
    shl  eax, 12
    lea  rsi, [rel native_app_arenas]
    add  rsi, rax
    mov  rdi, [r12 + NAPP_ENTRY]
    mov  edx, NAPP_ARENA_SIZE
    xor  ecx, ecx                      ; app entry receives no capabilities
    fxsave64 [rel native_app_host_fx]
    ; Snapshot outside the borrowed timer/CR3 boundary; measurements include
    ; arm/cleanup cost, and are never illustrative CPU or memory figures.
    mov  r13, rdi
    mov  rbx, rsi
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel native_app_start], rax
    mov  rdi, r13
    mov  rsi, rbx
    mov  edx, NAPP_ARENA_SIZE
    mov  r8, [r12 + NAPP_LEASE]          ; immutable for this registration
    call pmod_sandbox_call_native_budget
    mov  rbx, rax
    fxrstor64 [rel native_app_host_fx]
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel native_app_start]
    mov  [r12 + NAPP_ELAPSED], rax
    mov  byte [rel native_app_busy], 0
    mov  qword [r12 + NAPP_STATE], NAPP_READY
    mov  qword [r12 + NAPP_CAUSE], 0
    test rbx, rbx
    jz   .ok
    cmp  rbx, -3
    je   .unavailable
    mov  [r12 + NAPP_CAUSE], rbx         ; -1 recovered fault / -2 timeout
    mov  qword [r12 + NAPP_STATE], NAPP_STUCK
    mov  eax, 1
    jmp  .out
.unavailable:
    mov  rax, -4
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; restart(EDI=slot, RSI=current generation) -> RAX=0, RDX=new generation.
; No module cleanup callback is called: it too could hang. Only owned volatile
; state is reset; committed documents and WM state live outside this arena.
native_app_restart:
    push rbx
    call native_app_gate
    test rax, rax
    jnz  .out
    call native_app_resolve
    test rax, rax
    jnz  .out
    mov  rbx, r8
    mov  rdx, [r8 + NAPP_GEN]
    inc  rdx
    jz   .bad
    call native_app_zero_arena
    mov  [rbx + NAPP_GEN], rdx
    mov  qword [rbx + NAPP_ELAPSED], 0
    mov  qword [rbx + NAPP_CAUSE], 0
    mov  qword [rbx + NAPP_STATE], NAPP_READY
    xor  eax, eax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  rbx
    ret

; unregister(EDI=slot, RSI=current generation) -> RAX=0, or same refusals.
; Generation is retained when freeing; slot reuse advances it again.
native_app_unregister:
    push rbx
    call native_app_gate
    test rax, rax
    jnz  .out
    call native_app_resolve
    test rax, rax
    jnz  .out
    mov  rbx, r8
    call native_app_zero_arena
    mov  qword [rbx + NAPP_ENTRY], 0
    mov  qword [rbx + NAPP_LEASE], 0
    mov  qword [rbx + NAPP_ELAPSED], 0
    mov  qword [rbx + NAPP_CAUSE], 0
    mov  qword [rbx + NAPP_STATE], NAPP_FREE
    xor  eax, eax
.out:
    pop  rbx
    ret

native_app_zero_arena:
    mov  eax, edi
    shl  eax, 12
    lea  rdi, [rel native_app_arenas]
    add  rdi, rax
    mov  ecx, NAPP_ARENA_SIZE / 8
    xor  eax, eax
    cld
    rep  stosq
    ret

; query(EDI=slot) -> RAX=state (0 free/1 ready/2 stuck), RDX=generation,
; R8=private arena, R9=last measured dispatch cycles, R10=last failure cause
; (0 none, -1 recovered fault, -2 watchdog), R11=registered lease milliseconds.
; Negative=context/invalid. Refused re-entry preserves latched cause/cycles.
; An arena with a failed dispatch is not a committed result.
native_app_query:
    push rbx
    call native_app_gate
    test rax, rax
    jnz  .out
    cmp  edi, NAPP_MAX
    jae  .bad
    mov  eax, edi
    shl  eax, 6
    lea  rbx, [rel native_app_records]
    add  rbx, rax
    mov  rax, [rbx + NAPP_STATE]
    mov  rdx, [rbx + NAPP_GEN]
    mov  r9, [rbx + NAPP_ELAPSED]
    mov  r10, [rbx + NAPP_CAUSE]
    mov  r11, [rbx + NAPP_LEASE]
    shl  edi, 12
    lea  r8, [rel native_app_arenas]
    add  r8, rdi
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  rbx
    ret

%macro WDATA_native_app 0
native_app_busy: db 0
align 8
native_app_start: dq 0
native_app_records: times NAPP_MAX * NAPP_REC_SIZE db 0
align 16
native_app_host_fx: times 512 db 0
align 64
native_app_arenas: times NAPP_MAX * NAPP_ARENA_SIZE db 0
%endmacro
WDATA_DEFER WDATA_native_app
