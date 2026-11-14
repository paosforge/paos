;; MODULE svc/command_sched
;; LAYER 5
;; EXPORTS sched_class_selftest, cmd_verb_schedplace, cmd_verb_schedstat, sched_out_ready, sched_out_buf, sched_out_cur
;; IMPORTS boot/serial, core/lib/fmt, core/lib/str, core/sched, svc/command
;; CAPS
;; OWNER saga:sched
; ============================================================================
; svc/command_sched.asm — the MULTI-CLASS SCHEDULER POLICY LAYER (contract 1048,
; SCHEDULER.md §2-4,§8). On top of the cooperative core/sched seam this adds the
; declarative sched_class TABLE (owner/forge/throughput/realtime + the grid-ready
; "borrowed" row) and a PLACEMENT-POLICY HOOK: jobs are PLACED through a function
; pointer, NOT directly invoked.
;
; The keystone (SCHEDULER.md §2 grid-readiness / VIRTUAL_ELECTRICITY.md, PRINCIPLES
; §1 degenerate-to-one): the class TABLE and the placement HOOK exist AT v1 even
; though v1's policy is trivial-and-local. Every class row already carries a PEER
; target field (SC_PEER_LOCAL at v1) so a future "borrowed"/grid class + a
; peer-placement destination slot in ADDITIVELY — no retrofit of the seam, the
; field is present, degenerate to one.
;
; Topology is read at boot from CPUID (logical processor count) — real silicon,
; so placement SPREADS across the machine's actual cores. CORE-PARTITIONABLE: each
; class confines to [plo,phi]. Class is a PRIOR/hint steering PLACEMENT (which core
; a job LANDS on), not a command — the C3 work-stealing substrate stays the
; all-cores clearing mechanism.
;
; Bare-metal deliverable (probe_sched_priority_classes.sh): SCHEDPLACE <class>
; <nonce> PLACES a job in the named class carrying the nonce and replies
; "class=<c> core=<n>" (+ the nonce round-trips via the always-on ARG= echo); a
; latch cannot fake the nonce nor route owner/forge/throughput to different rows.
; SCHEDSTAT returns per-core occupancy so the >1-core SPREAD is provable (cores=1
; honest degenerate on a single-core box). Both are REGISTRY verbs (COMMANDS.md
; §1 single vocabulary); the UDP surface frames sched_out_buf like every other
; staged reply.
; ============================================================================

SCHED_MAXCORE   equ 32                     ; matches core/sched SMP_CPU_CAPACITY; includes 20-logical-CPU targets
SCHED_NCLASS    equ 5                      ; owner/forge/throughput/realtime/borrowed
SCHED_KAT_JOBS  equ 8                      ; throughput jobs the boot SPREAD selftest places
SCHED_OUT_CAP   equ 384                    ; includes the staged reply's final NUL
SCHED_STAT_ROW_MAX equ 28                  ; " core31=4294967295throughput"
SCHED_TRUNC_SUFFIX_LEN equ 12              ; " truncated=1"

; --- class ids (rows of the ONE table) ---
SC_OWNER        equ 0                      ; the owner's interactive work (near the input path)
SC_FORGE        equ 1                      ; background builds (the forge)
SC_TPUT         equ 2                      ; bulk throughput (spread across cores)
SC_RT           equ 3                      ; time-critical realtime (dedicated core, hard)
SC_BORROW       equ 4                      ; grid-ready "borrowed"/peer class (degenerate-local at v1)

; --- placement-policy affinity kinds (read by the hook) ---
AFF_PIN         equ 0                      ; pin to .home core (clamped into the partition)
AFF_SPREAD      equ 1                      ; round-robin across [plo,phi] (the SPREAD guarantee)
AFF_PEER        equ 2                      ; grid target (v1 peer==LOCAL -> degenerate to local spread)
SC_PEER_LOCAL   equ -1                     ; the degenerate-to-one peer target present at v1

; --- sched_class row layout (SCHEDULER.md §2 class table) ---
SCLS_NAME       equ 0                      ; dq  name cstr ptr
SCLS_AFF        equ 8                      ; dd  affinity kind (AFF_*)
SCLS_HOME       equ 12                     ; dd  home core (AFF_PIN target)
SCLS_PLO        equ 16                     ; dd  partition low  (CORE-PARTITIONABLE)
SCLS_PHI        equ 20                     ; dd  partition high
SCLS_PEER       equ 24                     ; dd  peer target (grid seam; SC_PEER_LOCAL at v1)
SCLS_RR         equ 28                     ; dd  round-robin cursor (AFF_SPREAD)
SCLS_SZ         equ 32

; ---------------------------------------------------------------------------
; sched_detect_cores -> EAX = logical processor count (>=1, clamped SCHED_MAXCORE).
;   Real topology from CPUID: leaf 0x0B subleaf 1 EBX[15:0] = logical procs across
;   the package (the true count on modern Intel). Fallback: leaf 1 EBX[23:16] when
;   HTT is set; else 1 (honest single-core degenerate). clobbers: RAX,RCX,RDX (RBX
;   preserved).
; ---------------------------------------------------------------------------
sched_detect_cores:
    push rbx
    mov  eax, 0x0B
    mov  ecx, 1
    cpuid
    and  ebx, 0xFFFF
    test ebx, ebx
    jnz  .have
    mov  eax, 1
    cpuid
    test edx, (1 << 28)                    ; HTT
    jz   .single
    shr  ebx, 16
    and  ebx, 0xFF
    test ebx, ebx
    jnz  .have
.single:
    mov  ebx, 1
.have:
    cmp  ebx, SCHED_MAXCORE
    jbe  .ok
    mov  ebx, SCHED_MAXCORE
.ok:
    mov  eax, ebx
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; sched_class_init — build the class table for the detected topology + arm the
;   placement-policy hook (grid-ready seam). Idempotent. clobbers: caller-saved.
; ---------------------------------------------------------------------------
sched_class_init:
    push rbx
    call sched_detect_cores
    mov  [rel sched_ncores], eax
    mov  ebx, eax                          ; ncores
    dec  ebx                               ; ncores-1 = top core (partition high)
    ; forge home = min(1, ncores-1) so it differs from owner(0) when SMP
    xor  ecx, ecx                          ; forge home
    cmp  dword [rel sched_ncores], 1
    jle  .forge_home_set
    mov  ecx, 1
.forge_home_set:
    ; owner row (PIN core 0 — near the input path)
    lea  rdi, [rel sched_class_tbl + SC_OWNER*SCLS_SZ]
    lea  rax, [rel sc_name_owner]
    mov  [rdi + SCLS_NAME], rax
    mov  dword [rdi + SCLS_AFF], AFF_PIN
    mov  dword [rdi + SCLS_HOME], 0
    mov  dword [rdi + SCLS_PLO], 0
    mov  [rdi + SCLS_PHI], ebx
    mov  dword [rdi + SCLS_PEER], SC_PEER_LOCAL
    mov  dword [rdi + SCLS_RR], 0
    ; forge row (PIN a background core)
    lea  rdi, [rel sched_class_tbl + SC_FORGE*SCLS_SZ]
    lea  rax, [rel sc_name_forge]
    mov  [rdi + SCLS_NAME], rax
    mov  dword [rdi + SCLS_AFF], AFF_PIN
    mov  [rdi + SCLS_HOME], ecx
    mov  dword [rdi + SCLS_PLO], 0
    mov  [rdi + SCLS_PHI], ebx
    mov  dword [rdi + SCLS_PEER], SC_PEER_LOCAL
    mov  dword [rdi + SCLS_RR], 0
    ; throughput row (SPREAD round-robin across all cores)
    lea  rdi, [rel sched_class_tbl + SC_TPUT*SCLS_SZ]
    lea  rax, [rel sc_name_tput]
    mov  [rdi + SCLS_NAME], rax
    mov  dword [rdi + SCLS_AFF], AFF_SPREAD
    mov  dword [rdi + SCLS_HOME], 0
    mov  dword [rdi + SCLS_PLO], 0
    mov  [rdi + SCLS_PHI], ebx
    mov  dword [rdi + SCLS_PEER], SC_PEER_LOCAL
    mov  dword [rdi + SCLS_RR], 0
    ; realtime row (PIN the top core, dedicated)
    lea  rdi, [rel sched_class_tbl + SC_RT*SCLS_SZ]
    lea  rax, [rel sc_name_rt]
    mov  [rdi + SCLS_NAME], rax
    mov  dword [rdi + SCLS_AFF], AFF_PIN
    mov  [rdi + SCLS_HOME], ebx
    mov  dword [rdi + SCLS_PLO], 0
    mov  [rdi + SCLS_PHI], ebx
    mov  dword [rdi + SCLS_PEER], SC_PEER_LOCAL
    mov  dword [rdi + SCLS_RR], 0
    ; borrowed row (PEER — the grid-ready seam; v1 peer==LOCAL -> local spread)
    lea  rdi, [rel sched_class_tbl + SC_BORROW*SCLS_SZ]
    lea  rax, [rel sc_name_borrow]
    mov  [rdi + SCLS_NAME], rax
    mov  dword [rdi + SCLS_AFF], AFF_PEER
    mov  dword [rdi + SCLS_HOME], 0
    mov  dword [rdi + SCLS_PLO], 0
    mov  [rdi + SCLS_PHI], ebx
    mov  dword [rdi + SCLS_PEER], SC_PEER_LOCAL
    mov  dword [rdi + SCLS_RR], 0
    ; zero the per-core occupancy tables
    xor  ecx, ecx
.zloop:
    cmp  ecx, SCHED_MAXCORE
    jge  .zdone
    lea  rax, [rel sched_core_total]
    mov  dword [rax + rcx*4], 0
    lea  rax, [rel sched_core_tput]
    mov  dword [rax + rcx*4], 0
    inc  ecx
    jmp  .zloop
.zdone:
    ; arm the placement-policy hook (the grid-ready indirection: swap this fn ptr
    ; for sched_place_peer additively when a "borrowed" policy lands — no seam edit)
    lea  rax, [rel sched_place_local]
    mov  [rel sched_place_hook], rax
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; sched_lookup_class(RDI=name cstr) -> EAX = class id, or -1 if no such class
;   (default-deny placement). clobbers: RAX,RCX,RDX,RSI,RDI,R8,R9,R10.
; ---------------------------------------------------------------------------
sched_lookup_class:
    push rbx
    push r12
    push r13
    mov  r12, rdi                          ; target name
    xor  r13d, r13d
.scan:
    cmp  r13d, SCHED_NCLASS
    jge  .miss
    mov  eax, r13d
    imul eax, SCLS_SZ
    lea  rbx, [rel sched_class_tbl]
    mov  rdi, [rbx + rax + SCLS_NAME]
    mov  rsi, r12
    call strcmp                            ; the ONE canonical strcmp (G1)
    test rax, rax
    jz   .hit
    inc  r13d
    jmp  .scan
.hit:
    mov  eax, r13d
    jmp  .out
.miss:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; sched_place_local(EDI=class id) -> EAX = core id. THE v1 placement policy behind
;   the hook. Reads the row's affinity + partition and returns the target core:
;     AFF_PIN    -> the home core, clamped into [plo,phi]
;     AFF_SPREAD -> plo + (rr++ mod partition width)  (the SPREAD guarantee)
;     AFF_PEER   -> peer==LOCAL degenerate: local spread (a remote target lands here
;                   additively later). clobbers: RAX,RCX,RDX,R8,R9,R10,R11.
; ---------------------------------------------------------------------------
sched_place_local:
    mov  eax, edi
    imul eax, SCLS_SZ
    lea  r10, [rel sched_class_tbl]
    add  r10, rax                          ; r10 = row
    mov  r8d, [r10 + SCLS_PLO]             ; plo
    mov  r9d, [r10 + SCLS_PHI]             ; phi
    mov  ecx, [r10 + SCLS_AFF]
    cmp  ecx, AFF_PIN
    je   .pin
    ; SPREAD / PEER(local): round-robin over the partition width
    mov  eax, r9d
    sub  eax, r8d
    inc  eax                               ; width = phi-plo+1 (>=1)
    mov  ecx, [r10 + SCLS_RR]
    mov  edx, ecx
    inc  edx
    mov  [r10 + SCLS_RR], edx              ; advance the cursor
    mov  eax, ecx
    xor  edx, edx
    mov  r11d, r9d
    sub  r11d, r8d
    inc  r11d                              ; width again (div source)
    div  r11d                              ; edx = rr mod width
    lea  eax, [r8 + rdx]                   ; core = plo + (rr mod width)
    ret
.pin:
    mov  eax, [r10 + SCLS_HOME]
    cmp  eax, r8d
    jae  .pin_hi
    mov  eax, r8d                          ; clamp up to plo
.pin_hi:
    cmp  eax, r9d
    jbe  .pin_ok
    mov  eax, r9d                          ; clamp down to phi
.pin_ok:
    ret

; ---------------------------------------------------------------------------
; sched_place(EDI=class id) -> EAX = core id, or -1 if the class id is invalid
;   (default-deny). Routes THROUGH the placement hook (never a direct invoke) then
;   records per-core occupancy (total + throughput). clobbers: caller-saved.
; ---------------------------------------------------------------------------
sched_place:
    push rbx
    cmp  edi, 0
    jl   .bad
    cmp  edi, SCHED_NCLASS
    jge  .bad
    mov  ebx, edi                          ; remember class id
    call [rel sched_place_hook]            ; EDI=class id -> EAX=core
    ; record occupancy: total[core]++ ; if throughput, tput[core]++
    mov  ecx, eax                          ; core
    cmp  ecx, 0
    jl   .done
    cmp  ecx, SCHED_MAXCORE
    jge  .done
    lea  rdx, [rel sched_core_total]
    inc  dword [rdx + rcx*4]
    cmp  ebx, SC_TPUT
    jne  .done
    lea  rdx, [rel sched_core_tput]
    inc  dword [rdx + rcx*4]
.done:
    pop  rbx
    ret
.bad:
    mov  eax, -1
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; staged-reply helpers (sched_out_buf, framed verbatim by command_udp.asm exactly
;   like reinit_out_buf/prin_out_buf). All writers retain a final in-buffer NUL.
;   clobbers: caller-saved registers only.
; ---------------------------------------------------------------------------
sched_out_reset:
    lea  rax, [rel sched_out_buf]
    mov  [rel sched_out_cur], rax
    mov  byte [rel sched_out_buf], 0
    ret

sched_put_str:                             ; RDI = cstr
    mov  rsi, [rel sched_out_cur]
    lea  rdx, [rel sched_out_buf + SCHED_OUT_CAP - 1]
.cp:
    mov  al, [rdi]
    test al, al
    jz   .done
    cmp  rsi, rdx
    jae  .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel sched_out_cur], rsi
    ret

sched_put_dec:                             ; RDI = value
    lea  rsi, [rel sched_numbuf]           ; fmt_dec needs up to 21 bytes including NUL
    call fmt_dec                           ; RAX = digit count, NUL-terminates
    lea  rdi, [rel sched_numbuf]
    jmp  sched_put_str                     ; the shared bounded append path

; sched_put_token(RSI=src) -> RSI past the token; copies src up to a space/NUL into
;   the staged buffer (bounded by the buffer). clobbers: RAX,RSI,RDI,RCX,R8.
sched_put_token:
    mov  rdi, [rel sched_out_cur]
    lea  r8, [rel sched_out_buf + SCHED_OUT_CAP - 1]
    mov  ecx, 64                           ; per-token bound
.cp:
    test ecx, ecx
    jz   .done
    mov  al, [rsi]
    test al, al
    jz   .done
    cmp  al, ' '
    je   .done
    cmp  rdi, r8
    jae  .done
    mov  [rdi], al
    inc  rdi
    inc  rsi
    dec  ecx
    jmp  .cp
.done:
    mov  byte [rdi], 0
    mov  [rel sched_out_cur], rdi
    ret

; ---------------------------------------------------------------------------
; VERB: SCHEDPLACE (RDI=req, RSI=resp) — ARGT_TEXT arg = "<class> <nonce>". PLACE a
;   job in the named class carrying the nonce; stage "class=<c> core=<n> nonce=<x>"
;   (the nonce ALSO round-trips via the always-on ARG= echo). Unknown class ->
;   default-deny "class=none" (NOT silently mis-placed). clobbers: caller-saved.
; ---------------------------------------------------------------------------
cmd_verb_schedplace:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  r13, rsi                          ; resp
    mov  r14, [rdi + REQ_ARG]              ; raw text: "<class> <nonce>"
    test r14, r14
    jz   .badarg                          ; refuse before parsing, placement or execution
    ; copy the class token out of the arg into sched_argclass (bounded)
    mov  rsi, r14
    lea  rdi, [rel sched_argclass]
    mov  ecx, 32
.ct:
    test ecx, ecx
    jz   .ct_done
    mov  al, [rsi]
    test al, al
    jz   .ct_done
    cmp  al, ' '
    je   .ct_done
    mov  [rdi], al
    inc  rdi
    inc  rsi
    dec  ecx
    jmp  .ct
.ct_done:
    mov  byte [rdi], 0
    mov  r12, rsi                          ; r12 -> after the class token (at space/NUL)
    ; advance past spaces to the nonce token start
.skip:
    cmp  byte [r12], ' '
    jne  .nonce_ready
    inc  r12
    jmp  .skip
.nonce_ready:
    ; resolve the class
    lea  rdi, [rel sched_argclass]
    call sched_lookup_class                ; EAX = class id / -1
    mov  ebx, eax                           ; SAVE class id in RBX (callee-saved: survives
                                            ; sched_out_reset's EAX clobber AND sched_place's
                                            ; hook clobber of r10/r11) — the class-id bug fix
    call sched_out_reset
    cmp  ebx, -1
    je   .deny
    mov  edi, ebx
    call sched_place                        ; EAX = core id (hook clobbers r10/r11, not rbx/r12-r14)
    mov  edi, eax
    call sched_affinity_probe_execute
    test eax, eax
    js   .exec_deny
    mov  r14d, eax
    ; "class=<name> core=<n> executed=1 nonce=<token>"
    lea  rdi, [rel str_sc_class]            ; " class="
    call sched_put_str
    mov  edi, ebx
    imul edi, SCLS_SZ
    lea  rax, [rel sched_class_tbl]
    mov  rdi, [rax + rdi + SCLS_NAME]
    call sched_put_str
    lea  rdi, [rel str_sc_core]             ; " core="
    call sched_put_str
    mov  edi, r14d
    call sched_put_dec
    lea  rdi, [rel str_sc_executed]
    call sched_put_str
    mov  edi, 1
    call sched_put_dec
    lea  rdi, [rel str_sc_nonce]            ; " nonce="
    call sched_put_str
    mov  rsi, r12
    call sched_put_token
    mov  byte [rel sched_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  eax, r14d
    mov  [r13 + RSP_VAL], rax               ; RSP_VAL = placed core
    jmp  .out
.exec_deny:
    lea  rdi, [rel str_sc_class]
    call sched_put_str
    mov  edi, ebx
    imul edi, SCLS_SZ
    lea  rax, [rel sched_class_tbl]
    mov  rdi, [rax + rdi + SCLS_NAME]
    call sched_put_str
    lea  rdi, [rel str_sc_core_none]
    call sched_put_str
    lea  rdi, [rel str_sc_executed]
    call sched_put_str
    xor  edi, edi
    call sched_put_dec
    lea  rdi, [rel str_sc_nonce]
    call sched_put_str
    mov  rsi, r12
    call sched_put_token
    mov  byte [rel sched_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], -1
    jmp  .out
.deny:
    lea  rdi, [rel str_sc_class_none]       ; " class=none nonce="
    call sched_put_str
    mov  rsi, r12
    call sched_put_token
    mov  byte [rel sched_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK    ; answered (default-deny), boot continues
    jmp  .out
.badarg:
    call sched_out_reset
    mov  byte [rel sched_out_ready], 0     ; no stale success body on malformed input
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    mov  qword [r13 + RSP_VAL], 0
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; VERB: SCHEDSTAT (RDI=req, RSI=resp) — stage "cores=<N>" + per-core throughput
;   occupancy tokens " core<c>=<count>throughput" so the SPREAD (>1 core carrying
;   throughput) is provable. cores=1 is the honest single-core degenerate.
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
cmd_verb_schedstat:
    call cmd_handler_prologue
    push r12
    push r13
    mov  r13, rsi                          ; resp
    call sched_out_reset
    lea  rdi, [rel str_sc_cores]            ; " cores="
    call sched_put_str
    mov  edi, [rel sched_ncores]
    call sched_put_dec
    xor  r12d, r12d
.core_loop:
    cmp  r12d, [rel sched_ncores]
    jge  .core_done
    cmp  r12d, SCHED_MAXCORE
    jge  .core_done
    lea  rax, [rel sched_core_tput]
    mov  eax, [rax + r12*4]
    test eax, eax
    jz   .core_next
    ; Keep complete occupancy tokens and reserve space for an honest truncation
    ; suffix. Sixteen maximum-u32 rows exceed this surface's fixed 384-byte ABI.
    lea  rdx, [rel sched_out_buf + SCHED_OUT_CAP - 1]
    sub  rdx, [rel sched_out_cur]
    cmp  rdx, SCHED_STAT_ROW_MAX + SCHED_TRUNC_SUFFIX_LEN
    jb   .truncated
    ; " core<c>=<count>throughput"
    lea  rdi, [rel str_sc_corepre]          ; " core"
    call sched_put_str
    mov  edi, r12d
    call sched_put_dec
    lea  rdi, [rel str_sc_eq]               ; "="
    call sched_put_str
    lea  rax, [rel sched_core_tput]
    mov  edi, [rax + r12*4]
    call sched_put_dec
    lea  rdi, [rel str_sc_tput]             ; "throughput"
    call sched_put_str
.core_next:
    inc  r12d
    jmp  .core_loop
.truncated:
    lea  rdi, [rel str_sc_truncated]
    call sched_put_str
.core_done:
    mov  byte [rel sched_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    pop  r13
    pop  r12
    ret

; ---------------------------------------------------------------------------
; sched_class_selftest — build the table, arm the hook, run the SPREAD KAT, and
;   register the two registry verbs. Emits the 3 markers (sched.classes /
;   sched.place.hook / sched.spread.kat) + the qemu KAT print. Called from
;   boot/header AFTER command_registry_selftest (the registry must exist).
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
sched_class_selftest:
    push rbx
    push r12
    push r13
    call sched_class_init
    ; marker 1: class table ready
    mov  byte [rel sched_m_classes], 1
    lea  rdi, [rel str_m_classes]
    call serial_string
    ; marker 2: placement-policy hook armed (grid-ready seam)
    mov  byte [rel sched_m_hook], 1
    lea  rdi, [rel str_m_hook]
    call serial_string
    ; --- SPREAD KAT: place SCHED_KAT_JOBS throughput jobs, count distinct cores ---
    xor  r12d, r12d                         ; job counter
.spread:
    cmp  r12d, SCHED_KAT_JOBS
    jge  .spread_done
    mov  edi, SC_TPUT
    call sched_place
    inc  r12d
    jmp  .spread
.spread_done:
    ; place an owner job -> must land on the owner/interactive home core (0)
    mov  edi, SC_OWNER
    call sched_place
    mov  r13d, eax                          ; owner core
    ; cores_used = number of distinct cores carrying throughput
    xor  ebx, ebx                           ; cores_used
    xor  ecx, ecx
.count:
    cmp  ecx, SCHED_MAXCORE
    jge  .count_done
    lea  rax, [rel sched_core_tput]
    cmp  dword [rax + rcx*4], 0
    je   .count_next
    inc  ebx
.count_next:
    inc  ecx
    jmp  .count
.count_done:
    mov  [rel sched_cores_used], ebx
    ; PASS if spread across >1 core OR honest single-core degenerate
    cmp  ebx, 1
    jg   .spread_pass
    cmp  dword [rel sched_ncores], 1
    jle  .spread_pass
    jmp  .spread_after                      ; multi-core but no spread -> no marker (honest)
.spread_pass:
    mov  byte [rel sched_m_spread], 1
    lea  rdi, [rel str_m_spread]
    call serial_string
.spread_after:
    ; qemu KAT print: "sched.kat cores_used=<k> jobs=<n> ncores=<N> owner_core=<c>"
    lea  rdi, [rel str_kat_pre]
    call serial_string
    mov  edi, [rel sched_cores_used]
    lea  rsi, [rel sched_numbuf]
    call fmt_dec
    lea  rdi, [rel sched_numbuf]
    call serial_string
    lea  rdi, [rel str_kat_jobs]
    call serial_string
    mov  edi, SCHED_KAT_JOBS
    lea  rsi, [rel sched_numbuf]
    call fmt_dec
    lea  rdi, [rel sched_numbuf]
    call serial_string
    lea  rdi, [rel str_kat_ncores]
    call serial_string
    mov  edi, [rel sched_ncores]
    lea  rsi, [rel sched_numbuf]
    call fmt_dec
    lea  rdi, [rel sched_numbuf]
    call serial_string
    lea  rdi, [rel str_kat_owner]
    call serial_string
    mov  edi, r13d
    lea  rsi, [rel sched_numbuf]
    call fmt_dec
    lea  rdi, [rel sched_numbuf]
    call serial_string
    call serial_newline
    ; --- register the two registry verbs (COMMANDS.md §1 single vocabulary) ---
    lea  rdi, [rel str_verb_schedplace]
    lea  rsi, [rel cmd_verb_schedplace]
    xor  edx, edx                           ; declared cap 0; remote floor already requires MUTATE
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9d, 1                            ; places/executes work: effect metadata, unchanged authority
    call command_register_verb
    lea  rdi, [rel str_verb_schedstat]
    lea  rsi, [rel cmd_verb_schedstat]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---- module data ----------------------------------------------------------
align 8
sched_place_hook:   dq 0                    ; the placement-policy hook (grid-ready indirection)
sched_ncores:       dd 1                    ; detected logical processor count
sched_cores_used:   dd 0                    ; distinct cores the SPREAD KAT touched
sched_m_classes:    db 0                    ; marker flags (set on selftest pass; ride every BOOTLOG reply)
sched_m_hook:       db 0
sched_m_spread:     db 0
sched_out_ready:    db 0                    ; 1 = sched_out_buf holds a staged reply line
align 8
sched_out_cur:      dq 0
sched_out_buf:      times SCHED_OUT_CAP db 0 ; staged SCHEDPLACE/SCHEDSTAT reply text
sched_argclass:     times 40 db 0           ; parsed class token
align 8
sched_class_tbl:    times (SCHED_NCLASS * SCLS_SZ) db 0
sched_core_total:   times SCHED_MAXCORE dd 0
sched_core_tput:    times SCHED_MAXCORE dd 0
sched_numbuf:       times 24 db 0

; class name strings (the table's SCLS_NAME targets)
sc_name_owner:      db "owner", 0
sc_name_forge:      db "forge", 0
sc_name_tput:       db "throughput", 0
sc_name_rt:         db "realtime", 0
sc_name_borrow:     db "borrowed", 0

; registry verb names
str_verb_schedplace: db "SCHEDPLACE", 0
str_verb_schedstat:  db "SCHEDSTAT", 0

; staged-reply fragments
str_sc_class:       db " class=", 0
str_sc_class_none:  db " class=none nonce=", 0
str_sc_core:        db " core=", 0
str_sc_core_none:   db " core=none", 0
str_sc_executed:    db " executed=", 0
str_sc_nonce:       db " nonce=", 0
str_sc_cores:       db " cores=", 0
str_sc_corepre:     db " core", 0
str_sc_eq:          db "=", 0
str_sc_tput:        db "throughput", 0
str_sc_truncated:   db " truncated=1", 0

; boot serial markers (registered in regression_tests.txt)
str_m_classes:  db "[PAOS64] P2 sched class: table ready (owner/forge/throughput/realtime/borrowed) [sched.classes]", 13, 10, 0
str_m_hook:     db "[PAOS64] P2 sched class: placement-policy hook armed (grid-ready seam) [sched.place.hook]", 13, 10, 0
str_m_spread:   db "[PAOS64] P2 sched class: N throughput jobs SPREAD across cores PASS [sched.spread.kat]", 13, 10, 0
str_kat_pre:    db "[PAOS64] P2 sched class: sched.kat cores_used=", 0
str_kat_jobs:   db " jobs=", 0
str_kat_ncores: db " ncores=", 0
str_kat_owner:  db " owner_core=", 0
