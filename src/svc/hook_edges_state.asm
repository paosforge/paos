;; MODULE svc/hook_edges_state
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS hook_webdigest_plan, hook_webdigest_post, hook_http_plan, hook_http_post, hook_tls_plan, hook_tls_post, hook_freqmsr_plan, hook_freqmsr_post, hook_throttle_log_plan, hook_throttle_log_post, hook_state_edges_declare, hook_netcheck_plan, hook_ntp_plan, hook_dns_plan, hook_tcp_plan, hook_tcp_post, hook_ssh_plan, hook_ssh_post, hook_idle_plan, hook_idle_post, hook_thermal_plan, hook_thermal_post, hook_bootclock_plan, hook_bootclock_post, hook_cpucost_plan, hook_srvstat_plan, hook_srvstat_post, hook_pstate_plan, hook_pstate_post
;; IMPORTS svc/command_web, svc/command_tls13, svc/command, svc/command_hook, svc/command_netcheck, svc/command_ntp, svc/command_dns, svc/command_net_diag, svc/command_ssh, svc/thermal, svc/boot_clock, svc/command_auth, svc/command_srvstat, svc/hook_edge_smpstat, svc/idle_probe, core/build_id, core/lib/fmt
;; CAPS
;; OWNER saga:command
; ============================================================================
; svc/hook_edges_state.asm -- RCQ-15 slice 4: network-state and idle HOOK edges.
;
;   netcheck  (network)  the one-shot network health line  native NETCHECK
;   ntp       (network)  the wall-clock sync state         native NTPSTAT / NTPSYNC <a.b.c.d[:port]>
;   dns       (network)  one name in the resolver cache    native DNSCACHE <name> / RESOLVE <name>
;   tcp       (network)  the TCP table counters            native TCPSTAT
;   ssh       (network)  the SSH login surface             native SSHSTAT / SSHKEYLIST
;   throttle_log (power) cached notice/status record    native THROTTLE_LOG (read only)
;   freqmsr   (power)    explicit active sprint/eff measurement native FREQMSR
;   pstate    (power)    bounded native APERF/MPERF ratio  native PSTATE? (read only)
;   thermal   (power)    native live temperature        native THERM (read only)
;   idle      (power)    cached boot idle observations     native IDLEDEPTH [<state>]
;
; As in slices 1 to 3, an edge only PLANS a native verb and argument;
; svc/command_hook dispatches it with the caller's own source, principal,
; capability and idempotency key, so the native gate decides. IDLEPROBE and
; IDLEDEPTH are registered with the explicit owner cap, so every idle op needs
; the authority the native read needs; IDLEDEPTH <state> is owner-only in its
; own handler as well. NTPSYNC and RESOLVE send packets and change state (the
; wall clock, the resolver cache), so they are SET ops and land in the hook
; event ring. Every native here stages its own reply text in a buffer the UDP
; reply chain frames ahead of the marker tail. TCP validates its complete native
; receipt before copying to typed staging;
; idle projects a passive cached snapshot;
; thermal validates and transfers its complete native reply into typed staging.
;
; Typed rules the edges add (stricter only):
;   * netcheck: GET, or SET propose <16 lowercase hex key> for the existing
;     no_lease DHCP-once card. Proposal is not confirmation; native card gates
;     and the common effectful-hook taint refusal remain authoritative;
;   * tcp: one instance, GET only; complete ordered native u64 receipt;
;   * ntp: one instance; GET is NTPSTAT (which may persist one valid receipt,
;     its own rule); SET takes exactly "sync <a.b.c.d>[:<port>]": four decimal
;     octets 0..255 of 1..3 digits, a port of 1..5 digits in 1..65535;
;   * dns: the instance is the name, 1..HST_DNS_NAME_MAX of [A-Za-z0-9.-]
;     starting with a letter or digit; GET is the cache entry, SET takes
;     exactly "resolve" (one query); LIST is "hook na" (no cache enumeration);
;   * ssh: one instance; GET is SSHSTAT, LIST is SSHKEYLIST (fingerprints and
;     capability masks, never key bytes); SSHKEYADD/SSHKEYDEL and the other
;     key verbs are not typed;
;   * idle: GET/OBSERVE boot summary or dense CPU instance, passive IDLEDEPTH
;     admission and cached snapshot, with typed owner envelope. Entry counters
;     are visible but excluded from OBSERVE witness, like SRVSTAT volatile counts.
;     SET remains boot-scoped IDLEDEPTH (HLT C1E C6 C8 C10 C2 C3), no instance.
; The owner-only state reads FSOWNSTAT and OWNERSTAT, FSOWN and AUTHFLOOR are
; not typed in this slice: their replies are RSP_HINT text, which the UDP
; reply chain never sends, so a hook reply would be a new remote channel for
; owner-private text (held for an rc-sec ruling).
; Thermal GET/OBSERVE dispatches the existing THERM operation with an empty
; argument, unchanged caller identity and native MUTATE capability classification.
; It is already a native staged transport response, not a new private projection.
; Source/degraded/unavailable mean exactly what THERM says: DTS and AMD Tctl are
; distinct sources; tjmax is the native cached/default threshold (not an AMD trip
; limit). There is no native sample timestamp/age/valid-bit field, so this edge
; promises none. THERM can do its existing gated sensor read; this adapter adds no
; sensor/firmware path, heat, PSTATE load, throttle, reset or settings operation.
; The planner retires old shared thermal staging before the native dispatch;
; post requires a newly staged, bounded, complete THERM record, copies only that
; record into hook staging and retires the shared reply on success/error. Existing
; BSP command serialization is retained. Witness covers only its four fields.
; Every unsupported op answers "hook na".
; BOOTCLOCK is cap0/destr0 and explicitly public in the shipped classifier;
; the native registration/gate remains authoritative if either metadata changes.
; GET/OBSERVE supplies a fresh correlation nonce, retains original caller identity,
; and validates the complete staged record before relaying public clock facts.
; No private projection or owner-envelope exception: native BOOTCLOCK already
; frames this response on the shared auth text rail. Planner retires old shared
; staging; post preserves fresh native refusals and consumes successful/malformed
; clock staging. Existing BSP command serialization remains the lifetime boundary.
; Origin is payload EFI entry, not power-on; no health/policy/sampling guarantee
; is inferred. Triplets retain present/reason/ms and full64 native durations;
; witness excludes request nonce and now (mere current observation-time churn).
; No native producer, calibration, deadline, boot gate or offline decoder writes.
; cpucost is a compact public read-only view of native BOOTCLOCKv7 preload/BSP
; elapsed-call intervals. It shares the complete receipt/grammar validator, not
; the legacy bootclock v6 projection or witness. It never loads microcode.
; Identities: netcheck, ntp, dns:<name>, tcp, ssh, idle, thermal, bootclock, cpucost, srvstat, pstate.
; SRVSTAT GET/OBSERVE relays only its existing public, bounded native record.
; It does not grant authority, sample extra diagnostics or expose private state.
; Plan retires prior software staging; post requires this dispatch's complete
; native record and transfers it to HOOK staging (native UDP is exact-verb-only).
; Native code/hint/refusal remain authoritative; BSP serialization owns lifetime.
; ARG is omitted correlation (native ARG=none), never a witness key. Uptime,
; NET_TX/RX and CSP_ENTER/DONE/ENTRIES/RETURNS/ACTIVE/POLLS are volatile: observing
; the pump can itself advance them. They remain visible in GET but are excluded
; from OBSERVE's witness. RAM availability, policy, sessions, diagnostic validity,
; RX identity/state and publisher state remain semantic witness inputs. Native
; constants are also keyed. Changing a latched diagnostic state is observable;
; mere continued self-observation is stable. None proves live service health,
; freshness, readiness, external reachability or watchdog progress. No policy
; consumes the record here; no native producer or offline decoder is changed.
; Identities: netcheck, ntp, dns:<name>, tcp, ssh, idle, thermal, srvstat.
; ============================================================================

HST_DNS_NAME_MAX   equ 253
HST_OCTET_DIGITS   equ 3
HST_PORT_DIGITS    equ 5

; hook_state_edges_declare -- bind the state descriptors (lea at init, ESSENCE S10)
;   and register them after the slice-3 edges. clobbers: caller-saved.
hook_state_edges_declare:
    push rbx
%if !PAOS_PUBLIC_BUILD
    ; The saved digest is a distinct read surface; old http stays body-free.
    lea  rbx, [rel hook_edge_webdigest]
    lea  rax, [rel str_hwd_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_network]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hwd_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_webdigest_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_webdigest_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0       ; all bytes, including untrusted text
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_http]
    lea  rax, [rel str_hhp_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_network]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hhp_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_http_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_http_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    lea  rax, [rel str_hhp_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

%endif
    lea  rbx, [rel hook_edge_tls]
    lea  rax, [rel str_hts_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_network]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hts_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_tls_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_tls_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    lea  rax, [rel str_hts_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_netcheck]
    lea  rax, [rel str_hst_netcheck]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_network]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hst_netcheck_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_netcheck_plan]
    mov  [rbx + HE_PLAN], rax
    mov  qword [rbx + HE_POST], 0
    lea  rax, [rel netcheck_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel netcheck_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hst_netcheck_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_ntp]
    lea  rax, [rel str_hst_ntp]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_network]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hst_ntp_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_ntp_plan]
    mov  [rbx + HE_PLAN], rax
    mov  qword [rbx + HE_POST], 0
    lea  rax, [rel ntp_cmd_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel ntp_cmd_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hst_ntp_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_dns]
    lea  rax, [rel str_hst_dns]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_network]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hst_dns_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_dns_plan]
    mov  [rbx + HE_PLAN], rax
    mov  qword [rbx + HE_POST], 0
    lea  rax, [rel dns_cmd_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel dns_cmd_out_ready]
    mov  [rbx + HE_OREADY], rax
    mov  qword [rbx + HE_WITNESS], 0      ; the whole entry line
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_tcp]
    lea  rax, [rel str_hst_tcp]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_network]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hst_tcp_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_tcp_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_tcp_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel tcpdiag_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel tcpdiag_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hst_tcp_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_ssh]
    lea  rax, [rel str_hst_ssh]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_network]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hst_ssh_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_ssh_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_ssh_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel ssh_cmd_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel ssh_cmd_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hst_ssh_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_idle]
    lea  rax, [rel str_hst_idle]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_power]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hst_idle_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_idle_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_idle_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel therm_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel therm_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hst_idle_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_thermal]
    lea  rax, [rel str_hst_thermal]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_power]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hst_thermal_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_thermal_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_thermal_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    lea  rax, [rel str_hst_thermal_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_bootclock]
    lea  rax, [rel str_hbc_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hbc_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hbc_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_bootclock_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_bootclock_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    lea  rax, [rel str_hbc_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_cpucost]
    lea  rax, [rel str_hbc_cpu_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hbc_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hbc_cpu_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_cpucost_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_bootclock_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    lea  rax, [rel str_hbc_cpu_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_srvstat]
    lea  rax, [rel str_hss_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hss_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hss_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_srvstat_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_srvstat_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    lea  rax, [rel str_hss_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_pstate]
    lea  rax, [rel str_hst_pstate]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_power]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hst_pstate_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_pstate_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_pstate_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    lea  rax, [rel str_hst_pstate_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register
    ; Separate passive SMPSTAT adapter; keep native registration/authority.
    lea  rbx, [rel hook_edge_smpstat]
    lea  rax, [rel str_hsm_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hsm_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hsm_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_smpstat_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_smpstat_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0       ; entire normalized passive record
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_throttle_log]
    lea  rax, [rel str_htl_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_power]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_htl_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_throttle_log_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_throttle_log_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    lea  rax, [rel str_htl_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register
    lea  rbx, [rel hook_edge_freqmsr]
    lea  rax, [rel str_hfm_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hst_kind_power]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hfm_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_freqmsr_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_freqmsr_post]
    mov  [rbx + HE_POST], rax
    mov  qword [rbx + HE_OBUF], 0
    mov  qword [rbx + HE_OREADY], 0
    mov  qword [rbx + HE_WITNESS], 0
    mov  rdi, rbx
    call command_hook_edge_register
    pop  rbx
    ret

; hst_dec_field(RDI text, ESI max digits, RDX max value) -> EAX 1 and RCX = the
;   byte after the digits when RDI starts with 1..ESI decimal digits whose
;   value is at most RDX; else EAX 0. clobbers: RAX, RCX, R8, R9
hst_dec_field:
    xor  ecx, ecx
    xor  r8d, r8d
.d:
    movzx eax, byte [rdi + rcx]
    sub  eax, '0'
    jb   .end
    cmp  eax, 9
    ja   .end
    cmp  ecx, esi
    jae  .no
    imul r8, r8, 10
    add  r8, rax
    inc  ecx
    jmp  .d
.end:
    test ecx, ecx
    jz   .no
    cmp  r8, rdx
    ja   .no
    lea  rcx, [rdi + rcx]
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hst_ntp_server(RDI) -> EAX 1 when RDI is exactly "a.b.c.d" or "a.b.c.d:port"
;   (octets 0..255, 1..3 digits; port 1..65535, 1..5 digits). clobbers: caller-saved
hst_ntp_server:
    push rbx
    mov  ebx, 4                           ; octets left
.octet:
    mov  esi, HST_OCTET_DIGITS
    mov  edx, 255
    call hst_dec_field
    test eax, eax
    jz   .no
    mov  rdi, rcx
    dec  ebx
    jz   .tail
    cmp  byte [rdi], '.'
    jne  .no
    inc  rdi
    jmp  .octet
.tail:
    cmp  byte [rdi], 0
    je   .yes
    cmp  byte [rdi], ':'
    jne  .no
    inc  rdi
    mov  esi, HST_PORT_DIGITS
    mov  edx, 65535
    call hst_dec_field
    test eax, eax
    jz   .no
    cmp  r8, 0
    je   .no                              ; port 0 is no port
    cmp  byte [rcx], 0
    jne  .no
.yes:
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; hst_dns_name(RDI) -> EAX 1 when RDI is 1..HST_DNS_NAME_MAX of [A-Za-z0-9.-]
;   and starts with a letter or digit. clobbers: RAX, RCX, RDX
hst_dns_name:
    xor  ecx, ecx
.c:
    movzx eax, byte [rdi + rcx]
    test eax, eax
    jz   .end
    cmp  ecx, HST_DNS_NAME_MAX
    jae  .no
    mov  edx, eax
    or   edx, 0x20                        ; fold letters to lower case
    cmp  edx, 'a'
    jb   .not_alpha
    cmp  edx, 'z'
    jbe  .ok
.not_alpha:
    cmp  eax, '0'
    jb   .punct
    cmp  eax, '9'
    jbe  .ok
.punct:
    test ecx, ecx
    jz   .no                              ; the first byte is a letter or digit
    cmp  eax, '.'
    je   .ok
    cmp  eax, '-'
    jne  .no
.ok:
    inc  ecx
    jmp  .c
.end:
    test ecx, ecx
    jz   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hst_get_one(EDI op, RSI inst, RDX rest) -> EAX 1 = GET with no instance and no
;   argument; 0 = not GET (EDX HOOK_PLAN_NA) or malformed (EDX HOOK_PLAN_BADARG).
hst_get_one:
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    mov  eax, 1
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; netcheck edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET netcheck                  NETCHECK
;   GET netcheck:<key>            CARDSTAT <key> (native proposer/local OWNER scope)
;   CANCEL netcheck:<key>         CARDCANCEL <key> (same scope, no confirmation)
;   SET netcheck propose <key>    CARDPROPOSE <key> NETCFG 1 none none -- DHCP ONCE <key>
; The adapter chooses no principal/capability and performs no network effect.
; The native card observes no_lease at proposal and again at local confirmation.
; ---------------------------------------------------------------------------
hook_netcheck_plan:
    push rbx
    push r12
    sub  rsp, 8
    ; BSP command serialization: every plan restores the health producer before
    ; selecting a keyed card reply. OBSERVE must hash the current producer,
    ; never a prior health line or a previous card's state.
    lea  rax, [rel netcheck_out_buf]
    mov  [rel hook_edge_netcheck + HE_OBUF], rax
    lea  rax, [rel netcheck_out_ready]
    mov  [rel hook_edge_netcheck + HE_OREADY], rax
    lea  rax, [rel str_hst_netcheck_witness]
    mov  [rel hook_edge_netcheck + HE_WITNESS], rax
    cmp  edi, HOP_SET
    je   .propose
    cmp  edi, HOP_CANCEL
    je   .card
    cmp  edi, HOP_GET
    jne  .health
    cmp  byte [rsi], 0
    jne  .card
.health:
    call hst_get_one
    test eax, eax
    jz   .out
    call command_hook_arg_reset           ; NETCHECK takes no argument
    lea  rax, [rel str_hst_verb_netcheck]
    jmp  .out
.card:
    cmp  byte [rsi], 0
    je   .health                         ; unkeyed CANCEL keeps its native NA reply
    mov  r12d, edi
    cmp  byte [rdx], 0
    jne  .bad
    mov  rbx, rsi
    call .key16
    test eax, eax
    jz   .bad
    call command_hook_arg_reset
    mov  rdi, rbx
    call command_hook_arg_str
    lea  rax, [rel card_out_buf]
    mov  [rel hook_edge_netcheck + HE_OBUF], rax
    lea  rax, [rel card_out_ready]
    mov  [rel hook_edge_netcheck + HE_OREADY], rax
    lea  rax, [rel str_hst_card_witness]
    mov  [rel hook_edge_netcheck + HE_WITNESS], rax
    cmp  r12d, HOP_CANCEL
    je   .cancel
    lea  rax, [rel str_hst_verb_cardstat]
    jmp  .out
.cancel:
    lea  rax, [rel str_hst_verb_cardcancel]
    jmp  .out
.propose:
    cmp  byte [rsi], 0
    jne  .bad
    mov  rdi, rdx
    lea  rsi, [rel str_hst_word_propose]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    mov  rbx, rax
    call .key16
    test eax, eax
    jz   .bad
    call command_hook_arg_reset
    mov  rdi, rbx
    call command_hook_arg_str
    lea  rdi, [rel str_hst_card_dhcp]
    call command_hook_arg_str
    mov  rdi, rbx
    call command_hook_arg_str
    lea  rax, [rel str_hst_verb_cardpropose]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret
.key16:
    xor  ecx, ecx
.key:
    mov  al, [rbx + rcx]
    cmp  al, '0'
    jb   .not_key
    cmp  al, '9'
    jbe  .digit
    cmp  al, 'a'
    jb   .not_key
    cmp  al, 'f'
    ja   .not_key
.digit:
    inc  ecx
    cmp  ecx, 16
    jb   .key
    cmp  byte [rbx + 16], 0
    jne  .not_key
    mov  eax, 1
    ret
.not_key:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; tcp edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET tcp                       TCPSTAT
; ---------------------------------------------------------------------------
HTC_REPLY_MAX equ 640                  ; native tcpdiag_out_buf capacity
hook_tcp_plan:
    ; Command owner serialization: discard any previous direct/typed stage
    ; before native authority dispatch. No native nonce exists for TCPSTAT.
    push rdi
    push rsi
    push rdx
    call htc_retire
    pop  rdx
    pop  rsi
    pop  rdi
    call hst_get_one
    test eax, eax
    jz   .out
    call command_hook_arg_reset
    mov  byte [rel htc_pending], 1
    lea  rax, [rel str_hst_verb_tcpstat]
.out:
    ret

; Preserve native refusals. Successful GET/OBSERVE needs a current complete
; ordered receipt, including the native producer's end cursor and ready byte.
; No inferred network health or cross-field counter relation is introduced:
; the native lock-busy snapshot deliberately omits transient table counts.
hook_tcp_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel htc_pending], 1
    jne  .bad
    cmp  qword [rbx + RSP_ACCEPTED], 1
    jne  .bad
    cmp  byte [rel tcpdiag_out_ready], 1
    jne  .bad
    lea  rdi, [rel tcpdiag_out_buf]
    xor  r12d, r12d
.length:
    cmp  r12d, HTC_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + r12], 0
    je   .bounded
    inc  r12d
    jmp  .length
.bounded:
    lea  rax, [rdi + r12]
    cmp  rax, [rel tcpdiag_out_cur]
    jne  .bad
    call htc_record
    test eax, eax
    jz   .bad
    call command_hook_out_reset
    lea  rdi, [rel tcpdiag_out_buf]
    mov  esi, r12d
    call command_hook_out_strn
    jmp  .retire
.bad:
    call command_hook_out_reset
    lea  rdi, [rel htc_bad_reply]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel htc_bad_reply]
    mov  [rbx + RSP_HINT], rax
.retire:
    call htc_retire
    mov  eax, 1
    jmp  .out
.refused:
    call htc_retire
    xor  eax, eax                       ; original native code/hint retained
.out:
    pop  r12
    pop  rbx
    ret

htc_retire:
    mov  byte [rel htc_pending], 0
    mov  byte [rel tcpdiag_out_ready], 0
    mov  qword [rel tcpdiag_out_cur], 0
    lea  rdi, [rel tcpdiag_out_buf]
    xor  eax, eax
    mov  ecx, HTC_REPLY_MAX
    rep stosb                         ; retire the complete native staging
    ret

; Only called on a bounded NUL-terminated native receipt. Each key is exact
; and each natural u64 consumes the complete canonical decimal token.
htc_record:
    push rbx
    lea  rbx, [rel htc_keys]
.field:
    mov  rsi, rbx
    call hst_thermal_literal
    test eax, eax
    jz   .out
    lea  rbx, [rsi + 1]
    call htc_decimal
    test eax, eax
    jz   .out
    cmp  byte [rbx], 0
    jne  .field
    call htc_realtek_tail
.out:
    pop  rbx
    ret

; Legacy receipts end after syn_reaps. Current native receipts carry ordered
; five-u64 rearm tuples and, if a family did not fit, its exact omitted mask.
; A driven family's tuple carries its diagnostic record instead: exactly 25
; (r25lr) or 15 (r26lr, r68lr) u64 values; any other count refuses (ROOT120117).
; This read-only suffix never enters the six-field table-state witness.
htc_realtek_tail:
    cmp byte [rdi], 0
    je .yes
    push rbx
    push r12
    push r13
    xor r12d, r12d                     ; present-family mask
    mov r13d, 1
    lea rbx, [rel htc_realtek_keys]
.family:
    mov r9, rdi                       ; literal failure may consume a prefix
    mov rsi, rbx
    call hst_thermal_literal
    test eax, eax
    jz .absent
    or r12d, r13d
    xor r10d, r10d                    ; values consumed in this tuple
.value:
    call htc_decimal
    test eax, eax
    jz .bad
    inc r10d
    cmp byte [rdi], ','
    jne .tuple_end
    cmp r10d, 25
    jae .bad
    inc rdi
    jmp .value
.tuple_end:
    cmp r10d, 5
    je .next
    lea rax, [rel htc_realtek_record]
    movzx eax, byte [rax + r13 - 1]
    cmp r10d, eax
    jne .bad
    jmp .next
.absent:
    mov rdi, r9
.next:
    ; Advance the fixed label independently of a failed literal match.
    cmp byte [rbx], 0
    lea rbx, [rbx+1]
    jne .next
    shl r13d, 1
    cmp r13d, 8
    jb .family
    cmp r12d, 7
    je .end                           ; all families present: no omission
    lea rsi, [rel htc_realtek_omitted]
    call hst_thermal_literal
    test eax, eax
    jz .bad
    movzx eax, byte [rdi]
    sub eax, '0'
    mov ecx, r12d
    xor ecx, 7                        ; precisely the absent families
    cmp eax, ecx
    jne .bad
    inc rdi                           ; mask is exactly one digit, 1..7
.end:
    cmp byte [rdi], 0
    jne .bad
    mov eax, 1
    jmp .done
.bad:
    xor eax, eax
.done:
    pop r13
    pop r12
    pop rbx
    ret
.yes:
    mov eax, 1
    ret

htc_realtek_keys:
    db " r25lr=", 0
    db " r26lr=", 0
    db " r68lr=", 0
htc_realtek_omitted: db " lr_omitted=", 0
htc_realtek_record: db 25, 15, 0, 15  ; tuple length with the record, by family bit

; UINT64_MAX is valid; overflow, signs and leading zeros refuse.
htc_decimal:
    xor  edx, edx
    cmp  byte [rdi], '0'
    jne  .digits
    inc  rdi
    mov  eax, 1
    ret
.digits:
    xor  ecx, ecx
    mov  r8, 1844674407370955161
.next:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .end
    cmp  rdx, r8
    ja   .no
    jne  .accumulate
    cmp  eax, 5
    ja   .no
.accumulate:
    imul rdx, rdx, 10
    add  rdx, rax
    inc  rdi
    inc  ecx
    jmp  .next
.end:
    xor  eax, eax
    test ecx, ecx
    setnz al
    ret
.no:
    xor  eax, eax
    ret

htc_pending: db 0
htc_bad_reply: db " hook err=tcp_reply_incomplete", 0
htc_keys:
    db " TCPSTAT rev=", 0
    db " listeners=", 0
    db " used=", 0
    db " max=", 0
    db " syn=", 0
    db " est=", 0
    db " closing=", 0
    db " timewait=", 0
    db " accepts=", 0
    db " rx=", 0
    db " tx=", 0
    db " retrans=", 0
    db " reaped=", 0
    db " full_rsts=", 0
    db " rsts=", 0
    db " closes=", 0
    db " lock_busy=", 0
    db " last_stage=", 0
    db " syn_reaps=", 0
    db 0

; ---------------------------------------------------------------------------
; ssh edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET ssh                       SSHSTAT
;   LIST ssh                      SSHKEYLIST
; ---------------------------------------------------------------------------
hook_ssh_plan:
    push rdi
    push rsi
    push rdx
    call ssr_retire
    pop  rdx
    pop  rsi
    pop  rdi
    cmp  edi, HOP_GET
    je   .one
    cmp  edi, HOP_LIST
    je   .one
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.one:
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    push rdi
    call command_hook_arg_reset
    pop  rdi
    mov  [rel ssr_pending], dil
    lea  rax, [rel str_hst_verb_sshstat]
    cmp  edi, HOP_GET
    je   .out
    lea  rax, [rel str_hst_verb_sshkeylist]
.out:
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

; RCQ-15 SSH reads: only complete native SSHSTAT/SSHKEYLIST publications enter
; typed output. The native registry/auth floor and original witness stay intact.
; Native text builder cursor is private/shared with audit, not an exported hook
; receipt. Consume only the exported768B reply/ready under BSP serialization.
; Local pending is a single dispatch lifetime, never caller authority.
hook_ssh_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .native_refused
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rcx
    cmp  byte [rel ssr_pending], 0
    je   .bad_reply
    cmp  byte [rel ssh_cmd_out_ready], 1
    jne  .bad_reply
    lea  rdi, [rel ssh_cmd_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, SSH_CMD_OUT_CAP
    jae  .bad_reply
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    mov  r12d, ecx
    call ssr_record
    test eax, eax
    jz   .bad_reply
    call command_hook_out_reset
    lea  rdi, [rel ssh_cmd_out_buf]
    mov  esi, r12d
    call command_hook_out_strn            ; native768 < existing typed1024
    jmp  .retire
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_ssr_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_ssr_bad]
    mov  [rbx + RSP_HINT], rax
.retire:
    call ssr_retire
    add  rsp, 8
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.native_refused:
    sub  rsp, 8
    call ssr_retire
    add  rsp, 8
    xor  eax, eax                         ; preserve native code/hint
    ret

ssr_retire:
    mov  byte [rel ssr_pending], 0
    mov  byte [rel ssh_cmd_out_ready], 0
    lea  rdi, [rel ssh_cmd_out_buf]
    xor  eax, eax
    mov  ecx, SSH_CMD_OUT_CAP
    rep  stosb
    ret

%macro SSR_LITERAL 1
    lea  rsi, [rel %1]
    call hst_thermal_literal
    test eax, eax
    jz   .no
%endmacro
%macro SSR_NUMBER 1
    SSR_LITERAL %1
    call hst_ss_u64                       ; canonical full-width unsigned decimal
    test eax, eax
    jz   .no
%endmacro
ssr_record:
    push r12
    push r13
    push r14
    cmp  byte [rel ssr_pending], HOP_GET
    jne  .list
    SSR_LITERAL str_ssr_stat
    lea  rsi, [rel str_ssr_sources]
    call ssr_name
    test eax, eax
    jz   .no
    SSR_NUMBER str_ssr_principal
    SSR_NUMBER str_ssr_ok
    SSR_NUMBER str_ssr_fail
    SSR_NUMBER str_ssr_streak
    SSR_NUMBER str_ssr_lockouts
    SSR_NUMBER str_ssr_lockout_ms
    SSR_NUMBER str_ssr_exec
    SSR_NUMBER str_ssr_refused
    SSR_NUMBER str_ssr_writes
    SSR_NUMBER str_ssr_keys
    cmp  r8, 4
    ja   .no
    call ssr_store
    test eax, eax
    jz   .no
    jmp  .end
.list:
    cmp  byte [rel ssr_pending], HOP_LIST
    jne  .no
    SSR_NUMBER str_ssr_list
    cmp  r8, 4
    ja   .no
    mov  r12d, r8d                        ; declared key count
    call ssr_store
    test eax, eax
    jz   .no
    xor  r13d, r13d                       ; exact number of rendered rows
    mov  r14d, -1                         ; native slot order, gaps allowed
.row:
    cmp  byte [rdi], 0
    je   .rows_done
    SSR_NUMBER str_ssr_slot
    cmp  r8, 3
    ja   .no
    cmp  r14d, -1
    je   .first
    cmp  r8d, r14d
    jbe  .no
.first:
    mov  r14d, r8d
    SSR_LITERAL str_ssr_fingerprint
    mov  ecx, 43
.fp:
    call ssr_b64_value
    test eax, eax
    js   .no
    inc  rdi
    dec  ecx
    jnz  .fp
    test eax, 3                           ;32-byte SHA256: two canonical pad bits
    jnz  .no
    SSR_LITERAL str_ssr_caps
    mov  ecx, 16
.hex:
    movzx eax, byte [rdi]
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .hex_char
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
.hex_char:
    inc  rdi
    loop .hex
    inc  r13d
    cmp  r13d, 4
    ja   .no
    jmp  .row
.rows_done:
    cmp  r13d, r12d
    jne  .no
.end:
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    ret
ssr_store:
    lea  rsi, [rel str_ssr_store]
    call hst_thermal_literal
    test eax, eax
    jz   .out
    lea  rsi, [rel str_ssr_stores]
    jmp  ssr_name
.out:
    ret
; NUL-separated exact enum spellings. Restore input cursor after each mismatch;
; admit only a space or NUL after the selected name, never a prefix/extension.
ssr_name:
    mov  r10, rdi
.next:
    mov  rdi, r10
    call hst_thermal_literal
    test eax, eax
    jz   .skip
    cmp  byte [rdi], 0
    je   .yes
    cmp  byte [rdi], ' '
    je   .yes
.skip:
    cmp  byte [rsi], 0
    je   .advance
    inc  rsi
    jmp  .skip
.advance:
    inc  rsi
    cmp  byte [rsi], 0
    jne  .next
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret
ssr_b64_value:
    movzx eax, byte [rdi]
    cmp  al, 'A'
    jb   .digit
    cmp  al, 'Z'
    ja   .lower
    sub  eax, 'A'
    ret
.lower:
    cmp  al, 'a'
    jb   .no
    cmp  al, 'z'
    ja   .no
    sub  eax, 'a'-26
    ret
.digit:
    cmp  al, '+'
    je   .plus
    cmp  al, '/'
    je   .slash
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    ja   .no
    add  eax, 52-'0'
    ret
.plus:
    mov  eax, 62
    ret
.slash:
    mov  eax, 63
    ret
.no:
    mov  eax, -1
    ret
ssr_pending: db 0
str_ssr_bad: db " hook err=ssh_reply_incomplete",0
str_ssr_stat: db "SSHSTAT source=",0
str_ssr_sources: db "internal",0,"udp",0,"serial",0,"aihook",0,"console",0,"ssh",0,"other",0,0
str_ssr_principal: db " principal=",0
str_ssr_ok: db " auth_ok=",0
str_ssr_fail: db " auth_fail=",0
str_ssr_streak: db " streak=",0
str_ssr_lockouts: db " lockouts=",0
str_ssr_lockout_ms: db " lockout_ms=",0
str_ssr_exec: db " exec=",0
str_ssr_refused: db " exec_refused=",0
str_ssr_writes: db " key_nvram_writes=",0
str_ssr_keys: db " keys=",0
str_ssr_store: db " store=",0
str_ssr_stores: db "unavailable",0,"ram",0,"nvram",0,"poisoned",0,0
str_ssr_list: db "SSHKEYLIST keys=",0
str_ssr_slot: db " k",0
str_ssr_fingerprint: db "=SHA256:",0
str_ssr_caps: db " caps=",0

; ---------------------------------------------------------------------------
; ntp edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET ntp                       NTPSTAT
;   SET ntp sync <a.b.c.d[:port]> NTPSYNC <a.b.c.d[:port]>
; ---------------------------------------------------------------------------
hook_ntp_plan:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdx
    cmp  byte [rsi], 0
    jne  .bad                             ; one instance: this node's clock
    cmp  edi, HOP_GET
    je   .stat
    cmp  edi, HOP_SET
    je   .sync
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.stat:
    cmp  byte [r12], 0
    jne  .bad
    call command_hook_arg_reset
    lea  rax, [rel str_hst_verb_ntpstat]
    jmp  .out
.sync:
    mov  rdi, r12
    lea  rsi, [rel str_hst_word_sync]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    mov  rbx, rax                         ; the server
    mov  rdi, rax
    call hst_ntp_server
    test eax, eax
    jz   .bad
    call command_hook_arg_reset
    mov  rdi, rbx
    call command_hook_arg_str
    lea  rax, [rel str_hst_verb_ntpsync]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; dns edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET dns:<name>                DNSCACHE <name>
;   SET dns:<name> resolve        RESOLVE <name>
; ---------------------------------------------------------------------------
hook_dns_plan:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    cmp  ebx, HOP_GET
    je   .name
    cmp  ebx, HOP_SET
    je   .name
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.name:
    mov  rdi, r12
    call hst_dns_name
    test eax, eax
    jz   .bad
    cmp  ebx, HOP_SET
    je   .resolve
    cmp  byte [r13], 0
    jne  .bad
    lea  rbx, [rel str_hst_verb_dnscache]
    jmp  .plan
.resolve:
    mov  rdi, r13
    lea  rsi, [rel str_hst_word_resolve]
    call command_hook_word_eq
    test eax, eax
    jz   .bad
    lea  rbx, [rel str_hst_verb_resolve]
.plan:
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    mov  rax, rbx
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; idle edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET idle[:cpu] [depth]        IDLEDEPTH              (passive cached report)
;   SET idle <state>              IDLEDEPTH <STATE>      (HLT C1E C6 C8 C10 C2 C3)
; ---------------------------------------------------------------------------
hook_idle_plan:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rdx
    cmp  ebx, HOP_GET
    je   .get
    cmp  ebx, HOP_SET
    je   .set
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.get:
    mov  rdi, rsi
    call hst_idle_cpu
    test edx, edx
    jz   .bad
    call command_hook_arg_reset           ; passive IDLEDEPTH report only
    cmp  byte [r12], 0
    je   .get_ready
    mov  rdi, r12
    lea  rsi, [rel str_hst_word_depth]
    call command_hook_word_eq
    test eax, eax
    jz   .bad
.get_ready:
    mov  byte [rel therm_out_ready], 0
    lea  rax, [rel str_hst_verb_idledepth] ; passive native owner admission
    jmp  .out
.set:
    cmp  byte [rsi], 0
    jne  .bad                             ; SET remains boot-wide
    lea  r13, [rel str_hst_idle_states]
.state:
    cmp  byte [r13], 0
    je   .bad
    mov  rdi, r12
    mov  rsi, r13
    call command_hook_word_eq
    test eax, eax
    jnz  .state_hit
.state_next:
    inc  r13
    cmp  byte [r13 - 1], 0
    jne  .state_next
    jmp  .state
.state_hit:
    call command_hook_arg_reset
    mov  rdi, r13                         ; the native's own (upper-case) spelling
    call command_hook_arg_str
    lea  rax, [rel str_hst_verb_idledepth]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Decimal dense CPU instance, at most two digits and strictly below capacity.
; Empty instance is the boot summary. No trailing characters or signed indices.
; RDI cstr -> EAX CPU/-1, EDX accepted. No state is changed.
hst_idle_cpu:
    cmp  byte [rdi], 0
    je   .summary
    push rdi
    call command_hook_parse_dec
    pop  rdi
    test edx, edx
    jz   .bad
    cmp  edx, 2
    ja   .bad
    cmp  byte [rdi + rdx], 0
    jne  .bad
    cmp  rax, MAXCORE
    jae  .bad
    mov  edx, 1
    ret
.summary:
    mov  eax, -1
    mov  edx, 1
    ret
.bad:
    xor  edx, edx
    ret

; GET/OBSERVE: native IDLEDEPTH with empty argument admits the unchanged caller
; and reports only cached state. SET still uses its original native staging and
; owner checks. Additional owner-envelope gate follows the typed power convention.
; BSP serialization owns snapshot/render lifetime. Never call an active probe.
hook_idle_post:
    cmp  edi, HOP_GET
    jne  .none
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .none                            ; native refusal remains authoritative
    push rbx
    push r12
    push r13
    mov  rbx, rcx
    mov  r13, rsi
    mov  byte [rel therm_out_ready], 0     ; consume only GET staging
    call command_auth_owner_envelope
    test eax, eax
    jz   .denied
    mov  rdi, r13
    call hst_idle_cpu                     ; grammar already validated by planner
    mov  esi, eax
    sub  rsp, IDO_SZ
    mov  r12, rsp
    mov  rdi, r12
    call idle_observation_snapshot
    call command_hook_out_reset
    lea  rdi, [rel str_hst_idle_head]
    call command_hook_out_str
    mov  eax, [r12 + IDO_STATE]
    mov  ecx, 7
    lea  rsi, [rel hst_idle_states]
    call hst_idle_enum
    lea  rdi, [rel str_hst_idle_hint]
    call command_hook_out_str
    mov  edi, [r12 + IDO_HINT]
    cmp  edi, -1
    jne  .hint_number
    lea  rdi, [rel str_hst_idle_hlt]
    call command_hook_out_str
    jmp  .reason
.hint_number:
    call command_hook_out_dec
.reason:
    lea  rdi, [rel str_hst_idle_reason]
    call command_hook_out_str
    mov  eax, [r12 + IDO_REASON]
    mov  ecx, 9
    lea  rsi, [rel hst_idle_reasons]
    call hst_idle_enum
    lea  rdi, [rel str_hst_idle_row]
    call command_hook_out_str
    mov  edi, [r12 + IDO_ROW]
    call command_hook_out_dec
    lea  rdi, [rel str_hst_idle_probe]
    call command_hook_out_str
    mov  eax, [r12 + IDO_PROBE]
    mov  ecx, 3
    lea  rsi, [rel hst_idle_probes]
    call hst_idle_enum
    lea  rdi, [rel str_hst_idle_topology]
    call command_hook_out_str
    lea  rdi, [rel str_hst_idle_unknown]
    cmp  dword [r12 + IDO_TOPO], 1
    jne  .topology_name
    lea  rdi, [rel str_hst_idle_valid]
.topology_name:
    call command_hook_out_str
    lea  rdi, [rel str_hst_idle_ncpu]
    call command_hook_out_str
    cmp  dword [r12 + IDO_TOPO], 1
    jne  .ncpu_unknown
    mov  edi, [r12 + IDO_NCPU]
    call command_hook_out_dec
    jmp  .mask
.ncpu_unknown:
    lea  rdi, [rel str_hst_idle_unknown]
    call command_hook_out_str
.mask:
    lea  rdi, [rel str_hst_idle_mask]
    call command_hook_out_str
    cmp  dword [r12 + IDO_TOPO], 1
    jne  .mask_unknown
    mov  rdi, [r12 + IDO_MASK]
    call command_hook_out_dec
    jmp  .cpu
.mask_unknown:
    lea  rdi, [rel str_hst_idle_unknown]
    call command_hook_out_str
.cpu:
    lea  rdi, [rel str_hst_idle_cpu]
    call command_hook_out_str
    mov  edi, [r12 + IDO_CPU]
    cmp  edi, -1
    jne  .cpu_number
    lea  rdi, [rel str_hst_idle_none]
    call command_hook_out_str
    jmp  .online
.cpu_number:
    call command_hook_out_dec
.online:
    lea  rdi, [rel str_hst_idle_online]
    call command_hook_out_str
    cmp  dword [r12 + IDO_TOPO], 1
    jne  .online_unknown
    cmp  dword [r12 + IDO_CPU], -1
    je   .online_unknown
    mov  edi, [r12 + IDO_LIVE]
    call command_hook_out_dec
    jmp  .check
.online_unknown:
    lea  rdi, [rel str_hst_idle_unknown]
    call command_hook_out_str
.check:
    lea  rdi, [rel str_hst_idle_check]
    call command_hook_out_str
    mov  eax, [r12 + IDO_CHECK]
    cmp  dword [r12 + IDO_LIVE], 1
    je   .check_name
    mov  eax, -1
.check_name:
    mov  ecx, 4
    lea  rsi, [rel hst_idle_checks]
    call hst_idle_enum
    lea  rdi, [rel str_hst_idle_halts]
    call command_hook_out_str
    cmp  dword [r12 + IDO_LIVE], 1
    jne  .halts_unknown
    mov  rdi, [r12 + IDO_HALTS]
    call command_hook_out_dec
    jmp  .deep
.halts_unknown:
    lea  rdi, [rel str_hst_idle_unknown]
    call command_hook_out_str
.deep:
    lea  rdi, [rel str_hst_idle_deep]
    call command_hook_out_str
    cmp  dword [r12 + IDO_LIVE], 1
    jne  .deep_unknown
    mov  rdi, [r12 + IDO_DEEP]
    call command_hook_out_dec
    jmp  .clear
.deep_unknown:
    lea  rdi, [rel str_hst_idle_unknown]
    call command_hook_out_str
.clear:
    mov  rdi, r12
    xor  eax, eax
    mov  ecx, IDO_SZ / 8
    rep  stosq
    add  rsp, IDO_SZ
    jmp  .staged
.denied:
    call command_hook_out_reset
    lea  rdi, [rel str_hst_idle_denied]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_AUTHDENY
    lea  rax, [rel str_hst_idle_denied]
    mov  [rbx + RSP_HINT], rax
.staged:
    pop  r13
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

; Fixed 16-byte enum slots; invalid cached values are explicitly unknown.
hst_idle_enum:
    lea  rdi, [rel str_hst_idle_unknown]
    cmp  eax, ecx
    jae  .out
    shl  eax, 4
    lea  rdi, [rsi + rax]
.out:
    jmp  command_hook_out_str

; ---------------------------------------------------------------------------
; thermal: a single read-only native THERM observation (OBSERVE plans as GET).
; Clear old staging only after static grammar accepts, before native dispatch.
; This touches no sensor; THERM's normal session/capability gate runs next.
hook_thermal_plan:
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    mov  byte [rel therm_out_ready], 0
    mov  byte [rel therm_out_buf], 0
    lea  rax, [rel str_hst_verb_therm]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

HST_THERM_REPLY_MAX equ 256              ; actual therm_out_buf capacity
hook_thermal_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .native_refused
    push rbx
    push r12
    mov  rbx, rcx
    cmp  byte [rel therm_out_ready], 1
    jne  .bad_reply
    lea  rdi, [rel therm_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HST_THERM_REPLY_MAX
    jae  .bad_reply
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    mov  r12d, ecx
    call hst_thermal_record
    test eax, eax
    jz   .bad_reply
    call command_hook_out_reset
    lea  rdi, [rel str_hst_thermal_head]
    call command_hook_out_str
    lea  rdi, [rel therm_out_buf]
    mov  esi, r12d
    call command_hook_out_strn
    jmp  .retire
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_hst_thermal_bad_reply]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    lea  rax, [rel str_hst_thermal_bad_reply]
    mov  [rbx + RSP_HINT], rax
.retire:
    mov  byte [rel therm_out_ready], 0
    mov  byte [rel therm_out_buf], 0
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.native_refused:
    mov  byte [rel therm_out_ready], 0
    mov  byte [rel therm_out_buf], 0
    xor  eax, eax                        ; original code/hint stay authoritative
    ret

; hst_thermal_record(RDI bounded NUL-terminated native reply) -> EAX 1/0.
; Exact native grammar, no missing/duplicate/extra fields or partial tokens.
; Numeric fields are native u32 decimals, not a guessed physical range. Native
; unavailable may have degraded=0 (a supported source has no plausible reading).
; Must only be called after a NUL was found within the native capacity above.
hst_thermal_record:
    push rbx
    xor  ebx, ebx                        ; 1 = native unavailable
    lea  rsi, [rel str_hst_th_tempc]
    call hst_thermal_literal
    test eax, eax
    jz   .out
    cmp  byte [rdi], 'u'
    je   .unavailable
    call hst_thermal_u32
    test eax, eax
    jz   .out
    jmp  .tj
.unavailable:
    lea  rsi, [rel str_hst_th_unavailable]
    call hst_thermal_literal
    test eax, eax
    jz   .out
    mov  ebx, 1
.tj:
    lea  rsi, [rel str_hst_th_tjmax]
    call hst_thermal_literal
    test eax, eax
    jz   .out
    call hst_thermal_u32
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hst_th_degraded]
    call hst_thermal_literal
    test eax, eax
    jz   .out
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 1
    ja   .no
    test eax, eax
    jz   .source
    test ebx, ebx
    jz   .no                             ; native degraded=1 never has a number
.source:
    inc  rdi
    lea  rsi, [rel str_hst_th_source]
    call hst_thermal_literal
    test eax, eax
    jz   .out
    cmp  byte [rdi], 'd'
    je   .dts
    cmp  byte [rdi], 'a'
    je   .amd
    test ebx, ebx
    jz   .no                             ; no native source never has a number
    lea  rsi, [rel str_hst_th_none]
    jmp  .last
.dts:
    lea  rsi, [rel str_hst_th_dts]
    jmp  .last
.amd:
    lea  rsi, [rel str_hst_th_amd]
.last:
    call hst_thermal_literal
    test eax, eax
    jz   .out
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Bytewise exact prefix, stops before reading past an input NUL.
; RDI advances only over matched bytes; EAX 1/0. No speculative word reads.
hst_thermal_literal:
    mov  al, [rsi]
    test al, al
    jz   .yes
    cmp  al, [rdi]
    jne  .no
    inc  rsi
    inc  rdi
    jmp  hst_thermal_literal
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

hst_thermal_u32:
    mov  esi, 10
    mov  edx, 0xffffffff
    call hst_dec_field
    test eax, eax
    jz   .out
    mov  rdi, rcx
.out:
    ret

; BOOTCLOCK: singleton read-only checked native boot timing observation.
; Only software staging is retired before normal native authority dispatch.
; Singleton compact view; the common planner retires every prior projection.
; Only a valid GET plan can select this software projection for its dispatch.
hook_cpucost_plan:
    call hook_bootclock_plan
    test rax, rax
    jz   .out
    mov  byte [rel hbc_cpu_projection], 1
.out:
    ret

hook_bootclock_plan:
    push rbx
    mov  ebx, edi
    push rsi
    push rdx
    call boot_clock_reply_retire
    lea  rdi, [rel hbc_pending]
    xor  eax, eax
    mov  ecx, 1 + 8 + 17 + 1
    rep stosb
    pop  rdx
    pop  rsi
    cmp  ebx, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    mov  rdi, [rel bc_reply_generation]
    cmp  rdi, -1
    je   .bad
    inc  rdi
    mov  [rel hbc_generation], rdi
    lea  rsi, [rel hbc_nonce]
    mov  edx, 16
    call fmt_hex
    call command_hook_arg_reset
    lea  rdi, [rel hbc_nonce]
    call command_hook_arg_str
    mov  byte [rel hbc_pending], 1
    mov  byte [rel command_auth_out_ready], 0
    mov  byte [rel command_auth_out_buf], 0
    lea  rax, [rel str_hbc_verb]
    pop  rbx
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    pop  rbx
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    pop  rbx
    ret

HST_BC_REPLY_MAX equ 1280                 ; actual AUTH_OUT_MAX shared staging
HST_BC_NATIVE_HEAD equ 36                 ; 20-byte head + 16-byte fresh nonce
HST_BC_CPU_TYPED_HEAD equ 12              ; " cpucost v=1"
HST_BC_TYPED_HEAD equ 14                  ; " bootclock v=6"
HST_BC_COMPLETE_BYTES equ 12              ; " truncated=0"
; Validate custody and complete grammar before copying any state or witnessing.
; A registry denial has no producer and preserves its original refusal text.
hook_bootclock_post:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rcx
    cmp  byte [rel hbc_pending], 1
    jne  .bad_reply
    cmp  byte [rel bc_reply_valid], 1
    jne  .no_producer
    mov  rax, [rel hbc_generation]
    cmp  rax, [rel bc_reply_generation]
    jne  .bad_reply
    lea  rdi, [rel bc_reply_req]
    call command_hook_request_matches
    test eax, eax
    jz   .bad_reply
    lea  rsi, [rel hbc_nonce]
    lea  rdi, [rel bc_reply_arg]
    mov  ecx, 17
    repe cmpsb
    jne  .bad_reply
    lea  rsi, [rel paos_build_hex]
    lea  rdi, [rel bc_reply_build]
    mov  ecx, 64
    repe cmpsb
    jne  .bad_reply
    mov  eax, [rel boot_nonce]
    cmp  eax, [rel bc_reply_boot]
    jne  .bad_reply
    mov  rsi, rbx
    lea  rdi, [rel bc_reply_rsp]
    mov  ecx, RSP_SZ
    repe cmpsb
    jne  .bad_reply
    cmp  byte [rel command_auth_out_ready], 1
    jne  .bad_reply
    mov  r12, [rel bc_reply_len]
    cmp  r12, HST_BC_REPLY_MAX
    jae  .bad_reply
    lea  rdi, [rel command_auth_out_buf]
    lea  rsi, [rel bc_reply_body]
    lea  rcx, [r12 + 1]
    repe cmpsb
    jne  .bad_reply
    lea  rdi, [rel command_auth_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HST_BC_REPLY_MAX
    jae  .bad_reply
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    cmp  rcx, r12
    jne  .bad_reply
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .native_refused
    call hst_bc_record
    test eax, eax
    jz   .bad_reply
    cmp  byte [rel hbc_cpu_projection], 1
    je   .cpu_projection
    ; The v7 native-only CPU costs were fully validated. Retain the exact v6
    ; typed projection/witness and its cap: prefix through DHCP + truncated=0.
    ; RDX is the validated prefix end, never an untrusted length search.
    lea  rax, [rel command_auth_out_buf]
    sub  rdx, rax
    mov  r12, rdx
    cmp  r12, HOOK_OUT_MAX - 1 + HST_BC_NATIVE_HEAD - HST_BC_TYPED_HEAD - HST_BC_COMPLETE_BYTES
    ja   .bad_reply                       ; never allow a partial typed success
    call command_hook_out_reset
    lea  rdi, [rel str_hbc_head]
    call command_hook_out_str
    lea  rdi, [rel command_auth_out_buf + HST_BC_NATIVE_HEAD]
    mov  esi, r12d
    sub  esi, HST_BC_NATIVE_HEAD
    call command_hook_out_strn
    lea  rdi, [rel str_hbc_complete]
    call command_hook_out_str
    jmp  .retire
.cpu_projection:
    ; RDX points to the validated space before ucp_cost. The complete native
    ; grammar and original custody were checked above, including both costs.
    mov  r12, rdx
    lea  rdi, [rel command_auth_out_buf]
    lea  rsi, [rel str_hbc_pixel_source]
    call hook_find
    test rax, rax
    jz   .bad_reply
    sub  rax, str_hbc_pixel_source_end - str_hbc_pixel_source - 1
    cmp  rax, r12
    jae  .bad_reply
    lea  r14, [rel command_auth_out_buf + HST_BC_NATIVE_HEAD]
    sub  rax, r14
    jc   .bad_reply
    mov  r14, rax                        ; common origin/unit/clock scalars
    lea  r15, [rel command_auth_out_buf]
    add  r15, [rel bc_reply_len]
    sub  r15, r12                        ; two costs and exact complete suffix
    jc   .bad_reply
    lea  rax, [r14 + r15 + HST_BC_CPU_TYPED_HEAD]
    cmp  rax, HOOK_OUT_MAX - 1
    ja   .bad_reply
    call command_hook_out_reset
    lea  rdi, [rel str_hbc_cpu_head]
    call command_hook_out_str
    lea  rdi, [rel command_auth_out_buf + HST_BC_NATIVE_HEAD]
    mov  rsi, r14
    call command_hook_out_strn
    mov  rdi, r12
    mov  rsi, r15
    call command_hook_out_strn
    jmp  .retire
.no_producer:
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .native_refused
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_hbc_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    lea  rax, [rel str_hbc_bad]
    mov  [rbx + RSP_HINT], rax
.retire:
    mov  byte [rel command_auth_out_ready], 0
    mov  byte [rel command_auth_out_buf], 0
    mov  r13d, 1
    jmp  .clear
.native_refused:
    xor  r13d, r13d                       ; preserve original native refusal
.clear:
    call boot_clock_reply_retire
    lea  rdi, [rel hbc_pending]
    xor  eax, eax
    mov  ecx, 1 + 8 + 17 + 1
    rep stosb
    mov  eax, r13d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%macro WDATA_hook_bootclock_custody 0
hbc_pending: db 0
hbc_generation: dq 0
hbc_nonce: times 17 db 0
hbc_cpu_projection: db 0
%endmacro
WDATA_DEFER WDATA_hook_bootclock_custody

; RDI has a NUL within HST_BC_REPLY_MAX (checked above). Exact native grammar,
; complete ordered fields, bounded enum/decimals, no suffix or partial triplet.
; R13 is the common snapshot reason ordinal (BC_* + 1) supplied to row validator.
; Success additionally returns RDX=end of the retained v6 prefix through DHCP.
hst_bc_record:
    push r13
    lea  rsi, [rel str_hbc_native_head]
    call hst_bc_literal
    test eax, eax
    jz   .out
    lea  rsi, [rel hbc_nonce]
    call hst_bc_literal
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_scope]
    call hst_bc_literal
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_reasons]
    call hst_bc_enum
    test eax, eax
    jz   .out
    cmp  eax, 2                          ; snapshot cannot be not-reached
    je   .no
    cmp  eax, 6                          ; snapshot cannot be future
    je   .no
    cmp  eax, 10                         ; not-required is a producer state, never a clock
    je   .no
    mov  r13d, eax
    lea  rsi, [rel str_hbc_source]
    call hst_bc_literal
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_sources]
    call hst_bc_enum
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_cal]
    call hst_bc_literal
    test eax, eax
    jz   .out
    call hst_bc_u64
    test eax, eax
    jz   .out
    cmp  r8, 255                         ; actual byte calibration reason
    ja   .no
    lea  rsi, [rel str_hbc_scale]
    call hst_bc_literal
    test eax, eax
    jz   .out
    call hst_bc_u64
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_pixel_source]
    call hst_bc_literal
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_pixels]
    call hst_bc_enum
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_now_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 1
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_boot_end_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_ebs_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_ready_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_ack_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_pixel_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_kbd_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_ptr_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_input_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_udp_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_ssh_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_terminal_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_nic_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_foundation_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_hv_cost_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_nic_cost_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_vtd_cost_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_amdvi_cost_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_airlock_cost_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_cpus_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0                          ; every discovered CPU is always required
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_storage_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 2
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_census_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_checks_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 2
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_settled_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_dhcp_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    mov  esi, 0                          ; v6 first usable lease: an ordinary milestone
    call hst_bc_row
    test eax, eax
    jz   .out
    mov  rdx, rdi                        ; retained v6 prefix end (row helpers preserve RDX)
    lea  rsi, [rel str_hbc_ucp_cost_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    xor  esi, esi
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_bsp_cost_key]
    call hst_bc_literal
    test eax, eax
    jz   .out
    xor  esi, esi
    call hst_bc_row
    test eax, eax
    jz   .out
    lea  rsi, [rel str_hbc_complete]
    call hst_bc_literal
    test eax, eax
    jz   .out
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    ret

; RDI input, RSI exact literal. Never reads past the input NUL; advances on
; matched bytes only. EAX 1/0; caller checks before consuming further input.
hst_bc_literal:
    mov  al, [rsi]
    test al, al
    jz   .yes
    cmp  al, [rdi]
    jne  .no
    inc  rsi
    inc  rdi
    jmp  hst_bc_literal
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; RDI input, RSI double-NUL enum literals -> EAX ordinal+1/0, RDI advanced on
; match. The caller must require its exact following delimiter.
hst_bc_enum:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, 1
.next:
    push rsi
    call hst_bc_literal
    pop  rsi
    test eax, eax
    jnz  .yes
    mov  rdi, rbx
.skip:
    cmp  byte [rsi], 0
    lea  rsi, [rsi + 1]
    jne  .skip
    inc  r12d
    cmp  byte [rsi], 0
    jne  .next
    xor  eax, eax
    jmp  .out
.yes:
    mov  eax, r12d
.out:
    pop  r12
    pop  rbx
    ret

; RDI decimal -> EAX 1/0, R8 full64 value and RDI after digits on success.
; Check BEFORE arithmetic: at most20 digits and no multiply/add wrap. Native
; formatting is canonical, so reject leading zeros as well as signed numbers.
hst_bc_u64:
    mov  rcx, rdi
    xor  r8d, r8d
    xor  r9d, r9d
    mov  r11, 1844674407370955161
.digit:
    movzx r10d, byte [rcx]
    sub  r10d, '0'
    jb   .end
    cmp  r10d, 9
    ja   .end
    cmp  r9d, 20
    jae  .no
    cmp  r8, r11
    ja   .no
    jb   .accumulate
    cmp  r10d, 5
    ja   .no
.accumulate:
    imul r8, r8, 10
    add  r8, r10
    inc  r9d
    inc  rcx
    jmp  .digit
.end:
    test r9d, r9d
    jz   .no
    cmp  r9d, 1
    jbe  .yes
    cmp  byte [rdi], '0'
    je   .no
.yes:
    mov  rdi, rcx
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; RDI triplet, ESI=1 only for now, ESI=2 for a v5 settled producer that may be
; 0/not-required/0 on a valid clock, else 0; R13=common reason ordinal. Refused durations
; must be0; valid0 remains distinct from not-reached. Preserve native common
; reason even for absent milestones, as boot_clock_ms_checked does.
hst_bc_row:
    push rbx
    push r12
    push r14
    mov  r12d, esi
    movzx ebx, byte [rdi]
    sub  ebx, '0'
    cmp  ebx, 1
    ja   .no
    inc  rdi
    cmp  byte [rdi], '/'
    jne  .no
    inc  rdi
    lea  rsi, [rel str_hbc_reasons]
    call hst_bc_enum
    test eax, eax
    jz   .out
    mov  r14d, eax
    cmp  byte [rdi], '/'
    jne  .no
    inc  rdi
    call hst_bc_u64
    test eax, eax
    jz   .out
    cmp  r14d, 1
    je   .valid
    test r8, r8
    jnz  .no                             ; every native refusal is duration0
.valid:
    cmp  r12d, 1
    jne  .common
    cmp  ebx, 1
    jne  .no                             ; now always has a sample
    cmp  r14d, r13d
    jne  .no
.common:
    cmp  r13d, 1
    je   .local
    cmp  r14d, r13d
    jne  .no                             ; snapshot refusal precedes presence
    jmp  .yes
.local:
    test ebx, ebx
    jnz  .present
    cmp  r14d, 2
    je   .yes
    cmp  r12d, 2
    jne  .no                             ; only storage/checks may be not-required
    cmp  r14d, 10
    jne  .no
    jmp  .yes
.present:
    cmp  r14d, 1
    je   .yes
    cmp  r14d, 5                          ; stamp before origin
    je   .yes
    cmp  r14d, 6                          ; stamp after current sample
    jne  .no
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r14
    pop  r12
    pop  rbx
    ret

str_hbc_cpu_name: db "cpucost",0
str_hbc_cpu_head: db " cpucost v=1",0
str_hbc_cpu_schema: db "v=1 inst=none get=BOOTCLOCK custody=request,nonce,build,boot,generation,extent origin=efi-entry(not-power-on) unit=ms resolution=tsc-khz-floor clock=reason source=pit|cpuid15|unknown cal_reason=u8 ticks_per_ms=u64 costs=ucp_cost(preload),bsp_cost(checked-load) triplet=present/reason/ms costs-meaning=elapsed-call(includes-IRQ;not-milestones) validity=native-checked-snapshot not-health-or-mitigation-efficacy-proof authority=native observe=clock,source,cal_reason,ticks_per_ms,ucp_cost,bsp_cost(now-excluded) list=na set=na input=na cancel=na",0
str_hbc_cpu_witness: db " clock=",0," source=",0," cal_reason=",0," ticks_per_ms=",0," ucp_cost=",0," bsp_cost=",0,0
str_hbc_name: db "bootclock",0
str_hbc_kind: db "service",0
str_hbc_verb: db "BOOTCLOCK",0
str_hbc_schema: db "v=6 inst=none get=BOOTCLOCK custody=request,nonce,build,boot,generation,extent physical-power-on=unknown origin=efi-entry(not-power-on) unit=ms resolution=tsc-khz-floor clock=reason source=pit|cpuid15|unknown cal_reason=u8 ticks_per_ms=u64 pixel_source=signin|cli-login|unknown rows=now,boot_end,ebs,ready,ack,pixel,kbd,ptr,input,udp,ssh,terminal,nic,foundation costs=hv_cost,nic_cost,vtd_cost,amdvi_cost,airlock_cost settle=cpus,storage,census,checks,settled(latest-complete;all-decided) lease=dhcp(first-usable-lease) not-required=storage,checks triplet=present/reason/ms costs-meaning=elapsed-call(includes-IRQ;not-milestones) validity=native-checked-snapshot not-health-proof authority=native observe=clock,source,cal_reason,ticks_per_ms,pixel_source,boot_end,ebs,ready,ack,pixel,kbd,ptr,input,udp,ssh,terminal,nic,foundation,hv_cost,nic_cost,vtd_cost,amdvi_cost,airlock_cost,cpus,storage,census,checks,settled,dhcp(now-excluded) list=na set=na input=na cancel=na",0
str_hbc_head: db " bootclock v=6",0
str_hbc_bad: db " hook err=bootclock_reply_incomplete",0
str_hbc_native_head: db "BOOTCLOCK v=7 nonce=",0
str_hbc_scope: db " origin=efi-entry unit=ms resolution=tsc-khz-floor clock=",0
str_hbc_source: db " source=",0
str_hbc_cal: db " cal_reason=",0
str_hbc_scale: db " ticks_per_ms=",0
str_hbc_pixel_source: db " pixel_source=",0
str_hbc_pixel_source_end:
str_hbc_sources: db "pit",0,"cpuid15",0,"unknown",0,0
str_hbc_pixels: db "signin",0,"cli-login",0,"unknown",0,0
str_hbc_reasons: db "ok",0,"not-reached",0,"uncalibrated",0,"origin-missing",0,"regressed",0,"future",0,"snapshot-changed",0,"calibration-invalid",0,"state-invalid",0,"not-required",0,0
str_hbc_complete: db " truncated=0",0
str_hbc_now_key: db " now=",0
str_hbc_boot_end_key: db " boot_end=",0
str_hbc_ebs_key: db " ebs=",0
str_hbc_ready_key: db " ready=",0
str_hbc_ack_key: db " ack=",0
str_hbc_pixel_key: db " pixel=",0
str_hbc_kbd_key: db " kbd=",0
str_hbc_ptr_key: db " ptr=",0
str_hbc_input_key: db " input=",0
str_hbc_udp_key: db " udp=",0
str_hbc_ssh_key: db " ssh=",0
str_hbc_terminal_key: db " terminal=",0
str_hbc_nic_key: db " nic=",0
str_hbc_foundation_key: db " foundation=",0
str_hbc_hv_cost_key: db " hv_cost=",0
str_hbc_nic_cost_key: db " nic_cost=",0
str_hbc_vtd_cost_key: db " vtd_cost=",0
str_hbc_amdvi_cost_key: db " amdvi_cost=",0
str_hbc_airlock_cost_key: db " airlock_cost=",0
str_hbc_cpus_key: db " cpus=",0
str_hbc_storage_key: db " storage=",0
str_hbc_census_key: db " census=",0
str_hbc_checks_key: db " checks=",0
str_hbc_settled_key: db " settled=",0
str_hbc_dhcp_key: db " dhcp=",0
str_hbc_ucp_cost_key: db " ucp_cost=",0
str_hbc_bsp_cost_key: db " bsp_cost=",0
str_hbc_witness: db " clock=",0," source=",0," cal_reason=",0," ticks_per_ms=",0," pixel_source=",0," boot_end=",0," ebs=",0," ready=",0," ack=",0," pixel=",0," kbd=",0," ptr=",0," input=",0," udp=",0," ssh=",0," terminal=",0," nic=",0," foundation=",0," hv_cost=",0," nic_cost=",0," vtd_cost=",0," amdvi_cost=",0," airlock_cost=",0," cpus=",0," storage=",0," census=",0," checks=",0," settled=",0," dhcp=",0,0
align 8
hook_edge_bootclock: times (HE_SZ / 8) dq 0
hook_edge_cpucost: times (HE_SZ / 8) dq 0

str_hst_netcheck:         db "netcheck", 0
str_hst_ntp:              db "ntp", 0
str_hst_dns:              db "dns", 0
str_hst_tcp:              db "tcp", 0
str_hst_ssh:              db "ssh", 0
str_hst_idle:             db "idle", 0
str_hst_kind_network:     db "network", 0
str_hst_kind_power:       db "power", 0
str_hst_netcheck_schema:  db "inst=none|key16hex get=none:NETCHECK{check,adapter,driver,link,addr_nic,net,dhcp,ip,gw,gw_arp,dns,resolver,web,web_status,*_age_s} keyed-get=CARDSTAT{KEY,STATE,RESULT?}(native-proposer-or-local-OWNER) keyed-observe=KEY,STATE,RESULT observe=check,adapter,driver,link,addr_nic,net,dhcp,ip,gw,gw_arp,dns,resolver,web,web_status (no ages) list=na set=propose<key16hex> input=na cancel=key16hex:CARDCANCEL(no-confirmation)", 0
str_hst_ntp_schema:       db "inst=none get=NTPSTAT{applied,offset_ms,delay_ms,unixtime,stratum,state,reason,samples,selected,receipt_*} set=sync <a.b.c.d>[:<port 1..65535>]:NTPSYNC observe=applied,stratum,state,reason,selected,receipt_valid,receipt_persisted,receipt_objid,receipt_version,receipt_owner,receipt_schema,receipt_checksum,receipt_utc_us,receipt_offset_fp,receipt_delay_fp,receipt_server_ip,receipt_samples,receipt_selected,receipt_stratum list=na input=na cancel=na", 0
str_hst_dns_schema:       db "inst=<name of [A-Za-z0-9.-], first a letter or digit; the 192-byte HOOK line caps it below 253> get=DNSCACHE <name>{A|NXDOMAIN|miss} set=resolve:RESOLVE <name> (one query) observe=the entry line list=na input=na cancel=na", 0
str_hst_tcp_schema:       db "inst=none get=TCPSTAT{rev,listeners,used,max,syn,est,closing,timewait,accepts,rx,tx,...} observe=listeners,used,syn,est,closing,timewait list=na set=na input=na cancel=na", 0
str_hst_ssh_schema:       db "inst=none get=SSHSTAT{source,principal,auth_ok,auth_fail,streak,lockouts,lockout_ms,exec,exec_refused,key_nvram_writes,keys,store} list=SSHKEYLIST{keys,store,k<i>=SHA256:<fp> caps=<hex16>} observe=auth_ok,auth_fail,lockouts,exec,store,exec_refused,key_nvram_writes,keys set=na input=na cancel=na", 0
str_hst_idle_schema:      db "inst=none|<dense cpu 0..31> get=cached-idle (depth alias; native IDLEDEPTH empty arg; owner envelope) fields=state,hint,reason,row,probe,topology,online_count,online_mask,cpu,online,check,halts,deep set=HLT|C1E|C6|C8|C10|C2|C3:IDLEDEPTH <state> (owner, boot only, no instance) observe=policy,probe,topology,selected-cpu-check (entry counters excluded; probe=prior-IDLEPROBE-gated-MSR-cache-only) snapshot=sequential unit=entries-mod64 halts=HLT-entries deep=MWAIT-or-IO-entries no-residency-energy-or-savings list=na input=na cancel=na",0
str_hst_netcheck_witness: db " check=",0," adapter=",0," driver=",0," link=",0," addr_nic=",0," net=",0," dhcp=",0," ip=",0," gw=",0," gw_arp=",0," dns=",0," resolver=",0," web=",0," web_status=",0,0
str_hst_ntp_witness:      db " applied=",0," stratum=",0," state=",0," reason=",0," selected=",0," receipt_valid=",0," receipt_persisted=",0," receipt_objid=",0," receipt_version=",0," receipt_owner=",0," receipt_schema=",0," receipt_checksum=",0," receipt_utc_us=",0," receipt_offset_fp=",0," receipt_delay_fp=",0," receipt_server_ip=",0," receipt_samples=",0," receipt_selected=",0," receipt_stratum=",0,0
str_hst_tcp_witness:      db " listeners=",0," used=",0," syn=",0," est=",0," closing=",0," timewait=",0,0
str_hst_ssh_witness:      db " auth_ok=",0," auth_fail=",0," lockouts=",0," exec=",0," store=",0," exec_refused=",0," key_nvram_writes=",0," keys=",0,0
str_hst_idle_witness:     db " state=",0," hint=",0," reason=",0," row=",0," probe=",0," topology=",0," online_count=",0," online_mask=",0," cpu=",0," online=",0," check=",0,0 ; counters intentionally excluded
str_hst_idle_states:      db "HLT",0,"C1E",0,"C6",0,"C8",0,"C10",0,"C2",0,"C3",0,0
str_hst_word_sync:        db "SYNC", 0
str_hst_word_resolve:     db "RESOLVE", 0
str_hst_word_depth:       db "DEPTH", 0
str_hst_verb_netcheck:    db "NETCHECK", 0
str_hst_verb_cardstat:    db "CARDSTAT", 0
str_hst_verb_cardcancel:  db "CARDCANCEL", 0
str_hst_card_witness:     db " KEY=",0," STATE=",0," RESULT=",0,0
str_hst_word_propose:     db "PROPOSE", 0
str_hst_card_dhcp:        db " NETCFG 1 none none -- DHCP ONCE ", 0
str_hst_verb_cardpropose: db "CARDPROPOSE", 0
str_hst_verb_ntpstat:     db "NTPSTAT", 0
str_hst_verb_ntpsync:     db "NTPSYNC", 0
str_hst_verb_dnscache:    db "DNSCACHE", 0
str_hst_verb_resolve:     db "RESOLVE", 0
str_hst_verb_tcpstat:     db "TCPSTAT", 0
str_hst_verb_sshstat:     db "SSHSTAT", 0
str_hst_verb_sshkeylist:  db "SSHKEYLIST", 0
str_hst_verb_idleprobe:   db "IDLEPROBE", 0
str_hst_verb_idledepth:   db "IDLEDEPTH", 0

align 8
hook_edge_netcheck:       times (HE_SZ / 8) dq 0
hook_edge_ntp:            times (HE_SZ / 8) dq 0
hook_edge_dns:            times (HE_SZ / 8) dq 0
hook_edge_tcp:            times (HE_SZ / 8) dq 0
hook_edge_ssh:            times (HE_SZ / 8) dq 0
hook_edge_idle:           times (HE_SZ / 8) dq 0

str_hst_thermal: db "thermal", 0
str_hst_verb_therm: db "THERM", 0
str_hst_thermal_schema: db "v=1 inst=none get=THERM{tempC=u32|unavailable,tjmax=u32,degraded=0|1,source=dts|amd_tctl|none} units=C native=live-read source=dts:Intel-DTS|amd_tctl:AMD-Tctl|none:unsupported validity=native-unavailable-or-degraded sample-age=not-provided sample-timestamp=not-provided tjmax=native-cached-or-default-not-AMD-trip-limit authority=native observe=tempC,tjmax,degraded,source list=na set=na input=na cancel=na", 0
str_hst_thermal_head: db " thermal v=1 ", 0
str_hst_thermal_bad_reply: db " hook err=thermal_reply_incomplete", 0
str_hst_th_tempc: db "tempC=", 0
str_hst_th_unavailable: db "unavailable", 0
str_hst_th_tjmax: db " tjmax=", 0
str_hst_th_degraded: db " degraded=", 0
str_hst_th_source: db " source=", 0
str_hst_th_dts: db "dts", 0
str_hst_th_amd: db "amd_tctl", 0
str_hst_th_none: db "none", 0
str_hst_thermal_witness: db " tempC=",0," tjmax=",0," degraded=",0," source=",0,0
align 8
hook_edge_thermal: times (HE_SZ / 8) dq 0


; ---------------------------------------------------------------------------
; Read-only public SRVSTAT via the ordinary native dispatcher. Discovery does
; not run this planner. Static refusals do not sample or change staged data.
hook_srvstat_plan:
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    mov  byte [rel srvstat_out_ready], 0
    mov  byte [rel srvstat_out_buf], 0
    lea  rax, [rel str_hss_verb]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

HST_SS_REPLY_MAX equ 1024                ; actual SRVSTAT_OUT_CAP
HST_SS_NATIVE_HEAD equ 19
HST_SS_TYPED_HEAD equ 12
hook_srvstat_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .native_refused
    push rbx
    push r12
    mov  rbx, rcx
    cmp  byte [rel srvstat_out_ready], 1
    jne  .bad_reply
    lea  rdi, [rel srvstat_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HST_SS_REPLY_MAX
    jae  .bad_reply
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    cmp  ecx, HST_SS_NATIVE_HEAD
    jb   .bad_reply
    cmp  ecx, HOOK_OUT_MAX - 1 - HST_SS_TYPED_HEAD + HST_SS_NATIVE_HEAD
    ja   .bad_reply
    mov  r12d, ecx
    call hst_ss_record
    test eax, eax
    jz   .bad_reply
    call command_hook_out_reset
    lea  rdi, [rel str_hss_head]
    call command_hook_out_str
    lea  rdi, [rel srvstat_out_buf + HST_SS_NATIVE_HEAD]
    mov  esi, r12d
    sub  esi, HST_SS_NATIVE_HEAD
    call command_hook_out_strn
    jmp  .retire
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_hss_bad_reply]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hss_bad_reply]
    mov  [rbx + RSP_HINT], rax
.retire:
    mov  byte [rel srvstat_out_ready], 0
    mov  byte [rel srvstat_out_buf], 0
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.native_refused:
    xor  eax, eax                        ; preserve native code/hint/staged refusal
    ret

; Exact complete public producer grammar; call only after bounded NUL above.
; Literals are bytewise and stop at mismatch/NUL, even at a guard-page edge.
; Decimal fields are canonical full u64; only NET_TX/NET_RX also allow unknown.
%macro HSS_LITERAL 1
    lea  rsi, [rel %1]
    call hst_thermal_literal
    test eax, eax
    jz   .out
%endmacro
%macro HSS_NUMBER 1
    HSS_LITERAL %1
    call hst_ss_u64
    test eax, eax
    jz   .out
%endmacro
hst_ss_record:
    sub  rsp, 8
    HSS_LITERAL str_hss_native_head
    HSS_NUMBER str_hss_uptime
    HSS_LITERAL str_hss_boot
    HSS_NUMBER str_hss_ram
    HSS_LITERAL str_hss_tx
    call hst_ss_counter
    test eax, eax
    jz   .out
    HSS_LITERAL str_hss_rx
    call hst_ss_counter
    test eax, eax
    jz   .out
    HSS_LITERAL str_hss_share
    cmp  byte [rdi], 'o'
    je   .owner
    cmp  byte [rdi], 'l'
    je   .legacy
    HSS_LITERAL str_hss_unsupported
    jmp  .policy_done
.owner:
    HSS_LITERAL str_hss_owner
    jmp  .policy_done
.legacy:
    HSS_LITERAL str_hss_legacy
.policy_done:
    HSS_NUMBER str_hss_bulk
    HSS_LITERAL str_hss_scope
    HSS_NUMBER str_hss_csp_state
    HSS_NUMBER str_hss_csp_enter
    HSS_NUMBER str_hss_csp_done
    HSS_NUMBER str_hss_csp_entries
    HSS_NUMBER str_hss_csp_returns
    HSS_NUMBER str_hss_csp_active
    HSS_NUMBER str_hss_csp_polls
    HSS_NUMBER str_hss_csp_rx_slot
    HSS_NUMBER str_hss_csp_rx_gen
    HSS_NUMBER str_hss_csp_rx_state
    HSS_NUMBER str_hss_csp_rx_side
    HSS_NUMBER str_hss_csp_health
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    add  rsp, 8
    ret
%unmacro HSS_LITERAL 1
%unmacro HSS_NUMBER 1

; Only unavailable network counters have this alternative. The next exact
; field literal enforces the delimiter; unknown-prefix/suffix injection fails.
hst_ss_counter:
    cmp  byte [rdi], 'u'
    jne  hst_ss_u64
    lea  rsi, [rel str_hss_counter_unknown]
    jmp  hst_thermal_literal

; hst_ss_u64: RDI advances across 1..20 digits; rejects overflow BEFORE
; multiplying, signs and noncanonical leading zeros. R8=result, EAX=1/0.
hst_ss_u64:
    xor  r8d, r8d
    xor  r9d, r9d
    mov  r11, 1844674407370955161
.digit:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .end
    cmp  r9d, 20
    jae  .no
    test r9d, r9d
    jz   .range
    test r8, r8
    jz   .no                             ; a leading zero cannot have more digits
.range:
    cmp  r8, r11
    ja   .no
    jb   .accumulate
    cmp  eax, 5
    ja   .no
.accumulate:
    imul r8, r8, 10
    add  r8, rax
    inc  rdi
    inc  r9d
    jmp  .digit
.end:
    test r9d, r9d
    jz   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

align 8
hook_edge_srvstat: times HE_SZ db 0
str_hss_name: db "srvstat", 0
str_hss_kind: db "service", 0
str_hss_verb: db "SRVSTAT", 0
str_hss_head: db " srvstat v=1", 0
str_hss_bad_reply: db " hook err=srvstat_reply_incomplete", 0
str_hss_schema: db "v=1 inst=none get=SRVSTAT{public-native-record,numeric=u64,NET_TX_RX=u64|unknown,BOOT_TARGET=unsupported,SHARE_ROOT=/SHARE,SHARE_STATE=unprovisioned,SHARE_POLICY=unsupported|owner_only|legacy_unrestricted,RAM_SCOPE=allocator_arenas,NET_SOURCE=reply_member} volatile=UPTIME_S,NET_TX,NET_RX,CSP_ENTER,CSP_DONE,CSP_ENTRIES,CSP_RETURNS,CSP_ACTIVE,CSP_POLLS observe=service,memory,policy,sessions,CSP_STATE,RX-identity-state,CSP_HEALTH self-progress-excluded correlation=omitted diagnostic-only readiness=self-attestation-not-runtime-health-proof RAM=unallocated-arena-not-reservation NET=frame-counters-not-reachability CSP=passive-progress-not-watchdog health=publisher-flag-not-service-proof authority=native list=na set=na input=na cancel=na", 0
str_hss_native_head: db "SRVSTAT OK ARG=none", 0
str_hss_uptime: db " UPTIME_S=", 0
str_hss_boot: db " BOOT_TARGET=unsupported", 0
str_hss_ram: db " RAM_FREE_KB=", 0
str_hss_tx: db " NET_TX=", 0
str_hss_rx: db " NET_RX=", 0
str_hss_share: db " SHARE_ROOT=/SHARE SHARE_STATE=unprovisioned SHARE_POLICY=", 0
str_hss_unsupported: db "unsupported", 0
str_hss_owner: db "owner_only", 0
str_hss_legacy: db "legacy_unrestricted", 0
str_hss_bulk: db " BULK_SESSIONS=", 0
str_hss_counter_unknown: db "unknown", 0
str_hss_scope: db " RAM_SCOPE=allocator_arenas NET_SOURCE=reply_member", 0
str_hss_csp_state: db " CSP_STATE=", 0
str_hss_csp_enter: db " CSP_ENTER=", 0
str_hss_csp_done: db " CSP_DONE=", 0
str_hss_csp_entries: db " CSP_ENTRIES=", 0
str_hss_csp_returns: db " CSP_RETURNS=", 0
str_hss_csp_active: db " CSP_ACTIVE=", 0
str_hss_csp_polls: db " CSP_POLLS=", 0
str_hss_csp_rx_slot: db " CSP_RX_SLOT=", 0
str_hss_csp_rx_gen: db " CSP_RX_GEN=", 0
str_hss_csp_rx_state: db " CSP_RX_STATE=", 0
str_hss_csp_rx_side: db " CSP_RX_SIDE=", 0
str_hss_csp_health: db " CSP_HEALTH=", 0
str_hss_witness: db " BOOT_TARGET=",0," RAM_FREE_KB=",0," SHARE_ROOT=",0," SHARE_STATE=",0," SHARE_POLICY=",0," BULK_SESSIONS=",0," RAM_SCOPE=",0," NET_SOURCE=",0," CSP_STATE=",0," CSP_RX_SLOT=",0," CSP_RX_GEN=",0," CSP_RX_STATE=",0," CSP_RX_SIDE=",0," CSP_HEALTH=",0,0

; PSTATE? owns its existing bounded APERF/MPERF sample/load window. This adapter
; adds no MSR, governor, frequency policy or THERM_INDUCE/FREQMSR route. It plans
; only the read native with the original caller identity and empty nonce. Ratio
; is floor(dAPERF*100/dMPERF), a percent of base, not MHz or runtime acceptance.
; Native unavailable status distinguishes unsupported from invalid windows;
; numeric zero is valid. No timestamp/age exists. BSP command serialization owns
; shared therm_out_buf lifetime; do not invoke from AP/IRQ or retain its pointer.
; Complete native publication is transferred then retired. Witness excludes
; correlation and covers ratio+status only, never health or performance proof.
hook_pstate_plan:
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    mov  byte [rel therm_out_ready], 0
    mov  byte [rel therm_out_buf], 0
    lea  rax, [rel str_hst_verb_pstate]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

HST_PSTATE_REPLY_MAX equ 256              ; actual native therm_out_buf capacity
hook_pstate_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .native_refused
    push rbx
    push r12
    push r13
    mov  rbx, rcx
    cmp  byte [rel therm_out_ready], 1
    jne  .bad_reply
    lea  rdi, [rel therm_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HST_PSTATE_REPLY_MAX
    jae  .bad_reply
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    mov  r12d, ecx
    call hst_pstate_record
    test eax, eax
    jz   .bad_reply
    mov  r13d, edx                       ; validated numeric native reply
    call command_hook_out_reset
    lea  rdi, [rel str_hst_pstate_head]
    call command_hook_out_str
    lea  rdi, [rel therm_out_buf]
    mov  esi, r12d
    call command_hook_out_strn
    test r13d, r13d
    jz   .retire
    lea  rdi, [rel str_hst_ps_valid]
    call command_hook_out_str
    jmp  .retire
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_hst_pstate_bad_reply]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hst_pstate_bad_reply]
    mov  [rbx + RSP_HINT], rax
.retire:
    mov  byte [rel therm_out_ready], 0
    mov  byte [rel therm_out_buf], 0
    pop  r13
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.native_refused:
    mov  byte [rel therm_out_ready], 0
    mov  byte [rel therm_out_buf], 0
    xor  eax, eax                        ; preserve native code/hint/value
    ret

; RDI NUL-terminated bounded publication -> EAX 1/0, EDX 1 numeric / 0 unavailable.
; Call only after capacity-bounded NUL scan. Reuses bytewise literal/u32 helpers;
; no missing/duplicate/extra fields, leading zeros, signed/overflow or partial text.
hst_pstate_record:
    lea  rsi, [rel str_hst_ps_ratio]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 'u'
    je   .unavailable
    cmp  byte [rdi], '0'
    jne  .numeric
    cmp  byte [rdi + 1], 0
    jne  .no
.numeric:
    call hst_thermal_u32
    test eax, eax
    jz   .no
    cmp  byte [rdi], 0
    jne  .no
    mov  edx, 1
    mov  eax, 1
    ret
.unavailable:
    lea  rsi, [rel str_hst_ps_unavailable]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 'u'
    je   .unsupported
    lea  rsi, [rel str_hst_ps_invalid]
    jmp  .last
.unsupported:
    lea  rsi, [rel str_hst_ps_unsupported]
.last:
    call hst_thermal_literal
    test eax, eax
    jz   .no
    cmp  byte [rdi], 0
    jne  .no
    xor  edx, edx
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

str_hst_pstate: db "pstate", 0
str_hst_verb_pstate: db "PSTATE?", 0
str_hst_pstate_schema: db "v=1 inst=none get=PSTATE?{ratio=u32|unavailable,status=valid|unsupported|invalid} units=percent-of-base ratio=floor(dAPERF*100/dMPERF) native=bounded-live-sample not-MHz not-liveness-or-performance-acceptance valid-zero=idle-or-rounded unavailable=unsupported-or-invalid-window counter-deltas=modular-less-than-2^63 sample-age=not-provided sample-timestamp=not-provided authority=native observe=ratio,status list=na set=na input=na cancel=na", 0
str_hst_pstate_head: db " pstate v=1 ", 0
str_hst_pstate_bad_reply: db " hook err=pstate_reply_incomplete", 0
str_hst_pstate_witness: db " ratio=",0," status=",0,0
str_hst_ps_ratio: db "ratio=", 0
str_hst_ps_valid: db " status=valid", 0
str_hst_ps_unavailable: db "unavailable status=", 0
str_hst_ps_unsupported: db "unsupported", 0
str_hst_ps_invalid: db "invalid", 0
align 8
hook_edge_pstate: times HE_SZ db 0

; Full normalized record is the witness: selector, logical ID, sample sequence,
; native status and counters remain semantic; the fixed transport nonce is gone.
align 8
hook_edge_smpstat: times HE_SZ db 0
str_hsm_name: db "smpstat", 0
str_hsm_kind: db "service", 0
str_hsm_schema: db "v=2 inst=none native=SMPSTAT|SMPWORK-ASYNC-STATUS|DETAIL|PROGRESS|RESULTS|ASYNC-CANCEL|SMPPOLSTAT|SMPPOLVALIDATE get=POLICY|VALIDATE{balanced|physical_first}|SUMMARY(default)|CPU{logical:u32}|HEALTH|LOAD{CHIP}|LOAD{logical:u32,sample:u32}|SCHEMA|WORK{nonce:hex8,generation:hex16}|DETAIL{nonce:hex8,generation:hex16}|PROGRESS{nonce:hex8,generation:hex16}|RESULTS{nonce:hex8,generation:hex16} sample_model=stable_snapshot frequency_model=passive_aperfmperf native-schema=SCHEMA LOAD-cpu=explicit-current-sample frequency=number|unavailable freq_state=measured|idle|unsupported temperature=unavailable WORK=retained-status-only owned=source,principal,nonce32,generation64 DETAIL=admission PROGRESS=published_mask,published;not-AP-completion RESULTS=frozen_rows,non-consuming;unknown-on-refusal observe=whole-record authority=native not-physical-SMP-or-performance-acceptance list=na set=na input=na cancel=WORK{nonce:hex8,generation:hex16}", 0


; THROTTLE_LOG passively projects one admitted software-notice snapshot.
; Hardware logbit is separate from software notice. Source-specific raw sensor
; word/temp/status/TSC survive later THERM refreshes. Saturating count is a lower
; bound at UINT64_MAX. Raw TSC supplies no age conversion or physical proof.
; Only staging changes here, under the existing BSP command serialization;
; retire before normal authorized native dispatch and consume on every post.
hook_throttle_log_plan:
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    mov  byte [rel therm_out_ready], 0
    mov  byte [rel therm_out_buf], 0
    lea  rax, [rel str_htl_verb]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

HTL_REPLY_MAX equ 256              ; actual therm_out_buf capacity
hook_throttle_log_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .native_refused
    push rbx
    push r12
    mov  rbx, rcx
    cmp  byte [rel therm_out_ready], 1
    jne  .bad_reply
    lea  rdi, [rel therm_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HTL_REPLY_MAX
    jae  .bad_reply
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    mov  r12d, ecx
    call htl_record
    test eax, eax
    jz   .bad_reply
    call command_hook_out_reset
    lea  rdi, [rel str_htl_head]
    call command_hook_out_str
    lea  rdi, [rel therm_out_buf]
    mov  esi, r12d
    call command_hook_out_strn
    jmp  .retire
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_htl_bad_reply]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_htl_bad_reply]
    mov  [rbx + RSP_HINT], rax
.retire:
    mov  byte [rel therm_out_ready], 0
    mov  byte [rel therm_out_buf], 0
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.native_refused:
    mov  byte [rel therm_out_ready], 0
    mov  byte [rel therm_out_buf], 0
    xor  eax, eax                        ; original code/hint stay authoritative
    ret


; After capacity-bounded NUL scan only. Exact singleton fields in native order;
; u32 natural lowercase hex, bool and canonical u64 decimal (full native widths).
; The v2 extension requires explicit notice/source/temp/raw; old prefixes alone
; cannot be silently promoted to coherent event observations.
htl_record:
    lea  rsi, [rel str_htl_status]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    call htl_hex32
    test eax, eax
    jz   .no
    lea  rsi, [rel str_htl_logbit]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 1
    ja   .no
    inc  rdi
    lea  rsi, [rel str_htl_events]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    call htl_u64
    test eax, eax
    jz   .no
    lea  rsi, [rel str_htl_ts]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    call htl_u64
    test eax, eax
    jz   .no
    lea  rsi, [rel str_htl_notice]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 1
    ja   .no
    mov  r10d, eax
    inc  rdi
    lea  rsi, [rel str_htl_source]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    test r10d, r10d
    jz   .none
    cmp  byte [rdi], 'd'
    je   .dts
    lea  rsi, [rel str_htl_amd]
    jmp  .source
.dts:
    lea  rsi, [rel str_htl_dts]
    jmp  .source
.none:
    lea  rsi, [rel str_htl_none]
.source:
    call hst_thermal_literal
    test eax, eax
    jz   .no
    lea  rsi, [rel str_htl_temp]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    test r10d, r10d
    jz   .unavailable
    call htl_u64
    test eax, eax
    jz   .no
    mov  eax, 0xffffffff
    cmp  rdx, rax
    ja   .no
    jmp  .raw
.unavailable:
    lea  rsi, [rel str_htl_unavailable]
    call hst_thermal_literal
    test eax, eax
    jz   .no
.raw:
    lea  rsi, [rel str_htl_raw]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    call htl_hex32
    test eax, eax
    jz   .no
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

htl_hex32:
    cmp  byte [rdi], '0'
    jne  .digits
    inc  rdi                            ; a sole zero; delimiter checked by caller
    mov  eax, 1
    ret
.digits:
    xor  ecx, ecx
.next:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    jbe  .digit
    sub  eax, 'a' - '0'
    cmp  eax, 5
    ja   .end
.digit:
    inc  ecx
    cmp  ecx, 8                         ; native u32, no ninth hex digit
    ja   .no
    inc  rdi
    jmp  .next
.end:
    xor  eax, eax
    test ecx, ecx
    setnz al
    ret
.no:
    xor  eax, eax
    ret

htl_u64:
    xor  edx, edx                       ; zero is also a decoded numeric value
    cmp  byte [rdi], '0'
    jne  .digits
    inc  rdi                            ; leading zeros cannot match next literal
    mov  eax, 1
    ret
.digits:
    xor  ecx, ecx
    xor  edx, edx
    mov  r8, 1844674407370955161         ; floor(UINT64_MAX/10)
.next:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .end
    cmp  rdx, r8
    ja   .no
    jb   .accumulate
    cmp  eax, 5                         ; remainder UINT64_MAX%10
    ja   .no
.accumulate:
    imul rdx, rdx, 10
    add  rdx, rax
    inc  ecx
    inc  rdi
    jmp  .next
.end:
    xor  eax, eax
    test ecx, ecx
    setnz al
    ret
.no:
    xor  eax, eax
    ret

str_htl_name: db "throttle_log", 0
str_htl_verb: db "THROTTLE_LOG", 0
str_htl_schema: db "v=2 inst=none get=THROTTLE_LOG{therm_status=u32-hex-natural-lower,logbit=0|1,events=u64,ts=u64,notice=0|1,source=none|dts|amd_tctl,tempC=u32|unavailable,raw=u32-hex-natural-lower} status=event-Intel-status-or-zero logbit=hardware-only notice=software-threshold events=saturating-notice-count ts=event-raw-TSC raw=source-sensor-word same-event-snapshot clock-age-conversion=not-provided zero-history=retained not-fresh-sample not-silicon-throttle-proof not-physical-acceptance authority=native observe=therm_status,logbit,events,ts,notice,source,tempC,raw list=na set=na input=na cancel=na", 0
str_htl_head: db " throttle_log v=2 ", 0
str_htl_bad_reply: db " hook err=throttle_log_reply_incomplete", 0
str_htl_witness: db " therm_status=",0," logbit=",0," events=",0," ts=",0," notice=",0," source=",0," tempC=",0," raw=",0,0
str_htl_status: db "therm_status=0x", 0
str_htl_logbit: db " logbit=", 0
str_htl_events: db " events=", 0
str_htl_ts: db " ts=", 0
str_htl_notice: db " notice=", 0
str_htl_source: db " source=", 0
str_htl_none: db "none", 0
str_htl_dts: db "dts", 0
str_htl_amd: db "amd_tctl", 0
str_htl_temp: db " tempC=", 0
str_htl_unavailable: db "unavailable", 0
str_htl_raw: db " raw=0x", 0
align 8
hook_edge_throttle_log: times HE_SZ db 0

; Explicit active action only. FREQMSR's legacy cap0/destr0 registration does
; not make it shipped-public: native MUTATE/session/source/principal/ticket and
; capability gates remain unchanged. Never plan from GET/OBSERVE or poll/witness.
; Only native handler measures, requests HWP and restores its existing policy.
; Post formats the completed fixed native snapshot, never live governor state.
; Unsupported/invalid carry no partial measurements; zero diagnostic fields are
; real zeros. Firmware default and thermal/no-turbo reasons retain native meaning.
; No timestamp, freshness, liveness, performance acceptance or policy is inferred.
hook_freqmsr_plan:
    cmp  edi, HOP_SET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    mov  rdi, rdx
    lea  rsi, [rel str_hfm_measure]
    call command_hook_word_eq
    test eax, eax
    jz   .bad
    call command_freq_reply_retire
    call command_hook_arg_reset           ; native nonce omitted, never "measure"
    lea  rax, [rel str_hfm_verb]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

hook_freqmsr_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .native_refused
    push rbx
    mov  rbx, rcx
    cmp  byte [rel command_freq_reply_ready], 1
    jne  .bad_reply
    cmp  byte [rel command_freq_reply + CFR_STATUS], 2
    ja   .bad_reply
    cmp  byte [rel command_freq_reply + CFR_HWP], 1
    je   .hwp
    cmp  byte [rel command_freq_reply + CFR_STATUS], 0
    jne  .bad_reply
    jmp  .emit
.hwp:
    cmp  byte [rel command_freq_reply + CFR_STATUS], 1
    jne  .emit
    cmp  byte [rel command_freq_reply + CFR_THERMAL], 1
    ja   .bad_reply
    cmp  byte [rel command_freq_reply + CFR_REASON], 2
    ja   .bad_reply
    cmp  byte [rel command_freq_reply + CFR_THERMAL], 0
    jne  .capped
    cmp  byte [rel command_freq_reply + CFR_REASON], 0
    jne  .bad_reply
    jmp  .emit
.capped:
    cmp  byte [rel command_freq_reply + CFR_REASON], 0
    je   .bad_reply
.emit:
    call command_hook_out_reset
    lea  rdi, [rel str_hfm_head]
    call command_hook_out_str
    movzx edi, byte [rel command_freq_reply + CFR_HWP]
    call command_hook_out_dec
    cmp  byte [rel command_freq_reply + CFR_HWP], 1
    jne  .firmware
    cmp  byte [rel command_freq_reply + CFR_STATUS], 1
    jne  .unavailable
    lea  rdi, [rel str_hfm_valid]
    call command_hook_out_str
    lea  rdi, [rel str_hfm_sprint]
    call command_hook_out_str
    mov  rdi, [rel command_freq_reply + CFR_SPRINT]
    call command_hook_out_dec
    lea  rdi, [rel str_hfm_eff]
    call command_hook_out_str
    mov  rdi, [rel command_freq_reply + CFR_EFF]
    call command_hook_out_dec
    lea  rdi, [rel str_hfm_base]
    call command_hook_out_str
    mov  rdi, [rel command_freq_reply + CFR_BASE]
    call command_hook_out_dec
    lea  rdi, [rel str_hfm_turbo]
    call command_hook_out_str
    movzx edi, byte [rel command_freq_reply + CFR_TURBO]
    call command_hook_out_dec
    lea  rdi, [rel str_hfm_hi]
    call command_hook_out_str
    movzx edi, byte [rel command_freq_reply + CFR_HI]
    call command_hook_out_dec
    lea  rdi, [rel str_hfm_lo]
    call command_hook_out_str
    movzx edi, byte [rel command_freq_reply + CFR_LO]
    call command_hook_out_dec
    lea  rdi, [rel str_hfm_thermal]
    call command_hook_out_str
    movzx edi, byte [rel command_freq_reply + CFR_THERMAL]
    call command_hook_out_dec
    lea  rdi, [rel str_hfm_none]
    cmp  byte [rel command_freq_reply + CFR_REASON], 0
    je   .reason
    lea  rdi, [rel str_hfm_thermal_reason]
    cmp  byte [rel command_freq_reply + CFR_REASON], 1
    je   .reason
    lea  rdi, [rel str_hfm_no_turbo]
.reason:
    call command_hook_out_str
    jmp  .retire
.firmware:
    lea  rdi, [rel str_hfm_firmware]
    call command_hook_out_str
    jmp  .retire
.unavailable:
    lea  rdi, [rel str_hfm_unsupported]
    cmp  byte [rel command_freq_reply + CFR_STATUS], 0
    je   .reason
    lea  rdi, [rel str_hfm_invalid]
    jmp  .reason
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_hfm_bad_reply]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hfm_bad_reply]
    mov  [rbx + RSP_HINT], rax
.retire:
    call command_freq_reply_retire
    pop  rbx
    mov  eax, 1
    ret
.native_refused:
    call command_freq_reply_retire
    xor  eax, eax
    ret

str_hfm_name: db "freqmsr", 0
str_hfm_verb: db "FREQMSR", 0
str_hfm_measure: db "MEASURE", 0
str_hfm_schema: db "v=1 inst=none set=measure native=FREQMSR active=sprint-efficiency-bounded-load-relax authority=native status=valid|unsupported|invalid mode=firmware_default{hwp!=1} valid={sprint_mhz:u64,eff_mhz:u64,base_mhz:u64,turbo_ratio:u8,hi:u8,lo:u8,thermal_capped:bool,cap_reason:none|thermal|no_turbo_headroom} units=sprint/eff/base:MHz,hi/lo:HWP-performance,turbo_ratio:ratio sample-age=not-provided not-performance-acceptance get=na observe=na list=na input=na cancel=na", 0
str_hfm_head: db " freqmsr v=1 hwp=", 0
str_hfm_valid: db " status=valid", 0
str_hfm_sprint: db " sprint_mhz=", 0
str_hfm_eff: db " eff_mhz=", 0
str_hfm_base: db " base_mhz=", 0
str_hfm_turbo: db " turbo_ratio=", 0
str_hfm_hi: db " hi=", 0
str_hfm_lo: db " lo=", 0
str_hfm_thermal: db " thermal_capped=", 0
str_hfm_none: db " cap_reason=none", 0
str_hfm_thermal_reason: db " cap_reason=thermal", 0
str_hfm_no_turbo: db " cap_reason=no_turbo_headroom", 0
str_hfm_firmware: db " status=unsupported mode=firmware_default", 0
str_hfm_unsupported: db " status=unsupported", 0
str_hfm_invalid: db " status=invalid", 0
str_hfm_bad_reply: db " hook err=freqmsr_reply_incomplete", 0
align 8
hook_edge_freqmsr: times HE_SZ db 0


; Stable schema values, matching the native IDLE_S_*, IDLE_R_*, SMP_IDLE_CPU_*.
hst_idle_states:
    db "hlt",0
    times (16 - ($ - hst_idle_states) % 16) % 16 db 0
    db "c1e",0
    times (16 - ($ - hst_idle_states) % 16) % 16 db 0
    db "c6",0
    times (16 - ($ - hst_idle_states) % 16) % 16 db 0
    db "c8",0
    times (16 - ($ - hst_idle_states) % 16) % 16 db 0
    db "c10",0
    times (16 - ($ - hst_idle_states) % 16) % 16 db 0
    db "c2",0
    times (16 - ($ - hst_idle_states) % 16) % 16 db 0
    db "c3",0
    times (16 - ($ - hst_idle_states) % 16) % 16 db 0
hst_idle_reasons:
    db "default_off",0
    times (16 - ($ - hst_idle_reasons) % 16) % 16 db 0
    db "no_row",0
    times (16 - ($ - hst_idle_reasons) % 16) % 16 db 0
    db "fwct",0
    times (16 - ($ - hst_idle_reasons) % 16) % 16 db 0
    db "hv",0
    times (16 - ($ - hst_idle_reasons) % 16) % 16 db 0
    db "not_offered",0
    times (16 - ($ - hst_idle_reasons) % 16) % 16 db 0
    db "cpu",0
    times (16 - ($ - hst_idle_reasons) % 16) % 16 db 0
    db "substate",0
    times (16 - ($ - hst_idle_reasons) % 16) % 16 db 0
    db "owner",0
    times (16 - ($ - hst_idle_reasons) % 16) % 16 db 0
    db "probe",0
    times (16 - ($ - hst_idle_reasons) % 16) % 16 db 0
hst_idle_probes:
    db "unprobed",0
    times (16 - ($ - hst_idle_probes) % 16) % 16 db 0
    db "unsupported",0
    times (16 - ($ - hst_idle_probes) % 16) % 16 db 0
    db "cached",0
    times (16 - ($ - hst_idle_probes) % 16) % 16 db 0
hst_idle_checks:
    db "unprobed",0
    times (16 - ($ - hst_idle_checks) % 16) % 16 db 0
    db "mwait",0
    times (16 - ($ - hst_idle_checks) % 16) % 16 db 0
    db "unsupported",0
    times (16 - ($ - hst_idle_checks) % 16) % 16 db 0
    db "io",0
    times (16 - ($ - hst_idle_checks) % 16) % 16 db 0
str_hst_idle_head: db " hook idle v=1 scope=boot snapshot=sequential unit=entries-mod64 state=",0
str_hst_idle_hint: db " hint=",0
str_hst_idle_reason: db " reason=",0
str_hst_idle_row: db " row=",0
str_hst_idle_probe: db " probe=",0
str_hst_idle_topology: db " topology=",0
str_hst_idle_ncpu: db " online_count=",0
str_hst_idle_mask: db " online_mask=",0
str_hst_idle_cpu: db " cpu=",0
str_hst_idle_online: db " online=",0
str_hst_idle_check: db " check=",0
str_hst_idle_halts: db " halts=",0
str_hst_idle_deep: db " deep=",0
str_hst_idle_unknown: db "unknown",0
str_hst_idle_valid: db "bounded",0
str_hst_idle_none: db "none",0
str_hst_idle_hlt: db "hlt",0
str_hst_idle_denied: db " hook err=owner_envelope_required",0

; TLSSTAT is an existing bounded diagnostic read. Plan only that native
; operation; unchanged nested dispatch owns all authority. Passive saved TLS
; fields are neither a fresh handshake nor certificate/reachability proof.
; Shared producer staging is serialized by ordinary BSP command dispatch.
; Retire it before dispatch, validate the complete bounded record, then consume
; once into the hook reply. No connection, KAT, IO, key material or raw body.
; A pending byte tracks only serialized plan/post lifetime, not authority.
; Join the exact native end cursor to the bounded NUL and retire all512 bytes.
hook_tls_plan:
    push rdi
    push rsi
    push rdx
    call hts_retire
    pop  rdx
    pop  rsi
    pop  rdi
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad                            ; TLS has one native session
    cmp  byte [rdx], 0
    jne  .bad                            ; no peer, KAT or connect selector
    mov  byte [rel hts_pending], 1
    lea  rax, [rel str_hts_verb]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

HST_TLS_REPLY_MAX equ 512                ; svc/command_tls13 actual native buffer
hook_tls_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .native_refused
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rcx
    cmp  byte [rel hts_pending], 1
    jne  .bad_reply
    cmp  byte [rel tls13_cmd_out_ready], 1
    jne  .bad_reply
    lea  rdi, [rel tls13_cmd_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HST_TLS_REPLY_MAX
    jae  .bad_reply
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel tls13_cmd_out_cur]
    jne  .bad_reply
    mov  r12d, ecx
    call hst_tls_record
    test eax, eax
    jz   .bad_reply
    call command_hook_out_reset
    lea  rdi, [rel str_hts_head]
    call command_hook_out_str
    lea  rdi, [rel tls13_cmd_out_buf]
    mov  esi, r12d
    call command_hook_out_strn
    jmp  .retire
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_hts_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hts_bad]
    mov  [rbx + RSP_HINT], rax
.retire:
    call hts_retire
    add  rsp, 8
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.native_refused:
    sub  rsp, 8
    call hts_retire
    add  rsp, 8
    xor  eax, eax                    ; preserve the original native code/hint
    ret

hts_retire:
    mov  byte [rel hts_pending], 0
    mov  byte [rel tls13_cmd_out_ready], 0
    mov  qword [rel tls13_cmd_out_cur], 0
    lea  rdi, [rel tls13_cmd_out_buf]
    mov  ecx, HST_TLS_REPLY_MAX
    xor  eax, eax
    rep  stosb
    ret

; Exact producer order and canonical decimal widths; no invented TLS policy.
; Native u8 fields remain u8 (diagnostic flags are not promoted to guarantees).
; SNI is the native printable, space-free name, empty until a peer is selected.
; Validate only after bounded NUL, so literals stop before any buffer overread.
%macro HTS_NUMBER 2
    lea  rsi, [rel %1]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    call hst_ss_u64
    test eax, eax
    jz   .no
    mov  eax, %2
    cmp  r8, rax
    ja   .no
%endmacro
hst_tls_record:
    sub  rsp, 8
    HTS_NUMBER str_hts_established, 255
    HTS_NUMBER str_hts_cert, 255
    lea  rsi, [rel str_hts_sni]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    xor  ecx, ecx
.sni:
    cmp  byte [rdi], ' '
    je   .state
    movzx eax, byte [rdi]
    cmp  eax, 33
    jb   .no
    cmp  eax, 126
    ja   .no
    inc  ecx
    cmp  ecx, 200
    ja   .no
    inc  rdi
    jmp  .sni
.state:
    HTS_NUMBER str_hts_state, 255
    HTS_NUMBER str_hts_error, 255
    HTS_NUMBER str_hts_tcp, 255
    HTS_NUMBER str_hts_records, 0xffffffff
    HTS_NUMBER str_hts_messages, 0xffffffff
    HTS_NUMBER str_hts_last_record, 255
    HTS_NUMBER str_hts_last_hs, 255
    HTS_NUMBER str_hts_finished, 255
    HTS_NUMBER str_hts_trust, 255
    HTS_NUMBER str_hts_rx, 0xffffffff
    HTS_NUMBER str_hts_hs, 0xffffffff
    HTS_NUMBER str_hts_entropy, 255
    cmp  byte [rdi], 0
    jne  .no                            ; exact complete native status
    mov  eax, 1
    add  rsp, 8
    ret
.no:
    xor  eax, eax
    add  rsp, 8
    ret

align 8
hook_edge_tls: times HE_SZ db 0
hts_pending: db 0
str_hts_name: db "tls",0
str_hts_verb: db "TLSSTAT",0
str_hts_head: db " tls v=1",0
str_hts_bad: db " hook err=tls_reply_incomplete",0
str_hts_schema: db "v=1 inst=none get=TLSSTAT{established:u8,cert_verified:u8,sni:ascii0..200,state:u8,error:u8,tcp_connected:u8,records:u32,hs_messages:u32,last_record:u8,last_hs:u8,peer_finished:u8,trust_path:u8,rx_pending:u32,hs_pending:u32,entropy_degraded:u8} authority=native diagnostic=retained-software-not-fresh-handshake-or-reachability-proof volatile=records,hs_messages,rx_pending,hs_pending observe=remaining-fields list=na set=na input=na cancel=na",0
str_hts_established: db " established=",0
str_hts_cert: db " cert_verified=",0
str_hts_sni: db " sni=",0
str_hts_state: db " state=",0
str_hts_error: db " error=",0
str_hts_tcp: db " tcp_connected=",0
str_hts_records: db " records=",0
str_hts_messages: db " hs_messages=",0
str_hts_last_record: db " last_record=",0
str_hts_last_hs: db " last_hs=",0
str_hts_finished: db " peer_finished=",0
str_hts_trust: db " trust_path=",0
str_hts_rx: db " rx_pending=",0
str_hts_hs: db " hs_pending=",0
str_hts_entropy: db " entropy_degraded=",0
str_hts_witness: db " established=",0," cert_verified=",0," sni=",0," state=",0," error=",0," tcp_connected=",0," last_record=",0," last_hs=",0," peer_finished=",0," trust_path=",0," entropy_degraded=",0,0

; HTTPSTAT is an existing bounded diagnostic read. Plan only that native
; operation; unchanged nested dispatch owns all authority. Saved parser facts
; are not a new fetch, freshness or network/certificate/reachability proof.
; Shared producer staging is serialized by ordinary BSP command dispatch.
; Retire it before dispatch, validate the complete bounded record, then consume
; once into the hook reply. Only the numeric prefix is copied; arbitrary body
; bytes, URLs, headers and connection/IO operations are excluded.
; The pending byte is a serialized plan/post lifetime, not caller authority.
; Match the native end cursor to the bounded NUL; retire all 1400 shared bytes
; and the cursor/ready/pending state on every admitted post and plan attempt.
%if !PAOS_PUBLIC_BUILD
hook_http_plan:
    push rdi
    push rsi
    push rdx
    call hhp_retire
    pop  rdx
    pop  rsi
    pop  rdi
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad                            ; HTTP has one saved response
    cmp  byte [rdx], 0
    jne  .bad                            ; no URL, fetch or body selector
    mov  byte [rel hhp_pending], 1
    lea  rax, [rel str_hhp_verb]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

HST_HTTP_REPLY_MAX equ 1400               ; svc/command_web actual native buffer
hook_http_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .native_refused
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rcx
    cmp  byte [rel hhp_pending], 1
    jne  .bad_reply
    cmp  byte [rel http_cmd_out_ready], 1
    jne  .bad_reply
    lea  rdi, [rel http_cmd_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HST_HTTP_REPLY_MAX
    jae  .bad_reply
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel http_cmd_out_cur]
    jne  .bad_reply
    mov  r12d, ecx
    call hst_http_record
    test eax, eax
    jz   .bad_reply
    call command_hook_out_reset
    lea  rdi, [rel str_hhp_head]
    call command_hook_out_str
    lea  rdi, [rel http_cmd_out_buf]
    sub  r12, rdi                        ; validated prefix ends before body marker
    mov  esi, r12d
    call command_hook_out_strn
    jmp  .retire
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_hhp_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hhp_bad]
    mov  [rbx + RSP_HINT], rax
.retire:
    call hhp_retire
    add  rsp, 8
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.native_refused:
    sub  rsp, 8
    call hhp_retire
    add  rsp, 8
    xor  eax, eax                    ; preserve the original native code/hint
    ret

hhp_retire:
    mov  byte [rel hhp_pending], 0
    mov  byte [rel http_cmd_out_ready], 0
    mov  qword [rel http_cmd_out_cur], 0
    lea  rdi, [rel http_cmd_out_buf]
    mov  ecx, HST_HTTP_REPLY_MAX
    xor  eax, eax
    rep  stosb
    ret

; Parse the actual producer's ten numeric fields in exact order. The bounded
; native record may end with any body text (including truncation); none of those
; bytes enters the typed response or witness. u8/u32/u64 remain native widths.
%macro HHP_NUMBER 2
    lea  rsi, [rel %1]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    call hst_ss_u64
    test eax, eax
    jz   .no
%if %2 != -1
    mov  eax, %2
    cmp  r8, rax
    ja   .no
%endif
%endmacro
; RDI=bounded native record; success R12=exclusive numeric-prefix end.
hst_http_record:
    sub  rsp, 8
    HHP_NUMBER str_hhp_status, 0xffffffff
    HHP_NUMBER str_hhp_headers, 0xffffffff
    HHP_NUMBER str_hhp_clen, 0xffffffff
    HHP_NUMBER str_hhp_blen, 0xffffffff
    HHP_NUMBER str_hhp_state, 255
    HHP_NUMBER str_hhp_error, 255
    HHP_NUMBER str_hhp_framing, 255
    HHP_NUMBER str_hhp_present, 255
    HHP_NUMBER str_hhp_declared, -1
    HHP_NUMBER str_hhp_eof, 255
    mov  r12, rdi
    lea  rsi, [rel str_hhp_body]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    mov  eax, 1
    add  rsp, 8
    ret
.no:
    xor  eax, eax
    add  rsp, 8
    ret

align 8
hook_edge_http: times HE_SZ db 0
hhp_pending: db 0
str_hhp_name: db "http",0
str_hhp_verb: db "HTTPSTAT",0
str_hhp_head: db " http v=1 ",0
str_hhp_bad: db " hook err=http_reply_incomplete",0
str_hhp_schema: db "v=1 inst=none get=HTTPSTAT{status:u32,headers:u32,clen:u32,blen:u32,state:u8,framing_error:u8,framing:u8,cl_present:u8,declared:u64,eof:u8} authority=native diagnostic=saved-parser-not-fresh-fetch-or-reachability-proof body=omitted observe=all-returned-fields list=na set=na input=na cancel=na",0
str_hhp_status: db "status=",0
str_hhp_headers: db " headers=",0
str_hhp_clen: db " clen=",0
str_hhp_blen: db " blen=",0
str_hhp_state: db " state=",0
str_hhp_error: db " framing_error=",0
str_hhp_framing: db " framing=",0
str_hhp_present: db " cl_present=",0
str_hhp_declared: db " declared=",0
str_hhp_eof: db " eof=",0
str_hhp_body: db " body=",0
str_hhp_witness: db " status=",0," headers=",0," clen=",0," blen=",0," state=",0," framing_error=",0," framing=",0," cl_present=",0," declared=",0," eof=",0,0

; RCQ-15/49 saved native web digest. No fetch, model, raw-body, URL argument,
; transport or authority producer. HTTPBODY keeps every native source/principal/
; capability gate through common nested dispatch. The native renderer alone
; joins completed leaf-pinned HTTPS source, hashes and parser output. Text remains
; untrusted data. BSP serialization owns plan/post lifetime; no freshness claim.
hook_webdigest_plan:
    push rdi
    push rsi
    push rdx
    call hwd_retire
    pop  rdx
    pop  rsi
    pop  rdi
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rdx], 0
    jne  .bad
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rsi
    lea  rbx, [rel str_hwd_formats]
.next:
    mov  rdi, r12
    mov  rsi, rbx
    call strcmp                          ; exact native uppercase format spelling
    test eax, eax
    jz   .selected
.skip:
    cmp  byte [rbx], 0
    je   .advance
    inc  rbx
    jmp  .skip
.advance:
    inc  rbx
    cmp  byte [rbx], 0
    jne  .next
    add  rsp, 8
    pop  r12
    pop  rbx
    jmp  .bad
.selected:
    mov  [rel hwd_format], rbx
    call command_hook_arg_reset
    lea  rdi, [rel str_hwd_selector]
    call command_hook_arg_str
    mov  rdi, rbx
    call command_hook_arg_str
    mov  byte [rel hwd_pending], 1
    lea  rax, [rel str_hwd_verb]
    add  rsp, 8
    pop  r12
    pop  rbx
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

hook_webdigest_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .native_refused
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rcx
    cmp  byte [rel hwd_pending], 1
    jne  .bad_reply
    cmp  byte [rel http_cmd_out_ready], 1
    jne  .bad_reply
    lea  rdi, [rel http_cmd_out_buf]
    xor  ecx, ecx
.length:
    cmp  ecx, HST_HTTP_REPLY_MAX
    jae  .bad_reply
    cmp  byte [rdi + rcx], 0
    je   .bounded
    inc  ecx
    jmp  .length
.bounded:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel http_cmd_out_cur]
    jne  .bad_reply
    ; Shared HOOK capacity stays unchanged. A complete native digest that does
    ; not fit (including typed prefix and NUL) refuses; no clipped success.
    cmp  ecx, HOOK_OUT_MAX-HWD_TYPED_HEAD_LEN
    jae  .bad_reply
    mov  r12d, ecx
    call hwd_record
    test eax, eax
    jz   .bad_reply
    call command_hook_out_reset
    lea  rdi, [rel str_hwd_head]
    call command_hook_out_str
    lea  rdi, [rel http_cmd_out_buf]
    mov  esi, r12d
    call command_hook_out_strn
    jmp  .retire
.bad_reply:
    call command_hook_out_reset
    lea  rdi, [rel str_hwd_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel str_hwd_bad]
    mov  [rbx + RSP_HINT], rax
.retire:
    call hwd_retire
    add  rsp, 8
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.native_refused:
    sub  rsp, 8
    call hwd_retire
    add  rsp, 8
    xor  eax, eax                         ; preserve native code/hint, no text leak
    ret

hwd_retire:
    mov  byte [rel hwd_pending], 0
    mov  qword [rel hwd_format], 0
    jmp  hhp_retire                       ; same native 1400B/cursor/ready lifetime

%macro HWD_LITERAL 1
    lea  rsi, [rel %1]
    call hst_thermal_literal
    test eax, eax
    jz   .no
%endmacro
%macro HWD_NUMBER 2
    HWD_LITERAL %1
    call hst_ss_u64
    test eax, eax
    jz   .no
%if %2 != -1
    mov  eax, %2
    cmp  r8, rax
    ja   .no
%endif
%endmacro
; After bounded NUL/cursor join only. Exact full native field order; hashes
; lowercase64; canonical u64 times/u32 bounded lengths, selected format, ASCII
; text of exactly text_bytes. Do not parse text as metadata or instructions.
hwd_record:
    push r13
    push r14
    sub  rsp, 8
    HWD_NUMBER str_hwd_header, -1
    mov  r13, r8
    HWD_NUMBER str_hwd_end_time, -1
    cmp  r8, r13
    jb   .no
    HWD_NUMBER str_hwd_status, 299
    cmp  r8, 200
    jb   .no
    HWD_LITERAL str_hwd_url
    HWD_LITERAL str_hwd_https
    mov  ecx, 8
    xor  r14d, r14d                     ; explicit path slash must be present
.url:
    movzx eax, byte [rdi]
    cmp  al, ' '
    je   .url_end
    cmp  ecx, 192
    jae  .no
    cmp  al, '/'
    je   .slash
    cmp  al, '.'
    je   .url_char
    cmp  al, '-'
    je   .url_char
    cmp  al, '_'
    je   .url_char
    cmp  al, '~'
    je   .url_char
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .url_char
    cmp  al, 'A'
    jb   .no
    cmp  al, 'Z'
    jbe  .url_char
    cmp  al, 'a'
    jb   .no
    cmp  al, 'z'
    ja   .no
    jmp  .url_char
.slash:
    cmp  ecx, 8
    je   .no                            ; empty hostname
    mov  r14d, 1
.url_char:
    inc  ecx
    inc  rdi
    jmp  .url
.url_end:
    test r14d, r14d
    jz   .no
    HWD_NUMBER str_hwd_bytes, 1024
    HWD_LITERAL str_hwd_sha
    call hwd_hex64
    test eax, eax
    jz   .no
    HWD_LITERAL str_hwd_pin
    call hwd_hex64
    test eax, eax
    jz   .no
    HWD_LITERAL str_hwd_format
    mov  rsi, [rel hwd_format]
    call hst_thermal_literal
    test eax, eax
    jz   .no
    HWD_NUMBER str_hwd_text_bytes, 768
    mov  r13, r8
    HWD_LITERAL str_hwd_text
.text:
    test r13, r13
    jz   .end
    movzx eax, byte [rdi]
    cmp  eax, 32
    jb   .no
    cmp  eax, 126
    ja   .no
    inc  rdi
    dec  r13
    jmp  .text
.end:
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r14
    pop  r13
    ret
hwd_hex64:
    mov  ecx, 64
.next:
    movzx eax, byte [rdi]
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .char
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
.char:
    inc  rdi
    loop .next
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

align 8
hook_edge_webdigest: times HE_SZ db 0
hwd_format: dq 0
hwd_pending: db 0
str_hwd_name: db "webdigest",0
str_hwd_verb: db "HTTPBODY",0
str_hwd_selector: db "DIGEST ",0
str_hwd_formats: db "TEXT",0,"HTML",0,"FEED",0,"JSON",0,0
str_hwd_head: db " webdigest v=1 ",0
HWD_TYPED_HEAD_LEN equ $-str_hwd_head-1
str_hwd_bad: db " hook err=webdigest_reply_incomplete_or_too_large",0
str_hwd_schema: db "v=1 inst=TEXT|HTML|FEED|JSON get=HTTPBODY_DIGEST{source,url,boot-ms,2xx,body_bytes,body_sha256,pin_sha256,format,text_bytes,text} text=untrusted-ASCII source=native-https-leaf-pin model=none authority=native saved-not-fresh-fetch observe=all-bytes max-reply=1023 oversized=refuse list=na set=na input=na cancel=na",0
str_hwd_header: db "digest=v1 source=[1] origin=native-https trust=leaf-pin model=none clock=boot-ms started_ms=",0
str_hwd_end_time: db " finished_ms=",0
str_hwd_status: db " status=",0
str_hwd_url: db " url=",0
str_hwd_https: db "https://",0
str_hwd_bytes: db " body_bytes=",0
str_hwd_sha: db " body_sha256=",0
str_hwd_pin: db " pin_sha256=",0
str_hwd_format: db " format=",0
str_hwd_text_bytes: db " text_bytes=",0
str_hwd_text: db " text=",0

%endif
