;; MODULE svc/command_audit
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS audit_sec_mca_drain, audit_sec_aer_event, audit_sec_session_unlock, audit_log_line, audit_log_net, audit_replace_newest, audit_selftest, cmd_verb_audit, audit_sec_event, audit_sec_rsp_meta, audit_sec_save, audit_sec_restore, audit_guardian_watch_tick, audit_sec_advisor_view, audit_sec_held, audit_sec_iommu_sync, audit_sec_iommu_event, audit_sec_iommu_amd_event, audit_sec_hid_drain, audit_sec_arp_drain, audit_sec_keyprov_refusal, audit_sec_airlock_drain
;; IMPORTS core/mca_poll, svc/cpu_policy_report, boot/serial, boot/header, core/lib/fmt, core/lib/mem, core/lib/str, core/time, core/capability, sec/principal, svc/command, svc/resilience, dev/usb/hid, net/arp_cache, svc/command_udp, sec/airlock, svc/guardian_alert, sec/cpu_security_report, sec/cpu_microcode_bsp_report
;; CAPS
;; OWNER saga:command
; ============================================================================
; svc/command_audit.asm — the PER-ACTION AUDIT RECEIPT ring (contract 1314,
; CRUCIBLE §9 Pillar-4 row 1 "owned/auditable AI").
;
; THE claim this module makes concrete: every AI/automation action on PaOS is a
; logged command through the ONE registry. The UDP projection calls
; audit_log_line with the FULL raw command line (verb + args, including any
; caller nonce) BEFORE dispatch, so N actions leave N content-bearing receipts
; — a counter can't fake nonces it never saw. The AUDIT verb reads the
; receipts back over the same wire for content grading (capdemo probe:
; receipts_per_action == 1.0, nonce-matched).
;
; Scope note: the ring records the UDP projection (the demo's drive surface).
; The serial projection shares command_dispatch but stages its own lines; a
; dispatch-level hook is the follow-up seam if serial actions need receipts.
;
; Ring: fixed-stride in-image records (seq qword + bounded NUL-terminated
; text), head wraps — same shape as core/diag's ring but svc-layer and
; TEXT-bearing (diag's 24-byte tag can't hold a nonce-tagged command line).
;
; Network-access gate rule 3 (PETER RULING 2026-09-29 "all remote access is
; audit-logged"): every REMOTE attempt — AUTH1/UDP and SSH, accepted AND
; refused — leaves exactly ONE row carrying structured metadata (source,
; service, authenticated principal, canonical verb, result/reason, boot-ms
; time; the seq is the row id). An accepted UDP line keeps its redacted
; command text (the 1314 nonce receipt) and gains the metadata; a refusal is a
; new text row "NET src=.. res=refused:<reason> verb=<VERB> pid=.." that never
; carries arguments. Refusal floods are coalesced (audit_log_net) so they can
; never wash the ring. `AUDIT [n]` output is unchanged for existing rows;
; `AUDIT net [n]` reads the structured view.
;
; GD1 security-event spine, first slice (ADMIN_INBOX_20260929_guardian_security
; §5): a SEPARATE fixed-size typed RAM ring beside the text ring above, which
; keeps its layout, APIs and output. A typed record holds only bounded numbers
; and enums - seq, t_us (time_monotonic_now_us), class, principal, subject,
; verdict, reason - never argument strings, command text, prompt contents,
; credentials or addresses. Only a principal the PRODUCER verified
; (PRIN_OWNER/PRIN_SYSTEM) takes a ring slot; every other event folds into a
; coalesced class x verdict counter with first/last t_us, so unauthenticated
; floods can never evict authenticated records. Overwriting the oldest record
; counts sec_drop. Producers in this slice: the two AI-hook exits
; (svc/command_aihook), remote decisions and native IOMMU observations.
; The IOMMU public INFO cell is a trusted observation aggregate; at most four
; native typed rows are held. Native boot-HID refusals have a separate lower-layer queue; net_arp is reserved for
; later rungs and have no producer yet. `AUDIT sec [n]` reads it back through
; the same verb and the same remote gate as `AUDIT`. RAM only: lost on reboot,
; never sent anywhere else.
; ============================================================================

AUDIT_NREC     equ 32              ; receipt capacity (ring wraps)
AUDIT_TXT      equ 72              ; text bytes per receipt (bounded, NUL-terminated)
AUDIT_REC_SZ   equ 144             ; 8-byte seq + AUDIT_TXT text + 64-byte remote-attempt metadata
AUDIT_DUMP_DEF equ 12              ; AUDIT dump default/cap (UDP reply budget)
AUDIT_NET_DEF  equ 8               ; AUDIT net dump default/cap (structured rows are wider)
AUDIT_OUT_MAX  equ 1536            ; staged dump buffer (every put is bounded by it)
AUDIT_VERB_MAX equ 24              ; canonical verb name bytes kept per row (NUL-terminated)

; ---------------------------------------------------------------------------
; Record layout. A receipt's slot is always seq mod AUDIT_NREC (seq and head
; advance together), so a coalesced row can be found again by its seq.
;   +0   seq       qword
;   +8   text      AUDIT_TXT bytes, NUL-terminated (what plain AUDIT prints)
;   +80  kind      0 = local/internal receipt, 1 = remote-attempt row (net)
;   +81  src       AUDIT_NSRC_*        (net rows)
;   +82  svc       AUDIT_NSVC_*
;   +83  res       AUDIT_NRES_*
;   +84  count     dword: attempts folded into this row (>= 1)
;   +88  pid       principal id the attempt AUTHENTICATED as (0 = none)
;   +96  t         boot ms of the first attempt
;   +104 tlast     boot ms of the latest folded attempt
;   +112 reason    cstr pointer (refused/blocked reason; 0 for admit)
;   +120 verb      canonical verb name (never arguments)
; ---------------------------------------------------------------------------
AR_SEQ    equ 0
AR_TEXT   equ 8
AR_KIND   equ 80
AR_SRC    equ 81
AR_SVC    equ 82
AR_RES    equ 83
AR_COUNT  equ 84
AR_PID    equ 88
AR_T      equ 96
AR_TLAST  equ 104
AR_REASON equ 112
AR_VERB   equ 120

AUDIT_KIND_LOCAL equ 0
AUDIT_KIND_NET   equ 1
AUDIT_NSRC_UDP   equ 1             ; AUTH1/UDP command projection (:9997/:9998)
AUDIT_NSRC_SSH   equ 2             ; SSH server
AUDIT_NSVC_AUTH1 equ 1             ; the AUTH1-UDP command service
AUDIT_NSVC_SSH   equ 2             ; the SSH service (userauth + exec)
AUDIT_NRES_ADMIT   equ 1
AUDIT_NRES_BLOCKED equ 2           ; net_access_policy_allows said no
AUDIT_NRES_REFUSED equ 3
; audit_log_net packed meta (ESI): src | svc << 8 | res << 16 [| AUDIT_NET_FRESH]
%define AUDIT_NET_META(src, svc, res) ((src) | ((svc) << 8) | ((res) << 16))
AUDIT_NET_FRESH equ 1 << 24        ; admit proven FRESH (consumed AUTH1 seq / SSH-bound): an anchor
; Flood rule (GD1 spirit): non-admit rows appended since the last anchor (a
; local receipt, or an admit whose authentication is fresh and so cannot be
; replayed by an attacker) are capped at AUDIT_NET_RUN_MAX; past the cap every
; further refusal folds into ONE flood row (repeat count), so refusals alone
; can never evict more than RUN_MAX+1 receipts.
AUDIT_NET_RUN_MAX equ 4

; ---------------------------------------------------------------------------
; GD1 typed security-event record (fixed AUDIT_SEC_REC_SZ; a record's slot is
; always seq mod AUDIT_SEC_NREC):
;   +0   seq      qword  +1 per typed record (public counters never take one)
;   +8   t        qword  time_monotonic_now_us, held non-decreasing
;   +16  subject  dword  producer subject (aihook: registry verb id; a wider
;                        value is stored as 0xFFFFFFFF)
;   +20  reason   word   AUDIT_SEC_R_*
;   +22  class    byte   AUDIT_SEC_C_*
;   +23  verdict  byte   AUDIT_SEC_V_*
;   +24  prin     byte   PRIN_OWNER, PRIN_SYSTEM or PRIN_ADVISOR (nothing else is stored)
;   +25  native backend/provenance (1=live VT-d,2=live boot-HID consumer,3=native ARP receive)
;   +26  native boot-local epoch u16; +28 native serial u32 (otherwise zero)
; ---------------------------------------------------------------------------
AUDIT_SEC_NREC     equ 64              ; typed records (a power of two; ring wraps)
AUDIT_SEC_REC_SZ   equ 32
AUDIT_SEC_DEF      equ 12              ; AUDIT sec dump default/cap (fits audit_out_buf, see below)
AUDIT_SEC_PUB_SZ   equ 24              ; public cell: count, first t, last t (qwords)
ASR_SEQ     equ 0
ASR_T       equ 8
ASR_SUBJECT equ 16
ASR_REASON  equ 20
ASR_CLASS   equ 22
ASR_VERDICT equ 23
ASR_PRIN    equ 24
ASR_BACKEND equ 25
ASR_EPOCH   equ 26
ASR_EVENT   equ 28
; Invalid classes normalize to RESERVED; existing class numbers remain stable.
AUDIT_SEC_C_VERB         equ 1         ; one remote UDP/SSH admit (audit_net_sec_account)
AUDIT_SEC_C_AIHOOK       equ 2         ; one command_aihook_submit[_authorized] outcome
AUDIT_SEC_C_AUTH_REFUSED equ 3         ; credential/binding refused before any dispatch
AUDIT_SEC_C_NET_ARP      equ 4         ; native ARP drop observation, no sender authentication
AUDIT_SEC_C_USB_HID      equ 5         ; live boot-HID consumer refusal observation
AUDIT_SEC_C_IOMMU        equ 6         ; native VT-d observation, no enforcement claim
AUDIT_SEC_C_GUARDIAN     equ 7         ; Guardian watch-tier SHADOW decision (no effect; SEC-GA1)
AUDIT_SEC_C_HISTORY      equ 8         ; svc/history: a query, reopen or clear, or a refused append (RC-history H1)
AUDIT_SEC_C_RESERVED     equ 9
AUDIT_SEC_C_HARDWARE     equ 10        ; native AER/MCA observations, handling unknown
AUDIT_SEC_NCLASS         equ 10
; verdict: 0 or anything above INFO is stored as INFO, never as allowed/refused
AUDIT_SEC_V_ALLOWED equ 1              ; admitted, and the synchronous response was OK
AUDIT_SEC_V_REFUSED equ 2              ; an authority/policy gate refused it
AUDIT_SEC_V_HELD    equ 3              ; subject held for owner action (reserved: GU0/GU1)
AUDIT_SEC_V_INFO    equ 4              ; neither: an operational/input error or an unknown code
AUDIT_SEC_NVERDICT  equ 4
; reason (u16)
AUDIT_SEC_R_ARP_NATIVE     equ 0x0800  ; | reason1..3, native parser/cache observation
AUDIT_ARP_MAX_LIVE         equ 4
AUDIT_SEC_R_HID_NATIVE     equ 0x0700  ; | reason1..5, live driver observation only
AUDIT_HID_MAX_LIVE         equ 4
AUDIT_SEC_R_IOMMU_AMD      equ 0x0900  ; |2 IO_PAGE_FAULT, backend4
AUDIT_SEC_R_IOMMU_VTD      equ 0x0600  ; | FRCD reason byte: observed live VT-d fault
AUDIT_AER_MAX_LIVE         equ 4       ; independent finite native hardware detail quota
AUDIT_SEC_R_MCA_OBSERVED   equ 0x0D01  ; CPU summary of passive non-corrected samples; handling unknown
AUDIT_SEC_R_AER_POLL       equ 0x0C00  ; |1 nonfatal,2 fatal,3 both; observation only
AUDIT_IOMMU_MAX_LIVE       equ 4       ; native storms cannot wash owner records
AUDIT_SEC_R_SESSION_NATIVE equ 0x0A00 ; bounded native session outcome/ingress/method
AUDIT_SEC_R_HISTORY_APPEND equ 0x0B00 ; | HIST_* refusal; subject = producer id (unverified: public fold)
AUDIT_SEC_R_HISTORY_QUERY  equ 0x0B40 ; | HIST_* status; subject = rows (allowed) or requester
AUDIT_SEC_R_HISTORY_REOPEN equ 0x0B80 ; subject = the record's category (allowed)
AUDIT_SEC_R_HISTORY_CLEAR  equ 0x0BC0 ; subject = records removed (counts, never content)
AUDIT_SESSION_MAX_LIVE    equ 4
AUDIT_SEC_R_NONE           equ 0x0000
AUDIT_SEC_R_DISPATCH       equ 0x0100  ; | CMDE_*: the final SYNCHRONOUS RSP_CODE (0x0100 = OK)
AUDIT_SEC_R_JOB_ADMITTED   equ 0x0180  ; CMDE_OK + RSP_ACCEPTED: a job was admitted, completion NOT observed
AUDIT_SEC_R_DISPATCH_OTHER equ 0x01FF  ; an RSP_CODE outside the audit_sec_rsp_meta table
AUDIT_SEC_R_PREBIND        equ 0x0200  ; credential init/fetch or binding did not yield the principal
AUDIT_SEC_R_NET            equ 0x0300  ; | svc << 4 | src: one audit_log_net remote decision (SEC-GD1b)
AUDIT_SEC_R_ADVISOR        equ 0x0500  ; GA2(b): an advisor-originated verb, never dispatched
AUDIT_SEC_R_ADVISOR_FILE   equ 0x0501  ; native VFS file advice, never dispatched
ADVISOR_MAX_LIVE           equ 4       ; typed advisor records held at once; beyond: public counter
AUDIT_SEC_R_SHADOW_REFUSAL_BURST equ 0x0400 ; GA1 shadow: would tighten after a remote-refusal burst
AUDIT_SEC_R_SHADOW_OBSERVATION_BURST equ 0x0401 ; positive native INFO delta, alone or mixed with refusals

; SEC-GA1 Guardian watch tier (shadow). Deterministic, no model, no authority.
GUARDIAN_WATCH_MS     equ 10000        ; one look per 10 s from the idle loop
GUARDIAN_BURST        equ 16           ; >= this many new refusals in a window = a burst
GUARDIAN_MIN_GAP_MS   equ 300000       ; at most one typed shadow record per 5 min
GUARDIAN_MAX_LIVE     equ 4            ; at most this many shadow records held in the typed ring
AUDIT_VIEW_SEC equ 2                   ; audit_parse_view EDX for `AUDIT sec`
AUDIT_VIEW_GUARDIAN equ 3              ; read-only retained watch state, no count
AUDIT_VIEW_GUARDIAN_SOURCES equ 4      ; strict current owner-seen source snapshot
AUDIT_VIEW_GUARDIAN_WINDOW equ 5       ; retained window minimum/quality only
; Legacy base-field bound with every decimal at its widest (u64 20, u32 10, u16 5):
;   header " audit sec_seq=<20> n=<2> view=sec sec_drop=<20> pub_ok=<20>
;          pub_refused=<20> pub_held=<20> pub_info=<20> pub_first=<20> pub_last=<20>"
;   row    CRLF "S<20> t=<20> c=<12> p=<7> s=<10> v=<7> r=<5>"
; These base fields fit the staging buffer. Native i=/b= extensions and the
; UDP envelope/hooks can exceed that budget. audit_out_full records incomplete
; staging; UDP sends the complete snapshot or an explicit REFUSED envelope.
AUDIT_SEC_HDR_MAX  equ 261
AUDIT_SEC_ROW_MAX  equ 103             ; base fields only; native extensions checked at runtime
    times -((AUDIT_SEC_HDR_MAX + AUDIT_SEC_DEF * AUDIT_SEC_ROW_MAX + 24) > AUDIT_OUT_MAX) db 0
    times -((PRIN_OWNER != 1) | (PRIN_SYSTEM != 2) | (PRIN_ADVISOR != 3)) db 0  ; audit_sec_prin_names order

; audit_claim_slot -> RAX = the next record, zeroed, seq stamped; advances
;   seq/head. At UINT64_MAX returns 0 before touching the ring/head and counts
;   one unstored attempt (saturating). MAX is never a receipt or flood identity.
;   clobbers: RAX,RCX,RDX,RSI,RDI.
audit_claim_slot:
    push rbx
    cmp  qword [rel audit_seq], -1
    je   .exhausted
    mov  eax, [rel audit_head]
    imul rax, rax, AUDIT_REC_SZ
    lea  rbx, [rel audit_ring]
    add  rbx, rax
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, AUDIT_REC_SZ
    call memset                         ; no stale bytes of an older receipt survive
    mov  rax, [rel audit_seq]
    mov  [rbx + AR_SEQ], rax
    inc  qword [rel audit_seq]
    mov  eax, [rel audit_head]
    inc  eax
    cmp  eax, AUDIT_NREC
    jb   .store
    xor  eax, eax                       ; wrap
.store:
    mov  [rel audit_head], eax
    mov  rax, rbx
    pop  rbx
    ret
.exhausted:
    add  qword [rel audit_legacy_unstored], 1
    jnc  .counted
    mov  qword [rel audit_legacy_unstored], -1
.counted:
    xor  eax, eax
    pop  rbx
    ret

; audit_newest_ptr -> RAX = newest record (caller checks audit_seq != 0).
;   clobbers: RAX,RCX,RDX.
audit_newest_ptr:
    mov  eax, [rel audit_head]
    add  eax, AUDIT_NREC - 1
    xor  edx, edx
    mov  ecx, AUDIT_NREC
    div  ecx
    mov  eax, edx
    imul rax, rax, AUDIT_REC_SZ
    lea  rcx, [rel audit_ring]
    add  rax, rcx
    ret

; audit_net_anchor — a trusted receipt ends the current refusal run.
audit_net_anchor:
    mov  dword [rel audit_net_run], 0
    mov  qword [rel audit_net_flood_seq], -1
    ret

; ---------------------------------------------------------------------------
; audit_log_line(RDI = NUL-terminated command line) — append ONE receipt.
;   Local/internal receipts (session unlock records, PUSH events, boot KATs).
;   Remote attempts use audit_log_net. Empty line -> no receipt.
;   clobbers: caller-saved (RBX preserved).
; ---------------------------------------------------------------------------
audit_log_line:
    push rbx
    cmp  byte [rdi], 0
    je   .done                          ; empty line: no action, no receipt
    mov  rbx, rdi
    call audit_claim_slot
    test rax, rax
    jz   .anchor
    lea  rdi, [rax + AR_TEXT]
    mov  rsi, rbx
    mov  edx, AUDIT_TXT
    call audit_store_text               ; bounded, control bytes escaped, ALWAYS NUL-terminates
.anchor:
    call audit_net_anchor               ; trusted local activity still ends a refusal run
.done:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; audit_log_net — ONE structured row per REMOTE attempt (PETER RULING
; 2026-09-29 rule 5 "all remote access is audit-logged"; network-access gate
; design rule 3), accepted AND refused.
;   RDI = row text (plain AUDIT shows it; callers never pass credential bytes)
;   ESI = AUDIT_NET_META(src, svc, res), | AUDIT_NET_FRESH for a fresh-auth admit
;   RDX = principal the attempt authenticated as (0 = none)
;   RCX = reason cstr (refused/blocked) or 0
;   R8  = canonical verb cstr (never arguments; 0 -> "-")
;   -> RAX = 1 a new row was appended, 0 the attempt was folded into an
;      existing row (identical newest row, or the run's flood row), or counted
;      as unstored at sequence exhaustion. No receipt identity is then minted.
; Coalescing (refused/blocked only): identical to the newest row -> count+1;
; else a new row while the run is below AUDIT_NET_RUN_MAX; else the run's
; single flood row absorbs it. Admits always append; a FRESH admit anchors
; (ends the run): a replayed signed public read is admitted but never anchors.
; clobbers: caller-saved (RBX,R12-R15 kept).
; ---------------------------------------------------------------------------
audit_log_net:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, esi
    mov  r13, rdx
    mov  r14, rcx
    mov  r15, r8
    ; bounded candidate copies: the key compare and the stored bytes agree
    mov  rsi, rdi
    lea  rdi, [rel audit_net_text_tmp]
    mov  edx, AUDIT_TXT
    call audit_store_text               ; escaped HERE so compare + stored row agree
    lea  rbx, [rel audit_net_text_tmp]
    test r15, r15
    jnz  .verb
    lea  r15, [rel str_audit_dash]
.verb:
    mov  rsi, r15
    lea  rdi, [rel audit_net_verb_tmp]
    mov  edx, AUDIT_VERB_MAX
    call audit_store_text
    lea  r15, [rel audit_net_verb_tmp]
    call boot_ms_now                    ; clobbers RAX,RCX,RDX
    mov  [rel audit_net_now], rax
    mov  eax, r12d
    shr  eax, 16
    cmp  al, AUDIT_NRES_ADMIT
    jne  .refusal
    test r12d, AUDIT_NET_FRESH
    jz   .append
    call audit_net_anchor               ; fresh authenticated admit: trusted anchor
    jmp  .append
.refusal:
    cmp  qword [rel audit_seq], 0
    je   .run
    call audit_newest_ptr
    mov  rdi, rax
    call audit_net_same
    test eax, eax
    jz   .run
    call audit_net_bump                 ; RDI = newest (preserved by audit_net_same)
    xor  eax, eax
    jmp  .out
.run:
    cmp  dword [rel audit_net_run], AUDIT_NET_RUN_MAX
    jae  .flood
    inc  dword [rel audit_net_run]
    jmp  .append
.flood:
    mov  rax, [rel audit_net_flood_seq]
    cmp  rax, -1
    je   .flood_new
    mov  rcx, [rel audit_seq]
    cmp  rax, rcx
    jae  .flood_new                     ; no current/future hint or wrapped age
    sub  rcx, rax                       ; age (>= 1), sequence never wraps
    cmp  rcx, AUDIT_NREC
    ja   .flood_new                     ; the flood row was overwritten
    xor  edx, edx
    mov  ecx, AUDIT_NREC
    div  rcx                            ; RDX = slot of that seq
    imul rdx, rdx, AUDIT_REC_SZ
    lea  rdi, [rel audit_ring]
    add  rdi, rdx
    mov  rax, [rel audit_net_flood_seq]
    cmp  [rdi + AR_SEQ], rax
    jne  .flood_new
    lea  rax, [rel str_audit_r_flood]
    cmp  [rdi + AR_REASON], rax
    jne  .flood_new
    mov  eax, r12d
    cmp  [rdi + AR_SRC], al
    je   .flood_src_ok
    mov  byte [rdi + AR_SRC], 0         ; mixed sources -> "any"
.flood_src_ok:
    shr  eax, 8
    cmp  [rdi + AR_SVC], al
    je   .flood_svc_ok
    mov  byte [rdi + AR_SVC], 0
.flood_svc_ok:
    call audit_net_bump
    xor  eax, eax
    jmp  .out
.flood_new:
    lea  rbx, [rel str_audit_flood_text]
    xor  r13d, r13d                     ; a flood row names no principal
    lea  r14, [rel str_audit_r_flood]
    lea  r15, [rel str_audit_star]
    and  r12d, 0x00FFFF
    or   r12d, AUDIT_NRES_REFUSED << 16
    call audit_net_append
    test rax, rax
    jz   .unstored
    mov  rax, [rax + AR_SEQ]
    mov  [rel audit_net_flood_seq], rax
    mov  eax, 1
    jmp  .out
.append:
    call audit_net_append
    test rax, rax
    jz   .unstored
    mov  eax, 1
    jmp  .out
.unstored:
    ; No legacy row exists for this attempt: retain the real result in public
    ; accounting, never lend an older receipt identity to a fresh principal.
    ; Fresh authentication already anchored above; this changes no permission.
    and  r12d, ~AUDIT_NET_FRESH
    xor  eax, eax
.out:
    push rax
    mov  edi, r12d
    mov  rsi, r13
    call audit_net_sec_account          ; every remote attempt, appended or folded
    pop  rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; audit_net_sec_account(EDI = AUDIT_NET_META | FRESH, RSI = row principal) —
;   the ONE GD1 spine event of an audit_log_net remote decision (SEC-GD1b).
;   A typed record only for an admit proven FRESH with a verified principal (a
;   consumed AUTH1 sequence or an SSH-bound exec): such an admit cannot be
;   replayed, so a LAN peer cannot mint owner records that evict real ones.
;   Every other admit is a VERB/allowed public count. A refusal or block is an
;   AUTH_REFUSED/refused count and NEVER trusts the principal: an expired or
;   replayed owner envelope carries a signature-verified principal.
;   Reason = AUDIT_SEC_R_NET | svc << 4 | src. Subject = AR_SEQ of the newest
;   net row (exact for a typed record, which always appends its own row).
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
audit_net_sec_account:
    mov  edx, edi
    shr  edx, 8
    and  edx, 0x0F                      ; svc
    shl  edx, 4
    mov  eax, edi
    and  eax, 0x0F                      ; src
    or   edx, eax
    or   edx, AUDIT_SEC_R_NET
    shl  edx, 16                        ; reason field
    mov  eax, edi
    shr  eax, 16
    and  eax, 0xFF                      ; res
    cmp  eax, AUDIT_NRES_ADMIT
    jne  .refused
    xor  r8d, r8d
    test edi, AUDIT_NET_FRESH
    jz   .admit_pub
    mov  r8, rsi
.admit_pub:
    mov  edi, AUDIT_SEC_C_VERB | (AUDIT_SEC_V_ALLOWED << 8)
    jmp  .emit
.refused:
    xor  r8d, r8d                       ; never the row principal (see above)
    mov  edi, AUDIT_SEC_C_AUTH_REFUSED | (AUDIT_SEC_V_REFUSED << 8)
.emit:
    or   edi, edx
    push rdi
    push r8
    call audit_newest_ptr
    mov  rdx, [rax + AR_SEQ]
    pop  rsi
    pop  rdi
    jmp  audit_sec_event

; ---------------------------------------------------------------------------
; audit_guardian_watch_tick — SEC-GA1, the Guardian watch tier in SHADOW mode
;   (RC spec 10.5; Guardian SG rules). Called from the idle loop. Every
;   GUARDIAN_WATCH_MS it differences independent refusal and native INFO totals.
;   When their combined window reaches GUARDIAN_BURST after a quiet window,
;   it records ONE typed decision: class GUARDIAN,
;   verdict HELD ("would tighten"), reason SHADOW_REFUSAL_BURST for refusal-only
;   windows or SHADOW_OBSERVATION_BURST when a positive native INFO delta
;   contributes. Neither reason asserts an attack or enforcement. Subject = the
;   burst size, principal SYSTEM (in-image, deterministic). It enforces nothing
;   and calls no verb: shadow mode has no authority, so a wrong or absent
;   verdict can never allow or block anything. Records are rate-limited to
;   one per GUARDIAN_MIN_GAP_MS (12/h) and at most GUARDIAN_MAX_LIVE of them
;   are ever held in the 64-slot typed ring, so a sustained refusal flood can
;   displace at most that many owner records. A counter that went DOWN (a KAT
;   bracket restore) resyncs that source only; independent growth is retained.
;   KAT ticks leave all watch state untouched until the spine is restored.
;   Native software-mask denials (including deliberate probes) are observations
;   in the same window, with no hardware-enforcement or attack attribution.
;   Native ARP and IOMMU INFO totals are independent observations too, not
;   attack attribution, AI authority, mitigation or automatic blocking.
;   A nonzero clock establishes the earliest look. Zero/reset defers a full
;   new window and restarts an existing emission cooldown, without consuming
;   counters or rearming a burst. An overflowing deadline saturates and waits
;   for an observed reset; repeated timestamps never fabricate elapsed time.
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
audit_guardian_watch_tick:
    push rbx
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out                              ; synthetic KAT events never consume a window
    call audit_sec_mca_drain                ; bounded retained CPU observations; BSP writer only
    call iommu_sec_drain                    ; finite2 native records before10s refusal watch
    call audit_sec_hid_drain                ; finite2 lower-layer HID observations
    call audit_sec_arp_drain                ; finite2 native ARP detail attempts
%if !PAOS_PUBLIC_BUILD
    call audit_sec_airlock_drain            ; finite2 queued native AIRLOCK reasons
%endif
    call boot_ms_now
    mov  rbx, rax
    test rax, rax
    jz   .clock_zero                       ; boot origin/scale unavailable
    cmp  byte [rel audit_guardian_clock_state], 0
    je   .clock_sample                     ; preserve the earliest valid look
    cmp  byte [rel audit_guardian_clock_state], 2
    je   .clock_rebase                     ; recovery after an unavailable clock
    cmp  rbx, [rel audit_guardian_clock_ms]
    jb   .clock_rebase                     ; reset: no elapsed window asserted
    mov  [rel audit_guardian_clock_ms], rbx
    cmp  byte [rel audit_guardian_clock_state], 3
    je   .out                              ; no representable next deadline
    cmp  rbx, [rel audit_guardian_next_ms]
    jb   .out
.clock_sample:
    mov  r9d, 1
    jmp  .clock_schedule
.clock_rebase:
    mov  byte [rel audit_guardian_window_quality], 0 ; no completed window after reset
    cmp  qword [rel audit_guardian_last_emit_ms], 0
    je   .clock_rebased
    mov  [rel audit_guardian_last_emit_ms], rbx
.clock_rebased:
    xor  r9d, r9d                          ; retain counters and burst latch
.clock_schedule:
    mov  [rel audit_guardian_clock_ms], rbx
    mov  byte [rel audit_guardian_clock_state], 1
    mov  rax, rbx
    add  rax, GUARDIAN_WATCH_MS
    jnc  .clock_deadline
    mov  rax, -1
    mov  byte [rel audit_guardian_clock_state], 3
.clock_deadline:
    mov  [rel audit_guardian_next_ms], rax
    test r9d, r9d
    jz   .out
    xor  r11d, r11d                        ; sampled saturated-source bits, row order
    xor  r9d, r9d                          ; aggregate delta addition overflow
    ; AUTH ingress deliberately uses the public cell even for verified but
    ; refused envelopes. AI uses its all-principal total, including the public
    ; subset ONCE. Difference each source before a saturating combine: a full
    ; source must not hide the other's growth, nor may one reset erase it.
    mov  rax, [rel audit_sec_pub + (((AUDIT_SEC_C_AUTH_REFUSED - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_REFUSED - 1) * AUDIT_SEC_PUB_SZ)]
    cmp  rax, -1
    jne  .auth_quality_exact
    or   r11d, 1
.auth_quality_exact:
    mov  rdx, rax
    sub  rdx, [rel audit_guardian_last_refused]
    mov  [rel audit_guardian_last_refused], rax
    jae  .auth_delta
    xor  edx, edx                          ; reset: zero delta, new baseline
.auth_delta:
    mov  rax, [rel audit_aihook_refused]
    cmp  rax, -1
    jne  .ai_quality_exact
    or   r11d, 16
.ai_quality_exact:
    mov  rcx, rax
    sub  rcx, [rel audit_guardian_last_aihook_refused]
    mov  [rel audit_guardian_last_aihook_refused], rax
    jae  .ai_delta
    xor  ecx, ecx                          ; reset only this source
.ai_delta:
    mov  rax, [rel cap_denied_count]
    cmp  rax, -1
    jne  .cap_quality_exact
    or   r11d, 32
.cap_quality_exact:
    mov  r8, rax
    sub  r8, [rel audit_guardian_last_cap_refused]
    mov  [rel audit_guardian_last_cap_refused], rax
    jae  .cap_delta
    xor  r8d, r8d                          ; reset only this source
.cap_delta:
    add  rcx, r8
    jnc  .cap_sum_ok
    mov  r9d, 1                           ; known sum is only a saturating minimum
    mov  rcx, -1
.cap_sum_ok:
    ; Native key-provenance refusals are not in the remote AUTH public cell.
    ; Difference the independent total once, including quota/sequence folds.
    mov  rax, [rel audit_keyprov_refused]
    cmp  rax, -1
    jne  .keyprov_quality_exact
    or   r11d, 256
.keyprov_quality_exact:
    mov  r8, rax
    sub  r8, [rel audit_guardian_last_keyprov_refused]
    mov  [rel audit_guardian_last_keyprov_refused], rax
    jae  .keyprov_delta
    xor  r8d, r8d                          ; reset only this source
.keyprov_delta:
    add  rcx, r8
    jnc  .keyprov_sum_ok
    mov  r9d, 1                           ; known sum is only a saturating minimum
    mov  rcx, -1
.keyprov_sum_ok:
    ; Native session outcomes have their own total, including quota folds.
    ; Count each once without folding into remote AUTH or acknowledging alerts.
    mov  rax, [rel audit_session_refused]
    cmp  rax, -1
    jne  .session_quality_exact
    or   r11d, 128
.session_quality_exact:
    mov  r8, rax
    sub  r8, [rel audit_guardian_last_session_refused]
    mov  [rel audit_guardian_last_session_refused], rax
    jae  .session_delta
    xor  r8d, r8d                          ; reset only this source
.session_delta:
    add  rcx, r8
    jnc  .session_sum_ok
    mov  r9d, 1                           ; known sum is only a saturating minimum
    mov  rcx, -1
.session_sum_ok:
%if !PAOS_PUBLIC_BUILD
    ; Native AIRLOCK refusals include honest boot probes and lost details.
    ; Sample the lifetime total once, independently of queue drain and seen.
    mov  rax, [rel airlock_refused_count]
    cmp  rax, -1
    jne  .airlock_quality_exact
    or   r11d, 64
.airlock_quality_exact:
    mov  r8, rax
    sub  r8, [rel audit_guardian_last_airlock_refused]
    mov  [rel audit_guardian_last_airlock_refused], rax
    jae  .airlock_delta
    xor  r8d, r8d                          ; reset only this source
.airlock_delta:
    add  rcx, r8
    jnc  .airlock_sum_ok
    mov  r9d, 1                           ; known sum is only a saturating minimum
    mov  rcx, -1
.airlock_sum_ok:
%endif
    xor  r10d, r10d                        ; window-local positive INFO contribution
    ; Native boot-HID refusals are INFO observations, never attack claims.
    ; The trusted BSP summary includes lost details; difference it once.
    mov  rax, [rel audit_sec_pub + (((AUDIT_SEC_C_USB_HID - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    cmp  rax, -1
    jne  .hid_quality_exact
    or   r11d, 4
.hid_quality_exact:
    mov  r8, rax
    sub  r8, [rel audit_guardian_last_hid_refused]
    mov  [rel audit_guardian_last_hid_refused], rax
    jae  .hid_delta
    xor  r8d, r8d                          ; reset only this source
.hid_delta:
    or   r10, r8                           ; classify only the reset-clamped u64 delta
    add  rcx, r8
    jnc  .hid_sum_ok
    mov  r9d, 1                           ; known sum is only a saturating minimum
    mov  rcx, -1
.hid_sum_ok:
    ; ARP INFO is the normalized native lifetime total, including lost detail.
    ; Typed records, drops and coalescing are not additional observations.
    mov  rax, [rel audit_sec_pub + (((AUDIT_SEC_C_NET_ARP - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    cmp  rax, -1
    jne  .arp_quality_exact
    or   r11d, 8
.arp_quality_exact:
    mov  r8, rax
    sub  r8, [rel audit_guardian_last_arp_observed]
    mov  [rel audit_guardian_last_arp_observed], rax
    jae  .arp_delta
    xor  r8d, r8d                          ; reset only this source
.arp_delta:
    or   r10, r8                           ; classify only the reset-clamped u64 delta
    add  rcx, r8
    jnc  .arp_sum_ok
    mov  r9d, 1                           ; known sum is only a saturating minimum
    mov  rcx, -1
.arp_sum_ok:
    ; IOMMU INFO already combines native backends and omitted detail once.
    ; No source/owner seen mark is changed; GUARDIAN output never feeds back.
    mov  rax, [rel audit_sec_pub + (((AUDIT_SEC_C_IOMMU - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    cmp  rax, -1
    jne  .iommu_quality_exact
    or   r11d, 2
.iommu_quality_exact:
    mov  r8, rax
    sub  r8, [rel audit_guardian_last_iommu_observed]
    mov  [rel audit_guardian_last_iommu_observed], rax
    jae  .iommu_delta
    xor  r8d, r8d                          ; reset only this source
.iommu_delta:
    or   r10, r8                           ; classify only the reset-clamped u64 delta
    add  rcx, r8
    jnc  .iommu_sum_ok
    mov  r9d, 1                           ; known sum is only a saturating minimum
    mov  rcx, -1
.iommu_sum_ok:
    mov  rax, [rel audit_aer_observed]
    cmp  rax, -1
    jne  .aer_quality_exact
    or   r11d, 512                         ; tenth native source, lower bound
.aer_quality_exact:
    mov  r8, rax
    sub  r8, [rel audit_guardian_last_aer_observed]
    mov  [rel audit_guardian_last_aer_observed], rax
    jae  .aer_delta
    xor  r8d, r8d
.aer_delta:
    or   r10, r8
    add  rcx, r8
    jnc  .aer_sum_ok
    mov  r9d, 1
    mov  rcx, -1
.aer_sum_ok:
    mov  rax, [rel audit_mca_observed]
    cmp  rax, -1
    jne  .mca_quality_exact
    or   r11d, 1024                        ; eleventh native source, lower bound
.mca_quality_exact:
    mov  r8, rax
    sub  r8, [rel audit_guardian_last_mca_observed]
    mov  [rel audit_guardian_last_mca_observed], rax
    jae  .mca_delta
    xor  r8d, r8d
.mca_delta:
    or   r10, r8
    add  rcx, r8
    jnc  .mca_sum_ok
    mov  r9d, 1
    mov  rcx, -1
.mca_sum_ok:
    add  rdx, rcx
    jnc  .sum_ok
    mov  r9d, 1                           ; known sum is only a saturating minimum
    mov  rdx, -1
.sum_ok:
    ; Retain facts from this completed look, before latch/rate/ring decisions.
    ; SourceMAX includes MAX-MAX: zero minimum never establishes exact quiet.
    mov  [rel audit_guardian_window_min], rdx
    mov  [rel audit_guardian_window_sources], r11
    mov  [rel audit_guardian_window_overflow], r9b
    mov  [rel audit_guardian_window_ms], rbx
    mov  al, 1                             ; exact native reset-clamped arithmetic
    test r11, r11
    jnz  .window_lower
    test r9b, r9b
    jz   .window_quality_ready
.window_lower:
    mov  al, 2                             ; known minimum, exact delta unavailable
.window_quality_ready:
    mov  [rel audit_guardian_window_quality], al
    cmp  rdx, GUARDIAN_BURST
    jb   .quiet
    cmp  byte [rel audit_guardian_in_burst], 1
    jne  .new_burst
    ; A lower-bound window never proved quiet, so it cannot prove this is the
    ; same burst either: a source held at u64 MAX would otherwise latch Guardian
    ; shut for good. Keep the latch; allow one record per rate gap instead.
    cmp  byte [rel audit_guardian_window_quality], 2
    jne  .out                               ; the same burst continues: already recorded
    jmp  .rate
.new_burst:
    mov  byte [rel audit_guardian_in_burst], 1
.rate:
    mov  rax, rbx
    sub  rax, [rel audit_guardian_last_emit_ms]
    cmp  qword [rel audit_guardian_last_emit_ms], 0
    je   .emit
    cmp  rax, GUARDIAN_MIN_GAP_MS
    jb   .out                               ; rate limit: counted, not recorded
.emit:
    ; cap: count the shadow records still held (read only; slots 0..min(seq,NREC)-1)
    mov  rcx, [rel audit_sec_seq]
    cmp  rcx, AUDIT_SEC_NREC
    jbe  .held_n
    mov  ecx, AUDIT_SEC_NREC
.held_n:
    lea  rsi, [rel audit_sec_ring]
    xor  eax, eax                           ; (RDX = burst size, kept for the record)
.held:
    test ecx, ecx
    jz   .held_done
    cmp  byte [rsi + ASR_CLASS], AUDIT_SEC_C_GUARDIAN
    jne  .held_next
    inc  eax
.held_next:
    add  rsi, AUDIT_SEC_REC_SZ
    dec  ecx
    jmp  .held
.held_done:
    cmp  eax, GUARDIAN_MAX_LIVE
    jae  .out                               ; cap reached: not recorded
    ; No typed sequence remains: preserve history and emission accounting.
    cmp  qword [rel audit_sec_seq], -1
    je   .out
    mov  [rel audit_guardian_last_emit_ms], rbx
    add  qword [rel audit_guardian_shadow_decisions], 1
    jnc  .decision_counted
    mov  qword [rel audit_guardian_shadow_decisions], -1
.decision_counted:
    mov  edi, AUDIT_SEC_C_GUARDIAN | (AUDIT_SEC_V_HELD << 8) | (AUDIT_SEC_R_SHADOW_REFUSAL_BURST << 16)
    test r10, r10
    jz   .shadow_reason_ready
    mov  edi, AUDIT_SEC_C_GUARDIAN | (AUDIT_SEC_V_HELD << 8) | (AUDIT_SEC_R_SHADOW_OBSERVATION_BURST << 16)
.shadow_reason_ready:
    mov  esi, PRIN_SYSTEM
    call audit_sec_event                    ; RDX = burst size (clamped to u32 by the spine)
    jmp  .out
.quiet:
    cmp  byte [rel audit_guardian_window_quality], 1
    jne  .out                              ; unknown does not prove quiet or rearm
    mov  byte [rel audit_guardian_in_burst], 0
    jmp  .out
.clock_zero:
    mov  byte [rel audit_guardian_window_quality], 0 ; no valid completed look
    cmp  byte [rel audit_guardian_clock_state], 0
    je   .out
    mov  byte [rel audit_guardian_clock_state], 2
.out:
    pop  rbx
    ret

; Native key provenance observation. EDI is bounded numeric provenance from
; keyprov's owned taint, not a principal or input/command bytes. The independent
; saturating total counts once per native receipt (SSH's existing burst throttle
; stays upstream). AUTH_REFUSED/SYSTEM detail is capped at4 held rows, shared
; conservatively with other native AUTH observers. At quota/seqMAX only our
; coalesced total advances: never fold into the remote AUTH public cell.
; KAT attempts produce neither native observations nor quota consumption.
audit_sec_keyprov_refusal:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    push rbx
    mov  ebx, edi
    add  qword [rel audit_keyprov_refused], 1
    jnc  .counted
    mov  qword [rel audit_keyprov_refused], -1
.counted:
    cmp  qword [rel audit_sec_seq], -1
    je   .fold
    mov  edi, AUDIT_SEC_C_AUTH_REFUSED
    mov  esi, PRIN_SYSTEM
    call audit_sec_held
    cmp  eax, 4
    jae  .fold
    mov  edi, ebx
    shl  edi, 16
    or   edi, AUDIT_SEC_C_AUTH_REFUSED | (AUDIT_SEC_V_REFUSED << 8)
    mov  esi, PRIN_SYSTEM
    xor  edx, edx                      ; no principal, verb or input subject
    call audit_sec_event
    jmp  .done
.fold:
    add  qword [rel audit_keyprov_coalesced], 1
    jnc  .done
    mov  qword [rel audit_keyprov_coalesced], -1
.done:
    pop  rbx
.out:
    ret

; audit_sec_save / audit_sec_restore — a boot KAT that drives the REAL remote
;   paths brackets itself with these, so its synthetic attempts leave no spine
;   event (the same truthful-operator rule as its restored refusal counters).
;   One level, no nesting. audit_sec_last_t stays advanced (non-decreasing).
;   clobbers: RAX,RCX,RDX,RSI,RDI.
audit_sec_save:
    mov  rax, [rel audit_keyprov_refused]
    mov  [rel audit_keyprov_saved_refused], rax
    mov  rax, [rel audit_keyprov_coalesced]
    mov  [rel audit_keyprov_saved_coalesced], rax
    mov  byte [rel audit_sec_test_active], 1
    mov  rax, [rel audit_aihook_refused]
    mov  [rel audit_aihook_saved_refused], rax
    mov  rax, [rel audit_sec_seq]
    mov  [rel audit_sec_saved_seq], rax
    mov  rax, [rel audit_sec_drop]
    mov  [rel audit_sec_saved_drop], rax
    lea  rdi, [rel audit_sec_saved_ring]
    lea  rsi, [rel audit_sec_ring]
    mov  edx, AUDIT_SEC_NREC * AUDIT_SEC_REC_SZ
    call memcpy
    lea  rdi, [rel audit_sec_saved_pub]
    lea  rsi, [rel audit_sec_pub]
    mov  edx, AUDIT_SEC_NCLASS * AUDIT_SEC_NVERDICT * AUDIT_SEC_PUB_SZ
    jmp  memcpy

audit_sec_restore:
    mov  rax, [rel audit_keyprov_saved_refused]
    mov  [rel audit_keyprov_refused], rax
    mov  rax, [rel audit_keyprov_saved_coalesced]
    mov  [rel audit_keyprov_coalesced], rax
    mov  rax, [rel audit_aihook_saved_refused]
    mov  [rel audit_aihook_refused], rax
    mov  rax, [rel audit_sec_saved_seq]
    mov  [rel audit_sec_seq], rax
    mov  rax, [rel audit_sec_saved_drop]
    mov  [rel audit_sec_drop], rax
    lea  rdi, [rel audit_sec_ring]
    lea  rsi, [rel audit_sec_saved_ring]
    mov  edx, AUDIT_SEC_NREC * AUDIT_SEC_REC_SZ
    call memcpy
    lea  rdi, [rel audit_sec_pub]
    lea  rsi, [rel audit_sec_saved_pub]
    mov  edx, AUDIT_SEC_NCLASS * AUDIT_SEC_NVERDICT * AUDIT_SEC_PUB_SZ
    call memcpy
    mov  byte [rel audit_sec_test_active], 0
    ret

; audit_net_append — write the candidate held in RBX(text) R12d(meta) R13(pid)
;   R14(reason) R15(verb) as a new net row. -> RAX = record, or 0 exhausted.
audit_net_append:
    call audit_claim_slot
    mov  [rel audit_net_cur], rax
    test rax, rax
    jz   .done
    lea  rdi, [rax + AR_TEXT]
    mov  rsi, rbx
    mov  edx, AUDIT_TXT
    call strcpy_s
    mov  rdi, [rel audit_net_cur]
    mov  byte [rdi + AR_KIND], AUDIT_KIND_NET
    mov  eax, r12d
    mov  [rdi + AR_SRC], al
    shr  eax, 8
    mov  [rdi + AR_SVC], al
    shr  eax, 8
    mov  [rdi + AR_RES], al
    mov  dword [rdi + AR_COUNT], 1
    mov  [rdi + AR_PID], r13
    mov  rax, [rel audit_net_now]
    mov  [rdi + AR_T], rax
    mov  [rdi + AR_TLAST], rax
    mov  [rdi + AR_REASON], r14
    lea  rdi, [rdi + AR_VERB]
    mov  rsi, r15
    mov  edx, AUDIT_VERB_MAX
    call strcpy_s
    mov  rax, [rel audit_net_cur]
.done:
    ret

; audit_net_same(RDI = record) -> EAX 1 when the record is a net row with the
;   candidate's key (src, svc, res, pid, reason, verb, text). RDI preserved.
audit_net_same:
    push rdi
    cmp  byte [rdi + AR_KIND], AUDIT_KIND_NET
    jne  .no
    mov  eax, r12d
    cmp  [rdi + AR_SRC], al
    jne  .no
    shr  eax, 8
    cmp  [rdi + AR_SVC], al
    jne  .no
    shr  eax, 8
    cmp  [rdi + AR_RES], al
    jne  .no
    cmp  [rdi + AR_PID], r13
    jne  .no
    cmp  [rdi + AR_REASON], r14
    jne  .no
    lea  rdi, [rdi + AR_VERB]
    mov  rsi, r15
    call strcmp
    test eax, eax
    jnz  .no
    mov  rdi, [rsp]
    lea  rdi, [rdi + AR_TEXT]
    mov  rsi, rbx
    call strcmp
    test eax, eax
    jnz  .no
    pop  rdi
    mov  eax, 1
    ret
.no:
    pop  rdi
    xor  eax, eax
    ret

; audit_net_bump(RDI = record) — fold one more attempt (saturating count).
audit_net_bump:
    mov  eax, [rdi + AR_COUNT]
    inc  eax
    jz   .sat
    mov  [rdi + AR_COUNT], eax
.sat:
    mov  rax, [rel audit_net_now]
    mov  [rdi + AR_TLAST], rax
    ret

; audit_replace_newest(RDI = NUL-terminated text) — COALESCE an identical
;   repeated refusal into the newest receipt so a flood cannot evict real
;   receipts; callers must have proven no other receipt was appended since
;   theirs. A net row keeps its first text and counts the repeat (plain AUDIT
;   renders " x<count>"); a local receipt has its text rewritten in place.
audit_replace_newest:
    cmp  qword [rel audit_seq], 0
    je   .done
    push rbx
    mov  rbx, rdi
    call audit_newest_ptr
    cmp  byte [rax + AR_KIND], AUDIT_KIND_NET
    je   .net
    lea  rdi, [rax + AR_TEXT]
    mov  rsi, rbx
    mov  edx, AUDIT_TXT
    call audit_store_text
    pop  rbx
    ret
.net:
    mov  rbx, rax
    call boot_ms_now
    mov  [rel audit_net_now], rax
    mov  rdi, rbx
    call audit_net_bump
    ; SEC-GD1b: a repeat folded into a net row (e.g. SSH brute force) is still
    ; one remote attempt in the spine; the row principal is never trusted here.
    movzx edi, byte [rbx + AR_SRC]
    movzx eax, byte [rbx + AR_SVC]
    shl  eax, 8
    or   edi, eax
    movzx eax, byte [rbx + AR_RES]
    shl  eax, 16
    or   edi, eax
    xor  esi, esi
    call audit_net_sec_account
    pop  rbx
.done:
    ret

; audit_sec_now -> RAX = time_monotonic_now_us held non-decreasing (an
;   uncalibrated 0 or a backwards step reuses the newest stamp).
;   clobbers: RAX,RCX,RDX,R8.
audit_sec_now:
    call time_monotonic_now_us
    cmp  rax, [rel audit_sec_last_t]
    jae  .fwd
    mov  rax, [rel audit_sec_last_t]
.fwd:
    mov  [rel audit_sec_last_t], rax
    ret

; ---------------------------------------------------------------------------
; audit_sec_event — account ONE security event in the GD1 spine.
;   EDI = class | verdict << 8 | reason << 16   (AUDIT_SEC_C_* / _V_* / _R_*)
;   RSI = principal the PRODUCER verified: PRIN_OWNER, PRIN_SYSTEM or (in-process,
;         GA2(b)) PRIN_ADVISOR. Any other
;         value, including 0, is unauthenticated.
;   RDX = subject (u32; a wider value is stored as 0xFFFFFFFF)
;   -> EAX = 1 a typed record was appended, 0 folded into the public counters.
; A verified principal appends while sequence remains, overwriting the oldest once the
; ring is full (sec_drop counts every overwrite). Anything else increments its
; class x verdict cell (count, first/last t_us) and never takes a ring slot,
; so unauthenticated floods cannot evict authenticated records.
; Overflow: sec_drop and every cell count saturate at 2^64-1. At seqMAX,
; verified events also fold into their normalized public cell and return0;
; retained typed history and overwrite diagnostics stay intact. No typed
; principal, subject or reason is asserted by a public fold. Constant time; no allocation,
; lock, file or network I/O. Single writer: the callers are the BSP command
; context (boot KATs and handlers dispatched from the idle-loop polls), the
; same serialization aihook_req/aihook_rsp and the text ring rely on.
; clobbers: RAX,RCX,RDX,RSI,RDI,R8 (RBX,RBP,R12-R15 preserved).
; ---------------------------------------------------------------------------
audit_sec_event:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    call audit_sec_now                  ; RAX = t
    movzx ecx, bl                       ; class -> 1..AUDIT_SEC_C_RESERVED
    lea  edx, [rcx - 1]
    cmp  edx, AUDIT_SEC_NCLASS
    jb   .class_ok
    mov  ecx, AUDIT_SEC_C_RESERVED
.class_ok:
    movzx edx, bh                       ; verdict -> 1..AUDIT_SEC_V_INFO
    lea  esi, [rdx - 1]
    cmp  esi, AUDIT_SEC_NVERDICT
    jb   .verdict_ok
    mov  edx, AUDIT_SEC_V_INFO
.verdict_ok:
    ; One lifetime AI refusal total across typed records and public folds.
    ; Keep public cells exclusively untyped; adding them again double-counts.
    ; Normalized class/verdict only: admission and operational errors do not
    ; assert a policy refusal. KAT save/restore brackets this total too.
    cmp  ecx, AUDIT_SEC_C_AIHOOK
    jne  .aihook_counted
    cmp  edx, AUDIT_SEC_V_REFUSED
    jne  .aihook_counted
    add  qword [rel audit_aihook_refused], 1
    jnc  .aihook_counted
    mov  qword [rel audit_aihook_refused], -1
.aihook_counted:
    cmp  r12, PRIN_OWNER
    je   .typed
    cmp  r12, PRIN_SYSTEM
    je   .typed
    cmp  r12, PRIN_ADVISOR
    je   .typed
.public:
    ; Public fold: cell[(class-1) * NVERDICT + verdict-1], no ring slot
    lea  esi, [rcx - 1]
    imul esi, esi, AUDIT_SEC_NVERDICT
    lea  esi, [rsi + rdx - 1]
    imul esi, esi, AUDIT_SEC_PUB_SZ
    lea  rdi, [rel audit_sec_pub]
    add  rdi, rsi
    cmp  qword [rdi], 0
    jne  .counted
    mov  [rdi + 8], rax                 ; first
.counted:
    add  qword [rdi], 1
    jnc  .last
    mov  qword [rdi], -1                ; saturate
.last:
    mov  [rdi + 16], rax
    xor  eax, eax
    jmp  .out
.typed:
    mov  r8, [rel audit_sec_seq]
    cmp  r8, -1
    je   .public                          ; no remaining typed sequence
    mov  esi, r8d
    and  esi, AUDIT_SEC_NREC - 1
    imul esi, esi, AUDIT_SEC_REC_SZ
    lea  rdi, [rel audit_sec_ring]
    add  rdi, rsi
    mov  [rdi + ASR_SEQ], r8
    mov  [rdi + ASR_T], rax
    mov  rax, r13
    mov  esi, 0xFFFFFFFF
    cmp  rax, rsi
    jbe  .subject_ok
    mov  eax, esi
.subject_ok:
    mov  [rdi + ASR_SUBJECT], eax
    mov  eax, ebx
    shr  eax, 16
    mov  [rdi + ASR_REASON], ax
    mov  [rdi + ASR_CLASS], cl
    mov  [rdi + ASR_VERDICT], dl
    mov  eax, r12d
    mov  [rdi + ASR_PRIN], al
    mov  byte [rdi + 25], 0             ; no stale bytes of the overwritten record
    mov  word [rdi + 26], 0
    mov  dword [rdi + 28], 0
    cmp  r8, AUDIT_SEC_NREC
    jb   .fresh
    add  qword [rel audit_sec_drop], 1  ; the oldest record was overwritten
    jnc  .fresh
    mov  qword [rel audit_sec_drop], -1
.fresh:
    inc  qword [rel audit_sec_seq]
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; BSP pull bridge over the accepted CPU-private original observations. Never
; call AUDIT on an AP or in #MC. Exactly32 single-attempt stable RAM copies:
; no hardware sampling, acknowledgement, recovery assessment or status clear.
; Each typed row is a CPU summary (not one invented bank/error record). Original
; bank/STATUS/ordinal and log losses remain in diag and HW mcalog. The independent
; total includes refused raw logs; typed omissions coalesce by observation count.
; Unavailable/unstable/inconsistent snapshots do not consume a CPU baseline.
; Zero is never a quiet-run/containment assertion. KAT never consumes real state.
audit_sec_mca_drain:
    cmp byte [rel audit_sec_test_active],0
    jne .out
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,32
    xor ebx,ebx
    lea r12,[rel audit_mca_cpu_seen]
.cpu:
    mov edi,ebx
    mov rsi,rsp
    call mca_poll_observed_copy
    test eax,eax
    jnz .next
    mov r15,[rsp]                        ; actual sampled seen ordinal/count
    mov rax,[rsp+8]
    cmp rax,r15
    ja .next
    mov rcx,[rsp+16]
    cmp rcx,r15
    ja .next
    add rax,rcx
    jnc .extent
    mov rax,-1
.extent:
    cmp rax,r15                          ; logged + dropped, saturating
    jne .next
    cmp qword [rsp+24],0
    jne .next
    mov r13,r15
    sub r13,[r12+rbx*8]
    jbe .next                            ; no replay after equal or regressed count
    mov [r12+rbx*8],r15                   ; consume before callbacks/quota
    add [rel audit_mca_observed],r13
    jnc .counted
    mov qword [rel audit_mca_observed],-1
.counted:
    cmp qword [rel audit_sec_seq],-1
    je .coalesce
    mov edi,AUDIT_SEC_C_HARDWARE
    mov esi,PRIN_SYSTEM
    call audit_sec_held
    cmp eax,AUDIT_AER_MAX_LIVE             ; shared finite hardware detail quota
    jae .coalesce
    mov edi,AUDIT_SEC_C_HARDWARE | (AUDIT_SEC_V_INFO << 8) | (AUDIT_SEC_R_MCA_OBSERVED << 16)
    mov esi,PRIN_SYSTEM
    mov rdx,rbx                          ; original dense CPU, no inferred bank
    call audit_sec_event
    test eax,eax
    jz .coalesce
    mov rax,[rel audit_sec_seq]
    dec eax
    and eax,AUDIT_SEC_NREC-1
    imul eax,AUDIT_SEC_REC_SZ
    lea rdx,[rel audit_sec_ring]
    mov byte [rdx+rax+ASR_BACKEND],6       ; passive native MCA; handling unknown
    dec r13                              ; one retained CPU summary detail
.coalesce:
    add [rel audit_mca_coalesced],r13
    jnc .next
    mov qword [rel audit_mca_coalesced],-1
.next:
    inc ebx
    cmp ebx,32
    jb .cpu
    add rsp,32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
.out:
    ret

; Native BSP aer_poll producer only; no IRQ/AP/synthetic AERINJECT caller.
; RDI=bus0 BDF[0..255], RSI=unmasked nonfatal32, RDX=unmasked fatal32,
; RCX=monotonic sample us. One strictly advancing native poll identity is consumed
; even at the typed quota/sequence ceiling. The independent observation total
; saturates, survives KAT restore and never implies isolation/recovery or attack.
; EAX1=observation accounted,0=invalid/stale/KAT (no mutation). At most4 typed
; HARDWARE/INFO/SYSTEM records are held; further detail coalesces without evicting
; owner history. Raw bitmaps/header remain in the existing retained AER/diag path.
audit_sec_aer_event:
    cmp byte [rel audit_sec_test_active],0
    jne .no
    cmp rdi,255
    ja .no
    mov eax,esi
    cmp rax,rsi
    jne .no
    mov eax,edx
    cmp rax,rdx
    jne .no
    or eax,esi
    jz .no
    test rcx,rcx
    jz .no
    cmp rcx,[rel audit_aer_last_us]
    jbe .no
    push rbx
    push r12
    push r13
    mov rbx,rdi
    xor r12d,r12d
    test esi,esi
    setnz r12b
    test edx,edx
    setnz al
    movzx eax,al
    shl eax,1
    or r12d,eax
    mov [rel audit_aer_last_us],rcx        ; consume before callbacks/publication
    cmp qword [rel audit_aer_observed],-1
    je .counted
    inc qword [rel audit_aer_observed]
.counted:
    cmp qword [rel audit_sec_seq],-1
    je .coalesce
    mov edi,AUDIT_SEC_C_HARDWARE
    mov esi,PRIN_SYSTEM
    call audit_sec_held
    cmp eax,AUDIT_AER_MAX_LIVE
    jae .coalesce
    or r12d,AUDIT_SEC_R_AER_POLL
    shl r12d,16
    mov edi,AUDIT_SEC_C_HARDWARE | (AUDIT_SEC_V_INFO << 8)
    or edi,r12d
    mov esi,PRIN_SYSTEM
    mov rdx,rbx
    call audit_sec_event
    test eax,eax
    jz .coalesce
    mov rax,[rel audit_sec_seq]
    dec eax
    and eax,AUDIT_SEC_NREC-1
    imul eax,AUDIT_SEC_REC_SZ
    lea rdx,[rel audit_sec_ring]
    mov byte [rdx+rax+ASR_BACKEND],5        ; read-only native AER polling
    jmp .yes
.coalesce:
    cmp qword [rel audit_aer_coalesced],-1
    je .yes
    inc qword [rel audit_aer_coalesced]
.yes:
    pop r13
    pop r12
    pop rbx
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; ---------------------------------------------------------------------------
; Native provenance is granted only by the trusted BSP producer queue. Public
; IOMMU/INFO is an observation total, including bounded queue-detail drops; it
; is not an unauthenticated refusal or proof of blocked DMA. Counters never
; regress outside the explicit boot KAT bracket. t is BSP publication time.
audit_sec_iommu_sync:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    lea  rbx, [rel audit_sec_pub + (((AUDIT_SEC_C_IOMMU - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    cmp  r12, [rbx]
    jbe  .drops
    call audit_sec_now
    cmp  qword [rbx], 0
    jne  .last
    mov  [rbx + 8], rax
.last:
    mov  [rbx + 16], rax
    mov  [rbx], r12
.drops:
    cmp  r13, [rel audit_iommu_drops]
    jbe  .done
    mov  [rel audit_iommu_drops], r13
.done:
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

; RDI=epoch16:serial32 identity, RSI=BDF, RDX=reason byte. Exactly-once source
; identity is consumed even when typed quota is full. At most4 IOMMU rows can
; be held; summary and dropped-detail counters continue independently.
audit_sec_iommu_event:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  rax, rdi
    shr  rax, 32
    test rax, rax
    jz   .done
    cmp  rax, 65535
    ja   .done
    test ebx, ebx
    jz   .done
    cmp  rsi, 65535
    ja   .done
    test rdx, rdx
    jz   .done
    cmp  rdx, 255
    ja   .done
    cmp  rbx, [rel audit_iommu_last_id]
    jbe  .done
    mov  [rel audit_iommu_last_id], rbx
    cmp  qword [rel audit_sec_seq], -1
    je   .coalesce                          ; no global spine sequence rollover
    mov  edi, AUDIT_SEC_C_IOMMU
    mov  esi, PRIN_SYSTEM
    call audit_sec_held
    cmp  eax, AUDIT_IOMMU_MAX_LIVE
    jae  .coalesce
    mov  edi, AUDIT_SEC_C_IOMMU | (AUDIT_SEC_V_INFO << 8) | (AUDIT_SEC_R_IOMMU_VTD << 16)
    mov  eax, r13d
    shl  eax, 16
    or   edi, eax
    mov  esi, PRIN_SYSTEM
    mov  rdx, r12
    call audit_sec_event
    test eax, eax
    jz   .done
    mov  rax, [rel audit_sec_seq]
    dec  eax
    and  eax, AUDIT_SEC_NREC - 1
    imul eax, eax, AUDIT_SEC_REC_SZ
    lea  rdx, [rel audit_sec_ring]
    add  rdx, rax
    mov  byte [rdx + ASR_BACKEND], 1
    mov  [rdx + ASR_EVENT], ebx
    shr  rbx, 32
    mov  [rdx + ASR_EPOCH], bx
    jmp  .done
.coalesce:
    add  qword [rel audit_iommu_coalesced], 1
    jnc  .done
    mov  qword [rel audit_iommu_coalesced], -1
.done:
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

; AMD IO_PAGE_FAULT variant shares identity/quota/accounting with VT-d, while
; the old VT-d event encoder and record bytes remain exact.
audit_sec_iommu_amd_event:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  rax, rdi
    shr  rax, 32
    test rax, rax
    jz   .done
    cmp  rax, 65535
    ja   .done
    test ebx, ebx
    jz   .done
    cmp  rsi, 65535
    ja   .done
    cmp  rdx, 2
    jne  .done
    cmp  rbx, [rel audit_iommu_last_id]
    jbe  .done
    mov  [rel audit_iommu_last_id], rbx
    cmp  qword [rel audit_sec_seq], -1
    je   .coalesce                          ; no global spine sequence rollover
    mov  edi, AUDIT_SEC_C_IOMMU
    mov  esi, PRIN_SYSTEM
    call audit_sec_held
    cmp  eax, AUDIT_IOMMU_MAX_LIVE
    jae  .coalesce
    mov  edi, AUDIT_SEC_C_IOMMU | (AUDIT_SEC_V_INFO << 8) | (AUDIT_SEC_R_IOMMU_AMD << 16)
    mov  eax, r13d
    shl  eax, 16
    or   edi, eax
    mov  esi, PRIN_SYSTEM
    mov  rdx, r12
    call audit_sec_event
    test eax, eax
    jz   .done
    mov  rax, [rel audit_sec_seq]
    dec  eax
    and  eax, AUDIT_SEC_NREC - 1
    imul eax, eax, AUDIT_SEC_REC_SZ
    lea  rdx, [rel audit_sec_ring]
    add  rdx, rax
    mov  byte [rdx + ASR_BACKEND], 4
    mov  [rdx + ASR_EVENT], ebx
    shr  rbx, 32
    mov  [rdx + ASR_EPOCH], bx
    jmp  .done
.coalesce:
    add  qword [rel audit_iommu_coalesced], 1
    jnc  .done
    mov  qword [rel audit_iommu_coalesced], -1
.done:
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret


; Pull-only BSP bridge. Lower-layer producer never writes this spine. Summary
; includes detail losses; each source ID may claim one typed info row at most.
audit_sec_hid_drain:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    push rbx
    call usb_hid_observation_snapshot
    mov  rdi, rax
    mov  rsi, rdx
    call audit_sec_hid_sync
    mov  ebx, 2
.loop:
    call usb_hid_observation_pop
    test eax, eax
    jz   .done
    js   .next
    mov  rdi, rdx
    mov  edx, esi
    mov  esi, ecx
    call audit_sec_hid_event
.next:
    dec  ebx
    jnz  .loop
.done:
    pop  rbx
.out:
    ret

audit_sec_hid_sync:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    lea  rbx, [rel audit_sec_pub + (((AUDIT_SEC_C_USB_HID - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    cmp  r12, [rbx]
    jbe  .drops
    call audit_sec_now
    cmp  qword [rbx], 0
    jne  .last
    mov  [rbx + 8], rax
.last:
    mov  [rbx + 16], rax
    mov  [rbx], r12
.drops:
    cmp  r13, [rel audit_hid_drops]
    jbe  .done
    mov  [rel audit_hid_drops], r13
.done:
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

; RDI=epoch16:serial32 identity, RSI=kind<<8|binding ordinal1..4, RDX=reason1..5. Exactly-once source
; identity is consumed even when typed quota is full. At most4 HID rows can
; be held; summary and dropped-detail counters continue independently.
audit_sec_hid_event:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  rax, rdi
    shr  rax, 32
    test rax, rax
    jz   .done
    cmp  rax, 65535
    ja   .done
    test ebx, ebx
    jz   .done
    mov  rax, rsi
    shr  rax, 8
    cmp  rax, 1
    jb   .done
    cmp  rax, 2
    ja   .done
    movzx eax, sil
    dec  eax
    cmp  eax, 4
    jae  .done
    test rdx, rdx
    jz   .done
    cmp  rdx, 5
    ja   .done
    cmp  rbx, [rel audit_hid_last_id]
    jbe  .done
    mov  [rel audit_hid_last_id], rbx
    cmp  qword [rel audit_sec_seq], -1
    je   .coalesce                          ; no global spine sequence rollover
    mov  edi, AUDIT_SEC_C_USB_HID
    mov  esi, PRIN_SYSTEM
    call audit_sec_held
    cmp  eax, AUDIT_HID_MAX_LIVE
    jae  .coalesce
    mov  edi, AUDIT_SEC_C_USB_HID | (AUDIT_SEC_V_INFO << 8) | (AUDIT_SEC_R_HID_NATIVE << 16)
    mov  eax, r13d
    shl  eax, 16
    or   edi, eax
    mov  esi, PRIN_SYSTEM
    mov  rdx, r12
    call audit_sec_event
    test eax, eax
    jz   .done
    mov  rax, [rel audit_sec_seq]
    dec  eax
    and  eax, AUDIT_SEC_NREC - 1
    imul eax, eax, AUDIT_SEC_REC_SZ
    lea  rdx, [rel audit_sec_ring]
    add  rdx, rax
    mov  byte [rdx + ASR_BACKEND], 2
    mov  [rdx + ASR_EVENT], ebx
    shr  rbx, 32
    mov  [rdx + ASR_EPOCH], bx
    jmp  .done
.coalesce:
    add  qword [rel audit_hid_coalesced], 1
    jnc  .done
    mov  qword [rel audit_hid_coalesced], -1
.done:
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

; Pull-only BSP bridge. Private owner/method/generation tokens are revalidated
; against current ingress before numeric publication and never enter the spine.
audit_sec_arp_drain:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    push rbx
    call arp_observation_snapshot
    mov  rdi, rax
    mov  rsi, rdx
    call audit_sec_arp_sync
    mov  ebx, 2
.loop:
    call arp_observation_pop
    test eax, eax
    jz   .done
    js   .next
    push rdx
    push rcx
    push rsi
    mov  rdi, r8
    mov  rsi, r10
    mov  rdx, r9
    sub  rsp, 8
    call command_udp_arp_observation_current
    add  rsp, 8
    pop  rsi
    pop  rcx
    pop  rdx
    cmp  eax, ecx
    jne  .discard
    mov  rdi, rdx
    mov  edx, esi
    mov  esi, ecx
    call audit_sec_arp_event
    jmp  .next
.discard:
    call arp_observation_discard
.next:
    dec  ebx
    jnz  .loop
.done:
    pop  rbx
.out:
    ret

audit_sec_arp_sync:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    lea  rbx, [rel audit_sec_pub + (((AUDIT_SEC_C_NET_ARP - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    cmp  r12, [rbx]
    jbe  .drops
    call audit_sec_now
    cmp  qword [rbx], 0
    jne  .last
    mov  [rbx + 8], rax
.last:
    mov  [rbx + 16], rax
    mov  [rbx], r12
.drops:
    cmp  r13, [rel audit_arp_drops]
    jbe  .done
    mov  [rel audit_arp_drops], r13
.done:
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

; RDI=epoch16:serial32 identity, RSI=native registry ordinal1..8, RDX=reason1..3. Exactly-once source
; identity is consumed even when typed quota is full. At most4 ARP rows can
; be held; summary and dropped-detail counters continue independently.
audit_sec_arp_event:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  rax, rdi
    shr  rax, 32
    test rax, rax
    jz   .done
    cmp  rax, 65535
    ja   .done
    test ebx, ebx
    jz   .done
    test rsi, rsi
    jz   .done
    cmp  rsi, 8
    ja   .done
    test rdx, rdx
    jz   .done
    cmp  rdx, 3
    ja   .done
    cmp  rbx, [rel audit_arp_last_id]
    jbe  .done
    mov  [rel audit_arp_last_id], rbx
    cmp  qword [rel audit_sec_seq], -1
    je   .coalesce                          ; no global spine sequence rollover
    mov  edi, AUDIT_SEC_C_NET_ARP
    mov  esi, PRIN_SYSTEM
    call audit_sec_held
    cmp  eax, AUDIT_ARP_MAX_LIVE
    jae  .coalesce
    mov  edi, AUDIT_SEC_C_NET_ARP | (AUDIT_SEC_V_INFO << 8) | (AUDIT_SEC_R_ARP_NATIVE << 16)
    mov  eax, r13d
    shl  eax, 16
    or   edi, eax
    mov  esi, PRIN_SYSTEM
    mov  rdx, r12
    call audit_sec_event
    test eax, eax
    jz   .done
    mov  rax, [rel audit_sec_seq]
    dec  eax
    and  eax, AUDIT_SEC_NREC - 1
    imul eax, eax, AUDIT_SEC_REC_SZ
    lea  rdx, [rel audit_sec_ring]
    add  rdx, rax
    mov  byte [rdx + ASR_BACKEND], 3
    mov  [rdx + ASR_EVENT], ebx
    shr  rbx, 32
    mov  [rdx + ASR_EPOCH], bx
    jmp  .done
.coalesce:
    add  qword [rel audit_arp_coalesced], 1
    jnc  .done
    mov  qword [rel audit_arp_coalesced], -1
.done:
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

; Native session refusals: trusted observer, untrusted input identity.
; EDI=outcome1 credential /2 owner-ticket /3 implicit remote unlock;
; ESI=method0 none /1 AUTHLOGIN /2 PUSHAUTH /3 fixture /4 local;
; EDX=ingress0 local-or-unknown /1 UDP /2 SSH /3 serial /4 injected /5 fixture.
; Reason0x0A00 | ingress<<5 | method<<2 | (outcome-1), subject0,
; AUTH_REFUSED/REFUSED/SYSTEM identifies the observing code, not its caller.
; Dedicated public lifetime/summary counters include typed details exactly once.
; At quota/sequence ceiling fold only here, never into the remote AUTH cell.
; At most4 SYSTEM AUTH_REFUSED details held: storms cannot evict owner history.
; BSP serialized like the text receipt. KATs leave no production observation.
audit_sec_session_unlock:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    lea  eax, [rdi - 1]
    cmp  eax, 2
    ja   .out                           ; successes/test-only/unknown are not refusals
    cmp  esi, 4
    ja   .out
    cmp  edx, 5
    ja   .out
    push rbx
    shl  edx, 5
    shl  esi, 2
    or   eax, edx
    or   eax, esi
    or   eax, AUDIT_SEC_R_SESSION_NATIVE
    mov  ebx, eax
    add  qword [rel audit_session_refused], 1
    jnc  .counted
    mov  qword [rel audit_session_refused], -1
.counted:
    cmp  qword [rel audit_sec_seq], -1
    je   .coalesce
    mov  edi, AUDIT_SEC_C_AUTH_REFUSED
    mov  esi, PRIN_SYSTEM
    call audit_sec_held
    cmp  eax, AUDIT_SESSION_MAX_LIVE
    jae  .coalesce
    mov  edi, ebx
    shl  edi, 16
    or   edi, AUDIT_SEC_C_AUTH_REFUSED | (AUDIT_SEC_V_REFUSED << 8)
    mov  esi, PRIN_SYSTEM
    xor  edx, edx                       ; no caller principal, ticket or secret
    call audit_sec_event
    jmp  .done
.coalesce:
    add  qword [rel audit_session_coalesced], 1
    jnc  .done
    mov  qword [rel audit_session_coalesced], -1
.done:
    pop  rbx
.out:
    ret

; Native AIRLOCK queue -> typed AUTH_REFUSED/SYSTEM, reason0x0B00 | cause
;1 tier,2 readiness,3 resident,4 backend identity,5 locked resident recheck,
;6 backend/UNKNOWN,7 missing input; bit7 explicitly marks the boot proof.
; SYSTEM is observer identity, never authenticated input/attack/enforcement.
; Typed t is BSP publication time; no native decision timestamp is claimed.
; BSP idle only, same writer as existing HID/ARP drains; producers never call
; this or the spine. Keep all native totals/seen marks independent: no remote
; AUTH public fold or second Guardian count. Shared native AUTH quota4;
; at seqMAX/quota only coalesced advances. No row metadata or source replay.
%if !PAOS_PUBLIC_BUILD
audit_sec_airlock_drain:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    push rbx
    push r12
    mov  r12d, 2
.next:
    call airlock_observation_take
    test eax, eax
    jz   .done
    mov  ebx, eax
    cmp  qword [rel audit_sec_seq], -1
    je   .fold
    mov  edi, AUDIT_SEC_C_AUTH_REFUSED
    mov  esi, PRIN_SYSTEM
    call audit_sec_held
    cmp  eax, 4
    jae  .fold
    mov  edi, ebx
    or   edi, 0x0B00
    shl  edi, 16
    or   edi, AUDIT_SEC_C_AUTH_REFUSED | (AUDIT_SEC_V_REFUSED << 8)
    mov  esi, PRIN_SYSTEM
    xor  edx, edx
    call audit_sec_event
    jmp  .step
.fold:
    add  qword [rel audit_airlock_coalesced], 1
    jnc  .step
    mov  qword [rel audit_airlock_coalesced], -1
.step:
    dec  r12d
    jnz  .next
.done:
    pop  r12
    pop  rbx
.out:
    ret

%endif
; audit_sec_rsp_meta(RDI = command response envelope, ESI = class) -> EAX =
;   the audit_sec_event meta for the envelope's FINAL SYNCHRONOUS response.
;   It is a dispatch/admission outcome, never proof a job completed. Stable
;   mapping (reason = AUDIT_SEC_R_DISPATCH | code unless noted):
;     CMDE_OK, RSP_ACCEPTED = 0                -> allowed
;     CMDE_OK, RSP_ACCEPTED != 0               -> allowed, AUDIT_SEC_R_JOB_ADMITTED
;     CMDE_AUTHDENY / CAPDENY / DESKTOP_LOCKED -> refused
;     CMDE_NOVERB / BADJOB / BADSEL / BADARG   -> info (an operational/input
;                                                 error is never "allowed")
;     any other code                           -> info, AUDIT_SEC_R_DISPATCH_OTHER
;   Reads RSP_CODE/RSP_ACCEPTED only. clobbers: RAX,RCX,RDX.
; ---------------------------------------------------------------------------
audit_sec_rsp_meta:
    mov  rax, [rdi + RSP_CODE]
    mov  ecx, AUDIT_SEC_V_INFO
    mov  edx, AUDIT_SEC_R_DISPATCH_OTHER
    cmp  rax, CMDE_OK
    jne  .not_ok
    mov  ecx, AUDIT_SEC_V_ALLOWED
    mov  edx, AUDIT_SEC_R_DISPATCH | CMDE_OK
    cmp  qword [rdi + RSP_ACCEPTED], 0
    je   .pack
    mov  edx, AUDIT_SEC_R_JOB_ADMITTED
    jmp  .pack
.not_ok:
    cmp  rax, CMDE_AUTHDENY
    je   .refused
    cmp  rax, CMDE_CAPDENY
    je   .refused
    cmp  rax, CMDE_DESKTOP_LOCKED
    je   .refused
    cmp  rax, CMDE_NOVERB
    je   .known
    cmp  rax, CMDE_BADJOB
    je   .known
    cmp  rax, CMDE_BADSEL
    je   .known
    cmp  rax, CMDE_BADARG
    je   .known
    jmp  .pack
.refused:
    mov  ecx, AUDIT_SEC_V_REFUSED
.known:
    lea  edx, [rax + AUDIT_SEC_R_DISPATCH]
.pack:
    shl  ecx, 8
    shl  edx, 16
    or   ecx, edx
    movzx eax, sil
    or   eax, ecx
    ret

; ---- staged-reply helpers (same shape as rt_out_* in svc/command_rt.asm) ----
; Every put is bounded by audit_out_buf. The UDP serializer refuses a snapshot
; if any put could not complete; a partial staged row is never a wire snapshot.
audit_out_reset:
    lea  rax, [rel audit_out_buf]
    mov  [rel audit_out_cur], rax
    mov  byte [rel audit_out_buf], 0
    mov  byte [rel audit_out_full], 0
    ret

audit_put_str:                          ; RDI = cstr
    mov  rsi, [rel audit_out_cur]
    lea  rdx, [rel audit_out_buf + AUDIT_OUT_MAX - 1]
.cp:
    mov  al, [rdi]
    test al, al
    jz   .done
    cmp  rsi, rdx
    jb   .put
    mov  byte [rel audit_out_full], 1
    jmp  .done
.put:
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel audit_out_cur], rsi
    ret

; audit_put_text(RDI = STORED row field) — like audit_put_str, but any byte
;   < 0x20 or 0x7F is emitted as '?': a stored field can never add a dump row,
;   even if a producer bypassed audit_store_text (defence in depth for F1).
audit_put_text:
    mov  rsi, [rel audit_out_cur]
    lea  rdx, [rel audit_out_buf + AUDIT_OUT_MAX - 1]
.cp:
    mov  al, [rdi]
    test al, al
    jz   .done
    cmp  rsi, rdx
    jb   .room
    mov  byte [rel audit_out_full], 1
    jmp  .done
.room:
    cmp  al, 0x20
    jb   .ctl
    cmp  al, 0x7F
    jne  .put
.ctl:
    mov  al, '?'
.put:
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel audit_out_cur], rsi
    ret

; audit_store_text(RDI = dst, RSI = src cstr, EDX = dst size) — the ONE way row
;   text enters the ring (security scan F1, CWE-117: an unauthenticated request
;   line carrying CR/LF must not forge AUDIT rows). Bounded copy in which every
;   byte < 0x20, 0x7F and '\' itself is stored as the 4-char escape "\xHH", so
;   a stored row never holds a control byte and escapes stay unambiguous. An
;   escape that does not fit whole is dropped, never split. ALWAYS NUL-terminates
;   (size 0: no write). clobbers: RAX,RCX,RDX,RSI,RDI,R8.
audit_store_text:
    test edx, edx
    jz   .out
    lea  r8, [rdi + rdx - 1]            ; the NUL slot
.loop:
    movzx eax, byte [rsi]
    test eax, eax
    jz   .term
    cmp  eax, 0x20
    jb   .esc
    cmp  eax, 0x7F
    je   .esc
    cmp  eax, '\'
    je   .esc
    cmp  rdi, r8
    jae  .term
    mov  [rdi], al
    inc  rdi
    inc  rsi
    jmp  .loop
.esc:
    lea  rcx, [rdi + 4]
    cmp  rcx, r8
    ja   .term                          ; the whole escape must fit before the NUL
    mov  byte [rdi], '\'
    mov  byte [rdi + 1], 'x'
    mov  ecx, eax
    shr  ecx, 4
    lea  rdx, [rel audit_hex_digits]
    movzx ecx, byte [rdx + rcx]
    mov  [rdi + 2], cl
    and  eax, 0x0F
    movzx eax, byte [rdx + rax]
    mov  [rdi + 3], al
    add  rdi, 4
    inc  rsi
    jmp  .loop
.term:
    mov  byte [rdi], 0
.out:
    ret

audit_put_dec:                          ; RDI = value
    mov  rsi, [rel audit_out_cur]
    lea  rax, [rel audit_out_buf + AUDIT_OUT_MAX - 24]
    cmp  rsi, rax
    jae  .full                          ; no room for 20 digits + NUL
    push rsi
    call fmt_dec                        ; RAX = digit count, NUL-terminates
    pop  rsi
    add  rsi, rax
    mov  [rel audit_out_cur], rsi
    ret
.full:
    mov  byte [rel audit_out_full], 1
    ret

; audit_put_src(EDI = AUDIT_NSRC_*) / audit_put_svc(EDI = AUDIT_NSVC_*)
audit_put_src:
    lea  rax, [rel str_audit_any]
    cmp  edi, AUDIT_NSRC_UDP
    jne  .ssh
    lea  rax, [rel str_audit_udp]
.ssh:
    cmp  edi, AUDIT_NSRC_SSH
    jne  .put
    lea  rax, [rel str_audit_ssh]
.put:
    mov  rdi, rax
    jmp  audit_put_str

audit_put_svc:
    lea  rax, [rel str_audit_any]
    cmp  edi, AUDIT_NSVC_AUTH1
    jne  .ssh
    lea  rax, [rel str_audit_auth1]
.ssh:
    cmp  edi, AUDIT_NSVC_SSH
    jne  .put
    lea  rax, [rel str_audit_ssh]
.put:
    mov  rdi, rax
    jmp  audit_put_str

; audit_parse_view(RDI = text arg or 0) -> RAX = count (0 = default),
;   EDX = 1 for the "net" view, AUDIT_VIEW_SEC for the "sec" view, ECX = 1
;   when the count overflowed u64 or strict guardian arguments are invalid.
;   EDX = AUDIT_VIEW_GUARDIAN for exact `guardian` plus optional spaces.
;   Strict numeric fallback: the count is the leading decimal run exactly as
;   the u64 marshaller parsed it before AUDIT took text ("12" -> 12, "" or a
;   non-numeric token -> 0), so `AUDIT` / `AUDIT <n>` replies are unchanged.
audit_parse_view:
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
    test rdi, rdi
    jz   .out
.lead:
    cmp  byte [rdi], ' '
    jne  .kw
    inc  rdi
    jmp  .lead
.kw:
    cmp  byte [rdi], 'g'
    je   .kw_guardian
    cmp  byte [rdi], 'n'
    jne  .kw_sec
    cmp  byte [rdi + 1], 'e'
    jne  .num
    cmp  byte [rdi + 2], 't'
    jne  .num
    movzx r8d, byte [rdi + 3]
    test r8d, r8d
    jz   .is_net
    cmp  r8d, ' '
    jne  .num
.is_net:
    mov  edx, 1
    add  rdi, 3
    jmp  .sp
; BEGIN Guardian status selector
.kw_guardian:
    cmp  byte [rdi + 1], 'u'
    jne  .num
    cmp  byte [rdi + 2], 'a'
    jne  .num
    cmp  byte [rdi + 3], 'r'
    jne  .num
    cmp  byte [rdi + 4], 'd'
    jne  .num
    cmp  byte [rdi + 5], 'i'
    jne  .num
    cmp  byte [rdi + 6], 'a'
    jne  .num
    cmp  byte [rdi + 7], 'n'
    jne  .num
    mov  edx, AUDIT_VIEW_GUARDIAN
    add  rdi, 8
.guardian_tail:
    cmp  byte [rdi], 0
    je   .out
    cmp  byte [rdi], ' '
    jne  .guardian_badarg
    inc  rdi
    cmp  byte [rdi], 's'
    je   .guardian_sources_kw
    cmp  byte [rdi], 'w'
    je   .guardian_window_kw
    jmp  .guardian_tail
; BEGIN Guardian window selector
.guardian_window_kw:
    cmp  byte [rdi + 1], 'i'
    jne  .guardian_badarg
    cmp  byte [rdi + 2], 'n'
    jne  .guardian_badarg
    cmp  byte [rdi + 3], 'd'
    jne  .guardian_badarg
    cmp  byte [rdi + 4], 'o'
    jne  .guardian_badarg
    cmp  byte [rdi + 5], 'w'
    jne  .guardian_badarg
    add  rdi, 6
    mov  edx, AUDIT_VIEW_GUARDIAN_WINDOW
.guardian_window_tail:
    cmp  byte [rdi], 0
    je   .out
    cmp  byte [rdi], ' '
    jne  .guardian_badarg
    inc  rdi
    jmp  .guardian_window_tail
; END Guardian window selector
; BEGIN Guardian sources selector
.guardian_sources_kw:
    cmp  byte [rdi + 1], 'o'
    jne  .guardian_badarg
    cmp  byte [rdi + 2], 'u'
    jne  .guardian_badarg
    cmp  byte [rdi + 3], 'r'
    jne  .guardian_badarg
    cmp  byte [rdi + 4], 'c'
    jne  .guardian_badarg
    cmp  byte [rdi + 5], 'e'
    jne  .guardian_badarg
    cmp  byte [rdi + 6], 's'
    jne  .guardian_badarg
    add  rdi, 7
    mov  edx, AUDIT_VIEW_GUARDIAN_SOURCES
.guardian_sources_tail:
    cmp  byte [rdi], 0
    je   .out
    cmp  byte [rdi], ' '
    jne  .guardian_badarg
    inc  rdi
    jmp  .guardian_sources_tail
; END Guardian sources selector
.guardian_badarg:
    mov  ecx, 1
    ret
; END Guardian status selector
.kw_sec:
    cmp  byte [rdi], 's'
    jne  .num
    cmp  byte [rdi + 1], 'e'
    jne  .num
    cmp  byte [rdi + 2], 'c'
    jne  .num
    movzx r8d, byte [rdi + 3]
    test r8d, r8d
    jz   .is_sec
    cmp  r8d, ' '
    jne  .num
.is_sec:
    mov  edx, AUDIT_VIEW_SEC
    add  rdi, 3
.sp:
    cmp  byte [rdi], ' '
    jne  .num
    inc  rdi
    jmp  .sp
.num:
    movzx r8d, byte [rdi]
    sub  r8d, '0'
    cmp  r8d, 9
    ja   .out
    mov  r9, 10
    push rdx
    mul  r9                             ; RDX:RAX = count * 10
    test rdx, rdx
    pop  rdx
    jnz  .overflow
    add  rax, r8
    jc   .overflow
    inc  rdi
    jmp  .num
.overflow:
    xor  eax, eax
    mov  ecx, 1
.out:
    ret

; Exact, count-free CPU view. 0=legacy parser,1=cpu,-1=malformed cpu prefix.
; Read each byte only after its predecessor matched; short tokens are safe.
audit_parse_cpu:
    mov dword [rel audit_cpu_policy_page],0
    xor  eax, eax
    test rdi, rdi
    jz   .out
.lead:
    cmp  byte [rdi], ' '
    jne  .word
    inc  rdi
    jmp  .lead
.word:
    cmp  byte [rdi], 'c'
    jne  .out
    inc  rdi
    cmp  byte [rdi], 'p'
    jne  .out
    inc  rdi
    cmp  byte [rdi], 'u'
    jne  .out
    inc  rdi
    cmp byte [rdi],0
    je .tail
    cmp byte [rdi],' '
    jne .bad
.tail:
    cmp  byte [rdi], ' '
    jne  .end
    inc  rdi
    jmp  .tail
.end:
    mov  eax, 1
    cmp  byte [rdi], 0
    je   .out
    ; Exact optional policy page, bounded canonical token parser.
    lea rsi,[rel audit_policy_word]
.policy_word:
    mov al,[rsi]
    test al,al
    jz .policy_number
    cmp [rdi],al
    jne .bad
    inc rdi
    inc rsi
    jmp .policy_word
.policy_number:
    call cpu_policy_report_parse
    test eax,eax
    js .bad
    inc eax
    mov [rel audit_cpu_policy_page],eax
    mov eax,1
    ret
.bad:
    mov  rax, -1
.out:
    ret

audit_policy_word: db 'policy ',0

; Same staged buffer and whole-snapshot refusal as existing AUDIT views.
; SHA256 binds the reviewed source census in docs/t1_6_absent_boundaries.json.
audit_absent_boundary_word: db " ABSENTBOUNDARY=v1;sha256=de9a352fa0986522a95ffadaf716d0c291d6a188d7ca50e46a823a178fd54e0c;n=3;kpti=no-host-cpl3;swapgs_entry=no-host-user-syscall;user_return=no-host-user-return;other=not-exempt", 0
audit_cpu_view:
    call audit_out_reset
    mov edx,[rel audit_cpu_policy_page]
    test edx,edx
    jz .legacy
    dec edx
    lea rdi,[rel audit_out_buf]
    mov esi,AUDIT_OUT_MAX
    call cpu_policy_report_page
    test rax,rax
    js .full
    lea rdx,[rel audit_out_buf]
    add rdx,rax
    mov [rel audit_out_cur],rdx
    ret
.legacy:
    call cpu_policy_report_capture
    lea  rdi, [rel audit_out_buf]
    mov  esi, AUDIT_OUT_MAX
    xor  edx, edx
    call cpu_security_report_text
    test rax, rax
    js   .full
    push rax
    lea  rdi, [rel audit_out_buf]
    add  rdi, rax
    mov  esi, AUDIT_OUT_MAX
    sub  esi, eax
    call cpu_microcode_boot_checked_text
    pop  rdx
    test rax, rax
    js   .full
    add  rax, rdx
    lea  rdx, [rel audit_out_buf]
    add  rdx, rax
    mov  [rel audit_out_cur], rdx
    ; X6 uses the existing bounded staged buffer and whole-snapshot refusal.
    lea  rdi, [rel audit_absent_boundary_word]
    call audit_put_str
    ret
.full:
    mov  byte [rel audit_out_buf], 0
    mov  byte [rel audit_out_full], 1
    ret

; ---------------------------------------------------------------------------
; VERB: AUDIT [n] | AUDIT net [n] | AUDIT sec [n] | AUDIT guardian
;   AUDIT [n] — dump the last n receipts (default/cap AUDIT_DUMP_DEF),
;   oldest-first: " audit seq=<total> n=<shown>" then per receipt
;   CRLF "A<seq> <text>" (a remote-attempt row that absorbed repeats adds
;   " x<count>"). The receipts are read BACK from the ring — the same bytes
;   the producers stored, so the dump content-grades the whole path.
;   AUDIT net [n] — the structured remote-attempt view (default/cap
;   AUDIT_NET_DEF rows), NEWEST-first so a reply-budget cut drops the oldest:
;   " audit seq=<total> n=<shown> view=net" then per row CRLF
;   "A<seq> src=<udp|ssh|any> svc=<auth1|ssh|any> pid=<n|none> verb=<VERB>
;    res=<admit|blocked:<r>|refused:<r>> t=<boot ms>[ x<count> last=<ms>]".
;   AUDIT sec [n] — the GD1 typed spine snapshot (default/cap AUDIT_SEC_DEF
;   records), NEWEST-first: " audit sec_seq=<typed records ever> n=<shown>
;   view=sec sec_drop=<overwritten> pub_ok=<n> pub_refused=<n> pub_held=<n>
;   pub_info=<n> pub_first=<t_us> pub_last=<t_us>" (public totals summed over
;   classes; first/last span every non-empty cell) then per record CRLF
;   "S<seq> t=<t_us> c=<class> p=<owner|system> s=<subject> v=<verdict>
;   r=<reason>". Same verb, same registration, same remote gate as AUDIT: any
;   principal that gate admits may read it - today the owner and the SYSTEM
;   operational AI principal (it is neither owner-exclusive nor read-only
;   authority). The readout never accounts an event itself.
;   AI scope (RCQ-26, root 2026-10-17 14:09:49): models get exactly the
;   advisor's one window. An AI-originated request (REQ_SOURCE AIHOOK: the AI
;   submits, a nested HOOK that copies it, a tethered keyprov line) reads AUDIT
;   sec as above; every other view (guardian, window, sources, net, cpu, the
;   receipts) is refused CMDE_AUTHDENY "refused:ai_scope view=sec_only", with
;   the earlier view wiped from the in-process buffer. Owner AUDIT is unchanged.
; ---------------------------------------------------------------------------
cmd_verb_audit:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rsi                       ; resp
    mov  r12, [rdi + REQ_ARG]           ; ARGT_TEXT token (may be 0 for internal callers)
    mov  [rel audit_req_arg], r12
    mov  rax, [rdi + REQ_SOURCE]
    mov  [rel audit_req_src], rax
    mov  rdi, r12
    call audit_parse_cpu
    test rax, rax
    js   .badarg
    jnz  .cpu_view
    mov  rdi, r12
    call audit_parse_view
    cmp  qword [rel audit_req_src], CMD_SOURCE_AIHOOK
    jne  .view_route
    test ecx, ecx
    jnz  .view_route                    ; malformed stays BADARG for every source
    cmp  edx, AUDIT_VIEW_SEC
    jne  .ai_scope
.view_route:
    cmp  edx, AUDIT_VIEW_GUARDIAN_WINDOW
    je   .guardian_window_view
    cmp  edx, AUDIT_VIEW_GUARDIAN_SOURCES
    je   .guardian_sources_view
    cmp  edx, AUDIT_VIEW_GUARDIAN
    je   .guardian_view
    test ecx, ecx
    jnz  .badarg
    mov  r14, rax                       ; requested count (0 -> default)
    cmp  edx, AUDIT_VIEW_SEC
    je   .sec_view
    test edx, edx
    jnz  .net_view
    mov  eax, AUDIT_DUMP_DEF
    test r14, r14
    jz   .use_def
    cmp  r14, rax
    jbe  .have_n
.use_def:
    mov  r14, rax
.have_n:
    mov  rax, [rel audit_seq]
    cmp  r14, rax
    jbe  .n_ok                          ; can't show more receipts than ever written
    mov  r14, rax
.n_ok:
    call audit_out_reset
    lea  rdi, [rel str_audit_hdr]       ; " audit seq="
    call audit_put_str
    mov  rdi, [rel audit_seq]
    call audit_put_dec
    lea  rdi, [rel str_audit_n]         ; " n="
    call audit_put_str
    mov  rdi, r14
    call audit_put_dec
    ; walk the last r14 receipts oldest-first: slot = (head - r14 + k) mod NREC
    mov  ebx, [rel audit_head]
    add  ebx, AUDIT_NREC
    sub  ebx, r14d                      ; ebx = first slot (un-modded)
    mov  r12, r14                       ; receipts remaining
.loop:
    test r12, r12
    jz   .done
    mov  eax, ebx
    xor  edx, edx
    mov  ecx, AUDIT_NREC
    div  ecx                            ; edx = slot mod NREC
    mov  eax, edx
    imul rax, rax, AUDIT_REC_SZ
    lea  r15, [rel audit_ring]
    add  r15, rax                       ; r15 = receipt slot
    lea  rdi, [rel str_audit_rec]       ; CRLF "A"
    call audit_put_str
    mov  rdi, [r15]                     ; receipt seq
    call audit_put_dec
    lea  rdi, [rel str_audit_sp]
    call audit_put_str
    lea  rdi, [r15 + AR_TEXT]           ; the receipt text, read back from the ring
    call audit_put_text
    cmp  byte [r15 + AR_KIND], AUDIT_KIND_NET
    jne  .next
    cmp  dword [r15 + AR_COUNT], 1
    jbe  .next
    lea  rdi, [rel str_audit_x]         ; " x"
    call audit_put_str
    mov  edi, [r15 + AR_COUNT]
    call audit_put_dec
.next:
    inc  ebx
    dec  r12
    jmp  .loop

.net_view:
    mov  eax, AUDIT_NET_DEF
    test r14, r14
    jz   .net_def
    cmp  r14, rax
    jbe  .net_have
.net_def:
    mov  r14, rax
.net_have:
    ; count the remote-attempt rows still in the ring (newest-first walk)
    mov  rax, [rel audit_seq]
    mov  r12d, AUDIT_NREC
    cmp  rax, r12
    jae  .net_live
    mov  r12, rax                       ; fewer receipts ever written than slots
.net_live:
    xor  r15d, r15d                     ; net rows shown
    mov  ebx, [rel audit_head]
    add  ebx, AUDIT_NREC - 1            ; newest slot (un-modded)
    push r12
    push rbx
    xor  ecx, ecx                       ; rows to show = min(n, net rows live)
.net_count:
    test r12, r12
    jz   .net_counted
    cmp  rcx, r14
    jae  .net_counted
    mov  eax, ebx
    xor  edx, edx
    push rcx
    mov  ecx, AUDIT_NREC
    div  ecx
    pop  rcx
    imul rdx, rdx, AUDIT_REC_SZ
    lea  rax, [rel audit_ring]
    cmp  byte [rax + rdx + AR_KIND], AUDIT_KIND_NET
    jne  .net_count_next
    inc  rcx
.net_count_next:
    dec  ebx
    dec  r12
    jmp  .net_count
.net_counted:
    pop  rbx
    pop  r12
    mov  [rel audit_net_shown], rcx
    call audit_out_reset
    lea  rdi, [rel str_audit_hdr]
    call audit_put_str
    mov  rdi, [rel audit_seq]
    call audit_put_dec
    lea  rdi, [rel str_audit_n]
    call audit_put_str
    mov  rdi, [rel audit_net_shown]
    call audit_put_dec
    lea  rdi, [rel str_audit_view_net]  ; " view=net"
    call audit_put_str
.net_loop:
    test r12, r12
    jz   .done
    cmp  r15, [rel audit_net_shown]
    jae  .done
    mov  eax, ebx
    xor  edx, edx
    mov  ecx, AUDIT_NREC
    div  ecx
    imul rdx, rdx, AUDIT_REC_SZ
    lea  rax, [rel audit_ring]
    add  rdx, rax
    cmp  byte [rdx + AR_KIND], AUDIT_KIND_NET
    jne  .net_skip
    push rdx
    mov  rdi, rdx
    call audit_put_net_row
    pop  rdx
    inc  r15
.net_skip:
    dec  ebx
    dec  r12
    jmp  .net_loop

; BEGIN Guardian window handler
.guardian_window_view:
    test ecx, ecx
    jnz  .guardian_badarg
    call audit_guardian_window_render
    jmp  .sec_done                         ; existing private admitted-source staging
; END Guardian window handler
; BEGIN Guardian sources handler
.guardian_sources_view:
    test ecx, ecx
    jnz  .guardian_badarg
%if !PAOS_PUBLIC_BUILD
    call audit_guardian_sources_render
%else
    jmp .guardian_badarg
%endif
    jmp  .sec_done                       ; unchanged admitted-source staging
; END Guardian sources handler
; BEGIN Guardian status handler
.guardian_view:
    test ecx, ecx
    jnz  .guardian_badarg
    call audit_guardian_render
    jmp  .sec_done                       ; existing source-aware staging/echo
.guardian_badarg:
    mov  byte [rel audit_out_ready], 0
    jmp  .badarg
; END Guardian status handler
.cpu_view:
    cmp  qword [rel audit_req_src], CMD_SOURCE_AIHOOK
    je   .ai_scope
    ; No event, authority change or inherited transport staging flag.
    mov  byte [rel audit_out_ready], 0
    call audit_cpu_view
    jmp  .sec_done
.sec_view:
    mov  eax, AUDIT_SEC_DEF
    test r14, r14
    jz   .sec_def
    cmp  r14, rax
    jbe  .sec_have
.sec_def:
    mov  r14, rax
.sec_have:
    mov  rax, [rel audit_sec_seq]
    cmp  r14, rax
    jbe  .sec_n                         ; can't show more records than ever written
    mov  r14, rax
.sec_n:
    call audit_sec_render
.sec_done:
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  rax, [rel audit_req_arg]
    mov  [r13 + RSP_VAL], rax
    ; Stage the reply only for a transport that frames audit_out_buf (UDP, and
    ; SSH and the owner console via command_udp_capture_reply). The flag was
    ; cleared above, so an in-process reader (AI hook, serial, internal) reads the buffer
    ; directly and leaves no flag, its own or inherited, for a later, possibly
    ; anonymous, reply to frame.
    mov  rax, [rel audit_req_src]
    cmp  rax, CMD_SOURCE_UDP
    je   .sec_stage
    cmp  rax, CMD_SOURCE_CONSOLE
    je   .sec_stage
    cmp  rax, CMD_SOURCE_SSH
    jne  .out
.sec_stage:
    mov  byte [rel audit_out_ready], 1
    jmp  .out

.done:
    call audit_put_legacy_exhaustion
    mov  byte [rel audit_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    ; ARGT_TEXT echo convention: RSP_VAL is the request's own token pointer
    ; (the serial projection asserts the round-trip); the totals ride the dump.
    mov  rax, [rel audit_req_arg]
    mov  [r13 + RSP_VAL], rax
    jmp  .out
.ai_scope:
    call audit_out_reset
    lea  rdi, [rel str_audit_ai_scope]
    call audit_put_str
    mov  byte [rel audit_out_ready], 0
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    lea  rax, [rel str_audit_ai_scope]
    mov  [r13 + RSP_HINT], rax
    jmp  .out
.badarg:
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .out
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Finite legacy receipt namespace: this suffix appears only at exhaustion.
; Unstored counts attempts needing a new row; existing repeat/flood rows keep
; their bounded count/tlast behavior and are not counted as missing receipts.
; A saturated counter is a lower bound, never an enforcement or auth verdict.
audit_put_legacy_exhaustion:
    cmp  qword [rel audit_seq], -1
    jne  .done
    lea  rdi, [rel str_audit_legacy_exhausted]
    call audit_put_str
    mov  rdi, [rel audit_legacy_unstored]
    call audit_put_dec
.done:
    ret

; BEGIN Guardian window renderer
; Read-only completed-watch facts. Copy before formatting, no clock/drain/ack.
; Not attack evidence, enforcement or authority. Existing status stays version1.
AUDIT_GUARDIAN_WINDOW_MAX equ 256
    times -((AUDIT_GUARDIAN_WINDOW_MAX + 24) >= AUDIT_OUT_MAX) db 0
audit_guardian_window_render:
    push rbx
    sub  rsp, 32
    mov  rax, [rel audit_guardian_window_min]
    mov  [rsp], rax
    mov  rax, [rel audit_guardian_window_sources]
    mov  [rsp + 8], rax
    mov  rax, [rel audit_guardian_window_ms]
    mov  [rsp + 16], rax
    movzx eax, byte [rel audit_guardian_window_quality]
    mov  [rsp + 24], rax
    mov  al, [rel audit_guardian_window_overflow]
    mov  [rsp + 25], al
    mov  byte [rel audit_out_ready], 0
    call audit_out_reset
    lea  rdi, [rel str_audit_gwindow_hdr]
    call audit_put_str
    mov  rdi, [rsp]
    call .number
    lea  rdi, [rel str_audit_gwindow_quality]
    call audit_put_str
    lea  rdi, [rel str_audit_guardian_unavailable]
    cmp  byte [rsp + 24], 0
    je   .quality_name
    lea  rdi, [rel str_audit_gsources_exact]
    cmp  byte [rsp + 24], 1
    je   .quality_name
    lea  rdi, [rel str_audit_gsources_lower]
.quality_name:
    call audit_put_str
    lea  rdi, [rel str_audit_gwindow_exact]
    call audit_put_str
    lea  rdi, [rel str_audit_guardian_unavailable]
    cmp  byte [rsp + 24], 1
    jne  .exact_name
    lea  rdi, [rel str_audit_guardian_available]
.exact_name:
    call audit_put_str
    lea  rdi, [rel str_audit_gwindow_sources]
    call audit_put_str
    mov  rdi, [rsp + 8]
    call .number
    lea  rdi, [rel str_audit_gwindow_overflow]
    call audit_put_str
    movzx edi, byte [rsp + 25]
    call .number
    lea  rdi, [rel str_audit_gwindow_ms]
    call audit_put_str
    mov  rdi, [rsp + 16]
    call .number
    add  rsp, 32
    pop  rbx
    ret
.number:
    ; Helper return address shifts the captured quality byte by8.
    cmp  byte [rsp + 32], 0
    jne  .numeric
    lea  rdi, [rel str_audit_guardian_unavailable]
    jmp  audit_put_str
.numeric:
    jmp  audit_put_dec
; END Guardian window renderer

%if !PAOS_PUBLIC_BUILD
; BEGIN Guardian sources renderer
; Current owner-seen observations, not the composition of a historical watch
; window. Snapshot all eleven sources before the first formatting helper. No
; clock, watch, producer, acknowledgement or event call; no private identities.
; Header/rows fit1480 bytes even with every value MAX and every quality lower.
AUDIT_GUARDIAN_SOURCES_MAX equ 1480
    times -((AUDIT_GUARDIAN_SOURCES_MAX + 24) >= AUDIT_OUT_MAX) db 0
audit_guardian_sources_render:
    push rbx
    push r12
    push r15
    sub  rsp, GUARDIAN_SOURCES_STACK
    mov  rdi, rsp
    mov  esi, GUARDIAN_SOURCES_SIZE
    call guardian_alert_sources_snapshot ; fixed non-null writable stack288
    mov  byte [rel audit_out_ready], 0
    call audit_out_reset
    lea  rdi, [rel str_audit_gsources_hdr]
    call audit_put_str
    mov  rdi, [rsp]
    call audit_put_dec
    lea  rdi, [rel str_audit_gsources_unseen]
    call audit_put_str
    mov  rdi, [rsp + 8]
    call audit_put_dec
    lea  rdi, [rel str_audit_gsources_total_q]
    call audit_put_str
    mov  rdi, [rsp + 16]
    shr  edi, 1
    and  edi, 1
    call .quality
    lea  rdi, [rel str_audit_gsources_unseen_q]
    call audit_put_str
    mov  rdi, [rsp + 16]
    and  edi, 1
    call .quality
    lea  r12, [rsp + 24]
    lea  r15, [rel audit_guardian_sources_names]
    xor  ebx, ebx
.row:
    lea  rdi, [rel str_audit_gsources_row]
    call audit_put_str
    lea  edi, [ebx + 1]
    call audit_put_dec
    lea  rdi, [rel str_audit_gsources_source]
    call audit_put_str
    mov  rdi, [r15 + rbx * 8]            ; signed offset from table, not a load address
    add  rdi, r15                           ; resolve in the actual loaded image
    call audit_put_str
    lea  rdi, [rel str_audit_gsources_total]
    call audit_put_str
    mov  rdi, [r12]
    call audit_put_dec
    lea  rdi, [rel str_audit_gsources_unseen]
    call audit_put_str
    mov  rdi, [r12 + 8]
    call audit_put_dec
    lea  rdi, [rel str_audit_gsources_quality]
    call audit_put_str
    mov  rdi, [r12 + 16]                 ; 0 or3: both per-source counts same quality
    call .quality
    cmp  ebx, 10
    jne  .row_done
    lea  rdi, [rel str_audit_gsources_mca_handling]
    call audit_put_str
.row_done:
    add  r12, 24
    inc  ebx
    cmp  ebx, 11
    jb   .row
    add  rsp, GUARDIAN_SOURCES_STACK
    pop  r15
    pop  r12
    pop  rbx
    ret
.quality:
    test edi, edi
    lea  rdi, [rel str_audit_gsources_exact]
    jz   .put_quality
    lea  rdi, [rel str_audit_gsources_lower]
.put_quality:
    jmp  audit_put_str
; END Guardian sources renderer

%endif
; BEGIN Guardian status renderer
; AUDIT guardian: retained BSP facts only, not a new clock sample or decision.
; last_emit_ms is rebased on clock recovery, so expose it as cooldown origin.
; No exact last-event reason/time/composition snapshot exists. No acknowledgement.
; All puts use the existing bounded reply buffer; no watch/producer/authority write.
audit_guardian_render:
    push rbx
    mov  byte [rel audit_out_ready], 0
    call audit_out_reset
    movzx ebx, byte [rel audit_guardian_clock_state]
    lea  rdi, [rel str_audit_guardian_hdr]
    call audit_put_str
    lea  rdi, [rel str_audit_guardian_unavailable]
    cmp  ebx, 1
    je   .available
    cmp  ebx, 3
    jne  .clock_name
    lea  rdi, [rel str_audit_guardian_overflow]
    jmp  .clock_name
.available:
    lea  rdi, [rel str_audit_guardian_available]
.clock_name:
    call audit_put_str
    lea  rdi, [rel str_audit_guardian_decisions]
    call audit_put_str
    mov  rdi, [rel audit_guardian_shadow_decisions]
    call audit_put_dec
    lea  rdi, [rel str_audit_guardian_burst]
    call audit_put_str
    movzx edi, byte [rel audit_guardian_in_burst]
    call audit_put_dec
    lea  rdi, [rel str_audit_guardian_clock_ms]
    call audit_put_str
    mov  rdi, [rel audit_guardian_clock_ms]
    call .valid_time
    lea  rdi, [rel str_audit_guardian_next_ms]
    call audit_put_str
    cmp  ebx, 1
    jne  .next_unavailable
    mov  rdi, [rel audit_guardian_next_ms]
    call audit_put_dec
    jmp  .origin
.next_unavailable:
    lea  rdi, [rel str_audit_guardian_unavailable]
    call audit_put_str
.origin:
    lea  rdi, [rel str_audit_guardian_origin_ms]
    call audit_put_str
    mov  rdi, [rel audit_guardian_last_emit_ms]
    test rdi, rdi
    jz   .origin_unavailable
    call .valid_time
    jmp  .done
.origin_unavailable:
    lea  rdi, [rel str_audit_guardian_unavailable]
    call audit_put_str
.done:
    pop  rbx
    ret
.valid_time:
    cmp  ebx, 1
    je   .numeric_time
    cmp  ebx, 3
    je   .numeric_time
    lea  rdi, [rel str_audit_guardian_unavailable]
    jmp  audit_put_str
.numeric_time:
    jmp  audit_put_dec
; END Guardian status renderer

; audit_sec_render(R14 = record count, already clamped to AUDIT_SEC_DEF and
;   audit_sec_seq) — write the `AUDIT sec` view into audit_out_buf and clear
;   audit_out_ready (the text describes no staged reply). Shared by the AUDIT
;   verb and the advisor's in-process read; it accounts nothing and reads only
;   the spine. clobbers: caller-saved (RBX, R12, R15 preserved).
audit_sec_render:
    push rbx
    push r12
    push r15
    ; The flag must describe THIS request only: a legacy AUDIT / AUDIT net
    ; (which always stages) leaves it set, and this snapshot overwrites the
    ; buffer it pointed at. Drop the inherited flag before writing.
    mov  byte [rel audit_out_ready], 0
    call audit_out_reset
    lea  rdi, [rel str_audit_k_secseq]  ; " audit sec_seq="
    call audit_put_str
    mov  rdi, [rel audit_sec_seq]
    call audit_put_dec
    lea  rdi, [rel str_audit_n]
    call audit_put_str
    mov  rdi, r14
    call audit_put_dec
    lea  rdi, [rel str_audit_view_sec]
    call audit_put_str
    lea  rdi, [rel str_audit_k_drop]
    call audit_put_str
    mov  rdi, [rel audit_sec_drop]
    call audit_put_dec
    lea  r15, [rel audit_sec_pub_keys]  ; " pub_ok=" .. " pub_info=", one per verdict
    mov  ebx, AUDIT_SEC_V_ALLOWED
.sec_pub:
    mov  rdi, r15
    call audit_put_str
.sec_pub_key:
    inc  r15                            ; step past this key's NUL
    cmp  byte [r15 - 1], 0
    jne  .sec_pub_key
    mov  edi, ebx
    call audit_sec_pub_total
    mov  rdi, rax
    call audit_put_dec
    inc  ebx
    cmp  ebx, AUDIT_SEC_NVERDICT
    jbe  .sec_pub
    call audit_sec_pub_span             ; RAX = first, RDX = last
    mov  rbx, rax
    mov  r15, rdx
    lea  rdi, [rel str_audit_k_pubfirst]
    call audit_put_str
    mov  rdi, rbx
    call audit_put_dec
    lea  rdi, [rel str_audit_k_publast]
    call audit_put_str
    mov  rdi, r15
    call audit_put_dec
    lea  rdi, [rel str_audit_k_ai_refused]
    call audit_put_str
    mov  rdi, [rel audit_aihook_refused]
    call audit_put_dec
    ; newest-first: seq = sec_seq - 1 down to sec_seq - n, slot = seq mod NREC
    mov  r12, [rel audit_sec_seq]
    mov  rbx, r14                       ; records remaining
.sec_loop:
    test rbx, rbx
    jz   .done
    dec  r12
    mov  eax, r12d
    and  eax, AUDIT_SEC_NREC - 1
    imul eax, eax, AUDIT_SEC_REC_SZ
    lea  r15, [rel audit_sec_ring]
    add  r15, rax                       ; r15 = record
    lea  rdi, [rel str_audit_sec_rec]   ; CRLF "S"
    call audit_put_str
    mov  rdi, [r15 + ASR_SEQ]
    call audit_put_dec
    lea  rdi, [rel str_audit_k_t]
    call audit_put_str
    mov  rdi, [r15 + ASR_T]
    call audit_put_dec
    lea  rdi, [rel str_audit_k_c]
    call audit_put_str
    lea  rdi, [rel audit_sec_class_names]
    movzx esi, byte [r15 + ASR_CLASS]
    mov  edx, AUDIT_SEC_NCLASS + 1
    call audit_sec_put_name
    lea  rdi, [rel str_audit_k_p]
    call audit_put_str
    lea  rdi, [rel audit_sec_prin_names]
    movzx esi, byte [r15 + ASR_PRIN]
    mov  edx, 4
    call audit_sec_put_name
    lea  rdi, [rel str_audit_k_s]
    call audit_put_str
    mov  edi, [r15 + ASR_SUBJECT]
    call audit_put_dec
    lea  rdi, [rel str_audit_k_v]
    call audit_put_str
    lea  rdi, [rel audit_sec_verdict_names]
    movzx esi, byte [r15 + ASR_VERDICT]
    mov  edx, AUDIT_SEC_NVERDICT + 1
    call audit_sec_put_name
    lea  rdi, [rel str_audit_k_r]
    call audit_put_str
    movzx edi, word [r15 + ASR_REASON]
    call audit_put_dec
    cmp  byte [r15 + ASR_CLASS], AUDIT_SEC_C_IOMMU
    je   .native_identity
    cmp  byte [r15 + ASR_CLASS], AUDIT_SEC_C_USB_HID
    je   .native_identity
    cmp  byte [r15 + ASR_CLASS], AUDIT_SEC_C_NET_ARP
    jne  .next_record
.native_identity:
    lea  rdi, [rel str_audit_k_iommu_id]
    call audit_put_str
    movzx edi, word [r15 + ASR_EPOCH]
    shl  rdi, 32
    mov  eax, [r15 + ASR_EVENT]
    or   rdi, rax
    call audit_put_dec
    cmp  byte [r15 + ASR_CLASS], AUDIT_SEC_C_IOMMU
    jne  .next_record
    cmp  byte [r15 + ASR_BACKEND], 4
    jne  .next_record
    lea  rdi, [rel str_audit_k_amd_backend]
    call audit_put_str
    mov  edi, 4
    call audit_put_dec
.next_record:
    dec  rbx
    jmp  .sec_loop
.done:
    ; Numeric native summary only; preserve the existing row schema/decoder.
    cmp  qword [rel audit_session_refused], 0
    je   .session_done
    lea  rdi, [rel str_audit_k_session_refused]
    call audit_put_str
    mov  rdi, [rel audit_session_refused]
    call audit_put_dec
    lea  rdi, [rel str_audit_k_session_coalesced]
    call audit_put_str
    mov  rdi, [rel audit_session_coalesced]
    call audit_put_dec
.session_done:
%if !PAOS_PUBLIC_BUILD
    ; Native AIRLOCK lifetime total includes boot proofs. Queue loss and
    ; quota/ceiling omission are independent; none acknowledges an observation.
    cmp  qword [rel airlock_refused_count], 0
    je   .airlock_done
    lea  rdi, [rel str_audit_k_airlock_refused]
    call audit_put_str
    mov  rdi, [rel airlock_refused_count]
    call audit_put_dec
    lea  rdi, [rel str_audit_k_airlock_dropped]
    call audit_put_str
    mov  rdi, [rel airlock_detail_drops]
    call audit_put_dec
    lea  rdi, [rel str_audit_k_airlock_coalesced]
    call audit_put_str
    mov  rdi, [rel audit_airlock_coalesced]
    call audit_put_dec
.airlock_done:
%endif
    ; Read-only software-mask observations, including deliberate test probes.
    ; Append after complete rows to preserve the bounded native decoder schema.
    lea  rdi, [rel str_audit_k_software_cap_denied]
    call audit_put_str
    mov  rdi, [rel cap_denied_count]
    call audit_put_dec
    pop  r15
    pop  r12
    pop  rbx
    ret

; audit_sec_advisor_view -> RAX = NUL-terminated `AUDIT sec` text (newest
;   min(AUDIT_SEC_DEF, records) typed rows and the public counters), RDX = its
;   length. SEC-GA2(b): the advisor's ONLY window on the spine. An in-process
;   read: no request, no gate, no dispatch, no verb authority, no event. The
;   text lives in audit_out_buf until the next AUDIT render.
;   clobbers: caller-saved.
audit_sec_advisor_view:
    push r14
    mov  r14d, AUDIT_SEC_DEF
    cmp  r14, [rel audit_sec_seq]
    jbe  .n
    mov  r14, [rel audit_sec_seq]
.n:
    call audit_sec_render
    lea  rax, [rel audit_out_buf]
    mov  rdx, [rel audit_out_cur]
    sub  rdx, rax
    pop  r14
    ret

; audit_sec_held(EDI = class, ESI = principal) -> EAX = typed records of that
;   class and principal still held in the ring. Read only.
;   clobbers: RAX,RCX,RDX,R8.
audit_sec_held:
    mov  rcx, [rel audit_sec_seq]
    cmp  rcx, AUDIT_SEC_NREC
    jbe  .n
    mov  ecx, AUDIT_SEC_NREC
.n:
    lea  r8, [rel audit_sec_ring]
    xor  eax, eax
.scan:
    test ecx, ecx
    jz   .out
    movzx edx, byte [r8 + ASR_CLASS]
    cmp  edx, edi
    jne  .next
    movzx edx, byte [r8 + ASR_PRIN]
    cmp  edx, esi
    jne  .next
    inc  eax
.next:
    add  r8, AUDIT_SEC_REC_SZ
    dec  ecx
    jmp  .scan
.out:
    ret

; audit_put_net_row(RDI = net record) — one structured row (see AUDIT net).
audit_put_net_row:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel str_audit_rec]       ; CRLF "A"
    call audit_put_str
    mov  rdi, [rbx + AR_SEQ]
    call audit_put_dec
    lea  rdi, [rel str_audit_k_src]
    call audit_put_str
    movzx edi, byte [rbx + AR_SRC]
    call audit_put_src
    lea  rdi, [rel str_audit_k_svc]
    call audit_put_str
    movzx edi, byte [rbx + AR_SVC]
    call audit_put_svc
    lea  rdi, [rel str_audit_k_pid]
    call audit_put_str
    mov  rdi, [rbx + AR_PID]
    test rdi, rdi
    jz   .nopid
    call audit_put_dec
    jmp  .verb
.nopid:
    lea  rdi, [rel str_audit_none]
    call audit_put_str
.verb:
    lea  rdi, [rel str_audit_k_verb]
    call audit_put_str
    lea  rdi, [rbx + AR_VERB]
    call audit_put_text
    lea  rdi, [rel str_audit_k_res]
    call audit_put_str
    movzx eax, byte [rbx + AR_RES]
    lea  rdi, [rel str_audit_admit]
    cmp  eax, AUDIT_NRES_ADMIT
    je   .res_put
    lea  rdi, [rel str_audit_blocked]
    cmp  eax, AUDIT_NRES_BLOCKED
    je   .res_reason
    lea  rdi, [rel str_audit_refused]
.res_reason:
    call audit_put_str
    lea  rdi, [rel str_audit_colon]
    call audit_put_str
    mov  rdi, [rbx + AR_REASON]
    test rdi, rdi
    jnz  .res_put
    lea  rdi, [rel str_audit_dash]
.res_put:
    call audit_put_str
    lea  rdi, [rel str_audit_k_t]
    call audit_put_str
    mov  rdi, [rbx + AR_T]
    call audit_put_dec
    cmp  dword [rbx + AR_COUNT], 1
    jbe  .out
    lea  rdi, [rel str_audit_x]
    call audit_put_str
    mov  edi, [rbx + AR_COUNT]
    call audit_put_dec
    lea  rdi, [rel str_audit_k_last]
    call audit_put_str
    mov  rdi, [rbx + AR_TLAST]
    call audit_put_dec
.out:
    pop  rbx
    ret

; audit_sec_put_name(RDI = NUL-separated name list, ESI = index, EDX = entry
;   count) — emit the index-th name; an index outside the list emits entry 0.
audit_sec_put_name:
    cmp  esi, edx
    jb   .skip
    xor  esi, esi
.skip:
    test esi, esi
    jz   audit_put_str
.next:
    inc  rdi
    cmp  byte [rdi - 1], 0
    jne  .next
    dec  esi
    jmp  .skip

; audit_sec_pub_total(EDI = verdict) -> RAX = that verdict's public count
;   summed over every class, saturating at 2^64-1. clobbers: RAX,RCX,RDX.
audit_sec_pub_total:
    lea  eax, [rdi - 1]
    imul eax, eax, AUDIT_SEC_PUB_SZ
    lea  rdx, [rel audit_sec_pub]
    add  rdx, rax
    xor  eax, eax
    mov  ecx, AUDIT_SEC_NCLASS
.add:
    add  rax, [rdx]
    jnc  .next
    mov  rax, -1
.next:
    add  rdx, AUDIT_SEC_NVERDICT * AUDIT_SEC_PUB_SZ
    dec  ecx
    jnz  .add
    ret

; audit_sec_pub_span -> RAX = earliest first t_us, RDX = latest last t_us over
;   every non-empty public cell (0, 0 when none). clobbers: RAX,RCX,RDX,RSI,R8.
audit_sec_pub_span:
    lea  rsi, [rel audit_sec_pub]
    mov  ecx, AUDIT_SEC_NCLASS * AUDIT_SEC_NVERDICT
    mov  rax, -1
    xor  edx, edx
    xor  r8d, r8d
.cell:
    cmp  qword [rsi], 0
    je   .next
    mov  r8d, 1
    cmp  [rsi + 8], rax
    jae  .first_ok
    mov  rax, [rsi + 8]
.first_ok:
    cmp  [rsi + 16], rdx
    jbe  .next
    mov  rdx, [rsi + 16]
.next:
    add  rsi, AUDIT_SEC_PUB_SZ
    dec  ecx
    jnz  .cell
    test r8d, r8d
    jnz  .out
    xor  eax, eax
.out:
    ret

; ---------------------------------------------------------------------------
; audit_selftest — KAT the write->readback path with CONTENT compare (append a
;   known line, read the newest receipt back from the ring, strcmp), emit the
;   gate marker, register the AUDIT verb. Called from boot/header after the
;   registry exists. clobbers: caller-saved (RBX saved).
; ---------------------------------------------------------------------------
audit_selftest:
    push rbx
    mov  qword [rel audit_net_flood_seq], -1
    lea  rdi, [rel str_audit_katline]
    call audit_log_line
    ; newest receipt = slot (head - 1) mod NREC
    call audit_newest_ptr
    mov  rbx, rax
    lea  rdi, [rbx + AR_TEXT]
    lea  rsi, [rel str_audit_katline]
    call strcmp                         ; 0 = byte-for-byte match
    test rax, rax
    jnz  .nokat
    lea  rdi, [rel str_m_audit_kat]
    call serial_string
.nokat:
    ; register the readback verb (COMMANDS.md §1 single vocabulary). ARGT_TEXT
    ; carries the optional "net"/"sec"/"guardian" selector; the count keeps the strict
    ; numeric fallback (audit_parse_view), so AUDIT / AUDIT <n> are unchanged.
    lea  rdi, [rel str_verb_audit]
    lea  rsi, [rel cmd_verb_audit]
    xor  edx, edx                       ; cap 0 (v1 allow-all)
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    pop  rbx
    ret

; ---- module data ----------------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_command_audit_0 0
align 8
audit_seq:       dq 0                   ; next receipt seq, stops at UINT64_MAX
audit_out_cur:   dq 0
audit_net_now:   dq 0                   ; boot ms of the attempt being logged
audit_net_cur:   dq 0                   ; record being written by audit_net_append
audit_net_flood_seq: dq -1              ; seq of the current run's flood row (-1 none)
times 24 db 0                  ; audit_net_shown..audit_sec_saved_pub moved to WDATA_svc_command_audit_0_bss1: keeps the labels below at their offset mod 64

str_verb_audit:    db "AUDIT", 0
audit_hex_digits:  db "0123456789abcdef"
str_audit_hdr:     db " audit seq=", 0
str_audit_n:       db " n=", 0
str_audit_rec:     db 13, 10, "A", 0
str_audit_sp:      db " ", 0
str_audit_x:       db " x", 0
str_audit_view_net: db " view=net", 0
str_audit_k_src:   db " src=", 0
str_audit_k_svc:   db " svc=", 0
str_audit_k_pid:   db " pid=", 0
str_audit_k_verb:  db " verb=", 0
str_audit_k_res:   db " res=", 0
str_audit_k_t:     db " t=", 0
str_audit_k_last:  db " last=", 0
str_audit_udp:     db "udp", 0
str_audit_ssh:     db "ssh", 0
str_audit_auth1:   db "auth1", 0
str_audit_any:     db "any", 0
str_audit_none:    db "none", 0
str_audit_admit:   db "admit", 0
str_audit_blocked: db "blocked", 0
str_audit_refused: db "refused", 0
str_audit_colon:   db ":", 0
str_audit_dash:    db "-", 0
str_audit_star:    db "*", 0
str_audit_r_flood: db "flood", 0
str_audit_flood_text: db "NET flood res=refused verb=* (distinct refusals folded)", 0
str_audit_k_secseq: db " audit sec_seq=", 0
str_audit_view_sec: db " view=sec", 0
str_audit_ai_scope: db "refused:ai_scope view=sec_only", 0
str_audit_k_drop:  db " sec_drop=", 0
audit_sec_pub_keys: db " pub_ok=", 0, " pub_refused=", 0, " pub_held=", 0, " pub_info=", 0
str_audit_k_pubfirst: db " pub_first=", 0
str_audit_k_publast: db " pub_last=", 0
str_audit_sec_rec: db 13, 10, "S", 0
str_audit_k_c:     db " c=", 0
str_audit_k_p:     db " p=", 0
str_audit_k_s:     db " s=", 0
str_audit_k_v:     db " v=", 0
str_audit_k_r:     db " r=", 0
str_audit_k_iommu_id: db " i=", 0
str_audit_k_amd_backend: db " b=", 0
audit_sec_class_names: db "-", 0, "verb", 0, "aihook", 0, "auth_refused", 0, "net_arp", 0, "usb_hid", 0, "iommu", 0, "guardian", 0, "history", 0, "reserved", 0, "hardware", 0
audit_sec_verdict_names: db "-", 0, "allowed", 0, "refused", 0, "held", 0, "info", 0
audit_sec_prin_names: db "none", 0, "owner", 0, "system", 0, "advisor", 0
str_audit_katline: db "AUDIT_KAT boot receipt content probe", 0
str_m_audit_kat:   db "[PAOS64] P2 audit: cmd receipt ring write->readback content OK [audit.ring.kat]", 13, 10, 0
str_audit_k_ai_refused: db " ai_refused=", 0
str_audit_k_session_refused: db " session_refused=", 0
str_audit_k_session_coalesced: db " session_coalesced=", 0
str_audit_k_airlock_refused: db " airlock_refused=", 0
str_audit_k_airlock_dropped: db " airlock_detail_dropped=", 0
str_audit_k_airlock_coalesced: db " airlock_coalesced=", 0
str_audit_k_software_cap_denied: db " software_cap_denied=", 0
str_audit_legacy_exhausted: db " legacy_exhausted=1 legacy_unstored=", 0
; BEGIN Guardian window strings
str_audit_gwindow_hdr: db " audit guardian_window_v=1 mode=shadow observed_min=", 0
str_audit_gwindow_quality: db " delta_q=", 0
str_audit_gwindow_exact: db " exact_delta=", 0
str_audit_gwindow_sources: db " source_lower_mask=", 0
str_audit_gwindow_overflow: db " aggregate_overflow=", 0
str_audit_gwindow_ms: db " sample_ms=", 0
; END Guardian window strings
; BEGIN Guardian sources strings
str_audit_gsources_hdr: db " audit guardian_sources_v=3 scope=observations n=11 total=", 0
str_audit_gsources_unseen: db " unseen=", 0
str_audit_gsources_total_q: db " total_q=", 0
str_audit_gsources_unseen_q: db " unseen_q=", 0
str_audit_gsources_row: db 13,10,"G", 0
str_audit_gsources_source: db " source=", 0
str_audit_gsources_total: db " total=", 0
str_audit_gsources_quality: db " quality=", 0
str_audit_gsources_exact: db "exact", 0
str_audit_gsources_lower: db "lower_bound", 0
str_audit_gsources_auth: db "auth_refused", 0
str_audit_gsources_iommu: db "iommu", 0
str_audit_gsources_hid: db "hid", 0
str_audit_gsources_arp: db "arp", 0
str_audit_gsources_ai: db "aihook", 0
str_audit_gsources_cap: db "capability", 0
str_audit_gsources_airlock: db "airlock", 0
str_audit_gsources_session: db "session", 0
str_audit_gsources_keyprov: db "keyprov", 0
align 8
str_audit_gsources_aer: db "aer_uncorrected",0
str_audit_gsources_mca: db "mca_noncorrected",0
str_audit_gsources_mca_handling: db " handling=unknown",0
align 8
audit_guardian_sources_names:
    ; PaOS's flat PE payload has no fixups for static absolute pointers.
    ; Resolve each relative entry against this table's live RIP-relative base.
    dq str_audit_gsources_auth - audit_guardian_sources_names
    dq str_audit_gsources_iommu - audit_guardian_sources_names
    dq str_audit_gsources_hid - audit_guardian_sources_names
    dq str_audit_gsources_arp - audit_guardian_sources_names
    dq str_audit_gsources_ai - audit_guardian_sources_names
    dq str_audit_gsources_cap - audit_guardian_sources_names
    dq str_audit_gsources_airlock - audit_guardian_sources_names
    dq str_audit_gsources_session - audit_guardian_sources_names
    dq str_audit_gsources_keyprov - audit_guardian_sources_names
    dq str_audit_gsources_aer - audit_guardian_sources_names
    dq str_audit_gsources_mca - audit_guardian_sources_names
; END Guardian sources strings
; BEGIN Guardian status strings
str_audit_guardian_hdr: db " audit guardian_v=1 mode=shadow clock=", 0
str_audit_guardian_available: db "available", 0
str_audit_guardian_unavailable: db "unavailable", 0
str_audit_guardian_overflow: db "deadline_overflow", 0
str_audit_guardian_decisions: db " decisions=", 0
str_audit_guardian_burst: db " burst=", 0
str_audit_guardian_clock_ms: db " clock_ms=", 0
str_audit_guardian_next_ms: db " next_ms=", 0
str_audit_guardian_origin_ms: db " cooldown_origin_ms=", 0
; END Guardian status strings
%endmacro
WDATA_DEFER WDATA_svc_command_audit_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_svc_command_audit_0_bss1 0
resb 40                 ; keeps audit_net_shown at its WDATA offset mod 64
audit_net_shown: resq 1
audit_req_arg:   resq 1                 ; AUDIT request token (RSP_VAL echo)
audit_head:      resd 1                 ; next-write slot
audit_net_run:   resd 1                 ; non-admit rows appended since the last anchor
audit_out_ready: resb 1                 ; 1 = audit_out_buf holds a staged reply
audit_cpu_policy_page: resd 1
audit_out_full:  resb 1                 ; a staged append was incomplete
alignb 8
audit_ring:      resb (AUDIT_NREC * AUDIT_REC_SZ)
audit_out_buf:   resb AUDIT_OUT_MAX        ; staged AUDIT dump text
audit_net_text_tmp: resb AUDIT_TXT
audit_net_verb_tmp: resb AUDIT_VERB_MAX
alignb 8
audit_sec_seq:     resq 1               ; typed records ever written (= next seq)
audit_sec_drop:    resq 1               ; typed records overwritten (saturating)
audit_sec_last_t:  resq 1               ; newest t_us handed out (non-decreasing)
audit_req_src:     resq 1               ; AUDIT request REQ_SOURCE (sec view staging)
audit_sec_ring:    resb (AUDIT_SEC_NREC * AUDIT_SEC_REC_SZ)
audit_sec_pub:     resb (AUDIT_SEC_NCLASS * AUDIT_SEC_NVERDICT * AUDIT_SEC_PUB_SZ)
alignb 8
audit_guardian_next_ms:          resq 1 ; SEC-GA1 watch tier: next look (boot ms)
audit_guardian_last_refused:     resq 1 ; public AUTH_REFUSED at the last look
audit_guardian_last_emit_ms:     resq 1 ; cooldown origin: last record or clock rebase
audit_guardian_shadow_decisions: resq 1 ; typed shadow decisions recorded
audit_guardian_in_burst:         resb 1
alignb 8
audit_sec_test_active: resb 1
alignb 8
audit_arp_last_id: resq 1
audit_arp_drops: resq 1
audit_arp_coalesced: resq 1
audit_hid_last_id: resq 1
audit_hid_drops: resq 1
audit_hid_coalesced: resq 1
audit_iommu_last_id: resq 1             ; never restored/reused by KAT
audit_iommu_drops: resq 1               ; source queue/reset/validation detail drops, saturating
audit_iommu_coalesced: resq 1           ; valid identities folded at typed quota/seq ceiling
audit_sec_saved_seq:  resq 1            ; audit_sec_save snapshot (boot KAT bracket)
audit_sec_saved_drop: resq 1
audit_sec_saved_ring: resb (AUDIT_SEC_NREC * AUDIT_SEC_REC_SZ)
audit_sec_saved_pub:  resb (AUDIT_SEC_NCLASS * AUDIT_SEC_NVERDICT * AUDIT_SEC_PUB_SZ)
alignb 8
audit_aihook_refused: resq 1            ; all AIHOOK/REFUSED, typed + public, saturating
audit_aihook_saved_refused: resq 1      ; boot KAT snapshot, never an acknowledgement
audit_guardian_last_aihook_refused: resq 1 ; all-principal AI refusals at last watch look
audit_guardian_last_cap_refused: resq 1 ; native software-mask refusals at last watch look
audit_session_refused: resq 1           ; native outcomes, typed + quota/ceiling folds
audit_session_coalesced: resq 1         ; detail not retained, independent saturating summary
audit_keyprov_refused: resq 1          ; native receipt total, independent of ring/public
audit_keyprov_coalesced: resq 1        ; typed detail omitted at quota/ceiling
audit_keyprov_saved_refused: resq 1
audit_keyprov_saved_coalesced: resq 1
audit_airlock_coalesced: resq 1        ; typed detail omitted at quota/ceiling
audit_legacy_unstored: resq 1           ; new-row attempts at exhausted legacy seq, saturating
audit_guardian_clock_ms: resq 1         ; last observed valid boot ms, even before deadline
audit_guardian_clock_state: resb 1      ; 0=new, 1=valid, 2=unavailable, 3=deadline overflow
alignb 8
audit_guardian_last_keyprov_refused: resq 1 ; independent native input-refusal baseline
audit_guardian_last_session_refused: resq 1 ; independent native unlock-refusal baseline
audit_guardian_last_airlock_refused: resq 1 ; independent native AIRLOCK refusal baseline
audit_guardian_last_hid_refused: resq 1 ; independent native HID refusal baseline
audit_guardian_last_arp_observed: resq 1 ; independent normalized ARP INFO baseline
audit_mca_observed: resq 1              ; sum of consumed real per-CPU sampled transitions
audit_mca_coalesced: resq 1             ; observations without a separate typed CPU summary
audit_mca_cpu_seen: resq 32             ; BSP baselines; never KAT-restored/reused
audit_guardian_last_mca_observed: resq 1
audit_aer_observed: resq 1              ; changed native uncorrected snapshots, not hardware totals
audit_aer_coalesced: resq 1             ; detail omitted at typed quota/sequence ceiling
audit_aer_last_us: resq 1               ; consumed native poll identity, not KAT restored
audit_guardian_last_aer_observed: resq 1
audit_guardian_last_iommu_observed: resq 1 ; independent normalized IOMMU INFO baseline
; BEGIN Guardian window quality state
alignb 8
audit_guardian_window_min: resq 1       ; known reset-clamped minimum, saturating sum
audit_guardian_window_sources: resq 1   ; saturated source bits in native row order
audit_guardian_window_ms: resq 1        ; valid completed look timestamp
audit_guardian_window_quality: resb 1   ; 0 unavailable,1 exact,2 lower_bound
audit_guardian_window_overflow: resb 1  ; independent aggregate addition carry
; END Guardian window quality state
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_audit_0_bss1
