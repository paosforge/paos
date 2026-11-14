;; MODULE svc/guardian_alert
;; LAYER 5
;; EXPORTS guardian_alert_sources_snapshot, guardian_alert_count_quality, guardian_alert_keyprov_status, guardian_alert_session_status, guardian_alert_counts, guardian_alert_owner_last, guardian_alert_acknowledge_local, guardian_alert_iommu_status, guardian_alert_hid_status, guardian_alert_arp_status, guardian_alert_cap_status, guardian_alert_airlock_status
;; IMPORTS svc/command_audit, sec/principal, core/capability, sec/airlock, sec/session
;; CAPS
;; OWNER saga:sec
; ============================================================================
; svc/guardian_alert.asm — SEC-GA0-lite data seam (RC spec 10.5; admin 10/08
; 01:57, option C condition 3). The security logic of the owner's local alert,
; kept apart from any painter so the GUI lane can move the pixels into its L2
; painter later without touching it. Read-only over the GD1 spine except for
; the one "owner has looked" mark.
;
;   guardian_alert_counts      -> RAX = security observations not yet seen,
;                                 RDX = all security observations. Sources
;                                 include the spine's public cell (class
;                                 AUTH_REFUSED, verdict REFUSED): every refused
;                                 UDP/SSH decision (SEC-GD1b) and every AI-hook
;                                 pre-bind failure, plus all AIHOOK/REFUSED
;                                 outcomes (typed or public) and native IOMMU faults.
;                                 Native boot-HID consumer refusals also count.
;                                 Native software capability gate denials have
;                                 their own source and seen mark (includes probes).
;                                 Observations assert no attack or enforcement.
;                                 A total below the mark (a
;                                 KAT bracket restore) shows 0 new.
;   guardian_alert_owner_last  -> EAX = 1 and RDX = seq, ECX = verb id of the
;                                 newest typed owner remote action still held
;                                 (class VERB, principal OWNER); EAX = 0 if none.
;   guardian_alert_acknowledge_local -> armed PID/token must still match the
;                                 current native local owner session. The
;                                 physical caller also checks origin, queued
;                                 report context, steering and dimensions.
; Inspection is not here: the owner reads `AUDIT sec` in the local console.
; No lock: the spine and this mark are written only from the BSP command/idle
; context (the spine's single-writer rule).
; ============================================================================

; BEGIN Guardian source snapshot
GUARDIAN_SOURCES_SIZE equ 264            ; 3 header qwords + 10 * 3 row qwords
GUARDIAN_SOURCES_STACK equ (GUARDIAN_SOURCES_SIZE + 15) & ~15 ; aligned caller scratch
; guardian_alert_sources_snapshot(RDI=writable caller buffer, RSI=capacity)
; -> EAX1 copied,0 null/short (no writes). Trusted BSP caller, not user memory.
; Header: total, unseen, quality (bit0 unseen lower bound,bit1 total lower).
; Ten rows: total, reset-clamped unseen, quality (0 exact,3 source saturated).
; BSP reads each total/seen once before formatting; no callback/yield/drain.
; Concurrent atomic producers may advance between rows: no global-instant claim.
; Rows and aggregate use these same captured values. Writes only caller264 bytes;
; all producer/seen/authority/history state remains untouched. Clobbers
; RAX,RDX,R8-R11. Snapshot rows have fixed order, documented by the AUDIT view.
%macro GA_SOURCE_SNAPSHOT_ROW 3
    mov  rax, [rel %1]
    mov  r8, rax
    sub  r8, [rel %2]
    jae  %%delta
    xor  r8d, r8d
%%delta:
    xor  r9d, r9d
    cmp  rax, -1
    jne  %%quality
    mov  r9d, 3
%%quality:
    mov  [rdi + %3], rax
    mov  [rdi + %3 + 8], r8
    mov  [rdi + %3 + 16], r9
    or   edx, r9d
    add  r10, rax
    jnc  %%total
    mov  r10, -1
    or   edx, 2
%%total:
    add  r11, r8
    jnc  %%done
    mov  r11, -1
    or   edx, 1
%%done:
%endmacro
guardian_alert_sources_snapshot:
    xor  eax, eax
    test rdi, rdi
    jz   .out
    cmp  rsi, GUARDIAN_SOURCES_SIZE
    jb   .out
    xor  edx, edx
    xor  r10d, r10d
    xor  r11d, r11d
    GA_SOURCE_SNAPSHOT_ROW audit_sec_pub + (((AUDIT_SEC_C_AUTH_REFUSED - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_REFUSED - 1) * AUDIT_SEC_PUB_SZ), guardian_alert_seen, 24
    GA_SOURCE_SNAPSHOT_ROW audit_sec_pub + (((AUDIT_SEC_C_IOMMU - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ), guardian_alert_iommu_seen, 48
    GA_SOURCE_SNAPSHOT_ROW audit_sec_pub + (((AUDIT_SEC_C_USB_HID - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ), guardian_alert_hid_seen, 72
    GA_SOURCE_SNAPSHOT_ROW audit_sec_pub + (((AUDIT_SEC_C_NET_ARP - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ), guardian_alert_arp_seen, 96
    GA_SOURCE_SNAPSHOT_ROW audit_aihook_refused, guardian_alert_aihook_seen, 120
    GA_SOURCE_SNAPSHOT_ROW cap_denied_count, guardian_alert_cap_seen, 144
    GA_SOURCE_SNAPSHOT_ROW airlock_refused_count, guardian_alert_airlock_seen, 168
    GA_SOURCE_SNAPSHOT_ROW audit_session_refused, guardian_alert_session_seen, 192
    GA_SOURCE_SNAPSHOT_ROW audit_keyprov_refused, guardian_alert_keyprov_seen, 216
    GA_SOURCE_SNAPSHOT_ROW audit_aer_observed, guardian_alert_aer_seen, 240
    mov  [rdi], r10
    mov  [rdi + 8], r11
    mov  [rdi + 16], rdx
    mov  eax, 1
.out:
    ret
%unmacro GA_SOURCE_SNAPSHOT_ROW 3
; END Guardian source snapshot

; BEGIN GUARDIAN COUNT QUALITY
; guardian_alert_count_quality -> EAX bit0 unseen lower bound, bit1 total
; lower bound. Zero means both numeric results are exact. A source at MAX
; cannot distinguish further observations, even after acknowledgement.
; Actual addition carry also loses count precision; an exact aggregate MAX
; made from finite sources does not. Restore/rollback uses the same clamped
; independent deltas as counts. Read-only BSP snapshot; no sticky state,
; producer call, clock, drain, permission, attack or enforcement conclusion.
; Clobbers RAX,R8-R10 only. Fixed ten normalized sources, each exactly once.
%macro GA_COUNT_QUALITY_SOURCE 2
    mov  r8, [rel %1]
    cmp  r8, -1
    jne  %%sum
    or   eax, 3
%%sum:
    add  r9, r8
    jnc  %%total
    or   eax, 2
    mov  r9, -1
%%total:
    sub  r8, [rel %2]
    jae  %%delta
    xor  r8d, r8d
%%delta:
    add  r10, r8
    jnc  %%done
    or   eax, 1
    mov  r10, -1
%%done:
%endmacro
guardian_alert_count_quality:
    xor  eax, eax
    xor  r9d, r9d
    xor  r10d, r10d
    GA_COUNT_QUALITY_SOURCE audit_sec_pub + (((AUDIT_SEC_C_AUTH_REFUSED - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_REFUSED - 1) * AUDIT_SEC_PUB_SZ), guardian_alert_seen
    GA_COUNT_QUALITY_SOURCE audit_sec_pub + (((AUDIT_SEC_C_IOMMU - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ), guardian_alert_iommu_seen
    GA_COUNT_QUALITY_SOURCE audit_sec_pub + (((AUDIT_SEC_C_USB_HID - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ), guardian_alert_hid_seen
    GA_COUNT_QUALITY_SOURCE audit_sec_pub + (((AUDIT_SEC_C_NET_ARP - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ), guardian_alert_arp_seen
    GA_COUNT_QUALITY_SOURCE audit_aihook_refused, guardian_alert_aihook_seen
    GA_COUNT_QUALITY_SOURCE cap_denied_count, guardian_alert_cap_seen
    GA_COUNT_QUALITY_SOURCE airlock_refused_count, guardian_alert_airlock_seen
    GA_COUNT_QUALITY_SOURCE audit_session_refused, guardian_alert_session_seen
    GA_COUNT_QUALITY_SOURCE audit_keyprov_refused, guardian_alert_keyprov_seen
    GA_COUNT_QUALITY_SOURCE audit_aer_observed, guardian_alert_aer_seen
    ret
%unmacro GA_COUNT_QUALITY_SOURCE 2
; END GUARDIAN COUNT QUALITY

; Native session refusals are independent of transport authentication refusal.
; Separate deltas keep saturation or restored counters from erasing evidence.
guardian_alert_counts:
    sub rsp,8
    call guardian_alert_pre_aer_counts
    add rsp,8
    mov rcx,[rel audit_aer_observed]
    add rdx,rcx
    jnc .total
    mov rdx,-1
.total:
    sub rcx,[rel guardian_alert_aer_seen]
    jae .delta
    xor ecx,ecx
.delta:
    add rax,rcx
    jnc .out
    mov rax,-1
.out:
    ret

guardian_alert_pre_aer_counts:
    sub  rsp, 8
    call guardian_alert_pre_keyprov_counts
    add  rsp, 8
    mov  rcx, [rel audit_keyprov_refused]
    add  rdx, rcx
    jnc  .total
    mov  rdx, -1
.total:
    sub  rcx, [rel guardian_alert_keyprov_seen]
    jae  .delta
    xor  ecx, ecx
.delta:
    add  rax, rcx
    jnc  .out
    mov  rax, -1
.out:
    ret

guardian_alert_pre_keyprov_counts:
    sub  rsp, 8
    call guardian_alert_pre_session_counts
    add  rsp, 8
    mov  rcx, [rel audit_session_refused]
    add  rdx, rcx
    jnc  .total
    mov  rdx, -1
.total:
    sub  rcx, [rel guardian_alert_session_seen]
    jae  .delta
    xor  ecx, ecx
.delta:
    add  rax, rcx
    jnc  .out
    mov  rax, -1
.out:
    ret

; RDI=armed PID, RSI=armed token -> EAX=1 acknowledged, 0 refused.
; The physical caller checks origin/steer/geometry. Recheck native session at
; the final seen-mark effect, with no intervening yield, painter or callback.
; This changes no authority, source counters, retained records or permissions.
guardian_alert_acknowledge_local:
    sub  rsp, 8
    call session_shell_local_authority
    add  rsp, 8
    cmp  rax, PRIN_OWNER
    jne  .refused
    cmp  rax, rdi
    jne  .refused
    cmp  rdx, rsi
    jne  .refused
    cmp  byte [rel audit_sec_test_active], 0
    jne  .refused
    sub  rsp, 8
    call guardian_alert_acknowledge
    add  rsp, 8
    mov  eax, 1
    ret
.refused:
    xor  eax, eax
    ret

; Private seen-mark worker: only the checked local entry calls this in product.
; The audit KAT guard also protects direct independent seen-mark fixtures.
guardian_alert_acknowledge:
    cmp byte [rel audit_sec_test_active],0
    jne .out
    sub rsp,8
    call guardian_alert_pre_aer_acknowledge
    add rsp,8
    mov rax,[rel audit_aer_observed]
    mov [rel guardian_alert_aer_seen],rax
.out:
    ret

align 8
guardian_alert_aer_seen: dq 0

guardian_alert_pre_aer_acknowledge:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    sub  rsp, 8
    call guardian_alert_pre_keyprov_acknowledge
    add  rsp, 8
    mov  rax, [rel audit_keyprov_refused]
    mov  [rel guardian_alert_keyprov_seen], rax
.out:
    ret

guardian_alert_pre_keyprov_acknowledge:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    sub  rsp, 8
    call guardian_alert_pre_session_acknowledge
    add  rsp, 8
    mov  rax, [rel audit_session_refused]
    mov  [rel guardian_alert_session_seen], rax
.out:
    ret

; Read-only native source detail: RAX total, RDX new, RCX quota/ceiling folds.
guardian_alert_session_status:
    mov  rax, [rel audit_session_refused]
    mov  rdx, rax
    sub  rdx, [rel guardian_alert_session_seen]
    jae  .summary
    xor  edx, edx
.summary:
    mov  rcx, [rel audit_session_coalesced]
    ret
align 8
guardian_alert_session_seen: dq 0

; guardian_alert_counts -> RAX unseen security observations, RDX total.
; Includes native boot-HID consumer refusals. Clobbers RAX,RCX,RDX.
; Remote AUTH_REFUSED plus native IOMMU fault observations (not enforcement).
; Independent marks/deltas prevent a saturated source hiding another.
; A restored/backwards counter contributes0 new. Read-only, BSP context.
guardian_alert_pre_session_counts:
    sub  rsp, 8
    call guardian_alert_pre_airlock_counts
    add  rsp, 8
    mov  rcx, [rel airlock_refused_count]
    add  rdx, rcx
    jnc  .total
    mov  rdx, -1
.total:
    sub  rcx, [rel guardian_alert_airlock_seen]
    jae  .delta
    xor  ecx, ecx
.delta:
    add  rax, rcx
    jnc  .out
    mov  rax, -1
.out:
    ret

; All existing sources retain their independent arithmetic and seen marks.
guardian_alert_pre_airlock_counts:
    sub  rsp, 8
    call guardian_alert_pre_cap_counts
    add  rsp, 8
    mov  rcx, [rel cap_denied_count]
    add  rdx, rcx
    jnc  .total
    mov  rdx, -1
.total:
    sub  rcx, [rel guardian_alert_cap_seen]
    jae  .delta
    xor  ecx, ecx
.delta:
    add  rax, rcx
    jnc  .out
    mov  rax, -1
.out:
    ret

; Preserve the existing AUTH/AI/HID/ARP/IOMMU arithmetic independently.
; Software capability observations are not hardware enforcement or attacks.
guardian_alert_pre_cap_counts:
    sub  rsp, 8
    call guardian_alert_pre_aihook_counts
    add  rsp, 8
    mov  rcx, [rel audit_aihook_refused]
    add  rdx, rcx
    jnc  .total
    mov  rdx, -1
.total:
    sub  rcx, [rel guardian_alert_aihook_seen]
    jae  .delta
    xor  ecx, ecx
.delta:
    add  rax, rcx
    jnc  .out
    mov  rax, -1
.out:
    ret

; Original remote/IOMMU/HID/ARP arithmetic retained exactly. The AI source
; counts each normalized AIHOOK/REFUSED event once, including typed records;
; its public cell is a subset and MUST NOT be added again.
guardian_alert_pre_aihook_counts:
    sub  rsp, 8
    call guardian_alert_pre_arp_counts
    add  rsp, 8
    mov  rcx, [rel audit_sec_pub + (((AUDIT_SEC_C_NET_ARP - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    add  rdx, rcx
    jnc  .total
    mov  rdx, -1
.total:
    sub  rcx, [rel guardian_alert_arp_seen]
    jae  .delta
    xor  ecx, ecx
.delta:
    add  rax, rcx
    jnc  .out
    mov  rax, -1
.out:
    ret

; Original remote/IOMMU/HID count arithmetic retained exactly.
guardian_alert_pre_arp_counts:
    sub  rsp, 8
    call guardian_alert_base_counts
    add  rsp, 8
    mov  rcx, [rel audit_sec_pub + (((AUDIT_SEC_C_USB_HID - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    add  rdx, rcx
    jnc  .total
    mov  rdx, -1
.total:
    sub  rcx, [rel guardian_alert_hid_seen]
    jae  .delta
    xor  ecx, ecx
.delta:
    add  rax, rcx
    jnc  .out
    mov  rax, -1
.out:
    ret

; Existing remote/IOMMU arithmetic retained exactly.
guardian_alert_base_counts:
    mov  rdx, [rel audit_sec_pub + (((AUDIT_SEC_C_AUTH_REFUSED - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_REFUSED - 1) * AUDIT_SEC_PUB_SZ)]
    mov  rax, rdx
    sub  rax, [rel guardian_alert_seen]
    jae  .remote
    xor  eax, eax
.remote:
    mov  rcx, [rel audit_sec_pub + (((AUDIT_SEC_C_IOMMU - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    add  rdx, rcx
    jnc  .total
    mov  rdx, -1
.total:
    sub  rcx, [rel guardian_alert_iommu_seen]
    jae  .native
    xor  ecx, ecx
.native:
    add  rax, rcx
    jnc  .out
    mov  rax, -1
.out:
    ret

; Local numeric detail: RAX native observations, RDX source queue detail drops,
; RCX valid identities folded into summary at the typed quota/sequence ceiling.
; No addresses/tags, no claim of DMA enforcement; read-only even after ack.
guardian_alert_iommu_status:
    mov  rax, [rel audit_sec_pub + (((AUDIT_SEC_C_IOMMU - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    mov  rdx, [rel audit_iommu_drops]
    mov  rcx, [rel audit_iommu_coalesced]
    ret

; guardian_alert_owner_last -> EAX found, RDX seq, ECX verb id.
;   clobbers: RAX, RCX, RDX, RSI, R8.
guardian_alert_owner_last:
    mov  r8, [rel audit_sec_seq]
    mov  ecx, AUDIT_SEC_NREC
    cmp  r8, rcx
    jae  .scan
    mov  ecx, r8d
.scan:
    test ecx, ecx
    jz   .none
    dec  r8
    mov  eax, r8d
    and  eax, AUDIT_SEC_NREC - 1
    imul eax, eax, AUDIT_SEC_REC_SZ
    lea  rsi, [rel audit_sec_ring]
    add  rsi, rax
    cmp  byte [rsi + ASR_CLASS], AUDIT_SEC_C_VERB
    jne  .next
    cmp  byte [rsi + ASR_PRIN], PRIN_OWNER
    jne  .next
    mov  rdx, [rsi + ASR_SEQ]
    mov  ecx, [rsi + ASR_SUBJECT]
    mov  eax, 1
    ret
.next:
    dec  ecx
    jmp  .scan
.none:
    xor  eax, eax
    ret

; guardian_alert_acknowledge — owner seen marks only, never queue/counters/records.
guardian_alert_pre_session_acknowledge:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    sub  rsp, 8
    call guardian_alert_pre_airlock_acknowledge
    add  rsp, 8
    mov  rax, [rel airlock_refused_count]
    mov  [rel guardian_alert_airlock_seen], rax
.out:
    ret

; Physical owner marks only. KAT acknowledgements never consume live sources.
guardian_alert_pre_airlock_acknowledge:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    sub  rsp, 8
    call guardian_alert_pre_cap_acknowledge
    add  rsp, 8
    mov  rax, [rel cap_denied_count]
    mov  [rel guardian_alert_cap_seen], rax
.out:
    ret

; Original seen updates retained. Physical owner inspection changes marks only.
guardian_alert_pre_cap_acknowledge:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    sub  rsp, 8
    call guardian_alert_pre_aihook_acknowledge
    add  rsp, 8
    mov  rax, [rel audit_aihook_refused]
    mov  [rel guardian_alert_aihook_seen], rax
.out:
    ret

; Original remote/IOMMU/HID/ARP seen updates retained exactly.
guardian_alert_pre_aihook_acknowledge:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    sub  rsp, 8
    call guardian_alert_pre_arp_acknowledge
    add  rsp, 8
    mov  rax, [rel audit_sec_pub + (((AUDIT_SEC_C_NET_ARP - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    mov  [rel guardian_alert_arp_seen], rax
.out:
    ret

; Original remote/IOMMU/HID seen updates retained exactly.
guardian_alert_pre_arp_acknowledge:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    sub  rsp, 8
    call guardian_alert_base_acknowledge
    add  rsp, 8
    mov  rax, [rel audit_sec_pub + (((AUDIT_SEC_C_USB_HID - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    mov  [rel guardian_alert_hid_seen], rax
.out:
    ret

; Existing remote/IOMMU seen updates retained exactly.
guardian_alert_base_acknowledge:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    mov  rax, [rel audit_sec_pub + (((AUDIT_SEC_C_AUTH_REFUSED - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_REFUSED - 1) * AUDIT_SEC_PUB_SZ)]
    mov  [rel guardian_alert_seen], rax
    mov  rax, [rel audit_sec_pub + (((AUDIT_SEC_C_IOMMU - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    mov  [rel guardian_alert_iommu_seen], rax
.out:
    ret

align 8
guardian_alert_seen: dq 0              ; AUTH_REFUSED/REFUSED seen mark
guardian_alert_iommu_seen: dq 0        ; native IOMMU/INFO seen mark

; HID consumer refusals are driver observations, never physical attack proof.
guardian_alert_hid_status:
    mov  rax, [rel audit_sec_pub + (((AUDIT_SEC_C_USB_HID - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    mov  rdx, [rel audit_hid_drops]
    mov  rcx, [rel audit_hid_coalesced]
    ret
align 8
guardian_alert_hid_seen: dq 0

; Native ARP refusals are parser/cache observations, never sender identity or
; attack/enforcement proof. Quota folds and queue/lifetime losses are distinct.
guardian_alert_arp_status:
    mov  rax, [rel audit_sec_pub + (((AUDIT_SEC_C_NET_ARP - 1) * AUDIT_SEC_NVERDICT + AUDIT_SEC_V_INFO - 1) * AUDIT_SEC_PUB_SZ)]
    mov  rdx, [rel audit_arp_drops]
    mov  rcx, [rel audit_arp_coalesced]
    ret
align 8
guardian_alert_arp_seen: dq 0

; Independent all-principal AIHOOK/REFUSED owner seen mark.
align 8
guardian_alert_aihook_seen: dq 0

; Read-only software-mask diagnostic. RAX = native denied gates (including
; deliberate probes), RDX = unseen since local acknowledgement, clamped at0.
; No AUTH/AI conflation, mask/permission change or hardware isolation claim.
guardian_alert_cap_status:
    mov  rax, [rel cap_denied_count]
    mov  rdx, rax
    sub  rdx, [rel guardian_alert_cap_seen]
    jae  .out
    xor  edx, edx
.out:
    ret
align 8
guardian_alert_cap_seen: dq 0

; Numeric local inspection: RAX native receipts, RDX unseen (clamped), RCX
; typed-detail coalesced. Read-only, no authority/enforcement/model verdict.
guardian_alert_keyprov_status:
    mov  rax, [rel audit_keyprov_refused]
    mov  rdx, rax
    sub  rdx, [rel guardian_alert_keyprov_seen]
    jae  .delta
    xor  edx, edx
.delta:
    mov  rcx, [rel audit_keyprov_coalesced]
    ret
align 8
guardian_alert_keyprov_seen: dq 0

; RAX = native AIRLOCK admission refusals (includes deliberate boot probes),
; RDX = unseen clamped at0. Source saturates at UINT64_MAX; no detail queue,
; identity, attack attribution or isolation claim. Read-only, independent mark.
guardian_alert_airlock_status:
    mov  rax, [rel airlock_refused_count]
    mov  rdx, rax
    sub  rdx, [rel guardian_alert_airlock_seen]
    jae  .out
    xor  edx, edx
.out:
    ret
align 8
guardian_alert_airlock_seen: dq 0
