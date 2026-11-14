;; MODULE net/arp_cache
;; LAYER 4
;; EXPORTS arp_cache_selftest, arp_cache_lookup_kat, arp_cache_insert_kat, arp_fault_battery, arp_pending_note, arp_cache_learn_solicited, arp_cache_age_tick, arp_observation_note, arp_observation_reset, arp_observation_snapshot, arp_observation_pop, arp_observation_discard
;; IMPORTS boot/serial, boot/header, core/lib/mem, net/netdev
;; CAPS
;; OWNER saga:net
; ============================================================================
; net/arp_cache.asm — the ARP resolution CACHE table LOGIC (contract 1045 /
; C10d, the qemu rung of the bare-metal 1022/1024/1025). Rides ON TOP of the
; arp layer proven in 1042 (net/stack.asm): a multi-entry IPv4 -> MAC table with
; insert-on-reply, lookup-hit, and age/evict, proven at boot over CANNED in-memory
; ARP replies — no NIC, no live wire (the live-wire resolution/cache-hit is
; 1022/1024/1025 bare_metal). The selftest is CONTENT-graded: it drives the table
; through insert -> hit -> a distinct 2nd insert -> age/evict and PRINTS the cached
; MAC bytes it read back OUT OF THE TABLE (KAT), so a stub that emits the marker
; without a real table FAILS:
;   * arp.cache.logic  — feed canned ARP reply #1 (sender-HW aa:bb:cc:dd:ee:01,
;                        sender-IP 192.168.0.10) -> INSERT; re-lookup the SAME IP
;                        serves the MAC FROM THE TABLE (hit, no new request); feed
;                        a DISTINCT reply #2 (…ee:02, .20) -> a 2nd entry the table
;                        holds ALONGSIDE #1 (proves >1 slot, not an overwrite);
;                        age entry #1 past its TTL -> it EVICTS (re-lookup misses)
;                        while entry #2 (younger) survives.
;   * NEGATIVE GATE    — a short/truncated ARP frame (len < 28) is bounds-checked
;                        and REJECTED by arp_cache_ingest_reply (no OOB, no crash,
;                        boot continues); a lookup for an un-cached IP returns MISS
;                        (0), never a stale/wrong MAC.
;
; The printed KAT is read back from the TABLE after a real lookup, and reply_sha is
; read from the canned frame — the probe re-checks entry1_mac == reply_sha byte-for
; -byte AND entry2_mac != entry1_mac. All copies go through core/lib/mem (G1).
; ============================================================================

; --- ARP frame field offsets (RFC 826; Ethernet/IPv4, 28-byte body) ------------
ARP_OPER      equ 6        ; opcode (2 bytes, network order): request=1 reply=2
ARP_SHA       equ 8        ; sender hardware address (6 bytes = the MAC we cache)
ARP_SPA       equ 14       ; sender protocol address (4 bytes = the IPv4 we key on)
ARP_BODY_LEN  equ 28       ; minimum well-formed ARP body

; --- cache entry layout (16 bytes/entry) ---------------------------------------
E_VALID       equ 0        ; 1 = occupied, 0 = free/evicted
E_AGE         equ 1        ; age in ticks; entry evicts when age >= ARP_TTL
E_RANK        equ 2        ; LRU recency among valid entries: 0 = most recent,
                           ;   valid ranks are always exactly 0..(valid count - 1)
E_IP          equ 4        ; IPv4 key (4 bytes, in-frame byte order)
E_MAC         equ 8        ; MAC value (6 bytes)
E_SIZE        equ 16
ARP_N         equ 8        ; table capacity (entries)
ARP_TTL       equ 8        ; evict threshold (ticks)
ARP_STATE_SIZE equ ARP_N * (E_SIZE + 8) ; table plus per-slot learn times

; arp_kat_isolated(RAX = KAT body) -> the body's RAX. RCQ-10 S3 (G3): the ARP
;   KATs re-initialise and fill the live arp_table with canned 192.168.0.x
;   entries. SELFTEST FULL re-runs them on a live boot (from the command poll,
;   the only task that touches the table). Save the table first and put it back
;   after, as arp_fault_battery already does for its own vectors.
;   Clobbers: caller-saved; the body preserves rbx, r12-r15.
arp_kat_isolated:
    sub  rsp, 8
    mov  ecx, [rel arp_obs_test_depth]
    mov  [rsp], rcx
    mov  dword [rel arp_obs_test_depth], 1
    call arp_kat_isolated_body
    mov  ecx, [rsp]
    mov  [rel arp_obs_test_depth], ecx
    add  rsp, 8
    ret

arp_kat_isolated_body:
    push rbx
    sub  rsp, ARP_STATE_SIZE                 ; table and times stay one snapshot
    mov  rbx, rax
    mov  rdi, rsp
    lea  rsi, [rel arp_table]
    mov  rdx, ARP_STATE_SIZE
    call memcpy
    call rbx
    mov  rbx, rax
    lea  rdi, [rel arp_table]
    mov  rsi, rsp
    mov  rdx, ARP_STATE_SIZE
    call memcpy
    mov  rax, rbx
    add  rsp, ARP_STATE_SIZE
    pop  rbx
    ret

; arp_cache_selftest — THE 1045 acceptance gate. Drives the table through the full
;   insert/hit/multi-entry/age-evict/negative sequence and only prints the KAT +
;   marker when EVERY check passes (all data read back out of the live table).
;   clobbers: caller-saved; preserves rbx,r12-r15 (saved here).
arp_cache_selftest:
    lea  rax, [rel .isolated]                ; RCQ-10 S3: never over a live lease
    jmp  arp_kat_isolated
.isolated:
    push rbx
    push r12
    push r13
    push r14
    push r15

    call arp_cache_init

    ; ---------- (1) IP1 must MISS before any insert ----------
    mov  edi, [rel arp_ip1]
    call arp_cache_lookup
    test rax, rax
    jnz  .done                              ; a fresh table must miss

    ; feed canned reply #1 -> insert IP1 -> MAC1
    lea  rdi, [rel arp_reply1]
    mov  rsi, ARP_BODY_LEN
    call arp_cache_ingest_reply
    test rax, rax
    jnz  .done                              ; a valid reply must ingest (0)

    ; ---------- (2) re-lookup IP1 -> HIT, serve MAC FROM THE TABLE ----------
    mov  edi, [rel arp_ip1]
    call arp_cache_lookup
    test rax, rax
    jz   .done                              ; must hit now
    lea  rsi, [rax + E_MAC]                  ; MAC read back out of the table
    lea  rdi, [rel arp_e1_mac]
    mov  rdx, 6
    call memcpy

    ; entry1's cached MAC must equal the canned reply's SHA byte-for-byte
    lea  rdi, [rel arp_e1_mac]
    lea  rsi, [rel arp_reply1 + ARP_SHA]
    mov  rdx, 6
    call memcmp
    test rax, rax
    jnz  .done

    ; ---------- (3) feed a DISTINCT reply #2 -> a 2nd entry alongside #1 ----------
    lea  rdi, [rel arp_reply2]
    mov  rsi, ARP_BODY_LEN
    call arp_cache_ingest_reply
    test rax, rax
    jnz  .done
    mov  edi, [rel arp_ip2]
    call arp_cache_lookup
    test rax, rax
    jz   .done                              ; entry #2 must be present
    lea  rsi, [rax + E_MAC]
    lea  rdi, [rel arp_e2_mac]
    mov  rdx, 6
    call memcpy

    ; entry #2 MAC must DIFFER from entry #1 (proves a real multi-entry table)
    lea  rdi, [rel arp_e1_mac]
    lea  rsi, [rel arp_e2_mac]
    mov  rdx, 6
    call memcmp
    test rax, rax
    jz   .done                              ; identical -> single slot / hardcode

    ; entry #1 must STILL be present after inserting #2 (table holds >1)
    mov  edi, [rel arp_ip1]
    call arp_cache_lookup
    test rax, rax
    jz   .done

    ; ---------- (4) age entry #1 past TTL -> it EVICTS, #2 survives ----------
    mov  edi, [rel arp_ip1]
    call arp_cache_lookup                    ; rax = entry #1 base
    mov  byte [rax + E_AGE], ARP_TTL         ; make #1 one tick from stale
    mov  edi, 1
    call arp_cache_age_evict                 ; #1 -> TTL+1 (evict); #2 -> 1 (survives)
    mov  edi, [rel arp_ip1]
    call arp_cache_lookup
    test rax, rax
    jnz  .done                               ; evicted entry MUST miss on re-lookup
    mov  edi, [rel arp_ip2]
    call arp_cache_lookup
    test rax, rax
    jz   .done                               ; younger entry must survive

    ; ---------- (5) NEGATIVE GATE: short frame rejected, no crash ----------
    lea  rdi, [rel arp_reply1]
    mov  rsi, 10                             ; < ARP_BODY_LEN
    call arp_cache_ingest_reply
    cmp  rax, -1
    jne  .done                               ; a malformed frame MUST be rejected

    ; ---------- all checks passed: print the KAT, then earn the marker ----------
    lea  rdi, [rel str_arp_sha_kat]
    lea  rsi, [rel arp_reply1 + ARP_SHA]     ; reply_sha (from the canned frame)
    call arp_emit_mac_kat
    lea  rdi, [rel str_arp_e1_kat]
    lea  rsi, [rel arp_e1_mac]               ; entry1_mac (from the table)
    call arp_emit_mac_kat
    lea  rdi, [rel str_arp_e2_kat]
    lea  rsi, [rel arp_e2_mac]               ; entry2_mac (from the table)
    call arp_emit_mac_kat
    lea  rdi, [rel str_arp_pass]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; arp_cache_init — clear table and learn times (all slots free).
arp_cache_init:
    lea  rdi, [rel arp_table]
    xor  rsi, rsi
    mov  rdx, ARP_STATE_SIZE
    call memset
    ret

; arp_cache_lookup(EDI=IPv4 key) -> RAX = entry base ptr, or 0 on MISS.
;   MOST-DURABLE hot-path (tournament v3). A resolver leaf (fan-in 8) must NEVER
;   hand a caller a stale/wrong MAC — one false hit poisons every frame the caller
;   then transmits — so this form is defensive-in-depth and DEGRADES TO MISS on
;   any ambiguity rather than risk a false hit:
;     * key == 0 (0.0.0.0) is not a resolvable ARP target -> reject up front, so an
;       uninitialised/zeroed caller key can never alias a slot.
;     * a slot matches ONLY when E_VALID == 1 AND E_IP == key -> a freed/evicted
;       slot (E_VALID = 0) is skipped even if a stale E_IP still lingers in it. This
;       scan does NOT depend on the age/evict path clearing E_IP; it stays correct
;       even if that invariant is ever violated (unlike a valid-free scan).
;     * strictly bounded to ARP_N slots (ECX down-counter) -> no OOB walk even on a
;       full/corrupt table; worst case simply returns MISS.
;   Un-cached IP returns 0. clobbers: RAX,RCX,R10.  (EDI preserved for the caller.)
arp_cache_lookup:
    test edi, edi
    jz   .lk_miss                            ; 0.0.0.0 is never a valid key -> MISS
    lea  r10, [rel arp_table]
    mov  ecx, ARP_N
.lk_scan:
    cmp  byte [r10 + E_VALID], 0
    je   .lk_next                            ; freed/evicted slot -> never served
    cmp  edi, [r10 + E_IP]                    ; occupied AND key matches -> hit
    je   .lk_hit
.lk_next:
    add  r10, E_SIZE
    dec  ecx
    jnz  .lk_scan
.lk_miss:
    xor  eax, eax
    ret
.lk_hit:
    mov  rax, r10
    jmp  arp_cache_touch                     ; lookups refresh recency

; arp_cache_touch(RAX=entry) -> RAX unchanged: make the entry most recent. Each
;   valid entry more recent than it ages one rank. Clobbers RCX,R10 only (the
;   lookup contract above).
arp_cache_touch:
    push rdx
    movzx edx, byte [rax + E_RANK]
    lea  r10, [rel arp_table]
    mov  ecx, ARP_N
.tc_scan:
    cmp  byte [r10 + E_VALID], 0
    je   .tc_next
    cmp  byte [r10 + E_RANK], dl
    jae  .tc_next
    inc  byte [r10 + E_RANK]
.tc_next:
    add  r10, E_SIZE
    dec  ecx
    jnz  .tc_scan
    mov  byte [rax + E_RANK], 0
    pop  rdx
    ret

; arp_binding_ok(EDI=IPv4 key, RSI=MAC ptr) -> EAX 0 storable / -1 never stored:
;   a 0.0.0.0 sender (RFC 5227 probe) and a zero, broadcast or multicast (I/G
;   bit) sender MAC are not bindings. Clobbers RAX,RCX.
arp_binding_ok:
    test edi, edi
    jz   .refuse
    test byte [rsi], 1
    jnz  .refuse                             ; multicast, including broadcast
    mov  eax, [rsi]
    movzx ecx, word [rsi + 4]
    or   eax, ecx
    jz   .refuse
    xor  eax, eax
    ret
.refuse:
    mov  eax, -1
    ret

; arp_cache_insert(EDI=IPv4 key, RSI=MAC ptr) -> RAX = entry base ptr, or 0 when
;   the binding is refused (see arp_binding_ok). Updates the existing entry for
;   that IP if present, else takes the first free slot, else replaces the least
;   recently used entry. The entry becomes most recent; age resets to 0.
;   clobbers: volatiles.
arp_cache_insert:
    call arp_binding_ok
    test eax, eax
    jnz  .ins_refuse
    ; pass 1: existing entry for this IP?
    lea  r10, [rel arp_table]
    mov  ecx, ARP_N
.up_scan:
    cmp  byte [r10 + E_VALID], 0
    je   .up_next
    mov  eax, [r10 + E_IP]
    cmp  eax, edi
    je   .place                              ; reuse the same slot
.up_next:
    add  r10, E_SIZE
    dec  ecx
    jnz  .up_scan
    ; pass 2: first free slot, ranked behind every valid entry
    lea  r10, [rel arp_table]
    mov  ecx, ARP_N
.fr_scan:
    cmp  byte [r10 + E_VALID], 0
    je   .new_free
    add  r10, E_SIZE
    dec  ecx
    jnz  .fr_scan
    call arp_cache_lru_victim                ; full -> least recently used
    jmp  .place
.new_free:
    call arp_cache_count_valid               ; ranked behind every valid entry
    mov  [r10 + E_RANK], al
.place:
    mov  byte [r10 + E_VALID], 1
    mov  byte [r10 + E_AGE], 0
    mov  [r10 + E_IP], edi
    mov  eax, [rsi]                          ; MAC bytes 0..3
    mov  [r10 + E_MAC], eax
    mov  ax,  [rsi + 4]                      ; MAC bytes 4..5
    mov  [r10 + E_MAC + 4], ax
    mov  rax, r10
    call arp_cache_stamp                    ; only an accepted binding restarts age
    jmp  arp_cache_touch
.ins_refuse:
    xor  eax, eax
    ret

; RAX=entry -> RAX unchanged. Timestamp is separate from the stable cache-entry
; layout. The clock may clobber RAX/RCX/RDX; do not carry the slot index in them.
arp_cache_stamp:
    push rax
    call boot_ms_now
    mov  rdx, rax
    pop  rax
    mov  rcx, rax
    lea  r10, [rel arp_table]
    sub  rcx, r10
    shr  rcx, 4                             ; E_SIZE=16, bounded table entry
    lea  r10, [rel arp_learned_ms]
    mov  [r10 + rcx*8], rdx
    ret

; arp_cache_update(EDI=IPv4 key, RSI=MAC ptr) -> RAX = entry, or 0 (no such
;   binding / refused). RFC 826 merge: refresh the MAC of a binding we already
;   hold; never creates one and never changes recency. clobbers: volatiles.
arp_cache_update:
    call arp_binding_ok
    test eax, eax
    jnz  .upd_none
    call arp_cache_lookup_raw
    test rax, rax
    jz   .upd_none
    mov  byte [rax + E_AGE], 0
    mov  ecx, [rsi]
    mov  [rax + E_MAC], ecx
    mov  cx, [rsi + 4]
    mov  [rax + E_MAC + 4], cx
    jmp  arp_cache_stamp
.upd_none:
    xor  eax, eax
    ret

; arp_cache_lookup_raw(EDI=key) -> RAX entry/0 without touching recency.
arp_cache_lookup_raw:
    test edi, edi
    jz   .lr_miss
    lea  r10, [rel arp_table]
    mov  ecx, ARP_N
.lr_scan:
    cmp  byte [r10 + E_VALID], 0
    je   .lr_next
    cmp  edi, [r10 + E_IP]
    je   .lr_hit
.lr_next:
    add  r10, E_SIZE
    dec  ecx
    jnz  .lr_scan
.lr_miss:
    xor  eax, eax
    ret
.lr_hit:
    mov  rax, r10
    ret

; arp_cache_count_valid -> EAX = valid entries. Clobbers RAX,RDX,R11.
arp_cache_count_valid:
    xor  eax, eax
    lea  r11, [rel arp_table]
    mov  edx, ARP_N
.cv_scan:
    cmp  byte [r11 + E_VALID], 0
    je   .cv_next
    inc  eax
.cv_next:
    add  r11, E_SIZE
    dec  edx
    jnz  .cv_scan
    ret

; arp_cache_lru_victim -> R10 = the valid entry with the highest rank (least
;   recently used). Called only with a full table. Clobbers RAX,RDX,R11.
arp_cache_lru_victim:
    lea  r10, [rel arp_table]
    lea  r11, [rel arp_table]
    xor  eax, eax                            ; best rank so far
    mov  edx, ARP_N
.lv_scan:
    cmp  byte [r11 + E_VALID], 0
    je   .lv_next
    cmp  byte [r11 + E_RANK], al
    jb   .lv_next
    mov  al, [r11 + E_RANK]
    mov  r10, r11
.lv_next:
    add  r11, E_SIZE
    dec  edx
    jnz  .lv_scan
    ret

; arp_cache_rank_close(R10=entry about to be freed): every valid entry older
;   than it moves one rank more recent, keeping ranks contiguous. Preserves all
;   registers except RAX.
arp_cache_rank_close:
    push rcx
    push rdx
    push r11
    movzx edx, byte [r10 + E_RANK]
    lea  r11, [rel arp_table]
    mov  ecx, ARP_N
.rc_scan:
    cmp  byte [r11 + E_VALID], 0
    je   .rc_next
    cmp  r11, r10
    je   .rc_next
    cmp  byte [r11 + E_RANK], dl
    jbe  .rc_next
    dec  byte [r11 + E_RANK]
.rc_next:
    add  r11, E_SIZE
    dec  ecx
    jnz  .rc_scan
    pop  r11
    pop  rdx
    pop  rcx
    ret

; arp_cache_ingest_reply(RDI=frame ptr, RSI=frame len) -> RAX = 0 ok / -1 reject.
;   Bounds-checks the frame (>= ARP_BODY_LEN) and that it is an ARP REPLY (oper=2)
;   BEFORE reading any field, then inserts SPA(IP) -> SHA(MAC). A short/truncated
;   or non-reply frame is rejected with no OOB read. clobbers: volatiles.
arp_cache_ingest_reply:
    cmp  rsi, ARP_BODY_LEN
    jb   .reject                             ; too short -> reject before any read
    cmp  byte [rdi + ARP_OPER], 0            ; oper high byte
    jne  .reject
    cmp  byte [rdi + ARP_OPER + 1], 2        ; oper low byte == reply(2)
    jne  .reject
    mov  r8d, [rdi + ARP_SPA]                ; SPA (IPv4 key)
    lea  r9,  [rdi + ARP_SHA]                ; SHA (MAC ptr)
    mov  edi, r8d
    mov  rsi, r9
    call arp_cache_insert
    xor  rax, rax
    ret
.reject:
    mov  rax, -1
    ret

; ---------------------------------------------------------------------------
; SEC-S7a solicited learning. Every PaOS ARP who-has notes its target here;
; only a REPLY from a noted target may create or refresh a binding. Unsolicited
; replies, gratuitous ARP, requests and IP-layer traffic never touch the table,
; so a LAN peer cannot rebind the gateway. Single writer: the BSP net context.
; ---------------------------------------------------------------------------
ARP_PENDING_N  equ 8
ARP_PENDING_MS equ 2000      ; a who-has answers within this window or not at all

; arp_pending_note(EDI=target IPv4) — remember one outstanding who-has for
;   ARP_PENDING_MS (ring of ARP_PENDING_N; a repeat target restarts its lifetime).
;   Clobbers RAX,RCX,RDX,R10.
arp_pending_note:
    test edi, edi
    jz   .pn_out
    push rdi
    call boot_ms_now                         ; RAX = now (clobbers RCX,RDX)
    pop  rdi
    lea  r10, [rel arp_pending_ip]
    xor  ecx, ecx
.pn_scan:
    cmp  [r10 + rcx*4], edi
    je   .pn_store
    inc  ecx
    cmp  ecx, ARP_PENDING_N
    jb   .pn_scan
    mov  ecx, [rel arp_pending_next]
    lea  edx, [rcx + 1]
    and  edx, ARP_PENDING_N - 1
    mov  [rel arp_pending_next], edx
.pn_store:
    mov  [r10 + rcx*4], edi
    lea  r10, [rel arp_pending_started]
    mov  [r10 + rcx*8], rax
.pn_out:
    ret

; arp_cache_learn_solicited(EDI=SPA, RSI=SHA ptr) -> RAX entry / 0. Consumes the
;   pending note for SPA; without one nothing is created or refreshed. A solicited
;   reply may change an existing binding's MAC (router swap recovery). A note
;   older than ARP_PENDING_MS or from a regressed/wrapped clock no longer counts.
;   Store the send time, not an overflowing absolute deadline; equality at two
;   seconds remains accepted. A reply whose MAC could never be stored (zero/
;   multicast) does not consume the note. clobbers: volatiles.
arp_cache_learn_solicited:
    call arp_binding_ok                      ; before consuming: a junk reply cannot burn the note
    test eax, eax
    jnz  .ls_none
    xor  ecx, ecx
    lea  r10, [rel arp_pending_ip]
.ls_scan:
    cmp  [r10 + rcx*4], edi
    je   .ls_hit
    inc  ecx
    cmp  ecx, ARP_PENDING_N
    jb   .ls_scan
.ls_none:
    xor  eax, eax
    ret
.ls_hit:
    mov  dword [r10 + rcx*4], 0              ; one reply per who-has
    lea  r10, [rel arp_pending_started]
    mov  r11, [r10 + rcx*8]
    push rdi
    push rsi
    push r11
    call boot_ms_now
    pop  r11
    pop  rsi
    pop  rdi
    sub  rax, r11                           ; elapsed since this target's who-has
    jc   .ls_expired                        ; clock moved behind the send time
    cmp  rax, ARP_PENDING_MS
    ja   .ls_expired                         ; the who-has expired unanswered
    jmp  arp_cache_insert
.ls_expired:
    push rdi
    mov  edi, 3                             ; observed pending-note expiry only
    call arp_observation_note
    pop  rdi
    jmp  .ls_none

; BSP-only numeric observation queue. Context is private to the existing
; UDP native poll bracket, filled only after its real RX op and pre/post native
; registry-generation checks. Neither a packet argument nor a direct parser/
; KAT/generic note call can set that context. No upward audit dependency.
ARP_OBS_N equ 8
ARP_OBS_SZ equ 40

arp_observation_reset:
    cmp  dword [rel arp_obs_test_depth], 0
    jne  .out
    mov  eax, [rel arp_obs_pending]
    add  [rel arp_obs_drops], rax
    jnc  .drop_ok
    mov  qword [rel arp_obs_drops], -1
.drop_ok:
    mov  dword [rel arp_obs_pending], 0
    mov  dword [rel arp_obs_head], 0
    mov  dword [rel arp_obs_tail], 0
    mov  dword [rel arp_obs_serial], 0
    mov  qword [rel arp_obs_context], 0
    cmp  qword [rel arp_obs_epoch], 65535
    jae  .frozen
    inc  qword [rel arp_obs_epoch]
    mov  byte [rel arp_obs_frozen], 0
    jmp  .clear
.frozen:
    mov  byte [rel arp_obs_frozen], 1
.clear:
    lea  rdi, [rel arp_obs_queue]
    xor  esi, esi
    mov  edx, ARP_OBS_N * ARP_OBS_SZ
    jmp  memset
.out:
    ret

; EDI1 SHA/Ethernet mismatch,2 sender-IP conflict,3 expired pending request.
; Fully transparent to the existing parser/cache scratch and return/flags.
arp_observation_note:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    sub  rsp, 8
    call arp_observation_enqueue
    add  rsp, 8
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    popfq
    ret

arp_observation_enqueue:
    cmp  dword [rel arp_obs_test_depth], 0
    jne  .out
    cmp  edi, 1
    jb   .out
    cmp  edi, 3
    ja   .out
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, [rel arp_obs_context]
    test r12, r12
    jz   .done
    mov  rdi, r12
    mov  rsi, [rel arp_obs_context + 8]
    call netdev_observation_member
    test eax, eax
    jz   .done
    cmp  rdx, [rel arp_obs_context + 16]
    jne  .done
    cmp  eax, [rel arp_obs_context + 24]
    jne  .done
    mov  r13d, eax
    cmp  byte [rel arp_obs_frozen], 0
    jne  .drop
    cmp  qword [rel arp_obs_epoch], 0
    je   .drop
    cmp  qword [rel arp_obs_epoch], 65535
    ja   .drop
    cmp  qword [rel arp_obs_total], -1
    je   .freeze
    cmp  dword [rel arp_obs_serial], -1
    je   .freeze
    inc  dword [rel arp_obs_serial]
    inc  qword [rel arp_obs_total]
    cmp  dword [rel arp_obs_pending], ARP_OBS_N
    jae  .drop
    mov  eax, [rel arp_obs_head]
    cmp  eax, ARP_OBS_N
    jae  .drop
    imul eax, ARP_OBS_SZ
    lea  r8, [rel arp_obs_queue]
    add  r8, rax
    mov  rax, [rel arp_obs_epoch]
    shl  rax, 32
    mov  ecx, [rel arp_obs_serial]
    or   rax, rcx
    mov  [r8], rax
    mov  [r8 + 8], r13d
    mov  [r8 + 12], ebx
    mov  [r8 + 16], r12
    mov  [r8 + 24], rdx
    mov  rax, [rel arp_obs_context + 8]
    mov  [r8 + 32], rax
    inc  dword [rel arp_obs_head]
    and  dword [rel arp_obs_head], ARP_OBS_N - 1
    inc  dword [rel arp_obs_pending]
    jmp  .done
.freeze:
    mov  byte [rel arp_obs_frozen], 1
.drop:
    call arp_observation_discard
.done:
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

arp_observation_discard:
    add  qword [rel arp_obs_drops], 1
    jnc  .out
    mov  qword [rel arp_obs_drops], -1
.out:
    ret

; RAX total,RDX queue/reset/stale detail drops. No packet/owner addresses.
arp_observation_snapshot:
    mov  rax, [rel arp_obs_total]
    mov  rdx, [rel arp_obs_drops]
    ret

; One attempt only: EAX1 record,0empty,-1discard. RDXid48,ECXslot1..8,
; ESIreason1..3. R8handle,R9generation,R10RXfn are PRIVATE lifetime tokens
; consumed by the BSP bridge, never stored in public/security records.
arp_observation_pop:
    cmp  dword [rel arp_obs_test_depth], 0
    jne  .empty
    cmp  dword [rel arp_obs_pending], 0
    je   .empty
    cmp  dword [rel arp_obs_pending], ARP_OBS_N
    ja   .corrupt
    mov  eax, [rel arp_obs_tail]
    cmp  eax, ARP_OBS_N
    jae  .corrupt
    imul eax, ARP_OBS_SZ
    lea  r11, [rel arp_obs_queue]
    add  r11, rax
    mov  rdx, [r11]
    mov  ecx, [r11 + 8]
    mov  esi, [r11 + 12]
    mov  r8, [r11 + 16]
    mov  r9, [r11 + 24]
    mov  r10, [r11 + 32]
    mov  qword [r11], 0
    mov  qword [r11 + 8], 0
    mov  qword [r11 + 16], 0
    mov  qword [r11 + 24], 0
    mov  qword [r11 + 32], 0
    inc  dword [rel arp_obs_tail]
    and  dword [rel arp_obs_tail], ARP_OBS_N - 1
    dec  dword [rel arp_obs_pending]
    mov  rax, rdx
    shr  rax, 32
    cmp  rax, [rel arp_obs_epoch]
    jne  .stale
    mov  eax, 1
    ret
.corrupt:
    sub  rsp, 8
    call arp_observation_reset
    add  rsp, 8
.stale:
    sub  rsp, 8
    call arp_observation_discard
    add  rsp, 8
    mov  eax, -1
    ret
.empty:
    xor  eax, eax
    ret

; arp_cache_age_tick — SEC-S7a: called from the idle loop. Evict after five
;   elapsed minutes since learning/solicited refresh; lookups do not refresh age.
;   Check each of the eight slots once, even after a long idle-loop delay. A new
;   binding must not inherit missed age ticks from an older binding. Clock
;   regression invalidates the binding rather than extending its lifetime.
;   E_AGE remains the explicit canned age/evict control, not a wall-clock counter.
;   Since only solicited replies teach the cache, a changed gateway MAC can
;   recover: the next consumer misses and asks again. clobbers: caller-saved.
ARP_AGE_MS equ 37500
ARP_MAX_AGE_MS equ ARP_TTL * ARP_AGE_MS
arp_cache_age_tick:
    call boot_ms_now
    mov  r11, rax
    lea  r10, [rel arp_table]
    lea  r9, [rel arp_learned_ms]
    xor  r8d, r8d
    mov  ecx, ARP_N
.at_scan:
    cmp  byte [r10 + E_VALID], 0
    je   .at_next
    mov  rdx, [r9 + r8*8]
    cmp  r11, rdx
    jb   .at_evict
    mov  rax, r11
    sub  rax, rdx
    cmp  rax, ARP_MAX_AGE_MS
    jb   .at_next
.at_evict:
    call arp_cache_rank_close
    mov  byte [r10 + E_AGE], ARP_TTL
    mov  byte [r10 + E_VALID], 0
.at_next:
    add  r10, E_SIZE
    inc  r8d
    dec  ecx
    jnz  .at_scan
    ret

; arp_cache_age_evict(EDI=age increment) — advance every occupied entry's age and
;   evict (free) any that reach ARP_TTL. Saturates age at 255. clobbers: volatiles.
arp_cache_age_evict:
    lea  r10, [rel arp_table]
    mov  ecx, ARP_N
.ae_scan:
    cmp  byte [r10 + E_VALID], 0
    je   .ae_next
    movzx eax, byte [r10 + E_AGE]
    add  eax, edi
    cmp  eax, 255
    jbe  .ae_store
    mov  eax, 255
.ae_store:
    mov  [r10 + E_AGE], al
    cmp  al, ARP_TTL
    jb   .ae_next
    call arp_cache_rank_close
    mov  byte [r10 + E_VALID], 0             ; stale -> evict
.ae_next:
    add  r10, E_SIZE
    dec  ecx
    jnz  .ae_scan
    ret

; arp_fmt_mac(RSI=6-byte MAC ptr, RDI=dst) — write "xx:xx:xx:xx:xx:xx\0" (18 bytes)
;   in lowercase hex. clobbers: RAX,RCX,RDX,R8,R9.
arp_fmt_mac:
    xor  ecx, ecx                            ; byte index 0..5
.fm_byte:
    movzx eax, byte [rsi + rcx]
    mov  edx, eax
    shr  edx, 4                              ; high nibble
    lea  r8, [rel arp_hexchars]
    mov  dl, [r8 + rdx]
    mov  [rdi], dl
    mov  edx, eax
    and  edx, 0x0f                           ; low nibble
    mov  dl, [r8 + rdx]
    mov  [rdi + 1], dl
    add  rdi, 2
    inc  ecx
    cmp  ecx, 6
    jae  .fm_end
    mov  byte [rdi], ':'                     ; separator between bytes
    inc  rdi
    jmp  .fm_byte
.fm_end:
    mov  byte [rdi], 0
    ret

; arp_emit_mac_kat(RDI=prefix str ptr [NUL-term, no CRLF], RSI=MAC ptr) —
;   print "<prefix><mac>\r\n". clobbers: volatiles.
arp_emit_mac_kat:
    push rsi
    call serial_string                       ; prefix (RDI)
    pop  rsi
    lea  rdi, [rel arp_mac_buf]
    call arp_fmt_mac
    lea  rdi, [rel arp_mac_buf]
    call serial_string
    lea  rdi, [rel str_arp_crlf]
    call serial_string
    ret

; arp_cache_lookup_kat — TOURNAMENT correctness + durability gate (v3).
;   Un-fakeable, content-graded gate for the fan-in-8 leaf arp_cache_lookup. It
;   earns up to THREE honest markers, each proving a distinct property; a stub that
;   merely prints a marker without a real table FAILS every one:
;     (A) tourn.arp_cache_lookup.kat   — correctness: HIT serves the inserted MAC
;         byte-for-byte, a 2nd key hits with a DISTINCT MAC (real multi-slot scan),
;         an absent key MISSES, and an EVICTED key MISSES while a younger survives.
;     (B) tourn.arp_cache_lookup.guard — graceful degradation: the leaf DEGRADES TO
;         MISS (never a false hit) on a 0.0.0.0 key AND on a freed slot whose E_IP
;         still lingers — the exact faults a valid-free scan would leak.
;     (C) tourn.arp_cache_lookup.bound — bounded scan: a FULL table's last-filled
;         key still HITS (scan reaches the final slot) and an absent key MISSES
;         (scan stops at ARP_N — no early stop, no OOB walk).
;   Each marker is printed ONLY after its checks pass. Preserves rbx,r12,r13.
;   clobbers: caller-saved.
arp_cache_lookup_kat:
    lea  rax, [rel .isolated]                ; RCQ-10 S3: never over a live lease
    jmp  arp_kat_isolated
.isolated:
    push rbx
    push r12
    push r13

    ; ============ (A) CORRECTNESS -> tourn.arp_cache_lookup.kat ============
    call arp_cache_init
    mov  edi, [rel arp_ip1]
    lea  rsi, [rel arp_reply1 + ARP_SHA]     ; MAC aa:bb:cc:dd:ee:01
    call arp_cache_insert
    mov  edi, [rel arp_ip2]
    lea  rsi, [rel arp_reply2 + ARP_SHA]     ; MAC aa:bb:cc:dd:ee:02
    call arp_cache_insert

    ; (1) HIT ip1 -> entry MAC == reply1.SHA byte-for-byte
    mov  edi, [rel arp_ip1]
    call arp_cache_lookup
    test rax, rax
    jz   .lkat_done                          ; present key MUST hit
    lea  rsi, [rax + E_MAC]                   ; MAC read back OUT OF THE TABLE
    lea  rdi, [rel arp_lk_mac]
    mov  rdx, 6
    call memcpy
    lea  rdi, [rel arp_lk_mac]
    lea  rsi, [rel arp_reply1 + ARP_SHA]
    mov  rdx, 6
    call memcmp
    test rax, rax
    jnz  .lkat_done                          ; wrong MAC -> fail (scores 0)

    ; (2) HIT ip2 -> distinct MAC (proves real multi-slot scan, not a hardcode)
    mov  edi, [rel arp_ip2]
    call arp_cache_lookup
    test rax, rax
    jz   .lkat_done
    lea  rsi, [rax + E_MAC]
    lea  rdi, [rel arp_lk_mac2]
    mov  rdx, 6
    call memcpy
    lea  rdi, [rel arp_lk_mac]               ; still holds ip1's MAC
    lea  rsi, [rel arp_lk_mac2]
    mov  rdx, 6
    call memcmp
    test rax, rax
    jz   .lkat_done                          ; identical -> single-slot -> fail

    ; (3) MISS: an un-cached key returns 0 (never a stale MAC)
    mov  edi, [rel arp_lk_absent]
    call arp_cache_lookup
    test rax, rax
    jnz  .lkat_done

    ; (4) EVICT ip1 -> miss; ip2 (younger) survives
    mov  edi, [rel arp_ip1]
    call arp_cache_lookup
    mov  byte [rax + E_AGE], ARP_TTL         ; one tick from stale
    mov  edi, 1
    call arp_cache_age_evict
    mov  edi, [rel arp_ip1]
    call arp_cache_lookup
    test rax, rax
    jnz  .lkat_done                          ; evicted key MUST miss
    mov  edi, [rel arp_ip2]
    call arp_cache_lookup
    test rax, rax
    jz   .lkat_done                          ; younger entry MUST survive

    lea  rdi, [rel str_arp_lk_kat]
    lea  rsi, [rel arp_lk_mac]               ; MAC lookup served for ip1 (from table)
    call arp_emit_mac_kat
    lea  rdi, [rel str_arp_lk_pass]
    call serial_string

    ; ========= (B) DURABILITY GUARD -> tourn.arp_cache_lookup.guard =========
    call arp_cache_init
    mov  edi, [rel arp_ip1]
    lea  rsi, [rel arp_reply1 + ARP_SHA]
    call arp_cache_insert                    ; one live entry (ip1) in slot 0
    ; (b1) lookup(0.0.0.0) MUST miss even though slot 0 is valid
    xor  edi, edi
    call arp_cache_lookup
    test rax, rax
    jnz  .lkat_done                          ; a zero key that HIT = fault escaped
    ; (b2) forge a freed slot (slot 1) whose stale E_IP still holds ip2's key
    lea  r10, [rel arp_table + E_SIZE]        ; slot #1
    mov  byte [r10 + E_VALID], 0              ; freed / evicted
    mov  eax, [rel arp_ip2]
    mov  [r10 + E_IP], eax                    ; stale key lingers in the freed slot
    mov  edi, [rel arp_ip2]
    call arp_cache_lookup
    test rax, rax
    jnz  .lkat_done                          ; served a freed slot = fault escaped

    lea  rdi, [rel str_arp_lk_guard]
    call serial_string

    ; ========= (C) BOUNDED SCAN -> tourn.arp_cache_lookup.bound =========
    call arp_cache_init
    mov  ebx, 1                               ; distinct non-zero keys 1..ARP_N
.lkat_fill:
    mov  edi, ebx
    lea  rsi, [rel arp_reply1 + ARP_SHA]      ; MAC value irrelevant here
    call arp_cache_insert
    inc  ebx
    cmp  ebx, ARP_N
    jbe  .lkat_fill                           ; fill ALL ARP_N slots
    ; last key (ARP_N) lives in the LAST slot -> a full-depth scan must reach it
    mov  edi, ARP_N
    call arp_cache_lookup
    test rax, rax
    jz   .lkat_done                           ; early stop -> fail
    ; an absent key on a FULL table must MISS (bounded, no OOB walk)
    mov  edi, 0x7FFFFFFF
    call arp_cache_lookup
    test rax, rax
    jnz  .lkat_done

    lea  rdi, [rel str_arp_lk_bound]
    call serial_string
.lkat_done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; arp_fault_battery -> RAX = contained count, RDX = ARPFB_TOTAL (=6).  [1116a]
;   The OS-side durability oracle for arp_cache_insert: feeds the routine (and its
;   bounds-checking ingest wrapper) 6 CONTRACT-FIXED hostile vectors and CONTENT-
;   grades each — not merely "didn't crash" — proving it degrades GRACEFULLY:
;     V1 boundary-insert   — a valid key lands in a fresh table and the cached MAC
;                            reads back byte-for-byte (correct placement).
;     V2 duplicate-no-leak — inserting the SAME key twice reuses ONE slot (occupied
;                            count stays 1) and UPDATES the MAC (no slot leak).
;     V3 empty-key 0.0.0.0 — insert stores it, but lookup(0) still MISSES: a zeroed
;                            caller key can never be SERVED (un-servable, inert).
;     V4 overflow full     — a 9th distinct insert into a full table overwrites slot 0
;                            (bounded); the past-table canary is INTACT and the table
;                            never grows past ARP_N (no OOB write / no corruption).
;     V5 malformed len<28  — a short frame is REJECTED (-1) with the table UNCHANGED.
;     V6 wrong-oper        — a well-formed but non-reply (oper=1) frame is REJECTED
;                            (-1) with the table UNCHANGED (no read past the guard).
;   The LIVE arp_table is snapshotted to arp_fault_snap on entry and RESTORED on exit,
;   so a FAULT call mid-session never disturbs real ARP state. Preserves rbx,r12-r15.
;   clobbers: caller-saved.
; ============================================================================
ARPFB_TOTAL equ 6

arp_fault_battery:
    sub  rsp, 8
    mov  ecx, [rel arp_obs_test_depth]
    mov  [rsp], rcx
    mov  dword [rel arp_obs_test_depth], 1
    call arp_fault_battery_body
    mov  ecx, [rsp]
    mov  [rel arp_obs_test_depth], ecx
    add  rsp, 8
    ret

arp_fault_battery_body:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; --- snapshot the live table so real ARP state is undisturbed on return ---
    lea  rdi, [rel arp_fault_snap]
    lea  rsi, [rel arp_table]
    mov  rdx, ARP_STATE_SIZE
    call memcpy
    xor  r12, r12                             ; r12 = contained count

    ; ---------------- V1: boundary-insert (valid key lands, MAC exact) ----------------
    call arp_cache_init
    mov  edi, [rel arp_ip1]
    lea  rsi, [rel arp_reply1 + ARP_SHA]
    call arp_cache_insert
    mov  edi, [rel arp_ip1]
    call arp_cache_lookup                     ; RAX = entry base or 0
    test rax, rax
    jz   .v2                                  ; failed to place -> not contained
    lea  rdi, [rax + E_MAC]
    lea  rsi, [rel arp_reply1 + ARP_SHA]
    mov  rdx, 6
    call memcmp
    test rax, rax
    jnz  .v2                                  ; wrong MAC -> not contained
    inc  r12

    ; ---------------- V2: duplicate-no-leak (one slot, MAC updated) ----------------
.v2:
    call arp_cache_init
    mov  edi, [rel arp_ip1]
    lea  rsi, [rel arp_reply1 + ARP_SHA]      ; MAC ...ee:01
    call arp_cache_insert
    mov  edi, [rel arp_ip1]                   ; SAME key
    lea  rsi, [rel arp_reply2 + ARP_SHA]      ; MAC ...ee:02 (different)
    call arp_cache_insert
    call arp_fb_occupied                      ; RAX = occupied slot count
    cmp  rax, 1
    jne  .v3                                  ; a leaked 2nd slot -> not contained
    mov  edi, [rel arp_ip1]
    call arp_cache_lookup
    test rax, rax
    jz   .v3
    lea  rdi, [rax + E_MAC]
    lea  rsi, [rel arp_reply2 + ARP_SHA]      ; must now hold the UPDATED MAC
    mov  rdx, 6
    call memcmp
    test rax, rax
    jnz  .v3                                  ; MAC not updated -> not contained
    inc  r12

    ; ---------------- V3: empty-key 0.0.0.0 (stored but un-servable) ----------------
.v3:
    call arp_cache_init
    xor  edi, edi                             ; 0.0.0.0
    lea  rsi, [rel arp_reply1 + ARP_SHA]
    call arp_cache_insert                     ; insert does not guard key==0...
    xor  edi, edi
    call arp_cache_lookup                     ; ...but lookup MUST refuse to serve it
    test rax, rax
    jnz  .v4                                  ; a served zero key = fault escaped
    inc  r12

    ; ---------------- V4: overflow full table (bounded, canary intact) ----------------
.v4:
    call arp_cache_init
    mov  rax, 0xC0FFEE11DEADBEEF
    mov  [rel arp_fb_canary], rax             ; arm the past-table sentinel
    mov  r13d, 1                              ; distinct nonzero keys 1..ARP_N
.v4_fill:
    mov  edi, r13d
    lea  rsi, [rel arp_reply1 + ARP_SHA]
    call arp_cache_insert
    inc  r13d
    cmp  r13d, ARP_N
    jbe  .v4_fill                             ; fill ALL ARP_N slots
    mov  edi, 0x0BADF00D                      ; a 9th DISTINCT key into a full table
    lea  rsi, [rel arp_reply2 + ARP_SHA]
    call arp_cache_insert
    mov  rax, 0xC0FFEE11DEADBEEF
    cmp  [rel arp_fb_canary], rax
    jne  .v5                                  ; OOB write clobbered the canary -> fail
    call arp_fb_occupied
    cmp  rax, ARP_N                           ; table must not have grown past capacity
    jne  .v5
    inc  r12

    ; ---------------- V5: malformed len<28 (rejected, no state change) ----------------
.v5:
    call arp_cache_init
    lea  rdi, [rel arp_reply1]
    mov  rsi, 10                              ; < ARP_BODY_LEN
    call arp_cache_ingest_reply
    cmp  rax, -1
    jne  .v6                                  ; a short frame MUST reject
    call arp_fb_occupied
    test rax, rax
    jnz  .v6                                  ; rejected frame must not have inserted
    inc  r12

    ; ---------------- V6: wrong-oper (rejected, no state change) ----------------
.v6:
    call arp_cache_init
    lea  rdi, [rel arp_req_frame]             ; well-formed length, oper=1 (request)
    mov  rsi, ARP_BODY_LEN
    call arp_cache_ingest_reply
    cmp  rax, -1
    jne  .fb_out                              ; a non-reply frame MUST reject
    call arp_fb_occupied
    test rax, rax
    jnz  .fb_out
    inc  r12

.fb_out:
    ; --- restore the live table byte-for-byte (ARP state undisturbed) ---
    lea  rdi, [rel arp_table]
    lea  rsi, [rel arp_fault_snap]
    mov  rdx, ARP_STATE_SIZE
    call memcpy
    mov  rax, r12                             ; contained
    mov  rdx, ARPFB_TOTAL                     ; total
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; arp_fb_occupied -> RAX = number of E_VALID==1 slots in arp_table. clobbers RAX,RCX,R10.
arp_fb_occupied:
    lea  r10, [rel arp_table]
    mov  ecx, ARP_N
    xor  eax, eax
.oc_scan:
    cmp  byte [r10 + E_VALID], 0
    je   .oc_next
    inc  eax
.oc_next:
    add  r10, E_SIZE
    dec  ecx
    jnz  .oc_scan
    ret

; ============================================================================
; arp_cache_insert_kat — 1419 tournament (v1 SMALLEST): the correctness + fault
;   GATE for arp_cache_insert. The insert body is UNCHANGED (already leanest-
;   correct); this is a PURE ADDITIVE gate reusing the existing canned vectors,
;   the arp_cache_lookup readback, and the shared arp_fault_battery. Two markers,
;   each printed ONLY on pass:
;     * tourn.arp_cache_insert.kat — drive the LIVE insert with two DISTINCT keys;
;         each key's MAC reads back BYTE-FOR-BYTE out of the table via lookup, and
;         the two cached MACs DIFFER (proves real placement across >1 slot, not a
;         hardcode). A wrong-output variant fails this -> no marker -> scores 0.
;     * tourn.arp_cache_insert.fault contained=6 total=6 — run the shared
;         arp_fault_battery (6 CONTRACT-FIXED hostile vectors, content-graded) and
;         emit the count ONLY when EVERY vector is contained (rax==rdx==ARPFB_TOTAL);
;         a variant that leaks even one vector prints nothing.
;   Every callee preserves rbx,r12-r15; this gate itself touches only caller-saved,
;   so it needs no register saves. clobbers: caller-saved.
; ============================================================================
arp_cache_insert_kat:
    lea  rax, [rel .isolated]                ; RCQ-10 S3: never over the live table
    jmp  arp_kat_isolated
.isolated:
    ; ---- correctness KAT -> tourn.arp_cache_insert.kat ----
    call arp_cache_init
    mov  edi, [rel arp_ip1]
    lea  rsi, [rel arp_reply1 + ARP_SHA]      ; MAC aa:bb:cc:dd:ee:01
    call arp_cache_insert
    mov  edi, [rel arp_ip2]
    lea  rsi, [rel arp_reply2 + ARP_SHA]      ; MAC aa:bb:cc:dd:ee:02
    call arp_cache_insert

    ; (1) ip1 present -> cached MAC == reply1.SHA byte-for-byte
    mov  edi, [rel arp_ip1]
    call arp_cache_lookup
    test rax, rax
    jz   .fault                               ; insert failed to place ip1
    lea  rsi, [rax + E_MAC]                    ; MAC read back OUT OF THE TABLE
    lea  rdi, [rel arp_lk_mac]
    mov  rdx, 6
    call memcpy
    lea  rdi, [rel arp_lk_mac]
    lea  rsi, [rel arp_reply1 + ARP_SHA]
    mov  rdx, 6
    call memcmp
    test rax, rax
    jnz  .fault                               ; wrong MAC -> no marker (scores 0)

    ; (2) ip2 present -> cached MAC DIFFERS from ip1's (real multi-slot placement)
    mov  edi, [rel arp_ip2]
    call arp_cache_lookup
    test rax, rax
    jz   .fault
    lea  rdi, [rel arp_lk_mac]                ; still holds ip1's MAC
    lea  rsi, [rax + E_MAC]                    ; ip2's MAC in the table
    mov  rdx, 6
    call memcmp
    test rax, rax
    jz   .fault                               ; identical -> single slot -> fail

    lea  rdi, [rel str_arp_ins_kat]
    call serial_string
.fault:
    ; ---- fault battery -> tourn.arp_cache_insert.fault contained=6 total=6 ----
    call arp_fault_battery                     ; RAX = contained, RDX = total
    cmp  rax, ARPFB_TOTAL
    jne  .done                                ; a vector escaped -> no marker
    cmp  rdx, ARPFB_TOTAL
    jne  .done
    lea  rdi, [rel str_arp_ins_fault]
    call serial_string
.done:
    ret

; --- net/arp_cache data (canned vectors + table; writable, in-image) -----------
; Canned ARP REPLY #1: htype=1 ptype=0x0800 hlen=6 plen=4 oper=2(reply);
;   SHA aa:bb:cc:dd:ee:01, SPA 192.168.0.10, THA/TPA our side (don't-care here).
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_arp_cache_0 0
arp_reply1:    db 0x00,0x01, 0x08,0x00, 0x06, 0x04, 0x00,0x02
               db 0xaa,0xbb,0xcc,0xdd,0xee,0x01      ; SHA (the MAC to cache)
               db 192,168,0,10                       ; SPA (the IPv4 key)
               db 0x52,0x54,0x00,0x12,0x34,0x56      ; THA (our MAC)
               db 192,168,0,199                       ; TPA (our IP)
; Canned ARP REPLY #2: a DISTINCT host — SHA aa:bb:cc:dd:ee:02, SPA 192.168.0.20.
arp_reply2:    db 0x00,0x01, 0x08,0x00, 0x06, 0x04, 0x00,0x02
               db 0xaa,0xbb,0xcc,0xdd,0xee,0x02      ; SHA (distinct MAC)
               db 192,168,0,20                        ; SPA (distinct IPv4)
               db 0x52,0x54,0x00,0x12,0x34,0x56      ; THA
               db 192,168,0,199                       ; TPA

arp_ip1:       db 192,168,0,10                        ; key for reply #1 (dword LE)
arp_ip2:       db 192,168,0,20                        ; key for reply #2

arp_table:     times ARP_N * E_SIZE db 0             ; the cache (8 entries)
arp_learned_ms: times ARP_N dq 0                    ; same-index accepted learn times
arp_pending_ip:   times ARP_PENDING_N dd 0               ; SEC-S7a outstanding who-has targets
arp_pending_next: dd 0
align 8
arp_pending_started: times ARP_PENDING_N dq 0            ; boot ms of this target's latest who-has
align 8
arp_fb_canary: dq 0                                   ; 1116a overflow sentinel — sits
                                                      ;   immediately past the last slot; a
                                                      ;   full-table insert that walked OOB
                                                      ;   would corrupt THIS word. bounded
                                                      ;   arp_cache_insert (overwrites slot 0)
                                                      ;   leaves it intact -> the proof.
arp_fault_snap: times ARP_STATE_SIZE db 0            ; live table and learn times
                                                      ;   so a FAULT call mid-session restores
                                                      ;   real ARP state on exit.
; 1116a wrong-oper vector: well-formed length (>= ARP_BODY_LEN) but oper=1 (REQUEST,
;   not reply=2) — arp_cache_ingest_reply must REJECT it before touching the table.
arp_req_frame: db 0x00,0x01, 0x08,0x00, 0x06, 0x04, 0x00,0x01   ; oper=1 (request)
               db 0xaa,0xbb,0xcc,0xdd,0xee,0x03      ; SHA
               db 192,168,0,30                        ; SPA
               db 0x52,0x54,0x00,0x12,0x34,0x56      ; THA
               db 192,168,0,199                       ; TPA
arp_e1_mac:    times 6 db 0                           ; entry #1 MAC read back
arp_e2_mac:    times 6 db 0                           ; entry #2 MAC read back
arp_mac_buf:   times 20 db 0                          ; "xx:xx:xx:xx:xx:xx\0"
arp_hexchars:  db "0123456789abcdef"

arp_lk_absent: db 192,168,0,99                         ; tourn KAT: an un-cached lookup key
arp_lk_mac:    times 6 db 0                            ; tourn KAT: MAC lookup served for ip1
arp_lk_mac2:   times 6 db 0                            ; tourn KAT: MAC lookup served for ip2

str_arp_pass:    db "[PAOS64] P4 net arp-cache: insert/hit/age-evict selftest PASS [arp.cache.logic]", 13,10,0
str_arp_sha_kat: db "[PAOS64][INF][net] arp.kat reply_sha=", 0
str_arp_e1_kat:  db "[PAOS64][INF][net] arp.kat entry1_mac=", 0
str_arp_e2_kat:  db "[PAOS64][INF][net] arp.kat entry2_mac=", 0
str_arp_lk_kat:  db "[PAOS64][INF][net] arp.lookup.kat served_mac=", 0
str_arp_lk_pass: db "[PAOS64] P4 net arp-cache-lookup: hit/miss/evict KAT PASS [tourn.arp_cache_lookup.kat]", 13,10,0
str_arp_lk_guard: db "[PAOS64] P4 net arp-cache-lookup: zero-key+stale-freed-slot degrade-to-MISS GUARD PASS [tourn.arp_cache_lookup.guard]", 13,10,0
str_arp_lk_bound: db "[PAOS64] P4 net arp-cache-lookup: full-table depth+absent bounded-scan BOUND PASS [tourn.arp_cache_lookup.bound]", 13,10,0
str_arp_ins_kat:   db "[PAOS64] P4 net arp-cache-insert: 2-key place+byte-exact+distinct KAT PASS [tourn.arp_cache_insert.kat]", 13,10,0
str_arp_ins_fault: db "[PAOS64] P4 net arp-cache-insert: 6-vector hostile battery all contained [tourn.arp_cache_insert.fault contained=6 total=6]", 13,10,0
str_arp_crlf:    db 13,10,0
%endmacro
WDATA_DEFER WDATA_net_arp_cache_0

%macro WDATA_net_arp_observation 0
alignb 8
arp_obs_epoch: resq 1
arp_obs_total: resq 1
arp_obs_drops: resq 1
arp_obs_context: resq 4               ; private receive owner/RX/generation/ordinal
arp_obs_serial: resd 1
arp_obs_pending: resd 1
arp_obs_head: resd 1
arp_obs_tail: resd 1
arp_obs_test_depth: resd 1
arp_obs_frozen: resb 1
alignb 8
arp_obs_queue: resb ARP_OBS_N * ARP_OBS_SZ
%endmacro
WDATA_BSS_DEFER WDATA_net_arp_observation
