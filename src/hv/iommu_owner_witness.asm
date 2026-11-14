;; MODULE hv/iommu_owner_witness
;; LAYER 5
;; EXPORTS cmd_verb_staleowner
;; IMPORTS hv/pci_assign, hv/amdvi, hv/amdvi_guest, hv/vtd, hv/vtd_guest, hv/vmx, svc/command
;; CAPS
;; OWNER saga:hv
; T1-4 "stale group ownership after failure" (LL-MEM-02; root 74158, SEC design 74048 + A1 74056).
;
; STALEOWNER <nonce> (owner verb): after the assigned-function guest has stopped, by any exit (a guest
; failure, a START refused after the attach, or a clean STOP), prove from the live tables that the
; IOMMU domain/owner record of that START is retired, or poisoned and fenced, and that the stale owner is
; refused on its next use:
;   RETIRED  pcia IDLE, backend RETIRED at pcia_gen, zero leaves, translation blocked (AMD DTE
;            BLOCKED/0/1/0, VT-d context entry zero), the six domain pages zero, no latched VT-d fault,
;            device span unpinned and the guest RAM back with the allocator          -> VERDICT=PASS
;   POISON   pcia POISON (the release was not proven), translation blocked, the span still pinned with
;            its RAM held, guest power refused                                         -> VERDICT=PASS_POISON
; In both, a detach at pcia_gen and an attach at pcia_gen and pcia_gen-1 are refused, and the receipt,
; the domain pages and the translation entry read back unchanged after those calls; vPCI forwarding,
; INTx injection and the playback source are all off. Anything else is VERDICT=FAILED. No live guest,
; no assignment this boot or no guest IOMMU domain is VERDICT=UNAVAILABLE and calls nothing.
;
; The attach/detach entry points are called only with a stale generation, so a correct product refuses
; each before any write (amdvi_guest_attach/vtd_guest_attach `jbe` on the generation, detach needs LIVE).
; A backend still LIVE here is reported FAILED before any call. Commands and the START loader share the
; cooperative scheduler, so no START can begin between the precondition checks and the calls.

SOW_UNAVAILABLE   equ 0
SOW_PASS          equ 1
SOW_PASS_POISON   equ 2
SOW_FAILED        equ 3
SOW_BK_AMD        equ 1
SOW_BK_VTD        equ 2
SOW_PAGES_QWORDS  equ 6 * 4096 / 8                 ; both backends: PML4, PDPT, four PDs

; -> EAX SOW_BK_* (0 none); the same order as pcia_iommu_attach.
sow_backend:
    mov  eax, SOW_BK_AMD
    cmp  byte [rel amdvi_owned], 1
    je   .out
    mov  eax, SOW_BK_VTD
    cmp  byte [rel vtd_enabled], 1
    je   .out
    xor  eax, eax
.out:
    ret

; -> RAX fold of the six domain pages (0 when none), EDX 1 when every byte is zero.
sow_pages_fold:
    mov  rsi, [rel amdvi_guest_pages]
    cmp  byte [rel sow_bk], SOW_BK_AMD
    je   .have
    mov  rsi, [rel vtdg_pages]
.have:
    xor  eax, eax
    mov  edx, 1
    test rsi, rsi
    jz   .out
    xor  r8d, r8d
    mov  ecx, SOW_PAGES_QWORDS
.loop:
    mov  r9, [rsi]
    or   r8, r9
    rol  rax, 7
    xor  rax, r9
    add  rsi, 8
    dec  ecx
    jnz  .loop
    test r8, r8
    setz dl
    movzx edx, dl
.out:
    ret

; -> EAX 1 when the domain's requester is blocked, RDX fold of its entry (DTE or context entry).
sow_translation:
    cmp  byte [rel sow_bk], SOW_BK_AMD
    jne  .vtd
    mov  eax, [rel amdvi_guest_bdf]
    shl  eax, 5
    add  rax, [rel amdvi_devtab]
    mov  rdx, [rax]
    rol  rdx, 13
    xor  rdx, [rax + 8]
    rol  rdx, 13
    xor  rdx, [rax + 16]
    rol  rdx, 13
    xor  rdx, [rax + 24]
    cmp  qword [rax], AMDVI_DTE_BLOCKED
    jne  .no
    cmp  qword [rax + 8], 0
    jne  .no
    cmp  qword [rax + 16], 1
    jne  .no
    cmp  qword [rax + 24], 0
    jne  .no
    mov  eax, 1
    ret
.vtd:
    mov  edi, [rel vtdg_bdf]
    call vtd_hda_ctx_entry
    xor  edx, edx
    test rax, rax
    jz   .no                                    ; no live root entry: nothing readable, nothing proven
    mov  rdx, [rax]
    rol  rdx, 13
    xor  rdx, [rax + 8]
    cmp  qword [rax], 0
    jne  .no
    cmp  qword [rax + 8], 0
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; RDI = 64-byte receipt buffer -> backend receipt (qword 0 state, 1 generation, 6 leaves, 7 events).
sow_receipt:
    jmp  pcia_iommu_receipt

; One " name=<decimal>" reply field (no label tables: the image is org 0).
%macro SOW_FIELD 3
    lea  rdi, [rel %1]
    call vtd_out_str
%ifidn %2, dword
    mov  edi, [rel %3]
%else
    movzx edi, byte [rel %3]
%endif
    call vtd_out_dec
%endmacro

cmd_verb_staleowner:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  [r12 + RSP_VAL], rbx
    mov  rdi, rbx
    call vtd_copy_nonce
    test eax, eax
    jz   .bad_nonce
    lea  rdi, [rel sow_rec]
    mov  ecx, SOW_REC_BYTES
    xor  eax, eax
    cld
    rep  stosb
    mov  r14, [rel pcia_gen]
    mov  [rel sow_gen], r14
    movzx eax, byte [rel pcia_state]
    mov  [rel sow_pstate], al
    lea  rbx, [rel str_sow_r_no_assignment]
    test r14, r14
    jz   .unavailable
    lea  rbx, [rel str_sow_r_guest_active]
    cmp  byte [rel hv_linux_running], 0
    jne  .unavailable
    cmp  byte [rel hv_linux_start_active], 0
    jne  .unavailable
    cmp  byte [rel hv_linux_run_req], 0
    jne  .unavailable
    lea  rbx, [rel str_sow_r_assignment_live]
    cmp  byte [rel pcia_state], PCIA_IDLE
    je   .idle_or_poison
    cmp  byte [rel pcia_state], PCIA_POISON
    jne  .unavailable
.idle_or_poison:
    lea  rbx, [rel str_sow_r_no_iommu]
    call sow_backend
    mov  [rel sow_bk], al
    test eax, eax
    jz   .unavailable
    lea  rdi, [rel sow_r0]
    call sow_receipt
    lea  rbx, [rel str_sow_r_no_domain]
    mov  rax, [rel sow_r0]
    mov  [rel sow_state], al
    test rax, rax
    jz   .unavailable                           ; this boot's START never built a guest domain
    cmp  [rel sow_r0 + 8], r14
    jne  .unavailable                           ; the attach of this START refused before its domain
    mov  eax, [rel sow_r0 + 16]
    mov  r15d, eax
    mov  [rel sow_bdf], eax
    mov  rax, [rel sow_r0 + 48]
    mov  [rel sow_leaves], eax
    mov  rax, [rel sow_r0 + 56]
    mov  [rel sow_events], eax
    movzx eax, byte [rel vtdg_fault_latched]
    cmp  byte [rel sow_bk], SOW_BK_VTD
    je   .latch
    xor  eax, eax
.latch:
    mov  [rel sow_latched], al
    mov  byte [rel sow_verdict], SOW_FAILED
    cmp  byte [rel sow_state], 1                ; LIVE with the function released: report, call nothing
    je   .render

    call sow_pages_fold
    mov  [rel sow_fold0], rax
    mov  [rel sow_zero], dl
    call sow_translation
    mov  [rel sow_blocked], al
    mov  [rel sow_tr0], rdx

    mov  edi, r15d
    mov  rsi, r14
    call pcia_iommu_detach
    test eax, eax
    setnz byte [rel sow_detach_refused]
    mov  r13, [rel amdvi_guest_size]
    mov  rbx, [rel amdvi_guest_host]
    cmp  byte [rel sow_bk], SOW_BK_AMD
    je   .sizes
    mov  r13, [rel vtdg_size]
    mov  rbx, [rel vtdg_host]
.sizes:
    mov  edi, r15d
    mov  rsi, r13
    mov  rdx, rbx
    mov  rcx, r14
    call pcia_iommu_attach
    test eax, eax
    setnz byte [rel sow_attach_same_refused]
    mov  byte [rel sow_attach_older_refused], 2   ; n/a: the first START has no older generation
    cmp  r14, 1
    jbe  .after
    mov  edi, r15d
    mov  rsi, r13
    mov  rdx, rbx
    lea  rcx, [r14 - 1]
    call pcia_iommu_attach
    test eax, eax
    setnz byte [rel sow_attach_older_refused]
.after:
    lea  rdi, [rel sow_r1]
    call sow_receipt
    call sow_pages_fold
    mov  r13, rax
    call sow_translation
    xor  ecx, ecx
    cmp  [rel sow_tr0], rdx
    jne  .compared
    cmp  [rel sow_fold0], r13
    jne  .compared
    lea  rsi, [rel sow_r0]
    lea  rdi, [rel sow_r1]
    mov  ecx, 7                                  ; state..leaves; qword 7 (events) is reported, not compared
    repe cmpsq
    sete cl
.compared:
    mov  [rel sow_unchanged], cl

    call pcia_owns_cfg
    mov  [rel sow_cfg], al
    call pcia_try_inject_irq
    mov  [rel sow_irq], al
    call pcia_playback_source
    test rax, rax
    setnz byte [rel sow_pcm]
    call hv_linux_span_pinned
    mov  [rel sow_pinned], al
    cmp  qword [rel hv_linux_mb_token], 0
    sete byte [rel sow_ram_returned]
    call pcia_guest_owned
    mov  [rel sow_power_refused], al

    ; Both verdicts: refusals, nothing changed, consumers off, no leaves, translation blocked.
    cmp  byte [rel sow_detach_refused], 1
    jne  .render
    cmp  byte [rel sow_attach_same_refused], 1
    jne  .render
    cmp  byte [rel sow_attach_older_refused], 0
    je   .render
    cmp  byte [rel sow_unchanged], 1
    jne  .render
    cmp  byte [rel sow_cfg], 0
    jne  .render
    cmp  byte [rel sow_irq], 0
    jne  .render
    cmp  byte [rel sow_pcm], 0
    jne  .render
    cmp  dword [rel sow_leaves], 0
    jne  .render
    cmp  byte [rel sow_blocked], 1
    jne  .render
    cmp  byte [rel sow_pstate], PCIA_POISON
    je   .poison
    ; RETIRED: the backend proved the retirement, nothing pins the span, the RAM went back.
    cmp  byte [rel sow_state], 2
    jne  .render
    cmp  byte [rel sow_zero], 1
    jne  .render
    cmp  byte [rel sow_latched], 0
    jne  .render
    cmp  byte [rel sow_pinned], 0
    jne  .render
    cmp  byte [rel sow_ram_returned], 1
    jne  .render
    mov  byte [rel sow_verdict], SOW_PASS
    jmp  .render
.poison:
    ; POISON: fenced, never returned. The backend may be RETIRED (pcia's own stop was not proven) or POISON.
    cmp  byte [rel sow_pinned], 1
    jne  .render
    cmp  byte [rel sow_ram_returned], 0
    jne  .render
    cmp  byte [rel sow_power_refused], 1
    jne  .render
    mov  byte [rel sow_verdict], SOW_PASS_POISON
    jmp  .render

.unavailable:
    mov  byte [rel sow_verdict], SOW_UNAVAILABLE
    call vtd_out_reset
    lea  rdi, [rel str_sow_head]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    lea  rdi, [rel str_sow_unavailable]
    call vtd_out_str
    mov  rdi, rbx
    call vtd_out_str
    lea  rdi, [rel str_sow_pcia_gen]
    call vtd_out_str
    mov  edi, [rel sow_gen]
    call vtd_out_dec
    lea  rdi, [rel str_sow_pcia_state]
    call vtd_out_str
    movzx edi, byte [rel sow_pstate]
    call vtd_out_dec
    lea  rdi, [rel str_sow_eol]
    call vtd_out_str
    jmp  .ready

.render:
    call vtd_out_reset
    lea  rdi, [rel str_sow_head]
    call vtd_out_str
    lea  rdi, [rel vtd_nonce]
    call vtd_out_str
    lea  rdi, [rel str_sow_amdvi]
    cmp  byte [rel sow_bk], SOW_BK_AMD
    je   .bk
    lea  rdi, [rel str_sow_vtd]
.bk:
    call vtd_out_str
    SOW_FIELD str_sow_f_gen, dword, sow_gen
    SOW_FIELD str_sow_f_bdf, dword, sow_bdf
    SOW_FIELD str_sow_pcia_state, byte, sow_pstate
    SOW_FIELD str_sow_f_state, byte, sow_state
    SOW_FIELD str_sow_f_leaves, dword, sow_leaves
    SOW_FIELD str_sow_f_blocked, byte, sow_blocked
    SOW_FIELD str_sow_f_zero, byte, sow_zero
    SOW_FIELD str_sow_f_detach, byte, sow_detach_refused
    SOW_FIELD str_sow_f_same, byte, sow_attach_same_refused
    SOW_FIELD str_sow_f_older, byte, sow_attach_older_refused
    SOW_FIELD str_sow_f_unchanged, byte, sow_unchanged
    SOW_FIELD str_sow_f_cfg, byte, sow_cfg
    SOW_FIELD str_sow_f_irq, byte, sow_irq
    SOW_FIELD str_sow_f_pcm, byte, sow_pcm
    SOW_FIELD str_sow_f_pinned, byte, sow_pinned
    SOW_FIELD str_sow_f_ram, byte, sow_ram_returned
    SOW_FIELD str_sow_f_power, byte, sow_power_refused
    SOW_FIELD str_sow_f_latched, byte, sow_latched
    SOW_FIELD str_sow_f_events, dword, sow_events
.verdict:
    movzx eax, byte [rel sow_verdict]
    lea  rdi, [rel str_sow_v_failed]
    cmp  eax, SOW_PASS
    jne  .not_pass
    lea  rdi, [rel str_sow_v_pass]
.not_pass:
    cmp  eax, SOW_PASS_POISON
    jne  .v
    lea  rdi, [rel str_sow_v_pass_poison]
.v:
    call vtd_out_str
    jmp  .ready
.bad_nonce:
    call vtd_out_reset
    lea  rdi, [rel str_sow_bad_nonce]
    call vtd_out_str
.ready:
    mov  byte [rel vtd_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

str_sow_head:          db " STALEOWNER nonce=", 0
str_sow_amdvi:         db " backend=amdvi", 0
str_sow_vtd:           db " backend=vtd", 0
str_sow_unavailable:   db " VERDICT=UNAVAILABLE reason=", 0
str_sow_r_no_assignment:   db "no_assignment", 0
str_sow_r_guest_active:    db "guest_active", 0
str_sow_r_assignment_live: db "assignment_live", 0
str_sow_r_no_iommu:        db "no_iommu", 0
str_sow_r_no_domain:       db "no_domain", 0
str_sow_pcia_gen:      db " pcia_gen=", 0
str_sow_pcia_state:    db " pcia_state=", 0
str_sow_f_gen:         db " gen=", 0
str_sow_f_bdf:         db " bdf=", 0
str_sow_f_state:       db " state=", 0
str_sow_f_leaves:      db " leaves=", 0
str_sow_f_blocked:     db " translation_blocked=", 0
str_sow_f_zero:        db " pages_zero=", 0
str_sow_f_detach:      db " detach_stale_refused=", 0
str_sow_f_same:        db " attach_same_refused=", 0
str_sow_f_older:       db " attach_older_refused=", 0
str_sow_f_unchanged:   db " receipt_unchanged=", 0
str_sow_f_cfg:         db " cfg_forward=", 0
str_sow_f_irq:         db " irq=", 0
str_sow_f_pcm:         db " pcm=", 0
str_sow_f_pinned:      db " span_pinned=", 0
str_sow_f_ram:         db " ram_returned=", 0
str_sow_f_power:       db " power_refused=", 0
str_sow_f_latched:     db " fault_latched=", 0
str_sow_f_events:      db " events=", 0
str_sow_v_pass:        db " VERDICT=PASS", 13, 10, 0
str_sow_v_pass_poison: db " VERDICT=PASS_POISON", 13, 10, 0
str_sow_v_failed:      db " VERDICT=FAILED", 13, 10, 0
str_sow_eol:           db 13, 10, 0
str_sow_bad_nonce:     db " STALEOWNER ERR bad_nonce", 13, 10, 0

%include "core/abi/wdata.inc"
%macro WDATA_hv_iommu_owner_witness 0
alignb 8
sow_r0: resq 8
sow_r1: resq 8
sow_rec:                                        ; zeroed by every STALEOWNER before it measures
sow_gen: resq 1
sow_fold0: resq 1
sow_tr0: resq 1
sow_bdf: resd 1
sow_leaves: resd 1
sow_events: resd 1
sow_pstate: resb 1
sow_state: resb 1
sow_bk: resb 1
sow_blocked: resb 1
sow_zero: resb 1
sow_detach_refused: resb 1
sow_attach_same_refused: resb 1
sow_attach_older_refused: resb 1
sow_unchanged: resb 1
sow_cfg: resb 1
sow_irq: resb 1
sow_pcm: resb 1
sow_pinned: resb 1
sow_ram_returned: resb 1
sow_power_refused: resb 1
sow_latched: resb 1
sow_verdict: resb 1
sow_rec_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_iommu_owner_witness
SOW_REC_BYTES equ sow_rec_end - sow_rec
