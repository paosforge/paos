;; MODULE sec/airlock
;; LAYER 5
;; EXPORTS airlock_init, airlock_select_tier, airlock_run, airlock_register_verbs, secair_ready, secair_tier_ok, secair_deny_ok, secair_no_vmx, airlock_refused_count, airlock_observation_take, airlock_detail_drops
;; IMPORTS hv/boundary_execution, hv/boundary, hv/vmx, hv/hv_ops, core/dma, core/lib/mem, core/lib/str, core/lock, boot/serial, svc/command, svc/command_airlock, sec/canned_blobs/airlock_fixtures
;; CAPS
;; LOCK: airlock_lock PROTECTS airlock_current_desc, airlock_admitted_blob, airlock_last_verdict
;; OWNER task:1056
%include "hv/boundary_transition.inc"
; ============================================================================
; Hardware AIRLOCK for untrusted code (contract 1056).
;
; This is a seam-adapted port of Classic's proven vmx_ept_selftest.asm.  The
; proven VMXON/VMCS/EPT/preemption-timer/restore order is retained.  The new
; security property is one dedicated host-owned page at AIR_HOST_PAGE_OFF.  Its
; intended guest alias AIR_DENIED_GPA has NO EPT leaf.  A canned hostile blob
; writes that alias; only a decoded hardware EPT write violation can yield
; AIR_VERDICT_FAILED_EPT.  The page is never restored after a run, so its live
; random canary readback is independent evidence that the write did not land.
;
; Untrusted manifests always select AIR_TIER_HARDWARE.  No VMX/EPT/watchdog, an
; unknown/stub backend, a resident guest, or a bad host state all REFUSE.  There
; is deliberately no in-keep fallback.
; ============================================================================

AIR_MAN_FLAGS              equ 0
AIR_MAN_TIER               equ 4
AIR_MAN_SIZE               equ 8
AIR_FOOTPRINT_PURE         equ 0x01
AIR_FOOTPRINT_UNTRUSTED    equ 0x02
AIR_FOOTPRINT_HOST_BOUND   equ 0x04
AIR_TIER_PURE              equ 1
AIR_TIER_HARDWARE          equ 2

AIR_BLOB_CODE              equ 0
AIR_BLOB_LEN               equ 8
AIR_BLOB_KIND              equ 12
AIR_BLOB_SIZE              equ 16
AIR_BLOB_HOSTILE           equ 1
AIR_BLOB_BENIGN            equ 2
AIR_BLOB_HANG              equ 3

AIR_VERDICT_OK             equ 0
AIR_VERDICT_FAILED_EPT     equ 1
AIR_VERDICT_REAPED         equ 2
AIR_VERDICT_REFUSED        equ 3
AIR_VERDICT_ERROR          equ 4

AIR_REGION_BYTES           equ 0x17000
AIR_VMCS_OFF               equ 0x1000
AIR_EPT_PML4_OFF           equ 0x2000
AIR_EPT_PDPT_OFF           equ 0x3000
AIR_EPT_PD_OFF             equ 0x4000
AIR_EPT_PT_OFF             equ 0x5000
AIR_GUEST_RAM_OFF          equ 0x6000
AIR_GUEST_PAGES            equ 16
AIR_HOST_PAGE_OFF          equ 0x16000
AIR_GUEST_CODE_GPA         equ 0x4000
AIR_MAILBOX_IN_GPA         equ 0x5000
AIR_GUEST_CODE_CAPACITY    equ AIR_MAILBOX_IN_GPA - AIR_GUEST_CODE_GPA
AIR_MAILBOX_OUT_GPA        equ 0x5100
AIR_GUEST_STACK_GPA        equ 0x6FF0
AIR_DENIED_GPA             equ 0x10000
AIR_CANARY_BYTES           equ 128
AIR_HOSTILE_SENTINEL       equ 0xBAD0C0DE5A17F00D

; ---------------------------------------------------------------------------
; Manifest selection.  The field is present at v1 even though the only shipped
; untrusted fixtures all select the same scale-1 hardware domain.
; ---------------------------------------------------------------------------
airlock_select_tier:
    xor  eax, eax
    test rdi, rdi
    jz   .out
    mov  ecx, [rdi + AIR_MAN_FLAGS]
    test ecx, AIR_FOOTPRINT_UNTRUSTED | AIR_FOOTPRINT_HOST_BOUND
    jnz  .hardware
    test ecx, AIR_FOOTPRINT_PURE
    jz   .out
    mov  eax, AIR_TIER_PURE
    jmp  .store
.hardware:
    mov  eax, AIR_TIER_HARDWARE
.store:
    mov  [rdi + AIR_MAN_TIER], al
.out:
    ret

; Named wrappers make the declared scale-1 lock site machine-auditable while
; retaining the single shared spinlock implementation from core/lock.
airlock_lock_acquire:
    lea  rdi, [rel airlock_lock]
    jmp  spin_acquire

airlock_lock_release:
    lea  rdi, [rel airlock_lock]
    jmp  spin_release

; Populate runtime code pointers (never static dq symbol RVAs), select the tier,
; allocate the persistent airlock, then execute the hostile proof once at boot.
airlock_init:
    mov  byte [rel secair_ready], 0
    mov  byte [rel secair_tier_ok], 0
    mov  byte [rel secair_deny_ok], 0
    mov  byte [rel secair_no_vmx], 0
    call airlock_populate_blob_descriptors
    lea  rdi, [rel air_manifest_untrusted]
    call airlock_select_tier
    cmp  eax, AIR_TIER_HARDWARE
    jne  .closed
    mov  byte [rel secair_tier_ok], 1
    lea  rdi, [rel str_air_tier]
    call serial_string

    call airlock_prepare
    test eax, eax
    jz   .closed
    ; Bootstrap-only readiness lets airlock_run execute the canned proof.  It
    ; is cleared again on any failure and is not published until the decoded
    ; EPT-write exit and unchanged host canary have both been observed.
    mov  byte [rel secair_ready], 1

    ; Per-boot, non-constant canary.  Keep a separate shadow for comparison;
    ; never copy the shadow back over the live host page after the guest runs.
    mov  rdi, [rel airlock_host_page]
    xor  esi, esi
    mov  edx, AIR_CANARY_BYTES
    call memset
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    xor  rax, [rel airlock_base]
    mov  rdi, [rel airlock_host_page]
    mov  [rdi], rax
    not  rax
    mov  [rdi + 8], rax
    lea  rsi, [rel airlock_canary_shadow]
    mov  rax, [rdi]
    mov  [rsi], rax
    mov  rax, [rdi + 8]
    mov  [rsi + 8], rax
    mov  dword [rel airlock_canary_len], 16

    lea  rdi, [rel air_blob_desc_hostile]
    lea  rsi, [rel air_manifest_untrusted]
    call airlock_run_probe
    mov  [rel airlock_boot_verdict], eax  ; ROOT118959 detail
    cmp  eax, AIR_VERDICT_FAILED_EPT
    jne  .proof_failed
    mov  rdi, [rel airlock_host_page]
    lea  rsi, [rel airlock_canary_shadow]
    mov  edx, 16
    call memcmp
    test eax, eax
    jnz  .proof_failed
    mov  byte [rel secair_deny_ok], 1
    lea  rdi, [rel str_air_deny]
    call serial_string
    lea  rdi, [rel str_air_ready]
    call serial_string
    jmp  .done
.proof_failed:
    mov  byte [rel secair_ready], 0
    lea  rdi, [rel str_air_proof_failed]
    call serial_string
    call airlock_proof_detail  ; ROOT118959 detail
    jmp  .done
.closed:
    mov  byte [rel secair_no_vmx], 1
    lea  rdi, [rel str_air_no_vmx]
    call serial_string
.done:
    ret

; airlock_prepare -> EAX=1 iff selected Intel VMX has EPT + a mandatory
; preemption timer and a persistent, page-aligned region was allocated.
airlock_prepare:
    xor  eax, eax
    mov  rdx, [rel hv_ops_active]
    lea  rcx, [rel hv_ops_vmx]
    cmp  rdx, rcx
    jne  .fail
    cmp  byte [rel hv_vmx_present], 1
    jne  .fail
    cmp  byte [rel hv_vmxon_ok], 1
    jne  .fail
    cmp  byte [rel hv_ept_built], 1
    jne  .fail
    ; Secondary controls, EPT, 4-level walk, WB leaves, preemption timer.
    mov  ecx, 0x482
    rdmsr
    bt   edx, 31
    jnc  .fail
    mov  ecx, 0x48B
    rdmsr
    bt   edx, 1
    jnc  .fail
    mov  ecx, 0x48C
    rdmsr
    bt   eax, 6
    jnc  .fail
    bt   eax, 14
    jnc  .fail
    mov  ecx, 0x481
    rdmsr
    bt   edx, 6
    jnc  .fail

    mov  rax, [rel airlock_base]
    test rax, rax
    jnz  .have_region
    mov  edi, AIR_REGION_BYTES
    call dma_alloc
    test rax, rax
    jz   .fail
    mov  [rel airlock_base], rax
    lea  rdx, [rax + AIR_HOST_PAGE_OFF]
    mov  [rel airlock_host_page], rdx
.have_region:
    ; Proven divisor-derived watchdog value: about one million TSC cycles.
    mov  ecx, 0x485
    rdmsr
    and  eax, 0x1F
    mov  ecx, eax
    mov  eax, 0x100000
    shr  eax, cl
    cmp  eax, 0x10
    jae  .wd_ok
    mov  eax, 0x10
.wd_ok:
    mov  [rel airlock_wd_value], eax
    mov  eax, 1
.out:
    ret
.fail:
    xor  eax, eax
    ret

; airlock_run(RDI=runtime blob descriptor, RSI=capability manifest) -> verdict.
; The one lock site serializes the VMCS, guest RAM and host-canary observation.
airlock_run:
    xor  ecx, ecx                         ; ordinary native admission
    jmp  airlock_run_observed

; Only the trusted boot proof uses the explicit probe ingress.
airlock_run_probe:
    mov  ecx, 0x80

airlock_run_observed:
    push rbx
    push r12
    push r13
    mov  byte [rel airlock_last_refusal], 0  ; ROOT118959 detail
    mov  byte [rel airlock_last_stage], 0  ; ROOT118959 detail
    mov  dword [rel airlock_last_vmwrites], 0  ; ROOT118959 detail
    mov  r13d, ecx
    or   r13d, 1                          ; tier not admitted (incl absent manifest)
    mov  rbx, rdi
    mov  r12, rsi
    mov  rdi, r12
    call airlock_select_tier
    cmp  eax, AIR_TIER_HARDWARE
    jne  .refused
    inc  r13d                             ;2 native readiness absent
    cmp  byte [rel secair_ready], 1
    jne  .refused
    inc  r13d                             ;3 resident guest before lock
    cmp  byte [rel hv_linux_running], 0
    jne  .refused
    inc  r13d                             ;4 selected backend is not VMX
    mov  rax, [rel hv_ops_active]
    lea  rdx, [rel hv_ops_vmx]
    cmp  rax, rdx
    jne  .refused
    call airlock_lock_acquire
    inc  r13d                             ;5 resident guest at locked recheck
    ; Close the launch race with a resident guest after taking the lock.
    cmp  byte [rel hv_linux_running], 0
    jne  .unlock_refused
    inc  r13d                             ;6 backend refusal, detailed cause UNKNOWN
    mov  rdi, rbx
    call airlock_vmx_run
    mov  ebx, eax
    call airlock_lock_release
    mov  eax, ebx
    jmp  .out
.unlock_refused:
    call airlock_lock_release
.refused:
    mov  eax, AIR_VERDICT_REFUSED
.out:
    ; One final admission; nested backend checks never publish separately.
    cmp  eax, AIR_VERDICT_REFUSED
    jne  .return
    mov  edi, r13d                        ; owned decision-local reason/probe bit
    mov  [rel airlock_last_refusal], dil  ; ROOT118959 detail
    call airlock_observe_refusal
.return:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bounded native admission observations, including deliberate boot probes.
; No identity/address/blob bytes and no assertion of attack or EPT isolation.
; Internal prepare/admit/backend helpers do not publish separate attempts.
; Preserve verdict and caller scratch values; concurrent increments cannot wrap.
airlock_note_refusal:
    push rax
    push rcx
    mov  rax, [rel airlock_refused_count]
.retry:
    cmp  rax, -1
    je   .out
    lea  rcx, [rax + 1]
    lock cmpxchg qword [rel airlock_refused_count], rcx
    jne  .retry
.out:
    pop  rcx
    pop  rax
    ret

; Final native refusal custody. EDI=reason1..7 | bit7 boot probe.
; Reasons are ONLY native gate facts, never a decoded backend/manifest guess.
; No principal, blob, key, address, token or later mutable state is retained.
; Concurrent callers may increment totals/enqueue; they NEVER write the spine.
; Try-lock is finite even from an interrupt: busy/full detail is counted lost.
; The existing lifetime total remains the sole Guardian refusal source.
airlock_observe_refusal:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    call airlock_note_refusal
    mov  esi, edi
    and  esi, 0x80
    and  edi, 0x7F
    cmp  edi, 1
    jb   .unknown
    cmp  edi, 7
    jbe  .reason
.unknown:
    mov  edi, 6
.reason:
    or   edi, esi
    mov  r8d, edi
    xor  eax, eax
    mov  ecx, 1
    lock cmpxchg byte [rel airlock_obs_lock], cl
    jne  .drop
    mov  ecx, [rel airlock_obs_pending]
    cmp  ecx, 8
    jae  .full
    add  ecx, [rel airlock_obs_head]
    and  ecx, 7
    lea  rdx, [rel airlock_obs_queue]
    mov  [rdx + rcx * 2], r8w
    inc  dword [rel airlock_obs_pending]
    mov  byte [rel airlock_obs_lock], 0
    jmp  .out
.full:
    mov  byte [rel airlock_obs_lock], 0
.drop:
    mov  rax, [rel airlock_detail_drops]
.retry:
    cmp  rax, -1
    je   .out
    lea  rcx, [rax + 1]
    lock cmpxchg qword [rel airlock_detail_drops], rcx
    jne  .retry
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; BSP idle consumer only. EAX=owned numeric reason,0 empty/busy. No callbacks
; under the try-lock. Publishing is deferred across AUDIT KAT brackets, so an
; earlier pending real refusal survives; native boot/KAT attempts stay honest.
airlock_observation_take:
    xor  eax, eax
    mov  ecx, 1
    lock cmpxchg byte [rel airlock_obs_lock], cl
    jne  .empty
    cmp  dword [rel airlock_obs_pending], 0
    je   .unlock_empty
    mov  ecx, [rel airlock_obs_head]
    lea  rdx, [rel airlock_obs_queue]
    movzx eax, word [rdx + rcx * 2]
    mov  word [rdx + rcx * 2], 0
    inc  ecx
    and  ecx, 7
    mov  [rel airlock_obs_head], ecx
    dec  dword [rel airlock_obs_pending]
    mov  byte [rel airlock_obs_lock], 0
    ret
.unlock_empty:
    mov  byte [rel airlock_obs_lock], 0
.empty:
    xor  eax, eax
    ret

; Only the three shipped descriptor identities are supported. Check identity
; before dereferencing: this is not an arbitrary-code loader. Each tuple must
; match its producer's exact source extent and kind. Publish canonical values,
; not a second descriptor read, under airlock_lock; callers may subsequently
; change the runtime descriptor without changing this run's copy or grading.
airlock_admit_blob:
    lea  rax, [rel air_blob_desc_hostile]
    cmp  rdi, rax
    je   .hostile
    lea  rax, [rel air_blob_desc_benign]
    cmp  rdi, rax
    je   .benign
    lea  rax, [rel air_blob_desc_hang]
    cmp  rdi, rax
    jne  .refused
    lea  rsi, [rel air_blob_hang_code]
    mov  edx, air_blob_hang_len
    mov  ecx, AIR_BLOB_HANG
    jmp  .check
.hostile:
    lea  rsi, [rel air_blob_hostile_code]
    mov  edx, air_blob_hostile_len
    mov  ecx, AIR_BLOB_HOSTILE
    jmp  .check
.benign:
    lea  rsi, [rel air_blob_benign_code]
    mov  edx, air_blob_benign_len
    mov  ecx, AIR_BLOB_BENIGN
.check:
    test edx, edx
    jz   .refused
    cmp  edx, AIR_GUEST_CODE_CAPACITY
    ja   .refused
    mov  rax, rsi
    add  rax, rdx                      ; refuse a wrapping source extent
    jc   .refused
    cmp  [rdi + AIR_BLOB_CODE], rsi
    jne  .refused
    cmp  [rdi + AIR_BLOB_LEN], edx
    jne  .refused
    cmp  [rdi + AIR_BLOB_KIND], ecx
    jne  .refused
    mov  [rel airlock_admitted_blob + AIR_BLOB_CODE], rsi
    mov  [rel airlock_admitted_blob + AIR_BLOB_LEN], edx
    mov  [rel airlock_admitted_blob + AIR_BLOB_KIND], ecx
    mov  eax, 1
    ret
.refused:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; VMX backend (airlock_lock held). Retains Classic's exact safety order:
; validate host state -> fresh VMXON/VMCS/EPT -> mandatory timer -> launch ->
; decode one exit -> VMCLEAR/VMXOFF -> restore CR0/CR4/RFLAGS.
; ---------------------------------------------------------------------------
airlock_vmx_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, HVB_SIZE
    mov  qword [rsp + HVB_ACTIVE], 0
    mov  qword [rsp + HVB_GUARD], 0
    mov  qword [rsp + HVB_REQUEST], 0
    mov  qword [rsp + HVB_LEASE], 0
    mov  qword [rsp + HVB_FRONTIER], 0
    call airlock_admit_blob
    test eax, eax
    jz   .restore_none                 ; no host/VMX/guest/canary effects
    mov  [rel airlock_current_desc], rdi
    mov  dword [rel airlock_last_verdict], AIR_VERDICT_ERROR
    mov  dword [rel airlock_last_exit], -1
    mov  qword [rel airlock_last_gpa], 0
    mov  qword [rel airlock_last_qual], 0
    mov  dword [rel airlock_instr_error], 0
    mov  byte [rel airlock_vmxon_live], 0
    mov  byte [rel airlock_last_stage], 1  ; ROOT118959 detail admitted

    ; E1: a bad host-state field refuses before VMXON, never after VMLAUNCH.
    mov  rdi, rsp
    call hv_validate_host_state
    cmp  qword [rel hv_val_ok], 1
    jne  .restore_none
    mov  byte [rel airlock_last_stage], 2  ; ROOT118959 detail host state valid

    mov  r15, [rel airlock_base]
    ; Preserve the seventeenth host page: clear only VMX/EPT + 64 KiB guest.
    mov  rdi, r15
    xor  esi, esi
    mov  edx, AIR_HOST_PAGE_OFF
    call memset
    mov  ecx, 0x480
    rdmsr
    and  eax, 0x7FFFFFFF
    mov  [r15], eax
    mov  [r15 + AIR_VMCS_OFF], eax
    lea  rax, [r15 + AIR_VMCS_OFF]
    mov  [rel airlock_vmcs_pa], rax

    ; Four-level EPT.  Exactly 16 leaves map GPA 0..0xffff to guest RAM.
    ; AIR_DENIED_GPA (0x10000) is the next, deliberately absent leaf.
    lea  rax, [r15 + AIR_EPT_PDPT_OFF]
    or   rax, HV_EPT_RWX
    mov  [r15 + AIR_EPT_PML4_OFF], rax
    lea  rax, [r15 + AIR_EPT_PD_OFF]
    or   rax, HV_EPT_RWX
    mov  [r15 + AIR_EPT_PDPT_OFF], rax
    lea  rax, [r15 + AIR_EPT_PT_OFF]
    or   rax, HV_EPT_RWX
    mov  [r15 + AIR_EPT_PD_OFF], rax
    lea  rdx, [r15 + AIR_GUEST_RAM_OFF]
    or   rdx, HV_EPT_WB_LEAF
    lea  rdi, [r15 + AIR_EPT_PT_OFF]
    mov  ecx, AIR_GUEST_PAGES
.ept_leaf:
    mov  [rdi], rdx
    add  rdx, 0x1000
    add  rdi, 8
    dec  ecx
    jnz  .ept_leaf
    lea  rax, [r15 + AIR_EPT_PML4_OFF]
    or   rax, HV_EPTP_WB_4LVL
    mov  [rel airlock_eptp], rax

    ; Guest page tables live inside the EPT sandbox and identity-map low 2 MiB.
    lea  rbx, [r15 + AIR_GUEST_RAM_OFF]
    mov  qword [rbx + 0x1000], 0x2003
    mov  qword [rbx + 0x2000], 0x3003
    mov  qword [rbx + 0x3000], 0x83

    ; Use only the admitted tuple, including after API calls and VM-exit.
    lea  rbp, [rel airlock_admitted_blob]
    mov  rsi, [rbp + AIR_BLOB_CODE]
    lea  rdi, [rbx + AIR_GUEST_CODE_GPA]
    mov  edx, [rbp + AIR_BLOB_LEN]
    call memcpy
    cmp  dword [rbp + AIR_BLOB_KIND], AIR_BLOB_BENIGN
    jne  .blob_ready
    lea  rdi, [rbx + AIR_MAILBOX_IN_GPA]
    lea  rsi, [rel airlock_benign_token]
    mov  edx, AIR_CANARY_BYTES
    call memcpy
.blob_ready:

    mov  eax, [rel hv_vmwrite_fails]
    mov  [rel airlock_saved_vmwrites], eax
    mov  dword [rel hv_vmwrite_fails], 0
    pushfq
    pop  rax
    mov  [rel airlock_saved_rflags], rax
    cli
    mov  rdi, rsp
    call hv_boundary_arm
    test rax, rax
    jnz  .guard_refused
    mov  byte [rel airlock_last_stage], 3  ; ROOT118959 detail boundary armed

    ; VMX fixed-bit CR0/CR4 dance, byte-for-byte shape of the proven launcher.
    mov  ecx, 0x486
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax
    mov  ecx, 0x487
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax
    mov  rax, cr0
    mov  [rel airlock_saved_cr0], rax
    or   rax, r12
    and  rax, r13
    mov  cr0, rax
    mov  [rel hv_launch_hcr0], rax
    mov  ecx, 0x488
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax
    mov  ecx, 0x489
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax
    mov  rax, cr4
    mov  [rel airlock_saved_cr4], rax
    or   rax, r12
    and  rax, r13
    mov  cr4, rax
    mov  [rel hv_launch_hcr4], rax

    mov  rax, r15
    mov  [rel airlock_vmxon_pa], rax
    vmxon [rel airlock_vmxon_pa]
    jc   .vmxon_fail
    jz   .vmxon_fail
    mov  byte [rel airlock_vmxon_live], 1
    mov  byte [rel airlock_last_stage], 4  ; ROOT118959 detail VMXON
    vmclear [rel airlock_vmcs_pa]
    jc   .vmcs_fail
    jz   .vmcs_fail
    vmptrld [rel airlock_vmcs_pa]
    jc   .vmcs_fail
    jz   .vmcs_fail
    mov  byte [rel airlock_last_stage], 5  ; ROOT118959 detail VMCS current

    ; Flush reusable EPT context when silicon provides all-context INVEPT.
    mov  ecx, 0x48C
    rdmsr
    bt   eax, 20
    jnc  .no_invept
    bt   eax, 26
    jnc  .no_invept
    mov  qword [rel airlock_invept_desc], 0
    mov  qword [rel airlock_invept_desc + 8], 0
    mov  ecx, 2
    invept rcx, [rel airlock_invept_desc]
.no_invept:
    call airlock_write_controls
    call hv_linux_write_state
    mov  edi, VMXF_G_RSP
    mov  esi, AIR_GUEST_STACK_GPA
    call hv_w
    mov  edi, VMXF_G_RIP
    mov  esi, AIR_GUEST_CODE_GPA
    call hv_w
    cmp  dword [rel hv_vmwrite_fails], 0
    jne  .vmcs_fail

    ; Host landing fields are last and refer to this exact stack frame.
    mov  edi, VMXF_H_RSP
    mov  rsi, rsp
    call hv_w
    mov  edi, VMXF_H_RIP
    lea  rsi, [rel .exit_landing]
    call hv_w
    ; The host landing fields are part of the same VMCS setup transaction.
    ; Never enter a guest after either final write failed.
    cmp  dword [rel hv_vmwrite_fails], 0
    jne  .vmcs_fail
    mov  byte [rel airlock_last_stage], 6  ; ROOT118959 detail VMCS written
    mov  rdi, rsp
    call hv_boundary_enter
    test rax, rax
    jnz  .boundary_refused
    mov  byte [rel airlock_last_stage], 7  ; ROOT118959 detail entry issued
    HV_BOUNDARY_FINAL
    vmlaunch
    mov  edi, VMXF_VMINSTR_ERR
    vmread rax, rdi
    mov  [rel airlock_instr_error], eax
    HV_BOUNDARY_LAND
    mov  rdi, rsp
    call hv_boundary_exit
    jmp  .finish

.exit_landing:
    ; GPRs are guest-owned on VM-exit; use only memory-backed state here.
    HV_BOUNDARY_LAND
    mov  rdi, rsp
    call hv_boundary_exit
    mov rdi,rsp
    mov edx,5
    call hv_boundary_exec_vmx
    mov  byte [rel airlock_last_stage], 8  ; ROOT118959 detail VM-exit landed
    mov  edi, VMXF_EXIT_REASON
    vmread rax, rdi
    test eax, 0x80000000
    jnz  .finish
    and  eax, 0xFFFF
    mov  [rel airlock_last_exit], eax
    cmp  eax, 48
    je   .exit_ept
    cmp  eax, 12
    je   .exit_hlt
    cmp  eax, 52
    je   .exit_timer
    jmp  .finish
.exit_ept:
    mov  edi, VMXF_G_PHYS_ADDR
    vmread rax, rdi
    mov  [rel airlock_last_gpa], rax
    mov  edi, VMXF_EXIT_QUAL
    vmread rax, rdi
    mov  [rel airlock_last_qual], rax
    lea  rdx, [rel airlock_admitted_blob]
    cmp  dword [rdx + AIR_BLOB_KIND], AIR_BLOB_HOSTILE
    jne  .finish
    cmp  qword [rel airlock_last_gpa], AIR_DENIED_GPA
    jne  .finish
    test qword [rel airlock_last_qual], 2       ; qualification bit1 = write
    jz   .finish
    mov  dword [rel airlock_last_verdict], AIR_VERDICT_FAILED_EPT
    jmp  .finish
.exit_hlt:
    lea  rdx, [rel airlock_admitted_blob]
    cmp  dword [rdx + AIR_BLOB_KIND], AIR_BLOB_BENIGN
    jne  .finish
    mov  dword [rel airlock_last_verdict], AIR_VERDICT_OK
    jmp  .finish
.exit_timer:
    lea  rdx, [rel airlock_admitted_blob]
    cmp  dword [rdx + AIR_BLOB_KIND], AIR_BLOB_HANG
    jne  .finish
    mov  dword [rel airlock_last_verdict], AIR_VERDICT_REAPED
    jmp  .finish

.boundary_refused:
    mov  dword [rel airlock_last_verdict], AIR_VERDICT_REFUSED
.finish:
    vmclear [rel airlock_vmcs_pa]
.vmcs_fail:
    cmp  byte [rel airlock_vmxon_live], 1
    jne  .restore
    vmxoff
    mov  byte [rel airlock_vmxon_live], 0
    jmp  .restore
.vmxon_fail:
    mov  dword [rel airlock_last_verdict], AIR_VERDICT_ERROR
.restore:
    mov  eax, [rel hv_vmwrite_fails]  ; ROOT118959 detail
    mov  [rel airlock_last_vmwrites], eax  ; ROOT118959 detail
    mov  rax, [rel airlock_saved_cr0]
    mov  cr0, rax
    mov  rax, [rel airlock_saved_cr4]
    mov  cr4, rax
    mov  rdi, rsp
    call hv_boundary_finish
    push qword [rel airlock_saved_rflags]
    popfq
    mov  eax, [rel airlock_saved_vmwrites]
    mov  [rel hv_vmwrite_fails], eax
    cmp  dword [rel airlock_last_verdict], AIR_VERDICT_OK
    jne  .return_verdict
    mov  rax, [rel airlock_base]
    lea  rsi, [rax + AIR_GUEST_RAM_OFF + AIR_MAILBOX_OUT_GPA]
    lea  rdi, [rel airlock_benign_echo]
    mov  edx, AIR_CANARY_BYTES
    call memcpy
.return_verdict:
    mov  eax, [rel airlock_last_verdict]
    jmp  .out
.restore_none:
    mov  eax, AIR_VERDICT_REFUSED
    jmp  .out
.guard_refused:
    mov  eax, [rel airlock_saved_vmwrites]
    mov  [rel hv_vmwrite_fails], eax
    push qword [rel airlock_saved_rflags]
    popfq
    mov  eax, AIR_VERDICT_REFUSED
.out:
    add  rsp, HVB_SIZE
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

airlock_write_controls:
    ; NMI-exiting + mandatory VMX preemption timer.
    mov  edi, 0x481
    mov  esi, 0x48
    call hv_adjust_ctls
    test eax, 0x40
    jz   .bad
    mov  edi, VMXF_PIN_CTLS
    mov  esi, eax
    call hv_w
    mov  edi, VMXF_PREEMPT_TIMER
    mov  esi, [rel airlock_wd_value]
    call hv_w
    ; HLT exiting + activate secondary controls.
    mov  edi, 0x482
    mov  esi, 0x80000080
    call hv_adjust_ctls
    test eax, 0x80000000
    jz   .bad
    mov  edi, VMXF_PROC_CTLS
    mov  esi, eax
    call hv_w
    ; EPT is the boundary; absence is a hard refusal.
    mov  edi, 0x48B
    mov  esi, 2
    call hv_adjust_ctls
    test eax, 2
    jz   .bad
    mov  edi, VMXF_PROC_CTLS2
    mov  esi, eax
    call hv_w
    mov  edi, VMXF_EPTP
    mov  rsi, [rel airlock_eptp]
    call hv_w
    mov  edi, 0x483
    mov  esi, 0x200
    call hv_adjust_ctls
    mov  edi, VMXF_EXIT_CTLS
    mov  esi, eax
    call hv_w
    mov  edi, 0x484
    mov  esi, 0x200
    call hv_adjust_ctls
    mov  edi, VMXF_ENTRY_CTLS
    mov  esi, eax
    call hv_w
    mov  edi, VMXF_EXC_BITMAP
    mov  esi, 0xFFFFFFFF                 ; guest faults exit to graded FAILED
    call hv_w
    mov  edi, VMXF_PF_MASK
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_PF_MATCH
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_CR3_TARGETS
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_EXIT_MSR_ST
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_EXIT_MSR_LD
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_ENTRY_MSR_LD
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_ENTRY_INTR
    xor  esi, esi
    call hv_w
    mov  edi, VMXF_LINK_PTR
    mov  rsi, -1
    call hv_w
    mov  edi, VMXF_G_DEBUGCTL
    xor  esi, esi
    call hv_w
    ret
.bad:
    inc  dword [rel hv_vmwrite_fails]
    ret

; ---------------------------------------------------------------------------
; Registry projection: five transport-independent typed verbs.  The existing
; command_airlock staging buffer is shared deliberately so UDP framing remains
; one path; these names do not overlap AIRLOCKSTATUS/AIRLOCKFILE.
; ---------------------------------------------------------------------------
airlock_register_verbs:
    lea  rdi, [rel str_verb_airseed]
    lea  rsi, [rel cmd_verb_airseed]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_airhostile]
    lea  rsi, [rel cmd_verb_airhostile]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_aircanary]
    lea  rsi, [rel cmd_verb_aircanary]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_airbenign]
    lea  rsi, [rel cmd_verb_airbenign]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_airhang]
    lea  rsi, [rel cmd_verb_airhang]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    ret

cmd_verb_airseed:
    call cmd_handler_prologue
    push r12
    mov  r12, rsi
    mov  rsi, [rdi + REQ_ARG]
    mov  [rel airlock_seed_arg], rsi
    call airlock_out_reset
    cmp  byte [rel secair_ready], 1
    jne  .refused
    test rsi, rsi
    jz   .badarg
.skip:
    cmp  byte [rsi], ' '
    jne  .seed
    inc  rsi
    jmp  .skip
.seed:
    cmp  byte [rsi], 0
    je   .badarg
    call airlock_lock_acquire
    mov  rdi, [rel airlock_host_page]
    xor  esi, esi
    mov  edx, AIR_CANARY_BYTES
    call memset
    lea  rdi, [rel airlock_canary_shadow]
    xor  esi, esi
    mov  edx, AIR_CANARY_BYTES
    call memset
    mov  rsi, [rel airlock_seed_arg]
    mov  rdi, [rel airlock_host_page]
    mov  edx, AIR_CANARY_BYTES
    call strcpy_s
    mov  [rel airlock_canary_len], eax
    mov  rsi, [rel airlock_host_page]
    lea  rdi, [rel airlock_canary_shadow]
    mov  edx, AIR_CANARY_BYTES
    call memcpy
    call airlock_lock_release
    lea  rdi, [rel str_airseed_ok]
    call airlock_out_str
    mov  rdi, [rel airlock_host_page]
    call airlock_out_str
    jmp  .done
.badarg:
    lea  rdi, [rel str_airseed_bad]
    call airlock_out_str
    mov  qword [r12 + RSP_CODE], CMDE_BADSEL
    jmp  .done
.refused:
    lea  rdi, [rel str_air_refused]
    call airlock_out_str
    mov  qword [r12 + RSP_CODE], CMDE_BADSEL
.done:
    mov  byte [rel airlock_out_ready], 1
    pop  r12
    ret

cmd_verb_airhostile:
    call cmd_handler_prologue
    push r12
    mov  r12, rsi
    call airlock_out_reset
    lea  rdi, [rel air_blob_desc_hostile]
    lea  rsi, [rel air_manifest_untrusted]
    call airlock_run
    cmp  eax, AIR_VERDICT_FAILED_EPT
    jne  .refused
    call airlock_canary_matches
    test eax, eax
    jz   .clobbered
    lea  rdi, [rel str_airhostile_failed]
    call airlock_out_str
    jmp  .done
.clobbered:
    lea  rdi, [rel str_airhostile_clobbered]
    call airlock_out_str
    mov  qword [r12 + RSP_CODE], CMDE_BADSEL
    jmp  .done
.refused:
    lea  rdi, [rel str_airhostile_refused]
    call airlock_out_str
    mov  qword [r12 + RSP_CODE], CMDE_BADSEL
.done:
    mov  byte [rel airlock_out_ready], 1
    pop  r12
    ret

cmd_verb_aircanary:
    call cmd_handler_prologue
    call airlock_out_reset
    lea  rdi, [rel str_aircanary]
    call airlock_out_str
    cmp  byte [rel secair_ready], 1
    jne  .refused
    mov  rdi, [rel airlock_host_page]
    call airlock_out_str
    jmp  .done
.refused:
    lea  rdi, [rel str_air_refused]
    call airlock_out_str
.done:
    mov  byte [rel airlock_out_ready], 1
    ret

cmd_verb_airbenign:
    call cmd_handler_prologue
    push r12
    mov  r12, rsi
    mov  rsi, [rdi + REQ_ARG]
    call airlock_out_reset
    test rsi, rsi
    jz   .input_refused
    lea  rdi, [rel airlock_benign_token]
    mov  edx, AIR_CANARY_BYTES
    call strcpy_s
    test eax, eax
    jz   .input_refused
    lea  rdi, [rel air_blob_desc_benign]
    lea  rsi, [rel air_manifest_untrusted]
    call airlock_run
    cmp  eax, AIR_VERDICT_OK
    jne  .refused
    lea  rdi, [rel airlock_benign_echo]
    lea  rsi, [rel airlock_benign_token]
    call strcmp
    test eax, eax
    jnz  .refused
    lea  rdi, [rel str_airbenign_ok]
    call airlock_out_str
    lea  rdi, [rel airlock_benign_echo]
    call airlock_out_str
    jmp  .done
.input_refused:
    ; Missing/empty token refuses before airlock_run; still one admission.
    mov  edi, 7
    call airlock_observe_refusal
.refused:
    lea  rdi, [rel str_airbenign_refused]
    call airlock_out_str
    mov  qword [r12 + RSP_CODE], CMDE_BADSEL
.done:
    mov  byte [rel airlock_out_ready], 1
    pop  r12
    ret

cmd_verb_airhang:
    call cmd_handler_prologue
    push r12
    mov  r12, rsi
    call airlock_out_reset
    lea  rdi, [rel air_blob_desc_hang]
    lea  rsi, [rel air_manifest_untrusted]
    call airlock_run
    cmp  eax, AIR_VERDICT_REAPED
    jne  .refused
    lea  rdi, [rel str_airhang_reaped]
    call airlock_out_str
    jmp  .done
.refused:
    lea  rdi, [rel str_airhang_refused]
    call airlock_out_str
    mov  qword [r12 + RSP_CODE], CMDE_BADSEL
.done:
    mov  byte [rel airlock_out_ready], 1
    pop  r12
    ret

;; ROOT118959 detail begin
; Boot proof failure detail: one numeric serial line, observation only. It runs
; after the proof verdict and readiness are final and changes neither. Fields are
; the probe verdict, the admission refusal (reason|0x80, 0=not refused), the last
; backend stage reached (0 none,1 admitted,2 host state valid,3 boundary armed,
; 4 VMXON,5 VMCS current,6 VMCS written,7 entry issued,8 VM-exit landed), the
; basic exit reason (ffffffff=none this run), VM-instruction error, failed
; VMWRITEs, and the proof's own 16-byte canary comparison. Exit reason and
; instruction error are this run's only when stage>=1. No address, blob or
; canary byte is emitted.
airlock_proof_detail:
    push rbx
    mov  esi, [rel airlock_boot_verdict]
    lea  rdi, [rel air_det_verdict]
    mov  ecx, 8
    call airlock_hex_put
    movzx esi, byte [rel airlock_last_refusal]
    lea  rdi, [rel air_det_refusal]
    mov  ecx, 2
    call airlock_hex_put
    movzx esi, byte [rel airlock_last_stage]
    lea  rdi, [rel air_det_stage]
    mov  ecx, 2
    call airlock_hex_put
    mov  esi, [rel airlock_last_exit]
    lea  rdi, [rel air_det_exit]
    mov  ecx, 8
    call airlock_hex_put
    mov  esi, [rel airlock_instr_error]
    lea  rdi, [rel air_det_vmerr]
    mov  ecx, 8
    call airlock_hex_put
    mov  esi, [rel airlock_last_vmwrites]
    lea  rdi, [rel air_det_vmwrites]
    mov  ecx, 8
    call airlock_hex_put
    mov  rdi, [rel airlock_host_page]
    lea  rsi, [rel airlock_canary_shadow]
    mov  edx, 16
    call memcmp
    test eax, eax
    setz bl
    add  bl, '0'
    mov  [rel air_det_canary], bl
    lea  rdi, [rel str_air_detail]
    call serial_string
    pop  rbx
    ret

; RDI=field, ESI=value, ECX=hex digits, most significant first.
airlock_hex_put:
    lea  rdi, [rdi + rcx - 1]
    lea  rdx, [rel air_det_hex]
.digit:
    mov  eax, esi
    and  eax, 15
    mov  al, [rdx + rax]
    mov  [rdi], al
    dec  rdi
    shr  esi, 4
    dec  ecx
    jnz  .digit
    ret
;; ROOT118959 detail end

; EAX=1 only when the current host page still equals the seed shadow.
airlock_canary_matches:
    mov  rdi, [rel airlock_host_page]
    lea  rsi, [rel airlock_canary_shadow]
    mov  edx, AIR_CANARY_BYTES
    call memcmp
    test eax, eax
    setz al
    movzx eax, al
    ret

airlock_populate_blob_descriptors:
    lea  rax, [rel air_blob_hostile_code]
    mov  [rel air_blob_desc_hostile + AIR_BLOB_CODE], rax
    lea  rax, [rel air_blob_benign_code]
    mov  [rel air_blob_desc_benign + AIR_BLOB_CODE], rax
    lea  rax, [rel air_blob_hang_code]
    mov  [rel air_blob_desc_hang + AIR_BLOB_CODE], rax
    ret

; CANNED fixtures are source-controlled bytes, never loop-generated at runtime.
%include "sec/canned_blobs/airlock_fixtures.asm"

align 8
air_manifest_untrusted:
    dd AIR_FOOTPRINT_UNTRUSTED | AIR_FOOTPRINT_HOST_BOUND
    db 0
    times AIR_MAN_SIZE - 5 db 0

air_blob_desc_hostile:
    dq 0
    dd air_blob_hostile_len
    dd AIR_BLOB_HOSTILE
air_blob_desc_benign:
    dq 0
    dd air_blob_benign_len
    dd AIR_BLOB_BENIGN
air_blob_desc_hang:
    dq 0
    dd air_blob_hang_len
    dd AIR_BLOB_HANG

align 8
airlock_refused_count:    dq 0             ; lifetime native refusals; never reset by init/KAT
airlock_detail_drops:     dq 0             ; queue busy/full, independent saturating total
airlock_obs_lock:         db 0
align 4
airlock_obs_head:         dd 0
airlock_obs_pending:      dd 0
airlock_obs_queue:        times 8 dw 0      ; bounded numeric reasons ONLY
align 8
airlock_base:             dq 0
airlock_host_page:        dq 0
airlock_current_desc:     dq 0
airlock_admitted_blob:    times AIR_BLOB_SIZE db 0
airlock_vmxon_pa:         dq 0
airlock_vmcs_pa:          dq 0
airlock_eptp:             dq 0
airlock_saved_rflags:     dq 0
airlock_saved_cr0:        dq 0
airlock_saved_cr4:        dq 0
airlock_last_gpa:         dq 0
airlock_last_qual:        dq 0
airlock_invept_desc:      dq 0, 0
airlock_seed_arg:         dq 0
airlock_saved_vmwrites:   dd 0
airlock_wd_value:         dd 0
airlock_last_verdict:     dd AIR_VERDICT_REFUSED
airlock_last_exit:        dd -1
airlock_instr_error:      dd 0
airlock_canary_len:       dd 0
airlock_lock:             db 0
airlock_vmxon_live:       db 0
secair_ready:             db 0
secair_tier_ok:           db 0
secair_deny_ok:           db 0
secair_no_vmx:            db 0
align 8
airlock_canary_shadow:    times AIR_CANARY_BYTES db 0
airlock_benign_token:     times AIR_CANARY_BYTES db 0
airlock_benign_echo:      times AIR_CANARY_BYTES db 0

str_verb_airseed:         db "AIRSEED", 0
str_verb_airhostile:      db "AIRHOSTILE", 0
str_verb_aircanary:       db "AIRCANARY", 0
str_verb_airbenign:       db "AIRBENIGN", 0
str_verb_airhang:         db "AIRHANG", 0
str_airseed_ok:           db " AIRSEED ACK canary=", 0
str_airseed_bad:          db " AIRSEED ERR usage=AIRSEED_<nonce>", 0
str_air_refused:          db " REFUSED reason=no-vmx-ept fail_closed=1", 0
str_airhostile_failed:    db " AIRHOSTILE VERDICT=FAILED reason=ept write=DENIED canary=unchanged", 0
str_airhostile_clobbered: db " AIRHOSTILE VERDICT=ERROR reason=canary-clobbered", 0
str_airhostile_refused:   db " AIRHOSTILE VERDICT=REFUSED reason=no-vmx-ept fail_closed=1", 0
str_aircanary:            db " AIRCANARY canary=", 0
str_airbenign_ok:         db " AIRBENIGN VERDICT=OK echo=", 0
str_airbenign_refused:    db " AIRBENIGN VERDICT=REFUSED reason=airlock-failed", 0
str_airhang_reaped:       db " AIRHANG VERDICT=REAPED reason=preemption-watchdog host=alive", 0
str_airhang_refused:      db " AIRHANG VERDICT=REFUSED reason=no-vmx-ept", 0

str_air_ready: db "[PAOS64] P2 airlock: EPT/paging-domain fence armed [airlock.ready]", 13, 10, 0
str_air_tier:  db "[PAOS64] P2 airlock: capability manifest -> tier select [airlock.tier]", 13, 10, 0
str_air_deny:  db "[PAOS64] P2 airlock: hostile write to host-owned scratch denied by hardware, blob FAILED [airlock.deny]", 13, 10, 0
str_air_no_vmx: db "[PAOS64] P2 airlock: skipped(no-vmx) untrusted execution REFUSED fail-closed", 13, 10, 0
str_air_proof_failed: db "[PAOS64] P2 airlock: hostile-denial selftest failed; untrusted execution REFUSED fail-closed", 13, 10, 0

;; ROOT118959 detail data begin
align 4
airlock_boot_verdict:     dd 0
airlock_last_vmwrites:    dd 0
airlock_last_refusal:     db 0
airlock_last_stage:       db 0
air_det_hex:              db "0123456789abcdef"
str_air_detail:           db "[PAOS64] P2 airlock: proof detail verdict="
air_det_verdict:          db "00000000 refusal="
air_det_refusal:          db "00 stage="
air_det_stage:            db "00 exit="
air_det_exit:             db "00000000 vmerr="
air_det_vmerr:            db "00000000 vmwrites="
air_det_vmwrites:         db "00000000 canary="
air_det_canary:           db "0 [airlock.proof.detail]", 13, 10, 0
;; ROOT118959 detail data end
