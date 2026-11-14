;; MODULE boot/pmod_loader
%include "core/abi/build_profile.inc"
;; LAYER 0
;; EXPORTS pmod_sandbox_call_native, pmod_sandbox_call_native_budget, pmod_sandbox_call_sensitive, pmod_sandbox_call_sensitive_until, pmod_sandbox_call_sensitive_until_fullfit, pmod_call_deadline_strict, pmod_fence_obs_timeouts, pmod_fence_obs_last_late_tsc, pmod_fence_obs_last_cleanup_tsc, pmod_fence_obs_max_late_tsc, pmod_fence_obs_max_cleanup_tsc, pmod_fence_obs_last_mode, pmod_fence_obs_last_tail_tsc, pmod_fence_obs_max_tail_tsc, pmod_call_active, pmod_preload, pmod_init, pmod_udp_try, pmod_status_append, pmod_timer_hooks_bind, pmod_first_active, pmod_second_active, pmod_cap_blocked, pmod_hash_mismatch_blocked, pmod_bad_sig_blocked, pmod_watchdog_blocked, pmod_netmon_bind, pmod_netmon_start, pmod_netmon_query
;; IMPORTS boot/header, boot/paging
;; CAPS
;; OWNER saga:pmod_bundle_seam
;; 1330d: PMOD's temporary LAPIC watchdog ownership returns through the
;; scheduler's complete timer-restore seam; cleanup must never be LVT-only.
; ============================================================================
; Contract 1020 — built-in PMOD/BUNDLE loader.
; Contract 2312 reuses this loader for the external signed netmon form.
; Contract 2312 — external netmon client must earn present/absent media verdicts.
;
; Ordering is fail-closed: read -> hash every member -> Merkle root -> detached
; RSA signature -> PMOD bounds/PIC/reloc validation -> copy -> RX seal -> guarded
; Tier-1 selftest -> export registration.  The keep's canonical handlers remain
; present and first-module degradation rebinds to them; a bad module never owns
; the boot path.  The external HELLO.PMD fixture is read from the boot ESP before
; EBS. Missing or malformed media degrades to the byte-identical built-in
; canonical fixture, so an attacker cannot turn /bundles into a boot dependency.
; ============================================================================

PMOD_REGION_BASE       equ 0x40000000
PMOD_PAGE_FIRST_CODE   equ 1
PMOD_PAGE_FIRST_DATA   equ 2
PMOD_PAGE_SECOND_CODE  equ 4
PMOD_PAGE_SECOND_DATA  equ 5
PMOD_PAGE_WDOG_CODE    equ 7
PMOD_PAGE_SCRATCH      equ 8
PMOD_PAGE_STACK        equ 10
PMOD_PAGE_SIZE         equ 4096
PMOD_FILE_MAX          equ 4096
PMOD_MANIFEST_SIZE     equ 152
PMOD_SIG_SIZE          equ 256
PMOD_FIRST_SIZE        equ 58
PMOD_SECOND_SIZE       equ 82
PMOD_WDOG_VECTOR       equ 0xF2
PMOD_APIC_EOI          equ 0x0B0
PMOD_APIC_LVT_TIMER    equ 0x320
PMOD_TSC_DEADLINE_MSR  equ 0x6E0
PMOD_SENSITIVE_CTX_MAX equ 16384         ; one bounded secret-bearing context per sensitive call
PMOD_SENSITIVE_WINDOW  equ 0x200000      ; sparse module PD entry the sandbox CR3 remaps
PMOD_TIMEOUT_MS        equ 5000          ; every live module call (nonce probe, netmon load/query)
PMOD_DRILL_TIMEOUT_MS  equ 500           ; boot EB-FE negative only (RC-boot-audit-fixes 2(b), rc-sec 20:15)
PMOD_WDOG_REARM_MAX    equ 4             ; early deadline-mode fires re-armed per call (ADL071)
PMOD_SERVICE_VERSION   equ 1
PMOD_PIC_FLAG          equ 1
PMOD_EXPORT_MAX        equ 128
PMOD_EXPORT_SIZE       equ 32

; PMOD v1 native header (64 bytes).  All ranges are relative to file start.
PMH_MAGIC       equ 0
PMH_VERSION     equ 4
PMH_LAYER       equ 6
PMH_CAPS        equ 8
PMH_FLAGS       equ 16
PMH_TOTAL       equ 20
PMH_CODE_OFF    equ 24
PMH_CODE_SIZE   equ 28
PMH_ENTRY_OFF   equ 32
PMH_SELF_OFF    equ 36
PMH_EXPORT_OFF  equ 40
PMH_NRELOC      equ 44
PMH_NEXPORT     equ 46
PMH_NIMPORT     equ 48
PMH_MODULE_ID   equ 52
PMH_SERVICE_VER equ 56
PMH_SIZE        equ 64

; Request/response fields from the one command registry ABI (svc/command.asm
; REQ_*/RSP_*). This file assembles before svc/command.asm, so the layout is
; mirrored here; the deferred WDATA block below asserts every mirror against the
; registry, where both are defined. pmod_req is a whole REQ_SZ envelope: a short
; one let command_dispatch read REQ_SOURCE/REQ_PRINCIPAL out of pmod_rsp.
PM_REQ_VERB equ 0
PM_REQ_CAP  equ 8
PM_REQ_IDEM equ 16
PM_REQ_SEL  equ 24
PM_REQ_ARG  equ 32
PM_REQ_SOURCE equ 40
PM_REQ_PRINCIPAL equ 48
PM_RSP_CODE equ 0
PM_RSP_VAL  equ 24
PM_REQ_SIZE equ 56
PM_RSP_SIZE equ 48
PM_SOURCE_UDP equ 1
PM_AUTH_T_PRINCIPAL equ 48
PM_ARGT_TEXT equ 2

; ---------------------------------------------------------------------------
; pmod_preload — pre-EBS, read \HELLO.PMD from this image's boot FAT volume.
; The bounded buffer is UEFI-owned EfiLoaderData and survives ExitBootServices.
; Failure is a quiet degrade; pmod_init selects the signed canonical fixture.
;  in: boot_services/image_handle live
; out: RAX=0 loaded / -1 absent-or-invalid
; clobbers: caller-saved
; caps: none
; ---------------------------------------------------------------------------
%if !PAOS_PUBLIC_BUILD
pmod_preload:
    ; Preserve the historical HELLO preload; the optional client has a separate
    ; bounded buffer and never falls back to an embedded copy.
    sub rsp, 8
    lea rax, [rel pmod_hello_path]
    mov [rel pmod_read_path], rax
    call pmod_preload_file
    push qword [rel pmod_external_buf]
    push qword [rel pmod_external_size]
    movzx eax, byte [rel pmod_external_seen]
    push rax
    sub rsp, 8
    lea rax, [rel pmod_netmon_path]
    mov [rel pmod_read_path], rax
    call pmod_preload_file
    mov rax, [rel pmod_external_buf]
    mov [rel pmod_nm_buf], rax
    mov rax, [rel pmod_external_size]
    mov [rel pmod_nm_size], rax
    mov al, [rel pmod_external_seen]
    mov [rel pmod_nm_seen], al
    add rsp, 8
    pop rax
    mov [rel pmod_external_seen], al
    pop qword [rel pmod_external_size]
    pop qword [rel pmod_external_buf]
    add rsp, 8
    ret

pmod_preload_file:
    push rbx
    push r12
    ; efi_entry's eight-register frame calls us with entry RSP mod 16 = 0.
    ; Keep firmware pre-call RSP mod 16 = 0 while retaining 32-byte shadow
    ; space plus root.Open's fifth argument at [rsp+32].
    sub  rsp, 48
    mov  byte [rel pmod_external_seen], 0
    mov  qword [rel pmod_external_buf], 0
    mov  qword [rel pmod_external_size], 0
    mov  qword [rel pmod_loaded_image], 0
    mov  qword [rel pmod_simple_fs], 0
    mov  qword [rel pmod_root], 0
    mov  qword [rel pmod_file], 0

    mov  rax, [rel boot_services]
    mov  rcx, [rel image_handle]
    lea  rdx, [rel pmod_loaded_image_guid]
    lea  r8, [rel pmod_loaded_image]
    sub  rsp, 32
    call [rax + 0x98]                    ; HandleProtocol(LoadedImage)
    add  rsp, 32
    test rax, rax
    jnz  .fail
    mov  rbx, [rel pmod_loaded_image]
    mov  rcx, [rbx + 24]                 ; LoadedImage.DeviceHandle
    mov  rax, [rel boot_services]
    lea  rdx, [rel pmod_simple_fs_guid]
    lea  r8, [rel pmod_simple_fs]
    sub  rsp, 32
    call [rax + 0x98]                    ; HandleProtocol(SimpleFileSystem)
    add  rsp, 32
    test rax, rax
    jnz  .fail
    mov  rax, [rel pmod_simple_fs]
    mov  rcx, rax
    lea  rdx, [rel pmod_root]
    sub  rsp, 32
    call [rax + 8]                       ; OpenVolume
    add  rsp, 32
    test rax, rax
    jnz  .fail

    mov  rax, [rel boot_services]
    mov  ecx, 2                          ; EfiLoaderData
    mov  edx, PMOD_FILE_MAX
    lea  r8, [rel pmod_external_buf]
    call [rax + 0x40]                    ; AllocatePool
    test rax, rax
    jnz  .close_root

    mov  rax, [rel pmod_root]
    mov  rcx, rax
    lea  rdx, [rel pmod_file]
    mov  r8, [rel pmod_read_path]
    mov  r9d, 1                          ; EFI_FILE_MODE_READ
    mov  qword [rsp + 32], 0
    call [rax + 8]                       ; root.Open
    test rax, rax
    jnz  .close_root
    mov  byte [rel pmod_external_seen], 2 ; opened but not yet a valid read
    mov  qword [rel pmod_external_size], PMOD_FILE_MAX
    mov  r12, [rel pmod_file]
    mov  rcx, r12
    lea  rdx, [rel pmod_external_size]
    mov  r8, [rel pmod_external_buf]
    sub  rsp, 32
    call [r12 + 32]                      ; file.Read
    add  rsp, 32
    test rax, rax
    jnz  .close_file
    cmp  qword [rel pmod_external_size], 24
    jb   .close_file
    cmp  qword [rel pmod_external_size], PMOD_FILE_MAX
    jae  .close_file                     ; exact max may be truncated; reject
    mov  byte [rel pmod_external_seen], 1
    xor  ebx, ebx
    jmp  .close_file_done
.close_file:
    mov  ebx, -1
.close_file_done:
    mov  rcx, r12
    sub  rsp, 32
    call [r12 + 16]                      ; Close
    add  rsp, 32
    jmp  .close_root_common
.close_root:
    mov  ebx, -1
.close_root_common:
    mov  r12, [rel pmod_root]
    test r12, r12
    jz   .return
    mov  rcx, r12
    sub  rsp, 32
    call [r12 + 16]
    add  rsp, 32
.return:
    movsxd rax, ebx
    add  rsp, 48
    pop  r12
    pop  rbx
    ret
.fail:
    mov  ebx, -1
    jmp  .return

; ---------------------------------------------------------------------------
; Merkle/signature helpers.
; ---------------------------------------------------------------------------

; pmod_hash_member(RDI=data,RDX=len,RSI=expected32) -> RAX=0 match/-1
pmod_hash_member:
    push rbx
    mov  rbx, rsi
    mov  rsi, rdi
    lea  rdi, [rel pmod_hash_tmp]
    call sha256_hash
    test rax, rax
    jnz  .bad
    lea  rdi, [rel pmod_hash_tmp]
    mov  rsi, rbx
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .bad
    xor  eax, eax
    pop  rbx
    ret
.bad:
    mov  rax, -1
    pop  rbx
    ret

; pmod_verify_bundle(RDI=member1 ptr) -> RAX=0 only for all members, root, sig.
; Signature verification is deliberately after the complete Merkle walk.
pmod_verify_bundle:
    push rbx
    push r12
    mov  r12, rdi
    cmp  dword [rel pmod_fixture_manifest], 'PBND'
    jne  .bad
    cmp  word [rel pmod_fixture_manifest + 4], 1
    jne  .bad
    cmp  word [rel pmod_fixture_manifest + 6], 2
    jne  .bad
    cmp  dword [rel pmod_fixture_manifest + 72], PMOD_FIRST_SIZE
    jne  .bad
    cmp  dword [rel pmod_fixture_manifest + 76], 1
    jne  .bad
    cmp  dword [rel pmod_fixture_manifest + 112], PMOD_SECOND_SIZE
    jne  .bad
    cmp  dword [rel pmod_fixture_manifest + 116], 2
    jne  .bad
    mov  rdi, r12
    lea  rsi, [rel pmod_fixture_manifest + 40]
    mov  edx, PMOD_FIRST_SIZE
    call pmod_hash_member
    test rax, rax
    jnz  .bad
    mov  rax, [rel pmod_hash_tmp]
    mov  [rel pmod_merkle_leaves], rax
    mov  rax, [rel pmod_hash_tmp + 8]
    mov  [rel pmod_merkle_leaves + 8], rax
    mov  rax, [rel pmod_hash_tmp + 16]
    mov  [rel pmod_merkle_leaves + 16], rax
    mov  rax, [rel pmod_hash_tmp + 24]
    mov  [rel pmod_merkle_leaves + 24], rax
    lea  rdi, [rel pmod_fixture_nonce]
    lea  rsi, [rel pmod_fixture_manifest + 80]
    mov  edx, PMOD_SECOND_SIZE
    call pmod_hash_member
    test rax, rax
    jnz  .bad
    mov  rax, [rel pmod_hash_tmp]
    mov  [rel pmod_merkle_leaves + 32], rax
    mov  rax, [rel pmod_hash_tmp + 8]
    mov  [rel pmod_merkle_leaves + 40], rax
    mov  rax, [rel pmod_hash_tmp + 16]
    mov  [rel pmod_merkle_leaves + 48], rax
    mov  rax, [rel pmod_hash_tmp + 24]
    mov  [rel pmod_merkle_leaves + 56], rax
    lea  rdi, [rel pmod_root_tmp]
    lea  rsi, [rel pmod_merkle_leaves]
    mov  edx, 64
    call sha256_hash
    test rax, rax
    jnz  .bad
    lea  rdi, [rel pmod_root_tmp]
    lea  rsi, [rel pmod_fixture_manifest + 8]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .bad
    mov  byte [rel pmod_merkle_ok], 1

    lea  rdi, [rel pmod_fixture_signature]
    lea  rsi, [rel pmod_fixture_manifest]
    mov  edx, PMOD_MANIFEST_SIZE
    lea  rcx, [rel pmod_fixture_modulus]
    call rsa2048_verify_sha256
    test eax, eax
    jnz  .bad
    mov  byte [rel pmod_sig_ok], 1
    xor  eax, eax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; Validate native PMOD #2: exhaustive bounds, loadable L3-L5, service-table
; version, no unresolved imports/relocs, one export, and near-PIC byte policy.
pmod_validate_native:
    push rbx
    mov  rbx, rdi
    cmp  dword [rbx + PMH_MAGIC], 'PMOD'
    jne  .bad
    cmp  word [rbx + PMH_VERSION], 1
    jne  .bad
    movzx eax, word [rbx + PMH_LAYER]
    cmp  eax, 3
    jb   .bad
    cmp  eax, 5
    ja   .bad
    cmp  qword [rbx + PMH_CAPS], 0       ; fixture requests no privileged service
    jne  .bad
    cmp  dword [rbx + PMH_FLAGS], PMOD_PIC_FLAG
    jne  .bad
    cmp  dword [rbx + PMH_TOTAL], PMOD_SECOND_SIZE
    jne  .bad
    cmp  dword [rbx + PMH_CODE_OFF], PMH_SIZE
    jne  .bad
    mov  eax, [rbx + PMH_CODE_SIZE]
    test eax, eax
    jz   .bad
    cmp  eax, PMOD_PAGE_SIZE
    ja   .bad
    mov  edx, [rbx + PMH_CODE_OFF]
    add  edx, eax
    jc   .bad
    cmp  edx, [rbx + PMH_TOTAL]
    ja   .bad
    mov  eax, [rbx + PMH_ENTRY_OFF]
    cmp  eax, [rbx + PMH_CODE_SIZE]
    jae  .bad
    mov  eax, [rbx + PMH_SELF_OFF]
    cmp  eax, [rbx + PMH_CODE_SIZE]
    jae  .bad
    cmp  word [rbx + PMH_NRELOC], 0      ; pure-PIC v1: no unconsumed fixups
    jne  .bad
    cmp  word [rbx + PMH_NIMPORT], 0
    jne  .bad
    cmp  word [rbx + PMH_NEXPORT], 1
    jne  .bad
    cmp  dword [rbx + PMH_MODULE_ID], 2
    jne  .bad
    cmp  dword [rbx + PMH_SERVICE_VER], PMOD_SERVICE_VERSION
    jne  .bad
    mov  eax, [rbx + PMH_EXPORT_OFF]
    cmp  eax, [rbx + PMH_TOTAL]
    jae  .bad
    mov  edx, eax
    add  edx, 11                         ; NONCE_ECHO plus NUL must fit in member
    jc   .bad
    cmp  edx, [rbx + PMH_TOTAL]
    ja   .bad
    cmp  dword [rbx + rax], 'NONC'
    jne  .bad
    cmp  dword [rbx + rax + 4], 'E_EC'
    jne  .bad
    cmp  word [rbx + rax + 8], 'HO'
    jne  .bad
    cmp  byte [rbx + rax + 10], 0
    jne  .bad
    ; Conservative PIC classifier: external rel32 control transfers and absolute
    ; moffs are forbidden unless a future format supplies exhaustive relocs.
    mov  esi, [rbx + PMH_CODE_OFF]
    add  rsi, rbx
    mov  ecx, [rbx + PMH_CODE_SIZE]
.scan:
    test ecx, ecx
    jz   .good
    movzx eax, byte [rsi]
    cmp  al, 0xE8
    je   .bad
    cmp  al, 0xE9
    je   .bad
    cmp  al, 0xA0
    jb   .next
    cmp  al, 0xA3
    jbe  .bad
.next:
    inc  rsi
    dec  ecx
    jmp  .scan
.good:
    xor  eax, eax
    pop  rbx
    ret
.bad:
    mov  rax, -1
    pop  rbx
    ret

; pmod_page_seal_rx(EDI=page index) -> RAX=0/-1.  Opcode/bytes are copied
; before the PTE becomes executable; invlpg closes stale writable translations.
pmod_page_seal_rx:
    mov  rax, [rel pmod_pt_addr]
    test rax, rax
    jz   .bad
    mov  ecx, edi
    btr  qword [rax + rcx*8], 1          ; clear RW
    btr  qword [rax + rcx*8], 63         ; clear NX => executable
    mov  rax, [rel pmod_region_base]
    shl  rcx, 12
    add  rax, rcx
    invlpg [rax]
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; ---------------------------------------------------------------------------
; Tier-1 call fence: distinct CR3, guard-paged module window, capability scope,
; recoverable #PF/#GP through core/idt, and a real 5-second TSC-deadline IRQ.
; ---------------------------------------------------------------------------

; Layer 0 owns only the temporary deadline-mode borrower. The Layer-1
; scheduler registers the one complete restore/restart seam after installing
; its LAPIC gates; PMOD retains its proven arm order and cannot reconstruct a
; partial scheduler timer from saved LVT bytes. The restore owner itself queues
; the post-call KAT, so the known-good NONCE_ECHO handler stays byte-for-byte on
; its original reply-staging path.
; pmod_timer_hooks_bind(RDI=restore).
%endif
pmod_timer_hooks_bind:
    mov  [rel pmod_timer_restore_hook], rdi
    ret

; One serial line with the last watchdog exit's timing (after the boot drill;
; metal and twin logs both carry it). Hex fields: mode, late_tsc (signed),
; cleanup_tsc, tsc_khz, timeouts. Observability only. Lab profile only: its one
; caller (the boot drill in pmod_init) and its strings are both lab-only.
%if !PAOS_PUBLIC_BUILD
pmod_fence_obs_print:
    push rdi
    lea  rdi, [rel str_pmod_obs_head]
    call serial_string
    movzx edi, byte [rel pmod_fence_obs_last_mode]
    call serial_hex64
    lea  rdi, [rel str_pmod_obs_late]
    call serial_string
    mov  rdi, [rel pmod_fence_obs_last_late_tsc]
    call serial_hex64
    lea  rdi, [rel str_pmod_obs_clean]
    call serial_string
    mov  rdi, [rel pmod_fence_obs_last_cleanup_tsc]
    call serial_hex64
    lea  rdi, [rel str_pmod_obs_khz]
    call serial_string
    mov  rdi, [rel tsc_khz]
    call serial_hex64
    lea  rdi, [rel str_pmod_obs_n]
    call serial_string
    mov  rdi, [rel pmod_fence_obs_timeouts]
    call serial_hex64
    lea  rdi, [rel str_pmod_obs_crlf]
    call serial_string
    pop  rdi
    ret
%endif

%ifdef PAOS_FENCE_TIMING_PROBE
; DIAGNOSTIC ONLY, never in a product or candidate build. After the boot
; drill: PMOD_PROBE_CALLS EB-FE calls through pmod_sandbox_call_sensitive_until
; with D = now + PMOD_PROBE_D_US (lease 100 ms, so the D cap is the deadline),
; then one [pmod.wdog.probe] line: calls, timeouts, other results, worst
; late/cleanup/tail (TSC ticks, worst of THESE calls), mode, tsc_khz.
PMOD_PROBE_CALLS equ 32
PMOD_PROBE_D_US  equ 2000
pmod_fence_timing_probe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  r12d, r12d                      ; timeouts
    xor  r13d, r13d                      ; other results
    xor  r14d, r14d                      ; worst late
    xor  r15d, r15d                      ; worst cleanup + tail
    mov  qword [rel pmod_probe_last_rc], 0
    mov  ebx, PMOD_PROBE_CALLS
.next:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel time_monotonic_tsc_origin]
    mov  rcx, 1000
    mul  rcx
    div  qword [rel tsc_khz]
    add  rax, PMOD_PROBE_D_US
    mov  r9, rax                          ; D, monotonic us
    mov  rdi, [rel pmod_region_base]
    add  rdi, PMOD_PAGE_WDOG_CODE * PMOD_PAGE_SIZE
    lea  rsi, [rel pmod_probe_ctx]
    mov  edx, 64
    mov  r8d, 100
    call pmod_sandbox_call_sensitive_until
    mov  [rel pmod_probe_last_rc], rax
    cmp  rax, -2
    je   .timed_out
    inc  r13
    jmp  .step
.timed_out:
    inc  r12
    mov  rax, [rel pmod_fence_obs_last_late_tsc]
    cmp  r12, 1
    je   .late_set
    cmp  rax, r14
    jle  .late_ok
.late_set:
    mov  r14, rax
.late_ok:
    mov  rax, [rel pmod_fence_obs_last_cleanup_tsc]
    add  rax, [rel pmod_fence_obs_last_tail_tsc]
    cmp  rax, r15
    jbe  .step
    mov  r15, rax
.step:
    dec  ebx
    jnz  .next
    lea  rdi, [rel str_pmod_probe_head]
    call serial_string
    mov  edi, PMOD_PROBE_CALLS
    call serial_hex64
    lea  rdi, [rel str_pmod_probe_to]
    call serial_string
    mov  rdi, r12
    call serial_hex64
    lea  rdi, [rel str_pmod_probe_other]
    call serial_string
    mov  rdi, r13
    call serial_hex64
    lea  rdi, [rel str_pmod_probe_rc]
    call serial_string
    mov  rdi, [rel pmod_probe_last_rc]
    call serial_hex64
    lea  rdi, [rel str_pmod_obs_late]
    call serial_string
    mov  rdi, r14
    call serial_hex64
    lea  rdi, [rel str_pmod_probe_full]
    call serial_string
    mov  rdi, r15
    call serial_hex64
    lea  rdi, [rel str_pmod_probe_tail]
    call serial_string
    mov  rdi, [rel pmod_fence_obs_max_tail_tsc]
    call serial_hex64
    lea  rdi, [rel str_pmod_probe_mode]
    call serial_string
    movzx edi, byte [rel pmod_fence_obs_last_mode]
    call serial_hex64
    lea  rdi, [rel str_pmod_obs_khz]
    call serial_string
    mov  rdi, [rel tsc_khz]
    call serial_hex64
    lea  rdi, [rel str_pmod_obs_crlf]
    call serial_string
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
%endif

pmod_watchdog_init:
    push rbx
    mov  byte [rel pmod_watchdog_deadline_mode], 0
    mov  byte [rel pmod_watchdog_available], 0
    mov  byte [rel pmod_watchdog_lvt_ok], 0
    mov  byte [rel pmod_watchdog_eoi_ok], 0
    mov  byte [rel pmod_watchdog_timeout_seen], 0
    mov  byte [rel pmod_watchdog_compatible], 0
    mov  eax, 1
    cpuid
    bt   edx, 9                          ; architectural local APIC
    jnc  .bad
    bt   ecx, 24                         ; TSC-deadline timer
    setc byte [rel pmod_watchdog_deadline_mode]
    cmp  qword [rel tsc_khz], 0
    je   .bad
    ; Use the one system LAPIC selector.  In particular, do not infer xAPIC
    ; merely because its legacy MMIO window is identity-mapped.
    call smp_lapic_detect_mode
    mov  al, [rel smp_lapic_mode]
    mov  [rel pmod_watchdog_mode], al
    mov  edi, PMOD_WDOG_VECTOR
    lea  rsi, [rel pmod_watchdog_isr]
    call idt_set_handler
    mov  byte [rel pmod_watchdog_available], 1
    xor  eax, eax
    pop  rbx
    ret
.bad:
    mov  byte [rel pmod_watchdog_available], 0
    mov  rax, -1
    pop  rbx
    ret

align 16
pmod_watchdog_isr:
    ; smp_lapic_write32 clobbers RAX/RCX/RDX/RSI in its xAPIC/x2APIC
    ; backends. Preserve all four before acknowledging the interrupt.  The
    ; CPU's saved RIP is consequently four qwords above this software frame.
    push rax
    push rcx
    push rdx
    push rsi
    mov  esi, PMOD_APIC_EOI
    xor  edx, edx
    call smp_lapic_write32
    jc   .eoi_done                       ; constant offset cannot normally fail
    mov  byte [rel pmod_watchdog_eoi_ok], 1
.eoi_done:
    cmp  byte [rel pmod_watchdog_armed], 1
    jne  .spurious
    ; Every armed IRQ samples the one absolute TSC deadline, in both modes. In
    ; the architectural LAPIC periodic fallback (including TCG) that is the
    ; fence itself; a missing deadline MSR never disables the sandbox's timeout
    ; or permits an unguarded call. In TSC-deadline mode an IRQ before the
    ; deadline is not expiry: Alder Lake erratum ADL071 (No Fix) may raise a
    ; timer interrupt after a non-zero 6E0h write (RCQ-27, root 16:20).
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, [rel pmod_watchdog_deadline]
    jae  .expired
    cmp  byte [rel pmod_watchdog_deadline_mode], 1
    jne  .spurious
    cmp  byte [rel pmod_watchdog_periodic_fallback], 1
    je   .spurious                       ; already sampling on the periodic LVT
    inc  qword [rel pmod_watchdog_early_fires]
    cmp  byte [rel pmod_watchdog_rearms], PMOD_WDOG_REARM_MAX
    jae  .rearm_exhausted
    inc  byte [rel pmod_watchdog_rearms]
    mov  rax, [rel pmod_watchdog_deadline] ; re-arm the SAME deadline
    mov  rdx, rax
    shr  rdx, 32
    mov  ecx, PMOD_TSC_DEADLINE_MSR
    wrmsr
    jmp  .spurious
.rearm_exhausted:
    ; Never hang: stop writing 6E0h and move the fence to the scheduler's
    ; calibrated periodic LVT, as the periodic arm does. Leaving deadline mode
    ; disarms the MSR; every IRQ from here samples the TSC deadline above.
    ; Cleanup still runs the complete scheduler restart. An LVT the backend
    ; refuses cannot be fenced: expire (fail-safe, the call returns -2).
    inc  qword [rel pmod_watchdog_rearm_fallbacks]
    call smp_preempt_init_local
    mov  esi, PMOD_APIC_LVT_TIMER
    mov  edx, PMOD_WDOG_VECTOR | (1 << 17)
    call smp_lapic_write32
    jc   .expired
    mov  byte [rel pmod_watchdog_periodic_fallback], 1
    jmp  .spurious
.expired:
    ; Observability only (ROOT105664): TSC at the expiry decision. RAX/RDX are
    ; the ISR's own saved registers.
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel pmod_fence_obs_expire_tsc], rax
    mov  byte [rel pmod_watchdog_armed], 0
    mov  byte [rel pmod_watchdog_timeout_seen], 1
    mov  rax, [rel pmod_watchdog_recover]
    mov  [rsp + 32], rax                 ; saved RIP after four preserved GPRs
.spurious:
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    iretq

; pmod_sandbox_call(RDI=fn,RSI=arg,RDX=len,RCX=granted_caps)
; -> RAX=0 returned / -1 fault / -2 watchdog / -3 sandbox unavailable /
;    -4 caller's original deadline already reached at arm (sensitive_until only) /
;    -5 whole lease + caller reserve no longer fits before D at arm (fullfit only).
%if !PAOS_PUBLIC_BUILD
pmod_sandbox_call:
    mov  r8d, PMOD_TIMEOUT_MS
    jmp  pmod_sandbox_call_budget

; pmod_init's EB-FE watchdog negative only (RC-boot-audit-fixes 2(b), rc-sec
; 20:15:26). Containment does not depend on the length; live calls keep
; PMOD_TIMEOUT_MS through pmod_sandbox_call.
pmod_sandbox_call_drill:
    mov  r8d, PMOD_DRILL_TIMEOUT_MS
    jmp  pmod_sandbox_call_budget

%endif
; Trusted native app dispatcher only: a short, non-renewable execution lease.
; The entry must not disable interrupts, call host services or hold core locks.
; Existing PMOD callers retain their original five-second budget.
pmod_sandbox_call_native:
    mov  r8d, 20
; Native-only fence clamps its trusted registration-time budget independently.
; R8=milliseconds; no live app may renew this absolute deadline.
pmod_sandbox_call_native_budget:
    test r8, r8
    jz   .bad
    cmp  r8, 100
    ja   .bad
    jmp  pmod_sandbox_call_budget
.bad:
    mov  rax, -3
    ret
pmod_sandbox_call_budget:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8                         ; SysV call alignment; module sees call-like RSP
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    cmp  byte [rel pmod_watchdog_available], 1
    jne  .unavailable
    cmp  qword [rel pmod_sandbox_pml4], 0
    je   .unavailable
    cmp  qword [rel pmod_timer_restore_hook], 0
    je   .unavailable
    cmp  byte [rel pmod_call_active], 0
    jne  .unavailable
    mov  byte [rel pmod_call_active], 1
    mov  [rel pmod_call_budget_ms], r8
    mov  rdi, r15
    call cap_enter_scope
    mov  [rel pmod_call_prev_caps], rax
    mov  rax, cr3
    mov  [rel pmod_call_host_cr3], rax
    mov  [rel pmod_call_host_rsp], rsp
    pushfq
    pop  rax
    mov  [rel pmod_call_host_rflags], rax
    cli                                  ; ownership + CR3 handoff is one boundary
    call smp_bsp_tick_lease_begin        ; RC power I2: the PIT carries timer_ticks through the lease
    lea  rax, [rel .fault]
    mov  [rel diag_fault_recover_rip], rax
    mov  byte [rel diag_fault_expect], 1
    lea  rax, [rel .timeout]
    mov  [rel pmod_watchdog_recover], rax

    ; No interrupt may observe the private CR3 with the possibly-unmapped host
    ; stack. Switch CR3 and RSP as one CLI-bounded transition, then restore the
    ; caller's flags on the dedicated guard-bounded sandbox stack.
    mov  rax, [rel pmod_sandbox_pml4]
    mov  cr3, rax                        ; real Tier-1 CR3 transition
    mov  rsp, [rel pmod_region_base]
    add  rsp, (PMOD_PAGE_STACK + 1) * PMOD_PAGE_SIZE
    ; No abandoned module frame or previous app scratch survives a new entry.
    mov  rdi, rsp
    sub  rdi, PMOD_PAGE_SIZE
    mov  ecx, PMOD_PAGE_SIZE / 8
    xor  eax, eax
    cld
    rep  stosq
    mov  rax, [rel pmod_call_host_rflags]
    push rax
    popfq

    ; Plant the module return address BEFORE arming the deadline. If the IRQ
    ; lands anywhere after arm, both timeout and fault paths restore the exact
    ; host frame rather than trusting an unverified module's current RSP.
    mov  [rel pmod_call_frame_rsp], rsp
    lea  rax, [rel .module_return]
    push rax
    cmp  byte [rel pmod_watchdog_deadline_mode], 1
    jne  .periodic_arm
    ; Preserve the proven PMOD ordering: the sandbox recovery frame exists
    ; before deadline mode is selected or the deadline MSR is armed.
    ; LVT selection, the TSC sample, the caller-D check and the MSR arm are one
    ; IF-masked boundary, as in the periodic arm: no IRQ between the D check
    ; and delivery being armed (review 105547).
    cli
    mov  byte [rel pmod_watchdog_lvt_ok], 0
    mov  esi, PMOD_APIC_LVT_TIMER
    mov  edx, PMOD_WDOG_VECTOR | (2 << 17)
    call smp_lapic_write32
    jc   .arm_failed
    mov  byte [rel pmod_watchdog_lvt_ok], 1
    ; The LAPIC LVT selection must be globally visible before the deadline
    ; MSR arms delivery. MFENCE is the architectural store-ordering boundary
    ; for the xAPIC MMIO backend and remains harmless on the x2APIC MSR path.
    mfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rdx, rax                        ; arm TSC for the caller-D cap
    mov  rcx, [rel tsc_khz]
    imul rcx, [rel pmod_call_budget_ms]
    add  rax, rcx
    call pmod_deadline_cap
    jc   .deadline_passed
    mov  [rel pmod_watchdog_deadline], rax ; the ISR's expiry test in both modes
    mov  byte [rel pmod_watchdog_rearms], 0
    mov  byte [rel pmod_watchdog_periodic_fallback], 0
    mov  ecx, PMOD_TSC_DEADLINE_MSR
    mov  rdx, rax
    shr  rdx, 32
    mov  byte [rel pmod_watchdog_armed], 1
    wrmsr
    ; Armed: run the module with the caller's IF, exactly as before this arm
    ; was masked (the sensitive gate admits only IF=1 callers).
    bt   qword [rel pmod_call_host_rflags], 9
    jnc  .invoke
    sti
.invoke:
    mov  rdi, r13
    mov  rsi, r14
    jmp  r12
.periodic_arm:
    ; Port the scheduler's complete DCR/LVT/initial-count sequence. The
    ; scheduler owns the calibrated reload; PMOD changes only its IRQ owner.
    ; Keep IF masked until all recovery and deadline state is published.
    cli
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rdx, rax                        ; arm TSC for the caller-D cap
    mov  rcx, [rel tsc_khz]
    imul rcx, [rel pmod_call_budget_ms]
    add  rax, rcx
    call pmod_deadline_cap
    jc   .deadline_passed
    mov  [rel pmod_watchdog_deadline], rax
    call smp_preempt_init_local
    mov  esi, PMOD_APIC_LVT_TIMER
    mov  edx, PMOD_WDOG_VECTOR | (1 << 17)
    call smp_lapic_write32
    jc   .arm_failed
    mov  byte [rel pmod_watchdog_lvt_ok], 1
    mov  byte [rel pmod_watchdog_armed], 1
    sti
    jmp  .invoke
.deadline_passed:
    ; The caller's original D was already reached at arm (RCX=0), or the whole
    ; lease plus the full-fit caller's reserve no longer fits before it (RCX=1):
    ; never enter the module, never renew D. Full common cleanup; the
    ; watchdog stays usable.
    mov  byte [rel pmod_call_status], -4
    test ecx, ecx
    jz   .cleanup
    mov  byte [rel pmod_call_status], -5
    jmp  .cleanup
.arm_failed:
    ; Never execute a module when the selected LAPIC backend cannot accept
    ; the lease. The common cleanup still restores every host-owned resource.
    mov  byte [rel pmod_watchdog_available], 0
    mov  byte [rel pmod_call_status], -3
    jmp  .cleanup
.module_return:
    mov  [rel pmod_call_rax], rax
    mov  [rel pmod_call_rdx], rdx
    mov  byte [rel pmod_call_status], 0
    jmp  .cleanup
.timeout:
    mov  rsp, [rel pmod_call_frame_rsp]
    mov  byte [rel pmod_call_status], -2
    jmp  .cleanup
.fault:
    mov  rsp, [rel pmod_call_frame_rsp]
    mov  byte [rel pmod_call_status], -1
.cleanup:
    cli                                  ; untrusted module may have changed IF
    mov  byte [rel pmod_watchdog_armed], 0
    cmp  byte [rel pmod_watchdog_deadline_mode], 1
    jne  .disarmed
    mov  ecx, PMOD_TSC_DEADLINE_MSR      ; disarm before exposing host frame
    xor  eax, eax
    xor  edx, edx
    wrmsr
.disarmed:
    mov  byte [rel diag_fault_expect], 0
    ; Every exit, not only the next entry, zeroes the shared sandbox stack: the
    ; page stays readable through the host identity map after return. It is
    ; mapped at this address only under the sandbox CR3, so wipe before the
    ; switch. IF is masked; nothing below pops from this page again.
    mov  rdi, [rel pmod_region_base]
    add  rdi, PMOD_PAGE_STACK * PMOD_PAGE_SIZE
    mov  ecx, (PMOD_PAGE_SIZE / 8)       ; spelled apart from the entry scrub's mutant anchors
    xor  eax, eax
    cld
    rep stosq
    mov  rax, [rel pmod_call_host_cr3]
    mov  cr3, rax
    mov  rsp, [rel pmod_call_host_rsp]
    cld                                  ; untrusted cell cannot leak DF into keep
    mov  rdi, [rel pmod_call_prev_caps]
    call cap_leave_scope
    ; Return capability ownership before restarting the periodic timer.  The
    ; restore hook runs with IF masked, so a pending first tick cannot observe
    ; PMOD's temporary capability scope or private CR3/stack.
    cmp  byte [rel pmod_watchdog_deadline_mode], 1
    jne  .restore_periodic
    call qword [rel pmod_timer_restore_hook] ; full scheduler DCR/LVT/ICR restart
    jmp  .restored
.restore_periodic:
    ; The deadline-only hook clears MSR 6E0, unavailable on this CPU. Reuse
    ; the scheduler's COMPLETE periodic restart, not an LVT-only restoration.
    call pmod_periodic_restore
.restored:
    call smp_bsp_tick_lease_end          ; RC power I2: back to the BSP LAPIC tick if the restore read back
    call pmod_fence_obs_exit             ; observability only; IF still masked
    mov  byte [rel pmod_call_active], 0
    mov  rax, [rel pmod_call_host_rflags]
    push rax
    popfq
    movsx rax, byte [rel pmod_call_status]
    jmp  .out
.unavailable:
    mov  rax, -3
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Fence timing observability (ROOT105664), called once per completed fence
; call at the end of cleanup: host CR3/stack/capabilities and the scheduler
; timer are restored, IF is still masked, caller RFLAGS not yet restored.
; Every exit stamps the return TSC. A watchdog exit (-2) also records
;   late    = ISR expiry stamp - programmed deadline (the D cap when it applied)
;   cleanup = return stamp - ISR expiry stamp
; signed TSC ticks, last and max, a count, and the timer mode in force (1 TSC
; deadline, 0 periodic, 2 ADL071 periodic fallback). Values are observations,
; not bounds. Clobbers RAX/RCX/RDX only; touches no fence state.
pmod_fence_obs_exit:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel pmod_fence_obs_return_tsc], rax
    mov  byte [rel pmod_fence_obs_stamped], 1   ; this call reached its cleanup stamp
    cmp  byte [rel pmod_call_status], -2
    jne  .done
    inc  qword [rel pmod_fence_obs_timeouts]
    mov  rcx, rax
    sub  rcx, [rel pmod_fence_obs_expire_tsc]
    mov  [rel pmod_fence_obs_last_cleanup_tsc], rcx
    cmp  rcx, [rel pmod_fence_obs_max_cleanup_tsc]
    jle  .cleanup_kept
    mov  [rel pmod_fence_obs_max_cleanup_tsc], rcx
.cleanup_kept:
    mov  rcx, [rel pmod_fence_obs_expire_tsc]
    sub  rcx, [rel pmod_watchdog_deadline]
    mov  [rel pmod_fence_obs_last_late_tsc], rcx
    cmp  qword [rel pmod_fence_obs_timeouts], 1
    je   .late_first
    cmp  rcx, [rel pmod_fence_obs_max_late_tsc]
    jle  .late_kept
.late_first:
    mov  [rel pmod_fence_obs_max_late_tsc], rcx
.late_kept:
    movzx eax, byte [rel pmod_watchdog_deadline_mode]
    cmp  byte [rel pmod_watchdog_periodic_fallback], 0
    je   .mode
    mov  eax, 2
.mode:
    mov  [rel pmod_fence_obs_last_mode], al
.done:
    ret

; Same scheduler restart and measured postconditions as the deadline hook,
; except no access to an unsupported MSR. Never publish an LVT-only success.
pmod_periodic_restore:
    mov  rax, [rel cpu_irq_count]
    mov  [rel smp_timer_irq0_before], rax
    mov  rax, [rel cpu_preempt_count]
    mov  [rel smp_timer_preempt0_before], rax
    mov  byte [rel smp_timer_restore_ok], 0
    call smp_preempt_init_local
    mov  esi, SMP_LAPIC_DIVIDE_CONFIG
    call smp_lapic_read32
    mov  [rel smp_timer_post_dcr], eax
    mov  esi, SMP_LAPIC_LVT_TIMER
    call smp_lapic_read32
    mov  [rel smp_timer_post_lvt], eax
    mov  esi, SMP_LAPIC_INITIAL_COUNT
    call smp_lapic_read32
    mov  [rel smp_timer_post_icr], eax
    mov  esi, SMP_LAPIC_CURRENT_COUNT
    call smp_lapic_read32
    mov  [rel smp_timer_post_current], eax
    inc  dword [rel smp_timer_restore_seq]
    cmp  dword [rel smp_timer_post_dcr], 0x03
    jne  .out
    cmp  dword [rel smp_timer_post_lvt], (1 << 17) | SMP_TIMER_VECTOR
    jne  .out
    mov  eax, [rel smp_timer_initial_count]
    cmp  [rel smp_timer_post_icr], eax
    jne  .out
    mov  byte [rel smp_timer_restore_ok], 1
    call sched_preempt_post_pmod_request
.out:
    ret

; pmod_sandbox_call_sensitive(RDI=trusted entry, RSI=context, RDX=context bytes,
;   R8=lease ms) -> RAX as pmod_sandbox_call_budget; -3 refused untouched.
; Earned admission for secret-bearing trusted compute (SEC 105425): the same BSP
; dispatch context native_app requires (IF=1, logical 0, outside IRQ, idle
; fence, deadline mode or calibrated periodic tick), no capabilities, the
; caller's original 1..100 ms lease (one absolute deadline, never renewed) and
; one bounded, non-wrapping context outside the remapped module window. The
; module receives RDI=context, RSI=bytes. On every return the host FX image is
; restored and caller-saved registers are zeroed; RAX is the status and module
; results stay in pmod_call_rax/rdx. NOT covered: AVX upper halves, the fault
; ring's RIP/CR2 record, and the context itself (its owner wipes it). The fence
; is a compute bound with honest-mistake containment: the sandbox CR3 still
; maps all host memory.
; RAX=lease deadline TSC, RDX=arm TSC -> RAX=min(RAX, caller cap), CF=1 and
; RCX=0 if the cap was already reached. Cap 0 (every non-until caller) changes
; nothing. With a full-fit reserve (fullfit entry only) the whole lease must
; end no later than cap - reserve: then RAX is kept (never shortened), else
; CF=1 and RCX=1. Clobbers RCX. Runs inside the CLI arm boundary.
pmod_deadline_cap:
    mov  rcx, [rel pmod_call_deadline_cap]
    test rcx, rcx
    jz   .keep
    cmp  rdx, rcx
    jae  .passed
    cmp  qword [rel pmod_call_fit_reserve_tsc], 0
    jne  .fullfit
    cmp  rax, rcx
    jbe  .keep
    mov  rax, rcx                       ; never past the caller's original D
.keep:
    clc
    ret
.fullfit:
    sub  rcx, [rel pmod_call_fit_reserve_tsc] ; fit cap = D_tsc - reserve
    jbe  .nofit                         ; reserve >= D_tsc: nothing fits, no underflow
    cmp  rax, rcx
    ja   .nofit                         ; whole lease ends past D - reserve (equality fits)
    clc
    ret
.nofit:
    mov  ecx, 1
    stc
    ret
.passed:
    xor  ecx, ecx
    stc
    ret

pmod_sandbox_call_sensitive:
    xor  r9d, r9d                       ; relative lease only, no caller-D cap
    xor  ecx, ecx                       ; no full-fit reserve
    jmp  pmod_sensitive_gate

; pmod_sandbox_call_sensitive_until(RDI, RSI, RDX, R8 as above, R9=the caller's
;   original absolute deadline D in time_monotonic_now_us units) -> RAX as
;   pmod_sandbox_call_sensitive, or -4 if D was already reached at arm (module
;   not entered). D is converted exactly once: D_tsc = time_monotonic_tsc_origin
;   + floor(D * tsc_khz / 1000), so monotonic(D_tsc) <= D. The arm, inside the
;   existing CLI boundary, uses min(arm + lease, D_tsc); nothing is renewed or
;   rounded up. The cutoff is strict at D only while TSC-deadline delivery holds
;   (pmod_call_deadline_strict=1); periodic sampling may add up to one
;   calibrated tick. IRQ delivery and the cleanup after the cutoff are the
;   caller's reserve to budget.
pmod_sandbox_call_sensitive_until:
    xor  ecx, ecx                       ; no full-fit reserve (RCX is not an argument here)
pmod_sensitive_until_convert:           ; RCX = full-fit reserve TSC, or 0
    test r9, r9
    jz   .refuse
    mov  r10, [rel tsc_khz]
    test r10, r10
    jz   .refuse
    mov  r11, rdx
    mov  rax, r9
    mul  r10                            ; RDX:RAX = D * kHz
    mov  r10d, 1000
    cmp  rdx, r10
    jae  .refuse_rdx                    ; quotient would not fit 64 bits
    div  r10
    add  rax, [rel time_monotonic_tsc_origin]
    jc   .refuse_rdx
    test rax, rax
    jz   .refuse_rdx
    mov  r9, rax                        ; D_tsc, nonzero
    mov  rdx, r11
    jmp  pmod_sensitive_gate
.refuse_rdx:
    mov  rdx, r11
.refuse:
    mov  rax, -3
    ret

; pmod_sandbox_call_sensitive_until_fullfit(RDI, RSI, RDX, RCX=reserve_us,
;   R8, R9 as sensitive_until) -> RAX as sensitive_until, or -5 if at the arm
;   the whole lease plus the reserve no longer fits before D (module not
;   entered; full common cleanup; pmod_call_deadline_strict=0). RCX is the
;   caller's whole post-cutoff service reserve (AV105751/SEC105760): nonzero,
;   converted once, rounded up: reserve_tsc = ceil(reserve_us * tsc_khz / 1000);
;   zero or an overflowing conversion is refused (-3) before admission. The
;   lease range, D conversion and every gate check are sensitive_until's; the
;   lease is never shortened, renewed or widened.
pmod_sandbox_call_sensitive_until_fullfit:
    test rcx, rcx
    jz   .refuse                        ; a zero reserve is refused
    mov  r10, [rel tsc_khz]
    test r10, r10
    jz   .refuse
    mov  r11, rdx
    mov  rax, rcx
    mul  r10                            ; RDX:RAX = reserve_us * kHz
    test rdx, rdx
    jnz  .refuse_rdx
    add  rax, 999                       ; round up to a whole tick
    jc   .refuse_rdx
    xor  edx, edx
    mov  r10d, 1000
    div  r10
    mov  rcx, rax                       ; reserve_tsc >= 1
    mov  rdx, r11
    jmp  pmod_sensitive_until_convert
.refuse_rdx:
    mov  rdx, r11
.refuse:
    mov  rax, -3
    ret

; Shared admission. R9 = D_tsc cap, or 0 for the relative-lease entry.
; RCX = full-fit reserve TSC (fullfit entry), else 0.
pmod_sensitive_gate:
    pushfq
    pop  rax
    test eax, 0x200                     ; IF=1: dispatch context, never IRQ/CLI
    jz   .refuse
    test r8, r8
    jz   .refuse
    cmp  r8, 100
    ja   .refuse
    test rdx, rdx
    jz   .refuse
    cmp  rdx, PMOD_SENSITIVE_CTX_MAX
    ja   .refuse
    test rsi, rsi
    jz   .refuse
    mov  rax, rsi
    add  rax, rdx                       ; exclusive end
    jc   .refuse
    mov  r10, [rel pmod_region_base]
    cmp  rax, r10
    jbe  .ctx_ok                        ; ends at or below the window
    add  r10, PMOD_SENSITIVE_WINDOW
    cmp  rsi, r10
    jb   .refuse                        ; overlaps [base, base+window)
.ctx_ok:
    push rdi
    push rsi
    push rdx
    push r8
    push r9
    push rcx
    sub  rsp, 8                         ; keep the call 16-byte aligned
    call smp_current_logical
    add  rsp, 8
    pop  rcx
    pop  r9
    pop  r8
    pop  rdx
    pop  rsi
    pop  rdi
    test eax, eax
    jnz  .refuse
    cmp  byte [rel cpu_irq_depth], 0    ; BSP slot; logical 0 checked above
    jne  .refuse
    cmp  byte [rel pmod_call_active], 0
    jne  .refuse
    cmp  byte [rel pmod_watchdog_deadline_mode], 1
    je   .admitted
    cmp  byte [rel smp_bsp_tick_calibrated], 1
    jne  .refuse
.admitted:
    fxsave64 [rel pmod_sensitive_host_fx]
    mov  [rel pmod_call_deadline_cap], r9
    mov  byte [rel pmod_fence_obs_stamped], 0   ; observability: set only by this call's cleanup
    mov  [rel pmod_call_fit_reserve_tsc], rcx
    xor  ecx, ecx                       ; no capabilities, whatever the caller held
    sub  rsp, 8
    call pmod_sandbox_call_budget
    add  rsp, 8
    mov  qword [rel pmod_call_deadline_cap], 0
    mov  qword [rel pmod_call_fit_reserve_tsc], 0
    ; Strict only if TSC-deadline delivery held for the whole call.
    xor  ecx, ecx
    cmp  rax, -5
    je   .strict                        ; full-fit refusal: never entered, never strict
    cmp  byte [rel pmod_watchdog_deadline_mode], 1
    jne  .strict
    cmp  byte [rel pmod_watchdog_periodic_fallback], 0
    sete cl
.strict:
    mov  [rel pmod_call_deadline_strict], cl
    fxrstor64 [rel pmod_sensitive_host_fx]
    ; Observability only (ROOT105664/AV105691): the sensitive tail after the
    ; stamped cleanup end (cap clear, strict byte, FXRSTOR). The register
    ; zeroing below and RET are not covered (8 XOR + RET, no memory access).
    ; A budget refusal before cleanup (-3 via .unavailable) has no stamp of
    ; its own: publish nothing rather than measure from an older stamp.
    cmp  byte [rel pmod_fence_obs_stamped], 1
    jne  .tail_skip
    push rax
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [rel pmod_fence_obs_return_tsc]
    mov  [rel pmod_fence_obs_last_tail_tsc], rax
    cmp  rax, [rel pmod_fence_obs_max_tail_tsc]
    jbe  .tail_kept
    mov  [rel pmod_fence_obs_max_tail_tsc], rax
.tail_kept:
    pop  rax
.tail_skip:
    xor  ecx, ecx
    xor  edx, edx
    xor  esi, esi
    xor  edi, edi
    xor  r8d, r8d
    xor  r9d, r9d
    xor  r10d, r10d
    xor  r11d, r11d
    ret
.refuse:
    mov  rax, -3
.refuse_out:
    ret

; pmod_register_export(RDI=name,RSI=entry,RDX=canonical-fallback,ECX=module-id)
; -> RAX=loader export slot / -1. The PMOD service/export registry is exactly
; one 4 KiB page (128 x 32-byte rows), so count validation makes overflow
; impossible. Pointers are populated at runtime, avoiding flat-PE RVA literals.
%if !PAOS_PUBLIC_BUILD
pmod_register_export:
    mov  r10d, [rel pmod_export_count]
    cmp  r10d, PMOD_EXPORT_MAX
    jae  .full
    mov  r11d, r10d
    shl  r11, 5
    lea  rax, [rel pmod_export_table]
    add  rax, r11
    mov  [rax + 0], rdi
    mov  [rax + 8], rsi
    mov  [rax + 16], rdx
    mov  [rax + 24], rcx
    inc  dword [rel pmod_export_count]
    mov  eax, r10d
    ret
.full:
    mov  rax, -1
    ret

; pmod_revert_export(EDI=slot) -> RAX=0/-1. Rebinding is one aligned pointer
; store: new callers immediately enter the canonical keep cell while any frame
; already inside the immutable old RX page can finish safely.
pmod_revert_export:
    cmp  edi, [rel pmod_export_count]
    jae  .bad
    mov  eax, edi
    shl  rax, 5
    lea  rcx, [rel pmod_export_table]
    add  rcx, rax
    mov  rdx, [rcx + 16]
    test rdx, rdx
    jz   .bad
    mov  [rcx + 8], rdx
    mov  qword [rcx + 24], 0
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; Canonical keep implementation for the service-table HELLO ABI.
pmod_canonical_hello_cell:
    lea  rax, [rel str_pmod_canonical_hello]
    mov  edx, str_pmod_canonical_hello_end - str_pmod_canonical_hello - 1
    ret

; ---------------------------------------------------------------------------
; Registry handlers and live UDP bridge.
; ---------------------------------------------------------------------------

pmod_verb_hello:
    call cmd_handler_prologue
    cmp  byte [rel pmod_first_active], 1
    jne  .canonical
    mov  rax, [rel pmod_first_response]
    jmp  .set
.canonical:
    lea  rax, [rel str_pmod_canonical_hello]
.set:
    mov  [rsi + PM_RSP_VAL], rax
    mov  qword [rsi + PM_RSP_CODE], 0
    ret

pmod_verb_nonce:
    push rbx
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov  byte [rel pmod_reply_valid], 0
    mov  r13, rdi
    mov  r14, rsi
    cmp  byte [rel pmod_second_active], 1
    jne  .deny
    mov  rsi, [r13 + PM_REQ_ARG]
    test rsi, rsi
    jz   .deny
    xor  edx, edx
.len:
    cmp  edx, 128
    jae  .deny
    cmp  byte [rsi + rdx], 0
    je   .invoke
    inc  edx
    jmp  .len
.invoke:
    test edx, edx
    jz   .deny
    mov  r15, rsi
    mov  ebx, edx
    mov  rdi, [rel pmod_second_entry]
    xor  ecx, ecx
    call pmod_sandbox_call
    test rax, rax
    jnz  .deny
    cmp  [rel pmod_call_rax], r15
    jne  .deny
    cmp  [rel pmod_call_rdx], rbx
    jne  .deny
    mov  [rel pmod_nonce_reply_ptr], r15
    mov  [rel pmod_nonce_reply_len], ebx
    mov  [r14 + PM_RSP_VAL], r15
    mov  qword [r14 + PM_RSP_CODE], 0
    mov  byte [rel pmod_reply_valid], 1
    mov  byte [rel pmod_measure_nonce_ok], 1
    jmp  .out
.deny:
    mov  qword [r14 + PM_RSP_CODE], 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; pmod_udp_try — called before ordinary UDP registry lookup.
;  :9998 NONCE_ECHO is dispatched THROUGH command_dispatch, then replies only if
; the loaded native export returned the exact pointer+length. :9997 exposes the
; negative capability receipt. RAX=1 consumed / 0 fall through-or-drop.
pmod_udp_try:
    cmp  byte [rel udp_pmod_ingress], 1
    jne  .core_port
    cmp  byte [rel pmod_second_active], 1
    jne  .miss
    mov  rdi, r12
    lea  rsi, [rel str_pmod_nonce_verb]
    call strcmp
    test rax, rax
    jnz  .miss
    mov  byte [rel pmod_reply_valid], 0
    ; Fill the whole envelope. The source is this UDP datagram and the principal
    ; is the one its envelope verified (udp_auth_ticket: zero/NONE when unsigned),
    ; as the registry route builds udp_req. Never OWNER for arriving on the LAN.
    mov  eax, [rel pmod_nonce_verb_id]
    mov  [rel pmod_req + PM_REQ_VERB], rax
    mov  qword [rel pmod_req + PM_REQ_CAP], 0
    mov  qword [rel pmod_req + PM_REQ_IDEM], 0
    mov  qword [rel pmod_req + PM_REQ_SEL], 0
    mov  [rel pmod_req + PM_REQ_ARG], r13
    mov  qword [rel pmod_req + PM_REQ_SOURCE], PM_SOURCE_UDP
    mov  rax, [rel udp_auth_ticket + PM_AUTH_T_PRINCIPAL]
    mov  [rel pmod_req + PM_REQ_PRINCIPAL], rax
    lea  rdi, [rel pmod_req]
    lea  rsi, [rel pmod_rsp]
    call command_dispatch
    cmp  byte [rel pmod_reply_valid], 1
    jne  .miss
    mov  rax, [rel pmod_nonce_reply_ptr]
    mov  [rel udp_arg_ptr], rax
    mov  eax, 1
    ret
.core_port:
    mov  rdi, r12
    lea  rsi, [rel str_pmod_cap_test]
    call strcmp
    test rax, rax
    jnz  .miss
    mov  rdi, PMCAP_BLOCK_WRITE
    call cap_check_gate
    cmp  rax, -1
    jne  .miss
    mov  byte [rel pmod_cap_blocked], 1
    mov  byte [rel pmod_out_ready], 1
    mov  eax, 1
    ret
.miss:
    xor  eax, eax
    ret

; pmod_status_append — early bounded STATUS projection. Also consumes
; the one-shot CAP_TEST_BLOCKED staged receipt. Accept both plain STATUS and
; STATUS <nonce>, so the deploy rail can retain a fresh, candidate-bound Trial
; receipt before its intentional confirmed-boot reconciliation.
pmod_status_append:
    cmp  byte [rel pmod_out_ready], 1
    jne  .status
    lea  rdi, [rel str_pmod_cap_reply]
    call udp_put_str
    mov  byte [rel pmod_out_ready], 0
.status:
    cmp  dword [rel udp_line], 'STAT'
    jne  .out
    cmp  word [rel udp_line + 4], 'US'
    jne  .out
    cmp  byte [rel udp_line + 6], 0
    je   .emit
    cmp  byte [rel udp_line + 6], ' '
    jne  .out
.emit:
    lea rdi, [rel pmod_nm_status_active]
    call udp_put_str
    movzx edi, byte [rel pmod_nm_active]
    call udp_put_dec
    lea rdi, [rel pmod_nm_status_generation]
    call udp_put_str
    mov rdi, [rel pmod_nm_generation]
    call udp_put_dec
    lea rdi, [rel pmod_nm_status_slot]
    call udp_put_str
    mov edi, [rel pmod_nm_verb]
    call udp_put_dec
    lea rdi, [rel pmod_nm_status_stage]
    call udp_put_str
    movzx edi, byte [rel pmod_nm_stage]
    call udp_put_dec
    cmp  byte [rel pmod_loader_ok], 1
    jne  .failed
    cmp  byte [rel pmod_watchdog_compatible], 1
    jne  .failed
    cmp  byte [rel pmod_watchdog_available], 1
    jne  .failed
    cmp  byte [rel smp_timer_restore_ok], 1
    jne  .failed
    lea  rdi, [rel str_pmod_status]
    call udp_put_str
    cmp  byte [rel pmod_watchdog_mode], 1
    je   .x2apic
    lea  rdi, [rel str_pmod_watchdog_xapic]
    jmp  .watchdog_mode
.x2apic:
    lea  rdi, [rel str_pmod_watchdog_x2apic]
.watchdog_mode:
    call udp_put_str
    lea  rdi, [rel str_pmod_watchdog_proof]
    call udp_put_str
    jmp  .out
.failed:
    lea  rdi, [rel str_pmod_fail_stage]
    call udp_put_str
    movzx edi, byte [rel pmod_init_stage]
    call udp_put_dec
.out:
    ret

; ---------------------------------------------------------------------------
; pmod_init — verify, sandbox, integrate two distinct PMODs, exercise negative
; cases, then degrade #1 to canonical and prove #2 survives.
; ---------------------------------------------------------------------------
pmod_init:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cld
    mov  byte [rel pmod_init_stage], 1
    cmp  qword [rel pmod_region_base], PMOD_REGION_BASE
    jne  .fail
    cmp  qword [rel pmod_region_phys], 0
    je   .fail
    cmp  qword [rel pmod_pt_addr], 0
    je   .fail
    cmp  qword [rel pmod_sandbox_pml4], 0
    je   .fail
    mov  byte [rel pmod_init_stage], 2
    call pmod_watchdog_init
    test rax, rax
    jnz  .fail
    mov  byte [rel pmod_init_stage], 3

    ; Prefer the external ESP member only if it byte-hashes to the signed leaf.
    lea  r12, [rel pmod_fixture_diag]
    cmp  byte [rel pmod_external_seen], 1
    jne  .source_ready
    cmp  qword [rel pmod_external_size], PMOD_FIRST_SIZE
    jne  .external_bad
    mov  rdi, [rel pmod_external_buf]
    lea  rsi, [rel pmod_fixture_manifest + 40]
    mov  edx, PMOD_FIRST_SIZE
    call pmod_hash_member
    test rax, rax
    jnz  .external_bad
    mov  r12, [rel pmod_external_buf]
    mov  byte [rel pmod_external_accepted], 1
    jmp  .source_ready
.external_bad:
    mov  byte [rel pmod_hash_mismatch_blocked], 1
.source_ready:
    mov  rdi, r12
    call pmod_verify_bundle
    test rax, rax
    jnz  .fail
    mov  byte [rel pmod_init_stage], 4

    ; Negative Merkle member: flip one byte in an owned copy; must reject.
    lea  rdi, [rel pmod_negative_buf]
    mov  rsi, r12
    mov  ecx, PMOD_FIRST_SIZE
    rep  movsb
    xor  byte [rel pmod_negative_buf + 24], 1
    lea  rdi, [rel pmod_negative_buf]
    lea  rsi, [rel pmod_fixture_manifest + 40]
    mov  edx, PMOD_FIRST_SIZE
    call pmod_hash_member
    test rax, rax
    jz   .fail
    mov  byte [rel pmod_hash_mismatch_blocked], 1
    ; Negative signature: corrupt a copy and require strict RSA rejection.
    lea  rdi, [rel pmod_bad_sig_buf]
    lea  rsi, [rel pmod_fixture_signature]
    mov  ecx, PMOD_SIG_SIZE
    rep  movsb
    xor  byte [rel pmod_bad_sig_buf], 1
    lea  rdi, [rel pmod_bad_sig_buf]
    lea  rsi, [rel pmod_fixture_manifest]
    mov  edx, PMOD_MANIFEST_SIZE
    lea  rcx, [rel pmod_fixture_modulus]
    call rsa2048_verify_sha256
    test eax, eax
    jz   .fail
    mov  byte [rel pmod_bad_sig_blocked], 1

    call capability_selftest
    test rax, rax
    jnz  .fail
    mov  byte [rel pmod_cap_blocked], 1
    mov  byte [rel pmod_init_stage], 5

    ; PMOD #1: legacy declarative v1 fixture from FAT/embedded canonical.
    cmp  dword [r12], 'PMOD'
    jne  .fail
    cmp  word [r12 + 4], 1
    jne  .fail
    cmp  word [r12 + 6], 5
    jne  .fail
    cmp  word [r12 + 8], 1
    jne  .fail
    cmp  dword [r12 + 12], 24
    jne  .fail
    cmp  dword [r12 + 16], 30
    jne  .fail
    cmp  dword [r12 + 20], PMOD_FIRST_SIZE
    jne  .fail
    ; Copy the signed declarative member into its RW+NX data page. A small,
    ; trusted format adapter is loaded into the paired code page; its bytes are
    ; deliberately different from native PMOD #2's body.
    mov  rdi, [rel pmod_region_phys]
    add  rdi, PMOD_PAGE_FIRST_DATA * PMOD_PAGE_SIZE
    mov  rsi, r12
    mov  ecx, PMOD_FIRST_SIZE
    rep  movsb
    mov  r12, [rel pmod_region_phys]
    add  r12, PMOD_PAGE_FIRST_DATA * PMOD_PAGE_SIZE
    mov  rdi, [rel pmod_region_phys]
    add  rdi, PMOD_PAGE_FIRST_CODE * PMOD_PAGE_SIZE
    lea  rsi, [rel pmod_legacy_adapter_code]
    mov  ecx, pmod_legacy_adapter_code_end - pmod_legacy_adapter_code
    rep  movsb
    mov  edi, PMOD_PAGE_FIRST_CODE
    call pmod_page_seal_rx
    test rax, rax
    jnz  .fail
    mov  rax, [rel pmod_region_base]
    add  rax, PMOD_PAGE_FIRST_CODE * PMOD_PAGE_SIZE
    mov  [rel pmod_first_entry], rax
    lea  rax, [r12 + 30]
    mov  [rel pmod_first_response], rax
    mov  byte [rel pmod_first_active], 1
    lea  rdi, [rel str_pmod_hello_verb]
    lea  rsi, [rel pmod_verb_hello]
    xor  edx, edx
    mov  ecx, PM_ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    cmp  eax, -1
    je   .fail
    mov  [rel pmod_hello_verb_id], eax
    lea  rdi, [rel str_pmod_hello_verb]
    mov  rsi, [rel pmod_first_entry]
    lea  rdx, [rel pmod_canonical_hello_cell]
    mov  ecx, 1
    call pmod_register_export
    cmp  rax, -1
    je   .fail
    mov  [rel pmod_first_export_slot], eax
    mov  byte [rel pmod_first_load_ok], 1
    lea  rdi, [rel pmod_first_response]
    mov  rdi, [rdi]
    lea  rsi, [rel str_pmod_hello_expect]
    call strcmp
    test rax, rax
    jnz  .fail
    mov  rdi, [rel pmod_first_response]
    call strlen
    mov  r14, rax
    mov  rdi, [rel pmod_first_entry]
    mov  rsi, [rel pmod_region_base]
    add  rsi, PMOD_PAGE_FIRST_DATA * PMOD_PAGE_SIZE + 30
    mov  rdx, r14
    xor  ecx, ecx
    call pmod_sandbox_call
    test rax, rax
    jnz  .fail
    mov  rax, [rel pmod_region_base]
    add  rax, PMOD_PAGE_FIRST_DATA * PMOD_PAGE_SIZE + 30
    cmp  [rel pmod_call_rax], rax
    jne  .fail
    cmp  [rel pmod_call_rdx], r14
    jne  .fail
    mov  byte [rel pmod_first_selftest_ok], 1
    mov  byte [rel pmod_init_stage], 6

    ; PMOD #2: distinct native pure-PIC nonce export.
    lea  rdi, [rel pmod_fixture_nonce]
    call pmod_validate_native
    test rax, rax
    jnz  .fail
    mov  rdi, [rel pmod_region_phys]
    add  rdi, PMOD_PAGE_SECOND_DATA * PMOD_PAGE_SIZE
    lea  rsi, [rel pmod_fixture_nonce]
    mov  ecx, PMOD_SECOND_SIZE
    rep  movsb
    mov  r13, [rel pmod_region_phys]
    add  r13, PMOD_PAGE_SECOND_DATA * PMOD_PAGE_SIZE
    mov  rdi, [rel pmod_region_phys]
    add  rdi, PMOD_PAGE_SECOND_CODE * PMOD_PAGE_SIZE
    lea  rsi, [r13 + PMH_SIZE]
    mov  ecx, 7
    rep  movsb
    mov  edi, PMOD_PAGE_SECOND_CODE
    call pmod_page_seal_rx
    test rax, rax
    jnz  .fail
    mov  rax, [rel pmod_region_base]
    add  rax, PMOD_PAGE_SECOND_CODE * PMOD_PAGE_SIZE
    mov  [rel pmod_second_entry], rax

    ; Per-verb selftest uses a fresh TSC-derived 128-bit token and the same
    ; sandbox call used by live packets; compare pointer, length, and bytes.
    rdtsc
    mov  [rel pmod_nonce_kat], eax
    mov  [rel pmod_nonce_kat + 4], edx
    not  eax
    xor  edx, 0x504D4F44
    mov  [rel pmod_nonce_kat + 8], eax
    mov  [rel pmod_nonce_kat + 12], edx
    mov  rdi, [rel pmod_second_entry]
    lea  rsi, [rel pmod_nonce_kat]
    mov  edx, 16
    xor  ecx, ecx
    call pmod_sandbox_call
    test rax, rax
    jnz  .fail
    lea  rax, [rel pmod_nonce_kat]
    cmp  [rel pmod_call_rax], rax
    jne  .fail
    cmp  qword [rel pmod_call_rdx], 16
    jne  .fail
    mov  byte [rel pmod_second_selftest_ok], 1
    mov  byte [rel pmod_measure_nonce_ok], 1

    lea  rdi, [rel str_pmod_nonce_verb]
    lea  rsi, [rel pmod_verb_nonce]
    xor  edx, edx
    mov  ecx, PM_ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    cmp  eax, -1
    je   .fail
    mov  [rel pmod_nonce_verb_id], eax
    lea  rdi, [rel str_pmod_nonce_verb]
    mov  rsi, [rel pmod_second_entry]
    xor  edx, edx                       ; no canonical nonce export
    mov  ecx, 2
    call pmod_register_export
    cmp  rax, -1
    je   .fail
    mov  byte [rel pmod_second_active], 1
    mov  byte [rel pmod_second_load_ok], 1
    mov  byte [rel pmod_init_stage], 7

    ; Guard-page negative: a four-byte cell dereferences module-window page 0,
    ; which is deliberately non-present. core/idt must convert the real #PF to
    ; a denied selftest result and resume the keep through the armed fault trap.
    mov  rdi, [rel pmod_region_phys]
    add  rdi, PMOD_PAGE_SCRATCH * PMOD_PAGE_SIZE
    mov  dword [rdi], 0xC3078B48         ; mov rax,[rdi] ; ret
    mov  edi, PMOD_PAGE_SCRATCH
    call pmod_page_seal_rx
    test rax, rax
    jnz  .fail
    mov  rdi, [rel pmod_region_base]
    add  rdi, PMOD_PAGE_SCRATCH * PMOD_PAGE_SIZE
    mov  rsi, [rel pmod_region_base]     ; page 0 is the leading guard
    xor  edx, edx
    xor  ecx, ecx
    call pmod_sandbox_call
    cmp  rax, -1
    jne  .fail
    mov  byte [rel pmod_fault_blocked], 1
    mov  byte [rel pmod_init_stage], 8

    ; Real watchdog negative: execute EB FE in a separate RX page. The deadline
    ; IRQ must redirect out after PMOD_DRILL_TIMEOUT_MS; returning normally or
    ; hanging is failure. Containment does not depend on the length (rc-sec
    ; 20:15:26); live module calls keep PMOD_TIMEOUT_MS.
    mov  rdi, [rel pmod_region_phys]
    add  rdi, PMOD_PAGE_WDOG_CODE * PMOD_PAGE_SIZE
    mov  word [rdi], 0xFEEB
    mov  edi, PMOD_PAGE_WDOG_CODE
    call pmod_page_seal_rx
    test rax, rax
    jnz  .fail
    mov  rdi, [rel pmod_region_base]
    add  rdi, PMOD_PAGE_WDOG_CODE * PMOD_PAGE_SIZE
    xor  esi, esi
    xor  edx, edx
    xor  ecx, ecx
    call pmod_sandbox_call_drill
    cmp  rax, -2
    jne  .fail
    cmp  byte [rel pmod_watchdog_timeout_seen], 1
    jne  .fail
    cmp  byte [rel pmod_watchdog_lvt_ok], 1
    jne  .fail
    cmp  byte [rel pmod_watchdog_eoi_ok], 1
    jne  .fail
    cmp  byte [rel smp_timer_restore_ok], 1
    jne  .fail
    mov  byte [rel pmod_watchdog_blocked], 1
    mov  byte [rel pmod_watchdog_compatible], 1
    mov  byte [rel pmod_init_stage], 9
    call pmod_fence_obs_print            ; the drill's late/cleanup timing, observability only
%ifdef PAOS_FENCE_TIMING_PROBE
    call pmod_fence_timing_probe         ; DIAGNOSTIC build only (ROOT105664 twin measurement)
%endif

    ; Measure-and-revert: remove #1's authority and rebind its registry handler
    ; to canonical ROM behavior. PMOD #2 remains registered and active. Its
    ; post-revert survival proof is the stronger acceptance operation: the live
    ; :9998 probe supplies an unpredictable nonce and pmod_verb_nonce invokes
    ; this same sandbox path before it can echo the bytes. Repeating that call
    ; here with the boot KAT token adds no evidence and couples installation to
    ; the just-fired negative watchdog's timer state.
    mov  edi, [rel pmod_first_export_slot]
    call pmod_revert_export
    test rax, rax
    jnz  .fail
    mov  byte [rel pmod_first_active], 0
    mov  byte [rel pmod_first_reverted], 1
    mov  byte [rel pmod_init_stage], 10

    ; All public markers are earned only after the positive and negative
    ; paths above completed without a keep crash.
    mov  byte [rel pmod_loader_ok], 1
    mov  byte [rel pmod_init_stage], 255
    lea  rdi, [rel str_pmod_loader_ok]
    call serial_string
    lea  rdi, [rel str_pmod_merkle_ok]
    call serial_string
    lea  rdi, [rel str_pmod_sig_ok]
    call serial_string
    lea  rdi, [rel str_pmod_sandbox_ok]
    call serial_string
    lea  rdi, [rel str_pmod_first_load]
    call serial_string
    lea  rdi, [rel str_pmod_first_test]
    call serial_string
    lea  rdi, [rel str_pmod_second_load]
    call serial_string
    lea  rdi, [rel str_pmod_second_test]
    call serial_string
    lea  rdi, [rel str_pmod_nonce_ok]
    call serial_string
    lea  rdi, [rel str_pmod_negative_ok]
    call serial_string
    lea  rdi, [rel str_pmod_watchdog_compatible]
    call serial_string
    xor  eax, eax
    jmp  .out
.fail:
    mov  byte [rel pmod_loader_ok], 0
    mov  byte [rel pmod_watchdog_compatible], 0
    mov  byte [rel pmod_first_active], 0
    mov  byte [rel pmod_second_active], 0
    lea  rdi, [rel str_pmod_fail]
    call serial_string
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; State and signed fixture bundle.
; ---------------------------------------------------------------------------
%endif
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state below is deferred to the page-isolated WDATA region (core/abi/wdata.inc):
; stores to it never land in a page that holds translated code (TCG SMC slow path).
%macro WDATA_pmod_loader 0
align 8
%if !PAOS_PUBLIC_BUILD
pmod_external_buf:      dq 0
pmod_external_size:     dq 0
pmod_loaded_image:      dq 0
pmod_simple_fs:         dq 0
pmod_root:              dq 0
pmod_file:              dq 0
pmod_first_response:    dq 0
pmod_first_entry:       dq 0
pmod_second_entry:      dq 0
pmod_nonce_reply_ptr:   dq 0
pmod_nonce_reply_len:   dq 0
%endif
pmod_call_budget_ms:    dq PMOD_TIMEOUT_MS
pmod_call_active:       db 0
align 8
pmod_call_rax:          dq 0
pmod_call_rdx:          dq 0
pmod_call_host_cr3:     dq 0
pmod_call_host_rsp:     dq 0
pmod_call_host_rflags:  dq 0
pmod_call_prev_caps:    dq 0
pmod_call_frame_rsp:    dq 0
pmod_watchdog_recover:  dq 0
pmod_watchdog_deadline: dq 0
pmod_watchdog_early_fires: dq 0         ; deadline-mode IRQs before the deadline (ADL071), never expiry
pmod_watchdog_rearm_fallbacks: dq 0     ; calls whose re-arms ran out and moved to the periodic LVT
; Fence timing observability (ROOT105664); see pmod_fence_obs_exit.
pmod_fence_obs_expire_tsc:       dq 0    ; ISR expiry decision TSC
pmod_fence_obs_return_tsc:       dq 0    ; end-of-cleanup TSC, every exit
pmod_fence_obs_timeouts:         dq 0    ; -2 exits recorded
pmod_fence_obs_last_late_tsc:    dq 0    ; signed: expiry - programmed deadline
pmod_fence_obs_last_cleanup_tsc: dq 0    ; return - expiry
pmod_fence_obs_max_late_tsc:     dq 0
pmod_fence_obs_max_cleanup_tsc:  dq 0
pmod_fence_obs_last_tail_tsc:    dq 0    ; sensitive entries: return - cleanup end
pmod_fence_obs_max_tail_tsc:     dq 0
pmod_fence_obs_last_mode:        db 0    ; 1 TSC deadline, 0 periodic, 2 ADL071 fallback
pmod_fence_obs_stamped:          db 0    ; 1 once the current sensitive call's cleanup stamped
pmod_timer_restore_hook:  dq 0
align 16
pmod_sensitive_host_fx:   times 512 db 0 ; host FX image across one sensitive call
pmod_call_deadline_cap:   dq 0           ; this sensitive_until call's D_tsc, else 0
pmod_call_fit_reserve_tsc: dq 0          ; this fullfit call's reserve TSC, else 0
pmod_call_deadline_strict: db 0          ; last sensitive call kept TSC-deadline delivery
%if !PAOS_PUBLIC_BUILD
pmod_hello_verb_id:     dd -1
pmod_nonce_verb_id:     dd -1
pmod_first_export_slot: dd -1
pmod_export_count:      dd 0
pmod_loader_ok:         db 0
pmod_init_stage:        db 0
pmod_merkle_ok:         db 0
pmod_sig_ok:            db 0
pmod_first_load_ok:     db 0
pmod_first_selftest_ok: db 0
pmod_second_load_ok:    db 0
pmod_second_selftest_ok: db 0
pmod_measure_nonce_ok:  db 0
pmod_first_active:      db 0
pmod_second_active:     db 0
pmod_first_reverted:    db 0
pmod_external_seen:     db 0
pmod_external_accepted: db 0
%endif
pmod_watchdog_available: db 0
pmod_watchdog_armed:    db 0
pmod_watchdog_mode:     db 0             ; copied from the system LAPIC selector
pmod_watchdog_deadline_mode: db 0       ; CPUID capability, never a QEMU override
pmod_watchdog_rearms:   db 0             ; this call's early-fire re-arms (<= PMOD_WDOG_REARM_MAX)
pmod_watchdog_periodic_fallback: db 0   ; this call's fence moved to the periodic LVT
pmod_watchdog_lvt_ok:   db 0
pmod_watchdog_eoi_ok:   db 0
pmod_watchdog_timeout_seen: db 0
pmod_watchdog_compatible: db 0
pmod_call_status:       db 0
%if !PAOS_PUBLIC_BUILD
pmod_reply_valid:       db 0
pmod_out_ready:         db 0
pmod_cap_blocked:       db 0
pmod_hash_mismatch_blocked: db 0
pmod_bad_sig_blocked:   db 0
pmod_watchdog_blocked:  db 0
pmod_fault_blocked:     db 0
align 16
pmod_hash_tmp:          times 32 db 0
pmod_root_tmp:          times 32 db 0
pmod_merkle_leaves:     times 64 db 0
pmod_negative_buf:      times PMOD_FIRST_SIZE db 0
pmod_bad_sig_buf:       times PMOD_SIG_SIZE db 0
pmod_nonce_kat:         times 16 db 0
pmod_req:               times PM_REQ_SIZE db 0
pmod_rsp:               times PM_RSP_SIZE db 0
%if PM_REQ_SIZE != REQ_SZ || PM_RSP_SIZE != RSP_SZ || PM_REQ_VERB != REQ_VERB || PM_REQ_CAP != REQ_CAP || PM_REQ_IDEM != REQ_IDEM || PM_REQ_SEL != REQ_SEL || PM_REQ_ARG != REQ_ARG || PM_REQ_SOURCE != REQ_SOURCE || PM_REQ_PRINCIPAL != REQ_PRINCIPAL || PM_RSP_CODE != RSP_CODE || PM_RSP_VAL != RSP_VAL || PM_SOURCE_UDP != CMD_SOURCE_UDP || PM_AUTH_T_PRINCIPAL != AUTH_T_PRINCIPAL
%error "pmod_loader: PM_* request/response mirror drifted from the command registry ABI"
%endif
%endif
%endmacro
WDATA_DEFER WDATA_pmod_loader

align 4096
%if !PAOS_PUBLIC_BUILD
pmod_export_table:      times (PMOD_EXPORT_MAX * PMOD_EXPORT_SIZE) db 0

pmod_loaded_image_guid:
    dd 0x5B1B31A1
    dw 0x9562, 0x11D2
    db 0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B
pmod_simple_fs_guid:
    dd 0x964E5B22
    dw 0x6459, 0x11D2
    db 0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B
pmod_hello_path: dw '\','H','E','L','L','O','.','P','M','D',0

str_pmod_hello_verb: db "HELLO",0
str_pmod_nonce_verb: db "NONCE_ECHO",0
str_pmod_cap_test: db "CAP_TEST_BLOCKED",0
str_pmod_hello_expect: db "ok=1 pmod=loaded verb=HELLO",0
str_pmod_canonical_hello: db "ok=1 pmod=canonical verb=HELLO",0
str_pmod_canonical_hello_end:
str_pmod_cap_reply: db " denied_by_cap default_mask_zero=1 no_module_execution_tested=1",0
str_pmod_status: db " pmod.loader.ok pmod.bundle.merkle.ok pmod.verify.sig.ok pmod.sandbox.tier1.ok pmod.1st.load.ok pmod.1st.selftest.pass pmod.2nd.load.ok pmod.2nd.selftest.pass pmod.measure.nonce.ok pmod.first=reverted pmod.second=active pmod.hash.mismatch=blocked pmod.sig.bad=blocked pmod.watchdog=blocked pmod.cap=blocked pmod.guard_pf=blocked pmod.fail.stage=0",0
str_pmod_watchdog_xapic: db " pmod.watchdog.apic_mode=xapic pmod.watchdog.lvt_backend=mmio pmod.watchdog.eoi_backend=mmio",0
str_pmod_watchdog_x2apic: db " pmod.watchdog.apic_mode=x2apic pmod.watchdog.lvt_backend=msr pmod.watchdog.eoi_backend=msr",0
str_pmod_watchdog_proof: db " pmod.watchdog.mode.compatible pmod.watchdog.delivery=earned pmod.watchdog.recovery=restored pmod.watchdog.frame=redirected pmod.watchdog.cleanup=restored",0
str_pmod_fail_stage: db " pmod.fail.stage=",0

str_pmod_loader_ok: db "[PAOS64] PMOD loader initialized [pmod.loader.ok]",13,10,0
str_pmod_merkle_ok: db "[PAOS64] PMOD bundle Merkle tree verified [pmod.bundle.merkle.ok]",13,10,0
str_pmod_sig_ok: db "[PAOS64] PMOD manifest signature verified [pmod.verify.sig.ok]",13,10,0
str_pmod_sandbox_ok: db "[PAOS64] PMOD Tier-1 sandbox selftest passed [pmod.sandbox.tier1.ok]",13,10,0
str_pmod_first_load: db "[PAOS64] first PMOD loaded and integrated [pmod.1st.load.ok]",13,10,0
str_pmod_obs_head:  db "[PAOS64] PMOD watchdog timing [pmod.wdog.timing] mode=",0
str_pmod_obs_late:  db " late_tsc=",0
str_pmod_obs_clean: db " cleanup_tsc=",0
str_pmod_obs_khz:   db " tsc_khz=",0
str_pmod_obs_n:     db " timeouts=",0
str_pmod_obs_crlf:  db 13,10,0
%ifdef PAOS_FENCE_TIMING_PROBE
str_pmod_probe_head:  db "[PAOS64] DIAGNOSTIC fence probe [pmod.wdog.probe] calls=",0
str_pmod_probe_to:    db " timeouts=",0
str_pmod_probe_other: db " other=",0
str_pmod_probe_rc:    db " last_rc=",0
str_pmod_probe_full:  db " cleanup_tail_tsc=",0
str_pmod_probe_tail:  db " tail_max_tsc=",0
str_pmod_probe_mode:  db " mode=",0
align 16
pmod_probe_ctx:       times 64 db 0
pmod_probe_last_rc:   dq 0
%endif
str_pmod_first_test: db "[PAOS64] first PMOD capability selftest passed [pmod.1st.selftest.pass]",13,10,0
str_pmod_second_load: db "[PAOS64] second PMOD loaded and integrated [pmod.2nd.load.ok]",13,10,0
str_pmod_second_test: db "[PAOS64] second PMOD nonce selftest passed [pmod.2nd.selftest.pass]",13,10,0
str_pmod_nonce_ok: db "[PAOS64] second PMOD exact nonce round-trip passed [pmod.measure.nonce.ok]",13,10,0
str_pmod_negative_ok: db "[PAOS64] PMOD negatives: cap/hash/sig/watchdog blocked; first reverted; second survived",13,10,0
str_pmod_watchdog_compatible: db "[PAOS64] pmod: watchdog APIC-mode compatibility KAT PASS [pmod.watchdog.mode.compatible]",13,10,0
str_pmod_fail: db "[PAOS64] PMOD loader: degraded (canonical keep retained)",13,10,0

; Trusted compatibility adapter for the signed legacy data-only PMOD.
; mov rax,rdi ; mov edx,esi ; ret (byte-distinct from native PMOD #2).
pmod_legacy_adapter_code:
    db 0x48,0x89,0xF8,0x89,0xF2,0xC3
pmod_legacy_adapter_code_end:

; PMOD #1 exactly matches run_regression_check.py::make_pmod_blob().
pmod_fixture_diag:
    db 0x50,0x4d,0x4f,0x44,0x01,0x00,0x05,0x00,0x01,0x00,0x00,0x00,0x18,0x00,0x00,0x00
    db 0x1e,0x00,0x00,0x00,0x3a,0x00,0x00,0x00,0x48,0x45,0x4c,0x4c,0x4f,0x00,0x6f,0x6b
    db 0x3d,0x31,0x20,0x70,0x6d,0x6f,0x64,0x3d,0x6c,0x6f,0x61,0x64,0x65,0x64,0x20,0x76
    db 0x65,0x72,0x62,0x3d,0x48,0x45,0x4c,0x4c,0x4f,0x00

; PMOD #2 is a DIFFERENT native module. Code = mov rax,rdi; mov rdx,rsi; ret.
pmod_fixture_nonce:
    db 0x50,0x4d,0x4f,0x44,0x01,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    db 0x01,0x00,0x00,0x00,0x52,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x07,0x00,0x00,0x00
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x47,0x00,0x00,0x00,0x00,0x00,0x01,0x00
    db 0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    db 0x48,0x89,0xf8,0x48,0x89,0xf2,0xc3,0x4e,0x4f,0x4e,0x43,0x45,0x5f,0x45,0x43,0x48
    db 0x4f,0x00

; PBND v1: root=SHA256(member_hash_1||member_hash_2), exact sizes/IDs, key ID.
pmod_fixture_manifest:
    db 0x50,0x42,0x4e,0x44,0x01,0x00,0x02,0x00,0xcb,0xf1,0x72,0x3d,0xe0,0x53,0x6f,0x55
    db 0xfe,0x7b,0x19,0x49,0x0f,0x80,0x7c,0x33,0x1d,0xbb,0xdc,0xba,0x18,0xeb,0x71,0x0c
    db 0xc4,0xb0,0x34,0x61,0xd7,0x14,0x26,0x56,0x60,0x01,0xfb,0xd5,0x73,0x85,0x27,0xc7
    db 0x7b,0x09,0x1c,0x2b,0x14,0xf0,0x3b,0xc3,0xf5,0x31,0x49,0xe2,0x97,0x61,0x32,0x6d
    db 0xeb,0x21,0xca,0x8f,0xa5,0xa2,0x66,0x4e,0x3a,0x00,0x00,0x00,0x01,0x00,0x00,0x00
    db 0x87,0x2a,0xe1,0x7a,0x59,0xae,0xdf,0xc5,0x52,0x81,0x04,0x6b,0x6d,0x63,0xaa,0x06
    db 0x78,0x69,0xc3,0x08,0x9b,0xfd,0x56,0xab,0x19,0x93,0xd0,0x5d,0xf6,0x14,0xcc,0xb7
    db 0x52,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x9b,0x7e,0xf9,0xc5,0xef,0xd0,0x8d,0xbe
    db 0x5e,0xf0,0xc5,0x16,0xe1,0xe5,0x0b,0xdb,0x49,0x8e,0xd8,0xce,0x9f,0x28,0x66,0xc2
    db 0x96,0x89,0x00,0x7d,0xcd,0x22,0xab,0x3e

pmod_fixture_signature:
    db 0x83,0x22,0xe3,0xa8,0x32,0x03,0xd9,0xae,0xe6,0x46,0x44,0x57,0x72,0x72,0x3f,0xce
    db 0xb3,0x13,0xbc,0xd6,0xc4,0x2d,0x9a,0x11,0x5a,0x8e,0x73,0x9a,0x23,0x62,0x39,0x7e
    db 0xf7,0x3b,0x2a,0x41,0x76,0x4e,0x45,0xfd,0x5c,0xbf,0xcd,0xf5,0x40,0xc9,0xf4,0x1c
    db 0x4b,0xbd,0x33,0x6c,0xcb,0x66,0xe9,0x0d,0x49,0x84,0x4d,0x7d,0xff,0x64,0xa7,0xf6
    db 0xcd,0x04,0xe4,0xa3,0xd6,0xd9,0xe8,0x2d,0xb8,0x60,0x72,0x5a,0xd2,0x19,0x6c,0xd5
    db 0x16,0x74,0xae,0x8d,0x66,0x6c,0x2d,0x9a,0xa6,0xdc,0x2c,0x2e,0xc0,0x1e,0x47,0x7e
    db 0x66,0x07,0x79,0xfd,0xfd,0x1a,0x78,0x28,0xe3,0x36,0xc4,0xc3,0x75,0x44,0xf8,0xdc
    db 0x85,0x39,0xab,0x69,0xd4,0xe8,0x90,0x2c,0x34,0xd1,0x27,0xd6,0x50,0x0b,0xd8,0xf8
    db 0x50,0xa2,0x29,0xb4,0xfc,0x7c,0x25,0x94,0xcc,0x02,0x56,0x96,0xc7,0xa3,0x00,0x45
    db 0xc2,0xb3,0xa4,0x2a,0xa0,0x58,0xd2,0xae,0x87,0xb4,0xff,0xc1,0xcc,0xfb,0x0c,0xca
    db 0xe1,0xfb,0x29,0x82,0x2e,0x91,0xfe,0xcb,0x7d,0xe5,0x0d,0xed,0xa9,0x42,0x88,0x0f
    db 0xb1,0xee,0xc8,0x4e,0x0e,0x10,0x17,0xae,0x11,0x23,0x74,0x31,0x18,0x93,0xf1,0x8d
    db 0x37,0x1b,0x8b,0x46,0xd3,0xe8,0x85,0x63,0x71,0xdb,0xb8,0x1a,0x86,0xf0,0xe8,0xb2
    db 0xe0,0xfc,0x65,0x5f,0x7c,0x80,0x0b,0x3d,0xb3,0xd9,0xd7,0xcb,0xe9,0x19,0xfd,0xdb
    db 0xef,0xff,0xeb,0x97,0x9f,0x6f,0x0b,0x4e,0xce,0xbc,0xfa,0xc0,0xd3,0x5a,0x35,0xb9
    db 0x62,0x9c,0x95,0xa6,0x2f,0x1b,0x53,0x53,0x63,0x56,0xaa,0x25,0xb2,0xd3,0x7d,0xa6

; Test-bundle public modulus, little-endian as required by the proven verifier.
; This key authenticates only the compiled contract fixture; it is not an owner
; deployment key and no private material is present in the keep. It is
; STRUCTURED and Fermat-factorable (closure NEW-2), so anyone can sign for it:
; a known-answer fixture over in-image bytes only, never an admission anchor.
; gauntlet_v2/tools/kat_anchor_lint.py (make lint) pins every use.
pmod_fixture_modulus:                   ; kat-only-anchor
    db 0x93,0x07,0x77,0xd7,0x81,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    times 112 db 0
    db 0xad,0x96,0x1c,0x18
    times 123 db 0
    db 0x90

; ---------------------------------------------------------------------------
; 2312 optional client. Pages 12/13 come from the existing 16-page PMOD arena;
; 11 and 14 remain guards. Releasing clears PTEs and backing, then reload reuses
; the same reservation. No heap allocation accumulates across hot swaps.
PMOD_NM_CODE equ 12
PMOD_NM_DATA equ 13
PMOD_NM_MEMBER equ 368
PMOD_NM_ID equ 2312

; L6 supplies bounded form lifetime and transport-neutral snapshot/reply seams.
%endif
%if !PAOS_PUBLIC_BUILD
pmod_netmon_bind:
    mov [rel pmod_nm_form_bind], rdi
    mov [rel pmod_nm_form_unbind], rsi
    mov [rel pmod_nm_snapshot], rdx
    mov [rel pmod_nm_reply], rcx
    ret

pmod_netmon_start:
    lea rdi, [rel pmod_nm_ctl_name]
    lea rsi, [rel pmod_nm_control]
    xor edx, edx
    mov ecx, PM_ARGT_TEXT
    xor r8d, r8d
    mov r9d, 1
    call command_register_verb
    call pmod_watchdog_init
    call pmod_netmon_load
    test eax, eax
    jz .out
    lea rdi, [rel pmod_nm_stage_marker]
    call serial_string
    movzx edi, byte [rel pmod_nm_stage]
    call serial_hex64
    lea rdi, [rel pmod_nm_stage_end]
    call serial_string
    cmp byte [rel pmod_nm_seen], 0
    jne .refused
    lea rdi, [rel pmod_nm_absent_marker]
    call serial_string
    jmp .out
.refused:
    lea rdi, [rel pmod_nm_refused_marker]
    call serial_string
.out:
    ret

; PBND one-member specialization, same hash/Merkle/RSA order as 1020.
; All metadata is signed; native header authorizes zero capabilities only.
pmod_netmon_verify:
    push rbx
    push r12
    push r13
    mov byte [rel pmod_nm_stage], 2
    mov r12, [rel pmod_nm_buf]
    cmp byte [rel pmod_nm_seen], 1
    jne .bad
    test r12, r12
    jz .bad
    mov r13, [rel pmod_nm_size]
    cmp r13, PMOD_NM_MEMBER+64
    jb .bad
    cmp r13, PMOD_FILE_MAX
    jae .bad
    cmp dword [r12], 'PBND'
    jne .bad
    cmp dword [r12+4], 0x00010001
    jne .bad
    sub r13, PMOD_NM_MEMBER
    cmp [r12+72], r13d
    jne .bad
    cmp dword [r12+76], PMOD_NM_ID
    jne .bad
    lea rdi, [r12+80]
    lea rsi, [rel pmod_netmon_keyid]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [r12+PMOD_NM_MEMBER]
    lea rsi, [r12+40]
    mov rdx, r13
    mov byte [rel pmod_nm_stage], 3
    call pmod_hash_member
    test eax, eax
    jnz .bad
    lea rdi, [rel pmod_root_tmp]
    lea rsi, [rel pmod_hash_tmp]
    mov edx, 32
    call sha256_hash
    test eax, eax
    jnz .bad
    lea rdi, [rel pmod_root_tmp]
    lea rsi, [r12+8]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [r12+112]
    mov rsi, r12
    mov edx, 112
    lea rcx, [rel pmod_netmon_modulus]
    mov byte [rel pmod_nm_stage], 4
    call rsa2048_verify_sha256
    test eax, eax
    jnz .bad
    lea rbx, [r12+PMOD_NM_MEMBER]
    mov byte [rel pmod_nm_stage], 5
    cmp dword [rbx], 'PMOD'
    jne .bad
    cmp dword [rbx+4], 0x00050001
    jne .bad
    cmp qword [rbx+PMH_CAPS], 0
    jne .bad
    cmp dword [rbx+PMH_FLAGS], PMOD_PIC_FLAG
    jne .bad
    cmp [rbx+PMH_TOTAL], r13d
    jne .bad
    cmp dword [rbx+PMH_CODE_OFF], PMH_SIZE
    jne .bad
    mov eax, r13d
    sub eax, PMH_SIZE
    cmp [rbx+PMH_CODE_SIZE], eax
    jne .bad
    cmp [rbx+PMH_ENTRY_OFF], eax
    jae .bad
    cmp [rbx+PMH_SELF_OFF], eax
    jae .bad
    cmp dword [rbx+PMH_NRELOC], 0x00010000
    jne .bad
    cmp dword [rbx+PMH_NIMPORT], 0
    jne .bad
    cmp dword [rbx+PMH_MODULE_ID], PMOD_NM_ID
    jne .bad
    cmp dword [rbx+PMH_SERVICE_VER], PMOD_SERVICE_VERSION
    jne .bad
    cmp dword [rbx+60], 0
    jne .bad
    mov eax, [rbx+PMH_EXPORT_OFF]
    cmp eax, PMH_SIZE
    jb .bad
    mov edx, eax
    add edx, 20
    jc .bad
    cmp edx, r13d
    ja .bad
    cmp dword [rbx+rax], 'NETM'
    jne .bad
    cmp dword [rbx+rax+4], 'ON_S'
    jne .bad
    cmp dword [rbx+rax+8], 0x00544154
    jne .bad
    mov edx, [rbx+rax+12]
    mov ecx, [rbx+rax+16]
    cmp edx, PMH_SIZE
    jb .bad
    test ecx, ecx
    jz .bad
    cmp ecx, 1536
    jae .bad
    add edx, ecx
    jc .bad
    cmp edx, r13d
    jne .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r13
    pop r12
    pop rbx
    ret

pmod_netmon_load:
    push rbx
    push r12
    mov byte [rel pmod_nm_stage], 1
    cmp byte [rel pmod_nm_active], 1
    je .ok
    cmp qword [rel pmod_region_phys], 0
    je .bad
    cmp qword [rel pmod_pt_addr], 0
    je .bad
    cmp qword [rel pmod_nm_form_bind], 0
    je .bad
    call pmod_netmon_verify
    test eax, eax
    jnz .bad
    mov r12, [rel pmod_nm_buf]
    add r12, PMOD_NM_MEMBER
    mov rbx, [rel pmod_region_phys]
    add rbx, PMOD_NM_CODE*PMOD_PAGE_SIZE
    mov rdi, rbx
    xor eax, eax
    mov ecx, 2*PMOD_PAGE_SIZE/8
    rep stosq
    mov rdi, rbx
    mov rsi, r12
    mov ecx, [r12+PMH_TOTAL]
    rep movsb
    mov rdx, [rel pmod_pt_addr]
    mov rax, rbx
    or rax, 3
    bts rax, 63
    mov [rdx+PMOD_NM_CODE*8], rax
    add rax, PMOD_PAGE_SIZE
    mov [rdx+PMOD_NM_DATA*8], rax
    mov rax, PMOD_REGION_BASE+PMOD_NM_CODE*PMOD_PAGE_SIZE
    invlpg [rax]
    add rax, PMOD_PAGE_SIZE
    invlpg [rax]
    mov edi, PMOD_NM_CODE
    mov byte [rel pmod_nm_stage], 6
    call pmod_page_seal_rx
    test eax, eax
    jnz .release
    mov edi, [r12+PMH_SELF_OFF]
    add rdi, PMOD_REGION_BASE+PMOD_NM_CODE*PMOD_PAGE_SIZE+PMH_SIZE
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    mov byte [rel pmod_nm_stage], 7
    call pmod_sandbox_call
    test eax, eax
    jnz .release
    cmp qword [rel pmod_call_rax], PMOD_NM_ID
    jne .release
    ; Verified entry is needed by the form linter's module-owned binding
    ; parser. It is private until bind + registry publication both succeed.
    mov eax, [r12+PMH_ENTRY_OFF]
    add rax, PMOD_REGION_BASE+PMOD_NM_CODE*PMOD_PAGE_SIZE+PMH_SIZE
    mov [rel pmod_nm_entry], rax
    mov edi, 3                         ; every reload starts at fresh counters
    xor esi, esi
    call pmod_netmon_query
    test rax, rax
    jz .release
    mov eax, [r12+PMH_EXPORT_OFF]
    mov edi, [r12+rax+12]
    add rdi, rbx
    mov esi, [r12+rax+16]
    mov byte [rel pmod_nm_stage], 8
    call qword [rel pmod_nm_form_bind]
    test eax, eax
    jnz .release
    lea rdi, [rel pmod_nm_verb_name]
    lea rsi, [rel pmod_nm_invoke]
    xor edx, edx
    mov ecx, PM_ARGT_TEXT
    xor r8d, r8d
    xor r9d, r9d
    mov byte [rel pmod_nm_stage], 9
    call command_register_verb
    cmp eax, -1
    je .unbind
    mov [rel pmod_nm_verb], eax
    mov eax, [r12+PMH_ENTRY_OFF]
    add rax, PMOD_REGION_BASE+PMOD_NM_CODE*PMOD_PAGE_SIZE+PMH_SIZE
    mov [rel pmod_nm_entry], rax
    mov byte [rel pmod_nm_active], 1
    mov byte [rel pmod_nm_stage], 0
    inc qword [rel pmod_nm_generation]
    lea rdi, [rel pmod_nm_loaded_marker]
    call serial_string
    lea rdi, [rel pmod_nm_catalog_marker]
    call serial_string
.ok:
    xor eax, eax
    jmp .out
.unbind:
    call qword [rel pmod_nm_form_unbind]
.release:
    call pmod_netmon_release
.bad:
    mov eax, -1
.out:
    pop r12
    pop rbx
    ret

pmod_netmon_unload:
    cmp byte [rel pmod_nm_busy], 0
    jne .bad
    cmp byte [rel pmod_nm_active], 0
    je .ok
    mov edi, [rel pmod_nm_verb]
    lea rsi, [rel pmod_nm_invoke]
    call command_unregister_verb
    test eax, eax
    jnz .bad
    call qword [rel pmod_nm_form_unbind]
    mov byte [rel pmod_nm_active], 0
    mov dword [rel pmod_nm_verb], -1
    jmp pmod_netmon_release
.ok:
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

pmod_netmon_release:
    mov rdx, [rel pmod_pt_addr]
    mov qword [rdx+PMOD_NM_CODE*8], 0
    mov qword [rdx+PMOD_NM_DATA*8], 0
    mov rax, PMOD_REGION_BASE+PMOD_NM_CODE*PMOD_PAGE_SIZE
    invlpg [rax]
    add rax, PMOD_PAGE_SIZE
    invlpg [rax]
    mov rdi, [rel pmod_region_phys]
    add rdi, PMOD_NM_CODE*PMOD_PAGE_SIZE
    xor eax, eax
    mov ecx, 2*PMOD_PAGE_SIZE/8
    rep stosq
    mov qword [rel pmod_nm_entry], 0
    ret

; Registry handler -> bounded scratch -> existing Tier-1 call -> bounded reply.
; A nonce in the UDP envelope alone is not proof: the module also formats nonce=
; into its own output, which is what the external observer must check.
pmod_nm_invoke:
    call cmd_handler_prologue
    push rbx
    mov rbx, rsi
    mov rsi, [rdi+PM_REQ_ARG]
    xor edi, edi
    call pmod_netmon_query
    test rax, rax
    jz .deny
    mov rdi, rax
    call qword [rel pmod_nm_reply]
    mov qword [rbx+PM_RSP_CODE], 0
    pop rbx
    ret
.deny:
    mov qword [rbx+PM_RSP_CODE], 5
    pop rbx
    ret

; One bounded data-only call for both the verb and the form's live bindings.
; EDI=operation 0..5, RSI=optional token (op 5: two-qword widget snapshot).
; RAX=host reply pointer / 0 on refusal, RDX/RCX=RX/TX rates,
; R8D=binding/action id, R9=widget value. No keep services enter the sandbox.
pmod_netmon_query:
    push rbx
    push r12
    push r13
    mov r13d, edi
    mov r12, rsi
    cmp edi, 5
    ja .deny
    cmp qword [rel pmod_nm_entry], 0
    je .deny
    cmp byte [rel pmod_nm_busy], 0
    jne .deny
    mov byte [rel pmod_nm_busy], 1
    test r12, r12
    jnz .have_arg
    cmp r13d, 5
    je .failed                         ; widget snapshots require both qwords
    lea r12, [rel pmod_nm_empty_arg]     ; preserve bare NETMON_STAT reads
.have_arg:
    mov rbx, [rel pmod_region_phys]
    add rbx, PMOD_NM_DATA*PMOD_PAGE_SIZE
    mov rdi, rbx
    call qword [rel pmod_nm_snapshot]
    mov [rbx+160], r13
    cmp r13d, 5
    jne .text_arg
    mov rax, [r12]
    mov [rbx+216], rax
    mov rax, [r12+8]
    mov [rbx+224], rax
    lea r12, [rel pmod_nm_empty_arg]
.text_arg:
    xor ecx, ecx
.copy:
    cmp ecx, 128
    jae .failed
    mov al, [r12+rcx]
    mov [rbx+rcx+32], al
    inc ecx
    test al, al
    jnz .copy
    mov byte [rbx+256], 0
    mov rdi, [rel pmod_nm_entry]
    mov esi, PMOD_REGION_BASE+PMOD_NM_DATA*PMOD_PAGE_SIZE
    lea rdx, [rsi+256]
    xor ecx, ecx
    call pmod_sandbox_call
    test eax, eax
    jnz .failed
    cmp qword [rel pmod_call_rax], PMOD_REGION_BASE+PMOD_NM_DATA*PMOD_PAGE_SIZE+256
    jne .failed
    mov rax, [rel pmod_call_rdx]
    cmp rax, 512
    jae .failed
    cmp byte [rbx+rax+256], 0
    jne .failed
    lea rax, [rbx+256]
    mov rdx, [rbx+184]
    mov rcx, [rbx+192]
    mov r8, [rbx+208]
    mov r9, [rbx+200]
    mov byte [rel pmod_nm_busy], 0
    jmp .out
.failed:
    mov byte [rel pmod_nm_busy], 0
.deny:
    xor eax, eax
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
.out:
    pop r13
    pop r12
    pop rbx
    ret

pmod_nm_control:
    call cmd_handler_prologue
    push rbx
    mov rbx, rsi
    mov rdi, [rdi+PM_REQ_ARG]
    test rdi, rdi
    jz .bad
    push rdi
    lea rsi, [rel pmod_nm_unload_arg]
    call strcmp
    pop rdi
    test eax, eax
    jz .unload
    push rdi
    lea rsi, [rel pmod_nm_load_arg]
    call strcmp
    pop rdi
    test eax, eax
    jz .load
    lea rsi, [rel pmod_nm_state_arg]
    call strcmp
    test eax, eax
    jnz .bad
    xor eax, eax
    jmp .result
.unload:
    call pmod_netmon_unload
    jmp .result
.load:
    call pmod_netmon_load
.result:
    test eax, eax
    jnz .bad
    mov rdx, [rel pmod_pt_addr]
    test rdx, rdx
    jz .bad
    mov rax, [rdx+PMOD_NM_CODE*8]
    and eax, 1
    movzx ecx, byte [rel pmod_nm_active]
    cmp eax, ecx
    jne .bad
    mov rax, [rdx+PMOD_NM_DATA*8]
    and eax, 1
    cmp eax, ecx
    jne .bad
    mov qword [rbx+PM_RSP_CODE], 0
    movzx eax, byte [rel pmod_nm_active]
    mov [rbx+PM_RSP_VAL], rax
    lea rdi, [rel pmod_nm_down]
    test eax, eax
    jz .reply
    lea rdi, [rel pmod_nm_up]
.reply:
    call qword [rel pmod_nm_reply]
    pop rbx
    ret
.bad:
    mov qword [rbx+PM_RSP_CODE], 5
    pop rbx
    ret

align 8
pmod_read_path: dq 0
pmod_nm_buf: dq 0
pmod_nm_size: dq 0
pmod_nm_entry: dq 0
pmod_nm_form_bind: dq 0
pmod_nm_form_unbind: dq 0
pmod_nm_snapshot: dq 0
pmod_nm_reply: dq 0
pmod_nm_generation: dq 0
pmod_nm_verb: dd -1
pmod_nm_seen: db 0
pmod_nm_active: db 0
pmod_nm_busy: db 0
pmod_nm_stage: db 0
pmod_nm_verb_name: db "NETMON_STAT",0
pmod_nm_ctl_name: db "PMODCTL",0
pmod_nm_load_arg: db "load",0
pmod_nm_unload_arg: db "unload",0
pmod_nm_state_arg: db "state",0
pmod_nm_empty_arg: db 0
; Failure stages: arena=1, media=2, hash=3, signature=4, native=5,
; seal=6, sandbox=7, form=8, registry=9. Zero means integrated.
pmod_nm_stage_marker: db "[PAOS64] P6 pmod: netmon load failed stage=",0
pmod_nm_stage_end: db 13,10,0
pmod_nm_up: db " pmod_netmon active=1 pages=2",0
pmod_nm_down: db " pmod_netmon active=0 pages=0",0
pmod_nm_status_active: db " pmod_netmon_active=",0
pmod_nm_status_generation: db " pmod_netmon_generation=",0
pmod_nm_status_slot: db " pmod_netmon_slot=",0
pmod_nm_status_stage: db " pmod_netmon_stage=",0
pmod_nm_refused_marker: db "[PAOS64] P6 pmod: external netmon rejected before integration [pmod.first.refused]",13,10,0
pmod_nm_loaded_marker: db "[PAOS64] P6 pmod: first signed PMOD verified+integrated from ESP [pmod.first.loaded]",13,10,0
pmod_nm_catalog_marker: db "[PAOS64] P6 pmod: PMOD verb registered into the generated CATALOG [pmod.first.catalog]",13,10,0
pmod_nm_absent_marker: db "[PAOS64] P6 pmod: PMOD absent -> keep boots unchanged, verb absent (honest degrade) [pmod.first.absent_degrades]",13,10,0
align 2                                 ; a CHAR16 string handed to firmware must be 2-aligned (UEFI; edk2 ASSERTs)
pmod_netmon_path: dw '\','E','F','I','\','P','a','O','S','\','m','o','d','u','l','e','s','\','n','e','t','m','o','n','.','p','m','d',0
%include "paos-pmod/owner.inc"

%endif
