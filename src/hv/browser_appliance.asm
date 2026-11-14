;; MODULE hv/browser_appliance
;; LAYER 5
;; EXPORTS browser_appliance_register, browser_appliance_prelaunch_verify, browser_appliance_deselect, browser_appliance_console_char, browser_out_ready, browser_out_buf
;; IMPORTS hv/vmx, fs/vfs, svc/command, svc/command_auth, core/lib/sha256, bootmgr/rsa2048_verify, core/heap, core/lib/mem
;; CAPS extension
;; OWNER saga:web_browser
; ============================================================================
; Contract 2715 — bounded signed browser-appliance BUNDLE consumer.
;
; The host accepts exactly BRAP v1: three named members, the owner signer, the
; fixed software-rendered Chromium launch field (v2: common, headless and
; windowed lines), and UID 2715.  Verification order is
; metadata bounds -> every member hash -> Merkle root -> detached RSA signature.
; No byte can become a VMLAUNCH input before the complete chain succeeds.
; RCQ-39 F-a: public INFO never measures. It formats the verdict cached by the
; last owner INFO MEASURE or START ("... measured_gen=N"), valid only while
; vfs_write_generation is still N; otherwise it reports "unmeasured gen=<now>". The cache is never launch
; authority: START and the prelaunch verify always re-measure in full. Raw
; block writes below VFS and media swapped under a mount are not counted, and
; are never claimed as detected.
; This is deliberately separate from pmod_verify_bundle: PMOD's verifier is a
; two-member fixture contract and is neither called nor generalized here.
; ============================================================================

BROWSER_MANIFEST_SIZE      equ 512
BROWSER_SIGNATURE_SIZE     equ 256
BROWSER_MEMBER_COUNT       equ 3
BROWSER_POLICY_FLAGS       equ 0x0F       ; sw-render/no-desktop/sandbox/no-gpu-pass
BROWSER_APPLIANCE_UID      equ 2715
BROWSER_KERNEL_MAX         equ 0x02000000 ; 32 MiB compressed kernel
BROWSER_INITRD_MAX         equ 0x32000000 ; 800 MiB bounded root artifact
BROWSER_INVENTORY_MAX      equ 0x00100000
BROWSER_IO_CHUNK           equ 0x08000     ; leaves code plus bounded static state within 64 KiB
                                           ; (the chunk itself is a zeroed kernel-heap buffer,
                                           ;  browser_io_base — was 32 KiB of image zero bytes)
%include "core/abi/heap_once.inc"
BROWSER_OUT_CAP            equ 1536
BROWSER_CONSOLE_CAP        equ 256       ; 512 hex chars fit the UDP reply clamp

BRAP_MAGIC                 equ 0
BRAP_VERSION               equ 4
BRAP_HEADER_SIZE           equ 6
BRAP_MEMBER_COUNT          equ 8
BRAP_POLICY                equ 10
BRAP_RESERVED              equ 12
BRAP_ROOT                  equ 16
BRAP_SIGNER                equ 48
BRAP_CHROME_HASH           equ 80
BRAP_KERNEL_SIZE           equ 112
BRAP_KERNEL_HASH           equ 120
BRAP_INITRD_SIZE           equ 152
BRAP_INITRD_HASH           equ 160
BRAP_INVENTORY_SIZE        equ 192
BRAP_INVENTORY_HASH        equ 200
BRAP_CHROME_VERSION        equ 232
BRAP_CHROME_VERSION_CAP    equ 48
BRAP_LAUNCH_FLAGS          equ 280
BRAP_LAUNCH_FLAGS_CAP      equ 224
BRAP_UID                   equ 504
BRAP_CHROME_VERSION_LEN    equ 508
BRAP_LAUNCH_FLAGS_LEN      equ 510

; Called from hv_register_verbs after the normal artifact selectors have been
; populated with relocated addresses.
browser_appliance_register:
    push rbx
    call browser_io_base                   ; allocate the hash I/O chunk now (heap is up)
    call browser_bundle_selftest
    ; INFO/STAT remain public observations.  The UDP route gate receives the
    ; already-split registry name, so parsed START/STOP branches enforce AUTH1
    ; themselves immediately before mutation; a space-containing interceptor
    ; could never match that route input.
    lea  rdi, [rel str_browser_verb]
    lea  rsi, [rel cmd_verb_browserimg]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9d, r9d                          ; handler gates only parsed lifecycle mutations
    call command_register_verb
    pop  rbx
    ret

; The command handler verifies before queueing, then the resident vCPU calls
; this again immediately before it reads either launch artifact.  Rebinding
; the names here closes both the staging TOCTOU window and cross-verb pointer
; drift: no browser-selected VMLAUNCH can consume bytes outside this BUNDLE.
browser_appliance_prelaunch_verify:
    cmp  byte [rel browser_selected], 1
    jne  .ordinary
    call browser_verify_bundle
    test eax, eax
    jnz  .ret
    call browser_appliance_select_artifacts
    ; Preserve native admission status; a managed run keeps its exact tuple.
.ret:
    ret
.ordinary:
    xor  eax, eax
    ret

browser_appliance_select_artifacts:
    sub  rsp, 8
    call vm_profile_reset_legacy             ; refuse before names/RAM can drift
    add  rsp, 8
    test eax, eax
    jnz  .out
    lea  rax, [rel browser_name_kernel]
    mov  [rel hv_linux_kernel_name_ptr], rax
    lea  rax, [rel browser_name_initrd]
    mov  [rel hv_linux_initrd_name_ptr], rax
    mov  qword [rel hv_linux_ram_bytes], HV_LINUX_BROWSER_RAM_BYTES
    xor  eax, eax
.out:
    ret

; The ordinary guest command owns the one shared vCPU next.  Clear only the
; browser-selection latch; its caller restores the ordinary artifact profile.
browser_appliance_deselect:
    mov  byte [rel browser_selected], 0
    ret

; BROWSERIMG INFO [MEASURE] | START [TAMPER] | STAT | STOP
cmd_verb_browserimg:
    push rbx
    push r12
    push r13
    mov  r13, rdi
    call cmd_handler_prologue
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  rdi, rbx
    lea  rsi, [rel str_browser_start]
    call hv_tok_is
    test al, al
    jnz  .start
    mov  rdi, rbx
    lea  rsi, [rel str_browser_stat]
    call hv_tok_is
    test al, al
    jnz  .stat
    mov  rdi, rbx
    lea  rsi, [rel str_browser_stop]
    call hv_tok_is
    test al, al
    jnz  .stop
    mov  rdi, rbx
    lea  rsi, [rel str_browser_info]
    call hv_tok_is
    test al, al
    jnz  .info
    cmp  byte [rbx], 0
    je   .info
    mov  byte [rel browser_error], 11      ; only INFO/START/STAT/STOP exist
    call browser_render_refused
    jmp  .done
.info:
    ; RCQ-39 F-a: empty, INFO and INFO with any other argument only format the
    ; cache. Only the exact "INFO MEASURE" measures, and only for the owner.
    mov  rdi, rbx
    lea  rsi, [rel str_browser_info_measure]
    call browser_arg_exact
    test al, al
    jz   .info_cached
    cmp  byte [rel command_auth_remote_active], 1
    jne  .measure_principal
    ; Remote (rc-sec F2b-2): the gate consumes this request's own ticket, so one
    ; owner envelope buys one measurement; a replay is refused before any hash.
    call browser_require_lifecycle_auth
    test eax, eax
    jnz  .measure_refused
    call command_auth_owner_request        ; 1 = own consumed owner AUTH1, 2 = owner SSH key
    test eax, eax
    jz   .measure_refused
.measure_principal:
    cmp  qword [r13 + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne  .measure_refused
    call browser_measure
.info_cached:
    call browser_render_info
    jmp  .done
.measure_refused:
    mov  byte [rel browser_error], 12      ; INFO MEASURE is owner-only
    call browser_render_refused
    jmp  .done
.start:
    call browser_require_lifecycle_auth
    test eax, eax
    jnz  .auth_refused
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .start_seam_busy                  ; RCQ-37: the media owner holds the vCPU seam
%endif
%endif
    ; RCQ-18: the one vCPU seam is busy while any byte of running, the loader's
    ; start_active or a queued run_req is nonzero. Test it before TAMPER (which
    ; reloads browser_manifest, read by the loader's prelaunch verify), the
    ; measurement, the selector and the START request.
    cmp  byte [rel hv_linux_running], 0
    jne  .start_busy
    cmp  byte [rel hv_linux_start_active], 0
    jne  .start_busy
    cmp  byte [rel hv_linux_run_req], 0
    jne  .start_busy
    mov  rdi, rbx
    lea  rsi, [rel str_browser_tamper]
    call hv_str_has
    test al, al
    jnz  .tamper
.start_verify:                             ; idle seam only
    call browser_measure                   ; full measurement; never the cached verdict
    test eax, eax
    jnz  .start_bad
    call browser_appliance_select_artifacts
    test eax, eax
    jnz  .start_busy
    mov  byte [rel browser_selected], 1
    mov  byte [rel browser_init_seen], 0
    mov  byte [rel browser_ready], 0
    mov  byte [rel browser_ready_marker_sent], 0
    mov  byte [rel browser_chromium_live], 0
    mov  byte [rel browser_renderer_nnp], 0
    mov  byte [rel browser_renderer_seccomp], 0
    mov  byte [rel browser_namespace_isolated], 0
    mov  byte [rel browser_sandbox_intact], 0
    mov  byte [rel browser_stop_requested], 0
    mov  dword [rel browser_init_match], 0
    mov  dword [rel browser_ready_match], 0
    mov  dword [rel browser_fail_match], 0
    call browser_console_reset
    inc  dword [rel browser_generation]
    call hv_guest_linux_request_start
    mov  eax, [rel hv_linux_start_gen]
    mov  [rel browser_hv_generation], eax
    cmp  byte [rel hv_linux_task_started], 1
    je   .start_kick
    lea  rdi, [rel hv_guest_linux_task]
    call sched_spawn
    cmp  eax, -1
    jne  .start_spawned
    mov  byte [rel hv_linux_run_req], 0
    mov  byte [rel browser_selected], 0
    mov  byte [rel browser_error], 8
    call hv_linux_select_default_artifacts
    call browser_render_refused
    jmp  .done
.start_spawned:
    mov  byte [rel hv_linux_task_started], 1
.start_kick:
    call sched_yield
    call browser_render_stat
    jmp  .done
.start_bad:
    call browser_render_refused
    jmp  .done
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
.start_seam_busy:                          ; media seam: never this browser's idempotent STAT
    mov  byte [rel browser_error], 7       ; the media owner holds the one vCPU seam
    call browser_render_refused
    jmp  .done
%endif
%endif
.start_busy:
    cmp  byte [rel browser_selected], 1
    je   .stat                             ; this browser's own START: idempotent STAT
    mov  byte [rel browser_error], 7       ; another guest owns the one vCPU seam
    call browser_render_refused
    jmp  .done
.tamper:
    mov  eax, [rel browser_generation]
    mov  [rel browser_tamper_generation_before], eax
    call browser_load_metadata
    test eax, eax
    jnz  .tamper_bad
    lea  rsi, [rel browser_manifest]
    lea  rdi, [rel browser_tamper_manifest]
    mov  ecx, BROWSER_MANIFEST_SIZE
    rep  movsb
    xor  byte [rel browser_tamper_manifest + BRAP_CHROME_VERSION], 1
    lea  rdi, [rel browser_tamper_manifest]
    call browser_verify_loaded
    test eax, eax
    jz   .tamper_accepted                  ; catastrophic: invalid signature accepted
    mov  eax, [rel browser_generation]
    cmp  eax, [rel browser_tamper_generation_before]
    jne  .tamper_accepted
    mov  byte [rel browser_tamper_refused], 1
    mov  byte [rel browser_verified], 0
    call browser_render_tamper
    jmp  .done
.tamper_accepted:
    mov  byte [rel browser_tamper_refused], 0
    mov  byte [rel browser_error], 9
    call browser_render_tamper
    jmp  .done
.tamper_bad:
    mov  byte [rel browser_tamper_refused], 0
    call browser_render_refused
    jmp  .done
.stat:
    call browser_refresh_state
    call browser_render_stat
    jmp  .done
.stop:
    call browser_require_lifecycle_auth
    test eax, eax
    jnz  .auth_refused
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .start_seam_busy                  ; RCQ-37: never stops the media owner's guest
%endif
%endif
    cmp  byte [rel browser_selected], 1
    jne  .stat
    mov  byte [rel browser_stop_requested], 1
    mov  byte [rel hv_linux_stop_req], 1
    call sched_yield
    call browser_refresh_state
    call browser_render_stat
    jmp  .done
.auth_refused:
    mov  qword [r12 + RSP_CODE], CMDE_AUTHDENY
    lea  rax, [rel command_auth_out_buf]
    mov  [r12 + RSP_HINT], rax
    pop  r13
    pop  r12
    pop  rbx
    ret
.done:
    lea  rax, [rel browser_out_buf]
    mov  [r12 + RSP_VAL], rax
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  byte [rel browser_out_ready], 1
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI = argument, RSI = literal -> AL 1 when they are byte-for-byte equal.
browser_arg_exact:
    mov  al, [rdi]
    cmp  al, [rsi]
    jne  .no
    test al, al
    jz   .yes
    inc  rdi
    inc  rsi
    jmp  browser_arg_exact
.yes:
    mov  al, 1
    ret
.no:
    xor  eax, eax
    ret

; RCQ-39 F-a: one full measurement whose verdict is cached against the VFS
; write generation read BEFORE the first member byte, so a write during the
; measurement leaves the cache already stale. EAX = browser_verify_bundle's.
browser_measure:
    mov  rax, [rel vfs_write_generation]
    mov  [rel browser_measure_gen], rax
    call browser_verify_bundle
    push rax
    mov  al, [rel browser_verified]
    mov  [rel browser_cache_verified], al
    mov  al, [rel browser_signature_valid]
    mov  [rel browser_cache_signature_valid], al
    mov  al, [rel browser_merkle_valid]
    mov  [rel browser_cache_merkle_valid], al
    mov  al, [rel browser_inventory_complete]
    mov  [rel browser_cache_inventory_complete], al
    lea  rdi, [rel browser_cache_manifest_hash]
    mov  ecx, 32 + 32 + BRAP_CHROME_VERSION_CAP
    xor  eax, eax
    rep  stosb                             ; a failed measurement caches no identity
    cmp  byte [rel browser_verified], 1
    jne  .stamp
    lea  rsi, [rel browser_manifest_hash]
    lea  rdi, [rel browser_cache_manifest_hash]
    mov  ecx, 32
    rep  movsb
    lea  rsi, [rel browser_image_hash]
    lea  rdi, [rel browser_cache_image_hash]
    mov  ecx, 32
    rep  movsb
    lea  rsi, [rel browser_manifest + BRAP_CHROME_VERSION]
    lea  rdi, [rel browser_cache_version]
    mov  ecx, BRAP_CHROME_VERSION_CAP
    rep  movsb
.stamp:
    mov  rax, [rel browser_measure_gen]
    mov  [rel browser_cache_gen], rax
    mov  byte [rel browser_cache_state], 1
    pop  rax
    ret

; Exact subverb authorization over the live UDP AUTH1 ticket. Internal callers
; remain governed by command_dispatch's source/principal checks.
browser_require_lifecycle_auth:
    mov  rdi, CMD_AUTH_CAP_EXTENSION
    lea  rsi, [rel str_browser_verb]
    jmp  command_auth_gate

browser_refresh_state:
    cmp  byte [rel browser_stop_requested], 1
    jne  .ret
    cmp  byte [rel hv_linux_running], 0
    jne  .ret
    cmp  byte [rel hv_linux_start_active], 0
    jne  .ret
    cmp  byte [rel hv_linux_run_req], 0
    jne  .ret
    mov  byte [rel browser_selected], 0
    mov  byte [rel browser_stop_requested], 0
    call hv_linux_select_default_artifacts
.ret:
    ret

; Load the exact fixed-size manifest and signature through the shipped VFS.
browser_load_metadata:
    cmp  dword [rel vfs_disk_handle], -1
    je   .io
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel browser_name_manifest]
    lea  rdx, [rel browser_stat_buf]
    call vfs_stat
    test rax, rax
    jnz  .io
    cmp  qword [rel browser_stat_buf], BROWSER_MANIFEST_SIZE
    jne  .format
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel browser_name_manifest]
    xor  edx, edx
    lea  rcx, [rel browser_manifest]
    mov  r8d, BROWSER_MANIFEST_SIZE
    call vfs_read_at
    cmp  rax, BROWSER_MANIFEST_SIZE
    jne  .io
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel browser_name_signature]
    lea  rdx, [rel browser_stat_buf]
    call vfs_stat
    test rax, rax
    jnz  .io
    cmp  qword [rel browser_stat_buf], BROWSER_SIGNATURE_SIZE
    jne  .format
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel browser_name_signature]
    xor  edx, edx
    lea  rcx, [rel browser_signature]
    mov  r8d, BROWSER_SIGNATURE_SIZE
    call vfs_read_at
    cmp  rax, BROWSER_SIGNATURE_SIZE
    jne  .io
    xor  eax, eax
    ret
.format:
    mov  byte [rel browser_error], 2
    mov  eax, -1
    ret
.io:
    mov  byte [rel browser_error], 1
    mov  eax, -1
    ret

browser_verify_bundle:
    mov  byte [rel browser_verified], 0
    mov  byte [rel browser_signature_valid], 0
    mov  byte [rel browser_merkle_valid], 0
    mov  byte [rel browser_inventory_complete], 0
    mov  byte [rel browser_error], 0
    call browser_load_metadata
    test eax, eax
    jnz  .ret
    lea  rdi, [rel browser_manifest]
    call browser_verify_loaded
.ret:
    ret

; RDI=512-byte manifest already loaded; detached signature is browser_signature.
browser_verify_loaded:
    push rbx
    push r12
    mov  r12, rdi
    call browser_validate_manifest_header
    test eax, eax
    jnz  .bad
    lea  rdi, [rel browser_name_kernel]
    mov  rsi, [r12 + BRAP_KERNEL_SIZE]
    lea  rdx, [r12 + BRAP_KERNEL_HASH]
    call browser_hash_member
    test eax, eax
    jnz  .hash_bad
    lea  rdi, [rel browser_name_initrd]
    mov  rsi, [r12 + BRAP_INITRD_SIZE]
    lea  rdx, [r12 + BRAP_INITRD_HASH]
    call browser_hash_member
    test eax, eax
    jnz  .hash_bad
    lea  rdi, [rel browser_name_inventory]
    mov  rsi, [r12 + BRAP_INVENTORY_SIZE]
    lea  rdx, [r12 + BRAP_INVENTORY_HASH]
    call browser_hash_member
    test eax, eax
    jnz  .hash_bad
    mov  byte [rel browser_inventory_complete], 1

    lea  rsi, [r12 + BRAP_KERNEL_HASH]
    lea  rdi, [rel browser_merkle_leaves]
    mov  ecx, 32
    rep  movsb
    lea  rsi, [r12 + BRAP_INITRD_HASH]
    mov  ecx, 32
    rep  movsb
    lea  rsi, [r12 + BRAP_INVENTORY_HASH]
    mov  ecx, 32
    rep  movsb
    lea  rdi, [rel browser_merkle_hash]
    lea  rsi, [rel browser_merkle_leaves]
    mov  edx, 96
    call sha256_hash
    test eax, eax
    jnz  .hash_bad
    lea  rdi, [rel browser_merkle_hash]
    lea  rsi, [r12 + BRAP_ROOT]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .merkle_bad
    mov  byte [rel browser_merkle_valid], 1

    lea  rdi, [rel browser_signature]
    mov  rsi, r12
    mov  edx, BROWSER_MANIFEST_SIZE
    lea  rcx, [rel command_auth_owner_modulus]
    call rsa2048_verify_sha256
    test eax, eax
    jnz  .sig_bad
    mov  byte [rel browser_signature_valid], 1
    lea  rdi, [rel browser_manifest_hash]
    mov  rsi, r12
    mov  edx, BROWSER_MANIFEST_SIZE
    call sha256_hash
    test eax, eax
    jnz  .hash_bad
    lea  rsi, [r12 + BRAP_INITRD_HASH]
    lea  rdi, [rel browser_image_hash]
    mov  ecx, 32
    rep  movsb
    mov  byte [rel browser_verified], 1
    xor  eax, eax
    jmp  .out
.bad:
    mov  byte [rel browser_error], 3
    jmp  .fail
.hash_bad:
    mov  byte [rel browser_error], 4
    jmp  .fail
.merkle_bad:
    mov  byte [rel browser_error], 5
    jmp  .fail
.sig_bad:
    mov  byte [rel browser_error], 6
.fail:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; Validate every security-relevant manifest field against the one v1 profile.
browser_validate_manifest_header:
    push rbx
    push r12
    mov  r12, rdi
    cmp  dword [r12 + BRAP_MAGIC], 0x50415242 ; "BRAP"
    jne  .bad
    cmp  word [r12 + BRAP_VERSION], 1
    jne  .bad
    cmp  word [r12 + BRAP_HEADER_SIZE], BROWSER_MANIFEST_SIZE
    jne  .bad
    cmp  word [r12 + BRAP_MEMBER_COUNT], BROWSER_MEMBER_COUNT
    jne  .bad
    cmp  word [r12 + BRAP_POLICY], BROWSER_POLICY_FLAGS
    jne  .bad
    cmp  dword [r12 + BRAP_RESERVED], 0
    jne  .bad
    cmp  dword [r12 + BRAP_UID], BROWSER_APPLIANCE_UID
    jne  .bad
    lea  rdi, [r12 + BRAP_SIGNER]
    lea  rsi, [rel command_auth_owner_key_id]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .bad
    mov  rax, [r12 + BRAP_ROOT]
    or   rax, [r12 + BRAP_ROOT + 8]
    or   rax, [r12 + BRAP_ROOT + 16]
    or   rax, [r12 + BRAP_ROOT + 24]
    jz   .bad
    mov  rax, [r12 + BRAP_CHROME_HASH]
    or   rax, [r12 + BRAP_CHROME_HASH + 8]
    or   rax, [r12 + BRAP_CHROME_HASH + 16]
    or   rax, [r12 + BRAP_CHROME_HASH + 24]
    jz   .bad
    mov  rax, [r12 + BRAP_KERNEL_SIZE]
    test rax, rax
    jz   .bad
    cmp  rax, BROWSER_KERNEL_MAX
    ja   .bad
    mov  rax, [r12 + BRAP_INITRD_SIZE]
    test rax, rax
    jz   .bad
    cmp  rax, BROWSER_INITRD_MAX
    ja   .bad
    mov  rax, [r12 + BRAP_INVENTORY_SIZE]
    test rax, rax
    jz   .bad
    cmp  rax, BROWSER_INVENTORY_MAX
    ja   .bad
    movzx ebx, word [r12 + BRAP_CHROME_VERSION_LEN]
    test ebx, ebx
    jz   .bad
    cmp  ebx, BRAP_CHROME_VERSION_CAP - 1
    ja   .bad
    cmp  byte [r12 + BRAP_CHROME_VERSION + rbx], 0
    jne  .bad
    xor  ecx, ecx
.version_ascii:
    cmp  ecx, ebx
    jae  .version_padding
    mov  al, [r12 + BRAP_CHROME_VERSION + rcx]
    cmp  al, 0x20
    jb   .bad
    cmp  al, 0x7E
    ja   .bad
    inc  ecx
    jmp  .version_ascii
.version_padding:
    cmp  ecx, BRAP_CHROME_VERSION_CAP
    jae  .flags
    cmp  byte [r12 + BRAP_CHROME_VERSION + rcx], 0
    jne  .bad
    inc  ecx
    jmp  .version_padding
.flags:
    movzx edx, word [r12 + BRAP_LAUNCH_FLAGS_LEN]
    cmp  edx, browser_launch_flags_len
    jne  .bad
    lea  rdi, [r12 + BRAP_LAUNCH_FLAGS]
    lea  rsi, [rel browser_launch_flags]
    call memcmp
    test eax, eax
    jnz  .bad
    movzx edx, word [r12 + BRAP_LAUNCH_FLAGS_LEN]
.flags_padding:
    cmp  edx, BRAP_LAUNCH_FLAGS_CAP
    jae  .canonical
    cmp  byte [r12 + BRAP_LAUNCH_FLAGS + rdx], 0
    jne  .bad
    inc  edx
    jmp  .flags_padding
.canonical:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; RDI=name11, RSI=exact size, RDX=expected SHA-256 -> EAX=0/-1.
browser_hash_member:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  rbp, rsi
    mov  r14, rdx
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, r12
    lea  rdx, [rel browser_stat_buf]
    call vfs_stat
    test rax, rax
    jnz  .bad
    cmp  qword [rel browser_stat_buf], rbp
    jne  .bad
    lea  rdi, [rel browser_sha_ctx]
    call sha256_stream_init
    xor  r15d, r15d
.loop:
    cmp  r15, rbp
    jae  .final
    mov  rbx, rbp
    sub  rbx, r15
    cmp  rbx, BROWSER_IO_CHUNK
    jbe  .chunk
    mov  ebx, BROWSER_IO_CHUNK
.chunk:
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, r12
    mov  rdx, r15
    call browser_io_base
    test rax, rax
    jz   .bad                              ; heap refused: never hash from address 0
    mov  rcx, rax
    mov  r8, rbx
    call vfs_read_at
    cmp  rax, rbx
    jne  .bad
    lea  rdi, [rel browser_sha_ctx]
    call browser_io_base
    mov  rsi, rax
    mov  rdx, rbx
    call sha256_stream_update
    test eax, eax
    jnz  .bad
    add  r15, rbx
    jmp  .loop
.final:
    lea  rdi, [rel browser_sha_ctx]
    lea  rsi, [rel browser_hash_tmp]
    call sha256_stream_final
    test eax, eax
    jnz  .bad
    lea  rdi, [rel browser_hash_tmp]
    mov  rsi, r14
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; browser_io_base -> RAX = the zeroed BROWSER_IO_CHUNK hash-read buffer, or 0 if
; the heap refused. Preserves every register except RAX.
HEAP_ONCE_ACCESSOR browser_io_base, browser_io_ptr, BROWSER_IO_CHUNK, str_browser_io_fail

; Deterministic policy + crypto KAT.  Directly uses the proven RSA primitive;
; it does not call the PMOD fixture verifier or accept PMOD as a browser bundle.
browser_bundle_selftest:
    push rbx
    lea  rdi, [rel browser_kat_manifest]
    xor  eax, eax
    mov  ecx, BROWSER_MANIFEST_SIZE
    rep  stosb
    mov  dword [rel browser_kat_manifest + BRAP_MAGIC], 0x50415242
    mov  word [rel browser_kat_manifest + BRAP_VERSION], 1
    mov  word [rel browser_kat_manifest + BRAP_HEADER_SIZE], BROWSER_MANIFEST_SIZE
    mov  word [rel browser_kat_manifest + BRAP_MEMBER_COUNT], BROWSER_MEMBER_COUNT
    mov  word [rel browser_kat_manifest + BRAP_POLICY], BROWSER_POLICY_FLAGS
    mov  dword [rel browser_kat_manifest + BRAP_UID], BROWSER_APPLIANCE_UID
    mov  qword [rel browser_kat_manifest + BRAP_ROOT], 1
    mov  qword [rel browser_kat_manifest + BRAP_CHROME_HASH], 1
    mov  qword [rel browser_kat_manifest + BRAP_KERNEL_SIZE], 1
    mov  qword [rel browser_kat_manifest + BRAP_INITRD_SIZE], 1
    mov  qword [rel browser_kat_manifest + BRAP_INVENTORY_SIZE], 1
    lea  rsi, [rel command_auth_owner_key_id]
    lea  rdi, [rel browser_kat_manifest + BRAP_SIGNER]
    mov  ecx, 32
    rep  movsb
    lea  rsi, [rel browser_kat_version]
    lea  rdi, [rel browser_kat_manifest + BRAP_CHROME_VERSION]
    mov  ecx, browser_kat_version_len
    rep  movsb
    mov  word [rel browser_kat_manifest + BRAP_CHROME_VERSION_LEN], browser_kat_version_len
    lea  rsi, [rel browser_launch_flags]
    lea  rdi, [rel browser_kat_manifest + BRAP_LAUNCH_FLAGS]
    mov  ecx, browser_launch_flags_len
    rep  movsb
    mov  word [rel browser_kat_manifest + BRAP_LAUNCH_FLAGS_LEN], browser_launch_flags_len
    lea  rdi, [rel browser_kat_manifest]
    call browser_validate_manifest_header
    test eax, eax
    jnz  .fail
    xor  byte [rel browser_kat_manifest + BRAP_LAUNCH_FLAGS], 1
    lea  rdi, [rel browser_kat_manifest]
    call browser_validate_manifest_header
    test eax, eax
    jz   .fail
    lea  rdi, [rel pmod_fixture_signature]
    lea  rsi, [rel pmod_fixture_manifest]
    mov  edx, PMOD_MANIFEST_SIZE
    lea  rcx, [rel pmod_fixture_modulus]
    call rsa2048_verify_sha256
    test eax, eax
    jnz  .fail
    lea  rsi, [rel pmod_fixture_manifest]
    lea  rdi, [rel browser_kat_rsa_message]
    mov  ecx, PMOD_MANIFEST_SIZE
    rep  movsb
    xor  byte [rel browser_kat_rsa_message + 8], 1
    lea  rdi, [rel pmod_fixture_signature]
    lea  rsi, [rel browser_kat_rsa_message]
    mov  edx, PMOD_MANIFEST_SIZE
    lea  rcx, [rel pmod_fixture_modulus]
    call rsa2048_verify_sha256
    test eax, eax
    jz   .fail
    call browser_console_selftest
    test eax, eax
    jnz  .fail
    mov  byte [rel browser_bundle_kat_ok], 1
    lea  rdi, [rel str_browser_bundle_kat]
    call serial_string
    pop  rbx
    ret
.fail:
    mov  byte [rel browser_bundle_kat_ok], 0
    lea  rdi, [rel str_browser_bundle_kat_fail]
    call serial_string
    pop  rbx
    ret

; A browser-only console tail preserves startup stderr after the ordinary
; prefix capture fills with kernel boot text. Port the bounded rolling-copy
; shape from hv_vcon_capture_core; never change the shared capture's policy.
browser_console_reset:
    mov  dword [rel browser_console_len], 0
    mov  dword [rel browser_console_dropped], 0
    mov  byte [rel browser_console_frozen], 0
    ret

; AL=raw byte, all registers preserved. Length is authoritative (including NUL
; bytes); STAT hex-encodes it so guest text cannot inject host key/value fields.
browser_console_record:
    push rbx
    push rcx
    push rsi
    push rdi
    mov  ebx, [rel browser_console_len]
    cmp  ebx, BROWSER_CONSOLE_CAP
    jb   .append
    lea  rsi, [rel browser_console_tail + 1]
    lea  rdi, [rel browser_console_tail]
    mov  ecx, BROWSER_CONSOLE_CAP - 1
    cld
    rep  movsb
    inc  dword [rel browser_console_dropped]
    mov  ebx, BROWSER_CONSOLE_CAP - 1
.append:
    lea  rdi, [rel browser_console_tail]
    mov  [rdi + rbx], al
    inc  ebx
    mov  [rel browser_console_len], ebx
    pop  rdi
    pop  rsi
    pop  rcx
    pop  rbx
    ret

; Exercise real overflow, retained order, and a fresh-generation reset. This
; fixture calls only the recorder and cannot manufacture appliance readiness.
browser_console_selftest:
    push rbx
    call browser_console_reset
    xor  ebx, ebx
.feed:
    mov  eax, ebx
    call browser_console_record
    inc  ebx
    cmp  ebx, BROWSER_CONSOLE_CAP + 3
    jb   .feed
    cmp  dword [rel browser_console_len], BROWSER_CONSOLE_CAP
    jne  .bad
    cmp  dword [rel browser_console_dropped], 3
    jne  .bad
    xor  ebx, ebx
    lea  rdx, [rel browser_console_tail]
.check:
    lea  eax, [rbx + 3]
    cmp  [rdx + rbx], al
    jne  .bad
    inc  ebx
    cmp  ebx, BROWSER_CONSOLE_CAP
    jb   .check
    call browser_console_reset
    mov  al, 'Z'
    call browser_console_record
    cmp  dword [rel browser_console_len], 1
    jne  .bad
    cmp  dword [rel browser_console_dropped], 0
    jne  .bad
    cmp  byte [rel browser_console_tail], 'Z'
    jne  .bad
    xor  ebx, ebx
    jmp  .done
.bad:
    mov  ebx, -1
.done:
    call browser_console_reset
    mov  eax, ebx
    pop  rbx
    ret

; AL=one byte from the real hvc console. Exact signed-init attestations earn
; readiness; substring or partial-line matches do not.
browser_appliance_console_char:
    push rax
    push rbx
    push rcx
    cmp  byte [rel browser_selected], 1
    jne  .out
    cmp  byte [rel browser_console_frozen], 1
    je   .match_init
    call browser_console_record
    ; Freeze only after the failure's newline, retaining the full stage and
    ; preceding measured diagnostics even if later kernel chatter continues.
    cmp  byte [rel browser_error], 10
    jne  .match_init
    cmp  al, 10
    jne  .match_init
    mov  byte [rel browser_console_frozen], 1
.match_init:
    mov  ebx, [rel browser_init_match]
    lea  rcx, [rel str_browser_init_token]
    cmp  al, [rcx + rbx]
    jne  .init_reset
    inc  ebx
    cmp  byte [rcx + rbx], 0
    jne  .init_store
    mov  byte [rel browser_init_seen], 1
    xor  ebx, ebx
.init_store:
    mov  [rel browser_init_match], ebx
    jmp  .ready
.init_reset:
    xor  ebx, ebx
    cmp  al, [rel str_browser_init_token]
    jne  .init_store
    mov  ebx, 1
    jmp  .init_store
.ready:
    mov  ebx, [rel browser_ready_match]
    lea  rcx, [rel str_browser_ready_token]
    cmp  al, [rcx + rbx]
    jne  .ready_reset
    inc  ebx
    cmp  byte [rcx + rbx], 0
    jne  .ready_store
    cmp  byte [rel browser_init_seen], 1
    jne  .ready_clear
    mov  byte [rel browser_ready], 1
    mov  byte [rel browser_chromium_live], 1
    mov  byte [rel browser_renderer_nnp], 1
    mov  byte [rel browser_renderer_seccomp], 2
    mov  byte [rel browser_namespace_isolated], 1
    mov  byte [rel browser_desktop_present], 0
    mov  byte [rel browser_gpu_enabled], 0
    mov  byte [rel browser_sandbox_intact], 1
    mov  eax, [rel browser_generation]
    mov  [rel browser_live_generation], eax
    cmp  byte [rel browser_ready_marker_sent], 1
    je   .ready_clear
    mov  byte [rel browser_ready_marker_sent], 1
    lea  rdi, [rel str_browser_boot_marker]
    call serial_string
.ready_clear:
    xor  ebx, ebx
.ready_store:
    mov  [rel browser_ready_match], ebx
    jmp  .failure
.ready_reset:
    xor  ebx, ebx
    cmp  al, [rel str_browser_ready_token]
    jne  .ready_store
    mov  ebx, 1
    jmp  .ready_store
.failure:
    mov  ebx, [rel browser_fail_match]
    lea  rcx, [rel str_browser_fail_token]
    cmp  al, [rcx + rbx]
    jne  .failure_reset
    inc  ebx
    cmp  byte [rcx + rbx], 0
    jne  .failure_store
    mov  byte [rel browser_ready], 0
    mov  byte [rel browser_chromium_live], 0
    mov  byte [rel browser_renderer_nnp], 0
    mov  byte [rel browser_renderer_seccomp], 0
    mov  byte [rel browser_namespace_isolated], 0
    mov  byte [rel browser_sandbox_intact], 0
    mov  dword [rel browser_live_generation], 0
    mov  byte [rel browser_error], 10
    xor  ebx, ebx
.failure_store:
    mov  [rel browser_fail_match], ebx
    jmp  .out
.failure_reset:
    xor  ebx, ebx
    cmp  al, [rel str_browser_fail_token]
    jne  .failure_store
    mov  ebx, 1
    jmp  .failure_store
.out:
    pop  rcx
    pop  rbx
    pop  rax
    ret

browser_out_reset:
    lea  rax, [rel browser_out_buf]
    mov  [rel browser_out_cur], rax
    mov  byte [rax], 0
    ret

browser_out_str:
    mov  rsi, [rel browser_out_cur]
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel browser_out_cur], rsi
    ret

browser_out_dec:
    mov  rsi, [rel browser_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel browser_out_cur], rsi
    ret

browser_out_hex32:
    mov  ecx, 32
browser_out_hex:
    push rbx
    mov  rbx, rdi
    mov  rdi, [rel browser_out_cur]
    lea  r9, [rel browser_hex]
    test ecx, ecx
    jz   .done
.byte:
    movzx eax, byte [rbx]
    mov  edx, eax
    shr  eax, 4
    mov  al, [r9 + rax]
    mov  [rdi], al
    inc  rdi
    and  edx, 15
    mov  dl, [r9 + rdx]
    mov  [rdi], dl
    inc  rdi
    inc  rbx
    dec  ecx
    jnz  .byte
.done:
    mov  byte [rdi], 0
    mov  [rel browser_out_cur], rdi
    pop  rbx
    ret

; RCQ-39 F-a: formats the cached verdict only; it never reads a member.
browser_render_info:
    call browser_out_reset
    cmp  byte [rel browser_cache_state], 1
    jne  .unmeasured
    mov  rax, [rel vfs_write_generation]
    cmp  rax, [rel browser_cache_gen]
    jne  .unmeasured
    lea  rdi, [rel str_browser_info_prefix]
    call browser_out_str
    movzx edi, byte [rel browser_cache_verified]
    call browser_out_dec
    lea  rdi, [rel str_browser_sig]
    call browser_out_str
    movzx edi, byte [rel browser_cache_signature_valid]
    call browser_out_dec
    lea  rdi, [rel str_browser_merkle]
    call browser_out_str
    movzx edi, byte [rel browser_cache_merkle_valid]
    call browser_out_dec
    lea  rdi, [rel str_browser_inventory]
    call browser_out_str
    movzx edi, byte [rel browser_cache_inventory_complete]
    call browser_out_dec
    lea  rdi, [rel str_browser_manifest_hash]
    call browser_out_str
    lea  rdi, [rel browser_cache_manifest_hash]
    call browser_out_hex32
    lea  rdi, [rel str_browser_signer]
    call browser_out_str
    lea  rdi, [rel command_auth_owner_key_id]
    call browser_out_hex32
    lea  rdi, [rel str_browser_chrome_version]
    call browser_out_str
    lea  rdi, [rel browser_cache_version]  ; zeroed unless the cached verdict verified
    call browser_out_str
    lea  rdi, [rel str_browser_image_hash]
    call browser_out_str
    lea  rdi, [rel browser_cache_image_hash]
    call browser_out_hex32
    lea  rdi, [rel str_browser_policy]
    call browser_out_str
    lea  rdi, [rel str_browser_gen]
    call browser_out_str
    mov  rdi, [rel browser_cache_gen]
    jmp  browser_out_dec
.unmeasured:
    lea  rdi, [rel str_browser_info_unmeasured]
    call browser_out_str
    mov  rdi, [rel vfs_write_generation]
    jmp  browser_out_dec

browser_render_stat:
    call browser_out_reset
    lea  rdi, [rel str_browser_stat_prefix]
    call browser_out_str
    movzx edi, byte [rel browser_selected]
    call browser_out_dec
    lea  rdi, [rel str_browser_running]
    call browser_out_str
    xor  edi, edi
    cmp  byte [rel browser_selected], 1
    jne  .running_done
    cmp  byte [rel hv_linux_running], 1
    je   .running_yes
    cmp  byte [rel hv_linux_start_active], 1
    je   .running_yes
    cmp  byte [rel hv_linux_run_req], 1
    jne  .running_done
.running_yes:
    mov  edi, 1
.running_done:
    call browser_out_dec
    lea  rdi, [rel str_browser_generation]
    call browser_out_str
    mov  edi, [rel browser_generation]
    call browser_out_dec
    lea  rdi, [rel str_browser_static_policy]
    call browser_out_str
    lea  rdi, [rel str_browser_live_generation]
    call browser_out_str
    mov  edi, [rel browser_live_generation]
    call browser_out_dec
    lea  rdi, [rel str_browser_init]
    call browser_out_str
    movzx edi, byte [rel browser_init_seen]
    call browser_out_dec
    lea  rdi, [rel str_browser_chromium]
    call browser_out_str
    movzx edi, byte [rel browser_chromium_live]
    call browser_out_dec
    lea  rdi, [rel str_browser_runtime_policy]
    call browser_out_str
    movzx edi, byte [rel browser_renderer_nnp]
    call browser_out_dec
    lea  rdi, [rel str_browser_seccomp]
    call browser_out_str
    movzx edi, byte [rel browser_renderer_seccomp]
    call browser_out_dec
    lea  rdi, [rel str_browser_namespace]
    call browser_out_str
    movzx edi, byte [rel browser_namespace_isolated]
    call browser_out_dec
    lea  rdi, [rel str_browser_desktop]
    call browser_out_str
    movzx edi, byte [rel browser_desktop_present]
    call browser_out_dec
    lea  rdi, [rel str_browser_gpu]
    call browser_out_str
    movzx edi, byte [rel browser_gpu_enabled]
    call browser_out_dec
    lea  rdi, [rel str_browser_sandbox]
    call browser_out_str
    movzx edi, byte [rel browser_sandbox_intact]
    call browser_out_dec
    lea  rdi, [rel str_browser_image_hash]
    call browser_out_str
    lea  rdi, [rel browser_image_hash]
    call browser_out_hex32
    ; Retain the consumed loader/VM-exit result alongside this browser request.
    ; In particular, a prelaunch refusal has no console or renderer evidence;
    ; reporting only init=0 hides the rung that actually failed.
    lea  rdi, [rel str_browser_error]
    call browser_out_str
    movzx edi, byte [rel browser_error]
    call browser_out_dec
    lea  rdi, [rel str_browser_hv_generation]
    call browser_out_str
    mov  edi, [rel browser_hv_generation]
    call browser_out_dec
    lea  rdi, [rel str_browser_hv_consumed]
    call browser_out_str
    mov  edi, [rel hv_linux_start_consumed]
    call browser_out_dec
    lea  rdi, [rel str_browser_load_error]
    call browser_out_str
    movzx edi, byte [rel hv_linux_load_err]
    call browser_out_dec
    lea  rdi, [rel str_browser_exit_reason]
    call browser_out_str
    mov  edi, [rel hv_exit_reason]
    call browser_out_dec
    lea  rdi, [rel str_browser_instr_error]
    call browser_out_str
    mov  edi, [rel hv_instr_err]
    call browser_out_dec
    lea  rdi, [rel str_browser_console_dropped]
    call browser_out_str
    mov  edi, [rel browser_console_dropped]
    call browser_out_dec
    lea  rdi, [rel str_browser_console_hex]
    call browser_out_str
    lea  rdi, [rel browser_console_tail]
    mov  ecx, [rel browser_console_len]
    call browser_out_hex
    ret

browser_render_refused:
    call browser_out_reset
    lea  rdi, [rel str_browser_refused]
    call browser_out_str
    movzx edi, byte [rel browser_error]
    call browser_out_dec
    lea  rdi, [rel str_browser_generation]
    call browser_out_str
    mov  edi, [rel browser_generation]
    call browser_out_dec
    ret

browser_render_tamper:
    call browser_out_reset
    lea  rdi, [rel str_browser_tamper_prefix]
    call browser_out_str
    movzx edi, byte [rel browser_tamper_refused]
    call browser_out_dec
    lea  rdi, [rel str_browser_generation]
    call browser_out_str
    mov  edi, [rel browser_generation]
    call browser_out_dec
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_hv_browser_appliance_0 0
align 8
times 16 db 0                  ; browser_out_cur..browser_console_tail moved to WDATA_hv_browser_appliance_0_bss1: keeps the labels below at their offset mod 64

; FAT 8.3 staged member names.  BROWMAN is staged last by the host transaction,
; so a visible manifest always refers to a complete content set.
browser_name_kernel:    db "BROWKERN   "
browser_name_initrd:    db "BROWINITGZ "
browser_name_inventory: db "BROWMEM TXT"
browser_name_manifest:  db "BROWMAN BIN"
browser_name_signature: db "BROWSIG BIN"

; RCQ-39 S1 launch field v2: the signed common line, then the headless and the
; windowed delta lines (LF-separated). DevTools is the pipe; no TCP port.
browser_launch_flags:
    db "--disable-gpu --no-first-run --no-default-browser-check --disable-background-networking --user-data-dir=/run/browser-profile --remote-debugging-pipe about:blank",10
    db "--headless=new",10
    db "--window-position=0,0 --window-size=800,600"
browser_launch_flags_len equ $ - browser_launch_flags
browser_kat_version: db "Chromium 2715.0"
browser_kat_version_len equ $ - browser_kat_version
browser_hex: db "0123456789abcdef"

str_browser_io_fail: db "[PAOS64] browser appliance: heap refused the hash I/O chunk",13,10,0
str_browser_verb: db "BROWSERIMG",0
str_browser_info: db "INFO",0
str_browser_info_measure: db "INFO MEASURE",0
str_browser_info_unmeasured: db "BROWSERIMG INFO unmeasured gen=",0
str_browser_gen: db " measured_gen=",0      ; rc-sec F2b-3: the verdict is as of this generation
str_browser_start: db "START",0
str_browser_stat: db "STAT",0
str_browser_stop: db "STOP",0
str_browser_tamper: db "TAMPER",0
str_browser_info_prefix: db "BROWSERIMG INFO bundle_verified=",0
str_browser_stat_prefix: db "BROWSERIMG STAT selected=",0
str_browser_refused: db "BROWSERIMG REFUSED error=",0
str_browser_tamper_prefix: db "BROWSERIMG TAMPER refused=",0
str_browser_sig: db " signature_valid=",0
str_browser_merkle: db " merkle_valid=",0
str_browser_inventory: db " inventory_complete=",0
str_browser_manifest_hash: db " manifest_sha256=",0
str_browser_signer: db " signer=",0
str_browser_chrome_version: db " chromium_version=",0
str_browser_image_hash: db " image_sha256=",0
str_browser_policy: db " members=3 software_render=1 desktop=0 credentials=0 sandbox=1 gpu=0 uid=2715 flags=exact",0
str_browser_running: db " running=",0
str_browser_static_policy: db " software_render=1",0
str_browser_generation: db " generation=",0
str_browser_live_generation: db " live_generation=",0
str_browser_init: db " init=",0
str_browser_chromium: db " chromium=",0
str_browser_runtime_policy: db " renderer_no_new_privs=",0
str_browser_seccomp: db " renderer_seccomp=",0
str_browser_namespace: db " namespace_isolated=",0
str_browser_desktop: db " desktop=",0
str_browser_gpu: db " gpu=",0
str_browser_sandbox: db " sandbox=",0
str_browser_error: db " error=",0
str_browser_hv_generation: db " hv_generation=",0
str_browser_hv_consumed: db " hv_consumed=",0
str_browser_load_error: db " load_err=",0
str_browser_exit_reason: db " vmexit_reason=",0
str_browser_instr_error: db " instr_err=",0
str_browser_console_dropped: db " guest_console_dropped=",0
str_browser_console_hex: db " guest_console_hex=",0

str_browser_init_token:
    db "PAOS_BROWSER_INIT init=1 uid=2715 desktop=0 gpu=0 sandbox=1",0
str_browser_ready_token:
    db "PAOS_BROWSER_READY chromium=1 desktop=0 gpu=0 sandbox=1 renderer_no_new_privs=1 renderer_seccomp=2 namespace_isolated=1",0
str_browser_fail_token: db "PAOS_BROWSER_FAIL stage=",0
str_browser_bundle_kat:
    db "[PAOS64] browser appliance signed BUNDLE verify/tamper KAT PASS [browser.appliance.bundle.kat]",13,10,0
str_browser_bundle_kat_fail:
    db "[PAOS64] browser appliance signed BUNDLE verify/tamper KAT FAIL",13,10,0
str_browser_boot_marker:
    db "[PAOS64] browser appliance init reached Chromium software-rendered ready [browser.appliance.boot]",13,10,0
%endmacro
WDATA_DEFER WDATA_hv_browser_appliance_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_hv_browser_appliance_0_bss1 0
alignb 8
browser_out_cur: resq 1
browser_out_ready: resb 1
browser_verified: resb 1
browser_signature_valid: resb 1
browser_merkle_valid: resb 1
browser_inventory_complete: resb 1
browser_bundle_kat_ok: resb 1
browser_selected: resb 1
browser_stop_requested: resb 1
browser_init_seen: resb 1
browser_ready: resb 1
browser_ready_marker_sent: resb 1
browser_chromium_live: resb 1
browser_renderer_nnp: resb 1
browser_renderer_seccomp: resb 1
browser_namespace_isolated: resb 1
browser_desktop_present: resb 1
browser_gpu_enabled: resb 1
browser_sandbox_intact: resb 1
browser_tamper_refused: resb 1
browser_error: resb 1
browser_cache_state: resb 1            ; RCQ-39 F-a: 1 once an owner MEASURE/START cached a verdict
browser_cache_verified: resb 1
browser_cache_signature_valid: resb 1
browser_cache_merkle_valid: resb 1
browser_cache_inventory_complete: resb 1
browser_console_frozen: resb 1
alignb 4
browser_console_len: resd 1
browser_console_dropped: resd 1
browser_generation: resd 1
browser_hv_generation: resd 1
browser_live_generation: resd 1
browser_tamper_generation_before: resd 1
browser_init_match: resd 1
browser_ready_match: resd 1
browser_fail_match: resd 1
alignb 16
browser_stat_buf: resb fs_stat_size
browser_sha_ctx: resb S256_CTX_SZ
browser_hash_tmp: resb 32
browser_merkle_hash: resb 32
browser_manifest_hash: resb 32
browser_image_hash: resb 32
browser_cache_gen: resq 1              ; vfs_write_generation the cached verdict was measured at
browser_measure_gen: resq 1
browser_cache_manifest_hash: resb 32         ; these three are contiguous: browser_measure zeroes them together
browser_cache_image_hash: resb 32
browser_cache_version: resb BRAP_CHROME_VERSION_CAP
browser_merkle_leaves: resb 96
browser_manifest: resb BROWSER_MANIFEST_SIZE
browser_tamper_manifest: resb BROWSER_MANIFEST_SIZE
browser_signature: resb BROWSER_SIGNATURE_SIZE
browser_kat_manifest: resb BROWSER_MANIFEST_SIZE
browser_kat_rsa_message: resb PMOD_MANIFEST_SIZE
alignb 8
browser_io_ptr: resq 1                 ; -> heap hash-read chunk (browser_io_base)
browser_out_buf: resb BROWSER_OUT_CAP
browser_console_tail: resb BROWSER_CONSOLE_CAP
%endmacro
WDATA_BSS_DEFER WDATA_hv_browser_appliance_0_bss1
