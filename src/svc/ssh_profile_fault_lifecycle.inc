; Lab-only lifecycle behind the consumed-OWNER fault controller.
; Bound OWNER or an unbound session with its own consumed top-level UDP
; OWNER ticket; never change the local execution/session principal.
%ifdef PAOS_PUBLICITY_LAB_PROFILE
%if PAOS_PUBLICITY_LAB_PROFILE

SSH_FAULT_PUBLIC_SIZE equ 40 + SSH_CLI_PINS * SSH_CLI_PIN_SZ

; EDI=store1..2, ESI=mode1..4 -> EAX0 armed, -1 refused.
; Capture the original public CACHE, then prove that fresh authenticated
; firmware reads reproduce it before enabling any wrapper. No TOFU, repair,
; enrollment, private-key restoration, or absent/ephemeral baseline.
ssh_cli_fault_arm:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, edi
    mov  r12d, esi
    call ssh_cli_fault_owner
    test eax, eax
    jnz  .refused
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .refused
    cmp  byte [rel ssh_profile_fault_active], 0
    jne  .refused
    cmp  byte [rel ssh_profile_fault_baseline_valid], 0
    jne  .refused
    cmp  byte [rel ssh_profile_fault_retire_result], 3
    je   .refused                       ; failed retirement requires reboot
    cmp  ebx, 1
    jb   .refused
    cmp  ebx, 2
    ja   .refused
    cmp  r12d, 1
    jb   .refused
    cmp  r12d, 4
    ja   .refused
    cmp  qword [rel ssh_cli_kh_epoch], -1
    je   .refused
    call ssh_cli_cid_load
    test eax, eax
    jnz  .refused
    call ssh_cli_kh_load
    cmp  byte [rel ssh_cli_cid_state], SSH_CID_ST_ENROLLED
    jne  .refused
    cmp  byte [rel ssh_cli_kh_state], SSH_KH_ST_NVRAM
    jne  .refused
    cmp  dword [rel ssh_cli_kh_gen], 0
    je   .refused
    lea  rdi, [rel ssh_profile_fault_baseline]
    call ssh_cli_fault_public_copy
    call ssh_cli_fault_real_reload
    test eax, eax
    jnz  .unrestored
    call ssh_cli_fault_public_equal
    test eax, eax
    jnz  .different
    ; Previous counters/shadow belong to the previous case. A second ARM
    ; above refuses before reaching this wipe, preserving its first evidence.
    lea  rdi, [rel ssh_profile_fault_state_begin]
    xor  esi, esi
    mov  edx, ssh_profile_fault_state_end - ssh_profile_fault_state_begin
    call memset
    mov  [rel ssh_profile_fault_store], bl
    mov  [rel ssh_profile_fault_mode], r12b
    mov  byte [rel ssh_profile_fault_baseline_valid], 1
    mov  byte [rel ssh_profile_fault_retire_result], 1 ; armed, no persistence credit
    ; Ordinary loads cache both records. Read faults must discard the selected
    ; public cache, otherwise the real client never reaches the wrapper. Keep
    ; the authenticated baseline and floors; write cases need their cache.
    cmp  r12d, 2
    ja   .cache_ready
    cmp  ebx, 1
    jne  .kh_unload
    call ssh_cli_cid_revoke
    mov  dword [rel ssh_cli_cid_gen], 0
    mov  byte [rel ssh_cli_cid_state], SSH_CID_ST_UNLOADED
    jmp  .cache_ready
.kh_unload:
    lea  rdi, [rel ssh_cli_pins]
    xor  esi, esi
    mov  edx, SSH_CLI_PINS * SSH_CLI_PIN_SZ
    call memset
    mov  dword [rel ssh_cli_kh_gen], 0
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_UNLOADED
.cache_ready:
    mov  byte [rel ssh_profile_fault_active], 1       ; publish last
    xor  eax, eax
    jmp  .out
.different:
    call ssh_cli_fault_revoke
.unrestored:
    mov  byte [rel ssh_profile_fault_retire_result], 3 ; reboot required
.refused:
    mov  eax, -1
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; EAX0 original public state authentically reloaded, -1 no authorized case,
; -2 retired but NOT restored: caller must record uncertainty/reboot required.
; Wrapper state is retired before any real read. Never repair firmware or
; lower an attempted floor, even if RAM-only injection caused that attempt.
ssh_cli_fault_retire:
    push rbx
    call ssh_cli_fault_owner
    test eax, eax
    jnz  .refused
    cmp  byte [rel ssh_profile_fault_active], 1
    jne  .refused
    mov  byte [rel ssh_profile_fault_active], 0
    mov  byte [rel ssh_profile_fault_shadow_ready], 0
    lea  rdi, [rel ssh_profile_fault_shadow]
    xor  esi, esi
    mov  edx, SSH_KH_REC_SIZE
    call memset
    mov  byte [rel ssh_profile_fault_retire_result], 3
    cmp  byte [rel ssh_profile_fault_baseline_valid], 1
    jne  .invalid
    mov  byte [rel ssh_profile_fault_baseline_valid], 0 ; one retirement only
    call ssh_cli_fault_real_reload
    test eax, eax
    jnz  .unrestored
    call ssh_cli_fault_public_equal
    test eax, eax
    jnz  .invalid
    mov  byte [rel ssh_profile_fault_retire_result], 2
    xor  eax, eax
    jmp  .out
.invalid:
    mov  byte [rel ssh_profile_fault_baseline_valid], 0
    call ssh_cli_fault_revoke
.unrestored:
    mov  eax, -2
    jmp  .out
.refused:
    mov  eax, -1
.out:
    pop  rbx
    ret

; Fresh firmware authentication of BOTH fixed records, never cached load.
; No publication until both MACs, CID derivation and volatile floors pass.
; Retire all old trust-admission tokens before publishing the authenticated
; state. No previous epoch or private ready cache is restored.
ssh_cli_fault_real_reload:
    push rbx
    cmp  byte [rel ssh_profile_fault_active], 0
    jne  .invalid
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .invalid
    cmp  qword [rel ssh_cli_kh_epoch], -1
    je   .invalid
    call ssh_cli_cid_read_valid
    test eax, eax
    jnz  .invalid
    mov  eax, [rel ssh_cli_cid_stage + SSH_CID_REC_GEN]
    cmp  eax, [rel ssh_cli_cid_floor]
    jb   .invalid
    call ssh_cli_kh_derive
    test eax, eax
    jnz  .invalid
    call ssh_cli_kh_getvar
    test eax, eax
    jnz  .invalid
    lea  rdi, [rel ssh_cli_kh_stage]
    call ssh_cli_kh_valid
    test eax, eax
    jz   .invalid
    mov  eax, [rel ssh_cli_kh_stage + SSH_KH_REC_GEN]
    cmp  eax, [rel ssh_cli_kh_floor]
    jb   .invalid
    call ssh_cli_fault_revoke
    call ssh_cli_cid_publish
    ; Native restore compacts saved entries but does not clear the tail.
    ; Wipe only the RAM table so a stale slot cannot survive a real reload.
    lea  rdi, [rel ssh_cli_pins]
    xor  esi, esi
    mov  edx, SSH_CLI_PINS * SSH_CLI_PIN_SZ
    call memset
    call ssh_cli_kh_restore
    mov  edi, [rel ssh_cli_kh_stage + SSH_KH_REC_GEN]
    mov  [rel ssh_cli_kh_gen], edi
    call ssh_cli_kh_note_floor
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_NVRAM
    xor  ebx, ebx
    jmp  .clean
.invalid:
    call ssh_cli_fault_revoke
    mov  ebx, -1
.clean:
    call ssh_cli_cid_cleanup
    call ssh_cli_kh_cleanup
    mov  eax, ebx
    pop  rbx
    ret

; Deny all future credential admission even at an exhausted epoch; never
; wrap its high-water. Historical first-generation values remain historical.
ssh_cli_fault_revoke:
    sub  rsp, 8
    call ssh_cli_cid_revoke
    mov  qword [rel ssh_cli_kh_admitted_epoch], 0
    cmp  qword [rel ssh_cli_kh_epoch], -1
    je   .exhausted
    call ssh_cli_kh_revoke
    jmp  .out
.exhausted:
    mov  byte [rel ssh_cli_kh_state], SSH_KH_ST_UNCERTAIN
    lea  rdx, [rel ssh_cli_pins]
    mov  ecx, SSH_CLI_PINS
.pin:
    cmp  byte [rdx + 7], 1
    jne  .next
    mov  byte [rdx + 7], 2
.next:
    add  rdx, SSH_CLI_PIN_SZ
    loop .pin
.out:
    add  rsp, 8
    ret

; RDI writable SSH_FAULT_PUBLIC_SIZE. Public only: CID/KH generation,
; enrolled CID public key and the exact32 current pin slots.
ssh_cli_fault_public_copy:
    push rbx
    mov  rbx, rdi
    mov  eax, [rel ssh_cli_cid_gen]
    mov  [rbx], eax
    mov  eax, [rel ssh_cli_kh_gen]
    mov  [rbx + 4], eax
    lea  rdi, [rbx + 8]
    lea  rsi, [rel ssh_cli_cid_pub]
    mov  edx, 32
    call memcpy
    lea  rdi, [rbx + 40]
    lea  rsi, [rel ssh_cli_pins]
    mov  edx, SSH_CLI_PINS * SSH_CLI_PIN_SZ
    call memcpy
    pop  rbx
    ret

; EAX0 exact original public state, otherwise -1. Epoch/private ready are
; deliberately excluded: reloading must revoke old credential admission.
ssh_cli_fault_public_equal:
    sub  rsp, 8
    mov  eax, [rel ssh_cli_cid_gen]
    cmp  eax, [rel ssh_profile_fault_baseline]
    jne  .different
    mov  eax, [rel ssh_cli_kh_gen]
    cmp  eax, [rel ssh_profile_fault_baseline + 4]
    jne  .different
    lea  rdi, [rel ssh_cli_cid_pub]
    lea  rsi, [rel ssh_profile_fault_baseline + 8]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .different
    lea  rdi, [rel ssh_cli_pins]
    lea  rsi, [rel ssh_profile_fault_baseline + 40]
    mov  edx, SSH_CLI_PINS * SSH_CLI_PIN_SZ
    call memcmp
    test eax, eax
    jnz  .different
    xor  eax, eax
    jmp  .out
.different:
    mov  eax, -1
.out:
    add  rsp, 8
    ret

; EAX0 authorized native context, -1 refused. An unbound locked session
; has no ambient OWNER grant: it needs the real consumed request's ticket.
; A different bound principal cannot borrow that ticket. The command also
; checks its own request source and this predicate BEFORE reading arguments.
ssh_cli_fault_owner:
    sub  rsp, 8
    call principal_current
    add  rsp, 8
    cmp  rax, PRIN_OWNER
    je   .ok
    test rax, rax
    jnz  .no
    cmp  byte [rel cmd_in_dispatch], 1
    jne  .no
    cmp  dword [rel cmd_dispatch_depth], 1
    jne  .no
    cmp  qword [rel cmd_dispatch_last_source], CMD_SOURCE_UDP
    jne  .no
    cmp  byte [rel command_auth_remote_active], 1
    jne  .no
    mov  rax, [rel command_auth_remote_ticket]
    test rax, rax
    jz   .no
    cmp  byte [rax + AUTH_T_STATE], AUTH_TS_CONSUMED
    jne  .no
    cmp  qword [rax + AUTH_T_PRINCIPAL], PRIN_OWNER
    jne  .no
.ok:
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; RDI=40 writable bytes -> EAX0; -1 unauthorized, no output write.
; Bounded public status only: active/store/mode/result, four zero reserved
; bytes, then the exact four unsigned wrapper counters. No store/key bytes.
ssh_cli_fault_status:
    push rbx
    mov  rbx, rdi
    call ssh_cli_fault_owner
    test eax, eax
    jnz  .out
    mov  qword [rbx], 0
    mov  al, [rel ssh_profile_fault_active]
    mov  [rbx], al
    mov  al, [rel ssh_profile_fault_store]
    mov  [rbx + 1], al
    mov  al, [rel ssh_profile_fault_mode]
    mov  [rbx + 2], al
    mov  al, [rel ssh_profile_fault_retire_result]
    mov  [rbx + 3], al
    lea  rdi, [rbx + 8]
    lea  rsi, [rel ssh_profile_fault_cid_reads]
    mov  edx, 32
    call memcpy
    xor  eax, eax
.out:
    pop  rbx
    ret

%macro WDATA_svc_ssh_profile_fault_lifecycle_0 0
ssh_profile_fault_lifecycle_begin:
ssh_profile_fault_baseline_valid: db 0
ssh_profile_fault_retire_result: db 0 ;0unused,1armed,2restored,3reboot_required
align 8, db 0
ssh_profile_fault_baseline: times SSH_FAULT_PUBLIC_SIZE db 0
ssh_profile_fault_lifecycle_end:
%endmacro
WDATA_DEFER WDATA_svc_ssh_profile_fault_lifecycle_0
%endif

%endif
