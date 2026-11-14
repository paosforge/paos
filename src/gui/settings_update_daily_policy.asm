;; T5-14 unit P -- NATIVE IMPLEMENTATION, ROOT110490 / ADMIN110488.
;; SEC110503 design read consumed. Fixed native P; D hooks are a separate supplier.
;; Owner rc-msi-claude; sole source reviewer rc-srcreview-claude.
;
; Agreed native ABI to V/D (AI110552; hooks land with D, not installed V):
; settings_update_daily_policy_read(void) -> EAX0 enabled,1 disabled,
;   2 independently confirmed absent,-1 refused,-2 busy,-3 uncertain.
; settings_update_daily_policy_save(EDI=daily_disabled0/1) -> EAX0 saved enabled,
;   1 saved disabled,-1 refused,-2 busy,-3 uncertain; no absent save result.
; A scheduler can query; it cannot turn a CHECK request into consent to write.
; settings_update_daily_policy_current(void) -> EAX0 current/-1 refused,
;   fixed sec wrapper's per-effect check during this serialized operation only.
; No generic callback, arbitrary filename or guest policy/authority constructor.
;
; Query outcomes must distinguish ENABLED, DISABLED, CONFIRMED_ABSENT, REFUSED,
; BUSY, UNCERTAIN; save returns SAVED_ENABLED/SAVED_DISABLED only after signed
; exact write + independent verified reopen/readback and current local consent.
; The agreed result encoding above is not a success/currentness authority.
; Unknown/corrupt/foreign/old-format/I/O-error != confirmed absence.
; Uncertainty must not enable checking, downloading or staging. D owns scheduling
; and the confirmed-absence default; V owns GUI gestures and saved presentation.
;
; Daily CHECK choice is distinct from UPDATE.CFG automatic download/stage.
; SEC110503 chooses separate fixed UPDAILY.CFG (FAT 'UPDAILY CFG', exact11).
; PUDC256: magic@0, u16format1@4,size256@6, positive u64revision@8,
; DATA64@16, u32consent1@80, u8daily_disabled0/1@84, zero107@85,
; active node Ed25519 signature64@192 over first192. Own in-boot revision floor.
; Separate provider class AND dedicated guarded writer mode; do not share old
; 256-byte UPDATE.CFG class. Every other writer/name combination must refuse.
; No reserved-zero UPDATE.CFG extension, altered semantics or generic checker.
;
; V/D owns daily_consent_take(out40)/current(exact40)/finish(exact40)
; private hooks in settings_updates.asm. P save obtains V's original once; caller
; supplies only requested choice, never a tuple/callback granting authority.
; Distinct40: generation u64@0, daily_disabled u32@8, version1 u32@12,
; local owner u64@16, session u64@24, original boot_ms deadline u64@32.
; V retains actual human gesture, window slot/generation and original deadline;
; exact tuple alone never creates consent. Not the update_request CHECK tuple.
; P repeats V's fixed current hook plus native local-owner check at every
; provider effect, and finishes the single-use consent on every acquired exit.
; A new choice needs a fresh human gesture; D cannot save from a scheduled CHECK.
; AI110552: original gesture deadline is30000ms, overflow/regression refuses,
; no take/current/finish renewal. Exact finish retires even after expiry/logout
; or window loss, never grants effects, and cannot retire another generation.
; P compares requested choice against the taken tuple. Hooks land with D11/17;
; P11/15 may test inert agreed stubs, not claim installed GUI/save authority.
;
; RESIDUAL (ROOT110520(1), first consumer under ROOT109271(B)): an older genuine
; owner-signed daily preference may return after reboot or a one-slot DATA
; A->B->A swap. An earlier owner choice may return. In-boot revision floor only;
; no durable replay floor. Release signature, anti-rollback, revocation and
; explicit restart remain required. V/D doc gauntlet_v2/docs/settings_update_ui.md
; carries the same disclosure under AI's sequential ownership (110525).

;; MODULE gui/settings_update_daily_policy
;; LAYER 6
;; EXPORTS settings_update_daily_policy_read, settings_update_daily_policy_save, settings_update_daily_policy_current
;; IMPORTS gui/settings_updates, sec/session, sec/node_identity, sec/data_config_local, fs/data_config_authority, fs/data_config_provider, core/lib/mem, core/smp
;; CAPS CAP_GUI
;; OWNER rc-msi-claude
;; CONTEXT: bsp_only
%include "core/abi/wdata.inc"

; No write, consent take or default on this route. Only authenticated current
; bytes can clear uncertainty; confirmed absence cannot reconcile a write.
settings_update_daily_policy_read:
    push rbx
    cmp byte [rel updc_busy], 0
    jne .busy
    call updc_eligible
    test eax, eax
    jnz .refused
    mov byte [rel updc_busy], 1
    mov byte [rel updc_kind], 2
    mov [rel updc_owner], r8
    mov [rel updc_session], r9
    lea rdi, [rel updc_token]
    call data_config_acquire_provisioned
    cmp eax, -2
    je .provider_busy
    test eax, eax
    jnz .failed
    mov byte [rel updc_token_valid], 1
    call updc_load
    cmp eax, 2
    je .absent
    test eax, eax
    jnz .failed
    call updc_operation_current
    test eax, eax
    jnz .failed
    mov byte [rel updc_uncertain], 0
    movzx ebx, byte [rel updc_old+84]
    jmp .release
.absent:
    call updc_operation_current
    test eax, eax
    jnz .failed
    cmp byte [rel updc_uncertain], 0
    jne .unknown
    mov ebx, 2
    jmp .release
.provider_busy:
    cmp byte [rel updc_uncertain], 0
    jne .unknown
    mov ebx, -2
    jmp .release
.failed:
    cmp byte [rel updc_uncertain], 0
    jne .unknown
    mov ebx, -1
    jmp .release
.unknown:
    mov ebx, -3
.release:
    call updc_release
    mov eax, ebx
    pop rbx
    ret
.busy:
    mov eax, -2
    pop rbx
    ret
.refused:
    mov eax, -1
    pop rbx
    ret

; EDI choice only. V's once-only private native gesture hook supplies consent,
; never the caller, CHECK, scheduler or a copied request tuple. No implicit retry.
settings_update_daily_policy_save:
    push rbx
    cmp byte [rel updc_busy], 0
    jne .busy
    cmp edi, 1
    ja .refused
    cmp byte [rel updc_uncertain], 0
    jne .unknown_entry
    mov ebx, edi
    call updc_eligible
    test eax, eax
    jnz .refused
    mov byte [rel updc_busy], 1
    mov byte [rel updc_kind], 1
    mov [rel updc_owner], r8
    mov [rel updc_session], r9
    mov [rel updc_choice], ebx
    lea rdi, [rel updc_consent]
    call settings_updates_daily_consent_take
    cmp eax, 1
    jne .failed
    mov byte [rel updc_taken], 1
    cmp qword [rel updc_consent], 0
    je .failed
    cmp dword [rel updc_consent+12], 1
    jne .failed
    mov eax, [rel updc_choice]
    cmp eax, [rel updc_consent+8]
    jne .failed
    mov rax, [rel updc_owner]
    cmp rax, [rel updc_consent+16]
    jne .failed
    mov rax, [rel updc_session]
    cmp rax, [rel updc_consent+24]
    jne .failed
    call settings_update_daily_policy_current
    test eax, eax
    jnz .failed
    lea rdi, [rel updc_token]
    call data_config_acquire_provisioned
    cmp eax, -2
    je .provider_busy
    test eax, eax
    jnz .failed
    mov byte [rel updc_token_valid], 1
    call updc_load
    cmp eax, 2
    je .missing
    test eax, eax
    jnz .failed
    mov rbx, [rel updc_old+8]
    jmp .new
.missing:
    xor ebx, ebx
.new:
    cmp rbx, -1
    je .failed
    inc rbx
    call updc_floor_applies
    test eax, eax
    jnz .above_floor
    cmp rbx, [rel updc_floor+8]
    jbe .failed
.above_floor:
    lea rdi, [rel updc_new]
    xor esi, esi
    mov edx, 256
    call memset
    mov dword [rel updc_new], 'PUDC'
    mov word [rel updc_new+4], 1
    mov word [rel updc_new+6], 256
    mov [rel updc_new+8], rbx
    lea rdi, [rel updc_new+16]
    lea rsi, [rel updc_token+48]
    mov edx, 64
    call memcpy
    mov dword [rel updc_new+80], 1
    mov eax, [rel updc_choice]
    mov [rel updc_new+84], al
    call settings_update_daily_policy_current
    test eax, eax
    jnz .failed
    lea rdi, [rel updc_new]
    mov esi, 192
    lea rdx, [rel updc_new+192]
    mov ecx, 64
    call node_identity_sign_active
    test eax, eax
    jnz .failed
    lea rdi, [rel updc_new]
    call updc_valid
    test eax, eax
    jnz .failed
    ; Fixed sec checker and mode6/name gates repeat original native currentness
    ; at every actual provider effect. No public callback or arbitrary filename.
    lea rdi, [rel updc_token]
    lea rsi, [rel updc_name]
    lea rdx, [rel updc_new]
    mov ecx, 256
    mov r8, [rel updc_consent+16]
    mov r9, [rel updc_consent+24]
    call data_config_write_daily
    cmp eax, -1
    je .failed
    cmp eax, -2
    je .provider_busy
    test eax, eax
    jnz .uncertain
    mov byte [rel updc_written], 1
    ; Independent actual reopen, signature, exact equality and final currentness.
    call updc_load
    test eax, eax
    jnz .uncertain
    lea rdi, [rel updc_new]
    lea rsi, [rel updc_old]
    mov edx, 256
    call memcmp
    test eax, eax
    jnz .uncertain
    call settings_update_daily_policy_current
    test eax, eax
    jnz .uncertain
    mov ebx, [rel updc_choice]
    jmp .finish
.uncertain:
    mov byte [rel updc_uncertain], 1
    mov ebx, -3
    jmp .finish
.provider_busy:
    mov ebx, -2
    jmp .finish
.failed:
    mov ebx, -1
.finish:
    cmp byte [rel updc_taken], 1
    jne .release
    ; Exact retirement is required even after expiry/logout/window loss. Do not
    ; retry or retake. Retirement failure cannot be presented as SAVED.
    lea rdi, [rel updc_consent]
    call settings_updates_daily_consent_finish
    cmp eax, 1
    je .release
    cmp byte [rel updc_written], 0
    jne .uncertain_finish
    cmp ebx, -3
    je .release
    mov ebx, -1
    jmp .release
.uncertain_finish:
    mov byte [rel updc_uncertain], 1
    mov ebx, -3
.release:
    call updc_release
    mov eax, ebx
    pop rbx
    ret
.busy:
    mov eax, -2
    pop rbx
    ret
.unknown_entry:
    mov eax, -3
    pop rbx
    ret
.refused:
    mov eax, -1
    pop rbx
    ret

; Only while an acquired save is active. Read eligibility is NOT write consent.
settings_update_daily_policy_current:
    cmp byte [rel updc_busy], 1
    jne .no
    cmp byte [rel updc_kind], 1
    jne .no
    cmp byte [rel updc_taken], 1
    jne .no
    sub rsp, 8
    call updc_context_current
    test eax, eax
    jnz .out
    lea rdi, [rel updc_consent]
    call settings_updates_daily_consent_current
    cmp eax, 1
    jne .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 8
    ret
.no:
    mov eax, -1
    ret

; ->0 and R8/R9=current native OWNER/session. Never checks or takes a gesture.
updc_eligible:
    sub rsp, 8
    call smp_current_logical
    test eax, eax
    jnz .bad
    cmp byte [rel session_locked], 0
    jne .bad
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    cmp dword [rel cmd_dispatch_depth], 0
    jne .bad
    cmp byte [rel command_auth_remote_active], 0
    jne .bad
    cmp byte [rel pbm_try_media], 0
    jne .bad
    call session_shell_local_authority
    cmp rax, 1
    jne .bad
    test rdx, rdx
    jz .bad
    mov r8, rax
    mov r9, rdx
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 8
    ret

updc_context_current:
    cmp byte [rel updc_busy], 1
    jne .no
    sub rsp, 8
    call updc_eligible
    test eax, eax
    jnz .out
    cmp r8, [rel updc_owner]
    jne .bad
    cmp r9, [rel updc_session]
    jne .bad
    cmp byte [rel updc_token_valid], 1
    jne .out
    lea rdi, [rel updc_token]
    call data_config_current
    test eax, eax
    jnz .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 8
    ret
.no:
    mov eax, -1
    ret

updc_operation_current:
    cmp byte [rel updc_kind], 1
    je settings_update_daily_policy_current
    cmp byte [rel updc_kind], 2
    je updc_context_current
    mov eax, -1
    ret

; ->0 valid,2 independently confirmed absent,-1 refused. Only native -4 means
; absence, and even that needs current context, no in-boot confirmed predecessor.
updc_load:
    sub rsp, 8
    call updc_operation_current
    test eax, eax
    jnz .out
    lea rdi, [rel updc_token]
    lea rsi, [rel updc_name]
    lea rdx, [rel updc_old]
    mov ecx, 256
    call data_config_read
    cmp rax, -4
    je .missing
    cmp rax, 256
    jne .bad
    lea rdi, [rel updc_old]
    call updc_valid
    test eax, eax
    jnz .out
    call updc_floor_applies
    test eax, eax
    jnz .confirm
    mov rax, [rel updc_floor+8]
    cmp [rel updc_old+8], rax
    jb .bad
    ja .confirm
    lea rdi, [rel updc_old]
    lea rsi, [rel updc_floor]
    mov edx, 256
    call memcmp
    test eax, eax
    jnz .bad
.confirm:
    lea rdi, [rel updc_floor]
    lea rsi, [rel updc_old]
    mov edx, 256
    call memcpy
    mov byte [rel updc_floor_valid], 1
    xor eax, eax
    jmp .out
.missing:
    call updc_operation_current
    test eax, eax
    jnz .out
    call updc_floor_applies
    test eax, eax
    jz .bad
    mov eax, 2
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 8
    ret

updc_floor_applies:
    cmp byte [rel updc_floor_valid], 1
    jne .no
    sub rsp, 8
    lea rdi, [rel updc_floor+16]
    lea rsi, [rel updc_token+48]
    mov edx, 64
    call memcmp
    add rsp, 8
    ret
.no:
    mov eax, 1
    ret

updc_valid:
    push rbx
    mov rbx, rdi
    cmp dword [rdi], 'PUDC'
    jne .bad
    cmp word [rdi+4], 1
    jne .bad
    cmp word [rdi+6], 256
    jne .bad
    cmp qword [rdi+8], 0
    je .bad
    cmp dword [rdi+80], 1
    jne .bad
    cmp byte [rdi+84], 1
    ja .bad
    mov ecx, 85
.zero:
    cmp byte [rdi+rcx], 0
    jne .bad
    inc ecx
    cmp ecx, 192
    jb .zero
    lea rdi, [rbx+16]
    lea rsi, [rel updc_token+48]
    mov edx, 64
    call memcmp
    test eax, eax
    jnz .bad
    mov rdi, rbx
    mov esi, 192
    lea rdx, [rbx+192]
    mov ecx, 64
    call node_identity_verify
    test eax, eax
    jnz .bad
    call updc_operation_current
    pop rbx
    ret
.bad:
    mov eax, -1
    pop rbx
    ret

; Clear only this synchronous operation. Keep authenticated in-boot floor and
; uncertain latch. Never clear another reentrant operation's busy/consent state.
updc_release:
    sub rsp, 8
    lea rdi, [rel updc_operation]
    xor esi, esi
    mov edx, updc_operation_end-updc_operation
    call memset
    add rsp, 8
    ret

updc_name: db 'UPDAILY CFG'
%macro WDATA_gui_settings_update_daily_policy 0
align 8, db 0
updc_floor: times 256 db 0
updc_floor_valid: db 0
updc_uncertain: db 0
align 8, db 0
updc_operation:
updc_token: times 112 db 0
updc_consent: times 40 db 0
updc_old: times 256 db 0
updc_new: times 256 db 0
updc_owner: dq 0
updc_session: dq 0
updc_choice: dd 0
updc_busy: db 0
updc_kind: db 0
updc_taken: db 0
updc_token_valid: db 0
updc_written: db 0
updc_operation_end:
%endmacro
WDATA_DEFER WDATA_gui_settings_update_daily_policy
