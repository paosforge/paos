;; MODULE sec/terminal_network_store
;; LAYER 6
;; EXPORTS terminal_network_store_load, terminal_network_store_query, terminal_network_store_snapshot, terminal_network_store_invalidate, settings_terminal_network_policy_read, settings_terminal_network_policy_save, settings_terminal_network_policy_current
;; IMPORTS sec/terminal_network_record, sec/terminal_network_gate, sec/session, fs/data_config_authority, fs/data_config_provider, boot/boot_v2_handoff, core/smp, svc/command, svc/command_auth, gui/settings_terminal_network_consent, sec/data_config_local, core/lib/sha256, hv/terminal_network
;; OWNER rc-codex-av
;; CONTEXT: bsp_only
; Native read/enforcement and fixed Settings Save backend. Defaults EMPTY.
; A trusted tools init must load before binding the broker policy callback.
; No command/device entry. Stable mapped native spans only; no guest pointers.
; Error is latched until an explicit owner-repair Save; an
; ordinary read cannot turn an invalid record into a saved empty policy.
; Floor survives invalidation, locks, volume loss and all failed loads. An
; older authentic same-owner disk record can return after reboot (accepted).
%include "core/abi/wdata.inc"

; Native command/remote/AP calls leave all private state unchanged.
tns_local:
    cmp byte [rel cmd_in_dispatch],0
    jne .no
    cmp dword [rel cmd_dispatch_depth],0
    jne .no
    cmp byte [rel command_auth_remote_active],0
    jne .no
    sub rsp,8
    call smp_current_logical
    add rsp,8
    test eax,eax
    setz al
    movzx eax,al
    ret
.no:
    xor eax,eax
    ret

; ->1 and actual R8/R9 owner/session; never a caller-provided assertion.
tns_owner:
    cmp byte [rel session_locked],0
    jne .no
    cmp byte [rel pbm_try_media],0
    jne .no
    sub rsp,8
    call session_shell_local_authority
    add rsp,8
    cmp rax,1
    jne .no
    test rdx,rdx
    jz .no
    mov r8,rax
    mov r9,rdx
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

tns_enter:
    sub rsp,8
    call tns_local
    test eax,eax
    jz .out
    cmp byte [rel tns_busy],0
    jne .no
    mov byte [rel tns_busy],1
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

; Wipe active enforcement only. NEVER clear the boot floor or an error latch.
tns_forget:
    lea rdi,[rel tns_cache]
    xor eax,eax
    mov ecx,tns_cache_end-tns_cache
    cld
    rep stosb
    cmp dword [rel tns_state],4
    je .out
    mov dword [rel tns_state],0
.out:
    ret

tns_fail:
    sub rsp,8
    mov dword [rel tns_state],4
    call tns_forget
    add rsp,8
    mov eax,-4
    ret

tns_leave:
    lea rdi,[rel tns_operation]
    xor eax,eax
    mov ecx,tns_operation_end-tns_operation
    cld
    rep stosb
    mov byte [rel tns_busy],0
    ret

; Original load owner/session plus current sealed DATA token, before/after IO.
tns_operation_current:
    sub rsp,8
    call tns_owner
    test eax,eax
    jz .no
    cmp r8,[rel tns_op_owner]
    jne .no
    cmp r9,[rel tns_op_session]
    jne .no
    lea rdi,[rel tns_op_token]
    call data_config_current
    test rax,rax
    jnz .no
    call tns_owner                    ; final owner after DATA role sampling
    test eax,eax
    jz .no
    cmp r8,[rel tns_op_owner]
    jne .no
    cmp r9,[rel tns_op_session]
    jne .no
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

; load(void)->0 authenticated,1 confirmed missing,-1 context refused,-2 busy,
; -4 visible load error. No auto-retry/reconcile after an invalid load.
terminal_network_store_load:
    push rbx
    call tns_local
    test eax,eax
    jz .refused
    cmp byte [rel tns_busy],0
    jne .busy
    call tns_enter
    test eax,eax
    jz .refused
    mov ebx,-1
    call tns_owner
    test eax,eax
    jz .lost
    cmp dword [rel tns_state],4
    je .error
    cmp dword [rel tns_state],3
    je .session_only
    mov [rel tns_op_owner],r8
    mov [rel tns_op_session],r9
    lea rdi,[rel tns_op_token]
    call data_config_acquire_provisioned
    cmp rax,-2
    je .provider_busy
    test rax,rax
    jnz .error
    call tns_operation_current
    test eax,eax
    jz .error
    lea rdi,[rel tns_op_token]
    lea rsi,[rel tns_name]
    lea rdx,[rel tns_record]
    mov ecx,4192
    call data_config_read
    cmp rax,-4
    je .missing
    cmp rax,4192
    jne .error
    ; Authenticate and consume THIS private copy; never re-read caller/media
    ; bytes between verification and installing names/revision.
    lea rdi,[rel tns_record]
    mov esi,4192
    call terminal_network_record_open
    cmp eax,1
    jne .error
    mov rax,[rel tns_record+24]
    cmp rax,[rel tns_floor+24]
    jb .error                         ; retained whole-boot revision floor
    ja .validated
    lea rdi,[rel tns_record]
    lea rsi,[rel tns_floor]
    mov ecx,4192
    cld
    repe cmpsb                        ; equal revision requires exact record
    jne .error
.validated:
    call tns_operation_current
    test eax,eax
    jz .error
    lea rdi,[rel tns_floor]
    lea rsi,[rel tns_record]
    mov ecx,4192
    cld
    rep movsb
    lea rdi,[rel tns_cache]
    lea rsi,[rel tns_record]
    mov ecx,4192
    rep movsb
    mov dword [rel tns_state],2
    xor ebx,ebx
    jmp .install_identity
.missing:
    call tns_operation_current
    test eax,eax
    jz .error
    cmp qword [rel tns_floor+24],0
    jne .error                        ; disappearance cannot erase a revoke
    call tns_forget
    mov dword [rel tns_state],1
    mov ebx,1
.install_identity:
    lea rdi,[rel tns_token]
    lea rsi,[rel tns_op_token]
    mov ecx,112
    cld
    rep movsb
    mov rax,[rel tns_op_owner]
    mov [rel tns_owner_pid],rax
    mov rax,[rel tns_op_session]
    mov [rel tns_owner_session],rax
    ; Final currentness after publication; failure erases the entire cache.
    call tns_operation_current
    test eax,eax
    jz .error
    jmp .leave
.lost:
    call tns_forget
    jmp .leave
.session_only:
    mov ebx,-3
    jmp .leave
.provider_busy:
    ; Do not keep an old list after an attempted refresh whose current DATA
    ; role cannot be proven. Busy is explicit, never a cached-success result.
    call tns_forget
    mov ebx,-2
    jmp .leave
.error:
    call tns_fail
    mov ebx,eax
.leave:
    call tns_leave
    mov eax,ebx
    pop rbx
    ret
.busy:
    mov eax,-2
    pop rbx
    ret
.refused:
    mov eax,-1
    pop rbx
    ret

; Cache is bound to the original owner/session and actual sealed DATA role.
; Every query/snapshot authenticates the same private cache again, so owner
; generation/reset/key drift refuses even before the next attempted reload.
tns_cache_current:
    sub rsp,8
    call tns_owner
    test eax,eax
    jz .lost
    cmp r8,[rel tns_owner_pid]
    jne .lost
    cmp r9,[rel tns_owner_session]
    jne .lost
    lea rdi,[rel tns_token]
    call data_config_current
    test rax,rax
    jnz .error
    cmp dword [rel tns_state],1
    je .yes
    lea rdi,[rel tns_cache]
    mov esi,4192
    call terminal_network_record_open
    cmp eax,1
    jne .error
    mov rax,[rel tns_cache+24]
    cmp rax,[rel tns_floor+24]
    jb .error
.yes:
    lea rdi,[rel tns_token]
    call data_config_current
    test rax,rax
    jnz .error
    call tns_owner                    ; final role check may have lost owner
    test eax,eax
    jz .lost
    cmp r8,[rel tns_owner_pid]
    jne .lost
    cmp r9,[rel tns_owner_session]
    jne .lost
    mov eax,1
    jmp .out
.lost:
    call tns_forget
    xor eax,eax
    jmp .out
.error:
    call tns_fail
    xor eax,eax
.out:
    add rsp,8
    ret

; Refuse null/wrapping/private-overlap spans BEFORE dereference/copy. The
; caller additionally owns mapped native memory, immutable across this call.
tns_span:
    test rdi,rdi
    jz .no
    mov rax,rdi
    add rax,rsi
    jc .no
    lea rdx,[rel tns_private_end]
    cmp rdi,rdx
    jae .yes
    lea rdx,[rel tns_private_begin]
    cmp rax,rdx
    ja .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; query(RDI hostname,ESI1..253)->nonzero revision only for an exact currently
; authenticated owner entry. Empty defaults/missing/error/unloaded deny all.
; This is the broker's immutable native policy callback, never a guest API.
terminal_network_store_query:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13d,esi
    xor ebx,ebx
    test esi,esi
    jz .out
    cmp esi,253
    ja .out
    mov esi,r13d
    call tns_span
    test eax,eax
    jz .out
    call tns_enter
    test eax,eax
    jz .out
    cmp dword [rel tns_state],2
    je .current
    cmp dword [rel tns_state],3
    jne .leave
.current:
    call tns_cache_current
    test eax,eax
    jz .leave
    lea rdi,[rel tns_host]
    mov rsi,r12
    mov edx,r13d
    call terminal_network_host_canon
    cmp eax,-1
    je .leave
    mov r13d,eax
    xor r12d,r12d
.next:
    movzx eax,word [rel tns_cache+12]
    cmp r12d,eax
    jae .leave
    mov eax,r12d
    shl eax,8
    lea rsi,[rel tns_cache+64]
    add rsi,rax
    movzx eax,byte [rsi]
    cmp eax,r13d
    jne .advance
    inc rsi
    lea rdi,[rel tns_host]
    mov ecx,r13d
    cld
    repe cmpsb
    jne .advance
    call tns_cache_current          ; fresh identity/role before permission
    test eax,eax
    jz .leave
    mov rbx,[rel tns_cache+24]
    jmp .leave
.advance:
    inc r12d
    jmp .next
.leave:
    call tns_leave
.out:
    mov rax,rbx
    pop r13
    pop r12
    pop rbx
    ret

; snapshot(RDI out4096,RSI out32meta)->0 loaded/1 missing/-1 refused/-2 busy/
; -3 Session only with candidate, -4 load error. Presentation only. On an
; admitted error, clear names and emit state4; final context loss wipes both.
terminal_network_store_snapshot:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    mov esi,4096
    call tns_span
    test eax,eax
    jz .refused
    mov rdi,r13
    mov esi,32
    call tns_span
    test eax,eax
    jz .refused
    lea rax,[r12+4096]
    cmp r13,rax
    jae .spans
    lea rax,[r13+32]
    cmp r12,rax
    jb .refused
.spans:
    call tns_local
    test eax,eax
    jz .refused
    cmp byte [rel tns_busy],0
    jne .busy
    call tns_enter
    test eax,eax
    jz .refused
    mov ebx,-4
    cmp dword [rel tns_state],1
    je .current
    cmp dword [rel tns_state],2
    je .current
    cmp dword [rel tns_state],3
    jne .empty
.current:
    call tns_cache_current
    test eax,eax
    jz .empty
    mov ebx,[rel tns_state]
    cmp ebx,2
    je .copy
    cmp ebx,3
    je .copy
    mov ebx,1
    jmp .empty
.copy:
    lea rsi,[rel tns_cache+64]
    mov rdi,r12
    mov ecx,4096
    cld
    rep movsb
    xor ebx,ebx
    cmp dword [rel tns_state],3
    jne .meta
    mov ebx,-3
    jmp .meta
.empty:
    mov rdi,r12
    mov ecx,4096
    xor eax,eax
    cld
    rep stosb
.meta:
    mov rdi,r13
    mov ecx,32
    xor eax,eax
    rep stosb
    mov eax,[rel tns_state]
    mov [r13+4],eax
    cmp eax,2
    je .names_meta
    cmp eax,3
    jne .final
.names_meta:
    movzx eax,word [rel tns_cache+12]
    mov [r13],eax
    mov rax,[rel tns_cache+24]
    mov [r13+8],rax
    mov [r13+24],rax
    mov rax,[rel tns_cache+16]
    mov [r13+16],rax
.final:
    call tns_owner
    test eax,eax
    jz .lost
    cmp dword [rel tns_state],3
    je .final_current
    test ebx,ebx
    js .leave
.final_current:
    call tns_cache_current
    test eax,eax
    jnz .leave
.lost:
    mov rdi,r12
    xor eax,eax
    mov ecx,4096
    cld
    rep stosb
    mov rdi,r13
    mov ecx,32
    rep stosb
    call tns_forget
    mov ebx,-1
.leave:
    call tns_leave
    mov eax,ebx
    jmp .out
.busy:
    mov eax,-2
    jmp .out
.refused:
    mov eax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Lifecycle invalidation fences policy synchronously; caller separately retires
; broker cookies from its serialized BSP site (never recurse from a callback).
; ->EAX1 fenced (also already empty), or0 refused/active operation. Native local
; lifecycle can fence a locked/lost owner; no ended-session authority required.
terminal_network_store_invalidate:
    sub rsp,8
    call tns_enter
    test eax,eax
    jz .out
    call tns_forget
    call tns_leave
    mov eax,1                 ; permission fenced, floor/latch retained
.out:
    add rsp,8
    ret

; Presentation read never takes consent, writes, repairs or clears a latch.
settings_terminal_network_policy_read:
    jmp terminal_network_store_snapshot

; Fixed per-effect DATA checker. No caller-supplied tuple/callback creates
; authority. Recheck owner after both GUI and sealed DATA role sampling.
settings_terminal_network_policy_current:
    sub rsp,8
    cmp byte [rel tns_busy],1
    jne .no
    cmp byte [rel tns_save_active],1
    jne .no
    cmp byte [rel tns_taken],1
    jne .no
    call tns_local
    test eax,eax
    jz .no
    call tns_owner
    test eax,eax
    jz .no
    cmp r8,[rel tns_op_owner]
    jne .no
    cmp r9,[rel tns_op_session]
    jne .no
    lea rdi,[rel tns_consent]
    call settings_terminal_network_consent_current
    cmp eax,1
    jne .no
    cmp byte [rel tns_token_valid],1
    jne .owner
    lea rdi,[rel tns_op_token]
    call data_config_current
    test rax,rax
    jnz .no
.owner:
    cmp byte [rel tns_record_ready],1
    jne .owner_final
    lea rdi,[rel tns_record]
    mov esi,4192
    call terminal_network_record_open     ; owner generation/reset at every effect
    cmp eax,1
    jne .no
.owner_final:
    call tns_owner
    test eax,eax
    jz .no
    cmp r8,[rel tns_op_owner]
    jne .no
    cmp r9,[rel tns_op_session]
    jne .no
    xor eax,eax
    jmp .out
.no:
    mov eax,-1
.out:
    add rsp,8
    ret

; No arguments: actual GUI's one original gesture + private candidate only.
; 0 Saved requires exact independent reopen/authentication/current consent;
; -1 refused, -2 busy before admission, -3 admitted choice not confirmed saved.
; A fresh explicit Save can repair a load-error latch. No retry or reload of
; old names after admission. All broker connections are fenced before write.
settings_terminal_network_policy_save:
    push rbx
    push r12
    sub rsp,8
    call tns_local
    test eax,eax
    jz .refused
    cmp byte [rel tns_busy],0
    jne .busy
    call tns_enter
    test eax,eax
    jz .refused
    mov ebx,-1
    xor r12d,r12d                     ; independently confirmed saved flag
    call tns_owner
    test eax,eax
    jz .leave
    mov [rel tns_op_owner],r8
    mov [rel tns_op_session],r9
    mov byte [rel tns_save_active],1
    lea rdi,[rel tns_consent]
    lea rsi,[rel tns_record+64]
    call settings_terminal_network_consent_take
    cmp eax,1
    jne .leave
    mov byte [rel tns_taken],1
    mov rax,[rel tns_consent]
    test rax,rax
    jz .finish
    cmp rax,-1
    je .finish
    mov rax,[rel tns_op_owner]
    cmp rax,[rel tns_consent+8]
    jne .finish
    mov rax,[rel tns_op_session]
    cmp rax,[rel tns_consent+16]
    jne .finish
    cmp qword [rel tns_consent+24],0
    je .finish
    cmp dword [rel tns_consent+32],16
    ja .finish
    cmp dword [rel tns_consent+36],1
    jne .finish
    cmp qword [rel tns_consent+72],0
    jne .finish
    lea rdi,[rel tns_digest]
    lea rsi,[rel tns_record+64]
    mov edx,4096
    call sha256_hash
    test eax,eax
    jnz .finish
    lea rdi,[rel tns_digest]
    lea rsi,[rel tns_consent+40]
    mov ecx,32
    cld
    repe cmpsb
    jne .finish
    call settings_terminal_network_policy_current
    test eax,eax
    jnz .finish
    lea rdi,[rel tns_op_token]
    call data_config_acquire_provisioned
    cmp rax,-2
    je .provider_busy
    test rax,rax
    jnz .finish
    mov byte [rel tns_token_valid],1
    call settings_terminal_network_policy_current
    test eax,eax
    jnz .finish
    lea rdi,[rel tns_op_token]
    lea rsi,[rel tns_name]
    lea rdx,[rel tns_check]
    mov ecx,4192
    call data_config_read
    cmp rax,-4
    je .floor
    test rax,rax
    js .read_failed
    cmp rax,4192
    ja .read_failed
    jne .floor                       ; fresh explicit repair of readable damage
    lea rdi,[rel tns_check]
    mov esi,4192
    call terminal_network_record_open
    cmp eax,1
    jne .floor                       ; never treat corrupt bytes as saved empty
    mov r12,[rel tns_check+24]
.floor:
    mov rax,[rel tns_floor+24]
    cmp r12,rax
    cmovb r12,rax
    cmp r12,-2
    jae .finish
    inc r12
    lea rdi,[rel tns_record]
    mov esi,[rel tns_consent+32]
    mov rdx,r12
    call terminal_network_record_header
    cmp eax,1
    jne .finish
    lea rdi,[rel tns_record]
    mov esi,4192
    call terminal_network_record_seal
    cmp eax,1
    jne .finish
    mov byte [rel tns_record_ready],1
    call settings_terminal_network_policy_current
    test eax,eax
    jnz .finish
    ; Commit the RAM revocation before persistence, keeping the private new
    ; record even on uncertainty. Never reload removed saved names this boot.
    lea rdi,[rel tns_floor]
    lea rsi,[rel tns_record]
    mov ecx,4192
    cld
    rep movsb
    mov byte [rel tns_admitted],1
    call tns_forget
    call terminal_network_retire       ; serialized BSP caller, no callback recursion
    call settings_terminal_network_policy_current
    test eax,eax
    jnz .uncertain
    lea rdi,[rel tns_cache]
    lea rsi,[rel tns_record]
    mov ecx,4192
    cld
    rep movsb
    lea rdi,[rel tns_token]
    lea rsi,[rel tns_op_token]
    mov ecx,112
    rep movsb
    mov rax,[rel tns_op_owner]
    mov [rel tns_owner_pid],rax
    mov rax,[rel tns_op_session]
    mov [rel tns_owner_session],rax
    mov dword [rel tns_state],3
    call settings_terminal_network_policy_current
    test eax,eax
    jnz .uncertain
    lea rdi,[rel tns_op_token]
    lea rsi,[rel tns_name]
    lea rdx,[rel tns_record]
    mov ecx,4192
    mov r8,[rel tns_op_owner]
    mov r9,[rel tns_op_session]
    call data_config_write_terminal_network ; one attempt; fixed sec checker per effect
    test rax,rax
    jnz .uncertain
    call settings_terminal_network_policy_current
    test eax,eax
    jnz .uncertain
    ; Independent reopen into a different private buffer, exact whole-file
    ; byte count, actual owner authentication, exact candidate and live consent.
    lea rdi,[rel tns_op_token]
    lea rsi,[rel tns_name]
    lea rdx,[rel tns_check]
    mov ecx,4192
    call data_config_read
    cmp rax,4192
    jne .uncertain
    lea rdi,[rel tns_check]
    mov esi,4192
    call terminal_network_record_open
    cmp eax,1
    jne .uncertain
    lea rdi,[rel tns_check]
    lea rsi,[rel tns_record]
    mov ecx,4192
    cld
    repe cmpsb
    jne .uncertain
    call settings_terminal_network_policy_current
    test eax,eax
    jnz .uncertain
.confirmed_saved:
    mov ebx,0
    mov r12d,1
    jmp .finish
.read_failed:
    call tns_fail
    jmp .finish
.provider_busy:
    call tns_forget
    mov ebx,-2
    jmp .finish
.uncertain:
    mov ebx,-3
    xor r12d,r12d
.finish:
    cmp byte [rel tns_taken],1
    jne .leave
    lea rdi,[rel tns_consent]
    call settings_terminal_network_consent_finish
    cmp eax,1
    je .finished
    mov ebx,-1
    xor r12d,r12d
.finished:
    cmp byte [rel tns_admitted],1
    jne .leave
    mov ebx,-3
    ; Consent retirement cannot hide owner/volume/key loss at final return.
    call tns_cache_current
    test eax,eax
    jz .leave
    test r12d,r12d
    jz .leave
    mov dword [rel tns_state],2
    xor ebx,ebx
.leave:
    call tns_leave
    mov eax,ebx
    jmp .out
.busy:
    mov eax,-2
    jmp .out
.refused:
    mov eax,-1
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

tns_name: db 'TERMNET CFG'
%macro WDATA_BSS_sec_terminal_network_store 0
alignb 16
tns_private_begin:
tns_floor: resb 4192
tns_cache: resb 4192
tns_token: resb 112
tns_owner_pid: resq 1
tns_owner_session: resq 1
tns_cache_end:
tns_state: resd 1                     ;0unloaded,1missing,2saved,3session only,4load error
tns_busy: resb 1
alignb 8
tns_operation:
tns_op_token: resb 112
tns_op_owner: resq 1
tns_op_session: resq 1
tns_record: resb 4192
tns_host: resb 256
tns_consent: resb 80
tns_check: resb 4192
tns_digest: resb 32
tns_save_active: resb 1
tns_taken: resb 1
tns_token_valid: resb 1
tns_admitted: resb 1
tns_record_ready: resb 1
tns_operation_end:
tns_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_terminal_network_store
