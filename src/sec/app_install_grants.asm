;; MODULE sec/app_install_grants
;; LAYER 6
;; PURPOSE Remember exact owner-selected install policy without reusing VM authority.
;; EXPORTS app_install_grants_preebs, app_install_grants_save, app_install_grants_restore, app_install_grants_revoke_durable, app_install_grants_init, app_install_grants_remember, app_install_grants_lookup, app_install_grants_revoke, app_install_grants_runtime, app_install_grants_room, app_install_grants_requested
;; IMPORTS sec/app_grants, sec/app_binding, sec/session, svc/app_script, svc/app_package, svc/app_analysis, svc/command, core/smp
;; OWNER saga:app_grants
;; CONTEXT: bsp_only
; Native-only cooperative BSP API. INPUT must prove its actual human install
; intent and successful owned installation before remember; no guest setter.
; The RAM rows survive binding retirement/lock, not machine reboot. Consent that
; survives reboot lives only in PaOSAppGrants below, never in any disk record.
; PaOSAppGrants: exact432, NV|BS|RT, PaOS data/config GUID, HMAC-SHA256 under
; HMAC(HKDF(Z, own label), sealed owner password block), so no runtime OS can forge
; a row and another owner reads the store as empty. Disk access alone cannot
; change consent. Residual: an OS booted on this machine can read the variable and
; later put back an older copy (a revoked grant returns) or delete it (new cards).
; Pre-EBS code or SPI access reads Z and can forge, as for the owner record.
IG_ROWS equ 8
IG_ROW_BYTES equ 80
IG_OWNER_PW_BYTES equ 52                ; PRIN_OWNER_PW_LEN: iterations, salt, verifier
IG_TOMBS equ 8
IG_TOMB_BYTES equ 40                    ; profile8, analysis hash32
IG_SCRIPT equ 1
IG_PACKAGE equ 2
IGS_BYTES equ 432
IGS_ROWS equ 8
IGS_ROW_BYTES equ 48
IGS_ROW0 equ 16
IGS_MAC equ 400
IGS_MAGIC equ 'PAGR'
IGS_ATTRS equ 7
IGS_NOT_FOUND equ 0x800000000000000e
IGS_TOO_SMALL equ 0x8000000000000005

; init()->1/0, depth-zero native composition after app_binding configuration.
; No remembered record or effective grant is created by initialization.
app_install_grants_init:
    call ig_enter
    test eax,eax
    jz ig_bad
    cmp byte [rel cmd_in_dispatch],0
    jne ig_fail
    lea rdi,[rel app_install_grants_runtime]
    call app_grants_configure_installed
    jmp ig_return

; remember(handle, profile1script/2sharing, selected4, owner_epoch,
;          exact_analysis192_or0)->nonreused approval id/0.
; Sharing requires current exact scanner report, including current registry.
; Four request bytes come from the verifier's indexed immutable grants member.
; Manifest requests alone never become effective policy.
app_install_grants_remember:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14,rcx
    mov r15,r8
    mov rbx,rdx
    call ig_enter
    test eax,eax
    jz .out
    call ig_owner
    test eax,eax
    jz .fail
    cmp rdx,r14
    jne .fail
    mov rdi,rbx
    mov esi,4
    call ig_disjoint
    test eax,eax
    jz .fail
    mov eax,[rbx]
    mov [rel ig_selected],eax
    cmp qword [rel ig_serial],-1
    je .fail
    cmp qword [rel ag_generation],-2
    jae .fail
    mov [rel ig_handle],r12
    mov [rel ig_profile],r13
    cmp r13,IG_SCRIPT
    je .legacy
    cmp r13,IG_PACKAGE
    jne .fail
    mov rdi,r15
    mov esi,192
    call ig_disjoint
    test eax,eax
    jz .fail
    mov rdi,r12
    mov rsi,r15
    call app_analysis_check
    cmp eax,1
    jne .fail
    jmp .load
.legacy:
    test r15,r15
    jnz .fail
.load:
    call ig_load
    test eax,eax
    jz .fail
    xor ecx,ecx
.choices:
    lea rdx,[rel ig_selected]
    movzx eax,byte [rdx+rcx]
    cmp eax,2
    ja .fail
    lea rdx,[rel ig_requested]
    cmp byte [rdx+rcx],0
    jne .next_choice
    test eax,eax
    jnz .fail
.next_choice:
    inc ecx
    cmp ecx,4
    jb .choices
    call ig_publish
    jmp .done
.fail:
    xor eax,eax
.done:
    mov byte [rel ig_busy],0
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; lookup(handle,profile,out4,exact4)->approval id/0, output unchanged on refusal.
; Re-staging identical bytes after lock is permitted; handle/epoch are not the
; remembered identity. New VM proof is still required at every runtime use.
app_install_grants_lookup:
    push rbx
    push r12
    mov r12,rdx
    mov rbx,rcx
    push rdi
    push rsi
    call ig_enter
    pop rsi
    pop rdi
    test eax,eax
    jz .out
    mov [rel ig_handle],rdi
    mov [rel ig_profile],rsi
    cmp rbx,4
    jne .fail
    mov rdi,r12
    mov esi,4
    call ig_disjoint
    test eax,eax
    jz .fail
    call ig_owner
    test eax,eax
    jz .fail
    call ig_load
    test eax,eax
    jz .fail
    call ig_find
    test rax,rax
    jz .fail
    mov ecx,[rax+52]
    mov rax,[rax]
    mov [r12],ecx
    jmp .done
.fail:
    xor eax,eax
.done:
    mov byte [rel ig_busy],0
.out:
    pop r12
    pop rbx
    ret

; requested(handle,profile,out4,exact4)->1/0. Read only, for INPUT's card; no consent
; is touched and the bytes come from the verifier's indexed immutable member.
; RDI verifier handle, RSI profile -> EAX 1 when remember would find this candidate's row or a free
; one, 2 when every row holds another app, 0 refused. Read-only, so an install past the row bound
; refuses before anything is stored (SEC I4-C8).
app_install_grants_room:
    push r12
    mov r12,rsi
    mov r8,rdi
    call ig_enter
    test eax,eax
    jz .refused
    mov [rel ig_handle],r8
    mov [rel ig_profile],r12
    call ig_owner
    test eax,eax
    jz .fail
    call ig_load
    test eax,eax
    jz .fail
    call ig_find
    test rax,rax
    jnz .room
    lea rax,[rel ig_rows]
    mov ecx,IG_ROWS
.free:
    cmp qword [rax],0
    je .room
    add rax,IG_ROW_BYTES
    loop .free
    mov byte [rel ig_busy],0
    mov eax,2
    pop r12
    ret
.fail:
    mov byte [rel ig_busy],0
.refused:
    xor eax,eax
    pop r12
    ret
.room:
    mov byte [rel ig_busy],0
    mov eax,1
    pop r12
    ret

app_install_grants_requested:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    mov rbx,rdx
    cmp rcx,4
    jne ig_requested_bad
    mov rdi,rbx
    mov esi,4
    call ig_disjoint
    test eax,eax
    jz ig_requested_bad
    call ig_enter
    test eax,eax
    jz ig_requested_bad
    mov [rel ig_handle],r12
    mov [rel ig_profile],r13
    call ig_owner
    test eax,eax
    jz ig_requested_fail
    call ig_load
    test eax,eax
    jz ig_requested_fail
    mov eax,[rel ig_requested]
    mov [rbx],eax
    mov byte [rel ig_busy],0
    mov eax,1
    jmp ig_requested_out
ig_requested_fail:
    mov byte [rel ig_busy],0
ig_requested_bad:
    xor eax,eax
ig_requested_out:
    pop r13
    pop r12
    pop rbx
    ret

; revoke(approval id,owner epoch)->1/0. Actual owner UI chooses this native id.
; An exact revocation clears remembered policy and live standing/ASK authority.
app_install_grants_revoke:
    push rbx
    push r12
    mov rbx,rdi
    mov r12,rsi
    call ig_enter
    test eax,eax
    jz .out
    call ig_owner
    test eax,eax
    jz .fail
    cmp rdx,r12
    jne .fail
    test rbx,rbx
    jz .fail
    cmp qword [rel ag_generation],-2
    jae .fail
    lea rdi,[rel ig_rows]
    mov ecx,IG_ROWS
.scan:
    cmp [rdi],rbx
    je .found
    add rdi,IG_ROW_BYTES
    loop .scan
    jmp .fail
.found:
    xor eax,eax
    mov ecx,IG_ROW_BYTES/8
    cld
    rep stosq
    call app_grants_revoke
    mov eax,1
    jmp .done
.fail:
    xor eax,eax
.done:
    mov byte [rel ig_busy],0
.out:
    pop r12
    pop rbx
    ret

; Native grant-store fallback only, desc160 ->policy0..2/generation or0/0.
; Full actual current VM/bundle/window/session proof, never a caller hash claim.
; Complete verified file digest binds its exact requested-grants member too.
; The same approval may authorize a NEW proved instance, never an old START.
app_install_grants_runtime:
    push rbx
    mov rbx,rdi
    call ig_enter
    test eax,eax
    jz .bad
    mov rdi,rbx
    call app_binding_validate
    cmp eax,1
    jne .fail
    cmp qword [rel session_bound_pid],PRIN_OWNER
    jne .fail
    mov rcx,[rbx+120]
    dec rcx
    cmp rcx,3
    ja .fail
    mov [rel ig_operation],rcx
    lea r8,[rel ig_rows]
    mov r9d,IG_ROWS
.scan:
    cmp qword [r8],0
    je .next
    cmp qword [r8+8],PRIN_OWNER
    jne .next
    lea rdi,[r8+16]
    lea rsi,[rbx+88]
    mov ecx,4
    cld
    repe cmpsq
    je .found
.next:
    add r8,IG_ROW_BYTES
    dec r9d
    jnz .scan
.fail:
    xor eax,eax
    xor edx,edx
    jmp .done
.found:
    mov rcx,[rel ig_operation]
    movzx eax,byte [r8+52+rcx]
    mov rdx,[rel ag_generation]
.done:
    mov byte [rel ig_busy],0
    pop rbx
    ret
.bad:
    xor eax,eax
    xor edx,edx
    pop rbx
    ret

ig_bad:
    xor eax,eax
    ret
ig_fail:
    xor eax,eax
ig_return:
    mov byte [rel ig_busy],0
    ret

; ig_selected + ig_requested + loaded descriptor -> published row id / 0.
ig_publish:
    call ig_find
    test rax,rax
    jnz .slot
    lea rax,[rel ig_rows]
    mov ecx,IG_ROWS
.free:
    cmp qword [rax],0
    je .slot
    add rax,IG_ROW_BYTES
    loop .free
    xor eax,eax
    ret
.slot:
    mov rbx,rax
    call app_grants_revoke             ; cancels ASK before any policy change
    inc qword [rel ig_serial]
    mov rdi,rbx
    xor eax,eax
    mov ecx,IG_ROW_BYTES/8
    cld
    rep stosq
    mov qword [rbx+8],PRIN_OWNER
    lea rsi,[rel ig_descriptor+32]
    lea rdi,[rbx+16]
    mov ecx,4
    rep movsq
    mov eax,[rel ig_requested]
    mov [rbx+48],eax
    mov eax,[rel ig_selected]
    mov [rbx+52],eax
    mov rax,[rel ig_profile]
    mov [rbx+56],rax
    mov rax,[rel ig_serial]
    mov [rbx],rax                      ; publish only fully initialized record
    ret

; A new owner inherits nothing (root 89985): the record's MAC key also binds this
; boot's sealed owner password block, so any other credential reads the store as empty.
; The machine cannot tell a handover from a password change, so both ask again.
; preebs(), after owner_stage_key_preebs and before owner_store_preebs discards
; Z. No Z leaves no key: nothing is restored or saved this boot.
app_install_grants_preebs:
    lea rdi,[rel ig_store_info]
    mov esi,ig_store_info.len
    lea rdx,[rel app_install_grants_mac_key]
    call owner_stage_key_hkdf
    cmp eax,1
    sete al
    mov [rel ig_key_ready],al
    ret

; save(handle,profile,owner_epoch,exact_analysis192_or0)->1 durable/0. Call after
; remember. On 0 the RAM grant still applies until restart; the caller says so.
app_install_grants_save:
    push rbx
    push r12
    call ig_store_admit
    test eax,eax
    jz .out
    call ig_find
    test rax,rax
    jz .fail
    mov r12,rax
    cmp byte [rel ig_tomb_full],0
    jne .fail
    call ig_store_load
    test eax,eax
    jz .fail
    lea rdi,[rel ig_stage]
    lea rsi,[rel ig_saved]
    mov ecx,IGS_BYTES/8
    cld
    rep movsq
    call ig_tomb_strip
    lea rdi,[rel ig_stage]
    call ig_store_find
    test rax,rax
    jnz .row
    lea rax,[rel ig_stage+IGS_ROW0]
    mov ecx,IGS_ROWS
.free_row:
    cmp dword [rax+40],0
    je .row
    add rax,IGS_ROW_BYTES
    loop .free_row
    jmp .fail
.row:
    lea rsi,[r12+16]
    mov rdi,rax
    mov ecx,5
    rep movsq                          ; hash32, requested4, selected4
    mov rcx,[rel ig_profile]
    mov [rdi],ecx
    mov eax,[rel ig_versions]
    mov [rdi+4],eax
    call ig_store_write
    test eax,eax
    jz .done
    call ig_tomb_lift                  ; the owner consented again and it is stored
    mov eax,1
    jmp .done
.fail:
    xor eax,eax
.done:
    mov byte [rel ig_busy],0
.out:
    pop r12
    pop rbx
    ret

; restore(handle,profile,owner_epoch,exact_analysis192_or0)->approval id/0. Caller
; has verified and analyzed the stored bytes; only an authenticated row for those
; exact bytes, requests and versions is consent. Anything else is 0: a new card.
app_install_grants_restore:
    push rbx
    push r12
    call ig_store_admit
    test eax,eax
    jz .out
    cmp qword [rel ig_serial],-1
    je .fail
    cmp qword [rel ag_generation],-2
    jae .fail
    cmp byte [rel ig_tomb_full],0
    jne .fail
    call ig_tomb_find
    test rax,rax
    jnz .fail
    call ig_store_load
    test eax,eax
    jz .fail
    lea rdi,[rel ig_saved]
    call ig_store_find
    test rax,rax
    jz .fail
    mov edx,[rel ig_requested]
    cmp [rax+32],edx
    jne .fail
    mov edx,[rel ig_versions]
    cmp [rax+44],edx
    jne .fail
    mov edx,[rax+36]
    mov [rel ig_selected],edx
    xor ecx,ecx
.selected:
    lea rdx,[rel ig_selected]
    movzx eax,byte [rdx+rcx]
    cmp eax,2
    ja .fail
    lea rdx,[rel ig_requested]
    or al,[rdx+rcx]
    jz .row_ok
    cmp byte [rdx+rcx],0
    je .fail
.row_ok:
    inc ecx
    cmp ecx,4
    jb .selected
    call ig_publish
    jmp .done
.fail:
    xor eax,eax
.done:
    mov byte [rel ig_busy],0
.out:
    pop r12
    pop rbx
    ret

; revoke_durable(approval id,owner epoch)->1 storage holds no authentic row for it
; (a tampered variable counts as none)/2 revoked now and for this boot, the store did
; not confirm, so it may return after restart/0 refused, nothing changed.
; The variable goes first: a cut after it cannot leave the consent to come back.
app_install_grants_revoke_durable:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov r13d,1
    call ig_enter
    test eax,eax
    jz .refused
    call ig_owner
    test eax,eax
    jz .refused_busy
    cmp rdx,r12
    jne .refused_busy
    test rbx,rbx
    jz .refused_busy
    cmp qword [rel ag_generation],-2
    jae .refused_busy
    lea r8,[rel ig_rows]
    mov ecx,IG_ROWS
.scan:
    cmp [r8],rbx
    je .found
    add r8,IG_ROW_BYTES
    loop .scan
    jmp .refused_busy
.found:
    mov rax,[r8+56]
    mov [rel ig_profile],rax
    lea rdi,[rel ig_descriptor+32]
    lea rsi,[r8+16]
    mov ecx,4
    cld
    rep movsq
    call ig_store_load
    test eax,eax
    jz .unsure
    lea rdi,[rel ig_stage]
    lea rsi,[rel ig_saved]
    mov ecx,IGS_BYTES/8
    rep movsq
    lea rdi,[rel ig_stage]
    call ig_store_find
    test rax,rax
    jz .ram
.wipe_row:
    mov rdi,rax
    xor eax,eax
    mov ecx,IGS_ROW_BYTES/8
    rep stosq
    lea rdi,[rel ig_stage]
    call ig_store_find
    test rax,rax
    jnz .wipe_row
    call ig_tomb_strip
    call ig_store_write
    test eax,eax
    jnz .ram
.unsure:
    mov r13d,2
    call ig_tomb_add
.ram:
    mov byte [rel ig_busy],0
    mov rdi,rbx
    mov rsi,r12
    call app_install_grants_revoke
    cmp eax,1
    je .result
    mov r13d,2                         ; the variable changed, RAM did not: say so
.result:
    mov eax,r13d
    jmp .out
.refused_busy:
    mov byte [rel ig_busy],0
.refused:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; An unconfirmed revoke stays gone for this boot: restore refuses its bytes and no
; later write carries its row back. Only a stored new consent lifts it. A full table
; refuses every restore and save until restart. RAM only: result 2 still says restart.
; ->rax tombstone for ig_profile and the ig_descriptor hash/0.
ig_tomb_find:
    lea r8,[rel ig_tombs]
    mov r9d,[rel ig_tomb_count]
.scan:
    test r9d,r9d
    jz .none
    mov rax,[r8]
    cmp rax,[rel ig_profile]
    jne .next
    lea rdi,[r8+8]
    lea rsi,[rel ig_descriptor+32]
    mov ecx,4
    cld
    repe cmpsq
    jne .next
    mov rax,r8
    ret
.next:
    add r8,IG_TOMB_BYTES
    dec r9d
    jmp .scan
.none:
    xor eax,eax
    ret

ig_tomb_add:
    call ig_tomb_find
    test rax,rax
    jnz .out
    mov eax,[rel ig_tomb_count]
    cmp eax,IG_TOMBS
    jae .full
    imul eax,eax,IG_TOMB_BYTES
    lea rdi,[rel ig_tombs]
    add rdi,rax
    mov rax,[rel ig_profile]
    mov [rdi],rax
    add rdi,8
    lea rsi,[rel ig_descriptor+32]
    mov ecx,4
    cld
    rep movsq
    inc dword [rel ig_tomb_count]
.out:
    ret
.full:
    mov byte [rel ig_tomb_full],1
    ret

ig_tomb_lift:
    call ig_tomb_find
    test rax,rax
    jz .out
    mov rdi,rax
    mov eax,[rel ig_tomb_count]
    dec eax
    mov [rel ig_tomb_count],eax
    imul eax,eax,IG_TOMB_BYTES
    lea rsi,[rel ig_tombs]
    add rsi,rax
    mov ecx,IG_TOMB_BYTES/8
    cld
    rep movsq
.out:
    ret

; Clear every ig_stage row a tombstone names.
ig_tomb_strip:
    lea r8,[rel ig_stage+IGS_ROW0]
    mov r9d,IGS_ROWS
.row:
    lea r11,[rel ig_tombs]
    mov r10d,[rel ig_tomb_count]
.tomb:
    test r10d,r10d
    jz .next_row
    mov eax,[r8+40]
    cmp rax,[r11]
    jne .next_tomb
    mov rdi,r8
    lea rsi,[r11+8]
    mov ecx,4
    cld
    repe cmpsq
    jne .next_tomb
    mov rdi,r8
    xor eax,eax
    mov ecx,IGS_ROW_BYTES/8
    rep stosq
    jmp .next_row
.next_tomb:
    add r11,IG_TOMB_BYTES
    dec r10d
    jmp .tomb
.next_row:
    add r8,IGS_ROW_BYTES
    dec r9d
    jnz .row
    ret

; Admit one save/restore with busy held: RDI handle, RSI profile, RDX epoch,
; RCX analysis. Loads the verified bytes and the row's analyzer/mapping versions.
ig_store_admit:
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    call ig_enter
    test eax,eax
    jz .out
    call ig_owner
    test eax,eax
    jz .fail
    cmp rdx,r14
    jne .fail
    mov [rel ig_handle],r12
    mov [rel ig_profile],r13
    mov dword [rel ig_versions],0
    cmp r13,IG_SCRIPT
    je .legacy
    cmp r13,IG_PACKAGE
    jne .fail
    mov rdi,r15
    mov esi,192
    call ig_disjoint
    test eax,eax
    jz .fail
    mov rdi,r12
    mov rsi,r15
    call app_analysis_check
    cmp eax,1
    jne .fail
    mov rax,[r15+128]
    mov rcx,[r15+136]
    mov rdx,rax
    or rdx,rcx
    shr rdx,16
    jnz .fail
    test eax,eax
    jz .fail
    test ecx,ecx
    jz .fail
    shl ecx,16
    or eax,ecx
    mov [rel ig_versions],eax
    jmp .load
.legacy:
    test r15,r15
    jnz .fail
.load:
    call ig_load
    test eax,eax
    jz .fail
    mov eax,1
    jmp .out
.fail:
    mov byte [rel ig_busy],0
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; RDI image -> row for ig_profile + ig_descriptor hash, or RAX 0.
ig_store_find:
    lea r8,[rdi+IGS_ROW0]
    mov r9d,IGS_ROWS
.scan:
    mov eax,[r8+40]
    test eax,eax
    jz .next
    cmp rax,[rel ig_profile]
    jne .next
    mov rdi,r8
    lea rsi,[rel ig_descriptor+32]
    mov ecx,4
    cld
    repe cmpsq
    jne .next
    mov rax,r8
    ret
.next:
    add r8,IGS_ROW_BYTES
    dec r9d
    jnz .scan
    xor eax,eax
    ret

; ->1 ig_saved is what storage holds (absent, wrong shape or unauthentic is empty)
; /0 no key, no sealed owner password, no runtime services or a firmware read error.
ig_store_load:
    cmp byte [rel ig_key_ready],1
    jne .bad
    cmp byte [rel ig_store_state],1
    je .ok
    call ig_owner_bind
    test eax,eax
    jz .bad
    lea rdi,[rel ig_saved]
    call ig_store_get
    cmp eax,-2
    je .bad
    test eax,eax
    jnz .empty
    lea rdi,[rel ig_saved]
    call ig_store_valid
    test eax,eax
    jnz .ready
.empty:
    lea rdi,[rel ig_saved]
    xor eax,eax
    mov ecx,IGS_BYTES/8
    cld
    rep stosq
.ready:
    mov byte [rel ig_store_state],1
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; ->1 ig_owner_key = HMAC(key, sealed owner password block)/0 no such owner. The
; block is fixed for the boot (principal takes it once); a change applies next boot.
ig_owner_bind:
    cmp byte [rel prin_owner_pw_state],1
    jne .no
    cmp dword [rel prin_owner_pw],0
    je .no
    lea rdi,[rel ig_owner_key]
    lea rsi,[rel app_install_grants_mac_key]
    mov edx,32
    lea rcx,[rel prin_owner_pw]
    mov r8d,IG_OWNER_PW_BYTES
    call hmac_sha256
    test rax,rax
    jnz .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; RDI image -> ig_mac_out = HMAC(owner key, image[0:400]).
ig_store_mac:
    mov rcx,rdi
    lea rdi,[rel ig_mac_out]
    lea rsi,[rel ig_owner_key]
    mov edx,32
    mov r8d,IGS_MAC
    jmp hmac_sha256

ig_store_valid:
    push rbx
    mov rbx,rdi
    cmp dword [rbx],IGS_MAGIC
    jne .no
    cmp word [rbx+4],1
    jne .no
    cmp word [rbx+6],IGS_BYTES
    jne .no
    cmp qword [rbx+8],0
    jne .no
    mov rdi,rbx
    call ig_store_mac
    test eax,eax
    jnz .no
    lea rsi,[rel ig_mac_out]
    xor eax,eax
    xor ecx,ecx
.cmp:
    mov dl,[rbx+rcx+IGS_MAC]
    xor dl,[rsi+rcx]
    or al,dl
    inc ecx
    cmp ecx,32
    jb .cmp
    test al,al
    setz al
    movzx eax,al
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

; RDI out432 -> 0 read, 1 absent, -1 wrong attributes or size, -2 other failure.
ig_store_get:
    push r12
    push r13
    mov r13,rsp
    mov r10,rdi
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .failure
    mov r12,[rel runtime_services]
    test r12,r12
    jz .failure
    mov qword [rel ig_size],IGS_BYTES
    mov dword [rel ig_attrs],0
    lea rcx,[rel ig_store_name]
    lea rdx,[rel ig_store_guid]
    lea r8,[rel ig_attrs]
    lea r9,[rel ig_size]
    and rsp,-16
    sub rsp,48
    mov [rsp+32],r10
    call [r12+0x48]
    mov rsp,r13
    test rax,rax
    jz .read
    mov rdx,IGS_NOT_FOUND
    cmp rax,rdx
    je .absent
    mov rdx,IGS_TOO_SMALL
    cmp rax,rdx
    jne .failure
.wrong:
    mov eax,-1
    jmp .out
.absent:
    mov eax,1
    jmp .out
.failure:
    mov eax,-2
    jmp .out
.read:
    cmp dword [rel ig_attrs],IGS_ATTRS
    jne .wrong
    cmp qword [rel ig_size],IGS_BYTES
    jne .wrong
    xor eax,eax
.out:
    pop r13
    pop r12
    ret

; Seal ig_stage, gate, SetVariable, exact readback ->1 and ig_saved=ig_stage. Any
; failure ->0 and forgets ig_saved: firmware may have committed, so re-read.
ig_store_write:
    push r12
    push r13
    mov r13,rsp
    mov dword [rel ig_stage],IGS_MAGIC
    mov word [rel ig_stage+4],1
    mov word [rel ig_stage+6],IGS_BYTES
    mov qword [rel ig_stage+8],0
    lea rdi,[rel ig_stage]
    call ig_store_mac
    test eax,eax
    jnz .bad
    lea rdi,[rel ig_stage+IGS_MAC]
    lea rsi,[rel ig_mac_out]
    mov ecx,4
    cld
    rep movsq
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .bad
    mov r12,[rel runtime_services]
    test r12,r12
    jz .bad
    call storage_access_request_intent
    mov edx,eax
    lea rdi,[rel ig_store_guid]
    lea rsi,[rel ig_store_name]
    lea rcx,[rel ig_store_tag]
    call storage_access_nvram_require
    test rax,rax
    jnz .bad
    lea rcx,[rel ig_store_name]
    lea rdx,[rel ig_store_guid]
    mov r8d,IGS_ATTRS
    mov r9d,IGS_BYTES
    and rsp,-16
    sub rsp,48
    lea rax,[rel ig_stage]
    mov [rsp+32],rax
    call [r12+0x58]
    mov rsp,r13
    test rax,rax
    jnz .bad
    lea rdi,[rel ig_verify]
    call ig_store_get
    test eax,eax
    jnz .bad
    lea rdi,[rel ig_stage]
    lea rsi,[rel ig_verify]
    mov ecx,IGS_BYTES/8
    cld
    repe cmpsq
    jne .bad
    lea rdi,[rel ig_saved]
    lea rsi,[rel ig_stage]
    mov ecx,IGS_BYTES/8
    rep movsq
    mov byte [rel ig_store_state],1
    mov eax,1
    jmp .out
.bad:
    mov byte [rel ig_store_state],0
    xor eax,eax
.out:
    mov rsp,r13
    pop r13
    pop r12
    ret

ig_store_info: db 'PaOS/sec/app_grants/v1'
.len equ $-ig_store_info
ig_store_tag: db 'app_install_grants_store',0
align 8
; PaOS data/config vendor GUID (nvg_paos_guids #3), as sec/idle_prefs
ig_store_guid:
    dd 0x5a6ec129
    dw 0x2554,0x494c
    db 0x99,0xbd,0xb0,0x39,0x60,0xdf,0x47,0x04
ig_store_name: dw 'P','a','O','S','A','p','p','G','r','a','n','t','s',0

; Mutations/views local OWNER only; runtime uses actual binding proof instead.
ig_owner:
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    cmp rdx,-1
    je .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    xor edx,edx
    ret

ig_enter:
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel ig_busy],0
    jne .bad
    mov byte [rel ig_busy],1
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Native caller owns mapped lifetime. Reject null/wrap/module private overlap.
ig_disjoint:
    test rdi,rdi
    jz .bad
    mov rax,rdi
    add rax,rsi
    jc .bad
    lea rdx,[rel ig_private_end]
    cmp rdi,rdx
    jae .ok
    lea rdx,[rel ig_private_begin]
    cmp rax,rdx
    ja .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Read actual verifier descriptor/index/copy APIs, no path reopen or guest parse.
ig_load:
    mov rdi,[rel ig_handle]
    lea rsi,[rel ig_descriptor]
    cmp qword [rel ig_profile],IG_SCRIPT
    je .script
    cmp qword [rel ig_profile],IG_PACKAGE
    jne .bad
    mov edx,704
    call app_package_descriptor
    cmp eax,1
    jne .bad
    mov rax,[rel ig_descriptor+104]
    mov rcx,[rel ig_descriptor+112]
    mov rdx,[rel ig_descriptor+120]
    jmp .index
.script:
    mov edx,384
    call app_script_descriptor
    cmp eax,1
    jne .bad
    mov rax,[rel ig_descriptor+336]
    mov rcx,[rel ig_descriptor+344]
    mov rdx,[rel ig_descriptor+352]
.index:
    mov [rel ig_assets],rdx
    test rcx,rcx
    jz .bad
    cmp rcx,1280
    ja .bad
    mov [rel ig_index_bytes],rcx
    mov rsi,rax
    lea rdx,[rel ig_index]
    call ig_copy
    cmp eax,1
    jne .bad
    xor r8d,r8d
.scan:
    lea r9,[rel ig_index]
    add r9,r8
    cmp dword [r9],5
    je .grants
    add r8,80
    cmp r8,[rel ig_index_bytes]
    jb .scan
    jmp .bad
.grants:
    cmp dword [r9+8],4
    jne .bad
    mov esi,[r9+4]
    add rsi,[rel ig_assets]
    jc .bad
    lea rdx,[rel ig_requested]
    mov ecx,4
    call ig_copy
    cmp eax,1
    jne .bad
    xor ecx,ecx
.check:
    lea rdx,[rel ig_requested]
    cmp byte [rdx+rcx],2
    ja .bad
    inc ecx
    cmp ecx,4
    jb .check
    mov rax,[rel ig_descriptor+32]
    or rax,[rel ig_descriptor+40]
    or rax,[rel ig_descriptor+48]
    or rax,[rel ig_descriptor+56]
    jz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret
ig_copy:
    mov rdi,[rel ig_handle]
    cmp qword [rel ig_profile],IG_SCRIPT
    je app_script_copy
    jmp app_package_copy

ig_find:
    lea r8,[rel ig_rows]
    mov r9d,IG_ROWS
.scan:
    cmp qword [r8],0
    je .next
    cmp qword [r8+8],PRIN_OWNER
    jne .next
    mov rax,[rel ig_profile]
    cmp [r8+56],rax
    jne .next
    mov eax,[rel ig_requested]
    cmp [r8+48],eax
    jne .next
    lea rdi,[r8+16]
    lea rsi,[rel ig_descriptor+32]
    mov ecx,4
    cld
    repe cmpsq
    je .found
.next:
    add r8,IG_ROW_BYTES
    dec r9d
    jnz .scan
    xor eax,eax
    ret
.found:
    mov rax,r8
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_sec_app_install_grants 0
alignb 8
ig_private_begin:
ig_busy: resb 1
alignb 8
ig_serial: resq 1
ig_handle: resq 1
ig_profile: resq 1
ig_assets: resq 1
ig_operation: resq 1
ig_index_bytes: resq 1
ig_selected: resd 1
ig_requested: resd 1
ig_versions: resd 1
ig_rows: resb IG_ROWS*IG_ROW_BYTES
ig_size: resq 1
ig_attrs: resd 1
ig_store_state: resb 1
ig_key_ready: resb 1
ig_tomb_full: resb 1
alignb 4
ig_tomb_count: resd 1
ig_tombs: resb IG_TOMBS*IG_TOMB_BYTES
alignb 8
app_install_grants_mac_key: resb 32
ig_owner_key: resb 32
ig_mac_out: resb 32
ig_saved: resb IGS_BYTES
ig_stage: resb IGS_BYTES
ig_verify: resb IGS_BYTES
ig_descriptor: resb 704
ig_index: resb 1280
ig_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_app_install_grants
