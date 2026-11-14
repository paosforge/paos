;; MODULE gui/settings_update_backend
;; LAYER 6
;; EXPORTS settings_update_backend_tick, settings_update_backend_observe
;; IMPORTS sec/update_request, gui/settings_updates, gui/settings_update_policy, hv/app_vm, hv/settings_update_service, fs/update_esp, svc/settings_update_app_source, core/time, core/smp
;; CAPS CAP_GUI
;; OWNER rc-msi-claude
;; CONTEXT: bsp_only
; T5-14 N partial native coordinator. ROOT110490 / SEC110503 / ADMIN110622.
; Private helpers implement nonconsuming once-only signed stage/prepare/READY
; activation, exact full original40/runtime128 capture and native FS terminal
; validation. FETCH remains the sole update_request_take. No worker result
; upload, caller-supplied identity, guest ACK authority or guessed lease.
; Bounded tick joins actual readiness, work and independently confirmed cleanup.
; ADMIN owns module include/link and existing tick call edges; GUI remains V's.
; Supplier source is separately reviewed. HOST fixtures prove N consumers only.
;
; UNO1/576 is ADMIN110658 + J110653's accepted passive native snapshot inside
; the existing T Calls/journal envelope. Historical native verification and UI
; acceptance are separate from sampled CURRENT/STOPPED and custody. This getter
; cannot capture lineage, consume a request, stage, launch, effect or clean up.
; Backend attachment must use actual BOOT passive readiness, transition-only;
; neither module presence nor a digest is availability. Original deadline is
; never renewed. AUTO3/4 use actual full delivery then native policy, no ESP.
%include "core/abi/wdata.inc"

; Existing idle caller only. No identity, verdict or worker result argument.
; Reserve against reentry/observation BEFORE supplier callbacks. Every pass is
; bounded; ordinary VM ticks own preparation, recipient retirement and scrub.
; ->0 idle/refused entry /1 pending work or cleanup /2 original actually closed.
settings_update_backend_tick:
    sub rsp,8
    call smp_current_logical
    test eax,eax
    jnz .no
    cmp byte [rel upbe_tick_busy],0
    jne .no
    cmp byte [rel upbe_observe_busy],0
    jne .no
    cmp byte [rel upbe_launch_busy],0
    jne .no
    cmp byte [rel upbe_ready_busy],0
    jne .no
    mov byte [rel upbe_tick_busy],1
    call upbe_refresh_backend
    call upbe_work_step
    cmp eax,2
    jne .release
    call upbe_cleanup_step
    cmp eax,1
    je .closed
    mov eax,1
    jmp .release
.closed:
    mov eax,2
.release:
    mov byte [rel upbe_tick_busy],0
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret

 ; The idle caller is BSP-only. Reserve before the passive source callback so
; reentry cannot repeat the setter. The real GUI setter INVALIDATES a request
; on every call, even 1->1: invoke it only on an actual readiness transition
; (or a mismatched actual backend byte). No stage/handle/runtime is created.
upbe_refresh_backend:
    cmp byte [rel upbe_ready_busy],0
    jne .no
    mov byte [rel upbe_ready_busy],1
    sub rsp,8
    call settings_update_app_ready
    cmp eax,1
    sete dil
    movzx edi,dil
    cmp dil,[rel upbe_attached]
    jne .transition
    cmp dil,[rel upd_backend]
    je .done
.transition:
    mov [rel upbe_attached],dil
    call settings_updates_backend_set
.done:
    movzx eax,byte [rel upbe_attached]
    mov byte [rel upbe_ready_busy],0
    add rsp,8
    ret
.no:
    xor eax,eax
    ret

; Private BSP-only: copy a still-pending original40, without taking it. Only
; the existing GUI writes upd_*; qualified service FETCH remains the sole take.
; There is no caller-supplied identity or output pointer. Revalidate AFTER the
; native authority/time callbacks, which must not let an intervening change
; become a retained launch identity. ->1 exact pending /0 with scratch cleared.
upbe_pending_copy:
    sub rsp,8
    call update_request_valid
    cmp eax,1
    jne .bad
    cmp dword [rel upd_phase],1
    jne .bad
    mov rax,[rel upd_serial]
    test rax,rax
    jz .bad
    mov [rel upbe_pending],rax
    mov eax,[rel upd_op]
    dec eax
    cmp eax,3
    ja .bad
    inc eax
    mov [rel upbe_pending+8],eax
    mov dword [rel upbe_pending+12],1
    mov rax,[rel upd_pid]
    mov [rel upbe_pending+16],rax
    mov rax,[rel upd_token]
    mov [rel upbe_pending+24],rax
    mov rax,[rel upd_deadline]
    mov [rel upbe_pending+32],rax
    call upbe_pending_current
    cmp eax,1
    jne .bad
    add rsp,8
    ret
.bad:
    lea rdi,[rel upbe_pending]
    xor eax,eax
    mov ecx,5
    cld
    rep stosq
    add rsp,8
    ret

; Repeat before/after native staging/prepare and before READY activation. This
; is pending identity only, never phase2 currentness or completion authority.
; The future coordinator must also retain its once-per-original launch latch.
upbe_pending_current:
    sub rsp,8
    call update_request_valid
    cmp eax,1
    jne .no
    cmp dword [rel upd_phase],1
    jne .no
    mov rax,[rel upbe_pending]
    test rax,rax
    jz .no
    cmp rax,[rel upd_serial]
    jne .no
    mov eax,[rel upbe_pending+8]
    dec eax
    cmp eax,3
    ja .no
    inc eax
    cmp eax,[rel upd_op]
    jne .no
    cmp dword [rel upbe_pending+12],1
    jne .no
    mov rax,[rel upbe_pending+16]
    cmp rax,[rel upd_pid]
    jne .no
    mov rax,[rel upbe_pending+24]
    cmp rax,[rel upd_token]
    jne .no
    mov rax,[rel upbe_pending+32]
    cmp rax,[rel upd_deadline]
    jne .no
    mov eax,1
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret

; Retain a genuine GENERAL VM snapshot for cleanup only, including before the
; first qualified updater exit/FETCH. This never sets full delivery, CURRENT,
; active, or completion. The producer sees our actual prepare instance; its
; exact returned START/endpoint survive owner loss. No identity is fabricated.
; ->1 retained /0 not available /-1 mismatched native output (retain custody).
upbe_vm_identity:
    sub rsp,8
    cmp byte [rel upbe_vm_identity_valid],1
    je .yes
    cmp byte [rel upbe_vm_identity_refused],1
    je .bad
    mov rdi,[rel upbe_launch_instance]
    test rdi,rdi
    jz .no
    lea rsi,[rel upbe_vm_sample]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .no
    cmp qword [rel upbe_vm_sample],1
    jne .mismatch
    cmp qword [rel upbe_vm_sample+16],0
    je .mismatch
    cmp qword [rel upbe_vm_sample+24],0
    je .mismatch
    mov rax,[rel upbe_launch_instance]
    cmp rax,[rel upbe_vm_sample+56]
    jne .mismatch
    mov rax,[rel upbe_launch_handle]
    test rax,rax
    jz .mismatch
    cmp rax,[rel upbe_vm_sample+96]
    jne .mismatch
    mov rax,[rel upbe_launch_original+16]
    cmp rax,[rel upbe_vm_sample+48]
    jne .mismatch
    mov rax,[rel upbe_launch_original+24]
    cmp rax,[rel upbe_vm_sample+40]
    jne .mismatch
    cmp qword [rel upbe_vm_sample+112],0
    jne .mismatch
    cmp qword [rel upbe_vm_sample+120],0
    jne .mismatch
    lea rdi,[rel upbe_vm_original]
    lea rsi,[rel upbe_vm_sample]
    mov ecx,16
    cld
    rep movsq
    mov byte [rel upbe_vm_identity_valid],1
.yes:
    mov eax,1
    jmp .out
.mismatch:
    mov byte [rel upbe_vm_identity_refused],1
.bad:
    mov eax,-1
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

; Only CPU/root containment of this original, never memory/service/ESP free.
; Existing normal VM ticks scrub asynchronously. No broad stop or guest census.
; A genuine retained native identity permits exact revoke after owner loss;
; otherwise the existing LOCAL OWNER instance stop is attempted once. Refusal
; stays unknown and normal VM admission-loss/deadline handling still applies.
; ->1 actual stopped/inactive original /0 unresolved, with N custody unchanged.
upbe_vm_contain:
    sub rsp,8
    lea rdi,[rel upbe_inactive]
    mov esi,256
    call app_vm_power_inactive
    test eax,eax
    jnz .running
    mov rax,[rel upbe_launch_instance]
    test rax,rax
    jz .yes
    cmp rax,[rel upbe_inactive+224]
    jne .no
    cmp byte [rel upbe_vm_identity_valid],1
    jne .service_start
    mov rax,[rel upbe_vm_original+24]
    jmp .match_start
.service_start:
    cmp byte [rel upbe_service_identity_valid],1
    jne .yes
    mov rax,[rel upbe_service_original+24]
.match_start:
    cmp rax,[rel upbe_inactive+232]
    jne .no
.yes:
    mov eax,1
    jmp .out
.running:
    call upbe_vm_identity
    cmp eax,1
    je .revoke
    test eax,eax
    jnz .no                          ; mismatched output is not local fallback
    cmp byte [rel upbe_stop_attempted],0
    jne .no
    mov rdi,[rel upbe_launch_instance]
    test rdi,rdi
    jz .no                          ; failed prepare may still be scrubbing
    mov byte [rel upbe_stop_attempted],1
    call app_vm_stop
    cmp eax,1
    jne .no
    jmp .yes
.revoke:
    lea rdi,[rel upbe_vm_original]
    mov esi,128
    call app_vm_recipient_revoke
    cmp eax,1
    jne .no
    jmp .yes
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

; Genuine service identity for cleanup, including partial FETCH EDX0. A
; partial original is never full delivery/current completion authority. Outputs
; come only from the passive native producer and must match this actual launch.
; Keep first exact qualified128; later replacement/mismatch cannot relabel it.
; ->1 CURRENT /2 STOPPED /0 UNKNOWN. No stage/take/effect/free or positive latch.
upbe_service_identity:
    push rbx
    lea rdi,[rel upbe_sample_original]
    mov esi,40
    lea rdx,[rel upbe_sample_runtime]
    mov ecx,128
    call settings_update_service_observe
    cmp eax,1
    je .matched_class
    cmp eax,2
    jne .no
.matched_class:
    mov ebx,eax
    lea rdi,[rel upbe_sample_original]
    lea rsi,[rel upbe_launch_original]
    mov ecx,5
    cld
    repe cmpsq
    jne .no
    mov rax,[rel upbe_launch_instance]
    test rax,rax
    jz .no
    cmp rax,[rel upbe_sample_runtime+56]
    jne .no
    mov rax,[rel upbe_launch_handle]
    test rax,rax
    jz .no
    cmp rax,[rel upbe_sample_runtime+96]
    jne .no
    cmp qword [rel upbe_sample_runtime],1
    jne .no
    cmp qword [rel upbe_sample_runtime+16],0
    je .no
    cmp qword [rel upbe_sample_runtime+24],0
    je .no
    cmp qword [rel upbe_sample_runtime+112],0
    jne .no
    cmp qword [rel upbe_sample_runtime+120],0
    jne .no
    mov rax,[rel upbe_launch_original+16]
    cmp rax,[rel upbe_sample_runtime+48]
    jne .no
    mov rax,[rel upbe_launch_original+24]
    cmp rax,[rel upbe_sample_runtime+40]
    jne .no
    cmp byte [rel upbe_service_identity_valid],1
    je .retained
    lea rdi,[rel upbe_service_original]
    lea rsi,[rel upbe_sample_runtime]
    mov ecx,16
    rep movsq
    mov byte [rel upbe_service_identity_valid],1
    jmp .yes
.retained:
    lea rdi,[rel upbe_service_original]
    lea rsi,[rel upbe_sample_runtime]
    mov ecx,16
    repe cmpsq
    jne .no
.yes:
    mov eax,ebx
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

; One bounded work step, called by the future BSP/reentry-guarded idle tick.
; No spin, synchronous VM tick/scrub, retries of stage/policy/UI, or deadline
; renewal. ->0 idle /1 original work pending /2 normal cleanup required.
; Cleanup authority and actual lifetime closure are separate below this step.
upbe_work_step:
    sub rsp,8
    cmp byte [rel upbe_cleanup],1
    je .cleanup
    cmp byte [rel upbe_custody],1
    je .owned
    cmp byte [rel upbe_attached],1
    jne .idle
    call upbe_launch_begin
    cmp eax,1
    je .pending
    cmp byte [rel upbe_custody],1
    je .cleanup
    jmp .idle
.owned:
    cmp byte [rel upbe_attached],1
    jne .cleanup
    cmp dword [rel upbe_launch_phase],4
    je .cleanup
    call upbe_request_alive
    cmp eax,1
    jne .cleanup
    call upbe_vm_identity
    cmp eax,-1
    je .cleanup
    cmp dword [rel upbe_launch_phase],2
    jne .running
    call upbe_launch_activate
    cmp dword [rel upbe_launch_phase],4
    je .cleanup
    jmp .pending
.running:
    cmp dword [rel upbe_launch_phase],3
    jne .cleanup
    cmp byte [rel upbe_activation_accepted],1
    jne .cleanup
    call upbe_service_identity
    cmp eax,2
    je .cleanup                         ; stopped worker never positive completion
    cmp eax,1
    jne .pending
    cmp byte [rel upbe_active],1
    je .admit
    call upbe_capture_service
    cmp eax,1
    jne .pending                        ; partial budget/FETCH cannot complete
.admit:
    call upbe_admit_completion
    cmp byte [rel upbe_completion_attempted],1
    je .cleanup                         ; success or refusal, no policy/UI retry
.pending:
    mov eax,1
    jmp .out
.cleanup:
    mov byte [rel upbe_cleanup],1
    cmp byte [rel upbe_ui_accepted],1
    je .cleanup_result
    mov byte [rel upbe_refused],1
.cleanup_result:
    mov eax,2
    jmp .out
.idle:
    xor eax,eax
.out:
    add rsp,8
    ret

; Service closure is separate from VM/ESP custody. The ESP stage must have
; independently confirmed its original lease/memory closure first, while this
; service identity is still retained. EAX0 from retire/observe is NEVER empty.
; Attempt actual matching STOPPED+invalid-original retirement once, then rely
; only on the passive exact all-empty receipt. Never clears N/VM/ESP custody.
; ->1 confirmed service empty /0 unresolved. No repeated uncertain retirement.
upbe_service_retire_step:
    sub rsp,8
    cmp byte [rel upbe_cleanup],1
    jne .no
    cmp byte [rel upbe_esp_closed],1
    jne .no
    call settings_update_service_empty
    cmp eax,1
    je .yes
    cmp byte [rel upbe_service_retire_attempted],0
    jne .no
    call upbe_service_identity
    cmp eax,2
    jne .no
    call upbe_request_alive
    test eax,eax
    jnz .no
    mov byte [rel upbe_service_retire_attempted],1
    call settings_update_service_retire
    ; Independent empty receipt resolves actual absence, not the return code.
    call settings_update_service_empty
    cmp eax,1
    jne .no
.yes:
    mov eax,1
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret

; Exact FS owner API (FS110724), not noarg freeze/reclaim or an observation0.
; The actual qualified service128 may be retained from partial delivery, but
; it never supplies completion. Runtime0 can confirm only actual broker absence.
; FS itself checks genuine STOPPED before any held lease/memory reclamation.
upbe_esp_close:
    sub rsp,8
    cmp byte [rel upbe_esp_closed],1
    je .yes
    call upbe_service_identity
    xor esi,esi
    cmp byte [rel upbe_service_identity_valid],1
    jne .call
    lea rsi,[rel upbe_service_original]
.call:
    lea rdi,[rel upbe_launch_original]
    call update_esp_cleanup
    cmp eax,1
    jne .no
    mov byte [rel upbe_esp_closed],1
.yes:
    mov eax,1
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret

; CPU/root containment is insufficient for RAM/scrub release. The independent
; passive VM all-inactive receipt must match our actual instance and, if known,
; original START. A failed prepare with no returned instance still requires
; actual global inactivity. No stop return, guest ACK or service0 substitutes.
upbe_vm_released:
    sub rsp,8
    lea rdi,[rel upbe_inactive]
    mov esi,256
    call app_vm_power_inactive
    test eax,eax
    jnz .no
    mov rax,[rel upbe_launch_instance]
    test rax,rax
    jz .yes
    cmp rax,[rel upbe_inactive+224]
    jne .no
    cmp byte [rel upbe_vm_identity_valid],1
    jne .service_start
    mov rax,[rel upbe_vm_original+24]
    jmp .match_start
.service_start:
    cmp byte [rel upbe_service_identity_valid],1
    jne .yes
    mov rax,[rel upbe_service_original+24]
.match_start:
    cmp rax,[rel upbe_inactive+232]
    jne .no
.yes:
    mov eax,1
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret

; Final native owner join. Keep the genuine service identity until FS closes,
; then independently confirm service absence, then actual VM memory inactivity.
; Unknowns remain held across ticks. Historical result/UI/original and serial
; latch survive release; a new request cannot reuse or renew the old original.
upbe_cleanup_step:
    sub rsp,8
    cmp byte [rel upbe_cleanup],1
    jne .no
    cmp byte [rel upbe_custody],1
    jne .no
    call upbe_refuse_ui
    call upbe_vm_contain
    cmp eax,1
    jne .no
    call upbe_esp_close
    cmp eax,1
    jne .no
    call upbe_service_retire_step
    cmp eax,1
    jne .no
    call upbe_vm_released
    cmp eax,1
    jne .no
    mov byte [rel upbe_active],0
    mov byte [rel upbe_custody],0
    mov byte [rel upbe_cleanup],0
    mov byte [rel upbe_launch_closed],1
    mov eax,1
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret

; Private fixed native terminal consumer, FS110592 / RESOURCE110596 / MSI110601.
; No caller pointers/verdict. The future coordinator installs original40 and
; runtime128 ONLY from the genuine service, matching its launched original.
; ->1 CURRENT /2 AVAILABLE /3 STAGED /0 incomplete-or-refused. This neither
; publishes GUI completion nor releases custody. STOPPED/feed/worker flags are
; never completion. Availability and launch remain separate unfinished work.
upbe_completion_ready:
    push rbx
    cmp byte [rel upbe_active],1
    jne .no
    call upbe_retained_current
    cmp eax,1
    jne .no
    lea rdi,[rel upbe_original]
    lea rsi,[rel upbe_runtime]
    lea rdx,[rel upbe_observation]
    mov ecx,512
    call update_esp_observe
    test eax,eax
    jnz .no
    cmp dword [rel upbe_observation],'UEO1'
    jne .no
    cmp word [rel upbe_observation+4],1
    jne .no
    cmp word [rel upbe_observation+6],512
    jne .no
    cmp qword [rel upbe_observation+8],0
    je .no
    cmp qword [rel upbe_observation+16],0
    je .no
    mov rax,[rel upbe_original]
    cmp rax,[rel upbe_observation+24]
    jne .no
    mov eax,[rel upbe_original+8]
    cmp eax,[rel upbe_observation+32]
    jne .no
    cmp dword [rel upbe_observation+36],1 ; retained live custody, not frozen
    jne .no
    mov rax,[rel upbe_original+32]
    cmp rax,[rel upbe_observation+40]
    jne .no
    cmp dword [rel upbe_observation+112],1 ; actual gate closed, not RO proof
    jne .no
    cmp dword [rel upbe_observation+116],1 ; CURRENT only, never STOPPED
    jne .no
    cmp dword [rel upbe_observation+120],2 ; native FINISH, not early FEED
    jne .no
    cmp dword [rel upbe_observation+124],0
    jne .no
    mov eax,[rel upbe_observation+56]
    test eax,~0x1ff                     ; exact v1 facts, no unknown bits
    jnz .no
    test eax,0x40                       ; uncertainty must remain retained
    jnz .no
    and eax,0x1a0                      ; confirmed RO + native owner/feed proof
    cmp eax,0x1a0
    jne .no
    call boot_ms_now
    cmp rax,[rel upbe_original+32]
    jae .no
    cmp rax,[rel upbe_observation+48]   ; no future/regressed observation
    jb .no
    cmp qword [rel upbe_observation+480],0
    je .no
    mov rax,[rel upbe_observation+496]
    cmp rax,[rel upbe_observation+504]  ; independent readbacks before RO
    jae .no
    cmp dword [rel upbe_original+8],1
    je .check
    cmp dword [rel upbe_original+8],2
    jne .no                            ; AUTO3/4 use fixed DATA policy
    cmp qword [rel upbe_observation+64],3
    jne .no
    cmp dword [rel upbe_observation+60],2 ; a genuinely AVAILABLE offer
    jne .no
    mov eax,[rel upbe_observation+56]
    and eax,0x3f                       ; issue/pub/readback/restore attempted
    cmp eax,0x3f
    jne .no
    cmp qword [rel upbe_observation+72],0
    je .no
    cmp qword [rel upbe_observation+80],0
    je .no
    cmp qword [rel upbe_observation+88],0
    je .no
    mov rax,[rel upbe_observation+96]
    test rax,rax
    jz .no
    and rax,[rel upbe_observation+104]
    cmp rax,[rel upbe_observation+96]   ; every published file read back
    jne .no
    mov rax,[rel upbe_observation+480]
    cmp rax,[rel upbe_observation+488]  ; admission BEFORE publication attempt
    jae .no
    mov rax,[rel upbe_observation+488]
    cmp rax,[rel upbe_observation+496]
    jae .no
    mov ebx,3
    jmp .recheck
.check:
    mov rbx,[rel upbe_observation+64]
    cmp rbx,1
    je .class
    cmp rbx,2
    jne .no
.class:
    cmp ebx,[rel upbe_observation+60]
    jne .no
    test dword [rel upbe_observation+56],7
    jnz .no                            ; CHECK cannot have RW/write/publication
    mov rax,[rel upbe_observation+72]
    or rax,[rel upbe_observation+80]
    or rax,[rel upbe_observation+88]
    or rax,[rel upbe_observation+96]
    or rax,[rel upbe_observation+488]
    jnz .no
    mov rax,[rel upbe_observation+480]
    cmp rax,[rel upbe_observation+496]
    jae .no
.recheck:
    ; Projection is not continuing authority. Repeat the real native lineage
    ; and complete delivery checks after every producer/time callback.
    call upbe_retained_current
    cmp eax,1
    jne .no
    mov eax,ebx
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

; No grant/capture: require actual service CURRENT plus full original/BUDGET,
; then compare every original and runtime byte with this active coordinator.
upbe_retained_current:
    sub rsp,8
    lea rdi,[rel upbe_sample_original]
    mov esi,40
    lea rdx,[rel upbe_sample_runtime]
    mov ecx,128
    call settings_update_service_observe
    cmp eax,1
    jne .no
    cmp edx,3
    jne .no
    lea rsi,[rel upbe_sample_original]
    lea rdi,[rel upbe_original]
    mov ecx,5
    cld
    repe cmpsq
    jne .no
    lea rsi,[rel upbe_sample_runtime]
    lea rdi,[rel upbe_runtime]
    mov ecx,16
    repe cmpsq
    jne .no
    mov eax,1
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret

; Join actual passive full delivery to THIS launch. No guessed runtime or
; worker-provided original: every40B must match the pending native original,
; instance and fresh signed handle must be the ones actually prepared here.
; Capture once only; currentness remains independently repeated afterwards.
; ->1 retained /0 not retained. Failure discards only N scratch, never custody.
upbe_capture_service:
    sub rsp,8
    cmp byte [rel upbe_active],0
    jne .no
    cmp dword [rel upbe_launch_phase],3
    jne .no
    lea rdi,[rel upbe_sample_original]
    mov esi,40
    lea rdx,[rel upbe_sample_runtime]
    mov ecx,128
    call settings_update_service_observe
    cmp eax,1
    jne .no
    cmp edx,3
    jne .no
    lea rsi,[rel upbe_sample_original]
    lea rdi,[rel upbe_launch_original]
    mov ecx,5
    cld
    repe cmpsq
    jne .no
    cmp qword [rel upbe_sample_runtime],1
    jne .no
    mov rax,[rel upbe_launch_instance]
    test rax,rax
    jz .no
    cmp rax,[rel upbe_sample_runtime+56]
    jne .no
    mov rax,[rel upbe_launch_handle]
    test rax,rax
    jz .no
    cmp rax,[rel upbe_sample_runtime+96]
    jne .no
    mov rax,[rel upbe_launch_original+16]
    cmp rax,[rel upbe_sample_runtime+48]
    jne .no
    mov rax,[rel upbe_launch_original+24]
    cmp rax,[rel upbe_sample_runtime+40]
    jne .no
    lea rsi,[rel upbe_sample_original]
    lea rdi,[rel upbe_original]
    mov ecx,5
    rep movsq
    lea rsi,[rel upbe_sample_runtime]
    lea rdi,[rel upbe_runtime]
    mov ecx,16
    rep movsq
    call upbe_retained_current
    cmp eax,1
    jne .discard
    mov byte [rel upbe_active],1
    mov dword [rel upbe_delivery_facts],3
    add rsp,8
    ret
.discard:
    lea rdi,[rel upbe_original]
    mov ecx,5+16
    xor eax,eax
    cld
    rep stosq
.no:
    xor eax,eax
    add rsp,8
    ret

; Private launch half, called only after actual backend readiness/attachment.
; No caller identity, borrowed handle or stage-installed fallback. The genuine
; VM's passive inactive check precedes stage; prepare/activate independently
; validate actual VM ownership/runtime. Reserve the serial BEFORE stage, even
; a failed stage must not be retried. These routines never call FETCH/take.
; ->1 prepare accepted /0 not launched. Actual instance retained on later loss.
upbe_launch_begin:
    push rbx
    cmp byte [rel upbe_launch_busy],0
    jne .no
    cmp byte [rel upbe_active],0
    jne .no
    cmp byte [rel upbe_custody],0
    jne .no
    cmp byte [rel upbe_launch_closed],1
    je .reserve
    cmp dword [rel upbe_launch_phase],1
    je .no
    cmp dword [rel upbe_launch_phase],2
    je .no
    cmp dword [rel upbe_launch_phase],3
    je .no
.reserve:
    mov byte [rel upbe_launch_busy],1
    lea rdi,[rel upbe_inactive]
    mov esi,256
    call app_vm_power_inactive
    test eax,eax
    jnz .release_no
    call upbe_pending_copy
    cmp eax,1
    jne .release_no
    mov rax,[rel upbe_pending]
    cmp rax,[rel upbe_launch_serial]
    jbe .release_no                     ; monotonic native GUI serial, no replay
    mov [rel upbe_launch_serial],rax
    mov dword [rel upbe_launch_phase],1 ; before any stage publication attempt
    mov qword [rel upbe_launch_instance],0
    mov qword [rel upbe_launch_handle],0
    mov dword [rel upbe_delivery_facts],0
    mov dword [rel upbe_native_result],0
    mov dword [rel upbe_saved_auto],-1
    mov byte [rel upbe_activation_attempted],0
    mov byte [rel upbe_activation_accepted],0
    mov byte [rel upbe_native_positive],0
    mov byte [rel upbe_completion_attempted],0
    mov byte [rel upbe_ui_accepted],0
    mov byte [rel upbe_refused],0
    mov byte [rel upbe_cleanup],0
    mov byte [rel upbe_ueo_valid],0
    mov byte [rel upbe_esp_closed],0
    mov byte [rel upbe_launch_closed],0
    mov byte [rel upbe_service_retire_attempted],0
    mov byte [rel upbe_service_identity_valid],0
    mov byte [rel upbe_vm_identity_valid],0
    mov byte [rel upbe_vm_identity_refused],0
    mov byte [rel upbe_stop_attempted],0
    mov byte [rel upbe_ui_attempted],0
    lea rdi,[rel upbe_launch_original]
    lea rsi,[rel upbe_pending]
    mov ecx,5
    cld
    rep movsq
    call settings_update_app_stage
    test rax,rax
    jz .failed
    mov [rel upbe_launch_handle],rax
    mov rbx,rax
    call upbe_launch_current
    cmp eax,1
    jne .failed
    mov rdi,rbx
    xor esi,esi                         ; genuine runtime's automatic RAM floor
    mov byte [rel upbe_custody],1   ; reserve before possibly partial prepare
    call app_vm_updater_prepare
    test rax,rax
    jz .failed
    mov [rel upbe_launch_instance],rax  ; retain even if original now lost
    mov byte [rel upbe_custody],1
    call upbe_launch_current
    cmp eax,1
    jne .failed
    mov dword [rel upbe_launch_phase],2
    mov eax,1
    jmp .release
.failed:
    mov dword [rel upbe_launch_phase],4 ; terminal attempt, no implicit retry
.release_no:
    xor eax,eax
.release:
    mov byte [rel upbe_launch_busy],0
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

; READY is reached by ordinary VM ticks, never synchronous spin/wipe here.
; ->1 activation accepted /0 not activated. A not-yet-READY VM stays pending;
; any actual activation attempt is once, including failure or postcheck loss.
upbe_launch_activate:
    sub rsp,8
    cmp byte [rel upbe_launch_busy],0
    jne .no
    cmp dword [rel upbe_launch_phase],2
    jne .no
    mov byte [rel upbe_launch_busy],1
    call upbe_launch_current
    cmp eax,1
    jne .failed
    mov rdi,[rel upbe_launch_instance]
    call app_vm_status
    cmp rax,1                           ; PREPARING
    je .release_no
    cmp rax,2                           ; LOADING
    je .release_no
    cmp rax,3                           ; actual READY
    jne .failed
    call upbe_launch_current
    cmp eax,1
    jne .failed
    mov dword [rel upbe_launch_phase],3 ; reserve before activation callback
    mov byte [rel upbe_activation_attempted],1
    mov rdi,[rel upbe_launch_instance]
    call app_vm_activate
    cmp eax,1
    jne .failed
    call upbe_launch_current
    cmp eax,1
    jne .failed
    mov byte [rel upbe_activation_accepted],1
    mov eax,1
    jmp .release
.failed:
    mov dword [rel upbe_launch_phase],4
.release_no:
    xor eax,eax
.release:
    mov byte [rel upbe_launch_busy],0
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret

; Preserve the reserved original through native callbacks as well as real
; pending request validation. Copying newer pending state cannot renew it.
upbe_launch_current:
    sub rsp,8
    lea rsi,[rel upbe_launch_original]
    lea rdi,[rel upbe_pending]
    mov ecx,5
    cld
    repe cmpsq
    jne .no
    call upbe_pending_current
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret

; Original lifetime may be pending before FETCH or current after its sole take.
; Reuse the actual request predicates; no altered phase, pre-take or deadline.
upbe_request_alive:
    cmp dword [rel upd_phase],1
    je upbe_launch_current
    cmp dword [rel upd_phase],2
    jne .no
    lea rdi,[rel upbe_launch_original]
    jmp update_request_current
.no:
    xor eax,eax
    ret

; Cleanup may settle an actually taken, still-current original as REFUSED via
; the trusted GUI adapter. Never invoke it on phase1 or a replacement, never
; retry an earlier positive/refusal UI attempt. This deliberately does NOT set
; UNO1 positive UI acceptance: refusal is distinct from verified success.
upbe_refuse_ui:
    sub rsp,8
    cmp byte [rel upbe_ui_attempted],0
    jne .no
    call upbe_request_alive
    cmp eax,1
    jne .no
    cmp dword [rel upd_phase],2
    jne .no
    mov byte [rel upbe_ui_attempted],1
    mov byte [rel upbe_refused],1
    mov rdi,[rel upbe_launch_original]
    mov esi,6
    xor edx,edx
    call settings_updates_complete
    cmp eax,1
    jne .no
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret

; One positive native admission attempt for one full original. Only native
; FS FINISH supplies CHECK/DOWNLOAD classes. AUTO's dedicated worker supplies
; no ESP/network result: fixed native DATA policy owns the effect/readback.
; A callback failure or uncertainty NEVER retries a policy writer or GUI call.
; Native success is historical; UI accepted is latched only on actual return1.
; ->1 GUI accepted /0 not accepted. No retirement, no request take or renewal.
upbe_admit_completion:
    push rbx
    cmp byte [rel upbe_active],1
    jne .no
    cmp byte [rel upbe_completion_attempted],0
    jne .no
    call upbe_retained_current
    cmp eax,1
    jne .no
    mov eax,[rel upbe_original+8]
    cmp eax,3
    je .auto
    cmp eax,4
    je .auto
    call upbe_completion_ready
    test eax,eax
    jz .no
    mov ebx,eax
    mov [rel upbe_native_result],eax
    mov byte [rel upbe_native_positive],1
    mov byte [rel upbe_ueo_valid],1
    mov byte [rel upbe_completion_attempted],1 ; before any DATA/UI callback
    cmp ebx,3
    je .publish
    ; A CHECK needs independently read saved consent, never a worker flag or
    ; default-on. The fixed native policy repeats original/local owner itself.
    lea rdi,[rel upbe_original]
    call settings_update_policy
    cmp eax,1
    ja .refused                     ; negatives and unknown values cannot CHECK
    mov [rel upbe_saved_auto],eax
    jmp .current
.auto:
    mov byte [rel upbe_completion_attempted],1 ; policy can effect: once only
    lea rdi,[rel upbe_original]
    call settings_update_policy
    cmp eax,1
    ja .auto_refused
    mov edx,[rel upbe_original+8]
    cmp edx,3
    jne .auto_off
    cmp eax,1
    jne .auto_refused
    mov ebx,4
    jmp .auto_saved
.auto_off:
    test eax,eax
    jnz .auto_refused
    mov ebx,5
.auto_saved:
    mov [rel upbe_saved_auto],eax
    ; Recheck before recording a positive native result or GUI acceptance.
    call upbe_retained_current
    cmp eax,1
    jne .refused
    mov [rel upbe_native_result],ebx
    mov byte [rel upbe_native_positive],1
    jmp .publish
.auto_refused:
    ; Policy -2 is BUSY, not UNO1 unavailable; terminal refusal, no retry.
    cmp eax,-3
    je .record_auto_error
    mov eax,-1
.record_auto_error:
    mov [rel upbe_native_result],eax
    jmp .refused
.current:
    call upbe_retained_current
    cmp eax,1
    jne .refused
.publish:
    ; No authority travels in the scalar ABI. The trusted GUI adapter repeats
    ; its own current owner/session/deadline and exact original operation.
    mov rdi,[rel upbe_original]
    mov esi,ebx
    mov edx,[rel upbe_saved_auto]
    mov byte [rel upbe_ui_attempted],1
    call settings_updates_complete
    cmp eax,1
    jne .refused
    mov byte [rel upbe_ui_accepted],1
    pop rbx
    ret
.refused:
    mov byte [rel upbe_refused],1
.no:
    xor eax,eax
    pop rbx
    ret

; Trusted native output only. Fixed-size, nonwrapping canonical buffer,
; disjoint from all N and native request private state. Rejected outputs are
; untouched. BSP + busy guards prohibit observing a half-updated coordinator.
; ->1 copied /0 refused. Scratch writes are observation scratch only.
settings_update_backend_observe:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    cmp esi,576
    jne .bad
    test rbx,rbx
    jz .bad
    mov r12,rbx
    add r12,576
    jc .bad
    mov rax,rbx
    shl rax,16
    sar rax,16
    cmp rax,rbx
    jne .bad
    lea rdx,[r12-1]
    mov rax,rdx
    shl rax,16
    sar rax,16
    cmp rax,rdx
    jne .bad
    lea rax,[rel upbe_state_end]
    cmp rbx,rax
    jae .request_span
    lea rax,[rel upbe_state_begin]
    cmp r12,rax
    ja .bad
.request_span:
    lea rax,[rel upd_backend+1]
    cmp rbx,rax
    jae .context
    lea rax,[rel upd_serial]
    cmp r12,rax
    ja .bad
.context:
    cmp byte [rel upbe_tick_busy],0
    jne .bad
    cmp byte [rel upbe_launch_busy],0
    jne .bad
    cmp byte [rel upbe_observe_busy],0
    jne .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    mov byte [rel upbe_observe_busy],1
    lea rdi,[rel upbe_export]
    xor eax,eax
    mov ecx,576/8
    cld
    rep stosq
    mov dword [rel upbe_export],'UNO1'
    mov word [rel upbe_export+4],1
    mov word [rel upbe_export+6],576
    mov dword [rel upbe_export+56],-1
    mov rax,[rel upbe_launch_serial]
    test rax,rax
    jz .time
    mov [rel upbe_export+8],rax
    mov eax,[rel upbe_launch_original+8]
    mov [rel upbe_export+16],eax
    mov rax,[rel upbe_launch_original+32]
    mov [rel upbe_export+32],rax
    mov eax,[rel upbe_launch_phase]
    cmp eax,4
    jne .phase
    mov eax,7                      ; refused attempt; never synthesize completion
.phase:
    cmp byte [rel upbe_active],1
    jne .terminal_phase
    mov eax,4
.terminal_phase:
    cmp byte [rel upbe_native_positive],1
    jne .ui_phase
    mov eax,5
.ui_phase:
    cmp byte [rel upbe_ui_accepted],1
    jne .cleanup_phase
    mov eax,6
.cleanup_phase:
    cmp byte [rel upbe_cleanup],1
    jne .store_phase
    mov eax,8
.store_phase:
    mov [rel upbe_export+20],eax
    mov eax,[rel upbe_native_result]
    mov [rel upbe_export+28],eax
    mov eax,[rel upbe_saved_auto]
    mov [rel upbe_export+56],eax
    ; Historical facts for this exact reserved original. Custody is sampled
    ; from N's actual retained ownership, cleared only by verified retirement.
    xor r13d,r13d
    cmp dword [rel upbe_launch_phase],0
    je .prepare_fact
    or r13d,1<<1
.prepare_fact:
    cmp qword [rel upbe_launch_instance],0
    je .activation_fact
    or r13d,1<<2
.activation_fact:
    cmp byte [rel upbe_activation_attempted],1
    jne .activated_fact
    or r13d,1<<3
.activated_fact:
    cmp byte [rel upbe_activation_accepted],1
    jne .delivery
    or r13d,1<<4
.delivery:
    mov eax,[rel upbe_delivery_facts]
    and eax,3
    shl eax,5
    or r13d,eax
    cmp byte [rel upbe_native_positive],1
    jne .ui_fact
    or r13d,1<<7
.ui_fact:
    cmp byte [rel upbe_ui_accepted],1
    jne .refusal_fact
    or r13d,1<<8
.refusal_fact:
    cmp byte [rel upbe_refused],1
    je .refused
    cmp dword [rel upbe_launch_phase],4
    jne .custody
.refused:
    or r13d,1<<9
.custody:
    cmp byte [rel upbe_custody],1
    jne .projection
    or r13d,1<<10
.projection:
    cmp byte [rel upbe_ueo_valid],1
    jne .lineage
    cmp dword [rel upbe_launch_original+8],2
    ja .lineage                     ; AUTO never borrows old ESP observation
    lea rdi,[rel upbe_export+64]
    lea rsi,[rel upbe_observation]
    mov ecx,512/8
    cld
    rep movsq
    or r13d,1<<11
.lineage:
    lea rdi,[rel upbe_export_original]
    mov esi,40
    lea rdx,[rel upbe_export_runtime]
    mov ecx,128
    call settings_update_service_observe
    cmp eax,1
    je .exact_lineage
    cmp eax,2
    jne .facts
.exact_lineage:
    mov r12d,eax
    lea rdi,[rel upbe_export_original]
    lea rsi,[rel upbe_launch_original]
    mov ecx,5
    cld
    repe cmpsq
    jne .facts
    mov rax,[rel upbe_launch_instance]
    test rax,rax
    jz .facts
    cmp rax,[rel upbe_export_runtime+56]
    jne .facts
    mov rax,[rel upbe_launch_handle]
    test rax,rax
    jz .facts
    cmp rax,[rel upbe_export_runtime+96]
    jne .facts
    cmp byte [rel upbe_active],1
    jne .store_lineage
    lea rdi,[rel upbe_export_runtime]
    lea rsi,[rel upbe_runtime]
    mov ecx,16
    repe cmpsq
    jne .facts
.store_lineage:
    mov [rel upbe_export+24],r12d
.facts:
    mov [rel upbe_export+48],r13
.time:
    cmp byte [rel upbe_attached],1
    jne .clock
    or qword [rel upbe_export+48],1
.clock:
    call boot_ms_now
    mov [rel upbe_export+40],rax
    ; No external callbacks after this point, and no authority is exported.
    mov rdi,rbx
    lea rsi,[rel upbe_export]
    mov ecx,576/8
    cld
    rep movsq
    mov byte [rel upbe_observe_busy],0
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

%macro WDATA_gui_settings_update_backend 0
align 8
upbe_state_begin:
upbe_pending: times 40 db 0
upbe_original: times 40 db 0
upbe_runtime: times 128 db 0
upbe_service_original: times 128 db 0
upbe_vm_original: times 128 db 0
upbe_vm_sample: times 128 db 0
upbe_sample_original: times 40 db 0
upbe_sample_runtime: times 128 db 0
upbe_observation: times 512 db 0
upbe_active: db 0
upbe_launch_busy: db 0
align 8
upbe_launch_serial: dq 0
upbe_launch_instance: dq 0
upbe_launch_handle: dq 0
upbe_launch_phase: dd 0             ; 0 none/1 reserved/2 preparing/3 sent/4 refused
align 8
upbe_launch_original: times 40 db 0
upbe_inactive: times 256 db 0
upbe_delivery_facts: dd 0
upbe_native_result: dd 0
upbe_saved_auto: dd -1
upbe_attached: db 0
upbe_activation_attempted: db 0
upbe_activation_accepted: db 0
upbe_custody: db 0
upbe_native_positive: db 0
upbe_completion_attempted: db 0
upbe_ui_attempted: db 0
upbe_esp_closed: db 0
upbe_launch_closed: db 0
upbe_service_retire_attempted: db 0
upbe_service_identity_valid: db 0
upbe_vm_identity_valid: db 0
upbe_vm_identity_refused: db 0
upbe_stop_attempted: db 0
upbe_ui_accepted: db 0
upbe_refused: db 0
upbe_cleanup: db 0
upbe_ueo_valid: db 0
upbe_ready_busy: db 0
upbe_tick_busy: db 0
upbe_observe_busy: db 0
align 8
upbe_export: times 576 db 0
upbe_export_original: times 40 db 0
upbe_export_runtime: times 128 db 0
upbe_state_end:
%endmacro
WDATA_DEFER WDATA_gui_settings_update_backend
