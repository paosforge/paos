; Opt-in BSP-only health boundary witness. PHG1/v1..v3/1216 or v4/1472, attrs7.
; v5 adds paired R26A/5248 RAM snapshots from the full-attach provider.
; v4 adds paired cached packet/profile extensions; no new observation sites.
; v3 adds cached native RAM status in the existing reserved snapshot tail.
; v2 only with NET_REFUSAL: actual first-DEFER -> network-WITHHOLD edge5.
; Independent diagnostic; no policy consumer. First returned net decision and
; first terminal checkpoint/G9/publisher outcome only, maximum TWO SetVariable
; ATTEMPTS, even on EFI error. No probe, allocation, retry, readback or tick IO.
; Persistence is a positive lower bound, NOT proof this writer returned. A last
; record or absence cannot locate a stall/cause. Firmware writes perturb timing.
%ifndef PAOS_HEALTH_PROGRESS_INC
%define PAOS_HEALTH_PROGRESS_INC 1
%ifndef PAOS_HEALTH_PROGRESS
%define PAOS_HEALTH_PROGRESS 0
%endif
%ifndef PAOS_HEALTH_PROGRESS_NET_REFUSAL
%define PAOS_HEALTH_PROGRESS_NET_REFUSAL 0
%endif
%ifndef PAOS_HEALTH_PROGRESS_NATIVE_STATUS
%define PAOS_HEALTH_PROGRESS_NATIVE_STATUS 0
%endif
%ifndef PAOS_HEALTH_PROGRESS_PACKET_PATH
%define PAOS_HEALTH_PROGRESS_PACKET_PATH 0
%endif
%if PAOS_HEALTH_PROGRESS_PACKET_PATH != 0 && PAOS_HEALTH_PROGRESS_PACKET_PATH != 1
%error "PAOS_HEALTH_PROGRESS_PACKET_PATH must be 0 or 1"
%endif
%if PAOS_HEALTH_PROGRESS_PACKET_PATH && !PAOS_HEALTH_PROGRESS_NATIVE_STATUS
%error "PACKET_PATH requires PAOS_HEALTH_PROGRESS_NATIVE_STATUS"
%endif
%ifndef PAOS_HEALTH_PROGRESS_ATTACH_TRACE
%define PAOS_HEALTH_PROGRESS_ATTACH_TRACE 0
%endif
%if PAOS_HEALTH_PROGRESS_ATTACH_TRACE != 0 && PAOS_HEALTH_PROGRESS_ATTACH_TRACE != 1
%error "PAOS_HEALTH_PROGRESS_ATTACH_TRACE must be 0 or 1"
%endif
%if PAOS_HEALTH_PROGRESS_ATTACH_TRACE && !PAOS_HEALTH_PROGRESS_PACKET_PATH
%error "ATTACH_TRACE requires PAOS_HEALTH_PROGRESS_PACKET_PATH"
%endif
; Pinned RESOURCE R26A/v1 capacity640, not the superseded capacity512 proposal.
%define HP_ATTACH_SIZE 5248
%define HP_RECORD_SIZE (1216 + 256*PAOS_HEALTH_PROGRESS_PACKET_PATH + 2*HP_ATTACH_SIZE*PAOS_HEALTH_PROGRESS_ATTACH_TRACE)
%if PAOS_HEALTH_PROGRESS_NATIVE_STATUS != 0 && PAOS_HEALTH_PROGRESS_NATIVE_STATUS != 1
%error "PAOS_HEALTH_PROGRESS_NATIVE_STATUS must be 0 or 1"
%endif
%if PAOS_HEALTH_PROGRESS_NATIVE_STATUS && (!PAOS_HEALTH_PROGRESS || !PAOS_HEALTH_PROGRESS_NET_REFUSAL)
%error "NATIVE_STATUS requires PAOS_HEALTH_PROGRESS and NET_REFUSAL"
%endif
%if PAOS_HEALTH_PROGRESS_NET_REFUSAL != 0 && PAOS_HEALTH_PROGRESS_NET_REFUSAL != 1
%error "PAOS_HEALTH_PROGRESS_NET_REFUSAL must be 0 or 1"
%endif
%if PAOS_HEALTH_PROGRESS_NET_REFUSAL && !PAOS_HEALTH_PROGRESS
%error "NET_REFUSAL requires PAOS_HEALTH_PROGRESS"
%endif
%if PAOS_HEALTH_PROGRESS != 0 && PAOS_HEALTH_PROGRESS != 1
%error "PAOS_HEALTH_PROGRESS must be 0 or 1"
%endif
%if PAOS_HEALTH_PROGRESS
%ifndef PAOS_NATIVE_TRACE_NONCE
%error "PAOS_HEALTH_PROGRESS requires PAOS_NATIVE_TRACE_NONCE"
%elif PAOS_NATIVE_TRACE_NONCE = 0
%error "PAOS_HEALTH_PROGRESS requires a nonzero composition nonce"
%endif
%endif
%macro HP_FIRST 0
%if PAOS_HEALTH_PROGRESS
    mov byte [rel hp_requested_edge],1
    call health_progress_observe
%endif
%endmacro
%macro HP_TERMINAL 1
%if PAOS_HEALTH_PROGRESS
    mov byte [rel hp_requested_edge],%1
    call health_progress_observe
%endif
%endmacro
%macro HP_NET_REFUSAL 0
%if PAOS_HEALTH_PROGRESS_NET_REFUSAL
    HP_TERMINAL 5
%endif
%endmacro
; First actual PARKED store, not the later snapshot's driver status or cause.
; RAM only, flags/GPRs preserved; default0 emits no instructions or storage.
%macro HP_PARKED_ORIGIN 1
%if PAOS_HEALTH_PROGRESS_NATIVE_STATUS
    pushfq
    cmp byte [rel hp_native_origin],0
    jne %%latched
    mov byte [rel hp_native_origin],%1
%%latched:
    popfq
%endif
%endmacro
; RAM-only values captured immediately after the ORIGINAL call returns.
; 0 vector storage,1 vector Set,2 vector Get,3 Ready storage,4 Ready Set,
; 5 vector core validator boolean,6 exact readback success,7 publisher return.
%macro HP_RETURNED 1
%if PAOS_HEALTH_PROGRESS
    pushfq
    mov [rel hp_status+%1*8],rax
    or qword [rel hp_status_valid],1 << %1
    popfq
%endif
%endmacro
%macro HP_CURSOR 1
%if PAOS_HEALTH_PROGRESS
    mov dword [rel hp_cursor],%1
%endif
%endmacro
%macro HP_OUTCOME 1
%if PAOS_HEALTH_PROGRESS
    mov dword [rel hp_outcome],%1
%endif
%endmacro
%macro HP_PUBLISH_BEGIN 0
%if PAOS_HEALTH_PROGRESS
    mov qword [rel hp_status_valid],0
    mov dword [rel hp_outcome],0
%endif
%endmacro
%macro HP_READBACK_OK 0
%if PAOS_HEALTH_PROGRESS
    pushfq
    mov qword [rel hp_status+6*8],1
    or qword [rel hp_status_valid],1 << 6
    popfq
%endif
%endmacro

; Keep deferred data definition top-level: the fail-closed BSP scanner collects
; macro bodies without nested-definition depth. Registration stays at emission.
%macro WDATA_health_progress 0
alignb 16
hp_record: resb HP_RECORD_SIZE
hp_status: resq 8
hp_status_valid: resq 1
hp_first_set_status: resq 1
hp_cursor: resd 1
hp_outcome: resd 1
hp_first_gate: resd 1
hp_requested_edge: resb 1
hp_first_seen: resb 1
hp_terminal_seen: resb 1
hp_first_recorded: resb 1
hp_attempts: resb 1
hp_first_set_returned: resb 1
%if PAOS_HEALTH_PROGRESS_NATIVE_STATUS
hp_native_origin: resb 1
%endif
%endmacro

%macro PAOS_HEALTH_PROGRESS_CODE 0
%if PAOS_HEALTH_PROGRESS
; Macros enter with original RAX/flags/live arguments intact. Save *all* GPRs,
; DF/RFLAGS, XMM0..15 and MXCSR before copies/guards/firmware, either stack parity.
; No guest/IRQ/AP caller; existing selected sites are serialized BSP only.
health_progress_observe:
    pushfq
    push rax
    push rbp
    mov rbp,rsp
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    and rsp,-16
    sub rsp,320
%assign hp_x 0
%rep 16
    movdqu [rsp+48+hp_x*16],xmm %+ hp_x
%assign hp_x hp_x+1
%endrep
    stmxcsr [rsp+304]
    cld
    movzx r12d,byte [rel hp_requested_edge]
    cmp r12d,1
    jne %%terminal
    cmp byte [rel hp_first_seen],0
    jne %%out
    mov byte [rel hp_first_seen],1       ; even refusal is never retried
    mov eax,[rbp+8]                     ; actual returned net predicate EAX
    mov [rel hp_first_gate],eax
    jmp %%eligible
%%terminal:
    cmp r12d,2
    jb %%out
%if PAOS_HEALTH_PROGRESS_NET_REFUSAL
    cmp r12d,5
    ja %%out
    jne %%terminal_claim
    ; Only the returned real predicate at the first refusal-latch site may
    ; consume edge5. No new probe, and rejected edge5 leaves the terminal free.
    cmp dword [rbp+8],C3WD_NET_WITHHOLD
    jne %%out
    cmp dword [rel hp_first_gate],C3WD_NET_DEFER
    jne %%out
    cmp byte [rel hp_first_recorded],1
    jne %%out
    cmp byte [rel hp_first_set_returned],1
    jne %%out
    cmp byte [rel hp_attempts],1
    jne %%out
    cmp byte [rel net_required],1
    jne %%out
    cmp byte [rel boot_nic_state],NIC_ST_PARKED
    jne %%out
    cmp byte [rel c3wd_net_withheld],1
    jne %%out
%%terminal_claim:
%else
    cmp r12d,4
    ja %%out
%endif
    cmp byte [rel hp_terminal_seen],0
    jne %%out
    mov byte [rel hp_terminal_seen],1
    cmp byte [rel hp_first_recorded],1
    jne %%out
%%eligible:
    cmp byte [rel hp_attempts],2
    jae %%out
    cmp byte [rel reset_wipe_done],0
    jne %%out
    cmp byte [rel pbm_try_media],0
    jne %%out
    cmp byte [rel pbm_manager_launch],1
    jne %%out
    cmp byte [rel pbm_safe_runtime_active],0
    jne %%out
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne %%out
    test byte [rel pbm_flags],PBM_HF_MUTABLE_ATTEMPT
    jz %%out
    movzx eax,byte [rel pbm_entry]
    cmp eax,PBM_ENTRY_PAOS_A
    je %%entry_ok
    cmp eax,PBM_ENTRY_PAOS_B
    jne %%out
%%entry_ok:
    cmp qword [rel native_progress_accepted],1
    jne %%out
    cmp byte [rel pbm_runtime_code_mapped],1
    jne %%out
    mov r14,[rel runtime_services]
    test r14,r14
    jz %%out
    cmp qword [r14+0x58],0
    je %%out
    cmp byte [rel paos_build_state],BID_ST_MATCH
    jne %%out
    ; Original validator accepted these bytes. Recompare live identity only;
    ; this diagnostic never substitutes for, or strengthens, boot admission.
    lea rbx,[rel native_progress_handoff]
    mov rax,[rel pbm_manager_sequence]
    test rax,rax
    jz %%out
    cmp [rbx+8],rax
    jne %%out
    mov rax,[rel pbm_attempt_nonce]
    test rax,rax
    jz %%out
    cmp [rbx+16],rax
    jne %%out
    mov rax,[rel pbm_state_generation]
    test rax,rax
    jz %%out
    cmp [rbx+24],rax
    jne %%out
    mov al,[rel pbm_entry]
    cmp [rbx+32],al
    jne %%out
    mov al,[rel pbm_profile]
    cmp [rbx+33],al
    jne %%out
    mov al,[rel pbm_reason]
    cmp [rbx+34],al
    jne %%out
    mov al,[rel pbm_flags]
    cmp [rbx+35],al
    jne %%out
    mov ax,[rel pbm_last_stage]
    cmp [rbx+36],ax
    jne %%out
    xor edx,edx
    xor ecx,ecx
    lea rsi,[rel pbm_payload_sha]
%%hash:
    mov al,[rsi+rcx]
    cmp [rbx+40+rcx],al
    jne %%out
    or dl,al
    inc ecx
    cmp ecx,32
    jb %%hash
    test dl,dl
    jz %%out
    lea rsi,[rel paos_build_measured]
    xor eax,eax
    mov ecx,32
%%build_nonzero:
    or al,[rsi]
    inc rsi
    loop %%build_nonzero
    test al,al
    jz %%out
    cmp qword [rel image_handle],0
    je %%out
    cmp r12d,1
    jne %%context_matches
    lea rdi,[rel hp_record]
    xor eax,eax
    mov ecx,HP_RECORD_SIZE/8
    rep stosq
    mov dword [rel hp_record],'PHG1'
    mov word [rel hp_record+4],1 + PAOS_HEALTH_PROGRESS_NET_REFUSAL + PAOS_HEALTH_PROGRESS_NATIVE_STATUS + PAOS_HEALTH_PROGRESS_PACKET_PATH + PAOS_HEALTH_PROGRESS_ATTACH_TRACE
    mov word [rel hp_record+6],HP_RECORD_SIZE
    mov rax,PAOS_NATIVE_TRACE_NONCE
    mov [rel hp_record+8],rax
    mov rax,[rel image_handle]
    mov [rel hp_record+16],rax
    lea rsi,[rel paos_build_measured]
    lea rdi,[rel hp_record+32]
    mov ecx,4
    rep movsq
    lea rsi,[rel native_progress_handoff]
    lea rdi,[rel hp_record+64]
    mov ecx,16
    rep movsq
    jmp %%snapshot
%%context_matches:
    mov rax,[rel image_handle]
    cmp [rel hp_record+16],rax
    jne %%out
    lea rsi,[rel paos_build_measured]
    lea rdi,[rel hp_record+32]
    mov ecx,4
    repe cmpsq
    jne %%out
    lea rsi,[rel native_progress_handoff]
    lea rdi,[rel hp_record+64]
    mov ecx,16
    repe cmpsq
    jne %%out
%%snapshot:
    lea r15,[rel hp_record+224]
    cmp r12d,1
    je %%capture
    add r15,480
%%capture:
    call health_progress_capture        ; RAM only, no fresh clock/NIC probes
%if PAOS_HEALTH_PROGRESS_PACKET_PATH
    call health_progress_packet_capture ; same guarded write, RAM only
%endif
%if PAOS_HEALTH_PROGRESS_ATTACH_TRACE
    call health_progress_attach_capture ; provider copies RAM; no device/firmware IO
%endif
    cmp r12d,1
    jne %%terminal_slot
    mov byte [rel hp_first_recorded],1
    mov dword [rel hp_record+28],1
    jmp %%publish
%%terminal_slot:
    mov dword [rel hp_record+28],3
    mov rax,[rel hp_first_set_status]
    mov [rel hp_record+192],rax
    movzx eax,byte [rel hp_first_set_returned]
    mov [rel hp_record+200],rax
%%publish:
    lea rdi,[rel pbm_health_var_guid]
    lea rsi,[rel hp_name]
    xor edx,edx                        ; original implicit PaOS namespace guard
    lea rcx,[rel hp_caller]
    call storage_access_nvram_require
    test rax,rax
    jnz %%out
    mov [rel hp_record+208],rax         ; actual diagnostic gate returned zero
    mov qword [rel hp_record+216],1
    inc byte [rel hp_attempts]          ; claim BEFORE firmware, errors consume it
    movzx eax,byte [rel hp_attempts]
    mov [rel hp_record+24],eax
    lea rdi,[rel hp_record]
    mov esi,HP_RECORD_SIZE-4
    call pbm_crc32
    mov [rel hp_record+HP_RECORD_SIZE-4],eax
    lea rcx,[rel hp_name]
    lea rdx,[rel pbm_health_var_guid]
    mov r8d,7
    mov r9d,HP_RECORD_SIZE
    lea rax,[rel hp_record]
    mov [rsp+32],rax                    ; MS ABI shadow + fifth argument
    call [r14+0x58]                    ; only diagnostic firmware call
    cmp r12d,1
    jne %%out
    mov [rel hp_first_set_status],rax    ; cannot be in its own stored first write
    mov byte [rel hp_first_set_returned],1
%%out:
    ldmxcsr [rsp+304]
%assign hp_x 0
%rep 16
    movdqu xmm %+ hp_x,[rsp+48+hp_x*16]
%assign hp_x hp_x+1
%endrep
    lea rsp,[rbp-104]
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rbp
    pop rax
    popfq
    ret

; R15 fixed zeroed 480B slot, R12=edge. All scalars are copied, not measured.
health_progress_capture:
    mov [r15],r12d
    mov eax,[rel hp_first_gate]
    mov [r15+4],eax
%assign hp_i 8
%rep 8
%if hp_i = 8
%define hp_sym net_required
%elif hp_i = 9
%define hp_sym boot_nic_state
%elif hp_i = 10
%define hp_sym pbm_manager_launch
%elif hp_i = 11
%define hp_sym pbm_profile
%elif hp_i = 12
%define hp_sym pbm_flags
%elif hp_i = 13
%define hp_sym pbm_safe_runtime_active
%elif hp_i = 14
%define hp_sym pbm_try_media
%else
%define hp_sym rpf_state
%endif
    mov al,[rel hp_sym]
    mov [r15+hp_i],al
%assign hp_i hp_i+1
%endrep
    mov rax,[rel rpf_f]
    mov [r15+16],rax
    mov al,[rel c3wd_checkpoint_rc]
    mov [r15+24],al
    mov al,[rel pbm_init_checkpoint_loaded]
    mov [r15+25],al
    mov al,[rel pbm_init_checkpoint_durable]
    mov [r15+26],al
    mov al,[rel pbm_runtime_code_mapped]
    mov [r15+27],al
    mov byte [r15+28],1                 ; eligibility proved runtime nonnull
    lea rsi,[rel pbm_init_checkpoint_record]
    lea rdi,[r15+32]
    mov ecx,16
    rep movsq
    mov al,[rel stab_state]
    mov [r15+160],al
    mov al,[rel stab_reason]
    mov [r15+161],al
    mov al,[rel pbm_strong_health_published]
    mov [r15+162],al
    mov al,[rel pbm_health_vector_published]
    mov [r15+163],al
    mov rax,[rel stab_armed_ms]
    mov [r15+168],rax
    mov rax,[rel stab_last_ms]
    mov [r15+176],rax
    mov rax,[rel stab_deadline_ms]
    mov [r15+184],rax
    ; Existing six scalar sample words only. Per-device block arrays excluded.
    lea rsi,[rel stab_arm_sample]
    lea rdi,[r15+192]
    mov ecx,6
    rep movsq
    lea rsi,[rel stab_now_sample]
    lea rdi,[r15+240]
    mov ecx,6
    rep movsq
    lea rsi,[rel udp_progress_record]
    lea rdi,[r15+288]
    mov ecx,12                        ; 88B record plus 8B revision
    rep movsq
    mov eax,[rel hp_cursor]
    mov [r15+384],eax
    mov eax,[rel hp_outcome]
    mov [r15+388],eax
    mov rax,[rel hp_status_valid]
    mov [r15+392],rax
    lea rsi,[rel hp_status]
    lea rdi,[r15+400]
    mov ecx,8
    rep movsq
%if PAOS_HEALTH_PROGRESS_NATIVE_STATUS
    ; NAR1/v3, only cached scalars. No registry walk, callback or hardware IO.
    ; This is snapshot-time state; the immutable origin may have been earlier.
    mov dword [r15+464],'NAR1'
    mov al,[rel hp_native_origin]
    mov [r15+468],al
    mov byte [r15+469],3
    xor edx,edx
%assign hp_bit 0
%rep 5
%if hp_bit = 0
%define hp_native_sym e5000b_registered
%elif hp_bit = 1
%define hp_native_sym e5000b_mac_ok
%elif hp_bit = 2
%define hp_native_sym e5000b_rings_ok
%elif hp_bit = 3
%define hp_native_sym e5000b_hw_ok
%else
%define hp_native_sym e5000b_link_up
%endif
    cmp byte [rel hp_native_sym],1
    sete al
    movzx eax,al
    shl eax,hp_bit
    or edx,eax
%assign hp_bit hp_bit+1
%endrep
    cmp qword [rel e5000b_recover_timeouts],0  ; cumulative, not attach-local
    setne al
    movzx eax,al
    shl eax,5
    or edx,eax
    cmp qword [rel e5000b_bdf],-1             ; discovery boolean, no address
    setne al
    movzx eax,al
    shl eax,6
    or edx,eax
    cmp dword [rel e5000b_matches],1
    sete al
    movzx eax,al
    shl eax,7
    or edx,eax
    movzx eax,byte [rel e5000b_reset_phase]
    and eax,31
    shl eax,8
    or edx,eax
    movzx eax,byte [rel e5000b_drain_expired]
    and eax,3
    shl eax,13
    or edx,eax
    mov [r15+470],dx
    ; Preserve raw words even unregistered; decoder then marks semantics UNKNOWN.
    mov eax,[rel e5000b_dev+dev.health]
    mov [r15+472],eax
    mov eax,[rel e5000b_dev+dev.flags]
    mov [r15+476],eax
    ; Former reserved bytes, NAR1 schema2/3. First/terminal paired samples.
    mov al,[rel e5000b_bmcr_valid]
    mov [r15+29],al
    mov ax,[rel e5000b_bmcr_before]
    mov [r15+30],ax
    mov ax,[rel e5000b_bmcr_after]
    mov [r15+164],ax
    mov ax,[rel e5000b_phy_state]
    mov [r15+166],ax
%endif
    ret
%if PAOS_HEALTH_PROGRESS_PACKET_PATH
; PKT1/v1, 128B paired appendices @1184/1312. Static scalar loads only:
; never dereference captured handles, walk membership, poll, allocate or call IO.
; Snapshot counters are cumulative and may precede later host traffic. Zero RX
; is no recorded completed/dropped frame, NOT proof of an empty DMA ring/wire.
health_progress_packet_capture:
    lea rdi,[rel hp_record+1184]
    cmp r12d,1
    je %%slot
    add rdi,128
%%slot:
    mov dword [rdi],'PKT1'
    mov word [rdi+4],1
    mov word [rdi+6],128
    xor edx,edx
    cmp byte [rel e5000b_registered],1
    sete dl
    lea rcx,[rel e5000b_dev]
    mov rax,[rel udp_nic_handle]
    mov [rdi+16],rax
    cmp rax,rcx
    sete al
    movzx eax,al
    shl eax,1
    or edx,eax
    mov rax,[rel udp_static_owner_handle]
    mov [rdi+24],rax
    cmp rax,rcx
    sete al
    movzx eax,al
    shl eax,3
    or edx,eax
    mov rax,[rel udp_dynamic_owner_handle]
    mov [rdi+32],rax
    cmp rax,rcx
    sete al
    movzx eax,al
    shl eax,4
    or edx,eax
    mov rax,[rel udp_oob_nic_handle]
    mov [rdi+40],rax
    cmp rax,rcx
    sete al
    movzx eax,al
    shl eax,5
    or edx,eax
    lea rcx,[rel e5000b_rx_poll]
    cmp [rel udp_rx_poll_fn],rcx
    sete al
    movzx eax,al
    shl eax,2
    or edx,eax
    cmp [rel udp_oob_rx_poll_fn],rcx
    sete al
    movzx eax,al
    shl eax,6
    or edx,eax
    mov [rdi+8],rdx
    mov eax,[rel udp_our_ip]
    mov [rdi+48],eax
    mov eax,[rel udp_our_ip2]
    mov [rdi+52],eax
    mov eax,[rel udp_our_ip3]
    mov [rdi+56],eax
    mov eax,[rel udp_our_mac]
    mov [rdi+60],eax
    mov ax,[rel udp_our_mac+4]
    mov [rdi+64],ax
    mov eax,[rel udp_primary_mac]
    mov [rdi+66],eax
    mov ax,[rel udp_primary_mac+4]
    mov [rdi+70],ax
    mov al,[rel udp_lab_fleet]
    mov [rdi+72],al
    mov al,[rel udp_public_dhcp]
    mov [rdi+73],al
    mov al,[rel udp_netcfg_static]
    mov [rdi+74],al
    mov al,[rel udp_public_link_up]
    mov [rdi+75],al
    mov al,[rel udp_fleet_link_up]
    mov [rdi+76],al
    mov al,[rel udp_dhcp_boot_pending]
    mov [rdi+77],al
    mov al,[rel udp_dhcp_boot_recovery_pending]
    mov [rdi+78],al
    mov rax,[rel e5000b_tx_frames]
    mov [rdi+80],rax
    mov rax,[rel e5000b_rx_frames]
    mov [rdi+88],rax
    mov rax,[rel e5000b_tx_drops]
    mov [rdi+96],rax
    mov rax,[rel e5000b_rx_drops]
    mov [rdi+104],rax
    mov rax,[rel e5000b_tx_timeouts]
    mov [rdi+112],rax
    mov rax,[rel e5000b_owner_mismatches]
    mov [rdi+120],rax
    ret
%endif
%if PAOS_HEALTH_PROGRESS_ATTACH_TRACE
; Two independent R26A/v1 slots @1440/6688. Snapshot return/header failure is
; unavailable evidence: clear just this slot, never change a health/return gate.
; The provider owns the trace and sampled counters. No captured handle is used.
health_progress_attach_capture:
    lea rdi,[rel hp_record+1440]
    cmp r12d,1
    je %%attach_slot
    add rdi,HP_ATTACH_SIZE
%%attach_slot:
    push rdi
    mov esi,HP_ATTACH_SIZE
    call rtl8126_attach_snapshot
    pop rdi
    cmp eax,HP_ATTACH_SIZE
    jne %%attach_unavailable
    cmp dword [rdi],0x41363252
    jne %%attach_unavailable
    cmp word [rdi+4],1
    jne %%attach_unavailable
    cmp word [rdi+6],HP_ATTACH_SIZE
    jne %%attach_unavailable
    cmp dword [rdi+8],640
    ja %%attach_unavailable
    ret
%%attach_unavailable:
    xor eax,eax
    mov ecx,HP_ATTACH_SIZE/8
    cld
    rep stosq
    ret
%endif
align 2
hp_name: dw 'P','a','O','S','H','e','a','l','t','h','P','r','o','g','r','e','s','s',0
hp_caller: db 'health-progress',0
%include "core/abi/wdata.inc"
WDATA_BSS_DEFER WDATA_health_progress
%endif
%endmacro
%endif
