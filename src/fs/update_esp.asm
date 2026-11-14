;; MODULE fs/update_esp
;; LAYER 4
;; EXPORTS update_esp_finish, update_esp_cleanup, update_esp_feed, update_esp_observe, update_esp_observe_raw, update_esp_current, update_esp_readonly, update_esp_begin, update_esp_io, update_esp_freeze, update_esp_reclaim
;; IMPORTS hv/settings_update_service, hv/app_vm, boot/boot_esp_guid, fs/guest_volume, fs/fat32_disk, fs/update_release, core/memory_budget, core/lib/mem, core/lib/sha256, core/smp, boot/header
;; CAPS CAP_BLOCK_READ, CAP_BLOCK_WRITE
;; OWNER rc-fs-claude
;; CONTEXT: bsp_only
; Included by fat32_disk. Native supervisor ABI only; no guest address or path.
; The fixed native accessor is authority. A returned tuple is never authority.
; CHECK uses the native no-argument RO provider. DOWNLOAD retains ordinary
; OWNER+SPECIAL admission, unavailable to Settings until genuine staged scope.
%ifndef UPDATE_ESP_INCLUDED
%define UPDATE_ESP_INCLUDED 1
UE_MAX equ 67108864
UE_CHUNK equ 4096
UE_OBJ_SIZE equ 80                 ; id, fixedID, size, entryLBA, entryOff, entry32, flags
UE_TEMP equ 9
UE_RAW_MAX equ 3312                ; five descriptors + 1024 + four 512 records
UE_MEDIA_LENGTH equ 8
UE_MEDIA_OFFSETS equ 16
UE_MEDIA_SHA equ 56
UE_MEDIA_RAW equ 88
UE_MEDIA_BYTES equ UE_MEDIA_RAW+UE_RAW_MAX
UE_SOURCE equ 0xfffffff1
%include "core/abi/memory_budget.inc"
UE_RAM_BYTES equ UE_MAX+UE_CHUNK
UE_MEMORY_OWNER equ 0x55504553        ; UPES, private CPU-only snapshot, never guest RAM

; No operands. Return nonreused binding (>0), -1 refusal, -2 busy.
update_esp_begin:
    push rbx
    cmp dword [rel ue_state],0
    jne .busy
    cmp qword [rel ue_observation_serial],-1
    je .no
    cmp qword [rel ue_sequence],-1
    je .no
    cmp byte [rel boot_esp_part_guid_ok],1
    jne .no
    mov dword [rel ue_observation_valid],0 ; new attempted original cannot relabel old media
    lea rdi,[rel ue_original]
    mov esi,40
    lea rdx,[rel ue_runtime]
    mov ecx,128
    call settings_update_service_original
    cmp eax,1
    jne .no
    cmp dword [rel ue_original+8],1
    je .op
    cmp dword [rel ue_original+8],2
    jne .no
.op:
    call vfs_copy_busy
    test eax,eax
    jnz .busy
    cmp dword [rel fd_cp_phase],FD_CP_IDLE
    jne .busy
    cmp dword [rel fd_dir_gate],0
    jne .busy
    lea rdi,[rel boot_esp_part_guid]
    call fat32_disk_boot_esp_open
    test rax,rax
    js .no
    lea rdi,[rel fd_ro_ctx]
    cmp dword [rdi+FD_MOUNTED],1
    jne .no
    cmp byte [rdi+FD_PART_ESP],1
    jne .no
    lea rsi,[rel boot_esp_part_guid]
    lea rdi,[rel fd_ro_ctx+FD_PART_GUID]
    mov edx,16
    call memcmp
    test eax,eax
    jnz .no
    lea rdi,[rel ue_ctx]
    lea rsi,[rel fd_ro_ctx]
    mov edx,FD_CTX_SIZE
    call memcpy
    ; Original device/extent/GUIDs, never operands supplied by a caller.
    lea rbx,[rel ue_desc]
    mov rax,[rel ue_ctx+FD_DEV]
    mov [rbx],rax
    mov rax,[rel ue_ctx+FD_MOUNT_GEN]
    mov [rbx+8],rax
    mov rax,[rel ue_ctx+FD_PART_LBA]
    mov [rbx+16],rax
    mov rax,[rel ue_ctx+FD_PART_SECTORS]
    mov [rbx+24],rax
    lea rdi,[rbx+32]
    lea rsi,[rel ue_ctx+FD_DISK_GUID]
    mov edx,32
    call memcpy
    ; Native owner/session; runtime instance/generation; original serial/deadline;
    ; original signed runtime source identity. All retained bytes rechecked below.
    lea rdi,[rbx+64]
    lea rsi,[rel ue_original+16]
    mov edx,16
    call memcpy
    lea rdi,[rbx+80]
    lea rsi,[rel ue_runtime+8]
    mov edx,16
    call memcpy
    mov rax,[rel ue_original]
    mov [rbx+96],rax
    mov rax,[rel ue_original+32]
    mov [rbx+104],rax
    lea rdi,[rbx+112]
    lea rsi,[rel ue_runtime+64]
    mov edx,16
    call memcpy
    mov rax,[rel ue_sequence]
    inc rax
    mov [rel ue_sequence],rax       ; consumed even if acquisition refuses
    cmp dword [rel ue_original+8],1
    je .check_lease
    mov [rbx+128],rax
    mov rdi,rbx
    call guest_volume_acquire
    jmp .acquired
.check_lease:
    mov qword [rbx+128],0           ; local binding is never a CHECK lease epoch
    call guest_volume_acquire_check ; derives original identity, never our tuple
.acquired:
    test rax,rax
    jz .no
    mov [rel ue_lease],rax
    ; New actual custody only. Worker exit/freeze/reclaim never clear these
    ; per-binding facts; failed writes before any publication remain visible.
    lea rdi,[rel ue_facts_start]
    xor esi,esi
    mov edx,ue_facts_end-ue_facts_start
    call memset
    mov dword [rel ue_readonly],1
    mov dword [rel ue_state],1
    cmp dword [rel ue_original+8],1
    jne .ready
    ; A cached descriptor is a fact, not permission. Validate the independently
    ; selected identity in full, then retain the provider's actual shared epoch.
    lea rdi,[rel ue_lease_snapshot]
    xor esi,esi
    mov edx,136
    call memset
    mov rdi,[rel ue_lease]
    lea rsi,[rel ue_lease_snapshot]
    mov edx,136
    call guest_volume_snapshot
    test rax,rax
    jnz .snapshot_failed
    lea rdi,[rel ue_desc]
    lea rsi,[rel ue_lease_snapshot]
    mov edx,128
    call memcmp
    test eax,eax
    jnz .snapshot_failed
    mov rax,[rel ue_lease_snapshot+128]
    test rax,rax
    jz .snapshot_failed
    mov [rel ue_desc+128],rax
.ready:
    mov dword [rel ue_ctx+FD_TX_BUSY],0
    mov dword [rel ue_ctx+FD_SWEEP_DONE],0
    mov dword [rel ue_ctx+FD_SWEEP_CLUSTER],0
    lea rax,[rel ue_ctx]
    mov [rel ue_mount+fsmount.priv],rax
    lea rdi,[rel ue_objects]
    xor esi,esi
    mov edx,UE_OBJ_SIZE*UE_TEMP
    call memset
    call ue_current
    test rax,rax
    jnz .no                        ; acquired custody retained, frozen; never released here
    ; Native original pre-effect records, not a worker projection. Errors are
    ; retained distinctly from absence; positive admission must reject them.
    call ue_capture_before
    mov rax,[rel ue_sequence]
    cmp dword [rel ue_state],1
    jne .no
    pop rbx
    ret
.snapshot_failed:
    call update_esp_freeze           ; retain acquired custody; no cleanup/retry
    jmp .no
.busy:
    mov rax,-2
    pop rbx
    ret
.no:
    mov rax,-1
    pop rbx
    ret

update_esp_current:
    push rbx
    mov ebx,esi
    cmp rdi,[rel ue_sequence]
    jne .bad
    cmp ebx,2
    ja .bad
    call ue_current
    test rax,rax
    jnz .bad
    cmp ebx,2
    je .yes
    cmp ebx,[rel ue_readonly]
    jne .bad
.yes:
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret
update_esp_readonly:
    cmp rdi,[rel ue_sequence]
    jne .bad
    cmp esi,1
    ja .bad
    cmp esi,1
    je .ro
    cmp dword [rel ue_original+8],2
    jne .bad
    cmp qword [rel ue_rw_issued],-1
    je .overflow
    inc qword [rel ue_rw_issued]    ; BEFORE native RW-entry/current dispatch
    mov qword [rel ue_ro_confirmed],0
    push rdi
    call ue_current
    pop rdi
    test rax,rax
    jnz .bad
    call ue_admitted
    test rax,rax
    jnz .bad
    mov dword [rel ue_readonly],0
    mov eax,1
    ret
.ro:
    mov dword [rel ue_readonly],1   ; safety gate closes even after lost custody
    cmp qword [rel ue_restore_attempts],-1
    je .overflow
    inc qword [rel ue_restore_attempts]
    mov qword [rel ue_ro_confirmed],0
    mov esi,1
    push rdi
    call update_esp_current
    pop rdi
    cmp eax,1
    jne .bad
    ; This confirms the actual native gate AND unchanged current custody.
    ; It is never a hardware BLKF_RO claim or a terminal staging verdict.
    mov qword [rel ue_ro_confirmed],1
    ret
.overflow:
    push rdi
    call ue_fault
    pop rdi
.bad:
    xor eax,eax
    ret

; Every operation and every original physical IO. Failure freezes, no retry.
ue_current:
    push rbx
    cmp dword [rel ue_state],1
    jne .no
    lea rdi,[rel ue_check]
    mov esi,40
    lea rdx,[rel ue_check+40]
    mov ecx,128
    call settings_update_service_original
    cmp eax,1
    jne .freeze
    lea rdi,[rel ue_check]
    lea rsi,[rel ue_original]
    mov edx,40
    call memcmp
    test eax,eax
    jnz .freeze
    lea rdi,[rel ue_check+40]
    lea rsi,[rel ue_runtime]
    mov edx,128
    call memcmp
    test eax,eax
    jnz .freeze
    mov rdi,[rel ue_lease]
    call guest_volume_current
    test rax,rax
    jnz .freeze
    call ue_ram_current
    test rax,rax
    jnz .freeze
    xor eax,eax
    pop rbx
    ret
.freeze:
    cmp qword [rel ue_rw_issued],0
    je .freeze_clean
    mov qword [rel ue_uncertain],1 ; possible partial RW despite zero publication
.freeze_clean:
    mov dword [rel ue_state],2
    mov rdi,[rel ue_lease]
    call guest_volume_freeze
.no:
    mov rax,-1
    pop rbx
    ret

 ; Original-specific ordinary cleanup, including no-BEGIN and failed capture.
; RDI actual reserved original40, RSI qualified native runtime128 or0.
; EAX1 proves no own retained broker custody;0 unknown/refused. No grant,
; publication, observation or terminal-success credit. Uncertain release is
; retained and never retried. Empty success performs no service/VM/ESP action.
update_esp_cleanup:
    push rbx
    push r12
    push r13
    mov r13,rdi
    mov r12,rsi
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp dword [rel ue_busy],0
    jne .bad
    mov rdi,r13
    mov esi,40
    call ue_observe_span
    test eax,eax
    jz .bad
    cmp qword [r13],0
    je .bad
    mov eax,[r13+8]
    dec eax
    cmp eax,3
    ja .bad
    cmp dword [r13+12],1
    jne .bad
    cmp qword [r13+16],0
    je .bad
    cmp qword [r13+24],0
    je .bad
    cmp qword [r13+32],0
    je .bad
    cmp dword [rel ue_state],0
    jne .held
    cmp qword [rel ue_memory_token],0
    jne .bad
    cmp qword [rel ue_buffer],0
    jne .bad
    cmp qword [rel ue_lease],0
    je .yes
    cmp qword [rel ue_reclaim_attempted],1
    je .yes                      ; prior confirmed release, no new effect
    jmp .bad
.held:
    cmp dword [rel ue_original+8],2
    ja .bad                      ; AUTO has no retained ESP effect binding
    cmp dword [rel ue_state],2
    ja .bad                      ; uncertain reclaim attempt cannot be replayed
    mov rdi,r12
    mov esi,128
    call ue_observe_span
    test eax,eax
    jz .bad
    mov rdi,r13
    mov esi,40
    mov rdx,r12
    mov ecx,128
    call ue_observe_disjoint
    test eax,eax
    jz .bad
    mov rdi,r13
    lea rsi,[rel ue_original]
    mov edx,40
    call memcmp
    test eax,eax
    jnz .bad
    mov rdi,r12
    lea rsi,[rel ue_runtime]
    mov edx,128
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[rel ue_runtime]
    mov esi,128
    call app_vm_updater_stopped   ; actual original stopped root, before effects
    cmp eax,1
    jne .bad
    cmp dword [rel ue_state],2
    je .reclaim
    call update_esp_freeze
.reclaim:
    call update_esp_reclaim
    test rax,rax
    jnz .bad
.yes:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Normal retirement requires genuine native stopped receipt, not guest ACK.
update_esp_freeze:
    mov dword [rel ue_state],2
    mov rdi,[rel ue_lease]
    jmp guest_volume_freeze
update_esp_reclaim:
    cmp dword [rel ue_state],2
    jne ue_refused
    lea rdi,[rel ue_runtime]
    mov esi,128
    call app_vm_updater_stopped
    cmp eax,1
    jne ue_refused
    call ue_ram_release            ; genuine stopped root; never guest cleanup ACK
    test rax,rax
    jnz ue_refused                  ; retain exact memory and lease on refusal
    mov qword [rel ue_reclaim_attempted],1
    mov dword [rel ue_state],3       ; one attempt, uncertain remains terminal
    mov rdi,[rel ue_lease]
    mov rsi,[rel ue_desc+128]
    call guest_volume_reclaim
    test rax,rax
    jnz ue_uncertain_return
    mov dword [rel ue_state],0
    xor eax,eax
    ret


; One original PCF1 feed, consumed only for the independently current binding.
; RDI=binding, RSI=trusted-native bounce1024, EDX=exact1024 ->1CURRENT,
; 2AVAILABLE,-1REFUSED,-2BUSY,-3UNCERTAIN. No terminal or worker verdict input.
update_esp_feed:
    push rbx
    push rbp
    push r12
    mov r12,rsi
    mov ebp,edx
    cmp rdi,[rel ue_sequence]
    jne .refused
    call smp_current_logical
    test eax,eax
    jnz .refused
    cmp dword [rel ue_busy],0
    jne .busy
    cmp dword [rel ue_finish_attempted],0
    jne .refused
    cmp dword [rel ue_feed_attempted],0
    jne .refused
    mov dword [rel ue_busy],1
    mov dword [rel ue_feed_attempted],1 ; never retried after a real attempt
    mov dword [rel ue_class],3
    call ue_current
    test rax,rax
    jnz .bad
    cmp ebp,1024
    jne .bad
    mov rdi,r12
    mov esi,1024
    call ue_observe_span
    test eax,eax
    jz .bad
    cmp dword [rel ue_observation_valid],1
    jne .bad
    cmp dword [rel ue_readonly],1
    jne .bad
    mov rax,[rel ue_rw_issued]
    or rax,[rel ue_write_issued]
    or rax,[rel ue_flush_issued]
    or rax,[rel ue_published_mask]
    or rax,[rel ue_uncertain]
    jnz .bad
    lea rdi,[rel ue_feed_raw]
    mov rsi,r12
    mov edx,1024
    call memcpy
    lea rdi,[rel ue_feed_sha]
    lea rsi,[rel ue_feed_raw]
    mov edx,1024
    call sha256_hash
    test rax,rax
    jnz .bad
    call ue_current_proof
    test rax,rax
    jnz .bad
    ; Select only the retained native PRL belonging to actual current Active.
    mov edi,3
    cmp dword [rel ue_active_slot],0
    je .record
    mov edi,4
.record:
    call ue_before_record
    xor ebx,ebx
    cmp dword [rax+4],2
    je .classify
    cmp dword [rax+4],1
    jne .bad
    cmp qword [rax+8],512
    jne .bad
    lea rbx,[rax+48]
.classify:
    lea rdi,[rel ue_feed_raw]
    mov rsi,rbx
    lea rdx,[rel ue_active_sha]
    mov rcx,[rel ue_active_size]
    call update_release_feed_classify
    cmp rax,1
    je .classified
    cmp rax,2
    jne .bad
.classified:
    mov ebx,eax
    cmp dword [rel ue_original+8],2
    jne .retain
    cmp ebx,2                   ; DOWNLOAD cannot stage CURRENT or an equal version
    jne .bad
.retain:
    call ue_current
    test rax,rax
    jnz .bad
    call update_public_policy_get
    test rax,rax
    jz .bad
    cmp edx,23408
    jne .bad
    lea rsi,[rax+48]
    lea rdi,[rel ue_policy_sha]
    mov edx,32
    call memcpy
    lea rsi,[rel ue_feed_raw+320]
    lea rdi,[rel ue_offer_sha]
    mov edx,32
    call memcpy
    mov rax,[rel ue_feed_raw+384]
    mov [rel ue_offer_size],rax
    cmp dword [rel ue_original+8],2
    jne .success
    call ue_event_next
    test rax,rax
    jnz .bad
    mov rax,[rel ue_native_event]
    mov [rel ue_release_admitted],rax ; actual authentication before publication
.success:
    mov [rel ue_class],ebx
    mov dword [rel ue_feed_verified],1
    mov eax,ebx
    jmp .unlock
.bad:
    mov rax,-1
    cmp qword [rel ue_uncertain],0
    je .unlock
    mov rax,-3
.unlock:
    mov dword [rel ue_busy],0
    jmp .out
.busy:
    mov rax,-2
    jmp .out
.refused:
    mov rax,-1
.out:
    pop r12
    pop rbp
    pop rbx
    ret

; Internal canonical descriptor index0..4, retained native bytes only.
ue_before_record:
    lea rax,[rel ue_before_offsets]
    mov rax,[rax+rdi*8]
    lea rdx,[rel ue_before_raw]
    add rax,rdx
    ret

; Fresh canonical descriptor helpers. Indices are private fixed native records.
ue_after_record:
    lea rax,[rel ue_after_offsets]
    mov rax,[rax+rdi*8]
    lea rdx,[rel ue_after_raw]
    add rax,rdx
    ret

; Same fixed record before/after, including genuine absence. ERROR never equal.
ue_record_equal:
    push rbx
    mov ebx,edi
    call ue_before_record
    cmp dword [rax+4],3
    je .bad
    mov rcx,rax
    mov edi,ebx
    call ue_after_record
    mov rsi,rax
    mov rdi,rcx
    mov rdx,[rdi+8]
    add rdx,48
    call memcmp
    test eax,eax
    jnz .bad
    xor eax,eax
    pop rbx
    ret
.bad:
    mov rax,-1
    pop rbx
    ret

; Identify the exact selected original copy, never a caller-selected journal.
ue_selected_copy:
    mov edi,1
    call ue_before_record
    add rax,48
    cmp rax,[rel ue_selected_state]
    je .zero
    mov edi,2
    call ue_before_record
    add rax,48
    cmp rax,[rel ue_selected_state]
    jne .bad
    mov eax,1
    ret
.zero:
    xor eax,eax
    ret
.bad:
    mov rax,-1
    ret

ue_verify_active:
    sub rsp,8
    mov edi,[rel ue_active_slot]
    add edi,7
    lea rsi,[rel ue_finish_sha]
    call ue_hash_fixed
    cmp rax,[rel ue_active_size]
    jne .bad
    lea rdi,[rel ue_finish_sha]
    lea rsi,[rel ue_active_sha]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    xor eax,eax
    jmp .out
.bad:
    mov rax,-1
.out:
    add rsp,8
    ret

; Before first slot publication, prove native-owned RAM equals the signed offer,
; fresh Active/PBMF/outgoing PRL are unchanged, and required retirement really
; reached the other journal. The copy engine subsequently verifies every byte.
ue_pre_slot:
    push rbx
    push r12
    push r13
    cmp qword [rel ue_first_slot_publication],0
    jne .bad
    call ue_ram_current
    test rax,rax
    jnz .bad
    mov rsi,[rel ue_buffer]
    test rsi,rsi
    jz .bad
    mov rdx,[rel ue_objects+UE_OBJ_SIZE*8+16]
    cmp rdx,[rel ue_offer_size]
    jne .bad
    lea rdi,[rel ue_publish_sha]
    call sha256_hash
    test rax,rax
    jnz .bad
    lea rdi,[rel ue_publish_sha]
    lea rsi,[rel ue_offer_sha]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    mov rdi,[rel ue_selected_state]
    lea rsi,[rel ue_stage_start]
    call update_release_stage_start
    test eax,eax
    jz .bad
    mov r12d,eax
    call ue_selected_copy
    test eax,eax
    js .bad
    mov r13d,eax
    lea rdi,[rel ue_after_mask]
    xor esi,esi
    call ue_capture_records
    test rax,rax
    jnz .bad
    xor edi,edi
    call ue_record_equal
    test rax,rax
    jnz .bad
    lea edi,[r13d+1]
    call ue_record_equal
    test rax,rax
    jnz .bad
    mov edi,[rel ue_active_slot]
    add edi,3
    call ue_record_equal
    test rax,rax
    jnz .bad
    mov edi,2
    sub edi,r13d
    cmp r12d,2
    je .retired
    call ue_record_equal
    test rax,rax
    jnz .bad
    jmp .active
.retired:
    lea ecx,[rdi+1]              ; state id3/4 => publication mask bit2/3
    bt qword [rel ue_published_mask],rcx
    jnc .bad
    call ue_after_record
    cmp dword [rax+4],1
    jne .bad
    cmp qword [rax+8],512
    jne .bad
    lea rdi,[rax+48]
    lea rsi,[rel ue_stage_start]
    mov edx,512
    call memcmp
    test eax,eax
    jnz .bad
.active:
    call ue_verify_active
    test rax,rax
    jnz .bad
    xor eax,eax
    jmp .out
.bad:
    mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Actual terminal/scratch record has exactly the expected complete fixed bytes.
; EDI descriptor index, RSI private expected512, EDX exact length.
ue_record_matches:
    push rbx
    push r12
    push r13
    mov r12,rsi
    mov r13d,edx
    call ue_after_record
    cmp dword [rax+4],1
    jne .bad
    cmp [rax+8],r13
    jne .bad
    lea rdi,[rax+48]
    mov rsi,r12
    mov rdx,r13
    call memcmp
    test eax,eax
    jnz .bad
    xor eax,eax
    jmp .out
.bad:
    mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Actual fresh PBMF is assessed against original owner/state and admitted PRL.
; No worker expected hash, sequence, selected copy or verdict is an operand.
ue_expected_after:
    push rbx
    xor edi,edi
    call ue_after_record
    cmp dword [rax+4],1
    jne .bad
    cmp qword [rax+8],1024
    jne .bad
    lea rbx,[rax+48]
    xor edi,edi
    call ue_before_record
    lea rdi,[rax+48]
    mov rsi,[rel ue_selected_state]
    mov rdx,rbx
    lea rcx,[rel ue_feed_raw+256]
    lea r8,[rel ue_stage_start]
    lea r9,[rel ue_stage_armed]
    call update_release_stage_expected
    test eax,eax
    jz .bad
    mov [rel ue_stage_kind],eax
    xor eax,eax
    pop rbx
    ret
.bad:
    mov rax,-1
    pop rbx
    ret

; One fixed publication graph on the actual native-owned TEMP bytes. EDI target.
; Retirement -> inactive payload -> exact admitted PRL -> signed successor PBMF
; -> one unverified Trial. Active payload and its PRL are never targets.
ue_publication_gate:
    push rbx
    push r12
    push r13
    mov r12d,edi
    lea ecx,[edi-1]
    bt qword [rel ue_published_mask],rcx
    jc .bad
    cmp edi,7
    jae .slot
    call ue_ram_current
    test rax,rax
    jnz .bad
    mov rbx,[rel ue_buffer]
    test rbx,rbx
    jz .bad
    mov r13,[rel ue_objects+UE_OBJ_SIZE*8+16]
    cmp r12d,1
    je .manifest
    cmp r12d,5
    jae .release
    ; Only the exact other-copy retirement may precede candidate publication.
    call ue_selected_copy
    test eax,eax
    js .bad
    mov ecx,1
    sub ecx,eax
    add ecx,3
    cmp qword [rel ue_first_slot_publication],0
    jne .armed
    cmp r12d,ecx
    jne .bad
    mov rdi,[rel ue_selected_state]
    lea rsi,[rel ue_stage_start]
    call update_release_stage_start
    cmp eax,2
    jne .bad
    lea rsi,[rel ue_stage_start]
    jmp .record512
.armed:
    test qword [rel ue_published_mask],1
    jz .bad
    lea rdi,[rel ue_after_mask]
    xor esi,esi
    call ue_capture_records
    test rax,rax
    jnz .bad
    call ue_expected_after
    test rax,rax
    jnz .bad
    call ue_selected_copy
    test eax,eax
    js .bad
    cmp dword [rel ue_stage_kind],2
    je .armed_target
    xor eax,1
.armed_target:
    add eax,3
    cmp r12d,eax
    jne .bad
    lea rsi,[rel ue_stage_armed]
    jmp .record512
.release:
    cmp qword [rel ue_first_slot_publication],0
    je .bad
    test qword [rel ue_published_mask],1
    jnz .bad
    mov eax,6
    sub eax,[rel ue_active_slot]
    cmp r12d,eax
    jne .bad
    lea ecx,[rax+1]             ; candidate slot id is incoming PRL id+2
    bt qword [rel ue_published_mask],rcx
    jnc .bad
    lea rsi,[rel ue_feed_raw+256]
.record512:
    cmp r13,512
    jne .bad
    mov rdi,rbx
    mov edx,512
    call memcmp
    test eax,eax
    jnz .bad
    jmp .good
.manifest:
    cmp r13,1024
    jne .bad
    cmp qword [rel ue_first_slot_publication],0
    je .bad
    mov ecx,5
    sub ecx,[rel ue_active_slot]
    bt qword [rel ue_published_mask],rcx
    jnc .bad
    add ecx,2
    bt qword [rel ue_published_mask],rcx
    jnc .bad
    xor edi,edi
    call ue_before_record
    lea rdi,[rax+48]
    mov rsi,[rel ue_selected_state]
    mov rdx,rbx
    lea rcx,[rel ue_feed_raw+256]
    lea r8,[rel ue_stage_start]
    lea r9,[rel ue_stage_armed]
    call update_release_stage_expected
    test eax,eax
    jz .bad
    mov [rel ue_stage_kind],eax
    jmp .good
.slot:
    call ue_pre_slot
    test rax,rax
    jnz .bad
.good:
    xor eax,eax
    jmp .out
.bad:
    mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Complete native DOWNLOAD readback proof, called only after fresh phase2,
; full original/BUDGET delivery, current custody and immutable-policy equality.
ue_finish_download:
    push rbx
    push r12
    push r13
    cmp dword [rel ue_class],2
    jne .bad
    cmp qword [rel ue_uncertain],0
    jne .bad
    cmp qword [rel ue_rw_issued],0
    je .bad
    cmp qword [rel ue_write_issued],0
    je .bad
    cmp qword [rel ue_flush_issued],0
    je .bad
    mov rax,[rel ue_release_admitted]
    test rax,rax
    jz .bad
    cmp rax,[rel ue_first_slot_publication]
    jae .bad
    call ue_expected_after
    test rax,rax
    jnz .bad
    call ue_selected_copy
    test eax,eax
    js .bad
    mov r12d,eax
    mov r13d,1                ; exact native publication mask
    mov ecx,7
    sub ecx,[rel ue_active_slot]
    bts r13,rcx
    sub ecx,2
    bts r13,rcx
    cmp dword [rel ue_stage_kind],2
    jne .no_retire
    or r13d,12               ; both exact journals: retirement and armed
    lea edi,[r12d+1]
    lea rsi,[rel ue_stage_armed]
    mov edx,512
    call ue_record_matches
    test rax,rax
    jnz .bad
    mov edi,2
    sub edi,r12d
    lea rsi,[rel ue_stage_start]
    mov edx,512
    call ue_record_matches
    test rax,rax
    jnz .bad
    jmp .records
.no_retire:
    mov ecx,3
    sub ecx,r12d
    bts r13,rcx
    lea edi,[r12d+1]
    call ue_record_equal
    test rax,rax
    jnz .bad
    mov edi,2
    sub edi,r12d
    lea rsi,[rel ue_stage_armed]
    mov edx,512
    call ue_record_matches
    test rax,rax
    jnz .bad
.records:
    cmp r13,[rel ue_published_mask]
    jne .bad
    mov edi,[rel ue_active_slot]
    add edi,3
    call ue_record_equal
    test rax,rax
    jnz .bad
    mov edi,4
    sub edi,[rel ue_active_slot]
    lea rsi,[rel ue_feed_raw+256]
    mov edx,512
    call ue_record_matches
    test rax,rax
    jnz .bad
    call ue_verify_active
    test rax,rax
    jnz .bad
    mov edi,8
    sub edi,[rel ue_active_slot]
    lea rsi,[rel ue_finish_sha]
    call ue_hash_fixed
    cmp rax,[rel ue_offer_size]
    jne .bad
    lea rdi,[rel ue_finish_sha]
    lea rsi,[rel ue_offer_sha]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    or qword [rel ue_readback_mask],192 ; actual full Active+candidate streams
    xor eax,eax
    jmp .out
.bad:
    mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Derive eligible selected journal from both exact original records and stream
; the complete Active file. No worker operand, handoff CRC or PEM supplies trust.
ue_current_proof:
    push rbx
    push r12
    push r13
    xor edi,edi
    call ue_before_record
    cmp dword [rax+4],1
    jne .bad
    cmp qword [rax+8],1024
    jne .bad
    lea r12,[rax+48]
    mov edi,1
    call ue_before_record
    xor ebx,ebx
    cmp dword [rax+4],2
    je .second
    cmp dword [rax+4],1
    jne .bad
    cmp qword [rax+8],512
    jne .bad
    lea rbx,[rax+48]
.second:
    mov edi,2
    call ue_before_record
    xor esi,esi
    cmp dword [rax+4],2
    je .select
    cmp dword [rax+4],1
    jne .bad
    cmp qword [rax+8],512
    jne .bad
    lea rsi,[rax+48]
.select:
    mov rdi,rbx
    call update_release_state_select
    test rax,rax
    jz .bad
    mov r13,rax
    mov rdi,r13
    call update_release_state_idle
    cmp eax,1
    jne .bad
    movzx edi,byte [r13+16]
    add edi,6                   ; fixed actual A/B files7/8, never signed arbitrary path
    lea rsi,[rel ue_active_sha]
    call ue_hash_fixed
    test rax,rax
    js .bad
    mov [rel ue_active_size],rax
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rel ue_active_sha]
    mov rcx,rax
    call update_release_current_join
    cmp eax,1
    jne .bad
    call ue_current
    test rax,rax
    jnz .bad
    mov [rel ue_selected_state],r13
    mov rax,[r13+8]
    mov [rel ue_selected_generation],rax
    movzx eax,byte [r13+16]
    dec eax
    mov [rel ue_active_slot],eax
    lea rdi,[rel ue_owner_sha]
    mov rsi,r12
    mov edx,1024
    call sha256_hash
    test rax,rax
    jnz .bad
    mov dword [rel ue_current_verified],1
    xor eax,eax
    jmp .out
.bad:
    mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Internal fixed file ID in EDI, private outputSHA32 in RSI ->actual full size/-1.
; Fresh original dirent/location/size before and after each bounded read, actual
; native custody on every physical IO, SHA over ALL bytes, never a worker claim.
ue_hash_fixed:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov r12d,edi
    mov r15,rsi
    lea rbx,[rel ue_hash_object]
    mov rdi,rbx
    xor esi,esi
    mov edx,80
    call memset
    mov [rbx+8],r12
    call ue_resolve_object
    test rax,rax
    jnz .bad
    mov r13,[rbx+16]
    cmp r13,512
    jb .bad
    cmp r13,UE_MAX
    ja .bad
    lea rdi,[rel ue_hash_context]
    call sha256_stream_init
    xor ebp,ebp
.chunk:
    call ue_object_check
    test rax,rax
    jnz .bad
    mov r14,r13
    sub r14,rbp
    cmp r14,UE_CHUNK
    jbe .read
    mov r14d,UE_CHUNK
.read:
    lea rdi,[rel ue_mount]
    mov rsi,[rel ue_read_path]
    mov rdx,rbp
    lea rcx,[rel ue_hash_chunk]
    mov r8,r14
    call fat32_disk_read_at
    cmp rax,r14
    jne .bad
    call ue_object_check
    test rax,rax
    jnz .bad
    lea rdi,[rel ue_hash_context]
    lea rsi,[rel ue_hash_chunk]
    mov rdx,r14
    call sha256_stream_update
    test rax,rax
    jnz .bad
    add rbp,r14
    cmp rbp,r13
    jb .chunk
    call ue_current
    test rax,rax
    jnz .bad
    lea rdi,[rel ue_hash_context]
    mov rsi,r15
    call sha256_stream_final
    test rax,rax
    jnz .bad
    mov rax,r13
    jmp .out
.bad:
    mov rax,-1
.out:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Native FINISH takes no worker verdict/payload. One actual assessment per
; binding, including failure. CHECK returns1CURRENT/2AVAILABLE; DOWNLOAD
; returns3 only for exact fresh native stage/readback/original-custody proof.
; Every positive requires actual full original40 AND BUDGET32 delivery facts.
update_esp_finish:
    push rbx
    push r12
    push r13
    mov r12,rdi
    call smp_current_logical
    test eax,eax
    jnz .refused
    cmp r12,[rel ue_sequence]
    jne .refused
    cmp r12,0
    je .refused
    cmp dword [rel ue_busy],0
    jne .busy
    cmp dword [rel ue_finish_attempted],0
    jne .refused
    cmp qword [rel ue_observation_serial],-1
    je .refused
    mov dword [rel ue_busy],1
    mov dword [rel ue_finish_attempted],1
    ; Capture actual fresh fixed originals even for a refused assessment.
    call ue_capture_after
    test rax,rax
    jnz .bad
    mov eax,[rel ue_after_mask]
    mov [rel ue_readback_mask],rax
    call ue_delivery
    test rax,rax
    jnz .bad
    call ue_current
    test rax,rax
    jnz .bad
    cmp dword [rel ue_feed_verified],1
    jne .bad
    cmp dword [rel ue_current_verified],1
    jne .bad
    call update_public_policy_get
    test rax,rax
    jz .bad
    cmp edx,23408
    jne .bad
    lea rdi,[rax+48]
    lea rsi,[rel ue_policy_sha]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    ; An ERROR descriptor never becomes absence or exact-readback credit.
    xor ebx,ebx
.clean:
    lea rax,[rel ue_after_offsets]
    mov rax,[rax+rbx*8]
    lea rdx,[rel ue_after_raw]
    add rax,rdx
    cmp dword [rax+4],1
    je .next
    cmp dword [rax+4],2
    jne .bad
.next:
    inc ebx
    cmp ebx,5
    jb .clean
    cmp dword [rel ue_original+8],2
    je .download
    cmp dword [rel ue_original+8],1
    jne .bad
    mov rax,[rel ue_rw_issued]
    or rax,[rel ue_write_issued]
    or rax,[rel ue_flush_issued]
    or rax,[rel ue_published_mask]
    or rax,[rel ue_uncertain]
    jnz .bad
    mov rdx,[rel ue_before_length]
    cmp rdx,[rel ue_after_length]
    jne .bad
    test rdx,rdx
    jz .bad
    lea rdi,[rel ue_before_raw]
    lea rsi,[rel ue_after_raw]
    call memcmp
    test eax,eax
    jnz .bad
    mov edi,[rel ue_active_slot]
    add edi,7
    lea rsi,[rel ue_finish_sha]
    call ue_hash_fixed
    cmp rax,[rel ue_active_size]
    jne .bad
    lea rdi,[rel ue_finish_sha]
    lea rsi,[rel ue_active_sha]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    mov ecx,[rel ue_active_slot]
    add ecx,6
    bts qword [rel ue_readback_mask],rcx
    mov r13d,[rel ue_class]
    cmp r13d,1
    je .readback_done
    cmp r13d,2
    jne .bad
    jmp .readback_done
.download:
    call ue_finish_download
    test rax,rax
    jnz .bad
    mov r13d,3
.readback_done:
    call ue_event_next
    test rax,rax
    jnz .bad
    mov rax,[rel ue_native_event]
    mov [rel ue_readback_ordinal],rax ; all actual required readbacks completed
    mov rdi,r12
    mov esi,1
    call update_esp_readonly        ; actual native gate/current confirmation
    cmp eax,1
    jne .bad
    call ue_delivery
    test rax,rax
    jnz .bad
    call ue_current
    test rax,rax
    jnz .bad
    call ue_event_next
    test rax,rax
    jnz .bad
    mov rax,[rel ue_native_event]
    mov [rel ue_final_ro_ordinal],rax
    mov qword [rel ue_readbacks_exact],1
    mov rax,r13
    jmp .result
.bad:
    ; Close the real safety gate even on refusal; no positive credit follows.
    mov rdi,r12
    mov esi,1
    call update_esp_readonly
    mov qword [rel ue_readbacks_exact],0
    mov qword [rel ue_readback_ordinal],0
    mov qword [rel ue_final_ro_ordinal],0
    mov rax,-1
    cmp qword [rel ue_uncertain],0
    je .result
    mov rax,-3
.result:
    mov [rel ue_finish_result],rax
    mov dword [rel ue_busy],0
    jmp .out
.busy:
    mov rax,-2
    jmp .out
.refused:
    mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Actual native service accessor is valid inside its closed exit. The passive
; idle observer is not an equivalent source there. EDX facts are read before
; comparisons, not derived from a guest class or a full-looking tuple.
ue_delivery:
    push rbx
    lea rdi,[rel ue_check]
    mov esi,40
    lea rdx,[rel ue_check+40]
    mov ecx,128
    call settings_update_service_original
    cmp eax,1
    jne .bad
    mov ebx,edx
    and ebx,3
    cmp ebx,3
    jne .bad
    lea rdi,[rel ue_check]
    lea rsi,[rel ue_original]
    mov edx,40
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[rel ue_check+40]
    lea rsi,[rel ue_runtime]
    mov edx,128
    call memcmp
    test eax,eax
    jnz .bad
    xor eax,eax
    pop rbx
    ret
.bad:
    mov rax,-1
    pop rbx
    ret

; Capture only at actual native acquisition before any RW entry or publication.
; Canonical packed descriptors distinguish confirmed ABSENT from every error.
; No mutable PEM is read as an anchor and no proof is inferred from these bytes.
ue_capture_before:
    lea rdi,[rel ue_before_mask]
    mov esi,1
    jmp ue_capture_records
ue_capture_after:
    lea rdi,[rel ue_after_mask]
    mov esi,2
; Internal private media struct, ESI phase0 scratch/1BEFORE/2TERMINAL.
ue_capture_records:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov [rsp],esi
    mov qword [rsp+8],0
    mov r15,rdi
    xor esi,esi
    mov edx,UE_MEDIA_BYTES
    call memset
    lea r12,[r15+UE_MEDIA_RAW]
    xor r13d,r13d
.record:
    lea rax,[rel ue_raw_ids]
    mov ebx,[rax+r13*4]
    mov [r12],ebx
    mov dword [r12+4],3             ; ERROR until actual complete read/absence
    mov qword [r12+8],0
    lea rax,[r15+UE_MEDIA_RAW]
    mov rdi,r12
    sub rdi,rax
    lea rax,[r15+UE_MEDIA_OFFSETS]
    mov [rax+r13*8],rdi
    mov ebp,512
    cmp ebx,1
    jne .size
    mov ebp,1024
.size:
    lea rax,[rel ue_paths]
    movsxd r14,dword [rax+rbx*4-4]
    add r14,rax
    lea rdi,[rel ue_ctx]
    mov rsi,r14
    mov qword [rel fd_path_cache_ctx],0
    mov byte [rel fd_resolve_strict],1
    call fat32_disk_resolve_path_lfn
    mov byte [rel fd_resolve_strict],0
    test rax,rax
    jnz .not_present
    test byte [rel fd_found_attr],0x18
    jnz .next
    cmp [rel fd_found_size],rbp
    jne .next
    lea rdi,[rel ue_mount]
    mov rsi,r14
    xor edx,edx
    lea rcx,[r12+48]
    mov r8,rbp
    call fat32_disk_read_at
    cmp rax,rbp
    jne .next
    lea rdi,[r12+16]
    lea rsi,[r12+48]
    mov rdx,rbp
    call sha256_hash
    test rax,rax
    jnz .next
    mov dword [r12+4],1
    mov [r12+8],rbp
    mov ecx,ebx
    dec ecx
    bts qword [rsp+8],rcx
    add r12,rbp
    jmp .next
.not_present:
    cmp byte [rel fd_resolve_absent],1
    jne .next
    mov dword [r12+4],2
.next:
    add r12,48
    inc r13d
    cmp r13d,5
    jb .record
    lea rsi,[r15+UE_MEDIA_RAW]
    sub r12,rsi
    mov [r15+UE_MEDIA_LENGTH],r12
    mov eax,[rsp+8]
    mov [r15],eax
    lea rdi,[r15+UE_MEDIA_SHA]
    mov rdx,r12
    call sha256_hash
    test rax,rax
    jnz .bad
    mov eax,[rsp]
    test eax,eax
    jz .ok
    cmp qword [rel ue_observation_serial],-1
    je .bad
    inc qword [rel ue_observation_serial]
    mov [rel ue_phase],eax         ; only actual native capture changes phase
    mov dword [rel ue_observation_valid],1
.ok:
    xor eax,eax
    jmp .out
.bad:
    mov qword [r15+UE_MEDIA_LENGTH],0
    mov rax,-1
.out:
    add rsp,24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Trusted-native read-only diagnostics. No worker binding or pointer is authority.
; RDI original40, RSI runtime128, RDX out512, ECX exactly512 ->0/-1.
; Caller owns mapping; all spans must be disjoint and outside private/VM RAM.
; Unknown leaves output untouched. No IO, mutation, capture or cleanup here.
update_esp_observe:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp,512
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    cmp ecx,512
    jne .bad
    mov esi,512
    mov rdi,r14
    call ue_observe_span
    test eax,eax
    jz .bad
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,512
    call ue_observe_match
    test eax,eax
    jz .bad
    mov ebp,eax                    ; independently observed CURRENT1/STOPPED2
    mov rdi,rsp
    xor esi,esi
    mov edx,512
    call memset
    mov dword [rsp],0x314f4555      ; UEO1
    mov dword [rsp+4],0x02000001   ; version1, exact512
    mov rax,[rel ue_sequence]
    mov [rsp+8],rax
    mov rax,[rel ue_observation_serial]
    mov [rsp+16],rax
    mov rax,[rel ue_original]
    mov [rsp+24],rax
    mov eax,[rel ue_original+8]
    mov [rsp+32],eax
    mov eax,[rel ue_state]
    cmp qword [rel ue_reclaim_attempted],0
    je .state
    mov eax,3
.state:
    mov [rsp+36],eax
    mov rax,[rel ue_original+32]
    mov [rsp+40],rax
    call boot_ms_now
    mov [rsp+48],rax
    xor ebx,ebx
    cmp qword [rel ue_rw_issued],0
    je .physical
    or ebx,1
.physical:
    mov rax,[rel ue_write_issued]
    or rax,[rel ue_flush_issued]
    jz .publication
    or ebx,2
.publication:
    cmp qword [rel ue_published_mask],0
    je .restore
    or ebx,4
.restore:
    cmp qword [rel ue_restore_attempts],0
    je .restored
    or ebx,16
.restored:
    cmp qword [rel ue_ro_confirmed],0
    je .uncertain
    or ebx,32
.uncertain:
    cmp qword [rel ue_uncertain],0
    je .facts
    or ebx,64
.facts:
    mov [rsp+56],ebx
    cmp dword [rel ue_current_verified],1
    jne .feed_facts
    or dword [rsp+56],128
.feed_facts:
    cmp dword [rel ue_feed_verified],1
    jne .proof_fields
    or dword [rsp+56],256
.proof_fields:
    mov eax,[rel ue_class]
    mov [rsp+60],eax
    mov rax,[rel ue_finish_result]
    mov [rsp+64],rax
    mov rax,[rel ue_readback_mask]
    mov [rsp+104],rax
    cmp qword [rel ue_readbacks_exact],1
    jne .terminal_fields
    or dword [rsp+56],8
.terminal_fields:
    mov rax,[rel ue_rw_issued]
    mov [rsp+72],rax
    mov rax,[rel ue_write_issued]
    mov [rsp+80],rax
    mov rax,[rel ue_flush_issued]
    mov [rsp+88],rax
    mov rax,[rel ue_published_mask]
    mov [rsp+96],rax
    mov eax,2
    cmp dword [rel ue_readonly],0
    je .gate
    mov eax,1
.gate:
    mov [rsp+112],eax
    mov [rsp+116],ebp
    mov eax,[rel ue_phase]
    mov [rsp+120],eax
    lea rdi,[rsp+128]
    lea rsi,[rel ue_original]
    mov edx,40
    call sha256_hash
    test rax,rax
    jnz .bad
    lea rdi,[rsp+160]
    lea rsi,[rel ue_runtime]
    mov edx,128
    call sha256_hash
    test rax,rax
    jnz .bad
    lea rdi,[rsp+192]
    lea rsi,[rel ue_desc]
    mov edx,136                    ; actual storage descriptor, never scratch168
    call sha256_hash
    test rax,rax
    jnz .bad
    lea rdi,[rsp+288]
    lea rsi,[rel ue_before_sha]
    mov edx,32
    call memcpy
    lea rdi,[rsp+224]
    lea rsi,[rel ue_feed_sha]
    mov edx,32
    call memcpy
    lea rdi,[rsp+256]
    lea rsi,[rel ue_policy_sha]
    mov edx,32
    call memcpy
    lea rdi,[rsp+352]
    lea rsi,[rel ue_active_sha]
    mov edx,32
    call memcpy
    lea rdi,[rsp+384]
    lea rsi,[rel ue_offer_sha]
    mov edx,32
    call memcpy
    mov rax,[rel ue_active_size]
    mov [rsp+416],rax
    mov rax,[rel ue_offer_size]
    mov [rsp+424],rax
    mov dword [rsp+432],0xffffffff ; unverified is never silently slot A
    cmp dword [rel ue_current_verified],1
    jne .not_verified
    mov eax,[rel ue_active_slot]
    mov [rsp+432],eax
.not_verified:
    mov rax,[rel ue_selected_generation]
    mov [rsp+440],rax
    lea rdi,[rsp+448]
    lea rsi,[rel ue_owner_sha]
    mov edx,32
    call memcpy
    cmp dword [rel ue_phase],2
    jne .after_sha_done
    lea rdi,[rsp+320]
    lea rsi,[rel ue_after_sha]
    mov edx,32
    call memcpy
 .after_sha_done:
    mov rax,[rel ue_readback_ordinal]
    mov [rsp+496],rax
    mov rax,[rel ue_final_ro_ordinal]
    mov [rsp+504],rax
    mov rax,[rel ue_release_admitted]
    mov [rsp+480],rax
    mov eax,[rel ue_before_mask]
    mov [rsp+436],eax
    mov rax,[rel ue_first_slot_publication]
    mov [rsp+488],rax
    mov rdi,r14
    mov rsi,rsp
    mov edx,512
    call memcpy
    xor eax,eax
    jmp .out
.bad:
    mov rax,-1
.out:
    add rsp,512
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Same exact native originals. RDX phase1BEFORE/2TERMINAL, RCX out3312,
; R8D exactly3312 ->actual canonical packed bytes/-1, unknown output untouched.
; Only retained capture, never new IO. Terminal bytes absent until real FINISH.
update_esp_observe_raw:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov r12,rdi
    mov r13,rsi
    mov ebp,edx
    mov r14,rcx
    cmp r8d,UE_RAW_MAX
    jne .bad
    cmp ebp,1
    je .before
    cmp ebp,2
    jne .bad
    cmp dword [rel ue_phase],2
    jne .bad
    lea rbx,[rel ue_after_mask]
    jmp .length
.before:
    lea rbx,[rel ue_before_mask]
.length:
    cmp qword [rbx+UE_MEDIA_LENGTH],0
    je .bad
    cmp qword [rbx+UE_MEDIA_LENGTH],UE_RAW_MAX
    ja .bad
    mov rdi,r14
    mov esi,UE_RAW_MAX
    call ue_observe_span
    test eax,eax
    jz .bad
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,UE_RAW_MAX
    call ue_observe_match
    test eax,eax
    jz .bad
    mov rdi,r14
    lea rsi,[rbx+UE_MEDIA_RAW]
    mov rbx,[rbx+UE_MEDIA_LENGTH]
    mov rdx,rbx
    call memcpy
    mov rax,rbx
    jmp .out
.bad:
    mov rax,-1
.out:
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Original40/runtime128/output spans already bounded; validate every byte and
; independently consult the single service observer. No guest/current IO call.
; RDI original,RSI runtime,RDX output,ECX outputlen ->1/2/0.
ue_observe_match:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp,176
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov ebp,ecx
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp dword [rel ue_busy],0
    jne .bad
    cmp qword [rel ue_lease],0
    je .bad
    cmp dword [rel ue_observation_valid],1
    jne .bad
    cmp qword [rel ue_before_length],0
    je .bad
    mov rdi,r12
    mov esi,40
    call ue_observe_span
    test eax,eax
    jz .bad
    mov rdi,r13
    mov esi,128
    call ue_observe_span
    test eax,eax
    jz .bad
    lea rax,[r12+40]
    cmp r13,rax
    jae .inputs
    lea rax,[r13+128]
    cmp r12,rax
    jb .bad
.inputs:
    mov rdi,r12
    mov esi,40
    mov rdx,r14
    mov ecx,ebp
    call ue_observe_disjoint
    test eax,eax
    jz .bad
    mov rdi,r13
    mov esi,128
    mov rdx,r14
    mov ecx,ebp
    call ue_observe_disjoint
    test eax,eax
    jz .bad
    mov rdi,r12
    lea rsi,[rel ue_original]
    mov edx,40
    call memcmp
    test eax,eax
    jnz .bad
    mov rdi,r13
    lea rsi,[rel ue_runtime]
    mov edx,128
    call memcmp
    test eax,eax
    jnz .bad
    mov rdi,rsp
    mov esi,40
    lea rdx,[rsp+40]
    mov ecx,128
    call settings_update_service_observe
    cmp eax,1
    je .lineage
    cmp eax,2
    jne .bad
.lineage:
    mov ebx,eax
    mov rdi,rsp
    lea rsi,[rel ue_original]
    mov edx,40
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[rsp+40]
    lea rsi,[rel ue_runtime]
    mov edx,128
    call memcmp
    test eax,eax
    jnz .bad
    mov eax,ebx
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,176
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Non-dereferencing canonical native span/private/guest alias checks.
ue_observe_span:
    push rbx
    push r12
    mov rbx,rdi
    mov r12d,esi
    test rdi,rdi
    jz .bad
    mov eax,esi
    add rax,rdi
    jc .bad
    mov rdx,rax
    dec rdx
    mov rcx,rdi
    shl rcx,16
    sar rcx,16
    cmp rcx,rdi
    jne .bad
    mov rcx,rdx
    shl rcx,16
    sar rcx,16
    cmp rcx,rdx
    jne .bad
    lea rdx,[rel ue_private_begin]
    mov ecx,ue_private_end-ue_private_begin
    call ue_observe_disjoint
    test eax,eax
    jz .bad
    lea rdx,[rel ue_private_data_begin]
    mov ecx,ue_private_data_end-ue_private_data_begin
    call ue_observe_disjoint
    test eax,eax
    jz .bad
    lea rdx,[rel ur_owner_key_id]
    mov ecx,ur_private_data_end-ur_owner_key_id
    call ue_observe_disjoint
    test eax,eax
    jz .bad
    lea rdx,[rel boot_v2_owner_modulus]
    mov ecx,256
    call ue_observe_disjoint
    test eax,eax
    jz .bad
    mov rdx,[rel ue_buffer]
    mov rcx,[rel ue_memory_capacity]
    call ue_observe_disjoint
    test eax,eax
    jz .bad
    mov rdx,[rel avm_base]
    mov rcx,[rel avm_capacity]
    call ue_observe_disjoint
    test eax,eax
    jz .bad
    mov rdx,[rel hv_linux_region]
    mov rcx,[rel hv_linux_region_capacity]
    call ue_observe_disjoint
    test eax,eax
    jz .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    mov rdi,rbx
    mov esi,r12d
    pop r12
    pop rbx
    ret
ue_observe_disjoint:                ; [rdi,rdi+rsi) disjoint [rdx,rdx+rcx)
    test rcx,rcx
    jz .yes
    mov rax,rdx
    add rax,rcx
    jc .bad
    cmp rdi,rax
    jae .yes
    mov rax,rdi
    add rax,rsi
    jc .bad
    cmp rax,rdx
    jbe .yes
.bad:
    xor eax,eax
    ret
.yes:
    mov eax,1
    ret

; Recognize exactly private context or current locked view. Preserves all args.
ue_context:
    lea rax,[rel ue_ctx]
    cmp rdi,rax
    je .yes
    lea rax,[rel fd_dir_ctx]
    cmp rdi,rax
    jne .no
    cmp dword [rel fd_dir_gate],1
    jne .no
    lea rax,[rel ue_ctx]
    cmp [rel fd_dir_owner],rax
    jne .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

ue_guard:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    call ue_current
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret
 ; Effect admission is native, immutable for this binding and consumed by
; FINISH. Preserve every argument except RAX at each independent IO boundary.
ue_admitted:
    cmp dword [rel ue_feed_verified],1
    jne ue_refused
    cmp dword [rel ue_class],2
    jne ue_refused
    cmp qword [rel ue_release_admitted],0
    je ue_refused
    cmp dword [rel ue_finish_attempted],0
    jne ue_refused
    xor eax,eax
    ret

ue_mutation:
    call ue_admitted
    test rax,rax
    jnz ue_refused
    cmp dword [rel ue_readonly],0
    jne ue_refused
    cmp dword [rel ue_original+8],2
    jne ue_refused
    jmp ue_guard
; Name gate returns 0 unrelated, 1 current private fixed name, -1 refusal.
ue_name_gate:
    push rdi
    mov rdi,rsi
    call ue_context
    pop rdi
    test eax,eax
    jz .out
    push rdi
    push rsi
    push rdx
    push rcx
    lea rsi,[rel ue_temp_name]
    mov edx,11
    call memcmp
    test eax,eax
    jz .yes
    mov rdi,[rsp+24]              ; memcmp advanced the first name pointer
    lea rsi,[rel ue_publish_name]
    mov edx,11
    call memcmp
    test eax,eax
    jnz .no
.yes:
    call ue_mutation
    test rax,rax
    jnz .no
    mov eax,1
    jmp .pop
.no:
    mov rax,-1
.pop:
    pop rcx
    pop rdx
    pop rsi
    pop rdi
.out:
    ret

; Native sector helper: EAX=0 read,1 write; original FAT absolute range.
; Called only through exact context dispatch at FAT IO boundaries.
ue_sectors:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov ebx,eax
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    cmp r12,[rel ue_ctx+FD_PART_LBA]
    jb .bad
    sub r12,[rel ue_ctx+FD_PART_LBA]
    mov rax,r12
    add rax,r13
    jc .bad
    cmp rax,[rel ue_ctx+FD_TOTAL_SECTORS]
    ja .bad
    test r13,r13
    jz .ok
.loop:
    call ue_current
    test rax,rax
    jnz .bad
    mov r15,r13
    cmp r15,8
    jbe .size
    mov r15d,8
.size:
    mov rdi,[rel ue_lease]
    mov rsi,r12
    mov rdx,r15
    mov rcx,r14
    test ebx,ebx
    jz .read
    cmp dword [rel ue_readonly],0
    jne .bad
    cmp dword [rel ue_original+8],2
    jne .bad
    call ue_admitted
    test rax,rax
    jnz .bad
    cmp qword [rel ue_write_issued],-1
    je .bad
    call ue_event_next
    test rax,rax
    jnz .bad
    inc qword [rel ue_write_issued] ; BEFORE dispatch, including failed first write
    inc qword [rel ue_effects]       ; before dispatch: failure may have persisted
    lea rdi,[rel ue_ctx]
    call fd_invalidate_caches
    mov rdi,[rel ue_lease]
    mov rsi,r12
    mov rdx,r15
    mov rcx,r14
    call guest_volume_write
    jmp .result
.read:
    call guest_volume_read
.result:
    test rax,rax
    jnz .bad
    call ue_current
    test rax,rax
    jnz .bad
    add r12,r15
    sub r13,r15
    shl r15,9
    add r14,r15
    test r13,r13
    jnz .loop
.ok:
    xor eax,eax
    jmp .out
.bad:
    call ue_fault
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
ue_flush:
    push rbx
    mov rbx,rdi
    call ue_context
    test eax,eax
    jnz .context
    lea rbx,[rel ue_ctx]
.context:
    cmp dword [rel ue_readonly],0
    jne .refused
    call ue_current
    test rax,rax
    jnz .fault
    cmp dword [rel ue_original+8],2
    jne .refused
    call ue_admitted
    test rax,rax
    jnz .refused
    ; Original hint delta follows the FAT, before this single device barrier.
    ; In a locked directory view its delta belongs to that view, not the root.
    mov rdi,rbx
    call fd_fsinfo_apply
    call ue_current
    test rax,rax
    jnz .fault
    cmp qword [rel ue_flush_issued],-1
    je .fault
    call ue_event_next
    test rax,rax
    jnz .fault
    inc qword [rel ue_flush_issued] ; BEFORE callback: failure may have persisted
    inc qword [rel ue_effects]
    mov rdi,[rel ue_lease]
    call guest_volume_flush
    test rax,rax
    jnz .fault
    call ue_current
    test rax,rax
    jnz .fault                    ; flush may persist before identity loss
    xor eax,eax
    jmp .out
.refused:
    mov rax,-1
    jmp .out
.fault:
    call ue_fault
.out:
    pop rbx
    ret
; One native nonwrapping ordering domain. Callers freeze/refuse on exhaustion.
ue_event_next:
    cmp qword [rel ue_native_event],-1
    je ue_refused
    inc qword [rel ue_native_event]
    xor eax,eax
    ret
ue_fault:
    cmp qword [rel ue_rw_issued],0
    je .clean
    mov qword [rel ue_uncertain],1 ; cumulative; never cleared by worker/stopped
.clean:
    mov dword [rel ue_state],2
    mov rdi,[rel ue_lease]
    call guest_volume_freeze
    mov rax,-3
    ret
ue_refused:
    mov rax,-1
    ret
ue_uncertain_return:
    mov rax,-3
    ret

; RDI binding RSI op RDX object/fixedID RCX offset/target R8 buffer R9 count.
; Only native mapped buffers. The VM transport must bounce, never pass GPA here.
update_esp_io:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,16
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    mov r15,r8
    mov rbp,r9
    cmp rdi,[rel ue_sequence]
    jne .no
    cmp dword [rel ue_busy],0
    jne .busy
    mov dword [rel ue_busy],1
    call ue_current
    test rax,rax
    jnz .no_unlock
    cmp r12,4
    jb .dispatch
    cmp r12,9
    je .dispatch                 ; close remains available for private cleanup
    call ue_admitted
    test rax,rax
    jnz .no_unlock
.dispatch:
    cmp r12,1
    je .open
    cmp r12,4
    je .temp
    cmp r12,7
    je .dirsync
    lea rbx,[rel ue_objects]
    mov ecx,UE_TEMP
.find:
    cmp [rbx],r13
    je .object
    add rbx,UE_OBJ_SIZE
    loop .find
    jmp .no_unlock
.object:
    test r13,r13
    jz .no_unlock
    cmp r12,9
    je .close
    cmp r12,10
    je .discard
    cmp r12,5
    je .append
    cmp r12,6
    je .sync
    cmp r12,8
    je .replace
    cmp r12,2
    je .stat
    cmp r12,3
    jne .no_unlock
    test r15,r15
    jz .no_unlock
    cmp rbp,UE_CHUNK
    ja .no_unlock
    mov rax,r15
    add rax,rbp
    jc .no_unlock
    cmp r14,[rbx+16]
    ja .no_unlock
    mov rdx,[rbx+16]
    sub rdx,r14
    cmp rbp,rdx
    jbe .read_size
    mov rbp,rdx
.read_size:
    cmp dword [rbx+72],1            ; unmaterialized private temp: actual RAM
    je .ram_read
    call ue_object_check
    test rax,rax
    jnz .no_unlock
    lea rdi,[rel ue_mount]
    mov rsi,[rel ue_read_path]
    mov rdx,r14
    mov rcx,r15
    mov r8,rbp
    call fat32_disk_read_at
    cmp rax,rbp
    jne .io_fault
    jmp .done
.ram_read:
    mov rdi,r15
    mov rsi,[rel ue_buffer]
    add rsi,r14
    mov rdx,rbp
    call memcpy
    mov rax,rbp
    jmp .done
.stat:
    test r15,r15
    jz .no_unlock
    cmp rbp,32
    jne .no_unlock
    cmp r15,-32
    ja .no_unlock
    cmp dword [rbx+72],1
    je .stat_ram
    call ue_object_check
    test rax,rax
    jnz .no_unlock
.stat_ram:
    mov rax,[rbx]
    mov [r15],rax
    mov rax,[rbx+16]
    mov [r15+8],rax
    mov rax,[rbx]
    mov [r15+16],rax               ; content token; frozen after materialization
    mov qword [r15+24],1          ; regular file only
    xor eax,eax
    jmp .done
.open:
    cmp r13,1
    jb .no_unlock
    cmp r13,8
    ja .no_unlock
    lea rbx,[rel ue_objects]
    imul rax,r13,UE_OBJ_SIZE
    lea rbx,[rbx+rax-UE_OBJ_SIZE]
    cmp qword [rbx],0
    jne .no_unlock
    mov [rbx+8],r13
    call ue_resolve_object
    test rax,rax
    jnz .done
    call ue_new_id
    jmp .done
.temp:
    cmp dword [rel ue_readonly],0
    jne .no_unlock
    cmp dword [rel ue_original+8],2
    jne .no_unlock
    cmp r13,1
    jb .no_unlock
    cmp r13,3
    ja .no_unlock
    ; Private representative fixedID identifies only original parent/size cap.
    mov rax,r13
    cmp rax,1
    je .parent_ready
    mov eax,3
    cmp r13,2
    je .parent_ready
    mov eax,7
.parent_ready:
    mov r13,rax
    lea rbx,[rel ue_objects+UE_OBJ_SIZE*8]
    cmp qword [rbx],0
    jne .busy_unlock
    mov [rel ue_temp_target],r13
    mov [rbx+8],r13
    mov rdi,r13
    call ue_parent
    test rax,rax
    jnz .done
    ; No prior private name may be overwritten, inferred disposable or retried.
    call ue_temp_path
    mov rsi,rax
    lea rdi,[rel ue_ctx]
    mov qword [rel fd_path_cache_ctx],0
    mov byte [rel fd_resolve_strict],1
    call fat32_disk_resolve_path_lfn
    mov byte [rel fd_resolve_strict],0
    test rax,rax
    jz .no_unlock
    cmp byte [rel fd_resolve_absent],1
    jne .no_unlock
    call ue_ram_acquire
    test rax,rax
    jz .no_unlock
.allocated:
    mov qword [rbx+16],0
    mov dword [rbx+72],1
    call ue_new_id
    jmp .done
.append:
    cmp rbx,0
    je .no_unlock
    lea rax,[rel ue_objects+UE_OBJ_SIZE*8]
    cmp rbx,rax
    jne .no_unlock
    cmp dword [rbx+72],1
    jne .no_unlock
    cmp dword [rel ue_readonly],0
    jne .no_unlock
    cmp dword [rel ue_original+8],2
    jne .no_unlock
    test r15,r15
    jz .no_unlock
    test rbp,rbp
    jz .zero
    cmp rbp,UE_CHUNK
    ja .no_unlock
    mov rax,r15
    add rax,rbp
    jc .no_unlock
    mov rax,[rbx+16]
    add rax,rbp
    jc .no_unlock
    mov [rsp],rax
    mov rdi,[rbx+8]
    call ue_limit
    cmp [rsp],rax
    ja .no_unlock
    mov rdi,[rel ue_buffer]
    add rdi,[rbx+16]
    mov rsi,r15
    mov rdx,rbp
    call memcpy
    add [rbx+16],rbp
    mov rax,rbp
    jmp .done
.sync:
    cmp dword [rbx+72],1
    jne .sync_file
    ; Freeze private snapshot before journal effects. Failure is terminal.
    mov dword [rbx+72],2
    mov rdi,[rbx+8]
    call ue_parent
    test rax,rax
    jnz .io_fault
    lea rsi,[rel ue_temp_name]
    call ue_snapshot_write
    test rax,rax
    jnz .io_fault
    call ue_temp_path
    mov [rel ue_read_path],rax
    call ue_save_entry
    test rax,rax
    jnz .io_fault
    mov dword [rbx+72],2
.sync_file:
    call ue_object_check
    test rax,rax
    jnz .no_unlock
    call ue_flush
    jmp .done
.replace:
    lea rax,[rel ue_objects+UE_OBJ_SIZE*8]
    cmp rbx,rax
    jne .no_unlock
    cmp dword [rbx+72],2
    jne .no_unlock
    cmp r14,1
    jb .no_unlock
    cmp r14,8
    ja .no_unlock
    cmp r14,2
    je .no_unlock
    ; Retain the exact current Active payload and its PRL throughout staging.
    mov eax,[rel ue_active_slot]
    add eax,7
    cmp r14,rax
    je .no_unlock
    sub eax,2
    cmp r14,rax
    je .no_unlock
    mov rdi,r14
    call ue_limit
    cmp [rbx+16],rax
    ja .no_unlock
    ; Common-anchor deltas retain exact parent identity without forming pointers.
    lea rdx,[rel ue_parents]
    mov eax,[rdx+r14*4-4]
    mov rcx,[rel ue_temp_target]
    cmp eax,[rdx+rcx*4-4]
    jne .no_unlock                 ; only same original parent
    cmp dword [rel ue_readonly],0
    jne .no_unlock
    call ue_object_check
    test rax,rax
    jnz .no_unlock
    mov rdi,r14
    call ue_publication_gate
    test rax,rax
    jnz .no_unlock
    mov rdi,r14
    call ue_parent
    test rax,rax
    jnz .no_unlock
    ; Resolve original fixed name; take the actual alias, never guess an LFN.
    lea rax,[rel ue_paths]
    movsxd rsi,dword [rax+r14*4-4]
    add rsi,rax
    mov [rel ue_read_path],rsi
    lea rdi,[rel ue_ctx]
    mov qword [rel fd_path_cache_ctx],0
    call fat32_disk_resolve_path_lfn
    test rax,rax
    jnz .missing_target
    test byte [rel fd_found_attr],0xdf
    jnz .no_unlock
    lea rdi,[rel ue_ctx]
    mov rsi,[rel fd_found_dir_lba]
    mov edx,1
    lea rcx,[rel fd_sector]
    call fd_read_sectors
    test rax,rax
    jnz .io_fault
    lea rsi,[rel fd_sector]
    mov eax,[rel fd_found_dir_off]
    add rsi,rax
    lea rdi,[rel ue_publish_name]
    mov edx,11
    call memcpy
    jmp .publish
.missing_target:
    cmp byte [rel fd_resolve_absent],1
    jne .no_unlock
    ; Only canonical fixed 8.3 names can be newly created by this backend.
    ; LFN creation is deliberately not inferred from a short alias.
    cmp r14,5
    je .new_release
    cmp r14,6
    je .new_release
    mov rdi,r14
    call ue_short_name
    test rax,rax
    jz .no_unlock
    mov rsi,rax
    lea rdi,[rel ue_publish_name]
    mov edx,11
    call memcpy
    jmp .publish
.new_release:
    mov [rel ue_publish_target],r14
    call ue_create_release
    test rax,rax
    jnz .io_fault
.publish:
    cmp r14,7
    jb .dispatch_publish
    cmp qword [rel ue_first_slot_publication],0
    jne .dispatch_publish
    call ue_event_next
    test rax,rax
    jnz .io_fault
    mov rax,[rel ue_native_event]
    mov [rel ue_first_slot_publication],rax ; BEFORE slot publication attempt
.dispatch_publish:
    lea rsi,[rel ue_publish_name]
    call ue_snapshot_write
    test rax,rax
    jnz .io_fault
    mov rcx,r14
    dec rcx
    bts qword [rel ue_published_mask],rcx ; actual successful publication only
    ; Same logical open object, new committed original backing. Sync/read/stat
    ; now reopen and compare that exact entry, not the unpublished old name.
    mov [rbx+8],r14
    mov dword [rbx+72],3
    lea rdx,[rel ue_paths]
    movsxd rax,dword [rdx+r14*4-4]
    add rax,rdx
    mov [rel ue_read_path],rax
    call ue_save_entry
    test rax,rax
    jnz .io_fault
    call ue_remove_temp
    test rax,rax
    jnz .io_fault
    xor eax,eax
    jmp .done
.discard:
    lea rax,[rel ue_objects+UE_OBJ_SIZE*8]
    cmp rbx,rax
    jne .no_unlock
    cmp dword [rbx+72],3
    je .no_unlock
    cmp dword [rbx+72],2
    jne .close
    call ue_remove_temp
    test rax,rax
    jnz .io_fault
    mov dword [rbx+72],1
.close:
    ; Materialized unpublished objects need explicit discard, not silent loss.
    cmp dword [rbx+72],2
    je .no_unlock
    lea rax,[rel ue_objects+UE_OBJ_SIZE*8]
    cmp rbx,rax
    jne .clear_object
    call ue_clear_ram
    test rax,rax
    jnz .no_unlock
.clear_object:
    mov rdi,rbx
    xor esi,esi
    mov edx,UE_OBJ_SIZE
    call memset
.zero:
    xor eax,eax
    jmp .done
.dirsync:
    cmp r13,1
    jb .no_unlock
    cmp r13,3
    ja .no_unlock
    call ue_flush
    jmp .done
.io_fault:
    call ue_fault
    jmp .done
.busy:
    mov rax,-2
    jmp .out
.busy_unlock:
    mov rax,-2
    jmp .done
.no:
    mov rax,-1
    jmp .out
.no_unlock:
    mov rax,-1
.done:
    mov dword [rel ue_busy],0
.out:
    add rsp,16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Independent native broker key, not a guest address or ordinary heap allocation.
; Allocation refuses if the actual final conventional-memory map has no room.
; One exact rounded owner ceiling; generation never truncates or reuses.
ue_ram_acquire:
    cmp qword [rel ue_buffer],0
    je .new
    call ue_ram_current
    test rax,rax
    jnz .no
    mov rax,[rel ue_buffer]
    ret
.new:
    cmp qword [rel ue_memory_token],0
    jne .no
    mov rsi,[rel ue_sequence]
    test rsi,rsi
    jz .no
    mov eax,0xffffffff
    cmp rsi,rax
    ja .no
    mov edi,UE_MEMORY_OWNER
    mov edx,MB_KIND_SNAPSHOT
    mov ecx,UE_RAM_BYTES
    mov r8d,UE_CHUNK
    xor r9d,r9d
    mov r10d,UE_RAM_BYTES
    call mb_acquire_bounded
    test eax,eax
    jnz .no
    mov [rel ue_memory_token],rdx
    mov [rel ue_buffer],r8
    mov [rel ue_memory_capacity],r9
    mov rax,[rel ue_sequence]
    mov [rel ue_memory_generation],rax
    mov rax,r8
    ret
.no:
    xor eax,eax
    ret

; Validate the exact live owner/generation/token AND retained geometry. Private
; CPU source has no guest, SLAT, DMA or AP users. This module never lends it.
; Caller serializes all accesses and release; broker read alone is no lease.
ue_ram_current:
    cmp qword [rel ue_buffer],0
    jne .key
    cmp qword [rel ue_memory_token],0
    jne .no
    xor eax,eax
    ret
.key:
    sub rsp,72
    mov edi,UE_MEMORY_OWNER
    mov rsi,[rel ue_memory_generation]
    mov rdx,[rel ue_memory_token]
    mov rcx,rsp
    mov r8d,MB_ALLOCATION_BYTES
    call mb_allocation_read
    test eax,eax
    jnz .bad
    cmp qword [rsp+MB_REC_OWNER],UE_MEMORY_OWNER
    jne .bad
    mov rax,[rel ue_memory_generation]
    cmp [rsp+MB_REC_GEN],rax
    jne .bad
    mov rax,[rel ue_memory_token]
    cmp [rsp+MB_REC_TOKEN],rax
    jne .bad
    cmp qword [rsp+MB_REC_KIND],MB_KIND_SNAPSHOT
    jne .bad
    mov rax,[rel ue_buffer]
    cmp [rsp+MB_REC_BASE],rax
    jne .bad
    cmp qword [rsp+MB_REC_BYTES],UE_RAM_BYTES
    jne .bad
    cmp qword [rel ue_memory_capacity],UE_RAM_BYTES
    jne .bad
    cmp qword [rsp+MB_REC_RESIDENT],0
    jne .bad
    xor eax,eax
    add rsp,72
    ret
.bad:
    add rsp,72
.no:
    mov rax,-1
    ret

; Clear only retained private snapshot after successful close/discard. Its
; reservation remains exact and reusable until genuine stopped retirement.
ue_clear_ram:
    call ue_ram_current
    test rax,rax
    jnz .out
    mov rdi,[rel ue_buffer]
    test rdi,rdi
    jz .out
    mov rdx,[rel ue_objects+UE_OBJ_SIZE*8+16]
    cmp rdx,UE_MAX
    ja .bad
    add rdx,UE_CHUNK
    xor esi,esi
    call memset
    xor eax,eax
.out:
    ret
.bad:
    mov rax,-1
    ret

; Only update_esp_reclaim after actual VM stop calls this. No copy job can
; outlive the synchronous source call. Scrub the entire owned capacity before
; exact-key release. A busy/stale release retains the private key and custody.
ue_ram_release:
    call ue_ram_current
    test rax,rax
    jnz .out
    cmp qword [rel ue_buffer],0
    je .out
    mov rdi,[rel ue_buffer]
    mov edx,UE_RAM_BYTES
    xor esi,esi
    call memset
    mov edi,UE_MEMORY_OWNER
    mov rsi,[rel ue_memory_generation]
    mov rdx,[rel ue_memory_token]
    call mb_release
    test eax,eax
    jnz .bad
    mov qword [rel ue_buffer],0
    mov qword [rel ue_memory_token],0
    mov qword [rel ue_memory_generation],0
    mov qword [rel ue_memory_capacity],0
    xor eax,eax
.out:
    ret
.bad:
    mov rax,-1
    ret

ue_new_id:
    cmp qword [rel ue_object_sequence],-1
    je ue_refused
    inc qword [rel ue_object_sequence]
    mov rax,[rel ue_object_sequence]
    mov [rbx],rax
    ret
; RDI fixed ID -> max exact product file size, zero invalid.
ue_limit:
    cmp rdi,1
    jne .key
    mov eax,1024
    ret
.key:
    cmp rdi,2
    jne .small
    mov eax,4096
    ret
.small:
    cmp rdi,7
    jae .slot
    mov eax,512
    ret
.slot:
    mov eax,UE_MAX
    ret

; Object identity is actual retained 32-byte native dirent+location, not name.
ue_resolve_object:
    mov rax,[rbx+8]
    lea rdx,[rel ue_paths]
    movsxd rax,dword [rdx+rax*4-4]
    add rax,rdx
    mov [rel ue_read_path],rax
    jmp ue_save_entry
ue_save_entry:
    lea rdi,[rel ue_ctx]
    mov rsi,[rel ue_read_path]
    mov qword [rel fd_path_cache_ctx],0
    mov byte [rel fd_resolve_strict],1
    call fat32_disk_resolve_path_lfn
    mov byte [rel fd_resolve_strict],0
    test rax,rax
    jnz .absent
    test byte [rel fd_found_attr],0x18
    jnz ue_refused
    mov rdi,[rbx+8]
    call ue_limit
    cmp [rel fd_found_size],rax
    ja ue_refused
    mov rax,[rel fd_found_size]
    mov [rbx+16],rax
    mov rax,[rel fd_found_dir_lba]
    mov [rbx+24],rax
    mov eax,[rel fd_found_dir_off]
    mov [rbx+32],rax
    lea rdi,[rel ue_ctx]
    mov rsi,[rbx+24]
    mov edx,1
    lea rcx,[rel fd_sector]
    call fd_read_sectors
    test rax,rax
    jnz ue_refused
    lea rsi,[rel fd_sector]
    add rsi,[rbx+32]
    lea rdi,[rbx+40]
    mov edx,32
    call memcpy
    xor eax,eax
    ret
.absent:
    cmp byte [rel fd_resolve_absent],1
    jne ue_refused
    mov rax,-4
    ret
ue_object_check:
    sub rsp,80
    mov rdi,rsp
    mov rsi,rbx
    mov edx,80
    call memcpy
    push rbx
    mov rbx,rsp
    add rbx,8
    cmp dword [rbx+72],2
    jne .fixed
    call ue_temp_path
    mov [rel ue_read_path],rax
    call ue_save_entry
    jmp .compare
.fixed:
    call ue_resolve_object
.compare:
    pop rbx
    test rax,rax
    jnz .out
    lea rdi,[rbx+16]
    lea rsi,[rsp+16]
    mov edx,56
    call memcmp
    test eax,eax
    jz .out
    mov rax,-1
.out:
    add rsp,80
    ret

; Fixed original parent only, no caller paths. Also takes directory-view gate
; for read-only temp collision checks and mutations. Snapshot writer releases.
ue_parent:
    push rbx
    cmp dword [rel fd_cp_phase],FD_CP_IDLE
    jne .bad
    cmp dword [rel fd_dir_gate],0
    jne .bad
    mov rax,rdi
    lea rdx,[rel ue_parents]
    movsxd rsi,dword [rdx+rax*4-4]
    add rsi,rdx
    mov [rel ue_parent_path],rsi
    lea rdi,[rel ue_ctx]
    mov qword [rel fd_path_cache_ctx],0
    call fat32_disk_resolve_path_lfn
    test rax,rax
    jnz .bad
    test byte [rel fd_found_attr],0x10
    jz .bad
    mov eax,[rel fd_found_cluster]
    mov [rel ue_parent_cluster],eax
    xor eax,eax
    pop rbx
    ret
.bad:
    mov rax,-1
    pop rbx
    ret
ue_temp_path:
    mov rax,[rel ue_temp_target]
    lea rdx,[rel ue_temps]
    movsxd rax,dword [rdx+rax*4-4]
    add rax,rdx
    ret
ue_short_name:
    lea rdx,[rel ue_short_names]
    movsxd rax,dword [rdx+rdi*4-4]
    test rax,rax
    jz .out
    add rax,rdx
.out:
    ret

; Original streaming copy engine, root journal and entry-last replacement.
; RSI exact11 name in already resolved parent; RBX logical temp object.
; No alternate allocator/FAT writer. Buffer is immutable through copy+verify.
ue_snapshot_write:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r13,rbx
    mov r15,[rbx+16]
    lea rdi,[rel fd_cp_name]
    mov edx,11
    call memcpy
    lea rbx,[rel ue_ctx]
    mov eax,1
    xchg eax,[rel fd_dir_gate]
    test eax,eax
    jnz .fail
    mov [rel fd_dir_owner],rbx
    mov byte [rel fd_dir_view_valid],0
    mov ebp,262144
.recover:
    mov rdi,rbx
    call fd_writer_enter
    test rax,rax
    jz .locked
    cmp dword [rel fat32_disk_last_error],FD_ERR_BUSY
    jne .gate_fail
    cmp dword [rbx+FD_TX_BUSY],0
    jne .gate_fail
    dec ebp
    jnz .recover
    jmp .gate_fail
.locked:
    mov rdi,rbx
    mov esi,[rel ue_parent_cluster]
    call fd_cp_view
    test rax,rax
    jnz .locked_fail
    mov dword [rel fd_tree_on],0
    mov qword [rel fd_tree_base],0
    mov byte [rel fd_cp_cmp_on],0
    mov byte [rel fd_cp_src_retry_pending],0
    mov byte [rel fd_cp_src_retried],0
    mov byte [rel fd_cp_src_fault],0
    mov byte [rel fd_cp_repl],0
    mov byte [rel fd_cp_swapped],0
    mov byte [rel fd_cp_old_case],0
    mov dword [rel fd_cp_kept],0
    mov dword [rel fd_cp_wrt],0
    mov dword [rel fd_cp_error],0
    mov dword [rel fd_cp_mode],FS_CMODE_FORCE
    mov dword [rel fd_cp_alloc_hint],2
    mov dword [rel fd_cp_src_head],UE_SOURCE
    mov [rel fd_cp_total],r15
    mov rax,[rbx+FD_DEV]
    mov [rel fd_cp_dev],rax
    mov rdx,[rax+dev.info]
    mov [rel fd_cp_info],rdx
    mov rdx,[rdx+blk_info.media_generation]
    mov [rel fd_cp_generation],rdx
    lea rdi,[rel ue_job]
    xor esi,esi
    mov edx,fs_copy_job_size
    call memset
    ; Zero sector slack in RAM before the native engine's sector compare.
    mov rdi,[rel ue_buffer]
    add rdi,r15
    xor esi,esi
    mov edx,UE_CHUNK
    call memset
    lea rdi,[rel fd_dir_ctx]
    lea rsi,[rel fd_cp_name]
    call fd_probe_slot
    test rax,rax
    js .locked_fail
    jz .arm
    mov rdi,rbx
    call fd_cp_older
    cmp eax,1
    jne .locked_fail
.arm:
    mov rdi,rbx
    call fd_cp_arm
    test rax,rax
    jnz .locked_fail
    lea rax,[rel ue_job]
    mov [rel fd_cp_job],rax
    mov [rel fd_cp_ctx],rbx
    mov [rel ue_job+fs_copy_job.total],r15
    mov dword [rel ue_job+fs_copy_job.state],FS_JOB_RUNNING
    call fd_cp_file_start
    mov rdi,rbx
    call fd_cp_view_release
    mov dword [rel fd_dir_gate],0
    mov ebp,262144
.step:
    call fd_cp_step
    cmp dword [rel fd_cp_phase],FD_CP_IDLE
    je .finished
    dec ebp
    jnz .step
    ; No asynchronous continuation may outlive private source/authority.
    mov dword [rel fd_cp_phase],FD_CP_IDLE
    mov dword [rbx+FD_TX_BUSY],0
    jmp .fail
.finished:
    cmp dword [rel ue_job+fs_copy_job.state],FS_JOB_DONE
    jne .fail
    cmp dword [rel ue_job+fs_copy_job.durable],FS_DUR_UNCERTAIN
    je .fail
    call ue_flush
    test rax,rax
    jnz .fail
    xor eax,eax
    jmp .out
.locked_fail:
    mov dword [rbx+FD_TX_BUSY],0
    mov rdi,rbx
    call fd_cp_view_release
.gate_fail:
    mov dword [rel fd_dir_gate],0
    mov qword [rel fd_dir_owner],0
.fail:
    call ue_fault
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

ue_remove_temp:
    mov rdi,[rel ue_temp_target]
    call ue_parent
    test rax,rax
    jnz ue_refused
    lea rdi,[rel ue_ctx]
    call fd_tree_enter
    test rax,rax
    jnz ue_refused
    lea rdi,[rel ue_ctx]
    call fd_writer_enter
    test rax,rax
    jnz .leave
    lea rdi,[rel ue_ctx]
    mov esi,[rel ue_parent_cluster]
    call fd_cp_view
    test rax,rax
    jnz .unlock
    lea rdi,[rel fd_dir_mount]
    lea rsi,[rel ue_temp_name]
    call fat32_disk_delete
.unlock:
    mov dword [rel ue_ctx+FD_TX_BUSY],0
.leave:
    lea rdi,[rel ue_ctx]
    jmp fd_tree_leave

; Only two fixed new long names. No generic LFN mutation API: publish a
; zero-length regular placeholder plus its exact LFN in ONE sector before
; the maintained replacement journal can allocate or expose payload bytes.
; Existing alias collision, insufficient contiguous space or any IO refuses.
ue_create_release:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    lea rsi,[rel ue_alias_a]
    cmp r14,5
    je .alias
    lea rsi,[rel ue_alias_b]
.alias:
    lea rdi,[rel ue_publish_name]
    mov edx,11
    call memcpy
    lea rdi,[rel ue_ctx]
    call fd_tree_enter
    test rax,rax
    jnz .bad
    lea rdi,[rel ue_ctx]
    call fd_writer_enter
    test rax,rax
    jnz .leave
    lea rdi,[rel ue_ctx]
    mov esi,[rel ue_parent_cluster]
    call fd_cp_view
    test rax,rax
    jnz .unlock
    lea rdi,[rel fd_dir_ctx]
    lea rsi,[rel ue_publish_name]
    call fd_lookup
    test rax,rax
    jz .unlock_bad
    cmp dword [rel fat32_disk_last_error],FD_ERR_NOT_FOUND
    jne .unlock_bad
    mov r12d,[rel ue_parent_cluster]
    mov r15d,FD_DIR_MAX_CLUSTERS
.cluster:
    lea rdi,[rel ue_ctx]
    mov esi,r12d
    call fd_cluster_lba
    cmp rax,-1
    je .unlock_bad
    mov r13,rax
    mov ebp,[rel ue_ctx+FD_SPC]
.sector:
    lea rdi,[rel ue_ctx]
    mov rsi,r13
    mov edx,1
    lea rcx,[rel ue_lfn_sector]
    call fd_read_sectors
    test rax,rax
    jnz .unlock_bad
    xor ebx,ebx
.scan:
    cmp ebx,384                     ; 3 entries plus a retained end marker
    ja .next_sector
    lea rdi,[rel ue_lfn_sector]
    add rdi,rbx
    xor ecx,ecx
    xor r14d,r14d
.free:
    cmp byte [rdi+rcx],0
    je .end
    cmp byte [rdi+rcx],0xe5
    jne .occupied
    add ecx,32
    cmp ecx,96
    jb .free
    jmp .found
.end:
    mov r14d,1
    jmp .found
.occupied:
    add ebx,32
    jmp .scan
.next_sector:
    ; An earlier end marker in the last three slots cannot be skipped.
    lea rdi,[rel ue_lfn_sector]
    mov ecx,416
.end_scan:
    cmp byte [rdi+rcx],0
    je .unlock_bad
    add ecx,32
    cmp ecx,512
    jb .end_scan
    inc r13
    dec ebp
    jnz .sector
    lea rdi,[rel ue_ctx]
    mov esi,r12d
    call fd_next_cluster
    cmp eax,2
    jb .unlock_bad
    cmp eax,[rel ue_ctx+FD_MAX_CLUSTER]
    jae .unlock_bad
    mov r12d,eax
    dec r15d
    jnz .cluster
    jmp .unlock_bad
.found:
    lea rdi,[rel ue_lfn_record]
    mov esi,0xff
    mov edx,64
    call memset
    lea rdi,[rel ue_lfn_record+64]
    xor esi,esi
    mov edx,33
    call memset
    lea rdi,[rel ue_lfn_record+64]
    lea rsi,[rel ue_publish_name]
    mov edx,11
    call memcpy
    mov byte [rel ue_lfn_record+75],0x20
    mov byte [rel ue_lfn_record],0x42
    mov byte [rel ue_lfn_record+32],1
    mov byte [rel ue_lfn_record+11],0x0f
    mov byte [rel ue_lfn_record+43],0x0f
    mov byte [rel ue_lfn_record+12],0
    mov byte [rel ue_lfn_record+44],0
    mov word [rel ue_lfn_record+26],0
    mov word [rel ue_lfn_record+58],0
    mov word [rel ue_lfn_record+1],'1'
    mov word [rel ue_lfn_record+3],0
    ; Actual checksum of the fixed short alias, used by the existing reader.
    lea rsi,[rel ue_publish_name]
    xor eax,eax
    mov ecx,11
.sum:
    ror al,1
    add al,[rsi]
    inc rsi
    loop .sum
    mov [rel ue_lfn_record+13],al
    mov [rel ue_lfn_record+45],al
    lea rsi,[rel ue_lfn_a]
    cmp qword [rel ue_publish_target],5
    je .text
    lea rsi,[rel ue_lfn_b]
.text:
    xor ecx,ecx
.chars:
    lea rdx,[rel ue_lfn_offsets]
    movzx eax,byte [rdx+rcx]
    lea rdi,[rel ue_lfn_record+32]
    movzx edx,byte [rsi+rcx]
    mov [rdi+rax],dx
    inc ecx
    cmp ecx,13
    jb .chars
    lea rdi,[rel ue_ctx]
    mov rsi,r13
    mov edx,ebx
    lea rcx,[rel ue_lfn_record]
    mov r8d,96
    add r8d,r14d                   ; preserve existing following entry, or end0
    call fd_dir_patch
    jmp .unlock
.unlock_bad:
    mov rax,-1
.unlock:
    mov dword [rel ue_ctx+FD_TX_BUSY],0
.leave:
    lea rdi,[rel ue_ctx]
    call fd_tree_leave
    jmp .out
.bad:
    mov rax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Private immutable RAM source adapter; the maintained engine owns all
; allocation, verification, journal, entry-last publication and old reclaim.
ue_memory_sectors:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r15, rcx
    mov ebp, r8d
    mov esi, edx
    call fd_cluster_lba
    cmp rax, -1
    je .fail
    mov r13, rax
    mov r14, [rel fd_cp_done]
    test ebp, ebp
    jz .buffer
    mov r14, [rel fd_cp_vdone]
.buffer:
    add r14, [rel ue_buffer]
.loop:
    test r15, r15
    jz .ok
    mov rbx, r15
    cmp rbx, 8
    jbe .size
    mov ebx, 8
.size:
    mov rdi, r12
    mov rsi, r13
    mov rdx, rbx
    test ebp, ebp
    jnz .compare
    mov rcx, r14
    call fd_write_sectors
    test rax, rax
    jnz .fail
    jmp .next
.compare:
    lea rcx, [rel fd_cp_vbuf]
    call fd_read_sectors
    test rax, rax
    jnz .fail
    lea rdi, [rel fd_cp_vbuf]
    mov rsi, r14
    mov rdx, rbx
    shl rdx, 9
    call memcmp
    test rax, rax
    jnz .fail
.next:
    add r13, rbx
    sub r15, rbx
    shl rbx, 9
    add r14, rbx
    jmp .loop
.ok:
    xor eax, eax
    jmp .out
.fail:
    mov rax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

%macro WDATA_fs_update_esp 0
ue_private_data_begin:
ue_raw_ids: dd 1,3,4,5,6
ue_temp_name: db 'UPDTMP  BIN'
ue_alias_a: db 'RELUPDA PRL'
ue_alias_b: db 'RELUPDB PRL'
ue_lfn_a: db 'release-a.prl'
ue_lfn_b: db 'release-b.prl'
ue_lfn_offsets: db 1,3,5,7,9,14,16,18,20,22,24,28,30
ue_p1: db '/EFI/PaOS/vault/manifest.bin',0
ue_p2: db '/EFI/PaOS/vault/owner-public.pem',0
ue_p3: db '/EFI/PaOS/state/state0.bin',0
ue_p4: db '/EFI/PaOS/state/state1.bin',0
ue_p5: db '/EFI/PaOS/state/release-a.prl1',0
ue_p6: db '/EFI/PaOS/state/release-b.prl1',0
ue_p7: db '/EFI/PaOS/slots/paos-a.efi',0
ue_p8: db '/EFI/PaOS/slots/paos-b.efi',0
ue_vault: db '/EFI/PaOS/vault',0
ue_state_path: db '/EFI/PaOS/state',0
ue_slots: db '/EFI/PaOS/slots',0
ue_vtemp: db '/EFI/PaOS/vault/UPDTMP.BIN',0
ue_stemp: db '/EFI/PaOS/state/UPDTMP.BIN',0
ue_ptemp: db '/EFI/PaOS/slots/UPDTMP.BIN',0
ue_n1: db 'MANIFESTBIN'
ue_n3: db 'STATE0  BIN'
ue_n4: db 'STATE1  BIN'
ue_n7: db 'PAOS-A  EFI'
ue_n8: db 'PAOS-B  EFI'
align 8
; Signed deltas from each table anchor; the image is loaded at a nonzero base.
ue_paths: dd ue_p1-ue_paths,ue_p2-ue_paths,ue_p3-ue_paths,ue_p4-ue_paths,ue_p5-ue_paths,ue_p6-ue_paths,ue_p7-ue_paths,ue_p8-ue_paths
ue_parents: dd ue_vault-ue_parents,ue_vault-ue_parents,ue_state_path-ue_parents,ue_state_path-ue_parents,ue_state_path-ue_parents,ue_state_path-ue_parents,ue_slots-ue_parents,ue_slots-ue_parents
ue_temps: dd ue_vtemp-ue_temps,ue_vtemp-ue_temps,ue_stemp-ue_temps,ue_stemp-ue_temps,ue_stemp-ue_temps,ue_stemp-ue_temps,ue_ptemp-ue_temps,ue_ptemp-ue_temps
; Zero is an absent short name, never the table anchor.
ue_short_names: dd ue_n1-ue_short_names,0,ue_n3-ue_short_names,ue_n4-ue_short_names,0,0,ue_n7-ue_short_names,ue_n8-ue_short_names
ue_private_data_end:
%endmacro
WDATA_DEFER WDATA_fs_update_esp
%macro WDATA_BSS_fs_update_esp 0
alignb 8
ue_private_begin:
ue_lfn_sector: resb 512
ue_lfn_record: resb 97
ue_publish_name: resb 11
alignb 8
ue_original: resb 40
ue_runtime: resb 128
ue_check: resb 168
ue_desc: resb 136
ue_lease_snapshot: resb 136
ue_ctx: resb FD_CTX_SIZE
ue_mount: resb fsmount_size
ue_objects: resb UE_OBJ_SIZE*UE_TEMP
ue_job: resb fs_copy_job_size
ue_buffer: resq 1
ue_memory_token: resq 1
ue_memory_generation: resq 1
ue_memory_capacity: resq 1
ue_observation_serial: resq 1
ue_sequence: resq 1
ue_object_sequence: resq 1
ue_lease: resq 1
ue_read_path: resq 1
ue_parent_path: resq 1
ue_temp_target: resq 1
ue_publish_target: resq 1
ue_effects: resq 1
; Diagnostic native facts, kept across freeze/stopped/reclaim. No setters.
ue_facts_start:
ue_rw_issued: resq 1
ue_write_issued: resq 1
ue_flush_issued: resq 1
ue_restore_attempts: resq 1
ue_ro_confirmed: resq 1
ue_uncertain: resq 1
ue_published_mask: resq 1
ue_native_event: resq 1
ue_first_slot_publication: resq 1
ue_reclaim_attempted: resq 1
ue_phase: resd 1
ue_observation_valid: resd 1
    resd 1
ue_before_mask: resd 1
    resd 1
ue_before_length: resq 1
ue_before_offsets: resq 5
ue_before_sha: resb 32
ue_before_raw: resb UE_RAW_MAX
ue_after_mask: resd 1
    resd 1
ue_after_length: resq 1
ue_after_offsets: resq 5
ue_after_sha: resb 32
ue_after_raw: resb UE_RAW_MAX
ue_finish_result: resq 1
ue_readback_mask: resq 1
ue_readbacks_exact: resq 1
ue_readback_ordinal: resq 1
ue_final_ro_ordinal: resq 1
ue_finish_sha: resb 32
ue_publish_sha: resb 32
ue_stage_kind: resd 1
ue_stage_start: resb 512
ue_stage_armed: resb 512
ue_feed_attempted: resd 1
ue_class: resd 1
ue_feed_verified: resd 1
ue_finish_attempted: resd 1
ue_current_verified: resd 1
ue_active_slot: resd 1
    resd 1
ue_selected_state: resq 1
ue_selected_generation: resq 1
ue_active_size: resq 1
ue_offer_size: resq 1
ue_release_admitted: resq 1
ue_feed_sha: resb 32
ue_policy_sha: resb 32
ue_active_sha: resb 32
ue_offer_sha: resb 32
ue_owner_sha: resb 32
ue_feed_raw: resb 1024
ue_hash_object: resb 80
ue_hash_context: resb 112
ue_hash_chunk: resb UE_CHUNK
ue_facts_end:
ue_parent_cluster: resd 1
ue_state: resd 1
ue_busy: resd 1
ue_readonly: resd 1
ue_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_update_esp
%endif

; Effect-free signed-release predicate for the native staging receiver.
%include "fs/update_release.asm"
