;; MODULE svc/service_progress
;; LAYER 5
;; EXPORTS service_progress_enter, service_progress_exit, service_progress_status_sent, service_progress_authstat_begin, service_progress_authstat_stage, service_progress_rmp1_begin, service_progress_rmp1_event, service_progress_rmp1_start, service_progress_plain_rx, service_progress_plain_tx, service_progress_prerx_status, service_progress_prerx_slice_enter, service_progress_prerx_slice_return
;; IMPORTS boot/header, boot/boot_v2_handoff, boot/boot_v2_health, boot/nvram_access, core/build_id, core/reset_wipe, svc/command_udp, hv/vmx
;; CAPS
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; Opt-in lab diagnostic. Persistence only on normal serialized BSP, never IRQ/AP/guest exit.
; PRERX adds bounded RAM-only hooks on the existing BSP guest host-slice boundary.
; PaOSServiceProgress / BootReady GUID, PSP1 v1, 512 bytes. Independent of UDP
; after return: read-only Windows GetFirmwareEnvironmentVariableExW or efivarfs.
; Two SetVariable attempts MAX: first returned poll baseline, first >=1000ms
; returned-poll or between-polls gap. First poll may itself be the final gap.
; Fixed RAM/scalar copies per hook, no allocation/spin/MMIO/traffic. Firmware
; latency cannot be bounded by this caller. Own IO excluded from the trigger.
; A permanent BSP stall cannot publish a new sample. Failure/absence UNKNOWN;
; no health/admission/mitigation/owner/custody/STALE effect. Default has no request matching.
; POST_HEALTH=1 waits without claiming initialization until the strong-health
; latch is observed at a poll entry. It never includes a pre-health interval.
%ifndef RCQ_SERVICE_PROGRESS_DIAG
%define RCQ_SERVICE_PROGRESS_DIAG 0
%endif
%if RCQ_SERVICE_PROGRESS_DIAG != 0 && RCQ_SERVICE_PROGRESS_DIAG != 1
%error "RCQ_SERVICE_PROGRESS_DIAG must be 0 or 1"
%endif
%ifndef RCQ_SERVICE_PROGRESS_POST_HEALTH
%define RCQ_SERVICE_PROGRESS_POST_HEALTH 0
%endif
%if RCQ_SERVICE_PROGRESS_POST_HEALTH != 0 && RCQ_SERVICE_PROGRESS_POST_HEALTH != 1
%error "RCQ_SERVICE_PROGRESS_POST_HEALTH must be 0 or 1"
%endif
%if RCQ_SERVICE_PROGRESS_POST_HEALTH && !RCQ_SERVICE_PROGRESS_DIAG
%error "RCQ_SERVICE_PROGRESS_POST_HEALTH requires RCQ_SERVICE_PROGRESS_DIAG=1"
%endif
%ifndef RCQ_SERVICE_PROGRESS_POST_STATUS
%define RCQ_SERVICE_PROGRESS_POST_STATUS 0
%endif
%if RCQ_SERVICE_PROGRESS_POST_STATUS != 0 && RCQ_SERVICE_PROGRESS_POST_STATUS != 1
%error "RCQ_SERVICE_PROGRESS_POST_STATUS must be 0 or 1"
%endif
%if RCQ_SERVICE_PROGRESS_POST_STATUS && (!RCQ_SERVICE_PROGRESS_DIAG || !RCQ_SERVICE_PROGRESS_POST_HEALTH)
%error "RCQ_SERVICE_PROGRESS_POST_STATUS requires DIAG=1 and POST_HEALTH=1"
%endif
%ifndef RCQ_SERVICE_PROGRESS_AUTHSTAT
%define RCQ_SERVICE_PROGRESS_AUTHSTAT 0
%endif
%if RCQ_SERVICE_PROGRESS_AUTHSTAT != 0 && RCQ_SERVICE_PROGRESS_AUTHSTAT != 1
%error "RCQ_SERVICE_PROGRESS_AUTHSTAT must be 0 or 1"
%endif
%if RCQ_SERVICE_PROGRESS_AUTHSTAT && (!RCQ_SERVICE_PROGRESS_DIAG || !RCQ_SERVICE_PROGRESS_POST_HEALTH || RCQ_SERVICE_PROGRESS_POST_STATUS)
%error "AUTHSTAT requires DIAG=1, POST_HEALTH=1, POST_STATUS=0"
%endif
; Separate raw eight-byte ingress observation, not a RMP1/owner envelope.
%ifndef RCQ_SERVICE_PROGRESS_PLAIN_AUTHSTAT
%define RCQ_SERVICE_PROGRESS_PLAIN_AUTHSTAT 0
%endif
%if RCQ_SERVICE_PROGRESS_PLAIN_AUTHSTAT != 0 && RCQ_SERVICE_PROGRESS_PLAIN_AUTHSTAT != 1
%error "PLAIN_AUTHSTAT must be 0 or 1"
%endif
%if RCQ_SERVICE_PROGRESS_PLAIN_AUTHSTAT && !RCQ_SERVICE_PROGRESS_AUTHSTAT
%error "PLAIN_AUTHSTAT requires AUTHSTAT=1 (and its DIAG/POST_HEALTH requirements)"
%endif
; Separate fixed kind8 overlay: last completed STATUS / pre-RX poll and slice
; history. Kind7/default serialization is unchanged when this flag is absent.
%ifndef RCQ_SERVICE_PROGRESS_PRERX
%define RCQ_SERVICE_PROGRESS_PRERX 0
%endif
%if RCQ_SERVICE_PROGRESS_PRERX != 0 && RCQ_SERVICE_PROGRESS_PRERX != 1
%error "PRERX must be 0 or 1"
%endif
%if RCQ_SERVICE_PROGRESS_PRERX && !RCQ_SERVICE_PROGRESS_PLAIN_AUTHSTAT
%error "PRERX requires PLAIN_AUTHSTAT=1 (and its AUTHSTAT/DIAG/POST_HEALTH requirements)"
%endif
; Separate public SESSIONINFO observation. Keep all prior modes byte-identical.
%ifndef RCQ_SERVICE_PROGRESS_SESSIONINFO
%define RCQ_SERVICE_PROGRESS_SESSIONINFO 0
%endif
%if RCQ_SERVICE_PROGRESS_SESSIONINFO != 0 && RCQ_SERVICE_PROGRESS_SESSIONINFO != 1
%error "SESSIONINFO must be 0 or 1"
%endif
%if RCQ_SERVICE_PROGRESS_SESSIONINFO && !RCQ_SERVICE_PROGRESS_PRERX
%error "SESSIONINFO requires PRERX=1 (and its PLAIN_AUTHSTAT/AUTHSTAT/DIAG/POST_HEALTH requirements)"
%endif
; Separate plain8B AUTHSTAT window, armed by completed STATUS even before RX.
; Kind10 shares kind9's paired RAM history and returned BSP persistence only.
%ifndef RCQ_SERVICE_PROGRESS_PREJOB_AUTHSTAT
%define RCQ_SERVICE_PROGRESS_PREJOB_AUTHSTAT 0
%endif
%if RCQ_SERVICE_PROGRESS_PREJOB_AUTHSTAT != 0 && RCQ_SERVICE_PROGRESS_PREJOB_AUTHSTAT != 1
%error "PREJOB_AUTHSTAT must be 0 or 1"
%endif
%if RCQ_SERVICE_PROGRESS_PREJOB_AUTHSTAT && (!RCQ_SERVICE_PROGRESS_PRERX || RCQ_SERVICE_PROGRESS_SESSIONINFO)
%error "PREJOB_AUTHSTAT requires PRERX=1 and SESSIONINFO=0"
%endif
%define SP_PRERX_WINDOW (RCQ_SERVICE_PROGRESS_SESSIONINFO || RCQ_SERVICE_PROGRESS_PREJOB_AUTHSTAT)
%ifndef RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT
%define RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT 0
%endif
%if RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT != 0 && RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT != 1
%error "RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT must be 0 or 1"
%endif
%if RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT && (!RCQ_SERVICE_PROGRESS_DIAG || !RCQ_SERVICE_PROGRESS_POST_HEALTH || RCQ_SERVICE_PROGRESS_POST_STATUS || RCQ_SERVICE_PROGRESS_AUTHSTAT)
%error "RMP1_AUTHSTAT requires DIAG=1, POST_HEALTH=1, POST_STATUS=0, AUTHSTAT=0"
%endif
%ifndef RCQ_SERVICE_PROGRESS_FIRST_START
%define RCQ_SERVICE_PROGRESS_FIRST_START 0
%endif
%if RCQ_SERVICE_PROGRESS_FIRST_START != 0 && RCQ_SERVICE_PROGRESS_FIRST_START != 1
%error "FIRST_START must be 0 or 1"
%endif
%if RCQ_SERVICE_PROGRESS_FIRST_START && !RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT
%error "FIRST_START requires RMP1_AUTHSTAT=1"
%endif
%if RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT
%define SP_AUTH_MASK 40
%define SP_AUTH_FIRST 28
%if RCQ_SERVICE_PROGRESS_FIRST_START
%define SP_AUTH_KIND 6
%else
%define SP_AUTH_KIND 5
%endif
%else
%define SP_AUTH_MASK 0
%define SP_AUTH_FIRST 52
%if RCQ_SERVICE_PROGRESS_PLAIN_AUTHSTAT
%if RCQ_SERVICE_PROGRESS_PREJOB_AUTHSTAT
%define SP_AUTH_KIND 10
%elif RCQ_SERVICE_PROGRESS_SESSIONINFO
%define SP_AUTH_KIND 9
%elif RCQ_SERVICE_PROGRESS_PRERX
%define SP_AUTH_KIND 8
%else
%define SP_AUTH_KIND 7
%endif
%else
%define SP_AUTH_KIND 4
%endif
%endif
%if RCQ_SERVICE_PROGRESS_DIAG
SP_SIZE equ 512
SP_SAMPLE equ 160
SP_CRC equ 508
SP_GAP_MS equ 1000

%macro SP_SAVE 0
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
%endmacro
%macro SP_RESTORE 0
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    ret
%endmacro

service_progress_eligible:
    cmp byte [rel reset_wipe_done], 0
    jne .no
%if RCQ_SERVICE_PROGRESS_POST_HEALTH
    cmp byte [rel pbm_strong_health_published], 1
    jne .no
%endif
    cmp byte [rel pbm_manager_launch], 1
    jne .no
    cmp byte [rel pbm_safe_runtime_active], 0
    jne .no
    test byte [rel pbm_flags], PBM_HF_MUTABLE_ATTEMPT
    jz .no
    cmp byte [rel pbm_profile], PBM_PROFILE_NORMAL
    jne .no
    movzx eax, byte [rel pbm_entry]
    cmp eax, PBM_ENTRY_PAOS_A
    je .entry
    cmp eax, PBM_ENTRY_PAOS_B
    jne .no
.entry:
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .no
    cmp qword [rel pbm_manager_sequence], 0
    je .no
    cmp qword [rel pbm_attempt_nonce], 0
    je .no
    cmp qword [rel pbm_state_generation], 0
    je .no
    cmp qword [rel boot_tsc_start], 0
    je .no
    cmp byte [rel paos_build_state], BID_ST_MATCH
    jne .no
    xor eax, eax
    xor edx, edx
    xor ecx, ecx
    lea r8, [rel pbm_payload_sha]
    lea r9, [rel paos_build_measured]
.digest:
    or al, [r8+rcx]
    or dl, [r9+rcx]
    inc ecx
    cmp ecx, 32
    jb .digest
    test al, al
    jz .no
    test dl, dl
    jz .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; Single claim, including refused initialization. No firmware at initialization.
service_progress_init:
    sub rsp, 8
    mov byte [rel sp_initialized], 1
    call service_progress_eligible
    test eax, eax
    jz .out
    lea rdi, [rel sp_record]
    xor eax, eax
    mov ecx, SP_SIZE/8
    rep stosq
    mov dword [rel sp_record], 'PSP1'
    mov word [rel sp_record+4], 1
    mov word [rel sp_record+6], SP_SIZE
    movzx eax, byte [rel pbm_entry]
    mov [rel sp_record+12], eax
    mov rax, [rel pbm_manager_sequence]
    mov [rel sp_record+16], rax
    mov rax, [rel pbm_attempt_nonce]
    mov [rel sp_record+24], rax
    mov rax, [rel pbm_state_generation]
    mov [rel sp_record+32], rax
    lea rsi, [rel pbm_payload_sha]
    lea rdi, [rel sp_record+40]
    mov ecx, 4
    rep movsq
    lea rsi, [rel paos_build_measured]
    lea rdi, [rel sp_record+72]
    mov ecx, 4
    rep movsq
    mov rax, [rel boot_tsc_start]
    mov [rel sp_record+104], rax
    mov qword [rel sp_record+112], SP_GAP_MS
%if RCQ_SERVICE_PROGRESS_POST_STATUS
    mov qword [rel sp_record+112], 30000
    lea rsi, [rel sp_status_nonce]
    lea rdi, [rel sp_record+448]
    mov ecx, 2
    rep movsq
    mov rax, [rel sp_status_ms]
    mov [rel sp_record+464], rax
%endif
%if RCQ_SERVICE_PROGRESS_AUTHSTAT || RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT
    mov qword [rel sp_record+112], 30000
%endif
    mov byte [rel sp_ready], 1
.out:
    add rsp, 8
    ret

; Fixed, sequential sample; no atomic/IRQ-exclusion claim. Guest counters are
; DWORDs reset per START; generation and active flags travel with each sample.
; RDI=private 160-byte destination, ESI=position (1 before poll, 2 after poll).
service_progress_sample:
    push rbx
    mov rbx, rdi
    mov [rbx+148], esi
    call boot_ms_now
    mov [rbx], rax
    lea rdi, [rbx+8]
    call command_udp_progress_snapshot
    call command_udp_status_snapshot
    mov r8d, r8d                       ; availability 0 or zero-extended -1
    mov [rbx+104], r8
    mov [rbx+112], rdx
    mov [rbx+120], rcx
    mov eax, [rel hv_linux_start_gen]
    mov [rbx+128], eax
    mov eax, [rel hv_linux_exits]
    mov [rbx+132], eax
    mov eax, [rel hv_linux_host_slices]
    mov [rbx+136], eax
    mov eax, [rel hv_exit_reason]
    mov [rbx+140], eax
    mov al, [rel hv_linux_running]
    mov [rbx+144], al
    mov al, [rel hv_guest_launched]
    mov [rbx+145], al
    mov al, [rel hv_linux_load_err]
    mov [rbx+146], al
    mov byte [rbx+147], 0
    mov qword [rbx+152], 0
    pop rbx
    ret

service_progress_context_matches:
    sub rsp, 8
    call service_progress_eligible
    add rsp, 8
    test eax, eax
    jz .no
    movzx eax, byte [rel pbm_entry]
    cmp eax, [rel sp_record+12]
    jne .no
    mov rax, [rel pbm_manager_sequence]
    cmp rax, [rel sp_record+16]
    jne .no
    mov rax, [rel pbm_attempt_nonce]
    cmp rax, [rel sp_record+24]
    jne .no
    mov rax, [rel pbm_state_generation]
    cmp rax, [rel sp_record+32]
    jne .no
    mov rax, [rel boot_tsc_start]
    cmp rax, [rel sp_record+104]
    jne .no
    lea rsi, [rel pbm_payload_sha]
    lea rdi, [rel sp_record+40]
    mov ecx, 4
    repe cmpsq
    jne .no
    lea rsi, [rel paos_build_measured]
    lea rdi, [rel sp_record+72]
    mov ecx, 4
    repe cmpsq
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; Pair already copied and phase consumed BEFORE IO. 0=baseline, 1=slow returned
; poll, 2=between polls, 3=post-STATUS, 4=AUTHSTAT, 5=RMP1 AUTHSTAT,
; 6=first START header/member, 7=exact plain ingress/dispatch/TX, 8=pre-RX scalars.
; On any missing/refused/uncertain write disable forever; no retry/readback.
service_progress_publish:
    push rbx
    push r12
    sub rsp, 8
%if RCQ_SERVICE_PROGRESS_AUTHSTAT || RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT
    ; AUTHSTAT kinds have one returned-poll checkpoint and one post-IO window.
    cmp byte [rel sp_phase], 0
    je .baseline
%endif
    test eax, eax
    jz .baseline
    mov byte [rel sp_phase], 2
    mov byte [rel sp_ready], 0
    jmp .phase
.baseline:
    mov byte [rel sp_phase], 1
.phase:
    mov [rel sp_record+120], rax
%if RCQ_SERVICE_PROGRESS_AUTHSTAT || RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT
    lea rsi, [rel sp_auth_meta]
    lea rdi, [rel sp_record+448]
    mov ecx, 60
    rep movsb
%endif
%if RCQ_SERVICE_PROGRESS_FIRST_START
    ; Kind6 alone overlays the first sample, after all sample copies and BEFORE
    ; CRC/write. Second sample and the existing kind5 metadata remain intact.
    lea rsi, [rel sp_start]
    lea rdi, [rel sp_record+128]
    mov ecx, 160/8
    rep movsq
%endif
%if RCQ_SERVICE_PROGRESS_PLAIN_AUTHSTAT
    ; Kind7 union: exact public tuple/scalars, never a before sample.
    lea rsi, [rel sp_plain]
    lea rdi, [rel sp_record+128]
    mov ecx, 160/8
    rep movsq
%endif
    movzx eax, byte [rel sp_phase]
    mov [rel sp_record+8], eax
    call service_progress_context_matches
    test eax, eax
    jz .disable
    mov r12, [rel runtime_services]
    test r12, r12
    jz .disable
    cmp qword [r12+0x58], 0
    je .disable
    lea rdi, [rel sp_record]
    mov esi, SP_CRC
    call pbm_crc32
    mov [rel sp_record+SP_CRC], eax
    lea rdi, [rel pbm_health_var_guid]
    lea rsi, [rel sp_var_name]
    xor edx, edx                       ; implicit PaOS-owned namespace only
    lea rcx, [rel sp_caller]
    call storage_access_nvram_require
    test rax, rax
    jnz .disable
    lea rcx, [rel sp_var_name]
    lea rdx, [rel pbm_health_var_guid]
    mov r8d, PBM_EFI_HEALTH_ATTRS
    mov r9d, SP_SIZE
    sub rsp, 48                        ; MS ABI shadow, fifth arg, alignment
    lea rbx, [rel sp_record]
    mov [rsp+32], rbx
    call [r12+0x58]
    add rsp, 48
    test rax, rax
    jz .out
.disable:
    mov byte [rel sp_ready], 0
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret

; Called immediately before actual command_udp_poll, after fatal-wipe gate.
service_progress_enter:
    SP_SAVE
%if RCQ_SERVICE_PROGRESS_POST_STATUS
    cmp byte [rel sp_status_seen], 1
    jne .out
%endif
    cmp byte [rel reset_wipe_done], 0
    jne .disable
    cmp byte [rel sp_initialized], 0
    jne .initialized
%if RCQ_SERVICE_PROGRESS_POST_HEALTH
    ; Wait without initialization, sampling or IO. An exit whose entry waited
    ; also sees sp_ready=0, even if health changed inside that unobserved poll.
    cmp byte [rel pbm_strong_health_published], 1
    jne .out
%endif
    call service_progress_init
.initialized:
    cmp byte [rel sp_ready], 1
    jne .out
    cmp byte [rel sp_active], 0
    jne .disable
%if RCQ_SERVICE_PROGRESS_PRERX
    mov ebx, 1
    call service_progress_prerx_event
    cmp byte [rel sp_ready], 1
    jne .out
%endif
%if RCQ_SERVICE_PROGRESS_AUTHSTAT || RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT
    call service_progress_authstat_enter
    jmp .out
%endif
%if RCQ_SERVICE_PROGRESS_POST_STATUS
    call service_progress_window_enter
    jmp .out
%endif
    lea rdi, [rel sp_current]
    mov esi, 1
    call service_progress_sample
    mov rax, [rel sp_current]
    test rax, rax
    jz .disable
    cmp byte [rel sp_previous_valid], 1
    jne .enter
    sub rax, [rel sp_previous]
    jc .disable                        ; never turn clock regression into gap
    cmp rax, SP_GAP_MS
    jb .enter
    lea rsi, [rel sp_previous]
    lea rdi, [rel sp_record+128]
    mov ecx, SP_SAMPLE/8
    rep movsq
    lea rsi, [rel sp_current]
    mov ecx, SP_SAMPLE/8
    rep movsq
    mov eax, 2
    call service_progress_publish
    jmp .out
.enter:
    lea rsi, [rel sp_current]
    lea rdi, [rel sp_entered]
    mov ecx, SP_SAMPLE/8
    rep movsq
    mov byte [rel sp_active], 1
    jmp .out
.disable:
    mov byte [rel sp_ready], 0
.out:
    SP_RESTORE

; Called only after actual command_udp_poll returned, never from HLT/guest exit.
service_progress_exit:
    SP_SAVE
    cmp byte [rel reset_wipe_done], 0
    jne .disable
    cmp byte [rel sp_ready], 1
    jne .out
    cmp byte [rel sp_active], 1
    jne .disable
%if RCQ_SERVICE_PROGRESS_PRERX
    mov ebx, 2
    call service_progress_prerx_event
    cmp byte [rel sp_ready], 1
    jne .out
%endif
    mov byte [rel sp_active], 0
%if RCQ_SERVICE_PROGRESS_AUTHSTAT || RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT
    call service_progress_authstat_exit
    jmp .out
%endif
%if RCQ_SERVICE_PROGRESS_POST_STATUS
    call service_progress_window_exit
    jmp .out
%endif
    lea rdi, [rel sp_current]
    mov esi, 2
    call service_progress_sample
    mov rax, [rel sp_current]
    sub rax, [rel sp_entered]
    jc .disable
    cmp rax, SP_GAP_MS
    jae .gap
    cmp byte [rel sp_phase], 0
    je .baseline
    lea rsi, [rel sp_current]
    lea rdi, [rel sp_previous]
    mov ecx, SP_SAMPLE/8
    rep movsq
    mov byte [rel sp_previous_valid], 1
    jmp .out
.gap:
    mov ebx, 1
    jmp .publish
.baseline:
    xor ebx, ebx
.publish:
    lea rsi, [rel sp_entered]
    lea rdi, [rel sp_record+128]
    mov ecx, SP_SAMPLE/8
    rep movsq
    lea rsi, [rel sp_current]
    mov ecx, SP_SAMPLE/8
    rep movsq
    mov eax, ebx
    call service_progress_publish
    cmp byte [rel sp_ready], 1
    jne .out
    ; Rebase AFTER baseline IO, with fresh counters/time. Do not discard the
    ; entire next inter-poll interval or turn firmware latency into a gap.
    cmp byte [rel reset_wipe_done], 0
    jne .disable
    lea rdi, [rel sp_previous]
    mov esi, 2
    call service_progress_sample
    mov rax, [rel sp_previous]
    cmp rax, [rel sp_current]
    jb .disable
    mov byte [rel sp_previous_valid], 1
    jmp .out
.disable:
    mov byte [rel sp_ready], 0
.out:
    SP_RESTORE

%if RCQ_SERVICE_PROGRESS_POST_STATUS
; Called only after exact STATUS/CMDE_OK completed a frame on the marked egress.
; RSI is the request argument. Retain a public 16-hex nonce and native time, not
; a packet, pointer or credential. This is NOT proof of host receipt. All GPRs
; and flags preserved; no IO, allocation, guest/AP/IRQ or security transition.
service_progress_status_sent:
    SP_SAVE
    cmp byte [rel sp_status_seen], 0
    jne .out
    mov rbx, rsi
    test rbx, rbx
    jz .out
    call service_progress_eligible
    test eax, eax
    jz .out
    xor ecx, ecx
.hex:
    movzx eax, byte [rbx+rcx]
    cmp al, '0'
    jb .out
    cmp al, '9'
    jbe .digit
    or al, 0x20
    cmp al, 'a'
    jb .out
    cmp al, 'f'
    ja .out
.digit:
    inc ecx
    cmp ecx, 16
    jb .hex
    cmp byte [rbx+16], 0
    jne .out
    call boot_ms_now
    test rax, rax
    jz .out
    mov [rel sp_status_ms], rax
    mov rsi, rbx
    lea rdi, [rel sp_status_nonce]
    mov ecx, 2
    rep movsq
    mov byte [rel sp_status_seen], 1
.out:
    SP_RESTORE

; One fixed 30s native observation window. First normal BSP entry after the TX
; latch takes a RAM baseline. Early gaps and later STATUS cannot consume/rebase
; it. First poll entry/return at the threshold publishes exactly once, after
; measuring both endpoints. No baseline EFI write or own-IO interval exists.
service_progress_window_enter:
    sub rsp, 8
    lea rdi, [rel sp_current]
    mov esi, 1
    call service_progress_sample
    cmp byte [rel sp_window_armed], 1
    je .check
    mov rax, [rel sp_current]
    cmp rax, [rel sp_status_ms]
    jb .disable
    lea rsi, [rel sp_current]
    lea rdi, [rel sp_entered]
    mov ecx, SP_SAMPLE/8
    rep movsq
    mov [rel sp_previous], rax
    mov byte [rel sp_window_armed], 1
.check:
    call service_progress_window_finish
    cmp byte [rel sp_ready], 1
    jne .out
    mov byte [rel sp_active], 1
.out:
    add rsp, 8
    ret
.disable:
    mov byte [rel sp_ready], 0
    jmp .out

service_progress_window_exit:
    sub rsp, 8
    lea rdi, [rel sp_current]
    mov esi, 2
    call service_progress_sample
    call service_progress_window_finish
    add rsp, 8
    ret

service_progress_window_finish:
    sub rsp, 8
    mov rax, [rel sp_current]
    cmp rax, [rel sp_previous]
    jb .disable
    mov [rel sp_previous], rax         ; monotonicity across every sampled hook
    sub rax, [rel sp_entered]
    jc .disable
    cmp rax, 30000
    jb .out
    lea rsi, [rel sp_entered]
    lea rdi, [rel sp_record+128]
    mov ecx, SP_SAMPLE/8
    rep movsq
    lea rsi, [rel sp_current]
    mov ecx, SP_SAMPLE/8
    rep movsq
    mov eax, 3                       ; elapsed window, NEVER mislabeled a gap
    call service_progress_publish   ; consumes final phase before any IO
.out:
    add rsp, 8
    ret
.disable:
    mov byte [rel sp_ready], 0
    jmp .out
%endif


%if RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT
; PSP1 kind5: same 512-byte record, 60-byte metadata union at 448, CRC at 508.
; +0 public nonce[16], +16 innerCRC u32, +20 generation u64, +28 first ms u64,
; +36 latest delta u32, +40 stages u16, +42 recognized u16, +44 route u8,
; +45 dispatch u8, +46 TX u8, +47 retired u8, +48 attempts u16,
; +50 accepted u16, +52 first reason u32, +56 first START delta u32 (-1 absent).
; Called AFTER successful transport unwrap, BEFORE owner-envelope processing.
; Exact public inner line only; neither signed lines nor body bytes are retained.
service_progress_rmp1_begin:
    SP_SAVE
    mov byte [rel sp_auth_current], 0
    cmp byte [rel sp_ready], 1
    jne .out
    cmp byte [rel sp_active], 1
    jne .out
    cmp byte [rel control_reply_active], 1
    jne .out
    cmp dword [rel udp_line], 'AUTH'
    jne .out
    cmp dword [rel udp_line+4], 'STAT'
    jne .out
    cmp byte [rel udp_line+8], 0
    jne .out
    cmp dword [rel control_reply_request_crc], 957173738
    jne .out
    cmp qword [rel control_reply_generation], 0
    je .out
    call service_progress_context_matches
    test eax, eax
    jz .disable
    cmp word [rel sp_auth_meta+40], 0
    jne .repeat
    call boot_ms_now
    cmp rax, [rel sp_entered]
    jb .disable
    test rax, rax
    jz .disable
    mov [rel sp_auth_meta+28], rax
    lea rsi, [rel control_reply_nonce]
    lea rdi, [rel sp_auth_meta]
    mov ecx, 2
    rep movsq
    mov eax, [rel control_reply_request_crc]
    mov [rel sp_auth_meta+16], eax
    mov rax, [rel control_reply_generation]
    mov [rel sp_auth_meta+20], rax
    mov word [rel sp_auth_meta+40], 1
    mov word [rel sp_auth_meta+42], 1
    mov dword [rel sp_auth_meta+56], -1
    mov byte [rel sp_auth_current], 1
    jmp .out
.repeat:
    cmp word [rel sp_auth_meta+42], 0xffff
    je .out
    inc word [rel sp_auth_meta+42]       ; repeats never replace the first
    jmp .out
.disable:
    mov byte [rel sp_ready], 0
.out:
    SP_RESTORE

; EAX=1..10 existing stages, 11 first START, 12 route-TX attempt,
; 13 route-TX return (EDX=0 accepted, 1 failed), 14 first reason (EDX=1..22),
; 15 completed-frame counter advanced. Every hook is bounded RAM/clock only;
; all flags/GPRs restored. Acceptance/completion NEVER proves host delivery.
service_progress_rmp1_event:
    SP_SAVE
    cmp byte [rel sp_auth_current], 1
    jne .out
    cmp byte [rel sp_ready], 1
    jne .out
    mov ebx, eax
    mov r12d, edx
    cmp ebx, 1
    jb .disable
    cmp ebx, 15
    ja .disable
    cmp ebx, 11
    jb .clock
    cmp ebx, 14                       ; reason hook is at the actual guard
    je .clock
    cmp byte [rel control_reply_sending], 1
    jne .out                          ; never count unrelated non-RMP1 TX
    cmp byte [rel control_reply_active], 1
    jne .out
.clock:
    call boot_ms_now
    sub rax, [rel sp_auth_meta+28]
    jc .disable
    mov edx, eax
    shr rax, 32
    jnz .disable
    cmp edx, [rel sp_auth_meta+36]
    jb .disable
    mov [rel sp_auth_meta+36], edx
    cmp ebx, 10
    ja .scalar
    bts word [rel sp_auth_meta+40], bx
    cmp ebx, 2
    je .route
    cmp ebx, 4
    je .dispatch
    cmp ebx, 10
    jne .out
    mov byte [rel sp_auth_meta+47], 1
    mov byte [rel sp_auth_current], 0
    jmp .out
.route:
    mov [rel sp_auth_meta+44], r12b
    jmp .out
.dispatch:
    mov [rel sp_auth_meta+45], r12b
    jmp .out
.scalar:
    cmp ebx, 11
    jne .attempt
    cmp edx, -1                       ; reserved absent-START encoding
    je .disable
    cmp dword [rel sp_auth_meta+56], -1
    jne .out
    mov [rel sp_auth_meta+56], edx
    jmp .out
.attempt:
    cmp ebx, 12
    jne .result
    cmp word [rel sp_auth_meta+48], 13
    jae .disable
    inc word [rel sp_auth_meta+48]
    jmp .out
.result:
    cmp ebx, 13
    jne .reason
%if RCQ_SERVICE_PROGRESS_FIRST_START
    cmp byte [rel sp_start_pending], 1
    jne .start_return_done
    or byte [rel sp_start+148], 2
    test r12d, r12d
    jnz .start_return_done
    or byte [rel sp_start+148], 4
.start_return_done:
%endif
    bts word [rel sp_auth_meta+40], 9
    test r12d, r12d
    jnz .failed
    inc word [rel sp_auth_meta+50]
    cmp byte [rel sp_auth_meta+46], 2
    je .out
    mov byte [rel sp_auth_meta+46], 1
    jmp .out
.failed:
    mov byte [rel sp_auth_meta+46], 2
    mov r12d, 20
    jmp .latch_reason
.reason:
    cmp ebx, 14
    jne .completed
    cmp r12d, 1
    jb .disable
    cmp r12d, 22
    ja .disable
.latch_reason:
    cmp dword [rel sp_auth_meta+52], 0
    jne .out
    mov [rel sp_auth_meta+52], r12d
    jmp .out
.completed:
%if RCQ_SERVICE_PROGRESS_FIRST_START
    cmp byte [rel sp_start_pending], 1
    jne .start_completed_done
    or byte [rel sp_start+148], 16
.start_completed_done:
%endif
    cmp byte [rel sp_auth_meta+46], 1
    jne .out
    mov byte [rel sp_auth_meta+46], 3
    jmp .out
.disable:
    mov byte [rel sp_ready], 0
    mov byte [rel sp_auth_current], 0
.out:
    SP_RESTORE
%endif

%if RCQ_SERVICE_PROGRESS_FIRST_START
; RSI=actual complete Ethernet frame, RDX=actual handed-off length. Called at
; the existing TX mark AFTER its software counter sample, immediately before
; command_udp_route_tx. No payload read: fixed 146 bytes ONLY for a START with
; zero chunk length; malformed/short lengths retain scalar UNKNOWN instead.
; The first recognized canonical public request and existing lifetime apply.
; RAM only, flags/all GPRs preserved, no driver call or extra clock/IO.
service_progress_rmp1_start:
    SP_SAVE
    mov byte [rel sp_start_pending], 0
    cmp byte [rel sp_auth_current], 1
    jne .out
    cmp byte [rel sp_ready], 1
    jne .out
    cmp byte [rel control_reply_active], 1
    jne .out
    cmp byte [rel control_reply_sending], 1
    jne .out
    cmp byte [rel sp_start_seen], 0
    jne .out
    cmp word [rel sp_auth_meta+48], 1
    jne .out
    cmp dword [rel sp_auth_meta+56], -1
    je .out
    mov byte [rel sp_start_seen], 1
    mov byte [rel sp_start_pending], 1
    cmp rdx, 0xffff
    jbe .length
    mov edx, 0xffff                     ; saturated, unsupported; never copy
.length:
    mov [rel sp_start+149], dx
    cmp edx, 146
    jne .unsupported
    cmp dword [rsi+42], 'RMP1'
    jne .unsupported
    cmp byte [rsi+46], 0                 ; START only; no response body
    jne .unsupported
    cmp dword [rsi+138], 0               ; RMP1 chunk length
    jne .unsupported
    lea rdi, [rel sp_start]
    mov ecx, 146
    cld
    rep movsb
    or byte [rel sp_start+148], 1
    jmp .member
.unsupported:
    or byte [rel sp_start+148], 32
.member:
    cmp qword [rel udp_reply_tx_before], -1
    je .identity
    or byte [rel sp_start+148], 8
.identity:
    mov rdi, [rel control_reply_handle]
    mov rsi, [rel control_reply_ops]
    call netdev_tx_identity             ; bounded registry read; NO driver IO
    cmp r8, [rel control_reply_epoch_ptr]
    jne .out                           ; registration changed: member UNKNOWN
    cmp rcx, [rel control_reply_epoch]
    jne .out
    mov [rel sp_start+146], al
    mov [rel sp_start+147], dl
    mov [rel sp_start+152], rcx
.out:
    SP_RESTORE
%endif

%if RCQ_SERVICE_PROGRESS_PRERX
; Only the already-completed exact STATUS/CMDE_OK reply path calls this hook.
; Validate its canonical public argument but retain no nonce, line or pointer.
service_progress_prerx_status:
    SP_SAVE
    test rsi, rsi
    jz .out
    xor ecx, ecx
.hex:
    movzx eax, byte [rsi+rcx]
    cmp al, '0'
    jb .out
    cmp al, '9'
    jbe .digit
    or al, 0x20
    cmp al, 'a'
    jb .out
    cmp al, 'f'
    ja .out
.digit:
    inc ecx
    cmp ecx, 16
    jb .hex
    cmp byte [rsi+16], 0
    jne .out
    mov ebx, 5
    call service_progress_prerx_event
.out:
    SP_RESTORE

; Existing clean BSP guest-exit host-slice entry and its common return. Preserve
; all flags/GPRs, one clock sample/context comparison, RAM only, no firmware,
; driver, allocator, scheduler, AP, receive or TX operation in these hooks.
service_progress_prerx_slice_enter:
    SP_SAVE
    mov ebx, 3
    call service_progress_prerx_event
    SP_RESTORE

service_progress_prerx_slice_return:
    SP_SAVE
    mov ebx, 4
    call service_progress_prerx_event
    SP_RESTORE

; Internal EBX=1 poll enter,2 poll return,3 slice enter,4 slice return,5 STATUS.
; Live history is 88 bytes; count overflow/clock regression/context revokes the
; diagnostic forever. RX freezes it; no event after RX can alter its meaning.
service_progress_prerx_event:
    sub rsp, 8
    cmp byte [rel sp_ready], 1
    jne .out
    cmp word [rel sp_auth_meta], 0
    jne .out
    call service_progress_context_matches
    test eax, eax
    jz .disable
    call boot_ms_now
    test rax, rax
    jz .disable
    cmp rax, [rel sp_prerx_last]
    jb .disable
    mov [rel sp_prerx_last], rax
    cmp ebx, 5
    je .status
%if SP_PRERX_WINDOW
    ; Readiness can begin inside sched_yield of an already-open host slice.
    ; Its first return has no observed entry: consume only that initial RAM
    ; state, without inventing a boundary/count/time in the retained history.
    cmp ebx, 3
    je .slice_enter
    cmp ebx, 4
    jne .boundary
    cmp byte [rel sp_session_slice_state], 0
    je .initial_slice_return
    cmp byte [rel sp_session_slice_state], 1
    jne .disable                      ; repeated return / invalid state
    mov byte [rel sp_session_slice_state], 2
    jmp .boundary
.initial_slice_return:
    mov byte [rel sp_session_slice_state], 2
    jmp .out
.slice_enter:
    cmp byte [rel sp_session_slice_state], 1
    je .disable                       ; repeated entry, never replace it
    cmp byte [rel sp_session_slice_state], 2
    ja .disable
    mov byte [rel sp_session_slice_state], 1
.boundary:
%endif
    lea rdi, [rel sp_prerx]
    mov [rdi+rbx*8], rax
    lea ecx, [rbx-1]
    cmp dword [rdi+rcx*4+40], 0xffffffff
    je .disable
    inc dword [rdi+rcx*4+40]
    jmp .stage
.status:
    mov [rel sp_prerx], rax
    lea rsi, [rel sp_prerx+40]
    lea rdi, [rel sp_prerx+56]
    mov ecx, 4
    rep movsd
    mov eax, [rel hv_linux_start_gen]
    mov [rel sp_prerx+72], eax
.stage:
    mov [rel sp_prerx+80], ebx
    jmp .out
.disable:
    mov byte [rel sp_ready], 0
.out:
    add rsp, 8
    ret
%endif

%if RCQ_SERVICE_PROGRESS_AUTHSTAT
; Exact raw datagram only, at validated UDP ingress BEFORE trimming/unwrapping.
; RBX=Ethernet frame, R12=IPv4 header, R14=UDP header, R13=exact copied length.
; No packet retention: only public addresses/ports/MACs, fixed length and time.
%if RCQ_SERVICE_PROGRESS_PLAIN_AUTHSTAT
service_progress_plain_rx:
    SP_SAVE
    mov byte [rel sp_auth_current], 0
%if RCQ_SERVICE_PROGRESS_SESSIONINFO
    cmp r13, 44
    jne .out
    call service_progress_sessioninfo_exact
    test eax, eax
    jz .out
%else
    cmp r13, 8
    jne .out
%endif
    cmp byte [rel udp_pmod_ingress], 0
    jne .out
    cmp word [r14+2], 0x0d27             ; network-order 9997
    jne .out
    call service_progress_authstat_begin
    cmp byte [rel sp_auth_current], 1
    jne .out                           ; repeats count, never replace tuple
%if RCQ_SERVICE_PROGRESS_SESSIONINFO
    mov dword [rel sp_plain], 'SSN1'
    mov dword [rel sp_plain+4], 44
%elif RCQ_SERVICE_PROGRESS_PREJOB_AUTHSTAT
    mov dword [rel sp_plain], 'PJA1'
    mov dword [rel sp_plain+4], 8
%else
    mov dword [rel sp_plain], 'PLN1'
    mov dword [rel sp_plain+4], 8
%endif
    mov eax, [r12+12]
    mov [rel sp_plain+8], eax
    mov eax, [r12+16]
    mov [rel sp_plain+12], eax
    mov eax, [r14]
    mov [rel sp_plain+16], eax
    mov eax, [rbx+6]
    mov [rel sp_plain+20], eax
    mov ax, [rbx+10]
    mov [rel sp_plain+24], ax
    mov eax, [rbx]
    mov [rel sp_plain+26], eax
    mov ax, [rbx+4]
    mov [rel sp_plain+30], ax
    mov rax, [rel sp_auth_meta+52]
    mov [rel sp_plain+32], rax
%if RCQ_SERVICE_PROGRESS_PRERX
    ; Freeze at FIRST exact software ingress, before dispatch or any write.
    ; No subsequent poll, STATUS, host slice or repeated RX replaces history.
    cmp rax, [rel sp_prerx_last]
    jb .prerx_disable
    mov dword [rel sp_plain+44], 'PRX1'
    lea rsi, [rel sp_prerx]
    lea rdi, [rel sp_plain+48]
    mov ecx, 88/8
    rep movsq
    mov eax, [rel hv_linux_start_gen]
    mov [rel sp_plain+124], eax
    jmp .out
.prerx_disable:
    mov byte [rel sp_ready], 0
    mov byte [rel sp_auth_current], 0
%endif
.out:
    SP_RESTORE

; EAX: 1=fallback, 2=ingress, 3=missing ops, 4=missing TX. Existing reply
; TX call boundary only; no dispatch/driver/firmware IO and no branch influence.
service_progress_plain_tx:
    SP_SAVE
    cmp byte [rel sp_auth_current], 1
    jne .out
    cmp byte [rel sp_ready], 1
    jne .out
    test word [rel sp_auth_meta], 1<<8   ; exact request reached reply mark
    jz .out
    cmp byte [rel control_reply_sending], 0
    jne .out
    cmp eax, 2
    ja .reason
    mov [rel sp_plain+40], al
    cmp word [rel sp_plain+42], 0xffff
    je .disable
    inc word [rel sp_plain+42]
    jmp .out
.reason:
    cmp byte [rel sp_plain+41], 0
    jne .out
    sub eax, 2
    mov [rel sp_plain+41], al
    jmp .out
.disable:
    mov byte [rel sp_ready], 0
    mov byte [rel sp_auth_current], 0
.out:
    SP_RESTORE
%endif

; Exact unsigned/public AUTHSTAT, no arguments, at the bounded line's initial
; dispatch boundary BEFORE any optional envelope unwrap. No pointer/line retained.
; Only a normal BSP poll with captured strong-health identity can own a request.
service_progress_authstat_begin:
    SP_SAVE
    mov byte [rel sp_auth_current], 0
    cmp byte [rel sp_ready], 1
    jne .out
    cmp byte [rel sp_active], 1
    jne .out
%if SP_PRERX_WINDOW
    cmp qword [rel sp_prerx], 0        ; only after a completed STATUS
    je .out
%endif
%if RCQ_SERVICE_PROGRESS_SESSIONINFO
    call service_progress_sessioninfo_exact
    test eax, eax
    jz .out
%else
    cmp dword [rel udp_line], 'AUTH'
    jne .out
    cmp dword [rel udp_line+4], 'STAT'
    jne .out
    cmp byte [rel udp_line+8], 0
    jne .out
%endif
    call service_progress_context_matches
    test eax, eax
    jz .disable
    cmp word [rel sp_auth_meta], 0
    jne .repeat
    call boot_ms_now
    cmp rax, [rel sp_entered]
    jb .disable
    test rax, rax
    jz .disable
    mov [rel sp_auth_meta+52], rax
    mov word [rel sp_auth_meta], 1     ; stage0 recognized; delta0 is zero
    mov word [rel sp_auth_meta+6], 1
    mov byte [rel sp_auth_current], 1
    jmp .out
.repeat:
    cmp word [rel sp_auth_meta+6], 0xffff
    je .out
    inc word [rel sp_auth_meta+6]      ; >=2 is ambiguous; never replace first
    jmp .out
.disable:
    mov byte [rel sp_ready], 0
.out:
    SP_RESTORE

; EAX=1..10 stage, EDX=closed outcome for route2/dispatch4/TX9 only.
; All caller registers/flags preserved. One bounded boot clock read and scalar
; RAM copies, no allocation, firmware, driver, packet, credential or policy IO.
; Stage9 may upgrade accepted to completed at the existing completion test.
service_progress_authstat_stage:
    SP_SAVE
    cmp byte [rel sp_auth_current], 1
    jne .out
    cmp byte [rel sp_ready], 1
    jne .out
%if RCQ_SERVICE_PROGRESS_SESSIONINFO
    cmp eax, 11
    je .session_projection
%endif
    cmp eax, 1
    jb .disable
    cmp eax, 10
    ja .disable
    mov ebx, eax
    mov r12d, edx
    movzx eax, word [rel sp_auth_meta]
    bt eax, ebx
    jc .upgrade
    cmp bl, [rel sp_auth_meta+5]
    jbe .disable
    call boot_ms_now
    sub rax, [rel sp_auth_meta+52]
    jc .disable
    mov edx, eax
    shr rax, 32
    jnz .disable
    movzx eax, byte [rel sp_auth_meta+5]
    lea rdi, [rel sp_auth_meta+8]
    cmp edx, [rdi+rax*4]
    jb .disable
    mov [rdi+rbx*4], edx
    bts word [rel sp_auth_meta], bx
    mov [rel sp_auth_meta+5], bl
    cmp ebx, 2
    je .route
    cmp ebx, 4
    je .dispatch
    cmp ebx, 9
    je .tx
    cmp ebx, 10
    jne .out
    mov byte [rel sp_auth_current], 0
    jmp .out
.upgrade:
    cmp ebx, 9
    jne .out
    cmp r12d, 3
    jne .out
    cmp byte [rel sp_auth_meta+4], 1
    jne .out
.tx:
%if RCQ_SERVICE_PROGRESS_PLAIN_AUTHSTAT
    cmp r12d, 2
    jne .plain_tx_done
    cmp byte [rel sp_plain+41], 0
    jne .plain_tx_done
    mov byte [rel sp_plain+41], 3        ; backend returned failure; no cause claim
.plain_tx_done:
%endif
    mov [rel sp_auth_meta+4], r12b
    jmp .out
.route:
    mov [rel sp_auth_meta+2], r12b
    jmp .out
.dispatch:
    mov [rel sp_auth_meta+3], r12b
    jmp .out
%if RCQ_SERVICE_PROGRESS_SESSIONINFO
.session_projection:
    ; Existing request-scoped semantic buffer selected by the actual reply path.
    ; Scalar only; never read or retain session text, nonce or credentials.
    test word [rel sp_auth_meta], 1<<7
    jz .disable
    cmp dword [rel sp_plain+132], 0
    jne .out
    call boot_ms_now
    sub rax, [rel sp_auth_meta+52]
    jc .disable
    mov edx, eax
    shr rax, 32
    jnz .disable
    cmp edx, [rel sp_auth_meta+8+7*4]
    jb .disable
    mov [rel sp_plain+136], edx
    mov dword [rel sp_plain+132], 1
    jmp .out
%endif
.disable:
    mov byte [rel sp_ready], 0
    mov byte [rel sp_auth_current], 0
.out:
    SP_RESTORE

%endif

%if RCQ_SERVICE_PROGRESS_AUTHSTAT || RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT
; Existing BSP entry only: rolling RAM baseline until first AUTHSTAT. After
; first checkpoint IO, sp_entered is rebased once, excluding our own write.
service_progress_authstat_enter:
    sub rsp, 8
    lea rdi, [rel sp_current]
    mov esi, 1
    call service_progress_sample
    cmp byte [rel sp_phase], 0
    jne .window
    mov rax, [rel sp_current]
    test rax, rax
    jz .disable
    lea rsi, [rel sp_current]
    lea rdi, [rel sp_entered]
    mov ecx, SP_SAMPLE/8
    rep movsq
    jmp .active
.window:
    call service_progress_authstat_finish
    cmp byte [rel sp_ready], 1
    jne .out
.active:
    mov byte [rel sp_active], 1
.out:
    add rsp, 8
    ret
.disable:
    mov byte [rel sp_ready], 0
    jmp .out

service_progress_authstat_exit:
    sub rsp, 8
%if SP_PRERX_WINDOW
    cmp qword [rel sp_prerx], 0         ; baseline only after completed STATUS
    je .out
%else
    cmp word [rel sp_auth_meta+SP_AUTH_MASK], 0
    je .out
%endif
    mov byte [rel sp_auth_current], 0   ; freeze at returned BSP poll boundary
    lea rdi, [rel sp_current]
    mov esi, 2
    call service_progress_sample
    cmp byte [rel sp_phase], 0
    jne .window
    mov rax, [rel sp_current]
    cmp rax, [rel sp_auth_meta+SP_AUTH_FIRST]
    jb .disable
    call service_progress_authstat_pair
    cmp byte [rel sp_ready], 1
    jne .out
    ; The only follow-up baseline is AFTER this checkpoint's own firmware IO.
    lea rdi, [rel sp_entered]
    mov esi, 1
    call service_progress_sample
    mov rax, [rel sp_entered]
    cmp rax, [rel sp_current]
    jb .disable
    mov [rel sp_previous], rax
%if SP_PRERX_WINDOW
    call service_progress_sessioninfo_rebase
%endif
    jmp .out
.window:
    call service_progress_authstat_finish
.out:
    add rsp, 8
    ret
.disable:
    mov byte [rel sp_ready], 0
    jmp .out

service_progress_authstat_finish:
    sub rsp, 8
    mov rax, [rel sp_current]
    cmp rax, [rel sp_previous]
    jb .disable
    mov [rel sp_previous], rax
    sub rax, [rel sp_entered]
    jc .disable
    cmp rax, 30000
    jb .out
    call service_progress_authstat_pair
.out:
    add rsp, 8
    ret
.disable:
    mov byte [rel sp_ready], 0
    jmp .out

service_progress_authstat_pair:
    sub rsp, 8
    lea rsi, [rel sp_entered]
    lea rdi, [rel sp_record+128]
    mov ecx, SP_SAMPLE/8
    rep movsq
    lea rsi, [rel sp_current]
    mov ecx, SP_SAMPLE/8
    rep movsq
%if SP_PRERX_WINDOW
    call service_progress_sessioninfo_prepare
%endif
    mov eax, SP_AUTH_KIND
    call service_progress_publish
    add rsp, 8
    ret
%endif

%if RCQ_SERVICE_PROGRESS_SESSIONINFO
; Canonical public client spelling +32 hexadecimal characters, bounded44B+NUL.
; This observes an exact request shape, not admission. No nonce bytes retained.
service_progress_sessioninfo_exact:
    cmp dword [rel udp_line], 'SESS'
    jne .no
    cmp dword [rel udp_line+4], 'IONI'
    jne .no
    cmp dword [rel udp_line+8], 'NFO '
    jne .no
    lea rdi, [rel udp_line+12]
    xor ecx, ecx
.loop:
    movzx eax, byte [rdi+rcx]
    cmp al, '0'
    jb .no
    cmp al, '9'
    jbe .next
    or al, 0x20
    cmp al, 'a'
    jb .no
    cmp al, 'f'
    ja .no
.next:
    inc ecx
    cmp ecx, 32
    jb .loop
    cmp byte [rdi+32], 0
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

%endif

%if SP_PRERX_WINDOW
; Existing publisher only. Before RX copy the still-live RAM history; afterwards
; preserve first-RX history exactly. No RX/tuple is invented for a no-RX record.
service_progress_sessioninfo_prepare:
%if RCQ_SERVICE_PROGRESS_PREJOB_AUTHSTAT
    mov dword [rel sp_plain], 'PJA1'
%else
    mov dword [rel sp_plain], 'SSN1'
%endif
    cmp qword [rel sp_plain+140], 0
    jne .armed
    mov rax, [rel sp_prerx]
    mov [rel sp_plain+140], rax
.armed:
    cmp word [rel sp_auth_meta], 0
    jne .out
    mov dword [rel sp_plain+44], 'PRX1'
    lea rsi, [rel sp_prerx]
    lea rdi, [rel sp_plain+48]
    mov ecx, 88/8
    rep movsq
.out:
    ret

; First baseline's fresh AFTER-IO clock is supplied in RAX. Rebase latest live
; boundaries (not counts or STATUS identity), so our own IO is not a pump gap.
; The explicit rebase timestamp prevents interpreting STATUS->RX as pure runtime.
service_progress_sessioninfo_rebase:
    cmp word [rel sp_auth_meta], 0
    jne .out
    mov [rel sp_plain+148], rax
    mov [rel sp_prerx_last], rax
    lea rdi, [rel sp_prerx]
    xor ecx, ecx
.loop:
    cmp dword [rdi+40+rcx*4], 0
    je .next
    mov [rdi+8+rcx*8], rax
.next:
    inc ecx
    cmp ecx, 4
    jb .loop
    mov dword [rel sp_prerx+80], 2     ; returned poll, equal-time rebased history
.out:
    ret
%endif

%if RCQ_SERVICE_PROGRESS_AUTHSTAT || RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT
align 2                           ; retained UTF16 variable name ABI
%endif
sp_var_name: dw 'P','a','O','S','S','e','r','v','i','c','e','P','r','o','g','r','e','s','s',0
sp_caller: db 'service-progress',0
%macro WDATA_svc_service_progress 0
alignb 8
sp_record: resb SP_SIZE
sp_entered: resb SP_SAMPLE
sp_previous: resb SP_SAMPLE
sp_current: resb SP_SAMPLE
sp_initialized: resb 1
sp_ready: resb 1
sp_phase: resb 1
sp_active: resb 1
sp_previous_valid: resb 1
%if RCQ_SERVICE_PROGRESS_AUTHSTAT || RCQ_SERVICE_PROGRESS_RMP1_AUTHSTAT
alignb 8
sp_auth_meta: resb 60
sp_auth_current: resb 1
%if RCQ_SERVICE_PROGRESS_PLAIN_AUTHSTAT
alignb 8
sp_plain: resb 160
%if RCQ_SERVICE_PROGRESS_PRERX
sp_prerx: resb 88
sp_prerx_last: resq 1
%if SP_PRERX_WINDOW
sp_session_slice_state: resb 1         ; 0 initial, 1 observed open, 2 returned
%endif
%endif
%endif
%if RCQ_SERVICE_PROGRESS_FIRST_START
alignb 8
sp_start: resb 160
sp_start_seen: resb 1
sp_start_pending: resb 1
%endif
%endif
%if RCQ_SERVICE_PROGRESS_POST_STATUS
alignb 8
sp_status_nonce: resb 16
sp_status_ms: resq 1
sp_status_seen: resb 1
sp_window_armed: resb 1
%endif
%endmacro
WDATA_BSS_DEFER WDATA_svc_service_progress
%endif
