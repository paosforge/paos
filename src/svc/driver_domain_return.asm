;; MODULE svc/driver_domain_return
;; LAYER 5
;; EXPORTS driver_domain_return_prepare, driver_domain_return_prepare_contained, driver_domain_return_prepare_s5, driver_return_branch, driver_return_verb_admit, driver_return_uncertain, driver_return_bn_owned, driver_return_bootnext_armed, driver_return_saved, driver_return_reset_admit, driver_return_admit_reason, driver_return_admit_blocker, driver_return_armed, driver_return_cmos_prior, driver_return_disarm, driver_return_contained_identity
;; IMPORTS boot/chainload, boot/serial, boot/boot_menu, hv/driver_domain_restart, svc/guest_restart_record, svc/guest_failure_record, hv/driver_domain_failure, hv/driver_domain_return, hv/driver_domain, hv/vmx, boot/header, boot/beacon, boot/boot_v2_handoff, boot/boot_v2_health, boot/nvram_access, core/build_id
;; CAPS
;; OWNER rc-boot-claude
;; CONTEXT: bsp_only
; Original post-ACK, pre-CLI boundary. VM owns exact STOP, terminal retirement
; and original deadlines. EAX0/1/2 permit the original reset; 3/4 refuse.
; Only UDP and the confirmed local desktop opt-in may accept fresh 5 for the contained platform-reset edge.
; One attempt per boot. Never reuse a cached observation after a new START.
; ROOT108522: a later call (a Shut Down that still failed, then restart or BOOT
; WIN) returns the first call's own safe result (0/1/2) only while the domain it
; observed is unchanged and still empty: same generation, START, state, terminal
; and release. No second STOP, yield or firmware write. Unsafe, budget, invalid
; or never-run first results keep refusing (3). Outcome 5 is never reusable.
; ROOT109558/109575: the boot's one attempt is never taken while a NON-domain
; guest is live. The first call admits first (one STOP and a bounded readback,
; VM's nd_return_guest_stop); an admit refusal returns 3 with the attempt still
; untaken, so a later reset retries the admit. Any final 3/4 then undoes the
; BootNext/CMOS override a reset verb armed for this reset (SEC109572 S2).
; rc-review109720 / SEC109734: each undo is verified (BootNext read back absent,
; the CMOS override read back equal to its prior) before its marker clears. An
; unconfirmed undo keeps its marker and its driver_return_uncertain bit; every
; reset entry re-runs that verified undo once, first, and is then admitted or
; refused as before. A reset that proceeds, or a refusal, with a bit still set is
; disclosed (reply text, rc, serial line); it is never blocked forever by it.
; The owner Shut down takes the unchanged body (ROOT109575 (2)): no reset follows.
driver_domain_return_prepare_s5:
    mov byte [rel driver_return_tried],0
    xor r11d,r11d
    jmp driver_domain_return_prepare.body
; SEC110010/110015/110859: UDP post-ACK and confirmed OWNER desktop only.
; VM alone proves containment. This initial STOP never reuses a cached5.
; SEC110893 permits a separate deliberate desktop read-only proof, below.
driver_domain_return_prepare_contained:
    call driver_return_cleanup
    mov r11d,1
    jmp driver_domain_return_prepare.body
driver_domain_return_prepare:
    call driver_return_cleanup
    xor r11d,r11d
.body:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    push r13
    push r14
    sub rsp,16
    mov r14d,r11d
    mov r13d,3
    mov byte [rel driver_return_branch],0
    mov byte [rel driver_return_admit_reason],0  ; describes this call only
    cmp byte [rel driver_return_once],0
    jne .again
    pushfq
    pop rax
    test eax,0x200                 ; never yield with interrupts excluded
    jz .unrun                      ; consumed and refused, as before
    call driver_return_reset_admit
    test eax,eax
    jnz .done                      ; live guest not retired: attempt untaken, no record
    mov byte [rel driver_return_once],1
    call nd_failure_run
    call nd_restart_run
    mov rax,[rel nd_return_sequence]
    mov [rsp],rax
    call nd_return_prepare
    call nd_failure_finish
    call nd_restart_finish
    cmp eax,4
    jbe .capture
    cmp eax,5
    jne .out
    cmp r14d,1
    jne .out                       ; generic callers map 5 to 3 plus verified undo
    mov rax,[rel nd_return_sequence]
    sub rax,[rsp]
    cmp rax,1
    jne .out                       ; this call must have produced one fresh record
    mov eax,5
.capture:
    mov r13d,eax
    lea rbx,[rel driver_return_bytes]
    mov rdi,rbx
    xor eax,eax
    mov ecx,256/8
    cld
    rep stosq
    mov rdi,rbx
    lea rsi,[rel nd_return_record]
    mov ecx,128/8
    rep movsq
    mov rax,0x0000314e5452444e
    cmp [rbx],rax
    jne .invalid
    cmp dword [rbx+8],1
    jne .invalid
    cmp dword [rbx+12],128
    jne .invalid
    cmp [rbx+44],r13d
    jne .invalid
    cmp dword [rbx+92],0
    jne .invalid
    lea eax,[r13-3]
    cmp eax,1
    ja .branch_done                ; +112 is diagnostic only on refused 3/4
    mov al,[rbx+112]
    mov [rel driver_return_branch],al
.branch_done:
    cmp r13d,2
    ja .first_kept
    mov [rel driver_return_first],r13b ; validated safe result of the boot's one attempt
.first_kept:
    ; Missing diagnostic evidence does not change independent reset safety.
    cmp byte [rel pbm_manager_launch],1
    jne .out
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .out
    test byte [rel pbm_flags],PBM_HF_MUTABLE_ATTEMPT
    jz .out
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne .out
    cmp byte [rel paos_build_state],BID_ST_MATCH
    jne .out
    mov r12,[rel runtime_services]
    test r12,r12
    jz .out
    mov rax,[rel boot_tsc_start]
    mov [rbx+128],rax
    mov eax,[rel boot_nonce]
    mov [rbx+136],eax
    mov rax,[rel pbm_manager_sequence]
    mov [rbx+144],rax
    mov rax,[rel pbm_attempt_nonce]
    mov [rbx+152],rax
    mov rax,[rel pbm_state_generation]
    mov [rbx+160],rax
    lea rdi,[rbx+168]
    lea rsi,[rel paos_build_measured]
    mov ecx,4
    rep movsq
    lea rsi,[rel pbm_payload_sha]
    mov ecx,4
    rep movsq
    mov al,[rel pbm_entry]
    mov [rbx+232],al
    mov byte [rbx+234],BID_ST_MATCH
    mov rdi,rbx
    mov esi,252
    call pbm_crc32
    mov [rbx+252],eax
    mov rdi,rbx
    call driver_return_wire_ok
    test eax,eax
    jz .out
    call driver_return_read
    mov rdx,0x800000000000000E
    cmp rax,rdx                    ; only confirmed NOT_FOUND is missing
    je .gate
    test rax,rax
    jnz .unknown
    cmp dword [rel driver_return_attrs],7
    jne .unknown
    cmp qword [rel driver_return_size],256
    jne .unknown
    lea rdi,[rel driver_return_verify]
    call driver_return_wire_ok
    test eax,eax
    jz .unknown                    ; preserve unknown existing diagnostic bytes
.gate:
    lea rdi,[rel driver_return_guid]
    lea rsi,[rel driver_return_name]
    xor edx,edx
    lea rcx,[rel driver_return_tag]
    call storage_access_nvram_require
    test rax,rax
    jnz .out
    lea rcx,[rel driver_return_name]
    lea rdx,[rel driver_return_guid]
    mov r8d,7
    mov r9d,256
    sub rsp,48                    ; aligned UEFI home space + fifth argument
    mov [rsp+32],rbx
    call [r12+0x58]
    add rsp,48
    test rax,rax
    jnz .unknown
    call driver_return_read
    test rax,rax
    jnz .unknown
    cmp dword [rel driver_return_attrs],7
    jne .unknown
    cmp qword [rel driver_return_size],256
    jne .unknown
    lea rdi,[rel driver_return_verify]
    mov rsi,rbx
    mov ecx,256/8
    cld
    repe cmpsq
    jne .unknown
    mov byte [rel driver_return_saved],1
.unknown:
    ; No erase, alternate variable, retry or second STOP after uncertainty.
.out:
    call guest_failure_save
    call guest_restart_save
.done:
    lea eax,[r13-3]
    cmp eax,1
    ja .result                     ; 0..2 ordinary reset, 5 contained reset; both retain one-shots
    call driver_return_disarm
.result:
    cmp byte [rel driver_return_uncertain],0
    je .ret
    lea rdi,[rel driver_return_uncertain_line]   ; SEC109734 (3.2): the log carries it
    call serial_string
.ret:
    mov eax,r13d
    add rsp,16
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret
.invalid:
    mov r13d,3
    jmp .out
.unrun:
    mov byte [rel driver_return_once],1
    jmp .out
.again:
    movzx eax,byte [rel driver_return_first]
    cmp eax,2
    ja .out
    lea rbx,[rel nd_return_record]
    cmp [rbx+44],eax
    jne .out
    cmp eax,1
    je .again_idle
    cmp dword [rbx+64],4               ; 0/2: retired, terminal and released
    jne .out
    cmp dword [rbx+68],1
    jne .out
    cmp dword [rbx+72],1
    jne .out
    jmp .again_live
.again_idle:
    cmp dword [rbx+64],0               ; 1: no domain (idle or preSTART failure)
    je .again_live
    cmp dword [rbx+64],5
    jne .out
.again_live:
    mov rcx,[rel nd_generation]        ; no new START since the observation
    cmp rcx,[rbx+16]
    jne .out
    mov ecx,[rel hv_linux_start_gen]
    cmp ecx,[rbx+80]
    jne .out
    mov ecx,[rel nd_state]
    cmp ecx,[rbx+64]
    jne .out
    mov ecx,[rel nd_terminal]
    cmp ecx,[rbx+68]
    jne .out
    mov ecx,[rel nd_released]
    cmp ecx,[rbx+72]
    jne .out
    call nd_return_empty               ; VM's exact empty CPU/RAM/region test, now
    test eax,eax
    jz .out
    movzx r13d,byte [rel driver_return_first]
    jmp .out

; SEC110893: identify the original validated5 for a later deliberate desktop
; action. This read is NOT current containment authority: the desktop must call
; VM's actual read-only proof/census afresh, including at its IF0 terminal edge.
; No STOP, record/sequence write, first-result cache or retry latch is created.
; EAX0/RDX original generation, otherwise EAX1. Boot-local record custody only.
driver_return_contained_identity:
    mov eax,1
    cmp byte [rel driver_return_once],1
    jne .out
    lea rdx,[rel driver_return_bytes]
    mov rcx,0x0000314e5452444e
    cmp [rdx],rcx
    jne .out
    cmp dword [rdx+8],1
    jne .out
    cmp dword [rdx+12],128
    jne .out
    cmp dword [rdx+44],5
    jne .out
    cmp dword [rdx+92],0
    jne .out
    cmp dword [rdx+64],6
    jne .out
    cmp dword [rdx+68],1
    jne .out
    cmp dword [rdx+72],0
    jne .out
    mov ecx,[rdx+40]
    cmp ecx,[rel nd_bdf]
    jne .out
    mov rdx,[rdx+16]
    cmp rdx,[rel nd_generation]
    jne .out
    xor eax,eax
.out:
    ret

; ROOT109558 (1): every reset entry admits first. EAX 0 continue (nothing live,
; stopped and read back empty, or the driver domain, which the attempt owns);
; 1 refuse: driver_return_admit_reason 3 (no STOP sent) or 4 (STOP sent, not read
; back in its bound), driver_return_admit_blocker = VM's EDX. Nothing is cached.
; Reset verbs (BOOT WIN/LINUX/override, UDP REBOOT): the verified cleanup retry,
; then the live-guest admit. EAX 0 admitted, 1 refused (reason 3/4).
driver_return_verb_admit:
    call driver_return_cleanup
    jmp driver_return_reset_admit

; SEC109848 (1)(3): the one step that records a verified BootNext arm, called by a
; reset verb only after its BootNext storage gate returned 0 AND its verified
; write succeeded. AX = the UINT16 written; DL = the exact intent that gate was
; passed. Owned value, intent and marker are set together; the arm supersedes its
; own uncertain bit (SEC109734). It writes memory only: every register survives.
driver_return_bootnext_armed:
    mov [rel driver_return_bn_owned],ax
    mov [rel driver_return_bn_intent],dl
    or byte [rel driver_return_armed],DRA_BOOTNEXT
    and byte [rel driver_return_uncertain],~DRA_BOOTNEXT
    ret

; SEC109734 (3.3): re-run the verified undo of every uncertain item, once per
; call. It never refuses by itself; driver_return_uncertain says what remains.
driver_return_cleanup:
    movzx eax,byte [rel driver_return_uncertain]
    mov [rel driver_return_tried],al
    jmp driver_return_undo_mask

driver_return_reset_admit:
    push rbx
    call nd_return_guest_stop
    mov ebx,eax
    xor eax,eax
    cmp ebx,2
    jbe .admitted
    mov byte [rel driver_return_admit_blocker],dl
    mov eax,4
    cmp ebx,4
    je .refused
    mov eax,3                      ; 3, or any value outside VM's ABI
.refused:
    mov byte [rel driver_return_admit_reason],al
    mov eax,1
    pop rbx
    ret
.admitted:
    mov byte [rel driver_return_admit_reason],0
    mov byte [rel driver_return_admit_blocker],0
    pop rbx
    ret

; SEC109572 S2: a refusal after a reset verb armed its one-shot leaves nothing
; armed. Only what that verb recorded is undone, each verified before its marker
; clears (rc-review109720, SEC109734): its BootNext read back absent, and the CMOS
; override read back equal to its prior byte. One delete/write and one verify per
; refusal: an item this call's cleanup already tried is not tried again.
driver_return_disarm:
    movzx eax,byte [rel driver_return_armed]
    movzx ecx,byte [rel driver_return_tried]
    not ecx
    and eax,ecx
driver_return_undo_mask:           ; AL = DRA_* items to undo
    push rbx
    mov ebx,eax
    test bl,DRA_BOOTNEXT
    jz .cmos
    call driver_return_bootnext_undo
.cmos:
    test bl,DRA_CMOS
    jz .none
    call driver_return_cmos_undo
.none:
    pop rbx
    ret

; SEC109734 (2): put the prior override byte back and read it back. DRA_CMOS
; clears only on equality. No CMOS I/O permitted (boot-constant, so the arm wrote
; nothing either) or a mismatch keeps it, uncertain. Only the override index.
driver_return_cmos_undo:
    call chainload_cmos_nvram_ok
    jne .uncertain
    mov dil,BM_CMOS_OVERRIDE
    movzx esi,byte [rel driver_return_cmos_prior]
    call chainload_cmos_wr
    mov dil,BM_CMOS_OVERRIDE
    call chainload_cmos_rd
    cmp al,[rel driver_return_cmos_prior]
    jne .uncertain
    and byte [rel driver_return_armed],~DRA_CMOS
    and byte [rel driver_return_uncertain],~DRA_CMOS
    xor eax,eax
    ret
.uncertain:
    or byte [rel driver_return_uncertain],DRA_CMOS
    mov eax,1
    ret

; rc-review109720: undo the BootNext a reset verb armed, verified. EAX 0: read
; back absent, so DRA_BOOTNEXT and its uncertain bit clear. EAX 1: unconfirmed;
; the marker and the uncertain bit stay. One delete, one verify. Only this boot's own armed
; UINT16 is ever deleted; a foreign, malformed or unreadable BootNext is left
; byte-for-byte untouched, and a delete status is never trusted without readback.
%macro DR_BOOTNEXT_READ 0
    mov qword [rel driver_return_bn_size],2
    mov word [rel driver_return_bn_readback],0xFFFF
    lea rcx,[rel driver_return_bn_name]
    lea rdx,[rel driver_return_global_guid]
    lea r8,[rel driver_return_bn_attrs]
    lea r9,[rel driver_return_bn_size]
    lea rax,[rel driver_return_bn_readback]
    mov [rsp+32],rax
    mov rax,[rel runtime_services]
    call [rax+0x48]                ; GetVariable(BootNext)
%endmacro
driver_return_bootnext_undo:
    push rbp
    mov rbp,rsp
    and rsp,-16
    sub rsp,48
    cmp qword [rel runtime_services],0
    je .unconfirmed
    DR_BOOTNEXT_READ
    mov rdx,DR_EFI_NOT_FOUND
    cmp rax,rdx
    je .absent
    test rax,rax
    jnz .unconfirmed               ; unreadable: never deleted blind
    cmp qword [rel driver_return_bn_size],2
    jne .unconfirmed
    movzx eax,word [rel driver_return_bn_readback]
    cmp ax,[rel driver_return_bn_owned]
    jne .unconfirmed               ; another value is foreign authority: untouched
    cmp byte [rel pbm_try_media],1
    je .unconfirmed                ; live Try media: no NV delete (as chainload's own clear)
    ; SEC109848: the storage gate on the constant (EFI_GLOBAL, BootNext) pair, with the
    ; intent the arm's own gate was passed, only after an equal readback, and only when
    ; that was SPECIAL. Any other recorded intent is unconfirmed with no call. EDX only:
    ; no request intent, owner or grant is set or read here. Audited under the tag.
    cmp byte [rel driver_return_bn_intent],SA_INTENT_SPECIAL
    jne .unconfirmed
    lea rdi,[rel driver_return_global_guid]
    lea rsi,[rel driver_return_bn_name]
    movzx edx,byte [rel driver_return_bn_intent]
    lea rcx,[rel driver_return_undo_tag]
    call storage_access_nvram_require
    test rax,rax
    jnz .unconfirmed               ; refused: nothing deleted, marker kept
    lea rcx,[rel driver_return_bn_name]
    lea rdx,[rel driver_return_global_guid]
    xor r8d,r8d
    xor r9d,r9d
    mov qword [rsp+32],0
    mov rax,[rel runtime_services]
    call [rax+0x58]                ; SetVariable(BootNext, size 0) deletes it
    DR_BOOTNEXT_READ               ; its status alone proves nothing
    mov rdx,DR_EFI_NOT_FOUND
    cmp rax,rdx
    jne .unconfirmed
.absent:
    and byte [rel driver_return_armed],~DRA_BOOTNEXT
    and byte [rel driver_return_uncertain],~DRA_BOOTNEXT
    mov byte [rel driver_return_bn_intent],0   ; SEC109848 (3): cleared with its marker
    xor eax,eax
    jmp .out
.unconfirmed:
    or byte [rel driver_return_uncertain],DRA_BOOTNEXT
    mov eax,1
.out:
    mov rsp,rbp
    pop rbp
    ret

; RDI=256B. Pure schema/CRC/full-identity validation before replacing a record.
; This diagnostic does not confer authority or certify actual OS return.
driver_return_wire_ok:
    push rbx
    mov rbx,rdi
    mov rax,0x0000314e5452444e
    cmp [rbx],rax
    jne .bad
    cmp dword [rbx+8],1
    jne .bad
    cmp dword [rbx+12],128
    jne .bad
    cmp dword [rbx+44],5
    ja .bad
    cmp dword [rbx+92],0
    jne .bad
    cmp qword [rbx+128],0
    je .bad
    cmp dword [rbx+140],0
    jne .bad
    cmp qword [rbx+144],0
    je .bad
    cmp qword [rbx+152],0
    je .bad
    cmp qword [rbx+160],0
    je .bad
    mov rax,[rbx+168]
    or rax,[rbx+176]
    or rax,[rbx+184]
    or rax,[rbx+192]
    jz .bad
    mov rax,[rbx+200]
    or rax,[rbx+208]
    or rax,[rbx+216]
    or rax,[rbx+224]
    jz .bad
    cmp byte [rbx+232],1
    jb .bad
    cmp byte [rbx+232],2
    ja .bad
    cmp word [rbx+233],0x0100
    jne .bad
    lea rdi,[rbx+235]
    mov ecx,17
    xor eax,eax
    cld
    repe scasb
    jne .bad
    mov rdi,rbx
    mov esi,252
    call pbm_crc32
    cmp eax,[rbx+252]
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

driver_return_read:
    mov qword [rel driver_return_size],256
    mov dword [rel driver_return_attrs],0
    lea rcx,[rel driver_return_name]
    lea rdx,[rel driver_return_guid]
    lea r8,[rel driver_return_attrs]
    lea r9,[rel driver_return_size]
    sub rsp,40
    lea rax,[rel driver_return_verify]
    mov [rsp+32],rax
    call [r12+0x48]
    add rsp,40
    ret

driver_return_guid: dd 0x7a965d12
    dw 0xc839,0x4a77
    db 0xb1,0xe2,0x90,0x6e,0xf7,0x24,0x43,0x8c
align 2
driver_return_name: dw 'P','a','O','S','D','r','i','v','e','r','D','o','m','a','i','n','R','e','t','u','r','n',0
driver_return_tag: db 'driver-domain-return',0
align 2
driver_return_uncertain_line: db 'driver_return: cleanup_uncertain=1 one-shot boot target may still be set',13,10,0
align 2
driver_return_bn_name: dw 'B','o','o','t','N','e','x','t',0
align 8
driver_return_global_guid: dd 0x8be4df61   ; EFI_GLOBAL_VARIABLE
    dw 0x93ca,0x11d2
    db 0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c
driver_return_undo_tag: db 'driver_return_undo',0
DRA_BOOTNEXT equ 1
DRA_CMOS     equ 2
DR_EFI_NOT_FOUND equ 0x800000000000000E
%include "core/abi/wdata.inc"
%macro WDATA_svc_driver_domain_return 0
driver_return_once: db 0
driver_return_saved: db 0
driver_return_branch: db 0           ; validated refused record's +112, else zero
driver_return_first: db 3             ; 0/1/2 only after a validated safe first attempt
driver_return_admit_reason: db 0      ; last admit: 0 admitted, 3 stop refused, 4 stop unverified
driver_return_admit_blocker: db 0     ; VM's first blocker for reason 3
driver_return_armed: db 0             ; DRA_* one-shot a reset verb armed for this reset
driver_return_cmos_prior: db 0        ; CMOS override byte before the verb wrote it
driver_return_uncertain: db 0         ; DRA_* items whose verified undo is unconfirmed (marker kept)
driver_return_tried: db 0             ; DRA_* items this prepare's cleanup already tried
driver_return_bn_intent: db 0         ; private (SEC109848): the arm's BootNext gate intent; two writers
align 2
driver_return_bn_owned: dw 0          ; the UINT16 this boot's reset verb armed and verified
driver_return_bn_readback: dw 0
align 8
driver_return_bn_size: dq 0
driver_return_bn_attrs: dd 0
align 8
driver_return_size: dq 0
driver_return_attrs: dd 0
align 8
driver_return_bytes: times 256 db 0
driver_return_verify: times 256 db 0
%endmacro
WDATA_DEFER WDATA_svc_driver_domain_return
