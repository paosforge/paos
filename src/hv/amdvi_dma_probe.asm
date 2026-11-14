;; MODULE hv/amdvi_dma_probe
;; LAYER 5
;; EXPORTS cmd_verb_amd_dmaviol, cmd_verb_amd_dmaviol_check, cmd_verb_amd_dmaviol4, cmd_verb_amd_dmaviol4_check, cmd_verb_amd_dmaviola, cmd_verb_amd_dmaviola_check
;; IMPORTS hv/amdvi, hv/amdvi_guest, hv/vtd, dev/blk/nvme, dev/blk/ahci, core/dma, svc/command
;; CAPS CAP_MMIO
;; OWNER rc-vm-claude
; Owner-authenticated DMAVIOL backend for AMD-Vi. It never changes a DTE,
; mapping, invalidation rule or device admission. The existing arena's final
; page is compat-carved and absent from DID2; only Identify Controller is sent.
; A full Identify pass requires 1..1024 fresh IO_PAGE_FAULT entries, each with the NVMe requester and
; exact target page, all4096 canary bytes unchanged, and the existing AMD event
; consumer accounting the complete validated batch. Missing/overflow/stale/ambiguous logs
; fail closed. This is not the Intel FRCD/DMAR capture path.

amdvi_dma_probe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov byte [rel amd_dma_valid],1
    mov byte [rel amd_dma_blocked],0
    mov byte [rel amd_dma_landed],1
    mov dword [rel amd_dma_delta],0
    mov dword [rel amd_dma_stage],1
    mov dword [rel amd_dma_nvme_status],0xFFFF
    mov qword [rel amd_dma_page],0
    mov qword [rel amd_dma_q0],0
    mov qword [rel amd_dma_q1],0
    cmp byte [rel amdvi_owned],1
    jne .fail
    cmp byte [rel amdvi_enabled],1
    jne .fail
    cmp byte [rel amdvi_guest_state],0
    jne .fail
    cmp byte [rel nvme_present],1
    jne .fail
    call amdvi_observation_binding
    test eax,eax
    jz .fail
    mov rax,[rel amdvi_mmio]
    cmp rax,[rel amdvi_obs_mmio]
    jne .fail
    mov rax,[rel amdvi_evtlog]
    cmp rax,[rel amdvi_obs_log]
    jne .fail
    call amdvi_observation_generation
    test rax,rax
    jz .fail
    mov [rel amd_dma_generation],rax
    mov rbx,[rel amdvi_mmio]
    mov eax,[rbx+AMDVI_R_CTRL]
    and eax,AMDVI_CTRL_EN|AMDVI_CTRL_EVTLOG|AMDVI_CTRL_CMDBUF
    cmp eax,AMDVI_CTRL_EN|AMDVI_CTRL_EVTLOG|AMDVI_CTRL_CMDBUF
    jne .fail

    ; Bind to the controller the real Identify seam actually uses, not the
    ; first NVMe-class inventory item. Reject non-native or reassigned DTEs.
    mov r14d,[rel nvme_busno]
    cmp r14d,255
    ja .fail
    shl r14d,8
    mov eax,[rel nvme_devno]
    cmp eax,31
    ja .fail
    shl eax,3
    or r14d,eax
    mov eax,[rel nvme_fn]
    cmp eax,7
    ja .fail
    or r14d,eax
    mov [rel amd_dma_bdf],r14d
    mov rdx,[rel amdvi_devtab]
    test rdx,rdx
    jz .fail
    mov eax,r14d
    shl eax,5
    add rdx,rax
    mov rax,[rel amdvi_native_qw0]
    cmp [rdx],rax
    jne .fail
    cmp qword [rdx+8],AMDVI_DOM_NATIVE
    jne .fail
    mov dword [rel amd_dma_stage],2

    mov r13,[rel amdvi_pool]
    add r13,AMDVI_POOL_PAGES*4096
    jc .fail
    test r13,r13
    jz .fail
    test r13,4095
    jnz .fail
    mov rdi,r13
    call dma_virt_to_phys
    cmp rax,r13
    jne .fail
    mov rdi,r13
    call amdvi_native_leaf_ptr
    test rax,rax
    jnz .fail
    mov [rel amd_dma_page],r13
    call amdvi_dma_ring_snapshot
    test eax,eax
    jz .fail
    cmp rdx,rcx
    jne .fail                         ; never discard an unrelated stale event
    mov [rel amd_dma_head],edx
    mov eax,[rel amdvi_events]
    cmp eax,-1
    je .fail
    mov [rel amd_dma_before],eax
    mov dword [rel amd_dma_stage],3

    rdtsc
    shl rdx,32
    or rax,rdx
    xor rax,[rel amd_dma_nonce]
    mov rdx,0x9E3779B97F4A7C15
    xor rax,rdx
    jnz .sentinel
    mov rax,rdx
.sentinel:
    mov [rel amd_dma_canary],rax
    mov rdi,r13
    mov ecx,4096/8
    cld
    rep stosq
    call amdvi_dma_flush_canary
    mov dword [rel amd_dma_stage],4
    mov rdi,r13
    mov esi,0xD112
    call nvme_identify_dma_to
    mov [rel amd_dma_nvme_status],eax
    mov dword [rel amd_dma_stage],5
    call amdvi_dma_canary_ok
    test eax,eax
    jz .fail
    mov byte [rel amd_dma_landed],0
    ; Successful/absent/foreign CQ is not a denied DMA completion.
    cmp dword [rel amd_dma_nvme_status],0
    je .fail
    cmp dword [rel amd_dma_nvme_status],0x8000
    jae .fail

    ; The event tail can lag a device completion. Poll a finite bound; an
    ; emulator which never logs faults cannot receive a containment pass.
    mov r15d,AMDVI_WAIT_SPINS
.wait:
    call amdvi_dma_ring_snapshot
    test eax,eax
    jz .fail
    cmp edx,[rel amd_dma_head]
    jne .fail
    cmp rdx,rcx
    jne .event
    pause
    dec r15d
    jnz .wait
    jmp .fail
.event:
    ; One command can be split into 1024 denied 4-byte translations. Validate
    ; every published entry; never turn overflow or a summary into evidence.
    mov r12d,ecx                       ; stable final tail, across calls
    mov r15d,ecx
    sub r15d,edx
    and r15d,AMDVI_EVT_MASK
    shr r15d,4
    cmp r15d,1024
    ja .fail
    mov eax,[rel amd_dma_before]
    add eax,r15d
    jc .fail                          ; no wrapped legacy event accounting
    mov rsi,[rel amdvi_evtlog]
    mfence
    mov rax,[rsi+rdx]
    mov [rel amd_dma_q0],rax
    mov rax,[rsi+rdx+8]
    mov [rel amd_dma_q1],rax
.validate:
    mov rax,[rsi+rdx]
    mov r8,rax
    shr rax,60
    cmp eax,2                         ; exact IO_PAGE_FAULT, not unknown detail
    jne .fail
    movzx eax,r8w
    cmp eax,r14d
    jne .fail
    mov rax,[rsi+rdx+8]
    and rax,-4096
    cmp rax,r13                       ; every address in the denied owned page
    jne .fail
    add edx,16
    and edx,AMDVI_EVT_MASK
    cmp edx,r12d
    jne .validate
    call amdvi_observation_generation
    cmp rax,[rel amd_dma_generation]
    jne .fail
    call amdvi_dma_ring_snapshot
    test eax,eax
    jz .fail
    cmp edx,[rel amd_dma_head]
    jne .fail
    cmp ecx,r12d
    jne .fail                         ; no unvalidated arrival may be consumed
    mov dword [rel amd_dma_stage],6
    call amdvi_event_check             ; original authority/unknown-loss observer
    cmp eax,r15d
    jne .fail
    mov eax,[rel amdvi_events]
    sub eax,[rel amd_dma_before]
    cmp eax,r15d
    jne .fail
    mov [rel amd_dma_delta],eax
    call amdvi_dma_ring_snapshot
    test eax,eax
    jz .fail
    cmp rdx,rcx
    jne .fail
    call amdvi_observation_generation
    cmp rax,[rel amd_dma_generation]
    jne .fail
    call amdvi_dma_canary_ok
    test eax,eax
    jz .fail
    mov byte [rel amd_dma_blocked],1
    mov dword [rel amd_dma_stage],7
    mov eax,1
    jmp .out
.fail:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Full-width cursors; reserved, unaligned, out-of-ring and overflow all refuse.
; No cursor/status writes here. RDX=head, RCX=tail, EAX=valid.
amdvi_dma_ring_snapshot:
    mov rax,[rel amdvi_mmio]
    mov rdx,[rax+AMDVI_R_EVT_HEAD]
    mov rcx,[rax+AMDVI_R_EVT_TAIL]
    cmp rdx,AMDVI_EVT_MASK
    ja .no
    cmp rcx,AMDVI_EVT_MASK
    ja .no
    test dl,15
    jnz .no
    test cl,15
    jnz .no
    test dword [rax+AMDVI_R_STATUS],AMDVI_STS_EVT_OVF
    jnz .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

amdvi_dma_flush_canary:
    mov rdi,[rel amd_dma_page]
    mov ecx,4096/64
.flush:
    clflush [rdi]
    add rdi,64
    dec ecx
    jnz .flush
    mfence
    ret

; Both initial result and same-nonce CHECK reload the entire page from memory.
amdvi_dma_canary_ok:
    cmp qword [rel amd_dma_page],0
    je .no
    call amdvi_dma_flush_canary
    mov rsi,[rel amd_dma_page]
    mov rax,[rel amd_dma_canary]
    mov ecx,4096/8
.check:
    cmp [rsi],rax
    jne .no
    add rsi,8
    dec ecx
    jnz .check
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

cmd_verb_amd_dmaviol:
    push rbx
    push r12
    call cmd_handler_prologue
    mov r12,rsi
    mov rbx,[rdi+REQ_ARG]
    mov [r12+RSP_VAL],rbx
    mov rdi,rbx
    call vtd_copy_nonce
    test eax,eax
    jz .bad_nonce
    lea rsi,[rel vtd_nonce]
    lea rdi,[rel amd_dma_nonce]
    mov ecx,8
    cld
    rep movsq
    call amdvi_dma_probe
    call vtd_out_reset
    lea rdi,[rel str_amd_dma_head]
    call vtd_out_str
    lea rdi,[rel amd_dma_nonce]
    call vtd_out_str
    cmp byte [rel amd_dma_blocked],1
    jne .failed
    lea rdi,[rel str_amd_dma_blocked]
    call vtd_out_str
    mov edi,[rel amd_dma_delta]
    call vtd_out_dec
    lea rdi,[rel str_amd_dma_blocked_tail]
    call vtd_out_str
    jmp .ready
.failed:
    lea rdi,[rel str_amd_dma_failed]
    call vtd_out_str
    mov edi,[rel amd_dma_delta]
    call vtd_out_dec
    lea rdi,[rel str_amd_dma_stage]
    call vtd_out_str
    mov edi,[rel amd_dma_stage]
    call vtd_out_dec
    lea rdi,[rel str_amd_dma_landed]
    call vtd_out_str
    movzx edi,byte [rel amd_dma_landed]
    call vtd_out_dec
    lea rdi,[rel str_amd_dma_status]
    call vtd_out_str
    mov edi,[rel amd_dma_nvme_status]
    call vtd_out_dec
    lea rdi,[rel str_amd_dma_q0]
    call vtd_out_str
    mov rdi,[rel amd_dma_q0]
    call vtd_out_hex_compact
    lea rdi,[rel str_amd_dma_q1]
    call vtd_out_str
    mov rdi,[rel amd_dma_q1]
    call vtd_out_hex_compact
    lea rdi,[rel str_amd_dma_eol]
    call vtd_out_str
    jmp .ready
.bad_nonce:
    call vtd_out_reset
    lea rdi,[rel str_amd_dma_bad_nonce]
    call vtd_out_str
.ready:
    mov byte [rel vtd_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    pop r12
    pop rbx
    ret

cmd_verb_amd_dmaviol_check:
    push rbx
    push r12
    call cmd_handler_prologue
    mov r12,rsi
    mov rbx,[rdi+REQ_ARG]
    mov [r12+RSP_VAL],rbx
    mov rdi,rbx
    call vtd_copy_nonce
    test eax,eax
    jz .bad_nonce
    lea rdi,[rel vtd_nonce]
    lea rsi,[rel amd_dma_nonce]
    call strcmp
    test rax,rax
    jnz .stale
    cmp byte [rel amd_dma_valid],1
    jne .stale
    ; Retained bytes/nonce are historical evidence, not current ownership.
    ; Match the bounded4 CHECK seam before any old-page read or result update.
    call amdvi_observation_binding
    test eax,eax
    jz .stale
    call amdvi_observation_generation
    cmp rax,[rel amd_dma_generation]
    jne .stale
    cmp byte [rel amd_dma_blocked],1
    jne .render
    call amdvi_dma_canary_ok
    test eax,eax
    jnz .render
    mov byte [rel amd_dma_blocked],0
    mov byte [rel amd_dma_landed],1
.render:
    call vtd_out_reset
    lea rdi,[rel str_amd_dma_check]
    call vtd_out_str
    lea rdi,[rel amd_dma_nonce]
    call vtd_out_str
    lea rdi,[rel str_amd_dma_landed]
    call vtd_out_str
    movzx edi,byte [rel amd_dma_landed]
    call vtd_out_dec
    lea rdi,[rel str_amd_dma_check_failed]
    cmp byte [rel amd_dma_blocked],1
    jne .verdict
    lea rdi,[rel str_amd_dma_check_blocked]
.verdict:
    call vtd_out_str
    jmp .ready
.stale:
    call vtd_out_reset
    lea rdi,[rel str_amd_dma_stale]
    call vtd_out_str
    jmp .ready
.bad_nonce:
    call vtd_out_reset
    lea rdi,[rel str_amd_dma_bad_check]
    call vtd_out_str
.ready:
    mov byte [rel vtd_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    pop r12
    pop rbx
    ret

str_amd_dma_head: db " DMAVIOL nonce=",0
str_amd_dma_blocked: db " VERDICT=BLOCKED source=ivrs fault_delta=",0
str_amd_dma_blocked_tail: db " landed=0",13,10,0
str_amd_dma_failed: db " VERDICT=FAILED source=ivrs fault_delta=",0
str_amd_dma_stage: db " stage=",0
str_amd_dma_landed: db " landed=",0
str_amd_dma_status: db " nvme_status=",0
str_amd_dma_q0: db " event_q0=0x",0
str_amd_dma_q1: db " event_q1=0x",0
str_amd_dma_eol: db 13,10,0
str_amd_dma_bad_nonce: db " DMAVIOL ERR bad_nonce",13,10,0
str_amd_dma_check: db " DMAVIOL_CHECK nonce=",0
str_amd_dma_check_blocked: db " VERDICT=BLOCKED source=ivrs",13,10,0
str_amd_dma_check_failed: db " VERDICT=FAILED source=ivrs",13,10,0
str_amd_dma_stale: db " DMAVIOL_CHECK landed=1 VERDICT=STALE source=ivrs",13,10,0
str_amd_dma_bad_check: db " DMAVIOL_CHECK ERR bad_nonce",13,10,0

%macro WDATA_hv_amdvi_dma_probe 0
align 8
amd_dma_page: resq 1
amd_dma_canary: resq 1
amd_dma_q0: resq 1
amd_dma_q1: resq 1
amd_dma_generation: resq 1
amd_dma_before: resd 1
amd_dma_head: resd 1
amd_dma_bdf: resd 1
amd_dma_nvme_status: resd 1
amd_dma_delta: resd 1
amd_dma_stage: resd 1
amd_dma_landed: resb 1
amd_dma_blocked: resb 1
amd_dma_valid: resb 1
amd_dma_nonce: resb 64
%endmacro
WDATA_BSS_DEFER WDATA_hv_amdvi_dma_probe

; Distinct bounded4B entry and private record. The original Identify entry,
; its record, and its strict overflow refusal above remain unchanged.
amdvi_dma4_probe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov byte [rel amd_dma4_valid],1
    mov byte [rel amd_dma4_blocked],0
    mov byte [rel amd_dma4_landed],1
    mov dword [rel amd_dma4_delta],0
    mov dword [rel amd_dma4_stage],1
    mov dword [rel amd_dma4_nvme_status],0xFFFF
    mov qword [rel amd_dma4_page],0
    mov qword [rel amd_dma4_q0],0
    mov qword [rel amd_dma4_q1],0
    cmp byte [rel amdvi_owned],1
    jne .fail
    cmp byte [rel amdvi_enabled],1
    jne .fail
    cmp byte [rel amdvi_guest_state],0
    jne .fail
    cmp byte [rel nvme_present],1
    jne .fail
    call amdvi_observation_binding
    test eax,eax
    jz .fail
    mov rax,[rel amdvi_mmio]
    cmp rax,[rel amdvi_obs_mmio]
    jne .fail
    mov rax,[rel amdvi_evtlog]
    cmp rax,[rel amdvi_obs_log]
    jne .fail
    call amdvi_observation_generation
    test rax,rax
    jz .fail
    mov [rel amd_dma4_generation],rax
    mov rbx,[rel amdvi_mmio]
    mov eax,[rbx+AMDVI_R_CTRL]
    and eax,AMDVI_CTRL_EN|AMDVI_CTRL_EVTLOG|AMDVI_CTRL_CMDBUF
    cmp eax,AMDVI_CTRL_EN|AMDVI_CTRL_EVTLOG|AMDVI_CTRL_CMDBUF
    jne .fail

    ; Bind to the controller the real NVMe admin seam actually uses, not the
    ; first NVMe-class inventory item. Reject non-native or reassigned DTEs.
    mov r14d,[rel nvme_busno]
    cmp r14d,255
    ja .fail
    shl r14d,8
    mov eax,[rel nvme_devno]
    cmp eax,31
    ja .fail
    shl eax,3
    or r14d,eax
    mov eax,[rel nvme_fn]
    cmp eax,7
    ja .fail
    or r14d,eax
    mov [rel amd_dma4_bdf],r14d
    mov rdx,[rel amdvi_devtab]
    test rdx,rdx
    jz .fail
    mov eax,r14d
    shl eax,5
    add rdx,rax
    mov rax,[rel amdvi_native_qw0]
    cmp [rdx],rax
    jne .fail
    cmp qword [rdx+8],AMDVI_DOM_NATIVE
    jne .fail
    mov dword [rel amd_dma4_stage],2

    mov r13,[rel amdvi_pool]
    add r13,AMDVI_POOL_PAGES*4096
    jc .fail
    test r13,r13
    jz .fail
    test r13,4095
    jnz .fail
    mov rdi,r13
    call dma_virt_to_phys
    cmp rax,r13
    jne .fail
    mov rdi,r13
    call amdvi_native_leaf_ptr
    test rax,rax
    jnz .fail
    mov [rel amd_dma4_page],r13
    call amdvi_dma4_ring_snapshot
    test eax,eax
    jz .fail
    cmp rdx,rcx
    jne .fail                         ; never discard an unrelated stale event
    mov [rel amd_dma4_head],edx
    mov eax,[rel amdvi_events]
    cmp eax,-1
    je .fail
    mov [rel amd_dma4_before],eax
    mov dword [rel amd_dma4_stage],3

    rdtsc
    shl rdx,32
    or rax,rdx
    xor rax,[rel amd_dma4_nonce]
    mov rdx,0x9E3779B97F4A7C15
    xor rax,rdx
    jnz .sentinel
    mov rax,rdx
.sentinel:
    mov [rel amd_dma4_canary],rax
    mov rdi,r13
    mov ecx,4096/8
    cld
    rep stosq
    call amdvi_dma4_flush_canary
    mov dword [rel amd_dma4_stage],4
    mov rdi,r13
    call nvme_get_log_error4_dma_to
    mov [rel amd_dma4_nvme_status],eax
    mov dword [rel amd_dma4_stage],5
    call amdvi_dma4_canary_ok
    test eax,eax
    jz .fail
    mov byte [rel amd_dma4_landed],0
    ; The CQ status is recorded, not graded: the log data reaches memory as a
    ; posted write, so a controller whose write AMD-Vi blocked still completes
    ; with success on real hardware (Reatan 0.0.248). Only the fault event
    ; below proves the block. A driver timeout, refusal or poison sentinel
    ; (>= 0x8000) is no real completion and never BLOCKED.
    cmp dword [rel amd_dma4_nvme_status],0x8000
    jae .fail

    ; The event tail can lag a device completion. Poll a finite bound; an
    ; emulator which never logs faults cannot receive a containment pass.
    mov r15d,AMDVI_WAIT_SPINS
.wait:
    call amdvi_dma4_ring_snapshot
    test eax,eax
    jz .fail
    cmp edx,[rel amd_dma4_head]
    jne .fail
    cmp rdx,rcx
    jne .event
    pause
    dec r15d
    jnz .wait
    jmp .fail
.event:
    mov eax,edx
    add eax,16
    and eax,AMDVI_EVT_MASK
    cmp eax,ecx
    jne .fail                         ; exactly one fresh event, not a batch
    mov rsi,[rel amdvi_evtlog]
    mfence
    mov r12,[rsi+rdx]
    mov r15,[rsi+rdx+8]
    mov [rel amd_dma4_q0],r12
    mov [rel amd_dma4_q1],r15
    mov rax,r12
    shr rax,60
    cmp eax,2                          ; IO_PAGE_FAULT, never an unknown summary
    jne .fail
    movzx eax,r12w
    cmp eax,r14d                       ; actual NVMe DeviceID
    jne .fail
    cmp r15,r13
    jne .fail
    call amdvi_observation_generation
    cmp rax,[rel amd_dma4_generation]
    jne .fail
    mov dword [rel amd_dma4_stage],6
    call amdvi_event_check             ; original consumer also publishes AMD witness
    cmp eax,1
    jne .fail
    mov eax,[rel amdvi_events]
    sub eax,[rel amd_dma4_before]
    cmp eax,1
    jne .fail
    mov [rel amd_dma4_delta],eax
    call amdvi_dma4_ring_snapshot
    test eax,eax
    jz .fail
    cmp rdx,rcx
    jne .fail
    mov byte [rel amd_dma4_blocked],1
    mov dword [rel amd_dma4_stage],7
    mov eax,1
    jmp .out
.fail:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Full-width cursors; reserved, unaligned, out-of-ring and overflow all refuse.
; No cursor/status writes here. RDX=head, RCX=tail, EAX=valid.
amdvi_dma4_ring_snapshot:
    mov rax,[rel amdvi_mmio]
    mov rdx,[rax+AMDVI_R_EVT_HEAD]
    mov rcx,[rax+AMDVI_R_EVT_TAIL]
    cmp rdx,AMDVI_EVT_MASK
    ja .no
    cmp rcx,AMDVI_EVT_MASK
    ja .no
    test dl,15
    jnz .no
    test cl,15
    jnz .no
    test dword [rax+AMDVI_R_STATUS],AMDVI_STS_EVT_OVF
    jnz .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

amdvi_dma4_flush_canary:
    mov rdi,[rel amd_dma4_page]
    mov ecx,4096/64
.flush:
    clflush [rdi]
    add rdi,64
    dec ecx
    jnz .flush
    mfence
    ret

; Both initial result and same-nonce CHECK reload the entire page from memory.
amdvi_dma4_canary_ok:
    cmp qword [rel amd_dma4_page],0
    je .no
    call amdvi_dma4_flush_canary
    mov rsi,[rel amd_dma4_page]
    mov rax,[rel amd_dma4_canary]
    mov ecx,4096/8
.check:
    cmp [rsi],rax
    jne .no
    add rsi,8
    dec ecx
    jnz .check
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

cmd_verb_amd_dmaviol4:
    push rbx
    push r12
    call cmd_handler_prologue
    mov r12,rsi
    mov rbx,[rdi+REQ_ARG]
    mov [r12+RSP_VAL],rbx
    mov rdi,rbx
    call vtd_copy_nonce
    test eax,eax
    jz .bad_nonce
    lea rsi,[rel vtd_nonce]
    lea rdi,[rel amd_dma4_nonce]
    mov ecx,8
    cld
    rep movsq
    call amdvi_dma4_probe
    call vtd_out_reset
    lea rdi,[rel str_amd_dma4_head]
    call vtd_out_str
    lea rdi,[rel amd_dma4_nonce]
    call vtd_out_str
    cmp byte [rel amd_dma4_blocked],1
    jne .failed
    lea rdi,[rel str_amd_dma4_blocked]
    call vtd_out_str
    jmp .ready
.failed:
    lea rdi,[rel str_amd_dma4_failed]
    call vtd_out_str
    mov edi,[rel amd_dma4_delta]
    call vtd_out_dec
    lea rdi,[rel str_amd_dma4_stage]
    call vtd_out_str
    mov edi,[rel amd_dma4_stage]
    call vtd_out_dec
    lea rdi,[rel str_amd_dma4_landed]
    call vtd_out_str
    movzx edi,byte [rel amd_dma4_landed]
    call vtd_out_dec
    lea rdi,[rel str_amd_dma4_status]
    call vtd_out_str
    mov edi,[rel amd_dma4_nvme_status]
    call vtd_out_dec
    lea rdi,[rel str_amd_dma4_q0]
    call vtd_out_str
    mov rdi,[rel amd_dma4_q0]
    call vtd_out_hex_compact
    lea rdi,[rel str_amd_dma4_q1]
    call vtd_out_str
    mov rdi,[rel amd_dma4_q1]
    call vtd_out_hex_compact
    lea rdi,[rel str_amd_dma4_eol]
    call vtd_out_str
    jmp .ready
.bad_nonce:
    call vtd_out_reset
    lea rdi,[rel str_amd_dma4_bad_nonce]
    call vtd_out_str
.ready:
    mov byte [rel vtd_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    pop r12
    pop rbx
    ret

cmd_verb_amd_dmaviol4_check:
    push rbx
    push r12
    call cmd_handler_prologue
    mov r12,rsi
    mov rbx,[rdi+REQ_ARG]
    mov [r12+RSP_VAL],rbx
    mov rdi,rbx
    call vtd_copy_nonce
    test eax,eax
    jz .bad_nonce
    lea rdi,[rel vtd_nonce]
    lea rsi,[rel amd_dma4_nonce]
    call strcmp
    test rax,rax
    jnz .stale
    cmp byte [rel amd_dma4_valid],1
    jne .stale
    call amdvi_observation_binding
    test eax,eax
    jz .stale
    call amdvi_observation_generation
    cmp rax,[rel amd_dma4_generation]
    jne .stale
    cmp byte [rel amd_dma4_blocked],1
    jne .render
    call amdvi_dma4_canary_ok
    test eax,eax
    jnz .render
    mov byte [rel amd_dma4_blocked],0
    mov byte [rel amd_dma4_landed],1
.render:
    call vtd_out_reset
    lea rdi,[rel str_amd_dma4_check]
    call vtd_out_str
    lea rdi,[rel amd_dma4_nonce]
    call vtd_out_str
    lea rdi,[rel str_amd_dma4_landed]
    call vtd_out_str
    movzx edi,byte [rel amd_dma4_landed]
    call vtd_out_dec
    lea rdi,[rel str_amd_dma4_check_failed]
    cmp byte [rel amd_dma4_blocked],1
    jne .verdict
    lea rdi,[rel str_amd_dma4_check_blocked]
.verdict:
    call vtd_out_str
    jmp .ready
.stale:
    call vtd_out_reset
    lea rdi,[rel str_amd_dma4_stale]
    call vtd_out_str
    jmp .ready
.bad_nonce:
    call vtd_out_reset
    lea rdi,[rel str_amd_dma4_bad_check]
    call vtd_out_str
.ready:
    mov byte [rel vtd_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    pop r12
    pop rbx
    ret

str_amd_dma4_head: db " DMAVIOL4 nonce=",0
str_amd_dma4_blocked: db " VERDICT=BLOCKED source=ivrs fault_delta=1 landed=0",13,10,0
str_amd_dma4_failed: db " VERDICT=FAILED source=ivrs fault_delta=",0
str_amd_dma4_stage: db " stage=",0
str_amd_dma4_landed: db " landed=",0
str_amd_dma4_status: db " nvme_status=",0
str_amd_dma4_q0: db " event_q0=0x",0
str_amd_dma4_q1: db " event_q1=0x",0
str_amd_dma4_eol: db 13,10,0
str_amd_dma4_bad_nonce: db " DMAVIOL4 ERR bad_nonce",13,10,0
str_amd_dma4_check: db " DMAVIOL4_CHECK nonce=",0
str_amd_dma4_check_blocked: db " VERDICT=BLOCKED source=ivrs",13,10,0
str_amd_dma4_check_failed: db " VERDICT=FAILED source=ivrs",13,10,0
str_amd_dma4_stale: db " DMAVIOL4_CHECK landed=1 VERDICT=STALE source=ivrs",13,10,0
str_amd_dma4_bad_check: db " DMAVIOL4_CHECK ERR bad_nonce",13,10,0

%macro WDATA_hv_amdvi_dma4_probe 0
align 8
amd_dma4_page: resq 1
amd_dma4_canary: resq 1
amd_dma4_q0: resq 1
amd_dma4_q1: resq 1
amd_dma4_generation: resq 1
amd_dma4_before: resd 1
amd_dma4_head: resd 1
amd_dma4_bdf: resd 1
amd_dma4_nvme_status: resd 1
amd_dma4_delta: resd 1
amd_dma4_stage: resd 1
amd_dma4_landed: resb 1
amd_dma4_blocked: resb 1
amd_dma4_valid: resb 1
amd_dma4_nonce: resb 64
%endmacro
WDATA_BSS_DEFER WDATA_hv_amdvi_dma4_probe

; T1-4 AHCI twin of the bounded challenge, for an AMD target whose only native
; storage requester is SATA (HP 02:00.1). One read-only IDENTIFY DEVICE (512 B)
; through ahci_identify_dma_to, its PRDT at the same compat-carved page. A
; 512 B data write may reach the IOMMU as several TLPs, so 1..AMDVI_DMAA_MAX
; fresh IO_PAGE_FAULT entries are accepted, every one validated (type, AHCI
; DeviceID, address inside the denied page). The HBA completion is recorded,
; not graded: an emulator may complete IDENTIFY after a denied write, and real
; hardware may stop the port (recovered by the driver). A poisoned port is
; never BLOCKED. The canary page is shared with DMAVIOL/DMAVIOL4: CHECK only
; vouches for the latest probe that wrote it.
AMDVI_DMAA_MAX     equ 64
AMDVI_DMAA_SETTLE  equ 4096
amdvi_dmaa_probe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov byte [rel amd_dmaa_valid],1
    mov byte [rel amd_dmaa_blocked],0
    mov byte [rel amd_dmaa_landed],1
    mov dword [rel amd_dmaa_delta],0
    mov dword [rel amd_dmaa_stage],1
    mov dword [rel amd_dmaa_ahci_status],0xFFFF
    mov qword [rel amd_dmaa_page],0
    mov qword [rel amd_dmaa_q0],0
    mov qword [rel amd_dmaa_q1],0
    cmp byte [rel amdvi_owned],1
    jne .fail
    cmp byte [rel amdvi_enabled],1
    jne .fail
    cmp byte [rel amdvi_guest_state],0
    jne .fail
    cmp byte [rel ahci_present],1
    jne .fail
    cmp byte [rel ahci_vmd_child],0
    jne .fail                         ; a VMD child is not its own requester
    call amdvi_observation_binding
    test eax,eax
    jz .fail
    mov rax,[rel amdvi_mmio]
    cmp rax,[rel amdvi_obs_mmio]
    jne .fail
    mov rax,[rel amdvi_evtlog]
    cmp rax,[rel amdvi_obs_log]
    jne .fail
    call amdvi_observation_generation
    test rax,rax
    jz .fail
    mov [rel amd_dmaa_generation],rax
    mov rbx,[rel amdvi_mmio]
    mov eax,[rbx+AMDVI_R_CTRL]
    and eax,AMDVI_CTRL_EN|AMDVI_CTRL_EVTLOG|AMDVI_CTRL_CMDBUF
    cmp eax,AMDVI_CTRL_EN|AMDVI_CTRL_EVTLOG|AMDVI_CTRL_CMDBUF
    jne .fail

    ; Bind to the HBA the AHCI backend actually drives. Reject non-native or
    ; reassigned DTEs.
    mov r14d,[rel ahci_busno]
    cmp r14d,255
    ja .fail
    shl r14d,8
    mov eax,[rel ahci_devno]
    cmp eax,31
    ja .fail
    shl eax,3
    or r14d,eax
    mov eax,[rel ahci_fn]
    cmp eax,7
    ja .fail
    or r14d,eax
    mov [rel amd_dmaa_bdf],r14d
    mov rdx,[rel amdvi_devtab]
    test rdx,rdx
    jz .fail
    mov eax,r14d
    shl eax,5
    add rdx,rax
    mov rax,[rel amdvi_native_qw0]
    cmp [rdx],rax
    jne .fail
    cmp qword [rdx+8],AMDVI_DOM_NATIVE
    jne .fail
    mov dword [rel amd_dmaa_stage],2

    mov r13,[rel amdvi_pool]
    add r13,AMDVI_POOL_PAGES*4096
    jc .fail
    test r13,r13
    jz .fail
    test r13,4095
    jnz .fail
    mov rdi,r13
    call dma_virt_to_phys
    cmp rax,r13
    jne .fail
    mov rdi,r13
    call amdvi_native_leaf_ptr
    test rax,rax
    jnz .fail
    mov [rel amd_dmaa_page],r13
    call amdvi_dma4_ring_snapshot
    test eax,eax
    jz .fail
    cmp rdx,rcx
    jne .fail                         ; never discard an unrelated stale event
    mov [rel amd_dmaa_head],edx
    mov eax,[rel amdvi_events]
    cmp eax,-1
    je .fail
    mov [rel amd_dmaa_before],eax
    mov dword [rel amd_dmaa_stage],3

    rdtsc
    shl rdx,32
    or rax,rdx
    xor rax,[rel amd_dmaa_nonce]
    mov rdx,0x9E3779B97F4A7C15
    xor rax,rdx
    jnz .sentinel
    mov rax,rdx
.sentinel:
    mov [rel amd_dmaa_canary],rax
    mov rdi,r13
    mov ecx,4096/8
    cld
    rep stosq
    call amdvi_dmaa_flush_canary
    mov dword [rel amd_dmaa_stage],4
    mov rdi,r13
    call ahci_identify_dma_to
    mov [rel amd_dmaa_ahci_status],eax
    mov dword [rel amd_dmaa_stage],5
    call amdvi_dmaa_canary_ok
    test eax,eax
    jz .fail
    mov byte [rel amd_dmaa_landed],0
    cmp dword [rel amd_dmaa_ahci_status],0xFFFE
    je .fail                          ; refused: nothing reached the device

    ; The event tail can lag the HBA. Poll a finite bound for the first entry,
    ; then until the tail holds still for AMDVI_DMAA_SETTLE reads (at most
    ; AMDVI_DMAA_MAX+1 restarts). An emulator that never logs faults cannot
    ; receive a containment pass.
    mov r15d,AMDVI_WAIT_SPINS
.wait:
    call amdvi_dma4_ring_snapshot
    test eax,eax
    jz .fail
    cmp edx,[rel amd_dmaa_head]
    jne .fail
    cmp rdx,rcx
    jne .settle_first
    pause
    dec r15d
    jnz .wait
    jmp .fail
.settle_first:
    mov r15d,AMDVI_DMAA_MAX+1         ; each restart is a new arrival
.settle_start:
    mov r12d,ecx
    mov ebx,AMDVI_DMAA_SETTLE
.settle:
    pause
    call amdvi_dma4_ring_snapshot
    test eax,eax
    jz .fail
    cmp edx,[rel amd_dmaa_head]
    jne .fail
    cmp ecx,r12d
    je .still
    dec r15d
    jz .fail
    jmp .settle_start
.still:
    dec ebx
    jnz .settle
.event:
    mov r15d,r12d
    sub r15d,edx
    and r15d,AMDVI_EVT_MASK
    shr r15d,4
    cmp r15d,AMDVI_DMAA_MAX
    ja .fail
    mov eax,[rel amd_dmaa_before]
    add eax,r15d
    jc .fail
    mov rsi,[rel amdvi_evtlog]
    mfence
    mov rax,[rsi+rdx]
    mov [rel amd_dmaa_q0],rax
    mov rax,[rsi+rdx+8]
    mov [rel amd_dmaa_q1],rax
.validate:
    mov rax,[rsi+rdx]
    mov r8,rax
    shr rax,60
    cmp eax,2                         ; IO_PAGE_FAULT, never an unknown summary
    jne .fail
    movzx eax,r8w
    cmp eax,r14d                      ; actual AHCI DeviceID
    jne .fail
    mov rax,[rsi+rdx+8]
    and rax,-4096
    cmp rax,r13                       ; every address inside the denied page
    jne .fail
    add edx,16
    and edx,AMDVI_EVT_MASK
    cmp edx,r12d
    jne .validate
    call amdvi_observation_generation
    cmp rax,[rel amd_dmaa_generation]
    jne .fail
    call amdvi_dma4_ring_snapshot
    test eax,eax
    jz .fail
    cmp edx,[rel amd_dmaa_head]
    jne .fail
    cmp ecx,r12d
    jne .fail                         ; no unvalidated arrival may be consumed
    mov dword [rel amd_dmaa_stage],6
    call amdvi_event_check            ; original consumer also publishes AMD witness
    cmp eax,r15d
    jne .fail
    mov eax,[rel amdvi_events]
    sub eax,[rel amd_dmaa_before]
    cmp eax,r15d
    jne .fail
    mov [rel amd_dmaa_delta],eax
    call amdvi_dma4_ring_snapshot
    test eax,eax
    jz .fail
    cmp rdx,rcx
    jne .fail
    call amdvi_observation_generation
    cmp rax,[rel amd_dmaa_generation]
    jne .fail
    call amdvi_dmaa_canary_ok
    test eax,eax
    jz .fail
    cmp dword [rel amd_dmaa_ahci_status],1
    ja .fail                          ; a poisoned port is not a serviceable device
    mov byte [rel amd_dmaa_blocked],1
    mov dword [rel amd_dmaa_stage],7
    mov eax,1
    jmp .out
.fail:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

amdvi_dmaa_flush_canary:
    mov rdi,[rel amd_dmaa_page]
    mov ecx,4096/64
.flush:
    clflush [rdi]
    add rdi,64
    dec ecx
    jnz .flush
    mfence
    ret

; Both initial result and same-nonce CHECK reload the entire page from memory.
amdvi_dmaa_canary_ok:
    cmp qword [rel amd_dmaa_page],0
    je .no
    call amdvi_dmaa_flush_canary
    mov rsi,[rel amd_dmaa_page]
    mov rax,[rel amd_dmaa_canary]
    mov ecx,4096/8
.check:
    cmp [rsi],rax
    jne .no
    add rsi,8
    dec ecx
    jnz .check
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

cmd_verb_amd_dmaviola:
    push rbx
    push r12
    call cmd_handler_prologue
    mov r12,rsi
    mov rbx,[rdi+REQ_ARG]
    mov [r12+RSP_VAL],rbx
    mov rdi,rbx
    call vtd_copy_nonce
    test eax,eax
    jz .bad_nonce
    lea rsi,[rel vtd_nonce]
    lea rdi,[rel amd_dmaa_nonce]
    mov ecx,8
    cld
    rep movsq
    call amdvi_dmaa_probe
    call vtd_out_reset
    lea rdi,[rel str_amd_dmaa_head]
    call vtd_out_str
    lea rdi,[rel amd_dmaa_nonce]
    call vtd_out_str
    cmp byte [rel amd_dmaa_blocked],1
    jne .failed
    lea rdi,[rel str_amd_dmaa_blocked]
    call vtd_out_str
    mov edi,[rel amd_dmaa_delta]
    call vtd_out_dec
    lea rdi,[rel str_amd_dmaa_blocked_tail]
    call vtd_out_str
    mov edi,[rel amd_dmaa_ahci_status]
    call vtd_out_dec
    lea rdi,[rel str_amd_dmaa_eol]
    call vtd_out_str
    jmp .ready
.failed:
    lea rdi,[rel str_amd_dmaa_failed]
    call vtd_out_str
    mov edi,[rel amd_dmaa_delta]
    call vtd_out_dec
    lea rdi,[rel str_amd_dmaa_stage]
    call vtd_out_str
    mov edi,[rel amd_dmaa_stage]
    call vtd_out_dec
    lea rdi,[rel str_amd_dmaa_landed]
    call vtd_out_str
    movzx edi,byte [rel amd_dmaa_landed]
    call vtd_out_dec
    lea rdi,[rel str_amd_dmaa_status]
    call vtd_out_str
    mov edi,[rel amd_dmaa_ahci_status]
    call vtd_out_dec
    lea rdi,[rel str_amd_dmaa_q0]
    call vtd_out_str
    mov rdi,[rel amd_dmaa_q0]
    call vtd_out_hex_compact
    lea rdi,[rel str_amd_dmaa_q1]
    call vtd_out_str
    mov rdi,[rel amd_dmaa_q1]
    call vtd_out_hex_compact
    lea rdi,[rel str_amd_dmaa_eol]
    call vtd_out_str
    jmp .ready
.bad_nonce:
    call vtd_out_reset
    lea rdi,[rel str_amd_dmaa_bad_nonce]
    call vtd_out_str
.ready:
    mov byte [rel vtd_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    pop r12
    pop rbx
    ret

cmd_verb_amd_dmaviola_check:
    push rbx
    push r12
    call cmd_handler_prologue
    mov r12,rsi
    mov rbx,[rdi+REQ_ARG]
    mov [r12+RSP_VAL],rbx
    mov rdi,rbx
    call vtd_copy_nonce
    test eax,eax
    jz .bad_nonce
    lea rdi,[rel vtd_nonce]
    lea rsi,[rel amd_dmaa_nonce]
    call strcmp
    test rax,rax
    jnz .stale
    cmp byte [rel amd_dmaa_valid],1
    jne .stale
    call amdvi_observation_binding
    test eax,eax
    jz .stale
    call amdvi_observation_generation
    cmp rax,[rel amd_dmaa_generation]
    jne .stale
    cmp byte [rel amd_dmaa_blocked],1
    jne .render
    call amdvi_dmaa_canary_ok
    test eax,eax
    jnz .render
    mov byte [rel amd_dmaa_blocked],0
    mov byte [rel amd_dmaa_landed],1
.render:
    call vtd_out_reset
    lea rdi,[rel str_amd_dmaa_check]
    call vtd_out_str
    lea rdi,[rel amd_dmaa_nonce]
    call vtd_out_str
    lea rdi,[rel str_amd_dmaa_landed]
    call vtd_out_str
    movzx edi,byte [rel amd_dmaa_landed]
    call vtd_out_dec
    lea rdi,[rel str_amd_dmaa_check_failed]
    cmp byte [rel amd_dmaa_blocked],1
    jne .verdict
    lea rdi,[rel str_amd_dmaa_check_blocked]
.verdict:
    call vtd_out_str
    jmp .ready
.stale:
    call vtd_out_reset
    lea rdi,[rel str_amd_dmaa_stale]
    call vtd_out_str
    jmp .ready
.bad_nonce:
    call vtd_out_reset
    lea rdi,[rel str_amd_dmaa_bad_check]
    call vtd_out_str
.ready:
    mov byte [rel vtd_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    pop r12
    pop rbx
    ret

str_amd_dmaa_head: db " DMAVIOLA nonce=",0
str_amd_dmaa_blocked: db " VERDICT=BLOCKED source=ivrs fault_delta=",0
str_amd_dmaa_blocked_tail: db " landed=0 ahci_status=",0
str_amd_dmaa_failed: db " VERDICT=FAILED source=ivrs fault_delta=",0
str_amd_dmaa_stage: db " stage=",0
str_amd_dmaa_landed: db " landed=",0
str_amd_dmaa_status: db " ahci_status=",0
str_amd_dmaa_q0: db " event_q0=0x",0
str_amd_dmaa_q1: db " event_q1=0x",0
str_amd_dmaa_eol: db 13,10,0
str_amd_dmaa_bad_nonce: db " DMAVIOLA ERR bad_nonce",13,10,0
str_amd_dmaa_check: db " DMAVIOLA_CHECK nonce=",0
str_amd_dmaa_check_blocked: db " VERDICT=BLOCKED source=ivrs",13,10,0
str_amd_dmaa_check_failed: db " VERDICT=FAILED source=ivrs",13,10,0
str_amd_dmaa_stale: db " DMAVIOLA_CHECK landed=1 VERDICT=STALE source=ivrs",13,10,0
str_amd_dmaa_bad_check: db " DMAVIOLA_CHECK ERR bad_nonce",13,10,0

%macro WDATA_hv_amdvi_dmaa_probe 0
align 8
amd_dmaa_page: resq 1
amd_dmaa_canary: resq 1
amd_dmaa_q0: resq 1
amd_dmaa_q1: resq 1
amd_dmaa_generation: resq 1
amd_dmaa_before: resd 1
amd_dmaa_head: resd 1
amd_dmaa_bdf: resd 1
amd_dmaa_ahci_status: resd 1
amd_dmaa_delta: resd 1
amd_dmaa_stage: resd 1
amd_dmaa_landed: resb 1
amd_dmaa_blocked: resb 1
amd_dmaa_valid: resb 1
amd_dmaa_nonce: resb 64
%endmacro
WDATA_BSS_DEFER WDATA_hv_amdvi_dmaa_probe
