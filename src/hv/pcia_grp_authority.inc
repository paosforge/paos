; W4c-2 A original reservation custody. Included once by pci_assign.asm.
; OWNER rc-vm-claude
%include "hv/pcia_grp.inc"
%include "core/abi/wdata.inc"

; Native cold bind fence: the private held set, even under stale/POISON
; common bytes, excludes new host claims. Never infer free from query refusal.
pcia_grp_any_held:
    xor eax, eax
    cmp byte [rel pcia_grpa_held], 0
    setne al
    ret

; Match immutable original header/member identity; ignore only the lifecycle,
; failure tags, and C/B diagnostic flags/IRQ bytes. No state or hardware write.
pcia_grp_frozen_equal:
    lea rax, [rel pcia_grp]
    cmp rdi, rax
    jne .no
    cmp dword [rdi+PG_MAGIC], PCIA_GRP_MAGIC
    jne .no
    lea r8, [rel pcia_grpa_identity]
    cmp dword [r8+PG_MAGIC], PCIA_GRP_MAGIC
    jne .no
    mov eax, [rdi+4]
    mov edx, [r8+4]
    and eax, 0xffffff00
    and edx, 0xffffff00
    cmp eax, edx
    jne .no
    mov ecx, 8
.header:
    mov rax, [rdi+rcx]
    cmp rax, [r8+rcx]
    jne .no
    add ecx, 8
    cmp ecx, 32
    jb .header
    mov eax, [rdi+PG_ATTEMPT]
    test eax, eax
    jz .no
    cmp eax, [r8+PG_ATTEMPT]
    jne .no
    mov ax, [rdi+PG_SEGMENT]
    cmp ax, [r8+PG_SEGMENT]
    jne .no
    mov ecx, PG_MEMBERS
.member:
    mov rax, [rdi+rcx]
    cmp rax, [r8+rcx]
    jne .no
    mov ax, [rdi+rcx+PGM_RSVD]
    cmp ax, [r8+rcx+PGM_RSVD]
    jne .no
    mov eax, [rdi+rcx+PGM_BK]
    cmp eax, [r8+rcx+PGM_BK]
    jne .no
    add ecx, PGM_BYTES
    cmp ecx, PCIA_GRP_BYTES
    jb .member
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; Common shape alone cannot make this positive. One private bit for every
; member represents its original BDF/attempt/START/reset domain reservation.
pcia_grp_identity:
    sub rsp, 8
    call pcia_grp_frozen_equal
    test eax, eax
    jz .out
    mov eax, [rel hv_linux_start_consumed]
    test eax, eax
    jz .out
    cmp [rdi+PG_GEN], rax
    jne .no
    movzx ecx, byte [rdi+PG_COUNT]
    cmp ecx, 2
    jb .no
    cmp ecx, PCIA_GRP_MAX
    ja .no
    mov eax, 1
    shl eax, cl
    dec eax
    cmp al, [rel pcia_grpa_held]
    jne .no
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    add rsp, 8
    ret

; ABI v1.1 pure query. POISON refuses but keeps every reservation held.
pcia_grp_reserved:
    sub rsp, 8
    call pcia_grp_identity
    test eax, eax
    jz .out
    cmp byte [rdi+PG_STATE], PGS_RESERVED
    jb .no
    cmp byte [rdi+PG_STATE], PGS_RELEASING
    ja .no
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    add rsp, 8
    ret

; Exact frozen backend and its current native owner. No backend fallback.
pcia_grp_backend:
    cmp byte [rdi+PG_BACKEND], PGB_AMDVI
    je .amd
    cmp byte [rdi+PG_BACKEND], PGB_VTD
    jne .no
    cmp byte [rel amdvi_owned], 0
    jne .no
    cmp byte [rel vtd_enabled], 1
    jne .no
    mov eax, PGB_VTD
    ret
.amd:
    cmp byte [rel amdvi_owned], 1
    jne .no
    cmp byte [rel vtd_enabled], 0
    jne .no
    mov eax, PGB_AMDVI
    ret
.no:
    xor eax, eax
    ret

; Pure actual native all-member liveness. Common POISON after a C reset
; failure does not replace B's live/unknown proof. No failure-tag publication.
pcia_grp_live:
    push r12
    mov r12, rdi
    call pcia_grp_identity
    cmp eax, 1
    jne .no
    mov rdi, r12
    call pcia_grp_backend
    cmp eax, PGB_AMDVI
    je .amd
    cmp eax, PGB_VTD
    jne .no
    mov rdi, r12
    pop r12
    jmp vtd_guest_group_live
.amd:
    mov rdi, r12
    pop r12
    jmp amdvi_guest_group_live
.no:
    mov eax, -1
    pop r12
    ret

pcia_grp_attach:
    push r12
    mov r12, rdi
    call pcia_grp_reserved
    cmp eax, 1
    jne .bad
    cmp byte [r12+PG_STATE], PGS_RESET_IN
    jne .bad
    mov rdi, r12
    call pcia_grp_backend
    cmp eax, PGB_AMDVI
    je .amd
    cmp eax, PGB_VTD
    jne .bad
    mov rdi, r12
    call vtd_guest_group_attach
    jmp .installed
.amd:
    mov rdi, r12
    call amdvi_guest_group_attach
.installed:
    test eax, eax
    jnz .bad
    mov rdi, r12
    call pcia_grp_live
    test eax, eax
    jnz .readback
    mov rdi, r12
    call pcia_grp_reserved
    cmp eax, 1
    jne .readback
    cmp byte [r12+PG_STATE], PGS_MAPPED
    jne .readback
    mov byte [r12+PG_STATE], PGS_LIVE
    xor eax, eax
    jmp .out
.readback:
    mov esi, PGX_READBACK
    jmp .poison
.bad:
    mov esi, PGX_MAP
.poison:
    mov rdi, r12
    call pcia_grp_poison
    mov eax, -1
.out:
    pop r12
    ret

; Only this dispatch can latch actual successful native detach. A diagnostic
; backend-retired flag, caller-built state or old generation can never do so.
pcia_grp_detach:
    push r12
    mov r12, rdi
    call pcia_grp_reserved
    cmp eax, 1
    jne .bad
    cmp byte [r12+PG_STATE], PGS_RELEASING
    jne .bad
    mov rdi, r12
    call pcia_grp_backend
    cmp eax, PGB_AMDVI
    je .amd
    cmp eax, PGB_VTD
    jne .bad
    mov rdi, r12
    call vtd_guest_group_detach
    jmp .detached
.amd:
    mov rdi, r12
    call amdvi_guest_group_detach
.detached:
    test eax, eax
    jnz .bad
    mov rdi, r12
    call pcia_grp_reserved
    cmp eax, 1
    jne .bad
    cmp byte [r12+PG_STATE], PGS_RELEASING
    jne .bad
    mov rax, [r12+PG_GEN]
    mov [rel pcia_grpa_detach_gen], rax
    xor eax, eax
    jmp .out
.bad:
    mov rdi, r12
    mov esi, PGX_RETIRE
    call pcia_grp_poison
    mov eax, -1
.out:
    pop r12
    ret

; Foreign pointers and records for which A never took custody stay inert.
; Preserve B/C's first failure tags when they have already published POISON.
pcia_grp_poison:
    lea rax, [rel pcia_grp]
    cmp rdi, rax
    jne .out
    cmp byte [rel pcia_grpa_held], 0
    je .out
    cmp byte [rdi+PG_STATE], PGS_POISON
    je .out
    mov byte [rdi+PG_FAIL_ORD], 0xff
    mov [rdi+PG_FAIL_STEP], sil
    mov byte [rdi+PG_STATE], PGS_POISON
.out:
    ret

; C calls only after actual outbound reset custody. Validate everything
; first, then clear the one complete private bitset; there is no partial drop.
pcia_grp_claims_retire:
    push r12
    mov r12, rdi
    call pcia_grp_reserved
    cmp eax, 1
    jne .no
    cmp byte [r12+PG_STATE], PGS_RELEASING
    jne .no
    mov rax, [r12+PG_GEN]
    cmp rax, [rel pcia_grpa_detach_gen]
    jne .no
    mov byte [rel pcia_grpa_held], 0
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    pop r12
    ret

; GRR1 version1: 8-byte receipt header + exact current 168-byte record.
; Passive, bounded copy only. Copies never confer A/C/backend authority.
pcia_grp_receipt:
    cmp esi, PCIA_GRP_BYTES+8
    jb .no
    test rdi, rdi
    jz .no
    mov rax, rdi
    add rax, PCIA_GRP_BYTES+8
    jc .no
    lea rcx, [rel pcia_grp]
    cmp rax, rcx
    jbe .private
    add rcx, PCIA_GRP_BYTES
    cmp rdi, rcx
    jb .no
.private:
    lea rcx, [rel pcia_grpa_private]
    cmp rax, rcx
    jbe .copy
    lea rcx, [rel pcia_grpa_private_end]
    cmp rdi, rcx
    jb .no
.copy:
    push r12
    mov r12, rdi
    lea rdi, [rel pcia_grp]
    call pcia_grp_frozen_equal
    cmp eax, 1
    jne .refuse
    mov dword [r12], 'GRR1'
    mov word [r12+4], 1
    mov word [r12+6], PCIA_GRP_BYTES+8
    lea rdi, [r12+8]
    lea rsi, [rel pcia_grp]
    mov ecx, PCIA_GRP_BYTES/8
    cld
    rep movsq
    mov eax, PCIA_GRP_BYTES+8
    pop r12
    ret
.refuse:
    pop r12
.no:
    xor eax, eax
    ret

; Original admission takes no caller-built common record. Its two complete
; independent collections agree before any reservation or lifecycle publish.
pcia_grp_admit:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 504
    mov ebx, edi
    mov rbp, rsi
    mov r12, rdx
    mov r13, rcx
    mov r14, rsp
    lea r15, [rsp+248]
    cmp edi, 65535
    ja .changed
    mov eax, [rel hv_linux_start_consumed]
    test eax, eax
    jz .changed
    cmp rax, rbp
    jne .changed
    call nica_cpu_off
    cmp eax, 1
    jne .changed
    cmp byte [rel nic_assignment_state], 0
    jne .claimed
    cmp byte [rel pcia_state], PCIA_IDLE
    jne .claimed
    cmp byte [rel pcia_grpa_held], 0
    jne .claimed
    cmp r12, [rel hv_linux_ram]
    jne .changed
    cmp r13, [rel hv_linux_ram_bytes]
    jne .changed
    test r12, r12
    jz .changed
    test r12, (2<<20)-1
    jnz .changed
    test r13, r13
    jz .changed
    test r13, (2<<20)-1
    jnz .changed
    mov rax, 1<<32
    cmp r13, rax
    ja .changed
    mov rax, r12
    add rax, r13
    jc .changed
    mov rdx, 1<<47
    cmp rax, rdx
    ja .changed
    cmp dword [rel pcia_grpa_attempt], -1
    je .changed
    cmp dword [rel pcia_grpa_identity+PG_MAGIC], 0
    je .first
    lea rdi, [rel pcia_grp]
    call pcia_grp_frozen_equal
    cmp eax, 1
    jne .changed
    cmp byte [rel pcia_grp+PG_STATE], PGS_RETIRED
    jne .claimed
    cmp rbp, [rel pcia_grpa_identity+PG_GEN]
    jbe .changed
    mov rax, [rel pcia_grpa_identity+PG_GEN]
    cmp rax, [rel pcia_grpa_detach_gen]
    jne .changed
    jmp .collect
.first:
    cmp byte [rel pcia_grp+PG_STATE], PGS_FREE
    jne .claimed
.collect:
    mov edi, ebx
    mov rsi, r14
    call pcia_grp_collect
    test eax, eax
    jnz .out
    mov edi, ebx
    mov rsi, r15
    call pcia_grp_collect
    test eax, eax
    jnz .out
    mov rdi, r14
    mov rsi, r15
    mov ecx, 248/8
    cld
    repe cmpsq
    jne .changed
    mov [r14+PG_GEN], rbp
    mov [r14+PG_RAM], r12
    mov [r14+PG_BYTES], r13
    mov eax, [rel pcia_grpa_attempt]
    inc eax
    mov [r14+PG_ATTEMPT], eax
    mov rdi, r14
    call iommu_guest_group_wdata_ok
    cmp eax, 1
    jne .changed
    ; Recheck the actual consumed START and CPU-off at first custody.
    call nica_cpu_off
    cmp eax, 1
    jne .changed
    mov eax, [rel hv_linux_start_consumed]
    cmp rax, rbp
    jne .changed
    mov eax, [r14+PG_ATTEMPT]
    mov [rel pcia_grpa_attempt], eax
    lea rdi, [rel pcia_grpa_identity]
    mov rsi, r14
    mov ecx, PCIA_GRP_BYTES/8
    cld
    rep movsq
    lea rdi, [rel pcia_grp]
    mov rsi, r14
    mov ecx, PCIA_GRP_BYTES/8
    rep movsq
    mov qword [rel pcia_grpa_detach_gen], 0
    movzx ecx, byte [r14+PG_COUNT]
    mov eax, 1
    shl eax, cl
    dec eax
    mov [rel pcia_grpa_held], al    ; all member reservations in one publish
    mov byte [rel pcia_grp+PG_STATE], PGS_RESERVED
    xor eax, eax
    jmp .out
.claimed:
    mov eax, ISO_GRP_CLAIMED
    jmp .out
.changed:
    mov eax, ISO_GRP_CHANGED
.out:
    mov [rel pcia_iso_reason], al  ; diagnostic only, never a reservation
    mov edi, ebx
    mov esi, eax
    mov edx, [rel hv_linux_start_consumed]
    call ndiso_group_capture       ; passive GRF1; preserves the original EAX
    add rsp, 504
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; EDI selected BDF, RSI caller-private 248B stage. Record + 8 original
; vendor/device+class/revision pairs (not a new public ABI). No effect/custody.
pcia_grp_collect:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 1064                 ; facts272, locked claims512, cfg256, scope16
    mov ebp, edi
    mov r12, rsi
    mov r14, rsp
    lea r15, [rsp+784]
    call pcia_group_gate
    cmp eax, ISO_PROTECTED
    je .claimed
    cmp eax, ISO_SHARED_DMA
    jne .singleton_or_error
    lea rdi, [rel pcia_iso_record]
    call devassign_group_classify
    test eax, eax
    jnz .out
    mov rdi, r14
    lea rsi, [rel pcia_iso_record]
    mov ecx, DA_REC_BYTES/8
    cld
    rep movsq
    mov rdi, r12
    mov ecx, 248/8
    xor eax, eax
    rep stosq
    mov dword [r12+PG_MAGIC], PCIA_GRP_MAGIC
    mov byte [r12+PG_FAIL_ORD], 0xff
    mov byte [r12+PG_BACKEND], PGB_VTD
    cmp byte [rel amdvi_owned], 1
    jne .owner
    mov byte [r12+PG_BACKEND], PGB_AMDVI
.owner:
    xor ebx, ebx
    xor r13d, r13d
.members:
    movzx ecx, byte [r14+3]
    cmp ebx, ecx
    jae .sort
    lea r8, [r14+16+rbx*8]
    mov al, [r14+23]              ; target group, builder guarantees target0
    cmp al, [r8+7]
    jne .next
    test byte [r8+6], DA_F_DMA
    jz .next
    cmp r13d, PCIA_GRP_MAX
    jae .overflow
    mov eax, r13d
    shl eax, 4
    mov dx, [r8+2]
    rol dx, 8                    ; fact bus byte precedes devfn byte
    mov [r12+rax+PG_MEMBERS+PGM_BDF], dx
    inc r13d
.next:
    inc ebx
    jmp .members
.sort:
    cmp r13d, 2
    jb .changed
    mov [r12+PG_COUNT], r13b
    ; Sort the BDFs before any member metadata is populated.
    xor ebx, ebx
.sort_i:
    mov ecx, ebx
    inc ecx
.sort_j:
    cmp ecx, r13d
    jae .sort_next
    mov eax, ebx
    shl eax, 4
    mov edx, ecx
    shl edx, 4
    mov si, [r12+rax+PG_MEMBERS]
    mov di, [r12+rdx+PG_MEMBERS]
    cmp si, di
    je .changed
    jb .sort_j_next
    mov [r12+rax+PG_MEMBERS], di
    mov [r12+rdx+PG_MEMBERS], si
.sort_j_next:
    inc ecx
    jmp .sort_j
.sort_next:
    inc ebx
    cmp ebx, r13d
    jb .sort_i
    xor ebx, ebx
.config:
    mov eax, ebx
    shl eax, 4
    lea r8, [r12+rax+PG_MEMBERS]
    mov [r8+PGM_BK], ebx
    mov byte [r8+PGM_ROLE], PGR_PARKED
    cmp [r8+PGM_BDF], bp
    jne .peer
    mov byte [r8+PGM_ROLE], PGR_SELECTED
    mov [r12+PG_SEL], bl
.peer:
    movzx edi, word [r8+PGM_BDF]
    call pcia_group_gate           ; chain RMRR/alias facts for EVERY member
    cmp eax, ISO_PROTECTED
    je .claimed
    cmp eax, ISO_SHARED_DMA
    jne .singleton_or_error
    lea rdi, [rel pcia_iso_record]
    call devassign_group_classify
    test eax, eax
    jnz .out
    mov rdi, r12
    call pcia_grp_member_set_equal
    cmp eax, 1
    jne .changed
    xor r13d, r13d
.read_cfg:
    mov eax, ebx
    shl eax, 4
    movzx edi, word [r12+rax+PG_MEMBERS]
    mov esi, r13d
    call pci_bdf_read
    mov [r15+r13], eax
    add r13d, 4
    cmp r13d, 256
    jb .read_cfg
    cmp word [r15], 0
    je .changed
    cmp word [r15], 0xffff
    je .changed
    test byte [r15+14], 0x7f
    jnz .class
    movzx eax, word [r15+10]
    cmp eax, 0x0200
    je .class_ok
    cmp eax, 0x0280
    jne .class
.class_ok:
    mov edx, ebx
    shl edx, 4
    mov [r12+rdx+PG_MEMBERS+PGM_CLASS], ax
    mov rax, [r15]
    mov eax, eax
    mov [r12+168+rbx*8], eax
    mov eax, [r15+8]
    mov [r12+172+rbx*8], eax
    movzx edi, word [r12+rdx+PG_MEMBERS]
    call vtd_iso_is_lifeline
    cmp eax, 1
    je .claimed
    mov eax, ebx
    shl eax, 4
    movzx edi, word [r12+rax+PG_MEMBERS]
    cmp byte [rel amdvi_owned], 1
    jne .ats
    call amdvi_hda_scope
    cmp eax, 1
    jne .rmrr
.ats:
    mov eax, ebx
    shl eax, 4
    movzx edi, word [r12+rax+PG_MEMBERS]
    call vtd_hda_ats_state
    cmp eax, 1
    ja .alias
    mov eax, ebx
    shl eax, 4
    movzx edi, word [r12+rax+PG_MEMBERS]
    call pcia_group_pcie
    test eax, eax
    jz .reset
    test dword [r15+rax+4], 1<<28
    jz .sbr
    mov eax, ebx
    shl eax, 4
    mov byte [r12+rax+PG_MEMBERS+PGM_RMETHOD], PGRM_FLR
    mov word [r12+rax+PG_MEMBERS+PGM_RDOMAIN], 0xffff
    jmp .verify
.sbr:
    mov rdi, r12
    mov esi, ebx
    mov rdx, r14
    lea rcx, [rsp+1040]
    call pcia_grp_sbr_domain
    cmp eax, -1
    je .reset
    mov edx, ebx
    shl edx, 4
    mov byte [r12+rdx+PG_MEMBERS+PGM_RMETHOD], PGRM_SBR
    mov [r12+rdx+PG_MEMBERS+PGM_RDOMAIN], ax
.verify:
    xor r13d, r13d
.verify_cfg:
    mov eax, ebx
    shl eax, 4
    movzx edi, word [r12+rax+PG_MEMBERS]
    mov esi, r13d
    call pci_bdf_read
    cmp eax, [r15+r13]
    jne .changed
    add r13d, 4
    cmp r13d, 256
    jb .verify_cfg
    inc ebx
    cmp bl, [r12+PG_COUNT]
    jb .config
    ; A complete recorder snapshot, including FAILED and overflow, is a
    ; refusal prerequisite, never the exclusive reservation itself.
    lea rdi, [rsp+272]
    call pci_claim_snapshot
    test edx, edx
    jnz .claimed
    cmp eax, 32
    ja .claimed
    mov r13d, eax
    xor ebx, ebx
.claim_row:
    cmp ebx, r13d
    jae .yes
    mov eax, ebx
    shl eax, 4
    lea r8, [rsp+272+rax]
    cmp dword [r8], 65535
    ja .claimed
    cmp dword [r8+4], 0
    je .claimed
    mov eax, [r8+8]
    dec eax
    cmp eax, 1
    ja .claimed
    xor ecx, ecx
.claim_member:
    mov edx, ecx
    shl edx, 4
    movzx eax, word [r12+rdx+PG_MEMBERS]
    cmp eax, [r8]
    je .claimed
    inc ecx
    cmp cl, [r12+PG_COUNT]
    jb .claim_member
    inc ebx
    jmp .claim_row
.yes:
    xor eax, eax
    jmp .out
.singleton_or_error:
    test eax, eax
    jnz .out
    mov eax, ISO_SHARED_DMA       ; singleton retains its original API
    jmp .out
.class: mov eax, ISO_GRP_CLASS
    jmp .out
.claimed: mov eax, ISO_GRP_CLAIMED
    jmp .out
.reset: mov eax, ISO_GRP_RESET
    jmp .out
.overflow: mov eax, ISO_GRP_OVERFLOW
    jmp .out
.changed: mov eax, ISO_GRP_CHANGED
    jmp .out
.rmrr: mov eax, ISO_RMRR
    jmp .out
.alias: mov eax, ISO_ALIAS
.out:
    add rsp, 1064
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Current completed builder record must name exactly the original DMA set.
pcia_grp_member_set_equal:
    push rbx
    xor ebx, ebx
    lea r8, [rel pcia_iso_record]
    cmp byte [r8+4], 0
    jne .no
    movzx r9d, byte [r8+3]
    cmp r9d, DA_REC_MAX
    ja .no
    movzx r10d, byte [r8+23]
    xor ecx, ecx
    xor r11d, r11d
.fact:
    cmp ecx, r9d
    jae .done
    lea rsi, [r8+16+rcx*8]
    inc ecx
    cmp [rsi+7], r10b
    jne .fact
    test byte [rsi+6], DA_F_DMA
    jz .fact
    mov ax, [rsi+2]
    rol ax, 8
    xor edx, edx
.find:
    mov esi, edx
    shl esi, 4
    cmp ax, [rdi+rsi+PG_MEMBERS]
    je .found
    inc edx
    cmp dl, [rdi+PG_COUNT]
    jb .find
    jmp .no
.found:
    bt ebx, edx
    jc .no
    bts ebx, edx
    inc r11d
    jmp .fact
.done:
    cmp r11b, [rdi+PG_COUNT]
    jne .no
    mov eax, 1
    pop rbx
    ret
.no:
    xor eax, eax
    pop rbx
    ret

; RDI candidate, ESI ordinal, RDX original facts, RCX private u16[8].
; Return root bridge BDF or -1; every possible SBR victim must be a member.
pcia_grp_sbr_domain:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12, rdi
    mov r13, rdx
    mov r14, rcx
    shl esi, 4
    movzx ebp, word [rdi+rsi+PG_MEMBERS]
    shr ebp, 8
    xor ebx, ebx
    mov r15d, -1
.bridge:
    cmp bl, [r13+3]
    jae .done
    lea r8, [r13+16+rbx*8]
    inc ebx
    cmp byte [r8+5], DA_K_BRIDGE
    jne .bridge
    mov ax, [r8+2]
    rol ax, 8
    movzx edi, ax
    mov [rsp], edi
    mov esi, 0x18
    call pci_bdf_read
    cmp eax, -1
    je .no
    movzx ecx, ah
    cmp ecx, ebp
    jne .bridge
    shr eax, 16
    movzx eax, al
    cmp eax, ebp
    jne .no
    cmp r15d, -1
    jne .no
    mov edi, [rsp]
    mov rsi, r14
    call pcia_root_scope
    test eax, eax
    jz .no
    cmp eax, PCIA_GRP_MAX
    ja .no
    mov r15d, [rsp]
    mov r9d, eax
    xor ecx, ecx
.victim:
    movzx eax, word [r14+rcx*2]
    xor edx, edx
.member:
    mov esi, edx
    shl esi, 4
    cmp ax, [r12+rsi+PG_MEMBERS]
    je .included
    inc edx
    cmp dl, [r12+PG_COUNT]
    jb .member
    jmp .no
.included:
    inc ecx
    cmp ecx, r9d
    jb .victim
    jmp .bridge
.done:
    mov eax, r15d
    jmp .out
.no:
    mov eax, -1
.out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

%macro WDATA_hv_pcia_grp_authority 0
alignb 64
pcia_grpa_private:
pcia_grpa_identity: resb PCIA_GRP_BYTES
pcia_grpa_held: resb 1
alignb 8
pcia_grpa_detach_gen: resq 1
pcia_grpa_attempt: resd 1
pcia_grpa_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_pcia_grp_authority
