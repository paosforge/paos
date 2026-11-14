; BSP-only private RAM/video implementation. Included after normal boot code.
; No link probe, backend call, EFI write, allocation, input or health mutation.
%if PAOS_PARKED_WATCH_DIAG
parked_watch_observe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12d,edi                   ; actual edge/reason
    mov r13,rsi                    ; actual returned RAX, not a new probe
    cmp byte [rel pw_active],1
    je .active
    test dil,dil                   ; only actual PARKED edge0 may arm
    jnz .out
    cmp byte [rel boot_nic_state],NIC_ST_PARKED
    jne .out
    cmp qword [rel native_progress_accepted],1
    jne .out
    cmp byte [rel pbm_manager_launch],1
    jne .out
    cmp byte [rel pbm_safe_runtime_active],0
    jne .out
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne .out
    test byte [rel pbm_flags],PBM_HF_MUTABLE_ATTEMPT
    jz .out
    cmp byte [rel paos_build_state],BID_ST_MATCH
    jne .out
    lea r14,[rel native_progress_handoff]
    mov rax,[rel pbm_manager_sequence]
    test rax,rax
    jz .out
    cmp rax,[r14+8]
    jne .out
    mov rax,[rel pbm_attempt_nonce]
    test rax,rax
    jz .out
    cmp rax,[r14+16]
    jne .out
    mov rax,[rel pbm_state_generation]
    test rax,rax
    jz .out
    cmp rax,[r14+24]
    jne .out
    mov al,[rel pbm_entry]
    cmp al,PBM_ENTRY_PAOS_A
    je .entry
    cmp al,PBM_ENTRY_PAOS_B
    jne .out
.entry:
    cmp al,[r14+32]
    jne .out
    mov byte [rel pw_active],1
.active:
    cmp r12d,32
    je .paint                      ; ordinary owner repaint, no new observation
    movzx ecx,r12b
    cmp ecx,32
    jae .out
    cmp ecx,10
    jne .not_watch_entry
    mov byte [rel pw_watch_scope],1 ; every visit, even after first slot is frozen
.not_watch_entry:
    cmp ecx,12
    je .end_scope
    cmp ecx,29
    je .end_scope
    cmp ecx,31
    jne .scope_check
.end_scope:
    mov byte [rel pw_watch_scope],0
.scope_check:
    cmp ecx,22
    jb .scope_ok
    cmp ecx,25
    ja .scope_ok
    cmp byte [rel pw_watch_scope],1 ; shared helper has non-watcher callers too
    jne .out
.scope_ok:
    cmp ecx,29
    jne .not_watcher_out
    bt dword [rel pw_seen],10       ; WARMING expiry's own OUT is not a later visit
    jnc .out
.not_watcher_out:
    cmp ecx,18
    jne .not_selection
    mov [rel pw_candidate],r13      ; internal handle, never projected raw
.not_selection:
    bt dword [rel pw_seen],ecx
    jc .out                        ; first occurrence immutable; <=32 updates
    bts dword [rel pw_seen],ecx
    mov [rel pw_last_edge],cl
    mov eax,r12d
    shr eax,8
    mov [rel pw_last_reason],al
    inc byte [rel pw_sequence]
    lea r14,[rel pw_slots]
    shl ecx,5
    add r14,rcx
    mov [r14],r12d
    movzx eax,byte [rel pw_sequence]
    mov [r14+4],eax
    ; Only clocks and actual returned numeric decisions may enter raw fields.
    ; Other sites can hold driver/function pointers in RAX; project zero.
    movzx edx,r12b
    bt dword [rel pw_numeric_edges],edx
    jc .numeric
    xor r13d,r13d
.numeric:
    mov [r14+8],r13
    mov rax,[rel boot_nic_park_poll_ms]
    mov [r14+16],rax
    movzx eax,byte [rel boot_nic_state]
    mov [r14+24],rax
.snapshot:
    lea r15,[rel pw_wire]
    mov dword [r15],'PWV1'
    mov byte [r15+4],1
    mov al,[rel pw_last_edge]
    mov [r15+5],al
    mov al,[rel pw_last_reason]
    mov [r15+6],al
    mov al,[rel pbm_entry]
    mov [r15+7],al
    mov rax,[rel pbm_state_generation]
    mov [r15+8],rax
    mov rax,[rel pbm_attempt_nonce]
    mov [r15+16],rax
    mov rax,[rel pbm_manager_sequence]
    mov [r15+24],rax
    lea rsi,[rel paos_build_measured]
    lea rdi,[r15+32]
    mov ecx,4
    cld
    rep movsq
    mov eax,[rel pw_seen]
    mov [r15+64],eax
    mov al,[rel pw_sequence]
    mov [r15+68],al
    mov al,[rel boot_nic_state]
    mov [r15+69],al
    cmp qword [rel udp_oob_nic_handle],0
    setne al
    mov [r15+70],al               ; OOB handle PRESENT, not a new owner decision
    cmp r12b,5
    jne .not_bound_result
    mov [r15+121],r13b             ; first ACTUAL native_bound return (0/1)
.not_bound_result:
    cmp r12b,26
    jne .not_post_reason
    mov eax,r12d
    shr eax,8
    mov [r15+120],al               ; first post-callback rejection reason survives OUT
.not_post_reason:
    mov [r15+72],r13              ; last edge's ACTUAL operand/return
    mov rax,[rel boot_nic_park_poll_ms]
    mov [r15+80],rax
    cmp r12b,25
    jne .owner
    mov [r15+88],r13              ; first actual link_status return
.owner:
    mov rdi,[rel udp_nic_handle]
    call parked_watch_member
    mov [r15+96],rax
    mov rdi,[rel pw_candidate]
    call parked_watch_member
    mov [r15+104],rax
    mov byte [r15+71],0
    test al,al
    jz .ops_done
    cmp al,255
    je .ops_done
    ; Do not inspect an ops table on a path the original watcher rejects.
    cmp dword [rdi+dev.class],CLASS_NET
    jne .ops_done
    cmp dword [rdi+dev.health],HEALTH_OK
    jne .ops_done
    cmp dword [rdi+dev.prio],PRIO_NATIVE_EXPERIMENTAL
    jb .ops_done
    test dword [rdi+dev.flags],NETDEV_F_ABSENT
    jnz .ops_done
    mov rdx,[rdi+dev.ops]         ; registered eligible member; no backend call
    test rdx,rdx
    jz .ops_done
    mov byte [r15+71],1
    cmp qword [rdx+netdev_ops.tx],0
    je .no_tx
    or byte [r15+71],2
.no_tx:
    cmp qword [rdx+netdev_ops.rx_poll],0
    je .no_rx
    or byte [r15+71],4
.no_rx:
    cmp qword [rdx+netdev_ops.get_mac],0
    je .no_mac
    or byte [r15+71],8
.no_mac:
    cmp qword [rdx+netdev_ops.link_status],0
    je .ops_done
    or byte [r15+71],16
.ops_done:
    ; Highest-priority registered native LINK_WAIT member, registry-only.
    xor edx,edx
    xor r8d,r8d
    lea r9,[rel netdev_table]
    xor r10d,r10d
.wait:
    cmp r10d,NETDEV_MAX_SLOTS
    jae .waiting_done
    mov rcx,[r9+r10*8]
    test rcx,rcx
    jz .next
    cmp dword [rcx+dev.class],CLASS_NET
    jne .next
    test dword [rcx+dev.flags],NETDEV_F_LINK_WAIT
    jz .next
    mov eax,[rcx+dev.prio]
    cmp eax,PRIO_NATIVE_EXPERIMENTAL
    jb .next
    cmp eax,r8d
    jb .next
    mov r8d,eax
    mov rdx,rcx
.next:
    inc r10d
    jmp .wait
.waiting_done:
    mov rdi,rdx
    call parked_watch_member
    mov [r15+112],rax
    lea rdi,[rel pw_wire]
    mov esi,124
    call hotpatch_crc32
    mov [rel pw_wire+124],eax
.paint:
    call parked_watch_paint
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Registered index+1, class, health, priority (low8 each), flags32. Zero=none;
; ff=unregistered nonnull. Never dereference an unregistered raw handle.
parked_watch_member:
    xor eax,eax
    test rdi,rdi
    jz .out
    mov eax,255
    lea r9,[rel netdev_table]
    xor ecx,ecx
.scan:
    cmp ecx,NETDEV_MAX_SLOTS
    jae .out
    cmp rdi,[r9+rcx*8]
    je .found
    inc ecx
    jmp .scan
.found:
    lea eax,[rcx+1]
    mov edx,[rdi+dev.class]
    and edx,255
    shl edx,8
    or eax,edx
    mov edx,[rdi+dev.health]
    and edx,255
    shl edx,16
    or eax,edx
    mov edx,[rdi+dev.prio]
    and edx,255
    shl edx,24
    or eax,edx
    mov edx,[rdi+dev.flags]
    shl rdx,32
    or rax,rdx
.out:
    ret

; Owned diagnostic at (8,8), 104x104, ABOVE the 640x480 lock card; never
; reuse the early PLV badge or cover input/notice. Existing presentation gate
; remains authoritative. No present-count change => no visible evidence.
; 32x32 MSB-first bits, 3px modules, 4px white border. CRC32 little endian.
parked_watch_paint:
    cmp byte [rel lock_composition_ok],1
    jne .out
    cmp byte [rel session_locked],SESSION_LOCKED
    jne .out
    cmp qword [rel fb_base],0
    je .out
    cmp dword [rel fb_width],640
    jb .out
    cmp dword [rel fb_height],704
    jb .out                         ; (height-480)/2 >=112; no unsigned underflow
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r8d,8
    mov r9d,8
    mov r10d,104
    mov r11d,104
    mov ebx,0x00ffffff
    call fb_fill_rect
    xor r12d,r12d
.row:
    xor r13d,r13d
.col:
    mov eax,r12d
    shl eax,2
    mov ecx,r13d
    shr ecx,3
    add eax,ecx
    lea rdx,[rel pw_wire]
    movzx r14d,byte [rdx+rax]
    mov ecx,r13d
    and ecx,7
    mov r15d,0x80
    shr r15d,cl
    xor ebx,ebx
    test r14d,r15d
    jz .pixel
    mov ebx,0x00ffffff
.pixel:
    lea r8d,[r13d+r13d*2+12]
    lea r9d,[r12d+r12d*2+12]
    mov r10d,3
    mov r11d,3
    call fb_fill_rect
    inc r13d
    cmp r13d,32
    jb .col
    inc r12d
    cmp r12d,32
    jb .row
    mov r8d,8
    mov r9d,8
    mov r10d,104
    mov r11d,104
    call fb_present_rect
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
.out:
    ret
pw_numeric_edges: dd (1<<5)|(1<<9)|(1<<11)|(1<<12)|(1<<13)|(1<<14)|(1<<15)|(1<<25)|(1<<27)
%include "core/abi/wdata.inc"
WDATA_BSS_DEFER WDATA_parked_watch
%endif
