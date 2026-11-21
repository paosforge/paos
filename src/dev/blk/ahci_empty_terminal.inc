; Passive terminal consumer of FS original post-EBS acquisition ABI32x192.
; No producer mutation, allocator access, foreign DMA dereference or Flush.
; Main terminal owns original admission, all32 preflight and irreversible latch.
ahci_empty_terminal_scan:
    xor r14d,r14d
.next:
    xor r10d,r10d
    mov edi,r14d
    call ahci_empty_owner_get
    jc .refused
    mov r10,rax
    cmp dword [r10],0
    jne .attempted
    ; Unseen means every original retained byte is zero, not schema alone.
    mov rdi,r10
    mov ecx,192/8
.zero:
    cmp qword [rdi],0
    jne .refused
    add rdi,8
    loop .zero
    jmp .advance
.attempted:
    call ahci_terminal_quiesce.record
    cmp dword [r12+4],2
    jne .refused                           ; no physical overlap with a registered disk
    mov dword [r12+4],3
    mov eax,[r10+4]
    mov [r12+20],eax                        ; actual producer state, never logical disk slot
    mov eax,[r10]
    mov [r12+24],eax                        ; actual producer schema
    mov eax,[r10+12]
    mov [r12+28],eax                        ; actual producer availability
    mov eax,[r10+144]
    mov [r12+32],eax                        ; actual acquisition issued-write count
    mov rax,[r10+64]
    mov [r12+36],rax                        ; expected native CL IOVA, full64
    mov rax,[r10+80]
    mov [r12+44],rax                        ; expected native FIS IOVA, full64
    mov rax,[r10+16]
    mov [r12+68],rax                        ; original acquisition generation, full64
    mov eax,[r10+148]
    mov [r12+108],eax                       ; original acquisition stage (not CMDcr)
    mov eax,[r10+104]
    mov [r12+144],eax                       ; original pre-acquisition CMD
    or dword [r12+16],8192                  ; actual producer snapshot is available
    lea eax,[r14+1]
    mov [r13+112],eax
    call ahci_empty_terminal_validate
    jc .refused
    test dword [r13+16],16384
    jnz .same_cap2
    mov eax,[r10+156]
    mov [r13+8],eax
.same_cap2:
    mov eax,[r10+156]
    cmp eax,[r13+8]
    jne .refused
    bts r15d,r14d
    jc .refused
    or dword [r13+16],16384              ; validated acquired-empty RAM exists
.advance:
    inc r14d
    cmp r14d,32
    jb .next
    mov dword [r13+112],0
    clc
    ret
.refused:
    mov eax,-1
    ; Earlier real acquisition effects cannot be reported as before-effect.
    test r10,r10
    jz .bad
    cmp dword [r10+4],2
    je .uncertain
    cmp dword [r10+4],4
    je .uncertain
    cmp dword [r10+144],0
    jne .uncertain
    cmp qword [r10+56],0
    je .bad
.uncertain:
    mov eax,-2
.bad:
    stc
    ret

; R10 original row/R14 physical. RAM only, before any terminal MMIO.
ahci_empty_terminal_validate:
    cmp dword [r10],1
    jne .bad
    cmp dword [r10+4],3
    jne .bad
    cmp [r10+8],r14d
    jne .bad
    cmp dword [r10+12],15
    jne .bad
    mov rax,[r10+16]
    test rax,rax
    jz .bad
    cmp rax,[rel ahci_empty_owner_generation]
    jne .bad
    mov rax,[r10+24]
    cmp rax,[r13+64]
    jne .bad
    cmp byte [rel ahci_claim_legacy],1
    jne .bad
    cmp byte [rel ahci_vmd_child],0
    jne .bad
    mov eax,[r13+44]
    shl eax,8
    mov edx,[r13+48]
    shl edx,3
    or eax,edx
    or eax,[r13+52]
    cmp eax,[r10+32]
    jne .bad
    mov eax,[r13+136]
    cmp eax,[r10+36]
    jne .bad
    mov eax,[r10+40]
    shr eax,8
    cmp eax,0x010601
    jne .bad
    mov eax,[rel ahci_cap]
    cmp eax,[r10+44]
    jne .bad
    mov eax,[rel ahci_pi]
    cmp eax,[r10+48]
    jne .bad
    bt eax,r14d
    jnc .bad
    mov eax,[r10+52]
    cmp eax,-1
    je .bad
    and eax,6
    cmp eax,6
    jne .bad
    mov rax,[r10+56]
    test rax,rax
    jz .bad
    test eax,4095
    jnz .bad
    cmp rax,[r10+64]
    jne .bad
    mov rdx,rax
    add rdx,4095
    jc .bad
    shr rdx,32
    jz .width_ok
    test dword [r10+44],0x80000000
    jz .bad
.width_ok:
    add rax,0x400
    jc .bad
    cmp rax,[r10+72]
    jne .bad
    cmp rax,[r10+80]
    jne .bad
    mov eax,[r10+108]
    test eax,0xffff8009
    jnz .bad
    and eax,0x4010
    cmp eax,0x4010
    jne .bad
    test dword [r10+112],15
    jnz .bad
    mov eax,[r10+120]
    or eax,[r10+124]
    or eax,[r10+128]
    or eax,[r10+132]
    or eax,[r10+136]
    jnz .bad
    test dword [r10+140],0x89
    jnz .bad
    cmp dword [r10+144],5
    jb .bad
    call .stale_entry                     ; S-6 (SEC 121230): FS F4 table (b) for this port
    jc .bad
    cmp dword [r10+144],6
    jbe .writes_bound                     ; 5..6 as before, only with no clear recorded
    cmp dword [r10+144],7
    jne .bad
    test edx,edx                          ; 7 only with the one DHRS W1C recorded
    jz .bad
    or dword [r12+16],16384               ; kind3 row: accepted the F4 seventh write
    jmp .writes_ok
.writes_bound:
    test edx,edx
    jnz .bad
.writes_ok:
    cmp dword [r10+148],0
    jne .bad
    cmp dword [r10+152],200
    ja .bad
    cmp dword [r10+156],-1                ; original CAP2, FS ABI R1
    je .bad
    mov rax,[r10+160]
    sub rax,[r10+168]
    jc .bad
    cmp rax,200000
    jne .bad
    mov eax,r14d
    shl eax,7
    add rax,[r13+64]
    jc .bad
    add rax,0x100
    jc .bad
    cmp rax,[r10+176]
    jne .bad
    cmp qword [r10+184],128
    jne .bad
    clc
    ret
.bad:
    stc
    ret
; S-6 helper: EDX=1 when this port's F4 entry records the one W1C (original ==
; cleared == AEO_IS_STALE) under the same claimed HBA (ABAR, BDF), 0 when nothing
; was latched as cleared. CF1 for any other entry, another HBA or a bad query. RAM only.
.stale_entry:
    push rdi
    mov edi,r14d
    call ahci_empty_owner_is_get
    pop rdi
    jc .stale_bad
    test edx,edx
    jz .stale_none                        ; never latched: no clear possible
    mov edx,[rax+4]
    test edx,edx
    jz .stale_none                        ; latched, no W1C intent: 5..6 only
    cmp edx,AEO_IS_STALE
    jne .stale_bad
    cmp edx,[rax]
    jne .stale_bad
    lea rax,[rel ahci_empty_owner_is_table]
    mov rdx,[rax+AEO_IS_ABAR]
    cmp rdx,[r13+64]
    jne .stale_bad
    mov edx,[rax+AEO_IS_BDF]
    cmp edx,[r10+32]                      ; already bound to the terminal's bus/dev/fn
    jne .stale_bad
    mov edx,1
    clc
    ret
.stale_none:
    xor edx,edx
    clc
    ret
.stale_bad:
    stc
    ret

; Entered after original fresh policy/PCI admission and eight actual port reads.
; Tail return to original preflight/stop caller, same CF contract.
ahci_empty_terminal_check:
    mov edi,r14d
    call ahci_empty_owner_get
    jc .bad
    mov r10,rax
    call ahci_empty_terminal_validate
    jc .bad
    mov eax,[r13+144]
    cmp eax,[r10+40]
    jne .bad
    mov eax,[r13+80]
    cmp eax,[r10+44]
    jne .bad
    mov eax,[r13+84]
    cmp eax,[r10+48]
    jne .bad
    mov rax,[r10+16]
    cmp rax,[r12+68]
    jne .bad
    mov rax,[r10+64]
    cmp rax,[r12+36]
    jne .bad
    mov rax,[r10+80]
    cmp rax,[r12+44]
    jne .bad
    test dword [r12+76],15                ; DET0 is no disk, not physical PCI absence
    jnz .bad
    cmp dword [r12+84],0
    jne .bad
    test dword [r12+96],0x89              ; exact empty acquisition predicate, no Flush claim
    jnz .bad
    cmp dword [r12+100],0
    jne .bad
    test dword [r12+104],0xffff8009       ; no ST/CR/CLO/unknown command mode
    jnz .bad
%macro AET_READ 2
    mov esi,r14d
    shl esi,7
    add esi,0x100+%1
    call ahci_terminal_quiesce.read
    jc .bad
    mov [r12+%2*4],eax
%endmacro
    AET_READ 0x10,35
    test eax,eax
    jnz .bad
    AET_READ 0x00,13
    AET_READ 0x04,14
    mov rax,[r12+52]
    cmp rax,[r12+36]
    jne .bad
    AET_READ 0x08,15
    AET_READ 0x0c,16
    mov rax,[r12+60]
    cmp rax,[r12+44]
    jne .bad
    or dword [r12+16],4
    clc
    ret
%unmacro AET_READ 2
.bad:
    stc
    ret

; Optional firmware ownership is distinct from successful ExitBootServices.
; Called after original native policy/PCI/MSE admission, before each effect.
; No BOHC write or invented handoff; BOH1 requires existing actual OS ownership.
ahci_empty_terminal_firmware_admit:
    mov esi,0x24
    call ahci_terminal_quiesce.read
    jc .bad
    or dword [r13+16],256                 ; current CAP2 actually observed
    cmp eax,-1
    je .bad
    cmp eax,[r13+8]                       ; exact original acquisition CAP2
    jne .bad
    test eax,1
    jz .ok
    mov esi,0x28
    call ahci_terminal_quiesce.read
    jc .bad
    mov [r13+132],eax
    or dword [r13+16],512                 ; actual BOHC available only where BOH1
    and eax,0x13
    cmp eax,2                            ; OOS1/BOS0/BB0
    jne .bad
.ok:
    clc
    ret
.bad:
    stc
    ret
