;; MODULE bootmgr/recovery_grant
;; LAYER 0
;; EXPORTS r5_grant_valid, r5_grant_digest, r5_request_valid, r5_source_valid, r5_zero, r5_equal, r5_grant, r5_request
;; IMPORTS core/lib/sha256, bootmgr/rsa2048_verify
;; CAPS
;; OWNER saga:boot
; Shared native/Manager pure validation. No I/O, journal mutation, timer,
; enrollment or authority from a CRC. r5_owner_modulus is the compiled owner
; key in each link unit. The Manager must additionally verify its independent
; signed Rescue descriptor/payload before launch.
%include "boot/recovery_contract.inc"

; RDI=start, ECX=count. EAX=1 iff all zero. Pointer/count clobbered.
r5_zero:
    xor eax,eax
.loop:
    test ecx,ecx
    jz .yes
    cmp byte [rdi],0
    jne .out
    inc rdi
    dec ecx
    jmp .loop
.yes:
    inc eax
.out:
    ret
; RDI/RSI bounded buffers, ECX=count. 1 iff equal, pointers clobbered.
r5_equal:
    repe cmpsb
    sete al
    movzx eax,al
    ret

; EAX=1 iff canonical structure AND actual owner signature. No bypass macro.
r5_grant_valid:
    push rbx
    lea rbx,[rel r5_grant]
    mov rax,R5_MAGIC
    cmp [rbx],rax
    jne .no
    cmp word [rbx+8],R5_VERSION
    jne .no
    cmp word [rbx+10],R5_GRANT_SIZE
    jne .no
    cmp byte [rbx+12],R5_CURRENT
    jb .no
    cmp byte [rbx+12],R5_NEXT
    ja .no
    cmp byte [rbx+13],PBM_ENTRY_PAOS_A
    jb .no
    cmp byte [rbx+13],PBM_ENTRY_PAOS_B
    ja .no
    cmp byte [rbx+14],2
    jb .no
    cmp byte [rbx+14],R5_COMPONENT_COUNT
    ja .no
    cmp byte [rbx+15],0
    jne .no
    cmp qword [rbx+R5_OP],0
    je .no
    cmp qword [rbx+R5_EXPECTED_GEN],0
    je .no
    cmp qword [rbx+R5_EXPECTED_GEN],-1
    je .no
    cmp qword [rbx+R5_SEQUENCE],0
    je .no
    cmp dword [rbx+R5_SOFT],R5_SOFT_SECONDS
    jne .no
    cmp dword [rbx+R5_HARD],R5_HARD_SECONDS
    jne .no
    cmp dword [rbx+R5_HEARTBEAT],R5_HEARTBEAT_SECONDS
    jne .no
    cmp byte [rbx+12],R5_NEXT
    jne .current
    cmp qword [rbx+R5_NONCE],0
    jne .no
    jmp .node
.current:
    ; Zero nonce is a prelaunch manual-arm grant: Manager MUST durably bind
    ; the fresh exact nonce/generation; it never auto-arms (NEXT alone does).
.node:
    lea rdi,[rbx+R5_NODE_UUID]
    mov ecx,16
    call r5_zero
    test eax,eax
    jnz .no
    mov rax,[rbx+R5_NODE_UUID]
    and rax,[rbx+R5_NODE_UUID+8]
    cmp rax,-1
    je .no
    cmp qword [rbx+R5_RESCUE_SIZE],4096
    jb .no
    cmp qword [rbx+R5_RESCUE_SIZE],0x1000000
    ja .no
    cmp word [rbx+R5_MEDIUM_LEN],4
    jb .no
    cmp word [rbx+R5_MEDIUM_LEN],512
    ja .no
    movzx ecx,word [rbx+R5_MEDIUM_LEN]
    lea rdi,[rbx+R5_MEDIUM]
    call r5_device_path_valid
    test eax,eax
    jz .no
    movzx eax,word [rbx+R5_MEDIUM_LEN]
    lea rdi,[rbx+rax+R5_MEDIUM]
    mov ecx,512
    sub ecx,eax
    call r5_zero
    test eax,eax
    jz .no
    cmp word [rbx+R5_OPTION_LEN],12
    jb .no
    cmp word [rbx+R5_OPTION_LEN],768
    ja .no
    cmp dword [rbx+220],0
    jne .no
    movzx eax,word [rbx+R5_OPTION_LEN]
    lea rdi,[rbx+rax+R5_OPTION]
    mov ecx,768
    sub ecx,eax
    call r5_zero
    test eax,eax
    jz .no
    ; Every full path is UTF-16, rooted, NUL-terminated, no trailing bytes.
    xor r8d,r8d
.component:
    imul edx,r8d,R5_COMPONENT_SIZE
    lea r9,[rbx+rdx+R5_COMPONENTS]
    cmp r8b,[rbx+14]
    jae .unused
    cmp qword [r9],4096
    jb .no
    cmp qword [r9],0x1000000
    ja .no
    lea rdi,[r9+8]
    mov ecx,32
    call r5_zero
    test eax,eax
    jnz .no
    cmp word [r9+40],0x5c
    jne .no
    mov ecx,1
.path:
    cmp ecx,128
    jae .no
    cmp word [r9+rcx*2+40],0
    je .tail
    ; A dot is allowed in file names, but never a relative path segment.
    cmp word [r9+rcx*2+40],'.'
    jne .character
    cmp word [r9+rcx*2+38],0x5c
    jne .character
    cmp word [r9+rcx*2+42],'.'
    je .no
    cmp word [r9+rcx*2+42],0x5c
    je .no
.character:
    inc ecx
    jmp .path
.tail:
    lea rdi,[r9+rcx*2+40]
    mov eax,ecx
    add eax,eax
    mov ecx,264
    sub ecx,eax
    call r5_zero
    test eax,eax
    jz .no
    jmp .next
.unused:
    mov rdi,r9
    mov ecx,R5_COMPONENT_SIZE
    call r5_zero
    test eax,eax
    jz .no
.next:
    inc r8d
    cmp r8d,R5_COMPONENT_COUNT
    jb .component
    lea rdi,[rbx+R5_COMPONENTS+R5_COMPONENT_SIZE*R5_COMPONENT_COUNT]
    mov ecx,R5_SIGNED_SIZE-R5_COMPONENTS-R5_COMPONENT_SIZE*R5_COMPONENT_COUNT
    call r5_zero
    test eax,eax
    jz .no
    lea rdi,[rbx+R5_SIGNATURE_OFF]
    mov rsi,rbx
    mov edx,R5_SIGNED_SIZE
    lea rcx,[rel r5_owner_modulus]
    call rsa2048_verify_sha256
    test eax,eax
    jnz .no
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop rbx
    ret

; Complete nonempty single-instance device path ending exactly in END_ENTIRE.
; No END_INSTANCE, no truncated/zero/overflowing node. ECX exact signed size.
r5_device_path_valid:
    xor eax,eax
.node:
    cmp ecx,4
    jb .out
    movzx edx,word [rdi+2]
    cmp edx,4
    jb .out
    cmp edx,ecx
    ja .out
    cmp byte [rdi],0x7f
    je .end
    add rdi,rdx
    sub ecx,edx
    jmp .node
.end:
    cmp dword [rdi],0x0004ff7f
    jne .out
    cmp ecx,4
    sete al
.out:
    ret

r5_grant_digest:
    lea rdi,[rel r5_digest]
    lea rsi,[rel r5_grant]
    mov edx,R5_GRANT_SIZE
    call sha256_hash
    test rax,rax
    sete al
    movzx eax,al
    ret

; r5_source_state points to a validated newest journal (caller handles CRC,
; generation ambiguity, manifest floor and signed manifest). This is the exact
; source attempt, BEFORE health or any ordinary attempt processing.
r5_source_valid:
    push rbx
    mov rbx,[rel r5_source_state]
    test rbx,rbx
    jz .no
    cmp byte [rbx+PBM_STATE_BIP_OFF],1
    jne .no
    cmp byte [rbx+PBM_STATE_LAST_PROFILE_OFF],PBM_PROFILE_NORMAL
    jne .no
    cmp byte [rbx+PBM_STATE_PENDING_ENTRY_OFF],PBM_ENTRY_NONE
    jne .no
    cmp byte [rbx+PBM_STATE_EXTERNAL_PENDING_OFF],0
    jne .no
    mov al,[rel r5_grant+13]
    cmp [rbx+PBM_STATE_LAST_ENTRY_OFF],al
    jne .no
    mov rax,[rel r5_grant+R5_SEQUENCE]
    cmp [rbx+PBM_STATE_MANIFEST_SEQ_OFF],rax
    jne .no
    lea rdi,[rel r5_grant+R5_MANIFEST_SHA]
    lea rsi,[rbx+PBM_STATE_MANIFEST_SHA_OFF]
    mov ecx,32
    call r5_equal
    test eax,eax
    jz .no
    cmp byte [rel r5_grant+12],R5_NEXT
    je .next
    cmp qword [rel r5_grant+R5_NONCE],0
    je .next                         ; prelaunch CURRENT requires the same durable binding
    mov rax,[rel r5_grant+R5_EXPECTED_GEN]
    cmp rax,[rbx+PBM_STATE_GENERATION_OFF]
    jne .no
    mov rax,[rel r5_grant+R5_NONCE]
    cmp rax,[rbx+PBM_STATE_ATTEMPT_NONCE_OFF]
    jne .no
    ; A monotonic operation high water is never lowered/reused.
    cmp dword [rbx+R5_STATE_MAGIC_OFF],R5_STATE_MAGIC
    jne .yes
    mov rax,[rel r5_grant+R5_OP]
    cmp rax,[rbx+R5_STATE_OP]
    jbe .no
    jmp .yes
.next:
    cmp dword [rbx+R5_STATE_MAGIC_OFF],R5_STATE_MAGIC
    jne .no
    cmp dword [rbx+R5_STATE_STATUS],R5_STATE_BOUND
    jne .no
    mov rax,[rel r5_grant+R5_OP]
    cmp rax,[rbx+R5_STATE_OP]
    jne .no
    mov rax,[rbx+PBM_STATE_GENERATION_OFF]
    cmp rax,[rbx+R5_STATE_GEN]
    jne .no
    mov rax,[rbx+PBM_STATE_ATTEMPT_NONCE_OFF]
    cmp rax,[rbx+R5_STATE_NONCE]
    jne .no
    lea rdi,[rel r5_digest]
    lea rsi,[rbx+R5_STATE_DIGEST]
    mov ecx,32
    call r5_equal
    test eax,eax
    jz .no
.yes:
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop rbx
    ret

; Caller independently verifies owner grant, actual medium/route/node,
; descriptor/payload and source state. CRC is only consistency protection.
r5_request_valid:
    mov rax,R5_REQUEST_MAGIC
    cmp [rel r5_request],rax
    jne .no
    mov rax,[rel r5_source_state]
    test rax,rax
    jz .no
    mov rdx,[rax+PBM_STATE_ATTEMPT_NONCE_OFF]
    cmp [rel r5_request+8],rdx
    jne .no
    mov rdx,[rax+PBM_STATE_GENERATION_OFF]
    cmp [rel r5_request+16],rdx
    jne .no
    mov rdx,[rel r5_grant+R5_OP]
    cmp [rel r5_request+24],rdx
    jne .no
    lea rdi,[rel r5_request+32]
    lea rsi,[rel r5_digest]
    mov ecx,32
    call r5_equal
    test eax,eax
    jz .no
    lea rdi,[rel r5_request+64]
    mov ecx,R5_REQUEST_CRC-64
    call r5_zero
    test eax,eax
    jz .no
    lea rdi,[rel r5_request]
    mov esi,R5_REQUEST_CRC
    call r5_crc32
    cmp eax,[rel r5_request+R5_REQUEST_CRC]
    jne .no
    jmp r5_source_valid
.no:
    xor eax,eax
    ret

%macro R5_GRANT_DATA 0
align 8
r5_grant: times R5_GRANT_SIZE db 0
r5_request: times R5_REQUEST_SIZE db 0
r5_digest: times 32 db 0
r5_source_state: dq 0
%endmacro
%ifndef R5_MANAGER_LINK
%include "core/abi/wdata.inc"
WDATA_DEFER R5_GRANT_DATA
%endif
