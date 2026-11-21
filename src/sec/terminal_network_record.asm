;; MODULE sec/terminal_network_record
;; LAYER 6
;; EXPORTS terminal_network_record_preebs, terminal_network_record_after_owner_preebs, terminal_network_record_header, terminal_network_record_seal, terminal_network_record_open
;; IMPORTS sec/owner_stage_key, sec/owner_store, sec/terminal_network_gate, core/reset_wipe, core/smp, svc/command, core/lib/hmac_sha256
;; OWNER rc-codex-av
;; CONTEXT: bsp_only
; Native record authentication, NOT Save/consent, DATA I/O or rollback protection.
; Caller supplies mapped, immutable-for-call native spans; no guest pointers.
; Calls never yield. Runtime APIs refuse AP/command/remote/reentrancy unchanged.
; Store/Settings must separately prove actual local human consent, exact DATA
; purpose, fresh policy revision, once-only write and authenticated readback.
TNR_BYTES equ 4192
TNR_MAC equ 4160
TNR_MAGIC equ 0x47464354454e5450       ; PTNETCFG

; Fixed boot call before owner_store discards Z. Never exports the derived key.
terminal_network_record_preebs:
    sub rsp,8
    call tnr_local
    test eax,eax
    jz .out
    lea rdi,[rel tnr_private_begin]
    xor eax,eax
    mov ecx,tnr_private_end-tnr_private_begin
    cld
    rep stosb
    lea rdi,[rel tnr_info]
    mov esi,tnr_info.len
    lea rdx,[rel tnr_seed]
    call owner_stage_key_hkdf
    cmp eax,1
    sete byte [rel tnr_seed_ready]
.out:
    add rsp,8
    ret

; Fixed boot call immediately after the committed owner pass. Snapshot the52
; sealed handoff bytes, never consume or modify principal's one-shot handoff.
terminal_network_record_after_owner_preebs:
    sub rsp,8
    call tnr_local
    test eax,eax
    jz .out
    mov byte [rel tnr_ready],0
    cmp byte [rel reset_wipe_done],0
    jne .wipe
    cmp byte [rel tnr_seed_ready],1
    jne .wipe
    cmp byte [rel ows_state],1
    jne .wipe
    cmp byte [rel ows_zbound],1
    jne .wipe
    cmp byte [rel ows_pw_ready],1
    jne .wipe
    cmp dword [rel ows_pw_handoff],0
    je .wipe
    mov rax,[rel ows_generation]
    test rax,rax
    jz .wipe
    cmp rax,-1
    je .wipe
    mov [rel tnr_generation],rax
    mov [rel tnr_owner_input+52],rax
    lea rdi,[rel tnr_owner_input]
    lea rsi,[rel ows_pw_handoff]
    mov ecx,52
    cld
    rep movsb
    lea rdi,[rel tnr_key]
    lea rsi,[rel tnr_seed]
    mov edx,32
    lea rcx,[rel tnr_owner_input]
    mov r8d,60
    call hmac_sha256
    test rax,rax
    jnz .wipe
    lea rdi,[rel tnr_binding]
    lea rsi,[rel tnr_key]
    mov edx,32
    lea rcx,[rel tnr_bind_info]
    mov r8d,tnr_bind_info.len
    call hmac_sha256
    test rax,rax
    jnz .wipe
    cmp byte [rel reset_wipe_done],0
    jne .wipe
    mov rax,[rel ows_generation]
    cmp rax,[rel tnr_generation]
    jne .wipe
    cmp byte [rel ows_state],1
    jne .wipe
    cmp byte [rel ows_zbound],1
    jne .wipe
    mov byte [rel tnr_ready],1
.wipe:
    lea rdi,[rel tnr_seed]
    xor eax,eax
    mov ecx,32
    rep stosb
    lea rdi,[rel tnr_owner_input]
    mov ecx,60
    rep stosb
    mov byte [rel tnr_seed_ready],0
    cmp byte [rel tnr_ready],1
    je .out
    call tnr_erase_key
.out:
    add rsp,8
    ret

; header(RDI out64,ESI count0..16,RDX revision1..MAX-1)->1/0.
; Output unchanged on refusal. Produces identity fields, never grants Save.
terminal_network_record_header:
    push r12
    push r13
    push r14
    mov r12,rdi
    mov r13d,esi
    mov r14,rdx
    cmp r13d,16
    ja .no
    test r14,r14
    jz .no
    cmp r14,-1
    je .no
    mov esi,64
    call tnr_span
    test eax,eax
    jz .no
    call tnr_enter
    test eax,eax
    jz .no
    lea rdi,[rel tnr_header]
    xor eax,eax
    mov ecx,8
    cld
    rep stosq
    mov rax,TNR_MAGIC
    mov [rel tnr_header],rax
    mov word [rel tnr_header+8],1
    mov word [rel tnr_header+10],TNR_BYTES
    mov [rel tnr_header+12],r13w
    mov rax,[rel tnr_generation]
    mov [rel tnr_header+16],rax
    mov [rel tnr_header+24],r14
    lea rsi,[rel tnr_binding]
    lea rdi,[rel tnr_header+32]
    mov ecx,4
    rep movsq
    call tnr_current               ; final identity before publication
    test eax,eax
    jz .failed
    mov rdi,r12
    lea rsi,[rel tnr_header]
    mov ecx,8
    rep movsq
    mov r14d,1
    jmp .leave
.failed:
    xor r14d,r14d
.leave:
    call tnr_leave
    mov eax,r14d
    jmp .out
.no:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    ret

; seal(RDI native record,ESI exact4192)->1/0. Write only final32 MAC bytes
; after complete shape and owner checks; all other bytes remain untouched.
terminal_network_record_seal:
    push r12
    push r13
    push r14
    xor r14d,r14d
    jmp tnr_record
; open(RDI native record,ESI exact4192)->1/0; read-only, no cached grant.
terminal_network_record_open:
    push r12
    push r13
    push r14
    mov r14d,1
; Common entry: r14=0 seal/1 open. R12 original native record; no pointer saved
; beyond this bounded call. Scratch wiped on every admitted outcome.
tnr_record:
    mov r12,rdi
    cmp esi,TNR_BYTES
    jne .no
    call tnr_span
    test eax,eax
    jz .no
    call tnr_enter
    test eax,eax
    jz .no
    call tnr_shape
    test eax,eax
    jz .failed
    lea rdi,[rel tnr_mac]
    lea rsi,[rel tnr_key]
    mov edx,32
    mov rcx,r12
    mov r8d,TNR_MAC
    call hmac_sha256
    test rax,rax
    jnz .failed
    test r14d,r14d
    jz .final
    lea rdi,[rel tnr_mac]
    lea rsi,[r12+TNR_MAC]
    xor eax,eax
    xor ecx,ecx
.compare:
    mov dl,[rdi+rcx]
    xor dl,[rsi+rcx]
    or al,dl
    inc ecx
    cmp ecx,32                    ; complete authenticator
    jb .compare
    test al,al
    jnz .failed
.final:
    call tnr_current
    test eax,eax
    jz .failed
    test r14d,r14d
    jnz .ok
    lea rdi,[r12+TNR_MAC]
    lea rsi,[rel tnr_mac]
    mov ecx,4
    cld
    rep movsq
.ok:
    mov r13d,1
    jmp .leave
.failed:
    xor r13d,r13d
.leave:
    call tnr_leave
    mov eax,r13d
    jmp .out
.no:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    ret

; Complete representation, including unused slots, before MAC success/seal.
; Slots compare by host bytes lexicographically (never by length byte).
tnr_shape:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov rax,TNR_MAGIC
    cmp [r12],rax
    jne .bad
    cmp word [r12+8],1
    jne .bad
    cmp word [r12+10],TNR_BYTES
    jne .bad
    cmp word [r12+12],16
    ja .bad
    cmp word [r12+14],0
    jne .bad
    mov rax,[rel tnr_generation]
    cmp [r12+16],rax
    jne .bad
    mov rax,[r12+24]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    xor ecx,ecx
    xor eax,eax
    lea rdi,[rel tnr_binding]
.binding:
    mov dl,[r12+rcx+32]
    xor dl,[rdi+rcx]
    or al,dl                       ; bind current committed owner
    inc ecx
    cmp ecx,32
    jb .binding
    test al,al
    jnz .bad
    xor ebx,ebx
    lea r13,[r12+64]
    xor r14d,r14d                  ; previous slot (none initially)
.row:
    movzx ebp,word [r12+12]
    cmp ebx,ebp
    jae .unused
    movzx r15d,byte [r13]
    test r15d,r15d
    jz .bad
    cmp r15d,253
    ja .bad
    lea rdi,[rel tnr_canon]
    lea rsi,[r13+1]
    mov edx,r15d
    call terminal_network_host_canon
    cmp eax,r15d
    jne .bad
    lea rdi,[rel tnr_canon]
    lea rsi,[r13+1]
    mov ecx,r15d
    cld
    repe cmpsb                     ; no upper-case aliases
    jne .bad
    lea ecx,[r15d+1]
.padding:
    cmp byte [r13+rcx],0
    jne .bad
    inc ecx
    cmp ecx,256
    jb .padding
    test r14,r14
    jz .next
    movzx edx,byte [r14]
    xor ecx,ecx
.lex:
    cmp ecx,edx
    jae .prefix
    cmp ecx,r15d
    jae .bad                       ; current is shorter equal prefix
    mov al,[r14+rcx+1]
    cmp al,[r13+rcx+1]
    jb .next                       ; strictly increasing ASCII names
    ja .bad
    inc ecx
    jmp .lex
.prefix:
    cmp edx,r15d
    jae .bad                       ; duplicate or decreasing prefix
.next:
    mov r14,r13
    jmp .advance
.unused:
    xor ecx,ecx
.zero:
    cmp byte [r13+rcx],0
    jne .bad
    inc ecx
    cmp ecx,256
    jb .zero
.advance:
    add r13,256
    inc ebx
    cmp ebx,16
    jb .row
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop rbp
    pop rbx
    ret

; Caller owns mapping. Reject null, wrap and any private overlap before access.
tnr_span:
    test rdi,rdi
    jz .bad
    mov rax,rdi
    add rax,rsi
    jc .bad
    lea rdx,[rel tnr_private_end]
    cmp rdi,rdx
    jae .ok
    lea rdx,[rel tnr_private_begin]
    cmp rax,rdx
    ja .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; No foreign context writes ANY private state, including busy/scratch/key.
tnr_local:
    sub rsp,8
    call smp_current_logical
    add rsp,8
    test eax,eax
    jnz .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

tnr_enter:
    sub rsp,8
    call tnr_local
    test eax,eax
    jz .bad
    cmp byte [rel tnr_busy],0
    jne .bad
    call tnr_current
    test eax,eax
    jz .bad
    mov byte [rel tnr_busy],1
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    ret

tnr_current:
    sub rsp,8
    call tnr_local
    test eax,eax
    jz .out
    cmp byte [rel reset_wipe_done],0
    jne .erase
    cmp byte [rel tnr_ready],1
    jne .erase
    cmp byte [rel ows_state],1
    jne .erase
    cmp byte [rel ows_zbound],1
    jne .erase
    mov rax,[rel ows_generation]
    cmp rax,[rel tnr_generation]
    jne .erase
    mov eax,1
    jmp .out
.erase:
    call tnr_erase_key
    xor eax,eax
.out:
    add rsp,8
    ret

tnr_erase_key:
    lea rdi,[rel tnr_key]
    xor eax,eax
    mov ecx,64                     ; key plus public owner binding
    cld
    rep stosb
    mov byte [rel tnr_ready],0
    mov qword [rel tnr_generation],0
    ret

tnr_leave:
    lea rdi,[rel tnr_scratch_begin]
    xor eax,eax
    mov ecx,tnr_scratch_end-tnr_scratch_begin
    cld
    rep stosb
    mov byte [rel tnr_busy],0
    ret

tnr_info: db 'PaOS/sec/terminal_network/v1'
.len equ $-tnr_info
tnr_bind_info: db 'PaOS/sec/terminal_network/owner-binding/v1'
.len equ $-tnr_bind_info
%include "core/abi/wdata.inc"
%macro WDATA_BSS_sec_terminal_network_record 0
alignb 8
tnr_private_begin:
tnr_seed: resb 32
tnr_key: resb 32
tnr_binding: resb 32
tnr_owner_input: resb 60
tnr_generation: resq 1
tnr_seed_ready: resb 1
tnr_ready: resb 1
tnr_busy: resb 1
    resb (-($-tnr_private_begin)) & 7 ; explicit BSS padding inside reset-wipe range
tnr_scratch_begin:
tnr_header: resb 64
tnr_canon: resb 256
tnr_mac: resb 32
tnr_scratch_end:
tnr_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_terminal_network_record
