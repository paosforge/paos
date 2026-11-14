;; MODULE svc/app_script
;; LAYER 5
;; EXPORTS app_script_stage, app_script_descriptor, app_script_native_descriptor, app_script_copy, app_script_retire, app_script_members
;; IMPORTS svc/app_bundle, core/lib/sha256, bootmgr/rsa2048_verify, core/heap, sec/session, core/smp
;; CAPS
;; OWNER saga:command
; Signed container-2 bash DATA, never native code or a VM identity assertion.
; Native BSP/non-yielding callers only; VFS must supply native-owned bytes.
; Snapshot storage is private: no pointer escapes, no caller buffer retained.
; VM must separately enforce an isolated instance, START and retirement binding.

AS_MAX equ 65536
AS_DESC equ 384

; RDI native bytes, RSI exact length -> RAX fresh snapshot handle, or zero.
; Two private heap buffers: failed verify/parse cannot replace a valid snapshot.
app_script_stage:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    call smp_current_logical
    test eax,eax
    jnz .refuse
    cmp byte [rel as_busy],0
    jne .refuse
    mov byte [rel as_busy],1
    test r12,r12
    jz .fail
    cmp r13,AS_MAX
    ja .fail
    cmp r13,656                     ; header + manifest + two rows + signature
    jb .fail
    call session_shell_require_unlocked
    test eax,eax
    jnz .fail
    mov r15,[rel session_authority_epoch]
    test r15,r15
    jz .fail
    cmp qword [rel as_sequence],-1
    je .fail
    cmp qword [rel as_stage],0
    jne .allocated
    mov edi,2*AS_MAX
    call kmalloc
    test rax,rax
    jz .fail
    mov [rel as_stage],rax
    add rax,AS_MAX
    mov [rel as_resident],rax
.allocated:
    mov rdi,[rel as_stage]
    mov rsi,r12
    mov rcx,r13
    cld
    rep movsb                      ; copy BEFORE verify; source is never reused
    mov r12,[rel as_stage]
    call as_verify
    test eax,eax
    jz .fail
    ; Trust/epoch still current at publication. No callbacks or yields below.
    call session_shell_require_unlocked
    test eax,eax
    jnz .fail
    cmp r15,[rel session_authority_epoch]
    jne .fail
    lea rdi,[r12+48]
    call app_trust_find
    test rax,rax
    jz .fail
    lea rdi,[rel as_digest]
    mov rsi,r12
    mov rdx,r13
    call sha256_hash
    mov rax,[rel as_resident]
    mov [rel as_stage],rax
    mov [rel as_resident],r12
    inc qword [rel as_sequence]     ; nonwrapping native handle, not bundle proof
    mov rax,[rel as_sequence]
    mov [rel as_handle],rax
    mov [rel as_epoch],r15
    mov rdx,[rel session_bound_pid]
    mov [rel as_owner],rdx          ; native session owner, never ambient request PID
    mov [rel as_length],r13
    call as_wipe_stage
    mov rax,[rel as_handle]
    mov byte [rel as_busy],0
    jmp .out
.fail:
    call as_wipe_stage
    mov byte [rel as_busy],0
.refuse:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; R12 private stage, R13 exact bounded size -> EAX boolean.
; Only header/bounds/trusted key are touched before the strict RSA check.
as_verify:
    mov rax,'PAOSAPP1'
    cmp [r12],rax
    jne .bad
    cmp dword [r12+8],0x00400002
    jne .bad
    cmp [r12+12],r13d
    jne .bad
    cmp dword [r12+16],64
    jne .bad
    cmp dword [r12+20],256
    jne .bad
    cmp dword [r12+24],320
    jne .bad
    mov eax,[r12+28]
    cmp eax,160
    jb .bad
    cmp eax,1280
    ja .bad
    xor edx,edx
    mov ecx,80
    div ecx
    test edx,edx
    jnz .bad
    mov ebx,eax                    ; bounded count, at least script + grants
    mov eax,[r12+28]
    add eax,320
    cmp [r12+32],eax
    jne .bad
    mov edx,[r12+36]
    cmp edx,AS_MAX
    ja .bad
    add eax,edx
    mov r14d,eax                   ; signature offset, sums cannot wrap
    add eax,256
    cmp eax,r13d
    jne .bad
    cmp qword [r12+40],0
    jne .bad
    lea rdi,[r12+48]
    call app_trust_find
    test rax,rax
    jz .bad
    mov rcx,rax
    lea rdi,[r12+r14]
    mov rsi,r12
    mov edx,r14d
    call rsa2048_verify_sha256
    test eax,eax
    jnz .bad
    mov rax,'BASHAPP1'
    cmp [r12+64],rax
    jne .bad
    jmp app_script_members
.bad:
    xor eax,eax
    ret

; Internal checked-manifest parser. Callers must authenticate the complete
; envelope before this entry. R12 immutable bytes, header extents already checked.
; Existing trusted stage and separate sharing candidate use the same role rules.
app_script_members:
    mov rax,0x100000001
    cmp [r12+72],rax                ; contract1/runtime bash1
    jne .bad
    cmp [r12+304],rax               ; forms1/verbs1
    jne .bad
    cmp qword [r12+312],0
    jne .bad
    lea rdi,[r12+80]
    mov ecx,64
    mov edx,1                      ; id grammar
    call as_text
    test eax,eax
    jz .bad
    lea rdi,[r12+144]
    mov ecx,64
    xor edx,edx
    call as_text
    test eax,eax
    jz .bad
    cmp byte [r12+208],0
    jne .icon_path
    lea rdi,[r12+208]
    mov ecx,64
    xor eax,eax
    repe scasb
    jne .bad
    jmp .data_path
.icon_path:
    lea rdi,[r12+208]
    mov ecx,64
    xor edx,edx
    call as_text
    test eax,eax
    jz .bad
.data_path:
    lea rdi,[r12+272]
    mov ecx,32
    xor edx,edx
    call as_text
    test eax,eax
    jz .bad
    mov dword [rel as_counts],0
    mov qword [rel as_counts+4],0
    mov qword [rel as_counts+12],0
    mov dword [rel as_counts+20],0
    mov r14d,[r12+24]
    add r14,r12
    xor r10d,r10d                  ; contiguous asset offset
.member:
    mov eax,[r14]
    cmp eax,1
    jb .bad
    cmp eax,5
    ja .bad
    cmp dword [r14+12],0
    jne .bad
    lea rcx,[rel as_counts]
    inc dword [rcx+rax*4]
    cmp [r14+4],r10d
    jne .bad
    mov r11d,[r14+8]
    test r11d,r11d
    jz .bad
    cmp r11d,8192
    ja .bad
    add r10d,r11d
    cmp r10d,[r12+36]
    ja .bad
    lea rdi,[r14+16]
    mov ecx,64
    xor edx,edx
    call as_text
    test eax,eax
    jz .bad
    ; Full canonical path uniqueness, not merely role uniqueness.
    mov r8d,[r12+24]
    add r8,r12
.duplicate:
    cmp r8,r14
    je .body
    lea rsi,[r8+16]
    lea rdi,[r14+16]
    mov ecx,64
    repe cmpsb
    je .bad
    add r8,80
    jmp .duplicate
.body:
    mov esi,[r12+32]
    add rsi,r12
    mov eax,[r14+4]
    add rsi,rax                    ; bounded exact body
    mov eax,[r14]
    cmp eax,1
    je .script
    cmp eax,2
    je .form
    cmp eax,3
    je .icon
    cmp eax,4
    je .data
    cmp dword [rel as_counts+20],1
    jne .bad
    cmp r11d,4
    jne .bad
    mov rax,'grants'
    cmp [r14+16],rax
    jne .bad
    lea rdi,[r14+24]
    mov ecx,56
    xor eax,eax
    repe scasb
    jne .bad
    mov ecx,4
.grants:
    cmp byte [rsi],2
    ja .bad
    inc rsi
    loop .grants
    jmp .next
.script:
    cmp dword [rel as_counts+4],1
    jne .bad
    lea rdi,[r12+144]
    push rsi
    lea rsi,[r14+16]
    mov ecx,64
    repe cmpsb
    pop rsi
    jne .bad
    mov edx,1                      ; bash allows TAB, forms do not
    jmp .text_body
.form:
    cmp dword [rel as_counts+8],4
    ja .bad
    cmp r11d,4096
    ja .bad
    ; Canonical path length from as_text is not retained; bounded suffix scan.
    lea rdi,[r14+16]
    xor ecx,ecx
.suffix:
    cmp byte [rdi+rcx],0
    je .suffix_end
    inc ecx
    jmp .suffix
.suffix_end:
    cmp ecx,4
    jb .bad
    cmp dword [rdi+rcx-4],'.frm'
    jne .bad
    xor edx,edx
.text_body:
    cmp byte [rsi+r11-1],10
    jne .bad
    mov ecx,r11d
.ascii:
    lodsb
    cmp al,10
    je .ascii_next
    test edx,edx
    jz .printable
    cmp al,9
    je .ascii_next
.printable:
    cmp al,32
    jb .bad
    cmp al,126
    ja .bad
.ascii_next:
    loop .ascii
    jmp .next
.icon:
    cmp dword [rel as_counts+12],1
    jne .bad
    cmp r11d,4096
    jne .bad
    lea rdi,[r12+208]
    lea rsi,[r14+16]
    mov ecx,64
    repe cmpsb
    jne .bad
    jmp .next
.data:
    lea rdi,[r12+272]
    lea rsi,[r14+16]
.namespace:
    mov al,[rdi]
    test al,al
    jz .slash
    cmp al,[rsi]
    jne .bad
    inc rdi
    inc rsi
    jmp .namespace
.slash:
    cmp byte [rsi],'/'
    jne .bad
    cmp dword [r12+40],0            ; legacy profile retains opaque data
    je .next
    mov esi,[r12+32]
    add rsi,r12
    mov eax,[r14+4]
    add rsi,rax
    mov ecx,r11d                    ; sharing data is bounded ASCII text
.data_ascii:
    lodsb
    cmp al,9
    je .data_next
    cmp al,10
    je .data_next
    cmp al,32
    jb .bad
    cmp al,126
    ja .bad
.data_next:
    loop .data_ascii
.next:
    add r14,80
    dec ebx
    jnz .member
    cmp r10d,[r12+36]
    jne .bad
    cmp dword [rel as_counts+4],1
    jne .bad
    cmp dword [rel as_counts+20],1
    jne .bad
    xor eax,eax
    cmp byte [r12+208],0
    setne al
    cmp eax,[rel as_counts+12]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Fixed NUL-padded id/path, rejects traversal/empty components/absolute paths.
; RDI bytes ECX capacity EDX id=1/path=0. Preserves RBX/R10-R15, returns bool.
as_text:
    xor eax,eax
    xor r9d,r9d
    xor r8d,r8d                    ; last char delimiter
.char:
    mov al,[rdi+r9]
    test al,al
    jz .end
    cmp al,'a'
    jb .number
    cmp al,'z'
    jbe .ordinary
.number:
    cmp al,'0'
    jb .separator
    cmp al,'9'
    jbe .ordinary
.separator:
    cmp al,'-'
    je .ordinary
    test edx,edx
    jnz .id_dot
    cmp al,'_'
    je .ordinary
    cmp al,'/'
    je .delimiter
.id_dot:
    cmp al,'.'
    jne .bad
    test edx,edx
    jnz .ordinary
.delimiter:
    test r9d,r9d
    jz .bad
    test r8d,r8d
    jnz .bad
    mov r8d,1
    jmp .advance
.ordinary:
    ; IDs must start with lower-case letter or digit.
    test edx,edx
    jz .reset
    test r9d,r9d
    jnz .reset
    cmp al,'-'
    je .bad
    cmp al,'.'
    je .bad
.reset:
    xor r8d,r8d
.advance:
    inc r9d
    cmp r9d,ecx
    jb .char
    jmp .bad
.end:
    test r9d,r9d
    jz .bad
    test r8d,r8d
    jnz .bad
    test edx,edx
    jz .padding
    cmp r9d,3
    jb .bad
.padding:
    cmp byte [rdi+r9],0
    jne .bad
    inc r9d
    cmp r9d,ecx
    jb .padding
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI handle -> EAX bool. Revoked trust/session synchronously wipes snapshot.
as_current:
    test rdi,rdi
    jz .bad
    cmp rdi,[rel as_handle]
    jne .bad
    push rbx
    call session_shell_require_unlocked
    test eax,eax
    jnz .retire
    mov rax,[rel as_epoch]
    cmp rax,[rel session_authority_epoch]
    jne .retire
    mov rbx,[rel as_resident]
    lea rdi,[rbx+48]
    call app_trust_find
    test rax,rax
    jz .retire
    mov eax,1
    pop rbx
    ret
.retire:
    call as_retire
    pop rbx
.bad:
    xor eax,eax
    ret

; RDI handle, RSI native output, RDX exact384 -> EAX1/0; no pointers serialized.
app_script_descriptor:
    push rbx
    push r12
    sub rsp,8
    mov r12,rsi
    cmp rdx,AS_DESC
    jne .bad
    call as_output
    test eax,eax
    jz .bad
    call as_current
    test eax,eax
    jz .bad
    call as_descriptor_write
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; Native VM/resolver observation only, including inside an active GUES frame.
; Same exact ABI/output discipline, but never borrows the request's principal.
; Does not stage/copy bytes, authorize a verb, install grants or expose an API
; to the guest. No yield/callback between this check and descriptor serialization.
app_script_native_descriptor:
    push rbx
    push r12
    sub rsp,8
    mov r12,rsi
    cmp rdx,AS_DESC
    jne .bad
    call as_output
    test eax,eax
    jz .bad
    call as_native_current
    test eax,eax
    jz .bad
    call as_descriptor_write
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; Check the resident's actual bound OWNER session, independent of active PID,
; remote ticket or injected-input provenance. This is observation, not authority
; to act as OWNER. Local stage/copy/descriptor keep their existing session gate.
as_native_current:
    test rdi,rdi
    jz .bad
    cmp rdi,[rel as_handle]
    jne .bad
    push rbx
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .retire
    cmp qword [rel session_key_handle],0
    je .retire
    cmp qword [rel as_owner],PRIN_OWNER
    jne .retire
    mov rax,[rel as_owner]
    cmp rax,[rel session_bound_pid]
    jne .retire
    mov rax,[rel as_epoch]
    test rax,rax
    jz .retire
    cmp rax,[rel session_authority_epoch]
    jne .retire
    cmp rax,[rel session_authority]
    jne .retire
    mov rbx,[rel as_resident]
    test rbx,rbx
    jz .retire
    lea rdi,[rbx+48]
    call app_trust_find
    test rax,rax
    jz .retire
    mov eax,1
    pop rbx
    ret
.retire:
    call as_retire
    pop rbx
.bad:
    xor eax,eax
    ret

; R12 native output already validated; caller preserves RBX/R12. Both getters
; use this exact serialization after their respective currentness check.
as_descriptor_write:
    cld
    mov rbx,[rel as_resident]
    mov rdi,r12
    xor eax,eax
    mov ecx,AS_DESC/8
    rep stosq
    mov qword [r12],1
    mov rax,[rel as_handle]
    mov [r12+8],rax
    mov rax,[rel as_length]
    mov [r12+16],rax
    mov eax,[rbx+28]
    xor edx,edx
    mov ecx,80
    div ecx
    mov [r12+24],rax
    lea rsi,[rel as_digest]
    lea rdi,[r12+32]
    mov ecx,4
    rep movsq
    lea rsi,[rbx+48]
    mov ecx,2
    rep movsq
    lea rsi,[rbx+64]
    mov ecx,32
    rep movsq
    mov qword [r12+336],320
    mov eax,[rbx+28]
    mov [r12+344],rax
    mov eax,[rbx+32]
    mov [r12+352],rax
    mov eax,[rbx+36]
    mov [r12+360],rax
    mov qword [r12+368],1
    mov eax,1
    ret

; RDI handle, RSI offset, RDX native destination, RCX count1..AS_MAX ->1/0.
; Exact immutable bytes only; executor must revalidate handle before activation.
app_script_copy:
    push rbx
    push r12
    push r13
    mov rbx,rsi
    mov r12,rdx
    mov r13,rcx
    test rcx,rcx
    jz .bad
    cmp rcx,AS_MAX
    ja .bad
    cmp rsi,AS_MAX
    ja .bad
    lea rax,[rsi+rcx]
    cmp rax,[rel as_length]
    ja .bad
    mov rsi,r12
    mov rdx,r13
    call as_output
    test eax,eax
    jz .bad
    call as_current
    test eax,eax
    jz .bad
    mov rsi,[rel as_resident]
    add rsi,rbx
    mov rdi,r12
    mov rcx,r13
    cld
    rep movsb
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Reject outputs aliasing either private allocation; do not expose an update API.
; RSI start RDX size; preserves RDI (handle).
as_output:
    push rdi
    push rsi
    push rdx
    call smp_current_logical
    pop rdx
    pop rsi
    pop rdi
    test eax,eax
    jnz .bad
    cmp byte [rel as_busy],0
    jne .bad
    test rsi,rsi
    jz .bad
    mov rax,rsi
    add rax,rdx
    jc .bad
    mov rcx,[rel as_stage]
    test rcx,rcx
    jz .bad
    mov r8,[rel as_resident]
    cmp rcx,r8
    cmova rcx,r8
    cmp rax,rcx
    jbe .ok
    add rcx,2*AS_MAX
    cmp rsi,rcx
    jb .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Native lifecycle caller: depth zero, before replacement/STOP/revoke/teardown.
; Session/trust changes also invalidate on every descriptor/copy access.
app_script_retire:
    sub rsp,8
    call smp_current_logical
    add rsp,8
    test eax,eax
    jnz .bad
    cmp byte [rel as_busy],0
    jne .bad
    call as_retire
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret
as_retire:
    mov qword [rel as_handle],0
    mov qword [rel as_length],0
    mov qword [rel as_epoch],0
    mov qword [rel as_owner],0
    mov rdi,[rel as_resident]
    test rdi,rdi
    jz .digest
    xor eax,eax
    mov ecx,AS_MAX/8
    cld
    rep stosq
.digest:
    lea rdi,[rel as_digest]
    xor eax,eax
    mov ecx,4
    rep stosq
    ret
as_wipe_stage:
    mov rdi,[rel as_stage]
    test rdi,rdi
    jz .out
    xor eax,eax
    mov ecx,AS_MAX/8
    cld
    rep stosq
.out:
    ret

%macro WDATA_BSS_app_script 0
alignb 8
as_stage: resq 1
as_resident: resq 1
as_sequence: resq 1
as_handle: resq 1
as_epoch: resq 1
as_owner: resq 1
as_length: resq 1
as_digest: resb 32
as_counts: resd 6
as_busy: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_app_script
