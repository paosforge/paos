;; MODULE svc/app_package
;; LAYER 5
;; EXPORTS app_package_verify_unsigned_script, app_package_verify_trusted_script, app_package_stage, app_package_descriptor, app_package_copy, app_package_retire
;; IMPORTS svc/app_script, svc/app_bundle, core/lib/sha256, bootmgr/rsa2048_verify, core/heap, sec/session, core/smp
;; CAPS
;; OWNER saga:command
; Private sharing candidate only. No install, confirmation, grants, author
; enrollment, filesystem, form materialization, execution or VM authority.
; BSP native-owned bytes, non-yielding local unlocked OWNER calls only.
; Existing app_script trusted-only handles cannot consume this object.
AP_MAX equ 65536
AP_DESC equ 704

app_package_stage:
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
    cmp byte [rel ap_busy],0
    jne .refuse
    mov byte [rel ap_busy],1
    test r12,r12
    jz .fail
    cmp r13,AP_MAX
    ja .fail
    cmp r13,769                     ; header + manifest + two rows + nonempty assets + hash
    jb .fail
    call session_shell_require_unlocked
    test eax,eax
    jnz .fail
    mov r15,[rel session_authority_epoch]
    test r15,r15
    jz .fail
    cmp qword [rel ap_sequence],-1
    je .fail
    cmp qword [rel appkg_stage],0
    jne .allocated
    mov edi,2*AP_MAX
    call kmalloc
    test rax,rax
    jz .fail
    mov [rel appkg_stage],rax
    add rax,AP_MAX
    mov [rel ap_resident],rax
.allocated:
    mov rdi,[rel appkg_stage]
    mov rsi,r12
    mov rcx,r13
    cld
    rep movsb                      ; copy BEFORE verify; source is never reused
    mov r12,[rel appkg_stage]
    call ap_verify
    test eax,eax
    jz .fail
    ; Trust/epoch still current at publication. No callbacks or yields below.
    call session_shell_require_unlocked
    test eax,eax
    jnz .fail
    cmp r15,[rel session_authority_epoch]
    jne .fail
    cmp qword [rel session_bound_pid],PRIN_OWNER
    jne .fail
    lea rdi,[rel ap_digest]
    mov rsi,r12
    mov rdx,r13
    call sha256_hash
    mov rax,[rel ap_resident]
    mov [rel appkg_stage],rax
    mov [rel ap_resident],r12
    inc qword [rel ap_sequence]     ; nonwrapping native handle, not bundle proof
    mov rax,[rel ap_sequence]
    mov [rel ap_handle],rax
    mov [rel ap_epoch],r15
    mov rdx,[rel session_bound_pid]
    mov [rel ap_owner],rdx          ; native session owner, never ambient request PID
    mov [rel ap_length],r13
    mov eax,[rel ap_verified_author]
    mov [rel ap_author],eax
    call ap_wipe_stage
    mov rax,[rel ap_handle]
    mov byte [rel ap_busy],0
    jmp .out
.fail:
    call ap_wipe_stage
    mov byte [rel ap_busy],0
.refuse:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; R12 private immutable stage, R13 bounded exact length -> EAX boolean.
; Before cryptography, touch only fixed envelope/bounds/public verification
; material. Never interpret manifest, index, script or form before integrity.
ap_verify:
    mov rax,'PAOSAPP1'
    cmp [r12],rax
    jne .bad
    cmp dword [r12+8],0x00400002
    jne .bad
    cmp [r12+12],r13d
    jne .bad
    cmp dword [r12+16],64
    jne .bad
    cmp dword [r12+20],512
    jne .bad
    cmp dword [r12+24],576
    jne .bad
    cmp dword [r12+44],0
    jne .bad
    mov eax,[r12+40]
    cmp eax,1
    je .flags_ok
    cmp eax,3
    jne .bad
.flags_ok:
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
    mov ebx,eax
    mov eax,[r12+28]
    add eax,576
    cmp eax,[r12+32]
    jne .bad
    mov edx,[r12+36]
    cmp edx,AP_MAX
    ja .bad
    add eax,edx
    mov r14d,eax                    ; bounded end-of-assets/content hash offset
    add eax,32
    cmp dword [r12+40],1
    je .tail
    add eax,512
.tail:
    cmp eax,r13d
    jne .bad
    lea rdi,[rel ap_content_digest]
    mov rsi,r12
    mov edx,r14d
    call sha256_hash
    lea rdi,[rel ap_content_digest]
    lea rsi,[r12+r14]
    mov ecx,32
    repe cmpsb
    jne .bad
    cmp dword [r12+40],1
    jne .signed
    cmp qword [r12+48],0
    jne .bad
    cmp qword [r12+56],0
    jne .bad
    jmp .metadata
.signed:
    lea rsi,[r12+r14+32]            ; carried BE modulus, never an anchor grant
    test byte [rsi],0x80
    jz .bad
    test byte [rsi+255],1
    jz .bad
    lea rdi,[rel ap_modulus]
    xor ecx,ecx
.modulus:
    mov eax,255
    sub eax,ecx
    mov dl,[rsi+rax]
    mov [rdi+rcx],dl
    inc ecx
    cmp ecx,256
    jb .modulus
    lea rdi,[rel ap_content_digest]
    mov edx,256
    call sha256_hash
    lea rdi,[rel ap_content_digest]
    lea rsi,[r12+48]
    mov ecx,16
    repe cmpsb
    jne .bad
    lea rdi,[r12+r14+288]
    mov rsi,r12
    lea edx,[r14d+288]
    lea rcx,[rel ap_modulus]
    call rsa2048_verify_sha256
    test eax,eax
    jnz .bad
    jmp .metadata
.metadata:
    mov rax,'BASHAPP2'
    cmp [r12+64],rax
    jne .bad
    lea rdi,[r12+320]              ; display name, no authority/path semantics
    call ap_display
    test eax,eax
    jz .bad
    lea rdi,[r12+416]
    call ap_version
    test eax,eax
    jz .bad
    lea rdi,[r12+448]
    mov ecx,128
    xor eax,eax
    repe scasb
    jne .bad
    call app_script_members        ; same canonical paths/roles/manifest checks
    test eax,eax
    jz .bad
    call ap_author_now
    mov [rel ap_verified_author],eax
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Current author trust classification, never a trust write. R12 candidate.
; Verified full public modulus must equal current trusted modulus too.
ap_author_now:
    cmp dword [r12+40],3
    jne .unknown
    lea rdi,[r12+48]
    call app_trust_find
    test rax,rax
    jz .unknown
    mov rdi,rax
    mov esi,[r12+32]
    add esi,[r12+36]
    lea rsi,[r12+rsi+32]
    xor ecx,ecx
.compare:
    mov eax,255
    sub eax,ecx
    mov dl,[rsi+rax]
    cmp dl,[rdi+rcx]
    jne .unknown
    inc ecx
    cmp ecx,256
    jb .compare
    mov eax,1
    ret
.unknown:
    xor eax,eax
    ret

; 1..95 printable ASCII, no leading/trailing space; exact NUL/zero padding.
ap_display:
    xor ecx,ecx
    xor edx,edx
    cmp byte [rdi],33
    jb .bad
.char:
    mov al,[rdi+rcx]
    test al,al
    jz .end
    cmp al,32
    jb .bad
    cmp al,126
    ja .bad
    mov dl,al
    inc ecx
    cmp ecx,96
    jb .char
    jmp .bad
.end:
    cmp dl,32
    jbe .bad
.padding:
    cmp byte [rdi+rcx],0
    jne .bad
    inc ecx
    cmp ecx,96
    jb .padding
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Exactly 3 canonical decimal uint16 components, no leading zero, padded32.
ap_version:
    xor ecx,ecx
    xor r8d,r8d
.component:
    xor edx,edx
    mov r9d,ecx
.digit:
    movzx eax,byte [rdi+rcx]
    cmp al,'0'
    jb .separator
    cmp al,'9'
    ja .separator
    cmp ecx,r9d
    je .accumulate
    cmp byte [rdi+r9],'0'
    je .bad
.accumulate:
    imul edx,10
    sub eax,'0'
    add edx,eax
    cmp edx,65535
    ja .bad
    inc ecx
    cmp ecx,32
    jae .bad
    jmp .digit
.separator:
    cmp ecx,r9d
    je .bad
    inc r8d
    cmp r8d,3
    je .last
    cmp al,'.'
    jne .bad
    inc ecx
    cmp ecx,32
    jae .bad
    jmp .component
.last:
    test al,al
    jnz .bad
.padding:
    cmp byte [rdi+rcx],0
    jne .bad
    inc ecx
    cmp ecx,32
    jb .padding
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; A candidate is not approved. All views require current local OWNER and same
; session/author classification. A trust change retires, never auto-upgrades.
ap_current:
    test rdi,rdi
    jz .bad
    cmp rdi,[rel ap_handle]
    jne .bad
    push r12
    call session_shell_require_unlocked
    test eax,eax
    jnz .retire
    cmp qword [rel session_bound_pid],PRIN_OWNER
    jne .retire
    mov rax,[rel ap_epoch]
    cmp rax,[rel session_authority_epoch]
    jne .retire
    mov rax,[rel ap_owner]
    cmp rax,[rel session_bound_pid]
    jne .retire
    mov r12,[rel ap_resident]
    call ap_author_now
    cmp eax,[rel ap_author]
    jne .retire
    mov eax,1
    pop r12
    ret
.retire:
    call ap_retire
    pop r12
.bad:
    xor eax,eax
    ret

; RDI handle, RSI native output, RDX exact704 -> EAX1/0. No pointers.
; This descriptor is a candidate view, never installation or VM proof.
app_package_descriptor:
    push rbx
    push r12
    sub rsp,8
    mov r12,rsi
    cmp rdx,AP_DESC
    jne .bad
    call ap_output
    test eax,eax
    jz .bad
    call ap_current
    test eax,eax
    jz .bad
    cld
    mov rbx,[rel ap_resident]
    mov rdi,r12
    xor eax,eax
    mov ecx,AP_DESC/8
    rep stosq
    mov qword [r12],1
    mov rax,[rel ap_handle]
    mov [r12+8],rax
    mov rax,[rel ap_length]
    mov [r12+16],rax
    mov rax,[rel ap_epoch]
    mov [r12+24],rax
    lea rsi,[rel ap_digest]
    lea rdi,[r12+32]
    mov ecx,4
    rep movsq
    lea rsi,[rbx+48]
    mov ecx,2
    rep movsq
    mov eax,[rel ap_author]
    mov [r12+80],rax
    xor eax,eax
    cmp dword [rbx+40],3
    sete al
    mov [r12+88],rax
    mov eax,[rbx+28]
    xor edx,edx
    mov ecx,80
    div ecx
    mov [r12+96],rax
    mov qword [r12+104],576
    mov eax,[rbx+28]
    mov [r12+112],rax
    mov eax,[rbx+32]
    mov [r12+120],rax
    mov eax,[rbx+36]
    mov [r12+128],rax
    mov qword [r12+136],1
    lea rsi,[rbx+64]
    lea rdi,[r12+192]
    mov ecx,64
    rep movsq
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

app_package_copy:
    push rbx
    push r12
    push r13
    mov rbx,rsi
    mov r12,rdx
    mov r13,rcx
    test rcx,rcx
    jz .bad
    cmp rcx,AP_MAX
    ja .bad
    cmp rsi,AP_MAX
    ja .bad
    lea rax,[rsi+rcx]
    cmp rax,[rel ap_length]
    ja .bad
    mov rsi,r12
    mov rdx,r13
    call ap_output
    test eax,eax
    jz .bad
    call ap_current
    test eax,eax
    jz .bad
    mov rsi,[rel ap_resident]
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

ap_output:
    push rdi
    push rsi
    push rdx
    call smp_current_logical
    pop rdx
    pop rsi
    pop rdi
    test eax,eax
    jnz .bad
    cmp byte [rel ap_busy],0
    jne .bad
    test rsi,rsi
    jz .bad
    mov rax,rsi
    add rax,rdx
    jc .bad
    mov rcx,[rel appkg_stage]
    test rcx,rcx
    jz .bad
    mov r8,[rel ap_resident]
    cmp rcx,r8
    cmova rcx,r8
    cmp rax,rcx
    jbe .ok
    add rcx,2*AP_MAX
    cmp rsi,rcx
    jb .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

app_package_retire:
    sub rsp,8
    call smp_current_logical
    add rsp,8
    test eax,eax
    jnz .bad
    cmp byte [rel ap_busy],0
    jne .bad
    call ap_retire
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret
ap_retire:
    mov qword [rel ap_handle],0
    mov qword [rel ap_length],0
    mov qword [rel ap_epoch],0
    mov qword [rel ap_owner],0
    mov rdi,[rel ap_resident]
    test rdi,rdi
    jz .digest
    xor eax,eax
    mov ecx,AP_MAX/8
    cld
    rep stosq
.digest:
    lea rdi,[rel ap_digest]
    xor eax,eax
    mov ecx,4
    rep stosq
    ret
ap_wipe_stage:
    mov rdi,[rel appkg_stage]
    test rdi,rdi
    jz .out
    xor eax,eax
    mov ecx,AP_MAX/8
    cld
    rep stosq
.out:
    ret

%macro WDATA_BSS_app_package 0
alignb 8
appkg_stage: resq 1
ap_resident: resq 1
ap_sequence: resq 1
ap_handle: resq 1
ap_epoch: resq 1
ap_owner: resq 1
ap_length: resq 1
ap_digest: resb 32
ap_content_digest: resb 32
ap_modulus: resb 256
ap_author: resd 1
ap_verified_author: resd 1
ap_busy: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_app_package

; Internal verifier composition used by the script snapshot, R12/R13 owned bytes.
; Sharing bytes stay unmodified: full content hash, carried-modulus signature,
; manifest/member parser AND exact current APPKEY modulus. Installed consent is
; not an APPKEY enrollment; signed unknown-author bytes still refuse here.
app_package_verify_trusted_script:
    cmp dword [r12+40],3
    jne .bad
    call ap_verify
    test eax,eax
    jz .bad
    call ap_author_now
    cmp eax,1
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Pure canonical-unsigned verifier. Success authenticates format/content only,
; never ownership, installation, an adoption choice or execution authority.
; Only the fixed script installed lookup composes it with owner-sealed state.
app_package_verify_unsigned_script:
    cmp dword [r12+40],1
    jne .bad
    jmp ap_verify
.bad:
    xor eax,eax
    ret
