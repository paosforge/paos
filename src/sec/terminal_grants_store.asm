;; MODULE sec/terminal_grants_store
;; LAYER 6
;; EXPORTS terminal_grants_store_preebs, terminal_grants_store_after_owner_preebs, terminal_grants_store_load, terminal_grants_store_save, terminal_grants_store_clear
;; IMPORTS sec/owner_stage_key, sec/owner_store, sec/session, sec/principal, svc/command, boot/header, boot/nvram_access, fs/storage_access, core/smp, core/reset_wipe, core/lib/hmac_sha256
;; OWNER saga:boot
;; CONTEXT: bsp_only
; Native persistence only: never grants authority or restores a live binding.
; See gauntlet_v2/docs/terminal_grants_store.md for the exact SEC scope128 ABI.
; The owner pass commits before after_owner_preebs snapshots its sealed handoff;
; principal still takes that handoff once. No app grant/key authority is reused.
; No firmware antirollback: another booted OS can replay an older authenticated
; snapshot under the same owner generation. Foreign/reset owners get no scopes.

TGS_BYTES equ 1088
TGS_MAC equ 1056
TGS_ROWS equ 8
TGS_ROW_BYTES equ 128
TGS_MAGIC equ 0x52475450                 ; PTGR
TGS_ATTRS equ 7                        ; NV|BS|RT

; Must precede owner_store_preebs (which discards Z). A failed derive leaves no
; partial key. All state is reset here, never at runtime configure/rebind.
terminal_grants_store_preebs:
    lea rdi,[rel tgs_private_begin]
    xor eax,eax
    mov ecx,tgs_private_end-tgs_private_begin
    cld
    rep stosb
    lea rdi,[rel tgs_info]
    mov esi,tgs_info.len
    lea rdx,[rel terminal_grants_mac_key]
    call owner_stage_key_hkdf
    cmp eax,1
    sete byte [rel tgs_seed_ready]
    ret

; Immediately after the committed owner pass; do not consume its one-shot
; password handoff. Bind all52 sealed bytes plus the committed generation.
; Conservative generation binding clears consent even when an owner-record
; update keeps the password. No ambiguous reset/replacement inherits consent.
terminal_grants_store_after_owner_preebs:
    mov byte [rel tgs_key_ready],0
    lea rdi,[rel tgs_owner_key]
    xor eax,eax
    mov ecx,4
    cld
    rep stosq
    cmp byte [rel reset_wipe_done],0
    jne .wipe
    cmp byte [rel tgs_seed_ready],1
    jne .wipe
    cmp byte [rel ows_state],1            ; committed LOADED
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
    mov [rel tgs_generation],rax
    mov [rel tgs_owner_input+52],rax
    lea rdi,[rel tgs_owner_input]
    lea rsi,[rel ows_pw_handoff]
    mov ecx,52
    rep movsb
    lea rdi,[rel tgs_owner_key]
    lea rsi,[rel terminal_grants_mac_key]
    mov edx,32
    lea rcx,[rel tgs_owner_input]
    mov r8d,60
    call hmac_sha256
    test rax,rax
    jnz .wipe
    cmp byte [rel reset_wipe_done],0
    jne .wipe
    mov byte [rel tgs_key_ready],1
.wipe:
    lea rdi,[rel terminal_grants_mac_key]
    xor eax,eax
    mov ecx,32
    rep stosb
    lea rdi,[rel tgs_owner_input]
    mov ecx,60
    rep stosb
    mov byte [rel tgs_seed_ready],0
    cmp byte [rel tgs_key_ready],1
    je .out
    lea rdi,[rel tgs_owner_key]
    mov ecx,32
    rep stosb
.out:
    ret

; load(RDI native writable1024,RSI current local OWNER token)
; -> EAX1 authenticated supported selections, EDX count /0,0 zero output.
; Fresh firmware read every time; no positive or negative cache. SEC must still
; prove a fresh Terminal binding and validate each final provider scope/indicator.
terminal_grants_store_load:
    push r12
    mov r12,rdi
    push r13
    mov r13,rsi
    mov esi,1024
    call tgs_span
    test eax,eax
    jz .refused
    mov rdi,r12
    xor eax,eax
    mov ecx,128
    cld
    rep stosq
    mov rdi,r13
    call tgs_enter
    test eax,eax
    jz .refused
    cmp byte [rel tgs_restore_blocked],0
    jne .failed
    lea rdi,[rel tgs_image]
    call tgs_get
    test eax,eax
    jnz .failed
    call tgs_shape
    test eax,eax
    jz .failed
    call tgs_mac
    test rax,rax
    jnz .failed
    lea rdi,[rel tgs_image+TGS_MAC]
    lea rsi,[rel tgs_mac_out]
    xor eax,eax
    xor ecx,ecx
.compare:
    mov dl,[rdi+rcx]
    xor dl,[rsi+rcx]
    or al,dl
    inc ecx
    cmp ecx,32
    jb .compare
    test al,al
    jnz .failed
    call tgs_owner
    test eax,eax
    jz .failed
    mov rdi,r12
    lea rsi,[rel tgs_image+32]
    mov ecx,128
    rep movsq
    mov edx,[rel tgs_image+16]
    mov eax,1
    call tgs_leave
    jmp .out
.failed:
    xor eax,eax
    xor edx,edx
    call tgs_leave
    jmp .out
.refused:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    ret

; save(RDI native rows,ESI count0..8,RDX local OWNER token)
; ->1 verified saved /2 structurally valid request, persistence uncertain /0 refused.
; Complete exact snapshot only. SEC owns physical consent and live policy; this
; is not a command entry or a grant resolver. No yield while copying native input.
terminal_grants_store_save:
    push r12
    push r13
    push r14
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    cmp r13,TGS_ROWS
    ja .refused
    test r13,r13
    jz .admit
    mov rsi,r13
    shl esi,7
    call tgs_span
    test eax,eax
    jz .refused
.admit:
    mov rdi,r14
    call tgs_enter
    test eax,eax
    jz .refused
    call tgs_empty
    mov [rel tgs_image+16],r13
    lea rdi,[rel tgs_image+32]
    mov rsi,r12
    mov rcx,r13
    shl ecx,4
    cld
    rep movsq
    call tgs_shape
    test eax,eax
    jz .invalid
    call tgs_write
    cmp eax,1
    jne .leave
    mov byte [rel tgs_restore_blocked],0 ; explicit new saved consent only
.leave:
    call tgs_leave
    jmp .out
.invalid:
    xor eax,eax
    jmp .leave
.refused:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    ret

; clear(RDI current local OWNER token)->1 saved empty /2 session-only /0 refused.
; SEC MUST fence runtime reads, pending actions and retained results BEFORE this
; call. Block reload before any firmware operation; a failed revoke must not
; resurrect an old valid record in this boot. No policy callback/recursion here.
terminal_grants_store_clear:
    call tgs_enter
    test eax,eax
    jz .out
    mov byte [rel tgs_restore_blocked],1
    call tgs_empty
    call tgs_write
    call tgs_leave
.out:
    ret

; Native mapped buffers are the caller's responsibility; reject null, wrap and
; private overlap before touching them. No guest address is accepted by an API.
tgs_span:
    test rdi,rdi
    jz .bad
    mov rax,rdi
    add rax,rsi
    jc .bad
    lea rdx,[rel tgs_private_end]
    cmp rdi,rdx
    jae .ok
    lea rdx,[rel tgs_private_begin]
    cmp rax,rdx
    ja .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; BSP + depth0 local owner, nonreentrant. Never release another caller's busy.
tgs_enter:
    push r12
    mov r12,rdi
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel tgs_busy],0
    jne .bad
    mov byte [rel tgs_busy],1
    mov [rel tgs_token],r12
    call tgs_owner
    test eax,eax
    jnz .out
    mov qword [rel tgs_token],0
    mov byte [rel tgs_busy],0
.bad:
    xor eax,eax
.out:
    pop r12
    ret

tgs_owner:
    cmp byte [rel reset_wipe_done],0
    jne .no
    cmp byte [rel tgs_key_ready],1
    jne .no
    cmp byte [rel cmd_in_dispatch],0
    jne .no
    cmp dword [rel cmd_dispatch_depth],0
    jne .no
    cmp byte [rel ows_state],1
    jne .no
    cmp byte [rel ows_zbound],1
    jne .no
    mov rax,[rel ows_generation]
    cmp rax,[rel tgs_generation]
    jne .no
    cmp qword [rel tgs_token],0
    je .no
    cmp qword [rel tgs_token],-1
    je .no
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .no
    cmp rdx,[rel tgs_token]
    jne .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

tgs_empty:
    lea rdi,[rel tgs_image]
    xor eax,eax
    mov ecx,TGS_BYTES/8
    cld
    rep stosq
    mov dword [rel tgs_image],TGS_MAGIC
    mov word [rel tgs_image+4],1
    mov word [rel tgs_image+6],TGS_BYTES
    mov qword [rel tgs_image+8],1          ; closed policy version
    mov rax,[rel tgs_generation]
    mov [rel tgs_image+24],rax
    ret

; Validate every row plus zero padding, including authenticated inputs. Scope
; identity remains opaque to storage: final object proof belongs to SEC/provider.
tgs_shape:
    lea r9,[rel tgs_image]
    cmp dword [r9],TGS_MAGIC
    jne .bad
    cmp word [r9+4],1
    jne .bad
    cmp word [r9+6],TGS_BYTES
    jne .bad
    cmp qword [r9+8],1
    jne .bad
    mov rax,[rel tgs_generation]
    cmp [r9+24],rax
    jne .bad
    mov r11,[r9+16]
    cmp r11,TGS_ROWS
    ja .bad
    lea r8,[r9+32]
    xor r10d,r10d                      ; one owner-picked folder at most
    xor ecx,ecx
.row:
    cmp rcx,r11
    jae .padding
    cmp qword [r8],1
    jne .bad
    cmp qword [r8+8],16
    jb .bad
    cmp qword [r8+8],21
    ja .bad
    cmp qword [r8+16],0
    je .bad
    cmp qword [r8+40],0
    jne .bad
    cmp qword [r8+112],0
    jne .bad
    cmp qword [r8+120],0
    jne .bad
    cmp qword [r8+8],18
    je .window
    cmp qword [r8+8],19
    jne .folder
.window:
    cmp qword [r8+24],0
    je .bad
    cmp qword [r8+32],0
    je .bad
.folder:
    cmp qword [r8+8],20
    jb .unique
    mov rax,[r8+48]
    or rax,[r8+56]
    or rax,[r8+64]
    or rax,[r8+72]
    or rax,[r8+80]
    or rax,[r8+88]
    or rax,[r8+96]
    or rax,[r8+104]
    jz .bad
    cmp qword [r8+8],21
    jne .unique
    inc r10d
    cmp r10d,1
    ja .bad
.unique:
    lea rdx,[r9+32]
.scan:
    cmp rdx,r8
    jae .next
    mov rax,[r8+16]
    cmp rax,[rdx+16]
    je .bad
    add rdx,TGS_ROW_BYTES
    jmp .scan
.next:
    add r8,TGS_ROW_BYTES
    inc ecx
    jmp .row
.padding:
    lea rdx,[r9+TGS_MAC]
.zero:
    cmp r8,rdx
    jae .ok
    cmp qword [r8],0
    jne .bad
    add r8,8
    jmp .zero
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

tgs_mac:
    lea rdi,[rel tgs_mac_out]
    lea rsi,[rel tgs_owner_key]
    mov edx,32
    lea rcx,[rel tgs_image]
    mov r8d,TGS_MAC
    jmp hmac_sha256

; RDI out1088 ->0 exact read/-1 anything else. Never confuse an EFI failure,
; wrong attributes, oversized or absent variable with authenticated empty state.
tgs_get:
    push r12
    push r13
    mov r13,rsp
    mov r10,rdi
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .bad
    mov r12,[rel runtime_services]
    test r12,r12
    jz .bad
    cmp qword [r12+0x48],0
    je .bad
    mov qword [rel tgs_size],TGS_BYTES
    mov dword [rel tgs_attrs],0
    lea rcx,[rel tgs_name]
    lea rdx,[rel tgs_guid]
    lea r8,[rel tgs_attrs]
    lea r9,[rel tgs_size]
    and rsp,-16
    sub rsp,48
    mov [rsp+32],r10
    call [r12+0x48]
    mov rsp,r13
    test rax,rax
    jnz .bad
    cmp qword [rel tgs_size],TGS_BYTES
    jne .bad
    cmp dword [rel tgs_attrs],TGS_ATTRS
    jne .bad
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    mov rsp,r13
    pop r13
    pop r12
    ret

; Private admitted snapshot ->1 only after successful SetVariable + byte-exact
; readback + current owner check. Even failed SetVariable may have committed:
; every failure is uncertain2, never "saved" and never an automatic retry.
tgs_write:
    push r12
    push r13
    mov r13,rsp
    call tgs_mac
    test rax,rax
    jnz .uncertain
    lea rdi,[rel tgs_image+TGS_MAC]
    lea rsi,[rel tgs_mac_out]
    mov ecx,4
    cld
    rep movsq
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .uncertain
    mov r12,[rel runtime_services]
    test r12,r12
    jz .uncertain
    cmp qword [r12+0x58],0
    je .uncertain
    call storage_access_request_intent
    mov edx,eax
    lea rdi,[rel tgs_guid]
    lea rsi,[rel tgs_name]
    lea rcx,[rel tgs_tag]
    call storage_access_nvram_require
    test rax,rax
    jnz .uncertain
    call tgs_owner
    test eax,eax
    jz .uncertain
    lea rcx,[rel tgs_name]
    lea rdx,[rel tgs_guid]
    mov r8d,TGS_ATTRS
    mov r9d,TGS_BYTES
    and rsp,-16
    sub rsp,48
    lea rax,[rel tgs_image]
    mov [rsp+32],rax
    call [r12+0x58]
    mov rsp,r13
    test rax,rax
    jnz .uncertain
    lea rdi,[rel tgs_verify]
    call tgs_get
    test eax,eax
    jnz .uncertain
    lea rdi,[rel tgs_image]
    lea rsi,[rel tgs_verify]
    mov ecx,TGS_BYTES/8
    cld
    repe cmpsq
    jne .uncertain
    call tgs_owner
    test eax,eax
    jz .uncertain
    mov eax,1
    jmp .out
.uncertain:
    mov eax,2
.out:
    mov rsp,r13
    pop r13
    pop r12
    ret

; Preserve public status/count, scrub record/MAC/token scratch after every call.
tgs_leave:
    push rax
    push rdx
    lea rdi,[rel tgs_scratch]
    xor eax,eax
    mov ecx,tgs_scratch_end-tgs_scratch
    cld
    rep stosb
    mov byte [rel tgs_busy],0
    pop rdx
    pop rax
    ret

tgs_info: db 'PaOS/sec/terminal_grants/v1'
.len equ $-tgs_info
tgs_tag: db 'terminal_grants_store',0
align 8
; Existing data/config vendor class; distinct variable name and key domain.
tgs_guid:
    dd 0x5a6ec129
    dw 0x2554,0x494c
    db 0x99,0xbd,0xb0,0x39,0x60,0xdf,0x47,0x04
tgs_name: dw 'P','a','O','S','T','e','r','m','i','n','a','l','G','r','a','n','t','s',0

%include "core/abi/wdata.inc"
%macro WDATA_BSS_sec_terminal_grants_store 0
alignb 8
tgs_private_begin:
tgs_seed_ready: resb 1
tgs_key_ready: resb 1
tgs_busy: resb 1
tgs_restore_blocked: resb 1
    resb 4
tgs_generation: resq 1
terminal_grants_mac_key: resb 32
tgs_owner_key: resb 32
tgs_owner_input: resb 60
    resb 4
tgs_scratch:
tgs_token: resq 1
tgs_size: resq 1
tgs_attrs: resd 1
    resb 4
tgs_mac_out: resb 32
tgs_image: resb TGS_BYTES
tgs_verify: resb TGS_BYTES
tgs_scratch_end:
tgs_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_terminal_grants_store
