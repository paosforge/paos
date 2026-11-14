;; MODULE sec/node_identity_store
;; LAYER 6
;; EXPORTS node_identity_store_preebs, node_identity_store_activate, node_identity_store_retire, node_identity_store_screen_sign, node_identity_store_state, node_identity_store_generation
;; IMPORTS boot/header, boot/smbios, sec/principal, sec/system_secret, sec/node_identity, svc/command_auth, core/lib/mem, core/lib/hmac_sha256, core/reset_wipe
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only
; Read-only production consumer. No enrollment, firmware write, key export or
; trust-pin construction. The absent authenticated durable producer stays absent.
; PaOSNodeIdentityV1, exact192/NV|BS: magic8/version4/size4/node16/epoch8/
; state4/reserved4/NID112/MAC32. MAC covers bytes0..159. Independent scoped
; SYSTEM HKDF labels bind MAC to node and wrapping key to node+epoch.
; A retired record has state2 and zero NID112. No rollback-proof floor exists
; here: a trusted pre-EBS provisioning/lifecycle owner must retain that policy.

NIS_SIZE equ 192
NIS_READY equ 5
NIS_ACTIVE equ 6
NIS_RETIRED equ 7
NIS_NOT_FOUND equ 0x800000000000000e
NIS_TOO_SMALL equ 0x8000000000000005

; Once per boot, after secureboot_snapshot captured SMBIOS, before Y is taken.
; state:0notrun/1unavailable/2absent/3corrupt/4io/5ready/6active/7retired.
; Firmware failures never cause deletion, creation, repair, or fallback.
node_identity_store_preebs:
%ifdef PAOS_NODE_IDENTITY_TEST_ACTIVE_FIXTURE
    ret                               ; keep the existing negative KAT observable
%endif
    push rbx
    push r12
    push r13
    cmp byte [rel node_identity_store_state],0
    jne .out
    mov byte [rel node_identity_store_state],1
    cmp byte [rel reset_wipe_done],0
    jne .out
    mov r12,[rel runtime_services]
    test r12,r12
    jz .out
    cmp dword [rel smbios_identity_state],0
    jne .out
    lea rdi,[rel nis_node]
    xor esi,esi
    cmp byte [rel smbios_sys_uuid_present],1
    jne .uuid
    lea rsi,[rel smbios_sys_uuid]
.uuid:
    lea rdx,[rel smbios_sys_serial]
    xor ecx,ecx                       ; no uninitialized NIC fallback/latch
    call command_auth_node_id_derive
    cmp eax,1                         ; actual bounded SMBIOS source only
    jne .wipe
    lea rdi,[rel nis_mac_info]
    lea rsi,[rel nis_mac_domain]
    mov edx,nis_mac_domain_end-nis_mac_domain
    call memcpy
    lea rdi,[rel nis_mac_info_node]
    lea rsi,[rel nis_node]
    mov edx,16
    call memcpy
    lea rdi,[rel nis_mac_info]
    mov esi,nis_mac_info_end-nis_mac_info
    lea rdx,[rel nis_mac_key]
    call system_secret_hkdf
    cmp eax,1
    jne .wipe
    lea rdi,[rel nis_record]
    call nis_read
    test rax,rax
    jz .first
    mov rdx,NIS_NOT_FOUND
    cmp rax,rdx
    je .absent
    mov rdx,NIS_TOO_SMALL
    cmp rax,rdx
    je .corrupt
    jmp .io
.first:
    lea rdi,[rel nis_record]
    call nis_authenticate
    test eax,eax
    jnz .corrupt
    lea rdi,[rel nis_readback]
    call nis_read
    test rax,rax
    jnz .io
    lea rdi,[rel nis_readback]
    call nis_authenticate
    test eax,eax
    jnz .corrupt
    lea rdi,[rel nis_record]
    lea rsi,[rel nis_readback]
    mov edx,NIS_SIZE
    call memcmp
    test eax,eax
    jnz .corrupt                     ; publication requires exact durable view
    mov rax,[rel nis_record+32]
    mov [rel node_identity_store_generation],rax
    cmp dword [rel nis_record+40],2
    je .retired
    lea rdi,[rel nis_wrap_info]
    lea rsi,[rel nis_wrap_domain]
    mov edx,nis_wrap_domain_end-nis_wrap_domain
    call memcpy
    lea rdi,[rel nis_wrap_info_node]
    lea rsi,[rel nis_node]
    mov edx,16
    call memcpy
    mov rax,[rel node_identity_store_generation]
    mov [rel nis_wrap_info_epoch],rax
    lea rdi,[rel nis_wrap_info]
    mov esi,nis_wrap_info_end-nis_wrap_info
    lea rdx,[rel nis_wrap_key]
    call system_secret_hkdf
    cmp eax,1
    jne .wipe
    mov byte [rel node_identity_store_state],NIS_READY ; publish last
    jmp .out
.absent:
    mov byte [rel node_identity_store_state],2
    jmp .wipe
.corrupt:
    mov byte [rel node_identity_store_state],3
    jmp .wipe
.io:
    mov byte [rel node_identity_store_state],4
    jmp .wipe
.retired:
    mov byte [rel node_identity_store_state],NIS_RETIRED
.wipe:
    call nis_pending_wipe
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Private Microsoft-ABI firmware GetVariable; attrs/size reset on BOTH reads.
nis_read:
    push rbp
    mov rbp,rsp
    and rsp,-16
    sub rsp,48
    mov [rsp+32],rdi
    mov qword [rel nis_io_size],NIS_SIZE
    mov dword [rel nis_io_attrs],0
    lea rcx,[rel nis_name]
    lea rdx,[rel prin_record_guid]
    lea r8,[rel nis_io_attrs]
    lea r9,[rel nis_io_size]
    call [r12+0x48]
    mov rsp,rbp
    pop rbp
    ret

; RDI192; fail closed, including noncanonical tombstones. HMAC compare fixed32.
nis_authenticate:
    push rbx
    mov rbx,rdi
    cmp qword [rel nis_io_size],NIS_SIZE
    jne .bad
    cmp dword [rel nis_io_attrs],3
    jne .bad
    mov rax,'PNIS0001'
    cmp [rbx],rax
    jne .bad
    cmp dword [rbx+8],1
    jne .bad
    cmp dword [rbx+12],NIS_SIZE
    jne .bad
    cmp dword [rbx+44],0
    jne .bad
    mov rax,[rbx+32]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    lea rdi,[rbx+16]
    lea rsi,[rel nis_node]
    mov edx,16
    call memcmp
    test eax,eax
    jnz .bad
    cmp dword [rbx+40],1
    je .mac
    cmp dword [rbx+40],2
    jne .bad
    xor eax,eax
    mov ecx,112
    lea rdi,[rbx+48]
.tomb:
    or al,[rdi]
    inc rdi
    loop .tomb
    test al,al
    jnz .bad
.mac:
    lea rdi,[rel nis_mac]
    lea rsi,[rel nis_mac_key]
    mov edx,32
    mov rcx,rbx
    mov r8d,160
    call hmac_sha256
    test eax,eax
    jnz .bad
    xor eax,eax
    xor ecx,ecx
.compare:
    lea rdx,[rel nis_mac]
    mov dl,[rdx+rcx]
    xor dl,[rbx+160+rcx]
    or al,dl
    inc ecx
    cmp ecx,32
    jb .compare
    test al,al
    jnz .bad
    xor eax,eax
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret

; Boot-only call AFTER both node identity KATs cleared their synthetic state.
; Import authenticates and rederives the public key before active publication.
node_identity_store_activate:
%ifdef PAOS_NODE_IDENTITY_TEST_ACTIVE_FIXTURE
    mov eax,-1                        ; never mask the original negative fixture
    ret
%endif
    push rbx
    mov ebx,-1
    cmp byte [rel node_identity_store_state],NIS_READY
    jne .out
    cmp byte [rel reset_wipe_done],0
    jne .retire
    mov byte [rel node_identity_store_state],3
    lea rdi,[rel nis_record+48]
    mov esi,112
    lea rdx,[rel nis_wrap_key]
    mov ecx,32
    call node_identity_envelope_import
    test eax,eax
    jnz .retire_bad
    call node_identity_active
    cmp eax,1
    jne .retire_bad
    ; Known public KAT identities are never a production response identity.
    ; These are the existing node_identity fresh-key denylist, not trust pins.
    lea rdi,[rel nis_mac]
    mov esi,32
    call node_identity_public
    test eax,eax
    jnz .retire_bad
    lea rdi,[rel nis_mac]
    lea rsi,[rel nis_fixture_public1]
    mov edx,32
    call memcmp
    test eax,eax
    jz .retire_bad
    lea rdi,[rel nis_mac]
    lea rsi,[rel nis_fixture_public2]
    mov edx,32
    call memcmp
    test eax,eax
    jz .retire_bad
    mov byte [rel node_identity_store_state],NIS_ACTIVE
    xor ebx,ebx
    jmp .wipe
.retire_bad:
    call node_identity_clear_runtime
    jmp .wipe
.retire:
    call node_identity_store_retire
.wipe:
    call nis_pending_wipe
.out:
    mov eax,ebx
    pop rbx
    ret

; Native runtime retirement is permanent for this boot. It never claims that a
; durable tombstone was written. The authenticated pre-EBS writer is separate.
node_identity_store_retire:
    sub rsp,8
    mov byte [rel node_identity_store_state],NIS_RETIRED
    call node_identity_clear_runtime
    lea rdi,[rel nis_private]
    xor esi,esi
    mov edx,nis_private_end-nis_private
    call memset
    add rsp,8
    xor eax,eax
    ret

; Native BSP only: (digest32,out64)->0/-1. Purpose is fixed, never caller text.
; MSI owns digest of the full admitted SCREEN transcript and per-session checks.
; Signature preimage72 = domain16 || exact node16 || epoch8 || transcriptSHA32.
; This is public identity output, NOT an independently authenticated verifier pin.
node_identity_store_screen_sign:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov rbx,rsi
    mov r13d,-1
    test rbx,rbx
    jz .out
    test r12,r12
    jz .clear
    cmp byte [rel node_identity_store_state],NIS_ACTIVE
    jne .clear
    cmp byte [rel reset_wipe_done],0
    jne .clear
    cmp byte [rel nis_busy],0
    jne .clear
    mov byte [rel nis_busy],1
    lea rdi,[rel nis_message+40]
    mov rsi,r12
    mov edx,32
    call memcpy
    lea rdi,[rel nis_message]
    lea rsi,[rel nis_screen_domain]
    mov edx,16
    call memcpy
    lea rdi,[rel nis_message+16]
    lea rsi,[rel nis_node]
    mov edx,16
    call memcpy
    mov rax,[rel node_identity_store_generation]
    mov [rel nis_message+32],rax
    lea rdi,[rel nis_message]
    mov esi,72
    mov rdx,rbx
    mov ecx,64
    call node_identity_sign_active
    mov r13d,eax
    lea rdi,[rel nis_message]
    xor esi,esi
    mov edx,72
    call memset
    mov byte [rel nis_busy],0
    test r13d,r13d
    jz .out
.clear:
    mov rdi,rbx
    xor esi,esi
    mov edx,64
    call memset
.out:
    mov eax,r13d
    pop r13
    pop r12
    pop rbx
    ret

nis_pending_wipe:
    lea rdi,[rel nis_pending]
    xor esi,esi
    mov edx,nis_pending_end-nis_pending
    jmp memset

align 2
nis_name: dw 'P','a','O','S','N','o','d','e','I','d','e','n','t','i','t','y','V','1',0
nis_screen_domain: db 'PAOS-SCREEN-V1',0,0
nis_screen_domain_end:
%if nis_screen_domain_end-nis_screen_domain != 16
    %error "SCREEN identity domain must be exactly16 bytes"
%endif
nis_mac_domain: db 'PaOS/node-identity/store/mac/v1',0
nis_mac_domain_end:
nis_wrap_domain: db 'PaOS/node-identity/store/wrap/v1',0
nis_wrap_domain_end:
nis_fixture_public1: db 0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a
    db 0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
nis_fixture_public2: db 0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc
    db 0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c

%include "core/abi/wdata.inc"
%macro WDATA_sec_node_identity_store 0
align 8
node_identity_store_state: db 0
nis_busy: db 0
align 8
nis_private:
nis_pending:
nis_mac_key: times 32 db 0
nis_wrap_key: times 32 db 0
nis_record: times NIS_SIZE db 0
nis_readback: times NIS_SIZE db 0
nis_mac: times 32 db 0
nis_pending_end:
nis_node: times 16 db 0
node_identity_store_generation: dq 0
nis_io_size: dq 0
nis_io_attrs: dd 0
nis_mac_info: times nis_mac_domain_end-nis_mac_domain db 0
nis_mac_info_node: times 16 db 0
nis_mac_info_end:
nis_wrap_info: times nis_wrap_domain_end-nis_wrap_domain db 0
nis_wrap_info_node: times 16 db 0
nis_wrap_info_epoch: dq 0
nis_wrap_info_end:
nis_message: times 72 db 0
nis_private_end:
%endmacro
WDATA_DEFER WDATA_sec_node_identity_store
