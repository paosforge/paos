; Lab-only SSH firmware interception boundary (SEC88676 S-C1/S-C2).
; No activation command is provided by this finite component. State starts
; zero/off at boot. A later consumed OWNER controller must own arm/retire,
; authenticated reload, original evidence, finally cleanup and applicability.
; No fault is physical firmware exhaustion, corruption or interrupted power.
%ifdef PAOS_PUBLICITY_LAB_PROFILE
%if PAOS_PUBLICITY_LAB_PROFILE
%define SSH_PROFILE_FAULT_ENABLED 1

; Every native call site supplies one of these exact static names/GUID and
; the fixed reviewed extent. No arbitrary firmware namespace can be reached.
; RCX=name,RDX=GUID -> CF0,R10D=cid1/kh2,R11D=extent; CF1 otherwise.
ssh_cli_fault_tuple:
    lea  rax, [rel ssh_cli_kh_var_guid]
    cmp  rdx, rax
    jne  .bad
    lea  rax, [rel ssh_cli_cid_var_name]
    cmp  rcx, rax
    je   .cid
    lea  rax, [rel ssh_cli_kh_var_name]
    cmp  rcx, rax
    jne  .bad
    mov  r10d, 2
    mov  r11d, SSH_KH_REC_SIZE
    clc
    ret
.cid:
    mov  r10d, 1
    mov  r11d, SSH_CID_REC_SIZE
    clc
    ret
.bad:
    stc
    ret

; Microsoft EFI ABI, including data at entry RSP+40, NOT SysV. Tail jumps
; preserve the caller's original firmware stack and nonvolatile registers.
; Mode1 missing,2 corrupt,3 full,4 uncertain. Active mode intercepts BOTH
; variables' writes/deletes, even if the selected read case is only one store.
ssh_cli_fault_getvar:
    cmp  byte [rel ssh_profile_fault_active], 0
    je   .firmware
    call ssh_cli_fault_tuple
    jc   .invalid
    test r8, r8
    jz   .invalid
    test r9, r9
    jz   .invalid
    cmp  [r9], r11
    jne  .invalid
    cmp  qword [rsp + 40], 0
    je   .invalid
    cmp  r10d, 1
    jne  .kh_count
    inc  qword [rel ssh_profile_fault_cid_reads]
    jmp  .counted
.kh_count:
    inc  qword [rel ssh_profile_fault_kh_reads]
.counted:
    cmp  r10b, [rel ssh_profile_fault_store]
    jne  .firmware
    cmp  byte [rel ssh_profile_fault_mode], 1
    je   .missing
    cmp  byte [rel ssh_profile_fault_mode], 2
    je   .corrupt
    cmp  byte [rel ssh_profile_fault_mode], 4
    jne  .firmware
    cmp  byte [rel ssh_profile_fault_shadow_ready], 0
    je   .firmware
    mov  rax, 0x8000000000000007       ; EFI_DEVICE_ERROR: RAM write has no exact readback
    ret
.missing:
    mov  rax, 0x800000000000000e       ; EFI_NOT_FOUND, never a delete
    ret
.invalid:
    mov  rax, 0x8000000000000002       ; EFI_INVALID_PARAMETER, no firmware call
    ret
.corrupt:
    ; Firmware fills the caller's bounded RAM output. Change one MAC byte in
    ; that copy only after an exact successful read, never the real variable.
    ; Preserve Microsoft nonvolatiles even though helpers elsewhere use SysV.
    push rbx
    push rdi
    push rsi
    mov  rbx, [rsp + 64]
    mov  rdi, r9
    mov  esi, SSH_CID_REC_MAC
    cmp  r10d, 1
    je   .offset
    mov  esi, SSH_KH_REC_MAC
.offset:
    sub  rsp, 48
    mov  [rsp + 32], rbx
    mov  [rsp + 40], r11
    call [r12 + 0x48]
    test rax, rax
    jnz  .corrupt_out
    mov  r11, [rsp + 40]
    cmp  [rdi], r11
    jne  .corrupt_out
    xor  byte [rbx + rsi], 1
.corrupt_out:
    add  rsp, 48
    pop  rsi
    pop  rdi
    pop  rbx
    ret
.firmware:
    jmp  [r12 + 0x48]

ssh_cli_fault_setvar:
    cmp  byte [rel ssh_profile_fault_active], 0
    je   .firmware
    call ssh_cli_fault_tuple
    jc   .invalid
    cmp  r8d, AUTH_EFI_ATTRS
    jne  .invalid
    test r9, r9
    jz   .delete
    cmp  r9, r11
    jne  .invalid
    cmp  qword [rsp + 40], 0
    je   .invalid
    jmp  .extent_ok
.delete:
    cmp  r10d, 2                       ; only known_hosts has a native delete operation
    jne  .invalid
.extent_ok:
    cmp  r10d, 1
    jne  .kh_count
    inc  qword [rel ssh_profile_fault_cid_writes]
    jmp  .counted
.kh_count:
    inc  qword [rel ssh_profile_fault_kh_writes]
.counted:
    ; ALL active cases block firmware on BOTH names, including recovery and
    ; real-login pin saves. Only the selected uncertain case acknowledges a
    ; write into this RAM shadow. Its next selected read refuses exact proof.
    cmp  r10b, [rel ssh_profile_fault_store]
    jne  .protected
    cmp  byte [rel ssh_profile_fault_mode], 3
    je   .full
    cmp  byte [rel ssh_profile_fault_mode], 4
    jne  .protected
    lea  r10, [rel ssh_profile_fault_shadow]
    xor  eax, eax
.wipe:
    mov  byte [r10 + rax], 0
    inc  eax
    cmp  eax, SSH_KH_REC_SIZE
    jb   .wipe
    xor  eax, eax
    mov  r11, [rsp + 40]
.copy:
    cmp  rax, r9
    jae  .shadowed
    mov  dl, [r11 + rax]
    mov  [r10 + rax], dl
    inc  rax
    jmp  .copy
.shadowed:
    mov  byte [rel ssh_profile_fault_shadow_ready], 1
    xor  eax, eax
    ret
.protected:
    mov  rax, 0x800000000000001a       ; EFI_SECURITY_VIOLATION (wrapper refusal)
    ret
.full:
    mov  rax, 0x8000000000000009       ; EFI_OUT_OF_RESOURCES (wrapper injection)
    ret
.invalid:
    mov  rax, 0x8000000000000002
    ret
.firmware:
    jmp  [r12 + 0x58]

; Plain marker makes even a wrongly labeled public payload fail the existing
; release rail. Code/state/marker are all absent when the named lab flag is0.
str_ssh_profile_fault_lab: db "PaOS LAB SSH PROFILE FAULT",0
%macro WDATA_svc_ssh_profile_fault_0 0
ssh_profile_fault_state_begin:
ssh_profile_fault_active: db 0
ssh_profile_fault_store: db 0
ssh_profile_fault_mode: db 0
ssh_profile_fault_shadow_ready: db 0
align 8, db 0
ssh_profile_fault_cid_reads: dq 0
ssh_profile_fault_kh_reads: dq 0
ssh_profile_fault_cid_writes: dq 0
ssh_profile_fault_kh_writes: dq 0
ssh_profile_fault_shadow: times SSH_KH_REC_SIZE db 0
ssh_profile_fault_state_end:
%endmacro
WDATA_DEFER WDATA_svc_ssh_profile_fault_0
%endif
%endif
