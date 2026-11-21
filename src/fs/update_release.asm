;; MODULE fs/update_release
;; LAYER 4
;; EXPORTS update_release_stage_expected, update_release_stage_start, update_release_feed_check, update_release_feed_classify, update_release_state_select, update_release_state_idle, update_release_current_join
;; IMPORTS sec/update_public_policy, boot/boot_v2_handoff, bootmgr/pbm_manifest_verify, bootmgr/rsa2048_verify, core/lib/sha256, core/lib/crc32, core/lib/mem
;; CAPS
;; OWNER rc-fs-claude
;; CONTEXT: bsp_only
; Effect-free receiving predicate. A successful return is NOT a write grant.
; RDI=original PCF1[1024], RSI=native-read current PRL1[512]/0 if genuinely absent,
; RDX=authenticated native active payload SHA[32], RCX=active payload size.
; -> RAX=0/-1. Only the outer native media/launch/presence join can establish
; currentness of these operands. No worker policy, callback, output or setter.
%ifndef UPDATE_RELEASE_INCLUDED
%define UPDATE_RELEASE_INCLUDED 1
; Same exact native operands for both entries; no effect grant.
; Classifier returns 1 exact signed CURRENT / 2 strictly newer AVAILABLE / -1.
; Predicate retains historical 0/-1 ABI, including equal-version valid offers.
update_release_feed_check:
    xor r8d,r8d
    jmp ur_feed_evaluate
update_release_feed_classify:
    mov r8d,1
ur_feed_evaluate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,1640
    mov rbp,rsp
    mov [rbp+1624],r8d            ; private entry mode, never a caller verdict
    test rdi,rdi
    jz .bad
    test rdx,rdx
    jz .bad
    cmp rcx,512
    jb .bad
    cmp rcx,67108864
    ja .bad
    mov rbx,rdi
    mov r13,rsi
    mov r14,rdx
    mov [rbp+1600],rcx
    mov [rbp+1608],r13
    mov qword [rbp+1616],0
    ; Private snapshot once, before policy/crypto. BSP-only synchronous input.
    mov rdi,rbp
    mov rsi,rbx
    mov edx,1024
    call memcpy
    lea rdi,[rbp+1536]
    mov rsi,r14
    mov edx,32
    call memcpy
    test r13,r13
    jz .snapshot_done
    lea rdi,[rbp+1024]
    mov rsi,r13
    mov edx,512
    call memcpy
.snapshot_done:
    lea rdi,[rbp+1536]
    mov edx,32
    call ur_nonzero
    test eax,eax
    jz .bad
    call update_public_policy_get
    test rax,rax
    jz .bad
    cmp rdx,23408
    jne .bad
    mov r12,rax
    cmp dword [r12],1
    jne .bad
    cmp dword [r12+4],23408
    jne .bad
    cmp qword [r12+8],0
    je .bad
    cmp qword [r12+16],0
    je .bad
    cmp dword [r12+44],1
    jb .bad
    cmp dword [r12+44],32
    ja .bad
    cmp dword [r12+36],32
    ja .bad
    cmp dword [r12+40],32
    ja .bad
    ; Complete original catalog validation, even when current is retained.
    xor r15d,r15d
.catalog:
    mov rbx,r15
    shl rbx,9
    lea rbx,[r12+rbx+7024]
    mov rdi,rbx
    call ur_record
    test rax,rax
    jnz .bad
    xor r14d,r14d
.duplicate:
    cmp r14,r15
    jae .catalog_joins
    mov rsi,r14
    shl rsi,9
    lea rsi,[r12+rsi+7024+64]
    lea rdi,[rbx+64]
    mov edx,32
    call memcmp
    test eax,eax
    jz .bad
    inc r14
    jmp .duplicate
.catalog_joins:
    ; A signed offered/retained record cannot redefine a catalogued payload.
    mov rdi,rbx
    lea rsi,[rbp+256]
    call ur_conflict
    test eax,eax
    jnz .bad
    cmp qword [rbp+1608],0
    je .catalog_current
    mov rdi,rbx
    lea rsi,[rbp+1024]
    call ur_conflict
    test eax,eax
    jnz .bad
    jmp .next
.catalog_current:
    lea rdi,[rbx+64]
    lea rsi,[rbp+1536]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .next
    mov rax,[rbp+1600]
    cmp [rbx+128],rax
    jne .next
    mov [rbp+1616],rbx
.next:
    inc r15
    cmp r15d,[r12+44]
    jb .catalog
    cmp qword [rbp+1608],0
    je .current_done
    lea rbx,[rbp+1024]
    mov rdi,rbx
    call ur_record
    test rax,rax
    jnz .bad
    lea rdi,[rbx+64]
    lea rsi,[rbp+1536]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    mov rax,[rbp+1600]
    cmp [rbx+128],rax
    jne .bad
    mov [rbp+1616],rbx
.current_done:
    mov r13,[rbp+1616]
    test r13,r13
    jz .bad
    ; Original feed grammar and installed selected channel/exact asset identity.
    cmp dword [rbp],0x31464350
    jne .bad
    cmp dword [rbp+4],0x04000001
    jne .bad
    lea rdi,[rbp+8]
    lea rsi,[r12+232]
    mov edx,24
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[rbp+32]
    lea rsi,[r12+80]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[rbp+64]
    lea rsi,[r12+528]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[rbp+128]
    lea rsi,[r12+176]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[rbp+160]
    mov edx,96
    call ur_nonzero
    test eax,eax
    jnz .bad
    lea rdi,[rbp+1568]
    lea rsi,[rbp+256]
    mov edx,512
    call sha256_hash
    test rax,rax
    jnz .bad
    lea rdi,[rbp+1568]
    lea rsi,[rbp+96]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[rbp+768]
    mov rsi,rbp
    mov edx,768
    lea rcx,[r12+256]
    call rsa2048_verify_sha256
    test eax,eax
    jnz .bad
    lea rbx,[rbp+256]
    mov rdi,rbx
    call ur_record
    test rax,rax
    jnz .bad
    mov rax,[rbx+136]
    cmp rax,[r12+16]
    jb .bad
    cmp rax,[r13+136]
    jb .bad
    lea rdi,[rbx+144]
    lea rsi,[r12+24]
    call ur_version_below
    test eax,eax
    jnz .bad
    lea rdi,[rbx+144]
    lea rsi,[r13+144]
    call ur_version_below
    test eax,eax
    jnz .bad
    xor r15d,r15d
.revoked_payload:
    cmp r15d,[r12+36]
    jae .revoked_build_start
    mov rsi,r15
    shl rsi,5
    lea rsi,[r12+rsi+4976]
    lea rdi,[rbx+64]
    mov edx,32
    call memcmp
    test eax,eax
    jz .bad
    inc r15
    jmp .revoked_payload
.revoked_build_start:
    xor r15d,r15d
.revoked_build:
    cmp r15d,[r12+40]
    jae .ok
    mov rsi,r15
    shl rsi,5
    lea rsi,[r12+rsi+6000]
    lea rdi,[rbx+96]
    mov edx,32
    call memcmp
    test eax,eax
    jz .bad
    inc r15
    jmp .revoked_build
.ok:
    cmp dword [rbp+1624],0
    je .predicate_ok
    ; Every signature, catalog join, floor and revocation above applies before
    ; classification. Product tuple must strictly advance, or full signed PRL1
    ; must equal the actual authenticated current record (including hash/size).
    lea rdi,[r13+144]
    lea rsi,[rbp+256+144]
    call ur_version_below
    test eax,eax
    jnz .available
    lea rdi,[rbp+256]
    mov rsi,r13
    mov edx,512
    call memcmp
    test eax,eax
    jnz .bad
    mov ebx,1
    jmp .scrub
.available:
    mov ebx,2
    jmp .scrub
.predicate_ok:
    xor ebx,ebx
    jmp .scrub
.bad:
    mov rbx,-1
.scrub:
    mov rdi,rbp
    xor esi,esi
    mov edx,1640
    call memset
    mov rax,rbx
    add rsp,1640
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Complete PRL1 grammar/signature against the installed release-purpose key.
; R12=immutable policy, RDI=private record. No admission/floor on outgoing current.
ur_record:
    push rbx
    mov rbx,rdi
    cmp dword [rbx],0x314c5250
    jne .bad
    cmp dword [rbx+4],0x02000001
    jne .bad
    lea rdi,[rbx+8]
    lea rsi,[r12+208]
    mov edx,24
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[rbx+32]
    lea rsi,[r12+80]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[rbx+64]
    mov edx,32
    call ur_nonzero
    test eax,eax
    jz .bad
    lea rdi,[rbx+96]
    mov edx,32
    call ur_nonzero
    test eax,eax
    jz .bad
    cmp qword [rbx+128],512
    jb .bad
    cmp qword [rbx+128],67108864
    ja .bad
    cmp qword [rbx+136],0
    je .bad
    cmp dword [rbx+156],0x50343658
    jne .bad
    lea rdi,[rbx+160]
    mov edx,96
    call ur_nonzero
    test eax,eax
    jnz .bad
    lea rdi,[rbx+256]
    mov rsi,rbx
    mov edx,256
    lea rcx,[r12+256]
    call rsa2048_verify_sha256
    test eax,eax
    jnz .bad
    xor eax,eax
    pop rbx
    ret
.bad:
    mov rax,-1
    pop rbx
    ret

; Same payload digest but different original512 is a conflict (including size).
ur_conflict:
    push rbx
    push r13
    sub rsp,8
    mov rbx,rdi
    mov r13,rsi
    add rdi,64
    add rsi,64
    mov edx,32
    call memcmp
    test eax,eax
    jnz .no
    mov rdi,rbx
    mov rsi,r13
    mov edx,512
    call memcmp
    jmp .done
.no:
    xor eax,eax
.done:
    add rsp,8
    pop r13
    pop rbx
    ret

ur_nonzero:
    xor eax,eax
.loop:
    or al,[rdi]
    inc rdi
    dec edx
    jnz .loop
    ret
ur_version_below:
    xor ecx,ecx
.loop:
    mov eax,[rdi+rcx*4]
    cmp eax,[rsi+rcx*4]
    jb .below
    ja .no
    inc ecx
    cmp ecx,3
    jb .loop
.no:
    xor eax,eax
    ret
.below:
    mov eax,1
    ret

; The same complete journal grammar as Manager (including B1 and external
; attempts), with its CRC entry adapted to the native core CRC ABI.
%ifndef PBM_CONTRACT_VERSION
%include "boot/boot_v2_contract.inc"
%endif
UR_B1_STATE_MAGIC                  equ 0x31503142 ; "B1P1"
UR_B1_STATE_OFF                    equ 152
UR_B1_STATE_MAGIC_OFF              equ 152
UR_B1_STATE_VERSION_OFF            equ 156
UR_B1_STATE_FLAGS_OFF              equ 157
UR_B1_STATE_EVIDENCE_MASK_OFF      equ 158
UR_B1_STATE_SAFE_ENTRY_OFF         equ 159
UR_B1_STATE_FP_A_OFF               equ 160
UR_B1_STATE_FP_B_OFF               equ 164
UR_B1_STATE_SHA_A_OFF              equ 168
UR_B1_STATE_SHA_B_OFF              equ 200
UR_B1_STATE_SAFE_SHA_OFF           equ 232
UR_B1_STATE_END_OFF                equ 264
UR_B1_STATE_VERSION                equ 1
UR_B1_F_SUSPECT_HARDWARE           equ 0x01
UR_B1_F_MEMTEST_PRESELECT          equ 0x02
UR_B1_F_SAFE_VIDEO_PENDING         equ 0x04
UR_B1_SLOT_BOTH_MASK               equ ((1 << PBM_ENTRY_PAOS_A) | (1 << PBM_ENTRY_PAOS_B))

UR_B1_FAILURE_FINGERPRINT_TAG      equ 0xB1000000
; RDI/RSI=exact private native-read copies or zero for confirmed absence.
; IO ERROR is not absence: the broker refuses that case before this pure leaf.
; RAX=selected original pointer or0. Selection precedes eligibility; never fall
; back to an older idle state after selecting a newer valid Trial/BIP.
update_release_state_select:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    xor ebx,ebx
    test r12,r12
    jz .second
    call ur_state_valid
    test eax,eax
    jz .second
    mov rbx,r12
.second:
    test r13,r13
    jz .out
    mov rdi,r13
    call ur_state_valid
    test eax,eax
    jz .out
    test rbx,rbx
    jz .choose_second
    mov rax,[r13+PBM_STATE_GENERATION_OFF]
    cmp rax,[rbx+PBM_STATE_GENERATION_OFF]
    ja .choose_second
    jb .out
    mov rdi,rbx
    mov rsi,r13
    mov edx,PBM_STATE_SIZE
    call memcmp
    test eax,eax
    jz .out
    xor ebx,ebx                 ; conflicting equal-generation originals
    jmp .out
.choose_second:
    mov rbx,r13
.out:
    mov rax,rbx
    pop r13
    pop r12
    pop rbx
    ret

; Selected journal only. Pure eligibility, never manifest authentication or a
; write grant. Preserve Manager's normal Rescue+BIP and closed failed external
; history; refuse unresolved Trial/pending/hardware suspicion and exhaustion.
update_release_state_idle:
    test rdi,rdi
    jz .early_bad
    push r12
    mov r12,rdi
    call ur_state_valid
    test eax,eax
    jz .bad
    cmp qword [r12+PBM_STATE_GENERATION_OFF],-1
    je .bad
    cmp byte [r12+PBM_STATE_TRIAL_OFF],0
    jne .bad
    cmp byte [r12+PBM_STATE_TRIES_LEFT_OFF],0
    jne .bad
    cmp byte [r12+PBM_STATE_FAILURE_COUNT_OFF],0
    jne .bad
    cmp word [r12+PBM_STATE_PENDING_ENTRY_OFF],0
    jne .bad
    movzx ecx,byte [r12+PBM_STATE_ACTIVE_OFF]
    mov eax,1
    shl eax,cl
    test [r12+PBM_STATE_VERIFIED_MASK_OFF],al
    jz .bad
    test [r12+PBM_STATE_QUARANTINE_MASK_OFF],al
    jnz .bad
    cmp byte [r12+PBM_STATE_BIP_OFF],0
    je .external
    cmp byte [r12+PBM_STATE_LAST_ENTRY_OFF],PBM_ENTRY_RESCUE
    jne .bad
    cmp byte [r12+PBM_STATE_LAST_PROFILE_OFF],PBM_PROFILE_RESCUE
    jne .bad
.external:
    cmp byte [r12+PBM_STATE_EXTERNAL_PENDING_OFF],0
    jne .bad
    cmp byte [r12+PBM_STATE_EXTERNAL_ENTRY_OFF],0
    jne .external_failed
    cmp byte [r12+PBM_STATE_EXTERNAL_STATUS_OFF],0
    jne .bad
    cmp qword [r12+PBM_STATE_EXTERNAL_NONCE_OFF],0
    jne .bad
    jmp .external_ready_zero
.external_failed:
    ; Structural validation already limits nonzero external ID to4/5.
    cmp byte [r12+PBM_STATE_EXTERNAL_STATUS_OFF],PBM_EXTERNAL_STATUS_UNAVAILABLE
    jne .bad
    cmp qword [r12+PBM_STATE_EXTERNAL_NONCE_OFF],0
    je .bad
.external_ready_zero:
    cmp qword [r12+PBM_STATE_EXTERNAL_READY_OFF],0
    jne .bad
    cmp dword [r12+UR_B1_STATE_MAGIC_OFF],0
    je .good
    ; B1 safe-video/suspect/Memtest recovery owns its own clear path.
    cmp byte [r12+UR_B1_STATE_FLAGS_OFF],0
    jne .bad
.good:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    ret
.early_bad:
    xor eax,eax
    ret

ur_b1_state_valid:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    cmp  dword [r12 + UR_B1_STATE_MAGIC_OFF], 0
    je   .good
    cmp  dword [r12 + UR_B1_STATE_MAGIC_OFF], UR_B1_STATE_MAGIC
    jne  .bad
    cmp  byte [r12 + UR_B1_STATE_VERSION_OFF], UR_B1_STATE_VERSION
    jne  .bad
    mov  al, [r12 + UR_B1_STATE_FLAGS_OFF]
    test al, 0xF8
    jnz  .bad
    mov  al, [r12 + UR_B1_STATE_EVIDENCE_MASK_OFF]
    test al, 0xF9
    jnz  .bad

    test al, (1 << PBM_ENTRY_PAOS_A)
    jz   .slot_b
    mov  eax, [r12 + UR_B1_STATE_FP_A_OFF]
    and  eax, 0xFF000000
    cmp  eax, UR_B1_FAILURE_FINGERPRINT_TAG
    jne  .bad
    lea  rbx, [r12 + UR_B1_STATE_SHA_A_OFF]
    xor  edx, edx
    xor  ecx, ecx
.sha_a:
    or   dl, [rbx + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .sha_a
    test dl, dl
    jz   .bad
.slot_b:
    mov  al, [r12 + UR_B1_STATE_EVIDENCE_MASK_OFF]
    test al, (1 << PBM_ENTRY_PAOS_B)
    jz   .safe_video
    mov  eax, [r12 + UR_B1_STATE_FP_B_OFF]
    and  eax, 0xFF000000
    cmp  eax, UR_B1_FAILURE_FINGERPRINT_TAG
    jne  .bad
    lea  rbx, [r12 + UR_B1_STATE_SHA_B_OFF]
    xor  edx, edx
    xor  ecx, ecx
.sha_b:
    or   dl, [rbx + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .sha_b
    test dl, dl
    jz   .bad

.safe_video:
    test byte [r12 + UR_B1_STATE_FLAGS_OFF], UR_B1_F_SAFE_VIDEO_PENDING
    jz   .safe_absent
    movzx eax, byte [r12 + UR_B1_STATE_SAFE_ENTRY_OFF]
    cmp  eax, PBM_ENTRY_PAOS_A
    jb   .bad
    cmp  eax, PBM_ENTRY_PAOS_B
    ja   .bad
    cmp  al, [r12 + PBM_STATE_PENDING_ENTRY_OFF]
    jne  .bad
    cmp  byte [r12 + PBM_STATE_PENDING_PROFILE_OFF], PBM_PROFILE_SAFE
    jne  .bad
    lea  rbx, [r12 + UR_B1_STATE_SAFE_SHA_OFF]
    xor  edx, edx
    xor  ecx, ecx
.safe_sha:
    or   dl, [rbx + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .safe_sha
    test dl, dl
    jz   .bad
    jmp  .suspect
.safe_absent:
    cmp  byte [r12 + UR_B1_STATE_SAFE_ENTRY_OFF], PBM_ENTRY_NONE
    jne  .bad
    lea  rbx, [r12 + UR_B1_STATE_SAFE_SHA_OFF]
    xor  edx, edx
    xor  ecx, ecx
.safe_zero:
    or   dl, [rbx + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .safe_zero
    test dl, dl
    jnz  .bad

.suspect:
    test byte [r12 + UR_B1_STATE_FLAGS_OFF], UR_B1_F_MEMTEST_PRESELECT
    jz   .suspect_flag
    test byte [r12 + UR_B1_STATE_FLAGS_OFF], UR_B1_F_SUSPECT_HARDWARE
    jz   .bad
.suspect_flag:
    test byte [r12 + UR_B1_STATE_FLAGS_OFF], UR_B1_F_SUSPECT_HARDWARE
    jz   .good
    mov  al, [r12 + UR_B1_STATE_EVIDENCE_MASK_OFF]
    and  al, UR_B1_SLOT_BOTH_MASK
    cmp  al, UR_B1_SLOT_BOTH_MASK
    jne  .bad
    mov  eax, [r12 + UR_B1_STATE_FP_A_OFF]
    cmp  eax, [r12 + UR_B1_STATE_FP_B_OFF]
    je   .bad
    test byte [r12 + UR_B1_STATE_FLAGS_OFF], UR_B1_F_MEMTEST_PRESELECT
    jz   .bad
    test byte [r12 + UR_B1_STATE_FLAGS_OFF], UR_B1_F_SAFE_VIDEO_PENDING
    jnz  .bad
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 0
    je   .suspect_pending
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 1
    jne  .bad
    ; After terminal selection the ordinary attempt transaction arms the
    ; verified Rescue child.  That BIP is coherent only for Rescue itself and
    ; must never reopen either PaOS slot.
    cmp  byte [r12 + PBM_STATE_LAST_ENTRY_OFF], PBM_ENTRY_RESCUE
    jne  .bad
    cmp  byte [r12 + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_RESCUE
    jne  .bad
    cmp  byte [r12 + PBM_STATE_LAST_REASON_OFF], PBM_REASON_RESCUE
    jne  .bad
.suspect_pending:
    cmp  byte [r12 + PBM_STATE_PENDING_ENTRY_OFF], PBM_ENTRY_NONE
    jne  .bad
    cmp  byte [r12 + PBM_STATE_TRIAL_OFF], PBM_ENTRY_NONE
    jne  .bad
.good:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; state_valid(RDI=512-byte record) -> EAX=1 valid, 0 rejected.
ur_state_valid:
    push rbx
    push r12
    mov  r12, rdi
    cmp  dword [r12 + PBM_STATE_MAGIC_OFF], PBM_STATE_MAGIC
    jne  .bad
    cmp  word [r12 + PBM_STATE_VERSION_OFF], PBM_CONTRACT_VERSION
    jne  .bad
    cmp  word [r12 + PBM_STATE_SIZE_OFF], PBM_STATE_SIZE
    jne  .bad
    mov  ebx, [r12 + PBM_STATE_CRC32]
    mov  rdi, r12
    mov  esi, PBM_STATE_CRC32
    call hotpatch_crc32
    cmp  eax, ebx
    jne  .bad
    movzx eax, byte [r12 + PBM_STATE_ACTIVE_OFF]
    cmp  eax, PBM_ENTRY_PAOS_A
    je   .active_ok
    cmp  eax, PBM_ENTRY_PAOS_B
    jne  .bad
.active_ok:
    movzx eax, byte [r12 + PBM_STATE_PREVIOUS_OFF]
    cmp  eax, PBM_ENTRY_PAOS_A
    je   .previous_ok
    cmp  eax, PBM_ENTRY_PAOS_B
    jne  .bad
.previous_ok:
    movzx eax, byte [r12 + PBM_STATE_TRIAL_OFF]
    cmp  eax, PBM_ENTRY_PAOS_B
    ja   .bad
    movzx edx, byte [r12 + PBM_STATE_ACTIVE_OFF]
    cmp  dl, [r12 + PBM_STATE_PREVIOUS_OFF]
    jne  .roles_ok
    test al, al
    jz   .bad
    cmp  al, dl
    je   .bad
.roles_ok:
    movzx eax, byte [r12 + PBM_STATE_MENU_POLICY_OFF]
    cmp  eax, PBM_MENU_DETAILED
    ja   .bad
    movzx eax, byte [r12 + PBM_STATE_MENU_TIMEOUT_OFF]
    cmp  eax, PBM_MENU_TIMEOUT_MIN
    jb   .bad
    cmp  eax, PBM_MENU_TIMEOUT_MAX
    ja   .bad
    movzx eax, byte [r12 + PBM_STATE_PENDING_ENTRY_OFF]
    cmp  eax, PBM_ENTRY_MAX
    ja   .bad
    movzx edx, byte [r12 + PBM_STATE_PENDING_PROFILE_OFF]
    cmp  edx, PBM_PROFILE_EXTERNAL
    ja   .bad
    test eax, eax
    jnz  .pending_nonempty
    test edx, edx
    jnz  .bad
    jmp  .pending_ok
.pending_nonempty:
    cmp  eax, PBM_ENTRY_PAOS_B
    ja   .pending_rescue
    cmp  edx, PBM_PROFILE_SAFE
    ja   .bad
    jmp  .pending_ok
.pending_rescue:
    cmp  eax, PBM_ENTRY_RESCUE
    jne  .pending_external
    cmp  edx, PBM_PROFILE_RESCUE
    jne  .bad
    jmp  .pending_ok
.pending_external:
    cmp  edx, PBM_PROFILE_EXTERNAL
    jne  .bad
.pending_ok:
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 1
    ja   .bad
    cmp  byte [r12 + PBM_STATE_LAST_ENTRY_OFF], PBM_ENTRY_MAX
    ja   .bad
    cmp  byte [r12 + PBM_STATE_LAST_PROFILE_OFF], PBM_PROFILE_EXTERNAL
    ja   .bad
    cmp  byte [r12 + PBM_STATE_LAST_REASON_OFF], PBM_REASON_CMOS_UNTRUSTED
    ja   .bad
    test byte [r12 + PBM_STATE_LAST_FLAGS_OFF], ~PBM_LAST_F_MASK & 0xFF
    jnz  .bad
    cmp  byte [r12 + PBM_STATE_START_COUNT_OFF], 2
    ja   .bad
    cmp  byte [r12 + PBM_STATE_START_ARMED_OFF], 1
    ja   .bad
    mov  al, [r12 + PBM_STATE_VERIFIED_MASK_OFF]
    or   al, [r12 + PBM_STATE_QUARANTINE_MASK_OFF]
    or   al, [r12 + PBM_STATE_SAFE_ATTEMPTED_OFF]
    test al, 0xF9                    ; only slot A/B bits 1 and 2 are legal
    jnz  .bad
    movzx eax, byte [r12 + PBM_STATE_EXTERNAL_ENTRY_OFF]
    test eax, eax
    jz   .external_empty
    cmp  eax, PBM_ENTRY_WINDOWS
    je   .external_identity
    cmp  eax, PBM_ENTRY_LINUX
    jne  .bad
.external_identity:
    cmp  byte [r12 + PBM_STATE_EXTERNAL_PENDING_OFF], 1
    ja   .bad
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_INVALID_PAYLOAD
    ja   .bad
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_INVALID_PAYLOAD
    je   .external_invalid
    mov  rax, [r12 + PBM_STATE_EXTERNAL_NONCE_OFF]
    test rax, rax
    jz   .bad
    mov  rdx, [r12 + PBM_STATE_EXTERNAL_READY_OFF]
    test rdx, rdx
    jz   .external_domains
    cmp  rdx, rax
    jne  .bad
.external_domains:
    cmp  byte [r12 + PBM_STATE_EXTERNAL_PENDING_OFF], 0
    je   .external_closed
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_NONE
    jne  .bad
    cmp  byte [r12 + PBM_STATE_BIP_OFF], 0
    jne  .bad
    jmp  .external_ok
.external_closed:
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_READY
    je   .external_closed_ready
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_UNAVAILABLE
    jne  .external_ok
    cmp  qword [r12 + PBM_STATE_EXTERNAL_READY_OFF], 0
    jne  .bad
    jmp  .external_ok
.external_closed_ready:
    cmp  rdx, rax
    jne  .bad
    jmp  .external_ok
.external_invalid:
    cmp  byte [r12 + PBM_STATE_EXTERNAL_PENDING_OFF], 0
    jne  .bad
    cmp  qword [r12 + PBM_STATE_EXTERNAL_NONCE_OFF], 0
    jne  .bad
    cmp  qword [r12 + PBM_STATE_EXTERNAL_READY_OFF], 0
    jne  .bad
    jmp  .external_ok
.external_empty:
    cmp  byte [r12 + PBM_STATE_EXTERNAL_PENDING_OFF], 0
    jne  .bad
    cmp  qword [r12 + PBM_STATE_EXTERNAL_NONCE_OFF], 0
    jne  .bad
    cmp  qword [r12 + PBM_STATE_EXTERNAL_READY_OFF], 0
    jne  .bad
    cmp  byte [r12 + PBM_STATE_EXTERNAL_STATUS_OFF], PBM_EXTERNAL_STATUS_NONE
    jne  .bad
.external_ok:
    cmp  dword [r12 + 59], 0
    jne  .bad
    cmp  byte [r12 + 63], 0
    jne  .bad
    mov  rax, [r12 + PBM_STATE_MANIFEST_SEQ_OFF]
    xor  edx, edx
    xor  ecx, ecx
.manifest_digest:
    or   dl, [r12 + PBM_STATE_MANIFEST_SHA_OFF + rcx]
    inc  ecx
    cmp  ecx, 32
    jb   .manifest_digest
    test rax, rax
    jz   .manifest_unbound
    test dl, dl
    jz   .bad
    jmp  .manifest_ok
.manifest_unbound:
    test dl, dl
    jnz  .bad
.manifest_ok:
    mov  rdi, r12
    call ur_b1_state_valid
    test eax, eax
    jz   .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret


; Exact private native originals only. This proves the signed owner manifest,
; selected eligible PBSJ and actual streamed Active payload agree. No PBH1,
; owner-public.pem, worker key, callback or successful class supplies trust.
; RDI=PBMF1024, RSI=selected PBSJ512, RDX=actual SHA32, RCX=actual full size.
; EAX=1 verified /0 refused. No IO, state update or grant.
update_release_current_join:
    test rdi,rdi
    jz .early_bad
    test rsi,rsi
    jz .early_bad
    test rdx,rdx
    jz .early_bad
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,32
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    mov esi,PBM_MANIFEST_SIZE
    lea rdx,[rel ur_owner_key_id]
    lea rcx,[rel boot_v2_owner_modulus]
    call pbm_manifest_verify_anchored
    cmp eax,1
    jne .bad
    mov rdi,r13
    call update_release_state_idle
    cmp eax,1
    jne .bad
    mov rax,[r12+8]
    cmp rax,[r13+PBM_STATE_MANIFEST_SEQ_OFF]
    jne .bad
    mov rdi,rsp
    mov rsi,r12
    mov edx,PBM_MANIFEST_SIZE
    call sha256_hash
    test rax,rax
    jnz .bad
    mov rdi,rsp
    lea rsi,[r13+PBM_STATE_MANIFEST_SHA_OFF]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    movzx ebx,byte [r13+PBM_STATE_ACTIVE_OFF]
    movzx ecx,byte [r12+18]
    lea rdi,[r12+128]
.find:
    cmp [rdi],bl
    je .found
    add rdi,128
    dec ecx
    jnz .find
    jmp .bad
.found:
    mov eax,[rdi+4]
    cmp rax,r15
    jne .bad
    mov r12,rdi
    ; The native broker reads fixed A/B paths, so a signed alternative path
    ; cannot be joined merely because a different file has the same digest.
    lea rsi,[rel ur_slot_a_path]
    cmp bl,PBM_ENTRY_PAOS_A
    je .path
    lea rsi,[rel ur_slot_b_path]
.path:
    cmp word [r12+48],(ur_slot_a_path_end-ur_slot_a_path)/2-1
    jne .bad
    lea rdi,[r12+52]
    mov edx,ur_slot_a_path_end-ur_slot_a_path
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[r12+16]
    mov rsi,r14
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.early_bad:
    xor eax,eax
    ret

; Pure receiving-side expected journals for the existing Settings stage rail.
; RDI original PBMF1024,RSI selected original PBSJ512,RDX successor PBMF1024,
; RCX original already-native-admitted PRL512,R8 outSTART512,R9 outARMED512.
; ->1 no retirement/2 retirement/0refused. No effect or payload authority.
; Matches update_effect.c: preserve all signed bytes except sequence and the
; inactive entry, +1 per-PC rollback index, retire credited inactive first,
; then exactly one unverified Trial with one try; never promote Active.
update_release_stage_expected:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,88
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    mov [rsp],r8
    mov [rsp+8],r9
    mov esi,1024
    lea rdx,[rel ur_owner_key_id]
    lea rcx,[rel boot_v2_owner_modulus]
    call pbm_manifest_verify_anchored
    cmp eax,1
    jne .bad
    mov rdi,r14
    mov esi,1024
    lea rdx,[rel ur_owner_key_id]
    lea rcx,[rel boot_v2_owner_modulus]
    call pbm_manifest_verify_anchored
    cmp eax,1
    jne .bad
    mov rdi,r13
    call update_release_state_idle
    cmp eax,1
    jne .bad
    mov rax,[r12+8]
    cmp rax,-1
    je .bad
    cmp rax,[r13+112]
    jne .bad
    inc rax
    cmp rax,[r14+8]
    jne .bad
    lea rdi,[rsp+32]
    mov rsi,r12
    mov edx,1024
    call sha256_hash
    test rax,rax
    jnz .bad
    lea rdi,[rsp+32]
    lea rsi,[r13+120]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    ; The existing normal stage rail uses the fixed A,B entry rows.
    cmp byte [r12+128],1
    jne .bad
    cmp byte [r12+256],2
    jne .bad
    movzx ebx,byte [r13+16]
    mov ebp,3
    sub ebp,ebx                    ; inactive ID1/2
    mov [rsp+24],ebp
    dec ebp
    shl ebp,7
    add ebp,128                    ; inactive entry offset
    xor ebx,ebx
.signed_bytes:
    cmp ebx,8
    jb .compare
    cmp ebx,16
    jb .next
    cmp ebx,ebp
    jb .compare
    lea eax,[rbp+128]
    cmp ebx,eax
    jb .next
.compare:
    mov al,[r12+rbx]
    cmp al,[r14+rbx]
    jne .bad
.next:
    inc ebx
    cmp ebx,768
    jb .signed_bytes
    lea rdi,[r12+rbp]
    lea rsi,[r14+rbp]
    mov edx,4
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[r12+rbp+48]
    lea rsi,[r14+rbp+48]
    mov edx,80
    call memcmp
    test eax,eax
    jnz .bad
    mov rax,[r12+rbp+8]
    cmp rax,-1
    je .bad
    inc rax
    cmp rax,[r14+rbp+8]
    jne .bad
    mov rax,[r15+128]
    cmp rax,512
    jb .bad
    cmp rax,67108864
    ja .bad
    mov edx,[r14+rbp+4]
    cmp rax,rdx
    jne .bad
    lea rdi,[r14+rbp+16]
    lea rsi,[r15+64]
    mov edx,32
    call memcmp
    test eax,eax
    jnz .bad
    lea rdi,[r12+rbp+16]
    lea rsi,[r15+64]
    mov edx,32
    call memcmp
    test eax,eax
    jz .bad
    ; Fixed native file ID must mean the exact owner-signed canonical path.
    lea rsi,[rel ur_slot_a_path]
    cmp dword [rsp+24],1
    je .path
    lea rsi,[rel ur_slot_b_path]
.path:
    cmp word [r14+rbp+48],(ur_slot_a_path_end-ur_slot_a_path)/2-1
    jne .bad
    lea rdi,[r14+rbp+52]
    mov edx,ur_slot_a_path_end-ur_slot_a_path
    call memcmp
    test eax,eax
    jnz .bad
    mov rdi,r13
    mov rsi,[rsp]
    call update_release_stage_start
    test eax,eax
    jz .bad
    mov [rsp+16],eax
    mov rdi,[rsp+8]
    mov rsi,[rsp]
    mov edx,512
    call memcpy
    mov rbx,[rsp+8]
    inc qword [rbx+8]
    mov ecx,[rsp+24]
    mov [rbx+18],cl
    mov byte [rbx+19],1
    mov eax,1
    shl eax,cl
    not eax
    and [rbx+20],al
    and [rbx+21],al
    and [rbx+30],al
    mov word [rbx+25],0
    mov byte [rbx+27],0
    mov rax,[r14+8]
    mov [rbx+112],rax
    lea rdi,[rbx+120]
    mov rsi,r14
    mov edx,1024
    call sha256_hash
    test rax,rax
    jnz .bad
    mov rdi,rbx
    mov esi,508
    call hotpatch_crc32
    mov [rbx+508],eax
    mov rdi,rbx
    call ur_state_valid
    cmp eax,1
    jne .bad
    mov eax,[rsp+16]
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,88
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI selected eligible PBSJ512,RSI out512 ->1unchanged/2retired/0refused.
; Pure normal-stage retirement transform, shared with the pre-publication gate.
update_release_stage_start:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    call update_release_state_idle
    cmp eax,1
    jne .bad
    mov rdi,r13
    mov rsi,r12
    mov edx,512
    call memcpy
    movzx ecx,byte [r12+16]
    mov eax,3
    sub eax,ecx
    mov ecx,eax
    mov ebx,1
    shl ebx,cl
    mov al,[r12+20]
    or al,[r12+30]
    test al,bl
    jz .plain
    cmp qword [r12+8],-2
    jae .bad                      ; two remaining generations required
    inc qword [r13+8]
    not ebx
    and [r13+20],bl
    and [r13+30],bl
    mov rdi,r13
    mov esi,508
    call hotpatch_crc32
    mov [r13+508],eax
    mov eax,2
    jmp .out
.plain:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; The immutable key ID and modulus are generated together by BUILD. Neither
; comes from the ESP or a mutable caller argument. No unprovisioned fallback.
%ifndef BOOT_V2_OWNER_KEY_ID_BYTES
%error "native updater requires the generated Boot-v2 owner key ID"
%endif
ur_owner_key_id: db BOOT_V2_OWNER_KEY_ID_BYTES
align 2, db 0                           ; CHAR16 paths (char16_align_check); b follows a at even length
ur_slot_a_path: dw __utf16__("\EFI\PaOS\slots\paos-a.efi"),0
ur_slot_a_path_end:
ur_slot_b_path: dw __utf16__("\EFI\PaOS\slots\paos-b.efi"),0
ur_private_data_end:
%include "bootmgr/pbm_manifest_verify.inc"
%endif
