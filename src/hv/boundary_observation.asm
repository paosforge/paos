;; MODULE hv/boundary_observation
;; LAYER 5
;; EXPORTS hv_boundary_observe, hv_boundary_render, hv_boundary_render_amd, hv_boundary_render_intel
;; IMPORTS hv/boundary, hv/vmx, hv/vm_profile, core/lib/sha256
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Passive native BSP observation, not a policy request/receipt or execution proof.
; Called with IF0 (SVM entry also GIF0), before loading guest GPRs. No callbacks,
; yielding, allocation, guest memory, privileged instruction or authority change.
; RDI=private retained HVB frame, ESI=actual backend1 VMX/2 SVM. All GPRs and
; flags survive; return RAX is the exact boundary adapter result. Publication is
; serialized with command readers at the existing stopped-vCPU BSP boundary.
; Arm clears old capture/policy; each sample clears again. Stage1=guard result,
; 2=sample attempted,3=selector attempted,4=selector scoped plan. -2 means not
; called; raw partial failed samples are NOT valid CSS. Stage4 is not VM entry.
; Latest Linux ENTRY observation only; AIRLOCK/HLT and exit receipts stay private.
; Retains immutable selected profile bytes, never exposes native pointers/tokens.
BNO_CAPTURE equ 112
BNO_POLICY equ 256
BNO_PROFILE equ 352
BNO_AMD_PRESENT equ BNO_PROFILE + VP_BYTES
BNO_AMD_INPUT equ BNO_AMD_PRESENT + 8
BNO_INTEL_PRESENT equ BNO_AMD_INPUT + 200
BNO_INTEL_INPUT equ BNO_INTEL_PRESENT + 8
BNO_SIZE equ BNO_INTEL_INPUT + 232

hv_boundary_observe:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov r8, rdi
    mov r9d, esi
    lea rdx, [rel hv_boundary_observation]
    mov qword [rdx], 0
    mov [rdx + 8], rax               ; exact adapter result; never an executor receipt
    mov [rdx + 16], r9
    movzx eax, byte [rel hv_launch_mode]
    mov [rdx + 24], rax
    mov eax, [rel hv_linux_start_gen]
    mov [rdx + 32], rax
    mov eax, [rel hv_linux_start_consumed]
    mov [rdx + 40], rax
    mov eax, [rel hv_linux_load_gen]
    mov [rdx + 48], rax
    mov eax, [rel vm_profile_gen]
    mov [rdx + 56], rax
    mov eax, [rel hv_launches]
    mov [rdx + 64], rax
    mov rax, [r8 + HVB_STAGE]
    mov [rdx + 72], rax
    mov rax, [r8 + HVB_SAMPLE_RC]
    mov [rdx + 80], rax
    mov rax, [r8 + HVB_SELECT_RC]
    mov [rdx + 88], rax
    mov qword [rdx + 96], 0
    mov rax, [rel vm_profile_active]
    mov [rdx + 104], rax              ; internal equality only, never rendered
    lea rdi, [rdx + BNO_CAPTURE]
    lea rsi, [r8 + HVB_CAPTURE]
    mov ecx, (144 + 96) / 8
    cld
    rep movsq
    ; The CSS144 projection does not contain checked160 bytes112..159 or
    ; the selector's private forty-byte tail. Retain the actual complete input
    ; only after the checked sampler succeeded and the AMD selector was called.
    ; Refusal is useful evidence too; presence never means admission/custody.
    lea rdi, [rdx + BNO_AMD_PRESENT]
    xor eax, eax
    mov ecx, (8 + 200) / 8
    rep stosq
    cmp qword [r8 + HVB_SAMPLE_RC], 0
    jne .amd_done
    cmp qword [r8 + HVB_STAGE], 3
    jb .amd_done
    cmp qword [r8 + HVB_STAGE], 4
    ja .amd_done
    cmp dword [r8 + HVB_AMD], 2       ; actual captured vendor, not host resampling
    jne .amd_done
    mov rax, [r8 + HVB_AMD + 160]
    cmp rax, 2
    je .amd_copy
    cmp rax, 3
    je .amd_copy
    cmp rax, 4
    je .amd_copy
    cmp rax, 7
    jne .amd_done
.amd_copy:
    lea rdi, [rdx + BNO_AMD_INPUT]
    lea rsi, [r8 + HVB_AMD]
    mov ecx, 200 / 8
    rep movsq
    mov qword [rdx + BNO_AMD_PRESENT], 1
.amd_done:
    ; CSS144 omits Intel's checked permissions/control values and full-policy
    ; selector tail. Keep one complete actual232 input, separately from AMD.
    ; Never reconstruct it from the legacy projection or resample at query time.
    lea rdi, [rdx + BNO_INTEL_PRESENT]
    xor eax, eax
    mov ecx, (8 + 232) / 8
    rep stosq
    cmp dword [r8 + HVB_SVM], 2
    jne .intel_done
    cmp qword [r8 + HVB_SAMPLE_RC], 0
    jne .intel_done
    cmp qword [r8 + HVB_STAGE], 3
    jb .intel_done
    cmp qword [r8 + HVB_STAGE], 4
    ja .intel_done
    cmp dword [r8 + HVB_INTEL], 1
    jne .intel_done
    cmp qword [r8 + HVB_INTEL + 192], 6
    jne .intel_done
    lea rdi, [rdx + BNO_INTEL_INPUT]
    lea rsi, [r8 + HVB_INTEL]
    mov ecx, 232 / 8
    rep movsq
    mov qword [rdx + BNO_INTEL_PRESENT], 1
.intel_done:
    lea rdi, [rdx + BNO_PROFILE]
    xor eax, eax
    mov ecx, VP_BYTES / 8
    rep stosq
    mov rsi, [rdx + 104]
    test rsi, rsi
    jz .publish
    lea rdi, [rdx + BNO_PROFILE]
    mov ecx, VP_BYTES / 8
    rep movsq
    mov qword [rdx + 96], 1
.publish:
    mov qword [rdx], 1
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

; Read-only: current0 retains old evidence as old; never binds it to new START.
; CSS/policy are exact byte-order hex, including validity bits and 64-bit values.
; Query hashing is over the retained signed profile bytes, not current selectors.
hv_boundary_render:
    push rbx
    push r12
    push r13
    xor r13d, r13d
    jmp hv_boundary_render_common

; Separate bounded page: no CSS144/policy duplication, no private pointers or
; receipts. The full input avoids stitching fields from different observations.
hv_boundary_render_amd:
    push rbx
    push r12
    push r13
    mov r13d, 1
    jmp hv_boundary_render_common

; Full checked192 capture plus selector tail40. Presence describes a retained
; input, never custody, admission, execution or mitigation efficacy.
hv_boundary_render_intel:
    push rbx
    push r12
    push r13
    mov r13d, 2
hv_boundary_render_common:
    lea rbx, [rel hv_boundary_observation]
    call hv_out_reset
    lea rdi, [rel str_bno_pre]
    test r13d, r13d
    jz .prefix
    lea rdi, [rel str_bno_amd_pre]
    cmp r13d, 1
    je .prefix
    lea rdi, [rel str_bno_intel_pre]
.prefix:
    call hv_out_str
    mov eax, [rbx]
    call hv_out_dec
    lea rdi, [rel str_bno_current]
    call hv_out_str
    xor r12d, r12d
    cmp qword [rbx], 1
    jne .current_done
    mov rax, [rbx + 32]
    mov ecx, [rel hv_linux_start_gen]
    cmp rax, rcx
    jne .current_done
    mov rax, [rbx + 40]
    mov ecx, [rel hv_linux_start_consumed]
    cmp rax, rcx
    jne .current_done
    mov rax, [rbx + 48]
    mov ecx, [rel hv_linux_load_gen]
    cmp rax, rcx
    jne .current_done
    mov rax, [rbx + 56]
    mov ecx, [rel vm_profile_gen]
    cmp rax, rcx
    jne .current_done
    mov rax, [rbx + 104]
    cmp rax, [rel vm_profile_active]
    jne .current_done
    mov rax, [rbx + 24]
    movzx ecx, byte [rel hv_launch_mode]
    cmp rax, rcx
    jne .current_done
    mov r12d, 1
.current_done:
    mov eax, r12d
    call hv_out_dec
    lea rdi, [rel str_bno_backend]
    call hv_out_str
    mov eax, [rbx + 16]
    call hv_out_dec
    lea rdi, [rel str_bno_mode]
    call hv_out_str
    mov eax, [rbx + 24]
    call hv_out_dec
    lea rdi, [rel str_bno_start_gen]
    call hv_out_str
    mov eax, [rbx + 32]
    call hv_out_dec
    lea rdi, [rel str_bno_consumed]
    call hv_out_str
    mov eax, [rbx + 40]
    call hv_out_dec
    lea rdi, [rel str_bno_load_gen]
    call hv_out_str
    mov eax, [rbx + 48]
    call hv_out_dec
    lea rdi, [rel str_bno_profile_gen]
    call hv_out_str
    mov eax, [rbx + 56]
    call hv_out_dec
    lea rdi, [rel str_bno_launches]
    call hv_out_str
    mov eax, [rbx + 64]
    call hv_out_dec
    lea rdi, [rel str_bno_stage]
    call hv_out_str
    mov eax, [rbx + 72]
    call hv_out_dec
    lea rdi, [rel str_bno_named]
    call hv_out_str
    mov eax, [rbx + 96]
    call hv_out_dec
    lea rdi, [rel str_bno_boundary_rc]
    call hv_out_str
    lea rdi, [rbx + 8]
    mov esi, 8
    call vp_out_hex
    lea rdi, [rel str_bno_sample_rc]
    call hv_out_str
    lea rdi, [rbx + 80]
    mov esi, 8
    call vp_out_hex
    lea rdi, [rel str_bno_select_rc]
    call hv_out_str
    lea rdi, [rbx + 88]
    mov esi, 8
    call vp_out_hex
    cmp r13d, 1
    je .amd_page
    cmp r13d, 2
    je .intel_page
    lea rdi, [rel str_bno_css]
    call hv_out_str
    lea rdi, [rbx + 112]
    mov esi, 144
    call vp_out_hex
    lea rdi, [rel str_bno_policy]
    call hv_out_str
    lea rdi, [rbx + 256]
    mov esi, 96
    call vp_out_hex
    jmp .profile
.amd_page:
    lea rdi, [rel str_bno_amd_present]
    call hv_out_str
    mov eax, [rbx + BNO_AMD_PRESENT]
    call hv_out_dec
    lea rdi, [rel str_bno_amd_input]
    call hv_out_str
    lea rdi, [rbx + BNO_AMD_INPUT]
    mov esi, 200
    call vp_out_hex
    jmp .profile
.intel_page:
    lea rdi, [rel str_bno_intel_present]
    call hv_out_str
    mov eax, [rbx + BNO_INTEL_PRESENT]
    call hv_out_dec
    lea rdi, [rel str_bno_intel_input]
    call hv_out_str
    lea rdi, [rbx + BNO_INTEL_INPUT]
    mov esi, 232
    call vp_out_hex
.profile:
    lea rdi, [rel str_bno_profile_name]
    call hv_out_str
    lea rdi, [rbx + BNO_PROFILE + VP_NAME]
    mov esi, VP_NAME_BYTES
    call vp_out_hex
    lea rdi, [rel str_bno_profile_sha]
    call hv_out_str
    cmp qword [rbx + 96], 1
    jne .unnamed
    lea rdi, [rel bno_sha]
    lea rsi, [rbx + BNO_PROFILE]
    mov edx, VP_BYTES
    call sha256_hash
    lea rdi, [rel bno_sha]
    mov esi, 32
    call vp_out_hex
    jmp .done
.unnamed:
    lea rdi, [rel str_bno_none]
    call hv_out_str
.done:
    pop r13
    pop r12
    pop rbx
    ret

str_bno_pre: db " GUESTVM BOUNDSTAT rev=1 scope=linux_entry observed=", 0
str_bno_amd_pre: db " GUESTVM BOUNDSTAT rev=2 scope=linux_entry format=amd200 observed=", 0
str_bno_amd_present: db " amd_present=", 0
str_bno_amd_input: db " amd_input=", 0
str_bno_intel_pre: db " GUESTVM BOUNDSTAT rev=3 scope=linux_entry format=intel232 observed=", 0
str_bno_intel_present: db " intel_present=", 0
str_bno_intel_input: db " intel_input=", 0
str_bno_none: db "none", 0
str_bno_current: db " current=", 0
str_bno_backend: db " backend=", 0
str_bno_mode: db " mode=", 0
str_bno_start_gen: db " start_gen=", 0
str_bno_consumed: db " consumed=", 0
str_bno_load_gen: db " load_gen=", 0
str_bno_profile_gen: db " profile_gen=", 0
str_bno_launches: db " launches=", 0
str_bno_stage: db " stage=", 0
str_bno_named: db " named=", 0
str_bno_boundary_rc: db " boundary_rc=", 0
str_bno_sample_rc: db " sample_rc=", 0
str_bno_select_rc: db " select_rc=", 0
str_bno_css: db " css=", 0
str_bno_policy: db " policy=", 0
str_bno_profile_name: db " profile_name=", 0
str_bno_profile_sha: db " profile_sha=", 0
%include "core/abi/wdata.inc"
%macro WDATA_hv_boundary_observation_bss 0
alignb 8
hv_boundary_observation: resb BNO_SIZE
bno_sha: resb 32
%endmacro
WDATA_BSS_DEFER WDATA_hv_boundary_observation_bss
